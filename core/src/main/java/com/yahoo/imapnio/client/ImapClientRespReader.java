package com.yahoo.imapnio.client;

import java.util.List;

import javax.annotation.Nonnull;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.handler.codec.TooLongFrameException;
import io.netty.util.ReferenceCountUtil;

/**
 * Reads server responses from the channel and frames each complete response, gluing every literal onto the response that carries it.
 *
 * <p>
 * Each byte of a line is read once: a single forward scan finds the line end and follows the response grammar (RFC 9051 sections 4 and 7, RFC 3501
 * sections 4 and 7). A response starts with a tag, "*" or "+". Status responses (OK, NO, BAD, BYE, PREAUTH) and continuation requests continue
 * with resp-text: an optional bracketed response code, then free-form text. Neither carries a literal, except the charset list of a BADCHARSET
 * code, which RFC 3501 defines as astrings; it is scanned as tokens, with quoted strings skipped so that a quoted "]" does not close it. Every
 * other response is scanned as tokens. A literal opens only where a string token starts, after SP or "(": "{" (or "~{" for a literal8, RFC 3516),
 * one or more digits, "}" and CRLF. Anything else, such as a folder name ending in {n} echoed in the text of a NO response, is part of the line,
 * and the response ends with that line.
 * </p>
 *
 * @author kaituo
 *
 */
public class ImapClientRespReader extends ByteToMessageDecoder {

    /**
     * Where the scan of a line stands in the response grammar.
     */
    private enum ScanState {
        /** Reading the tag, "*" or "+". */
        TAG,
        /** Reading the word after the tag, which tells a status response from a data response. */
        STATUS_WORD,
        /** At the start of resp-text: "[" opens a response code, anything else starts the text. */
        RESP_TEXT,
        /** Reading the atom that names a response code. */
        CODE_NAME,
        /** Between or inside the tokens of a data response or of a BADCHARSET code. */
        TOKENS,
        /** Inside a quoted string within a BADCHARSET code. */
        QUOTED,
        /** After a backslash inside a quoted string. */
        QUOTED_ESCAPE,
        /** After a "~" at the start of a token, which may begin a literal8. */
        LITERAL8,
        /** Reading the digits of a literal count. */
        LITERAL_COUNT,
        /** After the "}" of a literal count: the literal opens if the line ends here. */
        LITERAL_END,
        /** In resp-text that cannot carry a literal: free-form text, or a response code other than BADCHARSET. Runs to the end of the line. */
        TEXT
    }

    /** Status words whose remainder is resp-text, in upper case. */
    private static final String[] STATUS_WORDS = { "OK", "NO", "BAD", "BYE", "PREAUTH" };

    /** The one response code whose arguments can carry a literal (RFC 3501 section 9). */
    private static final String BADCHARSET = "BADCHARSET";

    /** Number base for the literal count. */
    private static final int RADIX = 10;

    /** Upper bound on the literal bytes allocated up front, so a large announced count cannot force a large allocation before the bytes arrive. */
    private static final int MAX_INITIAL_LITERAL_CAPACITY = 64 * 1024;

    /** Extra length to accommodate CRLF. */
    private static final int EXTRA_PADDING_LEN = 16;

    /** Literal response remaining bytes size. */
    private int literalCount;

    /** Literal response buffer. */
    private ByteBuf literalBuf;

    /** Whether the scan is inside a BADCHARSET code, which a "]" closes; a line after a literal can continue inside one. */
    private boolean inCode;

    /** Maximum length of a line, without its line terminator. */
    private final int maxLineLength;

    /** Bytes of the current line already scanned, counted from the reader index, so a line split across reads is not scanned again. */
    private int scanned;

    /** Whether the rest of a line that exceeded {@link #maxLineLength} is being skipped. */
    private boolean discarding;

    /** Where the scan of the current line stands. */
    private ScanState state;

    /** Whether the next byte can start a token, that is, it follows SP or "(". */
    private boolean tokenStart;

    /** Offset in the line where the word being read started. */
    private int wordStart;

    /** Literal count read so far, or -1 before its first digit. */
    private long count;

    /**
     * Constructor of IMAP client response reader.
     *
     * @param maxLineLength maximum response line length
     */
    public ImapClientRespReader(final int maxLineLength) {
        this.maxLineLength = maxLineLength;
        literalCount = -1;
    }

    @Override
    protected void decode(final ChannelHandlerContext ctx, final ByteBuf inputBuf, final List<Object> out) throws Exception {
        final Object frame = decode(ctx, inputBuf);
        if (frame != null) {
            out.add(frame);
        }
    }

    /**
     * Decode has 2 modes:
     *
     * (a) line mode : The client will return the decoded line if the response ends with it, that is, the line does not end with a literal.
     *
     * (b) literal mode : When a line ends with a literal announcement at a position where the grammar allows one, the client keeps buffering the
     * bytes until all literal data is read, and then continues reading the rest of the response.
     *
     * @param ctx the {@link ChannelHandlerContext} which this decoder belongs to
     * @param inputBuf the {@link ByteBuf} from which to read data
     * @return the {@link ByteBuf} which represent the frame or {@code null} if no frame could be created.
     * @throws Exception on decode failure
     */
    protected Object decode(final ChannelHandlerContext ctx, final ByteBuf inputBuf) throws Exception {
        while (inputBuf.readableBytes() > 0) {

            if (literalCount <= 0) { // LINE mode - read until CRLF

                final ByteBuf lineBuf = readLine(inputBuf);

                if (lineBuf == null) { // no CRLF seen in this case, don't return existing buffer since it is not done
                    return null;
                }
                if (this.literalCount < 0) { // the line does not end with a literal, so the response is complete
                    return getFinalResponse(lineBuf);
                }

                // literals follows if reaching here
                if (literalBuf == null) {
                    literalBuf = Unpooled.buffer(lineBuf.readableBytes() + Math.min(literalCount, MAX_INITIAL_LITERAL_CAPACITY) + EXTRA_PADDING_LEN);
                }
                writeLiteralBufFromLineBuf(lineBuf); // add current line (ex: "* 1 FETCH (FLAGS (\Seen $NotJunk) BODY[] {4495}\r\n")
                // back to top of loop to enter literal mode block

            } else { // LITERAL mode - read till reaching the count or end of inputBuf
                final int avail = inputBuf.readableBytes(); // available bytes unread in inputBuf
                final int actual = (literalCount <= avail) ? literalCount : avail; // actual length to copy
                literalBuf.writeBytes(inputBuf, actual);
                literalCount -= actual;
            }
        }

        return null;
    }

    /**
     * Writes the given lineBuf to literalBuf. When writing is finished, we need to release the given lineBuf since this lineBuf will not be given to
     * StringDecoder to release.
     *
     * @param lineBuf the line buffer obtained from {@link #readLine(ByteBuf)}
     */
    private void writeLiteralBufFromLineBuf(@Nonnull final ByteBuf lineBuf) {
        literalBuf.writeBytes(lineBuf);
        ReferenceCountUtil.release(lineBuf); // Decreases the reference count by {@link 1}
    }

    /**
     * Prepares final response and clear the holding buffer.
     *
     * @param lineBuf the current line obtained from input buffer
     * @return final response in ByteBuf
     */
    private ByteBuf getFinalResponse(@Nonnull final ByteBuf lineBuf) {
        if (literalBuf == null) { // literalBuf is empty
            return lineBuf;
        }
        writeLiteralBufFromLineBuf(lineBuf);
        final ByteBuf result = literalBuf;
        // reset existing
        literalBuf = null;
        literalCount = -1;
        return result;
    }

    /**
     * Scans the input forward from where the last call stopped, along the response grammar, until the line ends. Sets {@link #literalCount} to the
     * count of the literal the line ends with, or to -1 if the line ends the response.
     *
     * @param inputBuf the input, whose reader index is at the start of the line
     * @return the line with its line terminator, or null if the line has not ended yet
     * @throws TooLongFrameException if the line is longer than {@link #maxLineLength}
     */
    private ByteBuf readLine(@Nonnull final ByteBuf inputBuf) throws TooLongFrameException {
        if (discarding && !discardLine(inputBuf)) {
            return null;
        }
        final int start = inputBuf.readerIndex();
        final int end = inputBuf.writerIndex();
        if (scanned == 0) {
            startLine(literalBuf != null);
        }
        int i = start + scanned;
        while (i < end) {
            final byte b = inputBuf.getByte(i);
            if (b == '\n' || (b == '\r' && i + 1 < end && inputBuf.getByte(i + 1) == '\n')) {
                return endLine(inputBuf, i - start, b == '\r');
            }
            if (b == '\r' && i + 1 == end) { // whether a LF follows is not known yet
                break;
            }
            if (step(inputBuf, start, i - start, b)) { // otherwise the byte is read again in the state the step moved to
                i++;
            }
        }
        scanned = i - start;
        if (scanned > maxLineLength) {
            inputBuf.skipBytes(inputBuf.readableBytes());
            discarding = true;
            throw tooLong(scanned);
        }
        return null;
    }

    /**
     * Skips input up to and including the next LF, which ends a line that exceeded {@link #maxLineLength}.
     *
     * @param inputBuf the input
     * @return true if the line has ended, false if all the input was skipped without reaching its end
     */
    private boolean discardLine(@Nonnull final ByteBuf inputBuf) {
        final int lf = inputBuf.indexOf(inputBuf.readerIndex(), inputBuf.writerIndex(), (byte) '\n');
        if (lf < 0) {
            inputBuf.skipBytes(inputBuf.readableBytes());
            return false;
        }
        inputBuf.readerIndex(lf + 1);
        discarding = false;
        return true;
    }

    /**
     * Ends the line at the given offset and reads it from the input.
     *
     * @param inputBuf the input, whose reader index is at the start of the line
     * @param contentLen length of the line without its line terminator
     * @param crlf true if the line ends with CRLF, false if with a bare LF
     * @return the line with its line terminator
     * @throws TooLongFrameException if the line is longer than {@link #maxLineLength}
     */
    private ByteBuf endLine(@Nonnull final ByteBuf inputBuf, final int contentLen, final boolean crlf) throws TooLongFrameException {
        scanned = 0;
        final int lineLen = contentLen + (crlf ? 2 : 1);
        if (contentLen > maxLineLength) {
            inputBuf.skipBytes(lineLen);
            throw tooLong(contentLen);
        }
        literalCount = (crlf && state == ScanState.LITERAL_END) ? (int) count : -1;
        return inputBuf.readRetainedSlice(lineLen);
    }

    /**
     * Drops the response being read, whose line exceeded {@link #maxLineLength}, and builds the exception that reports it.
     *
     * @param length the length of the line read so far
     * @return the exception to throw
     */
    private TooLongFrameException tooLong(final int length) {
        scanned = 0;
        literalCount = -1;
        if (literalBuf != null) {
            literalBuf.release();
            literalBuf = null;
        }
        return new TooLongFrameException("frame length (" + length + ") exceeds the allowed maximum (" + maxLineLength + ")");
    }

    /**
     * Sets the scan up for the start of a line.
     *
     * @param continuing true if the line continues a response after a literal, false if it starts a response
     */
    private void startLine(final boolean continuing) {
        if (!continuing) {
            inCode = false;
        }
        state = continuing ? ScanState.TOKENS : ScanState.TAG;
        tokenStart = false;
        wordStart = 0;
        count = -1;
    }

    /**
     * Moves the scan of the line over one byte of its content.
     *
     * @param lineBuf buffer holding the line
     * @param start index in the buffer where the line starts
     * @param pos offset of the byte in the line
     * @param b the byte
     * @return true if the byte was consumed, false if it must be read again in the new state
     */
    private boolean step(@Nonnull final ByteBuf lineBuf, final int start, final int pos, final byte b) {
        boolean consumed = true;
        switch (state) {
        case TAG:
            if (b == ' ') {
                state = (pos == 1 && lineBuf.getByte(start) == '+') ? ScanState.RESP_TEXT : ScanState.STATUS_WORD;
                wordStart = pos + 1;
            }
            break;
        case STATUS_WORD:
            if (b == ' ') {
                state = isStatusWord(lineBuf, start + wordStart, start + pos) ? ScanState.RESP_TEXT : ScanState.TOKENS;
                tokenStart = true;
            }
            break;
        case RESP_TEXT:
            state = (b == '[') ? ScanState.CODE_NAME : ScanState.TEXT;
            wordStart = pos + 1;
            break;
        case CODE_NAME:
            if (b == ' ') {
                inCode = matchesWord(lineBuf, start + wordStart, start + pos, BADCHARSET);
                state = inCode ? ScanState.TOKENS : ScanState.TEXT;
                tokenStart = true;
            } else if (b == ']') {
                state = ScanState.TEXT;
            }
            break;
        case TOKENS:
            if (b == '"' && inCode) { // quotes cannot span a line end, so only a quoted "]" in a BADCHARSET code changes framing
                state = ScanState.QUOTED;
            } else if (b == ']' && inCode) {
                inCode = false;
                state = ScanState.TEXT;
            } else if (tokenStart && b == '{') {
                state = ScanState.LITERAL_COUNT;
                count = -1;
            } else if (tokenStart && b == '~') {
                state = ScanState.LITERAL8;
            }
            tokenStart = b == ' ' || b == '(';
            break;
        case QUOTED:
            if (b == '\\') {
                state = ScanState.QUOTED_ESCAPE;
            } else if (b == '"') {
                state = ScanState.TOKENS;
            }
            break;
        case QUOTED_ESCAPE:
            state = ScanState.QUOTED;
            break;
        case LITERAL8:
            if (b == '{') {
                state = ScanState.LITERAL_COUNT;
                count = -1;
            } else {
                state = ScanState.TOKENS;
                consumed = false;
            }
            break;
        case LITERAL_COUNT:
            if (b >= '0' && b <= '9') {
                count = Math.max(count, 0) * RADIX + (b - '0');
                if (count > Integer.MAX_VALUE) {
                    state = ScanState.TOKENS;
                }
            } else if (b == '}' && count >= 0) {
                state = ScanState.LITERAL_END;
            } else {
                state = ScanState.TOKENS;
                consumed = false;
            }
            break;
        case LITERAL_END:
            state = ScanState.TOKENS;
            consumed = false;
            break;
        default: // TEXT runs to the end of the line
            break;
        }
        return consumed;
    }

    /**
     * Tells whether the bytes in the given range are a status word, ignoring ASCII case.
     *
     * @param lineBuf buffer for the line
     * @param from index where the word starts
     * @param to index after the word
     * @return true if the word is one of {@link #STATUS_WORDS}
     */
    private boolean isStatusWord(@Nonnull final ByteBuf lineBuf, final int from, final int to) {
        for (final String word : STATUS_WORDS) {
            if (matchesWord(lineBuf, from, to, word)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param lineBuf buffer for the line
     * @param from index where the bytes to compare start
     * @param to index after the bytes to compare
     * @param word the upper-case ASCII word to compare against
     * @return true if the bytes in the range equal the word, ignoring ASCII case
     */
    private boolean matchesWord(@Nonnull final ByteBuf lineBuf, final int from, final int to, @Nonnull final String word) {
        if (to - from != word.length()) {
            return false;
        }
        for (int i = 0; i < word.length(); i++) {
            if (Character.toUpperCase((char) lineBuf.getByte(from + i)) != word.charAt(i)) {
                return false;
            }
        }
        return true;
    }
}
