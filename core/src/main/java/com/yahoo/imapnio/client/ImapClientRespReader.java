package com.yahoo.imapnio.client;

import javax.annotation.Nonnull;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.LineBasedFrameDecoder;
import io.netty.util.ReferenceCountUtil;

/**
 * Reads server responses from the channel and frames each complete response, gluing every literal onto the response that carries it.
 *
 * <p>
 * Each line is scanned forward along the response grammar (RFC 9051 sections 4 and 7, RFC 3501 sections 4 and 7). A response starts with a tag,
 * "*" or "+". Status responses (OK, NO, BAD, BYE, PREAUTH) and continuation requests continue with resp-text: an optional bracketed response code,
 * then free-form text. Neither carries a literal, except the charset list of a BADCHARSET code, which RFC 3501 defines as astrings; it is scanned
 * as tokens, with quoted strings skipped so that a quoted "]" does not close it. Every other response is scanned as tokens. A literal opens only
 * where a string token starts, after SP or "(": "{" (or "~{" for a literal8, RFC 3516), one or more digits, "}" and CRLF. Anything else, such as
 * a folder name ending in {n} echoed in the text of a NO response, is part of the line, and the response ends with that line.
 * </p>
 *
 * @author kaituo
 *
 */
public class ImapClientRespReader extends LineBasedFrameDecoder {

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

    /**
     * Constructor of IMAP client response reader.
     *
     * @param maxLineLength maximum response line length
     */
    public ImapClientRespReader(final int maxLineLength) {
        super(maxLineLength, false, true);
        literalCount = -1;
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
    @Override
    protected Object decode(final ChannelHandlerContext ctx, final ByteBuf inputBuf) throws Exception {
        while (inputBuf.readableBytes() > 0) {

            if (literalCount <= 0) { // LINE mode - read until CRLF

                final ByteBuf lineBuf = (ByteBuf) super.decode(ctx, inputBuf); // Read a CRLF terminated line from inputBuf

                if (lineBuf == null) { // no CRLF seen in this case, don't return existing buffer since it is not done
                    return null;
                }
                final int lineLen = lineBuf.readableBytes();
                this.literalCount = scanLine(lineBuf, lineLen, literalBuf != null);
                if (this.literalCount < 0) { // the line does not end with a literal, so the response is complete
                    return getFinalResponse(lineBuf);
                }

                // literals follows if reaching here
                if (literalBuf == null) {
                    literalBuf = Unpooled.buffer(lineLen + Math.min(literalCount, MAX_INITIAL_LITERAL_CAPACITY) + EXTRA_PADDING_LEN);
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
     * @param lineBuf the line buffer obtained from the super.decode
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
     * Scans one line of a response forward along the response grammar.
     *
     * @param lineBuf buffer for the line, ending with its line terminator
     * @param lineLen line length of the above lineBuf
     * @param continuing true if the line continues a response after a literal, false if it starts a response
     * @return the count of the literal the line ends with, or -1 if the line ends the response
     */
    private int scanLine(@Nonnull final ByteBuf lineBuf, final int lineLen, final boolean continuing) {
        final boolean crlf = lineLen >= 2 && lineBuf.getByte(lineLen - 2) == '\r';
        final int contentEnd = crlf ? lineLen - 2 : lineLen - 1;
        if (!continuing) {
            inCode = false;
        }
        ScanState state = continuing ? ScanState.TOKENS : ScanState.TAG;
        boolean tokenStart = false;
        int wordStart = 0;
        long count = -1;
        int i = 0;
        while (i < contentEnd) {
            final byte b = lineBuf.getByte(i);
            boolean consumed = true;
            switch (state) {
            case TAG:
                if (b == ' ') {
                    state = (i == 1 && lineBuf.getByte(0) == '+') ? ScanState.RESP_TEXT : ScanState.STATUS_WORD;
                    wordStart = i + 1;
                }
                break;
            case STATUS_WORD:
                if (b == ' ') {
                    state = isStatusWord(lineBuf, wordStart, i) ? ScanState.RESP_TEXT : ScanState.TOKENS;
                    tokenStart = true;
                }
                break;
            case RESP_TEXT:
                state = (b == '[') ? ScanState.CODE_NAME : ScanState.TEXT;
                wordStart = i + 1;
                break;
            case CODE_NAME:
                if (b == ' ') {
                    inCode = matchesWord(lineBuf, wordStart, i, BADCHARSET);
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
            if (consumed) {
                i++;
            }
        }
        return (crlf && state == ScanState.LITERAL_END) ? (int) count : -1;
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
