package com.luqin.bdcrypto.vault;

import java.util.Arrays;

/**
 * The three encodings the vault format uses, implemented here rather than borrowed.
 *
 * <p>The originals live in guava ({@code BaseEncoding}), which cryptolib calls but does not bundle,
 * and in {@code java.util.Base64}, which needs API 26. Both are avoidable: RFC 4648 base32 and
 * base64url are twenty lines each, they cannot drift, and they let the entire vault package be
 * compiled and run against nothing but cryptolib + siv-mode — which is exactly how the offline
 * harness proves the module's traversal.
 *
 * <p>Base32 is what {@code hashDirectoryId} ends in (32 characters, upper case, no padding for a
 * 20-byte digest); base64url is what entry names are (padded when the length demands it, which it
 * does about half the time).
 */
final class Encodings {

    private static final char[] BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();
    private static final char[] HEX = "0123456789abcdef".toCharArray();
    private static final String ALPHABET_URL =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    private static final String ALPHABET_STD =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    private Encodings() {
    }

    /** RFC 4648 base32, upper case, padded to a multiple of 8 with '='. */
    static String base32(byte[] in) {
        StringBuilder sb = new StringBuilder((in.length * 8 + 4) / 5 + 8);
        int buffer = 0;
        int bits = 0;
        for (byte b : in) {
            buffer = (buffer << 8) | (b & 0xff);
            bits += 8;
            while (bits >= 5) {
                sb.append(BASE32[(buffer >>> (bits - 5)) & 31]);
                bits -= 5;
            }
        }
        if (bits > 0) {
            sb.append(BASE32[(buffer << (5 - bits)) & 31]);
        }
        while (sb.length() % 8 != 0) {
            sb.append('=');
        }
        return sb.toString();
    }

    /** Base64url, the alphabet entry names on disk use. Padding is accepted and not required. */
    static byte[] base64Url(String s) {
        return base64(s, ALPHABET_URL);
    }

    /** Standard base64, the alphabet {@code masterkey.cryptomator} uses for its byte fields. */
    static byte[] base64(String s) {
        return base64(s, ALPHABET_STD);
    }

    private static byte[] base64(String s, String alphabet) {
        int len = s.length();
        while (len > 0 && s.charAt(len - 1) == '=') {
            len--;
        }
        byte[] out = new byte[len * 6 / 8 + 1];
        int buffer = 0;
        int bits = 0;
        int n = 0;
        for (int i = 0; i < len; i++) {
            char c = s.charAt(i);
            if (c == '\n' || c == '\r' || c == ' ' || c == '\t') {
                continue;
            }
            int v = alphabet.indexOf(c);
            if (v < 0) {
                throw new IllegalArgumentException("not valid base64: '" + c + "'");
            }
            buffer = (buffer << 6) | v;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out[n++] = (byte) (buffer >>> bits);
            }
        }
        return n == out.length ? out : Arrays.copyOf(out, n);
    }

    static String hex(byte[] in) {
        char[] out = new char[in.length * 2];
        for (int i = 0; i < in.length; i++) {
            out[2 * i] = HEX[(in[i] >>> 4) & 0xf];
            out[2 * i + 1] = HEX[in[i] & 0xf];
        }
        return new String(out);
    }
}
