package com.luqin.bdcrypto.vault;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Just enough JSON to read the two vault files, which are flat objects of strings and integers.
 *
 * <p>Not a JSON parser and deliberately so: {@code masterkey.cryptomator} is parsed by cryptolib
 * through gson, which is not bundled either, and a full parser would be the wrong size of solution
 * for seven fields that only ever appear once. The patterns are anchored on the field name and
 * accept a quoted string or a bare integer.
 */
final class Json {

    private Json() {
    }

    static String string(String json, String name) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(name) + "\"\\s*:\\s*\"([^\"]*)\"")
                .matcher(json);
        if (!m.find()) {
            throw new IllegalArgumentException("field not found in JSON: " + name);
        }
        return m.group(1);
    }

    static int integer(String json, String name) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(name) + "\"\\s*:\\s*(-?[0-9]+)")
                .matcher(json);
        if (!m.find()) {
            throw new IllegalArgumentException("field not found in JSON: " + name);
        }
        return Integer.parseInt(m.group(1));
    }
}
