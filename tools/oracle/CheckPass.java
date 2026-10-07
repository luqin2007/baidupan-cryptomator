import org.cryptomator.cryptolib.common.AesKeyWrap;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.cryptomator.cryptolib.common.Scrypt;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Manual, dependency-free answer to one question: does this passphrase open this masterkey file?
 *
 * <p>Deliberately does not use {@code MasterkeyFileAccess.load}: that API reports only
 * InvalidPassphraseException, which is also what a wrong argument to it would look like. This
 * performs the same three steps by hand -- scrypt, AES-KW unwrap of both keys, then the
 * versionMac check -- so a failure means the passphrase and nothing else.
 *
 * <p>Usage: CheckPass <masterkey.cryptomator> <passphrase>
 */
public final class CheckPass {

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("usage: CheckPass <masterkey.cryptomator> <passphrase>");
            System.exit(2);
        }
        Path mk = Paths.get(args[0]);
        String pass = args[1];
        String json = new String(Files.readAllBytes(mk), StandardCharsets.UTF_8);

        int version = Integer.parseInt(field(json, "version"));
        byte[] salt = b64(field(json, "scryptSalt"));
        int cost = Integer.parseInt(field(json, "scryptCostParam"));
        int blockSize = Integer.parseInt(field(json, "scryptBlockSize"));
        byte[] wrappedPrimary = b64(field(json, "primaryMasterKey"));
        byte[] wrappedHmac = b64(field(json, "hmacMasterKey"));
        byte[] versionMac = b64(field(json, "versionMac"));

        System.out.println("file          : " + mk);
        System.out.println("passphrase    : " + show(pass) + "  (" + pass.length() + " chars)");
        System.out.println("version       : " + version);
        System.out.println("scrypt        : salt=" + salt.length + "B cost=" + cost + " blockSize=" + blockSize);
        System.out.println("primaryMaster : wrapped " + wrappedPrimary.length + "B -> plain " + (wrappedPrimary.length - 8) + "B");
        System.out.println("hmacMaster    : wrapped " + wrappedHmac.length + "B -> plain " + (wrappedHmac.length - 8) + "B");
        System.out.println("versionMac    : " + versionMac.length + "B");

        long t0 = System.currentTimeMillis();
        byte[] kekBytes = Scrypt.scrypt(pass, salt, cost, blockSize, 32);
        System.out.println("scrypt(" + cost + "," + blockSize + ") -> 32B in " + (System.currentTimeMillis() - t0) + " ms");
        System.out.println("  kek = " + hex(kekBytes));

        DestroyableSecretKey kek = new DestroyableSecretKey(kekBytes, "AES");
        byte[] primary;
        byte[] hmac;
        try {
            primary = AesKeyWrap.unwrap(kek, wrappedPrimary, "AES").getEncoded();
            hmac = AesKeyWrap.unwrap(kek, wrappedHmac, "AES").getEncoded();
        } catch (Exception e) {
            System.out.println("RESULT: AES-KW UNWRAP FAILED -> " + e);
            System.out.println("        (RFC 3394 integrity check rejects the KEK: passphrase is wrong)");
            System.exit(1);
            return;
        }
        System.out.println("AES-KW unwrap OK");
        System.out.println("  primaryMasterKey = " + hex(primary));
        System.out.println("  hmacMasterKey    = " + hex(hmac));

        // versionMac = HMAC-SHA256(hmacMasterKey, <the version>). The spec's exact byte form of
        // "<the version>" is not obvious from the outside, so try the plausible encodings rather
        // than guess one and report a false negative.
        byte[] mac = hmacSha256(hmac, ByteBuffer.allocate(4).putInt(version).array());
        System.out.println("versionMac (4B BE int)      = " + hex(mac));
        boolean ok = java.util.Arrays.equals(mac, versionMac);

        if (!ok) {
            byte[] mac2 = hmacSha256(hmac, String.valueOf(version).getBytes(StandardCharsets.US_ASCII));
            System.out.println("versionMac (ASCII digits)   = " + hex(mac2));
            ok = java.util.Arrays.equals(mac2, versionMac);
            if (!ok) {
                byte[] mac3 = hmacSha256(hmac, ByteBuffer.allocate(8).putLong(version).array());
                System.out.println("versionMac (8B BE long)     = " + hex(mac3));
                ok = java.util.Arrays.equals(mac3, versionMac);
            }
        } else {
            System.out.println("versionMac (4B BE int) matches");
        }
        System.out.println("expected                    = " + hex(versionMac));

        if (ok) {
            System.out.println("RESULT: PASSPHRASE CORRECT (versionMac verified)");
        } else {
            System.out.println("RESULT: PASSPHRASE WRONG (AES-KW unwrap of primaryMasterKey succeeded "
                    + "but versionMac does not match)");
            System.exit(1);
        }
    }

    private static byte[] hmacSha256(byte[] key, byte[] msg) throws Exception {
        Mac m = Mac.getInstance("HmacSHA256");
        m.init(new SecretKeySpec(key, "HmacSHA256"));
        return m.doFinal(msg);
    }

    private static String field(String json, String name) {
        Matcher m = Pattern.compile("\"" + name + "\"\\s*:\\s*(\"[^\"]*\"|[0-9]+)").matcher(json);
        if (!m.find()) {
            throw new IllegalArgumentException("field not found: " + name);
        }
        String v = m.group(1);
        return v.startsWith("\"") ? v.substring(1, v.length() - 1) : v;
    }

    private static byte[] b64(String s) {
        return Base64.getDecoder().decode(s);
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(String.format("%02x", x));
        }
        return sb.toString();
    }

    /** Shows the passphrase with anything non-printable escaped, so a bad paste is visible. */
    private static String show(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            sb.append(c < 0x20 || c > 0x7e ? String.format("\\u%04x", (int) c) : c);
        }
        return sb.toString();
    }
}
