package com.luqin.bdcrypto.vault;

import org.cryptomator.cryptolib.common.Scrypt;

import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * {@code masterkey.cryptomator} → the vault's two 256-bit keys.
 *
 * <p>The file is plain JSON (it is {@code vault.cryptomator} that is a JWT). The passphrase goes
 * through scrypt, the result is the KEK, and both master keys arrive AES-KW wrapped under it. The
 * {@code versionMac} is what makes "the passphrase is wrong" and "the file is broken"
 * distinguishable: it is an HMAC under the unwrapped mac key, so it can only verify if the unwrap
 * produced the vault's real keys.
 *
 * <p>scrypt itself is cryptolib's, not hand-written — the one primitive here that is expensive to
 * get right (memory-hard, 32 MiB at the parameters this vault uses) and cheap to reuse. Everything
 * around it is small enough to be worth owning.
 *
 * <p>Note what is <em>not</em> used: {@code MasterkeyFileAccess.load}. It reports every failure as
 * {@code InvalidPassphraseException}, which is also what a wrong constructor argument looks like —
 * the pepper trap in {@code tools/oracle/README.md} cost an hour for exactly that reason. Doing the
 * steps here keeps each failure attributable.
 */
final class MasterkeyFile {

    /** scrypt output length: every cryptomator master key is 32 bytes. */
    private static final int KEY_LEN = 32;

    private MasterkeyFile() {
    }

    /** The unlocked key material. */
    static final class Keys {

        final int version;
        final byte[] encKey;
        final byte[] macKey;

        Keys(int version, byte[] encKey, byte[] macKey) {
            this.version = version;
            this.encKey = encKey;
            this.macKey = macKey;
        }

        /** {@code masterkey.getEncoded()}: the 64 bytes the vault config JWT is signed with. */
        byte[] encoded() {
            byte[] out = new byte[encKey.length + macKey.length];
            System.arraycopy(encKey, 0, out, 0, encKey.length);
            System.arraycopy(macKey, 0, out, encKey.length, macKey.length);
            return out;
        }
    }

    /**
     * @param json the contents of {@code masterkey.cryptomator}
     * @param passphrase the vault passphrase, as typed (cryptolib does not normalise it either)
     * @throws VaultException wrong passphrase, unsupported masterkey version, unusable key material
     */
    static Keys parse(String json, String passphrase) throws VaultException {
        final int version;
        final byte[] salt;
        final int cost;
        final int blockSize;
        final byte[] wrappedPrimary;
        final byte[] wrappedHmac;
        final byte[] versionMac;
        try {
            version = Json.integer(json, "version");
            salt = Encodings.base64(Json.string(json, "scryptSalt"));
            cost = Json.integer(json, "scryptCostParam");
            blockSize = Json.integer(json, "scryptBlockSize");
            wrappedPrimary = Encodings.base64(Json.string(json, "primaryMasterKey"));
            wrappedHmac = Encodings.base64(Json.string(json, "hmacMasterKey"));
            versionMac = Encodings.base64(Json.string(json, "versionMac"));
        } catch (RuntimeException e) {
            throw new VaultException("masterkey.cryptomator is not readable: " + e.getMessage(), e);
        }
        if (salt.length == 0 || wrappedPrimary.length == 0 || wrappedHmac.length == 0
                || versionMac.length == 0) {
            throw new VaultException("masterkey.cryptomator is incomplete");
        }

        byte[] kek = Scrypt.scrypt(passphrase, salt, cost, blockSize, KEY_LEN);
        byte[] encKey;
        byte[] macKey;
        try {
            encKey = KeyWrap.unwrap(kek, wrappedPrimary);
            macKey = KeyWrap.unwrap(kek, wrappedHmac);
        } catch (VaultException e) {
            // KeyWrap already told a wrong-KEK failure apart from a malformed one.
            throw e;
        } catch (Exception e) {
            throw new VaultException("key unwrap failed: " + e, e);
        } finally {
            Arrays.fill(kek, (byte) 0);
        }

        if (encKey.length != KEY_LEN || macKey.length != KEY_LEN) {
            throw new VaultException("unwrapped key lengths are " + encKey.length + "/" + macKey.length
                    + ", expected " + KEY_LEN + " each");
        }

        // Only now is "the passphrase is right" a fact rather than a hypothesis. cryptolib builds
        // exactly this MAC: HMAC-SHA256(macKey, the version as a 4-byte big-endian int).
        byte[] expected = hmacSha256(macKey, new byte[] {
                (byte) (version >>> 24), (byte) (version >>> 16),
                (byte) (version >>> 8), (byte) version});
        if (!digestsEqual(expected, versionMac)) {
            throw new VaultException("the masterkey unwrapped but its versionMac does not match "
                    + "(vault file inconsistent)");
        }
        return new Keys(version, encKey, macKey);
    }

    private static boolean digestsEqual(byte[] a, byte[] b) {
        return java.security.MessageDigest.isEqual(a, b);
    }

    static byte[] hmacSha256(byte[] key, byte[] message) throws VaultException {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(message);
        } catch (Exception e) {
            throw new VaultException("HmacSHA256 unavailable: " + e, e);
        }
    }
}
