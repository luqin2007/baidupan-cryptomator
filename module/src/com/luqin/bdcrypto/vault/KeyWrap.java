package com.luqin.bdcrypto.vault;

import java.security.GeneralSecurityException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * RFC 3394 AES key unwrap — the step that turns the vault passphrase into key material.
 *
 * <p>Cryptolib has an {@code AesKeyWrap} that does this, but it goes through
 * {@code Cipher.getInstance("AESWrap")}: a transformation whose presence on Android has not been
 * verified here, and whose absence would surface as "unlock does nothing" on the device while the
 * desktop harness stayed green. RFC 3394 is a few lines over AES/ECB/NoPadding, which every JVM and
 * every Android release provides.
 *
 * <p>Not being able to test "does this unwrap correctly?" is not a problem: the {@code versionMac}
 * that follows is an HMAC under the unwrapped key, so a wrong unwrap cannot pass. The check is
 * cryptographic, not structural.
 */
final class KeyWrap {

    /** The RFC 3394 initial value: what the destructively updated A register must read back as. */
    private static final byte[] IV = {
            (byte) 0xA6, (byte) 0xA6, (byte) 0xA6, (byte) 0xA6,
            (byte) 0xA6, (byte) 0xA6, (byte) 0xA6, (byte) 0xA6};

    private KeyWrap() {
    }

    /**
     * @param kek 32-byte key encryption key (scrypt output)
     * @param wrapped the wrapped key, 8-byte IV followed by n 8-byte blocks
     * @return the unwrapped key (n * 8 bytes)
     * @throws GeneralSecurityException only on a platform failure; a wrong KEK is a {@link VaultException}
     */
    static byte[] unwrap(byte[] kek, byte[] wrapped) throws GeneralSecurityException, VaultException {
        if (wrapped.length < 24 || wrapped.length % 8 != 0) {
            throw new VaultException("wrapped key must be >= 24 bytes and a multiple of 8, got "
                    + wrapped.length);
        }
        int n = wrapped.length / 8 - 1;
        byte[] a = new byte[8];
        System.arraycopy(wrapped, 0, a, 0, 8);
        byte[][] r = new byte[n][8];
        for (int i = 0; i < n; i++) {
            System.arraycopy(wrapped, 8 * (i + 1), r[i], 0, 8);
        }

        Cipher aes = Cipher.getInstance("AES/ECB/NoPadding");
        aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(kek, "AES"));

        byte[] block = new byte[16];
        for (int j = 5; j >= 0; j--) {
            for (int i = n; i >= 1; i--) {
                long t = (long) n * j + i;
                System.arraycopy(a, 0, block, 0, 8);
                // XOR the counter into the low 64 bits of A. t is tiny (n <= 8 for every key size
                // cryptomator uses), so only the last two bytes are ever non-zero.
                block[6] ^= (byte) (t >>> 8);
                block[7] ^= (byte) t;
                System.arraycopy(r[i - 1], 0, block, 8, 8);
                byte[] out = aes.doFinal(block);
                System.arraycopy(out, 0, a, 0, 8);
                System.arraycopy(out, 8, r[i - 1], 0, 8);
            }
        }

        for (int i = 0; i < 8; i++) {
            if (a[i] != IV[i]) {
                // This is what a wrong passphrase looks like on the inside: the KEK is wrong, so
                // the unwrap's own integrity value never comes back. Reported as its own case so a
                // caller can tell it apart from a broken vault file.
                throw new VaultException("key unwrap failed its integrity check "
                        + "(the passphrase does not belong to this vault)");
            }
        }

        byte[] key = new byte[n * 8];
        for (int i = 0; i < n; i++) {
            System.arraycopy(r[i], 0, key, i * 8, 8);
        }
        return key;
    }
}
