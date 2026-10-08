package com.luqin.bdcrypto.vault;

import org.cryptomator.siv.SivMode;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * The vault's two cryptographic operations, plus the content size model.
 *
 * <p>Everything here is reproducible from cryptolib's own bytecode, and had to be, because the
 * classes that do it there are package-private and take a guava {@code BaseEncoding} as a parameter:
 *
 * <ul>
 *   <li><b>Names</b> are AES-SIV over the cleartext name with the <em>directory id as associated
 *       data</em>, then base64url. Note that this is one associated-data element which may be
 *       empty (the root's id is the empty string) — not zero elements, which is a different S2V
 *       input, and the difference is invisible until a name fails to authenticate.</li>
 *   <li><b>{@code hashDirectoryId} is not a hash of the id.</b> cryptolib SIV-encrypts the id with
 *       no associated data first and hashes <em>that</em>: SHA-1, then base32. It follows that the
 *       content directory of a directory depends on the vault's key, so it cannot be computed
 *       without unlocking first.</li>
 * </ul>
 *
 * <p>SIV itself comes from the bundled {@code siv-mode} jar. Wire it by hand and the failure mode is
 * a name that "looks wrong" rather than an error, so the official implementation is used, reached
 * directly — cryptolib's {@code FileNameCryptor} interface is the same call plus guava's
 * {@code BaseEncoding}.
 */
final class VaultCipher {

    /**
     * Content files carry a fixed 68-byte header before the chunks; measured, not derived
     * (docs/recon.md §12.4). P3 is where this header finally gets decrypted rather than measured.
     */
    static final int HEADER_BYTES = 68;

    /** cleartext bytes per chunk. */
    static final int CHUNK_BYTES = 32768;

    /** ciphertext bytes added per chunk: a 12-byte nonce and a 16-byte GCM tag. */
    static final int CHUNK_OVERHEAD = 28;

    /**
     * {@code SivMode} keeps per-thread cipher state (cryptolib pools it for the same reason), so it
     * is held per thread rather than shared.
     */
    private static final ThreadLocal<SivMode> SIV = new ThreadLocal<SivMode>() {
        @Override
        protected SivMode initialValue() {
            return new SivMode();
        }
    };

    private final SecretKey encKey;
    private final SecretKey macKey;

    VaultCipher(byte[] encKey, byte[] macKey) {
        this.encKey = new SecretKeySpec(encKey, "AES");
        this.macKey = new SecretKeySpec(macKey, "AES");
    }

    /**
     * @param cipherName the on-disk name without its {@code .c9r} suffix
     * @param dirId the id of the directory the entry lives in ("" for the root)
     */
    String decryptName(String cipherName, String dirId) throws VaultException {
        byte[] ciphertext;
        try {
            ciphertext = Encodings.base64Url(cipherName);
        } catch (RuntimeException e) {
            throw new VaultException("entry name is not base64url: " + cipherName, e);
        }
        if (ciphertext.length < 16) {
            throw new VaultException("entry name is shorter than a SIV tag: " + cipherName);
        }
        byte[] cleartext;
        try {
            cleartext = SIV.get().decrypt(encKey, macKey, ciphertext,
                    dirId.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new VaultException("entry name does not authenticate under directory " + describe(dirId)
                    + ": " + cipherName, e);
        }
        return new String(cleartext, StandardCharsets.UTF_8);
    }

    /** {@code hashDirectoryId}: SIV-encrypt the id (no associated data), SHA-1 it, base32 it. */
    String hashDirectoryId(String dirId) throws VaultException {
        byte[] encrypted;
        try {
            encrypted = SIV.get().encrypt(encKey, macKey, dirId.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new VaultException("cannot hash directory id " + describe(dirId) + ": " + e, e);
        }
        byte[] digest;
        try {
            digest = MessageDigest.getInstance("SHA-1").digest(encrypted);
        } catch (Exception e) {
            throw new VaultException("SHA-1 unavailable: " + e, e);
        }
        return Encodings.base32(digest);
    }

    /** {@code d/<first two characters>/<the rest>} — where a directory's own entries live. */
    String contentPath(String dirId) throws VaultException {
        String hash = hashDirectoryId(dirId);
        if (hash.length() < 3) {
            throw new VaultException("hashDirectoryId returned " + hash);
        }
        return Vault.CONTENT_DIR + "/" + hash.substring(0, 2) + "/" + hash.substring(2);
    }

    /**
     * Inverts the measured content model {@code disk = 68 + 28*ceil(clear/32768) + clear}.
     *
     * <p>The module needs this to show a size for a file it has not downloaded, let alone
     * decrypted. It is exact for every size the fixture covers; {@code dirid.c9r} is the documented
     * exception (an empty id still occupies a chunk, so a shortened-length backup needs the written
     * case rather than this one).
     */
    static long cleartextSize(long ciphertextSize) throws VaultException {
        if (ciphertextSize == 0) {
            return 0;
        }
        if (ciphertextSize < HEADER_BYTES) {
            throw new VaultException("ciphertext of " + ciphertextSize
                    + " bytes is smaller than a file header");
        }
        long body = ciphertextSize - HEADER_BYTES;
        for (long chunks = 0; ; chunks++) {
            long cleartext = body - CHUNK_OVERHEAD * chunks;
            if (cleartext < 0) {
                throw new VaultException("ciphertext of " + ciphertextSize
                        + " bytes matches no cleartext size");
            }
            if (cleartext == 0) {
                // Declared empty, or an empty id written through the content channel (dirid.c9r).
                return 0;
            }
            if ((cleartext + CHUNK_BYTES - 1) / CHUNK_BYTES == chunks) {
                return cleartext;
            }
        }
    }

    private static String describe(String dirId) {
        return dirId.isEmpty() ? "the root" : "'" + dirId + "'";
    }
}
