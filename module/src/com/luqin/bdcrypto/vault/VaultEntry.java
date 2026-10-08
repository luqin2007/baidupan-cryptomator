package com.luqin.bdcrypto.vault;

/**
 * One thing the vault contains, named the way the user sees it.
 *
 * <p>A directory's {@code ciphertextPath} is the directory that holds its entries
 * ({@code d/<hash>…}), not the folder in its parent that points at it — that is what the official
 * oracle reports too, and it is the path worth having: it is where the next level of traversal
 * starts.
 */
public final class VaultEntry {

    /** Cleartext path: {@code /} for the root, otherwise relative and {@code /}-separated. */
    public final String path;

    public final boolean directory;

    /** Vault-relative ciphertext path, always {@code /}-separated. */
    public final String ciphertextPath;

    /** For directories: the id this directory was found under ("" for the root), else null. */
    public final String dirId;

    /** For files: bytes on disk, else 0. */
    public final long ciphertextSize;

    /** For files: cleartext bytes, derived from the size model, else 0. */
    public final long cleartextSize;

    VaultEntry(String path, boolean directory, String ciphertextPath, String dirId,
               long ciphertextSize, long cleartextSize) {
        this.path = path;
        this.directory = directory;
        this.ciphertextPath = ciphertextPath;
        this.dirId = dirId;
        this.ciphertextSize = ciphertextSize;
        this.cleartextSize = cleartextSize;
    }

    @Override
    public String toString() {
        if (directory) {
            return "DIR   " + path + "  <-  " + ciphertextPath;
        }
        return "FILE  " + path + "  <-  " + ciphertextPath
                + "  size=" + cleartextSize + " ct=" + ciphertextSize;
    }
}
