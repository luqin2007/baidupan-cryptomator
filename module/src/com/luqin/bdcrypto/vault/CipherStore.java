package com.luqin.bdcrypto.vault;

import java.io.IOException;

/**
 * Where the ciphertext comes from — the seam that keeps vault logic independent of how the bytes
 * were obtained.
 *
 * <p>Paths are vault-relative and always use {@code /}: {@code masterkey.cryptomator},
 * {@code vault.cryptomator}, {@code d/KJ/R2V2.../dirid.c9r}. The offline harness backs this with a
 * plain local directory ({@link FileCipherStore}); on the device the same walk will run over
 * whatever the module manages to read — today the download landing directory, later the app's own
 * content channel — without the traversal knowing the difference.
 *
 * <p>Only these five operations are needed, and deliberately nothing else: no mtime, no attributes,
 * no streaming. A vault is a name→bytes mapping as far as traversal is concerned.
 */
public interface CipherStore {

    boolean exists(String path);

    boolean isDirectory(String path);

    /** Entry names directly under {@code path}; empty when there are none. */
    String[] list(String path) throws IOException;

    byte[] read(String path) throws IOException;

    /** Size in bytes, or 0 when absent. */
    long length(String path) throws IOException;
}
