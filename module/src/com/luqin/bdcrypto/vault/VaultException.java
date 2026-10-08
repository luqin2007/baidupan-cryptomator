package com.luqin.bdcrypto.vault;

import java.io.IOException;

/**
 * A vault that could not be opened or walked: wrong passphrase, an unsupported format, a name that
 * does not authenticate, an entry that contradicts the measured layout.
 *
 * <p>It extends {@link IOException} so that the whole vault package can declare a single checked
 * exception, while a caller that cares about the difference (the unlock button does — "wrong
 * passphrase" is a message to show the user, "I/O error" is not) can still catch this type alone.
 */
public class VaultException extends IOException {

    private static final long serialVersionUID = 1L;

    public VaultException(String message) {
        super(message);
    }

    public VaultException(String message, Throwable cause) {
        super(message, cause);
    }
}
