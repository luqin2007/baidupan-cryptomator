package com.luqin.bdcrypto.vault;

import java.nio.charset.StandardCharsets;

/**
 * {@code vault.cryptomator} → the three parameters the traversal depends on.
 *
 * <p>It is an <b>HS256 JWT, not JSON</b>, signed with {@code masterkey.getEncoded()} (the 64 bytes
 * of encKey followed by macKey). Reading only the payload would work on a healthy vault and quietly
 * misread a file that had been tampered with, so the signature is verified: it costs one HMAC and
 * it also confirms the masterkey we unwrapped is the one this vault was configured with.
 *
 * <p>{@code format} and {@code cipherCombo} are checked rather than reported. The module implements
 * one format — 8 / SIV_GCM — and a vault that says anything else must fail loudly instead of being
 * walked with the wrong cipher.
 */
final class VaultConfigFile {

    /** The only vault format this module implements. */
    static final int SUPPORTED_FORMAT = 8;

    /** The only cipher combo this module implements. */
    static final String SUPPORTED_CIPHER_COMBO = "SIV_GCM";

    final int format;
    final String cipherCombo;
    final int shorteningThreshold;

    private VaultConfigFile(int format, String cipherCombo, int shorteningThreshold) {
        this.format = format;
        this.cipherCombo = cipherCombo;
        this.shorteningThreshold = shorteningThreshold;
    }

    /**
     * @param jwt the contents of {@code vault.cryptomator}
     * @param masterkey {@code encKey || macKey}, the JWT's signing key
     */
    static VaultConfigFile parse(String jwt, byte[] masterkey) throws VaultException {
        String token = jwt.trim();
        int first = token.indexOf('.');
        int second = first < 0 ? -1 : token.indexOf('.', first + 1);
        if (first <= 0 || second <= first || token.indexOf('.', second + 1) >= 0) {
            throw new VaultException("vault.cryptomator is not a three-part JWT");
        }

        String signed = token.substring(0, second);
        byte[] signature;
        String payload;
        try {
            signature = Encodings.base64Url(token.substring(second + 1));
            payload = new String(Encodings.base64Url(token.substring(first + 1, second)),
                    StandardCharsets.UTF_8);
        } catch (RuntimeException e) {
            throw new VaultException("vault.cryptomator is not valid base64url: " + e.getMessage(), e);
        }

        byte[] expected = MasterkeyFile.hmacSha256(masterkey, signed.getBytes(StandardCharsets.US_ASCII));
        if (!java.security.MessageDigest.isEqual(expected, signature)) {
            throw new VaultException("vault.cryptomator's HS256 signature does not verify "
                    + "(the masterkey does not belong to this config)");
        }

        final int format;
        final String combo;
        final int threshold;
        try {
            format = Json.integer(payload, "format");
            combo = Json.string(payload, "cipherCombo");
            threshold = Json.integer(payload, "shorteningThreshold");
        } catch (RuntimeException e) {
            throw new VaultException("vault.cryptomator payload is not readable: " + e.getMessage(), e);
        }

        if (format != SUPPORTED_FORMAT) {
            throw new VaultException("vault format " + format + " is not supported (this module "
                    + "implements format " + SUPPORTED_FORMAT + ")");
        }
        if (!SUPPORTED_CIPHER_COMBO.equals(combo)) {
            throw new VaultException("cipher combo " + combo + " is not supported (this module "
                    + "implements " + SUPPORTED_CIPHER_COMBO + ")");
        }
        return new VaultConfigFile(format, combo, threshold);
    }
}
