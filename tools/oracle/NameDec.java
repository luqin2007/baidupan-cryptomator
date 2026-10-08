import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.common.MasterkeyFileAccess;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;

/**
 * Official name oracle: encrypt/decrypt a single vault entry name with the REAL cryptolib.
 *
 * <p>{@link Unlock} can only talk about entries that exist in a vault on this machine, which leaves
 * one hole: a name that was never synced down here cannot be checked there. The list on the phone
 * is exactly that case — the cloud vault has entries the local copy does not. Without this program
 * the only available check would be "the rewritten row looks like a plausible Chinese name", and
 * a plausible-looking name is not evidence that the decryption was right.
 *
 * <p>SIV is deterministic given (key, associated data, input), so {@code enc} is a real test rather
 * than a smoke test: encrypting the suspected cleartext must reproduce the ciphertext name that is
 * actually on the cloud, character for character. {@code dec} runs the other way and says what the
 * phone SHOULD have shown.
 *
 * <p>The associated data is the containing directory's id. For the vault root that is the EMPTY
 * byte array passed as ONE argument — note this is not the same as passing no associated data at
 * all, which is what {@code hashDirectoryId} does (RFC 5297 distinguishes the two).
 *
 * <p>Both base64url variants are printed, because which one format 8 uses is not documented here and
 * the padded one is what the vault on disk actually shows; the run that reproduces the known-correct
 * name for {@code 欢迎.rtf} is the one that is authoritative.
 *
 * <p>Usage:
 * <pre>
 *   NameDec &lt;vaultDir&gt; &lt;passphrase&gt; &lt;dirId|-&gt; enc &lt;cleartextName&gt;...
 *   NameDec &lt;vaultDir&gt; &lt;passphrase&gt; &lt;dirId|-&gt; dec &lt;ciphertextName&gt;...
 * </pre>
 * {@code -} as the dirId means the vault root.
 *
 * <p>Reconnaissance tooling; not shipped in the module.
 */
public final class NameDec {

    /** Format 8 writes base64url WITH padding; this is what the vault's own names show. */
    private static final BaseEncoding PADDED = BaseEncoding.base64Url();

    /** Kept as the counter-hypothesis so a mismatch cannot be blamed on the wrong guess. */
    private static final BaseEncoding UNPADDED = BaseEncoding.base64Url().omitPadding();

    public static void main(String[] args) throws Exception {
        if (args.length < 5) {
            System.err.println("usage: NameDec <vaultDir> <passphrase> <dirId|-> enc|dec <name>...");
            System.exit(2);
        }
        final Path vault = Paths.get(args[0]).toAbsolutePath().normalize();
        final String passphrase = args[1];
        final String dirIdArg = args[2];
        final String mode = args[3];

        // The root directory's id is the empty string, which as bytes is an empty array. It must be
        // handed over as a single (empty) associated-data element, not as "no associated data".
        final byte[] dirId = "-".equals(dirIdArg) ? new byte[0]
                : dirIdArg.getBytes(StandardCharsets.UTF_8);

        // Pepper must be empty for every standard vault; a non-empty one silently changes the KEK
        // and surfaces as InvalidPassphraseException instead of an argument error.
        final MasterkeyFileAccess access = new MasterkeyFileAccess(new byte[0], new SecureRandom());
        final Masterkey masterkey = access.load(vault.resolve("masterkey.cryptomator"), passphrase);
        final Cryptor cryptor = CryptorProvider
                .forScheme(CryptorProvider.Scheme.SIV_GCM)
                .provide(masterkey, new SecureRandom());

        System.out.println("vault    : " + vault);
        System.out.println("dirId    : " + ("-".equals(dirIdArg) ? "<root, empty>" : dirIdArg));

        for (int i = 4; i < args.length; i++) {
            final String value = args[i];
            System.out.println();
            System.out.println("=== " + mode + " " + value);
            for (BaseEncoding enc : new BaseEncoding[]{PADDED, UNPADDED}) {
                final String label = enc == PADDED ? "base64Url(padded)" : "base64Url(unpadded)";
                try {
                    if ("enc".equals(mode)) {
                        System.out.println("  " + label + " -> "
                                + cryptor.fileNameCryptor().encryptFilename(enc, value, dirId));
                    } else {
                        System.out.println("  " + label + " -> "
                                + cryptor.fileNameCryptor().decryptFilename(enc, stripSuffix(value), dirId));
                    }
                } catch (Throwable t) {
                    // A wrong encoding or a wrong associated data shows up here, and the failure
                    // mode itself is the finding — do not swallow it into a blank line.
                    System.out.println("  " + label + " -> !" + t.getClass().getSimpleName()
                            + " " + t.getMessage());
                }
            }
        }

        // Independent of the two calls above: the root content directory's on-disk location is
        // base32(SHA1(SIV(encKey, macKey, "")))[0:2] / [2:], so printing it says whether dirId was
        // fed in the way the format expects.
        System.out.println();
        System.out.println("hashDirectoryId(\"\") : " + cryptor.fileNameCryptor().hashDirectoryId(""));
    }

    /** The vault stores {@code <name>.c9r}; the cipher is fed the name alone. */
    private static String stripSuffix(String name) {
        for (String suffix : new String[]{".c9r", ".c9s"}) {
            if (name.endsWith(suffix)) {
                return name.substring(0, name.length() - suffix.length());
            }
        }
        return name;
    }
}
