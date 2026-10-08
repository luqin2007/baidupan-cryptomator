import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.common.MasterkeyFileAccess;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;

/**
 * Official {@code hashDirectoryId} oracle: a directory id to where that directory's entries live.
 *
 * <p>This is the join in the whole vault that cannot be guessed from the outside. A directory's
 * entries are not stored next to its own entry: clicking {@code 游戏} in a listing opens
 * {@code d/SY/RGEQ…/LZPMYUH…==.c9r/}, a directory holding nothing but a 36-byte {@code dir.c9r}, and
 * the entries themselves sit in a completely different branch of {@code d/} named after
 * {@code hashDirectoryId(childId)}. That name is a one-way function of the id — SIV-encrypt the id,
 * SHA-1 the ciphertext, base32 the digest — so the only route from what the user clicked to what
 * they want to see runs through this function, and the id has to come out of {@code dir.c9r} first.
 *
 * <p>Which makes it worth having a second, independent implementation of the function: the module
 * has its own ({@code VaultCipher.hashDirectoryId}), and if the two disagree the module's is wrong,
 * not this one. Note it is deliberately NOT {@code SHA1(cleartextId)} — that reading is natural,
 * gives a plausible-looking 32-character answer, and is incorrect; the SIV step is what makes the
 * real answer come out right.
 *
 * <p>Usage:
 * <pre>
 *   DirHash &lt;vaultDir&gt; &lt;passphrase&gt; &lt;dirId&gt;...
 * </pre>
 * {@code -} as a dirId means the vault root, whose id is the empty string.
 *
 * <p>Reconnaissance tooling; not shipped in the module.
 */
public final class DirHash {

    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.err.println("usage: DirHash <vaultDir> <passphrase> <dirId>...   ('-' = root)");
            System.exit(2);
        }
        final Path vault = Paths.get(args[0]).toAbsolutePath().normalize();
        final String passphrase = args[1];

        // Empty pepper, as for every standard vault.
        final MasterkeyFileAccess access = new MasterkeyFileAccess(new byte[0], new SecureRandom());
        final Masterkey masterkey = access.load(vault.resolve("masterkey.cryptomator"), passphrase);
        final Cryptor cryptor = CryptorProvider
                .forScheme(CryptorProvider.Scheme.SIV_GCM)
                .provide(masterkey, new SecureRandom());

        System.out.println("vault: " + vault);
        for (int i = 2; i < args.length; i++) {
            final String id = "-".equals(args[i]) ? "" : args[i];
            final String hash = cryptor.fileNameCryptor().hashDirectoryId(id);
            System.out.println((id.isEmpty() ? "<root>" : id)
                    + "  ->  " + hash.substring(0, 2) + "/" + hash.substring(2)
                    + "   (d/" + hash.substring(0, 2) + "/" + hash.substring(2) + ")");
        }
    }
}
