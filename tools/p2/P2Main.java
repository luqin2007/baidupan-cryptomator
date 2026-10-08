import com.luqin.bdcrypto.vault.Vault;
import com.luqin.bdcrypto.vault.VaultEntry;
import com.luqin.bdcrypto.vault.VaultException;

import java.io.File;
import java.util.List;

/**
 * Offline P2 harness: unlock a vault and walk it, using the module's own vault package.
 *
 * <p>Why this exists rather than a unit test: the acceptance criterion for P2 is "the tree this
 * produces is the tree the official cryptofs produces", and the only authority for that is
 * {@code tools/oracle} running on the same vault. So this prints the manifest in the oracle's own
 * line format, and {@code p2.sh check} diffs the two after normalising both.
 *
 * <p>It also happens to be a structural guarantee worth having: it compiles
 * {@code module/src/com/luqin/bdcrypto/vault/**} with no {@code android.jar} anywhere on the
 * classpath, so an Android import creeping into the traversal fails the build here rather than on
 * the device.
 *
 * <p>Usage: P2Main &lt;vaultDir&gt; &lt;passphrase&gt;
 */
public final class P2Main {

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("usage: P2Main <vaultDir> <passphrase>");
            System.exit(2);
        }
        try {
            run(new File(args[0]).getAbsoluteFile(), args[1]);
        } catch (VaultException e) {
            // A vault-level failure is a result, not a crash: p2.sh's negative mode matches these
            // messages, so they have to stay one line and stay specific.
            System.err.println("VAULT ERROR: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void run(File vaultDir, String passphrase) throws Exception {
        long t0 = System.currentTimeMillis();
        Vault vault = Vault.open(vaultDir, passphrase);
        long unlockMs = System.currentTimeMillis() - t0;

        System.out.println("vault        : " + vaultDir);
        System.out.println("masterkey    : version=" + vault.masterkeyVersion());
        System.out.println("config       : format=" + vault.format()
                + " cipherCombo=" + vault.cipherCombo()
                + " shorteningThreshold=" + vault.shorteningThreshold());
        System.out.println("root content : " + vault.rootContentPath());
        System.out.println("RESULT: UNLOCK OK (" + unlockMs + " ms)");

        t0 = System.currentTimeMillis();
        List<VaultEntry> entries = vault.walk();
        long walkMs = System.currentTimeMillis() - t0;

        int dirs = 0;
        int files = 0;
        long bytes = 0;
        System.out.println();
        System.out.println("=== manifest: cleartext <-> ciphertext (P2: names and sizes) ===");
        for (VaultEntry entry : entries) {
            System.out.println(entry);
            if (entry.directory) {
                dirs++;
            } else {
                files++;
                bytes += entry.cleartextSize;
            }
        }
        System.out.println("totals: " + dirs + " dir(s), " + files + " file(s), " + bytes
                + " cleartext byte(s)");
        // Kept off the totals line: p2.sh diffs that line against the oracle's verbatim.
        System.out.println("walked in " + walkMs + " ms");

        List<String> warnings = vault.warnings();
        System.out.println();
        System.out.println("warnings: " + warnings.size());
        for (String warning : warnings) {
            System.out.println("  ! " + warning);
        }
        System.out.println(warnings.isEmpty() ? "P2 TRAVERSAL CLEAN" : "P2 TRAVERSAL HAS WARNINGS");
        System.exit(warnings.isEmpty() ? 0 : 1);
    }
}
