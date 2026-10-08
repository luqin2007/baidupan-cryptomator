import com.luqin.bdcrypto.vault.Vault;
import com.luqin.bdcrypto.vault.VaultEntry;
import com.luqin.bdcrypto.vault.VaultException;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

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

        // ------------------------------------------------ the file page's entry point ---------
        // names() is what the UI will call: it takes the ciphertext names a caller already has (on
        // the device, the rows the app is drawing) and answers what each is called in cleartext. It
        // has to agree with walk(), which is what cryptofs judges. The one thing it may decline is a
        // shortened name, whose real name is inside the folder itself — and then the walk must have
        // exactly as many names it alone could resolve as there were .c9s entries.
        List<String> problems = new ArrayList<String>();
        int dirsChecked = 0;
        int resolvedNames = 0;
        int shortened = 0;
        for (VaultEntry dir : entries) {
            if (!dir.directory) {
                continue;
            }
            dirsChecked++;
            String[] raw = vault.store().list(dir.ciphertextPath);
            String[] plain = vault.names(dir.dirId, raw);
            Set<String> resolved = new TreeSet<String>();
            for (int i = 0; i < raw.length; i++) {
                if (Vault.isInternal(raw[i])) {
                    continue;
                }
                if (plain[i] == null) {
                    if (raw[i].endsWith(".c9s")) {
                        shortened++;
                    } else {
                        problems.add(dir.path + ": " + raw[i] + " has no cleartext name");
                    }
                    continue;
                }
                resolved.add(plain[i]);
            }

            Set<String> fromWalk = new TreeSet<String>();
            for (VaultEntry child : entries) {
                if (child != dir && dir.path.equals(parentPath(child.path))) {
                    fromWalk.add(lastSegment(child.path));
                }
            }
            fromWalk.removeAll(resolved);
            resolvedNames += resolved.size();
            if (fromWalk.size() != countShortened(raw)) {
                problems.add(dir.path + ": names() resolved " + resolved.size() + " of "
                        + (resolved.size() + fromWalk.size()) + " entries, but the directory holds "
                        + countShortened(raw) + " shortened name(s); unresolved: " + fromWalk);
            }
        }

        System.out.println();
        System.out.println("names()  : " + dirsChecked + " dir(s), " + resolvedNames
                + " name(s) resolved, " + shortened + " shortened (unresolved by design)");
        System.out.println("problems : " + problems.size());
        for (String problem : problems) {
            System.out.println("  ! " + problem);
        }
        System.out.println(warnings.isEmpty() && problems.isEmpty()
                ? "P2 TRAVERSAL CLEAN" : "P2 TRAVERSAL HAS WARNINGS");
        System.exit(warnings.isEmpty() && problems.isEmpty() ? 0 : 1);
    }

    private static int countShortened(String[] raw) {
        int n = 0;
        for (String name : raw) {
            if (name.endsWith(".c9s")) {
                n++;
            }
        }
        return n;
    }

    private static String parentPath(String path) {
        int slash = path.lastIndexOf('/');
        return slash <= 0 ? "/" : path.substring(0, slash);
    }

    private static String lastSegment(String path) {
        int slash = path.lastIndexOf('/');
        return path.substring(slash + 1);
    }
}
