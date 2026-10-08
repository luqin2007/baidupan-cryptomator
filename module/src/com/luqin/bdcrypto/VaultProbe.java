package com.luqin.bdcrypto;

import android.content.Context;

import com.luqin.bdcrypto.vault.Vault;
import com.luqin.bdcrypto.vault.VaultEntry;
import com.luqin.bdcrypto.vault.VaultException;

import java.io.File;
import java.util.List;

/**
 * Device-side entry point for the P2 traversal: unlock a vault that is a directory on the device and
 * walk it, from inside the app's process.
 *
 * <p>This exists for one reason that the desktop harness cannot cover: everything in the vault
 * package has so far run on a JVM with a full JDK. On Android the same code goes through dex, a
 * different provider set (AES/ECB, HmacSHA256) and ART. Running it here is what turns "verified
 * offline" into "verified".
 *
 * <pre>
 *   am broadcast -a com.luqin.bdcrypto.PROBE --es cmd vault \
 *       --es arg /sdcard/Download/BaiduNetdisk/p0d-fixture=p0d-fixture-passphrase-7QzmN4vT
 * </pre>
 *
 * <p>Only the fixture's passphrase belongs here. {@code am broadcast} prints its command line into
 * logcat, so a real vault passphrase would end up in a log the user did not choose to write.
 *
 * <p>The full manifest goes to a report file (adb can pull it); the log carries a one-line summary
 * plus the head, because LSPosed truncates one record at ~7.6 KB.
 */
public final class VaultProbe {

    private VaultProbe() {
    }

    /** @param spec {@code <vaultDir>=<passphrase>} */
    public static void run(Context ctx, String spec) {
        int eq = spec.indexOf('=');
        if (eq <= 0 || eq == spec.length() - 1) {
            Logx.w("usage: --es cmd vault --es arg <vaultDir>=<passphrase>");
            return;
        }
        File dir = new File(spec.substring(0, eq));
        String passphrase = spec.substring(eq + 1);

        StringBuilder sb = new StringBuilder();
        sb.append("vault    : ").append(dir.getAbsolutePath()).append('\n');
        sb.append("exists   : ").append(dir.exists())
                .append("  isDirectory=").append(dir.isDirectory())
                .append("  canRead=").append(dir.canRead()).append('\n');
        String[] top = dir.list();
        // A null here is the interesting case on Android: it is what "the app cannot see this
        // directory at all" looks like (scoped storage), and it must not be confused with
        // "this is not a vault".
        sb.append("list()   : ").append(top == null ? "null — directory not listable" :
                top.length + " entries").append('\n');

        try {
            long t0 = System.currentTimeMillis();
            Vault vault = Vault.open(dir, passphrase);
            long unlockMs = System.currentTimeMillis() - t0;

            t0 = System.currentTimeMillis();
            List<VaultEntry> entries = vault.walk();
            long walkMs = System.currentTimeMillis() - t0;

            int dirs = 0;
            int files = 0;
            long bytes = 0;
            for (VaultEntry entry : entries) {
                if (entry.directory) {
                    dirs++;
                } else {
                    files++;
                    bytes += entry.cleartextSize;
                }
            }
            sb.append("masterkey: version=").append(vault.masterkeyVersion())
                    .append("  (scrypt ok, AES-KW ok, versionMac ok)\n");
            sb.append("config   : format=").append(vault.format())
                    .append(" cipherCombo=").append(vault.cipherCombo())
                    .append(" shorteningThreshold=").append(vault.shorteningThreshold()).append('\n');
            sb.append("rootCtx  : ").append(vault.rootContentPath()).append('\n');
            sb.append("timing   : unlock ").append(unlockMs).append(" ms, walk ")
                    .append(walkMs).append(" ms\n");
            sb.append("totals   : ").append(dirs).append(" dir(s), ").append(files)
                    .append(" file(s), ").append(bytes).append(" cleartext byte(s)\n\n");
            for (VaultEntry entry : entries) {
                sb.append(entry).append('\n');
            }
            sb.append('\n').append("warnings: ").append(vault.warnings().size()).append('\n');
            for (String warning : vault.warnings()) {
                sb.append("  ! ").append(warning).append('\n');
            }
            sb.append(vault.warnings().isEmpty() ? "P2 TRAVERSAL CLEAN" : "P2 TRAVERSAL HAS WARNINGS");
        } catch (VaultException e) {
            // A vault-level failure is a result, not a crash — and it is the message a wrong
            // passphrase or an unreadable vault should produce.
            sb.append("VAULT ERROR: ").append(e.getMessage()).append('\n');
            Logx.w("vault: " + e.getMessage());
        } catch (Throwable t) {
            sb.append("FAILED: ").append(t).append('\n');
            Logx.e("vault probe failed", t);
        }

        String path = Report.write(ctx, "vault.txt", sb.toString());
        String body = sb.toString();
        Logx.i("vault report (" + body.length() + " chars) -> " + path + "\n" + head(body, 1800));
    }

    private static String head(String s, int n) {
        return s.length() <= n ? s : s.substring(0, n) + "\n… (" + (s.length() - n) + " more chars)";
    }
}
