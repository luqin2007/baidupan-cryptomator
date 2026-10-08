package com.luqin.bdcrypto;

import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.text.InputType;
import android.widget.EditText;

import com.luqin.bdcrypto.vault.Vault;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * The file page's unlock: the passphrase dialog, the session it produces, and the translation from
 * ciphertext names to what the user should see.
 *
 * <p>Nothing here decrypts anything — that is the vault package, which is verified against
 * cryptofs by {@code tools/p2}. This class is the device half: it finds the two config files, hands
 * the vault's own directory to {@link Vault#open(File, String)}, and keeps the result.
 *
 * <p>Getting the ciphertext is the part that only exists on the device. The app downloads into
 * {@code /storage/emulated/0/Download/BaiduNetdisk/<cloud path>} (measured, docs/recon.md §11.5),
 * so a file the app has already fetched is already readable, and one it has not is fetched through
 * the app's own download pipeline ({@link Channel#fetch}) — the user is standing in the vault
 * directory, so the rows for {@code vault.cryptomator} and {@code masterkey.cryptomator} are right
 * there. Only those two files are needed to unlock; the directory tree itself is fetched lazily,
 * one entry listing at a time, because the app can only list the directory it is showing.
 */
public final class VaultUi {

    /** How long to wait for the app to fetch a config file it has not downloaded yet. */
    private static final long FETCH_TIMEOUT_MS = 20000;

    private static volatile Session session;

    private VaultUi() {
    }

    /**
     * An unlocked vault, and where its ciphertext lives — in the cloud and on this device.
     *
     * <p>{@code dirIdByContent} is the piece of state the file page needs and cannot derive: the
     * cloud directory {@code d/XY/<rest>} is named after {@code hashDirectoryId(dirId)}, which is
     * one-way, so the only way to know which directory id a given page is showing is to have
     * descended into it.
     */
    public static final class Session {

        public final String cloudDir;
        public final File localDir;
        public final Vault vault;
        private final Map<String, String> dirIdByContent = new HashMap<String, String>();

        Session(String cloudDir, File localDir, Vault vault) throws IOException {
            this.cloudDir = cloudDir;
            this.localDir = localDir;
            this.vault = vault;
            dirIdByContent.put(vault.rootContentPath(), "");
        }

        /** The id of the directory whose ciphertext sits at this vault-relative path, or null. */
        public String dirIdOf(String vaultRelativeContentPath) {
            return dirIdByContent.get(vaultRelativeContentPath);
        }

        public void remember(String vaultRelativeContentPath, String dirId) {
            dirIdByContent.put(vaultRelativeContentPath, dirId);
        }

        /**
         * Cleartext names for one directory of ciphertext names.
         *
         * @return null when this page's directory id is not known yet — the user jumped straight
         *     into a directory instead of descending from the root
         */
        public String[] namesOf(String vaultRelativeContentPath, String[] cipherNames)
                throws IOException {
            String dirId = dirIdOf(vaultRelativeContentPath);
            return dirId == null ? null : vault.names(dirId, cipherNames);
        }
    }

    public static Session session() {
        return session;
    }

    public static String stateLine() {
        Session s = session;
        if (s == null) {
            return "locked (no vault unlocked)";
        }
        return "unlocked: cloud=" + s.cloudDir + " local=" + s.localDir.getAbsolutePath()
                + " format=" + s.vault.format() + " " + s.vault.cipherCombo()
                + " root=" + safeRoot(s);
    }

    private static String safeRoot(Session s) {
        try {
            return s.vault.rootContentPath();
        } catch (IOException e) {
            return "<" + e + ">";
        }
    }

    /**
     * What the unlock button does: ask for the passphrase, then unlock on a worker thread.
     *
     * <p>The context must be the page's own {@code Activity} — a dialog built from the application
     * context has no window token and throws. The caller has one: the button lives in that
     * activity's view hierarchy.
     */
    public static void onUnlockClicked(Context ctx, final String cloudDir) {
        final EditText input = new EditText(ctx);
        input.setHint("保险库口令");
        input.setSingleLine(true);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        try {
            new AlertDialog.Builder(ctx)
                    .setTitle("解锁 Cryptomator 保险库")
                    .setMessage(cloudDir)
                    .setView(input)
                    .setPositiveButton("解锁", new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            unlock(cloudDir, input.getText().toString());
                        }
                    })
                    .setNegativeButton("取消", null)
                    .show();
        } catch (Throwable t) {
            Logx.e("[vault] cannot show the passphrase dialog", t);
            Hooks.toast("BdCryptomator：无法弹出对话框（" + t + "）");
        }
    }

    /** Unlocks without a dialog, synchronously — the same path the button takes, for the probe. */
    public static String unlockNow(String cloudDir, String passphrase) {
        try {
            return unlockSync(cloudDir, passphrase);
        } catch (Throwable t) {
            return "unlock failed: " + t;
        }
    }

    private static void unlock(final String cloudDir, final String passphrase) {
        if (passphrase == null || passphrase.length() == 0) {
            Hooks.toast("BdCryptomator：口令不能为空");
            return;
        }
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                String result;
                try {
                    result = unlockSync(cloudDir, passphrase);
                } catch (Throwable e) {
                    result = "unlock failed: " + e;
                    Logx.e("[vault] unlock failed", e);
                }
                Logx.i("[vault] " + result);
                Hooks.toast(result.startsWith("OK") ? "BdCryptomator：解锁成功"
                        : "BdCryptomator：" + shortReason(result));
            }
        }, "bdcrypto-unlock");
        t.setDaemon(true);
        t.start();
    }

    /** What to put on screen when the vault would not open. */
    private static String shortReason(String result) {
        if (result.contains("integrity check")) {
            return "口令不对（这个口令不属于该保险库）";
        }
        return result;
    }

    /**
     * The whole unlock: both config files on disk, then the vault's own open.
     *
     * @return a line starting with "OK" on success, otherwise the reason — the caller toasts it
     */
    static String unlockSync(String cloudDir, String passphrase) throws IOException {
        File masterkey = ensureConfig(cloudDir, "masterkey.cryptomator");
        if (masterkey == null) {
            return "拿不到 masterkey.cryptomator：本机没有，App 也没有列出它（请回到该目录再试）";
        }
        File config = ensureConfig(cloudDir, "vault.cryptomator");
        if (config == null) {
            return "拿不到 vault.cryptomator：本机没有，App 也没有列出它（请回到该目录再试）";
        }
        File localDir = Channel.localFileFor(cloudDir);
        Vault vault = Vault.open(localDir, passphrase);
        session = new Session(cloudDir, localDir, vault);
        // Every row of the page the user is standing on now has a cleartext name, but the page was
        // bound before that was true — ask for one reconcile pass, which rebinds the rows.
        Hooks.reconcileSoon("unlocked " + cloudDir);
        return "OK: " + cloudDir + " unlocked (format " + vault.format() + " / "
                + vault.cipherCombo() + ", root content " + vault.rootContentPath() + ")";
    }

    /** The config file on disk, fetched through the app when it is not there yet. */
    private static File ensureConfig(String cloudDir, String name) {
        File local = Channel.localFileFor(cloudDir + "/" + name);
        if (local.isFile() && local.length() > 0) {
            Logx.i("[vault] " + name + " already on disk (" + local.length() + " B)");
            return local;
        }
        Logx.i("[vault] fetching " + cloudDir + "/" + name + " …");
        return Channel.fetch(cloudDir + "/" + name, FETCH_TIMEOUT_MS);
    }
}
