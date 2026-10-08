package com.luqin.bdcrypto;

import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.text.InputType;
import android.widget.EditText;

import com.luqin.bdcrypto.vault.Vault;

import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

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
        private final Map<String, String> dirIdByContent = new ConcurrentHashMap<String, String>();
        private final Map<String, String> contentByDirId = new ConcurrentHashMap<String, String>();

        /**
         * Directory ids keyed by something a page may be <em>showing</em>.
         *
         * <p>Needed because a page's breadcrumb is built from the navigation the user performed, not
         * from the path it landed on: a jump straight from {@code /crypto/content} to
         * {@code d/DI/7HKQ…} adds exactly one crumb, so the crumb reads {@code …/7HKQ…} and the
         * {@code d/DI} in between is nowhere on screen. Matching only against whole content paths
         * therefore turns up nothing on every page the redirect produces — which is every page that
         * matters.
         */
        private final Map<String, String> dirIdByAlias = new ConcurrentHashMap<String, String>();

        /**
         * What each directory is called, keyed by directory id.
         *
         * <p>The breadcrumb cannot be derived from the path and cannot be read off the page: a
         * directory inside a vault is reached by a jump, so its crumb is <em>a hash of its id</em>,
         * and that hash is one-way. The cleartext name exists in exactly one place — the entry the
         * user tapped, which is decrypted when the redirect resolves it — so it is written down
         * here, at the one moment it is known.
         */
        private final Map<String, String> nameByDirId = new ConcurrentHashMap<String, String>();

        /**
         * Entry folders this session has already redirected from.
         *
         * <p>Session-scoped, and that is the whole point of it living here rather than beside the
         * redirect that fills it. Measured: 还原 then unlocking again, then tapping the same
         * directory, opened the entry folder and left the user staring at {@code dir.c9r} — a
         * module-static set had no memory of the lock, so the second tap looked like the first.
         * One redirect per entry folder is still the rule; the rule just has to end with the
         * session, or 还原 is not a way back to the beginning.
         */
        private final Set<String> redirected =
                Collections.newSetFromMap(new ConcurrentHashMap<String, Boolean>());

        /**
         * Whether the vault is still open. Cleared by {@link VaultUi#relock}, which keeps the
         * session rather than dropping it — see there for why the module needs to remember a vault
         * it is no longer decrypting.
         */
        private volatile boolean locked;

        /** False once the vault has been closed again; the paths and ids stay known either way. */
        public boolean isUnlocked() {
            return !locked;
        }

        /** True the first time this path is claimed in this session. */
        public boolean claimRedirect(String path) {
            return redirected.add(path);
        }

        /** Records what a directory is called, so its breadcrumb can read as the user's own name. */
        public void nameDir(String dirId, String cleartext) {
            if (dirId != null && cleartext != null && cleartext.length() > 0) {
                nameByDirId.put(dirId, cleartext);
            }
        }
        
        Session(String cloudDir, File localDir, Vault vault) throws IOException {
            this.cloudDir = cloudDir;
            this.localDir = localDir;
            this.vault = vault;
            String root = vault.rootContentPath();
            remember(root, "");
            // The root content directory is also reachable in one navigation — from the vault root,
            // or by a jump — and then its crumb is just the last segment of its own path. Without
            // this the very first page of the decrypted tree would draw as ciphertext names, which
            // is the one page nobody can afford to get wrong.
            alias(lastSegmentOf(root), "");
        }

        private static String lastSegmentOf(String path) {
            int slash = path.lastIndexOf('/');
            return slash < 0 ? path : path.substring(slash + 1);
        }

        /** The id of the directory whose ciphertext sits at this vault-relative path, or null. */
        public String dirIdOf(String vaultRelativeContentPath) {
            return dirIdByContent.get(vaultRelativeContentPath);
        }

        /**
         * Takes over what another session learnt about this same vault's directories.
         *
         * <p>Needed because 还原 no longer drops the session's <em>knowledge</em>, only its
         * decryption: unlocking again from inside the tree builds a fresh session, and a fresh
         * session knows exactly one directory — the root. Measured, that left the page the user was
         * standing on unrecognisable: {@code d/DI/7HKQ…} is named after a one-way hash of its id, so
         * the module cannot work it out again, and every row on it stayed ciphertext with the
         * unlock button swept off the toolbar.
         *
         * <p>Nothing about the vault's structure changes by locking it, so the ids, the two
         * spellings of each path, and the cleartext names all still hold. What is deliberately
         * <em>not</em> inherited is which entries have been redirected from
         * ({@link #redirected}): that is per-visit bookkeeping, and carrying it over is what made a
         * second tap on 游戏 open the pointer folder and stop there.
         */
        public void inheritFrom(Session other) {
            dirIdByContent.putAll(other.dirIdByContent);
            contentByDirId.putAll(other.contentByDirId);
            dirIdByAlias.putAll(other.dirIdByAlias);
            nameByDirId.putAll(other.nameByDirId);
        }

        /** Where {@code dirId}'s entries live, relative to the vault root — the reverse lookup. */
        public String contentPathOf(String dirId) {
            return contentByDirId.get(dirId);
        }

        /**
         * The id of the directory a breadcrumb reading names, or null.
         *
         * <p><b>Suffix matching, not prefix, and that is not a detail.</b> The breadcrumb is a
         * {@code RecyclerView}: only its visible crumbs are in the view tree, so as the user
         * descends the leading crumbs are recycled away. Measured on the device, the vault's own
         * root content directory reads as {@code /content/d/SY/RGEQ…} — the {@code /crypto} that
         * {@link #cloudDir} starts with is simply gone. Matching on {@code indexOf(cloudDir)}
         * therefore returns null exactly on the page that has something to decrypt.
         *
         * <p>What is invariant is the <em>tail</em>: a breadcrumb reading always ends with the
         * directory being shown. Longest match wins, so when a nested vault directory joins the
         * session it cannot be shadowed by an ancestor whose path is a suffix of it.
         */
        public String dirIdOfDrawn(String drawn) {
            if (drawn == null) {
                return null;
            }
            String bestPath = null;
            String bestDirId = null;
            for (Map<String, String> byKey : java.util.Arrays.asList(dirIdByContent, dirIdByAlias)) {
                for (Map.Entry<String, String> e : byKey.entrySet()) {
                    String path = "/" + e.getKey();
                    if (drawn.equals(path) || drawn.endsWith(path)) {
                        if (bestPath == null || path.length() > bestPath.length()) {
                            bestPath = path;
                            bestDirId = e.getValue();
                        }
                    }
                }
            }
            return bestDirId;
        }

        /** For the log: which directories this session can name. */
        public String knownPaths() {
            return dirIdByContent.keySet().toString();
        }

        // --- what a breadcrumb segment is, in this vault's own terms ---------------------------

        /** A name that means nothing to this vault: the app's own directory, or another app's. */
        public static final int CRUMB_FOREIGN = 0;

        /** {@code d} — the one bucket root every vault has, holding nothing but bucket folders. */
        public static final int CRUMB_BUCKET_ROOT = 1;

        /** A two-character bucket under {@code d}; the format splits directories across these. */
        public static final int CRUMB_BUCKET = 2;

        /** {@code d/XY/<hash>} — where a directory's entries actually live. */
        public static final int CRUMB_CONTENT = 3;

        /** {@code <base64url>.c9r} — the pointer folder that stands in for a directory. */
        public static final int CRUMB_ENTRY = 4;

        /**
         * Classifies a breadcrumb segment, so the breadcrumb can be shown as a path the user
         * walked rather than as the path the format stores.
         *
         * <p>The three content shapes are matched against this session's own knowledge rather than
         * by length or alphabet, which is what makes this safe to run on <em>every</em> page: a
         * hash only counts as a content directory if this session has descended into it, and a
         * bucket name only counts if a content path this session knows runs through it. A directory
         * of the user's that happens to be called {@code d} or {@code AB} is therefore left alone
         * unless it is one of these — and since a segment inside a vault is always a ciphertext
         * name, the vault's own pages can never collide with a cleartext one.
         */
        public int crumbKind(String name) {
            if (name == null || name.length() == 0) {
                return CRUMB_FOREIGN;
            }
            // Checked first: an alias may be a cleartext name this session recorded, so a crumb
            // this module has already renamed classifies the same way on the next bind.
            if (dirIdByAlias.containsKey(name)) {
                return CRUMB_CONTENT;
            }
            if ("d".equals(name)) {
                return CRUMB_BUCKET_ROOT;
            }
            if (name.endsWith(".c9r")) {
                return CRUMB_ENTRY;
            }
            return isBucketName(name) ? CRUMB_BUCKET : CRUMB_FOREIGN;
        }

        /** Whether {@code name} is the second segment of any content path this session has seen. */
        public boolean isBucketName(String name) {
            if (name.length() != 2) {
                return false;
            }
            for (String path : dirIdByContent.keySet()) {
                int first = path.indexOf('/');
                if (first < 0 || path.length() < first + 3) {
                    continue;
                }
                if (path.charAt(first + 1) == name.charAt(0)
                        && path.charAt(first + 2) == name.charAt(1)
                        && (path.length() == first + 3 || path.charAt(first + 3) == '/')) {
                    return true;
                }
            }
            return false;
        }

        /**
         * What a crumb naming this directory should read, or null when it should not be shown.
         *
         * <p>Null for the vault's own root on purpose. Its content directory is where the user
         * already is once the vault is open, so a crumb for it would be a level that does not
         * exist in the user's mind — and its name is a hash nobody asked to see.
         */
        public String nameOfDirId(String dirId) {
            return dirId == null || dirId.length() == 0 ? null : nameByDirId.get(dirId);
        }

        public void remember(String vaultRelativeContentPath, String dirId) {
            dirIdByContent.put(vaultRelativeContentPath, dirId);
            contentByDirId.put(dirId, vaultRelativeContentPath);
        }

        /**
         * Registers another reading of the same directory — the name a jumped-to page will actually
         * show in its breadcrumb. See {@link #dirIdByAlias}.
         */
        public void alias(String key, String dirId) {
            dirIdByAlias.put(key, dirId);
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

    /** True when this page is the vault that is currently open. */
    public static boolean isUnlockedFor(String cloudDir) {
        Session s = session;
        // samePath, not equals: the path a page reports comes from its own breadcrumb, and the
        // leading segments get recycled out of that RecyclerView (docs/recon.md §14.3).
        return s != null && s.isUnlocked() && cloudDir != null && Hooks.samePath(cloudDir, s.cloudDir);
    }

    /**
     * Closes the vault again, so the page goes back to showing the format's own file names.
     *
     * <p><b>The session survives, marked locked, and that is the point of it.</b> Unlocking sends
     * the user into the decrypted tree — a directory that the vault's own page is not an ancestor
     * of — so 还原 pressed from in there used to leave them on a page of hashes with the unlock
     * button gone and nothing to press: the button is placed on pages this module can name, and the
     * name came from the session. Keeping the names while dropping the decryption is what lets the
     * button read 解锁 in the middle of the tree and open the vault again from where the user
     * actually is.
     *
     * <p>The alternative — walking the page back to the vault's own directory — was tried and
     * measured worse: the app answered it by loading that directory's <em>contents</em> without
     * redrawing its breadcrumb, so the page listed {@code d/} and {@code masterkey.cryptomator}
     * under a crumb still reading the directory just left, and every decision the module makes is
     * taken from the breadcrumb. Nothing here moves the page; the way back is the app's own crumb,
     * which is on screen and does work.
     *
     * @return false when this page is not the open vault — the caller should unlock instead
     */
    public static boolean relock(String cloudDir) {
        final Session s = session;
        if (s == null || !s.isUnlocked() || cloudDir == null
                || !Hooks.samePath(cloudDir, s.cloudDir)) {
            return false;
        }
        s.locked = true;
        // The mirror of what unlockSync does, for the same reason: every row on the page was drawn
        // while the session was live, so the page needs one more bind to put the ciphertext names,
        // the sizes and the hidden rows back the way the app has them.
        Hooks.reconcileSoon("relocked " + cloudDir);
        // ...and the breadcrumb, which has no bind coming: no page navigates when the vault is
        // locked, so a crumb this module renamed would go on showing a name the user cannot act on.
        Crumb.release();
        Logx.i("[vault] relocked " + s.cloudDir + "; rows go back to ciphertext names");
        Hooks.toast("BdCryptomator：已还原为密文目录");
        return true;
    }

    public static String stateLine() {
        Session s = session;
        if (s == null) {
            return "locked (no vault unlocked)";
        }
        return (s.isUnlocked() ? "unlocked: " : "locked (names still known): ")
                + "cloud=" + s.cloudDir + " local=" + s.localDir.getAbsolutePath()
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
        final Session previous = session;
        session = new Session(cloudDir, localDir, vault);
        if (previous != null && Hooks.samePath(previous.cloudDir, cloudDir)) {
            // Same vault, unlocked again — possibly from inside the tree, where 还原 left the user.
            // The directory ids it had worked out are still the right ones. See inheritFrom.
            session.inheritFrom(previous);
        }
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
