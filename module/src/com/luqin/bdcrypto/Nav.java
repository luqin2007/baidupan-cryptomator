package com.luqin.bdcrypto;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import de.robv.android.xposed.XposedHelpers;

/**
 * Making the app open a directory it was not asked to open.
 *
 * <p>This exists because of one fact about the format that no amount of local cleverness can work
 * around: a Cryptomator directory's <em>entry</em> and its <em>contents</em> live in two unrelated
 * places. The entry is a folder named {@code <base64url>.c9r} sitting in the parent, holding nothing
 * but a {@code dir.c9r}; the contents sit under {@code d/<hashDirectoryId(dirId)>}. The hash is
 * one-way (docs/recon.md §15.4), so the app cannot be told to open the right place from the row it
 * was handed — somebody has to read {@code dir.c9r} first, turn the id into a path, and send the app
 * there. That is this class.
 *
 * <p><b>What is already measured</b>, so this class only has to carry the rest: {@link
 * Channel#fetch} retrieves {@code dir.c9r} (§15.3), {@link com.luqin.bdcrypto.vault.Vault#contentPath}
 * turns a directory id into {@code d/XY/…}, and a {@link
 * com.baidu.netdisk.cloudfile.io.model.CloudFile} can be fabricated from a path — the class has a
 * {@code CloudFile(String)} constructor and {@code setFilePath}/{@code setDir}, and a made-up one
 * reported {@code isDir=1 isDirectory=true} on the device.
 *
 * <p><b>The navigation entry point</b>, and how it was found after one wrong guess:
 *
 * <ul>
 *   <li>{@code BreadcrumbAdapter.Y(Function1, boolean)} — the callback the page stores on its
 *       breadcrumb. Invoking it with a fabricated {@code CloudFile} returns {@code kotlin.Unit} and
 *       <em>does nothing</em>: the argument is accepted, the screen does not change. So it is a
 *       notification ("the crumbs changed") rather than a request ("go here"), and the direction is
 *       backwards. Kept in the probe because the negative result is the useful half.</li>
 *   <li>{@code NetDiskFileListFragment.addNewChildFragment(Object, boolean)} — the descent itself.
 *       A tap on a folder ends here. Two traps sit in front of it:
 *       <ol>
 *         <li>The class in the live tree is <b>{@code FileTabListFragment}</b>, which is a
 *             <em>subclass</em>. Matching by exact class name therefore found nothing and reported
 *             "no NetDiskFileListFragment anywhere" while the page was in fact the very thing —
 *             {@code FileTabListFragment}'s own declared method list is empty because it declares
 *             none. Match by superclass chain.</li>
 *         <li>The method is {@code private}, and declared on the superclass, so it has to be looked
 *             up on the hierarchy rather than on {@code getClass()}.</li>
 *       </ol>
 *     </li>
 * </ul>
 */
final class Nav {

    /** {@code com.baidu.netdisk.cloudfile.io.model.CloudFile}. */
    private static final String CLOUD_FILE = "com.baidu.netdisk.cloudfile.io.model.CloudFile";

    /** The fragment that owns one directory level and knows how to descend. Subclassed, see above. */
    private static final String FILE_LIST_FRAGMENT =
            "com.baidu.netdisk.swipeback.view.NetDiskFileListFragment";

    /** How long the app is given to finish a descent before the crumb is read a second time. */
    private static final long SETTLE_MS = 1200;

    private static volatile Class<?> fileListFragmentClass;

    private Nav() {
    }

    /**
     * The probe's {@code nav} command: build a directory {@code CloudFile} for {@code cloudPath},
     * then ask the live file page to open it — and read the breadcrumb either side, so the answer
     * says whether the app actually moved rather than merely that a call returned.
     *
     * <p>Everything runs on the main thread: reading the fragment tree and the breadcrumb both need
     * it, and so does the navigation. The answer goes to a report file rather than to the log, both
     * because LSPosed truncates a long record in the middle (measured: the first run lost everything
     * after {@code [456 chars]}) and because two processes answer one broadcast.
     */
    static String probe(Context ctx, final String cloudPath) {
        final String[] out = new String[1];
        final CountDownLatch done = new CountDownLatch(1);
        final Handler main = new Handler(Looper.getMainLooper());
        final StringBuilder sb = new StringBuilder();
        sb.append("# pid=").append(android.os.Process.myPid())
                .append(" proc=").append(Report.processTag(ctx))
                .append('\n');
        sb.append("nav ").append(cloudPath);
        try {
            main.post(new Runnable() {
                @Override
                public void run() {
                    try {
                        sb.append(depart(cloudPath));
                        sb.append("\n  crumb before : ").append(Hooks.drawnCrumb());
                    } catch (Throwable t) {
                        sb.append("\n  FAILED: ").append(t);
                    }
                    // The descent is posted to the app's own message queue, so the screen has not
                    // moved by the time invoke() returns. Reading the crumb again after a pause is
                    // what turns "the call did not throw" into "the app is now somewhere else".
                    main.postDelayed(new Runnable() {
                        @Override
                        public void run() {
                            try {
                                sb.append("\n  crumb after  : ").append(Hooks.drawnCrumb());
                                sb.append("\n  tree now     : ").append(tree(Hooks.activity(), 3));
                            } catch (Throwable t) {
                                sb.append("\n  after-check FAILED: ").append(t);
                            } finally {
                                out[0] = sb.toString();
                                done.countDown();
                            }
                        }
                    }, SETTLE_MS);
                }
            });
        } catch (Throwable t) {
            return "cannot reach the main thread for nav: " + t;
        }
        try {
            done.await(SETTLE_MS + 8000, TimeUnit.MILLISECONDS);
        } catch (Throwable ignored) {
            // the caller still gets whatever was produced
        }
        String body = out[0] == null ? sb.append("\n  (timed out waiting for the screen)").toString() : out[0];
        String name = Report.perProcess(ctx, "nav.txt");
        Report.write(ctx, name, body + "\n");
        return "nav -> " + Report.path(ctx, name) + "\n" + firstLines(body, 4);
    }

    /** The bright half: fabricate the file, find the page, ask it to descend. */
    private static String depart(String cloudPath) {
        StringBuilder sb = new StringBuilder();

        Object file;
        try {
            file = fabricate(cloudPath, true);
        } catch (Throwable t) {
            return sb.append("\n  fabricate FAILED: ").append(t).toString();
        }
        sb.append("\n  made    : ").append(describe(file));

        Object frag = fileListFragment();
        if (frag == null) {
            return sb.append("\n  no ").append(FILE_LIST_FRAGMENT).append(" (or subclass) in the ")
                    .append("activity; tree: ").append(tree(Hooks.activity(), 3)).toString();
        }
        sb.append("\n  fragment: ").append(frag.getClass().getName())
                .append('@').append(Integer.toHexString(System.identityHashCode(frag)));
        sb.append("\n  graph   :\n").append(indent(Reflectx.graph("nav", frag, 2)));

        Method descend = descendMethod(frag.getClass());
        if (descend == null) {
            return sb.append("\n  no addNewChildFragment(Object, boolean) on it or above it").toString();
        }
        try {
            sb.append("\n  invoking: ").append(Reflectx.mdesc(descend));
            Object result = invokeDescend(descend, frag, file);
            sb.append("\n  returned: ").append(result);
        } catch (Throwable t) {
            Throwable cause = t.getCause() == null ? t : t.getCause();
            return sb.append("\n  descend FAILED: ").append(cause).toString();
        }
        return sb.toString();
    }

    /**
     * A {@code CloudFile} for a path, built from the public entry points the model keeps.
     *
     * <p>Measured: the class has a {@code CloudFile(String)} constructor and {@code final void
     * setFilePath(String)} / {@code void setDir(boolean)} / {@code void setFileName(String)}, so a
     * directory can be described without a cursor — which is the whole premise of the redirect.
     */
    static Object fabricate(String cloudPath, boolean isDir) throws Exception {
        Class<?> c = XposedHelpers.findClassIfExists(CLOUD_FILE, Hooks.cl());
        if (c == null) {
            throw new ClassNotFoundException(CLOUD_FILE);
        }
        Object file = c.getConstructor(String.class).newInstance(cloudPath);
        c.getMethod("setFilePath", String.class).invoke(file, cloudPath);
        int slash = cloudPath.lastIndexOf('/');
        c.getMethod("setFileName", String.class).invoke(file, slash < 0
                ? cloudPath : cloudPath.substring(slash + 1));
        c.getMethod("setDir", boolean.class).invoke(file, isDir);
        // `isDir` is also a plain public int field, and `isDir()` reads the field rather than
        // whatever setDir stored; setting both is cheaper than finding out which one the click path
        // consults.
        try {
            c.getField("isDir").setInt(file, isDir ? 1 : 0);
        } catch (Throwable ignored) {
            // then the setter above is the only route, which is fine
        }
        return file;
    }

    /** What the fabricated object reports about itself, so a wrong path is told from a wrong idea. */
    static String describe(Object file) {
        StringBuilder sb = new StringBuilder(file.getClass().getName());
        for (String m : new String[]{"getFilePath", "getFileName", "isDir", "isDirectory"}) {
            try {
                sb.append(' ').append(m).append('=').append(Reflectx.call0(file, m));
            } catch (Throwable t) {
                sb.append(' ').append(m).append("=<").append(t).append('>');
            }
        }
        return sb.toString();
    }

    /**
     * The live file page, wherever it is in the activity's fragment tree.
     *
     * <p>Found by walking rather than remembered: the page is rebuilt on every navigation and the
     * app holds several levels of child fragments at once, so a cached reference would be the level
     * the user has left. Depth-first, outermost first, which is the current level because a child
     * fragment manager is only descended into afterwards.
     */
    static Object fileListFragment() {
        Class<?> want = fileListFragmentClass();
        if (want == null) {
            return null;
        }
        return findInFragments(Hooks.activity(), want, 0);
    }

    private static Object findInFragments(Object node, Class<?> want, int depth) {
        if (depth > 6) {
            return null;
        }
        List<?> kids = childFragments(node);
        for (Object f : kids) {
            if (want.isInstance(f)) {
                return f;
            }
        }
        for (Object f : kids) {
            Object deeper = findInFragments(f, want, depth + 1);
            if (deeper != null) {
                return deeper;
            }
        }
        return null;
    }

    /**
     * A node's immediately contained fragments.
     *
     * <p>{@code getChildFragmentManager()} on a fragment and {@code getSupportFragmentManager()} on
     * an activity — and the first is the one that matters: measured, the activity's own list holds
     * only {@code FileTabListFragment}, and the page is a <em>child</em> of it. Asking a fragment for
     * {@code getSupportFragmentManager()} returns null and the walk stops one level too early, which
     * reads exactly like "this class is not in the tree at all".
     */
    private static List<?> childFragments(Object node) {
        if (node == null) {
            return Collections.emptyList();
        }
        Object list = safeFragments(Reflectx.call0(node, "getChildFragmentManager"));
        if (!(list instanceof List)) {
            list = safeFragments(Reflectx.call0(node, "getSupportFragmentManager"));
        }
        return list instanceof List ? (List<?>) list : Collections.emptyList();
    }

    /** {@code FragmentManager.getFragments()} — absent on very old support versions, so guarded. */
    private static Object safeFragments(Object fm) {
        try {
            return Reflectx.call0(fm, "getFragments");
        } catch (Throwable t) {
            return null;
        }
    }

    /** Every fragment reachable from the activity, as {@code Class@identity}, for the log. */
    static String tree(Object node, int depth) {
        StringBuilder sb = new StringBuilder();
        for (Object f : childFragments(node)) {
            if (sb.length() > 0) {
                sb.append(' ');
            }
            sb.append(f.getClass().getSimpleName())
                    .append('@').append(Integer.toHexString(System.identityHashCode(f)));
            if (depth > 0) {
                String inner = tree(f, depth - 1);
                if (inner.length() > 0) {
                    sb.append('[').append(inner).append(']');
                }
            }
        }
        return sb.length() == 0 ? "(none)" : sb.toString();
    }

    /**
     * {@code addNewChildFragment(Object, boolean)} by shape, since R8 keeps the name only by luck
     * and it is declared above the class actually in the tree.
     *
     * <p>The synthetic default-argument bridge is the fallback rather than the first choice: for a
     * {@code private} method Kotlin generates a {@code public static synthetic} twin that takes the
     * receiver, both arguments, the mask and the marker, and calling it is the same descent.
     */
    private static Method descendMethod(Class<?> c) {
        Method bridge = null;
        for (Class<?> k = c; k != null && k != Object.class; k = k.getSuperclass()) {
            for (Method m : k.getDeclaredMethods()) {
                Class<?>[] ps = m.getParameterTypes();
                if (ps.length == 2 && ps[0] == Object.class && ps[1] == boolean.class
                        && m.getName().startsWith("addNewChildFragment")) {
                    return m;
                }
                if (bridge == null && ps.length == 5 && ps[0] == c && ps[1] == Object.class
                        && ps[2] == boolean.class && ps[3] == int.class && ps[4] == Object.class
                        && m.getName().startsWith("addNewChildFragment")) {
                    bridge = m;
                }
            }
        }
        return bridge;
    }

    private static Object invokeDescend(Method m, Object frag, Object file) throws Exception {
        m.setAccessible(true);
        if (java.lang.reflect.Modifier.isStatic(m.getModifiers())) {
            // the default-argument bridge: (receiver, cloudFile, isDir, mask, marker)
            return m.invoke(null, frag, file, Boolean.FALSE, 0, null);
        }
        return m.invoke(frag, file, Boolean.FALSE);
    }

    private static Class<?> fileListFragmentClass() {
        Class<?> c = fileListFragmentClass;
        if (c == null) {
            c = XposedHelpers.findClassIfExists(FILE_LIST_FRAGMENT, Hooks.cl());
            fileListFragmentClass = c;
        }
        return c;
    }

    private static String indent(String s) {
        StringBuilder sb = new StringBuilder();
        for (String line : s.split("\n")) {
            sb.append("    ").append(line).append('\n');
        }
        return sb.toString().trim();
    }

    /** The first {@code n} lines, so the log line stays short enough to survive truncation. */
    private static String firstLines(String s, int n) {
        String[] parts = s.split("\n", n + 1);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(n, parts.length); i++) {
            if (i > 0) {
                sb.append('\n');
            }
            sb.append(parts[i]);
        }
        return sb.toString();
    }

    // ------------------------------------------------------- redirect -----

    /**
     * Opens the decrypted tree when the user arrives at the vault directory itself.
     *
     * <p>The vault directory — the one holding {@code d/}, {@code masterkey.cryptomator} and
     * {@code vault.cryptomator} — holds none of the user's files. Its entries live at
     * {@code hashDirectoryId("")}, one level down and under a name nobody could guess, so a user
     * who chooses to unlock and then has to walk {@code d → SY → RGEQ…} by hand has been handed the
     * ciphertext back with extra steps.
     *
     * <p>No fetch is needed here, unlike {@link #redirectEntry}: the root's own directory id is the
     * empty string, so its content path is known the moment the vault is open.
     *
     * <p>Guarded by the same once-per-path rule, which is what keeps the vault page usable: going
     * back to it is how the user reaches the 还原 button, and a second jump would take that away.
     */
    static void redirectVaultRoot(Context ctx, String drawn) {
        final VaultUi.Session session = VaultUi.session();
        // isUnlocked, because the session outlives 还原: a locked vault still knows its paths, and
        // acting on that would drag the user straight back into the tree they just asked to leave.
        if (session == null || !session.isUnlocked() || drawn == null
                || !Hooks.samePath(drawn, session.cloudDir)) {
            return;
        }
        final String root = session.contentPathOf("");
        if (root == null || !session.claimRedirect(drawn)) {
            return;
        }
        final String target = session.cloudDir + "/" + root;
        Logx.i("[nav] vault root opened: " + drawn + " -> " + target);
        new Handler(Looper.getMainLooper()).post(new Runnable() {
            @Override
            public void run() {
                try {
                    Object frag = fileListFragment();
                    if (frag == null) {
                        return;
                    }
                    Method m = descendMethod(frag.getClass());
                    if (m == null) {
                        return;
                    }
                    invokeDescend(m, frag, fabricate(target, true));
                    Logx.i("[nav] opened the decrypted root " + target);
                    settleAfterRedirect("");
                } catch (Throwable t) {
                    Logx.w("[nav] cannot open " + target + ": " + t);
                }
            }
        });
    }

    /**
     * Rescues a page that is inside the vault but on a directory this session cannot name.
     *
     * <p>The redirects put the user where the files are, and those directories are named after a
     * one-way hash of their id — so the only way to know one is to have gone through it. A session
     * that has just been created (unlocked) therefore cannot read the page it was unlocked from,
     * and neither can one that comes back after the app was restarted: measured, the rows stay
     * ciphertext and the toolbar loses its button, because both are placed from the directory id.
     *
     * <p>{@link VaultUi.Session#inheritFrom} covers the ordinary case — the same vault unlocked
     * again, whose ids are still known. This covers the rest, by taking the user to the one
     * directory every session can name: the decrypted root.
     *
     * <p>Claimed like the other redirects, so a page that cannot be read is left alone after one
     * attempt rather than being pushed to on every quarter-second pass.
     */
    static void recoverIfStranded(Context ctx, String drawn) {
        final VaultUi.Session session = VaultUi.session();
        if (session == null || !session.isUnlocked() || drawn == null
                || session.dirIdOfDrawn(drawn) != null || !looksInsideVault(drawn)) {
            return;
        }
        if (!session.claimRedirect("stranded:" + drawn)) {
            return;
        }
        final String root = session.contentPathOf("");
        if (root == null) {
            return;
        }
        final String target = session.cloudDir + "/" + root;
        Logx.i("[nav] " + drawn + " is inside the vault but not a directory this session can name"
                + " -> opening " + target);
        new Handler(Looper.getMainLooper()).post(new Runnable() {
            @Override
            public void run() {
                try {
                    Object frag = fileListFragment();
                    Method m = frag == null ? null : descendMethod(frag.getClass());
                    if (m == null) {
                        return;
                    }
                    invokeDescend(m, frag, fabricate(target, true));
                    settleAfterRedirect("");
                } catch (Throwable t) {
                    Logx.w("[nav] cannot recover " + drawn + ": " + t);
                }
            }
        });
    }

    /**
     * Whether a breadcrumb's path ends somewhere a Cryptomator tree would put it.
     *
     * <p>Shape only, and deliberately conservative: {@code d/XY/<hash>} or anything holding a
     * {@code .c9r}. Both are strong enough that an ordinary directory of the user's is not going to
     * match by accident, and a false negative costs nothing — the page is left as the app drew it,
     * which is what happens today.
     */
    private static boolean looksInsideVault(String drawn) {
        if (drawn.contains(".c9r")) {
            return true;
        }
        String[] seg = drawn.split("/");
        for (int i = 0; i + 2 < seg.length; i++) {
            if ("d".equals(seg[i]) && seg[i + 1].length() == 2 && seg[i + 2].length() == 30) {
                return true;
            }
        }
        return false;
    }

    /**
     * The vault's own navigation fix: a tap on a Cryptomator directory must not stop at the entry
     * folder.
     *
     * <p>A directory in this format is two unrelated places. The <em>entry</em> is a folder named
     * {@code <base64url name>.c9r} in the parent, holding nothing but a {@code dir.c9r}; the
     * <em>contents</em> sit under {@code d/<hashDirectoryId(dirId)>}, elsewhere entirely. Tapping the
     * row therefore lands the user on a folder that appears empty, while the ninety files they
     * wanted are somewhere the app has no reason to look. Measured on the device: the breadcrumb
     * read {@code …/LZPM…==.c9r} and the page listed one row, {@code dir.c9r}, with the real
     * contents at {@code d/DI/7HKQI7Z3NKNZLTDHRZXUKNCD5URD4I}.
     *
     * <p><b>Why the redirect has to happen after the landing, and not instead of it.</b> The join
     * from entry to contents is {@code dir.c9r}, and it cannot be read before the user gets there:
     * the module may only download a file the app has itself listed ({@code Channel.fetch} borrows
     * the app's download pipeline, which needs a {@code CloudFile} the app made), and the app has no
     * reason to have listed {@code dir.c9r} until somebody opens the folder it lives in. So the
     * sequence is: the app lands, lists one row, and <em>then</em> the module can resolve and move
     * on. A first visit therefore shows the entry folder for as long as the fetch takes.
     *
     * <p>{@link VaultUi.Session#claimRedirect} is what keeps this from being a trap. The entry
     * folder stays in the back stack, so pressing back returns to it and reconcile runs again;
     * without the guard it would shove the user forward every time and back would never get out.
     * One redirect per entry folder means back lands on the entry folder and stays there — a wart,
     * not a trap, and the alternative (replacing the level rather than pushing) is a separate
     * question about {@code changeViewLevel}.
     *
     * <p>The guard is held by the session rather than by this class, and that is not tidiness:
     * measured, a module-static set survived a 还原 followed by a fresh unlock, and the second tap
     * on 游戏 opened the pointer folder holding {@code dir.c9r} and left it there. 还原 has to be a
     * way back to the beginning.
     */
    private static final long ENTRY_FETCH_TIMEOUT_MS = 8000;

    /**
     * Called from the breadcrumb reconcile with the directory the drawn page is on.
     *
     * <p>Returns immediately for every page that is not a Cryptomator entry folder, which is almost
     * all of them: two string tests and a null check.
     */
    static void redirectEntry(Context ctx, String drawn) {
        final VaultUi.Session session = VaultUi.session();
        // isUnlocked: a vault that has been put back to ciphertext must keep showing ciphertext,
        // including the pointer folders — that is what the user asked for by pressing 还原.
        if (session == null || !session.isUnlocked() || drawn == null || !drawn.endsWith(".c9r")) {
            return;
        }
        final String entryCipher = drawn.substring(drawn.lastIndexOf('/') + 1);
        // The parent is the page the user came from, and its id is what names the entry: this is the
        // only moment that page is still the drawn one.
        final String parentDirId = session.dirIdOfDrawn(drawn.substring(0, drawn.lastIndexOf('/')));
        if (parentDirId == null) {
            if (warnedOnce.add(drawn)) {
                Logx.i("[nav] " + drawn + " is an entry folder but its parent is not a directory "
                        + "this session can name (knows " + session.knownPaths() + ")");
            }
            return;
        }
        // Where the entry sits, taken from the id rather than from the breadcrumb. Parsing the
        // breadcrumb would be the obvious source and is wrong: a page reached in one navigation
        // shows one crumb, so the leading d/XY/ of the content path is simply not on screen.
        final String parentContent = session.contentPathOf(parentDirId);
        if (parentContent == null) {
            return;
        }
        if (!session.claimRedirect(drawn)) {
            return;
        }
        final String entryRelative = parentContent + "/" + entryCipher;
        final String entryCloudPath = session.cloudDir + "/" + entryRelative;
        Thread worker = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    redirectOnWorker(session, drawn, entryCloudPath, entryRelative, entryCipher,
                            parentDirId);
                } catch (Throwable t) {
                    Logx.w("[nav] redirect of " + drawn + " failed: " + t);
                }
            }
        }, "bdcrypto-redirect");
        worker.setDaemon(true);
        worker.start();
    }

    private static void redirectOnWorker(VaultUi.Session session, String drawn, String entryCloudPath,
                                         String entryRelative, String entryCipher,
                                         String parentDirId) {
        File dirIdFile = Channel.fetch(entryCloudPath + "/dir.c9r", ENTRY_FETCH_TIMEOUT_MS);
        if (dirIdFile == null) {
            Logx.w("[nav] " + entryCloudPath + "/dir.c9r did not arrive; staying on the entry folder");
            return;
        }
        String childDirId;
        try {
            childDirId = session.vault.childDirectoryId(entryRelative);
        } catch (Throwable t) {
            Logx.w("[nav] " + entryRelative + "/dir.c9r did not read as an id: " + t);
            return;
        }
        if (childDirId == null) {
            Logx.w("[nav] " + entryRelative + " names no child id");
            return;
        }
        String relContent;
        try {
            relContent = session.vault.contentPath(childDirId);
        } catch (Throwable t) {
            Logx.w("[nav] cannot place " + childDirId + ": " + t);
            return;
        }
        // Registered before the move, because the new page binds its rows the moment it is created
        // and an unregistered path is a page of ciphertext names.
        session.remember(relContent, childDirId);
        // ...and under the name its breadcrumb will actually show. The page is reached in one
        // navigation from anywhere, so the crumb reads the last segment of the content path only;
        // see Session.dirIdByAlias for why whole-path matching turns up nothing here.
        session.alias(lastSegment(relContent), childDirId);
        String realName = null;
        if (parentDirId != null) {
            try {
                realName = session.vault.name(parentDirId, entryCipher);
            } catch (Throwable t) {
                Logx.w("[nav] " + entryCipher + " does not name a cleartext entry: " + t);
            }
        }
        if (realName != null && realName.length() > 0) {
            session.alias(realName, childDirId);
            // ...and so the breadcrumb of the page about to be opened can say 游戏 instead of
            // 7HKQI7Z3NKNZLTDHRZXUKNCD5URD4I. This is the only moment that name exists anywhere the
            // module can see: the entry the user tapped, read back through the vault.
            session.nameDir(childDirId, realName);
        }

        final String target = session.cloudDir + "/" + relContent;
        final String targetDirId = childDirId;
        Logx.i("[nav] " + drawn + " -> " + target + " (dirId " + childDirId + ", \""
                + (realName == null ? "?" : realName) + "\")");
        new Handler(Looper.getMainLooper()).post(new Runnable() {
            @Override
            public void run() {
                try {
                    Object frag = fileListFragment();
                    if (frag == null) {
                        Logx.w("[nav] the page went away before the redirect could be made");
                        return;
                    }
                    Object file = fabricate(target, true);
                    Method m = descendMethod(frag.getClass());
                    if (m == null) {
                        Logx.w("[nav] no way to descend on " + frag.getClass().getName());
                        return;
                    }
                    invokeDescend(m, frag, file);
                    Logx.i("[nav] redirected to " + target);
                    settleAfterRedirect(targetDirId);
                } catch (Throwable t) {
                    Logx.w("[nav] redirect to " + target + " failed: " + t);
                }
            }
        });
    }

    /** The last path segment — the name a breadcrumb would show for a directory reached in one hop. */
    private static String lastSegment(String path) {
        int slash = path.lastIndexOf('/');
        return slash < 0 ? path : path.substring(slash + 1);
    }

    /**
     * Keeps asking for a reconcile until the page being drawn is the directory just navigated to.
     *
     * <p>Not belt-and-braces: the pass that reads the new page can arrive <em>before</em> the new
     * page counts as drawn, and then nothing asks again. Measured twice on the same build — the
     * first unlock worked, the second did not — and the difference is one pass. The new page exists
     * with a readable crumb while {@code isShown()} is still false, so {@link Hooks#reconcile} skips
     * it, falls back to the page it replaced, and reads the directory being left; the breadcrumb
     * fires once per directory change and has already fired, so no second pass is coming. The screen
     * has moved and the rows keep their ciphertext names.
     *
     * <p>Compared by directory id rather than by path, because the two are not the same string and
     * cannot be made so: a page reached in one navigation shows one crumb, so the decrypted root
     * draws as {@code …/content/RGEQ…} while its content path is {@code …/d/SY/RGEQ…}. The session
     * already knows both spellings; asking it is what makes this test correct rather than lucky.
     *
     * <p>Bounded, and silent once it succeeds — a redirect that never lands leaves a log line and
     * gives up rather than polling for the life of the process.
     */
    private static void settleAfterRedirect(final String targetDirId) {
        final Handler handler = new Handler(Looper.getMainLooper());
        final int[] tries = {10};
        final Runnable[] step = new Runnable[1];
        step[0] = new Runnable() {
            @Override
            public void run() {
                VaultUi.Session session = VaultUi.session();
                String drawn = Hooks.drawnCrumb();
                String dirId = session == null ? null : session.dirIdOfDrawn(drawn);
                if (targetDirId.equals(dirId)) {
                    Logx.i("[nav] the drawn page is the redirect target (dirId \"" + targetDirId
                            + "\", crumb " + drawn + ")");
                    return;
                }
                if (--tries[0] <= 0) {
                    Logx.w("[nav] the redirect to dirId \"" + targetDirId + "\" never became the"
                            + " drawn page (crumb " + drawn + ")");
                    return;
                }
                Hooks.reconcileSoon("waiting for the redirect (crumb " + drawn + ")");
                handler.postDelayed(step[0], 200);
            }
        };
        handler.postDelayed(step[0], 200);
    }

    /** Entry folders already reported as unresolvable, so a quarter-second loop does not spam. */
    private static final Set<String> warnedOnce =
            Collections.newSetFromMap(new ConcurrentHashMap<String, Boolean>());

    /** Unused today, kept deliberately: the callback field is how the negative result was found. */
    static Field callbackField(Class<?> adapter) {
        for (Class<?> c = adapter; c != null && c != Object.class; c = c.getSuperclass()) {
            for (Field f : c.getDeclaredFields()) {
                if (f.getType().getName().equals("kotlin.jvm.functions.Function1")) {
                    return f;
                }
            }
        }
        return null;
    }
}
