package com.luqin.bdcrypto;

import android.app.Application;
import android.content.Context;
import android.os.Build;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * All hooks installed into the Baidu Netdisk process.
 *
 * <p>P0 is deliberately observation-only: nothing is mutated, no UI is altered. The goal is to
 * replace every remaining guess about the app's architecture with a line of evidence produced by
 * the running process:
 *
 * <ol>
 *   <li>which class actually backs the file list (adapter + item model),</li>
 *   <li>what a list row looks like as a {@code CloudFile}, including its {@code fsId} and full
 *       path — the two things the later phases need in order to act on the *ciphertext* file,</li>
 *   <li>which classes can hand out file content (the download pipeline).</li>
 * </ol>
 *
 * <p>Every callback body is wrapped so a failure can never take the host app down with it.
 */
public final class Hooks {

    private static final String APP_PKG = "com.baidu.drive.app";

    /** Cap on retained row samples; a vault listing is small but a scan of / could be large. */
    private static final int MAX_ROWS = 4000;
    private static final int MAX_URLS = 2000;
    private static final int MAX_CHANNEL_LOGS = 400;

    private static final java.util.concurrent.atomic.AtomicInteger channelLogs =
            new java.util.concurrent.atomic.AtomicInteger();

    private static volatile ClassLoader cl;
    private static volatile Context app;
    private static volatile boolean appHooksInstalled;

    private static volatile Object lastFragment;
    private static volatile String lastFragmentWhere = "-";

    private static final Set<String> rowsSeen = Collections.synchronizedSet(new HashSet<String>());
    private static final List<String> rows = Collections.synchronizedList(new ArrayList<String>());
    private static final Set<String> cursorColumns =
            Collections.synchronizedSet(new LinkedHashSet<String>());
    private static final Set<String> cursorClasses = Collections.synchronizedSet(new HashSet<String>());
    private static final Set<String> adapterClasses =
            Collections.synchronizedSet(new LinkedHashSet<String>());
    private static final List<String> urls = Collections.synchronizedList(new ArrayList<String>());
    private static final Set<String> urlSeen = Collections.synchronizedSet(new HashSet<String>());
    private static final List<String> missingTargets = Collections.synchronizedList(new ArrayList<String>());

    /**
     * Vault recognition, built purely from the listing we are already given.
     *
     * <p>A directory is a Cryptomator vault when its own listing contains both
     * {@code vault.cryptomator} and {@code masterkey.cryptomator}. Each marker is remembered
     * separately so the order in which the two rows arrive does not matter — the listing is
     * delivered row by row, in whatever order the cursor happens to yield.
     */
    private static final Set<String> dirsWithVaultFile =
            Collections.synchronizedSet(new HashSet<String>());
    private static final Set<String> dirsWithMasterkeyFile =
            Collections.synchronizedSet(new HashSet<String>());
    private static final Set<String> vaultsAnnounced =
            Collections.synchronizedSet(new HashSet<String>());

    /** So the toolbar dump is produced once per process, not once per vault. */
    private static final java.util.concurrent.atomic.AtomicBoolean toolbarDumped =
            new java.util.concurrent.atomic.AtomicBoolean();

    private Hooks() {
    }

    // ------------------------------------------------------------- state ----

    public static ClassLoader cl() {
        return cl;
    }

    public static Context app() {
        return app;
    }

    public static Object lastFragment() {
        return lastFragment;
    }

    // ----------------------------------------------------------- install ----

    public static void install(XC_LoadPackage.LoadPackageParam lp) {
        cl = lp.classLoader;
        Logx.i("=== BdCryptomator attached: pkg=" + lp.packageName
                + " pid=" + android.os.Process.myPid()
                + " version=" + Build.VERSION.SDK_INT + " ===");
        hookApplicationOnCreate();
    }

    /**
     * {@code Application.onCreate} is the earliest point at which we have a usable {@link Context}
     * (needed for the probe channel) and at which the app's own classes have begun loading.
     */
    private static void hookApplicationOnCreate() {
        try {
            XposedHelpers.findAndHookMethod("android.app.Application", cl, "onCreate",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            safe("Application.onCreate", new Body() {
                                @Override
                                public void run() {
                                    Context c = (Context) param.thisObject;
                                    if (app == null) {
                                        app = c;
                                    }
                                    ProbeReceiver.install(c);
                                    if (!appHooksInstalled) {
                                        appHooksInstalled = true;
                                        installAppHooks();
                                    }
                                }
                            });
                        }
                    });
            Logx.i("hooked Application.onCreate");
        } catch (Throwable t) {
            Logx.e("cannot hook Application.onCreate", t);
        }
    }

    private static void installAppHooks() {
        long t0 = System.currentTimeMillis();
        int before = missingTargets.size();
        hookFileListFragment();
        hookRecyclerAdapter();
        hookCloudFileModel();
        hookCursorColumns();
        hookNetwork();
        hookDownloadPipeline();
        Logx.i("app hooks installed in " + (System.currentTimeMillis() - t0) + " ms; "
                + (missingTargets.size() - before) + " target(s) missing"
                + (missingTargets.isEmpty() ? "" : " -> " + missingTargets));
    }

    // ------------------------------------------------------ file list ------

    /**
     * The file page fragment. Its lifecycle is the reliable "a directory listing is on screen"
     * signal, and its field graph tells us which object owns the adapter and the path.
     */
    private static void hookFileListFragment() {
        String[] targets = {
                "com.baidu.netdisk.allfiles.listfragment.FileTabListFragment",
                "com.baidu.netdisk.swipeback.view.NetDiskFileListFragment",
        };
        for (final String name : targets) {
            Class<?> c = XposedHelpers.findClassIfExists(name, cl);
            if (c == null) {
                note("missing target: " + name);
                continue;
            }
            for (final String m : new String[]{"onViewCreated", "onResume", "onDestroyView"}) {
                try {
                    XposedBridge.hookAllMethods(c, m, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            safe(name + "." + m, new Body() {
                                @Override
                                public void run() {
                                    onFragmentEvent(m, param.thisObject);
                                }
                            });
                        }
                    });
                } catch (Throwable t) {
                    note("hook " + name + "." + m + " failed: " + t);
                }
            }
            Logx.i("hooked " + name + " lifecycle");
        }
    }

    private static void onFragmentEvent(String where, Object fragment) {
        lastFragment = fragment;
        lastFragmentWhere = where + "@" + android.os.SystemClock.uptimeMillis();
        Logx.i("[fragment] " + where + " -> " + Reflectx.typeOf(fragment));
        if (!"onViewCreated".equals(where) && !"onResume".equals(where)) {
            return;
        }
        String g = Reflectx.graph(where, fragment, 3);
        if (app != null) {
            Report.write(app, "graph-" + where + ".txt", g);
        }
        Logx.i("[fragment.graph " + where + "] " + truncate(g, 1800));
        if ("onResume".equals(where) && !vaultsAnnounced.isEmpty()) {
            // The vault may have been recognised while no fragment was on screen; the toolbar only
            // exists now, so this is the second chance to measure it.
            dumpToolbarTree("resume, vaults=" + vaultsAnnounced);
        }
    }

    // ---------------------------------------------------- recycler list ----

    /** Confirms which adapter backs the file list and how many rows it thinks it has. */
    private static void hookRecyclerAdapter() {
        Class<?> rv = XposedHelpers.findClassIfExists("androidx.recyclerview.widget.RecyclerView", cl);
        if (rv == null) {
            note("missing target: androidx.recyclerview.widget.RecyclerView");
            return;
        }
        try {
            XposedBridge.hookAllMethods(rv, "setAdapter", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    safe("RecyclerView.setAdapter", new Body() {
                        @Override
                        public void run() {
                            Object a = param.args != null && param.args.length > 0 ? param.args[0] : null;
                            if (a == null) {
                                return;
                            }
                            String cn = a.getClass().getName();
                            if (adapterClasses.add(cn)) {
                                StringBuilder sb = new StringBuilder("[adapter] ").append(cn).append('\n');
                                sb.append(Reflectx.dumpClass(a.getClass()));
                                Logx.i(sb.toString());
                                if (app != null) {
                                    Report.write(app, "dump-adapter-" + cn.replace('.', '_') + ".txt",
                                            sb.toString());
                                }
                            }
                        }
                    });
                }
            });
            Logx.i("hooked RecyclerView.setAdapter");
        } catch (Throwable t) {
            note("hook RecyclerView.setAdapter failed: " + t);
        }
    }

    // ------------------------------------------------------- CloudFile ----

    /**
     * {@code CloudFile} is the app's universal file model and — unusually for an R8 build — kept
     * its readable method names. It is produced from a {@link android.database.Cursor}, so hooking
     * the two factories captures every row of every listing together with its {@code fsId}.
     */
    private static void hookCloudFileModel() {
        final Class<?> cf =
                XposedHelpers.findClassIfExists("com.baidu.netdisk.cloudfile.io.model.CloudFile", cl);
        if (cf == null) {
            note("missing target: CloudFile");
            return;
        }
        try {
            XposedBridge.hookAllMethods(cf, "createFormCursor", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    final MethodHookParam p = param;
                    safe("CloudFile.createFormCursor", new Body() {
                        @Override
                        public void run() {
                            recordRow(firstCursor(p.args), p.getResult(), "createFormCursor");
                        }
                    });
                }
            });
            XposedBridge.hookAllMethods(cf, "readFromCursor", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    final MethodHookParam p = param;
                    safe("CloudFile.readFromCursor", new Body() {
                        @Override
                        public void run() {
                            Object[] a = p.args;
                            if (a == null || a.length < 2) {
                                return;
                            }
                            recordRow(a[0], a[1], "readFromCursor");
                        }
                    });
                }
            });
            // A dlink appearing on a CloudFile is the single strongest signal that the app has
            // just resolved "where to fetch this file from" — i.e. the content channel is opening.
            XposedBridge.hookAllMethods(cf, "setDlink", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    final MethodHookParam p = param;
                    safe("CloudFile.setDlink", new Body() {
                        @Override
                        public void run() {
                            String url = p.args != null && p.args.length > 0
                                    ? String.valueOf(p.args[0]) : null;
                            if (url == null || "null".equals(url)) {
                                return;
                            }
                            Logx.i("[dlink] fsId=" + Reflectx.callLong(p.thisObject, "getFileId", -1L)
                                    + " name=" + Reflectx.callStr(p.thisObject, "getFileName")
                                    + " url=" + shortUrl(url));
                        }
                    });
                }
            });
            Logx.i("hooked CloudFile factories + setDlink");
        } catch (Throwable t) {
            note("hook CloudFile failed: " + t);
        }
    }

    /** The Cursor is always the first argument of the CloudFile factories. */
    private static Object firstCursor(Object[] args) {
        if (args == null || args.length == 0) {
            return null;
        }
        return args[0];
    }

    private static void recordRow(Object cursor, Object o, String from) {
        if (o == null || !o.getClass().getName().endsWith("CloudFile")) {
            return;
        }
        rememberCursor(cursor);
        long fsId = Reflectx.callLong(o, "getFileId", -1L);
        String path = Reflectx.callStr(o, "getFilePath");
        String name = Reflectx.callStr(o, "getFileName");
        String key = fsId + "|" + path + "|" + name;
        // Before the de-duplication guard: a directory is usually revisited many times, and the
        // vault test has to run on every pass, not only the first one.
        detectVault(path, name);
        if (!rowsSeen.add(key)) {
            return;
        }
        String line = "fsId=" + fsId
                + " dir=" + Reflectx.callBool(o, "isDir", false)
                + "/" + Reflectx.callBool(o, "isDirectory", false)
                + " dirType=" + Reflectx.callLong(o, "getDirectoryType", -1L)
                + " size=" + Reflectx.callLong(o, "getSize", -1L)
                + " mtime=" + Reflectx.callLong(o, "getServerMTime", -1L)
                + " md5=" + Reflectx.callStr(o, "getServerMD5")
                + " name=" + name
                + " path=" + path
                + "  <-" + from;
        if (rows.size() < MAX_ROWS) {
            rows.add(line);
        }
        Logx.i("[row] " + line);
    }

    /**
     * Learns the concrete Cursor class and its column names from the objects the app itself feeds
     * into {@code CloudFile}.
     *
     * <p>Hooking {@code android.database.AbstractCursor.getColumnNames} does not work — it is an
     * abstract method and LSPosed refuses (verified on device). The list's cursor is a custom
     * class anyway, so the reliable route is to ask the cursor we are handed.
     */
    private static void rememberCursor(Object cursor) {
        if (cursor == null) {
            return;
        }
        String cls = cursor.getClass().getName();
        if (cursorClasses.contains(cls)) {
            return;
        }
        String cols = "<none>";
        try {
            java.lang.reflect.Method m = cursor.getClass()
                    .getMethod("getColumnNames");
            Object r = m.invoke(cursor);
            if (r instanceof String[]) {
                cols = Arrays.toString((String[]) r);
            }
        } catch (Throwable t) {
            cols = "<" + t.getClass().getSimpleName() + ">";
        }
        if (cursorColumns.add(cls + " " + cols)) {
            cursorClasses.add(cls);
            Logx.i("[cursor] " + cls + " -> " + cols);
        }
    }

    // -------------------------------------------------------- Cursor -------

    /**
     * Column names of DB-backed cursors, as a complement to {@link #rememberCursor}.
     *
     * <p>{@code android.database.AbstractCursor} is deliberately absent: its
     * {@code getColumnNames} is abstract and LSPosed rejects the hook
     * ("Cannot hook abstract methods"), which was observed on device. The list's own cursor is a
     * custom class and is learned from {@code CloudFile} instead.
     */
    private static void hookCursorColumns() {
        String[] targets = {
                "android.database.CursorWrapper",
                "android.database.MatrixCursor",
                "android.database.sqlite.SQLiteCursor",
        };
        for (final String name : targets) {
            Class<?> c = XposedHelpers.findClassIfExists(name, null);
            if (c == null) {
                continue;
            }
            try {
                XposedBridge.hookAllMethods(c, "getColumnNames", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        safe(name + ".getColumnNames", new Body() {
                            @Override
                            public void run() {
                                Object r = param.getResult();
                                if (!(r instanceof String[])) {
                                    return;
                                }
                                String joined = Arrays.toString((String[]) r);
                                if (cursorColumns.add(joined)) {
                                    Logx.i("[cursor] " + Reflectx.typeOf(param.thisObject) + " -> " + joined);
                                }
                            }
                        });
                    }
                });
            } catch (Throwable t) {
                note("hook " + name + ".getColumnNames failed: " + t);
            }
        }
        Logx.i("hooked cursor column probes");
    }

    // ------------------------------------------------------- network -------

    /** Records outbound URLs so the dlink API endpoint can be identified from real traffic. */
    private static void hookNetwork() {
        Class<?> rb = XposedHelpers.findClassIfExists("okhttp3.Request$Builder", cl);
        if (rb == null) {
            note("okhttp3.Request$Builder not present in app classloader");
            return;
        }
        try {
            XposedBridge.hookAllMethods(rb, "build", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    safe("okhttp.Request$Builder.build", new Body() {
                        @Override
                        public void run() {
                            Object req = param.getResult();
                            Object u = Reflectx.call0(req, "url");
                            recordUrl(u == null ? null : u.toString());
                        }
                    });
                }
            });
            Logx.i("hooked okhttp3.Request$Builder.build");
        } catch (Throwable t) {
            note("hook okhttp build failed: " + t);
        }
    }

    private static void recordUrl(String url) {
        if (url == null || url.isEmpty()) {
            return;
        }
        String u = url.length() > 400 ? url.substring(0, 400) : url;
        if (!urlSeen.add(u) || urls.size() >= MAX_URLS) {
            return;
        }
        urls.add(u);
        if (u.contains("dlink") || u.contains("pcs") || u.contains("download")
                || u.contains("file") || u.contains("list")) {
            Logx.i("[url] " + u);
        }
    }

    // -------------------------------------------------- download channel ----

    /**
     * The content channel, approached from the outside.
     *
     * <p>Everything between "the app decides to fetch file X" and "the bytes are on disk" is
     * obfuscated ({@code _}, {@code __}, …), so instead of guessing which {@code __(String,
     * ResultReceiver)} means what, hook <em>every</em> method and constructor of the few classes
     * that own the pipeline and read the arguments off the wire. The name is taken from
     * {@code param.method}, so nothing here hard-codes an obfuscated identifier — which also means
     * this survives an app update.
     *
     * <p>There is no "hook every method of this class" helper: {@code hookAllMethods} takes a
     * method <em>name</em> and LSPosed rejects a null one outright
     * ({@code NullPointerException: methodName cannot be null} — observed on device, 16:33).
     * So each member is enumerated and passed to {@code hookMethod(Member, …)} individually, and
     * failures are counted per member rather than aborting the whole class. Abstract and native
     * members are skipped up front because the framework cannot hook them.
     */
    private static void hookDownloadPipeline() {
        String[] classes = {
                "com.baidu.netdisk.transfer.download.SingleFileDownloadHelper",
                "com.baidu.netdisk.transfer.download.SingleFileDownloadHelper$DownloadResultReceiver",
                "com.baidu.netdisk.transfer.task.DownloadTaskManager",
                "com.baidu.netdisk.file.download.component.apis.FDDownloadManagerApi",
                "com.baidu.netdisk.cloudp2p.component.provider.CloudP2pDlinkApi",
                "com.baidu.netdisk.transfer.transmitter.locate.LocateDownloadUrls",
                "com.baidu.netdisk.transfer.io.model.LocateDownloadResponse",
        };
        for (String name : classes) {
            Class<?> c = XposedHelpers.findClassIfExists(name, cl);
            if (c == null) {
                note("missing target: " + name);
                continue;
            }
            int hooked = 0;
            int skipped = 0;
            for (java.lang.reflect.Method m : c.getDeclaredMethods()) {
                int mod = m.getModifiers();
                if (java.lang.reflect.Modifier.isAbstract(mod)
                        || java.lang.reflect.Modifier.isNative(mod)) {
                    skipped++;
                    continue;
                }
                try {
                    XposedBridge.hookMethod(m, CHANNEL);
                    hooked++;
                } catch (Throwable t) {
                    skipped++;
                }
            }
            for (java.lang.reflect.Constructor<?> k : c.getDeclaredConstructors()) {
                try {
                    XposedBridge.hookMethod(k, CHANNEL);
                    hooked++;
                } catch (Throwable t) {
                    skipped++;
                }
            }
            if (hooked == 0) {
                note("no member hooked on " + name);
            }
            Logx.i("hooked download channel: " + name
                    + " (" + hooked + " members, " + skipped + " skipped)");
        }
    }

    private static final XC_MethodHook CHANNEL = new XC_MethodHook() {
        @Override
        protected void afterHookedMethod(MethodHookParam param) {
            final MethodHookParam p = param;
            safe("download channel", new Body() {
                @Override
                public void run() {
                    logChannel(p);
                }
            });
        }
    };

    private static void logChannel(XC_MethodHook.MethodHookParam p) {
        if (channelLogs.incrementAndGet() > MAX_CHANNEL_LOGS) {
            return;
        }
        StringBuilder sb = new StringBuilder("[dl] ");
        if (p.method != null) {
            sb.append(p.method.getDeclaringClass().getName()).append('.').append(p.method.getName());
        } else {
            sb.append("?");
        }
        sb.append('(').append(briefArgs(p.args)).append(')');
        if (p.hasThrowable()) {
            sb.append(" !! ").append(p.getThrowable());
        } else if (p.getResult() != null) {
            sb.append(" -> ").append(brief(p.getResult()));
        }
        Logx.i(sb.toString());
    }

    private static String briefArgs(Object[] args) {
        if (args == null || args.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < args.length; i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(brief(args[i]));
        }
        return sb.toString();
    }

    private static String brief(Object o) {
        if (o == null) {
            return "null";
        }
        if (o instanceof CharSequence) {
            String s = o.toString();
            return '"' + (s.length() > 200 ? s.substring(0, 200) + "…" : s) + '"';
        }
        if (o instanceof Number || o instanceof Boolean || o instanceof Character) {
            return o.toString();
        }
        return o.getClass().getName();
    }

    // ----------------------------------------------------------- vault -----

    /**
     * Turns "the listing contains these two file names" into "this directory is a vault".
     *
     * <p>Costs nothing: it reads data the app already produced. The only side effects are one log
     * line, one toast, and (once per process) a dump of the toolbar's real view tree.
     */
    private static void detectVault(String path, String name) {
        if (path == null || name == null) {
            return;
        }
        String dir;
        int slash = path.lastIndexOf('/');
        if (slash <= 0) {
            dir = "/";
        } else {
            dir = path.substring(0, slash);
        }

        boolean first;
        if ("vault.cryptomator".equals(name)) {
            first = dirsWithVaultFile.add(dir);
        } else if ("masterkey.cryptomator".equals(name)) {
            first = dirsWithMasterkeyFile.add(dir);
        } else {
            return;
        }
        if (!first) {
            return;
        }
        if (!dirsWithVaultFile.contains(dir) || !dirsWithMasterkeyFile.contains(dir)) {
            return;
        }
        if (!vaultsAnnounced.add(dir)) {
            return;
        }

        Logx.i("[vault] Cryptomator vault detected at " + dir);
        toast("BdCryptomator：检测到 Cryptomator 保险库\n" + dir);
        dumpToolbarTree("vault at " + dir);
    }

    /** A visible acknowledgement that the whole detect path ran, on the app's own UI. */
    private static void toast(final String msg) {
        final Context c = app;
        if (c == null) {
            return;
        }
        try {
            new android.os.Handler(android.os.Looper.getMainLooper()).post(new Runnable() {
                @Override
                public void run() {
                    try {
                        android.widget.Toast.makeText(c, msg, android.widget.Toast.LENGTH_LONG).show();
                    } catch (Throwable t) {
                        Logx.w("toast failed: " + t);
                    }
                }
            });
        } catch (Throwable t) {
            Logx.w("toast cannot be posted: " + t);
        }
    }

    /**
     * Prints the real view tree around {@code id/filter} as the app built it.
     *
     * <p>The static UI dump is not enough to place a button: it reports the accessibility tree, and
     * for this toolbar the reported parent ({@code LinearLayout id=container}) holds children whose
     * bounds do not stack the way a single LinearLayout would. The View tree — with each container's
     * class, orientation, child count, and the index and LayoutParams of the filter icon — is the
     * only thing that decides whether a sibling can be inserted safely.
     */
    private static void dumpToolbarTree(String why) {
        if (!toolbarDumped.compareAndSet(false, true)) {
            return;
        }
        try {
            Object f = lastFragment;
            if (f == null) {
                Logx.w("[toolbar] no fragment yet; will retry on next resume");
                toolbarDumped.set(false);
                return;
            }
            Object rv = Reflectx.call0(f, "getView");
            if (!(rv instanceof android.view.View)) {
                Logx.w("[toolbar] fragment view not available");
                toolbarDumped.set(false);
                return;
            }
            android.view.View root = (android.view.View) rv;
            int id = app == null ? -1 : app.getResources().getIdentifier("filter", "id", APP_PKG);
            if (id == -1) {
                Logx.w("[toolbar] R.id.filter not resolvable");
                return;
            }
            android.view.View v = root.findViewById(id);
            if (v == null) {
                Logx.w("[toolbar] id/filter not under the fragment view");
                toolbarDumped.set(false);
                return;
            }

            StringBuilder sb = new StringBuilder("[toolbar] view chain of id/filter (")
                    .append(why).append(")\n");
            android.view.View cur = v;
            for (int i = 0; cur != null && i < 8; i++) {
                android.view.ViewGroup.LayoutParams lp = cur.getLayoutParams();
                sb.append("  [").append(i).append("] ").append(cur.getClass().getName())
                        .append(" id=").append(idName(cur))
                        .append(" lp=").append(lp == null ? "null"
                                : lp.getClass().getSimpleName() + "(" + lp.width + "x" + lp.height + ")")
                        .append(" xy=").append((int) cur.getX()).append(',').append((int) cur.getY())
                        .append(" wh=").append(cur.getWidth()).append('x').append(cur.getHeight())
                        .append(" vis=").append(cur.getVisibility())
                        .append('\n');
                android.view.ViewParent p = cur.getParent();
                if (p instanceof android.view.ViewGroup) {
                    android.view.ViewGroup g = (android.view.ViewGroup) p;
                    sb.append("      parent=").append(g.getClass().getName())
                            .append(" id=").append(idName(g))
                            .append(" children=").append(g.getChildCount())
                            .append(" myIndex=").append(g.indexOfChild(cur));
                    if (g instanceof android.widget.LinearLayout) {
                        sb.append(" orientation=")
                                .append(((android.widget.LinearLayout) g).getOrientation());
                    }
                    if (g instanceof android.view.View) {
                        android.view.View gv = (android.view.View) g;
                        sb.append(" wh=").append(gv.getWidth()).append('x').append(gv.getHeight());
                        sb.append(" vis=").append(gv.getVisibility());
                    }
                    sb.append('\n');
                    for (int k = 0; k < g.getChildCount(); k++) {
                        android.view.View ck = g.getChildAt(k);
                        android.view.ViewGroup.LayoutParams klp = ck.getLayoutParams();
                        sb.append("        ").append(k).append(": ")
                                .append(ck.getClass().getSimpleName())
                                .append(" id=").append(idName(ck))
                                .append(" lp=").append(klp == null ? "null"
                                        : klp.getClass().getSimpleName()
                                                + "(" + klp.width + "x" + klp.height + ")")
                                .append('\n');
                    }
                }
                cur = (p instanceof android.view.View) ? (android.view.View) p : null;
            }
            Logx.i(sb.toString());
        } catch (Throwable t) {
            Logx.w("[toolbar] dump failed: " + t);
        }
    }

    private static String idName(android.view.View v) {
        try {
            int i = v.getId();
            if (i == android.view.View.NO_ID) {
                return "-";
            }
            if (app != null) {
                return app.getResources().getResourceEntryName(i);
            }
            return String.valueOf(i);
        } catch (Throwable t) {
            return "?";
        }
    }

    // -------------------------------------------------------- accessors ----

    public static String graphOfLastFragment() {
        Object f = lastFragment;
        if (f == null) {
            return "no FileTabListFragment seen yet — open the 文件 tab first";
        }
        return "last fragment (" + lastFragmentWhere + ")\n" + Reflectx.graph("lastFragment", f, 4);
    }

    public static String dumpCloudFiles() {
        StringBuilder sb = new StringBuilder("CloudFile rows captured: " + rows.size()
                + (rows.size() >= MAX_ROWS ? " (capped)" : "") + "\n");
        synchronized (rows) {
            for (String r : rows) {
                sb.append("  ").append(r).append('\n');
            }
        }
        return sb.toString();
    }

    public static String dumpCursorColumns() {
        StringBuilder sb = new StringBuilder("distinct cursor column sets: " + cursorColumns.size() + "\n");
        synchronized (cursorColumns) {
            for (String c : cursorColumns) {
                sb.append("  ").append(c).append('\n');
            }
        }
        return sb.toString();
    }

    public static String dumpHttpUrls() {
        StringBuilder sb = new StringBuilder("URLs observed: " + urls.size()
                + (urls.size() >= MAX_URLS ? " (capped)" : "") + "\n");
        synchronized (urls) {
            for (String u : urls) {
                sb.append("  ").append(u).append('\n');
            }
        }
        return sb.toString();
    }

    public static String stateSummary() {
        return "BdCryptomator state\n"
                + "  app context : " + (app == null ? "not captured" : "ok")
                + "\n  loader      : " + cl
                + "\n  fragment    : " + lastFragmentWhere + " " + Reflectx.typeOf(lastFragment)
                + "\n  adapters    : " + adapterClasses
                + "\n  rows        : " + rows.size()
                + "\n  cursor sets : " + cursorColumns.size()
                + "\n  urls        : " + urls.size()
                + "\n  vaults      : " + vaultsAnnounced
                + "\n  missing     : " + missingTargets;
    }

    // ---------------------------------------------------------- helpers ----

    private static void note(String s) {
        missingTargets.add(s);
        Logx.w("[target] " + s);
    }

    private static String truncate(String s, int n) {
        return s.length() <= n ? s : s.substring(0, n) + "\n... (" + s.length() + " chars total)";
    }

    private static String shortUrl(String u) {
        if (u == null || u.isEmpty()) {
            return "-";
        }
        int q = u.indexOf('?');
        return q > 0 ? u.substring(0, q) + "?…(" + u.length() + ")" : u;
    }

    interface Body {
        void run() throws Throwable;
    }

    /** Never let a probe bug become the app's crash. */
    private static void safe(String what, Body b) {
        try {
            b.run();
        } catch (Throwable t) {
            Logx.e("hook body failed: " + what, t);
        }
    }
}
