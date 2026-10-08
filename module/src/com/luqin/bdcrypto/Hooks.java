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

    /** The app's package: resource ids are resolved against it, and it is the target's identity. */
    static final String APP_PKG = "com.baidu.drive.app";

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

    /**
     * Directories proven to be vaults, and therefore directories the unlock button belongs in.
     *
     * <p>Separate from {@link #vaultsAnnounced}, which exists only to keep the log and the toast
     * honest at one per directory. The listing is re-delivered every time a directory is opened,
     * while the fragment view — and with it the button — is destroyed and rebuilt on every
     * navigation. So "is this a vault" has to be answerable without any per-directory first-time
     * bookkeeping, or the button appears once per process and never again.
     */
    private static final Set<String> vaultDirs =
            Collections.synchronizedSet(new HashSet<String>());

    /** Marks a view as ours, so "is the button already in this toolbar" needs no bookkeeping. */
    private static final Object TAG_UNLOCK = new Object();

    /**
     * One line describing the last injection attempt, for {@link #stateSummary()}.
     *
     * <p>There is deliberately no "the button" field any more. A page carries <em>two</em> toolbars
     * that both hold an {@code id/filter} — the live one inside {@code id/list_recycler_view} and a
     * second inside {@code id/empty_headers} — and the window holds more than one page at once
     * (measured: four {@code id/filter} across three page containers, two of which share a
     * breadcrumb). Which one is drawn on top is not something the module controls, so a single
     * remembered reference can only ever describe one of them, and "the button already exists"
     * decided from it was wrong most of the time. Identity now lives on the views themselves: every
     * injected child carries {@link #TAG_UNLOCK}, so each question — does this toolbar have a button,
     * remove it, restyle it — is asked of the toolbar it is about.
     */
    private static volatile String buttonSummary = "not injected";

    /** The last directory recognised as a vault, so the probe can re-inject on demand. */
    private static volatile String lastVaultDir;

    /**
     * The directory the drawn page is believed to be on — what the button is currently for, or null
     * when that page is not a vault.
     *
     * <p>Kept because a retry chain needs to know when to stop. Its whole purpose is to wait for one
     * particular page to finish settling, so the moment the drawn page is a different one the
     * question it is asking has no answer, and it can go.
     */
    private static volatile String lastWantedDir;

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
        hookBreadcrumb();
        hookCloudFileModel();
        hookCursorColumns();
        hookNetwork();
        hookDownloadPipeline();
        // P0-B. The pipeline hook above only renders arguments; this one keeps them, which is what
        // makes a replay possible at all (see Channel for why the objects cannot be built).
        Channel.install(cl);
        // P2's file page half: row text for an unlocked vault.
        VaultList.install(cl);
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
        if ("onDestroyView".equals(where)) {
            // The view tree (and the injected button with it) is thrown away here, so the summary
            // must not keep claiming a button that no longer exists.
            buttonSummary = "not injected (view destroyed)";
            armedButtons = 0;
            lastLoggedOutcome = null;
        }
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
        // A page being created or resumed is one of the few moments a directory can have changed,
        // and it costs a quarter-second-delayed tree read to be sure.
        reconcileSoon("fragment " + where);
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

    /**
     * Watches the breadcrumb for directory changes. This is the trigger the button lives on.
     *
     * <p>Chosen after the two obvious triggers were measured to be absent in the one case that
     * matters. Walking back from /crypto/content/d to /crypto/content produced <em>no</em>
     * CloudFile — the listing is served from cache, so nothing is constructed, so
     * {@link #detectVault} never runs — and <em>no</em> fragment lifecycle event, because the page
     * view is kept and merely re-fed. The breadcrumb is the one thing that always changes: its items
     * <em>are</em> the directory names.
     *
     * <p>Hooked on the class rather than on an instance because the app sets a fresh adapter on
     * every file page; hooking the class covers every one of them, including pages built later.
     */
    private static void hookBreadcrumb() {
        String name = "com.baidu.netdisk.ui.breadcrumb.BreadcrumbAdapter";
        Class<?> c = XposedHelpers.findClassIfExists(name, cl);
        if (c == null) {
            note("missing target: " + name);
            return;
        }
        try {
            XposedBridge.hookAllMethods(c, "onBindViewHolder", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    safe("BreadcrumbAdapter.onBindViewHolder", new Body() {
                        @Override
                        public void run() {
                            // Once per crumb item, so two or three times per directory change; the
                            // pending flag in reconcileSoon collapses them into one pass.
                            reconcileSoon("breadcrumb bound");
                        }
                    });
                }
            });
            Logx.i("hooked " + name + " for directory changes");
        } catch (Throwable t) {
            note("hook " + name + " failed: " + t);
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
        Channel.noteFile(o);
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
     *
     * <p>Deliberately knows nothing about buttons beyond asking for a reconcile. The set of vault
     * directories is the one thing that has to be learned from the rows; whether a button should be
     * on screen right now is a question about the breadcrumb, and {@link #reconcile} answers it.
     */
    private static void detectVault(String path, String name) {
        if (path == null || name == null) {
            return;
        }
        String dir = dirOf(path);

        // Fast path: this directory is already known to be a vault, so the listing now arriving is
        // the app re-opening it. The view was rebuilt, so the button has to be put back.
        if (vaultDirs.contains(dir)) {
            noteVaultDir(dir);
            return;
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

        vaultDirs.add(dir);
        if (vaultsAnnounced.add(dir)) {
            Logx.i("[vault] Cryptomator vault detected at " + dir);
            toast("BdCryptomator：检测到 Cryptomator 保险库\n" + dir);
            dumpToolbarTree("vault at " + dir);
        }
        noteVaultDir(dir);
    }

    /** The directory a path lives in, treating a shallower path as root. */
    private static String dirOf(String path) {
        int slash = path.lastIndexOf('/');
        return slash <= 0 ? "/" : path.substring(0, slash);
    }

    /**
     * Asks one page's list to bind its rows again.
     *
     * <p>Deferred with {@code post}: {@code notifyDataSetChanged} throws if the RecyclerView is in
     * the middle of a layout pass, and this runs from a timer that cannot know that.
     */
    private static void rebindRows(final android.view.View page) {
        if (page == null || app == null) {
            return;
        }
        final int id = app.getResources().getIdentifier("list_recycler_view", "id", APP_PKG);
        if (id == 0) {
            return;
        }
        final android.view.View list = page.findViewById(id);
        if (list == null) {
            return;
        }
        page.post(new Runnable() {
            @Override
            public void run() {
                try {
                    Object adapter = Reflectx.call0(list, "getAdapter");
                    if (adapter != null) {
                        Reflectx.call0(adapter, "notifyDataSetChanged");
                    }
                } catch (Throwable t) {
                    Logx.w("[list] rebind failed: " + t);
                }
            }
        });
    }

    /** Whether a reconcile is already queued; a burst of triggers collapses into one pass. */
    private static final java.util.concurrent.atomic.AtomicBoolean reconcilePending =
            new java.util.concurrent.atomic.AtomicBoolean();

    /**
     * Queues one {@link #reconcile()} shortly.
     *
     * <p>The delay is what lets a directory change settle before it is judged. Arriving somewhere
     * fires this from the breadcrumb's rebind, from the first CloudFile row and from the fragment's
     * resume, all while the app is still swapping pages; acting on the first of those would read the
     * breadcrumb of the directory being <em>left</em>. One pending pass is enough — later triggers
     * only move it, and the pass re-reads the tree from scratch.
     */
    static void reconcileSoon(final String why) {
        if (reconcilePending.getAndSet(true)) {
            return;
        }
        try {
            new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(new Runnable() {
                @Override
                public void run() {
                    reconcilePending.set(false);
                    try {
                        reconcile(why);
                    } catch (Throwable t) {
                        Logx.w("[button] reconcile failed: " + t);
                    }
                }
            }, 250);
        } catch (Throwable t) {
            reconcilePending.set(false);
        }
    }

    /**
     * Makes the toolbar match the directory the window is <em>drawing</em> — the whole of the
     * button's state, derived from one readable fact rather than from a stream of events.
     *
     * <p>Deriving it is not a stylistic choice; the events are unreliable in both directions.
     * Measured: walking back from /crypto/content/d to /crypto/content produced <em>no</em>
     * CloudFile at all (the listing is served from cache), <em>no</em> fragment lifecycle event (the
     * page view is kept alive), and therefore no button — the only trigger was a row being
     * constructed. Measured the other way: walking <em>into</em> /crypto/content/d left the vault
     * page in the window still wearing its button, because nothing notices a directory that has
     * merely stopped being listed.
     *
     * <p>The fact that is always right is the breadcrumb, so it is what this reads: the drawn page's
     * crumb names the directory, the button belongs there and nowhere else, and everything else —
     * the other page copies, the empty-state toolbar, the pages left behind — is swept.
     */
    private static void reconcile(String why) {
        final Context ctx = app;
        if (ctx == null) {
            return;
        }
        final int idFilter = ctx.getResources().getIdentifier("filter", "id", APP_PKG);
        final int idCrumb = ctx.getResources().getIdentifier("rv_breadcrumb", "id", APP_PKG);
        java.util.List<android.view.View> copies = allCopies(idFilter);
        if (copies.isEmpty()) {
            return;
        }

        // Which directory is the drawn page on? Among the pages in the window, the drawn one is the
        // last, and that is not interchangeable with the first.
        //
        // Measured: the app moves the current page's container to the end of its parent's child list
        // — the same container reported itself as child 1 of 3 while another page was on top and as
        // child 2 of 3 once it became current — and a later sibling draws over an earlier one. View
        // order in a depth-first walk is child order, so the last copy found is the top page.
        //
        // isShown() alone cannot answer this and says so loudly: measured, the page behind reports
        // shown=true as well, because it is VISIBLE and attached and merely painted over. Taking the
        // first shown copy therefore picked the page <em>behind</em> — /crypto while the user was
        // looking at /crypto/content — read it as "not a vault", and swept the button away.
        String drawn = null;
        android.view.View drawnCopy = null;
        for (int i = copies.size() - 1; i >= 0; i--) {
            android.view.View f = copies.get(i);
            if (!f.isShown()) {
                continue;
            }
            String crumb = crumbPathOf(f, idFilter, idCrumb);
            if (crumb != null) {
                drawn = crumb;
                drawnCopy = f;
                break;
            }
        }
        if (drawn == null) {
            // Nothing readable: mid-transition, or the app is somewhere else entirely. Leaving the
            // tree alone is the safe answer — the next trigger is at most a quarter second away.
            return;
        }

        String vault = vaultDirMatching(drawn);
        lastWantedDir = vault;
        // The rows of this page may already have been bound before the breadcrumb told us where the
        // page is, so a change of directory is what asks the list to bind them again — otherwise the
        // decrypted names would only appear once the user scrolled.
        if (VaultList.noteDrawnPath(drawn)) {
            rebindRows(drawnCopy);
        }
        if (vault != null) {
            // Restricted to the drawn page's own subtree. The window can hold two containers that
            // both show the same directory — measured, four copies over two containers, each
            // reporting shown=true — and without this both get a button, at the same coordinates,
            // one painted over the other. They are different pages, so the page root tells them
            // apart where the breadcrumb, the bounds and isShown() all agree.
            Logx.i("[button] " + attachUnlockButtons(vault, null, null, null,
                    why + ", drawn page is " + drawn,
                    pageRootOf(drawnCopy, idFilter, idCrumb)));
        } else {
            sweepAllOurButtons(why + ", drawn page is " + drawn);
        }
    }

    /** The known vault directory that {@code crumb} names, or null. Longest match wins. */
    private static String vaultDirMatching(String crumb) {
        String best = null;
        for (String d : vaultDirs) {
            if (samePath(crumb, d) && (best == null || d.length() > best.length())) {
                best = d;
            }
        }
        return best;
    }

    /**
     * Takes this module's button out of every toolbar copy in the window. Main thread.
     *
     * <p>Every copy, not just the drawn one: a page that has merely stopped being listed is still in
     * the window, and a button left on it is a button that reappears the moment the app brings that
     * page back. Measured — entering /crypto/content/d from the vault kept the vault page and its
     * button in the window, invisible but present in the accessibility tree at [641,398][767,470].
     */
    private static int sweepAllOurButtons(final String why) {
        final Context ctx = app;
        if (ctx == null) {
            return 0;
        }
        int idFilter = ctx.getResources().getIdentifier("filter", "id", APP_PKG);
        java.util.List<android.view.View> parents = new java.util.ArrayList<android.view.View>();
        for (android.view.View c : allCopies(idFilter)) {
            android.view.ViewParent p = c.getParent();
            if (p instanceof android.view.ViewGroup && !parents.contains(p)) {
                parents.add((android.view.View) p);
            }
        }
        int n = 0;
        for (android.view.View p : parents) {
            n += removeOurChildren((android.view.ViewGroup) p);
        }
        if (n > 0) {
            armedButtons = 0;
            buttonSummary = "swept " + n + " button(s) off (" + why + ")";
            logOnce(buttonSummary);
        }
        return n;
    }

    /**
     * A vault directory has been recognised: remember it for the probe, and re-derive the button.
     *
     * <p>Called from the row path, which runs on the app's loader thread, so nothing here touches a
     * view — a listing must never wait on us. The reconcile that does the work is posted.
     */
    private static void noteVaultDir(String dir) {
        lastVaultDir = dir;
        reconcileSoon("vault at " + dir);
    }

    /** A visible acknowledgement that the whole detect path ran, on the app's own UI. */
    static void toast(final String msg) {
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

    // ----------------------------------------------------------- button ----

    private static final String BUTTON_LABEL = "解锁";

    /** The same button once the vault is open. It locks it again, so it says so. */
    private static final String BUTTON_LABEL_UNLOCKED = "还原";

    /**
     * What the button on a page showing {@code pagePath} should read.
     *
     * <p>The label is state, not a constant: the same view unlocks a locked vault and re-locks an
     * open one. Leaving it at "解锁" while the vault is already open made the button look like the
     * first click had not worked. A probe override still wins — it exists precisely to try labels
     * the module would not pick by itself.
     */
    private static String buttonLabelFor(String pagePath, String override) {
        if (override != null && !override.isEmpty()) {
            return override;
        }
        return VaultUi.isUnlockedFor(pagePath) ? BUTTON_LABEL_UNLOCKED : BUTTON_LABEL;
    }

    /**
     * {@code btn} probe command: {@code off} removes the button from every page copy, {@code diag}
     * reports what each copy is showing and what is in it, anything else (re)injects it.
     *
     * <p>Optional overrides, comma separated: {@code w=<px>} (width), {@code size=<sp>} (text size),
     * {@code text=<label>}. They exist because the button's geometry has to be judged against the
     * real toolbar, and a module reinstall is far too slow a feedback loop for that.
     */
    public static String buttonCommand(String arg) {
        String a = arg == null ? "" : arg.replace(" ", "");
        if ("off".equalsIgnoreCase(a) || "rm".equalsIgnoreCase(a) || "0".equals(a)) {
            String r = detachUnlockButtons("probe");
            return r;
        }
        if ("diag".equalsIgnoreCase(a) || "copies".equalsIgnoreCase(a)) {
            return copiesReport("probe");
        }
        Integer w = null;
        Integer size = null;
        String label = null;
        for (String kv : a.split(",")) {
            if (kv.isEmpty()) {
                continue;
            }
            int eq = kv.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String k = kv.substring(0, eq);
            String v = kv.substring(eq + 1);
            try {
                if ("w".equals(k)) {
                    w = Integer.valueOf(v);
                } else if ("size".equals(k)) {
                    size = Integer.valueOf(v);
                } else if ("text".equals(k)) {
                    label = v;
                }
            } catch (Throwable ignored) {
                // a malformed override must not fail the whole command
            }
        }
        // The caller (the probe) logs the returned line, so this deliberately does not. lastWantedDir
        // is set here too, so a retry chain this starts knows what it is waiting for.
        lastWantedDir = lastVaultDir;
        return injectUnlockButtons(lastVaultDir, label, w, size, "probe");
    }

    /**
     * Runs one attach on the main thread and hands back its line. Used by the {@code btn} probe,
     * which is the only caller that wants the answer; everything else goes through {@link #reconcile}
     * and does not care.
     */
    private static String injectUnlockButtons(final String vaultDir, final String label,
                                              final Integer widthPx, final Integer sizeSp,
                                              final String why) {
        if (app == null) {
            return "no app context yet (" + why + ")";
        }
        return onMain(new Call() {
            @Override
            public String run() {
                return attachUnlockButtons(vaultDir, label, widthPx, sizeSp, why, null);
            }
        }, "attach " + why);
    }

    /**
     * Takes the button back out of every copy of the file page, for the {@code btn off} probe.
     *
     * <p>Emptying the whole window is the point: "which copy did I put it in" is exactly the
     * question that produced an invisible button, and the answer is not worth remembering when
     * finding every copy takes one traversal.
     */
    private static String detachUnlockButtons(final String why) {
        return onMain(new Call() {
            @Override
            public String run() {
                int n = sweepAllOurButtons(why);
                if (n == 0) {
                    buttonSummary = "not injected";
                    lastLoggedOutcome = buttonSummary;
                    return buttonSummary;
                }
                return buttonSummary;
            }
        }, "remove " + why);
    }

    /** Every copy of {@code id} in the current window, in draw order; empty when not measurable. */
    private static java.util.List<android.view.View> allCopies(int id) {
        java.util.List<android.view.View> out = new java.util.ArrayList<android.view.View>();
        if (id == 0) {
            return out;
        }
        android.app.Activity act = activityOf(lastFragment);
        android.view.View decor = act == null || act.getWindow() == null
                ? null : act.getWindow().getDecorView();
        collectById(decor, id, out);
        if (out.isEmpty()) {
            android.view.View fv = fragmentViewOf(lastFragment);
            if (fv != null) {
                android.view.View one = fv.findViewById(id);
                if (one != null) {
                    out.add(one);
                }
            }
        }
        return out;
    }

    /** Removes every child of {@code parent} that carries {@link #TAG_UNLOCK}. */
    private static int removeOurChildren(android.view.ViewGroup parent) {
        int n = 0;
        for (int i = parent.getChildCount() - 1; i >= 0; i--) {
            android.view.View c = parent.getChildAt(i);
            if (c.getTag() == TAG_UNLOCK) {
                parent.removeViewAt(i);
                n++;
            }
        }
        return n;
    }

    /**
     * The view surgery itself. Runs on the main thread; returns a one-line outcome on every path.
     *
     * <p>The window holds two complete copies of the file page at once and either can be the one
     * being drawn, so this reasons per copy rather than picking one:
     *
     * <ol>
     *   <li>enumerate every {@code id/filter} in the window,</li>
     *   <li>ask each copy which directory <em>it</em> is showing — from its own breadcrumb, since
     *       class, ids and bounds are identical between copies and only the crumbs differ,</li>
     *   <li>put the button in the copies showing the vault, and take it out of the others.</li>
     * </ol>
     *
     * <p>Styling is deliberately explicit rather than inherited. The first version copied its text
     * colour from a sibling and was measured on screen as <em>#FFFFFF on #FFFFFF</em> — present in
     * the accessibility tree, clickable, and invisible. A fixed blue pill with white text cannot
     * fail that way, and it matches the app's own selected chip.
     */
    private static String attachUnlockButtons(final String vaultDir, final String label,
                                              final Integer widthPx, final Integer sizeSp,
                                              final String why, final android.view.View pageRoot) {
        // Reset up front, not at the end: every early return below is a "nothing was armed" answer,
        // and a stale count would make the retry chain believe it had already succeeded.
        armedButtons = 0;
        final Context ctx = app;
        if (ctx == null) {
            return "no app context (" + why + ")";
        }
        final int idFilter = ctx.getResources().getIdentifier("filter", "id", APP_PKG);
        if (idFilter == 0) {
            return "R.id.filter is not resolvable (" + why + ")";
        }
        final int idFilterLabel =
                ctx.getResources().getIdentifier("filter_dialog_enter", "id", APP_PKG);
        final int idCrumb = ctx.getResources().getIdentifier("rv_breadcrumb", "id", APP_PKG);
        final int idSort = ctx.getResources().getIdentifier("sort", "id", APP_PKG);

        java.util.List<android.view.View> copies = allCopies(idFilter);
        if (copies.isEmpty()) {
            if (scheduleShownRetry(vaultDir, label, widthPx, sizeSp, why, pageRoot)) {
                return "no id/filter anywhere yet; retrying (" + why + ")";
            }
            return "id/filter is not in the current file page view (" + why + ")";
        }

        // Which copy is a page of the vault directory? Only the breadcrumb can say, and it says it
        // per copy: measured, the copy showing /crypto/content holds crumbs [crypto, content] while
        // the copy behind it holds [crypto].
        StringBuilder sb = new StringBuilder();
        int wanted = 0;
        final boolean[] isTarget = new boolean[copies.size()];
        final String[] paths = new String[copies.size()];
        for (int i = 0; i < copies.size(); i++) {
            paths[i] = crumbPathOf(copies.get(i), idFilter, idCrumb);
            boolean mine = pageRoot == null
                    || pageRootOf(copies.get(i), idFilter, idCrumb) == pageRoot;
            if (mine && paths[i] != null
                    && (vaultDir == null || samePath(paths[i], vaultDir))) {
                isTarget[i] = true;
                wanted++;
            }
        }

        // A page of the vault is not one toolbar but two: the live one inside id/list_recycler_view,
        // and a second inside id/empty_headers that the app keeps GONE whenever the list has rows.
        // Both resolve to the same directory — measured, both sit under the same
        // RelativeLayout#root with crumbs=1 — so attributing by directory alone still picks the
        // off-screen one as well, and a button placed there is invisible: present in the tree,
        // shown=false, zero-size, and simply not on screen. Only the drawn copy gets the button.
        for (int i = 0; i < copies.size(); i++) {
            if (isTarget[i] && !copies.get(i).isShown()) {
                isTarget[i] = false;
                wanted--;
            }
        }
        int placed = 0, removed = 0, kept = 0;
        if (wanted == 0) {
            // Either no copy has settled on the vault yet (the listing arrives while the page still
            // belongs to the directory just left, so every breadcrumb is a valid but wrong answer),
            // or the matching copy is not laid out yet. Neither justifies injecting into a copy that
            // cannot be seen — that is what produced an invisible button — so retry instead. What it
            // does justify is clearing out any button left from before, which the loop below does
            // because no copy is a target.
            for (int i = 0; i < copies.size(); i++) {
                android.view.ViewParent vp = copies.get(i).getParent();
                if (vp instanceof android.view.ViewGroup) {
                    removed += removeOurChildren((android.view.ViewGroup) vp);
                }
            }
            buttonSummary = "placed=0 kept=0 removed=" + removed
                    + " of " + copies.size() + " copy/copies (none is " + vaultDir + ")";
            lastLoggedOutcome = buttonSummary;
            boolean retried = scheduleShownRetry(vaultDir, label, widthPx, sizeSp, why, pageRoot);
            return buttonSummary + " (of " + java.util.Arrays.toString(paths) + ")"
                    + (retried ? "; retrying" : "") + " (" + why + ")";
        }
        for (int i = 0; i < copies.size(); i++) {
            android.view.View filter = copies.get(i);
            android.view.ViewParent vp = filter.getParent();
            if (!(vp instanceof android.view.ViewGroup)) {
                sb.append("copy ").append(i).append(": id/filter has no ViewGroup parent; ");
                continue;
            }
            android.view.ViewGroup parent = (android.view.ViewGroup) vp;
            if (!isTarget[i]) {
                int n = removeOurChildren(parent);
                removed += n;
                sb.append("copy ").append(i).append(": ").append(paths[i]).append(" no button")
                        .append(n == 0 ? "" : " (removed " + n + ")").append("; ");
                continue;
            }
            // The "筛选" control is a two-view group, not one view: id/filter_dialog_enter is the
            // label and id/filter is the icon, flush against each other as a single tap target.
            // Anchoring on id/filter would drop the button between the word and its own icon and
            // split the app's control in half, so the anchor is whichever of the two comes first
            // in the row. Both are looked up among *this* copy's siblings, never window-wide.
            int myIdx = parent.indexOfChild(filter);
            android.view.View anchor = null;
            for (int k = 0; k < myIdx; k++) {
                android.view.View ck = parent.getChildAt(k);
                if (idFilterLabel != 0 && ck.getId() == idFilterLabel) {
                    anchor = ck;
                    break;
                }
            }
            if (anchor == null) {
                anchor = filter;
            }

            android.view.View existing = ourChild(parent);
            if (existing != null) {
                if (existing.getParent() != parent) {
                    existing = null;
                }
            }
            // Resolved here, not inside buildButton/restyle: it decides what the button *means* on
            // this page, and both the fresh and the kept path have to agree on it.
            final String effLabel = buttonLabelFor(paths[i], label);
            if (existing != null) {
                restyle(existing, effLabel, sizeSp);
                kept++;
                sb.append("copy ").append(i).append(": ").append(paths[i]).append(" already has it")
                        .append(" at ").append(absRect(existing)).append(" alpha=")
                        .append(existing.getAlpha()).append(" color=")
                        .append(Integer.toHexString(((android.widget.TextView) existing)
                                .getCurrentTextColor())).append("; ");
                continue;
            }

            android.widget.TextView b = buildButton(anchor, idSort, effLabel, widthPx, sizeSp);
            int at = parent.indexOfChild(anchor);
            parent.addView(b, at, pillParams(anchor.getLayoutParams(), widthPx, b, parent));
            b.setOnClickListener(new android.view.View.OnClickListener() {
                @Override
                public void onClick(android.view.View v) {
                    // One button, two actions, decided at click time rather than at attach time:
                    // the page can be locked, unlocked and re-locked without the view being rebuilt.
                    if (VaultUi.relock(vaultDir)) {
                        Logx.i("[button] clicked -> 还原 for " + vaultDir);
                        return;
                    }
                    Logx.i("[button] clicked -> passphrase dialog for " + vaultDir);
                    // The button's own context IS the page's activity, which is what a dialog
                    // needs; the application context has no window token and throws.
                    VaultUi.onUnlockClicked(v.getContext(), vaultDir);
                }
            });
            placed++;
            sb.append("copy ").append(i).append(": ").append(paths[i]).append(" placed at at=")
                    .append(at).append('/').append(parent.getChildCount())
                    .append(" parent=").append(parent.getClass().getSimpleName())
                    .append(" id=").append(idName(parent))
                    .append(" wh=").append(parent.getWidth()).append('x').append(parent.getHeight())
                    .append(" anchor=").append(anchor == filter ? "filter" : "filter_dialog_enter")
                    .append("; ");
            watchForOverflow(parent, b, why);
        }

        buttonSummary = "placed=" + placed + " kept=" + kept + " removed=" + removed
                + " of " + copies.size() + " copy/copies of " + vaultDir;
        armedButtons = placed + kept;
        return buttonSummary + " " + sb + "(" + why + ")";
    }

    /** The child of {@code parent} this module injected, or null. */
    private static android.view.View ourChild(android.view.ViewGroup parent) {
        for (int i = 0; i < parent.getChildCount(); i++) {
            android.view.View c = parent.getChildAt(i);
            if (c.getTag() == TAG_UNLOCK) {
                return c;
            }
        }
        return null;
    }

    /** The last outcome already written to the log; an identical repeat is dropped. */
    private static volatile String lastLoggedOutcome;

    /**
     * Logs {@code line} unless it repeats the previous one.
     *
     * <p>The listing path asks for the button once per CloudFile row, so a twenty-row directory
     * produced twenty identical lines on every refresh and buried the rest of the module log.
     * Suppressing exact repeats loses nothing: a change — a button finally landing, one being
     * removed — is by definition a different line.
     */
    private static void logOnce(String line) {
        if (line == null || line.equals(lastLoggedOutcome)) {
            return;
        }
        lastLoggedOutcome = line;
        Logx.i("[button] " + line);
    }

    /**
     * A pill with hard-coded colours and radius.
     *
     * <p>Every visual property used to be inherited from the app's own toolbar "so it follows the
     * theme for free". It did not: the button was measured on screen as white text on a white row,
     * which the accessibility tree and a click handler both happily report as present. Legibility
     * is not something to delegate to a theme whose text colour the module cannot see.
     */
    private static android.widget.TextView buildButton(android.view.View anchor, int idSort,
                                                       String label, Integer widthPx,
                                                       Integer sizeSp) {
        Context themed = anchor.getContext() != null ? anchor.getContext() : app;
        android.widget.TextView b = new android.widget.TextView(themed);
        b.setTag(TAG_UNLOCK);
        // `label` is already resolved by buttonLabelFor — this only guards the probe passing "".
        b.setText(label != null && !label.isEmpty() ? label : BUTTON_LABEL);
        b.setSingleLine(true);
        b.setClickable(true);
        b.setGravity(android.view.Gravity.CENTER);
        b.setTextColor(0xFFFFFFFF);
        b.setAlpha(1f);

        float density = themed.getResources().getDisplayMetrics().density;
        float sizePx;
        if (sizeSp != null) {
            b.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, sizeSp.intValue());
            sizePx = b.getTextSize();
        } else {
            float inherited = sortTextSizePx(anchor, idSort);
            sizePx = inherited > 0 ? inherited
                    : android.util.TypedValue.applyDimension(android.util.TypedValue.COMPLEX_UNIT_SP,
                            13f, themed.getResources().getDisplayMetrics());
            b.setTextSize(android.util.TypedValue.COMPLEX_UNIT_PX, sizePx);
        }
        int padX = Math.round(Math.max(sizePx * 0.7f, 10f * density));
        b.setPadding(padX, 0, padX, 0);

        // Parked on a fixed dp height rather than the anchor's, so the pill reads as a pill instead
        // of a full-height block: the row is 30 dp and the app's own controls are ~30 dp tall.
        int h = Math.round(26f * density);
        android.graphics.drawable.GradientDrawable g = new android.graphics.drawable.GradientDrawable();
        g.setShape(android.graphics.drawable.GradientDrawable.RECTANGLE);
        g.setColor(0xFF4E6EF2);
        g.setCornerRadius(h / 2f);
        b.setBackground(new android.graphics.drawable.RippleDrawable(
                android.content.res.ColorStateList.valueOf(0x40FFFFFF), g, null));
        b.setMinimumHeight(0);
        b.setMinHeight(0);
        return b;
    }

    /** The laid-out text size of the app's own {@code id/sort} label, or 0 when it cannot be read. */
    private static float sortTextSizePx(android.view.View anchor, int idSort) {
        try {
            if (idSort == 0 || !(anchor.getParent() instanceof android.view.ViewGroup)) {
                return 0f;
            }
            android.view.ViewGroup pg = (android.view.ViewGroup) anchor.getParent();
            for (int k = 0; k < pg.getChildCount(); k++) {
                android.view.View ck = pg.getChildAt(k);
                if (ck.getId() == idSort && ck instanceof android.widget.TextView) {
                    return ((android.widget.TextView) ck).getTextSize();
                }
            }
        } catch (Throwable ignored) {
            // falling back to 13 sp is fine
        }
        return 0f;
    }

    /** Wraps {@code b} in LayoutParams matching the parent's own type, height fixed, no weight. */
    private static android.view.ViewGroup.LayoutParams pillParams(
            android.view.ViewGroup.LayoutParams src, Integer widthPx, android.widget.TextView b,
            android.view.ViewGroup parent) {
        int w = widthPx != null ? widthPx.intValue()
                : android.view.ViewGroup.LayoutParams.WRAP_CONTENT;
        int h = b.getMinHeight() > 0 ? b.getMinHeight() : android.view.ViewGroup.LayoutParams.WRAP_CONTENT;
        float density = b.getContext().getResources().getDisplayMetrics().density;
        h = Math.round(26f * density);
        // weight is deliberately not copied from the anchor: if the anchor were weight-sized and we
        // copied it, an extra child would silently re-split the row and shrink the existing icons.
        if (src instanceof android.widget.LinearLayout.LayoutParams) {
            android.widget.LinearLayout.LayoutParams n =
                    new android.widget.LinearLayout.LayoutParams(w, h);
            n.gravity = android.view.Gravity.CENTER_VERTICAL;
            n.leftMargin = Math.round(6f * density);
            n.rightMargin = Math.round(6f * density);
            return n;
        }
        if (src instanceof android.widget.FrameLayout.LayoutParams) {
            return new android.widget.FrameLayout.LayoutParams(w, h,
                    android.view.Gravity.CENTER_VERTICAL);
        }
        return new android.view.ViewGroup.LayoutParams(w, h);
    }

    /** Re-labels / re-sizes a button already in place, so the probe can restyle without a rebuild. */
    private static void restyle(android.view.View v, String label, Integer sizeSp) {
        if (!(v instanceof android.widget.TextView)) {
            return;
        }
        android.widget.TextView t = (android.widget.TextView) v;
        if (label != null && !label.isEmpty()) {
            t.setText(label);
        }
        if (sizeSp != null) {
            t.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, sizeSp.intValue());
        }
    }

    /**
     * The directory a copy of the file page is showing, as "/a/b", or null when unknowable.
     *
     * <p>This is the only thing that distinguishes one page from another, because the pages are
     * otherwise identical: measured, every {@code id/filter} in the window has the same class, the
     * same ancestors' ids and the same bounds, so geometry and view type cannot tell them apart.
     * Only the breadcrumb can, and only if it is read from the page's own subtree.
     *
     * <p>Measured, the crumbs carry the drawer root as well — a page at /crypto/content reads
     * "我的网盘/crypto/content" — so the result is matched by suffix, not equality.
     */
    private static String crumbPathOf(android.view.View filter, int idFilter, int idCrumb) {
        if (idCrumb == 0) {
            return null;
        }
        android.view.View page = pageRootOf(filter, idFilter, idCrumb);
        if (page == null) {
            return null;
        }
        android.view.View crumb = page.findViewById(idCrumb);
        if (crumb == null) {
            return null;
        }
        List<String> names = new ArrayList<String>();
        collectTexts(crumb, names);
        if (names.isEmpty()) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (String n : names) {
            sb.append('/').append(n);
        }
        return sb.toString();
    }

    /**
     * The root of the page {@code v} belongs to: the innermost ancestor that contains exactly one
     * {@code id/rv_breadcrumb}.
     *
     * <p>Climbing until the <em>breadcrumb</em> count reaches one is what keeps the search inside a
     * single page, and it is not the same rule as counting {@code id/filter}.
     *
     * <p>The obvious rule — climb while the ancestor holds exactly one {@code id/filter} — was
     * measured to stop one level too low. A page carries <em>two</em> toolbars, not one: the live
     * one inside {@code id/list_recycler_view}, and a second inside {@code id/empty_headers} that the
     * app draws while the list is empty. Both contain an {@code id/filter}, so the enclosing
     * {@code RelativeLayout#root} contains two, and the climb stopped at the container above the
     * toolbar — a level that holds {@code crumbs=0}. The breadcrumb lookup then returned null for
     * every copy, so nothing could be attributed and no button was ever placed.
     *
     * <p>Measured per copy, with the crumbs in place the climb terminates at
     * {@code RelativeLayout#root} ({@code kids=13 filters=2 crumbs=1}) for both the live and the
     * empty-state toolbar, which is exactly right: those two belong to the <em>same</em> page and
     * must resolve to the same directory. Climbing further would reach a
     * {@code ConstraintLayout} holding several pages at once ({@code filters=4 crumbs=2}) and
     * {@code findViewById} from there could return another page's breadcrumb.
     */
    private static android.view.View pageRootOf(android.view.View v, int idFilter, int idCrumb) {
        if (idCrumb != 0) {
            android.view.View byCrumb = climbTo(v, idCrumb, true);
            if (countById(byCrumb, idCrumb, 2) == 1) {
                return byCrumb;
            }
        }
        // No breadcrumb above this toolbar — another app build, or a page that has none. Fall back
        // to the filter count, which at least stops before the ancestor holding two pages. It
        // returns a level without crumbs, so attribution yields null and no button is placed: the
        // honest outcome, since without a breadcrumb there is nothing to attribute a copy to.
        return climbTo(v, idFilter, false);
    }

    /**
     * The ancestor of {@code v} that holds exactly one view with {@code id}.
     *
     * <p>{@code innermost} selects which of the two, and they are genuinely different questions.
     * Counting breadcrumbs wants the innermost level with exactly one — the smaller the subtree, the
     * less chance {@code findViewById} wanders into a neighbouring page. Counting toolbars wants the
     * outermost, because the toolbar itself sits in a chain of single-toolbar containers and the
     * interesting level is the last one before the count jumps.
     *
     * <p>Climbing stops at the first ancestor holding two, so the returned view never spans two
     * pages. Reads at most {@code 2} of each id, so this is O(ancestors) rather than O(tree).
     */
    private static android.view.View climbTo(android.view.View v, int id, boolean innermost) {
        android.view.View last = v;
        android.view.ViewParent p = v.getParent();
        int guard = 0;
        while (p instanceof android.view.ViewGroup && guard++ < 40) {
            android.view.ViewGroup g = (android.view.ViewGroup) p;
            int n = countById(g, id, 2);
            if (n > 1) {
                break;
            }
            if (n == 1 && innermost) {
                return g;
            }
            last = g;
            p = g.getParent();
        }
        return last;
    }

    /** Non-empty texts under {@code v}, depth-first, in draw order. */
    private static void collectTexts(android.view.View v, List<String> out) {
        if (v == null || out.size() >= 24) {
            return;
        }
        if (v instanceof android.widget.TextView) {
            CharSequence t = ((android.widget.TextView) v).getText();
            if (t != null && t.length() > 0) {
                out.add(t.toString().trim());
            }
        }
        if (v instanceof android.view.ViewGroup) {
            android.view.ViewGroup g = (android.view.ViewGroup) v;
            for (int i = 0; i < g.getChildCount(); i++) {
                collectTexts(g.getChildAt(i), out);
            }
        }
    }

    /** Depth-first count of views with {@code id}, stopping at {@code cap}. */
    private static int countById(android.view.View v, int id, int cap) {
        if (v == null) {
            return 0;
        }
        int n = v.getId() == id ? 1 : 0;
        if (v instanceof android.view.ViewGroup) {
            android.view.ViewGroup g = (android.view.ViewGroup) v;
            for (int i = 0; i < g.getChildCount() && n < cap; i++) {
                n += countById(g.getChildAt(i), id, cap - n);
            }
        }
        return n;
    }

    /**
     * Whether a breadcrumb path names {@code dir}.
     *
     * <p>A suffix test, not equality: the breadcrumb is a horizontally scrolling RecyclerView, so a
     * deep path can be showing only its tail. "/x/content" would be a false positive against
     * "/content", but {@code dir} is always the full path the listing reported, so a suffix match
     * on the full string cannot be one.
     */
    static boolean samePath(String path, String dir) {
        return path != null && dir != null
                && (path.equals(dir) || path.endsWith(dir));
    }

    /**
     * Per-copy diagnostic: what each page copy is showing, what is in its toolbar, and every
     * property that could make an injected button invisible.
     *
     * <p>Written after an accessibility dump and a screenshot disagreed: the dump reported a button
     * at [672,393][784,476] with {@code shown=true} and a working click handler, while every pixel
     * in that rectangle was #FFFFFF. Bounds and visibility flags cannot detect that; texture colour
     * can, so that is what this reports.
     */
    public static String copiesReport(final String why) {
        String s = onMain(new Call() {
            @Override
            public String run() {
                int idFilter = app == null ? 0
                        : app.getResources().getIdentifier("filter", "id", APP_PKG);
                int idCrumb = app == null ? 0
                        : app.getResources().getIdentifier("rv_breadcrumb", "id", APP_PKG);
                java.util.List<android.view.View> copies = allCopies(idFilter);
                if (copies.isEmpty()) {
                    return "no id/filter copy in the window (" + why + ")";
                }
                StringBuilder sb = new StringBuilder("page copies: " + copies.size());
                for (int i = 0; i < copies.size(); i++) {
                    android.view.View filter = copies.get(i);
                    sb.append("\ncopy ").append(i)
                            .append(": crumb=").append(crumbPathOf(filter, idFilter, idCrumb))
                            .append(" filter=").append(absRect(filter))
                            .append(" vis=").append(filter.getVisibility())
                            .append(" shown=").append(filter.isShown());
                    // The ancestry, with the number of id/filter and id/rv_breadcrumb views in each
                    // level. This is what decides where a page ends: stop too late and the
                    // breadcrumb found belongs to the page next door.
                    android.view.View cur = filter;
                    android.view.ViewParent p = cur.getParent();
                    for (int k = 0; cur != null && p != null && k < 9; k++) {
                        sb.append("\ncopy ").append(i).append(" up").append(k).append(": ")
                                .append(cur.getClass().getSimpleName())
                                .append('#').append(idName(cur))
                                .append(" wh=").append(cur.getWidth()).append('x').append(cur.getHeight())
                                .append(" abs=").append(absRect(cur));
                        if (p instanceof android.view.ViewGroup) {
                            android.view.ViewGroup g = (android.view.ViewGroup) p;
                            sb.append(" <- ").append(g.getClass().getSimpleName())
                                    .append('#').append(idName(g))
                                    .append(" idx=")
                                    .append(g.indexOfChild(cur)).append('/').append(g.getChildCount())
                                    .append(" z=").append(g.getZ())
                                    .append(" filters=").append(countById(g, idFilter, 9))
                                    .append(" crumbs=").append(countById(g, idCrumb, 9))
                                    .append(" wh=").append(g.getWidth()).append('x').append(g.getHeight());
                        } else {
                            sb.append(" <- ").append(p);
                        }
                        cur = p instanceof android.view.View ? (android.view.View) p : null;
                        p = cur == null ? null : cur.getParent();
                    }

                    android.view.ViewParent vp = filter.getParent();
                    if (!(vp instanceof android.view.ViewGroup)) {
                        sb.append("\ncopy ").append(i).append(" parent=not a ViewGroup: ").append(vp);
                        continue;
                    }
                    android.view.ViewGroup pg = (android.view.ViewGroup) vp;
                    boolean lin = pg instanceof android.widget.LinearLayout;
                    sb.append("\ncopy ").append(i).append(" parent=")
                            .append(pg.getClass().getSimpleName())
                            .append('#').append(idName(pg))
                            .append(" kids=").append(pg.getChildCount())
                            .append(lin ? " orientation=" + ((android.widget.LinearLayout) pg)
                                    .getOrientation() : "")
                            .append(" wh=").append(pg.getWidth()).append('x').append(pg.getHeight())
                            .append(" clip=").append(pg.getClipChildren())
                            .append(" shown=").append(pg.isShown());
                    for (int k = 0; k < pg.getChildCount(); k++) {
                        android.view.View c = pg.getChildAt(k);
                        android.view.ViewGroup.LayoutParams lp = c.getLayoutParams();
                        sb.append("\ncopy ").append(i).append(" kid").append(k).append(": ")
                                .append(c.getClass().getSimpleName())
                                .append('#').append(idName(c))
                                .append(" lp=").append(lp == null ? "null" : lp.width + "x" + lp.height)
                                .append(" xy=").append(c.getLeft()).append(',').append(c.getTop())
                                .append(" wh=").append(c.getWidth()).append('x').append(c.getHeight())
                                .append(" alpha=").append(c.getAlpha())
                                .append(" vis=").append(c.getVisibility())
                                .append(" shown=").append(c.isShown());
                        if (c instanceof android.widget.TextView) {
                            android.widget.TextView t = (android.widget.TextView) c;
                            sb.append(" text=").append(t.getText())
                                    .append(" color=#").append(Integer.toHexString(t.getCurrentTextColor()))
                                    .append(" size=").append(t.getTextSize());
                        }
                        sb.append(" bg=").append(c.getBackground() == null ? "none"
                                : c.getBackground().getClass().getSimpleName())
                                .append(" abs=").append(absRect(c));
                        if (c.getTag() == TAG_UNLOCK) {
                            sb.append("  <== ours");
                        }
                    }
                }
                return sb.toString();
            }
        }, "copies " + why);
        // One log line per fact. LSPosed truncates long messages — the first version of this dump
        // arrived as "…[4318 chars]" and lost exactly the child list it existed to produce.
        int lines = 0;
        for (String line : s.split("\n")) {
            Logx.i("[copies] " + line);
            lines++;
        }
        return "copies: " + lines + " line(s) logged (" + why + ")";
    }

    /**
     * Runs {@code c} on the main thread and returns its answer, or a description of why not.
     *
     * <p>Bounded by a 4 s wait: the file list is being built and laid out while this runs, and an
     * unbounded wait would be a way for a probe to freeze the very thread it is measuring.
     */
    private static String onMain(final Call c, final String what) {
        if (app == null) {
            return "no app context yet (" + what + ")";
        }
        final String[] out = new String[1];
        final java.util.concurrent.CountDownLatch done = new java.util.concurrent.CountDownLatch(1);
        try {
            boolean posted = new android.os.Handler(android.os.Looper.getMainLooper())
                    .post(new Runnable() {
                        @Override
                        public void run() {
                            try {
                                out[0] = c.run();
                            } catch (Throwable t) {
                                out[0] = what + " threw: " + t;
                            } finally {
                                done.countDown();
                            }
                        }
                    });
            if (!posted) {
                return "the main thread rejected " + what;
            }
        } catch (Throwable t) {
            return "cannot reach the main thread for " + what + ": " + t;
        }
        try {
            done.await(4, java.util.concurrent.TimeUnit.SECONDS);
        } catch (Throwable ignored) {
            // the caller still gets whatever was produced
        }
        return out[0] == null ? what + " timed out" : out[0];
    }

    /** A body that runs on the main thread and returns a line for the log. */
    private interface Call {
        String run();
    }

    private static android.app.Activity activityOf(Object fragment) {
        Object a = fragment == null ? null : Reflectx.call0(fragment, "getActivity");
        return a instanceof android.app.Activity ? (android.app.Activity) a : null;
    }

    /**
     * The Activity the file page is living in, or null.
     *
     * <p>For {@link Channel}: the app's download façade takes an {@code Activity} because it is
     * entitled to raise a dialog or a notification, so a replay needs one too. {@code Channel} only
     * ever sees an Activity when one happens to pass through the download pipeline, which is not the
     * case before the app has downloaded anything in this process.
     */
    static android.app.Activity activity() {
        return activityOf(lastFragment());
    }

    private static android.view.View fragmentViewOf(Object fragment) {
        Object v = fragment == null ? null : Reflectx.call0(fragment, "getView");
        return v instanceof android.view.View ? (android.view.View) v : null;
    }

    /** Buttons currently attached to a drawn page copy; 0 means the retry chain keeps going. */
    private static volatile int armedButtons;

    /**
     * Whether a retry chain is running.
     *
     * <p>One chain, not one per caller. The listing path asks for the button once per CloudFile row
     * — measured at twenty rows, twenty near-simultaneous requests, all arriving before the page has
     * settled — so a counter incremented per request would exhaust its budget on the requests rather
     * than the retries.
     */
    private static final java.util.concurrent.atomic.AtomicBoolean retryInFlight =
            new java.util.concurrent.atomic.AtomicBoolean();

    /** Attempts left in the running chain; re-armed by every fresh request. */
    private static final java.util.concurrent.atomic.AtomicInteger retryLeft =
            new java.util.concurrent.atomic.AtomicInteger();

    private static final int MAX_SHOWN_RETRIES = 40;

    /**
     * Re-attempts the insertion shortly, for the case where a listing arrives before its page has
     * settled — the breadcrumbs still name the directory just left, or the matching copy is not laid
     * out yet. Both resolve themselves shortly; neither justifies injecting into a copy that cannot
     * be seen, which is what produced an invisible button in the first place.
     *
     * @return true when a retry is running (or was started)
     */
    private static boolean scheduleShownRetry(final String vaultDir, final String label,
                                              final Integer widthPx, final Integer sizeSp,
                                              final String why, final android.view.View pageRoot) {
        retryLeft.set(MAX_SHOWN_RETRIES);
        if (!retryInFlight.compareAndSet(false, true)) {
            return true;
        }
        postRetry(vaultDir, label, widthPx, sizeSp, why, pageRoot);
        return true;
    }

    /** One link of the retry chain: re-posts itself until a button lands or the budget runs out. */
    private static void postRetry(final String vaultDir, final String label, final Integer widthPx,
                                  final Integer sizeSp, final String why,
                                  final android.view.View pageRoot) {
        try {
            new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(new Runnable() {
                @Override
                public void run() {
                    try {
                        String r = attachUnlockButtons(vaultDir, label, widthPx, sizeSp, why, pageRoot);
                        logOnce(r);
                        // Stop as soon as a button is in place, and stop as soon as the sentence has
                        // changed: a retry chain exists to wait for one directory's page to settle,
                        // so once the drawn page is somewhere else the answer will never change and
                        // the chain would only keep re-asking for ten seconds.
                        if (armedButtons > 0 || vaultDir == null
                                || !vaultDir.equals(lastWantedDir)) {
                            retryInFlight.set(false);
                            return;
                        }
                    } catch (Throwable t) {
                        Logx.w("[button] retry failed: " + t);
                    }
                    if (retryLeft.decrementAndGet() > 0) {
                        postRetry(vaultDir, label, widthPx, sizeSp, why, pageRoot);
                    } else {
                        retryInFlight.set(false);
                        Logx.w("[button] gave up after " + MAX_SHOWN_RETRIES
                                + " retries waiting for a drawn page of " + vaultDir + " (" + why
                                + ")");
                    }
                }
            }, 250);
        } catch (Throwable t) {
            retryInFlight.set(false);
            Logx.w("[button] cannot schedule a retry: " + t);
        }
    }

    /**
     * Reports, once, whether the button actually fits — measured after layout rather than reasoned
     * about beforehand.
     *
     * <p>The accessibility dump shows a 557 px gap in the middle of the toolbar row but not what
     * occupies it, and the answer decides the outcome: a weighted spacer shrinks and absorbs the
     * button harmlessly, whereas hard margins would push {@code id/switch_layout_icon} — which
     * already ends at x=1036 of 1080 — off the screen. The two cases are indistinguishable from the
     * dump, so this measures the laid-out result instead of guessing. It only reports; it never
     * removes the button, because a visible button that overflows still says far more than a
     * silently absent one.
     */
    private static void watchForOverflow(final android.view.ViewGroup parent,
                                         final android.view.View self, final String why) {
        try {
            final boolean[] done = {false};
            self.getViewTreeObserver().addOnGlobalLayoutListener(
                    new android.view.ViewTreeObserver.OnGlobalLayoutListener() {
                        @Override
                        public void onGlobalLayout() {
                            if (done[0]) {
                                return;
                            }
                            done[0] = true;
                            try {
                                int limit = parent.getWidth();
                                if (limit <= 0) {
                                    return;
                                }
                                int selfTop = self.getTop();
                                for (int i = 0; i < parent.getChildCount(); i++) {
                                    android.view.View c = parent.getChildAt(i);
                                    if (c == self || c.getTop() != selfTop) {
                                        continue;
                                    }
                                    if (c.getRight() > limit) {
                                        Logx.w("[button] OVERFLOW: " + idName(c) + " ends at x="
                                                + c.getRight() + " in a " + limit
                                                + " px row (" + why + "). Shrink with `am broadcast"
                                                + " -a com.luqin.bdcrypto.PROBE --es cmd btn --es arg"
                                                + " w=110`, or move the anchor.");
                                        return;
                                    }
                                }
                                Logx.i("[button] placed: at " + absRect(self) + " shown="
                                        + self.isShown() + " w=" + self.getWidth() + " in a "
                                        + limit + " px row, everything left of the edge (" + why
                                        + ")");
                            } catch (Throwable t) {
                                Logx.w("[button] overflow check failed: " + t);
                            }
                        }
                    });
        } catch (Throwable t) {
            Logx.w("[button] cannot install overflow check: " + t);
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
        String s = buildToolbarTree(why);
        if (s == null) {
            // Not measurable yet. Release the one-shot guard so the next listing retries.
            toolbarDumped.set(false);
            return;
        }
        Logx.i(s);
    }

    /** Probe entry point: a retry costs a broadcast, not a reinstall. */
    public static String toolbarTreeNow() {
        String s = buildToolbarTree("probe");
        return s == null ? "[toolbar] not measurable right now" : s;
    }

    /** @return the measurement, or null when it cannot be taken so the caller can retry later. */
    private static String buildToolbarTree(String why) {
        try {
            int id = app == null ? 0 : app.getResources().getIdentifier("filter", "id", APP_PKG);
            if (id == 0) {
                Logx.w("[toolbar] R.id.filter not resolvable");
                return null;
            }
            Object f = lastFragment;
            Object actObj = f == null ? null : Reflectx.call0(f, "getActivity");
            android.app.Activity act = actObj instanceof android.app.Activity
                    ? (android.app.Activity) actObj : null;

            android.view.View v = findShownById(act, id);
            String how = "the shown copy";
            if (v == null && f != null) {
                Object rv = Reflectx.call0(f, "getView");
                if (rv instanceof android.view.View) {
                    v = ((android.view.View) rv).findViewById(id);
                    how = "a fragment copy (nothing is shown)";
                }
            }
            if (v == null) {
                Logx.w("[toolbar] no id/filter anywhere yet; will retry");
                return null;
            }

            // One log line per view, deliberately not one big string: LSPosed truncates long
            // messages, and a single dump arrived here as "…[4792 chars]" — the first attempt at
            // this measurement lost the very child list it existed to obtain.
            Logx.i("[toolbar] id/filter via " + how + " (" + why + ")");
            android.view.View cur = v;
            for (int i = 0; cur != null && i < 6; i++) {
                android.view.ViewGroup.LayoutParams lp = cur.getLayoutParams();
                Logx.i("[toolbar] [" + i + "] " + cur.getClass().getName()
                        + " id=" + idName(cur)
                        + " lp=" + (lp == null ? "null"
                                : lp.getClass().getSimpleName() + "(" + lp.width + "x" + lp.height + ")")
                        + " xy=" + (int) cur.getX() + "," + (int) cur.getY()
                        + " wh=" + cur.getWidth() + "x" + cur.getHeight()
                        + " vis=" + cur.getVisibility() + " shown=" + cur.isShown()
                        + " abs=" + absRect(cur));
                android.view.ViewParent p = cur.getParent();
                if (p instanceof android.view.ViewGroup) {
                    android.view.ViewGroup g = (android.view.ViewGroup) p;
                    StringBuilder sb = new StringBuilder("[toolbar]    parent=")
                            .append(g.getClass().getName())
                            .append(" id=").append(idName(g))
                            .append(" children=").append(g.getChildCount())
                            .append(" myIndex=").append(g.indexOfChild(cur));
                    if (g instanceof android.widget.LinearLayout) {
                        sb.append(" orientation=")
                                .append(((android.widget.LinearLayout) g).getOrientation());
                    }
                    if (g instanceof android.view.View) {
                        android.view.View gv = (android.view.View) g;
                        sb.append(" wh=").append(gv.getWidth()).append('x').append(gv.getHeight())
                                .append(" vis=").append(gv.getVisibility())
                                .append(" shown=").append(gv.isShown());
                    }
                    Logx.i(sb.toString());
                    for (int k = 0; k < g.getChildCount(); k++) {
                        android.view.View ck = g.getChildAt(k);
                        android.view.ViewGroup.LayoutParams klp = ck.getLayoutParams();
                        Logx.i("[toolbar]      " + k + ": "
                                + ck.getClass().getSimpleName()
                                + " id=" + idName(ck)
                                + " lp=" + (klp == null ? "null"
                                        : klp.getClass().getSimpleName()
                                                + "(" + klp.width + "x" + klp.height + ")")
                                + " w=" + ck.getWidth()
                                + " shown=" + ck.isShown()
                                + " abs=" + absRect(ck));
                    }
                }
                cur = (p instanceof android.view.View) ? (android.view.View) p : null;
            }
            return "[toolbar] measured via " + how + " (" + why + ")";
        } catch (Throwable t) {
            Logx.w("[toolbar] dump failed: " + t);
            return null;
        }
    }

    /** Every view with the given id under {@code v}, depth-first, in draw order. */
    private static void collectById(android.view.View v, int id,
                                    java.util.List<android.view.View> out) {
        if (v == null || out.size() >= 64) {
            return;
        }
        if (v.getId() == id) {
            out.add(v);
        }
        if (v instanceof android.view.ViewGroup) {
            android.view.ViewGroup g = (android.view.ViewGroup) v;
            for (int i = 0; i < g.getChildCount(); i++) {
                collectById(g.getChildAt(i), id, out);
            }
        }
    }

    /**
     * The copy of {@code id} that is actually on screen, or null when none is.
     *
     * <p>There is usually more than one: the connection between two file pages stays alive, so the
     * previous directory's toolbar is still attached. Copies are searched from the end because
     * later siblings draw on top, which makes the last one the visible one. The single rule lives
     * here so the button and the diagnostic dump cannot disagree about which toolbar is real.
     */
    private static android.view.View findShownById(android.app.Activity act, int id) {
        if (act == null || id == 0) {
            return null;
        }
        android.view.Window w = act.getWindow();
        java.util.List<android.view.View> copies = new java.util.ArrayList<android.view.View>();
        collectById(w == null ? null : w.getDecorView(), id, copies);
        for (int i = copies.size() - 1; i >= 0; i--) {
            android.view.View c = copies.get(i);
            if (!c.isShown()) {
                continue;
            }
            android.graphics.Rect r = new android.graphics.Rect();
            if (c.getGlobalVisibleRect(r) && r.width() > 0 && r.height() > 0) {
                return c;
            }
        }
        return null;
    }

    /**
     * The part of {@code v} that is on screen, as {@code l,t-r,b}, or "none".
     *
     * <p>Absolute bounds, unlike {@code getLeft()}. A view inside the previous directory's retained
     * page reports perfectly ordinary left/right values while sitting nowhere near the screen,
     * which is exactly the trap that hid the first version of the unlock button.
     */
    private static String absRect(android.view.View v) {
        try {
            android.graphics.Rect r = new android.graphics.Rect();
            if (v.getGlobalVisibleRect(r)) {
                return r.left + "," + r.top + "-" + r.right + "," + r.bottom;
            }
        } catch (Throwable ignored) {
            // a view that cannot report a rect is reported as "none" below
        }
        return "none";
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
                + "\n  vault dirs  : " + vaultDirs
                + "\n  button      : " + buttonSummary
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
