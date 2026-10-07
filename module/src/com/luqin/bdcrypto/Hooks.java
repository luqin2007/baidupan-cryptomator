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

    private static volatile ClassLoader cl;
    private static volatile Context app;
    private static volatile boolean appHooksInstalled;

    private static volatile Object lastFragment;
    private static volatile String lastFragmentWhere = "-";

    private static final Set<String> rowsSeen = Collections.synchronizedSet(new HashSet<String>());
    private static final List<String> rows = Collections.synchronizedList(new ArrayList<String>());
    private static final Set<String> cursorColumns =
            Collections.synchronizedSet(new LinkedHashSet<String>());
    private static final Set<String> adapterClasses =
            Collections.synchronizedSet(new LinkedHashSet<String>());
    private static final List<String> urls = Collections.synchronizedList(new ArrayList<String>());
    private static final Set<String> urlSeen = Collections.synchronizedSet(new HashSet<String>());
    private static final List<String> missingTargets = Collections.synchronizedList(new ArrayList<String>());

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
                    safe("CloudFile.createFormCursor", new Body() {
                        @Override
                        public void run() {
                            recordCloudFile(param.getResult(), "createFormCursor");
                        }
                    });
                }
            });
            XposedBridge.hookAllMethods(cf, "readFromCursor", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    safe("CloudFile.readFromCursor", new Body() {
                        @Override
                        public void run() {
                            Object[] a = param.args;
                            if (a != null && a.length > 1) {
                                recordCloudFile(a[1], "readFromCursor");
                            }
                        }
                    });
                }
            });
            Logx.i("hooked CloudFile factories");
        } catch (Throwable t) {
            note("hook CloudFile failed: " + t);
        }
    }

    private static void recordCloudFile(Object o, String from) {
        if (o == null || !o.getClass().getName().endsWith("CloudFile")) {
            return;
        }
        long fsId = Reflectx.callLong(o, "getFileId", -1L);
        String path = Reflectx.callStr(o, "getFilePath");
        String name = Reflectx.callStr(o, "getFileName");
        String key = fsId + "|" + path + "|" + name;
        if (!rowsSeen.add(key)) {
            return;
        }
        String line = "fsId=" + fsId
                + " dir=" + Reflectx.callBool(o, "isDir", false)
                + " size=" + Reflectx.callLong(o, "getSize", -1L)
                + " mtime=" + Reflectx.callLong(o, "getServerMTime", -1L)
                + " md5=" + Reflectx.callStr(o, "getServerMD5")
                + " dlink=" + shortUrl(Reflectx.callStr(o, "getFileDlink"))
                + " name=" + name
                + " path=" + path
                + "  <-" + from;
        if (rows.size() < MAX_ROWS) {
            rows.add(line);
        }
        Logx.i("[row] " + line);
    }

    // -------------------------------------------------------- Cursor -------

    /** Column names of the list cursor: the raw truth about what the list query returns. */
    private static void hookCursorColumns() {
        String[] targets = {
                "android.database.AbstractCursor",
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
