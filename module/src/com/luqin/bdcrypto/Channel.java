package com.luqin.bdcrypto;

import android.app.Activity;
import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/**
 * The content channel: captures how the app itself starts a download, and replays it.
 *
 * <p>This is P0-B. The question it answers is "given a cloud file, which call produces its bytes",
 * and the answer cannot come from a disassembler: every class in the pipeline is method-obfuscated
 * ({@code f}, {@code l}, {@code __}), and the one type that would let us be self-sufficient —
 * {@code com.baidu.netdisk.transfer.task.IDownloadProcessorFactory} — returns an <em>abstract
 * class</em> ({@code com.baidu.netdisk.transfer.base.Processor}), so it cannot be satisfied by a
 * {@code java.lang.reflect.Proxy} and cannot be subclassed at runtime without generating bytecode.
 * Neither can a {@code TaskResultReceiver} be invented: its whole job is to be called back by
 * machinery we do not own.
 *
 * <p>So the objects are borrowed instead of built. The app produces a factory, a receiver and the
 * manager instance on every real download; this class keeps the ones it sees, and a later call can
 * be made with them. That is the whole design: observe once, replay after.
 *
 * <h2>Why recognition is by type, not by name</h2>
 *
 * <p>The first version of this class matched on class-name suffixes
 * ({@code cn.endsWith("IDownloadProcessorFactory")}). On the first real download
 * ({@code 2026-10-08 08:58}) that captured 37 distinct call signatures and still produced
 * {@code factory = null}, because the object the app passes is an R8-moved class named
 * {@code no0.___}. A name test can never see it. The interface is real and unchanged —
 * {@code com.baidu.netdisk.transfer.task.IDownloadProcessorFactory} is in the shipped dex — so the
 * fix is to walk the superclass-and-interface graph and match on <em>types</em>.
 *
 * <p>Two consequences worth keeping: the shipped class index omits obfuscated top-level packages
 * entirely (see {@code module/tools/gen_class_index.py}), and a class name is not evidence of
 * anything in an R8 build.
 *
 * <h2>Independent of the capture</h2>
 *
 * <p>A real download also proves the destination layout without any of the above: the app writes
 * {@code /storage/emulated/0/Download/BaiduNetdisk/<cloud path>}, and on 2026-10-08 the bytes
 * pulled from there were sha256-identical to the desktop copy of the vault
 * ({@code vault.cryptomator} 283 B, {@code 5b8dd122…}). So a replay is verifiable by pulling the
 * file it produces, not only by reading a log.
 */
public final class Channel {

    // ------------------------------------------------------------ capture ---

    /** Signatures already reported — the mechanism that makes the log uncappable in practice. */
    private static final Set<String> sigSeen = Collections.synchronizedSet(new HashSet<String>());

    /** Every distinct signature, in the order discovered, for {@code ch last}. */
    private static final List<String> sigs = Collections.synchronizedList(new ArrayList<String>());

    /** Bounded sample of individual calls, so repeats can be inspected without unbounded growth. */
    private static final int MAX_CALLS = 600;
    private static final List<String> calls = Collections.synchronizedList(new ArrayList<String>());

    private static volatile Object manager;      // a live DownloadTaskManager
    private static volatile Object api;          // a live FDDownloadManagerApi
    private static volatile Object helper;       // a live SingleFileDownloadHelper
    private static volatile Object extHelper;    // a live ExternalDownloadHelper

    // Borrowed from a real download. The reason this class exists.
    private static volatile Object lastFactory;  // IDownloadProcessorFactory
    private static volatile Object lastReceiver; // TaskResultReceiver
    private static volatile Object lastActivity; // Activity
    private static volatile String lastTrigger = "-";
    private static volatile String factoryTrigger = "-";
    private static volatile String receiverTrigger = "-";

    /** The last {@code N} CloudFiles the list handed us, so a replay has something to download. */
    private static final int MAX_FILES = 200;
    private static final List<Object> files = Collections.synchronizedList(new ArrayList<Object>());

    /**
     * Where the app's own downloads land. Measured, not configured (docs/recon.md §11.5): the
     * landing path is {@code <root>/<cloud path>} with the cloud path's leading slash removed, and
     * P0-B verified the bytes written there are sha256-identical to the originals — which is why
     * the module can read ciphertext the app has already fetched instead of asking for it again.
     */
    static final String DOWNLOAD_ROOT = "/storage/emulated/0/Download/BaiduNetdisk";

    private Channel() {
    }

    // -------------------------------------------------------------- hook ----

    /** Classes whose every method is a candidate member of the content path. */
    private static final String[] CLASSES = {
            "com.baidu.netdisk.transfer.task.DownloadTaskManager",
            "com.baidu.netdisk.file.download.component.apis.FDDownloadManagerApi",
            "com.baidu.netdisk.transfer.download.SingleFileDownloadHelper",
            "com.baidu.netdisk.util.ExternalDownloadHelper",
            "com.baidu.netdisk.transfer.task.TaskResultReceiver",
    };

    public static void install(ClassLoader cl) {
        for (String name : CLASSES) {
            Class<?> c = XposedHelpers.findClassIfExists(name, cl);
            if (c == null) {
                continue;
            }
            int n = 0;
            for (Method m : safeMethods(c)) {
                int mod = m.getModifiers();
                if (Modifier.isAbstract(mod) || Modifier.isNative(mod)) {
                    continue;
                }
                try {
                    XposedBridge.hookMethod(m, WATCH);
                    n++;
                } catch (Throwable ignored) {
                    // A member the framework refuses is not worth failing the whole class over.
                }
            }
            try {
                XposedBridge.hookAllConstructors(c, WATCH);
                n++;
            } catch (Throwable ignored) {
                // ignore
            }
            Logx.i("[ch] watching " + name + " (" + n + " members)");
        }
    }

    private static Method[] safeMethods(Class<?> c) {
        try {
            return c.getDeclaredMethods();
        } catch (Throwable t) {
            return new Method[0];
        }
    }

    private static final XC_MethodHook WATCH = new XC_MethodHook() {
        @Override
        protected void afterHookedMethod(MethodHookParam param) {
            final MethodHookParam p = param;
            try {
                note(p);
            } catch (Throwable t) {
                // A probe must never take the app down.
            }
        }
    };

    // ------------------------------------------------------------ typing ----

    private static void note(XC_MethodHook.MethodHookParam p) {
        boolean ctor = p.method == null;
        String owner = ctor
                ? (p.thisObject == null ? "?" : p.thisObject.getClass().getName())
                : p.method.getDeclaringClass().getName();
        String name = ctor ? "<init>" : p.method.getName();
        Object[] args = p.args == null ? new Object[0] : p.args;

        // Retain the objects the pipeline hands around. This is the capture. Note that the
        // *instance* and the *result* count too: the factory for a whole download is the return
        // value of FDDownloadManagerApi.q, and the manager is only ever seen as a fresh `this`.
        for (Object a : args) {
            retain(a, owner, name);
        }
        retain(p.thisObject, owner, name);
        if (!ctor) {
            try {
                retain(p.getResult(), owner, name);
            } catch (Throwable ignored) {
                // getResult on a void method is null; nothing to retain.
            }
        }

        // Key by signature, not by call: the app makes hundreds of uninteresting calls before the
        // interesting one, and a capped call log is exactly what loses it.
        StringBuilder sig = new StringBuilder(owner).append('#').append(name).append('(');
        for (int i = 0; i < args.length; i++) {
            if (i > 0) {
                sig.append(", ");
            }
            sig.append(args[i] == null ? "null" : args[i].getClass().getName());
        }
        sig.append(')');
        String key = sig.toString();
        boolean first = sigSeen.add(key);

        String line = key + describe(args) + outcome(p);
        if (first) {
            sigs.add(line);
            Logx.i("[ch#new] " + line);
        }
        if (calls.size() < MAX_CALLS) {
            calls.add(line);
        }
    }

    // ------------------------------------------------- object recognition ---

    private static final String[] T_FACTORY = {"IDownloadProcessorFactory", "IUploadProcessorFactory"};
    private static final String[] T_RECEIVER = {"TaskResultReceiver"};
    private static final String[] T_MANAGER = {"DownloadTaskManager"};
    private static final String[] T_API = {"FDDownloadManagerApi"};
    private static final String[] T_HELPER = {"SingleFileDownloadHelper"};
    private static final String[] T_EXT_HELPER = {"ExternalDownloadHelper"};

    /**
     * Is {@code c}, or anything it extends or implements, one of these types?
     *
     * <p>This is the whole point of the rewrite: an R8 build renames the <em>class</em> but cannot
     * change the type graph, so {@code no0.___ implements IDownloadProcessorFactory} is visible
     * here even though its name says nothing.
     */
    private static boolean isA(Class<?> c, String[] want) {
        return isA(c, want, 0);
    }

    private static boolean isA(Class<?> c, String[] want, int depth) {
        if (c == null || c == Object.class || depth > 32) {
            return false;
        }
        String n = c.getName();
        for (String w : want) {
            if (n.endsWith(w)) {
                return true;
            }
        }
        Class<?>[] ifs;
        try {
            ifs = c.getInterfaces();
        } catch (Throwable t) {
            ifs = new Class<?>[0];
        }
        for (Class<?> i : ifs) {
            if (isA(i, want, depth + 1)) {
                return true;
            }
        }
        return isA(c.getSuperclass(), want, depth + 1);
    }

    /**
     * Keeps the handful of objects a replay needs, and names anything else that is obviously part
     * of the pipeline so the shape of a real download is visible in the log.
     */
    private static void retain(Object a, String owner, String name) {
        if (a == null) {
            return;
        }
        Class<?> c = a.getClass();
        if (isA(c, T_FACTORY)) {
            if (lastFactory != a) {
                lastFactory = a;
                factoryTrigger = owner + "." + name;
                Logx.i("[ch#factory] borrowed factory from " + factoryTrigger + " -> " + c.getName());
            }
        } else if (isA(c, T_RECEIVER)) {
            if (lastReceiver != a) {
                lastReceiver = a;
                receiverTrigger = owner + "." + name;
                Logx.i("[ch#receiver] borrowed receiver from " + receiverTrigger + " -> "
                        + c.getName());
            }
        } else if (a instanceof Activity) {
            lastActivity = a;
        } else if (isA(c, T_MANAGER)) {
            manager = a;
        } else if (isA(c, T_API)) {
            api = a;
        } else if (isA(c, T_HELPER)) {
            helper = a;
        } else if (isA(c, T_EXT_HELPER)) {
            extHelper = a;
        }
    }

    /** Records a CloudFile the list produced, so a replay has a real object to hand the pipeline. */
    static void noteFile(Object o) {
        if (o == null) {
            return;
        }
        // Must be a synchronised *method* call, not a for-each: row binding happens on the main
        // thread and on binder threads at once, and iterating a synchronizedList outside its own
        // lock throws ConcurrentModificationException. That is not theoretical — it surfaced as
        // "hook body failed: CloudFile.readFromCursor :: java.util.ConcurrentModificationException"
        // during the 08:58 download.
        if (files.contains(o)) {
            return;
        }
        if (files.size() >= MAX_FILES) {
            files.remove(0);
        }
        files.add(o);
    }

    // ---------------------------------------------------------- rendering ---

    private static String describe(Object[] args) {
        if (args.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder("  args=[");
        for (int i = 0; i < args.length; i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(brief(args[i]));
        }
        return sb.append(']').toString();
    }

    private static String brief(Object o) {
        if (o == null) {
            return "null";
        }
        if (o instanceof CharSequence) {
            String s = o.toString();
            return '"' + (s.length() > 160 ? s.substring(0, 160) + "…" : s) + '"';
        }
        if (o instanceof Number || o instanceof Boolean) {
            return o.toString();
        }
        String cn = o.getClass().getName();
        if (cn.endsWith("CloudFile")) {
            // The three fields a replay and a byte comparison both need.
            return "CloudFile{id=" + Reflectx.callLong(o, "getFileId", -1L)
                    + " name=" + Reflectx.callStr(o, "getFileName")
                    + " path=" + Reflectx.callStr(o, "getFilePath")
                    + " size=" + Reflectx.callLong(o, "getSize", -1L)
                    + " dir=" + Reflectx.callBool(o, "isDir", false) + "}";
        }
        if (o instanceof List) {
            List<?> l = (List<?>) o;
            StringBuilder sb = new StringBuilder("List(").append(l.size()).append(")[");
            for (int i = 0; i < l.size() && i < 3; i++) {
                sb.append(i > 0 ? ", " : "").append(brief(l.get(i)));
            }
            return sb.append(']').toString();
        }
        return Reflectx.simple(cn) + "@" + Integer.toHexString(System.identityHashCode(o));
    }

    private static String outcome(XC_MethodHook.MethodHookParam p) {
        if (p.hasThrowable()) {
            return "  !! " + p.getThrowable();
        }
        Object r;
        try {
            r = p.getResult();
        } catch (Throwable t) {
            return "  -> (unavailable)";
        }
        return r == null ? "  -> void/null" : "  -> " + brief(r);
    }

    // ------------------------------------------------------------- probe ----

    /** {@code ch} probe: {@code last} | {@code files} | {@code hier} | {@code go <n|name> [flag]}. */
    public static String command(Context ctx, String arg) {
        String a = arg == null ? "" : arg.trim();
        String body;
        if (a.isEmpty() || "last".equalsIgnoreCase(a)) {
            body = report();
        } else if ("files".equalsIgnoreCase(a)) {
            body = fileList();
        } else if ("hier".equalsIgnoreCase(a)) {
            body = hierarchies();
        } else if (a.startsWith("go")) {
            body = replay(a.length() > 2 ? a.substring(2).trim() : "");
        } else {
            body = "ch: unknown argument '" + a + "' (last | files | hier | go <n|name> [flag])";
        }
        // The LSPosed log truncates a single record at ~7.6 KB, which silently ate the tail of the
        // 37-signature list. A file has no such limit.
        if (ctx != null && body != null && body.length() > 400) {
            String path = Report.write(ctx, "ch.txt", body);
            Logx.i(head(body) + "\n… (" + body.length() + " chars, full text in " + path + ")");
        } else {
            Logx.i(body);
        }
        return body;
    }

    private static String head(String s) {
        int n = Math.min(s.length(), 3600);
        return s.substring(0, n);
    }

    private static String report() {
        StringBuilder sb = new StringBuilder("channel capture\n");
        sb.append("  manager      : ").append(typeName(manager)).append('\n');
        sb.append("  api          : ").append(typeName(api)).append('\n');
        sb.append("  helper       : ").append(typeName(helper)).append('\n');
        sb.append("  extHelper    : ").append(typeName(extHelper)).append('\n');
        sb.append("  activity     : ").append(typeName(lastActivity)).append('\n');
        sb.append("  factory      : ").append(typeName(lastFactory))
                .append("  (from ").append(factoryTrigger).append(")\n");
        sb.append("  receiver     : ").append(typeName(lastReceiver))
                .append("  (from ").append(receiverTrigger).append(")\n");
        sb.append("  files held   : ").append(files.size()).append('\n');
        List<String> snapshot = new ArrayList<String>(sigs);
        sb.append("  distinct call signatures: ").append(snapshot.size()).append('\n');
        if (snapshot.isEmpty()) {
            sb.append("    (none — no download has been attempted in this process)\n");
        }
        for (String s : snapshot) {
            sb.append("    ").append(cut(s)).append('\n');
        }
        return sb.toString();
    }

    /** One report line must stay readable; the args of a long signature are already truncated. */
    private static String cut(String s) {
        return s.length() <= 400 ? s : s.substring(0, 400) + "…";
    }

    private static String typeName(Object o) {
        return o == null ? "<null>" : o.getClass().getName();
    }

    /** The type graph of every captured actor — the only way to read an R8-renamed class. */
    private static String hierarchies() {
        StringBuilder sb = new StringBuilder("captured actor types\n");
        actor(sb, "manager", manager);
        actor(sb, "api", api);
        actor(sb, "helper", helper);
        actor(sb, "extHelper", extHelper);
        actor(sb, "activity", lastActivity);
        actor(sb, "factory", lastFactory);
        actor(sb, "receiver", lastReceiver);
        return sb.toString();
    }

    private static void actor(StringBuilder sb, String label, Object o) {
        sb.append("\n  ").append(label).append(" : ").append(typeName(o)).append('\n');
        if (o == null) {
            return;
        }
        Set<Class<?>> seen = new HashSet<Class<?>>();
        for (Class<?> k = o.getClass().getSuperclass(); k != null && k != Object.class;
             k = k.getSuperclass()) {
            sb.append("      extends    ").append(k.getName()).append('\n');
        }
        ifaces(sb, o.getClass(), seen, 1);
        for (String[] want : new String[][]{T_FACTORY, T_RECEIVER, T_MANAGER, T_API, T_HELPER,
                T_EXT_HELPER}) {
            if (isA(o.getClass(), want)) {
                sb.append("      matches    ").append(want[0]).append('\n');
            }
        }
    }

    private static void ifaces(StringBuilder sb, Class<?> c, Set<Class<?>> seen, int depth) {
        if (c == null || depth > 4 || !seen.add(c)) {
            return;
        }
        Class<?>[] ifs;
        try {
            ifs = c.getInterfaces();
        } catch (Throwable t) {
            return;
        }
        for (Class<?> i : ifs) {
            sb.append("      implements ").append(i.getName()).append('\n');
            ifaces(sb, i, seen, depth + 1);
        }
    }

    private static String fileList() {
        StringBuilder sb = new StringBuilder("CloudFiles held: " + files.size() + "\n");
        List<Object> copy = new ArrayList<Object>(files);
        for (int i = 0; i < copy.size(); i++) {
            Object o = copy.get(i);
            if (i >= 120) {
                sb.append("  … ").append(copy.size() - 120).append(" more\n");
                break;
            }
            sb.append("  [").append(i).append("] ")
                    .append(Reflectx.callStr(o, "getFileName"))
                    .append("  dir=").append(Reflectx.callBool(o, "isDir", false))
                    .append("  size=").append(Reflectx.callLong(o, "getSize", -1L))
                    .append("  id=").append(Reflectx.callLong(o, "getFileId", -1L))
                    .append("  path=").append(Reflectx.callStr(o, "getFilePath"))
                    .append('\n');
        }
        if (copy.isEmpty()) {
            sb.append("  (none — open a file page first; rows are captured from the list)\n");
        }
        return sb.toString();
    }

    // ------------------------------------------------- local landing ------

    /** The file the app's own download of {@code cloudPath} produces — or reuses. */
    static java.io.File localFileFor(String cloudPath) {
        String rel = cloudPath.startsWith("/") ? cloudPath.substring(1) : cloudPath;
        return new java.io.File(DOWNLOAD_ROOT, rel);
    }

    /** The held CloudFile whose own path is exactly {@code cloudPath}, or null. */
    private static Object heldFileFor(String cloudPath) {
        // A copy: `files` is written from the list's own threads while this reads it (the P0-B
        // ConcurrentModificationException was exactly this mistake).
        for (Object o : new ArrayList<Object>(files)) {
            if (cloudPath.equals(Reflectx.callStr(o, "getFilePath"))) {
                return o;
            }
        }
        return null;
    }

    /**
     * Gets one cloud file onto local disk, for callers that need bytes rather than a probe answer.
     *
     * <p>An existing file is used as it is: the app deduplicates downloads, so something it has
     * already fetched is never written twice and waiting for a "fresh" copy would only time out.
     * The price is the reverse case — a file the app believes it downloaded but which is gone from
     * disk cannot be recovered here, and the caller gets null rather than a wrong answer.
     *
     * @return the local file, or null if it is neither on disk nor obtainable
     */
    static java.io.File fetch(final String cloudPath, long timeoutMs) {
        final java.io.File local = localFileFor(cloudPath);
        if (local.isFile() && local.length() > 0) {
            return local;
        }
        final Object held = heldFileFor(cloudPath);
        if (held == null) {
            Logx.w("[fetch] " + cloudPath + ": the app has never listed that path");
            return null;
        }
        // The app's entry points take an Activity and are entitled to touch UI, so the trigger runs
        // on the main thread while this worker waits for it to return and then for the file to land.
        final CountDownLatch triggered = new CountDownLatch(1);
        mainHandler().post(new Runnable() {
            @Override
            public void run() {
                try {
                    downloadHeld(held, 0, new StringBuilder());
                } catch (Throwable t) {
                    Logx.w("[fetch] " + cloudPath + ": trigger threw " + t);
                } finally {
                    triggered.countDown();
                }
            }
        });
        try {
            if (!triggered.await(30, TimeUnit.SECONDS)) {
                Logx.w("[fetch] " + cloudPath + ": the trigger never returned");
                return null;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            if (local.isFile() && local.length() > 0) {
                Logx.i("[fetch] " + cloudPath + " -> " + local.getAbsolutePath()
                        + " (" + local.length() + " B)");
                return local;
            }
            try {
                Thread.sleep(200);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return null;
            }
        }
        Logx.w("[fetch] " + cloudPath + ": not on disk after " + timeoutMs
                + " ms (already-downloaded files are skipped by the app, so an absent file may "
                + "simply be missing from disk)");
        return local.isFile() && local.length() > 0 ? local : null;
    }

    // ------------------------------------------------------------ replay ----

    /**
     * Starts a real download of a held CloudFile using objects borrowed from a previous one.
     *
     * <p>Runs on the main thread: {@code FDDownloadManagerApi.g} takes an {@code Activity}, so it
     * is entitled to touch UI, and enqueuing a task is cheap. A latch with a timeout keeps the
     * probe from hanging if a candidate entry point blocks.
     */
    private static String replay(String spec) {
        String[] parts = spec.split("\\s+");
        final String which = parts.length > 0 ? parts[0] : "";
        int flag = 0;
        if (parts.length > 1) {
            try {
                flag = Integer.parseInt(parts[1]);
            } catch (Throwable ignored) {
                // default
            }
        }
        if (which.isEmpty()) {
            return "ch go: give a file index or name (ch files)";
        }
        final int f = flag;

        final String[] out = new String[1];
        final CountDownLatch done = new CountDownLatch(1);
        mainHandler().post(new Runnable() {
            @Override
            public void run() {
                try {
                    out[0] = replayOnMain(which, f);
                } catch (Throwable t) {
                    out[0] = "ch go: threw " + t;
                } finally {
                    done.countDown();
                }
            }
        });
        try {
            if (!done.await(30, TimeUnit.SECONDS)) {
                return "ch go: still running on the main thread after 30 s";
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return "ch go: interrupted";
        }
        return out[0] == null ? "ch go: no result" : out[0];
    }

    private static String replayOnMain(String which, int flag) {
        Object target = heldBySpec(which);
        StringBuilder sb = new StringBuilder("ch go:\n");
        if (target == null) {
            return sb.append("  no held CloudFile matches '").append(which).append("' (")
                    .append(files.size()).append(" held; try 'ch files')\n").toString();
        }
        downloadHeld(target, flag, sb);
        return sb.toString();
    }

    /** Resolves a probe spec — an index into {@code ch files}, or a file name — to a held file. */
    private static Object heldBySpec(String which) {
        List<Object> copy = new ArrayList<Object>(files);
        try {
            int idx = Integer.parseInt(which);
            if (idx >= 0 && idx < copy.size()) {
                return copy.get(idx);
            }
            return null;
        } catch (Throwable ignored) {
            for (Object o : copy) {
                if (which.equals(Reflectx.callStr(o, "getFileName"))) {
                    return o;
                }
            }
            return null;
        }
    }

    /** Hands one held CloudFile to the app's own download pipeline and describes what happened. */
    private static void downloadHeld(Object target, int flag, StringBuilder sb) {
        String fileName = Reflectx.callStr(target, "getFileName");
        List<Object> list = new ArrayList<Object>();
        list.add(target);
        sb.append("  file=").append(fileName)
                .append("  size=").append(Reflectx.callLong(target, "getSize", -1L))
                .append("  path=").append(Reflectx.callStr(target, "getFilePath")).append('\n');

        // --- factory: prefer one the app already made; otherwise ask the app's own API to make one.
        Object factory = lastFactory;
        sb.append("  factory: ").append(typeName(factory))
                .append(factory == null ? "" : " (borrowed from " + factoryTrigger + ")").append('\n');
        if (factory == null && api != null) {
            Att a = invoke(api, new String[]{"q"}, new Object[]{list, flag, null, null});
            sb.append("  api.q(list, ").append(flag).append(", null, null) -> ").append(a).append('\n');
            if (a.ret != null) {
                factory = a.ret;
            }
        }
        Object receiver = lastReceiver;
        sb.append("  receiver: ").append(typeName(receiver))
                .append(receiver == null ? "" : " (borrowed from " + receiverTrigger + ")"); 
        sb.append('\n');

        // --- then replay, trying each entry point the app itself was observed to use.
        if (manager != null) {
            sb.append("  --- via DownloadTaskManager (this is what the app itself called) ---\n");
            if (attempt(sb, manager, "d", new Object[]{list, factory, receiver, flag})
                    || attempt(sb, manager, "e", new Object[]{list, factory, receiver, flag, null})
                    || attempt(sb, manager, "f", new Object[]{target, factory, receiver, flag})) {
                sb.append("  result: an entry point accepted the task\n");
                return;
            }
        }
        if (api != null && lastActivity != null) {
            sb.append("  --- via FDDownloadManagerApi ---\n");
            if (attempt(sb, api, "g",
                    new Object[]{lastActivity, Boolean.TRUE, list, factory, null, flag})
                    || attempt(sb, api, "______",
                    new Object[]{lastActivity, Boolean.TRUE, list, factory, null, flag, null})
                    || attempt(sb, api, "c",
                    new Object[]{lastActivity, list, flag, 0, Boolean.TRUE, null, null, null, null,
                            null})) {
                sb.append("  result: an entry point accepted the task\n");
                return;
            }
        }
        sb.append("  result: every entry point refused (see the lines above)\n");
    }

    /** Tries one method name; returns true only if a matching overload ran without throwing. */
    private static boolean attempt(StringBuilder sb, Object instance, String name, Object[] args) {
        Att a = invoke(instance, new String[]{name}, args);
        sb.append("  ").append(Reflectx.simple(instance.getClass().getName())).append('.').append(name)
                .append('(').append(args.length).append(" args) -> ").append(a).append('\n');
        return a.ok;
    }

    private static final class Att {
        boolean ok;
        Object ret;
        String note = "not found";

        @Override
        public String toString() {
            return note;
        }
    }

    /**
     * Invokes the first overload of any of {@code names} whose parameters can actually accept
     * {@code args}. Argument types matter here: {@code d} and {@code f} both take four arguments
     * but {@code f} wants an {@code IDownloadable}, not an {@code ArrayList}.
     */
    private static Att invoke(Object instance, String[] names, Object[] args) {
        Att att = new Att();
        if (instance == null) {
            att.note = "no instance";
            return att;
        }
        for (Class<?> k = instance.getClass(); k != null; k = k.getSuperclass()) {
            for (Method m : safeMethods(k)) {
                if (!nameIn(m.getName(), names)) {
                    continue;
                }
                Class<?>[] ps = m.getParameterTypes();
                if (ps.length != args.length) {
                    continue;
                }
                if (!accepts(ps, args)) {
                    att.note = "no overload accepts these arguments";
                    continue;
                }
                try {
                    m.setAccessible(true);
                    Object r = m.invoke(instance, args);
                    att.ok = true;
                    att.ret = r;
                    att.note = "ok, returned " + brief(r);
                } catch (Throwable t) {
                    Throwable c = t.getCause() == null ? t : t.getCause();
                    att.ok = false;
                    att.note = "threw " + c;
                }
                return att;
            }
        }
        return att;
    }

    private static boolean nameIn(String n, String[] names) {
        for (String x : names) {
            if (x.equals(n)) {
                return true;
            }
        }
        return false;
    }

    private static boolean accepts(Class<?>[] ps, Object[] args) {
        for (int i = 0; i < ps.length; i++) {
            if (args[i] == null) {
                continue;
            }
            if (!boxed(ps[i]).isInstance(args[i])) {
                return false;
            }
        }
        return true;
    }

    private static Class<?> boxed(Class<?> c) {
        if (!c.isPrimitive()) {
            return c;
        }
        if (c == int.class) {
            return Integer.class;
        }
        if (c == long.class) {
            return Long.class;
        }
        if (c == boolean.class) {
            return Boolean.class;
        }
        if (c == short.class) {
            return Short.class;
        }
        if (c == byte.class) {
            return Byte.class;
        }
        if (c == char.class) {
            return Character.class;
        }
        if (c == float.class) {
            return Float.class;
        }
        if (c == double.class) {
            return Double.class;
        }
        return c;
    }

    /** A main-thread Handler, for anything that must touch the UI. */
    static Handler mainHandler() {
        return new Handler(Looper.getMainLooper());
    }
}
