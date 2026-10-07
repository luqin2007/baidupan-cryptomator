package com.luqin.bdcrypto;

import android.app.Activity;
import android.os.Handler;
import android.os.Looper;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/**
 * The content channel: captures how the app itself starts a download, and replays it.
 *
 * <p>This is P0-B. The question it answers is "given a cloud file, which call produces its bytes",
 * and the answer cannot come from a disassembler: every class in the pipeline is method-obfuscated
 * ({@code f}, {@code l}, {@code __}), and the one type that would let us be self-sufficient —
 * {@code IDownloadProcessorFactory} — returns an <em>abstract class</em>
 * ({@code com.baidu.netdisk.transfer.base.Processor}, one abstract method {@code _()}), so it
 * cannot be satisfied by a {@code java.lang.reflect.Proxy} and cannot be subclassed at runtime
 * without generating bytecode. Neither can a {@code TaskResultReceiver} be invented: it extends
 * {@code WeakRefResultReceiver} and its whole job is to be called back by machinery we do not own.
 *
 * <p>So the objects are borrowed instead of built. The app produces a factory, a receiver and the
 * manager instance on every real download; this class keeps the ones it sees, and a later call can
 * be made with them. That is the whole design: observe once, replay after.
 *
 * <p>Two deliberate differences from {@code Hooks.hookDownloadPipeline}:
 * <ul>
 *   <li>That hook is capped at {@code MAX_CHANNEL_LOGS} raw lines, and the app makes hundreds of
 *       {@code [dl]} calls before any download starts, so the interesting line is exactly the one
 *       that gets dropped. Here every call is keyed by its <em>signature</em> — declaring class,
 *       method name, parameter types — and a signature is logged the first time it is ever seen.
 *       Volume therefore cannot hide it.</li>
 *   <li>That hook logs only rendered arguments. Here {@code IDownloadProcessorFactory},
 *       {@code TaskResultReceiver}, {@code CloudFile} and {@code Activity} arguments are also
 *       <em>retained</em>, because retaining them is the point.</li>
 * </ul>
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

    /** The last {@code N} CloudFiles the list handed us, so a replay has something to download. */
    private static final int MAX_FILES = 200;
    private static final List<Object> files = Collections.synchronizedList(new ArrayList<Object>());

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
                if (java.lang.reflect.Modifier.isAbstract(mod)
                        || java.lang.reflect.Modifier.isNative(mod)) {
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
        String owner = p.method == null ? "?" : p.method.getDeclaringClass().getName();
        String name = p.method == null ? "?" : p.method.getName();
        Object[] args = p.args == null ? new Object[0] : p.args;

        // Retain the objects the pipeline hands around. This is the capture.
        for (Object a : args) {
            retain(a, owner, name);
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

    /**
     * Keeps the handful of objects a replay needs, and names anything else that is obviously part
     * of the pipeline so the shape of a real download is visible in the log.
     */
    private static void retain(Object a, String owner, String name) {
        if (a == null) {
            return;
        }
        String cn = a.getClass().getName();
        if (cn.endsWith("IDownloadProcessorFactory") || cn.endsWith("DownloadProcessorFactory")) {
            if (lastFactory != a) {
                lastFactory = a;
                lastTrigger = owner + "." + name;
                Logx.i("[ch#factory] borrowed IDownloadProcessorFactory from " + lastTrigger
                        + " -> " + cn);
            }
        } else if (cn.endsWith("TaskResultReceiver")) {
            if (lastReceiver != a) {
                lastReceiver = a;
                Logx.i("[ch#receiver] borrowed TaskResultReceiver from " + owner + "." + name
                        + " -> " + cn);
            }
        } else if (a instanceof Activity) {
            lastActivity = a;
        } else if (cn.endsWith("DownloadTaskManager")) {
            manager = a;
        } else if (cn.endsWith("FDDownloadManagerApi")) {
            api = a;
        } else if (cn.endsWith("SingleFileDownloadHelper")) {
            helper = a;
        } else if (cn.endsWith("ExternalDownloadHelper")) {
            extHelper = a;
        }
    }

    /** Records a CloudFile the list produced, so a replay has a real object to hand the pipeline. */
    static void noteFile(Object o) {
        if (o == null) {
            return;
        }
        for (Object e : files) {
            if (e == o) {
                return;
            }
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
        if (cn.startsWith("java.util.") && o instanceof List) {
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
        Object r = p.getResult();
        return r == null ? "  -> void/null" : "  -> " + brief(r);
    }

    // ------------------------------------------------------------- probe ----

    /** {@code ch} probe: {@code last} | {@code files} | {@code go <n|name> [flag]}. */
    public static String command(String arg) {
        String a = arg == null ? "" : arg.trim();
        if (a.isEmpty() || "last".equalsIgnoreCase(a)) {
            return report();
        }
        if ("files".equalsIgnoreCase(a)) {
            return fileList();
        }
        if (a.startsWith("go")) {
            return replay(a.length() > 2 ? a.substring(2).trim() : "");
        }
        return "ch: unknown argument '" + a + "' (last | files | go <n|name> [flag])";
    }

    private static String report() {
        StringBuilder sb = new StringBuilder("channel capture\n");
        sb.append("  manager      : ").append(typeName(manager)).append('\n');
        sb.append("  api          : ").append(typeName(api)).append('\n');
        sb.append("  helper       : ").append(typeName(helper)).append('\n');
        sb.append("  extHelper    : ").append(typeName(extHelper)).append('\n');
        sb.append("  activity     : ").append(typeName(lastActivity)).append('\n');
        sb.append("  factory      : ").append(typeName(lastFactory))
                .append("  (from ").append(lastTrigger).append(")\n");
        sb.append("  receiver     : ").append(typeName(lastReceiver)).append('\n');
        sb.append("  files held   : ").append(files.size()).append('\n');
        sb.append("  distinct call signatures: ").append(sigs.size()).append('\n');
        int shown = 0;
        for (String s : sigs) {
            if (shown++ >= 60) {
                sb.append("  … ").append(sigs.size() - 60).append(" more\n");
                break;
            }
            sb.append("    ").append(s).append('\n');
        }
        if (sigs.isEmpty()) {
            sb.append("    (none — no download has been attempted in this process)\n");
        }
        return sb.toString();
    }

    private static String typeName(Object o) {
        return o == null ? "<null>" : o.getClass().getName();
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

    // ------------------------------------------------------------ replay ----

    /**
     * Starts a real download of a held CloudFile using the borrowed factory and receiver.
     *
     * <p>Deliberately runs on a background thread: this is called from the probe thread already, and
     * the pipeline is free to be slow — but nothing here may run on the main thread, because the
     * replay is meant to be usable while the app is busy painting a list.
     */
    private static String replay(String spec) {
        String[] parts = spec.split("\\s+");
        String which = parts.length > 0 ? parts[0] : "";
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
        List<Object> copy = new ArrayList<Object>(files);
        Object target = null;
        try {
            int idx = Integer.parseInt(which);
            if (idx >= 0 && idx < copy.size()) {
                target = copy.get(idx);
            }
        } catch (Throwable ignored) {
            for (Object o : copy) {
                if (which.equals(Reflectx.callStr(o, "getFileName"))) {
                    target = o;
                    break;
                }
            }
        }
        if (target == null) {
            return "ch go: no held CloudFile matches '" + which + "' (" + copy.size() + " held)";
        }
        if (lastFactory == null || lastReceiver == null) {
            return "ch go: no factory/receiver borrowed yet — perform one real download first "
                    + "(factory=" + typeName(lastFactory) + " receiver=" + typeName(lastReceiver) + ")";
        }
        if (manager == null) {
            return "ch go: no DownloadTaskManager instance captured yet";
        }
        StringBuilder sb = new StringBuilder("ch go: ");
        sb.append("file=").append(Reflectx.callStr(target, "getFileName"))
                .append(" flag=").append(flag).append('\n');
        sb.append(run(manager, "f", new Object[]{target, lastFactory, lastReceiver, flag},
                "DownloadTaskManager.f"));
        return sb.toString();
    }

    /** Invokes the first method of that name, whatever its parameters, and reports the outcome. */
    private static String run(Object instance, String method, Object[] args, String label) {
        if (instance == null) {
            return "  " + label + ": no instance\n";
        }
        for (Class<?> k = instance.getClass(); k != null; k = k.getSuperclass()) {
            for (Method m : safeMethods(k)) {
                if (!m.getName().equals(method)) {
                    continue;
                }
                if (m.getParameterTypes().length != args.length) {
                    continue;
                }
                try {
                    m.setAccessible(true);
                    Object r = m.invoke(instance, args);
                    return "  " + label + " -> ok, result=" + brief(r) + "\n";
                } catch (Throwable t) {
                    Throwable cause = t.getCause() == null ? t : t.getCause();
                    return "  " + label + " !! " + cause + "\n";
                }
            }
        }
        return "  " + label + ": method not found\n";
    }

    /** A main-thread Handler, for anything that must touch the UI. */
    static Handler mainHandler() {
        return new Handler(Looper.getMainLooper());
    }
}
