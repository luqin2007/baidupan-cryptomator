package com.luqin.bdcrypto;

import android.util.Log;

import de.robv.android.xposed.XposedBridge;

/**
 * Logging helper.
 *
 * <p>Two sinks on purpose:
 * <ul>
 *   <li>{@code android.util.Log} → visible to a plain (non-root) {@code adb logcat -s BDCrypto:I},
 *       which is the only observation channel we have on this device ({@code su} is unavailable
 *       from an adb shell). Long payloads are split so nothing is lost to the per-record limit.</li>
 *   <li>{@code XposedBridge.log} → shows up in the LSPosed manager's own log, so the module can be
 *       diagnosed even when logcat is filtered.</li>
 * </ul>
 */
public final class Logx {

    public static final String TAG = "BDCrypto";

    /** logcat drops records above ~4 KiB; stay comfortably below that. */
    private static final int CHUNK = 3000;

    private Logx() {
    }

    public static void i(String msg) {
        emit(Log.INFO, msg);
    }

    public static void w(String msg) {
        emit(Log.WARN, msg);
    }

    public static void e(String msg) {
        emit(Log.ERROR, msg);
    }

    public static void e(String msg, Throwable t) {
        emit(Log.ERROR, msg + " :: " + t);
        if (t != null) {
            emit(Log.ERROR, Log.getStackTraceString(t));
        }
    }

    private static void emit(int prio, String msg) {
        String body = msg == null ? "null" : msg;
        try {
            XposedBridge.log(TAG + ": " + brief(body));
        } catch (Throwable ignored) {
            // XposedBridge may be unavailable in odd loaders; logcat still works.
        }
        if (body.isEmpty()) {
            Log.println(prio, TAG, "(empty)");
            return;
        }
        for (int i = 0; i < body.length(); i += CHUNK) {
            Log.println(prio, TAG, body.substring(i, Math.min(body.length(), i + CHUNK)));
        }
    }

    private static String brief(String s) {
        if (s.length() <= 400) {
            return s;
        }
        return s.substring(0, 400) + " …[" + s.length() + " chars]";
    }
}
