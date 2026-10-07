package com.luqin.bdcrypto;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;

import de.robv.android.xposed.XposedHelpers;

/**
 * Interactive probe channel.
 *
 * <p>Reinstalling an Xposed module is a multi-second round trip (build → install → relaunch →
 * re-tick scope). During reverse engineering we need to ask the *running* app questions dozens of
 * times, so the module exposes a dynamically registered broadcast receiver:
 *
 * <pre>
 *   adb shell am broadcast -a com.luqin.bdcrypto.PROBE --es cmd dump \
 *       --es cls com.baidu.netdisk.filelist.view.FileListWrapperAdapter
 * </pre>
 *
 * <p>The receiver is registered with {@code RECEIVER_EXPORTED} because the sender is the adb shell
 * UID, not the app. Registration happens from the app's own {@code Application.onCreate}, so the
 * receiver only exists while the app process is alive — it is not a manifest receiver and leaks
 * nothing when the app is not running.
 */
public final class ProbeReceiver extends BroadcastReceiver {

    public static final String ACTION = "com.luqin.bdcrypto.PROBE";

    private static volatile boolean installed;

    private ProbeReceiver() {
    }

    public static void install(Context ctx) {
        if (installed) {
            return;
        }
        try {
            IntentFilter filter = new IntentFilter(ACTION);
            if (Build.VERSION.SDK_INT >= 33) {
                ctx.registerReceiver(new ProbeReceiver(), filter, Context.RECEIVER_EXPORTED);
            } else {
                ctx.registerReceiver(new ProbeReceiver(), filter);
            }
            installed = true;
            Logx.i("probe channel ready: am broadcast -a " + ACTION + " --es cmd help");
        } catch (Throwable t) {
            Logx.e("probe registration failed", t);
        }
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null || !ACTION.equals(intent.getAction())) {
            return;
        }
        final Context ctx = context.getApplicationContext();
        final String cmd = str(intent, "cmd");
        final String cls = str(intent, "cls");
        final String arg = str(intent, "arg");
        // Never block the main thread: class dumps and class scanning are not free.
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                long started = System.currentTimeMillis();
                try {
                    Probe.execute(ctx, cmd, cls, arg);
                } catch (Throwable e) {
                    Logx.e("probe '" + cmd + "' threw", e);
                }
                Logx.i("probe '" + cmd + "' done in " + (System.currentTimeMillis() - started) + " ms");
            }
        }, "bdcrypto-probe");
        t.setDaemon(true);
        t.start();
    }

    private static String str(Intent i, String key) {
        String v = i.getStringExtra(key);
        return v == null ? "" : v.trim();
    }

    /** Reads a text resource shipped in the module APK through the module's own classloader. */
    public static String asset(String name) {
        return Probe.readAsset("assets/" + name);
    }

    /** Convenience for the {@code hook} probe: does a class resolve in the app's loader? */
    public static Class<?> resolve(String className) {
        ClassLoader cl = Probe.appClassLoader();
        Class<?> c = XposedHelpers.findClassIfExists(className, cl);
        if (c != null) {
            return c;
        }
        try {
            return Class.forName(className, false, cl);
        } catch (Throwable t) {
            return null;
        }
    }
}
