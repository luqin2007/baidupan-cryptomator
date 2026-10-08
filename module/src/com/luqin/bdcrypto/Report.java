package com.luqin.bdcrypto;

import android.content.Context;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Comparator;

/**
 * Probe output channel.
 *
 * <p>Big dumps do not belong in logcat: records are truncated, ordering is interleaved with the
 * app's own logging, and reading them back through adb is painful. Instead every probe writes a
 * plain text file into the app's own external files dir, which a non-root {@code adb pull} can
 * reach. logcat then only carries a one-line pointer to the file.
 *
 * <p>Path on device: {@code /sdcard/Android/data/com.baidu.drive.app/files/bdcrypto/}
 */
public final class Report {

    private static final Charset UTF8 = Charset.forName("UTF-8");

    private Report() {
    }

    public static File dir(Context ctx) {
        File base = ctx.getExternalFilesDir(null);
        if (base == null) {
            base = ctx.getFilesDir();
        }
        File d = new File(base, "bdcrypto");
        if (!d.isDirectory() && !d.mkdirs()) {
            Logx.w("Report: cannot create " + d);
        }
        return d;
    }

    public static String path(Context ctx, String name) {
        return new File(dir(ctx), name).getAbsolutePath();
    }

    /**
     * A short tag for the process this code is running in — {@code main} or {@code p2p}.
     *
     * <p>A probe broadcast is delivered to <em>every</em> process the module is loaded into, and
     * they all report to the same directory. Two answers to one question is not the problem; two
     * answers written to one file is, because the second silently erases the first and the reader
     * has no way to notice. That is exactly how a held CloudFile was declared missing: the main
     * process's list had the file, the {@code :p2p} process's list did not, and
     * {@code ch files} showed the empty one.
     */
    public static String processTag(Context ctx) {
        String name = null;
        try {
            String full = ctx == null ? null : ctx.getPackageName();
            if (full != null) {
                int i = full.indexOf(':');
                name = i < 0 ? "main" : full.substring(i + 1);
            }
        } catch (Throwable ignored) {
            // fall through to the pid form
        }
        if (name == null || name.isEmpty()) {
            name = "pid" + android.os.Process.myPid();
        }
        return name.replaceAll("[^A-Za-z0-9_-]", "_");
    }

    /** {@code <name>} with the process tag spliced in before the extension. */
    public static String perProcess(Context ctx, String name) {
        int dot = name.lastIndexOf('.');
        String tag = processTag(ctx);
        return dot < 0 ? name + "-" + tag : name.substring(0, dot) + "-" + tag + name.substring(dot);
    }

    /** Writes (overwrites) a report and returns its absolute path, or null on failure. */
    public static String write(Context ctx, String name, String content) {
        File f = new File(dir(ctx), name);
        try {
            FileOutputStream fos = new FileOutputStream(f);
            try {
                Writer w = new OutputStreamWriter(fos, UTF8);
                w.write(content == null ? "" : content);
                w.flush();
            } finally {
                fos.close();
            }
            return f.getAbsolutePath();
        } catch (Throwable t) {
            Logx.e("Report: write failed " + f, t);
            return null;
        }
    }

    public static String listing(Context ctx) {
        File[] files = dir(ctx).listFiles();
        if (files == null) {
            return "(no files)";
        }
        Arrays.sort(files, new Comparator<File>() {
            @Override
            public int compare(File a, File b) {
                return Long.compare(b.lastModified(), a.lastModified());
            }
        });
        StringBuilder sb = new StringBuilder();
        for (File f : files) {
            sb.append(String.format("%10d  %s  %s%n", f.length(),
                    new java.text.SimpleDateFormat("MM-dd HH:mm:ss", java.util.Locale.US)
                            .format(new java.util.Date(f.lastModified())),
                    f.getAbsolutePath()));
        }
        return sb.toString();
    }

    public static void clear(Context ctx) {
        File[] files = dir(ctx).listFiles();
        if (files != null) {
            for (File f : files) {
                //noinspection ResultOfMethodCallIgnored
                f.delete();
            }
        }
    }
}
