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
     *
     * <p>{@link android.app.Application#getProcessName()} (API 28) is the only honest source for
     * this, and the obvious alternative is a trap that has already cost one wrong conclusion.
     * Measured 2026-10-08: {@code Context.getPackageName()} answers with the <em>base</em> package
     * in every process of that package, so {@code :p2p} was tagged {@code main} as well — one probe
     * answered twice into {@code nav-main.txt}, and the file came back as neither answer: the
     * shorter one's {@code …the activity has (none)} sitting where the longer one's fragment list
     * had been, with the rest of that list still glued on behind. Read at face value it said "the
     * live page has no fragments at all", which is the exact opposite of what the same run's logcat
     * reported and would have sent the search somewhere useless.
     */
    public static String processTag(Context ctx) {
        String name = null;
        try {
            name = android.app.Application.getProcessName();
        } catch (Throwable ignored) {
            // Pre-28 platform, or the call is not there: fall through.
        }
        if (name == null) {
            try {
                name = ctx == null ? null : ctx.getPackageName();
            } catch (Throwable ignored) {
                // then only the pid is left
            }
        }
        if (name != null) {
            int i = name.indexOf(':');
            // A name without a colon is the base package, i.e. the main process.
            name = i < 0 ? "main" : name.substring(i + 1);
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

    /**
     * Writes (overwrites) a report and returns its absolute path, or null on failure.
     *
     * <p>Writes beside the target and renames over it, because two processes can answer one probe
     * and a plain overwrite is not a write of one answer but of two interleaved ones. Measured
     * 2026-10-08: the two writers' bytes ended up in a single file, spliced at the offset where
     * the shorter answer stopped, producing a report that no process had ever produced — and a
     * believable one, which is worse than a missing one. A rename on the same filesystem is
     * atomic, so the file is always exactly one process's complete answer.
     */
    public static String write(Context ctx, String name, String content) {
        File d = dir(ctx);
        File f = new File(d, name);
        File tmp = new File(d, name + ".tmp-" + android.os.Process.myPid());
        try {
            FileOutputStream fos = new FileOutputStream(tmp);
            try {
                Writer w = new OutputStreamWriter(fos, UTF8);
                w.write(content == null ? "" : content);
                w.flush();
            } finally {
                fos.close();
            }
            if (!tmp.renameTo(f)) {
                // rename is same-filesystem only; a copy still beats having no report
                copy(tmp, f);
            }
            return f.getAbsolutePath();
        } catch (Throwable t) {
            Logx.e("Report: write failed " + f, t);
            return null;
        } finally {
            //noinspection ResultOfMethodCallIgnored
            tmp.delete();
        }
    }

    private static void copy(File from, File to) throws java.io.IOException {
        java.io.InputStream in = new java.io.FileInputStream(from);
        try {
            java.io.OutputStream out = new FileOutputStream(to);
            try {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) > 0) {
                    out.write(buf, 0, n);
                }
            } finally {
                out.close();
            }
        } finally {
            in.close();
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
