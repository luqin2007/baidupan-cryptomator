package com.luqin.bdcrypto;

import android.content.Context;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Probe command set. Driven from {@link ProbeReceiver}.
 *
 * <p>Every answer is produced from the *live* app process, so it reflects the exact class shapes R8
 * and the running build produced — not what a decompiler guessed.
 */
public final class Probe {

    /** Classes worth resolving on sight; the P0 acceptance criterion is "all of these resolve". */
    static final String[] KEY_CLASSES = {
            // --- file page (P1/P2 injection points) ---
            "com.baidu.netdisk.allfiles.listfragment.FileTabListFragment",
            "com.baidu.netdisk.allfiles.listfragment.extraview.header.FileListToolBarHeaderView",
            "com.baidu.netdisk.filelist.view.FileListWrapperAdapter",
            "com.baidu.netdisk.swipeback.view.NetDiskFileListFragment",
            "com.baidu.netdisk.filelist.repository.CloudFileListLoader",
            "com.baidu.netdisk.db.cursor.ObjectCursorLoader",
            // --- file model + list rows ---
            "com.baidu.netdisk.cloudfile.io.model.CloudFile",
            // --- download pipeline (P0-B) ---
            "com.baidu.netdisk.transfer.base.IDownloadable",
            "com.baidu.netdisk.transfer.download.SingleFileDownloadHelper",
            "com.baidu.netdisk.transfer.task.DownloadTaskManager",
            "com.baidu.netdisk.download.IDownloadTaskGenerator",
            "com.baidu.netdisk.file.download.component.apis.FDDownloadManagerApi",
            "com.baidu.netdisk.cloudp2p.component.provider.CloudP2pDlinkApi",
            "com.baidu.netdisk.transfer.io.model.LocateDownloadResponse",
            "com.baidu.netdisk.transfer.transmitter.locate.LocateDownloadUrls",
            "com.baidu.netdisk.util.ExternalDownloadHelper",
            // --- network stack ---
            "okhttp3.OkHttpClient",
            "okhttp3.Request$Builder",
            "retrofit2.Retrofit",
    };

    private Probe() {
    }

    public static ClassLoader appClassLoader() {
        return Hooks.cl();
    }

    public static void execute(Context ctx, String cmd, String cls, String arg) {
        if (cmd == null || cmd.isEmpty() || "help".equals(cmd)) {
            help();
        } else if ("ls".equals(cmd)) {
            Logx.i("reports:\n" + Report.listing(ctx));
        } else if ("clear".equals(cmd)) {
            Report.clear(ctx);
            Logx.i("reports cleared");
        } else if ("selftest".equals(cmd)) {
            selftest(ctx);
        } else if ("dump".equals(cmd)) {
            dump(ctx, cls);
        } else if ("classes".equals(cmd)) {
            searchClassList(ctx, cls);
        } else if ("resolve".equals(cmd)) {
            Class<?> c = ProbeReceiver.resolve(cls);
            Logx.i("resolve " + cls + " -> " + (c == null ? "NOT FOUND" : c.getName() + " loader=" + c.getClassLoader()));
        } else if ("graph".equals(cmd)) {
            Logx.i(Hooks.graphOfLastFragment());
        } else if ("items".equals(cmd)) {
            Logx.i(Hooks.dumpCloudFiles());
        } else if ("columns".equals(cmd)) {
            Logx.i(Hooks.dumpCursorColumns());
        } else if ("state".equals(cmd)) {
            Logx.i(Hooks.stateSummary());
        } else if ("net".equals(cmd)) {
            Logx.i(Hooks.dumpHttpUrls());
        } else if ("tree".equals(cmd)) {
            Logx.i(Hooks.toolbarTreeNow());
        } else if ("btn".equals(cmd)) {
            Logx.i(Hooks.buttonCommand(arg));
        } else if ("copies".equals(cmd)) {
            Logx.i(Hooks.copiesReport("probe"));
        } else if ("ch".equals(cmd)) {
            Channel.command(ctx, arg);
        } else if ("get".equals(cmd)) {
            Logx.i(Channel.get(arg.isEmpty() ? cls : arg));
        } else if ("vault".equals(cmd)) {
            VaultProbe.run(ctx, arg.isEmpty() ? cls : arg);
        } else if ("unlock".equals(cmd)) {
            // The button's own path (fetch config, open the vault, keep the session) without the
            // dialog, so the device test can be scripted: <cloudDir>=<passphrase>.
            int eq = arg.indexOf('=');
            if (eq <= 0 || eq == arg.length() - 1) {
                Logx.w("usage: --es cmd unlock --es arg <cloudDir>=<passphrase>");
            } else {
                Logx.i(VaultUi.unlockNow(arg.substring(0, eq), arg.substring(eq + 1)));
            }
        } else if ("session".equals(cmd)) {
            Logx.i("vault session: " + VaultUi.stateLine());
        } else {
            Logx.w("unknown cmd: " + cmd);
            help();
        }
    }

    private static void help() {
        Logx.i("probe commands (am broadcast -a " + ProbeReceiver.ACTION + " --es cmd <c> [--es cls <x>]):\n"
                + "  help                      this text\n"
                + "  selftest                  resolve every class this module cares about\n"
                + "  dump <class>              full member dump (real signatures) -> report file\n"
                + "  classes <regex>           search the shipped index of all app class names\n"
                + "  resolve <class>           is it loaded in the app?\n"
                + "  graph                     object graph of the last seen FileTabListFragment\n"
                + "  items                     every CloudFile row captured from the Cursor so far\n"
                + "  columns                   distinct Cursor column-name sets seen\n"
                + "  net                       HTTP URLs observed\n"
                + "  tree                      measure the toolbar view tree around id/filter, again\n"
                + "  copies                    every page copy in the window: what it is showing, what\n"
                + "                              is in its toolbar, and the colour/alpha of each child\n"
                + "  btn [args]                inject / style / remove the unlock button\n"
                + "                              off | diag | text=<label> | w=<px> | size=<sp>\n"
                + "  ch [arg]                  content channel (P0-B)\n"
                + "                              last   - what was captured, and every distinct call\n"
                + "                              files  - CloudFiles held from the list, for a replay\n"
                + "                              hier   - the type graph of each captured object\n"
                + "                                       (the only way to read an R8-renamed class)\n"
                + "                              go <n|name> [flag] - download one of them for real\n"
                + "  vault <dir>=<pass>        P2: unlock a vault directory on the DEVICE and walk it\n"
                + "                              (report -> vault.txt; use the fixture's passphrase\n"
                + "                               only — the broadcast command line lands in logcat)\n"
                + "  get <cloudPath>           fetch one cloud file through the app and print its\n"
                + "                              first bytes as hex + ascii. Built for the vault's\n"
                + "                              36-byte dir.c9r pointers: <name>.c9r/dir.c9r holds the\n"
                + "                              child directory's id in the clear, and the id is the\n"
                + "                              only route to that directory's real contents.\n"
                + "  unlock <cloudDir>=<pass>  the unlock button's own path: fetch the two config\n"
                + "                              files, open the vault, keep the session (no dialog)\n"
                + "  session                   what vault is unlocked right now\n"
                + "  state                     one-line summary of what has been captured\n"
                + "  ls | clear                list / delete probe report files");
    }

    // ------------------------------------------------------------ selftest ---

    private static void selftest(Context ctx) {
        StringBuilder sb = new StringBuilder("P0 selftest — class resolution in the live process\n");
        sb.append("pid=").append(android.os.Process.myPid())
                .append(" appLoader=").append(appClassLoader()).append("\n\n");
        int ok = 0;
        for (String name : KEY_CLASSES) {
            Class<?> c = ProbeReceiver.resolve(name);
            if (c == null) {
                sb.append("  MISSING  ").append(name).append('\n');
                continue;
            }
            ok++;
            String extra = "";
            if (c.isInterface()) {
                extra = " [interface]";
            }
            sb.append("  ok       ").append(name).append(extra)
                    .append("  methods=").append(countMethods(c)).append('\n');
        }
        sb.append("\nresolved ").append(ok).append('/').append(KEY_CLASSES.length).append('\n');
        String p = Report.write(ctx, "selftest.txt", sb.toString());
        Logx.i(sb.toString());
        Logx.i("-> " + p);
    }

    private static int countMethods(Class<?> c) {
        try {
            return c.getDeclaredMethods().length;
        } catch (Throwable t) {
            return -1;
        }
    }

    // ---------------------------------------------------------------- dump ---

    private static void dump(Context ctx, String cls) {
        if (cls.isEmpty()) {
            Logx.w("usage: --es cmd dump --es cls <fully.qualified.Class>");
            return;
        }
        Class<?> c = ProbeReceiver.resolve(cls);
        if (c == null) {
            Logx.w("dump: class not found -> " + cls);
            return;
        }
        String body = Reflectx.dumpHierarchy(c);
        String safe = cls.replace('.', '_').replace('$', '_');
        String p = Report.write(ctx, "dump-" + safe + ".txt", body);
        Logx.i("dump of " + cls + " (" + body.length() + " chars)\n" + head(body, 2200)
                + "\n... (full text in " + p + ")");
    }

    private static String head(String s, int n) {
        return s.length() <= n ? s : s.substring(0, n);
    }

    // ------------------------------------------------------ class index -----

    private static void searchClassList(Context ctx, String regex) {
        if (regex.isEmpty()) {
            Logx.w("usage: --es cmd classes --es cls <regex>");
            return;
        }
        Pattern p;
        try {
            p = Pattern.compile(regex);
        } catch (PatternSyntaxException e) {
            Logx.w("bad regex: " + e.getMessage());
            return;
        }
        String idx = readAssetGz("assets/app_classes.txt.gz");
        if (idx == null) {
            Logx.w("class index asset missing from the module apk "
                    + "(regenerate with module/tools/gen_class_index.py)");
            return;
        }
        List<String> hits = new ArrayList<String>();
        BufferedReader r = new BufferedReader(new java.io.StringReader(idx));
        try {
            String line;
            while ((line = r.readLine()) != null) {
                if (p.matcher(line).find()) {
                    hits.add(line.replace('/', '.'));
                    if (hits.size() >= 300) {
                        break;
                    }
                }
            }
        } catch (Throwable t) {
            Logx.e("scan failed", t);
        } finally {
            try {
                r.close();
            } catch (Throwable ignored) {
                // ignore
            }
        }
        StringBuilder sb = new StringBuilder("classes matching /" + regex + "/ -> " + hits.size()
                + (hits.size() >= 300 ? "+ (capped)" : "") + "\n");
        for (String h : hits) {
            sb.append("  ").append(h).append('\n');
        }
        Logx.i(sb.toString());
    }

    /** Reads a classpath resource out of the module APK (not the host app's). */
    static String readAsset(String name) {
        ClassLoader cl = Probe.class.getClassLoader();
        if (cl == null) {
            return null;
        }
        InputStream in = null;
        try {
            in = cl.getResourceAsStream(name);
            if (in == null) {
                return null;
            }
            BufferedReader r = new BufferedReader(new InputStreamReader(in, "UTF-8"));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) {
                sb.append(line).append('\n');
            }
            return sb.toString();
        } catch (Throwable t) {
            return null;
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (Throwable ignored) {
                    // ignore
                }
            }
        }
    }

    /**
     * Same as {@link #readAsset}, but for the gzipped class index. The index is ~3 MB raw and
     * ~260 KB gzipped, which matters because it ships inside the module APK.
     */
    static String readAssetGz(String name) {
        ClassLoader cl = Probe.class.getClassLoader();
        if (cl == null) {
            return null;
        }
        InputStream raw = null;
        java.util.zip.GZIPInputStream gz = null;
        try {
            raw = cl.getResourceAsStream(name);
            if (raw == null) {
                return null;
            }
            gz = new java.util.zip.GZIPInputStream(raw, 1 << 16);
            BufferedReader r = new BufferedReader(new InputStreamReader(gz, "UTF-8"), 1 << 16);
            StringBuilder sb = new StringBuilder(1 << 22);
            String line;
            while ((line = r.readLine()) != null) {
                sb.append(line).append('\n');
            }
            return sb.toString();
        } catch (Throwable t) {
            Logx.w("cannot read " + name + ": " + t);
            return null;
        } finally {
            if (gz != null) {
                try {
                    gz.close();
                } catch (Throwable ignored) {
                    // ignore
                }
            } else if (raw != null) {
                try {
                    raw.close();
                } catch (Throwable ignored) {
                    // ignore
                }
            }
        }
    }
}
