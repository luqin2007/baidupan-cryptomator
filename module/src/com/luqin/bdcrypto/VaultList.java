package com.luqin.bdcrypto;

import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import com.luqin.bdcrypto.vault.Vault;

import java.util.ArrayList;
import java.util.List;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/**
 * Rewrites the file page's rows so an unlocked vault reads like a normal folder.
 *
 * <p><b>Display only, and deliberately so.</b> The model ({@code CloudFile}) keeps the ciphertext
 * name: every operation the app performs — download, delete, share, rename — has to keep acting on
 * the original ciphertext file, which is P4's whole contract. Only the {@code TextView} inside the
 * bound row is touched.
 *
 * <p>Where the name lives was measured on a real content page rather than guessed: the row is
 * {@code id/checkable_layout}, the name is {@code id/text1} inside it, and the adapter's view holder
 * declares no fields (it binds with {@code findViewById}), so the id is as good as a field would be.
 * The text is still matched as a fallback, because a row whose text is a ciphertext name is
 * unambiguous whatever view it sits in.
 *
 * <p>What it does, per row, for a directory whose id is known:
 * <ul>
 *   <li>a {@code .c9r} name → the decrypted cleartext name;</li>
 *   <li>one of the format's own files ({@code dirid.c9r}, …) → the row is hidden;</li>
 *   <li>anything else (a shortened {@code .c9s} entry, {@code vault.cryptomator}, a toolbar or a
 *       header row) → left exactly as the app drew it.</li>
 * </ul>
 *
 * <p>Nothing here is attempted unless the page's directory id is known, which at this stage means
 * the vault root: a {@code d/XY/…} path is named after {@code hashDirectoryId(dirId)}, and that is
 * one-way, so a directory the session has not descended into cannot be decrypted. Sizes are also
 * still the ciphertext sizes the app computed — translating them is a separate step.
 */
public final class VaultList {

    /**
     * Where the rows are bound. The RecyclerView entry point is inherited from
     * {@code RecyclerCursorAdapter} — the adapter itself declares only the obfuscated
     * {@code O(ViewHolder, Cursor)} that entry point dispatches to — so the base class is the hook
     * that matters; hooking the subclass too costs nothing and covers the case where an app update
     * gives it its own override.
     */
    private static final String[] ADAPTERS = {
            "com.baidu.netdisk.kernel.architecture.adapter.RecyclerCursorAdapter",
            "com.baidu.netdisk.filelist.view.FileListAdapter",
    };

    /** The row's name view, measured on /crypto/content/d/SY/… (see recon/p2ui/RECON.md). */
    private static final String NAME_ID = "text1";

    /** The directory the drawn page is showing, as a cloud path. Set by {@link Hooks#reconcile}. */
    private static volatile String drawnCloudPath;

    /** The session the last reconcile saw, so a fresh unlock can force a rebind. */
    private static volatile VaultUi.Session lastSessionSeen;

    private static volatile boolean loggedFailure;

    private static volatile int nameId;

    private VaultList() {
    }

    public static void install(ClassLoader cl) {
        for (String name : ADAPTERS) {
            Class<?> c = XposedHelpers.findClassIfExists(name, cl);
            if (c == null) {
                Logx.w("[list] adapter not found: " + name);
                continue;
            }
            try {
                XposedBridge.hookAllMethods(c, "onBindViewHolder", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        try {
                            afterBind(param);
                        } catch (Throwable t) {
                            if (!loggedFailure) {
                                loggedFailure = true;
                                Logx.e("[list] rewriting a row failed (logged once)", t);
                            }
                        }
                    }
                });
                Logx.i("[list] hooked " + name + ".onBindViewHolder");
            } catch (Throwable t) {
                Logx.w("[list] hook " + name + " failed: " + t);
            }
        }
    }

    /**
     * Told by the button's reconcile pass which directory the window is actually drawing.
     *
     * @return true when the rows need binding again: the page moved, or a different vault is
     *     unlocked than the last time this was asked (unlocking while standing in the vault root
     *     changes every row without changing the directory)
     */
    static boolean noteDrawnPath(String cloudPath) {
        boolean changed = drawnCloudPath == null ? cloudPath != null : !drawnCloudPath.equals(cloudPath);
        drawnCloudPath = cloudPath;
        VaultUi.Session session = VaultUi.session();
        if (session != lastSessionSeen) {
            lastSessionSeen = session;
            changed = true;
        }
        return changed;
    }

    static String drawnPath() {
        return drawnCloudPath;
    }

    private static void afterBind(XC_MethodHook.MethodHookParam param) {
        VaultUi.Session session = VaultUi.session();
        if (session == null || param.args == null || param.args.length == 0) {
            return;
        }
        String relative = vaultRelative(session.cloudDir, drawnCloudPath);
        if (relative == null) {
            return;
        }
        String dirId = session.dirIdOf(relative);
        if (dirId == null) {
            // This page is inside the vault but the session has not descended into it (or it is a
            // .c9s pointer folder, whose internals must stay visible rather than be rewritten).
            return;
        }
        View row = viewOf(param.args[0]);
        if (row == null) {
            return;
        }
        rewrite(row, session.vault, dirId);
    }

    private static void rewrite(View row, Vault vault, String dirId) {
        TextView name = nameView(row);
        if (name == null) {
            return;
        }
        CharSequence cs = name.getText();
        String text = cs == null ? "" : cs.toString();
        if (!text.endsWith(".c9r") && !text.endsWith(".c9s")) {
            // Not one of the vault's entries: a toolbar, a header, vault.cryptomator itself. Its
            // visibility is the app's business, so nothing here touches it.
            return;
        }
        if (Vault.isInternal(text)) {
            // A content row the user must not see. Safe to hide because every visible row is
            // rebound, and the next rebind of this view puts it back (below).
            row.setVisibility(View.GONE);
            return;
        }
        row.setVisibility(View.VISIBLE);
        if (text.endsWith(".c9s")) {
            // A shortened name: its cleartext name lives inside the folder, which cannot be read
            // until that folder is listed. Left as drawn rather than guessed at.
            return;
        }
        try {
            String cleartext = vault.name(dirId, text);
            if (cleartext != null && !cleartext.equals(text)) {
                name.setText(cleartext);
            }
        } catch (Throwable t) {
            Logx.w("[list] " + text + " does not decrypt under " + dirId + ": " + t);
        }
    }

    /**
     * The view a row displays its file name in: by resource id first ({@code id/text1}, measured),
     * and otherwise whichever of the row's text views is holding a ciphertext name — which the app
     * has just written, so it is unambiguous.
     */
    private static TextView nameView(View row) {
        int id = nameId();
        if (id != 0) {
            View v = row.findViewById(id);
            if (v instanceof TextView) {
                return (TextView) v;
            }
        }
        List<TextView> texts = new ArrayList<TextView>();
        collectTexts(row, texts, 0);
        for (TextView tv : texts) {
            CharSequence cs = tv.getText();
            String text = cs == null ? "" : cs.toString();
            if (text.endsWith(".c9r") || text.endsWith(".c9s")) {
                return tv;
            }
        }
        return null;
    }

    private static int nameId() {
        int id = nameId;
        if (id == 0 && Hooks.app() != null) {
            id = Hooks.app().getResources().getIdentifier(NAME_ID, "id", Hooks.APP_PKG);
            nameId = id;
        }
        return id;
    }

    private static void collectTexts(View v, List<TextView> out, int depth) {
        if (depth > 8) {
            return;
        }
        if (v instanceof TextView) {
            out.add((TextView) v);
        }
        if (v instanceof ViewGroup) {
            ViewGroup g = (ViewGroup) v;
            for (int i = 0; i < g.getChildCount(); i++) {
                collectTexts(g.getChildAt(i), out, depth + 1);
            }
        }
    }

    /** The row view a view holder is drawing, or null. */
    private static View viewOf(Object holder) {
        if (holder instanceof View) {
            return (View) holder;
        }
        try {
            Object v = XposedHelpers.getObjectField(holder, "itemView");
            return v instanceof View ? (View) v : null;
        } catch (Throwable t) {
            return null;
        }
    }

    /**
     * The vault-relative path of the drawn directory, or null when the page is not inside the
     * unlocked vault. The breadcrumb is prefixed with crumb names the module does not own — e.g.
     * {@code /我的网盘/crypto/content/…} — so this matches on the vault's own cloud path.
     */
    private static String vaultRelative(String cloudDir, String drawn) {
        if (cloudDir == null || drawn == null) {
            return null;
        }
        int at = drawn.indexOf(cloudDir);
        if (at < 0) {
            return null;
        }
        String rel = drawn.substring(at + cloudDir.length());
        while (rel.startsWith("/")) {
            rel = rel.substring(1);
        }
        return rel.isEmpty() ? null : rel;
    }
}
