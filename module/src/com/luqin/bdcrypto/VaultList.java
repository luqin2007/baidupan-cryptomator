package com.luqin.bdcrypto;

import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import com.luqin.bdcrypto.vault.Vault;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
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
     * Every class in the page's adapter chain that can carry the per-row bind call.
     *
     * <p>The chain was measured, not guessed (`recon/p2ui/RECON.md` §1.1):
     * {@code FileListRecyclerView} is handed a {@code FileListWrapperAdapter}, which extends
     * {@code RecyclerView.Adapter} and holds the real row adapter {@code FileListAdapter} in its
     * field {@code _}. That one extends {@code RecyclerCursorAdapter}.
     *
     * <p>Hooking all three is deliberate over-coverage. Missing the entry point is silent — the
     * previous build hooked two of them and rewrote nothing at all.
     */
    private static final String[] ADAPTERS = {
            "com.baidu.netdisk.filelist.view.FileListWrapperAdapter",
            "com.baidu.netdisk.kernel.architecture.adapter.RecyclerCursorAdapter",
            "com.baidu.netdisk.filelist.view.FileListAdapter",
    };

    /** The row's name view, measured on /crypto/content/d/SY/… (see recon/p2ui/RECON.md). */
    private static final String NAME_ID = "text1";

    /**
     * How many binds to narrate per page: ordinary rows briefly, ciphertext rows generously.
     *
     * <p>Per page, not per process. A process-wide budget sounds safer and is worse, because the
     * spending is invisible: ordinary browsing reaches the vault directory through the home page,
     * {@code /crypto}, {@code /crypto/content}, {@code d} and {@code d/SY}, and a page that rebinds
     * as it scrolls runs the counter up on its own. Once the budget is gone the module keeps working
     * and stops saying anything, which reads exactly like "the hook never ran" — it cost an entire
     * diagnostic session on a build where the row rewriting was in fact fine.
     *
     * <p>So the cap is per page and split by kind. A ciphertext row is always worth a line (it is
     * the thing being rewritten); a cleartext-looking row is not.
     */
    private static final int BIND_LOG_ROWS_PER_PAGE = 3;
    private static final int BIND_LOG_CIPHERTEXT_PER_PAGE = 24;

    /** The directory the drawn page is showing, as a cloud path. Set by {@link Hooks#reconcile}. */
    private static volatile String drawnCloudPath;

    /** The session the last reconcile saw, so a fresh unlock can force a rebind. */
    private static volatile VaultUi.Session lastSessionSeen;

    /** ...and whether it was open at the time, which changes rows without changing the session. */
    private static volatile boolean lastUnlockedSeen;

    private static volatile boolean loggedFailure;

    private static volatile int nameId;

    /** Binds narrated so far. Only ever touched from a bind, i.e. the UI thread. */
    private static String bindLogPath;
    private static int bindLogsForPath;
    private static int bindCiphertextForPath;

    private VaultList() {
    }

    public static void install(ClassLoader cl) {
        int total = 0;
        for (String name : ADAPTERS) {
            Class<?> c = XposedHelpers.findClassIfExists(name, cl);
            if (c == null) {
                Logx.w("[list] adapter not found: " + name);
                continue;
            }
            total += hookBindEntries(c, name);
        }
        Logx.i("[list] bind entry points hooked: " + total);
    }

    /**
     * Hooks every method of {@code c} that can be the per-row bind call.
     *
     * <p>Two things here are learned from the previous attempt, which hooked by name and rewrote
     * nothing:
     * <ul>
     *   <li><b>A method name is not enough.</b> {@code FileListAdapter} declares its row binding as
     *       the obfuscated {@code O(RecyclerView$ViewHolder, Cursor)}; only the base class keeps the
     *       {@code onBindViewHolder} name. So the match is by <em>signature</em> as well: any method
     *       taking a holder and a cursor.</li>
     *   <li><b>{@code RecyclerCursorAdapter.O} is abstract</b> — it is the declaration the subclass
     *       implements. {@code XposedBridge.hookMethod} on it installs nothing, silently. Abstract
     *       and native methods are skipped, and a class that yields no entry point says so.</li>
     * </ul>
     */
    private static int hookBindEntries(Class<?> c, String label) {
        int hooked = 0;
        for (Method m : c.getDeclaredMethods()) {
            int mod = m.getModifiers();
            if (Modifier.isAbstract(mod) || Modifier.isNative(mod) || !isBindEntry(m)) {
                continue;
            }
            try {
                XposedBridge.hookMethod(m, new XC_MethodHook() {
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
                hooked++;
                Logx.i("[list] hooked " + label + "." + m.getName() + signatureOf(m));
            } catch (Throwable t) {
                Logx.w("[list] hook " + label + "." + m.getName() + " failed: " + t);
            }
        }
        if (hooked == 0) {
            Logx.w("[list] " + label + " declares no bind entry point");
        }
        return hooked;
    }

    /** {@code onBindViewHolder(…)} by name, or any {@code (ViewHolder, Cursor)} by signature. */
    private static boolean isBindEntry(Method m) {
        if ("onBindViewHolder".equals(m.getName())) {
            return true;
        }
        Class<?>[] p = m.getParameterTypes();
        return p.length == 2 && isA(p[0], "androidx.recyclerview.widget.RecyclerView$ViewHolder")
                && isA(p[1], "android.database.Cursor");
    }

    /** Walks superclasses and interfaces looking for {@code name}. */
    private static boolean isA(Class<?> c, String name) {
        if (c == null) {
            return false;
        }
        if (name.equals(c.getName())) {
            return true;
        }
        if (isA(c.getSuperclass(), name)) {
            return true;
        }
        for (Class<?> i : c.getInterfaces()) {
            if (isA(i, name)) {
                return true;
            }
        }
        return false;
    }

    private static String signatureOf(Method m) {
        StringBuilder sb = new StringBuilder("(");
        Class<?>[] p = m.getParameterTypes();
        for (int i = 0; i < p.length; i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(p[i].getSimpleName());
        }
        return sb.append(')').toString();
    }

    /**
     * Told by the button's reconcile pass which directory the window is actually drawing.
     *
     * @return true when the rows need binding again: the page moved, or the vault's state changed
     *     (unlocking while standing in the vault root changes every row without changing the
     *     directory, and so does locking it again — the session object survives that, so the
     *     unlocking flag has to be compared as well as the reference)
     */
    static boolean noteDrawnPath(String cloudPath) {
        boolean changed = drawnCloudPath == null ? cloudPath != null : !drawnCloudPath.equals(cloudPath);
        drawnCloudPath = cloudPath;
        VaultUi.Session session = VaultUi.session();
        boolean unlocked = session != null && session.isUnlocked();
        if (session != lastSessionSeen || unlocked != lastUnlockedSeen) {
            lastSessionSeen = session;
            lastUnlockedSeen = unlocked;
            changed = true;
        }
        return changed;
    }

    static String drawnPath() {
        return drawnCloudPath;
    }

    private static void afterBind(XC_MethodHook.MethodHookParam param) {
        Object holder = param.args != null && param.args.length > 0 ? param.args[0] : null;
        View row = viewOf(holder);
        // Before anything is decided about this bind: the view may be a recycled one that a previous
        // pass collapsed, or a row of a page that has just been re-locked. Either way the app's own
        // bind has already written its text, and the geometry has to be the app's again too.
        uncollapseRow(row);
        VaultUi.Session session = VaultUi.session();
        if (session == null || !session.isUnlocked()) {
            // The session survives 还原 marked locked, so "which vault" and "is it open" are two
            // different questions and the row rewriting is only about the second.
            logBind(textOf(row), session == null ? "no vault unlocked in this process"
                    : "the vault has been put back to ciphertext (还原)");
            return;
        }
        String dirId = session.dirIdOfDrawn(drawnCloudPath);
        if (dirId == null) {
            // This page is inside the vault but the session has not descended into it (or it is a
            // .c9s pointer folder, whose internals must stay visible rather than be rewritten).
            logBind(textOf(row), "no dirId for this page (session knows " + session.knownPaths() + ")");
            return;
        }
        if (row == null) {
            logBind("<no view>", "arg[0] is not a row view (" + holder + ")");
            return;
        }
        logBind(textOf(row), "dirId=\"" + dirId + "\" -> " + rewrite(row, session.vault, dirId));
    }

    /**
     * Narrates a page's binds, a few ordinary rows and many ciphertext ones.
     *
     * <p>This exists because "the hook ran" and "the hook was never called" used to look identical
     * from the outside: an earlier build logged {@code [list] hooked …} unconditionally, so the log
     * said everything was fine while nothing was rewritten.
     *
     * <p>The counters are per page and per kind — see the constants. They are deliberately not
     * cumulative: a silent cap turns a working module into one that merely stops talking, and that
     * is the more expensive failure of the two.
     */
    private static void logBind(String text, String note) {
        String page = drawnCloudPath;
        if (page == null ? bindLogPath != null : !page.equals(bindLogPath)) {
            bindLogPath = page;
            bindLogsForPath = 0;
            bindCiphertextForPath = 0;
        }
        if (text.endsWith(".c9r") || text.endsWith(".c9s")) {
            if (bindCiphertextForPath >= BIND_LOG_CIPHERTEXT_PER_PAGE) {
                return;
            }
            bindCiphertextForPath++;
        } else {
            if (bindLogsForPath >= BIND_LOG_ROWS_PER_PAGE) {
                return;
            }
            bindLogsForPath++;
        }
        Logx.i("[list] bind text=" + text + " drawn=" + page + " :: " + note);
    }

    /** The ciphertext name a row is currently showing, for the log. */
    private static String textOf(View row) {
        if (row == null) {
            return "<no view>";
        }
        TextView name = nameView(row);
        if (name == null) {
            return "<no name view>";
        }
        CharSequence cs = name.getText();
        return cs == null ? "<null>" : cs.toString();
    }

    /** @return what was done to the row, for the log */
    private static String rewrite(View row, Vault vault, String dirId) {
        TextView name = nameView(row);
        if (name == null) {
            return "left (no name view)";
        }
        CharSequence cs = name.getText();
        String text = cs == null ? "" : cs.toString();
        if (!text.endsWith(".c9r") && !text.endsWith(".c9s")) {
            // Not one of the vault's entries: a toolbar, a header, vault.cryptomator itself. Its
            // visibility is the app's business, so nothing here touches it.
            return "left (not a vault entry)";
        }
        if (Vault.isInternal(text)) {
            // A content row the user must not see. The next bind of this view puts it back
            // (uncollapseRow, at the top of afterBind).
            return collapseRow(row);
        }
        if (text.endsWith(".c9s")) {
            // A shortened name: its cleartext name lives inside the folder, which cannot be read
            // until that folder is listed. Left as drawn rather than guessed at.
            return "left (.c9s shortening; real name is inside the folder)";
        }
        try {
            String cleartext = vault.name(dirId, text);
            if (cleartext == null || cleartext.equals(text)) {
                return "left (decrypts to itself)";
            }
            name.setText(cleartext);
            return "renamed -> " + cleartext;
        } catch (Throwable t) {
            Logx.w("[list] " + text + " does not decrypt under " + dirId + ": " + t);
            return "left (decrypt failed: " + t + ")";
        }
    }

    /**
     * What was there before this module collapsed a row — {@code {lp.height, minHeight}} — keyed by
     * view.
     *
     * <p>Weak keys because rows are the app's views and outlive any particular bind: when a row is
     * recycled its entry falls out on its own, and nothing here keeps it alive.
     */
    private static final java.util.Map<View, int[]> COLLAPSED =
            java.util.Collections.synchronizedMap(new java.util.WeakHashMap<View, int[]>());

    /** Give a collapsed row the app's own geometry back. A no-op on a row this module never hid. */
    private static void uncollapseRow(View row) {
        if (row == null) {
            return;
        }
        int[] was = COLLAPSED.remove(row);
        if (was == null) {
            return;
        }
        ViewGroup.LayoutParams lp = row.getLayoutParams();
        if (lp != null) {
            lp.height = was[0];
        }
        row.setMinimumHeight(was[1]);
        row.setVisibility(View.VISIBLE);
        row.requestLayout();
    }

    /**
     * Hides a row the format needs and the user must not see.
     *
     * <p>{@code View.GONE} on its own does NOT do this, which is why this is a method rather than one
     * line in {@link #rewrite}. Measured on the device, the row's {@code lp.height} is {@code -2}
     * (WRAP_CONTENT) and its {@code getMinimumHeight()} is {@code 187} px — so the instinct "GONE
     * plus wrap_content must collapse" is wrong, because a wrap_content child is still measured at
     * {@code getSuggestedMinimumHeight()} whatever its visibility is. The result was a full-height
     * 187 px hole between two file rows. An explicit layout height of 0 is what reclaims it.
     *
     * <p>The measurement is in the returned line rather than only in this comment, because this is
     * exactly the kind of claim that is easy to write down wrongly: the first version of this method
     * asserted a fixed pixel height in LayoutParams, and the log answered {@code lp.height -2}.
     */
    private static String collapseRow(View row) {
        ViewGroup.LayoutParams lp = row.getLayoutParams();
        int before = lp == null ? -1 : lp.height;
        int minHeight = row.getMinimumHeight();
        int wasMeasured = row.getMeasuredHeight();
        if (lp != null) {
            // Only record the first time: the value in there now may already be this method's own 0,
            // and recording that would make the restore a no-op that leaves the row permanently flat.
            if (lp.height != 0 && !COLLAPSED.containsKey(row)) {
                COLLAPSED.put(row, new int[]{lp.height, minHeight});
            }
            lp.height = 0;
        }
        // A minimum height would override the 0 above; none of the app's rows should have one, but
        // the restore has to know about it either way.
        row.setMinimumHeight(0);
        row.setVisibility(View.GONE);
        row.requestLayout();
        return "hidden (format's own file; lp.height " + before + " -> 0, minHeight " + minHeight
                + " -> 0, was " + wasMeasured + "px)";
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
}
