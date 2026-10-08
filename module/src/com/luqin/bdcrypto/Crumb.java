package com.luqin.bdcrypto;

import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;

import de.robv.android.xposed.XposedHelpers;

/**
 * The breadcrumb, shown as the path the user walked rather than the path the format stores.
 *
 * <p>Once the redirects land, the page the user is <em>looking at</em> is right and the crumb above
 * it is wrong: unlocking draws {@code …/crypto/content/d/SY/RGEQKQVHFPTPFOF65L6I62FLLYWDS7}, and
 * opening 游戏 draws {@code …/LZPM…==.c9r/7HKQI7Z3NKNZLTDHRZXUKNCD5URD4I}. Both name the same two
 * directories the user calls {@code content} and {@code 游戏}. The rows were rewritten long ago;
 * this is the same service for the one piece of the page that is built from the app's own model.
 *
 * <p><b>What becomes of each segment</b>, classified by {@link VaultUi.Session#crumbKind} so that
 * only segments this session can actually vouch for are touched:
 *
 * <ul>
 *   <li>{@code d} and the two-character bucket under it — hidden. They are the format's split of
 *       one directory across {@code d/XY/}, and the user has never been anywhere that resembles
 *       them.</li>
 *   <li>{@code <base64url>.c9r}, the pointer folder standing in for a directory — hidden, because
 *       the crumb that follows it is the one worth showing.</li>
 *   <li>{@code d/XY/<hash>}, where the entries really live — renamed to the directory's cleartext
 *       name, which the session learnt when it resolved the redirect. The vault's own root reads
 *       as null there: its content directory <em>is</em> {@code content}, and the user is standing
 *       in it, so a crumb for it would be a level that does not exist in their mind.</li>
 * </ul>
 *
 * <p><b>Display only.</b> The module's own reading of the page — {@code Hooks.crumbPathOf}, and
 * through it the button, the drag of the drawn page and whether a redirect is needed — keeps seeing
 * the ciphertext path, because everything here also records what a segment said before it was
 * changed ({@link #originalOf}). Rewriting the text without that would quietly redirect the whole
 * of {@code reconcile} onto a path nothing else recognises: the decrypted root would become
 * indistinguishable from the vault directory it was reached from, and every page's rows would be
 * read against the wrong directory.
 *
 * <p><b>Two-way, because items are recycled.</b> A {@code RecyclerView} hands the same item view to
 * a different crumb on the next bind, so a hidden item is restored and a renamed one is rewritten
 * on <em>every</em> bind, from the app's own text, rather than assumed to stay as it was left.
 */
final class Crumb {

    /** How many actions of each kind to narrate per process. Enough to see, not enough to bury. */
    private static final int LOG_HIDES = 8;
    private static final int LOG_RENAMES = 8;

    private static volatile int hidesLogged;
    private static volatile int renamesLogged;

    /** What a crumb view said before this class touched it, and what it says instead. */
    private static final class Mark {
        final String physical;
        final String shown;

        Mark(String physical, String shown) {
            this.physical = physical;
            this.shown = shown;
        }
    }

    /**
     * Keyed by the view holding the name, with weak keys because crumbs are the app's views. An
     * entry exists only while a segment is actually being shown under another name.
     */
    private static final Map<TextView, Mark> MARK =
            Collections.synchronizedMap(new WeakHashMap<TextView, Mark>());

    /** Geometry an item had before it was collapsed, so a recycled item gets the app's back. */
    private static final Map<View, int[]> COLLAPSED =
            Collections.synchronizedMap(new WeakHashMap<View, int[]>());

    private Crumb() {
    }

    /**
     * The ciphertext name a crumb view was given by the app, or null while it is showing its own.
     *
     * <p>Consulted by {@link Hooks#crumbPathOf} so that the module's picture of where the app is
     * stays the app's picture. Returns null rather than the recorded name when the text on screen
     * is no longer the one this class put there: the item has been recycled and what the app has
     * just written is the truth again.
     */
    static String originalOf(TextView tv) {
        Mark m = MARK.get(tv);
        return m == null || !m.shown.equals(text(tv)) ? null : m.physical;
    }

    /**
     * Called after {@code BreadcrumbAdapter.onBindViewHolder}, for each crumb item.
     *
     * <p>Runs on every bind of every file page, so the first thing it does is return on the pages
     * that are not inside an unlocked vault — which is all of them until the user unlocks.
     */
    static void onBound(Object holder) {
        try {
            View item = itemView(holder);
            if (item == null) {
                return;
            }
            // Before anything is decided: this may be a recycled item that a previous crumb left
            // collapsed, and the app's own bind has already restored the text and the intent.
            restore(item);
            TextView name = nameView(item);
            if (name == null) {
                return;
            }
            VaultUi.Session s = VaultUi.session();
            if (s == null || !s.isUnlocked()) {
                // No vault, or one that has been put back to ciphertext: the crumb the app built is
                // the honest one again, and a mark left over would keep a name on screen that the
                // page underneath no longer means.
                MARK.remove(name);
                return;
            }
            String shown = text(name);
            Mark m = MARK.get(name);
            // Either the app has just written this crumb's name, or it is still the rename this
            // class made and the name underneath is the one to classify.
            String physical = m != null && m.shown.equals(shown) ? m.physical : shown;

            switch (s.crumbKind(physical)) {
                case VaultUi.Session.CRUMB_CONTENT: {
                    String want = s.nameOfDirId(s.dirIdOfDrawn("/" + physical));
                    if (want == null || want.length() == 0) {
                        collapse(item);
                        logHide(physical, "a content directory with no name of its own");
                    } else if (!want.equals(shown)) {
                        name.setText(want);
                        MARK.put(name, new Mark(physical, want));
                        logRename(physical, want);
                    }
                    break;
                }
                case VaultUi.Session.CRUMB_BUCKET_ROOT:
                case VaultUi.Session.CRUMB_BUCKET:
                case VaultUi.Session.CRUMB_ENTRY:
                    collapse(item);
                    logHide(physical, s.crumbKind(physical) == VaultUi.Session.CRUMB_ENTRY
                            ? "a pointer folder; the crumb after it carries the name"
                            : "part of how the format spreads one directory over d/XY/");
                    break;
                default:
                    // The app's own path, above the vault. Nothing here touches it, and a mark left
                    // over from a recycled item would make our own reading of the page disagree
                    // with what is on screen.
                    MARK.remove(name);
                    break;
            }
        } catch (Throwable t) {
            logOnce(t);
        }
    }

    /**
     * Undoes everything this class has done, for the vault being locked again.
     *
     * <p>Needed because the two directions are not symmetric. Collapsing and renaming happen on a
     * bind, so a crumb that is rewritten is rewritten again the moment the app binds it — but the
     * breadcrumb does not change when the vault is locked, so nothing is bound, and a crumb that
     * was hidden would stay hidden on a page that is now honestly showing ciphertext. Walking the
     * recorded views is the only way to put the app's own breadcrumb back without waiting for a
     * navigation that may not come.
     */
    static void release() {
        java.util.List<TextView> named = new ArrayList<TextView>(MARK.keySet());
        for (TextView tv : named) {
            Mark m = MARK.get(tv);
            // Only while the text is still the one this class put there: a recycled view holds
            // another crumb's name now, and overwriting it would invent a name the app never wrote.
            if (m != null && m.shown.equals(text(tv))) {
                tv.setText(m.physical);
            }
        }
        MARK.clear();
        // toArray because restore() removes from the map the loop is walking
        for (View item : COLLAPSED.keySet().toArray(new View[0])) {
            restore(item);
        }
    }

    /**
     * Every crumb the adapter holds, oldest first — the whole path, not the part on screen.
     *
     * <p><b>This is the only complete reading of the breadcrumb there is.</b> The view is a
     * {@code RecyclerView} and holds only what fits, so reading its text views says nothing about
     * what has scrolled out, and both ends can. Measured, and it cost a silent failure: 还原 handed
     * the collapsed crumbs their width back, the tail slid off the right edge, and the path read
     * back lost <em>the directory the page was on</em> — leaving {@code …/content/RGEQ…} for a page
     * inside {@code d/DI/7HKQ…}. Every directory id in the session is matched by suffix, so the
     * page then resolved to its own ancestor and rows were decrypted with the wrong directory key,
     * which reports itself as "entry name does not authenticate" and nothing else.
     *
     * <p>Reads the adapter's own list rather than its text, so it is also unaffected by the renames
     * this class performs: what comes back is the app's ciphertext path, which is what every
     * decision downstream is about.
     *
     * @return true when {@code out} was filled; false leaves the caller to fall back to the text
     *     views, which is right on another app build with a different adapter
     */
    static boolean wholePath(android.view.View crumbView, List<String> out) {
        try {
            // By reflection, and not by an instanceof: androidx.recyclerview is not on this module's
            // compile classpath (it is built against android.jar and the Xposed stubs), so the type
            // cannot be named here even though the app is full of it. A view with no getAdapter
            // throws and the caller falls back to the text views, which is the right answer.
            Object adapter = Reflectx.call0(crumbView, "getAdapter");
            if (adapter == null) {
                return false;
            }
            List<?> items = itemsOf(adapter);
            if (items == null || items.isEmpty()) {
                return false;
            }
            for (Object item : items) {
                String name = nameOf(item);
                if (name != null && name.length() > 0) {
                    out.add(name);
                }
            }
            return !out.isEmpty();
        } catch (Throwable t) {
            logOnce(t);
            return false;
        }
    }

    /** The list of crumbs behind a breadcrumb adapter, found by type: the field is R8-renamed. */
    private static List<?> itemsOf(Object adapter) {
        Class<?> c = adapter.getClass();
        Field f = itemsField;
        if (f == null || itemsFieldOwner != c) {
            f = null;
            for (Class<?> k = c; k != null && k != Object.class && f == null; k = k.getSuperclass()) {
                for (Field d : k.getDeclaredFields()) {
                    if (List.class.isAssignableFrom(d.getType())) {
                        d.setAccessible(true);
                        f = d;
                        break;
                    }
                }
            }
            itemsField = f;
            itemsFieldOwner = c;
        }
        if (f == null) {
            return null;
        }
        try {
            Object v = f.get(adapter);
            return v instanceof List ? (List<?>) v : null;
        } catch (Throwable t) {
            return null;
        }
    }

    private static volatile Field itemsField;
    private static volatile Class<?> itemsFieldOwner;

    /** What the app calls one crumb. {@code getFileName} first — it is the name being displayed. */
    private static String nameOf(Object item) {
        for (String m : new String[]{"getFileName", "getName"}) {
            try {
                Object v = de.robv.android.xposed.XposedHelpers.callMethod(item, m);
                if (v instanceof String && ((String) v).length() > 0) {
                    return ((String) v).trim();
                }
            } catch (Throwable ignored) {
                // try the next spelling
            }
        }
        return null;
    }

    private static volatile boolean loggedFailure;

    private static void logOnce(Throwable t) {
        if (!loggedFailure) {
            loggedFailure = true;
            Logx.e("[crumb] rewriting a breadcrumb failed (logged once)", t);
        }
    }

    private static void logHide(String physical, String why) {
        if (hidesLogged++ < LOG_HIDES) {
            Logx.i("[crumb] hid " + physical + " (" + why + ")");
        }
    }

    private static void logRename(String physical, String name) {
        if (renamesLogged++ < LOG_RENAMES) {
            Logx.i("[crumb] " + physical + " -> " + name);
        }
    }

    // ------------------------------------------------------------- views ----

    private static View itemView(Object holder) {
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
     * The view a crumb shows its name in: the first text view on the item that has anything to say.
     *
     * <p>By position rather than by resource id, because a breadcrumb item is small and there is
     * only ever one thing written on it — and the id, if there is one, was not worth a second
     * lookup that can come back null on another app build.
     */
    private static TextView nameView(View item) {
        if (item instanceof TextView) {
            return (TextView) item;
        }
        List<TextView> found = new ArrayList<TextView>();
        collect(item, found, 0);
        for (TextView tv : found) {
            if (text(tv).length() > 0) {
                return tv;
            }
        }
        return null;
    }

    private static void collect(View v, List<TextView> out, int depth) {
        if (depth > 4 || out.size() >= 8) {
            return;
        }
        if (v instanceof TextView) {
            out.add((TextView) v);
        }
        if (v instanceof ViewGroup) {
            ViewGroup g = (ViewGroup) v;
            for (int i = 0; i < g.getChildCount(); i++) {
                collect(g.getChildAt(i), out, depth + 1);
            }
        }
    }

    /** Collapses a crumb item the format needs and the user must not see. */
    private static void collapse(View item) {
        ViewGroup.LayoutParams lp = item.getLayoutParams();
        if (lp == null) {
            item.setVisibility(View.GONE);
            return;
        }
        // Recorded once: the numbers in there now may already be this method's own zeroes, and
        // recording those would make the restore a no-op that leaves the crumb permanently flat.
        if (!COLLAPSED.containsKey(item)) {
            COLLAPSED.put(item, new int[]{lp.width, lp.height, item.getMinimumWidth(),
                    item.getMinimumHeight(), item.getVisibility()});
        }
        // A zero layout size, not just GONE. A RecyclerView lays out every view it has attached
        // whatever its visibility, so a wrap_content item that is merely GONE keeps its width and
        // leaves a hole in the path — measured on the rows of the list page, where the same
        // instinct produced a 187 px gap (VaultList.collapseRow).
        lp.width = 0;
        lp.height = 0;
        item.setMinimumWidth(0);
        item.setMinimumHeight(0);
        item.setVisibility(View.GONE);
        item.requestLayout();
    }

    /** Gives a recycled item the app's own geometry back. A no-op on an item never collapsed. */
    private static void restore(View item) {
        int[] was = COLLAPSED.remove(item);
        if (was == null) {
            return;
        }
        ViewGroup.LayoutParams lp = item.getLayoutParams();
        if (lp != null) {
            lp.width = was[0];
            lp.height = was[1];
        }
        item.setMinimumWidth(was[2]);
        item.setMinimumHeight(was[3]);
        item.setVisibility(was[4]);
        item.requestLayout();
    }

    private static String text(TextView tv) {
        CharSequence cs = tv.getText();
        return cs == null ? "" : cs.toString().trim();
    }
}
