package com.luqin.bdcrypto;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;

/**
 * Reflection helpers used by the on-device probe.
 *
 * <p>The app is R8-processed: some classes keep readable names ({@code CloudFile},
 * {@code FileListWrapperAdapter}) while others are reduced to {@code a}/{@code _}/{@code a0}.
 * For the obfuscated ones the only reliable handle is the *descriptor*, so everything here renders
 * full signatures instead of just names.
 */
public final class Reflectx {

    /** Absolute ceiling on nested object-graph walking, so a probe can never hang the app. */
    private static final int HARD_MAX_DEPTH = 5;
    private static final int HARD_MAX_NODES = 1200;

    private Reflectx() {
    }

    /**
     * Only the app's own classes are worth walking.
     *
     * <p>A first version recursed into everything, which was useless: {@code MyNetdiskActivity}
     * inherits from {@code android.app.Activity}, so ~200 of the ~400 lines it produced were
     * framework internals (mHandler, mDecor, mWindowManager …) and the node budget ran out before
     * the app's own fields were reached. Restricting the walk to {@code com.baidu.*} is what makes
     * the graph readable.
     */
    static boolean isAppClass(Class<?> c) {
        String n = c.getName();
        return n.startsWith("com.baidu.") || n.startsWith("com.luqin.bdcrypto.");
    }

    // ------------------------------------------------------------- naming ---

    public static String simple(String className) {
        if (className == null) {
            return "null";
        }
        int i = className.lastIndexOf('.');
        return i < 0 ? className : className.substring(i + 1);
    }

    public static String tn(Class<?> c) {
        if (c == null) {
            return "?";
        }
        if (c.isArray()) {
            return tn(c.getComponentType()) + "[]";
        }
        return simple(c.getName());
    }

    public static String mods(int m) {
        if (m == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder(Modifier.toString(m));
        if ((m & 0x1000) != 0) {
            sb.append(" synthetic");
        }
        if ((m & 0x40) != 0) {
            sb.append(" bridge");
        }
        return sb.toString();
    }

    public static String mdesc(Method m) {
        StringBuilder sb = new StringBuilder();
        String mod = mods(m.getModifiers());
        if (!mod.isEmpty()) {
            sb.append(mod).append(' ');
        }
        sb.append(tn(m.getReturnType())).append(' ').append(m.getName()).append('(');
        Class<?>[] ps = m.getParameterTypes();
        for (int i = 0; i < ps.length; i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(tn(ps[i]));
        }
        return sb.append(')').toString();
    }

    public static String cdesc(Constructor<?> c) {
        StringBuilder sb = new StringBuilder();
        String mod = mods(c.getModifiers());
        if (!mod.isEmpty()) {
            sb.append(mod).append(' ');
        }
        sb.append(simple(c.getDeclaringClass().getName())).append('(');
        Class<?>[] ps = c.getParameterTypes();
        for (int i = 0; i < ps.length; i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(tn(ps[i]));
        }
        return sb.append(')').toString();
    }

    public static String fdesc(Field f) {
        String mod = mods(f.getModifiers());
        return (mod.isEmpty() ? "" : mod + " ") + tn(f.getType()) + " " + f.getName();
    }

    // ------------------------------------------------------------- dumps ----

    /** Full declared-member dump of one class, ordered by name. */
    public static String dumpClass(Class<?> c) {
        StringBuilder sb = new StringBuilder();
        sb.append("CLASS ").append(c.getName()).append('\n');
        sb.append("  super   : ")
                .append(c.getSuperclass() == null ? "-" : c.getSuperclass().getName()).append('\n');
        Class<?>[] ifaces = c.getInterfaces();
        sb.append("  ifaces  : ");
        if (ifaces.length == 0) {
            sb.append('-');
        }
        for (int i = 0; i < ifaces.length; i++) {
            sb.append(i > 0 ? ", " : "").append(ifaces[i].getName());
        }
        sb.append('\n');
        sb.append("  loader  : ").append(c.getClassLoader()).append('\n');
        sb.append("  isEnum=").append(c.isEnum())
                .append(" isInterface=").append(c.isInterface())
                .append(" isSynthetic=").append(c.isSynthetic()).append('\n');

        appendCtors(sb, c);
        appendMethods(sb, c);
        appendFields(sb, c);
        return sb.toString();
    }

    /** Class plus every superclass up to Object — where the inherited handles usually live. */
    public static String dumpHierarchy(Class<?> c) {
        StringBuilder sb = new StringBuilder();
        for (Class<?> k = c; k != null && k != Object.class; k = k.getSuperclass()) {
            sb.append(dumpClass(k)).append('\n');
        }
        return sb.toString();
    }

    private static void appendCtors(StringBuilder sb, Class<?> c) {
        List<Constructor<?>> cs = new ArrayList<Constructor<?>>();
        try {
            Collections.addAll(cs, c.getDeclaredConstructors());
        } catch (Throwable t) {
            sb.append("  ctors   : <").append(t).append(">\n");
            return;
        }
        Collections.sort(cs, new Comparator<Constructor<?>>() {
            @Override
            public int compare(Constructor<?> a, Constructor<?> b) {
                return cdesc(a).compareTo(cdesc(b));
            }
        });
        sb.append("  ctors(").append(cs.size()).append("):\n");
        for (Constructor<?> x : cs) {
            sb.append("    ").append(cdesc(x)).append('\n');
        }
    }

    private static void appendMethods(StringBuilder sb, Class<?> c) {
        List<Method> ms = new ArrayList<Method>();
        try {
            Collections.addAll(ms, c.getDeclaredMethods());
        } catch (Throwable t) {
            sb.append("  methods : <").append(t).append(">\n");
            return;
        }
        Collections.sort(ms, new Comparator<Method>() {
            @Override
            public int compare(Method a, Method b) {
                int x = a.getName().compareTo(b.getName());
                return x != 0 ? x : mdesc(a).compareTo(mdesc(b));
            }
        });
        sb.append("  methods(").append(ms.size()).append("):\n");
        for (Method m : ms) {
            sb.append("    ").append(mdesc(m)).append('\n');
        }
    }

    private static void appendFields(StringBuilder sb, Class<?> c) {
        List<Field> fs = new ArrayList<Field>();
        try {
            Collections.addAll(fs, c.getDeclaredFields());
        } catch (Throwable t) {
            sb.append("  fields  : <").append(t).append(">\n");
            return;
        }
        Collections.sort(fs, new Comparator<Field>() {
            @Override
            public int compare(Field a, Field b) {
                return a.getName().compareTo(b.getName());
            }
        });
        sb.append("  fields(").append(fs.size()).append("):\n");
        for (Field f : fs) {
            sb.append("    ").append(fdesc(f)).append('\n');
        }
    }

    // -------------------------------------------------------- object graph --

    /**
     * Walks the non-static fields of {@code root} and reports the shape of the object graph.
     *
     * <p>Only "interesting" values are recursed into: anything under {@code com.baidu.}, plus the
     * container/UI types we care about. Framework widgets are named but not entered, since the point
     * is to discover which app class holds the list adapter and the path state — not to mirror the
     * whole view tree.
     */
    public static String graph(String label, Object root, int depth) {
        StringBuilder sb = new StringBuilder();
        Set<Object> seen = Collections.newSetFromMap(new IdentityHashMap<Object, Boolean>());
        int[] budget = new int[]{HARD_MAX_NODES};
        sb.append("GRAPH ").append(label).append(" -> ").append(typeOf(root)).append('\n');
        walk(root, 1, Math.min(depth, HARD_MAX_DEPTH), seen, budget, sb);
        if (budget[0] <= 0) {
            sb.append("  … node budget exhausted\n");
        }
        return sb.toString();
    }

    private static void walk(Object o, int level, int maxDepth, Set<Object> seen, int[] budget,
                             StringBuilder sb) {
        if (o == null || level > maxDepth || budget[0] <= 0) {
            return;
        }
        if (!seen.add(o)) {
            sb.append(indent(level)).append("<cycle>\n");
            return;
        }
        for (Class<?> k = o.getClass(); k != null && k != Object.class; k = k.getSuperclass()) {
            // Stop as soon as the chain leaves the app's own packages — see isAppClass().
            if (!isAppClass(k)) {
                break;
            }
            Field[] fs;
            try {
                fs = k.getDeclaredFields();
            } catch (Throwable t) {
                continue;
            }
            for (Field f : fs) {
                if (Modifier.isStatic(f.getModifiers()) || f.isSynthetic()) {
                    continue;
                }
                if (budget[0] <= 0) {
                    return;
                }
                budget[0]--;
                String head = indent(level) + f.getName() + " : " + tn(f.getType());
                Object v;
                try {
                    f.setAccessible(true);
                    v = f.get(o);
                } catch (Throwable t) {
                    sb.append(head).append("   <").append(t.getClass().getSimpleName()).append(">\n");
                    continue;
                }
                if (v == null) {
                    sb.append(head).append(" = null\n");
                    continue;
                }
                sb.append(head).append(" = ").append(preview(v)).append('\n');
                if (level < maxDepth && (isAppClass(v.getClass()) || interesting(v))) {
                    walk(v, level + 1, maxDepth, seen, budget, sb);
                }
            }
        }
    }

    private static String indent(int level) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < level; i++) {
            sb.append("  ");
        }
        return sb.toString();
    }

    private static boolean interesting(Object v) {
        return v instanceof Iterable || v instanceof java.util.Map;
    }

    /** Short, non-invasive rendering — never calls app code, only toString on known-safe types. */
    private static String preview(Object v) {
        if (v == null) {
            return "null";
        }
        Class<?> c = v.getClass();
        if (c.isArray()) {
            return c.getComponentType().getSimpleName() + "[" + java.lang.reflect.Array.getLength(v)
                    + "]";
        }
        if (v instanceof CharSequence) {
            String s = v.toString();
            return '"' + (s.length() > 120 ? s.substring(0, 120) + "…" : s) + '"';
        }
        if (v instanceof Number || v instanceof Boolean || v instanceof Character) {
            return v.toString();
        }
        if (v instanceof Iterable) {
            int n = 0;
            Object first = null;
            for (Object e : (Iterable<?>) v) {
                if (first == null) {
                    first = e;
                }
                if (++n >= 200) {
                    break;
                }
            }
            return c.getName() + "(size≈" + n + (first == null ? "" : ", first=" + typeOf(first)) + ")";
        }
        if (v instanceof java.util.Map) {
            return c.getName() + "(size=" + ((java.util.Map<?, ?>) v).size() + ")";
        }
        return typeOf(v);
    }

    public static String typeOf(Object o) {
        return o == null ? "null" : o.getClass().getName();
    }

    // ------------------------------------------------------------ calling ---

    /** Invokes a no-arg method by name, tolerating the name being absent. */
    public static Object call0(Object target, String method) {
        if (target == null) {
            return null;
        }
        for (Class<?> k = target.getClass(); k != null; k = k.getSuperclass()) {
            try {
                Method m = k.getDeclaredMethod(method);
                m.setAccessible(true);
                return m.invoke(target);
            } catch (NoSuchMethodException ignored) {
                // keep walking up
            } catch (Throwable t) {
                return "<" + t.getClass().getSimpleName() + ": " + t.getMessage() + ">";
            }
        }
        return null;
    }

    public static String callStr(Object target, String method) {
        Object r = call0(target, method);
        return r == null ? null : String.valueOf(r);
    }

    public static long callLong(Object target, String method, long fallback) {
        Object r = call0(target, method);
        return r instanceof Number ? ((Number) r).longValue() : fallback;
    }

    public static boolean callBool(Object target, String method, boolean fallback) {
        Object r = call0(target, method);
        return r instanceof Boolean ? (Boolean) r : fallback;
    }
}
