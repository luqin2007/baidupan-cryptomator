package de.robv.android.xposed;

/** Compile-time stub of the Xposed API. */
public final class XposedBridge {

    private XposedBridge() {
    }

    public static void log(String text) {
    }

    public static void log(Throwable t) {
    }

    public static void log(String text, Throwable t) {
    }

    public static int getXposedVersion() {
        return 93;
    }

    public static java.util.Set<XC_MethodHook.Unhook> hookAllMethods(
            Class<?> hookClass, String methodName, XC_MethodHook callback) {
        throw new UnsupportedOperationException("stub");
    }

    public static java.util.Set<XC_MethodHook.Unhook> hookAllConstructors(
            Class<?> hookClass, XC_MethodHook callback) {
        throw new UnsupportedOperationException("stub");
    }

    /**
     * Return type must match the live framework exactly. Verified against the
     * framework dex shipped by LSPosed 2.1.1 (7790) on the test device:
     *
     * <pre>
     *   de.robv.android.xposed.XC_MethodHook$Unhook
     *       de.robv.android.xposed.XposedBridge.hookMethod(java.lang.reflect.Member,
     *                                                      de.robv.android.xposed.XC_MethodHook)
     * </pre>
     *
     * A stub that declared {@code void} would make d8 emit a method reference whose
     * prototype does not exist at runtime, i.e. NoSuchMethodError on first use.
     */
    public static XC_MethodHook.Unhook hookMethod(java.lang.reflect.Member method, XC_MethodHook callback) {
        return null;
    }

    public static Object invokeOriginalMethod(java.lang.reflect.Member method, Object thisObject, Object[] args)
            throws NullPointerException, IllegalAccessException, IllegalArgumentException,
            java.lang.reflect.InvocationTargetException {
        return null;
    }
}
