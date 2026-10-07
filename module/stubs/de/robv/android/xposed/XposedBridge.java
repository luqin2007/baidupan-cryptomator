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

    public static void hookMethod(java.lang.reflect.Member method, XC_MethodHook callback) {
    }

    public static Object invokeOriginalMethod(java.lang.reflect.Member method, Object thisObject, Object[] args)
            throws NullPointerException, IllegalAccessException, IllegalArgumentException,
            java.lang.reflect.InvocationTargetException {
        return null;
    }
}
