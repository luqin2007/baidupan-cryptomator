package de.robv.android.xposed;

/** Compile-time stub of the Xposed API. */
public final class XposedHelpers {

    private XposedHelpers() {
    }

    public static Class<?> findClass(String className, ClassLoader classLoader) {
        return null;
    }

    public static Class<?> findClassIfExists(String className, ClassLoader classLoader) {
        return null;
    }

    public static java.lang.reflect.Method findMethodExact(Class<?> clazz, String methodName,
                                                           Object... parameterTypes) {
        return null;
    }

    public static java.lang.reflect.Method findMethodExactIfExists(Class<?> clazz, String methodName,
                                                                   Object... parameterTypes) {
        return null;
    }

    public static XC_MethodHook.Unhook findAndHookMethod(Class<?> clazz, String methodName,
                                                         Object... parameterTypesAndCallback) {
        return null;
    }

    public static XC_MethodHook.Unhook findAndHookMethod(String className, ClassLoader classLoader,
                                                         String methodName,
                                                         Object... parameterTypesAndCallback) {
        return null;
    }

    public static Object getObjectField(Object obj, String fieldName) {
        return null;
    }

    public static void setObjectField(Object obj, String fieldName, Object value) {
    }

    public static Object getStaticObjectField(Class<?> clazz, String fieldName) {
        return null;
    }

    public static Object callMethod(Object obj, String methodName, Object... args) {
        return null;
    }

    public static Object callStaticMethod(Class<?> clazz, String methodName, Object... args) {
        return null;
    }

    public static int getIntField(Object obj, String fieldName, int fallback) {
        return fallback;
    }

    public static long getLongField(Object obj, String fieldName, long fallback) {
        return fallback;
    }

    public static boolean getBooleanField(Object obj, String fieldName, boolean fallback) {
        return fallback;
    }

    public static Object newInstance(Class<?> clazz, Object... args) {
        return null;
    }
}
