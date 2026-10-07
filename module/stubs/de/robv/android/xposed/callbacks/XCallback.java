package de.robv.android.xposed.callbacks;

/**
 * Compile-time stub of the Xposed API. NOT packaged into the module dex —
 * the real implementation is provided at runtime by LSPosed / Xposed.
 */
public abstract class XCallback {

    public static class Param {
    }

    public static final int PRIORITY_DEFAULT = 50;
    public static final int PRIORITY_HIGHEST = 10000;
    public static final int PRIORITY_LOWEST = -10000;

    public final int priority;

    public XCallback() {
        this.priority = PRIORITY_DEFAULT;
    }

    public XCallback(int priority) {
        this.priority = priority;
    }
}
