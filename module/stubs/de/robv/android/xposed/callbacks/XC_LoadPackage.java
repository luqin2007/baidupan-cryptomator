package de.robv.android.xposed.callbacks;

/** Compile-time stub of the Xposed API. */
public abstract class XC_LoadPackage extends XCallback {

    public static class LoadPackageParam extends XCallback.Param {
        public String packageName;
        public String processName;
        public ClassLoader classLoader;
        public android.content.pm.ApplicationInfo appInfo;
        public boolean isFirstApplication;
    }
}
