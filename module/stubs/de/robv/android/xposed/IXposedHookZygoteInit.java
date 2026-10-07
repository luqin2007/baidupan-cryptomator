package de.robv.android.xposed;

/** Compile-time stub of the Xposed API. */
public interface IXposedHookZygoteInit {

    void initZygote(StartupParam startupParam) throws Throwable;

    class StartupParam {
        public String modulePath;
        public boolean startsSystemServer;
    }
}
