package de.robv.android.xposed;

import de.robv.android.xposed.callbacks.XCallback;

/**
 * Compile-time stub of the Xposed API — intentionally NOT packaged into the
 * module dex; the real class is injected at runtime by LSPosed.
 *
 * IMPORTANT (verified on-device, LSPosed 2.1.1 / API 102):
 *   - the live API exposes XC_MethodHook as  de.robv.android.xposed.XC_MethodHook
 *   - it does NOT expose                         de.robv.android.xposed.callbacks.XC_MethodHook
 *
 * That was confirmed by reflecting over the framework's own XposedBridge:
 *     java.util.Set hookAllMethods(java.lang.Class, java.lang.String,
 *                                  de.robv.android.xposed.XC_MethodHook)
 * If a future LSPosed moves the class back under `callbacks`, the only file
 * that has to change is module/src/com/ugreen/unlock/HookAdapter.java
 * (plus this import).
 */
public abstract class XC_MethodHook extends XCallback {

    public XC_MethodHook() {
        super();
    }

    public XC_MethodHook(int priority) {
        super(priority);
    }

    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
    }

    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
    }

    public static class MethodHookParam extends XCallback.Param {
        public java.lang.reflect.Member method;
        public Object thisObject;
        public Object[] args;
        private Object result;
        private Throwable throwable;

        public Object getResult() {
            return result;
        }

        public void setResult(Object result) {
            this.result = result;
        }

        public Throwable getThrowable() {
            return throwable;
        }

        public void setThrowable(Throwable throwable) {
            this.throwable = throwable;
        }

        public boolean hasThrowable() {
            return throwable != null;
        }

        public Object getResultOrThrowable() throws Throwable {
            if (throwable != null) throw throwable;
            return result;
        }
    }

    public class Unhook {
        public java.lang.reflect.Member getHookedMethod() {
            return null;
        }

        public void unhook() {
        }
    }
}
