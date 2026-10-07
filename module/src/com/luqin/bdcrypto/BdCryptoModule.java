package com.luqin.bdcrypto;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Module entry point, named in {@code assets/xposed_init}.
 *
 * <p>The module has exactly one job in the host process: recognise the Baidu Netdisk app and hand
 * over to {@link Hooks}. Everything else lives there, so the entry point stays as small as the
 * framework allows.
 */
public class BdCryptoModule implements IXposedHookLoadPackage {

    /** The only package this module ever touches. */
    public static final String TARGET_PACKAGE = "com.baidu.drive.app";

    /** Kept in sync with {@code module/build.sh}. */
    public static final String VERSION = "0.1.0";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (lpparam == null || !TARGET_PACKAGE.equals(lpparam.packageName)) {
            return;
        }
        try {
            Hooks.install(lpparam);
        } catch (Throwable t) {
            Logx.e("module install failed", t);
        }
    }
}
