package com.google.common.base;

/**
 * The four guava {@code Preconditions} calls cryptolib makes, and nothing else.
 *
 * <p>Why this exists: cryptolib's API references guava, and guava is not bundled — the module ships
 * cryptolib + siv-mode only. Every entry point the vault needs reaches guava through exactly this
 * class ({@code DestroyableSecretKey}'s constructors and accessors), so without it the module would
 * throw {@code NoClassDefFoundError: com.google.common.base.Preconditions} the first time it tried
 * to run scrypt — on the device only, since the desktop oracle has real guava on its classpath.
 *
 * <p>That is a P0-C-sized finding: "cryptolib can be dexed" was verified by running d8, and d8 does
 * not resolve a referenced class until something calls it. Dexable is not the same as runnable.
 *
 * <p>Bundling all of guava to satisfy four assertions is not worth ~3 MB of dex, and these four
 * have fixed, spec-level semantics. If the host app happens to ship guava, its class is found first
 * and this one is never loaded — the behaviour is the same either way.
 */
public final class Preconditions {

    private Preconditions() {
    }

    public static void checkArgument(boolean expression) {
        if (!expression) {
            throw new IllegalArgumentException();
        }
    }

    public static void checkArgument(boolean expression, Object errorMessage) {
        if (!expression) {
            throw new IllegalArgumentException(String.valueOf(errorMessage));
        }
    }

    public static void checkState(boolean expression, Object errorMessage) {
        if (!expression) {
            throw new IllegalStateException(String.valueOf(errorMessage));
        }
    }

    public static <T> T checkNotNull(T reference) {
        if (reference == null) {
            throw new NullPointerException();
        }
        return reference;
    }

    public static <T> T checkNotNull(T reference, Object errorMessage) {
        if (reference == null) {
            throw new NullPointerException(String.valueOf(errorMessage));
        }
        return reference;
    }
}
