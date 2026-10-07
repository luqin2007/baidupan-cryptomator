#!/usr/bin/env bash
#
# Offline vault oracle: compile and run the two reference programs against a vault on this machine.
#
#   oracle.sh check  <vaultDir> <passphrase>      is the passphrase right?  (no phone involved)
#   oracle.sh unlock <vaultDir> <passphrase>      full manifest: cleartext <-> ciphertext
#
# Why this exists: the module must implement Cryptomator's directory traversal itself (it cannot
# ship cryptofs — that needs java.nio.file, guava, jackson and a local filesystem). These programs
# use the OFFICIAL cryptofs, so they are the authority the module's own implementation is checked
# against, and they produce the expected plaintext of every ciphertext file.
#
# Requires a local Cryptomator install for its jars. It does NOT need to be launched.
#
# NOTE ON THE JDK: cryptolib is Java 8 bytecode (which is exactly why it can be dexed into an
# Android module), but cryptofs is compiled for Java 25. A JDK that cannot read class file version
# 69 fails with "class file has wrong version 69.0, should be 65.0" — so this script insists on a
# JDK 25+ for everything, and the flag exists to point at one that is not on PATH.
set -euo pipefail

JAVA_HOME="${ORACLE_JAVA_HOME:-${JAVA25_HOME:-}}"
if [ -z "$JAVA_HOME" ] || [ ! -x "$JAVA_HOME/bin/javac.exe" ]; then
    for c in "$HOME"/../Java/microsoft-jdk-25* /c/Dev/Java/microsoft-jdk-25* /c/Dev/Java/jdk-25* \
             "$HOME"/.jdks/*25*; do
        [ -x "$c/bin/javac.exe" ] && JAVA_HOME="$c" && break
    done
fi
[ -n "$JAVA_HOME" ] || {
    echo "no JDK 25+ found; set ORACLE_JAVA_HOME (cryptofs is class file version 69)" >&2
    exit 1
}

MODS="${CRYPTOMATOR_MODS:-/c/Program Files/Cryptomator/app/mods}"
[ -d "$MODS" ] || { echo "Cryptomator mods dir not found: $MODS" >&2; exit 1; }
if command -v cygpath >/dev/null 2>&1; then
    MODS_WIN="$(cygpath -w "$MODS")\\*"
else
    MODS_WIN="$MODS/*"
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD="$HERE/.build"
mkdir -p "$BUILD"

# javac here is a native Windows binary: it cannot open '/c/Dev/...' paths, so everything handed to
# it goes through cygpath -m (mixed form, C:/Dev/...), which both it and bash understand.
if command -v cygpath >/dev/null 2>&1; then
    HERE_WIN="$(cygpath -m "$HERE")"
    BUILD_WIN="$(cygpath -m "$BUILD")"
else
    HERE_WIN="$HERE"
    BUILD_WIN="$BUILD"
fi

echo "jdk  : $JAVA_HOME"
echo "mods : $MODS"

"$JAVA_HOME/bin/javac.exe" -nowarn -cp "$MODS_WIN" -d "$BUILD_WIN" \
    "$HERE_WIN/CheckPass.java" "$HERE_WIN/Unlock.java" || exit 1

mode="${1:?usage: oracle.sh check|unlock <vaultDir> <passphrase>}"
vault="${2:?missing vaultDir}"
pass="${3:?missing passphrase}"

if [ "$mode" = "check" ]; then
    exec "$JAVA_HOME/bin/java.exe" -cp "$MODS_WIN;$BUILD_WIN" CheckPass \
        "$vault/masterkey.cryptomator" "$pass"
elif [ "$mode" = "unlock" ]; then
    exec "$JAVA_HOME/bin/java.exe" -cp "$MODS_WIN;$BUILD_WIN" Unlock "$vault" "$pass"
else
    echo "unknown mode: $mode" >&2
    exit 2
fi
