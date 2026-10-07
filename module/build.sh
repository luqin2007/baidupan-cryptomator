#!/usr/bin/env bash
#
# Offline build for the Baidu-Netdisk Cryptomator LSPosed module.
#
# Uses only a local Android SDK + JDK. No Gradle, no network.
#
#   javac  -> compile Xposed API stubs (compile-time only, never shipped)
#   javac  -> compile module sources against android.jar + stubs + module/libs/*.jar
#   d8     -> dex module classes together with the bundled crypto libraries
#   aapt2  -> resources + manifest + assets (xposed_init and the class index)
#   apksigner -> v1+v2+v3 signature
#
# Signing:
#   module/keystore.properties present -> release key (module/keystore/release.keystore)
#   otherwise                          -> debug key   (generated on first run)
# Neither the keystore nor keystore.properties is in version control.
#
set -euo pipefail

# ---------------------------------------------------------------- version ---
VERSION_CODE="${VERSION_CODE:-1}"
VERSION_NAME="${VERSION_NAME:-0.1.0}"

# ------------------------------------------------------------ toolchain ----
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if command -v cygpath >/dev/null 2>&1; then
  # javac / aapt2 are native Windows binaries and need Windows-style paths
  MODULE_DIR="$(cygpath -m "$_here")"
else
  MODULE_DIR="$_here"
fi

exists() { [ -n "${1:-}" ] && { [ -x "$1" ] || [ -f "$1" ]; }; }

first_existing() {
  local c
  for c in "$@"; do
    if exists "$c"; then printf '%s\n' "$c"; return 0; fi
  done
  return 1
}

first_existing_dir() {
  local c
  for c in "$@"; do
    if [ -d "$c" ]; then printf '%s\n' "$c"; return 0; fi
  done
  return 1
}

die() { printf '\n[ERROR] %s\n' "$*" >&2; exit 1; }

# --- Android SDK -------------------------------------------------------------
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [ ! -d "${SDK:-/nonexistent}" ]; then
  SDK="$(first_existing_dir \
      "${LOCALAPPDATA:-}/Android/Sdk" \
      "$HOME/AppData/Local/Android/Sdk" \
      "/c/Dev/AndroidSDK" \
      "/d/Dev/AndroidSDK" \
      "$HOME/Android/Sdk" \
      "/usr/lib/android-sdk" || true)"
fi
[ -d "${SDK:-/nonexistent}" ] || die "Android SDK not found. Set ANDROID_HOME."

BT_VER="${BUILD_TOOLS_VERSION:-$(ls "$SDK/build-tools" 2>/dev/null | sort -V | tail -1)}"
[ -n "$BT_VER" ] || die "no build-tools under $SDK/build-tools"
BUILD_TOOLS="$SDK/build-tools/$BT_VER"

PLAT_VER="${PLATFORM_VERSION:-$(ls "$SDK/platforms" 2>/dev/null | grep -E '^android-[0-9]+$' | sed 's/^android-//' | sort -n | tail -1)}"
[ -n "$PLAT_VER" ] || die "no platforms under $SDK/platforms"
PLATFORM_JAR="$SDK/platforms/android-$PLAT_VER/android.jar"

# --- JDK ---------------------------------------------------------------------
JDK="${JAVA_HOME:-}"
if [ ! -f "${JDK:-/nonexistent}/bin/javac.exe" ] && [ ! -f "${JDK:-/nonexistent}/bin/javac" ]; then
  javac_bin="$(command -v javac || true)"
  if [ -n "$javac_bin" ]; then
    jdk_dir="$(cd "$(dirname "$javac_bin")/.." && pwd)"
    JDK="$(cygpath -m "$jdk_dir" 2>/dev/null || printf '%s' "$jdk_dir")"
  fi
fi
[ -f "$JDK/bin/javac.exe" ] || [ -f "$JDK/bin/javac" ] || die "JDK not found. Set JAVA_HOME."

JAVA="$(first_existing "$JDK/bin/java.exe" "$JDK/bin/java")"
JAVAC="$(first_existing "$JDK/bin/javac.exe" "$JDK/bin/javac")"
KEYTOOL="$(first_existing "$JDK/bin/keytool.exe" "$JDK/bin/keytool")"

AAPT2="$BUILD_TOOLS/aapt2.exe"
[ -f "$AAPT2" ] || AAPT2="$BUILD_TOOLS/aapt2"
D8_JAR="$BUILD_TOOLS/lib/d8.jar"
APKSIGNER_JAR="$BUILD_TOOLS/lib/apksigner.jar"
ZIPALIGN="$BUILD_TOOLS/zipalign.exe"
[ -f "$ZIPALIGN" ] || ZIPALIGN="$BUILD_TOOLS/zipalign"

for f in "$AAPT2" "$D8_JAR" "$APKSIGNER_JAR" "$ZIPALIGN"; do
  [ -f "$f" ] || die "missing build-tool: $f"
done

PY="${PY:-$(first_existing \
    "${USERPROFILE:-$HOME}/.workbuddy/binaries/python/versions/"*/python.exe \
    "$(command -v python3 || true)" \
    "$(command -v python || true)" || true)}"
[ -n "$PY" ] || die "python not found. Set PY."

BUILD="$MODULE_DIR/build"
OUT="$MODULE_DIR/../dist"
APK_NAME="BdCryptomator-$VERSION_NAME.apk"

# Bundled runtime libraries (Cryptomator cryptolib + its dependencies). Optional:
# the P0 reconnaissance build needs none of them.
LIBS=()
while IFS= read -r -d '' j; do LIBS+=("$j"); done \
  < <(find "$MODULE_DIR/libs" -maxdepth 1 -name '*.jar' -print0 2>/dev/null | sort -z)

echo "==> [0/8] toolchain"
echo "    SDK          $SDK  (build-tools $BT_VER, platform android-$PLAT_VER)"
echo "    JDK          $JDK"
echo "    python       $PY"
echo "    libs         ${#LIBS[@]} jar(s)${LIBS:+: }$(printf '%s ' "${LIBS[@]##*/}")"

rm -rf "$BUILD"
mkdir -p "$BUILD/classes" "$BUILD/stubs" "$BUILD/dex" "$OUT"

echo "==> [1/8] compiling Xposed API stubs (compile-time only, NOT shipped)"
find "$MODULE_DIR/stubs" -name '*.java' > "$BUILD/stubs.txt"
"$JAVAC" -encoding UTF-8 -nowarn --release 11 \
    -cp "$PLATFORM_JAR" \
    -d "$BUILD/stubs" @"$BUILD/stubs.txt"

CP="$PLATFORM_JAR;$BUILD/stubs"
for j in ${LIBS+"${LIBS[@]}"}; do CP="$CP;$j"; done

echo "==> [2/8] compiling module sources"
find "$MODULE_DIR/src" -name '*.java' > "$BUILD/src.txt"
"$JAVAC" -encoding UTF-8 -nowarn --release 11 \
    -cp "$CP" \
    -d "$BUILD/classes" @"$BUILD/src.txt"

echo "==> [3/8] dexing (module classes${LIBS:+ + ${#LIBS[@]} jar(s)})"
find "$BUILD/classes" -name '*.class' > "$BUILD/classes.txt"
"$JAVA" -cp "$D8_JAR" com.android.tools.r8.D8 \
    --min-api 24 --lib "$PLATFORM_JAR" \
    --output "$BUILD/dex" \
    @"$BUILD/classes.txt" ${LIBS+"${LIBS[@]}"}

echo "    dex files:"; ls -la "$BUILD/dex" | tail -n +2

echo "==> [4/8] compiling resources"
"$AAPT2" compile --dir "$MODULE_DIR/res" -o "$BUILD/res.zip"

echo "==> [5/8] linking resources + manifest + assets"
"$AAPT2" link \
    -o "$BUILD/base.apk" \
    --manifest "$MODULE_DIR/AndroidManifest.xml" \
    -I "$PLATFORM_JAR" \
    -A "$MODULE_DIR/assets" \
    --min-sdk-version 24 \
    --target-sdk-version 36 \
    --version-code "$VERSION_CODE" \
    --version-name "$VERSION_NAME" \
    "$BUILD/res.zip"

echo "==> [6/8] packaging dex + aligning"
"$PY" - "$BUILD/base.apk" "$BUILD/dex" "$BUILD/unsigned.apk" <<'PYEOF'
import glob, os, shutil, sys, zipfile
src, dexdir, dst = sys.argv[1], sys.argv[2], sys.argv[3]
shutil.copyfile(src, dst)
dexes = sorted(glob.glob(os.path.join(dexdir, '*.dex')))
with zipfile.ZipFile(dst, 'a', zipfile.ZIP_DEFLATED) as z:
    for d in dexes:
        z.write(d, os.path.basename(d))
        print('    packaged %-14s %9d bytes' % (os.path.basename(d), os.path.getsize(d)))
PYEOF

"$ZIPALIGN" -f 4 "$BUILD/unsigned.apk" "$BUILD/aligned.apk"

# ------------------------------------------------------------- signing ------
prop() { sed -n "s/^[[:space:]]*$2[[:space:]]*=[[:space:]]*//p" "$1" | head -1 | tr -d '\r' | tr -d '\n'; }

echo "==> [7/8] signing"
KS_PROPS="$MODULE_DIR/keystore.properties"
if [ -f "$KS_PROPS" ]; then
    KS_REL="$(prop "$KS_PROPS" storeFile)"
    KS="$MODULE_DIR/${KS_REL:-keystore/release.keystore}"
    export KS_PASS="$(prop "$KS_PROPS" storePassword)"
    export KEY_PASS="$(prop "$KS_PROPS" keyPassword)"
    KS_ALIAS="$(prop "$KS_PROPS" keyAlias)"
    SIGN_MODE="release"
    [ -f "$KS" ] || die "keystore.properties exists but $KS does not"
    [ -n "$KS_PASS" ] || die "storePassword missing in keystore.properties"
else
    echo "    keystore.properties not found -> falling back to a debug key"
    KS="$MODULE_DIR/keystore/debug.keystore"
    KS_PASS="android"; KEY_PASS="android"; KS_ALIAS="androiddebugkey"
    SIGN_MODE="debug"
    if [ ! -f "$KS" ]; then
        mkdir -p "$(dirname "$KS")"
        "$KEYTOOL" -genkeypair -keystore "$KS" -storepass "$KS_PASS" -keypass "$KEY_PASS" \
            -alias "$KS_ALIAS" -keyalg RSA -keysize 2048 -validity 10950 \
            -dname "CN=Android Debug,O=Android,C=US" >/dev/null 2>&1
        echo "    generated debug keystore"
    fi
fi

# apksigner reads the passwords from the environment, never from argv.
export KS_PASS KEY_PASS

"$JAVA" -jar "$APKSIGNER_JAR" sign \
    --ks "$KS" \
    --ks-pass "env:KS_PASS" --key-pass "env:KEY_PASS" \
    --ks-key-alias "$KS_ALIAS" \
    --v1-signing-enabled true \
    --v2-signing-enabled true \
    --v3-signing-enabled true \
    --v4-signing-enabled false \
    --out "$OUT/$APK_NAME" \
    "$BUILD/aligned.apk"

unset KS_PASS KEY_PASS

echo "==> [8/8] verifying"
"$JAVA" -jar "$APKSIGNER_JAR" verify --print-certs "$OUT/$APK_NAME" | head -6
echo
echo "signing mode: $SIGN_MODE  (keystore: $KS)"
echo "OK -> $OUT/$APK_NAME  ($(du -h "$OUT/$APK_NAME" | cut -f1))"
