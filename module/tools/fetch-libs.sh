#!/usr/bin/env bash
#
# Reproduce module/libs/*.jar.
#
# The runtime crypto comes from Cryptomator's own libraries, which are AGPL-3.0.
# They are deliberately NOT vendored into this repository, so this script obtains
# them from one of two places:
#
#   1. a local Cryptomator desktop install (exact versions the user already runs,
#      verified to be Java 8 bytecode and therefore d8/Android-compatible), or
#   2. Maven Central.
#
# Usage:  bash module/tools/fetch-libs.sh [--from-maven-central]
#
set -euo pipefail

CRYPTOLIB_VERSION="${CRYPTOLIB_VERSION:-2.2.2}"
SIVMODE_VERSION="${SIVMODE_VERSION:-1.6.1}"

_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIBS="$(cd "$_here/.." && pwd)/libs"
mkdir -p "$LIBS"

need=( "cryptolib-$CRYPTOLIB_VERSION.jar" "siv-mode-$SIVMODE_VERSION.jar" )

have_all() {
  for f in "${need[@]}"; do
    [ -f "$LIBS/$f" ] || return 1
  done
}

if have_all && [ "${1:-}" != "--force" ]; then
  echo "libs already present in $LIBS"; exit 0
fi

# ---------------------------------------------------------- local install ----
if [ "${1:-}" != "--from-maven-central" ]; then
  for mods in \
      "/c/Program Files/Cryptomator/app/mods" \
      "/c/Program Files (x86)/Cryptomator/app/mods" \
      "$HOME/AppData/Local/Programs/Cryptomator/app/mods" \
      "/Applications/Cryptomator.app/Contents/app/mods" \
      "/usr/share/cryptomator/app/mods" \
      "/opt/cryptomator/app/mods" ; do
    if [ -d "$mods" ]; then
      echo "found local Cryptomator: $mods"
      for f in "${need[@]}"; do
        if [ -f "$mods/$f" ]; then
          cp "$mods/$f" "$LIBS/$f"
          echo "  copied $f"
        else
          echo "  MISSING $f"
        fi
      done
      if have_all; then echo "OK -> $LIBS"; exit 0; fi
      echo "local install incomplete, falling back to Maven Central"
    fi
  done
fi

# --------------------------------------------------------------- maven -------
BASE="https://repo1.maven.org/maven2"
fetch() { # url dest
  echo "  GET $2"
  curl -fsSL --retry 3 --max-time 180 -o "$LIBS/$2" "$1" \
    || { echo "download failed: $1" >&2; exit 1; }
}

echo "fetching from Maven Central"
fetch "$BASE/org/cryptomator/cryptolib/$CRYPTOLIB_VERSION/cryptolib-$CRYPTOLIB_VERSION.jar" \
      "cryptolib-$CRYPTOLIB_VERSION.jar"
fetch "$BASE/org/cryptomator/siv-mode/$SIVMODE_VERSION/siv-mode-$SIVMODE_VERSION.jar" \
      "siv-mode-$SIVMODE_VERSION.jar"

echo "OK -> $LIBS"
ls -la "$LIBS"
