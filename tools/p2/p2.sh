#!/usr/bin/env bash
#
# P2 offline harness: run the module's own vault traversal and check it against the official oracle.
#
#   p2.sh walk     <vaultDir> <passphrase>            unlock + walk, print the manifest
#   p2.sh check    <vaultDir> <passphrase>            walk, then diff against tools/oracle
#   p2.sh check-report <vaultDir> <passphrase> <file> diff a manifest produced elsewhere (a device
#                                                     report pulled with adb) against tools/oracle
#   p2.sh negative <vaultDir> <passphrase>            provoke the failure modes on a copy
#
# What this proves and why it is shaped like this:
#   * it compiles module/src/com/luqin/bdcrypto/vault/** with NO android.jar on the classpath, so
#     the traversal is guaranteed to be device-independent (and an accidental android import breaks
#     the build here, not on the phone);
#   * it deliberately does not use MasterkeyFileAccess, gson or guava's BaseEncoding — the harness
#     has only cryptolib + siv-mode, the same two jars the module ships, so anything the module
#     would need at runtime is needed here too;
#   * `check` compares against cryptofs, which is the only authority on what the tree should be.
#
# Requires the same JDK 25 the oracle needs (cryptofs is class file version 69).
set -euo pipefail

JAVA_HOME="${ORACLE_JAVA_HOME:-${JAVA25_HOME:-}}"
if [ -z "$JAVA_HOME" ] || [ ! -x "$JAVA_HOME/bin/javac.exe" ]; then
    for c in "$HOME"/../Java/microsoft-jdk-25* /c/Dev/Java/microsoft-jdk-25* /c/Dev/Java/jdk-25* \
             "$HOME"/.jdks/*25*; do
        [ -x "$c/bin/javac.exe" ] && JAVA_HOME="$c" && break
    done
fi
[ -n "$JAVA_HOME" ] || {
    echo "no JDK 25+ found; set ORACLE_JAVA_HOME" >&2
    exit 1
}

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

# javac/java are native Windows binaries: they need C:/... paths, not /c/...
if command -v cygpath >/dev/null 2>&1; then
    HERE_WIN="$(cygpath -m "$HERE")"
    ROOT_WIN="$(cygpath -m "$ROOT")"
else
    HERE_WIN="$HERE"
    ROOT_WIN="$ROOT"
fi

BUILD="$HERE/.build"
mkdir -p "$BUILD/classes"

LIBS=""
for j in "$ROOT_WIN/module/libs"/*.jar; do
    LIBS="${LIBS:+$LIBS;}$j"
done
[ -n "$LIBS" ] || { echo "module/libs is empty — run module/tools/fetch-libs.sh" >&2; exit 1; }

# The module's vault package, plus the one guava class cryptolib's scrypt path reaches for.
SOURCES=()
while IFS= read -r -d '' f; do SOURCES+=("$f"); done \
    < <(find "$ROOT_WIN/module/src/com/luqin/bdcrypto/vault" "$ROOT_WIN/module/src/com/google" \
         -name '*.java' -print0)
SOURCES+=("$HERE_WIN/P2Main.java")

echo "jdk    : $JAVA_HOME" >&2
echo "libs   : $LIBS" >&2
echo "sources: ${#SOURCES[@]} file(s) (module vault package + P2Main)" >&2

"$JAVA_HOME/bin/javac.exe" -encoding UTF-8 -nowarn --release 11 \
    -cp "$LIBS" -d "$HERE_WIN/.build/classes" "${SOURCES[@]}"

mode="${1:?usage: p2.sh walk|check|check-report|negative <vaultDir> <passphrase>}"
vault="${2:?missing vaultDir}"
pass="${3:?missing passphrase}"

p2_into() { # <vaultDir> <passphrase> — P2Main's stdout, exit code preserved
    "$JAVA_HOME/bin/java.exe" -Dstdout.encoding=UTF-8 -Dfile.encoding=UTF-8 \
        -cp "$LIBS;$HERE_WIN/.build/classes" P2Main "$1" "$2"
}

run_p2() {
    p2_into "$vault" "$pass"
}

# Both manifests are reduced to one normalised line per entry (D/F/T kind, cleartext path,
# ciphertext path, cleartext size) and sorted, so the comparison is about content and not about
# spacing, ordering or the fields P2 does not produce yet (content digests are P3). -n + p means
# every other line of either manifest — headers, timings, warnings — is dropped rather than diffed.
# `totals   :` with padding is accepted too: that is what the on-device report looks like.
normalise() {
    sed -n -E \
        -e 's/^DIR[[:space:]]+(.*[^[:space:]])[[:space:]]+<-[[:space:]]+([^[:space:]]+)[[:space:]]*$/D \1 \2/p' \
        -e 's/^FILE[[:space:]]+(.*[^[:space:]])[[:space:]]+<-[[:space:]]+([^[:space:]]+)[[:space:]]+size=([0-9]+).*$/F \1 \2 \3/p' \
        -e 's/^totals[[:space:]]*:[[:space:]]*(.*)$/T \1/p' \
        "$1" | LC_ALL=C sort
}

# Reduces one manifest of ours against cryptofs's, entry by entry.
compare_with_oracle() { # <our manifest file>
    local ours="$1"
    local raw="$BUILD/oracle-manifest.txt"
    # The oracle prints logback noise (DEBUG/WARN lines) into the same stream; only its manifest
    # lines are of interest.
    bash "$ROOT/tools/oracle/oracle.sh" unlock "$vault" "$pass" > "$raw" 2>&1 || {
        echo "oracle failed; see $raw" >&2
        return 1
    }
    grep -E '^(DIR |FILE |totals:)' "$raw" > "$BUILD/oracle-lines.txt" || true

    normalise "$BUILD/oracle-lines.txt" > "$BUILD/expected.txt"
    normalise "$ours" > "$BUILD/actual.txt"

    if diff -u "$BUILD/expected.txt" "$BUILD/actual.txt" > "$BUILD/manifest.diff"; then
        echo "P2 CHECK OK: $(grep -c '^[DF] ' "$BUILD/actual.txt") entries match cryptofs"
        grep -c '^D ' "$BUILD/actual.txt" | sed 's/^/  dirs : /'
        grep -c '^F ' "$BUILD/actual.txt" | sed 's/^/  files: /'
        grep '^T ' "$BUILD/actual.txt" | sed 's/^/  /'
        return 0
    fi
    echo "P2 CHECK FAILED — difference against cryptofs:" >&2
    cat "$BUILD/manifest.diff" >&2
    return 1
}

if [ "$mode" = "walk" ]; then
    run_p2
elif [ "$mode" = "check" ]; then
    P2_OUT="$BUILD/p2-manifest.txt"
    if ! run_p2 > "$P2_OUT"; then
        echo "P2 traversal failed or reported warnings:" >&2
        cat "$P2_OUT" >&2
        exit 1
    fi
    compare_with_oracle "$P2_OUT"
elif [ "$mode" = "check-report" ]; then
    # For output this script cannot produce itself: the report the module writes on the device
    # (adb pull …/bdcrypto/vault.txt). Same comparison, same authority.
    report="${4:?missing reportFile}"
    [ -f "$report" ] || { echo "no such report: $report" >&2; exit 2; }
    grep -q 'P2 TRAVERSAL CLEAN' "$report" || {
        echo "report is not clean (warnings or failure):" >&2
        tail -5 "$report" >&2
        exit 1
    }
    compare_with_oracle "$report"
elif [ "$mode" = "negative" ]; then
    # Proves the check above can fail. A verification that has only ever been run against a good
    # vault is indistinguishable from one that always says "ok", so each failure mode the format
    # has is provoked on a copy and matched against the message it is supposed to produce.
    WORK="$BUILD/negative"
    rm -rf "$WORK"
    cp -r "$vault" "$WORK"
    rc=0

    check_negative() { # <label> <vaultDir> <passphrase> <expected message fragment>
        local label="$1" dir="$2" pw="$3" needle="$4" log="$BUILD/negative.log"
        if p2_into "$dir" "$pw" > "$log" 2>&1; then
            echo "NEGATIVE FAIL: $label — the traversal succeeded" >&2
            return 1
        fi
        if grep -qF -- "$needle" "$log"; then
            printf 'ok  %-28s %s\n' "$label" "$(grep -m1 -F -- "$needle" "$log" | cut -c1-96)"
            return 0
        fi
        echo "NEGATIVE FAIL: $label — it failed, but not with '$needle':" >&2
        sed -n '1,8p' "$log" >&2
        return 1
    }

    # 1. a wrong passphrase must be reported as a failed unwrap, not as a broken vault file
    check_negative "wrong passphrase" "$WORK" "definitely-not-the-passphrase" \
        "integrity check" || rc=1

    # 2. an entry name that no longer authenticates (change one character of one .c9r name)
    victim="$(find "$WORK/d" -name '*.c9r' ! -name 'dir.c9r' ! -name 'dirid.c9r' \
        ! -name 'contents.c9r' | head -1)"
    if [ -n "$victim" ]; then
        base="$(basename "$victim")"
        first="${base:0:1}"
        [ "$first" = "A" ] && swap="B" || swap="A"
        mv "$victim" "$(dirname "$victim")/$swap${base:1}"
        check_negative "tampered entry name" "$WORK" "$pass" "does not authenticate" || rc=1
        mv "$(dirname "$victim")/$swap${base:1}" "$victim"
    else
        echo "NEGATIVE FAIL: no .c9r entry found to tamper with" >&2
        rc=1
    fi

    # 3. a tampered vault.cryptomator must fail the HS256 check (one character appended)
    printf 'A' >> "$WORK/vault.cryptomator"
    check_negative "tampered vault config" "$WORK" "$pass" "signature does not verify" || rc=1
    cp "$vault/vault.cryptomator" "$WORK/vault.cryptomator"

    # 4. a dirid.c9r that contradicts the id we walked with is a WARNING, and warnings are fatal
    dirid="$(find "$WORK/d" -name 'dirid.c9r' | head -1)"
    if [ -n "$dirid" ]; then
        head -c 100 "$dirid" > "$dirid.tmp" && mv "$dirid.tmp" "$dirid"
        check_negative "wrong dirid.c9r size" "$WORK" "$pass" "dirid.c9r of" || rc=1
    else
        echo "NEGATIVE FAIL: no dirid.c9r found" >&2
        rc=1
    fi

    if [ "$rc" = "0" ]; then
        echo "P2 NEGATIVE OK: every provoked fault was detected"
    else
        echo "P2 NEGATIVE FAILED" >&2
    fi
    exit "$rc"
else
    echo "unknown mode: $mode" >&2
    exit 2
fi
