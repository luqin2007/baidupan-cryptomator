#!/usr/bin/env bash
# Send one probe command to the module inside the running app and print just its answer.
#
#   p.sh <cmd> [clsOrArg]
#
# Differences from probe.sh, which this replaces:
#   - it re-reads the whole module log instead of tailing from a line marker, because the
#     marker race lost answers outright (probe.sh printed nothing while the log clearly
#     held the reply);
#   - it strips the LSPosed header per line, so the *multi-line* half of a report is kept.
#     LSPosed only prefixes the first line of a multi-line log record, and probe.sh's
#     sed then dropped the body — which is where every report's actual content lives;
#   - LSPosed truncates one record at ~7.6 KB, so Channel also writes a file; see `ch`.
#
# The answer is read from LSPosed's own log file, not logcat: the main ring buffer is 128 KiB
# and one app start wipes it (docs/recon.md 8.1).
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# A scratch copy of the module log, refetched on every call. Lands next to this script and is
# covered by the repo's `*.log` ignore rule; override with BDC_LOG_CACHE if you want it elsewhere.
CACHE="${BDC_LOG_CACHE:-$HERE/bdc.log}"
ADB="${ADB:-/c/Dev/AndroidSDK/platform-tools/adb.exe}"
export ANDROID_SERIAL="${ANDROID_SERIAL:-adb-68701bc5-igYOHf._adb-tls-connect._tcp}"
SSH_HOST="${SSH_HOST:-u0_a373@192.168.1.136}"
SSH_PORT="${SSH_PORT:-8022}"

cmd="${1:?usage: p.sh <cmd> [clsOrArg]}"
extra="${2:-}"

# LSPosed starts a fresh modules_*.log per app process, and this module's answers land in the
# newest one — so a hard-coded path goes silent the moment the app is restarted. That is not
# hypothetical: it cost a whole round of "the probe printed nothing" before anyone looked at
# `ls -t /data/adb/lspd/log`. Resolved on every run unless LSPD_LOG overrides it.
latest_log() {
    ssh -p "$SSH_PORT" -o StrictHostKeyChecking=no "$SSH_HOST" \
        "su -c 'ls -t /data/adb/lspd/log/modules_*.log 2>/dev/null | head -1'" 2>/dev/null | tr -d '\r'
}

pull() {
    ssh -p "$SSH_PORT" -o StrictHostKeyChecking=no "$SSH_HOST" "su -c 'cat $LOG'" 2>/dev/null \
        | sed 's/^\[[^]]*\][^(]*([^)]*)\[[^]]*\] BDCrypto: //' > "$CACHE"
}

LOG="${LSPD_LOG:-$(latest_log)}"
if [ -z "$LOG" ]; then
    echo "p.sh: no modules_*.log on the device (ssh $SSH_HOST:$SSH_PORT)" >&2
    exit 1
fi

pull
before=$(wc -l < "$CACHE")

args=(shell am broadcast -a com.luqin.bdcrypto.PROBE --es cmd "$cmd")
if [ -n "$extra" ]; then
    # 'adb shell' re-parses on the DEVICE, so an unescaped $ in a nested class name (Foo$Bar) is
    # expanded by the device shell to nothing and the probe silently receives the outer class.
    esc="$(printf '%s' "$extra" | sed 's/\$/\\$/g')"
    args+=(--es cls "$esc" --es arg "$esc")
fi
"$ADB" "${args[@]}" >/dev/null 2>&1

sleep "${PROBE_WAIT:-3}"
pull
tail -n +$((before + 1)) "$CACHE"
