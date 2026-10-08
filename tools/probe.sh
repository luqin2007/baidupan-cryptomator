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

# Arguments are paths *on the device* (`get /crypto/...`, `nav /crypto/...`), and MSYS rewrites a
# leading `/` into the Git installation directory on the way through — measured: `nav /crypto/…`
# arrived as `C:/Users/lq200/AppData/Local/Programs/WorkBuddy/resources/vendor/PortableGit/crypto/…`
# and the module dutifully built a CloudFile for that. Nothing in this script wants the conversion.
export MSYS_NO_PATHCONV=1

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# A scratch copy of the module log, refetched on every call. Lands next to this script and is
# covered by the repo's `*.log` ignore rule; override with BDC_LOG_CACHE if you want it elsewhere.
CACHE="${BDC_LOG_CACHE:-$HERE/bdc.log}"
ADB="${ADB:-/c/Dev/AndroidSDK/platform-tools/adb.exe}"
SSH_HOST="${SSH_HOST:-u0_a373@192.168.1.136}"
SSH_PORT="${SSH_PORT:-8022}"

# The serial is resolved, not remembered. It used to be hard-coded to
# `adb-68701bc5-igYOHf._adb-tls-connect._tcp`, and adb appends a " (2)" disambiguator of its own
# once it has seen the same mdns device twice — after which every broadcast died with
# `device '…' not found`, the `>/dev/null 2>&1` at the call site hid the message, and the empty
# output was indistinguishable from "the module did not answer". That cost a whole round of
# suspicion aimed at the module (2026-10-08 17:00). Field-splitting on TAB keeps the suffix, which
# is part of the serial; splitting on whitespace would drop it and reproduce the bug.
if [ -z "${ANDROID_SERIAL:-}" ]; then
    ANDROID_SERIAL="$("$ADB" devices | awk -F'\t' 'NR > 1 && $2 ~ /device/ {print $1; exit}')"
fi
if [ -z "$ANDROID_SERIAL" ]; then
    echo "p.sh: no adb device attached ($ADB)" >&2
    exit 1
fi
export ANDROID_SERIAL

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

# What the answer ends with. ProbeReceiver logs this even when the command itself printed nothing,
# so its arrival is the one signal that means "the module has finished and flushed".
marker="probe '$cmd' done in"
seen=$(grep -cF "$marker" "$CACHE" || true)

# The reply is not read here, only the failure: `am broadcast` exits 0 even when nobody receives
# it, so this can only catch "the command never reached a device" — which is exactly the failure
# that the old `>/dev/null 2>&1` made invisible.
if ! bcast=$("$ADB" "${args[@]}" 2>&1); then
    echo "p.sh: broadcast failed on $ANDROID_SERIAL: $bcast" >&2
    exit 1
fi

# Poll instead of sleeping once. LSPosed flushes the module log asynchronously, so a fixed wait
# races the writer: measured 2026-10-08, the same command answered in 2 ms while a 3 s sleep still
# saw an unchanged file, and the empty output read exactly like "the module did not answer".
#
# Waiting on the *marker* rather than on the file growing is the third iteration of this bug and
# the only one that is actually robust. Counted lines are a proxy: the sed below rewrites every
# line, so a pull that caught the file mid-write could compare a pre-broadcast count against a
# post-broadcast cache and see no difference — which is precisely what happened when `state`
# answered into the log at 16:57:56 while the call that asked for it had already given up.
deadline=$((SECONDS + ${PROBE_DEADLINE:-30}))
answered=0
while :; do
    sleep 1
    pull
    now=$(grep -cF "$marker" "$CACHE" || true)
    if [ "$now" -gt "$seen" ]; then
        answered=1
        break
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then
        echo "p.sh: no answer in ${PROBE_DEADLINE:-30}s (log still at $before lines," \
             "no '$marker' past line $seen)" >&2
        break
    fi
done

if [ "$answered" = 1 ]; then
    tail -n +$((before + 1)) "$CACHE"
fi
