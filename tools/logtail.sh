#!/usr/bin/env bash
# Tail the module's own log records.
#
# The authoritative module log is LSPosed's own file, not logcat (see MEMORY.md: the main ring
# buffer is 128 KiB and the app's startup wipes it, which has already produced one wrong
# "the module is not loading" conclusion). Line numbers are kept so a caller can correlate.
#
# usage: tools/logtail.sh [lines] [extra-grep-pattern]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SSH_HOST="${SSH_HOST:-u0_a373@192.168.1.136}"
SSH_PORT="${SSH_PORT:-8022}"
LINES="${1:-20}"
PAT="${2:-}"

LOG="$(timeout 20 ssh -p "$SSH_PORT" -o StrictHostKeyChecking=no "$SSH_HOST" \
    "su -c 'ls -t /data/adb/lspd/log/modules_*.log' 2>/dev/null | head -1" | tr -d '\r')"
if [ -z "$LOG" ]; then
    echo "logtail.sh: no modules_*.log on the device" >&2
    exit 1
fi
echo "log: $LOG"

PAT_LINE=""
if [ -n "$PAT" ]; then
    PAT_LINE="| grep -E $(printf '%q' "$PAT")"
fi

timeout 25 ssh -p "$SSH_PORT" -o StrictHostKeyChecking=no "$SSH_HOST" \
    "su -c 'grep -n \"BDCrypto:\" $LOG $PAT_LINE | tail -n $LINES'" 2>&1 \
    | sed -E 's/^.*\[[0-9]+\] BDCrypto: /| /'
