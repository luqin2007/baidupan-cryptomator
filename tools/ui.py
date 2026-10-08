#!/usr/bin/env python3
"""Drive the app's UI from the shell: dump the tree, find a node, tap its centre.

Exists because every tap has to be aimed at a *measured* rectangle rather than a remembered one:
tapping 84,72 for a back arrow that actually lives at 39..105 x 123..189 wasted a whole round of
testing earlier in this project.

    ui.py dump                     print the visible tree (text/resource-id + bounds)
    ui.py find <regex>             print matching nodes and their centres
    ui.py tap <regex> [n]          tap the centre of the n-th match (default 0)
    ui.py long <regex> [n]         long-press it (multi-select); swipe in place, no movement
    ui.py tapxy X Y                tap absolute coordinates
    ui.py back / home / enter      key events

Note MSYS_NO_PATHCONV: without it Git Bash rewrites /sdcard/ui.xml into a Windows path and
uiautomator writes the dump somewhere adb cannot read back.
"""
import os
import re
import subprocess
import sys
import tempfile
import time

ADB = os.environ.get("ADB", "C:/Dev/AndroidSDK/platform-tools/adb.exe")
REMOTE = "/sdcard/bdcrypto_ui.xml"
# Deliberately NOT next to this script: a stray ui.xml in the repo tree is easy to commit by
# accident, and the dump carries real cloud file names.
LOCAL = os.path.join(tempfile.gettempdir(), "bdcrypto_ui.xml")

ENV = dict(os.environ)
ENV["MSYS_NO_PATHCONV"] = "1"


def adb(*args, timeout=60):
    return subprocess.run([ADB, *args], capture_output=True, text=True, env=ENV,
                          timeout=timeout).stdout


def dump():
    adb("shell", "uiautomator", "dump", "--compressed", REMOTE)
    xml = adb("shell", "cat", REMOTE)
    with open(LOCAL, "w", encoding="utf-8") as f:
        f.write(xml)
    return xml


def nodes(xml):
    out = []
    for tag in re.findall(r"<node[^>]*>", xml):
        def attr(name):
            m = re.search(name + r'="([^"]*)"', tag)
            return m.group(1) if m else ""
        b = attr("bounds")
        m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", b)
        rect = tuple(int(x) for x in m.groups()) if m else None
        out.append({
            "text": attr("text"),
            "id": attr("resource-id"),
            "cls": attr("class").split(".")[-1],
            "desc": attr("content-desc"),
            "rect": rect,
            "raw": tag,
        })
    return out


def label(n):
    return n["text"] or n["id"] or n["desc"] or n["cls"]


def centre(n):
    l, t, r, b = n["rect"]
    return (l + r) // 2, (t + b) // 2


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "dump"
    xml = dump()
    ns = nodes(xml)

    if cmd == "dump":
        for n in ns:
            if n["rect"] is None:
                continue
            print("%-26s %-20s %s" % ("[%d,%d][%d,%d]" % n["rect"], n["cls"], label(n)[:60]))
    elif cmd == "find":
        pat = re.compile(sys.argv[2])
        for i, n in enumerate(ns):
            if n["rect"] and pat.search(label(n)):
                print("[%d] %-26s %-20s %s" % (i, "[%d,%d][%d,%d]" % n["rect"], n["cls"],
                                               label(n)[:60]))
    elif cmd == "tap":
        pat = re.compile(sys.argv[2])
        want = int(sys.argv[3]) if len(sys.argv) > 3 else 0
        hits = [n for n in ns if n["rect"] and pat.search(label(n))]
        if not hits:
            print("no node matches", sys.argv[2])
            sys.exit(1)
        n = hits[min(want, len(hits) - 1)]
        x, y = centre(n)
        print("tap %d,%d  (%s)" % (x, y, label(n)[:50]))
        adb("shell", "input", "tap", str(x), str(y))
    elif cmd == "long":
        # There is no `input longpress`; a swipe that starts and ends on the same pixel and lasts
        # longer than the long-press timeout is the standard substitute.
        pat = re.compile(sys.argv[2])
        want = int(sys.argv[3]) if len(sys.argv) > 3 else 0
        hits = [n for n in ns if n["rect"] and pat.search(label(n))]
        if not hits:
            print("no node matches", sys.argv[2])
            sys.exit(1)
        n = hits[min(want, len(hits) - 1)]
        x, y = centre(n)
        print("long-press %d,%d  (%s)" % (x, y, label(n)[:50]))
        adb("shell", "input", "swipe", str(x), str(y), str(x), str(y), "900")
    elif cmd == "tapxy":
        adb("shell", "input", "tap", sys.argv[2], sys.argv[3])
    elif cmd in ("back", "home", "enter"):
        adb("shell", "input", "keyevent",
            {"back": "KEYCODE_BACK", "home": "KEYCODE_HOME", "enter": "KEYCODE_ENTER"}[cmd])
    else:
        print(__doc__)
        sys.exit(2)
    time.sleep(0.3)


if __name__ == "__main__":
    main()
