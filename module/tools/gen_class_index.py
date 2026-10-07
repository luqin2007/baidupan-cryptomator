#!/usr/bin/env python3
"""Regenerate ``module/assets/app_classes.txt.gz`` — the on-device class index.

The module's probe can only answer "which classes exist?" if it carries a class
name index, because the host app's dex cannot be enumerated cheaply from inside
the app process. The index is derived from the *shipped* APK's dex files, which
are not redistributable, so only the resulting **class-name list** is committed —
and gzipped, because the app ships >50k classes under its own package root.

The file is a dev aid: the probe degrades to "index asset missing" without it.

Usage
-----
    python module/tools/gen_class_index.py <dir-with-classes*.dex> [output.gz]

Provenance: <dir> is produced by
    adb shell pm path com.baidu.drive.app   -> base.apk
    unzip base.apk 'classes*.dex' -d <dir>
"""
from __future__ import annotations

import glob
import gzip
import os
import struct
import sys

PREFIX = "com/baidu/netdisk/"


def uleb128(buf: bytes, off: int):
    result = 0
    shift = 0
    while True:
        b = buf[off]
        off += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return result, off
        shift += 7


def class_names(path: str, prefix: str) -> set[str]:
    with open(path, "rb") as fh:
        b = fh.read()
    (string_ids_size, string_ids_off, _t_s, _t_o, _p_s, _p_o, _f_s, _f_o,
     _m_s, _m_o, _c_s, _c_o) = struct.unpack_from("<12I", b, 0x38)
    out = set()
    for i in range(string_ids_size):
        off = struct.unpack_from("<I", b, string_ids_off + i * 4)[0]
        _len, p = uleb128(b, off)
        end = b.index(b"\x00", p)
        s = b[p:end].decode("utf-8", "replace")
        if not (s.startswith("L") and s.endswith(";") and "/" in s):
            continue
        body = s[1:-1]
        if not body.startswith(prefix):
            continue
        # keep only things that look like real class names, not descriptors
        if all(part and (part[0].isalpha() or part[0] in "_$") for part in body.split("/")):
            out.add(body)
    return out


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    dexdir = argv[1]
    out = argv[2] if len(argv) > 2 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "assets", "app_classes.txt.gz")
    out = os.path.normpath(out)

    files = sorted(glob.glob(os.path.join(dexdir, "*.dex")))
    if not files:
        print("no dex under", dexdir)
        return 1

    names: set[str] = set()
    for f in files:
        names |= class_names(f, PREFIX)
    blob = "\n".join(sorted(names)) + "\n"

    os.makedirs(os.path.dirname(out), exist_ok=True)
    with gzip.open(out, "wb", compresslevel=9) as gz:
        gz.write(blob.encode("utf-8"))

    print("dex files : %d" % len(files))
    print("classes   : %d  (prefix %s)" % (len(names), PREFIX))
    print("raw bytes : %d" % len(blob))
    print("gzip bytes: %d  -> %s" % (os.path.getsize(out), out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
