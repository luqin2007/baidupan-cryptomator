#!/usr/bin/env python3
"""DEX inspection toolkit.

Unlike a plain string-pool scraper, this resolves *real* type relations and
method prototypes out of the dex structures themselves:

  * ``interfaces``  - read ``interfaces_off`` so implementors of an interface can
    be found even when the class extends something else.
  * ``methods``     - render ``ReturnType method(ParamTypes)`` from
    ``proto_id``/``type_list``, which is what you need to write a reflection
    call or an Xposed hook against an obfuscated class.

Usage
-----
    python tools/dexdump.py --dex DIR classes <regex>
    python tools/dexdump.py --dex DIR methods <internal/Class;Name or dot.Name>
    python tools/dexdump.py --dex DIR impl <interface>       # implementors + methods
    python tools/dexdump.py --dex DIR subclasses <class>
    python tools/dexdump.py --dex DIR fields <class>
    python tools/dexdump.py --dex DIR refs <regex>           # classes referencing name
"""
from __future__ import annotations

import argparse
import glob
import os
import re
import struct
import sys
from collections import defaultdict

NO_INDEX = 0xFFFFFFFF


def uleb128(buf: bytes, off: int):
    result = 0
    shift = 0
    while True:
        byte = buf[off]
        off += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return result, off
        shift += 7


class Dex:
    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as fh:
            self.b = fh.read()
        if self.b[:4] not in (b"dex\n", b"cdex"):
            raise ValueError(f"not a dex: {path}")
        (self.string_ids_size, self.string_ids_off,
         self.type_ids_size, self.type_ids_off,
         self.proto_ids_size, self.proto_ids_off,
         self.field_ids_size, self.field_ids_off,
         self.method_ids_size, self.method_ids_off,
         self.class_defs_size, self.class_defs_off) = struct.unpack_from("<12I", self.b, 0x38)
        self._str_cache: dict[int, str] = {}

    # ---------------------------------------------------------------- ids ---
    def string(self, idx: int) -> str:
        if idx == NO_INDEX:
            return "<none>"
        hit = self._str_cache.get(idx)
        if hit is not None:
            return hit
        off = struct.unpack_from("<I", self.b, self.string_ids_off + idx * 4)[0]
        _, p = uleb128(self.b, off)
        end = self.b.index(b"\x00", p)
        s = self.b[p:end].decode("utf-8", "replace")
        self._str_cache[idx] = s
        return s

    def type(self, idx: int):
        if idx == NO_INDEX:
            return None
        return self.string(struct.unpack_from("<I", self.b, self.type_ids_off + idx * 4)[0])

    def type_list(self, off: int):
        if not off:
            return []
        size = struct.unpack_from("<I", self.b, off)[0]
        return [self.type(struct.unpack_from("<H", self.b, off + 4 + i * 2)[0])
                for i in range(size)]

    def proto(self, idx: int):
        shorty_idx, return_type_idx, params_off = struct.unpack_from(
            "<3I", self.b, self.proto_ids_off + idx * 12)
        return self.type_list(params_off), self.type(return_type_idx)

    def field(self, idx: int):
        class_idx, type_idx, name_idx = struct.unpack_from(
            "<HHI", self.b, self.field_ids_off + idx * 8)
        return self.type(class_idx), self.type(type_idx), self.string(name_idx)

    def method(self, idx: int):
        class_idx, proto_idx, name_idx = struct.unpack_from(
            "<HHI", self.b, self.method_ids_off + idx * 8)
        params, ret = self.proto(proto_idx)
        return self.type(class_idx), params, ret, self.string(name_idx)

    # ------------------------------------------------------------ classdef ---
    def class_defs(self):
        out = []
        for i in range(self.class_defs_size):
            off = self.class_defs_off + i * 32
            (class_idx, access, super_idx, ifaces_off, _src, _ann, cd_off,
             _sv) = struct.unpack_from("<8I", self.b, off)
            out.append({
                "name": self.type(class_idx),
                "access": access,
                "super": self.type(super_idx),
                "interfaces": self.type_list(ifaces_off),
                "class_data_off": cd_off,
            })
        return out

    def class_data_methods(self, off: int):
        """[(member_idx, access)] for direct + virtual methods declared here."""
        if not off:
            return []
        p = off
        s_f, p = uleb128(self.b, p)
        i_f, p = uleb128(self.b, p)
        d_m, p = uleb128(self.b, p)
        v_m, p = uleb128(self.b, p)
        for _ in range(s_f + i_f):
            _, p = uleb128(self.b, p)
            _, p = uleb128(self.b, p)
        out = []
        for count in (d_m, v_m):
            midx = 0
            for _ in range(count):
                diff, p = uleb128(self.b, p)
                access, p = uleb128(self.b, p)
                _, p = uleb128(self.b, p)
                midx += diff
                out.append((midx, access))
        return out

    def class_data_fields(self, off: int):
        if not off:
            return []
        p = off
        s_f, p = uleb128(self.b, p)
        i_f, p = uleb128(self.b, p)
        _, p = uleb128(self.b, p)
        _, p = uleb128(self.b, p)
        out = []
        for count in (s_f, i_f):
            fidx = 0
            for _ in range(count):
                diff, p = uleb128(self.b, p)
                access, p = uleb128(self.b, p)
                fidx += diff
                out.append((fidx, access))
        return out


# ------------------------------------------------------------------ format ---
def pretty(t: str) -> str:
    """Lcom/foo/Bar;  ->  com.foo.Bar ; [[I -> int[][]"""
    if t is None:
        return "?"
    depth = 0
    while t.startswith("["):
        depth += 1
        t = t[1:]
    prim = {"V": "void", "Z": "boolean", "B": "byte", "S": "short",
            "C": "char", "I": "int", "J": "long", "F": "float", "D": "double"}
    if t in prim:
        base = prim[t]
    elif t.startswith("L") and t.endswith(";"):
        base = t[1:-1].replace("/", ".")
    else:
        base = t
    return base + "[]" * depth


def sig(cls, params, ret, name) -> str:
    return "%s %s.%s(%s)" % (pretty(ret), pretty(cls), name,
                             ", ".join(pretty(p) for p in params))


def acc_str(a: int) -> str:
    bits = [("public", 0x1), ("private", 0x2), ("protected", 0x4), ("static", 0x8),
            ("final", 0x10), ("synthetic", 0x1000), ("abstract", 0x400),
            ("constructor", 0x10000), ("declared-synchronized", 0x20000)]
    return " ".join(n for n, m in bits if a & m)


def _sorted_sigs(d: "Dex", cd: dict):
    """Unique method signatures declared in this class, sorted by name then sig."""
    out = set()
    for mi, acc in d.class_data_methods(cd["class_data_off"]):
        out.add(sig(*d.method(mi)))
    return sorted(out, key=lambda s: (s.split("(")[0].split()[-1], s))


# ------------------------------------------------------------------ driver ---
class Suite:
    def __init__(self, dex_paths):
        self.dexes = [Dex(p) for p in dex_paths]
        self.classes: dict[str, dict] = {}
        self.iface_impls: dict[str, set[str]] = defaultdict(set)
        self.subs: dict[str, set[str]] = defaultdict(set)
        for d in self.dexes:
            for cd in d.class_defs():
                if not cd["name"]:
                    continue
                self.classes.setdefault(cd["name"], cd)
                if cd["super"]:
                    self.subs[cd["super"]].add(cd["name"])
                for itf in cd["interfaces"]:
                    self.iface_impls[itf].add(cd["name"])

    def find(self, name: str):
        """Accept internal (Lcom/x;), dotted (com.x) or bare simple-name form."""
        if name.endswith(";"):
            internal = name if name.startswith("L") else "L" + name
        elif name.startswith("L") and "/" in name:
            internal = name + ";"
        else:
            internal = "L" + name.replace(".", "/") + ";"
        if internal in self.classes:
            return internal
        simple = name.rsplit(".", 1)[-1].rstrip(";")
        hits = [c for c in self.classes if c[1:-1].split("/")[-1] == simple]
        return hits[0] if len(hits) == 1 else None


def cli():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dex", required=True, help="directory containing classes*.dex")
    ap.add_argument("--limit", type=int, default=0)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for c in ("classes", "methods", "fields", "impl", "subclasses", "refs", "sig"):
        p = sub.add_parser(c)
        p.add_argument("target")
    args = ap.parse_args()

    paths = sorted(glob.glob(os.path.join(args.dex, "*.dex")))
    if not paths:
        sys.exit("no dex in " + args.dex)
    sx = Suite(paths)
    out, lim = [], args.limit

    if args.cmd == "classes":
        rx = re.compile(args.target)
        out = [c[1:-1] for c in sorted(sx.classes) if rx.search(c)]
    elif args.cmd == "sig":  # search every method signature by regex
        rx = re.compile(args.target)
        for d in sx.dexes:
            for cd in d.class_defs():
                if not cd["name"]:
                    continue
                for midx, _a in d.class_data_methods(cd["class_data_off"]):
                    cls, params, ret, name = d.method(midx)
                    s = sig(cls, params, ret, name)
                    if rx.search(s):
                        out.append(s)
        out = sorted(set(out))
    else:
        target = sx.find(args.target)
        if not target:
            sys.exit("class not found: " + args.target)
        out.append("# " + target + "   super=" + str(sx.classes[target]["super"]))
        if args.cmd == "methods":
            for d in sx.dexes:
                for cd in d.class_defs():
                    if cd["name"] == target:
                        ms = _sorted_sigs(d, cd)
                        out += ["    " + s for s in ms]
        elif args.cmd == "fields":
            for d in sx.dexes:
                for cd in d.class_defs():
                    if cd["name"] == target:
                        fs = sorted(set(
                            "%s %s" % (pretty(d.field(fi)[1]), d.field(fi)[2])
                            for fi, _a in d.class_data_fields(cd["class_data_off"])))
                        out += ["    " + s for s in fs]
        elif args.cmd == "impl":
            for c in sorted(sx.iface_impls.get(target, ())):
                out.append(c[1:-1])
        elif args.cmd == "subclasses":
            for c in sorted(sx.subs.get(target, ())):
                out.append(c[1:-1])
        elif args.cmd == "refs":
            rx = re.compile(args.target)
            for d in sx.dexes:
                for cd in d.class_defs():
                    if cd["name"] and rx.search(cd["name"]):
                        out.append(cd["name"][1:-1])

    if lim:
        out = out[:lim]
    print("\n".join(out))
    print(f"\n[{len(out)} lines from {len(sx.dexes)} dex]")


if __name__ == "__main__":
    cli()
