#!/usr/bin/env python3
"""Differential test: full JSON dump of the Rust `moex` vs the C++ oracle.

    tests/golden/compare_live.py [--limit N] [--max-size BYTES] PATH...

PATH may be files or directories (scanned non-recursively). Needs
`build/moex-dump` (oracle) and `target/release/moex`. Exit code 1 on any
difference. Cells of the form `<process address>-><value>` in pointer tables
are compared after the `->` only (the C++ value changes on every run).
"""
import argparse, json, os, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ORACLE = os.environ.get("MOEX_ORACLE", os.path.join(ROOT, "build/moex-dump"))
MOEX = os.environ.get("MOEX_BIN", os.path.join(ROOT, "target/release/moex"))
POINTER_NODES = {"Literal Pointers", "Module Init Func Pointers", "Module Term Func Pointers"}
MAGICS = {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
          b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf", b"!<ar"}


def run(cmd, env):
    p = subprocess.run(cmd, capture_output=True, env=env, timeout=600)
    return p.returncode, p.stdout, p.stderr.decode("utf-8", "replace").strip().splitlines()[-1:] or [""]


def normalise(node):
    if node.get("name") in POINTER_NODES and "table" in node:
        for row in node["table"].get("rows", []):
            for holder, key in ((row.get("cells", {}), "Value"), (row.get("values", []), 2)):
                try:
                    v = holder[key]
                except (KeyError, IndexError):
                    continue
                if "->" in v:
                    holder[key] = v.split("->", 1)[1]
    for child in node.get("children", []):
        normalise(child)


def first_diff(a, b, path="analysis"):
    if type(a) != type(b):
        return f"{path}: type {type(a).__name__} vs {type(b).__name__}"
    if isinstance(a, dict):
        label = a.get("path", path)
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                return f"{label}: key {k!r} only on one side"
            if k == "children":
                if len(a[k]) != len(b[k]):
                    return f"{label}: {len(a[k])} vs {len(b[k])} children"
                for x, y in zip(a[k], b[k]):
                    d = first_diff(x, y, label)
                    if d:
                        return d
            elif a[k] != b[k]:
                d = first_diff(a[k], b[k], f"{label}.{k}")
                return d or f"{label}.{k} differs"
        return None
    if isinstance(a, list):
        if len(a) != len(b):
            return f"{path}: length {len(a)} vs {len(b)}"
        for i, (x, y) in enumerate(zip(a, b)):
            d = first_diff(x, y, f"{path}[{i}]")
            if d:
                return d
        return None
    return None if a == b else f"{path}: {str(a)[:120]!r} vs {str(b)[:120]!r}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--max-size", type=int, default=6 * 1024 * 1024)
    args = ap.parse_args()

    files = []
    for p in args.paths:
        entries = sorted(os.path.join(p, n) for n in os.listdir(p)) if os.path.isdir(p) else [p]
        for f in entries:
            try:
                if not os.path.isfile(f) or os.path.getsize(f) > args.max_size or os.path.getsize(f) < 8:
                    continue
                with open(f, "rb") as fh:
                    if fh.read(4) in MAGICS:
                        files.append(f)
            except OSError:
                pass
    if args.limit:
        files = files[: args.limit]

    env = dict(os.environ, TZ="UTC", MOEX_TZ="UTC")
    same = diff = both_fail = oracle_crash = 0
    for f in files:
        try:
            rc_c, out_c, err_c = run([ORACLE, "--format", "json", "--include-empty", f], env)
            rc_r, out_r, err_r = run([MOEX, "dump", "--format", "json", "--include-empty", f], env)
        except subprocess.TimeoutExpired:
            print(f"TIMEOUT {f}")
            diff += 1
            continue
        if rc_c < 0 or rc_c > 1:
            oracle_crash += 1  # the C++ tool crashed; nothing to compare against
            if rc_r not in (0, 1):
                print(f"RUST-CRASH {f}: rc={rc_r}")
                diff += 1
            continue
        if rc_c != 0 or rc_r != 0:
            if rc_c == rc_r and err_c == err_r:
                both_fail += 1
            else:
                print(f"DIFF {f}: exit {rc_c} {err_c} vs {rc_r} {err_r}")
                diff += 1
            continue
        a, b = json.loads(out_c), json.loads(out_r)
        normalise(a["analysis"]); normalise(b["analysis"])
        d = first_diff(a, b)
        if d:
            print(f"DIFF {f}: {d}")
            diff += 1
        else:
            same += 1
    print(f"compare-live: {len(files)} files, {same} identical, {both_fail} same error, "
          f"{oracle_crash} oracle crashed, {diff} different")
    sys.exit(1 if diff else 0)


if __name__ == "__main__":
    main()
