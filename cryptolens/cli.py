"""Standalone command-line interface for the CryptoLens core.

Usage:
    python -m cryptolens explain 0x9E3779B9
    python -m cryptolens explain 2654435769 --width 32
    python -m cryptolens apihash GetProcAddress
    python -m cryptolens apihash --resolve 0x7C0DFCAA
    python -m cryptolens selftest
"""
from __future__ import annotations

import argparse
import sys

from . import apihash, parse, report
from .selftest import run as run_selftest


def _cmd_explain(args: argparse.Namespace) -> int:
    p = parse.parse_token(args.value)
    if p.kind == "bytes":
        # Interpret byte blobs as little-endian ints per width chunk.
        print(f"bytes: {p.data.hex(' ')}")
        if len(p.data) in (1, 2, 4, 8):
            val = int.from_bytes(p.data, "little")
            print(report.explain_multi_text(val))
        return 0
    if args.width:
        print(report.explain_text(p.value, args.width))
    else:
        print(report.explain_multi_text(p.value))
    return 0


def _cmd_apihash(args: argparse.Namespace) -> int:
    if args.resolve is not None:
        p = parse.parse_token(args.resolve)
        hits = apihash.identify(p.value)
        if not hits:
            print(f"no API-hash match for 0x{p.value:08X}")
            return 0
        for h in hits:
            v = f" ({h.variant})" if h.variant else ""
            print(f"0x{h.value:08X} = {h.scheme}(\"{h.name}\"{v})")
        return 0
    name = args.name
    print(f"hashes of {name!r}:")
    for scheme in apihash.list_schemes():
        print(f"  {scheme:12s} 0x{apihash.hash_name(name, scheme):08X}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="cryptolens", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    ex = sub.add_parser("explain", help="explain a number / byte blob")
    ex.add_argument("value", help="0x.., decimal, 0b.., or 'string'")
    ex.add_argument("--width", type=int, choices=[8, 16, 32, 64], default=None)
    ex.set_defaults(func=_cmd_explain)

    ah = sub.add_parser("apihash", help="API-name hashing")
    ah.add_argument("name", nargs="?", default="GetProcAddress")
    ah.add_argument("--resolve", help="resolve a hash value back to an API name")
    ah.set_defaults(func=_cmd_apihash)

    st = sub.add_parser("selftest", help="run internal verification suite")
    st.set_defaults(func=lambda a: 0 if run_selftest() else 1)
    return ap


def main(argv=None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
