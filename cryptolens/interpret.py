"""General-purpose interpretation of an arbitrary integer (IDA-independent).

When the crypto engine finds no constant/variant match, a raw value seen in an
obfuscated binary is still often *something*: a timestamp, an IEEE-754 float, a
packed ASCII tag, a compiler division-magic reciprocal, a masked pointer, ...
``describe_value`` returns a list of plain-language interpretations so the
lookup panel is useful even on non-crypto constants.
"""
from __future__ import annotations

import datetime
import struct
from typing import List

from . import util

# Common unsigned-division "magic" reciprocals emitted by compilers (32-bit).
_DIV_MAGIC = {
    0xAAAAAAAB: "unsigned x / 3 (compiler division magic)",
    0xCCCCCCCD: "unsigned x / 5 (compiler division magic)",
    0x2AAAAAAB: "unsigned x / 6 (compiler division magic)",
    0x24924925: "unsigned x / 7 (compiler division magic)",
    0x92492493: "unsigned x / 7 variant (compiler division magic)",
    0x38E38E39: "unsigned x / 9 (compiler division magic)",
    0x4EC4EC4F: "unsigned x / 13 (compiler division magic)",
    0x51EB851F: "unsigned x / 100 or / 25 (compiler division magic)",
    0x55555556: "signed x / 3 (compiler division magic)",
    0x66666667: "signed x / 5 (compiler division magic)",
}

_UNIX_MIN = 946684800            # 2000-01-01
_UNIX_MAX = 4102444800           # 2100-01-01
_FILETIME_MIN = 125911584000000000   # 2000-01-01 in 100ns ticks since 1601
_FILETIME_MAX = 157469184000000000   # ~2100


def _fmt(unix_seconds: float):
    try:
        dt = datetime.datetime.fromtimestamp(unix_seconds, datetime.timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return None


def _reasonable_float(x: float) -> bool:
    import math
    if not math.isfinite(x):
        return False
    ax = abs(x)
    return x == 0.0 or (1e-4 <= ax <= 1e12)


def _ascii(b: bytes) -> str:
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b)


def describe_value(value: int) -> List[str]:
    out: List[str] = []
    if value < 0:
        return out

    widths = [w for w in (8, 16, 32, 64) if value <= util.mask(w)]
    width = widths[0] if widths else 64
    nbytes = max((value.bit_length() + 7) // 8, 1)

    out.append(f"decimal (unsigned): {value:,}")
    if width in (8, 16, 32, 64) and value >> (width - 1):
        out.append(f"decimal (signed {width}-bit): {value - (1 << width):,}")
    out.append(f"bits set: {bin(value).count('1')}, bit length: {value.bit_length()}")

    if nbytes <= 8:
        le = value.to_bytes(nbytes, "little")
        be = value.to_bytes(nbytes, "big")
        out.append(f"bytes LE: {le.hex(' ')}   ascii: '{_ascii(le)}'")
        if be != le:
            out.append(f"bytes BE: {be.hex(' ')}   ascii: '{_ascii(be)}'")

    # IEEE-754 interpretations
    if value <= util.mask(32):
        f = struct.unpack("<f", value.to_bytes(4, "little"))[0]
        if _reasonable_float(f):
            out.append(f"as IEEE-754 float32: {f!r}")
    if value <= util.mask(64):
        d = struct.unpack("<d", value.to_bytes(8, "little"))[0]
        if _reasonable_float(d):
            out.append(f"as IEEE-754 float64: {d!r}")

    # Timestamps
    if _UNIX_MIN <= value <= _UNIX_MAX:
        ts = _fmt(value)
        if ts:
            out.append(f"as Unix time (seconds): {ts}")
    if _UNIX_MIN * 1000 <= value <= _UNIX_MAX * 1000:
        ts = _fmt(value / 1000)
        if ts:
            out.append(f"as Unix time (milliseconds): {ts}")
    if _FILETIME_MIN <= value <= _FILETIME_MAX:
        ts = _fmt(value / 1e7 - 11644473600)
        if ts:
            out.append(f"as Windows FILETIME: {ts}")

    # Compiler division magic
    dm = _DIV_MAGIC.get(value)
    if dm:
        out.append(dm)

    # Prime / parity hints (only for modest magnitudes to stay fast)
    if 2 <= value < (1 << 64):
        if util.is_prime(value):
            out.append("is prime")
        elif value & 1 == 0:
            out.append("even")

    # Pointer-ish hint: high byte zero in a 64-bit-looking value.
    if value > util.mask(32) and (value >> 56) == 0:
        out.append("note: top byte is zero (possibly a masked / 56-bit value "
                   "or user-mode pointer)")

    return out
