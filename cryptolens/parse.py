"""Parsing user input for the lookup panel and interpreting raw values.

Accepts hex (0x..), decimal, binary (0b..), or a quoted/byte string, and offers
ASCII/endian interpretations so the panel can spot things like the ChaCha
"expand 32-byte k" sigma words that appear as 32-bit integers.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

from . import util


@dataclass
class ParsedInput:
    kind: str                 # "int" or "bytes"
    value: Optional[int] = None
    data: Optional[bytes] = None
    text: str = ""


def parse_token(s: str) -> ParsedInput:
    """Parse a single token into an int or a byte string."""
    s = s.strip()
    if not s:
        raise ValueError("empty input")
    # Quoted string -> bytes
    if len(s) >= 2 and s[0] in "'\"" and s[-1] == s[0]:
        return ParsedInput("bytes", data=s[1:-1].encode("latin-1", "ignore"), text=s)
    low = s.lower().replace("_", "")
    try:
        if low.startswith("0x"):
            return ParsedInput("int", value=int(low, 16), text=s)
        if low.startswith("0b"):
            return ParsedInput("int", value=int(low, 2), text=s)
        if low.startswith("0o"):
            return ParsedInput("int", value=int(low, 8), text=s)
        # Bare hex if it has a-f, else decimal
        if any(c in "abcdef" for c in low):
            return ParsedInput("int", value=int(low, 16), text=s)
        return ParsedInput("int", value=int(low, 10), text=s)
    except ValueError:
        pass
    # Hex byte blob like "de ad be ef" or "deadbeef"
    compact = s.replace(" ", "").replace(",", "").replace("\\x", "")
    if compact and all(c in "0123456789abcdefABCDEF" for c in compact) and len(compact) % 2 == 0:
        return ParsedInput("bytes", data=bytes.fromhex(compact), text=s)
    raise ValueError(f"could not parse: {s!r}")


def natural_width(value: int) -> int:
    """Smallest standard width (8/16/32/64/128) that holds ``value``."""
    for w in (8, 16, 32, 64, 128):
        if value <= util.mask(w):
            return w
    return 256


def ascii_of(value: int, width: int) -> List[Tuple[str, str]]:
    """Printable ASCII interpretations (little/big endian) of ``value``."""
    if width % 8 or width > 64:
        return []
    nbytes = width // 8
    out = []
    for order in ("little", "big"):
        raw = value.to_bytes(nbytes, order)
        if all(32 <= b < 127 for b in raw):
            out.append((order, raw.decode("ascii")))
    return out
