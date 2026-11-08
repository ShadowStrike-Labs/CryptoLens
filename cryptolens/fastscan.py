"""Fast exact-value scanning over a raw byte buffer (IDA-independent).

Variant/fuzzy detection is expensive, so it is reserved for instruction
immediates (few in number, handled by the IDA layer).  For bulk *data*
scanning we test each aligned 32/64-bit word against a precomputed membership
set of every anchor and signature value plus their byte-swapped forms, then run
the full engine only on the handful of hits to produce a rich label.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Dict, FrozenSet, List

from . import constants, engine, signatures, util


@lru_cache(maxsize=None)
def _members(width: int) -> FrozenSet[int]:
    vals = set()
    for (w, v), _anchors in constants.anchor_table().items():
        if w == width:
            vals.add(v)
    for (w, v), _sigs in signatures._index().items():
        if w == width:
            vals.add(v)
    # include byte-swapped forms (common storage variant)
    if width % 8 == 0:
        vals |= {util.bswap(v, width) for v in list(vals)}
    # drop trivially tiny values that cause data-scan noise
    return frozenset(v for v in vals if v >= 0x100)


@dataclass
class ScanHit:
    offset: int
    value: int
    width: int
    summary: str
    bucket: str


def scan_buffer(buf: bytes, base: int = 0, widths=(32, 64),
                aligned: bool = True) -> List[ScanHit]:
    """Scan ``buf`` for known constant values at the given widths."""
    hits: List[ScanHit] = []
    mv = memoryview(buf)
    n = len(buf)
    for width in widths:
        nbytes = width // 8
        members = _members(width)
        step = nbytes if aligned else 1
        for i in range(0, n - nbytes + 1, step):
            value = int.from_bytes(mv[i:i + nbytes], "little")
            if value in members:
                expls = engine.explain(value, width)
                if expls:
                    top = expls[0]
                    hits.append(ScanHit(base + i, value, width,
                                        top.summary, top.bucket))
    return hits
