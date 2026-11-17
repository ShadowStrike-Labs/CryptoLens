"""Fast exact-value scanning over a raw byte buffer.

This pass reports *individual* curated signatures only. Mathematical anchors
and speculative derivations are intentionally excluded; algorithm-level
promotion comes from :mod:`cryptolens.familyscan`, which requires related
constants to co-occur. This separation keeps broad coverage without noisy bulk
reports.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import FrozenSet, List

from . import engine, signatures, util


@lru_cache(maxsize=None)
def _members(width: int) -> FrozenSet[int]:
    vals = {v for (w, v) in signatures._index() if w == width and v >= 0x100}
    if width % 8 == 0:
        vals |= {util.bswap(v, width) for v in tuple(vals)}
    return frozenset(vals)


@dataclass
class ScanHit:
    offset: int
    value: int
    width: int
    summary: str
    bucket: str
    confidence: float


def _strength(value: int, width: int) -> float:
    direct = signatures.automatic_strength(value, width)
    swapped = signatures.automatic_strength(util.bswap(value, width), width)
    return max(direct, max(0.0, swapped - 0.12))


def scan_buffer(buf: bytes, base: int = 0, widths=(32, 64),
                aligned: bool = True) -> List[ScanHit]:
    """Scan ``buf`` for individual known constants at requested widths."""
    hits: List[ScanHit] = []
    mv = memoryview(buf)
    n = len(buf)
    for width in widths:
        nbytes = width // 8
        members = _members(width)
        step = nbytes if aligned else 1
        first = ((-base) % nbytes) if aligned else 0
        for i in range(first, n - nbytes + 1, step):
            value = int.from_bytes(mv[i:i + nbytes], "little")
            if value not in members:
                continue
            expls = engine.explain(value, width)
            if not expls:
                continue
            top = expls[0]
            confidence = min(top.confidence, _strength(value, width))
            bucket = ("high" if confidence >= 0.85 else
                      "medium" if confidence >= 0.60 else "low")
            hits.append(ScanHit(base + i, value, width, top.summary,
                                bucket, round(confidence, 3)))
    return hits
