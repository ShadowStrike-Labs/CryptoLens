"""Compute Shannon entropy and merge adjacent high-entropy blocks.

Entropy is reported in bits per byte (0..8). High entropy can indicate
encrypted, compressed, or packed data, but does not identify an algorithm.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import List, Tuple


def shannon(buf: bytes) -> float:
    """Shannon entropy of ``buf`` in bits per byte (0..8)."""
    if not buf:
        return 0.0
    counts = [0] * 256
    for b in buf:
        counts[b] += 1
    n = len(buf)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def entropy_map(buf: bytes, block: int = 256) -> List[Tuple[int, float]]:
    """Per-block entropy as a list of (offset, entropy)."""
    out = []
    for off in range(0, len(buf), block):
        chunk = buf[off:off + block]
        if len(chunk) < max(16, block // 4):
            break
        out.append((off, shannon(chunk)))
    return out


@dataclass
class EntropyRegion:
    start: int
    end: int
    avg_entropy: float

    @property
    def size(self) -> int:
        return self.end - self.start


def high_entropy_regions(buf: bytes, base: int = 0, block: int = 512,
                         threshold: float = 7.2,
                         min_blocks: int = 4) -> List[EntropyRegion]:
    """Merge consecutive high-entropy blocks into regions."""
    regions: List[EntropyRegion] = []
    run_start = None
    run_vals: List[float] = []
    off = 0
    n = len(buf)
    while off < n:
        chunk = buf[off:off + block]
        if len(chunk) < max(16, block // 4):
            break
        h = shannon(chunk)
        if h >= threshold:
            if run_start is None:
                run_start = off
                run_vals = []
            run_vals.append(h)
        else:
            if run_start is not None and len(run_vals) >= min_blocks:
                regions.append(EntropyRegion(base + run_start, base + off,
                                             sum(run_vals) / len(run_vals)))
            run_start = None
            run_vals = []
        off += block
    if run_start is not None and len(run_vals) >= min_blocks:
        regions.append(EntropyRegion(base + run_start, base + off,
                                     sum(run_vals) / len(run_vals)))
    return regions
