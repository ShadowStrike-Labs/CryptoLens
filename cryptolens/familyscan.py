"""Find constant families and ordered constant sequences.

A family match requires related values within a bounded region or an ordered
run. The scanner accepts raw buffers and does not depend on IDA function
boundaries.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import DefaultDict, Iterable, List, Tuple

from . import families


def _sequence_hits(buf: bytes, base: int) -> List[families.FamilyMatch]:
    out: List[families.FamilyMatch] = []
    seen = set()
    for fam in families.specs():
        m = fam.sequence_min
        if m <= 0:
            continue
        size = fam.width // 8
        if len(buf) < size * m:
            continue
        # Search every m-word fragment. bytes.find performs the buffer scan in C.
        starts = range(0, len(fam.values) - m + 1)
        for endian in ("little", "big"):
            for start_idx in starts:
                pattern = b"".join(v.to_bytes(size, endian)
                                   for v in fam.values[start_idx:start_idx + m])
                pos = 0
                while True:
                    off = buf.find(pattern, pos)
                    if off < 0:
                        break
                    run = m
                    while (start_idx + run < len(fam.values)
                           and off + (run + 1) * size <= len(buf)
                           and int.from_bytes(
                               buf[off + run * size:off + (run + 1) * size],
                               endian) == fam.values[start_idx + run]):
                        run += 1
                    key = (fam.family_id, base + off)
                    matched = fam.values[start_idx:start_idx + run]
                    if fam.required_any and not (set(matched) & set(fam.required_any)):
                        pos = off + 1
                        continue
                    if key not in seen:
                        seen.add(key)
                        out.append(families.FamilyMatch(
                            fam.family_id, fam.name, fam.width, tuple(matched),
                            min(1.0, 0.94 + 0.01 * min(run - m, 6)),
                            f"ordered run of {run} constants ({endian}-endian)",
                            base + off, "sequence", fam.source,
                        ))
                    pos = off + max(1, run * size)
    # Merge overlapping runs from the same array.
    merged: List[families.FamilyMatch] = []
    for hit in sorted(out, key=lambda h: (h.family_id, h.offset, -len(h.matched))):
        size = hit.width // 8
        hit_end = hit.offset + len(hit.matched) * size
        if any(old.family_id == hit.family_id
               and old.offset <= hit.offset
               and hit_end <= old.offset + len(old.matched) * size
               for old in merged):
            continue
        merged.append(hit)
    return merged


def scan_events(events: Iterable[Tuple[int, int, int]], window: int = 0x1000,
                base: int = 0) -> List[families.FamilyMatch]:
    """Match positioned ``(offset, width, value)`` events in a sliding window.

    Every qualifying set spanning at most ``window`` bytes is considered.
    """
    grouped: DefaultDict[str, List[Tuple[int, int]]] = defaultdict(list)
    for off, width, value in events:
        for fam, _index in families.memberships(value, width):
            grouped[fam.family_id].append((off, value))

    raw: List[families.FamilyMatch] = []
    for family_id, evs in grouped.items():
        fam = families.by_id()[family_id]
        evs.sort()
        counts: Counter = Counter()
        left = 0
        for right, (right_off, value) in enumerate(evs):
            counts[value] += 1
            while left <= right and right_off - evs[left][0] > window:
                old = evs[left][1]
                counts[old] -= 1
                if counts[old] == 0:
                    del counts[old]
                left += 1
            if len(counts) < fam.min_hits:
                continue
            if fam.required_any and not (set(counts) & set(fam.required_any)):
                continue
            match = next((m for m in families.match_values(counts, fam.width)
                          if m.family_id == family_id), None)
            if match is None:
                continue
            matched_set = set(match.matched)
            loc = min(off for off, val in evs[left:right + 1]
                      if val in matched_set)
            raw.append(families.FamilyMatch(
                match.family_id, match.name, match.width, match.matched,
                match.score, match.evidence + f" within 0x{window:X} bytes",
                base + loc, "cluster", match.source,
            ))

    # Keep one representative for overlapping windows of the same family.
    out: List[families.FamilyMatch] = []
    for hit in sorted(raw, key=lambda h: (-h.score, -len(h.matched), h.offset)):
        if any(old.family_id == hit.family_id
               and abs(old.offset - hit.offset) <= window for old in out):
            continue
        out.append(hit)
    return out


def _cluster_hits(buf: bytes, base: int, window: int) -> List[families.FamilyMatch]:
    events: List[Tuple[int, int, int]] = []
    idx = families.value_index()

    # Suppress constituent dwords of recognized qwords. This prevents
    # SHA-512/SHA-256, SHA-384/SHA-224, and xxHash64/xxHash32 aliases.
    covered_dwords = set()
    # Qword tables may begin at addresses congruent to 4 modulo 8.
    size = 8
    first = (-base) % 4
    for off in range(first, len(buf) - size + 1, 4):
        value = int.from_bytes(buf[off:off + size], "little")
        if (64, value) in idx:
            events.append((off, 64, value))
            covered_dwords.update((off, off + 4))

    size = 4
    first = (-base) % size
    for off in range(first, len(buf) - size + 1, size):
        if off in covered_dwords:
            continue
        value = int.from_bytes(buf[off:off + size], "little")
        if (32, value) in idx:
            events.append((off, 32, value))
    return scan_events(events, window=window, base=base)


def scan_buffer(buf: bytes, base: int = 0, window: int = 0x1000
                ) -> List[families.FamilyMatch]:
    """Find corroborated constant families in a byte buffer."""
    seq = _sequence_hits(buf, base)
    raw_clusters = _cluster_hits(buf, base, window)
    clusters: List[families.FamilyMatch] = []
    for hit in sorted(raw_clusters, key=lambda h: (-h.score, -len(h.matched), h.offset)):
        if any(old.family_id == hit.family_id
               and abs(old.offset - hit.offset) < window for old in clusters):
            continue
        clusters.append(hit)
    # Ordered hits supersede nearby clusters. A 64-bit sequence also
    # supersedes a 32-bit family formed only from its word halves.
    out = list(seq)
    for c in clusters:
        if any(s.family_id == c.family_id and abs(s.offset - c.offset) < window
               for s in seq):
            continue
        alias = False
        if c.width == 32:
            cvals = set(c.matched)
            for s in seq:
                if s.width != 64 or abs(s.offset - c.offset) >= window:
                    continue
                halves = {(v >> 32) & 0xFFFFFFFF for v in s.matched}
                halves |= {v & 0xFFFFFFFF for v in s.matched}
                if cvals and cvals <= halves:
                    alias = True
                    break
        if not alias:
            out.append(c)
    out.sort(key=lambda h: (-h.score, h.offset, h.name))
    return out
