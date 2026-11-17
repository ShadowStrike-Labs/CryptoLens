"""Debugger memory scan: recover runtime keys/tables/states from live memory.

Only useful during an active debug session.  It walks the process memory map
and feeds each (by default writable) region to the testable core:

* AES key schedules  -> recovered key bytes (cryptolens.memfind.find_aes_keys)
* RC4 states         -> 256-byte permutations (find_rc4_states)
* ChaCha/Salsa states-> "expand 32-byte k" blocks (find_chacha_states)
* runtime tables     -> AES S-box / CRC / Base64 (tables.detect_tables)
* runtime constants  -> known values (fastscan.scan_buffer)

Keys/states live in writable memory, so restricting to writable regions is both
correct and a large speed-up; pass only_writable=False to scan everything.
"""
from __future__ import annotations

from typing import List, Tuple

from cryptolens import families, familyscan, fastscan, memfind, tables

from .ida_shim import (HAVE_IDA, ida_bytes, ida_dbg, ida_idd, ida_segment,
                       idaapi, idautils, msg)

_SEGPERM_WRITE = 2


def is_debugging() -> bool:
    try:
        return bool(idaapi.is_debugger_on())
    except Exception:
        return False


def _regions() -> List[Tuple[int, int, int]]:
    out: List[Tuple[int, int, int]] = []
    try:
        mi = ida_idd.meminfo_vec_t()
        if ida_dbg.get_memory_info(mi) > 0:
            for r in mi:
                out.append((r.start_ea, r.end_ea, getattr(r, "perm", 0)))
            return out
    except Exception:
        pass
    for ea in idautils.Segments():
        seg = ida_segment.getseg(ea)
        if seg is not None:
            out.append((seg.start_ea, seg.end_ea, seg.perm))
    return out


def scan_memory(only_writable: bool = True, max_region: int = 16 * 1024 * 1024,
                do_aes: bool = True, do_rc4: bool = True, do_chacha: bool = True,
                do_tables: bool = True, do_constants: bool = True):
    """Scan live memory. Returns a list of Finding objects."""
    from .scanners import Finding

    findings: List[Finding] = []
    regions = _regions()
    msg(f"[CryptoLens] memory scan over {len(regions)} region(s)...\n")
    for start, end, perm in regions:
        size = end - start
        if size <= 0 or size > max_region:
            continue
        if only_writable and not (perm & _SEGPERM_WRITE):
            continue
        data = ida_bytes.get_bytes(start, size)
        if not data:
            continue

        if do_aes:
            for h in memfind.find_aes_keys(data, base=start):
                findings.append(Finding(
                    ea=h.offset, category="memory",
                    title=f"AES-{h.key_size * 8} key schedule",
                    detail=f"recovered key = {h.key_hex}",
                    confidence=1.0, bucket="high", value=None))
        if do_rc4:
            for h in memfind.find_rc4_states(data, base=start):
                findings.append(Finding(
                    ea=h.offset, category="memory",
                    title="RC4 state (256-byte permutation)",
                    detail="permutation of 0..255 in writable memory",
                    confidence=0.8, bucket="medium"))
        if do_chacha:
            for h in memfind.find_chacha_states(data, base=start):
                findings.append(Finding(
                    ea=h.offset, category="memory",
                    title="ChaCha/Salsa state",
                    detail="'expand 32-byte k' block", confidence=1.0,
                    bucket="high"))
        if do_tables:
            for h in tables.detect_tables(data, base=start):
                findings.append(Finding(
                    ea=h.offset, category="memory",
                    title=f"runtime table: {h.name}", detail=h.note,
                    confidence=h.confidence,
                    bucket=("high" if h.confidence >= 0.85 else "medium")))
        if do_constants:
            for h in familyscan.scan_buffer(data, base=start):
                findings.append(Finding(
                    ea=h.offset, category="memory",
                    title=f"runtime family: {h.name}", detail=h.evidence,
                    confidence=h.score, bucket=h.bucket, width=h.width))
            for h in fastscan.scan_buffer(data, base=start, aligned=True):
                if h.bucket != "high" or families.memberships(h.value, h.width):
                    continue
                findings.append(Finding(
                    ea=h.offset, category="memory", title=f"runtime constant: {h.summary}",
                    detail=f"{h.width}-bit", confidence=h.confidence,
                    bucket=h.bucket, value=h.value, width=h.width))

    findings.sort(key=lambda f: (-f.confidence, f.ea))
    msg(f"[CryptoLens] memory scan: {len(findings)} finding(s).\n")
    return findings
