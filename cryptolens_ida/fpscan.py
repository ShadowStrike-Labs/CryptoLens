"""Scan IDB segments for crypto fingerprints and high-entropy regions."""
from __future__ import annotations

from typing import List

from cryptolens import entropy, fingerprints

from .ida_shim import (HAVE_IDA, ida_bytes, ida_ua, idaapi, idautils, msg)
from .scanners import Finding, iter_segments


def scan_fingerprints() -> List[Finding]:
    out: List[Finding] = []
    for name, start, end, is_exec, data in iter_segments():
        for h in fingerprints.scan_bytes(data, base=start):
            out.append(Finding(
                ea=h.offset, category="fingerprint",
                title=f"{h.category}: {h.needle}",
                detail=f"{h.note} ({h.encoding}) in {name}",
                confidence=1.0, bucket="high"))
        if is_exec:
            out += _scan_calg(start, end)
    return out


def _scan_calg(start: int, end: int) -> List[Finding]:
    """Find CryptoAPI CALG_* ids used as instruction immediates."""
    out: List[Finding] = []
    for ea in idautils.Heads(start, end):
        if not ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
            continue
        insn = ida_ua.insn_t()
        if idaapi.decode_insn(insn, ea) <= 0:
            continue
        for op in insn.ops:
            if op.type == ida_ua.o_imm:
                nm = fingerprints.calg_name(op.value)
                if nm:
                    out.append(Finding(
                        ea=ea, category="fingerprint",
                        title=f"CryptoAPI {nm}",
                        detail=f"ALG_ID 0x{op.value:X} immediate",
                        confidence=0.9, bucket="high",
                        value=op.value & 0xFFFFFFFF, width=32))
    return out


def scan_entropy(threshold: float = 7.2) -> List[Finding]:
    out: List[Finding] = []
    for name, start, end, is_exec, data in iter_segments():
        for r in entropy.high_entropy_regions(data, base=start, threshold=threshold):
            out.append(Finding(
                ea=r.start, category="entropy",
                title=f"high-entropy region ({r.avg_entropy:.2f} bits/byte)",
                detail=f"0x{r.start:X}-0x{r.end:X} ({r.size} bytes) in {name}",
                confidence=min(1.0, (r.avg_entropy - 6.5) / 1.5),
                bucket="medium"))
    return out


def scan_all() -> List[Finding]:
    msg("[CryptoLens] scanning library/key fingerprints and high-entropy regions...\n")
    out = scan_fingerprints() + scan_entropy()
    out.sort(key=lambda f: (f.category, -f.confidence, f.ea))
    msg(f"[CryptoLens] Fingerprint/entropy findings: {len(out)}.\n")
    return out
