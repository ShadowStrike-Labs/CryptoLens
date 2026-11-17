"""Read IDB segments and instructions for CryptoLens scan passes.

The module emits :class:`Finding` records for hardware instructions, lookup
tables, constant families, standalone constants, and instruction immediates.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from cryptolens import engine, families, familyscan, fastscan, signatures, tables

from .ida_shim import (HAVE_IDA, ida_bytes, ida_funcs, ida_segment, ida_ua,
                       idaapi, idautils, msg)


@dataclass
class Finding:
    ea: int
    category: str
    title: str
    detail: str = ""
    confidence: float = 1.0
    bucket: str = "high"
    func: str = ""
    value: Optional[int] = None
    width: int = 0

    def to_row(self) -> List[str]:
        addr = f"0x{self.ea:X}" if self.ea else "-"
        val = f"0x{self.value:X}" if self.value is not None else ""
        return [addr, self.category, f"{self.confidence:.2f}",
                self.title, val, self.func, self.detail]


COLUMNS = ["Address", "Kind", "Score", "Finding", "Value", "Function", "Detail"]

# x86/x64 crypto-relevant mnemonics (matched case-insensitively, prefix-aware).
CRYPTO_MNEMONICS: Dict[str, str] = {
    "aesenc": "AES-NI encryption round",
    "aesenclast": "AES-NI final encryption round",
    "aesdec": "AES-NI decryption round",
    "aesdeclast": "AES-NI final decryption round",
    "aesimc": "AES-NI inverse mix columns",
    "aeskeygenassist": "AES-NI key schedule assist",
    "sha1rnds4": "SHA-NI SHA-1 rounds",
    "sha1nexte": "SHA-NI SHA-1 next-e",
    "sha1msg1": "SHA-NI SHA-1 message schedule",
    "sha1msg2": "SHA-NI SHA-1 message schedule",
    "sha256rnds2": "SHA-NI SHA-256 rounds",
    "sha256msg1": "SHA-NI SHA-256 message schedule",
    "sha256msg2": "SHA-NI SHA-256 message schedule",
    "pclmulqdq": "carry-less multiply (GCM / CRC)",
    "crc32": "SSE4.2 CRC-32C instruction",
    "rdrand": "hardware RNG (RDRAND)",
    "rdseed": "hardware RNG (RDSEED)",
}


def iter_segments() -> Iterable[Tuple[str, int, int, bool, bytes]]:
    """Yield (name, start, end, is_exec, data) for each segment."""
    for ea in idautils.Segments():
        seg = ida_segment.getseg(ea)
        if seg is None:
            continue
        name = ida_segment.get_segm_name(seg)
        size = seg.end_ea - seg.start_ea
        if size <= 0 or size > 256 * 1024 * 1024:
            continue
        data = ida_bytes.get_bytes(seg.start_ea, size) or b""
        is_exec = bool(seg.perm & ida_segment.SEGPERM_EXEC)
        yield name, seg.start_ea, seg.end_ea, is_exec, data


def scan_data_constants(min_bucket: str = "high", segments=None) -> List[Finding]:
    rank = {"low": 0, "medium": 1, "high": 2}
    threshold = rank.get(min_bucket, 2)
    out: List[Finding] = []
    for name, start, end, is_exec, data in (segments if segments is not None
                                                   else iter_segments()):
        # Executable bytes are handled as decoded immediates/family clusters;
        # interpreting opcodes as aligned raw words creates duplicate noise.
        if is_exec:
            continue
        for hit in fastscan.scan_buffer(data, base=start, aligned=True):
            if families.memberships(hit.value, hit.width):
                continue  # promoted only by corroborated family scan
            if rank.get(hit.bucket, 0) < threshold:
                continue
            out.append(Finding(
                ea=hit.offset, category="constant", title=hit.summary,
                detail=f"{hit.width}-bit value in {name}",
                confidence=hit.confidence,
                bucket=hit.bucket, value=hit.value, width=hit.width,
                func=_func_name(hit.offset),
            ))
    return out


def scan_constant_families(segments=None) -> List[Finding]:
    """Find ordered/co-located families, even without valid functions."""
    out: List[Finding] = []
    seen = set()
    for name, start, end, is_exec, data in (segments if segments is not None
                                                   else iter_segments()):
        for hit in familyscan.scan_buffer(data, base=start):
            key = (hit.family_id, hit.offset)
            if key in seen:
                continue
            seen.add(key)
            out.append(Finding(
                ea=hit.offset, category="family", title=hit.name,
                detail=f"{hit.evidence}; {hit.source}; segment {name}",
                confidence=hit.score, bucket=hit.bucket,
                func=_func_name(hit.offset), width=hit.width,
            ))
    return out


def scan_tables(segments=None) -> List[Finding]:
    out: List[Finding] = []
    for name, start, end, is_exec, data in (segments if segments is not None
                                                   else iter_segments()):
        for hit in tables.detect_tables(data, base=start):
            out.append(Finding(
                ea=hit.offset, category="table", title=hit.name,
                detail=hit.note or name, confidence=hit.confidence,
                bucket=("high" if hit.confidence >= 0.85 else "medium"),
                func=_func_name(hit.offset),
            ))
    return out


def _func_name(ea: int) -> str:
    if not HAVE_IDA:
        return ""
    f = ida_funcs.get_func(ea)
    if f is None:
        return ""
    return ida_funcs.get_func_name(f.start_ea) or ""


def _dtype_width(op) -> int:
    mapping = {
        getattr(ida_ua, "dt_byte", 0): 8,
        getattr(ida_ua, "dt_word", 1): 16,
        getattr(ida_ua, "dt_dword", 2): 32,
        getattr(ida_ua, "dt_qword", 7): 64,
    }
    return mapping.get(op.dtype, 32)


def _iter_code_heads():
    # Do not call iter_segments(): code traversal needs no bulk get_bytes().
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if seg is None or not (seg.perm & ida_segment.SEGPERM_EXEC):
            continue
        for ea in idautils.Heads(seg.start_ea, seg.end_ea):
            if ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
                yield ea


@dataclass(frozen=True)
class CodeRecord:
    ea: int
    mnem: str
    immediates: Tuple[Tuple[int, int], ...]  # (width, value)


def collect_code_records() -> List[CodeRecord]:
    """Decode executable heads once for all code-oriented scan passes."""
    records: List[CodeRecord] = []
    for ea in _iter_code_heads():
        insn = ida_ua.insn_t()
        if idaapi.decode_insn(insn, ea) <= 0:
            continue
        immediates = []
        for op in insn.ops:
            if op.type != ida_ua.o_imm:
                continue
            width = _dtype_width(op)
            if width not in (8, 16, 32, 64):
                width = 32
            immediates.append((width, op.value & ((1 << width) - 1)))
        records.append(CodeRecord(
            ea, (ida_ua.print_insn_mnem(ea) or "").lower(), tuple(immediates)))
    return records


def scan_code_families(code_records=None) -> List[Finding]:
    """Correlate immediates per function or sliding code window.

    The 4-KiB fallback also covers binaries with missing or incorrect function
    boundaries.
    """
    func_groups = {}
    orphan_events = []
    records = code_records if code_records is not None else collect_code_records()
    for record in records:
        ea = record.ea
        func = ida_funcs.get_func(ea)
        events = (func_groups.setdefault(func.start_ea, [])
                  if func else orphan_events)
        for width, value in record.immediates:
            if width not in (32, 64):
                width = 32
                value &= 0xFFFFFFFF
            events.append((ea, width, value))

    matches = []
    for events in func_groups.values():
        for width in (32, 64):
            selected = [(ea, value) for ea, w, value in events if w == width]
            if not selected:
                continue
            for match in families.match_values((v for _, v in selected), width):
                loc = min(ea for ea, value in selected
                          if value in set(match.matched))
                matches.append(families.FamilyMatch(
                    match.family_id, match.name, match.width, match.matched,
                    match.score, match.evidence + " within one IDA function",
                    loc, "cluster", match.source,
                ))
    matches.extend(familyscan.scan_events(orphan_events, window=0x1000))

    out: List[Finding] = []
    seen = set()
    for match in matches:
        key = (match.family_id, match.offset)
        if key in seen:
            continue
        seen.add(key)
        out.append(Finding(
            ea=match.offset, category="family", title=match.name,
            detail=f"{match.evidence}; {match.source}",
            confidence=match.score, bucket=match.bucket,
            func=_func_name(match.offset), width=match.width,
        ))
    return out


def scan_code_immediates(min_conf: float = 0.5, code_records=None) -> List[Finding]:
    """Run instruction immediates through the conservative lookup engine."""
    out: List[Finding] = []
    seen = set()
    records = code_records if code_records is not None else collect_code_records()
    for record in records:
        ea = record.ea
        for width, value in record.immediates:
            if value < 0x100:
                continue
            widths = {width}
            if width < 32:
                widths.add(32)
            for w in widths:
                for e in engine.explain(value, w):
                    if e.kind == "exact" and not e.algorithms:
                        continue  # bare mathematics is a lookup hint, not scan evidence
                    if families.memberships(value, w):
                        continue  # family members require co-occurrence
                    confidence = e.confidence
                    if e.kind in ("named", "transform"):
                        strength = signatures.automatic_strength(value, w)
                        if w % 8 == 0:
                            strength = max(
                                strength,
                                signatures.automatic_strength(
                                    int.from_bytes(value.to_bytes(w // 8, "little"), "big"), w
                                ) - 0.12,
                            )
                        confidence = min(confidence, max(0.0, strength))
                    if confidence < min_conf:
                        continue
                    bucket = ("high" if confidence >= 0.85 else
                              "medium" if confidence >= 0.60 else "low")
                    key = (ea, value, e.summary)
                    if key in seen:
                        continue
                    seen.add(key)
                    detail = "; ".join(x for x in (e.recipe, e.detail) if x)
                    out.append(Finding(
                        ea=ea, category="immediate", title=e.summary,
                        detail=detail, confidence=round(confidence, 3),
                        bucket=bucket, value=value, width=w,
                        func=_func_name(ea),
                    ))
    return out


def scan_crypto_instructions(code_records=None) -> List[Finding]:
    out: List[Finding] = []
    records = code_records if code_records is not None else collect_code_records()
    for record in records:
        ea = record.ea
        mnem = record.mnem
        if not mnem:
            continue
        key = mnem[1:] if (mnem.startswith("v") and mnem[1:] in CRYPTO_MNEMONICS) else mnem
        desc = CRYPTO_MNEMONICS.get(key)
        if desc is None:
            continue
        out.append(Finding(
            ea=ea, category="instruction", title=f"{mnem} - {desc}",
            detail="hardware crypto instruction", confidence=1.0,
            bucket="high", func=_func_name(ea),
        ))
    return out


_CATEGORY_ORDER = {"instruction": 0, "table": 1, "family": 2,
                   "constant": 3, "immediate": 4}


def run_all(data_constants: bool = True, do_tables: bool = True,
            immediates: bool = True, instructions: bool = True,
            min_bucket: str = "high") -> List[Finding]:
    findings: List[Finding] = []

    # Decode instructions once, then feed the same immutable records to all
    # three code passes (hardware opcodes, families, standalone values).
    code_records = (collect_code_records()
                    if (instructions or immediates) else None)
    if instructions:
        msg("[CryptoLens] scanning crypto instructions...\n")
        findings += scan_crypto_instructions(code_records)

    # Read each segment once and run all byte-oriented passes while its data is
    # in memory; this avoids three IDA get_bytes() calls per segment.
    if do_tables or data_constants:
        if do_tables:
            msg("[CryptoLens] scanning known tables...\n")
        if data_constants:
            msg("[CryptoLens] scanning corroborated constant families and "
                "strong standalone constants...\n")
        for segment in iter_segments():
            one = (segment,)
            if do_tables:
                findings += scan_tables(one)
            if data_constants:
                findings += scan_constant_families(one)
                findings += scan_data_constants(min_bucket=min_bucket,
                                                 segments=one)

    if immediates:
        msg("[CryptoLens] correlating code constants by function/sliding window...\n")
        findings += scan_code_families(code_records)
        msg("[CryptoLens] scanning strong standalone immediates/variants...\n")
        min_conf = {"high": 0.85, "medium": 0.5, "low": 0.4}.get(min_bucket, 0.5)
        findings += scan_code_immediates(min_conf=min_conf,
                                         code_records=code_records)
    rank = {"low": 0, "medium": 1, "high": 2}
    cutoff = rank.get(min_bucket, 2)
    findings = [f for f in findings if rank.get(f.bucket, 0) >= cutoff]
    findings.sort(key=lambda f: (_CATEGORY_ORDER.get(f.category, 9),
                                 -f.confidence, f.ea))
    msg(f"[CryptoLens] Findings: {len(findings)}.\n")
    return findings
