"""Binary scanners that feed IDB bytes/instructions into the testable core.

Produces a flat list of :class:`Finding` objects consumed by the results
chooser and the annotator.  Four passes:

* data constants   - aligned 32/64-bit words matched against known values
* known tables     - AES S-box, CRC tables, Base64 alphabets, custom alphabets
* code immediates  - instruction immediates run through the full engine
                     (this is where golden-ratio-*variant* detection happens)
* crypto CPU insns - AES-NI / SHA-NI / PCLMULQDQ / CRC32 / RDRAND mnemonics
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from cryptolens import engine, fastscan, tables

from .ida_shim import (HAVE_IDA, ida_bytes, ida_funcs, ida_segment, ida_ua,
                       idaapi, idautils, msg)


@dataclass
class Finding:
    ea: int
    category: str              # "constant" | "table" | "immediate" | "instruction"
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


def scan_data_constants(min_bucket: str = "high") -> List[Finding]:
    rank = {"low": 0, "medium": 1, "high": 2}
    threshold = rank.get(min_bucket, 2)
    out: List[Finding] = []
    for name, start, end, is_exec, data in iter_segments():
        for hit in fastscan.scan_buffer(data, base=start, aligned=True):
            if rank.get(hit.bucket, 0) < threshold:
                continue
            out.append(Finding(
                ea=hit.offset, category="constant", title=hit.summary,
                detail=f"{hit.width}-bit value in {name}",
                confidence=1.0 if hit.bucket == "high" else 0.6,
                bucket=hit.bucket, value=hit.value, width=hit.width,
                func=_func_name(hit.offset),
            ))
    return out


def scan_tables() -> List[Finding]:
    out: List[Finding] = []
    for name, start, end, is_exec, data in iter_segments():
        for hit in tables.detect_tables(data, base=start):
            out.append(Finding(
                ea=hit.offset, category="table", title=hit.title,
                detail=hit.note or name, confidence=1.0, bucket="high",
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
    for name, start, end, is_exec, _data in iter_segments():
        if not is_exec:
            continue
        for ea in idautils.Heads(start, end):
            if ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
                yield ea


def scan_code_immediates(min_conf: float = 0.5) -> List[Finding]:
    """Run instruction immediates through the full engine (variants included)."""
    out: List[Finding] = []
    seen = set()
    for ea in _iter_code_heads():
        insn = ida_ua.insn_t()
        if idaapi.decode_insn(insn, ea) <= 0:
            continue
        for op in insn.ops:
            if op.type != ida_ua.o_imm:
                continue
            width = _dtype_width(op)
            value = op.value & ((1 << width) - 1)
            if value < 0x100:
                continue
            widths = {width}
            if width < 32:
                widths.add(32)
            for w in widths:
                for e in engine.explain(value, w):
                    if e.confidence < min_conf:
                        continue
                    if e.kind in ("exact",) and not e.algorithms:
                        # a bare math-constant immediate with no algo context
                        # is weak on its own; keep only medium+ variants/named
                        pass
                    key = (ea, value, e.summary)
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append(Finding(
                        ea=ea, category="immediate", title=e.summary,
                        detail=(e.recipe or e.detail),
                        confidence=e.confidence, bucket=e.bucket,
                        value=value, width=w, func=_func_name(ea),
                    ))
    return out


def scan_crypto_instructions() -> List[Finding]:
    out: List[Finding] = []
    for ea in _iter_code_heads():
        mnem = ida_ua.print_insn_mnem(ea).lower()
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


_CATEGORY_ORDER = {"instruction": 0, "table": 1, "constant": 2, "immediate": 3}


def run_all(data_constants: bool = True, do_tables: bool = True,
            immediates: bool = True, instructions: bool = True,
            min_bucket: str = "high") -> List[Finding]:
    findings: List[Finding] = []
    if instructions:
        msg("[CryptoLens] scanning crypto instructions...\n")
        findings += scan_crypto_instructions()
    if do_tables:
        msg("[CryptoLens] scanning known tables...\n")
        findings += scan_tables()
    if data_constants:
        msg("[CryptoLens] scanning data constants...\n")
        findings += scan_data_constants(min_bucket=min_bucket)
    if immediates:
        msg("[CryptoLens] scanning code immediates (variants)...\n")
        min_conf = {"high": 0.85, "medium": 0.5, "low": 0.4}.get(min_bucket, 0.5)
        findings += scan_code_immediates(min_conf=min_conf)
    findings.sort(key=lambda f: (_CATEGORY_ORDER.get(f.category, 9),
                                 -f.confidence, f.ea))
    msg(f"[CryptoLens] {len(findings)} finding(s).\n")
    return findings
