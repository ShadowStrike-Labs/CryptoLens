"""Resolve API-name hashes and apply IDA enum members.

The resolver fingerprints a hash scheme from function features, maps immediate
values to candidate API names, and optionally creates an IDA enum and operand
annotations. Enum updates are isolated so resolution still completes when an
IDA version rejects a mutation call.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Dict, List, Optional, Tuple

from cryptolens import apihash, structure

from . import funcscan
from .ida_shim import (HAVE_IDA, ida_bytes, ida_funcs, ida_ua, idaapi,
                       idautils, idc, msg)

_ENUM_NAME = "CryptoLens_apihash"


def _sanitize(name: str) -> str:
    s = re.sub(r"[^0-9A-Za-z_]", "_", name)
    if s and s[0].isdigit():
        s = "_" + s
    return s or "api"


def _collect_imms(func) -> Dict[int, List[Tuple[int, int]]]:
    out: Dict[int, List[Tuple[int, int]]] = {}
    for ea in idautils.FuncItems(func.start_ea):
        insn = ida_ua.insn_t()
        if idaapi.decode_insn(insn, ea) <= 0:
            continue
        for i, op in enumerate(insn.ops):
            if op.type == ida_ua.o_imm:
                out.setdefault(op.value & 0xFFFFFFFFFFFFFFFF, []).append((ea, i))
    return out


def _make_enum(members: Dict[str, int]) -> Optional[int]:
    """Create/extend the CryptoLens enum. Returns enum id or None."""
    eid = None
    try:
        eid = idc.get_enum(_ENUM_NAME)
    except Exception:
        eid = None
    bad = getattr(idaapi, "BADADDR", 0xFFFFFFFFFFFFFFFF)
    if eid in (None, bad, -1):
        try:
            eid = idc.add_enum(bad, _ENUM_NAME, 0)
        except Exception:
            return None
    if eid in (None, bad, -1):
        return None
    for mname, val in members.items():
        try:
            idc.add_enum_member(eid, mname, val & 0xFFFFFFFF, bad)
        except Exception:
            pass
    return eid


def _apply_operand(ea: int, opn: int, eid: int) -> None:
    try:
        idc.op_enum(ea, opn, eid, 0)
    except Exception:
        pass


def _comment(ea: int, text: str) -> None:
    try:
        existing = ida_bytes.get_cmt(ea, False) or ""
        if text in existing:
            return
        merged = (existing + " | " if existing else "") + text
        ida_bytes.set_cmt(ea, merged, False)
    except Exception:
        pass


def _resolve_values(values, schemes):
    """When no scheme is known, retain schemes supported by two or more hits."""
    hits = apihash.resolve(values, schemes if schemes else None)
    if not schemes and hits:
        votes = Counter(h.scheme for h in hits)
        inferred = [s for s, c in votes.items() if c >= 2]
        if inferred:
            hits = [h for h in hits if h.scheme in inferred]
            return hits, inferred
    return hits, schemes


def resolve_in_function(func_ea: int, create_enum: bool = True,
                        apply_operands: bool = True, do_comment: bool = True):
    """Resolve hashed API names in one function. Returns (report_text, hits)."""
    func = ida_funcs.get_func(func_ea)
    if func is None:
        return "cursor is not inside a function", []

    feats = funcscan.extract_features(func_ea)
    schemes = [s for s, _ in structure.detect_hash_schemes(feats)]
    imm_addrs = _collect_imms(func)
    values = set(imm_addrs) | set(feats.constants)

    hits, schemes = _resolve_values(values, schemes)
    uniq = {}
    for h in hits:
        uniq[(h.value, h.name, h.scheme)] = h
    hits = list(uniq.values())

    fname = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:X}"
    lines = [f"CryptoLens - API-hash resolution", f"  {fname} @ 0x{func.start_ea:X}"]
    lines.append(f"  scheme(s): {', '.join(schemes) if schemes else 'inferred/none'}")
    if not hits:
        lines.append("  no hashed API names resolved.")
        return "\n".join(lines), []

    members = {}
    resolved_values = set()
    for h in hits:
        members[_sanitize(h.name)] = h.value
        resolved_values.add(h.value & 0xFFFFFFFF)

    eid = _make_enum(members) if create_enum else None
    applied = 0
    for value, addrs in imm_addrs.items():
        if (value & 0xFFFFFFFF) not in resolved_values:
            continue
        names = sorted({h.name for h in hits if h.value == (value & 0xFFFFFFFF)})
        for ea, opn in addrs:
            if eid is not None and apply_operands:
                _apply_operand(ea, opn, eid)
            if do_comment:
                _comment(ea, "CryptoLens: " + " / ".join(names))
            applied += 1

    lines.append(f"  names resolved: {len(hits)}; operands relabeled: {applied}"
                 + (f"; enum '{_ENUM_NAME}'" if eid is not None else ""))
    for h in sorted(hits, key=lambda x: x.name):
        v = f" ({h.variant})" if h.variant else ""
        lines.append(f"    0x{h.value:08X} = {h.scheme}(\"{h.name}\"{v})")
    return "\n".join(lines), hits


def resolve_in_binary(create_enum: bool = True, apply_operands: bool = True):
    """Resolve hashed API names across every function. Returns (text, findings)."""
    from .scanners import Finding

    all_members: Dict[str, int] = {}
    per_func = []
    total_hits = 0
    for fea in idautils.Functions():
        func = ida_funcs.get_func(fea)
        if func is None:
            continue
        feats = funcscan.extract_features(fea)
        schemes = [s for s, _ in structure.detect_hash_schemes(feats)]
        imm_addrs = _collect_imms(func)
        values = set(imm_addrs) | set(feats.constants)
        hits, schemes = _resolve_values(values, schemes)
        if not hits:
            continue
        uniq = {(h.value, h.name, h.scheme): h for h in hits}
        hits = list(uniq.values())
        total_hits += len(hits)
        for h in hits:
            all_members[_sanitize(h.name)] = h.value
        per_func.append((func.start_ea,
                         ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:X}",
                         hits, imm_addrs))

    eid = _make_enum(all_members) if (create_enum and all_members) else None
    findings = []
    for fea, fname, hits, imm_addrs in per_func:
        resolved_values = {h.value & 0xFFFFFFFF for h in hits}
        for value, addrs in imm_addrs.items():
            if (value & 0xFFFFFFFF) not in resolved_values:
                continue
            names = sorted({h.name for h in hits if h.value == (value & 0xFFFFFFFF)})
            for ea, opn in addrs:
                if eid is not None and apply_operands:
                    _apply_operand(ea, opn, eid)
                _comment(ea, "CryptoLens: " + " / ".join(names))
        top = sorted(hits, key=lambda x: x.name)
        findings.append(Finding(
            ea=fea, category="apihash",
            title=f"API-hash resolver (matches: {len(hits)})",
            detail=", ".join(h.name for h in top[:4]) + (" ..." if len(top) > 4 else ""),
            confidence=0.95, bucket="high", func=fname))

    msg(f"[CryptoLens] API-hash matches: {total_hits}; "
        f"functions: {len(findings)}.\n")
    text = (f"API-hash matches: {total_hits}; "
            f"functions: {len(findings)}.")
    return text, findings
