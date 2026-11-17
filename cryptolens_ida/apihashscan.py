"""Resolve API-name hashes and apply IDA enum members.

The resolver fingerprints a hash scheme from function features, maps immediate
values to candidate API names, and optionally creates an IDA enum and operand
annotations. Enum updates are isolated so resolution still completes when an
IDA version rejects a mutation call.
"""
from __future__ import annotations

import re
from typing import Dict, List, Tuple

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


def _add_member(members: Dict[str, Tuple[int, int]],
                hit: apihash.ApiHashHit) -> None:
    name = f"{_sanitize(hit.name)}__{_sanitize(hit.scheme)}"
    if hit.variant:
        name += f"__{_sanitize(hit.variant)}"
    entry = (hit.value, hit.width)
    suffix = 2
    candidate = name
    while candidate in members and members[candidate] != entry:
        candidate = f"{name}_{suffix}"
        suffix += 1
    members[candidate] = entry


def _operand_width(op) -> int:
    mapping = {
        getattr(ida_ua, "dt_byte", 0): 8,
        getattr(ida_ua, "dt_word", 1): 16,
        getattr(ida_ua, "dt_dword", 2): 32,
        getattr(ida_ua, "dt_qword", 7): 64,
    }
    return mapping.get(op.dtype, 32)


def _collect_imms(func) -> Dict[Tuple[int, int], List[Tuple[int, int]]]:
    out: Dict[Tuple[int, int], List[Tuple[int, int]]] = {}
    for ea in idautils.FuncItems(func.start_ea):
        insn = ida_ua.insn_t()
        if idaapi.decode_insn(insn, ea) <= 0:
            continue
        for i, op in enumerate(insn.ops):
            if op.type == ida_ua.o_imm:
                width = _operand_width(op)
                value = op.value & ((1 << width) - 1)
                out.setdefault((value, width), []).append((ea, i))
    return out


def _feature_values(feats):
    if feats is None:
        return set()
    if not feats.constants_by_width:
        return set(feats.constants)
    values = set()
    for width in (32, 64):
        values.update((value, width)
                      for value in feats.constants_for_width(width))
    return values


def _call_result_callees(func, lookahead: int = 8, limit: int = 16):
    """Return direct callees whose results are compared with nearby constants."""
    items = list(idautils.FuncItems(func.start_ea))
    out = []
    seen = set()

    def has_constant(ea: int) -> bool:
        insn = ida_ua.insn_t()
        if idaapi.decode_insn(insn, ea) <= 0:
            return False
        return any(op.type == ida_ua.o_imm and op.value >= 0x10000
                   for op in insn.ops)

    for index, ea in enumerate(items):
        mnem = (ida_ua.print_insn_mnem(ea) or "").lower()
        if not mnem.startswith("call"):
            continue
        callees = []
        for target in idautils.CodeRefsFrom(ea, 0):
            callee = ida_funcs.get_func(target)
            if callee is not None and callee.start_ea != func.start_ea:
                callees.append(callee)
        if not callees:
            continue

        nearby_constant = any(
            has_constant(prev_ea) for prev_ea in items[max(0, index - 4):index])
        compared = False
        for next_ea in items[index + 1:index + 1 + lookahead]:
            next_mnem = (ida_ua.print_insn_mnem(next_ea) or "").lower()
            if next_mnem.startswith("call") or next_mnem.startswith("ret"):
                break
            nearby_constant = nearby_constant or has_constant(next_ea)
            if next_mnem in ("cmp", "test") and nearby_constant:
                compared = True
                break
        if not compared:
            continue
        for callee in callees:
            if callee.start_ea in seen:
                continue
            seen.add(callee.start_ea)
            out.append(callee)
            if len(out) >= limit:
                return out
    return out


def _features(func_ea: int, cache=None):
    if cache is not None and func_ea in cache:
        return cache[func_ea]
    result = funcscan.extract_features(func_ea)
    if cache is not None:
        cache[func_ea] = result
    return result


def _schemes_with_callees(func, cache=None):
    """Detect schemes in a wrapper and its direct internal hash helpers."""
    schemes = []
    sources = []
    candidates = [func] + _call_result_callees(func)
    for candidate in candidates:
        # Hash helpers are normally compact. Avoid decompiling large dispatch or
        # initialization callees during a resolver scan.
        if candidate.start_ea != func.start_ea and candidate.end_ea - candidate.start_ea > 0x2000:
            continue
        feats = _features(candidate.start_ea, cache)
        if feats is None:
            continue
        found = structure.detect_hash_schemes(feats)
        if not found:
            continue
        name = ida_funcs.get_func_name(candidate.start_ea) or f"sub_{candidate.start_ea:X}"
        for scheme, evidence in found:
            if scheme not in schemes:
                schemes.append(scheme)
                sources.append(f"{scheme} in {name}: {evidence}")
    return schemes, sources


def _make_enum(members: Dict[str, Tuple[int, int]]):
    """Return ``(enum_id, accepted_values)`` for requested members."""
    try:
        eid = idc.get_enum(_ENUM_NAME)
    except Exception:
        eid = None
    bad = getattr(idaapi, "BADADDR", 0xFFFFFFFFFFFFFFFF)
    if eid in (None, bad, -1):
        try:
            eid = idc.add_enum(bad, _ENUM_NAME, 0)
        except Exception:
            return None, set()
    if eid in (None, bad, -1):
        return None, set()

    needs_wide = any(width == 64 for _value, width in members.values())
    wide_ready = not needs_wide
    if needs_wide:
        try:
            wide_ready = idc.get_enum_width(eid) == 8
        except Exception:
            wide_ready = False
        if not wide_ready:
            try:
                width_result = idc.set_enum_width(eid, 8)
                wide_ready = bool(width_result)
            except Exception:
                wide_ready = False
            try:
                wide_ready = wide_ready or idc.get_enum_width(eid) == 8
            except Exception:
                pass

    accepted = set()
    for member_name, (value, width) in members.items():
        if width == 64 and not wide_ready:
            continue
        try:
            existing = idc.get_enum_member(eid, value, 0, bad)
        except Exception:
            existing = bad
        if existing not in (None, bad, -1):
            accepted.add((value, width))
            continue
        try:
            result = idc.add_enum_member(eid, member_name, value, bad)
        except Exception:
            continue
        success = (result is True
                   or (isinstance(result, int)
                       and not isinstance(result, bool) and result == 0))
        if success:
            accepted.add((value, width))
    return eid, accepted


def _apply_operand(ea: int, opn: int, eid: int) -> bool:
    try:
        return bool(idc.op_enum(ea, opn, eid, 0))
    except Exception:
        return False


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
    """Resolve with structural schemes or conservative collision thresholds."""
    hits = apihash.resolve(values, schemes if schemes else None)
    if schemes:
        return hits, schemes
    if not hits:
        return [], []

    support = {}
    for hit in hits:
        support.setdefault(hit.scheme, set()).add(hit.value)
    widths = {scheme.name: scheme.width for scheme in apihash.SCHEMES}
    inferred = [
        scheme for scheme, matched_values in support.items()
        if len(matched_values) >= 2
        or (widths.get(scheme) == 64 and len(matched_values) >= 1)
    ]
    if not inferred:
        return [], []
    return [h for h in hits if h.scheme in inferred], inferred


def resolve_in_function(func_ea: int, create_enum: bool = True,
                        apply_operands: bool = True, do_comment: bool = True):
    """Resolve hashed API names in one function. Returns (report_text, hits)."""
    func = ida_funcs.get_func(func_ea)
    if func is None:
        return "cursor is not inside a function", []

    cache = {}
    feats = _features(func_ea, cache)
    schemes, scheme_sources = _schemes_with_callees(func, cache)
    imm_addrs = _collect_imms(func)
    values = set(imm_addrs)
    values.update(_feature_values(feats))

    hits, schemes = _resolve_values(values, schemes)
    uniq = {}
    for h in hits:
        uniq[(h.value, h.name, h.scheme)] = h
    hits = list(uniq.values())

    fname = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:X}"
    lines = ["CryptoLens - API-hash resolution", f"  {fname} @ 0x{func.start_ea:X}"]
    lines.append(f"  schemes: {', '.join(schemes) if schemes else 'none'}")
    for source in scheme_sources:
        lines.append(f"    {source}")
    if not hits:
        lines.append("  no hashed API names resolved")
        lines.append("  note: indirect or custom hash helpers may require "
                     "analysis from the helper function")
        return "\n".join(lines), []

    members = {}
    resolved_values = set()
    for h in hits:
        _add_member(members, h)
        resolved_values.add((h.value, h.width))

    eid, enum_values = (_make_enum(members) if create_enum
                        else (None, set()))
    relabeled = 0
    for (value, width), addrs in imm_addrs.items():
        if (value, width) not in resolved_values:
            continue
        names = sorted({h.name for h in hits
                        if h.value == value and h.width == width})
        for ea, opn in addrs:
            if (eid is not None and apply_operands
                    and (value, width) in enum_values
                    and _apply_operand(ea, opn, eid)):
                relabeled += 1
            if do_comment:
                _comment(ea, "CryptoLens: " + " / ".join(names))

    lines.append(f"  names resolved: {len(hits)}; operands relabeled: {relabeled}"
                 + (f"; enum '{_ENUM_NAME}'" if enum_values else ""))
    for h in sorted(hits, key=lambda x: x.name):
        v = f" ({h.variant})" if h.variant else ""
        digits = h.width // 4
        lines.append(f"    0x{h.value:0{digits}X} = {h.scheme}(\"{h.name}\"{v})")
    return "\n".join(lines), hits


def resolve_in_binary(create_enum: bool = True, apply_operands: bool = True):
    """Resolve hashed API names across every function. Returns (text, findings)."""
    from .scanners import Finding

    all_members: Dict[str, int] = {}
    per_func = []
    total_hits = 0
    feature_cache = {}
    for fea in idautils.Functions():
        func = ida_funcs.get_func(fea)
        if func is None:
            continue
        feats = _features(fea, feature_cache)
        schemes, _scheme_sources = _schemes_with_callees(func, feature_cache)
        imm_addrs = _collect_imms(func)
        values = set(imm_addrs)
        values.update(_feature_values(feats))
        hits, schemes = _resolve_values(values, schemes)
        if not hits:
            continue
        uniq = {(h.value, h.name, h.scheme): h for h in hits}
        hits = list(uniq.values())
        total_hits += len(hits)
        for h in hits:
            _add_member(all_members, h)
        per_func.append((func.start_ea,
                         ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:X}",
                         hits, imm_addrs))

    eid, enum_values = (_make_enum(all_members)
                        if (create_enum and all_members) else (None, set()))
    findings = []
    for fea, fname, hits, imm_addrs in per_func:
        resolved_values = {(h.value, h.width) for h in hits}
        for (value, width), addrs in imm_addrs.items():
            if (value, width) not in resolved_values:
                continue
            names = sorted({h.name for h in hits
                            if h.value == value and h.width == width})
            for ea, opn in addrs:
                if (eid is not None and apply_operands
                        and (value, width) in enum_values):
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
