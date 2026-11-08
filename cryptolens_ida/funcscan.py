"""Per-function algorithm analysis: extract features, then classify.

Answers "what algorithm is the function under my cursor?".  Features are
extracted from two sources and merged:

* disassembly  - always available; rol/ror amounts, shift amounts, ARX op
                 histogram, immediates, &0xFF byte-modular ops, xchg swaps,
                 loops, and references to known tables.
* Hex-Rays     - when a decompiler is present; recovers rotations the compiler
                 folded into shift/or pairs (via the __ROL4__/__ROR4__ helpers),
                 plus clean constants and byte-array indexing.

All scoring lives in the testable core (:mod:`cryptolens.structure`); this file
only reads the IDB.  Everything IDA-specific is written defensively so a single
SDK-version quirk degrades gracefully instead of aborting the analysis.
"""
from __future__ import annotations

import re
from typing import List, Optional

from cryptolens import engine, structure, tables

from .ida_shim import (HAVE_IDA, ida_bytes, ida_funcs, ida_ua, idaapi,
                       idautils, idc, msg)

_ROT_RE = re.compile(r"__(ROL|ROR)([1248])__")
_TABLE_CACHE = {}


def _dtype_width(op) -> int:
    mapping = {
        getattr(ida_ua, "dt_byte", 0): 8,
        getattr(ida_ua, "dt_word", 1): 16,
        getattr(ida_ua, "dt_dword", 2): 32,
        getattr(ida_ua, "dt_qword", 7): 64,
    }
    return mapping.get(op.dtype, 32)


def _imm_of(insn) -> Optional[int]:
    for op in insn.ops:
        if op.type == ida_ua.o_imm:
            return op.value
    return None


def _table_names_at(ea: int) -> List[str]:
    if ea in _TABLE_CACHE:
        return _TABLE_CACHE[ea]
    names: List[str] = []
    data = ida_bytes.get_bytes(ea, 1056) or b""
    if data:
        for hit in tables.detect_tables(data, base=0):
            if hit.offset <= 64:
                names.append(hit.name)
    _TABLE_CACHE[ea] = names
    return names


def _extract_asm(func, f: structure.FunctionFeatures) -> None:
    f.sources.add("asm")
    oc = f.op_counts
    count = 0
    start, end = func.start_ea, func.end_ea
    for ea in idautils.FuncItems(start):
        insn = ida_ua.insn_t()
        if idaapi.decode_insn(insn, ea) <= 0:
            continue
        count += 1
        mnem = (ida_ua.print_insn_mnem(ea) or "").lower()
        op0 = insn.ops[0]
        width = _dtype_width(op0) if op0.type != ida_ua.o_void else 32

        if mnem in ("add", "adc", "xadd"):
            oc["add"] += 1
        elif mnem in ("sub", "sbb"):
            oc["sub"] += 1
        elif mnem == "xor":
            if not (insn.ops[0].type == ida_ua.o_reg and insn.ops[1].type == ida_ua.o_reg
                    and insn.ops[0].reg == insn.ops[1].reg):
                oc["xor"] += 1
        elif mnem == "and":
            oc["and"] += 1
            if _imm_of(insn) == 0xFF:
                f.mod256 += 1
        elif mnem == "or":
            oc["or"] += 1
        elif mnem in ("mul", "imul"):
            oc["mul"] += 1
        elif mnem == "not":
            oc["not"] += 1
        elif mnem in ("shl", "sal", "shr", "sar"):
            d = "L" if mnem in ("shl", "sal") else "R"
            oc["shl" if d == "L" else "shr"] += 1
            if insn.ops[1].type == ida_ua.o_imm:
                f.shifts[(width, d, insn.ops[1].value % max(width, 1))] += 1
        elif mnem in ("rol", "ror"):
            d = "L" if mnem == "rol" else "R"
            if insn.ops[1].type == ida_ua.o_imm:
                f.rotations[(width, d, insn.ops[1].value % max(width, 1))] += 1
        elif mnem == "xchg":
            f.swaps += 1
        elif mnem in ("aesenc", "aesenclast", "aesdec", "aesdeclast",
                      "aesimc", "aeskeygenassist"):
            f.has_aesni = True
        elif mnem.startswith("sha1") or mnem.startswith("sha256"):
            f.has_shani = True

        for op in insn.ops:
            if op.type == ida_ua.o_imm:
                f.constants.add(op.value & 0xFFFFFFFFFFFFFFFF)

        for dref in idautils.DataRefsFrom(ea):
            for name in _table_names_at(dref):
                if name not in f.table_refs:
                    f.table_refs.append(name)

        for cref in idautils.CodeRefsFrom(ea, 0):
            if start <= cref < ea:
                f.loops += 1

    f.insn_count = count
    f.size = end - start


def _num_val(e, hx):
    try:
        if e is not None and e.op == hx.cot_num:
            return e.numval()
    except Exception:
        try:
            return e.n._value
        except Exception:
            return None
    return None


def _extract_hexrays(func, f: structure.FunctionFeatures) -> None:
    try:
        import ida_hexrays as hx
    except Exception:
        return
    try:
        if not hx.init_hexrays_plugin():
            return
        cfunc = hx.decompile(func.start_ea)
    except Exception:
        return
    if not cfunc:
        return
    f.sources.add("hexrays")

    oc = f.op_counts
    SHL = getattr(hx, "cot_shl", -1)
    SHR = getattr(hx, "cot_shr", -2)
    USHR = getattr(hx, "cot_ushr", -3)
    SSHR = getattr(hx, "cot_sshr", -4)

    class _V(hx.ctree_visitor_t):
        def __init__(self):
            super().__init__(hx.CV_FAST)

        def visit_expr(self, e):
            try:
                self._one(e)
            except Exception:
                pass
            return 0

        def _one(self, e):
            op = e.op
            if op == hx.cot_call and e.x and e.x.op == hx.cot_helper:
                m = _ROT_RE.match(e.x.helper or "")
                if m and e.a and e.a.size() >= 2:
                    d = "L" if m.group(1) == "ROL" else "R"
                    w = int(m.group(2)) * 8
                    amt = _num_val(e.a[1], hx)
                    if amt is not None:
                        f.rotations[(w, d, amt % w)] += 1
            elif op == SHL or op == SHR or op == USHR or op == SSHR:
                d = "L" if op == SHL else "R"
                amt = _num_val(e.y, hx)
                if amt is not None:
                    w = e.x.type.get_size() * 8 if e.x and e.x.type else 32
                    f.shifts[(w or 32, d, amt % max(w or 32, 1))] += 1
                oc["shl" if d == "L" else "shr"] += 1
            elif op == hx.cot_xor:
                oc["xor"] += 1
            elif op == hx.cot_add:
                oc["add"] += 1
            elif op == hx.cot_sub:
                oc["sub"] += 1
            elif op == hx.cot_mul:
                oc["mul"] += 1
            elif op == hx.cot_band:
                oc["and"] += 1
                if _num_val(e.y, hx) == 0xFF:
                    f.mod256 += 1
            elif op == hx.cot_bor:
                oc["or"] += 1
            elif op == hx.cot_num:
                v = _num_val(e, hx)
                if v is not None:
                    f.constants.add(v & 0xFFFFFFFFFFFFFFFF)
            elif op == hx.cot_idx:
                try:
                    if e.type and e.type.get_size() == 1:
                        f.byte_array_indexing = True
                except Exception:
                    pass

    try:
        _V().apply_to(cfunc.body, None)
    except Exception:
        pass


def extract_features(func_ea: int) -> Optional[structure.FunctionFeatures]:
    func = ida_funcs.get_func(func_ea)
    if func is None:
        return None
    f = structure.FunctionFeatures(ea=func.start_ea,
                                   name=ida_funcs.get_func_name(func.start_ea) or "")
    _extract_asm(func, f)
    _extract_hexrays(func, f)
    return f


def format_report(f: structure.FunctionFeatures,
                  matches: List[structure.AlgoMatch]) -> str:
    lines = [f"CryptoLens - function analysis",
             f"  {f.name}  @ 0x{f.ea:X}   ({f.insn_count} insns, {f.size} bytes)",
             f"  sources: {', '.join(sorted(f.sources)) or 'none'}",
             ""]
    if matches:
        lines.append("Detected algorithms:")
        for m in matches:
            lines.append(f"  [{m.bucket}] {m.algo}   score {m.score:.2f}")
            for e in m.evidence:
                lines.append(f"        - {e}")
    else:
        lines.append("No named algorithm matched.")
    arx = structure.arx_summary(f)
    if arx:
        lines += ["", arx]

    # Enrich notable constants through the phase-1 engine.
    enriched = []
    for c in sorted(f.constants):
        if c < 0x100:
            continue
        for w in (32, 64):
            if c > (1 << w) - 1:
                continue
            ex = engine.explain(c, w)
            if ex and ex[0].confidence >= 0.5:
                enriched.append(f"  0x{c:X} ({w}b): {ex[0].summary}")
                break
    if enriched:
        lines += ["", "Notable constants:"] + enriched[:12]

    L32 = sorted(f.as_left(32))
    if L32:
        lines += ["", f"Rotation amounts (as left, 32-bit): {L32}"]
    if f.table_refs:
        lines += [f"Referenced tables: {', '.join(sorted(set(f.table_refs)))}"]
    return "\n".join(lines)


def analyze_function(func_ea: int, annotate: bool = False):
    f = extract_features(func_ea)
    if f is None:
        return None, []
    matches = structure.classify(f)
    if annotate and matches:
        top = matches[0]
        cmt = f"CryptoLens: {top.algo} (score {top.score:.2f})"
        try:
            idc.set_func_cmt(f.ea, cmt, 0)
        except Exception:
            pass
    return f, matches


if HAVE_IDA:
    from .ida_shim import ida_kernwin
    from .scanners import Finding

    _VIEWERS = {}

    def _show_text(title: str, text: str) -> None:
        v = _VIEWERS.get(title)
        if v is None:
            v = ida_kernwin.simplecustviewer_t()
            if not v.Create(title):
                ida_kernwin.msg("[CryptoLens] could not create view\n")
                return
            _VIEWERS[title] = v
        v.ClearLines()
        for line in text.splitlines():
            v.AddLine(line)
        v.Refresh()
        v.Show()

    def analyze_current_function():
        ea = ida_kernwin.get_screen_ea()
        func = ida_funcs.get_func(ea)
        if func is None:
            ida_kernwin.warning("CryptoLens: cursor is not inside a function.")
            return
        f, matches = analyze_function(func.start_ea)
        text = format_report(f, matches)
        _show_text("CryptoLens: function", text)
        msg("[CryptoLens] " + (matches[0].algo if matches
                               else "no algorithm match") + "\n")

    def scan_all_functions(use_decompiler: bool = False,
                           threshold: float = 0.5) -> List["Finding"]:
        out: List[Finding] = []
        funcs = list(idautils.Functions())
        msg(f"[CryptoLens] analysing {len(funcs)} functions...\n")
        for fea in funcs:
            func = ida_funcs.get_func(fea)
            if func is None:
                continue
            f = structure.FunctionFeatures(
                ea=func.start_ea,
                name=ida_funcs.get_func_name(func.start_ea) or "")
            _extract_asm(func, f)
            if use_decompiler:
                _extract_hexrays(func, f)
            matches = structure.classify(f, threshold=threshold)
            if matches:
                top = matches[0]
                out.append(Finding(
                    ea=f.ea, category="function", title=f"{top.algo} (function)",
                    detail="; ".join(top.evidence[:2]),
                    confidence=top.score, bucket=top.bucket,
                    func=f.name))
        out.sort(key=lambda x: -x.confidence)
        msg(f"[CryptoLens] {len(out)} crypto-like function(s).\n")
        return out

else:  # pragma: no cover
    def analyze_current_function():
        raise RuntimeError("requires IDA")

    def scan_all_functions(*a, **k):
        raise RuntimeError("requires IDA")
