"""Rank exact and near matches for an integer.

``explain(value, width)`` checks generated mathematical anchors and curated
algorithm signatures. It applies byte-order conversion, documented
golden-ratio negation, and CRC bit reflection. Shared constants retain all
candidate attributions. If no exact match exists, the constrained resemblance
pass may report a golden-ratio near match or a low-confidence one-bit hint.

Automatic binary attribution is handled by :mod:`cryptolens.familyscan`, which
requires related values or an ordered sequence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple

from . import constants, signatures, util


# --------------------------------------------------------------------------
# Result model
# --------------------------------------------------------------------------
@dataclass
class Explanation:
    value: int
    width: int
    kind: str                       # exact | named | transform | variant
    confidence: float               # 0..1
    summary: str                    # one-line description
    recipe: str = ""                # mathematical origin
    transform: str = ""             # transform chain from the base value
    detail: str = ""                # distance / bit notes
    algorithms: List[str] = field(default_factory=list)
    base: str = ""

    @property
    def bucket(self) -> str:
        if self.confidence >= 0.85:
            return "high"
        if self.confidence >= 0.5:
            return "medium"
        return "low"


# --------------------------------------------------------------------------
# Pretty names for base ids
# --------------------------------------------------------------------------
def base_pretty(base: str) -> str:
    simple = {
        "golden_ratio": "golden-ratio reciprocal (1/phi)",
        "pi": "pi fractional constant",
        "e": "fractional-e constant (RC5 precursor)",
        "ln2": "ln(2) fractional constant",
        "sin": "MD5 sine-table constant",
    }
    if base in simple:
        return simple[base]
    if base.startswith("sqrt_p"):
        return f"SHA-2 sqrt({base[6:]}) IV-style constant"
    if base.startswith("cbrt_p"):
        return f"SHA-2 cbrt({base[6:]}) round constant"
    if base.startswith("sqrt"):
        return f"sqrt({base[4:]}) fractional constant"
    return base


# --------------------------------------------------------------------------
# Query-side transforms
# --------------------------------------------------------------------------
def _candidates(value: int, width: int) -> List[Tuple[str, int, int]]:
    """Return deduplicated (transform, cost, value) candidates."""
    value &= util.mask(width)
    out: List[Tuple[str, int, int]] = []
    seen = {}

    def push(text: str, cost: int, tv: int):
        tv &= util.mask(width)
        if tv in seen and seen[tv] <= cost:
            return
        seen[tv] = cost
        out.append((text, cost, tv))

    push("", 0, value)                                   # identity
    push("negated (documented relation)", 2, util.neg(value, width))
    if width % 8 == 0:
        push("byte-swapped (endianness)", 2, util.bswap(value, width))
    push("bit-reversed (CRC reflection candidate)", 3, util.bitrev(value, width))
    return out


# --------------------------------------------------------------------------
# Confidence
# --------------------------------------------------------------------------
def _conf_from_cost(total_cost: int, has_named: bool, is_identity: bool) -> float:
    if total_cost == 0 and is_identity:
        return 1.0
    base = 0.97 if has_named else 0.95
    return max(0.35, base - 0.08 * total_cost)


# --------------------------------------------------------------------------
# Exact / transform assembly
# --------------------------------------------------------------------------
def _assemble(value: int, width: int) -> List[Explanation]:
    results: List[Explanation] = []
    for ttext, tcost, tv in _candidates(value, width):
        anchors = constants.lookup(tv, width)
        sigs = signatures.lookup(tv, width)
        is_identity = (ttext == "")
        # Restrict transformations by semantics: byte order is general, bit
        # reversal applies to reflected CRCs, and negation applies to the
        # documented golden-ratio pair.
        if not is_identity:
            anchors = [a for a in anchors if a.canonical]
            if ttext.startswith("bit-reversed"):
                sigs = [s for s in sigs if "CRC" in s.algorithm]
                anchors = []
            elif ttext.startswith("negated"):
                golden_values = {
                    0x9E3779B9, 0x61C88647,
                    0x9E3779B97F4A7C15, 0x61C8864680B583EB,
                }
                if tv not in golden_values:
                    sigs = []
                    anchors = []
        if not anchors and not sigs:
            continue

        min_anchor_cost = min((a.cost for a in anchors), default=0)
        total_cost = tcost + (0 if sigs else min_anchor_cost)
        has_named = bool(sigs)
        conf = _conf_from_cost(total_cost, has_named, is_identity)

        if is_identity and total_cost == 0:
            kind = "named" if sigs else "exact"
        else:
            kind = "transform"

        base = anchors[0].base if anchors else "named"
        recipes = []
        for a in anchors:
            if a.recipe not in recipes:
                recipes.append(a.recipe)
        recipe = recipes[0] if recipes else ""

        algos = []
        for s in sigs:
            label = f"{s.algorithm} - {s.role}" if s.role else s.algorithm
            if label not in algos:
                algos.append(label)

        if sigs:
            raw_names = list(dict.fromkeys(s.algorithm for s in sigs))
            names = []
            for candidate in sorted(raw_names, key=len):
                low = candidate.lower()
                if any(low in existing.lower() or existing.lower() in low
                       for existing in names):
                    continue
                names.append(candidate)
            if len(names) == 1:
                summary = (f"{names[0]}: {sigs[0].role}"
                           if sigs[0].role else names[0])
            else:
                shown = "; ".join(names[:4])
                if len(names) > 4:
                    shown += f"; +{len(names) - 4} more"
                summary = f"shared constant used by {shown}"
        else:
            summary = base_pretty(base)
        if not is_identity:
            summary = f"{summary}  ({ttext})"

        results.append(Explanation(
            value=value, width=width, kind=kind, confidence=conf,
            summary=summary, recipe=recipe, transform=ttext,
            detail="", algorithms=algos, base=base,
        ))
    return results


# --------------------------------------------------------------------------
# 64-bit half projections
# --------------------------------------------------------------------------
def _half_projections(value: int) -> List[Explanation]:
    out: List[Explanation] = []
    halves = (("high 32 bits", util.hi_half(value, 64)),
              ("low 32 bits", util.lo_half(value, 64)))
    for label, hv in halves:
        anchors = constants.lookup(hv, 32)
        sigs = signatures.lookup(hv, 32)
        if not anchors and not sigs:
            continue
        algos = [f"{s.algorithm} - {s.role}" if s.role else s.algorithm for s in sigs]
        base = anchors[0].base if anchors else "named"
        name = sigs[0].algorithm if sigs else base_pretty(base)
        out.append(Explanation(
            value=value, width=64, kind="transform", confidence=0.42,
            summary=f"{label} match: {name}",
            recipe=(anchors[0].recipe if anchors else ""),
            transform=label, algorithms=algos, base=base,
        ))
    return out


# --------------------------------------------------------------------------
# Fuzzy variant search (canonical anchors only)
# --------------------------------------------------------------------------
def _fuzzy(value: int, width: int, max_results: int = 4) -> List[Explanation]:
    """Return constrained single-value resemblance hints.

    Golden-ratio near matches may receive medium confidence. Other one-bit
    neighbors remain low-confidence lookup hints.
    """
    if value < 0x100:
        return []
    cands: List[Explanation] = []
    for a_val in constants.canonical_values(width):
        if a_val == value:
            continue
        anchors = constants.lookup(a_val, width)
        canonical = [a for a in anchors if a.canonical]
        if not canonical:
            continue
        base = canonical[0].base
        d = util.hamming(value, a_val)
        delta = value - a_val
        conf = 0.0
        detail = ""
        if base == "golden_ratio":
            if d == 1:
                conf = 0.72
                detail = "differs in 1 bit"
            elif d == 2:
                conf = 0.52
                detail = "differs in 2 bits"
            elif 0 < abs(delta) <= 8:
                conf = 0.58
                detail = f"numeric offset {delta:+#x}"
        elif d == 1:
            conf = 0.42
            detail = "one-bit numerical neighbor; uncorroborated"
        if conf == 0.0:
            continue

        sigs = signatures.lookup(a_val, width)
        algos = [f"{s.algorithm} - {s.role}" if s.role else s.algorithm for s in sigs]
        pretty = base_pretty(base)
        prefix = "variant of" if base == "golden_ratio" else "possible variant of"
        cands.append(Explanation(
            value=value, width=width, kind="variant", confidence=conf,
            summary=f"{prefix} {pretty}",
            recipe=canonical[0].recipe,
            transform="", detail=f"{detail} vs 0x{a_val:0{width // 4}X}",
            algorithms=algos, base=base,
        ))
    cands.sort(key=lambda e: e.confidence, reverse=True)
    return cands[:max_results]


# --------------------------------------------------------------------------
# Ranking / dedupe
# --------------------------------------------------------------------------
def _rank_dedup(expls: List[Explanation], max_results: int) -> List[Explanation]:
    best = {}
    for e in expls:
        key = (e.kind, e.base, e.transform, tuple(e.algorithms))
        if key not in best or e.confidence > best[key].confidence:
            best[key] = e
    ranked = sorted(best.values(), key=lambda e: e.confidence, reverse=True)
    return ranked[:max_results]


def explain(value: int, width: int, max_results: int = 8) -> List[Explanation]:
    value &= util.mask(width)
    results = _assemble(value, width)
    if width == 64:
        results += _half_projections(value)
    has_exact = any(e.transform == "" and e.kind in ("exact", "named") for e in results)
    if not has_exact:
        results += _fuzzy(value, width)
    return _rank_dedup(results, max_results)


def explain_multi(value: int, widths=(32, 64, 16), max_results: int = 8) -> List[Explanation]:
    """Explain a value across several widths, best findings first."""
    out: List[Explanation] = []
    for w in widths:
        if value > util.mask(w):
            continue
        out += explain(value, w, max_results=max_results)
    out.sort(key=lambda e: e.confidence, reverse=True)
    # Deduplicate repeated findings within each width.
    seen = set()
    uniq = []
    for e in out:
        key = (e.summary, e.width, e.transform)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(e)
    return uniq[:max_results]
