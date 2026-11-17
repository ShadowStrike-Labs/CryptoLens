"""Generate mathematical anchors used by the lookup engine.

Canonical anchors come from formulas in :mod:`cryptolens.hpmath`. The index
also includes a small set of algorithm-defined relationships, including the
TEA decryption sum, RC5 odd constants, the xxHash32 prime, and golden-ratio
negation. Automatic algorithm attribution is handled by
:mod:`cryptolens.familyscan`.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Dict, List, Tuple

from . import hpmath as hp
from . import util


@dataclass(frozen=True)
class Anchor:
    value: int
    width: int
    base: str            # short base id, e.g. "golden_ratio"
    recipe: str          # human recipe, e.g. "floor(2^32 / phi)"
    cost: int = 0        # 0 = canonical; higher = lightly derived
    canonical: bool = True


# First 80 primes (SHA-256 uses 64; SHA-512 uses all 80).
_PRIMES80 = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
    151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
    233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311,
    313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397,
    401, 409,
]


def _canon_generators() -> List[Tuple[int, int, str, str]]:
    """Return (value, width, base, recipe) tuples for canonical anchors."""
    out: List[Tuple[int, int, str, str]] = []

    for w in (32, 64):
        out.append((hp.inv_phi_scaled(w), w, "golden_ratio",
                    f"floor(2^{w} / phi)  (golden-ratio reciprocal 1/phi)"))
        out.append((hp.named_frac_scaled("pi", w), w, "pi",
                    f"frac(pi) * 2^{w}"))
        out.append((hp.named_frac_scaled("e", w), w, "e",
                    f"floor(frac(e) * 2^{w})  (precursor to odd RC5 P)"))
        out.append((hp.named_frac_scaled("ln2", w), w, "ln2",
                    f"frac(ln 2) * 2^{w}"))
        # Prefer the SHA-specific recipe when a generic root has the same value.
        for p in _PRIMES80[:8]:
            out.append((hp.frac_root_scaled(p, 2, w), w, f"sqrt_p{p}",
                        f"frac(sqrt {p}) * 2^{w}  (SHA-2 initial hash)"))
        for k in (2, 3, 5, 6, 7, 10, 11, 13):
            out.append((hp.frac_root_scaled(k, 2, w), w, f"sqrt{k}",
                        f"frac(sqrt {k}) * 2^{w}"))
        k_count = 64 if w == 32 else 80
        for p in _PRIMES80[:k_count]:
            out.append((hp.frac_root_scaled(p, 3, w), w, f"cbrt_p{p}",
                        f"frac(cbrt {p}) * 2^{w}  (SHA-2 round constant)"))

    # SHA-1 style: floor(sqrt(n) * 2^30)
    for n in (2, 3, 5, 10):
        out.append((hp.sqrt_scaled(n, 30), 32, f"sqrt{n}",
                    f"floor(sqrt {n} * 2^30)  (SHA-1 round constant)"))

    # MD5 T-table: floor(|sin(i)| * 2^32), i = 1..64
    for i in range(1, 65):
        out.append((hp.sin_frac_scaled(i, 32), 32, "sin",
                    f"floor(|sin({i})| * 2^32)  (MD5 T[{i}])"))

    return out


def _build() -> Tuple[Dict[Tuple[int, int], List[Anchor]], Dict[int, List[int]]]:
    table: Dict[Tuple[int, int], List[Anchor]] = {}
    canon_values: Dict[int, set] = {32: set(), 64: set()}

    def add(value: int, width: int, base: str, recipe: str,
            cost: int, canonical: bool) -> None:
        value &= util.mask(width)
        key = (width, value)
        anchors = table.setdefault(key, [])
        if any(a.recipe == recipe for a in anchors):
            return
        anchors.append(Anchor(value, width, base, recipe, cost, canonical))

    for value, width, base, recipe in _canon_generators():
        add(value, width, base, recipe, 0, True)
        canon_values.setdefault(width, set()).add(value & util.mask(width))

    # Index only relationships defined by an algorithm. Generic rounding and
    # multiplication produce unsupported matches.
    g32 = hp.inv_phi_scaled(32)
    g64 = hp.inv_phi_scaled(64)
    add(util.neg(g32, 32), 32, "golden_ratio",
        "-floor(2^32 / phi) mod 2^32 (Linux/Java hash increment)", 1, False)
    add(util.neg(g64, 64), 64, "golden_ratio",
        "-floor(2^64 / phi) mod 2^64", 1, False)
    add((g32 * 32) & util.mask(32), 32, "golden_ratio",
        "floor(2^32 / phi) x 32 mod 2^32 (TEA decrypt start sum)", 1, False)
    add(0x9E3779B1, 32, "golden_ratio",
        "prime immediately below floor(2^32 / phi) (xxHash32 PRIME32_1)", 1, False)
    add(0xB7E15163, 32, "e",
        "Odd(floor((e - 2) * 2^32)) (RC5/RC6 P32)", 1, False)
    add(0xB7E151628AED2A6B, 64, "e",
        "Odd(floor((e - 2) * 2^64)) (RC5/RC6 P64)", 1, False)

    by_width = {w: sorted(vals) for w, vals in canon_values.items()}
    return table, by_width


@lru_cache(maxsize=1)
def _tables():
    return _build()


def anchor_table() -> Dict[Tuple[int, int], List[Anchor]]:
    return _tables()[0]


def canonical_values(width: int) -> List[int]:
    return _tables()[1].get(width, [])


def lookup(value: int, width: int) -> List[Anchor]:
    return anchor_table().get((width, value & util.mask(width)), [])
