"""Registry of base mathematical constants and the anchor table.

An *anchor* is a concrete integer value (at a given bit width) together with the
recipe that produced it.  Canonical anchors (``cost == 0``) are generated
directly from :mod:`cryptolens.hpmath` formulas.  A handful of cheap *forward
derivations* (round-to-odd, round-to-nearest-prime, multiply-by-small-k) are
added on top, because real code frequently stores a constant in one of those
lightly-processed forms (e.g. TEA's decryption sum is ``delta * 32``).

The engine matches a queried number against this table, applying its own
query-side transforms (negate / not / byteswap / bitreverse / rotate / halves).
Fuzzy "variant of X" matching only ever considers canonical anchors, so you
never see nonsense like "variant of (golden ratio x 3)".
"""
from __future__ import annotations

from dataclasses import dataclass, field
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


# First 64 primes (SHA-2 uses these for sqrt/cbrt fractional parts).
_PRIMES64 = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
    151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
    233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311,
]

# Small k multipliers worth pre-deriving (TEA decryption sum is delta*32, etc.).
_MULTIPLIERS = (2, 3, 4, 5, 8, 16, 32)


def _canon_generators() -> List[Tuple[int, int, str, str]]:
    """Yield (value, width, base, recipe) for every canonical anchor."""
    out: List[Tuple[int, int, str, str]] = []

    for w in (32, 64):
        out.append((hp.inv_phi_scaled(w), w, "golden_ratio",
                    f"floor(2^{w} / phi)  (golden-ratio reciprocal 1/phi)"))
        out.append((hp.named_frac_scaled("pi", w), w, "pi",
                    f"frac(pi) * 2^{w}"))
        out.append((hp.named_frac_scaled("e", w), w, "e",
                    f"frac(e) * 2^{w}  (also (e-2)*2^{w}, RC5 P)"))
        out.append((hp.named_frac_scaled("ln2", w), w, "ln2",
                    f"frac(ln 2) * 2^{w}"))
        for k in (2, 3, 5, 6, 7, 10, 11, 13):
            out.append((hp.frac_root_scaled(k, 2, w), w, f"sqrt{k}",
                        f"frac(sqrt {k}) * 2^{w}"))
        for p in _PRIMES64[:8]:
            out.append((hp.frac_root_scaled(p, 2, w), w, f"sqrt_p{p}",
                        f"frac(sqrt {p}) * 2^{w}  (SHA-2 initial hash)"))
        for p in _PRIMES64:
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
        # Avoid duplicate recipes for the same value.
        if any(a.recipe == recipe for a in anchors):
            return
        anchors.append(Anchor(value, width, base, recipe, cost, canonical))

    for value, width, base, recipe in _canon_generators():
        add(value, width, base, recipe, 0, True)
        canon_values.setdefault(width, set()).add(value & util.mask(width))

    # Forward derivations off each canonical anchor.
    for (width, value), anchors in list(table.items()):
        for a in [x for x in anchors if x.canonical]:
            odd = util.nearest_odd(a.value)
            if odd != a.value and util.fits(odd, width):
                add(odd, width, a.base, a.recipe + ", rounded up to odd", 1, False)
            pr, dist = util.nearest_prime(a.value, max_delta=256)
            if pr is not None and pr != a.value and util.fits(pr, width):
                sign = "+" if dist > 0 else "-"
                add(pr, width, a.base,
                    a.recipe + f", rounded to nearest prime ({sign}{abs(dist)})",
                    2, False)
            for k in _MULTIPLIERS:
                mv = (a.value * k) & util.mask(width)
                add(mv, width, a.base, a.recipe + f", x {k} (mod 2^{width})", 2, False)

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
