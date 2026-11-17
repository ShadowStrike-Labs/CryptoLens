"""Derive scaled integer constants with high-precision arithmetic.

The module implements the formulas used by the constant catalog: integer
roots, fractional roots, pi, e, ln(2), the golden ratio, and sine. It has no
third-party dependencies.
"""
from __future__ import annotations

from decimal import Decimal, getcontext, ROUND_FLOOR
from math import isqrt

getcontext().prec = 160  # Precision margin for 64-bit fractional extraction.


# --------------------------------------------------------------------------
# Integer roots (exact)
# --------------------------------------------------------------------------
def iroot(n: int, k: int) -> int:
    """floor(n ** (1/k)) for integers n >= 0, k >= 1 (exact, no floats)."""
    if n < 0:
        raise ValueError("iroot of negative number")
    if n == 0:
        return 0
    if k == 1:
        return n
    if k == 2:
        return isqrt(n)
    hi = 1 << ((n.bit_length() + k - 1) // k)
    lo = hi >> 1
    while lo < hi:
        mid = (lo + hi + 1) >> 1
        if mid ** k <= n:
            lo = mid
        else:
            hi = mid - 1
    return lo


def sqrt_scaled(n: int, bits: int) -> int:
    """floor(sqrt(n) * 2**bits)."""
    return isqrt(n << (2 * bits))


def root_scaled(n: int, k: int, bits: int) -> int:
    """floor(n**(1/k) * 2**bits)."""
    return iroot(n << (k * bits), k)


def frac_root_scaled(n: int, k: int, bits: int) -> int:
    """floor(frac(n**(1/k)) * 2**bits)  -- the SHA family's recipe."""
    return root_scaled(n, k, bits) - (iroot(n, k) << bits)


# --------------------------------------------------------------------------
# pi via Machin's formula (exact integer arithmetic)
# --------------------------------------------------------------------------
def _arccot(x: int, unity: int) -> int:
    total = xpow = unity // x
    x2 = x * x
    n = 3
    sign = -1
    while True:
        xpow //= x2
        term = xpow // n
        if term == 0:
            break
        total += sign * term
        sign = -sign
        n += 2
    return total


def pi_scaled(bits: int) -> int:
    """floor(pi * 2**bits)."""
    guard = 48
    unity = 1 << (bits + guard)
    pi_u = 16 * _arccot(5, unity) - 4 * _arccot(239, unity)
    return pi_u >> guard


# --------------------------------------------------------------------------
# Decimal-backed constants (e, ln2, pi) and derived helpers
# --------------------------------------------------------------------------
def _pi_dec() -> Decimal:
    return Decimal(pi_scaled(256)) / (Decimal(2) ** 256)


_PI = _pi_dec()
_TWO_PI = _PI * 2
_E = Decimal(1).exp()
_LN2 = Decimal(2).ln()

_NAMED_DEC = {
    "pi": _PI,
    "e": _E,
    "ln2": _LN2,
}


def dec_scaled(x: Decimal, bits: int) -> int:
    """floor(x * 2**bits) for a Decimal x."""
    v = (x * (Decimal(2) ** bits)).to_integral_value(rounding=ROUND_FLOOR)
    return int(v)


def frac_dec_scaled(x: Decimal, bits: int) -> int:
    """floor(frac(x) * 2**bits) for a Decimal x >= 0."""
    ip = int(x.to_integral_value(rounding=ROUND_FLOOR))
    return dec_scaled(x, bits) - (ip << bits)


def named_scaled(name: str, bits: int) -> int:
    return dec_scaled(_NAMED_DEC[name], bits)


def named_frac_scaled(name: str, bits: int) -> int:
    return frac_dec_scaled(_NAMED_DEC[name], bits)


# --------------------------------------------------------------------------
# Golden ratio
# --------------------------------------------------------------------------
def inv_phi_scaled(bits: int) -> int:
    """floor(2**bits / phi) = floor(2**(bits-1) * (sqrt5 - 1)).

    This is the TEA/XTEA delta recipe and Knuth's multiplicative-hash
    constant: 0x9E3779B9 at 32 bits, 0x9E3779B97F4A7C15 at 64 bits.
    """
    return sqrt_scaled(5, bits - 1) - (1 << (bits - 1))


# --------------------------------------------------------------------------
# Sine (for the MD5 table) via Decimal Taylor series with reduction
# --------------------------------------------------------------------------
def dsin(x: Decimal) -> Decimal:
    x = x % _TWO_PI
    if x > _PI:
        x -= _TWO_PI
    term = x
    total = x
    x2 = x * x
    n = 1
    eps = Decimal(10) ** (-80)
    while True:
        term = -term * x2 / Decimal((2 * n) * (2 * n + 1))
        total += term
        if term.copy_abs() < eps:
            break
        n += 1
    return total


def sin_frac_scaled(i_radians: int, bits: int) -> int:
    """floor(|sin(i)| * 2**bits) -- the MD5 T-table recipe (i in 1..64)."""
    s = dsin(Decimal(i_radians)).copy_abs()
    return int((s * (Decimal(2) ** bits)).to_integral_value(rounding=ROUND_FLOOR))
