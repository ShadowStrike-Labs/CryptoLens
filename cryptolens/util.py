"""Integer bit operations and number-theory helpers."""
from __future__ import annotations

_SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


def mask(width: int) -> int:
    """Bit mask for a value of ``width`` bits."""
    return (1 << width) - 1


def fits(x: int, width: int) -> bool:
    return 0 <= x <= mask(width)


def rol(x: int, r: int, width: int) -> int:
    """Rotate ``x`` left by ``r`` bits within ``width`` bits."""
    r %= width
    m = mask(width)
    x &= m
    if r == 0:
        return x
    return ((x << r) | (x >> (width - r))) & m


def ror(x: int, r: int, width: int) -> int:
    """Rotate ``x`` right by ``r`` bits within ``width`` bits."""
    return rol(x, width - (r % width), width)


def bswap(x: int, width: int) -> int:
    """Reverse the byte order of ``x`` (``width`` must be a multiple of 8)."""
    nbytes = width // 8
    return int.from_bytes((x & mask(width)).to_bytes(nbytes, "little"), "big")


def bitrev(x: int, width: int) -> int:
    """Reverse the bit order of ``x`` within ``width`` bits."""
    x &= mask(width)
    r = 0
    for _ in range(width):
        r = (r << 1) | (x & 1)
        x >>= 1
    return r


def neg(x: int, width: int) -> int:
    """Two's-complement negation within ``width`` bits."""
    return (-x) & mask(width)


def bnot(x: int, width: int) -> int:
    """Bitwise NOT within ``width`` bits."""
    return (~x) & mask(width)


def hi_half(x: int, width: int) -> int:
    """Upper half of a ``width``-bit value."""
    return (x >> (width // 2)) & mask(width // 2)


def lo_half(x: int, width: int) -> int:
    """Lower half of a ``width``-bit value."""
    return x & mask(width // 2)


def popcount(x: int) -> int:
    return bin(x & ((1 << x.bit_length()) - 1) if x >= 0 else x).count("1")


def hamming(a: int, b: int) -> int:
    """Number of differing bits between ``a`` and ``b``."""
    return bin(a ^ b).count("1")


def is_prime(n: int) -> bool:
    """Deterministic Miller-Rabin primality test for 64-bit integers."""
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in _SMALL_PRIMES:
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def nearest_prime(n: int, max_delta: int = 4096):
    """Nearest prime to ``n`` and its signed distance, or ``(None, None)``."""
    if n < 2:
        return 2, 2 - n
    if is_prime(n):
        return n, 0
    for delta in range(1, max_delta + 1):
        if is_prime(n + delta):
            return n + delta, delta
        if n - delta >= 2 and is_prime(n - delta):
            return n - delta, -delta
    return None, None


def nearest_odd(n: int) -> int:
    return n if n & 1 else n + 1


def modinv(a: int, width: int):
    """Modular inverse of ``a`` mod ``2**width`` (``None`` if ``a`` is even)."""
    a &= mask(width)
    if a % 2 == 0:
        return None
    return pow(a, -1, 1 << width)
