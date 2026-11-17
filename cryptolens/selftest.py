"""Internal verification suite (no pytest dependency).

Confirms that constants derive correctly from formulas and that the engine
classifies the headline scenarios as expected.  Run with:
    python -m cryptolens selftest
"""
from __future__ import annotations

from . import engine, families, familyscan, hpmath as hp, signatures, util

_PRIMES8 = (2, 3, 5, 7, 11, 13, 17, 19)
_SHA256_H = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
             0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
_SHA256_K0 = 0x428A2F98
_MD5_T = {1: 0xD76AA478, 2: 0xE8C7B756, 64: 0xEB86D391}


def _check(cond: bool, msg: str, failures: list) -> None:
    if not cond:
        failures.append(msg)


def check_constants(failures: list) -> None:
    _check(hp.inv_phi_scaled(32) == 0x9E3779B9, "golden ratio 32", failures)
    _check(hp.inv_phi_scaled(64) == 0x9E3779B97F4A7C15, "golden ratio 64", failures)
    for p, h in zip(_PRIMES8, _SHA256_H):
        _check(hp.frac_root_scaled(p, 2, 32) == h, f"sqrt {p}", failures)
    _check(hp.frac_root_scaled(2, 3, 32) == _SHA256_K0, "cbrt 2", failures)
    _check(hp.frac_root_scaled(2, 2, 64) == 0x6A09E667F3BCC908, "sqrt2 64", failures)
    _check(hp.sqrt_scaled(2, 30) == 0x5A827999, "sha1 sqrt2", failures)
    _check(hp.named_frac_scaled("pi", 32) == 0x243F6A88, "pi frac", failures)
    for i, t in _MD5_T.items():
        _check(hp.sin_frac_scaled(i, 32) == t, f"md5 T[{i}]", failures)
    _check(util.bitrev(0x04C11DB7, 32) == 0xEDB88320, "crc bitrev", failures)
    _check(util.modinv(0x01000193, 32) == 0x359C449B, "fnv modinv", failures)


def _top(value: int, width: int):
    r = engine.explain(value, width)
    return r[0] if r else None


def check_engine(failures: list) -> None:
    top = _top(0x9E3779B9, 32)
    _check(top is not None and top.kind == "named" and "TEA" in top.summary,
           "explain 0x9E3779B9 -> TEA", failures)

    top = _top(0xC6EF3720, 32)
    _check(top is not None and "TEA" in top.summary,
           "explain 0xC6EF3720 -> TEA x32", failures)

    # The flagship: a 1-bit-off golden-ratio value is a variant, not exact.
    top = _top(0x9E3779F9, 32)
    _check(top is not None and top.kind == "variant"
           and "golden-ratio" in top.summary
           and any("TEA" in use for use in top.algorithms),
           "explain 0x9E3779F9 -> golden-ratio variant with TEA candidate", failures)

    top = _top(0xEDB88320, 32)
    _check(top is not None and "CRC-32" in top.summary,
           "explain 0xEDB88320 -> CRC-32", failures)

    top = _top(0x6A09E667, 32)
    _check(top is not None and "SHA-256" in top.summary,
           "explain 0x6A09E667 -> SHA-256", failures)


def check_catalog(failures: list) -> None:
    _check(len(families.SHA256_K) == 64, "complete SHA-256 K table", failures)
    _check(len(families.SHA512_K) == 80, "complete SHA-512 K table", failures)
    _check(families.SHA512_K[-1] == 0x6C44198C4A475817,
           "SHA-512 final round constant", failures)
    _check(families.XXH64_PRIMES[3] == 0x85EBCA77C2B2AE63,
           "xxHash64 PRIME64_4", failures)
    _check(not signatures.lookup(0x60EA27EEADC0B5D6, 64),
           "removed incorrect xxHash64 PRIME64_5", failures)
    blob = b"x" * 7 + b"".join(v.to_bytes(8, "little")
                                 for v in families.KECCAK_RC)
    hits = familyscan.scan_buffer(blob)
    _check(any(h.family_id == "keccak_rc" and h.mode == "sequence" for h in hits),
           "Keccak ordered family scan", failures)


def run() -> bool:
    failures: list = []
    check_constants(failures)
    check_engine(failures)
    check_catalog(failures)
    if failures:
        print("SELFTEST FAILED:")
        for f in failures:
            print("  -", f)
        return False
    print("SELFTEST PASSED (constants + families + engine)")
    return True
