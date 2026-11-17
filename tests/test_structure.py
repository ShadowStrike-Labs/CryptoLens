"""Tests for the function structural classifier (no IDA required)."""
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptolens import structure as S  # noqa: E402


def _rots(width, pairs):
    c = Counter()
    for d, a in pairs:
        c[(width, d, a)] += 1
    return c


def _feat(**kw):
    f = S.FunctionFeatures()
    for k, v in kw.items():
        setattr(f, k, v)
    return f


def _top(f):
    ms = S.classify(f)
    return ms[0] if ms else None


def test_chacha_beats_salsa():
    f = _feat(rotations=_rots(32, [("L", 16), ("L", 12), ("L", 8), ("L", 7)]),
              op_counts=Counter(xor=8, add=8), constants={0x61707865})
    top = _top(f)
    assert top and top.algo == "ChaCha20" and top.bucket == "high"


def test_salsa():
    f = _feat(rotations=_rots(32, [("L", 7), ("L", 9), ("L", 13), ("L", 18)]),
              op_counts=Counter(xor=8, add=8))
    top = _top(f)
    assert top and top.algo == "Salsa20"


def test_sha256_right_rotations():
    f = _feat(rotations=_rots(32, [("R", 2), ("R", 13), ("R", 22), ("R", 6),
                                   ("R", 11), ("R", 25)]),
              constants={0x428A2F98})
    top = _top(f)
    assert top and top.algo == "SHA-256" and top.bucket == "high"


def test_rc4_no_rotations():
    f = _feat(mod256=3, byte_array_indexing=True, byte_mem_ops=6,
              swaps=2, loops=1, constants={256})
    top = _top(f)
    assert top and top.algo == "RC4"


def test_tea_delta_and_shifts():
    f = _feat(constants={0x9E3779B9, 32},
              shifts=Counter({(32, "L", 4): 1, (32, "R", 5): 1}))
    top = _top(f)
    assert top and top.algo == "TEA/XTEA"


def test_crc_polynomial():
    f = _feat(shifts=Counter({(32, "R", 1): 1}), op_counts=Counter(xor=3),
              loops=1, conditional_branches=1, constants={0xEDB88320})
    top = _top(f)
    assert top and top.algo == "CRC"


def test_plain_function_no_match():
    # Non-cryptographic arithmetic without a matching structure.
    f = _feat(op_counts=Counter(add=2, sub=1), constants={1, 4, 8})
    assert S.classify(f) == []
    assert S.arx_summary(f) == ""
