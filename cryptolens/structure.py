"""Structural algorithm detection from a function's extracted features.

This is the "what algorithm is this sub_XXX?" brain.  It is deliberately
IDA-independent: the IDA layer (:mod:`cryptolens_ida.funcscan`) extracts a
:class:`FunctionFeatures` from Hex-Rays + disassembly, and this module scores it
against structural signatures.  That split keeps the hard part (the detection
logic) unit-testable without launching IDA.

The strongest single feature is the *set of rotation amounts*: ARX ciphers and
hashes are defined by them (ChaCha 16/12/8/7, Salsa 7/9/13/18, the SHA-2 Sigma
rotations, MD5's per-round table, SHA-1's 1/5/30).  Rotations are normalised so
that a right-rotate by r is treated as a left-rotate by width-r, which makes the
detectors robust to however the compiler/decompiler chose to express them.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, List, Set, Tuple

W32 = 32
W64 = 64


@dataclass
class FunctionFeatures:
    ea: int = 0
    name: str = ""
    size: int = 0
    insn_count: int = 0
    # rotations/shifts keyed by (width, 'L'|'R', amount) -> occurrence count
    rotations: Counter = field(default_factory=Counter)
    shifts: Counter = field(default_factory=Counter)
    constants: Set[int] = field(default_factory=set)
    op_counts: Counter = field(default_factory=Counter)   # add/sub/xor/and/or/mul/not/shl/shr
    mod256: int = 0                 # count of &0xFF style byte-modular ops
    swaps: int = 0                  # xchg or decompiled swap patterns
    loops: int = 0
    byte_array_indexing: bool = False
    table_refs: List[str] = field(default_factory=list)
    calls: Set[str] = field(default_factory=set)
    has_aesni: bool = False
    has_shani: bool = False
    sources: Set[str] = field(default_factory=set)         # 'asm', 'hexrays'

    # -- rotation views ----------------------------------------------------
    def as_left(self, width: int = W32) -> Set[int]:
        out = set()
        for (w, d, a) in self.rotations:
            if w != width:
                continue
            out.add(a % width if d == "L" else (width - a) % width)
        out.discard(0)
        return out

    def as_right(self, width: int = W32) -> Set[int]:
        out = set()
        for (w, d, a) in self.rotations:
            if w != width:
                continue
            out.add(a % width if d == "R" else (width - a) % width)
        out.discard(0)
        return out

    def shift_set(self, width: int = W32, direction: str = None) -> Set[int]:
        out = set()
        for (w, d, a) in self.shifts:
            if w != width:
                continue
            if direction and d != direction:
                continue
            out.add(a)
        return out

    @property
    def arx_strength(self) -> int:
        return (self.op_counts.get("xor", 0) + self.op_counts.get("add", 0)
                + sum(self.rotations.values()))


def _cover(need: Set[int], have: Set[int]) -> float:
    """Fraction of ``need`` present in ``have`` (0..1)."""
    if not need:
        return 0.0
    return len(need & have) / len(need)


def _hexset(values) -> str:
    return ", ".join(f"0x{v:X}" for v in sorted(values))


# --------------------------------------------------------------------------
# Per-algorithm structural detectors: (score 0..1, evidence lines)
# --------------------------------------------------------------------------
_SIGMA_WORDS = {0x61707865, 0x3320646E, 0x79622D32, 0x6B206574}


def _d_chacha(f: FunctionFeatures):
    ev, score = [], 0.0
    cov = _cover({16, 12, 8, 7}, f.as_left(32))
    if cov >= 0.75:
        score += 0.6 * cov
        ev.append(f"ChaCha quarter-round rotations 16/12/8/7 ({int(cov * 4)}/4)")
    if f.constants & _SIGMA_WORDS:
        score += 0.3
        ev.append("ChaCha/Salsa sigma constant 'expand 32-byte k'")
    if score and f.op_counts.get("xor", 0) >= 4 and f.op_counts.get("add", 0) >= 4:
        score += 0.1
        ev.append("ARX add/xor/rotate structure")
    return min(score, 1.0), ev


def _d_salsa(f: FunctionFeatures):
    ev, score = [], 0.0
    cov = _cover({7, 9, 13, 18}, f.as_left(32))
    if cov >= 0.75:
        score += 0.6 * cov
        ev.append(f"Salsa20 rotations 7/9/13/18 ({int(cov * 4)}/4)")
    if f.constants & _SIGMA_WORDS:
        score += 0.3
        ev.append("ChaCha/Salsa sigma constant 'expand 32-byte k'")
    return min(score, 1.0), ev


def _d_sha256(f: FunctionFeatures):
    ev, score = [], 0.0
    R = f.as_right(32)
    big = {2, 13, 22, 6, 11, 25}            # Sigma0 / Sigma1
    small = {7, 18, 17, 19}                 # sigma0 / sigma1
    cov = _cover(big, R)
    if cov >= 0.6:
        score += 0.55 * cov
        ev.append(f"SHA-256 Sigma rotations ({int(cov * 6)}/6 of 2/13/22, 6/11/25)")
    if _cover(small, R) >= 0.5 and _cover({3, 10}, f.shift_set(32, "R")) >= 0.5:
        score += 0.2
        ev.append("SHA-256 message-schedule (ror7/18, ror17/19, >>3, >>10)")
    if f.constants & {0x428A2F98, 0x71374491, 0x6A09E667, 0xBB67AE85}:
        score += 0.3
        ev.append("SHA-256 IV / round constants present")
    return min(score, 1.0), ev


def _d_sha512(f: FunctionFeatures):
    ev, score = [], 0.0
    R = f.as_right(64)
    big = {28, 34, 39, 14, 18, 41}
    cov = _cover(big, R)
    if cov >= 0.6:
        score += 0.6 * cov
        ev.append(f"SHA-512 64-bit Sigma rotations ({int(cov * 6)}/6)")
    if f.constants & {0x428A2F98D728AE22, 0x6A09E667F3BCC908}:
        score += 0.3
        ev.append("SHA-512 IV / round constant present")
    return min(score, 1.0), ev


def _d_sha1(f: FunctionFeatures):
    ev, score = [], 0.0
    cov = _cover({5, 30, 1}, f.as_left(32))
    if cov >= 0.66:
        score += 0.45 * cov
        ev.append(f"SHA-1 rotations 5/30/1 ({int(cov * 3)}/3)")
    hit = f.constants & {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6}
    if hit:
        score += 0.5
        ev.append(f"SHA-1 round constants {_hexset(hit)}")
    return min(score, 1.0), ev


_MD5_ROTS = {7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21}


def _d_md5(f: FunctionFeatures):
    ev, score = [], 0.0
    cov = _cover(_MD5_ROTS, f.as_left(32))
    if cov >= 0.5:
        score += 0.6 * cov
        ev.append(f"MD5 per-round rotation set ({int(cov * 16)}/16)")
    if f.constants & {0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0x67452301}:
        score += 0.3
        ev.append("MD5 sine-table / IV constants")
    return min(score, 1.0), ev


def _d_rc4(f: FunctionFeatures):
    ev, score = [], 0.0
    if f.mod256 > 0 and f.byte_array_indexing:
        score += 0.4
        ev.append("256-entry byte state with &0xFF modular indexing")
    if f.swaps > 0 or (f.byte_array_indexing and f.mod256 >= 2):
        score += 0.3
        ev.append("byte swap inside state array (RC4 KSA/PRGA)")
    if f.constants & {256, 255}:
        score += 0.15
        ev.append("state size 256 / mask 255")
    if f.as_left(32):            # RC4 has no rotations
        score -= 0.25
    return max(min(score, 1.0), 0.0), ev


def _d_crc(f: FunctionFeatures):
    ev, score = [], 0.0
    polys = {0xEDB88320, 0x82F63B78, 0x04C11DB7, 0x1EDC6F41,
             0x1021, 0x8408, 0x8005, 0xA001}
    hit = f.constants & polys
    rsh = f.shift_set(32, "R") | f.shift_set(16, "R")
    if 1 in rsh and f.op_counts.get("xor", 0) >= 1:
        score += 0.3
        ev.append("bit-at-a-time shift-right + conditional XOR loop")
    if 8 in rsh and any("CRC" in t for t in f.table_refs):
        score += 0.4
        ev.append("table-driven CRC (>>8 + table lookup)")
    if hit:
        score += 0.5
        ev.append(f"CRC polynomial {_hexset(hit)}")
    if any("CRC" in t for t in f.table_refs):
        score += 0.3
        ev.append("references a CRC table")
    return min(score, 1.0), ev


def _d_tea(f: FunctionFeatures):
    ev, score = [], 0.0
    if f.constants & {0x9E3779B9, 0xC6EF3720, 0x9E3779B97F4A7C15}:
        score += 0.5
        ev.append("golden-ratio delta 0x9E3779B9 (TEA/XTEA)")
    if _cover({4, 5}, f.shift_set(32)) >= 1.0:
        score += 0.3
        ev.append("TEA shifts <<4 and >>5")
    if f.constants & {32, 64}:
        score += 0.1
        ev.append("round count 32/64")
    return min(score, 1.0), ev


def _d_aes(f: FunctionFeatures):
    ev, score = [], 0.0
    if f.has_aesni:
        score += 0.9
        ev.append("AES-NI instructions (aesenc/aesdec/aeskeygenassist)")
    aes_tables = [t for t in f.table_refs if "AES" in t]
    if aes_tables:
        score += 0.7
        ev.append("references " + ", ".join(sorted(set(aes_tables))))
    return min(score, 1.0), ev


def _d_base64(f: FunctionFeatures):
    ev, score = [], 0.0
    if 6 in f.shift_set(32) and 0x3F in f.constants:
        score += 0.5
        ev.append("6-bit grouping (shift by 6, mask 0x3F)")
    b64 = [t for t in f.table_refs if "Base64" in t or "Base32" in t]
    if b64:
        score += 0.5
        ev.append("references " + ", ".join(sorted(set(b64))))
    return min(score, 1.0), ev


def _d_mulhash(f: FunctionFeatures):
    ev, score = [], 0.0
    if f.constants & {0x01000193, 0x811C9DC5, 0x100000001B3}:
        score += 0.6
        ev.append("FNV prime / offset basis")
    if f.op_counts.get("mul", 0) >= 1 and (5 in f.shift_set(32) or 33 in f.constants):
        score += 0.3
        ev.append("multiply/shift-add byte hash (djb2 / sdbm-like)")
    return min(score, 1.0), ev


_DETECTORS: List[Tuple[str, Callable]] = [
    ("ChaCha20", _d_chacha),
    ("Salsa20", _d_salsa),
    ("SHA-256", _d_sha256),
    ("SHA-512", _d_sha512),
    ("SHA-1", _d_sha1),
    ("MD5", _d_md5),
    ("RC4", _d_rc4),
    ("CRC", _d_crc),
    ("TEA/XTEA", _d_tea),
    ("AES", _d_aes),
    ("Base64", _d_base64),
    ("FNV/djb2 hash", _d_mulhash),
]


@dataclass
class AlgoMatch:
    algo: str
    score: float
    evidence: List[str]

    @property
    def bucket(self) -> str:
        if self.score >= 0.8:
            return "high"
        if self.score >= 0.5:
            return "medium"
        return "low"


def classify(f: FunctionFeatures, threshold: float = 0.3) -> List[AlgoMatch]:
    out = []
    for name, det in _DETECTORS:
        score, ev = det(f)
        if score >= threshold and ev:
            out.append(AlgoMatch(name, round(score, 3), ev))
    out.sort(key=lambda m: m.score, reverse=True)
    return out


def arx_summary(f: FunctionFeatures) -> str:
    """A description of ARX structure even when no named algorithm matched."""
    L = f.as_left(32) | f.as_left(64)
    if len(L) >= 2 and f.op_counts.get("xor", 0) >= 2 and f.op_counts.get("add", 0) >= 2:
        return (f"ARX structure: rotations {sorted(L)}, "
                f"xor x{f.op_counts.get('xor', 0)}, add x{f.op_counts.get('add', 0)}, "
                f"{f.loops} loop(s)")
    return ""


# --------------------------------------------------------------------------
# API-hash scheme fingerprinting (which hashing scheme does this loop use?)
# --------------------------------------------------------------------------
def detect_hash_schemes(f: FunctionFeatures) -> List[Tuple[str, str]]:
    """Guess which API-hash scheme(s) a function implements, with evidence.

    Returns a list of (scheme_name, evidence) matching the scheme ids in
    :mod:`cryptolens.apihash`.  Used to narrow constant resolution so a value is
    not force-fit to an unrelated scheme.
    """
    out: List[Tuple[str, str]] = []
    R = f.as_right(32)
    L = f.as_left(32)
    sh = f.shift_set(32)
    oc = f.op_counts

    def rot(amount: int) -> bool:
        return amount in R or (32 - amount) % 32 in L

    if rot(13):
        out.append(("ror13_add", "rotate-by-13 then add (classic shellcode)"))
    if rot(7):
        out.append(("ror7_add", "rotate-by-7 then add"))
    if rot(11):
        out.append(("ror11_add", "rotate-by-11 then add"))
    if rot(9):
        out.append(("ror9_add", "rotate-by-9 then add"))
    if f.constants & {0x01000193, 0x811C9DC5}:
        out.append(("fnv1a32", "FNV-1a prime/offset"))
        out.append(("fnv1_32", "FNV-1 prime/offset"))
    if 5381 in f.constants or (5 in sh and oc.get("add", 0) >= 1 and oc.get("mul", 0) == 0):
        out.append(("djb2", "init 5381 / shift-5 add (djb2)"))
        out.append(("djb2_xor", "init 5381 with xor (djb2a)"))
    if oc.get("mul", 0) >= 1 and 33 in f.constants:
        out.append(("djb2", "multiply-by-33 (djb2)"))
    if {6, 16} <= sh:
        out.append(("sdbm", "shift 6 and 16 (sdbm)"))
    if f.constants & {0xEDB88320, 0x04C11DB7}:
        out.append(("crc32", "CRC-32 polynomial"))

    seen = set()
    uniq = []
    for name, ev in out:
        if name in seen:
            continue
        seen.add(name)
        uniq.append((name, ev))
    return uniq
