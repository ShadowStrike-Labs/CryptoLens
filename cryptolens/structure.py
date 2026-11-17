"""Classify algorithms from features extracted from a function.

:mod:`cryptolens_ida.funcscan` extracts disassembly and Hex-Rays features. This
module scores those features without importing IDA. Rotation amounts are
normalized to left- and right-rotation forms before matching structural
signatures.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Set, Tuple

from . import families

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
    constants_by_width: Dict[int, Set[int]] = field(default_factory=dict)
    op_counts: Counter = field(default_factory=Counter)   # add/sub/xor/and/or/mul/not/shl/shr
    mod256: int = 0                 # count of &0xFF style byte-modular ops
    swaps: int = 0                  # explicit xchg / recovered swap patterns
    loops: int = 0
    conditional_branches: int = 0
    byte_array_indexing: bool = False
    byte_mem_ops: int = 0
    table_refs: List[str] = field(default_factory=list)
    calls: Set[str] = field(default_factory=set)
    has_aesni: bool = False
    has_sha1ni: bool = False
    has_sha256ni: bool = False
    has_shani: bool = False          # compatibility: either SHA-NI family
    sources: Set[str] = field(default_factory=set)         # 'asm', 'hexrays'

    def add_constant(self, value: int, width: int) -> None:
        """Add a typed constant and suppress dword halves of known qwords.

        Optimized x86 code often loads one 64-bit table through two 32-bit
        references. Without width preservation SHA-384 looked like SHA-224 and
        xxHash64 like xxHash32.
        """
        width = 64 if width >= 64 else 32 if width >= 32 else width
        value &= (1 << width) - 1
        self.constants.add(value)
        bucket = self.constants_by_width.setdefault(width, set())
        if width == 64:
            bucket.add(value)
            dwords = self.constants_by_width.setdefault(32, set())
            dwords.discard(value & 0xFFFFFFFF)
            dwords.discard((value >> 32) & 0xFFFFFFFF)
        elif width == 32:
            halves = set()
            for qword in self.constants_by_width.get(64, ()):
                halves.add(qword & 0xFFFFFFFF)
                halves.add((qword >> 32) & 0xFFFFFFFF)
            if value not in halves:
                bucket.add(value)
        else:
            bucket.add(value)

    def constants_for_width(self, width: int) -> Set[int]:
        if self.constants_by_width:
            return set(self.constants_by_width.get(width, ()))
        # Synthetic/tests and external users may still populate .constants
        # directly; never truncate wider values into a narrower family.
        return {v for v in self.constants if 0 <= v < (1 << width)}

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
_SIGMA_WORDS = set(families.CHACHA_SIGMA)


def _count_values(f: FunctionFeatures, values) -> int:
    values = set(values)
    width = 64 if any(v > 0xFFFFFFFF for v in values) else 32
    return len(f.constants_for_width(width) & values)


def _arx(f: FunctionFeatures, minimum: int = 4) -> bool:
    return (f.op_counts.get("xor", 0) >= minimum
            and f.op_counts.get("add", 0) >= minimum)


def _d_chacha(f: FunctionFeatures):
    ev, score = [], 0.0
    cov = _cover({16, 12, 8, 7}, f.as_left(32))
    sigma = _count_values(f, families.CHACHA_SIGMA)
    if cov < 0.75 or not _arx(f):
        return 0.0, []
    score = 0.72 + 0.12 * cov
    ev.append(f"ChaCha/BLAKE2s ARX rotations 16/12/8/7 ({int(cov * 4)}/4)")
    ev.append("observed add/xor/rotate mixing")
    if sigma >= 2:
        score += 0.30
        ev.append(f"{sigma}/4 ChaCha/Salsa sigma words")
    else:
        ev.append("no sigma corroboration; ChaCha candidate")
    return min(score, 1.0), ev


def _d_blake2s(f: FunctionFeatures):
    cov = _cover({16, 12, 8, 7}, f.as_right(32))
    iv = _count_values(f, families.SHA256_IV)
    table = any("BLAKE2" in t for t in f.table_refs)
    if cov < 0.75 or not _arx(f) or (iv < 2 and not table):
        return 0.0, []
    ev = [f"BLAKE2s right rotations 16/12/8/7 ({int(cov * 4)}/4)",
          "ARX compression structure"]
    score = 0.66
    if iv >= 2:
        score += 0.16
        ev.append(f"{iv}/8 shared SHA-256/BLAKE2s IV words")
    if table:
        score += 0.18
        ev.append("references BLAKE2 sigma permutation")
    return min(score, 1.0), ev


def _d_blake2b(f: FunctionFeatures):
    cov = _cover({32, 24, 16, 63}, f.as_right(64))
    iv = _count_values(f, families.SHA512_IV)
    table = any("BLAKE2" in t for t in f.table_refs)
    if cov < 0.75 or not _arx(f) or (iv < 2 and not table):
        return 0.0, []
    ev = [f"BLAKE2b right rotations 32/24/16/63 ({int(cov * 4)}/4)",
          "64-bit ARX compression structure"]
    score = 0.68
    if iv >= 2:
        score += 0.15
        ev.append(f"{iv}/8 shared SHA-512/BLAKE2b IV words")
    if table:
        score += 0.17
        ev.append("references BLAKE2 sigma permutation")
    return min(score, 1.0), ev


def _d_salsa(f: FunctionFeatures):
    ev = []
    cov = _cover({7, 9, 13, 18}, f.as_left(32))
    if cov < 0.75 or not _arx(f):
        return 0.0, []
    score = 0.74 + 0.12 * cov
    ev.append(f"Salsa20 rotations 7/9/13/18 ({int(cov * 4)}/4)")
    ev.append("observed add/xor/rotate mixing")
    sigma = _count_values(f, families.CHACHA_SIGMA)
    if sigma >= 2:
        score += 0.28
        ev.append(f"{sigma}/4 ChaCha/Salsa sigma words")
    return min(score, 1.0), ev


def _d_sha256(f: FunctionFeatures):
    ev, score = [], 0.0
    R = f.as_right(32)
    big = {2, 13, 22, 6, 11, 25}
    small = {7, 18, 17, 19}
    cov = _cover(big, R)
    k_hits = _count_values(f, families.SHA256_K)
    if f.has_sha256ni:
        score += 0.85
        ev.append("SHA-256-NI instructions")
    if cov >= 0.6:
        score += 0.82 * cov
        ev.append(f"SHA-256 Sigma rotations ({int(cov * 6)}/6)")
    if _cover(small, R) >= 0.5 and {3, 10} <= f.shift_set(32, "R"):
        score += 0.20
        ev.append("message schedule rotations plus >>3 and >>10")
    if k_hits >= 2:
        score += min(0.35, 0.12 + 0.04 * k_hits)
        ev.append(f"{k_hits} SHA-256 round constants")
    if score < 0.5:
        return 0.0, []
    return min(score, 1.0), ev


def _d_sha512(f: FunctionFeatures):
    ev, score = [], 0.0
    R = f.as_right(64)
    big = {28, 34, 39, 14, 18, 41}
    cov = _cover(big, R)
    k_hits = _count_values(f, families.SHA512_K)
    if cov >= 0.6:
        score += 0.82 * cov
        ev.append(f"SHA-512 64-bit Sigma rotations ({int(cov * 6)}/6)")
    if k_hits >= 2:
        score += min(0.35, 0.12 + 0.04 * k_hits)
        ev.append(f"{k_hits} SHA-512 round constants")
    if score < 0.5:
        return 0.0, []
    return min(score, 1.0), ev


def _d_sha1(f: FunctionFeatures):
    ev, score = [], 0.0
    cov = _cover({5, 30, 1}, f.as_left(32))
    hit = f.constants_for_width(32) & {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6}
    if f.has_sha1ni:
        score += 0.85
        ev.append("SHA-1-NI instructions")
    if cov >= 0.66:
        score += 0.48 * cov
        ev.append(f"SHA-1 rotations 5/30/1 ({int(cov * 3)}/3)")
    if len(hit) >= 2:
        score += 0.40
        ev.append(f"{len(hit)}/4 SHA-1 round constants")
    if score < 0.5:
        return 0.0, []
    return min(score, 1.0), ev


_MD5_ROTS = {7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21}


def _d_md5(f: FunctionFeatures):
    ev, score = [], 0.0
    cov = _cover(_MD5_ROTS, f.as_left(32))
    t_hits = _count_values(f, families.MD5_T)
    if cov >= 0.5:
        score += 0.62 * cov
        ev.append(f"MD5 per-round rotation set ({int(cov * 16)}/16)")
    if t_hits >= 3:
        score += min(0.42, 0.18 + 0.04 * t_hits)
        ev.append(f"{t_hits} MD5 sine-table constants")
    if score < 0.5:
        return 0.0, []
    return min(score, 1.0), ev


def _d_rc4(f: FunctionFeatures):
    if f.as_left(32) or not f.byte_array_indexing or f.loops < 1:
        return 0.0, []
    modular = f.mod256 > 0 or bool(f.constants & {255, 256})
    state_activity = f.swaps > 0 or f.byte_mem_ops >= 4
    if not modular or not state_activity:
        return 0.0, []
    ev = ["loop over an indexed byte state",
          "modulo-256 indexing via mask/bound"]
    score = 0.68
    if f.swaps > 0:
        score += 0.18
        ev.append(f"{f.swaps} explicit byte-state swap(s)")
    elif f.byte_mem_ops >= 4:
        score += 0.08
        ev.append(f"{f.byte_mem_ops} byte-memory operations (swap candidate)")
    return min(score, 1.0), ev


def _d_crc(f: FunctionFeatures):
    ev, score = [], 0.0
    polys = {0xEDB88320, 0x82F63B78, 0x04C11DB7, 0x1EDC6F41,
             0x741B8CD7, 0xEB31D82E, 0x814141AB, 0xD5828281,
             0x1021, 0x8408, 0x8005, 0xA001}
    hit = f.constants_for_width(32) & polys
    crc_tables = [t for t in f.table_refs if "CRC" in t]
    rsh = f.shift_set(32, "R") | f.shift_set(16, "R")
    if (1 in rsh and f.op_counts.get("xor", 0) >= 1
            and f.loops >= 1 and f.conditional_branches >= 1):
        score += 0.62
        ev.append("looped bit-at-a-time right shift with branch and XOR")
    if 8 in rsh and crc_tables:
        score += 0.72
        ev.append("table-driven CRC (>>8 plus CRC-table reference)")
    elif crc_tables:
        score += 0.62
        ev.append("references a validated CRC table")
    if hit:
        score += 0.25
        ev.append(f"CRC polynomial {_hexset(hit)}")
    if score < 0.5:
        return 0.0, []
    return min(score, 1.0), ev


def _d_tea(f: FunctionFeatures):
    ev, score = [], 0.0
    delta = f.constants_for_width(32) & {0x9E3779B9, 0xC6EF3720, 0x61C88647}
    shifts_ok = (4 in f.shift_set(32, "L") and 5 in f.shift_set(32, "R"))
    if not shifts_ok:
        return 0.0, []
    score = 0.48
    ev.append("TEA dataflow shifts <<4 and >>5")
    if delta:
        score += 0.34
        ev.append(f"TEA delta/sum {_hexset(delta)}")
    if f.constants & {32, 64}:
        score += 0.10
        ev.append("round bound 32/64")
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
    b64 = [t for t in f.table_refs if "Base64" in t]
    if b64:
        score += 0.78
        ev.append("references " + ", ".join(sorted(set(b64))))
    if (6 in f.shift_set(32) and 0x3F in f.constants
            and f.byte_array_indexing and f.loops >= 1):
        score += 0.42
        ev.append("looped byte packing with shift 6 and mask 0x3F")
    if score < 0.5:
        return 0.0, []
    return min(score, 1.0), ev


def _d_fnv(f: FunctionFeatures):
    c32 = f.constants_for_width(32) & {0x01000193, 0x811C9DC5}
    c64 = f.constants_for_width(64) & {0x100000001B3, 0xCBF29CE484222325}
    hits = c32 | c64
    if (not hits or f.op_counts.get("xor", 0) < 1
            or f.op_counts.get("mul", 0) < 1):
        return 0.0, []
    score = 0.66 + (0.20 if len(hits) >= 2 else 0.0)
    ev = [f"{len(hits)} FNV prime/offset constant(s)",
          "observed xor and multiplication hash update"]
    return min(score, 1.0), ev


def _d_djb_sdbm(f: FunctionFeatures):
    L = f.shift_set(32, "L")
    if 5381 in f.constants and 5 in L and f.op_counts.get("add", 0) >= 2:
        return 0.72, ["djb2 seed 5381 and left-shift-5/add recurrence"]
    if {6, 16} <= L and f.op_counts.get("add", 0) >= 1 and f.op_counts.get("sub", 0) >= 1:
        return 0.70, ["sdbm left shifts 6/16 with add/sub recurrence"]
    return 0.0, []


def _d_keccak(f: FunctionFeatures):
    rc_values = f.constants_for_width(64) & set(families.KECCAK_RC)
    rc = len(rc_values)
    has_high_rc = any(v & (1 << 63) for v in rc_values)
    structural = (len(f.as_left(64)) >= 6
                  and f.op_counts.get("xor", 0) >= 5
                  and f.op_counts.get("and", 0) >= 2
                  and f.op_counts.get("not", 0) >= 1)
    if (rc < 3 or not has_high_rc) and not structural:
        return 0.0, []
    ev, score = [], 0.0
    if rc >= 3:
        score += min(0.92, 0.68 + 0.04 * rc)
        ev.append(f"{rc}/24 Keccak-f[1600] round constants")
    if structural:
        score += 0.20
        ev.append("64-bit XOR/AND/NOT permutation with many rotations")
    return min(score, 1.0), ev


def _d_siphash(f: FunctionFeatures):
    iv = _count_values(f, families.SIPHASH_IV)
    cov = _cover({13, 16, 17, 21, 32}, f.as_left(64))
    if iv < 2 or cov < 0.6 or not _arx(f, 2):
        return 0.0, []
    return min(1.0, 0.55 + 0.08 * iv + 0.18 * cov), [
        f"{iv}/4 SipHash ASCII initialization constants",
        f"SipRound rotation set ({int(cov * 5)}/5)",
        "64-bit add/xor/rotate structure",
    ]


def _d_murmur3(f: FunctionFeatures):
    h32 = _count_values(f, families.MURMUR3_32)
    h64 = _count_values(f, families.MURMUR3_128)
    hits = max(h32, h64)
    if hits < 2 or f.op_counts.get("mul", 0) < 1 or f.op_counts.get("xor", 0) < 1:
        return 0.0, []
    variant = "x86-32" if h32 >= h64 else "x64-128"
    return min(0.96, 0.58 + 0.10 * hits), [
        f"{hits} MurmurHash3 {variant} body/finalizer constants",
        "multiply/xor avalanche structure",
    ]


def _d_murmur2(f: FunctionFeatures):
    if (0x5BD1E995 in f.constants_for_width(32) and f.op_counts.get("mul", 0) >= 1
            and f.op_counts.get("xor", 0) >= 1
            and 24 in f.shift_set(32, "R")):
        return 0.88, ["MurmurHash2 multiplier 0x5BD1E995",
                      "multiply/xor/right-shift-24 recurrence"]
    if (0xC6A4A7935BD1E995 in f.constants_for_width(64)
            and f.op_counts.get("mul", 0) >= 1
            and f.op_counts.get("xor", 0) >= 1
            and 47 in f.shift_set(64, "R")):
        return 0.88, ["MurmurHash64A multiplier",
                      "multiply/xor/right-shift-47 recurrence"]
    return 0.0, []


def _d_sm3(f: FunctionFeatures):
    hits = _count_values(f, families.SM3_IV + families.SM3_T)
    cov = _cover({7, 9, 12, 15, 17, 19, 23}, f.as_left(32))
    if hits < 2 and cov < 0.7:
        return 0.0, []
    score = (0.32 + 0.07 * hits) if hits >= 2 else 0.0
    if cov >= 0.7:
        score += 0.45
    if score < 0.5:
        return 0.0, []
    ev = []
    if hits:
        ev.append(f"{hits} SM3 IV/round constants")
    if cov >= 0.7:
        ev.append(f"SM3 rotation/permutation set ({int(cov * 7)}/7)")
    return min(score, 1.0), ev


def _d_ripemd160(f: FunctionFeatures):
    hit_values = f.constants_for_width(32) & set(families.RIPEMD160_K)
    unique = hit_values & {0xA953FD4E, 0x50A28BE6, 0x5C4DD124,
                           0x6D703EF3, 0x7A6D76E9}
    if len(hit_values) < 3 or not unique:
        return 0.0, []
    return min(0.95, 0.60 + 0.08 * len(hit_values)), [
        f"{len(hit_values)}/8 RIPEMD-160 round constants including "
        f"{len(unique)} unique right/late-line value(s)"
    ]


def _d_xxhash(f: FunctionFeatures):
    h32 = _count_values(f, families.XXH32_PRIMES)
    h64 = _count_values(f, families.XXH64_PRIMES)
    hits = max(h32, h64)
    if hits < 2 or f.op_counts.get("mul", 0) < 1:
        return 0.0, []
    variant = "xxHash32" if h32 >= h64 else "xxHash64"
    return min(0.96, 0.58 + 0.10 * hits), [
        f"{hits}/5 {variant} primes", "observed multiplicative hash mixing"
    ]


def _d_splitmix64(f: FunctionFeatures):
    hits = _count_values(f, families.SPLITMIX64)
    shifts = f.shift_set(64, "R")
    if (hits < 2 or not ({27, 30} & shifts)
            or f.op_counts.get("mul", 0) < 1
            or f.op_counts.get("xor", 0) < 1):
        return 0.0, []
    return 0.90, [f"{hits}/3 SplitMix64 constants",
                  "observed 64-bit xor-shift/multiply finalizer"]


def _d_camellia(f: FunctionFeatures):
    hits = _count_values(f, families.CAMELLIA_SIGMA)
    if hits < 3:
        return 0.0, []
    return min(0.98, 0.68 + 0.05 * hits), [
        f"{hits}/6 Camellia SIGMA key-schedule constants"
    ]


def _d_sm4(f: FunctionFeatures):
    fk = _count_values(f, families.SM4_FK)
    ck = _count_values(f, families.SM4_CK)
    if fk < 3 and ck < 4:
        return 0.0, []
    return min(0.98, 0.68 + 0.04 * (fk + ck)), [
        f"SM4 key schedule: {fk}/4 FK and {ck}/32 CK constants"
    ]


_DETECTORS: List[Tuple[str, Callable]] = [
    ("ChaCha20", _d_chacha),
    ("BLAKE2s", _d_blake2s),
    ("BLAKE2b", _d_blake2b),
    ("Salsa20", _d_salsa),
    ("SHA-256", _d_sha256),
    ("SHA-512", _d_sha512),
    ("SHA-1", _d_sha1),
    ("MD5", _d_md5),
    ("Keccak/SHA-3", _d_keccak),
    ("SipHash", _d_siphash),
    ("MurmurHash3", _d_murmur3),
    ("MurmurHash2", _d_murmur2),
    ("SM3", _d_sm3),
    ("RIPEMD-160", _d_ripemd160),
    ("xxHash", _d_xxhash),
    ("SplitMix64", _d_splitmix64),
    ("Camellia", _d_camellia),
    ("SM4", _d_sm4),
    ("RC4", _d_rc4),
    ("CRC", _d_crc),
    ("TEA/XTEA", _d_tea),
    ("AES", _d_aes),
    ("Base64", _d_base64),
    ("FNV-1/FNV-1a", _d_fnv),
    ("djb2/sdbm hash", _d_djb_sdbm),
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


def classify(f: FunctionFeatures, threshold: float = 0.5) -> List[AlgoMatch]:
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
                f"loops: {f.loops}")
    return ""


# --------------------------------------------------------------------------
# API-hash scheme fingerprinting (which hashing scheme does this loop use?)
# --------------------------------------------------------------------------
def detect_hash_schemes(f: FunctionFeatures) -> List[Tuple[str, str]]:
    """Guess which API-hash scheme(s) a function implements, with evidence.

    Returns a list of (scheme_name, evidence) matching the scheme ids in
    :mod:`cryptolens.apihash`. The result limits API-name resolution to
    structurally compatible schemes.
    """
    out: List[Tuple[str, str]] = []
    R = f.as_right(32)
    Lsh = f.shift_set(32, "L")
    oc = f.op_counts

    def rot(amount: int) -> bool:
        return amount in R

    # A rotate alone is common bit-twiddling; require the add recurrence used
    # by these API-name hashes.
    if oc.get("add", 0) >= 1:
        if rot(13):
            out.append(("ror13_add", "rotate-right-13 plus add recurrence"))
        if rot(7):
            out.append(("ror7_add", "rotate-right-7 plus add recurrence"))
        if rot(11):
            out.append(("ror11_add", "rotate-right-11 plus add recurrence"))
        if rot(9):
            out.append(("ror9_add", "rotate-right-9 plus add recurrence"))
    if (f.constants_for_width(32) & {0x01000193, 0x811C9DC5}
            and oc.get("mul", 0) >= 1 and oc.get("xor", 0) >= 1):
        out.append(("fnv1a32", "FNV prime/offset with multiply and xor"))
        out.append(("fnv1_32", "FNV prime/offset with multiply and xor"))
    if 5381 in f.constants and 5 in Lsh:
        if oc.get("add", 0) >= 1:
            out.append(("djb2", "seed 5381 with left-shift-5/add"))
        if oc.get("xor", 0) >= 1:
            out.append(("djb2_xor", "seed 5381 with left-shift-5/xor"))
    if oc.get("mul", 0) >= 1 and 33 in f.constants and oc.get("add", 0) >= 1:
        out.append(("djb2", "multiply-by-33 plus add"))
    if {6, 16} <= Lsh and oc.get("add", 0) >= 1 and oc.get("sub", 0) >= 1:
        out.append(("sdbm", "left shifts 6/16 with add/sub recurrence"))
    if (f.constants_for_width(32) & {0xEDB88320, 0x04C11DB7}
            and oc.get("xor", 0) >= 1 and f.loops >= 1):
        out.append(("crc32", "CRC-32 polynomial in shift/xor loop"))

    seen = set()
    uniq = []
    for name, ev in out:
        if name in seen:
            continue
        seen.add(name)
        uniq.append((name, ev))
    return uniq
