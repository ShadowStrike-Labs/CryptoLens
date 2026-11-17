"""Corroborated constant families and sequence matching.

A single integer can identify a *numeric value* exactly without identifying the
algorithm that uses it.  For automatic scans CryptoLens therefore promotes an
algorithm only when several related constants occur together, or when an
ordered constant table is present.  Manual lookup can still explain every
individual member.

The catalogue below favors standards and reference implementations.  Sources:
FIPS 180-4/202, RFC 7693 (BLAKE2), RFC 3713 (Camellia), the SipHash reference,
Appleby's SMHasher reference, and the xxHash reference header.  See SOURCES.md.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from . import hpmath as hp, util


@dataclass(frozen=True)
class FamilySpec:
    family_id: str
    name: str
    width: int
    values: Tuple[int, ...]
    roles: Tuple[str, ...] = ()
    min_hits: int = 2
    sequence_min: int = 0
    required_any: Tuple[int, ...] = ()
    category: str = "hash"
    source: str = ""

    def role(self, index: int) -> str:
        if index < len(self.roles):
            return self.roles[index]
        if self.family_id.endswith("_iv"):
            return f"IV[{index}]"
        if self.family_id.endswith("_k"):
            return f"K[{index}]"
        if self.family_id == "md5_t":
            return f"T[{index + 1}]"
        if self.family_id == "keccak_rc":
            return f"RC[{index}]"
        return f"constant[{index}]"


@dataclass(frozen=True)
class FamilyMatch:
    family_id: str
    name: str
    width: int
    matched: Tuple[int, ...]
    score: float
    evidence: str
    offset: int = 0
    mode: str = "cluster"       # cluster | sequence
    source: str = ""

    @property
    def bucket(self) -> str:
        if self.score >= 0.85:
            return "high"
        if self.score >= 0.60:
            return "medium"
        return "low"


_PRIMES80 = (
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
    67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137,
    139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211,
    223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
    293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379,
    383, 389, 397, 401, 409,
)


def _root_words(k: int, width: int, count: int) -> Tuple[int, ...]:
    return tuple(hp.frac_root_scaled(p, k, width) for p in _PRIMES80[:count])


def _pi_words(count: int) -> Tuple[int, ...]:
    bits = 32 * count
    frac = hp.pi_scaled(bits) - (3 << bits)
    return tuple((frac >> (bits - 32 * (i + 1))) & 0xFFFFFFFF
                 for i in range(count))


def _sm4_ck() -> Tuple[int, ...]:
    return tuple(int.from_bytes(bytes(((4 * i + j) * 7) & 0xFF
                                      for j in range(4)), "big")
                 for i in range(32))


SHA256_IV = _root_words(2, 32, 8)
SHA512_IV = _root_words(2, 64, 8)
SHA256_K = _root_words(3, 32, 64)
SHA512_K = _root_words(3, 64, 80)
MD5_T = tuple(hp.sin_frac_scaled(i, 32) for i in range(1, 65))
BLOWFISH_P = _pi_words(18)

SHA224_IV = (
    0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
    0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4,
)
SHA384_IV = (
    0xCBBB9D5DC1059ED8, 0x629A292A367CD507,
    0x9159015A3070DD17, 0x152FECD8F70E5939,
    0x67332667FFC00B31, 0x8EB44A8768581511,
    0xDB0C2E0D64F98FA7, 0x47B5481DBEFA4FA4,
)
SHA512_224_IV = (
    0x8C3D37C819544DA2, 0x73E1996689DCD4D6,
    0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF,
    0x0F6D2B697BD44DA8, 0x77E36F7304C48942,
    0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1,
)
SHA512_256_IV = (
    0x22312194FC2BF72C, 0x9F555FA3C84C64C2,
    0x2393B86B6F53B151, 0x963877195940EABD,
    0x96283EE2A88EFFE3, 0xBE5E1E2553863992,
    0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2,
)

KECCAK_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)

SIPHASH_IV = (
    0x736F6D6570736575, 0x646F72616E646F6D,
    0x6C7967656E657261, 0x7465646279746573,
)

MURMUR3_32 = (0xCC9E2D51, 0x1B873593, 0xE6546B64,
              0x85EBCA6B, 0xC2B2AE35)
MURMUR3_128 = (0x87C37B91114253D5, 0x4CF5AD432745937F,
               0xFF51AFD7ED558CCD, 0xC4CEB9FE1A85EC53)

SM3_IV = (0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
          0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E)
SM3_T = (0x79CC4519, 0x7A879D8A)
RIPEMD160_K = (0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E,
               0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9)
CAMELLIA_SIGMA = (
    0xA09E667F3BCC908B, 0xB67AE8584CAA73B2,
    0xC6EF372FE94F82BE, 0x54FF53A5F1D36F1C,
    0x10E527FADE682D1D, 0xB05688C2B3E6C1FD,
)
SM4_FK = (0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC)
SM4_CK = _sm4_ck()

XXH32_PRIMES = (0x9E3779B1, 0x85EBCA77, 0xC2B2AE3D,
                0x27D4EB2F, 0x165667B1)
XXH64_PRIMES = (0x9E3779B185EBCA87, 0xC2B2AE3D27D4EB4F,
                0x165667B19E3779F9, 0x85EBCA77C2B2AE63,
                0x27D4EB2F165667C5)
SPLITMIX64 = (0x9E3779B97F4A7C15, 0xBF58476D1CE4E5B9,
              0x94D049BB133111EB)
CITYHASH64 = (0xC3A5C85C97CB3127, 0xB492B66FBE98F273,
              0x9AE16A3B2F90404F, 0x9DDFEA08EB382D69)
CHACHA_SIGMA = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
AES_RCON32 = (0x01000000, 0x02000000, 0x04000000, 0x08000000,
              0x10000000, 0x20000000, 0x40000000, 0x80000000,
              0x1B000000, 0x36000000)


@lru_cache(maxsize=1)
def specs() -> Tuple[FamilySpec, ...]:
    f = FamilySpec
    return (
        f("sha256_k", "SHA-224/SHA-256 round constants", 32, SHA256_K,
          min_hits=4, sequence_min=4, source="FIPS 180-4"),
        f("sha512_k", "SHA-384/SHA-512 round constants", 64, SHA512_K,
          min_hits=4, sequence_min=4, source="FIPS 180-4"),
        f("sha2_32_iv", "SHA-256 / BLAKE2s / BLAKE3 IV", 32, SHA256_IV,
          min_hits=4, sequence_min=4, source="FIPS 180-4; RFC 7693"),
        f("sha224_iv", "SHA-224 IV", 32, SHA224_IV,
          min_hits=4, sequence_min=4, source="FIPS 180-4"),
        f("sha2_64_iv", "SHA-512 / BLAKE2b IV", 64, SHA512_IV,
          min_hits=4, sequence_min=4, source="FIPS 180-4; RFC 7693"),
        f("sha384_iv", "SHA-384 IV", 64, SHA384_IV,
          min_hits=4, sequence_min=4, source="FIPS 180-4"),
        f("sha512_224_iv", "SHA-512/224 IV", 64, SHA512_224_IV,
          min_hits=4, sequence_min=4, source="FIPS 180-4"),
        f("sha512_256_iv", "SHA-512/256 IV", 64, SHA512_256_IV,
          min_hits=4, sequence_min=4, source="FIPS 180-4"),
        f("md5_t", "MD5 sine-derived round table", 32, MD5_T,
          min_hits=4, sequence_min=4, source="RFC 1321"),
        f("sha1_k", "SHA-1 round constants", 32,
          (0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6),
          min_hits=3, sequence_min=3, required_any=(0xCA62C1D6,),
          source="FIPS 180-4"),
        f("keccak_rc", "Keccak-f[1600] / SHA-3 round constants", 64, KECCAK_RC,
          min_hits=3, sequence_min=3,
          required_any=tuple(v for v in KECCAK_RC if v & (1 << 63)),
          source="FIPS 202"),
        f("siphash_iv", "SipHash initialization constants", 64, SIPHASH_IV,
          roles=("v0 ASCII constant", "v1 ASCII constant", "v2 ASCII constant",
                 "v3 ASCII constant"), min_hits=3, sequence_min=3,
          category="keyed hash", source="SipHash reference"),
        f("murmur3_32", "MurmurHash3 x86-32", 32, MURMUR3_32,
          roles=("body multiplier c1", "body multiplier c2", "round addend",
                 "fmix32 multiplier 1", "fmix32 multiplier 2"), min_hits=3,
          sequence_min=0, category="non-crypto hash", source="SMHasher"),
        f("murmur3_128", "MurmurHash3 x64-128", 64, MURMUR3_128,
          roles=("body multiplier c1", "body multiplier c2",
                 "fmix64 multiplier 1", "fmix64 multiplier 2"), min_hits=3,
          category="non-crypto hash", source="SMHasher"),
        f("sm3", "SM3 hash", 32, SM3_IV + SM3_T,
          roles=tuple(f"IV[{i}]" for i in range(8)) + ("T[0..15]", "T[16..63]"),
          min_hits=3, sequence_min=4, source="GB/T 32905 / CFRG draft"),
        f("ripemd160", "RIPEMD-160 round constants", 32, RIPEMD160_K,
          min_hits=3, sequence_min=3,
          required_any=(0xA953FD4E, 0x50A28BE6, 0x5C4DD124,
                        0x6D703EF3, 0x7A6D76E9),
          source="RIPEMD-160 specification"),
        f("camellia_sigma", "Camellia key-schedule SIGMA constants", 64,
          CAMELLIA_SIGMA, roles=tuple(f"SIGMA{i}" for i in range(1, 7)),
          min_hits=3, sequence_min=3, category="block cipher", source="RFC 3713"),
        f("sm4_fk", "SM4 system parameters FK", 32, SM4_FK,
          roles=tuple(f"FK{i}" for i in range(4)), min_hits=3, sequence_min=3,
          category="block cipher", source="GM/T 0002"),
        f("sm4_ck", "SM4 key-schedule constants CK", 32, SM4_CK,
          roles=tuple(f"CK{i}" for i in range(32)), min_hits=4, sequence_min=4,
          category="block cipher", source="GM/T 0002"),
        f("blowfish_p", "Blowfish P-array (pi digits)", 32, BLOWFISH_P,
          roles=tuple(f"P[{i}]" for i in range(18)), min_hits=4, sequence_min=4,
          category="block cipher", source="Blowfish specification"),
        f("xxh32", "xxHash32 prime family", 32, XXH32_PRIMES,
          roles=tuple(f"PRIME32_{i}" for i in range(1, 6)), min_hits=3,
          category="non-crypto hash", source="xxHash reference"),
        f("xxh64", "xxHash64 prime family", 64, XXH64_PRIMES,
          roles=tuple(f"PRIME64_{i}" for i in range(1, 6)), min_hits=3,
          category="non-crypto hash", source="xxHash reference"),
        f("splitmix64", "SplitMix64 generator/finalizer", 64, SPLITMIX64,
          roles=("golden-ratio increment", "mix multiplier 1", "mix multiplier 2"),
          min_hits=2, category="PRNG", source="SplitMix64 reference"),
        f("cityhash64", "CityHash/FarmHash 64-bit constants", 64, CITYHASH64,
          roles=("k0", "k1", "k2", "kMul"), min_hits=2,
          category="non-crypto hash", source="Google CityHash reference"),
        f("chacha_sigma", "ChaCha20/Salsa20 sigma words", 32, CHACHA_SIGMA,
          roles=('"expa"', '"nd 3"', '"2-by"', '"te k"'), min_hits=3,
          sequence_min=3, category="stream cipher", source="RFC 8439"),
        f("aes_rcon", "AES key-schedule Rcon words", 32, AES_RCON32,
          roles=tuple(f"Rcon[{i}]" for i in range(1, 11)), min_hits=8,
          sequence_min=4, category="block cipher", source="FIPS 197"),
        f("fnv32", "FNV-1/FNV-1a 32-bit", 32, (0x01000193, 0x811C9DC5),
          roles=("FNV prime", "offset basis"), min_hits=2,
          category="non-crypto hash", source="IETF FNV draft"),
        f("fnv64", "FNV-1/FNV-1a 64-bit", 64,
          (0x00000100000001B3, 0xCBF29CE484222325),
          roles=("FNV prime", "offset basis"), min_hits=2,
          category="non-crypto hash", source="IETF FNV draft"),
        f("rc5_32", "RC5/RC6 32-bit magic pair", 32,
          (0xB7E15163, 0x9E3779B9), roles=("P32", "Q32"), min_hits=2,
          category="block cipher", source="RFC 2040 / RC6 specification"),
        f("tiger_iv", "Tiger hash IV", 64,
          (0x0123456789ABCDEF, 0xFEDCBA9876543210, 0xF096A5B4C3B2E187),
          roles=("IV a", "IV b", "IV c"), min_hits=3, sequence_min=3,
          source="Tiger specification"),
    )


@lru_cache(maxsize=1)
def by_id() -> Dict[str, FamilySpec]:
    return {f.family_id: f for f in specs()}


@lru_cache(maxsize=1)
def value_index() -> Dict[Tuple[int, int], Tuple[Tuple[FamilySpec, int], ...]]:
    idx: Dict[Tuple[int, int], List[Tuple[FamilySpec, int]]] = {}
    for fam in specs():
        for i, value in enumerate(fam.values):
            idx.setdefault((fam.width, value & util.mask(fam.width)), []).append((fam, i))
    return {k: tuple(v) for k, v in idx.items()}


def memberships(value: int, width: int) -> Tuple[Tuple[FamilySpec, int], ...]:
    return value_index().get((width, value & util.mask(width)), ())


def match_values(values: Iterable[int], width: Optional[int] = None,
                 threshold: float = 0.60) -> List[FamilyMatch]:
    vals = set(values)
    out: List[FamilyMatch] = []
    for fam in specs():
        if width is not None and fam.width != width:
            continue
        vals_for_width = {v for v in vals if 0 <= v <= util.mask(fam.width)}
        matched = tuple(v for v in fam.values if v in vals_for_width)
        distinct = len(set(matched))
        if distinct < fam.min_hits:
            continue
        if fam.required_any and not (vals_for_width & set(fam.required_any)):
            continue
        coverage = distinct / len(set(fam.values))
        score = min(0.99, 0.66 + 0.055 * distinct
                    + 0.15 * min(coverage, 0.5))
        if score < threshold:
            continue
        out.append(FamilyMatch(
            fam.family_id, fam.name, fam.width, tuple(dict.fromkeys(matched)),
            round(score, 3),
            f"{distinct}/{len(set(fam.values))} related constants co-occur",
            source=fam.source,
        ))
    out.sort(key=lambda m: (-m.score, -len(m.matched), m.name))
    return out


def signature_rows():
    """Rows consumed by :mod:`signatures` for individual-value lookup."""
    for fam in specs():
        for i, value in enumerate(fam.values):
            # Individual family members are valid numeric matches but usually
            # need co-occurrence before automatic algorithm attribution.
            yield (value, fam.width, fam.name, fam.role(i), fam.source,
                   fam.family_id, 0.68)
