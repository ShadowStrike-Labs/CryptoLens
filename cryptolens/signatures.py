"""Map exact values to algorithms and roles.

Formula provenance is defined in :mod:`cryptolens.constants`; this module
records algorithm usage. Individual matches are available to value lookup.
Automatic scans use the per-signature strength and corroborated families from
:mod:`cryptolens.families`.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Dict, List, Tuple

from . import families, util


@dataclass(frozen=True)
class Signature:
    value: int
    width: int
    algorithm: str
    role: str
    note: str = ""
    family: str = ""
    strength: float = 0.72  # isolated automatic-scan strength; lookup stays exact


# (value, width, algorithm, role, note)
_RAW: List[Tuple[int, int, str, str, str]] = [
    # ---- Golden-ratio family ------------------------------------------------
    (0x9E3779B9, 32, "TEA/XTEA/XXTEA", "delta (key schedule)", "floor(2^32/phi)"),
    (0x9E3779B9, 32, "RC5/RC6", "magic Q (odd 2^32/phi)", ""),
    (0x9E3779B9, 32, "Serpent", "phi constant in key schedule", ""),
    (0x9E3779B9, 32, "boost::hash_combine / Fibonacci hashing", "mixing constant", ""),
    (0x9E3779B97F4A7C15, 64, "SplitMix64 / many PRNGs", "64-bit golden ratio increment", "floor(2^64/phi)"),
    (0x61C88647, 32, "Linux GOLDEN_RATIO_32 / Java ThreadLocalRandom", "negated golden ratio (HASH_INCREMENT)", "-0x9E3779B9 mod 2^32"),
    (0x61C8864680B583EB, 64, "Linux GOLDEN_RATIO_64", "negated 64-bit golden ratio", ""),
    (0xC6EF3720, 32, "TEA/XTEA", "sum after 32 rounds (delta*32), decrypt start", ""),
    (0x9E3779B1, 32, "xxHash32", "PRIME32_1 (prime below 2^32/phi)", ""),
    (0x9E370001, 32, "Linux (legacy) GOLDEN_RATIO_PRIME_32", "sparse golden-ratio prime", ""),

    # ---- xxHash -------------------------------------------------------------
    (0x85EBCA77, 32, "xxHash32", "PRIME32_2", ""),
    (0xC2B2AE3D, 32, "xxHash32", "PRIME32_3", ""),
    (0x27D4EB2F, 32, "xxHash32", "PRIME32_4", ""),
    (0x165667B1, 32, "xxHash32", "PRIME32_5", ""),
    (0x9E3779B185EBCA87, 64, "xxHash64", "PRIME64_1", ""),
    (0xC2B2AE3D27D4EB4F, 64, "xxHash64", "PRIME64_2", ""),
    (0x165667B19E3779F9, 64, "xxHash64", "PRIME64_3", ""),
    (0x85EBCA77C2B2AE63, 64, "xxHash64", "PRIME64_4", ""),
    (0x27D4EB2F165667C5, 64, "xxHash64", "PRIME64_5", ""),

    # ---- FNV ----------------------------------------------------------------
    (0x01000193, 32, "FNV-1 / FNV-1a", "32-bit FNV prime", ""),
    (0x811C9DC5, 32, "FNV-1 / FNV-1a", "32-bit offset basis", ""),
    (0x00000100000001B3, 64, "FNV-1 / FNV-1a", "64-bit FNV prime", ""),
    (0xCBF29CE484222325, 64, "FNV-1 / FNV-1a", "64-bit offset basis", ""),

    # ---- MD5 / SHA-1 init state --------------------------------------------
    (0x67452301, 32, "MD5 / SHA-1", "init state A / H0", ""),
    (0xEFCDAB89, 32, "MD5 / SHA-1", "init state B / H1", ""),
    (0x98BADCFE, 32, "MD5 / SHA-1", "init state C / H2", ""),
    (0x10325476, 32, "MD5 / SHA-1", "init state D / H3", ""),
    (0xC3D2E1F0, 32, "SHA-1", "init state E / H4", ""),

    # ---- SHA-256 IV (also derivable as frac(sqrt p)) -----------------------
    (0x6A09E667, 32, "SHA-256 / BLAKE2s / BLAKE3", "shared IV word 0", ""),
    (0xBB67AE85, 32, "SHA-256 / BLAKE2s / BLAKE3", "shared IV word 1", ""),

    # ---- CRC polynomials ----------------------------------------------------
    (0x04C11DB7, 32, "CRC-32 (IEEE, zlib/PNG/Ethernet)", "polynomial (normal)", ""),
    (0xEDB88320, 32, "CRC-32 (IEEE)", "polynomial (reflected)", ""),
    (0x1EDC6F41, 32, "CRC-32C (Castagnoli)", "polynomial (normal)", ""),
    (0x82F63B78, 32, "CRC-32C (Castagnoli)", "polynomial (reflected)", ""),
    (0x1021, 16, "CRC-16-CCITT / XMODEM", "polynomial (normal)", ""),
    (0x8408, 16, "CRC-16-CCITT", "polynomial (reflected)", ""),
    (0x8005, 16, "CRC-16-IBM/ANSI/MODBUS", "polynomial (normal)", ""),
    (0xA001, 16, "CRC-16-IBM/MODBUS", "polynomial (reflected)", ""),
    (0x42F0E1EBA9EA3693, 64, "CRC-64-ECMA/XZ", "polynomial (normal)", ""),
    (0xC96C5795D7870F42, 64, "CRC-64-ECMA/XZ", "polynomial (reflected)", ""),
    (0x741B8CD7, 32, "CRC-32K (Koopman)", "polynomial (normal)", ""),
    (0xEB31D82E, 32, "CRC-32K (Koopman)", "polynomial (reflected)", ""),
    (0x814141AB, 32, "CRC-32Q", "polynomial (normal)", ""),
    (0xD5828281, 32, "CRC-32Q", "polynomial (reflected)", ""),

    # ---- Universal / keyed hash and finite-field constants -----------------
    (0xE100000000000000, 64, "GHASH / AES-GCM", "GF(2^128) reduction constant", ""),
    (0x000000000001DB41, 64, "Curve25519", "Montgomery ladder constant 121665", ""),
    (0x5BD1E995, 32, "MurmurHash2", "32-bit multiplier", ""),
    (0xC6A4A7935BD1E995, 64, "MurmurHash64A", "64-bit multiplier", ""),

    # ---- ChaCha / Salsa20 "expand 32-byte k" sigma words -------------------
    (0x61707865, 32, "ChaCha20 / Salsa20", 'sigma word "expa"', "ASCII 'expa' (LE)"),
    (0x3320646E, 32, "ChaCha20 / Salsa20", 'sigma word "nd 3"', ""),
    (0x79622D32, 32, "ChaCha20 / Salsa20", 'sigma word "2-by"', ""),
    (0x6B206574, 32, "ChaCha20 / Salsa20", 'sigma word "te k"', ""),

    # ---- AES T-tables (strong indicators of table-based AES) ---------------
    (0xC66363A5, 32, "AES", "encryption T-table Te0[0]", ""),
    (0x51F4A750, 32, "AES", "decryption T-table Td0[0]", ""),

    # ---- RC5/RC6 magic P (odd (e-2)*2^w) -----------------------------------
    (0xB7E15163, 32, "RC5/RC6", "magic P (odd (e-2)*2^32)", ""),
    (0xB7E151628AED2A6B, 64, "RC5/RC6", "magic P (64-bit)", ""),

    # ---- SM4 (Chinese national standard block cipher) ----------------------
    (0xA3B1BAC6, 32, "SM4", "system parameter FK0", ""),
    (0x00070E15, 32, "SM4", "key-schedule constant CK0", ""),

    # ---- Mersenne Twister (MT19937) ----------------------------------------
    (0x6C078965, 32, "MT19937 (Mersenne Twister)", "init multiplier 1812433253", ""),
    (0x9908B0DF, 32, "MT19937", "matrix A (twist)", ""),
    (0x9D2C5680, 32, "MT19937", "tempering mask b", ""),
    (0xEFC60000, 32, "MT19937", "tempering mask c", ""),
    (0x5851F42D4C957F2D, 64, "MT19937-64 / PCG / MMIX LCG", "multiplier 6364136223846793005", ""),

    # ---- Common LCG PRNG constants -----------------------------------------
    (0x343FD, 32, "MSVC rand()", "LCG multiplier 214013", ""),
    (0x269EC3, 32, "MSVC rand()", "LCG increment 2531011", ""),
    (0x19660D, 32, "Numerical Recipes LCG", "multiplier 1664525", ""),
    (0x3C6EF35F, 32, "Numerical Recipes LCG", "increment 1013904223", ""),

    # ---- Adler-32 -----------------------------------------------------------
    (0xFFF1, 16, "Adler-32 (zlib)", "modulo prime 65521", ""),

    # ---- Tiger hash IV ------------------------------------------------------
    (0x0123456789ABCDEF, 64, "Tiger", "IV word a", ""),
    (0xFEDCBA9876543210, 64, "Tiger", "IV word b", ""),
    (0xF096A5B4C3B2E187, 64, "Tiger", "IV word c", ""),
]


def _legacy_strength(value: int, algorithm: str, role: str) -> float:
    """Return the automatic-scan strength of an isolated signature.

    Numeric match certainty and algorithm attribution are scored separately.
    Shared IVs and mixing constants require family evidence for promotion.
    """
    if "CRC" in algorithm and "polynomial" in role:
        return 0.90
    if algorithm == "AES":
        return 0.85
    if "sum after 32 rounds" in role:
        return 0.88
    if value in (0x9E3779B9, 0x9E3779B97F4A7C15):
        return 0.45
    return 0.68


@lru_cache(maxsize=1)
def _index() -> Dict[Tuple[int, int], List[Signature]]:
    idx: Dict[Tuple[int, int], List[Signature]] = {}
    seen = set()

    def add(sig: Signature) -> None:
        key = (sig.width, sig.value, sig.algorithm, sig.role)
        if key in seen:
            return
        seen.add(key)
        idx.setdefault((sig.width, sig.value), []).append(sig)

    for value, width, algo, role, note in _RAW:
        value &= util.mask(width)
        memberships = families.memberships(value, width)
        family = memberships[0][0].family_id if len(memberships) == 1 else ""
        add(Signature(value, width, algo, role, note, family,
                      _legacy_strength(value, algo, role)))
    for value, width, algo, role, note, family, strength in families.signature_rows():
        add(Signature(value & util.mask(width), width, algo, role, note,
                      family, strength))
    return idx


def lookup(value: int, width: int) -> List[Signature]:
    return _index().get((width, value & util.mask(width)), [])


def all_signatures() -> Tuple[Signature, ...]:
    return tuple(sig for sigs in _index().values() for sig in sigs)


def automatic_strength(value: int, width: int) -> float:
    sigs = lookup(value, width)
    return max((s.strength for s in sigs), default=0.0)


def all_widths() -> Tuple[int, ...]:
    return (16, 32, 64)
