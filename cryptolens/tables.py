"""Known lookup tables and table detection (IDA-independent, testable).

Tables are *computed* from their definitions rather than hard-coded as giant
byte literals, so there is nothing to mistype: the AES S-box comes from the
GF(2^8) inverse + affine map, the CRC tables from their polynomials, etc.
``detect_tables(buf)`` slides over a byte buffer and reports matches plus a
heuristic for custom Base64 alphabets.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import re
from typing import Dict, List, Optional, Tuple


# --------------------------------------------------------------------------
# AES S-box / inverse S-box (computed in GF(2^8), poly 0x11B)
# --------------------------------------------------------------------------
def _gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


@lru_cache(maxsize=1)
def aes_sbox() -> bytes:
    inv = [0] * 256
    # multiplicative inverse via exhaustive search (256 values, trivial)
    for a in range(256):
        for b in range(256):
            if _gmul(a, b) == 1:
                inv[a] = b
                break
    sbox = bytearray(256)
    for i in range(256):
        x = inv[i]
        s = x ^ ((x << 1) | (x >> 7)) ^ ((x << 2) | (x >> 6)) \
            ^ ((x << 3) | (x >> 5)) ^ ((x << 4) | (x >> 4))
        sbox[i] = (s ^ 0x63) & 0xFF
    return bytes(sbox)


@lru_cache(maxsize=1)
def aes_inv_sbox() -> bytes:
    s = aes_sbox()
    inv = bytearray(256)
    for i, v in enumerate(s):
        inv[v] = i
    return bytes(inv)


# --------------------------------------------------------------------------
# CRC tables (first entries used as signature)
# --------------------------------------------------------------------------
def _crc32_table(poly: int) -> List[int]:
    tbl = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (c >> 1) ^ (poly & -(c & 1))
            c &= 0xFFFFFFFF
        tbl.append(c)
    return tbl


# --------------------------------------------------------------------------
# Base64 alphabets
# --------------------------------------------------------------------------
B64_STD = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
B64_URL = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
B32_STD = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
B58_BITCOIN = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_FLICKR = b"123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"
BLAKE2_SIGMA = bytes(sum((
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
    (11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
    (7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
    (9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
    (2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
    (12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
    (13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
    (6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
    (10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
), ()))


@dataclass(frozen=True)
class TableSig:
    name: str
    signature: bytes      # distinctive prefix/full table to search for
    note: str = ""
    confidence: float = 1.0


@lru_cache(maxsize=1)
def _table_sigs() -> List[TableSig]:
    crc32 = _crc32_table(0xEDB88320)
    crc32c = _crc32_table(0x82F63B78)
    crc32k = _crc32_table(0xEB31D82E)
    crc32q = _crc32_table(0xD5828281)
    crc_bytes = b"".join(x.to_bytes(4, "little") for x in crc32[:8])
    crcc_bytes = b"".join(x.to_bytes(4, "little") for x in crc32c[:8])
    crck_bytes = b"".join(x.to_bytes(4, "little") for x in crc32k[:8])
    crcq_bytes = b"".join(x.to_bytes(4, "little") for x in crc32q[:8])
    return [
        TableSig("AES S-box", aes_sbox()[:32], "table-based AES encryption"),
        TableSig("AES inverse S-box", aes_inv_sbox()[:32], "table-based AES decryption"),
        TableSig("AES Rcon byte sequence",
                 bytes((1, 2, 4, 8, 16, 32, 64, 128, 27, 54)),
                 "AES key-schedule round constants", 0.92),
        TableSig("CRC-32 (IEEE) table", crc_bytes, "zlib/PNG/Ethernet CRC-32"),
        TableSig("CRC-32C table", crcc_bytes, "Castagnoli CRC-32C (SSE4.2)"),
        TableSig("CRC-32K table", crck_bytes, "Koopman CRC-32K"),
        TableSig("CRC-32Q table", crcq_bytes, "CRC-32Q"),
        TableSig("BLAKE2 sigma permutation", BLAKE2_SIGMA[:64],
                 "BLAKE2s/BLAKE2b message permutation"),
        TableSig("RC4 identity state", bytes(range(256)),
                 "unshuffled 256-byte RC4 KSA state", 0.75),
        TableSig("Base64 standard alphabet", B64_STD, ""),
        TableSig("Base64 URL-safe alphabet", B64_URL, ""),
        TableSig("Base32 standard alphabet", B32_STD, ""),
        TableSig("Base58 Bitcoin alphabet", B58_BITCOIN, ""),
        TableSig("Base58 Flickr alphabet", B58_FLICKR, ""),
    ]


@dataclass(frozen=True)
class TableHit:
    offset: int
    name: str
    note: str = ""
    confidence: float = 1.0


def detect_tables(buf: bytes, base: int = 0) -> List[TableHit]:
    """Find known tables and custom Base64 alphabets in ``buf``."""
    hits: List[TableHit] = []
    for ts in _table_sigs():
        start = 0
        while True:
            idx = buf.find(ts.signature, start)
            if idx < 0:
                break
            hits.append(TableHit(base + idx, ts.name, ts.note, ts.confidence))
            start = idx + 1
    hits.extend(_detect_custom_b64(buf, base))
    return hits


def _detect_custom_b64(buf: bytes, base: int) -> List[TableHit]:
    """Conservative custom-Base64 heuristic.

    A C-level regex first isolates printable runs of at least 64 bytes; rolling
    counters then require exactly 62 distinct alphanumerics plus two symbols.
    This is O(n) while avoiding a Python loop over every byte of binary data.
    """
    out: List[TableHit] = []
    known = {B64_STD, B64_URL}

    def is_alnum(b: int) -> bool:
        return (48 <= b <= 57) or (65 <= b <= 90) or (97 <= b <= 122)

    for printable_run in re.finditer(rb"[!-~]{64,}", buf):
        data = printable_run.group(0)
        counts = [0] * 256
        distinct = alnum = 0
        for i, b in enumerate(data):
            if counts[b] == 0:
                distinct += 1
            counts[b] += 1
            alnum += int(is_alnum(b))
            if i >= 64:
                old = data[i - 64]
                counts[old] -= 1
                if counts[old] == 0:
                    distinct -= 1
                alnum -= int(is_alnum(old))
            if i < 63 or distinct != 64 or alnum != 62:
                continue
            start = i - 63
            window = data[start:i + 1]
            monotonic = (all(window[j] + 1 == window[j + 1] for j in range(63))
                         or all(window[j] - 1 == window[j + 1] for j in range(63)))
            if window not in known and not monotonic:
                out.append(TableHit(
                    base + printable_run.start() + start,
                    "possible custom Base64 alphabet",
                    window.decode("ascii", "replace"), 0.68))
    return out
