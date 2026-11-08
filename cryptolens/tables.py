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


@dataclass(frozen=True)
class TableSig:
    name: str
    signature: bytes      # distinctive prefix to search for
    note: str = ""


@lru_cache(maxsize=1)
def _table_sigs() -> List[TableSig]:
    crc32 = _crc32_table(0xEDB88320)
    crc32c = _crc32_table(0x82F63B78)
    crc_bytes = b"".join(x.to_bytes(4, "little") for x in crc32[:8])
    crcc_bytes = b"".join(x.to_bytes(4, "little") for x in crc32c[:8])
    return [
        TableSig("AES S-box", aes_sbox()[:32], "table-based AES encryption"),
        TableSig("AES inverse S-box", aes_inv_sbox()[:32], "table-based AES decryption"),
        TableSig("CRC-32 (IEEE) table", crc_bytes, "zlib/PNG/Ethernet CRC-32"),
        TableSig("CRC-32C table", crcc_bytes, "Castagnoli CRC-32C (SSE4.2)"),
        TableSig("Base64 standard alphabet", B64_STD, ""),
        TableSig("Base64 URL-safe alphabet", B64_URL, ""),
        TableSig("Base32 standard alphabet", B32_STD, ""),
    ]


@dataclass(frozen=True)
class TableHit:
    offset: int
    name: str
    note: str = ""


def detect_tables(buf: bytes, base: int = 0) -> List[TableHit]:
    """Find known tables and custom Base64 alphabets in ``buf``."""
    hits: List[TableHit] = []
    for ts in _table_sigs():
        start = 0
        while True:
            idx = buf.find(ts.signature, start)
            if idx < 0:
                break
            hits.append(TableHit(base + idx, ts.name, ts.note))
            start = idx + 1
    hits.extend(_detect_custom_b64(buf, base))
    return hits


def _detect_custom_b64(buf: bytes, base: int) -> List[TableHit]:
    """Heuristic: 64 distinct printable bytes in a row -> custom alphabet."""
    out: List[TableHit] = []
    n = len(buf)
    i = 0
    known = {B64_STD, B64_URL}
    while i + 64 <= n:
        window = buf[i:i + 64]
        if all(33 <= b < 127 for b in window) and len(set(window)) == 64:
            if window not in known:
                out.append(TableHit(base + i, "possible custom Base64 alphabet",
                                    window.decode("ascii", "replace")))
            i += 64
        else:
            i += 1
    return out
