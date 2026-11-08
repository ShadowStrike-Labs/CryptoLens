"""Runtime-memory recovery helpers (IDA-independent, testable).

Used by the debugger memory scan, but pure: give it a byte buffer and it finds

* AES key schedules - by re-deriving the expansion from each candidate key and
  checking it against the following bytes (the aeskeyfind idea); this recovers
  the actual key, for AES-128/192/256.
* RC4 states - 256-byte windows that are a permutation of 0..255 (found with an
  O(n) rolling distinct-byte count).
* ChaCha/Salsa states - the literal "expand 32-byte k" constant block.

None of this needs any magic constant to be present in the image on disk, which
is the whole point of scanning live memory.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .tables import aes_sbox

_SBOX = aes_sbox()
# Rcon[i] = x^(i-1) in GF(2^8), 1-based index.
_RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
         0x6C, 0xD8, 0xAB, 0x4D]

_PARAMS = {16: (4, 10), 24: (6, 12), 32: (8, 14)}   # key_size -> (Nk, Nr)


def _rotword(w: bytes) -> bytes:
    return w[1:] + w[:1]


def _subword(w: bytes) -> bytes:
    return bytes(_SBOX[b] for b in w)


def _xor4(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def expand_key(key: bytes) -> bytes:
    """AES key expansion. Returns the full expanded key (incl. the key itself)."""
    nk, nr = _PARAMS[len(key)]
    total = 4 * (nr + 1)
    w = [key[4 * i:4 * i + 4] for i in range(nk)]
    for i in range(nk, total):
        temp = w[i - 1]
        if i % nk == 0:
            temp = _subword(_rotword(temp))
            temp = bytes([temp[0] ^ _RCON[i // nk], temp[1], temp[2], temp[3]])
        elif nk == 8 and i % nk == 4:
            temp = _subword(temp)
        w.append(_xor4(w[i - nk], temp))
    return b"".join(w)


def _schedule_matches(buf: bytes, off: int, key_size: int) -> bool:
    """True if buf[off:] begins with a valid expanded key of this size.

    Generates words one at a time and bails on the first mismatch, so almost
    every offset is rejected after comparing the first derived 4 bytes.
    """
    nk, nr = _PARAMS[key_size]
    total = 4 * (nr + 1)
    if off + total * 4 > len(buf):
        return False
    w = [buf[off + 4 * i:off + 4 * i + 4] for i in range(nk)]
    for i in range(nk, total):
        temp = w[i - 1]
        if i % nk == 0:
            temp = _subword(_rotword(temp))
            temp = bytes([temp[0] ^ _RCON[i // nk], temp[1], temp[2], temp[3]])
        elif nk == 8 and i % nk == 4:
            temp = _subword(temp)
        wi = _xor4(w[i - nk], temp)
        if wi != buf[off + 4 * i:off + 4 * i + 4]:
            return False
        w.append(wi)
    return True


@dataclass
class AesKeyHit:
    offset: int
    key_size: int          # 16 / 24 / 32
    key: bytes

    @property
    def key_hex(self) -> str:
        return self.key.hex()


def find_aes_keys(buf: bytes, base: int = 0,
                  key_sizes=(16, 24, 32)) -> List[AesKeyHit]:
    hits: List[AesKeyHit] = []
    n = len(buf)
    for off in range(0, n - 32):
        for ks in key_sizes:
            if _schedule_matches(buf, off, ks):
                hits.append(AesKeyHit(base + off, ks, bytes(buf[off:off + ks])))
                break
    return hits


@dataclass
class Rc4StateHit:
    offset: int


def find_rc4_states(buf: bytes, base: int = 0) -> List[Rc4StateHit]:
    """256-byte windows that are a permutation of 0..255 (O(n) rolling count)."""
    out: List[Rc4StateHit] = []
    counts = [0] * 256
    distinct = 0
    n = len(buf)
    for i in range(n):
        b = buf[i]
        counts[b] += 1
        if counts[b] == 1:
            distinct += 1
        if i >= 256:
            ob = buf[i - 256]
            counts[ob] -= 1
            if counts[ob] == 0:
                distinct -= 1
        if i >= 255 and distinct == 256:
            out.append(Rc4StateHit(base + i - 255))
    return out


@dataclass
class ChaChaStateHit:
    offset: int


def find_chacha_states(buf: bytes, base: int = 0) -> List[ChaChaStateHit]:
    out: List[ChaChaStateHit] = []
    needle = b"expand 32-byte k"
    start = 0
    while True:
        idx = buf.find(needle, start)
        if idx < 0:
            break
        out.append(ChaChaStateHit(base + idx))
        start = idx + 1
    return out
