"""Tests for API hashes, memory recovery, fingerprints, and interpretation."""
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptolens import (apihash, entropy, fingerprints, memfind,  # noqa: E402
                        structure as S)


def test_apihash_scheme_detection():
    f = S.FunctionFeatures(rotations=Counter({(32, "R", 13): 4}),
                           op_counts=Counter(add=4))
    schemes = [s for s, _ in S.detect_hash_schemes(f)]
    assert "ror13_add" in schemes


def test_apihash_resolve_filtered():
    vals = {apihash.hash_name("LoadLibraryA"), apihash.hash_name("GetProcAddress")}
    hits = apihash.resolve(vals, schemes=["ror13_add"])
    names = {h.name for h in hits}
    assert {"LoadLibraryA", "GetProcAddress"} <= names


def test_aes128_expansion_vector():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    exp = memfind.expand_key(key)
    assert exp[16:20].hex() == "a0fafe17"


def test_aes_key_recovery_all_sizes():
    for ks in (16, 24, 32):
        key = os.urandom(ks)
        blob = os.urandom(100) + memfind.expand_key(key) + os.urandom(100)
        hits = memfind.find_aes_keys(blob)
        assert any(h.key == key and h.key_size == ks for h in hits)


def test_rc4_state_and_no_false_positives():
    blob = os.urandom(200) + bytes(range(256)) + os.urandom(200)
    assert any(h.offset == 200 for h in memfind.find_rc4_states(blob))
    assert memfind.find_rc4_states(os.urandom(300_000)) == []


def test_chacha_state():
    blob = b"xx" + b"expand 32-byte k" + os.urandom(48)
    hits = memfind.find_chacha_states(blob)
    assert hits and hits[0].offset == 2


def test_fingerprint_strings_and_calg():
    blob = b"..OpenSSL.." + "mbed TLS".encode("utf-16-le")
    cats = {h.category for h in fingerprints.scan_bytes(blob)}
    assert {"openssl", "mbedtls"} <= cats
    assert fingerprints.calg_name(0x6610) == "CALG_AES_256"


def test_entropy_regions():
    assert entropy.shannon(b"\x00" * 1024) == 0.0
    blob = b"\x00" * 2048 + os.urandom(8192) + b"A" * 2048
    regs = entropy.high_entropy_regions(blob)
    assert regs and regs[0].avg_entropy > 7.3


def test_interpret_general_values():
    from cryptolens import interpret
    assert any("Unix time (seconds)" in s for s in interpret.describe_value(1700000000))
    assert any("float32" in s for s in interpret.describe_value(0x40490FDB))
    assert any("x / 3" in s for s in interpret.describe_value(0xAAAAAAAB))
    # General interpretation returns a description for an unmatched value.
    assert interpret.describe_value(0x003FBDA4852ED643)
