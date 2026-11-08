"""Pytest-discoverable tests for the CryptoLens core.

These assert the same properties as ``python -m cryptolens selftest`` plus a few
extra engine and scanner behaviours.  No IDA required.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptolens import engine, fastscan, hpmath as hp, tables, util  # noqa: E402


def test_golden_ratio():
    assert hp.inv_phi_scaled(32) == 0x9E3779B9
    assert hp.inv_phi_scaled(64) == 0x9E3779B97F4A7C15
    assert util.neg(0x9E3779B9, 32) == 0x61C88647


def test_sha_md5_constants():
    assert hp.frac_root_scaled(2, 2, 32) == 0x6A09E667   # SHA-256 H0
    assert hp.frac_root_scaled(2, 3, 32) == 0x428A2F98   # SHA-256 K0
    assert hp.sqrt_scaled(2, 30) == 0x5A827999           # SHA-1
    assert hp.sin_frac_scaled(1, 32) == 0xD76AA478       # MD5 T[1]


def test_crc_relations():
    assert util.bitrev(0x04C11DB7, 32) == 0xEDB88320


def test_engine_exact():
    top = engine.explain(0x9E3779B9, 32)[0]
    assert top.kind == "named" and "TEA" in top.summary


def test_engine_transform():
    top = engine.explain(0xEDB88320, 32)[0]
    assert "CRC-32" in top.summary


def test_engine_variant_flagship():
    # One bit off the golden ratio -> flagged as a variant, not exact.
    top = engine.explain(0x9E3779F9, 32)[0]
    assert top.kind == "variant"
    assert "differs in 1 bit" in top.detail


def test_table_detection():
    sb = tables.aes_sbox()
    hits = tables.detect_tables(b"\x00" * 8 + sb)
    assert any(h.name == "AES S-box" for h in hits)


def test_fastscan_no_false_positives():
    import os as _os
    hits = fastscan.scan_buffer(_os.urandom(200_000), aligned=True)
    assert len(hits) < 20
