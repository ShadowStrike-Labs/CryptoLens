"""Coverage and false-positive regression tests for the v0.3 catalogue."""
import os
import random
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptolens import (constants, engine, families, familyscan, fastscan,
                        fingerprints, signatures, structure as S, tables)


def _feat(**kw):
    f = S.FunctionFeatures()
    for key, value in kw.items():
        setattr(f, key, value)
    return f


def _rots(width, direction, amounts):
    return Counter({(width, direction, amount): 1 for amount in amounts})


def test_complete_sha2_round_tables():
    assert len(families.SHA256_K) == 64
    assert len(families.SHA512_K) == 80
    assert families.SHA256_K[0] == 0x428A2F98
    assert families.SHA256_K[-1] == 0xC67178F2
    assert families.SHA512_K[64] == 0xCA273ECEEA26619C
    assert families.SHA512_K[-1] == 0x6C44198C4A475817


def test_catalog_internal_invariants():
    specs = families.specs()
    assert len({f.family_id for f in specs}) == len(specs)
    for family in specs:
        assert family.min_hits >= 2
        assert family.min_hits <= len(set(family.values))
        assert set(family.required_any) <= set(family.values)
        assert all(0 <= v < (1 << family.width) for v in family.values)
        assert all(signatures.lookup(v, family.width) for v in family.values)


def test_xxhash64_primes_corrected():
    expected = (
        0x9E3779B185EBCA87, 0xC2B2AE3D27D4EB4F,
        0x165667B19E3779F9, 0x85EBCA77C2B2AE63,
        0x27D4EB2F165667C5,
    )
    assert families.XXH64_PRIMES == expected
    assert "PRIME64_4" in signatures.lookup(expected[3], 64)[0].role
    assert not signatures.lookup(0x60EA27EEADC0B5D6, 64)


def test_only_documented_anchor_derivations_are_generated():
    # Regression: the old cross-product produced 2,225 anchors.
    assert len(constants.anchor_table()) < 300
    assert not constants.lookup(0x243F6A89, 32)  # arbitrary pi+1
    assert constants.lookup(0xC6EF3720, 32)       # documented TEA delta*32


def test_fuzzy_prime_prefix_false_positive_removed():
    assert engine.explain(0x9E37857F, 32) == []
    hit = engine.explain(0x9E3779F9, 32)[0]
    assert hit.kind == "variant" and hit.confidence < 0.85


def test_universal_rotate_and_not_transforms_removed():
    target = 0x04C11DB7
    rotated = ((target << 5) | (target >> 27)) & 0xFFFFFFFF
    assert not any("CRC" in e.summary for e in engine.explain(rotated, 32))
    assert not any("CRC" in e.summary for e in engine.explain((~target) & 0xFFFFFFFF, 32))
    assert any("CRC" in e.summary for e in engine.explain(0xEDB88320, 32))


def test_ordered_family_sequences_at_unaligned_offsets():
    cases = (
        (families.SHA256_K, 32, "sha256_k"),
        (families.SHA512_K, 64, "sha512_k"),
        (families.MD5_T, 32, "md5_t"),
        (families.KECCAK_RC, 64, "keccak_rc"),
        (families.CAMELLIA_SIGMA, 64, "camellia_sigma"),
        (families.SM4_CK, 32, "sm4_ck"),
        (families.BLOWFISH_P, 32, "blowfish_p"),
    )
    for values, width, family_id in cases:
        packed = b"".join(v.to_bytes(width // 8, "little") for v in values)
        hits = familyscan.scan_buffer(b"X" * 13 + packed + b"Y" * 17)
        assert any(h.family_id == family_id and h.mode == "sequence" for h in hits)


def test_cluster_matching_survives_reordering():
    values = tuple(reversed(families.MURMUR3_32[:4]))
    blob = b"".join(v.to_bytes(4, "little") + b"\x00" * 12 for v in values)
    hits = familyscan.scan_buffer(blob)
    assert any(h.family_id == "murmur3_32" and h.mode == "cluster" for h in hits)


def test_benign_deterministic_buffers_have_no_family_findings():
    rng = random.Random(0xC0DEC0DE)
    random_blob = rng.getrandbits(2_000_000 * 8).to_bytes(2_000_000, "little")
    assert familyscan.scan_buffer(random_blob) == []
    structured = (bytes(range(256)) * 1024) + (b"\x00\xFF" * 131072)
    assert familyscan.scan_buffer(structured) == []


def test_custom_base64_shape_is_conservative():
    assert not any("custom Base64" in h.name
                   for h in tables.detect_tables(bytes(range(0x21, 0x61))))
    custom = b"ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210+/"
    hits = tables.detect_tables(custom)
    hit = next(h for h in hits if "custom Base64" in h.name)
    assert hit.confidence < 0.85


def test_table_adapter_uses_real_tablehit_fields():
    import cryptolens_ida.scanners as scanner
    original = scanner.iter_segments
    scanner.iter_segments = lambda: iter(((".rdata", 0x1000, 0x1100,
                                           False, tables.aes_sbox()),))
    try:
        hits = scanner.scan_tables()
    finally:
        scanner.iter_segments = original
    assert hits and hits[0].title == "AES S-box"


def test_adversarial_structure_negatives():
    # Pixel/escaping loop: byte indexing and masks but no state swaps/activity.
    pixel = _feat(mod256=2, byte_array_indexing=True, byte_mem_ops=2,
                  loops=1, constants={255})
    assert not any(m.algo == "RC4" for m in S.classify(pixel))

    # Bitfield code is not a CRC without a loop + branch.
    bitfield = _feat(shifts=Counter({(32, "R", 1): 1}),
                     op_counts=Counter(xor=2), constants={0xEDB88320})
    assert not any(m.algo == "CRC" for m in S.classify(bitfield))

    # SplitMix's 64-bit golden ratio must not be called TEA.
    splitmix = _feat(constants=set(families.SPLITMIX64),
                     shifts=Counter({(64, "R", 30): 1, (64, "R", 27): 1}),
                     op_counts=Counter(mul=2, xor=3))
    matches = S.classify(splitmix)
    assert matches and matches[0].algo == "SplitMix64"
    assert not any(m.algo == "TEA/XTEA" for m in matches)

    # Shift directions matter for TEA.
    reversed_tea = _feat(constants={0x9E3779B9},
                         shifts=Counter({(32, "R", 4): 1, (32, "L", 5): 1}))
    assert not any(m.algo == "TEA/XTEA" for m in S.classify(reversed_tea))

    assert not any(m.algo == "Base64" for m in
                   S.classify(_feat(table_refs=["Base32 standard alphabet"])))


def test_new_structural_families():
    sip = _feat(constants=set(families.SIPHASH_IV[:3]),
                rotations=_rots(64, "L", (13, 16, 17, 21, 32)),
                op_counts=Counter(add=6, xor=6))
    assert S.classify(sip)[0].algo == "SipHash"

    murmur = _feat(constants=set(families.MURMUR3_32[:3]),
                   op_counts=Counter(mul=3, xor=3))
    assert S.classify(murmur)[0].algo == "MurmurHash3"

    keccak = _feat(constants=set(families.KECCAK_RC[:4]))
    assert S.classify(keccak)[0].algo == "Keccak/SHA-3"


def test_api_hash_requires_the_claimed_operations():
    just_ror = _feat(rotations=Counter({(32, "R", 13): 2}))
    assert S.detect_hash_schemes(just_ror) == []
    ror_add = _feat(rotations=Counter({(32, "R", 13): 2}),
                    op_counts=Counter(add=2))
    assert S.detect_hash_schemes(ror_add)[0][0] == "ror13_add"

    seed_only = _feat(constants={5381}, shifts=Counter({(32, "L", 5): 1}),
                      op_counts=Counter(add=2))
    names = {name for name, _ in S.detect_hash_schemes(seed_only)}
    assert "djb2" in names and "djb2_xor" not in names


def test_binary_oid_and_added_table_fingerprints():
    rsa_oid = bytes.fromhex("06092A864886F70D010101")
    ed25519_oid = bytes.fromhex("06032B6570")
    hits = fingerprints.scan_bytes(b"xx" + rsa_oid + b"yy" + ed25519_oid)
    labels = {h.needle for h in hits}
    assert {"rsaEncryption OID", "Ed25519 OID"} <= labels

    rcon = bytes((1, 2, 4, 8, 16, 32, 64, 128, 27, 54))
    assert any(h.name == "AES Rcon byte sequence"
               for h in tables.detect_tables(b"pad" + rcon))


def test_murmurhash2_structure_requires_full_recurrence():
    positive = _feat(constants={0x5BD1E995},
                     shifts=Counter({(32, "R", 24): 1}),
                     op_counts=Counter(mul=2, xor=2))
    assert S.classify(positive)[0].algo == "MurmurHash2"
    constant_only = _feat(constants={0x5BD1E995})
    assert not any(m.algo == "MurmurHash2" for m in S.classify(constant_only))


def test_wide_tables_do_not_alias_narrow_families():
    cases = (
        (families.SHA512_K, 64, "sha256_k"),
        (families.SHA384_IV, 64, "sha224_iv"),
        (families.XXH64_PRIMES, 64, "xxh32"),
    )
    for values, width, forbidden in cases:
        blob = b"".join(v.to_bytes(width // 8, "little") for v in values)
        ids = {h.family_id for h in familyscan.scan_buffer(blob)}
        assert forbidden not in ids

    # A 64-bit array beginning at absolute address 4 mod 8 must still suppress
    # the derived 32-bit aliases.
    unaligned = b"xxxx" + b"".join(v.to_bytes(8, "little")
                                    for v in families.XXH64_PRIMES)
    ids = {h.family_id for h in familyscan.scan_buffer(unaligned)}
    assert "xxh64" in ids and "xxh32" not in ids

    # Widthless function-value matching must not truncate qwords into dwords.
    ids = {h.family_id for h in families.match_values(families.SHA384_IV)}
    assert "sha384_iv" in ids and "sha224_iv" not in ids


def test_sequence_finds_nonzero_start_fragment():
    fragment = families.SHA256_K[1:5]
    blob = b"x" * 11 + b"".join(v.to_bytes(4, "little") for v in fragment)
    hits = familyscan.scan_buffer(blob)
    assert any(h.family_id == "sha256_k" and h.mode == "sequence" for h in hits)


def test_sliding_event_windows_have_no_bucket_gap():
    events = [
        (0x0FF0, 64, families.SPLITMIX64[0]),
        (0x1008, 64, families.SPLITMIX64[1]),
    ]
    hits = familyscan.scan_events(events, window=0x1000)
    assert any(h.family_id == "splitmix64" for h in hits)


def test_sha1_and_ripemd_are_not_conflated():
    sha = _feat(constants={0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6})
    assert not any(m.algo == "RIPEMD-160" for m in S.classify(sha))

    ripemd = _feat(constants=set(families.RIPEMD160_K))
    matches = S.classify(ripemd)
    assert matches and matches[0].algo == "RIPEMD-160"
    assert not any(m.algo == "SHA-1" for m in matches)

    packed = b"".join(v.to_bytes(4, "big") for v in families.RIPEMD160_K)
    ids = {h.family_id for h in familyscan.scan_buffer(packed)}
    assert "ripemd160" in ids and "sha1_k" not in ids


def test_sparse_keccak_values_are_not_algorithm_evidence():
    sparse = {0x1, 0x88, 0x8A}
    assert not any(m.algo == "Keccak/SHA-3"
                   for m in S.classify(_feat(constants=sparse)))
    assert not any(m.family_id == "keccak_rc"
                   for m in families.match_values(sparse))


def test_typed_function_constants_suppress_split_qword_aliases():
    qwords = families.SHA384_IV[:4]
    f = S.FunctionFeatures()
    # Model x86 code referencing low/high dwords before a nearby qword xref is
    # recovered. Adding the typed qword must globally remove both aliases.
    for qword in qwords:
        f.add_constant(qword & 0xFFFFFFFF, 32)
        f.add_constant((qword >> 32) & 0xFFFFFFFF, 32)
    for qword in qwords:
        f.add_constant(qword, 64)
    narrow_ids = {m.family_id for m in
                  families.match_values(f.constants_for_width(32), width=32)}
    wide_ids = {m.family_id for m in
                families.match_values(f.constants_for_width(64), width=64)}
    assert "sha224_iv" not in narrow_ids
    assert "sha384_iv" in wide_ids


def test_ida_data_xref_probe_recovers_unaligned_qwords_with_width():
    import cryptolens_ida.funcscan as funcscan

    base = 0x1000
    table_start = base + 4
    blob = b"PAD!" + b"".join(v.to_bytes(8, "little")
                               for v in families.XXH64_PRIMES) + b"\x00" * 300

    class FakeBytes:
        @staticmethod
        def get_bytes(ea, size):
            off = ea - base
            if off < 0 or off >= len(blob):
                return None
            return blob[off:off + size]

    old_bytes = funcscan.ida_bytes
    funcscan.ida_bytes = FakeBytes()
    funcscan._CONST_CACHE.clear()
    try:
        observations = (funcscan._family_constants_at(table_start)
                        + funcscan._family_constants_at(table_start + 4))
    finally:
        funcscan.ida_bytes = old_bytes
        funcscan._CONST_CACHE.clear()

    f = S.FunctionFeatures(op_counts=Counter(mul=2, xor=2))
    for width, value in observations:
        f.add_constant(value, width)
    matches = S.classify(f)
    assert matches and matches[0].algo == "xxHash"
    assert "xxHash64" in matches[0].evidence[0]
    assert "xxh32" not in {m.family_id for m in
                            families.match_values(f.constants_for_width(32), 32)}
