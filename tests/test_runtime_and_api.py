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


def test_bkdr131_64_kernel32_hash():
    target = 0xB1F0FE0EF080D006
    assert apihash.hash_name("kernel32.dll", "bkdr131_64") == target
    hits = apihash.identify(target, 64)
    assert any(h.scheme == "bkdr131_64" and h.name == "kernel32.dll"
               for h in hits)


def test_64bit_api_hash_schemes():
    for scheme in ("fnv1a64", "fnv1_64", "djb2_64", "djb2_xor64",
                   "sdbm64", "ror13_add64"):
        value = apihash.hash_name("GetProcAddress", scheme)
        hits = apihash.identify(value, 64)
        assert any(h.scheme == scheme and h.name == "GetProcAddress"
                   for h in hits)


def test_bkdr_loop_scheme_detection():
    f = S.FunctionFeatures(constants={131}, op_counts=Counter(mul=1, add=1))
    schemes = {name for name, _ in S.detect_hash_schemes(f)}
    assert {"bkdr131_32", "bkdr131_64"} <= schemes


def test_unstructured_hash_resolution_thresholds():
    import cryptolens_ida.apihashscan as scan

    one32 = apihash.hash_name("GetProcAddress", "ror13_add")
    hits, schemes = scan._resolve_values({one32}, [])
    assert hits == [] and schemes == []

    two32 = {
        one32,
        apihash.hash_name("LoadLibraryA", "ror13_add"),
    }
    hits, schemes = scan._resolve_values(two32, [])
    assert "ror13_add" in schemes

    one64 = apihash.hash_name("kernel32.dll", "bkdr131_64")
    hits, schemes = scan._resolve_values({one64}, [])
    assert "bkdr131_64" in schemes


def test_wrapper_uses_direct_callee_hash_scheme():
    import cryptolens_ida.apihashscan as scan

    class Func:
        def __init__(self, start, end):
            self.start_ea = start
            self.end_ea = end

    wrapper = Func(0x1000, 0x1100)
    helper = Func(0x2000, 0x2080)
    helper_features = S.FunctionFeatures(
        constants={131}, op_counts=Counter(mul=1, add=1))
    empty_features = S.FunctionFeatures()

    old_callees = scan._call_result_callees
    old_features = scan._features
    old_funcs = scan.ida_funcs

    class FakeFuncs:
        @staticmethod
        def get_func_name(ea):
            return "hash_module_name" if ea == helper.start_ea else "wrapper"

    scan._call_result_callees = lambda func: [helper]
    scan._features = lambda ea, cache=None: (
        helper_features if ea == helper.start_ea else empty_features)
    scan.ida_funcs = FakeFuncs()
    try:
        schemes, sources = scan._schemes_with_callees(wrapper, {})
    finally:
        scan._call_result_callees = old_callees
        scan._features = old_features
        scan.ida_funcs = old_funcs

    assert "bkdr131_64" in schemes
    assert any("hash_module_name" in source for source in sources)


def test_sign_extended_32bit_hash_resolution():
    value = apihash.hash_name("LoadLibraryA", "ror13_add")
    sign_extended = value | 0xFFFFFFFF00000000
    negative = value - (1 << 32)
    for widened in (sign_extended, negative):
        hits = apihash.resolve({widened}, schemes=["ror13_add"])
        assert any(h.value == value and h.name == "LoadLibraryA" for h in hits)
        default_hits = apihash.identify(widened)
        assert any(h.value == value and h.name == "LoadLibraryA"
                   for h in default_hits)
        unfiltered = apihash.resolve({widened})
        assert any(h.value == value and h.name == "LoadLibraryA"
                   for h in unfiltered)


def test_low_64bit_hash_requires_64bit_operand_width():
    import cryptolens_ida.apihashscan as scan

    value = apihash.hash_name("send", "bkdr131_64")
    assert value <= 0xFFFFFFFF
    hits32, _ = scan._resolve_values({(value, 32)}, [])
    assert not any(h.scheme == "bkdr131_64" for h in hits32)
    hits64, schemes64 = scan._resolve_values({(value, 64)}, [])
    assert any(h.scheme == "bkdr131_64" for h in hits64)
    assert "bkdr131_64" in schemes64


def test_call_result_callee_discovery():
    import cryptolens_ida.apihashscan as scan

    class Func:
        start_ea = 0x2000
        end_ea = 0x2080

    class Op:
        type = 1
        value = 0x12345678

    class Insn:
        def __init__(self):
            self.ops = []

    class FakeUtils:
        @staticmethod
        def FuncItems(start):
            return [0x1000, 0x1005, 0x1008]

        @staticmethod
        def CodeRefsFrom(ea, flow):
            return [0x2000] if ea == 0x1000 else []

    class FakeFuncs:
        @staticmethod
        def get_func(ea):
            return Func() if ea == 0x2000 else None

    class FakeUA:
        o_imm = 1
        insn_t = Insn

        @staticmethod
        def print_insn_mnem(ea):
            return {0x1000: "call", 0x1005: "mov", 0x1008: "cmp"}[ea]

    class FakeApi:
        @staticmethod
        def decode_insn(insn, ea):
            # x86-64 loads an arbitrary 64-bit constant before register compare.
            insn.ops = [Op()] if ea == 0x1005 else []
            return 1

    saved = (scan.idautils, scan.ida_funcs, scan.ida_ua, scan.idaapi)
    scan.idautils, scan.ida_funcs = FakeUtils(), FakeFuncs()
    scan.ida_ua, scan.idaapi = FakeUA(), FakeApi()
    try:
        callees = scan._call_result_callees(type("Wrapper", (), {"start_ea": 0x1000})())
    finally:
        scan.idautils, scan.ida_funcs, scan.ida_ua, scan.idaapi = saved
    assert len(callees) == 1 and callees[0].start_ea == 0x2000


def test_enum_result_tracks_width_and_write_failures():
    import cryptolens_ida.apihashscan as scan

    calls = {"width": [], "members": []}

    class FakeApi:
        BADADDR = 0xFFFFFFFFFFFFFFFF

    class FakeIdc:
        @staticmethod
        def get_enum(name):
            return 7

        @staticmethod
        def set_enum_width(eid, width):
            calls["width"].append((eid, width))
            return True

        @staticmethod
        def get_enum_member(eid, value, serial, mask):
            return mask

        @staticmethod
        def add_enum_member(eid, name, value, mask):
            calls["members"].append((name, value))
            return 0 if "accepted" in name else 1

    saved = (scan.idc, scan.idaapi)
    scan.idc, scan.idaapi = FakeIdc(), FakeApi()
    try:
        eid, accepted = scan._make_enum({
            "accepted": (0x1234, 64),
            "rejected": (0x5678, 32),
        })
    finally:
        scan.idc, scan.idaapi = saved

    assert eid == 7
    assert calls["width"] == [(7, 8)]
    assert (0x1234, 64) in accepted
    assert (0x5678, 32) not in accepted


def test_failed_enum_width_rejects_64bit_members():
    import cryptolens_ida.apihashscan as scan

    member_calls = []

    class FakeApi:
        BADADDR = 0xFFFFFFFFFFFFFFFF

    class FakeIdc:
        @staticmethod
        def get_enum(name):
            return 9

        @staticmethod
        def get_enum_width(eid):
            return 4

        @staticmethod
        def set_enum_width(eid, width):
            return False

        @staticmethod
        def get_enum_member(eid, value, serial, mask):
            return mask

        @staticmethod
        def add_enum_member(eid, name, value, mask):
            member_calls.append((name, value))
            return 0

    saved = (scan.idc, scan.idaapi)
    scan.idc, scan.idaapi = FakeIdc(), FakeApi()
    try:
        eid, accepted = scan._make_enum({"low64": (0x1234, 64)})
    finally:
        scan.idc, scan.idaapi = saved

    assert eid == 9
    assert accepted == set()
    assert member_calls == []


def test_feature_candidates_preserve_widths():
    import cryptolens_ida.apihashscan as scan

    features = S.FunctionFeatures()
    features.add_constant(0x0F8387DC, 32)
    values = scan._feature_values(features)
    assert (0x0F8387DC, 32) in values
    assert (0x0F8387DC, 64) not in values
    assert 0x0F8387DC not in values


def test_bulk_resolution_preserves_feature_widths():
    import cryptolens_ida.apihashscan as scan

    class Func:
        start_ea = 0x1000
        end_ea = 0x1080

    features = S.FunctionFeatures()
    features.add_constant(apihash.hash_name("send", "bkdr131_64"), 32)

    class FakeUtils:
        @staticmethod
        def Functions():
            return [0x1000]

    class FakeFuncs:
        @staticmethod
        def get_func(ea):
            return Func()

        @staticmethod
        def get_func_name(ea):
            return "candidate"

    saved = (scan.idautils, scan.ida_funcs, scan._features,
             scan._schemes_with_callees, scan._collect_imms, scan.msg)
    scan.idautils, scan.ida_funcs = FakeUtils(), FakeFuncs()
    scan._features = lambda ea, cache=None: features
    scan._schemes_with_callees = lambda func, cache=None: ([], [])
    scan._collect_imms = lambda func: {}
    scan.msg = lambda text: None
    try:
        text, findings = scan.resolve_in_binary(
            create_enum=False, apply_operands=False)
    finally:
        (scan.idautils, scan.ida_funcs, scan._features,
         scan._schemes_with_callees, scan._collect_imms, scan.msg) = saved

    assert findings == []
    assert "matches: 0" in text
