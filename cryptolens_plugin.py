# -*- coding: utf-8 -*-
"""IDA Pro entry point for CryptoLens.

IDA discovers this file through ``ida-plugin.json`` and calls
``PLUGIN_ENTRY()``. The function-local plugin import is required for IDA builds
that execute entry files with separate global and local namespaces.
"""
import os
import sys

# Make the sibling ``cryptolens`` / ``cryptolens_ida`` packages importable,
# regardless of how IDA discovered this file.
_PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
if _PLUGIN_DIR not in sys.path:
    sys.path.insert(0, _PLUGIN_DIR)

# Optional override: point CRYPTOLENS_HOME at a repo checkout elsewhere.
_HOME = os.environ.get("CRYPTOLENS_HOME", "")
if _HOME and os.path.isdir(os.path.join(_HOME, "cryptolens")) and _HOME not in sys.path:
    sys.path.insert(0, _HOME)


def PLUGIN_ENTRY():
    """IDA plugin loader entry point."""
    try:
        from cryptolens_ida.plugin import CryptoLensPlugin
        return CryptoLensPlugin()
    except Exception:
        # Local imports so diagnostics survive IDA's split globals/locals exec.
        import traceback as _tb
        try:
            import ida_kernwin as _ik
            _ik.msg("[CryptoLens] PLUGIN_ENTRY failed:\n%s\n" % _tb.format_exc())
        except Exception:
            print("[CryptoLens] PLUGIN_ENTRY failed:\n%s" % _tb.format_exc())
        import ida_idaapi as _ii

        class _StubPlugin(_ii.plugin_t):
            flags = 0
            comment = "CryptoLens -- failed to load (see Output window)"
            help = comment
            wanted_name = "CryptoLens (load error)"
            wanted_hotkey = ""

            def init(self):
                return _ii.PLUGIN_SKIP

            def term(self):
                pass

            def run(self, arg):
                pass

        return _StubPlugin()
