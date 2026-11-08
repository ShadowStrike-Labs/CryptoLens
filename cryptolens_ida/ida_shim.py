"""Thin shim over the IDA SDK so the rest of the package imports cleanly.

All IDA modules are imported here behind ``HAVE_IDA``.  Non-IDA logic lives in
the ``cryptolens`` core package; this layer only does I/O against the IDB.
"""
from __future__ import annotations

HAVE_IDA = True
try:
    import ida_bytes
    import ida_dbg
    import ida_funcs
    import ida_idd
    import ida_kernwin
    import ida_nalt
    import ida_segment
    import ida_ua
    import idaapi
    import idautils
    import idc
except Exception:  # pragma: no cover - only outside IDA
    HAVE_IDA = False
    ida_bytes = ida_funcs = ida_kernwin = ida_nalt = None
    ida_segment = ida_ua = idaapi = idautils = idc = None
    ida_dbg = ida_idd = None


def require_ida() -> None:
    if not HAVE_IDA:
        raise RuntimeError("CryptoLens IDA layer must run inside IDA Pro")


def msg(text: str) -> None:
    if HAVE_IDA:
        ida_kernwin.msg(text)
    else:  # pragma: no cover
        print(text, end="")
