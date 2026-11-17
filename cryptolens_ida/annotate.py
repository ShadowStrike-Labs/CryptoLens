"""Write CryptoLens findings back into the IDB as comments and colors."""
from __future__ import annotations

from typing import Iterable

from .ida_shim import HAVE_IDA, ida_bytes, idc
from .scanners import Finding

# IDA item colors are encoded as BGR integers.
_COLORS = {
    "instruction": 0x90EE90,
    "table": 0xE0C0FF,
    "family": 0xA8E6CF,
    "constant": 0xC0E0FF,
    "immediate": 0xC0FFFF,
    "function": 0xB0E0B0,
    "apihash": 0xB0D0FF,
    "memory": 0xFFD0B0,
    "fingerprint": 0xD0FFD0,
    "entropy": 0xD0D0D0,
}
_PREFIX = "CryptoLens: "


def apply_comment(f: Finding) -> None:
    text = _PREFIX + f.title
    if f.detail:
        text += f" [{f.detail}]"
    existing = ida_bytes.get_cmt(f.ea, False) or ""
    if _PREFIX in existing:
        return
    merged = (existing + " | " if existing else "") + text
    ida_bytes.set_cmt(f.ea, merged, False)


def apply_color(f: Finding) -> None:
    color = _COLORS.get(f.category)
    if color is not None:
        idc.set_color(f.ea, idc.CIC_ITEM, color)


def apply_all(findings: Iterable[Finding], do_comment: bool = True,
              do_color: bool = True) -> int:
    if not HAVE_IDA:
        raise RuntimeError("annotate requires IDA")
    count = 0
    for f in findings:
        if f.ea == 0:
            continue
        if do_comment:
            apply_comment(f)
        if do_color:
            apply_color(f)
        count += 1
    return count
