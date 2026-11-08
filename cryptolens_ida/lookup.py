"""Interactive 'paste a number' lookup panel (dockable text viewer).

Accepts a hex/decimal value, a byte blob, or a 'quoted string' and shows the
full CryptoLens explanation: exact match, variant-of, API-hash, ASCII, tables,
plus general interpretations (timestamp / float / division-magic / pointer) so
even non-crypto constants from obfuscated binaries are explained.

Analysis is delegated to the testable core (:func:`cryptolens.report.lookup_text`).
"""
from __future__ import annotations

from cryptolens import report

from .ida_shim import (HAVE_IDA, ida_bytes, ida_kernwin, ida_ua, idaapi)


def _parse_ida_number(token: str):
    """Parse a token as IDA might render a constant (0x.., ..h, decimal)."""
    if not token:
        return None
    t = token.strip().replace("_", "")
    try:
        if t.lower().startswith("0x"):
            return int(t, 16)
        if t[-1] in "hH" and all(c in "0123456789abcdefABCDEF" for c in t[:-1]):
            return int(t[:-1], 16)
        if all(c in "0123456789abcdefABCDEF" for c in t) and any(c in "abcdefABCDEF" for c in t):
            return int(t, 16)
        return int(t, 10)
    except ValueError:
        return None


if HAVE_IDA:

    class LookupPanel(ida_kernwin.simplecustviewer_t):
        TITLE = "CryptoLens Lookup"

        def create(self) -> bool:
            if not self.Create(self.TITLE):
                return False
            self.ClearLines()
            self.AddLine("CryptoLens lookup.  Query (Ctrl-Shift-L) to type a "
                         "value, or put the cursor/highlight on a constant and "
                         "use 'Lookup value under cursor'.")
            self.AddLine("Accepts: 0x9E3779B9 | 2654435769 | de ad be ef | "
                         "'expand 32-byte k'.  Explains crypto constants, "
                         "variants, API hashes, timestamps, floats and more.")
            self.Refresh()
            return True

        def append_report(self, user_input: str, note: str = "") -> None:
            self.AddLine("")
            self.AddLine("=" * 64)
            self.AddLine(f">>> {user_input}" + (f"   [{note}]" if note else ""))
            for line in report.lookup_text(user_input).splitlines():
                self.AddLine(line)
            self.Refresh()
            self.Jump(self.Count() - 1)

    _PANEL = {"inst": None}

    def get_panel() -> "LookupPanel":
        panel = _PANEL["inst"]
        if panel is None:
            panel = LookupPanel()
            panel.create()
            _PANEL["inst"] = panel
        panel.Show()
        return panel

    def prompt_and_query() -> None:
        s = ida_kernwin.ask_str("", 0, "CryptoLens: number / bytes / 'string'")
        if not s:
            return
        get_panel().append_report(s)

    def _value_under_cursor():
        """Find a number at the cursor: highlighted token, then immediate,
        then the data item value. Returns (value, source) or (None, '')."""
        # 1) Highlighted identifier (works in disassembly / pseudocode / hex).
        try:
            viewer = ida_kernwin.get_current_viewer()
            hl = ida_kernwin.get_highlight(viewer)
            if hl and hl[0]:
                val = _parse_ida_number(hl[0])
                if val is not None:
                    return val, f"highlight '{hl[0]}'"
        except Exception:
            pass
        # 2) Immediate operand of the instruction at the cursor.
        ea = ida_kernwin.get_screen_ea()
        try:
            insn = ida_ua.insn_t()
            if idaapi.decode_insn(insn, ea) > 0:
                for op in insn.ops:
                    if op.type == ida_ua.o_imm:
                        return op.value, f"immediate @ 0x{ea:X}"
        except Exception:
            pass
        # 3) The data value at the cursor (qword / dword / word).
        try:
            flags = ida_bytes.get_full_flags(ea)
            if ida_bytes.is_qword(flags):
                return ida_bytes.get_qword(ea), f"qword @ 0x{ea:X}"
            if ida_bytes.is_dword(flags):
                return ida_bytes.get_dword(ea), f"dword @ 0x{ea:X}"
            if ida_bytes.is_word(flags):
                return ida_bytes.get_wide_word(ea), f"word @ 0x{ea:X}"
        except Exception:
            pass
        return None, ""

    def lookup_current() -> None:
        val, src = _value_under_cursor()
        if val is None:
            ida_kernwin.warning(
                "CryptoLens: no number under the cursor. Highlight a constant, "
                "or place the cursor on an instruction with an immediate, or use "
                "'Lookup a number...' to type one.")
            return
        get_panel().append_report(hex(val), note=src)

else:  # pragma: no cover

    def get_panel():
        raise RuntimeError("lookup panel requires IDA")

    def prompt_and_query():
        raise RuntimeError("lookup panel requires IDA")

    def lookup_current():
        raise RuntimeError("lookup panel requires IDA")
