"""Interactive 'paste a number' lookup panel (dockable text viewer).

Accepts a hex/decimal value, a byte blob, or a 'quoted string' and shows the
full CryptoLens explanation (exact match, variant-of, API-hash, ASCII, tables).
Delegates all analysis to the testable core (:func:`cryptolens.report.lookup_text`).
"""
from __future__ import annotations

from cryptolens import report

from .ida_shim import HAVE_IDA, ida_kernwin


if HAVE_IDA:

    class LookupPanel(ida_kernwin.simplecustviewer_t):
        TITLE = "CryptoLens Lookup"

        def create(self) -> bool:
            if not self.Create(self.TITLE):
                return False
            self.ClearLines()
            self.AddLine("CryptoLens lookup - enter a value with 'Query' "
                         "(Ctrl-Shift-L) ...")
            self.AddLine("Examples: 0x9E3779B9 | 2654435769 | de ad be ef | "
                         "'expand 32-byte k'")
            self.Refresh()
            return True

        def append_report(self, user_input: str) -> None:
            self.AddLine("")
            self.AddLine("=" * 60)
            self.AddLine(f">>> {user_input}")
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
        panel = get_panel()
        panel.append_report(s)

else:  # pragma: no cover

    def get_panel():
        raise RuntimeError("lookup panel requires IDA")

    def prompt_and_query():
        raise RuntimeError("lookup panel requires IDA")
