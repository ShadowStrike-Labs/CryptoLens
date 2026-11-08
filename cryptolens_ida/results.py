"""Results table built on ida_kernwin.Choose (no direct Qt dependency)."""
from __future__ import annotations

from typing import List

from .ida_shim import HAVE_IDA, ida_kernwin
from .scanners import COLUMNS, Finding

_COL_WIDTHS = [16, 10, 6, 40, 18, 22, 30]


if HAVE_IDA:

    class ResultsChooser(ida_kernwin.Choose):
        def __init__(self, findings: List[Finding], title: str = "CryptoLens findings"):
            cols = [[c, w] for c, w in zip(COLUMNS, _COL_WIDTHS)]
            super().__init__(title, cols, flags=ida_kernwin.Choose.CH_RESTORE)
            self.findings = findings

        def OnGetSize(self) -> int:
            return len(self.findings)

        def OnGetLine(self, n: int) -> List[str]:
            return self.findings[n].to_row()

        def OnSelectLine(self, n):
            ea = self.findings[n].ea
            if ea:
                ida_kernwin.jumpto(ea)
            return (ida_kernwin.Choose.NOTHING_CHANGED,)

    def show_findings(findings: List[Finding], title: str = "CryptoLens findings"):
        ch = ResultsChooser(findings, title)
        ch.Show()
        return ch

else:  # pragma: no cover - stub outside IDA

    class ResultsChooser:  # type: ignore
        def __init__(self, *a, **k):
            raise RuntimeError("ResultsChooser requires IDA")

    def show_findings(*a, **k):
        raise RuntimeError("show_findings requires IDA")
