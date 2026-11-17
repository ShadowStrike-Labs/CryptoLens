"""CryptoLens plugin controller: actions, menu, hotkeys, orchestration."""
from __future__ import annotations

import json
from typing import List

from .ida_shim import HAVE_IDA, ida_kernwin, idaapi, msg
from . import (annotate, apihashscan, fpscan, funcscan, lookup, memscan,
               results, scanners)
from .scanners import Finding

_STATE = {"findings": []}  # type: ignore

ACT_SCAN = "cryptolens:scan"
ACT_SCAN_ALL = "cryptolens:scan_all"
ACT_FUNC = "cryptolens:func"
ACT_FUNC_ALL = "cryptolens:func_all"
ACT_APIHASH = "cryptolens:apihash"
ACT_APIHASH_ALL = "cryptolens:apihash_all"
ACT_MEM = "cryptolens:memscan"
ACT_FP = "cryptolens:fingerprint"
ACT_LOOKUP = "cryptolens:lookup"
ACT_LOOKUP_CUR = "cryptolens:lookup_cur"
ACT_ANNOTATE = "cryptolens:annotate"
ACT_EXPORT = "cryptolens:export"

_MENU = "CryptoLens/"


def _do_fingerprint() -> None:
    findings = fpscan.scan_all()
    _STATE["findings"] = findings
    if findings:
        results.show_findings(findings, "CryptoLens fingerprints & entropy")
    else:
        ida_kernwin.info("CryptoLens: no library/key fingerprints or "
                         "high-entropy regions found.")


def _do_memscan() -> None:
    if not memscan.is_debugging():
        ida_kernwin.warning("CryptoLens: start a debug session first "
                            "(memory scan recovers runtime keys/states).")
        return
    findings = memscan.scan_memory()
    _STATE["findings"] = findings
    if findings:
        results.show_findings(findings, "CryptoLens memory findings")
    else:
        ida_kernwin.info("CryptoLens: nothing recovered from memory.")


def _do_func() -> None:
    funcscan.analyze_current_function()


def _do_apihash() -> None:
    ea = ida_kernwin.get_screen_ea()
    func = funcscan.ida_funcs.get_func(ea)
    if func is None:
        ida_kernwin.warning("CryptoLens: cursor is not inside a function.")
        return
    text, hits = apihashscan.resolve_in_function(func.start_ea)
    funcscan._show_text("CryptoLens: API hashes", text)


def _do_apihash_all() -> None:
    text, findings = apihashscan.resolve_in_binary()
    if findings:
        _STATE["findings"] = findings
        results.show_findings(findings, "CryptoLens API-hash resolvers")
    else:
        ida_kernwin.info("CryptoLens: no API-hash resolvers found.")


def _do_func_all() -> None:
    findings = funcscan.scan_all_functions(use_decompiler=False, threshold=0.5)
    _STATE["findings"] = findings
    if findings:
        results.show_findings(findings, "CryptoLens crypto-like functions")
    else:
        ida_kernwin.info("CryptoLens: no crypto-like functions found "
                         "(try the decompiler-assisted single-function view).")


def _do_scan(min_bucket: str) -> None:
    findings = scanners.run_all(min_bucket=min_bucket)
    _STATE["findings"] = findings
    if findings:
        results.show_findings(findings,
                              f"CryptoLens findings ({min_bucket}+)")
    else:
        ida_kernwin.info("CryptoLens: no findings at this confidence level.")


def _do_annotate() -> None:
    findings: List[Finding] = _STATE["findings"]
    if not findings:
        ida_kernwin.warning("CryptoLens: run a scan first.")
        return
    n = annotate.apply_all(findings)
    ida_kernwin.info(f"CryptoLens: annotated {n} location(s).")


def _do_export() -> None:
    findings: List[Finding] = _STATE["findings"]
    if not findings:
        ida_kernwin.warning("CryptoLens: run a scan first.")
        return
    path = ida_kernwin.ask_file(True, "*.json", "Export CryptoLens findings")
    if not path:
        return
    rows = [f.__dict__ for f in findings]
    if path.lower().endswith(".html"):
        _write_html(path, findings)
    else:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(rows, fh, indent=2)
    msg(f"[CryptoLens] Exported findings: {len(findings)}; path: {path}\n")


def _write_html(path: str, findings: List[Finding]) -> None:
    head = ("<html><head><meta charset='utf-8'><title>CryptoLens</title>"
            "<style>body{font-family:sans-serif}table{border-collapse:collapse}"
            "td,th{border:1px solid #ccc;padding:4px 8px;font-size:13px}"
            "th{background:#eee}</style></head><body><h2>CryptoLens findings</h2>"
            "<table><tr>" + "".join(f"<th>{c}</th>" for c in scanners.COLUMNS)
            + "</tr>")
    body = []
    for f in findings:
        cells = "".join(f"<td>{_esc(c)}</td>" for c in f.to_row())
        body.append(f"<tr>{cells}</tr>")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(head + "".join(body) + "</table></body></html>")


def _esc(s: str) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))


if HAVE_IDA:

    class _Handler(ida_kernwin.action_handler_t):
        def __init__(self, fn):
            super().__init__()
            self.fn = fn

        def activate(self, ctx):
            self.fn()
            return 1

        def update(self, ctx):
            return ida_kernwin.AST_ENABLE_ALWAYS

    _ACTIONS = [
        (ACT_FUNC, "Analyze current function", _do_func,
         "Ctrl-Shift-A", "Identify the algorithm in the function under the cursor"),
        (ACT_FUNC_ALL, "Scan all functions for crypto", _do_func_all,
         "", "Classify every function and list the crypto-like ones"),
        (ACT_APIHASH, "Resolve API hashes in function", _do_apihash,
         "Ctrl-Shift-H", "Name hashed imports and build an enum for this function"),
        (ACT_APIHASH_ALL, "Resolve API hashes (whole binary)", _do_apihash_all,
         "", "Resolve hashed imports across every function"),
        (ACT_MEM, "Scan process memory (debugger)", _do_memscan,
         "", "Recover runtime keys/tables/states from a live debug session"),
        (ACT_FP, "Fingerprint libraries / keys / entropy", _do_fingerprint,
         "", "Detect crypto libraries, PEM/SSH keys, CALG ids, high-entropy blobs"),
        (ACT_SCAN, "Scan binary (high confidence)", lambda: _do_scan("high"),
         "Ctrl-Shift-Y", "Scan for crypto/hash constants, tables and instructions"),
        (ACT_SCAN_ALL, "Scan binary (include variants)", lambda: _do_scan("medium"),
         "", "Also report medium-confidence variant constants"),
        (ACT_LOOKUP, "Lookup a number...", lookup.prompt_and_query,
         "Ctrl-Shift-L", "Explain a value / bytes / string"),
        (ACT_LOOKUP_CUR, "Lookup value under cursor", lookup.lookup_current,
         "", "Read and explain the selected or current value"),
        (ACT_ANNOTATE, "Annotate findings in IDB", _do_annotate,
         "", "Add comments and colors for the last scan"),
        (ACT_EXPORT, "Export findings (JSON/HTML)...", _do_export,
         "", "Export the last scan results"),
    ]

    # Add context actions to disassembly, pseudocode, and hex views.
    _POPUP_WIDGETS = (
        getattr(ida_kernwin, "BWN_DISASM", 1),
        getattr(ida_kernwin, "BWN_PSEUDOCODE", 51),
        getattr(ida_kernwin, "BWN_HEXVIEW", 2),
    )

    class _PopupHook(ida_kernwin.UI_Hooks):
        def finish_populating_widget_popup(self, widget, popup):
            try:
                wtype = ida_kernwin.get_widget_type(widget)
                if wtype in _POPUP_WIDGETS:
                    ida_kernwin.attach_action_to_popup(
                        widget, popup, ACT_LOOKUP_CUR, "CryptoLens/")
                    ida_kernwin.attach_action_to_popup(
                        widget, popup, ACT_FUNC, "CryptoLens/")
                    ida_kernwin.attach_action_to_popup(
                        widget, popup, ACT_APIHASH, "CryptoLens/")
            except Exception:
                pass

    _HOOK = {"inst": None}

    def _register_actions() -> None:
        for name, label, fn, hotkey, tip in _ACTIONS:
            desc = ida_kernwin.action_desc_t(name, label, _Handler(fn),
                                             hotkey, tip)
            ida_kernwin.register_action(desc)
            ida_kernwin.attach_action_to_menu(_MENU + label, name,
                                              ida_kernwin.SETMENU_APP)
        if _HOOK["inst"] is None:
            _HOOK["inst"] = _PopupHook()
            _HOOK["inst"].hook()

    def _unregister_actions() -> None:
        if _HOOK["inst"] is not None:
            try:
                _HOOK["inst"].unhook()
            except Exception:
                pass
            _HOOK["inst"] = None
        for name, label, *_ in _ACTIONS:
            ida_kernwin.detach_action_from_menu(_MENU + label, name)
            ida_kernwin.unregister_action(name)

    class CryptoLensPlugin(idaapi.plugin_t):
        flags = idaapi.PLUGIN_KEEP
        comment = "Scan for crypto/hash constants, variants, tables and instructions"
        help = "CryptoLens: crypto & hash algorithm pattern scanner"
        wanted_name = "CryptoLens"
        wanted_hotkey = ""

        def init(self):
            try:
                _register_actions()
            except Exception:
                import traceback
                msg("[CryptoLens] init failed:\n" + traceback.format_exc())
                return idaapi.PLUGIN_SKIP
            msg("[CryptoLens] loaded. Menu: CryptoLens/  |  "
                "Analyze function: Ctrl-Shift-A  Scan: Ctrl-Shift-Y  "
                "Lookup: Ctrl-Shift-L\n")
            return idaapi.PLUGIN_KEEP

        def run(self, arg):
            _do_func()

        def term(self):
            _unregister_actions()

    # Compatibility entry point when this module is loaded directly.
    def PLUGIN_ENTRY(_cls=CryptoLensPlugin):
        return _cls()

else:  # pragma: no cover

    def PLUGIN_ENTRY():
        raise RuntimeError("CryptoLens must be loaded inside IDA Pro")
