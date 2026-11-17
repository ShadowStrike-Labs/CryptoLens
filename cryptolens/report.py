"""Human-readable formatting of engine findings for the CLI and the IDA panel."""
from __future__ import annotations

from typing import List

from . import apihash, engine, interpret, parse, util
try:
    from . import families, familyscan, tables, fastscan
except Exception:  # pragma: no cover
    families = familyscan = tables = fastscan = None

_BUCKET_TAG = {"high": "[high]  ", "medium": "[medium]", "low": "[low]   "}


def format_explanation(e: engine.Explanation, indent: str = "  ") -> str:
    lines = [f"{indent}{_BUCKET_TAG.get(e.bucket, '[?]')} {e.summary}"]
    sub = indent + "    "
    if e.recipe:
        lines.append(f"{sub}origin : {e.recipe}")
    if e.detail:
        lines.append(f"{sub}detail : {e.detail}")
    if e.algorithms:
        lines.append(f"{sub}used by: {'; '.join(e.algorithms)}")
    lines.append(f"{sub}score  : {e.confidence:.2f} ({e.kind})")
    return "\n".join(lines)


def explain_text(value: int, width: int) -> str:
    """Full lookup report for one integer at one width."""
    expls = engine.explain(value, width)
    header = f"0x{value:0{max(width // 4, 1)}X}  ({value})  as {width}-bit"
    out = [header, "-" * len(header)]

    # ASCII interpretation
    for order, s in parse.ascii_of(value, width):
        out.append(f"  ascii ({order}-endian): {s!r}")

    # API-hash interpretation
    if width in (32, 64):
        hits = apihash.identify(value, width)
        for h in hits[:6]:
            v = f" ({h.variant})" if h.variant else ""
            out.append(f"  [high]   API hash: {h.scheme}(\"{h.name}\"{v})")

    if not expls and not out[2:]:
        out.append("  (no known constant / variant match)")
    for e in expls:
        out.append(format_explanation(e))
    return "\n".join(out)


def explain_multi_text(value: int) -> str:
    """Try the natural width plus 32/64, de-duplicated, best first."""
    widths = []
    nat = parse.natural_width(value)
    for w in (nat, 32, 64):
        if w not in widths and value <= util.mask(w):
            widths.append(w)
    blocks = [explain_text(value, w) for w in widths]
    return "\n\n".join(blocks)


def lookup_text(user_input: str) -> str:
    """Full report for arbitrary panel input: int, hex blob, or 'string'."""
    try:
        p = parse.parse_token(user_input)
    except ValueError as exc:
        return f"! {exc}"

    if p.kind == "int":
        blocks = [explain_multi_text(p.value)]
        general = interpret.describe_value(p.value)
        if general:
            blocks.append("General interpretations:\n"
                          + "\n".join("  " + g for g in general))
        return "\n\n".join(blocks)

    # Byte blob / string input.
    data = p.data or b""
    out = [f"bytes ({len(data)}): {data.hex(' ')}"]
    printable = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    out.append(f"ascii: {printable!r}")
    if len(data) in (1, 2, 4, 8):
        val = int.from_bytes(data, "little")
        out.append("")
        out.append(explain_multi_text(val))
    if tables is not None:
        for h in tables.detect_tables(data):
            out.append(f"  [{('high' if h.confidence >= 0.85 else 'medium')}] "
                       f"table: {h.name}  ({h.note})")
        for hit in familyscan.scan_buffer(data):
            out.append(f"  [{hit.bucket}] family: {hit.name}  ({hit.evidence})")
        for hit in fastscan.scan_buffer(data, aligned=False):
            out.append(f"  +0x{hit.offset:X} [{hit.bucket}] 0x{hit.value:X} "
                       f"({hit.width}b) {hit.summary}")
    return "\n".join(out)
