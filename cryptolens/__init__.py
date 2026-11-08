"""CryptoLens core: IDA-independent crypto/hash constant & variant analysis.

The core (this package) has no IDA imports so it can be unit-tested and used
from a plain CLI.  The IDA integration lives in ``cryptolens_ida`` and the
plugin entry point ``cryptolens_plugin.py``.
"""
from __future__ import annotations

from . import apihash, constants, engine, hpmath, parse, report, signatures, util
from .engine import Explanation, explain, explain_multi

__version__ = "0.1.0"

__all__ = [
    "apihash", "constants", "engine", "hpmath", "parse", "report",
    "signatures", "util", "Explanation", "explain", "explain_multi",
    "__version__",
]
