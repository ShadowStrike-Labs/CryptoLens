"""CryptoLens core analysis package.

IDA-specific adapters are provided by :mod:`cryptolens_ida`.
"""
from __future__ import annotations

from . import (apihash, constants, engine, entropy, families, familyscan,
               fastscan, fingerprints, hpmath, interpret, memfind, parse, report,
               signatures, structure, tables, util)
from .engine import Explanation, explain, explain_multi

__version__ = "0.3.0"

__all__ = [
    "apihash", "constants", "engine", "entropy", "families", "familyscan",
    "fastscan", "fingerprints", "hpmath", "interpret", "memfind", "parse",
    "report", "signatures", "structure", "tables", "util", "Explanation",
    "explain", "explain_multi", "__version__",
]
