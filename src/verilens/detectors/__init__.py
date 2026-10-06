"""Pattern-based static detectors.

Each detector encodes a well-known SWC pattern as a cheap, high-recall
heuristic. They are deliberately permissive: the hybrid pipeline relies on an
LLM to prune false alarms, so missing a real bug here is worse than flagging a
benign one.
"""

from __future__ import annotations

from ..findings import Finding, dedupe
from ..solidity import SourceUnit
from . import access, arithmetic, blockvars, calls, ordering  # noqa: F401  (register detectors)
from .base import REGISTRY

SUPPORTED_CATEGORIES = sorted({cat for cat, _ in REGISTRY})


def run_static(unit: SourceUnit, categories: set[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for category, fn in REGISTRY:
        if categories and category not in categories:
            continue
        findings.extend(fn(unit))
    return dedupe(findings)


__all__ = ["SUPPORTED_CATEGORIES", "run_static"]
