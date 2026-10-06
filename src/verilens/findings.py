from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Finding:
    category: str
    line: int
    title: str
    message: str
    rule: str = ""
    contract: str = ""
    function: str = ""
    confidence: str = "medium"  # low | medium | high
    source: str = "static"  # static | llm
    snippet: str = ""
    # Filled in by LLM verification / discovery.
    verdict: str | None = None  # vulnerable | not_vulnerable | None (unverified)
    llm_confidence: float | None = None
    explanation: str = ""
    exploit: str = ""
    fix: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if not d["extra"]:
            d.pop("extra")
        return d


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Keep one finding per (category, line), preferring higher confidence."""
    rank = {"high": 3, "medium": 2, "low": 1}
    best: dict[tuple[str, int], Finding] = {}
    for f in findings:
        key = (f.category, f.line)
        if key not in best or rank.get(f.confidence, 0) > rank.get(best[key].confidence, 0):
            best[key] = f
    return sorted(best.values(), key=lambda f: (f.line, f.category))
