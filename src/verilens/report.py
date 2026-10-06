"""Output formats for ``verilens scan``."""

from __future__ import annotations

import json

from . import __version__
from .findings import Finding
from .taxonomy import CATEGORIES

_SEVERITY = {"high": "error", "medium": "warning", "low": "note"}
_COLORS = {"high": "\033[31m", "medium": "\033[33m", "low": "\033[36m"}


def to_text(path: str, findings: list[Finding], color: bool = False) -> str:
    if not findings:
        return f"{path}: no findings\n"
    out = [f"{path}: {len(findings)} finding(s)\n"]
    for f in findings:
        tag = f"[{f.confidence.upper():6}]"
        if color:
            tag = f"{_COLORS.get(f.confidence, '')}{tag}\033[0m"
        where = f"{f.contract}.{f.function}" if f.function else f.contract
        out.append(f"{tag} {path}:{f.line}  {f.category}  {f.title}" + (f"  ({where})" if where else ""))
        out.append(f"         {f.snippet}")
        out.append(f"         {f.explanation or f.message}")
        if f.verdict:
            out.append(f"         LLM verdict: {f.verdict} (confidence {f.llm_confidence:.2f})")
        if f.exploit:
            out.append(f"         Exploit: {f.exploit}")
        if f.fix:
            out.append(f"         Fix: {f.fix}")
        out.append("")
    return "\n".join(out)


def to_json(path: str, findings: list[Finding]) -> str:
    return json.dumps({"file": path, "findings": [f.to_dict() for f in findings]}, indent=2, ensure_ascii=False)


def to_sarif(results: dict[str, list[Finding]]) -> str:
    """SARIF 2.1.0 - upload to GitHub code scanning to get inline PR annotations."""
    rules = {}
    sarif_results = []
    for path, findings in results.items():
        for f in findings:
            rule_id = f"{f.category}/{f.rule or 'finding'}"
            cat = CATEGORIES.get(f.category)
            rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": cat.description if cat else f.title},
                    "properties": {"tags": ["security", f.category, *(cat.swc if cat else ())]},
                },
            )
            text = f.explanation or f.message
            if f.fix:
                text += f"\nFix: {f.fix}"
            sarif_results.append(
                {
                    "ruleId": rule_id,
                    "level": _SEVERITY.get(f.confidence, "warning"),
                    "message": {"text": text},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": path},
                                "region": {"startLine": max(f.line, 1)},
                            }
                        }
                    ],
                }
            )
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "verilens",
                        "version": __version__,
                        "informationUri": "https://github.com/Rashiin/verilens",
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(doc, indent=2)
