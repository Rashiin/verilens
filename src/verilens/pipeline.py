"""Analysis modes.

``static``       pattern detectors only (fast, high recall, noisy).
``llm``          the LLM audits the contract from scratch (zero-shot discovery).
``hybrid``       static candidates are each verified by the LLM; only confirmed
                 ones are kept. Research question: does verification raise
                 precision without hurting recall?
``hybrid-plus``  ``hybrid`` plus LLM discovery, to recover issues the
                 detectors cannot express.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from .detectors import run_static
from .findings import Finding, dedupe
from .llm.base import LLMClient, QuotaExceeded
from .llm.prompts import SYSTEM, as_float, discover_prompt, parse_json, verify_prompt
from .solidity import SourceUnit
from .taxonomy import normalize_category

MODES = ("static", "llm", "hybrid", "hybrid-plus")
VERIFY_BATCH = 25


@dataclass
class AnalysisResult:
    findings: list[Finding]
    candidates: list[Finding] = field(default_factory=list)  # static output before filtering
    errors: list[str] = field(default_factory=list)
    seconds: float = 0.0


def _items(data: Any, keys: tuple[str, ...]) -> list:
    """Accept the shapes models actually return: the requested wrapper object, a bare
    list, a different wrapper key, or a single item."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for k in keys:
            if isinstance(data.get(k), list):
                return data[k]
        lists = [v for v in data.values() if isinstance(v, list)]
        if len(lists) == 1:
            return lists[0]
        return [data]
    return []


def verdict_map(data: Any) -> dict[int, dict]:
    out: dict[int, dict] = {}
    for pos, v in enumerate(_items(data, ("verdicts", "results", "candidates")), 1):
        if not isinstance(v, dict) or "verdict" not in v:
            continue
        try:
            out[int(str(v.get("id", pos)).strip().lstrip("#"))] = v
        except ValueError:
            out[pos] = v
    return out


def verify(
    source: str, candidates: list[Finding], llm: LLMClient, threshold: float = 0.5
) -> tuple[list[Finding], list[str]]:
    kept: list[Finding] = []
    errors: list[str] = []
    for start in range(0, len(candidates), VERIFY_BATCH):
        batch = candidates[start : start + VERIFY_BATCH]
        try:
            data = parse_json(llm.complete(SYSTEM, verify_prompt(source, batch)))
            verdicts = verdict_map(data)
        except QuotaExceeded:
            raise
        except Exception as e:  # fail open: keep unverified candidates
            errors.append(f"verify: {e}")
            kept.extend(batch)
            continue
        for i, f in enumerate(batch, 1):
            v = verdicts.get(i)
            if v is None:
                errors.append(f"verify: no verdict for candidate {i} (line {f.line})")
                kept.append(f)
                continue
            f.verdict = "vulnerable" if str(v.get("verdict", "")).lower().startswith("vuln") else "not_vulnerable"
            f.llm_confidence = as_float(v.get("confidence"))
            f.explanation = str(v.get("explanation", ""))
            f.exploit = str(v.get("exploit", ""))
            f.fix = str(v.get("fix", ""))
            if f.verdict == "vulnerable" and f.llm_confidence >= threshold:
                kept.append(f)
    return kept, errors


def discover(source: str, unit: SourceUnit, llm: LLMClient, threshold: float = 0.5) -> tuple[list[Finding], list[str]]:
    try:
        data = parse_json(llm.complete(SYSTEM, discover_prompt(source)))
    except QuotaExceeded:
        raise
    except Exception as e:
        return [], [f"discover: {e}"]
    out: list[Finding] = []
    errors: list[str] = []
    items = _items(data, ("findings", "vulnerabilities", "issues"))
    for item in items or []:
        if not isinstance(item, dict):
            continue
        cat = normalize_category(str(item.get("category", "")))
        if cat is None:
            errors.append(f"discover: unknown category {item.get('category')!r}")
            continue
        conf = as_float(item.get("confidence"))
        if conf < threshold:
            continue
        lines = [int(x) for x in item.get("lines") or [] if str(x).lstrip("-").isdigit()] or [0]
        for line in lines:
            out.append(
                Finding(
                    category=cat,
                    line=line,
                    title=cat.replace("_", " ").capitalize(),
                    message=str(item.get("explanation", "")),
                    rule="llm-discovery",
                    function=str(item.get("function", "")),
                    confidence="high" if conf >= 0.8 else "medium",
                    source="llm",
                    snippet=unit.line_text(line),
                    verdict="vulnerable",
                    llm_confidence=conf,
                    explanation=str(item.get("explanation", "")),
                    exploit=str(item.get("exploit", "")),
                    fix=str(item.get("fix", "")),
                )
            )
    return out, errors


def _merge(primary: list[Finding], extra: list[Finding], tolerance: int = 2) -> list[Finding]:
    merged = list(primary)
    for f in extra:
        if not any(g.category == f.category and abs(g.line - f.line) <= tolerance for g in merged):
            merged.append(f)
    return dedupe(merged)


def analyze(
    source: str,
    mode: str = "static",
    llm: LLMClient | None = None,
    threshold: float = 0.5,
    path: str = "<memory>",
) -> AnalysisResult:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    if mode != "static" and llm is None:
        raise ValueError(f"mode {mode!r} needs an LLM client")
    t0 = time.perf_counter()
    unit = SourceUnit(source, path)
    candidates = run_static(unit) if mode != "llm" else []
    errors: list[str] = []

    if mode == "static":
        findings = candidates
    elif mode == "llm":
        findings, errors = discover(source, unit, llm, threshold)
        findings = dedupe(findings)
    else:
        findings, errors = verify(source, candidates, llm, threshold) if candidates else ([], [])
        if mode == "hybrid-plus":
            found, e2 = discover(source, unit, llm, threshold)
            errors += e2
            findings = _merge(findings, found)
    return AnalysisResult(
        findings=sorted(findings, key=lambda f: (f.line, f.category)),
        candidates=candidates,
        errors=errors,
        seconds=time.perf_counter() - t0,
    )
