"""Benchmark runner: analyse every sample, score it, and write a report."""

from __future__ import annotations

import json
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .. import __version__
from ..llm.base import LLMClient, LLMError
from ..pipeline import analyze
from ..taxonomy import CATEGORIES
from .datasets import Sample
from .metrics import Scorer


def run_benchmark(
    samples: list[Sample],
    mode: str,
    dataset: str,
    llm: LLMClient | None = None,
    threshold: float = 0.5,
    tolerance: int = 2,
    progress: bool = True,
) -> dict:
    scorer = Scorer(tolerance=tolerance)
    # Upper bound for any verify-only approach: a perfect verifier keeps exactly
    # the static candidates that match a label and nothing else.
    oracle = Scorer(tolerance=tolerance)
    errors: dict[str, list[str]] = {}
    candidates = verified_out = 0
    t0 = time.perf_counter()
    for i, s in enumerate(samples, 1):
        res = analyze(s.source, mode=mode, llm=llm, threshold=threshold, path=s.path)
        scorer.add(s, res.findings)
        oracle.add(
            s,
            [f for f in res.candidates if any(c == f.category and abs(x - f.line) <= tolerance for c, x in s.labels)],
        )
        candidates += len(res.candidates)
        verified_out += sum(1 for f in res.candidates if f.verdict == "not_vulnerable")
        if res.errors:
            errors[s.path] = res.errors
            # Verification fails open, which is right for one flaky call but would silently
            # turn a whole run into "static" if the LLM is unreachable. Stop instead.
            if llm and llm.calls + llm.cache_hits == 0 and len(errors) >= 3:
                raise LLMError(f"no LLM call has succeeded; first error: {next(iter(errors.values()))[0]}")
        if progress and sys.stderr.isatty():
            print(f"\r[{i}/{len(samples)}] {s.path[:70]:<70}", end="", file=sys.stderr, flush=True)
    if progress and sys.stderr.isatty():
        print(file=sys.stderr)
    summary = scorer.summary()
    summary["config"] = {
        "dataset": dataset,
        "mode": mode,
        "llm": llm.name if llm else None,
        "threshold": threshold if llm else None,
        "verilens": __version__,
        "python": platform.python_version(),
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
    }
    summary["runtime_seconds"] = round(time.perf_counter() - t0, 2)
    if mode != "llm":
        ub = oracle.summary()
        summary["verification_upper_bound"] = {
            k: ub[k] for k in ("category_level_micro", "line_level_micro", "safe_twin_false_alarm_rate") if k in ub
        }
    if mode in ("hybrid", "hybrid-plus"):
        summary["static_candidates"] = candidates
        summary["candidates_rejected_by_llm"] = verified_out
    if llm:
        summary["llm_calls"] = llm.calls
        summary["llm_cache_hits"] = llm.cache_hits
    summary["samples_with_errors"] = len(errors)
    summary["complete"] = not errors
    summary["errors"] = errors
    summary["per_sample"] = scorer.per_sample
    return summary


def _pct(x: float) -> str:
    return f"{100 * x:.1f}"


def to_markdown(summary: dict) -> str:
    cfg = summary["config"]
    cm = summary["category_level_micro"]
    lm = summary["line_level_micro"]
    lines = [
        f"### {cfg['dataset']} - mode `{cfg['mode']}`" + (f" ({cfg['llm']})" if cfg["llm"] else ""),
        "",
    ]
    if not summary.get("complete", True):
        lines += [
            f"> **INCOMPLETE RUN:** {summary['samples_with_errors']} contract(s) had LLM errors and kept "
            "unverified static findings. Do not report these numbers; fix the errors and re-run "
            "(cached answers are reused).",
            "",
        ]
    lines += [
        f"{summary['samples']} contracts, {summary['runtime_seconds']} s, verilens {cfg['verilens']}, {cfg['date']}.",
        "",
        "| Granularity | Precision | Recall | F1 |",
        "|---|---:|---:|---:|",
        f"| Category (micro) | {_pct(cm['precision'])} | {_pct(cm['recall'])} | {_pct(cm['f1'])} |",
        f"| Line (micro, ±{lm['tolerance']}) | {_pct(lm['precision'])} | {_pct(lm['recall'])} | - |",
        "",
        f"Category-level macro F1: **{_pct(summary['category_level_macro_f1'])}**.",
    ]
    if "safe_twin_false_alarm_rate" in summary:
        lines.append(
            f"False-alarm rate on safe twins: **{_pct(summary['safe_twin_false_alarm_rate'])}%** "
            f"({summary['safe_twins']} patched contracts)."
        )
    if "verification_upper_bound" in summary:
        ub = summary["verification_upper_bound"]
        lines.append(
            "Upper bound for a perfect verifier on these candidates: category-level "
            f"P {_pct(ub['category_level_micro']['precision'])} / R {_pct(ub['category_level_micro']['recall'])} / "
            f"F1 {_pct(ub['category_level_micro']['f1'])}."
        )
    if "static_candidates" in summary:
        lines.append(
            f"LLM rejected {summary['candidates_rejected_by_llm']} of {summary['static_candidates']} static candidates."
        )
    if summary.get("samples_with_errors"):
        lines.append(f"Samples with LLM errors (fail-open): {summary['samples_with_errors']}.")
    lines += [
        "",
        "| Category | P | R | F1 | TP | FP | FN |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for cat, m in summary["per_category"].items():
        c = m["category_level"]
        title = CATEGORIES[cat].title if cat in CATEGORIES else cat
        lines.append(
            f"| {title} | {_pct(c['precision'])} | {_pct(c['recall'])} | {_pct(c['f1'])} "
            f"| {c['tp']} | {c['fp']} | {c['fn']} |"
        )
    return "\n".join(lines) + "\n"


def write_report(summary: dict, out_dir: str | Path) -> tuple[Path, Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cfg = summary["config"]
    stem = f"{cfg['dataset']}_{cfg['mode']}" + (
        "_" + cfg["llm"].replace(":", "-").replace("/", "-") if cfg["llm"] else ""
    )
    j = out_dir / f"{stem}.json"
    m = out_dir / f"{stem}.md"
    j.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    m.write_text(to_markdown(summary))
    return j, m
