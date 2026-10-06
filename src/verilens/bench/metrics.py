"""Evaluation metrics.

Two granularities are reported, following common practice for SmartBugs:

* **Category level** - unit of evaluation is a (contract, category) pair: did
  the tool report category *c* anywhere in the contract?
* **Line level** - a labelled (category, line) is detected if the tool reports
  the same category within +/- ``tolerance`` lines; a reported finding is a
  true positive if it matches some label that way.

The contrastive *pairs* benchmark additionally reports the **false-alarm rate
on safe twins**: the fraction of patched contracts on which the tool still
reports the category that was fixed.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from ..findings import Finding
from .datasets import Sample


def prf(tp: int, fp: int, fn: int) -> dict[str, float]:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4), "tp": tp, "fp": fp, "fn": fn}


@dataclass
class Scorer:
    tolerance: int = 2
    cat_counts: dict[str, list[int]] = field(default_factory=lambda: defaultdict(lambda: [0, 0, 0]))
    line_pred: dict[str, list[int]] = field(default_factory=lambda: defaultdict(lambda: [0, 0]))  # matched, total
    line_gold: dict[str, list[int]] = field(default_factory=lambda: defaultdict(lambda: [0, 0]))  # found, total
    safe_alarms: list[int] = field(default_factory=lambda: [0, 0])  # alarms, safe contracts
    per_sample: list[dict] = field(default_factory=list)

    def add(self, sample: Sample, findings: list[Finding]) -> dict:
        gold = sample.categories
        pred = {f.category for f in findings}
        for c in gold | pred:
            counts = self.cat_counts[c]
            if c in gold and c in pred:
                counts[0] += 1
            elif c in pred:
                counts[1] += 1
            else:
                counts[2] += 1

        def near(cat: str, line: int, pool) -> bool:
            return any(c == cat and abs(line - x) <= self.tolerance for c, x in pool)

        for f in findings:
            stats = self.line_pred[f.category]
            stats[1] += 1
            stats[0] += near(f.category, f.line, sample.labels)
        pred_lines = [(f.category, f.line) for f in findings]
        for cat, line in sample.labels:
            stats = self.line_gold[cat]
            stats[1] += 1
            stats[0] += near(cat, line, pred_lines)

        if sample.meta.get("safe"):
            fixed = sample.meta.get("fixed_category")
            self.safe_alarms[1] += 1
            self.safe_alarms[0] += bool(fixed in pred) if fixed else bool(pred)

        row = {
            "path": sample.path,
            "gold": sorted(gold),
            "pred": sorted(pred),
            "findings": [(f.category, f.line, f.rule) for f in findings],
        }
        self.per_sample.append(row)
        return row

    def summary(self) -> dict:
        cats = sorted(set(self.cat_counts) | set(self.line_gold) | set(self.line_pred))
        per_cat = {}
        tot = [0, 0, 0]
        for c in cats:
            tp, fp, fn = self.cat_counts.get(c, [0, 0, 0])
            tot = [tot[0] + tp, tot[1] + fp, tot[2] + fn]
            m_pred, n_pred = self.line_pred.get(c, [0, 0])
            m_gold, n_gold = self.line_gold.get(c, [0, 0])
            per_cat[c] = {
                "category_level": prf(tp, fp, fn),
                "line_level": {
                    "precision": round(m_pred / n_pred, 4) if n_pred else 0.0,
                    "recall": round(m_gold / n_gold, 4) if n_gold else 0.0,
                    "reported": n_pred,
                    "labelled": n_gold,
                },
            }
        macro = [per_cat[c]["category_level"] for c in cats if c in self.cat_counts and sum(self.cat_counts[c][::2])]
        lp = [sum(v[0] for v in self.line_pred.values()), sum(v[1] for v in self.line_pred.values())]
        lg = [sum(v[0] for v in self.line_gold.values()), sum(v[1] for v in self.line_gold.values())]
        out = {
            "samples": len(self.per_sample),
            "category_level_micro": prf(*tot),
            "category_level_macro_f1": round(sum(m["f1"] for m in macro) / len(macro), 4) if macro else 0.0,
            "line_level_micro": {
                "precision": round(lp[0] / lp[1], 4) if lp[1] else 0.0,
                "recall": round(lg[0] / lg[1], 4) if lg[1] else 0.0,
                "reported": lp[1],
                "labelled": lg[1],
                "tolerance": self.tolerance,
            },
            "per_category": per_cat,
        }
        if self.safe_alarms[1]:
            out["safe_twin_false_alarm_rate"] = round(self.safe_alarms[0] / self.safe_alarms[1], 4)
            out["safe_twins"] = self.safe_alarms[1]
        return out
