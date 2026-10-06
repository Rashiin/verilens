"""Benchmark datasets.

Both datasets use the SmartBugs ``vulnerabilities.json`` label format::

    [{"name": ..., "path": ..., "vulnerabilities": [{"lines": [..], "category": ..}]}]

Label-leakage control
---------------------
SmartBugs-curated annotates the ground truth *inside* the source
(``// <yes> <report> REENTRANCY`` and ``@vulnerable_at_lines``) and many files
carry explanatory comments describing the bug. An LLM would simply read the
answer. ``sanitize`` therefore blanks every comment while preserving line
numbers, so labels stay aligned and no evaluated mode sees them.
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from ..solidity import strip_comments
from ..taxonomy import normalize_category

SMARTBUGS_REPO = "smartbugs/smartbugs-curated"
SMARTBUGS_COMMIT = "230e649123477eff332742a59a1c7cc6dc286cab"
PAIRS_DIR = Path(__file__).resolve().parents[3] / "benchmarks" / "pairs"


@dataclass
class Sample:
    name: str
    path: str
    source: str
    labels: list[tuple[str, int]] = field(default_factory=list)
    group: str = ""  # directory / pair id
    meta: dict = field(default_factory=dict)

    @property
    def categories(self) -> set[str]:
        return {c for c, _ in self.labels}


def sanitize(source: str) -> str:
    return strip_comments(source)


def _load_manifest(root: Path, manifest: Path) -> list[Sample]:
    samples = []
    for entry in json.loads(manifest.read_text()):
        src_path = root / entry["path"]
        labels = []
        for v in entry.get("vulnerabilities", []):
            cat = normalize_category(v["category"]) or "other"
            labels.extend((cat, int(line)) for line in v.get("lines", []))
        samples.append(
            Sample(
                name=entry["name"],
                path=entry["path"],
                source=sanitize(src_path.read_text(encoding="utf-8", errors="replace")),
                labels=labels,
                group=entry.get("pair") or Path(entry["path"]).parent.name,
                meta={k: v for k, v in entry.items() if k in ("pair", "safe", "fixed_category", "pragma", "note")},
            )
        )
    return samples


def load_smartbugs(root: str | Path) -> list[Sample]:
    root = Path(root)
    manifest = root / "vulnerabilities.json"
    if not manifest.exists():
        raise FileNotFoundError(f"{manifest} not found - run `verilens fetch-smartbugs --dest {root}` first")
    return _load_manifest(root, manifest)


def load_pairs(root: str | Path | None = None) -> list[Sample]:
    root = Path(root) if root else PAIRS_DIR
    return _load_manifest(root, root / "labels.json")


def fetch_smartbugs(dest: str | Path, commit: str = SMARTBUGS_COMMIT, verbose: bool = True) -> Path:
    """Download SmartBugs-curated at a pinned commit (raw files, no git needed)."""
    dest = Path(dest)
    base = f"https://raw.githubusercontent.com/{SMARTBUGS_REPO}/{commit}/"

    def get(rel: str) -> bytes:
        with urllib.request.urlopen(base + rel, timeout=60) as r:
            return r.read()

    dest.mkdir(parents=True, exist_ok=True)
    manifest = dest / "vulnerabilities.json"
    manifest.write_bytes(get("vulnerabilities.json"))
    entries = json.loads(manifest.read_text())
    for i, e in enumerate(entries, 1):
        target = dest / e["path"]
        if target.exists():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(get(e["path"]))
        if verbose:
            print(f"[{i}/{len(entries)}] {e['path']}")
    (dest / "COMMIT").write_text(commit + "\n")
    return dest
