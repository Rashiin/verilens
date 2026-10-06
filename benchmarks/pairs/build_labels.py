"""Regenerate labels.json from the `// @vuln <category>` markers in *_vuln.sol files.

Markers live in comments, which the benchmark loader strips before analysis,
so they never leak into what a tool (or an LLM) sees.
"""

import json
import re
from pathlib import Path

ROOT = Path(__file__).parent
MARKER = re.compile(r"//\s*@vuln\s+(\w+)")

entries = []
for vuln in sorted(ROOT.glob("*/*_vuln.sol")):
    labels: dict[str, list[int]] = {}
    for i, line in enumerate(vuln.read_text().splitlines(), 1):
        m = MARKER.search(line)
        if m:
            labels.setdefault(m.group(1), []).append(i)
    assert len(labels) == 1, f"{vuln}: expected exactly one labelled category"
    category = next(iter(labels))
    pair = f"{vuln.parent.name}/{vuln.name.removesuffix('_vuln.sol')}"
    safe = vuln.with_name(vuln.name.replace("_vuln.sol", "_safe.sol"))
    assert safe.exists(), f"missing safe twin for {vuln}"
    entries.append(
        {
            "name": vuln.name,
            "path": str(vuln.relative_to(ROOT)),
            "pair": pair,
            "safe": False,
            "vulnerabilities": [{"category": category, "lines": lines} for category, lines in labels.items()],
        }
    )
    entries.append(
        {
            "name": safe.name,
            "path": str(safe.relative_to(ROOT)),
            "pair": pair,
            "safe": True,
            "fixed_category": category,
            "vulnerabilities": [],
        }
    )

(ROOT / "labels.json").write_text(json.dumps(entries, indent=2) + "\n")
print(f"{len(entries)} contracts, {len(entries) // 2} pairs")
