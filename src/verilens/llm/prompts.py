"""Prompt templates and response parsing.

Prompts ask for strict JSON so answers are machine-checkable. The contract is
shown with line numbers because both verification and discovery are scored at
line granularity.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..findings import Finding
from ..taxonomy import taxonomy_prompt_block

MAX_SOURCE_CHARS = 60_000

SYSTEM = (
    "You are a senior smart-contract security auditor. You reason step by step about "
    "control flow, who can call each function, and what state an attacker controls. "
    "You are calibrated: you only call something vulnerable when you can describe a "
    "concrete exploit, and you say so when a pattern is benign in context. "
    "Always answer with a single JSON object and nothing else."
)


def numbered(source: str) -> str:
    lines = source.split("\n")
    width = len(str(len(lines)))
    text = "\n".join(f"{i:>{width}} | {line}" for i, line in enumerate(lines, 1))
    if len(text) > MAX_SOURCE_CHARS:
        text = text[:MAX_SOURCE_CHARS] + "\n... [truncated]"
    return text


def verify_prompt(source: str, candidates: list[Finding]) -> str:
    items = "\n".join(
        f"{i}. [{f.category}] line {f.line}"
        + (f" in `{f.function}`" if f.function else "")
        + f": {f.title}. {f.message}"
        for i, f in enumerate(candidates, 1)
    )
    return f"""A static analyzer flagged the following candidate issues in the Solidity contract below.
Static analyzers are noisy: many candidates are false positives (e.g. the value is guarded
elsewhere, the function is access-restricted, the compiler checks overflow, the timestamp
tolerance is irrelevant, or the pattern is unreachable).

For EACH candidate decide whether it is a real, exploitable vulnerability of the stated category.

Candidates:
{items}

Contract:
```solidity
{numbered(source)}
```

Respond with JSON:
{{"verdicts": [{{"id": <candidate number>,
  "verdict": "vulnerable" | "not_vulnerable",
  "confidence": <0.0-1.0>,
  "explanation": "<2-3 sentences, cite line numbers>",
  "exploit": "<concrete attack steps, or empty if not vulnerable>",
  "fix": "<minimal code-level fix, or empty>"}}]}}"""


def discover_prompt(source: str) -> str:
    return f"""Audit the Solidity contract below. Report every vulnerability you can justify with a
concrete exploit. Use exactly these category keys:
{taxonomy_prompt_block()}

Contract:
```solidity
{numbered(source)}
```

Respond with JSON:
{{"findings": [{{"category": "<category key>",
  "lines": [<line numbers where the vulnerable statement is>],
  "function": "<function name>",
  "confidence": <0.0-1.0>,
  "explanation": "<2-3 sentences>",
  "exploit": "<concrete attack steps>",
  "fix": "<minimal fix>"}}]}}
Return {{"findings": []}} if the contract is safe."""


def parse_json(text: str) -> Any:
    """Extract the first JSON value from a model response (tolerates code fences / prose)."""
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if fence:
        text = fence.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    decoder = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch in "{[":
            try:
                value, _ = decoder.raw_decode(text[i:])
                return value
            except json.JSONDecodeError:
                continue
    raise ValueError(f"No JSON found in model response: {text[:200]!r}")


def as_float(x: Any, default: float = 0.5) -> float:
    try:
        return max(0.0, min(1.0, float(x)))
    except (TypeError, ValueError):
        return default
