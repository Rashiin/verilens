"""Detectors for misuse of block variables: bad randomness (SWC-120) and
timestamp dependence (SWC-116)."""

from __future__ import annotations

import re

from ..findings import Finding
from ..solidity import SourceUnit
from .base import detector, make_finding

STRONG_ENTROPY_RE = re.compile(
    r"\bblock\s*\.\s*(?:blockhash|difficulty|prevrandao|coinbase|gaslimit)\b|(?<![\w.])blockhash\s*\("
)
TIMESTAMP_RE = re.compile(r"\bblock\s*\.\s*timestamp\b|(?<![\w.])now\b")
WEAK_ENTROPY_RE = re.compile(r"\bblock\s*\.\s*(?:timestamp|number)\b|(?<![\w.])now\b")
HASH_RE = re.compile(r"\b(?:keccak256|sha3|sha256|ripemd160)\s*\(")
MIXING_RE = re.compile(HASH_RE.pattern + r"|%")
RANDOM_NAME_RE = re.compile(r"\b\w*(?:rand|seed|lucky|winner|entropy)\w*\s*=(?!=)", re.I)
COMPARISON_OP_RE = re.compile(r"(?<![<>=!])(?:[<>]=?|==|!=)(?![<>=])")


@detector("bad_randomness")
def bad_randomness(unit: SourceUnit) -> list[Finding]:
    out = []
    offset = 0
    for line in unit.masked.split("\n"):
        strong = STRONG_ENTROPY_RE.search(line)
        weak = WEAK_ENTROPY_RE.search(line)
        mixed = MIXING_RE.search(line) or RANDOM_NAME_RE.search(line)
        # Timestamp/number on their own are usually deadlines (time_manipulation);
        # they become randomness only when hashed or stored as a seed.
        weak_as_entropy = weak and (HASH_RE.search(line) or RANDOM_NAME_RE.search(line))
        hit = strong or (weak if weak_as_entropy else None)
        if hit:
            fn = unit.function_at(offset + hit.start())
            if not (fn and fn.kind == "modifier"):
                out.append(
                    make_finding(
                        unit,
                        fn,
                        offset + hit.start(),
                        "bad_randomness",
                        "block-entropy",
                        "Predictable randomness from block variables",
                        f"`{hit.group(0).strip()}` is known to (or chosen by) the block producer and "
                        "readable by other contracts in the same block, so derived 'random' values "
                        "can be predicted or biased.",
                        "high" if mixed else "medium",
                    )
                )
        offset += len(line) + 1
    return out


@detector("time_manipulation")
def time_manipulation(unit: SourceUnit) -> list[Finding]:
    out = []
    offset = 0
    for line in unit.masked.split("\n"):
        ts = TIMESTAMP_RE.search(line)
        if not ts:
            offset += len(line) + 1
            continue
        mod = re.search(r"(?:\bblock\s*\.\s*timestamp\b|(?<![\w.])now\b)\s*%", line)
        cmp_ = COMPARISON_OP_RE.search(line.replace("=>", "  "))
        hit = ts if (cmp_ or mod) else None
        if hit:
            fn = unit.function_at(offset + hit.start())
            exact = mod is not None or (cmp_ is not None and cmp_.group(0) in ("==", "!="))
            out.append(
                make_finding(
                    unit,
                    fn,
                    offset + hit.start(),
                    "time_manipulation",
                    "timestamp-dependence",
                    "Logic depends on block.timestamp",
                    "Block producers can shift the timestamp by several seconds; "
                    + (
                        "exact equality/modulo checks on it are directly exploitable."
                        if exact
                        else "this is only safe if the logic tolerates that drift."
                    ),
                    "medium" if exact else "low",
                )
            )
        offset += len(line) + 1
    return out
