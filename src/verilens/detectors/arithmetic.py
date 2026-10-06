"""Integer overflow / underflow detector (SWC-101)."""

from __future__ import annotations

import re

from ..findings import Finding
from ..solidity import SourceUnit, match_brace, statement_start
from .base import detector, find_in_body, make_finding, storage_aliases

COMPOUND_RE = re.compile(r"((?<![\w.])[A-Za-z_]\w*(?:\s*\[[^\]]*\]|\s*\.\s*[A-Za-z_]\w*)*)\s*(\+=|-=|\*=)\s*([^;]+);")
ASSIGN_RE = re.compile(r"((?<![\w.])[A-Za-z_]\w*(?:\s*\[[^\]]*\])*)\s*=(?!=)\s*([^;]+);")
BINARY_OP_RE = re.compile(r"[\w)\]]\s*[-+*]\s*[\w(]")
TIME_RE = re.compile(r"\b(?:seconds|minutes|hours|days|weeks|years|now)\b|block\.(?:timestamp|number)")


def _norm(x: str) -> str:
    return re.sub(r"\s+", "", x)


def _guarded(before: str, target: str, op: str, rhs: str) -> bool:
    b, t, r = _norm(before), re.escape(_norm(target)), re.escape(_norm(rhs))
    if op == "-=":
        return bool(re.search(rf"{t}>={r}|{r}<={t}|{t}<{r}|{r}>{t}", b))
    if op == "+=":
        return bool(re.search(rf"{t}\+{r}(?:>=|>){t}|{r}\+{t}(?:>=|>){t}|{t}\+{r}<=|{t}<=\w+-{r}", b))
    return False


def _unchecked_spans(unit: SourceUnit) -> list[tuple[int, int]]:
    s = unit.masked
    spans = []
    for m in re.finditer(r"\bunchecked\s*\{", s):
        open_idx = m.end() - 1
        spans.append((open_idx, match_brace(s, open_idx)))
    return spans


@detector("arithmetic")
def arithmetic(unit: SourceUnit) -> list[Finding]:
    out: list[Finding] = []
    s = unit.masked
    spans = _unchecked_spans(unit)
    checked = unit.has_checked_arithmetic
    if checked and not spans:
        return out

    def in_scope(offset: int) -> bool:
        return not checked or any(a <= offset <= b for a, b in spans)

    for c in unit.contracts:
        if c.kind == "library":
            continue  # SafeMath-style libraries guard their own operations
        state = c.state_var_names
        for fn in c.functions:
            if fn.kind == "modifier" or fn.is_readonly or not fn.has_body:
                continue
            persistent = state | storage_aliases(unit, fn, state)
            for m in find_in_body(unit, fn, COMPOUND_RE):
                target, op, rhs = m.group(1), m.group(2), m.group(3)
                root = re.match(r"[A-Za-z_]\w*", target).group(0)
                if root not in persistent or not in_scope(m.start()) or TIME_RE.search(rhs):
                    continue
                if _guarded(s[fn.body_start : m.start()], target, op, rhs):
                    continue
                verb = {"+=": "overflow", "-=": "underflow", "*=": "overflow"}[op]
                out.append(
                    make_finding(
                        unit,
                        fn,
                        m.start(),
                        "arithmetic",
                        "unchecked-compound-op",
                        f"Possible integer {verb}",
                        f"`{_norm(target)} {op} ...` on state without overflow protection "
                        f"({'inside an unchecked block' if checked else 'compiler < 0.8, no SafeMath'}).",
                        "medium",
                    )
                )
            for m in find_in_body(unit, fn, ASSIGN_RE):
                target, rhs = m.group(1), m.group(2)
                st = statement_start(s, m.start(), fn.body_start + 1)
                if re.search(r"\b(?:for|require|assert|if)\b", s[st : m.start()]):
                    continue
                root = re.match(r"[A-Za-z_]\w*", target).group(0)
                if not BINARY_OP_RE.search(rhs) or TIME_RE.search(rhs) or not in_scope(m.start()):
                    continue
                rhs_state = {v for v in state if re.search(rf"(?<![\w.]){re.escape(v)}\b", rhs)}
                if root not in state and not rhs_state:
                    continue
                if root in state and re.search(rf"(?<![\w.]){re.escape(root)}\b", rhs):
                    conf = "medium"
                else:
                    conf = "low"
                out.append(
                    make_finding(
                        unit,
                        fn,
                        m.start(),
                        "arithmetic",
                        "unchecked-binary-op",
                        "Possible integer overflow/underflow",
                        f"Unchecked arithmetic `{_norm(rhs)[:60]}` involving contract state.",
                        conf,
                    )
                )
    return out
