"""Shared helpers for the pattern-based detectors."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator

from ..findings import Finding
from ..solidity import Function, SourceUnit

Detector = Callable[[SourceUnit], list[Finding]]

REGISTRY: list[tuple[str, Detector]] = []


def detector(category: str) -> Callable[[Detector], Detector]:
    def wrap(fn: Detector) -> Detector:
        REGISTRY.append((category, fn))
        return fn

    return wrap


AUTH_MODIFIER_RE = re.compile(r"only|owner|admin|auth|restricted|governance|guardian|role", re.I)
AUTH_BODY_RE = re.compile(
    r"msg\.sender\s*[!=]=|[!=]=\s*msg\.sender|\b(?:isOwner|_checkOwner|_checkRole|hasRole|onlyOwner)\b"
)
REENTRANCY_GUARD_RE = re.compile(r"nonReentrant|noReentrancy|noReentrant|reentrancyGuard|mutex|lock", re.I)


def find_in_body(unit: SourceUnit, fn: Function, pattern: str | re.Pattern) -> Iterator[re.Match]:
    """Yield matches of ``pattern`` inside ``fn``'s body (offsets are global)."""
    if not fn.has_body:
        return
    rx = re.compile(pattern) if isinstance(pattern, str) else pattern
    yield from rx.finditer(unit.masked, fn.body_start, fn.body_end + 1)


def has_auth_check(unit: SourceUnit, fn: Function) -> bool:
    """Heuristic: is ``fn`` restricted to privileged callers?"""
    if AUTH_BODY_RE.search(unit.body(fn)):
        return True
    for name in fn.modifiers:
        if AUTH_MODIFIER_RE.search(name):
            return True
        mod = fn.contract.modifier(name)
        if mod is not None and AUTH_BODY_RE.search(unit.body(mod)):
            return True
    return False


def has_reentrancy_guard(unit: SourceUnit, fn: Function) -> bool:
    return any(REENTRANCY_GUARD_RE.search(m) for m in fn.modifiers)


def state_write_pattern(names: set[str]) -> re.Pattern | None:
    """Regex matching a write to any of the given state variables."""
    if not names:
        return None
    alt = "|".join(sorted(map(re.escape, names), key=len, reverse=True))
    index = r"(?:\s*\[[^\]]*\]|\s*\.\s*[A-Za-z_]\w*)*"
    return re.compile(
        rf"(?<![\w.])(?:{alt}){index}\s*(?:=(?!=)|\+=|-=|\*=|/=|%=|\+\+|--)"
        rf"|\bdelete\s+(?:{alt})\b"
        rf"|(?<![\w.])(?:{alt}){index}\s*\.\s*(?:push|pop)\s*\("
    )


def storage_aliases(unit: SourceUnit, fn: Function, state: set[str]) -> set[str]:
    """Local storage pointers into state, e.g. ``var acc = accounts[msg.sender];``."""
    if not state:
        return set()
    alt = "|".join(map(re.escape, state))
    rx = rf"(?:\bvar|\bstorage)\s+([A-Za-z_]\w*)\s*=\s*(?:{alt})\b"
    return {m.group(1) for m in find_in_body(unit, fn, rx)}


def make_finding(
    unit: SourceUnit,
    fn: Function | None,
    offset: int,
    category: str,
    rule: str,
    title: str,
    message: str,
    confidence: str = "medium",
) -> Finding:
    line = unit.line_of(offset)
    return Finding(
        category=category,
        line=line,
        title=title,
        message=message,
        rule=rule,
        contract=fn.contract.name if fn else "",
        function=fn.name if fn else "",
        confidence=confidence,
        snippet=unit.line_text(line),
    )


def loop_bodies(unit: SourceUnit, fn: Function) -> Iterator[tuple[int, int, str]]:
    """Yield (start, end, header) for every for/while loop in ``fn``."""
    from ..solidity import match_brace, statement_end

    s = unit.masked
    for m in find_in_body(unit, fn, r"\b(for|while)\s*\("):
        hdr_close = match_brace(s, m.end() - 1, "(", ")")
        header = s[m.end() : hdr_close]
        k = hdr_close + 1
        while k < len(s) and s[k].isspace():
            k += 1
        if k < len(s) and s[k] == "{":
            yield k, match_brace(s, k), header
        else:
            yield k, statement_end(s, k), header
