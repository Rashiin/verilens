"""Detectors built around external calls: reentrancy, unchecked low-level
calls and denial of service via failing / unbounded calls."""

from __future__ import annotations

import re

from ..findings import Finding
from ..solidity import Function, SourceUnit, statement_end, statement_start
from .base import (
    detector,
    find_in_body,
    has_reentrancy_guard,
    loop_bodies,
    make_finding,
    state_write_pattern,
    storage_aliases,
)

# ``.call``/``.send``/... followed by an invocation, option block or .value()/.gas()
LOW_LEVEL_CALL_RE = re.compile(r"\.\s*(call|send|delegatecall|callcode)\s*(?=[.({])")
VALUE_TRANSFER_RE = re.compile(r"\s*(?:\.\s*(?:gas\s*\([^)]*\)\s*\.\s*)?value\s*\(|\{[^}]*\bvalue\s*:)")
ETHER_SEND_RE = re.compile(r"\.\s*(transfer|send)\s*\(")
OWNER_LIKE_RE = re.compile(r"owner|admin|creator|ceo|dev|beneficiary|wallet|treasury", re.I)
_TYPE_WORDS = {"bool", "bytes", "memory", "uint", "uint256", "address", "payable"}


def _assigned_names(prefix: str) -> list[str]:
    lhs = prefix.split("=", 1)[0]
    return [t for t in re.findall(r"[A-Za-z_]\w*", lhs) if t not in _TYPE_WORDS]


def call_result_is_checked(unit: SourceUnit, fn: Function, call_start: int) -> bool:
    """Decide whether the boolean returned by a low-level call is consumed."""
    s = unit.masked
    st = statement_start(s, call_start, fn.body_start + 1)
    prefix = s[st:call_start]
    if prefix.count("(") > prefix.count(")"):
        # The call is an argument of something: require(...), if (...), foo(...)
        return True
    if re.search(r"\breturn\b|!|&&|\|\||\?", prefix):
        return True
    if re.search(r"(?<![=!<>])=(?!=)", prefix):
        names = _assigned_names(prefix)
        rest = s[statement_end(s, call_start) + 1 : fn.body_end]
        return any(re.search(rf"\b{re.escape(n)}\b", rest) for n in names)
    return False


@detector("unchecked_low_level_calls")
def unchecked_low_level_calls(unit: SourceUnit) -> list[Finding]:
    out = []
    for fn in unit.functions():
        for m in find_in_body(unit, fn, LOW_LEVEL_CALL_RE):
            if call_result_is_checked(unit, fn, m.start()):
                continue
            kind = m.group(1)
            out.append(
                make_finding(
                    unit,
                    fn,
                    m.start(),
                    "unchecked_low_level_calls",
                    "unchecked-call",
                    f"Unchecked return value of `{kind}`",
                    f"The boolean returned by `.{kind}` is ignored; if the call fails, "
                    "execution continues as if it had succeeded.",
                    "high" if kind in ("send", "call") else "medium",
                )
            )
    return out


@detector("reentrancy")
def reentrancy(unit: SourceUnit) -> list[Finding]:
    out = []
    s = unit.masked
    for c in unit.contracts:
        for fn in c.functions:
            if fn.kind == "modifier" or fn.is_readonly or has_reentrancy_guard(unit, fn):
                continue
            state = c.state_var_names
            writes = state_write_pattern(state | storage_aliases(unit, fn, state))
            if writes is None:
                continue
            for m in find_in_body(unit, fn, LOW_LEVEL_CALL_RE):
                kind = m.group(1)
                if kind not in ("call", "callcode"):
                    continue  # send/transfer forward only 2300 gas; delegatecall is access control
                sends_value = bool(VALUE_TRANSFER_RE.match(s, m.end()))
                after = statement_end(s, m.start())
                w = writes.search(s, after, fn.body_end)
                if not w:
                    continue
                var = w.group(0).split("[")[0].split(".")[0].replace("delete", "").strip()
                out.append(
                    make_finding(
                        unit,
                        fn,
                        m.start(),
                        "reentrancy",
                        "state-write-after-call",
                        "State updated after external call",
                        f"`{fn.name}` makes an external `.{kind}` "
                        f"{'that forwards ether and all remaining gas ' if sends_value else ''}"
                        f"and only afterwards writes state variable `{var}` "
                        f"(line {unit.line_of(w.start())}). A re-entrant callee observes the stale value.",
                        "high" if sends_value else "medium",
                    )
                )
    return out


@detector("denial_of_service")
def denial_of_service(unit: SourceUnit) -> list[Finding]:
    out = []
    s = unit.masked
    for c in unit.contracts:
        arrays = {v.name for v in c.state_vars if "[" in v.type or v.type.endswith("[]")}
        state_names = c.state_var_names
        for fn in c.functions:
            if fn.kind == "modifier" or not fn.has_body:
                continue
            for start, end, header in loop_bodies(unit, fn):
                body = s[start : end + 1]
                call = re.search(r"\.\s*(transfer|send|call)\s*[.({]", body)
                if call:
                    out.append(
                        make_finding(
                            unit,
                            fn,
                            start + call.start(),
                            "denial_of_service",
                            "call-in-loop",
                            "External call inside a loop",
                            "A single failing or gas-hungry recipient makes the whole loop revert, "
                            "blocking every other recipient (prefer pull payments).",
                            "medium",
                        )
                    )
                length = re.search(r"([A-Za-z_]\w*)\s*\.\s*length", header)
                if length and length.group(1) in state_names:
                    out.append(
                        make_finding(
                            unit,
                            fn,
                            start - 1,
                            "denial_of_service",
                            "unbounded-loop",
                            "Loop bounded by a growing storage array",
                            f"The loop iterates over `{length.group(1)}`, whose length can grow "
                            "without bound until the function exceeds the block gas limit.",
                            "low",
                        )
                    )
                for p in re.finditer(r"([A-Za-z_]\w*)\s*\.\s*push\s*\(", body):
                    if p.group(1) in arrays:
                        out.append(
                            make_finding(
                                unit,
                                fn,
                                start + p.start(),
                                "denial_of_service",
                                "push-in-loop",
                                "Storage array grown inside a loop",
                                f"`{p.group(1)}` grows on every iteration; later operations over it "
                                "can exceed the block gas limit.",
                                "low",
                            )
                        )
            # Push payment to a stored address whose failure reverts the call.
            for m in find_in_body(unit, fn, ETHER_SEND_RE):
                st = statement_start(s, m.start(), fn.body_start + 1)
                receiver = s[st : m.start()].strip()
                unwrapped = re.sub(r"\b(?:payable|address)\s*\(", "", receiver)
                root = re.match(r"(?:require\s*\(|assert\s*\(|if\s*\(\s*!?)?\s*([A-Za-z_]\w*)", unwrapped)
                if not root:
                    continue
                name = root.group(1)
                if name not in state_names or OWNER_LIKE_RE.search(name):
                    continue
                reverts = m.group(1) == "transfer" or re.match(r"(require|assert)\s*\(|if\s*\(\s*!", unwrapped)
                if reverts:
                    out.append(
                        make_finding(
                            unit,
                            fn,
                            m.start(),
                            "denial_of_service",
                            "push-payment-revert",
                            "Push payment to a stored address can block the contract",
                            f"If `{name}` is a contract that rejects ether, this payment reverts "
                            f"and `{fn.name}` becomes permanently unusable.",
                            "medium",
                        )
                    )
    return out
