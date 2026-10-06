"""Vulnerability taxonomy.

We use the DASP-10 categories adopted by the SmartBugs-curated benchmark so
that results are directly comparable with prior work, and attach the most
relevant SWC registry identifiers to each category.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Category:
    key: str
    title: str
    swc: tuple[str, ...]
    description: str


CATEGORIES: dict[str, Category] = {
    c.key: c
    for c in [
        Category(
            "reentrancy",
            "Reentrancy",
            ("SWC-107",),
            "An external call hands control to an untrusted contract before the "
            "caller has finished updating its own state, so the callee can re-enter "
            "and act on stale state (e.g. withdraw twice).",
        ),
        Category(
            "access_control",
            "Access control",
            ("SWC-105", "SWC-106", "SWC-112", "SWC-115", "SWC-118", "SWC-124"),
            "A privileged action (ownership change, selfdestruct, fund withdrawal, "
            "delegatecall, arbitrary storage write) is reachable by unauthorised "
            "callers, or authorisation relies on tx.origin / a mis-named constructor.",
        ),
        Category(
            "arithmetic",
            "Integer overflow / underflow",
            ("SWC-101",),
            "Unchecked integer arithmetic wraps around (Solidity < 0.8, or inside an "
            "`unchecked` block), corrupting balances or bypassing checks.",
        ),
        Category(
            "unchecked_low_level_calls",
            "Unchecked low-level call",
            ("SWC-104",),
            "The boolean result of call / send / delegatecall / callcode is ignored, "
            "so a failed transfer silently continues execution.",
        ),
        Category(
            "denial_of_service",
            "Denial of service",
            ("SWC-113", "SWC-128"),
            "A function can be blocked permanently, e.g. by a reverting recipient in "
            "a push-payment, or by loops whose gas cost grows without bound.",
        ),
        Category(
            "bad_randomness",
            "Bad randomness",
            ("SWC-120",),
            "Randomness derived from block variables (timestamp, blockhash, number, "
            "difficulty/prevrandao) that miners/validators or other contracts can "
            "predict or influence.",
        ),
        Category(
            "front_running",
            "Front running / transaction-order dependence",
            ("SWC-114",),
            "The outcome depends on transaction ordering, so an observer of the "
            "mempool can profit by submitting a competing transaction first.",
        ),
        Category(
            "time_manipulation",
            "Timestamp dependence",
            ("SWC-116",),
            "Security-relevant logic depends on block.timestamp/now with a "
            "granularity a block producer can manipulate (~seconds).",
        ),
        Category(
            "short_addresses",
            "Short address",
            (),
            "The EVM pads under-length calldata, which can scale token amounts when input length is not validated.",
        ),
        Category("other", "Other", (), "Vulnerabilities outside the categories above."),
    ]
}

ALIASES = {
    "unchecked_ll_calls": "unchecked_low_level_calls",
    "unchecked_calls": "unchecked_low_level_calls",
    "unchecked_call": "unchecked_low_level_calls",
    "unchecked_low_level_call": "unchecked_low_level_calls",
    "integer_overflow": "arithmetic",
    "overflow": "arithmetic",
    "underflow": "arithmetic",
    "integer_overflow_underflow": "arithmetic",
    "dos": "denial_of_service",
    "timestamp_dependence": "time_manipulation",
    "timestamp": "time_manipulation",
    "weak_randomness": "bad_randomness",
    "randomness": "bad_randomness",
    "transaction_order_dependence": "front_running",
    "tod": "front_running",
    "frontrunning": "front_running",
    "authorization": "access_control",
    "tx_origin": "access_control",
}


def normalize_category(name: str) -> str | None:
    """Map a free-form category name (e.g. from an LLM) onto a taxonomy key."""
    key = name.strip().lower().replace("-", "_").replace(" ", "_")
    if key in CATEGORIES:
        return key
    return ALIASES.get(key)


def taxonomy_prompt_block() -> str:
    return "\n".join(f"- {c.key}: {c.description}" for c in CATEGORIES.values())
