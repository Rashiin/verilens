"""Access-control detectors (SWC-105/106/112/115/118/124)."""

from __future__ import annotations

import re

from ..findings import Finding
from ..solidity import SourceUnit
from .base import detector, find_in_body, has_auth_check, make_finding

PRIVILEGED_VAR_RE = re.compile(
    r"^(?:\w*owner\w*|admin\w*|creator|ceo\w*|controller|authority|manager|operator|governance)$", re.I
)
INIT_GUARD_RE = re.compile(
    r"require\s*\(\s*!\s*\w*initiali[sz]ed|initializer|==\s*(?:address\s*\(\s*0\s*\)|0x0+\b|0\b)"
)


def _edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


@detector("access_control")
def access_control(unit: SourceUnit) -> list[Finding]:
    out: list[Finding] = []
    legacy = unit.pragma_min_version is None or unit.pragma_min_version < (0, 5, 0)

    for c in unit.contracts:
        privileged = {v.name for v in c.state_vars if PRIVILEGED_VAR_RE.match(v.name)}

        for fn in c.functions:
            if not fn.has_body:
                continue

            for m in find_in_body(unit, fn, r"tx\.origin\s*[!=]=|[!=]=\s*tx\.origin"):
                out.append(
                    make_finding(
                        unit,
                        fn,
                        m.start(),
                        "access_control",
                        "tx-origin-auth",
                        "Authorisation via tx.origin",
                        "tx.origin is the externally-owned account that started the transaction; "
                        "a malicious contract the owner interacts with can pass this check (phishing).",
                        "high",
                    )
                )

            if fn.kind == "modifier" or fn.is_constructor:
                continue
            public = fn.is_public
            authed = has_auth_check(unit, fn)

            if public and not authed:
                for m in find_in_body(unit, fn, r"\b(selfdestruct|suicide)\s*\("):
                    out.append(
                        make_finding(
                            unit,
                            fn,
                            m.start(),
                            "access_control",
                            "unprotected-selfdestruct",
                            "Unprotected selfdestruct",
                            f"Anyone can call `{fn.name}` and destroy the contract, sending its balance away.",
                            "high",
                        )
                    )
                for m in find_in_body(unit, fn, r"\.\s*(delegatecall|callcode)\s*[.({]"):
                    out.append(
                        make_finding(
                            unit,
                            fn,
                            m.start(),
                            "access_control",
                            "unprotected-delegatecall",
                            f"Unrestricted `{m.group(1)}`",
                            "Code from another address runs in this contract's storage context and "
                            "is reachable by any caller; with attacker-influenced target or calldata "
                            "this allows taking over the contract.",
                            "medium",
                        )
                    )
                if privileged and not INIT_GUARD_RE.search(unit.body(fn)):
                    alt = "|".join(map(re.escape, privileged))
                    for m in find_in_body(unit, fn, rf"(?<![\w.])({alt})\s*=(?!=)"):
                        out.append(
                            make_finding(
                                unit,
                                fn,
                                m.start(),
                                "access_control",
                                "unprotected-privileged-write",
                                f"Anyone can overwrite `{m.group(1)}`",
                                f"`{fn.name}` is callable by any account and assigns the privileged "
                                f"variable `{m.group(1)}` without an authorisation check.",
                                "high",
                            )
                        )

            if legacy:
                for m in find_in_body(unit, fn, r"\b[A-Za-z_]\w*(?:\[[^\]]*\])?\s*\.\s*length\s*(?:--|-=|\+=|=(?!=))"):
                    out.append(
                        make_finding(
                            unit,
                            fn,
                            m.start(),
                            "access_control",
                            "array-length-write",
                            "Direct write to a dynamic array's length",
                            "Shrinking/setting `.length` (pre-0.6) can underflow it and turn the "
                            "array into an arbitrary storage-write primitive.",
                            "medium",
                        )
                    )

            # Constructor mistakes (pre-0.5 compilers only).
            if legacy and fn.kind == "function":
                if fn.name == "constructor":
                    msg = (
                        "`function constructor()` is an ordinary public function in this compiler "
                        "version, so anyone can call it later and re-initialise the contract."
                    )
                elif fn.name != c.name and len(c.name) >= 5 and _edit_distance(fn.name.lower(), c.name.lower()) <= 2:
                    msg = (
                        f"`{fn.name}` looks like an intended constructor of `{c.name}` but the name "
                        "does not match exactly, so it is a public function anyone can call."
                    )
                else:
                    continue
                out.append(
                    make_finding(
                        unit,
                        fn,
                        fn.start,
                        "access_control",
                        "misnamed-constructor",
                        "Mis-named constructor",
                        msg,
                        "high",
                    )
                )
    return out
