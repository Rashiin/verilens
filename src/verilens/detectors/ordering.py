"""Transaction-order dependence / front-running detector (SWC-114)."""

from __future__ import annotations

import re

from ..findings import Finding
from ..solidity import SourceUnit
from .base import detector, find_in_body, make_finding

HASH_CALL_RE = re.compile(r"\b(?:keccak256|sha3|sha256)\s*\(")
PAYOUT_RE = re.compile(r"\.\s*(?:transfer|send)\s*\(|\.\s*call\s*(?:\.\s*value\s*\(|\{)")
ALLOWANCE_RE = re.compile(r"(?<![\w.])(_?(?:allowed|allowances?|approvals?)\w*)\s*\[[^\]]*\]\s*\[[^\]]*\]\s*=(?!=)")


@detector("front_running")
def front_running(unit: SourceUnit) -> list[Finding]:
    out: list[Finding] = []
    s = unit.masked
    for c in unit.contracts:
        public_fns = [f for f in c.functions if f.has_body and f.is_public and not f.is_constructor]

        for fn in public_fns:
            body = unit.body(fn)

            # ERC20 approve race: allowance overwritten without requiring it to be 0 first.
            if fn.name.lower() == "approve":
                for m in find_in_body(unit, fn, ALLOWANCE_RE):
                    if re.search(r"==\s*0\b|\b0\s*==", body):
                        continue
                    out.append(
                        make_finding(
                            unit,
                            fn,
                            m.start(),
                            "front_running",
                            "erc20-approve-race",
                            "ERC20 approve race condition",
                            "Changing a non-zero allowance directly lets the spender front-run the "
                            "change and spend both the old and the new allowance.",
                            "low",
                        )
                    )

            # Hash puzzle: a public "solution" checked against a stored hash and rewarded.
            if fn.params and PAYOUT_RE.search(body):
                for m in find_in_body(unit, fn, HASH_CALL_RE):
                    args = s[m.end() : s.find(")", m.end()) + 1]
                    if any(re.search(rf"\b{re.escape(p)}\b", args) for p in fn.params) and "==" in body:
                        out.append(
                            make_finding(
                                unit,
                                fn,
                                m.start(),
                                "front_running",
                                "public-solution",
                                "Submitted solution is visible in the mempool",
                                f"The answer passed to `{fn.name}` can be copied from the pending "
                                "transaction and resubmitted with a higher gas price to steal the reward.",
                                "medium",
                            )
                        )
                        break

        # Reward amount that one public function changes and another pays out.
        scalars = [v.name for v in c.state_vars if "mapping" not in v.type and "[" not in v.type]
        for var in scalars:
            write = re.compile(rf"(?<![\w.]){re.escape(var)}\s*(?:=(?!=)|\+=|-=)")
            writers = {f.name for f in public_fns if write.search(unit.body(f))}
            if not writers:
                continue
            pay = re.compile(
                rf"\.\s*(?:transfer|send)\s*\(\s*{re.escape(var)}\s*\)"
                rf"|\.\s*value\s*\(\s*{re.escape(var)}\s*\)|value\s*:\s*{re.escape(var)}\b"
            )
            for fn in public_fns:
                if fn.name in writers and len(writers) == 1:
                    continue
                for m in find_in_body(unit, fn, pay):
                    out.append(
                        make_finding(
                            unit,
                            fn,
                            m.start(),
                            "front_running",
                            "transaction-order-dependence",
                            "Payout depends on transaction order",
                            f"`{var}` is paid out here but can be changed by "
                            f"`{', '.join(sorted(writers))}`; whichever transaction is mined first "
                            "decides the amount.",
                            "low",
                        )
                    )
    return out
