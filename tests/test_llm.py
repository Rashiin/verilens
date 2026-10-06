import json

import pytest

from verilens.llm.base import ReplayClient
from verilens.llm.prompts import parse_json
from verilens.pipeline import analyze

VULN = """pragma solidity ^0.8.20;
contract Bank {
    mapping(address => uint256) public balances;
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] = 0;
    }
    function lucky() external view returns (bool) {
        return block.timestamp > 1700000000;
    }
}"""


def verdicts(*items):
    return json.dumps({"verdicts": [dict(zip(("id", "verdict", "confidence"), it, strict=False)) for it in items]})


@pytest.mark.parametrize(
    "text",
    ['{"a": 1}', '```json\n{"a": 1}\n```', 'Sure! Here you go: {"a": 1} hope it helps', "[1]"],
)
def test_parse_json_tolerates_wrappers(text):
    assert parse_json(text) in ({"a": 1}, [1])


def test_parse_json_rejects_prose():
    with pytest.raises(ValueError):
        parse_json("no json here")


def test_hybrid_keeps_confirmed_and_drops_rejected():
    static = analyze(VULN, "static")
    assert [f.category for f in static.findings] == ["reentrancy", "time_manipulation"]
    llm = ReplayClient(lambda s, p: verdicts((1, "vulnerable", 0.9), (2, "not_vulnerable", 0.8)))
    res = analyze(VULN, "hybrid", llm)
    assert [f.category for f in res.findings] == ["reentrancy"]
    assert res.findings[0].verdict == "vulnerable"
    assert res.candidates[1].verdict == "not_vulnerable"
    assert not res.errors


def test_low_confidence_confirmations_are_dropped():
    llm = ReplayClient(lambda s, p: verdicts((1, "vulnerable", 0.3), (2, "vulnerable", 0.9)))
    res = analyze(VULN, "hybrid", llm, threshold=0.5)
    assert [f.category for f in res.findings] == ["time_manipulation"]


def test_hybrid_fails_open_on_malformed_response():
    res = analyze(VULN, "hybrid", ReplayClient(lambda s, p: "I cannot help with that"))
    assert len(res.findings) == 2
    assert res.errors


def test_llm_discovery_normalises_categories():
    payload = {
        "findings": [
            {"category": "Reentrancy", "lines": [6], "confidence": 0.9, "explanation": "x"},
            {"category": "integer overflow", "lines": [5], "confidence": 0.7},
            {"category": "made_up", "lines": [1], "confidence": 0.9},
        ]
    }
    res = analyze(VULN, "llm", ReplayClient(lambda s, p: json.dumps(payload)))
    assert [(f.category, f.line) for f in res.findings] == [("arithmetic", 5), ("reentrancy", 6)]
    assert any("made_up" in e for e in res.errors)


def test_cache_makes_reruns_free(tmp_path):
    calls = []
    llm = ReplayClient(
        lambda s, p: calls.append(1) or verdicts((1, "vulnerable", 1), (2, "vulnerable", 1)), cache_dir=tmp_path
    )
    analyze(VULN, "hybrid", llm)
    analyze(VULN, "hybrid", llm)
    assert len(calls) == 1 and llm.calls == 1 and llm.cache_hits == 1


def test_label_annotations_are_not_shown_to_the_llm():
    from verilens.bench.datasets import sanitize

    seen = []
    src = "/* @vulnerable_at_lines: 4 */\npragma solidity ^0.4.24;\ncontract C { function f(address a) public {\n// <yes> <report> UNCHECKED_LL_CALLS\na.send(1); } }"
    analyze(sanitize(src), "hybrid", ReplayClient(lambda s, p: seen.append(p) or verdicts((1, "vulnerable", 1))))
    assert seen and all("<yes>" not in p and "vulnerable_at_lines" not in p for p in seen)
