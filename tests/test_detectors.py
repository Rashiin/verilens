import pytest

from verilens.bench.datasets import load_pairs
from verilens.detectors import SUPPORTED_CATEGORIES, run_static
from verilens.solidity import SourceUnit

PAIRS = load_pairs()


def scan(src: str):
    return run_static(SourceUnit(src))


@pytest.mark.parametrize("sample", [s for s in PAIRS if not s.meta.get("safe")], ids=lambda s: s.path)
def test_static_layer_flags_every_vulnerable_twin(sample):
    """Recall regression test: the static layer is the candidate generator, so it must
    report each labelled vulnerability (category + line within 2)."""
    findings = scan(sample.source)
    for cat, line in sample.labels:
        assert any(f.category == cat and abs(f.line - line) <= 2 for f in findings), (cat, line, findings)


def test_supported_categories():
    assert set(SUPPORTED_CATEGORIES) == {
        "access_control",
        "arithmetic",
        "bad_randomness",
        "denial_of_service",
        "front_running",
        "reentrancy",
        "time_manipulation",
        "unchecked_low_level_calls",
    }


@pytest.mark.parametrize(
    "stmt",
    [
        "require(a.send(1));",
        "if (!a.send(1)) revert();",
        "bool ok = a.send(1); require(ok);",
        '(bool ok, ) = a.call{value: 1}(""); if (!ok) revert();',
        "return a.send(1);",
    ],
)
def test_checked_low_level_calls_are_not_reported(stmt):
    src = f"pragma solidity ^0.8.0; contract C {{ function f(address payable a) public returns (bool) {{ {stmt} }} }}"
    assert not [f for f in scan(src) if f.category == "unchecked_low_level_calls"]


@pytest.mark.parametrize("stmt", ["a.send(1);", 'a.call{value: 1}("");', '(bool ok, ) = a.call("");'])
def test_unchecked_low_level_calls_are_reported(stmt):
    src = f"pragma solidity ^0.8.0; contract C {{ function f(address payable a) public {{ {stmt} }} }}"
    assert [f for f in scan(src) if f.category == "unchecked_low_level_calls"]


def test_reentrancy_through_storage_pointer():
    src = """pragma solidity ^0.4.25;
contract W {
    struct Holder { uint balance; }
    mapping(address => Holder) public Acc;
    function Collect(uint _am) public {
        var acc = Acc[msg.sender];
        if (msg.sender.call.value(_am)()) {
            acc.balance -= _am;
        }
    }
}"""
    (f,) = [f for f in scan(src) if f.category == "reentrancy"]
    assert f.line == 7 and f.confidence == "high"


def test_reentrancy_guard_modifier_suppresses_report():
    src = """pragma solidity ^0.8.0;
contract V {
    mapping(address => uint) b;
    function w() external nonReentrant {
        (bool ok, ) = msg.sender.call{value: b[msg.sender]}("");
        require(ok);
        b[msg.sender] = 0;
    }
}"""
    assert not [f for f in scan(src) if f.category == "reentrancy"]


def test_checked_arithmetic_compiler_is_not_reported():
    src = "pragma solidity ^0.8.4; contract T { uint s; function f(uint x) public { s += x; } }"
    assert not scan(src)


def test_comments_and_strings_never_trigger_detectors():
    src = 'pragma solidity ^0.8.0; contract C { string s = "selfdestruct(x)"; // tx.origin == owner\n}'
    assert not scan(src)
