from verilens.solidity import SourceUnit, mask_comments_and_strings, strip_comments

SRC = """pragma solidity ^0.4.24;
// a comment with tx.origin == owner
contract Bank {
    mapping(address => uint) public balances;
    address owner;
    struct Acc { uint balance; }
    string constant NAME = "call.value(";

    function Bank() public { owner = msg.sender; }
    function () public payable {}
    function withdraw(uint _amount) public onlyOwner returns (bool ok) {
        msg.sender.transfer(_amount);
    }
    modifier onlyOwner() { require(msg.sender == owner); _; }
}
"""


def test_masking_preserves_offsets_and_hides_comments_and_strings():
    masked = mask_comments_and_strings(SRC)
    assert len(masked) == len(SRC)
    assert masked.count("\n") == SRC.count("\n")
    assert "tx.origin" not in masked
    assert "call.value(" not in masked


def test_strip_comments_keeps_line_numbers():
    out = strip_comments(SRC)
    assert out.count("\n") == SRC.count("\n")
    assert "a comment" not in out
    assert '"call.value("' in out


def test_structure():
    u = SourceUnit(SRC)
    assert u.pragma_min_version == (0, 4, 24)
    assert not u.has_checked_arithmetic
    (c,) = u.contracts
    assert c.name == "Bank"
    assert {"balances", "owner", "NAME"} <= c.state_var_names
    kinds = {f.name: f.kind for f in c.functions}
    assert kinds["Bank"] == "constructor"
    assert kinds["fallback"] == "fallback"
    assert kinds["onlyOwner"] == "modifier"
    w = next(f for f in c.functions if f.name == "withdraw")
    assert w.params == ["_amount"]
    assert w.modifiers == ["onlyOwner"]
    assert w.is_public and not w.is_readonly
    assert u.line_of(w.start) == 11


def test_modern_syntax():
    u = SourceUnit(
        "pragma solidity >=0.8.0 <0.9.0;\n"
        "contract A is B, C(1) {\n"
        "  uint256[] public xs;\n"
        "  constructor() {}\n"
        "  receive() external payable {}\n"
        "  function f() external view returns (uint256) { return xs.length; }\n"
        "}\n"
    )
    assert u.has_checked_arithmetic
    c = u.contracts[0]
    assert c.bases == ["B", "C"]
    assert c.state_vars[0].name == "xs" and "[]" in c.state_vars[0].type
    assert [f.kind for f in c.functions] == ["constructor", "receive", "function"]
    assert c.functions[2].is_readonly
