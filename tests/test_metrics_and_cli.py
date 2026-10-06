import json

from verilens.bench.datasets import Sample, load_pairs
from verilens.bench.metrics import Scorer
from verilens.bench.run import run_benchmark, to_markdown
from verilens.cli import main
from verilens.findings import Finding


def F(cat, line):
    return Finding(category=cat, line=line, title="t", message="m")


def test_scorer_category_and_line_level():
    sc = Scorer(tolerance=1)
    sc.add(Sample("a", "a.sol", "", labels=[("reentrancy", 10)]), [F("reentrancy", 11), F("arithmetic", 3)])
    sc.add(Sample("b", "b.sol", "", labels=[("arithmetic", 5)], meta={"safe": False}), [])
    sc.add(
        Sample("c", "c.sol", "", labels=[], meta={"safe": True, "fixed_category": "reentrancy"}), [F("reentrancy", 2)]
    )
    s = sc.summary()
    cm = s["category_level_micro"]
    assert (cm["tp"], cm["fp"], cm["fn"]) == (1, 2, 1)
    assert s["line_level_micro"]["precision"] == round(1 / 3, 4)
    assert s["line_level_micro"]["recall"] == 0.5
    assert s["safe_twin_false_alarm_rate"] == 1.0


def test_pairs_benchmark_static_has_full_recall():
    summary = run_benchmark(load_pairs(), "static", "contrastive-pairs", progress=False)
    assert summary["samples"] == 34
    assert summary["category_level_micro"]["recall"] == 1.0
    assert "Category (micro)" in to_markdown(summary)


def test_cli_scan_text_json_sarif(tmp_path, capsys):
    sol = tmp_path / "Bank.sol"
    sol.write_text(
        "pragma solidity ^0.8.0;\ncontract C {\n function f(address payable a) public {\n  a.send(1);\n }\n}\n"
    )
    assert main(["scan", str(sol)]) == 0
    assert "unchecked_low_level_calls" in capsys.readouterr().out

    main(["scan", str(sol), "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["findings"][0]["line"] == 4

    out = tmp_path / "out.sarif"
    main(["scan", str(sol), "--format", "sarif", "-o", str(out)])
    sarif = json.loads(out.read_text())
    assert sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 4

    assert main(["scan", str(sol), "--fail-on-findings"]) == 1


def test_cli_llm_mode_without_key_is_a_clean_error(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    sol = tmp_path / "a.sol"
    sol.write_text("pragma solidity ^0.8.0; contract C {}")
    assert main(["scan", str(sol), "--mode", "hybrid"]) == 2
    assert "GEMINI_API_KEY" in capsys.readouterr().err
