"""Command-line interface.

verilens scan contracts/Token.sol                      # static only, no key needed
verilens scan Token.sol --mode hybrid                   # + Gemini verification
verilens scan Token.sol --mode hybrid --provider openai --model qwen2.5-coder:7b   # local Ollama
verilens fetch-smartbugs --dest data/smartbugs
verilens bench --dataset smartbugs --data data/smartbugs --mode hybrid
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .bench.datasets import fetch_smartbugs, load_pairs, load_smartbugs
from .bench.run import run_benchmark, to_markdown, write_report
from .llm.base import LLMError
from .llm.providers import make_client
from .pipeline import MODES, analyze
from .report import to_json, to_sarif, to_text

DEFAULT_CACHE = ".verilens_cache"


def _add_llm_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--mode", choices=MODES, default="static")
    p.add_argument("--provider", default="gemini", help="gemini | openai (any OpenAI-compatible API, e.g. Ollama)")
    p.add_argument("--model", default=None, help="model name (default: gemini-flash-latest)")
    p.add_argument("--base-url", default=None, help="override the API base URL (e.g. a local Ollama server)")
    p.add_argument("--threshold", type=float, default=0.5, help="minimum LLM confidence to keep a finding")
    p.add_argument("--rpm", type=float, default=None, help="max LLM requests per minute (free tiers)")
    p.add_argument("--cache-dir", default=DEFAULT_CACHE, help="LLM response cache ('' to disable)")


def _client(args):
    if args.mode == "static":
        return None
    kw = {"cache_dir": args.cache_dir or None, "rpm": args.rpm}
    if args.base_url:
        kw["base_url"] = args.base_url
    return make_client(args.provider, model=args.model, **kw)


def cmd_scan(args) -> int:
    llm = _client(args)
    results = {}
    files = []
    for p in args.paths:
        path = Path(p)
        files += sorted(path.rglob("*.sol")) if path.is_dir() else [path]
    exit_code = 0
    for f in files:
        res = analyze(f.read_text(encoding="utf-8", errors="replace"), args.mode, llm, args.threshold, str(f))
        results[str(f)] = res.findings
        for e in res.errors:
            print(f"warning: {f}: {e}", file=sys.stderr)
        if res.findings:
            exit_code = 1
        if args.format == "text":
            print(to_text(str(f), res.findings, color=sys.stdout.isatty()))
        elif args.format == "json":
            print(to_json(str(f), res.findings))
    if args.format == "sarif":
        out = to_sarif(results)
        if args.output:
            Path(args.output).write_text(out)
        else:
            print(out)
    return exit_code if args.fail_on_findings else 0


def cmd_bench(args) -> int:
    llm = _client(args)
    if args.dataset == "smartbugs":
        samples = load_smartbugs(args.data)
        name = "smartbugs-curated"
    else:
        samples = load_pairs(args.data)
        name = "contrastive-pairs"
    if args.limit:
        samples = samples[: args.limit]
    summary = run_benchmark(samples, args.mode, name, llm, args.threshold, args.tolerance)
    print(to_markdown(summary))
    j, m = write_report(summary, args.out)
    print(f"wrote {j} and {m}")
    return 0


def cmd_fetch(args) -> int:
    fetch_smartbugs(args.dest)
    print(f"SmartBugs-curated downloaded to {args.dest}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="verilens", description="LLM-verified static analysis for Solidity")
    ap.add_argument("--version", action="version", version=f"verilens {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="analyse .sol files or directories")
    s.add_argument("paths", nargs="+")
    s.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    s.add_argument("-o", "--output", help="write SARIF to this file")
    s.add_argument("--fail-on-findings", action="store_true", help="exit 1 if anything is found (CI)")
    _add_llm_args(s)
    s.set_defaults(func=cmd_scan)

    b = sub.add_parser("bench", help="evaluate on a labelled benchmark")
    b.add_argument("--dataset", choices=("smartbugs", "pairs"), default="pairs")
    b.add_argument("--data", default=None, help="dataset root (default for pairs: bundled)")
    b.add_argument("--out", default="results")
    b.add_argument("--limit", type=int, default=None)
    b.add_argument("--tolerance", type=int, default=2, help="line tolerance for line-level matching")
    _add_llm_args(b)
    b.set_defaults(func=cmd_bench)

    f = sub.add_parser("fetch-smartbugs", help="download SmartBugs-curated (pinned commit)")
    f.add_argument("--dest", default="data/smartbugs")
    f.set_defaults(func=cmd_fetch)

    args = ap.parse_args(argv)
    if getattr(args, "dataset", None) == "smartbugs" and not args.data:
        args.data = "data/smartbugs"
    try:
        return args.func(args)
    except (LLMError, FileNotFoundError, ConnectionError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
