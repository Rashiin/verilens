"""Interactive demo: paste a contract, see static candidates and LLM verdicts.

    pip install -e ".[demo]"
    python app/app.py              # static mode works without any key
    GEMINI_API_KEY=... python app/app.py

Also runs unchanged as a Hugging Face Space (set GEMINI_API_KEY as a secret).
"""

from __future__ import annotations

import html
import os
import sys
from pathlib import Path

import gradio as gr

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from verilens.bench.datasets import load_pairs  # noqa: E402
from verilens.llm.base import LLMError  # noqa: E402
from verilens.llm.providers import GeminiClient  # noqa: E402
from verilens.pipeline import analyze  # noqa: E402
from verilens.taxonomy import CATEGORIES  # noqa: E402

EXAMPLES = {f"{s.path.removesuffix('.sol')}": s.source for s in load_pairs()}
DEFAULT = "reentrancy/guarded_vault_vuln"

CSS = """
.finding {border:1px solid var(--border-color-primary); border-radius:10px; padding:12px 14px; margin:10px 0}
.finding .head {display:flex; gap:8px; align-items:center; flex-wrap:wrap; font-weight:600}
.pill {font-size:12px; padding:2px 8px; border-radius:999px; font-weight:600}
.high {background:#fde2e1; color:#a61b1b} .medium {background:#fff1d6; color:#8a5300} .low {background:#e3f0ff; color:#1f4f8f}
.ok {background:#dcf5e3; color:#17663a} .no {background:#eceff3; color:#4a5565}
.finding code {font-size:12.5px}
.muted {opacity:.75; font-size:13px}
"""


def _card(f, rejected: bool = False) -> str:
    cat = CATEGORIES[f.category].title if f.category in CATEGORIES else f.category
    verdict = ""
    if f.verdict:
        cls = "ok" if f.verdict == "vulnerable" else "no"
        label = "LLM: confirmed" if f.verdict == "vulnerable" else "LLM: false positive"
        verdict = f'<span class="pill {cls}">{label} · {f.llm_confidence:.2f}</span>'
    parts = [
        f'<div class="finding" style="{"opacity:.6" if rejected else ""}">',
        f'<div class="head"><span class="pill {f.confidence}">{f.confidence}</span>'
        f"<span>Line {f.line} · {html.escape(cat)}</span>{verdict}</div>",
        f"<div><code>{html.escape(f.snippet)}</code></div>",
        f'<div class="muted">{html.escape(f.explanation or f.message)}</div>',
    ]
    if f.exploit:
        parts.append(f"<div><b>Exploit:</b> {html.escape(f.exploit)}</div>")
    if f.fix:
        parts.append(f"<div><b>Fix:</b> {html.escape(f.fix)}</div>")
    parts.append("</div>")
    return "".join(parts)


def run(source: str, mode: str, api_key: str) -> tuple[str, str]:
    llm = None
    if mode != "static":
        try:
            llm = GeminiClient(api_key=api_key or None, rpm=10)
        except LLMError as e:
            return f"<p>{html.escape(str(e))}</p>", ""
    res = analyze(source, mode=mode, llm=llm)
    kept = {(f.category, f.line) for f in res.findings}
    rejected = [f for f in res.candidates if (f.category, f.line) not in kept]

    summary = f"**{len(res.findings)} finding(s)** · mode `{mode}` · {res.seconds:.2f}s"
    if mode in ("hybrid", "hybrid-plus") and res.candidates:
        summary += f" · LLM rejected {len(rejected)} of {len(res.candidates)} static candidates"
    if res.errors:
        summary += f" · ⚠️ {len(res.errors)} LLM error(s), unverified candidates kept"

    body = "".join(_card(f) for f in res.findings) or "<p>No vulnerabilities reported.</p>"
    if rejected:
        body += "<h4>Filtered out by the LLM</h4>" + "".join(_card(f, rejected=True) for f in rejected)
    return body, summary


# Gradio 6 moved theme/css from Blocks() to launch().
_GRADIO6 = int(gr.__version__.split(".")[0]) >= 6
STYLE = {"css": CSS, "theme": gr.themes.Soft()}

with gr.Blocks(title="verilens", **({} if _GRADIO6 else STYLE)) as demo:
    gr.Markdown(
        "# verilens\n"
        "LLM-verified static analysis for Solidity. Static detectors propose candidates with high recall; "
        "an LLM acts as a skeptical auditor and keeps only the ones it can justify with a concrete exploit."
    )
    with gr.Row():
        with gr.Column(scale=3):
            example = gr.Dropdown(list(EXAMPLES), value=DEFAULT, label="Example (from the contrastive-pairs benchmark)")
            code = gr.Code(EXAMPLES[DEFAULT], language="javascript", label="Solidity source", lines=26)
        with gr.Column(scale=2):
            mode = gr.Radio(["static", "hybrid", "hybrid-plus", "llm"], value="static", label="Mode")
            key = gr.Textbox(
                label="Gemini API key (only for LLM modes; used for this request, never stored)",
                type="password",
                value="",
                placeholder="uses GEMINI_API_KEY if empty",
            )
            go = gr.Button("Analyze", variant="primary")
            summary = gr.Markdown()
            results = gr.HTML()
    example.change(lambda name: EXAMPLES[name], example, code)
    go.click(run, [code, mode, key], [results, summary])

if __name__ == "__main__":
    demo.launch(server_name=os.getenv("HOST", "127.0.0.1"), **(STYLE if _GRADIO6 else {}))
