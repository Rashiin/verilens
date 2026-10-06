"""Exercise the real HTTP code paths of both providers against a local mock server."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from verilens.llm.base import LLMError
from verilens.llm.providers import GeminiClient, OpenAICompatibleClient


@pytest.fixture
def server():
    state = {"requests": [], "fail_first": 0}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state["requests"].append((self.path, {k.lower(): v for k, v in self.headers.items()}, body))
            if state["fail_first"] > 0:
                state["fail_first"] -= 1
                self.send_response(429)
                self.send_header("Retry-After", "0")
                self.end_headers()
                return
            if "generateContent" in self.path:
                out = {"candidates": [{"content": {"parts": [{"text": '{"ok": '}, {"text": "true}"}]}}]}
            else:
                out = {"choices": [{"message": {"content": '{"ok": true}'}}]}
            data = json.dumps(out).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    state["url"] = f"http://127.0.0.1:{httpd.server_port}"
    yield state
    httpd.shutdown()


def test_gemini_request_shape_and_retry(server):
    server["fail_first"] = 1
    c = GeminiClient(model="m", api_key="k", base_url=server["url"] + "/v1beta")
    assert c.complete("sys", "hello") == '{"ok": true}'
    path, headers, body = server["requests"][-1]
    assert path == "/v1beta/models/m:generateContent"
    assert headers["x-goog-api-key"] == "k"
    assert body["systemInstruction"]["parts"][0]["text"] == "sys"
    assert body["generationConfig"]["temperature"] == 0
    assert len(server["requests"]) == 2  # one 429, then success


def test_openai_compatible_request_shape(server):
    c = OpenAICompatibleClient(model="qwen", base_url=server["url"] + "/v1")
    assert c.complete("sys", "hi") == '{"ok": true}'
    path, headers, body = server["requests"][-1]
    assert path == "/v1/chat/completions"
    assert [m["role"] for m in body["messages"]] == ["system", "user"]


def test_gemini_requires_key(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    with pytest.raises(LLMError):
        GeminiClient()


def test_non_retryable_error_is_reported(server):
    server["fail_first"] = 99
    c = GeminiClient(model="m", api_key="k", base_url=server["url"], max_retries=1)
    with pytest.raises(LLMError, match="429"):
        c.complete("s", "p")
