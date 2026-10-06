"""Minimal, dependency-free LLM client abstraction.

Every provider implements ``_complete(system, prompt) -> str``. The base class
adds what matters for reproducible research on a free API tier:

* a content-addressed on-disk cache (same model + prompt -> same answer, no
  repeated quota use; re-running a benchmark is free and deterministic),
* client-side rate limiting (requests per minute),
* retries with exponential backoff on 429 / 5xx.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


class LLMError(RuntimeError):
    pass


class LLMClient:
    provider = "base"

    def __init__(
        self,
        model: str,
        cache_dir: str | os.PathLike | None = None,
        rpm: float | None = None,
        max_retries: int = 5,
        timeout: float = 120.0,
    ):
        self.model = model
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.min_interval = 60.0 / rpm if rpm else 0.0
        self.max_retries = max_retries
        self.timeout = timeout
        self._last_call = 0.0
        self.calls = 0  # network calls actually made
        self.cache_hits = 0

    # ------------------------------------------------------------------ API
    @property
    def name(self) -> str:
        return f"{self.provider}:{self.model}"

    def complete(self, system: str, prompt: str) -> str:
        key = hashlib.sha256(f"{self.name}\x00{system}\x00{prompt}".encode()).hexdigest()
        path = self.cache_dir / f"{key}.json" if self.cache_dir else None
        if path and path.exists():
            self.cache_hits += 1
            return json.loads(path.read_text())["response"]

        wait = self.min_interval - (time.monotonic() - self._last_call)
        if wait > 0:
            time.sleep(wait)
        response = self._with_retries(system, prompt)
        self._last_call = time.monotonic()
        self.calls += 1

        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"model": self.name, "response": response}, ensure_ascii=False))
        return response

    # -------------------------------------------------------------- helpers
    def _complete(self, system: str, prompt: str) -> str:  # pragma: no cover - abstract
        raise NotImplementedError

    def _with_retries(self, system: str, prompt: str) -> str:
        delay = 2.0
        for attempt in range(self.max_retries + 1):
            try:
                return self._complete(system, prompt)
            except urllib.error.HTTPError as e:
                retryable = e.code == 429 or e.code >= 500
                if not retryable or attempt == self.max_retries:
                    body = e.read().decode(errors="replace")[:500]
                    raise LLMError(f"{self.name}: HTTP {e.code}: {body}") from e
                retry_after = e.headers.get("Retry-After") if e.headers else None
                time.sleep(float(retry_after) if retry_after and retry_after.isdigit() else delay)
                delay = min(delay * 2, 60)
            except (urllib.error.URLError, TimeoutError) as e:
                if attempt == self.max_retries:
                    raise LLMError(f"{self.name}: {e}") from e
                time.sleep(delay)
                delay = min(delay * 2, 60)
        raise LLMError("unreachable")

    def _post_json(self, url: str, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", **headers},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode())


class ReplayClient(LLMClient):
    """Returns canned responses; used in tests and offline demos."""

    provider = "replay"

    def __init__(self, responder, model: str = "replay", **kw):
        super().__init__(model=model, **kw)
        self.responder = responder

    def _complete(self, system: str, prompt: str) -> str:
        return self.responder(system, prompt)
