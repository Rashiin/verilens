"""HTTPS helpers shared by the LLM clients and the dataset downloader."""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from functools import lru_cache

SSL_HINT = (
    "TLS certificate verification failed. Your Python cannot find the system CA certificates. "
    "Fix: `pip install certifi` (verilens uses it automatically), or on macOS with the python.org "
    "installer run `/Applications/Python 3.X/Install Certificates.command`."
)


@lru_cache(maxsize=1)
def ssl_context() -> ssl.SSLContext:
    """Default TLS context, using certifi's CA bundle when it is installed."""
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def is_cert_error(err: BaseException) -> bool:
    reason = getattr(err, "reason", err)
    return isinstance(reason, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in str(err)


def urlopen(req: urllib.request.Request | str, timeout: float):
    return urllib.request.urlopen(req, timeout=timeout, context=ssl_context())


__all__ = ["SSL_HINT", "is_cert_error", "ssl_context", "urlopen"]
