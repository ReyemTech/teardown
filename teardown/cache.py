"""Bounded daily response cache; never writes known secret-bearing bodies."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from pathlib import Path

from .http_client import FetchResponse
from .safety import safe_headers, safe_text, safe_url

_SENSITIVE_CONTEXT = re.compile(
    r"password|secret|token|credential|session|authorization|auth|"
    r"private[-_ ]?key|api[-_ ]?key|access[-_ ]?key",
    re.I,
)
_OPAQUE_VALUE = re.compile(r"(?:=|:)\s*[\"']([A-Za-z0-9_-]{16,})[\"']")


class ResponseCache:
    def __init__(self, directory: str | Path, day: str | None = None) -> None:
        self.directory = Path(directory)
        self.day = day or dt.datetime.now(dt.timezone.utc).date().isoformat()

    def _path(self, url: str) -> Path:
        key = hashlib.sha256(f"GET\n{url}\n{self.day}".encode()).hexdigest()
        return self.directory / self.day / f"{key}.json"

    def get(self, url: str) -> FetchResponse | None:
        try:
            data = json.loads(self._path(url).read_text(encoding="utf-8"))
            return FetchResponse(**data)
        except (OSError, ValueError, TypeError):
            return None

    def put(self, url: str, response: FetchResponse) -> None:
        if response.status is None or response.status >= 400 or response.error:
            return
        body = response.text or ""
        # Free-form bodies can contain credentials in attributes, JSON, or text.
        # If a body even names a sensitive concept, do not persist it.
        if _SENSITIVE_CONTEXT.search(body) or _OPAQUE_VALUE.search(body):
            return
        from .collectors.html_js import detect_secret_leaks
        if detect_secret_leaks(body, response.final_url):
            return
        path = self._path(url)
        path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "url": safe_url(response.url), "final_url": safe_url(response.final_url),
            "status": response.status, "headers": safe_headers(response.headers),
            "text": safe_text(body), "error": None,
            "status_chain": response.status_chain, "tls": response.tls,
        }
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(record), encoding="utf-8")
        tmp.chmod(0o600)
        tmp.replace(path)
