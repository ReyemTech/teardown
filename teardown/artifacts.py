"""Private, bounded, sanitized copies of first-party bundle evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from .models import ArtifactRef
from .safety import safe_text

MAX_ARTIFACT_BYTES = 4_000_000
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)(?:password|passwd|secret|token|credential|authorization|api[_-]?key|"
    r"access[_-]?key|private[_-]?key|db[_-]?url|connectionstring)"
    r"[\w\s.]{0,20}?[\"'`]?\s*[:=]\s*[\"'`]([^\"'`]+)[\"'`]"
)
_OPAQUE_STRING = re.compile(r"([\"'`])([A-Za-z0-9_+/=-]{20,})\1")
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{8,}")
_URI_USERINFO = re.compile(r"([a-z][a-z0-9+.-]*://)[^/\s\"'`@]+@", re.I)
_VLQ_MAPPINGS = re.compile(r"[A-Za-z0-9+/;,]*\Z")


def _sanitize_source(text: str) -> str:
    from .collectors.html_js import redact_secret_values

    text = redact_secret_values(safe_text(text))
    for pattern in (_SENSITIVE_ASSIGNMENT, _OPAQUE_STRING):
        spans = [match.span(1 if pattern is _SENSITIVE_ASSIGNMENT else 2)
                 for match in pattern.finditer(text)]
        for start, end in reversed(spans):
            text = text[:start] + "[REDACTED]" + text[end:]
    text = _URI_USERINFO.sub(r"\1[REDACTED]@", text)
    return _BEARER.sub("Bearer [REDACTED]", text)


def _sanitize_map(value: Any, key: str = "") -> Any:
    if isinstance(value, dict):
        return {name: _sanitize_map(item, name) for name, item in value.items()}
    if isinstance(value, list):
        return [_sanitize_map(item, key) for item in value]
    if isinstance(value, str):
        return value if key == "mappings" else _sanitize_source(value)
    return value


class ArtifactStore:
    def __init__(self, directory: str | Path, max_bytes: int = MAX_ARTIFACT_BYTES) -> None:
        self.directory = Path(directory).expanduser()
        self.max_bytes = max_bytes

    def _write(self, text: str, suffix: str) -> ArtifactRef | None:
        encoded = text.encode("utf-8")
        if len(encoded) > self.max_bytes:
            return None
        from .collectors.html_js import detect_secret_leaks
        if detect_secret_leaks(text, ""):
            return None
        digest = hashlib.sha256(encoded).hexdigest()
        path = self.directory / f"{digest}.{suffix}"
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name != "nt":
            self.directory.chmod(0o700)
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(encoded)
        return ArtifactRef(local_path=str(path.resolve()), sha256=digest,
                           bytes=len(encoded), redacted=True)

    def save_source(self, source: str) -> ArtifactRef | None:
        if len(source.encode("utf-8")) > self.max_bytes:
            return None
        return self._write(_sanitize_source(source), "js")

    def save_map(self, source_map: dict[str, Any]) -> ArtifactRef | None:
        mappings = source_map.get("mappings")
        if not isinstance(mappings, str) or not _VLQ_MAPPINGS.fullmatch(mappings):
            return None
        raw = json.dumps(source_map, ensure_ascii=False)
        if len(raw.encode("utf-8")) > self.max_bytes:
            return None
        sanitized = _sanitize_map(source_map)
        return self._write(json.dumps(sanitized, ensure_ascii=False,
                                      sort_keys=True, separators=(",", ":")), "map")
