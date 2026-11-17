"""Safeguards for public scan data and request scope."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import tldextract

_SENSITIVE = re.compile(
    r"(?:cookie|authorization|auth|api[-_]?key|(?:^|[-_])key(?:$|[-_])|"
    r"token|secret|password|credential|session|signature|(?:^|[-_])sig(?:$|[-_]))",
    re.I,
)
_URL_IN_TEXT = re.compile(r"(?:https?|wss?)://[^\s<>\"'`)]+")
_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
)


def registrable_domain(host: str) -> str:
    parts = _EXTRACT(host)
    return f"{parts.domain}.{parts.suffix}" if parts.suffix else host


def redact_key(value: str | None) -> str | None:
    if not value:
        return value
    return value[:8] + "…"


def safe_url(url: str | None) -> str | None:
    """Remove URL credentials and sensitive query values before output."""
    if not url:
        return url
    try:
        parts = urlsplit(url)
        netloc = parts.hostname or ""
        if parts.port:
            netloc += f":{parts.port}"
        query = urlencode([
            (key, "[REDACTED]" if _SENSITIVE.search(key) else value)
            for key, value in parse_qsl(parts.query, keep_blank_values=True)
        ])
        return urlunsplit((parts.scheme, netloc, parts.path, query, ""))
    except ValueError:
        return "[INVALID URL]"


def safe_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        key: "[REDACTED]" if _SENSITIVE.search(key) else (
            safe_url(value) if key.lower() == "location" else safe_text(value)
        )
        for key, value in headers.items()
    }


def safe_text(value: str) -> str:
    """Mask sensitive URL query values embedded in free-text findings or CSP."""
    return _URL_IN_TEXT.sub(lambda match: safe_url(match.group()) or "", value)


def in_scope(url: str, root_domain: str) -> bool:
    host = urlsplit(url).hostname
    return bool(host and (host == root_domain or host.endswith("." + root_domain)))


def source_map_url(bundle_url: str) -> str:
    parts = urlsplit(bundle_url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path + ".map", parts.query, ""))
