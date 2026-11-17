"""HTTP header + CSP collectors (pure, no network).

Ports Step 1 of the teardown agent: server/platform fingerprinting, security
posture, cache strategy, and — the big intel source — Content-Security-Policy
third-party domain extraction.
"""

from __future__ import annotations

from teardown.http_client import FetchResponse
from teardown.models import CspInfo, HttpInfo
from teardown.safety import safe_headers, safe_url
import re
from html import unescape

# CSP directives that name hosts the app talks to (the intel goldmine).
_CSP_HOST_DIRECTIVES = (
    "script-src",
    "connect-src",
    "img-src",
    "frame-src",
    "style-src",
    "font-src",
    "media-src",
)

# CSP source keywords / scheme sources that are NOT third-party hostnames.
_CSP_KEYWORDS = {
    "'self'",
    "'none'",
    "'unsafe-inline'",
    "'unsafe-eval'",
    "'unsafe-hashes'",
    "'strict-dynamic'",
    "'report-sample'",
    "'wasm-unsafe-eval'",
    "'inline-speculation-rules'",
}
_CSP_SCHEME_ONLY = {
    "data:",
    "blob:",
    "filesystem:",
    "mediastream:",
    "https:",
    "http:",
    "ws:",
    "wss:",
    "*",
}


def _lower_headers(headers: dict[str, str]) -> dict[str, str]:
    """Collectors may be handed raw dicts; normalise keys defensively."""
    return {k.lower(): v for k, v in headers.items()}


def parse_headers(resp: FetchResponse) -> HttpInfo:
    """Extract server, powered-by, security posture, and cache signals."""
    headers = safe_headers(_lower_headers(resp.headers or {}))

    security: dict[str, object] = {}
    if "strict-transport-security" in headers:
        security["hsts"] = True
    if "x-frame-options" in headers:
        security["x_frame_options"] = headers["x-frame-options"]
    if "x-content-type-options" in headers:
        security["x_content_type_options"] = headers["x-content-type-options"]
    if "referrer-policy" in headers:
        security["referrer_policy"] = headers["referrer-policy"]
    if "permissions-policy" in headers:
        security["permissions_policy"] = headers["permissions-policy"]

    cache: dict[str, object] = {}
    if "cf-cache-status" in headers:
        cache["cf_cache_status"] = headers["cf-cache-status"]
    if "x-vercel-cache" in headers:
        cache["x_vercel_cache"] = headers["x-vercel-cache"]
    if "x-litespeed-cache" in headers:
        cache["x_litespeed_cache"] = headers["x-litespeed-cache"]
    if "age" in headers:
        cache["age"] = headers["age"]

    title_match = re.search(r"<title\b[^>]*>(.*?)</title\s*>", resp.text or "", re.I | re.S)
    title = unescape(re.sub(r"\s+", " ", title_match.group(1)).strip())[:200] if title_match else None
    cdn = ("cloudflare" if "cf-ray" in headers or "cf-cache-status" in headers else
           "fastly" if "x-served-by" in headers and "fastly" in headers.get("via", "").lower() else
           "cloudfront" if "x-amz-cf-id" in headers else
           "akamai" if "x-akamai-transformed" in headers else None)

    return HttpInfo(
        status=resp.status,
        final_url=safe_url(resp.final_url),
        server=headers.get("server"),
        powered_by=headers.get("x-powered-by"),
        security_headers=security,
        cache=cache,
        all_headers=headers,
        title=title,
        status_chain=resp.status_chain or ([resp.status] if resp.status is not None else []),
        tls=resp.tls,
        cdn=cdn,
    )


def _host_from_source(source: str) -> str | None:
    """Reduce a CSP source expression to a bare host (keeping wildcards)."""
    src = source.strip()
    if not src:
        return None
    low = src.lower()
    if low in _CSP_KEYWORDS or src in _CSP_SCHEME_ONLY:
        return None
    # Hashes / nonces are never hosts.
    if src.startswith(("'sha", "'nonce-")):
        return None
    # Strip any scheme ("https://", "wss://", schemeless "//host").
    if "://" in src:
        src = src.split("://", 1)[1]
    elif src.startswith("//"):
        src = src[2:]
    # A remaining bare scheme like "data:" is not a host.
    if src.endswith(":") and "/" not in src:
        return None
    # Drop path and port.
    src = src.split("/", 1)[0]
    if ":" in src and not src.startswith("["):
        src = src.split(":", 1)[0]
    src = src.strip().rstrip(".").lower()
    if not src or "." not in src:
        return None
    return src


def parse_csp(headers: dict[str, str]) -> CspInfo:
    """Parse CSP (enforced or report-only) into directives + third-party hosts.

    Note: the signature only receives headers, so the "site's own host" cannot
    be known here; self-references are already excluded via the 'self' keyword.
    """
    headers = safe_headers(_lower_headers(headers or {}))
    raw = headers.get("content-security-policy") or headers.get(
        "content-security-policy-report-only"
    )
    if not raw:
        return CspInfo(present=False)

    directives: dict[str, list[str]] = {}
    for chunk in raw.split(";"):
        parts = chunk.split()
        if not parts:
            continue
        name = parts[0].lower()
        directives[name] = parts[1:]

    third_party: list[str] = []
    seen: set[str] = set()
    for directive in _CSP_HOST_DIRECTIVES:
        for source in directives.get(directive, []):
            host = _host_from_source(source)
            if host and host not in seen:
                seen.add(host)
                third_party.append(host)

    return CspInfo(
        present=True,
        directives=directives,
        third_party_domains=third_party,
    )
