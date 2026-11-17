"""Tests for the headers + CSP collector (pure, no network)."""

from __future__ import annotations

from teardown.collectors.headers import parse_csp, parse_headers
from teardown.http_client import FetchResponse


def _resp(headers: dict[str, str], *, status: int = 200, url: str = "https://example.com/") -> FetchResponse:
    return FetchResponse(
        url=url,
        final_url=url,
        status=status,
        headers={k.lower(): v for k, v in headers.items()},
        text="",
    )


def test_parse_headers_basic_fields():
    resp = _resp(
        {
            "Server": "nginx",
            "X-Powered-By": "PHP/8.2.1",
        },
        status=200,
        url="https://foo.test/",
    )
    info = parse_headers(resp)
    assert info.server == "nginx"
    assert info.powered_by == "PHP/8.2.1"
    assert info.status == 200
    assert info.final_url == "https://foo.test/"
    assert info.all_headers["server"] == "nginx"


def test_parse_headers_security_posture():
    resp = _resp(
        {
            "Strict-Transport-Security": "max-age=63072000",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
    )
    sec = parse_headers(resp).security_headers
    assert sec["hsts"] is True
    assert sec["x_frame_options"] == "DENY"
    assert sec["x_content_type_options"] == "nosniff"
    assert sec["referrer_policy"] == "no-referrer"
    assert sec["permissions_policy"] == "geolocation=()"


def test_parse_headers_missing_security_absent():
    info = parse_headers(_resp({"Server": "nginx"}))
    assert "hsts" not in info.security_headers
    assert "x_frame_options" not in info.security_headers


def test_parse_headers_cache_signals():
    resp = _resp(
        {
            "CF-Cache-Status": "HIT",
            "X-Vercel-Cache": "MISS",
            "X-LiteSpeed-Cache": "hit",
            "Age": "42",
        }
    )
    cache = parse_headers(resp).cache
    assert cache["cf_cache_status"] == "HIT"
    assert cache["x_vercel_cache"] == "MISS"
    assert cache["x_litespeed_cache"] == "hit"
    assert cache["age"] == "42"


def test_parse_csp_absent():
    info = parse_csp({"server": "nginx"})
    assert info.present is False
    assert info.directives == {}
    assert info.third_party_domains == []


def test_parse_csp_directives_and_third_parties():
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://js.stripe.com https://cdn.segment.com; "
        "connect-src 'self' https://api.segment.io wss://ws.pusher.com data: blob:; "
        "img-src 'self' data: https://*.cloudfront.net; "
        "frame-src https://js.stripe.com:443/v3/; "
        "font-src 'self'"
    )
    info = parse_csp({"content-security-policy": csp})
    assert info.present is True
    # directives parsed into source lists
    assert info.directives["script-src"] == [
        "'self'",
        "'unsafe-inline'",
        "https://js.stripe.com",
        "https://cdn.segment.com",
    ]
    tp = info.third_party_domains
    # external hosts, scheme + port + path stripped, wildcards kept
    assert "js.stripe.com" in tp
    assert "cdn.segment.com" in tp
    assert "api.segment.io" in tp
    assert "ws.pusher.com" in tp
    assert "*.cloudfront.net" in tp
    # keyword / scheme-only sources excluded
    assert "'self'" not in tp
    assert "'unsafe-inline'" not in tp
    assert "data:" not in tp
    assert "blob:" not in tp
    # deduped
    assert len(tp) == len(set(tp))
    # js.stripe.com only once despite appearing in two directives
    assert tp.count("js.stripe.com") == 1


def test_parse_csp_report_only_fallback():
    info = parse_csp(
        {"content-security-policy-report-only": "connect-src https://o123.ingest.sentry.io"}
    )
    assert info.present is True
    assert "o123.ingest.sentry.io" in info.third_party_domains
