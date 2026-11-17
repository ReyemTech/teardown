"""Offline regressions for scan scope, bounded work, and redacted output."""

from __future__ import annotations

import json

import pytest
import httpx

from teardown.cli import _normalize, build_parser, teardown_host
from teardown.analyze import analyze_host
from teardown.collectors.api_discovery import discover_api
from teardown.collectors.headers import parse_csp, parse_headers
from teardown.collectors.html_js import extract_bundles, fingerprint_third_parties
from teardown.collectors.html_js import enrich_bundles
from teardown.enumerate import filter_live
from teardown.http_client import FetchResponse, HttpClient
from teardown.models import Bundle, CspInfo, HostTeardown, OpsecFinding, ScanResult, Severity, to_dict
from teardown.render import render_markdown
from teardown.safety import safe_url


def test_public_suffix_root():
    assert _normalize("https://app.example.co.uk")[2] == "example.co.uk"


def test_private_suffix_root_stays_in_tenant_scope():
    assert _normalize("https://app.foo.github.io")[2] == "foo.github.io"


@pytest.mark.parametrize("flag,value", [
    ("--concurrency", "0"), ("--rate", "0"),
    ("--max-hosts", "-1"), ("--max-probes", "-1"),
])
def test_cli_rejects_invalid_limits(flag, value):
    with pytest.raises(SystemExit) as error:
        build_parser().parse_args(["example.com", flag, value])
    assert error.value.code == 2


def test_foreign_co_uk_source_map_is_not_first_party():
    host = HostTeardown(target="https://app.example.co.uk", host="app.example.co.uk",
                        bundles=[Bundle(url="https://cdn.other.co.uk/app.js", has_sourcemap=True)])
    assert not any("Source map" in f.title for f in analyze_host(host))


def test_sensitive_third_party_key_is_redacted():
    key = "pk_live_ABCDEFGHIJKLMNOP123456789"
    parties = fingerprint_third_parties(f'<script>Stripe("{key}")</script>')
    assert key not in json.dumps(to_dict(parties))
    assert parties[0].key.startswith("pk_live_")


def test_url_redaction_covers_userinfo_and_signed_queries():
    url = "https://user:verysecret@example.com/app.js?key=verysecret&signature=verysecret"
    redacted = safe_url(url)
    assert "verysecret" not in redacted
    assert "user" not in redacted
    assert "example.com/app.js" in redacted


def test_sensitive_headers_are_redacted():
    resp = FetchResponse(
        url="https://example.com", final_url="https://example.com", status=200,
        headers={"set-cookie": "session=verysecret", "x-api-key": "verysecret", "server": "nginx"},
    )
    info = parse_headers(resp)
    assert "verysecret" not in json.dumps(to_dict(info))
    assert info.all_headers["server"] == "nginx"


def test_csp_url_query_is_redacted_in_collected_model():
    csp = parse_csp({"content-security-policy":
                     "connect-src https://api.example.com/?token=verysecret"})
    assert "verysecret" not in json.dumps(to_dict(csp))
    assert "verysecret" not in repr(csp)


def test_bundle_url_query_is_redacted_in_collected_model():
    bundles = extract_bundles('<script src="/app.js?token=verysecret"></script>',
                              "https://example.com")
    assert "verysecret" not in repr(bundles)


def test_render_does_not_emit_sensitive_url_query():
    host = HostTeardown(
        target="https://example.com/?token=verysecret", host="example.com",
        csp=CspInfo(present=True, directives={"connect-src": [
            "https://api.example.com/?api_key=verysecret"]}),
        opsec_findings=[OpsecFinding(severity=Severity.INFO, title="Signal",
                                     detail="Found at https://example.com/?token=verysecret")],
    )
    result = ScanResult(root_domain="example.com", hosts=[host])
    assert "verysecret" not in render_markdown(result)
    assert "verysecret" not in json.dumps(to_dict(result))


class FakeFetcher:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    async def get(self, url, **kwargs):
        self.calls.append(url)
        return self.responses.get(url, FetchResponse(url=url, final_url=url, status=None))

    async def request(self, method, url, **kwargs):
        return await self.get(url)


@pytest.mark.asyncio
async def test_liveness_probe_cap_bounds_requests():
    hosts = [f"h{i}.example.com" for i in range(10)]
    fetcher = FakeFetcher({})
    await filter_live(hosts, fetcher, max_probes=3)
    assert len(fetcher.calls) == 6


@pytest.mark.asyncio
async def test_liveness_cap_checks_apex_first():
    fetcher = FakeFetcher({"https://example.com": FetchResponse(
        url="https://example.com", final_url="https://example.com", status=200)})
    live = await filter_live(["api.example.com", "example.com"], fetcher,
                             max_probes=1, preferred_host="example.com")
    assert live == ["https://example.com"]


@pytest.mark.asyncio
async def test_api_html_fallback_is_not_rest_or_graphql():
    base = "https://example.com"
    responses = {f"{base}{path}": FetchResponse(
        url=f"{base}{path}", final_url=f"{base}{path}", status=200,
        headers={"content-type": "text/html"}, text="<html>SPA shell</html>",
    ) for path in ("/api/", "/api/v1/", "/api/v2/", "/graphql", "/api/graphql")}
    surface = await discover_api(base, FakeFetcher(responses))
    assert surface.rest == []
    assert surface.graphql.present is False


@pytest.mark.asyncio
async def test_arbitrary_json_is_not_openapi():
    url = "https://example.com/openapi.json"
    response = FetchResponse(url=url, final_url=url, status=200, text='{"hello":"world"}')
    surface = await discover_api("https://example.com", FakeFetcher({url: response}))
    assert surface.openapi.present is False


@pytest.mark.asyncio
async def test_foreign_api_redirect_is_ignored():
    url = "https://example.com/openapi.json"
    response = FetchResponse(url=url, final_url="https://elsewhere.test/spec", status=200,
                             text='{"openapi":"3.0.0","paths":{}}')
    surface = await discover_api("https://example.com", FakeFetcher({url: response}))
    assert surface.openapi.present is False


@pytest.mark.asyncio
async def test_generic_json_is_not_wordpress_root():
    url = "https://example.com/wp-json/"
    response = FetchResponse(url=url, final_url=url, status=200, text='{"name":"Site"}')
    surface = await discover_api("https://example.com", FakeFetcher({url: response}))
    assert surface.wordpress.wp_json is False


@pytest.mark.asyncio
async def test_http_client_does_not_follow_foreign_redirect():
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(302, headers={"location": "https://elsewhere.test/secret"})

    async with HttpClient(root_domain="example.com", retries=0,
                          transport=httpx.MockTransport(handler)) as client:
        response = await client.get("https://example.com/")
    assert seen == ["https://example.com/"]
    assert response.status is None


@pytest.mark.asyncio
async def test_http_client_follows_in_scope_redirect():
    seen = []

    def handler(request):
        seen.append(str(request.url))
        if request.url.host == "example.com":
            return httpx.Response(302, headers={"location": "https://www.example.com/"})
        return httpx.Response(200, text="ok")

    async with HttpClient(root_domain="example.com", retries=0,
                          transport=httpx.MockTransport(handler)) as client:
        response = await client.get("https://example.com/")
    assert seen == ["https://example.com/", "https://www.example.com/"]
    assert response.status == 200
    assert response.final_url == "https://www.example.com/"


@pytest.mark.asyncio
async def test_http_client_refuses_out_of_scope_asset():
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(200, text="asset")

    async with HttpClient(root_domain="example.com", retries=0,
                          transport=httpx.MockTransport(handler)) as client:
        response = await client.get("https://cdn.elsewhere.test/app.js")
    assert response.status is None
    assert seen == []


@pytest.mark.asyncio
async def test_http_client_limits_response_body():
    def handler(request):
        return httpx.Response(200, text="abcdefghijklmnop")

    async with HttpClient(root_domain="example.com", retries=0,
                          max_response_bytes=8,
                          transport=httpx.MockTransport(handler)) as client:
        response = await client.get("https://example.com/")
    assert response.status == 200
    assert len(response.text.encode()) <= 8
    assert response.error == "response body truncated at 8 bytes"


@pytest.mark.asyncio
async def test_html_fallback_is_not_a_source_map():
    url = "https://example.com/app.js"
    responses = {
        url + ".map": FetchResponse(url=url + ".map", final_url=url + ".map",
                                    status=200, text="<html>SPA shell</html>"),
        url: FetchResponse(url=url, final_url=url, status=200, text="schema"),
    }
    bundles = await enrich_bundles([Bundle(url=url)], FakeFetcher(responses))
    assert bundles[0].has_sourcemap is False


@pytest.mark.asyncio
async def test_source_map_probe_preserves_bundle_query_position():
    url = "https://example.com/app.js?v=1"
    map_url = "https://example.com/app.js.map?v=1"
    responses = {
        map_url: FetchResponse(url=map_url, final_url=map_url, status=200,
                               text='{"version":3,"sources":["app.ts"],"mappings":"AAAA"}'),
        url: FetchResponse(url=url, final_url=url, status=200, text="schema"),
    }
    bundles = await enrich_bundles([Bundle(url=url)], FakeFetcher(responses))
    assert bundles[0].has_sourcemap is True
    host = HostTeardown(target="https://example.com", host="example.com", bundles=bundles)
    finding = next(f for f in analyze_host(host) if "Source map" in f.title)
    assert finding.evidence_url == map_url


@pytest.mark.asyncio
async def test_collection_error_does_not_store_exception_text(monkeypatch):
    def failing_parser(_html):
        raise ValueError("verysecret")

    monkeypatch.setattr("teardown.cli.detect_frameworks", failing_parser)
    url = "https://example.com"
    fetcher = FakeFetcher({url: FetchResponse(url=url, final_url=url, status=200)})
    host = await teardown_host(url, fetcher)
    assert "verysecret" not in repr(host)
    assert host.errors == ["collection error: ValueError"]


@pytest.mark.asyncio
async def test_truncated_homepage_is_reported_in_host_errors():
    url = "https://example.com"
    response = FetchResponse(url=url, final_url=url, status=200, text="<html></html>",
                             error="response body truncated at 8 bytes")
    host = await teardown_host(url, FakeFetcher({url: response}))
    assert "response body truncated at 8 bytes" in host.errors
