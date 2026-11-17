"""Offline coverage for data, passive sources, liveness, cache and diff."""

from __future__ import annotations

import json

import pytest
import httpx

from teardown.cache import ResponseCache
from teardown.diff import diff_results
from teardown.enumerate import enumerate_subdomains, probe_live
from teardown.fingerprints import (
    _convert_wapp, detect_technologies, framework_names, load_fingerprints,
    update_external_database,
)
from teardown.http_client import FetchResponse, HttpClient
from teardown.collectors.headers import parse_headers
from teardown.safety import safe_headers
from teardown.models import HostTeardown, Detection, ScanResult, EnumerationInfo
from teardown.analyze import analyze_host
from teardown.render import render_host_markdown


def response(url: str, text: str = "", status: int | None = 200,
             headers: dict[str, str] | None = None) -> FetchResponse:
    return FetchResponse(url=url, final_url=url, status=status, text=text, headers=headers or {})


class FakeFetcher:
    def __init__(self, responses: dict[str, FetchResponse]) -> None:
        self.responses = responses
        self.calls: list[str] = []

    async def get(self, url: str, **kwargs) -> FetchResponse:
        self.calls.append(url)
        return self.responses.get(url, response(url, status=None))

    async def request(self, method: str, url: str, **kwargs) -> FetchResponse:
        return await self.get(url)


def test_builtin_database_detects_laravel_livewire_with_safe_evidence():
    html = '<div wire:id="abc"></div><script src="/livewire/livewire.js"></script>'
    detections = detect_technologies(html, {"set-cookie": "laravel_session=privatevalue; Path=/"},
                                     "https://example.com")
    names = {d.name: d for d in detections}
    assert len(load_fingerprints()) >= 589
    assert names["Laravel"].confidence > 0
    assert names["Livewire"].confidence > 0
    assert "laravel" in framework_names(detections)
    assert "privatevalue" not in json.dumps([d.__dict__ for d in detections])


def test_database_matches_header_meta_and_script():
    definitions = [{"name": "ExampleTech", "categories": ["js-framework"],
                    "headers": {"x-example": "yes"}, "meta": {"generator": "Example"},
                    "scriptSrc": ["example\\.js"]}]
    html = '<meta name="generator" content="Example"><script src="/example.js"></script>'
    found = detect_technologies(html, {"X-Example": "yes"}, "https://example.com", definitions)
    assert len(found) == 1
    assert found[0].confidence > 80
    assert set(found[0].evidence) >= {"header:x-example", "meta:generator"}


def test_imported_fingerprint_updates_builtin_name(monkeypatch, tmp_path):
    path = tmp_path / "updated.json"
    path.write_text(json.dumps([{"name": "React", "categories": ["js-framework"],
                                 "html": ["custom-react-marker"]}]))
    monkeypatch.setenv("TEARDOWN_FINGERPRINT_DB", str(path))
    react = next(item for item in load_fingerprints() if item["name"] == "React")
    assert react["html"] == ["custom-react-marker"]


def test_imported_alternate_header_patterns_are_retained():
    definition = _convert_wapp("Example", {"cats": [12],
                                            "headers": {"x-example": ["first", "second"]}})
    found = detect_technologies("", {"x-example": "second"}, "https://example.com", [definition])
    assert found[0].evidence == ["header:x-example"]


def test_legacy_framework_view_includes_build_tools():
    from teardown.collectors.html_js import detect_frameworks
    assert "vite" in detect_frameworks('<script src="/@vite/client"></script>')


@pytest.mark.parametrize("asset", [
    '<script src="/_astro/page.B1D-nYk3.js"></script>',
    '<link rel="stylesheet" href="/_astro/index.DpanXZtb.css">',
])
def test_astro_detected_from_built_asset_paths(asset):
    detections = detect_technologies(asset, {}, "https://stint.reyem.tech")
    astro = next(item for item in detections if item.name == "Astro")
    assert astro.confidence >= 80
    assert "astro" in framework_names(detections)


def test_stint_style_headers_identify_fastly_without_cloudflare():
    headers = {"server": "GitHub.com", "x-fastly-request-id": "request-id",
               "x-served-by": "cache-yto123", "via": "1.1 varnish"}
    info = parse_headers(response("https://stint.reyem.tech", headers=headers))
    detections = detect_technologies("", headers, "https://stint.reyem.tech")
    assert info.cdn == "fastly"
    assert "Fastly" in {item.name for item in detections}
    assert "Cloudflare" not in {item.name for item in detections}


def test_external_import_is_unassisted_and_local(monkeypatch, tmp_path):
    payload = json.dumps({"ExampleTech": {"cats": [12], "html": "example\\;confidence:50"}})

    class Reply:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, _limit=-1):
            return self.body

    def fetch(request, **_kwargs):
        reply = Reply()
        reply.body = (json.dumps([{"name": "a.json"}]) if "api.github.com" in request.full_url
                      else payload).encode()
        return reply

    monkeypatch.setattr("urllib.request.urlopen", fetch)
    dest = tmp_path / "external.json"
    assert update_external_database(dest) == 1
    assert json.loads(dest.read_text())[0]["categories"] == ["js-framework"]


@pytest.mark.asyncio
async def test_passive_sources_are_scoped_and_merged():
    domain = "example.com"
    cert = (f"https://api.certspotter.com/v1/issuances?domain={domain}"
            "&include_subdomains=true&expand=dns_names")
    wayback = (f"https://web.archive.org/cdx/search/cdx?url={domain}"
               "&matchType=domain&output=json&fl=original&collapse=urlkey&limit=5000")
    crt = f"https://crt.sh/?q=%25.{domain}&output=json"
    fetcher = FakeFetcher({
        crt: response(crt, "[]"),
        cert: response(cert, json.dumps([{"dns_names": ["api.example.com", "evil.com"]}])),
        wayback: response(wayback, json.dumps([["original"], ["https://app.example.com/a"],
                                               ["https://example.com.attacker.net/"]])),
    })
    hosts, info = await enumerate_subdomains(domain, fetcher)
    assert hosts == ["api.example.com", "app.example.com", "example.com"]
    assert info.sources == ["crt.sh", "certspotter", "wayback"]


@pytest.mark.asyncio
async def test_probe_live_preserves_initial_response():
    url = "https://example.com"
    fetcher = FakeFetcher({url: response(url, "<title>Example</title>")})
    found = await probe_live(["example.com"], fetcher)
    assert found[0][0] == url
    assert found[0][1].text == "<title>Example</title>"
    assert fetcher.calls == [url]


def test_cache_hits_same_day_and_skips_secrets(tmp_path):
    cache = ResponseCache(tmp_path, day="2026-11-16")
    url = "https://example.com"
    cache.put(url, response(url, "<title>Safe</title>"))
    assert cache.get(url).text == "<title>Safe</title>"
    assert ResponseCache(tmp_path, day="2026-11-17").get(url) is None
    secret_url = url + "/secret"
    cache.put(secret_url, response(secret_url, "api_key='abcdefghijklmnop'"))
    assert cache.get(secret_url) is None
    assert "abcdefghijklmnop" not in "".join(p.read_text() for p in tmp_path.rglob("*.json"))
    cookie_url = url + "/cookies"
    cache.put(cookie_url, response(cookie_url, headers={"set-cookie": "laravel_session=verysecret"}))
    assert cache.get(cookie_url).headers["set-cookie"] == "laravel_session=[REDACTED]"
    assert "verysecret" not in "".join(p.read_text() for p in tmp_path.rglob("*.json"))
    private_url = url + "/private"
    cache.put(private_url, response(private_url,
                                    '<meta name="private-key" content="verysecretvalue123456">'))
    assert cache.get(private_url) is None
    assert "verysecretvalue123456" not in "".join(p.read_text() for p in tmp_path.rglob("*.json"))
    camel_url = url + "/camel"
    cache.put(camel_url, response(camel_url,
                                  '<script>window.config = { credentialValue: "abcdef1234567890abcdef" };</script>'))
    assert cache.get(camel_url) is None
    assert "abcdef1234567890abcdef" not in "".join(p.read_text() for p in tmp_path.rglob("*.json"))
    asset_url = url + "/assets"
    asset_html = '<script src="/assets/index-17caf134d64fe3c9.js"></script>'
    cache.put(asset_url, response(asset_url, asset_html))
    assert cache.get(asset_url).text == asset_html


def test_cookie_names_survive_redaction_for_fingerprints():
    headers = safe_headers({"set-cookie": "laravel_session=verysecret; Path=/; HttpOnly"})
    assert headers["set-cookie"] == "laravel_session=[REDACTED]"
    assert "verysecret" not in str(headers)
    found = detect_technologies("", headers, "https://example.com")
    assert "Laravel" in {item.name for item in found}


def test_liveness_metadata_title_chain_tls_and_cdn():
    resp = response("https://example.com", "<title> Example  Site </title>",
                    headers={"cf-ray": "abc", "server": "cloudflare"})
    resp.status_chain = [301, 200]
    resp.tls = {"version": "TLSv1.3", "not_after": "Dec 1 00:00:00 2027 GMT"}
    info = parse_headers(resp)
    assert info.title == "Example Site"
    assert info.status_chain == [301, 200]
    assert info.tls["version"] == "TLSv1.3"
    assert info.cdn == "cloudflare"


def test_framework_finding_carries_detection_confidence_and_evidence():
    host = HostTeardown(target="https://example.com", host="example.com", frameworks=["livewire"],
                        detections=[Detection(name="Livewire", categories=["backend-framework"],
                                              confidence=83, evidence=["html:wire:id="])])
    finding = next(item for item in analyze_host(host)
                   if item.title == "Framework / CMS fingerprintable")
    assert finding.confidence == 83
    assert finding.evidence == ["html:wire:id="]
    markdown = render_host_markdown(host)
    assert "| Livewire | 83% | html:wire:id= |" in markdown


@pytest.mark.asyncio
async def test_teardown_reuses_probe_response():
    from teardown.cli import teardown_host
    url = "https://example.com"
    fetcher = FakeFetcher({})
    host = await teardown_host(url, fetcher, response(url, "<title>Reused</title>"))
    assert host.http.title == "Reused"
    assert url not in fetcher.calls


@pytest.mark.asyncio
async def test_http_client_records_redirect_chain():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(301, headers={"location": "/app"})
        return httpx.Response(200, text="<title>App</title>")

    async with HttpClient(root_domain="example.com", transport=httpx.MockTransport(handler),
                          rate_per_sec=1000) as client:
        resp = await client.get("https://example.com/")
    assert resp.status_chain == [301, 200]
    assert resp.final_url == "https://example.com/app"


@pytest.mark.asyncio
async def test_run_scan_reuses_liveness_page_and_serializes_detections(monkeypatch):
    from teardown.cli import run_scan
    from teardown.models import to_dict
    crt = "https://crt.sh/?q=%25.example.com&output=json"
    home = "https://example.com"
    fetcher = FakeFetcher({
        crt: response(crt, "[]"),
        home: response(home, '<div wire:id="abc"></div><title>Example</title>',
                       headers={"set-cookie": "laravel_session=[REDACTED]"}),
    })

    class Client:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return fetcher

        async def __aexit__(self, *args):
            pass

    monkeypatch.setattr("teardown.cli.HttpClient", Client)
    result = await run_scan("example.com", single=False, active_dns=False, wordlist=None,
                            max_hosts=1, max_probes=1, concurrency=2, rate_per_sec=10,
                            cache_dir="")
    assert fetcher.calls.count(home) == 1
    host = to_dict(result)["hosts"][0]
    assert host["http"]["title"] == "Example"
    assert "Livewire" in {item["name"] for item in host["detections"]}
    assert result.schema_version == "1.5"
    assert "Livewire" in result.aggregate.detections_union


def test_diff_ignores_timestamps_and_reports_stable_changes():
    old = {"root_domain": "example.com", "schema_version": "1.1", "hosts": [
        {"host": "example.com", "scanned_at": "old", "frameworks": ["react"],
         "http": {"all_headers": {"date": "Monday"}}},
        {"host": "old.example.com"},
    ]}
    new = {"root_domain": "example.com", "schema_version": "1.1", "hosts": [
        {"host": "example.com", "scanned_at": "new", "frameworks": ["vue"],
         "http": {"all_headers": {"date": "Tuesday"}}},
        {"host": "new.example.com"},
    ]}
    result = diff_results(old, new)
    assert result["added_hosts"] == ["new.example.com"]
    assert result["removed_hosts"] == ["old.example.com"]
    assert [c["path"] for c in result["changed_hosts"][0]["changes"]] == ["frameworks"]


def test_diff_ignores_artifact_paths_but_tracks_hashes():
    old = {"root_domain": "example.com", "hosts": [{"host": "example.com", "bundles": [
        {"url": "https://example.com/app.js", "source_artifact":
         {"local_path": "/one/a.js", "sha256": "abc", "bytes": 3}}]}]}
    new = {"root_domain": "example.com", "hosts": [{"host": "example.com", "bundles": [
        {"url": "https://example.com/app.js", "source_artifact":
         {"local_path": "/two/a.js", "sha256": "abc", "bytes": 3}}]}]}
    assert diff_results(old, new)["changed_hosts"] == []
    new["hosts"][0]["bundles"][0]["source_artifact"]["sha256"] = "def"
    assert diff_results(old, new)["changed_hosts"]


def test_mcp_transport_selection(monkeypatch):
    from teardown import mcp_server
    calls = []
    settings = []

    class Server:
        def run(self, **kwargs):
            calls.append(kwargs)

    def fake_server(**kwargs):
        settings.append(kwargs)
        return Server()

    monkeypatch.setattr(mcp_server, "create_server", fake_server)
    mcp_server.main(["--transport", "http", "--port", "8123"])
    mcp_server.main(["--transport", "stdio"])
    mcp_server.main(["--transport", "stdio", "--no-history", "--data-dir", "/tmp/custom"])
    mcp_server.main(["--transport", "stdio", "--no-artifacts"])
    assert calls == [{"transport": "http", "host": "127.0.0.1", "port": 8123},
                     {"transport": "stdio"}, {"transport": "stdio"},
                     {"transport": "stdio"}]
    assert settings[-2] == {"history_enabled": False, "artifacts_enabled": True,
                            "data_dir": "/tmp/custom"}
    assert settings[-1]["artifacts_enabled"] is False


@pytest.mark.asyncio
async def test_mcp_tools_in_process(monkeypatch):
    fastmcp = pytest.importorskip("fastmcp")
    from teardown.mcp_server import create_server
    calls = []

    async def fake_run_scan(target, **kwargs):
        calls.append((target, kwargs))
        return ScanResult(root_domain="example.com", hosts=[
            HostTeardown(target="https://example.com", host="example.com", reachable=True)])

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    async def fake_enumerate(domain, _client, **kwargs):
        return [domain, f"api.{domain}"], EnumerationInfo(sources=["crt.sh"], subdomains_found=2)

    monkeypatch.setattr("teardown.mcp_server.run_scan", fake_run_scan)
    monkeypatch.setattr("teardown.http_client.HttpClient", FakeClient)
    monkeypatch.setattr("teardown.enumerate.enumerate_subdomains", fake_enumerate)
    async with fastmcp.Client(create_server(history_enabled=False)) as client:
        tools = await client.list_tools()
        assert {tool.name for tool in tools} == {
            "teardown_host", "teardown_domain", "enumerate_subdomains",
            "scan_domain", "diff_scans"}
        old = {"root_domain": "example.com", "hosts": []}
        new = {"root_domain": "example.com", "hosts": [{"host": "api.example.com"}]}
        result = await client.call_tool("diff_scans", {"old": old, "new": new})
        assert result.data["added_hosts"] == ["api.example.com"]
        host = await client.call_tool("teardown_host", {"url": "example.com"})
        assert host.data["host"] == "example.com"
        scan = await client.call_tool("teardown_domain", {"domain": "example.com", "active_dns": True})
        assert scan.data["root_domain"] == "example.com"
        assert calls[-1][1]["active_dns"] is True
        subs = await client.call_tool("enumerate_subdomains", {"domain": "example.com"})
        assert subs.data["hosts"] == ["example.com", "api.example.com"]
