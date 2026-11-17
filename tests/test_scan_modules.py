"""Offline contract tests for named, composable host scan modules."""

from __future__ import annotations

import pytest

from teardown.cli import run_scan, teardown_host
from teardown.http_client import FetchResponse
from teardown.models import to_dict
from teardown.scan_modules import ScanModule, default_modules, register_module, safe_extension


class FakeFetcher:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def get(self, url: str, **kwargs) -> FetchResponse:
        self.calls.append(url)
        return FetchResponse(url=url, final_url=url, status=None)

    async def request(self, method: str, url: str, **kwargs) -> FetchResponse:
        return await self.get(url)


def _response(url: str, html: str = "") -> FetchResponse:
    return FetchResponse(url=url, final_url=url, status=200, text=html)


def test_builtin_module_order_is_explicit():
    assert [module.name for module in default_modules()] == [
        "http", "fingerprints", "bundles", "third_parties", "secrets", "api"]


def test_extension_redacts_secret_values_even_under_public_keys():
    payload = {"public_marker": "sk_live_abcdefghijklmnop",
               "nested": ["token=abcdefghijklmnop", "https://x.test/?api_key=hidden"]}
    output = safe_extension(payload)
    assert "sk_live_abcdefghijklmnop" not in str(output)
    assert "abcdefghijklmnop" not in str(output)
    assert "hidden" not in str(output)


@pytest.mark.asyncio
async def test_extra_module_adds_namespaced_redacted_payload():
    async def extra(context):
        assert context.html == "<title>Example</title>"
        return {"signal": True, "source_url": "https://example.com/?token=private",
                "api_key": "private"}

    url = "https://example.com"
    fetcher = FakeFetcher()
    modules = [*default_modules(), ScanModule("extra", extra)]
    host = await teardown_host(url, fetcher, _response(url, "<title>Example</title>"),
                               modules=modules)
    output = to_dict(host)
    assert output["extensions"]["extra"]["signal"] is True
    assert "private" not in str(output["extensions"])
    assert url not in fetcher.calls


@pytest.mark.asyncio
async def test_module_failure_does_not_stop_following_module():
    async def broken(_context):
        raise ValueError("secret detail")

    async def working(_context):
        return {"observed": True}

    url = "https://example.com"
    host = await teardown_host(url, FakeFetcher(), _response(url), modules=[
        ScanModule("broken", broken), ScanModule("working", working)])
    assert host.extensions["working"] == {"observed": True}
    assert host.errors == ["module broken error: ValueError"]
    assert "secret detail" not in str(to_dict(host))


def test_registration_rejects_duplicate_names(monkeypatch):
    import teardown.scan_modules as module_api
    monkeypatch.setattr(module_api, "_EXTRA_MODULES", [])

    async def extra(_context):
        return None

    register_module(ScanModule("extra", extra))
    assert [module.name for module in default_modules()][-1] == "extra"
    with pytest.raises(ValueError):
        register_module(ScanModule("extra", extra))


@pytest.mark.asyncio
async def test_run_scan_accepts_module_list(monkeypatch):
    async def extra(_context):
        return {"observed": "yes"}

    class LiveFetcher(FakeFetcher):
        async def get(self, url: str, **kwargs) -> FetchResponse:
            if url == "https://example.com":
                return _response(url)
            return await super().get(url, **kwargs)

    class Client:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return LiveFetcher()

        async def __aexit__(self, *args):
            pass

    monkeypatch.setattr("teardown.cli.HttpClient", Client)
    result = await run_scan("example.com", single=True, active_dns=False,
                            wordlist=None, max_hosts=1, max_probes=1,
                            concurrency=1, rate_per_sec=1,
                            modules=[ScanModule("extra", extra)])
    assert result.hosts[0].extensions == {"extra": {"observed": "yes"}}
