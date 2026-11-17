"""Tests for teardown.enumerate — no real network, no real DNS."""

from __future__ import annotations

import json

import pytest

import teardown.enumerate as enum_mod
from teardown.enumerate import DEFAULT_WORDLIST, enumerate_subdomains, filter_live
from teardown.http_client import FetchResponse

DOMAIN = "example.com"
CRT_URL = f"https://crt.sh/?q=%25.{DOMAIN}&output=json"


class FakeFetcher:
    """Canned-response Fetcher keyed by URL."""

    def __init__(self, responses: dict[str, FetchResponse]) -> None:
        self._responses = responses
        self.calls: list[str] = []

    def _lookup(self, url: str) -> FetchResponse:
        self.calls.append(url)
        if url in self._responses:
            return self._responses[url]
        return FetchResponse(url=url, final_url=url, status=None, error="unreachable")

    async def get(self, url: str, **kwargs) -> FetchResponse:
        return self._lookup(url)

    async def request(self, method: str, url: str, **kwargs) -> FetchResponse:
        return self._lookup(url)


def crt_payload(*name_values: str) -> str:
    return json.dumps([{"name_value": nv} for nv in name_values])


def resp(url: str, body: str, status: int = 200) -> FetchResponse:
    return FetchResponse(url=url, final_url=url, status=status, text=body)


# --- crt.sh passive enumeration --------------------------------------------

@pytest.mark.asyncio
async def test_crtsh_parse_wildcard_strip_and_dedupe():
    body = crt_payload(
        "*.example.com",
        "www.example.com\napi.example.com",  # multi-line name_value
        "WWW.example.com",                    # case-insensitive dedupe
        "example.com",                        # apex
    )
    subs, info = await enumerate_subdomains(
        DOMAIN, FakeFetcher({CRT_URL: resp(CRT_URL, body)})
    )
    assert subs == ["api.example.com", "example.com", "www.example.com"]
    assert info.sources == ["crt.sh"]
    assert info.subdomains_found == 3
    assert info.live_hosts == 0


@pytest.mark.asyncio
async def test_crtsh_domain_filtering_excludes_foreign_names():
    body = crt_payload(
        "good.example.com",
        "evil.com",
        "example.com.attacker.net",   # ends in attacker.net, not example.com
        "notexample.com",             # must not match via bare endswith
    )
    subs, info = await enumerate_subdomains(
        DOMAIN, FakeFetcher({CRT_URL: resp(CRT_URL, body)})
    )
    assert subs == ["example.com", "good.example.com"]
    assert "evil.com" not in subs
    assert "notexample.com" not in subs
    assert "example.com.attacker.net" not in subs


@pytest.mark.asyncio
async def test_apex_included_even_when_crtsh_empty():
    subs, info = await enumerate_subdomains(
        DOMAIN, FakeFetcher({CRT_URL: resp(CRT_URL, "[]")})
    )
    assert subs == ["example.com"]
    assert info.subdomains_found == 1


@pytest.mark.asyncio
async def test_crtsh_unreachable_still_returns_apex(monkeypatch):
    # No canned response -> status None -> tolerated (retries, no real backoff).
    monkeypatch.setattr(enum_mod, "CRTSH_RETRY_BACKOFF", 0.0)
    subs, info = await enumerate_subdomains(DOMAIN, FakeFetcher({}))
    assert subs == ["example.com"]
    assert info.sources == ["crt.sh"]


@pytest.mark.asyncio
async def test_crtsh_non_json_tolerated(monkeypatch):
    monkeypatch.setattr(enum_mod, "CRTSH_RETRY_BACKOFF", 0.0)
    subs, info = await enumerate_subdomains(
        DOMAIN, FakeFetcher({CRT_URL: resp(CRT_URL, "<html>rate limited</html>")})
    )
    assert subs == ["example.com"]


# --- active DNS brute force (monkeypatched resolver) -----------------------

@pytest.mark.asyncio
async def test_active_dns_adds_resolving_hosts(monkeypatch):
    import dns.resolver

    live = {f"www.{DOMAIN}", f"api.{DOMAIN}"}

    class FakeResolver:
        def resolve(self, host, rdtype):
            if host in live and rdtype == "A":
                return ["1.2.3.4"]  # truthy answer
            raise dns.resolver.NXDOMAIN(f"no {host}")

    monkeypatch.setattr(dns.resolver, "Resolver", FakeResolver)

    subs, info = await enumerate_subdomains(
        DOMAIN,
        FakeFetcher({CRT_URL: resp(CRT_URL, "[]")}),
        active_dns=True,
    )
    assert "www.example.com" in subs
    assert "api.example.com" in subs
    assert "example.com" in subs
    # A word that doesn't resolve must not appear.
    assert "jenkins.example.com" not in subs
    assert info.sources == ["crt.sh", "dns-brute"]


@pytest.mark.asyncio
async def test_active_dns_respects_custom_wordlist(monkeypatch):
    import dns.resolver

    class FakeResolver:
        def resolve(self, host, rdtype):
            if host == f"portal.{DOMAIN}":
                return ["9.9.9.9"]
            raise dns.resolver.NXDOMAIN(host)

    monkeypatch.setattr(dns.resolver, "Resolver", FakeResolver)

    subs, _ = await enumerate_subdomains(
        DOMAIN,
        FakeFetcher({CRT_URL: resp(CRT_URL, "[]")}),
        active_dns=True,
        wordlist=["portal", "nope"],
    )
    assert "portal.example.com" in subs
    assert "nope.example.com" not in subs
    # www is in the default list but not the custom one -> absent.
    assert "www.example.com" not in subs


def test_default_wordlist_has_expected_words():
    for w in ("www", "api", "admin", "staging"):
        assert w in DEFAULT_WORDLIST


# --- filter_live -----------------------------------------------------------

@pytest.mark.asyncio
async def test_filter_live_prefers_https():
    host = "www.example.com"
    responses = {
        f"https://{host}": resp(f"https://{host}", "", 200),
        f"http://{host}": resp(f"http://{host}", "", 200),
    }
    fetcher = FakeFetcher(responses)
    live = await filter_live([host], fetcher)
    assert live == [f"https://{host}"]
    # http should not even be probed when https succeeds.
    assert f"http://{host}" not in fetcher.calls


@pytest.mark.asyncio
async def test_filter_live_falls_back_to_http():
    host = "legacy.example.com"
    responses = {
        # https unreachable (status None), http works.
        f"http://{host}": resp(f"http://{host}", "", 200),
    }
    live = await filter_live([host], FakeFetcher(responses))
    assert live == [f"http://{host}"]


@pytest.mark.asyncio
async def test_filter_live_excludes_dead_hosts():
    hosts = ["dead.example.com", "up.example.com"]
    responses = {
        "https://up.example.com": resp("https://up.example.com", "", 301),
    }
    live = await filter_live(hosts, FakeFetcher(responses))
    assert live == ["https://up.example.com"]


@pytest.mark.asyncio
async def test_filter_live_preserves_order():
    hosts = ["a.example.com", "b.example.com", "c.example.com"]
    responses = {
        "https://a.example.com": resp("https://a.example.com", "", 200),
        "https://c.example.com": resp("https://c.example.com", "", 200),
    }  # b is dead
    live = await filter_live(hosts, FakeFetcher(responses))
    assert live == ["https://a.example.com", "https://c.example.com"]
