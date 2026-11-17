"""Offline network attribution contract and error behavior."""

from __future__ import annotations

import json

import httpx
import pytest

from teardown.diff import diff_results
from teardown.http_client import FetchResponse, HttpClient
from teardown.models import (DnsObservation, HostTeardown, HttpInfo, NetworkAddress,
                             NetworkInfo, GeoIpInfo, ScanResult, to_dict)
from teardown.network import collect_network, resolve_dns
from teardown.render import render_host_markdown, render_markdown


class FakeResolver:
    def __init__(self, records):
        self.records = records

    async def resolve(self, host, record_type, **_kwargs):
        value = self.records.get((host, record_type))
        if isinstance(value, Exception):
            raise value
        return value or []


class FakeFetcher:
    def __init__(self, dns, payloads):
        self.dns = dns
        self.payloads = payloads
        self.urls = []

    async def resolve_dns(self, _host):
        return self.dns

    async def get(self, url, **_kwargs):
        self.urls.append(url)
        payload = self.payloads.get(url)
        if payload is None:
            return FetchResponse(url=url, final_url=url, status=None, error="timeout")
        return FetchResponse(url=url, final_url=url, status=200, text=json.dumps(payload))


@pytest.mark.asyncio
async def test_resolve_dns_cname_and_both_address_families():
    dns = await resolve_dns("www.example.com", FakeResolver({
        ("www.example.com", "CNAME"): ["edge.example.net."],
        ("edge.example.net", "A"): ["1.1.1.1", "1.1.1.2"],
        ("edge.example.net", "AAAA"): ["2606:4700::1111"],
    }))
    assert dns.cname_chain == ["edge.example.net"]
    assert dns.addresses == ["1.1.1.1", "1.1.1.2", "2606:4700::1111"]


@pytest.mark.asyncio
async def test_resolve_dns_loop_and_address_cap():
    dns = await resolve_dns("a.example.com", FakeResolver({
        ("a.example.com", "CNAME"): ["b.example.com."],
        ("b.example.com", "CNAME"): ["a.example.com."],
        ("b.example.com", "A"): [f"1.1.1.{n}" for n in range(1, 12)],
    }))
    assert dns.cname_chain == ["b.example.com"]
    assert dns.truncated
    assert len(dns.addresses) == 8


@pytest.mark.asyncio
async def test_resolve_dns_cap_retains_ipv6_when_ipv4_has_many_answers():
    dns = await resolve_dns("example.com", FakeResolver({
        ("example.com", "A"): [f"1.1.1.{n}" for n in range(1, 12)],
        ("example.com", "AAAA"): ["2606:4700::1111"],
    }))
    assert len(dns.addresses) == 8
    assert "2606:4700::1111" in dns.addresses


@pytest.mark.asyncio
async def test_collect_network_multi_origin_holder_and_edge():
    from teardown.models import DnsObservation
    address = "1.1.1.1"
    base = "https://stat.ripe.net/data/"
    fetcher = FakeFetcher(DnsObservation(addresses=[address]), {
        f"{base}network-info/data.json?resource={address}":
            {"data": {"prefix": "1.1.1.0/24", "asns": [13335, 64500]}},
        f"{base}as-overview/data.json?resource=AS13335":
            {"data": {"holder": "Cloudflare, Inc."}},
        f"{base}as-overview/data.json?resource=AS64500":
            {"data": {"holder": "Other Network"}},
        f"{base}whois/data.json?resource={address}":
            {"data": {"authorities": ["arin"], "records": [[
                {"key": "OrgName", "value": "Cloudflare, Inc."},
                {"key": "NetName", "value": "CLOUDFLARENET"}]]}},
    })
    host = HostTeardown(target="https://example.com", host="example.com",
                        http=HttpInfo(cdn="cloudflare"))
    network = await collect_network(host, fetcher)
    assert network.observation == "cdn_edge"
    assert network.addresses[0].prefix == "1.1.1.0/24"
    assert network.addresses[0].asns == [13335, 64500]
    assert network.addresses[0].asn_holders == {"13335": "Cloudflare, Inc.",
                                               "64500": "Other Network"}
    assert network.addresses[0].registered_holder == "Cloudflare, Inc."
    assert network.addresses[0].network_name == "CLOUDFLARENET"
    assert "network" in to_dict(HostTeardown(target="https://example.com", host="example.com",
                                             network=network))


@pytest.mark.asyncio
async def test_geo_ip_selects_best_valid_location_and_preserves_routing():
    from teardown.models import DnsObservation
    address = "8.8.8.8"
    base = "https://stat.ripe.net/data/"
    fetcher = FakeFetcher(DnsObservation(addresses=[address]), {
        f"{base}network-info/data.json?resource={address}":
            {"data": {"prefix": "8.8.8.0/24", "asns": [15169]}},
        f"{base}maxmind-geo-lite/data.json?resource={address}": {"data": {
            "result_time": "2026-11-13T20:46:43", "located_resources": [{"locations": [
                {"country": "?", "city": "", "latitude": 0, "longitude": 0,
                 "covered_percentage": 80},
                {"country": "US", "city": "Mountain View", "latitude": 37.4,
                 "longitude": -122.1, "covered_percentage": 60},
                {"country": "CA", "city": "Toronto", "latitude": 43.7,
                 "longitude": -79.4, "covered_percentage": 90},
            ]}]}},
    })
    network = await collect_network(HostTeardown(target="https://example.com", host="example.com"),
                                    fetcher)
    entry = network.addresses[0]
    assert entry.prefix == "8.8.8.0/24"
    assert entry.geo.country_code == "CA"
    assert entry.geo.city == "Toronto"
    assert entry.geo.latitude == 43.7
    assert entry.geo.source == "MaxMind GeoLite2 via RIPEstat"
    assert entry.geo.data_updated_at == "2026-11-13T20:46:43"


@pytest.mark.asyncio
async def test_geo_ip_unknown_placeholder_and_failure_do_not_invent_location():
    from teardown.models import DnsObservation
    address = "8.8.8.8"
    url = f"https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource={address}"
    unknown = FakeFetcher(DnsObservation(addresses=[address]), {
        url: {"data": {"located_resources": [{"locations": [
            {"country": "?", "city": "", "latitude": 0, "longitude": 0}
        ]}]}},
    })
    unknown_entry = (await collect_network(HostTeardown(target="https://example.com",
                                                          host="example.com"), unknown)).addresses[0]
    assert unknown_entry.geo is None
    failed = FakeFetcher(DnsObservation(addresses=[address]), {})
    failed_entry = (await collect_network(HostTeardown(target="https://example.com",
                                                         host="example.com"), failed)).addresses[0]
    assert failed_entry.geo is None
    assert "geo-ip unavailable" in failed_entry.errors


@pytest.mark.asyncio
async def test_geo_ip_keeps_country_without_invalid_city_or_coordinates():
    address = "8.8.8.8"
    url = f"https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource={address}"
    fetcher = FakeFetcher(DnsObservation(addresses=[address]), {
        url: {"data": {"located_resources": [{"locations": [
            {"country": "US", "city": "?", "latitude": 999, "longitude": 0}
        ]}]}},
    })
    geo = (await collect_network(HostTeardown(target="https://example.com",
                                               host="example.com"), fetcher)).addresses[0].geo
    assert geo.country_code == "US"
    assert geo.city is None
    assert geo.latitude is None and geo.longitude is None


@pytest.mark.asyncio
async def test_collect_network_skips_private_and_tolerates_missing_sources():
    from teardown.models import DnsObservation
    fetcher = FakeFetcher(DnsObservation(addresses=["10.0.0.1", "8.8.8.8"]), {})
    host = HostTeardown(target="https://example.com", host="example.com")
    network = await collect_network(host, fetcher)
    assert network.observation == "observed_endpoint"
    assert [item.address for item in network.addresses] == ["10.0.0.1", "8.8.8.8"]
    assert network.addresses[0].prefix is None
    assert network.addresses[1].errors == ["network-info unavailable", "whois unavailable",
                                         "geo-ip unavailable"]
    assert not any("10.0.0.1" in url for url in fetcher.urls)


@pytest.mark.asyncio
async def test_collect_network_tolerates_null_asns_and_authorities():
    from teardown.models import DnsObservation
    base = "https://stat.ripe.net/data/"
    fetcher = FakeFetcher(DnsObservation(addresses=["8.8.8.8"]), {
        f"{base}network-info/data.json?resource=8.8.8.8":
            {"data": {"prefix": "8.8.8.0/24", "asns": None}},
        f"{base}whois/data.json?resource=8.8.8.8":
            {"data": {"records": None, "authorities": None}},
    })
    network = await collect_network(HostTeardown(target="https://example.com", host="example.com"),
                                    fetcher)
    assert network.addresses[0].prefix == "8.8.8.0/24"
    assert network.addresses[0].asns == []


@pytest.mark.asyncio
async def test_http_client_rates_each_dns_question():
    resolver = FakeResolver({("example.com", "A"): ["8.8.8.8"]})
    async with HttpClient(root_domain="example.com", dns_resolver=resolver,
                          rate_per_sec=1000) as client:
        calls = []

        async def counted_wait():
            calls.append(1)

        client._rl.wait = counted_wait
        await client.resolve_dns("example.com")
    assert len(calls) == 3


@pytest.mark.asyncio
async def test_ripe_api_is_allowlisted_but_other_external_paths_are_blocked():
    requests = []

    def handler(request):
        requests.append(str(request.url))
        return httpx.Response(200, json={"data": {"prefix": "8.8.8.0/24"}})

    async with HttpClient(root_domain="example.com", transport=httpx.MockTransport(handler),
                          rate_per_sec=1000, retries=0) as client:
        good = await client.get("https://stat.ripe.net/data/network-info/data.json?resource=8.8.8.8")
        geo = await client.get("https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource=8.8.8.8")
        bad = await client.get("https://stat.ripe.net/other?resource=8.8.8.8")
    assert good.status == 200
    assert geo.status == 200
    assert bad.status is None
    assert requests == ["https://stat.ripe.net/data/network-info/data.json?resource=8.8.8.8",
                        "https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource=8.8.8.8"]


def test_network_renders_and_diffs_as_structured_evidence():
    old = ScanResult(root_domain="example.com", hosts=[
        HostTeardown(target="https://example.com", host="example.com")])
    network = NetworkInfo(observation="cdn_edge",
                          dns=DnsObservation(addresses=["1.1.1.1"], cname_chain=["edge.example.net"]),
                          addresses=[NetworkAddress(address="1.1.1.1", prefix="1.1.1.0/24",
                                                    asns=[13335], asn_holders={"13335": "Cloudflare"},
                                                    registered_holder="Cloudflare, Inc.",
                                                    sources=["ripe_ris", "rir_whois"])])
    host = HostTeardown(target="https://example.com", host="example.com", network=network)
    rendered = render_host_markdown(host)
    assert "AS13335" in rendered
    assert "1.1.1.0/24" in rendered
    assert "CDN edge" in rendered
    assert "Cloudflare, Inc." in rendered
    new = ScanResult(root_domain="example.com", hosts=[host])
    paths = [change["path"] for change in diff_results(to_dict(old), to_dict(new))["changed_hosts"][0]["changes"]]
    assert "network.addresses" in paths or any(path.startswith("network.addresses") for path in paths)


def test_asn_holder_reassignment_appears_in_diff():
    def result(holders):
        return to_dict(ScanResult(root_domain="example.com", hosts=[
            HostTeardown(target="https://example.com", host="example.com",
                         network=NetworkInfo(addresses=[NetworkAddress(
                             address="1.1.1.1", asns=[1, 2], asn_holders=holders)]))]))

    changes = diff_results(result({"1": "Alpha", "2": "Beta"}),
                           result({"1": "Beta", "2": "Alpha"}))["changed_hosts"]
    assert changes


def test_geo_ip_rendering_attribution_and_diff():
    geo = GeoIpInfo(country_code="CA", city="Toronto", latitude=43.7,
                    longitude=-79.4, data_updated_at="2026-11-13T20:46:43")
    old_host = HostTeardown(target="https://example.com", host="example.com",
                            http=HttpInfo(cdn="cloudflare"),
                            network=NetworkInfo(observation="cdn_edge", addresses=[
                                NetworkAddress(address="1.1.1.1")]))
    new_host = HostTeardown(target="https://example.com", host="example.com",
                            http=HttpInfo(cdn="cloudflare"),
                            network=NetworkInfo(observation="cdn_edge", addresses=[
                                NetworkAddress(address="1.1.1.1", geo=geo)]))
    rendered = render_host_markdown(new_host)
    assert "Toronto, CA" in rendered
    assert "CDN edge" in rendered
    assert "approximate" in rendered.lower()
    assert "MaxMind GeoLite" in render_markdown(ScanResult(root_domain="example.com", hosts=[new_host]))
    old = to_dict(ScanResult(root_domain="example.com", hosts=[old_host]))
    new = to_dict(ScanResult(root_domain="example.com", hosts=[new_host]))
    assert any(change["path"] == "network.addresses" and "geo" in str(change["after"])
               for change in diff_results(old, new)["changed_hosts"][0]["changes"])


@pytest.mark.asyncio
async def test_ripe_api_concurrency_stays_below_provider_limit():
    import asyncio

    active = 0
    peak = 0

    async def handler(_request):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.01)
        active -= 1
        return httpx.Response(200, json={"data": {}})

    async with HttpClient(root_domain="example.com", concurrency=12, rate_per_sec=10000,
                          retries=0, transport=httpx.MockTransport(handler)) as client:
        await asyncio.gather(*(client.get(
            f"https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource=8.8.8.{n}")
            for n in range(1, 13)))
    assert peak <= 8


@pytest.mark.asyncio
async def test_named_network_module_persists_in_scan_history(tmp_path, monkeypatch):
    from teardown.cli import run_scan
    from teardown.history import HistoryStore
    from teardown.scan_modules import default_modules

    data = {
        "https://stat.ripe.net/data/network-info/data.json?resource=8.8.8.8":
            {"data": {"prefix": "8.8.8.0/24", "asns": [15169]}},
    }

    class Client(FakeFetcher):
        def __init__(self, **_kwargs):
            super().__init__(DnsObservation(addresses=["8.8.8.8"]), data)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

        async def get(self, url, **kwargs):
            if url == "https://example.com":
                return FetchResponse(url=url, final_url=url, status=200, text="<title>Example</title>")
            return await super().get(url, **kwargs)

    monkeypatch.setattr("teardown.cli.HttpClient", Client)
    modules = [module for module in default_modules() if module.name in {"http", "network"}]
    with HistoryStore(tmp_path) as history:
        result = await run_scan("example.com", single=True, active_dns=False,
                                wordlist=None, max_hosts=1, concurrency=1,
                                rate_per_sec=8, data_dir=str(tmp_path),
                                history=history, modules=modules)
        assert result.hosts[0].network.addresses[0].prefix == "8.8.8.0/24"
        assert history.latest_result("example.com")["hosts"][0]["network"]["addresses"][0]["asns"] == [15169]
