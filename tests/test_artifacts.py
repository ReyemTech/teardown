"""Private, sanitized retention of first-party exposed source maps."""

from __future__ import annotations

import json
import os
import stat

import pytest

from teardown.artifacts import ArtifactStore
from teardown.collectors.html_js import enrich_bundles
from teardown.http_client import FetchResponse
from teardown.models import Bundle


class FakeFetcher:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    async def get(self, url, **_kwargs):
        self.calls.append(url)
        return self.responses.get(url, FetchResponse(url=url, final_url=url, status=None))


def response(url, body):
    return FetchResponse(url=url, final_url=url, status=200, text=body)


def test_artifact_store_redacts_secrets_and_preserves_valid_map(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts")
    secret = "sk_live_abcdef1234567890"
    source_text = f'const token = "{secret}"; const x=1;'
    source = store.save_source(source_text)
    source_map = store.save_map({
        "version": 3, "sources": ["src/app.ts"], "mappings": "AAAA",
        "sourcesContent": [f'const password = "{secret}";'],
    })
    assert source and source_map
    assert secret not in open(source.local_path, encoding="utf-8").read()
    saved_map = json.load(open(source_map.local_path, encoding="utf-8"))
    assert saved_map["mappings"] == "AAAA"
    assert secret not in json.dumps(saved_map)
    assert "[REDACTED]" in saved_map["sourcesContent"][0]
    assert store.save_source(source_text).sha256 == source.sha256
    if os.name != "nt":
        assert stat.S_IMODE((tmp_path / "artifacts").stat().st_mode) == 0o700
        assert stat.S_IMODE(os.stat(source.local_path).st_mode) == 0o600


def test_artifact_size_cap(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts", max_bytes=16)
    assert store.save_source("x" * 17) is None
    assert not (tmp_path / "artifacts").exists()


def test_artifacts_redact_connection_uri_credentials(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts")
    credential = "postgres://alice:p4ssword@db.example.com/prod"
    source = store.save_source(f'const connectionString = "{credential}";')
    mapping = store.save_map({"version": 3, "sources": ["src/app.ts"],
                              "mappings": "AAAA",
                              "sourcesContent": [f'const db_url = "{credential}";']})
    assert source and mapping
    assert credential not in open(source.local_path, encoding="utf-8").read()
    assert credential not in open(mapping.local_path, encoding="utf-8").read()


def test_artifact_store_rejects_non_vlq_mappings(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts")
    assert store.save_map({"version": 3, "sources": [],
                           "mappings": "password=cleartext"}) is None


def test_artifact_store_redacts_quoted_secret_properties(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts")
    source = store.save_source('const config = {"clientSecret": "short!pass", "db_url": "pw:123"};')
    assert source
    saved = open(source.local_path, encoding="utf-8").read()
    assert "short!pass" not in saved
    assert "pw:123" not in saved


def test_saved_map_redacts_relative_url_query_credentials(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts")
    secret = "shortpass"
    saved = store.save_map({
        "version": 3, "mappings": "AAAA",
        "sources": ["src/app.js?token=" + secret],
        "sourcesContent": ["const url='/api/data?token=" + secret + "';"],
    })
    assert saved
    assert secret not in open(saved.local_path, encoding="utf-8").read()


@pytest.mark.asyncio
async def test_enrich_saves_only_first_party_exposed_map(tmp_path):
    first = "https://app.example.com/assets/app.js"
    third = "https://cdn.vendor.com/sdk.js"
    mapping = {"version": 3, "sources": ["app.ts"], "mappings": "AAAA",
               "sourcesContent": ["export const app = true;"]}
    fetcher = FakeFetcher({
        first + ".map": response(first + ".map", json.dumps(mapping)),
        first: response(first, "const app=true;"),
        third + ".map": response(third + ".map", json.dumps(mapping)),
        third: response(third, "const sdk=true;"),
    })
    bundles = await enrich_bundles([Bundle(first), Bundle(third)], fetcher,
                                   artifact_store=ArtifactStore(tmp_path / "artifacts"),
                                   host_name="app.example.com")
    assert bundles[0].source_artifact is not None
    assert bundles[0].sourcemap_artifact is not None
    assert bundles[0].source_map_sources == 1
    assert bundles[1].has_sourcemap
    assert bundles[1].source_artifact is None
    assert bundles[1].sourcemap_artifact is None


@pytest.mark.asyncio
async def test_first_party_map_intel_is_available_without_artifact_saving():
    first = "https://app.example.com/app.js"
    third = "https://cdn.vendor.com/sdk.js"
    spec = {"openapi": "3.0.3", "paths": {"/api/users": {"get": {}}}}
    mapping = {"version": 3, "sources": ["src/static.js"], "mappings": "AAAA",
               "sourcesContent": ["const api = " + json.dumps(spec) + ";"]}
    fetcher = FakeFetcher({
        first + ".map": response(first + ".map", json.dumps(mapping)),
        first: response(first, "const app=true;"),
        third + ".map": response(third + ".map", json.dumps(mapping)),
        third: response(third, "const sdk=true;"),
    })
    bundles = await enrich_bundles([Bundle(first), Bundle(third)], fetcher,
                                   host_name="app.example.com")
    assert bundles[0].source_map_intel is not None
    assert bundles[0].source_map_intel.embedded_openapi.path_count == 1
    assert bundles[0].sourcemap_artifact is None
    assert bundles[1].source_map_intel is None
    assert not any("/api/users" in url for url in fetcher.calls)


@pytest.mark.asyncio
async def test_malformed_map_artifact_does_not_skip_bundle_analysis(tmp_path):
    url = "https://app.example.com/app.js"
    mapping = {"version": 3, "sources": ["src/app.js"],
               "mappings": "AAAA", "sourcesContent": ["\ud800"]}
    fetcher = FakeFetcher({
        url + ".map": response(url + ".map", json.dumps(mapping)),
        url: response(url, 'const endpoint = "/graphql";'),
    })
    bundle = (await enrich_bundles([Bundle(url)], fetcher,
                                   artifact_store=ArtifactStore(tmp_path / "artifacts"),
                                   host_name="app.example.com"))[0]
    assert "graphql" in bundle.interesting_tokens
    assert bundle.sourcemap_artifact is None


@pytest.mark.asyncio
async def test_run_scan_artifact_toggle(monkeypatch, tmp_path):
    from teardown.cli import run_scan

    home = "https://app.example.com"
    bundle_url = home + "/app.js"
    mapping = {"version": 3, "sources": ["app.ts"], "mappings": "AAAA"}
    fetcher = FakeFetcher({
        home: response(home, '<script src="/app.js"></script>'),
        bundle_url: response(bundle_url, "const app=true;"),
        bundle_url + ".map": response(bundle_url + ".map", json.dumps(mapping)),
    })

    class Client:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return fetcher

        async def __aexit__(self, *_args):
            pass

    monkeypatch.setattr("teardown.cli.HttpClient", Client)
    options = dict(single=True, active_dns=False, wordlist=None, max_hosts=1,
                   concurrency=2, rate_per_sec=8, data_dir=str(tmp_path), cache_dir="")
    saved = await run_scan(home, **options)
    assert saved.hosts[0].bundles[0].sourcemap_artifact is not None
    assert (tmp_path / "artifacts").exists()
    disabled = await run_scan(home, save_artifacts=False, **options)
    assert disabled.hosts[0].bundles[0].sourcemap_artifact is None
