"""Tests for teardown.collectors.api_discovery — no real network."""

from __future__ import annotations

import json

import pytest

from teardown.collectors.api_discovery import discover_api
from teardown.http_client import FetchResponse

BASE = "https://example.com"


class FakeFetcher:
    """Canned-response Fetcher keyed by URL (and by (method, url) for request)."""

    def __init__(self, responses: dict[str, FetchResponse]) -> None:
        self._responses = responses
        self.calls: list[tuple[str, str]] = []

    def _lookup(self, method: str, url: str) -> FetchResponse:
        self.calls.append((method, url))
        if (method, url) in self._responses:
            return self._responses[(method, url)]
        if url in self._responses:
            return self._responses[url]
        # Default: unreachable / not found.
        return FetchResponse(url=url, final_url=url, status=None, error="no canned response")

    async def get(self, url: str, **kwargs) -> FetchResponse:
        return self._lookup("GET", url)

    async def request(self, method: str, url: str, **kwargs) -> FetchResponse:
        return self._lookup(method, url)


def ok(url: str, body: str = "", status: int = 200) -> FetchResponse:
    return FetchResponse(url=url, final_url=url, status=status, text=body)


def missing(url: str, status: int = 404) -> FetchResponse:
    return FetchResponse(url=url, final_url=url, status=status, text="Not Found")


# --- REST ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rest_probe_records_responding_endpoints_only():
    responses = {
        f"{BASE}/api/": ok(f"{BASE}/api/", "{}", 200),
        f"{BASE}/api/v1/": ok(f"{BASE}/api/v1/", "", 401),  # <500, still recorded
        f"{BASE}/api/v2/": FetchResponse(
            url=f"{BASE}/api/v2/", final_url=f"{BASE}/api/v2/", status=503, text=""
        ),  # 5xx -> dropped
    }
    surface = await discover_api(BASE, FakeFetcher(responses))
    paths = {(e.path, e.status) for e in surface.rest}
    assert ("/api/", 200) in paths
    assert ("/api/v1/", 401) in paths
    assert all(e.path != "/api/v2/" for e in surface.rest)  # 503 excluded


@pytest.mark.asyncio
async def test_rest_probe_excludes_unreachable():
    # No canned responses -> all status None -> nothing recorded.
    surface = await discover_api(BASE, FakeFetcher({}))
    assert surface.rest == []


# --- OpenAPI ---------------------------------------------------------------

@pytest.mark.asyncio
async def test_openapi_endpoint_extraction():
    spec = json.dumps(
        {
            "openapi": "3.0.0",
            "paths": {"/users": {}, "/users/{id}": {}, "/orders": {}},
        }
    )
    url = f"{BASE}/openapi.json"
    surface = await discover_api(BASE, FakeFetcher({url: ok(url, spec)}))
    assert surface.openapi.present is True
    assert surface.openapi.url == url
    assert surface.openapi.endpoints == ["/users", "/users/{id}", "/orders"]


@pytest.mark.asyncio
async def test_openapi_non_json_ignored():
    url = f"{BASE}/openapi.json"
    surface = await discover_api(BASE, FakeFetcher({url: ok(url, "<html>nope</html>")}))
    assert surface.openapi.present is False
    assert surface.openapi.endpoints == []


@pytest.mark.asyncio
async def test_openapi_falls_through_to_swagger_path():
    spec = json.dumps({"swagger": "2.0", "paths": {"/ping": {}}})
    url = f"{BASE}/swagger.json"
    responses = {
        f"{BASE}/openapi.json": missing(f"{BASE}/openapi.json"),
        url: ok(url, spec),
    }
    surface = await discover_api(BASE, FakeFetcher(responses))
    assert surface.openapi.present is True
    assert surface.openapi.url == url
    assert surface.openapi.endpoints == ["/ping"]


# --- GraphQL ---------------------------------------------------------------

@pytest.mark.asyncio
async def test_graphql_introspection_open():
    body = json.dumps(
        {"data": {"__schema": {"types": [{"name": "Query"}, {"name": "User"}]}}}
    )
    url = f"{BASE}/graphql"
    surface = await discover_api(BASE, FakeFetcher({url: ok(url, body)}))
    assert surface.graphql.present is True
    assert surface.graphql.introspection_open is True
    assert surface.graphql.types == ["Query", "User"]


@pytest.mark.asyncio
async def test_graphql_introspection_blocked():
    # Endpoint exists (200) but introspection disabled -> errors, no __schema.
    body = json.dumps({"errors": [{"message": "introspection is disabled"}]})
    url = f"{BASE}/graphql"
    surface = await discover_api(BASE, FakeFetcher({url: ok(url, body, 200)}))
    assert surface.graphql.present is True
    assert surface.graphql.introspection_open is False
    assert surface.graphql.types == []


@pytest.mark.asyncio
async def test_graphql_absent_when_404():
    url = f"{BASE}/graphql"
    url2 = f"{BASE}/api/graphql"
    responses = {url: missing(url), url2: missing(url2)}
    surface = await discover_api(BASE, FakeFetcher(responses))
    assert surface.graphql.present is False
    assert surface.graphql.introspection_open is False


@pytest.mark.asyncio
async def test_graphql_found_on_secondary_path():
    body = json.dumps({"data": {"__schema": {"types": [{"name": "Query"}]}}})
    url2 = f"{BASE}/api/graphql"
    responses = {
        f"{BASE}/graphql": missing(f"{BASE}/graphql"),
        url2: ok(url2, body),
    }
    surface = await discover_api(BASE, FakeFetcher(responses))
    assert surface.graphql.present is True
    assert surface.graphql.introspection_open is True
    assert surface.graphql.types == ["Query"]


# --- WordPress -------------------------------------------------------------

@pytest.mark.asyncio
async def test_wordpress_user_enumeration_detected():
    users = json.dumps(
        [
            {"id": 1, "name": "Admin User", "slug": "admin"},
            {"id": 2, "name": "Jane", "slug": "jane"},
        ]
    )
    responses = {
        f"{BASE}/wp-json/": ok(f"{BASE}/wp-json/", json.dumps({"name": "Site", "namespaces": ["wp/v2"]})),
        f"{BASE}/wp-json/wp/v2/users": ok(f"{BASE}/wp-json/wp/v2/users", users),
    }
    surface = await discover_api(BASE, FakeFetcher(responses))
    assert surface.wordpress.wp_json is True
    assert surface.wordpress.users_enumerable is True
    assert surface.wordpress.users == ["admin", "jane"]


@pytest.mark.asyncio
async def test_wordpress_json_present_but_users_locked_down():
    # wp-json present, but users endpoint returns a 401 error object (not a list).
    err = json.dumps({"code": "rest_cannot_access", "message": "unauthorized"})
    responses = {
        f"{BASE}/wp-json/": ok(f"{BASE}/wp-json/", json.dumps({"name": "Site", "namespaces": ["wp/v2"]})),
        f"{BASE}/wp-json/wp/v2/users": FetchResponse(
            url=f"{BASE}/wp-json/wp/v2/users",
            final_url=f"{BASE}/wp-json/wp/v2/users",
            status=401,
            text=err,
        ),
    }
    surface = await discover_api(BASE, FakeFetcher(responses))
    assert surface.wordpress.wp_json is True
    assert surface.wordpress.users_enumerable is False
    assert surface.wordpress.users == []


@pytest.mark.asyncio
async def test_wordpress_absent_on_non_wp_site():
    surface = await discover_api(BASE, FakeFetcher({}))
    assert surface.wordpress.wp_json is False
    assert surface.wordpress.users_enumerable is False


@pytest.mark.asyncio
async def test_discover_api_never_raises_on_all_failures():
    # Everything unreachable; should return a clean, empty-ish ApiSurface.
    surface = await discover_api(BASE, FakeFetcher({}))
    assert surface.rest == []
    assert surface.openapi.present is False
    assert surface.graphql.present is False
    assert surface.wordpress.wp_json is False
