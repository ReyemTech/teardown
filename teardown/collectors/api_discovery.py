"""Passive API-surface discovery.

Ports the Step 3 probes from the teardown agent: REST roots, OpenAPI/Swagger
specs, GraphQL introspection, and the WordPress REST API (including user
enumeration). Everything here is read-only and must never raise — the injected
Fetcher returns errors as :class:`FetchResponse` with ``status=None``.
"""

from __future__ import annotations

import json
from typing import Any

from ..http_client import Fetcher
from ..models import (
    ApiSurface,
    GraphQLInfo,
    OpenApiInfo,
    RestEndpoint,
    WordPressInfo,
)

REST_PATHS = ["/api/", "/api/v1/", "/api/v2/"]
OPENAPI_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/swagger/v1/swagger.json",
]
GRAPHQL_PATHS = ["/graphql", "/api/graphql"]
INTROSPECTION_QUERY = {"query": "{__schema{types{name}}}"}


def _try_json(text: str) -> Any:
    """Parse JSON, returning None on any failure (never raises)."""
    if not text:
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def _base(base_url: str) -> str:
    return base_url.rstrip("/")


async def discover_api(base_url: str, fetcher: Fetcher) -> ApiSurface:
    """Probe a host for exposed API surface. Never raises."""
    base = _base(base_url)
    surface = ApiSurface()

    await _discover_rest(base, fetcher, surface)
    await _discover_openapi(base, fetcher, surface)
    await _discover_graphql(base, fetcher, surface)
    await _discover_wordpress(base, fetcher, surface)

    return surface


async def _discover_rest(base: str, fetcher: Fetcher, surface: ApiSurface) -> None:
    for path in REST_PATHS:
        resp = await fetcher.get(base + path)
        # Count anything that responds and is not a server error.
        if resp.status is not None and resp.status < 500:
            surface.rest.append(RestEndpoint(path=path, status=resp.status))


async def _discover_openapi(base: str, fetcher: Fetcher, surface: ApiSurface) -> None:
    for path in OPENAPI_PATHS:
        url = base + path
        resp = await fetcher.get(url)
        if resp.status is None:
            continue
        spec = _try_json(resp.text)
        if not isinstance(spec, dict):
            continue
        # A JSON doc that parses here counts as an OpenAPI/Swagger spec.
        endpoints: list[str] = []
        paths = spec.get("paths")
        if isinstance(paths, dict):
            endpoints = list(paths.keys())
        surface.openapi = OpenApiInfo(present=True, url=url, endpoints=endpoints)
        return


async def _discover_graphql(base: str, fetcher: Fetcher, surface: ApiSurface) -> None:
    present = False
    for path in GRAPHQL_PATHS:
        url = base + path
        resp = await fetcher.request("POST", url, json=INTROSPECTION_QUERY)
        if resp.status is None:
            continue

        body = _try_json(resp.text)
        schema = None
        if isinstance(body, dict):
            data = body.get("data")
            if isinstance(data, dict):
                schema = data.get("__schema")

        if isinstance(schema, dict):
            types = [
                t["name"]
                for t in schema.get("types", [])
                if isinstance(t, dict) and "name" in t
            ]
            surface.graphql = GraphQLInfo(
                present=True, introspection_open=True, types=types
            )
            return

        # Endpoint responded (and isn't a plain 404) → it exists but either
        # blocks introspection or returned a GraphQL error.
        if resp.status != 404 and resp.status < 500:
            present = True
        elif isinstance(body, dict) and ("data" in body or "errors" in body):
            present = True

    if present:
        surface.graphql = GraphQLInfo(present=True, introspection_open=False)


async def _discover_wordpress(base: str, fetcher: Fetcher, surface: ApiSurface) -> None:
    wp = WordPressInfo()

    root = await fetcher.get(base + "/wp-json/")
    if root.status is not None and _try_json(root.text) is not None:
        wp.wp_json = True

    users_resp = await fetcher.get(base + "/wp-json/wp/v2/users")
    if users_resp.status is not None:
        body = _try_json(users_resp.text)
        if isinstance(body, list) and body:
            names: list[str] = []
            for entry in body:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("slug") or entry.get("name")
                if name:
                    names.append(str(name))
            if names:
                wp.users_enumerable = True
                wp.users = names

    surface.wordpress = wp
    return
