"""Offline structural analysis of public source maps."""

from __future__ import annotations

import json

from teardown.models import to_dict
from teardown.sourcemap_intel import analyze_source_map


def test_embedded_openapi_inventory_and_dependency_split():
    spec = {
        "openapi": "3.0.3", "paths": {
            "/api/users": {"get": {"operationId": "users"},
                           "post": {"operationId": "createUser"}},
            "/api/roles/{id}": {"get": {"operationId": "role"}},
        }, "components": {"schemas": {"User": {}, "Role": {}}},
    }
    result = analyze_source_map({
        "version": 3, "mappings": "AAAA",
        "sources": ["../../app/models/static.js", "../../node_modules/lodash-es/keys.js"],
        "sourcesContent": ["const api = " + json.dumps(spec) + ";", "export const keys = [];"],
    })
    assert result is not None
    assert result.total_sources == 2
    assert result.embedded_sources == 2
    assert result.application_sources == 1
    assert result.dependency_sources == 1
    assert len(result.sources) == 2
    assert result.embedded_openapi is not None
    assert result.embedded_openapi.version == "3.0.3"
    assert result.embedded_openapi.path_count == 2
    assert result.embedded_openapi.operation_count == 3
    assert result.embedded_openapi.schema_count == 2
    assert result.embedded_openapi.methods == {"GET": 2, "POST": 1}
    assert [(item.path, item.methods) for item in result.embedded_openapi.paths] == [
        ("/api/roles/{id}", ["GET"]), ("/api/users", ["GET", "POST"]),
    ]


def test_map_without_sources_content_only_reports_paths():
    result = analyze_source_map({"version": 3, "mappings": "AAAA",
                                 "sources": ["src/app.js", "node_modules/pkg/index.js"]})
    assert result is not None
    assert result.embedded_sources == 0
    assert result.embedded_openapi is None
    assert all(not item.embedded for item in result.sources)


def test_inventory_is_bounded_and_secrets_are_absent():
    spec = {"openapi": "3.0.0", "paths": {
        f"/api/item{i}": {"get": {}} for i in range(205)
    }}
    source = 'const password = "supersecretvalue"; const api = ' + json.dumps(spec)
    result = analyze_source_map({"version": 3, "mappings": "AAAA",
                                 "sources": [f"src/item{i}.js" for i in range(204)],
                                 "sourcesContent": [source] + [None] * 203})
    assert result is not None
    assert len(result.sources) == 200
    assert result.sources_omitted == 4
    assert result.embedded_openapi is not None
    assert len(result.embedded_openapi.paths) == 200
    assert result.embedded_openapi.paths_omitted == 5
    assert "supersecretvalue" not in json.dumps(to_dict(result))


def test_malformed_or_oversized_map_is_ignored():
    assert analyze_source_map({"version": 3, "sources": [], "mappings": "bad="}) is None
    assert analyze_source_map({"version": 3, "sources": [], "mappings": "A" * 4_000_001}) is None


def test_embedded_spec_with_missing_components_is_tolerated():
    spec = {"openapi": "3.0.3", "paths": {"/api/users": {"get": {}}},
            "components": None}
    result = analyze_source_map({"version": 3, "mappings": "AAAA",
                                 "sources": ["src/api.js"],
                                 "sourcesContent": ["const api = " + json.dumps(spec)]})
    assert result is not None
    assert result.embedded_openapi is not None
    assert result.embedded_openapi.schema_count == 0


def test_relative_path_queries_cannot_leak_tokens():
    secret = "shortpass"
    spec = {"openapi": "3.0.3", "paths": {
        "/api/data?token=" + secret: {"get": {}}
    }}
    result = analyze_source_map({"version": 3, "mappings": "AAAA",
                                 "sources": ["src/app.js?token=" + secret],
                                 "sourcesContent": ["const api = " + json.dumps(spec)]})
    assert result is not None
    payload = json.dumps(to_dict(result))
    assert secret not in payload
    assert result.sources[0].path == "src/app.js"
    assert result.embedded_openapi.paths[0].path == "/api/data"
