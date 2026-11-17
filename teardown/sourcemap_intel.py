"""Pure, bounded structural intelligence from already fetched source maps."""

from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any

from .artifacts import _sanitize_source
from .models import ApiPathReference, EmbeddedOpenApi, SourceMapIntel, SourceMapSource
from .safety import safe_text

MAX_MAP_BYTES = 4_000_000
MAX_SOURCE_BYTES = MAX_MAP_BYTES
MAX_INVENTORY = 200
_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}
_VLQ_MAPPINGS = re.compile(r"[A-Za-z0-9+/;,]*\Z")
_ASSIGNED_OBJECT = re.compile(r"\b(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=\s*(\{)")
_API_PATH = re.compile(r"/api/[A-Za-z0-9_/{}/:.()-]+")
_LONG_SEGMENT = re.compile(r"/[A-Za-z0-9_-]{24,}(?=/|$)")


def _safe_label(value: str) -> str:
    path_only = value.split("?", 1)[0].split("#", 1)[0]
    cleaned = _sanitize_source(safe_text(path_only)).replace("\n", " ").replace("\r", " ")
    return _LONG_SEGMENT.sub("/[REDACTED]", cleaned[:240])


def _spec_from_source(content: str, path: str) -> EmbeddedOpenApi | None:
    candidates = [content.lstrip()] if content.lstrip().startswith("{") else []
    candidates += [content[match.start(1):] for match in _ASSIGNED_OBJECT.finditer(content)]
    for candidate in candidates[:20]:
        try:
            document, _end = json.JSONDecoder().raw_decode(candidate)
        except (ValueError, TypeError):
            continue
        if not isinstance(document, dict) or not isinstance(document.get("openapi"), str):
            continue
        raw_paths = document.get("paths")
        if not isinstance(raw_paths, dict):
            continue
        methods: Counter[str] = Counter()
        paths: list[ApiPathReference] = []
        for route, item in raw_paths.items():
            if not isinstance(route, str) or not isinstance(item, dict):
                continue
            verbs = sorted(key.upper() for key in item if isinstance(key, str)
                           and key.lower() in _METHODS)
            methods.update(verbs)
            paths.append(ApiPathReference(path=_safe_label(route), methods=verbs))
        paths.sort(key=lambda item: item.path)
        components = document.get("components")
        raw_schemas = components.get("schemas", {}) if isinstance(components, dict) else {}
        if not isinstance(raw_schemas, dict):
            raw_schemas = {}
        schema_names = sorted(_safe_label(name) for name in raw_schemas if isinstance(name, str))
        return EmbeddedOpenApi(
            source_path=path, version=_safe_label(document["openapi"]),
            path_count=len(paths), operation_count=sum(methods.values()),
            schema_count=len(raw_schemas), methods=dict(sorted(methods.items())),
            paths=paths[:MAX_INVENTORY], paths_omitted=max(0, len(paths) - MAX_INVENTORY),
            schema_names=schema_names[:MAX_INVENTORY],
            schemas_omitted=max(0, len(schema_names) - MAX_INVENTORY),
        )
    return None


def analyze_source_map(source_map: dict[str, Any]) -> SourceMapIntel | None:
    """Inventory map contents without network requests or raw source in output."""
    if not isinstance(source_map, dict) or source_map.get("version") != 3:
        return None
    sources = source_map.get("sources")
    mappings = source_map.get("mappings")
    if not isinstance(sources, list) or not isinstance(mappings, str):
        return None
    if not _VLQ_MAPPINGS.fullmatch(mappings):
        return None
    if len(json.dumps(source_map, ensure_ascii=False).encode("utf-8")) > MAX_MAP_BYTES:
        return None
    content = source_map.get("sourcesContent")
    if not isinstance(content, list):
        content = []
    inventory: list[SourceMapSource] = []
    embedded = application = dependency = 0
    referenced_routes: set[str] = set()
    embedded_spec: EmbeddedOpenApi | None = None
    for index, raw_path in enumerate(sources):
        if not isinstance(raw_path, str):
            continue
        path = _safe_label(raw_path)
        is_dependency = "node_modules" in path.replace("\\", "/").split("/")
        body = content[index] if index < len(content) else None
        has_body = isinstance(body, str) and bool(body)
        embedded += has_body
        dependency += is_dependency
        application += not is_dependency
        if len(inventory) < MAX_INVENTORY:
            inventory.append(SourceMapSource(path=path,
                                             kind="dependency" if is_dependency else "application",
                                             embedded=has_body))
        if is_dependency or not has_body or len(body.encode("utf-8")) > MAX_SOURCE_BYTES:
            continue
        safe_body = _sanitize_source(body)
        referenced_routes.update(_safe_label(match.group().rstrip("/"))
                                 for match in _API_PATH.finditer(safe_body))
        spec = _spec_from_source(safe_body, path)
        if spec and (embedded_spec is None or spec.path_count > embedded_spec.path_count):
            embedded_spec = spec
    routes = sorted(referenced_routes)
    return SourceMapIntel(
        total_sources=len(sources), embedded_sources=embedded,
        application_sources=application, dependency_sources=dependency,
        sources=inventory, sources_omitted=max(0, len(sources) - len(inventory)),
        referenced_api_paths=routes[:MAX_INVENTORY],
        routes_omitted=max(0, len(routes) - MAX_INVENTORY),
        embedded_openapi=embedded_spec,
    )
