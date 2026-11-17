"""Named host scan modules over one shared response and injected Fetcher.

Modules collect deterministic signals. Extra modules may return a JSON mapping;
it is stored under their name in ``HostTeardown.extensions``. No module should
make requests outside the injected Fetcher.
"""

from __future__ import annotations

import json
import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .collectors.api_discovery import discover_api
from .collectors.headers import parse_csp, parse_headers
from .collectors.html_js import (
    detect_cms,
    detect_secret_leaks,
    enrich_bundles,
    extract_bundles,
    fingerprint_third_parties,
    redact_secret_values,
)
from .fingerprints import detect_technologies, framework_names
from .http_client import Fetcher, FetchResponse
from .models import HostTeardown, to_dict
from .safety import safe_text

_NAME = re.compile(r"[a-z][a-z0-9_]*\Z")
_SECRET_KEY = re.compile(
    r"password|secret|token|credential|session|auth|api[_-]?key|access[_-]?key|"
    r"(?:^|[_-])key(?:$|[_-])", re.I)


@dataclass
class ScanContext:
    host: HostTeardown
    response: FetchResponse
    fetcher: Fetcher
    base_url: str
    html: str


@dataclass(frozen=True)
class ScanModule:
    name: str
    collect: Callable[[ScanContext], Awaitable[Mapping[str, Any] | None]]

    def __post_init__(self) -> None:
        if not _NAME.fullmatch(self.name):
            raise ValueError("module name must be lowercase letters, digits or underscores")


def safe_extension(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Convert and redact an extension payload before it enters the model."""
    if not isinstance(payload, Mapping):
        raise TypeError("module payload must be a mapping")

    def scrub(value: Any) -> Any:
        if isinstance(value, dict):
            return {str(key): "[REDACTED]" if _SECRET_KEY.search(str(key)) else scrub(item)
                    for key, item in value.items()}
        if isinstance(value, list):
            return [scrub(item) for item in value]
        if isinstance(value, str):
            return redact_secret_values(safe_text(value))
        return value

    result = scrub(to_dict(dict(payload)))
    json.dumps(result)
    return result


async def _http(context: ScanContext) -> None:
    context.host.http = parse_headers(context.response)
    context.host.csp = parse_csp(context.response.headers)


async def _fingerprints(context: ScanContext) -> None:
    host = context.host
    host.detections = detect_technologies(context.html, context.response.headers,
                                          context.response.final_url)
    host.frameworks = framework_names(host.detections)
    host.cms = detect_cms(context.html, context.response.headers)
    if not host.cms.type:
        cms_matches = [item for item in host.detections if "cms" in item.categories]
        if cms_matches:
            host.cms.type = max(cms_matches, key=lambda item: item.confidence).name.lower()


async def _bundles(context: ScanContext) -> None:
    bundles = extract_bundles(context.html, context.base_url)
    context.host.bundles = await enrich_bundles(bundles, context.fetcher)


async def _third_parties(context: ScanContext) -> None:
    context.host.third_parties = fingerprint_third_parties(context.html)


async def _secrets(context: ScanContext) -> None:
    context.host.secret_leaks = detect_secret_leaks(context.html, context.base_url)


async def _api(context: ScanContext) -> None:
    context.host.api_surface = await discover_api(context.base_url, context.fetcher)


_BUILTIN_MODULES = (
    ScanModule("http", _http),
    ScanModule("fingerprints", _fingerprints),
    ScanModule("bundles", _bundles),
    ScanModule("third_parties", _third_parties),
    ScanModule("secrets", _secrets),
    ScanModule("api", _api),
)
_EXTRA_MODULES: list[ScanModule] = []


def register_module(module: ScanModule) -> None:
    """Append an extra module to subsequent host scans in this process."""
    if module.name in {item.name for item in (*_BUILTIN_MODULES, *_EXTRA_MODULES)}:
        raise ValueError(f"duplicate module name: {module.name}")
    _EXTRA_MODULES.append(module)


def default_modules() -> tuple[ScanModule, ...]:
    """Return built-ins followed by explicitly registered extra modules."""
    return (*_BUILTIN_MODULES, *_EXTRA_MODULES)


async def run_modules(context: ScanContext, modules: Sequence[ScanModule] | None = None) -> None:
    """Run each module independently, preserving later modules after failures."""
    selected = default_modules() if modules is None else tuple(modules)
    for module in selected:
        try:
            payload = await module.collect(context)
            if payload is not None:
                context.host.extensions[module.name] = safe_extension(payload)
        except Exception as exc:  # noqa: BLE001 - collection is best-effort per module
            context.host.errors.append(f"module {module.name} error: {type(exc).__name__}")
