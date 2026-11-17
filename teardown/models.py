"""Data contract for the teardown tool.

These dataclasses are the agent-readable schema. Everything the collectors
produce and the renderer consumes flows through these types. Bump
SCHEMA_VERSION on any breaking change to field names/shapes.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

SCHEMA_VERSION = "1.1"


class Severity(str, Enum):
    CRITICAL = "critical"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class HttpInfo:
    status: int | None = None
    final_url: str | None = None
    server: str | None = None
    powered_by: str | None = None
    # e.g. {"hsts": True, "x_frame_options": "DENY", ...}
    security_headers: dict[str, Any] = field(default_factory=dict)
    # e.g. {"cf_cache_status": "HIT", "x_vercel_cache": "MISS", ...}
    cache: dict[str, Any] = field(default_factory=dict)
    all_headers: dict[str, str] = field(default_factory=dict)
    title: str | None = None
    status_chain: list[int] = field(default_factory=list)
    tls: dict[str, str] = field(default_factory=dict)
    cdn: str | None = None


@dataclass
class CspInfo:
    present: bool = False
    # directive -> list of sources, e.g. {"script-src": ["'self'", "https://x.com"]}
    directives: dict[str, list[str]] = field(default_factory=dict)
    # flattened unique third-party domains across all directives
    third_party_domains: list[str] = field(default_factory=list)


@dataclass
class CmsInfo:
    type: str | None = None          # "wordpress", "drupal", "shopify", ...
    version: str | None = None
    plugins: list[str] = field(default_factory=list)
    themes: list[str] = field(default_factory=list)


@dataclass
class Bundle:
    url: str
    type: str = "js"                 # "js" | "css"
    has_sourcemap: bool = False
    interesting_tokens: list[str] = field(default_factory=list)


@dataclass
class RestEndpoint:
    path: str
    status: int | None = None


@dataclass
class GraphQLInfo:
    present: bool = False
    introspection_open: bool = False
    types: list[str] = field(default_factory=list)


@dataclass
class OpenApiInfo:
    present: bool = False
    url: str | None = None
    endpoints: list[str] = field(default_factory=list)


@dataclass
class WordPressInfo:
    wp_json: bool = False
    users_enumerable: bool = False
    users: list[str] = field(default_factory=list)


@dataclass
class ApiSurface:
    rest: list[RestEndpoint] = field(default_factory=list)
    graphql: GraphQLInfo = field(default_factory=GraphQLInfo)
    openapi: OpenApiInfo = field(default_factory=OpenApiInfo)
    wordpress: WordPressInfo = field(default_factory=WordPressInfo)


@dataclass
class ThirdParty:
    name: str                        # "segment", "sentry", "stripe", ...
    category: str = "unknown"        # "analytics" | "auth" | "payments" | ...
    key: str | None = None           # extracted key/id if any
    evidence: str | None = None      # where it was seen


@dataclass
class SecretLeak:
    type: str                        # "stripe_pk", "segment_write_key", ...
    value_prefix: str                # redacted prefix, NEVER the full secret
    source_url: str | None = None


@dataclass
class OpsecFinding:
    severity: Severity
    title: str
    detail: str
    evidence_url: str | None = None
    confidence: int = 100
    evidence: list[str] = field(default_factory=list)


@dataclass
class Detection:
    name: str
    categories: list[str] = field(default_factory=list)
    confidence: int = 0
    evidence: list[str] = field(default_factory=list)


@dataclass
class HostTeardown:
    target: str                      # original URL as scanned
    host: str                        # hostname
    scanned_at: str = ""             # ISO8601 UTC
    reachable: bool = False
    http: HttpInfo = field(default_factory=HttpInfo)
    csp: CspInfo = field(default_factory=CspInfo)
    frameworks: list[str] = field(default_factory=list)
    detections: list[Detection] = field(default_factory=list)
    cms: CmsInfo = field(default_factory=CmsInfo)
    bundles: list[Bundle] = field(default_factory=list)
    api_surface: ApiSurface = field(default_factory=ApiSurface)
    third_parties: list[ThirdParty] = field(default_factory=list)
    secret_leaks: list[SecretLeak] = field(default_factory=list)
    opsec_findings: list[OpsecFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class EnumerationInfo:
    sources: list[str] = field(default_factory=list)   # ["crt.sh", "dns-brute"]
    subdomains_found: int = 0
    live_hosts: int = 0


@dataclass
class Aggregate:
    tech_stack_union: dict[str, list[str]] = field(default_factory=dict)
    detections_union: list[str] = field(default_factory=list)
    third_parties_union: list[str] = field(default_factory=list)
    critical_findings: list[OpsecFinding] = field(default_factory=list)


@dataclass
class ScanResult:
    root_domain: str
    scanned_at: str = ""
    schema_version: str = SCHEMA_VERSION
    enumeration: EnumerationInfo = field(default_factory=EnumerationInfo)
    hosts: list[HostTeardown] = field(default_factory=list)
    aggregate: Aggregate = field(default_factory=Aggregate)


def to_dict(obj: Any) -> Any:
    """Recursively convert dataclasses/enums to JSON-serializable dicts."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return to_dict(dataclasses.asdict(obj))
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, dict):
        from .safety import safe_url
        url_fields = {"target", "final_url", "source_url", "evidence_url", "url"}
        return {k: safe_url(v) if k in url_fields and isinstance(v, str) else to_dict(v)
                for k, v in obj.items()}
    if isinstance(obj, str):
        from .safety import safe_text
        return safe_text(obj)
    if isinstance(obj, (list, tuple)):
        return [to_dict(v) for v in obj]
    return obj
