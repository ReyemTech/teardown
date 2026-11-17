"""Deterministic OPSEC analysis + cross-host aggregation.

`analyze_host` turns the raw signals a collector already gathered on a
`HostTeardown` into a prioritized list of `OpsecFinding`s. `build_aggregate`
rolls the whole scan up into tech-stack / third-party unions and pulls out every
critical finding. Pure and offline — no network, no mutation of inputs.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from .models import (
    Aggregate,
    HostTeardown,
    OpsecFinding,
    Severity,
)
from .safety import registrable_domain, source_map_url

# A dotted version number ("nginx/1.18.0", "PHP/8.1") or a "/<digit>" suffix.
_VERSION_RE = re.compile(r"\d+\.\d+|/\s*\d")

# Private / internal network markers that should never appear in a public CSP.
_PRIVATE_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
)
_INTERNAL_MARKERS = (
    "internal",
    "intranet",
    "corp",
    "vpn",
    "staging",
    "preprod",
    "pre-prod",
    ".local",
    ".svc",
    "cluster.local",
    "localhost",
)

# Names we treat as analytics / tracking when a key is exposed.
_ANALYTICS_NAMES = {
    "ga",
    "ga4",
    "gtag",
    "gtm",
    "google-analytics",
    "googleanalytics",
    "segment",
    "mixpanel",
    "posthog",
    "amplitude",
    "hotjar",
    "heap",
    "plausible",
    "matomo",
    "fathom",
}
_ANALYTICS_CATEGORIES = {"analytics", "tracking", "telemetry"}


def _is_https(host: HostTeardown) -> bool:
    url = (host.http.final_url or host.target or "").strip().lower()
    return url.startswith("https://")


def _reveals_version(value: str | None) -> bool:
    return bool(value) and bool(_VERSION_RE.search(value or ""))


def _header_present(host: HostTeardown, sec_key: str, header_name: str) -> bool:
    """True if a security header is set via either the parsed dict or raw headers."""
    sec = host.http.security_headers or {}
    if sec.get(sec_key):
        return True
    lowered = {k.lower() for k in (host.http.all_headers or {})}
    return header_name.lower() in lowered


def _is_live_secret(type_: str, value_prefix: str) -> bool:
    t = (type_ or "").lower()
    p = (value_prefix or "").lower()
    if "live" in t or "live" in p:
        return True
    # Server-side secret keys are always live-grade exposure.
    return p.startswith(("sk_", "rk_")) or "secret" in t


def analyze_host(host: HostTeardown) -> list[OpsecFinding]:
    """Derive OPSEC findings from the already-collected signals on `host`.

    Defensive: every field may be missing/empty. Returns a fresh list; does not
    mutate `host`.
    """
    findings: list[OpsecFinding] = []
    target = host.target or (f"https://{host.host}" if host.host else None)

    api = host.api_surface
    gql = api.graphql
    openapi = api.openapi
    wp = api.wordpress

    # ---- CRITICAL --------------------------------------------------------
    if gql and gql.introspection_open:
        findings.append(
            OpsecFinding(
                severity=Severity.CRITICAL,
                title="GraphQL introspection enabled",
                detail=(
                    "The GraphQL endpoint answers __schema introspection queries, "
                    f"exposing the full type system ({len(gql.types)} types) to anyone."
                ),
                evidence_url=f"{target}/graphql" if target else None,
            )
        )

    if wp and wp.users_enumerable:
        names = ", ".join(wp.users[:10]) if wp.users else "author accounts"
        findings.append(
            OpsecFinding(
                severity=Severity.CRITICAL,
                title="WordPress user enumeration open",
                detail=(
                    "The WP REST API returns the user list, leaking login names "
                    f"({names}) for credential-stuffing / brute-force targeting."
                ),
                evidence_url=f"{target}/wp-json/wp/v2/users" if target else None,
            )
        )

    if openapi and openapi.present:
        findings.append(
            OpsecFinding(
                severity=Severity.CRITICAL,
                title="OpenAPI/Swagger specification publicly exposed",
                detail=(
                    "A machine-readable API spec is reachable without auth, "
                    f"enumerating {len(openapi.endpoints)} endpoints and their shapes."
                ),
                evidence_url=openapi.url or (f"{target}/openapi.json" if target else None),
            )
        )

    for leak in host.secret_leaks or []:
        if _is_live_secret(leak.type, leak.value_prefix):
            findings.append(
                OpsecFinding(
                    severity=Severity.CRITICAL,
                    title=f"Live secret exposed: {leak.type}",
                    detail=(
                        f"A live-scope secret ({leak.type}) is present in client-visible "
                        f"content, redacted prefix `{leak.value_prefix}`."
                    ),
                    evidence_url=leak.source_url,
                )
            )

    for bundle in host.bundles or []:
        # Only first-party source maps are the target's own exposure. A third-party
        # CDN (Sentry, jsdelivr, …) publishing maps for its own SDK is not this
        # host leaking anything, so those are skipped. Source-map disclosure is an
        # information leak, not a credential/data leak -> MEDIUM, not CRITICAL.
        if bundle.has_sourcemap and _is_first_party(bundle.url, host.host):
            findings.append(
                OpsecFinding(
                    severity=Severity.MEDIUM,
                    title="Source map exposed on first-party bundle",
                    detail=(
                        f"The first-party bundle {bundle.url} ships a source map, "
                        "reconstructing original source (unminified logic, comments, "
                        "internal paths). Vendor libraries served first-party leak the "
                        "library's source; app bundles leak your own."
                    ),
                    evidence_url=source_map_url(bundle.url),
                )
            )

    # ---- MEDIUM ----------------------------------------------------------
    version_bits = []
    if _reveals_version(host.http.server):
        version_bits.append(f"Server: `{host.http.server}`")
    if _reveals_version(host.http.powered_by):
        version_bits.append(f"X-Powered-By: `{host.http.powered_by}`")
    if version_bits:
        findings.append(
            OpsecFinding(
                severity=Severity.MEDIUM,
                title="Server / framework version disclosure",
                detail=(
                    "Response headers reveal exact software versions, narrowing CVE "
                    "lookup for an attacker — " + "; ".join(version_bits) + "."
                ),
                evidence_url=target,
            )
        )

    internal = _internal_hosts_in_csp(host)
    if internal:
        findings.append(
            OpsecFinding(
                severity=Severity.MEDIUM,
                title="CSP leaks internal/infrastructure hostnames",
                detail=(
                    "The Content-Security-Policy references non-public hosts, mapping "
                    "internal infrastructure: " + ", ".join(internal) + "."
                ),
                evidence_url=target,
            )
        )

    if _is_https(host) and not _header_present(host, "hsts", "strict-transport-security"):
        findings.append(
            OpsecFinding(
                severity=Severity.MEDIUM,
                title="Missing HSTS on HTTPS site",
                detail=(
                    "No Strict-Transport-Security header, so browsers will honor a "
                    "downgrade to HTTP and are exposed to SSL-stripping on first visit."
                ),
                evidence_url=target,
            )
        )

    # ---- LOW -------------------------------------------------------------
    analytics = [
        tp
        for tp in (host.third_parties or [])
        if tp.key
        and (
            (tp.category or "").lower() in _ANALYTICS_CATEGORIES
            or (tp.name or "").lower() in _ANALYTICS_NAMES
        )
    ]
    if analytics:
        listed = ", ".join(f"{tp.name} (`{tp.key}`)" for tp in analytics)
        findings.append(
            OpsecFinding(
                severity=Severity.LOW,
                title="Analytics / tracking keys visible",
                detail=(
                    "Client-side analytics keys are exposed (expected for these SDKs, "
                    "but worth noting): " + listed + "."
                ),
                evidence_url=target,
            )
        )

    fingerprint = list(host.frameworks or [])
    if host.cms and host.cms.type:
        cms_label = host.cms.type + (f" {host.cms.version}" if host.cms.version else "")
        fingerprint.append(cms_label)
    if fingerprint:
        findings.append(
            OpsecFinding(
                severity=Severity.LOW,
                title="Framework / CMS fingerprintable",
                detail=(
                    "The stack is identifiable from public markers: "
                    + ", ".join(fingerprint)
                    + "."
                ),
                evidence_url=target,
            )
        )

    if not _header_present(host, "x_frame_options", "x-frame-options"):
        findings.append(
            OpsecFinding(
                severity=Severity.LOW,
                title="Missing X-Frame-Options",
                detail=(
                    "No X-Frame-Options header (and no frame-ancestors CSP seen), "
                    "leaving the site open to clickjacking via framing."
                ),
                evidence_url=target,
            )
        )
    if not _header_present(host, "x_content_type_options", "x-content-type-options"):
        findings.append(
            OpsecFinding(
                severity=Severity.LOW,
                title="Missing X-Content-Type-Options",
                detail=(
                    "No X-Content-Type-Options: nosniff header, allowing MIME-sniffing "
                    "of responses."
                ),
                evidence_url=target,
            )
        )

    # ---- INFO ------------------------------------------------------------
    if host.third_parties:
        names = sorted({tp.name for tp in host.third_parties if tp.name})
        if names:
            findings.append(
                OpsecFinding(
                    severity=Severity.INFO,
                    title="Third-party services enumerated",
                    detail=(
                        "Public signals enumerate the third parties this host talks to: "
                        + ", ".join(names)
                        + "."
                    ),
                    evidence_url=target,
                )
            )

    for finding in findings:
        if finding.title == "Framework / CMS fingerprintable" and host.detections:
            finding.confidence = max(item.confidence for item in host.detections)
            finding.evidence = sorted({signal for item in host.detections
                                       for signal in item.evidence})[:8]
        elif finding.title == "Third-party services enumerated":
            finding.evidence = sorted({tp.evidence or tp.name for tp in host.third_parties})[:8]
        elif finding.evidence_url:
            finding.evidence = [finding.evidence_url]
    return findings


def _registrable(hostname: str) -> str:
    return registrable_domain(hostname or "")


def _is_first_party(bundle_url: str, host_name: str) -> bool:
    """True if the bundle shares the host's registrable domain (or is a relative URL)."""
    bundle_host = urlsplit(bundle_url).hostname
    if not bundle_host:
        return True  # relative/same-origin URL
    return _registrable(bundle_host) == _registrable(host_name)


def _internal_hosts_in_csp(host: HostTeardown) -> list[str]:
    """Return sorted unique CSP sources that look internal/infra (not public)."""
    csp = host.csp
    if not csp or not csp.present:
        return []
    candidates: set[str] = set(csp.third_party_domains or [])
    for sources in (csp.directives or {}).values():
        for src in sources or []:
            s = src.strip().strip("'")
            if s and not s.startswith(("'", "data:", "blob:")):
                candidates.add(s)
    hits: set[str] = set()
    for dom in candidates:
        low = dom.lower()
        if _PRIVATE_IP_RE.search(low) or any(m in low for m in _INTERNAL_MARKERS):
            hits.add(dom)
    return sorted(hits)


def _detect_hosting(host: HostTeardown) -> list[str]:
    """Infer hosting/CDN providers from cache headers and the server string."""
    providers: set[str] = set()
    cache_keys = {k.lower() for k in (host.http.cache or {})}
    all_header_keys = {k.lower() for k in (host.http.all_headers or {})}
    keys = cache_keys | all_header_keys
    server = (host.http.server or "").lower()
    powered = (host.http.powered_by or "").lower()

    markers = {
        "Cloudflare": ("cf_cache_status", "cf-cache-status", "cf-ray"),
        "Vercel": ("x_vercel_cache", "x-vercel-cache", "x_vercel_id", "x-vercel-id"),
        "Netlify": ("x_nf_request_id", "x-nf-request-id"),
        "Fastly": ("x-served-by", "x_served_by", "fastly"),
        "AWS CloudFront": ("x-amz-cf-id", "x_amz_cf_id", "x-amz-cf-pop"),
    }
    for name, hints in markers.items():
        if any(h in keys for h in hints):
            providers.add(name)
    for name in ("cloudflare", "vercel", "netlify", "fastly", "akamai"):
        if name in server or name in powered:
            providers.add(name.capitalize())
    return sorted(providers)


def build_aggregate(hosts: list[HostTeardown]) -> Aggregate:
    """Union tech stack + third parties across hosts and collect critical findings."""
    frameworks: set[str] = set()
    detections: set[str] = set()
    cms: set[str] = set()
    servers: set[str] = set()
    hosting: set[str] = set()
    third_parties: set[str] = set()
    criticals: list[OpsecFinding] = []

    for host in hosts or []:
        detections.update(item.name for item in (host.detections or []) if item.name)
        for fw in host.frameworks or []:
            if fw:
                frameworks.add(fw)
        if host.cms and host.cms.type:
            cms.add(host.cms.type)
        if host.http.server:
            servers.add(host.http.server)
        if host.http.powered_by:
            servers.add(host.http.powered_by)
        for provider in _detect_hosting(host):
            hosting.add(provider)
        for tp in host.third_parties or []:
            if tp.name:
                third_parties.add(tp.name)
        for finding in host.opsec_findings or []:
            if finding.severity == Severity.CRITICAL:
                criticals.append(finding)

    tech_stack_union = {
        "frameworks": sorted(frameworks),
        "cms": sorted(cms),
        "servers": sorted(servers),
        "hosting": sorted(hosting),
    }
    return Aggregate(
        tech_stack_union=tech_stack_union,
        detections_union=sorted(detections),
        third_parties_union=sorted(third_parties),
        critical_findings=criticals,
    )
