"""Vault-compatible markdown + JSON output for a teardown scan.

Mirrors the frontmatter and section layout of the hand-written reference
teardowns (see references/intelligence/liteline-teardown.md) so the output
drops straight into the Obsidian vault. Pure/offline.
"""

from __future__ import annotations

import datetime
import json
import os

from .models import (
    HostTeardown,
    ScanResult,
    Severity,
    to_dict,
)
from .safety import safe_text, safe_url, source_map_url

# Severity -> (emoji heading label) for the OPSEC buckets, matching the agent's
# Step 5 ("### 🔴 Critical" etc.).
_SEVERITY_BUCKETS = [
    (Severity.CRITICAL, "🔴 Critical"),
    (Severity.MEDIUM, "🟡 Medium"),
    (Severity.LOW, "🟢 Low"),
    (Severity.INFO, "ℹ️ Info"),
]


def _today() -> str:
    return datetime.date.today().isoformat()


def _yaml_escape(value: str) -> str:
    """Quote a scalar for YAML if it contains characters that need it."""
    if value == "" or any(c in value for c in ':#"\n') or value.strip() != value:
        return '"' + value.replace('"', '\\"') + '"'
    return value


def _primary_url(result: ScanResult) -> str:
    for host in result.hosts:
        if host.target:
            return host.target
    return f"https://{result.root_domain}"


def _frontmatter(result: ScanResult) -> str:
    today = _today()
    tags = ["teardown"]
    # Derive a couple of signal tags from the aggregate for discoverability.
    for fw in result.aggregate.tech_stack_union.get("frameworks", []):
        slug = fw.lower().replace(" ", "-").replace(".", "")
        if slug and slug not in tags:
            tags.append(slug)
    lines = ["---", "type: intelligence", "category: teardown", "tags:"]
    lines += [f"  - {t}" for t in tags]
    lines += [
        f"created: {today}",
        f"updated: {today}",
        f"last-updated: {today}",
        "status: active",
        f"url: {_yaml_escape(safe_url(_primary_url(result)) or '')}",
        f"root_domain: {_yaml_escape(result.root_domain)}",
        "---",
    ]
    return "\n".join(lines)


def _host_framework_cms(host: HostTeardown) -> str:
    parts: list[str] = list(host.frameworks or [])
    if host.cms and host.cms.type:
        label = host.cms.type
        if host.cms.version:
            label += f" {host.cms.version}"
        parts.append(label)
    return ", ".join(parts) if parts else "—"


def _findings_by_severity(host: HostTeardown, severity: Severity) -> list:
    return [f for f in (host.opsec_findings or []) if f.severity == severity]


def _render_findings_block(host: HostTeardown) -> str:
    lines: list[str] = []
    for severity, label in _SEVERITY_BUCKETS:
        bucket = _findings_by_severity(host, severity)
        if severity == Severity.INFO and not bucket:
            # Only show the Info bucket when there is something to say.
            continue
        lines.append(f"#### {label}")
        if not bucket:
            lines.append("None found.")
        else:
            for f in bucket:
                detail = f.detail
                if f.evidence_url:
                    detail += f" (evidence: {safe_url(f.evidence_url)})"
                lines.append(f"- **{f.title}** — {detail}")
        lines.append("")
    return "\n".join(lines).rstrip()


def _network_cell(value: str | None) -> str:
    return (value or "—").replace("|", "\\|").replace("\n", " ")


def _code_cell(value: str) -> str:
    return "`" + _network_cell(value).replace("`", "'") + "`"


def render_host_markdown(host: HostTeardown) -> str:
    """The single-host section (reused by render_markdown and usable standalone)."""
    lines: list[str] = [f"### {host.host or host.target or 'host'}", ""]

    reach = "reachable" if host.reachable else "unreachable"
    bits = [reach]
    if host.http.status is not None:
        bits.append(f"HTTP {host.http.status}")
    if host.http.final_url:
        bits.append(safe_url(host.http.final_url) or "")
    if host.http.title:
        bits.append(host.http.title)
    if host.http.cdn:
        bits.append(f"CDN: {host.http.cdn}")
    lines.append("_" + " · ".join(bits) + "_")
    lines.append("")

    # Tech stack
    lines.append("**Tech stack**")
    lines.append("")
    lines.append("| Layer | Technology |")
    lines.append("|-------|-----------|")
    hosting = host.http.server or "—"
    lines.append(f"| Web server | {hosting} |")
    if host.http.powered_by:
        lines.append(f"| Powered-By | {host.http.powered_by} |")
    lines.append(f"| Framework | {', '.join(host.frameworks) if host.frameworks else '—'} |")
    if host.cms and host.cms.type:
        cms_val = host.cms.type + (f" {host.cms.version}" if host.cms.version else "")
        lines.append(f"| CMS | {cms_val} |")
    lines.append("")

    if host.detections:
        lines.append("**Technology evidence**")
        lines.append("")
        lines.append("| Technology | Confidence | Evidence |")
        lines.append("|------------|------------|----------|")
        for item in host.detections:
            evidence = ", ".join(item.evidence[:3]).replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {item.name} | {item.confidence}% | {evidence or '—'} |")
        lines.append("")

    # Public DNS/routing evidence; never an origin claim.
    lines.append("**Network attribution**")
    lines.append("")
    observation = {"cdn_edge": "CDN edge", "observed_endpoint": "Observed endpoint"}.get(
        host.network.observation, "Unknown")
    lines.append(f"- Address type: {observation} (DNS observation; origin not inferred)")
    if any(entry.geo for entry in host.network.addresses):
        lines.append("- Geo-IP is approximate. A CDN edge location is not the site's origin location.")
    if host.network.dns.cname_chain:
        lines.append("- CNAME chain: " + " → ".join(host.network.dns.cname_chain))
    if host.network.providers:
        lines.append("- Hosting and routing evidence:")
        for provider in host.network.providers:
            lines.append(
                f"  - {provider.name} ({provider.role}, {provider.confidence}% confidence): "
                f"`{provider.evidence}`"
            )
    if host.network.dns.truncated:
        lines.append("- DNS results truncated at the scan limit.")
    if host.network.addresses:
        lines.append("")
        lines.append("| DNS address | Routed prefix | Origin ASN (holder) | Registered holder | Network name | Geo-IP | Sources |")
        lines.append("|-------------|---------------|---------------------|-------------------|--------------|--------|---------|")
        for entry in host.network.addresses:
            asns = ", ".join(
                f"AS{asn}" + (f" ({_network_cell(entry.asn_holders[str(asn)])})"
                              if str(asn) in entry.asn_holders else "")
                for asn in entry.asns)
            geo = (", ".join(part for part in (entry.geo.city, entry.geo.country_code) if part)
                   if entry.geo else "—")
            lines.append(
                f"| {_network_cell(entry.address)} | {_network_cell(entry.prefix)} | "
                f"{asns or '—'} | {_network_cell(entry.registered_holder)} | "
                f"{_network_cell(entry.network_name)} | {_network_cell(geo)} | "
                f"{_network_cell(', '.join(entry.sources))} |"
            )
        if any(entry.geo for entry in host.network.addresses):
            lines.append("")
            lines.append("Geo-IP source: MaxMind GeoLite2 via RIPEstat. "
                         "This product includes GeoLite Data created by MaxMind, "
                         "available from https://www.maxmind.com.")
    else:
        lines.append("- No DNS addresses observed.")
    lines.append("")

    exposed_bundles = [bundle for bundle in host.bundles if bundle.has_sourcemap]
    if exposed_bundles:
        lines.append("**Source maps and saved evidence**")
        lines.append("")
        for bundle in exposed_bundles:
            lines.append(f"- Bundle: {safe_url(bundle.url) or bundle.url}")
            map_url = source_map_url(bundle.url)
            lines.append(f"  - Public map: {safe_url(map_url) or map_url}")
            if bundle.source_map_sources:
                lines.append(f"  - {bundle.source_map_sources} original sources listed")
            for label, artifact in (("Generated source", bundle.source_artifact),
                                    ("Source map", bundle.sourcemap_artifact)):
                if artifact:
                    lines.append(f"  - {label}: `{artifact.local_path}` "
                                 f"(SHA-256 `{artifact.sha256}`, sanitized, {artifact.bytes} bytes)")
            intel = bundle.source_map_intel
            if intel:
                lines.append("")
                lines.append(f"#### Source-map appendix — {_code_cell(bundle.url)}")
                lines.append("")
                lines.append(f"- {intel.total_sources} source paths; {intel.embedded_sources} "
                             "have embedded original content.")
                lines.append(f"- {intel.application_sources} application/non-dependency "
                             f"paths; {intel.dependency_sources} dependency paths "
                             "(classified from source paths).")
                lines.append("")
                lines.append("| Original source path | Class | Content embedded |")
                lines.append("|----------------------|-------|------------------|")
                for source in intel.sources:
                    lines.append(f"| {_code_cell(source.path)} | {source.kind} | "
                                 f"{'Yes' if source.embedded else 'No'} |")
                if intel.sources_omitted:
                    lines.append(f"| … {intel.sources_omitted} additional paths omitted "
                                 "at the inventory cap | — | — |")
                lines.append("")
                spec = intel.embedded_openapi
                if spec:
                    lines.append(f"**Embedded OpenAPI {spec.version} specification** "
                                 f"in {_code_cell(spec.source_path)}")
                    lines.append("")
                    lines.append(f"- {spec.path_count} path entries, "
                                 f"{spec.operation_count} HTTP operations, "
                                 f"{spec.schema_count} component schemas.")
                    lines.append("- Methods: " + ", ".join(
                        f"{method} {count}" for method, count in sorted(spec.methods.items())))
                    lines.append("")
                    lines.append("| Referenced API path | Methods described |")
                    lines.append("|---------------------|-------------------|")
                    for path in spec.paths:
                        lines.append(f"| {_code_cell(path.path)} | "
                                     f"{', '.join(path.methods) or '—'} |")
                    if spec.paths_omitted:
                        lines.append(f"| … {spec.paths_omitted} additional paths omitted "
                                     "at the inventory cap | — |")
                    lines.append("")
                    if spec.schema_names:
                        lines.append("Component schemas: " + ", ".join(
                            _code_cell(name) for name in spec.schema_names)
                            + (f", … {spec.schemas_omitted} omitted" if spec.schemas_omitted else "") + ".")
                        lines.append("")
                elif intel.referenced_api_paths:
                    lines.append("**API path references in embedded source**")
                    lines.append("")
                    lines.extend(f"- {_code_cell(path)}" for path in intel.referenced_api_paths)
                    if intel.routes_omitted:
                        lines.append(f"- … {intel.routes_omitted} additional paths omitted "
                                     "at the inventory cap")
                    lines.append("")
                lines.append("These paths are source references, not verified reachable "
                             "endpoints. This scan does not establish their authorization "
                             "behavior. Review against "
                             "[OWASP WSTG-INFO-05](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Web_Page_Content_for_Information_Leakage/) "
                             "and [WSTG-APIT-03](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/12-API_Testing/03-Excessive_Data_Exposure/).")
        lines.append("")

    # API surface
    lines.append("**API surface**")
    lines.append("")
    api = host.api_surface
    api_lines: list[str] = []
    if api.rest:
        eps = ", ".join(
            f"{e.path}" + (f" ({e.status})" if e.status is not None else "")
            for e in api.rest
        )
        api_lines.append(f"- REST: {eps}")
    if api.graphql and api.graphql.present:
        intro = "introspection OPEN" if api.graphql.introspection_open else "introspection closed"
        api_lines.append(f"- GraphQL: present, {intro} ({len(api.graphql.types)} types)")
    if api.openapi and api.openapi.present:
        api_lines.append(
            f"- OpenAPI/Swagger: exposed at {api.openapi.url or 'unknown'} "
            f"({len(api.openapi.endpoints)} endpoints)"
        )
    for bundle in host.bundles:
        intel = bundle.source_map_intel
        if intel and intel.embedded_openapi:
            spec = intel.embedded_openapi
            api_lines.append(
                f"- Embedded OpenAPI structure in source map: {spec.path_count} "
                f"referenced path entries, {spec.operation_count} described operations "
                "(not verified reachable)."
            )
    if api.wordpress and (api.wordpress.wp_json or api.wordpress.users_enumerable):
        wp_state = "users enumerable" if api.wordpress.users_enumerable else "wp-json present"
        api_lines.append(f"- WordPress: {wp_state}")
    lines.extend(api_lines if api_lines else ["- No REST/GraphQL/OpenAPI surface observed."])
    lines.append("")

    # Third parties
    lines.append("**Third parties**")
    lines.append("")
    if host.third_parties:
        lines.append("| Service | Category | Key/ID |")
        lines.append("|---------|----------|--------|")
        for tp in host.third_parties:
            lines.append(f"| {tp.name} | {tp.category} | {tp.key or '—'} |")
    else:
        lines.append("None identified.")
    lines.append("")

    # OPSEC findings
    lines.append("**OPSEC findings**")
    lines.append("")
    lines.append(_render_findings_block(host))

    return safe_text("\n".join(lines).rstrip() + "\n")


def _overview(result: ScanResult) -> str:
    n_hosts = len(result.hosts)
    live = sum(1 for h in result.hosts if h.reachable)
    n_crit = len(result.aggregate.critical_findings)
    return (
        f"Passive architecture teardown of **{result.root_domain}**. "
        f"{n_hosts} host(s) examined, {live} reachable. "
        f"{len(result.aggregate.third_parties_union)} distinct third-party service(s) "
        f"and {n_crit} critical OPSEC finding(s) across the estate. "
        "Passive reconnaissance only — no authenticated access or exploitation."
    )


def _aggregate_tech_table(result: ScanResult) -> str:
    agg = result.aggregate.tech_stack_union
    lines = ["| Category | Technologies |", "|----------|--------------|"]
    order = ["hosting", "servers", "frameworks", "cms"]
    labels = {
        "hosting": "Hosting / CDN",
        "servers": "Web server / runtime",
        "frameworks": "Frameworks",
        "cms": "CMS",
    }
    seen = set()
    for key in order + [k for k in agg if k not in order]:
        if key in seen:
            continue
        seen.add(key)
        vals = agg.get(key) or []
        lines.append(f"| **{labels.get(key, key)}** | {', '.join(vals) if vals else '—'} |")
    return "\n".join(lines)


def _tldr(result: ScanResult) -> str:
    live = sum(host.reachable for host in result.hosts)
    providers = sorted(set(result.aggregate.tech_stack_union.get("hosting", [])))
    frameworks = result.aggregate.tech_stack_union.get("frameworks", [])
    mapped = [bundle.source_map_intel for host in result.hosts for bundle in host.bundles
              if bundle.source_map_intel]
    embedded_maps = sum(bool(intel.embedded_sources) for intel in mapped)
    spec_count = sum(bool(intel.embedded_openapi) for intel in mapped)
    counts = {severity: sum(f.severity == severity for host in result.hosts
                             for f in host.opsec_findings) for severity in Severity}
    return "\n".join([
        f"- {live} of {len(result.hosts)} hosts reachable.",
        f"- Observed hosting/routing: {', '.join(providers) if providers else 'none identified'}.",
        f"- Frameworks: {', '.join(frameworks) if frameworks else 'none identified'}.",
        f"- Source maps: {embedded_maps} with embedded source; "
        f"{spec_count} with embedded OpenAPI structure.",
        "- Findings: " + ", ".join(f"{counts[s]} {s.value}" for s in Severity) + ".",
    ])


_ACTIONS = {
    "GraphQL introspection enabled": "Review whether public GraphQL introspection is intended",
    "WordPress user enumeration open": "Review public WordPress user enumeration",
    "OpenAPI/Swagger specification publicly exposed": "Review whether the public API specification is intended",
    "Source map exposed on first-party bundle": "Review the exposed first-party source map and remove it from production if unintended",
    "Server / framework version disclosure": "Review server and framework version disclosure",
    "CSP leaks internal/infrastructure hostnames": "Review internal hostnames in the CSP",
    "Missing HSTS on HTTPS site": "Review HSTS for this HTTPS host",
    "Missing X-Frame-Options": "Review clickjacking protection",
    "Missing X-Content-Type-Options": "Review X-Content-Type-Options",
}


def _todo(result: ScanResult) -> str:
    grouped: dict[str, list[tuple[str, str | None]]] = {}
    for host in result.hosts:
        for finding in host.opsec_findings:
            if finding.severity not in {Severity.CRITICAL, Severity.MEDIUM, Severity.LOW}:
                continue
            if finding.title not in _ACTIONS and not finding.title.startswith("Live secret exposed:"):
                continue
            grouped.setdefault(finding.title, []).append((host.host, finding.evidence_url))
    if not grouped:
        return "- No actionable findings identified."
    lines = []
    for title in sorted(grouped):
        action = (_ACTIONS.get(title) or "Rotate or revoke the exposed secret and review its use")
        hosts = sorted({name for name, _url in grouped[title]})
        urls = sorted({safe_url(url) for _name, url in grouped[title] if url and safe_url(url)})
        evidence = f" Evidence: {', '.join(urls)}." if urls else ""
        lines.append(f"- [ ] {action} — {', '.join(hosts)}.{evidence}")
    return "\n".join(lines)


def render_markdown(result: ScanResult) -> str:
    """Render the full vault-compatible teardown markdown document."""
    parts: list[str] = []
    parts.append(_frontmatter(result))
    parts.append("")
    parts.append(f"# {result.root_domain} — Architecture Teardown")
    parts.append("")
    parts.append("## TL;DR")
    parts.append("")
    parts.append(_tldr(result))
    parts.append("")
    parts.append("## Overview")
    parts.append("")
    parts.append(_overview(result))
    parts.append("")

    # Subdomain / host inventory
    parts.append("## Subdomain / Host Inventory")
    parts.append("")
    parts.append("| Host | Reachable | Framework / CMS | # Findings |")
    parts.append("|------|-----------|-----------------|------------|")
    for host in result.hosts:
        reachable = "✅" if host.reachable else "❌"
        parts.append(
            f"| {host.host or host.target or '—'} | {reachable} | "
            f"{_host_framework_cms(host)} | {len(host.opsec_findings or [])} |"
        )
    parts.append("")

    # Aggregate tech stack
    parts.append("## Aggregate Tech Stack")
    parts.append("")
    parts.append(_aggregate_tech_table(result))
    parts.append("")

    # Third-party dependencies
    parts.append("## Third-Party Dependencies")
    parts.append("")
    if result.aggregate.third_parties_union:
        for name in result.aggregate.third_parties_union:
            parts.append(f"- {name}")
    else:
        parts.append("None identified across the estate.")
    parts.append("")

    # Per-host sections
    parts.append("## Per-Host Detail")
    parts.append("")
    for host in result.hosts:
        parts.append(render_host_markdown(host))
        parts.append("")

    # Key findings
    parts.append("## Key Findings")
    parts.append("")
    crit = result.aggregate.critical_findings
    if crit:
        for f in crit:
            parts.append(f"- 🔴 **{f.title}** — {f.detail}")
    else:
        parts.append("- No critical findings across the estate.")
    parts.append("")

    parts.append("## To Do")
    parts.append("")
    parts.append(_todo(result))
    parts.append("")

    return safe_text("\n".join(parts).rstrip() + "\n")


def write_outputs(result: ScanResult, out_dir: str, basename: str) -> dict[str, str]:
    """Write <out_dir>/<basename>-teardown.{json,md}. Returns the two paths."""
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, f"{basename}-teardown.json")
    md_path = os.path.join(out_dir, f"{basename}-teardown.md")

    with os.fdopen(os.open(json_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600),
                   "w", encoding="utf-8") as fh:
        os.fchmod(fh.fileno(), 0o600)
        fh.write(json.dumps(to_dict(result), indent=2))
    with os.fdopen(os.open(md_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600),
                   "w", encoding="utf-8") as fh:
        os.fchmod(fh.fileno(), 0o600)
        fh.write(render_markdown(result))

    return {"json": json_path, "md": md_path}
