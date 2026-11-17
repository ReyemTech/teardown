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
from .safety import safe_text, safe_url

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


def render_host_markdown(host: HostTeardown) -> str:
    """The single-host section (reused by render_markdown and usable standalone)."""
    lines: list[str] = [f"### {host.host or host.target or 'host'}", ""]

    reach = "reachable" if host.reachable else "unreachable"
    bits = [reach]
    if host.http.status is not None:
        bits.append(f"HTTP {host.http.status}")
    if host.http.final_url:
        bits.append(safe_url(host.http.final_url) or "")
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


def render_markdown(result: ScanResult) -> str:
    """Render the full vault-compatible teardown markdown document."""
    parts: list[str] = []
    parts.append(_frontmatter(result))
    parts.append("")
    parts.append(f"# {result.root_domain} — Architecture Teardown")
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

    return safe_text("\n".join(parts).rstrip() + "\n")


def write_outputs(result: ScanResult, out_dir: str, basename: str) -> dict[str, str]:
    """Write <out_dir>/<basename>-teardown.{json,md}. Returns the two paths."""
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, f"{basename}-teardown.json")
    md_path = os.path.join(out_dir, f"{basename}-teardown.md")

    with open(json_path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(to_dict(result), indent=2))
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(render_markdown(result))

    return {"json": json_path, "md": md_path}
