"""Tests for teardown.render — markdown layout, frontmatter, and file outputs."""

from __future__ import annotations

import datetime
import json

from teardown.analyze import analyze_host, build_aggregate
from teardown.render import render_host_markdown, render_markdown, write_outputs
from teardown.models import (
    ApiSurface,
    Bundle,
    CmsInfo,
    GraphQLInfo,
    HostTeardown,
    HttpInfo,
    OpenApiInfo,
    ScanResult,
    SecretLeak,
    ThirdParty,
    WordPressInfo,
    HostingEvidence,
    ArtifactRef,
)


def _build_result() -> ScanResult:
    host = HostTeardown(
        target="https://app.example.com",
        host="app.example.com",
        reachable=True,
        http=HttpInfo(
            status=200,
            final_url="https://app.example.com",
            server="nginx/1.18.0",
            powered_by="PHP/8.1",
            security_headers={},  # missing everything -> medium + low findings
        ),
        frameworks=["Next.js"],
        cms=CmsInfo(type="wordpress", version="6.4"),
        bundles=[Bundle(url="https://app.example.com/app.js", has_sourcemap=True)],
        api_surface=ApiSurface(
            graphql=GraphQLInfo(present=True, introspection_open=True, types=["User"]),
            openapi=OpenApiInfo(present=True, url="https://app.example.com/openapi.json",
                                endpoints=["/api/v1/users"]),
            wordpress=WordPressInfo(wp_json=True, users_enumerable=True, users=["admin"]),
        ),
        third_parties=[
            ThirdParty(name="segment", category="analytics", key="wk_live_abc"),
            ThirdParty(name="stripe", category="payments"),
        ],
        secret_leaks=[
            SecretLeak(type="stripe_pk_live", value_prefix="pk_live_51Hx",
                       source_url="https://app.example.com/app.js"),
        ],
    )
    host.opsec_findings = analyze_host(host)

    # a second, mostly-clean unreachable host
    host2 = HostTeardown(
        target="https://api.example.com",
        host="api.example.com",
        reachable=False,
        http=HttpInfo(server="cloudflare", cache={"cf_cache_status": "HIT"}),
    )
    host2.opsec_findings = analyze_host(host2)

    result = ScanResult(root_domain="example.com", hosts=[host, host2])
    result.aggregate = build_aggregate(result.hosts)
    return result


def test_frontmatter_has_required_fields():
    md = render_markdown(_build_result())
    assert md.startswith("---\n")
    fm = md.split("---", 2)[1]
    today = datetime.date.today().isoformat()
    assert "type: intelligence" in fm
    assert "category: teardown" in fm
    assert "status: active" in fm
    assert f"created: {today}" in fm
    assert f"updated: {today}" in fm
    assert f"last-updated: {today}" in fm
    assert "url:" in fm
    assert "root_domain:" in fm
    assert "- teardown" in fm


def test_all_top_level_sections_present():
    md = render_markdown(_build_result())
    assert "# example.com — Architecture Teardown" in md
    assert "## Overview" in md
    assert "## Subdomain / Host Inventory" in md
    assert "## Aggregate Tech Stack" in md
    assert "## Third-Party Dependencies" in md
    assert "## Per-Host Detail" in md
    assert "## Key Findings" in md


def test_tldr_and_action_list_are_deterministic():
    result = _build_result()
    result.hosts[0].network.providers = [
        HostingEvidence("Render", "platform", 95, "app.example.com.onrender.com"),
    ]
    result.aggregate = build_aggregate(result.hosts)
    md = render_markdown(result)
    assert md.index("## TL;DR") < md.index("## Overview")
    assert "1 of 2 hosts reachable" in md
    assert "Render" in md.split("## TL;DR", 1)[1].split("## Overview", 1)[0]
    todo = md.split("## To Do", 1)[1]
    assert "app.example.com" in todo
    assert "Review the exposed first-party source map" in todo
    assert "Analytics / tracking keys visible" not in todo
    assert "Framework / CMS fingerprintable" not in todo
    assert md.rstrip().endswith(todo.rstrip())


def test_host_exposes_hosting_evidence_and_artifact_paths():
    result = _build_result()
    host = result.hosts[0]
    host.network.providers = [HostingEvidence("Porter", "platform", 95, "web.onporter.run")]
    host.bundles[0].source_map_sources = 3
    host.bundles[0].source_artifact = ArtifactRef("/tmp/abc.js", "a" * 64, 100)
    host.bundles[0].sourcemap_artifact = ArtifactRef("/tmp/def.map", "b" * 64, 200)
    section = render_host_markdown(host)
    assert "Porter" in section and "web.onporter.run" in section
    assert "/tmp/abc.js" in section and "/tmp/def.map" in section
    assert "3 original sources" in section


def test_map_link_preserves_query_position():
    host = _build_result().hosts[0]
    host.bundles[0].url = "https://app.example.com/app.js?v=1"
    section = render_host_markdown(host)
    assert "https://app.example.com/app.js.map?v=1" in section


def test_inventory_table_lists_hosts_and_counts():
    md = render_markdown(_build_result())
    assert "| Host | Reachable | Framework / CMS | # Findings |" in md
    assert "app.example.com" in md
    assert "api.example.com" in md
    # reachable emoji markers
    assert "✅" in md
    assert "❌" in md


def test_emoji_severity_buckets_present():
    md = render_markdown(_build_result())
    assert "🔴 Critical" in md
    assert "🟡 Medium" in md
    assert "🟢 Low" in md


def test_redacted_secret_prefix_in_markdown_not_full_secret():
    md = render_markdown(_build_result())
    assert "pk_live_51Hx" in md
    # ensure we only have the redacted prefix, nothing longer masquerading as a full key
    assert "pk_live_51Hx0000" not in md


def test_critical_findings_in_key_findings():
    md = render_markdown(_build_result())
    key_section = md.split("## Key Findings", 1)[1]
    assert "GraphQL introspection" in key_section or "OpenAPI" in key_section
    assert "🔴" in key_section


def test_render_host_markdown_standalone():
    result = _build_result()
    section = render_host_markdown(result.hosts[0])
    assert section.startswith("### app.example.com")
    assert "**Tech stack**" in section
    assert "**API surface**" in section
    assert "**Third parties**" in section
    assert "**OPSEC findings**" in section
    assert "🔴 Critical" in section


def test_write_outputs_writes_both_files(tmp_path):
    result = _build_result()
    paths = write_outputs(result, str(tmp_path), "example-com")
    assert paths["json"].endswith("example-com-teardown.json")
    assert paths["md"].endswith("example-com-teardown.md")

    import os
    assert os.path.exists(paths["json"])
    assert os.path.exists(paths["md"])

    # JSON round-trips
    with open(paths["json"], encoding="utf-8") as fh:
        data = json.loads(fh.read())
    assert data["root_domain"] == "example.com"
    assert data["schema_version"]
    assert len(data["hosts"]) == 2
    assert data["aggregate"]["third_parties_union"] == ["segment", "stripe"]

    # markdown file contains the document heading
    with open(paths["md"], encoding="utf-8") as fh:
        md = fh.read()
    assert "# example.com — Architecture Teardown" in md


def test_write_outputs_creates_missing_dir(tmp_path):
    nested = tmp_path / "sub" / "dir"
    result = _build_result()
    paths = write_outputs(result, str(nested), "x")
    import os
    assert os.path.isdir(str(nested))
    assert os.path.exists(paths["json"])
