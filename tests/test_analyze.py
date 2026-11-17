"""Tests for teardown.analyze — OPSEC rule firing and cross-host aggregation."""

from __future__ import annotations

from teardown.analyze import analyze_host, build_aggregate
from teardown.models import (
    ApiSurface,
    Bundle,
    CmsInfo,
    CspInfo,
    GraphQLInfo,
    HostTeardown,
    HttpInfo,
    OpenApiInfo,
    OpsecFinding,
    SecretLeak,
    Severity,
    ThirdParty,
    WordPressInfo,
)


def _clean_host(**overrides) -> HostTeardown:
    """A fully-hardened https host that should trip NO findings by default."""
    host = HostTeardown(
        target="https://app.example.com",
        host="app.example.com",
        reachable=True,
        http=HttpInfo(
            status=200,
            final_url="https://app.example.com",
            server="cloudflare",          # no version
            powered_by=None,
            security_headers={
                "hsts": "max-age=63072000",
                "x_frame_options": "DENY",
                "x_content_type_options": "nosniff",
            },
        ),
    )
    for k, v in overrides.items():
        setattr(host, k, v)
    return host


def _titles(findings: list[OpsecFinding]) -> set[str]:
    return {f.title for f in findings}


def _by_sev(findings: list[OpsecFinding], sev: Severity) -> list[OpsecFinding]:
    return [f for f in findings if f.severity == sev]


# --------------------------------------------------------------------------
# Clean baseline
# --------------------------------------------------------------------------

def test_clean_host_has_no_findings():
    findings = analyze_host(_clean_host())
    assert findings == []


def test_analyze_does_not_mutate_host():
    host = _clean_host()
    analyze_host(host)
    assert host.opsec_findings == []


# --------------------------------------------------------------------------
# CRITICAL rules
# --------------------------------------------------------------------------

def test_graphql_introspection_fires_critical():
    host = _clean_host(
        api_surface=ApiSurface(
            graphql=GraphQLInfo(present=True, introspection_open=True, types=["User", "Order"])
        )
    )
    findings = analyze_host(host)
    crit = _by_sev(findings, Severity.CRITICAL)
    assert any("GraphQL introspection" in f.title for f in crit)
    assert any(f.evidence_url and f.evidence_url.endswith("/graphql") for f in crit)


def test_graphql_introspection_closed_does_not_fire():
    host = _clean_host(
        api_surface=ApiSurface(graphql=GraphQLInfo(present=True, introspection_open=False))
    )
    findings = analyze_host(host)
    assert not any("GraphQL" in f.title for f in findings)


def test_wordpress_user_enumeration_fires_critical():
    host = _clean_host(
        api_surface=ApiSurface(
            wordpress=WordPressInfo(wp_json=True, users_enumerable=True, users=["admin", "editor"])
        )
    )
    crit = _by_sev(analyze_host(host), Severity.CRITICAL)
    f = next(f for f in crit if "WordPress" in f.title)
    assert "admin" in f.detail


def test_wordpress_wp_json_without_enum_does_not_fire_critical():
    host = _clean_host(
        api_surface=ApiSurface(wordpress=WordPressInfo(wp_json=True, users_enumerable=False))
    )
    assert not _by_sev(analyze_host(host), Severity.CRITICAL)


def test_openapi_exposed_fires_critical():
    host = _clean_host(
        api_surface=ApiSurface(
            openapi=OpenApiInfo(
                present=True,
                url="https://app.example.com/openapi.json",
                endpoints=["/api/v1/users", "/api/v1/orders"],
            )
        )
    )
    crit = _by_sev(analyze_host(host), Severity.CRITICAL)
    f = next(f for f in crit if "OpenAPI" in f.title)
    assert f.evidence_url == "https://app.example.com/openapi.json"


def test_openapi_absent_does_not_fire():
    host = _clean_host(api_surface=ApiSurface(openapi=OpenApiInfo(present=False)))
    assert not any("OpenAPI" in f.title for f in analyze_host(host))


def test_live_secret_leak_fires_critical():
    host = _clean_host(
        secret_leaks=[
            SecretLeak(
                type="stripe_pk_live",
                value_prefix="pk_live_51Hx",
                source_url="https://app.example.com/main.js",
            )
        ]
    )
    crit = _by_sev(analyze_host(host), Severity.CRITICAL)
    f = next(f for f in crit if "Live secret" in f.title)
    # redacted prefix is surfaced, not a full secret
    assert "pk_live_51Hx" in f.detail


def test_test_mode_secret_does_not_fire_critical():
    host = _clean_host(
        secret_leaks=[SecretLeak(type="stripe_pk_test", value_prefix="pk_test_51Hx")]
    )
    assert not _by_sev(analyze_host(host), Severity.CRITICAL)


def test_first_party_sourcemap_fires_medium():
    host = _clean_host(
        bundles=[Bundle(url="https://app.example.com/app.js", has_sourcemap=True)]
    )
    med = _by_sev(analyze_host(host), Severity.MEDIUM)
    f = next(f for f in med if "Source map" in f.title)
    assert f.evidence_url == "https://app.example.com/app.js.map"
    # It must NOT sit in the critical bucket with credential/data leaks.
    assert not any("Source map" in f.title
                   for f in _by_sev(analyze_host(host), Severity.CRITICAL))


def test_third_party_sourcemap_does_not_fire():
    # A third-party CDN publishing a map for its own SDK is not this host's exposure.
    host = _clean_host(
        bundles=[Bundle(url="https://browser.sentry-cdn.com/9.47/bundle.min.js",
                        has_sourcemap=True)]
    )
    assert not any("Source map" in f.title for f in analyze_host(host))


def test_bundle_without_sourcemap_does_not_fire():
    host = _clean_host(
        bundles=[Bundle(url="https://app.example.com/app.js", has_sourcemap=False)]
    )
    assert not any("Source map" in f.title for f in analyze_host(host))


# --------------------------------------------------------------------------
# MEDIUM rules
# --------------------------------------------------------------------------

def test_version_disclosure_fires_medium():
    host = _clean_host(http=HttpInfo(
        status=200, final_url="https://app.example.com",
        server="nginx/1.18.0", powered_by="PHP/8.1",
        security_headers={"hsts": "x", "x_frame_options": "DENY", "x_content_type_options": "nosniff"},
    ))
    med = _by_sev(analyze_host(host), Severity.MEDIUM)
    f = next(f for f in med if "version disclosure" in f.title)
    assert "nginx/1.18.0" in f.detail and "PHP/8.1" in f.detail


def test_server_without_version_does_not_fire():
    # 'cloudflare' / 'Apache' with no version number
    host = _clean_host(http=HttpInfo(
        status=200, final_url="https://app.example.com",
        server="Apache", powered_by="ASP.NET",
        security_headers={"hsts": "x", "x_frame_options": "DENY", "x_content_type_options": "nosniff"},
    ))
    assert not any("version disclosure" in f.title for f in analyze_host(host))


def test_csp_internal_hostname_fires_medium():
    host = _clean_host(csp=CspInfo(
        present=True,
        directives={"connect-src": ["'self'", "https://api.internal.example.com", "https://10.0.0.5"]},
        third_party_domains=["api.internal.example.com", "10.0.0.5"],
    ))
    med = _by_sev(analyze_host(host), Severity.MEDIUM)
    f = next(f for f in med if "CSP leaks internal" in f.title)
    assert "api.internal.example.com" in f.detail


def test_csp_public_only_does_not_fire():
    host = _clean_host(csp=CspInfo(
        present=True,
        directives={"script-src": ["'self'", "https://js.stripe.com"]},
        third_party_domains=["js.stripe.com"],
    ))
    assert not any("CSP leaks" in f.title for f in analyze_host(host))


def test_missing_hsts_on_https_fires_medium():
    host = _clean_host(http=HttpInfo(
        status=200, final_url="https://app.example.com", server="cloudflare",
        security_headers={"x_frame_options": "DENY", "x_content_type_options": "nosniff"},
    ))
    med = _by_sev(analyze_host(host), Severity.MEDIUM)
    assert any("Missing HSTS" in f.title for f in med)


def test_missing_hsts_on_http_does_not_fire():
    host = _clean_host(
        target="http://app.example.com",
        http=HttpInfo(
            status=200, final_url="http://app.example.com", server="cloudflare",
            security_headers={"x_frame_options": "DENY", "x_content_type_options": "nosniff"},
        ),
    )
    assert not any("Missing HSTS" in f.title for f in analyze_host(host))


def test_hsts_via_raw_header_does_not_fire():
    host = _clean_host(http=HttpInfo(
        status=200, final_url="https://app.example.com", server="cloudflare",
        security_headers={"x_frame_options": "DENY", "x_content_type_options": "nosniff"},
        all_headers={"Strict-Transport-Security": "max-age=1"},
    ))
    assert not any("Missing HSTS" in f.title for f in analyze_host(host))


# --------------------------------------------------------------------------
# LOW rules
# --------------------------------------------------------------------------

def test_analytics_key_fires_low():
    host = _clean_host(third_parties=[
        ThirdParty(name="segment", category="analytics", key="wk_abc123"),
    ])
    low = _by_sev(analyze_host(host), Severity.LOW)
    f = next(f for f in low if "Analytics" in f.title)
    assert "segment" in f.detail and "wk_abc123" in f.detail


def test_third_party_without_key_does_not_fire_analytics():
    host = _clean_host(third_parties=[ThirdParty(name="segment", category="analytics", key=None)])
    assert not any("Analytics" in f.title for f in analyze_host(host))


def test_framework_fingerprint_fires_low():
    host = _clean_host(frameworks=["Next.js"], cms=CmsInfo(type="wordpress", version="6.4"))
    low = _by_sev(analyze_host(host), Severity.LOW)
    f = next(f for f in low if "fingerprintable" in f.title)
    assert "Next.js" in f.detail and "wordpress 6.4" in f.detail


def test_missing_frame_and_nosniff_fire_low():
    host = _clean_host(http=HttpInfo(
        status=200, final_url="https://app.example.com", server="cloudflare",
        security_headers={"hsts": "x"},  # missing both frame + nosniff
    ))
    titles = _titles(analyze_host(host))
    assert "Missing X-Frame-Options" in titles
    assert "Missing X-Content-Type-Options" in titles


def test_present_frame_and_nosniff_do_not_fire():
    findings = analyze_host(_clean_host())
    titles = _titles(findings)
    assert "Missing X-Frame-Options" not in titles
    assert "Missing X-Content-Type-Options" not in titles


# --------------------------------------------------------------------------
# INFO
# --------------------------------------------------------------------------

def test_third_parties_enumerated_info():
    host = _clean_host(third_parties=[
        ThirdParty(name="stripe", category="payments"),
        ThirdParty(name="sentry", category="error-tracking"),
    ])
    info = _by_sev(analyze_host(host), Severity.INFO)
    f = next(f for f in info if "enumerated" in f.title)
    assert "stripe" in f.detail and "sentry" in f.detail


# --------------------------------------------------------------------------
# Defensive: empty / unreachable host
# --------------------------------------------------------------------------

def test_empty_host_is_handled():
    host = HostTeardown(target="http://down.example.com", host="down.example.com", reachable=False)
    # http (no https) + no headers => frame + nosniff missing fire, nothing explodes
    findings = analyze_host(host)
    assert isinstance(findings, list)
    assert not _by_sev(findings, Severity.CRITICAL)


# --------------------------------------------------------------------------
# build_aggregate
# --------------------------------------------------------------------------

def test_build_aggregate_unions_and_collects_criticals():
    h1 = _clean_host(
        host="a.example.com",
        frameworks=["Next.js"],
        cms=CmsInfo(type="wordpress"),
        http=HttpInfo(server="nginx/1.18.0", powered_by="PHP/8.1",
                      cache={"cf_cache_status": "HIT"}),
        third_parties=[ThirdParty(name="segment"), ThirdParty(name="stripe")],
    )
    h2 = _clean_host(
        host="b.example.com",
        frameworks=["Next.js", "React"],
        http=HttpInfo(server="cloudflare", cache={"x_vercel_cache": "MISS"}),
        third_parties=[ThirdParty(name="sentry"), ThirdParty(name="stripe")],
    )
    # assign findings the way the caller would
    h1.opsec_findings = analyze_host(h1)
    h2.opsec_findings = analyze_host(h2)
    h1.opsec_findings.append(OpsecFinding(Severity.CRITICAL, "Manual crit", "detail"))

    agg = build_aggregate([h1, h2])

    assert agg.tech_stack_union["frameworks"] == ["Next.js", "React"]
    assert agg.tech_stack_union["cms"] == ["wordpress"]
    assert "nginx/1.18.0" in agg.tech_stack_union["servers"]
    assert "cloudflare" in agg.tech_stack_union["servers"]
    # hosting inferred from cache headers
    assert "Cloudflare" in agg.tech_stack_union["hosting"]
    assert "Vercel" in agg.tech_stack_union["hosting"]
    # third parties merged + sorted + unique
    assert agg.third_parties_union == ["segment", "sentry", "stripe"]
    # at least the manually-added critical is collected
    assert any(f.title == "Manual crit" for f in agg.critical_findings)
    assert all(f.severity == Severity.CRITICAL for f in agg.critical_findings)


def test_build_aggregate_empty_is_safe():
    agg = build_aggregate([])
    assert agg.tech_stack_union == {"frameworks": [], "cms": [], "servers": [], "hosting": []}
    assert agg.third_parties_union == []
    assert agg.critical_findings == []
