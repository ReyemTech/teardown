"""HTML / JS fingerprinting collectors.

Ports Steps 2 & 4 of the teardown agent: framework + CMS detection, bundle
extraction, third-party service fingerprinting, secret-leak scanning, and
(the one network-touching function) bundle enrichment via an injected Fetcher.

All parsers are PURE except `enrich_bundles`, which takes a Fetcher and never
raises (the Fetcher already swallows network errors).
"""

from __future__ import annotations

import re
import json
from urllib.parse import urljoin, urlsplit

from teardown.artifacts import ArtifactStore
from teardown.http_client import Fetcher
from teardown.models import Bundle, CmsInfo, SecretLeak, ThirdParty
from teardown.safety import redact_key, registrable_domain, safe_url, source_map_url

# --------------------------------------------------------------------------- #
# Framework detection
# --------------------------------------------------------------------------- #

def detect_frameworks(html: str) -> list[str]:
    """Compatibility view of data-driven framework detections from HTML."""
    from teardown.fingerprints import detect_technologies, framework_names, load_fingerprints

    framework_categories = {"js-framework", "backend-framework", "ui-framework", "static-site-generator", "build-tool"}
    definitions = [fp for fp in load_fingerprints()
                   if framework_categories.intersection(fp.get("categories", []))]
    return framework_names(detect_technologies(html, {}, "", definitions))


# --------------------------------------------------------------------------- #
# CMS detection
# --------------------------------------------------------------------------- #

_WP_PLUGIN_RE = re.compile(r"wp-content/plugins/([^/\"'?\s>]+)", re.IGNORECASE)
_WP_THEME_RE = re.compile(r"wp-content/themes/([^/\"'?\s>]+)", re.IGNORECASE)
_GENERATOR_RE = re.compile(
    r"<meta[^>]+name=[\"']generator[\"'][^>]*content=[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
_WP_VERSION_RE = re.compile(r"wordpress\s+([0-9][0-9.]*)", re.IGNORECASE)


def detect_cms(html: str, headers: dict[str, str]) -> CmsInfo:
    """Detect CMS/platform. WordPress gets plugin/theme/version extraction."""
    text = html or ""
    low = text.lower()
    hdrs = {k.lower(): (v or "") for k, v in (headers or {}).items()}
    hdr_blob = " ".join(f"{k}: {v}" for k, v in hdrs.items()).lower()

    generator = ""
    m = _GENERATOR_RE.search(text)
    if m:
        generator = m.group(1)
    gen_low = generator.lower()

    # WordPress -------------------------------------------------------------
    if (
        "wp-content" in low
        or "wp-includes" in low
        or "wordpress" in gen_low
        or "wp-json" in hdr_blob
    ):
        plugins = sorted({p.lower() for p in _WP_PLUGIN_RE.findall(text)})
        themes = sorted({t.lower() for t in _WP_THEME_RE.findall(text)})
        version = None
        vm = _WP_VERSION_RE.search(generator)
        if vm:
            version = vm.group(1)
        return CmsInfo(
            type="wordpress", version=version, plugins=plugins, themes=themes
        )

    # Drupal ---------------------------------------------------------------
    if (
        "drupal" in gen_low
        or "x-drupal-cache" in hdrs
        or "x-generator" in hdrs and "drupal" in hdrs.get("x-generator", "").lower()
        or "/sites/default/files" in low
        or "drupal.settings" in low
    ):
        version = None
        dm = re.search(r"drupal\s+([0-9][0-9.]*)", generator, re.IGNORECASE)
        if dm:
            version = dm.group(1)
        return CmsInfo(type="drupal", version=version)

    # Shopify --------------------------------------------------------------
    if (
        "cdn.shopify.com" in low
        or "shopify" in gen_low
        or "x-shopify-stage" in hdrs
        or "x-shopid" in hdrs
        or "shopify-features" in low
    ):
        return CmsInfo(type="shopify")

    # Wix ------------------------------------------------------------------
    if (
        "static.parastorage.com" in low
        or "wix.com" in low
        or "wix-" in gen_low
        or "x-wix-request-id" in hdrs
        or any(k.startswith("x-wix") for k in hdrs)
    ):
        return CmsInfo(type="wix")

    # Squarespace ----------------------------------------------------------
    if (
        "squarespace" in low
        or "static1.squarespace.com" in low
        or "squarespace" in hdr_blob
    ):
        return CmsInfo(type="squarespace")

    # Webflow --------------------------------------------------------------
    if (
        "webflow" in gen_low
        or "assets.website-files.com" in low
        or "assets-global.website-files.com" in low
        or "data-wf-site" in low
        or "data-wf-page" in low
    ):
        return CmsInfo(type="webflow")

    return CmsInfo()


# --------------------------------------------------------------------------- #
# Bundle extraction
# --------------------------------------------------------------------------- #

_SCRIPT_SRC_RE = re.compile(
    r"<script\b[^>]*\bsrc=[\"']([^\"']+)[\"']", re.IGNORECASE
)
_LINK_TAG_RE = re.compile(r"<link\b[^>]*>", re.IGNORECASE)
_HREF_RE = re.compile(r"\bhref=[\"']([^\"']+)[\"']", re.IGNORECASE)
_REL_RE = re.compile(r"\brel=[\"']([^\"']+)[\"']", re.IGNORECASE)


def extract_bundles(html: str, base_url: str) -> list[Bundle]:
    """Collect <script src> (js) and <link rel=stylesheet> (css), URLs resolved."""
    text = html or ""
    bundles: list[Bundle] = []
    seen: set[tuple[str, str]] = set()

    def _add(raw_url: str, kind: str) -> None:
        resolved = safe_url(urljoin(base_url, raw_url.strip())) or ""
        key = (kind, resolved)
        if resolved and key not in seen:
            seen.add(key)
            bundles.append(Bundle(url=resolved, type=kind))

    for src in _SCRIPT_SRC_RE.findall(text):
        _add(src, "js")

    for tag in _LINK_TAG_RE.findall(text):
        rel = _REL_RE.search(tag)
        if not rel or "stylesheet" not in rel.group(1).lower():
            continue
        href = _HREF_RE.search(tag)
        if href:
            _add(href.group(1), "css")

    return bundles


# --------------------------------------------------------------------------- #
# Third-party service fingerprinting
# --------------------------------------------------------------------------- #

# name, category, presence-patterns (case-insensitive substrings), optional
# key-extraction regex.
_THIRD_PARTY_SIGNATURES: list[tuple[str, str, tuple[str, ...], re.Pattern | None]] = [
    (
        "segment",
        "analytics",
        ("cdn.segment.com", "analytics.load(", "segment.io"),
        re.compile(r"analytics\.load\(\s*[\"']([A-Za-z0-9]{8,})[\"']"),
    ),
    (
        "google-analytics",
        "analytics",
        ("googletagmanager.com", "google-analytics.com", "gtag(", "G-"),
        re.compile(r"\b(G-[A-Z0-9]{6,})\b"),
    ),
    (
        "posthog",
        "analytics",
        ("posthog", "phc_"),
        re.compile(r"\b(phc_[A-Za-z0-9]{16,})\b"),
    ),
    (
        "sentry",
        "error-tracking",
        ("sentry", "@sentry", "ingest.sentry.io"),
        re.compile(r"(https://[0-9a-f]+@[A-Za-z0-9.\-]*sentry\.io/\d+)", re.IGNORECASE),
    ),
    (
        "stripe",
        "payments",
        ("js.stripe.com", "stripe", "pk_live_", "pk_test_"),
        re.compile(r"\b(pk_(?:live|test)_[A-Za-z0-9]{8,})\b"),
    ),
    (
        "clerk",
        "auth",
        ("clerk.", "@clerk", "clerk-js", "clerk.accounts"),
        re.compile(r"(clerk\.[A-Za-z0-9.\-]+)", re.IGNORECASE),
    ),
    (
        "auth0",
        "auth",
        ("auth0", ".auth0.com"),
        re.compile(r"([A-Za-z0-9\-]+\.auth0\.com)", re.IGNORECASE),
    ),
    (
        "firebase",
        "backend",
        ("firebaseapp.com", "firebaseio.com", "firebase"),
        re.compile(r"\b(AIza[0-9A-Za-z_\-]{20,})\b"),
    ),
    (
        "supabase",
        "backend",
        ("supabase.co", "supabase"),
        re.compile(r"([A-Za-z0-9]+\.supabase\.co)", re.IGNORECASE),
    ),
    (
        "mixpanel",
        "analytics",
        ("mixpanel", "cdn.mxpnl.com"),
        None,
    ),
    (
        "amplitude",
        "analytics",
        ("amplitude", "api.amplitude.com", "cdn.amplitude.com"),
        None,
    ),
    (
        "hotjar",
        "analytics",
        ("hotjar", "static.hotjar.com"),
        re.compile(r"hjid\s*[:=]\s*(\d{5,})"),
    ),
    (
        "intercom",
        "support",
        ("intercom", "widget.intercom.io"),
        re.compile(r"app_id[\"']?\s*[:=]\s*[\"']([A-Za-z0-9]{6,})[\"']"),
    ),
    (
        "hubspot",
        "marketing",
        ("hubspot", "js.hs-scripts.com", "hs-analytics"),
        re.compile(r"hs-scripts\.com/(\d{4,})"),
    ),
    (
        "datadog",
        "monitoring",
        ("datadoghq", "datadog-rum", "datadog"),
        None,
    ),
    (
        "launchdarkly",
        "feature-flags",
        ("launchdarkly", "ldclient", "clientstream.launchdarkly"),
        None,
    ),
    (
        "statsig",
        "feature-flags",
        ("statsig",),
        re.compile(r"\b(client-[A-Za-z0-9]{16,})\b"),
    ),
    (
        "fullstory",
        "analytics",
        ("fullstory", "fs.js", "_fs_org"),
        None,
    ),
    (
        "logrocket",
        "analytics",
        ("logrocket",),
        None,
    ),
    (
        "heap",
        "analytics",
        ("heapanalytics", "heap.load(", "heap.io"),
        re.compile(r"heap\.load\(\s*[\"']?(\d{6,})"),
    ),
]


def fingerprint_third_parties(html: str) -> list[ThirdParty]:
    """Identify third-party SaaS from page markup, extracting keys where possible."""
    text = html or ""
    low = text.lower()
    found: list[ThirdParty] = []

    for name, category, patterns, key_re in _THIRD_PARTY_SIGNATURES:
        hit = next((p for p in patterns if p.lower() in low), None)
        if hit is None:
            continue
        key = None
        if key_re is not None:
            km = key_re.search(text)
            if km:
                key = redact_key(km.group(1))
        found.append(
            ThirdParty(name=name, category=category, key=key, evidence=hit)
        )

    return found


# --------------------------------------------------------------------------- #
# Secret-leak scanning (always redacted)
# --------------------------------------------------------------------------- #


def _redact(value: str) -> str:
    """Return a safe prefix: first ~8 chars + ellipsis. NEVER the full secret."""
    return value[:8] + "…"


# type, regex. Group 1 (if present) is the sensitive value, else group 0.
_SECRET_SIGNATURES: list[tuple[str, re.Pattern]] = [
    ("stripe_pk", re.compile(r"\b(pk_(?:live|test)_[A-Za-z0-9]{8,})\b")),
    ("stripe_secret", re.compile(r"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{8,})\b")),
    (
        "segment_write_key",
        re.compile(r"analytics\.load\(\s*[\"']([A-Za-z0-9]{10,})[\"']"),
    ),
    (
        "segment_write_key",
        re.compile(r"writeKey[\"']?\s*[:=]\s*[\"']([A-Za-z0-9]{10,})[\"']"),
    ),
    (
        "sentry_dsn",
        re.compile(r"(https://[0-9a-f]+@[A-Za-z0-9.\-]*sentry\.io/\d+)", re.IGNORECASE),
    ),
    ("posthog_key", re.compile(r"\b(phc_[A-Za-z0-9]{16,})\b")),
    ("ga_measurement_id", re.compile(r"\b(G-[A-Z0-9]{6,})\b")),
    (
        "firebase_api_key",
        re.compile(r"\b(AIza[0-9A-Za-z_\-]{20,})\b"),
    ),
    (
        "supabase_anon_key",
        re.compile(r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b"),
    ),
    (
        "generic_secret",
        re.compile(
            r"(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret|token)"
            r"[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{16,})[\"']?",
            re.IGNORECASE,
        ),
    ),
]


def redact_secret_values(text: str) -> str:
    """Remove recognized secret values from arbitrary module output."""
    spans: list[tuple[int, int]] = []
    for _, pattern in _SECRET_SIGNATURES:
        for match in pattern.finditer(text):
            spans.append(match.span(1) if match.groups() else match.span())
    for start, end in sorted(set(spans), reverse=True):
        text = text[:start] + "[REDACTED]" + text[end:]
    return text


def detect_secret_leaks(text: str, source_url: str) -> list[SecretLeak]:
    """Scan text for leaked keys/tokens. Stores only a REDACTED prefix, never the value."""
    blob = text or ""
    leaks: list[SecretLeak] = []
    seen: set[tuple[str, str]] = set()

    for leak_type, pattern in _SECRET_SIGNATURES:
        for m in pattern.finditer(blob):
            value = m.group(1) if m.groups() else m.group(0)
            if not value:
                continue
            key = (leak_type, value)
            if key in seen:
                continue
            seen.add(key)
            leaks.append(
                SecretLeak(
                    type=leak_type,
                    value_prefix=_redact(value),
                    source_url=source_url,
                )
            )

    return leaks


# --------------------------------------------------------------------------- #
# Bundle enrichment (the one network-touching function)
# --------------------------------------------------------------------------- #

_INTERESTING_RE = re.compile(
    r"(openapi|swagger|/api/v[0-9]+|endpoint|route|schema|graphql)",
    re.IGNORECASE,
)


async def enrich_bundles(
    bundles: list[Bundle], fetcher: Fetcher, max_bundles: int = 8,
    artifact_store: ArtifactStore | None = None, host_name: str | None = None,
) -> list[Bundle]:
    """For up to max_bundles JS bundles: probe for sourcemaps and scan for tokens.

    Uses fetcher.get only and never raises (the Fetcher swallows network errors).
    CSS bundles are left untouched. Returns the same list with fields filled.
    """
    processed = 0
    for bundle in bundles:
        if bundle.type != "js":
            continue
        if processed >= max_bundles:
            break
        processed += 1

        try:
            # 1. Sourcemap probe.
            map_resp = await fetcher.get(source_map_url(bundle.url))
            source_map = None
            if map_resp.status == 200:
                try:
                    source_map = json.loads(map_resp.text)
                except (TypeError, ValueError):
                    source_map = None
                bundle.has_sourcemap = (
                    isinstance(source_map, dict)
                    and source_map.get("version") == 3
                    and isinstance(source_map.get("sources"), list)
                    and isinstance(source_map.get("mappings"), str)
                )
                if bundle.has_sourcemap:
                    bundle.source_map_sources = len(source_map["sources"])

            bundle_host = urlsplit(bundle.url).hostname or ""
            first_party = bool(host_name and bundle_host and
                               registrable_domain(bundle_host) == registrable_domain(host_name))
            save = bool(artifact_store and bundle.has_sourcemap and first_party)
            if save and source_map is not None:
                bundle.sourcemap_artifact = artifact_store.save_map(source_map)

            # 2. Fetch + scan the bundle body.
            body_resp = await fetcher.get(bundle.url)
            body = body_resp.text or ""
            if save and body_resp.status == 200 and body:
                bundle.source_artifact = artifact_store.save_source(body)
            if not body:
                continue

            tokens: list[str] = list(bundle.interesting_tokens)
            seen = {t.lower() for t in tokens}

            for match in _INTERESTING_RE.findall(body):
                tok = match.lower()
                if tok not in seen:
                    seen.add(tok)
                    tokens.append(tok)

            # Feed redacted secret indicators into interesting_tokens.
            for leak in detect_secret_leaks(body, bundle.url):
                marker = f"{leak.type}:{leak.value_prefix}"
                if marker.lower() not in seen:
                    seen.add(marker.lower())
                    tokens.append(marker)

            bundle.interesting_tokens = tokens
        except Exception:  # noqa: BLE001 - never raise to the orchestrator
            continue

    return bundles
