"""Tests for the HTML/JS fingerprinting collectors (pure parsers + fake Fetcher)."""

from __future__ import annotations

from teardown.collectors.html_js import (
    detect_cms,
    detect_frameworks,
    detect_secret_leaks,
    enrich_bundles,
    extract_bundles,
    fingerprint_third_parties,
)
from teardown.http_client import FetchResponse
from teardown.models import Bundle


# --------------------------------------------------------------------------- #
# Fake Fetcher
# --------------------------------------------------------------------------- #


class FakeFetcher:
    """Canned-response Fetcher for enrich_bundles (no network)."""

    def __init__(self, responses: dict[str, FetchResponse]) -> None:
        self._responses = responses
        self.requested: list[str] = []

    async def get(self, url: str, **kwargs) -> FetchResponse:
        self.requested.append(url)
        if url in self._responses:
            return self._responses[url]
        return FetchResponse(url=url, final_url=url, status=404, text="")

    async def request(self, method: str, url: str, **kwargs) -> FetchResponse:
        return await self.get(url, **kwargs)


# --------------------------------------------------------------------------- #
# Framework detection
# --------------------------------------------------------------------------- #


def test_detect_frameworks_next_and_react():
    html = '<div id="__next"></div><script>window.__NEXT_DATA__ = {}</script><script src="/_next/static/chunks/main.js"></script><div data-reactroot></div>'
    fw = detect_frameworks(html)
    assert "next.js" in fw
    assert "react" in fw
    assert fw == list(dict.fromkeys(fw))  # deduped


def test_detect_frameworks_nuxt_vue():
    html = "<script>window.__NUXT__={}</script><div data-v-abc123></div>"
    fw = detect_frameworks(html)
    assert "nuxt" in fw
    assert "vue" in fw


def test_detect_frameworks_none():
    assert detect_frameworks("<html><body>plain</body></html>") == []


# --------------------------------------------------------------------------- #
# CMS detection
# --------------------------------------------------------------------------- #


def test_detect_cms_wordpress_with_plugins_themes_version():
    html = (
        '<meta name="generator" content="WordPress 6.4.2" />'
        '<link rel="stylesheet" href="/wp-content/themes/astra/style.css" />'
        '<script src="/wp-content/plugins/elementor/assets/js/frontend.js"></script>'
        '<script src="/wp-content/plugins/woocommerce/assets/js/cart.js"></script>'
        '<link href="/wp-includes/css/dist/block-library/style.min.css" rel="stylesheet" />'
    )
    cms = detect_cms(html, {})
    assert cms.type == "wordpress"
    assert cms.version == "6.4.2"
    assert "elementor" in cms.plugins
    assert "woocommerce" in cms.plugins
    assert "astra" in cms.themes


def test_detect_cms_shopify():
    cms = detect_cms('<script src="https://cdn.shopify.com/s/files/app.js"></script>', {})
    assert cms.type == "shopify"


def test_detect_cms_webflow():
    cms = detect_cms('<html data-wf-site="abc123"><link href="https://assets.website-files.com/x.css"></html>', {})
    assert cms.type == "webflow"


def test_detect_cms_drupal_header():
    cms = detect_cms("<html></html>", {"X-Drupal-Cache": "HIT"})
    assert cms.type == "drupal"


def test_detect_cms_none():
    assert detect_cms("<html><body>nope</body></html>", {}).type is None


# --------------------------------------------------------------------------- #
# Bundle extraction / URL resolution
# --------------------------------------------------------------------------- #


def test_extract_bundles_resolves_relative_urls():
    html = (
        '<script src="/static/app.js"></script>'
        '<script src="https://cdn.example.net/vendor.js"></script>'
        '<link rel="stylesheet" href="../css/site.css" />'
        '<link rel="preload" href="/font.woff2" />'  # not a stylesheet -> skipped
    )
    bundles = extract_bundles(html, "https://foo.test/app/index.html")
    by_url = {b.url: b for b in bundles}
    assert by_url["https://foo.test/static/app.js"].type == "js"
    assert by_url["https://cdn.example.net/vendor.js"].type == "js"
    assert by_url["https://foo.test/css/site.css"].type == "css"
    # the preload link was not a stylesheet
    assert "https://foo.test/font.woff2" not in by_url


def test_extract_bundles_empty():
    assert extract_bundles("<html></html>", "https://x.test/") == []


# --------------------------------------------------------------------------- #
# Third-party fingerprinting + key extraction
# --------------------------------------------------------------------------- #


def test_fingerprint_third_parties_keys():
    html = (
        '<script>analytics.load("abc123WRITEKEY")</script>'
        '<script src="https://js.stripe.com/v3/"></script>'
        "<script>Stripe('pk_live_51ABCdef0123456789')</script>"
        '<script>gtag("config", "G-ABCDE12345")</script>'
        "<script>posthog.init('phc_abcDEF1234567890abcDEF')</script>"
        '<script src="https://browser.sentry-cdn.com/x.js"></script>'
        "<script>Sentry.init({dsn:'https://deadbeef0000@o42.ingest.sentry.io/1337'})</script>"
    )
    parties = {p.name: p for p in fingerprint_third_parties(html)}
    assert parties["segment"].key == "abc123WR…"
    assert parties["segment"].category == "analytics"
    assert parties["stripe"].key == "pk_live_…"
    assert parties["stripe"].category == "payments"
    assert parties["google-analytics"].key == "G-ABCDE1…"
    assert parties["posthog"].key == "phc_abcD…"
    assert parties["sentry"].key == "https://…"


def test_fingerprint_third_parties_none():
    assert fingerprint_third_parties("<html><body>plain</body></html>") == []


# --------------------------------------------------------------------------- #
# Secret leaks + redaction
# --------------------------------------------------------------------------- #


def test_detect_secret_leaks_redacts_full_secret():
    full_stripe = "pk_live_51ABCDEFghijklmnop0123456789"
    full_posthog = "phc_SUPERsecret0123456789abcdef"
    text = f"const k='{full_stripe}'; posthog.init('{full_posthog}');"
    leaks = detect_secret_leaks(text, "https://foo.test/app.js")
    types = {leak.type for leak in leaks}
    assert "stripe_pk" in types
    assert "posthog_key" in types
    # CRITICAL: the full secret must never appear in any stored field.
    for leak in leaks:
        assert full_stripe not in leak.value_prefix
        assert full_posthog not in leak.value_prefix
        assert leak.value_prefix.endswith("…")
        assert leak.source_url == "https://foo.test/app.js"
    # and the redacted prefix really is just a prefix
    stripe_leak = next(leak for leak in leaks if leak.type == "stripe_pk")
    assert full_stripe.startswith(stripe_leak.value_prefix[:-1])


def test_detect_secret_leaks_generic_and_dsn():
    text = (
        'apiKey: "AIzaSyD1234567890abcdefGHIJKLMNOPQRS", '
        'token = "abcdef0123456789abcdef", '
        "dsn: 'https://cafe0000@o1.ingest.sentry.io/99'"
    )
    types = {leak.type for leak in detect_secret_leaks(text, "x")}
    assert "firebase_api_key" in types
    assert "generic_secret" in types
    assert "sentry_dsn" in types


def test_detect_secret_leaks_none():
    assert detect_secret_leaks("nothing sensitive here", "u") == []


# --------------------------------------------------------------------------- #
# Bundle enrichment (fake Fetcher)
# --------------------------------------------------------------------------- #


async def test_enrich_bundles_sourcemap_and_tokens():
    js_url = "https://foo.test/app.js"
    body = (
        "fetch('/api/v2/users'); const schema={}; "
        "openapi='3.0'; const k='pk_live_ABCDEFGH1234567890';"
    )
    responses = {
        js_url + ".map": FetchResponse(url=js_url + ".map", final_url=js_url + ".map", status=200, text='{"version":3,"sources":["app.ts"],"mappings":"AAAA"}'),
        js_url: FetchResponse(url=js_url, final_url=js_url, status=200, text=body),
    }
    fetcher = FakeFetcher(responses)
    bundles = [Bundle(url=js_url, type="js"), Bundle(url="https://foo.test/site.css", type="css")]

    out = await enrich_bundles(bundles, fetcher)

    js_bundle = out[0]
    assert js_bundle.has_sourcemap is True
    toks = js_bundle.interesting_tokens
    assert "/api/v2" in toks
    assert "openapi" in toks
    assert "schema" in toks
    # secret indicator fed in as a redacted marker (never the full secret)
    assert any(t.startswith("stripe_pk:") for t in toks)
    assert not any("pk_live_ABCDEFGH1234567890" in t for t in toks)
    # css bundle left untouched + never fetched
    assert out[1].interesting_tokens == []
    assert "https://foo.test/site.css" not in fetcher.requested


async def test_enrich_bundles_no_sourcemap():
    js_url = "https://foo.test/b.js"
    responses = {
        js_url + ".map": FetchResponse(url=js_url + ".map", final_url=js_url + ".map", status=404, text=""),
        js_url: FetchResponse(url=js_url, final_url=js_url, status=200, text="const endpoint='/x';"),
    }
    out = await enrich_bundles([Bundle(url=js_url, type="js")], FakeFetcher(responses))
    assert out[0].has_sourcemap is False
    assert "endpoint" in out[0].interesting_tokens


async def test_enrich_bundles_caps_at_max():
    bundles = [Bundle(url=f"https://foo.test/{i}.js", type="js") for i in range(5)]
    responses = {}
    for b in bundles:
        responses[b.url] = FetchResponse(url=b.url, final_url=b.url, status=200, text="schema")
        responses[b.url + ".map"] = FetchResponse(url=b.url + ".map", final_url=b.url + ".map", status=404, text="")
    fetcher = FakeFetcher(responses)
    await enrich_bundles(bundles, fetcher, max_bundles=2)
    # only the first 2 js bundles were fetched (2 * (map + body) = 4 requests)
    assert fetcher.requested.count("https://foo.test/0.js") == 1
    assert fetcher.requested.count("https://foo.test/2.js") == 0
