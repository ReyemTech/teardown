"""CLI orchestration: enumerate -> per-host teardown -> analyze -> render.

Flow:
    enumerate_subdomains -> filter_live -> teardown_host (per live host, bounded)
    -> analyze_host / build_aggregate -> write_outputs (JSON + vault markdown).

Passive recon only. Bounded concurrency + rate limiting live in HttpClient.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as _dt
import sys
from urllib.parse import urlsplit

from .analyze import analyze_host, build_aggregate
from .collectors.api_discovery import discover_api
from .collectors.headers import parse_csp, parse_headers
from .collectors.html_js import (
    detect_cms,
    detect_frameworks,
    detect_secret_leaks,
    enrich_bundles,
    extract_bundles,
    fingerprint_third_parties,
)
from .enumerate import enumerate_subdomains, filter_live
from .http_client import Fetcher, HttpClient
from .models import HostTeardown, ScanResult
from .render import write_outputs
from .safety import registrable_domain, safe_url


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be at least 0")
    return parsed


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def _positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def _normalize(target: str) -> tuple[str, str, str]:
    """Return (url, hostname, root_domain) for a raw target string."""
    raw = target.strip()
    if "://" not in raw:
        raw = "https://" + raw
    parts = urlsplit(raw)
    host = parts.hostname or ""
    url = f"{parts.scheme}://{parts.netloc}"
    root = registrable_domain(host)
    return url, host, root


def _base_url(final_url: str, fallback: str) -> str:
    parts = urlsplit(final_url or fallback)
    if not parts.scheme or not parts.netloc:
        return fallback
    return f"{parts.scheme}://{parts.netloc}"


async def teardown_host(url: str, fetcher: Fetcher) -> HostTeardown:
    """Run the full single-host collection pipeline. Never raises."""
    host_name = urlsplit(url).hostname or url
    host = HostTeardown(target=safe_url(url) or url, host=host_name, scanned_at=_now())

    resp = await fetcher.get(url)
    if resp.status is None:
        host.reachable = False
        if resp.error:
            host.errors.append(resp.error)
        return host

    host.reachable = True
    if resp.error:
        host.errors.append(resp.error)
    html = resp.text or ""
    base = _base_url(resp.final_url, url)

    try:
        host.http = parse_headers(resp)
        host.csp = parse_csp(resp.headers)
        host.frameworks = detect_frameworks(html)
        host.cms = detect_cms(html, resp.headers)
        host.bundles = extract_bundles(html, base)
        host.bundles = await enrich_bundles(host.bundles, fetcher)
        host.third_parties = fingerprint_third_parties(html)
        host.secret_leaks = detect_secret_leaks(html, base)
        host.api_surface = await discover_api(base, fetcher)
        host.opsec_findings = analyze_host(host)
    except Exception as exc:  # noqa: BLE001 - collection is best-effort per host
        host.errors.append(f"collection error: {type(exc).__name__}")

    return host


async def run_scan(
    target: str,
    *,
    single: bool,
    active_dns: bool,
    wordlist: list[str] | None,
    max_hosts: int,
    concurrency: int,
    rate_per_sec: float,
    max_probes: int = 100,
) -> ScanResult:
    url, _host, root = _normalize(target)
    result = ScanResult(root_domain=root, scanned_at=_now())

    async with HttpClient(concurrency=concurrency, rate_per_sec=rate_per_sec,
                          root_domain=root) as client:
        if single:
            live_urls = [url]
            result.enumeration.sources = ["single-host"]
            result.enumeration.subdomains_found = 1
        else:
            subs, enum_info = await enumerate_subdomains(
                root, client, active_dns=active_dns, wordlist=wordlist
            )
            live_urls = await filter_live(subs, client, max_probes=max_probes,
                                          preferred_host=root)
            enum_info.live_hosts = len(live_urls)
            result.enumeration = enum_info

        if max_hosts > 0:
            live_urls = live_urls[:max_hosts]
        result.enumeration.live_hosts = len(live_urls)

        tasks = [teardown_host(u, client) for u in live_urls]
        result.hosts = list(await asyncio.gather(*tasks)) if tasks else []

    result.aggregate = build_aggregate(result.hosts)
    return result


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="teardown",
        description="Passive web-app architecture teardown with subdomain fan-out.",
    )
    p.add_argument("target", help="Domain or URL (e.g. example.com or https://example.com)")
    p.add_argument("--single", action="store_true",
                   help="Scan only the given host; skip subdomain enumeration.")
    p.add_argument("--active-dns", action="store_true",
                   help="Opt in to active DNS brute-force enumeration (needs dnspython).")
    p.add_argument("--wordlist", default=None,
                   help="Path to a newline-delimited subdomain wordlist for --active-dns.")
    p.add_argument("--max-hosts", type=_nonnegative_int, default=25,
                   help="Cap live hosts torn down (0 = no cap). Default 25.")
    p.add_argument("--max-probes", type=_nonnegative_int, default=100,
                   help="Cap hosts checked for liveness (0 = no cap). Default 100.")
    p.add_argument("--concurrency", type=_positive_int, default=10,
                   help="Max concurrent requests. Default 10.")
    p.add_argument("--rate", type=_positive_float, default=8.0,
                   help="Global requests/sec cap. Default 8.")
    p.add_argument("--out-dir", default=".",
                   help="Directory for the JSON + markdown outputs. Default cwd.")
    p.add_argument("--name", default=None,
                   help="Output basename (default: derived from root domain).")
    p.add_argument("--json-only", action="store_true",
                   help="Print JSON to stdout and skip writing files.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    wordlist = None
    if args.wordlist:
        with open(args.wordlist, encoding="utf-8") as fh:
            wordlist = [ln.strip() for ln in fh if ln.strip()]

    _url, _host, root = _normalize(args.target)
    basename = args.name or root.replace(".", "-")

    result = asyncio.run(run_scan(
        args.target,
        single=args.single,
        active_dns=args.active_dns,
        wordlist=wordlist,
        max_hosts=args.max_hosts,
        max_probes=args.max_probes,
        concurrency=args.concurrency,
        rate_per_sec=args.rate,
    ))

    if args.json_only:
        import json
        from .models import to_dict
        print(json.dumps(to_dict(result), indent=2))
    else:
        paths = write_outputs(result, args.out_dir, basename)
        print(f"hosts torn down : {len(result.hosts)}")
        print(f"live / found    : {result.enumeration.live_hosts} / "
              f"{result.enumeration.subdomains_found}")
        print(f"critical findings: {len(result.aggregate.critical_findings)}")
        print(f"JSON -> {paths['json']}")
        print(f"MD   -> {paths['md']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
