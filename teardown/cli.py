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
import json
import sys
from collections.abc import Callable, Sequence
from contextlib import nullcontext
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from .analyze import analyze_host, build_aggregate
from .artifacts import ArtifactStore
from .enumerate import enumerate_subdomains, probe_live
from .http_client import Fetcher, FetchResponse, HttpClient
from .history import HistoryStore, data_home, ensure_data_home
from .models import HostTeardown, ScanResult
from .render import write_outputs
from .safety import registrable_domain, safe_url
from .scan_modules import ScanContext, ScanModule, default_modules, run_modules
from .terminal import CliReporter, print_comparison, print_history

ProgressCallback = Callable[[str, dict[str, object]], None]


def _emit(callback: ProgressCallback | None, event: str, **details: object) -> None:
    if callback:
        callback(event, details)


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


async def teardown_host(url: str, fetcher: Fetcher,
                        initial_response: FetchResponse | None = None,
                        modules: Sequence[ScanModule] | None = None,
                        on_module: Callable[[str, bool], None] | None = None,
                        artifact_store: ArtifactStore | None = None) -> HostTeardown:
    """Run the full single-host collection pipeline. Never raises."""
    host_name = urlsplit(url).hostname or url
    host = HostTeardown(target=safe_url(url) or url, host=host_name, scanned_at=_now())

    resp = initial_response if initial_response is not None else await fetcher.get(url)
    if resp.status is None:
        host.reachable = False
        if resp.error:
            host.errors.append(resp.error)
        return host

    host.reachable = True
    if resp.error:
        host.errors.append(resp.error)
    base = _base_url(resp.final_url, url)

    try:
        context = ScanContext(host=host, response=resp, fetcher=fetcher,
                              base_url=base, html=resp.text or "",
                              artifact_store=artifact_store)
        await run_modules(context, modules, on_module=on_module)
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
    use_subfinder: bool = False,
    cache_dir: str | None = None,
    modules: Sequence[ScanModule] | None = None,
    data_dir: str | None = None,
    history: HistoryStore | None = None,
    on_event: ProgressCallback | None = None,
    save_artifacts: bool = True,
) -> ScanResult:
    url, _host, root = _normalize(target)
    result = ScanResult(root_domain=root, scanned_at=_now())

    effective_cache = (str(ensure_data_home(data_dir) / "cache")
                       if cache_dir is None else cache_dir)
    artifact_store = ArtifactStore(data_home(data_dir) / "artifacts") if save_artifacts else None
    scan_id = history.start(root, safe_url(url) or root, result.scanned_at) if history else None
    _emit(on_event, "start", target=root, scan_id=scan_id or "")
    try:
        async with HttpClient(concurrency=concurrency, rate_per_sec=rate_per_sec,
                              root_domain=root, cache_dir=effective_cache) as client:
            if single:
                live = [(url, None)]
                result.enumeration.sources = ["single-host"]
                result.enumeration.subdomains_found = 1
            else:
                subs, enum_info = await enumerate_subdomains(
                    root, client, active_dns=active_dns, wordlist=wordlist,
                    use_subfinder=use_subfinder,
                    on_source=lambda source, count: _emit(
                        on_event, "source", source=source, count=count),
                )
                _emit(on_event, "enumerated", count=len(subs))
                live = await probe_live(
                    subs, client, max_probes=max_probes, preferred_host=root,
                    on_probe=lambda host, reachable, done, total: _emit(
                        on_event, "probe", host=host, reachable=reachable,
                        done=done, total=total),
                )
                enum_info.live_hosts = len(live)
                result.enumeration = enum_info

            if max_hosts > 0:
                live = live[:max_hosts]
            result.enumeration.live_hosts = len(live)
            _emit(on_event, "live", count=len(live), found=result.enumeration.subdomains_found)

            selected_modules = default_modules() if modules is None else tuple(modules)
            completed = 0

            async def scan_one(host_url: str, response: FetchResponse | None) -> HostTeardown:
                nonlocal completed
                host_name = urlsplit(host_url).hostname or host_url
                _emit(on_event, "host_start", host=host_name)
                host = await teardown_host(
                    host_url, client, response, modules=selected_modules,
                    on_module=lambda name, success: _emit(
                        on_event, "module", host=host_name, module=name,
                        success=success),
                    artifact_store=artifact_store,
                )
                if history and scan_id:
                    history.checkpoint(scan_id, host)
                completed += 1
                _emit(on_event, "host_done", host=host_name, done=completed,
                      total=len(live), findings=len(host.opsec_findings),
                      reachable=host.reachable)
                return host

            tasks = [scan_one(u, resp) for u, resp in live]
            result.hosts = list(await asyncio.gather(*tasks)) if tasks else []

        result.aggregate = build_aggregate(result.hosts)
        if history and scan_id:
            history.finish(scan_id, result)
        _emit(on_event, "finished", hosts=len(result.hosts), scan_id=scan_id or "")
        return result
    except BaseException:
        if history and scan_id:
            history.fail(scan_id)
        raise


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="teardown",
        description="Passive web-app architecture teardown with subdomain fan-out.",
        epilog="Other commands: teardown history DOMAIN; teardown compare DOMAIN; "
               "teardown diff OLD NEW; teardown fingerprints update",
    )
    p.add_argument("target", help="Domain or URL (e.g. example.com or https://example.com)")
    p.add_argument("--single", action="store_true",
                   help="Scan only the given host; skip subdomain enumeration.")
    p.add_argument("--active-dns", action="store_true",
                   help="Opt in to active DNS brute-force enumeration (needs dnspython).")
    p.add_argument("--subfinder", action="store_true",
                   help="Use installed subfinder for additional passive sources.")
    p.add_argument("--cache-dir", default=None,
                   help="Directory for daily sanitized response cache (default: ~/.teardown/cache).")
    p.add_argument("--no-cache", action="store_true", help="Disable response cache.")
    p.add_argument("--data-dir", default=None,
                   help="Data home for reports, cache and history (default: ~/.teardown).")
    p.add_argument("--no-history", action="store_true",
                   help="Do not save this scan to SQLite history.")
    p.add_argument("--no-artifacts", action="store_true",
                   help="Do not retain first-party bundles with exposed source maps.")
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
    p.add_argument("--out-dir", default=None,
                   help="Directory for JSON + markdown (default: ~/.teardown/reports/DOMAIN).")
    p.add_argument("--name", default=None,
                   help="Output basename (default: derived from root domain).")
    p.add_argument("--json-only", action="store_true",
                   help="Print JSON to stdout and skip report files; history still saves.")
    verbosity = p.add_mutually_exclusive_group()
    verbosity.add_argument("-q", "--quiet", action="store_true", help="Suppress scan status.")
    verbosity.add_argument("-v", "--verbose", action="count", default=0,
                           help="Show host details; use -vv for module details.")
    p.add_argument("--no-color", action="store_true", help="Disable terminal colors.")
    return p


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "diff":
        diff_parser = argparse.ArgumentParser(prog="teardown diff")
        diff_parser.add_argument("old")
        diff_parser.add_argument("new")
        paths = diff_parser.parse_args(argv[1:])
        from .diff import diff_files
        print(json.dumps(diff_files(paths.old, paths.new), indent=2, sort_keys=True))
        return 0
    if argv and argv[0] in {"history", "compare"}:
        command = argv[0]
        parser = argparse.ArgumentParser(prog=f"teardown {command}")
        parser.add_argument("domain")
        parser.add_argument("--data-dir", default=None)
        parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
        parser.add_argument("--no-color", action="store_true")
        if command == "history":
            parser.add_argument("--limit", type=_positive_int, default=20)
        else:
            parser.add_argument("--days", type=_positive_int, default=None,
                                help="Compare with latest scan at least N days older.")
        options = parser.parse_args(argv[1:])
        root = _normalize(options.domain)[2]
        try:
            with HistoryStore(options.data_dir) as history:
                if command == "history":
                    payload = history.list_scans(root, limit=options.limit)
                else:
                    payload = history.compare(root, days=options.days)
        except ValueError as exc:
            print(f"teardown {command}: {exc}", file=sys.stderr)
            return 2
        if options.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        elif command == "history":
            print_history(root, payload, no_color=options.no_color)
        else:
            print_comparison(payload, no_color=options.no_color)
        return 0
    if argv[:2] == ["fingerprints", "update"]:
        from .fingerprints import update_external_database, external_db_path
        count = update_external_database()
        print(f"Imported {count} WebAppAnalyzer fingerprints into {external_db_path()}")
        return 0
    args = build_parser().parse_args(argv)

    wordlist = None
    if args.wordlist:
        with open(args.wordlist, encoding="utf-8") as fh:
            wordlist = [ln.strip() for ln in fh if ln.strip()]

    _url, _host, root = _normalize(args.target)
    basename = args.name or root.replace(".", "-")

    history_context = nullcontext(None) if args.no_history else HistoryStore(args.data_dir)
    with history_context as history, CliReporter(
        verbosity=args.verbose, quiet=args.quiet, no_color=args.no_color,
    ) as reporter:
        result = asyncio.run(run_scan(
            args.target,
            single=args.single,
            active_dns=args.active_dns,
            wordlist=wordlist,
            max_hosts=args.max_hosts,
            max_probes=args.max_probes,
            concurrency=args.concurrency,
            rate_per_sec=args.rate,
            use_subfinder=args.subfinder,
            cache_dir="" if args.no_cache else args.cache_dir,
            data_dir=args.data_dir,
            history=history,
            on_event=reporter,
            save_artifacts=not args.no_artifacts,
        ))

        paths = None
        if not args.json_only:
            if args.out_dir is None:
                out_dir = ensure_data_home(args.data_dir) / "reports" / root
                stamp = result.scanned_at.replace(":", "").replace("-", "")
                basename = f"{args.name or basename}-{stamp}-{uuid4().hex[:8]}"
            else:
                out_dir = Path(args.out_dir)
            paths = write_outputs(result, str(out_dir), basename)
        reporter.summary(result, paths)

    if args.json_only:
        from .models import to_dict
        print(json.dumps(to_dict(result), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
