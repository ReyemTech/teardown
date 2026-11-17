"""Subdomain enumeration and liveness filtering.

Passive by default: queries crt.sh, CertSpotter and Wayback. An opt-in active
path (``active_dns=True``) brute-forces a small wordlist via DNS, with
``dnspython`` lazy-imported so the tool runs without it when the active path is
not used.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from .http_client import Fetcher, FetchResponse
from .models import EnumerationInfo

# Base backoff (seconds) between crt.sh retries. A module constant so tests can
# set it to 0; multiplied by the attempt number for a linear backoff.
CRTSH_RETRY_BACKOFF = 1.0

# Small built-in brute-force wordlist for the active DNS path.
DEFAULT_WORDLIST = [
    "www", "api", "app", "staging", "dev", "admin", "mail", "portal",
    "dashboard", "blog", "shop", "cdn", "auth", "docs", "status", "test",
    "vpn", "git", "gitlab", "jenkins",
]


def _try_json(text: str) -> Any:
    if not text:
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def _parse_crtsh(payload: Any, domain: str) -> set[str]:
    """Extract subdomains from a crt.sh JSON array for ``domain``."""
    found: set[str] = set()
    if not isinstance(payload, list):
        return found
    suffix = "." + domain
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        name_value = entry.get("name_value")
        if not name_value:
            continue
        for raw in str(name_value).split("\n"):
            name = raw.strip()
            if name.startswith("*."):
                name = name[2:]
            name = name.strip().lower()
            if not name:
                continue
            if name == domain or name.endswith(suffix):
                found.add(name)
    return found


def _scope_names(values: list[str], domain: str) -> set[str]:
    suffix = "." + domain
    return {name for raw in values if (name := raw.lower().strip().removeprefix("*."))
            and re.fullmatch(r"[a-z0-9.-]+", name)
            and (name == domain or name.endswith(suffix))}


async def _certspotter(domain: str, fetcher: Fetcher) -> set[str]:
    url = (f"https://api.certspotter.com/v1/issuances?domain={domain}"
           "&include_subdomains=true&expand=dns_names")
    response = await fetcher.get(url)
    payload = _try_json(response.text) if response.status == 200 else None
    if not isinstance(payload, list):
        return set()
    return _scope_names([name for item in payload if isinstance(item, dict)
                         for name in (item.get("dns_names") or []) if isinstance(name, str)], domain)


async def _wayback(domain: str, fetcher: Fetcher) -> set[str]:
    url = (f"https://web.archive.org/cdx/search/cdx?url={domain}"
           "&matchType=domain&output=json&fl=original&collapse=urlkey&limit=5000")
    response = await fetcher.get(url)
    payload = _try_json(response.text) if response.status == 200 else None
    if not isinstance(payload, list):
        return set()
    urls = [row[0] for row in payload if isinstance(row, list) and row and isinstance(row[0], str)]
    return _scope_names([urlsplit(url).hostname or "" for url in urls], domain)


PASSIVE_SOURCES = {"certspotter": _certspotter, "wayback": _wayback}


async def _subfinder(domain: str) -> set[str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            "subfinder", "-d", domain, "-silent", "-duc", "-rl", "2",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
    except OSError:
        return set()
    try:
        output, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return set()
    return _scope_names(output[:2_000_000].decode(errors="replace").splitlines(), domain)


async def enumerate_subdomains(
    domain: str,
    fetcher: Fetcher,
    active_dns: bool = False,
    wordlist: list[str] | None = None,
    use_subfinder: bool = False,
    on_source: Callable[[str, int], None] | None = None,
) -> tuple[list[str], EnumerationInfo]:
    """Enumerate subdomains of ``domain``.

    Returns the sorted, de-duplicated host list (including the apex) and an
    :class:`EnumerationInfo`. ``live_hosts`` is left at 0 here — fill it via
    :func:`filter_live`.
    """
    domain = domain.strip().lower().rstrip(".")
    sources: list[str] = []
    hosts: set[str] = {domain}

    # --- Passive: crt.sh certificate transparency ---
    # crt.sh is flaky: it intermittently answers with a 404/HTML error page,
    # which is a "successful" HTTP response the client won't retry. So retry at
    # this layer on any non-JSON-array body, and try the bare-domain query form
    # as a fallback. Both forms are equivalent; the wildcard is the usual one.
    sources.append("crt.sh")
    crt_urls = [
        f"https://crt.sh/?q=%25.{domain}&output=json",
        f"https://crt.sh/?q={domain}&output=json",
    ]
    for attempt in range(4):
        crt_url = crt_urls[attempt % len(crt_urls)]
        resp = await fetcher.get(crt_url)
        payload = _try_json(resp.text) if resp.status is not None else None
        if isinstance(payload, list):
            hosts |= _parse_crtsh(payload, domain)
            break
        if attempt < 3:
            await asyncio.sleep(CRTSH_RETRY_BACKOFF * (attempt + 1))
    if on_source:
        on_source("crt.sh", len(hosts))

    for name, source in PASSIVE_SOURCES.items():
        found = await source(domain, fetcher)
        if found:
            hosts |= found
            sources.append(name)
        if on_source:
            on_source(name, len(hosts))
    if use_subfinder and shutil.which("subfinder"):
        hosts |= await _subfinder(domain)
        sources.append("subfinder")
        if on_source:
            on_source("subfinder", len(hosts))

    # --- Active: DNS brute force (opt-in) ---
    if active_dns:
        words = wordlist if wordlist is not None else DEFAULT_WORDLIST
        resolved = await _dns_brute(domain, words)
        if resolved:
            hosts |= resolved
        sources.append("dns-brute")
        if on_source:
            on_source("dns-brute", len(hosts))

    ordered = sorted(hosts)
    info = EnumerationInfo(
        sources=sources,
        subdomains_found=len(ordered),
        live_hosts=0,
    )
    return ordered, info


async def _dns_brute(domain: str, words: list[str]) -> set[str]:
    """Resolve ``{word}.{domain}`` candidates. Lazy-imports dnspython."""
    try:
        import dns.resolver  # noqa: PLC0415 - lazy so the tool runs without dnspython
    except ImportError:
        return set()

    resolver = dns.resolver.Resolver()

    def _resolves(host: str) -> bool:
        for rdtype in ("A", "AAAA"):
            try:
                answers = resolver.resolve(host, rdtype)
                if answers:
                    return True
            except Exception:  # noqa: BLE001 - NXDOMAIN, NoAnswer, timeout, etc.
                continue
        return False

    found: set[str] = set()
    for word in words:
        host = f"{word}.{domain}"
        # dnspython is synchronous; offload to a thread to stay async-friendly.
        if await asyncio.to_thread(_resolves, host):
            found.add(host)
    return found


async def probe_live(
    hosts: list[str], fetcher: Fetcher, max_probes: int = 100,
    preferred_host: str | None = None,
    on_probe: Callable[[str, bool, int, int], None] | None = None,
) -> list[tuple[str, FetchResponse]]:
    """Return reachable URLs and their first responses, preferring HTTPS.

    A host is live if a request to it returns any status (not None).
    Concurrency is handled by the fetcher's internal semaphore.
    """

    ordered = ([preferred_host] + [h for h in hosts if h != preferred_host]
               if preferred_host in hosts else hosts)
    candidates = ordered[:max_probes] if max_probes > 0 else ordered
    done = 0

    async def _probe(host: str) -> tuple[str, FetchResponse] | None:
        nonlocal done
        https = f"https://{host}"
        resp = await fetcher.get(https)
        if resp.status is not None:
            done += 1
            if on_probe:
                on_probe(host, True, done, len(candidates))
            return https, resp
        http = f"http://{host}"
        resp = await fetcher.get(http)
        if resp.status is not None:
            done += 1
            if on_probe:
                on_probe(host, True, done, len(candidates))
            return http, resp
        done += 1
        if on_probe:
            on_probe(host, False, done, len(candidates))
        return None

    results = await asyncio.gather(*(_probe(h) for h in candidates))
    return [item for item in results if item is not None]


async def filter_live(
    hosts: list[str], fetcher: Fetcher, max_probes: int = 100,
    preferred_host: str | None = None,
) -> list[str]:
    """Compatibility wrapper returning URL strings only."""
    return [url for url, _ in await probe_live(hosts, fetcher, max_probes, preferred_host)]
