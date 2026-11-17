"""Subdomain enumeration and liveness filtering.

Passive by default: queries crt.sh certificate transparency logs. An opt-in
active path (``active_dns=True``) brute-forces a small wordlist via DNS, with
``dnspython`` lazy-imported so the tool runs without it when the active path is
not used.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from .http_client import Fetcher
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


async def enumerate_subdomains(
    domain: str,
    fetcher: Fetcher,
    active_dns: bool = False,
    wordlist: list[str] | None = None,
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

    # --- Active: DNS brute force (opt-in) ---
    if active_dns:
        words = wordlist if wordlist is not None else DEFAULT_WORDLIST
        resolved = await _dns_brute(domain, words)
        if resolved:
            hosts |= resolved
        sources.append("dns-brute")

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


async def filter_live(
    hosts: list[str], fetcher: Fetcher, max_probes: int = 100,
    preferred_host: str | None = None,
) -> list[str]:
    """Return reachable URLs for ``hosts``, preferring https over http.

    A host is live if a request to it returns any status (not None).
    Concurrency is handled by the fetcher's internal semaphore.
    """

    async def _probe(host: str) -> str | None:
        https = f"https://{host}"
        resp = await fetcher.get(https)
        if resp.status is not None:
            return https
        http = f"http://{host}"
        resp = await fetcher.get(http)
        if resp.status is not None:
            return http
        return None

    ordered = ([preferred_host] + [h for h in hosts if h != preferred_host]
               if preferred_host in hosts else hosts)
    candidates = ordered[:max_probes] if max_probes > 0 else ordered
    results = await asyncio.gather(*(_probe(h) for h in candidates))
    return [url for url in results if url is not None]
