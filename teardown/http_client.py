"""Polite, bounded async HTTP client and the Fetcher protocol.

Collectors never touch httpx directly — they receive a `Fetcher` so they can be
unit-tested with a fake. The real client enforces concurrency limits, a global
rate limit, timeouts, bounded retries, and an identifying User-Agent. Passive
recon only.
"""

from __future__ import annotations

import asyncio
import time
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urljoin, urlsplit

import httpx

from .models import DnsObservation
from .safety import in_scope, safe_headers, safe_url

USER_AGENT = (
    "TechTeardown/1.0 (+https://github.com/ReyemTech/teardown; passive architecture recon)"
)
DEFAULT_TIMEOUT = 15.0
DEFAULT_RETRIES = 1
DEFAULT_CONCURRENCY = 10
DEFAULT_RATE_PER_SEC = 8.0
DEFAULT_MAX_RESPONSE_BYTES = 8_000_000


@dataclass
class FetchResponse:
    """What collectors receive. Network errors are captured, not raised."""

    url: str                       # requested URL
    final_url: str                 # after redirects
    status: int | None             # None if the request failed outright
    headers: dict[str, str] = field(default_factory=dict)  # lower-cased keys
    text: str = ""
    error: str | None = None       # populated on failure
    status_chain: list[int] = field(default_factory=list)
    tls: dict[str, str] = field(default_factory=dict)


class Fetcher(Protocol):
    """Injected into collectors. Must never raise for network errors."""

    async def get(self, url: str, **kwargs) -> FetchResponse: ...

    async def request(self, method: str, url: str, **kwargs) -> FetchResponse: ...

    async def resolve_dns(self, host: str) -> DnsObservation: ...


class _RateLimiter:
    """Simple async token-bucket."""

    def __init__(self, rate_per_sec: float) -> None:
        self._interval = 1.0 / rate_per_sec if rate_per_sec > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next = 0.0

    async def wait(self) -> None:
        if self._interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            wait_for = max(0.0, self._next - now)
            self._next = max(now, self._next) + self._interval
        if wait_for > 0:
            await asyncio.sleep(wait_for)


class HttpClient:
    """Real Fetcher implementation. Use as an async context manager."""

    def __init__(
        self,
        *,
        concurrency: int = DEFAULT_CONCURRENCY,
        rate_per_sec: float = DEFAULT_RATE_PER_SEC,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        root_domain: str | None = None,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        transport: httpx.AsyncBaseTransport | None = None,
        cache_dir: str | None = None,
        dns_resolver: Any = None,
    ) -> None:
        self._sem = asyncio.Semaphore(concurrency)
        self._ripe_sem = asyncio.Semaphore(4)
        self._rl = _RateLimiter(rate_per_sec)
        self._retries = retries
        self._root_domain = root_domain
        self._max_response_bytes = max_response_bytes
        self._dns_resolver = dns_resolver
        if cache_dir:
            from .cache import ResponseCache
            self._cache = ResponseCache(cache_dir)
        else:
            self._cache = None
        self._client = httpx.AsyncClient(
            follow_redirects=False,
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
            verify=True,
            transport=transport,
        )

    async def __aenter__(self) -> "HttpClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self._client.aclose()

    async def get(self, url: str, **kwargs) -> FetchResponse:
        return await self.request("GET", url, **kwargs)

    async def resolve_dns(self, host: str) -> DnsObservation:
        from .network import resolve_dns
        import dns.asyncresolver

        resolver = self._dns_resolver or dns.asyncresolver.Resolver()
        if self._dns_resolver is None:
            resolver.timeout = 3.0
            resolver.lifetime = 5.0

        class LimitedResolver:
            async def resolve(_self, name: str, record_type: str):
                async with self._sem:
                    await self._rl.wait()
                    return await resolver.resolve(name, record_type)

        return await resolve_dns(host, LimitedResolver())

    async def request(self, method: str, url: str, **kwargs) -> FetchResponse:
        requested_host = urlsplit(url).hostname

        def allowed(candidate: str, *, external: bool = False) -> bool:
            parts = urlsplit(candidate)
            if parts.scheme not in ("http", "https"):
                return False
            if external:
                if parts.scheme != "https" or parts.hostname != requested_host:
                    return False
                if parts.hostname == "stat.ripe.net":
                    return parts.path in {
                        "/data/network-info/data.json", "/data/as-overview/data.json",
                        "/data/whois/data.json", "/data/maxmind-geo-lite/data.json"}
                return parts.hostname in {"crt.sh", "api.certspotter.com", "web.archive.org"}
            return self._root_domain is None or in_scope(candidate, self._root_domain)

        external = requested_host in {"crt.sh", "api.certspotter.com", "web.archive.org",
                                      "stat.ripe.net"}
        if not allowed(url, external=external):
            return FetchResponse(url=safe_url(url) or "", final_url=safe_url(url) or "",
                                 status=None, error="out-of-scope request blocked")
        if method.upper() == "GET" and self._cache is not None:
            hit = self._cache.get(url)
            if hit is not None:
                return hit
        last_err: str | None = None
        for attempt in range(self._retries + 1):
            current = url
            chain: list[int] = []
            try:
                for _ in range(6):
                    async with AsyncExitStack() as slots:
                        await slots.enter_async_context(self._sem)
                        if urlsplit(current).hostname == "stat.ripe.net":
                            await slots.enter_async_context(self._ripe_sem)
                        await self._rl.wait()
                        async with self._client.stream(method, current, **kwargs) as resp:
                            if resp.is_redirect and "location" in resp.headers:
                                chain.append(resp.status_code)
                                destination = urljoin(current, resp.headers["location"])
                                if not allowed(destination, external=external):
                                    return FetchResponse(url=safe_url(url) or "",
                                                         final_url=safe_url(current) or "",
                                                         status=None, error="out-of-scope redirect blocked")
                                current = destination
                                if resp.status_code == 303:
                                    method = "GET"
                                    kwargs.pop("json", None)
                                continue
                            body = bytearray()
                            tls: dict[str, str] = {}
                            stream = resp.extensions.get("network_stream")
                            ssl_object = stream.get_extra_info("ssl_object") if stream else None
                            if ssl_object:
                                tls["version"] = ssl_object.version() or ""
                                cipher = ssl_object.cipher()
                                if cipher:
                                    tls["cipher"] = cipher[0]
                                cert = ssl_object.getpeercert() or {}
                                if cert.get("notAfter"):
                                    tls["not_after"] = cert["notAfter"]
                                for part in cert.get("subject", ()):
                                    for key, value in part:
                                        if key == "commonName":
                                            tls["common_name"] = value
                                for part in cert.get("issuer", ()):
                                    for key, value in part:
                                        if key == "commonName":
                                            tls["issuer_common_name"] = value
                            truncated = False
                            async for chunk in resp.aiter_bytes():
                                room = self._max_response_bytes - len(body)
                                body.extend(chunk[:max(room, 0)])
                                if len(chunk) > room:
                                    truncated = True
                                    break
                            result = FetchResponse(
                                url=safe_url(url) or "", final_url=safe_url(str(resp.url)) or "",
                                status=resp.status_code,
                                headers=safe_headers({k.lower(): v for k, v in resp.headers.items()}),
                                text=body.decode(resp.encoding or "utf-8", errors="replace"),
                                error=(f"response body truncated at {self._max_response_bytes} bytes"
                                       if truncated else None),
                                status_chain=chain + [resp.status_code],
                                tls=tls,
                            )
                            if method.upper() == "GET" and self._cache is not None:
                                self._cache.put(url, result)
                            return result
                return FetchResponse(url=safe_url(url) or "", final_url=safe_url(current) or "",
                                     status=None, error="redirect limit exceeded")
            except Exception as exc:  # noqa: BLE001 - never raise to collectors
                last_err = type(exc).__name__
            if attempt < self._retries:
                await asyncio.sleep(0.5 * (attempt + 1))
        return FetchResponse(
            url=safe_url(url) or "", final_url=safe_url(url) or "", status=None, error=last_err
        )
