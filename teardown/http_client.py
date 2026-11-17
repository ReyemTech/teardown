"""Polite, bounded async HTTP client and the Fetcher protocol.

Collectors never touch httpx directly — they receive a `Fetcher` so they can be
unit-tested with a fake. The real client enforces concurrency limits, a global
rate limit, timeouts, bounded retries, and an identifying User-Agent. Passive
recon only.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Protocol

import httpx

USER_AGENT = (
    "ReyemTech-Teardown/1.0 (+https://reyem.tech; passive architecture recon)"
)
DEFAULT_TIMEOUT = 15.0
DEFAULT_RETRIES = 1
DEFAULT_CONCURRENCY = 10
DEFAULT_RATE_PER_SEC = 8.0


@dataclass
class FetchResponse:
    """What collectors receive. Network errors are captured, not raised."""

    url: str                       # requested URL
    final_url: str                 # after redirects
    status: int | None             # None if the request failed outright
    headers: dict[str, str] = field(default_factory=dict)  # lower-cased keys
    text: str = ""
    error: str | None = None       # populated on failure


class Fetcher(Protocol):
    """Injected into collectors. Must never raise for network errors."""

    async def get(self, url: str, **kwargs) -> FetchResponse: ...

    async def request(self, method: str, url: str, **kwargs) -> FetchResponse: ...


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
    ) -> None:
        self._sem = asyncio.Semaphore(concurrency)
        self._rl = _RateLimiter(rate_per_sec)
        self._retries = retries
        self._client = httpx.AsyncClient(
            follow_redirects=True,
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
            verify=True,
        )

    async def __aenter__(self) -> "HttpClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self._client.aclose()

    async def get(self, url: str, **kwargs) -> FetchResponse:
        return await self.request("GET", url, **kwargs)

    async def request(self, method: str, url: str, **kwargs) -> FetchResponse:
        last_err: str | None = None
        for attempt in range(self._retries + 1):
            async with self._sem:
                await self._rl.wait()
                try:
                    resp = await self._client.request(method, url, **kwargs)
                    return FetchResponse(
                        url=url,
                        final_url=str(resp.url),
                        status=resp.status_code,
                        headers={k.lower(): v for k, v in resp.headers.items()},
                        text=resp.text,
                    )
                except Exception as exc:  # noqa: BLE001 - never raise to collectors
                    last_err = f"{type(exc).__name__}: {exc}"
            if attempt < self._retries:
                await asyncio.sleep(0.5 * (attempt + 1))
        return FetchResponse(
            url=url, final_url=url, status=None, error=last_err
        )
