"""Polite async HTTP layer: pooled session, UA rotation, per-host buckets, retries."""
from __future__ import annotations

import asyncio
import random
import ssl
import time
from dataclasses import dataclass, field
from typing import Optional

import aiohttp

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "curl/8.7.1",
]

BROWSER_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Upgrade-Insecure-Requests": "1",
}


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except Exception:
        pass
    try:
        ctx.set_ciphers("DEFAULT@SECLEVEL=1")
    except Exception:
        pass
    return ctx


@dataclass
class Response:
    status: int = 0
    url: str = ""
    headers: dict = field(default_factory=dict)
    body: str = ""
    error: Optional[str] = None
    elapsed: float = 0.0

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status < 400


class Bucket:
    def __init__(self, rate: float, burst: float = 3.0):
        self.rate, self.burst = rate, burst
        self.tokens = burst
        self.stamp = time.monotonic()
        self.lock = asyncio.Lock()

    async def take(self) -> None:
        async with self.lock:
            now = time.monotonic()
            self.tokens = min(self.burst, self.tokens + (now - self.stamp) * self.rate)
            self.stamp = now
            if self.tokens < 1:
                await asyncio.sleep((1 - self.tokens) / self.rate)
                self.tokens = 0
                self.stamp = time.monotonic()
            else:
                self.tokens -= 1


class Fetcher:
    def __init__(self, cfg):
        self.cfg = cfg
        self._session: Optional[aiohttp.ClientSession] = None
        self._buckets: dict[str, Bucket] = {}

    async def __aenter__(self) -> "Fetcher":
        connector = aiohttp.TCPConnector(
            limit=self.cfg.concurrency, limit_per_host=4,
            ssl=_ssl_context(), force_close=False, enable_cleanup_closed=True,
            ttl_dns_cache=300,
        )
        timeout = aiohttp.ClientTimeout(
            total=self.cfg.request_timeout, connect=min(8, self.cfg.request_timeout))
        self._session = aiohttp.ClientSession(
            connector=connector, timeout=timeout, trust_env=True,
            headers={"User-Agent": random.choice(UA_POOL)},
        )
        return self

    async def __aexit__(self, *exc) -> None:
        if self._session:
            await self._session.close()

    def _bucket(self, host: str) -> Bucket:
        b = self._buckets.get(host)
        if b is None:
            b = Bucket(rate=1.0 / max(self.cfg.per_host_delay, 0.01), burst=2)
            self._buckets[host] = b
        return b

    async def request(self, method: str, url: str, *, headers: Optional[dict] = None,
                      data=None, json=None, allow_redirects: bool = True,
                      retries: Optional[int] = None, read_body: bool = True,
                      polite: bool = True) -> Response:
        retries = self.cfg.retries if retries is None else retries
        last = Response(url=url, error="not attempted")
        for attempt in range(retries + 1):
            try:
                if polite:
                    from urllib.parse import urlparse
                    await self._bucket(urlparse(url).netloc).take()
                hdrs = dict(BROWSER_HEADERS)
                hdrs["User-Agent"] = random.choice(UA_POOL)
                if headers:
                    hdrs.update(headers)
                started = time.monotonic()
                async with self._session.request(
                        method, url, headers=hdrs, data=data, json=json,
                        allow_redirects=allow_redirects, ssl=False) as resp:
                    body = ""
                    if read_body:
                        raw = await resp.read()
                        body = raw[:400_000].decode("utf-8", errors="replace")
                    last = Response(status=resp.status, url=str(resp.url),
                                    headers=dict(resp.headers), body=body,
                                    elapsed=time.monotonic() - started)
                if last.status < 500:
                    return last
            except asyncio.TimeoutError:
                last = Response(url=url, error="timeout")
            except aiohttp.ClientError as exc:
                last = Response(url=url, error=f"{type(exc).__name__}: {exc}"[:200])
            except Exception as exc:  # noqa: BLE001
                last = Response(url=url, error=f"{type(exc).__name__}: {exc}"[:200])
            if attempt < retries:
                await asyncio.sleep((0.4 * (2 ** attempt)) + random.random() * 0.4)
        return last

    async def get(self, url: str, **kw) -> Response:
        return await self.request("GET", url, **kw)

    async def head(self, url: str, **kw) -> Response:
        return await self.request("HEAD", url, read_body=False, **kw)

    async def post(self, url: str, **kw) -> Response:
        return await self.request("POST", url, **kw)

    async def resolve(self, host: str) -> list[str]:
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(host, None, type=0)
        except Exception:
            return []
        return sorted({i[4][0] for i in infos if ":" not in i[4][0]})
