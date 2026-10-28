"""Keyless discovery sources. Every source returns a set of IPs; failures are isolated."""
from __future__ import annotations

import asyncio
import base64
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from .net import Fetcher

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
PRIVATE = re.compile(r"^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)")

SHODAN_Q = [
    'http.title:"ASRock Rack"',
    '"MegaRAC" http.title',
    'http.html:"ASRockRack"',
    'http.html:"MegaRAC" http.html:"redfish"',
    'port:623 product:"AMI"',
    'http.title:"MegaRAC"',
    'http.favicon.hash:-1507567067',
]
FOFA_Q = [
    'title="ASRock Rack"',
    'body="ASRockRack"',
    'body="MegaRAC"',
    'server="AMI"',
    'body="/redfish/v1" && body="MegaRAC"',
    'title="MegaRAC"',
]
DORK_Q = [
    'intitle:"ASRock Rack"',
    '"ASRock Rack" "Redfish" login',
    'intitle:"MegaRAC" login',
    'inurl:"redfish/v1" "MegaRAC"',
]
CT_Q = ["%.asrockrack.com", "%.asrock.com", "MegaRAC", "ASRockRack"]


@dataclass
class Source:
    name: str
    fn: Callable[[Fetcher, int], Awaitable[set[str]]]
    kind: str = "engine"
    notes: str = ""


SOURCES: dict[str, Source] = {}


def source(name: str, kind: str = "engine", notes: str = ""):
    def deco(fn):
        SOURCES[name] = Source(name=name, fn=fn, kind=kind, notes=notes)
        return fn
    return deco


def _clean(ips) -> set[str]:
    return {ip for ip in ips if not PRIVATE.match(ip) and not ip.startswith(("0.", "255."))}


def _ips(html: str) -> set[str]:
    return _clean(IP_RE.findall(html or ""))


async def _engine(fetcher: Fetcher, urls: list[str], limit: int) -> set[str]:
    out: set[str] = set()
    for url in urls:
        if len(out) >= limit:
            break
        resp = await fetcher.get(url, polite=False)
        if resp.ok:
            out |= _ips(resp.body)
        await asyncio.sleep(1.2)
    return set(list(out)[:limit])


@source("shodan", notes="shodan.io HTML search")
async def shodan(fetcher: Fetcher, limit: int) -> set[str]:
    urls = [f"https://www.shodan.io/search?query={urllib.parse.quote(q)}" for q in SHODAN_Q]
    return await _engine(fetcher, urls, limit)


@source("fofa", notes="fofa.info HTML search")
async def fofa(fetcher: Fetcher, limit: int) -> set[str]:
    urls = []
    for q in FOFA_Q:
        b64 = base64.b64encode(q.encode()).decode()
        urls.append(f"https://fofa.info/result?qbase64={urllib.parse.quote(b64)}")
    return await _engine(fetcher, urls, limit)


@source("zoomeye", notes="zoomeye.org HTML search")
async def zoomeye(fetcher: Fetcher, limit: int) -> set[str]:
    qs = ['title:"ASRock Rack"', 'app:"ASRock Rack"', '"MegaRAC"']
    urls = [f"https://www.zoomeye.org/searchResult?q={urllib.parse.quote(q)}" for q in qs]
    return await _engine(fetcher, urls, limit)


@source("quake", notes="quake.360.net HTML search")
async def quake(fetcher: Fetcher, limit: int) -> set[str]:
    qs = ['title:"ASRock Rack"', 'body:"MegaRAC"', 'body:"ASRockRack"']
    urls = [f"https://quake.360.net/quake/#/searchResult?searchVal={urllib.parse.quote(q)}"
            for q in qs]
    return await _engine(fetcher, urls, limit)


@source("hunter", notes="hunter.how HTML search")
async def hunter(fetcher: Fetcher, limit: int) -> set[str]:
    qs = ['web.title="ASRock Rack"', 'web.body="MegaRAC"']
    urls = [f"https://hunter.qianxin.com/list?search={urllib.parse.quote(q)}" for q in qs]
    return await _engine(fetcher, urls, limit)


@source("netlas", notes="app.netlas.io HTML search")
async def netlas(fetcher: Fetcher, limit: int) -> set[str]:
    qs = ['http.title:"ASRock Rack"', 'http.body:"MegaRAC"']
    urls = [f"https://app.netlas.io/responses/?q={urllib.parse.quote(q)}" for q in qs]
    return await _engine(fetcher, urls, limit)


@source("censys", notes="search.censys.io HTML search")
async def censys(fetcher: Fetcher, limit: int) -> set[str]:
    qs = ['services.http.response.html_title:"ASRock Rack"', '"MegaRAC"']
    urls = [f"https://search.censys.io/search?resource=hosts&q={urllib.parse.quote(q)}"
            for q in qs]
    return await _engine(fetcher, urls, limit)


@source("onyphe", notes="onyphe.io HTML search")
async def onyphe(fetcher: Fetcher, limit: int) -> set[str]:
    qs = ['http.title:"ASRock Rack"', 'http.body:"MegaRAC"']
    urls = [f"https://www.onyphe.io/search/?q={urllib.parse.quote(q)}" for q in qs]
    return await _engine(fetcher, urls, limit)


@source("dork_ddg", kind="dork", notes="DuckDuckGo HTML dorks")
async def dork_ddg(fetcher: Fetcher, limit: int) -> set[str]:
    urls = [f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(q)}" for q in DORK_Q]
    found = await _engine(fetcher, urls, limit)
    return found | await _hosts_from_pages(fetcher, found, limit)


@source("dork_bing", kind="dork", notes="Bing HTML dorks")
async def dork_bing(fetcher: Fetcher, limit: int) -> set[str]:
    urls = [f"https://www.bing.com/search?q={urllib.parse.quote(q)}&count=50" for q in DORK_Q]
    found = await _engine(fetcher, urls, limit)
    return found | await _hosts_from_pages(fetcher, found, limit)


HOST_RE = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,24})\b", re.I)


async def _hosts_from_pages(fetcher: Fetcher, _ips_seen: set[str], limit: int) -> set[str]:
    """Resolve hostnames found in dork output (re-scan of cached bodies not kept, so
    callers pass nothing; this resolves asrock-ish domains from a static list)."""
    domains = ["asrockrack.com", "asrock.com"]
    out: set[str] = set()
    for dom in domains:
        for ip in await fetcher.resolve(dom):
            out.add(ip)
    return out


@source("crtsh", kind="ct", notes="certificate transparency via crt.sh")
async def crtsh(fetcher: Fetcher, limit: int) -> set[str]:
    out: set[str] = set()
    for q in CT_Q:
        resp = await fetcher.get(f"https://crt.sh/?q={urllib.parse.quote(q)}&output=json")
        if not resp.ok:
            continue
        try:
            rows = json.loads(resp.body)
        except Exception:
            continue
        names: set[str] = set()
        for row in rows[:3000]:
            for name in str(row.get("name_value", "")).splitlines():
                name = name.strip().lower().lstrip("*.")
                if name and "." in name and not name.endswith((".local", ".lan")):
                    names.add(name)
        for batch in _chunks(sorted(names), 40):
            res = await asyncio.gather(*(fetcher.resolve(n) for n in batch))
            for ips in res:
                out |= _clean(ips)
            if len(out) >= limit:
                break
        if len(out) >= limit:
            break
    return set(list(out)[:limit])


@source("hackertarget", kind="ct", notes="HackerTarget hostsearch")
async def hackertarget(fetcher: Fetcher, limit: int) -> set[str]:
    out: set[str] = set()
    for dom in ("asrockrack.com", "asrock.com"):
        resp = await fetcher.get(
            f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(dom)}")
        if resp.ok and "," in resp.body and "error" not in resp.body.lower():
            out |= _ips(resp.body)
        await asyncio.sleep(2.0)
    return set(list(out)[:limit])


@source("internetdb", kind="enrich", notes="Shodan InternetDB per-IP vuln tags")
async def internetdb_lookup(fetcher: Fetcher, ip: str) -> dict:
    resp = await fetcher.get(f"https://internetdb.shodan.io/{ip}", polite=False)
    if not resp.ok:
        return {}
    try:
        return json.loads(resp.body)
    except Exception:
        return {}


async def enrich(fetcher: Fetcher, ip: str) -> dict:
    """Free, keyless enrichment: geo/ASN + Shodan InternetDB vuln tags."""
    data: dict = {}
    idb = await internetdb_lookup(fetcher, ip)
    if idb:
        data["ports"] = idb.get("ports", [])
        data["hostnames"] = idb.get("hostnames", [])
        data["cpes"] = idb.get("cpes", [])
        data["vulns"] = idb.get("vulns", [])
    geo = await fetcher.get(
        f"http://ip-api.com/json/{ip}?fields=status,country,as,org,asn", polite=False)
    if geo.ok:
        try:
            g = json.loads(geo.body)
            if g.get("status") == "success":
                data["country"] = g.get("country", "")
                data["asn"] = g.get("as", "")
                data["org"] = g.get("org", "")
        except Exception:
            pass
    return data


def _chunks(seq, size):
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


async def run_all(fetcher: Fetcher, cfg, limit: int) -> dict[str, set[str]]:
    """Run every enabled engine source, one failure at a time."""
    results: dict[str, set[str]] = {}
    engines = [n for n in SOURCES if SOURCES[n].kind != "enrich"]
    for name in engines:
        if not cfg.engines.get(name, False):
            continue
        try:
            ips = await asyncio.wait_for(SOURCES[name].fn(fetcher, limit), timeout=180)
            results[name] = ips
        except Exception as exc:  # noqa: BLE001
            results[name] = set()
            results.setdefault("_errors", set())
            results["_errors"].add(f"{name}: {type(exc).__name__}")
    return results
