"""Subnet file parsing, expansion with deterministic sampling, ASN harvest."""
from __future__ import annotations

import gzip
import ipaddress
import os
import random
import re
from typing import Iterable, Iterator

from .net import Fetcher

IP2ASN_URL = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"
SKIP = {
    ipaddress.ip_network("0.0.0.0/8"), ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"), ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"), ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"), ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
}
LINE_RE = re.compile(r"^\s*([0-9a-zA-Z_.:\-/]+)")


def _parse_line(line: str) -> list[ipaddress.IPv4Network]:
    line = line.split("#", 1)[0].strip()
    if not line:
        return []
    m = LINE_RE.match(line)
    if not m:
        return []
    token = m.group(1)
    nets = []
    try:
        if "-" in token and token.count(".") == 6:
            a, b = token.split("-")
            start, end = ipaddress.IPv4Address(a), ipaddress.IPv4Address(b)
            nets.extend(ipaddress.summarize_address_range(start, end))
        else:
            net = ipaddress.ip_network(token, strict=False)
            if net.version == 4:
                nets.append(net)
    except ValueError:
        return []
    return [n for n in nets if not any(n.subnet_of(s) for s in SKIP)]


def load_file(path: str) -> list[ipaddress.IPv4Network]:
    if not os.path.exists(path):
        return []
    out: list[ipaddress.IPv4Network] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            out.extend(_parse_line(line))
    return out


def sample_ips(net: ipaddress.IPv4Network, limit: int, full: bool) -> Iterator[str]:
    size = net.num_addresses
    if full or size <= limit:
        for ip in net.hosts() if size > 2 else net:
            yield str(ip)
        return
    rng = random.Random(int(net.network_address))
    picked = set()
    base = int(net.network_address)
    while len(picked) < limit:
        offset = rng.randrange(1, size - 1)
        if offset in picked:
            continue
        picked.add(offset)
        yield str(ipaddress.IPv4Address(base + offset))


async def harvest_asns(fetcher: Fetcher, asns_file: str, cache_path: str,
                       max_age_hours: int = 168) -> list[ipaddress.IPv4Network]:
    """Download ip2asn and return prefixes for the configured ASNs (keyless)."""
    asns = set()
    if os.path.exists(asns_file):
        with open(asns_file, encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line.isdigit():
                    asns.add(int(line))
    if not asns:
        return []

    stale = True
    if os.path.exists(cache_path):
        age = (os.path.getmtime(cache_path))
        import time
        stale = (time.time() - age) > max_age_hours * 3600

    if stale:
        resp = await fetcher.get(IP2ASN_URL, read_body=False, polite=False)
        if resp.ok:
            raw = await _download_bytes(fetcher, IP2ASN_URL)
            if raw:
                with open(cache_path, "wb") as fh:
                    fh.write(raw)

    if not os.path.exists(cache_path):
        return []

    nets: list[ipaddress.IPv4Network] = []
    with gzip.open(cache_path, "rt", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 3 or not parts[2].isdigit():
                continue
            if int(parts[2]) not in asns:
                continue
            try:
                net = ipaddress.ip_network(
                    f"{parts[0]}/{_mask(parts[0], parts[1])}", strict=False)
            except ValueError:
                continue
            if net.prefixlen >= 16:
                nets.append(net)
    return nets


async def _download_bytes(fetcher: Fetcher, url: str) -> bytes | None:
    import aiohttp
    try:
        async with fetcher._session.get(url, ssl=False) as resp:
            if resp.status == 200:
                return await resp.read()
    except Exception:
        return None
    return None


def _mask(start: str, end: str) -> int:
    span = int(ipaddress.IPv4Address(end)) - int(ipaddress.IPv4Address(start)) + 1
    return 32 - (span.bit_length() - 1)


def collect_targets(cfg) -> tuple[list[ipaddress.IPv4Network], dict[str, int]]:
    """Load every configured source file into a deduplicated network list."""
    sources = {cfg.subnets_file: 10}
    if cfg.use_datacenters:
        sources[cfg.datacenters_file] = 2
    nets: dict[str, ipaddress.IPv4Network] = {}
    counts = {}
    for path, weight in sources.items():
        found = load_file(path)
        counts[os.path.basename(path)] = len(found)
        for net in found:
            nets.setdefault(str(net), net)
    ordered = sorted(nets.values(), key=lambda n: n.prefixlen)
    return ordered, counts
