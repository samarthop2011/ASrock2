"""Scan pipeline: probe a host, fingerprint, verify the CVE, persist."""
from __future__ import annotations

import asyncio
import sqlite3
from datetime import datetime, timezone

from . import cve_2024_54085 as cve
from .db import DB, utcnow
from .fingerprint import probe
from .net import Fetcher
from .notifier import format_hit, notify, should_notify


async def scan_host(fetcher: Fetcher, db: DB, cfg, row: sqlite3.Row,
                    sem: asyncio.Semaphore) -> dict:
    ip, port = row["ip"], row["port"]
    stats = {"alive": 0, "vuln": 0, "new_vuln": 0}

    async with sem:
        fp = None
        scheme_used = row["scheme"] or "https"
        for scheme in _schemes_for(cfg, port):
            fp = await probe(fetcher, ip, port, scheme)
            if fp.alive:
                scheme_used = scheme
                break
        if fp is None or not fp.alive:
            db.mark_dead(ip, port, cfg, "no response")
            return stats

        stats["alive"] = 1
        fields = {
            "title": fp.title[:200] if fp.title else None,
            "server": fp.server[:200] if fp.server else None,
            "product": "ASRock Rack / MegaRAC" if fp.candidate else None,
            "firmware": fp.firmware or None,
            "redfish": int(fp.redfish),
            "score": fp.score,
            "evidence": "; ".join(fp.evidence)[:1500],
            "scheme": scheme_used,
        }

        if not fp.candidate:
            db.mark_alive(ip, port, cfg, **fields)
            return stats

        verdict = await cve.verify(fetcher, ip, port, scheme_used, fp.firmware)
        if verdict.firmware and not fp.firmware:
            fields["firmware"] = verdict.firmware

        if not verdict.vulnerable:
            fields.update(status="alive", confidence="suspect",
                          next_scan=_iso(cfg.rescan_alive_hours))
            db.update_host(ip, port, **fields)
            db.record_vuln(ip, port, cve.CVE, "suspect", "fingerprint-only",
                           "; ".join(fp.evidence)[:1200], fp.firmware)
            return stats

        stats["vuln"] = 1
        fields.update(status="vuln", confidence=verdict.confidence,
                      evidence=(fp.evidence + [verdict.evidence]) and
                               "; ".join(fp.evidence + [verdict.evidence])[:1500],
                      next_scan=_iso(cfg.rescan_vuln_hours))
        db.update_host(ip, port, **fields)
        is_new = db.record_vuln(ip, port, cve.CVE, verdict.confidence,
                                verdict.method, verdict.evidence, verdict.firmware)
        stats["new_vuln"] = int(is_new)

        if is_new and should_notify(cfg, verdict.confidence):
            text = format_hit(ip, port, scheme_used, verdict, fp)
            await notify(fetcher, cfg, text)
            with open("data/vulns_found.log", "a", encoding="utf-8") as fh:
                fh.write(text + "\n\n")
        return stats


def _schemes_for(cfg, port: int) -> list[str]:
    if port in (80, 8080):
        return ["http", "https"]
    if port in (443, 8443):
        return ["https", "http"]
    return ["https", "http"]


def _iso(hours: int) -> str:
    from datetime import timedelta
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat(timespec="seconds")


async def run_batch(fetcher: Fetcher, db: DB, cfg, limit: int) -> dict:
    rows = db.next_batch(limit)
    if not rows:
        return {"scanned": 0, "alive": 0, "vuln": 0, "new_vuln": 0}

    sem = asyncio.Semaphore(cfg.concurrency)
    tasks = [scan_host(fetcher, db, cfg, r, sem) for r in rows]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    total = {"scanned": len(rows), "alive": 0, "vuln": 0, "new_vuln": 0}
    for res in results:
        if isinstance(res, dict):
            for k in total:
                if k in res:
                    total[k] += res[k]
    return total
