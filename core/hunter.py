#!/usr/bin/env python3
"""ASRock Rack / AMI MegaRAC CVE-2024-54085 hunter.

Continuous, keyless discovery + verification of ASRock Rack BMCs and
assessment of CVE-2024-54085 (Redfish authentication bypass).
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import random
import signal
import sys
import time
from logging.handlers import RotatingFileHandler

from core import config as cfgmod
from core import sources
from core.db import DB
from core.net import Fetcher
from core.scanner import run_batch
from core.targets import collect_targets, harvest_asns, sample_ips

LOG = logging.getLogger("hunter")
STOP = asyncio.Event()


def setup_logging(cfg) -> None:
    os.makedirs(os.path.dirname(cfg.log_file) or ".", exist_ok=True)
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s %(message)s")
    fh = RotatingFileHandler(cfg.log_file, maxBytes=20 * 1024 * 1024, backupCount=5)
    fh.setFormatter(fmt)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    LOG.setLevel(getattr(logging, cfg.log_level.upper(), logging.INFO))
    LOG.addHandler(fh)
    LOG.addHandler(sh)


def install_signals() -> None:
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, STOP.set)
        except NotImplementedError:
            pass


# ---------------------------------------------------------------- ingestion
async def ingest_subnets(db: DB, cfg) -> int:
    nets, counts = collect_targets(cfg)
    LOG.info("subnet files loaded: %s", counts)

    if cfg.use_asn_harvest:
        try:
            asn_nets = await harvest_asns(None, cfg.asns_file, "data/ip2asn-v4.tsv.gz")
            LOG.info("ASN harvest produced %d prefixes", len(asn_nets))
            nets.extend(asn_nets)
        except Exception as exc:  # noqa: BLE001
            LOG.warning("ASN harvest failed: %s", exc)

    added = 0
    for net in nets:
        db.add_subnet(str(net), "file")
        for ip in sample_ips(net, cfg.max_ips_per_subnet, cfg.full_scan):
            if db.add_host(ip, 443, "https", f"net:{net}", score=10):
                added += 1
    LOG.info("subnet expansion queued %d new IPs", added)
    return added


async def ingest_engines(fetcher: Fetcher, db: DB, cfg) -> int:
    if not cfg.harvest_enabled:
        return 0
    added = 0
    for name in sources.SOURCES:
        src = sources.SOURCES[name]
        if src.kind == "enrich" or not cfg.engines.get(name, False):
            continue
        if not db.source_due(name, cfg.source_interval_hours):
            continue
        try:
            ips = await asyncio.wait_for(
                src.fn(fetcher, cfg.source_result_limit), timeout=240)
        except Exception as exc:  # noqa: BLE001
            db.source_fail(name, str(exc))
            LOG.warning("source %s failed: %s", name, exc)
            continue
        for ip in ips:
            if db.add_host(ip, 443, "https", f"src:{name}", score=35):
                added += 1
        db.source_ok(name, len(ips))
        LOG.info("source %-14s %4d ips (%d new)", name, len(ips), added)
    return added


async def enrich_batch(fetcher: Fetcher, db: DB, cfg, limit: int = 60) -> None:
    if not cfg.enrich:
        return
    rows = db.conn.execute(
        "SELECT ip, port FROM hosts WHERE status='vuln' AND asn IS NULL LIMIT ?",
        (limit,)).fetchall()
    for row in rows:
        data = await sources.enrich(fetcher, row["ip"])
        fields = {k: (",".join(map(str, v)) if isinstance(v, list) else v)
                  for k, v in data.items() if k in ("country", "asn", "org")}
        idb_vulns = data.get("vulns") or []
        if "CVE-2024-54085" in idb_vulns:
            db.record_vuln(row["ip"], row["port"], "CVE-2024-54085", "confirmed",
                           "internetdb-tag", "shodan internetdb vuln tag")
        if fields:
            db.update_host(row["ip"], row["port"], **fields)


# ---------------------------------------------------------------- cycle
async def cycle(fetcher: Fetcher, db: DB, cfg, do_harvest: bool = True) -> None:
    run_id = db.start_run()
    new_ips = 0
    if do_harvest:
        new_ips += await ingest_engines(fetcher, db, cfg)
        new_ips += await ingest_subnets(db, cfg)

    total = {"scanned": 0, "alive": 0, "vuln": 0, "new_vuln": 0}
    while not STOP.is_set():
        batch = await run_batch(fetcher, db, cfg, cfg.concurrency * 4)
        if not batch["scanned"]:
            break
        for k in total:
            total[k] += batch[k]
        LOG.info("batch: scanned=%d alive=%d vuln=%d new_vuln=%d",
                 batch["scanned"], batch["alive"], batch["vuln"], batch["new_vuln"])

    await enrich_batch(fetcher, db, cfg)
    db.finish_run(run_id, total["scanned"], total["alive"], new_ips, total["new_vuln"])
    LOG.info("cycle done: %s", total)


async def main_async(cfg, args) -> None:
    db = DB(cfg.db_path)
    async with Fetcher(cfg) as fetcher:
        if args.stats:
            print(db.stats())
            return
        if args.export:
            print(db.export_all(cfg.export_dir))
            return

        install_signals()

        if args.once:
            await cycle(fetcher, db, cfg)
            db.export_all(cfg.export_dir)
            return

        LOG.info("daemon starting (pid %d)", os.getpid())
        last_maintenance = 0.0
        while not STOP.is_set():
            try:
                now = time.time()
                do_harvest = (now - last_maintenance) > cfg.daily_maintenance_hour * 3600
                if do_harvest:
                    last_maintenance = now
                await cycle(fetcher, db, cfg, do_harvest=do_harvest)
                db.export_all(cfg.export_dir)
                db.kv_set("last_cycle", str(int(now)))
            except Exception as exc:  # noqa: BLE001
                LOG.exception("cycle crashed: %s", exc)
                await asyncio.sleep(30)

            delay = cfg.cycle_interval + random.randint(0, cfg.cycle_jitter)
            LOG.info("sleeping %ds", delay)
            try:
                await asyncio.wait_for(STOP.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass
        LOG.info("shutdown requested")
        db.export_all(cfg.export_dir)
        db.close()


def main() -> None:
    ap = argparse.ArgumentParser(description="ASRock Rack / MegaRAC hunter")
    ap.add_argument("-c", "--config", default="config.yaml")
    ap.add_argument("--once", action="store_true", help="single cycle then exit")
    ap.add_argument("--full", action="store_true", help="do not sample subnets")
    ap.add_argument("--export", action="store_true", help="export databases and exit")
    ap.add_argument("--stats", action="store_true", help="print stats and exit")
    ap.add_argument("--no-enrich", action="store_true")
    ap.add_argument("--ports", help="comma separated port override")
    ap.add_argument("--concurrency", type=int)
    args = ap.parse_args()

    cfg = cfgmod.Config.load(args.config)
    if args.full:
        cfg.full_scan = True
    if args.no_enrich:
        cfg.enrich = False
    if args.ports:
        cfg.ports = [int(p) for p in args.ports.split(",") if p.strip()]
    if args.concurrency:
        cfg.concurrency = args.concurrency

    setup_logging(cfg)
    asyncio.run(main_async(cfg, args))


if __name__ == "__main__":
    main()
