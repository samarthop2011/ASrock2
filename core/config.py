from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from typing import Any

import yaml


@dataclass
class Config:
    db_path: str = "data/hunter.db"
    export_dir: str = "data/exports"
    log_file: str = "data/hunter.log"
    log_level: str = "INFO"

    subnets_file: str = "subnets.txt"
    datacenters_file: str = "datacenter_subnets.txt"
    use_datacenters: bool = True
    asns_file: str = "asns.txt"
    use_asn_harvest: bool = True
    resolve_hostnames: bool = True

    ports: list = field(default_factory=lambda: [443, 80, 8443, 5900, 5901, 623])
    schemes: list = field(default_factory=lambda: ["https", "http"])
    concurrency: int = 200
    per_host_delay: float = 0.15
    request_timeout: int = 12
    retries: int = 2
    max_ips_per_subnet: int = 4096
    rescan_alive_hours: int = 168
    rescan_dead_hours: int = 720
    rescan_vuln_hours: int = 24
    max_attempts: int = 5

    harvest_enabled: bool = True
    source_interval_hours: int = 6
    source_result_limit: int = 400
    engines: dict = field(default_factory=dict)

    cycle_interval: int = 900
    cycle_jitter: int = 240
    daily_maintenance_hour: int = 4

    discord_webhook: str = ""
    slack_webhook: str = ""
    generic_webhook: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    notify_min_confidence: str = "likely"

    full_scan: bool = False
    enrich: bool = True

    @classmethod
    def load(cls, path: str = "config.yaml") -> "Config":
        raw: dict[str, Any] = {}
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh) or {}
        known = {f.name for f in fields(cls)}
        cfg = cls(**{k: v for k, v in raw.items() if k in known})
        os.makedirs(os.path.dirname(cfg.db_path) or ".", exist_ok=True)
        os.makedirs(cfg.export_dir, exist_ok=True)
        return cfg
