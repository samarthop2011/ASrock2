"""SQLite storage: full host inventory, vulnerability ledger, exports."""
from __future__ import annotations

import csv
import json
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS hosts (
    ip            TEXT NOT NULL,
    port          INTEGER NOT NULL DEFAULT 443,
    scheme        TEXT NOT NULL DEFAULT 'https',
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    sources       TEXT DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'new',
    attempts      INTEGER NOT NULL DEFAULT 0,
    next_scan     TEXT,
    title         TEXT,
    server        TEXT,
    product       TEXT,
    firmware      TEXT,
    favicon_hash  TEXT,
    redfish       INTEGER DEFAULT 0,
    country       TEXT,
    asn           TEXT,
    org           TEXT,
    score         INTEGER DEFAULT 0,
    confidence    TEXT,
    evidence      TEXT,
    notes         TEXT,
    PRIMARY KEY (ip, port)
);

CREATE TABLE IF NOT EXISTS vulns (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip           TEXT NOT NULL,
    port         INTEGER NOT NULL,
    cve          TEXT NOT NULL,
    confidence   TEXT NOT NULL,
    method       TEXT,
    evidence     TEXT,
    firmware     TEXT,
    confirmed_at TEXT NOT NULL,
    last_checked TEXT NOT NULL,
    UNIQUE (ip, port, cve)
);

CREATE TABLE IF NOT EXISTS subnets (
    cidr     TEXT PRIMARY KEY,
    source   TEXT,
    added_at TEXT,
    enabled  INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS source_stats (
    name        TEXT PRIMARY KEY,
    last_ok     TEXT,
    last_error  TEXT,
    fail_streak INTEGER DEFAULT 0,
    ips_total   INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS runs (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    started  TEXT,
    finished TEXT,
    scanned  INTEGER DEFAULT 0,
    alive    INTEGER DEFAULT 0,
    new_ips  INTEGER DEFAULT 0,
    vulns    INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS kv (
    k TEXT PRIMARY KEY,
    v TEXT
);

CREATE INDEX IF NOT EXISTS idx_hosts_status ON hosts(status, next_scan);
CREATE INDEX IF NOT EXISTS idx_hosts_score  ON hosts(score DESC);
CREATE INDEX IF NOT EXISTS idx_vulns_cve    ON vulns(cve);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _iso(delta_hours: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=delta_hours)).isoformat(timespec="seconds")


class DB:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(path, check_same_thread=False, timeout=30)
        self.conn.row_factory = sqlite3.Row
        with self._lock:
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    def close(self) -> None:
        with self._lock:
            self.conn.commit()
            self.conn.close()

    # ---------------- hosts ----------------
    def add_host(self, ip: str, port: int = 443, scheme: str = "https",
                 source: str = "", score: int = 0) -> bool:
        """Insert if unseen. Returns True when the row is new."""
        now = utcnow()
        with self._lock:
            cur = self.conn.execute(
                "SELECT sources FROM hosts WHERE ip=? AND port=?", (ip, port))
            row = cur.fetchone()
            if row:
                srcs = set(filter(None, (row["sources"] or "").split(",")))
                srcs.add(source)
                self.conn.execute(
                    "UPDATE hosts SET sources=?, last_seen=?, score=MAX(score,?) "
                    "WHERE ip=? AND port=?",
                    (",".join(sorted(srcs)), now, score, ip, port))
                self.conn.commit()
                return False
            self.conn.execute(
                "INSERT INTO hosts (ip, port, scheme, first_seen, last_seen, sources, "
                "status, score, next_scan) VALUES (?,?,?,?,?,?,?,?,?)",
                (ip, port, scheme, now, now, source, "new", score, now))
            self.conn.commit()
            return True

    def next_batch(self, limit: int) -> list[sqlite3.Row]:
        with self._lock:
            cur = self.conn.execute(
                "SELECT * FROM hosts WHERE status IN ('new','retry') "
                "AND attempts < ? ORDER BY score DESC, last_seen ASC LIMIT ?",
                (999999, limit))
            rows = cur.fetchall()
            if rows:
                self.conn.executemany(
                    "UPDATE hosts SET status='scanning' WHERE ip=? AND port=?",
                    [(r["ip"], r["port"]) for r in rows])
                self.conn.commit()
            return rows

    def update_host(self, ip: str, port: int, **fields) -> None:
        if not fields:
            return
        cols = ", ".join(f"{k}=?" for k in fields)
        with self._lock:
            self.conn.execute(
                f"UPDATE hosts SET {cols} WHERE ip=? AND port=?",
                (*fields.values(), ip, port))
            self.conn.commit()

    def mark_dead(self, ip: str, port: int, cfg, note: str = "") -> None:
        with self._lock:
            self.conn.execute(
                "UPDATE hosts SET status='dead', next_scan=?, notes=?, last_seen=? "
                "WHERE ip=? AND port=?",
                (_iso(cfg.rescan_dead_hours), note, utcnow(), ip, port))
            self.conn.commit()

    def mark_alive(self, ip: str, port: int, cfg, **fields) -> None:
        fields.setdefault("attempts", 0)
        fields["status"] = "alive"
        fields["next_scan"] = _iso(cfg.rescan_alive_hours)
        fields["last_seen"] = utcnow()
        self.update_host(ip, port, **fields)

    # ---------------- vulns ----------------
    def record_vuln(self, ip: str, port: int, cve: str, confidence: str,
                    method: str, evidence: str, firmware: str = "") -> bool:
        now = utcnow()
        with self._lock:
            cur = self.conn.execute(
                "SELECT id FROM vulns WHERE ip=? AND port=? AND cve=?", (ip, port, cve))
            if cur.fetchone():
                self.conn.execute(
                    "UPDATE vulns SET confidence=?, method=?, evidence=?, firmware=?, "
                    "last_checked=? WHERE ip=? AND port=? AND cve=?",
                    (confidence, method, evidence, firmware, now, ip, port, cve))
                self.conn.commit()
                return False
            self.conn.execute(
                "INSERT INTO vulns (ip, port, cve, confidence, method, evidence, firmware, "
                "confirmed_at, last_checked) VALUES (?,?,?,?,?,?,?,?,?)",
                (ip, port, cve, confidence, method, evidence, firmware, now, now))
            self.conn.commit()
            return True

    # ---------------- subnets ----------------
    def add_subnet(self, cidr: str, source: str) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO subnets (cidr, source, added_at) VALUES (?,?,?)",
                (cidr, source, utcnow()))
            self.conn.commit()

    def subnets(self) -> list[str]:
        with self._lock:
            cur = self.conn.execute("SELECT cidr FROM subnets WHERE enabled=1")
            return [r["cidr"] for r in cur.fetchall()]

    # ---------------- source stats ----------------
    def source_ok(self, name: str, count: int) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO source_stats (name, last_ok, fail_streak, ips_total) "
                "VALUES (?,?,0,?) ON CONFLICT(name) DO UPDATE SET "
                "last_ok=excluded.last_ok, fail_streak=0, ips_total=ips_total+excluded.ips_total",
                (name, utcnow(), count))
            self.conn.commit()

    def source_fail(self, name: str, err: str) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO source_stats (name, last_error, fail_streak) VALUES (?,?,1) "
                "ON CONFLICT(name) DO UPDATE SET last_error=excluded.last_error, "
                "fail_streak=fail_streak+1", (name, err[:400]))
            self.conn.commit()

    def source_due(self, name: str, interval_hours: int) -> bool:
        with self._lock:
            cur = self.conn.execute(
                "SELECT last_ok, last_error, fail_streak FROM source_stats WHERE name=?",
                (name,))
            row = cur.fetchone()
        if not row:
            return True
        if row["fail_streak"] >= 5:
            # back off hard on persistent breakage
            interval_hours *= min(row["fail_streak"], 12)
        stamp = row["last_ok"] or row["last_error"]
        if not stamp:
            return True
        return datetime.fromisoformat(stamp) + timedelta(hours=interval_hours) < datetime.now(timezone.utc)

    # ---------------- runs / kv ----------------
    def start_run(self) -> int:
        with self._lock:
            cur = self.conn.execute("INSERT INTO runs (started) VALUES (?)", (utcnow(),))
            self.conn.commit()
            return int(cur.lastrowid)

    def finish_run(self, run_id: int, scanned: int, alive: int, new_ips: int, vulns: int) -> None:
        with self._lock:
            self.conn.execute(
                "UPDATE runs SET finished=?, scanned=?, alive=?, new_ips=?, vulns=? WHERE id=?",
                (utcnow(), scanned, alive, new_ips, vulns, run_id))
            self.conn.commit()

    def kv_set(self, k: str, v: str) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO kv (k,v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                (k, v))
            self.conn.commit()

    def kv_get(self, k: str, default: str = "") -> str:
        with self._lock:
            cur = self.conn.execute("SELECT v FROM kv WHERE k=?", (k,))
            row = cur.fetchone()
            return row["v"] if row else default

    # ---------------- exports ----------------
    def export_all(self, export_dir: str) -> dict:
        os.makedirs(export_dir, exist_ok=True)
        out = {}

        hosts = self.conn.execute("SELECT * FROM hosts ORDER BY score DESC").fetchall()
        out["all_ips.txt"] = _write_txt(
            os.path.join(export_dir, "all_ips.txt"), [r["ip"] for r in hosts])
        out["all_hosts.csv"] = _write_csv(
            os.path.join(export_dir, "all_hosts.csv"), hosts)
        out["alive_hosts.csv"] = _write_csv(
            os.path.join(export_dir, "alive_hosts.csv"),
            self.conn.execute(
                "SELECT * FROM hosts WHERE status IN ('alive','vuln') ORDER BY score DESC").fetchall())

        vulns = self.conn.execute(
            "SELECT * FROM vulns ORDER BY confidence, confirmed_at DESC").fetchall()
        out["vuln_ips.txt"] = _write_txt(
            os.path.join(export_dir, "vuln_ips.txt"), sorted({r["ip"] for r in vulns}))
        out["vulns.csv"] = _write_csv(os.path.join(export_dir, "vulns.csv"), vulns)
        out["vulns.jsonl"] = _write_jsonl(os.path.join(export_dir, "vulns.jsonl"), vulns)
        return out

    def stats(self) -> dict:
        q = lambda sql: self.conn.execute(sql).fetchone()[0]
        return {
            "hosts_total": q("SELECT COUNT(*) FROM hosts"),
            "hosts_alive": q("SELECT COUNT(*) FROM hosts WHERE status IN ('alive','vuln')"),
            "hosts_pending": q("SELECT COUNT(*) FROM hosts WHERE status IN ('new','retry')"),
            "vulns_total": q("SELECT COUNT(*) FROM vulns"),
            "vulns_confirmed": q("SELECT COUNT(*) FROM vulns WHERE confidence='confirmed'"),
            "subnets": q("SELECT COUNT(*) FROM subnets WHERE enabled=1"),
            "last_run": (self.conn.execute(
                "SELECT started FROM runs ORDER BY id DESC LIMIT 1").fetchone() or ["-"])[0],
        }


def _write_txt(path: str, rows: Iterable[str]) -> int:
    rows = list(rows)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(rows))
        if rows:
            fh.write("\n")
    return len(rows)


def _write_csv(path: str, rows: list) -> int:
    if not rows:
        open(path, "w").close()
        return 0
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(rows[0].keys())
        w.writerows([tuple(r) for r in rows])
    return len(rows)


def _write_jsonl(path: str, rows: list) -> int:
    with open(path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(dict(r), default=str) + "\n")
    return len(rows)
