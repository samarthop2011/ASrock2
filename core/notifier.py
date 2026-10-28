"""Out-of-band alerting for confirmed findings."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .net import Fetcher

CONF_ORDER = {"suspect": 0, "likely": 1, "confirmed": 2}


def should_notify(cfg, confidence: str) -> bool:
    return CONF_ORDER.get(confidence, -1) >= CONF_ORDER.get(cfg.notify_min_confidence, 1)


def format_hit(ip: str, port: int, scheme: str, verdict, fp) -> str:
    return (
        f"ASRock Rack / MegaRAC hit — {verdict.confidence.upper()}\n"
        f"URL: {scheme}://{ip}:{port}\n"
        f"Title: {fp.title or '-'}\n"
        f"Server: {fp.server or '-'}\n"
        f"Firmware: {verdict.firmware or fp.firmware or '-'}\n"
        f"Method: {verdict.method}\n"
        f"Evidence: {verdict.evidence}\n"
        f"Time: {datetime.now(timezone.utc).isoformat(timespec='seconds')}"
    )


async def notify(fetcher: Fetcher, cfg, text: str) -> None:
    if cfg.discord_webhook:
        await fetcher.post(cfg.discord_webhook, json={"content": text[:1900]})
    if cfg.slack_webhook:
        await fetcher.post(cfg.slack_webhook, json={"text": text})
    if cfg.generic_webhook:
        await fetcher.post(cfg.generic_webhook, json={"text": text})
    if cfg.telegram_bot_token and cfg.telegram_chat_id:
        await fetcher.post(
            f"https://api.telegram.org/bot{cfg.telegram_bot_token}/sendMessage",
            json={"chat_id": cfg.telegram_chat_id, "text": text[:3900]})
