"""CVE-2024-54085 — AMI MegaRAC Redfish host-interface authentication bypass.

Redfish resources below normally require a session token. When the bypass is
present they answer 200/201 with a valid payload to a fully anonymous client.
Verdicts are graded so you can filter noise.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from .net import Fetcher

CVE = "CVE-2024-54085"

# (method, path, body, expected marker in response)
PROBES = [
    ("GET", "/redfish/v1/Managers/Self", None, ("ManagerType", "FirmwareVersion", "Id")),
    ("GET", "/redfish/v1/Systems/Self", None, ("SystemType", "PowerState", "Id")),
    ("GET", "/redfish/v1/AccountService/Accounts", None, ("Members", "Accounts")),
    ("GET", "/redfish/v1/Managers/Self/NetworkProtocol", None, ("HTTPS", "SSH", "IPMI")),
    ("GET", "/redfish/v1/SessionService/Sessions", None, ("Members",)),
    ("POST", "/redfish/v1/SessionService/Sessions",
     {"UserName": "", "Password": ""}, ("Id", "token")),
]

CONFIDENCE_ORDER = {"suspect": 0, "likely": 1, "confirmed": 2}


@dataclass
class Verdict:
    vulnerable: bool = False
    confidence: str = "none"
    method: str = ""
    evidence: str = ""
    firmware: str = ""

    @property
    def rank(self) -> int:
        return CONFIDENCE_ORDER.get(self.confidence, -1)


def _looks_like_redfish(body: str) -> bool:
    try:
        data = json.loads(body)
    except Exception:
        return False
    if not isinstance(data, dict):
        return False
    keys = {k.lower() for k in data}
    return bool(keys & {"@odata.id", "@odata.type", "id", "members", "name"})


async def verify(fetcher: Fetcher, ip: str, port: int, scheme: str,
                 firmware: str = "") -> Verdict:
    base = f"{scheme}://{ip}:{port}"
    hits: list[str] = []
    firmware_seen = firmware

    for method, path, payload, markers in PROBES:
        if method == "POST":
            resp = await fetcher.post(base + path, json=payload)
        else:
            resp = await fetcher.get(base + path)

        if resp.status not in (200, 201):
            continue
        if not _looks_like_redfish(resp.body):
            continue

        hit = f"{method} {path} -> {resp.status}"
        if "X-Auth-Token" in resp.headers:
            hit += " (X-Auth-Token issued)"
            hits.append(hit)
            hits.append(hit)
            continue
        if any(m.lower() in resp.body.lower() for m in markers):
            hits.append(hit)
            continue
        hits.append(hit)

        if not firmware_seen:
            m = re.search(r'"FirmwareVersion"\s*:\s*"([^"]{1,40})"', resp.body)
            if m:
                firmware_seen = m.group(1)

    if not hits:
        return Verdict(firmware=firmware_seen)

    if len(hits) >= 2:
        confidence = "confirmed"
    else:
        confidence = "likely"

    return Verdict(vulnerable=True, confidence=confidence,
                   method="redfish-unauth-probe",
                   evidence="; ".join(dict.fromkeys(hits))[:1200],
                   firmware=firmware_seen)
