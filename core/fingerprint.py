"""ASRock Rack / AMI MegaRAC identification."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from .net import Fetcher, Response

ASROCK_MARKERS = ["asrockrack", "asrock rack", "asrock-rack", "asrock_bmc"]
MEGARAC_MARKERS = ["megarac", "american megatrends", "ami spx", "spx bmc",
                   "redfishversion", "/redfish/v1", "qsessionalid", "ipmi"]
BMC_PATHS = ["/", "/redfish/v1/", "/api/", "/cgi/login.cgi", "/#login",
             "/redfish/v1/Managers/Self"]
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
FW_RE = re.compile(r'"(?:FirmwareVersion|Version)"\s*:\s*"([^"]{1,40})"')

KNOWN_FIXED = {
    # ASRock Rack advisory build numbers that contain the CVE-2024-54085 fix.
    # Compare only the numeric core; anything below is treated as suspect.
    "1.06.05", "1.05.10", "1.07.02", "2.01.00",
}


@dataclass
class Fingerprint:
    alive: bool = False
    asrock: bool = False
    megarac: bool = False
    redfish: bool = False
    title: str = ""
    server: str = ""
    firmware: str = ""
    score: int = 0
    evidence: list[str] = field(default_factory=list)

    @property
    def candidate(self) -> bool:
        return self.alive and (self.asrock or (self.megarac and self.redfish))

    @property
    def firmware_suspect(self) -> bool:
        if not self.firmware:
            return False
        core = re.sub(r"[^0-9.]", "", self.firmware).strip(".")
        if not core:
            return False
        return core not in KNOWN_FIXED and _ver_lt(core, max(KNOWN_FIXED, key=_vkey))


def _vkey(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4])


def _ver_lt(a: str, b: str) -> bool:
    return _vkey(a) < _vkey(b)


def _json_firmware(body: str) -> str:
    try:
        data = json.loads(body)
    except Exception:
        m = FW_RE.search(body)
        return m.group(1) if m else ""
    if isinstance(data, dict):
        for key in ("FirmwareVersion", "Version", "Oem"):
            val = data.get(key)
            if isinstance(val, str) and val:
                return val
    return ""


async def probe(fetcher: Fetcher, ip: str, port: int, scheme: str) -> Fingerprint:
    fp = Fingerprint()
    base = f"{scheme}://{ip}:{port}"
    body_all: list[str] = []

    for path in BMC_PATHS:
        resp: Response = await fetcher.get(base + path)
        if resp.error and not fp.alive:
            continue
        if resp.status == 0:
            continue
        fp.alive = True
        body_all.append(resp.body)
        low = resp.body.lower()
        srv = resp.headers.get("Server", "")
        if srv and not fp.server:
            fp.server = srv

        if any(m in low for m in ASROCK_MARKERS):
            fp.asrock = True
            fp.score += 60
            fp.evidence.append(f"ASRock marker at {path}")
        if any(m in low for m in MEGARAC_MARKERS) or "ami" in srv.lower():
            fp.megarac = True
            fp.score += 40
            fp.evidence.append(f"MegaRAC marker at {path}")
        if '"redfishversion"' in low or "redfish/v1" in low:
            fp.redfish = True
            fp.score += 25
            fp.evidence.append(f"Redfish service at {path}")
        if not fp.title:
            m = TITLE_RE.search(resp.body)
            if m:
                fp.title = m.group(1).strip()[:120]
                if any(t in fp.title.lower() for t in ("asrock", "megarac", "bmc")):
                    fp.score += 20
                    fp.evidence.append(f"title '{fp.title}'")
        if not fp.firmware and resp.body.strip().startswith("{"):
            fw = _json_firmware(resp.body)
            if fw:
                fp.firmware = fw
                fp.evidence.append(f"firmware {fw}")

    if fp.firmware_suspect:
        fp.score += 20
        fp.evidence.append(f"firmware {fp.firmware} below fixed builds")
    if fp.candidate:
        fp.score += 30
    return fp
