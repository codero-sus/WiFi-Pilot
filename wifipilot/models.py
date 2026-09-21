"""Domain model: access points, clients, captures, attempts, findings."""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from .util import clamp, mac_norm, now_iso, oui_vendor, slugify

# --------------------------------------------------------------------------- #
# enums (plain strings keep the JSON contract with the LLM trivial)
# --------------------------------------------------------------------------- #

ENCRYPTIONS = ("OPEN", "WEP", "WPA", "WPA2", "WPA3", "WPA2/WPA3", "OWE", "ENTERPRISE")
WPS_STATES = ("", "unlocked", "locked", "configured", "unknown")
CAPTURE_KINDS = ("handshake", "pmkid", "wep_ivs")

#: attack primitives the planner is allowed to choose from (whitelist!)
ATTACK_NAMES = (
    "handshake",      # deauth + 4-way capture
    "pmkid",          # client-less PMKID (hcxdumptool / airodump --pmkid)
    "wps_pixie",      # offline Pixie-Dust against WPS
    "wps_pin",        # online PIN brute force / default-PIN replay
    "wep_ivs",        # ARP-replay IV harvesting
    "passive",        # listen only, never transmit
)

STATUS_IDLE = "idle"
STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_SUCCESS = "success"
STATUS_FAILED = "failed"
STATUS_SKIPPED = "skipped"


@dataclass
class Client:
    """A station associated with (or probing) an access point."""

    mac: str
    bssid: str = ""            # AP it is associated with ("" when unassociated)
    signal: int = -100
    packets: int = 0
    probes: List[str] = field(default_factory=list)
    vendor: str = ""
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    handshake: bool = False

    def __post_init__(self) -> None:
        self.mac = mac_norm(self.mac) or self.mac
        if not self.vendor:
            self.vendor = oui_vendor(self.mac)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mac": self.mac, "bssid": self.bssid, "signal": self.signal,
            "packets": self.packets, "probes": self.probes[:5], "vendor": self.vendor,
            "handshake": self.handshake, "age": round(time.time() - self.last_seen, 1),
        }


@dataclass
class AccessPoint:
    """Everything we know about one BSSID."""

    bssid: str
    essid: str = ""
    channel: int = 0
    frequency: int = 0
    signal: int = -100
    encryption: str = "WPA2"
    cipher: str = "CCMP"
    auth: str = "PSK"
    privacy: bool = True
    wps: bool = False
    wps_version: str = ""
    wps_locked: str = ""
    wps_model: str = ""
    wps_device: str = ""
    wps_manufacturer: str = ""
    pmf: bool = False              # 802.11w management frame protection
    sae: bool = False              # WPA3-SAE
    sai: bool = False              # WPA3 transition mode indicator
    hidden: bool = False
    beacon_count: int = 0
    data_count: int = 0
    vendor: str = ""
    band: str = ""
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    clients: "OrderedDict[str, Client]" = field(default_factory=OrderedDict)
    captures: List["Capture"] = field(default_factory=list)
    attempts: List["Attempt"] = field(default_factory=list)
    status: str = STATUS_IDLE
    notes: str = ""
    # runtime bookkeeping
    handshake_ts: float = 0.0
    pmkid_ts: float = 0.0
    deauths_sent: int = 0
    score: float = 0.0
    picked_by: str = ""            # "heuristic" | "llm" | "operator"
    pick_reason: str = ""

    def __post_init__(self) -> None:
        self.bssid = mac_norm(self.bssid) or self.bssid
        if not self.vendor:
            self.vendor = oui_vendor(self.bssid)
        if not self.band:
            self.band = "5GHz" if self.frequency >= 4900 else "2.4GHz"

    # -- presentation ------------------------------------------------------
    @property
    def display_name(self) -> str:
        if self.essid:
            return self.essid
        if self.hidden:
            return "<hidden>"
        return f"<{self.bssid[-8:]}>"

    @property
    def signal_bar(self) -> str:
        if self.signal >= -50:
            return "▁▄█"
        if self.signal >= -60:
            return "▁▄▅"
        if self.signal >= -70:
            return "▁▄_"
        if self.signal >= -80:
            return "▁__"
        return "___"

    @property
    def quality(self) -> int:
        """0-100 signal quality, RSSI -> percentage."""
        return int(clamp(2 * (self.signal + 100), 0, 100))

    @property
    def security(self) -> str:
        if self.encryption == "WPA2/WPA3":
            return "WPA2+WPA3"
        return self.encryption

    @property
    def has_handshake(self) -> bool:
        return any(c.kind == "handshake" and c.valid for c in self.captures)

    @property
    def has_pmkid(self) -> bool:
        return any(c.kind == "pmkid" and c.valid for c in self.captures)

    @property
    def cracked(self) -> bool:
        return any(c.password for c in self.captures)

    @property
    def password(self) -> str:
        for cap in self.captures:
            if cap.password:
                return cap.password
        return ""

    @property
    def wps_open(self) -> bool:
        return self.wps and self.wps_locked not in ("locked", "configured")

    @property
    def client_list(self) -> List[Client]:
        return list(self.clients.values())

    def attackable(self, enabled: Optional[List[str]] = None) -> List[str]:
        """Which attack primitives make sense for this AP."""
        enabled = enabled or list(ATTACK_NAMES)
        out: List[str] = []
        if self.encryption in ("WPA", "WPA2", "WPA2/WPA3", "WPA3"):
            if "pmkid" in enabled:
                out.append("pmkid")
            if "handshake" in enabled and not self.sae:
                out.append("handshake")
        if self.wps and self.wps_open and "wps_pixie" in enabled:
            out.append("wps_pixie")
            if "wps_pin" in enabled:
                out.append("wps_pin")
        if self.encryption == "WEP" and "wep_ivs" in enabled:
            out.append("wep_ivs")
        if "passive" in enabled:
            out.append("passive")
        return out

    def add_client(self, client: Client) -> bool:
        key = client.mac
        existing = self.clients.get(key)
        if existing:
            existing.last_seen = client.last_seen
            existing.packets = max(existing.packets, client.packets)
            existing.signal = client.signal or existing.signal
            if client.bssid:
                existing.bssid = client.bssid
            for probe in client.probes:
                if probe and probe not in existing.probes:
                    existing.probes.append(probe)
            return False
        self.clients[key] = client
        return True

    def touch(self) -> None:
        self.last_seen = time.time()

    def to_dict(self, detail: bool = False,
                enabled: Optional[List[str]] = None) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "bssid": self.bssid,
            "essid": self.essid,
            "display_name": self.display_name,
            "channel": self.channel,
            "frequency": self.frequency,
            "band": self.band,
            "signal": self.signal,
            "quality": self.quality,
            "encryption": self.encryption,
            "security": self.security,
            "cipher": self.cipher,
            "auth": self.auth,
            "wps": self.wps,
            "wps_locked": self.wps_locked,
            "wps_version": self.wps_version,
            "wps_model": self.wps_model,
            "pmf": self.pmf,
            "sae": self.sae,
            "sai": self.sai,
            "hidden": self.hidden,
            "vendor": self.vendor,
            "clients": len(self.clients),
            "beacons": self.beacon_count,
            "data": self.data_count,
            "handshake": self.has_handshake,
            "pmkid": self.has_pmkid,
            "cracked": self.cracked,
            "password": self.password,
            "status": self.status,
            "score": round(self.score, 2),
            "picked_by": self.picked_by,
            "pick_reason": self.pick_reason,
            "deauths_sent": self.deauths_sent,
            "age": round(time.time() - self.last_seen, 1),
            "age_first": round(time.time() - self.first_seen, 1),
            "attacks": self.attackable(enabled),
            "captures": [c.to_dict() for c in self.captures],
            "notes": self.notes,
        }
        if detail:
            data["clients_list"] = [c.to_dict() for c in self.clients.values()]
            data["attempts"] = [a.to_dict() for a in self.attempts[-25:]]
        return data


@dataclass
class Capture:
    """An artifact: handshake, PMKID or WEP IV dump."""

    kind: str                     # handshake | pmkid | wep_ivs
    bssid: str
    essid: str = ""
    path: str = ""
    valid: bool = False
    tool: str = ""
    created: float = field(default_factory=time.time)
    eapol: int = 0
    size: int = 0
    password: str = ""
    crack_tool: str = ""
    crack_seconds: float = 0.0
    crack_attempts: int = 0
    hash_path: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def label(self) -> str:
        bits = [self.kind.upper(), self.essid or self.bssid]
        if self.password:
            bits.append(f"PSK={self.password}")
        return " · ".join(x for x in bits if x)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind, "bssid": self.bssid, "essid": self.essid,
            "path": self.path, "hash_path": self.hash_path, "valid": self.valid,
            "tool": self.tool, "created": now_iso(),
            "created_ts": self.created, "eapol": self.eapol, "size": self.size,
            "password": self.password, "crack_tool": self.crack_tool,
            "crack_seconds": round(self.crack_seconds, 2),
            "crack_attempts": self.crack_attempts, "label": self.label,
            "extra": self.extra,
        }


@dataclass
class Attempt:
    """One run of one attack primitive against one AP."""

    attack: str
    bssid: str
    started: float = field(default_factory=time.time)
    ended: float = 0.0
    status: str = STATUS_RUNNING
    result: str = ""
    capture: Optional[Capture] = None
    tool: str = ""
    command: str = ""
    detail: str = ""
    chosen_by: str = "heuristic"
    reason: str = ""

    @property
    def duration(self) -> float:
        return (self.ended or time.time()) - self.started

    @property
    def succeeded(self) -> bool:
        return self.status == STATUS_SUCCESS

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack": self.attack, "bssid": self.bssid,
            "started": self.started, "duration": round(self.duration, 1),
            "status": self.status, "result": self.result, "tool": self.tool,
            "command": self.command, "detail": self.detail,
            "chosen_by": self.chosen_by, "reason": self.reason,
            "capture": self.capture.to_dict() if self.capture else None,
        }


@dataclass
class Finding:
    """Something the operator (or the LLM) should care about."""

    kind: str                     # loot | risk | note | advice | error
    title: str
    detail: str = ""
    severity: str = "info"        # info | low | medium | high | critical
    bssid: str = ""
    created: float = field(default_factory=time.time)
    source: str = "core"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind, "title": self.title, "detail": self.detail,
            "severity": self.severity, "bssid": self.bssid,
            "source": self.source, "created": now_iso(), "created_ts": self.created,
        }


@dataclass
class SessionStats:
    started: float = field(default_factory=time.time)
    aps_seen: int = 0
    clients_seen: int = 0
    handshakes: int = 0
    pmkids: int = 0
    wps_cracks: int = 0
    wep_cracks: int = 0
    passwords: int = 0
    attacks_run: int = 0
    attacks_failed: int = 0
    deauths: int = 0
    crack_attempts: int = 0
    llm_calls: int = 0
    llm_tokens: int = 0
    llm_errors: int = 0
    llm_cost: float = 0.0              # USD spent on a paid provider (OpenRouter)

    @property
    def uptime(self) -> float:
        return time.time() - self.started

    @property
    def loot(self) -> int:
        return self.handshakes + self.pmkids + self.wps_cracks + self.wep_cracks

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["uptime"] = round(self.uptime, 1)
        data["loot"] = self.loot
        data["started"] = now_iso()
        return data


def loot_filename(ap: AccessPoint, cap: Capture, ext: str = ".cap") -> str:
    base = slugify(f"{cap.essid or 'hidden'}_{ap.bssid.replace(':', '')}")
    return base + ext
