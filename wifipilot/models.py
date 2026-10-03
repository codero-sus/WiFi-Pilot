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

#: attack primitives the planner is allowed to choose from (whitelist!).  Every
#: name here is registered in ``wifipilot.attacks.ATTACK_CLASSES`` and described in
#: ``wifipilot.attacks.meta``; a test keeps the three lists in step.
ATTACK_NAMES = (
    # offline: files the session already has, no radio, no authorisation
    "loot_audit",       # what is in the session's loot, and what is missing
    "eapol_audit",      # decode the EAPOL exchanges already captured
    "wep_audit",        # count IVs/ARP in a WEP capture and say what is missing
    "crack_sweep",      # every usable hash the session holds -> the cracker
    "eap_md5_crack",    # EAP-MD5 offline dictionary (RFC 2759)
    "pixie_offline",    # pixiewps against a stored WPS exchange
    "rogue_detect",     # rogue/twin infrastructure in the captures
    "twin_detect",      # identical SSIDs, different vendors
    "roam_audit",       # 802.11k/r/v and PMF posture
    "wps_lockout_audit",  # lockout policy of WPS APs already seen
    # capture
    "handshake",      # deauth + 4-way capture
    "handshake_broadcast",  # the same, deauthenticating every client at once
    "pmkid",          # client-less PMKID (hcxdumptool / airodump --pmkid)
    "pmkid_flood",    # active PMKID hunt: deauth to force M1 with a PMKID
    "hcxdump_capture",  # the hcxdumptool -> hcxpcapngtool pipeline
    # read-only surveys
    "passive",        # listen only, never transmit
    "pmf_audit",      # RSN/PMF audit: which classic attacks are still possible
    "saewolf",        # WPA3 SAE capture + transition-mode analysis
    "sae_group_audit",  # SAE groups, H2E and PMF posture from a capture
    "ie_audit",       # decode the elements airodump's CSV throws away
    "pnl_harvest",    # what clients are asking for, and which names are not on air
    "hidden_ssid",    # name a hidden network from probe responses/associations
    "tracker",        # follow one station: its real PNL, its signal trend
    "rogue_ap",       # read-only twin/attacker-infrastructure survey
    "enterprise",     # 802.1X survey: method, identity, server certificate
    # WPS / WEP
    "wps_pixie",      # offline Pixie-Dust against WPS
    "wps_ap_pin",     # vendor-derived static AP PIN
    "wps_lockout_probe",  # measure the lockout policy with three wrong PINs
    "wps_pbc",        # push-button enrolment: is a window open?
    "wps_pin",        # online PIN brute force / default-PIN replay
    "wep_ivs",        # ARP-replay IV harvesting
    "wep_p0841",      # injected ARP (P0841) so the IV harvest can run
    "wep_chopchop",   # KoreK chopchop: keystream without the key
    "wep_fragment",   # fragmentation attack: PRGA for injection
    "wep_hirte",      # client-oriented fragmentation
    "eapol_logoff",   # unauthenticated disconnect (PMF does not cover EAPOL)
    # rogue infrastructure, lures, impersonation
    "karma",          # answer every probe request and see who trusts the name
    "karma_detect",   # probes for names that cannot exist: find a Karma device
    "csa_attack",     # channel-switch announcement: silent eviction
    "ssid_confusion",  # the same SSID from a new BSSID
    "ssid_bruteforce",  # dictionary probes against a hidden network
    "ap_isolation_audit",  # can one client reach another? (spoofed ARP)
    "evil_twin",      # serve the SSID ourselves and see who prefers it
    "rogue_radius",   # impersonate the AP: will a client trust any certificate?
    # denial of service (opt-in, always, and capped in time)
    "deauth_flood",   # denial-of-service / WIDS detection test
    "auth_flood",     # authentication flood: association-table exhaustion test
    "assoc_flood",    # association flood: state exhaustion, no external tool
    "null_data_flood",  # power-save buffer exhaustion: no deauth frames at all
    "probe_flood",    # probe flood: hidden-SSID disclosure test
    "eapol_start_flood",  # 802.1X session exhaustion (enterprise)
    "sae_commit_flood",  # WPA3 CPU exhaustion: commits before authentication
    "tkip_michael",   # replay two corrupted TKIP frames: 60-second shutdown
    "wids_confusion",  # deauths carrying a neighbour's BSSID
    "beacon_flood",   # beacon-flood / WIDS detection test
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
    #: recent signal readings, oldest first (bounded): the tracker reads the trend
    signal_history: List[int] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.mac = mac_norm(self.mac) or self.mac
        if not self.vendor:
            self.vendor = oui_vendor(self.mac)

    def remember_signal(self, signal: int, keep: int = 60) -> None:
        """Record one signal reading, keeping the list bounded."""
        if not signal:
            return
        self.signal_history.append(int(signal))
        if len(self.signal_history) > keep:
            del self.signal_history[:-keep]

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
    #: free-form operator tags (put in scope, out of scope, retest, ...)
    tags: List[str] = field(default_factory=list)
    #: what happened to this AP, oldest first (bounded; see ``remember``)
    history: List[Dict[str, Any]] = field(default_factory=list)
    #: a coarse classification, useful for filtering and reporting
    target_kind: str = ""
    #: vendor dossier key (see :mod:`wifipilot.vendors`), never a measurement
    vendor_profile: str = ""
    #: operator notes / advice attached to this AP
    notes: str = ""
    pmf: bool = False              # 802.11w management frame protection
    sae: bool = False              # WPA3-SAE
    sai: bool = False              # WPA3 transition mode indicator
    pmf_checked: bool = False      # the RSN/PMF audit has read this AP's elements
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
        """Which attack primitives make sense for this AP, best first.

        This is the *advisory* list shown next to a target (and in the report),
        ordered the way the planner would run them: read-only surveys first, the
        attacks that need no client before the ones that do, and the disruptive
        ones last.
        """
        enabled = enabled or list(ATTACK_NAMES)
        out: List[str] = []

        def add(name: str, when: bool = True) -> None:
            if when and name in enabled and name not in out:
                out.append(name)

        # read-only: these change what we know and transmit nothing
        add("ie_audit")
        add("pmf_audit")
        add("hidden_ssid", not (self.essid or "").strip())
        add("pnl_harvest")
        add("tracker", bool(self.clients))
        add("rogue_ap")
        enterprise = (self.encryption in ("WPA-ENTERPRISE", "WPA2-ENTERPRISE",
                                          "ENTERPRISE")
                      or (self.auth or "").upper() in ("MGT", "802.1X", "ENTERPRISE"))
        add("enterprise", enterprise)
        add("rogue_radius", enterprise)
        add("saewolf", bool(self.sae or "WPA3" in (self.encryption or "")))
        # capture
        if self.encryption in ("WPA", "WPA2", "WPA2/WPA3", "WPA3"):
            add("pmkid", not self.has_pmkid)
            add("pmkid_flood", bool(self.clients) and not self.has_pmkid)
            add("handshake", not self.sae and not self.has_handshake)
            add("eapol_logoff", bool(self.clients) and not self.pmf)
        if self.wps and self.wps_open:
            add("wps_pixie")
            add("wps_pin")
        if self.encryption == "WEP":
            add("wep_ivs")
            add("wep_p0841")
            add("wep_chopchop", not self.clients)
            add("wep_fragment", not self.clients)
            add("wep_hirte", bool(self.clients))
        # rogue infrastructure and the denial-of-service tests, last
        add("evil_twin", bool((self.essid or "").strip()) and not enterprise)
        add("karma", not enterprise)
        add("deauth_flood")
        add("auth_flood")
        add("probe_flood")
        add("beacon_flood")
        add("passive")
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

    # -- engagement bookkeeping (see Session.add_note / tag_ap) ---------- #
    def tag(self, name: str, add: bool = True) -> List[str]:
        """Add or remove a tag; returns the tags on this AP afterwards."""
        name = str(name).strip().lower()[:32]
        if not name:
            return list(self.tags)
        if add:
            if name not in self.tags:
                self.tags.append(name)
        else:
            self.tags = [existing for existing in self.tags if existing != name]
        return list(self.tags)

    def remember(self, kind: str, detail: str = "", **extra: Any) -> Dict[str, Any]:
        """Append one line to this AP's history (newest last, bounded at 50)."""
        entry = {"ts": time.time(), "kind": kind, "detail": detail, **extra}
        self.history.append(entry)
        del self.history[:-50]
        return entry

    @property
    def vendor_key(self) -> str:
        """Dossier key for this AP's vendor (``"AVM"``, ``"TP-Link"``, ...)."""
        from .vendors import _key_for
        return _key_for(self.vendor or "")

    def enrich(self) -> Dict[str, Any]:
        """Add everything that can be derived from the OUI and the SSID.

        Idempotent: safe to call on every scan round.  Returns what it added so
        the caller can log it.
        """
        from .analytics import guess_vendor, identify
        from .vendors import vendor_dossier
        added: Dict[str, Any] = {}
        if not self.vendor:
            guess = guess_vendor(self.essid, self.bssid)
            if guess:
                self.vendor = guess
                added["vendor"] = guess
        if not self.vendor_key:
            key = vendor_dossier(self.bssid).get("key", "") if self.bssid else ""
            if key:
                added["vendor"] = self.vendor or key
        if not self.target_kind:
            self.target_kind = classify_target(self)
            added["target_kind"] = self.target_kind
        if not self.vendor_profile:
            profile = vendor_dossier(self.vendor or self.bssid)
            if profile.get("matched"):
                self.vendor_profile = str(profile.get("key", ""))
                added["vendor_profile"] = self.vendor_profile
        if not self.notes:
            info = identify(self.essid, self.vendor or "")
            if info.get("scheme"):
                self.notes = str(info.get("advice") or info.get("scheme_note") or "")
                added["notes"] = self.notes[:80]
        return added

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
            "pmf_checked": self.pmf_checked,
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
            "tags": list(self.tags),
            "target_kind": self.target_kind,
            "vendor_profile": self.vendor_profile,
        }
        if detail:
            data["clients_list"] = [c.to_dict() for c in self.clients.values()]
            data["attempts"] = [a.to_dict() for a in self.attempts[-25:]]
            data["history"] = list(self.history)
        return data


def classify_target(ap: "AccessPoint") -> str:
    """A coarse label: what *kind* of network this looks like.

    Used for filtering (``wifipilot targets --kind guest``) and reporting; it is
    a heuristic over the data already collected, not a measurement.
    """
    essid = (ap.essid or "").lower()
    if not ap.essid:
        return "hidden"
    if any(token in essid for token in ("guest", "gast", "visitor", "_vip")):
        return "guest"
    if any(token in essid for token in ("iot", "smart", "camera", "cam-", "printer",
                                        "thermostat", "light", "plug")):
        return "iot"
    if "tetra" in essid or "police" in essid or "eduroam" in essid:
        return "public-safety"
    if ap.vendor_key in ("AVM", "TP-Link", "Netgear", "D-Link", "ASUS", "Huawei",
                         "Zyxel", "ARRIS", "Cisco") or ap.encryption in ("WPA2", "WPA", "WPA2/WPA3"):
        if len(ap.clients) > 8:
            return "small-business"
        return "home-router"
    if ap.encryption == "OPEN":
        return "open"
    if ap.encryption == "WPA3":
        return "wpa3-only"
    return "wireless"


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
    #: which stage produced this: attack | manual | imported | demo
    found_in: str = ""
    #: operator note attached to this capture
    note: str = ""

    @property
    def label(self) -> str:
        bits = [self.kind.upper(), self.essid or self.bssid]
        if self.password:
            bits.append(f"PSK={self.password}")
        return " · ".join(x for x in bits if x)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind, "bssid": self.bssid, "essid": self.essid,
            "found_in": self.found_in, "note": self.note,
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
    #: structured payload the attack produced (survey findings, PIN candidates...)
    extra: Dict[str, Any] = field(default_factory=dict)

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
            "extra": self.extra,
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
    # -- intelligence gathered without a single injection ------------------
    hidden_revealed: int = 0           # SSIDs learned from hidden networks
    probes_seen: int = 0               # probe requests from clients (PNL)
    rogue_twins: int = 0               # twin/rogue patterns reported
    enterprise_surveys: int = 0        # 802.1X exchanges captured
    rogue_radius: int = 0              # rogue-RADIUS attempts that reached a client
    sae_captures: int = 0              # SAE exchanges captured for the report
    pmf_audits: int = 0                # RSN/PMF audits run
    twins_run: int = 0                 # evil twins that lured at least one station
    floods_run: int = 0                # denial-of-service tests run
    wep_enablers: int = 0              # WEP injection techniques that succeeded
    ie_audits: int = 0                 # beacon-element configuration audits run
    pnl_harvests: int = 0              # preferred-network-list harvests
    logoffs: int = 0                   # EAPOL-Logoff attempts delivered
    offline_audits: int = 0            # analyses that never transmitted anything
    rogue_detections: int = 0          # rogue/twin patterns found in a capture
    lure_runs: int = 0                 # channel-switch / SSID-confusion lures sent
    wps_probes: int = 0                # WPS lockout/PIN probes answered maybe
    wps_lockouts_missing: int = 0      # APs found without a WPS lockout policy
    karma_runs: int = 0                # Karma attempts run
    stations_tracked: int = 0          # stations followed for a signal trend
    probing_clients: int = 0           # clients whose PNL was read out of a capture
    pmk_hits: int = 0                  # captures "cracked" from the PMK cache
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
