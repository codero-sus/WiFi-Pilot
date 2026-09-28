"""Discovery: turn airodump-ng / wash output into AccessPoint objects.

Live mode drives the real tools:

* ``airodump-ng --output-format csv`` for access points, clients, signal,
  encryption, cipher, auth, beacons and data frames (plus handshake detection)
* ``wash -i <mon> -a`` for WPS state (version, locked, model, manufacturer)
* optional ``hcxdumptool`` for PMKID (started by the pmkid attack module)

Demo mode drives :class:`wifipilot.demo.DemoRadio`, which fabricates a small
but realistically messy neighbourhood so the whole pipeline can be exercised
without a radio.
"""

from __future__ import annotations

import contextlib
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .config import Config
from .deps import registry
from .events import EK
from .session import Session
from .util import Process, mac_norm, safe_int

# --------------------------------------------------------------------------- #
# channel / band helpers
# --------------------------------------------------------------------------- #

CHANNELS_2G = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
CHANNELS_5G = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120,
               124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]


def band_channels(band: str) -> List[int]:
    if band == "2.4GHz":
        return list(CHANNELS_2G)
    if band == "5GHz":
        return list(CHANNELS_5G)
    return CHANNELS_2G + CHANNELS_5G


def freq_to_channel(freq: int) -> int:
    if not freq:
        return 0
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if freq == 2484:
        return 14
    if 5000 <= freq <= 5900:
        return (freq - 5000) // 5
    if 5955 <= freq <= 7115:
        return (freq - 5950) // 5
    return 0


def channel_to_freq(channel: int) -> int:
    if 1 <= channel <= 13:
        return 2407 + channel * 5
    if channel == 14:
        return 2484
    if channel >= 32:
        return 5000 + channel * 5
    return 0


def normalize_encryption(privacy: str, cipher: str = "", auth: str = "") -> Tuple[str, bool, bool]:
    """airodump's Privacy/Cipher/Auth columns -> (label, sae, pmf_required)."""
    privacy = (privacy or "").upper().strip()
    auth = (auth or "").upper().strip()
    cipher = (cipher or "").upper().strip()
    sae = "WPA3" in privacy or "SAE" in auth
    if "WPA3" in privacy and "WPA2" in privacy:
        return "WPA2/WPA3", sae, False
    if "WPA3" in privacy:
        return "WPA3", True, True
    if "WPA2" in privacy:
        return "WPA2", False, False
    if "WPA" in privacy:
        return "WPA", False, False
    if "WEP" in privacy or privacy == "WEP":
        return "WEP", False, False
    if "OWE" in privacy:
        return "OWE", False, True
    if privacy in ("OPN", "OPEN", ""):
        return ("OPEN", False, False) if not privacy else ("OPEN", False, False)
    if "WPA" in cipher:
        return "WPA", False, False
    return privacy or "OPEN", sae, False


# --------------------------------------------------------------------------- #
# parsers
# --------------------------------------------------------------------------- #

BSSID_COL = "BSSID"
_AP_HEADER_MARK = "BSSID, First time seen"


@dataclass
class ApRecord:
    bssid: str
    essid: str = ""
    channel: int = 0
    frequency: int = 0
    privacy: str = ""
    cipher: str = ""
    auth: str = ""
    signal: int = -100
    beacons: int = 0
    data: int = 0
    essid_len: int = 0
    key: str = ""
    lan_ip: str = ""


@dataclass
class ClientRecord:
    mac: str
    bssid: str = ""
    signal: int = -100
    packets: int = 0
    probes: List[str] = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0


def _clean(value: Optional[str]) -> str:
    return (value or "").strip()


def parse_airodump_csv(text: str) -> Tuple[List[ApRecord], List[ClientRecord]]:
    """Parse a full ``airodump-ng --output-format csv`` dump.

    Handles both the current multi-line header format and older single-line
    layouts, and tolerates any amount of missing/garbled rows (radios are
    noisy, the CSV is written asynchronously).
    """
    aps: List[ApRecord] = []
    clients: List[ClientRecord] = []
    if not text:
        return aps, clients

    # split into the AP block and the station block on the station header
    station_mark = re.search(r"^\s*Station MAC\b.*$", text, re.M)
    ap_block = text[: station_mark.start()] if station_mark else text
    station_block = text[station_mark.start():] if station_mark else ""

    for row in _csv_rows(ap_block):
        if len(row) < 13:
            continue
        bssid = mac_norm(row[0])
        if not bssid:
            continue
        if bssid.startswith("00:00:00"):
            continue
        try:
            channel = safe_int(row[3], 0)
        except IndexError:  # pragma: no cover
            channel = 0
        aps.append(ApRecord(
            bssid=bssid,
            essid=_clean(row[13]) if len(row) > 13 else "",
            channel=channel,
            frequency=channel_to_freq(channel),
            privacy=_clean(row[5]) if len(row) > 5 else "",
            cipher=_clean(row[6]) if len(row) > 6 else "",
            auth=_clean(row[7]) if len(row) > 7 else "",
            signal=safe_int(row[8], -100) if len(row) > 8 else -100,
            beacons=safe_int(row[9], 0) if len(row) > 9 else 0,
            data=safe_int(row[10], 0) if len(row) > 10 else 0,
            lan_ip=_clean(row[11]) if len(row) > 11 else "",
            essid_len=safe_int(row[12], 0) if len(row) > 12 else 0,
            key=_clean(row[14]) if len(row) > 14 else "",
        ))

    for row in _csv_rows(station_block):
        if len(row) < 6:
            continue
        if row[0].lower().startswith("station"):
            continue
        mac = mac_norm(row[0])
        if not mac or mac.startswith("00:00:00"):
            continue
        probes = [_clean(p) for p in row[6:] if _clean(p) and not _clean(p).startswith("(not associated)")]
        clients.append(ClientRecord(
            mac=mac,
            bssid=mac_norm(row[5]) if len(row) > 5 else "",
            signal=safe_int(row[3], -100) if len(row) > 3 else -100,
            packets=safe_int(row[4], 0) if len(row) > 4 else 0,
            probes=probes,
        ))
    return aps, clients


def _csv_rows(block: str) -> List[List[str]]:
    rows: List[List[str]] = []
    for line in block.splitlines():
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        stripped = line.strip()
        if stripped.startswith("BSSID,") or stripped.startswith("Station MAC,"):
            continue
        if stripped.upper().startswith("BSSID ") or stripped.startswith("Station MAC"):
            continue
        row = [cell.strip() for cell in line.split(",")]
        if len(row) < 3:
            continue
        if not re.match(r"^[0-9A-Fa-f:]{17}", row[0]):
            continue
        rows.append(row)
    return rows


WASH_LINE_RE = re.compile(
    r"^(?P<bssid>[0-9A-Fa-f:]{17})\s+(?P<channel>\d+)\s+(?P<rssi>-?\d+)\s+"
    r"(?P<wps>[0-9.]+)?\s*(?P<locked>Yes|No)?\s*"
    r"(?:(?P<version>[\d.]+)\s*)?(?P<state>[A-Za-z0-9._-]+)?\s*"
    r"(?P<model>.*?)\s{2,}(?P<manufacturer>.*)$"
)


def parse_wash(text: str) -> List[Dict[str, Any]]:
    """Parse ``wash -a`` output into WPS records (tolerant of version drift)."""
    out: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.rstrip()
        if not line or line.startswith("-") or "BSSID" in line[:16]:
            continue
        fields = line.split()
        if len(fields) < 5:
            continue
        bssid = mac_norm(fields[0])
        if not bssid:
            continue
        record: Dict[str, Any] = {"bssid": bssid}
        rest = fields[1:]
        if rest and rest[0].isdigit():
            record["wps_channel"] = safe_int(rest[0], 0)
            rest = rest[1:]
        if rest and re.match(r"^-?\d+$", rest[0]):
            record["wps_signal"] = safe_int(rest[0], -100)
            rest = rest[1:]
        if rest and rest[0].upper() in ("YES", "NO"):
            record["wps_locked"] = "locked" if rest[0].upper() == "YES" else "unlocked"
            rest = rest[1:]
        elif rest and rest[0].lower() in ("locked", "unlocked", "configured", "unknown"):
            record["wps_locked"] = rest[0].lower()
            rest = rest[1:]
        if rest and re.match(r"^[\d.]+$", rest[0]):
            record["wps_version"] = rest[0]
            rest = rest[1:]
        if rest and rest[0].lower() in ("configured", "unconfigured", "unknown"):
            record["wps_state"] = rest[0].lower()
            rest = rest[1:]
        if rest:
            record["wps_model"] = " ".join(rest[:2])
            record["wps_manufacturer"] = " ".join(rest[2:]) if len(rest) > 2 else ""
        out.append(record)
    return out


# --------------------------------------------------------------------------- #
# scanner
# --------------------------------------------------------------------------- #


class Scanner:
    """Runs discovery in a background thread and feeds the session."""

    def __init__(self, session: Session, iface=None, config: Optional[Config] = None,
                 demo_radio=None, verbose: bool = False):
        self.session = session
        self.iface = iface
        self.config = config or session.config
        self.bus = session.bus
        self.verbose = verbose
        self.demo_radio = demo_radio
        self.thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._proc: Optional[Process] = None
        self._wash_proc: Optional[Process] = None
        self._csv_prefix = ""
        self._csv_seen_mtime = 0.0
        self._last_wps_refresh = 0.0
        self._last_stats = 0.0
        self._last_publish: Dict[str, float] = {}
        self._started_at = 0.0
        self.start_count = 0
        self.error = ""
        self.handshake_watch: Dict[str, bool] = {}
        self.new_aps_since_think = 0

    # -- public API --------------------------------------------------------
    @property
    def running(self) -> bool:
        return bool(self.thread and self.thread.is_alive() and not self._stop.is_set())

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._started_at = time.time()
        self.start_count += 1
        self.session.scanning = True
        self.bus.publish(EK.SCAN_START, {
            "demo": self.session.demo, "band": self.config.band,
            "channel_hop": self.config.channel_hop,
        })
        self.thread = threading.Thread(target=self._run, name="scanner", daemon=True)
        self.thread.start()

    def stop(self, timeout: float = 6.0) -> None:
        self._stop.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=timeout)
        self._teardown()
        self.session.scanning = False
        self.bus.publish(EK.SCAN_STOP, {"aps": len(self.session.aps)})

    def _teardown(self) -> None:
        for proc in (self._proc, self._wash_proc):
            if proc is not None:
                with contextlib.suppress(Exception):
                    proc.stop()
        self._proc = None
        self._wash_proc = None

    def sweep(self, seconds: float) -> None:
        """Blocking discovery sweep (used by ``wifipilot scan``/``attack``)."""
        self.start()
        deadline = time.time() + seconds
        try:
            while time.time() < deadline:
                time.sleep(0.4)
        finally:
            self.stop()
        self.bus.log(f"discovery finished: {len(self.session.aps)} APs, "
                     f"{self.session.stats.clients_seen} clients", level="success")

    def stats(self) -> Dict[str, Any]:
        return {
            "running": self.running,
            "elapsed": round(time.time() - self._started_at, 1) if self._started_at else 0,
            "aps": len(self.session.aps),
            "clients": sum(len(ap.clients) for ap in self.session.aps.values()),
            "error": self.error,
        }

    # -- worker ------------------------------------------------------------
    def _run(self) -> None:
        try:
            if self.session.demo:
                self._run_demo()
            else:
                self._run_live()
        except Exception as exc:  # pragma: no cover - defensive
            self.error = str(exc)
            self.bus.error(f"scanner crashed: {exc}")
        finally:
            self._teardown()

    def _run_demo(self) -> None:
        radio = self.demo_radio
        if radio is None:
            self.error = "demo mode without a radio"
            return
        while not self._stop.is_set():
            for record in radio.tick():
                self._apply(record)
            self._publish_stats()
            self._stop.wait(1.0)

    def _run_live(self) -> None:
        airodump = registry.path("airodump-ng")
        if not airodump:
            self.error = "airodump-ng not found"
            self.bus.error("airodump-ng is required for discovery (apt install aircrack-ng)")
            return
        monitor = (self.iface.monitor if self.iface else "") or self.config.monitor_interface
        if not monitor:
            self.error = "no monitor interface"
            self.bus.error("scanner started without a monitor interface")
            return
        self._csv_prefix = os.path.join(self.session.state_dir, "scan", f"scan-{self.start_count}")
        Path(self._csv_prefix).parent.mkdir(parents=True, exist_ok=True)

        args = [airodump, monitor, "--output-format", "csv", "--write",
                self._csv_prefix, "--write-interval", "1", "--ignore-negative-one"]
        if self.config.band == "2.4GHz":
            args += ["--band", "bg"]
        elif self.config.band == "5GHz":
            args += ["--band", "a"]
        else:
            args += ["--band", "abg"]
        channels = self.config.channels or ([] if self.config.channel_hop and not self.config.channels else [])
        if channels:
            args += ["-c", ",".join(str(c) for c in channels)]

        if self.verbose:
            self.bus.log(f"starting: {' '.join(args)}", level="debug")
        self._proc = Process(args, name="airodump-ng", echo_lines=self.config.verbose_tools,
                             on_line=self._on_airodump_line)
        if self.iface is not None:
            self.iface.stop_hop()
        self._proc.start()
        if self._proc.error:
            self.error = self._proc.error
            self.bus.error(f"failed to start airodump-ng: {self._proc.error}")
            return
        self.bus.log(f"discovery running on {monitor} (band {self.config.band})", level="success")
        self._maybe_start_wash(monitor)

        while not self._stop.is_set() and self._proc.running:
            self._parse_csv()
            self._refresh_wps()
            self._publish_stats()
            self._stop.wait(1.0)
        if self._proc and not self._proc.running and not self._stop.is_set():
            tail = self._proc.tail
            if tail:
                self.error = tail.splitlines()[-1]
            self.bus.warn(f"airodump-ng exited early: {self.error}")

    # -- airodump / wash ---------------------------------------------------
    def _on_airodump_line(self, line: str) -> None:
        """Watch airodump's status line and its handshake announcements."""
        if "WPA handshake:" in line:
            bssid = mac_norm(line.split("WPA handshake:")[1].strip().split()[0])
            if bssid:
                self.handshake_watch[bssid] = True
                self.bus.publish(EK.CAPTURE_PROGRESS, {
                    "label": f"handshake seen for {bssid}", "kind": "capture",
                    "bssid": bssid, "detail": line.strip()[:160],
                })
        match = re.search(r"CH\s+(\d+)", line)
        if match and self.iface is not None:
            self.iface.current_channel = safe_int(match.group(1), 0)
        if self.verbose and ("Elapsed" in line or "handshake" in line):
            self.bus.log(line.strip()[:200], level="debug")

    def _parse_csv(self) -> None:
        path = self._csv_path()
        if not path:
            return
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            return
        if mtime == self._csv_seen_mtime:
            return
        self._csv_seen_mtime = mtime
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        aps, clients = parse_airodump_csv(text)
        for record in aps:
            self._apply_ap(record)
        for record in clients:
            self._apply_client(record)

    def _csv_path(self) -> str:
        for suffix in ("-01.csv", ".csv", "-01.csv.tmp", ".csv.tmp"):
            candidate = self._csv_prefix + suffix
            if os.path.exists(candidate):
                return candidate
        return ""

    def _maybe_start_wash(self, monitor: str) -> None:
        if not self.config.attacks or "wps_pixie" not in self.config.attacks:
            if "wps_pin" not in self.config.attacks:
                return
        wash = registry.path("wash")
        if not wash:
            return
        args = [wash, "-i", monitor, "-a"]
        if self.config.band == "2.4GHz":
            args += ["-b", "2"]
        elif self.config.band == "5GHz":
            args += ["-b", "5"]
        self._wash_proc = Process(
            args, name="wash", echo_lines=self.config.verbose_tools,
            on_line=self._on_wash_line,
        )
        self._wash_proc.start()
        if self._wash_proc.error:
            self.bus.log(f"wash unavailable: {self._wash_proc.error}", level="debug")

    def _on_wash_line(self, line: str) -> None:
        if not re.match(r"^[0-9A-Fa-f:]{17}", line):
            return
        for record in parse_wash(line):
            bssid = record.pop("bssid")
            self._apply_wps(bssid, record)

    def _refresh_wps(self) -> None:
        """Housekeeping hook: WPS data arrives via wash stdout, so nothing to poll."""
        self._last_wps_refresh = time.time()

    # -- record application ------------------------------------------------
    def _apply(self, record: Any) -> None:
        if isinstance(record, ApRecord):
            self._apply_ap(record)
        elif isinstance(record, ClientRecord):
            self._apply_client(record)
        elif isinstance(record, dict):
            if "bssid" in record and "mac" not in record:
                payload = dict(record)
                self._apply_wps(payload.pop("bssid"), payload)
            elif "mac" in record:
                self._apply_client(ClientRecord(**record))

    def _apply_ap(self, record: ApRecord) -> None:
        encryption, sae, pmf = normalize_encryption(record.privacy, record.cipher, record.auth)
        existing = self.session.ap(record.bssid)
        hidden = not record.essid or record.essid.lower() in ("<length: 0>", "")
        if existing and hidden and existing.essid:
            record.essid = existing.essid
            hidden = False
        ap, created = self.session.upsert_ap(
            record.bssid,
            record.essid,
            channel=record.channel or (existing.channel if existing else 0),
            frequency=record.frequency or (existing.frequency if existing else 0),
            privacy=bool(record.privacy),
            cipher=record.cipher or "CCMP",
            auth=record.auth or "PSK",
            encryption=encryption,
            sae=sae,
            sai=encryption == "WPA2/WPA3",
            pmf=pmf,
            signal=record.signal,
            hidden=hidden,
            beacon_count=record.beacons,
            data_count=record.data,
            publish=self._should_publish(record.bssid),
        )
        if created:
            self.new_aps_since_think += 1
            self.bus.log(f"new AP {ap.display_name} ({ap.bssid}) ch{ap.channel} "
                         f"{ap.signal}dBm {ap.security}"
                         + (f" vendor={ap.vendor}" if ap.vendor else ""), level="ap")

    def _should_publish(self, bssid: str, interval: float = 2.5) -> bool:
        now = time.time()
        if now - self._last_publish.get(bssid, 0) >= interval:
            self._last_publish[bssid] = now
            return True
        return False

    def _apply_client(self, record: ClientRecord) -> None:
        target = record.bssid
        if not target and record.probes:
            for ap in self.session.aps.values():
                if ap.essid and ap.essid in record.probes:
                    target = ap.bssid
                    break
        if not target:
            return
        self.session.add_client(target, record.mac, signal=record.signal,
                                packets=record.packets, probes=record.probes)

    def _apply_wps(self, bssid: str, record: Dict[str, Any]) -> None:
        ap = self.session.ap(bssid)
        if ap is None:
            ap, _ = self.session.upsert_ap(bssid, "", publish=False)
        changed = False
        for key, value in record.items():
            attr = key if hasattr(ap, key) else None
            if attr and value not in (None, "") and getattr(ap, attr) != value:
                setattr(ap, attr, value)
                changed = True
        ap.wps = True
        if not ap.wps_locked:
            ap.wps_locked = "unknown"
        if changed:
            self.bus.publish(EK.AP_UPDATE, ap.to_dict())

    def _publish_stats(self) -> None:
        if time.time() - self._last_stats < 2.0:
            return
        self._last_stats = time.time()
        stats = self.stats()
        stats["aps"] = len(self.session.aps)
        stats["loot"] = self.session.stats.loot
        self.bus.publish(EK.SCAN_STATS, stats)


# --------------------------------------------------------------------------- #
# helpers used by the attack modules
# --------------------------------------------------------------------------- #


def parse_crack_output(text: str) -> List[Tuple[str, str]]:
    """Extract ``BSSID:KEY`` pairs from aircrack-ng output."""
    found = []
    for match in re.finditer(r"([0-9A-Fa-f:]{17})\s*:?\s*\n?\s*KEY FOUND!?\s*\[?\s*([^\]]+?)\s*\]?$",
                             text, re.M):
        found.append((match.group(1).lower(), match.group(2).strip()))
    for match in re.finditer(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", text):
        found.append(("", match.group(1)))
    return found


def parse_aireplay_stats(text: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    match = re.search(r"(\d+)\s+packets?\s+transmitted", text)
    if match:
        out["sent"] = int(match.group(1))
    match = re.search(r"#Data:\s*(\d+)", text)
    if match:
        out["data"] = int(match.group(1))
    return out


def parse_handshake_progress(line: str) -> Dict[str, Any]:
    """airodump prints ``WPA handshake: AA:BB:...`` when it sees one."""
    out: Dict[str, Any] = {}
    match = re.search(r"WPA handshake:\s*([0-9A-Fa-f:]{17})", line)
    if match:
        out["handshake_bssid"] = match.group(1).lower()
    match = re.search(r"CH\s+(\d+)", line)
    if match:
        out["channel"] = int(match.group(1))
    return out
