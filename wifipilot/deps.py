"""External tool registry: detection, version probing and install hints.

wifipilot is a *driver*: it orchestrates the classic aircrack-ng toolchain
rather than reimplementing 802.11 in Python.  This module knows where each
binary lives, whether it is usable, and what to tell the operator when it is
missing.
"""

from __future__ import annotations

import re
import shutil
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .util import CommandResult, is_root, which

# --------------------------------------------------------------------------- #
# tool definitions
# --------------------------------------------------------------------------- #


@dataclass
class ToolSpec:
    name: str
    purpose: str
    package: str = ""
    version_args: List[str] = field(default_factory=lambda: ["--help"])
    required: bool = False
    category: str = "core"
    alternatives: List[str] = field(default_factory=list)


TOOLS: Dict[str, ToolSpec] = {
    t.name: t
    for t in [
        ToolSpec("aircrack-ng", "WPA/WEP key cracking + capture validation", "aircrack-ng",
                 ["--help"], required=True, category="core"),
        ToolSpec("airmon-ng", "monitor mode / interface management", "aircrack-ng",
                 ["--help"], required=True, category="core"),
        ToolSpec("airodump-ng", "passive discovery + capture", "aircrack-ng",
                 ["--help"], required=True, category="core"),
        ToolSpec("aireplay-ng", "deauthentication + injection tests", "aircrack-ng",
                 ["--help"], category="core"),
        ToolSpec("airdecap-ng", "decrypt verified captures", "aircrack-ng",
                 ["--help"], category="optional"),
        ToolSpec("wash", "WPS AP discovery", "reaver",
                 ["--help"], category="wps"),
        ToolSpec("reaver", "WPS Pixie-Dust / PIN attacks", "reaver",
                 ["--help"], category="wps"),
        ToolSpec("bully", "alternative WPS implementation", "bully",
                 ["--help"], category="wps"),
        ToolSpec("pixiewps", "offline WPS Pixie-Dust solver", "pixiewps",
                 ["--help"], category="wps"),
        ToolSpec("hcxdumptool", "client-less PMKID capture", "hcxtools",
                 ["--help"], category="pmkid"),
        ToolSpec("hcxpcapngtool", "convert captures to hashcat 22000", "hcxtools",
                 ["--help"], category="pmkid"),
        ToolSpec("hashcat", "GPU/CPU hash cracking", "hashcat",
                 ["--version"], category="crack"),
        ToolSpec("john", "CPU cracking (WPA-PMKID format)", "john",
                 ["--help"], category="crack"),
        ToolSpec("cowpatty", "WPA-PSK dictionary attack", "cowpatty",
                 ["-h"], category="crack"),
        ToolSpec("iw", "modern nl80211 interface control", "iw",
                 ["--version"], category="iface"),
        ToolSpec("iwconfig", "legacy wireless extensions", "wireless-tools",
                 ["--version"], category="iface"),
        ToolSpec("nmcli", "NetworkManager interface listing", "network-manager",
                 ["--version"], category="iface"),
        ToolSpec("rfkill", "unblock wireless radios", "rfkill",
                 ["--help"], category="iface"),
        ToolSpec("ethtool", "driver / channel information", "ethtool",
                 ["--version"], category="iface"),
        ToolSpec("tcpdump", "packet capture fallback", "tcpdump",
                 ["--version"], category="optional"),
        ToolSpec("tshark", "pcaps -> hashcat conversion fallback", "tshark",
                 ["-v"], category="optional"),
    ]
}

#: minimum a truly functional run needs
REQUIRED_FOR_LIVE = ("aircrack-ng", "airmon-ng", "airodump-ng")

INSTALL_HINTS = {
    "aircrack-ng": "apt install aircrack-ng   |   pacman -S aircrack-ng   |   brew install aircrack-ng",
    "reaver": "apt install reaver           |   pacman -S reaver",
    "wash": "apt install reaver           |   pacman -S reaver",
    "bully": "apt install bully            |   pacman -S bully",
    "pixiewps": "apt install pixiewps        |   pacman -S pixiewps",
    "hcxtools": "apt install hcxtools         |   pacman -S hcxtools",
    "hashcat": "apt install hashcat          |   pacman -S hashcat",
    "john": "apt install john             |   pacman -S john",
    "iw": "apt install iw               |   pacman -S iw",
    "rfkill": "apt install rfkill           |   pacman -S rfkill",
    "nmcli": "apt install network-manager  |   pacman -S networkmanager",
    "ethtool": "apt install ethtool",
    "cowpatty": "apt install cowpatty",
    "tcpdump": "apt install tcpdump",
    "tshark": "apt install tshark",
}

VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?[A-Za-z0-9._-]*)")


@dataclass
class ToolInfo:
    name: str
    path: str = ""
    version: str = ""
    available: bool = False
    category: str = "core"
    purpose: str = ""
    install: str = ""
    error: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name, "path": self.path, "version": self.version,
            "available": self.available, "category": self.category,
            "purpose": self.purpose, "install": self.install, "error": self.error,
        }


class ToolRegistry:
    """Cached lookups for the external binaries wifipilot drives."""

    def __init__(self) -> None:
        self._info: Dict[str, ToolInfo] = {}
        self._lock = threading.RLock()
        self.resolved: Dict[str, str] = {}

    def probe(self, name: str, force: bool = False) -> ToolInfo:
        with self._lock:
            if name in self._info and not force:
                return self._info[name]
        spec = TOOLS.get(name, ToolSpec(name, "external tool"))
        info = ToolInfo(
            name=name, category=spec.category, purpose=spec.purpose,
            install=INSTALL_HINTS.get(spec.package or name, INSTALL_HINTS.get(name, "")),
        )
        path = which(name)
        if not path and spec.alternatives:
            for alt in spec.alternatives:
                path = which(alt)
                if path:
                    break
        info.path = path or ""
        info.available = bool(path)
        if info.available:
            from .util import run
            result: CommandResult = run([path, *spec.version_args], timeout=10)
            match = VERSION_RE.search(result.text)
            info.version = match.group(1) if match else ""
            if not result.ok and not result.text:
                info.error = result.error or "no output from version probe"
        with self._lock:
            self._info[name] = info
        return info

    def path(self, name: str) -> Optional[str]:
        with self._lock:
            if name in self.resolved:
                return self.resolved[name] or None
        info = self.probe(name)
        with self._lock:
            self.resolved[name] = info.path
        return info.path or None

    def has(self, name: str) -> bool:
        return self.path(name) is not None

    def all(self, force: bool = False) -> List[ToolInfo]:
        return [self.probe(name, force) for name in TOOLS]

    def by_category(self) -> Dict[str, List[ToolInfo]]:
        out: Dict[str, List[ToolInfo]] = {}
        for info in self.all():
            out.setdefault(info.category, []).append(info)
        return out

    def missing_required(self) -> List[str]:
        return [n for n in REQUIRED_FOR_LIVE if not self.has(n)]

    def capabilities(self) -> Dict[str, bool]:
        """Feature flags the planner uses to avoid impossible plans."""
        return {
            "aircrack": self.has("aircrack-ng"),
            "airodump": self.has("airodump-ng"),
            "deauth": self.has("aireplay-ng"),
            "monitor": self.has("airmon-ng") or self.has("iw"),
            "wps": self.has("reaver") or self.has("bully"),
            "wash": self.has("wash") or self.has("reaver"),
            "pmkid": self.has("hcxdumptool") or self.has("airodump-ng"),
            "hcxtools": self.has("hcxpcapngtool"),
            "hashcat": self.has("hashcat"),
            "john": self.has("john"),
            "iw": self.has("iw"),
            "nmcli": self.has("nmcli"),
            "root": is_root(),
        }

    def summary(self) -> Dict[str, object]:
        caps = self.capabilities()
        return {
            "tools": {info.name: info.to_dict() for info in self.all()},
            "capabilities": caps,
            "missing_required": self.missing_required(),
            "interfaces": list_interfaces(),
        }


# --------------------------------------------------------------------------- #
# wireless interfaces
# --------------------------------------------------------------------------- #


@dataclass
class WirelessInterface:
    name: str
    phy: str = ""
    driver: str = ""
    chipset: str = ""
    mode: str = ""
    kind: str = "wifi"
    bands: List[str] = field(default_factory=list)
    channels: List[int] = field(default_factory=list)
    supports_monitor: bool = False
    supports_ap: bool = False
    supports_injection: bool = False
    state: str = "unknown"
    managed: bool = False
    monitor: bool = False
    vendor: str = ""

    @property
    def bands_label(self) -> str:
        return "/".join(self.bands) if self.bands else "?"

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name, "phy": self.phy, "driver": self.driver,
            "chipset": self.chipset, "mode": self.mode, "bands": self.bands,
            "channels": len(self.channels), "monitor": self.supports_monitor,
            "ap": self.supports_ap, "injection": self.supports_injection,
            "state": self.state, "is_monitor": self.monitor, "vendor": self.vendor,
        }


#: chipsets known to do monitor mode + injection well (for operator advice)
GOOD_CHIPSETS = ("ath9k", "ath10k", "rt2800usb", "mt76", "iwlwifi", "8812au",
                 "8814au", "rtl8812au", "rtl88xxau", "carl9170", "rt73usb")


def list_interfaces(force: bool = False) -> List[WirelessInterface]:
    """Enumerate wireless interfaces with ``iw`` and enrich with driver info."""
    if not force:
        cached = _iface_cache.get("value")
        if cached and (__import__("time").time() - _iface_cache.get("ts", 0)) < 5:
            return cached
    from .util import run
    interfaces: "Dict[str, WirelessInterface]" = {}

    iw_path = which("iw")
    if iw_path:
        result = run([iw_path, "dev"], timeout=10)
        current: Optional[WirelessInterface] = None
        for raw in result.stdout.splitlines():
            line = raw.strip()
            match = re.match(r"Interface (\S+)", line)
            if match:
                current = WirelessInterface(name=match.group(1))
                interfaces[current.name] = current
                continue
            if current is None:
                continue
            if line.startswith("addr "):
                continue
            if line.startswith("type "):
                current.mode = line.split(None, 1)[1].strip()
                current.monitor = current.mode == "monitor"
            elif line.startswith("channel "):
                match = re.search(r"channel (\d+).*?\((\d+) MHz\)", line)
                if match:
                    current.channels = [int(match.group(1))]
            elif line.startswith("ssid "):
                continue
        for name, iface in interfaces.items():
            info = run([iw_path, "dev", name, "info"], timeout=10)
            iface.state = "up" if "type" in info.stdout else iface.state
        # phy capabilities (monitor mode support, bands)
        for phy in {i.phy for i in interfaces.values() if i.phy} or _phys(iw_path):
            caps = run([iw_path, "phy", phy, "info"], timeout=10)
            if not caps.ok:
                continue
            bands = []
            if re.search(r"24[0-9]{2} MHz", caps.stdout):
                bands.append("2.4GHz")
            if re.search(r"5[0-9]{3} MHz", caps.stdout):
                bands.append("5GHz")
            if re.search(r"6[0-9]{3} MHz", caps.stdout):
                bands.append("6GHz")
            monitor = bool(re.search(r"^\s*\*\s*monitor", caps.stdout, re.M))
            ap_mode = bool(re.search(r"^\s*\*\s*AP\b", caps.stdout, re.M))
            for iface in interfaces.values():
                if not iface.phy or iface.phy == phy:
                    iface.phy = iface.phy or phy
                    iface.bands = bands
                    iface.supports_monitor = monitor or iface.supports_monitor
                    iface.supports_ap = ap_mode
                    iface.supports_injection = monitor
    if not interfaces:
        iwconfig = which("iwconfig")
        if iwconfig:
            result = run([iwconfig], timeout=10)
            for raw in result.stdout.splitlines():
                match = re.match(r"^(\S+)\s+IEEE 802\.11", raw)
                if match:
                    name = match.group(1)
                    interfaces[name] = WirelessInterface(
                        name=name, mode="managed", bands=["2.4GHz"],
                        supports_monitor=True, supports_injection=True,
                    )
    for iface in interfaces.values():
        if not iface.driver:
            iface.driver = _driver_for(iface.name)
        if iface.driver and not iface.chipset:
            iface.chipset = iface.driver
        iface.supports_monitor = iface.supports_monitor or iface.driver in GOOD_CHIPSETS
        iface.supports_injection = iface.supports_injection or iface.driver in GOOD_CHIPSETS
    values = list(interfaces.values())
    _iface_cache["value"] = values
    _iface_cache["ts"] = __import__("time").time()
    return values


_iface_cache: Dict[str, object] = {}


def _phys(iw_path: str) -> List[str]:
    from .util import run
    result = run([iw_path, "phy"], timeout=10)
    return re.findall(r"phy#(\d+)", result.stdout)


def _driver_for(interface: str) -> str:
    base = Path(f"/sys/class/net/{interface}/device")
    try:
        resolved = base.resolve()
        return resolved.parent.name.split(":")[0]
    except OSError:
        return ""


def pick_interface(preferred: str = "") -> Optional[WirelessInterface]:
    interfaces = list_interfaces()
    if preferred:
        for iface in interfaces:
            if iface.name == preferred:
                return iface
    for iface in interfaces:
        if iface.monitor:
            return iface
    for iface in interfaces:
        if iface.supports_monitor and "mon" not in iface.name:
            return iface
    return interfaces[0] if interfaces else None


registry = ToolRegistry()
