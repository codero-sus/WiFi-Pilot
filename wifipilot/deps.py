# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""External tool registry: detection, version probing and install hints.

wifipilot is a *driver*: it orchestrates the classic aircrack-ng toolchain
rather than reimplementing 802.11 in Python.  This module knows where each
binary lives, whether it is usable, and what to tell the operator when it is
missing.
"""

from __future__ import annotations

import re
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
        ToolSpec("mdk4", "deauth/beacon floods + probe replay", "mdk4",
                 ["--help"], category="flood"),
        ToolSpec("hostapd", "software access point (evil twin)", "hostapd",
                 ["-v"], category="twin"),
        ToolSpec("hostapd-mana", "evil twin with EAP/probe harvesting", "hostapd-mana",
                 ["-v"], category="twin"),
        ToolSpec("wpa_supplicant", "client association (post-exploitation checks)",
                 "wpasupplicant", ["-v"], category="optional"),
    ]
}

#: minimum a truly functional run needs
REQUIRED_FOR_LIVE = ("aircrack-ng", "airmon-ng", "airodump-ng")

#: wifipilot is a Linux tool: every attack path drives Linux wireless tooling.
#: Hints list the package name per Linux distribution family.
INSTALL_HINTS = {
    "aircrack-ng": "apt install aircrack-ng   |   pacman -S aircrack-ng   |   dnf install aircrack-ng",
    "reaver": "apt install reaver           |   pacman -S reaver",
    "wash": "apt install reaver           |   pacman -S reaver",
    "bully": "apt install bully            |   pacman -S bully",
    "pixiewps": "apt install pixiewps        |   pacman -S pixiewps",
    "hcxtools": "apt install hcxtools         |   pacman -S hcxtools",
    "hashcat": "apt install hashcat          |   pacman -S hashcat",
    "john": "apt install john             |   pacman -S john",
    "cowpatty": "apt install cowpatty",
    "iw": "apt install iw               |   pacman -S iw",
    "iwconfig": "apt install wireless-tools",
    "rfkill": "apt install rfkill           |   pacman -S rfkill",
    "nmcli": "apt install network-manager  |   pacman -S networkmanager",
    "ethtool": "apt install ethtool",
    "tcpdump": "apt install tcpdump          |   pacman -S tcpdump",
    "tshark": "apt install tshark           |   pacman -S wireshark-cli",
    "mdk4": "apt install mdk4              |   pacman -S mdk4",
    "hostapd": "apt install hostapd           |   pacman -S hostapd",
    "hostapd-mana": "apt install hostapd-mana      |   git clone https://github.com/sensepost/hostapd-mana",
    "wpa_supplicant": "apt install wpasupplicant",
}

#: convenience one-liner shown when required tools are missing
#: (the optional attack families are named in ``scripts/install-tools.sh``: mdk4 for
#: the floods, hostapd/hostapd-mana for the evil twin, wpasupplicant for client checks)
DISTRO_INSTALL_COMMAND = {
    "apt": "sudo apt update && sudo apt install -y aircrack-ng reaver bully pixiewps hcxtools hashcat iw rfkill",
    "pacman": "sudo pacman -S --needed aircrack-ng reaver bully pixiewps hcxtools hashcat iw rfkill",
    "dnf": "sudo dnf install -y aircrack-ng reaver bully pixiewps hcxtools hashcat iw rfkill",
    "zypper": "sudo zypper install aircrack-ng reaver bully pixiewps hcxtools hashcat iw rfkill",
    "apk": "sudo apk add aircrack-ng reaver bully pixiewps hcxtools hashcat iw rfkill",
}


def install_command() -> str:
    """The right one-liner for this distribution, or a generic hint."""
    from .util import package_manager
    manager = package_manager()
    for key, command in DISTRO_INSTALL_COMMAND.items():
        if manager.startswith(key):
            return command
    return (DISTRO_INSTALL_COMMAND["apt"] + "   # adjust for your distribution"
            if not manager else DISTRO_INSTALL_COMMAND["apt"])


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
        # derived views, cached until a probe observes a different reality
        self._caps: Optional[Dict[str, bool]] = None
        self._summary_cache: Optional[Dict[str, object]] = None


    def _invalidate_views(self) -> None:
        self._caps = None
        self._summary_cache = None

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
            previous = self._info.get(name)
            self._info[name] = info
            if previous is None or previous.path != info.path:
                # reality changed (first look, or a tool appeared/vanished —
                # e.g. right after `tools install`): every derived view and
                # the resolved-path cache must agree with the new probe
                self.resolved[name] = info.path
                self._invalidate_views()
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
        """Feature flags the planner uses to avoid impossible plans (cached).

        The planner and every attack's ``available()`` ask constantly; the
        answers only change when a probe sees a tool appear or vanish.
        """
        with self._lock:
            if self._caps is not None:
                return dict(self._caps)
        caps = {
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
            "mdk4": self.has("mdk4"),
            "hostapd": self.has("hostapd") or self.has("hostapd-mana"),
            "twin": self.has("hostapd") or self.has("hostapd-mana"),
            "root": is_root(),
        }
        with self._lock:
            self._caps = caps
        return dict(caps)

    def summary(self) -> Dict[str, object]:
        # the registry-derived parts are cached until the next probe(); the
        # interface list is rebuilt every call (list_interfaces has its own
        # short TTL) so a plugged-in adapter shows immediately — and the web
        # state push that asks every tick costs one dict merge, not a rebuild
        with self._lock:
            static = self._summary_cache
        if static is None:
            from .util import platform_info
            static = {
                "tools": {info.name: info.to_dict() for info in self.all()},
                "capabilities": self.capabilities(),
                "missing_required": self.missing_required(),
                "platform": platform_info(),
                "install_command": install_command(),
            }
            with self._lock:
                self._summary_cache = static
        summary = dict(static)
        summary["tools"] = dict(static["tools"])    # callers must not corrupt the cache
        # plain dicts: this summary goes straight to json.dumps (the
        # WebSocket state push, CLI --json).  Raw WirelessInterface
        # dataclasses crashed the WS handler with "Object of type
        # WirelessInterface is not JSON serializable" on any machine
        # that actually has a WiFi adaptor — empty on CI, fatal live.
        summary["interfaces"] = [info.to_dict() for info in list_interfaces()]
        return summary


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
        # "is not None", not truthy: an empty list (no adaptors) must cache
        # too, or every state push re-runs the full enumeration
        if cached is not None and (__import__("time").time() - _iface_cache.get("ts", 0)) < 5:
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


# --------------------------------------------------------------------------- #
# `wifipilot tools install` — install the toolchain, don't just hint at it
# --------------------------------------------------------------------------- #
#: package names that differ from the Debian spelling, per manager family
_PACKAGE_OVERRIDES = {
    "pacman": {"network-manager": "networkmanager", "tshark": "wireshark-cli",
               "wpasupplicant": "wpa_supplicant", "wireless-tools": "wireless_tools"},
    "dnf": {"network-manager": "NetworkManager", "tshark": "wireshark-cli",
            "wpasupplicant": "wpa_supplicant"},
    "zypper": {"network-manager": "NetworkManager", "tshark": "wireshark",
               "wpasupplicant": "wpa_supplicant"},
    "apk": {"network-manager": "networkmanager", "wpasupplicant": "wpa_supplicant"},
}

#: how each supported manager family installs a package list (argv templates;
#: ``{pkgs}`` is replaced by the package names — no shell is ever involved)
_INSTALL_ARGV = {
    "apt": [["apt-get", "update"], ["apt-get", "install", "-y", "{pkgs}"]],
    "pacman": [["pacman", "-Sy", "--needed", "--noconfirm", "{pkgs}"]],
    "dnf": [["dnf", "install", "-y", "{pkgs}"]],
    "zypper": [["zypper", "--non-interactive", "install", "-y", "{pkgs}"]],
    "apk": [["apk", "add", "{pkgs}"]],
}


def _manager_family(manager: str = "") -> str:
    from .util import package_manager
    name = (manager or package_manager() or "").lower()
    if name.startswith("apt"):
        return "apt"
    for family in ("pacman", "dnf", "zypper", "apk"):
        if name.startswith(family):
            return family
    return ""


def _package_for(spec: ToolSpec, family: str) -> str:
    package = spec.package or spec.name
    return _PACKAGE_OVERRIDES.get(family, {}).get(package, package)


def install_plan(categories=None, only_missing: bool = True,
                 manager: str = "", with_web: bool = False) -> dict:
    """What ``wifipilot tools install`` would run, without running anything.

    Returns the manager family, the deduplicated package list, and the exact
    argv command lines (sudo-prefixed when we are not root and sudo exists),
    so the operator sees precisely what will happen before it does.
    """
    import sys as _sys

    family = _manager_family(manager)
    wanted = [spec for spec in TOOLS.values()
              if categories is None or spec.category in categories]
    present = [spec.name for spec in wanted if which(spec.name)]
    missing = [spec.name for spec in wanted if not which(spec.name)]
    targets = missing if only_missing else [spec.name for spec in wanted]
    packages: List[str] = []
    for name in targets:
        package = _package_for(TOOLS[name], family)
        if package and package not in packages:
            packages.append(package)
    sudo = (not is_root()) and bool(which("sudo"))
    commands: List[List[str]] = []
    if family in _INSTALL_ARGV and packages:
        for template in _INSTALL_ARGV[family]:
            argv: List[str] = []
            for part in template:
                if part == "{pkgs}":
                    argv.extend(packages)
                else:
                    argv.append(part)
            commands.append((["sudo"] + argv) if sudo else argv)
    if with_web:
        commands.append([_sys.executable, "-m", "pip", "install", "fastapi", "uvicorn"])
    return {
        "manager": family,
        "supported": family in _INSTALL_ARGV,
        "sudo": sudo,
        "missing_tools": missing,
        "present_tools": present,
        "packages": packages,
        "commands": commands,
        "display": " && ".join(" ".join(argv) for argv in commands)
                   or install_command(),
        "hint": "" if family in _INSTALL_ARGV else
                f"no supported package manager found — install manually: "
                f"{' '.join(packages) or '(see wifipilot tools)'}",
    }


def install_tools(categories=None, dry_run: bool = False, yes: bool = False,
                  with_web: bool = False, runner=None, manager: str = "") -> dict:
    """Install every missing external dependency for the detected distro.

    This is the engine behind ``wifipilot tools install``.  Nothing runs
    unless ``yes=True`` (the CLI asks, or takes ``--yes``); ``dry_run`` only
    ever returns the plan.  ``runner`` is injectable for tests.
    """
    from .util import run as _run

    plan = install_plan(categories=categories, manager=manager, with_web=with_web)
    result = {"ok": True, "dry_run": dry_run, "needs_confirmation": False,
              "plan": plan, "results": [], "before_missing": plan["missing_tools"],
              "after_missing": plan["missing_tools"]}
    if dry_run:
        return result
    if not plan["commands"]:
        result["ok"] = plan["supported"] or not plan["missing_tools"]
        return result
    if not yes:
        result["needs_confirmation"] = True
        return result
    if not plan["supported"] and plan["packages"]:
        result["ok"] = False
        return result
    run_cmd = runner or _run
    env = {"DEBIAN_FRONTEND": "noninteractive"} if plan["manager"] == "apt" else None
    for argv in plan["commands"]:
        completed = run_cmd(argv, timeout=1800, env=env)
        result["results"].append({
            "command": " ".join(argv),
            "ok": bool(getattr(completed, "ok", False)),
            "returncode": int(getattr(completed, "returncode", -1)),
            "timed_out": bool(getattr(completed, "timed_out", False)),
        })
        if not getattr(completed, "ok", False):
            result["ok"] = False
    after = []
    for name in plan["missing_tools"]:
        info = registry.probe(name, force=True)
        if not info.path:
            after.append(name)
    result["after_missing"] = after
    if after:
        result["ok"] = False
    return result
