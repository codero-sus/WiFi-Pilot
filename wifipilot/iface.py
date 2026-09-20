"""Wireless interface control: monitor mode, channel hopping, cleanup.

Everything here shells out to ``airmon-ng`` / ``iw`` / ``ip`` -- the same tools
wifite uses -- and restores the machine to its original state on exit.
"""

from __future__ import annotations

import contextlib
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .deps import WirelessInterface, list_interfaces, registry
from .util import C, is_root, mac_random, run, which


class InterfaceError(RuntimeError):
    pass


@dataclass
class InterfaceState:
    """Snapshot of the machine so we can put it back the way we found it."""

    original: List[WirelessInterface] = field(default_factory=list)
    created_monitor: str = ""
    monitor_started_by_us: bool = False
    killed_processes: List[str] = field(default_factory=list)
    original_mac: str = ""
    original_channel: int = 0
    original_txpower: int = 0


class InterfaceManager:
    """Owns the monitor interface for the whole session."""

    def __init__(self, bus=None, verbose: bool = False):
        self.bus = bus
        self.verbose = verbose
        self.state = InterfaceState()
        self.interface: str = ""          # managed/base interface
        self.monitor: str = ""            # monitor interface in use
        self.phy: str = ""
        self.driver: str = ""
        self.chipset: str = ""
        self.current_channel: int = 0
        self.hop_thread: Optional[threading.Thread] = None
        self._hop_stop = threading.Event()
        self._lock = threading.RLock()
        self._hop_channels: List[int] = []
        self.on_channel: Optional[Callable[[int], None]] = None
        self.channel_failures = 0

    # -- logging -----------------------------------------------------------
    def _log(self, message: str, level: str = "info") -> None:
        if self.bus is not None:
            self.bus.log(message, level=level, scope="iface")
        elif self.verbose:
            print(f"[iface] {message}")

    def _cmd(self, args: List[str], timeout: float = 20.0, sudo: bool = True):
        cmd = list(args)
        if sudo and not is_root():
            sudo_bin = which("sudo")
            if not sudo_bin:
                raise InterfaceError(
                    f"need root for: {' '.join(cmd)} (run wifipilot as root)"
                )
            cmd = [sudo_bin, "-n", *cmd]
        result = run(cmd, timeout=timeout)
        if self.verbose and result.text:
            self._log(f"$ {' '.join(cmd)} -> {result.text.splitlines()[0] if result.lines else ''}", "debug")
        return result

    # -- discovery ---------------------------------------------------------
    def detect(self, preferred: str = "", monitor_preferred: str = "") -> List[WirelessInterface]:
        self.state.original = list_interfaces(force=True)
        return self.state.original

    def pick(self, preferred: str = "") -> WirelessInterface:
        ifaces = self.state.original or list_interfaces(force=True)
        if preferred:
            for iface in ifaces:
                if iface.name == preferred:
                    return iface
            raise InterfaceError(f"interface {preferred!r} not found (have: "
                                 f"{', '.join(i.name for i in ifaces) or 'none'})")
        for iface in ifaces:
            if iface.monitor:
                return iface
        for iface in ifaces:
            if iface.supports_monitor:
                return iface
        if not ifaces:
            raise InterfaceError("no wireless interface found (need a WiFi adapter "
                                 "that supports monitor mode)")
        return ifaces[0]

    # -- monitor mode ------------------------------------------------------
    def enable_monitor(self, interface: str = "", kill_interfering: bool = True,
                       randomize_mac: bool = False, timeout: float = 20.0) -> str:
        """Put an adapter into monitor mode.  Returns the monitor interface name."""
        with self._lock:
            iface = self.pick(interface)
            self.interface = iface.name
            self.phy = iface.phy or self._phy_of(iface.name)
            self.driver = iface.driver
            self.chipset = iface.chipset
            self.state.original_mac = self._mac_of(iface.name)
            self._log(f"interface {iface.name} ({iface.driver or 'unknown driver'}, "
                      f"{iface.bands_label}) selected")
            if kill_interfering:
                self.kill_interfering()
            if self.phy:
                self._unblock_rfkill()

            if iface.monitor:
                self.monitor = iface.name
                self._log(f"{iface.name} is already in monitor mode")
                self._set_channel_any(1)
                return self.monitor

            airmon = registry.path("airmon-ng")
            if airmon:
                result = self._cmd([airmon, "start", iface.name], timeout=timeout)
                found = re.search(r"monitor mode (?:vif )?enabled (?:on|for) (\S+)",
                                  result.stdout + result.stderr)
                if found:
                    name = found.group(1).strip(":").strip()
                    if name != iface.name:
                        self.monitor = name
                    else:
                        self.monitor = self._find_monitor(iface.name)
                else:
                    self.monitor = self._find_monitor(iface.name)
                if found or self.monitor:
                    self.state.monitor_started_by_us = True
            if not self.monitor:
                if not registry.has("iw"):
                    raise InterfaceError(
                        "cannot enable monitor mode: neither airmon-ng nor iw is available"
                    )
                self.monitor = self._iw_monitor(iface, timeout)
                self.state.created_monitor = self.monitor
                self.state.monitor_started_by_us = True
            if not self.monitor:
                raise InterfaceError(
                    f"failed to enable monitor mode on {iface.name} "
                    f"(driver {iface.driver or '?'} may not support it)"
                )
            self._wait_monitor(timeout)
            if randomize_mac:
                self.randomize_mac()
            self._log(f"monitor interface ready: {self.monitor}", "success")
            if self.bus:
                self.bus.publish("interface", {
                    "action": "monitor", "monitor": self.monitor,
                    "interface": self.interface, "driver": self.driver,
                    "chipset": self.chipset,
                })
            return self.monitor

    def _iw_monitor(self, iface: WirelessInterface, timeout: float) -> str:
        name = f"{iface.name}mon"
        with contextlib.suppress(InterfaceError):
            self._cmd(["ip", "link", "set", iface.name, "down"])
        args = ["iw", "phy", self.phy, "interface", "add", name, "type", "monitor"] if self.phy \
            else ["iw", "dev", iface.name, "interface", "add", name, "type", "monitor"]
        result = self._cmd(args, timeout=timeout)
        if result.error or not result.ok and "File exists" not in result.text:
            # some drivers rename the interface; look for anything monitor-ish
            found = self._find_monitor(iface.name)
            if found:
                name = found
            elif result.error:
                raise InterfaceError(f"iw monitor add failed: {result.error}")
        self._cmd(["ip", "link", "set", name, "up"], timeout=timeout)
        return name

    def _find_monitor(self, base: str) -> str:
        for cand in (f"{base}mon", base, f"mon{base}"):
            if cand:
                from pathlib import Path
                if Path(f"/sys/class/net/{cand}").exists():
                    info = run([registry.path("iw") or "iw", "dev", cand, "info"], timeout=8)
                    if "monitor" in info.stdout or cand.endswith("mon"):
                        return cand
        for iface in list_interfaces(force=True):
            if iface.monitor:
                return iface.name
        return ""

    def _wait_monitor(self, timeout: float) -> None:
        deadline = time.time() + timeout
        from pathlib import Path
        while time.time() < deadline:
            if self.monitor and Path(f"/sys/class/net/{self.monitor}").exists():
                return
            time.sleep(0.4)
        raise InterfaceError(f"monitor interface {self.monitor!r} never appeared")

    def disable_monitor(self) -> None:
        """Best-effort teardown; safe to call multiple times."""
        with self._lock:
            if not self.monitor and not self.state.monitor_started_by_us:
                return
            self.stop_hop()
            airmon = registry.path("airmon-ng")
            try:
                if self.state.monitor_started_by_us and airmon and self.interface:
                    self._cmd([airmon, "stop", self.monitor or self.interface], timeout=25)
                elif self.state.created_monitor:
                    self._cmd(["ip", "link", "set", self.state.created_monitor, "down"], timeout=10)
                    self._cmd(["iw", "dev", self.state.created_monitor, "del"], timeout=10)
            except InterfaceError as exc:
                self._log(f"monitor teardown: {exc}", "warning")
            if self.interface and self.state.original_mac:
                with contextlib.suppress(InterfaceError):
                    self._cmd(["ip", "link", "set", self.interface, "down"], timeout=10)
                    self._cmd(["ip", "link", "set", self.interface, "address",
                               self.state.original_mac], timeout=10)
                    self._cmd(["ip", "link", "set", self.interface, "up"], timeout=10)
                    self._log(f"restored MAC address of {self.interface}")
            self.monitor = ""
            if self.bus:
                self.bus.publish("interface", {"action": "monitor-off"})

    # -- channel control ---------------------------------------------------
    def set_channel(self, channel: int) -> bool:
        if not channel or channel < 0:
            return False
        if self.current_channel == channel:
            return True
        ok = self._set_channel_any(channel)
        if ok:
            self.current_channel = channel
        return ok

    def _set_channel_any(self, channel: int) -> bool:
        target = self.monitor or self.interface
        if not target:
            return False
        if registry.has("iw"):
            result = self._cmd(["iw", "dev", target, "set", "channel", str(channel)], timeout=10)
            if not result.error and "Network is down" not in result.text:
                return result.ok or not result.text
        if registry.has("iwconfig"):
            result = self._cmd(["iwconfig", target, "channel", str(channel)], timeout=10)
            return result.ok
        return False

    def start_hop(self, channels: List[int], interval: float = 0.35) -> None:
        if not channels:
            return
        self.stop_hop()
        self._hop_channels = [c for c in channels if c > 0]
        self._hop_stop.clear()

        def loop() -> None:
            index = 0
            while not self._hop_stop.is_set():
                channel = self._hop_channels[index % len(self._hop_channels)]
                index += 1
                if not self.set_channel(channel):
                    self.channel_failures += 1
                elif self.on_channel:
                    with contextlib.suppress(Exception):
                        self.on_channel(channel)
                self._hop_stop.wait(interval)

        self.hop_thread = threading.Thread(target=loop, name="channel-hop", daemon=True)
        self.hop_thread.start()

    def stop_hop(self, restore_channel: int = 0) -> None:
        self._hop_stop.set()
        if self.hop_thread and self.hop_thread.is_alive():
            self.hop_thread.join(timeout=2.0)
        self.hop_thread = None
        if restore_channel:
            self.set_channel(restore_channel)

    def hop_channels(self) -> List[int]:
        return list(self._hop_channels)

    # -- misc --------------------------------------------------------------
    def kill_interfering(self) -> List[str]:
        """Stop NetworkManager / wpa_supplicant / dhclient so injection is reliable."""
        if not is_root():
            return []
        killed: List[str] = []
        airmon = registry.path("airmon-ng")
        if airmon:
            result = self._cmd([airmon, "check", "kill"], timeout=30)
            killed = re.findall(r"^(\d+)\s+\S+\s+(\S+)", result.stdout, re.M)
            names = sorted({name for _, name in killed})
            self.state.killed_processes = names
            if names:
                self._log(f"stopped interfering processes: {', '.join(names)}")
            return names
        for proc in ("NetworkManager", "wpa_supplicant", "dhclient", "avahi-daemon"):
            result = run(["pkill", "-f", proc], timeout=10)
            if result.ok:
                killed.append(proc)
        self.state.killed_processes = killed
        if killed:
            self._log(f"stopped interfering processes: {', '.join(killed)}")
        return killed

    def _unblock_rfkill(self) -> None:
        if not registry.has("rfkill"):
            return
        result = self._cmd(["rfkill", "unblock", "wifi"], timeout=10)
        if result.ok:
            self._log("rfkill: wireless unblocked", "debug")

    def randomize_mac(self, target: str = "") -> str:
        target = target or self.monitor or self.interface
        if not target:
            return ""
        new_mac = mac_random()
        with contextlib.suppress(InterfaceError):
            self._cmd(["ip", "link", "set", target, "down"], timeout=10)
            result = self._cmd(["ip", "link", "set", target, "address", new_mac], timeout=10)
            self._cmd(["ip", "link", "set", target, "up"], timeout=10)
            if result.ok or not result.error:
                self._log(f"randomised MAC of {target}: {new_mac}", "debug")
                return new_mac
        return ""

    def set_txpower(self, dbm: int) -> bool:
        target = self.monitor or self.interface
        iw = registry.path("iw")
        if not target or not iw:
            return False
        result = self._cmd([iw, "dev", target, "set", "txpower", "fixed", str(dbm * 100)], timeout=10)
        return result.ok

    def test_injection(self, bssid: str = "ff:ff:ff:ff:ff:ff") -> bool:
        """Quick probe: can we actually transmit?  (5 packets, one AP-less test.)"""
        aireplay = registry.path("aireplay-ng")
        if not aireplay or not self.monitor:
            return False
        result = self._cmd([aireplay, "--test", "--interface", self.monitor], timeout=25)
        return "Injection is working" in result.text

    def _phy_of(self, name: str) -> str:
        iw = registry.path("iw")
        if not iw:
            return ""
        result = run([iw, "dev", name], timeout=8)
        match = re.search(r"wiphy (\d+)", result.stdout)
        return match.group(1) if match else ""

    def _mac_of(self, name: str) -> str:
        try:
            return open(f"/sys/class/net/{name}/address").read().strip()
        except OSError:
            return ""

    def cleanup(self) -> None:
        self.stop_hop()
        self.disable_monitor()

    def summary(self) -> Dict[str, object]:
        return {
            "interface": self.interface,
            "monitor": self.monitor,
            "phy": self.phy,
            "driver": self.driver,
            "chipset": self.chipset,
            "channel": self.current_channel,
            "hopping": bool(self.hop_thread and self.hop_thread.is_alive()),
            "killed": self.state.killed_processes,
        }
