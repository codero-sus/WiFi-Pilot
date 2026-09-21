"""Session state: the single source of truth shared by CLI, web UI and the LLM.

The session owns every access point, capture, attempt and finding, keeps a
JSONL journal of everything that happened, and can render two views of itself:

* ``snapshot()``   -> the full UI state (verbose, for the browser)
* ``situation()``  -> a compact report for the LLM planner (token-frugal)
"""

from __future__ import annotations

import contextlib
import os
import shutil
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .config import Config, ensure_dirs, find_wordlists
from .deps import registry
from .events import EK, EventBus
from .models import (STATUS_FAILED, STATUS_RUNNING, STATUS_SUCCESS, AccessPoint,
                     Attempt, Capture, Client, Finding, SessionStats, loot_filename)
from .util import append_jsonl, human_duration, mac_norm, now_iso, read_json, safe_int, slugify, write_json


@dataclass
class Progress:
    """Live progress for whatever long-running thing is happening."""

    label: str = ""
    kind: str = ""                 # capture | crack | wps | scan
    bssid: str = ""
    percent: float = 0.0
    value: float = 0.0
    total: float = 0.0
    detail: str = ""
    speed: str = ""
    eta: str = ""
    started: float = field(default_factory=time.time)

    @property
    def elapsed(self) -> float:
        return time.time() - self.started

    def to_dict(self) -> Dict[str, Any]:
        return {
            "label": self.label, "kind": self.kind, "bssid": self.bssid,
            "percent": round(self.percent, 1), "value": self.value,
            "total": self.total, "detail": self.detail, "speed": self.speed,
            "eta": self.eta, "elapsed": round(self.elapsed, 1),
            "active": bool(self.label),
        }


class Session:
    def __init__(self, config: Config, bus: EventBus, demo: bool = False,
                 session_id: Optional[str] = None, authorized: bool = False):
        self.config = config
        self.bus = bus
        self.demo = demo
        self.authorized = authorized or config.authorized
        self.id = session_id or datetime.now().strftime("%Y%m%d-%H%M%S")
        self.started = time.time()
        self.aps: "OrderedDict[str, AccessPoint]" = OrderedDict()
        self.attempts: List[Attempt] = []
        self.findings: List[Finding] = []
        self.stats = SessionStats()
        self.progress = Progress()
        self.active_attempt: Optional[Attempt] = None
        self.interface_summary: Dict[str, Any] = {}
        self.scanning = False
        self.attacking = False
        self.auto_think = bool(config.autothink_enabled())
        self.stealth = config.stealth
        self.selected_bssids: List[str] = []
        self.known_wordlists: List[Dict[str, Any]] = []
        self.notes: List[str] = []
        self.state_dir = ""
        self._setup_dirs()
        self.bus.journal_path = str(Path(self.state_dir) / "journal.jsonl")

    # ------------------------------------------------------------------ #
    # paths
    # ------------------------------------------------------------------ #
    def _setup_dirs(self) -> None:
        dirs = ensure_dirs(self.config)
        self.output_dir = dirs["output"]
        self.state_dir = str(Path(dirs["sessions"]) / self.id)
        for sub in ("", "handshakes", "pmkid", "wep", "cracks", "wordlists", "reports"):
            Path(self.state_dir, sub).mkdir(parents=True, exist_ok=True)
        self.known_wordlists = find_wordlists(self.config)

    def path(self, *parts: str) -> str:
        return str(Path(self.state_dir, *parts))

    def loot_path(self, filename: str) -> str:
        target = Path(self.output_dir) / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        return str(target)

    def save_artifact(self, source: str, kind: str, name: str = "") -> str:
        """Copy a produced file into the loot directory and return the new path."""
        stem = name or f"{kind}_{int(time.time())}"
        ext = Path(source).suffix or ".cap"
        try:
            destination = self.loot_path(f"{slugify(stem)}{ext}")
            if os.path.exists(source):
                shutil.copy2(source, destination)
            return destination
        except OSError:
            return source

    # ------------------------------------------------------------------ #
    # access points
    # ------------------------------------------------------------------ #
    def upsert_ap(self, bssid: str, essid: str = "", publish: bool = True,
                  **fields: Any) -> Tuple[AccessPoint, bool]:
        bssid = mac_norm(bssid) or bssid
        if not bssid:
            raise ValueError("access point without a BSSID")
        ap = self.aps.get(bssid)
        created = ap is None
        if ap is None:
            ap = AccessPoint(bssid=bssid, essid=essid or "")
            self.aps[bssid] = ap
            self.stats.aps_seen += 1
        if essid and not ap.essid:
            ap.essid = essid
        for key, value in fields.items():
            if value in (None, "", 0):
                continue
            if key == "signal":
                ap.signal = int(value)
            elif key == "clients":
                continue
            elif hasattr(ap, key):
                setattr(ap, key, value)
        ap.touch()
        if publish:
            self.bus.publish(EK.AP_NEW if created else EK.AP_UPDATE, ap.to_dict())
        elif created:
            self.bus.publish(EK.AP_NEW, ap.to_dict())
        return ap, created

    def add_client(self, bssid: str, mac: str, **fields: Any) -> Optional[Client]:
        bssid, mac = mac_norm(bssid), mac_norm(mac)
        if not bssid or not mac or mac == "ff:ff:ff:ff:ff:ff":
            return None
        ap = self.aps.get(bssid)
        if ap is None:
            return None
        client = Client(mac=mac, bssid=bssid,
                        signal=safe_int(fields.get("signal"), -100),
                        packets=safe_int(fields.get("packets"), 0))
        is_new = ap.add_client(client)
        if is_new:
            self.stats.clients_seen += 1
            self.bus.publish(EK.CLIENT_NEW, {"bssid": bssid, "mac": mac, **client.to_dict()})
        return client

    def ap(self, bssid: str) -> Optional[AccessPoint]:
        return self.aps.get(mac_norm(bssid) or bssid)

    def sorted_aps(self, key: str = "score") -> List[AccessPoint]:
        aps = list(self.aps.values())
        if key == "signal":
            return sorted(aps, key=lambda a: a.signal, reverse=True)
        if key == "clients":
            return sorted(aps, key=lambda a: len(a.clients), reverse=True)
        if key == "ssid":
            return sorted(aps, key=lambda a: a.essid.lower())
        return sorted(aps, key=lambda a: (a.score, a.signal), reverse=True)

    def stale_aps(self, timeout: float = 90.0) -> List[AccessPoint]:
        now = time.time()
        return [ap for ap in self.aps.values() if now - ap.last_seen > timeout]

    def drop_stale(self, timeout: float = 240.0) -> None:
        for ap in self.stale_aps(timeout):
            if ap.status == STATUS_RUNNING:
                continue
            self.aps.pop(ap.bssid, None)
            self.bus.publish(EK.AP_LOST, {"bssid": ap.bssid, "essid": ap.essid})

    # ------------------------------------------------------------------ #
    # captures / attempts / findings
    # ------------------------------------------------------------------ #
    def add_capture(self, cap: Capture) -> Capture:
        # a capture of the same kind for the same BSSID that we already hold and
        # that carries no new information would only pollute the report
        for existing in list(self.loot()):
            if (existing.bssid == cap.bssid and existing.kind == cap.kind
                    and existing.valid and not cap.password and cap.path
                    and existing.path == cap.path):
                return existing
        ap = self.ap(cap.bssid)
        if ap is None:
            ap, _ = self.upsert_ap(cap.bssid, cap.essid)
        if not cap.essid and ap.essid:
            cap.essid = ap.essid
        ap.captures.append(cap)
        if cap.kind == "handshake":
            ap.handshake_ts = time.time()
            self.stats.handshakes += 1
        elif cap.kind == "pmkid":
            ap.pmkid_ts = time.time()
            self.stats.pmkids += 1
        if cap.password:
            self.stats.passwords += 1
        self.bus.publish(EK.CAPTURE_NEW, {"bssid": cap.bssid, **cap.to_dict()})
        severity = "high" if cap.password else "medium"
        self.add_finding(Finding(
            kind="loot", severity=severity, bssid=cap.bssid,
            title=f"{cap.kind.upper()} captured for {cap.essid or cap.bssid}",
            detail=(f"PSK recovered: {cap.password}" if cap.password
                    else f"Saved to {cap.path}") + (f" (tool: {cap.tool})" if cap.tool else ""),
        ))
        self.append_report_entry("capture", cap.to_dict())
        return cap

    def start_attempt(self, attack: str, bssid: str, tool: str = "", command: str = "",
                      chosen_by: str = "heuristic", reason: str = "") -> Attempt:
        attempt = Attempt(attack=attack, bssid=bssid, tool=tool, command=command,
                          chosen_by=chosen_by, reason=reason)
        self.attempts.append(attempt)
        self.active_attempt = attempt
        self.stats.attacks_run += 1
        ap = self.ap(bssid)
        if ap:
            ap.attempts.append(attempt)
            ap.status = STATUS_RUNNING
        self.bus.publish(EK.ATTACK_START, {
            "attack": attack, "bssid": bssid, "tool": tool, "command": command,
            "chosen_by": chosen_by, "reason": reason,
            "essid": ap.essid if ap else "",
        })
        return attempt

    def end_attempt(self, attempt: Attempt, status: str, result: str = "",
                    detail: str = "", capture: Optional[Capture] = None) -> Attempt:
        attempt.status = status
        attempt.result = result
        attempt.detail = detail
        attempt.ended = time.time()
        attempt.capture = capture
        if status == STATUS_FAILED:
            self.stats.attacks_failed += 1
        ap = self.ap(attempt.bssid)
        if ap:
            ap.status = status
        self.bus.publish(EK.ATTACK_END, attempt.to_dict())
        self.progress = Progress()
        self.append_report_entry("attempt", attempt.to_dict())
        return attempt

    def add_finding(self, finding: Finding, publish: bool = True) -> Finding:
        self.findings.append(finding)
        if publish:
            self.bus.publish(EK.FINDING, finding.to_dict())
        return finding

    def set_progress(self, label: str = "", **fields: Any) -> Progress:
        """Update the live progress indicator (new label == new task)."""
        if label and label != self.progress.label:
            self.progress = Progress(label=label, started=time.time())
        elif label:
            self.progress.label = label
        for key, value in fields.items():
            if key == "label":
                continue
            if hasattr(self.progress, key):
                setattr(self.progress, key, value)
        self.bus.publish(EK.CAPTURE_PROGRESS, self.progress.to_dict())
        return self.progress

    def clear_progress(self) -> None:
        self.progress = Progress()

    # ------------------------------------------------------------------ #
    # reporting
    # ------------------------------------------------------------------ #
    def append_report_entry(self, kind: str, payload: Dict[str, Any]) -> None:
        append_jsonl(Path(self.state_dir) / "reports" / "timeline.jsonl",
                     {"kind": kind, "ts": now_iso(), **payload})

    def all_captures(self) -> List[Capture]:
        """Every capture held by any access point, newest first."""
        return sorted((cap for ap in self.aps.values() for cap in ap.captures),
                      key=lambda c: c.created, reverse=True)

    def loot(self) -> List[Capture]:
        out: List[Capture] = []
        for ap in self.aps.values():
            for cap in ap.captures:
                if cap.valid or cap.password:
                    out.append(cap)
        return sorted(out, key=lambda c: c.created, reverse=True)

    def write_report(self, path: Optional[str] = None) -> str:
        target = Path(path or Path(self.state_dir) / "reports" / "report.json")
        write_json(target, self.export())
        return str(target)

    def write_markdown_report(self, path: Optional[str] = None) -> str:
        target = Path(path or Path(self.output_dir) / f"wifipilot-{self.id}.md")
        lines = [
            f"# wifipilot engagement {self.id}",
            "",
            f"* started: {datetime.fromtimestamp(self.started, timezone.utc).isoformat()}",
            f"* interface: {self.interface_summary.get('monitor') or self.interface_summary.get('interface') or 'n/a'}",
            f"* mode: {'simulation' if self.demo else 'live'}",
            f"* APs seen: {self.stats.aps_seen} · clients: {self.stats.clients_seen} · "
            f"handshakes: {self.stats.handshakes} · PMKIDs: {self.stats.pmkids} · "
            f"passwords: {self.stats.passwords}",
            "",
            "## Access points",
            "",
            "| SSID | BSSID | CH | SIG | Security | WPS | Clients | Loot |",
            "|------|-------|----|-----|----------|-----|---------|------|",
        ]
        for ap in self.sorted_aps():
            loot_bits = []
            if ap.has_handshake:
                loot_bits.append("handshake")
            if ap.has_pmkid:
                loot_bits.append("pmkid")
            if ap.password:
                loot_bits.append(f"PSK `{ap.password}`")
            lines.append(
                f"| {ap.display_name} | {ap.bssid} | {ap.channel} | {ap.signal} | "
                f"{ap.security} | {ap.wps_locked or ('yes' if ap.wps else 'no')} | "
                f"{len(ap.clients)} | {', '.join(loot_bits) or '-'} |"
            )
        lines += ["", "## Captures", ""]
        for cap in self.loot():
            lines.append(f"* **{cap.kind}** {cap.essid or cap.bssid} — `{cap.path}`"
                         + (f" — PSK `{cap.password}`" if cap.password else ""))
        lines += ["", "## Findings", ""]
        for finding in self.findings:
            lines.append(f"* [{finding.severity}] {finding.title} — {finding.detail}")
        lines += ["", "## AI advisor decisions", ""]
        for attempt in self.attempts:
            if attempt.chosen_by == "llm" and attempt.reason:
                lines.append(f"* `{attempt.attack}` on {attempt.bssid}: {attempt.reason}")
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("\n".join(lines) + "\n", encoding="utf-8")
        except OSError:
            pass
        return str(target)

    def export(self) -> Dict[str, Any]:
        return {
            "session": {
                "id": self.id,
                "started": now_iso(),
                "demo": self.demo,
                "authorized": self.authorized,
                "interface": self.interface_summary,
                "config": self.config.to_dict(),
            },
            "stats": self.stats.to_dict(),
            "access_points": [ap.to_dict(detail=True) for ap in self.sorted_aps()],
            "attempts": [a.to_dict() for a in self.attempts],
            "findings": [f.to_dict() for f in self.findings],
            "loot": [c.to_dict() for c in self.loot()],
            "notes": self.notes,
        }

    # ------------------------------------------------------------------ #
    # views for UI / LLM
    # ------------------------------------------------------------------ #
    def snapshot(self, detail_bssid: str = "", event_limit: int = 120,
                 max_aps: int = 200) -> Dict[str, Any]:
        enabled = list(self.config.attacks)
        aps = [ap.to_dict(detail=ap.bssid == detail_bssid, enabled=enabled)
               for ap in self.sorted_aps()[:max_aps]]
        return {
            "session": {
                "id": self.id,
                "demo": self.demo,
                "authorized": self.authorized,
                "started_ts": self.started,
                "uptime": round(self.stats.uptime, 1),
                "uptime_h": human_duration(self.stats.uptime),
                "scanning": self.scanning,
                "attacking": self.attacking,
                "auto_think": self.auto_think,
                "stealth": self.stealth,
                "selected": self.selected_bssids,
                "output_dir": self.output_dir,
                "state_dir": self.state_dir,
            },
            "stats": self.stats.to_dict(),
            "interface": self.interface_summary,
            "access_points": aps,
            "progress": self.progress.to_dict(),
            "active_attempt": self.active_attempt.to_dict() if self.active_attempt else None,
            "attempts": [a.to_dict() for a in self.attempts[-40:]],
            "findings": [f.to_dict() for f in self.findings[-60:]],
            "loot": [c.to_dict() for c in self.loot()],
            "wordlists": self.known_wordlists[:8],
            "events": [e.to_dict() for e in self.bus.recent(event_limit)],
            "capabilities": registry.capabilities(),
            "tool_names": [t.name for t in registry.all() if t.available],
        }

    def situation(self, max_aps: int = 12, include_tools: bool = True) -> Dict[str, Any]:
        """Token-frugal report for the LLM: only what changes a decision."""
        aps = []
        for ap in self.sorted_aps()[:max_aps]:
            aps.append({
                "bssid": ap.bssid,
                "ssid": ap.essid or "",
                "ch": ap.channel,
                "band": ap.band,
                "rssi": ap.signal,
                "sec": ap.security,
                "cipher": ap.cipher,
                "wps": ("yes" if ap.wps_open else ("locked" if ap.wps else "no")),
                "pmf": ap.pmf,
                "clients": len(ap.clients),
                "handshake": ap.has_handshake,
                "pmkid": ap.has_pmkid,
                "psk": ap.password,
                "attacks_tried": [a.attack for a in ap.attempts],
                "failures": sum(1 for a in ap.attempts if a.status == STATUS_FAILED),
                "status": ap.status,
                "deauths": ap.deauths_sent,
                "vendor": ap.vendor,
            })
        recent_attempts = [{
            "attack": a.attack, "bssid": a.bssid, "status": a.status,
            "result": a.result, "detail": (a.detail or "")[:160],
            "dur": round(a.duration), "by": a.chosen_by,
        } for a in self.attempts[-12:]]
        recent_findings = [{
            "severity": f.severity, "title": f.title, "detail": f.detail[:160],
        } for f in self.findings[-12:]]
        data: Dict[str, Any] = {
            "session": {
                "id": self.id,
                "mode": "simulation" if self.demo else "live",
                "uptime_s": round(self.stats.uptime),
                "stealth": self.stealth,
                "authorized": self.authorized,
                "interface": self.interface_summary.get("monitor")
                             or self.interface_summary.get("interface") or "none",
                "channel": self.interface_summary.get("channel", 0),
            },
            "stats": {
                "aps": len(self.aps), "handshakes": self.stats.handshakes,
                "pmkids": self.stats.pmkids, "passwords": self.stats.passwords,
                "wps_cracks": self.stats.wps_cracks, "attacks": self.stats.attacks_run,
                "failures": self.stats.attacks_failed,
            },
            "targets": aps,
            "attempts": recent_attempts,
            "findings": recent_findings,
            "wordlists": [w["name"] for w in self.known_wordlists[:5]],
            "time_budgets": {
                "handshake": self.config.handshake_timeout,
                "pmkid": self.config.pmkid_timeout,
                "wps": self.config.wps_timeout,
                "wep": self.config.wep_timeout,
            },
            "enabled_attacks": self.config.attacks,
        }
        if include_tools:
            data["capabilities"] = {k: v for k, v in registry.capabilities().items() if v}
        return data

    # ------------------------------------------------------------------ #
    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.write_report()

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Session {self.id} aps={len(self.aps)} attempts={len(self.attempts)}>"
