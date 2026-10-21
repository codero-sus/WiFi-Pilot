# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""The orchestrator: scanner + advisor + attacks + cracker, one worker thread.

Everything wifipilot does to a radio happens through this class.  A single
worker thread owns the monitor interface, and every operation (a campaign, a
one-off attack from the web UI, a manual crack job) is queued as a job.  That
makes the whole tool deterministic: no two processes ever fight over the
adapter, and stopping is always clean.

    engine = Engine(config)
    engine.prepare()                       # interface, dirs, tools
    engine.add_job(lambda: engine.run_campaign())
    engine.start_worker()
    ...
    engine.shutdown()
"""

from __future__ import annotations

import contextlib
import os
import queue
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .advisor import Advisor
from .attacks import AttackContext, ATTACK_CLASSES, get_attack
from .config import Config
from .crack import Cracker
from .demo import DemoRadio
from .deps import registry
from .events import EK, EventBus
from .iface import InterfaceError, InterfaceManager
from .models import (STATUS_FAILED, STATUS_RUNNING, STATUS_SKIPPED, AccessPoint,
                      Attempt, Capture)
from .planner import Plan, heuristic_plan, preferred_attacks, should_replan
from .scanner import Scanner
from .session import Session
from .util import ProcessManager, human_duration, is_root, mac_norm, platform_info


class _StopFlag:
    """Combines the global stop and the per-attack cancel into one check."""

    def __init__(self, *events: threading.Event):
        self.events = events

    def is_set(self) -> bool:
        return any(event.is_set() for event in self.events)


def _side_lane_attack(attack: str) -> bool:
    """May this attack run beside the radio work instead of after it?

    One adapter means Wi-Fi attacks stay serial, and one HCI means Bluetooth
    does too — but IT-edition attacks talk to sockets and offline attacks read
    files, so nothing is gained by making them queue behind a 90-second
    handshake window.  Those get the parallel side lane (``config.jobs``).
    """
    from .attacks import ATTACK_META
    meta = ATTACK_META.get(attack, {})
    if meta.get("domain", "wifi") == "it":
        return True
    return meta.get("category", "") == "offline"


@dataclass
class EngineStatus:
    phase: str = "idle"          # idle | preparing | scanning | attacking | cracking | thinking | stopped
    detail: str = ""
    campaign_running: bool = False
    queue_depth: int = 0
    current_job: str = ""
    started: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase": self.phase, "detail": self.detail,
            "campaign_running": self.campaign_running,
            "queue_depth": self.queue_depth, "current_job": self.current_job,
            "uptime": round(time.time() - self.started, 1) if self.started else 0,
        }


class Engine:
    def __init__(self, config: Config, bus: Optional[EventBus] = None, demo: bool = False,
                 authorized: bool = False, session: Optional[Session] = None,
                 verbose: bool = False):
        self.config = config
        self.demo = demo or config.demo
        self.authorized = authorized or config.authorized
        self.bus = bus or EventBus()
        self.verbose = verbose
        self.session = session or Session(config, self.bus, demo=self.demo,
                                         authorized=self.authorized)
        self.iface: Optional[InterfaceManager] = None
        self.radio: Optional[DemoRadio] = None
        self.scanner: Optional[Scanner] = None
        self.advisor = Advisor(self.session, None, self.bus, demo=self.demo)
        self.advisor.configure(provider="", announce=False)
        self.cracker = Cracker(self.session, config, self.bus, demo=self.demo)
        self.processes = ProcessManager()
        self.status = EngineStatus(started=time.time())
        self.stop_event = threading.Event()
        self.attack_cancel = threading.Event()
        self.pause_event = threading.Event()
        self.pause_event.set()          # set = not paused
        self._jobs: "queue.Queue[Tuple[str, Callable[[], Any]]]" = queue.Queue()
        self._worker: Optional[threading.Thread] = None
        self._prepared = False
        self._failures_since_plan = 0
        self._last_plan: Optional[Plan] = None
        self._new_aps_at_plan = 0
        self._targets_filter: List[str] = []
        self.campaign_deadline = 0.0
        # speed lanes: non-radio attacks and loot cracking beside the radio
        # work (created lazily, only when a preset/config asks for them)
        self._side_pool: Optional[ThreadPoolExecutor] = None
        self._crack_pool: Optional[ThreadPoolExecutor] = None
        self._side_futures: List[Any] = []
        self._crack_futures: List[Any] = []

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #
    def prepare(self, announce: bool = True) -> Dict[str, Any]:
        """Bring up the monitor interface (live) or the simulated radio (demo)."""
        self.status.phase = "preparing"
        self.status.detail = "simulating a radio" if self.demo else "configuring monitor mode"
        if self.demo:
            self.radio = DemoRadio(verbose=self.verbose)
            self.cracker.radio = self.radio
            info = {"mode": "simulation", "interface": "demo0", "monitor": "demo0mon"}
            self.session.interface_summary = {**info, "driver": "wifipilot-demo",
                                              "chipset": "simulated"}
            self.bus.publish(EK.INTERFACE, self.session.interface_summary)
            if announce:
                self.bus.log("simulation mode: no radio will be touched — "
                             "this walks the full pipeline against a fake neighbourhood",
                             level="warning")
            self._prepared = True
            self.status.phase = "idle"
            return self.session.interface_summary

        if not is_root():
            self.bus.warn("wifipilot is not running as root: monitor mode, injection and "
                          "deauth will most likely fail (try: sudo wifipilot ...)")
        missing = registry.missing_required()
        if missing:
            self.bus.error("missing required tools: " + ", ".join(missing)
                           + " — install the aircrack-ng suite")
        self.iface = InterfaceManager(self.bus, verbose=self.verbose)
        try:
            self.iface.detect()
            monitor = self.iface.enable_monitor(
                self.config.interface, kill_interfering=self.config.kill_interfering,
                randomize_mac=self.config.randomize_mac,
                timeout=self.config.iface_ready_timeout,
            )
        except InterfaceError as exc:
            self.status.phase = "error"
            self.status.detail = str(exc)
            self.bus.error(f"interface setup failed: {exc}")
            raise
        self.config.monitor_interface = monitor
        self.session.interface_summary = self.iface.summary()
        self.session.interface_summary["monitor"] = monitor
        self.bus.publish(EK.INTERFACE, self.session.interface_summary)
        self.scanner = Scanner(self.session, self.iface, self.config,
                               verbose=self.verbose)
        self._prepared = True
        self.status.phase = "idle"
        if announce:
            self.bus.log(f"ready: monitor {monitor} via {self.iface.interface} "
                         f"({self.iface.driver or 'unknown driver'})", level="success")
        return self.session.interface_summary

    def start_worker(self) -> None:
        if self._worker and self._worker.is_alive():
            return
        self._worker = threading.Thread(target=self._run_jobs, name="engine", daemon=True)
        self._worker.start()

    def shutdown(self, timeout: float = 10.0) -> None:
        self.bus.log("shutting down: stopping attacks and restoring the interface",
                     level="info")
        self.stop_event.set()
        self.attack_cancel.set()
        for pool in (self._side_pool, self._crack_pool):
            if pool is not None:
                pool.shutdown(wait=False, cancel_futures=True)
        self._side_pool = self._crack_pool = None
        with contextlib.suppress(Exception):
            self.cracker.close()
        if self.scanner is not None:
            with contextlib.suppress(Exception):
                self.scanner.stop()
        if self.iface is not None:
            with contextlib.suppress(Exception):
                self.iface.cleanup()
        self.processes.stop_all()
        self.status.phase = "stopped"
        self.bus.publish(EK.SESSION_END, {
            "id": self.session.id, "uptime": round(self.session.stats.uptime, 1),
            "loot": self.session.stats.loot, "passwords": self.session.stats.passwords,
        })
        with contextlib.suppress(Exception):
            self.session.write_report()
            self.session.write_markdown_report()

    # ------------------------------------------------------------------ #
    # job queue
    # ------------------------------------------------------------------ #
    def add_job(self, name: str, function: Callable[[], Any]) -> None:
        self._jobs.put((name, function))
        self.status.queue_depth = self._jobs.qsize()
        self.bus.publish("engine.queue", {"name": name, "depth": self._jobs.qsize()})

    def _run_jobs(self) -> None:
        while not self.stop_event.is_set():
            try:
                name, function = self._jobs.get(timeout=0.5)
            except queue.Empty:
                continue
            self.status.current_job = name
            self.status.queue_depth = self._jobs.qsize()
            try:
                function()
            except Exception as exc:  # pragma: no cover - keep the worker alive
                self.bus.error(f"job {name!r} crashed: {exc}")
                if self.verbose:
                    import traceback
                    traceback.print_exc()
            finally:
                self.attack_cancel.clear()
                self.status.current_job = ""
                self.status.queue_depth = self._jobs.qsize()
                self._jobs.task_done()

    def wait_idle(self, timeout: float = 30.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._jobs.empty() and not self.status.current_job:
                return True
            time.sleep(0.2)
        return False

    # ------------------------------------------------------------------ #
    # scanning
    # ------------------------------------------------------------------ #
    def start_scan(self) -> None:
        if not self._prepared:
            self.prepare()
        if self.demo:
            if self.scanner is None:
                self.scanner = Scanner(self.session, None, self.config, self.radio,
                                       verbose=self.verbose)
        elif self.scanner is None:
            self.scanner = Scanner(self.session, self.iface, self.config, verbose=self.verbose)
        self.scanner.start()
        self.status.phase = "scanning"
        self.status.detail = "discovery running"

    def stop_scan(self) -> None:
        if self.scanner is not None:
            self.scanner.stop()
        if self.status.phase == "scanning":
            self.status.phase = "idle"

    def scan_for(self, seconds: float) -> None:
        """Blocking sweep used by `wifipilot scan`."""
        self.start_scan()
        deadline = time.time() + seconds
        while time.time() < deadline and not self.stop_event.is_set():
            time.sleep(0.3)
        self.stop_scan()

    # ------------------------------------------------------------------ #
    # operator conveniences (targets, vendor dossiers, benchmark, advice)
    # ------------------------------------------------------------------ #
    def select_targets(self, bssids: Sequence[str] = (), tag: str = "",
                       kind: str = "", vendor: str = "",
                       cracked: Optional[bool] = None, loot: Optional[bool] = None,
                       clear: bool = False) -> List[str]:
        """Choose what the campaign is allowed to touch, and return the selection.

        Filters compose (``tag="in-scope"`` plus ``kind="guest"``), and the
        result lands in ``session.selected_bssids`` so the UI, the planner and
        the report all agree on the scope.
        """
        if clear:
            self.session.selected_bssids = []
        chosen: List[str] = []
        if bssids:
            for bssid in bssids:
                ap = self.session.ap(bssid)
                if ap is not None:
                    chosen.append(ap.bssid)
        matched = self.session.filter_aps(kind=kind, tag=tag, vendor=vendor,
                                          cracked=cracked, loot=loot)
        chosen.extend(ap.bssid for ap in matched)
        selected = sorted({*self.session.selected_bssids, *chosen})
        self.session.selected_bssids = selected
        self.bus.log(f"scope: {len(selected)} target(s) selected", level="info")
        return selected

    def selected(self) -> List[Dict[str, object]]:
        """The current selection, as plain dicts (for the UI and the report)."""
        out: List[Dict[str, object]] = []
        for bssid in self.session.selected_bssids:
            ap = self.session.ap(bssid)
            if ap is not None:
                out.append({"bssid": ap.bssid, "essid": ap.essid,
                            "kind": ap.target_kind, "tags": list(ap.tags),
                            "score": round(ap.score, 2)})
        return out

    def vendor_info(self, bssid: str) -> Dict[str, Any]:
        """What the vendor dossier plus the SSID say about one AP."""
        from .analytics import identify
        from .vendors import vendor_dossier
        ap = self.session.ap(bssid)
        if ap is None:
            return {}
        dossier = vendor_dossier(ap.vendor or ap.bssid)
        info = identify(ap.essid, ap.vendor or ap.bssid)
        return {"bssid": ap.bssid, "essid": ap.essid, "vendor": ap.vendor,
                "dossier": dossier, "identification": info,
                "disclaimer": "vendor behaviour is a heuristic, not a finding"}

    def benchmark(self, seconds: float = 5.0, candidates: int = 0) -> Dict[str, Any]:
        """Measure how fast *this* machine verifies candidates, and estimate.

        Read-only and radio-free: it verifies wrong candidates against a
        synthetic handshake, so the number is a rate, never a claim about a
        real network.  The estimate it returns is labelled ``estimate``.
        """
        from .synth import build_capture
        from .models import Capture as _Capture
        from .pcap import analyze_file
        import tempfile

        path = os.path.join(tempfile.gettempdir(), "wifipilot-benchmark.pcap")
        build_capture(path, "wifipilot-benchmark", "aa:bb:cc:11:22:33",
                      "02:00:00:00:00:0b", "benchmark-passphrase")
        analysis = analyze_file(path)
        started = time.time()
        verified = 0
        cracker = self.cracker
        ap = AccessPoint(bssid="aa:bb:cc:11:22:33", essid="wifipilot-benchmark")
        capture = _Capture(kind="handshake", bssid=ap.bssid, essid=ap.essid,
                           path=path, valid=True)
        try:
            while time.time() - started < max(1.0, seconds):
                if candidates and verified >= candidates:
                    break
                verified += 1
                cracker._verify(ap, capture, analysis, f"wrong-{verified}")
        finally:
            with contextlib.suppress(OSError):
                os.unlink(path)
        elapsed = max(0.001, time.time() - started)
        rate = verified / elapsed
        per_candidate = elapsed / max(1, verified)
        estimates = {
            name: {"seconds": (space / rate), "human": human_duration(space / rate)}
            for name, space in (("8 digits", 10 ** 8), ("10 digits", 10 ** 10),
                                ("rockyou-sized (14M)", 14_000_000))
        }
        result = {
            "candidates": verified, "seconds": round(elapsed, 3),
            "rate": round(rate, 1), "ms_per_candidate": round(per_candidate * 1000, 3),
            "estimates": estimates,
            "note": ("measured on a synthetic handshake; estimates are this machine's "
                     "rate applied to a candidate space, not a promise"),
        }
        self.bus.log(f"benchmark: {rate:,.0f} candidates/s "
                     f"({per_candidate * 1000:.2f} ms each) on this machine",
                     level="info")
        return result

    def advice(self) -> List[Dict[str, Any]]:
        """Prioritised, plain-language next steps (no LLM needed).

        Each item says what to do, why, and how confident the rule behind it is;
        the heuristic planner already had the logic — this exposes it directly.
        """
        items: List[Dict[str, Any]] = []
        aps = self.session.sorted_aps()
        not_looted = [ap for ap in aps if not (ap.has_handshake or ap.has_pmkid)]
        if not aps:
            items.append({"priority": 1, "action": "scan",
                          "why": "nothing discovered yet",
                          "confidence": "certain"})
        for ap in aps[:5]:
            if ap.password:
                continue
            if ap.has_pmkid:
                items.append({"priority": 1, "action": "crack",
                              "bssid": ap.bssid, "essid": ap.essid,
                              "why": "PMKID captured: cracking needs no radio time",
                              "confidence": "certain"})
            elif ap.has_handshake:
                items.append({"priority": 2, "action": "crack",
                              "bssid": ap.bssid, "essid": ap.essid,
                              "why": "handshake captured: crack it before deauthing again",
                              "confidence": "certain"})
            elif ap.wps_open:
                items.append({"priority": 2, "action": "wps_pixie",
                              "bssid": ap.bssid, "essid": ap.essid,
                              "why": "WPS reports unlocked: Pixie-Dust is offline and fast",
                              "confidence": "high"})
            elif ap.clients:
                items.append({"priority": 3, "action": "handshake",
                              "bssid": ap.bssid, "essid": ap.essid,
                              "why": f"{len(ap.clients)} client(s) present: deauth has targets",
                              "confidence": "medium"})
            else:
                items.append({"priority": 4, "action": "pmkid",
                              "bssid": ap.bssid, "essid": ap.essid,
                              "why": "clientless: PMKID first, it is silent",
                              "confidence": "medium"})
        if not_looted and not any(item.get("action") == "crack" for item in items):
            items.append({"priority": 3, "action": "passive",
                          "why": "loot is thin; a passive dwell often beats more deauth",
                          "confidence": "medium"})
        if self.session.stats.crack_attempts > 20 and not self.session.stats.passwords:
            items.append({"priority": 2, "action": "strategy",
                          "why": "many candidates verified, no hit: try "
                                 "--strategy thorough or --mask 'vendor-?d?d?d?d'",
                          "confidence": "high"})
        items.sort(key=lambda item: item["priority"])
        return items

    def kill_tool(self, name: str = "") -> Dict[str, Any]:
        """Stop the external tool(s) we started — hashcat/aircrack, or all."""
        stopped_before = self.processes.pids() if hasattr(self.processes, "pids") else []
        if name:
            killed = self.processes.stop_matching(name) if hasattr(
                self.processes, "stop_matching") else 0
        else:
            killed = self.processes.stop_all()
        message = (f"stopped {killed} process(es)" + (f" matching {name!r}" if name else ""))
        self.bus.log(message, level="warning")
        return {"stopped": killed, "name": name or "<all>", "before": len(stopped_before)}

    # ------------------------------------------------------------------ #
    # thinking
    # ------------------------------------------------------------------ #
    def think(self, force: bool = False) -> Plan:
        """One advisor cycle (LLM when available, heuristics otherwise)."""
        self.status.phase = "thinking"
        self.status.detail = "asking the advisor for a plan"
        self.bus.publish(EK.ADVISOR_THINKING, {
            "stage": "plan", "targets": len(self.session.aps),
            "available": self.advisor.available or bool(getattr(self.advisor.config, "enabled", False)),
        })
        plan = self.advisor.plan() if (self.config.ai_enabled() and self.advisor.check()) \
            else self._heuristic_plan()
        self._last_plan = plan
        self._failures_since_plan = 0
        self._new_aps_at_plan = len(self.session.aps)
        # mark which APs were picked by whom (for the UI and the report)
        for action in plan.actions:
            ap = self.session.ap(action.bssid)
            if ap is not None:
                ap.picked_by = "llm" if plan.source == "llm" else "operator"
                if action.reason:
                    ap.pick_reason = action.reason
        self.status.phase = "idle"
        self.status.detail = plan.summary()
        return plan

    def _heuristic_plan(self) -> Plan:
        plan = heuristic_plan(self.session)
        if not self.config.ai_enabled():
            plan.reasoning = "deterministic planner (AI advisor disabled): " + plan.reasoning
        self.bus.publish(EK.ADVISOR_PLAN, plan.to_dict())
        return plan

    # ------------------------------------------------------------------ #
    # attacks
    # ------------------------------------------------------------------ #
    def context(self, cancel: Optional[threading.Event] = None) -> AttackContext:
        """The context handed to attacks.

        ``cancel`` is a per-attack stop used by the side lanes and the budget
        watchdog: a parallel attack must be stoppable without touching the
        shared ``attack_cancel`` that the radio lane is watching.
        """
        events = [self.stop_event, self.attack_cancel]
        if cancel is not None:
            events.append(cancel)
        return AttackContext(
            session=self.session, config=self.config, bus=self.bus,
            iface=self.iface, scanner=self.scanner, radio=self.radio, demo=self.demo,
            processes=self.processes,
            stop_event=_StopFlag(*events),
        )

    def attackable(self, ap: AccessPoint) -> List[str]:
        """Attacks that are enabled, usable and sensible for this AP right now."""
        return preferred_attacks(ap, self.config)

    def run_attack(self, bssid: str, attack: str, reason: str = "",
                   source: str = "operator", lane: bool = False) -> Optional[Attempt]:
        """Run one attack.  ``lane=True`` runs it on a side lane thread: same
        bookkeeping, but the shared phase/attacking indicators and the advisor
        triage stay with the radio lane that owns them."""
        cls = ATTACK_CLASSES.get(attack)
        if cls is None:
            self.bus.warn(f"unknown attack: {attack}")
            return None
        module = get_attack(attack)
        # policy gate first: without authorisation wifipilot does not transmit at all
        if not self.demo and not self.authorized and module.needs_injection:
            self.bus.error("refusing to transmit: pass --i-am-authorized (or set "
                           "authorized=true, or tick the UI checkbox) to confirm you "
                           "have written permission for every target")
            return None
        ap = self.session.ap(bssid)
        if ap is None:
            self.bus.warn(f"no such target: {bssid}")
            return None
        # every attack gets its own cancel event: a watchdog (or a side lane)
        # must be able to stop *this* attack without poisoning the next one
        own_cancel = threading.Event()
        ctx = self.context(cancel=own_cancel)
        if not module.available(ctx):
            self.bus.warn(f"{attack} unavailable: {module.unavailable_reason(ctx)}")
            return None
        if not module.applies(ap):
            self.bus.log(f"{attack} does not apply to {ap.display_name} "
                         f"({ap.security})", level="warning")
            return None
        ap.picked_by = source
        if reason:
            ap.pick_reason = reason
        if not lane:
            self.status.phase = "attacking"
            self.status.detail = f"{attack} → {ap.display_name}"
            self.session.attacking = True
        self.bus.log(f"▶ {module.label} against {ap.display_name} "
                     f"({ap.bssid}, ch {ap.channel}, {ap.signal} dBm)", level="attack")
        known = {id(item) for item in self.session.attempts}
        watchdog = self._watchdog(module, ctx, own_cancel)
        try:
            outcome = module.run(ctx, ap)
        except Exception as exc:  # pragma: no cover - defensive
            self.bus.error(f"attack {attack} crashed: {exc}")
            attempt = self._find_attempt(known, ap.bssid, attack)
            if attempt is not None and attempt.status == STATUS_RUNNING:
                self.session.end_attempt(attempt, STATUS_FAILED, "internal error", str(exc))
            outcome = None
        finally:
            if watchdog is not None:
                watchdog.cancel()
        if not lane:
            self.session.attacking = False
            self.status.phase = "idle"
        attempt = self._find_attempt(known, ap.bssid, attack)
        if (outcome is not None and attempt is not None
                and attempt.status == STATUS_RUNNING):
            # an attack that decided not to act (already captured, nothing to do,
            # no client around) must still close its attempt record: otherwise the
            # UI shows an attack running forever
            self.session.end_attempt(attempt, STATUS_SKIPPED,
                                     outcome.result or "skipped", outcome.detail)
        if outcome is not None and outcome.extra and attempt is not None:
            # structured results (a survey's twins, a PIN plan) belong on the
            # attempt record, not only in the log line
            attempt.extra.update(outcome.extra)
        if attempt is not None and attempt.status == STATUS_FAILED:
            self._failures_since_plan += 1
            diagnosis = "" if lane else self._triage(attempt)
            if diagnosis:
                self.bus.publish(EK.FINDING, {
                    "kind": "advice", "severity": "medium", "bssid": attempt.bssid,
                    "title": "advisor diagnosis", "detail": diagnosis,
                    "source": "advisor",
                })
        # loot => try to crack it right away (on the crack lane when the
        # preset allows: a 3-minute crack must never stall the next attack)
        if outcome is not None and outcome.ok and outcome.capture is not None:
            if outcome.capture.password:
                pass
            elif not self.config.skip_crack:
                if self.config.parallel_crack:
                    self._crack_async(ap, outcome.capture, quick=True)
                else:
                    self.crack_capture(ap, outcome.capture, quick=True)
        return attempt

    def _find_attempt(self, known: set, bssid: str, attack: str) -> Optional[Attempt]:
        """The attempt this run just created — found by identity, not position.

        ``session.attempts[-1]`` is only ours while attacks are serial; with
        side lanes the newest attempt may belong to a parallel attack.
        """
        wanted = (bssid or "").lower()
        for attempt in reversed(self.session.attempts):
            if id(attempt) in known:
                continue
            if attempt.attack == attack and (attempt.bssid or "").lower() == wanted:
                return attempt
        return None

    def _watchdog(self, module: Any, ctx: AttackContext,
                  cancel: threading.Event) -> Optional[threading.Timer]:
        """Arm the per-attack hard cap: past the budget (+grace) the attack's
        own stop flag fires, so even an attack that ignores its budget cannot
        run the campaign into the ground."""
        cap = float(getattr(self.config, "attack_cap", 0.0) or 0.0)
        if cap <= 0:
            return None
        try:
            budget = float(module.budget(ctx))
        except Exception:                                    # pragma: no cover - defensive
            budget = cap
        limit = max(budget, 1.0) + max(10.0, 0.25 * budget)

        def fire() -> None:
            cancel.set()
            self.bus.warn(f"{module.name} exceeded its budget "
                          f"({human_duration(limit)}): stopping it")

        timer = threading.Timer(limit, fire)
        timer.daemon = True
        timer.start()
        return timer

    # ------------------------------------------------------------------ #
    # speed lanes: side attacks + background cracking
    # ------------------------------------------------------------------ #
    def _side_executor(self) -> Optional[ThreadPoolExecutor]:
        from .accel import lanes
        jobs = lanes(self.config)
        if jobs <= 1:
            return None
        if self._side_pool is None:
            self._side_pool = ThreadPoolExecutor(max_workers=jobs,
                                                 thread_name_prefix="wifipilot-side")
        return self._side_pool

    def _crack_executor(self) -> ThreadPoolExecutor:
        if self._crack_pool is None:
            self._crack_pool = ThreadPoolExecutor(max_workers=1,
                                                  thread_name_prefix="wifipilot-crack")
        return self._crack_pool

    def _crack_async(self, ap: AccessPoint, capture: Capture, quick: bool = False) -> None:
        self._crack_futures = [f for f in self._crack_futures if not f.done()]
        self._crack_futures.append(
            self._crack_executor().submit(self._crack_lane_run, ap, capture, quick))

    def _crack_lane_run(self, ap: AccessPoint, capture: Capture, quick: bool) -> None:
        with contextlib.suppress(Exception):
            self.crack_capture(ap, capture, quick=quick)

    def _reap_lanes(self, wait: bool = False) -> None:
        """Collect finished lane work; with ``wait`` block (bounded) for the rest."""
        timeout = max(30.0, float(getattr(self.config, "attack_cap", 0.0) or 0.0) + 30.0)
        for futures in (self._side_futures, self._crack_futures):
            for future in list(futures):
                if future.done():
                    with contextlib.suppress(Exception):
                        future.result()
                    futures.remove(future)
                elif wait:
                    with contextlib.suppress(Exception):
                        future.result(timeout=timeout)
                    if future.done():
                        futures.remove(future)

    def _side_sweep(self, attackable_cache: Dict[str, List[str]]) -> int:
        """Feed the side lane from every target's backlog.

        The planner only ever nominates a couple of attacks per round, which
        is right for the one radio — but IT/offline backlog would then take
        forever to drain.  The sweep submits up to ``jobs * 3`` queued side
        attacks per round (hard cap 24), skipping anything already running.
        """
        pool = self._side_executor()
        if pool is None:
            return 0
        from .accel import lanes
        self._side_futures = [f for f in self._side_futures if not f.done()]
        quota = min(24, lanes(self.config) * 3) - len(self._side_futures)
        if quota <= 0:
            return 0
        running = {(a.bssid.lower(), a.attack) for a in self.session.attempts
                   if a.status == STATUS_RUNNING}
        submitted = 0
        for ap in list(self.session.aps.values()):
            if submitted >= quota or self.stop_event.is_set():
                break
            if not self._wanted(ap.bssid) or ap.cracked:
                continue
            for name in attackable_cache.get(ap.bssid, []):
                if submitted >= quota:
                    break
                if not _side_lane_attack(name):
                    continue
                if (ap.bssid.lower(), name) in running:
                    continue
                self._side_futures.append(pool.submit(
                    self.run_attack, ap.bssid, name,
                    "side lane (parallel to radio work)", "preset", True))
                running.add((ap.bssid.lower(), name))
                submitted += 1
        return submitted

    def debug_last_attempt(self) -> Optional[Attempt]:
        return self.session.attempts[-1] if self.session.attempts else None

    def _triage(self, attempt: Attempt) -> str:
        if not self.config.ai_enabled() or self.config.think_interval_seconds() <= 0:
            return ""
        ap = self.session.ap(attempt.bssid)
        summary = ap.to_dict() if ap else {}
        with contextlib.suppress(Exception):
            return self.advisor.triage(attempt.to_dict(), summary)
        return ""

    def crack_capture(self, ap: AccessPoint, capture: Capture, quick: bool = False,
                      wordlists: Optional[Sequence[str]] = None,
                      masks: Optional[Sequence[str]] = None) -> Optional[str]:
        self.status.phase = "cracking"
        self.status.detail = f"cracking {ap.display_name}"
        timeout = min(self.config.crack_timeout, 180) if quick else self.config.crack_timeout
        result = self.cracker.crack_capture(ap, capture, wordlists=wordlists,
                                            timeout=timeout, masks=masks)
        self.status.phase = "idle"
        if result.cracked:
            self.bus.log(f"✔ PSK for {ap.display_name}: {result.password} "
                         f"(via {result.tool}"
                         + (", verified)" if result.verified else ", unverified)"),
                         level="success")
        return result.password or None

    def crack_target(self, bssid: str, wordlists: Optional[Sequence[str]] = None,
                     masks: Optional[Sequence[str]] = None) -> Optional[str]:
        ap = self.session.ap(bssid)
        if ap is None:
            return None
        capture = next((c for c in reversed(ap.captures)
                        if c.kind in ("handshake", "pmkid") and (c.path or c.hash_path)), None)
        if capture is None:
            self.bus.warn(f"{ap.display_name}: nothing captured yet, cannot crack")
            return None
        if not self.demo and not self.authorized:
            self.bus.error("refusing to crack: confirm authorisation first")
            return None
        return self.crack_capture(ap, capture, wordlists=wordlists, masks=masks)

    # ------------------------------------------------------------------ #
    # campaign
    # ------------------------------------------------------------------ #
    def _apply_preset_if_any(self) -> float:
        """Stamp the configured preset (+ allowed acceleration) onto the config.

        Returns the campaign length in minutes the preset asks for (0 = none).
        Applied here, at campaign start, so CLI/API/web/config-file presets
        all take effect the same way.
        """
        from .accel import apply_accel
        for note in apply_accel(self.config).get("notes", []):
            self.bus.log(f"acceleration: {note}", level="info")
        spec = (self.config.preset or "").strip()
        if not spec:
            return 0.0
        from .presets import apply_preset, get_preset
        try:
            report = apply_preset(self.config, spec, self.config.posture)
        except KeyError as error:
            self.bus.error(str(error))
            return 0.0
        # CPU acceleration may raise the lane count the preset just set
        apply_accel(self.config)
        posture = f":{report['posture']}" if report["posture"] else ""
        self.bus.log(
            f"preset {report['preset']}{posture} ({report['label']}): "
            f"{report['attacks']} attacks, budgets x{report['budget_scale']}, "
            f"per-attack cap {report['attack_cap']:.0f}s, {report['jobs']} lane(s), "
            f"campaign budget {report['minutes']:.0f} min", level="info")
        preset = get_preset(spec)
        return float(preset.minutes or 0.0) if preset else 0.0

    def run_campaign(self, targets: Optional[Sequence[str]] = None,
                     duration: float = 0.0, scan_first: bool = True) -> None:
        """The main loop: scan, think, attack, crack — until done or told to stop."""
        self._targets_filter = [mac_norm(t) for t in (targets or []) if mac_norm(t)]
        minutes = self._apply_preset_if_any()
        if not duration and minutes:
            duration = minutes * 60.0
        if duration:
            self.campaign_deadline = time.time() + duration
        self.status.campaign_running = True
        self.bus.publish(EK.SESSION_START, {
            "id": self.session.id, "demo": self.demo, "authorized": self.authorized,
            "config": {
                "attacks": self.config.attacks,
                "preset": self.config.preset,
                "posture": self.config.posture,
                "accel": self.config.accel,
                "stealth": self.config.stealth,
                "ai": self.config.ai_enabled(),
                "provider": self.advisor.provider,
                "model": self.advisor.model or getattr(self.config.llm_config(), "model", ""),
                "duration": duration,
                "targets": self._targets_filter,
            },
        })
        try:
            if not self._prepared:
                self.prepare()
            if scan_first and self.config.scan_time:
                self.bus.log(f"discovery phase: {int(self.config.scan_time)}s "
                             f"(band {self.config.band})", level="info")
                self.scan_for(self.config.scan_time)
            else:
                self.start_scan()
            if self.config.ai_enabled():
                self.advisor.check(force=True)
            self._campaign_loop()
        except Exception as exc:
            self.bus.error(f"campaign failed: {exc}")
        finally:
            # let the side lanes land before the report is written
            with contextlib.suppress(Exception):
                self._reap_lanes(wait=True)
            self.status.campaign_running = False
            with contextlib.suppress(Exception):
                self.stop_scan()
            self.bus.log(f"campaign finished: {self.session.stats.loot} loot item(s), "
                         f"{self.session.stats.passwords} password(s)", level="success")
            with contextlib.suppress(Exception):
                self.session.write_report()
                path = self.session.write_markdown_report()
                self.bus.log(f"report written to {path}", level="info")

    def _campaign_loop(self) -> None:
        rounds = 0
        empty_rounds = 0
        stale_rounds = 0
        force_replan = False
        last_crack_pass = 0.0
        while not self.stop_event.is_set():
            rounds += 1
            if self.campaign_deadline and time.time() > self.campaign_deadline:
                self.bus.log("campaign duration reached", level="info")
                break
            if self.config.max_targets and self.session.stats.passwords >= self.config.max_targets:
                self.bus.log(f"reached the password target ({self.config.max_targets}), stopping",
                             level="success")
                break

            plan = self.think(force=True) if (rounds == 1 or force_replan) \
                else self._maybe_replan()
            force_replan = False
            actions = [a for a in (plan.actions if plan else []) if self._wanted(a.bssid)]
            if not actions:
                empty_rounds += 1
                if empty_rounds == 1:
                    self.bus.log("no actionable target: keeping the scanner running and "
                                 "re-evaluating", level="warning")
                if empty_rounds > 3:
                    if self.config.scan_time and not self.session.aps:
                        self.bus.log("no access points found — check the adapter, the band "
                                     "and the channel settings", level="warning")
                    self.bus.log("nothing left to do in this campaign", level="info")
                    break
                self._sleep_interruptible(min(30.0, max(10.0, self.config.scan_time)))
                continue

            empty_rounds = 0
            ran_any = False
            # preferred_attacks() re-derives the whole ladder per call; one
            # answer per target per round is plenty and keeps big presets fast
            attackable_cache: Dict[str, List[str]] = {}
            side_pool = self._side_executor()
            for action in actions:
                if self.stop_event.is_set():
                    break
                if self.campaign_deadline and time.time() > self.campaign_deadline:
                    break
                ap = self.session.ap(action.bssid)
                if ap is None:
                    continue
                if ap.cracked:
                    self.bus.log(f"{ap.display_name}: already cracked, skipping "
                                 f"{action.attack}", level="debug")
                    continue
                if action.attack != "crack" and action.attack not in \
                        attackable_cache.setdefault(ap.bssid, self.attackable(ap)):
                    self.bus.log(f"{ap.display_name}: {action.attack} is no longer "
                                 f"sensible, skipping the stale plan entry", level="debug")
                    continue
                if action.attack == "crack":
                    capture = next((c for c in reversed(ap.captures)
                                    if c.kind in ("handshake", "pmkid") and not c.password), None)
                    if capture is not None:
                        ran_any = True
                        self.crack_capture(ap, capture)
                    continue
                if action.attack == "stop":
                    continue
                reason = action.reason
                if action.source == "llm":
                    reason = f"AI: {action.reason}"
                source = "llm" if action.source == "llm" else "heuristic"
                if side_pool is not None and _side_lane_attack(action.attack):
                    # IT/offline work runs beside the radio, not behind it
                    ran_any = True
                    self._side_futures.append(side_pool.submit(
                        self.run_attack, ap.bssid, action.attack, reason, source, True))
                    continue
                if self.run_attack(ap.bssid, action.attack, reason=reason,
                                   source=source) is not None:
                    ran_any = True
                # a fresh crack pass every few minutes keeps loot from piling up uncracked
                if time.time() - last_crack_pass > 300:
                    last_crack_pass = time.time()
                    self._crack_all_pending()

            # drain the non-radio backlog in parallel while the planner's
            # radio choices run their course
            if self._side_sweep(attackable_cache):
                ran_any = True
            self._reap_lanes()
            if ran_any:
                stale_rounds = 0
            else:
                # every planned action was stale (target cracked since the
                # plan was made, attack no longer sensible): do not execute
                # the same dead plan until the deadline — replan now, and
                # stop after three dead rounds in a row
                stale_rounds += 1
                force_replan = True
                if stale_rounds >= 3:
                    self.bus.log("the planner has nothing actionable left", level="info")
                    break
            if self._all_done():
                self.bus.log("every discovered target has been handled", level="success")
                break
            self._sleep_interruptible(2.0)

    def _maybe_replan(self) -> Optional[Plan]:
        provider_config = self.config.llm_config()
        interval = self.config.think_interval_seconds()
        min_interval = float(getattr(provider_config, "min_interval", 12.0) or 12.0)
        interval = max(min_interval, interval)
        if not self.config.autothink_enabled():
            interval = max(20.0, interval)
        new_aps = max(0, len(self.session.aps) - self._new_aps_at_plan)
        due, why = should_replan(self.session, self._last_plan,
                                 new_aps=new_aps, failures=self._failures_since_plan,
                                 interval=interval if self.config.ai_enabled() else max(20.0, interval))
        if not due:
            return self._last_plan
        self.bus.log(f"re-planning ({why})", level="debug")
        plan = self.think(force=True) if self.config.ai_enabled() else self._heuristic_plan()
        return plan

    def _crack_all_pending(self) -> None:
        for ap in list(self.session.aps.values()):
            if ap.cracked:
                continue
            capture = next((c for c in ap.captures
                            if c.kind in ("handshake", "pmkid") and not c.password
                            and (c.path or c.hash_path)), None)
            if capture is None:
                continue
            if self.stop_event.is_set():
                return
            self.crack_capture(ap, capture)

    def _wanted(self, bssid: str) -> bool:
        return not self._targets_filter or bssid in self._targets_filter

    def _all_done(self) -> bool:
        if any(not f.done() for f in self._side_futures):
            return False
        candidates = [ap for ap in self.session.aps.values() if self._wanted(ap.bssid)]
        if not candidates:
            return False
        for ap in candidates:
            if ap.cracked:
                continue
            if self.attackable(ap):
                return False
        return True

    def _sleep_interruptible(self, seconds: float) -> None:
        deadline = time.time() + seconds
        while time.time() < deadline:
            if self.stop_event.is_set():
                return
            if not self.pause_event.wait(0.3):
                self.pause_event.wait()
            time.sleep(0.1)

    # ------------------------------------------------------------------ #
    # operator controls (web UI)
    # ------------------------------------------------------------------ #
    def request_start(self, targets: Sequence[str] = (), duration: float = 0.0,
                      scan_first: bool = True, preset: str = "",
                      accel: str = "") -> str:
        if self.status.campaign_running:
            return "a campaign is already running"
        if preset:
            self.config.preset = preset
        if accel:
            self.config.accel = accel
        self.stop_event.clear()
        self.attack_cancel.clear()
        self.add_job("campaign", lambda: self.run_campaign(list(targets), duration, scan_first))
        self.start_worker()
        return "campaign queued"

    def request_stop(self) -> str:
        self.attack_cancel.set()
        self.stop_event.set()
        self.bus.log("stop requested by operator", level="warning")
        return "stopping"

    def request_cancel_attack(self) -> str:
        self.attack_cancel.set()
        self.bus.log("cancelling the current attack", level="warning")
        return "cancelling"

    def request_attack(self, bssid: str, attack: str = "", reason: str = "") -> str:
        ap = self.session.ap(bssid)
        if ap is None:
            return f"unknown target {bssid}"
        choices = self.attackable(ap)
        attack = attack or (choices[0] if choices else "")
        if not attack:
            return f"no attack available for {ap.display_name}"
        if attack not in choices:
            self.bus.warn(f"{attack} is not currently sensible for {ap.display_name}; running anyway")
        self.start_worker()
        self.add_job(f"attack:{attack}", lambda: self.run_attack(bssid, attack, reason or "", "operator"))
        return f"queued {attack} against {ap.display_name}"

    def request_crack(self, bssid: str, wordlists: Sequence[str] = (),
                      masks: Sequence[str] = ()) -> str:
        self.start_worker()
        self.add_job(f"crack:{bssid}", lambda: self.crack_target(bssid, wordlists, masks))
        return (f"queued crack for {bssid}"
                + (f" with {len(list(masks))} mask(s)" if masks else ""))

    def request_rescan(self, seconds: float = 20.0) -> str:
        self.start_worker()
        self.add_job("rescan", lambda: self.scan_for(seconds))
        return f"rescanning for {int(seconds)}s"

    def request_think(self) -> Plan:
        return self.think(force=True)

    # ------------------------------------------------------------------ #
    def snapshot(self) -> Dict[str, Any]:
        data = self.session.snapshot()
        data["engine"] = self.status.to_dict()
        data["advisor"] = self.advisor.status()
        data["scanner"] = self.scanner.stats() if self.scanner else {}
        data["attacks"] = self._attack_catalog()
        # redact_secrets: /api/state is served to the browser
        data["config"] = self.config.to_dict(redact_secrets=True)
        data["platform"] = platform_info()
        data["capabilities"] = registry.capabilities()
        return data

    def _attack_catalog(self) -> List[Dict[str, Any]]:
        from .attacks import attack_catalog
        catalog = attack_catalog()
        caps = registry.capabilities()
        for item in catalog:
            item["available"] = all(caps.get(flag, False) for flag in item["requires"]) or self.demo
            item["enabled"] = item["name"] in self.config.attacks
        return catalog

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Engine demo={self.demo} phase={self.status.phase} aps={len(self.session.aps)}>"
