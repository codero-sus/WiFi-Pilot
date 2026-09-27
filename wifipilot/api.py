"""Scriptable API — drive wifipilot from your own Python code.

Everything the command line does is available here as ordinary function calls::

    import wifipilot as wp

    wp.attack(target="all", mode="force")            # live (needs authorisation)
    wp.attack(target="all", mode="force", demo=True) # safe simulation, no radio

    result = wp.scan(duration=10)
    for ap in result.strongest():
        print(ap.essid, ap.bssid, ap.encryption, ap.score)

    result = wp.attack(target=["AC:12:34:56:78:90", "CafeWiFi"], mode="stealth",
                       duration=300, on_event=print)
    for hit in result.passwords:
        print(hit["essid"], "->", hit["password"])

Design notes
------------
* **Never silent about danger.** :func:`attack` refuses to transmit on a live
  radio unless authorisation was asserted (:func:`authorize`, ``authorized=True``
  or ``demo=True``).  The refusal is an exception, not a prompt.
* **Linux only**, like the tool itself: calling into the engine on another
  platform raises :class:`PlatformError` (importing :mod:`wifipilot` is always
  safe, so documentation/CI tooling can read the package anywhere).
* **One campaign at a time.** A module-level context holds the active config,
  engine and session; a second :func:`attack` while one is running raises
  :class:`BusyError` instead of silently fighting over the radio.  Use
  ``background=True`` to keep control and ``run.wait()`` / ``run.stop()``.
* **No quiet surprises.** Chatter goes to the event bus, not stdout; pass
  ``on_event=``, :func:`subscribe` or ``verbose=True`` to watch it.
"""

from __future__ import annotations

import builtins
import json
import os
import threading
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union

from .config import Config
from .engine import Engine
from .events import Event
from .models import AccessPoint, Capture
from .util import PLATFORM_OVERRIDE_ENV, is_linux, mac_norm, parse_duration

__all__ = [
    "ALL", "MODES", "WifiPilotError", "PlatformError", "AuthorizationError", "BusyError",
    "TargetError", "CampaignError", "Run", "ScanResult", "CampaignResult",
    "configure", "config", "demo", "authorize", "set_provider", "providers", "advisor_status",
    "scan", "attack", "crack", "analyze", "export", "suggest_masks", "loot", "report",
    "strategies", "targets", "select", "selected", "note", "notes", "tag", "history",
    "vendor", "identify", "passwords", "advice", "benchmark", "hash_stats",
    "merge_hashes", "rescue_capture", "wordlist_stats", "expand_wordlist",
    "rules_info", "loot_manifest", "verify_loot",
    "status", "session", "engine", "current_run", "subscribe", "stop", "reset",
    "is_running",
]

#: wildcard target: every access point the scan found ("all", "*", None — and the
#: builtin ``all``, so ``wp.attack(target=all)`` does what it looks like it does)
ALL = "all"

#: how much a run is allowed to disturb the neighbourhood
MODES: Dict[str, Dict[str, Any]] = {
    # name        loud, disruptive, everything that is off by default is turned on
    "force": {"stealth": False, "wps_pin": True, "attacks": None},
    # the tool's own defaults: handsake/PMKID/WPS-pixie/WEP, no online PIN attack
    "default": {"stealth": False, "wps_pin": False, "attacks": None},
    # listen-only: passive capture + offline cracking, no deauth, no online PIN
    "stealth": {"stealth": True, "wps_pin": False, "attacks": None},
    # strictly passive: capture what the neighbourhood volunteers, never transmit
    "passive": {"stealth": True, "wps_pin": False,
                "attacks": ["passive", "pmkid", "handshake", "crack"]},
    # grab a handshake/PMKID as fast as possible and crack it offline
    "quick": {"stealth": False, "wps_pin": False,
              "attacks": ["pmkid", "handshake", "crack"]},
}
#: "recall" is easy to type and means the same as a normal engagement
MODES["recall"] = MODES["default"]


# --------------------------------------------------------------------------- #
# errors
# --------------------------------------------------------------------------- #


class WifiPilotError(RuntimeError):
    """Base class for everything this module raises on purpose."""


class PlatformError(WifiPilotError):
    """wifipilot drives Linux wireless subsystems it cannot work without."""


class AuthorizationError(WifiPilotError, PermissionError):
    """A live run was requested without an authorisation attestation."""


class BusyError(WifiPilotError):
    """Another campaign/scan is already using this process' radio."""


class TargetError(WifiPilotError):
    """The target selector matched nothing (or nothing was discovered)."""


class CampaignError(WifiPilotError):
    """The campaign itself blew up; the partial result is on ``.result``."""

    def __init__(self, message: str, result: Any = None):
        super().__init__(message)
        self.result = result


# --------------------------------------------------------------------------- #
# results
# --------------------------------------------------------------------------- #


@dataclass
class Run:
    """A finished (or running) engagement: the session plus convenience views."""

    session: Any
    engine: Any = None
    demo: bool = False
    authorized: bool = False
    modes: str = ""
    error: str = ""                      # set when the campaign raised
    _thread: Optional[threading.Thread] = None

    # -- APs ---------------------------------------------------------------- #
    @property
    def aps(self) -> List[AccessPoint]:
        """Every access point seen, strongest first."""
        return list(self.session.sorted_aps())

    def strongest(self, limit: int = 0) -> List[AccessPoint]:
        aps = self.aps
        return aps[:limit] if limit else aps

    def by_ssid(self, pattern: str) -> List[AccessPoint]:
        needle = pattern.lower()
        return [ap for ap in self.aps if needle in (ap.essid or "").lower()]

    def get(self, bssid: str) -> Optional[AccessPoint]:
        return self.session.ap(mac_norm(bssid) or bssid)

    def __iter__(self):
        return iter(self.aps)

    def __len__(self) -> int:
        return len(self.session.aps)

    # -- loot --------------------------------------------------------------- #
    @property
    def captures(self) -> List[Capture]:
        """Every artifact captured this run (valid or not), newest first."""
        return list(self.session.all_captures())

    @property
    def loot(self) -> List[Capture]:
        """Captures good enough to crack (valid capture or a recovered password)."""
        return list(self.session.loot())

    @property
    def passwords(self) -> List[Dict[str, Any]]:
        """Every recovered key: ``{bssid, essid, password, kind, verified}``."""
        out: List[Dict[str, Any]] = []
        for capture in self.session.all_captures():
            if not capture.password:
                continue
            ap = self.session.ap(capture.bssid)
            out.append({
                "bssid": capture.bssid,
                "essid": (ap.essid if ap else "") or "",
                "password": capture.password,
                "kind": capture.kind,
                "verified": bool(capture.valid),
                "path": capture.path,
            })
        return out

    @property
    def stats(self) -> Any:
        return self.session.stats

    @property
    def provider(self) -> str:
        advisor = getattr(self.engine, "advisor", None)
        return advisor.provider if advisor is not None else "none"

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    # -- reports ------------------------------------------------------------ #
    @property
    def report_json(self) -> str:
        """Path of the JSON report for this run (written by :meth:`save`)."""
        return self.session.path("reports", "report.json")

    @property
    def report_markdown(self) -> str:
        """Path of the markdown report for this run (written by ``save(markdown=True)``)."""
        return self.session.path("reports", "report.md")

    def to_dict(self) -> Dict[str, Any]:
        data = self.session.export()
        data["passwords"] = self.passwords
        data["demo"] = self.demo
        data["authorized"] = self.authorized
        data["modes"] = self.modes
        data["error"] = self.error
        data["platform"] = _platform()
        return data

    def json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def save(self, path: str = "", markdown: bool = False) -> str:
        """Write the report (JSON by default) and return the path used."""
        if markdown:
            return self.session.write_markdown_report(path or None)
        return self.session.write_report(path or None)

    def summary(self) -> str:
        stats = self.stats
        lines = [
            f"{'simulation' if self.demo else 'engagement'} {self.session.id} "
            f"finished after {stats.uptime:.0f}s",
            f"  targets   {stats.aps_seen} APs · {stats.clients_seen} clients",
            f"  attacks   {stats.attacks_run} run · {stats.attacks_failed} failed",
            f"  captures  {stats.loot} loot items (handshakes {stats.handshakes}, "
            f"PMKIDs {stats.pmkids}, WPS {stats.wps_cracks}, WEP {stats.wep_cracks})",
            f"  AI        provider {self.provider} · {stats.llm_calls} calls · "
            f"{stats.llm_tokens} tokens · ${stats.llm_cost:.4f}",
            f"  results   {stats.passwords} "
            f"{'password' if stats.passwords == 1 else 'passwords'} recovered",
        ]
        for hit in self.passwords:
            lines.append(f"    {hit['essid'] or hit['bssid']} → {hit['password']} "
                         f"({hit['kind']}{', verified' if hit['verified'] else ''})")
        return "\n".join(lines)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (f"<{type(self).__name__} {self.session.id} "
                f"{'demo' if self.demo else 'live'} aps={len(self.session.aps)} "
                f"passwords={len(self.passwords)}>")

    # -- control ------------------------------------------------------------ #
    def wait(self, timeout: float = 0.0) -> "Run":
        """Block until the campaign finishes (``timeout=0`` waits forever)."""
        if self._thread is not None:
            self._thread.join(timeout or None)
        return self

    def stop(self) -> "Run":
        """Ask a background run to stop cleanly and wait for it."""
        stop()
        return self


class ScanResult(Run):
    """What :func:`scan` found."""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session": self.session.id,
            "demo": self.demo,
            "platform": _platform(),
            "access_points": [ap.to_dict() if hasattr(ap, "to_dict") else vars(ap)
                              for ap in self.aps],
        }


class CampaignResult(Run):
    """The outcome of :func:`attack` — same views as :class:`Run`, plus helpers."""

    def cracked(self) -> List[Dict[str, Any]]:
        return [hit for hit in self.passwords if hit["verified"]]

    def unbroken(self) -> List[AccessPoint]:
        """Targets that were attacked but produced no key (the honest findings)."""
        recovered = {hit["bssid"] for hit in self.passwords}
        return [ap for ap in self.aps if ap.bssid not in recovered]


# --------------------------------------------------------------------------- #
# module state
# --------------------------------------------------------------------------- #


class _Context:
    """Holds the active config/engine/session. One campaign at a time."""

    def __init__(self) -> None:
        self.config: Optional[Config] = None
        self.engine: Optional[Engine] = None
        self.run: Optional[Run] = None
        #: a detached session for notes/tags before (or after) a campaign
        self.session: Optional[Any] = None
        self.lock = threading.RLock()
        self.subscribers: List[Tuple[Callable[[Event], Any], Optional[List[str]]]] = []
        self.quiet = True

    def get_config(self) -> Config:
        if self.config is None:
            self.config = Config()
        return self.config

    def attach(self, engine: Engine) -> List["_Pump"]:
        pumps = [_Pump(engine, fn, kinds) for fn, kinds in self.subscribers]
        return pumps


@dataclass
class _Pump:
    """Delivers bus events to a user callback from a background thread."""

    engine: Engine
    callback: Callable[[Event], Any]
    kinds: Optional[List[str]] = None
    thread: Optional[threading.Thread] = field(default=None, init=False)
    _closing: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        self._sub = self.engine.bus.subscribe(self.kinds)
        self.thread = threading.Thread(target=self._loop, name="wifipilot-events", daemon=True)
        self.thread.start()

    def _loop(self) -> None:
        while not self._closing:
            event = self._sub.get(0.25)
            if event is None:
                if self.engine.stop_event.is_set() and self._sub.queue.empty():
                    break
                continue
            try:
                self.callback(event)
            except Exception:      # a broken callback must not kill the campaign
                pass

    def close(self) -> None:
        self._closing = True
        self._sub.close()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)


_CTX = _Context()


def _platform() -> Dict[str, Any]:
    from .util import platform_info
    return platform_info()


def _require_linux() -> None:
    override = os.environ.get(PLATFORM_OVERRIDE_ENV, "").strip().lower()
    if is_linux() or override not in ("", "0", "false", "no"):
        return
    raise PlatformError(
        "wifipilot drives Linux wireless subsystems (nl80211 monitor mode, rfkill, "
        "/sys/class/net, aircrack-ng) and has no non-Linux implementation. Run it on "
        f"Linux, or set {PLATFORM_OVERRIDE_ENV}=1 to bypass this check for "
        "tooling and tests.")


# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #

_CONFIG_KEYS = {
    "demo", "interface", "monitor_interface", "authorized", "stealth", "aggressive",
    "attacks", "wps_pin", "wordlists", "wordlist", "output_dir", "session_dir",
    "scan_time", "max_targets", "band", "channels", "channel_hop", "skip_crack",
    "crack_timeout", "cracker", "handshake_timeout", "pmkid_timeout", "wps_timeout",
    "wep_timeout", "attack_timeout", "ai_provider", "provider", "model", "think_interval",
    "ai_budget", "redact_identifiers", "verbose_tools", "log_level", "rules",
    "use_rules", "use_masks", "mask_patterns", "mask_candidates", "targeted_candidates",
    "mac_rotate", "randomize_mac", "kill_interfering",
    "restore_interface", "check_handshakes", "save_session", "ignore_known",
    "config_file", "config", "openrouter_key", "ollama_host", "authorization_note",
    "deauth_count", "deauth_interval", "deauth_burst", "scan_rounds",
}


def configure(**kwargs: Any) -> Config:
    """Create or update the module-level configuration.

    Every keyword matches a :class:`~wifipilot.config.Config` field, plus the
    conveniences ``provider``/``model``/``think_interval``/``ai_budget``/
    ``redact_identifiers``/``wordlist``.  Returns the config object, which is
    also what every other function in this module uses until :func:`reset`.
    """
    unknown = set(kwargs) - _CONFIG_KEYS
    if unknown:
        raise TypeError(f"unknown configuration option(s): {', '.join(sorted(unknown))}")

    with _CTX.lock:
        base = _CTX.config
        if kwargs.get("config") is not None:
            base = kwargs["config"]
        elif kwargs.get("config_file"):
            base = Config.load(kwargs["config_file"])
        if base is None:
            base = Config()
        _CTX.config = base
        config = base

        if "wordlist" in kwargs and kwargs["wordlist"]:
            config.wordlists = _as_list(kwargs["wordlist"])
        if "wordlists" in kwargs and kwargs["wordlists"]:
            config.wordlists = _as_list(kwargs["wordlists"])
        if kwargs.get("wps_pin"):
            if "wps_pin" not in (config.attacks or []):
                config.attacks = list(config.attacks or []) + ["wps_pin"]
        if kwargs.get("attacks"):
            attacks = kwargs["attacks"]
            config.attacks = (list(attacks) if not isinstance(attacks, str)
                              else [a.strip() for a in attacks.split(",") if a.strip()])
        if kwargs.get("channels"):
            config.channels = [int(c) for c in _as_list(kwargs["channels"])]

        direct = {
            "demo": "demo", "interface": "interface", "monitor_interface": "monitor_interface",
            "authorized": "authorized", "stealth": "stealth", "aggressive": "aggressive",
            "output_dir": "output_dir", "session_dir": "session_dir",
            "scan_time": "scan_time", "max_targets": "max_targets", "band": "band",
            "channel_hop": "channel_hop", "skip_crack": "skip_crack",
            "crack_timeout": "crack_timeout", "cracker": "cracker",
            "handshake_timeout": "handshake_timeout", "pmkid_timeout": "pmkid_timeout",
            "wps_timeout": "wps_timeout", "wep_timeout": "wep_timeout",
            "attack_timeout": "attack_timeout",
            "verbose_tools": "verbose_tools", "log_level": "log_level",
            "rules": "rules", "use_rules": "use_rules", "use_masks": "use_masks",
            "mask_patterns": "mask_patterns", "mask_candidates": "mask_candidates",
            "targeted_candidates": "targeted_candidates",
            "mac_rotate": "mac_rotate", "randomize_mac": "randomize_mac",
            "kill_interfering": "kill_interfering", "restore_interface": "restore_interface",
            "check_handshakes": "check_handshakes", "save_session": "save_session",
            "ignore_known": "ignore_known", "deauth_count": "deauth_count",
            "deauth_interval": "deauth_interval", "deauth_burst": "deauth_burst",
            "scan_rounds": "scan_rounds", "authorization_note": "authorization_note",
        }
        for key, attribute in direct.items():
            if key in kwargs and kwargs[key] is not None:
                setattr(config, attribute, kwargs[key])

        provider = kwargs.get("provider", kwargs.get("ai_provider"))
        if provider:
            config.ai_provider = str(provider).strip().lower()
            if config.ai_provider == "openrouter":
                config.openrouter.enabled = True
        if kwargs.get("model"):
            target = (config.openrouter if config.ai_provider == "openrouter"
                      else config.ollama)
            target.model = kwargs["model"]
        if kwargs.get("think_interval") is not None:
            seconds = float(parse_duration(str(kwargs["think_interval"]), 45.0))
            config.ollama.think_interval = seconds
            config.openrouter.think_interval = seconds
        if kwargs.get("ai_budget") is not None:
            config.openrouter.max_cost_usd = float(kwargs["ai_budget"])
        if kwargs.get("redact_identifiers") is not None:
            config.openrouter.redact_identifiers = bool(kwargs["redact_identifiers"])
        if kwargs.get("openrouter_key"):
            config.openrouter.api_key = str(kwargs["openrouter_key"])
        if kwargs.get("ollama_host"):
            config.ollama.host = str(kwargs["ollama_host"])
        return config


def config() -> Config:
    """The configuration every function in this module is using."""
    return _CTX.get_config()


def demo(enabled: bool = True) -> Config:
    """Turn simulation mode on/off (no radio is touched while it is on)."""
    return configure(demo=bool(enabled))


def authorize(note: str = "", confirmed: bool = True) -> Config:
    """Assert written authorisation for the targets you are about to test.

    Required before :func:`attack` will transmit on a live radio.  ``note`` is
    stored with the session and printed in the report, so an engagement can
    always be traced back to whoever approved it.
    """
    config = configure(authorized=bool(confirmed))
    if note:
        config.authorization_note = note
    return config


def set_provider(provider: str = "auto", model: str = "", **kwargs: Any) -> Dict[str, Any]:
    """Choose the AI provider (``auto``/``ollama``/``openrouter``/``none``).

    Returns the advisor status dict.  Enabling OpenRouter means engagement data
    leaves this machine; identifiers stay pseudonymised unless
    ``redact_identifiers=False`` is passed.
    """
    provider = (provider or "auto").strip().lower()
    if provider not in ("auto", "ollama", "openrouter", "none"):
        raise ValueError("provider must be auto, ollama, openrouter or none")
    if provider == "openrouter":
        kwargs.setdefault("redact_identifiers", True)
    configure(provider=provider, model=model or None, **kwargs)
    if _CTX.engine is not None:
        _CTX.engine.advisor.configure(provider, announce=False)
        if model:
            _CTX.engine.advisor.use_model(model)
    return advisor_status()


def providers(probe: bool = False) -> List[Dict[str, Any]]:
    """What is configured for each provider, and (optionally) whether it answers."""
    from .llm import provider_status
    cfg = config()
    return provider_status(cfg.ollama, cfg.openrouter, probe=probe)


def advisor_status() -> Dict[str, Any]:
    """The advisor's view of itself: provider, model, reachability, spend."""
    engine = _CTX.engine
    if engine is None:
        from .advisor import Advisor
        from .events import EventBus
        from .session import Session
        cfg = config()
        session = Session(cfg, EventBus(), demo=cfg.demo, authorized=cfg.authorized)
        advisor = Advisor(session, None, session.bus, demo=cfg.demo)
        advisor.configure(provider="", announce=False)
        return advisor.status()
    return engine.advisor.status()


# --------------------------------------------------------------------------- #
# running a session
# --------------------------------------------------------------------------- #


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        return [value]
    return list(value)


def _is_wildcard(target: Any) -> bool:
    return (target is None or target is builtins.all or target == ALL
            or (isinstance(target, str) and target.strip() in ("", "*", "all", "any")))


def _ap_matchers(target: Any) -> List[Callable[[AccessPoint], bool]]:
    """Turn a target selector into predicates over discovered access points."""
    if _is_wildcard(target):
        return [lambda ap: True]
    matchers: List[Callable[[AccessPoint], bool]] = []
    for item in _as_list(target):
        if isinstance(item, AccessPoint):
            bssid = mac_norm(item.bssid)
            matchers.append(lambda ap, b=bssid: ap.bssid == b)
            continue
        if hasattr(item, "bssid") and not isinstance(item, str):     # Client or duck type
            bssid = mac_norm(getattr(item, "bssid", "") or "")
            if bssid:
                matchers.append(lambda ap, b=bssid: ap.bssid == b)
                continue
        text = str(item).strip()
        bssid = mac_norm(text)
        if bssid:
            matchers.append(lambda ap, b=bssid: ap.bssid == b)
        else:
            needle = text.lower()
            matchers.append(lambda ap, n=needle: n in (ap.essid or "").lower())
    return matchers


def _select(session: Any, target: Any) -> List[str]:
    matchers = _ap_matchers(target)
    selected = [ap.bssid for ap in session.sorted_aps()
                if any(match(ap) for match in matchers)]
    if selected:
        return selected
    if _is_wildcard(target):
        raise TargetError(
            "no access points found — check the adapter, the band, or scan longer "
            "(wifipilot.scan(duration=30))")
    seen = ", ".join(f"{ap.essid or '?'} ({ap.bssid})" for ap in session.sorted_aps()[:8])
    raise TargetError(
        f"target {target!r} matched nothing. Discovered: {seen or 'nothing'}")


def _apply_mode(mode: str, config: Config, **overrides: Any) -> Dict[str, Any]:
    key = (mode or "default").strip().lower()
    if key not in MODES:
        raise ValueError(f"unknown mode {mode!r} — pick one of: {', '.join(sorted(MODES))}")
    preset = dict(MODES[key])
    for name, value in overrides.items():
        if value is not None:
            preset[name] = value
    if preset.get("stealth") is not None:
        config.stealth = bool(preset["stealth"])
    if preset.get("attacks"):
        config.attacks = list(preset["attacks"])
    if preset.get("wps_pin"):
        if "wps_pin" not in config.attacks:
            config.attacks = list(config.attacks) + ["wps_pin"]
    elif "wps_pin" in config.attacks:                 # modes without it switch it off
        config.attacks = [a for a in config.attacks if a != "wps_pin"]
    return preset


def _new_engine(config: Config, verbose: bool = False,
                authorized: bool = False) -> Tuple[Engine, List["_Pump"]]:
    if _CTX.engine is not None and _CTX.run is not None and _CTX.run.running:
        raise BusyError("a campaign is already running — stop it first (wifipilot.stop()) "
                        "or pass background=False and wait for the previous call")
    engine = Engine(config, demo=config.demo, authorized=authorized or config.authorized,
                    verbose=verbose)
    _CTX.quiet = not verbose
    if verbose:
        engine.bus.echo = lambda line: print(line, flush=True)
    _CTX.engine = engine
    return engine, _CTX.attach(engine)


def _scan_phase(engine: Engine, seconds: float) -> None:
    if seconds and seconds > 0:
        engine.scan_for(seconds)


def scan(target: Any = ALL, duration: Union[float, str] = 15.0, demo: Optional[bool] = None,
         interface: str = "", on_event: Optional[Callable[[Event], Any]] = None,
         verbose: bool = False, **kwargs: Any) -> ScanResult:
    """Discover access points and clients without attacking anything.

    ``duration`` is the discovery window in seconds (``"30s"``/``"2m"`` work
    too).  The return value is a :class:`ScanResult` whose ``.aps`` are sorted by
    score, with ``.get(bssid)``/``.by_ssid(text)`` helpers for picking a target.
    ``target`` only filters which APs are marked as selected.
    """
    seconds = float(parse_duration(str(duration), 15.0)) if duration else 0.0
    config = configure(demo=demo, interface=interface or None, **kwargs)
    _require_linux()

    with _CTX.lock:
        engine, pumps = _new_engine(config, verbose=verbose, authorized=True)
        if on_event is not None:
            pumps.append(_Pump(engine, on_event))
        try:
            engine.prepare(announce=not _CTX.quiet)
            _scan_phase(engine, seconds)
            engine.session.selected_bssids = _select(engine.session, target)
            result = ScanResult(session=engine.session, engine=engine, demo=config.demo,
                                authorized=True, modes="scan")
            _CTX.run = result
        finally:
            engine.stop_scan()
            for pump in pumps:
                pump.close()
            engine.shutdown()
        return result


def attack(target: Any = ALL, mode: str = "force", duration: Union[float, str] = 0.0,
           scan_time: Union[float, str, None] = None, demo: Optional[bool] = None,
           authorized: Optional[bool] = None, interface: str = "",
           on_event: Optional[Callable[[Event], Any]] = None, verbose: bool = False,
           background: bool = False, crack: bool = True, raise_on_error: bool = True,
           wps_pin: Optional[bool] = None, stealth: Optional[bool] = None,
           attacks: Optional[Sequence[str]] = None, **kwargs: Any) -> CampaignResult:
    """Run a full engagement against ``target`` and return the result.

    ``target`` is ``wifipilot.ALL`` (or ``all``/``"all"``/``"*"``/``None``) for
    everything discovered, a BSSID, an SSID (substring), a list of either, or
    :class:`~wifipilot.models.AccessPoint` objects.

    ``mode`` decides how intrusive the run is (see :data:`MODES`).  The default,
    ``"force"``, is the loud one: deauthentications plus the online WPS PIN
    attack, which can lock an access point's WPS for good.  Use ``"stealth"``
    for listen-only, ``"quick"`` for handshake/PMKID only.

    Live runs need :func:`authorize` first (or ``authorized=True``); without it
    this raises :class:`AuthorizationError` before touching the radio.  Pass
    ``demo=True`` to rehearse the whole thing in simulation mode instead.

    A missing radio or an unmatched target raises immediately
    (:class:`~wifipilot.iface.InterfaceError`, :class:`TargetError`).  A failure
    *during* the campaign is recorded on ``result.error`` and re-raised as
    :class:`CampaignError` (carrying ``.result`` with whatever loot was already
    collected) unless ``raise_on_error=False``.  Background runs never raise
    campaign failures — poll ``result.error`` or watch the events.
    """
    config = configure(demo=demo, interface=interface or None, **kwargs)
    _apply_mode(mode, config, wps_pin=wps_pin, stealth=stealth, attacks=attacks)
    seconds = float(parse_duration(str(duration), 0.0)) if duration else 0.0
    discovery = None if scan_time is None else float(parse_duration(str(scan_time), 0.0))
    if discovery is None:
        discovery = float(config.scan_time or 0.0)
    if not crack:
        config.skip_crack = True

    _require_linux()
    live = not config.demo
    if live and not (authorized if authorized is not None else config.authorized):
        raise AuthorizationError(
            "refusing to transmit: no authorisation on record. Call "
            "wifipilot.authorize(\"change ticket #123\") — or pass authorized=True — "
            "once you have written permission for every target network, or use "
            "demo=True to rehearse the run against a simulated neighbourhood.")

    with _CTX.lock:
        engine, pumps = _new_engine(config, verbose=verbose,
                                    authorized=bool(config.authorized or authorized))
        if on_event is not None:
            pumps.append(_Pump(engine, on_event))
        result = CampaignResult(session=engine.session, engine=engine, demo=config.demo,
                                authorized=engine.authorized, modes=mode)
        _CTX.run = result
        try:
            # interface setup, discovery and target resolution happen up front and
            # synchronously, so their failures are raised to the caller right here
            # (a missing radio or a typo in a target is a programming error, not a
            # campaign incident) — even for background runs.
            engine.prepare(announce=not _CTX.quiet)
            _scan_phase(engine, discovery)
            selected = _select(engine.session, target)
        except BaseException:
            for pump in pumps:
                pump.close()
            raise
        engine.session.selected_bssids = selected

        def campaign() -> None:
            try:
                engine.run_campaign(targets=selected, duration=seconds, scan_first=False)
            except Exception as exc:                     # surfaced through the result
                engine.bus.error(f"campaign failed: {exc}")
                result.error = f"{type(exc).__name__}: {exc}"
            finally:
                for pump in pumps:
                    pump.close()

        thread = threading.Thread(target=campaign, name="wifipilot-campaign", daemon=True)
        result._thread = thread
        thread.start()

    if background:
        return result
    thread.join()
    with _CTX.lock:
        engine.shutdown()
    if result.error and raise_on_error:
        raise CampaignError(result.error.split(": ", 1)[-1], result=result) from None
    return result


def crack(capture: str, wordlist: Union[str, Sequence[str], None] = None,
          essid: str = "", bssid: str = "", timeout: Optional[float] = None,
          mask: Union[str, Sequence[str], None] = None,
          masks: bool = True) -> Any:
    """Crack a capture or a hash file (``.cap``/``.pcap``/``.pcapng``/``.hc22000``).

    Returns the cracker's :class:`~wifipilot.crack.CrackResult` — ``.cracked``,
    ``.password``, ``.verified``, ``.tool``, ``.seconds``.

    This is always the real engine: cracking a file needs no radio, so the
    simulation flag does not apply here.  The built-in engine (SSID/vendor/date
    candidate generation, verified against the handshake MIC or the PMKID) runs
    first, then the supplied ``wordlist``/configured wordlists through
    aircrack-ng or hashcat when they are installed.

    ``mask`` is a hashcat-style mask (``"Telekom-?d?d?d?d"``) or a list of them;
    ``masks=False`` turns the stage off.  Masks bigger than the built-in engine's
    budget are handed to hashcat ``-a 3`` instead of being half-swept.
    """
    from . import hash22000, masks as masks_module
    from .crack import Cracker
    from .models import Capture as CaptureModel
    from .pcap import analyze_file
    from .session import Session
    from .events import EventBus

    config = configure()
    config.use_masks = bool(masks)
    patterns: List[str] = []
    if mask:
        patterns = [mask] if isinstance(mask, str) else [str(m) for m in mask]
        for pattern in patterns:
            masks_module.mask_space(pattern)      # raises MaskError on nonsense
        config.use_masks = True
    path = str(capture)
    if not os.path.exists(path):
        raise WifiPilotError(f"capture not found: {path}")
    if hash22000.is_hash_file(path):
        lines = hash22000.parse_file(path)
        if not lines:
            raise WifiPilotError(f"no usable hash lines in {path}")
        first = lines[0]
        target_bssid = mac_norm(bssid) or first.bssid
        target_essid = essid or first.essid
        kind = "pmkid" if all(line.kind == "pmkid" for line in lines) else "handshake"
        ap = AccessPoint(bssid=target_bssid, essid=target_essid)
        found = CaptureModel(kind=kind, bssid=target_bssid, essid=target_essid, path=path,
                             valid=bool(hash22000.verifiers(lines)),
                             hash_path=path,
                             extra={"pmkid": next((line.pmkid for line in lines
                                                   if line.kind == "pmkid"), "")})
    else:
        analysis = analyze_file(path)
        target_bssid = mac_norm(bssid) or (analysis.bssids[0] if analysis.bssids else "")
        target_essid = (essid or analysis.essids.get(target_bssid, "")
                        or next(iter(analysis.essids.values()), ""))
        kind = ("handshake" if analysis.has_handshake
                else "pmkid" if analysis.has_pmkid
                else "wep_ivs" if analysis.wep_data > 5000 else "handshake")
        ap = AccessPoint(bssid=target_bssid, essid=target_essid)
        found = CaptureModel(kind=kind, bssid=target_bssid, essid=target_essid, path=path,
                             valid=bool(analysis.valid), eapol=analysis.eapol_messages)
    sess = Session(config, EventBus(), demo=False, authorized=True)
    sess.add_capture(found)
    cracker = Cracker(sess, config, sess.bus, demo=False)
    lists = _as_list(wordlist) or list(config.wordlists)
    return cracker.crack_capture(ap, found, wordlists=[str(w) for w in lists], masks=patterns,
                                 timeout=timeout)


def analyze(capture: str) -> Dict[str, Any]:
    """Inspect a capture file, or a hashcat mode 22000 hash file.

    A capture is parsed for EAPOL handshakes, PMKIDs, ESSIDs and validity; a
    ``.hc22000``/``.22000`` file is read as hashes and reported with what can
    actually be tested.
    """
    from . import hash22000
    from .pcap import analyze_file
    path = str(capture)
    if hash22000.is_hash_file(path) and os.path.exists(path):
        lines, problems = hash22000.parse_text(
            Path(path).read_text(encoding="utf-8", errors="replace"))
        data = hash22000.summary(lines, problems)
        data["path"] = path
        data["format"] = "hc22000"
        data["hashes"] = [line.to_dict() for line in lines]
        return data
    analysis = analyze_file(path)
    data = analysis.to_dict() if hasattr(analysis, "to_dict") else dict(vars(analysis))
    return data


def export(capture: str, path: str = "", fmt: str = "22000",
           pmkid: bool = True, eapol: bool = True) -> str:
    """Write a capture out as hashcat mode 22000 (or ``json``/``csv``), return the path.

    The mode 22000 writer is wifipilot's own: no hcxtools, no hashcat, no
    external converter — a capture in, a hash file anyone can crack out.
    """
    from . import hash22000
    from .pcap import analyze_file
    source = str(capture)
    if not os.path.exists(source):
        raise WifiPilotError(f"capture not found: {source}")
    target = path or (os.path.splitext(source)[0] + {
        "json": ".json", "csv": ".csv"}.get(fmt, ".hc22000"))
    if fmt == "22000":
        if hash22000.is_hash_file(source):
            return source                                    # already a hash file
        analysis = analyze_file(source)
        return hash22000.write_lines(hash22000.lines_from_analysis(analysis, pmkid, eapol),
                                     target)
    analysis = analyze_file(source)
    if fmt == "json":
        with open(target, "w", encoding="utf-8") as handle:
            json.dump(analysis.to_dict(), handle, indent=2)
        return target
    raise WifiPilotError(f"unsupported export format {fmt!r} (use 22000, json or csv)")


def suggest_masks(essid: str = "", vendor: str = "") -> List[Dict[str, object]]:
    """Mask patterns worth trying against a target, smallest space first.

    Returns ``[{"mask": "Telekom-?d?d?d?d", "space": 10000, "note": ...}, ...]``
    — the same list the cracker uses, so a caller can show the operator what is
    about to be tried (or feed it back into :func:`crack`).
    """
    from . import masks

    # ``vendor`` may be given, or resolved from the ESSID's OUI like the scanner does
    vendor = vendor or ""
    return [mask.to_dict() for mask in masks.suggest_masks(essid, vendor)]


def strategies() -> List[Dict[str, object]]:
    """The crack strategy presets, with what each one does."""
    from .crack import STRATEGIES
    return [dict(preset) for _, preset in sorted(STRATEGIES.items())]


def _offline_session() -> Any:
    """The active session, or a fresh detached one built from the config.

    The notes/tags/targets helpers must work *before* a campaign starts (and
    after one ends) — they are read-mostly, so a detached Session is enough and
    writing to its state directory is exactly what we want the notes to do.
    """
    if _CTX.session is not None:
        return _CTX.session
    existing = session()
    if existing is not None:
        return existing
    from .events import EventBus
    from .session import Session
    cfg = config()
    fresh = Session(cfg, EventBus(), demo=bool(getattr(cfg, "demo", False)),
                    authorized=bool(getattr(cfg, "authorized", False)))
    _CTX.session = fresh
    return fresh


def targets(kind: str = "", tag: str = "", vendor: str = "",
            cracked: Optional[bool] = None, loot: Optional[bool] = None,
            encryption: str = "", channel: int = 0) -> List[Dict[str, Any]]:
    """Filter the access points discovered so far.

    Filters compose; ``kind`` is the coarse classification
    (:func:`~wifipilot.models.classify_target`), ``vendor`` matches the vendor
    name or its dossier key.  Works with or without a running campaign.
    """
    sess = _offline_session()
    rows: List[Dict[str, Any]] = []
    for ap in sess.filter_aps(kind=kind, tag=tag, vendor=vendor, cracked=cracked,
                              loot=loot, encryption=encryption, channel=channel):
        rows.append(ap.to_dict())
    return rows


def select(bssids: Union[str, Sequence[str], None] = None, **filters: Any) -> List[str]:
    """Make access points the campaign scope; returns the selected BSSIDs.

    ``wp.select(tag="in-scope")`` or ``wp.select(["aa:bb:..."])``; ``clear=True``
    empties the selection first.
    """
    clear = bool(filters.pop("clear", False))
    chosen: List[str] = []
    if bssids:
        chosen.extend(_as_list(bssids))
    if filters:
        chosen.extend(row["bssid"] for row in targets(**filters))
    sess = _offline_session()
    selected = sorted(set(chosen) if clear else {*sess.selected_bssids, *chosen})
    sess.selected_bssids = selected
    return selected


def selected() -> List[Dict[str, Any]]:
    """The current campaign scope, with each AP's kind and tags."""
    sess = _offline_session()
    out: List[Dict[str, Any]] = []
    for bssid in sess.selected_bssids:
        ap = sess.ap(bssid)
        if ap is not None:
            out.append({"bssid": ap.bssid, "essid": ap.essid,
                        "kind": ap.target_kind, "tags": list(ap.tags),
                        "score": round(ap.score, 2)})
    return out


def note(text: str, bssid: str = "") -> Dict[str, Any]:
    """Record an operator note (engagement-level, or attached to one AP)."""
    return _offline_session().add_note(text, bssid=bssid)


def notes(limit: int = 200) -> List[Dict[str, Any]]:
    """Every operator note on disk for this configuration (newest first)."""
    from .session import load_notes
    return load_notes(config(), limit=limit)


def tag(bssid: str, name: str, remove: bool = False) -> List[str]:
    """Tag (or untag) an access point; returns its tags afterwards."""
    return _offline_session().tag_ap(bssid, name, add=not remove)


def history(bssid: str = "", limit: int = 50) -> List[Dict[str, Any]]:
    """What happened, newest first — one AP's history or the whole session."""
    return _offline_session().history(bssid=bssid, limit=limit)


def vendor(query: str = "", bssid: str = "") -> Dict[str, Any]:
    """Vendor dossier + identification for a MAC, vendor name or ESSID.

    Includes ``confidence: "heuristic"``: vendor behaviour is a starting point,
    never a finding.
    """
    from .analytics import identify
    from .util import mac_norm
    from .vendors import oui_lookup, vendor_dossier

    target = bssid or query
    mac = mac_norm(target)
    if mac:
        name, match = oui_lookup(mac)
        return {"query": query or bssid, "mac": mac, "vendor": name, "match": match,
                "dossier": vendor_dossier(name or mac),
                "identification": identify("", name)}
    return {"query": query, "vendor": "", "match": "",
            "dossier": vendor_dossier(query), "identification": identify(query)}


def identify(essid: str = "", bssid: str = "") -> Dict[str, Any]:
    """What wifipilot can guess about a network name/BSSID: scheme, masks, words."""
    from .analytics import identify as identify_impl
    return identify_impl(essid, bssid)


def passwords(include_weak: bool = True) -> List[Dict[str, Any]]:
    """Weakness report for every PSK recovered in this session.

    Each row carries the analyst verdict (pattern family, character classes,
    score) and the time-to-crack estimates, so a report can say *how bad* a
    password is rather than just listing it.
    """
    from .analytics import password_report
    rows: List[Dict[str, Any]] = []
    for ap in _offline_session().sorted_aps():
        if not ap.password:
            continue
        report = password_report(ap.password).to_dict()
        report.update({"bssid": ap.bssid, "essid": ap.essid})
        if not include_weak and report["score"] < 60:
            continue                                     # keep only the strong ones
        rows.append(report)
    rows.sort(key=lambda item: item["score"])
    return rows


def advice() -> List[Dict[str, Any]]:
    """Prioritised next steps from the heuristics, with no LLM round trip."""
    engine_obj = engine()
    if engine_obj is None:
        return heuristic_advice()
    return engine_obj.advice()


def benchmark(seconds: float = 5.0) -> Dict[str, Any]:
    """Measure this machine's candidate verification rate (no radio needed)."""
    from .engine import Engine
    from .events import EventBus
    from .session import Session

    cfg = config()
    sess = Session(cfg, EventBus(), demo=True)
    machine = Engine(cfg, sess.bus, session=sess, demo=True)
    return machine.benchmark(seconds=seconds)


def hash_stats(path: str) -> Dict[str, Any]:
    """What is in a mode 22000 hash file (lines, verifiable, ESSIDs, pairs)."""
    from . import toolbox
    return toolbox.hash_stats(str(path))


def merge_hashes(paths: Sequence[str], out: str = "", dedupe: bool = True
                 ) -> Dict[str, Any]:
    """Merge hash files into one, by default dropping duplicates."""
    from . import toolbox
    return toolbox.merge_hash_files([str(path) for path in paths], out, dedupe=dedupe)


def rescue_capture(capture: str, out: str = "") -> Dict[str, Any]:
    """Recover hashes a normal converter misses (e.g. a PMKID in message 1)."""
    from . import toolbox
    return toolbox.rescue_partial_capture(str(capture), out)


def wordlist_stats(path: str) -> Dict[str, Any]:
    """Shape of a wordlist: lengths, uniqueness, WPA-compatible share, ETA."""
    from . import toolbox
    return toolbox.wordlist_stats(str(path))


def expand_wordlist(path: str, out: str, rules: str = "best64",
                    limit: int = 0) -> Dict[str, Any]:
    """Apply a hashcat rule file (or a built-in preset) to a wordlist."""
    from . import toolbox
    return toolbox.expand_wordlist(str(path), str(out), rules, limit=limit)


def rules_info(spec: str = "best64") -> Dict[str, Any]:
    """Parse and describe a rule file or preset (counts, commands, examples)."""
    from . import rules as rules_module
    loaded = (rules_module.parse_file(spec) if os.path.exists(spec)
              else rules_module.preset(spec))
    return rules_module.describe(loaded)


def loot_manifest(directory: str = "") -> Dict[str, Any]:
    """sha256 every file in the loot directory (write ``manifest.sha256``)."""
    from . import toolbox
    return toolbox.write_manifest(directory or config().output_dir)


def verify_loot(directory: str = "") -> Dict[str, Any]:
    """Check the loot directory against its manifest."""
    from . import toolbox
    return toolbox.verify_manifest(directory or config().output_dir)


def heuristic_advice() -> List[Dict[str, Any]]:
    """Advice without an engine (used when nothing is running)."""
    from .planner import heuristic_plan
    sess = _offline_session()
    if not sess.aps:
        return [{"priority": 1, "action": "scan",
                 "why": "nothing discovered yet", "confidence": "certain"}]
    plan = heuristic_plan(sess)
    return [{"priority": index + 1, "action": action.attack, "bssid": action.bssid,
             "essid": getattr(sess.ap(action.bssid), "essid", ""),
             "why": action.reason, "confidence": "medium"}
            for index, action in enumerate(plan.actions)]


def loot(path: str = "") -> List[Capture]:
    """Captures worth keeping from the most recent run (or a report on disk)."""
    if path:
        with open(path) as handle:
            data = json.load(handle)
        entries = data.get("loot") or data.get("captures") or []
        return [Capture(**{k: v for k, v in entry.items()
                           if k in Capture.__dataclass_fields__})
                for entry in entries]
    return list(_CTX.run.loot) if _CTX.run is not None else []


def report(path: str = "", markdown: bool = False) -> str:
    """Write the most recent run's report and return the path."""
    if _CTX.run is None:
        raise WifiPilotError("no run to report on yet — call scan() or attack() first")
    return _CTX.run.save(path, markdown=markdown)


def status() -> Dict[str, Any]:
    """A small, JSON-friendly picture of what the module is doing right now."""
    run = _CTX.run
    engine = _CTX.engine
    config = _CTX.get_config()
    data: Dict[str, Any] = {
        "platform": _platform(),
        "demo": bool(config.demo),
        "authorized": bool(config.authorized),
        "provider": engine.advisor.provider if engine is not None else config.ai_provider,
        "model": (engine.advisor.model if engine is not None else "") or config.ollama.model,
        "running": bool(run and run.running),
        "mode": run.modes if run else "",
    }
    if run is not None:
        data.update({
            "session": run.session.id,
            "access_points": len(run.session.aps),
            "loot": run.stats.loot,
            "passwords": run.stats.passwords,
            "llm_calls": run.stats.llm_calls,
            "llm_cost_usd": run.stats.llm_cost,
            "report": run.report_json,
        })
    return data


def session() -> Any:
    """The active/last :class:`~wifipilot.session.Session` (or ``None``).

    Order: the running campaign's session, then the engine's, then the detached
    one :func:`_offline_session` creates for the notes/tags/targets helpers.
    """
    if _CTX.run is not None:
        return _CTX.run.session
    if _CTX.engine is not None:
        return _CTX.engine.session
    return _CTX.session


def current_run() -> Optional[Run]:
    """The active/most recent :class:`Run` (``None` before the first call)."""
    return _CTX.run


def engine() -> Optional[Engine]:
    """The active/last :class:`~wifipilot.engine.Engine` (``None`` before a run)."""
    return _CTX.engine


def subscribe(callback: Callable[[Event], Any],
              kinds: Optional[Sequence[str]] = None) -> Callable[[], None]:
    """Call ``callback(event)`` for every bus event (from a background thread).

    ``kinds`` filters by event kind, e.g. ``[EK.AP_NEW, EK.CRACK_FOUND]``.  The
    callbacks stay registered for later runs too; call the returned function to
    unsubscribe.
    """
    entry = (callback, list(kinds) if kinds else None)
    with _CTX.lock:
        _CTX.subscribers.append(entry)
        live = (_CTX.engine is not None and _CTX.run is not None and _CTX.run.running)
        pumps = [_Pump(_CTX.engine, callback, entry[1])] if live else []

    def unsubscribe() -> None:
        with _CTX.lock:
            if entry in _CTX.subscribers:
                _CTX.subscribers.remove(entry)
        for pump in pumps:
            pump.close()

    return unsubscribe


def is_running() -> bool:
    """True while a background campaign is still going."""
    run = _CTX.run
    return bool(run and run.running)


def stop() -> bool:
    """Stop the active campaign/scan cleanly. Returns True if something was running."""
    run = _CTX.run
    if run is None or run.engine is None:
        return False
    engine = run.engine
    engine.stop_event.set()
    engine.attack_cancel.set()
    engine.pause_event.set()                    # pause_event set == not paused
    run.wait(timeout=30.0)
    return True


def reset() -> None:
    """Stop everything and start from a clean configuration."""
    stop()
    with _CTX.lock:
        for callback, kinds in list(_CTX.subscribers):
            _CTX.subscribers.remove((callback, kinds))
        _CTX.subscribers.clear()
        _CTX.engine = None
        _CTX.run = None
        _CTX.config = None
        _CTX.session = None       # drop the detached notes/tags session too
