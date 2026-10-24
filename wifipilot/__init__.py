# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""wifipilot -- an AI-piloted alternative to wifite.

wifipilot automates the boring parts of authorised WiFi auditing:

* discovery of access points and their clients (airodump-ng / iw / nmcli)
* capture of WPA/WPA2 4-way handshakes and client-less PMKID hashes
* WPS Pixie-Dust / PIN recovery (reaver / bully, via wash for discovery)
* WEP IV harvesting
* offline cracking orchestration (aircrack-ng / hashcat) with wordlist + rule
  intelligence
* **auto-think**: a local LLM served by Ollama (or OpenRouter, opt-in) plans the
  engagement, adapts when an attack fails and explains itself in plain language —
  *AI-piloted* means the model proposes and wifipilot disposes; every plan is
  validated before it reaches the radio
* **optional by design, off by one switch**: `wp.ai(disable=True)`,
  `--no-ai`/`--disable-ai`/`--offline` or `WIFIPILOT_NO_AI=1` hands the piloting
  back to the deterministic planner, which does the same job with no model in the
  loop at all and never opens a socket to one
* a live web UI (FastAPI + WebSocket) that mirrors the whole session

It is also a library: the public API is re-exported here, so a script can drive
an engagement directly::

    import wifipilot as wp

    wp.attack(target="all", mode="force", demo=True)      # rehearse safely
    result = wp.attack(target="CafeWiFi", mode="stealth", duration="10m")
    for hit in result.passwords:
        print(hit["essid"], "->", hit["password"])

See docs/PYTHON-API.md.  Live runs refuse to transmit without
``wp.authorize(...)``, and everything is Linux-only.

Written and maintained by **codero-sus** —
https://github.com/codero-sus · https://the-codero.web.app

The Linux-only tools are imported lazily, so ``import wifipilot`` works
everywhere (CI, docs builds, a laptop that only wants the type hints) and only
fails — with a clear message — when you actually run something.
"""

from __future__ import annotations

__version__ = "0.1.0"

#: wifipilot is written and maintained by codero-sus.
__author__ = "codero-sus"
AUTHOR = "codero-sus"
AUTHOR_GITHUB = "https://github.com/codero-sus"
AUTHOR_SITE = "https://the-codero.web.app"
CREDIT = "wifipilot by codero-sus — https://github.com/codero-sus · https://the-codero.web.app"

__all__ = [
    "__version__", "__author__", "AUTHOR", "AUTHOR_GITHUB", "AUTHOR_SITE", "CREDIT",
    "TOOL_NAME", "LEGAL_NOTICE",
    # scriptable API
    "ALL", "ALL_ATTACKS", "MODES", "WifiPilotError", "PlatformError", "AuthorizationError",
    "BusyError",
    "TargetError", "Run", "ScanResult", "CampaignResult",
    "configure", "config", "demo", "authorize", "ai", "set_provider", "providers",
    "advisor_status", "scan", "attack", "crack", "analyze", "export", "suggest_masks",
    "strategies", "presets", "accel_info", "install_tools", "update",
    "targets", "select", "selected", "note", "notes", "tag", "history",
    "vendor", "identify", "passwords", "advice", "benchmark", "hash_stats",
    "merge_hashes", "rescue_capture", "wordlist_stats", "expand_wordlist",
    "rules_info", "loot_manifest", "verify_loot", "loot", "report",
    "survey", "probes", "pins", "reveal", "eap", "decode", "pmk_verify", "pmk_convert",
    "pmk_cache",
    "status",
    "session", "engine", "subscribe", "stop", "reset", "is_running",
    # editions and the device shelf
    "editions", "devices", "device",
    # the simulated environments a demo run meets
    "simulations",
    # run bookkeeping and the catalogue (imported above, now also exported)
    "current_run", "catalogue",
    # event kinds, the transport exception tree and the data/config classes
    # a script needs without reaching into submodules
    "EK", "LLMAuthError", "LLMCreditError", "LLMError", "LLMPolicyError",
    "LLMRateLimitError", "Config", "OllamaConfig", "OpenRouterConfig",
    "AccessPoint", "Capture",
]

TOOL_NAME = "wifipilot"

LEGAL_NOTICE = """\
wifipilot is an offensive WiFi auditing framework.

Using it against networks you do not own or do not have explicit written
permission to test is a criminal offence in most jurisdictions
(Computer Fraud and Abuse Act, Computer Misuse Act, StGB s.202a-c, ...).

Active attacks (deauthentication, WPS PIN brute force, association floods)
disrupt the target network: never run them on a production network without a
maintenance window and a named authorising party.
"""


# --------------------------------------------------------------------------- #
# scriptable API
# --------------------------------------------------------------------------- #
# eager: pure stdlib, no side effects, and the whole point of the package is
# that `import wifipilot as wp` gives you something to call.
# `wp.presets` is the API function and `wifipilot.presets` is also a submodule
# (the same dual life `wp.config` leads): loading the submodule first keeps
# the package attribute from flipping to the module on first lazy import.
# (Removing this preload — the _PackageModule guard below should have made
# it unnecessary — deterministically failed the 3.13 CI job while 3.9-3.12
# stayed green; 13 ms is cheap insurance until that is understood on a
# local 3.13, which this project currently cannot run.)
from . import presets as _presets_module  # noqa: E402,F401
from .api import (  # noqa: E402  (import at the end: api.py imports config/models)
    # ALL_ATTACKS and MODES are deliberately absent here: both need the
    # attack registry (~0.5 s of imports), so they materialise on first
    # access through the module __getattr__ below instead of taxing every
    # ``import wifipilot``.
    ALL, AuthorizationError, BusyError, CampaignResult, PlatformError, Run,
    ScanResult, TargetError, WifiPilotError, advisor_status, analyze, attack, authorize,
    config, configure, crack, current_run, demo, engine, export, is_running, loot,
    suggest_masks, strategies, presets, accel_info, install_tools, update,
    catalogue, targets, select, selected, note, notes, tag, history,
    editions, devices, device, simulations,
    vendor, identify, passwords, advice, benchmark, hash_stats, merge_hashes,
    rescue_capture, wordlist_stats, expand_wordlist, rules_info, loot_manifest,
    verify_loot, survey, probes, pins, reveal, eap, decode, pmk_verify, pmk_convert,
    pmk_cache, ai,
    providers, report, reset, scan, session, set_provider, status, stop, subscribe,
)

# `wp.EK` for event filtering plus the exception tree of the transports, so
# scripts do not have to reach into submodules for the common cases.
from .events import EK  # noqa: E402
from .llm import (  # noqa: E402
    LLMAuthError, LLMCreditError, LLMError, LLMPolicyError, LLMRateLimitError,
)
from .config import Config, OllamaConfig, OpenRouterConfig  # noqa: E402
from .models import AccessPoint, Capture  # noqa: E402


def __getattr__(name: str):  # PEP 562: registry-derived data, on first touch
    if name in ("ALL_ATTACKS", "MODES"):
        import importlib

        # NB: importlib, not ``from . import api`` — this package's
        # attributes lead dual lives (``wp.presets``/``wp.config`` are
        # functions), and the module must come from sys.modules either way.
        api = importlib.import_module("wifipilot.api")
        value = getattr(api, name)          # api.__getattr__ builds + caches it
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    return sorted(set(globals()) | {"ALL_ATTACKS", "MODES"})


# Six public names lead dual lives: ``wp.crack`` is a function and
# ``wifipilot.crack`` is also a submodule (likewise config/demo/engine/
# presets/session).  Python sets the package attribute to the *module*
# whenever a submodule is first loaded, so a single lazy
# ``import wifipilot.demo`` anywhere used to flip ``wp.demo`` into a module
# and break the documented API.  The old defence was import-order luck
# (everything loaded eagerly, functions bound last); with the lazy imports
# above that luck ran out.  This module subclass makes the functions win
# deterministically, whatever gets imported in whatever order — the
# submodules stay reachable through ``sys.modules``/``importlib``, which is
# how this codebase already reaches shadowed modules.
import sys as _sys
import types as _types

_API_FUNCTIONS = {
    "config": config, "crack": crack, "demo": demo,
    "engine": engine, "presets": presets, "session": session,
}


class _PackageModule(_types.ModuleType):
    """Package module whose API functions outrank same-named submodules."""

    def __getattribute__(self, name: str):
        fn = _API_FUNCTIONS.get(name)
        if fn is not None:
            return fn
        return super().__getattribute__(name)


_sys.modules[__name__].__class__ = _PackageModule
