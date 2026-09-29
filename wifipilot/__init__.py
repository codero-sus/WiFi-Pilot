"""wifipilot -- an AI-piloted alternative to wifite.

wifipilot automates the boring parts of authorised WiFi auditing:

* discovery of access points and their clients (airodump-ng / iw / nmcli)
* capture of WPA/WPA2 4-way handshakes and client-less PMKID hashes
* WPS Pixie-Dust / PIN recovery (reaver / bully, via wash for discovery)
* WEP IV harvesting
* offline cracking orchestration (aircrack-ng / hashcat) with wordlist + rule
  intelligence
* **auto-think**: a local LLM served by Ollama plans the engagement, adapts when
  an attack fails and explains itself in plain language
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

The Linux-only tools are imported lazily, so ``import wifipilot`` works
everywhere (CI, docs builds, a laptop that only wants the type hints) and only
fails — with a clear message — when you actually run something.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = [
    "__version__", "TOOL_NAME", "LEGAL_NOTICE",
    # scriptable API
    "ALL", "ALL_ATTACKS", "MODES", "WifiPilotError", "PlatformError", "AuthorizationError",
    "BusyError",
    "TargetError", "Run", "ScanResult", "CampaignResult",
    "configure", "config", "demo", "authorize", "set_provider", "providers",
    "advisor_status", "scan", "attack", "crack", "analyze", "export", "suggest_masks",
    "strategies", "targets", "select", "selected", "note", "notes", "tag", "history",
    "vendor", "identify", "passwords", "advice", "benchmark", "hash_stats",
    "merge_hashes", "rescue_capture", "wordlist_stats", "expand_wordlist",
    "rules_info", "loot_manifest", "verify_loot", "loot", "report",
    "survey", "probes", "pins", "reveal", "eap", "pmk_verify", "pmk_convert",
    "pmk_cache",
    "status",
    "session", "engine", "subscribe", "stop", "reset", "is_running",
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
from .api import (  # noqa: E402  (import at the end: api.py imports config/models)
    ALL, ALL_ATTACKS, MODES, AuthorizationError, BusyError, CampaignResult, PlatformError, Run,
    ScanResult, TargetError, WifiPilotError, advisor_status, analyze, attack, authorize,
    config, configure, crack, current_run, demo, engine, export, is_running, loot,
    suggest_masks, strategies, targets, select, selected, note, notes, tag, history,
    vendor, identify, passwords, advice, benchmark, hash_stats, merge_hashes,
    rescue_capture, wordlist_stats, expand_wordlist, rules_info, loot_manifest,
    verify_loot, survey, probes, pins, reveal, eap, pmk_verify, pmk_convert, pmk_cache,
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
