"""``wifipilot`` command line interface.

    wifipilot scan                        # discover access points
    wifipilot attack --i-am-authorized    # AI-planned campaign (live)
    wifipilot demo                        # same pipeline, simulated radio
    wifipilot web --open                  # browser UI
    wifipilot crack loot/handshake-*.cap  # crack a capture or a .hc22000 hash file
    wifipilot analyze capture.pcapng      # what is actually inside that file
    wifipilot export capture.cap          # turn a capture into hashcat mode 22000
    wifipilot tools                       # dependency + capability report
    wifipilot ai status | models | pull | ask

The live dashboard is a rich table driven by the same event bus the web UI
uses, so the CLI and the browser always tell the same story.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import LEGAL_NOTICE, TOOL_NAME, __version__
from .config import Config, find_wordlists
from .deps import list_interfaces, registry
from .events import EK, Event, EventBus
from .llm import LLMError, provider_status
from .crack import STRATEGIES as _STRATEGIES, apply_strategy, strategy, strategy_names
from .models import ATTACK_NAMES, Capture, classify_target

STRATEGY_NAMES = tuple(_STRATEGIES)
from .util import (C, banner, human_bytes, human_duration, mac_norm, oui_vendor,
                   parse_duration, platform_info, read_json, require_linux, run)

# --------------------------------------------------------------------------- #
# rich helpers (the CLI still works without rich, just plainer)
# --------------------------------------------------------------------------- #

try:
    from rich import box as rich_box
    from rich.console import Console, Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress_bar import ProgressBar
    from rich.table import Table
    from rich.text import Text
    HAVE_RICH = True
except ImportError:  # pragma: no cover
    # rich is the *only* runtime dependency of the core CLI, and it is a nicety: the
    # panels, tables and colour are there to make a long run readable, not to make it
    # work.  A machine that has no rich — a minimal container, a locked-down consultant's
    # laptop, an air-gapped box — still has to be able to run an assessment, so the
    # names the rest of this module uses are defined here as plain stand-ins that render
    # to text.  Without them the first ``Panel(...)`` in a command raises NameError, and
    # "the optional dependency is missing" becomes a crash rather than a plainer run.
    HAVE_RICH = False

    class _PlainStyle:                                  # pragma: no cover
        """The ``rich.box`` names, so ``box=rich_box.MINIMAL`` still resolves."""

        def __getattr__(self, name: str) -> None:
            return None

    class Text:                                         # pragma: no cover
        """A string that accepts rich's ``append`` and renders to text."""

        def __init__(self, value: Any = "", style: str = "", **kwargs: Any) -> None:
            self.parts: List[str] = []
            if value:
                self.parts.append(str(value))

        def append(self, value: Any = "", style: str = "", **kwargs: Any) -> "Text":
            self.parts.append(str(value))
            return self

        def __str__(self) -> str:
            return C.strip_markup("".join(self.parts))

        def __bool__(self) -> bool:
            return bool("".join(self.parts))

    class Group:                                        # pragma: no cover
        """Several renderables, printed one after another."""

        def __init__(self, *items: Any) -> None:
            self.items = list(items)

        def __str__(self) -> str:
            return C.strip_markup("\n".join(str(item) for item in self.items))

    class Panel:                                        # pragma: no cover
        """A boxed renderable: without rich, a title and the text under it."""

        def __init__(self, renderable: Any = "", title: str = "", **kwargs: Any) -> None:
            self.renderable, self.title = renderable, title

        def __str__(self) -> str:
            body = C.strip_markup(str(self.renderable))
            if not self.title:
                return body
            rule = "-" * min(72, max(8, len(self.title) + 4))
            return f"{self.title}\n{rule}\n{body}"

    class Table:                                        # pragma: no cover
        """A table: the columns, then the rows as tab-separated lines."""

        def __init__(self, title: str = "", box: Any = None, **kwargs: Any) -> None:
            self.title = title
            self.columns: List[str] = []
            self.rows: List[List[str]] = []

        def add_column(self, name: str = "", **kwargs: Any) -> None:
            self.columns.append(str(name))

        def add_row(self, *values: Any, **kwargs: Any) -> None:
            self.rows.append([str(value) for value in values])

        def add_section(self, *args: Any, **kwargs: Any) -> None:
            self.rows.append([])

        def __str__(self) -> str:
            lines = ["\t".join(self.columns)] if self.columns else []
            lines.extend("\t".join(row) for row in self.rows)
            if self.title:
                lines.insert(0, self.title)
            return "\n".join(lines)

    class ProgressBar:                                  # pragma: no cover
        """A bar as a percentage, which is what the number was for."""

        def __init__(self, total: float = 100.0, completed: float = 0.0,
                     width: int = 40, **kwargs: Any) -> None:
            self.total, self.completed = float(total or 1.0), float(completed)

        def __str__(self) -> str:
            percent = 0.0 if not self.total else self.completed / self.total * 100.0
            return f"{percent:5.1f}%"

    class Console:                                      # pragma: no cover
        """A console that prints: markup is dropped by ``C.strip`` at the call sites."""

        def __init__(self, **kwargs: Any) -> None:
            pass

        def print(self, *items: Any, **kwargs: Any) -> None:
            for item in items:
                print(C.strip_markup(str(item)))

        def rule(self, title: str = "", **kwargs: Any) -> None:
            print(f"--- {title} ---" if title else "---")

    class Live:                                         # pragma: no cover
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def __enter__(self) -> "Live":
            return self

        def __exit__(self, *exc: Any) -> bool:
            return False

        def update(self, *args: Any, **kwargs: Any) -> None:
            pass

    rich_box = _PlainStyle()


# --------------------------------------------------------------------------- #
# argument parsing
# --------------------------------------------------------------------------- #


def _global_arguments(parser: argparse.ArgumentParser, suppress: bool = False) -> None:
    """Every option that is valid before *and* after the sub-command.

    ``suppress`` marks the defaults as "not given", which is what the copies
    attached to each subparser need: argparse applies a subparser's defaults
    after the top level has been parsed, so real defaults there would silently
    wipe out a flag the operator placed before the sub-command.
    """

    def add(container, *args, **kwargs):
        if suppress:
            if "default" in kwargs:
                kwargs["default"] = argparse.SUPPRESS
            elif kwargs.get("action") in ("store_true", "store_false", "append", "count"):
                kwargs["default"] = argparse.SUPPRESS
        return container.add_argument(*args, **kwargs)

    add(parser, "--version", action="version",
                        version=f"{TOOL_NAME} {__version__}")
    add(parser, "-c", "--config", default="", help="config file to load")
    add(parser, "-i", "--interface", default="", help="wireless interface to use")
    add(parser, "-m", "--monitor", default="", help="monitor interface to use")
    add(parser, "--demo", action="store_true",
                        help="simulation mode: no radio is touched")
    add(parser, "-y", "--i-am-authorized", dest="authorized", action="store_true",
                        help="confirm you have written permission to test the targets "
                             "(required before wifipilot transmits)")
    add(parser, "--stealth", action="store_true",
                        help="listen-only: never deauthenticate and no online PIN attacks")
    add(parser, "--attacks", default="",
                        help="comma separated attack list; `wifipilot attacks` prints the "
                             f"{len(ATTACK_NAMES)} names, `wifipilot attacks --domain it` "
                             "the IT ones")
    add(parser, "--edition", default="", choices=("", "wifi", "bluetooth", "it", "all"),
                        help="which edition to plan for: wifi, bluetooth, it or all "
                             "(the switches the planner, the catalogue and the web UI use)")
    add(parser, "--it-host", default="", metavar="IP",
                        help="the host the IT attacks talk to (default: the target, then "
                             "the gateway; the web UI's device list sets this for you)")
    add(parser, "--it-port", type=int, default=0, metavar="PORT",
                        help="the port an IT attack should use instead of its protocol's "
                             "own default")
    add(parser, "--wps-pin", action="store_true",
                        help="enable the online WPS PIN attack (slow, disruptive, off by default)")
    add(parser, "--reveal-with-probe", action="store_true",
                        help="let hidden-SSID discovery ask for the name with a directed "
                             "probe (the only part of it that transmits)")
    add(parser, "--broadcast-handshake", action="store_true",
                        help="let the planner use the broadcast variant of the handshake "
                             "capture (drops every client of the AP at once instead of one)")
    add(parser, "--no-pmk-cache", action="store_true",
                        help="do not reuse PMKs learned earlier for the same ESSID")
    add(parser, "-w", "--wordlist", action="append", default=[],
                        help="wordlist to crack with (repeatable)")
    add(parser, "-o", "--output", default="", help="loot directory (default: loot/)")
    add(parser, "--session-dir", default="", help="session directory (default: sessions/)")
    add(parser, "--timeout", default="", help="attack budget override, e.g. 5m")
    add(parser, "--log-level", default="", help="debug|info|warning|error")
    add(parser, "-v", "--verbose", action="store_true", help="verbose (tool chatter)")
    add(parser, "--no-color", action="store_true", help="disable ANSI colour")
    add(parser, "--json", action="store_true", help="machine readable output")

    # -- ai ----------------------------------------------------------------
    ai = parser.add_argument_group("advisor (optional — wifipilot needs no model)")
    add(ai, "--no-ai", "--disable-ai", dest="no_ai", action="store_true",
                    help="never call a model: deterministic planner only "
                         "(same as ai_provider=none or WIFIPILOT_NO_AI=1)")
    add(ai, "--offline", dest="no_ai", action="store_true",
                    help="alias for --no-ai: nothing leaves the machine but the radio")
    add(ai, "--provider", default="",
                    choices=["", "auto", "ollama", "cortex", "openrouter", "none"],
                    help="model provider: auto (prefer a local model), ollama, cortex "
                         "(Cortex LLMHoster), openrouter, none")
    add(ai, "--model", default="", help="model name for the active provider")
    add(ai, "--ollama-host", default="", help="Ollama base URL")
    add(ai, "--cortex-host", default="", metavar="URL",
                    help="Cortex LLMHoster base URL (default http://127.0.0.1:8624) — "
                         "a local, OpenAI-compatible model host")
    add(ai, "--cortex-model", default="", metavar="NAME",
                    help="model to ask on the Cortex LLMHoster (default: the hoster's)")
    add(ai, "--openrouter-key", default="",
                    help="OpenRouter API key (prefer the OPENROUTER_API_KEY environment "
                         "variable: a key on the command line lands in your shell history)")
    add(ai, "--openrouter-base-url", default="",
                    help="OpenRouter API base URL (default https://openrouter.ai/api/v1)")
    add(ai, "--ai-redact", dest="ai_redact", action="store_true", default=None,
                    help="pseudonymise SSIDs/BSSIDs/MACs/PSKs before sending them to a "
                         "cloud provider (default on for OpenRouter)")
    add(ai, "--no-ai-redact", dest="ai_redact", action="store_false",
                    help="send real identifiers to the cloud provider (not recommended)")
    add(ai, "--ai-budget", default="",
                    help="stop cloud planning after this much spend, e.g. 0.50 (USD)")
    add(ai, "--think-interval", default="", help="seconds between advisor re-plans")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="AI-piloted WiFi auditing for Linux — a wifite alternative with a "
                    "web UI and an optional local (Ollama) or cloud (OpenRouter) "
                    "advisor that can be switched off completely.",
        epilog=LEGAL_NOTICE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _global_arguments(parser)

    # the same options, without defaults, so they also work *after* the sub-command
    common = argparse.ArgumentParser(add_help=False, argument_default=argparse.SUPPRESS)
    _global_arguments(common, suppress=True)

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p_scan = sub.add_parser("scan", parents=[common], help="discover access points and clients")
    p_scan.add_argument("-t", "--time", default="30", help="scan duration (default 30s)")
    p_scan.add_argument("--band", default="", choices=["", "2.4GHz", "5GHz", "both"])
    p_scan.add_argument("--save", default="", help="write the discovered APs to a JSON file")

    p_attack = sub.add_parser("attack", parents=[common], help="run a full attack campaign")
    p_attack.add_argument("-b", "--bssid", action="append", default=[],
                          help="attack only this BSSID (repeatable)")
    p_attack.add_argument("-t", "--time", default="", help="discovery phase length (default 30s)")
    p_attack.add_argument("-d", "--duration", default="", help="total campaign budget, e.g. 45m")
    p_attack.add_argument("--no-scan", action="store_true", help="skip the discovery phase")
    p_attack.add_argument("--client", default="",
                          help="deauthenticate this station only (handshake attack)")
    p_attack.add_argument("--twin-interface", default="",
                          help="interface the evil twin serves on (default: the monitor "
                               "interface; a second radio keeps the capture running)")
    p_attack.add_argument("--skip-crack", action="store_true",
                          help="capture only, do not run the cracker")

    p_web = sub.add_parser("web", parents=[common], help="start the web UI")
    p_web.add_argument("--host", default="", help="bind address (default 0.0.0.0)")
    p_web.add_argument("--port", type=int, default=0, help="port (default 8787)")
    p_web.add_argument("--open", action="store_true", help="open a browser window")

    p_crack = sub.add_parser("crack", parents=[common], help="crack a capture you already have")
    p_crack.add_argument("capture", nargs="*", help=".cap / .pcap / .pcapng / .hc22000 file(s)")
    p_crack.add_argument("-b", "--bssid", default="", help="BSSID (optional, inferred from the file)")
    p_crack.add_argument("-e", "--essid", default="", help="SSID (needed for handshake MIC checks)")
    p_crack.add_argument("--engine", default="", choices=["", "auto", "aircrack", "hashcat"])
    p_crack.add_argument("--mask", action="append", nargs="?", const="auto",
                         default=None, metavar="PATTERN",
                         help="mask attack: try a hashcat-style pattern such as "
                              "'Telekom-?d?d?d?d' (repeatable). Bare --mask derives "
                              "patterns from the target's ESSID/vendor; patterns "
                              "too big for the built-in engine go to hashcat -a 3")
    p_crack.add_argument("--mask-candidates", type=int, default=None, metavar="N",
                         help="how many candidates the built-in engine may spend on "
                              "masks (default 20000; 0 disables masks)")
    p_crack.add_argument("--no-masks", action="store_true", help="skip the mask stage")

    p_crack.add_argument("--strategy", default="",
                         choices=["", *sorted(STRATEGY_NAMES)],
                         help="one preset instead of six flags: quick, thorough, "
                              "mask-only, wordlist-only, ...")
    p_crack.add_argument("--rule-file", default="",
                         help="hashcat .rule file (or best64/leet/...) the built-in "
                              "engine applies too")
    p_crack.add_argument("--list-strategies", action="store_true",
                         help="show the strategy presets and what each one does")
    p_crack.add_argument("--crack-order", default="",
                         help="stage order, e.g. targeted,masks,builtin "
                              "(default: targeted,masks,hashcat-masks,external,builtin)")

    p_targets = sub.add_parser("targets", parents=[common],
                               help="filter and select discovered access points")
    p_targets.add_argument("--kind", default="", help="home-router | guest | iot | open | ...")
    p_targets.add_argument("--tag", default="", help="only APs carrying this tag")
    p_targets.add_argument("--vendor", default="", help="vendor name or dossier key (AVM, TP-Link, ...)")
    p_targets.add_argument("--cracked", action="store_true", help="only cracked APs")
    p_targets.add_argument("--loot", action="store_true", help="only APs with a handshake/PMKID")
    p_targets.add_argument("--encryption", default="", help="substring match (WPA2, WPA3, OPEN)")
    p_targets.add_argument("--channel", type=int, default=0)
    p_targets.add_argument("--select", action="store_true",
                           help="remember the matches as the campaign scope")
    p_targets.add_argument("--report", default="", help="load a previous JSON export")
    p_targets.add_argument("--kinds", action="store_true", help="list the target kinds in use")

    p_note = sub.add_parser("note", parents=[common], help="annotate the engagement")
    p_note.add_argument("text", nargs="?", default="", help="the note")
    p_note.add_argument("--list", action="store_true", help="show the notes so far")
    p_note.add_argument("--bssid", default="", help="attach the note to one AP")
    p_note.add_argument("--state-dir", default="", help="session directory (with --list)")
    p_note.add_argument("--history", action="store_true",
                        help="show what happened (attempts, captures, notes)")

    p_tag = sub.add_parser("tag", parents=[common], help="tag access points for scoping")
    p_tag.add_argument("bssid", nargs="?", default="")
    p_tag.add_argument("tag", nargs="?", default="")
    p_tag.add_argument("--remove", action="store_true", help="remove instead of add")
    p_tag.add_argument("--list", action="store_true", help="show every tag in use")
    p_tag.add_argument("--state-dir", default="")

    p_vendor = sub.add_parser("vendor", parents=[common],
                              help="what wifipilot knows about a vendor (OUI + dossier)")
    p_vendor.add_argument("query", nargs="?", default="", help="a MAC, a vendor name, or an ESSID")
    p_vendor.add_argument("--bssid", default="", help="resolve a BSSID's vendor")
    p_vendor.add_argument("--oui-stats", action="store_true", help="show the OUI registry size")
    p_vendor.add_argument("--import-oui", default="", metavar="FILE",
                          help="merge an IEEE oui.txt into the registry")

    p_attacks = sub.add_parser("attacks", parents=[common],
                               help="the attack catalogue: what each one costs and shows")
    p_attacks.add_argument("--category", default="", metavar="NAME",
                           help="only this category (offline, survey, capture, wps, "
                                "wep, enterprise, rogue, dos)")
    # (a global --offline already exists and switches the advisor off, so this one
    #  is named for what it selects: attacks that need no radio at all)
    p_attacks.add_argument("--no-radio", dest="only_offline", action="store_true",
                           help="only the attacks that transmit nothing at all")
    p_attacks.add_argument("--noise", default="", metavar="LEVEL",
                           help="only attacks at this noise level (silent, quiet, "
                                "moderate, loud, extreme)")
    # (the global --edition already selects an edition for a run; this one narrows the
    #  listing, and both spellings work here because the fallback below reads either)
    p_attacks.add_argument("--domain", default="", metavar="EDITION",
                           help="only this edition (wifi, bluetooth, it, all)")
    p_attacks.add_argument("--device", default="", metavar="TYPE",
                           help="only the attacks that fit a device type from the shelf "
                                "(printer, ip_camera, smart_tv, ...; see `wifipilot devices`)")

    p_devices = sub.add_parser("devices", parents=[common],
                               help="the device shelf: what a device is, and how to test it")
    p_devices.add_argument("--domain", default="", metavar="EDITION",
                           help="only this edition's devices (wifi, bluetooth, it, all)")
    p_devices.add_argument("--group", default="", metavar="NAME",
                           help="only this shelf (network, server, iot, ot, voip, consumer, "
                                "mobile, bt, ...)")
    p_devices.add_argument("--type", default="", metavar="ID",
                           help="one device type: the ports and protocols that find it, and "
                                "the attacks that fit it")

    p_sim = sub.add_parser("sim", parents=[common],
                           help="the simulated environments a --demo run is made of")
    p_sim.add_argument("--domain", default="", metavar="EDITION",
                       help="bluetooth, it — or both (the default)")
    p_sim.add_argument("--list", dest="rows", action="store_true",
                       help="list every simulated device, not just the shape of the floor")
    p_sim.add_argument("--limit", type=int, default=60, metavar="N",
                       help="rows to list (default 60)")

    p_bench = sub.add_parser("benchmark", parents=[common],
                             help="measure this machine's candidate rate (no radio)")
    p_bench.add_argument("--seconds", type=float, default=5.0)

    p_advice = sub.add_parser("advice", parents=[common],
                              help="prioritised next steps, no LLM required")
    p_advice.add_argument("--report", default="", help="load a previous JSON export")
    p_advice.add_argument("--state-dir", default="")

    p_wl = sub.add_parser("wordlist", parents=[common], help="wordlist tooling")
    wl_sub = p_wl.add_subparsers(dest="wordlist_command", metavar="ACTION")
    p_wl_stats = wl_sub.add_parser("stats", parents=[common], help="shape of a wordlist")
    p_wl_stats.add_argument("files", nargs="+")
    p_wl_merge = wl_sub.add_parser("merge", parents=[common], help="merge/dedupe wordlists")
    p_wl_merge.add_argument("files", nargs="+")
    p_wl_merge.add_argument("--out", required=True)
    p_wl_merge.add_argument("--limit", type=int, default=0)
    p_wl_merge.add_argument("--keep-short", action="store_true",
                            help="keep words that cannot be WPA passphrases")
    p_wl_expand = wl_sub.add_parser("expand", parents=[common],
                                    help="apply rules to every word (hashcat .rule or preset)")
    p_wl_expand.add_argument("file")
    p_wl_expand.add_argument("--out", required=True)
    p_wl_expand.add_argument("-r", "--rule-file", default="best64")
    p_wl_expand.add_argument("--limit", type=int, default=0)
    p_wl_masks = wl_sub.add_parser("from-masks", parents=[common],
                                   help="write the candidates of masks to a wordlist")
    p_wl_masks.add_argument("masks", nargs="+")
    p_wl_masks.add_argument("--out", required=True)
    p_wl_masks.add_argument("--limit", type=int, default=0)
    p_wl_rules = wl_sub.add_parser("rules-info", parents=[common],
                                   help="explain a rule file (or a preset)")
    p_wl_rules.add_argument("spec", nargs="?", default="best64")

    p_hash = sub.add_parser("hash", parents=[common], help="hash-file tooling (mode 22000)")
    hash_sub = p_hash.add_subparsers(dest="hash_command", metavar="ACTION")
    p_hash_stats = hash_sub.add_parser("stats", parents=[common], help="what is in a hash file")
    p_hash_stats.add_argument("files", nargs="+")
    p_hash_merge = hash_sub.add_parser("merge", parents=[common], help="merge hash files")
    p_hash_merge.add_argument("files", nargs="+")
    p_hash_merge.add_argument("--out", default="")
    p_hash_merge.add_argument("--no-dedupe", action="store_true")
    p_hash_dedupe = hash_sub.add_parser("dedupe", parents=[common], help="drop duplicate lines")
    p_hash_dedupe.add_argument("file")
    p_hash_dedupe.add_argument("--out", default="")
    p_hash_filter = hash_sub.add_parser("filter", parents=[common], help="keep matching lines only")
    p_hash_filter.add_argument("file")
    p_hash_filter.add_argument("--out", default="")
    p_hash_filter.add_argument("--essid", default="")
    p_hash_filter.add_argument("--bssid", default="")
    p_hash_filter.add_argument("--kind", default="", choices=["", "pmkid", "eapol"])
    p_hash_filter.add_argument("--verifiable-only", action="store_true")
    p_hash_split = hash_sub.add_parser("split", parents=[common], help="split for a cracking farm")
    p_hash_split.add_argument("file")
    p_hash_split.add_argument("--out-dir", required=True)
    p_hash_split.add_argument("--per-file", type=int, default=1)
    p_hash_normalize = hash_sub.add_parser("normalize", parents=[common],
                                           help="rewrite canonically (sorted, lower-case)")
    p_hash_normalize.add_argument("file")
    p_hash_normalize.add_argument("--out", default="")
    p_hash_rescue = hash_sub.add_parser("rescue", parents=[common],
                                        help="recover hashes a normal converter skips")
    p_hash_rescue.add_argument("capture")
    p_hash_rescue.add_argument("--out", default="")

    p_pot = sub.add_parser("potfile", parents=[common], help="import/export hashcat potfiles")
    pot_sub = p_pot.add_subparsers(dest="potfile_command", metavar="ACTION")
    p_pot_show = pot_sub.add_parser("show", parents=[common], help="list potfile entries")
    p_pot_show.add_argument("file", nargs="?", default="")
    p_pot_show.add_argument("--limit", type=int, default=0)
    p_pot_export = pot_sub.add_parser("export", parents=[common], help="export to CSV/JSON")
    p_pot_export.add_argument("file")
    p_pot_export.add_argument("--out", default="")
    p_pot_export.add_argument("--format", default="csv", choices=["csv", "json"])
    p_pot_remove = pot_sub.add_parser("remove", parents=[common], help="delete matching entries")
    p_pot_remove.add_argument("file")
    p_pot_remove.add_argument("needle")

    p_loot = sub.add_parser("loot", parents=[common], help="the loot directory: list and verify")
    loot_sub = p_loot.add_subparsers(dest="loot_command", metavar="ACTION")
    p_loot_list = loot_sub.add_parser("list", parents=[common], help="list loot files")
    p_loot_list.add_argument("--dir", default="")
    p_loot_manifest = loot_sub.add_parser("manifest", parents=[common],
                                          help="write a sha256 manifest of the loot")
    p_loot_manifest.add_argument("--dir", default="")
    p_loot_verify = loot_sub.add_parser("verify", parents=[common],
                                        help="verify the loot against its manifest")
    p_loot_verify.add_argument("--dir", default="")


    p_survey = sub.add_parser("survey", parents=[common],
                              help="read-only intelligence: probe requests, deauths, twins")
    p_survey.add_argument("capture", nargs="?", default="",
                          help="capture to read (optional: the session's own captures are "
                               "used when omitted)")
    p_survey.add_argument("--limit", type=int, default=40,
                          help="how many probing clients to report (default 40)")

    p_eap = sub.add_parser("eap", parents=[common],
                           help="decode an 802.1X exchange: method, identity, certificate")
    p_eap.add_argument("capture", help="capture containing the EAP exchange")
    p_eap.add_argument("--limit", type=int, default=4,
                       help="how many certificates to decode (default 4)")

    p_decode = sub.add_parser("decode", parents=[common],
                              help="decode a capture's information elements (read-only)")
    p_decode.add_argument("capture", help="capture to read (pcap/pcapng)")
    p_decode.add_argument("--no-low", action="store_true",
                          help="hide the low-severity housekeeping findings")
    p_decode.add_argument("--limit", type=int, default=40,
                          help="how many networks to print (default 40)")

    p_reveal = sub.add_parser("reveal", parents=[common],
                              help="name the hidden networks in a capture (read-only)")
    p_reveal.add_argument("capture", nargs="?", default="",
                          help="capture to read (optional: the session's own captures are "
                               "used when omitted)")

    p_pins = sub.add_parser("pins", parents=[common],
                            help="WPS PIN candidates and an attempt plan (offline arithmetic)")
    p_pins.add_argument("bssid", nargs="?", default="", help="target BSSID (vendor pins)")
    p_pins.add_argument("-e", "--essid", default="", help="SSID (for the ESSID-derived pins)")
    p_pins.add_argument("--vendor", default="", help="vendor override when the OUI is unknown")
    p_pins.add_argument("--first-half", default="",
                        help="a known first half (4 digits) -> plan its 1,000 completions")
    p_pins.add_argument("--limit", type=int, default=24, help="how many candidates to show")

    p_pmk = sub.add_parser("pmk", parents=[common],
                           help="PMK tooling: verify a PSK, write mode 22001, browse the cache")
    pmk_sub = p_pmk.add_subparsers(dest="pmk_command", metavar="ACTION")
    p_pmk_verify = pmk_sub.add_parser("verify", parents=[common],
                                      help="check a PSK against a capture or hash file")
    p_pmk_verify.add_argument("capture", nargs="+")
    p_pmk_verify.add_argument("-p", "--psk", default="", help="the PSK to check")
    p_pmk_verify.add_argument("-e", "--essid", default="", help="ESSID (auto-detected)")
    p_pmk_convert = pmk_sub.add_parser("convert", parents=[common],
                                       help="write mode 22001 (raw-PMK candidates) for a "
                                            "capture whose PSK you know")
    p_pmk_convert.add_argument("capture", nargs="+")
    p_pmk_convert.add_argument("-p", "--psk", default="", help="the known PSK")
    p_pmk_convert.add_argument("-e", "--essid", default="")
    p_pmk_convert.add_argument("--out", default="")
    p_pmk_show = pmk_sub.add_parser("show", parents=[common],
                                    help="read a mode 22001 (or potfile-style) PMK file")
    p_pmk_show.add_argument("file")
    pmk_sub.add_parser("cache", parents=[common],
                       help="what this engagement has already learned")

    p_analyze = sub.add_parser("analyze", parents=[common],
                               help="inspect captures: handshakes, PMKIDs, EAPOL")
    p_analyze.add_argument("capture", nargs="+", help="capture or .hc22000 hash file(s)")
    p_analyze.add_argument("-b", "--bssid", default="", help="limit the mask report to one BSSID")
    p_analyze.add_argument("-e", "--essid", default="", help="SSID to derive mask patterns from")
    p_analyze.add_argument("--masks", action="store_true",
                           help="also show the mask patterns the cracker would try "
                                "(ESSID/vendor derived) and where they would run")

    p_export = sub.add_parser("export", parents=[common],
                              help="convert a capture to hashcat mode 22000 (or JSON/CSV)")
    p_export.add_argument("capture", nargs="+", help="capture file(s)")
    p_export.add_argument("--out", default="",
                          help="output file or directory (default: next to the capture; "
                               "'-' writes to stdout)")
    p_export.add_argument("--format", default="22000", choices=["22000", "json", "csv"],
                          help="output format (default: 22000, the hashcat format)")
    p_export.add_argument("--pmkid-only", action="store_true", help="only PMKID hashes")
    p_export.add_argument("--eapol-only", action="store_true", help="only EAPOL (handshake) hashes")
    p_export.add_argument("--hcxtools", action="store_true",
                          help="prefer hcxpcapngtool when it is installed")

    p_tools = sub.add_parser("tools", parents=[common], help="show tool availability and capabilities")
    p_tools.add_argument("--force", action="store_true", help="re-probe instead of using cache")

    p_ai = sub.add_parser("ai", parents=[common],
                          help="optional advisor: status, models, providers, off/on, "
                               "pull, use, ask (no model is required to run wifipilot)")
    ai_sub = p_ai.add_subparsers(dest="ai_command", metavar="ACTION")
    p_ai.add_argument("--report", default="",
                      help="load access points from a previous JSON export for context")
    ai_sub.add_parser("status", parents=[common], help="which provider/model is active, and is it reachable?")
    p_ai_models = ai_sub.add_parser("models", parents=[common], help="list models the active provider offers")
    p_ai_models.add_argument("--search", default="", help="filter by name")
    p_ai_models.add_argument("--free", action="store_true", help="only free models")
    p_ai_models.add_argument("--limit", type=int, default=0, help="show at most N models")
    p_ai_models.add_argument("--refresh", action="store_true", help="ignore the cache")
    p_ai_providers = ai_sub.add_parser("providers", parents=[common], help="show every provider and what it needs")
    p_ai_providers.add_argument("--probe", action="store_true",
                                help="test reachability (network/daemon calls)")
    p_pull = ai_sub.add_parser("pull", parents=[common], help="download a model through Ollama")
    p_pull.add_argument("model", help="model name, e.g. llama3.1:8b")
    p_use = ai_sub.add_parser("use", parents=[common], help="select the active provider and/or model")
    p_use.add_argument("model", nargs="?", default="", help="model name (e.g. openai/gpt-4o-mini)")
    p_use.add_argument("--save", action="store_true", help="persist the choice to wifipilot.json")
    p_ask = ai_sub.add_parser("ask", parents=[common], help="ask the advisor about an engagement")
    p_ask.add_argument("question", nargs="+", help="your question")
    p_ai_off = ai_sub.add_parser(
        "off", parents=[common],
        help="stop using a model entirely (the deterministic planner takes over)")
    p_ai_off.add_argument("--save", action="store_true",
                          help="persist ai_provider=none to wifipilot.json")
    p_ai_on = ai_sub.add_parser("on", parents=[common],
                                help="re-enable the advisor (auto, or NAME)")
    p_ai_on.add_argument("provider_name", nargs="?", default="",
                         choices=["", "auto", "ollama", "openrouter"],
                         help="which provider to use (default: auto)")
    p_ai_on.add_argument("--save", action="store_true", help="persist the choice")
    p_ai_toggle = ai_sub.add_parser("toggle", parents=[common],
                                    help="switch the advisor off, or back on as it was")
    p_ai_toggle.add_argument("--save", action="store_true", help="persist the choice")

    p_config = sub.add_parser("config", parents=[common], help="show or write the configuration")
    p_config.add_argument("--write", default="", help="write the effective config to this file")
    p_config.add_argument("--init", action="store_true", help="write ./wifipilot.json")

    sub.add_parser("demo", parents=[common], help="run the whole pipeline in simulation mode (no radio)")
    return parser


def apply_cli_config(args: argparse.Namespace) -> Config:
    config = Config.load(args.config or None)
    # only pass values the operator actually provided: empty strings would wipe
    # defaults coming from the config file
    overrides = {
        "interface": args.interface, "monitor_interface": args.monitor,
        "output_dir": args.output, "session_dir": args.session_dir,
        "log_level": args.log_level,
        "cracker": getattr(args, "engine", ""),
    }
    for key, value in overrides.items():
        if value:
            setattr(config, key, value)
    config.update(
        verbose_tools=args.verbose, stealth=args.stealth,
        demo=args.demo, authorized=args.authorized,
    )
    if args.wordlist:
        config.wordlists = [os.path.abspath(os.path.expanduser(w)) for w in args.wordlist]
    if getattr(args, "strategy", ""):
        try:
            preset = apply_strategy(config, args.strategy)
        except KeyError as error:
            raise SystemExit(str(error))
        if not getattr(args, "json", False):
            print(f"strategy {preset['label']}: {preset['note']}", file=sys.stderr)
    if getattr(args, "crack_order", ""):
        config.crack_order = args.crack_order
    if getattr(args, "rule_file", ""):
        config.rule_file = args.rule_file
    if getattr(args, "no_masks", False):
        config.use_masks = False
    if getattr(args, "mask_candidates", None) is not None:
        config.mask_candidates = max(0, int(args.mask_candidates))
    masks_given = getattr(args, "mask", None)
    if masks_given:
        config.use_masks = True
        config.mask_patterns = [m for m in masks_given if m and m != "auto"]
    if getattr(args, "engine", ""):
        # --engine used to be accepted and ignored; subcommands without it
        # (every command but `crack`) simply have no such attribute
        config.cracker = args.engine
    if args.timeout:
        budget = parse_duration(args.timeout, config.attack_timeout)
        config.attack_timeout = budget
        config.crack_timeout = budget
    edition = (getattr(args, "edition", "") or "").strip().lower()
    attacks = [a for a in (args.attacks or "").replace(" ", "").split(",") if a]
    if attacks:
        unknown = [a for a in attacks if a not in ATTACK_NAMES]
        if unknown:
            raise SystemExit(f"unknown attack type(s): {', '.join(unknown)} "
                             f"(valid: {', '.join(ATTACK_NAMES)})")
        config.attacks = attacks
    elif args.wps_pin:
        if "wps_pin" not in config.attacks:
            config.attacks = [*config.attacks, "wps_pin"]
    if edition:
        # the edition switch: naming an edition *is* the plan, so the attacks that
        # belong to it become the enabled list (an explicit --attacks still wins)
        config.edition = edition
        if not attacks:
            from .attacks import ATTACK_META
            config.attacks = [name for name in ATTACK_NAMES
                              if edition == "all"
                              or ATTACK_META.get(name, {}).get("domain", "wifi") == edition]
    if getattr(args, "it_host", ""):
        config.it_host = str(args.it_host).strip()
    if getattr(args, "it_port", 0):
        config.it_port = int(args.it_port)
    if getattr(args, "reveal_with_probe", False):
        config.reveal_with_probe = True
    if getattr(args, "broadcast_handshake", False):
        config.broadcast_handshake = True
    if getattr(args, "no_pmk_cache", False):
        config.pmk_cache = False
    if getattr(args, "client", ""):
        config.client_mac = mac_norm(args.client) or ""
    if getattr(args, "twin_interface", ""):
        config.twin_interface = args.twin_interface
    if config.attacks and "wps_pin" in config.attacks and not args.wps_pin:
        # only when the operator asked for it explicitly (or via the config file)
        pass
    # -- AI provider ------------------------------------------------------- #
    provider = (getattr(args, "provider", "") or "").strip().lower()
    if provider:
        config.ai_provider = provider
        if provider == "openrouter":
            # selecting it on the command line *is* the consent decision
            config.openrouter.enabled = True
        elif provider == "ollama":
            config.ollama.enabled = True
    if args.no_ai:
        config.ai_provider = "none"
        config.ollama.enabled = False
        config.cortex.enabled = False
        config.openrouter.enabled = False
    if getattr(args, "openrouter_key", ""):
        config.openrouter.api_key = args.openrouter_key
        config.openrouter.enabled = True
    if getattr(args, "openrouter_base_url", ""):
        config.openrouter.base_url = args.openrouter_base_url
    if getattr(args, "ai_redact", None) is not None:
        config.openrouter.redact_identifiers = bool(args.ai_redact)
    if getattr(args, "ai_budget", ""):
        try:
            config.openrouter.max_cost_usd = float(args.ai_budget)
        except ValueError:
            raise SystemExit(f"--ai-budget must be a number of USD, got {args.ai_budget!r}")
    if args.model:
        resolved = config.active_provider(probe=False)[0]
        if resolved == "openrouter":
            config.openrouter.model = args.model
        elif resolved == "cortex":
            config.cortex.model = args.model
        else:
            config.ollama.model = args.model
    if args.ollama_host:
        config.ollama.host = args.ollama_host
    if getattr(args, "cortex_host", ""):
        config.cortex.host = args.cortex_host
        config.cortex.enabled = True
    if getattr(args, "cortex_model", ""):
        config.cortex.model = args.cortex_model
        config.cortex.enabled = True
    if args.think_interval:
        interval = parse_duration(args.think_interval, 45.0)
        config.ollama.think_interval = interval
        config.openrouter.think_interval = interval
    return config


# --------------------------------------------------------------------------- #
# live dashboard
# --------------------------------------------------------------------------- #


class Dashboard:
    """rich-powered live view of the running campaign."""

    def __init__(self, engine, console: Optional["Console"] = None, max_logs: int = 7,
                 plain: bool = False):
        self.engine = engine
        self.bus = engine.bus
        self.console = console or Console()
        self.max_logs = max_logs
        self.plain = plain or not HAVE_RICH
        self.subscription = self.bus.subscribe(maxsize=6000)
        self.logs: List[str] = []
        self.live: Optional["Live"] = None
        self.started = time.time()
        self._last_render = 0.0

    # -- rendering ---------------------------------------------------------
    def build(self):
        session = self.engine.session
        status = self.engine.status
        advisor = self.engine.advisor
        stats = session.stats

        header = Text()
        mode = "SIMULATION" if session.demo else ("LIVE · authorised" if session.authorized else "LIVE · not authorised")
        header.append(f" {mode} ", style="bold black on yellow" if session.demo else "bold white on red")
        header.append("  phase: ", style="dim")
        header.append(status.phase or "idle", style="bold cyan")
        iface = session.interface_summary.get("monitor") or session.interface_summary.get("interface") or "—"
        header.append(f"  iface: {iface}", style="dim")
        header.append(f"  uptime: {human_duration(session.stats.uptime)}", style="dim")
        header.append(f"  loot: {session.stats.loot}", style="bold green")
        header.append(f"  PSKs: {session.stats.passwords}", style="bold magenta")
        cfg = self.engine.config
        header.append("  AI: ", style="dim")
        if cfg.ai_off():
            # the honest label: there is no model in the loop, by choice
            header.append("off", style="dim")
            header.append(" · deterministic", style="dim italic")
        elif advisor.available:
            header.append(f"{advisor.model or 'ready'}", style="bold magenta")
            if stats.llm_calls:
                header.append(f" ·{stats.llm_calls} calls", style="dim magenta")
        elif cfg.ollama.enabled or cfg.openrouter.enabled:
            header.append("offline → heuristics", style="yellow")
        else:
            header.append("off", style="dim")

        vitals = Text()

        def vital(label: str, value: Any, style: str = "white") -> None:
            vitals.append(f" {label} ", style="dim")
            vitals.append(str(value), style=f"bold {style}")

        clients = sum(len(ap.clients) for ap in session.aps.values())
        captures = len(session.all_captures()) if hasattr(session, "all_captures") else 0
        vital("APs", len(session.aps), "cyan")
        vital("clients", clients, "cyan")
        vital("attacks", f"{stats.attacks_run} run / {stats.attacks_failed} failed",
              "green" if not stats.attacks_failed else "yellow")
        vital("captures", captures, "bold green" if captures else "white")
        vital("handshakes", stats.handshakes, "green")
        vital("PMKIDs", stats.pmkids, "green")
        vital("keys", stats.passwords, "magenta")
        vital("audits", stats.ie_audits + stats.pnl_harvests, "white")
        if cfg.ai_off():
            vital("decisions", "deterministic", "dim")
        else:
            vital("decisions", "model + planner", "magenta")
            vital("model calls", f"{stats.llm_calls} · {stats.llm_tokens} tok", "magenta")

        table = Table(box=None, pad_edge=False, expand=True, show_edge=False)
        for column, justify in (("SSID", "left"), ("BSSID", "left"), ("CH", "right"),
                                ("SIG", "right"), ("SEC", "left"), ("WPS", "left"),
                                ("CLI", "right"), ("LOOT", "left"), ("BY", "left"),
                                ("NEXT", "left")):
            table.add_column(column, justify=justify, no_wrap=True, overflow="ellipsis")
        for ap in self.engine.session.sorted_aps()[:14]:
            loot = []
            if ap.has_handshake:
                loot.append("HS")
            if ap.has_pmkid:
                loot.append("PMKID")
            if ap.password:
                loot.append(f"PSK={ap.password}")
            signal_style = "green" if ap.signal >= -60 else ("yellow" if ap.signal >= -75 else "red")
            wps = "—"
            if ap.wps:
                wps = "lock" if ap.wps_locked == "locked" else (ap.wps_locked or "yes")
            next_attacks = "/".join(self.engine.attackable(ap)[:2]) or "—"
            table.add_row(
                Text(ap.display_name[:22], style="bold white" if not ap.hidden else "dim"),
                Text(ap.bssid, style="dim"),
                Text(str(ap.channel or "?"), style="cyan"),
                Text(f"{ap.signal}", style=signal_style),
                Text(ap.security, style="magenta" if ap.encryption not in ("OPEN",) else "dim"),
                Text(wps, style="yellow" if ap.wps else "dim"),
                Text(str(len(ap.clients))),
                Text(" ".join(loot) or "—", style="green" if loot else "dim"),
                Text(ap.picked_by or "—", style="magenta" if ap.picked_by == "llm" else "dim"),
                Text(next_attacks, style="cyan" if next_attacks != "—" else "dim"),
            )
        if not self.engine.session.aps:
            table.add_row("—", "waiting for beacons", "", "", "", "", "", "", "", "")

        progress = self.engine.session.progress
        bar = ProgressBar(total=100, completed=max(0.0, min(100.0, progress.percent)),
                          width=40) if HAVE_RICH else Text("")
        progress_line = Text()
        if progress.label:
            progress_line.append(f" {progress.label} ", style="bold cyan")
            progress_line.append(f"{progress.percent:4.0f}%  {progress.speed}  ", style="dim")
            progress_line.append(progress.detail or "", style="dim")

        logs = Text()
        for line in self.logs[-self.max_logs:]:
            logs.append_text(line)
            logs.append("\n")

        footer = Text()
        advisor_note = ""
        plan = advisor.last_plan
        if plan is not None:
            who = "AI" if plan.source == "llm" else ("planner" if cfg.ai_off() else "heuristic")
            advisor_note = f"{who} plan: {plan.summary()}"
        footer.append(" " + (advisor_note or status.detail or "")[:160], style="dim")
        block = rich_box.MINIMAL if HAVE_RICH else None
        return Group(Panel(header, box=block, padding=(0, 0)),
                     Panel(vitals, box=block, padding=(0, 0)), table,
                     Panel(Group(bar, progress_line), box=block, padding=(0, 0)) if HAVE_RICH else Text(""),
                     Panel(logs, title="[dim]events[/dim]", box=block, padding=(0, 0)),
                     footer)

    def log(self, event: Event) -> None:
        style = {
            EK.AP_NEW: "cyan", EK.ATTACK_START: "magenta", EK.ATTACK_END: "dim",
            EK.CAPTURE_NEW: "green", EK.CRACK_FOUND: "bold green", EK.WARNING: "yellow",
            EK.ERROR: "red", EK.ADVISOR_PLAN: "magenta", EK.ADVISOR_CHAT: "magenta",
            EK.DEJAUTH if hasattr(EK, "DEJAUTH") else "deauth": "yellow",
        }.get(event.kind, "white")
        data = event.data
        message = (data.get("message") or data.get("reasoning")
                   or f"{data.get('attack', '')} {data.get('essid') or data.get('bssid') or ''}"
                   or data.get("kind", event.kind))
        prefix = event.kind.split(".")[0]
        line = Text()
        line.append(f" {event.ts and time.strftime('%H:%M:%S', time.localtime(event.ts))} ", style="dim")
        line.append(f"{prefix:<8}", style=style)
        line.append(str(message)[:150], style="white" if style in ("white", "dim") else style)
        self.logs.append(line)
        del self.logs[:-400]

    def drain(self) -> None:
        for event in self.subscription.drain(400):
            self.log(event)
        if not self.plain:
            self.render()

    def render(self, force: bool = False) -> None:
        now = time.time()
        if not force and now - self._last_render < 0.25:
            return
        self._last_render = now
        if self.live is not None:
            self.live.update(self.build(), refresh=True)

    def __enter__(self):
        if self.plain:
            return self
        self.live = Live(self.build(), console=self.console, screen=False,
                         refresh_per_second=4, transient=False)
        self.live.__enter__()
        return self

    def __exit__(self, *exc):
        if self.live is not None:
            with contextlib.suppress(Exception):
                self.live.update(self.build(), refresh=True)
                self.live.__exit__(*exc)
        self.subscription.close()
        return False


class Spinner:
    """Plain-text progress for the non-rich fallback."""

    def __init__(self, engine, interval: float = 3.0):
        self.engine = engine
        self.interval = interval
        self.last = 0.0
        self.subscription = engine.bus.subscribe(maxsize=2000)

    def tick(self) -> None:
        for event in self.subscription.drain(200):
            data = event.data
            message = data.get("message") or data.get("reasoning") or data.get("title")
            if message:
                print(f"[{event.kind}] {message}", file=sys.stderr)
        now = time.time()
        if now - self.last < self.interval:
            return
        self.last = now
        session = self.engine.session
        progress = session.progress
        line = (f"... phase={self.engine.status.phase} aps={len(session.aps)} "
                f"clients={session.stats.clients_seen} loot={session.stats.loot} "
                f"psks={session.stats.passwords} uptime={human_duration(session.stats.uptime)}")
        if progress.label:
            line += f" | {progress.label} {progress.percent:.0f}%"
        print(line, flush=True, file=sys.stderr)

    def close(self) -> None:
        self.subscription.close()

    # a tiny common interface with Dashboard so callers can treat both alike
    def __enter__(self) -> "Spinner":
        return self

    def __exit__(self, *exc) -> bool:
        self.close()
        return False

    def drain(self) -> None:
        self.tick()

    def render(self, force: bool = False) -> None:      # noqa: ARG002 - interface parity
        self.tick()


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #


def command_scan(args, config: Config, console) -> int:
    from .engine import Engine
    if args.band:
        config.band = args.band
    if args.time:
        config.scan_time = parse_duration(args.time, 30)
    if not config.demo and not list_interfaces():
        console.print("[yellow]No wireless interface found — running in simulation mode. "
                      "Use --demo to make that explicit.[/yellow]")
        config.demo = True
    engine = Engine(config, demo=config.demo, authorized=config.authorized)
    try:
        engine.prepare()
        with (Spinner(engine) if args.json or not HAVE_RICH else Dashboard(engine, console)) as view:
            engine.start_scan()
            deadline = time.time() + config.scan_time
            while time.time() < deadline and not engine.stop_event.is_set():
                time.sleep(0.3)
                view.tick() if isinstance(view, Spinner) else view.drain()
    except KeyboardInterrupt:
        console.print("\n[dim]scan interrupted[/dim]")
    finally:
        engine.shutdown()
    aps = engine.session.sorted_aps()
    if args.json:
        print(json.dumps([ap.to_dict() for ap in aps], indent=2))
    else:
        if HAVE_RICH:
            table = Table(title=f"discovered {len(aps)} access points", box=None)
            for column in ("SSID", "BSSID", "CH", "SIG", "SEC", "WPS", "CLIENTS", "VENDOR", "ATTACKS"):
                table.add_column(column)
            for ap in aps:
                table.add_row(ap.display_name, ap.bssid, str(ap.channel), f"{ap.signal}",
                              ap.security, "yes" if ap.wps else "no", str(len(ap.clients)),
                              ap.vendor or "-", "/".join(engine.attackable(ap)) or "-")
            console.print(table)
        else:
            for ap in aps:
                print(f"{ap.bssid}  ch{ap.channel:<3} {ap.signal:>4}dBm  {ap.security:<10} "
                      f"{ap.display_name}  clients={len(ap.clients)} wps={ap.wps}")
    if args.save:
        Path(args.save).write_text(json.dumps([ap.to_dict(detail=True) for ap in aps], indent=2))
        console.print(f"[green]saved {len(aps)} APs to {args.save}[/green]")
    return 0


def command_attack(args, config: Config, console) -> int:
    from .engine import Engine
    if args.skip_crack:
        config.skip_crack = True
    if args.time:
        config.scan_time = parse_duration(args.time, 30)
    authorized = config.authorized or args.authorized or config.demo
    if not config.demo and not authorized:
        console.print("[red]Refusing to transmit without authorisation.[/red]\n"
                      "Re-run with [bold]--i-am-authorized[/bold] once you have written "
                      "permission for every target network, or use [bold]--demo[/bold] "
                      "to explore the tool safely.")
        return 2
    engine = Engine(config, demo=config.demo, authorized=authorized)
    dashboard = Spinner(engine) if (args.json or not HAVE_RICH) else Dashboard(engine, console)
    try:
        with dashboard as view:
            engine.prepare()
            dashboard_thread = None
            if isinstance(view, Dashboard):
                import threading
                def pump() -> None:
                    while not engine.stop_event.is_set():
                        view.drain()
                        time.sleep(0.25)
                dashboard_thread = threading.Thread(target=pump, daemon=True)
                dashboard_thread.start()
            engine.run_campaign(list(args.bssid), parse_duration(args.duration, 0), not args.no_scan)
    except KeyboardInterrupt:
        console.print("\n[yellow]interrupted — stopping attacks cleanly[/yellow]")
    finally:
        engine.shutdown()
    return report_summary(engine, console, args.json)


def report_summary(engine, console, as_json: bool = False) -> int:
    session = engine.session
    if as_json:
        print(json.dumps(session.export(), indent=2, default=str))
        return 0
    stats = session.stats
    console.print()
    console.print(Panel(
        "\n".join([
            f"[bold]{'Simulation' if session.demo else 'Engagement'} {session.id}[/bold]"
            f" finished after {human_duration(stats.uptime)}",
            f"discovery   · {stats.aps_seen} APs · {stats.clients_seen} clients",
            f"attacks     · {stats.attacks_run} run · {stats.attacks_failed} failed · "
            f"{stats.deauths} deauth frames",
            f"loot        · {stats.loot} items "
            f"(handshakes {stats.handshakes}, PMKIDs {stats.pmkids}, "
            f"WPS {stats.wps_cracks}, WEP {stats.wep_cracks})",
            f"AI          · {stats.llm_calls} model calls · {stats.llm_tokens} tokens · "
            f"{stats.llm_errors} errors",
            f"[bold magenta]passwords recovered: {stats.passwords}[/bold magenta]",
        ]),
        title="summary", border_style="cyan"))
    loot = session.loot()
    if loot:
        if HAVE_RICH:
            table = Table(box=None, title="loot")
            for column in ("KIND", "SSID", "BSSID", "PSK", "TOOL", "FILE"):
                table.add_column(column)
            for cap in loot:
                table.add_row(cap.kind, cap.essid or "<hidden>", cap.bssid,
                              cap.password or "-", cap.tool or "-",
                              Path(cap.path).name if cap.path else "-")
            console.print(table)
        else:
            for cap in loot:
                print(f"{cap.kind}\t{cap.essid}\t{cap.bssid}\t{cap.password}\t{cap.path}")
    cracked = [ap for ap in session.aps.values() if ap.cracked]
    if cracked:
        console.print("\n[bold green]recovered credentials[/bold green]")
        for ap in cracked:
            console.print(f"  [green]{ap.display_name}[/green] ({ap.bssid}) → "
                          f"[bold magenta]{ap.password}[/bold magenta]")
    console.print(f"\n[dim]session data: {session.state_dir}\nloot: {session.output_dir}[/dim]")
    return 0


def command_web(args, config: Config, console) -> int:
    from .web.app import run_server
    demo = config.demo
    if not demo and not config.authorized:
        console.print("[yellow]Live mode without authorisation: the UI will refuse to run "
                      "attacks until you tick the authorisation box.[/yellow]")
    host = args.host or config.web_host or "0.0.0.0"
    port = args.port or config.web_port
    provider, _ = config.active_provider(probe=False)
    if config.ai_off():
        ai_line = "advisor: off · deterministic planner (no model, nothing leaves the box)"
    else:
        ai_line = f"advisor: {provider} (optional)"
    if provider == "openrouter" and not config.ai_off():
        ai_line += (f" · model {config.openrouter.model}"
                    + (" · identifiers pseudonymised"
                       if config.openrouter.redact_identifiers else
                       " · [red]identifier redaction OFF[/red]"))
    elif provider == "ollama":
        ai_line += f" · model {config.ollama.model} · local ({config.ollama.host})"
    console.print(Panel(
        f"[bold]wifipilot web UI[/bold]\n"
        f"http://127.0.0.1:{port}/  (bound to {host})\n"
        f"platform: Linux ({platform_info()['distro']})\n"
        f"mode: {'simulation' if demo else 'live'}\n"
        f"{ai_line}",
        border_style="cyan"))
    if provider == "openrouter" and not config.ai_off():
        console.print("[yellow]Cloud provider: SSIDs, BSSIDs, MACs and recovered PSKs of this "
                      "engagement are sent to openrouter.ai"
                      + (" (pseudonymised)" if config.openrouter.redact_identifiers else "")
                      + ". Keep it local with --provider ollama.[/yellow]")
    with contextlib.suppress(KeyboardInterrupt):
        run_server(config, host=host, port=port, demo=demo, authorized=config.authorized,
                   open_browser=args.open)
    return 0


def _print_strategies(console, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps([strategy(name) for name in strategy_names()], indent=2))
        return
    table = Table(title="crack strategies", box=None)
    for column in ("name", "targeted", "masks", "wordlists", "order", "what it does"):
        table.add_column(column, overflow="fold")
    for name in strategy_names():
        preset = strategy(name)
        table.add_row(name, f"{preset['targeted_candidates']:,}",
                      f"{preset['mask_candidates']:,}", str(preset["wordlists"]),
                      str(preset["order"]), str(preset["note"]))
    console.print(table)
    console.print("[dim]use one with --strategy NAME (individual flags still win)[/dim]")


def command_crack(args, config: Config, console) -> int:
    if getattr(args, "list_strategies", False):
        _print_strategies(console, as_json=getattr(args, "json", False))
        return 0
    if not args.capture:
        console.print("[yellow]give at least one capture, or --list-strategies[/yellow]")
        return 2
    from . import hash22000
    from .crack import Cracker
    from .pcap import analyze_file
    from .session import Session

    bus = EventBus()
    session = Session(config, bus, demo=False)
    cracker = Cracker(session, config, bus)
    exit_code = 1
    for item in args.capture:
        path = os.path.abspath(os.path.expanduser(item))
        if not os.path.exists(path):
            console.print(f"[red]no such file: {path}[/red]")
            continue
        if hash22000.is_hash_file(path):
            exit_code = min(exit_code, _crack_hash_file(path, cracker, session, config,
                                                        console))
            continue
        analysis = analyze_file(path)
        console.print(Panel(
            f"[bold]{Path(path).name}[/bold] · {analysis.format or 'unknown'} · "
            f"{analysis.packets} packets · EAPOL {analysis.eapol_messages}\n"
            f"handshakes: {len(analysis.handshakes)} "
            f"({'crackable' if analysis.has_handshake else 'none'}) · "
            f"PMKIDs: {len(analysis.pmkids)} · WEP data frames: {analysis.wep_data}",
            title="capture", border_style="cyan"))
        if analysis.error:
            console.print(f"[red]{analysis.error}[/red]")
            continue
        bssid = mac_norm(args.bssid)
        if not bssid:
            if analysis.handshakes:
                bssid = analysis.handshakes[0].bssid
            elif analysis.pmkids:
                bssid = analysis.pmkids[0].bssid
            elif analysis.bssids:
                bssid = analysis.bssids[0]
        if not bssid:
            console.print("[red]could not determine the BSSID; pass -b[/red]")
            continue
        essid = args.essid or analysis.essids.get(bssid, "")
        ap = session.aps.get(bssid)
        if ap is None:
            ap, _ = session.upsert_ap(bssid, essid, publish=False)
        capture = Capture(kind="pmkid" if analysis.has_pmkid else ("wep_ivs" if analysis.wep_data else "handshake"),
                          bssid=bssid, essid=essid, path=path, valid=True,
                          hash_path=path, extra={"pmkid": analysis.pmkids[0].pmkid if analysis.pmkids else ""})
        if not essid and analysis.has_handshake:
            console.print("[yellow]no SSID known: handshake MIC checks need the ESSID, "
                          "pass -e to enable the built-in verifier[/yellow]")
        progress_sub = bus.subscribe([EK.CRACK_PROGRESS])
        last_print = [0.0]

        def drain_progress() -> None:
            for event in progress_sub.drain(50):
                now = time.time()
                if now - last_print[0] < 1.5:
                    continue
                last_print[0] = now
                data = event.data
                console.print(f"[dim]  {data.get('percent', 0):5.1f}%  "
                              f"{data.get('done', 0):,}/{data.get('total', 0):,}  "
                              f"{data.get('speed', '')}  {str(data.get('detail', ''))[:70]}[/dim]")

        import threading as _threading
        stop_pump = _threading.Event()

        def pump() -> None:
            while not stop_pump.is_set():
                drain_progress()
                time.sleep(0.4)

        pump_thread = _threading.Thread(target=pump, daemon=True)
        pump_thread.start()
        try:
            result = cracker.crack_capture(ap, capture, wordlists=config.wordlists or None)
        finally:
            stop_pump.set()
            progress_sub.close()
        if result.cracked:
            console.print(f"[bold green]PSK found: {result.password}[/bold green] "
                          f"(tool: {result.tool}, {result.attempts:,} candidates, "
                          f"{human_duration(result.seconds)}, "
                          f"{'verified' if result.verified else 'unverified'})")
            exit_code = 0
        else:
            console.print(f"[yellow]not cracked[/yellow]: {result.reason} "
                          f"({result.attempts:,} candidates, {human_duration(result.seconds)})")
            if result.log:
                console.print(f"[dim]{result.log[-600:]}[/dim]")
    session.close()
    return exit_code


def _crack_hash_file(path: str, cracker, session, config: Config, console) -> int:
    """Crack a mode-22000 file: one line, one capture — no pcap required."""
    from . import hash22000

    lines, problems = hash22000.parse_text(Path(path).read_text(encoding="utf-8",
                                                                errors="replace"))
    console.print(Panel(f"[bold]{Path(path).name}[/bold] · hashcat mode 22000 · "
                        f"{len(lines)} line(s)",
                        title="hash file", border_style="cyan"))
    for problem in problems:
        console.print(f"  [yellow]{problem}[/yellow]")
    if not lines:
        console.print("[red]no usable hash lines[/red]")
        return 1
    found_any = 0
    for line in lines:
        essid = line.essid
        ap = session.aps.get(line.bssid)
        if ap is None:
            ap, _ = session.upsert_ap(line.bssid, essid, publish=False)
        extra = {"pmkid": line.pmkid} if line.kind == "pmkid" else {}
        capture = Capture(kind=line.kind, bssid=line.bssid, essid=essid or line.essid,
                          path=path, hash_path=path, valid=line.verifiable,
                          extra=extra)
        if not line.verifiable:
            console.print(f"  [yellow]{line.label}: not verifiable, skipping[/yellow]")
            continue
        result = cracker.crack_capture(ap, capture, wordlists=config.wordlists or None)
        label = essid or line.bssid
        if result.cracked:
            found_any += 1
            console.print(f"[bold green]PSK found for {label}: {result.password}[/bold green] "
                          f"(tool: {result.tool}, {result.attempts:,} candidates, "
                          f"{human_duration(result.seconds)}, "
                          f"{'verified' if result.verified else 'unverified'})")
        else:
            console.print(f"[yellow]not cracked[/yellow] {label}: {result.reason} "
                          f"({result.attempts:,} candidates, {human_duration(result.seconds)})")
    return 0 if found_any else 1


def command_survey(args, config: Config, console) -> int:
    """Read-only intelligence from a capture and/or the session: probes, deauths, twins."""
    from .session import Session
    from .sniff import passive_report

    path = _expand(args.capture) if args.capture else ""
    if path and not os.path.exists(path):
        console.print(f"[red]no such file: {path}[/red]")
        return 1
    session = _load_session_for(args, config, console) or Session(config, EventBus(),
                                                                 demo=True)
    if not path:
        # no capture given: use the newest capture the session already has
        captures = [capture for capture in session.all_captures()
                    if capture.path and os.path.exists(capture.path)]
        if captures:
            path = captures[-1].path
    aps = [ap.to_dict() for ap in session.aps.values()]
    report = passive_report(path, aps, limit=max(1, int(args.limit)))
    if args.json:
        print(json.dumps(report, indent=2))
        return 0
    console.print(f"[bold]passive survey[/bold] "
                  f"[dim]({Path(path).name if path else 'no capture'}, "
                  f"{len(aps)} AP(s) known)[/dim]")
    attacks = report.get("attacks") or {}
    console.print(f"  deauth/disassoc frames: [yellow]{attacks.get('total', 0)}[/yellow] "
                  f"({attacks.get('deauth', 0)} deauth, {attacks.get('disassoc', 0)} "
                  f"disassoc, {attacks.get('broadcast', 0)} broadcast)"
                  + ("  [red]flood[/red]" if attacks.get("flood") else ""))
    probes = report.get("probes") or []
    if probes:
        table = Table(title=f"probing clients ({len(probes)})", box=None)
        for column in ("client", "vendor", "probes", "networks it asked for"):
            table.add_column(column, overflow="fold")
        for entry in probes:
            table.add_row(entry["mac"], entry.get("vendor") or "-",
                          f"{entry['directed']}+{entry['broadcast']}",
                          ", ".join(entry["ssids"][:6]) or "(wildcard only)")
        console.print(table)
    wanted = report.get("wanted_networks") or []
    if wanted:
        console.print("  networks clients want but that are not on air: "
                      + ", ".join(item["essid"] for item in wanted[:10]))
    rogue = report.get("rogue") or []
    for twin in rogue:
        console.print(f"  [red]twin pattern[/red] {twin['essid']!r}: "
                      f"{len(twin['bssids'])} BSSIDs, vendors "
                      f"{', '.join(twin['vendors']) or 'unknown'}, "
                      f"{twin['signal_spread_db']} dB spread [dim]({twin['confidence']})[/dim]")
    if not probes and not rogue and not attacks.get("total"):
        console.print("[dim]nothing to report: no probes, no deauths, no twins[/dim]")
    console.print("[dim]read-only: nothing was transmitted[/dim]")
    return 0


def command_eap(args, config: Config, console) -> int:
    """Decode an 802.1X exchange offline: EAP methods, identities, certificates."""
    from .sniff import eap_exchange

    path = _expand(args.capture)
    if not path or not os.path.exists(path):
        console.print(f"[red]no such file: {args.capture}[/red]")
        return 1
    report = eap_exchange(path, limit_certs=max(1, int(args.limit)))
    if args.json:
        print(json.dumps(report, indent=2))
        return 0 if report["eapol"] else 1
    console.print(f"[bold]802.1X[/bold] [dim]({Path(path).name}, "
                  f"{report['eapol']} EAPOL frame(s))[/dim]")
    if not report["eapol"]:
        console.print("[yellow]no EAPOL frames in this capture: not an 802.1X network, "
                      "or the exchange was not captured[/yellow]")
        return 1
    console.print(f"  EAP method(s): {', '.join(report['methods']) or 'unknown'}")
    for identity in report["identities"]:
        leak = "" if identity.lower().startswith("anonymous") else \
            "  [yellow](outer identity leaks the realm)[/yellow]"
        console.print(f"  identity: {identity}{leak}")
    for facts in report["certificates"]:
        line = f"  certificate: {facts['subject'] or 'undecodable'}"
        if facts["self_signed"]:
            line += "  [red](self-signed: impersonable)[/red]"
        console.print(line + (f"  [dim]serial {facts['serial']}[/dim]"
                              if facts.get("serial") else ""))
        if facts.get("issuer") and facts["issuer"] != facts["subject"]:
            console.print(f"    issued by: {facts['issuer']}")
    console.print("[dim]decoded offline: the EAP method, the outer identity and the "
                  "server certificate are all in the clear on air[/dim]")
    return 0


def command_reveal(args, config: Config, console) -> int:
    """Name hidden networks from a capture — the offline half of hidden_ssid."""
    from .pcap import analyze_file
    from .session import Session

    path = _expand(args.capture) if args.capture else ""
    if path and not os.path.exists(path):
        console.print(f"[red]no such file: {path}[/red]")
        return 1
    session = _load_session_for(args, config, console) or Session(config, EventBus(),
                                                                 demo=True)
    if not path:
        captures = [capture for capture in session.all_captures()
                    if capture.path and os.path.exists(capture.path)]
        if captures:
            path = captures[-1].path
    if not path or not os.path.exists(path):
        console.print("[yellow]no capture to read: pass one, or run a campaign "
                      "first[/yellow]")
        return 1
    analysis = analyze_file(path)
    rows = []
    for bssid, essid in sorted(analysis.essids.items()):
        if not essid:
            continue
        mac = mac_norm(bssid)
        ap = session.ap(mac)
        revealed = bool(ap is not None and (ap.hidden or not ap.essid))
        if revealed:
            ap.essid = essid
            ap.hidden = False
            ap.remember("revealed", f"SSID {essid!r} learned from {Path(path).name}")
            session.stats.hidden_revealed += 1
        rows.append({"bssid": mac, "essid": essid, "known_target": ap is not None,
                     "revealed": revealed})
    if args.json:
        print(json.dumps({"capture": path, "named": rows,
                          "revealed": sum(1 for row in rows if row["revealed"])},
                         indent=2))
        return 0
    revealed = [row for row in rows if row["revealed"]]
    console.print(f"[bold]hidden networks[/bold] [dim]({Path(path).name})[/dim]")
    if not rows:
        console.print("[dim]this capture names no network: beacons without an SSID are "
                      "only revealed by probe responses, associations or the handshake"
                      "[/dim]")
        return 1
    table = Table(box=None)
    for column in ("BSSID", "SSID", "was", "now"):
        table.add_column(column)
    for row in rows:
        table.add_row(row["bssid"], row["essid"],
                      "hidden" if row["revealed"] else
                      ("known target" if row["known_target"] else "unknown"),
                      "named" if row["revealed"] else "-")
    console.print(table)
    console.print(f"  {len(revealed)} name(s) recovered, {len(rows)} BSSID(s) with a name "
                  f"[dim](read-only: nothing was transmitted)[/dim]")
    return 0


def command_decode(args, config: Config, console) -> int:
    """Decode the information elements of a capture — the offline half of ie_audit.

    Nothing is transmitted and nothing is required but the file: the same decoder the
    ``ie_audit`` attack runs over a live capture, pointed at a pcap an operator already
    has.  Findings are printed worst first, because that is the order they matter in.
    """
    from .ies import capture_beacons, ie_findings, vendor_breakdown

    path = _expand(args.capture)
    if not os.path.exists(path):
        console.print(f"[red]no such file: {path}[/red]")
        return 1
    result = capture_beacons(path)
    networks = list(result.get("networks") or [])[:max(1, int(args.limit))]
    findings = ie_findings(networks, include_low=not args.no_low)
    vendors = vendor_breakdown(networks)
    if args.json:
        print(json.dumps({"capture": path, "frames": result.get("frames", 0),
                          "networks": networks, "findings": findings,
                          "vendors": vendors}, indent=2))
        return 0 if networks else 1
    if not networks:
        console.print("[yellow]no beacon-like frames in that capture: nothing an AP said "
                      "about itself was recorded[/yellow]")
        return 1
    console.print(f"[bold]information elements[/bold] [dim]({Path(path).name}, "
                  f"{result.get('frames', 0)} frame(s))[/dim]")
    # the table is a nicety: without rich the same rows are printed plainly rather
    # than raising NameError, because "the optional dependency is missing" is not a
    # reason for a read-only command to fail
    table = Table(box=None) if HAVE_RICH else None
    if table is not None:
        for column in ("BSSID", "SSID", "CH", "PMF", "WPS", "elements"):
            table.add_column(column)
    for entry in networks:
        facts = entry.get("facts") or {}
        wps = facts.get("wps") or {}
        wps_state = "locked" if wps.get("locked") else ("open" if wps.get("present")
                                                       else "-")
        pmf = ("required" if facts.get("pmf_required") else
               "capable" if facts.get("pmf_capable") else "none")
        highlights = [name.upper() for name in ("vht", "he", "eht") if facts.get(name)]
        elements = ", ".join(["/".join((facts.get("rsn") or {}).get("akm") or [])] +
                             highlights + ([facts["country"]] if facts.get("country")
                                           else []))
        row = (entry.get("bssid", ""), entry.get("essid", ""),
               str(facts.get("channel", 0) or ""), pmf, wps_state, elements or "-")
        if table is not None:
            table.add_row(*row)
        else:
            console.print("  " + "  ".join(str(cell) for cell in row))
    if table is not None:
        console.print(table)
    for finding in findings:
        colour = {"high": "red", "medium": "yellow", "low": "dim"}.get(
            finding["severity"], "dim")
        console.print(f"  [{colour}]{finding['severity']}[/{colour}] "
                      f"{finding['kind']} — {finding['title']}")
    console.print(f"  {len(networks)} network(s), {len(findings)} finding(s)"
                  + (f", vendor elements: {', '.join(row['vendor'] for row in vendors[:4])}"
                     if vendors else "")
                  + " [dim](read-only: nothing was transmitted)[/dim]")
    return 0


def command_pins(args, config: Config, console) -> int:
    """WPS PIN candidates and the attempt plan — arithmetic, no radio."""
    from . import wps

    bssid = mac_norm(args.bssid)
    if args.bssid and not bssid:
        console.print(f"[red]not a MAC address: {args.bssid}[/red]")
        return 2
    vendor = args.vendor or oui_vendor(bssid) if bssid else args.vendor
    candidates = wps.candidate_pins(bssid=bssid, essid=args.essid, vendor=vendor)
    order = list(wps.pin_attempt_order([pin.pin for pin in candidates if pin.pin],
                                       first_half=args.first_half))
    shown = order[:max(1, int(args.limit))]
    plan = wps.attempt_plan(bssid=bssid, essid=args.essid, vendor=vendor)
    if args.json:
        print(json.dumps({"bssid": bssid, "essid": args.essid, "vendor": vendor,
                          "candidates": [pin.to_dict() for pin in candidates],
                          "order": shown, "plan": plan}, indent=2))
        return 0
    console.print(f"[bold]WPS[/bold] {bssid or '(no BSSID)'} "
                  f"{args.essid or ''} [dim]{vendor or 'unknown vendor'}[/dim]")
    table = Table(title="candidate PINs (best first)", box=None)
    for column in ("PIN", "source", "confidence", "why"):
        table.add_column(column, overflow="fold")
    for pin in candidates[:max(1, int(args.limit))]:
        table.add_row(pin.pin, pin.source, pin.confidence, pin.note or "-")
    console.print(table)
    console.print(f"  attempt order starts: {', '.join(shown[:8])}"
                  + (" …" if len(order) > 8 else ""))
    spaces = plan["spaces"]
    console.print(f"  every 8-digit value: {spaces['every 8-digit value']:,}  ·  "
                  f"checksum-valid: {spaces['checksum-valid PINs']:,}  ·  "
                  f"two-half sweep: {spaces['two-half sweep (the documented attack)']:,}"
                  f"  ·  candidates above: {spaces['candidates above']}")
    for key, seconds in plan["seconds"].items():
        console.print(f"  [dim]{key}: {human_duration(float(seconds))} at "
                      f"{plan['seconds_per_attempt']}s/attempt[/dim]")
    console.print(f"  [dim]{plan['note']}[/dim]")
    console.print("[dim]information only: nothing was transmitted. The online PIN attack "
                  "(--wps-pin) is what talks to the AP.[/dim]")
    return 0


def command_pmk(args, config: Config, console) -> int:
    """PMK tooling: verify a PSK, write mode 22001, read a PMK file, browse the cache."""
    from . import pmk

    action = getattr(args, "pmk_command", "") or ""
    if action == "cache":
        directory = _expand(args.session_dir) if args.session_dir else ""
        cache = pmk.PMKCache(directory=directory).load() if directory else \
            _pmk_cache_for(config)
        entries = cache.entries() if cache else []
        if args.json:
            print(json.dumps([entry.to_dict() for entry in entries], indent=2))
            return 0
        if not entries:
            console.print("[dim]the PMK cache is empty (nothing cracked yet)[/dim]")
            return 0
        table = Table(title=f"PMK cache: {cache.path}", box=None)
        for column in ("ESSID", "PSK", "learned from", "age"):
            table.add_column(column, overflow="fold")
        for entry in entries:
            table.add_row(entry.essid, entry.psk, entry.source or "-",
                          human_duration(max(0.0, time.time() - entry.created)))
        console.print(table)
        console.print("[dim]ESSID-keyed: a second capture of the same network is verified "
                      "against the cache, never cracked twice[/dim]")
        return 0

    if action == "show":
        path = _expand(args.file)
        if not os.path.exists(path):
            console.print(f"[red]no such file: {path}[/red]")
            return 1
        rows = pmk.read_pmk_file(path)
        if args.json:
            print(json.dumps(rows, indent=2))
            return 0
        if not rows:
            console.print("[yellow]no readable PMK entries[/yellow] "
                          "[dim](mode 22001 lines, or 'PMK<TAB>ESSID' pairs)[/dim]")
            return 0
        table = Table(title=f"{Path(path).name}: {len(rows)} entry(ies)", box=None)
        for column in ("ESSID", "BSSID", "kind", "PMK"):
            table.add_column(column, overflow="fold")
        for row in rows:
            table.add_row(row.get("essid", ""), row.get("bssid", ""), row.get("kind", ""),
                          (row.get("pmk", "")[:24] + "…") if row.get("pmk") else "")
        console.print(table)
        return 0

    if not getattr(args, "psk", ""):
        console.print("[red]--psk is required for verify/convert[/red]")
        return 2
    exit_code = 0
    for item in args.capture:
        path = _expand(item)
        if not os.path.exists(path):
            console.print(f"[red]no such file: {path}[/red]")
            exit_code = 1
            continue
        if action == "verify":
            result = pmk.verify_psk_against(args.psk, path, args.essid)
            mark = "[green]verified[/green]" if result["ok"] else "[red]not this PSK[/red]"
            if args.json:
                print(json.dumps({"path": path, **result}, indent=2))
            else:
                console.print(f"{Path(path).name}: {mark} "
                              f"[dim]({result['lines']} line(s) for "
                              f"{', '.join(result['essids']) or 'unknown ESSID'})[/dim]")
            if not result["ok"]:
                exit_code = 1
            continue
        out = _expand(args.out) if args.out else ""
        written = pmk.convert_to_22001(path, out=out, psk=args.psk, essid=args.essid)
        if args.json:
            print(json.dumps(written, indent=2))
            continue
        if not written.get("lines"):
            console.print(f"[yellow]{Path(path).name}: nothing verifiable "
                          f"({written.get('note', 'no usable handshake')})[/yellow]")
            exit_code = 1
            continue
        console.print(f"[green]{Path(path).name}[/green] -> "
                      f"[green]{written['path']}[/green] "
                      f"({written['lines']} PMK line(s), mode 22001)")
    return exit_code


def _pmk_cache_for(config: Config):
    """The engagement's PMK cache (or ``None`` when the cache is switched off)."""
    from . import pmk
    if not config.pmk_cache:
        return None
    path = config.pmk_cache_path or os.path.join(config.session_dir, pmk.PMK_CACHE_NAME)
    return pmk.PMKCache(path=path).load()


def command_analyze(args, config: Config, console) -> int:
    from . import hash22000
    from .pcap import analyze_file
    payload = []
    for item in args.capture:
        path = os.path.abspath(os.path.expanduser(item))
        if hash22000.is_hash_file(path):
            payload.append(_analyze_hash_file(path, args, config, console))
            continue
        analysis = analyze_file(path)
        data = analysis.to_dict()
        if getattr(args, "masks", False):
            bssid = args.bssid or next(iter(analysis.essids), "")
            vendor = oui_vendor(bssid)
            data["masks"] = _mask_report(config, args.essid or analysis.essids.get(bssid, ""),
                                         vendor)
        payload.append(data)
        if args.json:
            continue
        console.print(Panel(
            f"[bold]{Path(path).name}[/bold]  format={analysis.format or '?'}  "
            f"packets={analysis.packets}  beacons={analysis.beacons}  data={analysis.data_packets}\n"
            f"EAPOL messages: {analysis.eapol_messages} · "
            f"retransmits ignored: {analysis.retransmits}\n"
            f"handshakes: {len(analysis.crackable_handshakes())} crackable / "
            f"{len(analysis.handshakes)} seen · "
            f"PMKIDs: {len(analysis.pmkids)} · WEP IV frames: {analysis.wep_data}",
            title="analysis", border_style="cyan"))
        for handshake in analysis.crackable_handshakes():
            pair = ("M1+M2 challenge" if handshake.challenge
                    else "M2+M3 authorized" if handshake.authorized else "partial")
            console.print(f"  [green]crackable[/green] {handshake.bssid} ↔ {handshake.station} "
                          f"messages={sorted(handshake.messages)} ({pair}) "
                          f"pmkid={'yes' if handshake.pmkid else 'no'} score={handshake.score}")
        for handshake in analysis.handshakes:
            if handshake.can_verify_mic:
                continue
            console.print(f"  [yellow]incomplete[/yellow] {handshake.bssid} ↔ {handshake.station} "
                          f"messages={sorted(handshake.messages)} "
                          f"(no usable MIC: needs M1+M2 or M2+M3 plus both nonces)")
        for pmkid in analysis.pmkids:
            console.print(f"  [green]PMKID[/green] {pmkid.bssid} → {pmkid.pmkid}")
        if analysis.essids:
            console.print(f"  [dim]SSIDs: {', '.join(f'{k}={v}' for k, v in analysis.essids.items())}[/dim]")
        if getattr(args, "masks", False):
            _print_masks(console, data.get("masks", []))
        if analysis.error:
            console.print(f"  [red]{analysis.error}[/red]")
    if args.json:
        print(json.dumps(payload, indent=2))
    return 0


def _mask_report(config: Config, essid: str, vendor: str = "") -> List[Dict[str, Any]]:
    """The masks the cracker would try, and which engine would run each one."""
    from . import masks as masks_module
    chosen = []
    for mask in masks_module.suggest_masks(essid, vendor):
        chosen.append(mask.to_dict())
    budget = max(0, int(getattr(config, "mask_candidates", 0)))
    runnable, skipped = masks_module.select_masks(
        [masks_module.Mask(item["mask"], "") for item in chosen], budget)
    running = {mask.pattern for mask in runnable}
    for item in chosen:
        item["engine"] = ("built-in (fits the budget)" if item["mask"] in running
                          else "hashcat -a 3")
    if not getattr(config, "use_masks", True):
        for item in chosen:
            item["engine"] = "disabled (--no-masks)"
    return chosen


def _print_masks(console, report: List[Dict[str, Any]]) -> None:
    if not report:
        console.print("  [dim]no mask patterns to suggest for this target[/dim]")
        return
    console.print("  [dim]mask attacks the cracker would try:[/dim]")
    for item in report:
        console.print(f"    [cyan]{item['mask']}[/cyan]  "
                      f"{item['space']:>15,} candidates  [dim]{item['engine']} · "
                      f"{item['note']}[/dim]")


def _analyze_hash_file(path: str, args, config: Config, console) -> Dict[str, Any]:
    """Report a mode 22000 hash file: what is in it, and what can be tested."""
    from . import hash22000
    lines, problems = hash22000.parse_text(
        Path(path).read_text(encoding="utf-8", errors="replace"))
    data = hash22000.summary(lines, problems)
    data["path"] = path
    data["format"] = "hc22000"
    data["detail"] = [line.to_dict() for line in lines]
    if getattr(args, "masks", False):
        first = lines[0] if lines else None
        data["masks"] = _mask_report(config, first.essid if first else "",
                                     oui_vendor(first.bssid) if first else "")
    if not args.json:
        console.print(Panel(
            f"[bold]{Path(path).name}[/bold]  hashcat mode 22000\n"
            f"{data['lines']} hash line(s): {data['pmkid']} PMKID, {data['eapol']} EAPOL"
            f" \u00b7 {data['verifiable']} verifiable\n"
            f"SSIDs: {', '.join(data['essids']) or '-'}\n"
            f"APs: {', '.join(data['bssids']) or '-'}",
            title="hash file", border_style="cyan"))
        for line in lines:
            mark = "[green]verifiable[/green]" if line.verifiable else "[yellow]no usable nonce[/yellow]"
            console.print(f"  {mark} {line.label} \u00b7 {line.bssid} \u2194 {line.station} "
                          f"\u00b7 MIC {line.mic_algorithm} ({line.mic.hex()[:16]}\u2026)")
        for problem in data["problems"]:
            console.print(f"  [yellow]{problem}[/yellow]")
        if getattr(args, "masks", False):
            _print_masks(console, data.get("masks", []))
    return data


def _load_session_for(args, config: Config, console) -> Optional[Any]:
    """Load a previous engagement (JSON export) or the live session, if any."""
    from .session import Session
    report = getattr(args, "report", "")
    if report:
        path = os.path.abspath(os.path.expanduser(report))
        data = read_json(path, None)
        if not isinstance(data, dict) or "access_points" not in data:
            console.print(f"[red]{path} is not a wifipilot JSON export[/red]")
            return None
        session = Session(config, EventBus(), demo=True)
        for item in data.get("access_points") or []:
            ap, _ = session.upsert_ap(item.get("bssid", ""), item.get("essid", ""),
                                      publish=False)
            for key in ("channel", "signal", "encryption", "cipher", "auth", "vendor",
                        "target_kind", "wps", "notes", "password", "status", "score"):
                if item.get(key) not in (None, ""):
                    setattr(ap, key, item[key])
            ap.tags = list(item.get("tags") or [])
        session.notes = list(data.get("notes") or [])
        return session
    return None


def _session_from_last_run(config: Config, console):
    """The newest saved session of this config, if there is one."""
    from .session import Session, load_notes

    root = Path(config.session_dir)
    if not root.is_dir():
        return None
    reports = sorted(root.glob("*/reports/report.json"),
                     key=lambda item: item.stat().st_mtime, reverse=True)
    if not reports:
        return None
    data = read_json(reports[0], None)
    if not isinstance(data, dict):
        return None
    session = Session(config, EventBus(), demo=True, session_id=reports[0].parent.parent.name)
    for item in data.get("access_points") or []:
        ap, _ = session.upsert_ap(item.get("bssid", ""), item.get("essid", ""), publish=False)
        for key in ("channel", "signal", "encryption", "cipher", "auth", "vendor",
                    "target_kind", "wps", "notes", "password", "status"):
            if item.get(key) not in (None, ""):
                setattr(ap, key, item[key])
        ap.tags = list(item.get("tags") or [])
    session.notes = list(data.get("notes") or []) or load_notes(config)
    console.print(f"[dim]using the saved session {session.id} "
                  f"({len(session.aps)} access points)[/dim]")
    return session


def command_targets(args, config: Config, console) -> int:
    """Filter the discovered APs and optionally make them the campaign scope."""
    from .session import Session
    from .api import scan as api_scan

    session = _load_session_for(args, config, console)
    if session is None:
        session = _session_from_last_run(config, console)
    if session is None:
        # scan briefly, so the command is useful on its own
        console.print("[dim]scanning briefly to build the target list…[/dim]")
        try:
            payload = api_scan(duration=config.scan_time)
        except Exception as error:                     # no radio, no root, no scan
            console.print(f"[red]cannot scan ({error})[/red]")
            console.print("[dim]pass --report export.json (or run a session first) to "
                          "filter a saved engagement instead[/dim]")
            return 2
        session = Session(config, EventBus(), demo=getattr(args, "demo", False))
        for ap in getattr(payload, "aps", []) or []:
            row, _ = session.upsert_ap(ap.bssid, ap.essid, publish=False)
            row.enrich()
    if getattr(args, "kinds", False):
        kinds: Dict[str, int] = {}
        for ap in session.aps.values():
            kind = ap.target_kind or classify_target(ap)
            kinds[kind] = kinds.get(kind, 0) + 1
        if args.json:
            print(json.dumps(kinds, indent=2))
            return 0
        table = Table(title="target kinds", box=None)
        table.add_column("kind"); table.add_column("APs", justify="right")
        for kind, count in sorted(kinds.items(), key=lambda item: -item[1]):
            table.add_row(kind, str(count))
        console.print(table)
        return 0
    matched = session.filter_aps(kind=args.kind, tag=args.tag, vendor=args.vendor,
                                cracked=True if args.cracked else None,
                                loot=True if args.loot else None,
                                encryption=args.encryption, channel=args.channel)
    table = Table(title=f"targets ({len(matched)} of {len(session.aps)})", box=None)
    for column in ("BSSID", "SSID", "kind", "vendor", "ch", "sig", "tags", "loot"):
        table.add_column(column, overflow="fold")
    for ap in matched:
        loot = "PSK" if ap.password else ("pmkid" if ap.has_pmkid else
                                          "handshake" if ap.has_handshake else "-")
        table.add_row(ap.bssid, ap.essid or "(hidden)", ap.target_kind or "-",
                      ap.vendor or "-", str(ap.channel), str(ap.signal),
                      ",".join(ap.tags) or "-", loot)
    if matched:
        console.print(table)
    else:
        console.print("[yellow]no access points match those filters[/yellow]")
    if getattr(args, "select", False):
        session.selected_bssids = [ap.bssid for ap in matched]
        if getattr(args, "json", False):
            print(json.dumps({"selected": session.selected_bssids,
                              "count": len(matched)}, indent=2))
        else:
            console.print(f"[green]{len(matched)} target(s) selected for the campaign[/green]")
    elif getattr(args, "json", False):
        print(json.dumps([ap.to_dict() for ap in matched], indent=2))
    return 0


def command_note(args, config: Config, console) -> int:
    """Add/list operator notes and show the engagement history."""
    from .session import Session

    state_dir = _expand(getattr(args, "state_dir", ""))
    if args.history:
        session = _load_session_for(args, config, console) or Session(config, EventBus(),
                                                                     demo=True)
        history = session.history(limit=40)
        if args.json:
            print(json.dumps(history, indent=2))
            return 0
        if not history:
            console.print("[dim]nothing recorded yet[/dim]")
            return 0
        table = Table(title="history (newest first)", box=None)
        for column in ("when", "what", "detail", "bssid"):
            table.add_column(column, overflow="fold")
        for entry in history:
            table.add_row(human_duration(max(0.0, time.time() - (entry.get("ts") or 0)))
                          + " ago", str(entry.get("kind", "")), str(entry.get("detail", "")),
                          str(entry.get("bssid", "")))
        console.print(table)
        return 0
    if args.list or not args.text:
        from .session import load_notes
        notes = load_notes(config, state_dir)
        if args.json:
            print(json.dumps(notes, indent=2))
            return 0
        if not notes:
            console.print("[dim]no notes yet — `wifipilot note \"text\"` writes one[/dim]")
            return 0
        for entry in notes:
            stamp = entry.get("ts", "")
            where = f" [{entry['bssid']}]" if entry.get("bssid") else ""
            console.print(f"[dim]{stamp}[/dim]{where} {entry.get('text', '')}")
        return 0
    session = Session(config, EventBus(), demo=True)
    if state_dir:
        session.state_dir = _expand(state_dir)
        Path(session.state_dir).mkdir(parents=True, exist_ok=True)
    entry = session.add_note(args.text, bssid=args.bssid)
    if args.json:
        print(json.dumps(entry, indent=2))
    else:
        console.print(f"[green]note saved[/green] to {session.state_dir}")
    return 0


def command_tag(args, config: Config, console) -> int:
    """Tag (or untag) an access point, or list the tags in use."""
    session = _load_session_for(args, config, console)
    if args.list or not (args.bssid and args.tag):
        tags = (session.tags() if session else {})
        if args.json:
            print(json.dumps(tags, indent=2))
            return 0
        if not tags:
            console.print("[dim]no tags in use[/dim]")
            return 0
        for tag, bssids in sorted(tags.items()):
            console.print(f"[cyan]{tag}[/cyan] — {len(bssids)}: {', '.join(bssids)}")
        return 0
    tags = session.tag_ap(args.bssid, args.tag, add=not args.remove)
    if args.json:
        print(json.dumps({"bssid": args.bssid, "tags": tags}, indent=2))
    else:
        console.print(f"{args.bssid}: {', '.join(tags) or '(no tags)'}")
    return 0


def command_vendor(args, config: Config, console) -> int:
    """Vendor lookup: OUI registry, dossier, and what it implies."""
    from . import vendors
    from .analytics import identify

    if args.oui_stats:
        stats = vendors.oui_stats()
        if args.json:
            print(json.dumps(stats, indent=2))
        else:
            console.print(f"OUI registry: [cyan]{stats['exact']}[/cyan] exact prefixes, "
                          f"[cyan]{stats['prefix']}[/cyan] 28-bit blocks ({stats['file']})")
        return 0
    if args.import_oui:
        path = os.path.abspath(os.path.expanduser(args.import_oui))
        if not os.path.exists(path):
            console.print(f"[red]no such file: {path}[/red]")
            return 1
        result = vendors.import_oui_file(path)
        console.print(f"[green]merged[/green] {result['vendors']:,} vendor prefixes "
                      f"from {Path(path).name} into {result['path']}")
        return 0
    query = args.bssid or args.query
    if not query:
        console.print("[yellow]give a MAC, a vendor name, an ESSID, or --oui-stats[/yellow]")
        return 2
    mac = mac_norm(query)
    if mac:
        vendor, match = vendors.oui_lookup(mac)
        dossier = vendors.vendor_dossier(vendor or mac)
        info = identify("", vendor)
        if args.json:
            print(json.dumps({"mac": mac, "vendor": vendor, "match": match,
                              "dossier": dossier, "identification": info}, indent=2))
            return 0
        console.print(Panel(f"[bold]{vendor or 'unknown vendor'}[/bold] "
                            f"({match or 'not in the registry'}) · {mac}",
                            title="oui", border_style="cyan"))
        if dossier.get("matched"):
            console.print(f"  WPS: {dossier.get('wps')}\n"
                          f"  bands: {dossier.get('bands')}\n"
                          f"  default key: {dossier.get('default_key')}\n"
                          f"  notes: {dossier.get('notes')}")
            console.print(f"  [dim]{dossier.get('disclaimer')}[/dim]")
        return 0
    dossier = vendors.vendor_dossier(query)
    info = identify(query)
    if args.json:
        print(json.dumps({"query": query, "dossier": dossier, "identification": info},
                         indent=2))
        return 0
    if dossier.get("matched"):
        console.print(Panel(f"[bold]{dossier.get('label')}[/bold] — {query}",
                            title="vendor dossier", border_style="cyan"))
        for key in ("wps", "bands", "default_key", "notes"):
            console.print(f"  [cyan]{key}[/cyan]: {dossier.get(key)}")
        console.print(f"  [dim]{dossier.get('disclaimer')}[/dim]")
    else:
        console.print(f"[yellow]no dossier for {query!r}[/yellow] — "
                      f"treat it like any other AP")
    if info.get("masks"):
        console.print("  mask candidates:")
        for item in info["masks"][:6]:
            console.print(f"    [cyan]{item['mask']}[/cyan] "
                          f"{item['space']:>15,} candidates · {item['note']}")
    return 0


def command_benchmark(args, config: Config, console) -> int:
    """Measure this machine's candidate rate (no radio, no target)."""
    from .engine import Engine
    from .session import Session

    session = Session(config, EventBus(), demo=True)
    engine = Engine(config, session.bus, session=session, demo=True)
    result = engine.benchmark(seconds=args.seconds)
    if args.json:
        print(json.dumps(result, indent=2))
        return 0
    console.print(Panel(f"[bold]{result['rate']:,.0f}[/bold] candidates/s "
                        f"({result['ms_per_candidate']:.2f} ms each)\n"
                        f"{result['candidates']:,} candidates in {result['seconds']}s",
                        title="benchmark", border_style="cyan"))
    table = Table(box=None)
    table.add_column("candidate space"); table.add_column("seconds", justify="right")
    for name, estimate in result["estimates"].items():
        table.add_row(name, estimate["human"])
    console.print(table)
    console.print(f"[dim]{result['note']}[/dim]")
    return 0


def command_advice(args, config: Config, console) -> int:
    """Prioritised next steps from the heuristics (no LLM round trip)."""
    from .engine import Engine
    from .session import Session

    session = _load_session_for(args, config, console) or Session(config, EventBus(),
                                                                 demo=True)
    engine = Engine(config, session.bus, session=session, demo=True)
    items = engine.advice()
    if args.json:
        print(json.dumps(items, indent=2))
        return 0
    if not items:
        console.print("[dim]nothing to advise: no access points discovered[/dim]")
        return 0
    table = Table(title="next steps", box=None)
    for column in ("#", "action", "target", "why", "confidence"):
        table.add_column(column, overflow="fold")
    for item in items:
        target = item.get("essid") or item.get("bssid") or "engagement"
        table.add_row(str(item["priority"]), item["action"], target,
                      item["why"], item["confidence"])
    console.print(table)
    return 0


def command_wordlist(args, config: Config, console) -> int:
    """Wordlist tooling: stats, merge, rule expansion, masks -> list."""
    from . import toolbox
    action = getattr(args, "wordlist_command", "") or "stats"
    if action == "stats":
        result = [toolbox.wordlist_stats(_expand(item)) for item in args.files]
        if args.json:
            print(json.dumps(result, indent=2))
            return 0
        table = Table(title="wordlists", box=None)
        for column in ("file", "lines", "unique", "8-63 chars", "min", "max", "avg"):
            table.add_column(column, overflow="fold")
        for item in result:
            table.add_row(Path(item["path"]).name, f"{item['lines']:,}",
                          f"{item['unique']:,}" if item["unique_exact"] else f"~{item['unique']:,}",
                          f"{item['wpa_compatible']:,}", str(item["min_length"]),
                          str(item["max_length"]), str(item["average_length"]))
        console.print(table)
        for item in result:
            classes = ", ".join(f"{k}={v}" for k, v in item["classes"].items() if v)
            console.print(f"  [dim]{Path(item['path']).name}: {classes}[/dim]")
            console.print(f"  [dim]built-in engine needs ~"
                          f"{human_duration(item['estimated_seconds_builtin'])} for the "
                          f"WPA-shaped words; a CPU hashcat ~"
                          f"{human_duration(item['estimated_seconds_hashcat_cpu'])}[/dim]")
        return 0
    if action == "merge":
        result = toolbox.merge_wordlists([_expand(i) for i in args.files],
                                         _expand(args.out),
                                         min_length=1 if args.keep_short else 8,
                                         limit=args.limit)
        console.print(f"[green]{result['written']:,}[/green] words -> {result['path']} "
                      f"({result['duplicates']:,} duplicates, "
                      f"{result['rejected']:,} rejected)")
        if args.json:
            print(json.dumps(result, indent=2))
        return 0
    if action == "expand":
        result = toolbox.expand_wordlist(_expand(args.file), _expand(args.out),
                                         args.rule_file, limit=args.limit)
        console.print(f"[green]{result['written']:,}[/green] candidates from "
                      f"{result['base_words']:,} words × {result['rules']} rules -> "
                      f"{result['path']}")
        if args.json:
            print(json.dumps(result, indent=2))
        return 0
    if action == "from-masks":
        result = toolbox.wordlist_from_masks(args.masks, _expand(args.out),
                                             limit=args.limit)
        console.print(f"[green]{result['written']:,}[/green] of {result['space']:,} "
                      f"candidates -> {result['path']}")
        if args.json:
            print(json.dumps(result, indent=2))
        return 0
    if action == "rules-info":
        from . import rules as rules_module
        spec = args.spec
        if os.path.exists(spec):
            rules = rules_module.parse_file(spec)
            label = Path(spec).name
        else:
            rules = rules_module.preset(spec)
            label = f"preset {spec}"
        info = rules_module.describe(rules)
        if args.json:
            print(json.dumps(info, indent=2))
            return 0
        console.print(Panel(f"[bold]{label}[/bold]\n"
                            f"{info['rules']} rules · {info['usable']} usable · "
                            f"{info['skipped']} skipped",
                            title="rule file", border_style="cyan"))
        if info["commands"]:
            console.print("  commands: " + ", ".join(
                f"{name}×{count}" for name, count in info["commands"].items()))
        if info["unsupported"]:
            console.print("  [yellow]unsupported: "
                          + ", ".join(f"{k!r}×{v}" for k, v in info["unsupported"].items())
                          + "[/yellow]")
        for example in info["examples"]:
            console.print(f"  [dim]{example['rule']!r} → {example['password']!r}[/dim]")
        return 0
    console.print(f"[red]unknown wordlist action: {action}[/red]")
    return 2


def command_hash(args, config: Config, console) -> int:
    """Hash-file tooling: stats, merge, dedupe, filter, split, normalize, rescue."""
    from . import toolbox
    action = getattr(args, "hash_command", "") or "stats"
    if action == "stats":
        result = [toolbox.hash_stats(_expand(item)) for item in args.files]
        if args.json:
            print(json.dumps(result, indent=2))
            return 0
        table = Table(title="hash files", box=None)
        for column in ("file", "lines", "PMKID", "EAPOL", "verifiable", "SSIDs"):
            table.add_column(column, overflow="fold")
        for item in result:
            table.add_row(Path(item["path"]).name, str(item["lines"]), str(item["pmkid"]),
                          str(item["eapol"]), str(item["verifiable"]),
                          ", ".join(item["essids"])[:40] or "-")
        console.print(table)
        for item in result:
            for label in item["unverifiable"]:
                console.print(f"  [yellow]unverifiable[/yellow] {label}")
        return 0
    if action == "merge":
        result = toolbox.merge_hash_files([_expand(i) for i in args.files],
                                          _expand(args.out) if args.out else "",
                                          dedupe=not args.no_dedupe)
        console.print(f"[green]{result['written']}[/green] line(s) -> {result['path']} "
                      f"({result['duplicates']} duplicate(s) dropped)")
        if args.json:
            print(json.dumps(result, indent=2))
        return 0
    if action == "dedupe":
        result = toolbox.dedupe_hash_file(_expand(args.file),
                                          _expand(args.out) if args.out else "")
        console.print(f"[green]{result['written']}[/green] unique line(s), "
                      f"{result['duplicates']} dropped")
        if args.json:
            print(json.dumps(result, indent=2))
        return 0
    if action == "filter":
        result = toolbox.filter_hash_file(_expand(args.file),
                                          _expand(args.out) if args.out else "",
                                          essid=args.essid, bssid=args.bssid,
                                          kind=args.kind,
                                          verifiable_only=args.verifiable_only)
        console.print(f"[green]{result['written']}[/green] kept, "
                      f"{result['dropped']} dropped -> {result['path']}")
        if args.json:
            print(json.dumps(result, indent=2))
        return 0
    if action == "split":
        result = toolbox.split_hash_file(_expand(args.file), _expand(args.out_dir),
                                         per_file=args.per_file)
        console.print(f"[green]{result['files']}[/green] file(s) in {result['path']} "
                      f"({result['written']} line(s) total)")
        if args.json:
            print(json.dumps(result, indent=2))
        return 0
    if action == "normalize":
        result = toolbox.normalize_hash_file(_expand(args.file),
                                             _expand(args.out) if args.out else "")
        console.print(f"[green]{result['written']}[/green] line(s) canonicalised "
                      f"({result['changed']} changed) -> {result['path']}")
        if args.json:
            print(json.dumps(result, indent=2))
        return 0
    if action == "rescue":
        result = toolbox.rescue_partial_capture(_expand(args.capture),
                                                _expand(args.out) if args.out else "")
        console.print(f"[green]{result['written']}[/green] line(s) -> {result['path']} "
                      f"({result['note']})")
        if args.json:
            print(json.dumps(result, indent=2))
        return 0
    console.print(f"[red]unknown hash action: {action}[/red]")
    return 2


def command_potfile(args, config: Config, console) -> int:
    """Potfile: show, export, remove — so hashcat's loot joins the report."""
    from . import toolbox
    action = getattr(args, "potfile_command", "") or "show"
    path = _expand(args.file) if getattr(args, "file", "") else _default_potfile(config)
    if action == "show":
        entries = toolbox.potfile_entries(path, limit=args.limit)
        if args.json:
            print(json.dumps(entries, indent=2))
            return 0
        if not entries:
            console.print(f"[dim]no entries in {path}[/dim]")
            return 0
        table = Table(title=f"potfile ({len(entries)} entries)", box=None)
        for column in ("ESSID", "BSSID", "kind", "password"):
            table.add_column(column, overflow="fold")
        for entry in entries:
            table.add_row(entry["essid"] or "-", entry["bssid"] or "-",
                          entry["kind"] or "-", entry["password"])
        console.print(table)
        return 0
    if action == "export":
        result = toolbox.potfile_export(path, _expand(args.out) if args.out else "",
                                        fmt=args.format)
        if args.out:
            console.print(f"[green]{result['count']}[/green] entrie(s) -> {result['path']}")
        if args.json:
            print(json.dumps({"count": result["count"], "text": result["text"]}, indent=2))
        elif not args.out:
            print(result["text"])
        return 0
    if action == "remove":
        result = toolbox.potfile_remove(path, args.needle)
        console.print(f"[green]{result['removed']}[/green] removed, "
                      f"{result['kept']} kept in {result['path']}")
        if args.json:
            print(json.dumps(result, indent=2))
        return 0
    console.print(f"[red]unknown potfile action: {action}[/red]")
    return 2


def command_loot(args, config: Config, console) -> int:
    """The loot directory: list it, or prove it has not changed."""
    from . import toolbox
    action = getattr(args, "loot_command", "") or "list"
    directory = _expand(args.dir) if getattr(args, "dir", "") else config.output_dir
    if action == "manifest":
        result = toolbox.write_manifest(directory)
        console.print(f"[green]manifest written[/green] for {result['files']} file(s) "
                      f"({human_bytes(result['bytes'])}) -> {result['path']}")
        if args.json:
            print(json.dumps(result, indent=2))
        return 0
    if action == "verify":
        result = toolbox.verify_manifest(directory)
        if args.json:
            print(json.dumps(result, indent=2))
            return 0 if result["ok"] else 1
        if result["ok"]:
            console.print(f"[green]loot verified[/green]: {result['checked']} file(s) "
                          f"unchanged")
        else:
            console.print(f"[red]loot changed[/red]: {len(result['missing'])} missing, "
                          f"{len(result['changed'])} modified, "
                          f"{len(result['extra'])} extra")
            for name in result["missing"]:
                console.print(f"  [red]missing[/red] {name}")
            for name in result["changed"]:
                console.print(f"  [red]modified[/red] {name}")
        return 0
    files = sorted(Path(directory).rglob("*")) if os.path.isdir(directory) else []
    entries = [item for item in files if item.is_file() and item.name != toolbox.MANIFEST_NAME]
    if args.json:
        print(json.dumps([{"path": str(item), "bytes": item.stat().st_size}
                          for item in entries], indent=2))
        return 0
    if not entries:
        console.print(f"[dim]nothing in {directory} yet[/dim]")
        return 0
    table = Table(title=f"loot: {directory}", box=None)
    for column in ("file", "size", "age"):
        table.add_column(column, overflow="fold")
    for item in entries:
        table.add_row(str(item.relative_to(directory)), human_bytes(item.stat().st_size),
                      human_duration(max(0.0, time.time() - item.stat().st_mtime)))
    console.print(table)
    return 0


def _expand(path: str) -> str:
    """``~``/relative path -> absolute, expanded (what every file argument wants)."""
    return os.path.abspath(os.path.expanduser(str(path or "")))


def _default_potfile(config: Config) -> str:
    """Where hashcat's potfile lives for this configuration."""
    return os.path.join(config.session_dir, "cracks", "hashcat.potfile")


def command_export(args, config: Config, console) -> int:
    """Write a capture out as hashcat mode 22000 (or JSON/CSV)."""
    from . import hash22000
    from .pcap import analyze_file
    include_pmkid = not args.eapol_only
    include_eapol = not args.pmkid_only
    exit_code = 0
    for item in args.capture:
        path = os.path.abspath(os.path.expanduser(item))
        if not os.path.exists(path):
            console.print(f"[red]no such file: {path}[/red]")
            exit_code = 1
            continue
        if hash22000.is_hash_file(path):
            console.print(f"[yellow]{Path(path).name} is already a hash file[/yellow]")
            continue
        analysis = analyze_file(path)
        if analysis.error:
            console.print(f"[red]{Path(path).name}: {analysis.error}[/red]")
            exit_code = 1
            continue
        lines = hash22000.lines_from_analysis(analysis, include_pmkid, include_eapol)
        if args.format == "json":
            body = json.dumps(analysis.to_dict(), indent=2) + "\n"
        elif args.format == "csv":
            body = _capture_csv(analysis)
        else:
            converter = registry.path("hcxpcapngtool") if args.hcxtools else ""
            if converter:
                target = _export_path(args.out, path, ".hc22000")
                with contextlib.suppress(Exception):
                    run([converter, "-o", target, path], timeout=180)
                if os.path.exists(target) and os.path.getsize(target):
                    console.print(f"[green]{Path(target).name}[/green] "
                                  f"({Path(target).stat().st_size} bytes, hcxpcapngtool)")
                    continue
                console.print("[yellow]hcxpcapngtool produced nothing; "
                              "using the built-in writer[/yellow]")
            body = "".join(line + "\n" for line in lines)
        if args.out in ("-", "/dev/stdout"):
            print(body, end="")
            continue
        target = _export_path(args.out, path, {"json": ".json", "csv": ".csv"}[args.format]
                              if args.format != "22000" else ".hc22000")
        if target:
            Path(target).parent.mkdir(parents=True, exist_ok=True)
            Path(target).write_text(body, encoding="utf-8")
            console.print(f"[green]{Path(target).name}[/green] \u00b7 {len(lines)} hash line(s) "
                          f"from {analysis.eapol_messages} EAPOL frame(s) "
                          f"({analysis.retransmits} retransmits ignored)")
    return exit_code


def _capture_csv(analysis) -> str:
    """One row per handshake/PMKID: what a spreadsheet or a report wants."""
    rows = ["bssid,station,essid,kind,message_pair,complete,pmkid,eapol_frames,retransmits,score"]
    for handshake in analysis.handshakes:
        essid = analysis.essids.get(handshake.bssid, "")
        rows.append(",".join([
            handshake.bssid, handshake.station, essid,
            "handshake", "M1+M2" if handshake.challenge else "M2+M3" if handshake.authorized else "partial",
            "yes" if handshake.complete else "no", handshake.pmkid,
            str(handshake.eapol_count), str(sum(m.retransmits for m in handshake.messages.values())),
            str(handshake.score),
        ]))
    for pmkid in analysis.pmkids:
        rows.append(",".join([pmkid.bssid, pmkid.station, analysis.essids.get(pmkid.bssid, ""),
                              "pmkid", "", "no", pmkid.pmkid, "0", "0", "0"]))
    return "\n".join(rows) + "\n"


def _export_path(out: str, capture: str, suffix: str) -> str:
    if not out:
        return os.path.splitext(capture)[0] + suffix
    if out.endswith(suffix):
        return out
    if os.path.isdir(out):
        return os.path.join(out, Path(capture).stem + suffix)
    return out


def _device_filter(args) -> str:
    """The edition a listing was narrowed to, from either spelling of the flag."""
    return (getattr(args, "domain", "") or getattr(args, "edition", "") or "").strip().lower()


def command_devices(args, config: Config, console) -> int:
    """The device shelf in the terminal: what the device is, and what fits it.

    The same table the web UI's picker and the API read (``wifipilot.api.devices`` and
    ``wifipilot.api.device``): a device type, the ports and protocols that identify it, and
    the attacks in the catalogue that apply to it.  The plan it prints starts with the
    discovery rows on purpose — a discovery row names the model, and the model decides
    which of the rest is worth running.
    """
    from .api import device as device_detail
    from .api import devices as device_rows

    wanted = (getattr(args, "type", "") or "").strip().lower()
    if wanted:
        matches = device_rows(device=wanted)
        ids = {str(row["id"]) for row in matches}
        if not matches:
            print(f"error: no device type matches {wanted!r} "
                  "(`wifipilot devices` lists them)", file=sys.stderr)
            return 1
        if len(matches) > 1 and wanted not in ids:
            print(f"error: {wanted!r} matches {len(matches)} device types: "
                  + ", ".join(sorted(ids)), file=sys.stderr)
            return 1
        detail = device_detail(str(matches[0]["id"]))
        if args.json:
            print(json.dumps(detail, indent=2))
            return 0
        console.print(f"[bold]{detail['label']}[/bold]  [dim]({detail['id']} · "
                      f"{detail.get('group_label', '')} · the {detail['domain']} edition)[/dim]")
        ports = ", ".join(str(port) for port in detail["ports"]) or "none declared"
        protocols = ", ".join(detail["protocols"]) or "none declared"
        console.print(f"  found by: {ports}")
        console.print(f"  it answers: {protocols}")
        if detail.get("risk"):
            console.print(f"  [dim]{detail['risk']}[/dim]")
        names = list(detail["attack_names"])
        console.print(f"[bold]{len(names)} attack(s) apply[/bold]"
                      + (f" — start with: {', '.join(list(detail['plan'])[:6])}"
                         if detail.get("plan") else ""))
        for row in detail["attacks"]:
            console.print(f"  · {row['name']}  [dim]{row.get('label', '')}[/dim]")
        return 0

    rows = device_rows(edition=_device_filter(args), group=(getattr(args, "group", "") or "").strip())
    if args.json:
        print(json.dumps({"count": len(rows), "devices": rows}, indent=2))
        return 0 if rows else 1
    if not rows:
        console.print("[yellow]no device type matches that filter[/yellow]"
                      "  [dim](`wifipilot devices --domain it` — the shelf is per edition)[/dim]")
        return 1
    console.print(f"[bold]{len(rows)} device type(s)[/bold]"
                  + (f"  [dim](the {_device_filter(args)} edition)[/dim]"
                     if _device_filter(args) else "")
                  + f"  [dim]({sum(len(row['attack_names']) for row in rows)} attack "
                    "suggestion(s) in total)[/dim]")
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(str(row.get("group_label", "")), []).append(row)
    for group, members in grouped.items():
        console.print(f"[bold]{group or 'other'}[/bold] [dim]({len(members)})[/dim]")
        for row in members:
            ports = ", ".join(str(port) for port in row["ports"][:4]) or "—"
            console.print(f"  {row['id']:24s} {row['label']:26s} [dim]{ports:26s} "
                          f"{len(row['attack_names'])} attack(s)[/dim]")
    console.print("[dim]`wifipilot devices --type <id>` shows one device and its plan[/dim]")
    return 0


def command_sim(args, config: Config, console) -> int:
    """What the simulated environments contain.

    Demo mode is a simulation, not a stub: :mod:`wifipilot.blesim` answers HCI the way a
    controller does and :mod:`wifipilot.itsim` answers the protocols a segment speaks, so
    a demo run meets devices, refuses what a hardened one refuses, and goes through the
    same parsers as a live run.  This prints that world — from the same function the API
    and the web UI read (``wifipilot.api.simulations``).
    """
    from .api import simulations

    wanted = _device_filter(args)
    if wanted in ("ble", "bt", "blue"):
        wanted = "bluetooth"
    if wanted not in ("", "all", "bluetooth", "it"):
        print(f"error: unknown edition {wanted!r} (bluetooth, it or all)", file=sys.stderr)
        return 1
    try:
        data = simulations("" if wanted in ("", "all") else wanted)
    except Exception as exc:                                     # pragma: no cover
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(data, indent=2))
        return 0
    limit = max(1, int(getattr(args, "limit", 60)))
    console.print("[bold]simulated environments[/bold]  [dim]what a --demo run is made "
                  "of (no radio, real code paths)[/dim]")
    bluetooth = data.get("bluetooth")
    if bluetooth:
        rssi = bluetooth["rssi_range"]
        console.print(f"[bold]Bluetooth floor[/bold]  {bluetooth['devices']} device(s) · "
                      f"{bluetooth['profiles']} profile(s) · RSSI {rssi[0]}..{rssi[1]} dBm")
        console.print("  " + ", ".join(f"{name} ×{count}" for name, count
                                       in sorted(bluetooth["by_profile"].items())))
        console.print(f"  [dim]trackers {bluetooth['trackers']} · beacons "
                      f"{bluetooth['beacons']} · classic {bluetooth['classic']} · GATT "
                      f"servers {bluetooth['gatt_servers']} · roles: "
                      f"{', '.join(sorted(bluetooth['link_roles']))}[/dim]")
        if getattr(args, "rows", False):
            for row in bluetooth["catalog"][:limit]:
                addr = row.get("address", "")
                console.print(f"  {addr:18s} {row.get('name', '') or '(no name)':22s} "
                              f"[dim]{row.get('device', ''):16s} {row.get('profile', ''):13s} "
                              f"{row.get('rssi', '')} dBm"
                              + (f" · {row['tracker']} tracker" if row.get("tracker") else "")
                              + (f" · {row['beacon']} beacon" if row.get("beacon") else "")
                              + "[/dim]")
    it = data.get("it")
    if it:
        console.print(f"[bold]IT segment[/bold]  {it['hosts']} host(s) · "
                      f"{it['profiles']} profile(s) · {len(it['open_ports'])} port(s) · "
                      f"{len(it['responders'])} responder(s)")
        console.print("  " + ", ".join(f"{name} ×{count}" for name, count
                                       in sorted(it["by_profile"].items())))
        console.print(f"  [dim]{', '.join(sorted(it['responders']))}[/dim]")
        if getattr(args, "rows", False):
            for row in it["catalog"][:limit]:
                console.print(f"  {row.get('ip', ''):15s} {row.get('hostname', ''):20s} "
                              f"[dim]{row.get('device_label', ''):20s} "
                              f"{row.get('profile', ''):15s} "
                              f"{', '.join(str(port) for port in row.get('ports', [])[:6])}"
                              "[/dim]")
    if not bluetooth and not it:                                 # pragma: no cover
        console.print("[yellow]nothing to show for that edition[/yellow]")
        return 1
    console.print("[dim]`wifipilot sim --list` prints the devices; `--json` prints it "
                  "all for a script[/dim]")
    return 0


def command_attacks(args, config: Config, console) -> int:
    """The catalogue, grouped by what an attack costs and what it produces.

    This is the same table the planner, the web UI and the advisor prompt read
    (``wifipilot.attacks.attack_catalog``): one source, so the CLI cannot describe an
    attack differently from the report that ran it.
    """
    from .attacks import (IMPACT_STYLE, NOISE_STYLE, OFFLINE_ATTACKS, attack_catalog,
                          category_label)

    entries = attack_catalog()
    if args.category:
        wanted = args.category.strip().lower()
        entries = [entry for entry in entries
                   if str(entry["category"]) == wanted
                   or category_label(str(entry["category"])).lower() == wanted]
    if args.noise:
        entries = [entry for entry in entries if entry["noise"] == args.noise.strip().lower()]
    if args.only_offline:
        entries = [entry for entry in entries if entry["offline"]]
    wanted_domain = (getattr(args, "domain", "") or getattr(args, "edition", "")
                     or "").strip().lower()
    if wanted_domain:
        entries = [entry for entry in entries if entry.get("domain") == wanted_domain]
    wanted_device = (getattr(args, "device", "") or "").strip().lower()
    device_plan: List[str] = []
    if wanted_device:
        from .itdev import DEVICE_TYPES, device_type, plan_for_device
        chosen = device_type(wanted_device) or next(
            (dev for dev in DEVICE_TYPES if wanted_device in dev.id
             or wanted_device in dev.label.lower()), None)
        if not chosen:
            console.print(f"[yellow]no device type called {wanted_device!r} in the shelf "
                          "[/yellow][dim](`wifipilot devices` lists them)[/dim]")
            return 1
        device_plan = plan_for_device(chosen.id)
        entries = [entry for entry in entries if str(entry["name"]) in set(device_plan)]
    if args.json:
        print(json.dumps({"count": len(entries), "attacks": entries,
                          "offline_attacks": list(OFFLINE_ATTACKS)}, indent=2))
        return 0 if entries else 1
    if not entries:
        console.print("[yellow]no attack matches that filter[/yellow]")
        return 1

    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for entry in entries:
        grouped.setdefault(str(entry["category"]), []).append(entry)
    total = len(attack_catalog())
    console.print(f"[bold]{len(entries)} of {total} attacks[/bold]"
                  + (f"  [dim](the {wanted_domain} edition)[/dim]" if wanted_domain else "")
                  + ("  [dim](the ones that transmit nothing)[/dim]"
                     if args.only_offline else ""))
    if wanted_device:
        console.print(f"[dim]device shelf: {chosen.label} · {len(device_plan)} attacks fit it · "
                      "`wifipilot attack --edition it --it-host <ip> --attacks "
                      + ",".join(device_plan[:3]) + ",...`[/dim]")
    for category, items in grouped.items():
        console.print(f"\n[bold]{category_label(category)}[/bold] "
                      f"[dim]({len(items)})[/dim]")
        for entry in items:
            noise = NOISE_STYLE.get(str(entry["noise"]), "")
            impact = IMPACT_STYLE.get(str(entry["impact"]), "")
            flags = []
            if entry["needs_injection"]:
                flags.append("injects")
            if entry["default_enabled"]:
                flags.append("on by default")
            if entry["offline"]:
                flags.append("no radio")
            console.print(f"  [bold]{entry['name']:<20}[/bold] {entry['label']}")
            console.print(f"      {noise} · {impact} · "
                          f"{' · '.join(flags) if flags else 'opt-in'}")
            console.print(f"      [dim]tool:[/dim] {entry['tool']}")
            console.print(f"      [dim]defender sees:[/dim] {entry['detection']}")
    console.print("\n[dim]every attack is described in docs/ATTACKS.md and in the "
                  "report it produces; `--category`, `--noise` and `--no-radio` "
                  "filter this list, `--json` returns it[/dim]")
    return 0


def command_tools(args, config: Config, console) -> int:
    from .deps import list_interfaces
    infos = registry.all(force=args.force)
    caps = registry.capabilities()
    interfaces = list_interfaces(force=args.force)
    if args.json:
        print(json.dumps({
            "tools": [i.to_dict() for i in infos],
            "capabilities": caps,
            "interfaces": [i.to_dict() for i in interfaces],
            "missing_required": registry.missing_required(),
            "platform": platform_info(),
        }, indent=2))
        return 0
    if HAVE_RICH:
        table = Table(title="external tools", box=None)
        for column in ("TOOL", "CATEGORY", "PURPOSE", "STATUS", "VERSION", "INSTALL"):
            table.add_column(column)
        for info in infos:
            table.add_row(info.name, info.category, info.purpose,
                          "[green]ready[/green]" if info.available else "[red]missing[/red]",
                          info.version or "-", info.install or "-")
        console.print(table)
    else:
        for info in infos:
            print(f"{info.name:<16} {'ok' if info.available else 'MISSING':<8} "
                  f"{info.version or ''} {info.purpose}")
    info = platform_info()
    console.print(f"\n[bold]platform[/bold]\n  {info['os']} "
                  f"{info['distro']} · kernel {info['kernel']} · "
                  f"{'supported' if info['supported'] else '[red]unsupported (Linux only)[/red]'}"
                  + (f" · {info['package_manager']}" if info["package_manager"] else ""))
    console.print("\n[bold]capabilities[/bold]")
    for key, value in caps.items():
        console.print(f"  {key:<12} {'[green]yes[/green]' if value else '[red]no[/red]'}")
    console.print("\n[bold]wireless interfaces[/bold]")
    if not interfaces:
        console.print("  [yellow]none detected[/yellow] — simulation mode is available with --demo")
    for iface in interfaces:
        console.print(f"  {iface.name} ({iface.driver or 'unknown'}) bands={iface.bands_label} "
                      f"monitor={'yes' if iface.supports_monitor else 'no'} "
                      f"injection={'yes' if iface.supports_injection else 'unknown'}")
    missing = registry.missing_required()
    if missing:
        console.print(f"\n[red]missing required tools: {', '.join(missing)}[/red]")
        for name in missing:
            console.print(f"  {name}: {registry.probe(name).install}")
    return 0 if not missing else 1


def command_ai(args, config: Config, console) -> int:
    from .advisor import Advisor
    from .session import Session
    from .util import read_json

    bus = EventBus()
    session = Session(config, bus, demo=config.demo)
    if args.report and os.path.exists(args.report):
        data = read_json(args.report, {}) or {}
        for entry in data.get("access_points", []):
            bssid = entry.get("bssid", "")
            if not bssid:
                continue
            ap, _ = session.upsert_ap(bssid, entry.get("essid", ""), publish=False)
            for key in ("channel", "signal", "encryption", "wps", "wps_locked", "vendor",
                        "hidden", "sae", "pmf"):
                if entry.get(key) is not None:
                    setattr(ap, key, entry[key])
            ap.notes = "loaded from report"
        console.print(f"[dim]loaded context from {args.report} "
                      f"({len(session.aps)} APs)[/dim]")

    provider_override = (getattr(args, "provider", "") or "").strip().lower()
    if provider_override:
        if provider_override == "openrouter":
            config.openrouter.enabled = True
        config.ai_provider = provider_override
    advisor = Advisor(session, None, bus, demo=config.demo)
    advisor.configure(config.ai_provider)
    action = args.ai_command or "status"

    if config.ai_off() and action in ("status", "models", "pull", "use", "ask"):
        # "off" is not a failure state, and it is not a reason to reach for the
        # network either: report it and stop
        if args.json:
            print(json.dumps({"ok": True, "disabled": True, "provider": "none",
                              "action": action,
                              "note": "advisor disabled; the deterministic planner "
                                      "is in use"},
                             indent=2))
            return 0 if action == "status" else 1
        console.print("[bold]advisor: off[/bold] — "
                      + ("no model is in use." if action == "status"
                         else f"`{action}` needs a model, and none is in use.")
                      + " The deterministic planner does the deciding.")
        console.print("[dim]turn it on with `wifipilot ai on` (or drop --no-ai / "
                      "WIFIPILOT_NO_AI).[/dim]")
        return 0 if action == "status" else 1

    if action in ("off", "on", "toggle"):
        # the switch itself: no provider is probed on the way here, and "off" writes
        # nothing but the one field, so it cannot be talked out of it
        if action == "off" or (action == "toggle" and not config.ai_off()):
            config.ai_provider = "none"
        elif action == "on":
            config.ai_provider = (getattr(args, "provider_name", "") or "auto").strip().lower()
        else:                                   # toggle, and AI is currently off
            config.ai_provider = "auto"
        if getattr(args, "save", False):
            path = config.save()
            console.print(f"[dim]saved to {path}[/dim]")
        disabled = config.ai_off()
        env_off = str(os.environ.get("WIFIPILOT_NO_AI", "")).strip().lower() in (
            "1", "true", "yes", "on")
        payload = {"ok": True, "disabled": disabled, "ai_provider": config.ai_provider,
                   "enabled": config.ai_enabled(), "env_off": env_off,
                   "resolution": config.active_provider(probe=False)[1]}
        if args.json:
            print(json.dumps(payload, indent=2))
            return 0
        if disabled:
            console.print("[bold]advisor: off[/bold] — the deterministic planner is "
                          "doing the deciding. No model is called, and nothing about "
                          "the engagement leaves this machine.")
            console.print("[dim]turn it back on with `wifipilot ai on` (or "
                          "`wp.ai(disable=False)` in Python).[/dim]")
        else:
            console.print(f"[bold]advisor: on[/bold] — provider "
                          f"[magenta]{payload['resolution']}[/magenta]")
        if env_off:
            console.print("[yellow]note: WIFIPILOT_NO_AI is set in this shell, so the "
                          "advisor stays off until you unset it.[/yellow]")
        return 0

    if action == "status":
        available = advisor.check(force=True, announce=False)
        payload = advisor.status()
        if args.json:
            print(json.dumps(payload, indent=2))
            return 0
        model_list = [m["name"] for m in payload["models"]]
        lines = [
            f"provider: [magenta]{payload['provider_label']}[/magenta] "
            f"({'cloud — data leaves this machine' if payload['cloud'] else 'local — data stays here'})",
            f"host: [cyan]{payload['host']}[/cyan]",
            f"reachable: {'[green]yes[/green]' if available else '[red]no[/red]'}",
            f"selected model: [magenta]{payload['model'] or '—'}[/magenta]",
            f"available models: {', '.join(model_list[:6]) or 'none'}"
            + (f" (+{len(model_list) - 6} more)" if len(model_list) > 6 else ""),
            f"auto-think: {'on' if payload['auto_think'] else 'off'} · "
            f"plan interval: {payload['policy'].get('think_interval', 0)}s · "
            f"temperature: {payload['policy'].get('temperature', 0)}",
            f"calls: {payload['calls']} · errors: {payload['errors']} · "
            f"avg latency: {payload['avg_latency']}s",
            f"tokens: {payload['tokens']} · spend: ${payload['cost_usd']:.4f}"
            + (f" (budget ${payload['policy'].get('max_cost_usd', 0):.2f})"
               if payload["policy"].get("max_cost_usd") else ""),
        ]
        if payload["cloud"]:
            key = payload.get("key") or {}
            lines.insert(3, f"api key: "
                            f"{'[green]' + key.get('hint', 'set') + '[/green]' if key.get('configured') else '[red]not configured[/red]'}")
            lines.insert(4, f"identifiers: "
                            f"{'pseudonymised' if payload['policy'].get('redact_identifiers') else '[red]sent verbatim[/red]'}")
            if payload.get("allowance"):
                lines.insert(5, f"allowance: {payload['allowance']}")
        lines.append(f"last error: [red]{payload['last_error'] or '—'}[/red]")
        console.print(Panel("\n".join(lines), title="advisor (optional)", border_style="magenta"))
        if not available:
            console.print(f"[yellow]{advisor._offline_message()}[/yellow]")
        return 0

    if action == "providers":
        rows = provider_status(config.ollama, config.openrouter, probe=bool(args.probe),
                               cortex=config.cortex)
        active = advisor.provider
        if args.json:
            print(json.dumps({"active": active, "providers": rows}, indent=2))
            return 0
        if HAVE_RICH:
            table = Table(title="model providers", box=None)
            for column in ("", "PROVIDER", "STATE", "CONFIGURED", "MODEL", "REQUIREMENTS"):
                table.add_column(column)
            for row in rows:
                requirements = ("needs a local daemon: ollama serve" if row["name"] == "ollama"
                                else "needs enabled=true + OPENROUTER_API_KEY")
                state = ("[green]active[/green]" if row["name"] == active
                         else "[dim]idle[/dim]")
                reachable = row.get("reachable")
                if reachable is True:
                    state += " [green](online)[/green]"
                elif reachable is False:
                    state += " [red](unreachable)[/red]"
                configured = "yes" if row["configured"] else "[red]no[/red]"
                if row["name"] == "openrouter":
                    configured += f" {row.get('key_hint', '')}"
                table.add_row("→" if row["name"] == active else "", row["label"], state,
                              configured, str(row["model"]), requirements)
            console.print(table)
        else:
            for row in rows:
                print(f"{row['name']:<12} enabled={row['enabled']} configured={row['configured']} "
                      f"model={row['model']}")
        console.print(f"[dim]active: [magenta]{active}[/magenta] — switch with "
                      f"`wifipilot ai use <model> --provider <name>` or the --provider flag[/dim]")
        return 0

    if action == "models":
        models = advisor.models(force=True, query=getattr(args, "search", ""),
                                limit=getattr(args, "limit", 0),
                                free_only=bool(getattr(args, "free", False)))
        if args.json:
            print(json.dumps(models, indent=2))
            return 0
        if not models:
            console.print(f"[yellow]no models found from {advisor.client.label}"
                          f"{': ' + advisor.client.models_error if getattr(advisor.client, 'models_error', '') else ''}[/yellow]")
            return 1
        if HAVE_RICH:
            table = Table(title=f"{advisor.provider} models ({len(models)})", box=None)
            for column in ("MODEL", "CONTEXT", "PRICE", "SIZE"):
                table.add_column(column)
            for model in models:
                table.add_row(model["name"], f"{model['context']:,}" if model["context"] else "-",
                              model["price"], f"{model['size_gb']} GB" if model["size_gb"] else "-")
            console.print(table)
        else:
            for model in models:
                print(f"{model['name']:<48} {model['price']}")
        if advisor.provider == "openrouter":
            console.print(f"[dim]prices are USD per 1M tokens (in/out), from "
                          f"{advisor.client.host}/models · set one with "
                          f"`wifipilot ai use <model>`[/dim]")
        return 0

    if action == "use":
        target_model = getattr(args, "model", "") or ""
        target_provider = (getattr(args, "provider", "") or "").strip().lower()
        if not target_model and not target_provider:
            console.print("[yellow]nothing to do: give a model name and/or --provider[/yellow]")
            return 2
        if target_provider == "openrouter":
            config.openrouter.enabled = True
        advisor.configure(target_provider or advisor.provider, announce=False)
        ok = advisor.use_model(target_model, target_provider)
        if target_provider:
            config.ai_provider = target_provider
        if getattr(args, "save", False):
            path = config.save()
            console.print(f"[green]saved to {path}[/green] (mode 600)")
        if args.json:
            print(json.dumps(advisor.status(), indent=2))
            return 0 if ok else 1
        console.print(f"provider: [magenta]{advisor.provider}[/magenta] · "
                      f"model: [magenta]{advisor.model or target_model or 'auto'}[/magenta] · "
                      f"reachable: {'[green]yes[/green]' if advisor.available else '[red]no[/red]'}")
        if not advisor.available:
            console.print(f"[yellow]{advisor._offline_message()}[/yellow]")
        return 0 if ok else 1

    if action == "pull":
        if advisor.provider != "ollama":
            console.print("[red]only Ollama models can be pulled locally[/red] — "
                          f"{advisor.provider} models are hosted. List them with "
                          f"`wifipilot ai models --provider {advisor.provider}`.")
            return 2
        console.print(f"[cyan]pulling {args.model} through Ollama…[/cyan]")
        last = ""

        def on_progress(chunk: Dict[str, Any]) -> None:
            nonlocal last
            status = chunk.get("status", "")
            total, done = chunk.get("total"), chunk.get("completed")
            if total and done:
                status += f"  {done * 100 // total}%"
            if status != last:
                last = status
                console.print(f"  [dim]{status}[/dim]")

        ok = advisor.pull_model(args.model)
        console.print("[green]model available[/green]" if ok else "[red]pull failed[/red]")
        return 0 if ok else 1
    if action == "ask":
        question = " ".join(args.question)
        console.print("[dim]thinking…[/dim]")

        def on_event(event: Event) -> None:
            if event.kind == EK.ADVISOR_TOKEN:
                print(event.data.get("piece", ""), end="", flush=True)

        subscription = bus.subscribe([EK.ADVISOR_TOKEN])
        import threading

        def pump() -> None:
            while True:
                event = subscription.get(timeout=0.4)
                if event is None and not threading.main_thread().is_alive():
                    return
                if event is not None:
                    on_event(event)

        thread = threading.Thread(target=pump, daemon=True)
        thread.start()
        answer = advisor.ask(question, model=args.model)
        print()
        subscription.close()
        if not answer:
            console.print("[red]no answer (is Ollama running?)[/red]")
            return 1
        return 0
    console.print(f"[red]unknown ai action: {action}[/red]")
    return 2


def command_config(args, config: Config, console) -> int:
    if args.init or args.write:
        target = args.write or "wifipilot.json"
        config.save(target)
        console.print(f"[green]wrote configuration to {target}[/green]")
        return 0
    if args.json:
        print(json.dumps(config.to_dict(), indent=2))
        return 0
    console.print(Panel(json.dumps(config.to_dict(), indent=2), title="effective configuration",
                        border_style="cyan"))
    console.print("[dim]wordlists found:[/dim]")
    for item in find_wordlists(config):
        console.print(f"  {item['path']} ({item['size']} bytes"
                      f"{', bundled' if item['builtin'] else ''})")
    return 0


def command_demo(args, config: Config, console) -> int:
    config.demo = True
    config.authorized = False
    config.ollama.think_interval = min(config.ollama.think_interval, 30.0)
    args_command = argparse.Namespace(**vars(args))
    args_command.skip_crack = False
    args_command.time = "20"
    args_command.duration = ""
    args_command.bssid = []
    args_command.no_scan = False
    console.print("[yellow]Simulation mode: wifipilot will not touch any radio. "
                  "A fake neighbourhood is driven through the real pipeline "
                  "(scanner → planner → attacks → cracker → report).[/yellow]")
    return command_attack(args_command, config, console)


# --------------------------------------------------------------------------- #
# entry point
# --------------------------------------------------------------------------- #


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # wifipilot drives Linux-only subsystems (nl80211/aircrack-ng/sysfs/rfkill):
    # refuse to run anywhere else instead of failing halfway through an engagement.
    try:
        require_linux()
    except SystemExit as exc:
        print(str(exc), file=sys.stderr)
        return 2
    try:
        config = apply_cli_config(args)
    except SystemExit as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.no_color:
        os.environ["NO_COLOR"] = "1"
    console = Console(no_color=args.no_color or bool(os.environ.get("NO_COLOR")),
                      soft_wrap=True, stderr=bool(args.json)) if HAVE_RICH else None
    if console is None:
        # Without rich the console is plainer, not different: prose still goes to stderr
        # when --json asked for a machine-readable stdout (or the JSON parser would meet
        # a banner), and rich markup is dropped rather than printed as literal tags.
        class _FallbackConsole:  # pragma: no cover
            def __init__(self, stderr: bool = False, **kwargs: Any) -> None:
                self.stream = sys.stderr if stderr else sys.stdout

            def print(self, *items: Any, **kwargs: Any) -> None:
                print(*[C.strip_markup(str(item)) for item in items], file=self.stream)

            def rule(self, title: str = "", **kwargs: Any) -> None:
                print(f"--- {title} ---" if title else "---", file=self.stream)
        console = _FallbackConsole(stderr=bool(args.json))

    command = args.command or "attack"
    if command in ("scan", "attack", "demo") and not args.json:
        console.print(banner())
        provider, provider_reason = config.active_provider(probe=False)
        if provider == "openrouter":
            console.print(f"[yellow]AI: OpenRouter (cloud) — model "
                          f"{config.openrouter.model}; engagement data is sent to "
                          f"openrouter.ai"
                          + (" with identifiers pseudonymised"
                             if config.openrouter.redact_identifiers
                             else " [bold]verbatim[/bold]")
                          + ". Keep it local with --provider ollama.[/yellow]")
        elif provider == "none" and not args.no_ai:
            console.print(f"[dim]{config.provider_note()} ({provider_reason})[/dim]")

    handlers = {
        "scan": command_scan,
        "attack": command_attack,
        "web": command_web,
        "crack": command_crack,
        "analyze": command_analyze,
        "export": command_export,
        "survey": command_survey,
        "eap": command_eap,
        "reveal": command_reveal,
        "decode": command_decode,
        "pins": command_pins,
        "pmk": command_pmk,
        "targets": command_targets,
        "note": command_note,
        "tag": command_tag,
        "vendor": command_vendor,
        "attacks": command_attacks,
        "devices": command_devices,
        "sim": command_sim,
        "benchmark": command_benchmark,
        "advice": command_advice,
        "wordlist": command_wordlist,
        "hash": command_hash,
        "potfile": command_potfile,
        "loot": command_loot,
        "tools": command_tools,
        "ai": command_ai,
        "config": command_config,
        "demo": command_demo,
    }
    handler = handlers.get(command)
    if handler is None:
        parser.print_help()
        return 2
    try:
        return handler(args, config, console)
    except KeyboardInterrupt:
        console.print("\n[yellow]interrupted[/yellow]")
        return 130
    except LLMError as exc:
        # expected, operator-facing conditions (no key, daemon down, out of
        # credit, rate limited, over budget): say so plainly instead of dumping
        # a traceback at the operator mid-engagement.
        if args.verbose:
            raise
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
