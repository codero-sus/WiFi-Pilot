"""``wifipilot`` command line interface.

    wifipilot scan                        # discover access points
    wifipilot attack --i-am-authorized    # AI-planned campaign (live)
    wifipilot demo                        # same pipeline, simulated radio
    wifipilot web --open                  # browser UI
    wifipilot crack loot/handshake-*.cap  # crack an existing capture
    wifipilot analyze capture.pcapng      # what is actually inside that file
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
from .models import ATTACK_NAMES, Capture
from .util import (C, banner, human_duration, mac_norm, parse_duration,
                   platform_info, require_linux)

# --------------------------------------------------------------------------- #
# rich helpers (the CLI still works without rich, just plainer)
# --------------------------------------------------------------------------- #

try:
    from rich.console import Console, Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress_bar import ProgressBar
    from rich.table import Table
    from rich.text import Text
    HAVE_RICH = True
except ImportError:  # pragma: no cover
    HAVE_RICH = False


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
                        help=f"comma separated attack list (from: {', '.join(ATTACK_NAMES)})")
    add(parser, "--wps-pin", action="store_true",
                        help="enable the online WPS PIN attack (slow, disruptive, off by default)")
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
    ai = parser.add_argument_group("AI advisor (local Ollama or OpenRouter)")
    add(ai, "--no-ai", action="store_true", help="disable the AI advisor entirely")
    add(ai, "--provider", default="",
                    choices=["", "auto", "ollama", "openrouter", "none"],
                    help="model provider: auto (prefer local Ollama), ollama, openrouter, none")
    add(ai, "--model", default="", help="model name for the active provider")
    add(ai, "--ollama-host", default="", help="Ollama base URL")
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
        description="AI-piloted WiFi auditing — a wifite alternative for Linux, with a "
                    "local (Ollama) or cloud (OpenRouter) LLM advisor and a web UI.",
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
    p_attack.add_argument("--skip-crack", action="store_true",
                          help="capture only, do not run the cracker")

    p_web = sub.add_parser("web", parents=[common], help="start the web UI")
    p_web.add_argument("--host", default="", help="bind address (default 0.0.0.0)")
    p_web.add_argument("--port", type=int, default=0, help="port (default 8787)")
    p_web.add_argument("--open", action="store_true", help="open a browser window")

    p_crack = sub.add_parser("crack", parents=[common], help="crack a capture you already have")
    p_crack.add_argument("capture", nargs="+", help=".cap / .pcap / .pcapng / .hc22000 file(s)")
    p_crack.add_argument("-b", "--bssid", default="", help="BSSID (optional, inferred from the file)")
    p_crack.add_argument("-e", "--essid", default="", help="SSID (needed for handshake MIC checks)")
    p_crack.add_argument("--engine", default="", choices=["", "auto", "aircrack", "hashcat"])
    p_crack.add_argument("--mask", action="store_true", help="also try common mask patterns")

    p_analyze = sub.add_parser("analyze", parents=[common], help="inspect captures: handshakes, PMKIDs, EAPOL")
    p_analyze.add_argument("capture", nargs="+", help="capture file(s)")

    p_tools = sub.add_parser("tools", parents=[common], help="show tool availability and capabilities")
    p_tools.add_argument("--force", action="store_true", help="re-probe instead of using cache")

    p_ai = sub.add_parser("ai", parents=[common], help="AI advisor utilities (Ollama, OpenRouter)")
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
    if args.timeout:
        budget = parse_duration(args.timeout, config.attack_timeout)
        config.attack_timeout = budget
        config.crack_timeout = budget
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
        else:
            config.ollama.model = args.model
    if args.ollama_host:
        config.ollama.host = args.ollama_host
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
        header.append("  AI: ", style="dim")
        if advisor.available:
            header.append(f"{advisor.model or 'ready'}", style="bold magenta")
        elif self.engine.config.ollama.enabled:
            header.append("offline → heuristics", style="yellow")
        else:
            header.append("disabled", style="dim")

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
            advisor_note = f"{'AI' if plan.source == 'llm' else 'heuristic'} plan: {plan.summary()}"
        footer.append(" " + (advisor_note or status.detail or "")[:160], style="dim")
        return Group(Panel(header, box=None, padding=(0, 0)), table,
                     Panel(Group(bar, progress_line), box=None, padding=(0, 0)) if HAVE_RICH else Text(""),
                     Panel(logs, title="[dim]events[/dim]", box=None, padding=(0, 0)),
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
    host = args.host or config.web_host
    port = args.port or config.web_port
    provider, _ = config.active_provider(probe=False)
    ai_line = f"provider: {provider}"
    if provider == "openrouter":
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
    if provider == "openrouter":
        console.print("[yellow]Cloud provider: SSIDs, BSSIDs, MACs and recovered PSKs of this "
                      "engagement are sent to openrouter.ai"
                      + (" (pseudonymised)" if config.openrouter.redact_identifiers else "")
                      + ". Keep it local with --provider ollama.[/yellow]")
    with contextlib.suppress(KeyboardInterrupt):
        run_server(config, host=host, port=port, demo=demo, authorized=config.authorized,
                   open_browser=args.open)
    return 0


def command_crack(args, config: Config, console) -> int:
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


def command_analyze(args, config: Config, console) -> int:
    from .pcap import analyze_file
    payload = []
    for item in args.capture:
        path = os.path.abspath(os.path.expanduser(item))
        analysis = analyze_file(path)
        payload.append(analysis.to_dict())
        if args.json:
            continue
        console.print(Panel(
            f"[bold]{Path(path).name}[/bold]  format={analysis.format or '?'}  "
            f"packets={analysis.packets}  beacons={analysis.beacons}  data={analysis.data_packets}\n"
            f"EAPOL messages: {analysis.eapol_messages} · "
            f"handshakes: {len(analysis.handshakes)} ({'crackable' if analysis.has_handshake else 'incomplete'}) · "
            f"PMKIDs: {len(analysis.pmkids)} · WEP IV frames: {analysis.wep_data}",
            title="analysis", border_style="cyan"))
        for handshake in analysis.handshakes:
            mark = "[green]crackable[/green]" if handshake.complete else "[yellow]incomplete[/yellow]"
            console.print(f"  {mark} {handshake.bssid} ↔ {handshake.station} "
                          f"messages={sorted(handshake.messages)} pmkid={'yes' if handshake.pmkid else 'no'}")
        for pmkid in analysis.pmkids:
            console.print(f"  [green]PMKID[/green] {pmkid.bssid} → {pmkid.pmkid}")
        if analysis.essids:
            console.print(f"  [dim]SSIDs: {', '.join(f'{k}={v}' for k, v in analysis.essids.items())}[/dim]")
        if analysis.error:
            console.print(f"  [red]{analysis.error}[/red]")
    if args.json:
        print(json.dumps(payload, indent=2))
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
        console.print(Panel("\n".join(lines), title="AI advisor", border_style="magenta"))
        if not available:
            console.print(f"[yellow]{advisor._offline_message()}[/yellow]")
        return 0

    if action == "providers":
        rows = provider_status(config.ollama, config.openrouter, probe=bool(args.probe))
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
        class _FallbackConsole:  # pragma: no cover
            def print(self, *items, **kwargs):
                print(*[C.strip(str(i)) for i in items])
        console = _FallbackConsole()

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
