# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Process execution, formatting, MAC/enum helpers and terminal colour.

Kept dependency free: the whole of wifipilot's *core* works with nothing but
the standard library, so the tool still runs on a locked-down pentest box that
only has aircrack-ng installed.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Union

# --------------------------------------------------------------------------- #
# terminal
# --------------------------------------------------------------------------- #

IS_TTY = bool(getattr(sys.stdout, "isatty", lambda: False)())
NO_COLOR = bool(os.environ.get("NO_COLOR")) or not IS_TTY


#: The rich styles wifipilot's own output uses, named so the fallback console (the one
#: that runs when ``rich`` is not installed) can drop the tags instead of printing them.
#: The list is deliberately a vocabulary rather than "anything in brackets": ``[WPA2]``,
#: ``[200 OK]`` and ``[1, 2]`` are data, and the no-rich path may not eat them.
MARKUP_ATTRIBUTES = ("bold", "b", "dim", "italic", "i", "underline", "u", "blink",
                     "reverse", "r", "strike", "s", "conceal", "reset")
MARKUP_COLOURS = ("black", "red", "green", "yellow", "blue", "magenta", "cyan", "white",
                  "grey", "gray", "bright_black", "bright_red", "bright_green",
                  "bright_yellow", "bright_blue", "bright_magenta", "bright_cyan",
                  "bright_white")
#: the palette as an alternation, longest first so ``bright_red`` wins over ``red``.
#: The ``on_`` forms are their own alternatives on purpose: writing ``on_X|X`` inside a
#: pattern means "on_X or X" — the prefix binds to the first alternative only, which is
#: how a three-word tag like ``[bold green on_red]`` slips through unstripped.
MARKUP_COLOUR_ALT = "|".join(sorted(MARKUP_COLOURS, key=len, reverse=True))
MARKUP_ON_ALT = "|".join("on_" + colour
                         for colour in sorted(MARKUP_COLOURS, key=len, reverse=True))
MARKUP_ATTRIBUTE_ALT = "|".join(sorted(MARKUP_ATTRIBUTES, key=len, reverse=True))
#: one style token: an attribute, a background, or a colour
MARKUP_TOKEN = ("(?:" + MARKUP_ATTRIBUTE_ALT + "|" + MARKUP_ON_ALT + "|"
                + MARKUP_COLOUR_ALT + ")")

#: one opening or closing rich tag: one or more style tokens, a hex colour, or a link
MARKUP_TAG = re.compile(
    r"\[(/?)(?:" + MARKUP_TOKEN + r"(?:[ ]" + MARKUP_TOKEN + r")*"
    r"|#(?:[0-9a-fA-F]{6}|[0-9a-fA-F]{3})"
    r"|link(?:=[^\[\]]*)?"
    r")\]"
)


class C:
    """ANSI colour helpers (degrade to no-ops when not on a TTY)."""

    RESET = "" if NO_COLOR else "\033[0m"
    BOLD = "" if NO_COLOR else "\033[1m"
    DIM = "" if NO_COLOR else "\033[2m"
    RED = "" if NO_COLOR else "\033[31m"
    GREEN = "" if NO_COLOR else "\033[32m"
    YELLOW = "" if NO_COLOR else "\033[33m"
    BLUE = "" if NO_COLOR else "\033[34m"
    MAGENTA = "" if NO_COLOR else "\033[35m"
    CYAN = "" if NO_COLOR else "\033[36m"
    WHITE = "" if NO_COLOR else "\033[37m"
    GREY = "" if NO_COLOR else "\033[90m"

    @staticmethod
    def wrap(text: str, colour: str) -> str:
        return text if NO_COLOR or not colour else f"{colour}{text}{C.RESET}"

    @staticmethod
    def strip(text: str) -> str:
        return re.sub(r"\033\[[0-9;]*m", "", text)

    #: the markup pattern, reachable from the class as well as the module
    MARKUP_TAG = MARKUP_TAG

    @staticmethod
    def strip_markup(text: str) -> str:
        """ANSI escapes *and* rich markup gone: what a rich-less console can print.

        With ``rich`` installed, ``[green]ok[/green]`` is a colour; without it, the tags
        would be part of the text a script reads.  So the fallback console runs the string
        through here — the tags are dropped, the text stays, and data that happens to be
        in brackets ("[WPA2]", "[200 OK]") is untouched because it is not a style.
        """
        return C.MARKUP_TAG.sub("", C.strip(text))


# --------------------------------------------------------------------------- #
# platform
# --------------------------------------------------------------------------- #

#: wifipilot drives Linux-only subsystems: nl80211 via iw/airmon-ng, /sys/class/net,
#: rfkill, the aircrack-ng suite's monitor-mode handling and Linux-specific
#: hcxdumptool flags.  There is no supported non-Linux target.
SUPPORTED_PLATFORMS = ("linux",)

#: escape hatch for packaging/tests on other operating systems (never for real use)
PLATFORM_OVERRIDE_ENV = "WIFIPILOT_ALLOW_NON_LINUX"


def platform_name() -> str:
    """The platform string reported by the running interpreter."""
    return sys.platform


def is_linux() -> bool:
    return sys.platform.startswith("linux")


def distro_name() -> str:
    """Best-effort Linux distribution name (``Kali GNU/Linux``, ``Ubuntu`` …)."""
    data = read_kv_file("/etc/os-release")
    pretty = data.get("PRETTY_NAME") or data.get("NAME")
    if pretty:
        return pretty
    for path, key in (("/etc/redhat-release", None), ("/etc/arch-release", None)):
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace").strip()
            if text:
                return text.splitlines()[0]
        except OSError:
            continue
    return "unknown Linux"


def read_kv_file(path: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            out[key.strip()] = value.strip().strip('"').strip("'")
    except OSError:
        pass
    return out


def package_manager() -> str:
    """The distro's package manager binary, for install hints (``apt``, ``pacman`` …)."""
    for candidate in ("apt-get", "apt", "pacman", "dnf", "zypper", "apk", "xbps-install",
                      "nix-env", "emerge"):
        found = which(candidate)
        if found:
            return candidate
    return ""


def kernel_release() -> str:
    try:
        return os.uname().release
    except AttributeError:  # pragma: no cover - non-POSIX
        return ""


@lru_cache(maxsize=1)
def _platform_info_cached() -> Dict[str, str]:
    return {
        "platform": platform_name(),
        "os": "linux" if is_linux() else platform_name(),
        "kernel": kernel_release(),
        "distro": distro_name() if is_linux() else "",
        "package_manager": package_manager() if is_linux() else "",
        "supported": is_linux(),
    }


def platform_info() -> Dict[str, str]:
    """Everything the dashboards and reports need to say about the host OS.

    Computed once (it reads /etc/os-release and probes for a package
    manager): the web state push asks every tick, the answer never changes.
    """
    return dict(_platform_info_cached())


def require_linux(component: str = "wifipilot",
                  override_env: str = PLATFORM_OVERRIDE_ENV) -> None:
    """Abort with a clear message when running anywhere but Linux.

    Import the library anywhere you like — but *running* wifipilot needs Linux:
    every attack path drives Linux wireless tooling and sysfs.  Set
    ``WIFIPILOT_ALLOW_NON_LINUX=1`` only for packaging checks and test suites.
    """
    if is_linux() or os.environ.get(override_env, "").strip() not in ("", "0", "false", "no"):
        return
    raise SystemExit(
        f"{component} runs on Linux only (detected: {sys.platform}).\n"
        f"It drives the aircrack-ng suite, nl80211 monitor mode, /sys/class/net and\n"
        f"rfkill, none of which exist on {sys.platform} in a usable form.\n"
        f"Run it in a Linux VM, a container with the radio passed through, or on\n"
        f"Kali/Parrot/Ubuntu/Debian/Arch directly.  The simulated radio (--demo) is\n"
        f"also Linux-only in this build."
    )


def banner() -> str:
    return (
        f"{C.CYAN}{C.BOLD}"
        "  ██╗    ██╗██╗███████╗██╗██████╗ ██╗██╗      ██████╗ ████████╗\n"
        "  ██║    ██║██║██╔════╝██║██╔══██╗██║██║     ██╔═══██╗╚══██╔══╝\n"
        "  ██║ █╗ ██║██║█████╗  ██║██████╔╝██║██║     ██║   ██║   ██║\n"
        "  ██║███╗██║██║██╔══╝  ██║██╔═══╝ ██║██║     ██║   ██║   ██║\n"
        "  ╚███╔███╔╝██║██║     ██║██║     ██║███████╗╚██████╔╝   ██║\n"
        "   ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝╚═╝     ╚═╝╚══════╝ ╚═════╝    ╚═╝\n"
        f"{C.RESET}{C.GREY}  AI-piloted wifi auditing · wifite alternative · authorised use only · by codero-sus{C.RESET}"
    )


# --------------------------------------------------------------------------- #
# time / formatting
# --------------------------------------------------------------------------- #


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def now_ts() -> float:
    return time.time()


def clock(ts: Optional[float] = None) -> str:
    ts = time.time() if ts is None else ts
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def human_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"


def human_bytes(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}" if unit != "B" else f"{int(num)}{unit}"
        num /= 1024.0
    return f"{num:.1f}PB"


def parse_duration(text: Union[str, int, float, None], default: float = 0.0) -> float:
    """``"90"``, ``"90s"``, ``"5m"``, ``"1h30m"`` -> seconds."""
    if text is None:
        return default
    if isinstance(text, (int, float)):
        return float(text)
    text = str(text).strip().lower()
    if not text:
        return default
    if text.isdigit():
        return float(text)
    units = {"s": 1, "sec": 1, "m": 60, "min": 60, "h": 3600, "d": 86400}
    total, matched = 0.0, False
    for value, unit in re.findall(r"(\d+(?:\.\d+)?)\s*([a-z]*)", text):
        if not unit:
            total += float(value)
            matched = True
        elif unit in units:
            total += float(value) * units[unit]
            matched = True
    return total if matched else default


def slugify(text: str, maxlen: int = 48) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", (text or "").strip())
    text = re.sub(r"_+", "_", text).strip("_")
    return (text or "unnamed")[:maxlen]


class Rate:
    """Simple exponentially weighted moving average rate counter (per second)."""

    def __init__(self, half_life: float = 5.0):
        self.half_life = half_life
        self._value = 0.0
        self._last = time.time()
        self._total = 0.0

    def update(self, delta: float = 1.0) -> None:
        now = time.time()
        elapsed = max(1e-6, now - self._last)
        self._last = now
        self._total += delta
        instant = delta / elapsed
        alpha = 1.0 - 0.5 ** (elapsed / self.half_life)
        self._value += alpha * (instant - self._value)

    @property
    def value(self) -> float:
        return self._value

    @property
    def total(self) -> float:
        return self._total

    def reset(self) -> None:
        self._value, self._total, self._last = 0.0, 0.0, time.time()


# --------------------------------------------------------------------------- #
# MAC helpers
# --------------------------------------------------------------------------- #

MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")
_MAC_ANY = re.compile(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}")


def mac_norm(mac: Optional[str]) -> str:
    """Normalise to lower-case colon form; ``""`` when not a MAC."""
    if not mac:
        return ""
    return _mac_norm_cached(mac)


@lru_cache(maxsize=8192)
def _mac_norm_cached(mac: str) -> str:
    mac = mac.strip().lower().replace("-", ":")
    return mac if MAC_RE.match(mac) else ""


def mac_is_valid(mac: Optional[str]) -> bool:
    return bool(mac_norm(mac))


def mac_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac_norm(mac).split(":"))


def mac_random(locally_administered: bool = True) -> str:
    raw = bytearray(os.urandom(6))
    raw[0] = (raw[0] | 0x02) if locally_administered else (raw[0] & ~0x02)
    raw[0] &= ~0x01  # unicast
    return ":".join(f"{b:02x}" for b in raw)


def oui_vendor(mac: str, strict: bool = False) -> str:
    """Vendor guess from the OUI, offline.

    The registry lives in ``wifipilot/data/oui-wifi.json`` (see
    :mod:`wifipilot.vendors`); this wrapper keeps the historical call sites
    working and falls back to a small inline table if the data file is missing.
    The answer only depends on the OUI prefix, so it is cached per prefix —
    a snapshot asks once per AP and client, every tick.
    """
    key = mac_norm(mac)
    if not key:
        return ""
    return _oui_vendor_cached(key, strict)


@lru_cache(maxsize=8192)
def _oui_vendor_cached(key: str, strict: bool) -> str:
    try:
        from .vendors import oui_vendor as registry_lookup
    except Exception:                                  # pragma: no cover - import cycle
        registry_lookup = None
    if registry_lookup is not None:
        vendor = registry_lookup(key, strict=strict)
        if vendor:
            return vendor
    prefix = key[:8]
    if prefix in _OUI_FALLBACK:
        return _OUI_FALLBACK[prefix]
    return "" if strict else _OUI_FALLBACK_PREFIX.get(key[:7], "")


#: last-resort table (used only when the bundled registry cannot be read)
_OUI_FALLBACK = {
    "00:0c:29": "VMware", "00:50:56": "VMware", "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi", "f8:1a:67": "TP-Link", "3c:84:6a": "TP-Link",
    "50:c7:bf": "TP-Link", "ec:08:6b": "TP-Link", "f4:f2:6d": "TP-Link",
    "b0:be:76": "TP-Link", "84:16:f9": "TP-Link", "d8:47:32": "TP-Link",
    "00:24:b2": "Netgear", "2c:30:33": "Netgear", "a0:40:a0": "Netgear",
    "1c:5f:2b": "D-Link", "00:1e:58": "D-Link", "cc:b2:55": "D-Link",
    "ac:22:0b": "ASUS", "00:0f:66": "Cisco-Linksys", "c8:d7:19": "Cisco",
    "e8:bd:d1": "Huawei", "88:3f:d3": "Huawei", "00:e0:fc": "Huawei",
    "24:a4:3c": "Ubiquiti", "78:8a:20": "Ubiquiti", "fc:ec:da": "Ubiquiti",
    "d0:9e:12": "AVM", "38:10:d5": "AVM", "00:1a:2b": "Ayecom",
    "00:11:22": "Cimsys", "00:1c:df": "Belkin", "c4:41:1e": "Belkin",
}
_OUI_FALLBACK_PREFIX = {"d0:9e:1": "AVM", "9c:c7:a": "AVM", "e8:df:7": "AVM",
                        "50:c7:b": "TP-Link", "20:4e:7": "Netgear"}


# --------------------------------------------------------------------------- #
# process execution
# --------------------------------------------------------------------------- #


@dataclass
class CommandResult:
    cmd: List[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    timed_out: bool = False
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.error

    @property
    def text(self) -> str:
        return (self.stdout + ("\n" + self.stderr if self.stderr else "")).strip()

    @property
    def lines(self) -> List[str]:
        return [ln for ln in self.text.splitlines() if ln.strip()]

    def first_line(self) -> str:
        lines = self.lines
        return lines[0] if lines else ""

    def shell(self) -> str:
        return " ".join(self.cmd)

    def as_dict(self) -> Dict[str, object]:
        return {
            "cmd": self.cmd, "returncode": self.returncode, "ok": self.ok,
            "stdout": self.stdout[-4000:], "stderr": self.stderr[-2000:],
            "duration": round(self.duration, 3), "timed_out": self.timed_out,
            "error": self.error,
        }


def which(program: str) -> Optional[str]:
    """``shutil.which`` that also looks in the usual sbin locations."""
    found = shutil.which(program)
    if found:
        return found
    for prefix in ("/usr/sbin", "/sbin", "/usr/local/sbin", "/opt/homebrew/sbin"):
        candidate = Path(prefix) / program
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def run(
    cmd: Sequence[str],
    timeout: Optional[float] = 30.0,
    cwd: Optional[Union[str, Path]] = None,
    env: Optional[Dict[str, str]] = None,
    input_text: Optional[str] = None,
    check: bool = False,
) -> CommandResult:
    """Run a command to completion, never raising for non-zero exits."""
    cmd = [str(x) for x in cmd]
    started = time.time()
    full_env = dict(os.environ)
    full_env.setdefault("LC_ALL", "C")  # stable parsing of tool output
    if env:
        full_env.update(env)
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            env=full_env,
            input=input_text.encode() if input_text else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        result = CommandResult(
            cmd=cmd,
            returncode=proc.returncode,
            stdout=proc.stdout.decode("utf-8", "replace"),
            stderr=proc.stderr.decode("utf-8", "replace"),
            duration=time.time() - started,
        )
    except subprocess.TimeoutExpired as exc:
        result = CommandResult(
            cmd=cmd,
            returncode=124,
            stdout=(exc.stdout or b"").decode("utf-8", "replace") if exc.stdout else "",
            stderr=(exc.stderr or b"").decode("utf-8", "replace") if exc.stderr else "",
            duration=time.time() - started,
            timed_out=True,
        )
    except (OSError, ValueError) as exc:
        result = CommandResult(
            cmd=cmd, returncode=127, duration=time.time() - started, error=str(exc)
        )
    if check and not result.ok:
        raise RuntimeError(f"command failed: {result.shell()} -> {result.error or result.stderr}")
    return result


class Process:
    """A long lived child process with line-by-line streaming in a thread.

    Used for every external tool that runs during an attack (airodump-ng,
    reaver, aircrack-ng, hashcat ...).  ``on_line`` is called from a worker
    thread; ``on_exit`` receives the return code.
    """

    def __init__(
        self,
        cmd: Sequence[str],
        on_line: Optional[Callable[[str], None]] = None,
        on_exit: Optional[Callable[[int], None]] = None,
        cwd: Optional[Union[str, Path]] = None,
        env: Optional[Dict[str, str]] = None,
        name: str = "",
        echo_lines: bool = False,
    ):
        self.cmd = [str(x) for x in cmd]
        self.name = name or Path(self.cmd[0]).name
        self.on_line = on_line
        self.on_exit = on_exit
        self.cwd = str(cwd) if cwd else None
        self.env = env
        self.echo_lines = echo_lines
        self.lines: List[str] = []
        self.started_at = time.time()
        self.ended_at: Optional[float] = None
        self.returncode: Optional[int] = None
        self.pid: Optional[int] = None
        self.error = ""
        self._proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._stopping = False

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> "Process":
        full_env = dict(os.environ)
        full_env.setdefault("LC_ALL", "C")
        if self.env:
            full_env.update(self.env)
        try:
            self._proc = subprocess.Popen(
                self.cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                cwd=self.cwd,
                env=full_env,
                bufsize=1,
                universal_newlines=True,
                start_new_session=True,  # own process group -> clean kill of children
            )
        except (OSError, ValueError) as exc:
            self.error = str(exc)
            self.returncode = 127
            self.ended_at = time.time()
            if self.on_exit:
                with contextlib.suppress(Exception):
                    self.on_exit(127)
            return self
        self.pid = self._proc.pid
        self._thread = threading.Thread(target=self._pump, name=f"proc-{self.name}", daemon=True)
        self._thread.start()
        return self

    def _pump(self) -> None:
        assert self._proc is not None
        stream = self._proc.stdout
        if stream is not None:
            try:
                for raw in stream:
                    line = raw.rstrip("\r\n")
                    if not line.strip():
                        continue
                    with self._lock:
                        self.lines.append(line)
                        if len(self.lines) > 4000:
                            del self.lines[:2000]
                    if self.echo_lines and not NO_COLOR:
                        print(f"{C.GREY}{self.name}| {line}{C.RESET}", flush=True)
                    if self.on_line:
                        with contextlib.suppress(Exception):
                            self.on_line(line)
            except (ValueError, OSError):
                pass
        with contextlib.suppress(Exception):
            stream.close() if stream else None
        code = self._proc.wait()
        self.ended_at = time.time()
        self.returncode = code
        if self.on_exit:
            with contextlib.suppress(Exception):
                self.on_exit(code)

    # -- control -----------------------------------------------------------
    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    @property
    def alive(self) -> bool:
        return self.running

    @property
    def duration(self) -> float:
        return (self.ended_at or time.time()) - self.started_at

    def wait(self, timeout: Optional[float] = None) -> int:
        deadline = None if timeout is None else time.time() + timeout
        while self.running:
            if deadline and time.time() > deadline:
                return self.returncode if self.returncode is not None else -1
            time.sleep(0.1)
        if self._thread is not None:
            self._thread.join(timeout=1.0)
        return self.returncode if self.returncode is not None else -1

    def send(self, text: str) -> None:
        """Write to stdin (some tools, e.g. reaver, ask questions)."""
        if self._proc and self._proc.stdin:
            with contextlib.suppress(Exception):
                self._proc.stdin.write(text)
                self._proc.stdin.flush()

    def stop(self, grace: float = 1.5) -> None:
        """SIGTERM the process group, then SIGKILL if it does not die."""
        self._stopping = True
        if self._proc is None:
            return
        if self._proc.poll() is None:
            for sig, wait in ((signal.SIGINT, grace * 0.5), (signal.SIGTERM, grace * 0.5)):
                with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
                    os.killpg(os.getpgid(self._proc.pid), sig)
                deadline = time.time() + max(0.1, wait)
                while time.time() < deadline:
                    if self._proc.poll() is not None:
                        break
                    time.sleep(0.05)
            if self._proc.poll() is None:
                with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
                    os.killpg(os.getpgid(self._proc.pid), signal.SIGKILL)
        self.wait(timeout=grace)

    @property
    def tail(self) -> str:
        with self._lock:
            return "\n".join(self.lines[-12:])

    def as_dict(self) -> Dict[str, object]:
        return {
            "name": self.name, "cmd": self.cmd, "pid": self.pid,
            "running": self.running, "returncode": self.returncode,
            "duration": round(self.duration, 1), "error": self.error,
        }

    def __repr__(self) -> str:  # pragma: no cover
        state = "running" if self.running else f"rc={self.returncode}"
        return f"<Process {self.name} {state} {self.duration:.1f}s>"


class ProcessManager:
    """Tracks every child process so the UI can kill everything on shutdown."""

    def __init__(self) -> None:
        self._procs: List[Process] = []
        self._lock = threading.Lock()

    def spawn(self, *args, **kwargs) -> Process:
        proc = Process(*args, **kwargs).start()
        with self._lock:
            self._procs.append(proc)
        return proc

    def attach(self, proc: Process) -> Process:
        proc.start()
        with self._lock:
            self._procs.append(proc)
        return proc

    @property
    def running(self) -> List[Process]:
        with self._lock:
            return [p for p in self._procs if p.running]

    def stop_all(self) -> int:
        """Stop every running child; returns how many were stopped."""
        stopped = 0
        for proc in self.running:
            with contextlib.suppress(Exception):
                proc.stop()
                stopped += 1
        return stopped

    def stop_matching(self, needle: str) -> int:
        """Stop the children whose command line contains ``needle``."""
        needle = (needle or "").lower()
        stopped = 0
        for proc in self.running:
            command = " ".join(getattr(proc, "cmd", []) or []).lower()
            if needle and needle in command:
                with contextlib.suppress(Exception):
                    proc.stop()
                    stopped += 1
        return stopped

    def pids(self) -> List[int]:
        """PIDs of the running children (for the UI's tool view)."""
        return [getattr(proc, "pid", 0) for proc in self.running if getattr(proc, "pid", 0)]

    def describe(self) -> List[Dict[str, Any]]:
        """A small table of the running children, for `wifipilot tools --running`."""
        out: List[Dict[str, Any]] = []
        for proc in self.running:
            out.append({"pid": getattr(proc, "pid", 0),
                        "command": " ".join(getattr(proc, "cmd", []) or [])[:200],
                        "name": getattr(proc, "name", "")})
        return out

    def prune(self, keep: int = 40) -> None:
        with self._lock:
            done = [p for p in self._procs if not p.running]
            if len(done) > keep:
                finished = {id(p) for p in done[: len(done) - keep]}
                self._procs = [p for p in self._procs if id(p) not in finished]


# --------------------------------------------------------------------------- #
# files / json
# --------------------------------------------------------------------------- #


def read_json(path: Union[str, Path], default=None):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def write_json(path: Union[str, Path], data, indent: int = 2) -> bool:
    path = Path(path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=indent, default=str)
        tmp.replace(path)
        return True
    except OSError:
        return False


_jsonl_handles: Dict[str, Any] = {}
_jsonl_dirs: set = set()
_jsonl_lock = threading.Lock()


def _jsonl_handle(path: Path):
    """A cached, line-buffered append handle for ``path``.

    The event journal appends per log line — open()+mkdir+close per line was
    three syscalls where one write does.  Line buffering keeps the crash
    durability identical (every line reaches the OS immediately).
    """
    key = str(path)
    handle = _jsonl_handles.get(key)
    if handle is None or handle.closed:
        parent = str(path.parent)
        if parent not in _jsonl_dirs:
            path.parent.mkdir(parents=True, exist_ok=True)
            _jsonl_dirs.add(parent)
        if len(_jsonl_handles) >= 32:
            eldest_key, eldest = next(iter(_jsonl_handles.items()))
            with contextlib.suppress(Exception):
                eldest.close()
            _jsonl_handles.pop(eldest_key, None)
        handle = open(path, "a", encoding="utf-8", buffering=1)
        _jsonl_handles[key] = handle
    return handle


def append_jsonl(path: Union[str, Path], record) -> None:
    try:
        line = json.dumps(record, default=str) + "\n"
        with _jsonl_lock:
            _jsonl_handle(Path(path)).write(line)
    except (OSError, ValueError):
        pass


def read_jsonl(path: Union[str, Path]) -> List[dict]:
    out: List[dict] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                with contextlib.suppress(ValueError):
                    out.append(json.loads(line))
    except OSError:
        pass
    return out


def truncate(text: Optional[str], limit: int = 200) -> str:
    text = (text or "").replace("\n", " ").strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def chunked(items: Iterable, size: int) -> Iterator[list]:
    batch: list = []
    for item in items:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def safe_int(value, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def safe_float(value, default: float = 0.0) -> float:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))
