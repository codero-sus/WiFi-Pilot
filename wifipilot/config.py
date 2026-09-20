"""Configuration: defaults, file loading, CLI merging and wordlist discovery."""

from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict, fields
from pathlib import Path
from typing import Any, Dict, List, Optional

from .util import parse_duration, read_json, write_json

CONFIG_NAME = "wifipilot.json"
CONFIG_ENV = "WIFIPILOT_CONFIG"

#: common wordlists, first existing wins unless the user overrides
WORDLIST_CANDIDATES = (
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/rockyou.txt.gz",
    "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
    "/usr/share/wordlists/nmap.lst",
    "/usr/share/wordlists/fasttrack.txt",
    "/opt/wordlists/rockyou.txt",
    str(Path.home() / "wordlists" / "rockyou.txt"),
)

#: wordlists ship with wifipilot for the "-k" style quick wins
BUILTIN_WORDLISTS = ("wifi-defaults.txt", "wifi-common-ssids.txt")


@dataclass
class OllamaConfig:
    """Local LLM settings (Ollama HTTP API)."""

    enabled: bool = True
    host: str = "http://127.0.0.1:11434"
    model: str = "auto"                # "auto" picks the best installed model
    fallback_models: List[str] = field(default_factory=lambda: [
        "llama3.1:8b", "llama3:8b", "qwen2.5:7b", "qwen2.5:3b", "mistral:7b",
        "phi3:mini", "gemma2:9b", "deepseek-r1:8b", "llama3.2:3b",
    ])
    temperature: float = 0.15
    num_ctx: int = 8192
    max_tokens: int = 700
    timeout: float = 120.0
    keep_alive: str = "10m"
    think_interval: float = 45.0       # seconds between autonomous re-plans
    min_interval: float = 12.0         # hard floor, protects weak CPUs
    enable_autothink: bool = True
    enable_chat: bool = True
    allow_remote_host: bool = False    # refuse non-loopback unless explicitly allowed
    json_mode: bool = True
    stream: bool = True

    def base(self) -> str:
        return self.host.rstrip("/")


@dataclass
class Config:
    # -- engagement ---------------------------------------------------------
    interface: str = ""
    monitor_interface: str = ""
    authorized: bool = False           # operator attestation; active attacks need it
    demo: bool = False                 # simulation mode, no radio required
    stealth: bool = False              # passive-first, minimal transmission
    aggressive: bool = True            # deauth clients to force handshakes
    channel_hop: bool = True
    channels: List[int] = field(default_factory=list)   # empty = auto
    band: str = "both"                 # 2.4GHz | 5GHz | both
    scan_time: float = 30.0            # seconds of discovery before selecting
    scan_rounds: int = 0               # 0 = until scan_time elapses
    max_targets: int = 0               # 0 = unlimited

    # -- per-attack budgets (seconds) --------------------------------------
    handshake_timeout: float = 90.0
    pmkid_timeout: float = 60.0
    wps_timeout: float = 300.0
    wep_timeout: float = 300.0
    attack_timeout: float = 0.0        # 0 = derive from the per-attack values
    deauth_count: int = 5
    deauth_interval: float = 5.0       # seconds between deauth bursts
    deauth_burst: int = 3

    # -- attack enable/disable (wifite-compatible spirit) ------------------
    #: wps_pin is deliberately NOT here: online PIN brute force is opt-in
    #: (CLI: --wps-pin / --attacks wps_pin, UI: attack toggles)
    attacks: List[str] = field(default_factory=lambda: [
        "pmkid", "handshake", "wps_pixie", "wep_ivs",
    ])
    skip_crack: bool = False
    crack_timeout: float = 600.0
    cracker: str = "auto"              # auto | aircrack | hashcat
    wordlists: List[str] = field(default_factory=list)
    rules: str = "best64"
    use_rules: bool = True
    use_masks: bool = True
    hashcat_mode: int = 22000
    hashcat_workload: int = 3
    hashcat_devices: str = ""
    custom_pmkid_only: bool = False

    # -- environment --------------------------------------------------------
    kill_interfering: bool = True
    restore_interface: bool = True
    mac_rotate: bool = False           # per-attack client MAC rotation
    randomize_mac: bool = False        # randomise the monitor interface MAC
    ignore_known: bool = False
    check_handshakes: bool = True      # verify with aircrack-ng/pycryptodomex
    save_session: bool = True
    output_dir: str = "loot"
    session_dir: str = "sessions"
    log_level: str = "info"
    iface_ready_timeout: float = 20.0
    verbose_tools: bool = False        # echo external tool output to the console

    # -- web ---------------------------------------------------------------
    web_host: str = "0.0.0.0"
    web_port: int = 8787
    web_open_browser: bool = False

    # -- ai -----------------------------------------------------------------
    ollama: OllamaConfig = field(default_factory=OllamaConfig)

    # ------------------------------------------------------------------ #
    def attack_timeout_for(self, attack: str) -> float:
        if self.attack_timeout > 0:
            return self.attack_timeout
        return {
            "handshake": self.handshake_timeout,
            "pmkid": self.pmkid_timeout,
            "wps_pixie": self.wps_timeout,
            "wps_pin": max(self.wps_timeout, 600.0),
            "wep_ivs": self.wep_timeout,
            "passive": self.scan_time,
        }.get(attack, self.attack_timeout or 60.0)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        ollama_data = data.pop("ollama", None) or {}
        known = {f.name for f in fields(cls)}
        clean = {k: v for k, v in data.items() if k in known}
        cfg = cls(**clean)
        ollama_known = {f.name for f in fields(OllamaConfig)}
        for key, value in ollama_data.items():
            if key in ollama_known:
                setattr(cfg.ollama, key, value)
        return cfg

    def update(self, **values: Any) -> "Config":
        for key, value in values.items():
            if value is None:
                continue
            if key == "ollama" and isinstance(value, dict):
                for k2, v2 in value.items():
                    if hasattr(self.ollama, k2):
                        setattr(self.ollama, k2, v2)
            elif hasattr(self, key):
                setattr(self, key, value)
        return self

    def save(self, path: Optional[str] = None) -> str:
        target = Path(path or CONFIG_NAME)
        write_json(target, self.to_dict())
        return str(target)

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Config":
        path = path or os.environ.get(CONFIG_ENV) or CONFIG_NAME
        candidate = Path(path)
        if not candidate.exists():
            for fallback in (Path.cwd() / CONFIG_NAME, Path.home() / ".config" / "wifipilot" / CONFIG_NAME):
                if fallback.exists():
                    candidate = fallback
                    break
        data = read_json(candidate, None)
        if not isinstance(data, dict):
            return cls()
        return cls.from_dict(data)


# --------------------------------------------------------------------------- #
# wordlists
# --------------------------------------------------------------------------- #


def find_wordlists(config: Optional[Config] = None) -> List[Dict[str, Any]]:
    """All wordlists we could crack with, best first."""
    found: List[Dict[str, Any]] = []
    seen = set()
    builtin_dir = Path(__file__).parent / "data"
    candidates: List[str] = []
    if config and config.wordlists:
        candidates.extend(config.wordlists)
    candidates.extend(WORDLIST_CANDIDATES)
    candidates.extend(str(builtin_dir / name) for name in BUILTIN_WORDLISTS)
    for path in candidates:
        expanded = os.path.expanduser(str(path))
        if expanded in seen:
            continue
        seen.add(expanded)
        if not os.path.exists(expanded):
            continue
        try:
            size = os.path.getsize(expanded)
        except OSError:
            continue
        found.append({
            "path": expanded,
            "name": Path(expanded).name,
            "size": size,
            "builtin": str(builtin_dir) in expanded,
            "compressed": expanded.endswith(".gz"),
        })
    return found


def default_wordlist(config: Optional[Config] = None) -> str:
    for item in find_wordlists(config):
        if not item["builtin"]:
            return item["path"]
    lists = find_wordlists(config)
    return lists[0]["path"] if lists else ""


def expand_paths(path: str) -> str:
    return os.path.abspath(os.path.expanduser(str(path)))


def ensure_dirs(config: Config) -> Dict[str, str]:
    dirs = {
        "output": expand_paths(config.output_dir),
        "sessions": expand_paths(config.session_dir),
    }
    for path in dirs.values():
        Path(path).mkdir(parents=True, exist_ok=True)
    return dirs
