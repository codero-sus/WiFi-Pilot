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
class OpenRouterConfig:
    """OpenRouter settings — a *cloud* provider, so everything here is opt-in.

    wifipilot only talks to OpenRouter when ``enabled`` is true *and* a key is
    present.  Engagement identifiers (SSIDs, BSSIDs, client MACs) are replaced
    with stable pseudonyms before the situation report is sent unless
    ``redact_identifiers`` is switched off; the advisor maps the pseudonyms back
    before validating the plan, so the model never sees the real network names
    while wifipilot still knows what it was told to attack.
    """

    enabled: bool = False              # explicit consent to send data off-box
    api_key: str = ""                  # prefer the environment or a key file
    api_key_env: str = "OPENROUTER_API_KEY"
    key_file: str = ""                 # e.g. ~/.config/wifipilot/openrouter.key
    base_url: str = "https://openrouter.ai/api/v1"
    model: str = "auto"                # "auto" picks from fallback_models
    fallback_models: List[str] = field(default_factory=lambda: [
        "openai/gpt-4o-mini", "google/gemini-2.5-flash", "anthropic/claude-3.5-haiku",
        "meta-llama/llama-3.3-70b-instruct", "qwen/qwen-2.5-72b-instruct",
        "deepseek/deepseek-chat", "openrouter/auto",
    ])
    temperature: float = 0.15
    max_tokens: int = 900
    timeout: float = 120.0
    think_interval: float = 45.0
    min_interval: float = 12.0
    enable_autothink: bool = True
    enable_chat: bool = True
    json_mode: bool = True             # response_format={"type":"json_object"}
    stream: bool = True                # SSE streaming (token-by-token in the UI)
    redact_identifiers: bool = True    # pseudonymise SSID/BSSID/MAC before sending
    provider_routing: Dict[str, Any] = field(default_factory=dict)   # e.g. {"sort": "throughput"}
    site_url: str = ""                 # HTTP-Referer attribution
    app_title: str = "wifipilot"
    allow_insecure_base_url: bool = False   # http:// base URLs (local proxies only)
    max_cost_usd: float = 0.0          # 0 = no cap; else stop planning when exceeded

    def base(self) -> str:
        return self.base_url.rstrip("/")

    def key_file_value(self) -> str:
        if not self.key_file:
            return ""
        try:
            path = Path(os.path.expanduser(self.key_file))
            if path.exists():
                return path.read_text(encoding="utf-8").strip()
        except OSError:
            return ""
        return ""

    def api_key_value(self) -> str:
        """Environment first, then key file, then the literal config value."""
        env = os.environ.get(self.api_key_env or "OPENROUTER_API_KEY", "").strip()
        if env:
            return env
        return self.key_file_value() or (self.api_key or "").strip()

    def key_source(self) -> str:
        if os.environ.get(self.api_key_env or "OPENROUTER_API_KEY", "").strip():
            return f"environment ({self.api_key_env})"
        if self.key_file_value():
            return f"key file ({self.key_file})"
        if (self.api_key or "").strip():
            return "config file"
        return "not configured"

    def key_hint(self) -> str:
        """Safe to display *and* to serve to a browser: length and source, no material."""
        key = self.api_key_value()
        if not key:
            return ""
        return f"set ({len(key)} chars, {self.key_source()})"

    def ai_enabled(self) -> bool:
        """True when *any* usable provider is configured (no network probe)."""
        provider, _ = self.active_provider(probe=False)
        return provider != "none"

    def think_interval_seconds(self) -> float:
        """Autonomous re-plan interval of the active provider (0 = never)."""
        cfg = self.llm_config()
        if cfg is None:
            return 0.0
        return float(getattr(cfg, "think_interval", 45.0) or 0.0)

    def autothink_enabled(self) -> bool:
        return bool(self.enabled and self.enable_autothink)

    def think_interval_for(self) -> float:
        return max(self.min_interval, self.think_interval)


@dataclass
class Config:
    # -- engagement ---------------------------------------------------------
    interface: str = ""
    monitor_interface: str = ""
    authorized: bool = False           # operator attestation; active attacks need it
    authorization_note: str = ""       # who/what authorised it (ticket, client, date)
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
    #: auto | ollama | openrouter | none  ("auto" prefers the local model)
    ai_provider: str = "auto"
    ollama: OllamaConfig = field(default_factory=OllamaConfig)
    openrouter: OpenRouterConfig = field(default_factory=OpenRouterConfig)

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

    # -- ai providers -------------------------------------------------- #
    def llm_config(self, provider: str = "") -> Any:
        """The provider-specific config dataclass for ``provider`` (or the active one)."""
        name = (provider or self.ai_provider or "auto").strip().lower()
        if name == "openrouter":
            return self.openrouter
        if name == "ollama":
            return self.ollama
        if name in ("none", "off", "disabled"):
            return self.ollama          # inert: nothing is called while AI is off
        # auto: the provider that would actually be used
        return self.ollama if self.ollama.enabled else (
            self.openrouter if self.openrouter.enabled else self.ollama)

    def ai_enabled(self) -> bool:
        """True when *any* usable provider is configured (no network probe)."""
        provider, _ = self.active_provider(probe=False)
        return provider != "none"

    def think_interval_seconds(self) -> float:
        """Autonomous re-plan interval of the active provider (0 = never)."""
        cfg = self.llm_config()
        if cfg is None:
            return 0.0
        return float(getattr(cfg, "think_interval", 45.0) or 0.0)

    def autothink_enabled(self) -> bool:
        """True when the *active* provider wants autonomous re-planning."""
        name, _ = self.active_provider(probe=False)
        if name == "openrouter":
            return self.openrouter.autothink_enabled()
        if name == "ollama":
            return bool(self.ollama.enabled and self.ollama.enable_autothink)
        return False

    def active_provider(self, probe: bool = False) -> tuple:
        """(provider, reason) — see :func:`wifipilot.llm.select_provider`."""
        from .llm import select_provider
        return select_provider(self.ai_provider, self.ollama, self.openrouter, probe=probe)

    def to_dict(self, redact_secrets: bool = False) -> Dict[str, Any]:
        data = asdict(self)
        if redact_secrets:
            secret = bool(data["openrouter"].get("api_key"))
            data["openrouter"]["api_key"] = ""
            data["openrouter"]["has_api_key"] = secret or bool(self.openrouter.api_key_value())
            data["openrouter"]["key_source"] = self.openrouter.key_source()
            data["openrouter"]["key_hint"] = self.openrouter.key_hint()
        data["ai_provider_resolved"] = self.active_provider(probe=False)[0]
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        data = dict(data)
        ollama_data = data.pop("ollama", None) or {}
        openrouter_data = data.pop("openrouter", None) or {}
        # pseudo-keys returned by to_dict(redact_secrets=True) are not config fields
        for key in ("ai_provider_resolved",):
            data.pop(key, None)
        known = {f.name for f in fields(cls)}
        clean = {k: v for k, v in data.items() if k in known}
        cfg = cls(**clean)
        ollama_known = {f.name for f in fields(OllamaConfig)}
        for key, value in ollama_data.items():
            if key in ollama_known:
                setattr(cfg.ollama, key, value)
        openrouter_known = {f.name for f in fields(OpenRouterConfig)}
        for key, value in openrouter_data.items():
            if key in openrouter_known:
                setattr(cfg.openrouter, key, value)
        return cfg

    def update(self, **values: Any) -> "Config":
        for key, value in values.items():
            if value is None:
                continue
            if key == "ollama" and isinstance(value, dict):
                for k2, v2 in value.items():
                    if hasattr(self.ollama, k2):
                        setattr(self.ollama, k2, v2)
            elif key == "openrouter" and isinstance(value, dict):
                for k2, v2 in value.items():
                    if hasattr(self.openrouter, k2):
                        setattr(self.openrouter, k2, v2)
            elif hasattr(self, key):
                setattr(self, key, value)
        return self

    def save(self, path: Optional[str] = None) -> str:
        target = Path(path or CONFIG_NAME)
        write_json(target, self.to_dict())
        try:
            # the file can contain an API key: keep it out of other users' reach
            target.chmod(0o600)
        except OSError:
            pass
        return str(target)

    def provider_note(self) -> str:
        """One line for banners/logs: which model brain is in use and where it runs."""
        provider, reason = self.active_provider(probe=False)
        if provider == "openrouter":
            return (f"AI: OpenRouter cloud ({self.openrouter.model}) — engagement data "
                    f"leaves this machine; {'identifiers pseudonymised' if self.openrouter.redact_identifiers else 'identifier redaction OFF'}")
        if provider == "ollama":
            return f"AI: local Ollama ({self.ollama.model}) at {self.ollama.host}"
        return f"AI: disabled ({reason})"

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
