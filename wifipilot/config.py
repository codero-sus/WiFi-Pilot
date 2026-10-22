# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Configuration: defaults, file loading, CLI merging and wordlist discovery."""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, Dict, List, Optional

from .util import read_json, write_json


_FIELD_NAMES: Dict[type, tuple] = {}


def _field_names(cls: type) -> tuple:
    names = _FIELD_NAMES.get(cls)
    if names is None:
        names = tuple(f.name for f in fields(cls))
        _FIELD_NAMES[cls] = names
    return names


def _shallow_dc(obj: Any) -> Dict[str, Any]:
    """``asdict`` without the deepcopy, for flat scalar/list/dict configs."""
    out: Dict[str, Any] = {}
    for name in _field_names(type(obj)):
        value = getattr(obj, name)
        if isinstance(value, list):
            out[name] = list(value)
        elif isinstance(value, dict):
            out[name] = dict(value)
        elif isinstance(value, tuple):
            out[name] = tuple(value)
        else:
            out[name] = value
    return out

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
class CortexConfig:
    """Cortex LLMHoster settings — a *local* model host, on this machine.

    `Cortex LLMHoster <https://github.com/codero-sus/Cortex_LLMHoster>`_ runs GGUF models
    behind an OpenAI-compatible API (``/v1/chat/completions``, ``/v1/models``) and starts
    them itself, which is the piece Ollama does not give you: ``llama.cpp`` flags, a
    starting model, and a dashboard.  Because it is local, nothing needs to leave the
    machine for the advisor to work — but the listener is a *local service*, so this
    client refuses any host that is not loopback unless the operator says otherwise.
    """

    enabled: bool = False              # opt-in: wifipilot does not probe services it was
                                       # not told about, not even on localhost
    host: str = "http://127.0.0.1:8624"
    model: str = ""                    # "" = the hoster's default model
    api_key: str = ""                  # usually CORTEX_API_KEY in the environment
    api_key_env: str = "CORTEX_API_KEY"
    fallback_models: List[str] = field(default_factory=lambda: [
        "qwen-local", "llama3-local", "mistral-local",
    ])
    temperature: float = 0.15
    max_tokens: int = 700
    timeout: float = 300.0             # a local model loading a GGUF can take a while
    json_mode: bool = False            # llama.cpp grammars are per-model; opt in per host
    stream: bool = True
    allow_remote_host: bool = False    # refuse a non-loopback host unless explicitly set

    def base(self) -> str:
        return self.host.rstrip("/")

    def api_key_value(self) -> str:
        """The environment first, then the literal config value.

        Cortex can run keyless (``CORTEX_API_AUTH_ENABLED=false`` on a trusted listener),
        so an empty key is not an error here — it is the keyless mode.
        """
        return (os.environ.get(self.api_key_env or "CORTEX_API_KEY", "") or "").strip() \
            or (self.api_key or "").strip()

    def key_hint(self) -> str:
        key = self.api_key_value()
        if not key:
            return "none (keyless local listener)"
        source = "environment (CORTEX_API_KEY)" if os.environ.get(
            self.api_key_env or "CORTEX_API_KEY") else "config file"
        return f"set ({len(key)} chars, {source})"


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

    # -- presets and speed -------------------------------------------------- #
    #: named preset controlling the attack set, budgets and campaign length
    #: (see ``wifipilot.presets``); empty = the engine default behaviour
    preset: str = ""
    #: how a run should behave: "" (preset default), "force" (loud, success at
    #: any cost — the opposite of stealth) or "stealth" (quiet, no injection)
    posture: str = ""
    #: every per-attack budget is multiplied by this (0.5 = twice as fast)
    budget_scale: float = 1.0
    #: hard cap in seconds for any single attack, enforced by a watchdog; 0 = none
    attack_cap: float = 0.0
    #: how many non-radio attacks (IT / offline analysis) may run side by side
    #: while the one adapter works; 0 = auto (one lane per CPU, cap 8),
    #: 1 = the classic strictly serial behaviour
    jobs: int = 0
    #: crack freshly captured loot on a side thread instead of blocking the
    #: attack that captured it
    parallel_crack: bool = True
    #: hardware acceleration: "auto" (default — multiprocessing CPU + RAM
    #: caches, GPU via hashcat when one is detected), "cpu", "ram", "gpu",
    #: "all", or "off" for the classic single-threaded run (see
    #: ``wifipilot.accel``)
    accel: str = "auto"
    #: crack worker processes when CPU acceleration is on; 0 = auto
    accel_workers: int = 0
    #: MB of RAM acceleration may spend on candidate caches; 0 = auto
    accel_ram_mb: int = 0

    # -- attack enable/disable (wifite-compatible spirit) ------------------
    #: wps_pin is deliberately NOT here: online PIN brute force is opt-in
    #: (CLI: --wps-pin / --attacks wps_pin, UI: attack toggles)
    #: hidden_ssid is here because it only listens (a hidden network is not a
    #: target until it has a name); rogue_ap and enterprise are situational and
    #: stay opt-in.
    attacks: List[str] = field(default_factory=lambda: [
        "pmkid", "handshake", "wps_pixie", "wep_ivs", "hidden_ssid", "tracker",
    ])
    #: follow one station only (``tracker``; empty means "pick the best one")
    client_mac: str = ""
    #: handshake capture with a *broadcast* deauth (``handshake_broadcast``): the
    #: single-client burst is the default because it is quieter, and dropping every
    #: client on the channel at once is a different act from deauthing one station
    broadcast_handshake: bool = False
    #: an address to ask about (gateway management page, DNS, SNMP): empty means guess
    gateway_ip: str = ""
    #: the RADIUS server to test shared secrets against (radius_secret_test)
    radius_server: str = ""
    radius_ports: tuple = (1812, 1645)
    #: the lease pool a rogue DHCP server hands out, and the address it advertises
    rogue_network: str = "192.168.213.0/24"
    dns_sink_ip: str = ""
    dns_port: int = 53
    #: the port the captive portal binds
    portal_port: int = 80
    #: the network's DNS domain, for the WPAD audit
    domain: str = ""
    #: the Bluetooth address a live Bluetooth attack targets (pairing, SDP, RFCOMM)
    # -- the IT edition ----------------------------------------------------- #
    #: which edition a run plans in: "wifi", "bluetooth", "it" or "all".  The catalogue
    #: is one list; the edition decides which of it the planner and the UI offer.
    edition: str = "all"
    #: the host an IT attack talks to when the operator has named one (a camera, a
    #: printer, a PLC).  Empty means: use the target AP's address, or the gateway.
    it_host: str = ""
    #: the port an IT attack should use, when it is not the protocol's own default
    it_port: int = 0
    #: the device type the operator picked in the web UI (its label is used in reports)
    it_device: str = ""
    bt_target: str = ""
    #: how long a Bluetooth command may wait for its controller event
    bt_timeout: float = 2.0
    #: the ACL handle the Bluetooth link-layer probes are aimed at.  A controller hands
    #: one out in the Connection Complete event; naming it here lets an operator aim the
    #: probes at a link that a tool has already opened (``bt_handle``).
    bt_handle: int = 0
    #: the line the HID-injection attacks type once a host accepts the keyboard.  The
    #: default proves the injection and changes nothing, and it ends in a newline because
    #: the newline *is* the Enter key: a payload that is never submitted has typed
    #: nothing.  An engagement sets its own.
    hid_payload: str = "id\n"
    #: the gateway's MAC on the assessed network, for the FragAttacks injection: the
    #: packet claims to come from it.  Empty means "use the access point's own address".
    gateway_mac: str = ""
    #: the interface the evil twin binds to; empty means "the monitor interface"
    twin_interface: str = ""
    #: ask the AP for the name of a hidden network with a directed probe (the
    #: only part of hidden-SSID discovery that transmits)
    reveal_with_probe: bool = False
    #: where recovered PMKs are cached, so a second capture on the same network
    #: costs nothing to "crack" again (mode 22001)
    pmk_cache: bool = True
    pmk_cache_path: str = ""
    skip_crack: bool = False
    crack_timeout: float = 600.0
    cracker: str = "auto"              # auto | aircrack | hashcat
    wordlists: List[str] = field(default_factory=list)
    rules: str = "best64"
    use_rules: bool = True
    #: a hashcat ``.rule`` file (or the name of a built-in set) that the
    #: *built-in* engine applies too, so a machine without hashcat can still use
    #: ``best64.rule``/``rockyou-30000.rule``
    rule_file: str = ""
    #: one name instead of six flags: quick | default | thorough | insane |
    #: mask-only | wordlist-only | pixie-then-crack
    crack_strategy: str = ""
    #: which stages run, and in which order (only these four tokens)
    crack_order: str = "targeted,masks,hashcat-masks,external,builtin"
    #: cap on how many configured wordlists a run uses (0 = all)
    wordlist_limit: int = 0
    use_masks: bool = True
    #: operator-supplied masks (``--mask 'Telekom-?d?d?d?d'``); empty means
    #: "use the patterns derived from the target itself"
    mask_patterns: List[str] = field(default_factory=list)
    #: what the *built-in* engine may spend on the mask stage (~25 s at its
    #: ~400 candidates/s).  A mask bigger than this is left to hashcat rather
    #: than half-swept in Python.
    mask_candidates: int = 10000
    #: how many target-derived candidates the built-in engine tries first
    targeted_candidates: int = 3000
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
    cortex: CortexConfig = field(default_factory=CortexConfig)
    openrouter: OpenRouterConfig = field(default_factory=OpenRouterConfig)

    # ------------------------------------------------------------------ #
    def attack_timeout_for(self, attack: str) -> float:
        """Seconds this attack may run (before budget_scale/attack_cap).

        Cached per (attack, timeout fields): the table below has ~200
        entries and every attack asks for its budget, some per loop
        iteration — rebuilding the dict each time was measurable waste.
        The cache lives outside the dataclass fields, so it never
        serialises; changing any timeout field simply misses once.
        """
        key = (attack, self.attack_timeout, self.handshake_timeout,
               self.pmkid_timeout, self.wps_timeout, self.wep_timeout,
               self.bt_timeout, self.crack_timeout, self.scan_time)
        cache = self.__dict__.setdefault("_timeout_cache", {})
        if key in cache:
            return cache[key]
        value = self._attack_timeout_for(attack)
        if len(cache) > 4096:
            cache.clear()
        cache[key] = value
        return value

    def _attack_timeout_for(self, attack: str) -> float:
        if self.attack_timeout > 0:
            return self.attack_timeout
        budget = {
            "handshake": self.handshake_timeout,
            "pmkid": self.pmkid_timeout,
            "wps_pixie": self.wps_timeout,
            "wps_pin": max(self.wps_timeout, 600.0),
            "wep_ivs": self.wep_timeout,
            # the three surveys: hidden-SSID discovery waits for a client to say the
            # name, the 802.1X survey waits for one to authenticate, and the rogue
            # survey only reads what is already on disk
            "hidden_ssid": max(self.scan_time, 20.0),
            "enterprise": max(self.scan_time, 30.0),
            "rogue_ap": max(self.scan_time, 15.0),
            # a rogue RADIUS is a conversation with a client, not a capture window
            "rogue_radius": max(self.scan_time * 4, 120.0),
            # following a device that walks away needs more than a scan window
            "tracker": max(self.scan_time * 2, 45.0),
            # WPA3/SAE needs a client to authenticate; the audit only reads beacons
            "saewolf": max(self.scan_time * 2, 60.0),
            "pmf_audit": max(self.scan_time, 15.0),
            # an active PMKID hunt is bounded by the same window as the passive one
            "pmkid_flood": self.pmkid_timeout,
            # rogue infrastructure: bounded on purpose (these are disruptive)
            "evil_twin": max(self.scan_time * 4, 180.0),
            "deauth_flood": max(self.scan_time, 30.0),
            "auth_flood": max(self.scan_time, 30.0),
            "probe_flood": max(self.scan_time, 30.0),
            "beacon_flood": max(self.scan_time, 30.0),
            # the read-only element/probe audits finish as fast as the capture reads
            "ie_audit": max(self.scan_time, 15.0),
            "pnl_harvest": max(self.scan_time, 15.0),
            # a Logoff burst is three frames per client: it needs no window at all
            "eapol_logoff": max(self.scan_time, 10.0),
            # Karma is a conversation with whatever is probing around
            "karma": max(self.scan_time * 4, 180.0),
            # WEP injection techniques: enough time to hold a packet exchange
            "wep_chopchop": self.wep_timeout,
            "wep_fragment": self.wep_timeout,
            "wep_hirte": self.wep_timeout,
            "wep_p0841": self.wep_timeout,
            "passive": self.scan_time,
            # -- offline analysis: file work, so the budget is about the file ----
            "loot_audit": max(self.scan_time, 60.0),
            "eapol_audit": max(self.scan_time, 30.0),
            "wep_audit": max(self.scan_time, 30.0),
            "pixie_offline": max(self.scan_time, 60.0),
            "eap_md5_crack": max(self.scan_time, 120.0),
            "rogue_detect": max(self.scan_time, 45.0),
            "twin_detect": max(self.scan_time, 45.0),
            "roam_audit": max(self.scan_time, 30.0),
            "wps_lockout_audit": max(self.scan_time, 20.0),
            # a sweep is the one offline attack whose budget is the cracker's own
            "crack_sweep": max(self.crack_timeout, 120.0),
            # -- capture ----------------------------------------------------------
            # the broadcast handshake is the blunt variant: same window as handshake
            "handshake_broadcast": self.handshake_timeout,
            "hcxdump_capture": max(self.pmkid_timeout, 120.0),
            # -- surveys and lures ------------------------------------------------
            "sae_group_audit": max(self.scan_time * 2, 45.0),
            "karma_detect": max(self.scan_time * 2, 30.0),
            "csa_attack": max(self.scan_time * 2, 30.0),
            "ssid_confusion": max(self.scan_time * 2, 30.0),
            "ssid_bruteforce": max(self.scan_time * 2, 30.0),
            "ap_isolation_audit": max(self.scan_time, 30.0),
            # -- WPS --------------------------------------------------------------
            "wps_ap_pin": max(self.wps_timeout, 90.0),
            "wps_lockout_probe": max(self.wps_timeout, 90.0),
            "wps_pbc": max(self.wps_timeout, 60.0),
            # -- the in-process floods: capped short by the classes themselves ----
            "assoc_flood": max(self.scan_time, 30.0),
            "null_data_flood": max(self.scan_time, 30.0),
            "eapol_start_flood": max(self.scan_time, 30.0),
            "sae_commit_flood": max(self.scan_time, 30.0),
            "tkip_michael": max(self.scan_time, 10.0),
            "wids_confusion": max(self.scan_time, 25.0),
            # -- second wave: analysis and protocol work ---------------------------
            # offline analysts read files: the budget is the file, not the radio
            "capture_quality": max(self.scan_time, 20.0),
            "hash_audit": max(self.scan_time, 30.0),
            "wordlist_audit": max(self.scan_time, 60.0),
            "wordlist_mine": max(self.scan_time, 30.0),
            "crack_plan": max(self.scan_time, 45.0),
            "vendor_fingerprint": max(self.scan_time, 20.0),
            "beacon_timeline": max(self.scan_time, 20.0),
            "cleartext_sniff": max(self.scan_time, 45.0),
            "pmk_check": max(self.scan_time, 45.0),
            "loot_manifest": max(self.scan_time, 30.0),
            "krack_detect": max(self.scan_time, 30.0),
            "kr00k_detect": max(self.scan_time, 30.0),
            "fragattacks_detect": max(self.scan_time, 30.0),
            "ft_audit": max(self.scan_time, 20.0),
            "beacon_rate_audit": max(self.scan_time, 20.0),
            "tsf_clone_detect": max(self.scan_time, 20.0),
            "client_fingerprint": max(self.scan_time, 45.0),
            # 802.1X work that reads a capture finishes when the capture does
            "eap_identity_harvest": max(self.scan_time, 30.0),
            "certificate_audit": max(self.scan_time, 30.0),
            "ttls_inner_audit": max(self.scan_time, 30.0),
            "eap_tls_version": max(self.scan_time, 30.0),
            "mschapv2_crack": max(self.crack_timeout, 120.0),
            # ...and the two that talk to a real server need a network budget
            "eap_method_probe": max(self.scan_time * 2, 60.0),
            "radius_secret_test": max(self.scan_time * 2, 60.0),
            # capture and injection helpers: bounded by the technique they enable
            "injection_test": max(self.scan_time, 30.0),
            "arp_replay": max(self.wep_timeout, 60.0),
            "pcap_replay": max(self.scan_time * 2, 45.0),
            "mac_filter_probe": max(self.scan_time, 30.0),
            "channel_sweep": max(self.scan_time * 2, 60.0),
            # network-layer audits: one host, a handful of ports, so a short window
            "ap_admin_audit": max(self.scan_time, 45.0),
            "upnp_audit": max(self.scan_time, 30.0),
            "snmp_audit": max(self.scan_time, 30.0),
            "dns_audit": max(self.scan_time, 20.0),
            "wpad_audit": max(self.scan_time, 20.0),
            "rogue_dhcp_detect": max(self.scan_time, 30.0),
            "arp_spoof_detect": max(self.scan_time, 30.0),
            "ipv6_ra_audit": max(self.scan_time, 30.0),
            # rogue services: they serve clients, so they get a service-sized budget
            "rogue_dhcp": max(self.scan_time * 3, 90.0),
            "dns_sink": max(self.scan_time * 3, 90.0),
            "captive_portal": max(self.scan_time * 3, 90.0),
            "arp_mitm": max(self.scan_time * 2, 60.0),
            "beacon_clone": max(self.scan_time * 3, 90.0),
            "wpa3_downgrade_twin": max(self.scan_time * 4, 180.0),
            # frames that reconfigure a client: one exchange, then observe
            "pmf_downgrade_probe": max(self.scan_time * 2, 60.0),
            "btm_hijack": max(self.scan_time * 2, 60.0),
            # the new floods are capped by their own class attributes as well
            "disassoc_flood": max(self.scan_time, 30.0),
            "rts_flood": max(self.scan_time, 20.0),
            "cts_flood": max(self.scan_time, 20.0),
            "channel_switch_flood": max(self.scan_time, 30.0),
            "sa_query_flood": max(self.scan_time, 20.0),
            "tdls_teardown_flood": max(self.scan_time, 20.0),
            "probe_response_flood": max(self.scan_time, 30.0),
            "dhcp_discover_flood": max(self.scan_time, 20.0),
            # -- the Bluetooth wave ------------------------------------------------
            # Bluetooth work is bounded by its own radio window, not by the Wi-Fi scan
            "bt_le_scan": max(self.bt_timeout * 2, 15.0),
            "bt_hci_inquiry": max(self.bt_timeout * 4, 20.0),
            "bt_sdp_browse": max(self.bt_timeout * 4, 20.0),
            "bt_gatt_enumeration": max(self.bt_timeout * 4, 20.0),
            "bt_rfcomm_scan": max(self.bt_timeout * 4, 20.0),
            # advertising work is a bounded burst by design
            "bt_adv_name_flood": max(self.bt_timeout * 2, 15.0),
            "bt_adv_dos": max(self.bt_timeout * 2, 15.0),
            "bt_beacon_clone": max(self.bt_timeout * 2, 15.0),
            "bt_tracker_clone": max(self.bt_timeout * 2, 15.0),
            "bt_connectable_lure": max(self.bt_timeout * 4, 30.0),
            "bt_pairing_flood": max(self.bt_timeout * 2, 15.0),
            "bt_l2cap_echo_flood": max(self.bt_timeout * 2, 15.0),
            # the famous wave: a probe battery needs an event round-trip per probe, and
            # the serial-profile attacks need a socket to open and an OBEX session to run
            "bt_blueborne": max(self.bt_timeout * 8, 30.0),
            "bt_bias": max(self.bt_timeout * 6, 25.0),
            "bt_knob": max(self.bt_timeout * 5, 20.0),
            "bt_bluebugging": max(self.bt_timeout * 10, 45.0),
            "bt_blesa": max(self.bt_timeout * 5, 25.0),
            "bt_sweyntooth": max(self.bt_timeout * 8, 30.0),
            "bt_bluesnarf": max(self.bt_timeout * 12, 60.0),
            "bt_bluesmack": max(self.bt_timeout * 5, 25.0),
            "bt_hid_injection": max(self.bt_timeout * 6, 25.0),
            # -- the network wave: every flood is capped by its own class as well ---
            "krack_replay": max(self.scan_time, 30.0),
            "fragattacks_inject": max(self.scan_time, 30.0),
            "airgeddon_portal": max(self.scan_time * 3, 90.0),
            "dhcp_starvation": max(self.scan_time, 45.0),
            "dhcp_flood": max(self.scan_time, 30.0),
            "forged_dhcp_release": max(self.scan_time, 30.0),
            "dhcp_nak_injection": max(self.scan_time, 30.0),
            "dhcp_option_injection": max(self.scan_time * 3, 90.0),
            "syn_flood": max(self.scan_time, 30.0),
            "udp_flood": max(self.scan_time, 30.0),
            "tcp_reset_injection": max(self.scan_time, 30.0),
            "udp_reflection": max(self.scan_time, 30.0),
            "icmp_redirect_injection": max(self.scan_time, 30.0),
            "icmp_unreachable_injection": max(self.scan_time, 30.0),
            "rogue_ra": max(self.scan_time * 4, 120.0),
            "ra_flood": max(self.scan_time, 30.0),
            "ns_na_spoof": max(self.scan_time * 2, 60.0),
            "llmnr_poisoning": max(self.scan_time * 2, 60.0),
            "nbns_poisoning": max(self.scan_time * 2, 60.0),
            "mdns_poisoning": max(self.scan_time * 2, 60.0),
            "stp_root_takeover": max(self.scan_time * 2, 45.0),
            "lldp_spoof": max(self.scan_time * 2, 45.0),
            "cdp_spoof": max(self.scan_time * 2, 45.0),
            "vlan_double_tag_hop": max(self.scan_time, 30.0),
            "mqtt_recon": max(self.scan_time, 45.0),
            "rtsp_camera_audit": max(self.scan_time, 45.0),
            "pjl_printer_audit": max(self.scan_time, 45.0),
        }.get(attack)
        if budget:
            return budget
        # An attack added in a batch and not named above still needs a budget, and the
        # right one follows from what the attack *is*: a file read is bounded by the
        # file, an active test by the scan window, a flood by its own cap.
        try:
            from .attacks.meta import ATTACK_META
        except Exception:                                       # pragma: no cover
            ATTACK_META = {}
        meta = ATTACK_META.get(attack) or {}
        category = meta.get("category")
        if category == "offline":
            return max(self.crack_timeout if meta.get("impact") == "loot"
                       else self.scan_time, 60.0)
        if category == "dos":
            return max(self.scan_time, 30.0)
        if category == "survey":
            return max(self.scan_time * 2, 45.0)
        if category in ("rogue", "enterprise"):
            return max(self.scan_time * 4, 120.0)
        return self.attack_timeout or max(self.scan_time, 60.0)

    # -- ai providers -------------------------------------------------- #
    def llm_config(self, provider: str = "") -> Any:
        """The provider-specific config dataclass for ``provider`` (or the active one)."""
        name = (provider or self.ai_provider or "auto").strip().lower()
        if name == "openrouter":
            return self.openrouter
        if name == "cortex":
            return self.cortex
        if name == "ollama":
            return self.ollama
        if name in ("none", "off", "disabled"):
            return self.ollama          # inert: nothing is called while AI is off
        # auto: the provider that would actually be used, in the order auto resolves
        if self.ollama.enabled:
            return self.ollama
        if getattr(self, "cortex", None) is not None and self.cortex.enabled:
            return self.cortex
        if self.openrouter.enabled:
            return self.openrouter
        return self.ollama

    def ai_off(self) -> bool:
        """True when the operator asked for no AI at all.

        Three ways to say it, all equivalent: ``ai_provider="none"``, ``--no-ai`` /
        ``--disable-ai`` (which set that field), or ``WIFIPILOT_NO_AI=1`` in the
        environment (useful for CI, and for anyone who never wants a model in the
        loop).  The switch is checked before anything is probed or called, so a
        disabled advisor never opens a socket.
        """
        if (self.ai_provider or "").strip().lower() in ("none", "off", "disabled"):
            return True
        return str(os.environ.get("WIFIPILOT_NO_AI", "")).strip().lower() in (
            "1", "true", "yes", "on")

    def ai_enabled(self) -> bool:
        """True when *any* usable provider is configured (no network probe)."""
        if self.ai_off():
            return False
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
        if self.ai_off():
            return "none", ("AI advisor disabled "
                            "(ai_provider=none, --no-ai/--disable-ai or WIFIPILOT_NO_AI)")
        return select_provider(self.ai_provider, self.ollama, self.openrouter, probe=probe,
                               cortex=self.cortex)

    def to_dict(self, redact_secrets: bool = False) -> Dict[str, Any]:
        # fast path: asdict() deep-copies the whole tree via deepcopy (~170µs
        # for this ~180-field config) — and to_dict runs on every web state
        # push.  A shallow field walk is ~15x cheaper and identical in shape:
        # scalars as-is, one copy per list/dict/tuple, and the same walk for
        # the three provider sub-configs.
        data: Dict[str, Any] = {}
        for name in _field_names(type(self)):
            value = getattr(self, name)
            if isinstance(value, (OllamaConfig, CortexConfig, OpenRouterConfig)):
                data[name] = _shallow_dc(value)
            elif isinstance(value, list):
                data[name] = list(value)
            elif isinstance(value, dict):
                data[name] = dict(value)
            elif isinstance(value, tuple):
                data[name] = tuple(value)
            else:
                data[name] = value
        if redact_secrets:
            secret = bool(data["openrouter"].get("api_key"))
            data["openrouter"]["api_key"] = ""
            data["openrouter"]["has_api_key"] = secret or bool(self.openrouter.api_key_value())
            data["openrouter"]["key_source"] = self.openrouter.key_source()
            data["openrouter"]["key_hint"] = self.openrouter.key_hint()
        data["ai_provider_resolved"] = self.active_provider(probe=False)[0]
        data["ai_disabled"] = self.ai_off()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        data = dict(data)
        ollama_data = data.pop("ollama", None) or {}
        cortex_data = data.pop("cortex", None) or {}
        openrouter_data = data.pop("openrouter", None) or {}
        # pseudo-keys returned by to_dict(redact_secrets=True) are not config fields
        for key in ("ai_provider_resolved", "ai_disabled"):
            data.pop(key, None)
        known = {f.name for f in fields(cls)}
        clean = {k: v for k, v in data.items() if k in known}
        cfg = cls(**clean)
        ollama_known = {f.name for f in fields(OllamaConfig)}
        for key, value in ollama_data.items():
            if key in ollama_known:
                setattr(cfg.ollama, key, value)
        cortex_known = {f.name for f in fields(CortexConfig)}
        for key, value in cortex_data.items():
            if key in cortex_known:
                setattr(cfg.cortex, key, value)
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
        # same precedence as load(): an explicit path, then WIFIPILOT_CONFIG, then ./
        target = Path(path or os.environ.get(CONFIG_ENV) or CONFIG_NAME)
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
