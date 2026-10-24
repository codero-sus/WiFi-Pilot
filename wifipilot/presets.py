# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
# Copyright (c) 2025-2026 codero-sus
"""Attack presets: named, time-boxed ways to run a campaign.

A preset is a *plan*: which attacks run, how long each may take, how long the
whole campaign gets, and how much parallelism the engine may use.  Every
preset exists so that one Wi-Fi network is finished in **minutes, not an
hour** — the defaults aim at the 7-12 minute window.

Every preset also has **postures**, because *which* attacks and *how loud*
are different questions:

``success``
    the plain preset, tuned as designed.
``success:force`` (or ``--force`` / ``force=True``)
    **FORCE** — the opposite of stealth.  Success matters, noise does not:
    stealth off, aggressive on, broadcast handshake deauth, more deauths,
    bigger crack candidate budgets, boosters like ``wps_pin`` added.
``success:stealth``
    the same plan with anything that transmits (injection, floods) removed
    and stealth on: listen, analyse, crack — never shout.

Use them anywhere: ``wifipilot attack --preset success --force``,
``wp.attack(target=all, preset="blitz:force")``, the web UI's preset picker,
or ``"preset": "rogue"`` in ``wifipilot.json``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

__all__ = [
    "Preset", "PRESETS", "POSTURES", "preset_names", "get_preset",
    "resolve_attacks", "apply_preset", "list_presets", "parse_preset",
]

#: postures every preset supports; "" means "as designed"
POSTURES = ("", "force", "stealth")

#: extra Wi-Fi boosters FORCE bolts onto any preset whose plan touches Wi-Fi
_FORCE_BOOSTERS = ("handshake_broadcast", "pmkid_flood", "wps_pin")


@dataclass(frozen=True)
class Preset:
    """One named plan.  ``attacks`` is an explicit best-first list; ``domains``
    / ``categories`` instead select whole slices of the catalogue."""

    name: str
    label: str
    description: str
    attacks: Tuple[str, ...] = ()
    domains: Tuple[str, ...] = ()
    categories: Tuple[str, ...] = ()
    #: per-attack budgets are multiplied by this
    budget_scale: float = 1.0
    #: hard per-attack cap in seconds (watchdog-enforced), 0 = none
    attack_cap: float = 0.0
    #: discovery seconds before the first attack
    scan_time: float = 30.0
    #: the whole-campaign budget the preset asks for ("" = operator decides)
    minutes: float = 10.0
    #: parallel non-radio attack lanes
    jobs: int = 4
    #: crack loot on a side thread while attacking continues
    parallel_crack: bool = True
    #: names a sibling preset this one is an alias of
    alias_of: str = ""


def _p(name: str, label: str, description: str, **kw: Any) -> Preset:
    return Preset(name=name, label=label, description=description, **kw)


#: the catalogue of plans.  Explicit attack lists are best-first; unknown
#: names are filtered at resolve time, so a renamed attack can never break
#: a preset — it just drops out.
PRESETS: Dict[str, Preset] = {p.name: p for p in [
    _p("success", "Success",
       "The highest-success-chance route to a key: PMKID and handshake "
       "capture first, WPS pixie-dust and offline PIN recovery, WEP IV "
       "recovery, then the audits that tell you why anything failed. "
       "This is the preset to pick when the goal is *getting in*.",
       attacks=(
           "pmkid", "handshake", "hcxdump_capture", "pmkid_flood",
           "handshake_broadcast", "wps_pixie", "pixie_offline",
           "wps_lockout_probe", "wps_ap_pin", "wep_ivs", "wep_p0841",
           "eapol_audit", "loot_audit", "ie_audit", "pmf_audit",
           "enterprise", "eap_md5_crack", "crack_sweep",
       ),
       budget_scale=0.6, attack_cap=60.0, scan_time=20.0, minutes=10.0),
    _p("blitz", "Blitz",
       "The fastest possible answer: the four classic key-recovery attacks "
       "with tight budgets, nothing else.  Minutes, not tens of minutes.",
       attacks=("pmkid", "handshake", "wps_pixie", "wep_ivs",
                "ie_audit", "pmf_audit", "eapol_audit"),
       budget_scale=0.4, attack_cap=45.0, scan_time=12.0, minutes=7.0),
    _p("balanced", "Balanced",
       "A sensible default audit: key recovery, the main protocol audits "
       "and a quick look at the wired side, all inside about ten minutes.",
       attacks=(
           "pmkid", "handshake", "wps_pixie", "wep_ivs", "hidden_ssid",
           "tracker", "ie_audit", "pmf_audit", "eapol_audit", "loot_audit",
           "wps_lockout_probe", "pixie_offline", "crack_sweep",
           "enterprise", "eap_md5_crack",
       ),
       budget_scale=0.7, attack_cap=60.0, scan_time=20.0, minutes=10.0),
    _p("stealth", "Stealth",
       "Listen only.  No injection, no deauth, no floods: passive capture "
       "and offline analysis that a WIDS has nothing to complain about.",
       categories=("survey", "offline", "discovery"),
       budget_scale=0.8, attack_cap=45.0, scan_time=30.0, minutes=10.0, jobs=2),
    _p("survey", "Survey",
       "Map first, shoot later: discovery and survey across Wi-Fi, "
       "Bluetooth and the wired side, so the next run knows its targets.",
       categories=("survey", "discovery"),
       budget_scale=0.6, attack_cap=30.0, scan_time=20.0, minutes=8.0),
    _p("rogue", "Rogue AP",
       "Become the network: evil twin, Karma, captive portal phishing, "
       "rogue DHCP/DNS and the MITM plumbing that makes them pay off.",
       attacks=(
           "evil_twin", "karma", "rogue_dhcp", "dns_sink", "captive_portal",
           "airgeddon_portal", "rogue_radius", "beacon_clone",
           "wpa3_downgrade_twin", "arp_mitm", "rogue_ap",
       ),
       budget_scale=0.7, attack_cap=60.0, scan_time=15.0, minutes=12.0),
    _p("enterprise", "Enterprise / 802.1X",
       "WPA-Enterprise: rogue RADIUS, EAP identity harvesting, MD5 and "
       "MSCHAPv2 cracking, certificate and inner-method audits.",
       attacks=(
           "enterprise", "rogue_radius", "eap_md5_crack",
           "eap_identity_harvest", "certificate_audit", "ttls_inner_audit",
           "eap_tls_version", "mschapv2_crack", "eap_method_probe",
           "radius_secret_test",
       ),
       budget_scale=0.7, attack_cap=60.0, scan_time=15.0, minutes=12.0),
    _p("disrupt", "Disrupt",
       "Denial-of-service testing only: deauth, floods and resource "
       "exhaustion, each hard-capped so the test ends when you said it would.",
       categories=("dos",),
       budget_scale=0.5, attack_cap=30.0, scan_time=10.0, minutes=8.0),
    _p("bluetooth", "Bluetooth",
       "The Bluetooth edition: discovery, pairing and protocol attacks "
       "against BLE and classic devices.",
       domains=("bluetooth",),
       budget_scale=0.6, attack_cap=30.0, scan_time=10.0, minutes=12.0),
    _p("it", "IT / LAN",
       "The IT edition: services, protocols and device families on the "
       "wired side — highly parallel, because none of it needs the radio.",
       domains=("it",),
       budget_scale=0.6, attack_cap=30.0, scan_time=5.0, minutes=12.0, jobs=8),
    _p("full", "Full catalogue (fast)",
       "Every attack in the catalogue, but with the speed governor on: "
       "scaled budgets, per-attack caps and parallel side lanes, so even "
       "the everything-run finishes instead of wandering off.",
       domains=("wifi", "bluetooth", "it"),
       budget_scale=0.35, attack_cap=30.0, scan_time=15.0, minutes=12.0, jobs=8),
    # aliases ----------------------------------------------------------- #
    _p("quick", "Quick (alias of Blitz)", "", alias_of="blitz"),
    _p("default", "Default (alias of Balanced)", "", alias_of="balanced"),
    _p("passive", "Passive (alias of Stealth)", "", alias_of="stealth"),
]}


def preset_names(include_aliases: bool = False) -> List[str]:
    return [name for name, p in PRESETS.items() if include_aliases or not p.alias_of]


def parse_preset(spec: str) -> Tuple[str, str]:
    """``"success:force"`` → ``("success", "force")``; junk postures are dropped."""
    text = (spec or "").strip().lower()
    if ":" in text:
        name, _, posture = text.partition(":")
        posture = posture.strip()
        return name.strip(), posture if posture in POSTURES else ""
    return text, ""


def get_preset(spec: str) -> Optional[Preset]:
    name, _ = parse_preset(spec)
    preset = PRESETS.get(name)
    if preset is not None and preset.alias_of:
        return PRESETS.get(preset.alias_of, preset)
    return preset


def resolve_attacks(preset: Preset, posture: str = "") -> List[str]:
    """The concrete attack list for a preset + posture, registry-validated."""
    from .attacks import ATTACK_META   # lazy: heavy import (also fills the registry)
    from .models import ATTACK_NAMES

    known = set(ATTACK_NAMES)
    names: List[str] = []
    if preset.attacks:
        names = [n for n in preset.attacks if n in known]
    elif preset.domains:
        names = [n for n in ATTACK_NAMES
                 if ATTACK_META.get(n, {}).get("domain", "wifi") in preset.domains]
    elif preset.categories:
        names = [n for n in ATTACK_NAMES
                 if ATTACK_META.get(n, {}).get("category", "") in preset.categories]
    if posture == "force":
        touches_wifi = any(
            ATTACK_META.get(n, {}).get("domain", "wifi") == "wifi" for n in names)
        if touches_wifi:
            for booster in _FORCE_BOOSTERS:
                if booster in known and booster not in names:
                    names.append(booster)
    if posture == "stealth":
        from .attacks import ATTACK_CLASSES
        names = [n for n in names
                 if not getattr(ATTACK_CLASSES.get(n), "needs_injection", False)
                 and ATTACK_META.get(n, {}).get("noise", "silent") in ("silent", "quiet")
                 and ATTACK_META.get(n, {}).get("category", "") != "dos"]
    return names


def apply_preset(config: Any, spec: str, posture: str = "") -> Dict[str, Any]:
    """Stamp a preset (+ optional posture) onto a config.

    Returns a small report (also what the UIs show).  Raises ``KeyError`` for
    an unknown preset name so typos fail loudly instead of running the
    hour-long default by accident.
    """
    name, parsed_posture = parse_preset(spec)
    posture = (posture or parsed_posture or "").strip().lower()
    if posture not in POSTURES:
        posture = ""
    preset = get_preset(name)
    if preset is None:
        raise KeyError(
            f"unknown preset {name!r} (valid: {', '.join(preset_names())}; "
            f"each also accepts :force and :stealth)")
    config.preset = preset.name
    config.posture = posture
    config.attacks = resolve_attacks(preset, posture)
    config.budget_scale = preset.budget_scale
    config.attack_cap = preset.attack_cap
    config.scan_time = preset.scan_time
    config.jobs = max(1, preset.jobs)
    config.parallel_crack = preset.parallel_crack
    if preset.name == "stealth" and not posture:
        config.stealth = True
        config.aggressive = False
    if posture == "force":
        # FORCE: success over subtlety — the anti-stealth posture.
        config.stealth = False
        config.aggressive = True
        config.broadcast_handshake = True
        config.deauth_count = max(int(config.deauth_count or 5), 10)
        config.targeted_candidates = max(int(config.targeted_candidates or 0), 6000)
        config.mask_candidates = max(int(config.mask_candidates or 0), 25000)
        config.use_rules = True
        config.jobs = max(config.jobs, 6)
    elif posture == "stealth":
        config.stealth = True
        config.aggressive = False
        config.jobs = min(config.jobs, 2)
    return {
        "preset": preset.name, "label": preset.label, "posture": posture,
        "attacks": len(config.attacks), "budget_scale": preset.budget_scale,
        "attack_cap": preset.attack_cap, "scan_time": preset.scan_time,
        "minutes": preset.minutes, "jobs": config.jobs,
        "parallel_crack": config.parallel_crack,
    }


def list_presets() -> List[Dict[str, Any]]:
    """Every preset with its resolved size, for CLI/API/web pickers."""
    out: List[Dict[str, Any]] = []
    for name in preset_names():
        preset = PRESETS[name]
        out.append({
            "name": preset.name, "label": preset.label,
            "description": preset.description,
            "attacks": len(resolve_attacks(preset)),
            "force_attacks": len(resolve_attacks(preset, "force")),
            "stealth_attacks": len(resolve_attacks(preset, "stealth")),
            "budget_scale": preset.budget_scale, "attack_cap": preset.attack_cap,
            "scan_time": preset.scan_time, "minutes": preset.minutes,
            "jobs": preset.jobs, "parallel_crack": preset.parallel_crack,
            "postures": [p for p in POSTURES if p],
        })
    return out
