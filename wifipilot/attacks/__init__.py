"""Attack registry: every primitive wifipilot can execute."""

from __future__ import annotations

from typing import Dict, List, Type

from .base import Attack, AttackContext, AttackOutcome
from .enterprise import EnterpriseSurveyAttack
from .flood import BeaconFloodAttack, DeauthFloodAttack
from .handshake import HandshakeAttack
from .hidden import HiddenSsidAttack
from .offensive import RogueRadiusAttack, ROGUE_TOOLS
from .passive import PassiveAttack
from .pmkid import PmkidAttack, PmkidFloodAttack
from .rogue import RogueApAttack
from .tracker import TrackerAttack, airodump_stations
from .twin import EvilTwinAttack
from .wep import (WepAttack, WepChopchopAttack, WepFragmentAttack, WepHirteAttack,
                  WepP0841Attack, keystream_file)
from .wpa3 import PmfAuditAttack, SaeWolfAttack
from .wps import PixieDustAttack, WpsPinAttack, candidate_pins

ATTACK_CLASSES: Dict[str, Type[Attack]] = {
    # capture
    "handshake": HandshakeAttack,
    "pmkid": PmkidAttack,
    "pmkid_flood": PmkidFloodAttack,
    # WPS / WEP
    "wps_pixie": PixieDustAttack,
    "wps_pin": WpsPinAttack,
    "wep_ivs": WepAttack,
    "wep_p0841": WepP0841Attack,
    "wep_chopchop": WepChopchopAttack,
    "wep_fragment": WepFragmentAttack,
    "wep_hirte": WepHirteAttack,
    # surveys (read-only)
    "hidden_ssid": HiddenSsidAttack,
    "rogue_ap": RogueApAttack,
    "enterprise": EnterpriseSurveyAttack,
    "tracker": TrackerAttack,
    "pmf_audit": PmfAuditAttack,
    "saewolf": SaeWolfAttack,
    "passive": PassiveAttack,
    # rogue infrastructure
    "evil_twin": EvilTwinAttack,
    "rogue_radius": RogueRadiusAttack,
    "deauth_flood": DeauthFloodAttack,
    "beacon_flood": BeaconFloodAttack,
}

#: order the engine falls back to when the advisor does not decide.  The
#: read-only surveys come first: they cost no radio time and they change what the
#: planner knows (a revealed SSID, a twin warning) before a noisy attack starts.
DEFAULT_ORDER = ["rogue_ap", "pmf_audit", "hidden_ssid", "tracker", "saewolf", "pmkid",
                 "pmkid_flood", "handshake", "wps_pixie", "wps_pin", "wep_ivs",
                 "wep_p0841", "wep_chopchop", "wep_fragment", "wep_hirte", "enterprise",
                 "evil_twin", "rogue_radius", "deauth_flood", "beacon_flood", "passive"]

__all__ = [
    "Attack", "AttackContext", "AttackOutcome", "ATTACK_CLASSES", "DEFAULT_ORDER",
    "HandshakeAttack", "PmkidAttack", "PixieDustAttack", "WpsPinAttack", "WepAttack",
    "HiddenSsidAttack", "RogueApAttack", "EnterpriseSurveyAttack", "PassiveAttack",
    "RogueRadiusAttack", "TrackerAttack", "ROGUE_TOOLS",
    "SaeWolfAttack", "PmfAuditAttack", "EvilTwinAttack", "DeauthFloodAttack",
    "BeaconFloodAttack", "PmkidFloodAttack", "WepChopchopAttack", "WepFragmentAttack",
    "WepHirteAttack", "WepP0841Attack", "keystream_file",
    "candidate_pins", "get_attack", "attack_catalog", "airodump_stations",
]


def get_attack(name: str) -> Attack:
    cls = ATTACK_CLASSES.get(name)
    if cls is None:
        raise KeyError(f"unknown attack {name!r} (have: {', '.join(ATTACK_CLASSES)})")
    return cls()


def attack_catalog() -> List[Dict[str, object]]:
    """Machine-readable list for the UI, the CLI and the LLM prompt."""
    out = []
    for name in DEFAULT_ORDER:
        cls = ATTACK_CLASSES.get(name)
        if cls is None:
            continue
        out.append({
            "name": name, "label": cls.label, "tool": cls.tool,
            "description": cls.description, "requires": list(cls.requires),
            "needs_injection": cls.needs_injection,
            "applies_to": list(cls.applies_to),
            # exactly the names in Config.attacks: everything else (including the
            # read-only WPA3 survey and the disruptive attacks) is opt-in
            "default_enabled": name in ("pmkid", "handshake", "wps_pixie", "wep_ivs",
                                        "hidden_ssid", "tracker"),
        })
    return out
