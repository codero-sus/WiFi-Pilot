"""Attack registry: every primitive wifipilot can execute."""

from __future__ import annotations

from typing import Dict, List, Type

from .base import Attack, AttackContext, AttackOutcome
from .enterprise import EnterpriseSurveyAttack
from .handshake import HandshakeAttack
from .hidden import HiddenSsidAttack
from .offensive import RogueRadiusAttack, ROGUE_TOOLS
from .passive import PassiveAttack
from .pmkid import PmkidAttack
from .rogue import RogueApAttack
from .tracker import TrackerAttack, airodump_stations
from .wep import WepAttack
from .wps import PixieDustAttack, WpsPinAttack, candidate_pins

ATTACK_CLASSES: Dict[str, Type[Attack]] = {
    "handshake": HandshakeAttack,
    "pmkid": PmkidAttack,
    "wps_pixie": PixieDustAttack,
    "wps_pin": WpsPinAttack,
    "wep_ivs": WepAttack,
    "hidden_ssid": HiddenSsidAttack,
    "rogue_ap": RogueApAttack,
    "enterprise": EnterpriseSurveyAttack,
    "rogue_radius": RogueRadiusAttack,
    "tracker": TrackerAttack,
    "passive": PassiveAttack,
}

#: order the engine falls back to when the advisor does not decide.  The
#: read-only surveys come first: they cost no radio time and they change what the
#: planner knows (a revealed SSID, a twin warning) before a noisy attack starts.
DEFAULT_ORDER = ["rogue_ap", "hidden_ssid", "tracker", "pmkid", "handshake",
                 "wps_pixie", "wps_pin", "wep_ivs", "enterprise", "rogue_radius",
                 "passive"]

__all__ = [
    "Attack", "AttackContext", "AttackOutcome", "ATTACK_CLASSES", "DEFAULT_ORDER",
    "HandshakeAttack", "PmkidAttack", "PixieDustAttack", "WpsPinAttack", "WepAttack",
    "HiddenSsidAttack", "RogueApAttack", "EnterpriseSurveyAttack", "PassiveAttack",
    "RogueRadiusAttack", "TrackerAttack", "ROGUE_TOOLS",
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
            "default_enabled": name in ("pmkid", "handshake", "wps_pixie", "wep_ivs",
                                        "hidden_ssid", "tracker"),
        })
    return out
