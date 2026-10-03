"""Attack registry: every primitive wifipilot can execute.

Fifty-four attacks, and the registry is the single place that knows all of them.  The
catalogue it produces (:func:`attack_catalog`) carries more than a name and a label: it
carries what :mod:`wifipilot.attacks.meta` says about each attack — its category, how
noisy it is, what it costs if it works, and what a defender would see — so the CLI
matrix, the web UI, the report and the advisor prompt all describe an attack the same
way, and adding an attack without that description fails a test instead of shipping.

Read it as a ladder:

* **offline** — reads files the session already has.  No radio, no authorisation, no
  noise: ``loot_audit``, ``crack_sweep``, the audits, ``pixie_offline``.
* **survey** — reads the air (``passive``, ``ie_audit``, ``pmf_audit``, ``saewolf``,
  ``sae_group_audit``): a network's *documented* weakness is not an intrusion.
* **capture** — asks for the material, from polite (``pmkid``) to blunt
  (``handshake_broadcast``, ``hcxdump_capture``).
* **wps / wep / enterprise** — the protocol-specific paths.
* **rogue** — impersonation and lures: ``evil_twin``, ``karma``, ``csa_attack``.
* **dos** — floods and state exhaustion, all opt-in, all capped: their report says
  plainly that the deliverable is the finding, not a password.
"""

from __future__ import annotations

from typing import Dict, List, Type

from .audit import IeAuditAttack, PnlHarvestAttack
from .base import Attack, AttackContext, AttackOutcome
from .capture2 import HandshakeBroadcastAttack, HcxdumpCaptureAttack
from .enterprise import EnterpriseSurveyAttack
from .flood import (AuthFloodAttack, BeaconFloodAttack, DeauthFloodAttack,
                    ProbeFloodAttack)
from .flood2 import (AssocFloodAttack, EapolStartFloodAttack, NullDataFloodAttack,
                     SaeCommitFloodAttack, TkipMichaelAttack, WidsConfusionAttack)
from .forensics import (CrackSweepAttack, EapMd5CrackAttack, EapolAuditAttack,
                        LootAuditAttack, PixieOfflineAttack, RoamAuditAttack,
                        RogueDetectAttack, TwinDetectAttack, WepAuditAttack,
                        WpsLockoutAuditAttack)
from .karma import KarmaAttack
from .logoff import EapolLogoffAttack, logoff_preview
from .handshake import HandshakeAttack
from .hidden import HiddenSsidAttack
from .lure import (ApIsolationAuditAttack, CsaAttack, KarmaDetectAttack,
                   SsidBruteforceAttack, SsidConfusionAttack)
from .meta import (ATTACK_META, CATEGORIES, IMPACT_LEVELS, IMPACT_STYLE,
                   NOISE_LEVELS, NOISE_STYLE, category_label, meta_for, validate)
from .offensive import RogueRadiusAttack, ROGUE_TOOLS
from .passive import PassiveAttack
from .pmkid import PmkidAttack, PmkidFloodAttack
from .rogue import RogueApAttack
from .survey2 import SaeGroupAuditAttack
from .tracker import TrackerAttack, airodump_stations
from .twin import EvilTwinAttack
from .wep import (WepAttack, WepChopchopAttack, WepFragmentAttack, WepHirteAttack,
                  WepP0841Attack, keystream_file)
from .wpa3 import PmfAuditAttack, SaeWolfAttack
from .wps import PixieDustAttack, WpsPinAttack, candidate_pins
from .wps2 import WpsApPinAttack, WpsLockoutProbeAttack, WpsPbcAttack

ATTACK_CLASSES: Dict[str, Type[Attack]] = {
    # -- offline: no radio, no authorisation, no frames ----------------------
    "loot_audit": LootAuditAttack,
    "eapol_audit": EapolAuditAttack,
    "wep_audit": WepAuditAttack,
    "crack_sweep": CrackSweepAttack,
    "eap_md5_crack": EapMd5CrackAttack,
    "pixie_offline": PixieOfflineAttack,
    "rogue_detect": RogueDetectAttack,
    "twin_detect": TwinDetectAttack,
    "roam_audit": RoamAuditAttack,
    "wps_lockout_audit": WpsLockoutAuditAttack,
    # -- capture -------------------------------------------------------------
    "handshake": HandshakeAttack,
    "handshake_broadcast": HandshakeBroadcastAttack,
    "pmkid": PmkidAttack,
    "pmkid_flood": PmkidFloodAttack,
    "hcxdump_capture": HcxdumpCaptureAttack,
    # -- surveys (read-only) -------------------------------------------------
    "passive": PassiveAttack,
    "ie_audit": IeAuditAttack,
    "pnl_harvest": PnlHarvestAttack,
    "tracker": TrackerAttack,
    "hidden_ssid": HiddenSsidAttack,
    "rogue_ap": RogueApAttack,
    "pmf_audit": PmfAuditAttack,
    "saewolf": SaeWolfAttack,
    "sae_group_audit": SaeGroupAuditAttack,
    # -- WPS / WEP / enterprise ----------------------------------------------
    "wps_pixie": PixieDustAttack,
    "wps_pin": WpsPinAttack,
    "wps_ap_pin": WpsApPinAttack,
    "wps_lockout_probe": WpsLockoutProbeAttack,
    "wps_pbc": WpsPbcAttack,
    "wep_ivs": WepAttack,
    "wep_p0841": WepP0841Attack,
    "wep_chopchop": WepChopchopAttack,
    "wep_fragment": WepFragmentAttack,
    "wep_hirte": WepHirteAttack,
    "enterprise": EnterpriseSurveyAttack,
    "eapol_logoff": EapolLogoffAttack,
    # -- rogue infrastructure, lures and impersonation ----------------------
    "evil_twin": EvilTwinAttack,
    "karma": KarmaAttack,
    "karma_detect": KarmaDetectAttack,
    "csa_attack": CsaAttack,
    "ssid_confusion": SsidConfusionAttack,
    "ssid_bruteforce": SsidBruteforceAttack,
    "ap_isolation_audit": ApIsolationAuditAttack,
    "rogue_radius": RogueRadiusAttack,
    # -- denial of service (opt-in, always) ----------------------------------
    "deauth_flood": DeauthFloodAttack,
    "auth_flood": AuthFloodAttack,
    "assoc_flood": AssocFloodAttack,
    "null_data_flood": NullDataFloodAttack,
    "probe_flood": ProbeFloodAttack,
    "eapol_start_flood": EapolStartFloodAttack,
    "sae_commit_flood": SaeCommitFloodAttack,
    "tkip_michael": TkipMichaelAttack,
    "wids_confusion": WidsConfusionAttack,
    "beacon_flood": BeaconFloodAttack,
}

#: order the engine falls back to when the advisor does not decide.  The
#: read-only work comes first — offline audits cost nothing, surveys change what the
#: planner knows (a revealed SSID, a twin warning) — then capture, then the
#: protocol-specific attacks, then the lures, and the floods last, where a reader who
#: stops before the end never meets them.
DEFAULT_ORDER = [
    # offline
    "loot_audit", "eapol_audit", "wep_audit", "pixie_offline", "eap_md5_crack",
    "crack_sweep", "rogue_detect", "twin_detect", "roam_audit", "wps_lockout_audit",
    # read-only surveys
    "passive", "rogue_ap", "ie_audit", "pmf_audit", "saewolf", "sae_group_audit",
    "hidden_ssid", "pnl_harvest", "tracker",
    # capture
    "pmkid", "handshake", "handshake_broadcast", "pmkid_flood", "hcxdump_capture",
    # WPS / WEP / enterprise
    "wps_pixie", "wps_ap_pin", "wps_lockout_probe", "wps_pbc", "wps_pin",
    "wep_ivs", "wep_p0841", "wep_chopchop", "wep_fragment", "wep_hirte",
    "enterprise", "eapol_logoff",
    # rogue infrastructure and lures
    "karma_detect", "csa_attack", "ssid_bruteforce", "ssid_confusion",
    "ap_isolation_audit", "evil_twin", "karma", "rogue_radius",
    # denial of service
    "deauth_flood", "auth_flood", "assoc_flood", "null_data_flood", "probe_flood",
    "eapol_start_flood", "sae_commit_flood", "tkip_michael", "wids_confusion",
    "beacon_flood",
]

#: exactly the names :class:`wifipilot.config.Config` enables out of the box.  The
#: catalogue reports these as ``default_enabled``; everything else — the offline
#: audits included — is opt-in, so a run does exactly what the operator asked for.
DEFAULT_ENABLED = ("pmkid", "handshake", "wps_pixie", "wep_ivs", "hidden_ssid",
                   "tracker")

#: attacks that never transmit anything: pure file analysis, so they need no radio,
#: no monitor interface and no authorisation.  (``pmkid`` is *silent* too, but it
#: still needs a monitor interface and, often, a frame: noisy-in-a-different-way is
#: not the same as offline.)
OFFLINE_ATTACKS = tuple(name for name in DEFAULT_ORDER
                        if ATTACK_META.get(name, {}).get("category") == "offline")

#: attacks the planner only runs when the operator has explicitly named them: every
#: denial-of-service test, plus the two that impersonate a network
OPT_IN_ATTACKS = tuple(name for name in DEFAULT_ORDER
                       if ATTACK_META.get(name, {}).get("category") == "dos") + (
    "rogue_radius", "evil_twin", "karma", "karma_detect", "csa_attack",
    "ssid_confusion", "wps_pbc", "wps_pin", "wps_ap_pin", "handshake_broadcast",
    "hcxdump_capture", "tkip_michael", "wids_confusion")

__all__ = [
    "Attack", "AttackContext", "AttackOutcome", "ATTACK_CLASSES", "DEFAULT_ORDER",
    "DEFAULT_ENABLED", "OFFLINE_ATTACKS", "OPT_IN_ATTACKS", "ATTACK_META",
    "CATEGORIES", "NOISE_LEVELS", "IMPACT_LEVELS", "NOISE_STYLE", "IMPACT_STYLE",
    "category_label", "meta_for", "validate",
    "HandshakeAttack", "HandshakeBroadcastAttack", "HcxdumpCaptureAttack",
    "PmkidAttack", "PixieDustAttack", "WpsPinAttack", "WpsApPinAttack",
    "WpsLockoutProbeAttack", "WpsPbcAttack", "WepAttack",
    "HiddenSsidAttack", "RogueApAttack", "EnterpriseSurveyAttack", "PassiveAttack",
    "RogueRadiusAttack", "TrackerAttack", "ROGUE_TOOLS",
    "SaeWolfAttack", "SaeGroupAuditAttack", "PmfAuditAttack", "EvilTwinAttack",
    "KarmaAttack", "KarmaDetectAttack", "CsaAttack", "SsidConfusionAttack",
    "SsidBruteforceAttack", "ApIsolationAuditAttack", "EapolLogoffAttack",
    "DeauthFloodAttack", "AuthFloodAttack", "AssocFloodAttack", "NullDataFloodAttack",
    "ProbeFloodAttack", "EapolStartFloodAttack", "SaeCommitFloodAttack",
    "TkipMichaelAttack", "WidsConfusionAttack", "BeaconFloodAttack",
    "LootAuditAttack", "EapolAuditAttack", "WepAuditAttack", "CrackSweepAttack",
    "EapMd5CrackAttack", "PixieOfflineAttack", "RogueDetectAttack", "TwinDetectAttack",
    "RoamAuditAttack", "WpsLockoutAuditAttack",
    "PmkidFloodAttack", "WepChopchopAttack", "WepFragmentAttack",
    "WepHirteAttack", "WepP0841Attack", "keystream_file",
    "IeAuditAttack", "PnlHarvestAttack", "logoff_preview",
    "candidate_pins", "get_attack", "attack_catalog", "airodump_stations",
]


def get_attack(name: str) -> Attack:
    cls = ATTACK_CLASSES.get(name)
    if cls is None:
        raise KeyError(f"unknown attack {name!r} (have: {', '.join(ATTACK_CLASSES)})")
    return cls()


def attack_catalog() -> List[Dict[str, object]]:
    """Machine-readable list for the UI, the CLI, the docs matrix and the LLM prompt.

    Every entry carries the metadata from :mod:`wifipilot.attacks.meta` as well as the
    attack's own text, which is what lets the catalogue be the single source for
    "what does this attack cost": ``noise`` (how visible), ``impact`` (what it breaks
    when it works) and ``detection`` (what a defender sees) come from one table, and a
    test fails if an attack is added without them.
    """
    out: List[Dict[str, object]] = []
    for name in DEFAULT_ORDER:
        cls = ATTACK_CLASSES.get(name)
        if cls is None:
            continue
        meta = meta_for(name)
        out.append({
            "name": name, "label": cls.label, "tool": cls.tool,
            "description": cls.description, "requires": list(cls.requires),
            "needs_injection": cls.needs_injection,
            "applies_to": list(cls.applies_to),
            "category": meta["category"],
            "category_label": category_label(str(meta["category"])),
            "noise": meta["noise"], "impact": meta["impact"],
            "detection": meta["detection"],
            # "offline" means no radio at all: the category is the test, not the
            # silence — a PMKID request is silent but it is not analysis
            "offline": meta["category"] == "offline" and not cls.needs_injection,
            "default_enabled": name in DEFAULT_ENABLED,
        })
    return out
