"""Attack metadata: what each technique *is*, how loud it is, and what it costs.

The class attributes on :class:`~wifipilot.attacks.base.Attack` describe how to run an
attack.  This module describes how to *choose* one: its family (capture, offline,
rogue, denial-of-service, …), how much noise it puts on the air, and what changes for
the site if it works.  The CLI's ``wifipilot attacks`` matrix, the web UI's groups, the
planner's ordering and the documentation tables are all generated from it, so there is
exactly one place to correct when an attack's character changes.

Noise is the axis an operator actually plans around:

``silent``
    transmits nothing at all — reads files, beacons already on air, or the session.
``quiet``
    a handful of frames: an association, a probe, one deauthentication.
``moderate``
    seconds to a few minutes of traffic, or an access point of our own.
``loud``
    saturates the channel or floods a table; only ever a deliberate test.
``extreme``
    the attack exists to be noticed by the site's monitoring, or to disable a service
    for as long as it runs.

Impact is what the engagement report will say:

``none``      nothing changes for the site (analysis only)
``info``      a finding, no effect on clients or the AP
``degraded``  some clients lose connectivity while it runs
``outage``    the tested network stops working for the duration
``loot``      a capture, credential or PSK that can be taken away and cracked/cited
"""

from __future__ import annotations

from typing import Dict, List

#: category -> one-line description, in the order the docs and the CLI show them
CATEGORIES: List[Dict[str, str]] = [
    {"name": "offline", "label": "Offline analysis",
     "description": "reads captures and session state; transmits nothing"},
    {"name": "capture", "label": "Capture",
     "description": "harvests material that can be cracked later"},
    {"name": "survey", "label": "Survey & reconnaissance",
     "description": "passive discovery and decoding of what is on air"},
    {"name": "wps", "label": "WPS",
     "description": "PIN and push-button attacks against WPS"},
    {"name": "wep", "label": "WEP",
     "description": "the WEP family: IV harvesting and injection enablers"},
    {"name": "enterprise", "label": "802.1X / enterprise",
     "description": "identity, certificate and radius attacks"},
    {"name": "rogue", "label": "Rogue infrastructure & spoofing",
     "description": "access points and frames we are not supposed to be able to send"},
    {"name": "dos", "label": "Denial-of-service tests",
     "description": "deliberate disruption, with detection as the finding"},
]

NOISE_LEVELS = ("silent", "quiet", "moderate", "loud", "extreme")
IMPACT_LEVELS = ("none", "info", "degraded", "outage", "loot")

#: tone used for each noise level in tables and the web UI
NOISE_STYLE = {"silent": "dim", "quiet": "green", "moderate": "cyan", "loud": "yellow",
               "extreme": "red"}
IMPACT_STYLE = {"none": "dim", "info": "green", "degraded": "yellow", "outage": "red",
                "loot": "bold green"}

#: name -> (category, noise, impact, detection).  The first three are the axes the
#: planner and the docs sort by; ``detection`` is the sentence an operator repeats to
#: the client, and it is part of the deliverable, not decoration.
ATTACK_META: Dict[str, Dict[str, str]] = {
    # -- offline analysis -------------------------------------------------- #
    "loot_audit": {"category": "offline", "noise": "silent", "impact": "info",
                   "detection": "nothing on air; reads the session's own files"},
    "crack_sweep": {"category": "offline", "noise": "silent", "impact": "loot",
                    "detection": "nothing on air; CPU only"},
    "eapol_audit": {"category": "offline", "noise": "silent", "impact": "info",
                    "detection": "nothing on air; decodes EAPOL already captured"},
    "wep_audit": {"category": "offline", "noise": "silent", "impact": "info",
                  "detection": "nothing on air; counts IVs already captured"},
    "eap_md5_crack": {"category": "offline", "noise": "silent", "impact": "loot",
                      "detection": "nothing on air; offline dictionary against a captured "
                                   "EAP-MD5 exchange"},
    "pixie_offline": {"category": "offline", "noise": "silent", "impact": "loot",
                      "detection": "nothing on air; runs pixiewps against a stored exchange"},
    "rogue_detect": {"category": "offline", "noise": "silent", "impact": "info",
                     "detection": "nothing on air; compares what the scanner already sees"},
    "twin_detect": {"category": "offline", "noise": "silent", "impact": "info",
                    "detection": "nothing on air; fingerprints identical SSIDs"},
    "roam_audit": {"category": "offline", "noise": "silent", "impact": "info",
                   "detection": "nothing on air; reads 802.11k/r/v elements"},
    "wps_lockout_audit": {"category": "offline", "noise": "silent", "impact": "info",
                          "detection": "nothing on air; assesses WPS from IEs and history"},
    # -- capture ----------------------------------------------------------- #
    "handshake": {"category": "capture", "noise": "quiet", "impact": "loot",
                  "detection": "two short deauth bursts per client; a WIDS counting deauths "
                               "sees them"},
    "handshake_broadcast": {"category": "capture", "noise": "moderate", "impact": "loot",
                            "detection": "broadcast deauth; every client on the channel "
                                         "drops at once"},
    "pmkid": {"category": "capture", "noise": "silent", "impact": "loot",
              "detection": "nothing from us; the AP volunteers the PMKID to associated "
                           "clients"},
    "pmkid_flood": {"category": "capture", "noise": "loud", "impact": "degraded",
                    "detection": "deauth-driven PMKID hunt; frequent disconnects"},
    "hcxdump_capture": {"category": "capture", "noise": "moderate", "impact": "loot",
                        "detection": "an active hcxdumptool session: association attempts "
                                     "and deauths under its own policy"},
    # -- surveys ----------------------------------------------------------- #
    "passive": {"category": "survey", "noise": "silent", "impact": "none",
                "detection": "nothing at all; listen-only capture"},
    "ie_audit": {"category": "survey", "noise": "silent", "impact": "info",
                 "detection": "nothing on air; decodes beacons"},
    "pnl_harvest": {"category": "survey", "noise": "silent", "impact": "info",
                    "detection": "nothing on air; reads probe requests"},
    "tracker": {"category": "survey", "noise": "silent", "impact": "info",
                "detection": "follows a station with the capture radio only"},
    "hidden_ssid": {"category": "survey", "noise": "quiet", "impact": "info",
                    "detection": "one probe request per hidden name; the AP's own answer "
                                 "reveals it"},
    "rogue_ap": {"category": "survey", "noise": "silent", "impact": "info",
                 "detection": "nothing on air; cross-checks the neighbourhood"},
    "pmf_audit": {"category": "survey", "noise": "silent", "impact": "info",
                  "detection": "nothing on air; reads RSN capabilities"},
    "sae_group_audit": {"category": "survey", "noise": "silent", "impact": "info",
                        "detection": "nothing on air beyond the capture that was already "
                                     "happening; reads the RSN element and SAE commits"},
    "saewolf": {"category": "survey", "noise": "quiet", "impact": "loot",
                "detection": "captures SAE frames; sends nothing until a client authenticates"},
    # -- WPS --------------------------------------------------------------- #
    "wps_pixie": {"category": "wps", "noise": "quiet", "impact": "loot",
                  "detection": "one WPS exchange (EAP messages 1-4); the AP sees a normal "
                               "enrolment"},
    "wps_pin": {"category": "wps", "noise": "moderate", "impact": "loot",
                "detection": "a stream of PIN attempts; APs with lockout will report it"},
    "wps_pbc": {"category": "wps", "noise": "quiet", "impact": "loot",
                "detection": "push-button enrolment attempts; fails visibly while the AP's "
                             "button window is shut"},
    "wps_ap_pin": {"category": "wps", "noise": "quiet", "impact": "loot",
                   "detection": "static AP-PIN attempts from a vendor algorithm"},
    "wps_lockout_probe": {"category": "wps", "noise": "quiet", "impact": "info",
                          "detection": "a few deliberately-wrong PINs, then stop: the "
                                       "finding is whether the AP locked out"},
    # -- WEP --------------------------------------------------------------- #
    "wep_ivs": {"category": "wep", "noise": "loud", "impact": "loot",
                "detection": "ARP-replay injection; the network's own traffic rises"},
    "wep_p0841": {"category": "wep", "noise": "loud", "impact": "loot",
                  "detection": "injected ARP frames with a spoofed client"},
    "wep_chopchop": {"category": "wep", "noise": "loud", "impact": "loot",
                     "detection": "one frame chopped byte by byte; thousands of injected "
                                  "frames"},
    "wep_fragment": {"category": "wep", "noise": "moderate", "impact": "loot",
                     "detection": "fragmented injected frames"},
    "wep_hirte": {"category": "wep", "noise": "moderate", "impact": "loot",
                  "detection": "client-driven fragmentation; a station must be active"},
    # -- enterprise -------------------------------------------------------- #
    "enterprise": {"category": "enterprise", "noise": "silent", "impact": "info",
                   "detection": "nothing on air; decodes 802.1X already captured"},
    "rogue_radius": {"category": "enterprise", "noise": "moderate", "impact": "loot",
                     "detection": "a rogue RADIUS/eaphammer AP; clients that trust any "
                                  "certificate will offer credentials"},
    # -- rogue & spoofing -------------------------------------------------- #
    "evil_twin": {"category": "rogue", "noise": "moderate", "impact": "loot",
                  "detection": "a second access point with the same SSID; the real network's "
                               "clients may prefer it"},
    "karma": {"category": "rogue", "noise": "moderate", "impact": "loot",
              "detection": "an AP that answers every probe request (hostapd-mana)"},
    "karma_detect": {"category": "rogue", "noise": "quiet", "impact": "info",
                     "detection": "probe requests for names that do not exist; anything "
                                  "that answers is a Karma device"},
    "csa_attack": {"category": "rogue", "noise": "moderate", "impact": "degraded",
                   "detection": "beacons with a Channel Switch Announcement; clients leave "
                                "the channel"},
    "ssid_confusion": {"category": "rogue", "noise": "moderate", "impact": "degraded",
                       "detection": "beacons for an existing SSID from a new BSSID"},
    "ssid_bruteforce": {"category": "rogue", "noise": "moderate", "impact": "info",
                        "detection": "probe/association attempts with dictionary SSIDs "
                                     "against a hidden network"},
    "ap_isolation_audit": {"category": "rogue", "noise": "quiet", "impact": "info",
                           "detection": "a handful of spoofed ARP frames between two "
                                        "clients"},
    # -- denial of service ------------------------------------------------- #
    "deauth_flood": {"category": "dos", "noise": "extreme", "impact": "outage",
                     "detection": "every client of the AP is disconnected, repeatedly"},
    "auth_flood": {"category": "dos", "noise": "loud", "impact": "degraded",
                   "detection": "thousands of authentication frames from fake stations"},
    "assoc_flood": {"category": "dos", "noise": "loud", "impact": "degraded",
                    "detection": "thousands of association requests; the association table "
                                 "fills"},
    "null_data_flood": {"category": "dos", "noise": "loud", "impact": "degraded",
                        "detection": "QoS Null frames only — no deauth frames at all, so "
                                     "deauth-based WIDS rules do not fire"},
    "eapol_start_flood": {"category": "dos", "noise": "loud", "impact": "degraded",
                          "detection": "EAPOL-Starts from fake supplicants; the RADIUS "
                                       "server holds half-open sessions"},
    "sae_commit_flood": {"category": "dos", "noise": "loud", "impact": "degraded",
                         "detection": "SAE commit frames from fake stations; anti-clogging "
                                      "tokens are the mitigation"},
    "tkip_michael": {"category": "dos", "noise": "extreme", "impact": "outage",
                     "detection": "TKIP MIC failures trigger the AP's 60-second Michael "
                                  "countermeasure shutdown"},
    "wids_confusion": {"category": "dos", "noise": "extreme", "impact": "degraded",
                       "detection": "attack frames from a list of spoofed transmitters; the "
                                    "test is whether the site's monitoring can tell"},
    "beacon_flood": {"category": "dos", "noise": "extreme", "impact": "degraded",
                     "detection": "hundreds of phantom SSIDs in every scan list"},
    "probe_flood": {"category": "dos", "noise": "loud", "impact": "degraded",
                    "detection": "a dictionary of directed probe requests"},
    "eapol_logoff": {"category": "rogue", "noise": "quiet", "impact": "degraded",
                     "detection": "EAPOL-Logoff frames: no deauth, and PMF does not cover "
                                  "them"},
}


def meta_for(name: str, **overrides: str) -> Dict[str, str]:
    """The metadata for one attack, with the class's own attributes winning."""
    meta = dict(ATTACK_META.get(name, {}))
    meta.setdefault("category", "capture")
    meta.setdefault("noise", "moderate")
    meta.setdefault("impact", "info")
    meta.setdefault("detection", "")
    for key, value in overrides.items():
        if value:
            meta[key] = value
    return meta


def category_label(name: str) -> str:
    for entry in CATEGORIES:
        if entry["name"] == name:
            return entry["label"]
    return name


def validate() -> List[str]:
    """Complaints about the metadata table (used by the test suite).

    Every attack must have metadata, every category/noise/impact value must be one of
    the declared ones, and no entry may exist for an attack that was removed.
    """
    from . import ATTACK_CLASSES

    problems: List[str] = []
    known = set(ATTACK_CLASSES)
    for name in sorted(known):
        if name not in ATTACK_META:
            problems.append(f"{name}: no metadata")
            continue
        meta = ATTACK_META[name]
        if meta.get("category") not in {entry["name"] for entry in CATEGORIES}:
            problems.append(f"{name}: unknown category {meta.get('category')!r}")
        if meta.get("noise") not in NOISE_LEVELS:
            problems.append(f"{name}: unknown noise {meta.get('noise')!r}")
        if meta.get("impact") not in IMPACT_LEVELS:
            problems.append(f"{name}: unknown impact {meta.get('impact')!r}")
        if not meta.get("detection"):
            problems.append(f"{name}: no detection note")
    for name in sorted(set(ATTACK_META) - known):
        problems.append(f"{name}: metadata for an attack that does not exist")
    return problems


__all__ = ["ATTACK_META", "CATEGORIES", "IMPACT_LEVELS", "IMPACT_STYLE", "NOISE_LEVELS",
           "NOISE_STYLE", "category_label", "meta_for", "validate"]
