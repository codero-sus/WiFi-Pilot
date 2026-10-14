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

from typing import Any, Dict, List


def _domains() -> List[Dict[str, str]]:
    """The edition table, from itdev; a lazy import keeps the module importable alone."""
    try:
        from ..itdev import DOMAINS as domains
        return [dict(entry) for entry in domains]
    except Exception:                                     # pragma: no cover - defensive
        return [{"id": "wifi", "label": "Wi-Fi", "description": ""}]

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
    {"name": "discovery", "label": "Discovery & fingerprinting",
     "description": "finds hosts, services and versions, and reads what they volunteer"},
    {"name": "exploit", "label": "Service exploitation",
     "description": "protocol-level abuse: default credentials, bypasses, unauthenticated "
                    "reads and writes"},
]

#: the editions, re-exported from :mod:`wifipilot.itdev` so the metadata validator can
#: check a domain without importing the attack package it is validating.
DOMAINS: List[Dict[str, str]] = _domains()
DOMAIN_IDS = {entry["id"] for entry in DOMAINS}

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
    # -- enterprise, second wave ------------------------------------------- #
    "eap_identity_harvest": {"category": "enterprise", "noise": "silent", "impact": "info",
                             "detection": "nothing from us until a client authenticates; "
                                          "reads the EAP-Response/Identity the AP asked for"},
    "eap_method_probe": {"category": "enterprise", "noise": "quiet", "impact": "info",
                         "detection": "one EAPOL-Start per identity, then the NAK method "
                                      "list: a short negotiation the AP logs"},
    "certificate_audit": {"category": "enterprise", "noise": "silent", "impact": "info",
                          "detection": "nothing on air; parses certificates already captured"},
    "ttls_inner_audit": {"category": "enterprise", "noise": "silent", "impact": "info",
                         "detection": "nothing on air; reads the inner conversation of a "
                                      "captured TTLS tunnel"},
    "mschapv2_crack": {"category": "offline", "noise": "silent", "impact": "loot",
                       "detection": "nothing on air; a dictionary against a captured "
                                    "MS-CHAPv2 exchange"},
    "radius_secret_test": {"category": "enterprise", "noise": "quiet", "impact": "info",
                           "detection": "one Access-Request per candidate secret; a real "
                                        "RADIUS server logs the failures"},
    "eap_tls_version": {"category": "enterprise", "noise": "silent", "impact": "info",
                        "detection": "nothing on air; reads the TLS version out of a "
                                     "captured EAP-TLS handshake"},
    # -- rogue infrastructure, second wave --------------------------------- #
    "rogue_dhcp": {"category": "rogue", "noise": "moderate", "impact": "degraded",
                   "detection": "a second DHCP server on the segment: offers carry our "
                                "gateway and resolver"},
    "dns_sink": {"category": "rogue", "noise": "moderate", "impact": "degraded",
                 "detection": "every DNS query answered by us, one log line per name"},
    "captive_portal": {"category": "rogue", "noise": "moderate", "impact": "degraded",
                       "detection": "a portal page asking for credentials, served by us"},
    "arp_mitm": {"category": "rogue", "noise": "loud", "impact": "degraded",
                 "detection": "gratuitous ARP replies claiming the gateway: traffic "
                              "passes through our radio"},
    "beacon_clone": {"category": "rogue", "noise": "moderate", "impact": "degraded",
                     "detection": "beacons with the network's own BSSID and elements, sent "
                                  "from a second radio"},
    "wpa3_downgrade_twin": {"category": "rogue", "noise": "moderate", "impact": "degraded",
                            "detection": "a twin with SAE and PMF stripped: clients that "
                                         "do not require WPA3 may join it"},
    # -- protocol-level analysis and manipulation -------------------------- #
    "krack_detect": {"category": "offline", "noise": "silent", "impact": "info",
                     "detection": "nothing on air; the retransmission pattern is read out "
                                  "of a capture we already have"},
    "kr00k_detect": {"category": "offline", "noise": "silent", "impact": "info",
                     "detection": "nothing on air; scans captured ciphertext for the "
                                  "all-zero keystream signature"},
    "fragattacks_detect": {"category": "offline", "noise": "silent", "impact": "info",
                           "detection": "nothing on air; looks for A-MSDU and fragment "
                                        "patterns in stored frames"},
    "ft_audit": {"category": "offline", "noise": "silent", "impact": "info",
                 "detection": "nothing on air; reads mobility-domain and AKM elements"},
    "pmf_downgrade_probe": {"category": "rogue", "noise": "quiet", "impact": "degraded",
                            "detection": "association attempts with MFPC/MFPR cleared: the "
                                         "AP either enforces PMF or negotiates it away"},
    "btm_hijack": {"category": "rogue", "noise": "quiet", "impact": "degraded",
                   "detection": "BTM requests naming candidate BSSIDs that are not the "
                                "AP's neighbours"},
    "beacon_rate_audit": {"category": "offline", "noise": "silent", "impact": "info",
                          "detection": "nothing on air; compares beacon intervals, TSF and "
                                       "sequence numbers in a capture"},
    "tsf_clone_detect": {"category": "offline", "noise": "silent", "impact": "info",
                         "detection": "nothing on air; TSF timers compared between "
                                      "identical BSSIDs"},
    "client_fingerprint": {"category": "offline", "noise": "silent", "impact": "info",
                           "detection": "nothing on air; reads probe requests and their "
                                        "element sets"},
    # -- capture, second wave ---------------------------------------------- #
    "injection_test": {"category": "capture", "noise": "quiet", "impact": "none",
                       "detection": "aireplay-ng's own test frames: a handful of probe "
                                    "requests, then it stops"},
    "arp_replay": {"category": "wep", "noise": "loud", "impact": "degraded",
                   "detection": "injected ARP frames that the AP rebroadcasts; network "
                                "traffic rises while IVs accumulate"},
    "pcap_replay": {"category": "capture", "noise": "loud", "impact": "degraded",
                    "detection": "frames replayed from a capture file at their recorded "
                                 "timing"},
    "mac_filter_probe": {"category": "survey", "noise": "quiet", "impact": "none",
                         "detection": "association attempts from random MACs; a MAC filter "
                                      "rejects them visibly"},
    "channel_sweep": {"category": "survey", "noise": "silent", "impact": "none",
                      "detection": "nothing but channel changes on our own radio"},
    # -- network-layer audits ---------------------------------------------- #
    "ap_admin_audit": {"category": "survey", "noise": "quiet", "impact": "none",
                       "detection": "TCP connections to management ports: a port scan of "
                                    "one host"},
    "upnp_audit": {"category": "survey", "noise": "quiet", "impact": "none",
                   "detection": "one SSDP M-SEARCH multicast, then HTTP GETs to the "
                                "description URLs"},
    "snmp_audit": {"category": "survey", "noise": "quiet", "impact": "none",
                   "detection": "SNMP GET requests carrying default community strings"},
    "dns_audit": {"category": "survey", "noise": "quiet", "impact": "none",
                  "detection": "a handful of DNS queries to the network's own resolver"},
    "wpad_audit": {"category": "survey", "noise": "quiet", "impact": "none",
                   "detection": "DNS queries for the wpad names, then a GET for wpad.dat"},
    "rogue_dhcp_detect": {"category": "survey", "noise": "silent", "impact": "info",
                          "detection": "nothing but listening for DHCP replies from the "
                                       "segment"},
    "arp_spoof_detect": {"category": "survey", "noise": "silent", "impact": "info",
                         "detection": "nothing on air; reads ARP claims from a capture or "
                                      "a listen window"},
    "ipv6_ra_audit": {"category": "survey", "noise": "silent", "impact": "info",
                      "detection": "nothing but listening for router advertisements"},
    # -- denial of service, second wave ------------------------------------ #
    "disassoc_flood": {"category": "dos", "noise": "extreme", "impact": "outage",
                       "detection": "disassociation frames in a loop: every client of the "
                                    "AP drops, and rules that count deauths do not fire"},
    "rts_flood": {"category": "dos", "noise": "extreme", "impact": "degraded",
                  "detection": "RTS frames with a maximal duration reserve the medium and "
                               "are never answered: control frames only"},
    "cts_flood": {"category": "dos", "noise": "extreme", "impact": "degraded",
                  "detection": "CTS-to-self frames hold the channel silent; no management "
                               "frame is on air at all"},
    "channel_switch_flood": {"category": "dos", "noise": "loud", "impact": "outage",
                             "detection": "beacons carrying CSA elements, one channel move "
                                          "after another"},
    "sa_query_flood": {"category": "dos", "noise": "loud", "impact": "degraded",
                       "detection": "SA Query requests with rotating tokens: the AP's "
                                    "association state is walked at frame rate"},
    "tdls_teardown_flood": {"category": "dos", "noise": "loud", "impact": "degraded",
                            "detection": "TDLS Teardown action frames break direct links "
                                         "and push traffic through the AP"},
    "probe_response_flood": {"category": "dos", "noise": "loud", "impact": "degraded",
                             "detection": "probe responses from BSSIDs that do not exist: "
                                          "client scan lists fill with phantoms"},
    "dhcp_discover_flood": {"category": "dos", "noise": "loud", "impact": "degraded",
                            "detection": "DHCP DISCOVER broadcasts from fake stations walk "
                                         "the server through its pool"},
    # -- offline analysis, second wave -------------------------------------- #
    "capture_quality": {"category": "offline", "noise": "silent", "impact": "info",
                        "detection": "nothing on air; scores the session's own captures"},
    "wordlist_audit": {"category": "offline", "noise": "silent", "impact": "info",
                       "detection": "nothing on air; reads the configured wordlists"},
    "hash_audit": {"category": "offline", "noise": "silent", "impact": "info",
                   "detection": "nothing on air; parses mode-22000 hash files"},
    "crack_plan": {"category": "offline", "noise": "silent", "impact": "info",
                   "detection": "nothing on air; a PBKDF2 benchmark and a multiplication"},
    "vendor_fingerprint": {"category": "offline", "noise": "silent", "impact": "info",
                           "detection": "nothing on air; groups the scanner's findings by "
                                        "vendor and model"},
    "beacon_timeline": {"category": "offline", "noise": "silent", "impact": "info",
                        "detection": "nothing on air; the session's own history of the "
                                     "neighbourhood"},
    "wordlist_mine": {"category": "offline", "noise": "silent", "impact": "info",
                      "detection": "nothing on air; candidates derived from the SSIDs and "
                                   "vendors already seen"},
    "pmk_check": {"category": "offline", "noise": "silent", "impact": "loot",
                  "detection": "nothing on air; recomputes MICs with keys the session "
                               "already holds"},
    "loot_manifest": {"category": "offline", "noise": "silent", "impact": "info",
                      "detection": "nothing on air; SHA-256 over the session's artefacts"},
    "cleartext_sniff": {"category": "offline", "noise": "silent", "impact": "loot",
                        "detection": "nothing on air; reads credentials out of a capture"},
}


def register_batch(module) -> List[str]:
    """Merge a batch module's metadata into the table, and return the names it added.

    Batch modules carry their metadata next to their code (``META``), because the two
    are written together and a table in another file is a table that gets forgotten.
    This is the one place that copies it in, so :func:`validate` still has a single
    table to check and the UI still has a single table to read.
    """
    added: List[str] = []
    for name, row in dict(getattr(module, "META", {}) or {}).items():
        if name not in ATTACK_META:
            added.append(name)
        entry = dict(row)
        entry.setdefault("domain", _domain_of(name, entry))
        ATTACK_META[name] = entry
    return added


def _domain_of(name: str, row: Dict[str, Any]) -> str:
    """Which edition an attack belongs to: the row's own answer, else its name.

    The Bluetooth modules predate the edition field, and their names are the honest
    signal: everything that talks to a controller, a GATT server or a profile starts
    with ``bt_`` or ``ble_``.  Everything else is the wireless work this tool began as.
    """
    if row.get("domain"):
        return str(row["domain"])
    return "bluetooth" if name.startswith(("bt_", "ble_", "blue")) else "wifi"


def meta_for(name: str, **overrides: str) -> Dict[str, Any]:
    """The metadata for one attack, with the class's own attributes winning.

    Beyond the three axes the planner sorts by, a row may carry the *edition*
    (``domain``: wifi, bluetooth or it), the device types it applies to (``devices``) and
    the port/protocol it speaks — which is what the web UI's edition switch, its device
    list and its per-device attack list are built from.
    """
    meta = dict(ATTACK_META.get(name, {}))
    meta.setdefault("category", "capture")
    meta.setdefault("noise", "moderate")
    meta.setdefault("impact", "info")
    meta.setdefault("detection", "")
    meta.setdefault("domain", "wifi")
    meta.setdefault("devices", [])
    for key, value in overrides.items():
        if value:
            meta[key] = value
    return meta


def _device_ids() -> set:
    try:
        from ..itdev import device_ids
        return set(device_ids())
    except Exception:                                     # pragma: no cover - defensive
        return set()


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
        domain = meta.get("domain", "wifi")
        if domain not in DOMAIN_IDS:
            problems.append(f"{name}: unknown domain {domain!r}")
        devices = meta.get("devices") or []
        if isinstance(devices, str):
            problems.append(f"{name}: devices must be a list, not a string")
        else:
            unknown = [dev for dev in devices if dev not in _device_ids()]
            if unknown:
                problems.append(f"{name}: unknown device type(s) {', '.join(unknown[:3])}")
    for name in sorted(set(ATTACK_META) - known):
        problems.append(f"{name}: metadata for an attack that does not exist")
    return problems


__all__ = ["ATTACK_META", "CATEGORIES", "DOMAINS", "DOMAIN_IDS", "IMPACT_LEVELS", "IMPACT_STYLE", "NOISE_LEVELS",
           "NOISE_STYLE", "category_label", "meta_for", "register_batch", "validate"]
