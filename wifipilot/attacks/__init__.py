"""Attack registry: every primitive wifipilot can execute.

A hundred and seven attacks, and the registry is the single place that knows all of
them.  The
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
from .capture3 import (ArpReplayAttack, ChannelSweepAttack, InjectionTestAttack,
                       MacFilterProbeAttack, PcapReplayAttack)
from .dos2 import (ChannelSwitchFloodAttack, CtsFloodAttack, DhcpDiscoverFloodAttack,
                   DisassocFloodAttack, ProbeResponseFloodAttack, RtsFloodAttack,
                   SaQueryFloodAttack, TdlsTeardownFloodAttack)
from .enterprise import EnterpriseSurveyAttack
from .enterprise2 import (CertificateAuditAttack, EapIdentityHarvestAttack,
                          EapMethodProbeAttack, EapTlsVersionAttack,
                          Mschapv2CrackAttack, RadiusSecretTestAttack,
                          TtlsInnerAuditAttack)
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
from .offline2 import (BeaconTimelineAttack, CaptureQualityAttack, CleartextSniffAttack,
                       CrackPlanAttack, HashAuditAttack, LootManifestAttack,
                       PmkCheckAttack, VendorFingerprintAttack, WordlistAuditAttack,
                       WordlistMineAttack)
from .handshake import HandshakeAttack
from .hidden import HiddenSsidAttack
from .lure import (ApIsolationAuditAttack, CsaAttack, KarmaDetectAttack,
                   SsidBruteforceAttack, SsidConfusionAttack)
from .meta import (ATTACK_META, CATEGORIES, IMPACT_LEVELS, IMPACT_STYLE,
                   NOISE_LEVELS, NOISE_STYLE, category_label, meta_for,
                   register_batch, validate)
from .offensive import RogueRadiusAttack, ROGUE_TOOLS
from .passive import PassiveAttack
from .protocol2 import (BeaconRateAuditAttack, BtmHijackAttack, ClientFingerprintAttack,
                        FragAttacksDetectAttack, FtAuditAttack, KrackDetectAttack,
                        Kr00kDetectAttack, PmfDowngradeProbeAttack, TsfCloneDetectAttack)
from .pmkid import PmkidAttack, PmkidFloodAttack
from .rogue import RogueApAttack
from .rogue2 import (ArpMitmAttack, BeaconCloneAttack, CaptivePortalAttack, DnsSinkAttack,
                     RogueDhcpAttack, Wpa3DowngradeTwinAttack)
from .survey2 import SaeGroupAuditAttack
from .survey3 import (ApAdminAuditAttack, ArpSpoofDetectAttack, DnsAuditAttack,
                      Ipv6RaAuditAttack, RogueDhcpDetectAttack, SnmpAuditAttack,
                      UpnpAuditAttack, WpadAuditAttack)
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
    # -- offline, second wave (analysis of what is already held) -------------
    "capture_quality": CaptureQualityAttack,
    "hash_audit": HashAuditAttack,
    "wordlist_audit": WordlistAuditAttack,
    "crack_plan": CrackPlanAttack,
    "vendor_fingerprint": VendorFingerprintAttack,
    "beacon_timeline": BeaconTimelineAttack,
    "wordlist_mine": WordlistMineAttack,
    "pmk_check": PmkCheckAttack,
    "loot_manifest": LootManifestAttack,
    "cleartext_sniff": CleartextSniffAttack,
    # -- protocol analysis: the bugs, read out of captures ------------------
    "krack_detect": KrackDetectAttack,
    "kr00k_detect": Kr00kDetectAttack,
    "fragattacks_detect": FragAttacksDetectAttack,
    "ft_audit": FtAuditAttack,
    "beacon_rate_audit": BeaconRateAuditAttack,
    "tsf_clone_detect": TsfCloneDetectAttack,
    "client_fingerprint": ClientFingerprintAttack,
    # -- enterprise, second wave --------------------------------------------
    "eap_identity_harvest": EapIdentityHarvestAttack,
    "eap_method_probe": EapMethodProbeAttack,
    "certificate_audit": CertificateAuditAttack,
    "ttls_inner_audit": TtlsInnerAuditAttack,
    "eap_tls_version": EapTlsVersionAttack,
    "mschapv2_crack": Mschapv2CrackAttack,
    "radius_secret_test": RadiusSecretTestAttack,
    # -- capture and injection, second wave ---------------------------------
    "injection_test": InjectionTestAttack,
    "arp_replay": ArpReplayAttack,
    "pcap_replay": PcapReplayAttack,
    "mac_filter_probe": MacFilterProbeAttack,
    "channel_sweep": ChannelSweepAttack,
    # -- network-layer audits (the services behind the wireless network) ----
    "ap_admin_audit": ApAdminAuditAttack,
    "upnp_audit": UpnpAuditAttack,
    "snmp_audit": SnmpAuditAttack,
    "dns_audit": DnsAuditAttack,
    "wpad_audit": WpadAuditAttack,
    "rogue_dhcp_detect": RogueDhcpDetectAttack,
    "arp_spoof_detect": ArpSpoofDetectAttack,
    "ipv6_ra_audit": Ipv6RaAuditAttack,
    # -- rogue, second wave --------------------------------------------------
    "rogue_dhcp": RogueDhcpAttack,
    "dns_sink": DnsSinkAttack,
    "captive_portal": CaptivePortalAttack,
    "arp_mitm": ArpMitmAttack,
    "beacon_clone": BeaconCloneAttack,
    "wpa3_downgrade_twin": Wpa3DowngradeTwinAttack,
    # -- frame-level manipulation -------------------------------------------
    "pmf_downgrade_probe": PmfDowngradeProbeAttack,
    "btm_hijack": BtmHijackAttack,
    # -- denial of service, second wave --------------------------------------
    "disassoc_flood": DisassocFloodAttack,
    "rts_flood": RtsFloodAttack,
    "cts_flood": CtsFloodAttack,
    "channel_switch_flood": ChannelSwitchFloodAttack,
    "sa_query_flood": SaQueryFloodAttack,
    "tdls_teardown_flood": TdlsTeardownFloodAttack,
    "probe_response_flood": ProbeResponseFloodAttack,
    "dhcp_discover_flood": DhcpDiscoverFloodAttack,
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
    "capture_quality", "hash_audit", "wordlist_audit", "wordlist_mine", "crack_plan",
    "vendor_fingerprint", "beacon_timeline", "cleartext_sniff", "pmk_check",
    "loot_manifest",
    # read-only surveys
    "passive", "rogue_ap", "ie_audit", "pmf_audit", "saewolf", "sae_group_audit",
    "hidden_ssid", "pnl_harvest", "tracker",
    "ap_admin_audit", "upnp_audit", "snmp_audit", "dns_audit", "wpad_audit",
    "rogue_dhcp_detect", "arp_spoof_detect", "ipv6_ra_audit",
    # capture and protocol analysis
    "pmkid", "handshake", "handshake_broadcast", "pmkid_flood", "hcxdump_capture",
    "injection_test", "arp_replay", "pcap_replay", "mac_filter_probe", "channel_sweep",
    "krack_detect", "kr00k_detect", "fragattacks_detect", "ft_audit",
    "beacon_rate_audit", "tsf_clone_detect", "client_fingerprint",
    # WPS / WEP / enterprise
    "wps_pixie", "wps_ap_pin", "wps_lockout_probe", "wps_pbc", "wps_pin",
    "wep_ivs", "wep_p0841", "wep_chopchop", "wep_fragment", "wep_hirte",
    "enterprise", "eap_identity_harvest", "eap_method_probe", "certificate_audit",
    "ttls_inner_audit", "eap_tls_version", "mschapv2_crack", "radius_secret_test",
    "eapol_logoff",
    # rogue infrastructure and lures
    "karma_detect", "csa_attack", "ssid_bruteforce", "ssid_confusion",
    "ap_isolation_audit", "pmf_downgrade_probe", "btm_hijack", "evil_twin", "karma",
    "rogue_radius", "rogue_dhcp", "dns_sink", "captive_portal", "arp_mitm",
    "beacon_clone", "wpa3_downgrade_twin",
    # denial of service
    "deauth_flood", "auth_flood", "assoc_flood", "null_data_flood", "probe_flood",
    "eapol_start_flood", "sae_commit_flood", "tkip_michael", "wids_confusion",
    "beacon_flood", "disassoc_flood", "rts_flood", "cts_flood",
    "channel_switch_flood", "sa_query_flood", "tdls_teardown_flood",
    "probe_response_flood", "dhcp_discover_flood",
]

#: exactly the names :class:`wifipilot.config.Config` enables out of the box.  The
#: catalogue reports these as ``default_enabled``; everything else — the offline
#: audits included — is opt-in, so a run does exactly what the operator asked for.
# -- batch modules ------------------------------------------------------------ #
# Attacks added in waves live in their own module together with their metadata, and
# register here by being listed once.  A wave is one import and one tuple entry, so
# adding forty attacks does not mean editing forty places.
from . import blehid as _batch_blehid                        # noqa: E402
from . import btattacks as _batch_btattacks                    # noqa: E402
from . import btred as _batch_btred                            # noqa: E402
from . import famous as _batch_famous                          # noqa: E402
from . import itsvc as _batch_itsvc                            # noqa: E402
from . import netdos as _batch_netdos                          # noqa: E402
from . import offline3 as _batch_offline3                      # noqa: E402
from . import offline4 as _batch_offline4                      # noqa: E402

BATCH_MODULES = (_batch_offline3, _batch_offline4, _batch_btattacks,
                 _batch_blehid, _batch_netdos, _batch_btred, _batch_famous,
                 _batch_itsvc)


def _register_batches() -> List[str]:
    """Fold every batch module into the registry, in the order they are listed."""
    added: List[str] = []
    for module in BATCH_MODULES:
        register_batch(module)
        for cls in module.ATTACKS:
            if cls.name in ATTACK_CLASSES:                     # already in the ladder
                continue
            ATTACK_CLASSES[cls.name] = cls
            DEFAULT_ORDER.append(cls.name)
            added.append(cls.name)
    return added


BATCH_ATTACKS: List[str] = _register_batches()

# The planner, the CLI and the AI pilot all take their whitelist from
# ``models.ATTACK_NAMES``: an attack that registers but never reaches that list is an
# attack the pilot cannot choose, so the batch names are appended to it here — in place,
# so every module that already holds a reference sees them.
from ..models import ATTACK_NAMES as _DOMAIN_ATTACK_NAMES            # noqa: E402

for _name in BATCH_ATTACKS:
    if _name not in _DOMAIN_ATTACK_NAMES:
        _DOMAIN_ATTACK_NAMES.append(_name)

DEFAULT_ENABLED = ("pmkid", "handshake", "wps_pixie", "wep_ivs", "hidden_ssid",
                   "tracker")

#: attacks that never transmit anything: pure file analysis, so they need no radio,
#: no monitor interface and no authorisation.  (``pmkid`` is *silent* too, but it
#: still needs a monitor interface and, often, a frame: noisy-in-a-different-way is
#: not the same as offline.)
OFFLINE_ATTACKS = tuple(name for name in DEFAULT_ORDER
                        if ATTACK_META.get(name, {}).get("category") == "offline")

#: every denial-of-service test, derived from the metadata so a new flood cannot be
#: forgotten by the planner's stealth gate
DOS_ATTACKS = tuple(name for name in DEFAULT_ORDER
                    if ATTACK_META.get(name, {}).get("category") == "dos")

#: the four floods that need mdk4; everything else in DOS_ATTACKS is built in-process
MDK4_FLOODS = ("deauth_flood", "auth_flood", "probe_flood", "beacon_flood")

#: attacks the planner only runs when the operator has explicitly named them: every
#: denial-of-service test, plus the two that impersonate a network
OPT_IN_ATTACKS = tuple(name for name in DEFAULT_ORDER
                       if ATTACK_META.get(name, {}).get("category") == "dos") + (
    "rogue_radius", "evil_twin", "karma", "karma_detect", "csa_attack",
    "ssid_confusion", "wps_pbc", "wps_pin", "wps_ap_pin", "handshake_broadcast",
    "hcxdump_capture", "tkip_michael", "wids_confusion",
    # the second wave: rogue services and the frames that reconfigure clients
    "rogue_dhcp", "dns_sink", "captive_portal", "arp_mitm", "beacon_clone",
    "wpa3_downgrade_twin", "pmf_downgrade_probe", "btm_hijack", "pcap_replay",
    "arp_replay",
    # the famous wave: the Wi-Fi replays and the Bluetooth impersonations.  Everything
    # that transmits on the Bluetooth radio is opt-in for the same reason the floods are:
    # a site did not ask to be attacked just because it asked to be assessed.
    "airgeddon_portal", "krack_replay", "fragattacks_inject",
    "bt_blueborne", "bt_bias", "bt_knob", "bt_bluebugging", "bt_blesa",
    "bt_sweyntooth", "bt_bluesnarf", "bt_bluesmack", "bt_hid_injection") + tuple(
    # the IT edition: every attack that talks to a *service* on the network is opt-in.
    # A site that asked for a wireless assessment did not ask for its printers, cameras
    # and PLCs to be greeted by name, so the whole wave is behind an explicit choice.
    name for name in DEFAULT_ORDER if name.startswith("it_"))

__all__ = [
    "Attack", "AttackContext", "AttackOutcome", "ATTACK_CLASSES", "DEFAULT_ORDER",
    "DEFAULT_ENABLED", "OFFLINE_ATTACKS", "OPT_IN_ATTACKS", "DOS_ATTACKS",
    "MDK4_FLOODS", "ATTACK_META",
    "CATEGORIES", "DOMAINS", "DOMAIN_IDS",
    "NOISE_LEVELS", "IMPACT_LEVELS", "NOISE_STYLE", "IMPACT_STYLE",
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
    # second-wave classes
    "CaptureQualityAttack", "HashAuditAttack", "WordlistAuditAttack", "CrackPlanAttack",
    "VendorFingerprintAttack", "BeaconTimelineAttack", "WordlistMineAttack",
    "PmkCheckAttack", "LootManifestAttack", "CleartextSniffAttack",
    "KrackDetectAttack", "Kr00kDetectAttack", "FragAttacksDetectAttack", "FtAuditAttack",
    "BeaconRateAuditAttack", "TsfCloneDetectAttack", "ClientFingerprintAttack",
    "EapIdentityHarvestAttack", "EapMethodProbeAttack", "CertificateAuditAttack",
    "TtlsInnerAuditAttack", "EapTlsVersionAttack", "Mschapv2CrackAttack",
    "RadiusSecretTestAttack", "InjectionTestAttack", "ArpReplayAttack",
    "PcapReplayAttack", "MacFilterProbeAttack", "ChannelSweepAttack",
    "ApAdminAuditAttack", "UpnpAuditAttack", "SnmpAuditAttack", "DnsAuditAttack",
    "WpadAuditAttack", "RogueDhcpDetectAttack", "ArpSpoofDetectAttack",
    "Ipv6RaAuditAttack", "RogueDhcpAttack", "DnsSinkAttack", "CaptivePortalAttack",
    "ArpMitmAttack", "BeaconCloneAttack", "Wpa3DowngradeTwinAttack",
    "PmfDowngradeProbeAttack", "BtmHijackAttack", "DisassocFloodAttack",
    "RtsFloodAttack", "CtsFloodAttack", "ChannelSwitchFloodAttack",
    "SaQueryFloodAttack", "TdlsTeardownFloodAttack", "ProbeResponseFloodAttack",
    "DhcpDiscoverFloodAttack",
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
        # the class's own declarations win where it makes one (base.Attack documents
        # category/noise/impact as "normally taken from the metadata table, overridable
        # per class"), so the catalogue cannot disagree with the attack it describes
        meta = meta_for(name, category=getattr(cls, "category", "") or "",
                        noise=getattr(cls, "noise", "") or "",
                        impact=getattr(cls, "impact", "") or "")
        out.append({
            "name": name, "label": cls.label, "tool": cls.tool,
            "description": cls.description, "requires": list(cls.requires),
            "needs_injection": cls.needs_injection,
            "applies_to": list(cls.applies_to),
            "category": meta["category"],
            "category_label": category_label(str(meta["category"])),
            "noise": meta["noise"], "impact": meta["impact"],
            "detection": meta["detection"],
            "domain": meta.get("domain", "wifi"),
            "devices": list(meta.get("devices", []) or []),
            "port": meta.get("port", 0),
            "protocol": meta.get("protocol", ""),
            # "offline" means no radio at all: the category is the test, not the
            # silence — a PMKID request is silent but it is not analysis
            "offline": meta["category"] == "offline" and not cls.needs_injection,
            "default_enabled": name in DEFAULT_ENABLED,
        })
    return out
