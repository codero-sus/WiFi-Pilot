"""The fourth attack batch: information elements, raw frames, Logoff, Karma, floods.

Four things are new and each of them is checked against something this repository
builds itself:

* :mod:`wifipilot.ies` — a beacon's information elements decoded element by element,
  including the vendor elements (WPS, WMM, WPA1) that are the reason the audit exists.
* :mod:`wifipilot.rawtx` — the frames for the EAPOL-Logoff, packed the way the
  repository's own pcap decoder reads them back.
* the *audit* pair — ``ie_audit`` and ``pnl_harvest`` — which read, annotate the
  session, and write a trace, but transmit nothing.
* the *active* pair — ``eapol_logoff`` and ``karma`` — plus the two new flood modes,
  which are asserted to be bounded, documented as denial of service, and to report
  the finding rather than a password.

The last test in the file is the one that keeps this honest: every attack the build
ships has to be named in the documentation, and the documentation's count has to be
the registry's count.  A tool that grows an attack nobody documented has grown a
secret.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from wifipilot import ies, rawtx, synth
from wifipilot.attacks import (ATTACK_CLASSES, DEFAULT_ORDER, attack_catalog,
                               IeAuditAttack, PnlHarvestAttack)
from wifipilot.attacks.audit import PnlHarvestAttack as PnlClass
from wifipilot.attacks.flood import (AuthFloodAttack, BeaconFloodAttack,
                                     DeauthFloodAttack, ProbeFloodAttack)
from wifipilot.attacks.karma import KarmaAttack, patterns
from wifipilot.attacks.logoff import EapolLogoffAttack, logoff_preview
from wifipilot.config import Config
from wifipilot.engine import Engine
from wifipilot.models import (ATTACK_NAMES, STATUS_SUCCESS, AccessPoint, Client,
                              SessionStats)
from wifipilot.planner import explain_failure, preferred_attacks, validate_plan
from wifipilot.session import Session

#: the six attacks this batch adds on top of the twenty-one already shipped
NEW_ATTACKS = ("ie_audit", "pnl_harvest", "eapol_logoff", "karma", "auth_flood",
               "probe_flood")

AP_MAC = "d0:9e:12:9d:36:cc"
STA_MAC = "02:00:00:00:00:09"


def _beacon(extra: bytes = b"", rates: bytes = synth.MODERN_RATES,
            ssid: str = "HOME-2F4A", pmf: bool = False) -> bytes:
    """The management body of a beacon, which is what the IE parser is fed."""
    return synth.build_beacon(ssid, AP_MAC, channel=6, akm="psk", pmf=pmf,
                              extra_ies=extra, rates=rates)[36:]


def _engine(tmp_path, attacks=None, timeout=3) -> Engine:
    config = Config()
    config.demo = True
    config.ollama.enabled = False
    config.output_dir = str(tmp_path / "loot")
    config.session_dir = str(tmp_path / "sessions")
    config.scan_time = 2
    config.attack_timeout = timeout
    config.use_masks = False
    config.attacks = list(attacks or NEW_ATTACKS)
    engine = Engine(config, demo=True)
    engine.prepare()
    engine.scan_for(2)
    return engine


@pytest.fixture(scope="module")
def engine(tmp_path_factory):
    """One demo neighbourhood, scanned once, shared by the attack-level tests."""
    return _engine(tmp_path_factory.mktemp("more"))


def _ap(engine: Engine, essid: str) -> AccessPoint:
    for ap in engine.session.aps.values():
        if ap.essid == essid:
            return ap
    raise AssertionError(f"no {essid} in the demo neighbourhood")


# --------------------------------------------------------------------------- #
# wifipilot/ies.py — reading what an AP says about itself
# --------------------------------------------------------------------------- #

def test_a_beacon_is_split_into_its_elements():
    elements = ies.parse_ies(_beacon())
    tags = [element.tag for element in elements]
    assert tags[:4] == [0, 1, 3, 48]                     # SSID, rates, DS, RSN
    assert [element.name for element in elements[:3]] == ["SSID", "Supported rates",
                                                          "DS parameter set"]
    assert elements[0].text() == "HOME-2F4A"
    assert elements[0].hex().startswith("484f4d45")       # "HOME"


def test_an_element_that_is_cut_short_does_not_break_the_walk():
    # an AP that pads badly must not hide the elements behind it
    payload = _beacon() + b"\xdd\x20"                      # claims 32 bytes, has none
    elements = ies.parse_ies(payload)
    assert [element.tag for element in elements[:4]] == [0, 1, 3, 48]


def test_the_rsn_element_is_decoded_field_by_field():
    facts = ies.decode_ies(ies.parse_ies(_beacon()))
    rsn = facts["rsn"]
    assert rsn["version"] == 1
    assert rsn["ciphers"] == ["CCMP"] and rsn["group"] == "CCMP"
    assert rsn["akm"] == ["PSK"]
    assert facts["ssid"] == "HOME-2F4A" and facts["channel"] == 6
    assert facts["pmf_capable"] is False and facts["pmf_required"] is False
    assert facts["rates"]


def test_a_transition_mode_beacon_is_read_as_sae_plus_psk():
    body = synth.build_beacon("Mix", AP_MAC, akm="sae+psk", pmf=True)[36:]
    facts = ies.decode_ies(ies.parse_ies(body))
    assert facts["rsn"]["akm"] == ["SAE", "PSK"]
    assert facts["rsn"]["transition_mode"] is True
    assert facts["pmf_capable"] and facts["pmf_required"]


def test_vendor_elements_are_dispatched_by_their_four_byte_vendor_id():
    wps = synth.wps_element(manufacturer="Cisco", model="AIR-CAP2702",
                            methods=0x0088)
    facts = ies.decode_ies(ies.parse_ies(_beacon(extra=wps)))
    assert facts["wps"]["manufacturer"] == "Cisco"
    assert facts["wps"]["model"] == "AIR-CAP2702"
    assert facts["wps"]["methods"] == ["display", "push button"]
    assert facts["wps"]["config_methods_mask"] == 0x0088
    assert facts["vendor_ouis"] == ["00:50:f2:04"]              # four bytes, not three
    assert ies.vendor_name("00:50:f2:04") == "WPS (Wi-Fi Alliance)"
    assert ies.vendor_name("aa:bb:cc:dd") == "aa:bb:cc:dd"      # unknown: no guessing


def test_a_locked_wps_ap_says_so():
    wps = synth.wps_element(locked=True, methods=0x0008)
    facts = ies.decode_ies(ies.parse_ies(_beacon(extra=wps)))
    assert facts["wps"]["locked"] is True
    assert facts["wps"]["methods"] == ["display"]
    assert facts["wps"]["config_methods_mask"] & ies.WPS_PUSH_BUTTON_BITS == 0


def test_wps_configuration_methods_are_never_ghost_matched():
    # the table is single-bit on purpose: 0x0088 is display+push-button, not "0x80
    # because 0x88 & 0x80 is non-zero"
    assert ies.method_names(0x0088) == ["display", "push button"]
    assert ies.method_names(0x2080) == ["virtual push button"]
    assert ies.method_names(0x2008) == ["display", "virtual display pin"]
    assert ies.method_names(0x0100) == ["keypad"]
    assert ies.method_names(0) == []


def test_ht_vht_and_he_elements_are_not_confused():
    extra = synth.ht_capabilities(width40=True) + synth.vht_capabilities()
    facts = ies.decode_ies(ies.parse_ies(_beacon(extra=extra)))
    assert facts["ht"] is True and facts["vht"] is True
    assert facts["channel_width"] in ("40 MHz", "80 MHz")
    only_ht = ies.decode_ies(ies.parse_ies(_beacon(extra=synth.ht_capabilities())))
    assert only_ht["ht"] is True and only_ht["vht"] is False
    assert facts["max_mcs"] >= 0 and facts["vht"] is True


def test_roaming_and_mobility_elements_are_read():
    extra = synth.extended_capabilities() + synth.mobility_domain(b"\x00\x01")
    facts = ies.decode_ies(ies.parse_ies(_beacon(extra=extra)))
    assert facts["roaming"] == {"r": True, "k": False, "v": True}
    assert facts["mobility_domain"] == "0001"


def test_a_country_element_is_read_as_a_regulatory_domain():
    facts = ies.decode_ies(ies.parse_ies(_beacon(extra=synth.country_element("IN"))))
    assert facts["country"] == "IN"
    # an AP with no country element reports an empty code, which is the finding
    assert ies.decode_ies(ies.parse_ies(_beacon()))["country"] == ""


def test_a_legacy_beacon_is_annotated_as_such():
    facts = ies.decode_ies(ies.parse_ies(_beacon(rates=synth.LEGACY_RATES)))
    entry = ies.BssElements(bssid=AP_MAC, essid="Old", facts=facts)
    ies._annotate_legacy(entry)
    assert facts["legacy_rates_only"] is True
    # and a modern one is not
    modern = ies.decode_ies(ies.parse_ies(_beacon(extra=synth.ht_capabilities())))
    entry = ies.BssElements(bssid=AP_MAC, essid="New", facts=modern)
    ies._annotate_legacy(entry)
    assert modern["legacy_rates_only"] is False
    # ...and no rates at all is not "legacy", it is "unknown"
    empty = ies.BssElements(bssid=AP_MAC, essid="?", facts={})
    ies._annotate_legacy(empty)
    assert empty.facts["legacy_rates_only"] is False


# --------------------------------------------------------------------------- #
# wifipilot/ies.py — findings
# --------------------------------------------------------------------------- #

def _network(**facts) -> dict:
    base = {"bssid": AP_MAC, "essid": "HOME-2F4A", "facts": {}}
    base["facts"].update(facts)
    return base


def _kinds(network: dict, **kwargs) -> list:
    return [item["kind"] for item in ies.ie_findings([network], **kwargs)]


def test_an_open_network_is_a_high_finding_hidden_or_not():
    for network in (_network(), {**_network(), "essid": "",
                                 "facts": {"ssid": ""}}):
        findings = {item["kind"]: item for item in ies.ie_findings([network])}
        assert findings["ie_open_network"]["severity"] == "high"
    # ...and the hidden variant says so in the detail, because hiding an SSID is a
    # setting, not a control
    hidden = ies.ie_findings([{**_network(), "essid": "", "facts": {"ssid": ""}}])
    open_finding = [item for item in hidden if item["kind"] == "ie_open_network"][0]
    assert "hidden" in open_finding["detail"]
    # a real RSN network never gets the finding at all
    assert "ie_open_network" not in _kinds(_network(rsn={"akm": ["PSK"]}))


def test_tkip_and_wpa1_are_high_findings():
    tkip = _network(rsn={"tkip": True, "akm": ["PSK"]}, pmf_capable=False)
    assert "ie_tkip" in _kinds(tkip)
    wpa1 = _network(wpa1=True)
    assert "ie_wpa1" in _kinds(wpa1)


def test_pmf_findings_distinguish_absent_from_optional():
    assert "ie_no_pmf" in _kinds(_network(rsn={"akm": ["PSK"]}))
    optional = _network(rsn={"akm": ["PSK"], "tkip": False},
                        pmf_capable=True, pmf_required=False)
    assert "ie_pmf_optional" in _kinds(optional)
    required = _network(rsn={"akm": ["SAE"]}, pmf_capable=True, pmf_required=True)
    kinds = _kinds(required)
    assert "ie_no_pmf" not in kinds and "ie_pmf_optional" not in kinds


def test_wps_and_the_missing_push_button_are_separate_findings():
    enabled = _network(rsn={"akm": ["PSK"]},
                       wps={"present": True, "locked": False, "methods": ["keypad"],
                            "config_methods_mask": 0x0100})
    kinds = _kinds(enabled)
    assert kinds[0] == "ie_wps_enabled"                      # worst first
    assert "ie_wps_no_pbc" in kinds
    locked = _network(rsn={"akm": ["PSK"]},
                      wps={"present": True, "locked": True, "methods": ["display"],
                           "config_methods_mask": 0x0088})
    severities = {item["kind"]: item["severity"]
                  for item in ies.ie_findings([locked])}
    assert severities["ie_wps_enabled"] == "medium"           # locked is less urgent


def test_ft_without_required_pmf_is_its_own_finding():
    network = _network(rsn={"akm": ["PSK"]}, roaming={"r": True, "k": False},
                       pmf_capable=True, pmf_required=False)
    assert "ie_ft_without_pmf" in _kinds(network)
    safe = _network(rsn={"akm": ["SAE"]}, roaming={"r": True, "k": False},
                    pmf_capable=True, pmf_required=True)
    assert "ie_ft_without_pmf" not in _kinds(safe)


def test_forty_megahertz_in_two_point_four_ghz_is_a_finding_only_there():
    busy = _network(rsn={"akm": ["PSK"]}, ht=True, channel_width="40 MHz", channel=6,
                    country={"code": "IN"})
    assert "ie_40mhz_2ghz" in _kinds(busy)
    five = _network(rsn={"akm": ["PSK"]}, ht=True, channel_width="40 MHz", channel=44,
                    country={"code": "IN"})
    assert "ie_40mhz_2ghz" not in _kinds(five)


def test_a_busy_channel_is_only_reported_when_low_findings_are_wanted():
    network = _network(rsn={"akm": ["PSK"]}, country={"code": "IN"},
                       bss_load={"utilisation_percent": 88, "stations": 41})
    assert "ie_busy_channel" not in _kinds(network, include_low=False)
    assert "ie_busy_channel" in _kinds(network, include_low=True)


def test_findings_come_out_worst_first():
    network = _network(roaming={"r": True}, ht=True, channel_width="40 MHz",
                       channel=6, wps={"present": True, "locked": False,
                                       "methods": ["keypad"],
                                       "config_methods_mask": 0x0100})
    ranking = [ies._SEVERITY_RANK[item["severity"]]
               for item in ies.ie_findings([network])]
    assert ranking == sorted(ranking)
    assert ranking[0] == 1                                   # something high comes first


def test_the_vendor_breakdown_counts_ouis():
    wps = synth.wps_element(manufacturer="Cisco", model="AIR-CAP2702")
    extra = wps + synth.ht_capabilities()
    facts = ies.decode_ies(ies.parse_ies(_beacon(extra=extra)))
    entry = {"bssid": AP_MAC, "essid": "HOME-2F4A", "facts": facts}
    breakdown = ies.vendor_breakdown([entry])
    assert breakdown and breakdown[0]["oui"] == "00:50:f2:04"
    assert breakdown[0]["vendor"] == "WPS (Wi-Fi Alliance)"
    assert breakdown[0]["count"] == 1
    # two vendor elements with the same OUI are two rows, not one
    double = {"bssid": AP_MAC, "essid": "HOME",
              "facts": {"vendor_ouis": ["00:50:f2:04", "00:50:f2:04"]}}
    assert ies.vendor_breakdown([double])[0]["count"] == 2


# --------------------------------------------------------------------------- #
# wifipilot/ies.py — reading a capture
# --------------------------------------------------------------------------- #

def test_beacons_and_probe_requests_are_read_from_a_capture(tmp_path):
    path = str(tmp_path / "read.pcap")
    # synth.write_pcap takes the management body, not a radiotap-prefixed frame
    synth.write_pcap(path, [
        synth.build_beacon("HOME-2F4A", AP_MAC, channel=6,
                           extra_ies=synth.wps_element(manufacturer="Cisco",
                                                       model="AIR-CAP2702")
                           + synth.country_element("IN")),
        synth.build_beacon("", "8c:3f:fe:50:73:a6", channel=11),   # hidden SSID
        synth.build_probe_request(STA_MAC, "HOME-2F4A"),
    ], spacing=0.01)
    result = ies.capture_beacons(path)
    # only what the APs said: the probe request is a client frame and is read by the
    # PNL harvester's decoder instead, which is a different question
    assert result["frames"] == 2
    networks = {entry["bssid"]: entry for entry in result["networks"]}
    assert set(networks) == {AP_MAC, "8c:3f:fe:50:73:a6"}
    assert networks[AP_MAC]["essid"] == "HOME-2F4A"
    assert networks[AP_MAC]["facts"]["wps"]["model"] == "AIR-CAP2702"
    assert networks[AP_MAC]["facts"]["country"] == "IN"
    hidden = networks["8c:3f:fe:50:73:a6"]
    assert hidden["hidden"] is True and hidden["essid"] == "<hidden>"
    assert hidden["kinds"]["beacon"] == 1
    assert result["note"].startswith("read-only")
    assert "elements" not in networks[AP_MAC]["facts"]        # the raw blob is dropped
    # ...and the other decoder reads the client half of the same capture
    from wifipilot.sniff import probe_requests
    probes = probe_requests(path)
    assert STA_MAC in probes and "HOME-2F4A" in probes[STA_MAC].ssids


# --------------------------------------------------------------------------- #
# wifipilot/rawtx.py — the frames
# --------------------------------------------------------------------------- #

def test_the_frame_control_byte_packs_type_and_subtype_the_way_the_decoder_reads():
    assert rawtx.frame_control(0, 8) == (0x80, 0)                # beacon
    assert rawtx.frame_control(0, 12) == (0xC0, 0)               # deauthentication
    assert rawtx.frame_control(2, 0) == (0x08, 0)                # data
    assert rawtx.frame_control(2, 8, flags=0x02) == (0x88, 0x02)  # QoS data, FromDS


def test_a_deauthentication_frame_is_addressed_to_whom_it_should_be():
    frame = rawtx.build_deauth(AP_MAC, STA_MAC)
    assert len(frame) == 35                                  # radiotap 9 + 24 header + 2
    assert rawtx.header_offset(frame) == 9                   # the radiotap's own length
    assert rawtx.describe([frame]) == [("deauthentication", 35)]
    body = rawtx.frame_only(frame)                           # the 802.11 frame itself
    assert len(body) == 26 and body[0] == 0xC0
    assert body[4:10] == rawtx._mac_bytes(STA_MAC)            # addr1: who it is for
    assert body[10:16] == rawtx._mac_bytes(AP_MAC)            # addr2: who it is from
    assert body[16:22] == rawtx._mac_bytes(AP_MAC)            # addr3: the BSSID
    # a client-spoofed frame swaps the transmitter, which is the whole point of the flag
    other = rawtx.frame_only(rawtx.build_deauth(AP_MAC, STA_MAC, station_is_source=True))
    assert other[4:10] == rawtx._mac_bytes(AP_MAC)
    assert other[10:16] == rawtx._mac_bytes(STA_MAC)
    # ...and a disassociation is a different subtype, not a different name
    assert rawtx.describe([rawtx.build_deauth(AP_MAC, STA_MAC,
                                              disassociate=True)])[0][0] == \
        "disassociation"


def test_the_eapol_logoff_is_a_data_frame_from_the_ap_to_the_client():
    frame = rawtx.build_eapol_logoff(AP_MAC, STA_MAC)
    assert rawtx.describe([frame]) == [("EAPOL-Logoff", len(frame))]
    body = rawtx.frame_only(frame)
    assert body[0] == 0x08                                   # data
    assert body[1] == 0x02                                   # FromDS: the AP sent it
    assert body[4:10] == rawtx._mac_bytes(STA_MAC)            # addr1: the client
    assert body[10:16] == rawtx._mac_bytes(AP_MAC)            # addr2: the BSSID
    assert body[16:22] == rawtx._mac_bytes(AP_MAC)
    assert b"\x88\x8e" in body                               # LLC/SNAP for 802.1X
    assert body[-4:] == b"\x01\x02\x00\x00"                  # version 1, Logoff, len 0


def test_the_qos_shape_of_the_same_frame_is_longer_by_the_qos_control():
    plain = rawtx.build_eapol_logoff(AP_MAC, STA_MAC)
    qos = rawtx.build_qos_eapol(AP_MAC, STA_MAC)
    assert len(qos) == len(plain) + 2
    assert rawtx.frame_only(qos)[0] == 0x88                   # QoS data
    # both shapes are a Logoff, so the name is the same and only the length differs
    assert rawtx.describe([plain, qos]) == [("EAPOL-Logoff", len(plain)),
                                            ("EAPOL-Logoff", len(qos))]
    # ...while a Key frame is named for what it is
    assert rawtx.describe([rawtx.build_qos_eapol(AP_MAC, STA_MAC,
                                                 payload_type=3)])[0][0] == "EAPOL-Key"


def test_a_logoff_burst_is_bounded_and_reproducible():
    frames = rawtx.eapol_logoff_burst(AP_MAC, STA_MAC, count=3)
    assert len(frames) == 3
    assert len({bytes(frame) for frame in frames}) == 1        # same frame three times
    assert len(rawtx.eapol_logoff_burst(AP_MAC, STA_MAC, count=5)) == 5


def test_the_frames_survive_the_repository_s_own_pcap_decoder(tmp_path):
    from wifipilot.pcap import _parse_frame

    path = str(tmp_path / "raw.pcap")
    frames = [rawtx.build_deauth(AP_MAC, STA_MAC),
              rawtx.build_eapol_logoff(AP_MAC, STA_MAC),
              rawtx.build_qos_eapol(AP_MAC, STA_MAC, payload_type=1)]
    # write_pcap prepends its own radiotap header: hand it the body, not the frame
    synth.write_pcap(path, [rawtx.frame_only(frame) for frame in frames], spacing=0.01)
    from wifipilot.pcap import iter_frames
    seen = []
    for _ts, buf, start, length in iter_frames(path):
        parsed = _parse_frame(buf, start, length)
        assert parsed is not None
        ftype, subtype, bssid, station, _payload = parsed
        seen.append((ftype, subtype, bssid, station))
    assert seen[0][:2] == (0, 12) and seen[0][2] == AP_MAC
    # the data frames are read back as the AP talking to the client, which is what
    # the logoff claims — the spoof that makes the attack work
    assert seen[1][:2] == (2, 0) and seen[1][2] == AP_MAC
    assert seen[1][3] == STA_MAC
    assert seen[2][:2] == (2, 8) and seen[2][3] == STA_MAC


def test_injection_availability_answers_instead_of_raising():
    assert rawtx.injection_available("wifipilot-there-is-no-such-interface") is False
    assert isinstance(rawtx.injection_available("lo"), bool)


def test_the_logoff_preview_is_a_read_only_list_of_what_would_be_sent():
    lines = logoff_preview(AP_MAC, STA_MAC)
    assert len(lines) == 3
    assert all("bytes" in line for line in lines)
    assert lines[0].startswith("EAPOL-Logoff")


# --------------------------------------------------------------------------- #
# the read-only pair: ie_audit and pnl_harvest
# --------------------------------------------------------------------------- #

def test_ie_audit_reads_the_demo_neighbourhood_and_annotates_the_session(engine):
    ap = _ap(engine, "HOME-2F4A")
    before = engine.session.stats.ie_audits
    outcome = engine.run_attack(ap.bssid, "ie_audit")
    assert outcome is not None and outcome.status == STATUS_SUCCESS
    assert engine.session.stats.ie_audits == before + 1
    assert outcome.extra["networks"], "an audit has to name the networks it read"
    assert isinstance(outcome.extra["findings"], list)
    assert outcome.extra["capture"].endswith(".pcap")
    assert outcome.extra["vendor_elements"], "a vendor element count is what makes it IE"
    # the point of the attack: what it learned is on the session, not just the report
    assert ap.pmf_checked is True
    assert ap.wps_version or ap.wps_manufacturer or ap.wps_model or ap.wps_locked != ""
    # the file it read is kept as evidence — and it is not "loot", because nothing in
    # it can be cracked
    assert any(capture.path.endswith(".pcap") for capture in ap.captures)
    assert not [capture for capture in engine.session.loot() if capture.kind == "ie_audit"]
    assert engine.session.history(ap.bssid)


def test_ie_audit_findings_are_written_once_however_often_it_runs(engine):
    ap = _ap(engine, "HOME-2F4A")
    engine.run_attack(ap.bssid, "ie_audit")
    after_first = [finding for finding in engine.session.findings
                   if finding.kind.startswith("ie_")]
    engine.run_attack(ap.bssid, "ie_audit")
    after_second = [finding for finding in engine.session.findings
                    if finding.kind.startswith("ie_")]
    assert len(after_second) == len(after_first)


def test_pnl_harvest_writes_its_trace_and_reports_the_names_it_found(engine):
    ap = _ap(engine, "HOME-2F4A")
    outcome = engine.run_attack(ap.bssid, "pnl_harvest")
    assert outcome is not None and outcome.status == STATUS_SUCCESS
    trace = outcome.extra["trace"]
    assert os.path.isfile(trace)
    payload = json.loads(Path(trace).read_text(encoding="utf-8"))
    assert payload["probes"] and payload["networks"]
    assert outcome.extra["wanted"], "the harvest has to report the SSIDs asked for"
    assert engine.session.stats.pnl_harvests >= 1
    assert ap.captures, "the read-only attacks keep their capture on the AP"
    assert payload["capture"] and payload["networks"]
    assert payload["ssids_wanted"], "the trace has to carry the wanted list"
    assert any(entry.kind == "pnl_harvest" for entry in ap.captures)


def test_a_name_clients_ask_for_that_nothing_advertises_is_the_finding(engine):
    ap = _ap(engine, "NETGEAR47")
    outcome = engine.run_attack(ap.bssid, "pnl_harvest")
    assert outcome is not None and outcome.status == STATUS_SUCCESS
    # the simulated site's stations remember a set of networks nothing serves, which
    # is what the finding is about
    assert set(outcome.extra["not_on_air"]) & set(PnlClass.FORGOTTEN_NETWORKS)
    assert not set(outcome.extra["not_on_air"]) & {entry.essid for entry
                                                   in engine.session.aps.values()}
    titles = [finding.title for finding in engine.session.findings
              if finding.kind == "pnl_missing_network"]
    assert titles, "a name that nothing advertises has to be written down"


def test_the_audit_pair_needs_a_capture_and_never_transmits():
    for cls in (IeAuditAttack, PnlHarvestAttack):
        assert cls.needs_injection is False
        assert cls.requires, f"{cls.name} has to declare what it needs"
        assert "airodump" in cls.requires, cls.name
    assert Config().attack_timeout_for(PnlHarvestAttack.name) >= 15


# --------------------------------------------------------------------------- #
# eapol_logoff
# --------------------------------------------------------------------------- #

def test_the_logoff_only_applies_where_somebody_is_associated():
    attack = EapolLogoffAttack()
    empty = AccessPoint(AP_MAC, "HOME", encryption="WPA2", auth="PSK")
    assert attack.applies(empty) is False
    empty.clients = {STA_MAC: Client(STA_MAC, AP_MAC)}
    assert attack.applies(empty) is True


def test_the_logoff_is_decided_by_the_severity_of_the_response(engine):
    ap = _ap(engine, "HOME-2F4A")
    before = engine.session.stats.logoffs
    outcome = engine.run_attack(ap.bssid, "eapol_logoff")
    assert outcome is not None and outcome.status == STATUS_SUCCESS
    assert engine.session.stats.logoffs == before + 1
    assert outcome.extra["frames"] > 0
    assert outcome.extra["clients"], "somebody had to be addressed"
    finding = [item for item in engine.session.findings
               if item.kind == "eapol_logoff"][-1]
    assert "re-associated" in finding.detail or "re-appeared" in finding.detail
    assert "Logoff" in finding.title
    # the demo's WPA2 clients come back: this is the high-severity case
    assert finding.severity in ("high", "medium")


def test_a_wpa3_network_gets_the_same_frames_and_a_honest_answer(engine):
    ap = _ap(engine, "Vodafone-9C31")            # the demo's WPA3-only network
    assert ap.pmf or ap.sae
    outcome = engine.run_attack(ap.bssid, "eapol_logoff")
    assert outcome is not None
    assert outcome.status in (STATUS_SUCCESS, "skipped")
    if outcome.status == STATUS_SUCCESS:
        # PMF does not cover a Logoff: the frames still go out, the clients just do
        # not believe them, and the report says exactly that
        assert "0 re-associated" in outcome.detail or "refused" in outcome.detail
        finding = [item for item in engine.session.findings
                   if item.kind == "eapol_logoff"][-1]
        assert finding.severity == "medium"
        assert "Logoff" in finding.title


def test_a_logoff_never_claims_a_password(engine):
    ap = _ap(engine, "HOME-2F4A")
    outcome = engine.run_attack(ap.bssid, "eapol_logoff")
    assert not outcome.extra.get("password")
    assert "not a capture technique" in outcome.extra["note"] or \
        "no password" in outcome.extra["note"]


# --------------------------------------------------------------------------- #
# karma
# --------------------------------------------------------------------------- #

def test_the_mana_patterns_read_a_real_log_line():
    connected, ssid, mac = patterns()
    line = ('wlan1: AP-STA-CONNECTED 00:11:22:33:44:55\n'
            'wlan1: probe request from 66:77:88:99:aa:bb for SSID="CorpNet-8021X"')
    assert connected.search(line)
    assert ssid.search(line).group("ssid") == "CorpNet-8021X"
    assert mac.search(line).group(1) == "00:11:22:33:44:55"


def test_karma_builds_a_mana_config_that_can_be_killed(engine):
    ap = _ap(engine, "HOME-2F4A")
    attack = KarmaAttack()
    with __import__("tempfile").TemporaryDirectory() as directory:
        path = attack._config(ap, directory, "wlan9")
        text = Path(path).read_text(encoding="utf-8")
    assert "enable_mana=1" in text and "mana_loud=1" in text
    assert "mana_credout=karma.creds" in text
    assert "interface=wlan9" in text
    assert f"channel={ap.channel}" in text
    assert "hw_mode=g" in text


def test_karma_answers_the_demo_probes_and_reports_who_joined(engine):
    ap = _ap(engine, "HOME-2F4A")
    before = engine.session.stats.karma_runs
    outcome = engine.run_attack(ap.bssid, "karma")
    assert outcome is not None and outcome.status == STATUS_SUCCESS
    assert engine.session.stats.karma_runs == before + 1
    assert outcome.extra["probed_ssids"], "the names asked for are the intelligence"
    assert outcome.extra["joined"] or outcome.extra["refused"]
    assert "simulated" in outcome.extra


def test_karma_is_refused_in_stealth_mode(engine, tmp_path):
    config = Config()
    config.demo = True
    config.stealth = True
    config.ollama.enabled = False
    config.output_dir = str(tmp_path / "loot")
    config.session_dir = str(tmp_path / "sessions")
    config.attack_timeout = 2
    config.attacks = ["karma"]
    quiet = Engine(config, demo=True)
    quiet.prepare()
    quiet.scan_for(2)
    ap = _ap(quiet, "HOME-2F4A")
    outcome = quiet.run_attack(ap.bssid, "karma")
    assert outcome is None or outcome.status in ("skipped", "failed")
    assert quiet.session.stats.karma_runs == 0


def test_karma_needs_mana_and_says_so(monkeypatch):
    class _Empty:
        def path(self, name):
            return None

    import wifipilot.attacks.karma as karma_module
    monkeypatch.setattr(karma_module, "registry", _Empty())
    attack = KarmaAttack()
    context = type("Ctx", (), {"demo": False})()
    assert attack.available(context) is False
    assert "hostapd-mana" in attack.unavailable_reason(context)


# --------------------------------------------------------------------------- #
# the two new flood modes
# --------------------------------------------------------------------------- #

def test_the_flood_modes_are_the_ones_mdk4_uses_and_are_duration_capped():
    classes = (DeauthFloodAttack, AuthFloodAttack, ProbeFloodAttack, BeaconFloodAttack)
    assert [cls.mode for cls in classes] == ["d", "a", "p", "b"]
    assert all(cls.max_seconds <= 60 for cls in classes)
    assert AuthFloodAttack.max_seconds <= 45 and ProbeFloodAttack.max_seconds <= 45
    assert DeauthFloodAttack.finding_severity == "high"
    assert AuthFloodAttack.finding_severity == "high"
    assert ProbeFloodAttack.finding_severity == "medium"
    assert set(ProbeFloodAttack.demo_rate) == {"d", "a", "p", "b"}


def test_the_mdk4_command_sets_the_channel_for_every_mode(engine):
    ap = _ap(engine, "HOME-2F4A")
    context = type("Ctx", (), {"monitor": "wlan1"})()
    commands = {}
    for cls in (DeauthFloodAttack, AuthFloodAttack, ProbeFloodAttack, BeaconFloodAttack):
        commands[cls.name] = cls()._command(context, ap)
    for name, command in commands.items():
        assert command[1] == "wlan1"
        assert "-c" in command and str(ap.channel) in command, name
    # only the deauth flood is aimed at one BSSID: mdk4's other modes have no -t
    assert "-t" in commands["deauth_flood"]
    assert "-t" not in commands["auth_flood"]
    assert "-t" not in commands["probe_flood"]
    assert "-t" not in commands["beacon_flood"]


def test_an_auth_flood_reports_its_frames_and_its_finding(engine):
    ap = _ap(engine, "HOME-2F4A")
    before = engine.session.stats.floods_run
    outcome = engine.run_attack(ap.bssid, "auth_flood")
    assert outcome is not None and outcome.status == STATUS_SUCCESS
    assert engine.session.stats.floods_run == before + 1
    assert outcome.extra["frames"] > 0
    assert "denial-of-service" in outcome.extra["note"]


def test_a_probe_flood_is_a_medium_and_names_itself_as_a_flood(engine):
    ap = _ap(engine, "HOME-2F4A")
    outcome = engine.run_attack(ap.bssid, "probe_flood")
    assert outcome is not None and outcome.status == STATUS_SUCCESS
    finding = [item for item in engine.session.findings
               if item.kind == "probe_flood"][-1]
    assert finding.severity == "medium"
    assert "flood" in finding.title.lower()


def test_a_flood_never_reports_a_password(engine):
    ap = _ap(engine, "HOME-2F4A")
    for name in ("auth_flood", "probe_flood"):
        outcome = engine.run_attack(ap.bssid, name)
        assert outcome is not None
        assert not outcome.extra.get("password")
        assert outcome.extra["seconds"] >= 0


# --------------------------------------------------------------------------- #
# the session and the models the new attacks rely on
# --------------------------------------------------------------------------- #

def test_the_session_exposes_every_station_across_every_ap():
    from wifipilot.events import EventBus

    session = Session(Config(), EventBus())
    session.upsert_ap("aa:bb:cc:dd:ee:01", "One")
    session.upsert_ap("aa:bb:cc:dd:ee:02", "Two")
    session.add_client("aa:bb:cc:dd:ee:01", STA_MAC, signal=-50)
    session.add_client("aa:bb:cc:dd:ee:02", STA_MAC, signal=-70, probes=["A", "B", "C"])
    client = session.clients[STA_MAC]
    assert len(client.probes) == 3                # the richer record wins
    assert session.clients["02:00:00:00:00:09"] is client
    assert len(session.clients) == 1
    # and the station is still on both APs, where the AP-level view needs it
    assert STA_MAC in session.aps["aa:bb:cc:dd:ee:01"].clients
    assert STA_MAC in session.aps["aa:bb:cc:dd:ee:02"].clients


def test_the_new_counters_exist_and_start_at_zero():
    stats = SessionStats()
    for name in ("ie_audits", "pnl_harvests", "logoffs", "karma_runs"):
        assert getattr(stats, name) == 0


def test_every_new_attack_is_registered_and_named_exactly_once():
    for name in NEW_ATTACKS:
        assert name in ATTACK_CLASSES and name in ATTACK_NAMES
    assert len(ATTACK_NAMES) == len(set(ATTACK_NAMES))
    assert set(DEFAULT_ORDER) == set(ATTACK_CLASSES)
    assert len(DEFAULT_ORDER) == len(set(DEFAULT_ORDER))


def test_a_configuration_attack_is_offered_wherever_it_makes_sense():
    ap = AccessPoint(AP_MAC, "HOME", encryption="WPA2", auth="PSK", wps=True,
                     wps_locked="unlocked", channel=6)
    offered = ap.attackable()
    assert "ie_audit" in offered and "pnl_harvest" in offered
    assert "karma" in offered and "auth_flood" in offered and "probe_flood" in offered
    # ...and where it does not: no client, no Logoff; 802.1X, no Karma
    assert "eapol_logoff" not in offered
    ap.clients = {STA_MAC: Client(STA_MAC, AP_MAC)}
    assert "eapol_logoff" in ap.attackable()
    enterprise = AccessPoint(AP_MAC, "Corp", encryption="WPA2-ENTERPRISE", auth="MGT")
    assert "karma" not in enterprise.attackable()


# --------------------------------------------------------------------------- #
# the planner and the plan validator know the new attacks
# --------------------------------------------------------------------------- #

def _planner_ap(**kwargs) -> AccessPoint:
    ap = AccessPoint(AP_MAC, "HOME-2F4A", encryption="WPA2", auth="PSK", channel=6)
    for key, value in kwargs.items():
        setattr(ap, key, value)
    return ap


def test_the_planner_audits_first_and_harvests_only_where_nobody_is_around():
    config = Config(demo=True, attacks=list(DEFAULT_ORDER))
    busy = preferred_attacks(_planner_ap(clients={STA_MAC: Client(STA_MAC, AP_MAC)}),
                             config)
    assert busy[0] == "ie_audit"
    assert "eapol_logoff" in busy and "pnl_harvest" not in busy
    quiet = preferred_attacks(_planner_ap(), config)
    assert "pnl_harvest" in quiet and "eapol_logoff" not in quiet


def test_the_planner_will_not_log_off_a_pmf_network_or_flood_in_stealth():
    config = Config(demo=True, attacks=list(DEFAULT_ORDER))
    busy = _planner_ap(clients={STA_MAC: Client(STA_MAC, AP_MAC)})
    assert "eapol_logoff" in preferred_attacks(busy, config)
    busy.pmf = True
    valid = preferred_attacks(busy, config)
    assert "eapol_logoff" not in valid and "deauth_flood" in valid
    stealth = Config(demo=True, stealth=True, attacks=list(DEFAULT_ORDER))
    quiet = preferred_attacks(busy, stealth)
    for name in ("auth_flood", "probe_flood", "deauth_flood", "karma"):
        assert name not in quiet, name


def test_the_plan_validator_drops_what_the_operator_forbade_with_a_reason():
    from wifipilot.events import EventBus

    session = Session(Config(attacks=list(DEFAULT_ORDER)), EventBus())
    session.add_client  # documented above: stations live on their AP
    session.upsert_ap(AP_MAC, "HOME-2F4A")
    ap = session.aps[AP_MAC]
    ap.clients = {STA_MAC: Client(STA_MAC, AP_MAC)}
    raw = {"actions": [{"attack": "eapol_logoff", "bssid": AP_MAC},
                       {"attack": "karma", "bssid": AP_MAC}],
           "reasoning": "disconnect the client and impersonate the network"}
    plan = validate_plan(raw, session)
    assert {action.attack for action in plan.actions} == {"eapol_logoff", "karma"}
    # a Logoff on a PMF network is a deliberate choice, not a default
    ap.pmf = True
    plan = validate_plan(raw, session)
    assert [action.attack for action in plan.actions] == ["karma"]
    assert any("Logoff" in note for note in plan.dropped)
    # and an 802.1X site needs the RADIUS rogue, not Karma
    ap.pmf = False
    ap.auth = "MGT"
    plan = validate_plan(raw, session)
    assert "karma" not in {action.attack for action in plan.actions}
    assert any("802.1X" in note for note in plan.dropped)


def test_the_plan_validator_refuses_a_flood_with_nobody_to_disconnect():
    from wifipilot.events import EventBus

    session = Session(Config(attacks=list(DEFAULT_ORDER)), EventBus())
    session.upsert_ap(AP_MAC, "HOME-2F4A")
    raw = {"actions": [{"attack": "eapol_logoff", "bssid": AP_MAC}], "reasoning": ""}
    plan = validate_plan(raw, session)
    assert plan.actions == []
    assert any("nobody associated" in note for note in plan.dropped)


def test_failure_triage_has_something_specific_to_say_about_each_new_attack():
    for name in ("eapol_logoff", "karma", "auth_flood", "probe_flood", "ie_audit",
                 "pnl_harvest"):
        text = explain_failure({"attack": name, "output": []}, None)
        assert text and len(text) > 20, name
        assert "unknown attack" not in text.lower(), name


# --------------------------------------------------------------------------- #
# the offline command the documentation promises: `wifipilot decode`
# --------------------------------------------------------------------------- #

def _decode_capture(tmp_path) -> str:
    path = str(tmp_path / "decode.pcap")
    synth.write_pcap(path, [
        synth.build_beacon("HOME-2F4A", AP_MAC, channel=6, extra_ies=(
            synth.wps_element(manufacturer="Cisco", model="AIR-CAP2702", methods=0x0008)
            + synth.ht_capabilities(width40=True)
            + synth.country_element("IN")
            + synth.extended_capabilities()
            + synth.mobility_domain(b"\x00\x01"))),
        synth.build_beacon("", "8c:3f:fe:50:73:a6", channel=11),
        synth.build_probe_request(STA_MAC, "Cafe-Guest-Old"),
    ], spacing=0.01)
    return path


def test_the_decode_call_reads_a_capture_without_a_radio(tmp_path):
    import wifipilot as wp

    data = wp.decode(_decode_capture(tmp_path))
    assert data["capture"] and data["frames"] == 2
    names = {entry["bssid"]: entry for entry in data["networks"]}
    assert set(names) == {AP_MAC, "8c:3f:fe:50:73:a6"}
    assert names[AP_MAC]["facts"]["wps"]["model"] == "AIR-CAP2702"
    assert names[AP_MAC]["facts"]["country"] == "IN"
    assert names["8c:3f:fe:50:73:a6"]["hidden"] is True
    kinds = {finding["kind"] for finding in data["findings"]}
    assert {"ie_wps_enabled", "ie_ft_without_pmf", "ie_no_pmf"} <= kinds
    assert data["vendors"][0]["oui"] == "00:50:f2:04"
    # ...and the clients' half of the capture comes with it
    assert STA_MAC in {client["mac"] for client in data["probes"]}
    assert "Cafe-Guest-Old" in data["ssids_wanted"]


def test_the_decode_call_can_hide_the_housekeeping_findings(tmp_path):
    import wifipilot as wp

    path = _decode_capture(tmp_path)
    loud = {finding["kind"] for finding in wp.decode(path)["findings"]}
    quiet = {finding["kind"] for finding in wp.decode(path, include_low=False)["findings"]}
    assert "ie_40mhz_2ghz" in loud and "ie_40mhz_2ghz" not in quiet
    assert "ie_wps_enabled" in quiet                 # high findings are never hidden


def test_decode_says_so_when_the_file_is_not_there():
    import wifipilot as wp

    with pytest.raises(wp.TargetError):
        wp.decode("/nonexistent/capture.pcap")


def test_the_decode_command_prints_a_table_and_emits_json(tmp_path, capsys):
    from wifipilot import cli

    path = _decode_capture(tmp_path)
    assert cli.main(["--no-color", "decode", path]) == 0
    out = capsys.readouterr().out
    assert "information elements" in out
    assert "HOME-2F4A" in out and "WPS" in out
    assert "ie_wps_enabled" in out
    assert "read-only" in out

    assert cli.main(["--json", "decode", path]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["frames"] == 2 and payload["findings"]
    assert payload["networks"][0]["facts"]["channel"] == 6

    # a file that does not exist is an error, not a traceback
    assert cli.main(["--no-color", "decode", str(tmp_path / "nope.pcap")]) == 1
    assert "no such file" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# the catalog, the API surface and the documentation
# --------------------------------------------------------------------------- #

def test_the_catalog_describes_every_registered_attack():
    catalog = attack_catalog()
    # the catalogue is generated from the registry, so the two can only disagree if
    # an attack was registered outside DEFAULT_ORDER (which the batch tests catch)
    assert len(catalog) == len(DEFAULT_ORDER)
    names = [entry["name"] for entry in catalog]
    assert sorted(names) == sorted(DEFAULT_ORDER)
    for entry in catalog:
        assert entry["label"] and entry["description"]
        assert isinstance(entry["needs_injection"], bool)
    by_name = {entry["name"]: entry for entry in catalog}
    assert by_name["eapol_logoff"]["needs_injection"] is True
    assert by_name["ie_audit"]["needs_injection"] is False
    assert by_name["karma"]["tool"].startswith("hostapd-mana")


def test_the_timeouts_the_new_attacks_ask_for_are_honoured():
    config = Config()
    assert config.attack_timeout_for("ie_audit") >= 15
    assert config.attack_timeout_for("pnl_harvest") >= 15
    assert config.attack_timeout_for("eapol_logoff") >= 10
    assert config.attack_timeout_for("karma") >= 180
    assert config.attack_timeout_for("auth_flood") >= 30
    assert config.attack_timeout_for("probe_flood") >= 30


def test_every_attack_the_build_ships_is_documented():
    root = Path(__file__).resolve().parents[1]
    attacks_doc = (root / "docs" / "ATTACKS.md").read_text(encoding="utf-8")
    readme = (root / "README.md").read_text(encoding="utf-8")
    missing = [name for name in DEFAULT_ORDER if name not in attacks_doc]
    assert not missing, f"undocumented attacks: {missing}"
    assert "wifipilot decode" in attacks_doc, "the offline command must be documented"
    missing = [name for name in DEFAULT_ORDER if name not in readme]
    assert not missing, f"attacks missing from the README table: {missing}"
    # and the count in the copy is the count in the registry, whatever it is
    count = str(len(DEFAULT_ORDER))
    assert count in attacks_doc and count in readme
    assert f"{count} attacks" in attacks_doc or f"**{count} attacks**" in attacks_doc
    assert f"{count} attacks" in readme
    for stale in ("21 attacks", "27 attacks"):
        assert stale not in readme, stale
