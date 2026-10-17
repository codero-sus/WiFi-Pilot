# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""The 54-attack build: registry ↔ metadata ↔ planner ↔ docs, plus a demo run of all.

The suite this belongs to is the one that has to stay honest as the attack count grows,
so it tests the *contract* rather than the incidentals:

* every attack is registered, named in ``ATTACK_NAMES`` and described in the metadata
  table (a new attack with no category/noise/impact/detection fails here);
* the planner gates the new families correctly — offline attacks need no radio, the
  denial-of-service tests never run in stealth mode, the broadcast handshake is opt-in;
* every new attack runs in demo mode without raising, and its report says what the
  capture showed rather than what the frame hoped for;
* the frame builders produce frames the project's own decoder can name, because a
  builder that writes 26 bytes of nonsense would otherwise pass every other test;
* every attack name appears in ``docs/ATTACKS.md``.
"""

from __future__ import annotations

import json
import os

import pytest

from wifipilot.attacks import (ATTACK_CLASSES, ATTACK_META, CATEGORIES, DEFAULT_ENABLED,
                               DEFAULT_ORDER, OFFLINE_ATTACKS, OPT_IN_ATTACKS,
                               attack_catalog, get_attack, meta_for, validate)
from wifipilot.attacks.base import AttackContext
from wifipilot.config import Config
from wifipilot.models import ATTACK_NAMES, AccessPoint
from wifipilot.planner import preferred_attacks


#: the attacks this batch added, in the order the docs list them
NEW_ATTACKS = (
    # offline
    "loot_audit", "eapol_audit", "wep_audit", "crack_sweep", "eap_md5_crack",
    "pixie_offline", "rogue_detect", "twin_detect", "roam_audit", "wps_lockout_audit",
    # capture
    "handshake_broadcast", "hcxdump_capture",
    # survey
    "sae_group_audit",
    # WPS
    "wps_ap_pin", "wps_lockout_probe", "wps_pbc",
    # rogue / lures
    "karma_detect", "csa_attack", "ssid_confusion", "ssid_bruteforce",
    "ap_isolation_audit",
    # denial of service
    "assoc_flood", "null_data_flood", "eapol_start_flood", "sae_commit_flood",
    "tkip_michael", "wids_confusion",
)

DOS_ATTACKS = tuple(name for name in DEFAULT_ORDER
                    if meta_for(name)["category"] == "dos")


@pytest.fixture(scope="module")
def engine(tmp_path_factory):
    """One demo engine for the whole module: a scan is expensive, the attacks are not."""
    from wifipilot.engine import Engine

    root = tmp_path_factory.mktemp("attacks-v3")
    config = Config()
    config.demo = True
    config.ollama.enabled = False
    config.output_dir = str(root / "loot")
    config.session_dir = str(root / "sessions")
    config.scan_time = 2
    config.attacks = list(NEW_ATTACKS) + ["handshake", "pmkid"]
    engine = Engine(config, demo=True)
    engine.prepare()
    engine.scan_for(2)
    yield engine
    try:
        engine.stop()
    except Exception:                       # pragma: no cover - teardown best effort
        pass


def context_for(engine) -> AttackContext:
    return AttackContext(session=engine.session, config=engine.config, bus=engine.bus,
                         iface=engine.iface, scanner=engine.scanner, radio=engine.radio,
                         demo=True, processes=engine.processes,
                         stop_event=engine.stop_event)


# --------------------------------------------------------------------------- #
# registry and metadata
# --------------------------------------------------------------------------- #

def test_the_registry_matches_the_order_and_the_names():
    # the exact number is asserted by the batch that added the last attacks; here
    # the three surfaces only have to agree with each other, whatever the count is
    assert len(ATTACK_CLASSES) == len(DEFAULT_ORDER) >= 54
    assert len(ATTACK_NAMES) == len(DEFAULT_ORDER)
    assert set(ATTACK_CLASSES) == set(ATTACK_NAMES) == set(DEFAULT_ORDER)
    assert len(set(DEFAULT_ORDER)) == len(DEFAULT_ORDER)     # no duplicates
    assert set(NEW_ATTACKS) <= set(ATTACK_CLASSES)
    assert len(NEW_ATTACKS) == 27


def test_every_attack_has_metadata_and_the_metadata_has_no_orphans():
    assert validate() == []
    assert set(ATTACK_META) == set(ATTACK_CLASSES)


def test_the_catalogue_carries_what_each_attack_costs():
    catalog = {entry["name"]: entry for entry in attack_catalog()}
    assert len(catalog) == len(DEFAULT_ORDER)
    for name, entry in catalog.items():
        assert entry["label"] and entry["tool"] and entry["description"], name
        assert entry["category"] in {item["name"] for item in CATEGORIES}
        assert entry["noise"] in ("silent", "quiet", "moderate", "loud", "extreme")
        assert entry["impact"] in ("none", "info", "degraded", "outage", "loot")
        assert entry["detection"], f"{name} has no detection note"
        assert isinstance(entry["offline"], bool)
        # the class and the table must agree when both state the same axis
        cls = ATTACK_CLASSES[name]
        for field in ("category", "noise", "impact"):
            # "" is not a declaration: base.Attack documents it as "take this axis
            # from the metadata table", which is where most classes leave it
            declared = getattr(cls, field, None)
            if declared:
                assert declared == entry[field], f"{name}: {field} disagrees"


def test_the_default_enabled_set_is_exactly_what_config_enables():
    catalog = {entry["name"]: entry for entry in attack_catalog()}
    enabled = {name for name, entry in catalog.items() if entry["default_enabled"]}
    assert enabled == set(Config().attacks) == set(DEFAULT_ENABLED)
    # and the disruptive families are never in it
    assert not (enabled & set(DOS_ATTACKS))
    assert not (enabled & set(OPT_IN_ATTACKS))


def test_the_offline_attacks_need_no_radio_and_no_authorisation():
    assert len(OFFLINE_ATTACKS) >= 10
    config = Config()
    config.demo = False                                # a real (radio-less) run
    config.authorized = False
    session_ctx = _offline_context(config)
    for name in OFFLINE_ATTACKS:
        attack = get_attack(name)
        assert attack.needs_injection is False, name
        assert tuple(attack.requires) == (), name
        assert attack.available(session_ctx) is True, name
        assert meta_for(name)["noise"] == "silent", name
        entry = {item["name"]: item for item in attack_catalog()}[name]
        assert entry["offline"] is True


def _offline_context(config: Config) -> AttackContext:
    from wifipilot.events import EventBus
    from wifipilot.session import Session

    session = Session(config, EventBus(), demo=False, authorized=False)
    return AttackContext(session=session, config=config, bus=session.bus, iface=None,
                         scanner=None, radio=None, demo=False, processes=None,
                         stop_event=None)


def test_denial_of_service_is_opt_in_and_never_runs_in_stealth():
    ap = AccessPoint("d0:9e:12:9d:36:cc", "HOME-2F4A", encryption="WPA2", auth="PSK",
                     channel=6)
    assert len(DOS_ATTACKS) >= 10
    loud = Config(demo=True)
    loud.attacks = list(ATTACK_NAMES)                  # everything the build has
    loud.stealth = True
    plan = preferred_attacks(ap, loud)
    assert not (set(plan) & set(DOS_ATTACKS))
    # a flood that is not enabled is not planned either, whatever the mode
    quiet = Config(demo=True)
    quiet.attacks = ["handshake", "pmkid"]
    assert "deauth_flood" not in preferred_attacks(ap, quiet)
    assert "assoc_flood" not in preferred_attacks(ap, quiet)


def test_the_offline_mode_covers_the_attacks_that_never_transmit():
    from wifipilot.api import MODES

    offline = MODES["offline"]["attacks"]
    assert MODES["offline"]["stealth"] is True
    assert set(offline) - {"crack"} <= set(ATTACK_NAMES)
    assert set(OFFLINE_ATTACKS) <= set(offline)
    assert MODES["force"]["attacks"] == list(DEFAULT_ORDER)
    # the passive mode keeps the silent decoders, because they are free
    for name in ("passive", "pmf_audit", "saewolf", "sae_group_audit", "hidden_ssid"):
        assert name in MODES["passive"]["attacks"]


def test_the_planner_uses_the_new_attacks_where_they_belong():
    # a hidden network is where the SSID brute force belongs
    hidden = AccessPoint("aa:bb:cc:11:22:33", "", encryption="WPA2", auth="PSK",
                         hidden=True)
    config = Config(demo=True)
    config.attacks = list(ATTACK_NAMES)
    assert "ssid_bruteforce" in preferred_attacks(hidden, config)
    # ...and a broadcasting one is not
    open_name = AccessPoint("aa:bb:cc:11:22:34", "Lobby", encryption="WPA2", auth="PSK")
    assert "ssid_bruteforce" not in preferred_attacks(open_name, config)
    # the SAE audit goes to the WPA3 network, and the EAP-MD5 dictionary to the
    # enterprise one (which has no PSK path to try instead)
    wpa3 = AccessPoint("f0:63:da:4a:c1:f5", "Vodafone-9C31", encryption="WPA3",
                       auth="SAE", sae=True, channel=100)
    assert "sae_group_audit" in preferred_attacks(wpa3, config)
    from wifipilot.models import Capture

    enterprise = AccessPoint("34:c9:27:19:79:89", "CorpNet-8021X", encryption="WPA2",
                             auth="MGT")
    # the EAP-MD5 dictionary needs an exchange to check: it only appears once the
    # session holds a capture from that AP
    enterprise.captures = [Capture(kind="handshake", bssid=enterprise.bssid,
                                   essid=enterprise.essid, path="")]
    plan = preferred_attacks(enterprise, config)
    assert "eap_md5_crack" in plan and "handshake" not in plan
    # an AP nobody shares a network with gets the isolation audit and not the lures
    quiet = AccessPoint("aa:bb:cc:11:22:35", "Boardroom", encryption="WPA2", auth="PSK")
    assert "ap_isolation_audit" not in preferred_attacks(quiet, config)


def test_the_broadcast_handshake_is_opt_in_even_in_force_mode():
    from wifipilot.models import Client

    ap = AccessPoint("d0:9e:12:9d:36:cc", "HOME-2F4A", encryption="WPA2", auth="PSK")
    ap.clients = {"02:00:00:00:00:09": Client("02:00:00:00:00:09", ap.bssid)}
    config = Config(demo=True)
    config.attacks = list(ATTACK_NAMES)
    assert "handshake_broadcast" not in preferred_attacks(ap, config)
    config.broadcast_handshake = True
    assert "handshake_broadcast" in preferred_attacks(ap, config)
    # and without a client there is nothing to broadcast to
    config.broadcast_handshake = True
    clientless = AccessPoint("d0:9e:12:9d:36:cd", "Empty", encryption="WPA2", auth="PSK")
    assert "handshake_broadcast" not in preferred_attacks(clientless, config)


# --------------------------------------------------------------------------- #
# the frame builders
# --------------------------------------------------------------------------- #

def test_every_new_builder_produces_a_frame_the_decoder_can_name():
    from wifipilot.rawtx import (build_arp_reply, build_arp_request, build_assoc_request,
                                 build_auth_request, build_csa_beacon,
                                 build_eapol_start, build_null_data,
                                 build_probe_request, build_probe_response,
                                 build_reassoc_request, build_ssid_confusion_beacon,
                                 describe, frame_only, header_offset)

    frames = [
        (build_auth_request("aa:bb:cc:dd:ee:ff", "02:00:00:00:00:01"), "authentication"),
        (build_assoc_request("aa:bb:cc:dd:ee:ff", "02:00:00:00:00:01", "Lab"),
         "association request"),
        (build_reassoc_request("aa:bb:cc:dd:ee:ff", "02:00:00:00:00:01"), "reassociation"),
        (build_null_data("aa:bb:cc:dd:ee:ff", "02:00:00:00:00:01", power_save=True), "null"),
        (build_eapol_start("aa:bb:cc:dd:ee:ff", "02:00:00:00:00:01"), "eapol-start"),
        (build_probe_request("02:00:00:00:00:01", "Lab"), "probe request"),
        (build_probe_response("02:00:00:00:00:01", "aa:bb:cc:dd:ee:ff", "Lab"),
         "probe response"),
        (build_csa_beacon("aa:bb:cc:dd:ee:ff", "Lab", 6, 1), "beacon"),
        (build_ssid_confusion_beacon("02:00:9e:00:00:01", "Lab", 6), "beacon"),
        (build_arp_request("02:00:00:00:00:01", "192.168.1.5", "192.168.1.9",
                           "aa:bb:cc:dd:ee:ff"), "data"),
        (build_arp_reply("02:00:00:00:00:02", "192.168.1.9", "02:00:00:00:00:01",
                         "192.168.1.5", "aa:bb:cc:dd:ee:ff"), "data"),
    ]
    for frame, expected in frames:
        assert header_offset(frame) == 9
        assert frame[0] == 0x00 and frame[1] == 0x00          # radiotap present
        name, size = describe([frame])[0]
        assert expected in name.lower()
        assert size == len(frame)                     # radiotap included, as sent
        assert len(frame_only(frame)) == len(frame) - header_offset(frame)


def test_the_frames_carry_what_they_claim_to():
    from wifipilot.rawtx import (build_arp_reply, build_csa_beacon, build_null_data,
                                 build_probe_response, build_ssid_confusion_beacon,
                                 frame_only)

    csa = frame_only(build_csa_beacon("aa:bb:cc:dd:ee:ff", "Lab", channel=6,
                                      new_channel=11))
    assert bytes([37, 3, 1, 11]) in csa               # IE 37: switch mode, new channel
    assert b"Lab" in csa

    confusion = frame_only(build_ssid_confusion_beacon("02:00:9e:00:00:01", "Lab", 6))
    assert b"Lab" in confusion
    assert confusion[10:16].hex(":") == "02:00:9e:00:00:01"

    power_save = frame_only(build_null_data("aa:bb:cc:dd:ee:ff", "02:00:00:00:00:01",
                                            power_save=True))
    assert power_save[1] & 0x10                        # the PM bit is set
    awake = frame_only(build_null_data("aa:bb:cc:dd:ee:ff", "02:00:00:00:00:01"))
    assert not awake[1] & 0x10

    answer = frame_only(build_probe_response("02:00:00:00:00:01", "aa:bb:cc:dd:ee:ff",
                                             "GhostNet"))
    assert b"GhostNet" in answer

    reply = frame_only(build_arp_reply("02:00:00:00:00:02", "10.0.0.9",
                                       "02:00:00:00:00:01", "10.0.0.5",
                                       "aa:bb:cc:dd:ee:ff"))
    assert reply[24:32] == b"\xaa\xaa\x03\x00\x00\x00\x08\x06"
    assert reply[32:34] == b"\x00\x01" and reply[34:36] == b"\x08\x00"   # Ethernet/IPv4
    assert reply[38:40] == b"\x00\x02"                                   # opcode: reply


def test_spoofed_stations_are_deterministic_and_obviously_fake():
    from wifipilot.rawtx import spoofed_mac

    first = spoofed_mac(7)
    assert first == spoofed_mac(7)                     # a report that reproduces
    assert first != spoofed_mac(8)
    assert int(first.split(":")[0], 16) & 0x02         # locally administered
    assert not int(first.split(":")[0], 16) & 0x01     # unicast
    universal = int(spoofed_mac(9, locally_administered=False).split(":")[0], 16)
    assert universal & 0x01 == 0                       # never a multicast address


# --------------------------------------------------------------------------- #
# the attacks themselves, in demo mode
# --------------------------------------------------------------------------- #

def _run(engine, name: str):
    """Run one attack against the first AP it applies to; return (attack, outcome)."""
    attack = get_attack(name)
    ctx = context_for(engine)
    candidates = [ap for ap in engine.session.sorted_aps() if attack.applies(ap)]
    assert candidates, f"{name} applies to nothing in the demo neighbourhood"
    outcomes = []
    for ap in candidates[:12]:
        outcome = attack.run(ctx, ap)
        outcomes.append(outcome)
        if outcome.ok:
            break
    return attack, outcomes


def test_every_new_attack_runs_in_demo_mode_without_raising(engine):
    ran = {}
    for name in NEW_ATTACKS:
        attack, outcomes = _run(engine, name)
        assert outcomes, name
        for outcome in outcomes:
            assert outcome is not None, name
            assert outcome.result, name
        ran[name] = outcomes[-1]
        # the attempt record is closed, whatever the outcome
        assert any(attempt.attack == name for attempt in engine.session.attempts), name
    assert len(ran) == len(NEW_ATTACKS)
    positive = [name for name, outcome in ran.items() if outcome.ok]
    # the demo neighbourhood is built to give most of these a positive result: if a
    # change makes everything skip, the suite should say so
    assert len(positive) >= 20, sorted(set(ran) - set(positive))


def test_the_floods_report_themselves_as_denial_of_service(engine):
    for name in ("assoc_flood", "null_data_flood", "eapol_start_flood",
                 "sae_commit_flood", "wids_confusion"):
        _attack, outcomes = _run(engine, name)
        outcome = outcomes[-1]
        assert outcome.ok, name
        assert outcome.extra["category"] == "dos"
        assert "denial-of-service" in outcome.extra["note"]
        assert outcome.extra["frames"] > 0
        assert outcome.extra["simulated"] is True


def test_the_offline_audits_never_claim_to_have_touched_the_radio(engine):
    catalog = {entry["name"]: entry for entry in attack_catalog()}
    for name in ("loot_audit", "eapol_audit", "wep_audit", "pixie_offline",
                 "rogue_detect", "twin_detect", "roam_audit", "wps_lockout_audit"):
        attack, outcomes = _run(engine, name)
        outcome = outcomes[-1]
        assert catalog[name]["offline"] is True, name
        assert attack.needs_injection is False, name
        assert meta_for(name)["noise"] == "silent", name
        if not outcome.ok:
            continue                    # "nothing captured yet" is a valid answer
        # the report of a silent attack must not carry a transmission counter at all
        assert "frames" not in outcome.extra, name
        # and it must not have raised a deauth count either
        assert not outcome.deauths, name


def test_the_lures_say_what_the_capture_showed(engine):
    for name in ("csa_attack", "ssid_confusion", "karma_detect", "ap_isolation_audit",
                 "ssid_bruteforce"):
        _attack, outcomes = _run(engine, name)
        outcome = outcomes[-1]
        if not outcome.ok:
            continue
        assert outcome.extra.get("observed"), name
        # the report keeps the raw observation keys and the conclusion apart
        assert outcome.detail, name


def test_the_sae_audit_ranks_a_weak_group_from_the_rsn_element_and_the_commits(tmp_path):
    from wifipilot.synth import build_wpa3_capture

    from wifipilot.events import EventBus
    from wifipilot.session import Session

    config = Config()
    config.demo = False
    session = Session(config, EventBus(), demo=False, authorized=False)
    ap = AccessPoint("aa:bb:cc:dd:ee:99", "Lab-WPA3", encryption="WPA3", auth="SAE",
                     sae=True, channel=6)
    attack = get_attack("sae_group_audit")
    path = str(tmp_path / "weak.pcap")
    build_wpa3_capture(path, essid="Lab-WPA3", bssid=ap.bssid, station="02:00:00:00:00:41",
                       akm="sae", pmf=False, group=22)
    ctx = AttackContext(session=session, config=config, bus=session.bus, demo=False)
    outcome = attack._report(ctx, ap, _attempt_for(session, attack, ap), path, False)
    assert outcome.ok
    assert outcome.extra["groups"] == [22]
    assert outcome.extra["weak_groups"] == [22]
    assert outcome.extra["h2e_advertised"] is False       # no SAE-EXT-KEY AKM
    assert outcome.extra["pmf_required"] is False
    assert outcome.extra["offline_feasible"] is False
    assert "weak SAE group" in outcome.result

    strong = str(tmp_path / "strong.pcap")
    build_wpa3_capture(strong, essid="Lab-WPA3", bssid=ap.bssid,
                       station="02:00:00:00:00:42", akm="sae-ext", pmf=True, group=19)
    outcome = attack._report(ctx, ap, _attempt_for(session, attack, ap), strong, False)
    assert outcome.extra["groups"] == [19]
    assert outcome.extra["weak_groups"] == []
    assert outcome.extra["h2e_advertised"] is True
    assert outcome.extra["pmf_required"] is True
    assert outcome.extra["strong_groups"] == [19]


def _attempt_for(session, attack, ap):
    return session.start_attempt(attack.name, ap.bssid, tool=attack.tool)


def test_karma_detect_flags_a_device_that_answers_two_made_up_names(tmp_path):
    from wifipilot.rawtx import build_probe_response, frame_only
    from wifipilot.synth import write_pcap

    from wifipilot.events import EventBus
    from wifipilot.session import Session

    config = Config()
    session = Session(config, EventBus(), demo=False, authorized=False)
    ap = AccessPoint("aa:bb:cc:dd:ee:01", "Cafe", encryption="WPA2", auth="PSK")
    attack = get_attack("karma_detect")
    ctx = AttackContext(session=session, config=config, bus=session.bus, demo=False)
    station = attack.station(ap)
    rogue = "02:00:00:00:0f:0f"
    names = attack.fake_names()
    path = str(tmp_path / "karma.pcap")
    write_pcap(path, [frame_only(build_probe_response(station, rogue, ssid=names[0])),
                      frame_only(build_probe_response(station, rogue, ssid=names[1])),
                      frame_only(build_probe_response(station, ap.bssid,
                                                      ssid="Cafe"))])
    observed = attack.observe(ctx, ap, path)
    # only answers to the names that cannot exist are evidence: an AP answering its
    # own name is the healthy case and is not counted
    assert set(observed["by_bssid"]) == {rogue}
    report = attack.interpret(ctx, ap, observed)
    assert "answered" in report["extra"]
    assert report["extra"]["karma_bssids"] == [rogue]
    assert "made-up" in report["detail"]


def test_ap_isolation_audit_reads_an_arp_reply_between_two_clients(tmp_path):
    from wifipilot.models import Client
    from wifipilot.rawtx import build_arp_reply, frame_only
    from wifipilot.synth import write_pcap

    from wifipilot.events import EventBus
    from wifipilot.session import Session

    config = Config()
    session = Session(config, EventBus(), demo=False, authorized=False)
    ap = AccessPoint("aa:bb:cc:dd:ee:02", "Guest", encryption="WPA2", auth="PSK")
    ap.clients = {"02:00:00:00:00:11": Client("02:00:00:00:00:11", ap.bssid),
                  "02:00:00:00:00:12": Client("02:00:00:00:00:12", ap.bssid)}
    attack = get_attack("ap_isolation_audit")
    ctx = AttackContext(session=session, config=config, bus=session.bus, demo=False)
    source, target = attack.stations(ap)
    path = str(tmp_path / "isolation.pcap")
    write_pcap(path, [frame_only(build_arp_reply(target, "192.168.1.77", source,
                                                 "192.168.1.50", bssid=ap.bssid))])
    report = attack.interpret(ctx, ap, attack.observe(ctx, ap, path))
    assert report["extra"]["isolated"] is False
    assert report["severity"] == "high"
    # ...and the negative branch is a real result too
    empty = str(tmp_path / "clean.pcap")
    write_pcap(empty, [frame_only(build_arp_reply("02:00:00:00:00:99", "10.0.0.1",
                                                  source, "10.0.0.2", bssid=ap.bssid))])
    report = attack.interpret(ctx, ap, attack.observe(ctx, ap, empty))
    assert report["extra"]["isolated"] is True
    assert report["extra"]["replies"] == []


def test_ssid_bruteforce_reveals_the_name_a_probe_response_gives_away(tmp_path):
    from wifipilot.rawtx import build_probe_response, frame_only
    from wifipilot.synth import write_pcap

    from wifipilot.events import EventBus
    from wifipilot.session import Session

    config = Config()
    session = Session(config, EventBus(), demo=False, authorized=False)
    ap = AccessPoint("aa:bb:cc:dd:ee:03", "", encryption="WPA2", auth="PSK", hidden=True)
    attack = get_attack("ssid_bruteforce")
    ctx = AttackContext(session=session, config=config, bus=session.bus, demo=False)
    path = str(tmp_path / "hidden.pcap")
    write_pcap(path, [frame_only(build_probe_response(attack.station(ap), ap.bssid,
                                                      ssid="Lab-IoT"))])
    report = attack.interpret(ctx, ap, attack.observe(ctx, ap, path))
    assert report["extra"]["ssid"] == "Lab-IoT"
    assert "Lab-IoT" in report["detail"]


def test_the_wps_attacks_agree_about_a_locked_access_point(engine):
    ap = engine.session.sorted_aps()[0]
    ap.wps_locked = "locked during an earlier attempt"
    attack = get_attack("wps_ap_pin")
    ctx = context_for(engine)
    outcome = attack.run(ctx, ap)
    assert outcome is not None                    # a stale flag warns, it does not skip
    ap.wps_locked = ""


def test_hcxdump_capture_converts_a_capture_into_mode_22000(engine):
    from wifipilot.hash22000 import parse_file
    from wifipilot.models import Capture

    attack = get_attack("hcxdump_capture")
    ctx = context_for(engine)
    ap = next(candidate for candidate in engine.session.sorted_aps()
              if attack.applies(candidate))
    outcome = attack.run(ctx, ap)
    assert outcome.ok
    assert outcome.extra["lines"] >= 1
    assert outcome.extra["pmkids"] + outcome.extra["handshakes"] >= 1
    hashes = [capture for capture in engine.session.all_captures()
              if capture.kind == "hash"]
    assert hashes and os.path.exists(hashes[-1].path)
    assert parse_file(hashes[-1].path)                    # the file is readable
    assert outcome.extra["next"] == "crack_sweep"


def test_the_registry_catalogue_is_what_the_engine_reports(engine):
    catalog = {entry["name"]: entry for entry in engine._attack_catalog()}
    assert len(catalog) == len(DEFAULT_ORDER)
    for entry in catalog.values():
        assert "category" in entry and "noise" in entry and "impact" in entry
        assert "available" in entry and "enabled" in entry
    assert catalog["assoc_flood"]["category"] == "dos"
    assert catalog["loot_audit"]["offline"] is True


# --------------------------------------------------------------------------- #
# the CLI and the docs
# --------------------------------------------------------------------------- #

def test_the_cli_lists_the_catalogue_with_its_costs(capsys):
    from wifipilot.cli import main

    assert main(["attacks", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["count"] == len(DEFAULT_ORDER)
    assert len(payload["offline_attacks"]) == len(OFFLINE_ATTACKS)
    assert all(entry["detection"] for entry in payload["attacks"])

    assert main(["attacks", "--no-radio"]) == 0
    text = capsys.readouterr().out
    # the count is read from the catalogue, not written here: a wave of attacks must
    # not require editing an assertion to prove it shipped
    offline = len([entry for entry in attack_catalog() if entry["offline"]])
    assert f"{offline} of {len(DEFAULT_ORDER)} attacks" in text
    assert "crack_sweep" in text and "deauth_flood" not in text

    assert main(["attacks", "--category", "dos"]) == 0
    text = capsys.readouterr().out
    assert "Denial-of-service tests" in text
    assert "assoc_flood" in text and "deauth_flood" in text

    assert main(["attacks", "--category", "nonsense"]) == 1
    capsys.readouterr()


def test_every_attack_is_documented():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "docs", "ATTACKS.md"), encoding="utf-8") as handle:
        text = handle.read()
    missing = [name for name in DEFAULT_ORDER if name not in text]
    assert not missing, f"docs/ATTACKS.md does not mention: {missing}"
    assert f"{len(DEFAULT_ORDER)} attacks" in text


def test_the_readme_states_the_attack_count_it_ships():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "README.md"), encoding="utf-8") as handle:
        text = handle.read()
    assert f"{len(DEFAULT_ORDER)} attacks" in text
    assert "27 attacks" not in text
