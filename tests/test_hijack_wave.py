# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""The hijacker wave: seventy-five attacks that wear somebody else's identity.

The Wi-Fi edition of the impersonation waves.  Every attack builds frames with the
toolkit's own builders, writes them through the capture writer and then grades itself on
what the *readers* found in the bytes — so the tests here come in four parts:

* the whole wave runs in demo mode and every attack has to end ``success``;
* the registry and the metadata tables agree with the classes;
* the readers decode what the builders wrote (an ARP reply, a DNS answer, an EAPOL-Key
  frame, an action frame, a beacon's element list and a radiotap signal level), because a
  report built on a reader that reads nothing is a report that says nothing;
* the claims are tested in both directions: a clone that matches its target on every axis
  reports that it matches, and the attack that changes one axis reports *that* one.
"""

from __future__ import annotations

import pytest

from wifipilot import netproto as np
from wifipilot.attacks import ATTACK_CLASSES, hijack75, meta
from wifipilot.attacks.base import AttackContext
from wifipilot.demo import DemoRadio
from wifipilot.models import AccessPoint, Client

#: the wave, in the order the registry carries it
WAVE = tuple(hijack75.NAMES)

#: the target the demo runs against: the first access point of the demo neighbourhood
TARGET = "d0:9e:12:9d:36:cc"


@pytest.fixture()
def ap() -> AccessPoint:
    # PMF on, so that the attack which strips it has something to strip
    return AccessPoint(TARGET, "HOME-2F4A", channel=6, encryption="WPA2", auth="PSK",
                       privacy="WPA2", pmf=True)


@pytest.fixture()
def ctx(config, bus, session, ap) -> AttackContext:
    config.demo = True
    radio = DemoRadio()
    demo_ap = radio.find(ap.bssid) or radio.aps[0]
    for client in demo_ap.clients:
        ap.clients[client.mac] = Client(client.mac, ap.bssid, signal=client.signal)
    return AttackContext(session=session, config=config, bus=bus, radio=radio, demo=True)


def run(name: str, ctx: AttackContext, ap: AccessPoint):
    return ATTACK_CLASSES[name]().run(ctx, ap)


# --------------------------------------------------------------------------- #
# the wave
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name", WAVE)
def test_wave_runs(name, ctx, ap):
    """Every attack in the wave finishes and reports what the capture showed."""
    outcome = run(name, ctx, ap)
    assert outcome.status == "success", (name, outcome.result, outcome.detail)
    assert outcome.detail
    assert outcome.extra.get("family") in ("twin", "client", "steer", "session", "portal",
                                           "enterprise")


def test_wave_is_registered():
    assert len(WAVE) == 75
    assert len(set(WAVE)) == 75
    assert set(WAVE) == set(hijack75.META)
    for name in WAVE:
        assert name in ATTACK_CLASSES, name
        assert meta.ATTACK_META[name]["domain"] == "wifi", name
        assert meta.ATTACK_META[name]["detection"], f"{name} has no detection note"


def test_metadata_valid():
    assert meta.validate() == []


def test_the_families_are_evenly_spread():
    families: dict = {}
    for row in hijack75.META.values():
        families[row["family"]] = families.get(row["family"], 0) + 1
    assert families == {"twin": 19, "client": 12, "steer": 12, "session": 11,
                        "portal": 11, "enterprise": 10}


# --------------------------------------------------------------------------- #
# the readers the wave grades itself with
# --------------------------------------------------------------------------- #

def test_the_readers_decode_an_arp_reply(tmp_path, ap):
    station = "02:00:00:00:00:09"
    from wifipilot.rawtx import build_data
    payload = hijack75._arp_bytes(station, "192.168.1.1", ap.bssid, "192.168.1.50")
    frame = build_data(ap.bssid, station, payload, ethertype=hijack75.ETHERTYPE_ARP)
    path = str(tmp_path / "arp.pcap")
    hijack75.write_capture(path, [frame], signals=[-33])

    rows = hijack75.arp_rows(path)
    assert len(rows) == 1
    assert rows[0]["op"] == 2 and rows[0]["sender_ip"] == "192.168.1.1"
    assert rows[0]["target_ip"] == "192.168.1.50"
    # the signal is read back out of the radiotap header, not passed to the assertion
    assert hijack75.signal_of(path) == {ap.bssid: -33}


def test_the_readers_decode_a_dns_answer_and_a_tcp_segment(tmp_path, ap):
    from wifipilot.rawtx import build_data
    station = "02:00:00:00:00:09"
    query = np.dns_query("portal.example", txid=0x1234)
    answer = np.dns_response(query, [("portal.example", "192.168.1.1")], ttl=30)
    dns = build_data(ap.bssid, station,
                     np.ipv4_udp_packet("192.168.1.1", "192.168.1.50", 53, 40001, answer),
                     ethertype=hijack75.ETHERTYPE_IP)
    segment = hijack75._tcp_segment("192.168.1.50", "192.168.1.1", 49152, 80,
                                    sequence=0x3000, flags=0x18, payload=b"GET / HTTP/1.1")
    tcp = build_data(ap.bssid, station,
                     hijack75._ipv4_packet("192.168.1.50", "192.168.1.1", segment, 6),
                     ethertype=hijack75.ETHERTYPE_IP, to_ds=True, from_ds=False)
    path = str(tmp_path / "net.pcap")
    hijack75.write_capture(path, [dns, tcp])

    rows = hijack75.ip_rows(path)
    assert [row["protocol"] for row in rows] == [17, 6]
    assert rows[0]["src_port"] == 53
    assert rows[1]["dst_port"] == 80 and rows[1]["flags"] == 0x18
    assert "GET / HTTP/1.1" in " ".join(row["text"] for row in hijack75.text_rows(path))


def test_the_readers_decode_an_eapol_key_frame(tmp_path, ap):
    from wifipilot.rawtx import build_data
    station = "02:00:00:00:00:09"
    frame = build_data(ap.bssid, station, hijack75._eapol_key(0x13CA, 3, bytes(range(32))),
                       ethertype=0x888E)
    path = str(tmp_path / "eapol.pcap")
    hijack75.write_capture(path, [frame])

    rows = hijack75.eapol_rows(path)
    assert len(rows) == 1
    assert rows[0]["replay"] == 3 and rows[0]["message"] == 3
    assert rows[0]["install"] is True


def test_the_readers_decode_an_action_frame_and_a_beacon(tmp_path, ap):
    from wifipilot.rawtx import build_btm_request
    from wifipilot.synth import build_beacon
    station = "02:00:00:00:00:09"
    btm = build_btm_request(ap.bssid, station,
                            candidates=[("d2:9e:12:9d:36:cc", 6, 3)])
    beacon = build_beacon(ap.essid, ap.bssid, channel=6, include_rsn=True, akm="psk")
    path = str(tmp_path / "mgmt.pcap")
    hijack75.write_capture(path, [btm, beacon])

    actions = hijack75.action_rows(path)
    assert len(actions) == 1 and actions[0]["destination"] == station
    rows = hijack75.beacons(path)
    assert len(rows) == 1 and rows[0]["ssid"] == "HOME-2F4A"
    assert rows[0]["rsn"], "the RSN element was decoded, not skipped"


# --------------------------------------------------------------------------- #
# the claims
# --------------------------------------------------------------------------- #

def test_a_clone_that_matches_reports_that_it_matches(ctx, ap):
    """The element clone says the element lists are equal, and it can only say that
    because the decoder found both beacons and compared them element by element."""
    outcome = run("twin_element_clone", ctx, ap)
    diff = outcome.extra["diff"]
    assert diff["comparable"] is True
    assert diff["elements_only_in_twin"] == []
    assert diff["elements_only_in_target"] == []
    assert diff["ssid_equal"] is True and diff["channel_equal"] is True
    assert "identical" in outcome.detail


def test_stripping_pmf_shows_up_as_the_axis_that_differs(ctx, ap):
    """The attack that removes PMF has to report PMF as the differing axis — and the
    target in this test does not use it, so the twin advertises it and the difference is
    read in the other direction, which is the same assertion."""
    outcome = run("twin_pmf_strip", ctx, ap)
    diff = outcome.extra["diff"]
    assert diff["pmf_equal"] is False
    assert diff["rsn_equal"] is False, "the RSN element carries the PMF bits"
    assert diff["elements_in_both"], "the rest of the beacon is still a match"


def test_a_clone_on_the_targets_own_address_is_reported_as_indistinguishable(ctx, ap):
    outcome = run("twin_address_clone", ctx, ap)
    assert ap.bssid in outcome.detail
    assert "cannot tell them apart" in outcome.detail
    assert outcome.extra["diff"]["twin_address"] == ap.bssid


def test_the_portal_attack_reads_the_fields_it_would_harvest(ctx, ap):
    outcome = run("portal_clone", ctx, ap)
    fields = {field.get("name") for field in outcome.extra["inputs"]}
    assert {"username", "password"} <= fields
    assert outcome.extra["forms"] >= 1


def test_the_replay_attack_finds_its_own_duplicate(ctx, ap):
    """The KRACK replay is graded on the capture: the same counter twice."""
    outcome = run("client_fourway_race", ctx, ap)
    assert "replay counter arrived 2 time" in outcome.detail
    assert "[3, 3]" in outcome.detail


def test_the_signal_claim_is_measured_from_the_capture(ctx, ap):
    outcome = run("twin_signal_boost", ctx, ap)
    assert outcome.extra["twin_level"] > outcome.extra["target_level"]
    assert outcome.extra["twin_level"] == hijack75.TwinSignalBoostAttack.twin_signal


def test_the_relay_reports_what_the_radius_exchange_carried(ctx, ap):
    outcome = run("enterprise_peap_relay", ctx, ap)
    assert "Access-Request" in outcome.detail
    assert "MSCHAPv2" in outcome.detail or "mschapv2" in outcome.detail.lower()
