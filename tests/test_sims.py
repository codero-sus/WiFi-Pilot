# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""The two simulated environments: the Bluetooth floor and the IT segment.

Demo mode is the fastest way to exercise 848 attacks, and the only way to exercise the
Bluetooth and IT ones without a lab — so the simulations are load-bearing, not decoration.
This file checks that they are internally consistent, that they answer with bytes the
toolkit's *own* parsers read (a simulation whose answers the toolkit cannot parse would be
a simulation of nothing), and that the library, the CLI and the web all describe one world.
"""

from __future__ import annotations

import json
import struct

import pytest

from wifipilot import api, bt, blesim, itsim
from wifipilot.attacks import ATTACK_CLASSES, btred
from wifipilot.attacks.base import AttackContext
from wifipilot.models import AccessPoint


@pytest.fixture()
def ctx(config, bus, session) -> AttackContext:
    """A demo context aimed at nothing in particular — the way an attack run starts."""
    config.demo = True
    config.bt_timeout = 2.0
    return AttackContext(session=session, config=config, bus=bus, demo=True)


@pytest.fixture()
def ap() -> AccessPoint:
    return AccessPoint(bssid="aa:bb:cc:11:22:33", essid="demo-bridge", channel=6,
                       signal=-40)


@pytest.fixture(autouse=True)
def fresh_floor():
    """Every test starts on a fresh simulated floor, so a crash in one is not a state."""
    blesim.reset_ble()
    itsim.reset_demo_lan()
    yield
    blesim.reset_ble()


# --------------------------------------------------------------------------- #
# the Bluetooth floor
# --------------------------------------------------------------------------- #

def test_the_floor_is_internally_consistent():
    airspace = blesim.ble()
    assert len(airspace) >= 40, "the floor is supposed to be a building, not a demo of one"
    addresses = [device.address for device in airspace]
    assert len(addresses) == len(set(addresses)), "two devices share a BD_ADDR"
    for device in airspace:
        assert device.profile in blesim.PROFILES, (device.address, device.profile)
        assert bt.classify_address(device.address) in ("public", "random",
                                                       "random static",
                                                       "random private",
                                                       "resolvable private",
                                                       "non-resolvable private"), device.address
        assert -100 < device.rssi < 0 and device.interval_ms > 0
        assert device.weaknesses(), f"{device.address} has no posture to report"
    # the profiles the demo needs to be able to meet
    profiles = {device.profile for device in airspace}
    assert {"wide_open", "open_gatt", "fragile_stack", "hardened"} <= profiles


def test_every_device_advertises_something_the_parsers_read():
    airspace = blesim.ble()
    named = [device for device in airspace if device.name]
    assert len(named) >= 10
    for device in airspace:
        if device.kind == "bredr":
            continue                                     # classic devices do not advertise
        pdu = bt.adv_pdu(device.pdu_type(), device.address, device.ad_payload())
        parsed = bt.parse_adv_pdu(pdu)
        assert parsed["address"] == device.address, device.address
        assert bt.parse_ad(parsed["data"]), device.address
    # the payloads carry what the audits look for: names, services, beacons and trackers
    named = [device for device in airspace if device.scan_name or device.name]
    assert any(bt.payload_name(bt.parse_ad(
        bt.parse_adv_pdu(bt.adv_pdu(d.pdu_type(), d.address, d.ad_payload()))["data"]))
        for d in named)
    assert airspace.candidates("tracker") and airspace.candidates("beacon")


def test_every_role_maps_to_a_registered_attack_and_a_device():
    """A role that no device can answer is an attack a demo run can never exercise."""
    from wifipilot.attacks import ATTACK_CLASSES

    assert set(blesim.ATTACK_ROLES) <= set(ATTACK_CLASSES)
    # the on-air attacks have to name a role, or a demo run aims them at nothing in
    # particular: these are the ones that open a link and send protocol bytes
    for name in ("bt_blueborne", "bt_bias", "bt_knob", "bt_bluebugging", "bt_blesa",
                 "bt_sweyntooth", "bt_bluesnarf", "bt_bluesmack", "bt_hid_injection",
                 "bt_rfcomm_scan", "bt_adv_dos", "bt_adv_name_flood"):
        assert blesim.role_for(name) != "any", name
    airspace = blesim.ble()
    for role in blesim.LINK_ROLES:
        assert airspace.candidates(role), role
        assert blesim.role_for("", role) == role
    # and the catalogue says which of them each device answers
    row = blesim.ble_catalog()[0]
    assert row["roles"] and set(row["roles"]) <= set(blesim.LINK_ROLES)
    assert set(row["attacks"]) <= set(ATTACK_CLASSES)


def test_the_beacons_and_trackers_are_recognised():
    airspace = blesim.ble()
    beacon = airspace.pick("beacon")
    assert beacon is not None and beacon.beacon
    entry = bt.parse_ad(bt.parse_adv_pdu(
        bt.adv_pdu(beacon.pdu_type(), beacon.address, beacon.ad_payload()))["data"])
    manufacturer = [item for item in entry if item.get("type") == 0xFF]
    service_data = [item for item in entry if item.get("type") == 0x16]
    if beacon.beacon.startswith("ibeacon"):
        assert any(bt.parse_ibeacon(item) for item in manufacturer)
    else:
        assert any(bt.parse_eddystone(item) for item in service_data + manufacturer)
    tracker = airspace.pick("tracker")
    assert tracker is not None
    structures = bt.parse_ad(bt.parse_adv_pdu(
        bt.adv_pdu(tracker.pdu_type(), tracker.address, tracker.ad_payload()))["data"])
    assert bt.tracker_of(structures) is not None


def test_the_virtual_controller_answers_a_scan_and_an_inquiry():
    sock = blesim.controller_socket(role="le")
    bt.hci_send(sock, bt.le_set_scan_enable(True), timeout=1.0)
    seen = {}
    for event in bt.iter_hci_events(sock, seconds=1.0, limit=400):
        for report in event.get("reports") or []:
            report["channel"] = (event.get("parameters") or b"\x00")[0]
            seen[report["address"]] = report
    assert len(seen) >= 20, "a scan of a full floor should hear most of it"
    assert sum(1 for report in seen.values() if report.get("name")) >= 5

    classic = blesim.controller_socket(role="bredr")
    bt.hci_send(classic, bt.inquiry_command(), timeout=1.0)
    found = [report for event in bt.iter_hci_events(classic, seconds=1.0, limit=200)
             for report in event.get("reports") or []]
    assert len(found) >= 5
    assert any(report["major_class_text"] != "miscellaneous" for report in found)


def test_an_acl_dialogue_comes_back_as_acl():
    device = blesim.ble().pick("gatt")
    assert device is not None
    sock = blesim.controller_socket(ctx=None, address=device.address, role="gatt")
    request = bytes([0x10, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28])      # Read By Group Type
    answer = bt.hci_send(sock, bt.acl_packet(0x0040, bt.l2cap_frame(0x0004, request)),
                         timeout=1.0)
    parsed = bt.parse_acl_packet(answer)
    assert parsed["handle"] == 0x0040
    att = bt.parse_att((parsed["l2cap"] or {}).get("payload") or b"")
    assert att.get("opcode") == 0x11, att
    services = bt.gatt_services_from_att(att.get("entries") or [])
    assert services and services[0]["uuid"].startswith("0x")


def test_sdp_answers_with_records_that_name_their_channel():
    airspace = blesim.ble()
    device = airspace.pick("sdp")
    assert device is not None and device.sdp
    sock = blesim.controller_socket(ctx=None, address=device.address, role="sdp")
    request = bt.sdp_service_search_attribute(uuids=(0x1101,))
    answer = bt.hci_send(sock, bt.acl_packet(0x0040, bt.l2cap_frame(0x0040, request)),
                         timeout=1.0)
    records = bt.parse_sdp((bt.parse_acl_packet(answer)["l2cap"] or {}).get("payload") or b"")
    assert records
    assert any(record.get("channel") for record in records)
    channels = {int(channel) for channel in device.channels}
    assert all(record["channel"] in channels for record in records if record.get("channel"))


def test_the_serial_profiles_answer_at_and_obex():
    phone = blesim.ble().pick("at")
    assert phone is not None
    channel = int(phone.channels[0])
    sock = blesim.rfcomm_socket(ctx=None, address=phone.address, channel=channel)
    assert sock is not None
    sock.send(b"AT+CGMI\r")
    answer = sock.recv(200)
    assert b"+CGMI" in answer or b"OK" in answer

    obex = blesim.ble().pick("obex")
    assert obex is not None
    store = blesim.rfcomm_socket(ctx=None, address=obex.address,
                                 channel=int(obex.channels[0]))
    store.send(bt.obex_connect())
    connect = bt.parse_obex_packet(store.recv(200))
    assert connect["opcode"] == 0xA0 and connect["response"] == "OK"
    store.send(bt.obex_get("telecom/pb.vcf"))
    pulled = bt.parse_obex_packet(store.recv(4096))
    assert pulled["response"] == "OK" and pulled["name"] == "telecom/pb.vcf"
    assert b"BEGIN:VCARD" in (pulled.get("body") or b"")
    # a channel the device does not offer is not open at all
    refused = [number for number in range(1, 13) if number not in set(phone.channels)]
    assert refused
    assert blesim.rfcomm_socket(ctx=None, address=phone.address, channel=refused[-1]) is None


def test_a_fragile_stack_falls_over_and_a_hardened_one_does_not():
    airspace = blesim.ble()
    fragile = airspace.pick("fragile")
    hardened = airspace.pick("hardened")
    assert fragile is not None and hardened is not None

    # a configure request whose MTU option block runs past the PDU: the BlueBorne shape
    options = bytes([0x01, 0x02]) + struct.pack("<H", 0x0000) + bytes([0x00])
    configure = bytes([0x04, 0x02]) + struct.pack("<HHH", 672, 0x0000, len(options)) + options
    for device, dies in ((fragile, True), (hardened, False)):
        link = airspace.open_link(device, handle=0x0040)
        blesim.VirtualController(airspace).feed(
            bt.acl_packet(0x0040, bt.l2cap_frame(0x0001, configure)))
        assert (not link.alive) is dies, (device.address, device.profile)


def test_the_floor_is_written_as_a_capture_the_audits_read(tmp_path):
    path = str(tmp_path / "floor.pcap")
    blesim.write_capture(path, seconds=6.0, seed=7)
    frames = list(bt.iter_le_frames(path))
    assert len(frames) >= 50
    advertising = [packet for _stamp, packet in frames if packet.get("advertising")]
    assert len(advertising) >= 40
    assert any(packet.get("address") for packet in advertising)
    # the capture has to carry the connection too, or the pairing and GATT audits have
    # nothing to read: the security manager and the attribute table live on the data channel
    assert any(not packet.get("advertising") for _stamp, packet in frames)


def test_the_offline_audits_read_the_simulated_floor(ctx, ap):
    census = ATTACK_CLASSES["bt_device_census"]().run(ctx, ap)
    assert census.status == "success"
    assert (census.extra or {}).get("devices") and census.detail
    tracker = ATTACK_CLASSES["bt_tracker_detect"]().run(ctx, ap)
    assert tracker.status == "success"
    assert (tracker.extra or {}).get("trackers") or "tracker" in tracker.detail.lower()


def test_an_on_air_attack_speaks_to_the_simulated_floor(ctx, ap):
    scan = ATTACK_CLASSES["bt_le_scan"]().run(ctx, ap)
    assert scan.status == "success"
    assert "device" in scan.result and (scan.extra or {}).get("demo") is True
    gatt = ATTACK_CLASSES["bt_gatt_enumeration"]().run(ctx, ap)
    assert gatt.status == "success"
    assert (gatt.extra or {}).get("demo") is True
    knob = btred.KnobAttack().run(ctx, ap)
    assert knob.status == "success"
    transcript = (knob.extra or {}).get("transcript") or []
    assert transcript, "a battery that was never sent has nothing to report"
    assert any(entry.get("answer") for entry in transcript), \
        "the simulated controller answered none of the KNOB probes"


def test_the_target_is_chosen_once_per_run(ctx):
    first = blesim.choose_target("bt_blueborne", role="fragile")
    assert first == blesim.choose_target("bt_blueborne", role="fragile")
    assert first in {device.address for device in blesim.ble().candidates("fragile")}
    # a device that was taken down is reconnected for the next run, and remembered
    airspace = blesim.ble()
    link = airspace.open_link(airspace.by_address(first), handle=0x0040)
    link.dies("the test said so")
    again = airspace.open_link(airspace.by_address(first), handle=0x0040)
    assert again.alive and airspace.by_address(first).crashes >= 1


# --------------------------------------------------------------------------- #
# the IT segment
# --------------------------------------------------------------------------- #

def test_the_segment_is_internally_consistent():
    lan = itsim.demo_lan()
    assert len(lan.hosts) == 51
    ips = [host.ip for host in lan.hosts]
    assert len(ips) == len(set(ips))
    for host in lan.hosts:
        assert host.profile_name in itsim.PROFILES
        assert host.ports, f"{host.hostname} exposes no port to test"
        assert host.device and host.vendor
    summary = lan.summary()
    assert summary["hosts"] == 51 and summary["profiles"] == len(itsim.PROFILES)
    assert len(summary["responders"]) == len(itsim.RESPONDERS) == 45
    # the IT attacks and the simulation read one segment, not two
    assert itsim.demo_lan() is lan


def test_the_segment_answers_every_protocol_it_claims():
    lan = itsim.demo_lan()
    from wifipilot import itproto as proto

    mqtt = lan.pick(port=1883)
    assert mqtt is not None
    assert lan.exchange(mqtt.ip, 1883, proto.mqtt_connect())[:4] == b"\x20\x02\x00\x00"
    ssdp = lan.pick(port=1900)
    assert ssdp is not None
    answer = lan.exchange(ssdp.ip, 1900, proto.ssdp_msearch())
    assert proto.parse_ssdp(answer.decode("latin-1", "replace"))["headers"]
    http = lan.pick(port=80)
    assert http is not None
    response = lan.exchange(http.ip, 80, proto.http_request(http.ip, "/", method="GET"))
    assert b"HTTP/1." in response
    assert lan.exchanges >= 3


def test_a_sweep_walks_the_weakest_host_first():
    lan = itsim.demo_lan()
    ranked = itsim.hosts_by_weakness(lan.hosts)
    ranks = [itsim.profile_rank(host.profile_name) for host in ranked]
    assert ranks == sorted(ranks)
    weakest = lan.candidates(device_ids=("router",))[0]
    assert itsim.profile_rank(weakest.profile_name) <= itsim.profile_rank(
        lan.hosts[0].profile_name) or weakest.profile_name != "hardened"


# --------------------------------------------------------------------------- #
# one world, three front ends
# --------------------------------------------------------------------------- #

def test_the_library_describes_both_simulations():
    data = api.simulations()
    assert set(data) == {"edition", "bluetooth", "it"}
    assert data["bluetooth"]["devices"] >= 40
    assert data["bluetooth"]["catalog"] and data["it"]["catalog"]
    assert data["it"]["hosts"] == 51
    assert "bluetooth" in api.simulations("ble") and "it" not in api.simulations("ble")
    with pytest.raises(api.TargetError):
        api.simulations("nope")


def test_the_cli_prints_both_simulations(capsys):
    from wifipilot.cli import main

    assert main(["sim", "--json", "--no-color"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["bluetooth"]["devices"] and data["it"]["hosts"] == 51
    assert main(["sim", "--domain", "it", "--list", "--no-color"]) == 0
    text = capsys.readouterr().out
    assert "IT segment" in text and "Bluetooth floor" not in text
    assert main(["sim", "--domain", "nope", "--no-color"]) == 1


def test_the_web_exposes_the_simulations_and_the_floor(config):
    from fastapi.testclient import TestClient

    from wifipilot.web.app import create_app

    config.demo = True
    with TestClient(create_app(config, demo=True)) as client:
        data = client.get("/api/sim").json()
        assert data["bluetooth"]["devices"] and data["it"]["hosts"] == 51
        assert len(client.get("/api/sim", params={"limit": 3}).json()["bluetooth"]["catalog"]) == 3
        only_it = client.get("/api/sim", params={"domain": "it"}).json()
        assert "it" in only_it and "bluetooth" not in only_it
        device = blesim.ble().pick("le")
        picked = client.post("/api/sim/target", json={"address": device.address}).json()
        assert picked["selected"]["bt"] == device.address and picked["device"]["address"]
        assert client.post("/api/sim/target", json={}).status_code == 400
        assert client.post("/api/sim/target",
                           json={"address": "aa:bb:cc:dd:ee:ff"}).status_code == 404
        shelf = client.get("/api/devices").json()
        assert len(shelf["demo_ble"]) >= 40 and len(shelf["demo_hosts"]) == 51


def test_the_attacks_of_both_editions_are_exercisable_in_demo(ctx, ap):
    """The point of the simulations: no radio, no lab, and every parser still runs."""
    results = {}
    for name in ("bt_le_scan", "bt_sdp_browse", "bt_gatt_enumeration", "bt_bluesnarf",
                 "it_mqtt_discover", "ssdp_device_census", "it_http_default_creds"):
        outcome = ATTACK_CLASSES[name]().run(ctx, ap)
        results[name] = outcome
        assert outcome.status == "success", (name, outcome.result, outcome.detail)
        assert outcome.result or outcome.detail
    assert "device" in results["bt_le_scan"].result
    assert results["it_mqtt_discover"].extra.get("simulated") is True
    assert results["bt_le_scan"].extra.get("demo") is True
    # and the registry is the one that was exercised
    assert len([name for name in ATTACK_CLASSES if name.startswith("bt_")]) == 35
    # eight from the HID wave, twenty-five from the imitation wave, fifty from the
    # takeover wave that followed them, and twenty-five peripherals
    assert len([name for name in ATTACK_CLASSES if name.startswith("ble_")]) == 108
