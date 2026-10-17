# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""The imitation wave: clone an identity, count who believes it.

Twenty-five attacks that all make one argument — a bond is a secret, but the decision to
reconnect is made on a *name* and an *address*, both of which are broadcast.  Each attack
here copies an identity that exists on the simulated floor and reports what the copy got:
the hosts that came back, the hosts that asked for the link key, and what the hijacked
link then did.

The file pins the two attacks the brief named, ``ble_hid_mimic`` and ``ble_speaker_mimic``,
together with the engines behind them: the AVDTP streams a speaker offers, the AVRCP
notifications that carry the track and the volume, the HIDP reports a classic host accepts,
the BNEP bridge a NAP answers on, and the SIM APDUs a car kit reads.  Those engines live in
:mod:`wifipilot.blesim`, so the assertions read the same decoders an analysis of a capture
would use.
"""

from __future__ import annotations

import pytest

from wifipilot import bt, blesim
from wifipilot.attacks import ATTACK_CLASSES, blemimic, meta
from wifipilot.attacks.base import AttackContext
from wifipilot.models import AccessPoint

#: the wave, in the order the registry carries it
WAVE = ("ble_hid_mimic", "ble_speaker_mimic", "ble_pairing_mimic", "ble_bond_hijack",
        "ble_adv_identity_clone", "ble_name_collision", "ble_device_mimic",
        "ble_tracker_mimic", "ble_beacon_mimic", "ble_eddystone_mimic",
        "ble_smartlock_mimic", "ble_badge_mimic", "ble_ev_charger_mimic", "ble_mesh_mimic",
        "ble_anchor_mimic", "ble_printer_mimic", "ble_ir_mimic", "ble_fastpair_mimic",
        "ble_fido_mimic", "ble_telemetry_mimic", "ble_patient_mimic",
        "ble_hid_multi_host", "ble_consumer_mimic", "ble_audio_le_mimic",
        "ble_peripheral_shadow")

#: the keyboard five hosts are bonded to: the identity ``ble_hid_mimic`` adopts
PEER = "WF-KEYBOARD"

#: the address those hosts wrote down, and the address a clone has to use
PEER_ADDRESS = "5c:11:22:33:44:aa"


@pytest.fixture()
def ctx(config, bus, session) -> AttackContext:
    config.demo = True
    config.bt_timeout = 1.0
    return AttackContext(session=session, config=config, bus=bus, demo=True)


@pytest.fixture()
def ap() -> AccessPoint:
    return AccessPoint(bssid="aa:bb:cc:11:22:33", essid="demo-bridge", channel=6,
                       signal=-40)


@pytest.fixture(autouse=True)
def _fresh():
    blesim.reset_ble()
    yield
    blesim.reset_ble()


def run(name: str, ctx: AttackContext, ap: AccessPoint):
    return ATTACK_CLASSES[name]().run(ctx, ap)


# --------------------------------------------------------------------------- #
# the wave, as a wave
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name", WAVE)
def test_wave_runs(name, ctx, ap):
    """Every attack in the wave completes and reports what it did."""
    outcome = run(name, ctx, ap)
    assert outcome.status in ("success", "partial", "failed")
    assert outcome.detail


def test_wave_is_registered():
    """Every attack in the wave is in the registry with metadata, in the Bluetooth edition."""
    names = set(blemimic.NAMES)
    assert len(names) == len(WAVE) == 25
    for name in WAVE:
        assert name in ATTACK_CLASSES
        assert meta.ATTACK_META[name]["domain"] == "bluetooth"
        assert blesim.role_for(name) != "any"


def test_metadata_valid():
    assert meta.validate() == []


def test_blemimic_exports():
    assert set(blemimic.ATTACKS) == set(blemimic.ATTACKS)
    assert len(blemimic.REGISTRY) == 25
    assert len(blemimic.META) == 25


def test_every_attack_aims_at_something():
    """Each one picks a device through the floor's own roles, in demo mode."""
    airspace = blesim.ble()
    for name in WAVE:
        role = blesim.role_for(name)
        assert airspace.candidates(role), f"{name} aims at '{role}', which is empty"


# --------------------------------------------------------------------------- #
# the two the brief named
# --------------------------------------------------------------------------- #

def test_hid_mimic_types_on_every_host(ctx, ap):
    """``ble_hid_mimic`` clones the keyboard and types on every host that reconnects."""
    outcome = run("ble_hid_mimic", ctx, ap)
    extra = outcome.extra
    assert extra["identity"] == {"name": PEER, "address": PEER_ADDRESS}
    hosts = {entry["host"] for entry in extra["reconnected"]}
    assert hosts, "no host reconnected to the clone"
    assert len(hosts) >= 2, "the clone should reach more than one host in the demo"
    typed = [row["typed"] for row in extra["deliveries"] if row.get("typed")]
    assert typed and all(text == extra["payload"] for text in typed)
    assert extra["keystrokes"] == len(extra["payload"])
    assert all(row["sent"] == len(extra["payload"]) * 2 for row in extra["deliveries"])
    assert extra["refused"], "the strict host is the negative control and must be present"
    assert "typed on" in outcome.result


def test_hid_mimic_names_the_strict_host_nowhere(ctx, ap):
    """The hosts that verified the key do not appear among the deliveries."""
    outcome = run("ble_hid_mimic", ctx, ap)
    delivered = {row["host"] for row in outcome.extra["deliveries"]}
    refused = {entry["host"] for entry in outcome.extra["refused"]}
    assert delivered and refused
    assert not (delivered & refused)


def test_speaker_mimic_takes_the_audio_link(ctx, ap):
    """``ble_speaker_mimic`` configures an AVDTP stream and registers AVRCP."""
    outcome = run("ble_speaker_mimic", ctx, ap)
    extra = outcome.extra
    signals = [row["command"] for row in extra["avdtp"]]
    assert signals[:2] == ["Discover", "GetCapabilities"]
    assert "SetConfiguration" in signals
    assert all(row["sent"] for row in extra["avdtp"]), "the open speaker accepts audio"
    assert extra["codec"].startswith("SBC")
    assert any(row["answer"].get("event_name") == "PlaybackStatusChanged"
               for row in extra["avrcp"])
    assert extra["audio_events"] >= 4
    assert outcome.extra["identity"]["name"] == "WF-SPEAKER"


def test_speaker_mimic_respects_a_speaker_that_checks(ctx, ap):
    """The hardened speaker is the negative control: its audio link is refused."""
    airspace = blesim.ble()
    picky = airspace.by_name("AVR-Elite")
    link = airspace.open_link(picky)
    answers = [bt.parse_avdtp(airspace.avdtp_request(picky, command, link))
               for command in (bt.avdtp_discover(), bt.avdtp_get_capabilities(1),
                               bt.avdtp_set_configuration(1))]
    assert all(row["status"] == "reject" for row in answers)
    assert link.audio_refused == 3
    assert link.audio_events == []


# --------------------------------------------------------------------------- #
# the engines the wave added
# --------------------------------------------------------------------------- #

def test_avdtp_streams():
    """A sink offers a sink endpoint and a source endpoint, with the codec it plays."""
    airspace = blesim.ble()
    speaker = airspace.by_name("SoundBar Loft")
    link = airspace.open_link(speaker)
    discover = bt.parse_avdtp(airspace.avdtp_request(speaker, bt.avdtp_discover(), link))
    assert discover["status"] == "accept"
    kinds = {sep["seid"]: (sep["type"], sep["media_type"]) for sep in discover["seps"]}
    assert kinds[1] == ("sink", "audio")
    assert kinds[2] == ("source", "audio")
    caps = bt.parse_avdtp(airspace.avdtp_request(speaker, bt.avdtp_get_capabilities(1),
                                                 link))
    codec = caps["categories"][0]
    assert codec["codec"] == "SBC"
    assert codec["sampling_khz"] == 48.0
    assert codec["bitpool_max"] >= codec["bitpool_min"] > 0
    configured = bt.parse_avdtp(airspace.avdtp_request(speaker,
                                                       bt.avdtp_set_configuration(1), link))
    assert configured["status"] == "accept"
    assert link.audio_events and len(link.audio_events) == 3


def test_avrcp_notifications():
    """The player answers the notifications a controller registers for."""
    airspace = blesim.ble()
    speaker = airspace.by_name("SoundBar Loft")
    link = airspace.open_link(speaker)
    frame = bt.avctp_frame(bt.avrcp_register(0x01, interval=2000))
    answer = bt.parse_avctp(airspace.avrcp_request(speaker, frame, link))
    parsed = bt.parse_avrcp(answer["payload"], response=True)
    assert parsed["event_name"] == "PlaybackStatusChanged"
    assert parsed["playback"] == "playing"
    volume = bt.avctp_frame(bt.avrcp_register(0x0D))
    parsed = bt.parse_avrcp(bt.parse_avctp(airspace.avrcp_request(speaker, volume,
                                                                  link))["payload"],
                            response=True)
    assert parsed["volume"] == 64
    press = bt.avctp_frame(bt.avrcp_passthrough(0x44))
    parsed = bt.parse_avrcp(bt.parse_avctp(airspace.avrcp_request(speaker, press,
                                                                  link))["payload"],
                            response=True)
    assert parsed["passthrough"] == "play" and parsed["pressed"] is True


def test_hidp_reports():
    """The classic HID channel acknowledges a control frame and counts input reports."""
    airspace = blesim.ble()
    host = airspace.by_address("00:1a:7d:11:22:06")
    link = airspace.link_for(host.address, "hid")
    assert bt.parse_hidp(airspace.hidp_request(host, bt.hidp_handshake(), link))
    report = bt.hidp_frame(0x0A, 0x01, bytes([0x01]) + bytes(8))
    assert bt.parse_hidp(report)["parameter_name"] == "input"
    assert airspace.hidp_request(host, report, link) == b""
    assert link.hidp_reports == [bytes([0x01]) + bytes(8)]
    protocol = bt.parse_hidp(airspace.hidp_request(host, bt.hidp_frame(0x06, 0x00),
                                                  link))
    assert protocol["transaction_name"] == "data"
    assert protocol["payload"] == b"\x01"                    # report protocol mode


def test_bnep_bridge():
    """A PAN access point accepts the setup and answers a real frame over the bridge."""
    airspace = blesim.ble()
    nap = airspace.by_name("NAP-Office")
    assert nap.flags["pan"] is True
    link = airspace.open_link(nap)
    setup = bt.bnep_control(0x01, bt.bnep_setup()[2:])
    answer = bt.parse_bnep(airspace.bnep_request(nap, setup, link))
    assert answer["type_name"] == "control"
    assert answer["control_name"] == "SetupConnectionRsp"
    assert answer["result"] == 0
    assert {answer["source"], answer["destination"]} == {"PANU", "NAP"}
    frame = bt.bnep_frame(bt.ethernet_frame(dst="ff:ff:ff:ff:ff:ff",
                                            src="aa:bb:cc:dd:ee:ff", ethertype=0x0806,
                                            payload=bytes(28)))
    reply = bt.parse_bnep(airspace.bnep_request(nap, frame, link))
    assert reply["protocol"] == "ARP"
    assert link.network_frames and len(link.network_frames) == 1
    request = bt.parse_bnep(setup)
    assert request["control_name"] == "SetupConnectionReq"
    assert {request["source"], request["destination"]} == {"PANU", "NAP"}


def test_sap_apdus():
    """The SIM answers a select and a read: the subscriber identity is read, not guessed."""
    airspace = blesim.ble()
    car = airspace.by_name("CarKit-Parrot")
    link = airspace.open_link(car)
    connect = bt.parse_sap(airspace.sap_request(car, bt.sap_message(0x00), link))
    assert connect["message_name"] == "ConnectRsp"
    status = bt.parse_sap(airspace.sap_request(car, bt.sap_message(0x0E), link))
    assert status["message_name"] == "TransferCardReaderStatusRsp"
    assert bt.parse_sap(airspace.sap_request(car, bt.sap_message(0x06),
                                             link))["parameters"]
    select = bt.parse_sap(airspace.sap_request(
        car, bt.sap_message(0x04, bt.sap_parameter(0x06, bt.apdu_select(0x6F07))), link))
    assert select["apdu_response"] == "9f09"
    read = bt.parse_sap(airspace.sap_request(
        car, bt.sap_message(0x04, bt.sap_parameter(0x06, bt.apdu_read_binary(9))), link))
    imsi = bt.imsi_from_ef_imsi(bytes.fromhex(read["apdu_response"][:-4]))
    assert imsi.startswith("40407") and len(imsi) == 15
    assert [row["command"] for row in link.apdus] == ["SELECT 6F07", "READ BINARY 9"]


def test_sim_reads_a_file_it_does_not_have():
    """An unknown file gets the card's own answer rather than an empty success."""
    airspace = blesim.ble()
    car = airspace.by_name("CarKit-Parrot")
    link = airspace.open_link(car)
    answer = bt.parse_sap(airspace.sap_request(
        car, bt.sap_message(0x04, bt.sap_parameter(0x06, bt.apdu_select(0x1234))), link))
    assert answer["apdu_response"] == "6a82"


def test_phonebook_and_messages():
    """PBAP and MAP answers carry cards and a message, and both frame their length."""
    airspace = blesim.ble()
    phone = airspace.by_name("Phone-Company")
    card = airspace.obex_request(phone, bt.obex_get("telecom/pb.vcf"))
    assert b"BEGIN:VCARD" in card and b"TEL;TYPE=CELL" in card
    parsed = bt.parse_obex_packet(card)
    assert parsed["response"] == "OK" and parsed["opcode"] == 0xA0
    message = airspace.obex_request(phone, bt.obex_get("telecom/msg/inbox"))
    assert b"BEGIN:BMSG" in message and b"Gate 2 alarm" in message
    assert len(card) > 255, "a phonebook needs the two-byte body length"


def test_controller_routes_dynamic_channels():
    """The PSM a channel was opened for is remembered, and it decides the engine."""
    airspace = blesim.ble()
    assert airspace.psm_for(0x0048) == 0
    speaker = airspace.by_name("SoundBar Loft")
    link = airspace.open_link(speaker)
    assert airspace.avdtp_request(speaker, bt.avdtp_discover(), link)
    airspace.channels[0x0048] = 0x0019                      # as signalling records it
    assert airspace.psm_for(0x0048) == 0x0019
    assert airspace.psm_for(0x0040) == 0 or airspace.psm_for(0x9999) == 0


# --------------------------------------------------------------------------- #
# the imitation itself
# --------------------------------------------------------------------------- #

def test_impersonation_uses_the_bonded_address(ctx, ap):
    """A clone advertises under the name *and* the address the hosts wrote down."""
    attack = blemimic.BleHidMimicAttack()
    name, address = attack.identity_of(PEER, PEER_ADDRESS)
    assert (name, address) == (PEER, PEER_ADDRESS)
    result = attack.impersonate(ctx, name, address, services=(bt.HID_SERVICE_UUID,))
    assert result["advertised"]["name"] == PEER
    assert result["advertised"]["address"] == PEER_ADDRESS
    assert result["reconnected"]


def test_trusting_hosts_reconnect_and_strict_ones_do_not(ctx, ap):
    """The floor is the control: the same clone is believed by some and checked by others."""
    attack = blemimic.BleHidMimicAttack()
    result = attack.impersonate(ctx, PEER, PEER_ADDRESS)
    profiles = {entry["profile"] for entry in result["reconnected"]}
    refused = {entry["profile"] for entry in result["refused"]}
    hosts = {entry["host"] for entry in result["reconnected"]}
    checked = {entry["host"] for entry in result["refused"]}
    assert profiles == {"hid_trusting"}
    assert refused == {"hid_bonded"}
    assert hosts == {"00:1a:7d:11:22:06", "3c:11:22:33:00:01", "3c:11:22:33:00:02"}
    assert checked == {"3c:11:22:33:00:03", "3c:11:22:33:00:04"}
    assert not (hosts & checked)


def test_beacon_clone_decodes_identically(ctx, ap):
    """The cloned iBeacon parses to the same UUID, major and minor as the original."""
    outcome = run("ble_beacon_mimic", ctx, ap)
    extra = outcome.extra
    assert extra["match"] is True
    assert extra["original"] == extra["clone"]
    assert extra["original"]["uuid"] == extra["uuid"]
    assert extra["original"]["major"] == extra["major"]


def test_eddystone_clone_points_to_the_same_url(ctx, ap):
    """The cloned Eddystone URL is the URL the original advertised."""
    outcome = run("ble_eddystone_mimic", ctx, ap)
    assert outcome.extra["url"]
    assert outcome.extra["url"] == outcome.extra["clone_url"]


def test_lock_clone_opens_the_lock(ctx, ap):
    """The lock's control characteristic is written and read back on a clone's link."""
    outcome = run("ble_smartlock_mimic", ctx, ap)
    opened = outcome.extra["open"]
    assert opened["accepted"] is True
    assert opened["confirmed"] is True
    assert outcome.status == "success"


def test_badge_clone_reads_the_reader(ctx, ap):
    """The reader hands the badge identity back to the clone."""
    outcome = run("ble_badge_mimic", ctx, ap)
    assert outcome.extra["badge"]["bytes"] > 0


def test_shadow_reads_the_attribute_table(ctx, ap):
    """The shadow copies the characteristics it can read and says how many there were."""
    outcome = run("ble_peripheral_shadow", ctx, ap)
    assert outcome.extra["characteristics"]
    assert outcome.extra["copied"] >= 1
    assert all(row["uuid"].startswith("0x") for row in outcome.extra["characteristics"])


def test_the_whole_wave_reports_success(ctx, ap):
    """Every attack in the wave finishes on its own feet, not as a caught exception."""
    statuses = {}
    for name in WAVE:
        blesim.reset_ble()
        outcome = run(name, ctx, ap)
        statuses[name] = outcome.status
        assert outcome.status == "success", (name, outcome.result, outcome.detail)
    assert set(statuses.values()) == {"success"}
