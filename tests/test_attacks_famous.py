"""The famous wave: KRACK, FragAttacks, airgeddon, and nine named Bluetooth attacks.

The brief named these attacks one by one, and the tests here hold the wave to the same
three standards as the two before it:

* **the protocol bytes are real** — an OBEX CONNECT parses back to the version and packet
  size it was built with, an RFCOMM frame survives its own FCS, a HID report is eight
  bytes a host would type, and the link-control commands carry the opcode the
  specification gives them;
* **the famous shapes are the shapes** — a KRACK replay is message 3 of a real captured
  handshake in a QoS data frame with the retry bit set, and a FragAttacks injection is a
  plaintext A-MSDU with the aggregation bit set, a gateway source address and the
  fragment numbering the advisories describe;
* **the registry and the documentation agree** — every attack in the wave has metadata, a
  budget, a place in the planner's action set and a line in the generated tables.

The one thing no test can do here is put a radio on the air: the live paths are exercised
through the demo engine, which is why every live attack in the wave has to *report* what
it would have sent rather than claim it sent it.
"""

from __future__ import annotations

import os
import struct

import pytest

from wifipilot import bt
from wifipilot.attacks import (ATTACK_CLASSES, DEFAULT_ORDER, attack_catalog)
from wifipilot.attacks import meta
from wifipilot.attacks import btred
from wifipilot.attacks.btred import ATTACKS as BTRED_ATTACKS
from wifipilot.attacks.btred import META as BTRED_META
from wifipilot.attacks.btred import _scan_events
from wifipilot.attacks.famous import (ATTACKS as FAMOUS_ATTACKS, META as FAMOUS_META,
                                      _data_frame, _eapol_messages)
from wifipilot.config import Config
from wifipilot.models import ATTACK_NAMES, AccessPoint, Capture
from wifipilot.rawtx import header_offset
from wifipilot.synth import build_capture

AP_MAC = "aa:bb:cc:11:22:33"
STA_MAC = "02:00:00:00:00:09"
SSID = "TestNet"
PSK = "TestNet2024"

#: the twelve attacks this wave adds
FAMOUS = ("bt_blueborne", "bt_bias", "bt_knob", "bt_bluebugging", "bt_blesa",
          "bt_sweyntooth", "bt_bluesnarf", "bt_bluesmack", "bt_hid_injection",
          "krack_replay", "fragattacks_inject", "airgeddon_portal")

#: the wave as one table, for the tests that iterate
WAVES = {"btred": (BTRED_ATTACKS, BTRED_META), "famous": (FAMOUS_ATTACKS, FAMOUS_META)}

#: the two attacks whose "battery" is a serial-profile transcript rather than link-layer
#: PDUs: BlueBugging drives an RFCOMM socket and BlueSnarfing an OBEX session, so their
#: payloads are tested as transcripts instead of as HCI packets
SERIAL_ATTACKS = ("bt_bluebugging", "bt_bluesnarf")


def _attack(name: str, config: Config, session, demo: bool = True,
            ap: AccessPoint = None) -> object:
    """Run one attack in demo mode against the shared test access point."""
    from wifipilot.attacks.base import AttackContext

    target = ap or AccessPoint(bssid=AP_MAC, essid=SSID, channel=6, encryption="WPA2",
                               signal=-42, vendor="Test")
    context = AttackContext(session=session, config=config, bus=session.bus, demo=demo)
    return ATTACK_CLASSES[name]().run(context, target)


class _FakeContext:
    """The attributes the frame builders read, without a whole session.

    The builders take a real ``AttackContext`` in production; here they need the gateway
    settings, a monitor interface, an empty capture list and a directory the airgeddon
    workspace can be written to.
    """

    demo = True
    monitor = ""

    class config:                                             # noqa: N801
        gateway_mac = "de:ad:be:ef:00:01"
        gateway_ip = "192.168.1.1"
        bt_target = ""
        bt_handle = 0x0040
        hid_payload = "id"                       # two characters: four reports

    class session:                                            # noqa: N801
        state_dir = "/tmp/wifipilot-famous-test"

        @staticmethod
        def all_captures():
            return []


# --------------------------------------------------------------------------- #
# the registry: the wave is wired in, complete and budgeted
# --------------------------------------------------------------------------- #


def test_the_famous_wave_is_registered():
    assert len(BTRED_ATTACKS) == 9
    assert len(FAMOUS_ATTACKS) == 3
    for name in FAMOUS:
        assert name in ATTACK_CLASSES, name
        assert name in DEFAULT_ORDER, name
        assert name in ATTACK_NAMES, name
    # 248 from the famous/Bluetooth waves + 213 services-and-devices + the 73
    # cross-cutting version/cleartext audits every service now carries + the 8 of the
    # BLE wave (HID injection, the downgrades around it, and identity) + the 25 of the
    # imitation wave (keyboards, speakers, tags, locks: devices faked convincingly)
    assert len(DEFAULT_ORDER) == 617


def test_registry_and_documentation_agree():
    """What the tool ships and what the docs claim have to be the same number."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for relative in ("README.md", os.path.join("docs", "ATTACKS.md")):
        with open(os.path.join(root, relative), encoding="utf-8") as handle:
            text = handle.read()
        assert f"{len(DEFAULT_ORDER)} attacks" in text, relative
    assert meta.validate() == []
    assert len(attack_catalog()) == len(DEFAULT_ORDER)


def test_every_famous_attack_has_a_budget(config):
    for name in FAMOUS:
        assert config.attack_timeout_for(name) > 0, name


def test_famous_metadata_is_complete():
    for wave, (attacks, metadata) in WAVES.items():
        for cls in attacks:
            entry = metadata[cls.name]
            assert entry["category"] in {item["name"] for item in meta.CATEGORIES}, wave
            assert entry["noise"] in meta.NOISE_LEVELS, wave
            assert entry["impact"] in meta.IMPACT_LEVELS, wave
            assert entry["detection"].strip(), wave
            assert cls.label.strip(), cls.name
            assert cls.tool.strip(), cls.name
            assert cls.description.strip(), cls.name


def test_famous_wave_is_opt_in(config):
    """Nothing in the wave runs by default: a site did not ask to be attacked."""
    for name in FAMOUS:
        assert name not in config.attacks, name


# --------------------------------------------------------------------------- #
# the protocol helpers: OBEX, RFCOMM, HID, LMP
# --------------------------------------------------------------------------- #


def test_obex_round_trips():
    connect = bt.parse_obex_packet(bt.obex_connect(max_packet_size=2048))
    assert connect["request"] == "CONNECT"
    assert connect["version"] == 0x10
    assert connect["max_packet_size"] == 2048

    get = bt.parse_obex_packet(bt.obex_get("telecom/pb.vcf"))
    assert get["request"] == "GET"
    assert get["name"] == "telecom/pb.vcf"

    utf16 = bt.parse_obex_packet(bt.obex_get("telecom/cal.vcs", utf16=True))
    assert utf16["name"] == "telecom/cal.vcs"

    setpath = bt.parse_obex_packet(bt.obex_setpath("telecom"))
    assert setpath["request"] == "SETPATH"
    assert setpath["setpath_flags"] == 0
    assert setpath["name"] == "telecom"

    reply = bt.parse_obex_packet(bt.obex_packet(0xA0, [
        bt.obex_header(0xC3, (1234).to_bytes(4, "big"))]))
    assert reply["response"] == "OK"
    assert reply["headers"][0]["number"] == 1234

    body = bt.parse_obex_packet(bt.obex_packet(0x83, body=b"BEGIN:VCARD\r\nEND:VCARD\r\n"))
    assert body["body"] == b"BEGIN:VCARD\r\nEND:VCARD\r\n"


def test_rfcomm_frames_round_trip_and_check_their_fcs():
    frame = bt.rfcomm_frame(bt.rfcomm_dlci(3), b"AT+CKPD=200\r")
    parsed = bt.parse_rfcomm(frame)
    assert parsed["channel"] == 3
    assert parsed["payload"] == b"AT+CKPD=200\r"
    assert parsed["fcs_ok"] is True

    corrupted = bytearray(frame)
    corrupted[-1] ^= 0xFF
    assert bt.parse_rfcomm(bytes(corrupted))["fcs_ok"] is False

    # a payload over 127 bytes needs the two-octet length form, and has to survive it
    long_frame = bt.rfcomm_frame(bt.rfcomm_dlci(1), b"A" * 200)
    assert bt.parse_rfcomm(long_frame)["payload"] == b"A" * 200


def test_hid_reports_are_a_keyboard():
    assert len(bt.HID_KEYBOARD_REPORT_MAP) > 40
    assert bt.HID_KEYBOARD_REPORT_MAP[:2] == b"\x05\x01"          # usage page, generic desktop
    assert bt.hid_key("a") == 0x04 and bt.hid_key("enter") == 0x28
    assert bt.hid_key_reports("A")[0][0] == bt.HID_MODIFIERS["left shift"]
    assert bt.hid_key_reports("a")[0] == bt.hid_boot_report(0, [0x04])
    assert bt.hid_key_reports("a")[1] == bt.hid_boot_report(0, [])   # the release
    assert len(bt.hid_key_reports("id")) == 4

    table = bt.hid_gatt_table()
    uuids = {row["uuid_value"] for row in table}
    assert bt.HID_SERVICE_UUID in uuids
    assert 0x2A4B in uuids and 0x2A22 in uuids
    report_map = [row for row in table if row["uuid_value"] == 0x2A4B][0]
    assert report_map["value"] == bt.HID_KEYBOARD_REPORT_MAP

    notification = bt.hid_input_report(bt.hid_boot_report(0, [0x04]), 0x0025)
    # L2CAP header (length, ATT channel), then the ATT opcode: an 11-byte PDU
    assert notification[:4] == struct.pack("<HH", 11, 0x0004)
    assert notification[4] == 0x1B                                # handle value notification
    assert notification[5:7] == struct.pack("<H", 0x0025)         # the report handle


def test_link_control_commands_and_feature_pages():
    for name, (ogf, ocf) in bt.HCI_LINK_CONTROL.items():
        packet = bt.link_control(name)
        opcode = struct.unpack("<H", packet[1:3])[0]
        assert opcode == (ogf << 10) | ocf, name

    features = bt.explain_bredr_features(bytes([0x04, 0, 0, 0, 0, 0, 0, 0]), page=2)
    assert features["secure connections (controller)"] is True
    page0 = bt.explain_bredr_features(bytes([0x04, 0, 0, 0, 0, 0, 0, 0]), page=0)
    assert page0["encryption"] is True

    # a Read Remote Extended Features Complete event, built by hand
    event = bytes([0x04, bt.HCI_EVENT_READ_REMOTE_EXTENDED_FEATURES, 12, 0x00,
                   0x40, 0x00, 0x02]) + bytes([0x04, 0, 0, 0, 0, 0, 0, 0])
    parsed = bt.parse_features_event(event)
    assert parsed["handle"] == 0x0040
    assert parsed["page"] == 2
    assert parsed["names"]["secure connections (controller)"] is True


def test_event_scanner_reads_a_transcript():
    """The link-layer attacks judge a run by which events came back, not by a byte count."""
    encryption_change = bytes([0x04, 0x08, 0x05, 0x00, 0x40, 0x00, 0x01, 0x01])
    link_key_request = bytes([0x04, 0x17, 0x06]) + bytes.fromhex("aabbcc112233")
    events = _scan_events(encryption_change + link_key_request)
    assert [event["event"] for event in events] == [0x08, 0x17]
    assert events[0]["key_size"] == 1
    assert events[1]["address"] == "aa:bb:cc:11:22:33"


# --------------------------------------------------------------------------- #
# the Bluetooth wave: the batteries are real PDUs
# --------------------------------------------------------------------------- #


def test_every_red_attack_builds_a_battery_of_real_pdus():
    context = _FakeContext()
    ap = AccessPoint(bssid=AP_MAC, essid=SSID, channel=6)
    attacks = [cls for cls in BTRED_ATTACKS if cls.name not in SERIAL_ATTACKS]
    assert len(attacks) == 7
    for cls in attacks:
        attack = cls()
        battery = list(attack.battery(context, ap))
        assert battery, cls.name
        for label, packet in battery:
            assert label.strip(), cls.name
            assert packet[:1] in (b"\x01", b"\x02"), f"{cls.name}: {label} is not HCI"
            if packet[:1] == b"\x01":                        # a command: type + opcode + len
                declared = packet[3]
                assert declared == len(packet) - 4, f"{cls.name}: {label} length disagrees"
            else:                                             # ACL data: type + handle + len
                declared = struct.unpack("<H", packet[3:5])[0]
                assert declared == len(packet) - 5, f"{cls.name}: {label} length disagrees"


def test_serial_profile_attacks_carry_their_commands():
    """BlueBugging speaks AT, BlueSnarfing asks for objects: both are real transcripts."""
    from wifipilot.attacks.btred import SNARF_OBJECTS

    commands = ATTACK_CLASSES["bt_bluebugging"].COMMANDS
    assert len(commands) >= 6
    assert all(command.endswith(b"\r") for _label, command in commands)
    assert any(b"CKPD" in command for _label, command in commands)
    assert len(SNARF_OBJECTS) >= 5
    assert all(name.endswith((".vcf", ".vcs")) for name in SNARF_OBJECTS)
    assert "telecom/pb.vcf" in SNARF_OBJECTS


def test_blueborne_sends_the_malformed_shapes():
    context = _FakeContext()
    ap = AccessPoint(bssid=AP_MAC, essid=SSID, channel=6)
    labels = [label for label, _ in ATTACK_CLASSES["bt_blueborne"]().battery(context, ap)]
    assert any("information request" in label for label in labels)
    assert any("configure request" in label for label in labels)
    assert any("SDP" in label for label in labels)


def test_bluesmack_escalates_to_the_largest_echo_that_fits():
    context = _FakeContext()
    ap = AccessPoint(bssid=AP_MAC, essid=SSID, channel=6)
    attack = ATTACK_CLASSES["bt_bluesmack"]()
    packets = [packet for _label, packet in attack.battery(context, ap)]
    assert len(packets) == len(attack.SIZES)
    # the L2CAP frame inside the ACL packet is bounded by the 16-bit length field, and
    # the H4 type byte plus the ACL header are the five bytes around it
    largest = max(len(packet) for packet in packets)
    assert largest - 5 <= 0xFFFF
    assert len(packets[-1]) - 5 == 0xFFFF              # the maximum the specification allows
    assert b"A" * 600 in packets[0]


def test_hid_attack_advertises_a_keyboard_and_types_its_payload(config):
    config.hid_payload = "id"
    context = _FakeContext()
    ap = AccessPoint(bssid=AP_MAC, essid=SSID, channel=6)
    battery = ATTACK_CLASSES["bt_hid_injection"]().battery(context, ap)
    labels = [label for label, _ in battery]
    assert any("Advertise the HID service" in label for label in labels)
    assert sum("HID boot report" in label for label in labels) == 4      # two keys, press+release
    # the payload this *ships* with is a command line: it ends in the Enter key, because a
    # line that is never submitted has typed nothing
    assert btred.DEFAULT_HID_PAYLOAD.endswith("\n")
    assert len(bt.hid_key_reports(btred.DEFAULT_HID_PAYLOAD)) == \
        2 * len(btred.DEFAULT_HID_PAYLOAD)
    advertising = [packet for label, packet in battery if "HID service" in label][0]
    assert bytes([0x12, 0x18]) in advertising                       # the 0x1812 service UUID


# --------------------------------------------------------------------------- #
# the famous Wi-Fi shapes: KRACK and FragAttacks
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def handshake_path(tmp_path_factory) -> str:
    path = tmp_path_factory.mktemp("famous") / "handshake.pcap"
    build_capture(str(path), SSID, AP_MAC, STA_MAC, PSK)
    return str(path)


def test_krack_replay_uses_the_captured_message_three(handshake_path):
    messages = _eapol_messages(handshake_path)
    thirds = [entry for entry in messages if entry["message"] == 3]
    assert thirds, "the synthesised handshake has to contain message 3"
    assert thirds[0]["key_info"] & 0x0040                      # the install bit
    assert thirds[0]["eapol"][:2] == b"\x02\x03"                # EAPOL version, key

    ap = AccessPoint(bssid=AP_MAC, essid=SSID, channel=6)
    ap.clients[STA_MAC] = {}
    ap.captures.append(Capture(kind="handshake", bssid=ap.bssid, path=handshake_path))
    context = _FakeContext()
    attack = ATTACK_CLASSES["krack_replay"]()
    assert attack.copies(context, ap), "the capture has to be found through the session"
    frames = attack.frames(context, ap, 0)
    assert frames, "a message 3 in the capture means a replay frame on the air"
    frame = frames[0]
    offset = header_offset(frame)
    assert frame[offset] == 0x88                                # QoS data
    assert frame[offset + 1] & 0x08                             # the retry bit
    assert frame.find(b"\x88\x8e") > 0                          # the EAPOL ethertype


def test_krack_refuses_to_replay_nothing(config, session):
    """Without a handshake there is no message 3, and the attack says so."""
    outcome = _attack("krack_replay", config, session, demo=False)
    assert outcome.status == "skipped"
    assert "message 3" in outcome.detail


def test_fragattacks_builds_the_aggregation_shape():
    ap = AccessPoint(bssid=AP_MAC, essid=SSID, channel=6)
    context = _FakeContext()
    attack = ATTACK_CLASSES["fragattacks_inject"]()
    frame = attack.amsdu_frame(context, ap, STA_MAC)
    offset = header_offset(frame)
    assert frame[offset] == 0x88                                # QoS data
    assert frame[offset + 24] & 0x80                            # A-MSDU present
    # the subframe: client, then the gateway as the source, then a length that fits
    body = frame[offset + 26:]
    assert body[:6] == bytes.fromhex(STA_MAC.replace(":", ""))
    assert body[6:12] == bytes.fromhex("deadbeef0001")
    declared = struct.unpack(">H", body[12:14])[0]
    assert declared == len(body) - 14
    packet = body[14 + 8:]                                      # past the LLC/SNAP
    assert packet[12:16] == bytes.fromhex("c0a80101")           # the gateway's address


def test_fragattacks_builds_the_fragment_shapes():
    ap = AccessPoint(bssid=AP_MAC, essid=SSID, channel=6)
    context = _FakeContext()
    attack = ATTACK_CLASSES["fragattacks_inject"]()
    frames = attack.fragment_frames(context, ap, STA_MAC)
    offsets = [header_offset(frame) for frame in frames]
    controls = [frame[offset + 1] for frame, offset in zip(frames, offsets)]
    fragment_numbers = [frame[offset + 22] & 0x0F
                        for frame, offset in zip(frames, offsets)]
    run = len(frames) - 2                                       # the contiguous sequence
    assert fragment_numbers[:run] == list(range(run))
    assert all(control & 0x04 for control in controls[:run - 1])   # More Fragments set
    assert not controls[run - 1] & 0x04                            # off on the last fragment
    assert fragment_numbers[-1] == 3                            # the non-contiguous shape
    assert fragment_numbers[-2] == 0 and controls[-2] & 0x04


def test_data_frame_exposes_the_fields_the_shapes_need():
    frame = _data_frame(AP_MAC, STA_MAC, b"payload", qos=True, snap=True, amsdu=True,
                        frag=2, more_fragments=True, retry=True, seq=0x123)
    offset = header_offset(frame)
    assert frame[offset] == 0x88
    assert frame[offset + 1] & 0x02 and frame[offset + 1] & 0x04 and frame[offset + 1] & 0x08
    assert frame[offset + 24] & 0x80
    sequence = struct.unpack("<H", frame[offset + 22:offset + 24])[0]
    assert sequence & 0x0F == 2 and sequence >> 4 == 0x123


# --------------------------------------------------------------------------- #
# airgeddon: the pipeline is prepared, and the report says which path ran
# --------------------------------------------------------------------------- #


def test_airgeddon_workspace_holds_the_pipeline(config, session, tmp_path):
    ap = AccessPoint(bssid=AP_MAC, essid=SSID, channel=6)
    context = _FakeContext()
    context.session.state_dir = str(tmp_path)
    attack = ATTACK_CLASSES["airgeddon_portal"]()
    workspace = attack.workspace(context, ap)
    assert os.path.exists(workspace["hostapd"])
    assert os.path.exists(workspace["dnsmasq"])
    assert os.path.exists(os.path.join(workspace["portal"], "index.html"))
    with open(workspace["hostapd"], encoding="utf-8") as handle:
        hostapd = handle.read()
    assert f"ssid={SSID}" in hostapd and "channel=6" in hostapd
    with open(workspace["dnsmasq"], encoding="utf-8") as handle:
        dnsmasq = handle.read()
    assert "address=/#/" in dnsmasq                             # the blackhole
    with open(os.path.join(workspace["portal"], "index.html"), encoding="utf-8") as handle:
        portal = handle.read()
    assert "password" in portal                                 # a form that asks for it


def test_airgeddon_attack_reports_which_path_ran(config, session):
    outcome = _attack("airgeddon_portal", config, session)
    assert outcome.status == "success"
    assert "path" in outcome.extra
    assert "hostapd" in outcome.extra.get("pipeline", {})


# --------------------------------------------------------------------------- #
# the live paths run: in demo mode they report the battery instead of pretending
# --------------------------------------------------------------------------- #


def test_famous_live_attacks_run_in_demo(config, session):
    """Every transmitting attack in the wave finishes and says what it would have sent."""
    names = [name for name in FAMOUS if name not in ("krack_replay", "fragattacks_inject")]
    assert len(names) == 10
    for name in names:
        outcome = _attack(name, config, session)
        assert outcome.status == "success", f"{name}: {outcome.result}: {outcome.detail}"
        assert outcome.extra.get("simulated") or name == "airgeddon_portal"


def test_demo_runs_do_not_claim_a_radio(config, session):
    """A simulated run says so, and the counts are the PDUs that were answered.

    The Bluetooth batteries drive the simulated floor now, so an answer is either the
    peer's own protocol bytes or nothing at all — never a claim that a radio did
    something.  What the report has to keep honest is the arithmetic: every probe is in
    the transcript, and the number answered is the number with a body.
    """
    outcome = _attack("bt_blueborne", config, session)
    assert outcome.extra["simulated"] is True
    transcript = outcome.extra["transcript"]
    answered = [entry for entry in transcript if entry.get("answer")]
    assert len(answered) == outcome.extra["answered"] >= 1
    assert len(outcome.extra["unanswered"]) == len(transcript) - len(answered)
    assert set(outcome.extra["probes"]) == {entry["probe"] for entry in transcript}
    # the device that answered is a device on the floor, and the verdict reads it
    assert outcome.extra["target"] and outcome.extra["alive_after"] is not None
    assert outcome.extra["exposed"] is (outcome.extra["alive_after"] is False
                                        or bool(outcome.extra["unanswered"]
                                                and answered))
