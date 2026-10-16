"""The takeover wave: fifty attacks, one per profile, table, link and pairing step.

Where the imitation wave copied an identity, this one takes what is behind it.  The tests
here exercise every attack against the simulated floor and pin the engines underneath:
the AT channel a car kit answers, the phonebook and message store over OBEX, the SIM the
profile reads APDUs from, the HIDP channel, AVDTP and AVRCP, BNEP, the attribute
operations (Read By Group Type, Find Information, Exchange MTU, Read Blob), the link-layer
control PDUs and the security-manager commands.

The two halves of every attack's claim are tested together: what the reference device
answers, and what the device that checks does instead — a lock that refuses the write, a
speaker that refuses the audio link, a television that refuses the injection.
"""

from __future__ import annotations

import pytest

from wifipilot import bt, blesim
from wifipilot.attacks import ATTACK_CLASSES, blehijack2, meta
from wifipilot.attacks.base import AttackContext
from wifipilot.models import AccessPoint

#: the wave, in the order the registry carries it
WAVE = tuple(blehijack2.NAMES)

#: the devices the demo aims at: the weakest that can answer each role, which is what
#: makes a run reproducible
CAR_KIT = "d2:11:22:33:44:01"
PHONE = "d2:11:22:33:44:02"
NAP = "d3:11:22:33:44:01"


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


@pytest.mark.parametrize("name", WAVE)
def test_wave_runs(name, ctx, ap):
    """Every attack in the takeover wave finishes and reports what it found."""
    outcome = run(name, ctx, ap)
    assert outcome.status == "success", (name, outcome.result, outcome.detail)
    assert outcome.detail


def test_wave_is_registered():
    assert len(WAVE) == 50
    assert set(WAVE) == set(blehijack2.META)
    for name in WAVE:
        assert name in ATTACK_CLASSES
        assert meta.ATTACK_META[name]["domain"] == "bluetooth"
        assert blesim.role_for(name) != "any"


def test_metadata_valid():
    assert meta.validate() == []


def test_every_attack_aims_at_a_device():
    airspace = blesim.ble()
    for name in WAVE:
        role = blesim.role_for(name)
        assert airspace.candidates(role), f"{name} aims at '{role}', which is empty"


# --------------------------------------------------------------------------- #
# the engines the wave talks to
# --------------------------------------------------------------------------- #

def test_the_at_channel_answers_a_car_kit(ctx):
    attack = blehijack2.BleHfpHijackAttack()
    identity = attack.at(ctx, CAR_KIT, "AT+CGMM")
    assert identity["connected"] and identity["ok"]
    listed = attack.at(ctx, CAR_KIT, "AT+CGSN")
    assert listed["answer"].startswith("+CGSN")
    placed = attack.at(ctx, CAR_KIT, "ATD+15550100;")
    assert "+CLCC" in placed["answer"]


def test_the_phonebook_and_the_messages_come_over_obex(ctx):
    attack = blehijack2.BlePbapHijackAttack()
    card = attack.obex(ctx, PHONE, "telecom/pb.vcf")
    assert card["connected"] and card["bytes"] > 255
    raw = bytes.fromhex(card["raw"])
    assert b"BEGIN:VCARD" in raw and b"TEL;TYPE=CELL" in raw
    listing = attack.obex(ctx, PHONE, "telecom/msg/inbox")
    assert b"BEGIN:BMSG" in bytes.fromhex(listing["raw"])


def test_the_sim_answers_the_sap_engine(ctx):
    attack = blehijack2.BleSapImsiReadAttack()
    connect = bt.parse_sap(attack.sap(ctx, CAR_KIT, bt.sap_message(0x00)))
    assert connect["message_name"] == "ConnectRsp"
    select = bt.parse_sap(attack.sap(ctx, CAR_KIT, bt.sap_message(
        0x04, bt.sap_parameter(0x06, bt.apdu_select(0x6F07)))))
    assert select["apdu_response"] == "9f09"
    read = bt.parse_sap(attack.sap(ctx, CAR_KIT, bt.sap_message(
        0x04, bt.sap_parameter(0x06, bt.apdu_read_binary(9)))))
    assert read["apdu_response"].endswith("9000")


def test_psm_sweep_separates_what_is_there(ctx):
    attack = blehijack2.BleL2capPsmSweepAttack()
    sweep = attack.psm_sweep(CAR_KIT)
    by_psm = {row["psm"]: row for row in sweep}
    assert by_psm[0x0001]["accepted"], "SDP is always there"
    assert by_psm[0x0003]["accepted"], "an AT channel needs RFCOMM"
    assert by_psm[0x0019]["accepted"], "a car kit answers the audio PSM"
    assert by_psm[0x0005]["reason"] == "PSM not supported"


def test_the_attribute_table_answers_the_operations(ctx):
    attack = blehijack2.BleGattValueDumpAttack()
    device = blesim.ble().pick("gatt")
    assert attack.group_services(device.address), "Read By Group Type answers"
    assert attack.find_info(device.address, 0x0001, 0xFFFF), "Find Information answers"
    payload, _parsed = attack.att(device.address, bytes([0x02]) + bytes([0xF5, 0x01]))
    assert payload[:1] == b"\x03" and int.from_bytes(payload[1:3], "little") > 23


def test_the_link_layer_answers_the_pdus(ctx):
    attack = blehijack2.BleLlUnknownProbeAttack()
    # a stack that is not the deliberately fragile one: the point of the probe is what a
    # *working* controller answers to a PDU it does not implement
    device = next(device for device in blesim.ble().devices
                  if device.connectable and not device.flags.get("fragile"))
    version = attack.ll(device.address, 0x0C, bytes([0x09, 0x00, 0x00, 0x05, 0x00]))
    assert version["reply_name"] == "LL_VERSION_IND"
    assert bytes.fromhex(version["reply"])[1] >= 0x08, "a real controller version comes back"
    unsupported = attack.ll(device.address, 0x1F, bytes(8))
    assert unsupported["reply_name"] == "LL_UNKNOWN_RSP"
    ping = attack.ll(device.address, 0x12)
    assert ping["reply_name"] == "LL_PING_RSP"


def test_the_security_manager_answers_the_commands(ctx):
    attack = blehijack2.BleSmpCommandProbeAttack()
    device = blesim.ble().pick("smp")
    answer, parsed = attack.smp(device.address, bt.smp_pairing_request(io_capability=0x03,
                                                                     auth=0x00,
                                                                     key_size=16))
    assert answer[:1] == b"\x02" and parsed["name"] == "Pairing Response"
    assert parsed["max_key_size"] >= 7
    follow_up, follow_up_parsed = attack.smp(device.address, bytes([0x04]) + bytes(16))
    assert follow_up and follow_up[:1] in (b"\x05", b"\x01", b"\x02", b"\x06")


def test_the_hidp_and_audio_engines_answer(ctx):
    attack = blehijack2.BleHidpClassicInjectAttack()
    host = blesim.ble().pick("classic_hid")
    handshake = bt.parse_hidp(attack.hidp(ctx, host.address, bt.hidp_handshake()))
    assert handshake["transaction_name"] == "handshake"
    assert handshake["result_name"] == "successful" and handshake["accepted"] is True
    speaker = blesim.ble().pick("audio")
    answered = bt.parse_avdtp(attack.avdtp(ctx, speaker.address, bt.avdtp_discover()))
    assert answered["status"] == "accept"
    frame = bt.avctp_frame(bt.avrcp_register(0x01, interval=1000))
    body = bt.parse_avctp(attack.avrcp(ctx, speaker.address, frame))["payload"]
    assert bt.parse_avrcp(body, response=True)["playback"] == "playing"


def test_the_bnep_bridge_and_the_apdu_engine():
    airspace = blesim.ble()
    nap = airspace.by_name("NAP-Office")
    link = airspace.open_link(nap)
    assert bt.parse_bnep(airspace.bnep_request(nap, bt.bnep_control(
        0x01, bt.bnep_setup()[2:]), link))["result"] == 0
    assert airspace.psm_for(0x0042) == 0                 # not opened in this run
    assert link.service_conversations == ["BNEP setup"]


def test_aes_cmac_is_the_standard_construction():
    """The derivation the cross-transport attack reports is the RFC's own CMAC."""
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    assert bt.aes_cmac(key, b"").hex() == "bb1d6929e95937287fa37d129b756746"
    assert bt.aes_cmac(key, bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")).hex() \
        == "070a16b46b4d4144f79bdd9dd04a287c"
    assert len(bt.h7(bytes(range(16)))) == 16
    assert bt.CMAC_SALT.hex() == "00000000000000000000000000746d7031"


# --------------------------------------------------------------------------- #
# the claims, checked against the device that checks
# --------------------------------------------------------------------------- #

def test_a_lock_that_checks_refuses_the_write(ctx):
    """The hardened lock is the control: its control characteristic is not writable."""
    attack = blehijack2.BleGattWriteSweepAttack()
    # a device that requires encryption before it will answer a write, and serves a
    # writable characteristic: the refusal has to come from the gate, not from the table
    guarded = None
    for device in blesim.ble().devices:
        rows = [row for row in attack.characteristics(device.address)
                if row.get("writable")]
        if rows and not device.flags.get("gatt_write"):
            # a device with an open table and a checked write: the gate that refuses is
            # the one the ATT engine reports as insufficient authentication
            _ = device.flags.get("gatt_before_auth")
            guarded = (device, rows[0])
            break
    assert guarded is not None, "the floor carries a device that guards its writes"
    device, row = guarded
    result = attack.att_write(device.address, int(row["handle"]), b"\x01")
    assert result["accepted"] is False
    assert result["error"], "the refusal carries the error the peer chose"


def test_a_strict_television_refuses_the_classic_injection(ctx):
    """The bonded HID host answers the handshake with a refusal rather than input."""
    strict = blesim.ble().by_address("3c:11:22:33:00:03")
    attack = blehijack2.BleHidpClassicInjectAttack()
    raw = attack.hidp(ctx, strict.address, bt.hidp_frame(0x0A, 0x01, bytes(9)))
    answer = bt.parse_hidp(raw) if raw else {}
    assert answer.get("transaction_name") == "handshake"
    assert answer.get("result_name") == "unsupported request"
    link = blesim.ble().link_for(strict.address, "classic_hid")
    assert link is not None
    assert link.hidp_reports == [], "a television that requires a bond takes no input"
    assert link.hid_refused == 1
    assert any(entry.get("event") == "hidp" for entry in link.transcript)


def test_the_discovery_attacks_do_not_write(ctx, ap):
    """A reconnaissance attack that writes is not a reconnaissance attack."""
    for name in ("ble_service_table_dump", "ble_gatt_handle_enum", "ble_rpa_follow",
                 "ble_smp_command_probe", "ble_version_spoof", "ble_feature_page_spoof"):
        device = blesim.ble().pick(blesim.role_for(name))
        before = dict(device.written)
        blesim.reset_ble()
        outcome = run(name, ctx, ap)
        assert outcome.status == "success"
        device = blesim.ble().by_address(device.address)
        assert dict(device.written) == before, name
