"""The peripheral wave: be the device the floor already trusts.

Twenty-five attacks that all make the same argument as the imitation wave, from the other
end of the link.  A host does not have to be fooled into typing: the devices around it —
locks, bulbs, plugs, sensors, doorbells, a soundbar — take commands from whoever the link
says they are.  Each attack here copies one device that exists on the simulated floor, puts
that identity back on the air, and then *does the thing the device does*: it writes the
characteristic that trips a relay, sends the notification that reports a healthy patient,
rings the doorbell, opens the audio profile, or clones the advertisement a positioning
system keys on.

The wave is also a test of the simulator's honesty.  ``blesim`` answers an ATT write with
the value it stored — so ``read_back`` proves the device took the command, not that the
attack sent it — and it records what a *host* received, so a notification attack reports
what arrived rather than what it hoped to send.  The assertions below read those records
with the same decoders an analysis of a capture would use (:mod:`wifipilot.bt`), which is
why the numbers are pinned: a change in the simulator that quietly stops delivering
notifications fails here instead of printing "accepted".
"""

from __future__ import annotations

import pytest

from wifipilot import blesim, bt
from wifipilot.attacks import ATTACK_CLASSES, DEFAULT_ORDER, blewave, blemimic, meta
from wifipilot.attacks.base import AttackContext
from wifipilot.models import AccessPoint

#: the wave, in the order the registry carries it
WAVE = ("ble_mouse_mimic", "ble_combo_dongle_mimic", "ble_lock_mimic", "ble_lock_mesh_mimic",
        "ble_bulb_mimic", "ble_mesh_lamp_mimic", "ble_plug_mimic", "ble_band_mimic",
        "ble_thermostat_mimic", "ble_scale_mimic", "ble_glucose_mimic", "ble_pressure_mimic",
        "ble_ecg_mimic", "ble_hr_mimic", "ble_air_quality_mimic", "ble_charger_mimic",
        "ble_label_printer_mimic", "ble_ir_hub_mimic", "ble_uwb_anchor_mimic",
        "ble_patient_monitor_mimic", "ble_vehicle_tracker_mimic", "ble_vending_mimic",
        "ble_doorbell_mimic", "ble_ibeacon_mimic", "ble_soundbar_mimic")

#: the registry the wave landed in
REGISTRY_TOTAL = 848
BLUETOOTH_TOTAL = 143

#: the keyboard five hosts are bonded to: the identity the two HID peripherals adopt
PEER = "WF-KEYBOARD"
PEER_ADDRESS = "5c:11:22:33:44:aa"

#: the soundbar three rooms are bonded to
AUDIO_PEER = "WF-SPEAKER"


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
def test_every_attack_runs_and_reports(name, ctx, ap):
    """Every attack in the wave completes and says what it did."""
    outcome = run(name, ctx, ap)
    assert outcome.status in ("success", "partial", "failed")
    assert outcome.detail
    assert outcome.extra["capability"]
    identity = outcome.extra["identity"]
    assert identity["name"] or identity["address"]          # a beacon has no name


@pytest.mark.parametrize("name", WAVE)
def test_every_capability_landed(name, ctx, ap):
    """The simulator accepted every capability: nothing in the wave is a stub.

    This is the assertion the wave exists for.  ``accepted`` is not "we transmitted": it
    is the device's own record — a write that was read back, a notification a host
    received, a read that came back with the value the device holds.
    """
    capability = run(name, ctx, ap).extra["capability"]
    assert capability["accepted"] is True, capability
    assert capability.get("action")


def test_wave_is_registered():
    """Every attack in the wave is in the registry, in the Bluetooth edition, with a role."""
    assert len(blewave.NAMES) == len(set(blewave.NAMES)) == len(WAVE) == 25
    for name in WAVE:
        assert name in ATTACK_CLASSES
        assert meta.ATTACK_META[name]["domain"] == "bluetooth"
        assert meta.ATTACK_META[name]["technique"] == "impersonation"
        assert blesim.role_for(name) != "any", name


def test_the_wave_did_not_collide_with_the_earlier_ones():
    """The two names the committed wave already owned were renamed, not overwritten.

    ``ble_printer_mimic`` and ``ble_beacon_mimic`` belong to the first imitation wave and
    still point at those classes: reusing the strings here would have made the registry
    lose two attacks while every test kept passing.
    """
    assert ATTACK_CLASSES["ble_printer_mimic"] is blemimic.BlePrinterMimicAttack
    assert ATTACK_CLASSES["ble_beacon_mimic"] is blemimic.BleBeaconMimicAttack
    assert ATTACK_CLASSES["ble_label_printer_mimic"] is not ATTACK_CLASSES["ble_printer_mimic"]
    assert ATTACK_CLASSES["ble_ibeacon_mimic"] is not ATTACK_CLASSES["ble_beacon_mimic"]
    assert len(DEFAULT_ORDER) == len(set(DEFAULT_ORDER)) == REGISTRY_TOTAL


def test_metadata_valid():
    assert meta.validate() == []


def test_edition_counts():
    """The wave is 25 Bluetooth attacks on top of the 118 the edition already had."""
    from wifipilot.api import editions

    counts = {row["id"]: row["attacks"] for row in editions()}
    assert counts["bluetooth"] == BLUETOOTH_TOTAL
    assert counts["all"] == REGISTRY_TOTAL


def test_every_attack_aims_at_a_real_device(ctx, ap):
    """Each one picks a device the floor actually has, by role."""
    airspace = blesim.ble()
    for name in WAVE:
        role = blesim.role_for(name)
        assert airspace.candidates(role), f"{name} aims at '{role}', which is empty"


def test_every_attack_advertises_the_identity_it_copied(ctx, ap):
    """The clone is on the air under the copied name, address and services."""
    for name in WAVE:
        extra = run(name, ctx, ap).extra
        advertised = extra["advertised"]
        assert advertised.get("name") == extra["identity"]["name"] or not extra["identity"]["name"]
        assert advertised.get("address") == extra["identity"]["address"]


# --------------------------------------------------------------------------- #
# HID peripherals: the keyboard's bond, from the peripheral side
# --------------------------------------------------------------------------- #

def _deliveries(outcome):
    return {row["host"]: row for row in outcome.extra["capability"]["deliveries"]}


def test_mouse_clicks_on_every_host_that_reconnects(ctx, ap):
    """``ble_mouse_mimic`` clones the keyboard and clicks on the desks that trust it."""
    outcome = run("ble_mouse_mimic", ctx, ap)
    assert outcome.extra["identity"]["name"] == PEER
    assert outcome.extra["identity"]["address"] == PEER_ADDRESS
    deliveries = _deliveries(outcome)
    accepting = {host: row for host, row in deliveries.items() if row["accepted"]}
    assert len(accepting) >= 3, "the clone should click on at least three hosts"
    for row in accepting.values():
        assert row["reports"] == outcome.extra["capability"]["reports_sent"]
        assert row["payload"] == "click"
    assert outcome.extra["capability"]["hosts_reached"] == len(accepting)


def test_the_hosts_that_verified_the_link_key_refuse_the_mouse(ctx, ap):
    """The two bonded hosts ask for the link key: a clone without it is turned away."""
    outcome = run("ble_mouse_mimic", ctx, ap)
    refused = {row["host_name"] for row in outcome.extra["refused"]}
    assert refused == {"TV-MeetingRoom", "Phone-Desk-04"}
    assert all(row["why"] == "the host verified the link key" for row in outcome.extra["refused"])
    deliveries = _deliveries(outcome)
    assert deliveries["TV-MeetingRoom"]["refused"] == deliveries["TV-MeetingRoom"]["sent"]


def test_combo_dongle_presses_the_consumer_keys(ctx, ap):
    """``ble_combo_dongle_mimic`` sends media keys, not letters: volume, mute, next track."""
    outcome = run("ble_combo_dongle_mimic", ctx, ap)
    capability = outcome.extra["capability"]
    assert capability["keys"] == [0xE9, 0xEA, 0xE2, 0xB5]
    assert capability["hosts_reached"] >= 3
    deliveries = _deliveries(outcome)
    accepted = sum(row["accepted"] for row in deliveries.values())
    assert accepted == capability["keys"].__len__() * capability["hosts_reached"]


def test_hid_reports_are_read_back_by_the_simulator(ctx, ap):
    """The keystrokes are decoded off the host's own link, not assumed from the send."""
    outcome = run("ble_combo_dongle_mimic", ctx, ap)
    deliveries = _deliveries(outcome)
    typed = {row["typed"] for row in deliveries.values() if row["accepted"]}
    assert typed, "the host decoded nothing at all"
    assert any(text for text in typed), "the reports arrived but carried no key codes"


# --------------------------------------------------------------------------- #
# access control
# --------------------------------------------------------------------------- #

def test_lock_mimic_writes_the_unlock_command(ctx, ap):
    """The lock takes the control-point write and reports the state that follows it."""
    capability = run("ble_lock_mimic", ctx, ap).extra["capability"]
    assert capability["uuid"] == "0xfee9"
    assert capability["sent"] == "02000000"
    assert capability["read_back"] == capability["sent"]
    assert capability["confirmed"] is True
    assert capability["refusals_on_the_link"] == 0
    assert "state_before" in capability and "state_after" in capability


def test_lock_mesh_mimic_installs_an_admin_key(ctx, ap):
    """The mesh lock accepts a new admin key from the clone — the door is now the clone's."""
    capability = run("ble_lock_mesh_mimic", ctx, ap).extra["capability"]
    assert capability["uuid"] == "0xfeea"
    assert capability["text"] == "WP-ADMIN-0001"
    assert capability["accepted"] is True
    assert capability["confirmed"] is True


# --------------------------------------------------------------------------- #
# building automation: the actuators
# --------------------------------------------------------------------------- #

def test_bulb_mimic_sets_the_colour(ctx, ap):
    """Colour and brightness travel as one write on the light's control characteristic."""
    capability = run("ble_bulb_mimic", ctx, ap).extra["capability"]
    assert capability["uuid"] == "0x2a56"
    assert capability["sent"] == "ff004010"
    assert capability["read_back"] == capability["sent"]


def test_mesh_lamp_mimic_invites_itself_into_the_mesh(ctx, ap):
    """Provisioning is the interesting write: it is how a lamp joins a network."""
    capability = run("ble_mesh_lamp_mimic", ctx, ap).extra["capability"]
    assert capability["uuid"] == "0x2adb"
    assert bytes.fromhex(capability["sent"])[0] == 0x03
    assert capability["accepted"] is True


def test_plug_mimic_switches_the_washer_on(ctx, ap):
    capability = run("ble_plug_mimic", ctx, ap).extra["capability"]
    assert capability["uuid"] == "0xfeef"
    assert capability["sent"] == "01"


def test_charger_mimic_starts_a_session(ctx, ap):
    """An EV charger that starts a session for a clone is a charger that gives away power."""
    capability = run("ble_charger_mimic", ctx, ap).extra["capability"]
    assert capability["uuid"] == "0xfff2"
    assert capability["sent"] == "11010005"
    assert capability["confirmed"] is True


def test_label_printer_mimic_prints_a_label(ctx, ap):
    """The print job is ESC/P: the clone's text is what the printer would put on the roll."""
    capability = run("ble_label_printer_mimic", ctx, ap).extra["capability"]
    assert capability["uuid"] == "0xffb1"
    assert capability["read_back"].startswith("1b401b69")     # ESC @ then ESC i a
    assert "WP-LABEL" in bytes.fromhex(capability["read_back"]).decode("latin-1")


def test_ir_hub_mimic_sends_an_nec_frame(ctx, ap):
    capability = run("ble_ir_hub_mimic", ctx, ap).extra["capability"]
    assert capability["uuid"] == "0xfe41"
    sent = bytes.fromhex(capability["sent"])
    assert sent[4] == 0x26                                       # the NEC command byte


def test_uwb_anchor_mimic_rewrites_the_range(ctx, ap):
    capability = run("ble_uwb_anchor_mimic", ctx, ap).extra["capability"]
    assert capability["uuid"] == "0xffe2"
    assert bytes.fromhex(capability["sent"])[-1] == 100          # centimetres


def test_doorbell_mimic_rings_the_bell(ctx, ap):
    capability = run("ble_doorbell_mimic", ctx, ap).extra["capability"]
    assert capability["uuid"] == "0xfe32"
    assert capability["sent"] == "0101"


# --------------------------------------------------------------------------- #
# medical, wearable and telemetry: the notifications
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name, uuid, indication", [
    ("ble_band_mimic", "0x2a53", False),
    ("ble_ecg_mimic", "0x2a37", False),
    ("ble_hr_mimic", "0x2a37", False),
    ("ble_thermostat_mimic", "0x2a1c", True),
    ("ble_pressure_mimic", "0x2a35", True),
    ("ble_patient_monitor_mimic", "0xffa1", False),
])
def test_notifications_arrive_at_the_host(name, uuid, indication, ctx, ap):
    """Every push-style attack is answered by the host's own record of what it received.

    A notification is not a request, so nothing can "succeed" on the wire: the only
    evidence is the host's record, which :mod:`wifipilot.blesim` keeps on the link.
    """
    capability = run(name, ctx, ap).extra["capability"]
    assert capability["uuid"] == uuid
    received = capability["received_by_the_host"]
    assert received, "the host recorded nothing"
    assert received["value"] == capability["sent"]
    assert received["handle"] == int(capability["handle"], 16)
    assert received["indication"] is indication
    assert capability["host_received"] >= 1
    assert capability["accepted"] is True


def test_band_notification_carries_a_real_measurement(ctx, ap):
    """The band's own record and the clone's notification are two different things."""
    capability = run("ble_band_mimic", ctx, ap).extra["capability"]
    assert capability["device_own_text"] == "FB-3 1.0.0"          # what the device holds
    assert capability["sent"] != capability["device_own_value"]  # what the clone sent


def test_ecg_notification_encodes_the_heart_rate(ctx, ap):
    """16-bit heart rate in the flagged layout: the rate is 200 bpm, not a random byte."""
    capability = run("ble_ecg_mimic", ctx, ap).extra["capability"]
    raw = bytes.fromhex(capability["sent"])
    assert raw[0] & 0x01, "the flags byte does not announce a 16-bit measurement"
    assert int.from_bytes(raw[1:3], "little") == 200


def test_glucose_mimic_calibrates_the_meter(ctx, ap):
    """A calibration write is the meter's trust: it changes what every later reading means."""
    capability = run("ble_glucose_mimic", ctx, ap).extra["capability"]
    assert capability["uuid"] == "0xfef1"
    assert capability["sent"] == "02006400c8"
    assert capability["read_back"] == capability["sent"]


def test_vehicle_tracker_mimic_repositions_the_van(ctx, ap):
    capability = run("ble_vehicle_tracker_mimic", ctx, ap).extra["capability"]
    assert capability["uuid"] == "0xffd3"
    assert len(bytes.fromhex(capability["sent"])) == 8            # lat, lon, packed


# --------------------------------------------------------------------------- #
# devices that only answer reads
# --------------------------------------------------------------------------- #

def test_scale_mimic_reports_what_it_read(ctx, ap):
    capability = run("ble_scale_mimic", ctx, ap).extra["capability"]
    assert capability["technique"] == "read"
    assert {row["text"] for row in capability["reads"]} == {"Scale-500"}


def test_vending_mimic_reads_a_telemetry_block(ctx, ap):
    capability = run("ble_vending_mimic", ctx, ap).extra["capability"]
    assert capability["technique"] == "read"
    assert set(capability["identity"].values()) == {"Vending-7"}


def test_air_quality_mimic_reads_a_gated_attribute(ctx, ap):
    """The monitor refuses a direct read; the wave enumerates the table instead.

    This is the difference between "the device turned me down" and "nothing came back".
    A Read Request for a gated attribute is answered with *Insufficient Authentication*,
    while a Read By Type for the same attribute still returns the value — and it is the
    value the report quotes.
    """
    device = blesim.ble().by_name("AirQ-2")
    row = next(entry for entry in device.gatt_rows() if entry["uuid"] == 0x2A29)
    sock = blesim.controller_socket(None, address=device.address, role="gatt")
    link = blesim.ble().link_for(device.address, "gatt")
    from wifipilot.attacks.blehid import _att_read

    raw, parsed = _att_read(sock, link, row["handle"])
    assert raw == b""
    assert parsed["error_text"] == "Insufficient Authentication"

    capability = run("ble_air_quality_mimic", ctx, ap).extra["capability"]
    assert capability["accepted"] is True
    assert capability["identity"]["manufacturer"] == "Qingping"
    assert capability["identity"]["model"] == "AQ-200"


# --------------------------------------------------------------------------- #
# audio
# --------------------------------------------------------------------------- #

def test_soundbar_mimic_takes_the_audio_link(ctx, ap):
    """AVDTP and AVRCP are L2CAP profiles: the clone configures a stream nobody started."""
    outcome = run("ble_soundbar_mimic", ctx, ap)
    capability = outcome.extra["capability"]
    assert outcome.extra["identity"]["name"] == AUDIO_PEER
    assert {row["host"] for row in capability["avdtp"]} == {"SoundBar Loft", "ConfUnit-2F",
                                                            "AVR-Elite"}
    assert all(row["sent"] for row in capability["avdtp"])
    signals = {row["signal"] for row in capability["avdtp"]}
    assert {"Discover", "GetCapabilities", "SetConfiguration"} <= signals
    assert len(capability["avrcp"]) == 3 * 3                      # three hosts, three commands
    assert capability["audio_refused"] > 0


def test_the_receiver_that_checks_the_link_key_still_says_so(ctx, ap):
    """The AVR verifies the bond: its refusal is reported, and the other two are not."""
    outcome = run("ble_soundbar_mimic", ctx, ap)
    refused = {row["host_name"] for row in outcome.extra["refused"]}
    assert refused == {"AVR-Elite"}
    reconnected = {row["host_name"] for row in outcome.extra["reconnected"]}
    assert reconnected == {"SoundBar Loft", "ConfUnit-2F"}


def test_avrcp_answers_carry_the_playback_state(ctx, ap):
    """The clone reads the track and the volume back out of the receiver's own replies."""
    capability = run("ble_soundbar_mimic", ctx, ap).extra["capability"]
    registered = [row for row in capability["avrcp"] if row["answer"].get("event_name")]
    assert registered, "no AVRCP notification was registered"
    answer = registered[0]["answer"]
    assert answer["name"] == "RegisterNotification"
    assert answer["playback"] == "playing"


def test_blesim_records_what_a_host_received(ctx, ap):
    """The simulator's notification record is what the whole wave reports against."""
    device = blesim.ble().by_name("BP-7000")
    link = blesim.ble().link_for(device.address, "gatt")
    sock = blesim.controller_socket(None, address=device.address, role="gatt")
    pdu = blewave.notification_pdu(2, bytes.fromhex("007800500050006e01"), indication=True)
    from wifipilot.attacks.blehid import _att_exchange

    _att_exchange(sock, link, pdu)
    assert link.notifications, "the link kept no record of the indication"
    record = link.notifications[-1]
    assert record["handle"] == 2
    assert record["indication"] is True
    assert bytes.fromhex(record["value"]) == bytes.fromhex("007800500050006e01")


# --------------------------------------------------------------------------- #
# the advertisement itself
# --------------------------------------------------------------------------- #

def test_ibeacon_mimic_clones_a_payload_a_scanner_believes(ctx, ap):
    """The clone's own PDU is read back with the decoder an indoor positioning system uses."""
    capability = run("ble_ibeacon_mimic", ctx, ap).extra["capability"]
    assert capability["uuid"] == "5a" * 16
    assert (capability["major"], capability["minor"]) == (1, 7)
    assert capability["company_id"] == 0x004C and capability["company"] == "Apple"
    read_back = capability["read_back"]
    assert read_back["kind"] == "iBeacon"
    assert read_back["uuid"].replace("-", "") == capability["uuid"]
    assert (read_back["major"], read_back["minor"]) == (1, 7)
    assert capability["structures"] == ["flags", "manufacturer data"]
    assert capability["advertised_bytes"] > capability["payload_bytes"]


def test_the_beacon_payload_is_a_real_advertisement(ctx, ap):
    """One more time, through the toolkit's own parser rather than the attack's summary."""
    capability = run("ble_ibeacon_mimic", ctx, ap).extra["capability"]
    ad_type, payload = bt.ibeacon(capability["uuid"], major=1, minor=7, tx_power=-59)
    pdu = bt.adv_pdu(0x00, "d0:00:00:00:00:01",
                     bt.adv_payload(bt.ad_flags(le_general=True), (ad_type, payload)))
    parsed = bt.parse_adv_pdu(pdu)
    assert parsed["pdu_type"] == 0x00 and parsed["address"] == "d0:00:00:00:00:01"
    beacon = next(entry for entry in parsed["ad"] if entry["type"] == 0xFF)
    assert beacon["company_name"] == "Apple"
    assert bt.parse_ibeacon(beacon)["major"] == 1
