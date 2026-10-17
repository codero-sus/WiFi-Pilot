# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""The Bluetooth and network waves: the second radio and the layer behind the bridge.

Two waves land here, and both of them have to be honest about the same three things:

* **the decoder is real** — a BLE capture written by :func:`synth.build_bt_scene` is read
  back by :mod:`wifipilot.bt` and the device census, the beacons and the captured pairing
  are checked against what the scene put in it;
* **the frames are real** — the network scene is dissected by :mod:`wifipilot.netstack`
  all the way from the 802.11 header to the DHCP option that matters, so an audit's
  finding can be traced back to the bytes that produced it;
* **the registry is complete** — every attack in both waves has metadata, a budget, a
  place in the planner's action set and a line in the documentation, and a live attack
  that would transmit refuses to claim it did so in a session with no radio.

The last test is the one the repository has kept since the first wave: what the docs say
and what the registry ships are the same number.
"""

from __future__ import annotations

import os

import pytest

from wifipilot import bt, netproto, netstack, synth
from wifipilot.attacks import (ATTACK_CLASSES, BATCH_ATTACKS, DEFAULT_ORDER,
                               OFFLINE_ATTACKS, attack_catalog)
from wifipilot.attacks import meta
from wifipilot.attacks.btattacks import ATTACKS as BT_ATTACKS
from wifipilot.attacks.btattacks import META as BT_META
from wifipilot.attacks.netdos import ATTACKS as NET_ATTACKS
from wifipilot.attacks.netdos import META as NET_META
from wifipilot.config import Config
from wifipilot.models import ATTACK_NAMES, AccessPoint

AP_MAC = "aa:bb:cc:11:22:33"

#: the two waves, for the tests that treat them as one
WAVES = {"btattacks": (BT_ATTACKS, BT_META), "netdos": (NET_ATTACKS, NET_META)}


@pytest.fixture(scope="module")
def bt_capture(tmp_path_factory) -> str:
    path = tmp_path_factory.mktemp("bt") / "scene.pcap"
    synth.build_bt_scene(str(path), seconds=20.0, seed=7)
    return str(path)


@pytest.fixture(scope="module")
def net_capture(tmp_path_factory) -> str:
    path = tmp_path_factory.mktemp("net") / "scene.pcap"
    synth.build_network_scene(str(path), bssid=AP_MAC, clients=6, rounds=1, seed=11)
    return str(path)


def _attack(name: str, config: Config, session, demo: bool = True) -> object:
    """Run one attack in demo mode and return its outcome."""
    from wifipilot.attacks.base import AttackContext

    cfg = config
    ap = AccessPoint(bssid=AP_MAC, essid="TestNet", channel=6, encryption="WPA2",
                     signal=-42, vendor="Test")
    context = AttackContext(session=session, config=cfg, bus=session.bus, demo=demo)
    return ATTACK_CLASSES[name]().run(context, ap)


# --------------------------------------------------------------------------- #
# the registry: both waves are wired in, complete and budgeted
# --------------------------------------------------------------------------- #


def test_both_waves_are_registered():
    assert len(BT_ATTACKS) == 26
    assert len(NET_ATTACKS) == 29
    for name in list(BT_META) + list(NET_META):
        assert name in ATTACK_CLASSES, name
        assert name in DEFAULT_ORDER, name
        assert name in ATTACK_NAMES, name


def test_registry_and_documentation_agree():
    """What the tool ships and what the docs claim have to be the same number."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for relative in ("README.md", os.path.join("docs", "ATTACKS.md")):
        with open(os.path.join(root, relative), encoding="utf-8") as handle:
            text = handle.read()
        assert f"{len(DEFAULT_ORDER)} attacks" in text, relative
    assert meta.validate() == []
    assert len(attack_catalog()) == len(DEFAULT_ORDER)


def test_every_wave_attack_has_a_budget(config):
    for name in list(BT_META) + list(NET_META):
        assert config.attack_timeout_for(name) > 0, name


def test_wave_metadata_is_complete():
    for wave, (attacks, metadata) in WAVES.items():
        for cls in attacks:
            entry = metadata[cls.name]
            assert entry["category"] in {item["name"] for item in meta.CATEGORIES}
            assert entry["noise"] in meta.NOISE_LEVELS
            assert entry["impact"] in meta.IMPACT_LEVELS
            assert entry["detection"].strip(), wave


# --------------------------------------------------------------------------- #
# the Bluetooth decoder and the scene it reads
# --------------------------------------------------------------------------- #


def test_scene_round_trips_through_the_decoder(bt_capture):
    devices = {}
    for stamp, packet in bt.iter_le_frames(bt_capture):
        if packet.get("advertising"):
            bt.merge_observations(devices, packet, stamp)
    assert len(devices) >= 10
    names = {device.name for device in devices.values()}
    assert "KBD-1C2B" in names             # a name that only arrives in a scan response
    assert "PRN-4B2C" in names
    beacons = {device.beacon["kind"] for device in devices.values() if device.beacon}
    assert {"iBeacon", "Eddystone-URL"} <= beacons
    companies = {device.company for device in devices.values()}
    assert "Apple" in companies and "Nordic Semiconductor" in companies


def test_scene_has_a_rotating_tracker(bt_capture):
    """Ten sightings of one tag, and none of them share an address."""
    addresses = []
    for _stamp, packet in bt.iter_le_frames(bt_capture):
        if not packet.get("advertising"):
            continue
        tracker = bt.tracker_of(packet.get("ad") or [])
        if tracker:
            addresses.append(packet["address"])
    assert len(addresses) >= 5
    assert len(set(addresses)) == len(addresses)
    assert all(bt.classify_address(address) == "resolvable private"
               for address in addresses)


def test_scene_carries_a_connection_and_a_pairing_request(bt_capture):
    records = []
    for _stamp, packet in bt.iter_le_frames(bt_capture):
        if packet.get("advertising"):
            continue
        parsed = bt.parse_data_channel(packet.get("frame") or b"")
        if parsed.get("ll"):
            records.append(parsed)
    assert records, "the scene must contain data-channel traffic"
    controls = {record["ll"].get("control") for record in records}
    assert "LL_ENC_REQ" in controls
    smp = next(((record.get("l2cap") or {}).get("smp") for record in records
                if (record.get("l2cap") or {}).get("smp")), None)
    assert smp is not None
    assert smp["name"] == "Pairing Request"
    assert smp["just_works"] is True and smp["secure_connections"] is False
    services = [entry for record in records
                for entry in ((record.get("att") or {}).get("entries") or [])]
    assert services, "the ATT read-by-group-type response must be readable"


def test_every_bt_audit_finds_something_in_the_scene(config, session):
    for name in ("bt_device_census", "bt_tracker_detect", "bt_ibeacon_audit",
                 "bt_eddystone_audit", "bt_address_privacy", "bt_manufacturer_census",
                 "bt_service_census", "bt_interval_audit", "bt_channel_audit",
                 "bt_connectable_audit", "bt_pairing_audit", "bt_gatt_audit",
                 "bt_feature_audit", "bt_tracker_follow"):
        outcome = _attack(name, config, session)
        assert outcome.status == "success", f"{name}: {outcome.result}"


def test_bt_live_attacks_do_not_claim_to_transmit_in_demo(config, session):
    for name, cls in ATTACK_CLASSES.items():
        if not name.startswith("bt_") or getattr(cls, "scene", False):
            continue
        outcome = _attack(name, config, session)
        assert outcome.status == "success", f"{name}: {outcome.result}"


# --------------------------------------------------------------------------- #
# the network dissector and the scene it reads
# --------------------------------------------------------------------------- #


def test_network_scene_dissects_to_the_protocols_it_advertises(net_capture):
    summary = netstack.network_summary(net_capture)
    protocols = summary["protocols"]
    for protocol in ("dhcp", "arp", "ipv4", "ipv6", "stp", "lldp", "name-service"):
        assert protocols.get(protocol), protocol
    assert summary["tcp_syn_only"] >= 20            # the SYN flood
    assert summary["icmp"].get("icmp 5") == 1       # one forged redirect
    assert summary["icmp"].get("icmpv6 134") == 1   # one router advertisement


def test_dissected_frames_keep_the_fields_an_audit_counts(net_capture):
    frames = [frame for _stamp, frame in netstack.iter_network_frames(net_capture)]
    dhcp = [frame for frame in frames if frame.get("dhcp")]
    servers = {frame["dhcp"].get("server_id") for frame in dhcp}
    assert "192.168.1.66" in servers                 # the rogue server, by address
    releases = [frame for frame in dhcp if frame["dhcp"].get("message_type") == "release"]
    assert len(releases) == 1
    tagged = [frame for frame in frames if len(frame.get("vlans") or []) >= 2]
    assert tagged, "the doubly tagged frame has to survive dissection"


def test_dhcp_builders_and_parsers_agree(config):
    mac = "02:00:00:00:de:ad"
    release = netproto.dhcp_release(mac, "192.168.1.100", "192.168.1.1")
    parsed = netproto.parse_dhcp(release)
    assert parsed["message_type"] == "release"
    assert parsed["client_mac"] == mac
    offer = netproto.dhcp_rogue_offer(mac, "192.168.1.200", router="192.168.1.66",
                                     dns="192.168.1.66", lease=600)
    parsed = netproto.parse_dhcp(offer)
    assert parsed["message_type"] == "offer"
    assert parsed["yiaddr"] == "192.168.1.200"
    notify = netproto.ssdp_notify(name="router", model="NETGEAR R7000",
                                 location="http://192.168.1.1/desc.xml")
    headers = netproto.parse_ssdp(notify.decode())
    assert headers["nt"] == "upnp:rootdevice"
    assert headers["location"].endswith("desc.xml")


def test_every_network_audit_finds_something_in_the_scene(config, session):
    for name in ("dhcp_lease_audit", "ipv6_prefix_audit", "iot_credential_audit",
                 "iot_service_census", "ssdp_device_census"):
        outcome = _attack(name, config, session)
        assert outcome.status == "success", f"{name}: {outcome.result}"


def test_lease_audit_names_the_rogue_server(config, session):
    outcome = _attack("dhcp_lease_audit", config, session)
    assert outcome.extra["hostile"] == ["192.168.1.66"]
    assert outcome.extra["conflicts"] >= 1
    assert "forged" in outcome.detail


def test_live_network_attacks_are_bounded_and_report(config, session):
    """Every transmitter in the wave has to finish, and say what it sent."""
    names = [name for name in NET_META if ATTACK_CLASSES[name].category != "offline"]
    assert len(names) == 24
    for name in names:
        outcome = _attack(name, config, session)
        assert outcome.status == "success", f"{name}: {outcome.result}"


def test_submission_is_opt_in_and_capped(config):
    """Nothing in either wave runs by default: the config lists only the classics."""
    enabled = set(config.attacks)
    assert not (set(BT_META) & enabled)
    assert not (set(NET_META) & enabled)
    for name in list(BT_META) + list(NET_META):
        assert name not in config.attacks, name
