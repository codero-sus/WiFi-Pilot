"""The IT hijacker wave: seventy attacks that answer as something else.

The IT editions of the impersonation waves.  Every attack talks to a real service — in
demo mode the simulated network, live the segment under test — and every claim it makes is
read back out of a capture: the frames it wrote, decoded again by the protocol's own codec.

The tests come in four parts, the same shape as the Wi-Fi wave's: the whole wave runs and
ends ``success``; the registry and the metadata agree with the classes; the readers decode
what the builders wrote; and the claims are tested in both directions — a relay that
carried the device's own bytes reports that it carried them, and the attack that wears a
camera's identity reports the model it wore.
"""

from __future__ import annotations

import pytest

from wifipilot import itproto as proto
from wifipilot import netproto as np
from wifipilot.attacks import ATTACK_CLASSES, ithijack, meta
from wifipilot.attacks.base import AttackContext
from wifipilot.models import AccessPoint

#: the wave, in the order the registry carries it
WAVE = tuple(ithijack.NAMES)

#: the families and how many attacks each contributes
FAMILIES = {"mimic": 14, "impersonate": 12, "hijack": 12, "poison": 12, "relay": 10,
            "steal": 10}


@pytest.fixture()
def ctx(config, bus, session) -> AttackContext:
    config.demo = True
    return AttackContext(session=session, config=config, bus=bus, demo=True)


def run(name: str, ctx: AttackContext):
    """One attack's run: the wave is LAN-side, so any access point will do as the anchor."""
    return ATTACK_CLASSES[name]().run(ctx, _ap())


def _ap() -> AccessPoint:
    return AccessPoint("d0:9e:12:9d:36:cc", "HOME-2F4A", channel=6, encryption="WPA2",
                       auth="PSK", privacy="WPA2")


# --------------------------------------------------------------------------- #
# the wave
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name", WAVE)
def test_wave_runs(name, ctx):
    """Every attack finishes, talks to a host and states what it read."""
    outcome = run(name, ctx)
    assert outcome.status == "success", (name, outcome.result, outcome.detail)
    assert outcome.detail
    assert outcome.extra["family"] in FAMILIES
    assert outcome.extra["frames"] >= 1, "every attack writes at least one frame"
    assert outcome.extra["confirmed"] is True or outcome.extra["answers"] >= 1


def test_wave_is_registered():
    assert len(WAVE) == 70
    assert len(set(WAVE)) == 70
    assert set(WAVE) == set(ithijack.META)
    for name in WAVE:
        assert name in ATTACK_CLASSES, name
        assert meta.ATTACK_META[name]["domain"] == "it", name
        assert meta.ATTACK_META[name]["detection"], f"{name} has no detection note"
        assert meta.ATTACK_META[name]["devices"], f"{name} names no device type"


def test_metadata_valid():
    assert meta.validate() == []


def test_the_families_are_evenly_spread():
    families: dict = {}
    for row in ithijack.META.values():
        families[row["family"]] = families.get(row["family"], 0) + 1
    assert families == FAMILIES


def test_the_wave_costs_something():
    """No attack in the wave is silent *and* harmless: the metadata has to say so."""
    for name, row in ithijack.META.items():
        assert row["category"] in ("rogue", "capture", "exploit"), name
        assert row["noise"] in ("silent", "quiet", "moderate", "loud"), name
        assert row["impact"] in ("info", "degraded", "outage", "loot"), name


# --------------------------------------------------------------------------- #
# the readers the wave grades itself with
# --------------------------------------------------------------------------- #

def test_the_readers_decode_an_arp_reply(tmp_path):
    frame = ithijack.ether("b8:27:eb:40:a5:4d", ithijack.OUR_MAC,
                           ithijack.hijack75._arp_bytes(
                               ithijack.OUR_MAC, ithijack.GATEWAY,
                               "b8:27:eb:40:a5:4d", "192.168.1.20"),
                           ithijack.ETHERTYPE_ARP)
    path = str(tmp_path / "arp.pcap")
    ithijack.hijack75.write_capture(path, [frame])

    rows = ithijack.ether_rows(path)
    assert len(rows) == 1 and rows[0]["ethertype"] == ithijack.ETHERTYPE_ARP
    parsed = np.parse_arp(rows[0]["body"])
    assert parsed["op"] == "reply"
    assert parsed["sender_mac"] == ithijack.OUR_MAC
    assert parsed["sender_ip"] == ithijack.GATEWAY


def test_the_readers_decode_a_udp_payload(tmp_path):
    payload = np.dhcp_offer(ithijack.OUR_MAC, "192.168.1.99", ithijack.OUR_IP,
                            ithijack.OUR_IP, dns=[ithijack.OUR_IP])
    packet = np.ipv4_udp_packet(ithijack.OUR_IP, ithijack.BROADCAST_IP, 67, 68, payload)
    path = str(tmp_path / "dhcp.pcap")
    ithijack.hijack75.write_capture(
        path, [ithijack.ether(ithijack.BROADCAST_MAC, ithijack.OUR_MAC, packet)])

    rows = ithijack.payloads(path)
    assert len(rows) == 1
    assert (rows[0]["src_port"], rows[0]["dst_port"]) == (67, 68)
    offer = np.parse_dhcp(rows[0]["payload"])
    assert offer["yiaddr"] == "192.168.1.99"
    assert ithijack.OUR_IP in (offer["options"]["dns"] if isinstance(
        offer["options"]["dns"], list) else [offer["options"]["dns"]])


def test_the_readers_decode_a_tcp_segment(tmp_path):
    segment = ithijack.hijack75._tcp_segment(ithijack.OUR_IP, "192.168.1.60", 1883, 1883,
                                             flags=0x18, sequence=0x2000,
                                             payload=b"\x20\x02\x00\x00")
    packet = ithijack.hijack75._ipv4_packet(ithijack.OUR_IP, "192.168.1.60", segment, 6)
    path = str(tmp_path / "tcp.pcap")
    ithijack.hijack75.write_capture(
        path, [ithijack.ether("b8:27:eb:bb:04:0e", ithijack.OUR_MAC, packet)])

    rows = ithijack.payloads(path, ithijack.IPPROTO_TCP)
    assert len(rows) == 1 and rows[0]["dst_port"] == 1883
    assert rows[0]["payload"] == b"\x20\x02\x00\x00"
    assert proto.parse_mqtt(rows[0]["payload"])["type"] == 2      # CONNACK


def test_the_ntp_reply_is_forty_eight_bytes_with_the_time_being_served():
    reply = ithijack.ntp_reply(1_767_225_600, stratum=1)
    assert len(reply) == 48
    assert reply[1] == 1                                          # the stratum we claim
    assert int.from_bytes(reply[40:44], "big") == 1_767_225_600


# --------------------------------------------------------------------------- #
# the claims, in both directions
# --------------------------------------------------------------------------- #

def test_the_relay_carries_the_devices_own_bytes(ctx):
    """The relay's whole claim: what the client got was the device's answer."""
    outcome = run("it_relay_redis", ctx)
    assert outcome.extra["relayed_byte_for_byte"] is True
    assert outcome.extra["bytes_carried"] == outcome.extra["the_device_answered_us"]
    fields = outcome.extra["device_answers"][0]["fields"]
    assert fields["version"], "the device's own INFO carried its version"
    assert fields["auth_required"] is False, "and it answered before any AUTH"


def test_the_arp_attack_claims_the_gateway_on_our_mac(ctx):
    outcome = run("it_poison_arp_gateway", ctx)
    assert outcome.extra["claimed_address"] == ithijack.GATEWAY
    assert outcome.extra["our_mac"] == ithijack.OUR_MAC
    assert outcome.extra["poisoned_caches"] >= 1


def test_wearing_a_printers_identity_reports_the_printers_own_name(ctx):
    outcome = run("it_impersonate_ipp", ctx)
    device = outcome.extra["device_answers"][0]["fields"]
    assert device["name"], "the printer answered with its own name"
    assert outcome.extra["our_name"] == device["name"], "and that is the name we wear"
    assert outcome.extra["our_status"] == "successful-ok"


def test_the_dhcp_attack_leaves_the_lease_alone_and_takes_the_resolver(ctx):
    outcome = run("it_poison_dhcp_option", ctx)
    assert outcome.extra["our_dns_option"] == [ithijack.OUR_IP]
    assert outcome.extra["lease_we_leave_alone"] == ithijack.ROGUE_LEASE
    assert outcome.extra["destination_mac"] == ithijack.BROADCAST_MAC


def test_the_takeover_attack_hands_over_what_it_took(ctx):
    outcome = run("it_steal_iot_token", ctx)
    assert outcome.extra["confirmed"] is True
    assert outcome.extra["handed_over"] > 0
    device = outcome.extra["device_answers"][0]["fields"]
    assert device["model"] and device["alias"]


def test_a_service_with_nothing_to_answer_is_graded_on_the_wire(ctx):
    """The DNS attack owes its proof to the capture: no device answers a rogue resolver."""
    outcome = run("it_mimic_dns", ctx)
    assert outcome.extra["answers"] == 0
    assert outcome.extra["rogue_records"][0]["value"] == ithijack.OUR_IP
    assert "we answered as the service ourselves" in outcome.result
