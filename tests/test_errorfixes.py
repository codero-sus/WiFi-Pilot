# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Regression tests for the ruff F821/F841 error sweep.

Every test here pins a bug that was invisible to the demo-driven suite
because it lived on a live-only path (the same genus as the
``WirelessInterface`` WebSocket crash):

* ``parse_ipv4`` never surfaced UDP ports, so the rogue-DHCP attacks'
  live loops skipped every frame and ``parse_dhcp`` got a BOOTP body
  still wearing its 8-byte UDP header.
* ``survey3.rogue_dhcp_detect`` called ``parse_ipv4`` without importing
  it — a ``NameError`` on the first live frame.
* ``protocol2``'s PMF probe and BTM hijack returned a success outcome
  without closing their attempt, so the engine filed both under
  "skipped"; their computed ``severity`` was dropped on the floor
  (likewise ``capture3.mac_filter_probe``).
"""

from __future__ import annotations

import struct
import threading

import pytest

from wifipilot import netproto
from wifipilot.attacks import get_attack, survey3
from wifipilot.attacks.base import AttackContext
from wifipilot.models import STATUS_SUCCESS
from wifipilot.session import Session

AP = "aa:bb:cc:11:22:33"
STA = "02:00:00:00:00:09"


def _ctx(config, bus, demo: bool) -> AttackContext:
    session = Session(config, bus, demo=demo)
    return AttackContext(session=session, config=config, bus=bus, demo=demo,
                         stop_event=threading.Event())


def _ap(ctx: AttackContext, clients: bool = False):
    ap, _ = ctx.session.upsert_ap(AP, "TestNet", channel=6)
    if clients:
        ctx.session.add_client(AP, STA)
    return ctx.session.ap(AP) or ap


# --------------------------------------------------------------------------- #
# netproto.parse_ipv4: the UDP contract its callers were written against
# --------------------------------------------------------------------------- #

def test_parse_ipv4_decodes_udp_offer_for_parse_dhcp():
    offer = netproto.dhcp_offer(STA, "192.168.1.50", "192.168.1.1", "192.168.1.1")
    packet = netproto.ipv4_udp_packet("192.168.1.1", "255.255.255.255", 67, 68, offer)
    ip = netproto.parse_ipv4(packet)
    assert (ip["protocol"], ip["sport"], ip["dport"]) == (17, 67, 68)
    assert ip["l4_payload"] == offer
    reply = netproto.parse_dhcp(ip["l4_payload"])
    assert reply["op"] == "reply" and reply["yiaddr"] == "192.168.1.50"


def test_parse_ipv4_decodes_udp_discover():
    discover = netproto.dhcp_discover(STA, hostname="android-7f2a")
    packet = netproto.ipv4_udp_packet("0.0.0.0", "255.255.255.255", 68, 67, discover)
    ip = netproto.parse_ipv4(packet)
    assert (ip["sport"], ip["dport"]) == (68, 67)
    request = netproto.parse_dhcp(ip["l4_payload"])
    assert request["op"] == "request" and request["message_type"] == "discover"
    assert request["client_mac"] == STA and request["hostname"] == "android-7f2a"


def test_parse_ipv4_leaves_tcp_and_garbage_alone():
    segment = b"\x00\x50\x1f\x90" + b"\x00" * 16 + b"GET / HTTP/1.1\r\n\r\n"
    header = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(segment), 1, 0, 64, 6, 0,
                         bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    ip = netproto.parse_ipv4(header + segment)
    assert ip["protocol"] == 6 and ip["sport"] == 0 and ip["dport"] == 0
    assert ip["l4_payload"] == segment                     # untouched for TCP
    junk = netproto.parse_ipv4(b"\x60" + b"\x00" * 39)      # IPv6-looking
    assert junk["version"] == 0 and junk["l4_payload"] == b""
    short_udp = netproto.ipv4_udp_packet("10.0.0.1", "10.0.0.2", 1, 2, b"")[:24]
    assert netproto.parse_ipv4(short_udp)["sport"] == 0     # truncated: no crash


# --------------------------------------------------------------------------- #
# survey3.rogue_dhcp_detect: the live listen loop (was NameError + deaf)
# --------------------------------------------------------------------------- #

def test_survey3_has_its_live_parsers_imported():
    # the exact F821 that bit in the field: the name must exist in the module
    assert survey3.parse_ipv4 is netproto.parse_ipv4
    assert survey3.parse_dhcp is netproto.parse_dhcp


def test_rogue_dhcp_detect_counts_two_servers_live(config, bus):
    ctx = _ctx(config, bus, demo=False)
    ap = _ap(ctx)
    observations = []
    for server in ("192.168.1.1", "192.168.1.77"):
        offer = netproto.dhcp_offer(STA, "192.168.1.50", server, server)
        observations.append({
            "ethertype": 0x0800,
            "payload": netproto.ipv4_udp_packet(server, "255.255.255.255", 67, 68, offer),
        })
    ctx.listen = lambda *args, **kwargs: iter(observations)
    outcome = get_attack("rogue_dhcp_detect").run(ctx, ap)
    assert outcome.ok, outcome
    servers = {row["server"] for row in outcome.extra["servers"]}
    assert servers == {"192.168.1.1", "192.168.1.77"}
    assert ctx.session.attempts[-1].status == STATUS_SUCCESS


# --------------------------------------------------------------------------- #
# rogue2.rogue_dhcp: the live server loop (was silently skipping everything)
# --------------------------------------------------------------------------- #

def test_rogue_dhcp_answers_a_discover_live(config, bus, monkeypatch):
    from wifipilot.attacks import rogue2

    sent: list = []

    class FakeInjector:
        def __init__(self, _iface):
            self.error = ""

        def send(self, frame):
            sent.append(frame)

    monkeypatch.setattr(rogue2, "RawInjector", FakeInjector)
    ctx = _ctx(config, bus, demo=False)
    ap = _ap(ctx)
    discover = netproto.dhcp_discover(STA, hostname="android-7f2a")
    ctx.listen = lambda *args, **kwargs: iter([{
        "ethertype": 0x0800, "station": STA,
        "payload": netproto.ipv4_udp_packet("0.0.0.0", "255.255.255.255", 68, 67, discover),
    }])
    outcome = get_attack("rogue_dhcp").run(ctx, ap)
    assert outcome.ok, outcome
    leases = outcome.extra["leases"]
    assert len(leases) == 1 and leases[0]["mac"] == STA
    assert leases[0]["hostname"] == "android-7f2a"
    assert sent, "the rogue server never transmitted an offer"


# --------------------------------------------------------------------------- #
# protocol2 / capture3: a success must be filed as a success, severity intact
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name", ["pmf_downgrade_probe", "btm_hijack"])
def test_protocol2_success_closes_its_attempt(config, bus, name):
    ctx = _ctx(config, bus, demo=True)
    ap = _ap(ctx, clients=True)
    outcome = get_attack(name).run(ctx, ap)
    assert outcome.ok, outcome
    attempt = ctx.session.attempts[-1]
    assert attempt.status == STATUS_SUCCESS, f"{name} attempt left {attempt.status!r}"
    assert outcome.extra["severity"] in ("info", "medium", "high")


def test_btm_severity_tracks_whether_the_station_followed(config, bus):
    ctx = _ctx(config, bus, demo=True)
    ap = _ap(ctx, clients=True)
    outcome = get_attack("btm_hijack").run(ctx, ap)
    assert (outcome.extra["severity"] == "high") is bool(outcome.extra["followed"])


def test_mac_filter_probe_reports_its_severity(config, bus):
    ctx = _ctx(config, bus, demo=True)
    ap = _ap(ctx)
    outcome = get_attack("mac_filter_probe").run(ctx, ap)
    assert outcome.ok, outcome
    assert outcome.extra["severity"] == ("info" if outcome.extra["allowed"] else "low")
    assert ctx.session.attempts[-1].status == STATUS_SUCCESS


# --------------------------------------------------------------------------- #
# the package surface: __all__ must tell the truth
# --------------------------------------------------------------------------- #

def test_public_all_names_all_exist():
    import wifipilot as wp

    missing = [name for name in wp.__all__ if not hasattr(wp, name)]
    assert missing == []
    # the names ruff F401 used to flag are deliberate public API
    for name in ("catalogue", "current_run", "EK", "Config", "OllamaConfig",
                 "OpenRouterConfig", "AccessPoint", "Capture", "LLMError"):
        assert name in wp.__all__
