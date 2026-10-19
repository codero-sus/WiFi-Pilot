# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Network protocols, implemented rather than shelled out to.

The wireless engagement ends at the air interface and starts again on the network
behind it: a rogue DHCP server, a DNS sink, an SNMP query, a RADIUS shared-secret
test, credentials recovered from a capture.  Every one of those is a protocol with a
published wire format, and this module implements the ones the attacks need so that

* nothing depends on a tool being installed (``dnsmasq``, ``snmpget``, ``radclient``
  and ``tshark`` are all allowed to be absent),
* the tests can pin the encoders against published vectors, and
* what an attack sends is visible in the repository rather than behind a subprocess.

Everything here is bytes in, bytes out — no sockets.  The attacks own the sockets and
the timeouts, so a protocol function can always be tested without a network.

Layout:

* **IPv4/UDP/TCP/ARP** — :func:`ipv4_udp_packet`, :func:`parse_ipv4`, :func:`parse_arp`,
  :func:`parse_tcp`, with real checksums.
* **DHCP** (RFC 2131) — :func:`dhcp_discover`, :func:`parse_dhcp`.
* **DNS** (RFC 1035) — :func:`dns_query`, :func:`parse_dns`, :func:`dns_response`.
* **SSDP/UPnP** — :func:`ssdp_msearch`, :func:`ssdp_notify`, :func:`parse_ssdp`.
* **SNMP v2c** (RFC 3416, BER) — :func:`snmp_get`, :func:`parse_snmp`.
* **RADIUS** (RFC 2865) — :func:`radius_access_request`, :func:`radius_response`,
  :func:`radius_verify_response`, :func:`radius_decrypt_password`, plus
  :data:`RADIUS_PORTS` and :data:`RADIUS_DEFAULT_SECRETS`.
* **Cleartext credentials** — :func:`http_credentials`, :func:`ftp_credentials`,
  :func:`pop_imap_credentials`, :func:`cleartext_credentials` for capture analysis.
"""

from __future__ import annotations

import hashlib
import os
import socket
import struct
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #


def mac_to_bytes(mac: str) -> bytes:
    clean = mac.replace(":", "").replace("-", "")
    return bytes.fromhex(clean) if len(clean) == 12 else b"\x00" * 6


def bytes_to_mac(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw[:6])


def ipv4_bytes(address: str) -> bytes:
    return socket.inet_aton(address)


def ipv4_text(raw: bytes) -> str:
    return socket.inet_ntoa(raw)


def checksum(data: bytes) -> int:
    """The internet checksum (RFC 1071): one's complement of the 16-bit sum."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) | data[index + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4_udp_packet(source: str, destination: str, source_port: int, dest_port: int,
                    payload: bytes, ttl: int = 64, identification: int = 0) -> bytes:
    """An IPv4 packet carrying one UDP datagram, checksums computed for real."""
    udp = struct.pack(">HHHH", source_port, dest_port, 8 + len(payload), 0) + payload
    pseudo = ipv4_bytes(source) + ipv4_bytes(destination) + b"\x00\x11" \
        + struct.pack(">H", len(udp))
    udp_sum = checksum(pseudo + udp)
    udp = struct.pack(">HHHH", source_port, dest_port, 8 + len(payload), udp_sum) + payload
    total_length = 20 + len(udp)
    header = struct.pack(">BBHHHBBH", 0x45, 0, total_length, identification, 0, ttl, 17, 0) \
        + ipv4_bytes(source) + ipv4_bytes(destination)
    header = header[:10] + struct.pack(">H", checksum(header)) + header[12:]
    return header + udp


def parse_ipv4(data: bytes) -> Dict[str, Any]:
    """Decode an IPv4 packet; the L4 payload comes back as ``l4_payload``.

    For UDP the 8-byte header is decoded too: ``sport``/``dport`` are set
    and ``l4_payload`` is what the datagram *carries* (a DHCP BOOTP body, a
    DNS message), ready for :func:`parse_dhcp` and friends.  Callers in the
    rogue-DHCP and rogue-server surveys were written against exactly that
    contract — without it their live loops saw no ``sport`` key, skipped
    every frame, and the BOOTP magic cookie sat 8 bytes out of place.
    Non-UDP payloads (TCP segments above all) pass through untouched.
    """
    out: Dict[str, Any] = {"version": 0, "protocol": 0, "src": "", "dst": "",
                           "sport": 0, "dport": 0,
                           "l4_payload": b"", "header_length": 0, "total_length": 0}
    if len(data) < 20 or data[0] >> 4 != 4:
        return out
    header_length = (data[0] & 0x0F) * 4
    if len(data) < header_length:
        return out
    total_length = int.from_bytes(data[2:4], "big") or len(data)
    payload = data[header_length:min(total_length, len(data))]
    out.update({
        "version": 4, "header_length": header_length, "total_length": total_length,
        "dscp": data[1] >> 2, "ttl": data[8], "protocol": data[9],
        "src": ipv4_text(data[12:16]), "dst": ipv4_text(data[16:20]),
        "fragmented": bool(int.from_bytes(data[6:8], "big") & 0x1FFF),
        "l4_payload": payload,
        "protocol_name": {1: "icmp", 6: "tcp", 17: "udp"}.get(data[9], str(data[9])),
    })
    if data[9] == 17 and len(payload) >= 8:            # UDP: strip its header
        out["sport"], out["dport"] = struct.unpack(">HH", payload[:4])
        out["l4_payload"] = payload[8:]
    return out


def parse_tcp(data: bytes) -> Dict[str, Any]:
    """Decode the TCP and HTTP layers of an IPv4 payload (best effort)."""
    out: Dict[str, Any] = {"sport": 0, "dport": 0, "seq": 0, "ack": 0, "flags": "",
                           "payload": b"", "http": False, "request_line": "",
                           "headers": {}}
    if len(data) < 20:
        return out
    sport, dport, seq, ack = struct.unpack(">HHII", data[:12])
    data_offset = (data[12] >> 4) * 4
    flags = data[13]
    payload = data[data_offset:] if len(data) >= data_offset else b""
    out.update({"sport": sport, "dport": dport, "seq": seq, "ack": ack,
                "payload": payload, "data_offset": data_offset,
                "flags": "".join(name for bit, name in ((0x02, "SYN"), (0x10, "ACK"),
                                                        (0x01, "FIN"), (0x04, "RST"))
                                 if flags & bit)})
    if payload[:4] in (b"GET ", b"POST", b"HEAD", b"PUT "):
        out["http"] = True
        lines = payload.split(b"\r\n")
        out["request_line"] = lines[0].decode("latin-1", "replace")[:200]
        for line in lines[1:20]:
            if b":" in line:
                key, _, value = line.partition(b":")
                out["headers"][key.decode("latin-1", "replace").strip().lower()] = \
                    value.decode("latin-1", "replace").strip()[:200]
        out["body"] = lines[-1] if len(lines) > 2 else b""
    return out


def parse_arp(payload: bytes) -> Dict[str, str]:
    """A single ARP packet as sender/target hardware and protocol addresses."""
    if len(payload) < 28:
        return {}
    htype, ptype, hlen, plen, opcode = struct.unpack("!HHBBH", payload[:8])
    if htype != 1 or ptype != 0x0800 or hlen != 6 or plen != 4:
        return {}
    return {
        "op": {1: "request", 2: "reply"}.get(opcode, str(opcode)),
        "sender_mac": bytes_to_mac(payload[8:14]),
        "sender_ip": ipv4_text(payload[14:18]),
        "target_mac": bytes_to_mac(payload[18:24]),
        "target_ip": ipv4_text(payload[24:28]),
        "gratuitous": payload[14:18] == payload[24:28],
    }


# --------------------------------------------------------------------------- #
# DHCP (RFC 2131)
# --------------------------------------------------------------------------- #

DHCP_CLIENT_PORT = 68
DHCP_SERVER_PORT = 67

#: the option codes worth naming (RFC 2132)
DHCP_OPTIONS = {1: "subnet_mask", 3: "router", 6: "dns", 12: "hostname",
                15: "domain", 28: "broadcast", 50: "requested_ip", 51: "lease_time",
                53: "message_type", 54: "server_id", 55: "parameter_list",
                57: "max_message_size", 60: "vendor_class", 61: "client_id",
                81: "client_fqdn", 119: "domain_search", 121: "classless_routes",
                249: "ms_classless_routes", 43: "vendor_specific", 56: "message",
                66: "tftp_server", 67: "bootfile", 82: "relay_agent",
                252: "wpad"}

DHCP_MESSAGE_TYPES = {1: "discover", 2: "offer", 3: "request", 4: "decline",
                      5: "ack", 6: "nak", 7: "release", 8: "inform"}


def _dhcp_packet(op: int, mac: str, options: List[Tuple[int, bytes]],
                 xid: int, flags: int, requested_ip: str = "") -> bytes:
    client = mac_to_bytes(mac)
    body = struct.pack(">BBBBIHH", op, 1, 6, 0, xid, 0, flags)
    body += bytes([0, 0, 0, 0])
    body += ipv4_bytes(requested_ip or "0.0.0.0")      # yiaddr
    body += ipv4_bytes("0.0.0.0")                      # siaddr
    body += ipv4_bytes("0.0.0.0")                      # giaddr
    body += client + b"\x00" * 10                      # chaddr, 16 bytes
    body += b"\x00" * 64                               # sname
    body += b"\x00" * 128                              # file
    body += b"\x63\x82\x53\x63"                        # magic cookie
    for code, value in options:
        body += bytes([code, len(value)]) + value
    body += b"\xff"
    return body


def dhcp_discover(mac: str, xid: Optional[int] = None, hostname: str = "",
                  requested_ip: str = "", vendor_class: str = "wifipilot",
                  client_id: bool = True) -> bytes:
    """A DHCP DISCOVER: the packet a station sends before it has an address."""
    xid = xid if xid is not None else int.from_bytes(os.urandom(4), "big")
    options: List[Tuple[int, bytes]] = [(53, b"\x01")]
    if client_id:
        options.append((61, bytes([1]) + mac_to_bytes(mac)))
    if requested_ip:
        options.append((50, ipv4_bytes(requested_ip)))
    if hostname:
        options.append((12, hostname.encode()[:32]))
    if vendor_class:
        options.append((60, vendor_class.encode()[:32]))
    options.append((55, bytes([1, 3, 6, 15, 28, 51, 58, 59])))
    return _dhcp_packet(1, mac, options, xid, 0x8000, requested_ip=requested_ip)


def dhcp_request(mac: str, requested_ip: str, server_id: str,
                 xid: Optional[int] = None, hostname: str = "") -> bytes:
    """A DHCP REQUEST for an address a server offered."""
    xid = xid if xid is not None else int.from_bytes(os.urandom(4), "big")
    options: List[Tuple[int, bytes]] = [(53, b"\x03"), (50, ipv4_bytes(requested_ip)),
                                        (54, ipv4_bytes(server_id)),
                                        (61, bytes([1]) + mac_to_bytes(mac))]
    if hostname:
        options.append((12, hostname.encode()[:32]))
    return _dhcp_packet(1, mac, options, xid, 0x8000, requested_ip=requested_ip)


def parse_dhcp(data: bytes) -> Dict[str, Any]:
    """Decode a DHCP packet, options included."""
    out: Dict[str, Any] = {"op": "", "message_type": "", "xid": 0, "client_mac": "",
                           "yiaddr": "", "siaddr": "", "options": {}, "hostname": "",
                           "requested_ip": "", "server_id": "", "vendor_class": ""}
    if len(data) < 240 or data[236:240] != b"\x63\x82\x53\x63":
        return out
    op = data[0]
    out["op"] = {1: "request", 2: "reply"}.get(op, str(op))
    out["xid"] = int.from_bytes(data[4:8], "big")
    out["client_mac"] = bytes_to_mac(data[28:34])
    out["yiaddr"] = ipv4_text(data[16:20])
    out["siaddr"] = ipv4_text(data[20:24])
    offset = 240
    while offset < len(data):
        code = data[offset]
        if code == 0:
            offset += 1
            continue
        if code == 255:
            break
        if offset + 1 >= len(data):
            break
        length = data[offset + 1]
        value = data[offset + 2:offset + 2 + length]
        name = DHCP_OPTIONS.get(code, f"option_{code}")
        if name == "message_type" and value:
            out["message_type"] = DHCP_MESSAGE_TYPES.get(value[0], str(value[0]))
        elif name in ("router", "dns", "subnet_mask", "broadcast", "requested_ip",
                      "server_id") and len(value) >= 4:
            addresses = [ipv4_text(value[index:index + 4])
                         for index in range(0, len(value) - 3, 4)]
            out["options"][name] = addresses if len(addresses) > 1 else addresses[0]
            if name == "requested_ip":
                out["requested_ip"] = addresses[0]
            if name == "server_id":
                out["server_id"] = addresses[0]
        elif name == "hostname":
            out["hostname"] = value.decode("latin-1", "replace").strip("\x00")
        elif name == "vendor_class":
            out["vendor_class"] = value.decode("latin-1", "replace").strip("\x00")
        elif name == "lease_time" and len(value) >= 4:
            out["options"][name] = int.from_bytes(value[:4], "big")
        else:
            out["options"][name] = value
        offset += 2 + length
    return out


def dhcp_offer(mac: str, yiaddr: str, server_id: str, router: str,
               dns: Union[str, Sequence[str]] = (), lease: int = 3600,
               hostname: str = "", xid: int = 0, message_type: int = 2) -> bytes:
    """A DHCP OFFER/ACK a rogue server can send: the answer side of the protocol."""
    options: List[Tuple[int, bytes]] = [(53, bytes([message_type])),
                                        (54, ipv4_bytes(server_id)),
                                        (51, struct.pack(">I", lease))]
    if router:
        options.append((3, ipv4_bytes(router)))
    if dns:
        # one resolver is a string and several are a sequence: a caller should not have to
        # remember which.  A bare string iterated character by character is a bug that
        # only surfaces on a capture with "192.168.1.66" in it, so it is handled here
        # rather than at every call site.
        servers = [dns] if isinstance(dns, str) else list(dns)
        options.append((6, b"".join(ipv4_bytes(address) for address in servers)))
    if hostname:
        options.append((12, hostname.encode()[:32]))
    return _dhcp_packet(2, mac, options, xid, 0x0000, requested_ip=yiaddr)


def dhcp_message(message_type: int, mac: str, xid: int = 0, server_id: str = "",
                 requested_ip: str = "", client_ip: str = "", options: Sequence[
                     Tuple[int, bytes]] = ()) -> bytes:
    """A DHCP message of any type, with the options the caller wants.

    RELEASE and DECLINE are the two a *client* sends that an attacker has no business
    sending: a RELEASE gives an address back, and a DECLINE marks one as in use.  Both
    carry the client's own MAC in ``chaddr`` and nothing that proves the sender is that
    client — which is the whole problem with them.
    """
    entries: List[Tuple[int, bytes]] = [(53, bytes([message_type & 0xFF]))]
    if server_id:
        entries.append((54, ipv4_bytes(server_id)))
    if requested_ip:
        entries.append((50, ipv4_bytes(requested_ip)))
    if client_ip:
        entries.append((12, client_ip.encode()[:32]))
    entries.extend((int(code), bytes(value)) for code, value in options)
    return _dhcp_packet(1, mac, entries, xid or int.from_bytes(os.urandom(4), "big"),
                        0x8000, requested_ip=requested_ip)


def dhcp_release(mac: str, address: str, server_id: str, xid: int = 0) -> bytes:
    """A DHCP RELEASE: "give my address back", unauthenticated as the standard defines."""
    return dhcp_message(7, mac, xid=xid, server_id=server_id, requested_ip=address)


def dhcp_decline(mac: str, address: str, server_id: str, xid: int = 0) -> bytes:
    """A DHCP DECLINE: "that address is already in use" — which burns it in the pool."""
    return dhcp_message(4, mac, xid=xid, server_id=server_id, requested_ip=address)


def dhcp_inform(mac: str, client_ip: str, xid: int = 0) -> bytes:
    """A DHCP INFORM: a station that already has an address asking for its options."""
    return dhcp_message(8, mac, xid=xid, requested_ip=client_ip)


def dhcp_nak(mac: str, server_id: str, requested_ip: str = "", xid: int = 0,
             message: str = "address not available") -> bytes:
    """A DHCP NAK: the message that makes a client throw its configuration away."""
    options: List[Tuple[int, bytes]] = [(56, message.encode()[:64])]
    entries = [(53, b"\x06"), (54, ipv4_bytes(server_id) if server_id else bytes(4))]
    if requested_ip:
        entries.append((50, ipv4_bytes(requested_ip)))
    entries.extend(options)
    return _dhcp_packet(2, mac, entries, xid or int.from_bytes(os.urandom(4), "big"),
                        0x0000, requested_ip=requested_ip)


def dhcp_rogue_offer(mac: str, yiaddr: str, router: str, dns: Union[str, Sequence[str]] = (),
                     lease: int = 86400, xid: int = 0,
                     wpad: str = "", routes: str = "") -> bytes:
    """An OFFER built to win: a long lease, itself as router, and the option bombs.

    Option 252 (WPAD) is what turns a rogue DHCP server into a proxy configuration
    attack — the client configures itself to fetch a proxy script from the attacker.
    Option 121 pushes a classless static route, which is how a rogue server makes itself
    the path to a subnet it is not on.
    """
    options: List[Tuple[int, bytes]] = [(53, b"\x02"), (54, ipv4_bytes(router)),
                                        (51, struct.pack(">I", lease)),
                                        (3, ipv4_bytes(router))]
    if dns:
        # one resolver is a string and several are a sequence: a caller should not have to
        # remember which.  A bare string iterated character by character is a bug that
        # only surfaces on a capture with "192.168.1.66" in it, so it is handled here
        # rather than at every call site.
        servers = [dns] if isinstance(dns, str) else list(dns)
        options.append((6, b"".join(ipv4_bytes(address) for address in servers)))
    if wpad:
        options.append((252, wpad.encode()[:64]))
    if routes:
        options.append((121, _encode_classless_routes(routes)))
    return _dhcp_packet(2, mac, options, xid or int.from_bytes(os.urandom(4), "big"),
                        0x0000, requested_ip=yiaddr)


def _encode_classless_routes(routes: str) -> bytes:
    """Option 121: a (prefix length, significant bytes, router) list per RFC 3442."""
    out = bytearray()
    for entry in routes.split(";") if isinstance(routes, str) else routes:
        if not entry:
            continue
        network, _, router = entry.partition(":")
        address, _, length = network.partition("/")
        prefix = int(length or 24)
        raw = ipv4_bytes(address)
        significant = (prefix + 7) // 8
        out += bytes([prefix]) + raw[:significant] + ipv4_bytes(router or "0.0.0.0")
    return bytes(out) if out else b"\x00" + ipv4_bytes("192.168.1.1")


# --------------------------------------------------------------------------- #
# DNS (RFC 1035)
# --------------------------------------------------------------------------- #

DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
             16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 43: "DS", 46: "RRSIG",
             48: "DNSKEY", 255: "ANY"}
DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
              4: "NOTIMP", 5: "REFUSED"}


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        out += bytes([len(label)]) + label.encode("latin-1", "replace")
    return out + b"\x00"


def decode_name(data: bytes, offset: int, depth: int = 0) -> Tuple[str, int]:
    """Decode a DNS name, following compression pointers (bounded)."""
    labels: List[str] = []
    cursor = offset
    jumped = False
    end = offset
    while depth < 12:
        if cursor >= len(data):
            break
        length = data[cursor]
        if length == 0:
            cursor += 1
            if not jumped:
                end = cursor
            break
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[cursor + 1]
            if not jumped:
                end = cursor + 2
            jumped = True
            cursor = pointer
            depth += 1
            continue
        labels.append(data[cursor + 1:cursor + 1 + length].decode("latin-1", "replace"))
        cursor += 1 + length
        if not jumped:
            end = cursor
    return ".".join(labels), end


def dns_query(name: str, qtype: int = 1, txid: Optional[int] = None,
              recursion: bool = True) -> bytes:
    """A recursive DNS query: one question, no answers."""
    txid = txid if txid is not None else int.from_bytes(os.urandom(2), "big")
    flags = 0x0100 if recursion else 0x0000
    header = struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0)
    question = encode_name(name) + struct.pack(">HH", qtype, 1)
    return header + question


def parse_dns(data: bytes) -> Dict[str, Any]:
    """Decode a DNS message: header flags, questions, answers, authority."""
    out: Dict[str, Any] = {"txid": 0, "qr": False, "rcode": "", "recursion_available":
                           False, "recursion_desired": False, "truncated": False,
                           "questions": [], "answers": [], "authority": [],
                           "answer_count": 0, "flags_word": 0}
    if len(data) < 12:
        return out
    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
    out.update({"txid": txid, "flags_word": flags, "qr": bool(flags & 0x8000),
                "recursion_desired": bool(flags & 0x0100),
                "recursion_available": bool(flags & 0x0080),
                "truncated": bool(flags & 0x0200),
                "rcode": DNS_RCODES.get(flags & 0x000F, str(flags & 0x000F)),
                "answer_count": ancount, "authority_count": nscount})
    offset = 12
    for _ in range(qdcount):
        name, offset = decode_name(data, offset)
        if offset + 4 > len(data):
            return out
        qtype, qclass = struct.unpack(">HH", data[offset:offset + 4])
        offset += 4
        out["questions"].append({"name": name, "type": DNS_TYPES.get(qtype, str(qtype)),
                                 "type_code": qtype, "class": qclass})
    for section, count in (("answers", ancount), ("authority", nscount)):
        for _ in range(min(count, 64)):
            if offset >= len(data):
                return out
            name, offset = decode_name(data, offset)
            if offset + 10 > len(data):
                return out
            rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
            offset += 10
            rdata = data[offset:offset + rdlength]
            offset += rdlength
            record = {"name": name, "type": DNS_TYPES.get(rtype, str(rtype)),
                      "type_code": rtype, "class": rclass, "ttl": ttl}
            if rtype == 1 and len(rdata) == 4:
                record["value"] = ipv4_text(rdata)
            elif rtype == 28 and len(rdata) == 16:
                record["value"] = socket.inet_ntop(socket.AF_INET6, rdata)
            elif rtype == 5:
                record["value"] = decode_name(data, offset - rdlength)[0]
            elif rtype in (2, 12):
                record["value"] = decode_name(data, offset - rdlength)[0]
            elif rtype == 16:
                record["value"] = rdata[1:].decode("latin-1", "replace")
            elif rtype == 15 and len(rdata) > 3:
                record["value"] = decode_name(data, offset - rdlength + 2)[0]
            else:
                record["value"] = rdata.hex()[:120]
            out[section].append(record)
    return out


def dns_response(query: bytes, answers: Sequence[Tuple[str, str]],
                 ttl: int = 60, rcode: int = 0) -> bytes:
    """Build a reply to a query: the DNS sink's whole job.

    ``answers`` is a list of ``(name, ipv4)`` pairs; the question section is echoed,
    which is what every client checks before it believes an answer.
    """
    parsed = parse_dns(query)
    txid = parsed.get("txid", 0)
    question = parsed["questions"][0] if parsed.get("questions") else {"name": ""}
    qname = question.get("name", "")
    qtype = question.get("type_code", 1)
    records = b""
    count = 0
    for name, address in answers:
        if qtype not in (1, 255):
            continue
        records += encode_name(name or qname) + struct.pack(">HHIH", 1, 1, ttl, 4) \
            + ipv4_bytes(address)
        count += 1
    flags = 0x8180 | (rcode & 0x000F)             # response, recursion available
    header = struct.pack(">HHHHHH", txid, flags, 1 if qname else 0, count, 0, 0)
    return header + (encode_name(qname) + struct.pack(">HH", qtype, 1) if qname else b"") \
        + records


# --------------------------------------------------------------------------- #
# SSDP / UPnP
# --------------------------------------------------------------------------- #

SSDP_ADDRESS = "239.255.255.250"
SSDP_PORT = 1900


def ssdp_msearch(search_target: str = "ssdp:all", mx: int = 2,
                 user_agent: str = "wifipilot/upnp") -> bytes:
    """An SSDP M-SEARCH datagram: how a UPnP device announces itself."""
    return ("M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {SSDP_ADDRESS}:{SSDP_PORT}\r\n"
            'MAN: "ssdp:discover"\r\n'
            f"MX: {mx}\r\n"
            f"ST: {search_target}\r\n"
            f"USER-AGENT: {user_agent}\r\n\r\n").encode()


def ssdp_notify(name: str = "router", address: str = "", location: str = "",
                model: str = "", nt: str = "upnp:rootdevice", nts: str = "ssdp:alive",
                usn: str = "", cache: int = 1800, server: str = "") -> bytes:
    """An SSDP ``NOTIFY``: a device announcing itself to the whole segment.

    Three of these go out when a device joins, and then again as each cached
    announcement expires — which is why a five-minute capture of a quiet network knows
    the make and model of every television, router and printer on it.  ``LOCATION`` is
    the description document; ``USN`` is the identity, and it is what makes a device
    recognisable across captures even when its address changes.
    """
    usn = usn or f"uuid:{name}"
    server = server or f"Linux/3.14 UPnP/1.1 {model or name}/1.0"
    headers = ["NOTIFY * HTTP/1.1", f"HOST: {SSDP_ADDRESS}:{SSDP_PORT}",
               f"CACHE-CONTROL: max-age={cache}", f"NT: {nt}", f"NTS: {nts}",
               f"USN: {usn}::{nt}", f"SERVER: {server}"]
    if location:
        headers.append(f"LOCATION: {location}")
    return ("\r\n".join(headers) + "\r\n\r\n").encode()


def parse_ssdp(text: str) -> Dict[str, str]:
    """SSDP/HTTP-ish headers, lower-cased, first line included as ``_``."""
    out: Dict[str, str] = {}
    for index, line in enumerate(text.splitlines()):
        if not line.strip():
            continue
        if ":" not in line:
            if index == 0:
                out["_"] = line.strip()
            continue
        key, _, value = line.partition(":")
        out[key.strip().lower()] = value.strip()
    return out


def html_title(body: str) -> str:
    """The ``<title>`` of an HTML page, which is what an admin page gives away."""
    lowered = body.lower()
    start = lowered.find("<title")
    if start < 0:
        return ""
    start = lowered.find(">", start)
    end = lowered.find("</title>", start)
    if start < 0 or end < 0:
        return ""
    return " ".join(body[start + 1:end].split())[:120]


def html_inputs(body: str) -> List[Dict[str, str]]:
    """Every ``<input>`` on a page: the fields a login form is made of."""
    out: List[Dict[str, str]] = []
    lowered = body.lower()
    index = 0
    while True:
        start = lowered.find("<input", index)
        if start < 0:
            break
        end = lowered.find(">", start)
        if end < 0:
            break
        tag = body[start:end + 1]
        fields: Dict[str, str] = {}
        for name in ("type", "name", "id", "value", "placeholder"):
            marker = f'{name}="'
            position = tag.lower().find(marker)
            if position < 0:
                marker = f"{name}='"
                position = tag.lower().find(marker)
                if position < 0:
                    continue
                closing = "'"
            else:
                closing = '"'
            value = tag[position + len(marker):]
            value = value.split(closing)[0]
            fields[name] = value
        out.append(fields)
        index = end + 1
    return out


def http_get(host: str, port: int, path: str = "/", timeout: float = 3.0,
             https: bool = False) -> Dict[str, Any]:
    """A minimal, honest HTTP/1.0 GET: status line, headers and body."""
    if https:
        import ssl

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as sock:
                return _http_exchange(sock, host, path)
    with socket.create_connection((host, port), timeout=timeout) as sock:
        return _http_exchange(sock, host, path)


def _http_exchange(sock: socket.socket, host: str, path: str) -> Dict[str, Any]:
    sock.settimeout(6.0)
    request = (f"GET {path} HTTP/1.0\r\nHost: {host}\r\n"
               "User-Agent: wifipilot\r\nAccept: */*\r\n\r\n").encode()
    sock.sendall(request)
    chunks: List[bytes] = []
    while sum(len(chunk) for chunk in chunks) < 65536:
        try:
            chunk = sock.recv(4096)
        except OSError:
            break
        if not chunk:
            break
        chunks.append(chunk)
    raw = b"".join(chunks)
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1", "replace").split("\r\n")
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()
    return {"status": lines[0] if lines else "", "headers": headers,
            "body": body.decode("latin-1", "replace"), "bytes": len(body),
            "ok": bool(lines and lines[0].startswith("HTTP"))}


def urlget(url: str, timeout: float = 3.0) -> Dict[str, Any]:
    """Split a URL and GET it; the in-process equivalent of ``curl``."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    scheme = (parsed.scheme or "http").lower()
    host = parsed.hostname or ""
    if not host:
        return {"ok": False, "status": "", "body": "", "bytes": 0, "headers": {}}
    port = parsed.port or (443 if scheme == "https" else 80)
    return http_get(host, port, parsed.path or "/", timeout=timeout,
                    https=scheme == "https")


# --------------------------------------------------------------------------- #
# SNMP v2c (BER)
# --------------------------------------------------------------------------- #

SNMP_PORT = 161
#: the OIDs an audit asks for: description, name, uptime, contact, location
SNMP_IDENTITY_OIDS = {
    "1.3.6.1.2.1.1.1.0": "sysDescr",
    "1.3.6.1.2.1.1.3.0": "sysUpTime",
    "1.3.6.1.2.1.1.4.0": "sysContact",
    "1.3.6.1.2.1.1.5.0": "sysName",
    "1.3.6.1.2.1.1.6.0": "sysLocation",
    "1.3.6.1.2.1.1.7.0": "sysServices",
}
SNMP_DEFAULT_COMMUNITIES = ("public", "private", "cisco", "admin", "snmp", "default",
                            "write", "read", "network")


def _ber_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _ber_tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _ber_length(len(payload)) + payload


def _ber_integer(value: int) -> bytes:
    if value == 0:
        return _ber_tlv(0x02, b"\x00")
    if value < 0:
        raise ValueError("only unsigned integers are needed here")
    encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return _ber_tlv(0x02, encoded)


def encode_oid(oid: str) -> bytes:
    """Encode a dotted OID as BER: first two arcs combined, then base-128."""
    parts = [int(part) for part in oid.strip(".").split(".") if part != ""]
    if len(parts) < 2:
        raise ValueError("an OID needs at least two arcs")
    out = bytearray([40 * parts[0] + parts[1]])
    for value in parts[2:]:
        if value < 0x80:
            out.append(value)
            continue
        encoded = bytearray()
        while value:
            encoded.insert(0, value & 0x7F)
            value >>= 7
        for index in range(len(encoded) - 1):
            encoded[index] |= 0x80
        out.extend(encoded)
    return bytes(out)


def decode_oid(data: bytes) -> str:
    if not data:
        return ""
    first = data[0]
    parts = [first // 40, first % 40]
    value = 0
    for byte in data[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    if value:
        parts.append(value)
    return ".".join(str(part) for part in parts)


def tcp_flag_names(flags: int) -> List[str]:
    """The names of the TCP flags set in a header's flag byte, in wire order."""
    names = []
    for bit, name in ((0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
                      (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR")):
        if flags & bit:
            names.append(name)
    return names


def snmp_get(community: str, oids: Sequence[str] = ("1.3.6.1.2.1.1.1.0",),
             request_id: Optional[int] = None) -> bytes:
    """An SNMP v2c GetRequest for a list of OIDs (BER encoded from scratch)."""
    request_id = request_id if request_id is not None else int.from_bytes(os.urandom(4),
                                                                          "big") & 0x7FFFFFFF
    varbinds = b"".join(_ber_tlv(0x30, _ber_tlv(0x06, encode_oid(oid)) + b"\x05\x00")
                        for oid in oids)
    pdu = _ber_tlv(0xA0, _ber_integer(request_id) + _ber_integer(0) + _ber_integer(0)
                   + _ber_tlv(0x30, varbinds))
    message = _ber_integer(1) + _ber_tlv(0x04, community.encode()) + pdu
    return _ber_tlv(0x30, message)


def _ber_read(data: bytes, offset: int = 0) -> Tuple[int, bytes, int]:
    """Read one TLV: ``(tag, value, next_offset)``."""
    if offset + 2 > len(data):
        raise ValueError("truncated BER")
    tag = data[offset]
    length = data[offset + 1]
    cursor = offset + 2
    if length & 0x80:
        count = length & 0x7F
        if cursor + count > len(data):
            raise ValueError("truncated BER length")
        length = int.from_bytes(data[cursor:cursor + count], "big")
        cursor += count
    if cursor + length > len(data):
        raise ValueError("truncated BER value")
    return tag, data[cursor:cursor + length], cursor + length


def parse_snmp(data: bytes) -> Dict[str, Any]:
    """Decode an SNMP response into request id, error status and varbinds."""
    out: Dict[str, Any] = {"version": 0, "community": "", "request_id": 0,
                           "error_status": 0, "error_index": 0, "varbinds": [],
                           "ok": False}
    try:
        _tag, message, _ = _ber_read(data, 0)
        _tag, version, cursor = _ber_read(message, 0)
        _tag, community, cursor = _ber_read(message, cursor)
        _tag, pdu, _ = _ber_read(message, cursor)
        out["version"] = int.from_bytes(version, "big")
        out["community"] = community.decode("latin-1", "replace")
        _tag, request_id, cursor = _ber_read(pdu, 0)
        out["request_id"] = int.from_bytes(request_id, "big")
        _tag, error_status, cursor = _ber_read(pdu, cursor)
        out["error_status"] = int.from_bytes(error_status, "big")
        _tag, error_index, cursor = _ber_read(pdu, cursor)
        out["error_index"] = int.from_bytes(error_index, "big")
        _tag, varbind_list, _ = _ber_read(pdu, cursor)
        position = 0
        while position < len(varbind_list):
            _tag, varbind, position = _ber_read(varbind_list, position)
            _tag, oid, inner = _ber_read(varbind, 0)
            tag, value, _ = _ber_read(varbind, inner)
            out["varbinds"].append({"oid": decode_oid(oid),
                                    "name": SNMP_IDENTITY_OIDS.get(decode_oid(oid), ""),
                                    "type": tag, "value": _ber_value(tag, value)})
        out["ok"] = bool(out["varbinds"]) and not out["error_status"]
    except (ValueError, IndexError):
        return out
    return out


def snmp_get_live(host: str, community: str, oids: Sequence[str] = (),
                 timeout: float = 1.5, port: int = SNMP_PORT) -> Dict[str, Any]:
    """Send one SNMP get and decode the answer; ``ok`` is False on silence.

    A UDP client with one socket and one timeout: an audit that tries ten community
    strings against twenty devices must not take ten minutes to say "nothing".
    """
    out: Dict[str, Any] = {"ok": False, "community": community, "host": host,
                           "varbinds": [], "error": ""}
    request = snmp_get(community, list(oids) or ["1.3.6.1.2.1.1.1.0"])
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(request, (host, port))
            payload, _peer = sock.recvfrom(4096)
    except OSError as exc:
        out["error"] = type(exc).__name__
        return out
    parsed = parse_snmp(payload)
    out["ok"] = parsed.get("ok", False)
    out["varbinds"] = parsed.get("varbinds", [])
    out["error_status"] = parsed.get("error_status", 0)
    return out


def _ber_value(tag: int, value: bytes) -> Any:
    if tag == 0x04:
        text = value.decode("latin-1", "replace")
        return text.rstrip("\x00").strip()
    if tag == 0x02:
        return int.from_bytes(value, "big", signed=True)
    if tag in (0x41, 0x42, 0x43):
        return int.from_bytes(value, "big")
    if tag == 0x40:
        return ipv4_text(value) if len(value) == 4 else value.hex()
    if tag == 0x06:
        return decode_oid(value)
    if tag == 0x05:
        return None
    return value.hex()[:80]


# --------------------------------------------------------------------------- #
# RADIUS (RFC 2865)
# --------------------------------------------------------------------------- #

RADIUS_PORT = 1812
RADIUS_LEGACY_PORT = 1645
RADIUS_PORTS = (RADIUS_PORT, RADIUS_LEGACY_PORT)
RADIUS_ACCOUNTING_PORT = 1813

#: shared secrets that ship with (or are typed into) real deployments
RADIUS_DEFAULT_SECRETS = ("secret", "radius", "testing123", "shared", "cisco",
                          "password", "public", "private", "wifi", "wireless",
                          "guest", "lab", "admin", "123456", "8021x", "enterprise")

RADIUS_ATTRIBUTES = {1: "user_name", 2: "user_password", 3: "chap_password",
                     4: "nas_ip_address", 5: "nas_port", 6: "service_type",
                     7: "framed_protocol", 8: "framed_ip", 18: "reply_message",
                     24: "state", 25: "class", 26: "vendor_specific",
                     27: "session_timeout", 28: "idle_timeout", 30: "called_station_id",
                     31: "calling_station_id", 32: "nas_identifier",
                     79: "eap_message", 80: "message_authenticator"}

RADIUS_CODES = {1: "Access-Request", 2: "Access-Accept", 3: "Access-Reject",
                4: "Accounting-Request", 5: "Accounting-Response", 11: "Access-Challenge",
                12: "Status-Server", 13: "Status-Client"}


def radius_password_encrypt(password: str, secret: str, authenticator: bytes) -> bytes:
    """Hide a password with MD5 chaining (RFC 2865 §5.2)."""
    raw = password.encode()[:128]
    padded = raw + b"\x00" * ((16 - len(raw) % 16) % 16 or 16)
    out = b""
    previous = authenticator
    for index in range(0, len(padded), 16):
        digest = hashlib.md5(secret.encode() + previous).digest()
        block = bytes(a ^ b for a, b in zip(padded[index:index + 16], digest))
        out += block
        previous = block
    return out


def radius_password_decrypt(encrypted: bytes, secret: str, authenticator: bytes) -> str:
    """Undo :func:`radius_password_encrypt` — what a capture analysis does."""
    out = b""
    previous = authenticator
    for index in range(0, len(encrypted) - 15, 16):
        block = encrypted[index:index + 16]
        digest = hashlib.md5(secret.encode() + previous).digest()
        out += bytes(a ^ b for a, b in zip(block, digest))
        previous = block
    return out.rstrip(b"\x00").decode("utf-8", "replace")


def _radius_packet(code: int, identifier: int, authenticator: bytes,
                   attributes: Sequence[Tuple[int, bytes]]) -> bytes:
    body = b"".join(bytes([type_]) + bytes([2 + len(value)]) + value
                    for type_, value in attributes)
    length = 20 + len(body)
    return struct.pack(">BBH", code, identifier, length) + authenticator + body


def radius_access_request(secret: str, username: str, password: str,
                          nas_ip: str = "192.168.1.16", identifier: int = 0,
                          nas_port: int = 3, authenticator: Optional[bytes] = None,
                          extra: Sequence[Tuple[int, bytes]] = ()
                          ) -> Tuple[bytes, bytes]:
    """An Access-Request with a real request authenticator; returns both."""
    authenticator = authenticator or os.urandom(16)
    attributes: List[Tuple[int, bytes]] = [(1, username.encode()[:253])]
    if password:
        attributes.append((2, radius_password_encrypt(password, secret, authenticator)))
    attributes += [(4, ipv4_bytes(nas_ip)), (5, struct.pack(">I", nas_port)),
                   (6, struct.pack(">I", 1)), (7, struct.pack(">I", 1))]
    attributes += list(extra)
    # RFC 2865 §3: an Access-Request carries a *random* Request Authenticator (it is
    # what hides the password, and what the response authenticator is computed over).
    # Only the response and accounting requests use a digest here.
    packet = _radius_packet(1, identifier, authenticator, attributes)
    return packet, authenticator


def radius_response(request: bytes, secret: str, code: int = 2,
                    reply_message: str = "wifipilot shared-secret test",
                    identifier: Optional[int] = None,
                    attributes: Sequence[Tuple[int, bytes]] = ()) -> bytes:
    """An Access-Accept/Reject for a request, with a valid Response Authenticator."""
    if len(request) < 20:
        raise ValueError("not a RADIUS packet")
    identifier = identifier if identifier is not None else request[1]
    request_authenticator = request[4:20]
    attrs: List[Tuple[int, bytes]] = list(attributes)
    if reply_message:
        attrs.append((18, reply_message.encode()[:253]))
    body = b"".join(bytes([type_]) + bytes([2 + len(value)]) + value
                    for type_, value in attrs)
    length = 20 + len(body)
    digest = hashlib.md5(struct.pack(">BBH", code, identifier, length)
                         + request_authenticator + body + secret.encode()).digest()
    return struct.pack(">BBH", code, identifier, length) + digest + body


def radius_verify_response(secret: str, request: bytes, response: bytes) -> bool:
    """Does this response carry the authenticator ``secret`` would produce?

    The argument order is ``(secret, request, response)`` because that is the order the
    secret test reads in: try the secret against the request it answered.  The request
    authenticator (RFC 2865 §3) is what the response digest is computed over.
    """
    if len(request) < 20 or len(response) < 20:
        return False
    request_authenticator = request[4:20]
    code, identifier, length = struct.unpack(">BBH", response[:4])
    claimed = response[4:20]
    body = response[20:length]
    digest = hashlib.md5(struct.pack(">BBH", code, identifier, length)
                         + request_authenticator + body + secret.encode()).digest()
    return digest == claimed


def parse_radius(data: bytes) -> Dict[str, Any]:
    """Decode a RADIUS packet, including the attributes worth naming."""
    out: Dict[str, Any] = {"code": "", "code_value": 0, "identifier": 0, "length": 0,
                           "authenticator": "", "attributes": [], "user_name": "",
                           "reply_message": "", "eap_message": False}
    if len(data) < 20:
        return out
    code, identifier, length = struct.unpack(">BBH", data[:4])
    out.update({"code": RADIUS_CODES.get(code, str(code)), "code_value": code,
                "identifier": identifier, "length": length,
                "authenticator": data[4:20].hex()})
    offset = 20
    while offset + 2 <= min(length, len(data)):
        type_ = data[offset]
        attr_length = data[offset + 1]
        if attr_length < 2 or offset + attr_length > len(data):
            break
        value = data[offset + 2:offset + attr_length]
        name = RADIUS_ATTRIBUTES.get(type_, f"attribute_{type_}")
        entry = {"type": type_, "name": name, "length": attr_length}
        if name == "user_name":
            entry["value"] = value.decode("utf-8", "replace")
            out["user_name"] = entry["value"]
        elif name == "user_password":
            entry["value"] = value.hex()
            entry["encrypted"] = True
        elif name == "reply_message":
            entry["value"] = value.decode("utf-8", "replace")
            out["reply_message"] = entry["value"]
        elif name == "eap_message":
            entry["value"] = value.hex()[:160]
            out["eap_message"] = True
        elif name in ("nas_ip_address", "framed_ip") and len(value) == 4:
            entry["value"] = ipv4_text(value)
        elif name in ("nas_port", "service_type", "framed_protocol"):
            entry["value"] = int.from_bytes(value, "big")
        else:
            entry["value"] = value.hex()[:160]
        out["attributes"].append(entry)
        offset += attr_length
    return out


# --------------------------------------------------------------------------- #
# MS-CHAPv2: MD4, DES and RFC 2759
# --------------------------------------------------------------------------- #
#
# MS-CHAPv2 is the inner method of most PEAP and TTLS deployments, and its response
# is a pure function of the password: an NT hash (MD4) and three DES blocks.  Both
# primitives are implemented here — not because the standard library lacks them in
# spirit, but because it genuinely lacks them, and a cracker that shells out to a
# crypto library is a cracker that does not run on a stripped engagement laptop.
#
# DES is the Data Encryption Standard with the standard tables (FIPS 46-3); the
# implementation is bit-by-bit and slow on purpose — it is called a few thousand
# times by a verification, and the clarity is worth more than the cycles.

_IP = (58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
       62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
       57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
       61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7)
_FP = (40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
       38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
       36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
       34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25)
_E = (32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
      12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
      24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1)
_P = (16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
      2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25)
_PC1 = (57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4)
_PC2 = (14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32)
_SHIFTS = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)
_SBOX = (
    ((14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7),
     (0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8),
     (4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0),
     (15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13)),
    ((15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10),
     (3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5),
     (0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15),
     (13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9)),
    ((10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8),
     (13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1),
     (13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7),
     (1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12)),
    ((7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15),
     (13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9),
     (10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4),
     (3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14)),
    ((2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9),
     (14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6),
     (4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14),
     (11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3)),
    ((12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11),
     (10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8),
     (9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6),
     (4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13)),
    ((4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1),
     (13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6),
     (1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2),
     (6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12)),
    ((13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7),
     (1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2),
     (7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8),
     (2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11)))


def _bits(data: bytes) -> List[int]:
    return [(byte >> (7 - index)) & 1 for byte in data for index in range(8)]


def _from_bits(bits: Sequence[int]) -> bytes:
    out = bytearray()
    for offset in range(0, len(bits), 8):
        value = 0
        for bit in bits[offset:offset + 8]:
            value = (value << 1) | bit
        out.append(value)
    return bytes(out)


def _permute(bits: Sequence[int], table: Sequence[int]) -> List[int]:
    return [bits[index - 1] for index in table]


def _rotate(bits: List[int], count: int) -> List[int]:
    count %= len(bits)
    return bits[count:] + bits[:count]


def _expand_key7(key: bytes) -> bytes:
    """The 7-byte MS-CHAPv2 key as an 8-byte DES key (parity bits inserted)."""
    bits = _bits(key)[:56]
    out: List[int] = []
    for index in range(0, 56, 7):
        out.extend(bits[index:index + 7])
        out.append(0)                     # the parity bit DES will ignore
    return _from_bits(out)


def des_subkeys(key: bytes) -> List[List[int]]:
    """The sixteen 48-bit round keys of DES from a 7- or 8-byte key."""
    if len(key) == 7:
        raw = _bits(_expand_key7(key))
    else:
        raw = _bits(key[:8].ljust(8, b"\x00"))
    permuted = _permute(raw, _PC1)
    left, right = permuted[:28], permuted[28:]
    subkeys: List[List[int]] = []
    for shift in _SHIFTS:
        left, right = _rotate(left, shift), _rotate(right, shift)
        subkeys.append(_permute(left + right, _PC2))
    return subkeys


def _feistel(right: Sequence[int], subkey: Sequence[int]) -> List[int]:
    expanded = _permute(right, _E)
    mixed = [a ^ b for a, b in zip(expanded, subkey)]
    out: List[int] = []
    for box in range(8):
        chunk = mixed[box * 6:box * 6 + 6]
        row = (chunk[0] << 1) | chunk[5]
        column = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
        value = _SBOX[box][row][column]
        out.extend([(value >> shift) & 1 for shift in (3, 2, 1, 0)])
    return _permute(out, _P)


def _des_run(key: bytes, block: bytes, subkeys: Sequence[Sequence[int]]) -> bytes:
    bits = _permute(_bits(block[:8].ljust(8, b"\x00")), _IP)
    left, right = bits[:32], bits[32:]
    for subkey in subkeys:
        left, right = right, [a ^ b for a, b in zip(left, _feistel(right, subkey))]
    # the preoutput is R16||L16, which is what the final permutation selects from
    return _from_bits(_permute(right + left, _FP))


def des_encrypt_block(key: bytes, block: bytes) -> bytes:
    """One DES block.  ``key`` is 7 bytes of key material or a full 8-byte key.

    MS-CHAPv2 splits the 16-byte NT hash into three 7-byte keys, so the 7-byte form is
    the one the cracker needs; the 8-byte form is what the FIPS test vectors use.
    """
    return _des_run(key, block, des_subkeys(key))


def des_decrypt_block(key: bytes, block: bytes) -> bytes:
    """DES in the other direction: the round keys reversed."""
    return _des_run(key, block, list(reversed(des_subkeys(key))))


def md4(message: bytes) -> bytes:
    """MD4 (RFC 1320), the hash MS-CHAPv2 builds the NT hash out of.

    MD4 is broken as a collision-resistant hash, which is exactly why MS-CHAPv2 is
    crackable; it is implemented here because the standard library dropped it.
    """
    message = bytearray(message)
    original_bits = (8 * len(message)) & 0xFFFFFFFFFFFFFFFF
    message.append(0x80)
    while len(message) % 64 != 56:
        message.append(0)
    message += original_bits.to_bytes(8, "little")
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    mask = 0xFFFFFFFF

    def rol(value: int, count: int) -> int:
        return ((value << count) | (value >> (32 - count))) & mask

    for offset in range(0, len(message), 64):
        words = [int.from_bytes(message[offset + i * 4:offset + i * 4 + 4], "little")
                 for i in range(16)]
        aa, bb, cc, dd = a, b, c, d
        for index in range(16):                                  # round 1
            shift = (3, 7, 11, 19)[index % 4]
            aa = rol((aa + ((bb & cc) | (~bb & dd)) + words[index]) & mask, shift)
            aa, bb, cc, dd = dd, aa, bb, cc
        order = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
        for index in range(16):                                  # round 2
            shift = (3, 5, 9, 13)[index % 4]
            value = words[order[index]]
            aa = rol((aa + ((bb & cc) | (bb & dd) | (cc & dd)) + value + 0x5A827999)
                     & mask, shift)
            aa, bb, cc, dd = dd, aa, bb, cc
        order = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
        for index in range(16):                                  # round 3
            shift = (3, 9, 11, 15)[index % 4]
            value = words[order[index]]
            aa = rol((aa + (bb ^ cc ^ dd) + value + 0x6ED9EBA1) & mask, shift)
            aa, bb, cc, dd = dd, aa, bb, cc
        a = (a + aa) & mask
        b = (b + bb) & mask
        c = (c + cc) & mask
        d = (d + dd) & mask
    return a.to_bytes(4, "little") + b.to_bytes(4, "little") \
        + c.to_bytes(4, "little") + d.to_bytes(4, "little")


def nt_hash(password: str) -> bytes:
    """The NT hash: MD4 of the UTF-16LE password."""
    return md4(password.encode("utf-16-le"))


def mschapv2_challenge_hash(challenge: bytes, peer_challenge: bytes,
                            username: str) -> bytes:
    """RFC 2759: ``SHA1(PeerChallenge ‖ AuthenticatorChallenge ‖ UserName)[0:8]``.

    The peer challenge comes first and the user name is the bytes as sent (not the
    UTF-16LE form used for the NT hash) — the order the RFC's own vector at §9.2 pins
    down, and the one every implementation follows.
    """
    return hashlib.sha1(peer_challenge + challenge + username.encode("latin-1")
                        ).digest()[:8]


def mschapv2_response(password: str, challenge: bytes, peer_challenge: bytes,
                      username: str) -> bytes:
    """The 24-byte NT-Response: three DES blocks under the NT hash."""
    digest = mschapv2_challenge_hash(challenge, peer_challenge, username)
    # RFC 2759 §8.1: the 16-byte NT hash is zero-padded to 21 bytes, then split into
    # three 7-byte DES keys — the pad is part of the key material, not a formality
    padded = nt_hash(password) + b"\x00" * 5
    return b"".join(des_encrypt_block(padded[offset:offset + 7], digest)
                    for offset in (0, 7, 14))


def mschapv2_verify(password: str, challenge: bytes, peer_challenge: bytes,
                    username: str, response: bytes) -> bool:
    """True when ``password`` produces exactly the captured 24-byte response."""
    return mschapv2_response(password, challenge, peer_challenge, username) == response


def mschapv2_session_key(nt_hash_value: bytes, challenge: bytes,
                         response: bytes) -> Tuple[bytes, bytes]:
    """The MPPE master key and asymmetric start key (RFC 3079 §3).

    Returned rather than used: deriving them is what a PEAP relay would do next, and
    the report should say whether that is possible at all.
    """
    digest = hashlib.sha1(nt_hash_value + response).digest()
    master = hashlib.sha1(digest[:16] + mschapv2_challenge_hash(
        challenge, b"\x00" * 16, "")).digest()[:16]
    master = master + hashlib.sha1(digest[:16] + master).digest()[:8]
    return master, digest[:16]


# --------------------------------------------------------------------------- #
# cleartext credentials in captured traffic
# --------------------------------------------------------------------------- #

CREDENTIAL_PATTERNS = ("password", "passwd", "pwd", "pass", "secret", "pin", "token",
                       "apikey", "api_key", "credential", "user", "username", "login",
                       "email", "account")


def http_credentials(payload: bytes) -> List[Dict[str, str]]:
    """Credentials in an HTTP request: Basic auth, and login form fields."""
    out: List[Dict[str, str]] = []
    text = payload.decode("latin-1", "replace")
    for line in text.split("\r\n"):
        key, _, value = line.partition(":")
        if key.lower().strip() == "authorization" and value.strip().lower().startswith(
                "basic "):
            import base64

            try:
                decoded = base64.b64decode(value.strip()[6:].strip()).decode(
                    "utf-8", "replace")
            except Exception:                                   # pragma: no cover
                continue
            user, _, secret = decoded.partition(":")
            out.append({"kind": "http-basic", "user": user, "secret": secret,
                        "authorization": "Authorization: Basic"})
    body = text.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in text else ""
    if "=" in body and any(word in body.lower() for word in CREDENTIAL_PATTERNS):
        from urllib.parse import unquote_plus

        fields: Dict[str, str] = {}
        for pair in body.replace(";", "&").split("&"):
            key, _, value = pair.partition("=")
            if not key:
                continue
            fields[unquote_plus(key.strip())] = unquote_plus(value.strip())[:120]
        user = next((fields[key] for key in fields
                     if key.lower() in ("user", "username", "login", "email", "account",
                                        "userid", "user_name")), "")
        secret = next((fields[key] for key in fields
                       if key.lower() in ("password", "passwd", "pwd", "pass", "pin",
                                          "secret", "token")), "")
        if user or secret:
            out.append({"kind": "http-form", "user": user, "secret": secret,
                        "fields": ", ".join(sorted(fields)[:8])})
    return out


def ftp_credentials(payload: bytes) -> List[Dict[str, str]]:
    """FTP USER/PASS pairs: the protocol sends both in the clear by design."""
    out: List[Dict[str, str]] = []
    lines = payload.decode("latin-1", "replace").splitlines()
    user = ""
    for line in lines:
        upper = line.strip().upper()
        if upper.startswith("USER "):
            user = line.strip()[5:].strip()
        elif upper.startswith("PASS "):
            secret = line.strip()[5:].strip()
            if user or secret:
                out.append({"kind": "ftp", "user": user, "secret": secret})
            user = ""
    return out


def pop_imap_credentials(payload: bytes) -> List[Dict[str, str]]:
    """POP3/IMAP logins: ``USER``/``PASS`` and ``LOGIN``/``AUTHENTICATE``."""
    out: List[Dict[str, str]] = []
    lines = payload.decode("latin-1", "replace").splitlines()
    user = ""
    for line in lines:
        stripped = line.strip()
        upper = stripped.upper()
        if upper.startswith("USER "):
            user = stripped[5:].strip()
        elif upper.startswith("PASS ") or upper.startswith("PASS\t"):
            secret = stripped[5:].strip()
            if user or secret:
                out.append({"kind": "pop3", "user": user, "secret": secret})
            user = ""
        elif upper.startswith("LOGIN "):
            parts = stripped.split()
            if len(parts) >= 3:
                out.append({"kind": "imap", "user": parts[1], "secret": parts[2]})
        elif upper.startswith("AUTHENTICATE PLAIN"):
            out.append({"kind": "imap", "user": "", "secret": "",
                        "note": "AUTHENTICATE PLAIN offered"})
    return out


def cleartext_credentials(payload: bytes) -> List[Dict[str, str]]:
    """Anything credential-shaped in one captured payload."""
    return http_credentials(payload) + ftp_credentials(payload) \
        + pop_imap_credentials(payload)


__all__ = ["CREDENTIAL_PATTERNS", "DHCP_CLIENT_PORT", "DHCP_MESSAGE_TYPES",
           "DHCP_OPTIONS", "DHCP_SERVER_PORT", "DNS_RCODES", "DNS_TYPES",
           "RADIUS_ACCOUNTING_PORT", "RADIUS_ATTRIBUTES", "RADIUS_CODES",
           "RADIUS_DEFAULT_SECRETS", "RADIUS_LEGACY_PORT", "RADIUS_PORT", "RADIUS_PORTS",
           "SNMP_DEFAULT_COMMUNITIES", "SNMP_IDENTITY_OIDS", "SNMP_PORT", "SSDP_ADDRESS",
           "SSDP_PORT", "ssdp_notify", "bytes_to_mac", "checksum", "cleartext_credentials",
           "decode_name", "decode_oid", "dhcp_discover", "dhcp_offer", "dhcp_request",
           "dns_query", "dns_response", "encode_name", "encode_oid", "ftp_credentials",
           "html_inputs", "html_title", "http_credentials", "http_get",
           "ipv4_bytes", "ipv4_text", "ipv4_udp_packet", "mac_to_bytes", "parse_arp",
           "parse_dhcp", "parse_dns", "parse_ipv4", "parse_radius", "parse_snmp",
           "parse_ssdp", "parse_tcp", "pop_imap_credentials", "radius_access_request",
           "snmp_get_live",
           "des_decrypt_block", "des_encrypt_block", "des_subkeys", "md4",
           "mschapv2_challenge_hash", "mschapv2_response", "mschapv2_session_key",
           "mschapv2_verify", "nt_hash",
           "radius_password_decrypt", "radius_password_encrypt", "radius_response",
           "radius_verify_response", "snmp_get", "ssdp_msearch", "urlget"]

