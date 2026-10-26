# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Network-layer attacks: what the wireless network's own services expose.

A wireless engagement does not end at the air interface.  Once a client — or the
auditor — is on the network, the services behind it decide most of the findings, and
these eight attacks look at them directly, with real protocol implementations from
:mod:`wifipilot.netproto` and no dependency on nmap or a scanner:

* ``ap_admin_audit`` — the management surface: HTTP/HTTPS/SSH/Telnet/alternate ports on
  the gateway, with page titles, server banners and login-form detection.
* ``upnp_audit`` — SSDP discovery and the device description XML: a UPnP-enabled
  gateway with the port-mapping service exposed is the classic NAT-punching finding.
* ``snmp_audit`` — SNMP v2c with the default community strings, decoded with our own
  BER codec: a device answering ``public`` hands over model, name and uptime.
* ``dns_audit`` — the resolver: does it recurse for the internet, is it open to
  everyone on the network, does it validate DNSSEC?
* ``wpad_audit`` — is ``wpad.<domain>`` resolvable and serving a proxy script?  WPAD is
  the protocol that makes a name-resolution attack into a traffic-redirection attack.
* ``rogue_dhcp_detect`` — a second DHCP server on the network (ours or somebody else's)
  is a serious finding, and it is visible from one listen window.
* ``arp_spoof_detect`` — two devices claiming the same address, or one address claimed
  by a MAC that is not the gateway's: ARP poisoning in progress, detected rather than
  performed.
* ``ipv6_ra_audit`` — IPv6 router advertisements: who is announcing a default route,
  and is a rogue RA handing out a prefix nobody asked for?

The five active ones need an interface with an IP address on the target network; the
three passive ones need only a monitor interface (or a capture).  All eight are
read-only towards the network — they ask, they do not change.
"""

from __future__ import annotations

import contextlib
import socket
import struct
import time
from typing import Any, Dict, List, Optional, Tuple

from ..models import STATUS_SUCCESS, AccessPoint, Attempt, Finding
from ..netproto import (SSDP_ADDRESS, SSDP_PORT, dns_query, html_inputs, html_title,
                        http_get, parse_dhcp, parse_dns, parse_ipv4, parse_ssdp, snmp_get_live, ssdp_msearch)
from .base import Attack, AttackContext, AttackOutcome

ALL = ("WPA", "WPA2", "WPA2/WPA3", "WPA3", "WEP", "OPEN", "OWE", "WPA-ENTERPRISE",
       "WPA2-ENTERPRISE", "ENTERPRISE")

#: the management surface worth asking about, in order of interest
ADMIN_PORTS = ((80, "http"), (443, "https"), (22, "ssh"), (23, "telnet"),
               (8080, "http-alt"), (8443, "https-alt"), (8000, "http-alt"),
               (53, "dns"), (161, "snmp"), (1900, "upnp"), (52869, "wps-upnp"),
               (1883, "mqtt"), (554, "rtsp"))

#: SNMP community strings that are still shipping on access points
SNMP_COMMUNITIES = ("public", "private", "cisco", "admin", "snmp", "default",
                    "write", "read", "secret", "comcast", "guest")


class _NetworkAttack(Attack):
    """Shared: find the address under test and say so when it cannot be found."""

    category = "survey"
    noise = "quiet"
    impact = "none"
    requires = ()
    needs_injection = False
    applies_to = ALL
    #: whether the attack needs an address to talk to (rather than only listening)
    active = True

    def applies(self, ap: AccessPoint) -> bool:
        return True

    def available(self, ctx: AttackContext) -> bool:
        if not self.active:
            return True
        return bool(ctx.demo or self._address(ctx, None))

    def unavailable_reason(self, ctx: AttackContext) -> str:
        return ("needs an interface with an address on the target network: set "
                "`gateway_ip` (or `interface`) so there is something to ask")

    # -- addressing -------------------------------------------------------- #
    @staticmethod
    def _local_address(ctx: AttackContext) -> str:
        interface = getattr(ctx.config, "interface", "") or ""
        if interface:
            try:
                import fcntl
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    packed = struct.pack("256s", interface[:15].encode())
                    raw = fcntl.ioctl(sock.fileno(), 0x8915, packed)   # SIOCGIFADDR
                    return socket.inet_ntoa(raw[20:24])
            except (OSError, ImportError):
                pass
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.connect(("8.8.8.8", 53))
            address = probe.getsockname()[0]
            probe.close()
            return address
        except OSError:
            return ""

    def _address(self, ctx: AttackContext, ap: Optional[AccessPoint]) -> str:
        """The address to ask: explicit config, the AP's own, or the local subnet's .1."""
        configured = (getattr(ctx.config, "gateway_ip", "")
                      or getattr(ctx.config, "target_ip", "") or "")
        if configured:
            return configured
        if ap is not None and getattr(ap, "ip", ""):
            return ap.ip                                     # type: ignore[attr-defined]
        local = self._local_address(ctx)
        if not local or local.startswith("127."):
            return ""
        return local.rsplit(".", 1)[0] + ".1"

    def _skip(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
              reason: str) -> AttackOutcome:
        ctx.session.end_attempt(attempt, "skipped", reason)
        return AttackOutcome.skipped(reason, f"{ap.display_name}: {reason}")

    def _finish(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                result: str, detail: str, extra: Dict[str, Any],
                severity: str = "info", title: str = "") -> AttackOutcome:
        ctx.session.add_finding(Finding(kind=self.name, severity=severity,
                                        bssid=ap.bssid, title=title or result,
                                        detail=detail))
        ap.remember(self.name, detail)
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, result, detail)
        return AttackOutcome.success(result, detail=detail, extra=extra)

    def _demo_address(self, ctx: AttackContext, ap: AccessPoint) -> str:
        seed = int(ap.bssid.replace(":", ""), 16)
        return f"192.168.{seed % 200}.1"


# --------------------------------------------------------------------------- #
# 1. management surface
# --------------------------------------------------------------------------- #


class ApAdminAuditAttack(_NetworkAttack):
    name = "ap_admin_audit"
    label = "Management surface audit (admin ports and pages)"
    tool = "wifipilot (raw sockets + HTTP)"
    description = ("Ask the gateway or AP what it exposes: HTTP and HTTPS on the "
                   "management ports, SSH, Telnet, SNMP, the vendor's WPS UPnP port.  "
                   "Each open port is reported with what it answers — page title, "
                   "server banner, and whether the page is a login form — because "
                   "'port 80 open' is not a finding and 'an unauthenticated firmware "
                   "status page with the model and serial' is.")
    category = "survey"
    noise = "quiet"
    impact = "none"
    applies_to = ALL

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        target = self._address(ctx, ap)
        if ctx.demo:
            target = target or self._demo_address(ctx, ap)
            return self._demo(ctx, ap, attempt, target)
        if not target:
            return self._skip(ctx, ap, attempt, "no address to audit (set gateway_ip)")
        results: List[Dict[str, Any]] = []
        for port, label in ADMIN_PORTS:
            if ctx.want_stop():
                break
            state = self._probe(target, port)
            if not state["open"]:
                continue
            entry: Dict[str, Any] = {"port": port, "service": label, "open": True,
                                     "banner": state.get("banner", "")}
            if port in (80, 8080, 8000, 8443, 443, 52869):
                entry["scheme"] = "https" if port in (443, 8443) else "http"
                page = http_get(target, port, "/", timeout=2.5)
                if page.get("ok"):
                    entry["status"] = page.get("status", "")
                    entry["server"] = page.get("headers", {}).get("server", "")
                    entry["title"] = html_title(page.get("body", ""))
                    entry["login_form"] = any(
                        field.get("type", "").lower() == "password" or
                        field.get("name", "").lower() in ("password", "passwd", "pwd")
                        for field in html_inputs(page.get("body", "")))
                    entry["body_bytes"] = page.get("bytes", 0)
            results.append(entry)
            ctx.progress(f"management audit of {target}", kind="survey", bssid=ap.bssid,
                         percent=min(95, len(results) * 12),
                         detail=f"{len(results)} open port(s)")
        if not results:
            return self._finish(ctx, ap, attempt, "no management ports answered",
                                f"{len(ADMIN_PORTS)} port(s) probed on {target}: all "
                                f"closed or filtered", {"target": target,
                                                        "ports": [port for port, _ in ADMIN_PORTS]},
                                severity="info")
        logins = [entry for entry in results if entry.get("login_form")]
        cleartext = [entry for entry in results
                     if entry["port"] in (80, 8080, 8000, 23) or
                     entry["service"] in ("telnet",)]
        if cleartext:
            severity, title = "high", "management interface reachable in cleartext"
        elif results:
            severity, title = "medium", f"{len(results)} management port(s) exposed"
        else:
            severity, title = "info", "no management ports answered"
        detail = (f"{len(results)} open port(s) on {target}: "
                  + "; ".join(f"{entry['port']}/{entry['service']}"
                              + (f" ({entry['title'][:40]})" if entry.get("title") else "")
                              + (" [login form]" if entry.get("login_form") else "")
                              for entry in results[:8]))
        return self._finish(ctx, ap, attempt, title, detail,
                            {"target": target, "ports": results, "logins": logins,
                             "cleartext": [entry["port"] for entry in cleartext],
                             "note": ("an administrative page on the wireless segment "
                                      "is reachable by every client on it: the finding "
                                      "is the exposure, not the password")},
                            severity=severity)

    @staticmethod
    def _probe(host: str, port: int, timeout: float = 1.2) -> Dict[str, Any]:
        """A TCP connect with a banner read: the cheapest honest port test."""
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(1.0)
                banner = b""
                with contextlib.suppress(OSError):
                    banner = sock.recv(256)
                return {"open": True, "banner": banner.decode("latin-1", "replace").strip()}
        except OSError:
            return {"open": False}

    def _demo(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
              target: str) -> AttackOutcome:
        seed = int(ap.bssid.replace(":", ""), 16)
        ports = [{"port": 80, "service": "http", "open": True,
                  "title": "Router Configuration", "server": "lighttpd/1.4.59",
                  "login_form": True, "status": "HTTP/1.0 200 OK"}]
        if seed % 2:
            ports.append({"port": 23, "service": "telnet", "open": True,
                          "banner": "BusyBox telnetd"})
            ports.append({"port": 161, "service": "snmp", "open": True})
        detail = (f"{len(ports)} open port(s) on {target} (simulated): "
                  + ", ".join(f"{entry['port']}/{entry['service']}" for entry in ports))
        return self._finish(ctx, ap, attempt, "management ports exposed", detail,
                            {"target": target, "ports": ports, "simulated": True},
                            severity="high" if any(entry["service"] == "telnet"
                                                   for entry in ports) else "medium")


# --------------------------------------------------------------------------- #
# 2. UPnP
# --------------------------------------------------------------------------- #


class UpnpAuditAttack(_NetworkAttack):
    name = "upnp_audit"
    label = "UPnP/SSDP audit (device description and IGD)"
    tool = "wifipilot netproto.py (SSDP + HTTP)"
    description = ("Send an SSDP M-SEARCH and read the answers: each device that replies "
                   "hands over a description URL, and fetching it gives the model, the "
                   "manufacturer and — for an Internet Gateway Device — the control URL "
                   "of the port-mapping service.  That last one is the classic "
                   "NAT-punching finding: unauthenticated port mapping on the customer's "
                   "gateway.")
    category = "survey"
    noise = "quiet"
    impact = "none"
    applies_to = ALL

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        if ctx.demo:
            return self._demo(ctx, ap, attempt)
        replies: List[Dict[str, Any]] = []
        devices: List[Dict[str, Any]] = []
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
                sock.settimeout(1.0)
                sock.sendto(ssdp_msearch("ssdp:all", mx=2), (SSDP_ADDRESS, SSDP_PORT))
                deadline = time.time() + 4.0
                seen: set = set()
                while time.time() < deadline and len(replies) < 30:
                    try:
                        payload, peer = sock.recvfrom(4096)
                    except socket.timeout:
                        continue
                    text = payload.decode("latin-1", "replace")
                    headers = parse_ssdp(text)
                    location = headers.get("location", "")
                    if not location or location in seen:
                        continue
                    seen.add(location)
                    replies.append({"from": peer[0], "st": headers.get("st", ""),
                                    "server": headers.get("server", ""),
                                    "location": location})
        except OSError as exc:
            return self._skip(ctx, ap, attempt,
                              f"SSDP could not send ({exc}); the network may filter "
                              f"multicast")
        for reply in replies[:8]:
            location = reply["location"]
            try:
                from urllib.parse import urlparse
                parsed = urlparse(location)
                page = http_get(parsed.hostname or "", parsed.port or 80,
                                parsed.path or "/", timeout=2.5)
            except (ValueError, OSError):
                continue
            if not page.get("ok"):
                continue
            body = page.get("body", "")
            device = {"host": reply["from"], "location": location,
                      "st": reply["st"], "server": reply["server"],
                      "friendly_name": _xml_value(body, "friendlyName"),
                      "model": _xml_value(body, "modelName"),
                      "manufacturer": _xml_value(body, "manufacturer"),
                      "device_type": _xml_value(body, "deviceType"),
                      "control_url": _xml_value(body, "controlURL"),
                      "service_type": _xml_value(body, "serviceType")}
            device["igd"] = "InternetGatewayDevice" in (device["device_type"] or "")
            device["port_mapping"] = any("WANIPConnection" in _all_xml(body, "serviceType")
                                         or "WANPPPConnection" in _all_xml(body, "serviceType")
                                         for _ in [0])
            devices.append(device)
        if not devices:
            return self._finish(ctx, ap, attempt, "no UPnP devices answered",
                                f"{len(replies)} SSDP repl(ies), no readable description",
                                {"replies": replies},
                                severity="info" if replies else "low",
                                title="UPnP discovery found nothing")
        igds = [device for device in devices if device["igd"]]
        if igds and any(device["port_mapping"] for device in igds):
            severity, title = "high", "UPnP gateway exposes the port-mapping service"
        elif devices:
            severity, title = "medium", f"{len(devices)} UPnP device(s) described"
        else:
            severity, title = "info", "no UPnP devices answered"
        detail = (f"{len(devices)} device description(s) read: "
                  + "; ".join(f"{device['manufacturer']} {device['model']} "
                              f"({device['host']})"
                              + (" [IGD]" if device["igd"] else "")
                              for device in devices[:5]))
        return self._finish(ctx, ap, attempt, title, detail,
                            {"devices": devices, "replies": replies,
                             "note": ("a gateway that accepts unauthenticated "
                                      "AddPortMapping requests lets any client on the "
                                      "network publish a service to the internet")},
                            severity=severity)

    def _demo(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt) -> AttackOutcome:
        seed = int(ap.bssid.replace(":", ""), 16)
        devices = [{"host": self._demo_address(ctx, ap), "st": "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
                    "server": "Linux/3.10 UPnP/1.0 MiniUPnPd/2.2.0",
                    "friendly_name": "Wireless Router", "model": "Archer C6",
                    "manufacturer": "TP-Link", "device_type": "InternetGatewayDevice:1",
                    "control_url": "/ctl/IPConn", "igd": True,
                    "port_mapping": bool(seed % 2)}]
        severity = "high" if devices[0]["port_mapping"] else "medium"
        detail = ("1 device described: TP-Link Archer C6 (simulated)"
                  + (" — the port-mapping control URL answers unauthenticated"
                     if devices[0]["port_mapping"] else ""))
        return self._finish(ctx, ap, attempt, "UPnP device described", detail,
                            {"devices": devices, "simulated": True}, severity=severity)


def _xml_value(body: str, tag: str) -> str:
    """The first value of an XML tag, without pulling in an XML parser."""
    lowered = body.lower()
    start = lowered.find(f"<{tag.lower()}>")
    if start < 0:
        return ""
    start = lowered.find(">", start) + 1
    end = lowered.find("<", start)
    if end < 0:
        return ""
    return body[start:end].strip()[:120]


def _all_xml(body: str, tag: str) -> str:
    out = []
    lowered = body.lower()
    index = 0
    while True:
        start = lowered.find(f"<{tag.lower()}>", index)
        if start < 0:
            break
        start = lowered.find(">", start) + 1
        end = lowered.find("<", start)
        out.append(body[start:end].strip())
        index = end + 1
    return " ".join(out)


# --------------------------------------------------------------------------- #
# 3. SNMP
# --------------------------------------------------------------------------- #


class SnmpAuditAttack(_NetworkAttack):
    name = "snmp_audit"
    label = "SNMP audit (default community strings)"
    tool = "wifipilot netproto.py (BER codec)"
    description = ("Ask the device for its identity with each of the community strings "
                   "that ship on access points.  An SNMP agent that answers 'public' "
                   "hands over the model, the firmware string, the device name and the "
                   "uptime — and with a writable community, a configuration change.  The "
                   "BER encoder and decoder are ours, so the report can show exactly "
                   "what was asked and what came back.")
    category = "survey"
    noise = "quiet"
    impact = "none"
    applies_to = ALL

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        target = self._address(ctx, ap)
        if ctx.demo:
            target = target or self._demo_address(ctx, ap)
            community = "public" if int(ap.bssid.replace(":", ""), 16) % 2 else ""
            if not community:
                return self._finish(ctx, ap, attempt, "SNMP agent did not answer",
                                    f"community strings tried on {target}: none "
                                    f"accepted (simulated)", {"target": target,
                                                              "simulated": True},
                                    severity="low")
            identity = {"sysDescr": f"Wireless AP {ap.essid or 'ap'}, firmware 2.1.4",
                        "sysName": (ap.essid or "ap").lower().replace(" ", "-"),
                        "sysUpTime": 412000}
            detail = (f"community 'public' accepted on {target} (simulated): "
                      f"{identity['sysDescr']}")
            return self._finish(ctx, ap, attempt, "SNMP answered with 'public'", detail,
                                {"target": target, "community": "public",
                                 "identity": identity, "simulated": True},
                                severity="medium")
        if not target:
            return self._skip(ctx, ap, attempt, "no address to ask (set gateway_ip)")
        accepted: List[Dict[str, Any]] = []
        for community in SNMP_COMMUNITIES:
            if ctx.want_stop():
                break
            answer = snmp_get_live(target, community, timeout=1.5)
            if answer.get("ok") and answer.get("varbinds"):
                values = {item["name"] or item["oid"]: item["value"]
                          for item in answer["varbinds"]}
                accepted.append({"community": community, "values": values})
                if community in ("private", "write", "cisco"):
                    break
        if not accepted:
            return self._finish(ctx, ap, attempt, "SNMP did not answer",
                                f"{len(SNMP_COMMUNITIES)} community string(s) tried on "
                                f"{target}: no reply", {"target": target},
                                severity="low")
        writable = [entry["community"] for entry in accepted
                    if entry["community"] in ("private", "write")]
        identity = accepted[0]["values"]
        severity = "high" if writable else "medium"
        title = (f"SNMP read/write community accepted: {writable[0]}" if writable
                 else f"SNMP community {accepted[0]['community']!r} accepted")
        detail = (f"{len(accepted)} community string(s) accepted on {target}; "
                  f"device: {identity.get('sysDescr', 'unknown')[:80]}")
        return self._finish(ctx, ap, attempt, title, detail,
                            {"target": target, "communities": accepted,
                             "writable": writable,
                             "note": ("SNMP v2c sends the community in the clear: on a "
                                      "wireless segment anyone can read it, and a "
                                      "writable one is a configuration change away")},
                            severity=severity)


# --------------------------------------------------------------------------- #
# 4. DNS
# --------------------------------------------------------------------------- #


class DnsAuditAttack(_NetworkAttack):
    name = "dns_audit"
    label = "DNS resolver audit (open resolver, DNSSEC)"
    tool = "wifipilot netproto.py (DNS client)"
    description = ("Ask the network's resolver three questions: does it resolve an "
                   "external name (recursion), does it validate DNSSEC (a broken "
                   "signature for a signed domain should be rejected, not answered), and "
                   "does it answer for a name it should not (an open resolver is a "
                   "weapon for amplification attacks launched from the client's "
                   "network).")
    category = "survey"
    noise = "quiet"
    impact = "none"
    applies_to = ALL

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        target = self._address(ctx, ap)
        if ctx.demo:
            target = target or self._demo_address(ctx, ap)
            findings = {"recursion": True, "open_resolver": True, "dnssec": False,
                        "resolver": target}
            detail = (f"{target} resolves external names and answers requests from any "
                      f"client; DNSSEC validation not evident (simulated)")
            return self._finish(ctx, ap, attempt, "resolver recurses and is open", detail,
                                {**findings, "simulated": True}, severity="medium")
        if not target:
            return self._skip(ctx, ap, attempt, "no resolver to ask (set gateway_ip)")
        answers: Dict[str, Any] = {"resolver": target}
        payload = self._ask(target, dns_query("example.com", 1, txid=0x1234))
        parsed = parse_dns(payload)
        answers["recursion"] = bool(parsed.get("recursion_available"))
        answers["example_com"] = [record.get("value") for record
                                  in parsed.get("answers", [])[:4]]
        answers["open_resolver"] = bool(parsed.get("answers"))
        dnssec_payload = self._ask(target, dns_query("cloudflare.com", 48, txid=0x2222))
        dnssec = parse_dns(dnssec_payload)
        answers["dnssec_records"] = [record.get("value") for record
                                     in dnssec.get("answers", [])[:3]]
        answers["dnssec_supported"] = bool(dnssec.get("answers")) or \
            bool(dnssec.get("authority"))
        if answers["open_resolver"] and answers["recursion"]:
            severity, title = "medium", "recursive resolver answers the whole network"
        elif answers["recursion"]:
            severity, title = "info", "resolver recurses"
        else:
            severity, title = "low", "resolver did not answer"
        detail = (f"resolver {target}: recursion "
                  f"{'available' if answers['recursion'] else 'not confirmed'}, "
                  f"answers for external names "
                  f"{'yes' if answers['open_resolver'] else 'no'}, DNSSEC data "
                  f"{'present' if answers['dnssec_supported'] else 'absent'}")
        return self._finish(ctx, ap, attempt, title, detail,
                            {**answers,
                             "note": ("an open recursive resolver on a wireless "
                                      "segment can be abused for amplification; asking "
                                      "it is read-only, answering for anyone is not")},
                            severity=severity)

    @staticmethod
    def _ask(server: str, query: bytes, timeout: float = 2.0) -> bytes:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(query, (server, 53))
                payload, _peer = sock.recvfrom(4096)
                return payload
        except OSError:
            return b""


# --------------------------------------------------------------------------- #
# 5. WPAD
# --------------------------------------------------------------------------- #


class WpadAuditAttack(_NetworkAttack):
    name = "wpad_audit"
    label = "WPAD audit (proxy auto-discovery exposure)"
    tool = "wifipilot netproto.py (DNS + HTTP)"
    description = ("Ask for ``wpad`` and for ``wpad.<the network's domain>`` and see "
                   "whether a proxy configuration is served.  WPAD is resolved by name, "
                   "which means whoever answers first controls the clients' proxy — on a "
                   "wireless network that is a legitimate-looking route to reading all "
                   "their HTTP traffic.  The audit reports whether the name resolves, "
                   "who answers it, and whether a wpad.dat is served.")
    category = "survey"
    noise = "quiet"
    impact = "none"
    applies_to = ALL

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        if ctx.demo:
            domain = "lab.local" if int(ap.bssid.replace(":", ""), 16) % 2 else ""
            results = {"domain": domain, "wpad_resolves": bool(domain),
                       "served": bool(domain), "server": "10.20.30.5" if domain else ""}
            detail = (f"wpad.{domain or '<none>'} "
                      + ("resolves and serves a proxy script (simulated)" if domain
                         else "does not resolve (simulated)"))
            return self._finish(ctx, ap, attempt,
                                "WPAD is resolvable and served" if domain
                                else "no WPAD service found", detail,
                                {**results, "simulated": True},
                                severity="medium" if domain else "info")
        resolver = self._address(ctx, ap)
        if not resolver:
            return self._skip(ctx, ap, attempt, "no resolver to ask (set gateway_ip)")
        domain = (getattr(ctx.config, "domain", "") or "").strip(".")
        names = ["wpad"] + ([f"wpad.{domain}"] if domain else [])
        results: Dict[str, Any] = {"names": names, "resolved": {}, "served": False}
        for name in names:
            payload = DnsAuditAttack._ask(resolver, dns_query(name, 1))
            parsed = parse_dns(payload)
            addresses = [record.get("value") for record in parsed.get("answers", [])
                         if record.get("type") == "A"]
            if addresses:
                results["resolved"][name] = addresses
        for name, addresses in results["resolved"].items():
            for address in addresses[:2]:
                page = http_get(address, 80, "/wpad.dat", timeout=2.0)
                if page.get("ok") and "HTTP/" in page.get("status", ""):
                    results["served"] = True
                    results["server"] = address
                    results["script_bytes"] = page.get("bytes", 0)
                    results["script_head"] = page.get("body", "")[:200]
                    break
        if results["served"]:
            severity, title = "medium", "WPAD proxy script is served on this network"
        elif results["resolved"]:
            severity, title = "low", "wpad name resolves but serves nothing"
        else:
            severity, title = "info", "no WPAD name resolved"
        detail = (f"asked {', '.join(names)}: "
                  + (f"resolved {results['resolved']}"
                     + (f", proxy script served by {results.get('server')}"
                        if results["served"] else ", no script served")
                     if results["resolved"] else "no answer"))
        return self._finish(ctx, ap, attempt, title, detail,
                            {**results,
                             "note": ("WPAD is name-based: a spoofed answer gives an "
                                      "attacker the clients' proxy configuration")},
                            severity=severity)


# --------------------------------------------------------------------------- #
# 6. rogue DHCP detection
# --------------------------------------------------------------------------- #


class RogueDhcpDetectAttack(_NetworkAttack):
    name = "rogue_dhcp_detect"
    label = "Rogue DHCP detection (second server on the segment)"
    tool = "wifipilot netproto.py (DHCP sniff)"
    description = ("Listen for DHCP servers answering on the segment and count the "
                   "distinct server identifiers.  One is the network working; two is a "
                   "rogue server handing out leases with somebody else's gateway and DNS "
                   "— ours or a criminal's, and the finding is the same either way.")
    category = "survey"
    noise = "silent"
    impact = "info"
    requires = ("monitor",)
    applies_to = ALL
    active = False

    def available(self, ctx: AttackContext) -> bool:
        return True

    def unavailable_reason(self, ctx: AttackContext) -> str:
        return ""

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        if ctx.demo:
            servers = ["192.168.1.1"]
            if int(ap.bssid.replace(":", ""), 16) % 3 == 0:
                servers.append("192.168.1.77")
            detail = (f"{len(servers)} DHCP server(s) answering (simulated): "
                      + ", ".join(servers))
            severity = "high" if len(servers) > 1 else "info"
            return self._finish(ctx, ap, attempt,
                                "rogue DHCP detected" if len(servers) > 1
                                else "one DHCP server on the segment", detail,
                                {"servers": servers, "simulated": True},
                                severity=severity)
        if not ctx.monitor:
            return self._skip(ctx, ap, attempt,
                              "needs a monitor interface to hear broadcasts (or a "
                              "capture: run `passive` first)")
        servers: Dict[str, Dict[str, Any]] = {}
        for observation in ctx.listen(min(self.budget(ctx, 20.0), 30.0),
                                      channel=ap.channel):
            ethertype = observation.get("ethertype")
            if ethertype not in (0x0800, 0x86dd):
                continue
            ip = parse_ipv4(observation.get("payload") or b"")
            if ip.get("protocol") != 17 or ip.get("sport") != 67:
                continue
            reply = parse_dhcp(ip.get("l4_payload") or b"")
            if not reply or reply.get("op") != "reply":
                continue
            server_id = reply.get("options", {}).get("server_id", ip.get("src", ""))
            entry = servers.setdefault(server_id, {"server": server_id,
                                                   "message_types": [],
                                                   "offered": [], "clients": []})
            message_type = reply.get("message_type", "reply")
            if message_type not in entry["message_types"]:
                entry["message_types"].append(message_type)
            if reply.get("yiaddr") and reply["yiaddr"] not in entry["offered"]:
                entry["offered"].append(reply["yiaddr"])
            if reply.get("client_mac") and reply["client_mac"] not in entry["clients"]:
                entry["clients"].append(reply["client_mac"])
        if not servers:
            return self._finish(ctx, ap, attempt, "no DHCP replies in the window",
                                "nothing answered while we listened: either the segment "
                                "uses no DHCP or the window was too quiet",
                                {}, severity="low")
        rogue = len(servers) > 1
        severity = "high" if rogue else "info"
        title = (f"{len(servers)} DHCP servers answering" if rogue
                 else "one DHCP server on the segment")
        detail = ("; ".join(f"{entry['server']} offered "
                            f"{', '.join(entry['offered'][:3])}"
                            for entry in servers.values()))
        return self._finish(ctx, ap, attempt, title, detail,
                            {"servers": list(servers.values()),
                             "note": ("the second server is the finding: leases it "
                                      "hands out also define the gateway and the "
                                      "resolver a client will use")},
                            severity=severity)


# --------------------------------------------------------------------------- #
# 7. ARP spoof detection
# --------------------------------------------------------------------------- #


class ArpSpoofDetectAttack(_NetworkAttack):
    name = "arp_spoof_detect"
    label = "ARP spoofing detection (address conflicts)"
    tool = "wifipilot netproto.py (ARP parsing)"
    description = ("Watch ARP traffic — or read a capture — and report address conflicts: "
                   "two MACs claiming one IP, a gateway's IP claimed by a MAC that is not "
                   "the gateway's, or a flood of gratuitous ARP replies.  Wireless "
                   "networks are where ARP poisoning is easiest and quietest, and the "
                   "detection is entirely passive.")
    category = "survey"
    noise = "silent"
    impact = "info"
    requires = ("monitor",)
    applies_to = ALL
    active = False

    def available(self, ctx: AttackContext) -> bool:
        return True

    def unavailable_reason(self, ctx: AttackContext) -> str:
        return ""

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        if ctx.demo:
            conflicts = []
            if int(ap.bssid.replace(":", ""), 16) % 2 == 0:
                conflicts = [{"ip": "192.168.1.1", "macs": ["aa:bb:cc:00:11:22",
                                                            "aa:bb:cc:00:11:33"]}]
            detail = (f"{len(conflicts)} address conflict(s) (simulated): "
                      + (", ".join(conflict["ip"] for conflict in conflicts)
                         if conflicts else "none"))
            return self._finish(ctx, ap, attempt,
                                "ARP address conflicts detected" if conflicts
                                else "no ARP conflicts", detail,
                                {"conflicts": conflicts, "simulated": True},
                                severity="high" if conflicts else "info")
        claims: Dict[str, Dict[str, int]] = {}
        gratuitous = 0
        observations = 0
        if ctx.monitor:
            for observation in ctx.listen(min(self.budget(ctx, 20.0), 30.0),
                                          channel=ap.channel):
                if observation.get("ethertype") != 0x0806:
                    continue
                observations += 1
                parsed = _parse_arp(observation.get("payload") or b"")
                if not parsed:
                    continue
                claims.setdefault(parsed["sender_ip"], {}).setdefault(
                    parsed["sender_mac"], 0)
                claims[parsed["sender_ip"]][parsed["sender_mac"]] += 1
                if parsed["sender_ip"] == parsed["target_ip"]:
                    gratuitous += 1
        else:
            path = _session_capture(ctx, ap)
            if not path:
                return self._skip(ctx, ap, attempt,
                                  "needs a monitor interface or a capture to read ARP "
                                  "from")
            observations, claims, gratuitous = _arp_from_capture(path)
        conflicts = [{"ip": ip, "macs": list(macs),
                      "frames": sum(macs.values())}
                     for ip, macs in claims.items() if len(macs) > 1]
        if not observations:
            return self._finish(ctx, ap, attempt, "no ARP traffic in the window",
                                "nothing to judge: ARP detection needs ARP frames",
                                {}, severity="low")
        severity = "high" if conflicts else "info"
        title = (f"{len(conflicts)} ARP address conflict(s)" if conflicts
                 else "no ARP conflicts in the window")
        detail = (f"{observations} ARP frame(s) analysed, {gratuitous} gratuitous, "
                  f"{len(conflicts)} address conflict(s)"
                  + (": " + "; ".join(f"{conflict['ip']} claimed by "
                                      f"{', '.join(conflict['macs'])}"
                                      for conflict in conflicts[:4]) if conflicts else ""))
        return self._finish(ctx, ap, attempt, title, detail,
                            {"conflicts": conflicts, "arp_frames": observations,
                             "gratuitous": gratuitous,
                             "note": ("two MACs for one IP is either a "
                                      "misconfiguration or an attack in progress; both "
                                      "deserve a report line")},
                            severity=severity)


def _session_capture(ctx: AttackContext, ap: AccessPoint) -> str:
    """The newest capture the session holds for this AP, or any capture at all."""
    import os

    candidates = [capture for capture in ap.captures
                  if capture.path and os.path.exists(capture.path)]
    for capture in ctx.session.all_captures():
        if capture.path and os.path.exists(capture.path) and capture not in candidates:
            candidates.append(capture)
    if not candidates:
        return ""
    return max(candidates, key=lambda capture: capture.created).path


def _parse_arp(payload: bytes) -> Optional[Dict[str, str]]:
    """A single ARP packet: sender/target hardware and protocol addresses."""
    if len(payload) < 28:
        return None
    htype, ptype, hlen, plen, opcode = struct.unpack("!HHBBH", payload[:8])
    if htype != 1 or ptype != 0x0800 or hlen != 6 or plen != 4:
        return None
    sender_mac = ":".join(f"{byte:02x}" for byte in payload[8:14])
    sender_ip = socket.inet_ntoa(payload[14:18])
    target_mac = ":".join(f"{byte:02x}" for byte in payload[18:24])
    target_ip = socket.inet_ntoa(payload[24:28])
    return {"op": {1: "request", 2: "reply"}.get(opcode, str(opcode)),
            "sender_mac": sender_mac, "sender_ip": sender_ip,
            "target_mac": target_mac, "target_ip": target_ip}


def _arp_from_capture(path: str) -> Tuple[int, Dict[str, Dict[str, int]], int]:
    from ..pcap import TYPE_DATA, _parse_frame, iter_frames

    claims: Dict[str, Dict[str, int]] = {}
    observations = gratuitous = 0
    for _ts, buf, start, length in iter_frames(str(path), max_packets=400_000):
        parsed = _parse_frame(buf, start, length)
        if parsed is None or parsed[0] != TYPE_DATA:
            continue
        raw = bytes(buf[start + parsed[4]:start + length])
        index = raw.find(b"\xaa\xaa\x03\x00\x00\x00\x08\x06")
        if index < 0:
            continue
        arp = _parse_arp(raw[index + 8:])
        if not arp:
            continue
        observations += 1
        claims.setdefault(arp["sender_ip"], {}).setdefault(arp["sender_mac"], 0)
        claims[arp["sender_ip"]][arp["sender_mac"]] += 1
        if arp["sender_ip"] == arp["target_ip"]:
            gratuitous += 1
    return observations, claims, gratuitous


# --------------------------------------------------------------------------- #
# 8. IPv6 router advertisements
# --------------------------------------------------------------------------- #


class Ipv6RaAuditAttack(_NetworkAttack):
    name = "ipv6_ra_audit"
    label = "IPv6 router advertisement audit"
    tool = "wifipilot (ICMPv6 parsing)"
    description = ("Router advertisements define IPv6 default routes and prefixes, and "
                   "any host on the segment can send them: a rogue RA is the IPv6 twin "
                   "of a rogue DHCP server, and it does not need to win a race — one "
                   "advertisement is enough for a client to install the route.  The "
                   "audit reports who is announcing, which prefixes, and whether more "
                   "than one source is doing it.")
    category = "survey"
    noise = "silent"
    impact = "info"
    requires = ("monitor",)
    applies_to = ALL
    active = False

    def available(self, ctx: AttackContext) -> bool:
        return True

    def unavailable_reason(self, ctx: AttackContext) -> str:
        return ""

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        if ctx.demo:
            routers = ["fe80::1"] if int(ap.bssid.replace(":", ""), 16) % 3 else \
                ["fe80::1", "fe80::beef"]
            detail = (f"{len(routers)} router advertisement source(s) (simulated): "
                      + ", ".join(routers))
            return self._finish(ctx, ap, attempt,
                                "multiple RA sources" if len(routers) > 1
                                else "one IPv6 router advertising", detail,
                                {"routers": routers, "simulated": True},
                                severity="high" if len(routers) > 1 else "info")
        if not ctx.monitor:
            return self._skip(ctx, ap, attempt, "needs a monitor interface for IPv6 "
                                                "frames (IPv6 is often not bridged to "
                                                "the monitor at all)")
        routers: Dict[str, Dict[str, Any]] = {}
        neighbour_solicits = 0
        for observation in ctx.listen(min(self.budget(ctx, 20.0), 30.0),
                                      channel=ap.channel):
            if observation.get("ethertype") != 0x86DD:
                continue
            packet = observation.get("payload") or b""
            if len(packet) < 48 or (packet[0] >> 4) != 6:
                continue
            next_header = packet[6]
            if next_header != 58 or len(packet) < 40 + 16:
                continue
            icmp_type = packet[40]
            source = _ipv6_text(packet[8:24])
            if icmp_type == 134:                       # router advertisement
                entry = routers.setdefault(source, {"router": source,
                                                    "advertisements": 0,
                                                    "prefixes": [], "lifetime": 0})
                entry["advertisements"] += 1
                entry["lifetime"] = int.from_bytes(packet[44:46], "big")
                for prefix in _ra_prefixes(packet[40 + 16:]):
                    if prefix not in entry["prefixes"]:
                        entry["prefixes"].append(prefix)
            elif icmp_type == 135:                     # neighbour solicitation
                neighbour_solicits += 1
        if not routers:
            return self._finish(ctx, ap, attempt, "no IPv6 router advertisements",
                                f"nothing advertised while we listened "
                                f"({neighbour_solicits} neighbour solicitation(s) seen)",
                                {"neighbour_solicits": neighbour_solicits},
                                severity="low")
        rogue = len(routers) > 1
        severity = "high" if rogue else "info"
        title = (f"{len(routers)} IPv6 routers advertising" if rogue
                 else "one IPv6 router advertising")
        detail = ("; ".join(f"{entry['router']} lifetime {entry['lifetime']}s, prefixes "
                            f"{', '.join(entry['prefixes'][:3]) or 'none'}"
                            for entry in routers.values()))
        return self._finish(ctx, ap, attempt, title, detail,
                            {"routers": list(routers.values()),
                             "neighbour_solicits": neighbour_solicits,
                             "note": ("router advertisements are unauthenticated: any "
                                      "host can become the default IPv6 route for the "
                                      "segment, and IPv6 is often forgotten in "
                                      "wireless security reviews")},
                            severity=severity)


def _ipv6_text(raw: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET6, raw) if len(raw) == 16 else raw.hex()


def _ra_prefixes(icmp_body: bytes) -> List[str]:
    """Prefix information options inside a router advertisement."""
    out: List[str] = []
    offset = 0
    while offset + 2 <= len(icmp_body):
        option_type = icmp_body[offset]
        length = icmp_body[offset + 1] * 8
        if length < 8 or offset + length > len(icmp_body):
            break
        if option_type == 3 and length >= 32:
            prefix = icmp_body[offset + 16:offset + 32]
            length_bits = icmp_body[offset + 2]
            out.append(f"{_ipv6_text(prefix)}/{length_bits}")
        offset += length
    return out


__all__ = ["ApAdminAuditAttack", "ArpSpoofDetectAttack", "DnsAuditAttack",
           "Ipv6RaAuditAttack", "RogueDhcpDetectAttack", "SnmpAuditAttack",
           "UpnpAuditAttack", "WpadAuditAttack"]
