"""A simulated network of devices, so the IT attacks have something real to talk to.

Live mode sends the bytes from :mod:`wifipilot.itproto` at a real host.  Demo mode — and
every test in the suite — needs the other half of that conversation: a device that
answers, with the quirks that make the attacks meaningful.  This module is that half.

Each host is a small record: an address, a vendor, a device type from
:mod:`wifipilot.itdev`, the ports it is listening on, and a *profile* that decides how it
behaves — whether the admin password was ever changed, whether the RTSP stream asks for
credentials, whether the container API answers to anyone at all.  A profile is also what
makes a finding honest: ``it_rtsp_anonymous`` succeeds exactly when the host's profile
says the stream is open, and fails when it does not, so a demo run exercises both
outcomes instead of celebrating every probe.

The responders are real protocol answers built with the same codecs the attacks use:
a Modbus read comes back as MBAP + function 3, an MQTT CONNECT gets a CONNACK with a
return code, ONVIF answers SOAP with a Manufacturer and a Model, a Redis PING without
AUTH gets ``-NOAUTH``.  Nothing here reaches the network.
"""

from __future__ import annotations

import base64
import hashlib
import json
import random
import re
import struct
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from . import itproto as proto
from .itdev import DeviceType, classify, device_type

__all__ = ["LanHost", "VirtualLan", "build_lan", "lan_catalog", "RESPONDERS"]

#: every host gets one of these: they decide what answers, and how it answers.
#: the shape of a device's posture.  The boolean flags are read by the responders, so
#: every one of them has to be a *key of the dict*, not just the name of the profile: a
#: branch on ``profile.get("hardened")`` was dead code until the flag was spelled out.
PROFILES: Dict[str, Dict[str, Any]] = {
    "hardened": {"default_creds": (), "anonymous": False, "open_write": False,
                 "auth_required": True, "tls": True, "firmware": "current",
                 "hardened": True,
                 "note": "patched, credentials changed, no anonymous access"},
    "default_creds": {"default_creds": (("admin", "admin"), ("admin", "password")),
                      "anonymous": False, "open_write": False, "auth_required": True,
                      "tls": False, "firmware": "2021.4", "spoofable": True,
                      "note": "the installer never changed the password"},
    "anonymous": {"default_creds": (), "anonymous": True, "open_write": False,
                  "auth_required": False, "tls": False, "firmware": "3.1.9",
                  "note": "the service answers before authentication"},
    "unauthenticated": {"default_creds": (), "anonymous": True, "open_write": True,
                        "auth_required": False, "tls": False, "firmware": "2.0.7",
                        "unauthenticated": True,
                        "note": "the protocol has no authentication to begin with"},
    "legacy": {"default_creds": (("root", "root"),), "anonymous": True, "open_write": True,
               "auth_required": False, "tls": False, "firmware": "1.2.1", "legacy": True,
               "note": "end of life: no updates, and the last one was years ago"},
    "kiosk": {"default_creds": (("admin", "admin"),), "anonymous": True, "open_write": False,
              "auth_required": False, "tls": False, "firmware": "1.4.2", "kiosk": True,
              "note": "an unattended screen: the desktop is on the network and the VNC "
                      "password was never set"},
}

#: which profile a sweep should probe first.  The ones that answer before they ask
#: questions come first, the ones that ask come next, and a hardened host comes last —
#: the ordering is the difference between a run that finds the misconfigurations and a
#: run that collects 401s.
WEAKNESS_ORDER: Tuple[str, ...] = ("unauthenticated", "anonymous", "kiosk", "legacy",
                                   "default_creds", "hardened")


def profile_rank(name: str) -> int:
    """The position of a profile in the sweep order (unknown profiles go last)."""
    return WEAKNESS_ORDER.index(name) if name in WEAKNESS_ORDER else len(WEAKNESS_ORDER)


@dataclass
class LanHost:
    """One device on the simulated segment."""

    ip: str
    mac: str
    hostname: str
    vendor: str
    device: str                       # a device type id from itdev
    model: str = ""
    firmware: str = ""
    profile_name: str = "hardened"
    ports: Tuple[int, ...] = ()
    note: str = ""
    mac_vendor: str = ""

    @property
    def profile(self) -> Dict[str, Any]:
        return PROFILES.get(self.profile_name, PROFILES["hardened"])

    @property
    def type(self) -> Optional[DeviceType]:
        return device_type(self.device)

    @property
    def label(self) -> str:
        dev = self.type
        return dev.label if dev else self.device

    def to_dict(self, lan: Optional["VirtualLan"] = None) -> Dict[str, Any]:
        dev = self.type
        return {
            "ip": self.ip, "mac": self.mac, "hostname": self.hostname,
            "label": self.hostname or self.ip,
            "vendor": self.vendor, "device": self.device, "device_label": self.label,
            "group": dev.group if dev else "", "model": self.model,
            "firmware": self.firmware, "profile": self.profile_name,
            "ports": list(self.ports), "note": self.note or self.profile.get("note", ""),
            "protocols": list(dev.protocols) if dev else [],
            "risk": dev.risk if dev else "",
        }


#: the shape of the demo segment: (hostname, vendor, device type, model, ports, profile).
#: Deliberately mixed — a couple of hardened hosts, many default-credential ones, the
#: industrial gear that has no authentication at all — because a demo where every probe
#: succeeds teaches nothing about reading the failures.
LAN_TABLE: Tuple[Tuple[str, str, str, str, Tuple[int, ...], str], ...] = (
    ("gw-edge-01", "MikroTik", "router", "hEX S", (53, 80, 443, 1900, 5353, 7547), "default_creds"),
    ("fw-utm-01", "Fortinet", "firewall", "FortiGate 60F", (443, 4443, 8443), "legacy"),
    ("sw-core-01", "Cisco", "switch", "Catalyst 2960", (22, 23, 80, 161), "default_creds"),
    ("ap-lobby", "Ubiquiti", "access_point", "U6-Pro", (22, 80, 443), "hardened"),
    ("vpn-gw-01", "SonicWall", "vpn_gateway", "NSA 2700", (443, 500, 4500), "legacy"),
    ("ont-01", "Calix", "modem_ont", "854G", (80, 443, 7547), "anonymous"),
    ("cam-lobby-01", "Hikvision", "ip_camera", "DS-2CD2143", (80, 554, 8000), "anonymous"),
    ("cam-gate-02", "Dahua", "ip_camera", "IPC-HDW2231", (80, 554, 37777), "default_creds"),
    ("nvr-01", "Hikvision", "nvr_dvr", "DS-7608", (80, 554, 8000), "default_creds"),
    ("door-front", "2N", "doorbell", "IP Verso", (80, 443, 5060), "hardened"),
    ("acl-controller", "Suprema", "badge_reader", "BioStation 2", (80, 443), "default_creds"),
    ("prn-floor2", "HP", "printer", "LaserJet M404", (80, 161, 631, 9100, 5353), "default_creds"),
    ("mfp-reception", "Xerox", "mfp_scanner", "AltaLink C8030", (80, 139, 445, 631, 9100), "default_creds"),
    ("nas-01", "Synology", "nas", "DS920+",
     (21, 22, 111, 139, 389, 445, 2049, 5000, 873, 5353), "default_creds"),
    ("backup-01", "Veeam", "backup_appliance", "VAO", (22, 443, 8000), "hardened"),
    ("esx-01", "VMware", "hypervisor_host", "ESXi 7.0", (22, 443, 5988), "legacy"),
    ("srv-web-01", "nginx", "web_server", "Debian 12", (22, 80, 443, 8080), "hardened"),
    ("srv-dc-01", "Microsoft", "domain_controller", "Server 2019", (53, 88, 389, 445, 636), "hardened"),
    ("srv-db-01", "PostgreSQL", "database_server", "PG 14", (5432, 6379, 9200, 27017), "anonymous"),
    ("srv-ci-01", "Jenkins", "ci_server", "LTS 2.4", (80, 8080, 50000), "anonymous"),
    ("k8s-node-01", "Kubernetes", "container_host", "v1.28", (2375, 6443, 10250), "legacy"),
    ("phone-101", "Yealink", "voip_phone", "T46S", (80, 443, 5060), "default_creds"),
    ("pbx-01", "Asterisk", "pbx", "FreePBX 16", (80, 443, 5060, 5038), "legacy"),
    ("plc-line1", "Siemens", "plc", "S7-1200", (102, 502, 4840), "unauthenticated"),
    ("rtu-substation", "SEL", "rtu", "SEL-3530", (502, 20000, 2404), "unauthenticated"),
    ("hvac-bms-01", "Johnson Controls", "building_controller", "NCE", (80, 443, 47808), "default_creds"),
    ("hmi-line1", "Advantech", "hmi_panel", "TPC-1251", (80, 3389, 502), "legacy"),
    ("meter-main", "Schneider", "energy_meter", "PM5560", (80, 161, 502), "unauthenticated"),
    ("ct-scanner", "Philips", "medical_device", "IntelliVue", (80, 104, 11112), "legacy"),
    ("pos-till-3", "Verifone", "pos_terminal", "V240m", (80, 443, 9100), "default_creds"),
    ("sign-lobby", "BrightSign", "digital_signage", "XT1144", (80, 443, 8080), "default_creds"),
    ("proj-meeting", "Epson", "projector", "EB-L200", (80, 4352), "unauthenticated"),
    ("tv-boardroom", "Samsung", "smart_tv", "QE65", (8008, 8009, 9080, 5353), "default_creds"),
    ("speaker-lobby", "Sonos", "smart_speaker", "One", (1400, 1443, 8008, 5353), "anonymous"),
    ("plug-rack", "TP-Link", "smart_plug", "HS110", (9999, 80), "unauthenticated"),
    ("lock-backdoor", "Nuki", "smart_lock", "Smart Lock 3", (80, 8080), "default_creds"),
    ("thermo-hall", "Honeywell", "thermostat", "T6", (80, 443), "default_creds"),
    ("cam-baby", "Wyze", "camera_doorbell", "V3", (80, 554), "anonymous"),
    ("vacuum-2f", "Roborock", "robot_vacuum", "S7", (54321,), "anonymous"),
    ("ev-charger-1", "Wallbox", "ev_charger", "Pulsar", (80, 443, 502), "default_creds"),
    # -- the hosts the IT wave needs a target for in a demo run --------------------- #
    ("mqtt-broker-01", "Mosquitto", "gateway_hub", "Broker 2.0", (1883, 8883, 80), "anonymous"),
    ("sensor-coap-01", "Shelly", "sensor", "Plus H&T", (5683, 80), "unauthenticated"),
    ("cache-01", "Memcached", "linux_server", "1.6.21", (22, 11211), "anonymous"),
    ("atv-living", "Apple", "smart_tv", "Apple TV 4K", (7000, 7001, 3689, 8009), "anonymous"),
    ("plc-packaging-01", "Allen-Bradley", "plc", "CompactLogix 5380", (44818, 80, 2222),
     "unauthenticated"),
    ("srv-sql-02", "MySQL", "database_server", "MySQL 8.0", (3306, 80), "default_creds"),
    ("srv-dc-02", "Samba", "domain_controller", "Samba 4.13", (88, 139, 389, 445, 636),
     "anonymous"),
    ("srv-ftp-legacy", "Microsoft", "windows_server", "Server 2008 R2", (21, 80, 445),
     "anonymous"),
    ("mail-relay-01", "Postfix", "mail_server", "Postfix 3.5", (25, 587, 993, 80), "legacy"),
    ("phone-user-2", "Samsung", "smartphone", "Galaxy A54", (5555,), "anonymous"),
    ("tablet-kiosk", "Lenovo", "tablet", "Tab M10", (5900,), "kiosk"),
)


def build_lan(seed: int = 7, limit: int = 0) -> List[LanHost]:
    """The demo segment: deterministic addresses, vendors and profiles.

    ``seed`` only jitters the last octet of MAC addresses and the firmware strings; the
    hosts, their ports and their profiles are fixed, because a demo that changes shape
    every run cannot be compared with the last one.
    """
    rng = random.Random(seed)
    hosts: List[LanHost] = []
    for index, (hostname, vendor, device, model, ports, profile_name) in enumerate(LAN_TABLE):
        if limit and len(hosts) >= limit:
            break
        ip = f"192.168.1.{20 + index}"
        mac = "b8:27:eb:%02x:%02x:%02x" % (0x40 + index, rng.randrange(256),
                                           rng.randrange(256))
        firmware = PROFILES[profile_name].get("firmware", "1.0.0")
        hosts.append(LanHost(ip=ip, mac=mac, hostname=hostname, vendor=vendor, device=device,
                             model=model, firmware=firmware, profile_name=profile_name,
                             ports=tuple(ports), note=PROFILES[profile_name]["note"]))
    return hosts


def hosts_by_weakness(hosts: Sequence[LanHost]) -> List[LanHost]:
    """The same hosts, weakest profile first, stable inside a profile."""
    return sorted(hosts, key=lambda host: (profile_rank(host.profile_name),
                                           len(host.ports), host.ip))


def lan_catalog(hosts: Sequence[LanHost]) -> List[Dict[str, Any]]:
    return [host.to_dict() for host in hosts]


# --------------------------------------------------------------------------- #
# which protocol lives on which port, and what the answer looks like
# --------------------------------------------------------------------------- #

PORT_PROTOCOL: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 88: "kerberos",
    102: "s7", 104: "dicom", 111: "rpc", 139: "smb", 143: "imap", 161: "snmp",
    389: "ldap", 443: "http", 445: "smb", 502: "modbus", 515: "pjl", 554: "rtsp",
    587: "smtp", 631: "ipp", 636: "ldap", 873: "rsync", 993: "imap", 1400: "http",
    1443: "http", 1883: "mqtt", 1900: "ssdp", 2049: "nfs", 3306: "mysql", 3389: "rdp",
    4352: "pjlink", 5000: "http", 5038: "ami", 5060: "sip", 5353: "mdns", 5432: "postgres",
    5555: "adb", 5683: "coap", 5900: "vnc", 5988: "http", 6379: "redis", 6443: "http",
    7547: "cwmp", 8000: "http", 8008: "http", 8009: "cast", 8080: "http", 8443: "http",
    4443: "http", 8883: "mqtt", 7000: "airplay", 7001: "airplay", 3689: "airplay",
    44818: "cip", 11211: "memcached", 137: "netbios", 2222: "ssh", 50000: "http",
    37777: "http", 5038: "ami", 2049: "nfs", 111: "rpc", 2375: "http", 5988: "http",
    8554: "rtsp", 9080: "http", 9100: "pjl", 9200: "http", 9999: "kasa", 10250: "http",
    11112: "dicom", 20000: "dnp3", 2375: "http", 2404: "iec104", 27017: "mongo",
    37777: "http", 47808: "bacnet", 4840: "opcua", 54321: "miio", 50000: "http",
}

#: the web-management ports answer with the device's own admin page
HTTP_PORTS = {80, 443, 1400, 1443, 3000, 443, 5000, 5988, 6443, 7547, 8000, 8008, 8080,
              8443, 9080, 9200, 10250, 2375, 37777, 50000}


def protocol_for(host: LanHost, port: int) -> str:
    """The protocol on a port, with the device type's own protocols winning."""
    dev = host.type
    if dev and dev.protocols:
        for name in dev.protocols:
            mapped = PROTOCOL_PORTS.get(name)
            if mapped and port in mapped:
                return name
    return PORT_PROTOCOL.get(port, "http" if port in HTTP_PORTS else "")


#: protocol id -> the ports it usually answers on (the reverse of PORT_PROTOCOL, by hand
#: for the protocols whose port is not the one a scanner would try first)
PROTOCOL_PORTS: Dict[str, Tuple[int, ...]] = {
    "http": (80, 443, 8080, 8000, 8008, 8443, 9080, 5000, 5988, 10250),
    "http_json": (2375, 6443, 8080, 9200, 8080),
    "ssdp": (1900,), "mdns": (5353,), "dns": (53,), "cwmp": (7547,), "tr069": (7547,),
    "ssh": (22,), "telnet": (23,), "ftp": (21,), "smtp": (25, 587), "imap": (143, 993),
    "snmp": (161,), "rtsp": (554, 8554), "onvif": (80, 443), "ipp": (631,),
    "pjl": (9100, 515), "smb": (139, 445), "nfs": (2049,), "rpc": (111,),
    "rsync": (873,), "rdp": (3389,), "vnc": (5900,), "ldap": (389, 636),
    "postgres": (5432,), "mysql": (3306,), "redis": (6379,), "mongo": (27017,),
    "elastic": (9200,), "sip": (5060,), "ami": (5038,), "s7comm": (102,),
    "modbus": (502,), "opcua": (4840,), "dnp3": (20000,), "iec104": (2404,),
    "bacnet": (47808,), "dicom": (104, 11112), "cast": (8009,), "kasa": (9999,),
    "miio": (54321,), "adb": (5555,), "pjlink": (4352,), "mqtt": (1883,),
    "coap": (5683,), "docker": (2375,), "kubernetes": (6443, 10250), "jenkins": (8080,),
}


def _json_response(payload: Dict[str, Any], status: str = "200 OK",
                   server: str = "wifipilot-sim") -> bytes:
    body = json.dumps(payload, indent=2, sort_keys=True).encode()
    return (f"HTTP/1.1 {status}\r\nServer: {server}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body


def _html_response(title: str, lines: Sequence[str], status: str = "200 OK",
                   server: str = "wifipilot-sim", form: bool = False) -> bytes:
    fields = "".join(f'<input name="{name}" type="text">' for name in lines) if form \
        else "".join(f"<li>{line}</li>" for line in lines)
    body = (f"<html><head><title>{title}</title></head><body><h1>{title}</h1>"
            f"{'<form method=post>' + fields + '<input type=submit></form>' if form else '<ul>' + fields + '</ul>'}"
            f"</body></html>").encode()
    return (f"HTTP/1.1 {status}\r\nServer: {server}\r\nContent-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body


#: what each kind of device says in its Server header.  Every embedded web server names
#: itself and its version, and that line is what a version audit reads — an anonymous
#: "wifipilot-sim" would be the one banner no real device ever sends.
SERVER_BANNERS = {"router": "RouterOS 6.49.7", "firewall": "lighttpd/1.4.59",
                  "access_point": "lighttpd/1.4.53", "switch": "GoAhead-Webs/2.5.0",
                  "ip_camera": "GoAhead-Webs/2.5.0", "nvr_dvr": "Boa/0.94.14rc21",
                  "doorbell": "GoAhead-Webs/3.0.1", "camera_doorbell": "GoAhead-Webs/3.0.1",
                  "printer": "mini_httpd/1.30", "mfp_scanner": "mini_httpd/1.19",
                  "label_printer": "mini_httpd/1.30", "nas": "lighttpd/1.4.53",
                  "web_server": "nginx/1.24.0", "database_server": "RomPager/4.07",
                  "container_host": "thttpd/2.29", "hypervisor_host": "Jetty(9.4.48)"}


def _server_for(host: LanHost) -> str:
    """The Server header of the host: the device's own name for its web server."""
    return SERVER_BANNERS.get(host.device, "Boa/0.94.14rc21")


def _http_answer(host: LanHost, payload: bytes, path_hint: str = "") -> bytes:
    """The web side of a device, with the banner that device's web server would send.

    Every branch below answers with a body, a status and its own headers; the banner is
    one line, it is the line a version audit reads, and it does not depend on the branch.
    """
    answer = _http_body(host, payload, path_hint)
    banner = _server_for(host).encode()
    if b"Server: " not in answer:
        return answer
    lines = answer.split(b"\r\n")
    body_start = next((index for index, line in enumerate(lines) if not line), len(lines))
    headers = [line for line in lines[1:body_start] if not line.lower().startswith(b"server:")]
    head = [lines[0], b"Server: " + banner] + headers
    return b"\r\n".join(head + lines[body_start:])


def _http_body(host: LanHost, payload: bytes, path_hint: str = "") -> bytes:
    """The web side of a device: a login form, a status page or a JSON API.

    The path in the request decides which, and that is the whole point of the responder:
    ``/version`` on a Docker host really answers with a version, and an admin page of a
    default-credential device really answers ``401`` until the credential is sent.
    """
    request = payload.decode("latin-1", "replace")
    first = request.splitlines()[0] if request else ""
    parts = first.split(" ")
    path = parts[1] if len(parts) > 1 else "/"
    profile = host.profile
    wants_auth = profile.get("auth_required", True) and not profile.get("anonymous")
    # every device names its web server, and the name carries the firmware version
    server = f"{host.vendor.lower()}-httpd/{host.firmware}"
    containers = 2375 in host.ports or 2376 in host.ports
    cluster = 6443 in host.ports or 8443 in host.ports
    # a host can be both (a cluster node runs a container daemon): the port the request
    # was addressed to decides which API answers, and that port is in its Host header
    match = re.search(r"host:\s*[^\s:]+:(\d{2,5})", request, re.I)
    asked_port = int(match.group(1)) if match else 0
    if asked_port:
        containers = asked_port in (2375, 2376, 4243)
        cluster = asked_port in (6443, 8443, 10250, 10255)
    lowered = request.lower()
    credentials = _basic_credentials(request)
    authorised = bool(credentials[0] or credentials[1]) and _with_auth(host, credentials)
    # the classic embedded bug: a device that trusts the header saying the request came
    # from localhost serves the page behind the login form to anyone who sets it
    localhost_claim = bool(re.search(r"x-forwarded-for:\s*127\.0\.0\.1|"
                                     r"x-real-ip:\s*127\.0\.0\.1", request, re.I))
    if wants_auth and not authorised and localhost_claim and profile.get("spoofable"):
        return _html_response(f"{host.hostname} configuration",
                              (f"model={host.model}", f"firmware={host.firmware}",
                               f"vendor={host.vendor}", "admin-user=admin",
                               "trusted-from=127.0.0.1"), server=server)

    if "soap" in lowered or "onvif" in path or "GetDeviceInformation" in request or \
            "GetSystemDateAndTime" in request:
        if wants_auth and not authorised:
            return _html_response(f"{host.model} login", ("username", "password"),
                                  status="401 Unauthorized", form=True)
        return _onvif_answer(host, request)
    if path.startswith("/api/v1") or path.startswith("/apis/") or \
            path.startswith("/api/v1/namespaces"):
        kind = "NamespaceList" if "namespaces" in path else "NodeList"
        return _json_response({"kind": kind, "apiVersion": "v1",
                               "items": [{"metadata": {"name": "default",
                                                       "uid": "8f1c2f4e-demo",
                                                       "creationTimestamp": "2026-01-04T09:14:00Z"},
                                          "status": {"phase": "Active"}}],
                               "serverAddressByClientCIDRs": [{"clientCIDR": "0.0.0.0/0",
                                                               "serverAddress": host.ip}]},
                              server=server)
    if "/containers/json" in path or path.endswith("/containers"):
        return _json_response([
            {"Id": "b1c9f0d2d3e4", "Names": ["/wp-portal"], "Image": "ghcr.io/wp/portal:1.4",
             "State": "running", "Status": "Up 3 days",
             "Ports": [{"PrivatePort": 8080, "PublicPort": 8080, "Type": "tcp"}]},
            {"Id": "9d8c7b6a5f4e", "Names": ["/wp-db"], "Image": "postgres:16-alpine",
             "State": "running", "Status": "Up 3 days",
             "Ports": [{"PrivatePort": 5432, "Type": "tcp"}]}], server=server)
    if "containers/create" in path:                          # a write, and never sent twice
        return _json_response({"Id": "wp-demo-c0ffee123456", "Warnings": []},
                              status="201 Created", server=server)
    if path.startswith("/version"):
        if cluster:                                          # Kubernetes API server
            return _json_response({"major": "1", "minor": "28",
                                   "gitVersion": "v1.28.4", "gitCommit": "bae2c62",
                                   "buildDate": "2024-01-17T08:14:07Z", "platform": "linux/amd64",
                                   "goVersion": "go1.20.13"}, server=server)
        if containers:                                       # Docker Engine API
            return _json_response({"Version": "24.0.7", "ApiVersion": "1.43",
                                   "MinAPIVersion": "1.12", "Os": "linux", "Arch": "amd64",
                                   "KernelVersion": "5.15.0-88-generic"}, server=server)
        return _json_response({"product": host.model, "server": server,
                               "firmware": host.firmware}, server=server)
    if path.startswith("/info") and containers:
        return _json_response({"ID": "K7ZQ:4GH2", "Name": host.hostname, "Containers": 6,
                               "Images": 14, "Driver": "overlay2", "DockerRootDir":
                               "/var/lib/docker", "OperatingSystem": host.vendor,
                               "KernelVersion": "5.15.0-88-generic",
                               "NCPU": 4, "MemTotal": 8123456789}, server=server)
    if path.rstrip("/") in ("/api", "/api/v1") or path.startswith("/apis") or \
            (path.rstrip("/") == "" and (cluster or containers)):
        # "/" on a device is its web page; "/" on a cluster or a container daemon is the
        # API index — the same path, two different answers
        return _json_response({"kind": "APIVersions", "versions": ["v1"],
                               "serverAddressByClientCIDRs": []}, server=server)
    if path.startswith("/healthz") or path.startswith("/_ping") or path == "/health":
        return _json_response({"status": "ok", "response": "pong"})
    if path.startswith("/api/json"):                        # Jenkins
        return _json_response({"jobs": [{"name": "deploy-prod", "color": "blue"},
                                        {"name": "build-images", "color": "red"}],
                               "_class": "hudson.model.Hudson"})
    if path.startswith("/_cat") or path.startswith("/_cluster"):
        return _json_response({"name": "srv-db-01", "cluster_name": "wp-demo",
                               "version": {"number": "8.11.1", "build_flavor":
                                           "default"}})
    if host.device in ("smart_plug", "smart_bulb") and not wants_auth:
        return _json_response({"system": {"get_sysinfo": {"model": host.model,
                                                          "alias": host.hostname,
                                                          "relay_state": 1}}})
    if host.device == "smart_tv" and path.startswith("/getDeviceInfo"):
        return _json_response({"device": {"name": host.hostname, "model": host.model,
                                          "version": host.firmware}})
    if host.device == "ev_charger" and path.startswith("/ocpp"):
        return _json_response({"status": "Accepted", "charger": host.model})
    if wants_auth and not authorised:
        # a device that wants a password usually *serves* its login page with a 200 and
        # answers 401 only on the pages behind the form: both shapes are in the wild
        landing = path.rstrip("/") in ("", "/index.htm", "/index.html", "/login")
        return _html_response(f"{host.model} login", ("username", "password"),
                              status="200 OK" if landing else "401 Unauthorized",
                              form=True, server=server)
    if path.startswith("/admin") or path.startswith("/config") or "/configuration" in path:
        return _html_response(f"{host.hostname} configuration",
                              (f"model={host.model}", f"firmware={host.firmware}",
                               f"vendor={host.vendor}", "admin-user=admin",
                               f"snmp-community={host.vendor.lower()}",
                               "wifi-psk=<redacted for the report>"), server=server)
    if path.startswith("/status") or path.startswith("/info"):
        return _json_response({"hostname": host.hostname, "model": host.model,
                               "firmware": host.firmware, "vendor": host.vendor,
                               "uptime": 86400})
    return _html_response(f"{host.model} - {host.hostname}",
                          (f"firmware {host.firmware}", f"vendor {host.vendor}",
                           "management interface"), server=server)


def _basic_strings(payload: bytes) -> Tuple[str, str]:
    """The user and password of a Basic header in a binary request, if there is one.

    The HTTP-shaped helpers read a decoded string; IPP and friends send the same header
    inside a byte string, so this is the same search one type earlier.
    """
    text = payload.decode("latin-1", "replace")
    for line in text.splitlines():
        if "authorization:" in line.lower() and "basic" in line.lower():
            return _decode_basic(line.split()[-1])
    return ("", "")


def _decode_basic(token: str) -> Tuple[str, str]:
    try:
        decoded = base64.b64decode(token + "===", validate=False).decode("latin-1")
    except Exception:                                      # noqa: BLE001 - a broken header
        return ("", "")
    user, _, password = decoded.partition(":")
    return (user, password)


def _basic_credentials(request: str) -> Tuple[str, str]:
    """The user and password from an ``Authorization: Basic`` header, if there is one."""
    for line in request.splitlines():
        if line.lower().startswith("authorization:") and "basic" in line.lower():
            return _decode_basic(line.split()[-1])
    return ("", "")


def _onvif_answer(host: LanHost, request: str) -> bytes:
    """The SOAP body ONVIF clients expect, with the fields the attacks read."""
    if "GetSystemDateAndTime" in request:
        inner = ("<tds:GetSystemDateAndTimeResponse><tds:SystemDateAndTime>"
                 "<tt:DateTimeType>Manual</tt:DateTimeType>"
                 "<tt:UTCDateTime><tt:Time><tt:Hour>9</tt:Hour><tt:Minute>31</tt:Minute>"
                 "</tt:Time><tt:Date><tt:Year>2026</tt:Year><tt:Month>10</tt:Month>"
                 "<tt:Day>14</tt:Day></tt:Date></tt:UTCDateTime></tds:SystemDateAndTime>"
                 "</tds:GetSystemDateAndTimeResponse>")
    else:
        inner = ("<tds:GetDeviceInformationResponse>"
                 f"<tds:Manufacturer>{host.vendor}</tds:Manufacturer>"
                 f"<tds:Model>{host.model}</tds:Model>"
                 f"<tds:FirmwareVersion>{host.firmware}</tds:FirmwareVersion>"
                 f"<tds:SerialNumber>{host.mac.replace(':', '')}</tds:SerialNumber>"
                 f"<tds:HardwareId>1.0</tds:HardwareId>"
                 "</tds:GetDeviceInformationResponse>")
    body = ('<?xml version="1.0" encoding="UTF-8"?>'
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
            'xmlns:tds="http://www.onvif.org/ver10/device/wsdl" '
            'xmlns:tt="http://www.onvif.org/ver10/schema"><s:Body>' + inner +
            "</s:Body></s:Envelope>")
    return (f"HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\nServer: {host.vendor}ONVIF/1.0\r\n\r\n"
            + body).encode()


def _with_auth(host: LanHost, credentials: Tuple[str, str]) -> bool:
    """Whether the credentials a probe just sent are the ones this host accepts."""
    accepted = tuple(tuple(pair) for pair in host.profile.get("default_creds", ()))
    return tuple(credentials) in accepted or (not accepted and
                                              not host.profile.get("auth_required", True))


# -- the responders ---------------------------------------------------------- #

def r_mqtt(host: LanHost, payload: bytes) -> bytes:
    packet = proto.parse_mqtt(payload)
    if packet.get("type") == 1:                            # CONNECT
        text = payload.decode("latin-1", "replace")
        if host.profile.get("auth_required") and not host.profile.get("default_creds"):
            return bytes([proto.MQTT_CONNACK, 0x02, 0x00, 0x05])       # not authorised
        if "password" in text.lower() or host.profile.get("anonymous"):
            return bytes([proto.MQTT_CONNACK, 0x02, 0x00, 0x00])       # accepted
        return bytes([proto.MQTT_CONNACK, 0x02, 0x00, 0x04])           # bad credentials
    return bytes([proto.MQTT_CONNACK, 0x02, 0x00, 0x00])


def _coap_option_size(payload: bytes) -> int:
    """The longest option value in a CoAP request, so the responder can refuse it."""
    length, offset = 0, 1
    if payload:
        offset += payload[0] & 0x0F                          # skip the token
    delta, previous = 0, 0
    while offset < len(payload) and payload[offset] != 0xFF:
        byte = payload[offset]
        offset += 1
        delta = (byte >> 4) if (byte >> 4) < 13 else 0
        length = (byte & 0x0F) if (byte & 0x0F) < 13 else 0
        if delta:
            offset += delta
        option_key = (previous + (byte >> 4)) if (byte >> 4) < 13 else previous
        previous = option_key
        if length:
            offset += length
    return length


def r_coap(host: LanHost, payload: bytes) -> bytes:
    """2.05 for a read, 2.04 for a write, 4.13 for an option the device cannot hold,
    and 4.01 when the profile says this endpoint wants a credential it never gets."""
    request = proto.parse_coap(payload)
    code = 0x45                                            # 2.05 Content
    if request.get("type") == 0 and (request.get("code") or 0) >= 2:
        code = 0x44                                        # 2.04 Changed
    if _coap_option_size(payload) > 32:
        code = 0x8D                                        # 4.13 Request Entity Too Large
    if host.profile.get("auth_required") and not host.profile.get("default_creds"):
        code = 0x81                                        # 4.01 Unauthorized
    body = (json.dumps({"uri": request.get("uri"), "host": host.hostname,
                        "model": host.model}).encode()
            if code in (0x44, 0x45) else b"request refused")
    first = (1 << 6) | (2 << 4) | len(request.get("token", b""))     # ACK, same token
    return bytes([first, code]) + proto.be16(request.get("message_id", 0) or 0) + \
        request.get("token", b"") + b"\xff" + body


def r_modbus(host: LanHost, payload: bytes) -> bytes:
    request = proto.parse_modbus(payload, request=True)
    unit = request.get("unit", 1) or 1
    transaction = request.get("transaction", 1)
    function = request.get("function", 3)
    count = int(request.get("count", 5) or 5)
    if count > 125:                                        # illegal data value, as a real PLC
        pdu = bytes([function | 0x80, 3])
        return proto.be16(transaction) + b"\x00\x00" + proto.be16(len(pdu) + 1) + \
            bytes([unit]) + pdu
    # the register map is stable per device: a base value from the MAC, then a stride
    base = 100 + sum(host.mac.encode()) % 400
    registers = [(base + index * 64) & 0xFFFF for index in range(max(1, count))]
    if function in (3, 4):
        data = b"".join(proto.be16(value) for value in registers)
        pdu = bytes([function, len(data)]) + data
    elif function in (1, 2):
        pdu = bytes([function, 1, 0x0D])
    elif function in (5, 6):
        pdu = payload[7:12] if len(payload) >= 12 else bytes([function, 0, 0, 0, 0])
        if not host.profile.get("open_write", False):
            pdu = bytes([function | 0x80, 3])               # illegal data value
    elif function == 43:
        pdu = bytes([43, 0x0E, 0x01, 0x01, 0x00, 0x00, len(host.model), 0x00]) + \
            host.model.encode()
    else:
        pdu = bytes([function | 0x80, 0x01])
    return proto.be16(transaction) + b"\x00\x00" + proto.be16(len(pdu) + 1) + \
        bytes([unit]) + pdu


def r_bacnet(host: LanHost, payload: bytes) -> bytes:
    """An I-Am for a Who-Is, a complex ACK for a Read-Property."""
    request = proto.parse_bacnet(payload)
    if request.get("service") == 8:                        # who-is -> i-am
        body = b"\x10\x05" + b"\x0c" + bytes([4]) + proto.be16(1) + \
            b"\x19\x03" + bytes([8]) + b"\x2c" + bytes([len(host.model)]) + \
            host.model.encode() + b"\x3e\x04" + proto.be16(host.mac_vendor and 0 or 17)
        return proto.bacnet_frame(0x0A, body)
    return proto.bacnet_frame(0x0A, b"\x10\x05" + b"\x0c\x04" + proto.be16(1))


def r_rtsp(host: LanHost, payload: bytes) -> bytes:
    text = payload.decode("latin-1", "replace")
    method = text.split(" ", 1)[0].upper() if text else "OPTIONS"
    authorised = "authorization:" in text.lower()
    if host.profile.get("auth_required") and not host.profile.get("anonymous") \
            and not authorised and method != "OPTIONS":
        return (b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nServer: " +
                f"{host.vendor} {host.model} V{host.firmware}".encode() +
                b"\r\nWWW-Authenticate: Digest realm=\"" +
                host.model.encode() + b"\", nonce=\"0a1b2c3d\", algorithm=MD5\r\n\r\n")
    sdp = (f"v=0\r\no=- 1 1 IN IP4 {host.ip}\r\ns={host.model} stream\r\n"
           f"c=IN IP4 {host.ip}\r\nt=0 0\r\nm=video 0 RTP/AVP 96\r\n"
           f"a=rtpmap:96 H264/90000\r\na=framesize:96 1920-1080\r\n"
           f"a=control:track1\r\n").encode()
    head = (f"RTSP/1.0 200 OK\r\nCSeq: 1\r\n"
            f"Server: {host.vendor} {host.model} V{host.firmware}\r\n"
            f"Session: 1234567890\r\nContent-Type: application/sdp\r\n"
            f"Content-Length: {len(sdp)}\r\n\r\n").encode()
    return head + (sdp if method in ("DESCRIBE", "SETUP", "PLAY") else b"")


def _ipp_attr(tag: int, name: str, value: bytes) -> bytes:
    """One IPP attribute: tag, the name length (two bytes), the name, then the value.

    RFC 8011 §3.1.2 spells the name length as an INT16, exactly like the value length:
    a one-byte name length parses in this repository and nowhere else.
    """
    encoded = name.encode()
    return bytes([tag]) + proto.be16(len(encoded)) + encoded + proto.be16(len(value)) + value


#: the IPP operations a printer answers before it asks who is calling: reading the
#: attributes of the device and of its own jobs is discovery, printing is not
IPP_READ_ONLY = (0x0009, 0x000A, 0x000B, 0x0012)


def r_ipp(host: LanHost, payload: bytes) -> bytes:
    """An IPP answer: the request id echoed, the printer's name, state and model.

    A printer that requires an account to print still answers *discovery*: RFC 8011's
    attributes of the printer itself are what a client needs before it can even ask for
    a credential, and a LaserJet left at its defaults answers them to anyone.
    """
    request = proto.parse_ipp(payload, response=False)
    credentials = _basic_strings(payload)
    pairs = tuple(tuple(pair) for pair in host.profile.get("default_creds", ()))
    authorised = bool(credentials) and credentials in pairs
    read_only = request.get("operation") in IPP_READ_ONLY
    status = 0x0000 if (not host.profile.get("auth_required") or authorised
                        or read_only) else 0x0403                 # not authenticated
    make = f"{host.vendor} {host.model}"
    body = bytes([0x01])                                   # operation attributes group
    body += _ipp_attr(0x47, "attributes-charset", b"utf-8")
    body += _ipp_attr(0x48, "attributes-natural-language", b"en")
    body += bytes([0x04])                                  # printer attributes group
    body += _ipp_attr(0x42, "printer-name", host.hostname.encode())
    body += _ipp_attr(0x23, "printer-state", proto.be32(3))
    body += _ipp_attr(0x41, "printer-make-and-model", make.encode())
    body += _ipp_attr(0x41, "printer-firmware-version", host.firmware.encode())
    body += _ipp_attr(0x21, "printer-impressions-completed", proto.be32(41207))
    body += _ipp_attr(0x44, "printer-uri-supported",
                      f"ipp://{host.ip}/ipp/print".encode())
    body += bytes([0x03])                                  # end-of-attributes-tag
    return (proto.be16(2) + proto.be16(status) + proto.be32(request.get("request_id", 1))
            + body)


def r_pjl(host: LanHost, payload: bytes) -> bytes:
    text = payload.decode("latin-1", "replace").upper()
    if "INFO ID" in text:
        return (f"@PJL INFO ID\r\n\"{host.vendor} {host.model}\"\r\n\x0c").encode()
    if "STATUS" in text:
        return b"@PJL INFO STATUS\r\nCODE=10001\r\nDISPLAY=\"READY\"\r\nONLINE=TRUE\r\n\x0c"
    if "CONFIG" in text:
        return (f"@PJL INFO CONFIG\r\nSERIAL={host.mac}\r\nFIRMWARE={host.firmware}\r\n"
                f"MODEL={host.model}\r\n\x0c").encode()
    if "FILESYS" in text:
        return b"@PJL INFO FILESYS\r\nVOLUME=0:\\  TYPE=RAM\r\n\x0c"
    if "PAGECOUNT" in text:
        return b"@PJL INFO PAGECOUNT\r\nTOTAL=14823\r\n\x0c"
    if "USTATUS" in text:
        return b"@PJL USTATUS DEVICE\r\nCODE=10001\r\n\x0c"
    return b"@PJL ECHO WIFIPILOT-TEST\r\n\x0c"


def r_telnet(host: LanHost, payload: bytes) -> bytes:
    # the version is the reason the row exists: a banner without one is not a fingerprint
    banner = (f"\r\n{host.model} firmware {host.firmware}.1 ({host.vendor})\r\n"
              "login: ").encode()
    return bytes([0xFF, 0xFD, 0x18, 0xFF, 0xFD, 0x20, 0xFF, 0xFB, 0x01]) + banner


def r_sip(host: LanHost, payload: bytes) -> bytes:
    text = payload.decode("latin-1", "replace")
    method = text.split(" ", 1)[0].upper() if text else "OPTIONS"
    authorised = "authorization:" in text.lower()
    if host.profile.get("auth_required") and not authorised:
        return (f"SIP/2.0 401 Unauthorized\r\nVia: SIP/2.0/UDP wifipilot\r\n"
                f"To: <sip:{host.hostname}>\r\nFrom: <sip:wifipilot>;tag=wp\r\n"
                f"Call-ID: wp@wp\r\nCSeq: 1 {method}\r\nServer: {host.vendor} {host.model}\r\n"
                f"WWW-Authenticate: Digest realm=\"{host.hostname}\", "
                f"nonce=\"a1b2c3d4e5\", algorithm=MD5\r\nContent-Length: 0\r\n\r\n").encode()
    return (f"SIP/2.0 200 OK\r\nServer: {host.vendor} {host.model}\r\n"
            f"Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REGISTER\r\n"
            f"Content-Length: 0\r\n\r\n").encode()


def r_cwmp(host: LanHost, payload: bytes) -> bytes:
    text = payload.decode("latin-1", "replace")
    if "Inform" in text:
        return (b'<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org'
                b'/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0"><soap:Header>'
                b"<cwmp:ID>wp1</cwmp:ID></soap:Header><soap:Body><cwmp:InformResponse>"
                b"<MaxEnvelopes>1</MaxEnvelopes></cwmp:InformResponse></soap:Body>"
                b"</soap:Envelope>")
    return (b'<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org'
            b'/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0"><soap:Body>'
            b"<cwmp:GetParameterValuesResponse><ParameterList><ParameterValueStruct>"
            b"<Name>InternetGatewayDevice.DeviceInfo.SoftwareVersion</Name><Value>"
            + host.firmware.encode() + b"</Value></ParameterValueStruct>"
            b"<ParameterValueStruct><Name>InternetGatewayDevice.WANDevice.1.WANConnection"
            b"Device.1.WANIPConnection.1.ExternalIPAddress</Name><Value>203.0.113.7</Value>"
            b"</ParameterValueStruct></ParameterList></cwmp:GetParameterValuesResponse>"
            b"</soap:Body></soap:Envelope>")


def r_smb(host: LanHost, payload: bytes) -> bytes:
    """An SMB2 NEGOTIATE reply: header, then StructureSize 65, the security mode, the
    dialect revision, the server GUID, sizes, times and the security buffer."""
    security_mode = 0x0001 if host.profile.get("auth_required") else 0x0000
    dialect = 0x0202 if host.profile.get("hardened") else 0x0311
    guid = hashlib.md5(host.mac.encode()).digest()
    body = (proto.le16(65) + proto.le16(security_mode) + proto.le16(dialect) + b"\x00\x00" +
            guid + proto.le32(0x80000000) + proto.le32(0x00100000) + proto.le32(0x00100000) +
            proto.le32(0x00100000) +
            struct.pack("<Q", 133338000000000000) + struct.pack("<Q", 133337000000000000) +
            proto.le16(0) + proto.le16(0) + proto.le32(0))   # no security buffer to offer
    header = (b"\xfeSMB" + proto.le16(64) + proto.le16(1) + proto.le32(0) + proto.le16(0)
              + proto.le16(1) + proto.le32(0) + proto.le32(0) + b"\x00" * 8
              + proto.le32(0) + proto.le32(0) + proto.le64(0) + b"\x00" * 16)
    packet = header + body
    return b"\x00" + proto.le32(len(packet))[1:] + packet


def _ldap_result(message_id: bytes, code: int) -> bytes:
    """A BindResponse with one result code — the whole answer a directory sends to a bind."""
    return proto._ber_tlv(0x30, proto._ber_tlv(0x02, message_id) + proto._ber_tlv(
        0x61, proto._ber_tlv(0x0A, bytes([code])) + proto._ber_tlv(0x04, b"") +
        proto._ber_tlv(0x04, b"")))


def r_ldap(host: LanHost, payload: bytes) -> bytes:
    """A bind the profile decides, and a rootDSE search that answers with entries.

    Two rules, and both are what a real directory does: a bind is judged from the DN and
    the password it carries, and an *anonymous read of the rootDSE* is allowed even on a
    directory that refuses anonymous binds.  Judging the packet by whether the word
    "password" appears in it, as this responder first did, refuses both.
    """
    request = proto.parse_ldap(payload)
    message_id = bytes([request.get("message_id", 1) & 0xFF]) or b"\x01"
    if request.get("operation") == "bindRequest":
        bind = proto.ldap_bind_fields(payload)
        pairs = tuple(tuple(pair) for pair in host.profile.get("default_creds", ()))
        account = bind["dn"].split(",")[0].split("=")[-1].lower()
        known = any(pair[0].lower() == account and pair[1] == bind["password"]
                    for pair in pairs)
        anonymous = not bind["dn"] and not bind["password"]
        if known:
            return _ldap_result(message_id, 0)
        if anonymous:
            allowed = host.profile.get("anonymous") or not host.profile.get("auth_required")
            return _ldap_result(message_id, 0 if allowed else 48)
        return _ldap_result(message_id, 49)                    # invalidCredentials
    if request.get("operation") == "searchRequest":
        return _ldap_search_answer(host, message_id)
    return _ldap_result(message_id, 0)


def r_redis(host: LanHost, payload: bytes) -> bytes:
    if host.profile.get("auth_required") and not host.profile.get("anonymous"):
        return b"-NOAUTH Authentication required.\r\n"
    command = payload.decode("latin-1", "replace").upper()
    if "PING" in command:
        return b"+PONG\r\n"
    if "INFO" in command:
        return (f"$0\r\nredis_version:{host.firmware}\r\nos:Linux 5.15 x86_64\r\n"
                f"tcp_port:6379\r\nconnected_clients:3\r\nrole:master\r\n"
                f"total_commands_processed:48123\r\n").encode()
    if "CONFIG" in command:
        return b"*4\r\n$3\r\ndir\r\n$11\r\n/var/lib/red\r\n$8\r\ndbfilename\r\n$8\r\ndump.rdb\r\n"
    if "KEYS" in command:
        return b"*3\r\n$6\r\nconfig\r\n$5\r\nusers\r\n$5\r\nsess:\r\n"
    return b"+OK\r\n"


def _ldap_search_answer(host: LanHost, message_id: bytes) -> bytes:
    """A rootDSE search answered the way a directory answers one: attributes, then done."""
    attributes = (("namingContexts", "dc=example,dc=local"),
                  ("supportedLDAPVersion", "3"),
                  ("supportedSASLMechanisms", "GSSAPI DIGEST-MD5"),
                  ("serverName", host.hostname),
                  ("vendorName", host.vendor),
                  ("subschemaSubentry", "cn=Subschema"))
    parts = b""
    for name, value in attributes:
        parts += proto._ber_tlv(0x30, proto._ber_tlv(0x04, name.encode()) +
                                proto._ber_tlv(0x31, value.encode()))
    entry = proto._ber_tlv(0x64, proto._ber_tlv(0x04, host.vendor.lower().encode() +
                                                 b",dc=local") +
                           proto._ber_tlv(0x30, parts))
    done = proto._ber_tlv(0x65, proto._ber_tlv(0x0A, b"\x00") +
                          proto._ber_tlv(0x04, b"") + proto._ber_tlv(0x04, b""))
    return proto._ber_tlv(0x30, proto._ber_tlv(0x02, message_id) + entry + done)


def r_mongo(host: LanHost, payload: bytes) -> bytes:
    """An OP_MSG hello reply: a real BSON document, so the parser reads real fields."""
    document = proto.bson_document([
        ("isWritablePrimary", True),
        ("maxWireVersion", 9 if host.profile.get("legacy") else 17),
        ("minWireVersion", 0),
        ("maxBsonObjectSize", 16777216),
        ("maxMessageSizeBytes", 48000000),
        ("maxWriteBatchSize", 100000),
        ("version", host.firmware or "7.0.5"),
        ("ok", 1.0),
    ])
    body = proto.le32(0) + b"\x00" + document               # flagBits, then a body section
    return (proto.le32(21 + len(body)) + proto.le32(1) + proto.le32(0) + proto.le32(2013) +
            body)


def r_kasa(host: LanHost, payload: bytes) -> bytes:
    info = {"system": {"get_sysinfo": {"model": host.model, "alias": host.hostname,
                                       "relay_state": 1, "sw_ver": host.firmware,
                                       "mac": host.mac, "err_code": 0}}}
    raw = json.dumps(info).encode()
    encrypted = proto.kasa_encrypt(raw)
    return proto.be32(len(encrypted)) + encrypted


def r_cast(host: LanHost, payload: bytes) -> bytes:
    request = proto.parse_cast_message(payload)
    answer = json.dumps({"type": "RECEIVER_STATUS",
                         "requestId": 1,
                         "status": {"applications": [{"appId": "E8C28D3C",
                                                      "displayName": host.model,
                                                      "namespaces": []}]}})
    return proto.cast_message(request.get("namespace", "urn:x-cast:com.google.cast.tp"
                                          ".connection"),
                              answer, "receiver-0", request.get("source", "sender-0"))


def r_adb(host: LanHost, payload: bytes) -> bytes:
    if not host.profile.get("anonymous"):
        return proto.le32(proto.ADB_AUTH) + proto.le32(1) + proto.le32(0) + proto.le32(20) \
            + proto.le32(0) + proto.le32(proto.ADB_AUTH ^ 0xFFFFFFFF) + b"device::\x00"
    banner = f"device::{host.model}:{host.firmware}\x00"
    data = banner.encode()
    return proto.le32(proto.ADB_CNXN) + proto.le32(0x01000001) + proto.le32(4096) + \
        proto.le32(len(data)) + proto.le32(0) + proto.le32(proto.ADB_CNXN ^ 0xFFFFFFFF) + data


def r_vnc(host: LanHost, payload: bytes) -> bytes:
    """The version line, then the security types this server offers.

    ``none`` (type 1) is the finding: a kiosk configured for touch-and-go really does
    offer it, and a hardened host really does not.
    """
    if b"RFB" not in payload:
        return b"RFB 003.008\n"
    if host.profile.get("anonymous") or host.profile.get("unauthenticated"):
        types = b"\x01\x02"                                 # none and VNC auth
    elif host.profile.get("legacy"):
        types = b"\x02\x1E"                                 # VNC auth, then a Diffie-Hellman
    else:
        types = b"\x02"
    return b"RFB 003.008\n" + bytes([len(types)]) + types


def r_pjlink(host: LanHost, payload: bytes) -> bytes:
    text = payload.decode("latin-1", "replace").upper()
    if "POWR" in text:
        return b"%1POWR=1\r"
    if "NAME" in text:
        return f"%1NAME={host.hostname}\r".encode()
    if "LAMP" in text:
        return b"%1LAMP=12\r"
    return b"%1INFO=1\r"


def r_dicom(host: LanHost, payload: bytes) -> bytes:
    if payload[:1] == b"\x01":
        body = (b"\x00\x01\x00\x00" + b"WIFIPILOT        " + b"\x00" * 16 +
                b"ANY-SCP         " + b"\x00" * 16 + b"\x00" * 32)
        return bytes([0x02, 0x00]) + proto.be32(len(body)) + body
    return bytes([0x06, 0x00]) + proto.be32(4) + b"\x00\x00\x00\x00"


def r_s7(host: LanHost, payload: bytes) -> bytes:
    """The COTP connection confirm, then the SZL reply that names the rack.

    A connection request is answered *at the COTP level*: TPKT, the PDU length, the PDU
    type 0xD0 (connection confirm), the destination and source references swapped, the
    class-option byte and the three parameters every controller sends back.  Wrapping
    those bytes in a data PDU (0xF0) is a mistake no PLC makes, and a scanner that reads
    the PDU type would have called the device something else.
    """
    if len(payload) > 5 and payload[5] in (0xE0, 0xD0):
        params = b"\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x03"
        cotp = bytes([len(params) + 6, 0xD0]) + b"\x00\x00\x00\x0f\x00" + params
        return b"\x03\x00" + proto.be16(len(cotp) + 4) + cotp
    record = proto.szl_record(1, host.model, f"{host.vendor} {host.model}",
                              f"S {host.mac.replace(':', '')[:11].upper()}", host.vendor)
    data = b"\xff\x09" + proto.be16(len(record)) + b"\x00\x00" + record
    params = bytes([0x00, 0x01, 0x12, 0x08, 0x11, 0x44, 0x01, 0x00, 0x1C, 0x00, 0x00, 0x00])
    s7 = proto.s7_message(0x08, params, data)
    cotp = bytes([0x02, 0xF0, 0x80])
    return b"\x03\x00" + proto.be16(len(s7) + len(cotp) + 4) + cotp + s7


def r_cip(host: LanHost, payload: bytes) -> bytes:
    name = f"{host.vendor} {host.model}".encode()
    item = (proto.le16(1) + proto.le16(0x000C + len(name) + 1) + proto.le16(host.mac_vendor
            and 1 or 1))
    item = (proto.le16(1) + proto.le16(14 + len(name) + 1) + proto.le16(1) + proto.le16(1) +
            proto.le16(0x0001) + bytes([2, 1]) + proto.le16(0) + proto.le32(int(
                host.mac.replace(":", ""), 16) & 0xFFFFFFFF) + bytes([len(name)]) + name +
            b"\x00" + bytes([0x03]))
    return (proto.le16(0x0063) + proto.le16(len(item)) + proto.le32(0) + proto.le32(0) +
            b"\x01\x02\x03\x04\x00\x00\x00\x00" + proto.le32(0) + item)


def r_dnp3(host: LanHost, payload: bytes) -> bytes:
    """A link-status reply: DNP3 answers a reset with its own address, unauthenticated."""
    return proto.dnp3_reset_link(source=1024, destination=1)[:4] + b"\x0b\xc0\x01\x00" \
        + proto.dnp3_crc(b"\x05\x64\x0b")


def r_iec104(host: LanHost, payload: bytes) -> bytes:
    """STARTDT gets its confirmation; an interrogation gets the confirmation and then a
    measured value, which is what an outstation really sends."""
    request = proto.parse_iec104(payload)
    if request.get("u_function") == "STARTDT act":
        return proto.iec104_start(activate=False).replace(b"\x13", b"\x0b", 1)
    if request.get("i_frame"):
        common = request.get("common_address") or 1
        return (proto.iec104_confirmation(common_address=common, send_sequence=0,
                                          receive_sequence=1) +
                proto.iec104_measurement(ioa=16385, value=230.5, common_address=common,
                                         send_sequence=1, receive_sequence=1))


def r_opcua(host: LanHost, payload: bytes) -> bytes:
    body = (proto.le32(0) + proto.le32(65536) + proto.le32(65536) + proto.le32(65536) +
            proto.le32(0) + proto.le32(0))
    return b"ACKF" + proto.le32(len(body) + 8) + body


def r_ssh(host: LanHost, payload: bytes) -> bytes:
    return (f"SSH-2.0-OpenSSH_9.2p1 {host.vendor}\r\n"
            f"\x00\x00\x01\x14\x14").encode("latin-1") + b"\x00" * 16 + \
        b"curve25519-sha256,ecdh-sha2-nistp256\x00ssh-ed25519,rsa-sha2-512\x00" \
        b"aes256-gcm@openssh.com,chacha20-poly1305@openssh.com\x00" \
        b"hmac-sha2-256-etm@openssh.com\x00none,zlib@openssh.com\x00"


def r_rdp(host: LanHost, payload: bytes) -> bytes:
    nego = b"\x03\x00\x08\x00\x02\x00\x00\x00"                # PROTOCOL_SSL | HYBRID
    x224 = bytes([7 + len(nego), 0xD0]) + proto.be16(0) + b"\x00" + bytes([len(nego)])
    return b"\x03\x00" + proto.be16(len(x224) + len(nego) + 4) + x224 + nego


def r_miio(host: LanHost, payload: bytes) -> bytes:
    request = proto.parse_miio_hello(payload)
    token = hashlib.sha256(host.mac.encode()).digest()[:16]
    body = proto.le32(request.get("device_id", 1)) + proto.le32(request.get("stamp", 0) + 1) \
        + token
    return b"\x21\x31" + proto.be16(32) + b"\x00" * 4 + body


def r_postgres(host: LanHost, payload: bytes) -> bytes:
    if host.profile.get("anonymous"):
        return b"R" + proto.be32(8) + proto.be32(0)               # AuthenticationOk
    return b"R" + proto.be32(12) + proto.be32(5) + b"\x01\x02\x03\x04"


def r_rsync(host: LanHost, payload: bytes) -> bytes:
    """The greeting, the module list, and — for an open module — a directory listing."""
    text = payload.decode("latin-1", "replace")
    greeting = b"@RSYNCD: 31.0\n"
    modules = f"wp-backup\t{host.hostname} backups\npublic\tshared files\n"
    if "#list" in text or not text.strip():
        return greeting + modules.encode()
    module = text.strip().splitlines()[-1].strip() if text.strip() else ""
    if module in ("wp-backup", "public") and (host.profile.get("anonymous") or
                                              host.profile.get("default_creds") or
                                              host.profile.get("unauthenticated") or
                                              host.profile.get("open_write")):
        listing = ("drwxr-xr-x          4096 2026/01/04 09:12:00 .\n"
                   "-rw-r--r--      12849152 2026/01/03 02:00:01 site-backup.tar.gz\n"
                   "-rw-------         31121 2026/01/04 08:59:44 wp-config.php.bak\n"
                   "drwxr-xr-x          4096 2025/12/19 17:41:23 uploads\n")
        return greeting + b"@RSYNCD: OK\n" + listing.encode() + b"\n@RSYNCD: EXIT\n"
    return greeting + b"@ERROR: auth failed on module " + module.encode() + b"\n"


def r_ftp(host: LanHost, payload: bytes) -> bytes:
    """Banner, USER/PASS, and the two accounts the demo devices accept.

    A probe usually sends USER and PASS in one packet, so the decision is made on the
    whole buffer: the profile decides which account works, exactly as the attack reads it.
    """
    text = payload.decode("latin-1", "replace")
    upper = text.upper()
    if "PASS" in upper:
        user = ""
        match = re.search(r"USER\s+(\S+)", text, re.I)
        if match:
            user = match.group(1).lower()
        password = ""
        match = re.search(r"PASS\s+(\S+)", text, re.I)
        if match:
            password = match.group(1)
        pairs = tuple(tuple(pair) for pair in host.profile.get("default_creds", ()))
        if (user, password) in pairs or tuple([user, password]) in pairs:
            return b"230 Login successful.\r\n"
        if user in ("anonymous", "ftp") and host.profile.get("anonymous"):
            return b"230 Anonymous access granted.\r\n"
        return b"530 Login incorrect.\r\n"
    if upper.startswith("USER"):
        return b"331 Please specify the password.\r\n"
    if upper.startswith("SYST"):
        return b"215 UNIX Type: L8\r\n"
    if upper.startswith("FEAT"):
        return b"211-Features:\r\n PASV\r\n UTF8\r\n211 End\r\n"
    return f"220 (vsFTPd 3.0.3) {host.hostname}\r\n".encode()


def r_smtp(host: LanHost, payload: bytes) -> bytes:
    text = payload.decode("latin-1", "replace").upper()
    if text.startswith("EHLO"):
        return (f"250-{host.hostname} ESMTP Postfix\r\n250-STARTTLS\r\n"
                f"250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n").encode()
    if text.startswith("MAIL FROM"):
        return b"250 2.1.0 Ok\r\n"
    return f"220 {host.hostname} ESMTP Postfix\r\n".encode()


def r_ssdp(host: LanHost, payload: bytes) -> bytes:
    location = f"http://{host.ip}/description.xml"
    return (b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nEXT:\r\n"
            b"LOCATION: " + location.encode() + b"\r\nSERVER: " +
            f"{host.vendor}/{host.firmware} UPnP/1.0 {host.model}/1.0".encode() +
            b"\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nUSN: uuid:" +
            hashlib.md5(host.mac.encode()).hexdigest().encode() +
            b"::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n")


def r_mdns(host: LanHost, payload: bytes) -> bytes:
    """A real mDNS answer: the question echoed, then an A record, and a PTR record when
    the query was the DNS-SD meta-query or a service type.  Demo honesty depends on this
    being a packet a resolver would actually accept."""
    question = proto.parse_dns(payload)
    asked = question["questions"][0] if question["questions"] else {"name": "_services._dns-sd._udp.local",
                                                                   "type": 12, "class": 1}
    qname = str(asked["name"]) or "_services._dns-sd._udp.local"
    qtype = int(asked.get("type", 12)) or 12
    qclass = int(asked.get("class", 1)) & 0x7FFF or 1
    name = f"{host.hostname}.local"
    question_bytes = proto.dns_name(qname) + proto.be16(qtype) + proto.be16(qclass)
    service = "_http._tcp.local" if "http" in (host.hostname + host.model).lower() \
        else "_ipp._tcp.local"
    answers: List[bytes] = []
    if qtype in (12, 255):
        owner = b"\xc0\x0c"                               # the question name, compressed
        target = proto.dns_name(service if "_services" in qname else name)
        answers.append(owner + proto.be16(12) + proto.be16(qclass) + proto.le32(4500) +
                       proto.be16(len(target)) + target)
    owner_host = proto.dns_name(name)
    address = bytes(int(part) for part in host.ip.split("."))
    answers.append(owner_host + proto.be16(1) + proto.be16(qclass | 0x8000) + proto.le32(120) +
                   proto.be16(4) + address)
    strings = [f"model={host.model}", f"fw={host.firmware}", f"vendor={host.vendor}"]
    txt = b"".join(bytes([len(s)]) + s.encode() for s in strings)
    answers.append(owner_host + proto.be16(16) + proto.be16(qclass | 0x8000) + proto.le32(4500) +
                   proto.be16(len(txt)) + txt)
    header = (proto.be16(0) + proto.be16(0x8400) + proto.be16(1) + proto.be16(len(answers)) +
              proto.be16(0) * 2)
    return header + question_bytes + b"".join(answers)


def r_memcached(host: LanHost, payload: bytes) -> bytes:
    """The text protocol: stats, version, and a get/set that the profile decides."""
    text = payload.decode("latin-1", "replace").strip()
    command = text.split(" ")[0].lower() if text else "stats"
    if command == "version":
        return f"VERSION {host.firmware}\r\n".encode()
    if command in ("get", "gets"):
        key = text.split(" ")[1] if len(text.split(" ")) > 1 else "key"
        if host.profile.get("anonymous") or host.profile.get("unauthenticated"):
            value = '{"session":"wp-demo-token","user":"admin"}'
            return (f"VALUE {key} 0 {len(value)}\r\n{value}\r\nEND\r\n").encode()
        return b"END\r\n"
    if command in ("set", "add", "replace"):
        if host.profile.get("open_write") or host.profile.get("anonymous") or \
                host.profile.get("unauthenticated"):
            return b"STORED\r\n"
        return b"NOT_STORED\r\n"
    if command in ("stats", "stats items", "stats sizes"):
        return ("STAT pid 1893\r\n"
                f"STAT version {host.firmware}\r\n"
                "STAT uptime 1912043\r\n"
                "STAT curr_items 4211\r\n"
                "STAT bytes 10293221\r\n"
                "STAT cmd_get 98112\r\n"
                "STAT cmd_set 29103\r\n"
                "STAT evictions 512\r\n"
                "END\r\n").encode()
    if command in ("quit",):
        return b"\r\n"
    return b"ERROR\r\n"


def r_mysql(host: LanHost, payload: bytes) -> bytes:
    """The initial handshake: version, connection id, capability flags and plugin."""
    legacy = bool(host.profile.get("legacy"))
    version = "5.5.62" if legacy else f"8.0.32-{host.vendor.lower()}"
    plugin = b"mysql_native_password" if legacy else b"caching_sha2_password"
    salt = bytes(range(1, 21))
    capabilities = 0x0000_FFFF & ~0x0000_0002          # everything but CLIENT_COMPRESS
    if not host.profile.get("tls"):
        capabilities &= ~0x0000_0800                   # CLIENT_SSL is *not* on offer
    packet = (b"\x0a" + version.encode() + b"\x00" +
              proto.le32(41207) + salt[:8] + b"\x00" +
              proto.le16(capabilities & 0xFFFF) + b"\x21" + b"\x02\x00" +
              proto.le16(capabilities >> 16) + bytes([len(salt) - 8]) + b"\x00" * 10 +
              salt[8:] + b"\x00" + plugin + b"\x00")
    return bytes([len(packet) & 0xFF, (len(packet) >> 8) & 0xFF, 0, 0]) + packet


def r_airplay(host: LanHost, payload: bytes) -> bytes:
    """AirPlay's /info as a text plist: model, build, and the pairing feature flags."""
    pin = host.profile.get("auth_required", False) and not host.profile.get("anonymous")
    body = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
            "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">"
            "<plist version=\"1.0\"><dict>"
            f"<key>model</key><string>{host.model.replace(' ', '')}</string>"
            f"<key>deviceid</key><string>{host.mac.upper()}</string>"
            f"<key>srcvers</key><string>220.68</string>"
            f"<key>osBuildVersion</key><string>18K802</string>"
            f"<key>features</key><integer>{0x5A7FFFF7 if pin else 0x5A7FFFF7 | 0x40000000}</integer>"
            f"<key>pk</key><data>{'0' * 64}</data>"
            f"<key>pi</key><string>{host.mac}</string>"
            f"<key>flags</key><integer>{0x4 if pin else 0x0}</integer>"
            "</dict></plist>")
    return (f"HTTP/1.1 200 OK\r\nContent-Type: text/x-apple-plist+xml\r\n"
            f"Content-Length: {len(body)}\r\nServer: AirTunes/220.68\r\n\r\n"
            + body).encode()


#: protocol id -> the responder that answers it.  A protocol that is absent here has no
#: simulated answer, and the attack that speaks it reports "no answer" in demo mode —
#: which is the honest outcome, not a finding.
RESPONDERS: Dict[str, Callable[[LanHost, bytes], bytes]] = {
    "http": _http_answer,
    "http_json": _http_answer,
    "docker": _http_answer,
    "kubernetes": _http_answer,
    "jenkins": _http_answer,
    "elastic": _http_answer,
    "mqtt": r_mqtt, "coap": r_coap, "modbus": r_modbus, "bacnet": r_bacnet,
    "rtsp": r_rtsp, "onvif": _http_answer, "ipp": r_ipp, "pjl": r_pjl,
    "telnet": r_telnet, "sip": r_sip, "cwmp": r_cwmp, "tr069": r_cwmp,
    "smb": r_smb, "ldap": r_ldap, "redis": r_redis, "mongo": r_mongo,
    "kasa": r_kasa, "cast": r_cast, "adb": r_adb, "vnc": r_vnc, "pjlink": r_pjlink,
    "dicom": r_dicom, "s7comm": r_s7, "cip": r_cip, "dnp3": r_dnp3, "iec104": r_iec104,
    "opcua": r_opcua, "ssh": r_ssh, "rdp": r_rdp, "miio": r_miio,
    "postgres": r_postgres, "rsync": r_rsync, "ftp": r_ftp,
    "smtp": r_smtp, "ssdp": r_ssdp, "mdns": r_mdns, "memcached": r_memcached,
    "mysql": r_mysql, "airplay": r_airplay,
}


class VirtualLan:
    """The demo network: hosts, their open ports, and the answers their services give."""

    def __init__(self, hosts: Optional[Sequence[LanHost]] = None, seed: int = 7) -> None:
        self.hosts: List[LanHost] = list(hosts) if hosts is not None else build_lan(seed=seed)
        self.exchanges = 0
        self.transcript: List[Dict[str, Any]] = []

    # -- lookups ----------------------------------------------------------- #
    def by_ip(self, ip: str) -> Optional[LanHost]:
        return next((host for host in self.hosts if host.ip == ip), None)

    def candidates(self, device_ids: Sequence[str] = (), port: Optional[int] = None,
                   profile: str = "") -> List[LanHost]:
        """Every host that matches, weakest profile first — the order a sweep walks.

        A run does not pick one address and hope: it walks the hosts of the right type on
        the right port and starts with the one whose profile says it answers before it
        asks questions.
        """
        wanted = set(device_ids or ())
        found = [host for host in self.hosts
                 if (not wanted or host.device in wanted)
                 and (not port or port in host.ports)
                 and (not profile or host.profile_name == profile)]
        return hosts_by_weakness(found)

    def pick(self, device_ids: Sequence[str] = (), port: Optional[int] = None,
             profile: str = "") -> Optional[LanHost]:
        """The weakest host that matches: by device type, by port, and by profile."""
        found = self.candidates(device_ids, port, profile)
        return found[0] if found else None

    def hosts_for(self, device_ids: Sequence[str] = ()) -> List[LanHost]:
        wanted = set(device_ids or ())
        return [host for host in self.hosts if not wanted or host.device in wanted]

    def open_ports(self, host: LanHost) -> List[int]:
        return sorted(host.ports)

    # -- conversations ----------------------------------------------------- #
    def respond(self, host: LanHost, port: int, payload: bytes,
                protocol: str = "") -> bytes:
        """Answer a request as the host would.  Records the exchange either way."""
        name = protocol or protocol_for(host, port)
        responder = RESPONDERS.get(name)
        answer = responder(host, payload) if responder else b""
        self.exchanges += 1
        self.transcript.append({"host": host.ip, "port": port, "protocol": name,
                                "request": len(payload), "response": len(answer),
                                "answered": bool(answer)})
        return answer

    def exchange(self, ip: str, port: int, payload: bytes,
                 protocol: str = "") -> bytes:
        host = self.by_ip(ip) or (self.hosts[0] if self.hosts else None)
        if host is None:
            return b""
        return self.respond(host, port, payload, protocol)

    # -- discovery --------------------------------------------------------- #
    def discover(self) -> List[Dict[str, Any]]:
        """What a sweep of this segment finds, with a first guess at each device."""
        out: List[Dict[str, Any]] = []
        for host in self.hosts:
            ranked = classify(ports=host.ports, hostname=host.hostname, vendor=host.vendor,
                              services=[host.device], hints=[host.model])
            row = host.to_dict()
            row["guesses"] = [{"device": dev.id, "label": dev.label, "score": score,
                               "evidence": evidence} for dev, score, evidence in ranked[:3]]
            out.append(row)
        return out

    def summary(self) -> Dict[str, Any]:
        by_device: Dict[str, int] = {}
        by_profile: Dict[str, int] = {}
        for host in self.hosts:
            by_device[host.device] = by_device.get(host.device, 0) + 1
            by_profile[host.profile_name] = by_profile.get(host.profile_name, 0) + 1
        return {"hosts": len(self.hosts), "exchanges": self.exchanges,
                "by_device": by_device, "by_profile": by_profile,
                "open_ports": sorted({port for host in self.hosts for port in host.ports})}
