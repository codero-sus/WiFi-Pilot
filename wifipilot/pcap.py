"""Minimal but real 802.11 capture parser (pure stdlib).

wifipilot does not trust a capture just because a tool wrote a file: it opens
the .cap/.pcapng itself and looks for

* EAPOL-Key message pairs (M1+M2 or M2+M3) => a crackable 4-way handshake
* RSN PMKID KDE inside EAPOL message 1        => a client-less PMKID hash
* the number of WEP data frames (IV harvest progress)

Supports classic pcap (both endiannesses, µs and ns) and pcapng (SHB/IDB/EPB/
SPB), plus radiotap / Prism / AVS headers.  Used for validation, for progress
reporting and by ``wifipilot analyze``.
"""

from __future__ import annotations

import re
import mmap
import struct
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

#: magic -> (byte order, fractions per second).  The divisor is what the record
#: header's sub-second field is measured in: a microsecond capture divides by
#: 1_000_000, a nanosecond one by 1_000_000_000.  Reading the microsecond magic with
#: a divisor of 1000 made every timestamp a thousandth of a second too early, which
#: silently turned "beacons at 10 per second" into "beacons at 10000 per second" for
#: every rate and drift calculation in the tool.
PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),      # little endian, microseconds
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),      # big endian
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),  # little endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

# 802.11 frame types
TYPE_MGMT, TYPE_CTRL, TYPE_DATA = 0, 1, 2
SUBTYPE_ASSOC_REQ, SUBTYPE_ASSOC_RESP, SUBTYPE_REASSOC_REQ, SUBTYPE_REASSOC_RESP = 0, 1, 2, 3
SUBTYPE_PROBE_REQ, SUBTYPE_PROBE_RESP = 4, 5
SUBTYPE_BEACON, SUBTYPE_ATIM, SUBTYPE_DISASSOC, SUBTYPE_AUTH, SUBTYPE_DEAUTH = 8, 9, 10, 11, 12
SUBTYPE_ACTION = 13

ETHERTYPE_EAPOL = 0x888E
KDE_PMKID = b"\x00\x0f\xac\x04"


@dataclass
class EapolMessage:
    bssid: str
    station: str
    number: int           # 1..4
    key_info: int
    replay: int
    frame_time: float
    pmkid: str = ""
    has_kde: bool = False
    nonce: str = ""       # ANonce (M1/M3) or SNonce (M2)
    raw: bytes = b""      # full 802.11 data frame, for MIC recomputation
    mic: bytes = b""      # the MIC as it appears on air (16 bytes)
    key_version: int = 0  # 1 = WPA/TKIP (HMAC-MD5), 2 = WPA2/RSN (AES-CMAC)
    key_len: int = 0
    install: bool = False
    encrypted: bool = False
    error: bool = False
    retransmits: int = 0  # identical frames seen after this one

    @property
    def from_ap(self) -> bool:
        return self.number in (1, 3)

    @property
    def mic_present(self) -> bool:
        return bool(self.key_info & 0x0100)

    @property
    def message(self) -> str:
        return f"M{self.number}"

    @property
    def flags(self) -> Dict[str, bool]:
        return {"install": self.install, "secure": bool(self.key_info & 0x0200),
                "ack": bool(self.key_info & 0x0080),
                "mic": bool(self.key_info & 0x0100),
                "encrypted": self.encrypted, "error": self.error}

    @property
    def label(self) -> str:
        return (f"M{self.number} {self.station}->{self.bssid}"
                + (f" pmkid={self.pmkid}" if self.pmkid else "")
                + (f" x{self.retransmits + 1}" if self.retransmits else ""))

    def to_dict(self) -> Dict[str, object]:
        return {
            "number": self.number, "bssid": self.bssid, "station": self.station,
            "key_info": self.key_info, "replay": self.replay, "nonce": self.nonce,
            "pmkid": self.pmkid, "mic": self.mic.hex(), "has_kde": self.has_kde,
            "key_version": self.key_version, "key_len": self.key_len,
            "flags": self.flags, "retransmits": self.retransmits,
            "time": self.frame_time,
        }


@dataclass
class Handshake:
    bssid: str
    station: str
    messages: Dict[int, EapolMessage] = field(default_factory=dict)
    pmkid: str = ""
    first_ts: float = 0.0
    last_ts: float = 0.0

    @property
    def anonce(self) -> str:
        message = self.messages.get(1) or self.messages.get(3)
        return message.nonce if message else ""

    @property
    def snonce(self) -> str:
        message = self.messages.get(2)
        return message.nonce if message else ""

    @property
    def can_verify_mic(self) -> bool:
        """Everything needed to recompute a MIC is present."""
        return bool(self.anonce and self.snonce
                    and (2 in self.messages or 4 in self.messages))

    @property
    def complete(self) -> bool:
        """Crackable means both nonces plus a MIC: M1+M2 (or M2+M3)."""
        has_pair = ((1 in self.messages and 2 in self.messages)
                    or (2 in self.messages and 3 in self.messages))
        return bool(has_pair and self.anonce and self.snonce)

    @property
    def eapol_count(self) -> int:
        return len(self.messages)

    @property
    def challenge(self) -> bool:
        """M1+M2: the pair every client actually produces (and WPA defines)."""
        return 1 in self.messages and 2 in self.messages

    @property
    def authorized(self) -> bool:
        """M2+M3: the pair produced when the handshake is completed."""
        return 2 in self.messages and 3 in self.messages

    @property
    def mic_message(self) -> Optional[EapolMessage]:
        """The message whose MIC a cracker recomputes (M2 first, then M4)."""
        for number in (2, 4):
            message = self.messages.get(number)
            if message is not None and message.mic:
                return message
        return None

    @property
    def score(self) -> int:
        """How good a cracking candidate this handshake is; higher is better.

        Ranked by what makes a *verifiable* MIC: a real challenge pair, then an
        authorized pair, then anything else; retransmitted frames and missing
        nonces cost nothing but add no value either.
        """
        if not self.can_verify_mic:
            return 0
        value = 3 if self.challenge else 2 if self.authorized else 1
        if self.mic_message is not None and not self.mic_message.retransmits:
            value += 1
        if self.pmkid:
            value += 1
        return value

    def to_dict(self) -> Dict[str, object]:
        return {
            "bssid": self.bssid, "station": self.station,
            "messages": sorted(self.messages), "complete": self.complete,
            "challenge": self.challenge, "authorized": self.authorized,
            "pmkid": self.pmkid, "eapol": self.eapol_count, "score": self.score,
            "first": self.first_ts, "last": self.last_ts,
            "detail": [m.to_dict() for _, m in sorted(self.messages.items())],
        }


@dataclass
class CaptureAnalysis:
    path: str = ""
    format: str = ""
    packets: int = 0
    data_packets: int = 0
    mgmt_packets: int = 0
    beacons: int = 0
    wep_data: int = 0
    eapol_messages: int = 0
    retransmits: int = 0
    handshakes: List[Handshake] = field(default_factory=list)
    pmkids: List[Handshake] = field(default_factory=list)
    bssids: List[str] = field(default_factory=list)
    essids: Dict[str, str] = field(default_factory=dict)
    error: str = ""

    @property
    def has_handshake(self) -> bool:
        return any(h.complete for h in self.handshakes)

    @property
    def has_pmkid(self) -> bool:
        return bool(self.pmkids) or any(h.pmkid for h in self.handshakes)

    @property
    def valid(self) -> bool:
        return self.has_handshake or self.has_pmkid or self.wep_data > 5000

    def best_handshake(self) -> Optional[Handshake]:
        """The most useful handshake: verifiable, challenge pair first."""
        complete = [h for h in self.handshakes if h.complete]
        if complete:
            return max(complete, key=lambda h: (h.score, h.eapol_count))
        return self.handshakes[0] if self.handshakes else None

    def crackable_handshakes(self) -> List[Handshake]:
        """Every handshake a MIC can be recomputed for, best first and unique.

        Retransmitted messages produce identical handshakes, and identical
        handshakes produce identical MIC checks: a long capture of one client
        must not cost one verification per copy.
        """
        seen = set()
        unique: List[Handshake] = []
        for handshake in sorted(self.handshakes, key=lambda h: -h.score):
            if not handshake.can_verify_mic:
                continue
            mic = handshake.mic_message
            key = (handshake.station, handshake.anonce, handshake.snonce,
                   mic.mic.hex() if mic else "")
            if key in seen:
                continue
            seen.add(key)
            unique.append(handshake)
        return unique

    def to_dict(self) -> Dict[str, object]:
        return {
            "path": self.path, "format": self.format, "packets": self.packets,
            "data": self.data_packets, "mgmt": self.mgmt_packets, "beacons": self.beacons,
            "wep_data": self.wep_data, "eapol": self.eapol_messages,
            "retransmits": self.retransmits,
            "handshakes": [h.to_dict() for h in self.handshakes],
            "pmkids": [h.to_dict() for h in self.pmkids],
            "bssids": self.bssids, "essids": self.essids,
            "has_handshake": self.has_handshake, "has_pmkid": self.has_pmkid,
            "valid": self.valid, "error": self.error,
        }


# --------------------------------------------------------------------------- #
# low level helpers
# --------------------------------------------------------------------------- #


def mac(b: bytes) -> str:
    """aa:bb:cc:dd:ee:ff — ``bytes.hex`` with a separator is a C-level fast path."""
    return b.hex(":", 1)


def _iter_pcap(data, start_offset: int = 0, endian: str = "",
               divisor: float = 0.0) -> Iterator[Tuple[float, int, int, int]]:
    """Yield ``(timestamp, offset, length, next_offset)`` for every packet record.

    Offsets instead of bytes: a 200 MB capture used to be sliced into millions of
    small ``bytes`` objects (copy + object header each), which dominated parsing
    time.  Callers read straight out of the buffer with ``struct.unpack_from`` or
    a one-off slice for the handful of frames they actually keep.

    ``start_offset`` makes the walk resumable, so a capture that is still being
    written can be parsed one appended chunk at a time.
    """
    if not endian:
        endian, divisor = PCAP_MAGIC[data[:4]]
    total = len(data)
    offset = start_offset or 24          # 24 byte global header
    while offset + 16 <= total:
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if incl_len > 262144 or offset + incl_len > total:
            break
        yield (ts_sec + ts_frac / divisor), offset, incl_len, offset + incl_len
        offset += incl_len


class _PcapngReader:
    """Resumable pcapng block walker.

    Larger than the pcap equivalent because pcapng keeps its timestamp
    resolution in interface blocks, which has to survive a resumed parse.
    """

    __slots__ = ("ts_resolution",)

    def __init__(self, ts_resolution: float = 1_000_000.0):
        self.ts_resolution = ts_resolution

    def rows(self, data, start_offset: int = 0) -> Iterator[Tuple[float, int, int, int]]:
        offset = start_offset
        total = len(data)
        endian = "<"
        resolution = self.ts_resolution
        while offset + 12 <= total:
            block_type = data[offset:offset + 4]
            if block_type == b"\x0a\x0d\x0d\x0a":            # SHB resets endianness
                byte_order_magic = data[offset + 8:offset + 12]
                endian = "<" if byte_order_magic == b"\x4d\x3c\x2b\x1a" else ">"
            block_len = struct.unpack_from(endian + "I", data, offset + 4)[0]
            if block_len < 12 or offset + block_len > total:
                break
            if block_type == b"\x06\x00\x00\x00":            # Enhanced Packet Block
                if block_len >= 32:
                    _, ts_high, ts_low, cap_len, _ = struct.unpack_from(
                        endian + "IIIII", data, offset + 8)
                    start = offset + 28
                    if cap_len and start + cap_len <= offset + block_len - 4:
                        yield ((ts_high << 32) | ts_low) / resolution, start, cap_len, \
                            offset + block_len
            elif block_type == b"\x03\x00\x00\x00":          # Simple Packet Block
                if block_len >= 16:
                    cap_len = struct.unpack_from(endian + "I", data, offset + 8)[0]
                    start = offset + 12
                    if cap_len and start + cap_len <= offset + block_len - 4:
                        yield 0.0, start, cap_len, offset + block_len
            elif block_type == b"\x01\x00\x00\x00":          # Interface Description Block
                if block_len >= 20:
                    resolution = float(struct.unpack_from(endian + "I", data, offset + 12)[0]) \
                        or 1_000_000.0
                    self.ts_resolution = resolution
            offset += block_len
        self.ts_resolution = resolution


def _radiotap_length(data, start: int, length: int) -> int:
    """Length of the radiotap/Prism/AVS header at ``start`` (0 if there is none).

    Byte comparisons rather than slices: no allocation, and this runs once per
    packet.
    """
    if length < 4:
        return 0
    if data[start] == 0 and (data[start + 2] or data[start + 3]):
        header_len = data[start + 2] | (data[start + 3] << 8)
        if 8 <= header_len <= length:
            return header_len
    if (data[start] == 0x44 and data[start + 1] == 0 and data[start + 2] == 0
            and data[start + 3] == 0 and length >= 8 and data[start + 4] == 0x02):
        return 144                                              # Prism header
    if length > 64 and not (data[start] or data[start + 1] or data[start + 2]
                            or data[start + 3]):
        return 64                                               # AVS header
    return 0


def _strip_radiotap(packet: bytes) -> bytes:
    """Remove radiotap/Prism/AVS headers, returning the 802.11 frame.

    Kept as a convenience for scripts; the parse loop uses
    :func:`_radiotap_length` with offsets and never copies the packet.
    """
    length = _radiotap_length(packet, 0, len(packet))
    return packet[length:] if length else packet


def _parse_frame(buf, start: int, length: int):
    """The bits of an 802.11 frame we care about, read straight out of the buffer.

    Returns ``(type, subtype, bssid, station, payload_offset)`` or ``None``.
    A tuple (not a dict) and offsets (not slices) because this runs for every
    packet in a capture: millions of small allocations dominate otherwise.
    """
    if length < 24:
        return None
    fc = buf[start]
    if fc & 0x03:                          # not an 802.11 frame
        return None
    ftype = (fc >> 2) & 0x03
    subtype = (fc >> 4) & 0x0F
    flags = buf[start + 1]
    if ftype == TYPE_MGMT:
        # management frames only ever contribute their BSSID here: don't format
        # the transmitter address for every beacon in a multi-megabyte capture
        payload = 36 if length >= 36 else length
        return ftype, subtype, buf[start + 16:start + 22].hex(":", 1), "", payload
    if ftype == TYPE_DATA:
        to_ds = flags & 0x01
        from_ds = flags & 0x02
        if from_ds and not to_ds:
            bssid = buf[start + 10:start + 16].hex(":", 1)
            station = buf[start + 4:start + 10].hex(":", 1)
        elif to_ds and not from_ds:
            bssid = buf[start + 4:start + 10].hex(":", 1)
            station = buf[start + 10:start + 16].hex(":", 1)
        else:
            bssid = buf[start + 16:start + 22].hex(":", 1)
            station = buf[start + 10:start + 16].hex(":", 1)
        header_len = 30 if (to_ds and from_ds) else 24
        payload = header_len if length > header_len else length
        return ftype, subtype, bssid, station, payload
    if ftype == TYPE_CTRL:
        return None
    return ftype, subtype, "", "", length


def essid_from_beacon(payload: bytes) -> str:
    """Beacon/probe-response IEs -> SSID ('' for hidden)."""
    offset = 0
    while offset + 2 <= len(payload):
        tag = payload[offset]
        length = payload[offset + 1]
        value = payload[offset + 2: offset + 2 + length]
        if tag == 0 and length:
            return value.decode("utf-8", "replace").replace("\x00", "")
        offset += 2 + length
    return ""


def probe_request_essid(buf, start: int, length: int) -> str:
    """The SSID a probe *request* asks for (``""`` for a wildcard probe).

    A probe request carries **no fixed fields**: the information elements start
    immediately after the 24-byte header, so the SSID element is the first thing in the
    body.  (Beacons and probe *responses* are the frames with a timestamp, an interval
    and a capability field before their elements — those are read with
    :func:`essid_from_beacon`.)  Reading this frame like a beacon used to make every
    directed probe look like a wildcard one, which turns "the client is asking for
    Corp-WiFi" into "the client is asking for anything" — the finding this function
    exists to produce.
    """
    body_start = start + 24
    if length <= 24:
        return ""
    return essid_from_beacon(bytes(buf[body_start:start + length]))


def _read_essid(buf, start: int, length: int, payload_at: int, bssid: str,
                essids: Dict[str, str]) -> None:
    """Record ``essids[bssid]`` from a beacon, once per BSSID."""
    if bssid in essids:
        return
    ssid = essid_from_beacon(bytes(buf[start + payload_at:start + length]))
    if ssid:
        essids[bssid] = ssid


#: first eight bytes of an EAPOL payload: LLC/SNAP + the EAPOL ethertype, which
#: is the common case and can therefore be tested in place with one slice
LLC_SNAP = b"\xaa\xaa\x03\x00\x00\x00"   # 802.2 header that precedes EAPOL
EAPOL_PREFIX = LLC_SNAP + b"\x88\x8e"


def _parse_eapol(payload: bytes) -> Optional[dict]:
    """LLC/SNAP -> EAPOL-Key, returning key_info/replay/KDE data."""
    if len(payload) < 8:
        return None
    index = payload.find(LLC_SNAP)
    if index < 0 or len(payload) < index + 8:
        return None
    return _parse_eapol_body(payload[index + 6:])


def _parse_eapol_body(body: bytes) -> Optional[dict]:
    """The EAPOL-Key parser, given the bytes at the ethertype (``88 8e``)."""
    if len(body) < 6:
        return None
    if struct.unpack_from(">H", body, 0)[0] != ETHERTYPE_EAPOL:
        return None
    return parse_eapol_frame(body[2:])     # skip the 2 byte ethertype


def parse_eapol_frame(eapol: bytes) -> Optional[dict]:
    """The EAPOL-Key parser, given a frame starting at the version byte.

    Returns ``None`` for anything that is not an EAPOL-Key; the nonce and the MIC
    come back as bytes because callers either store the hex form or hand the raw
    bytes to the crypto.

    The layout (IEEE 802.11i §8.5.2), offsets relative to this frame::

        0   EAPOL version (1 or 2)
        1   EAPOL type (3 = EAPOL-Key)
        2   body length
        4   key descriptor (2 = RSN/AES, 3 = WPA/TKIP)
        5   key information (flags)
        7   key length
        9   replay counter
        17  nonce (ANonce or SNonce, 32 bytes)
        49  key IV, 61 RSC, 69 key ID
        81  MIC (16 bytes)
        97  key data length, then key data (RSN IE, GTK, PMKID KDE ...)
    """
    if len(eapol) < 5:
        return None
    version, eapol_type, length = eapol[0], eapol[1], struct.unpack_from(">H", eapol, 2)[0]
    eapol_body = eapol[4:4 + length] if length else eapol[4:]
    if eapol_type != 3 or len(eapol_body) < 3:        # 3 = EAPOL-Key
        return None
    desc_type = eapol_body[0]
    if desc_type not in (2, 3):                       # RSN / WPA
        return None
    key_info = struct.unpack_from(">H", eapol_body, 1)[0]
    replay = struct.unpack_from(">Q", eapol_body, 5)[0] if len(eapol_body) >= 13 else 0
    is_pairwise = bool(key_info & 0x0008)
    key_ack = bool(key_info & 0x0080)
    secure = bool(key_info & 0x0200)
    install = bool(key_info & 0x0040)
    mic_present = bool(key_info & 0x0100)
    encrypted = bool(key_info & 0x1000)
    error_flag = bool(key_info & 0x0400)
    key_len = struct.unpack_from(">H", eapol_body, 3)[0] if len(eapol_body) >= 5 else 0
    if is_pairwise:
        if key_ack and not secure:
            number = 1
        elif key_ack and secure:
            number = 3
        elif not key_ack and secure:
            number = 4
        else:
            number = 2
    else:
        number = 0                                    # group key handshake
    # 802.11i EAPOL-Key body layout:
    #   type(1) keyinfo(2) keylen(2) replay(8) nonce(32) iv(16) rsc(8) keyid(8)
    #   mic(16) keydatalen(2) keydata(...)
    key_data_len = struct.unpack_from(">H", eapol_body, 93)[0] if len(eapol_body) >= 95 else 0
    key_data = (eapol_body[95:95 + key_data_len]
                if key_data_len and len(eapol_body) >= 95 else b"")
    pmkid = ""
    if key_data:
        position = key_data.find(KDE_PMKID)
        if position >= 0 and len(key_data) >= position + 20:
            pmkid = key_data[position + 4: position + 20].hex()
    nonce = eapol_body[13:45] if len(eapol_body) >= 45 else b""
    # the MIC is what proves a password: slice it once, here, instead of making
    # every consumer find the offset again
    mic = eapol_body[77:93] if mic_present and len(eapol_body) >= 93 else b""
    return {
        "version": version, "number": number, "key_info": key_info,
        "replay": replay, "pmkid": pmkid, "has_kde": bool(key_data),
        "key_data_len": key_data_len, "nonce": nonce, "mic": mic,
        "key_version": key_info & 0x0007, "key_len": key_len,
        "install": install, "encrypted": encrypted, "error": error_flag,
        "mic_present": mic_present,
    }



@dataclass
class _AnalysisState:
    """Resumable parse state.

    Captures are written while we read them — a handshake hunt polls the same
    ``.cap`` once a second — so this keeps the accumulator and the byte offset of
    the last complete record, and only the appended bytes get parsed.  Re-reading
    a growing file from the start was the largest recurring cost of an attack.

    The accumulator is deliberately *not* what callers receive: every call
    returns a fresh :class:`CaptureAnalysis` snapshot, so an object handed out
    earlier never changes underneath its owner.
    """

    path: str = ""
    format: str = ""
    error: str = ""
    packets: int = 0
    data_packets: int = 0
    mgmt_packets: int = 0
    beacons: int = 0
    wep_data: int = 0
    eapol_messages: int = 0
    retransmits: int = 0
    essids: Dict[str, str] = field(default_factory=dict)
    bssids: set = field(default_factory=set)
    handshakes: Dict[Tuple[str, str], Handshake] = field(default_factory=dict)
    pmkids: List[Handshake] = field(default_factory=list)
    seen_pmkids: set = field(default_factory=set)
    offset: int = 0                  # bytes consumed; always on a record boundary
    capped: bool = False             # stopped early because max_packets was reached
    max_packets: int = 400_000
    pcapng: "_PcapngReader" = field(default_factory=_PcapngReader)
    result: Optional[CaptureAnalysis] = None      # last snapshot handed out

    def snapshot(self) -> CaptureAnalysis:
        return CaptureAnalysis(
            path=self.path, format=self.format, packets=self.packets,
            data_packets=self.data_packets, mgmt_packets=self.mgmt_packets,
            beacons=self.beacons, wep_data=self.wep_data,
            eapol_messages=self.eapol_messages, retransmits=self.retransmits,
            handshakes=list(self.handshakes.values()), pmkids=list(self.pmkids),
            bssids=sorted(self.bssids), essids=dict(self.essids),
            error=self.error,
        )


#: path -> parse state (bounded, see ``_ANALYSIS_CACHE_MAX``)
_ANALYSIS_CACHE: "OrderedDict[str, _AnalysisState]" = OrderedDict()
_ANALYSIS_CACHE_MAX = 64


def clear_cache() -> None:
    """Forget cached capture analyses (used by tests and long-running services)."""
    _ANALYSIS_CACHE.clear()


def analyze_file(path: str, max_packets: int = 400_000,
                 use_cache: bool = True) -> CaptureAnalysis:
    """Parse a capture file and report handshakes, PMKIDs and WEP IVs.

    The file is memory-mapped and walked record by record, so a 200 MB capture
    costs no copy and only the frames we keep (EAPOL, beacons we need an SSID
    for) are sliced out.  Analyses are cached per path and *resumed* rather than
    repeated: an attack cycle — and every poll of a capture that is still being
    written — pays only for the bytes it has not seen yet.
    """
    file_path = Path(path)
    try:
        stat = file_path.stat()
    except OSError:
        result = CaptureAnalysis(path=str(path))
        result.error = "file not found"
        return result

    size = stat.st_size
    state = _ANALYSIS_CACHE.get(str(file_path)) if use_cache else None
    if state is not None:
        if state.error:
            state = None                              # retry an earlier failure
        else:
            _ANALYSIS_CACHE.move_to_end(str(file_path))
            if state.capped or state.offset >= size:
                if state.max_packets >= max_packets and state.result is not None:
                    return state.result               # nothing new to look at
            if size < state.offset:                   # truncated or replaced
                state = None

    if state is None:
        state = _AnalysisState(path=str(file_path))
        if not size:
            state.error = "empty capture"
            state.result = state.snapshot()
            return state.result

    try:
        handle = open(file_path, "rb")
    except OSError as exc:
        state.error = str(exc)
        state.result = state.snapshot()
        return state.result
    try:
        buf = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
    except (ValueError, OSError):          # empty/second-class files
        handle.close()
        try:
            with open(file_path, "rb") as plain:
                return _analyze_buffer(plain.read(), state, max_packets, use_cache)
        except OSError as exc:
            state.error = str(exc)
            state.result = state.snapshot()
            return state.result

    try:
        return _analyze_buffer(buf, state, max_packets, use_cache)
    finally:
        buf.close()
        handle.close()


def iter_frames(path: str, max_packets: int = 400_000):
    """Yield ``(timestamp, buffer, start, length)`` for every frame in a capture.

    Read-only, no state, no cache: the modules in :mod:`wifipilot.sniff` need to
    walk a capture themselves (probe requests, deauths) and they must not disturb
    the incremental analysis cache the attack cycle depends on.  The buffer is
    whatever the caller provided — an ``mmap`` slices fine, and slicing *offsets*
    keeps this allocation-free per packet.
    """
    file_path = Path(path)
    try:
        size = file_path.stat().st_size
    except OSError:
        return
    if not size:
        return
    with open(file_path, "rb") as handle:
        try:
            import mmap
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as buf:
                yield from _iter_frames_buffer(buf, size, max_packets)
        except (OSError, ValueError):                 # pragma: no cover - exotic FS
            data = handle.read()
            yield from _iter_frames_buffer(data, len(data), max_packets)


def _iter_frames_buffer(buf, size: int, max_packets: int):
    if not size:
        return
    if buf[:4] == PCAPNG_MAGIC:
        rows = _PcapngReader().rows(buf, 0)
    elif buf[:4] in PCAP_MAGIC:
        rows = _iter_pcap(buf, 0)
    else:
        return
    count = 0
    for timestamp, start, length, _next_offset in rows:
        if count >= max_packets:
            return
        count += 1
        header = _radiotap_length(buf, start, length)
        start += header
        length -= header
        if length < 24:
            continue
        yield timestamp, buf, start, length


def _analyze_buffer(buf, state: _AnalysisState, max_packets: int,
                    use_cache: bool) -> CaptureAnalysis:
    """The parser itself: works on anything supporting slicing (mmap or bytes)."""
    if not state.format:
        head = buf[:4]
        if head == PCAPNG_MAGIC:
            state.format = "pcapng"
        elif head in PCAP_MAGIC:
            state.format = "pcap"
        else:
            state.error = "not a pcap/pcapng file"
            state.result = state.snapshot()
            return state.result
    state.error = ""
    state.max_packets = max_packets

    if state.format == "pcapng":
        rows = state.pcapng.rows(buf, state.offset)
    else:
        rows = _iter_pcap(buf, state.offset)

    handshakes = state.handshakes
    pmkids = state.pmkids
    seen_pmkids = state.seen_pmkids
    bssids = state.bssids
    essids = state.essids
    packets = state.packets
    capped = False
    for timestamp, start, length, next_offset in rows:
        if packets >= max_packets:
            capped = True
            break
        packets += 1
        state.offset = next_offset
        header = _radiotap_length(buf, start, length)
        start += header
        length -= header
        if length < 24:
            continue
        parsed = _parse_frame(buf, start, length)
        if parsed is None:
            continue
        ftype, subtype, bssid, station, payload_at = parsed
        if bssid:
            bssids.add(bssid)
        if ftype == TYPE_MGMT:
            state.mgmt_packets += 1
            if subtype == SUBTYPE_BEACON:
                state.beacons += 1
                if bssid:
                    _read_essid(buf, start, length, payload_at, bssid, essids)
            continue
        if ftype != TYPE_DATA:
            continue
        state.data_packets += 1
        payload_start = start + payload_at
        payload_end = start + length
        # EAPOL always starts with LLC/SNAP immediately after the 802.11 header:
        # check those bytes in place so ordinary traffic costs no slice at all
        if payload_start + 8 <= payload_end:
            if buf[payload_start:payload_start + 8] == EAPOL_PREFIX:
                eapol = _parse_eapol_body(buf[payload_start + 6:payload_end])
            elif LLC_SNAP in buf[payload_start:payload_end]:
                eapol = _parse_eapol(buf[payload_start:payload_end])
            else:
                eapol = None
        else:
            eapol = None
        if eapol and eapol["number"]:
            state.eapol_messages += 1
            pair = (bssid, station)
            handshake = handshakes.get(pair)
            if handshake is None:
                handshake = handshakes[pair] = Handshake(bssid=bssid, station=station,
                                                         first_ts=timestamp)
            number = eapol["number"]
            replay = eapol["replay"]
            mic = eapol["mic"]
            previous = handshake.messages.get(number)
            if (previous is not None and replay == previous.replay
                    and mic == previous.mic):
                # an exact retransmission: same replay counter, same MIC.  Keep
                # the frame we already extracted (and measured) and count it.
                previous.retransmits += 1
                state.retransmits += 1
            elif previous is None or replay >= previous.replay:
                handshake.messages[number] = EapolMessage(
                    bssid=bssid, station=station, number=number,
                    key_info=eapol["key_info"], replay=replay,
                    frame_time=timestamp, pmkid=eapol["pmkid"], has_kde=eapol["has_kde"],
                    nonce=eapol["nonce"].hex(), raw=bytes(buf[start:start + length]),
                    mic=mic, key_version=eapol["key_version"], key_len=eapol["key_len"],
                    install=eapol["install"], encrypted=eapol["encrypted"],
                    error=eapol["error"],
                )
            if eapol["pmkid"] and eapol["pmkid"] not in seen_pmkids:
                seen_pmkids.add(eapol["pmkid"])
                pmkids.append(Handshake(
                    bssid=bssid, station=station, pmkid=eapol["pmkid"],
                    first_ts=timestamp, last_ts=timestamp,
                    messages={number: handshake.messages[number]},
                ))
            if eapol["pmkid"]:
                handshake.pmkid = eapol["pmkid"]
            handshake.last_ts = timestamp
        else:
            # anything that is not a numbered EAPOL-Key: on a network whose SSID
            # we never saw, this is how WEP IV traffic shows up
            if length > payload_at + 4 and not essids.get(bssid, ""):
                state.wep_data += 1

    state.packets = packets
    state.capped = capped
    state.result = result = state.snapshot()
    if use_cache:
        _ANALYSIS_CACHE[state.path] = state
        _ANALYSIS_CACHE.move_to_end(state.path)
        while len(_ANALYSIS_CACHE) > _ANALYSIS_CACHE_MAX:
            _ANALYSIS_CACHE.popitem(last=False)
    return result



def eapol_frame(message: EapolMessage) -> bytes:
    """The raw EAPOL-Key frame of a stored message (hashcat mode 22000 wants it).

    ``EapolMessage.raw`` is a whole 802.11 data frame; the EAPOL frame starts
    after LLC/SNAP + ethertype, which is why the MIC offset (81) is defined
    relative to the returned buffer.
    """
    from .crypto import _eapol_frame_from_bytes
    return _eapol_frame_from_bytes(message.raw)


def quick_check(path: str, use_cache: bool = True) -> Tuple[bool, str]:
    """Fast ``(valid, human summary)`` used after each capture attempt."""
    analysis = analyze_file(path, use_cache=use_cache)
    if analysis.error:
        return False, analysis.error
    bits = []
    if analysis.has_handshake:
        best = analysis.best_handshake()
        bits.append(f"handshake (EAPOL {best.eapol_count if best else '?'})")
    if analysis.has_pmkid:
        bits.append(f"PMKID x{len(analysis.pmkids)}")
    if analysis.wep_data:
        bits.append(f"{analysis.wep_data} data frames")
    if not bits:
        return False, "no handshake/PMKID in capture"
    return True, ", ".join(bits)


HANDSHAKE_RE = re.compile(r"(\d+)\s+handshake", re.I)


def aircrack_handshake_count(output: str) -> int:
    """Parse aircrack-ng's ``N handshake(s)`` line."""
    match = HANDSHAKE_RE.search(output)
    return int(match.group(1)) if match else 0
