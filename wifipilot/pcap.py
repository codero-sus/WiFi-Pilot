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
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1000),   # little endian, microseconds
    b"\xa1\xb2\xc3\xd4": (">", 1000),   # big endian
    b"\x4d\x3c\xb2\xa1": ("<", 1),      # little endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": (">", 1),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

# 802.11 frame types
TYPE_MGMT, TYPE_CTRL, TYPE_DATA = 0, 1, 2
SUBTYPE_BEACON, SUBTYPE_PROBE_REQ, SUBTYPE_PROBE_RESP, SUBTYPE_AUTH = 8, 4, 5, 11

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

    @property
    def label(self) -> str:
        return f"M{self.number} {self.station}->{self.bssid}" + (f" pmkid={self.pmkid}" if self.pmkid else "")


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

    def to_dict(self) -> Dict[str, object]:
        return {
            "bssid": self.bssid, "station": self.station,
            "messages": sorted(self.messages), "complete": self.complete,
            "pmkid": self.pmkid, "eapol": self.eapol_count,
            "first": self.first_ts, "last": self.last_ts,
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
        complete = [h for h in self.handshakes if h.complete]
        if complete:
            return max(complete, key=lambda h: h.eapol_count)
        return self.handshakes[0] if self.handshakes else None

    def to_dict(self) -> Dict[str, object]:
        return {
            "path": self.path, "format": self.format, "packets": self.packets,
            "data": self.data_packets, "mgmt": self.mgmt_packets, "beacons": self.beacons,
            "wep_data": self.wep_data, "eapol": self.eapol_messages,
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
    return ":".join(f"{x:02x}" for x in b)


def _iter_pcap(data: bytes) -> Iterator[Tuple[float, bytes]]:
    magic = data[:4]
    endian, divisor = PCAP_MAGIC[magic]
    header_len = 16
    offset = 24  # global header
    total = len(data)
    while offset + header_len <= total:
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack_from(endian + "IIII", data, offset)
        offset += header_len
        if incl_len > 262144 or offset + incl_len > total:
            break
        yield (ts_sec + ts_frac / (1_000_000.0 * divisor)), data[offset:offset + incl_len]
        offset += incl_len


def _iter_pcapng(data: bytes) -> Iterator[Tuple[float, bytes]]:
    offset = 0
    total = len(data)
    endian = "<"
    ts_resolution = 1_000_000.0
    while offset + 12 <= total:
        block_type = data[offset:offset + 4]
        if block_type == b"\x0a\x0d\x0d\x0a":            # SHB resets endianness
            byte_order_magic = data[offset + 8:offset + 12]
            endian = "<" if byte_order_magic == b"\x4d\x3c\x2b\x1a" else ">"
        block_len = struct.unpack_from(endian + "I", data, offset + 4)[0]
        if block_len < 12 or offset + block_len > total:
            break
        body = data[offset + 8: offset + block_len - 4]
        if block_type == b"\x06\x00\x00\x00":            # Enhanced Packet Block
            if len(body) >= 20:
                _, ts_high, ts_low, cap_len, _ = struct.unpack_from(endian + "IIIII", body, 0)
                timestamp = (ts_high << 32) | ts_low
                packet = body[20:20 + cap_len]
                yield timestamp / ts_resolution, packet
        elif block_type == b"\x03\x00\x00\x00":          # Simple Packet Block
            if len(body) >= 4:
                cap_len = struct.unpack_from(endian + "I", body, 0)[0]
                yield 0.0, body[4:4 + cap_len]
        elif block_type == b"\x01\x00\x00\x00":          # Interface Description Block
            if len(body) >= 8:
                ts_resolution = float(struct.unpack_from(endian + "I", body, 4)[0]) or 1_000_000.0
        offset += block_len


def _strip_radiotap(packet: bytes) -> bytes:
    """Remove radiotap/Prism/AVS headers, returning the 802.11 frame."""
    if len(packet) < 4:
        return packet
    version = packet[0]
    if version == 0 and len(packet) >= 4 and packet[2:4] != b"\x00\x00":
        header_len = struct.unpack_from("<H", packet, 2)[0]
        if 8 <= header_len <= len(packet):
            return packet[header_len:]
    if packet[:8] == b"\x44\x00\x00\x00\x02\x00\x00\x00":     # Prism monitoring header
        return packet[144:]
    if packet[:4] == b"\x00\x00\x00\x00" and len(packet) > 64:
        return packet[64:]
    return packet


def _parse_frame(frame: bytes) -> Optional[dict]:
    """Parse the bits of an 802.11 frame we care about."""
    if len(frame) < 24:
        return None
    fc = frame[0]
    flags = frame[1]                      # 802.11: FC byte 1 carries to/from DS + protection
    version = fc & 0x03
    ftype = (fc >> 2) & 0x03
    subtype = (fc >> 4) & 0x0F
    to_ds = bool(flags & 0x01)
    from_ds = bool(flags & 0x02)
    if version != 0:
        return None
    header_len = 24
    if ftype == TYPE_DATA and to_ds and from_ds:
        header_len = 30
    elif (ftype == TYPE_DATA and (to_ds or from_ds)) or (ftype == TYPE_MGMT and subtype in (SUBTYPE_BEACON, SUBTYPE_PROBE_RESP)):
        header_len = 24
    info: dict = {
        "type": ftype, "subtype": subtype, "bssid": "", "station": "",
        "payload": b"", "protected": bool(flags & 0x40), "to_ds": to_ds, "from_ds": from_ds,
    }
    if ftype == TYPE_MGMT:
        info["bssid"] = mac(frame[16:22])
        info["station"] = mac(frame[10:16])
        if len(frame) >= 36:
            info["payload"] = frame[36:]
    elif ftype == TYPE_DATA:
        addr1, addr2, addr3 = mac(frame[4:10]), mac(frame[10:16]), mac(frame[16:22])
        if from_ds and not to_ds:
            info["bssid"], info["station"] = addr2, addr1
        elif to_ds and not from_ds:
            info["bssid"], info["station"] = addr1, addr2
        else:
            info["bssid"], info["station"] = addr3, addr2
        if len(frame) > header_len:
            info["payload"] = frame[header_len:]
    elif ftype == TYPE_CTRL:
        return None
    return info


def _parse_eapol(payload: bytes) -> Optional[dict]:
    """LLC/SNAP -> EAPOL-Key, returning key_info/replay/KDE data."""
    if len(payload) < 8:
        return None
    index = payload.find(b"\xaa\xaa\x03\x00\x00\x00")
    if index < 0:
        return None
    data = payload[index + 6:]
    if len(data) < 4:
        return None
    ethertype = struct.unpack_from(">H", data, 0)[0]
    if ethertype != ETHERTYPE_EAPOL:
        return None
    eapol = data[2:]                     # skip the 2 byte ethertype
    if len(eapol) < 4:
        return None
    version, eapol_type, length = eapol[0], eapol[1], struct.unpack_from(">H", eapol, 2)[0]
    body = eapol[4:4 + length] if length else eapol[4:]
    if eapol_type != 3 or len(body) < 3:              # 3 = EAPOL-Key
        return None
    desc_type = body[0]
    if desc_type not in (2, 3):                       # RSN / WPA
        return None
    key_info = struct.unpack_from(">H", body, 1)[0]
    replay = struct.unpack_from(">Q", body, 5)[0] if len(body) >= 13 else 0
    is_pairwise = bool(key_info & 0x0008)
    key_ack = bool(key_info & 0x0080)
    install = bool(key_info & 0x0040)
    secure = bool(key_info & 0x0200)
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
    key_data_len = struct.unpack_from(">H", body, 93)[0] if len(body) >= 95 else 0
    key_data = body[95:95 + key_data_len] if key_data_len and len(body) >= 95 else b""
    pmkid = ""
    if key_data:
        position = key_data.find(KDE_PMKID)
        if position >= 0 and len(key_data) >= position + 20:
            pmkid = key_data[position + 4: position + 20].hex()
    nonce = body[13:45].hex() if len(body) >= 45 else ""
    return {
        "version": version, "number": number, "key_info": key_info,
        "replay": replay, "pmkid": pmkid, "has_kde": bool(key_data),
        "key_data_len": key_data_len, "nonce": nonce,
    }


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


# --------------------------------------------------------------------------- #
# public API
# --------------------------------------------------------------------------- #


def analyze_file(path: str, max_packets: int = 400_000) -> CaptureAnalysis:
    """Parse a capture file and report handshakes, PMKIDs and WEP IVs."""
    result = CaptureAnalysis(path=str(path))
    file_path = Path(path)
    if not file_path.exists():
        result.error = "file not found"
        return result
    try:
        data = file_path.read_bytes()
    except OSError as exc:
        result.error = str(exc)
        return result
    if not data:
        result.error = "empty capture"
        return result

    if data[:4] == PCAPNG_MAGIC:
        packets = _iter_pcapng(data)
        result.format = "pcapng"
    elif data[:4] in PCAP_MAGIC:
        packets = _iter_pcap(data)
        result.format = "pcap"
    else:
        result.error = "not a pcap/pcapng file"
        return result

    handshakes: Dict[Tuple[str, str], Handshake] = {}
    seen_bssids = set()
    for timestamp, raw in packets:
        result.packets += 1
        if result.packets > max_packets:
            break
        frame = _strip_radiotap(raw)
        info = _parse_frame(frame)
        if not info:
            continue
        ftype, subtype = info["type"], info["subtype"]
        bssid, station = info["bssid"], info["station"]
        if bssid:
            seen_bssids.add(bssid)
        if ftype == TYPE_MGMT:
            result.mgmt_packets += 1
            if subtype == SUBTYPE_BEACON:
                result.beacons += 1
                if bssid and bssid not in result.essids:
                    ssid = essid_from_beacon(info["payload"])
                    if ssid:
                        result.essids[bssid] = ssid
            continue
        if ftype != TYPE_DATA:
            continue
        if subtype == 8:                       # QoS data
            pass
        result.data_packets += 1
        eapol = _parse_eapol(info["payload"])
        if eapol and eapol["number"] and not eapol.get("protected"):
            result.eapol_messages += 1
            key = (bssid, station)
            handshake = handshakes.setdefault(key, Handshake(bssid=bssid, station=station,
                                                             first_ts=timestamp))
            message = EapolMessage(
                bssid=bssid, station=station, number=eapol["number"],
                key_info=eapol["key_info"], replay=eapol["replay"],
                frame_time=timestamp, pmkid=eapol["pmkid"], has_kde=eapol["has_kde"],
                nonce=eapol["nonce"], raw=frame,
            )
            previous = handshake.messages.get(message.number)
            if previous is None or message.replay >= previous.replay:
                handshake.messages[message.number] = message
            if message.pmkid:
                handshake.pmkid = message.pmkid
                if not any(h.pmkid == message.pmkid for h in result.pmkids):
                    result.pmkids.append(Handshake(
                        bssid=bssid, station=station, pmkid=message.pmkid,
                        first_ts=timestamp, last_ts=timestamp, messages={1: message},
                    ))
            handshake.last_ts = timestamp
        else:
            # WEP: unencrypted-flag data frames with an IV header (no LLC/SNAP)
            if len(info["payload"]) > 4 and not result.essids.get(bssid, ""):
                result.wep_data += 1

    result.handshakes = list(handshakes.values())
    result.bssids = sorted(seen_bssids)
    return result


def quick_check(path: str) -> Tuple[bool, str]:
    """Fast ``(valid, human summary)`` used after each capture attempt."""
    analysis = analyze_file(path)
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
