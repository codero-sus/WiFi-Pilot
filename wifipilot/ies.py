# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Information elements: what a beacon actually says about a network's configuration.

Every beacon and probe response is a fixed header followed by a list of
*tagged* elements, and most of what an assessment reports as "configuration" lives
in those tags: the RSN element (AKM, ciphers, PMF), the WPS vendor element, the
HT/VHT/HE/EHT capability elements, the 802.11k/v/r elements, the country element,
the rates, the WMM/QoS element.  wifipilot's scanner reads airodump's CSV, which
throws all of that away — so this module reads the frames themselves, the same way
:mod:`wifipilot.wpa3` does for the RSN bits.

Everything here is read-only and offline: it decodes a capture (or a list of frames
somebody else produced) and reports what the network claims about itself.  The
findings are deliberately *configuration* findings — TKIP is still advertised, WPS is
open, PMF is absent, 802.11r is on without PMF, the country element is missing, an
obsolete 802.11b/g-only rate set, a 40 MHz channel in the 2.4 GHz band — because
those are the things a report can act on, unlike "the vendor name looks odd".
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Tuple

from .pcap import (SUBTYPE_ASSOC_REQ, SUBTYPE_ASSOC_RESP, SUBTYPE_BEACON,
                   SUBTYPE_PROBE_REQ, SUBTYPE_PROBE_RESP, SUBTYPE_REASSOC_REQ,
                   SUBTYPE_REASSOC_RESP, TYPE_MGMT, iter_frames)
from .util import mac_norm

__all__ = ["IE_NAMES", "InformationElement", "parse_ies", "BssElements",
           "capture_beacons", "ie_findings", "decode_ies", "WPS_VENDOR_OUI",
           "vendor_breakdown"]

#: element id -> name (the ones worth naming; the rest keep their number)
IE_NAMES = {
    0: "SSID", 1: "Supported rates", 2: "FH parameter set", 3: "DS parameter set",
    4: "CF parameter set", 5: "TIM", 6: "IBSS parameter set", 7: "Country",
    8: "Hopping pattern", 9: "Hopping pattern table", 10: "Request",
    11: "BSS load", 12: "EDCA parameter set", 13: "TSPEC", 14: "TCLAS",
    15: "Schedule", 16: "Challenge text", 32: "Power constraint",
    33: "Power capability", 34: "TPC request", 35: "TPC report",
    36: "Supported channels", 37: "Channel switch announcement",
    38: "Measurement request", 39: "Measurement report", 40: "Quiet",
    41: "IBSS DFS", 42: "ERP information", 45: "HT capabilities",
    46: "HT operation", 47: "20/40 BSS coexistence", 48: "RSN",
    50: "Extended supported rates", 52: "Mobility domain",
    54: "Supported operating classes", 57: "HT operation mode",
    59: "Supported channels (6 GHz)", 60: "QoS map", 61: "DSSS parameter set",
    62: "Multiple BSSID", 63: "Interworking", 68: "Mesh ID",
    70: "Mesh configuration", 72: "20/40 BSS coexistence (intolerant)",
    74: "Overlapping BSS scan", 76: "MMIE", 91: "MCCAOP advertisement overview",
    93: "Extended capabilities", 94: "FILS capabilities", 107: "Interworking (ext)",
    108: "QoS map (6 GHz)", 127: "Extended BSS load",
    191: "VHT capabilities", 192: "VHT operation", 193: "Extended BSS load",
    195: "VHT transmit power envelope", 196: "Channel switch wrapper",
    197: "AID", 199: "Operating mode notification", 201: "Reduced neighbor report",
    205: "6 GHz capabilities", 221: "Vendor specific",
    242: "WAVE", 255: "Element extension",
}

#: vendor elements start with a 3-byte OUI; WPS adds a one-byte type (0x04), so
#: the constants below are the four bytes that identify each element
WPS_VENDOR_OUI = b"\x00\x50\xf2\x04"
#: WMM/WME: the QoS element clients and APs advertise (type 0x02)
WMM_VENDOR_OUI = b"\x00\x50\xf2\x02"
#: the RSN/WPA1 vendor element (WPA1 is also advertised as a vendor IE, type 0x01)
WPA1_VENDOR_OUI = b"\x00\x50\xf2\x01"

#: 802.11v/k/r live in the extended capabilities + dedicated elements; these are the
#: elements worth mentioning in a report by name
FEATURE_ELEMENTS = {
    "Mobility domain": "802.11r (fast BSS transition)",
    "Extended capabilities": "802.11k/v/w (radio measurement, BSS transition, PMF)",
    "Reduced neighbor report": "802.11k neighbour reports",
    "BSS load": "802.11e/WMM load advertisement",
}

#: the 802.11b/g basic rate set (1, 2, 5.5, 11 Mb/s, basic-bit set)
LEGACY_RATES = (0x82, 0x84, 0x8B, 0x96)

#: "the network is 802.11g-era" is a per-BSS fact, not a per-frame one, so the walk
#: remembers which BSSIDs advertised HT/VHT/HE and annotates the entry afterwards
#: WPS configuration methods: single-bit names only.  The combined values in the
#: specification (0x0280 virtual push button, 0x0480 physical push button,
#: 0x2008/0x4008 display-pin variants) are *combinations*, so matching them with a
#: bitwise test would report them for unrelated masks — the human-readable variant
#: is derived from the bits instead.
WPS_CONFIG_METHODS = {
    0x0001: "USB", 0x0002: "Ethernet", 0x0004: "label", 0x0008: "display",
    0x0010: "external NFC", 0x0020: "internal NFC", 0x0040: "NFC interface",
    0x0080: "push button", 0x0100: "keypad",
}
#: The vendor ids element 221 is commonly carrying, named for the report.  This is a
#: display table, not an authority: the OUI itself is always printed next to the name,
#: and an unknown one is reported as its hex rather than guessed at.
VENDOR_NAMES = {
    "00:50:f2:00": "WMM (Wi-Fi Alliance)",
    "00:50:f2:01": "WPA1 (Wi-Fi Alliance)",
    "00:50:f2:02": "WMM (Wi-Fi Alliance)",
    "00:50:f2:04": "WPS (Wi-Fi Alliance)",
    "00:0f:ac:00": "WMM (IEEE 802.11)",
    "00:0f:ac:02": "WMM (IEEE 802.11)",
    "00:0f:ac:04": "WPS (IEEE 802.11)",
    "50:6f:9a:09": "Wi-Fi Alliance (Passpoint)",
    "00:03:7f:00": "Atheros",
    "00:0b:86:00": "Aruba Networks",
    "00:0c:43:00": "Ralink",
    "00:10:18:00": "Broadcom",
    "00:40:96:00": "Cisco / Aironet",
    "00:e0:4c:00": "Realtek",
}

#: bit 7 (virtual) and the display bit make the combined "virtual display pin" shape
WPS_PUSH_BUTTON_BITS = 0x0080
WPS_DISPLAY_BITS = 0x0008
WPS_KEYPAD_BITS = 0x0100
WPS_VIRTUAL_BIT = 0x2000
WPS_PHYSICAL_BIT = 0x4000

def method_names(mask: int) -> List[str]:
    """Human names for a WPS configuration-methods bitmask.

    The table is single-bit on purpose: ``0x0088`` is display *and* push button, and a
    naive ``mask & bit`` loop over combined constants reports bits that were never set.
    The two combinations the specification names explicitly are derived here instead.
    """
    if not mask:
        return []
    if mask == (WPS_PUSH_BUTTON_BITS | WPS_VIRTUAL_BIT):
        return ["virtual push button"]
    if mask == (WPS_PUSH_BUTTON_BITS | WPS_PHYSICAL_BIT):
        return ["physical push button"]
    names = [name for bit, name in WPS_CONFIG_METHODS.items() if mask & bit]
    if mask & WPS_DISPLAY_BITS and mask & WPS_VIRTUAL_BIT:
        names.append("virtual display pin")
    if mask & WPS_DISPLAY_BITS and mask & WPS_PHYSICAL_BIT:
        names.append("physical display pin")
    return names


@dataclass
class InformationElement:
    """One tagged element from a beacon, probe response or association frame."""

    tag: int
    length: int
    value: bytes

    @property
    def name(self) -> str:
        return IE_NAMES.get(self.tag, f"element {self.tag}")

    @property
    def oui(self) -> bytes:
        """The three-byte OUI, or empty when the element is too short to have one."""
        return self.value[:3] if self.length >= 3 else b""

    @property
    def vendor_id(self) -> bytes:
        """OUI plus the vendor type byte — what identifies WPS, WMM or WPA1."""
        return self.value[:4] if self.length >= 4 else b""

    def hex(self, limit: int = 64) -> str:
        return self.value[:limit].hex()

    def text(self) -> str:
        """A printable rendering: SSIDs and country codes decode, the rest is hex."""
        if self.tag == 0:
            return self.value.decode("utf-8", "replace").replace("\x00", "")
        if self.tag in (7,):
            return self.value.decode("ascii", "replace")
        return self.hex()

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {"id": self.tag, "name": self.name,
                                "length": self.length, "hex": self.hex()}
        if self.value and self.tag in (0, 7):
            data["text"] = self.text()
        if self.tag == 221 and self.oui:
            data["oui"] = self.oui.hex(":")
        return data


def parse_ies(payload: bytes) -> List[InformationElement]:
    """Walk a management frame's element list.

    A malformed length is reported honestly: the walk stops at the element whose
    length runs past the end of the frame rather than inventing an element, because
    a truncated capture is a normal thing for a capture file to contain.
    """
    out: List[InformationElement] = []
    offset = 0
    while offset + 2 <= len(payload):
        tag = payload[offset]
        length = payload[offset + 1]
        if offset + 2 + length > len(payload):
            out.append(InformationElement(tag, length, payload[offset + 2:]))
            break
        out.append(InformationElement(tag, length, payload[offset + 2:offset + 2 + length]))
        offset += 2 + length
    return out


def decode_ies(ies: Iterable[InformationElement]) -> Dict[str, Any]:
    """Turn an element list into the facts a report can quote."""
    elements = list(ies)
    facts: Dict[str, Any] = {
        "ssid": "", "channel": 0, "country": "", "rates": [], "ext_rates": [],
        "rsn": None, "wpa1": False, "wps": None, "wmm": False, "ht": False,
        "vht": False, "he": False, "eht": False, "pmf_capable": False,
        "pmf_required": False, "bss_load": None, "mobility_domain": "",
        "roaming": {"r": False, "k": False, "v": False}, "elements": [],
        "vendor_ouis": [], "extended_capabilities": None, "legacy_rates_only": False,
        "extended_bits": {}, "neighbour_report": [], "rm_enabled": None,
        "interworking": None, "hs20": None, "wmm_parameters": None, "ft_over_ds": False,
        "channel_width": "20 MHz", "max_mcs": 0, "tim": False, "power_constraint": None,
    }
    basic_rates: List[int] = []
    for element in elements:
        facts["elements"].append(element.to_dict())
        tag, value = element.tag, element.value
        if tag == 0:
            facts["ssid"] = element.text()
        elif tag == 1 or tag == 50:
            rates = [byte & 0x7F for byte in value]
            key = "rates" if tag == 1 else "ext_rates"
            facts[key] = [rate / 2 for rate in rates]
            basic_rates += [byte & 0x7F for byte in value if byte & 0x80]
        elif tag == 3 and value:
            facts["channel"] = value[0]
        elif tag == 5:
            facts["tim"] = True
        elif tag == 7 and value:
            facts["country"] = value[:2].decode("ascii", "replace")
        elif tag == 11 and len(value) >= 5:
            # the BSS Load element is station count (2), channel utilisation (1),
            # available admission capacity (2) — all little endian, in that order
            facts["bss_load"] = {
                "stations": int.from_bytes(value[0:2], "little"),
                "utilisation_percent": round(value[2] * 100 / 255),
                "available_admission": int.from_bytes(value[3:5], "little")}
        elif tag == 32 and value:
            facts["power_constraint"] = struct.unpack("b", value[:1])[0]
        elif tag == 45:
            facts["ht"] = True
            if len(value) >= 2:
                facts["channel_width"] = ("40 MHz" if value[1] & 0x04 else "20 MHz")
        elif tag in (191, 192):
            facts["vht"] = True
            if tag == 191 and len(value) >= 4:
                # the VHT MCS map packs four 2-bit maps per byte, one per stream count
                facts["max_mcs"] = max(facts["max_mcs"],
                                       max((value[3] >> shift) & 0x03 for shift in (0, 2, 4, 6)))
        elif tag == 54 and len(value) >= 3:
            # 802.11r: the mobility domain (MDID) and the capability byte
            facts["mobility_domain"] = value[:2].hex()
            facts["ft_over_ds"] = bool(value[2] & 0x01)
            facts["roaming"]["r"] = True
        elif tag == 52 and len(value) >= 13:
            # a neighbour report: 13 bytes per BSSID this AP will hand a client to
            entries = []
            for cursor in range(0, len(value) - 12, 13):
                entries.append({"bssid": ":".join(f"{byte:02x}" for byte in
                                                  value[cursor:cursor + 6]),
                                "operating_class": value[cursor + 10],
                                "channel": value[cursor + 11],
                                "phy": value[cursor + 12]})
            facts["neighbour_report"] = entries
        elif tag == 70:
            # RM enabled capabilities (802.11k): five bytes of measurements
            facts["rm_enabled"] = {"link_measurement": bool(value[0] & 0x02),
                                   "neighbour_report": bool(value[0] & 0x04),
                                   "beacon_passive": bool(value[0] & 0x08),
                                   "beacon_active": bool(value[0] & 0x10),
                                   "beacon_table": bool(value[0] & 0x20)} if value else None
            if value and value[0] & 0x04:
                facts["roaming"]["k"] = True
        elif tag == 107 and value:
            facts["interworking"] = {
                "network_type": value[0] & 0x0F, "internet": bool(value[0] & 0x10),
                "asra": bool(value[0] & 0x20), "esr": bool(value[0] & 0x40),
                "uesa": bool(value[0] & 0x80),
                "venue_group": (value[1] >> 4) if len(value) > 1 else 0}
        elif tag == 201:
            facts["roaming"]["k"] = True                         # RM vendor element
        elif tag == 255 and len(value) >= 1:
            # element extension (id 255): 0 = HE capabilities, others are 6 GHz / EHT
            facts["he"] = facts["he"] or value[0] == 35
            facts["eht"] = facts["eht"] or value[0] == 108
        elif tag == 127:
            # Extended Capabilities (tag 127 — not 93, which is why a tool that trusts
            # the wrong number reports 802.11v on networks that never heard of it).
            # The bits are numbered from the start of the element: 19 is BSS transition,
            # 24 is WNM sleep, 0 is 20/40 coexistence.
            facts["extended_capabilities"] = value.hex()
            facts["extended_bits"] = {
                "bss_transition": bool(value[2] & 0x08) if len(value) > 2 else False,
                "wnm_sleep": bool(value[3] & 0x01) if len(value) > 3 else False,
                "coexistence": bool(value[0] & 0x01),
                "channel_switch": bool(value[0] & 0x04)}
            if facts["extended_bits"]["bss_transition"]:
                facts["roaming"]["v"] = True
        elif tag == 48 and len(value) >= 2:
            facts["rsn"] = _decode_rsn(value)
            if facts["rsn"].get("mfpc"):
                facts["pmf_capable"] = True
            if facts["rsn"].get("mfpr"):
                facts["pmf_required"] = True
        elif tag == 221:
            vendor = element.vendor_id
            facts["vendor_ouis"].append(vendor.hex(":"))
            if vendor[:3] == WPS_VENDOR_OUI[:3] and vendor[3:4] == b"\x04":
                facts["wps"] = _decode_wps(value)
            elif vendor[:3] == WMM_VENDOR_OUI[:3] and vendor[3:4] in (b"\x02", b"\x00"):
                facts["wmm"] = True
                if vendor[3:4] == b"\x02" and len(value) >= 4:
                    facts["wmm_parameters"] = _decode_wmm_parameters(value)
            elif vendor[:3] == WPS_VENDOR_OUI[:3] and vendor[3:4] == b"\x11":
                # Hotspot 2.0: a release number and the ANQP domain the AP answers on
                facts["hs20"] = {"release": value[4] & 0x0F if len(value) > 4 else 0,
                                 "anqp_domain": int.from_bytes(value[5:7], "big")
                                 if len(value) > 6 else 0}
            elif vendor[:3] == WPA1_VENDOR_OUI[:3] and vendor[3:4] == b"\x01":
                facts["wpa1"] = True
    # a network advertising only the four legacy rates is 802.11b/g-only hardware
    facts["legacy_rates_only"] = bool(basic_rates) and set(basic_rates) <= set(LEGACY_RATES)
    facts["max_rate"] = max(facts["rates"] + facts["ext_rates"], default=0.0)
    return facts


def _decode_wmm_parameters(value: bytes) -> Dict[str, Any]:
    """The WMM Parameter element's four access-category records (EDCA parameters).

    ``value`` starts with the OUI and the element type, then a version and a QoS info
    byte, then four four-byte records: AIFSN (low nibble of byte 0), an exponent range
    (ECW min in bits 0-3, ECW max in bits 4-7 of byte 1), and the ACM bit in byte 2.
    """
    names = ("best effort", "background", "video", "voice")
    out: Dict[str, Any] = {"version": value[4] if len(value) > 4 else 0, "ac": {}}
    for index, name in enumerate(names):
        start = 6 + index * 4
        if start + 4 > len(value):
            break
        out["ac"][name] = {"aifsn": value[start] & 0x0F,
                           "ecw_min": value[start + 1] & 0x0F,
                           "ecw_max": (value[start + 1] >> 4) & 0x0F,
                           "acm": bool(value[start + 2] & 0x01)}
    return out


def _decode_rsn(value: bytes) -> Dict[str, Any]:
    """The RSN element, in the same shape :mod:`wifipilot.wpa3` reports."""
    from .wpa3 import CIPHER_SUITES, AKM_SUITES
    facts: Dict[str, Any] = {"version": int.from_bytes(value[:2], "little"),
                             "ciphers": [], "akm": [], "capabilities": 0}
    if len(value) < 6:
        return facts
    cursor = 2
    facts["group"] = CIPHER_SUITES.get(
        int.from_bytes(value[cursor:cursor + 4], "little") & 0xFF,
        f"cipher-{value[cursor]}")
    cursor += 4
    if cursor + 2 > len(value):
        return facts
    count = int.from_bytes(value[cursor:cursor + 2], "little")
    cursor += 2
    for _ in range(min(count, 8)):
        if cursor + 4 > len(value):
            return facts
        facts["ciphers"].append(CIPHER_SUITES.get(
            int.from_bytes(value[cursor:cursor + 4], "little") & 0xFF,
            f"cipher-{value[cursor]}"))
        cursor += 4
    if cursor + 2 > len(value):
        return facts
    count = int.from_bytes(value[cursor:cursor + 2], "little")
    cursor += 2
    for _ in range(min(count, 8)):
        if cursor + 4 > len(value):
            return facts
        facts["akm"].append(AKM_SUITES.get(
            int.from_bytes(value[cursor:cursor + 4], "little") & 0xFF,
            f"akm-{value[cursor]}"))
        cursor += 4
    if cursor + 2 <= len(value):
        facts["capabilities"] = int.from_bytes(value[cursor:cursor + 2], "little")
        facts["mfpc"] = bool(facts["capabilities"] & 0x0020)
        facts["mfpr"] = bool(facts["capabilities"] & 0x0010)
    facts["transition_mode"] = ("SAE" in facts["akm"] and "PSK" in facts["akm"])
    facts["tkip"] = any(cipher == "TKIP" for cipher in facts["ciphers"])
    return facts


def _decode_wps(value: bytes) -> Dict[str, Any]:
    """The WPS element: version, configuration methods, lock state, model names."""
    facts: Dict[str, Any] = {"present": True, "version": "", "methods": [],
                             "locked": None, "config_error": None, "model": "",
                             "manufacturer": "", "device_name": "", "serial": "",
                             "selected_registrar": None, "response_type": None}
    if len(value) < 6:
        return facts
    cursor = 4                          # OUI + type
    while cursor + 4 <= len(value):
        attr = int.from_bytes(value[cursor:cursor + 2], "big")
        length = int.from_bytes(value[cursor + 2:cursor + 4], "big")
        body = value[cursor + 4:cursor + 4 + length]
        cursor += 4 + length
        if attr == 0x1044 and len(body) >= 1:        # version
            facts["version"] = f"{body[0]}.{body[1] if len(body) > 1 else 0}"
        elif attr == 0x1053:                          # selected registrar
            facts["selected_registrar"] = bool(body and body[0])
        elif attr == 0x1057 and body:                 # response type
            facts["response_type"] = body[0]
        elif attr == 0x1012 and len(body) >= 2:       # config methods
            mask = int.from_bytes(body[:2], "big")
            facts["methods"] = method_names(mask)
            facts["config_methods_mask"] = mask
        elif attr == 0x1051 and body:                 # AP setup locked
            facts["locked"] = bool(body[0] & 0x01)
        elif attr == 0x1049 and body:                 # configuration error
            facts["config_error"] = int.from_bytes(body[:2], "big")
        elif attr == 0x1021:
            facts["manufacturer"] = body.decode("utf-8", "replace")
        elif attr == 0x1023:
            facts["model"] = body.decode("utf-8", "replace")
        elif attr == 0x1024:
            facts["model_number"] = body.decode("utf-8", "replace")
        elif attr == 0x1026:
            facts["device_name"] = body.decode("utf-8", "replace")
        elif attr == 0x104A:
            facts["serial"] = body.decode("utf-8", "replace")
    return facts


# --------------------------------------------------------------------------- #
# reading a capture
# --------------------------------------------------------------------------- #


@dataclass
class BssElements:
    """Everything one BSSID said about itself, plus how often we heard it."""

    bssid: str
    essid: str = ""
    frames: int = 0
    channel: int = 0
    hidden: bool = False
    facts: Dict[str, Any] = field(default_factory=dict)
    kinds: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"bssid": self.bssid, "essid": self.essid or "<hidden>",
                "frames": self.frames, "channel": self.channel,
                "hidden": self.hidden, "kinds": dict(self.kinds),
                "facts": {key: value for key, value in self.facts.items()
                          if key not in ("elements",)},
                "why": []}

    def summary(self) -> str:
        bits = []
        if self.facts.get("rsn"):
            bits.append("/".join(self.facts["rsn"]["akm"]) or "RSN")
        if self.facts.get("wpa1"):
            bits.append("WPA1")
        if self.facts.get("wps"):
            bits.append("WPS")
        for name in ("ht", "vht", "he"):
            if self.facts.get(name):
                bits.append(name.upper())
        if self.facts.get("pmf_required"):
            bits.append("PMF-required")
        elif self.facts.get("pmf_capable"):
            bits.append("PMF-capable")
        return ", ".join(bits) or "no RSN (open or WEP)"


_BEACON_LIKE = (SUBTYPE_BEACON, SUBTYPE_PROBE_RESP, SUBTYPE_ASSOC_RESP,
                SUBTYPE_REASSOC_RESP)


def capture_beacons(path: str, max_packets: int = 200_000,
                    kinds: Tuple[int, ...] = _BEACON_LIKE) -> Dict[str, Any]:
    """Decode the elements of every beacon-like frame in a capture, per BSSID."""
    from .pcap import _parse_frame

    networks: Dict[str, BssElements] = {}
    frames = 0
    for _ts, buf, start, length in iter_frames(str(path), max_packets=max_packets):
        parsed = _parse_frame(buf, start, length)
        if parsed is None:
            continue
        ftype, subtype, bssid, _station, payload_at = parsed
        if ftype != TYPE_MGMT or subtype not in kinds:
            continue
        bssid = mac_norm(bssid)
        if not bssid:
            continue
        frames += 1
        ies = parse_ies(bytes(buf[start + payload_at:start + length]))
        entry = networks.get(bssid)
        if entry is None:
            entry = networks[bssid] = BssElements(bssid=bssid)
        entry.frames += 1
        entry.kinds[_kind_name(subtype)] = entry.kinds.get(_kind_name(subtype), 0) + 1
        facts = decode_ies(ies)
        entry.facts = facts                       # the latest reading wins
        entry.channel = entry.channel or facts.get("channel", 0)
        if facts.get("ssid"):
            entry.essid = facts["ssid"]
        elif not entry.essid:
            entry.hidden = True
    for entry in networks.values():
        _annotate_legacy(entry)
    return {"path": str(path), "frames": frames,
            "networks": [entry.to_dict() for entry in networks.values()],
            "note": "read-only: beacon-likes decoded, nothing transmitted"}


def _annotate_legacy(entry: BssElements) -> None:
    """A network with no HT/VHT/HE and only the b/g basic rates is 802.11g-era kit."""
    facts = entry.facts
    if facts is None:                      # an entry built before anything was decoded
        entry.facts = facts = {}
    modern = bool(facts.get("ht") or facts.get("vht") or facts.get("he") or facts.get("eht"))
    rates = set(round(rate * 2) for rate in (facts.get("rates") or []))
    basic = {raw | 0x80 for raw in LEGACY_RATES}
    legacy_rates = bool(rates) and rates <= {raw & 0x7F for raw in basic}
    facts["legacy_rates_only"] = not modern and legacy_rates


def _kind_name(subtype: int) -> str:
    return {SUBTYPE_BEACON: "beacon", SUBTYPE_PROBE_RESP: "probe response",
            SUBTYPE_ASSOC_RESP: "association response",
            SUBTYPE_REASSOC_RESP: "reassociation response",
            SUBTYPE_PROBE_REQ: "probe request",
            SUBTYPE_ASSOC_REQ: "association request",
            SUBTYPE_REASSOC_REQ: "reassociation request"}.get(
                subtype, f"subtype {subtype}")


# --------------------------------------------------------------------------- #
# findings
# --------------------------------------------------------------------------- #


def ie_findings(networks: List[Dict[str, Any]],
                include_low: bool = True) -> List[Dict[str, str]]:
    """Configuration findings, worst first, for a list of decoded networks.

    Every finding names the element it came from, because "your network is
    insecure" is not a finding — "TKIP is still advertised in the RSN element" is.
    """
    out: List[Dict[str, str]] = []
    for entry in networks:
        bssid = entry.get("bssid", "")
        name = entry.get("essid") or "<hidden>"
        facts = entry.get("facts") or {}
        rsn = facts.get("rsn") or {}

        def add(kind: str, severity: str, title: str, detail: str) -> None:
            out.append({"kind": kind, "severity": severity, "bssid": bssid,
                        "title": title, "detail": detail})

        if not rsn and not facts.get("wpa1"):
            add("ie_open_network", "high", f"{name} is an open network",
                "no RSN element: traffic on this SSID is unencrypted and anyone in "
                "range is on the same layer-2 segment."
                + ("  The SSID is hidden, which is not a security control." 
                   if not facts.get("ssid") else ""))
        if facts.get("wpa1"):
            add("ie_wpa1", "high", f"{name} still advertises WPA1 (vendor element)",
                "WPA1/TKIP is deprecated (802.11-2012 removed it): the WPA1 multicast "
                "weaknesses apply and any client that can be pushed onto it loses "
                "CCMP.")
        if rsn.get("tkip"):
            add("ie_tkip", "high", f"{name} advertises TKIP in its RSN element",
                "TKIP (Michael) is deprecated and only present for old hardware; a "
                "client that associates with TKIP is open to the Beck-Tews and "
                "Michael countermeasure attacks.  Configure CCMP-only.")
        if rsn and not facts.get("pmf_capable"):
            add("ie_no_pmf", "low", f"{name} does not advertise PMF",
                "no MFPC bit in the RSN element: 802.11w is not available, so "
                "deauthentication and disassociation frames are unauthenticated.")
        elif rsn and facts.get("pmf_capable") and not facts.get("pmf_required"):
            add("ie_pmf_optional", "low", f"{name} makes PMF optional",
                "MFPC set, MFPR clear: a client may still associate without PMF, "
                "which is what a downgrade attack targets.  Enable PMF-required "
                "where the clients support it.")
        if rsn.get("transition_mode"):
            add("ie_wpa3_transition", "medium", f"{name} runs WPA2/WPA3 transition mode",
                "both SAE and PSK AKMs are advertised: clients, and therefore the "
                "WPA2 handshake, still use the weaker path.")
        wps = facts.get("wps")
        if wps and wps.get("present"):
            locked = wps.get("locked")
            methods = ", ".join(wps.get("methods") or []) or "unknown"
            severity = "high" if not locked else "medium"
            add("ie_wps_enabled", severity, f"{name} advertises WPS",
                f"WPS is enabled (config methods: {methods}); "
                + ("the AP reports itself unlocked, so Pixie-Dust or a PIN attempt "
                   "can be run." if not locked else
                   "the setup state is not reported as unlocked, so the AP may be "
                   "rate-limiting or locked."))
        if wps and wps.get("config_methods_mask") and \
                not (wps["config_methods_mask"] & WPS_PUSH_BUTTON_BITS):
            add("ie_wps_no_pbc", "low", f"{name} disables WPS push-button",
                "only PIN-based configuration is advertised: PIN methods are the "
                "ones with the known 11,000-attempt weakness.")
        if facts.get("roaming", {}).get("r") and not facts.get("pmf_required"):
            add("ie_ft_without_pmf", "medium",
                f"{name} uses 802.11r without required PMF",
                "fast BSS transition is advertised while management frames stay "
                "unauthenticated: FT frames are a known target when PMF is absent.")
        if facts.get("ht") and facts.get("channel_width") == "40 MHz" and \
                0 < facts.get("channel", 0) <= 14:
            add("ie_40mhz_2ghz", "low", f"{name} uses 40 MHz in the 2.4 GHz band",
                "40 MHz channels in 2.4 GHz occupy most of the band and collide with "
                "every neighbour; 20 MHz is the recommended setting.")
        if not facts.get("country"):
            add("ie_no_country", "low", f"{name} sends no country element",
                "without the country element the AP does not advertise its regulatory "
                "domain, which usually means the firmware is unconfigured (and on "
                "some hardware it means the wrong power/DFS rules).")
        if facts.get("legacy_rates_only"):
            add("ie_legacy_only", "medium", f"{name} advertises only 802.11b/g rates",
                "no HT/VHT/HE elements and only 1-11 Mb/s basic rates: this is "
                "802.11g-era hardware, which today means it cannot be patched "
                "independently of its mediocre crypto support.")
        if facts.get("bss_load") and \
                facts["bss_load"]["utilisation_percent"] >= 70:
            add("ie_busy_channel", "low", f"{name} reporting a busy channel",
                f"the AP says the channel is {facts['bss_load']['utilisation_percent']}% "
                f"utilised with {facts['bss_load']['stations']} stations: expect "
                f"packet loss, and expect the site to already know.")
    if not include_low:
        # "the housekeeping" is the whole low band, not one finding: a caller that
        # asked for the findings worth acting on gets none of the nice-to-know ones
        out = [item for item in out if item["severity"] != "low"]
    out.sort(key=lambda item: _SEVERITY_RANK.get(item["severity"], 9))
    return out


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def vendor_name(vendor_id: str) -> str:
    """A human name for a 4-byte vendor id, falling back to the id itself."""
    return VENDOR_NAMES.get(vendor_id, vendor_id)


def vendor_breakdown(networks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Which vendor ids a set of networks' elements carry, worst-offender first.

    The count is per *element*, not per network: an AP that sends WPS and WMM with the
    same OUI is reported as two rows, because they are two different elements and the
    reason an analyst looks at this table is to see which ones are present.
    """
    counts: Dict[str, int] = {}
    for entry in networks:
        for vendor_id in (entry.get("facts") or {}).get("vendor_ouis") or []:
            counts[vendor_id] = counts.get(vendor_id, 0) + 1
    return [{"oui": vendor_id, "vendor": vendor_name(vendor_id), "count": count}
            for vendor_id, count in sorted(counts.items(), key=lambda item: -item[1])]
