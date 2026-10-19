# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""802.11 frame parsing for attacks that have to *watch* an answer.

``pcap._parse_frame`` is built for speed over millions of stored frames and returns
offsets into a buffer; it deliberately throws away everything a live test needs — the
receiver/transmitter addresses, the fixed fields, and where the body starts.  This
module is the slow, complete parser: it takes one frame at a time and returns a dict an
attack can reason about.

What the attacks ask it:

* *Did the AP answer that association request, and with which status code?*
  (``status``)
* *Did the client leave — is there a deauth/disassoc to it, or a new association?*
* *Is this frame protected?* (the Protected Frame bit decides whether a SA Query or
  a disassociation was accepted, which is the PMF question)
* *Which action frame is this?* (SA Query, TDLS, RRM, BTM — the category/action pair)
* *Is that beacon a clone?* (TSF, interval, sequence number, IEs)

It is deliberately dependency-free and total: any frame, including malformed ones,
returns either a dict or ``None`` — never an exception, because it runs inside a capture
loop.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

TYPE_MGMT, TYPE_CTRL, TYPE_DATA = 0, 1, 2

SUBTYPE_NAMES = {
    (0, 0): "association request", (0, 1): "association response",
    (0, 2): "reassociation request", (0, 3): "reassociation response",
    (0, 4): "probe request", (0, 5): "probe response", (0, 8): "beacon",
    (0, 9): "ATIM", (0, 10): "disassociation", (0, 11): "authentication",
    (0, 12): "deauthentication", (0, 13): "action",
    (1, 11): "RTS", (1, 12): "CTS", (1, 13): "ACK",
    (2, 0): "data", (2, 4): "null data", (2, 8): "QoS data", (2, 12): "QoS null",
}

#: action-frame (category, action) names — the ones the attacks here generate and read
ACTION_NAMES = {
    (0, 0): "spectrum management request",
    (3, 0): "block ack request", (3, 1): "block ack",
    (5, 0): "radio measurement request", (5, 1): "radio measurement report",
    (5, 4): "neighbor report request", (5, 5): "beacon request",
    (6, 0): "FT authentication request", (6, 2): "FT authentication response",
    (8, 0): "SA Query request", (8, 1): "SA Query response",
    (9, 7): "unprotected BTM request", (10, 7): "protected BTM request",
    (10, 1): "BTM query", (12, 0): "TDLS teardown", (12, 2): "TDLS setup request",
    (7, 0): "SAE", (127, 0): "vendor specific",
}

#: authentication algorithm numbers
AUTH_ALGORITHMS = {0: "open system", 1: "shared key", 2: "fast BSS transition",
                   3: "SAE", 4: "SAE (H2E)", 128: "network EAP"}

#: status codes that tell an attacker or an auditor something
STATUS_CODES = {
    0: "success", 1: "unspecified failure", 2: "capabilities too high",
    3: "association denied: capabilities", 4: "outside scope of BSS",
    5: "association denied", 6: "outside authentication sequence", 7: "denied",
    9: "requested capability not supported", 10: "reassociation denied",
    11: "denied: must authenticate", 12: "authentication timed out",
    13: "denied: too many stations", 14: "denied: challenge failure",
    15: "challenge timeout", 16: "denied: unsupported algorithm",
    17: "denied: sequence", 18: "denied: challenge text",
    19: "denied: unsupported auth", 23: "denied: 802.1X closed",
    30: "denied: TKIP not allowed", 89: "denied: cipher not supported",
}

REASON_CODES = {
    1: "unspecified", 2: "previous auth invalid", 3: "station left",
    4: "inactivity", 5: "AP too busy", 6: "class 2 frame from unauthenticated station",
    7: "class 3 frame from unassociated station", 8: "station left BSS",
    9: "association expired", 15: "4-way handshake timeout", 16: "group key timeout",
    17: "handshake element mismatch", 18: "invalid group cipher",
    19: "invalid pairwise cipher", 23: "802.1X failed", 34: "disconnect: 802.1X",
    45: "PMF policy mismatch", 46: "denied: PMF required",
}


def _mac(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw[:6])


def parse_80211(frame: bytes) -> Optional[Dict[str, Any]]:
    """Parse one frame (without radiotap) into the fields the attacks read."""
    if len(frame) < 10:
        return None
    control = frame[0]
    if control & 0x03:                       # protocol version != 0
        return None
    ftype = (control >> 2) & 0x03
    subtype = (control >> 4) & 0x0F
    flags = frame[1]
    out: Dict[str, Any] = {
        "type": ftype, "subtype": subtype,
        "kind": SUBTYPE_NAMES.get((ftype, subtype), f"type {ftype}/{subtype}"),
        "retry": bool(flags & 0x08), "power_save": bool(flags & 0x10),
        "protected": bool(flags & 0x40), "more_data": bool(flags & 0x20),
        "order": bool(flags & 0x80), "length": len(frame),
        "addr1": "", "addr2": "", "addr3": "", "bssid": "", "station": "",
        "sequence": 0, "fragment": 0,
    }
    if ftype == TYPE_CTRL:
        if subtype == 11 and len(frame) >= 16:              # RTS
            out.update({"addr1": _mac(frame[4:10]), "addr2": _mac(frame[10:16])})
        elif subtype in (12, 13) and len(frame) >= 10:      # CTS / ACK
            out.update({"addr1": _mac(frame[4:10])})
        out["duration"] = int.from_bytes(frame[2:4], "little")
        out["bssid"] = out["addr1"]
        out["station"] = out["addr2"]
        return out
    if len(frame) < 24:
        return None
    out["addr1"] = _mac(frame[4:10])
    out["addr2"] = _mac(frame[10:16])
    out["addr3"] = _mac(frame[16:22])
    sequence = int.from_bytes(frame[22:24], "little")
    out["sequence"] = sequence >> 4
    out["fragment"] = sequence & 0x0F
    out["duration"] = int.from_bytes(frame[2:4], "little")
    if ftype == TYPE_MGMT:
        out["bssid"] = out["addr3"]
        out["station"] = out["addr2"] if out["addr3"] != out["addr2"] else out["addr1"]
        body = frame[24:]
        if subtype in (8, 5, 2, 0, 1, 3):
            if len(body) >= 12:
                out["timestamp"] = int.from_bytes(body[0:8], "little")
                out["interval"] = int.from_bytes(body[8:10], "little")
                out["capability"] = int.from_bytes(body[10:12], "little")
                out["essid"] = _first_ie(body[12:], 0)
                out["channel"] = _channel(body[12:])
                out["rsn"] = _first_ie(body[12:], 48)
                out["wps"] = _first_ie(body[12:], 221)
                out["body_offset"] = 36
            if subtype in (0, 2) and len(body) >= 4:
                out["capability"] = int.from_bytes(body[0:2], "little")
                out["listen_interval"] = int.from_bytes(body[2:4], "little")
                out["body_offset"] = 28
                out["essid"] = _first_ie(body[4:], 0)
            if subtype in (1, 3) and len(body) >= 6:
                out["capability"] = int.from_bytes(body[0:2], "little")
                out["status"] = int.from_bytes(body[2:4], "little")
                out["status_text"] = STATUS_CODES.get(out["status"], "unknown")
                out["aid"] = int.from_bytes(body[4:6], "little") & 0x3FFF
                out["body_offset"] = 30
                if subtype == 3 and len(body) >= 36:
                    out["essid"] = _first_ie(body[6:], 0)
        elif subtype == 4:                                 # probe request
            out["essid"] = _first_ie(body, 0)
            out["body_offset"] = 24
            out["randomised"] = _randomised(out["addr2"])
        elif subtype == 11 and len(body) >= 6:              # authentication
            out["algorithm"] = int.from_bytes(body[0:2], "little")
            out["algorithm_text"] = AUTH_ALGORITHMS.get(out["algorithm"], "unknown")
            out["auth_sequence"] = int.from_bytes(body[2:4], "little")
            out["status"] = int.from_bytes(body[4:6], "little")
            out["status_text"] = STATUS_CODES.get(out["status"], "unknown")
            out["body_offset"] = 30
        elif subtype in (10, 12) and len(body) >= 2:        # disassoc / deauth
            out["reason"] = int.from_bytes(body[0:2], "little")
            out["reason_text"] = REASON_CODES.get(out["reason"], "unknown")
            out["body_offset"] = 26
        elif subtype == 13 and len(body) >= 2:              # action
            out["category"] = body[0]
            out["action"] = body[1]
            out["action_text"] = ACTION_NAMES.get((body[0], body[1]),
                                                  f"action {body[0]}/{body[1]}")
            out["body_offset"] = 26
            if body[0] == 8 and len(body) >= 4:              # SA Query
                out["sa_query_token"] = int.from_bytes(body[2:4], "little")
            if body[0] == 5 and body[1] == 5 and len(body) >= 10:   # beacon request
                out["measurement_channel"] = body[3]
                out["regulatory_class"] = body[2]
                out["measurement_duration"] = int.from_bytes(body[4:6], "little")
            if body[0] in (9, 10) and body[1] == 7 and len(body) >= 7:   # BTM request
                # category, action, dialog token, request mode, timer(2), validity
                out["body_offset"] = 31
                out["btm_candidates"] = _btm_candidates(body[7:])
        return out
    # data frames: which addresses mean what depends on the DS bits
    to_ds, from_ds = bool(flags & 0x01), bool(flags & 0x02)
    if from_ds and not to_ds:
        out["bssid"], out["station"] = out["addr2"], out["addr1"]
    elif to_ds and not from_ds:
        out["bssid"], out["station"] = out["addr1"], out["addr2"]
    else:
        out["bssid"], out["station"] = out["addr3"], out["addr2"]
    header = 30 if (to_ds and from_ds) else 24
    if subtype & 0x08:
        header += 2                                          # QoS control
    if (subtype & 0x04) and len(frame) >= header + 4:         # null-data variants
        out["body_offset"] = header
        return out
    if len(frame) >= header + 8 and frame[header:header + 6] == b"\xaa\xaa\x03\x00\x00\x00":
        out["ethertype"] = int.from_bytes(frame[header + 6:header + 8], "big")
        out["payload"] = frame[header + 8:]
    else:
        out["payload"] = frame[header:] if len(frame) > header else b""
    out["body_offset"] = header
    return out


def _first_ie(body: bytes, wanted: int) -> bytes:
    offset = 0
    while offset + 2 <= len(body):
        tag = body[offset]
        length = body[offset + 1]
        value = body[offset + 2:offset + 2 + length]
        if tag == wanted:
            return value
        offset += 2 + length
    return b""


def _channel(body: bytes) -> int:
    value = _first_ie(body, 3)
    return value[0] if value else 0


def _randomised(mac: str) -> bool:
    """The locally-administered bit: a randomised (or spoofed) transmitter address."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def _btm_candidates(body: bytes) -> List[Dict[str, Any]]:
    """The neighbour-report list inside a BTM request body."""
    out: List[Dict[str, Any]] = []
    offset = 0
    while offset + 2 <= len(body):
        element = body[offset]
        length = body[offset + 1]
        chunk = body[offset + 2:offset + 2 + length]
        offset += 2 + length
        if element != 52 or not chunk:
            continue
        inner = chunk[1:]                     # first byte: the neighbour-report mode
        while len(inner) >= 13:
            out.append({"bssid": _mac(inner[0:6]), "opclass": inner[10],
                        "channel": inner[11]})
            inner = inner[13:]
    return out


def essid_of(frame: bytes) -> str:
    """SSID out of a beacon/probe-response frame, as text ('' when hidden)."""
    parsed = parse_80211(frame)
    if not parsed:
        return ""
    return parsed.get("essid", b"").decode("utf-8", "replace").strip("\x00")


def summary(parsed: Dict[str, Any]) -> str:
    """One line for a log: what the frame is, who it is between, what it says."""
    kind = parsed.get("kind", "frame")
    parts = [kind, f"{parsed.get('addr2') or parsed.get('station', '')} → "
                   f"{parsed.get('addr1', '')}"]
    for key in ("status_text", "reason_text", "action_text", "algorithm_text", "essid"):
        value = parsed.get(key)
        if isinstance(value, bytes):
            value = value.decode("utf-8", "replace").strip("\x00")
        if value:
            parts.append(f"{key.replace('_text', '')}={value}")
    if parsed.get("protected"):
        parts.append("protected")
    if parsed.get("retry"):
        parts.append("retry")
    return " · ".join(part for part in parts if part)


__all__ = ["ACTION_NAMES", "AUTH_ALGORITHMS", "REASON_CODES", "STATUS_CODES",
           "SUBTYPE_NAMES", "essid_of", "parse_80211", "summary"]
