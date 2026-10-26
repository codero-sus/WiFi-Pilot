# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Passive intelligence read out of a capture: probes, deauths, rogue twins.

Three questions a capture can answer without transmitting anything:

* **Who is looking for what?**  A client's probe requests name the networks it
  remembers (its preferred network list).  That is how you learn that the laptop
  in the lobby is looking for ``CorpNet`` — a target that may not be on air at
  all, and a much more interesting finding than the guest SSID it is actually
  associated with.
* **Is somebody being attacked right now?**  Deauthentication and disassociation
  frames are counted per BSSID, with broadcast floods called out separately: a
  burst of broadcast deauths is either a neighbour's broken router or an active
  attack on the environment.
* **Is there a twin?**  The same ESSID on two BSSIDs from different vendors, or
  a sudden new BSSID with the same name and a very different signal, is what an
  evil twin looks like from the outside.

Everything here is read-only: it parses a file that already exists.  Nothing in
this module transmits, associates or authenticates.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .pcap import (EAPOL_PREFIX, LLC_SNAP, SUBTYPE_DEAUTH, SUBTYPE_DISASSOC,
                   SUBTYPE_PROBE_REQ, TYPE_DATA, TYPE_MGMT, _parse_frame, iter_frames,
                   probe_request_essid)
from .util import mac_norm, oui_vendor

__all__ = ["probe_requests", "attack_frames", "rogue_aps", "passive_report",
           "ProbeClient", "eap_exchange", "x509_name", "EAP_METHOD_NAMES"]


@dataclass
class ProbeClient:
    """One station seen probing, and the networks it asked for."""

    mac: str
    ssids: List[str] = field(default_factory=list)
    broadcast: int = 0                 # wildcard probes ("any network?")
    directed: int = 0                  # probes for a named SSID
    vendor: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"mac": self.mac, "vendor": self.vendor, "ssids": self.ssids,
                "probes": self.directed + self.broadcast,
                "directed": self.directed, "broadcast": self.broadcast}

    @property
    def pnl(self) -> List[str]:
        """The preferred network list this client just handed us."""
        return list(self.ssids)


def probe_requests(path: str, limit: int = 500) -> Dict[str, ProbeClient]:
    """``{client_mac: ProbeClient}`` for every probe request in the capture.

    Probe requests are broadcast in the clear even on WPA3 networks, which is
    why this needs no injection and no association — and why it is a privacy
    problem worth reporting on a client's behalf.
    """
    clients: Dict[str, ProbeClient] = {}
    for _ts, buf, start, length in iter_frames(str(path)):
        parsed = _parse_frame(buf, start, length)
        if parsed is None:
            continue
        ftype, subtype, _bssid, _station, _payload = parsed
        if ftype != TYPE_MGMT or subtype != SUBTYPE_PROBE_REQ:
            continue
        client = mac_norm(buf[start + 10:start + 16].hex(":", 1))
        if not client:
            continue
        essid = probe_request_essid(buf, start, length)
        entry = clients.get(client)
        if entry is None:
            if len(clients) >= limit:
                continue                  # the report is capped, not the capture
            entry = clients[client] = ProbeClient(mac=client, vendor=oui_vendor(client))
        if essid:
            entry.directed += 1
            if essid not in entry.ssids and len(entry.ssids) < 64:
                entry.ssids.append(essid)
        else:
            entry.broadcast += 1
    return clients


def attack_frames(path: str) -> Dict[str, Any]:
    """Count deauth/disassoc frames and where they were aimed.

    A management deauthentication frame carries the AP's BSSID in ``addr3`` and
    the victim in ``addr1``; a broadcast victim is the "deny everyone" variant,
    so it is counted separately.
    """
    by_bssid: Dict[str, int] = {}
    broadcast = 0
    directed = 0
    total = 0
    types: Dict[str, int] = {"deauth": 0, "disassoc": 0}
    for _ts, buf, start, length in iter_frames(str(path)):
        parsed = _parse_frame(buf, start, length)
        if parsed is None:
            continue
        ftype, subtype, bssid, _station, _payload = parsed
        if ftype != TYPE_MGMT or subtype not in (SUBTYPE_DEAUTH, SUBTYPE_DISASSOC):
            continue
        total += 1
        types["deauth" if subtype == SUBTYPE_DEAUTH else "disassoc"] += 1
        bssid = mac_norm(bssid)
        by_bssid[bssid or "<unknown>"] = by_bssid.get(bssid or "<unknown>", 0) + 1
        if length >= 22:
            victim = buf[start + 4:start + 10]
            if victim == b"\xff\xff\xff\xff\xff\xff":
                broadcast += 1
            else:
                directed += 1
    ordered = sorted(by_bssid.items(), key=lambda item: -item[1])
    return {"total": total, "deauth": types["deauth"], "disassoc": types["disassoc"],
            "broadcast": broadcast, "directed": directed,
            "by_bssid": [{"bssid": bssid, "count": count} for bssid, count in ordered],
            "flood": total >= 100,
            "note": ("management frames are unauthenticated before 802.11w: a count "
                     "here is evidence of traffic, not of who sent it")}


def rogue_aps(aps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """ESSIDs served by more than one vendor — the outside view of a twin.

    Signal strength is included because the giveaway is usually *location*: a
    twin of a distant SSID that is suddenly local.  The detector reports the
    pattern and labels it as a pattern; it cannot prove intent.
    """
    by_essid: Dict[str, List[Dict[str, Any]]] = {}
    for ap in aps:
        essid = (ap.get("essid") or "").strip()
        if not essid:
            continue
        by_essid.setdefault(essid.lower(), []).append(ap)
    out: List[Dict[str, Any]] = []
    for essid, group in sorted(by_essid.items()):
        bssids = {ap.get("bssid", "") for ap in group}
        if len(bssids) < 2:
            continue
        vendors = {oui_vendor(ap.get("bssid", "")) for ap in group}
        vendors.discard("")
        signal_spread = _spread([ap.get("signal", -100) for ap in group])
        if len(vendors) < 2 and signal_spread < 25:
            continue
        out.append({
            "essid": group[0].get("essid", ""),
            "bssids": sorted(bssids),
            "vendors": sorted(vendors),
            "signal_spread_db": signal_spread,
            "reason": ("one ESSID seen from several vendors" if len(vendors) > 1
                       else "one ESSID with a very wide signal spread"),
            "confidence": "heuristic",
        })
    return out


def _spread(values: List[int]) -> int:
    clean = [value for value in values if isinstance(value, int)]
    return (max(clean) - min(clean)) if len(clean) > 1 else 0


# --------------------------------------------------------------------------- #
# 802.1X: the EAP conversation, offline
# --------------------------------------------------------------------------- #

#: EAP method codes -> name (RFC 3748 and the registry entries that matter here)
EAP_METHOD_NAMES = {
    1: "Identity", 2: "Notification", 3: "Nak", 4: "MD5-Challenge", 5: "OTP",
    6: "GTC", 13: "TLS", 17: "LEAP", 18: "SIM", 21: "TTLS", 23: "AKA", 25: "PEAP",
    26: "MSCHAPv2", 43: "FAST", 47: "AKA'", 50: "PWD", 55: "TEAP",
}

#: X.509 name attributes worth reporting, by OID
_NAME_OIDS = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
    "2.5.4.10": "O", "2.5.4.11": "OU", "1.2.840.113549.1.9.1": "emailAddress",
}


def _der_tlv(data: bytes, offset: int):
    """(tag, content, next_offset) at ``offset``, or ``None`` when malformed."""
    if offset + 2 > len(data):
        return None
    tag = data[offset]
    length = data[offset + 1]
    cursor = offset + 2
    if length & 0x80:                       # long form
        count = length & 0x7F
        if not count or cursor + count > len(data):
            return None
        length = int.from_bytes(data[cursor:cursor + count], "big")
        cursor += count
    end = cursor + length
    if end > len(data):
        return None
    return tag, data[cursor:end], end


def _der_oid(raw: bytes) -> str:
    if not raw:
        return ""
    parts = [raw[0] // 40, raw[0] % 40]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(part) for part in parts)


def _der_name(content: bytes) -> str:
    """An X.509 Name (RDNSequence) -> ``CN=..., O=...`` (best effort)."""
    pairs: List[str] = []
    offset = 0
    while offset < len(content):
        rdn = _der_tlv(content, offset)
        if rdn is None:
            break
        tag, body, offset = rdn
        if tag != 0x31:                     # SET OF AttributeTypeAndValue
            continue
        atv = _der_tlv(body, 0)
        if atv is None:
            continue
        _, attribute, _ = atv
        oid = _der_tlv(attribute, 0)
        value = _der_tlv(attribute, oid[2] if oid else 0)
        if oid is None or value is None or value[0] not in (0x0C, 0x13, 0x16):
            continue
        name = _NAME_OIDS.get(_der_oid(oid[1]))
        if not name:
            continue
        text = value[1].decode("utf-8", "replace").strip()
        if text:
            pairs.append(f"{name}={text}")
    return ", ".join(pairs)


def x509_name(der: bytes) -> Dict[str, Any]:
    """Subject/issuer of a DER certificate, and whether it signs itself.

    Only the parts needed for a finding are decoded: the two Names and whether
    they are identical (a self-signed certificate, i.e. one nobody can validate).
    """
    facts: Dict[str, Any] = {"subject": "", "issuer": "", "self_signed": False,
                             "serial": "", "sha1": ""}
    outer = _der_tlv(der, 0)
    if outer is None or outer[0] != 0x30:
        return facts
    inner = _der_tlv(outer[1], 0)
    if inner is None or inner[0] != 0x30:
        return facts
    body = inner[1]
    cursor = 0
    names: List[str] = []
    for _ in range(8):                       # version, serial, sigalg, issuer, validity…
        item = _der_tlv(body, cursor)
        if item is None:
            break
        tag, content, cursor = item
        if tag == 0xA0:                      # [0] EXPLICIT version
            continue
        if tag == 0x02 and not facts["serial"]:
            facts["serial"] = "".join(f"{byte:02x}" for byte in content[:8])
            continue
        if tag == 0x30:
            text = _der_name(content)
            if text:
                names.append(text)
                if len(names) == 2:
                    break
    # TBSCertificate puts the *issuer* first (after version/serial/signature) and the
    # *subject* after the validity window, so two names arrive in that order
    if names:
        facts["issuer"] = names[0]
        facts["subject"] = names[1] if len(names) > 1 else names[0]
    facts["self_signed"] = bool(len(names) > 1 and names[0] == names[1])
    try:
        import hashlib
        facts["sha1"] = hashlib.sha1(der).hexdigest()[:16]
    except Exception:                                 # pragma: no cover
        pass
    return facts


def _eap_header(body: bytes, offset: int):
    """An EAP header at ``offset``: (code, type, data_offset) or ``None``."""
    if offset + 4 > len(body):
        return None
    code, length = body[offset], int.from_bytes(body[offset + 2:offset + 4], "big")
    if code not in (1, 2):                     # Request / Response only
        return None
    data_at = offset + 5
    if data_at > len(body):
        return None
    return code, (body[offset + 4] if length else 0), data_at


def eap_exchange(path: str, limit_certs: int = 4) -> Dict[str, Any]:
    """Decode the EAP conversation in a capture: methods, identities, certificates.

    The 802.1X findings that matter are all in this function's output: which EAP
    method the network uses, the outer identity a client sends in the clear, and
    the certificate the server presents — including whether it is self-signed,
    which is the difference between "uses 802.1X" and "impersonable".
    """
    methods: List[str] = []
    identities: List[str] = []
    certificates: List[Dict[str, Any]] = []
    eapol = 0
    frames_scanned = 0
    for _ts, buf, start, length in iter_frames(str(path)):
        frames_scanned += 1
        parsed = _parse_frame(buf, start, length)
        if parsed is None:
            continue
        ftype, _subtype, _bssid, _station, payload_at = parsed
        if ftype != TYPE_DATA:
            continue
        start_at = start + payload_at
        end_at = start + length
        if start_at + 8 > end_at:
            continue
        # the payload starts at LLC/SNAP: 6 bytes of 802.2 header, 2 of ethertype,
        # then the EAPOL frame (version, type, length, ...) and the EAP message
        if bytes(buf[start_at:start_at + 8]) == EAPOL_PREFIX:
            frame = bytes(buf[start_at + 8:end_at])
        else:
            raw = bytes(buf[start_at:end_at])
            index = raw.find(LLC_SNAP)
            if index < 0:
                continue
            frame = raw[index + 8:]
        if len(frame) < 5:
            continue
        eapol += 1
        header = _eap_header(frame, 4)         # version, type, length, then EAP
        if header is None:
            continue
        _code, method, data_at = header
        name = EAP_METHOD_NAMES.get(method, f"type {method}" if method else "")
        if name and name not in methods:
            methods.append(name)
        if method == 1:                        # EAP Identity
            text = frame[data_at:data_at + 128].decode("utf-8", "replace")
            text = text.strip("\x00\r\n ")
            if text and text not in identities:
                identities.append(text)
        if method in (13, 21, 25, 43, 55):     # TLS-based: look for a certificate
            certificates.extend(_tls_certificates(frame[data_at:], limit_certs))
            if len(certificates) >= limit_certs:
                certificates = certificates[:limit_certs]
    return {"eapol": eapol, "methods": methods, "identities": identities,
            "certificates": certificates, "frames": frames_scanned,
            "note": ("decoded offline: EAP types, clear-text outer identities and "
                     "server certificates are all visible on air")}


def _tls_certificates(data: bytes, limit: int = 4) -> List[Dict[str, Any]]:
    """Certificates out of a TLS handshake record (PEAP/TTLS/TLS/EAP-TLS)."""
    out: List[Dict[str, Any]] = []
    index = 0
    while index + 6 < len(data) and len(out) < limit:
        # TLS record: type(1) version(2) length(2); 22 = handshake
        record_type = data[index]
        if record_type != 0x16:
            index += 1
            continue
        record_len = int.from_bytes(data[index + 3:index + 5], "big")
        record = data[index + 5:index + 5 + record_len]
        cursor = 0
        while cursor + 4 <= len(record) and len(out) < limit:
            msg_type = record[cursor]
            msg_len = int.from_bytes(record[cursor + 1:cursor + 4], "big")
            message = record[cursor + 4:cursor + 4 + msg_len]
            if msg_type == 0x0B:               # Certificate
                certificates = _parse_certificate_message(message)
                for der in certificates:
                    out.append(x509_name(der))
                if certificates:
                    break
            cursor += 4 + msg_len
        index += 5 + record_len if record_len else 1
    return out


def _parse_certificate_message(message: bytes) -> List[bytes]:
    """TLS Certificate message -> list of DER blobs."""
    out: List[bytes] = []
    if len(message) < 6:
        return out
    total = int.from_bytes(message[0:3], "big")
    cursor = 3
    seen = 0
    while cursor + 3 <= len(message) and seen <= total:
        size = int.from_bytes(message[cursor:cursor + 3], "big")
        cursor += 3
        if size <= 0 or cursor + size > len(message):
            break
        blob = message[cursor:cursor + size]
        if blob[:1] == b"\x30":
            out.append(blob)
        cursor += size
        seen += size
        if len(out) >= 4:
            break
    return out


def passive_report(path: str = "", aps: Optional[List[Dict[str, Any]]] = None,
                   limit: int = 40) -> Dict[str, Any]:
    """Everything the passive layer knows: probes, attacks, twins.

    ``path`` is a capture (optional); ``aps`` is the live target list (optional)
    — either one alone still produces a useful report.
    """
    report: Dict[str, Any] = {"path": str(path or ""), "probes": [], "attacks": {},
                              "rogue": [], "note": "read-only: nothing was transmitted"}
    if path and Path(path).exists():
        probes = probe_requests(path, limit=limit)
        report["probes"] = [entry.to_dict() for entry in
                            sorted(probes.values(), key=lambda item: -item.directed)]
        report["attacks"] = attack_frames(path)
    if aps:
        report["rogue"] = rogue_aps(list(aps))
    wanted: Dict[str, List[str]] = {}
    for entry in report["probes"]:
        for essid in entry["ssids"]:
            wanted.setdefault(essid, []).append(entry["mac"])
    report["wanted_networks"] = [{"essid": essid, "clients": macs}
                                 for essid, macs in sorted(wanted.items())]
    report["hidden_targets"] = [essid for essid in wanted
                                if not any(ap.get("essid", "").lower() == essid.lower()
                                           for ap in (aps or []))]
    return report
