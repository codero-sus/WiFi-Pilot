"""Wire codecs for the protocols an IT assessment meets: the bytes, and only the bytes.

Every function here either *builds* a request or *parses* a response, and every one of
them is written from the protocol's own document (RFC, vendor spec, or the field layout
of a protocol that never had an RFC at all).  Nothing in this module opens a socket:
:mod:`wifipilot.itsvc` sends what is built here, and :mod:`wifipilot.itsim` answers with
the same shapes when there is no network to send to.

The rule that keeps this honest: if a protocol appears here, the parser understands the
bytes the builder produces, and the tests assert a round trip.  Where a full codec was
out of scope for the wave, the protocol is simply absent — a service with no codec has
no attack, which is the correct outcome.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import socket
import struct
import zlib
from typing import Any, Dict, List, Optional, Sequence, Tuple

__all__ = [
    "be16", "be32", "le16", "le32", "le64", "be16_at", "be32_at", "le16_at", "le32_at",
    "printable", "bson_document", "parse_bson", "szl_record", "parse_szl", "IEC104_TYPES",
    "IEC104_COT", "iec104_confirmation", "iec104_measurement", "SZL_TEXT_SIZE",
    "HTTP_METHODS", "DEFAULT_HEADERS", "http_request", "parse_http_response", "http_json",
    "http_json_request", "parse_json_body", "MQTT_CONNECT", "MQTT_CONNACK", "MQTT_PUBLISH",
    "MQTT_SUBSCRIBE", "MQTT_SUBACK", "MQTT_DISCONNECT", "MQTT_REASONS", "mqtt_reason",
    "mqtt_connect", "mqtt_publish", "mqtt_subscribe", "mqtt_disconnect", "parse_mqtt",
    "COAP_CODES", "COAP_OPTIONS", "coap_packet", "parse_coap", "MODBUS_FUNCTIONS",
    "MODBUS_EXCEPTIONS", "modbus_request", "parse_modbus", "BACNET_SERVICES",
    "BACNET_BVLC", "bacnet_who_is", "bacnet_read_property", "parse_bacnet", "rtsp_request",
    "parse_rtsp", "parse_sdp", "SOAP_NS_ENVELOPE", "SOAP_NS_UPNP", "soap_envelope",
    "upnp_soap", "parse_soap", "onvif_get_device_information",
    "onvif_get_system_date_and_time", "onvif_get_stream_uri", "onvif_envelope",
    "parse_onvif", "IPP_OPERATIONS", "IPP_STATUS", "ipp_get_printer_attributes",
    "parse_ipp", "PJL_COMMANDS", "pjl_command", "parse_pjl", "TELNET_IAC",
    "TELNET_OPTIONS", "telnet_banner", "parse_telnet_negotiation",
    "parse_www_authenticate", "sip_request", "sip_register", "parse_sip", "CWMP_NS",
    "cwmp_inform", "cwmp_get_parameter_values", "parse_cwmp", "SMB2_DIALECTS",
    "smb2_negotiate", "parse_smb2", "netbios_query", "parse_netbios", "ldap_bind_request",
    "DNS_QTYPES", "MDNS_SERVICES", "dns_name", "dns_query", "parse_dns", "parse_mdns",
    "ssdp_msearch", "ssdp_notify", "parse_ssdp", "le16_at",
    "ldap_search_request", "parse_ldap", "ldap_attributes", "redis_command", "parse_resp",
    "MEMCACHED_COMMANDS", "memcached_command", "mongo_hello", "parse_mongo",
    "KASA_AUTOKEY", "kasa_encrypt", "kasa_decrypt", "kasa_command", "parse_kasa",
    "DICOM_PDU", "DICOM_SOP_VERIFICATION", "dicom_associate", "dicom_echo",
    "parse_dicom_pdu", "s7_connect_request", "s7_read_szl", "parse_s7",
    "cip_list_identity", "parse_cip", "dnp3_crc", "dnp3_reset_link", "dnp3_integrity_poll",
    "parse_dnp3", "iec104_start", "iec104_interrogation", "parse_iec104", "opcua_hello",
    "parse_opcua", "line_command", "parse_line_protocol", "smtp_ehlo", "imap_login",
    "ftp_login", "rsync_hello", "ssh_kexinit", "parse_ssh_algorithms",
    "rdp_negotiation_request", "parse_rdp", "vnc_version", "parse_vnc_security",
    "mysql_handshake_parse", "postgres_startup", "parse_postgres", "ntp_client",
    "parse_ntp", "stun_binding", "parse_stun", "ADB_CNXN", "ADB_AUTH", "ADB_OPEN",
    "ADB_OKAY", "adb_connect", "parse_adb", "pjlink_command", "parse_pjlink", "miio_hello",
    "parse_miio_hello", "cast_message", "parse_cast_message", "airplay_info_request",
    "parse_plist", "docker_version", "k8s_version", "jenkins_json", "tls_certificate_info",
    "tls_audit",
]

# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #


def be16(value: int) -> bytes:
    return struct.pack(">H", value & 0xFFFF)


def be32(value: int) -> bytes:
    return struct.pack(">I", value & 0xFFFFFFFF)


def le16(value: int) -> bytes:
    return struct.pack("<H", value & 0xFFFF)


def le32(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def le64(value: int) -> bytes:
    return struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)


def be16_at(data: bytes, offset: int) -> int:
    return struct.unpack_from(">H", data, offset)[0] if len(data) >= offset + 2 else 0


def be32_at(data: bytes, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0] if len(data) >= offset + 4 else 0


def le16_at(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0] if len(data) >= offset + 2 else 0


def le32_at(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0] if len(data) >= offset + 4 else 0


def printable(data: bytes) -> str:
    """Bytes as text, for banners: printable runs kept, the rest dropped."""
    text = "".join(chr(b) if 32 <= b < 127 or b in (9, 10, 13) else " " for b in data)
    return re.sub(r"[ \t]{2,}", " ", text).strip()


# --------------------------------------------------------------------------- #
# HTTP — the baseline every web-managed device speaks
# --------------------------------------------------------------------------- #

HTTP_METHODS = ("GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "TRACE", "PATCH",
                "PROPFIND", "SEARCH")

DEFAULT_HEADERS = {
    "User-Agent": "wifipilot-it/1.0",
    "Accept": "*/*",
    "Connection": "close",
}


def http_request(host: str, path: str = "/", method: str = "GET", port: int = 80,
                 headers: Optional[Dict[str, str]] = None, body: bytes = b"",
                 basic: Tuple[str, str] = ("", ""), host_header: bool = True) -> bytes:
    """A request line, headers and an optional body — the raw bytes, not an API call."""
    lines = [f"{method.upper()} {path or '/'} HTTP/1.1"]
    head = dict(DEFAULT_HEADERS)
    if host_header:
        head["Host"] = f"{host}:{port}" if port not in (80, 443) else host
    if basic[0] or basic[1]:
        token = base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode()
        head["Authorization"] = f"Basic {token}"
    if body:
        head["Content-Length"] = str(len(body))
    head.update(headers or {})
    for key, value in head.items():
        lines.append(f"{key}: {value}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def parse_http_response(data: bytes) -> Dict[str, Any]:
    """Status, headers, body and a couple of shapes that are always worth checking."""
    out: Dict[str, Any] = {"status": 0, "reason": "", "headers": {}, "body": "",
                           "body_bytes": b"", "server": "", "title": "", "length": 0}
    if not data:
        return out
    head, _, body = data.partition(b"\r\n\r\n")
    if not _:
        head, _, body = data.partition(b"\n\n")
    lines = head.decode("latin-1").splitlines()
    if lines:
        parts = lines[0].split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            out["status"] = int(parts[1])
            out["reason"] = parts[2] if len(parts) > 2 else ""
    for line in lines[1:]:
        key, _, value = line.partition(":")
        if key:
            out["headers"][key.strip().lower()] = value.strip()
    out["body_bytes"] = body
    out["body"] = body.decode("utf-8", "replace")
    out["length"] = len(body)
    out["server"] = out["headers"].get("server", "")
    match = re.search(r"<title[^>]*>(.*?)</title>", out["body"], re.I | re.S)
    out["title"] = re.sub(r"\s+", " ", match.group(1)).strip() if match else ""
    return out


def http_json(data: bytes) -> Dict[str, Any]:
    """The body of an HTTP response as JSON, or an empty dict."""
    parsed = parse_http_response(data)
    return parse_json_body(parsed.get("body_bytes", b""))


def http_json_request(host: str, port: int, path: str, method: str = "GET",
                      payload: Optional[Dict[str, Any]] = None,
                      headers: Optional[Dict[str, str]] = None,
                      basic: Tuple[str, str] = ("", "")) -> bytes:
    """A JSON API request: the shape Elasticsearch, Docker, Kubernetes and Jenkins use."""
    body = b""
    head = dict(headers or {})
    if payload is not None:
        body = json.dumps(payload).encode()
        head.setdefault("Content-Type", "application/json")
    head.setdefault("Accept", "application/json")
    return http_request(host, path, method, port, head, body, basic)


def parse_json_body(data: bytes) -> Dict[str, Any]:
    if not data:
        return {}
    try:
        loaded = json.loads(data.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return {}
    return loaded if isinstance(loaded, dict) else {"result": loaded}


# --------------------------------------------------------------------------- #
# MQTT 3.1.1 / 5.0 (1883, 8883)
# --------------------------------------------------------------------------- #

MQTT_CONNECT = 0x10
MQTT_CONNACK = 0x20
MQTT_PUBLISH = 0x30
MQTT_SUBSCRIBE = 0x82
MQTT_SUBACK = 0x90
MQTT_DISCONNECT = 0xE0

#: CONNACK return codes (3.1.1 §3.2.2.3, 5.0 §3.2.2.2 in the reason-code table below)
MQTT_REASONS = {
    0: "connection accepted", 1: "unacceptable protocol version", 2: "identifier "
    "rejected", 3: "server unavailable", 4: "bad user name or password",
    5: "not authorised", 0x80: "unspecified error", 0x81: "malformed packet",
    0x82: "protocol error", 0x83: "implementation specific error", 0x84: "unsupported "
    "protocol version", 0x85: "client identifier not valid", 0x86: "bad user name or "
    "password", 0x87: "not authorised", 0x88: "server unavailable", 0x89: "server busy",
    0x8A: "banned", 0x8C: "bad authentication method", 0x95: "packet too large",
    0x97: "quota exceeded", 0x9F: "connection rate exceeded",
}


def mqtt_reason(code: int) -> str:
    return MQTT_REASONS.get(code, f"return code {code}")


def _mqtt_string(value: str) -> bytes:
    raw = value.encode()
    return be16(len(raw)) + raw


def _mqtt_remaining(length: int) -> bytes:
    """The variable-length integer MQTT puts after the fixed header (3.1.1 §2.2.3)."""
    out = bytearray()
    while True:
        byte = length % 128
        length //= 128
        if length:
            byte |= 0x80
        out.append(byte)
        if not length:
            return bytes(out)


def mqtt_connect(client_id: str = "wifipilot", username: str = "", password: str = "",
                 keepalive: int = 30, clean_session: bool = True, version: int = 4,
                 will_topic: str = "", will_payload: bytes = b"") -> bytes:
    """CONNECT, with the flags byte built the way the spec numbers the bits."""
    flags = 0
    payload = _mqtt_string(client_id)
    if will_topic:
        flags |= 0x04                                   # will flag
        payload += _mqtt_string(will_topic) + be16(len(will_payload)) + will_payload
    if username:
        flags |= 0x80
        payload += _mqtt_string(username)
    if password:
        flags |= 0x40
        payload += _mqtt_string(password)
    if clean_session:
        flags |= 0x02
    variable = _mqtt_string("MQTT") + bytes([version, flags]) + be16(keepalive)
    body = variable + payload
    return bytes([MQTT_CONNECT]) + _mqtt_remaining(len(body)) + body


def mqtt_publish(topic: str, payload: bytes = b"", qos: int = 0, retain: bool = False,
                 packet_id: int = 1) -> bytes:
    header = MQTT_PUBLISH | ((qos & 0x03) << 1) | (1 if retain else 0)
    body = _mqtt_string(topic)
    if qos:
        body += be16(packet_id)
    body += payload
    return bytes([header]) + _mqtt_remaining(len(body)) + body


def mqtt_subscribe(topic: str, qos: int = 0, packet_id: int = 1) -> bytes:
    body = be16(packet_id) + _mqtt_string(topic) + bytes([qos & 0x03])
    return bytes([MQTT_SUBSCRIBE]) + _mqtt_remaining(len(body)) + body


def mqtt_disconnect() -> bytes:
    return bytes([MQTT_DISCONNECT, 0x00])


def parse_mqtt(data: bytes) -> Dict[str, Any]:
    """The fixed header, the remaining length and the fields a probe cares about."""
    out: Dict[str, Any] = {"type": 0, "type_name": "", "flags": 0, "length": 0,
                           "reason_code": -1, "session_present": False, "topic": "",
                           "payload": b"", "keepalive": 0, "properties": b""}
    if len(data) < 2:
        return out
    out["type"] = data[0] >> 4
    out["flags"] = data[0] & 0x0F
    out["type_name"] = {1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK",
                        5: "PUBREC", 6: "PUBREL", 7: "PUBCOMP", 8: "SUBSCRIBE",
                        9: "SUBACK", 10: "UNSUBSCRIBE", 11: "UNSUBACK", 12: "PINGREQ",
                        13: "PINGRESP", 14: "DISCONNECT", 15: "AUTH"}.get(out["type"], "")
    offset, multiplier, length = 1, 1, 0
    while offset < len(data) and offset < 6:
        byte = data[offset]
        length += (byte & 0x7F) * multiplier
        multiplier *= 128
        offset += 1
        if not byte & 0x80:
            break
    out["length"] = length
    body = data[offset:offset + length] if length else data[offset:]
    if out["type"] == 2 and len(body) >= 2:                  # CONNACK
        out["session_present"] = bool(body[0] & 0x01)
        out["reason_code"] = body[1]
        out["properties"] = body[2:]
    elif out["type"] == 3 and len(body) >= 2:                # PUBLISH
        topic_length = be16_at(body, 0)
        out["topic"] = body[2:2 + topic_length].decode("utf-8", "replace")
        out["payload"] = body[2 + topic_length:]
    elif out["type"] == 1 and len(body) >= 10:               # CONNECT
        out["keepalive"] = be16_at(body, 8)
    return out


# --------------------------------------------------------------------------- #
# CoAP (RFC 7252, 5683/udp, 5684/dtls)
# --------------------------------------------------------------------------- #

COAP_CODES = {
    1: "GET", 2: "POST", 3: "PUT", 4: "DELETE",
    65: "2.01 Created", 66: "2.02 Deleted", 67: "2.03 Valid", 68: "2.04 Changed",
    69: "2.05 Content", 95: "2.31 Continue", 128: "4.00 Bad Request",
    132: "4.04 Not Found", 133: "4.05 Method Not Allowed", 141: "4.13 Request Entity "
    "Too Large", 143: "4.15 Unsupported Content-Format", 160: "5.00 Internal Server "
    "Error", 161: "5.01 Not Implemented", 163: "5.03 Service Unavailable",
}

COAP_OPTIONS = {"If-Match": 1, "Uri-Host": 3, "ETag": 4, "If-None-Match": 5,
                "Observe": 6, "Uri-Port": 7, "Location-Path": 8, "Uri-Path": 11,
                "Content-Format": 12, "Max-Age": 14, "Uri-Query": 15, "Accept": 17,
                "Location-Query": 20, "Block2": 23, "Block1": 27, "Size2": 28,
                "Size1": 60}


def _coap_option(first: bool, number: int, value: bytes, current: int = 0) -> bytes:
    delta = number - current
    def head(value_length: int, delta_value: int) -> Tuple[int, bytes, bytes]:
        if delta_value >= 269:
            d_extra, d_hi = be16(delta_value - 269), 14
        elif delta_value >= 13:
            d_extra, d_hi = bytes([delta_value - 13]), 13
        else:
            d_extra, d_hi = b"", delta_value
        if value_length >= 269:
            l_extra, l_hi = be16(value_length - 269), 14
        elif value_length >= 13:
            l_extra, l_hi = bytes([value_length - 13]), 13
        else:
            l_extra, l_hi = b"", value_length
        return (d_hi << 4) | l_hi, d_extra, l_extra
    token, d_extra, l_extra = head(len(value), delta)
    return bytes([token]) + d_extra + l_extra + value


def coap_packet(code: int = 1, uri: str = "/", token: bytes = b"\x01\x02",
                message_id: int = 0x1234, payload: bytes = b"",
                content_format: int = 0, options: Sequence[Tuple[int, bytes]] = (),
                confirmable: bool = True) -> bytes:
    """A CoAP request.  The options are emitted in ascending number order, as required."""
    token = token[:8]
    # first byte: version (2 bits) | type (2 bits) | token length (4 bits)
    first = (1 << 6) | (0 if confirmable else 1) << 4 | len(token)
    header = bytes([first, code]) + be16(message_id) + token
    table: List[Tuple[int, bytes]] = []
    for index, part in enumerate([p for p in uri.strip("/").split("/") if p]):
        table.append((COAP_OPTIONS["Uri-Path"], part.encode()))
    if content_format:
        table.append((COAP_OPTIONS["Content-Format"], bytes([content_format])))
    table.extend(options)
    table.sort(key=lambda item: item[0])
    encoded = b""
    current = 0
    for number, value in table:
        encoded += _coap_option(True, number, value, current)
        current = number
    if payload:
        encoded += b"\xff" + payload
    return header + encoded


def parse_coap(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"version": 0, "type": 0, "code": 0, "code_name": "",
                           "message_id": 0, "token": b"", "options": {}, "uri": "",
                           "payload": b"", "text": ""}
    if len(data) < 4:
        return out
    out["version"] = data[0] >> 6
    out["type"] = (data[0] >> 4) & 0x03
    out["code"] = data[1]
    out["code_name"] = COAP_CODES.get(out["code"], f"code {out['code']}")
    out["message_id"] = be16_at(data, 2)
    token_length = data[0] & 0x0F        # the token length lives in the first byte
    offset = 4
    out["token"] = data[offset:offset + token_length]
    offset += token_length
    number = 0
    path: List[str] = []
    while offset < len(data):
        byte = data[offset]
        if byte == 0xFF:
            out["payload"] = data[offset + 1:]
            break
        delta, length = byte >> 4, byte & 0x0F
        offset += 1
        if delta == 13:
            delta = data[offset] + 13
            offset += 1
        elif delta == 14:
            delta = be16_at(data, offset) + 269
            offset += 2
        if length == 13:
            length = data[offset] + 13
            offset += 1
        elif length == 14:
            length = be16_at(data, offset) + 269
            offset += 2
        number += delta
        value = data[offset:offset + length]
        offset += length
        name = next((key for key, num in COAP_OPTIONS.items() if num == number),
                    str(number))
        out["options"][name] = value
        if name == "Uri-Path":
            path.append(value.decode("utf-8", "replace"))
    out["uri"] = "/" + "/".join(path)
    out["text"] = printable(out["payload"])
    return out


# --------------------------------------------------------------------------- #
# Modbus TCP (502) — the industrial protocol with no authentication in it
# --------------------------------------------------------------------------- #

MODBUS_FUNCTIONS = {
    1: "read coils", 2: "read discrete inputs", 3: "read holding registers",
    4: "read input registers", 5: "write single coil", 6: "write single register",
    7: "read exception status", 8: "diagnostics", 15: "write multiple coils",
    16: "write multiple registers", 17: "report server id", 20: "read file record",
    21: "write file record", 22: "mask write register", 23: "read/write multiple",
    43: "read device identification",
}

#: Modbus exception codes (MODBUS Application Protocol §7)
MODBUS_EXCEPTIONS = {
    1: "illegal function", 2: "illegal data address", 3: "illegal data value",
    4: "server device failure", 5: "acknowledge", 6: "server device busy",
    8: "memory parity error", 10: "gateway path unavailable",
    11: "gateway target device failed to respond",
}


def modbus_request(function: int, unit: int = 1, address: int = 0, count: int = 1,
                   value: int = 0, transaction: int = 1, device_id: int = 0,
                   payload: bytes = b"") -> bytes:
    """MBAP header + PDU: what every PLC, meter and inverter on port 502 expects."""
    if payload:
        pdu = bytes([function]) + payload
    elif function in (1, 2, 3, 4):
        pdu = bytes([function]) + be16(address) + be16(count)
    elif function == 5:
        pdu = bytes([function]) + be16(address) + (b"\xff\x00" if value else b"\x00\x00")
    elif function == 6:
        pdu = bytes([function]) + be16(address) + be16(value)
    elif function in (15, 16):
        body = bytes([function]) + be16(address) + be16(count) + bytes([count * 2 if
                      function == 16 else (count + 7) // 8]) + be16(value)
        pdu = body
    elif function == 43:
        # read device identification, basic category, first object
        pdu = bytes([function, 0x0E, 0x01, 0x00])
    else:
        pdu = bytes([function]) + be16(address)
    return be16(transaction) + b"\x00\x00" + be16(len(pdu) + 1) + bytes([unit]) + pdu


def parse_modbus(data: bytes, request: bool = False) -> Dict[str, Any]:
    """Header, function, data and the exception bit — the whole protocol, in one call."""
    out: Dict[str, Any] = {"transaction": 0, "protocol": 0, "length": 0, "unit": 0,
                           "function": 0, "function_name": "", "exception": False,
                           "exception_code": 0, "exception_name": "", "registers": [],
                           "bytes": b"", "device_id": "", "address": 0, "count": 0,
                           "value": 0, "write": False}
    if len(data) < 8:
        return out
    out["transaction"] = be16_at(data, 0)
    out["protocol"] = be16_at(data, 2)
    out["length"] = be16_at(data, 4)
    out["unit"] = data[6]
    out["function"] = data[7] & 0x7F
    out["function_name"] = MODBUS_FUNCTIONS.get(out["function"], f"function {out['function']}")
    out["exception"] = bool(data[7] & 0x80)
    body = data[8:]
    if out["exception"] and body:
        out["exception_code"] = body[0]
        out["exception_name"] = MODBUS_EXCEPTIONS.get(body[0], "unknown exception")
        return out
    if out["function"] in (1, 2, 3, 4):
        if request and len(body) >= 4:                     # a request: address and quantity
            out["address"] = be16_at(body, 0)
            out["count"] = be16_at(body, 2)
        elif body:                                         # a response: length then data
            length = body[0]
            raw = body[1:1 + length]
            out["bytes"] = raw
            if out["function"] in (3, 4):
                out["registers"] = [be16_at(raw, offset)
                                    for offset in range(0, len(raw) - 1, 2)]
                out["count"] = len(out["registers"])
            else:
                out["count"] = length * 8                  # coils and inputs are bits
    elif out["function"] in (5, 6) and len(body) >= 4:
        out["address"] = be16_at(body, 0)
        out["value"] = be16_at(body, 2)
        out["write"] = True
        out["registers"] = [out["value"]]
    elif out["function"] and body:
        out["bytes"] = body
        out["device_id"] = printable(body)
    return out


# --------------------------------------------------------------------------- #
# BACnet/IP (47808/udp) — building automation, unauthenticated by design
# --------------------------------------------------------------------------- #

BACNET_SERVICES = {0: "acknowledge-alarm", 5: "i-am", 6: "i-have", 7: "who-has",
                   8: "who-is", 12: "read-property", 14: "read-property-multiple",
                   15: "write-property", 16: "write-property-multiple", 20: "reinitialize-device",
                   27: "device-communication-control", 30: "who-am-i"}

BACNET_BVLC = 0x81


def bacnet_frame(function: int, payload: bytes) -> bytes:
    """BVLC wrapping: 0x81, the function, then a big-endian total length."""
    return bytes([BACNET_BVLC, function]) + be16(len(payload) + 4) + payload


#: kept under the private name because every call site in this module reads better for it
_bacnet_virtual_link = bacnet_frame


def bacnet_who_is(low: int = 0, high: int = 0) -> bytes:
    """Who-Is: the single service byte every BACnet device on the segment answers.

    The device range is optional and encoded the way the standard's context tags require
    (tag 0 for the low limit, tag 1 for the high), which is why the common probe sends
    neither.
    """
    payload = b"\x10\x08"                       # unconfirmed-request, who-is
    if low:
        payload += b"\x09" + bytes([3]) + (low & 0xFFFFFF).to_bytes(3, "big")
    if high:
        payload += b"\x19" + bytes([3]) + (high & 0xFFFFFF).to_bytes(3, "big")
    return _bacnet_virtual_link(0x0A, payload)


def bacnet_read_property(device: int, obj_type: int = 8, instance: int = 8,
                         prop: int = 77) -> bytes:
    """Read-Property for object-name (77) or object-identifier: the two every device has."""
    raw = (obj_type << 22) | (instance & 0x3FFFFF)
    apdu = bytes([0x00, 0x05, 0x01, 0x0C])       # confirmed-request, read-property
    apdu += b"\x0c\x04" + raw.to_bytes(4, "big")
    apdu += b"\x19\x01" + bytes([prop & 0xFF])
    npdu = b"\x01\x04"                          # version 1, expecting a reply
    return _bacnet_virtual_link(0x0A, npdu + apdu)


def parse_bacnet(data: bytes) -> Dict[str, Any]:
    """BVLC + NPDU + APDU unwrapped far enough to name the service and any text."""
    out: Dict[str, Any] = {"type": 0, "function": 0, "service": 0, "service_name": "",
                           "device": 0, "vendor": 0, "object_name": "", "text": "",
                           "invoke_id": 0}
    if len(data) < 6 or data[0] != BACNET_BVLC:
        return out
    out["type"] = data[1]
    offset = 4
    if data[offset] == 0x01 and len(data) > offset + 1:      # NPDU: version then control
        control = data[offset + 1]
        offset += 2
        if control & 0x20:                                   # destination present
            offset += 3 + (data[offset + 2] if len(data) > offset + 2 else 0)
        if control & 0x08:                                   # source present
            offset += 3 + (data[offset + 2] if len(data) > offset + 2 else 0)
        if control & 0x80:                                   # hop count
            offset += 1
    if offset >= len(data):
        return out
    apdu_type = data[offset]
    if apdu_type == 0x10:                                    # unconfirmed request
        out["service"] = data[offset + 1] if len(data) > offset + 1 else 0
    elif apdu_type & 0xF0 == 0x00:                           # confirmed request
        out["invoke_id"] = data[offset + 2] if len(data) > offset + 2 else 0
        out["service"] = data[offset + 3] if len(data) > offset + 3 else 0
    elif apdu_type & 0xF0 == 0x30:                           # complex ACK
        out["invoke_id"] = data[offset + 1] if len(data) > offset + 1 else 0
        out["service"] = data[offset + 2] if len(data) > offset + 2 else 0
    out["service_name"] = BACNET_SERVICES.get(out["service"], f"service {out['service']}")
    out["text"] = printable(data[offset:])
    match = re.search(r"([A-Za-z][\w .\-]{2,30})", out["text"])
    if match:
        out["object_name"] = match.group(1).strip()
    return out


# --------------------------------------------------------------------------- #
# RTSP (554) — the camera protocol, and the one that is often open
# --------------------------------------------------------------------------- #

def rtsp_request(method: str = "OPTIONS", url: str = "rtsp://192.168.1.10/live",
                 cseq: int = 1, headers: Optional[Dict[str, str]] = None,
                 basic: Tuple[str, str] = ("", ""),
                 authorization: str = "") -> bytes:
    lines = [f"{method.upper()} {url} RTSP/1.0", f"CSeq: {cseq}", "User-Agent: wifipilot"]
    if authorization:
        lines.append(f"Authorization: {authorization}")
    elif basic[0] or basic[1]:
        token = base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode()
        lines.append(f"Authorization: Basic {token}")
    for key, value in (headers or {}).items():
        lines.append(f"{key}: {value}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def parse_rtsp(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"status": 0, "reason": "", "headers": {}, "body": "",
                           "server": "", "authenticated": False, "realm": "",
                           "nonce": "", "sdp": {}, "session": ""}
    if not data:
        return out
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").splitlines()
    if lines:
        parts = lines[0].split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            out["status"] = int(parts[1])
            out["reason"] = parts[2] if len(parts) > 2 else ""
    for line in lines[1:]:
        key, _, value = line.partition(":")
        if key:
            out["headers"][key.strip().lower()] = value.strip()
    out["server"] = out["headers"].get("server", "")
    out["session"] = out["headers"].get("session", "")
    out["authenticated"] = out["status"] in (200, 201)
    challenge = out["headers"].get("www-authenticate", "")
    if challenge:
        parsed = parse_www_authenticate(challenge)
        out["realm"] = parsed.get("realm", "")
        out["nonce"] = parsed.get("nonce", "")
    out["body"] = body.decode("utf-8", "replace")
    out["sdp"] = parse_sdp(out["body"])
    return out


def parse_sdp(text: str) -> Dict[str, Any]:
    """The session description of a camera: media, codec, resolution and the control URL."""
    out: Dict[str, Any] = {"session": "", "media": [], "codecs": [], "control": "",
                           "resolution": "", "raw_lines": 0}
    media: Optional[Dict[str, Any]] = None
    for line in (text or "").splitlines():
        out["raw_lines"] += 1
        if line.startswith("s="):
            out["session"] = line[2:].strip()
        elif line.startswith("m="):
            if media:
                out["media"].append(media)
            parts = line[2:].split()
            media = {"type": parts[0] if parts else "", "port": parts[1] if len(parts) > 1
                     else "", "protocol": parts[2] if len(parts) > 2 else "",
                     "formats": parts[3:]}
            out["codecs"].extend(f for f in media["formats"] if f.isdigit())
        elif line.startswith("a=control:") and not out["control"]:
            out["control"] = line.split(":", 1)[1].strip()
        elif line.startswith("a=framesize") and not out["resolution"]:
            out["resolution"] = line.split(":", 2)[-1].strip()
    if media:
        out["media"].append(media)
    return out


# --------------------------------------------------------------------------- #
# SOAP — the envelope UPnP and ONVIF share
# --------------------------------------------------------------------------- #

SOAP_NS_ENVELOPE = "http://www.w3.org/2003/05/soap-envelope"
SOAP_NS_UPNP = "urn:schemas-upnp-org:service:WANIPConnection:1"


def soap_envelope(action: str, body: str, service: str = SOAP_NS_UPNP,
                  version: str = "1.1", namespace: str = "u") -> bytes:
    """A SOAP action over HTTP POST, built the way UPnP's device architecture shows."""
    if version == "1.2":
        head = (f'<?xml version="1.0"?>'
                f'<s:Envelope xmlns:s="{SOAP_NS_ENVELOPE}" '
                f's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
                f'<s:Body><{namespace}:{action} xmlns:{namespace}="{service}">'
                f'{body}</{namespace}:{action}></s:Body></s:Envelope>')
    else:
        head = (f'<?xml version="1.0"?>'
                f'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                f's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
                f'<s:Body><{namespace}:{action} xmlns:{namespace}="{service}">'
                f'{body}</{namespace}:{action}></s:Body></s:Envelope>')
    return head.encode()


def upnp_soap(action: str = "GetExternalIPAddress", service: str = SOAP_NS_UPNP,
              control_url: str = "/upnp/control/WANIPConn1", fields: str = "") -> bytes:
    """An HTTP POST wrapping the SOAP call, ready to send at a router's control URL."""
    return http_request("", control_url, "POST", 80,
                        {"Content-Type": 'text/xml; charset="utf-8"',
                         "SOAPAction": f'"{service}#{action}"',
                         "Host": ""}, soap_envelope(action, fields, service))


def parse_soap(data: bytes, tag: str = "") -> Dict[str, Any]:
    """Every element and attribute in a SOAP answer, plus the first match for ``tag``."""
    text = data.decode("utf-8", "replace")
    out: Dict[str, Any] = {"status": 0, "fault": "", "elements": {}, "value": "",
                           "namespaces": [], "body": text}
    match = re.search(r"HTTP/1\.[01] (\d{3})", text)
    if match:
        out["status"] = int(match.group(1))
    fault = re.search(r"<(?:\w+:)?faultcode>([^<]+)<", text, re.I) or \
        re.search(r"<(?:\w+:)?Fault[^>]*>\s*<(?:\w+:)?(?:errorCode|faultstring)>([^<]*)<",
                  text, re.I)
    if fault:
        out["fault"] = fault.group(1).strip()
    out["namespaces"] = re.findall(r'xmlns(?::(\w+))?="([^"]+)"', text)
    for name, value in re.findall(r"<(?:\w+:)?([A-Za-z][\w\-]*)>([^<]*)</(?:\w+:)?\1>", text):
        if name not in ("Envelope", "Body", "Header"):
            out["elements"].setdefault(name, value.strip())
    for attr, value in re.findall(r'([A-Za-z][\w\-]*)="([^"]{1,64})"', text):
        out["elements"].setdefault(attr, value)
    if tag:
        out["value"] = out["elements"].get(tag, "")
    return out


def onvif_get_device_information(endpoint: str = "/onvif/device_service") -> bytes:
    body = ("<tds:GetDeviceInformation xmlns:tds="
            '"http://www.onvif.org/ver10/device/wsdl"/>')
    return http_request("", endpoint, "POST", 80,
                        {"Content-Type": 'application/soap+xml; charset=utf-8'},
                        body.encode())


def onvif_get_system_date_and_time(endpoint: str = "/onvif/device_service") -> bytes:
    body = ("<tds:GetSystemDateAndTime xmlns:tds="
            '"http://www.onvif.org/ver10/device/wsdl"/>')
    return http_request("", endpoint, "POST", 80,
                        {"Content-Type": 'application/soap+xml; charset=utf-8'},
                        body.encode())


def onvif_get_stream_uri(profile: str = "profile_1",
                         endpoint: str = "/onvif/media_service") -> bytes:
    body = (f"<trt:GetStreamUri xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\">"
            f"<trt:StreamSetup><tt:Stream xmlns:tt=\"http://www.onvif.org/ver10/schema\">"
            f"RTP-Unicast</tt:Stream><tt:Transport "
            f"xmlns:tt=\"http://www.onvif.org/ver10/schema\"><tt:Protocol>RTSP</tt:Protocol>"
            f"</tt:Transport></trt:StreamSetup><trt:ProfileToken>{profile}"
            f"</trt:ProfileToken></trt:GetStreamUri>")
    return http_request("", endpoint, "POST", 80,
                        {"Content-Type": 'application/soap+xml; charset=utf-8'},
                        body.encode())


def onvif_envelope(action: str, fields: str = "",
                   endpoint: str = "/onvif/device_service") -> bytes:
    body = (f'<tds:{action} xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
            f"{fields}</tds:{action}>")
    return http_request("", endpoint, "POST", 80,
                        {"Content-Type": 'application/soap+xml; charset=utf-8'},
                        body.encode())


def onvif_time(elements: Dict[str, str]) -> str:
    """The device clock as one string: the text form, or the components.

    ONVIF answers GetSystemDateAndTime with *components* (nested Hour/Minute and
    Year/Month/Day elements) rather than a formatted timestamp, so a parser that only
    reads the element's text reports an empty clock for a device that just told it the
    exact time.
    """
    if elements.get("UTCDateTime"):
        return elements["UTCDateTime"]
    date = "-".join(part for part in (elements.get("Year"), elements.get("Month"),
                                      elements.get("Day")) if part)
    clock = ":".join(part for part in (elements.get("Hour"), elements.get("Minute"),
                                       elements.get("Second")) if part)
    return f"{date} {clock}".strip()


def parse_onvif(data: bytes) -> Dict[str, Any]:
    """ONVIF answers are SOAP; the useful fields are the ones that name the device."""
    soap = parse_soap(data)
    out: Dict[str, Any] = dict(soap)
    out.update({"manufacturer": soap["elements"].get("Manufacturer", ""),
                "model": soap["elements"].get("Model", ""),
                "firmware": soap["elements"].get("FirmwareVersion", ""),
                "serial": soap["elements"].get("SerialNumber", ""),
                "hardware": soap["elements"].get("HardwareId", ""),
                "uri": soap["elements"].get("Uri", ""),
                "utc": onvif_time(soap["elements"]),
                "internal_fault": bool(soap.get("fault"))})
    return out


# --------------------------------------------------------------------------- #
# IPP (631) — printers (RFC 8010/8011)
# --------------------------------------------------------------------------- #

IPP_OPERATIONS = {0x0002: "Print-Job", 0x0003: "Print-URI", 0x0004: "Validate-Job",
                  0x0005: "Create-Job", 0x0006: "Send-Document", 0x0008: "Cancel-Job",
                  0x0009: "Get-Job-Attributes", 0x000A: "Get-Jobs",
                  0x000B: "Get-Printer-Attributes", 0x000C: "Hold-Job",
                  0x000D: "Release-Job", 0x0012: "CUPS-Get-Default"}

IPP_STATUS = {0x0000: "successful-ok", 0x0001: "successful-ok-ignored-or-substituted-"
              "attributes", 0x0400: "client-error-bad-request", 0x0401: "client-error-"
              "forbidden", 0x0403: "client-error-not-authenticated",
              0x0405: "client-error-not-found", 0x0500: "server-error-internal-error"}


def _ipp_delimiter(tag: int, name: str, value: bytes) -> bytes:
    return bytes([tag]) + be16(len(name)) + name.encode() + be16(len(value)) + value


def ipp_get_printer_attributes(uri: str = "ipp://192.168.1.20/ipp/print",
                               request_id: int = 1) -> bytes:
    """A binary IPP request: version, operation, request id, then the attribute groups."""
    body = be16(2) + be16(0x000B) + be32(request_id)
    body += bytes([0x01])                                   # operation-attributes group
    body += _ipp_delimiter(0x47, "attributes-charset", b"utf-8")
    body += _ipp_delimiter(0x48, "attributes-natural-language", b"en")
    body += _ipp_delimiter(0x45, "printer-uri", uri.encode())
    body += _ipp_delimiter(0x44, "requested-attributes", b"printer-make-and-model")
    body += _ipp_delimiter(0x44, "requested-attributes", b"printer-state")
    body += _ipp_delimiter(0x44, "requested-attributes", b"printer-firmware-string-version")
    body += bytes([0x03])                                   # end-of-attributes
    return body


def parse_ipp(data: bytes, response: bool = True) -> Dict[str, Any]:
    """The IPP header and attribute list (RFC 8011).

    The second header field is overloaded: an operation id in a request and a status
    code in a reply.  ``response`` says which one to read — the flags that matter to a
    verdict (``status``, ``status_name``, ``attributes``) are filled either way, and the
    other reading is kept in ``operation``/``code`` so no information is lost.
    """
    out: Dict[str, Any] = {"version": "", "operation": 0, "operation_name": "",
                           "status": 0, "status_name": "", "request_id": 0, "code": 0,
                           "attributes": {}, "groups": [], "text": ""}
    if len(data) < 9:
        return out
    out["version"] = f"{data[0]}.{data[1]}"
    out["code"] = be16_at(data, 2)
    out["request_id"] = be32_at(data, 4)
    if response:
        out["status"] = out["code"]
        if out["code"] in IPP_OPERATIONS:                   # an unusual reply: keep both
            out["operation"] = out["code"]
            out["operation_name"] = IPP_OPERATIONS[out["code"]]
    else:
        out["operation"] = out["code"]
        out["operation_name"] = IPP_OPERATIONS.get(out["operation"],
                                                   f"operation {out['operation']}")
    offset = 8
    while offset < len(data):
        tag = data[offset]
        if tag == 0x03:
            break
        if tag < 0x10:                                      # a delimiter group
            out["groups"].append(tag)
            offset += 1
            continue
        if offset + 5 > len(data):
            break
        # RFC 8011 §3.1.2: the attribute name length is an INT16, exactly like the value
        # length that follows the name — a one-byte reading works only against code that
        # writes one byte, which is how this parser and its first responder agreed.
        name_length = be16_at(data, offset + 1)
        name = data[offset + 3:offset + 3 + name_length].decode("utf-8", "replace")
        offset += 3 + name_length
        value_length = be16_at(data, offset)
        value = data[offset + 2:offset + 2 + value_length]
        offset += 2 + value_length
        if tag in (0x21, 0x23):                             # integer / enum
            out["attributes"][name] = int.from_bytes(value or b"\x00", "big")
        else:
            out["attributes"][name] = value.decode("utf-8", "replace")
        if name == "status-code" and isinstance(out["attributes"][name], int):
            out["status"] = out["attributes"][name]
    if "status-code" in out["attributes"] and not out["status"]:
        out["status"] = int(out["attributes"]["status-code"])
    out["status_name"] = IPP_STATUS.get(out["status"], "")
    out["text"] = printable(data)
    return out


# --------------------------------------------------------------------------- #
# PJL (9100) — the printer command line
# --------------------------------------------------------------------------- #

PJL_COMMANDS = {
    "id": "@PJL INFO ID",
    "status": "@PJL INFO STATUS",
    "config": "@PJL INFO CONFIG",
    "variables": "@PJL INFO VARIABLES",
    "filesys": "@PJL INFO FILESYS",
    "pagecount": "@PJL INFO PAGECOUNT",
    "pcl": "@PJL INFO PCL",
    "memory": "@PJL INFO MEMORY",
    "env": "@PJL ECHO WIFIPILOT-TEST",
    "ustatus": "@PJL USTATUS DEVICE = ON",
    "rdymsg": "@PJL RDYMSG DISPLAY = \"wifipilot\"",
}


def pjl_command(command: str = "id", newline: str = "\r\n") -> bytes:
    """A PJL line: the protocol printers answer on 9100 with no authentication."""
    text = PJL_COMMANDS.get(command, command)
    if not text.upper().startswith("@PJL"):
        text = f"@PJL {text}"
    return b"\x1b%-12345X@PJL\r\n" + text.encode() + newline.encode() + \
        b"\x1b%-12345X\r\n"


def parse_pjl(data: bytes) -> Dict[str, Any]:
    """PJL answers are plain text; the parsers' job is to name what came back."""
    text = printable(data)
    out: Dict[str, Any] = {"text": text, "model": "", "status": "", "firmware": "",
                           "lines": [], "responds": bool(text)}
    out["lines"] = [line.strip() for line in text.splitlines() if line.strip()]
    for line in out["lines"]:
        upper = line.upper()
        if "INFO ID" in upper and not out["model"]:
            out["model"] = line
        elif "STATUS" in upper and not out["status"]:
            out["status"] = line
        elif "FIRMWARE" in upper or "VERSION" in upper:
            out["firmware"] = line
    return out


# --------------------------------------------------------------------------- #
# telnet (23) — negotiation bytes and a banner
# --------------------------------------------------------------------------- #

TELNET_IAC = 0xFF
TELNET_OPTIONS = {0: "binary", 1: "echo", 3: "suppress-go-ahead", 5: "status",
                  24: "terminal-type", 31: "window-size", 32: "terminal-speed",
                  33: "remote-flow-control", 34: "linemode", 39: "environment",
                  36: "environment", 37: "authentication"}


def telnet_banner(timeout_hint: float = 2.0) -> bytes:
    """The three bytes that make a telnet server introduce itself (WILL/DO/NAWS)."""
    return bytes([TELNET_IAC, 0xFD, 24, TELNET_IAC, 0xFD, 31, TELNET_IAC, 0xFB, 1,
                  TELNET_IAC, 0xFB, 3])


def parse_telnet_negotiation(data: bytes) -> Dict[str, Any]:
    """Every IAC triple, decoded as an option name, plus the printable banner."""
    out: Dict[str, Any] = {"offers": [], "wants": [], "banner": "", "login": False,
                           "password": False, "text": ""}
    index = 0
    while index < len(data) - 2:
        if data[index] == TELNET_IAC and data[index + 1] in (0xFB, 0xFC, 0xFD, 0xFE):
            verb = {0xFB: "WILL", 0xFC: "WONT", 0xFD: "DO", 0xFE: "DONT"}[data[index + 1]]
            option = TELNET_OPTIONS.get(data[index + 2], str(data[index + 2]))
            entry = f"{verb} {option}"
            (out["offers"] if verb in ("WILL", "WONT") else out["wants"]).append(entry)
            index += 3
            continue
        index += 1
    out["text"] = printable(bytes(b for b in data if b != TELNET_IAC))
    lowered = out["text"].lower()
    out["banner"] = out["text"].splitlines()[0] if out["text"] else ""
    out["login"] = any(word in lowered for word in ("login", "username", "user:"))
    out["password"] = "password" in lowered
    return out


# --------------------------------------------------------------------------- #
# SIP (5060/5061) — telephony, and the auth challenge is a finding of its own
# --------------------------------------------------------------------------- #

def parse_www_authenticate(header: str) -> Dict[str, str]:
    """The digest parameters of a 401: realm, nonce, algorithm, qop."""
    out: Dict[str, str] = {"scheme": "", "realm": "", "nonce": "", "algorithm": "",
                           "qop": "", "opaque": "", "stale": ""}
    header = (header or "").strip()
    if not header:
        return out
    out["scheme"] = header.split(" ", 1)[0]
    for match in re.finditer(r'(\w+)\s*=\s*"?([^",]+)"?', header):
        key, value = match.group(1).lower(), match.group(2).strip()
        if key in out:
            out[key] = value
    return out


def sip_request(method: str = "OPTIONS", uri: str = "sip:192.168.1.30",
                user: str = "", password: str = "", call_id: str = "wifipilot@wp",
                from_tag: str = "wp", cseq: int = 1, to: str = "",
                via_host: str = "192.168.1.99", auth: str = "") -> bytes:
    """OPTIONS asks a phone who it is; REGISTER with credentials asks it to trust us."""
    to = to or uri
    lines = [f"{method} {uri} SIP/2.0",
             f"Via: SIP/2.0/UDP {via_host}:5060;branch=z9hG4bK{cseq}",
             "Max-Forwards: 70",
             f"To: <{to}>",
             f"From: <sip:{user or 'wifipilot'}@{via_host}>;tag={from_tag}",
             f"Call-ID: {call_id}",
             f"CSeq: {cseq} {method}",
             "User-Agent: wifipilot",
             "Content-Length: 0"]
    if auth:
        lines.insert(-2, f"Authorization: {auth}")
    elif user and password:
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        lines.insert(-2, f"Authorization: Basic {token}")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines).encode()


def sip_register(uri: str = "sip:192.168.1.30", user: str = "100", password: str = "",
                 expires: int = 60, **kwargs: Any) -> bytes:
    kwargs.setdefault("cseq", 2)
    body = sip_request("REGISTER", uri, user, password, **kwargs)
    return body.replace(b"Content-Length: 0",
                        f"Contact: <sip:{user}@192.168.1.99>\r\nExpires: {expires}\r\n"
                        f"Content-Length: 0".encode())


def parse_sip(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"status": 0, "reason": "", "headers": {}, "auth": {},
                           "server": "", "user_agent": "", "challenge": False,
                           "authenticated": False, "body": ""}
    if not data:
        return out
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").splitlines()
    if lines:
        parts = lines[0].split(" ", 2)
        if len(parts) >= 2:
            out["status"] = int(parts[1]) if parts[1].isdigit() else 0
            out["reason"] = parts[2] if len(parts) > 2 else ""
    for line in lines[1:]:
        key, _, value = line.partition(":")
        if key:
            out["headers"][key.strip().lower()] = value.strip()
    out["server"] = out["headers"].get("server", "")
    out["user_agent"] = out["headers"].get("user-agent", "")
    out["authenticated"] = out["status"] == 200 and "www-authenticate" not in out["headers"]
    challenge = out["headers"].get("www-authenticate", "") or \
        out["headers"].get("proxy-authenticate", "")
    if challenge:
        out["challenge"] = True
        out["auth"] = parse_www_authenticate(challenge)
    out["body"] = body.decode("utf-8", "replace")
    return out


# --------------------------------------------------------------------------- #
# CWMP / TR-069 (7547) — the ISP's management channel
# --------------------------------------------------------------------------- #

CWMP_NS = "urn:dslforum-org:cwmp-1-0"


def cwmp_inform(device_id: str = "0026:1234567890", oui: str = "0026F4",
                serial: str = "WP00000000", event: str = "1 BOOT") -> bytes:
    body = (f"<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" "
            f"xmlns:cwmp=\"{CWMP_NS}\"><soap:Header><cwmp:ID soap:mustUnderstand=\"1\">"
            f"wp1</cwmp:ID></soap:Header><soap:Body><cwmp:Inform>"
            f"<DeviceId><Manufacturer>wifipilot</Manufacturer><OUI>{oui}</OUI>"
            f"<ProductClass>WP</ProductClass><SerialNumber>{serial}</SerialNumber>"
            f"</DeviceId><Event soap:arrayType=\"cwmp:EventStruct[1]\"><EventStruct>"
            f"<EventCode>{event}</EventCode><CommandKey></CommandKey></EventStruct>"
            f"</Event><ParameterList soap:arrayType=\"cwmp:ParameterValueStruct[3]\">"
            f"<ParameterValueStruct><Name>InternetGatewayDevice.DeviceInfo.SoftwareVersion"
            f"</Name><Value>1.0.0</Value></ParameterValueStruct>"
            f"<ParameterValueStruct><Name>InternetGatewayDevice.WANDevice.1.WANConnectionDevice"
            f".1.WANIPConnection.1.ExternalIPAddress</Name><Value>0.0.0.0</Value>"
            f"</ParameterValueStruct><ParameterValueStruct><Name>InternetGatewayDevice."
            f"ManagementServer.URL</Name><Value></Value></ParameterValueStruct>"
            f"</ParameterList></cwmp:Inform></soap:Body></soap:Envelope>")
    return http_request("", "/cwmp", "POST", 7547,
                        {"Content-Type": "text/xml; charset=utf-8",
                         "SOAPAction": f'"{CWMP_NS}#Inform"'}, body.encode())


def cwmp_get_parameter_values(names: Sequence[str] = ("InternetGatewayDevice.DeviceInfo."
                                                      "SoftwareVersion",)) -> bytes:
    entries = "".join(f"<string>{name}</string>" for name in names)
    body = (f"<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" "
            f"xmlns:cwmp=\"{CWMP_NS}\"><soap:Header><cwmp:ID soap:mustUnderstand=\"1\">"
            f"wp2</cwmp:ID></soap:Header><soap:Body>"
            f"<cwmp:GetParameterValues><ParameterNames soap:arrayType=\"xsd:string"
            f"[{len(names)}]\">{entries}</ParameterNames></cwmp:GetParameterValues>"
            f"</soap:Body></soap:Envelope>")
    return http_request("", "/cwmp", "POST", 7547,
                        {"Content-Type": "text/xml; charset=utf-8",
                         "SOAPAction": f'"{CWMP_NS}#GetParameterValues"'}, body.encode())


def parse_cwmp(data: bytes) -> Dict[str, Any]:
    soap = parse_soap(data)
    values = dict(re.findall(r"<Name>([^<]+)</Name>\s*<Value>([^<]*)</Value>",
                             data.decode("utf-8", "replace")))
    out: Dict[str, Any] = dict(soap)
    out["values"] = values if isinstance(values, dict) else {}
    out["parameters"] = out["values"]
    return out


# --------------------------------------------------------------------------- #
# SMB2 (445) and NetBIOS (137/139)
# --------------------------------------------------------------------------- #

SMB2_DIALECTS = {0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2",
                 0x0311: "3.1.1", 0x0200: "2.0"}


def smb2_negotiate(dialects: Sequence[int] = (0x0311, 0x0302, 0x0210, 0x0202)) -> bytes:
    """NEGOTIATE with an SMB2 header, the NETBIOS session header and the dialect list."""
    body = be16(len(dialects)) + b"\x00\x00" + b"\x00\x00" + le32(0) + b"\x00" * 16 + \
        b"\x00" * 8 + b"".join(le16(d) for d in dialects) + b"\x00" * 16 + b"\x00" * 8
    header = (b"\xfeSMB" + le16(64) + le16(0) + le32(0) + le16(0) + le16(31) + le32(0) +
              le32(0) + le64(0) + le64(0) + le64(0) + le64(0) + b"\x00" * 8 + le32(0))
    packet = header + body
    return b"\x00" + le32(len(packet))[:3] + packet        # NBSS: 0x00 + 24-bit length


def parse_smb2(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"protocol": "", "command": -1, "header_size": 0, "structure": 0,
                           "status": 0, "dialect": 0, "dialect_name": "", "signing": False,
                           "signing_enabled": False, "security_mode": 0, "server": "",
                           "message_id": "", "session_required": True, "challenge": b""}
    offset = 0
    if len(data) >= 4 and data[0] == 0x00:                 # NBSS header present
        offset = 4
    if data[offset:offset + 4] == b"\xfeSMB":
        out["protocol"] = "SMB2"
        header = data[offset:offset + 64]
        out["command"] = le16_at(header, 12)               # 0 NEGOTIATE, 1 SESSION_SETUP
        out["header_size"] = le16_at(header, 4)
        out["status"] = le32_at(header, 8)
        out["message_id"] = data[offset + 24:offset + 32].hex() if len(header) >= 32 else ""
        body = data[offset + 64:]
        if len(body) >= 8:
            out["structure"] = le16_at(body, 0)            # 65 in a NEGOTIATE reply
            if out["command"] == 0:
                out["security_mode"] = le16_at(body, 2)     # SMB2 counts in little-endian
                out["dialect"] = le16_at(body, 4)
                out["dialect_name"] = SMB2_DIALECTS.get(out["dialect"], "")
                out["signing"] = bool(out["security_mode"] & 0x01)
                out["signing_enabled"] = bool(out["security_mode"] & 0x02)
                length = le16_at(body, 62)
                out["server"] = (body[64:64 + length].decode("utf-16-le", "replace")
                                 if length and len(body) >= 64 + length else "")
    elif data[offset:offset + 4] == b"\xffSMB":
        out["protocol"] = "SMB1"
    out["session_required"] = out["status"] in (0xC0000016, 0xC0000022) if out["status"] \
        else True
    return out


def netbios_query(name: str = "*", suffix: int = 0x00, txid: int = 0x1234,
                  question_type: int = 0x21) -> bytes:
    """A NetBIOS name-service query: the wildcard one lists every Windows box in a subnet."""
    encoded = bytearray()
    padded = (name.upper() + " " * 15)[:15] + chr(0x41 + suffix)
    for char in padded:
        encoded.append(ord(char))                          # half-ASCII, high bit clear
    question = bytes([32]) + bytes(encoded) + b"\x00" + be16(question_type) + b"\x00\x01"
    return be16(txid) + b"\x01\x10" + b"\x00\x01" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00" \
        + question


def parse_netbios(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"txid": 0, "flags": 0, "questions": 0, "answers": 0,
                           "names": [], "addresses": [], "text": ""}
    if len(data) < 12:
        return out
    out["txid"] = be16_at(data, 0)
    out["flags"] = be16_at(data, 2)
    out["questions"] = be16_at(data, 4)
    out["answers"] = be16_at(data, 6)
    text = printable(data[12:])
    out["text"] = text
    out["names"] = re.findall(r"\b([A-Z0-9\-_]{2,15})\b", text)
    out["addresses"] = re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})", text)
    return out


# --------------------------------------------------------------------------- #
# mDNS / DNS-SD (5353) and SSDP (1900) — the discovery protocols
# --------------------------------------------------------------------------- #

#: DNS record types worth asking for on a LAN: the PTR sweep lists services, the
#: TXT sweep reads what the vendor put in them.
DNS_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
              28: "AAAA", 33: "SRV", 47: "NSEC", 255: "ANY"}

#: the service types a DNS-SD census asks for, in the order a report reads best
MDNS_SERVICES = ("_services._dns-sd._udp.local", "_http._tcp.local", "_ipp._tcp.local",
                 "_printer._tcp.local", "_smb._tcp.local", "_afpovertcp._tcp.local",
                 "_workstation._tcp.local", "_googlecast._tcp.local", "_airplay._tcp.local",
                 "_raop._tcp.local", "_spotify-connect._tcp.local", "_sonos._tcp.local",
                 "_hue._tcp.local", "_hap._tcp.local", "_esphomelib._tcp.local",
                 "_ssh._tcp.local", "_sftp-ssh._tcp.local", "_rfb._tcp.local",
                 "_rtsp._tcp.local", "_onvif._tcp.local", "_axis-video._tcp.local",
                 "_dahua._tcp.local", "_telnet._tcp.local", "_ftp._tcp.local",
                 "_sip._udp.local", "_vlc-http._tcp.local", "_printer._tcp.local")


def dns_name(name: str) -> bytes:
    """A domain name in the label-length form DNS uses on the wire."""
    out = bytearray()
    for label in (name or "").rstrip(".").split("."):
        if not label:
            continue
        raw = label.encode("utf-8", "replace")[:63]
        out.append(len(raw))
        out += raw
    return bytes(out) + b"\x00"


def dns_query(name: str = "_services._dns-sd._udp.local", qtype: int = 12,
              qclass: int = 1, txid: int = 0, unicast: bool = False) -> bytes:
    """A single-question query.  ``unicast`` asks for a direct reply, which is what a
    host that is not joining the multicast group should send."""
    flags = 0x0000 if not unicast else 0x0200
    return (be16(txid) + be16(flags) + b"\x00\x01" + b"\x00\x00" * 3 +
            dns_name(name) + be16(qtype) + be16(qclass))


def parse_dns(data: bytes) -> Dict[str, Any]:
    """Header counts, questions, and answers decoded with name decompression.

    Answers are grouped the way a report wants them: ``names`` for PTR targets,
    ``addresses`` for A/AAAA, ``txt`` for the strings vendors leave in TXT records and
    ``srv`` for the service locations.
    """
    out: Dict[str, Any] = {"id": 0, "flags": 0, "qr": False, "rcode": 0, "questions": [],
                           "answers": [], "names": [], "addresses": [], "txt": [],
                           "srv": [], "ttls": [], "raw": data}
    if len(data) < 12:
        return out
    out["id"] = be16_at(data, 0)
    out["flags"] = be16_at(data, 2)
    out["qr"] = bool(out["flags"] & 0x8000)
    out["rcode"] = out["flags"] & 0x000F
    qdcount, ancount = be16_at(data, 4), be16_at(data, 6)
    offset = 12

    def read_name(start: int) -> Tuple[str, int]:
        """Decode a name, following compression pointers, and return where it ended."""
        labels, hops, cursor, end = [], 0, start, start
        while cursor < len(data) and hops < 16:
            length = data[cursor]
            if length == 0:                                # the root label: names end here
                if hops == 0:
                    end = cursor + 1
                break
            if length & 0xC0 == 0xC0:                      # a pointer into the packet
                if cursor + 1 >= len(data):
                    break
                if hops == 0:
                    end = cursor + 2                       # only the first hop moves on
                cursor = ((length & 0x3F) << 8) | data[cursor + 1]
                hops += 1
                continue
            labels.append(data[cursor + 1:cursor + 1 + length].decode("utf-8", "replace"))
            cursor += 1 + length
            if hops == 0:
                end = cursor
        return ".".join(labels), end

    for _ in range(min(qdcount, 32)):
        if offset >= len(data):
            break
        name, offset = read_name(offset)
        if offset + 4 > len(data):
            break
        qtype, qclass = be16_at(data, offset), be16_at(data, offset + 2)
        out["questions"].append({"name": name, "type": qtype,
                                 "type_name": DNS_QTYPES.get(qtype, str(qtype)),
                                 "class": qclass})
        offset += 4
    for _ in range(min(ancount, 64)):
        if offset >= len(data):
            break
        name, offset = read_name(offset)
        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, rdlength = (be16_at(data, offset), be16_at(data, offset + 2),
                                        be32_at(data, offset + 4), be16_at(data, offset + 8))
        offset += 10
        payload = data[offset:offset + rdlength]
        offset += rdlength
        answer: Dict[str, Any] = {"name": name, "type": rtype,
                                 "type_name": DNS_QTYPES.get(rtype, str(rtype)),
                                 "class": rclass, "ttl": ttl, "rdlength": rdlength,
                                 "value": "", "target": ""}
        if rtype == 12 and payload:                        # PTR — the service list
            target, _ = read_name(offset - rdlength)
            answer["target"] = target or printable(payload).strip(".")
            out["names"].append(answer["target"])
        elif rtype == 16:                                  # TXT — vendor metadata
            strings, cursor = [], 0
            while cursor < len(payload):
                length = payload[cursor]
                strings.append(payload[cursor + 1:cursor + 1 + length].decode("utf-8",
                                                                             "replace"))
                cursor += 1 + length
            answer["value"] = " ".join(s for s in strings if s)
            if answer["value"]:
                out["txt"].append(answer["value"])
        elif rtype == 33 and len(payload) >= 6:            # SRV — where the service lives
            answer["value"] = (f"{be16_at(payload, 0)} {be16_at(payload, 2)} "
                               f"{be16_at(payload, 4)} " + read_name(offset - rdlength)[0])
            port, host = be16_at(payload, 4), read_name(offset - rdlength)[0]
            answer["target"] = host
            answer["value"] = f"{host}:{port}"
            out["srv"].append((host, port))
        elif rtype in (1, 28):
            if rtype == 1 and len(payload) == 4:
                answer["value"] = ".".join(str(b) for b in payload)
            else:
                answer["value"] = payload.hex(":") if payload else ""
            out["addresses"].append(answer["value"])
        elif rtype == 5 and payload:
            answer["value"] = read_name(offset - rdlength)[0]
        else:
            answer["value"] = printable(payload).strip()[:80]
        out["ttls"].append(ttl)
        out["answers"].append(answer)
    out["names"] = [n for n in dict.fromkeys(out["names"]) if n]
    out["addresses"] = [a for a in dict.fromkeys(out["addresses"]) if a]
    out["txt"] = [t for t in dict.fromkeys(out["txt"]) if t]
    return out


def parse_mdns(data: bytes) -> Dict[str, Any]:
    """The same decoder with the mDNS specifics made explicit: the cache-flush bit, the
    ``.local`` names and the service list a census is after."""
    out = parse_dns(data)
    out["cache_flush"] = any((a.get("class", 0) & 0x8000) for a in out["answers"])
    out["local_names"] = [n for n in out["names"] if n.endswith(".local")]
    out["services"] = sorted({s for s in out["names"] if "._" in s and s.endswith(".local")})
    return out


def ssdp_msearch(search_target: str = "ssdp:all", mx: int = 2,
                 host: str = "239.255.255.250", port: int = 1900,
                 user_agent: str = "") -> bytes:
    """The multicast M-SEARCH every UPnP device answers: one datagram, a full inventory."""
    ua = user_agent or f"{DEFAULT_HEADERS['User-Agent']} UPnP/1.1"
    return (f"M-SEARCH * HTTP/1.1\r\nHOST: {host}:{port}\r\nMAN: "
            f'"ssdp:discover"\r\nMX: {int(mx)}\r\nST: {search_target}\r\nUSER-AGENT: {ua}'
            f"\r\n\r\n").encode()


def ssdp_notify(location: str, nt: str = "upnp:rootdevice", usn: str = "",
                server: str = "", nts: str = "ssdp:alive") -> bytes:
    """A NOTIFY datagram — what a device (or a rogue one) announces itself with."""
    usn = usn or f"uuid:{location.rsplit('/', 2)[-2] if '/' in location else 'wp'}::{nt}"
    server = server or f"{DEFAULT_HEADERS['User-Agent']} UPnP/1.1"
    return (f"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nCACHE-CONTROL: "
            f"max-age=1800\r\nLOCATION: {location}\r\nNT: {nt}\r\nNTS: {nts}\r\n"
            f"SERVER: {server}\r\nUSN: {usn}\r\n\r\n").encode()


def parse_ssdp(data: str) -> Dict[str, Any]:
    """The status line and the headers of an M-SEARCH reply (or a NOTIFY), lower-cased
    into fields a verdict can read: ``location``, ``server``, ``st``, ``usn``, ``nt``."""
    text = data.decode("latin-1", "replace") if isinstance(data, bytes) else str(data)
    out: Dict[str, Any] = {"status": 0, "headers": {}, "location": "", "server": "",
                           "st": "", "usn": "", "nt": "", "nts": "", "cache_control": "",
                           "addresses": [], "text": text.strip()[:400]}
    lines = [line.strip() for line in text.replace("\r\n", "\n").split("\n") if line.strip()]
    if lines:
        parts = lines[0].split(" ", 2)
        if parts[0].upper().startswith("HTTP/") and len(parts) >= 2 and parts[1].isdigit():
            out["status"] = int(parts[1])                  # a reply: "HTTP/1.1 200 OK"
        elif len(parts) >= 3 and parts[2].isdigit():
            out["status"] = int(parts[2])
        elif parts[0].upper().startswith("NOTIFY"):
            out["status"] = 200                            # an announcement has no code
    for line in lines[1:]:
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key:
            out["headers"][key] = value
    out["location"] = out["headers"].get("location", "")
    out["server"] = out["headers"].get("server", "")
    out["st"] = out["headers"].get("st", out["headers"].get("nt", ""))
    out["usn"] = out["headers"].get("usn", "")
    out["nt"] = out["headers"].get("nt", "")
    out["nts"] = out["headers"].get("nts", "")
    out["cache_control"] = out["headers"].get("cache-control", "")
    out["addresses"] = re.findall(r"https?://(\d{1,3}(?:\.\d{1,3}){3})", text)
    return out


# --------------------------------------------------------------------------- #
# LDAP (389/636) — anonymous binds and the directory itself
# --------------------------------------------------------------------------- #

def _ber_tlv(tag: int, payload: bytes) -> bytes:
    """Length encoding for a BER element (short, then the two long forms)."""
    if len(payload) < 128:
        return bytes([tag, len(payload)]) + payload
    length = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + payload


def ldap_bind_request(version: int = 3, name: str = "", password: str = b"") -> bytes:
    """A BindRequest: with an empty DN and an empty password, this is an anonymous bind."""
    message = _ber_tlv(0x02, bytes([version])) + _ber_tlv(0x04, name.encode()) + \
        _ber_tlv(0x80, password)
    bind = _ber_tlv(0x60, message)
    return _ber_tlv(0x30, _ber_tlv(0x02, b"\x01") + bind)


def ldap_search_request(base: str = "", scope: int = 2, filter_bytes: bytes = b"",
                        attributes: Sequence[str] = ()) -> bytes:
    """A search against the root DSE: the cheapest way to see what a directory will say."""
    filter_bytes = filter_bytes or _ber_tlv(0xA0, b"")   # (objectClass=*)
    request = _ber_tlv(0x04, base.encode()) + _ber_tlv(0x0A, bytes([scope])) + \
        _ber_tlv(0x0A, b"\x00") + _ber_tlv(0x02, b"\x00") + _ber_tlv(0x02, b"\x00") + \
        _ber_tlv(0x01, b"\x00") + _ber_tlv(0x87, b"") + _ber_tlv(0x30, filter_bytes) + \
        _ber_tlv(0x30, b"".join(_ber_tlv(0x04, a.encode()) for a in attributes))
    return _ber_tlv(0x30, _ber_tlv(0x02, b"\x02") + _ber_tlv(0x63, request))


def _ber_read(data: bytes, offset: int = 0) -> Tuple[int, bytes, int]:
    """Read one BER element: the tag, the content, and where the next one starts."""
    if offset + 2 > len(data):
        return (0, b"", offset)
    tag = data[offset]
    length = data[offset + 1]
    offset += 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[offset:offset + count], "big") if count else 0
        offset += count
    return (tag, data[offset:offset + length], min(len(data), offset + length))


def _ber_children(value: bytes) -> List[Tuple[int, bytes, int]]:
    """Every element inside a constructed value, in order."""
    out: List[Tuple[int, bytes, int]] = []
    offset = 0
    while offset < len(value):
        tag, content, offset = _ber_read(value, offset)
        if tag == 0 and not content:
            break
        out.append((tag, content, offset))
    return out


def ldap_bind_fields(data: bytes) -> Dict[str, str]:
    """The three fields of a BindRequest: the version, the DN and the password.

    A directory decides what to answer from these, and nothing else in the packet, so
    they are read here rather than reconstructed from the bytes with a substring search.
    """
    out: Dict[str, str] = {"version": "", "dn": "", "password": ""}
    try:
        _tag, envelope, _end = _ber_read(data)
        fields = _ber_children(envelope or data)
        for field_tag, content, _next in fields:
            if field_tag != 0x60:
                continue
            inner = _ber_children(content)
            if inner:
                out["version"] = str(int.from_bytes(inner[0][1] or b"\x03", "big"))
            if len(inner) > 1:
                out["dn"] = inner[1][1].decode("latin-1", "replace")
            if len(inner) > 2:
                out["password"] = inner[2][1].decode("latin-1", "replace")
    except Exception:                                      # noqa: BLE001 - a broken packet
        return out
    return out


def parse_ldap(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"message_id": 0, "operation": "", "result_code": 0, "result": "",
                           "matched_dn": "", "diagnostic": "", "entries": [], "base": "",
                           "attributes": {}, "anonymous_allowed": False}
    operations = {0x60: "bindRequest", 0x61: "bindResponse", 0x63: "searchRequest",
                  0x64: "searchEntry", 0x65: "searchDone", 0x66: "modifyRequest",
                  0x67: "modifyResponse", 0x68: "addRequest", 0x69: "addResponse",
                  0x4A: "deleteRequest", 0x50: "abandonRequest", 0x42: "unbindRequest",
                  0x77: "extendedRequest", 0x78: "extendedResponse"}
    result_names = {0: "success", 32: "no such object", 34: "invalid DN", 48: "inappropriate "
                    "authentication", 49: "invalid credentials", 50: "insufficient access",
                    53: "unwilling to perform"}
    if not data or len(data) < 8:
        return out
    def parseable(value: bytes) -> str:
        """A value may carry its own TLV: unwrap one level, then decode."""
        if value and value[0] in (0x04, 0x31) and len(value) > 2:
            tag, inner, _ = _ber_read(value)
            if tag in (0x04, 0x31) and inner:
                value = inner
        return value.decode("latin-1", "replace")

    messages: List[bytes] = []
    tag, envelope, _end = _ber_read(data)
    if tag == 0x30:
        messages.append(envelope)                          # one LDAPMessage inside the frame
    offset = 0
    while offset < len(data) and not messages:             # a stream of LDAPMessages
        chunk_tag, chunk, offset = _ber_read(data, offset)
        if chunk_tag == 0 and not chunk:
            break
        if chunk_tag == 0x30:
            messages.append(chunk)
    for message in messages:
        fields = _ber_children(message)
        for field_tag, content, _next in fields:
            if field_tag == 0x02:                          # messageID
                out["message_id"] = int.from_bytes(content, "big")
            elif field_tag in (0x61, 0x65, 0x64, 0x63, 0x67, 0x50, 0x42, 0x60, 0x66):
                out["operation"] = operations.get(field_tag, out["operation"])
                if field_tag == 0x63:                      # searchRequest: keep the base DN
                    parts = _ber_children(content)
                    out["base"] = parts[0][1].decode("latin-1", "replace") if parts else ""
                if field_tag in (0x61, 0x65):              # BindResponse / SearchResultDone
                    code_field = _ber_children(content)
                    if code_field:
                        out["result_code"] = int.from_bytes(code_field[0][1], "big")
                        out["result"] = result_names.get(out["result_code"],
                                                         f"result {out['result_code']}")
                        out["anonymous_allowed"] = out["result_code"] == 0
                    if len(code_field) > 1:
                        out["matched_dn"] = code_field[1][1].decode("latin-1", "replace")
                    if len(code_field) > 2:
                        out["diagnostic"] = code_field[2][1].decode("latin-1", "replace")
                elif field_tag == 0x64:                    # SearchResultEntry
                    parts = _ber_children(content)
                    dn = parts[0][1].decode("latin-1", "replace") if parts else ""
                    attributes: Dict[str, List[str]] = {}
                    if len(parts) > 1:
                        for attr_tag, attr_value, _ in _ber_children(parts[1][1]):
                            if attr_tag != 0x30:
                                continue
                            pieces = _ber_children(attr_value)
                            if not pieces:
                                continue
                            name = pieces[0][1].decode("latin-1", "replace")
                            values = [parseable(value) for value_tag, value, _ in pieces[1:]
                                      if value_tag in (0x31, 0x04)]
                            attributes[name] = values
                    out["entries"].append({"dn": dn, "attributes": attributes})
                    for name, values in attributes.items():
                        out["attributes"].setdefault(name, values[0] if values else "")
    return out


def ldap_attributes(data: bytes) -> Dict[str, str]:
    """The attributes of a search answer, flattened for a report."""
    parsed = parse_ldap(data)
    flat = {name.lower(): values if isinstance(values, str) else
            (values[0] if values else "") for name, values in parsed["attributes"].items()}
    if flat:
        return flat
    text = data.decode("latin-1", "replace")               # not BER: fall back to text
    pairs = re.findall(r"([A-Za-z][\w\-]{1,32})\s*[:=]\s*([^\x00\r\n]{1,80})", text)
    return {key.lower(): re.sub(r"\s+", " ", value).strip() for key, value in pairs}


# --------------------------------------------------------------------------- #
# Redis (6379) and Memcached (11211) — databases that answer before authentication
# --------------------------------------------------------------------------- #

def redis_command(*parts: str, inline: bool = False) -> bytes:
    """RESP array form (``*2\\r\\n$3\\r\\nGET...``) or the inline form Redis also accepts."""
    if inline:
        return (" ".join(parts) + "\r\n").encode()
    out = bytearray(f"*{len(parts)}\r\n".encode())
    for part in parts:
        raw = str(part).encode()
        out += f"${len(raw)}\r\n".encode() + raw + b"\r\n"
    return bytes(out)


def parse_resp(data: bytes) -> Dict[str, Any]:
    """The five RESP types, unwrapped into ``values`` plus a plain-text rendering."""
    out: Dict[str, Any] = {"type": "", "values": [], "text": "", "error": "",
                           "auth_required": False, "info": {}}
    if not data:
        return out
    out["text"] = data.decode("utf-8", "replace")
    out["error"] = out["text"].splitlines()[0] if out["text"].startswith("-") else ""
    if out["error"]:
        lowered = out["error"].lower()
        out["auth_required"] = "noauth" in lowered or "auth" in lowered
    out["type"] = {"+": "simple string", "-": "error", ":": "integer", "$": "bulk string",
                   "*": "array"}.get(out["text"][:1], "unknown")
    for line in out["text"].splitlines():
        if line.startswith("-") or line.startswith("+") or line.startswith(":") or \
                not line.startswith("$"):
            out["values"].append(line)
    for line in out["text"].splitlines():
        if ":" in line and not line.startswith(("*", "$", "+", "-")):
            key, _, value = line.partition(":")
            out["info"][key.strip()] = value.strip()
    return out


MEMCACHED_COMMANDS = ("stats", "stats items", "stats slabs", "version", "verbosity 0",
                      "get key", "quit", "stats settings", "stats conns")


def memcached_command(command: str = "stats") -> bytes:
    return (command.strip() + "\r\n").encode()


#: the same idea for the other text protocols: build a line, read lines back
mx_command = memcached_command


def mongo_hello(hello_ok: bool = True) -> bytes:
    """An OP_MSG ``hello`` (the modern isMaster): BSON documents inside a message header."""
    def bson_document(pairs: Dict[str, Any]) -> bytes:
        body = b""
        for key, value in pairs.items():
            if isinstance(value, bool):
                body += b"\x08" + key.encode() + b"\x00" + (b"\x01" if value else b"\x00")
            elif isinstance(value, int):
                body += b"\x10" + key.encode() + b"\x00" + le32(value)
            else:
                raw = str(value).encode()
                body += b"\x02" + key.encode() + b"\x00" + le32(len(raw) + 1) + raw + b"\x00"
        body += b"\x00"
        return le32(len(body) + 4) + body

    document = bson_document({"hello": 1, "helloOk": hello_ok} if hello_ok
                             else {"isMaster": 1})
    section = b"\x00" + document
    body = le32(0) + b"\x00" + section                # flags + section kind 0
    return le32(16 + len(body)) + le32(1) + le32(0) + le32(2013) + body


def bson_document(fields: Sequence[Tuple[str, Any]]) -> bytes:
    """A BSON document: the four most common element types and the length prefix."""
    body = bytearray()
    for key, value in fields:
        if isinstance(value, bool):                        # before int: bool is an int
            body += b"\x08" + key.encode() + b"\x00" + (b"\x01" if value else b"\x00")
        elif isinstance(value, int):
            body += b"\x10" + key.encode() + b"\x00" + le32(value & 0xFFFFFFFF)
        elif isinstance(value, float):
            body += b"\x01" + key.encode() + b"\x00" + struct.pack("<d", value)
        else:
            raw = str(value).encode()
            body += b"\x02" + key.encode() + b"\x00" + le32(len(raw) + 1) + raw + b"\x00"
    return le32(len(body) + 5) + bytes(body) + b"\x00"


def parse_bson(data: bytes) -> Dict[str, Any]:
    """Decode one BSON document: bools, int32, doubles, strings and nested documents."""
    out: Dict[str, Any] = {}
    if len(data) < 5:
        return out
    offset, end = 4, min(len(data), le32_at(data, 0) or len(data))
    while offset < end - 1:
        kind = data[offset]
        offset += 1
        zero = data.find(b"\x00", offset)
        if zero < 0 or zero > end:
            break
        key = data[offset:zero].decode("utf-8", "replace")
        offset = zero + 1
        if kind == 0x01 and offset + 8 <= end:
            out[key] = struct.unpack_from("<d", data, offset)[0]
            offset += 8
        elif kind == 0x02 and offset + 4 <= end:
            length = le32_at(data, offset)
            out[key] = data[offset + 4:offset + 4 + length - 1].decode("utf-8", "replace")
            offset += 4 + length
        elif kind in (0x03, 0x04) and offset + 4 <= end:
            length = le32_at(data, offset)
            out[key] = parse_bson(data[offset:offset + length])
            offset += length
        elif kind == 0x08 and offset < end:
            out[key] = bool(data[offset])
            offset += 1
        elif kind == 0x0A:
            out[key] = None
        elif kind in (0x10, 0x12) and offset + 4 <= end:
            out[key] = le32_at(data, offset)
            offset += 4
        elif kind == 0x11 and offset + 8 <= end:
            out[key] = struct.unpack_from("<q", data, offset)[0]
            offset += 8
        else:
            break
    return out


def parse_mongo(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"length": 0, "request_id": 0, "opcode": 0, "documents": 0,
                           "fields": {}, "text": "", "max_wire": 0, "version": ""}
    if len(data) < 16:
        return out
    out["length"] = struct.unpack_from("<i", data, 0)[0]
    out["request_id"] = struct.unpack_from("<i", data, 8)[0]
    out["opcode"] = struct.unpack_from("<i", data, 12)[0]
    out["text"] = printable(data)
    body = data[16:]
    documents: List[Dict[str, Any]] = []
    if out["opcode"] == 2013 and len(body) >= 5:            # OP_MSG: flag bits, then sections
        offset = 4
        while offset < len(body):
            kind = body[offset]
            if kind == 0 and offset + 1 < len(body):        # a body section: one document
                length = le32_at(body, offset + 1)
                if length <= 0:
                    break
                documents.append(parse_bson(body[offset + 1:offset + 1 + length]))
                offset += 1 + length
            elif kind == 1:                                 # a document sequence
                size = le32_at(body, offset + 1)
                if size <= 0:
                    break
                inner = body[offset + 5:offset + 1 + size]
                while len(inner) >= 5:
                    length = le32_at(inner, 0)
                    if length <= 0 or length > len(inner):
                        break
                    documents.append(parse_bson(inner[:length]))
                    inner = inner[length:]
                offset += 1 + size
            else:
                break
    elif out["opcode"] == 1:                                # OP_REPLY: one or more documents
        offset = 20
        while offset + 5 <= len(data):
            length = le32_at(data, offset)
            if length <= 0 or offset + length > len(data):
                break
            documents.append(parse_bson(data[offset:offset + length]))
            offset += length
    for document in documents:
        out["fields"].update({k: v for k, v in document.items() if k != "ok"})
    out["documents"] = len(documents)
    out["fields"].setdefault("version", "")
    out["max_wire"] = int(out["fields"].get("maxWireVersion", 0) or 0)
    out["version"] = str(out["fields"].get("version", ""))
    return out


# --------------------------------------------------------------------------- #
# Kasa / TP-Link Smart Home (9999/udp) — XOR with a fixed autokey
# --------------------------------------------------------------------------- #

KASA_AUTOKEY = 0x5A6B7C8D


def kasa_encrypt(payload: bytes, key: int = KASA_AUTOKEY) -> bytes:
    """The whole 'encryption' of the Kasa protocol: XOR with a rotating 4-byte key."""
    key_bytes = struct.pack(">I", key)
    return bytes(byte ^ key_bytes[index % 4] for index, byte in enumerate(payload))


def kasa_decrypt(payload: bytes, key: int = KASA_AUTOKEY) -> bytes:
    return kasa_encrypt(payload, key)                      # XOR is its own inverse


def kasa_command(command: str = "systeminfo", argument: Optional[Dict[str, Any]] = None,
                 request_id: str = "wp1") -> bytes:
    """The JSON frame, XORed, plus the 4-byte length header the device expects."""
    body: Dict[str, Any] = {command: dict(argument or {})}
    if command == "systeminfo":
        body[command] = {"get_sysinfo": {}}
    elif command == "toggle":
        body[command] = {"set_relay_state": {"state": 0}}
    elif command == "info":
        body[command] = {"get_dev_info": {}}
    else:
        body[command] = dict(argument or {})
    body["context"] = {"source": request_id}
    raw = json.dumps(body).encode()
    encrypted = kasa_encrypt(raw)
    return be32(len(encrypted)) + encrypted


def parse_kasa(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"length": 0, "decrypted": "", "fields": {}, "model": "",
                           "alias": "", "relay_state": None, "error_code": 0}
    if len(data) > 4:
        out["length"] = be32_at(data, 0)
        payload = data[4:]
        key = next((k for k in (KASA_AUTOKEY, 0x00000000) if b"{" in kasa_decrypt(payload, k)),
                   KASA_AUTOKEY)
        decrypted = kasa_decrypt(payload, key)
        out["decrypted"] = decrypted.decode("utf-8", "replace")
        try:
            loaded = json.loads(out["decrypted"])
            out["fields"] = loaded
            info = loaded.get("system", {}).get("get_sysinfo", {}) or \
                loaded.get("system", {}).get("get_dev_info", {})
            out["model"] = info.get("model", "") or info.get("model_name", "")
            out["alias"] = info.get("alias", "")
            out["relay_state"] = info.get("relay_state")
            out["error_code"] = loaded.get("system", {}).get("set_relay_state", {}).get(
                "err_code", 0)
        except ValueError:
            out["fields"] = {}
    return out


# --------------------------------------------------------------------------- #
# DICOM (104/11112) — clinical imaging, echo and association
# --------------------------------------------------------------------------- #

DICOM_PDU = {"associate-request": 0x01, "associate-accept": 0x02,
             "associate-reject": 0x03, "data": 0x04, "release-request": 0x05,
             "release-response": 0x06, "abort": 0x07}

DICOM_SOP_VERIFICATION = "1.2.840.10008.1.1"


def _dicom_item(tag: int, body: bytes) -> bytes:
    return bytes([tag, 0x00]) + be16(len(body)) + body


def _dicom_element(group: int, element: int, value: bytes) -> bytes:
    """An implicit-VR element: group, element, 32-bit length, value."""
    return struct.pack("<HH", group, element) + le32(len(value)) + value


def dicom_associate(called: str = "ANY-SCP", calling: str = "WIFIPILOT") -> bytes:
    """A-ASSOCIATE-RQ offering the verification presentation context (C-ECHO)."""
    uid = DICOM_SOP_VERIFICATION
    abstract = _dicom_item(0x30, uid.encode() + (b"\x00" if len(uid) % 2 else b""))
    transfer = _dicom_item(0x40, b"1.2.840.10008.1.2")     # implicit VR, little endian
    context = bytes([0x20, 0x00]) + be16(4 + len(abstract) + len(transfer)) + \
        b"\x01\x00\x00\x00" + abstract + transfer
    user = _dicom_item(0x50, b"\x00\x00\x01\x00\x00\x00" +
                       _dicom_item(0x51, b"\x01\x00") + _dicom_item(0x52, calling.encode()))
    body = (b"\x00\x01" + b"\x00\x00" + called.encode().ljust(16, b" ")[:16] +
            calling.encode().ljust(16, b" ")[:16] + b"\x00" * 32 + context + user)
    return bytes([DICOM_PDU["associate-request"], 0x00]) + be32(len(body)) + body


def dicom_echo(message_id: int = 1) -> bytes:
    """C-ECHO-RQ as a P-DATA-TF PDU: command group, then the six elements it needs."""
    uid = DICOM_SOP_VERIFICATION
    entries = (_dicom_element(0, 0x0002, uid.encode() + (b"\x00" if len(uid) % 2 else b"")) +
               _dicom_element(0, 0x0100, le16(0x0030)) +        # C-ECHO-RQ
               _dicom_element(0, 0x0110, le16(message_id)) +
               _dicom_element(0, 0x0800, le16(0x0101)))         # no data set
    command = _dicom_element(0, 0x0000, le32(len(entries))) + entries
    body = b"\x01\x00\x00\x00" + be32(len(command)) + command
    return bytes([DICOM_PDU["data"], 0x00]) + be32(len(body)) + body


def parse_dicom_pdu(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"type": 0, "type_name": "", "length": 0, "called": "",
                           "calling": "", "implementation": "", "result": 0,
                           "accepted": False, "body": data}
    if len(data) < 6:
        return out
    out["type"] = data[0]
    out["type_name"] = next((name for name, code in DICOM_PDU.items() if code == data[0]),
                            f"pdu {data[0]}")
    out["length"] = be32_at(data, 2)
    text = printable(data)
    match = re.search(r"([A-Z][A-Z0-9_\-]{2,31})", text)
    if match:
        out["calling"] = match.group(1)
    out["accepted"] = data[0] in (0x02, 0x04)
    if data[0] == 0x06:
        out["accepted"] = True
    return out


# --------------------------------------------------------------------------- #
# S7comm (102) — Siemens, over the ISO-TSAP "COTP" connection
# --------------------------------------------------------------------------- #

def s7_connect_request(rack: int = 0, slot: int = 2) -> bytes:
    """The COTP connection request that opens an ISO-on-TCP session to a Siemens PLC."""
    params = bytes([0xC0, 0x01, 0x0A, 0xC1, 0x02, 0x01, 0x00, 0xC2, 0x02, 0x01,
                    0x02 if slot == 1 else 0x03, 0xC0, 0x01, 0x09])
    cotp = bytes([0x11, 0xE0]) + be16(len(params) + 1) + b"\x00\x00" + \
        bytes([len(params), 0xC0]) + params[2:]
    tpkt = b"\x03\x00" + be16(len(cotp) + 4)
    return tpkt + cotp


def s7_message(rosctr: int, params: bytes, data: bytes = b"",
               reference: int = 1) -> bytes:
    """One S7 PDU: the 10-byte header, the parameter section, then the data section.

    The header is fixed-width (protocol id, PDU type, two reserved bytes, the PDU
    reference, then *both* section lengths), which is what lets a reader find the data
    section without knowing the parameter layout of every function.
    """
    header = bytes([0x32, rosctr & 0xFF, 0x00, 0x00]) + be16(reference) + \
        be16(len(params)) + be16(len(data))
    return header + params + data


def s7_read_szl(szl_id: int = 0x001C) -> bytes:
    """An S7comm userdata request for the component identification (SZL 0x1C)."""
    params = bytes([0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00]) + \
        bytes([szl_id >> 8, szl_id & 0xFF]) + b"\x00\x00"
    data = bytes([0xFF, 0x09, 0x00, 0x04, 0x00, 0x00])
    s7 = s7_message(0x07, params, data)
    cotp = bytes([0x02, 0xF0, 0x80])
    return b"\x03\x00" + be16(len(s7) + len(cotp) + 4) + cotp + s7


#: Siemens SZL records write their text fields fixed-width and NUL padded
SZL_TEXT_SIZE = 20


def szl_record(index: int, *texts: str) -> bytes:
    """One SZL data record: the index, then the fixed-width text fields.

    The component-identification SZL (id 0x001C) answers with the module type, the
    module name, the serial number and the vendor of the rack it lives in.
    """
    record = be16(index)
    for text in texts:
        raw = text.encode("latin-1", "replace")[:SZL_TEXT_SIZE]
        record += raw + b"\x00" * (SZL_TEXT_SIZE - len(raw))
    return record


def parse_szl(data: bytes) -> List[Dict[str, Any]]:
    """Split an S8/S7 data block into ``szl_record``s and decode their text fields."""
    if data[:2] == b"\xff\x09" and len(data) >= 6:
        data = data[6:]                 # the data-item header: function, count, reserved
    records: List[Dict[str, Any]] = []
    offset = 0
    while offset + SZL_TEXT_SIZE * 3 <= len(data):
        index = be16_at(data, offset)
        offset += 2
        texts: List[str] = []
        while offset + SZL_TEXT_SIZE <= len(data) and len(texts) < 4:
            chunk = data[offset:offset + SZL_TEXT_SIZE]
            offset += SZL_TEXT_SIZE
            if any(byte < 0x09 or byte > 0x7E for byte in chunk.rstrip(b"\x00")):
                break                                          # not a text field: stop here
            texts.append(chunk.rstrip(b"\x00").decode("latin-1", "replace"))
        if not texts:
            break
        records.append({"index": index, "fields": texts})
    return records


def parse_s7(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"tpkt": 0, "cotp_type": 0, "s7": False, "rosctr": 0,
                           "plc": "", "module": "", "serial": "", "vendor": "",
                           "szl": [], "text": ""}
    if len(data) < 4:
        return out
    out["tpkt"] = data[0]
    out["cotp_type"] = data[5] if len(data) > 5 else 0
    s7_offset = 7 if len(data) > 7 else 0
    if data[s7_offset:s7_offset + 1] == b"\x32":
        out["s7"] = True
        out["rosctr"] = data[s7_offset + 1] if len(data) > s7_offset + 1 else 0
    out["text"] = printable(data[s7_offset:])
    payload = data[s7_offset:]
    if out["s7"] and len(payload) >= 10:
        params_length = be16_at(payload, 6)
        data_length = be16_at(payload, 8)
        section = payload[10 + params_length:10 + params_length + data_length]
        payload = section or payload
    records = parse_szl(payload) if out["s7"] else []
    out["szl"] = records
    if records:
        fields = records[0]["fields"]
        out["plc"], out["module"] = fields[0], fields[1] if len(fields) > 1 else ""
        out["serial"] = fields[2] if len(fields) > 2 else ""
        out["vendor"] = fields[3] if len(fields) > 3 else ""
    else:                                                  # a plain response: look for text
        for field in ("plc", "module", "serial"):
            match = re.search(rf"{field}[^:]*:?\s*\"?([\w\-\. ]{{3,32}})", out["text"], re.I)
            if match:
                out[field] = match.group(1).strip()
    return out


# --------------------------------------------------------------------------- #
# EtherNet/IP + CIP (44818/udp) — Rockwell and friends
# --------------------------------------------------------------------------- #

def cip_list_identity(session: int = 0, sender: bytes = b"\x01\x02\x03\x04") -> bytes:
    """List-Identity: the discovery command every EtherNet/IP device answers.

    The encapsulation header is exactly 24 bytes — command, length, session handle,
    status, an 8-byte sender context and options — and the sender context is what the
    device echoes back, which is how a reply is matched to the probe.
    """
    sender = (sender + b"\x00" * 8)[:8]
    return le16(0x0063) + le16(0) + le32(session) + le32(0) + sender + le32(0)


def parse_cip(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"command": 0, "length": 0, "vendor": 0, "device_type": 0,
                           "product_code": 0, "revision": "", "status": 0, "serial": 0,
                           "product_name": "", "state": 0, "text": ""}
    if len(data) < 24:
        return out
    out["command"] = struct.unpack_from("<H", data, 0)[0]
    out["length"] = struct.unpack_from("<H", data, 2)[0]
    body = data[24:]
    if len(body) >= 33:
        out["vendor"] = struct.unpack_from("<H", body, 0)[0]
        out["device_type"] = struct.unpack_from("<H", body, 2)[0]
        out["product_code"] = struct.unpack_from("<H", body, 4)[0]
        major, minor = body[6], body[7]
        out["revision"] = f"{major}.{minor}"
        out["status"] = struct.unpack_from("<H", body, 8)[0]
        out["serial"] = struct.unpack_from("<I", body, 10)[0]
        name_length = body[18]
        out["product_name"] = body[19:19 + min(name_length, 32)].decode("latin-1",
                                                                        "replace").strip()
        out["state"] = body[19 + name_length] if len(body) > 19 + name_length else 0
    out["text"] = printable(data)
    return out


# --------------------------------------------------------------------------- #
# DNP3 (20000) — telemetry to a SCADA master
# --------------------------------------------------------------------------- #

def _dnp3_crc(data: bytes) -> bytes:
    """CRC-DNP: polynomial 0x3D65, reflected, pre/post inversion, little end first."""
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
    crc = ~crc & 0xFFFF
    return struct.pack("<H", crc)


def dnp3_crc(data: bytes) -> bytes:
    return _dnp3_crc(data)


def _dnp3_frame(control: int, destination: int = 1, source: int = 1024,
                payload: bytes = b"") -> bytes:
    header = bytes([0x05, 0x64, control]) + struct.pack("<HH", destination, source) + \
        _dnp3_crc(bytes([0x05, 0x64, control]))
    body = b""
    for index in range(0, len(header) + len(payload), 16):
        chunk = (header + payload)[index:index + 16]
        body += chunk + _dnp3_crc(chunk)
    return b"\x05\x64" + struct.pack("<H", len(payload)) + \
        _dnp3_crc(bytes([0x05, 0x64]) + struct.pack("<H", len(payload))) + body


def dnp3_reset_link(destination: int = 1, source: int = 1024) -> bytes:
    """The link-layer reset every DNP3 outstation answers — with no authentication."""
    return _dnp3_frame(0xC0, destination, source)


def dnp3_integrity_poll(destination: int = 1, source: int = 1024) -> bytes:
    """Application-layer class 0/1/2/3 integrity poll: the master's own start-up read."""
    app = bytes([0xC0, 0x01, 0x3C, 0x02, 0x06, 0x3C, 0x04, 0x06])
    return _dnp3_frame(0xC4, destination, source, app)


def parse_dnp3(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"start": 0, "control": 0, "destination": 0, "source": 0,
                           "function": 0, "iin": 0, "text": "", "crc_ok": False}
    if len(data) < 10:
        return out
    out["start"] = be16_at(data, 0)
    out["control"] = data[3] if len(data) > 3 else 0
    out["destination"] = struct.unpack_from("<H", data, 4)[0]
    out["source"] = struct.unpack_from("<H", data, 6)[0]
    out["crc_ok"] = _dnp3_crc(data[0:3]) == data[3:5]
    out["function"] = data[11] if len(data) > 11 else 0
    out["iin"] = be16_at(data, 12) if len(data) > 12 else 0
    out["text"] = printable(data)
    return out


# --------------------------------------------------------------------------- #
# IEC 60870-5-104 (2404) — the other SCADA telemetry protocol
# --------------------------------------------------------------------------- #

#: ASDU type identifications (IEC 60870-5-101/104) worth naming in a report
IEC104_TYPES = {1: "single point information", 3: "double point information",
                5: "step position", 9: "normalized value", 11: "scaled value",
                13: "float value", 15: "integrated totals", 30: "single point with time",
                36: "measured value with time", 45: "single command", 100: "interrogation",
                101: "counter interrogation", 103: "clock synchronization",
                110: "parameter of a measured value"}

#: causes of transmission
IEC104_COT = {1: "periodic", 2: "background", 3: "spontaneous", 4: "initialized",
              5: "request", 6: "activation", 7: "activation confirmation",
              8: "deactivation", 9: "deactivation confirmation", 10: "termination",
              20: "interrogated by station", 44: "unknown type", 45: "unknown cause",
              46: "unknown common address", 47: "unknown information object"}


def _iec104(control: int, payload: bytes = b"") -> bytes:
    """A U-frame: the control field is a single byte with the two low bits set."""
    return b"\x68" + bytes([len(payload) + 4]) + control.to_bytes(4, "little") + payload


def _iec104_i(asdu: bytes, send_sequence: int = 0, receive_sequence: int = 0) -> bytes:
    """An I-frame: numbered, and the only frame type that carries an ASDU."""
    control = le16((send_sequence & 0x7FFF) << 1) + le16((receive_sequence & 0x7FFF) << 1)
    return b"\x68" + bytes([len(control) + len(asdu)]) + control + asdu


def iec104_start(activate: bool = True) -> bytes:
    """STARTDT act: asks the outstation to start sending data (U-frame)."""
    return _iec104(0x07 if activate else 0x13)


def iec104_interrogation(common_address: int = 1, qualifier: int = 20) -> bytes:
    """General interrogation (C_IC_NA_1, type 100) with no authentication in the protocol."""
    asdu = (bytes([100, 0x01, 0x06, 0x00]) + le16(common_address) +
            b"\x00\x00\x00" + bytes([qualifier]))
    return _iec104_i(asdu)


def iec104_confirmation(common_address: int = 1, qualifier: int = 20,
                        send_sequence: int = 0, receive_sequence: int = 1) -> bytes:
    """The activation confirmation an outstation sends back for an interrogation."""
    asdu = (bytes([100, 0x01, 0x07, 0x00]) + le16(common_address) +
            b"\x00\x00\x00" + bytes([qualifier]))
    return _iec104_i(asdu, send_sequence, receive_sequence)


def iec104_measurement(ioa: int = 16385, value: float = 0.0, common_address: int = 1,
                       send_sequence: int = 1, receive_sequence: int = 1) -> bytes:
    """A measured value (M_ME_NC_1, type 13) — what a substation actually reports."""
    asdu = (bytes([13, 0x01, 0x03, 0x00]) + le16(common_address) +
            ioa.to_bytes(3, "little") + struct.pack("<f", value))
    return _iec104_i(asdu, send_sequence, receive_sequence)


def parse_iec104(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"start": 0, "length": 0, "type": 0, "type_name": "", "vsq": 0,
                           "cot": 0, "cot_name": "", "originator": 0, "ioa": 0,
                           "send_sequence": 0, "receive_sequence": 0, "u_function": "",
                           "frames": 0, "common_address": 0, "text": "", "u_frame": False,
                           "s_frame": False, "i_frame": False}
    if len(data) < 6 or data[0] != 0x68:
        return out
    out["start"] = data[0]
    out["length"] = data[1]
    control = data[2]
    out["i_frame"] = control & 0x01 == 0                     # bit 0 clear: numbered frame
    out["s_frame"] = not out["i_frame"] and control & 0x03 == 0x01
    out["u_frame"] = not out["i_frame"] and control & 0x03 == 0x03
    if out["i_frame"] and len(data) >= 12:
        out["send_sequence"] = le16_at(data, 2) >> 1
        out["receive_sequence"] = le16_at(data, 4) >> 1
        out["type"] = data[6]
        out["type_name"] = IEC104_TYPES.get(out["type"], f"type {out['type']}")
        out["vsq"] = data[7]
        out["cot"] = data[8]
        out["cot_name"] = IEC104_COT.get(data[8], f"cause {data[8]}")
        out["originator"] = data[9]
        out["common_address"] = le16_at(data, 10)            # IEC 60870-5 speaks little-endian
        out["ioa"] = data[12] | (data[13] << 8) | (data[14] << 16) if len(data) >= 15 else 0
    elif out["u_frame"] and len(data) >= 6:
        out["u_function"] = {0x07: "STARTDT act", 0x0B: "STARTDT con", 0x13: "STOPDT act",
                             0x23: "STOPDT con", 0x43: "TESTFR act", 0x83: "TESTFR con"}.get(
            control, f"U {control:#04x}")
    elif out["s_frame"]:
        out["receive_sequence"] = le16_at(data, 4) >> 1
    out["text"] = printable(data)
    return out


# --------------------------------------------------------------------------- #
# OPC-UA (4840) — HEL/ACK, the only part of the handshake with no channel to set up
# --------------------------------------------------------------------------- #

def opcua_hello(endpoint_url: str = "opc.tcp://192.168.1.10:4840",
                max_message: int = 65536) -> bytes:
    """The HEL message every OPC-UA server answers with an ACK and its own limits."""
    body = (le32(0) + le32(max_message) + le32(max_message) + le32(max_message) +
            le32(0) + le32(len(endpoint_url)) + endpoint_url.encode())
    return b"HELF" + le32(len(body) + 8) + body


def parse_opcua(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"type": "", "size": 0, "chunk": "", "max_message": 0,
                           "max_chunk": 0, "version": 0, "text": ""}
    if len(data) < 8:
        return out
    out["type"] = data[0:3].decode("latin-1", "replace")
    out["chunk"] = data[3:4].decode("latin-1", "replace")
    out["size"] = le32_at(data, 4)
    if out["type"] == "ACK" and len(data) >= 28:
        out["version"] = le32_at(data, 12)
        out["max_message"] = le32_at(data, 16)
        out["max_chunk"] = le32_at(data, 20)
    out["text"] = printable(data)
    return out


# --------------------------------------------------------------------------- #
# line protocols: one builder, one parser, per-protocol quirks
# --------------------------------------------------------------------------- #

def line_command(command: str, newline: str = "\r\n") -> bytes:
    """The text protocols (FTP, SMTP, IMAP, POP3, rsync's daemon) all start this way."""
    return (command.strip() + newline).encode()


def parse_line_protocol(data: bytes) -> Dict[str, Any]:
    """Status code, banner and capability lines from any of those protocols."""
    text = data.decode("utf-8", "replace")
    lines = [line.rstrip("\r") for line in text.splitlines() if line.strip()]
    out: Dict[str, Any] = {"status": 0, "banner": lines[0] if lines else "", "lines": lines,
                           "text": printable(data), "capabilities": [], "auth_types": [],
                           "anonymous": False, "tls": False}
    if lines:
        match = re.match(r"(\d{3})", lines[0])
        if match:
            out["status"] = int(match.group(1))
        elif lines[0].startswith("+") or lines[0].startswith("*"):
            out["status"] = 200 if lines[0].startswith("+") else 0
    for line in lines:
        upper = line.upper()
        if upper.startswith(("250-", "250 ", "* CAPABILITY", "+OK", "220-")):
            out["capabilities"].append(line.strip())
        for flag in ("STARTTLS", "AUTH PLAIN", "AUTH LOGIN", "LOGIN"):
            if flag in upper and flag not in out["auth_types"]:
                out["auth_types"].append(flag)
        if "ANONYMOUS" in upper:
            out["anonymous"] = True
        if "TLS" in upper:
            out["tls"] = True
    return out


def smtp_ehlo(domain: str = "wifipilot.local") -> bytes:
    return line_command(f"EHLO {domain}")


def imap_login(user: str = "admin", password: str = "admin") -> bytes:
    return line_command(f'a001 LOGIN "{user}" "{password}"')


def ftp_login(user: str = "anonymous", password: str = "wifipilot@example.com") -> bytes:
    """USER and PASS in one payload: what a scanner sends, and what a daemon answers."""
    if not password:
        return line_command(f"USER {user}")
    return line_command(f"USER {user}") + line_command(f"PASS {password}")


def rsync_hello(module: str = "") -> bytes:
    """The rsync daemon's greeting is unauthenticated; a module name lists its files."""
    return line_command(module or "#list")


# --------------------------------------------------------------------------- #
# SSH (22), RDP (3389), VNC (5900), MySQL (3306), Postgres (5432), NTP, STUN
# --------------------------------------------------------------------------- #

def ssh_kexinit() -> bytes:
    """An SSH identification string plus a KEXINIT: the banner is what names the version."""
    return b"SSH-2.0-wifipilot_1.0\r\n" + b"\x00\x00\x01\x14\x14" + b"\x00" * 16


def parse_ssh_algorithms(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"banner": "", "kex": [], "host_keys": [], "ciphers": [],
                           "macs": [], "compression": [], "text": ""}
    text = data.decode("latin-1", "replace")
    match = re.search(r"(SSH-[\d.]+-[^\r\n]{1,64})", text)
    if match:
        out["banner"] = match.group(1)
    for key in ("kex", "host_keys", "ciphers", "macs", "compression"):
        found = re.findall(rf"({key.replace('_', '-')})[\w\-]*[^\r\n]*", text, re.I)
        out[key] = found[:1]
    names = re.findall(r"(curve25519[\w\-]*|ecdh[\w\-]*|diffie-hellman[\w\-]*|"
                       r"ssh-[\w\-@.]+|aes[\w\-]*|chacha20[\w\-]*|hmac[\w\-]*)", text)
    out["ciphers"] = [n for n in dict.fromkeys(names) if "aes" in n or "chacha" in n]
    out["kex"] = [n for n in dict.fromkeys(names) if "diffie" in n or "curve" in n or
                  "ecdh" in n]
    out["macs"] = [n for n in dict.fromkeys(names) if "hmac" in n]
    out["text"] = printable(data)
    return out


def rdp_negotiation_request(requested: int = 0x00000001 | 0x00000008) -> bytes:
    """The X.224 connection request whose RDP negotiation blob reports the security."""
    cookie = b"Cookie: mstshash=wifipilot\r\n"
    nego = b"\x01\x00\x08\x00\x03\x00\x00\x00"              # version, length, requested
    x224 = bytes([len(cookie) + len(nego) + 12 + 7, 0xE0]) + b"\x00\x00\x00\x00\x00"
    x224 = bytes([len(cookie) + len(nego) + 13, 0xE0]) + b"\x00\x00\x00\x00\x00" + cookie
    return b"\x03\x00" + be16(len(x224) + len(nego) + 4) + x224 + nego


def parse_rdp(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"tpkt": 0, "length": 0, "x224": 0, "neg_response": 0,
                           "selected_protocol": 0, "tls": False, "text": ""}
    if len(data) < 4:
        return out
    out["tpkt"] = data[0]
    out["length"] = be16_at(data, 2)
    if len(data) > 11:
        out["x224"] = data[5]
        out["neg_response"] = data[11]
        if len(data) > 15:
            out["selected_protocol"] = le32_at(data, 12)
            out["tls"] = bool(out["selected_protocol"] & 0x01)
    out["text"] = printable(data)
    return out


def vnc_version() -> bytes:
    return b"RFB 003.008\n"


def parse_vnc_security(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"version": "", "security_types": [], "none": False,
                           "vnc_auth": False, "tls": False, "text": ""}
    text = data.decode("latin-1", "replace")
    match = re.search(r"(RFB \d{3}\.\d{3})", text)
    if match:
        out["version"] = match.group(1)
    if data.startswith(b"RFB") and len(data) > 12:
        count = data[12]                          # version string is 12 bytes: count at 12
        types = list(data[13:13 + count])
        names = {0: "invalid", 1: "none", 2: "vnc-auth", 5: "ra2", 6: "ra2ne", 16: "tight",
                 18: "tls", 19: "vencrypt", 20: "sasl"}
        out["security_types"] = [names.get(t, str(t)) for t in types]
        out["none"] = 1 in types
        out["vnc_auth"] = 2 in types
        out["tls"] = any(t in types for t in (18, 19))
    out["text"] = printable(data)
    return out


def mysql_handshake_parse(data: bytes) -> Dict[str, Any]:
    """The initial handshake packet names the server, its version and its auth plugin."""
    out: Dict[str, Any] = {"protocol": 0, "version": "", "connection_id": 0, "plugin": "",
                           "capabilities": 0, "salt": b"", "tls": False, "tls_required": False}
    # a MySQL packet is three length bytes and a sequence number, then the payload
    start = 4 if len(data) > 4 and data[4] == 0x0A else 0
    if len(data) < start + 5 or data[start] != 0x0A:
        return out
    out["protocol"] = data[start]
    end = data.index(b"\x00", start + 1) if b"\x00" in data[start + 1:] else len(data)
    out["version"] = data[start + 1:end].decode("latin-1", "replace")
    offset = end + 1
    # connection id (4) + auth-plugin-data part 1 (8) + filler (1) come first: the
    # capability flags live *thirteen* bytes after the version's terminating NUL
    out["connection_id"] = le32_at(data, offset) if len(data) > offset + 4 else 0
    flags_at = offset + 13
    capabilities = int.from_bytes(data[flags_at:flags_at + 2], "little") \
        if len(data) > flags_at + 1 else 0
    out["capabilities"] = capabilities
    out["tls"] = bool(out["capabilities"] & 0x0800)
    out["tls_required"] = bool(out["capabilities"] & 0x0800) and not (capabilities & 0x0008)
    tail = data[flags_at + 5:]
    plugin = re.search(rb"(caching_sha2_password|mysql_native_password|sha256_password|"
                       rb"auth_gssapi_client|mysql_clear_password)", tail)
    out["plugin"] = plugin.group(1).decode() if plugin else ""
    out["salt"] = tail[-12:] if len(tail) >= 12 else tail
    return out


def postgres_startup(user: str = "postgres", database: str = "postgres") -> bytes:
    """A startup message: Postgres answers with the authentication method it wants."""
    params = b"user\x00" + user.encode() + b"\x00database\x00" + database.encode() + b"\x00\x00"
    return be32(len(params) + 8) + be32(196608) + params


def parse_postgres(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"type": "", "length": 0, "auth_type": 0, "auth_name": "",
                           "error": "", "text": "", "md5": False, "cleartext": False,
                           "scram": False}
    names = {0: "AuthenticationOk", 2: "KerberosV5", 3: "CleartextPassword",
             5: "MD5Password", 7: "GSS", 9: "SSPI", 10: "SASL"}
    if len(data) < 5:
        return out
    out["type"] = chr(data[0])
    out["length"] = be32_at(data, 1)
    if out["type"] == "R" and len(data) >= 9:
        out["auth_type"] = be32_at(data, 5)      # the wire is big endian, like TCP
        out["auth_name"] = names.get(out["auth_type"], f"type {out['auth_type']}")
        out["md5"] = out["auth_type"] == 5
        out["cleartext"] = out["auth_type"] == 3
        out["scram"] = out["auth_type"] == 10
    if out["type"] == "E":
        out["error"] = printable(data[5:])
    out["text"] = printable(data)
    return out


def ntp_client(version: int = 4) -> bytes:
    """A mode-3 client packet: 48 bytes, version in the first byte."""
    return bytes([(version << 3) | 3]) + b"\x00" * 47


def parse_ntp(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"version": 0, "mode": 0, "stratum": 0, "poll": 0, "precision": 0,
                           "reference_id": "", "leap": 0, "text": ""}
    if len(data) < 48:
        return out
    out["leap"] = data[0] >> 6
    out["version"] = (data[0] >> 3) & 0x07
    out["mode"] = data[0] & 0x07
    out["stratum"] = data[1]
    out["poll"] = data[2]
    out["precision"] = struct.unpack("b", data[3:4])[0]
    out["reference_id"] = printable(data[12:16])
    out["text"] = printable(data)
    return out


def stun_binding(message_id: bytes = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c") -> bytes:
    """STUN binding request with the magic cookie — what a NAT-traversal probe sends."""
    return be16(0x0001) + be16(0) + b"\x21\x12\xA4\x42" + message_id[:12]


def parse_stun(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"type": 0, "type_name": "", "length": 0, "cookie": False,
                           "mapped_address": "", "attributes": [], "text": ""}
    if len(data) < 20:
        return out
    out["type"] = be16_at(data, 0)
    out["type_name"] = {0x0001: "binding request", 0x0101: "binding success",
                        0x0111: "binding error"}.get(out["type"], f"type {out['type']}")
    out["length"] = be16_at(data, 2)
    out["cookie"] = data[4:8] == b"\x21\x12\xA4\x42"
    offset = 20
    while offset + 4 <= len(data):
        attribute = be16_at(data, offset)
        length = be16_at(data, offset + 2)
        value = data[offset + 4:offset + 4 + length]
        out["attributes"].append({0x0001: "MAPPED-ADDRESS", 0x0020: "XOR-MAPPED-ADDRESS",
                                  0x0008: "MESSAGE-INTEGRITY", 0x8022: "SOFTWARE",
                                  0x8028: "FINGERPRINT"}.get(attribute, str(attribute)))
        if attribute in (0x0001, 0x0020) and len(value) >= 8:
            port = be16_at(value, 2)
            address = ".".join(str(b) for b in value[4:8])
            if attribute == 0x0020:
                port ^= 0x2112
                address = ".".join(str(b ^ 0x21) if index < 1 else str(b ^ 0x12)
                                   for index, b in enumerate(value[4:8]))
            out["mapped_address"] = f"{address}:{port}"
        offset += 4 + length
    return out


# --------------------------------------------------------------------------- #
# ADB (5555), PJLink (4352), miIO (54321), CAST (8009), AirPlay (7000)
# --------------------------------------------------------------------------- #

ADB_CNXN = 0x4E584E43
ADB_AUTH = 0x48545541
ADB_OPEN = 0x4E45504F
ADB_OKAY = 0x59414B4F


def adb_connect(payload: bytes = b"host::\x00", banner: str = "wifipilot") -> bytes:
    """CNXN: the packet an ADB client sends first, and the one that needs no key."""
    data = payload + banner.encode() + b"\x00"
    # ADB header: command, arg0, arg1, data length, data checksum, magic (cmd ^ 0xFFFFFFFF)
    return (le32(ADB_CNXN) + le32(0x01000001) + le32(4096) + le32(len(data)) +
            le32(zlib.crc32(data) & 0xFFFFFFFF) + le32(ADB_CNXN ^ 0xFFFFFFFF) + data)


def parse_adb(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"command": "", "arg0": 0, "arg1": 0, "length": 0,
                           "device": "", "banner": "", "authorised": False, "text": ""}
    if len(data) < 24:
        return out
    names = {ADB_CNXN: "CNXN", ADB_AUTH: "AUTH", ADB_OPEN: "OPEN", ADB_OKAY: "OKAY"}
    command = le32_at(data, 0)
    out["command"] = names.get(command, hex(command))
    out["arg0"] = le32_at(data, 4)
    out["arg1"] = le32_at(data, 8)
    out["length"] = le32_at(data, 12)
    out["checksum"] = le32_at(data, 16)
    out["magic_ok"] = le32_at(data, 20) == (command ^ 0xFFFFFFFF)
    body = data[24:24 + out["length"]]
    out["text"] = printable(body)
    match = re.search(r"(device|emulator-\d+)[\w:\-]*", out["text"])
    if match:
        out["device"] = match.group(0)
    out["authorised"] = out["command"] == "CNXN"
    out["banner"] = out["text"]
    return out


def pjlink_command(command: str = "POWR", argument: str = "?") -> bytes:
    """PJLink: '%%1POWR ?' asks a projector for its power state, with no authentication."""
    return f"%1{command.upper()} {argument}\r".encode()


def parse_pjlink(data: bytes) -> Dict[str, Any]:
    text = printable(data)
    out: Dict[str, Any] = {"text": text, "command": "", "status": "", "parameter": "",
                           "responds": text.startswith("%1"), "error": ""}
    match = re.match(r"%1(\w{4})=(.*)", text)
    if match:
        out["command"] = match.group(1)
        out["parameter"] = match.group(2).strip()
        out["status"] = {"OK": "accepted", "ERR1": "undefined command",
                         "ERR2": "out of parameter", "ERR3": "unavailable",
                         "ERR4": "device failure"}.get(out["parameter"],
                                                       out["parameter"])
    return out


def miio_hello(device_id: int = 0x01234567, stamp: int = 0,
               token: bytes = b"\xff" * 16) -> bytes:
    """The miIO handshake: magic 0x2131, length, device id, stamp and a token.

    The device answers with its own device id, a fresh stamp and the token it holds —
    which is exactly the secret every command is encrypted with.  A device that answers
    this to a stranger is telling that stranger it has not been bound yet.
    """
    body = le32(device_id) + le32(stamp) + token[:16].ljust(16, b"\x00")
    return b"\x21\x31" + be16(32) + b"\x00" * 4 + body


def parse_miio_hello(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"magic": "", "length": 0, "device_id": 0, "stamp": 0,
                           "token": b"", "text": ""}
    if len(data) < 32:
        return out
    out["magic"] = data[:2].hex()
    out["length"] = be16_at(data, 2)
    out["device_id"] = le32_at(data, 8)
    out["stamp"] = le32_at(data, 12)
    out["token"] = data[16:32]
    out["text"] = printable(data[32:])
    return out


#: CASTV2 is protobuf over TLS on 8009; the two fields in the tutorial's message are enough
def _protobuf_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _protobuf_field(number: int, wire_type: int, payload: bytes) -> bytes:
    """A protobuf field: the key, then — for the length-delimited types — the length."""
    key = _protobuf_varint((number << 3) | wire_type)
    if wire_type == 2:
        return key + _protobuf_varint(len(payload)) + payload
    return key + payload


def cast_message(namespace: str = "urn:x-cast:com.google.cast.tp.connection",
                 payload: str = '{"type":"CONNECT"}', source: str = "sender-0",
                 destination: str = "receiver-0") -> bytes:
    """A CastMessage: length-prefixed protobuf, which is what the Chromecast speaks."""
    message = (_protobuf_field(1, 0, _protobuf_varint(0)) +          # protocol_version
               _protobuf_field(2, 2, source.encode()) +
               _protobuf_field(3, 2, destination.encode()) +
               _protobuf_field(4, 2, namespace.encode()) +
               _protobuf_field(5, 0, _protobuf_varint(0)) +          # payload_type STRING
               _protobuf_field(6, 2, payload.encode()))
    return be32(len(message)) + message


def parse_cast_message(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"length": 0, "namespace": "", "source": "", "destination": "",
                           "payload": "", "protocol": 0, "fields": []}
    if len(data) < 5:
        return out
    offset = 0
    if be32_at(data, 0) and be32_at(data, 0) <= len(data):
        out["length"] = be32_at(data, 0)          # the prefix is big endian, like the fields
        offset = 4
    index = offset
    while index < len(data):
        key = data[index]
        index += 1
        field, wire = key >> 3, key & 0x07
        if wire == 2:
            length = 0
            shift = 0
            while index < len(data):
                byte = data[index]
                index += 1
                length |= (byte & 0x7F) << shift
                shift += 7
                if not byte & 0x80:
                    break
            value = data[index:index + length]
            index += length
            text = value.decode("utf-8", "replace")
            out["fields"].append((field, text))
            if field == 2:
                out["source"] = text
            elif field == 3:
                out["destination"] = text
            elif field == 4:
                out["namespace"] = text
            elif field == 6:
                out["payload"] = text
        elif wire == 0:
            value = 0
            shift = 0
            while index < len(data):
                byte = data[index]
                index += 1
                value |= (byte & 0x7F) << shift
                shift += 7
                if not byte & 0x80:
                    break
            out["fields"].append((field, value))
            if field == 1:
                out["protocol"] = value
        else:
            break
    return out


def airplay_info_request(host: str = "192.168.1.40") -> bytes:
    """AirPlay's /info: a text plist naming the device, its model and its features."""
    return http_request(host, "/info", "GET", 7000, {"User-Agent": "AirPlay/1.0"})


def parse_plist(text: str) -> Dict[str, Any]:
    """Apple's text plist as a flat dict.

    The elements are read as one stream rather than line by line: a plist written by a
    device often puts ``<key>`` and its value on the same line, and a line-oriented
    parser loses every one of those.
    """
    out: Dict[str, Any] = {}
    current: Optional[str] = None
    pattern = re.compile(r"<(key|string|integer|real|data|true|false)>([^<]*)</\1>")
    for match in pattern.finditer(text or ""):
        tag, raw = match.group(1), match.group(2)
        if tag == "key":
            current = raw.strip()
            continue
        if current is None:
            continue
        if tag == "integer":
            out[current] = int(raw) if raw.strip().isdigit() else raw.strip()
        elif tag == "data":
            out[current] = base64.b64decode(raw + "=" * (-len(raw) % 4))[:32]
        elif tag in ("true", "false"):
            out[current] = tag == "true"
        else:
            out[current] = raw
        current = None
    return out


# --------------------------------------------------------------------------- #
# service APIs worth their own helpers (Docker, Kubernetes, Jenkins, Elastic)
# --------------------------------------------------------------------------- #

def docker_version(host: str = "192.168.1.50", port: int = 2375) -> bytes:
    return http_json_request(host, port, "/version")


def k8s_version(host: str = "192.168.1.50", port: int = 6443) -> bytes:
    return http_json_request(host, port, "/version")


def jenkins_json(host: str = "192.168.1.50", port: int = 8080) -> bytes:
    return http_json_request(host, port, "/api/json")


# --------------------------------------------------------------------------- #
# TLS (443, 8443, …) — the certificate is a finding, not a handshake detail
# --------------------------------------------------------------------------- #

def tls_certificate_info(host: str, port: int = 443, timeout: float = 4.0,
                         server_hostname: str = "") -> Dict[str, Any]:
    """Connect, take the peer certificate apart, and report what a client would accept.

    This is the one function here that opens a socket, because a certificate cannot be
    judged without the server presenting it: expiry, subject, issuer, the names it covers
    and whether the chain validates are all properties of the *answer*, not of the bytes.
    """
    import ssl

    out: Dict[str, Any] = {"host": host, "port": port, "ok": False, "error": "",
                           "subject": "", "issuer": "", "common_name": "", "alt_names": [],
                           "not_after": "", "days_left": 0, "expired": False,
                           "self_signed": False, "version": "", "cipher": "",
                           "validates": False, "weak_protocol": False}
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=server_hostname or None) as tls:
                der = tls.getpeercert(binary_form=True) or b""
                out["version"] = tls.version() or ""
                cipher = tls.cipher()
                out["cipher"] = cipher[0] if cipher else ""
                out["weak_protocol"] = out["version"] in ("TLSv1", "TLSv1.1", "SSLv3")
                if der:
                    digest = hashlib.sha256(der).hexdigest()
                    out["fingerprint"] = ":".join(digest[i:i + 2] for i in range(0, 32, 2))
                    out["ok"] = True
    except (OSError, ssl.SSLError) as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    if host in ("", "0.0.0.0"):
        out["error"] = out["error"] or "no host to connect to"
    return out


#: kept for symmetry with tls_certificate_info: the audit of an *unreachable* server is
#: the finding "the endpoint does not do TLS at all", which is why the port is a probe
def tls_audit(host: str, port: int = 443, timeout: float = 4.0) -> Dict[str, Any]:
    return tls_certificate_info(host, port, timeout)
