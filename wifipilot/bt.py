"""Bluetooth and Bluetooth Low Energy: real packets, real HCI, real parsing.

wifipilot is a wireless tool, and on a modern site "wireless" is not only 802.11.  A
Bluetooth assessment is a different radio with a different packet format, and the same
question at the end of it: *what is this site putting on the air, and what does that
tell an attacker?*  This module is the part that knows the packets — the advertising
PDUs, the advertising-data structures, the HCI commands that put them on air, the
GATT attribute model for reading a device's services, and the link-layer capture format
(``LINKTYPE_BLUETOOTH_LE_LL``) that an offline analysis has to read.

Everything here is standard-layout, from the Bluetooth Core Specification:

* **LE advertising** — a PDU is a 2-byte header (type, TxAdd, ChSel, length) followed by
  ``AdvA`` (6 address bytes) and up to 31 bytes of advertising data made of Length-Type-
  Value structures.  Advertising happens on three channels (37/38/39 = 2402/2426/2480
  MHz), and a *legacy* advertiser sends the same 31-byte payload on all three.
* **Advertising data** — the type byte is what says whether the payload is a name, a
  service UUID, service data, manufacturer data, or the beacon format somebody layered on
  top (iBeacon is manufacturer data 0x004C/0x02/0x15; Eddystone is service data
  0xFEAA).  This module builds and parses all of them.
* **HCI** — the host-controller interface, reached on Linux through an ``AF_BLUETOOTH``
  raw socket: ``LE Set Advertising Data``, ``LE Set Advertising Parameters``, ``LE Set
  Advertising Enable``, ``LE Set Scan ...``, ``Inquiry``.  The commands are four
  opcode bytes and a parameter block, and this module builds them for real so an attack
  can *be* the advertiser rather than describe one.
* **Captures** — ``DLT_BLUETOOTH_LE_LL_WITH_PHDR`` (256) frames a packet as channel,
  signal power, noise power, access address and PDU; the parser here reads that, which is
  what lets an offline analysis of a ``btmon``/``tcpdump`` capture answer questions an
  over-the-air scan would have to be present to answer.

Addresses get the same treatment: a BLE address is public or random, a random address is
static, resolvable-private (rotating) or non-resolvable, and *which one* an advertiser
uses is a privacy finding rather than a detail — a static address means "this device can
be followed from a recording".
"""

from __future__ import annotations

import contextlib
import hashlib
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .crypto import AES

__all__ = [
    "AD_TYPES", "ad_structure", "ad_structures", "adv_payload", "ad_name",
    "payload_name", "parse_ad", "ad_flags", "ad_service_uuids", "ad_manufacturer", "ad_service_data",
    "ADV_TYPES",
    "adv_pdu", "adv_address", "parse_adv_pdu", "ibeacon", "parse_ibeacon",
    "eddystone_url", "eddystone_uid", "parse_eddystone", "le_set_advertising_data",
    "le_set_advertising_parameters", "le_set_advertising_enable", "le_set_scan_parameters",
    "le_set_scan_enable", "hci_command", "hci_packet", "hci_socket", "inquiry_command",
    "ADV_CHANNELS", "LE_ADV_CHANNEL_MHZ", "ADDRESS_TYPES", "classify_address",
    "random_static_address", "resolvable_private_address", "COMPANY_IDS", "SERVICE_UUIDS",
    "GATT_SERVICES", "GATT_CHARACTERISTICS", "TRACKER_SIGNATURES", "tracker_of",
    "APPEARANCE", "BLUETOOTH_LE_LL", "BLUETOOTH_LE_LL_WITH_PHDR", "BLUETOOTH_BREDR_BB",
    "iter_le_frames", "parse_le_wrapper", "find_adv_pdu", "mac_bytes", "mac_text", "company_name",
    "service_name", "appearance_name", "eir_kind_name", "major_class_name",
    "sdp_service_search_attribute", "parse_sdp", "PRINTER", "AUDIO", "HID", "WEARABLE",
    # the profiles above the link: LMP features, RFCOMM, OBEX and HID reports
    "HCI_LINK_CONTROL", "link_control", "disconnect_command", "authentication_requested",
    "set_connection_encryption", "change_connection_link_key", "read_remote_features_command",
    "link_key_request_reply", "link_key_request_negative_reply",
    "io_capability_request_reply", "user_confirmation_request_reply",
    "user_passkey_request_reply", "parse_features_event", "explain_bredr_features",
    "BREDR_FEATURES",
    "RFCOMM_PSM", "rfcomm_dlci", "rfcomm_address", "rfcomm_length_field", "rfcomm_frame",
    "parse_rfcomm", "rfcomm_socket", "crc8_lapb",
    "obex_packet", "obex_header", "obex_name_header", "obex_connect", "obex_get",
    "obex_setpath", "obex_disconnect", "obex_response", "parse_obex_packet",
    "OBEX_REQUESTS", "OBEX_RESPONSES", "OBEX_HEADERS",
    "HID_SERVICE_UUID", "HID_CHARACTERISTICS", "HID_KEYBOARD_REPORT_MAP", "HID_KEYS",
    "HID_MODIFIERS", "HID_SHIFTED", "hid_key", "hid_boot_report", "hid_key_reports",
    "hid_gatt_table", "hid_input_report", "HID_USAGE_NAMES", "HID_KEY_TEXT",
    "HID_UNSHIFTED", "hid_usage_name", "hid_report_text", "hid_decode_report",
    "hid_decode_stream",
    # the security manager, and the addresses an identity key resolves
    "smp_pairing_request", "L2CAP_CID_SMP", "SMP_COMMANDS", "SMP_FAILURE_REASONS",
    "rpa_from_irk", "resolves_irk", "rpa_prand", "address_irk_candidates",
    "SERVICE_GROUPS", "service_group",
    # the classic profiles: the codecs the hijack wave speaks (A2DP, AVRCP, BNEP, HIDP,
    # SAP and the APDUs a SIM answers)
    "AVDTP_SIGNALS", "AVDTP_MESSAGES", "AVDTP_CATEGORIES", "AVDTP_CODECS",
    "avdtp_signal", "avdtp_discover", "avdtp_get_capabilities", "avdtp_set_configuration",
    "avdtp_simple", "parse_avdtp",
    "AVRCP_OPERATIONS", "AVRCP_EVENTS", "AVRCP_PASSTHROUGH", "avctp_frame", "parse_avctp",
    "avrcp_command", "avrcp_passthrough", "avrcp_register", "avrcp_set_absolute_volume",
    "parse_avrcp",
    "BNEP_TYPES", "BNEP_CONTROLS", "BNEP_UUIDS", "bnep_control", "bnep_setup",
    "bnep_frame", "ethernet_frame", "parse_bnep",
    "HIDP_TRANSACTIONS", "HIDP_PARAMETERS", "HIDP_HANDSHAKES", "hidp_frame",
    "hidp_handshake", "parse_hidp",
    "SAP_MESSAGES", "SAP_PARAMETERS", "sap_message", "sap_parameter", "parse_sap",
    "APDU_STATUS", "apdu_select", "apdu_read_binary", "parse_apdu", "SIM_FILES",
    "imsi_from_ef_imsi", "ef_imsi", "iccid_from_ef_iccid",
    "aes_cmac", "h7", "CMAC_SALT"]

# --------------------------------------------------------------------------- #
# addresses
# --------------------------------------------------------------------------- #

#: the three address kinds a BLE advertiser can use, and what each one means for
#: somebody who is recording: a public address is permanent and traceable, a random
#: static address is stable for the life of the pairing (also traceable), a
#: resolvable-private address rotates every 15 minutes and *needs the IRK* to follow
ADDRESS_TYPES = {0: "public", 1: "random"}


def mac_bytes(address: str) -> bytes:
    """``"aa:bb:cc:dd:ee:ff"`` -> six bytes (never raises: bad input gives zeros)."""
    try:
        return bytes(int(part, 16) for part in address.replace("-", ":").split(":")[:6])
    except (ValueError, AttributeError):
        return b"\x00" * 6


def mac_text(raw: bytes) -> str:
    """Six bytes -> ``"aa:bb:cc:dd:ee:ff"``."""
    return ":".join(f"{byte:02x}" for byte in bytes(raw)[:6])


def classify_address(address: str) -> str:
    """Which of the four BLE address kinds this is, from its two most significant bits.

    A random address has the top two bits of its *most significant* byte set to
    ``11``; what follows decides whether it is static, resolvable-private (the
    rotating kind, top bits ``01``) or non-resolvable.
    """
    raw = mac_bytes(address)
    if not any(raw):
        return "unset"
    # an address is written most-significant byte first (``hcitool`` and every other
    # tool prints it that way), and the random-address type bits are the two most
    # significant bits of the *address*, so they are the top bits of the first byte
    bits = (raw[0] >> 6) & 0x03
    if bits == 0x03:
        return "random static"
    if bits == 0x01:
        return "resolvable private"
    if bits == 0x00:
        return "non-resolvable private"
    return "public"


def random_static_address(seed: int = 0) -> str:
    """A random *static* address: stable for the life of the device's bond."""
    value = (0xC0 | (seed & 0x3F)) << 40 | (seed * 2654435761) & 0xFFFFFFFFFF
    raw = value.to_bytes(6, "little")
    return mac_text(raw)


def random_address_hash(irk: bytes, prand: int) -> int:
    """The privacy function ``ah``: ``e(k, r') mod 2**24``, exactly as the specification says.

    ``r'`` is the 24-bit input zero-padded to 128 bits — Core Specification Vol 3, Part H,
    2.2.2 gives the example that ``r`` of ``0x423456`` becomes
    ``0x00000000000000000000000000423456`` — and the result is the *low* 24 bits of the one
    AES-128 block that key ``k`` encrypts it to.  The specification's own sample data
    (Appendix D.7) resolves the whole question of octet order, and the test suite checks
    this function against it::

        ah(ec0234a3 57c8ad05 341010a6 0a397d9b, 0x708194) == 0x0dfbaa

    One block, not two, and the hash is taken from the end of the output rather than the
    front: a resolver that got either of those wrong would produce addresses that no
    compliant controller — a phone, a laptop, a real sniffer — could ever match.
    """
    key = bytes(irk)[:16].ljust(16, b"\x00")
    padding = b"\x00" * 13 + (int(prand) & 0xFFFFFF).to_bytes(3, "big")
    return int.from_bytes(AES(key).encrypt_block(padding)[13:16], "big")


#: the salt the key derivation functions use when a cross-transport key is derived from
#: an LE long-term key (Core Specification Vol 3, Part H, 2.2.5: ``h7(SALT, K)`` with the
#: 128-bit constant ``tmp1``, which the specification prints as
#: ``0x0000 0000 0000 0000 0000 0000 0074 6D70 31``)
CMAC_SALT = bytes.fromhex("00000000000000000000000000746d7031")


def _cmac_subkey(block: bytes) -> bytes:
    """The CMAC subkey: left-shift by one, then XOR the polynomial if the top bit fell off."""
    shifted = int.from_bytes(block, "big") << 1
    if shifted >> 128:
        shifted ^= 0x87
    return (shifted & ((1 << 128) - 1)).to_bytes(16, "big")


def aes_cmac(key: bytes, message: bytes) -> bytes:
    """AES-CMAC (RFC 4493) over the toolkit's own AES.

    The derivation functions of the Bluetooth specification are built on CMAC, so a
    toolkit that wants to compute a cross-transport link key has to have it: the last
    block of the message is finished with a subkey when it is a complete block and with
    the padded form when it is not, and the block that is encrypted at each step is the
    XOR of the previous output with the message.
    """
    from hmac import compare_digest as _compare                   # noqa: F401  (kept close)
    cipher = AES(bytes(key)[:16].ljust(16, b"\x00"))
    sub1 = _cmac_subkey(cipher.encrypt_block(bytes(16)))
    sub2 = _cmac_subkey(sub1)
    data = bytes(message)
    if data and len(data) % 16 == 0:
        blocks = [data[offset:offset + 16] for offset in range(0, len(data), 16)]
        blocks[-1] = bytes(a ^ b for a, b in zip(blocks[-1], sub1))
    else:
        last = data[-(len(data) % 16):] if len(data) % 16 else b""
        padded = last + b"\x80" + bytes(15 - len(last))
        blocks = [data[offset:offset + 16] for offset in
                  range(0, len(data) - len(last), 16)] + [padded]
        blocks[-1] = bytes(a ^ b for a, b in zip(blocks[-1], sub2))
    state = bytes(16)
    for block in blocks:
        state = cipher.encrypt_block(bytes(a ^ b for a, b in zip(state, block)))
    return state


def h7(ltk: bytes, salt: bytes = CMAC_SALT) -> bytes:
    """``h7(SALT, K)``: the link key derived from a long-term key.

    This is what cross-transport key derivation produces — an LE bond turned into a BR/EDR
    link key — and computing it is what lets an assessment say the classic key on a device
    is only as strong as the LE pairing that produced it.
    """
    return aes_cmac(bytes(salt)[:16].ljust(16, b"\x00"), bytes(ltk))


def rpa_from_irk(irk: bytes, prand: int = 1) -> str:
    """The resolvable private address a device with this IRK would present.

    The Core Specification's own construction: ``prand`` is a 24-bit number whose two most
    significant bits are ``0b01``, ``hash = ah(IRK, prand)``, and the address is
    ``prand || hash`` — the most significant octet of *prand* is the most significant octet
    of the address, which is why the type marker is visible in the first printed octet of
    every private address.  An address built this way can only be recognised by somebody
    holding the IRK, which is what makes the resolution below evidence rather than a guess.
    """
    number = (int(prand) & 0xFFFFFF) | 0x400000
    return mac_text(number.to_bytes(3, "big")
                    + random_address_hash(irk, number).to_bytes(3, "big"))


def resolves_irk(irk: bytes, address: str) -> bool:
    """Does ``address`` come from this IRK?  The check the controller itself makes.

    Both halves have to hold: the address has to *look* like a resolvable private address
    (the two most significant bits of its most significant octet are ``0b01`` — an address
    that is public or static is not hidden by anybody's key) and the hash behind the random
    part has to be the ``ah`` of that random part under this key.
    """
    raw = mac_bytes(address)
    if len(raw) != 6 or raw[0] >> 6 != 0x01:
        return False
    prand = int.from_bytes(raw[0:3], "big")
    return random_address_hash(irk, prand).to_bytes(3, "big") == raw[3:6]


def rpa_prand(address: str) -> int:
    """The random half of a resolvable private address, or 0 if it is not one."""
    raw = mac_bytes(address)
    if len(raw) != 6 or raw[0] >> 6 != 0x01:
        return 0
    return int.from_bytes(raw[0:3], "big")


def address_irk_candidates(address: str, keys: Iterable[bytes]) -> List[bytes]:
    """Every key in ``keys`` that resolves ``address`` — normally zero or one."""
    return [bytes(key) for key in keys if resolves_irk(key, address)]


def resolvable_private_address(irk_hash: bytes, seed: int = 0) -> str:
    """A resolvable private address built from a 3-byte IRK hash (``prand || hash``).

    On air an RPA is ``hash(24 bits) || prand(24 bits)`` with the top two bits of prand
    set to ``01``; a device that knows the IRK can confirm the address belongs to the
    device, and a device that does not sees a new address every 15 minutes.
    """
    base = bytes(irk_hash)[:4] or b"\x00"
    prand = bytes([(base[0] & 0x3F) | 0x40,                       # top two bits = 01
                   (seed >> 8) & 0xFF, seed & 0xFF])
    digest = hashlib.sha256(base + prand + seed.to_bytes(4, "little")).digest()
    return mac_text(prand + digest[:3])


# --------------------------------------------------------------------------- #
# advertising data
# --------------------------------------------------------------------------- #

#: advertising-data structure types (Core Specification, Supplement: "Data Types").
#: The list is long; these are the ones an assessment actually meets on a site.
AD_TYPES = {
    0x01: "flags", 0x02: "16-bit service UUIDs (complete)",
    0x03: "16-bit service UUIDs (incomplete)", 0x04: "32-bit service UUIDs (complete)",
    0x05: "32-bit service UUIDs (incomplete)", 0x06: "128-bit service UUIDs (complete)",
    0x07: "128-bit service UUIDs (incomplete)", 0x08: "shortened local name",
    0x09: "complete local name", 0x0A: "TX power level", 0x0D: "class of device",
    0x10: "device ID (SIG)", 0x11: "mesh provisioning", 0x12: "mesh data",
    0x14: "16-bit service solicitation", 0x15: "128-bit service solicitation",
    0x16: "service data (16-bit UUID)", 0x19: "appearance",
    0x1B: "advertising interval", 0x1C: "LE role", 0x1F: "32-bit service solicitation",
    0x20: "service data (32-bit UUID)", 0x21: "service data (128-bit UUID)",
    0x24: "URI", 0x25: "transport discovery data", 0x27: "LE supported features",
    0x2A: "channel map update", 0x2B: "big info", 0x2C: "broadcast code",
    0x2D: "resolvable set identifier", 0x3A: "3D information data",
    0xFF: "manufacturer data",
}

#: advertising PDU types, and which of them expect a reply
ADV_TYPES = {
    0x00: "ADV_IND", 0x01: "ADV_DIRECT_IND", 0x02: "ADV_NONCONN_IND",
    0x03: "SCAN_REQ", 0x04: "SCAN_RSP", 0x05: "CONNECT_IND",
    0x06: "ADV_SCAN_IND", 0x07: "ADV_EXT_IND", 0x08: "AUX_SCAN_REQ",
    0x09: "AUX_CONNECT_REQ", 0x0A: "AUX_SCAN_RSP", 0x0B: "AUX_SYNC_IND",
    0x0C: "AUX_CHAIN_IND", 0x0D: "AUX_SYNC_SUBIND", 0x0E: "SCAN_IND",
}
#: the three legacy advertising channels, in the order the spec numbers them
ADV_CHANNELS = (37, 38, 39)
LE_ADV_CHANNEL_MHZ = {37: 2402, 38: 2426, 39: 2480}

#: company identifiers worth knowing on sight (the full list has thousands)
COMPANY_IDS = {
    0x0006: "Microsoft", 0x004C: "Apple", 0x0075: "Samsung", 0x0087: "Garmin",
    0x00E0: "Google", 0x0157: "Xiaomi", 0x0171: "Amazon", 0x027D: "Huawei",
    0x0310: "Xiaomi", 0x038F: "Xiaomi", 0x0499: "Ruuvi", 0x05A7: "Fossil",
    0x0A0C: "Qualcomm", 0x0F81: "Xiaomi", 0x2C7C: "Tile", 0x0387: "Samsung",
    0x0078: "Nike", 0x0131: "Polar", 0x01AB: "Suunto", 0x0157 + 1: "Xiaomi",
    0x000F: "Broadcom", 0x000A: "CSR", 0x001D: "Qualcomm", 0x0030: "Nordic",
    0x0059: "Nordic Semiconductor", 0x02E0: "Samsung", 0x06C5: "Tile",
    0x00CD: "Bose", 0x012D: "Sony", 0x012A: "Sennheiser", 0x0001: "Nokia",
    0x0830: "Amazon", 0x0A9F: "Beats", 0x026B: "Harman", 0x006D: "Jabra",
}

#: 16-bit service UUIDs that identify a category of device rather than a product
SERVICE_UUIDS = {
    0x1800: "Generic Access", 0x1801: "Generic Attribute", 0x1802: "Immediate Alert",
    0x1803: "Link Loss", 0x1804: "Tx Power", 0x1805: "Current Time",
    0x1808: "Glucose", 0x1809: "Health Thermometer", 0x180A: "Device Information",
    0x180D: "Heart Rate", 0x180E: "Phone Alert Status", 0x180F: "Battery Service",
    0x1810: "Blood Pressure", 0x1811: "Alert Notification", 0x1812: "Human Interface Device",
    0x1813: "Scan Parameters", 0x1814: "Running Speed and Cadence",
    0x1815: "Automation IO", 0x1816: "Cycling Speed and Cadence",
    0x1818: "Cycling Power", 0x1819: "Location and Navigation",
    0x181A: "Environmental Sensing", 0x181B: "Body Composition",
    0x181C: "User Data", 0x181D: "Weight Scale", 0x181E: "Bond Management",
    0x181F: "Continuous Glucose Monitoring", 0x1820: "Internet Protocol Support",
    0x1821: "Indoor Positioning", 0x1822: "Pulse Oximeter", 0x1823: "HTTP Proxy",
    0x1824: "Transport Discovery", 0x1825: "Object Transfer", 0x1826: "Fitness Machine",
    0x1827: "Mesh Provisioning", 0x1828: "Mesh Proxy", 0x1829: "Reconnection",
    0x183A: "Insulin Delivery", 0x1843: "Audio Input Control",
    0x1844: "Volume Control", 0x1846: "Volume Offset Control",
    0x1848: "Coordinated Set Identification", 0x184E: "Audio Stream Control",
    0x184F: "Broadcast Audio Scan", 0x1850: "Published Audio Capabilities",
    0x1851: "Basic Audio Announcement", 0x1852: "Broadcast Audio Announcement",
    0xFD6F: "Exposure Notification", 0xFE59: "Nordic DFU", 0xFEAA: "Eddystone",
    0xFE9F: "Google Fast Pair", 0xFEED: "Tile (legacy)", 0xFEEC: "Tile",
    0xFD5A: "Samsung SmartTag", 0xFD44: "Apple (proximity pairing)",
    0xFFF0: "vendor 0xFFF0", 0xFFF5: "MIFARE", 0xFFF6: "Qualcomm (AllJoyn)",
}

#: ``(company id, vendor, product, payload prefix, what it is)`` — the payload prefix
#: is what comes *after* the two company id bytes, which is how manufacturer data is
#: laid out on air.  A tracker beacon is recognisable from a recording, which is the
#: whole point of the signature table: an unknown tracker in a staff car park is a
#: thing you can prove rather than suspect.
TRACKER_SIGNATURES: List[Tuple[int, str, str, bytes, str]] = [
    (0x004C, "Apple", "Find My network", b"\x12", "Apple item tracker (AirTag or a Find "
                                                   "My accessory)"),
    (0x004C, "Apple", "Handoff", b"\x0f", "Apple continuity packet (proximity)"),
    (0x004C, "Apple", "AirPods", b"\x07", "Apple AirPods advertising"),
    (0x004C, "Apple", "Find My (older)", b"\x10", "Apple proximity pairing"),
    (0x2C7C, "Tile", "Tile", b"", "Tile item tracker"),
    (0x06C5, "Tile", "Tile", b"", "Tile item tracker"),
    (0x02E0, "Samsung", "SmartTag", b"", "Samsung SmartTag"),
    (0x0075, "Samsung", "SmartTag", b"\x02", "Samsung SmartTag"),
    (0x00E0, "Google", "Fast Pair", b"", "Google Fast Pair accessory"),
    (0x0E00, "Google", "Find My Device", b"", "Google Find My Device network beacon"),
    (0x0100, "Chipolo", "Chipolo", b"", "Chipolo item tracker"),
    (0x0499, "Ruuvi", "RuuviTag", b"", "RuuviTag sensor beacon"),
    (0x0157, "Xiaomi", "Mi Tag", b"", "Xiaomi item tracker"),
]

#: the first byte of Apple Find My _and_ the "separated from owner" bit that a
#: tracker emits when it has been following something for a while
APPLE_FIND_MY = b"\x4c\x00\x12"

#: appearance values, by category (Core Specification Supplement 0x19)
APPEARANCE = {
    0x0000: "unknown", 0x0040: "generic phone", 0x0080: "generic computer",
    0x00C0: "generic watch", 0x00C1: "sports watch", 0x00C2: "smartwatch",
    0x0100: "generic clock", 0x0140: "generic display", 0x0180: "generic remote control",
    0x01C0: "generic eye-glasses", 0x01C1: "sunglasses", 0x0200: "generic tag",
    0x0240: "generic keyring", 0x0280: "generic media player", 0x02C0: "generic barcode",
    0x0300: "generic thermometer", 0x0340: "generic heart rate sensor",
    0x0380: "generic blood pressure", 0x03C0: "generic HID",
    0x03C1: "keyboard", 0x03C2: "mouse", 0x03C3: "joystick", 0x03C4: "gamepad",
    0x03C5: "digitizer tablet", 0x03C6: "card reader", 0x03C7: "digital pen",
    0x03C8: "barcode scanner", 0x0400: "generic glucose meter",
    0x0440: "generic running walking sensor", 0x0480: "generic cycling",
    0x04C0: "generic control device", 0x0500: "generic network device",
    0x0540: "generic sensor", 0x0580: "generic light fixture",
    0x05C0: "generic fan", 0x0600: "generic HVAC", 0x0640: "generic air conditioning",
    0x0680: "generic humidifier", 0x06C0: "generic heating",
    0x0800: "generic pulse oximeter", 0x0840: "generic weight scale",
    0x0880: "generic personal mobility device", 0x08C0: "generic continuous glucose",
    0x0900: "generic insulin pump", 0x0940: "generic medication delivery",
    0x0C40: "generic outdoor sports activity", 0x0C80: "generic location display",
    0x0CC0: "generic environmental sensor", 0x0D00: "generic audio sink",
    0x0D40: "generic wearable audio", 0x1440: "generic motorized device",
    0x1480: "generic power device", 0x14C0: "generic light source",
}

#: GATT services and the characteristics an assessment looks for inside them
GATT_SERVICES = {
    "1800": "Generic Access", "1801": "Generic Attribute", "1802": "Immediate Alert",
    "1803": "Link Loss", "1804": "Tx Power", "1805": "Current Time", "180A": "Device Information",
    "180F": "Battery Service", "1812": "Human Interface Device", "181A": "Environmental Sensing",
    "181C": "User Data", "181D": "Weight Scale", "1826": "Fitness Machine",
    "FE59": "Nordic DFU (firmware update over the air)", "FEAA": "Eddystone",
    "FE9F": "Google Fast Pair", "FFE0": "vendor service FFE0",
    "FFE5": "vendor service FFE5", "FF01": "vendor service FF01",
}

GATT_CHARACTERISTICS = {
    "2A00": "Device Name", "2A01": "Appearance", "2A04": "Peripheral Preferred Connection "
            "Parameters", "2A05": "Service Changed", "2A19": "Battery Level",
    "2A24": "Model Number String", "2A25": "Serial Number String",
    "2A26": "Firmware Revision String", "2A27": "Hardware Revision String",
    "2A28": "Software Revision String", "2A29": "Manufacturer Name String",
    "2A37": "Heart Rate Measurement", "2A38": "Body Sensor Location",
    "2A6E": "Temperature", "2A6F": "Humidity", "2A23": "System ID",
    "2A50": "PnP ID", "2ACC": "Fitness Machine Feature",
    "2902": "Client Characteristic Configuration (notify/indicate)",
    "2901": "Characteristic User Description",
}

#: device classes for BR/EDR "Class of Device" (the major service bits are separate)
MAJOR_DEVICE_CLASSES = {
    0x00: "miscellaneous", 0x01: "computer", 0x02: "phone", 0x03: "LAN/network access point",
    0x04: "audio/video", 0x05: "peripheral", 0x06: "imaging", 0x07: "wearable",
    0x08: "toy", 0x09: "health", 0x1F: "uncategorized",
}
#: the input/output capabilities that decide whether pairing can be MITM-protected
IO_CAPABILITIES = {0: "display only", 1: "display yes/no", 2: "keyboard only",
                   3: "no input no output", 4: "keyboard display", 5: "display yes/no"}


def major_class_name(class_of_device: int) -> str:
    """The major device class out of a 24-bit class-of-device value."""
    return MAJOR_DEVICE_CLASSES.get((class_of_device >> 8) & 0x1F, "unknown")


def company_name(identifier: int) -> str:
    return COMPANY_IDS.get(identifier, f"company 0x{identifier:04x}")


#: service groups the survey buckets devices into: a printer, an audio device, an input
#: device and something wearable say different things about a site, and the census the
#: Bluetooth wave prints is grouped by exactly these lists.
PRINTER = (0x1109, 0x1116, 0x1122, 0x1123)
AUDIO = (0x1108, 0x110A, 0x110B, 0x110C, 0x110E, 0x1112, 0x111E, 0x112F)
HID = (0x1124, 0x1812)
WEARABLE = (0x180D, 0x180F, 0x1816, 0x1818, 0x1826)
SERVICE_GROUPS = {"printer": PRINTER, "audio": AUDIO, "hid": HID, "wearable": WEARABLE}


def service_group(uuid: int) -> str:
    """Which group a service UUID belongs to, or ``""`` when it belongs to none."""
    for name, members in SERVICE_GROUPS.items():
        if uuid in members:
            return name
    return ""


def service_name(uuid: int) -> str:
    if isinstance(uuid, str):
        key = uuid.upper().replace("-", "")
        return (GATT_SERVICES.get(key[:4]) or GATT_CHARACTERISTICS.get(key[:4])
                or f"service {uuid}")
    return SERVICE_UUIDS.get(uuid, f"service 0x{uuid:04x}")


def appearance_name(value: int) -> str:
    value &= 0xFFFF
    return APPEARANCE.get(value & 0xFFC0, APPEARANCE.get(value, f"appearance 0x{value:04x}"))


def eir_kind_name(type_byte: int) -> str:
    return AD_TYPES.get(type_byte, f"type 0x{type_byte:02x}")


# --------------------------------------------------------------------------- #
# advertising data: build and parse
# --------------------------------------------------------------------------- #

def ad_structure(type_byte: int, value: bytes) -> bytes:
    """One advertising-data structure: length, type, value."""
    return bytes([len(value) + 1, type_byte]) + bytes(value)[:31]


def ad_structures(structures: Sequence[Tuple[int, bytes]]) -> bytes:
    """A whole advertising payload, truncated at the 31-byte legacy limit."""
    out = bytearray()
    for type_byte, value in structures:
        chunk = bytes([len(value) + 1, type_byte]) + bytes(value)
        if len(out) + len(chunk) > 31:
            break                                   # 31 bytes is the whole budget
        out += chunk
    return bytes(out)


def adv_payload(*structures: Tuple[int, bytes]) -> bytes:
    """Build a whole advertising payload from structures (the 31-byte limit applies)."""
    return ad_structures(list(structures))


def ad_name(name: str, complete: bool = True) -> Tuple[int, bytes]:
    return (0x09 if complete else 0x08, name.encode("utf-8")[:29])


def ad_flags(le_limited: bool = False, le_general: bool = True, br_edr: bool = False) -> Tuple[int, bytes]:
    value = 0
    if le_limited:
        value |= 0x01
    if le_general:
        value |= 0x02
    if br_edr:
        value |= 0x04
    return 0x01, bytes([value])


def ad_tx_power(tx_power: int = -59) -> Tuple[int, bytes]:
    """The transmitted-power element: what a distance estimate is calibrated against."""
    return 0x0A, struct.pack("b", max(-127, min(20, int(tx_power))))


def ad_service_uuids(uuids: Sequence[int]) -> Tuple[int, bytes]:
    return 0x03, b"".join(struct.pack("<H", uuid & 0xFFFF) for uuid in uuids)


def ad_manufacturer(company_id: int, payload: bytes) -> Tuple[int, bytes]:
    return 0xFF, struct.pack("<H", company_id & 0xFFFF) + bytes(payload)[:27]


def ad_service_data(uuid: int, payload: bytes) -> Tuple[int, bytes]:
    return 0x16, struct.pack("<H", uuid & 0xFFFF) + bytes(payload)[:25]


def parse_ad(data: bytes) -> List[Dict[str, Any]]:
    """Parse an advertising payload into its structures.

    A structure is ``length, type, value``; a malformed one (a length that runs off the
    end, or a zero length) stops the walk, because the rest of the payload is not
    trustworthy once the framing is broken.
    """
    out: List[Dict[str, Any]] = []
    offset = 0
    while offset + 1 < len(data):
        length = data[offset]
        if length == 0 or offset + 1 + length > len(data):
            break
        type_byte = data[offset + 1]
        value = data[offset + 2:offset + 1 + length]
        entry: Dict[str, Any] = {"type": type_byte, "kind": eir_kind_name(type_byte),
                                 "value_hex": value.hex()}
        if type_byte in (0x08, 0x09):
            entry["text"] = value.decode("utf-8", "replace")
        elif type_byte == 0x0A and value:
            entry["tx_power"] = struct.unpack("b", value[:1])[0]
        elif type_byte == 0x01 and value:
            entry["flags"] = value[0]
        elif type_byte in (0x02, 0x03, 0x14) and value:
            entry["uuids"] = [struct.unpack_from("<H", value, index)[0]
                              for index in range(0, len(value) - 1, 2)]
            entry["services"] = [service_name(uuid) for uuid in entry["uuids"]]
        elif type_byte == 0x19 and len(value) >= 2:
            entry["appearance"] = struct.unpack_from("<H", value)[0]
            entry["appearance_text"] = appearance_name(entry["appearance"])
        elif type_byte == 0xFF and len(value) >= 2:
            entry["company"] = struct.unpack_from("<H", value)[0]
            entry["company_name"] = company_name(entry["company"])
            entry["data"] = value[2:]
        elif type_byte == 0x16 and len(value) >= 2:
            entry["uuid"] = struct.unpack_from("<H", value)[0]
            entry["service"] = service_name(entry["uuid"])
            entry["data"] = value[2:]
        elif type_byte == 0x0D and len(value) >= 3:
            entry["class_of_device"] = int.from_bytes(value[:3], "little")
            entry["major_class"] = major_class_name(entry["class_of_device"])
        out.append(entry)
        offset += 1 + length
    return out


def payload_name(structures: Iterable[Dict[str, Any]]) -> str:
    """The local name out of a *parsed* payload, complete or shortened."""
    name = ""
    for structure in structures:
        if structure.get("type") in (0x08, 0x09) and structure.get("text"):
            name = structure["text"]
    return name


# --------------------------------------------------------------------------- #
# link-layer PDUs
# --------------------------------------------------------------------------- #

def adv_address(address: str, random: bool = False) -> bytes:
    """``AdvA``: six bytes, least significant byte first (as the radio sends it)."""
    return mac_bytes(address)[:6]


def adv_pdu(pdu_type: int, address: str = "00:00:00:00:00:00", payload: bytes = b"",
            tx_add: bool = False, ch_sel: bool = True,
            peer_address: str = "") -> bytes:
    """A legacy advertising-channel PDU: header, ``AdvA``, then the payload.

    ``SCAN_REQ`` and ``CONNECT_IND`` carry two addresses (the scanner's and the
    advertiser's) rather than one, and their payload is the remainder after those two.
    """
    if pdu_type in (0x03, 0x05, 0x08, 0x09):        # ScanA + AdvA, then data
        body = payload
        length = 12 + len(body)
    else:
        body = bytes(payload)
        length = 6 + len(body)
    header = bytes([(pdu_type & 0x0F) | (0x40 if tx_add else 0x00) | (0x20 if ch_sel else 0),
                    length & 0x3F])
    if pdu_type in (0x03, 0x05, 0x08, 0x09):
        # the second address is the scanner/target for SCAN_REQ/CONNECT_IND: leaving it
        # at zero is what an unaddressed request looks like, which is a real frame but
        # not the one an attack usually means to send
        peer = mac_bytes(peer_address) if peer_address else b"\x00" * 6
        return header + mac_bytes(address) + peer + body
    return header + mac_bytes(address) + body


def parse_adv_pdu(pdu: bytes) -> Dict[str, Any]:
    """Parse one advertising-channel PDU back into fields an attack can talk about."""
    if len(pdu) < 2:
        return {}
    header, length = pdu[0], pdu[1]
    pdu_type = header & 0x0F
    body = pdu[2:2 + (length & 0x3F)]
    out: Dict[str, Any] = {"pdu_type": pdu_type, "type": ADV_TYPES.get(pdu_type, "?"),
                           "tx_add": bool(header & 0x40), "ch_sel": bool(header & 0x20),
                           "length": length & 0x3F}
    if pdu_type in (0x03, 0x05, 0x08, 0x09):
        out["scan_address"] = mac_text(body[:6])
        out["address"] = mac_text(body[6:12])
        out["data"] = body[12:]
    elif pdu_type != 0x0B:                            # every other legacy PDU has AdvA
        out["address"] = mac_text(body[:6])
        out["data"] = body[6:]
        if pdu_type == 0x01 and len(body) >= 12:      # ADV_DIRECT_IND: target too
            out["target_address"] = mac_text(body[6:12])
            out["data"] = body[12:]
    if pdu_type in (0x05, 0x0A) and len(out.get("data") or b"") >= 22:
        out["connection"] = parse_connection_request(out["data"])
    out["ad"] = parse_ad(out.get("data") or b"")
    out["name"] = payload_name(out["ad"])
    out["address_kind"] = classify_address(out["address"]) if out.get("address") else ""
    return out


# --------------------------------------------------------------------------- #
# the beacon formats layered on the advertising data
# --------------------------------------------------------------------------- #

def ibeacon(uuid: str, major: int = 1, minor: int = 1, tx_power: int = -59,
            company: int = 0x004C) -> Tuple[int, bytes]:
    """An iBeacon payload: manufacturer data, company 0x004C, type 0x02, length 0x15.

    The layout is 16 bytes of proximity UUID, then major and minor (big endian), then
    the measured power at one metre — which is what every indoor positioning system
    built on beacons reads, and what an attacker overwrites when they clone one.
    """
    clean = uuid.replace("-", "")
    raw = bytes.fromhex(clean) if len(clean) == 32 else (clean.encode()[:16].ljust(16, b"\x00"))
    return ad_manufacturer(company, b"\x02\x15" + raw + struct.pack(">HH", major, minor)
                           + struct.pack("b", tx_power))


def parse_ibeacon(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Recognise an iBeacon structure and read its fields back."""
    if entry.get("type") != 0xFF:
        return None
    data = entry.get("data") or b""
    # 0x02 0x15, the 16-byte proximity UUID, major, minor, and the measured power at
    # one metre: 23 bytes of payload, so reading the power from the byte before it is
    # wrong by two and quietly reports the *minor* number's high byte instead
    if len(data) < 23 or data[0] != 0x02 or data[1] != 0x15:
        return None
    uuid = data[2:18]
    major, minor = struct.unpack_from(">HH", data, 18)
    tx_power = struct.unpack("b", data[22:23])[0]
    return {"uuid": f"{uuid.hex()[:8]}-{uuid.hex()[8:12]}-{uuid.hex()[12:16]}-"
                    f"{uuid.hex()[16:20]}-{uuid.hex()[20:]}",
            "kind": "iBeacon", "major": major, "minor": minor, "tx_power": tx_power,
            "company": entry.get("company"), "company_name": entry.get("company_name")}


def eddystone_uid(namespace: bytes, instance: bytes, tx_power: int = -20) -> Tuple[int, bytes]:
    """An Eddystone-UID frame: service data 0xFEAA, frame type 0x00."""
    return ad_service_data(0xFEAA, b"\x00" + struct.pack("b", tx_power)
                           + bytes(namespace)[:10] + bytes(instance)[:6])


def eddystone_url(url: str, tx_power: int = -20, scheme: int = 0x02) -> Tuple[int, bytes]:
    """An Eddystone-URL frame: service data 0xFEAA, frame type 0x10, a URL scheme byte."""
    return ad_service_data(0xFEAA, b"\x10" + struct.pack("b", tx_power)
                           + bytes([scheme]) + url.encode("ascii", "ignore")[:17])


EDDYSTONE_SCHEMES = {0x00: "http://www.", 0x01: "https://www.", 0x02: "http://",
                     0x03: "https://"}
EDDYSTONE_TLDS = {"com": 0x08, "org": 0x09, "edu": 0x0A, "net": 0x0B, "info": 0x0C,
                  "biz": 0x0D, "gov": 0x0E}


def parse_eddystone(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Recognise an Eddystone frame (UID, URL, TLM or EID)."""
    if entry.get("type") != 0x16 or entry.get("uuid") != 0xFEAA:
        return None
    data = entry.get("data") or b""
    if not data:
        return None
    kind = {0x00: "UID", 0x10: "URL", 0x20: "TLM", 0x30: "EID"}.get(data[0],
                                                                   f"0x{data[0]:02x}")
    out: Dict[str, Any] = {"kind": f"Eddystone-{kind}", "frame_type": kind,
                           "tx_power": None, "data": data.hex()}
    if kind == "UID" and len(data) >= 18:
        out["tx_power"] = struct.unpack("b", data[1:2])[0]
        out["namespace"] = data[2:12].hex()
        out["instance"] = data[12:18].hex()
    elif kind == "URL" and len(data) >= 3:
        out["tx_power"] = struct.unpack("b", data[1:2])[0]
        scheme = EDDYSTONE_SCHEMES.get(data[2], "")
        host = data[3:].decode("ascii", "replace").strip("\x00")
        out["url"] = "".join([scheme, host])
    elif kind == "TLM" and len(data) >= 13:
        out["battery_mv"] = struct.unpack_from(">H", data, 2)[0]
        out["temperature_c"] = struct.unpack_from(">h", data, 4)[0] / 256.0
        out["pdu_count"] = struct.unpack_from(">I", data, 6)[0]
    return out


def tracker_of(structures: Iterable[Dict[str, Any]]) -> Optional[Dict[str, str]]:
    """Is this payload a tracker beacon?  Match it against the known signatures."""
    for entry in structures:
        if entry.get("type") != 0xFF:
            continue
        company = entry.get("company")
        data = entry.get("data") or b""
        for identifier, vendor, product, signature, description in TRACKER_SIGNATURES:
            if company is not None and company != identifier:
                continue
            if data[:len(signature)] == signature:
                return {"vendor": vendor, "product": product, "detail": description,
                        "company": entry.get("company_name") or vendor,
                        "signature": (bytes([identifier & 0xFF, identifier >> 8])
                                      + signature).hex()}
    return None


# --------------------------------------------------------------------------- #
# HCI: the commands that make a radio do something
# --------------------------------------------------------------------------- #

#: HCI opcodes are two bytes: the OGF (command group) in the top six bits and the OCF
#: in the low ten.  These are the ones an LE attack needs.
HCI_OGF_LE = 0x08
HCI_OGF_LINK_CONTROL = 0x01
HCI_OGF_INFORMATIONAL = 0x04
HCI_COMMANDS = {
    "LE Set Advertising Parameters": (HCI_OGF_LE, 0x0006),
    "LE Set Advertising Data": (HCI_OGF_LE, 0x0008),
    "LE Set Scan Response Data": (HCI_OGF_LE, 0x0009),
    "LE Set Advertising Enable": (HCI_OGF_LE, 0x000A),
    "LE Set Scan Parameters": (HCI_OGF_LE, 0x000B),
    "LE Set Scan Enable": (HCI_OGF_LE, 0x000C),
    "LE Create Connection": (HCI_OGF_LE, 0x000D),
    "LE Read Buffer Size": (HCI_OGF_LE, 0x0002),
    "LE Set Random Address": (HCI_OGF_LE, 0x0005),
    "LE Read Advertising Channel Tx Power": (HCI_OGF_LE, 0x0007),
    "LE Read Remote Features": (HCI_OGF_LE, 0x0016),
    "LE Read Supported States": (HCI_OGF_LE, 0x001C),
    "Inquiry": (HCI_OGF_LINK_CONTROL, 0x0001),
    "Inquiry Cancel": (HCI_OGF_LINK_CONTROL, 0x0002),
    "Create Connection": (HCI_OGF_LINK_CONTROL, 0x0005),
    "Remote Name Request": (HCI_OGF_LINK_CONTROL, 0x0019),
    "Read Local Version": (HCI_OGF_INFORMATIONAL, 0x0001),
    "Read BD_ADDR": (HCI_OGF_INFORMATIONAL, 0x0009),
}

#: HCI packet type indicators (the "H4" transport): what byte goes in front
HCI_COMMAND_PACKET, HCI_ACL_PACKET, HCI_EVENT_PACKET = 0x01, 0x02, 0x04


def hci_command(opcode: int, parameters: bytes = b"") -> bytes:
    """A command packet, H4-framed: type, opcode (little endian), length, parameters."""
    return bytes([HCI_COMMAND_PACKET]) + struct.pack("<HB", opcode, len(parameters)) \
        + bytes(parameters)


def hci_packet(name: str, parameters: bytes = b"") -> bytes:
    """``hci_packet("LE Set Advertising Data", data)`` -> a real command packet."""
    ogf, ocf = HCI_COMMANDS[name]
    return hci_command((ogf << 10) | ocf, parameters)


def le_set_advertising_data(data: bytes) -> bytes:
    """LE Set Advertising Data: 31 bytes of advertising payload."""
    return hci_packet("LE Set Advertising Data", bytes([len(data) & 0x1F]) + bytes(data[:31]))


def le_set_scan_response_data(data: bytes) -> bytes:
    return hci_packet("LE Set Scan Response Data", bytes([len(data) & 0x1F]) + bytes(data[:31]))


def le_set_advertising_parameters(interval_min_ms: float = 100.0, interval_max_ms: float = 100.0,
                                  adv_type: int = 0x00, channel_map: int = 0x07,
                                  own_address_type: int = 0, peer_address: str = "",
                                  filter_policy: int = 0) -> bytes:
    """LE Set Advertising Parameters: interval (0.625 ms units), type, channels."""
    interval_min = max(0x20, min(0x4000, int(interval_min_ms / 0.625)))
    interval_max = max(interval_min, min(0x4000, int(interval_max_ms / 0.625)))
    # the peer address is only meaningful for the directed advertising types, and the
    # command carries it in one field either way: a public own-address means the field is
    # the peer's, and the placeholder below is what the specification wants when there is
    # no peer (the kernel and the controller ignore it for undirected advertising)
    parameters = (struct.pack("<HH", interval_min, interval_max)
                  + bytes([adv_type, own_address_type, 0x00])       # own address type 0 = public
                  + mac_bytes(peer_address or "00:00:00:00:00:00")
                  + bytes([channel_map, filter_policy]))
    return hci_packet("LE Set Advertising Parameters", parameters)


def le_set_advertising_enable(enable: bool = True) -> bytes:
    return hci_packet("LE Set Advertising Enable", bytes([1 if enable else 0]))


def le_set_scan_parameters(scan_type: int = 1, interval_ms: float = 100.0,
                           window_ms: float = 50.0, own_address_type: int = 0,
                           filter_policy: int = 0) -> bytes:
    """LE Set Scan Parameters: type (1 = active), interval and window in 0.625 ms units."""
    interval = max(0x04, min(0x4000, int(interval_ms / 0.625)))
    window = max(0x04, min(interval, int(window_ms / 0.625)))
    return hci_packet("LE Set Scan Parameters",
                      bytes([scan_type, 0x00])
                      + struct.pack("<HH", interval, window)
                      + bytes([own_address_type, filter_policy]))


def le_set_scan_enable(enable: bool = True, filter_duplicates: bool = True) -> bytes:
    return hci_packet("LE Set Scan Enable", bytes([1 if enable else 0,
                                                    1 if filter_duplicates else 0]))


def le_set_random_address(address: str) -> bytes:
    """LE Set Random Address: the address the controller advertises under.

    Every BLE attack that wants to look like a *different* device, or like the same
    device with a new address, has to set this first — an advertising address type of
    1 without it is answered with "command disallowed" and nothing goes on air.
    """
    return hci_packet("LE Set Random Address", bytes(mac_bytes(address)))


def le_create_connection(peer: str, peer_address_type: int = 0, own_address_type: int = 0,
                         scan_interval_ms: float = 60.0, scan_window_ms: float = 30.0,
                         interval_min_ms: float = 40.0, interval_max_ms: float = 60.0,
                         latency: int = 0, timeout_ms: int = 2000, filter_policy: int = 0
                         ) -> bytes:
    """LE Create Connection: the command that opens a link to an advertising device.

    The parameters are not decoration.  A short interval makes the link responsive
    (which is what enumeration wants) and a long supervision timeout keeps it alive
    through a hostile channel; an attacker who sets the latency to its maximum is
    invisible to the device's own power management, which is why the values are worth
    reading back out of a capture.
    """
    interval_min = max(0x06, min(0x0C80, int(interval_min_ms / 1.25)))
    interval_max = max(interval_min, min(0x0C80, int(interval_max_ms / 1.25)))
    parameters = (struct.pack("<HH", max(0x04, int(scan_interval_ms / 0.625)),
                              max(0x04, int(scan_window_ms / 0.625)))
                  + bytes([filter_policy, peer_address_type & 0x01])
                  + bytes(mac_bytes(peer))
                  + bytes([own_address_type & 0x01])
                  # minimum/maximum CE length are the peripheral's latency allowance
                  + struct.pack("<HHHHHH", interval_min, interval_max, latency & 0xFFFF,
                                max(0x000A, min(0x0C80, int(timeout_ms / 10))), 0, 0))
    return hci_packet("LE Create Connection", parameters)


def le_read_remote_features(handle: int) -> bytes:
    """LE Read Remote Features: what the peer's controller says it can do."""
    return hci_packet("LE Read Remote Features", struct.pack("<H", handle & 0x0FFF))


def acl_packet(handle: int, payload: bytes, pb: int = 0, bc: int = 0) -> bytes:
    """An HCI ACL data packet, H4-framed — how L2CAP/ATT bytes reach the controller.

    ``pb`` says whether this is the start of an L2CAP PDU (0) or a continuation (1), and
    the handle is the connection handle the LE Create Connection event returned.
    """
    flags = (handle & 0x0FFF) | ((pb & 0x03) << 12) | ((bc & 0x03) << 14)
    return (bytes([HCI_ACL_PACKET]) + struct.pack("<HH", flags, len(payload))
            + bytes(payload))


def l2cap_echo_request(payload: bytes = b"\x00\x00\x00\x00", identifier: int = 1) -> bytes:
    """An L2CAP signalling **echo request** (code 0x08) carrying ``payload``.

    The echo is the one signalling command every stack must answer — which is why it is
    both the flood's packet and the ping-of-death's: the remote end copies the payload
    into a buffer and sends it back.  The code byte matters: ``0x0A`` is an *information
    request*, and a device answering that is answering a question about itself, not an
    echo, so an attack that calls 0x0A an echo is describing the wrong PDU.
    """
    return bytes([0x08, identifier & 0xFF]) + struct.pack("<H", len(payload)) + bytes(payload)


def l2cap_frame(cid: int, payload: bytes, identifier: int = 0) -> bytes:
    """An L2CAP frame for the fixed channels: length, channel ID, then the payload."""
    return struct.pack("<HH", len(payload), cid & 0xFFFF) + bytes(payload)


def inquiry_command(duration_1_28s: int = 8, num_responses: int = 0) -> bytes:
    """The classic BR/EDR Inquiry, which is how a site's headsets and printers appear."""
    return hci_packet("Inquiry", bytes([0x9E, 0x8B, 0x33])   # GIAC, general inquiry
                      + bytes([duration_1_28s & 0xFF, num_responses & 0xFF]))


#: HCI event codes a scan produces, and what they mean in a report
HCI_EVENT_DISCONNECTION_COMPLETE = 0x05
HCI_EVENT_INQUIRY_COMPLETE = 0x01
HCI_EVENT_INQUIRY_RESULT = 0x02
HCI_EVENT_CONNECTION_COMPLETE = 0x03
HCI_EVENT_COMMAND_STATUS = 0x0F
HCI_EVENT_COMMAND_COMPLETE = 0x0E
HCI_EVENT_LE_META = 0x3E

HCI_EVENTS = {0x01: "inquiry complete", 0x02: "inquiry result",
              0x03: "connection complete", 0x05: "disconnection complete",
              0x0E: "command complete", 0x0F: "command status",
              0x13: "number of completed packets", 0x3E: "LE meta"}

#: the LE meta subevents: the scan the reader cares about is 0x02
LE_META_SUBEVENTS = {0x01: "LE connection complete", 0x02: "LE advertising report",
                     0x03: "LE connection update complete",
                     0x04: "LE read remote features complete",
                     0x05: "LE long term key request", 0x06: "LE remote connection "
                     "parameter request", 0x0A: "LE data length change",
                     0x0B: "LE read local P-256 public key complete",
                     0x0C: "LE generate DHKey complete", 0x0D: "LE enhanced connection "
                     "complete", 0x0F: "LE enhanced connection complete v2",
                     0x22: "LE extended advertising report"}

#: the advertising report event types, which say whether a device can be connected to
ADV_REPORT_TYPES = {0x00: "connectable undirected", 0x01: "connectable directed",
                    0x02: "scannable undirected", 0x03: "non-connectable undirected",
                    0x04: "scan response"}

#: HCI error codes worth naming in a report (the ones an attack actually hits)
HCI_ERRORS = {0x00: "success", 0x01: "unknown HCI command",
              0x02: "unknown connection identifier", 0x03: "hardware failure",
              0x05: "authentication failure", 0x06: "PIN or key missing",
              0x08: "connection timeout", 0x0C: "command disallowed",
              0x0D: "rejected: limited resources", 0x12: "rejected: no suitable "
              "channel found", 0x13: "remote user terminated",
              0x16: "connection terminated by local host",
              0x17: "repeated attempts", 0x18: "pairing not allowed",
              0x19: "unknown LMP PDU", 0x1A: "unsupported remote feature",
              0x1E: "invalid LL parameters", 0x1F: "unspecified error",
              0x1B: "unsupported LMP parameter value", 0x22: "LMP response timeout",
              0x23: "unknown connection identifier", 0x28: "instant passed",
              0x29: "pairing with unit key not supported", 0x2A: "different "
              "transaction collision", 0x3B: "unsupported remote feature",
              0x3E: "unsupported LMP parameter value", 0x41: "advertising timeout"}


def hci_status_name(code: int) -> str:
    return HCI_ERRORS.get(code, f"error 0x{code:02x}")


def hci_recv(sock: Any, timeout: float = 1.0, size: int = 4096) -> bytes:
    """Read one HCI packet from an open socket (``b""`` when nothing arrives)."""
    if sock is None:
        return b""
    try:
        sock.settimeout(timeout)
        return sock.recv(size)
    except OSError:
        return b""


def parse_hci_event(packet: bytes) -> Dict[str, Any]:
    """One HCI event packet, unpacked far enough to be useful.

    The controller answers an LE scan with *event packets*: a command complete for the
    scan-enable itself, then one LE meta event per advertisement heard.  Parsing them
    is what turns "we sent a scan command" into "we heard eleven devices", and an attack
    that cannot read the answer is a command with no result.
    """
    out: Dict[str, Any] = {"kind": "unknown", "event": None, "event_name": "",
                           "status": None, "status_text": "", "parameters": b"",
                           "reports": [], "address": "", "name": ""}
    if len(packet) < 3:
        return out
    offset = 1 if packet[0] == HCI_EVENT_PACKET else 0      # H4 framing is optional here
    if len(packet) < offset + 3:
        return out
    code = packet[offset]
    length = packet[offset + 1]
    parameters = packet[offset + 2:offset + 2 + length]
    out.update({"event": code, "event_name": HCI_EVENTS.get(code, f"event 0x{code:02x}"),
                "kind": "event", "parameters": parameters})
    if code == HCI_EVENT_COMMAND_COMPLETE and len(parameters) >= 4:
        out["command"] = int.from_bytes(parameters[1:3], "little")
        out["status"] = parameters[3]
        out["status_text"] = hci_status_name(parameters[3])
    elif code == HCI_EVENT_COMMAND_STATUS and len(parameters) >= 4:
        out["status"] = parameters[0]
        out["status_text"] = hci_status_name(parameters[0])
    elif code == HCI_EVENT_INQUIRY_RESULT:
        out["reports"] = parse_inquiry_results(parameters)
    elif code == HCI_EVENT_LE_META and parameters:
        subevent = parameters[0]
        out["subevent"] = subevent
        out["subevent_name"] = LE_META_SUBEVENTS.get(subevent,
                                                     f"LE subevent 0x{subevent:02x}")
        if subevent == 0x02:
            out["reports"] = parse_advertising_reports(parameters[1:])
        elif subevent in (0x01, 0x0D) and len(parameters) >= 13:
            # subevent, status, connection handle (2), role, address type, address (6)
            out["status"] = parameters[1]
            out["status_text"] = hci_status_name(parameters[1])
            out["handle"] = int.from_bytes(parameters[2:4], "little")
            out["address_type"] = parameters[5]
            out["address"] = mac_text(parameters[6:12])
    return out


def parse_advertising_reports(data: bytes) -> List[Dict[str, Any]]:
    """The advertising reports inside an LE Advertising Report subevent.

    Each report is the event type, the address *type* (public or random), the address,
    the length-prefixed advertising data, and the RSSI — the whole census in one packet,
    which is why a scan is one command and a lot of answers.
    """
    reports: List[Dict[str, Any]] = []
    if not data:
        return reports
    count = data[0]
    offset = 1
    for _index in range(count):
        if offset + 9 > len(data):
            break
        event_type = data[offset]
        address_type = data[offset + 1]
        address = mac_text(data[offset + 2:offset + 8])
        length = data[offset + 8]
        payload = data[offset + 9:offset + 9 + length]
        if len(payload) < length:
            break
        rssi = data[offset + 9 + length] - 256 if len(data) > offset + 9 + length else 0
        entry = {"event_type": event_type,
                 "event_type_text": ADV_REPORT_TYPES.get(event_type, "unknown"),
                 "address_type": address_type,
                 "address_type_text": "random" if (address_type & 0x01) else "public",
                 "address": address, "data_length": length,
                 "structures": parse_ad(payload), "rssi": rssi}
        entry["name"] = payload_name(entry["structures"])
        entry["tracker"] = tracker_of(entry["structures"])
        # the parsed structures under the same key a capture record uses, so a scanner
        # and a capture reader fold into a device map the same way
        entry["ad"] = entry["structures"]
        entry["company"] = next((company_name(item["company_id"])
                                 for item in entry["structures"]
                                 if item.get("company_id") is not None), "")
        reports.append(entry)
        offset += 9 + length + 1
    return reports


def parse_inquiry_results(parameters: bytes) -> List[Dict[str, Any]]:
    """The classic BR/EDR Inquiry Result event: addresses, class of device, names."""
    reports: List[Dict[str, Any]] = []
    if len(parameters) < 15:
        return reports
    count = parameters[0]
    offset = 1
    for _index in range(count):
        # one inquiry response is thirteen bytes: the address, the page scan repetition
        # mode, a reserved byte, the class of device (three) and the clock offset (two)
        if offset + 13 > len(parameters):
            break
        address = mac_text(parameters[offset:offset + 6])
        class_of_device = int.from_bytes(parameters[offset + 8:offset + 11], "little")
        reports.append({"address": address,
                        "page_scan_repetition": parameters[offset + 6] & 0x03,
                        "clock_offset": int.from_bytes(parameters[offset + 11:offset + 13],
                                                       "little") & 0x7FFF,
                        "class_of_device": class_of_device,
                        "major_class": (class_of_device >> 8) & 0x1F,
                        "major_class_text": major_class_name(class_of_device)})
        offset += 13
    return reports


def iter_hci_events(sock: Any, seconds: float = 5.0, limit: int = 5000) -> Iterable[Dict[str, Any]]:
    """Read HCI events for a while and yield the parsed ones (live scans use this)."""
    import time as _time

    deadline = _time.time() + max(0.0, seconds)
    count = 0
    while count < limit and _time.time() < deadline:
        packet = hci_recv(sock, timeout=max(0.05, min(0.5, deadline - _time.time())))
        if not packet:
            # a simulated controller knows when it has finished reporting; a real one
            # cannot say anything a timeout does not already say, so only the simulated
            # socket gets to end the loop early
            if hasattr(sock, "has_events") and not sock.has_events():
                return
            continue
        count += 1
        yield parse_hci_event(packet)


#: how a link type 256 record is written: RF channel, signal power, noise power, then
#: the access address.  Everything after that is the advertising PDU a scanner sends.
BT_LL_WRAPPER_CHANNELS = (37, 38, 39)


def le_wrapper(pdu: bytes, channel: int = 37, rssi: int = -60, noise: int = -95,
               access_address: bytes = b"") -> bytes:
    """Wrap an advertising PDU in the pseudo header ``LINKTYPE_..._WITH_PHDR`` uses.

    Signal and noise power are stored as dBm + 127, which is how a capture records
    "signal power" as an unsigned byte that can represent everything from -127 to +127.
    """
    address = access_address or ADV_ACCESS_ADDRESS
    # the pseudo header libpcap defines: channel, signal, noise, AA offenses, reference AA
    pseudo = (bytes([channel & 0xFF, (rssi + 127) & 0xFF, (noise + 127) & 0xFF, 0x00])
              + bytes(address))
    return pseudo + bytes(pdu)


def write_le_pcap(path: str, records: Iterable[bytes], spacing: float = 0.01,
                  link_type: int = 256, times: Optional[Sequence[float]] = None,
                  base_time: Optional[float] = None) -> str:
    """Write link-type-256 records as a real libpcap file (a BLE capture, no radio)."""
    import struct as _struct
    import time as _time

    payload = list(records)
    link_type = int(link_type)
    header = bytes.fromhex("d4c3b2a1") + _struct.pack("<HHiiii", 2, 4, 0, 0, 262144,
                                                       link_type)
    buffer = bytearray(header)
    base = int(base_time if base_time is not None else _time.time())
    for index, record in enumerate(payload):
        moment = float(times[index]) if times is not None and index < len(times) \
            else base + index * spacing
        stamp = int(moment)
        usec = int((moment % 1) * 1_000_000)
        buffer += _struct.pack("<IIII", stamp, usec, len(record), len(record))
        buffer += record
    path_obj = __import__("pathlib").Path(path)
    path_obj.parent.mkdir(parents=True, exist_ok=True)
    path_obj.write_bytes(bytes(buffer))
    return str(path_obj)



# --------------------------------------------------------------------------- #
# the link layer, L2CAP and the security manager: what a connected capture shows
# --------------------------------------------------------------------------- #
#: LL control PDUs (opcode -> name).  Radio captures of a *connection* are these, and
#: reading them is what tells an auditor whether the link is encrypted, how often it
#: hops, and what the two ends claim to support.
LL_CONTROL_OPCODES = {
    0x00: "LL_CONNECTION_UPDATE_IND", 0x01: "LL_CHANNEL_MAP_IND",
    0x02: "LL_TERMINATE_IND", 0x03: "LL_ENC_REQ", 0x04: "LL_ENC_RSP",
    0x05: "LL_START_ENC_REQ", 0x06: "LL_START_ENC_RSP", 0x07: "LL_UNKNOWN_RSP",
    0x08: "LL_FEATURE_REQ", 0x09: "LL_FEATURE_RSP", 0x0A: "LL_PAUSE_ENC_REQ",
    0x0B: "LL_PAUSE_ENC_RSP", 0x0C: "LL_VERSION_IND", 0x0D: "LL_REJECT_IND",
    0x0E: "LL_PERIPHERAL_FEATURE_REQ", 0x0F: "LL_CONNECTION_PARAM_REQ",
    0x10: "LL_CONNECTION_PARAM_RSP", 0x11: "LL_REJECT_EXT_IND", 0x12: "LL_PING_REQ",
    0x13: "LL_PING_RSP", 0x14: "LL_LENGTH_REQ", 0x15: "LL_LENGTH_RSP",
    0x16: "LL_PHY_REQ", 0x17: "LL_PHY_RSP", 0x18: "LL_PHY_UPDATE_IND",
    0x19: "LL_MIN_USED_CHANNELS_IND", 0x1A: "LL_CTE_REQ", 0x1B: "LL_CTE_RSP",
    0x1C: "LL_PERIODIC_SYNC_IND", 0x1D: "LL_CLOCK_ACCURACY_REQ",
    0x1E: "LL_CLOCK_ACCURACY_RSP", 0x1F: "LL_CIS_REQ", 0x20: "LL_CIS_RSP",
    0x21: "LL_CIS_IND", 0x22: "LL_CIS_TERMINATE_IND", 0x23: "LL_POWER_CONTROL_REQ",
    0x24: "LL_POWER_CONTROL_RSP", 0x25: "LL_POWER_CHANGE_IND",
}

#: the LL feature bits an assessment cares about (Core spec, Vol 6, Part B, 4.6).
#: "LE Encryption" and "LE Data Packet Length Extension" are the ones every phone
#: has; the coded PHY and the CTE bits are what a long-range or direction-finding
#: tracker needs; the channel-selection bit decides how hard the link is to follow.
LL_FEATURE_BITS = {
    0: "LE Encryption", 1: "Connection Parameters Request Procedure",
    2: "Extended Reject Indication", 3: "Peripheral-initiated Features Exchange",
    4: "LE Ping", 5: "LE Data Packet Length Extension", 6: "LL Privacy",
    7: "Extended Scanner Filter Policies", 8: "LE 2M PHY",
    9: "Stable Modulation Index - Transmitter", 10: "Stable Modulation Index - Receiver",
    11: "LE Coded PHY", 12: "LE Extended Advertising", 13: "LE Periodic Advertising",
    14: "Channel Selection Algorithm #2", 15: "LE Power Class 1",
    16: "Minimum Number of Used Channels Procedure", 17: "Connection CTE Request",
    18: "Connection CTE Response", 19: "Constant Tone Extension Transmit",
    20: "Constant Tone Extension Receive", 21: "Remote Public Key Validation",
}

#: L2CAP channel identifiers.  The fixed channels are the same numbers on every link,
#: and getting one of them wrong sends a security-manager frame to the attribute
#: protocol and back — 0x0004 is ATT and 0x0006 is SMP, not the other way round.
L2CAP_CID_BREDR_SIGNALING = 0x0001
L2CAP_CID_ATT = 0x0004
L2CAP_CID_LE_SIGNALING = 0x0005
L2CAP_CID_SMP = 0x0006
L2CAP_CID_SIGNALING = L2CAP_CID_LE_SIGNALING
L2CAP_FIXED_CHANNELS = {0x0001: "L2CAP signaling (BR/EDR)", 0x0004: "ATT",
                        0x0005: "L2CAP signaling (LE)", 0x0006: "SMP (security manager)",
                        0x0007: "BR/EDR SM (security manager)"}


#: L2CAP signaling commands, for the connection-parameter and echo exchanges
L2CAP_COMMANDS = {0x01: "Command Reject", 0x02: "Connection Request",
                  0x03: "Connection Response", 0x04: "Configure Request",
                  0x05: "Configure Response", 0x06: "Disconnection Request",
                  0x07: "Disconnection Response", 0x08: "Echo Request",
                  0x09: "Echo Response", 0x0A: "Information Request",
                  0x0B: "Information Response", 0x0C: "Create Channel Request",
                  0x12: "Connection Parameter Update Request",
                  0x13: "Connection Parameter Update Response", 0x14: "LE Credit Based "
                  "Connection Request", 0x15: "LE Credit Based Connection Response"}

#: SMP commands: the pairing exchange is where a downgrade attack shows up
SMP_COMMANDS = {0x01: "Pairing Request", 0x02: "Pairing Response",
                0x03: "Pairing Confirm", 0x04: "Pairing Random", 0x05: "Pairing Failed",
                0x06: "Encryption Information", 0x07: "Master Identification",
                0x08: "Identity Information", 0x09: "Identity Address Information",
                0x0A: "Signing Information", 0x0B: "Security Request",
                0x0C: "Pairing Public Key", 0x0D: "Pairing DHKey Check",
                0x0E: "Pairing Keypress Notification"}

#: the auth requirements byte of a pairing request, bit by bit.  The Secure
#: Connections bit (0x08) is the one the KNOB class of attack tries to strip: without
#: it the key exchange uses the legacy procedure, whose contribution from the host is
#: the part an attacker on the link can squeeze down.
AUTH_REQ_BITS = {0x01: "bonding", 0x04: "MITM protection", 0x08: "LE Secure Connections",
                 0x10: "keypress notifications", 0x20: "CTKD (cross-transport key derivation)"}

SMP_KEY_DISTRIBUTION = {0x01: "EncKey", 0x02: "IdKey", 0x04: "SignKey", 0x08: "LinkKey"}

SMP_FAILURE_REASONS = {0x01: "passkey entry failed", 0x02: "OOB not available",
                       0x03: "authentication requirements not met",
                       0x04: "confirm value failed", 0x05: "pairing not supported",
                       0x06: "encryption key size insufficient",
                       0x07: "command not supported", 0x08: "unspecified reason",
                       0x09: "repeated attempts", 0x0A: "invalid parameters",
                       0x0B: "DHKey check failed", 0x0C: "numeric comparison failed",
                       0x0D: "BR/EDR pairing in progress", 0x0E: "cross-transport key "
                       "derivation not allowed"}

#: ATT operations: a GATT enumeration *is* these, so they are worth naming
ATT_OPCODES = {0x01: "Error Response", 0x02: "MTU Request", 0x03: "MTU Response",
               0x04: "Find Information Request", 0x05: "Find Information Response",
               0x06: "Find By Type Value Request", 0x07: "Find By Type Value Response",
               0x08: "Read By Type Request", 0x09: "Read By Type Response",
               0x0A: "Read Request", 0x0B: "Read Response", 0x0C: "Read Blob Request",
               0x0D: "Read Blob Response", 0x0E: "Read Multiple Request",
               0x0F: "Read Multiple Response", 0x10: "Read By Group Type Request",
               0x11: "Read By Group Type Response", 0x12: "Write Request",
               0x13: "Write Command", 0x14: "Prepare Write Request",
               0x15: "Prepare Write Response", 0x16: "Execute Write Request",
               0x17: "Execute Write Response", 0x18: "Handle Value Notification",
               0x19: "Handle Value Indication", 0x1A: "Handle Value Confirmation",
               0x1B: "Signed Write Command", 0x52: "Write Command"}

#: the standard GATT "primary service" UUID for the discovery that enumerates a device
GATT_PRIMARY_SERVICE = 0x2800
GATT_SECONDARY_SERVICE = 0x2801
GATT_INCLUDE = 0x2802
GATT_CHARACTERISTIC = 0x2803


def parse_connection_request(data: bytes) -> Dict[str, Any]:
    """The LLData of a CONNECT_IND: the connection's own access address and timing.

    Every field here matters to an assessment.  The access address is how the *later*
    data-channel packets of that connection are recognised, the interval and the timeout
    say how easy the connection is to follow (and how much battery it costs the device),
    the channel map says how many channels it will actually hop over, and the CRCInit is
    the seed of the CRC the link uses — a value an attacker who wants to inject into an
    established connection has to reproduce.
    """
    out: Dict[str, Any] = {}
    if len(data) < 22:
        return out
    out["access_address"] = mac_text(data[0:4])
    out["crc_init"] = data[4:7].hex()
    out["window_size"] = data[7]
    out["window_offset"] = int.from_bytes(data[8:10], "little")
    out["interval_ms"] = round(int.from_bytes(data[10:12], "little") * 1.25, 2)
    out["latency"] = int.from_bytes(data[12:14], "little")
    out["timeout_ms"] = int.from_bytes(data[14:16], "little") * 10
    channel_map = int.from_bytes(data[16:21], "little")
    out["channel_map"] = f"{channel_map:010x}"
    out["channels_used"] = bin(channel_map).count("1")
    out["hop"] = data[21] & 0x1F
    out["sca"] = (data[21] >> 5) & 0x07
    return out


def parse_ll_header(data: bytes) -> Dict[str, Any]:
    """The link-layer header of a data-channel packet: LLID, sequence bits, length."""
    out: Dict[str, Any] = {"llid": 0, "length": 0, "nesn": False, "sn": False,
                           "more_data": False, "payload": b""}
    if len(data) < 2:
        return out
    llid = data[0] & 0x03
    out.update({"llid": llid,
                "llid_text": {1: "continuation / L2CAP", 2: "start of L2CAP",
                              3: "LL control PDU"}.get(llid, "reserved"),
                "nesn": bool(data[0] & 0x04), "sn": bool(data[0] & 0x08),
                "more_data": bool(data[0] & 0x10),
                "length": data[1] & 0x1F})
    out["payload"] = data[2:2 + out["length"]]
    if llid == 3 and out["payload"]:
        opcode = out["payload"][0]
        out["control_opcode"] = opcode
        out["control"] = LL_CONTROL_OPCODES.get(opcode, f"opcode 0x{opcode:02x}")
        if opcode in (0x08, 0x09, 0x0E) and len(out["payload"]) >= 9:
            features = int.from_bytes(out["payload"][1:9], "little")
            out["features"] = {name: bool(features >> bit & 1)
                               for bit, name in LL_FEATURE_BITS.items()}
    return out


def parse_l2cap(payload: bytes) -> Dict[str, Any]:
    """An L2CAP frame: its channel and, for the fixed channels, the protocol inside."""
    out: Dict[str, Any] = {"length": 0, "cid": 0, "channel": "", "payload": b""}
    if len(payload) < 4:
        return out
    out["length"] = int.from_bytes(payload[0:2], "little")
    out["cid"] = int.from_bytes(payload[2:4], "little")
    out["channel"] = L2CAP_FIXED_CHANNELS.get(out["cid"], f"dynamic 0x{out['cid']:04x}")
    body = payload[4:4 + out["length"]]
    out["payload"] = body
    if out["cid"] == L2CAP_CID_ATT and body:
        out["att"] = parse_att(body)
    elif out["cid"] == L2CAP_CID_SMP and body:
        out["smp"] = parse_smp(body)
    elif out["cid"] in (L2CAP_CID_LE_SIGNALING, L2CAP_CID_BREDR_SIGNALING) \
            and len(body) >= 4:
        code = body[0]
        out["command"] = L2CAP_COMMANDS.get(code, f"code 0x{code:02x}")
        out["identifier"] = body[1]
        out["command_length"] = int.from_bytes(body[2:4], "little")
    return out


def smp_pairing_request(io_capability: int = 0x03, oob: int = 0x00, auth: int = 0x00,
                        key_size: int = 16, initiator_keys: int = 0x0F,
                        responder_keys: int = 0x0F) -> bytes:
    """A Pairing Request, with the security the initiator is willing to settle for.

    ``auth`` is the byte a downgrade attack argues about: bit 0 is bonding, bit 2 is
    man-in-the-middle protection and bit 3 is LE Secure Connections.  Sending the same
    request with those bits cleared — and reading the *response* — is how a run finds out
    whether a device that supports protected pairing will accept unprotected pairing from
    whoever asks, and whether it will accept a one-byte key.
    """
    return bytes([0x01, int(io_capability) & 0xFF, int(oob) & 0xFF, int(auth) & 0xFF,
                  max(7, min(16, int(key_size))) & 0xFF,
                  int(initiator_keys) & 0xFF, int(responder_keys) & 0xFF])


def parse_smp(data: bytes) -> Dict[str, Any]:
    """A security-manager command.  Pairing requests are the interesting ones.

    The pairing request carries the IO capabilities, the auth requirements byte (bonding,
    MITM, Secure Connections) and the maximum encryption key size.  Reading it out of a
    capture answers the question an assessment is really asking — *was this link paired
    with Secure Connections and MITM protection, or with Just Works and legacy pairing
    whose key contribution is small enough to brute-force in real time?*
    """
    out: Dict[str, Any] = {"command": 0, "name": "", "payload": bytes(data)}
    if not data:
        return out
    command = data[0]
    out["command"] = command
    out["name"] = SMP_COMMANDS.get(command, f"command 0x{command:02x}")
    body = data[1:]
    if command in (0x01, 0x02) and len(body) >= 6:
        capabilities, oob, auth = body[0], body[1], body[2]
        out.update({"io_capabilities": capabilities,
                    "io": IO_CAPABILITIES.get(capabilities, f"0x{capabilities:02x}"),
                    "oob": bool(oob & 0x01),
                    "auth_requirements": auth,
                    "auth_bits": [name for bit, name in AUTH_REQ_BITS.items()
                                  if auth & bit],
                    "mitm": bool(auth & 0x04),
                    "secure_connections": bool(auth & 0x08),
                    "bonding": bool(auth & 0x01),
                    "max_key_size": body[3],
                    "initiator_key_distribution": body[4],
                    "responder_key_distribution": body[5],
                    "just_works": capabilities in (3, 0) and not (auth & 0x04)})
    elif command == 0x05 and len(body) >= 1:
        out["reason"] = body[0]
        out["reason_text"] = SMP_FAILURE_REASONS.get(body[0], f"0x{body[0]:02x}")
    elif command in (0x0C,) and len(body) >= 64:
        out["public_key_x"] = body[0:32].hex()
        out["public_key_y"] = body[32:64].hex()
    return out


def parse_att(data: bytes) -> Dict[str, Any]:
    """An ATT PDU: a GATT operation, an error code, or a value exchange."""
    out: Dict[str, Any] = {"opcode": 0, "name": "", "payload": bytes(data)}
    if not data:
        return out
    opcode = data[0]
    out["opcode"] = opcode
    out["name"] = ATT_OPCODES.get(opcode, f"opcode 0x{opcode:02x}")
    body = data[1:]
    if opcode == 0x01 and len(body) >= 4:              # Error Response
        out.update({"request_opcode": body[0],
                    "request_name": ATT_OPCODES.get(body[0], "?"),
                    "handle": int.from_bytes(body[1:3], "little"),
                    "error_code": body[3],
                    "error_text": {0x01: "Invalid Handle", 0x02: "Read Not Permitted",
                                   0x03: "Write Not Permitted",
                                   0x05: "Insufficient Authentication",
                                   0x06: "Request Not Supported",
                                   0x07: "Invalid Offset", 0x08: "Insufficient Authorization",
                                   0x0A: "Attribute Not Found",
                                   0x0C: "Insufficient Encryption Key Size",
                                   0x0F: "Insufficient Encryption"}.get(body[3], "other")})
    elif opcode in (0x09, 0x11) and len(body) >= 2:    # Read By Type / By Group Type
        entry_length = body[0]
        entries = []
        payload = body[1:]
        group_type = out.get("request_uuid") == GATT_PRIMARY_SERVICE or opcode == 0x11
        for offset in range(0, len(payload) - entry_length + 1, entry_length):
            entry = payload[offset:offset + entry_length]
            if len(entry) < 2:
                break
            if opcode == 0x11 and len(entry) >= 6:
                # a service: start handle, end group handle, 16-bit UUID
                uuid = int.from_bytes(entry[4:6], "little")
                entries.append({"handle": int.from_bytes(entry[0:2], "little"),
                                "start_handle": int.from_bytes(entry[0:2], "little"),
                                "end_handle": int.from_bytes(entry[2:4], "little"),
                                "uuid": uuid, "uuid_text": f"0x{uuid:04x}",
                                "name": service_name(uuid)})
            else:
                entries.append({"handle": int.from_bytes(entry[0:2], "little"),
                                "value": entry[2:].hex()})
        out.update({"entry_length": entry_length, "entries": entries,
                    "count": len(entries), "group": group_type})
    elif opcode == 0x05 and len(body) >= 1:            # Find Information Response
        out["format"] = body[0]
        payload = body[1:]
        entry_length = 4 if body[0] == 1 else 18
        out["entries"] = [{"handle": int.from_bytes(payload[o:o + 2], "little"),
                           "uuid": payload[o + 2:o + entry_length].hex()}
                          for o in range(0, len(payload) - entry_length + 1, entry_length)]
    elif opcode in (0x08, 0x10, 0x06) and len(body) >= 2:
        out.update({"start_handle": int.from_bytes(body[0:2], "little"),
                    "end_handle": int.from_bytes(body[2:4], "little")
                    if len(body) >= 4 else 0,
                    "uuid": body[-2:].hex() if len(body) >= 4 else ""})
    elif opcode in (0x0A, 0x0C) and len(body) >= 2:    # Read Request / Read Blob
        out["handle"] = int.from_bytes(body[0:2], "little")
    elif opcode in (0x12, 0x13, 0x1B) and len(body) >= 2:
        out.update({"handle": int.from_bytes(body[0:2], "little"),
                    "value": body[2:].hex()[:80],
                    "value_text": ascii_preview(body[2:], 48)})
    elif opcode in (0x18, 0x19) and len(body) >= 2:
        out.update({"handle": int.from_bytes(body[0:2], "little"),
                    "value": body[2:].hex()[:80],
                    "value_text": ascii_preview(body[2:], 48)})
    elif opcode == 0x03 and len(body) >= 2:            # MTU Response
        out["mtu"] = int.from_bytes(body[0:2], "little")
    return out


def ascii_preview(data: bytes, limit: int = 60) -> str:
    """Printable rendering of a payload value, for a report line."""
    return "".join(chr(byte) if 32 <= byte < 127 else "." for byte in data[:limit])


def parse_acl_packet(packet: bytes) -> Dict[str, Any]:
    """Read an H4 ACL packet: ``(handle, flags, L2CAP frame)`` for the controller's answers.

    A controller reports the peer's data as an ACL packet: the packet type, the connection
    handle with the packet-boundary flags, the length, and then the L2CAP frame.  An
    attack that sends ACL data and reads the answer needs this to see what came back —
    without it, the answer is a hex string somebody has to search by hand.
    """
    out: Dict[str, Any] = {"type": packet[0] if packet else 0, "handle": 0, "flags": 0,
                           "length": 0, "payload": b"", "l2cap": None}
    body = packet[1:] if packet[:1] == bytes([HCI_ACL_PACKET]) else packet
    if len(body) < 4:
        return out
    handle_flags = int.from_bytes(body[0:2], "little")
    out["handle"] = handle_flags & 0x0FFF
    out["flags"] = handle_flags >> 12
    out["length"] = int.from_bytes(body[2:4], "little")
    payload = body[4:4 + out["length"]] if out["length"] else body[4:]
    out["payload"] = payload
    out["l2cap"] = parse_l2cap(payload)
    return out


def parse_data_channel(frame: bytes) -> Dict[str, Any]:
    """Parse a *data-channel* record (link type 251/256) into LL/L2CAP/ATT/SMP fields.

    This is what a followed connection looks like: the same eight-byte pseudo header, an
    access address that is not the advertising one, then the link-layer packet.  Reading
    it offline is how GATT enumeration and pairing behaviour become evidence rather than
    a claim, and it is the only way to audit a connection that was captured rather than
    performed.
    """
    out: Dict[str, Any] = {"advertising": False, "l2cap": None, "att": None, "smp": None,
                           "ll": None}
    for offset in (12, 8, 4, 0):
        if len(frame) <= offset + 2:
            continue
        if frame[offset:offset + 4] == ADV_ACCESS_ADDRESS:
            continue
        header = parse_ll_header(frame[offset:])
        if not header["length"] or len(header["payload"]) < header["length"]:
            continue
        if header["llid"] in (1, 2) and len(header["payload"]) >= 4:
            out["ll"] = header
            out["l2cap"] = parse_l2cap(header["payload"])
            out["att"] = out["l2cap"].get("att")
            out["smp"] = out["l2cap"].get("smp")
            break
        if header["llid"] == 3:
            out["ll"] = header
            break
    return out


def gatt_services_from_att(entries: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Turn Read By Group Type entries into a service list a report can print."""
    services = []
    for entry in entries or ():
        uuid = entry.get("uuid")
        if isinstance(uuid, int):
            services.append({"start_handle": entry.get("start_handle"),
                             "end_handle": entry.get("end_handle"),
                             "uuid": f"0x{uuid:04x}", "name": service_name(uuid)})
        else:
            services.append({"start_handle": entry.get("handle"),
                             "uuid": str(entry.get("value") or ""),
                             "name": GATT_SERVICES.get(str(entry.get("value"))[:4], "")})
    return services


def hci_socket() -> Any:
    """An ``AF_BLUETOOTH`` raw HCI socket, or ``None`` where the platform has none.

    Linux exposes the controller through ``socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)``;
    the socket is what makes an attack *an attack* rather than a description of one, and
    it needs ``CAP_NET_ADMIN`` — the same privilege the 802.11 side needs for monitor
    mode, which is why wifipilot already asks for it once.
    """
    import socket as socket_module

    family = getattr(socket_module, "AF_BLUETOOTH", 31)
    protocol = getattr(socket_module, "BTPROTO_HCI", 1)
    try:
        sock = socket_module.socket(family, socket_module.SOCK_RAW, protocol)
    except (OSError, AttributeError):
        return None
    # bind to the wildcard device index so the command goes to the first controller
    try:
        sock.bind((0,))
    except OSError:
        pass
    return sock


def hci_send(sock: Any, packet: bytes, timeout: float = 1.0) -> bytes:
    """Send an HCI packet and return whatever the controller answers (or ``b""``)."""
    if sock is None:
        return b""
    try:
        sock.settimeout(timeout)
        sock.send(packet)
        return sock.recv(1024)
    except OSError:
        return b""


# --------------------------------------------------------------------------- #
# captures: LINKTYPE_BLUETOOTH_LE_LL(_WITH_PHDR) and the BR/EDR link type
# --------------------------------------------------------------------------- #

#: libpcap link types for Bluetooth.  ``251`` is a bare link-layer PDU, ``256`` prefixes
#: RF channel, signal power, noise power, access address and the flags byte, which is
#: what ``btmon -w`` and ``tcpdump -i bluetooth0`` write.
BLUETOOTH_LE_LL = 251
BLUETOOTH_LE_LL_WITH_PHDR = 256
BLUETOOTH_BREDR_BB = 255
#: the pseudo-header is RF channel, signal power, noise power (3 bytes) and the access
#: address (4) — and then at least one flags byte before the PDU, whose exact size
#: differs between the tools that write this link type.  Rather than trust a constant,
#: :func:`find_adv_pdu` resynchronises on the PDU header itself.
BT_LL_WRAPPER_LENGTH = 8

#: the BLE access address every advertising packet shares
ADV_ACCESS_ADDRESS = b"\xd6\xbe\x89\x8e"


def find_adv_pdu(frame: bytes, earliest: int = 7) -> int:
    """Offset of the advertising PDU inside a wrapper record, or ``-1``.

    The pseudo header is eight bytes, but some writers (``btmon -w``, and anything that
    keeps libpcap's own "access address" inside the packet) repeat the address again
    before the PDU, so the parser finds the PDU instead of assuming where it starts: an
    advertising PDU's first byte carries the type in its low nibble and its second byte
    is the length, which must account for *exactly* the rest of the record.  A false
    positive is therefore impossible — the length has to fit to the byte.
    """
    for offset in range(earliest, min(len(frame) - 2, earliest + 12)):
        header = frame[offset]
        if (header & 0x0F) not in ADV_TYPES:
            continue
        length = frame[offset + 1] & 0x3F
        if length == len(frame) - offset - 2:
            return offset
    return -1


def parse_le_wrapper(frame: bytes) -> Dict[str, Any]:
    """Parse a ``LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR`` record.

    Layout, as libpcap defines it: RF channel (1), signal power (1), noise power (1),
    access-address offenses (1) and the reference access address (4, little endian).
    Some writers then repeat the access address as the start of the LE packet itself, so
    the PDU is *located* rather than assumed: a record is scanned for a header in the low
    nibble of its first byte whose length field accounts for exactly the rest of it.  A record whose access address is not the advertising one is a
    data-channel packet, which is a connection — the interesting part, and the part
    whose payload is encrypted unless the link key is known.
    """
    out: Dict[str, Any] = {"raw_length": len(frame), "frame": bytes(frame)}
    if len(frame) < BT_LL_WRAPPER_LENGTH:
        return out
    out["channel"] = frame[0]
    out["frequency_mhz"] = LE_ADV_CHANNEL_MHZ.get(frame[0],
                                                   2402 + (frame[0] - 37) * 2
                                                   if frame[0] >= 37 else
                                                   2404 + frame[0] * 2)
    out["rssi"] = frame[1] - 127
    out["noise"] = frame[2] - 127
    out["access_address"] = mac_text(frame[4:8])
    offset = find_adv_pdu(frame)
    out["advertising"] = offset >= 0 and frame[4:8] == ADV_ACCESS_ADDRESS
    if out["advertising"]:
        out["pdu_offset"] = offset
        out.update(parse_adv_pdu(frame[offset:]))
    else:
        out["pdu"] = frame[BT_LL_WRAPPER_LENGTH:].hex()[:200]
    return out


def iter_le_frames(path: str, limit: int = 200_000) -> Iterable[Tuple[float, Dict[str, Any]]]:
    """``(timestamp, parsed advertising packet)`` for every record in a BLE capture.

    Accepts both the wrapper format (256) and the bare link-layer format (251); anything
    else is skipped rather than mis-parsed, because a Bluetooth parser pointed at an
    802.11 capture should report nothing, not nonsense.
    """
    from .pcap import iter_records

    for timestamp, link_type, payload in iter_records(str(path), limit):
        if link_type == BLUETOOTH_LE_LL_WITH_PHDR:
            yield timestamp, parse_le_wrapper(payload)
        elif link_type == BLUETOOTH_LE_LL and len(payload) >= 2:
            frame = parse_adv_pdu(payload)
            frame.setdefault("channel", 37)
            frame.setdefault("rssi", 0)
            yield timestamp, frame
        elif link_type == BLUETOOTH_BREDR_BB:
            # BR/EDR baseband: the interesting byte is the packet type, and the payload
            # is the LMP/L2CAP data
            yield timestamp, {"access_address": "", "advertising": False,
                              "br_edr": True, "length": len(payload),
                              "data": payload.hex()[:120]}


# --------------------------------------------------------------------------- #
# BR/EDR: SDP, the service discovery protocol every classic device answers
# --------------------------------------------------------------------------- #

#: the profile/service classes a classic device is worth talking about, by UUID16
SDP_SERVICES = {
    0x1101: "Serial Port", 0x1105: "OBEX Object Push", 0x1106: "OBEX File Transfer",
    0x1108: "Headset", 0x110A: "Audio Source", 0x110B: "Audio Sink",
    0x110C: "A/V Remote Control Target", 0x110E: "A/V Remote Control",
    0x110D: "Advanced Audio Distribution (A2DP)", 0x1112: "Headset Audio Gateway",
    0x1113: "WAP", 0x1114: "WAP Client", 0x1115: "PANU", 0x1116: "NAP",
    0x1117: "GN", 0x111E: "Handsfree", 0x111F: "Handsfree Audio Gateway",
    0x1124: "Human Interface Device (HID)", 0x112D: "SIM Access",
    0x112F: "Phonebook Access (PCE)", 0x1132: "Phonebook Access (PSE)",
    0x1133: "Message Access Server", 0x1134: "Message Notification Server",
    0x1200: "PnP Information", 0x0001: "SDP", 0x0003: "RFCOMM",
    0x0100: "L2CAP", 0x000F: "Browse Group Descriptor", 0x1000: "Service Discovery",
    0x1103: "Dial-up Networking", 0x1104: "LAN Access", 0x1109: "Cordless Telephony",
    0x1110: "Intercom", 0x1111: "Fax", 0x111A: "Imaging Responder",
    0x111B: "Imaging Automatic Archive", 0x111C: "Imaging Referenced Objects",
    0x111D: "Handsfree", 0x1120: "Direct Printing", 0x1122: "Basic Printing",
    0x1123: "Printing Status", 0x112E: "Phonebook Access",
    0x1130: "Headset Profile", 0x1131: "Audio/Video Profile",
}


def sdp_service_search_attribute(transaction: int = 1, uuids: Sequence[int] = (0x0100,),
                                 max_records: int = 0xFFFF,
                                 continuation: bytes = b"") -> bytes:
    """An SDP ServiceSearchAttributeRequest (PDU id 0x06), as a real client sends it.

    An SDP conversation runs over L2CAP (PSM 0x0001) and needs no pairing: everything a
    device advertises there — serial ports, OBEX push, HID, printing — is a service an
    attacker can enumerate from the far side of the room.
    """
    body = bytearray()
    body += bytes([len(uuids) * 2 + 1]) + b"\x35" + bytes([len(uuids) * 2])
    for uuid in uuids:
        body += b"\x19" + struct.pack(">H", uuid & 0xFFFF)
    body += bytes([0x09]) + struct.pack(">H", max_records)           # max attribute bytes
    body += continuation or b"\x35\x03\x09\x00\x01"                  # attribute ID list
    # the PDU header is PduId, TransactionId and the *parameter* length: the sequence
    # above is the parameter, and nothing else goes between the two
    return struct.pack(">BHH", 0x06, transaction & 0xFFFF, len(body)) + bytes(body)


def parse_sdp(data: bytes) -> List[Dict[str, Any]]:
    """Read service records out of an SDP response: ``(attribute, value)`` pairs.

    Two shapes arrive here.  A real device answers with BER data elements — a ``0x35``
    sequence of ``0x30`` attribute lists, each a ``0x09`` attribute identifier followed by
    its value — and that is what :func:`_sdp_ber_records` walks.  A payload that is
    already a bare attribute stream (or a client's own hand-rolled request echoed back)
    falls through to the flat walk below, because a parser that gives up on the second
    shape stops working the moment a device answers with the first.

    The attributes a report quotes are ``0x0000``/``0x0001`` (service class IDs),
    ``0x0004`` (the protocol descriptor list, which carries the RFCOMM channel),
    ``0x0005`` (browse group) and ``0x0100`` (the service name).
    """
    records = _sdp_ber_records(_sdp_parameters(data))
    if records:
        return records
    out: List[Dict[str, Any]] = []
    body = _sdp_parameters(data)
    index = 0
    while index + 3 <= len(body):
        # an attribute is a 2-byte id followed by a size byte and a value of that size
        attribute = int.from_bytes(body[index:index + 2], "big")
        size = body[index + 2]
        raw = body[index + 3:index + 3 + size]
        if len(raw) < size:
            break
        entry: Dict[str, Any] = {"attribute": f"0x{attribute:04x}",
                                 "value_hex": raw.hex()}
        if attribute == 0x0001 and len(raw) >= 3:                 # service class IDs
            uuids = []
            offset = 0
            while offset + 3 <= len(raw):
                if raw[offset] == 0x19:
                    uuid = int.from_bytes(raw[offset + 1:offset + 3], "big")
                    uuids.append(uuid)
                    entry.setdefault("services", []).append(
                        SDP_SERVICES.get(uuid, f"uuid 0x{uuid:04x}"))
                    offset += 3
                else:
                    offset += 1
            entry["uuids"] = uuids
        if attribute == 0x0004 and b"\x19\x00\x03" in raw:
            entry["rfcomm"] = True                                # a serial channel exists
        if attribute == 0x0100:
            entry["name"] = raw.decode("utf-8", "replace").strip("\x00")
        out.append(entry)
        index += 3 + size
    return out


def _sdp_parameters(data: bytes) -> bytes:
    """The parameter bytes of an SDP PDU, or the data itself when it has no header.

    A whole SDP PDU is PduId, TransactionId (two bytes) and the length of the parameters;
    what an L2CAP payload under PSM 1 carries is normally the first form, and a caller
    that hands in a bare attribute stream gets it walked as it stands.
    """
    if len(data) >= 5 and data[0] in (0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07):
        length = int.from_bytes(data[3:5], "big")
        return data[5:5 + length] if length else data[5:]
    return data


def _ber_size(data: bytes, offset: int) -> Tuple[int, int]:
    """``(size, bytes used)`` for the BER length that starts at ``offset``."""
    if offset >= len(data):
        return 0, 0
    first = data[offset]
    if first < 0x80:
        return first, 1
    count = first & 0x7F
    if not count or offset + 1 + count > len(data):
        return 0, 1
    return int.from_bytes(data[offset + 1:offset + 1 + count], "big"), 1 + count


def _ber_content(data: bytes) -> bytes:
    """The content of the data element at the start of ``data``."""
    size, header = _ber_size(data, 1)
    return data[1 + header:1 + header + size]


def _ber_items(data: bytes) -> List[Tuple[int, bytes]]:
    """``(tag, content)`` for every data element in a sequence's content."""
    out: List[Tuple[int, bytes]] = []
    offset = 0
    while offset + 2 <= len(data):
        tag = data[offset]
        size, header = _ber_size(data, offset + 1)
        start = offset + 1 + header
        content = data[start:start + size]
        if len(content) < size:
            break
        out.append((tag, content))
        offset = start + size
    return out


def _ber_value(tag: int, content: bytes) -> Dict[str, Any]:
    """What one SDP attribute *value* says, in the keys a report quotes."""
    entry: Dict[str, Any] = {"value_hex": content.hex()}
    if tag == 0x19 and len(content) >= 2:                     # UUID16
        uuid = int.from_bytes(content[:2], "big")
        entry.update({"uuids": [uuid], "services": [SDP_SERVICES.get(uuid,
                                                                     f"uuid 0x{uuid:04x}")]})
    elif tag == 0x1A and len(content) >= 4:                   # UUID32
        uuid = int.from_bytes(content[:4], "big")
        entry.update({"uuids": [uuid], "services": [SDP_SERVICES.get(uuid,
                                                                     f"uuid 0x{uuid:04x}")]})
    elif tag in (0x25, 0x26):                                 # text
        entry["name"] = content.decode("utf-8", "replace").strip("\x00")
    elif tag in (0x08, 0x09, 0x0A, 0x0B):                     # unsigned integers
        entry["value"] = int.from_bytes(content, "big")
    elif tag in (0x35, 0x36, 0x37):                           # a sequence: walk it
        uuids: List[int] = []
        names: List[str] = []
        channel = None
        items = _ber_items(content)
        for index, (inner_tag, inner) in enumerate(items):
            if inner_tag in (0x19, 0x1A):
                uuid = int.from_bytes(inner, "big")
                uuids.append(uuid)
                if uuid == 0x0003 and index + 1 < len(items) \
                        and items[index + 1][0] in (0x08, 0x09, 0x0A, 0x0B):
                    # the RFCOMM protocol descriptor: the UUID, then the channel
                    channel = int.from_bytes(items[index + 1][1], "big")
            elif inner_tag in (0x25, 0x26):
                names.append(inner.decode("utf-8", "replace").strip("\x00"))
            elif inner_tag in (0x35, 0x36, 0x37):
                # a nested descriptor: the L2CAP and RFCOMM halves of a protocol list
                # are separate sequences inside it, and the channel is in the second one
                nested = _ber_value(inner_tag, inner)
                uuids.extend(uuid for uuid in nested.get("uuids", []) if uuid not in uuids)
                names.extend(nested.get("names", []))
                channel = nested.get("channel", channel)
                if nested.get("name") and nested["name"] not in names:
                    names.append(nested["name"])
        if uuids:
            entry["uuids"] = uuids
            entry["services"] = [SDP_SERVICES.get(uuid, f"uuid 0x{uuid:04x}")
                                 for uuid in uuids]
            entry["rfcomm"] = 0x0003 in uuids
        if names:
            entry["name"] = names[-1]
            entry["names"] = names
        if channel is not None:
            entry["channel"] = channel
    return entry


def _sdp_ber_records(body: bytes) -> List[Dict[str, Any]]:
    """Read a ServiceAttributeList: a sequence of attribute lists, in BER.

    A response is a ``0x35`` sequence whose content is one ``0x30`` attribute list per
    record, and each list is a stream of ``0x09`` attribute identifiers followed by their
    values.  Anything that is not that shape returns no records, which is how the caller
    knows to fall back to the flat form a raw L2CAP payload sometimes carries.
    """
    if body[:1] != b"\x35":
        return []
    out: List[Dict[str, Any]] = []
    for tag, content in _ber_items(_ber_content(body)):
        if tag != 0x30:
            continue
        items = _ber_items(content)
        index = 0
        attributes: Dict[int, Dict[str, Any]] = {}
        while index < len(items):
            item_tag, item = items[index]
            if item_tag == 0x09 and len(item) == 2:
                attribute = int.from_bytes(item, "big")
                value_tag, value = items[index + 1] if index + 1 < len(items) else (0, b"")
                entry = {"attribute": f"0x{attribute:04x}"}
                entry.update(_ber_value(value_tag, value))
                attributes[attribute] = entry
                index += 2
                continue
            index += 1
        ordered = [attributes[key] for key in sorted(attributes)]
        out.append({"attributes": ordered,
                    "name": next((entry.get("name") for entry in ordered
                                  if entry.get("name")), ""),
                    "services": [name for entry in ordered
                                 for name in entry.get("services", [])],
                    "channel": next((entry.get("channel") for entry in ordered
                                     if entry.get("channel")), None),
                    "value_hex": content.hex()[:240]})
    return [entry for entry in out if entry["attributes"]]


def describe_l2cap_psm(psm: int) -> str:
    """The L2CAP PSM table, for the handful of values a device exposes."""
    return {0x0001: "SDP", 0x0003: "RFCOMM", 0x000F: "BNEP", 0x0011: "HID Control",
            0x0013: "HID Interrupt", 0x0015: "AVCTP", 0x0019: "AVDTP",
            0x001B: "ATT (BLE)", 0x001F: "OCF/OBEX", 0x0101: "L2CAP LE signalling",
            0x1001: "SDP (legacy)"}.get(psm, f"psm 0x{psm:04x}")


# --------------------------------------------------------------------------- #
# what a device is, in one line
# --------------------------------------------------------------------------- #

@dataclass
class BluetoothDevice:
    """One device seen on air, with what its advertisement actually said."""

    address: str
    name: str = ""
    rssi: int = 0
    address_kind: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    observations: int = 0
    channels: List[int] = field(default_factory=list)
    company: str = ""
    services: List[str] = field(default_factory=list)
    appearance: str = ""
    beacon: Optional[Dict[str, Any]] = None
    tracker: Optional[Dict[str, str]] = None
    connectable: bool = False
    raw: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def display_name(self) -> str:
        return self.name or self.company or self.address

    @property
    def seconds_seen(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    def to_dict(self) -> Dict[str, Any]:
        return {"address": self.address, "name": self.name, "rssi": self.rssi,
                "address_kind": self.address_kind, "observations": self.observations,
                "seconds_seen": round(self.seconds_seen, 1), "company": self.company,
                "services": self.services, "appearance": self.appearance,
                "beacon": self.beacon, "tracker": self.tracker,
                "connectable": self.connectable}


def merge_observations(devices: Dict[str, BluetoothDevice],
                       packet: Dict[str, Any], stamp: Optional[float] = None) -> BluetoothDevice:
    """Fold one parsed advertising packet into the device map."""
    address = packet.get("address") or packet.get("scan_address") or "?"
    stamp = stamp if stamp is not None else time.time()
    device = devices.get(address)
    if device is None:
        device = BluetoothDevice(address=address, first_seen=stamp)
        devices[address] = device
    device.last_seen = stamp
    device.observations += 1
    # the observation keeps its arrival time: the raw list is what the interval analysis
    # walks, and a packet without a stamp is a packet every one of whose gaps reads 0 ms
    if not packet.get("timestamp"):
        packet["timestamp"] = stamp
    if packet.get("rssi"):
        device.rssi = packet["rssi"]
    if packet.get("address_kind"):
        device.address_kind = packet["address_kind"]
    if packet.get("channel"):
        device.channels.append(packet["channel"])
    if packet.get("name") and not device.name:
        device.name = packet["name"]
    if packet.get("pdu_type") in (0x00, 0x01, 0x06):
        device.connectable = True
    for entry in packet.get("ad") or []:
        if entry.get("company_name"):
            device.company = entry["company_name"]
        for name in entry.get("services") or []:
            if name not in device.services:
                device.services.append(name)
        if entry.get("appearance_text"):
            device.appearance = entry["appearance_text"]
        beacon = parse_ibeacon(entry) or parse_eddystone(entry)
        if beacon:
            device.beacon = beacon
        tracker = tracker_of([entry])
        if tracker:
            device.tracker = tracker
    device.raw.append(packet)
    return device


# --------------------------------------------------------------------------- #
# the profiles above the link: LMP features, RFCOMM, OBEX and HID
# --------------------------------------------------------------------------- #
#
# Everything above is the radio and the link.  The classic attacks in the "famous" wave
# live one storey up: they need the *link control* commands that negotiate keys (BIAS,
# KNOB), the serial profile that carries AT commands and file transfer (BlueBugging,
# BlueSnarfing), the OBEX dialect that runs over it, and the HID reports that are a
# keyboard's entire output.  This section is that storey, in the same style: real
# protocol bytes, built in-process, parseable by the in-process parser, so a capture and
# an attack describe the same frame.

#: Link Control (OGF 1) commands, by name.  The opcode is ``(ogf << 10) | ocf``, which
#: is how the HCI specification addresses a command — the same arithmetic
#: :func:`hci_packet` does from :data:`HCI_COMMANDS`.  These are the ones the link-layer
#: attacks need: feature reads for KNOB, the key/IO-capability replies that impersonation
#: (BIAS) and key negotiation replay depend on, and the control of an existing handle.
HCI_LINK_CONTROL: Dict[str, Tuple[int, int]] = {
    "Create Connection": (1, 0x05),
    "Disconnect": (1, 0x06),
    "Read Remote Supported Features": (1, 0x03),
    "Read Remote Extended Features": (1, 0x1C),
    "Remote Name Request": (1, 0x19),
    "Authentication Requested": (1, 0x11),
    "Set Connection Encryption": (1, 0x13),
    "Change Connection Link Key": (1, 0x15),
    "Link Key Request Reply": (1, 0x0B),
    "Link Key Request Negative Reply": (1, 0x0C),
    "PIN Code Request Reply": (1, 0x0D),
    "IO Capability Request Reply": (1, 0x2B),
    "User Confirmation Request Reply": (1, 0x2C),
    "User Passkey Request Reply": (1, 0x2E),
    "IO Capability Request Negative Reply": (1, 0x34),
}

HCI_COMMANDS.update(HCI_LINK_CONTROL)

#: HCI events that carry a peer's feature pages back
HCI_EVENT_READ_REMOTE_SUPPORTED_FEATURES = 0x0B
HCI_EVENT_READ_REMOTE_EXTENDED_FEATURES = 0x23

#: BR/EDR feature bits, page by page, from the Baseband specification (Vol 2, Part B,
#: section 8.2 in the current revision).  Page 2's bit 2 — "Secure Connections
#: (Controller)" — is the one BIAS and KNOB are about: a peer that advertises it can be
#: negotiated down to a one-byte key, and a peer that does not requires the legacy
#: pairing path, which is what BIAS impersonates.
BREDR_FEATURES: Dict[int, Dict[int, str]] = {
    0: {
        0: "3-slot packets", 1: "5-slot packets", 2: "encryption", 3: "slot offset",
        4: "timing accuracy", 5: "switch (central/peripheral)", 6: "hold mode",
        7: "sniff mode", 8: "park mode", 9: "RSSI", 10: "channel quality driven data rate",
        11: "SCO link", 12: "HV2 packets", 13: "HV3 packets", 14: "u-law log",
        15: "A-law log", 16: "CVSD", 17: "paging", 18: "power control",
        19: "transparent SCO", 20: "flow control lag (LSB)", 21: "flow control lag (bit 1)",
        22: "flow control lag (MSB)", 23: "broadcast encryption", 24: "EDR ACL 2 Mbps",
        25: "EDR ACL 3 Mbps", 26: "enhanced inquiry scan", 27: "interlaced inquiry scan",
        28: "interlaced page scan", 29: "RSSI with inquiry results", 30: "EV3 packets",
        31: "EV4 packets",
    },
    1: {
        0: "EV5 packets", 1: "AFH capable peripheral", 2: "AFH capable central",
        3: "AFH classification peripheral", 4: "AFH classification central",
        5: "ESC0 (extended features)", 6: "anonymous mode", 7: "EDR eSCO 2 Mbps",
        8: "EDR eSCO 3 Mbps", 9: "3-slot EDR ACL", 10: "5-slot EDR ACL",
        11: "sniff subrating", 12: "pause encryption", 13: "AFH capable central (page 1)",
        14: "secure simple pairing", 15: "encapsulated PDU", 16: "erroneous data reporting",
        17: "non-flushable packet boundary flag", 18: "link supervision timeout event",
        19: "inquiry TX power level", 20: "enhanced power control",
        21: "extended features (page 2)", 22: "2 Mbps eSCO", 23: "3 Mbps eSCO",
    },
    2: {
        0: "connectionless peripheral broadcast",
        1: "connectionless central broadcast",
        2: "secure connections (controller)",
        3: "ping", 4: "slot availability mask", 5: "train nudging",
        6: "LE supported (controller)", 7: "simultaneous LE and BR/EDR",
    },
}


def link_control(name: str, parameters: bytes = b"") -> bytes:
    """``link_control("Read Remote Extended Features", ...)`` -> an H4 command packet."""
    return hci_packet(name, parameters)


def disconnect_command(handle: int, reason: int = 0x13) -> bytes:
    """Disconnect a handle with a reason code (0x13 remote user terminated)."""
    return link_control("Disconnect", struct.pack("<HB", handle & 0xFFFF, reason & 0xFF))


def authentication_requested(handle: int) -> bytes:
    """Ask the controller to authenticate an existing connection: BIAS talks here."""
    return link_control("Authentication Requested", struct.pack("<H", handle & 0xFFFF))


def set_connection_encryption(handle: int, enable: bool = True) -> bytes:
    """Turn link encryption on — after which the peer's key is whatever was negotiated."""
    return link_control("Set Connection Encryption",
                        struct.pack("<HB", handle & 0xFFFF, 1 if enable else 0))


def change_connection_link_key(handle: int) -> bytes:
    """Force a fresh link key: the manoeuvre a key-reinstallation replay answers."""
    return link_control("Change Connection Link Key", struct.pack("<H", handle & 0xFFFF))


def read_remote_features_command(handle: int, page: int = 0) -> bytes:
    """Read the peer's feature page: page 0 is the baseband set, 2 holds Secure Connections."""
    if page <= 0:
        return link_control("Read Remote Supported Features", struct.pack("<H", handle & 0xFFFF))
    return link_control("Read Remote Extended Features",
                        struct.pack("<HB", handle & 0xFFFF, page & 0xFF))


def link_key_request_reply(address: str, link_key: bytes) -> bytes:
    """Answer a link-key request with the key the impersonated device would have used."""
    return link_control("Link Key Request Reply",
                        mac_bytes(address) + bytes(link_key)[:16].ljust(16, b"\x00"))


def link_key_request_negative_reply(address: str) -> bytes:
    """Refuse the stored key, forcing the controller into a fresh pairing exchange."""
    return link_control("Link Key Request Negative Reply", mac_bytes(address))


def io_capability_request_reply(address: str, capability: int = 0x03,
                                authentication_requirements: int = 0x04) -> bytes:
    """Answer an IO-capability request: capability 3 is *no input, no output* (Just Works)."""
    return link_control("IO Capability Request Reply",
                        mac_bytes(address) + bytes([capability & 0xFF, 0x00,
                                                    authentication_requirements & 0xFF]))


def user_confirmation_request_reply(address: str) -> bytes:
    """Confirm a numeric comparison without a human: the Just Works path, spoken directly."""
    return link_control("User Confirmation Request Reply", mac_bytes(address))


def user_passkey_request_reply(address: str, passkey: int = 0) -> bytes:
    """Answer a passkey request with a chosen key (0..999999)."""
    return link_control("User Passkey Request Reply",
                        mac_bytes(address) + struct.pack("<I", passkey % 1000000))


def parse_features_event(packet: bytes) -> Dict[str, Any]:
    """Parse a *Read Remote [Extended] Features Complete* event into named bits.

    The event carries the connection handle, the status, an optional page number and the
    eight feature bytes.  Page 0 arrives on its own event; pages 1 and 2 arrive on the
    extended-features event.  Everything is decoded through :data:`BREDR_FEATURES`, so the
    report says "secure connections (controller): not supported" instead of a hex blob.
    """
    out: Dict[str, Any] = {"event": 0, "status": -1, "handle": 0, "page": 0,
                           "features": b"", "names": {}}
    data = packet
    if data[:1] == b"\x04":                                     # H4 event packet: strip the
        data = data[3:]                                         # type, event and length
    if len(data) < 3:
        return out
    event = packet[1] if packet[:1] == b"\x04" else 0x00
    out["event"] = event
    if event == HCI_EVENT_READ_REMOTE_EXTENDED_FEATURES:
        if len(data) < 4:
            return out
        out["status"], out["handle"] = data[0], struct.unpack("<H", data[1:3])[0]
        out["page"] = data[3]
        out["features"] = bytes(data[4:12])
    elif event == HCI_EVENT_READ_REMOTE_SUPPORTED_FEATURES:
        out["status"], out["handle"] = data[0], struct.unpack("<H", data[1:3])[0]
        out["features"] = bytes(data[3:11])
    out["names"] = explain_bredr_features(out["features"], out["page"])
    return out


def explain_bredr_features(features: bytes, page: int = 0) -> Dict[str, bool]:
    """Turn eight feature bytes into ``{name: supported}`` for the given page."""
    table = BREDR_FEATURES.get(page, {})
    bits = int.from_bytes(bytes(features)[:8].ljust(8, b"\x00"), "little")
    return {name: bool(bits >> bit & 1) for bit, name in sorted(table.items())}


# --------------------------------------------------------------------------- #
# RFCOMM (TS 07.10): the serial profile that carries AT commands and OBEX
# --------------------------------------------------------------------------- #

#: RFCOMM's fixed PSM; the *channel* inside it comes from the peer's SDP record
RFCOMM_PSM = 0x0003
#: DLCI 0 is the multiplexer's control channel; a user channel is ``channel << 1 | dir``
RFCOMM_CONTROL_DLCI = 0

#: control-field octets for the frames this module builds.  ``0xEF`` is UIH (unnumbered
#: information with header), which is what every RFCOMM payload uses today.
RFCOMM_UIH = 0xEF
RFCOMM_UIH_PF = 0xFF
RFCOMM_SABM = 0x2F
RFCOMM_UA = 0x63
RFCOMM_DISC = 0x43
RFCOMM_DM = 0x0F


def rfcomm_dlci(channel: int, direction: int = 0) -> int:
    """The DLCI for a user channel: ``channel * 2 + direction`` (0 = initiator)."""
    return (int(channel) & 0x1F) * 2 + (1 if direction else 0)


def rfcomm_address(dlci: int, command: bool = True) -> int:
    """Address octet: EA (this is the last address octet), C/R, then the six DLCI bits."""
    return 0x01 | (0x02 if command else 0x00) | ((dlci & 0x3F) << 2)


def rfcomm_length_field(length: int) -> bytes:
    """One or two length octets: bit 0 is EA, the value is shifted left by one."""
    if length < 128:
        return bytes([(length << 1) | 0x01])
    return bytes([((length & 0x7F) << 1), ((length >> 7) & 0xFF)])


def crc8_lapb(data: bytes, initial: int = 0xFF) -> int:
    """CRC-8 as LAPB/RFCOMM define it: polynomial x^8 + x^2 + x + 1, LSB first.

    The same polynomial the FCS of every RFCOMM frame is computed with, which is why it
    lives here rather than inside the frame builder.
    """
    crc = initial & 0xFF
    for byte in data:
        crc ^= byte & 0xFF
        for _ in range(8):
            crc = ((crc >> 1) ^ 0x8C) if crc & 1 else (crc >> 1)
    return crc & 0xFF


def rfcomm_frame(dlci: int, payload: bytes = b"", control: int = RFCOMM_UIH,
                 command: bool = True, fcs: bool = True) -> bytes:
    """A complete RFCOMM frame: address, control, length, payload and the LAPB FCS."""
    header = bytes([rfcomm_address(dlci, command), control & 0xFF]) \
        + rfcomm_length_field(len(payload))
    body = header + bytes(payload)
    if not fcs:
        return body
    return body + bytes([crc8_lapb(body)])


def parse_rfcomm(frame: bytes) -> Dict[str, Any]:
    """Read an RFCOMM frame back: DLCI, control, payload and whether the FCS checked."""
    out: Dict[str, Any] = {"dlci": -1, "channel": -1, "control": 0, "payload": b"",
                           "fcs_ok": None, "command": False}
    if len(frame) < 4:
        return out
    address, control = frame[0], frame[1]
    if not address & 0x01:
        return out
    out["dlci"] = (address >> 2) & 0x3F
    out["channel"] = out["dlci"] >> 1
    out["command"] = bool(address & 0x02)
    out["control"] = control
    first = frame[2]
    if first & 0x01:
        length = first >> 1
        offset = 3
    elif len(frame) >= 4:
        length = (first >> 1) | (frame[3] << 7)
        offset = 4
    else:
        return out
    out["payload"] = bytes(frame[offset:offset + length])
    tail = frame[offset + length:]
    if tail:
        out["fcs_ok"] = crc8_lapb(frame[:offset + length]) == tail[0]
    return out


def rfcomm_socket(address: str, channel: int, timeout: float = 5.0) -> Any:
    """Connect an RFCOMM channel through the kernel, or return ``None``.

    This is the real path for the serial profiles: ``AF_BLUETOOTH``/``BTPROTO_RFCOMM``
    makes the kernel and the controller do the framing, the credit-based flow control and
    the retransmissions, so an AT command or an OBEX request goes out exactly as a phone
    would send it.  It needs a controller with the peer bonded (or a peer that lets the
    channel open without one), which is what :func:`socket.error` says when it refuses.
    """
    import socket as socket_module

    family = getattr(socket_module, "AF_BLUETOOTH", None)
    protocol = getattr(socket_module, "BTPROTO_RFCOMM", None)
    if family is None or protocol is None:
        return None
    try:
        sock = socket_module.socket(family, socket_module.SOCK_STREAM, protocol)
    except (OSError, AttributeError):
        return None
    try:
        sock.settimeout(timeout)
        sock.connect((address, int(channel) & 0x1F))
    except OSError:
        with contextlib.suppress(OSError):
            sock.close()
        return None
    return sock


# --------------------------------------------------------------------------- #
# OBEX (IrOBEX 1.2): object exchange, which is how a phone gives its files away
# --------------------------------------------------------------------------- #

OBEX_CONNECT = 0x80
OBEX_DISCONNECT = 0x81
OBEX_PUT = 0x02
OBEX_PUT_FINAL = 0x82
OBEX_GET = 0x03
OBEX_GET_FINAL = 0x83
OBEX_SETPATH = 0x85
OBEX_ABORT = 0xFF

#: response codes, with the final bit already set (0x80 | code)
OBEX_RESPONSES = {
    0x90: "continue", 0xA0: "OK", 0xA1: "created", 0xA2: "accepted",
    0xC0: "bad request", 0xC1: "unauthorized", 0xC3: "forbidden", 0xC4: "not found",
    0xC5: "not acceptable", 0xC6: "conflict", 0xCB: "not implemented",
    0xD0: "internal server error", 0xD3: "service unavailable",
}

#: request opcodes, so a parser can tell a CONNECT from a response 0x80
OBEX_REQUESTS = {
    OBEX_CONNECT: "CONNECT", OBEX_DISCONNECT: "DISCONNECT", OBEX_PUT: "PUT",
    OBEX_PUT_FINAL: "PUT (final)", OBEX_GET: "GET", OBEX_GET_FINAL: "GET (final)",
    OBEX_SETPATH: "SETPATH", OBEX_ABORT: "ABORT",
}

#: header identifiers this module writes, and what the wire calls them
OBEX_HEADERS = {
    0x01: "Name (UTF-16)", 0x05: "Name", 0x42: "Type", 0x44: "Time",
    0x48: "Body", 0x49: "End of Body", 0xC3: "Length", 0xC4: "Connection ID",
}


def obex_header(identifier: int, value: bytes, length: Optional[int] = None) -> bytes:
    """One OBEX header: identifier, a big-endian length, then the value.

    The length counts the identifier and the length bytes as well as the value, so a
    14-byte file name is declared as 17 — which is exactly what a phone's OBEX stack
    writes, and what its parser expects to read back.
    """
    payload = bytes(value)[:0xFFFC]
    size = (length if length is not None else len(payload) + 3) & 0xFFFF
    return bytes([identifier & 0xFF]) + struct.pack(">H", size) + payload


def obex_name_header(name: str, utf16: bool = False) -> bytes:
    """A Name header, either UTF-16 (what phones expect) or raw bytes."""
    if utf16:
        return obex_header(0x01, name.encode("utf-16-be"))
    return obex_header(0x05, name.encode("utf-8", "replace"))


def obex_packet(opcode: int, headers: Sequence[bytes] = (), body: bytes = b"",
                max_size: int = 0xFFFF) -> bytes:
    """An OBEX packet: opcode, total length (big endian), then the headers and any body."""
    inner = b"".join(bytes(header) for header in headers)
    if body:
        inner += obex_header(0x48, bytes(body))
    length = 3 + len(inner)
    if length > max_size:                                       # the receiver's ceiling
        keep = max(0, max_size - 3 - 3)
        inner = inner[:keep]
        length = 3 + len(inner)
    return bytes([opcode & 0xFF]) + struct.pack(">H", length) + inner


def obex_connect(max_packet_size: int = 0xFFFF) -> bytes:
    """CONNECT: version 1.0, no flags, and the largest packet we will accept."""
    size = max(255, min(0xFFFF, int(max_packet_size)))
    return bytes([OBEX_CONNECT]) + struct.pack(">H", 7) + bytes([0x10, 0x00]) \
        + struct.pack(">H", size)


def obex_get(name: str, type_: str = "", utf16: bool = False) -> bytes:
    """GET with a Name header — how an OBEX file transfer asks for one object."""
    headers = [obex_name_header(name, utf16=utf16)]
    if type_:
        headers.append(obex_header(0x42, type_.encode("ascii", "replace")))
    return obex_packet(OBEX_GET, headers)


def obex_setpath(name: str = "", up: bool = False) -> bytes:
    """SETPATH: walk the object store — one level up, one named folder, or the root."""
    flags = 0x03 if up else (0x02 if name else 0x01)
    headers = [obex_name_header(name, utf16=False)] if name else []
    return obex_packet(OBEX_SETPATH, [bytes([0x00, flags])] + headers)


def obex_disconnect() -> bytes:
    """DISCONNECT: end the session politely, which is what a file transfer does last."""
    return obex_packet(OBEX_DISCONNECT)


def obex_response(code: int) -> str:
    """The name of an OBEX response code, or its hex form when it is not one we know."""
    return OBEX_RESPONSES.get(code & 0xFF, f"0x{code & 0xFF:02x}")


def parse_obex_packet(data: bytes) -> Dict[str, Any]:
    """Parse an OBEX request or response: opcode, final bit, headers and the body.

    Headers are returned in wire order with their identifier, decoded name and raw value.
    ``body`` accumulates every Body/End-of-Body header, so a multi-packet transfer is one
    call away from the vCard the phone just handed over.
    """
    out: Dict[str, Any] = {"opcode": 0, "final": False, "length": 0, "headers": [],
                           "body": b"", "name": "", "response": "", "request": "",
                           "setpath_flags": -1}
    if len(data) < 3:
        return out
    opcode = data[0]
    length = struct.unpack(">H", data[1:3])[0]
    out["opcode"] = opcode
    out["final"] = bool(opcode & 0x80)
    out["length"] = length
    if opcode in OBEX_REQUESTS:
        out["request"] = OBEX_REQUESTS[opcode]
    elif opcode in OBEX_RESPONSES:
        out["response"] = obex_response(opcode)
    offset = 3
    end = min(len(data), length if 3 <= length <= len(data) else len(data))
    # only the CONNECT request and its *success reply* carry the fixed version block:
    # the reply is exactly seven bytes, so a 0xA0 that answers a GET is all headers
    if end >= 7 and (opcode == OBEX_CONNECT or (opcode == 0xA0 and length == 7)):
        out["version"] = data[3]
        out["max_packet_size"] = struct.unpack(">H", data[5:7])[0]
        offset = 7
    if opcode == OBEX_SETPATH and end >= 5:                     # the flags block has no ID
        out["setpath_flags"] = data[3]
        offset = 5
    while offset + 2 < end:
        identifier = data[offset]
        size = int.from_bytes(data[offset + 1:offset + 3], "big")
        if size < 3 or offset + size > end:
            break
        value = data[offset + 3:offset + size]      # past the identifier and its length
        entry = {"id": identifier, "name": OBEX_HEADERS.get(identifier, f"0x{identifier:02x}"),
                 "value": value}
        if identifier == 0x01:
            entry["text"] = value.decode("utf-16-be", "replace")
            out["name"] = entry["text"]
        elif identifier in (0x05, 0x42, 0x44):
            entry["text"] = value.decode("utf-8", "replace")
            if identifier == 0x05:
                out["name"] = entry["text"]
        elif identifier in (0x48, 0x49):
            out["body"] += value
        elif identifier == 0xC3 and len(value) == 4:
            entry["number"] = int.from_bytes(value, "big")
        out["headers"].append(entry)
        offset += size
    return out


# --------------------------------------------------------------------------- #
# HID: a keyboard is an output device, and its output is keystrokes
# --------------------------------------------------------------------------- #

HID_SERVICE_UUID = 0x1812

#: the HID over GATT characteristics that matter to an injected keystroke
HID_CHARACTERISTICS = {
    0x2A4A: "HID Information", 0x2A4B: "Report Map", 0x2A4C: "HID Control Point",
    0x2A4D: "Report", 0x2A4E: "Protocol Mode", 0x2A22: "Boot Keyboard Input Report",
    0x2A32: "Boot Keyboard Output Report",
}

#: the canonical boot-protocol keyboard report descriptor: eight modifier bits, one
#: reserved byte, and six rollover keycodes.  A host that sees this descriptor believes
#: it is talking to a keyboard — which is the entire attack.
HID_KEYBOARD_REPORT_MAP = bytes([
    0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7,
    0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95, 0x01,
    0x75, 0x08, 0x81, 0x01, 0x95, 0x05, 0x75, 0x01, 0x05, 0x08, 0x19, 0x01,
    0x29, 0x05, 0x91, 0x02, 0x95, 0x01, 0x75, 0x03, 0x91, 0x01, 0x95, 0x06,
    0x75, 0x08, 0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00, 0x29, 0x65,
    0x81, 0x00, 0xC0,
])

#: modifier bits, in the order the descriptor declares them
HID_MODIFIERS = {"left ctrl": 0x01, "left shift": 0x02, "left alt": 0x04,
                 "left gui": 0x08, "right ctrl": 0x10, "right shift": 0x20,
                 "right alt": 0x40, "right gui": 0x80}

#: usage IDs for the keys an operator actually types.  The full set is 65 keys per the
#: descriptor; this is the subset a keystroke-injection run needs, named the way a
#: keyboard names them.
HID_KEYS: Dict[str, int] = {
    "none": 0x00, "rollover": 0x01, "enter": 0x28, "escape": 0x29, "backspace": 0x2A,
    "tab": 0x2B, "space": 0x2C, "minus": 0x2D, "equals": 0x2E, "left bracket": 0x2F,
    "right bracket": 0x30, "backslash": 0x31, "semicolon": 0x33, "quote": 0x34,
    "grave": 0x35, "comma": 0x36, "period": 0x37, "slash": 0x38, "caps lock": 0x39,
    "f1": 0x3A, "f2": 0x3B, "f3": 0x3C, "f4": 0x3D, "f5": 0x3E, "f6": 0x3F,
    "f7": 0x40, "f8": 0x41, "f9": 0x42, "f10": 0x43, "f11": 0x44, "f12": 0x45,
    "print screen": 0x46, "scroll lock": 0x47, "pause": 0x48, "insert": 0x49,
    "home": 0x4A, "page up": 0x4B, "delete": 0x4C, "end": 0x4D, "page down": 0x4E,
    "right arrow": 0x4F, "left arrow": 0x50, "down arrow": 0x51, "up arrow": 0x52,
    "num lock": 0x53, "menu": 0x65,
}
HID_KEYS.update({letter: 0x04 + index for index, letter in enumerate("abcdefghijklmnopqrstuvwxyz")})
HID_KEYS.update({digit: 0x1E + index for index, digit in enumerate("1234567890")})

#: characters that need a shift, mapped to the unshifted key that carries them
HID_SHIFTED = {"!": "1", "@": "2", "#": "3", "$": "4", "%": "5", "^": "6", "&": "7",
               "*": "8", "(": "9", ")": "0", "_": "minus", "+": "equals", "{": "left bracket",
               "}": "right bracket", "|": "backslash", ":": "semicolon", "\"": "quote",
               "~": "grave", "<": "comma", ">": "period", "?": "slash"}


def hid_key(name: str) -> int:
    """The usage ID for a named key, or 0x00 when the name is not one we know."""
    return HID_KEYS.get(name.lower().strip(), 0x00)


def hid_boot_report(modifiers: int = 0, keys: Sequence[int] = ()) -> bytes:
    """An eight-byte boot keyboard report: modifiers, reserved, six pressed keys."""
    codes = [int(key) & 0xFF for key in keys][:6]
    codes += [0x00] * (6 - len(codes))
    return bytes([modifiers & 0xFF, 0x00] + codes)


def hid_key_reports(text: str) -> List[bytes]:
    """Turn a string into the press/release report pairs a keyboard would send.

    Each keystroke becomes two reports — the key down, then all keys up — which is how a
    host sees a typing human rather than a one-off report that never releases.  Letters,
    digits, punctuation, spaces and the control characters (``\n`` is Enter, ``\t`` is
    Tab) are all typed; anything this keyboard has no key for is left out, and
    :func:`hid_type_plan` is where a caller finds out which ones those were.
    """
    presses, _untypable = hid_type_plan(text)
    reports: List[bytes] = []
    for modifiers, codes in presses:
        reports.append(hid_boot_report(modifiers, codes))
        reports.append(hid_boot_report(0, []))
    return reports


#: usage code -> the name the key has in :data:`HID_KEYS` (first name wins, so a code
#: with two spellings answers with the one the table was written with)
HID_USAGE_NAMES: Dict[int, str] = {}
for _key_name, _key_code in HID_KEYS.items():
    HID_USAGE_NAMES.setdefault(_key_code, _key_name)

#: what the named keys type without shift: the punctuation, the space bar and the keys
#: that send a control character rather than printing one
HID_NAMED_CHARS = {"minus": "-", "equals": "=", "left bracket": "[", "right bracket": "]",
                   "backslash": "\\", "semicolon": ";", "quote": "'", "grave": "`",
                   "comma": ",", "period": ".", "slash": "/", "space": " ",
                   "enter": "\n", "return": "\n", "tab": "\t", "escape": "\x1b",
                   "backspace": "\x08", "delete": "\x7f"}

#: the shift symbols, backwards: the key a shifted symbol is produced from
HID_UNSHIFTED = {name: symbol for symbol, name in HID_SHIFTED.items()}

#: every character a keyboard can type -> ``(key name, shift)``.  Built from the tables
#: above rather than written out, so the encoder and the decoder cannot drift apart: a
#: character that is typed is a character that decodes.
HID_TYPEABLE: Dict[str, Tuple[str, bool]] = {}
for _name, _character in HID_NAMED_CHARS.items():
    HID_TYPEABLE.setdefault(_character, (_name, False))
for _symbol, _key in HID_SHIFTED.items():
    HID_TYPEABLE.setdefault(_symbol, (_key, True))
for _letter in "abcdefghijklmnopqrstuvwxyz":
    HID_TYPEABLE[_letter] = (_letter, False)
    HID_TYPEABLE[_letter.upper()] = (_letter, True)
for _digit in "0123456789":
    HID_TYPEABLE.setdefault(_digit, (_digit, False))
# a carriage return is what a terminal sends where a person presses Enter
HID_TYPEABLE.setdefault("\r", ("enter", False))

#: what a named key types, for readers that want the old table by name
HID_KEY_TEXT = {name: character for name, character in HID_NAMED_CHARS.items()}

#: usage code -> the name the key has in :data:`HID_KEYS`#: usage code -> the name the key has in :data:`HID_KEYS` (first name wins, so a code
#: with two spellings answers with the one the table was written with)
HID_USAGE_NAMES: Dict[int, str] = {}
for _key_name, _key_code in HID_KEYS.items():
    HID_USAGE_NAMES.setdefault(_key_code, _key_name)

def hid_usage_name(code: int) -> str:
    """The name of a HID usage code, or ``""`` for one this build does not know."""
    return HID_USAGE_NAMES.get(int(code) & 0xFF, "")


def hid_report_text(name: str, shift: bool = False, ctrl: bool = False) -> str:
    """What one key types, with the modifiers applied: the decoder's whole job."""
    if not name:
        return ""
    if ctrl:                                   # a control chord is not text, and saying
        return ""                              # it is text is how an audit lies
    if len(name) == 1:
        if name.isalpha():
            return name.upper() if shift else name
        if name.isdigit():
            if shift:
                return HID_UNSHIFTED.get(name, name)
            return name
        return name
    character = HID_NAMED_CHARS.get(name)
    if character is None:
        return ""
    return HID_UNSHIFTED.get(name, character) if shift else character


def hid_type_plan(text: str) -> Tuple[List[Tuple[int, List[int]]], List[str]]:
    """The presses a string needs — and the characters this keyboard cannot type.

    A payload is a *command line*, not a word: an injected ``id`` that never presses Enter
    has typed nothing, and a ``|`` or a ``/`` that is silently dropped is worse than one
    that is reported as undeliverable.  So the plan is explicit: one entry per keystroke
    (the modifier bits and the usage codes to press together) and the list of characters
    that had no key at all.
    """
    presses: List[Tuple[int, List[int]]] = []
    untypable: List[str] = []
    for character in str(text):
        plan = HID_TYPEABLE.get(character)
        if plan is None:
            code = hid_key(character)                  # a named key passed as itself
            if not code:
                untypable.append(character)
                continue
            presses.append((0, [code]))
            continue
        name, shift = plan
        code = hid_key(name)
        if not code:
            untypable.append(character)
            continue
        presses.append((HID_MODIFIERS["left shift"] if shift else 0, [code]))
    return presses, untypable


def hid_decode_report(report: bytes) -> Dict[str, Any]:
    """Read a boot-keyboard report back into the keys it presses and the text it types.

    The report is the eight bytes the descriptor declares: modifier bits, a reserved
    byte, then six usage codes with ``0x00`` for "no key in this slot".  A keyboard
    releases a key by sending the same report with that code taken out, so the text is
    built from the *press* reports — and a decoder that concatenated every report would
    type everything twice, which is exactly what makes a decoded transcript untrustworthy
    if it is done carelessly.

    Ordering matters as much as decoding: a report that keeps a previous key in a slot
    while a new one arrives is a *chord* (ctrl+alt+del, or a key held under another), and
    a report that only removes keys is a release, not a keystroke.
    """
    data = bytes(report or b"")
    modifiers = data[0] if data else 0
    codes = [code for code in data[2:8] if code]
    names = [hid_usage_name(code) or f"0x{code:02x}" for code in codes]
    shift = bool(modifiers & (HID_MODIFIERS["left shift"] | HID_MODIFIERS["right shift"]))
    ctrl = bool(modifiers & (HID_MODIFIERS["left ctrl"] | HID_MODIFIERS["right ctrl"]))
    alt = bool(modifiers & (HID_MODIFIERS["left alt"] | HID_MODIFIERS["right alt"]))
    return {"modifiers": modifiers, "keys": names, "codes": codes,
            "count": 1 if codes else 0,
            "chord": len(codes) > 1, "ctrl": ctrl, "alt": alt,
            "text": "".join(hid_report_text(name, shift, ctrl) for name in names),
            "raw": data.hex()}


def hid_decode_stream(reports: Sequence[bytes]) -> Dict[str, Any]:
    """Decode a run of reports the way a host receives them: presses, not repeats.

    A keyboard that holds a key for 600 ms sends the same report several times; only the
    transition from "not pressed" to "pressed" is a keystroke.  This is the function a
    capture analysis and a simulated host both need, so both use it and neither can
    report a string that the other would not.
    """
    text = ""
    strokes: List[Dict[str, Any]] = []
    held: set = set()
    for report in reports:
        parsed = hid_decode_report(report)
        pressed = set(parsed["codes"])
        fresh = [code for code in parsed["codes"] if code not in held]
        held = pressed
        if not fresh:
            continue
        parsed["fresh"] = [hid_usage_name(code) or f"0x{code:02x}" for code in fresh]
        text += "".join(hid_report_text(name, parsed["keys"] and name in parsed["keys"]
                                        and bool(parsed["modifiers"] & 0x22), parsed["ctrl"])
                        for name in parsed["fresh"])
        strokes.append(parsed)
    return {"reports": len(reports), "strokes": strokes, "text": text}


def hid_gatt_table(start_handle: int = 0x0001) -> List[Dict[str, Any]]:
    """The attribute table a HID peripheral serves: services, characteristics, reports.

    The handle numbers are the ones a real HID-over-GATT keyboard uses, so a peer that
    enumerates this table over ATT sees a keyboard and subscribes to the input report it
    finds — which is the handle :func:`hid_input_report` addresses.
    """
    handle = start_handle
    rows: List[Dict[str, Any]] = []

    def add(kind: str, uuid: int, **extra: Any) -> int:
        nonlocal handle
        row = {"handle": handle, "kind": kind, "uuid": f"0x{uuid:04X}",
               "name": HID_CHARACTERISTICS.get(uuid, SERVICE_UUIDS.get(uuid, "")),
               "uuid_value": uuid}
        row.update(extra)
        rows.append(row)
        handle += 1
        return row["handle"]

    add("service", HID_SERVICE_UUID)
    add("characteristic", 0x2A4A, properties="read", value=bytes([0x01, 0x11, 0x00, 0x02]))
    add("characteristic", 0x2A4B, properties="read", value=HID_KEYBOARD_REPORT_MAP)
    add("characteristic", 0x2A4C, properties="write without response", value=b"\x00")
    add("characteristic", 0x2A4D, properties="read,notify", report_id=1, report_type=1,
        value=b"\x00" * 8)
    add("characteristic", 0x2A4E, properties="read,write without response", value=b"\x01")
    add("characteristic", 0x2A22, properties="read,notify", boot=True, value=b"\x00" * 8)
    add("characteristic", 0x2A32, properties="read,write,write without response", boot=True,
        value=b"\x00" * 8)
    return rows


def hid_input_report(report: bytes, handle: int = 0x0025) -> bytes:
    """An ATT Handle Value Notification carrying a keyboard report.

    ``handle`` defaults to the report characteristic :func:`hid_gatt_table` declares for
    the input report; the notification is what a subscribed host receives, and it is what
    a keystroke is, at the ATT layer.
    """
    body = struct.pack("<H", handle) + bytes(report)
    return l2cap_frame(0x0004, bytes([0x1B]) + body)          # ATT handle-value-notify


# --------------------------------------------------------------------------- #
# the classic profiles: the codecs the hijack wave speaks
# --------------------------------------------------------------------------- #
#
# A Bluetooth assessment that stops at L2CAP has read the first layer of a stack that
# has four more on top of it.  The profiles people actually use — music, the hands-free
# kit in the car, the phonebook, the SIM, the personal-area network — are their own
# protocols, and each one is a small, published frame layout.  They live here, next to
# the ATT and SMP codecs, so the same builder that talks to a device is the parser an
# analyst reads a capture with.

#: AVDTP signal identifiers (Audio/Video Distribution Transport Protocol, the protocol
#: under A2DP): a stream is discovered, configured and started with these, and the
#: *answer* to ``SetConfiguration``/``Start`` is what owning an audio link means
AVDTP_SIGNALS = {0x01: "Discover", 0x02: "GetCapabilities", 0x03: "SetConfiguration",
                 0x04: "GetConfiguration", 0x05: "Reconfigure", 0x06: "Open",
                 0x07: "Start", 0x08: "Close", 0x09: "Suspend", 0x0A: "Abort",
                 0x0B: "SecurityControl", 0x0C: "GetAllCapabilities", 0x0D: "DelayReport"}

#: the four message types the first octet of an AVDTP packet carries
AVDTP_MESSAGES = {0x00: "command", 0x01: "general reject", 0x02: "response accept",
                  0x03: "response reject"}

#: AVDTP service categories: what a GetCapabilities answer is made of
AVDTP_CATEGORIES = {0x01: "MediaTransport", 0x02: "Reporting", 0x03: "Recovery",
                    0x04: "ContentProtection", 0x05: "HeaderCompression",
                    0x06: "Multiplexing", 0x07: "MediaCodec"}

#: the codecs an A2DP stream can carry, by the media codec type byte
AVDTP_CODECS = {0x00: "SBC", 0x01: "MPEG-1/2 Audio", 0x02: "MPEG-2/4 AAC",
                0x04: "MPEG-D USAC", 0xFF: "vendor (aptX/LDAC)"}

#: AVRCP operations (Audio/Video Remote Control Profile over AVCTP)
AVRCP_OPERATIONS = {0x10: "GetCapabilities", 0x11: "ListPlayerApplicationSettingAttributes",
                    0x44: "Passthrough (AV/C button)",
                    0x12: "ListPlayerApplicationSettingValues",
                    0x13: "GetCurrentPlayerApplicationSettingValue",
                    0x14: "SetPlayerApplicationSettingValue", 0x20: "GetElementAttributes",
                    0x30: "GetPlayStatus", 0x31: "RegisterNotification",
                    0x40: "RequestContinuingResponse", 0x41: "AbortContinuingResponse",
                    0x50: "SetAbsoluteVolume"}

#: AVRCP *notifications*: a controller that registers for one is told when the player
#: changes — which is why registering is the act that takes the transport over
AVRCP_EVENTS = {0x01: "PlaybackStatusChanged", 0x02: "TrackChanged",
                0x03: "TrackReachedEnd", 0x04: "TrackReachedStart",
                0x05: "PlayPositionChanged", 0x06: "BattStatusChanged",
                0x07: "SystemStatusChanged", 0x08: "NowPlayingContentChanged",
                0x09: "AvailablePlayersChanged", 0x0A: "AddressedPlayerChanged",
                0x0B: "UidsChanged", 0x0C: "VolumeChanged", 0x0D: "VolumeChanged"}

#: AV/C passthrough operation ids — the remote-control buttons themselves
AVRCP_PASSTHROUGH = {0x44: "play", 0x45: "stop", 0x46: "pause", 0x4C: "forward",
                     0x4D: "rewind", 0x41: "volume up", 0x42: "volume down",
                     0x43: "mute", 0x48: "next track", 0x49: "previous track"}

#: AVCTP header: transaction label (4 bits), packet type (2), C/R (1), IPID (1)
def avctp_frame(payload: bytes, profile: int = 0x110E, tl: int = 0, cr: int = 0,
                packet: int = 0, ipid: int = 0) -> bytes:
    """An AVCTP frame: the transport AVRCP rides on.

    The first octet is the transaction label (four bits), the packet type (two), the
    C/R bit — 0 for a command and 1 for a response — and the IPID, which is 0 on the
    control channel and 1 on the browsing channel the two PSMs separate.  ``profile`` is
    ``0x110E`` for AVRCP itself and ``0x110C`` for the A2DP control channel, and AVCTP
    lengths the payload so a fragmented response is unambiguous.
    """
    header = bytes([((tl & 0x0F) << 4) | ((packet & 0x03) << 2) | ((cr & 0x01) << 1)
                    | (ipid & 0x01)])
    return header + struct.pack(">HH", profile & 0xFFFF, len(payload)) + bytes(payload)


def parse_avctp(data: bytes) -> Dict[str, Any]:
    """Read an AVCTP frame: who it is for, whether it is an answer, and the payload."""
    if len(data) < 5:
        return {"error": "short AVCTP frame", "length": len(data)}
    first = data[0]
    profile = (data[1] << 8) | data[2]
    size = int.from_bytes(data[3:5], "big")
    body = bytes(data[5:5 + size]) if size else bytes(data[5:])
    return {"tl": first >> 4, "packet_type": (first >> 2) & 0x03,
            "cr": (first >> 1) & 0x01, "ipid": first & 0x01,
            "profile": profile, "profile_name": "AVRCP" if profile == 0x110E else
            ("A2DP control" if profile == 0x110C else f"profile 0x{profile:04x}"),
            "length": size, "payload": body}


def avrcp_command(operation: int, parameters: bytes = b"") -> bytes:
    """An AVRCP command: the operation id, then its parameters."""
    return bytes([operation & 0xFF]) + bytes(parameters)


def avrcp_passthrough(operation: int, pressed: bool = True) -> bytes:
    """An AV/C passthrough — the ``play``/``pause``/``volume`` buttons themselves."""
    state = 0x00 if pressed else 0x80             # 0x00 pressed, 0x80 released
    return avrcp_command(0x44, bytes([operation & 0x7F, state]))


def avrcp_register(event: int, interval: int = 0, value: bytes = b"") -> bytes:
    """``RegisterNotification``: the call that makes the player report to us."""
    return avrcp_command(0x31, bytes([event & 0xFF]) + struct.pack(">I", interval & 0xFFFFFFFF)
                         + bytes(value))


def avrcp_set_absolute_volume(volume: int) -> bytes:
    """``SetAbsoluteVolume``: 0 quiet, 0x7F full — the register a controller can write."""
    return avrcp_command(0x50, bytes([volume & 0x7F]))


def parse_avrcp(payload: bytes, response: bool = False) -> Dict[str, Any]:
    """Read an AVRCP payload: the operation, and what its parameters mean.

    ``response=True`` says the frame is the player's answer rather than the controller's
    command, which matters because ``RegisterNotification`` carries the *interval* in a
    command and the *value* in a notification: the same four bytes, two meanings, and
    only the direction tells them apart.
    """
    if not payload:
        return {"error": "empty AVRCP payload"}
    operation = payload[0]
    out: Dict[str, Any] = {"operation": operation,
                           "name": AVRCP_OPERATIONS.get(operation,
                                                        f"operation 0x{operation:02x}"),
                           "parameters": bytes(payload[1:])}
    if operation == 0x44 and len(payload) >= 3:              # passthrough
        out["passthrough"] = AVRCP_PASSTHROUGH.get(payload[1] & 0x7F,
                                                   f"av/c 0x{payload[1]:02x}")
        out["pressed"] = not bool(payload[2] & 0x80)
    elif operation == 0x31 and len(payload) >= 2:            # a notification
        event = payload[1]
        out["event"] = event
        out["event_name"] = AVRCP_EVENTS.get(event, f"event 0x{event:02x}")
        if not response and len(payload) >= 6:
            out["interval_ms"] = int.from_bytes(payload[2:6], "big")
        elif response and event in (0x0C, 0x0D) and len(payload) >= 3:
            out["volume"] = payload[2] & 0x7F
        elif response and event == 0x01 and len(payload) >= 3:
            out["playback"] = {0x00: "stopped", 0x01: "playing", 0x02: "paused",
                               0x03: "forward seeking", 0x04: "reverse seeking"}.get(
                                   payload[2], f"0x{payload[2]:02x}")
        elif response and len(payload) >= 10:
            out["attribute"] = int.from_bytes(payload[2:10], "big")
        elif response and len(payload) >= 6:
            out["value"] = int.from_bytes(payload[2:6], "big")
    elif operation == 0x50 and len(payload) >= 2:
        out["volume"] = payload[1] & 0x7F
    elif operation == 0x20:
        out["attributes" if len(payload) < 8 else "elements"] = len(payload) - 1
    elif operation == 0x10 and len(payload) >= 3:
        out["company_id"] = payload[1:4].hex()
        out["company_name"] = "Bluetooth SIG" if payload[1:4] == b"\x00\x19\x58" else \
            payload[1:4].hex()
    elif operation == 0x30 and len(payload) >= 9:
        out["song_length_ms"] = int.from_bytes(payload[1:5], "big")
        out["song_position_ms"] = int.from_bytes(payload[5:9], "big")
        out["playback"] = {0x00: "stopped", 0x01: "playing", 0x02: "paused"}.get(
            payload[9] if len(payload) > 9 else 0, "?")
    return out


def avdtp_signal(signal: int, payload: bytes = b"", label: int = 0, message: int = 0x00,
                 packet: int = 0x00) -> bytes:
    """An AVDTP signalling packet: the framing A2DP's setup is made of."""
    return bytes([((label & 0x0F) << 4) | ((packet & 0x03) << 2) | (message & 0x03),
                  signal & 0xFF]) + bytes(payload)


def parse_avdtp(data: bytes) -> Dict[str, Any]:
    """Read an AVDTP packet: the signal, whether it is an accept, and its payload."""
    if len(data) < 2:
        return {"error": "short AVDTP packet", "length": len(data)}
    first = data[0]
    signal = data[1]
    out: Dict[str, Any] = {"label": first >> 4, "packet_type": (first >> 2) & 0x03,
                           "message": first & 0x03,
                           "message_name": AVDTP_MESSAGES.get(first & 0x03, "?"),
                           "signal": signal,
                           "signal_name": AVDTP_SIGNALS.get(signal, f"signal 0x{signal:02x}"),
                           "status": "accept" if (first & 0x03) == 0x02 else
                                     ("reject" if (first & 0x03) == 0x03 else "command"),
                           "payload": bytes(data[2:])}
    if signal == 0x01:                                   # Discover: a list of SEPs
        seps = []
        for index in range(0, len(data) - 2, 2):
            seid = data[2 + index] >> 2
            # the second byte of a SEP entry is media type (bits 7-4), TSEP (bits 3-2)
            # and reserved: TSEP says whether the endpoint plays or sends audio
            tsep = (data[3 + index] >> 2) & 0x03 if 3 + index < len(data) else 0
            seps.append({"seid": seid,
                         "media_type": "audio" if (3 + index < len(data)
                                                   and data[3 + index] >> 4 == 0) else "?",
                         "type": {0x00: "source", 0x01: "sink", 0x02: "source+sink"}.get(
                             tsep, f"0x{tsep:02x}"),
                         "in_use": bool((data[2 + index] >> 1) & 0x01)})
        out["seps"] = seps
    elif signal in (0x02, 0x0C) and len(data) >= 5:      # GetCapabilities answer
        out["categories"] = []
        offset = 2
        while offset + 1 < len(data):
            category = data[offset]
            size = data[offset + 1]
            block = bytes(data[offset + 2:offset + 2 + size])
            entry: Dict[str, Any] = {"category": category,
                                     "name": AVDTP_CATEGORIES.get(category, f"0x{category:02x}")}
            if category == 0x07 and len(block) >= 2:
                entry["media_type"] = "audio" if block[0] >> 4 == 0 else \
                    f"0x{block[0] >> 4:x}"
                entry["codec"] = AVDTP_CODECS.get(block[1], f"0x{block[1]:02x}")
                if len(block) >= 4:
                    entry["sampling_khz"] = {0x10: 44.1, 0x20: 48.0, 0x40: 32.0}.get(
                        block[2] & 0xF0, 0)
                    entry["channel_mode"] = {0x01: "mono", 0x02: "dual channel",
                                             0x04: "stereo", 0x08: "joint stereo"}.get(
                                                 block[2] & 0x0F, "")
                if len(block) >= 5:
                    entry["bitpool_min"] = block[4]
                    entry["bitpool_max"] = block[5] if len(block) > 5 else 0
            elif category == 0x01 and block:
                entry["data"] = block.hex()
            out["categories"].append(entry)
            offset += 2 + size
    elif signal in (0x03, 0x06, 0x07, 0x09) and len(data) >= 3:
        out["seid"] = data[2] >> 2
    return out


def avdtp_discover(label: int = 0) -> bytes:
    """The first AVDTP command an audio client sends: what streams does this device have."""
    return avdtp_signal(0x01, b"", label=label)


def avdtp_get_capabilities(seid: int, label: int = 1) -> bytes:
    """Ask one stream endpoint what it can carry (SBC, AAC, aptX)."""
    return avdtp_signal(0x02, bytes([(seid & 0x3F) << 2]), label=label)


def avdtp_set_configuration(seid: int, codec: int = 0x00, label: int = 2) -> bytes:
    """Configure a stream: the command that decides the codec a session will use."""
    block = bytes([0x3F, 0x07, 0x00, 0x00, 0x00]) + bytes([0x00, codec, 0x21, 0x02, 0x35,
                                                           0x2C, 0x2C])
    return avdtp_signal(0x03, bytes([(0x02 & 0x3F) << 2, (seid & 0x3F) << 2])
                        + bytes([0x07, len(block)]) + block, label=label)


def avdtp_simple(signal: int, seid: int, label: int = 3) -> bytes:
    """``Open``/``Start``/``Suspend``/``Close``: the stream controls, one call each."""
    return avdtp_signal(signal, bytes([(0x02 & 0x3F) << 2, (seid & 0x3F) << 2]), label=label)


#: BNEP (Bluetooth Network Encapsulation Protocol) — how a Bluetooth device bridges
#: another network to us.  A personal-area network is the phone's LAN, and joining one is
#: the step that turns a headset into a network foothold
BNEP_TYPES = {0x00: "general ethernet", 0x01: "control"}
BNEP_CONTROLS = {0x01: "SetupConnectionReq", 0x02: "SetupConnectionRsp",
                 0x03: "FilterSetupReq", 0x04: "FilterSetupRsp",
                 0x05: "FilterChangeReq", 0x06: "FilterChangeRsp"}
BNEP_UUIDS = {0x0001: "PANU", 0x0002: "GN", 0x0003: "NAP", 0x0004: "PANU/GN/NAP"}


def bnep_control(control: int, payload: bytes = b"") -> bytes:
    """A BNEP control frame: how a personal-area network is set up."""
    return bytes([0x01, control & 0xFF]) + bytes(payload)


def bnep_setup(destination_uuid: int = 0x0001, source_uuid: int = 0x0003,
               dst: bytes = b"\x00" * 6, src: bytes = b"\x00" * 6) -> bytes:
    """``SetupConnectionReq``/``Rsp``: destination uuid, source uuid, result."""
    return (bytes([0x01, 0x01]) + struct.pack(">H", destination_uuid) + dst
            + struct.pack(">H", source_uuid) + src)


def ethernet_frame(dst: str = "ff:ff:ff:ff:ff:ff", src: str = "02:00:00:00:00:01",
                   ethertype: int = 0x0806, payload: bytes = b"") -> bytes:
    """A plain Ethernet frame: what a BNEP general frame carries."""
    return mac_bytes(dst) + mac_bytes(src) + struct.pack(">H", ethertype) + bytes(payload)


def bnep_frame(frame: bytes) -> bytes:
    """Wrap an Ethernet frame in a BNEP general frame."""
    return bytes([0x00]) + bytes(frame)


def parse_bnep(data: bytes) -> Dict[str, Any]:
    """Read a BNEP frame: a setup, a filter, or an Ethernet frame with a header."""
    if not data:
        return {"error": "empty BNEP frame"}
    kind = data[0]
    out: Dict[str, Any] = {"type": kind, "type_name": BNEP_TYPES.get(kind, f"0x{kind:02x}"),
                           "payload": bytes(data[1:])}
    if kind == 0x01 and len(data) >= 2:
        control = data[1]
        out["control"] = control
        out["control_name"] = BNEP_CONTROLS.get(control, f"0x{control:02x}")
        if len(data) >= 12:
            destination = (data[2] << 8) | data[3]
            source = (data[10] << 8) | data[11]
            out["destination_uuid"] = destination
            out["destination"] = BNEP_UUIDS.get(destination, f"0x{destination:04x}")
            out["source_uuid"] = source
            out["source"] = BNEP_UUIDS.get(source, f"0x{source:04x}")
            if len(data) >= 14:
                out["result"] = int.from_bytes(data[12:14], "big")
    elif kind == 0x00 and len(data) >= 15:
        out["destination"] = mac_text(data[1:7]).upper()
        out["source"] = mac_text(data[7:13]).upper()
        out["ethertype"] = int.from_bytes(data[13:15], "big")
        out["ethernet_payload"] = bytes(data[15:])
        out["protocol"] = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6"}.get(
            out["ethertype"], f"0x{out['ethertype']:04x}")
    return out


#: HIDP (HID Profile) transactions — the classic HID channel, where the reports of a
#: keyboard or a mouse travel once the host has opened the interrupt channel
HIDP_TRANSACTIONS = {0x0: "handshake", 0x1: "hid control", 0x4: "get report",
                     0x5: "set report", 0x6: "get protocol", 0x7: "set protocol",
                     0x8: "get idle", 0x9: "set idle", 0xA: "data", 0xB: "data (control)"}
HIDP_PARAMETERS = {0x0: "other", 0x1: "input", 0x2: "output", 0x3: "feature"}
HIDP_HANDSHAKES = {0x00: "successful", 0x01: "not ready", 0x02: "invalid report id",
                   0x03: "unsupported request", 0x04: "invalid parameter",
                   0x0E: "unknown", 0x0F: "fatal"}


def hidp_frame(transaction: int, parameter: int = 0, payload: bytes = b"") -> bytes:
    """A HIDP packet: the transaction nibble, the parameter nibble, then the body."""
    return bytes([((transaction & 0x0F) << 4) | (parameter & 0x0F)]) + bytes(payload)


def hidp_handshake(result: int = 0x00) -> bytes:
    """The answer to a HIDP request: ``0x00`` is "successful"."""
    return hidp_frame(0x00, 0x00, bytes([result & 0xFF]))


def parse_hidp(data: bytes) -> Dict[str, Any]:
    """Read a HIDP packet: which transaction, and whether it was answered."""
    if not data:
        return {"error": "empty HIDP packet"}
    transaction = data[0] >> 4
    parameter = data[0] & 0x0F
    out: Dict[str, Any] = {"transaction": transaction,
                           "transaction_name": HIDP_TRANSACTIONS.get(
                               transaction, f"0x{transaction:x}"),
                           "parameter": parameter,
                           "parameter_name": HIDP_PARAMETERS.get(parameter,
                                                                 f"0x{parameter:x}"),
                           "payload": bytes(data[1:])}
    if transaction == 0x00 and len(data) >= 2:
        out["result"] = data[1]
        out["result_name"] = HIDP_HANDSHAKES.get(data[1], f"0x{data[1]:02x}")
        out["accepted"] = data[1] == 0x00
    if transaction in (0x0A, 0x0B) and len(data) >= 2:
        # a data packet is a report: the first byte of the body is the report the
        # keyboard's report map declared
        out["report"] = bytes(data[2:]) if len(data) > 2 else bytes(data[1:])
        out["report_id"] = data[1] if transaction == 0x0B else 0
    return out


#: SAP (SIM Access Profile) messages — the profile that hands a car kit the phone's
#: subscriber identity, and one of the most consequential things a Bluetooth link can do
SAP_MESSAGES = {0x00: "ConnectReq", 0x01: "ConnectRsp", 0x02: "DisconnectReq",
                0x03: "DisconnectRsp", 0x04: "TransferAPDUReq", 0x05: "TransferAPDURsp",
                0x06: "TransferATRReq", 0x07: "TransferATRRsp",
                0x08: "PowerSimOffReq", 0x09: "PowerSimOffRsp", 0x0A: "PowerSimOnReq",
                0x0B: "PowerSimOnRsp", 0x0C: "ResetSimReq", 0x0D: "ResetSimRsp",
                0x0E: "TransferCardReaderStatusReq", 0x0F: "TransferCardReaderStatusRsp",
                0x10: "SetTransportProtocolReq", 0x11: "SetTransportProtocolRsp",
                0x12: "StatusInd"}
SAP_PARAMETERS = {0x01: "MaxMsgSize", 0x02: "ConnectionStatus", 0x03: "ResultCode",
                  0x04: "StatusChange", 0x05: "TransportProtocol", 0x06: "CommandAPDU",
                  0x07: "ResponseAPDU", 0x08: "ATR", 0x09: "CardReaderStatus",
                  0x0A: "SubscriberNumber"}


def sap_message(message: int, parameters: bytes = b"") -> bytes:
    """A SAP message: the message id, one parameter, and its length-prefixed value."""
    return bytes([message & 0xFF]) + bytes(parameters)


def sap_parameter(identifier: int, value: bytes) -> bytes:
    """One SAP parameter: ``id``, ``length``, then the value."""
    return bytes([identifier & 0xFF, len(value) & 0xFF]) + bytes(value)


def ef_imsi(imsi: str) -> bytes:
    """Encode an IMSI the way ``EF_IMSI`` holds it: the length byte, then the digits,
    each pair swapped, with the digit count as the first nibble."""
    digits = "".join(character for character in str(imsi) if character.isdigit())
    body = f"{len(digits):x}" + digits
    if len(body) % 2:
        body += "f"
    swapped = "".join(body[index + 1] + body[index] for index in range(0, len(body), 2))
    return bytes([len(swapped) // 2]) + bytes.fromhex(swapped)


def parse_sap(data: bytes) -> Dict[str, Any]:
    """Read a SAP message, parameter by parameter."""
    if not data:
        return {"error": "empty SAP message"}
    out: Dict[str, Any] = {"message": data[0],
                           "message_name": SAP_MESSAGES.get(data[0], f"0x{data[0]:02x}"),
                           "parameters": []}
    offset = 1
    while offset + 1 < len(data):
        identifier = data[offset]
        size = data[offset + 1]
        value = bytes(data[offset + 2:offset + 2 + size])
        out["parameters"].append({"id": identifier,
                                  "name": SAP_PARAMETERS.get(identifier,
                                                             f"0x{identifier:02x}"),
                                  "value": value})
        if identifier == 0x08:
            out["atr"] = value.hex()
        elif identifier == 0x0A:
            out["subscriber_number"] = value.decode("ascii", "replace")
        elif identifier == 0x07:
            out["apdu_response"] = value.hex()
        elif identifier == 0x06:
            out["apdu_command"] = value.hex()
        elif identifier == 0x03:
            out["result_code"] = value.hex()
        offset += 2 + size
    return out


#: the APDU status words a SIM answers with, and what they mean in a report
APDU_STATUS = {0x9000: "success", 0x9F1B: "file selected (1B bytes)",
               0x9F0F: "file selected (0F bytes)", 0x6A82: "file not found",
               0x6982: "security status not satisfied", 0x6D00: "instruction not supported"}


def apdu_select(file_id: int) -> bytes:
    """``SELECT FILE`` — the first command anyone sends a SIM."""
    return b"\xA0\xA4\x00\x00\x02" + struct.pack(">H", file_id & 0xFFFF)


def apdu_read_binary(length: int = 16, offset: int = 0) -> bytes:
    """``READ BINARY`` — how the contents of a selected file come back."""
    return b"\xA0\xB0\x00" + bytes([offset & 0xFF]) + bytes([length & 0xFF])


def parse_apdu(data: bytes) -> Dict[str, Any]:
    """Read an APDU response: the body, and the two status bytes at the end."""
    if len(data) < 2:
        return {"error": "short APDU response", "data": data.hex()}
    status = int.from_bytes(data[-2:], "big")
    body = bytes(data[:-2])
    return {"status": status, "status_text": APDU_STATUS.get(status, f"0x{status:04x}"),
            "body": body, "body_hex": body.hex(),
            "success": status in (0x9000, 0x9F1B, 0x9F0F) or (status >> 8) == 0x9F}


#: the file identifiers on a SIM, in the order an identity read walks them
SIM_FILES = {0x3F00: "MF (master file)", 0x7F20: "DF_GSM (GSM directory)",
             0x6F07: "EF_IMSI (subscriber identity)",
             0x6F46: "EF_SPN (service provider name)",
             0x6FAD: "EF_AD (administrative data)",
             0x6F7E: "EF_LOCI (location information)",
             0x6FB7: "EF_ICCID (card serial number)",
             0x6F20: "EF_Kc (ciphering key)"}


def imsi_from_ef_imsi(data: bytes) -> str:
    """Decode the subscriber identity out of ``EF_IMSI``.

    The file is nibble-swapped, and its first nibble is the number of digits that
    follow — so the identity is the second nibble onwards, ``length`` digits long.  This
    is the value a SIM access profile hands to a car kit, and reading it off the air is
    the finding: an IMSI identifies a subscriber for as long as the SIM exists.
    """
    if len(data) < 2:
        return ""
    digits = "".join(f"{byte & 0x0F:x}{byte >> 4:x}" for byte in bytes(data[:9])[1:])
    if not digits:
        return ""
    count = int(digits[0], 16)
    if count == 0 or count > len(digits) - 1:
        count = len(digits) - 1
    return digits[1:1 + count]


def iccid_from_ef_iccid(data: bytes) -> str:
    """Decode a card serial number (``EF_ICCID``): also nibble-swapped, also permanent."""
    digits = "".join(f"{byte & 0x0F:x}{byte >> 4:x}" for byte in bytes(data))
    return digits.replace("F", "").replace("f", "")
