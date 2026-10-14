"""A simulated floor of Bluetooth devices, so the Bluetooth attacks have a radio.

Wi-Fi has :mod:`wifipilot.demo` — a fake neighbourhood whose access points react to a
deauthentication the way real ones do.  The IT edition has :mod:`wifipilot.itsim` — a
segment of hosts that answer ONVIF, Modbus, Redis and SMB with the same bytes a real
device would, according to a *profile* that says whether the installer ever changed the
password.  This module is the third one: the Bluetooth editions' airspace.

It is a simulator in two halves, because Bluetooth has two halves and the attacks live in
both:

* **The airspace.**  :class:`VirtualBle` holds a table of :class:`BleDevice` records —
  beacons, trackers, watches, medical peripherals, locks, HID devices, hands-free units,
  industrial sensors, and the phones of the people carrying them.  Each one advertises
  its real AD structures (built with the same builders in :mod:`wifipilot.bt` that the
  decoders parse), some of them rotate their address, some name themselves only in a scan
  response, and each one has a *profile* that decides whether it can be paired with
  without a human, whether its GATT server answers before authentication, whether its
  attribute exchange is writeable, and whether its stack survives a malformed PDU.  The
  offline audits read the capture :meth:`VirtualBle.capture` writes; the on-air attacks
  talk to the same devices over the simulated controller.

* **The controller.**  :class:`VirtualController` answers HCI commands the way a real
  controller does — a Command Complete for the advertising and scanning commands, LE
  Meta events carrying advertising *reports* for a scan, an Inquiry Result for the classic
  inquiry, a Connection Complete when a link is created — and answers the ACL data the
  attacks send with the peer's own L2CAP, ATT, SMP, SDP, OBEX and RFCOMM replies.  The
  output is H4 packets built by hand, so the toolkit's own parsers
  (:func:`wifipilot.bt.parse_hci_event`, :func:`wifipilot.bt.parse_att`,
  :func:`wifipilot.bt.parse_obex_packet`, ...) read the simulation end to end: a demo run
  is a *conversation*, not a description of one.

Two things keep the simulator honest.  First, nothing is unconditional: every answer is
read out of the target's profile, so ``bt_knob`` finds a one-byte key on the device whose
profile says its key is one byte and reports a clean link on the one that says otherwise,
``bt_bluesnarf`` reads vCards off the phone that leaves its object store open and gets
``0xC4 not found`` from the one that does not, and ``bt_blueborne`` reports a stack that
stopped answering only because the profile says that stack falls over.  Second, the
simulator is deterministic: :func:`build_ble` takes a seed and a fresh
:class:`VirtualBle` is produced on demand, so a demo run and a test run see the same
floor — addresses, names, channels, weak profiles and all.
"""

from __future__ import annotations

import hashlib
import random
import struct
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from . import bt

__all__ = ["BleDevice", "VirtualBle", "VirtualController", "DemoHciSocket",
           "DemoRfcommSocket", "PROFILES", "WEAKNESS_ORDER", "DEVICE_TABLE", "build_ble",
           "ble_catalog", "profile_rank", "devices_by_weakness", "choose_target",
           "controller_socket", "rfcomm_socket", "ble", "reset_ble", "summary",
           "write_capture", "LINK_ROLES"]

# --------------------------------------------------------------------------- #
# what a device's posture is
# --------------------------------------------------------------------------- #

#: Every device gets one of these.  A profile is the answer to "how does this thing
#: behave when somebody it does not know talks to it", and each flag is read by the
#: controller (or by a responder) rather than merely described: ``secure_connections``
#: decides what a pairing attempt returns, ``key_size`` is the number ``bt_knob`` reports,
#: ``gatt_write`` is whether the vendor characteristic takes a write from a stranger, and
#: ``fragile`` names the battery whose malformed PDU takes the stack down.  A flag that
#: nothing read would be a comment; these are all wired.
PROFILES: Dict[str, Dict[str, Any]] = {
    "wide_open": {
        "secure_connections": False, "mitm": False, "bonding": False, "key_size": 7,
        "io": "no input no output", "just_works": True, "pairing": False,
        "gatt_write": True, "gatt_before_auth": True, "obex": False, "at": False,
        "hid": False, "fragile": "", "link_key": False,
        "note": "no pairing at all: the attribute table, the object store and the AT "
                "channel answer anybody, and the link key is whatever the peer says"},
    "open_gatt": {
        "secure_connections": False, "mitm": False, "bonding": True, "key_size": 7,
        "io": "no input no output", "just_works": True, "pairing": True,
        "gatt_write": True, "gatt_before_auth": True, "obex": False, "at": False,
        "hid": False, "fragile": "", "link_key": True,
        "note": "Just Works pairing, and the vendor characteristic is writeable without "
                "authentication: the session is not bound to the key"},
    "hid_trusting": {
        "secure_connections": False, "mitm": False, "bonding": True, "key_size": 7,
        "io": "no input no output", "just_works": True, "pairing": True,
        "gatt_write": False, "gatt_before_auth": True, "obex": False, "at": False,
        "hid": True, "fragile": "", "link_key": True,
        "note": "accepts HID input reports from a keyboard it paired with using Just "
                "Works: nothing about the host asks the human whether it should"},
    "fragile_stack": {
        "secure_connections": False, "mitm": False, "bonding": True, "key_size": 7,
        "io": "keyboard only", "just_works": True, "pairing": True,
        "gatt_write": False, "gatt_before_auth": False, "obex": False, "at": False,
        "hid": False, "fragile": "l2cap,sdp,ll", "link_key": True,
        "note": "a stack from before the advisories: a malformed L2CAP configuration, an "
                "oversized L2CAP echo or a bad link-layer PDU stops it"},
    "knober": {
        "secure_connections": False, "mitm": False, "bonding": True, "key_size": 1,
        "io": "display yes/no", "just_works": False, "pairing": True,
        "gatt_write": False, "gatt_before_auth": False, "obex": False, "at": False,
        "hid": False, "fragile": "", "link_key": True,
        "note": "CVE-2019-9506: the controllers negotiate a one-byte key, so the whole "
                "key space fits in one captured exchange"},
    "blesa": {
        "secure_connections": False, "mitm": False, "bonding": True, "key_size": 7,
        "io": "no input no output", "just_works": True, "pairing": True,
        "gatt_write": True, "gatt_before_auth": True, "obex": False, "at": False,
        "hid": False, "fragile": "", "link_key": True,
        "note": "accepts GATT work before the session is authenticated: the reconnect "
                "path never binds the attribute table to the bond"},
    "legacy_push": {
        "secure_connections": False, "mitm": False, "bonding": True, "key_size": 7,
        "io": "no input no output", "just_works": True, "pairing": True,
        "gatt_write": False, "gatt_before_auth": False, "obex": True, "at": True,
        "hid": False, "fragile": "", "link_key": True,
        "note": "an old handset: OBEX and the AT channel answer without a bond, and the "
                "pairing it does offer is legacy"},
    "hardened": {
        "secure_connections": True, "mitm": True, "bonding": True, "key_size": 16,
        "io": "display yes/no", "just_works": False, "pairing": True,
        "gatt_write": False, "gatt_before_auth": False, "obex": False, "at": False,
        "hid": False, "fragile": "", "link_key": True,
        "note": "patched and configured: Secure Connections with MITM protection, "
                "sixteen-byte keys, no unauthenticated attribute work, no open store"},
}

#: Which profile an attack should meet first.  The order is the difference between a run
#: that finds the misconfigurations and a run that collects refusals: the devices that
#: answer before they ask questions come first, then the ones with a small key or a
#: fragile stack, and a hardened device — which is still useful, as the negative control —
#: comes last.
WEAKNESS_ORDER: Tuple[str, ...] = ("wide_open", "open_gatt", "hid_trusting", "fragile_stack",
                                   "knober", "blesa", "legacy_push", "hardened")


def profile_rank(name: str) -> int:
    """The position of a profile in the sweep order (unknown profiles go last)."""
    return WEAKNESS_ORDER.index(name) if name in WEAKNESS_ORDER else len(WEAKNESS_ORDER)


def devices_by_weakness(devices: Iterable["BleDevice"]) -> List["BleDevice"]:
    """Sort devices weakest-profile-first, then closest-first: the order a run walks them.

    The profile decides the order, because a device that answers before it asks questions
    is the one a run should meet first; signal strength breaks the tie, because an attack
    that has to open a link has a better chance on the device in the next room than on the
    one on the far side of the building.
    """
    return sorted(devices, key=lambda device: (profile_rank(device.profile),
                                               -int(device.rssi), device.address))


#: what an attack needs from a device before it is worth aiming at.  ``bt_*`` attacks
#: name a role (see :func:`choose_target`), and the role is what makes a demo run meet a
#: device that *can* answer the question instead of the first address in the table.
LINK_ROLES: Dict[str, str] = {
    "le": "any advertising LE device",
    "bredr": "a classic BR/EDR device that answers inquiry",
    "l2cap": "a connectable device with a signalling channel",
    "gatt": "a GATT server",
    "smp": "a device that will pair",
    "sdp": "a device with SDP records",
    "rfcomm": "a device with a serial port profile",
    "at": "a hands-free unit with an AT command channel",
    "obex": "a device with an object exchange store",
    "hid": "a HID device",
    "fragile": "a device whose stack is known to fall over",
    "tracker": "an item tracker",
    "beacon": "a beacon",
}


# --------------------------------------------------------------------------- #
# one device
# --------------------------------------------------------------------------- #

#: the GATT services a profile can be given without spelling out every attribute.  Each
#: entry is ``(uuid, [(characteristic uuid, name, properties), ...])`` and the handles are
#: assigned in order from 0x0001 up, exactly as a peripheral numbers its attribute table.
GATT_LIBRARY: Dict[str, Tuple[int, Tuple[Tuple[int, str, str], ...]]] = {
    "device_info": (0x180A, ((0x2A29, "Manufacturer Name", "read"),
                             (0x2A24, "Model Number", "read"),
                             (0x2A26, "Firmware Revision", "read"),
                             (0x2A25, "Serial Number", "read"))),
    "battery": (0x180F, ((0x2A19, "Battery Level", "read,notify"),)),
    "heart_rate": (0x180D, ((0x2A37, "Heart Rate Measurement", "notify"),
                            (0x2A38, "Body Sensor Location", "read"))),
    "blood_pressure": (0x1810, ((0x2A35, "Blood Pressure Measurement", "indicate"),
                                (0x2A49, "Blood Pressure Feature", "read"))),
    "thermometer": (0x1809, ((0x2A1C, "Temperature Measurement", "indicate"),
                             (0x2A1D, "Temperature Type", "read"))),
    "glucose": (0x1808, ((0x2A18, "Glucose Measurement", "notify"),
                         (0x2A34, "Glucose Feature", "read"))),
    "fitness": (0x1814, ((0x2A53, "RSC Measurement", "notify"),)),
    "automation": (0x1815, ((0x2A56, "Digital", "read,write"),
                            (0x2A58, "Analog", "read"))),
    "hid": (0x1812, ((0x2A4A, "HID Information", "read"),
                     (0x2A4B, "Report Map", "read"),
                     (0x2A4C, "HID Control Point", "write without response"),
                     (0x2A4D, "Report", "read,notify"))),
    "vendor_lock": (0xFEE7, ((0xFEE8, "Lock State", "read,notify"),
                             (0xFEE9, "Lock Control", "write"),
                             (0xFEEA, "Admin Key", "write"))),
    "vendor_scooter": (0xFEED, ((0xFEEE, "Speed Limit", "read,write"),
                                (0xFEEF, "Motor Enable", "write"))),
    "vendor_plc": (0xFE30, ((0xFE31, "Process Value", "read,notify"),
                            (0xFE32, "Setpoint", "write"),
                            (0xFE33, "Calibration", "write"))),
    "vendor_glucose": (0xFEF0, ((0xFEF1, "Calibration Data", "read,write"),
                                (0xFEF2, "Recorder", "notify"))),
}


@dataclass
class BleDevice:
    """One device of the simulated floor, and everything it will say about itself."""

    address: str
    name: str = ""
    company: str = ""
    company_id: int = 0xFFFF
    model: str = ""
    device: str = "unknown"                 # a device-class label: headset, tracker, ...
    kind: str = "le"                        # le, bredr, dual
    profile: str = "hardened"
    class_of_device: int = 0                # BR/EDR class, for an inquiry
    appearance: int = 0
    tx_power: int = -59
    rssi: int = -60
    interval_ms: float = 500.0
    channel: int = 37
    connectable: bool = True
    bondable: bool = True
    address_type: int = 0                   # 0 public, 1 random
    rotate: bool = False                    # a resolvable private address per report
    firmware: str = ""
    services: Tuple[int, ...] = ()          # advertised service UUIDs
    manufacturer_data: bytes = b""
    tracker: str = ""                       # the tracker signature this device carries
    beacon: str = ""                        # "", ibeacon, eddystone-url, eddystone-uid
    beacon_args: Tuple[Any, ...] = ()
    scan_name: bool = False                 # names itself only in a scan response
    gatt: Tuple[str, ...] = ()              # GATT_LIBRARY keys this device serves
    sdp: Tuple[int, ...] = ()               # SDP service UUID16s
    channels: Tuple[int, ...] = ()          # RFCOMM channels
    at_name: str = ""                       # what the AT engine answers with
    notes: str = ""
    crashes: int = 0                        # times a malformed PDU took this stack down

    # -- the profile --------------------------------------------------------- #
    @property
    def flags(self) -> Dict[str, Any]:
        return PROFILES.get(self.profile, PROFILES["hardened"])

    def weakness(self, key: str, default: Any = None) -> Any:
        return self.flags.get(key, default)

    def weaknesses(self) -> List[str]:
        """What is wrong with this device, in the words a report would use."""
        out: List[str] = []
        flags = self.flags
        if not flags.get("pairing"):
            out.append("no pairing: the attribute table answers strangers")
        if not flags.get("secure_connections"):
            out.append("legacy pairing (no Secure Connections)")
        if not flags.get("mitm"):
            out.append("no man-in-the-middle protection (Just Works)")
        if int(flags.get("key_size", 16)) <= 2:
            out.append(f"encryption key of {flags.get('key_size')} byte(s) (KNOB)")
        if flags.get("gatt_write"):
            out.append("a writeable vendor characteristic without authentication")
        if flags.get("gatt_before_auth"):
            out.append("GATT work accepted before authentication (BLESA)")
        if flags.get("obex"):
            out.append("object exchange store reachable without a bond")
        if flags.get("at"):
            out.append("an AT command channel on RFCOMM")
        if flags.get("hid"):
            out.append("accepts HID input reports from a Just Works keyboard")
        if flags.get("fragile"):
            out.append(f"stack known to fall over: {flags['fragile']}")
        if not out:
            out.append("nothing known: Secure Connections with MITM, no open service")
        return out

    # -- the advertisement --------------------------------------------------- #
    def structures(self) -> List[Tuple[int, bytes]]:
        """The advertising data, built with the same builders the decoder parses."""
        out: List[Tuple[int, bytes]] = [bt.ad_flags(le_general=True, br_edr=self.kind != "le")]
        if self.beacon == "ibeacon":
            uuid_text, major, minor = (list(self.beacon_args) + [1, 1])[:3]
            out.append(bt.ibeacon(str(uuid_text), int(major), int(minor), self.tx_power))
        elif self.beacon == "eddystone-url":
            url, scheme = (list(self.beacon_args) + ["", 0x03])[:2]
            out.append(bt.ad_service_uuids([0xFEAA]))
            out.append(bt.eddystone_url(str(url), self.tx_power, scheme=int(scheme)))
        elif self.beacon == "eddystone-uid":
            namespace, instance = (list(self.beacon_args) + ["00" * 10, "00" * 6])[:2]
            out.append(bt.ad_service_uuids([0xFEAA]))
            out.append(bt.eddystone_uid(bytes.fromhex(str(namespace)),
                                        bytes.fromhex(str(instance)), self.tx_power))
        if self.manufacturer_data and self.company_id != 0xFFFF:
            out.append(bt.ad_manufacturer(self.company_id, self.manufacturer_data))
        if self.name and not self.scan_name:
            out.append(bt.ad_name(self.name))
        if self.services:
            out.append(bt.ad_service_uuids(list(self.services)))
        if self.appearance:
            out.append(bt.ad_structure(0x19, struct.pack("<H", self.appearance)))
        out.append(bt.ad_tx_power(self.tx_power))
        return out

    def scan_structures(self) -> List[Tuple[int, bytes]]:
        """What the device answers an active scan with (its name, if it is shy)."""
        if not self.scan_name or not self.name:
            return []
        return [bt.ad_flags(), bt.ad_name(self.name)]

    def ad_payload(self) -> bytes:
        return bt.adv_payload(*self.structures())

    def pdu_type(self) -> int:
        """Which legacy advertising PDU this device sends.

        A connectable device advertises ``ADV_IND`` (0x00); one that only answers names
        sends ``ADV_SCAN_IND`` (0x06); a pure broadcaster — a beacon, or a tracker that
        will not be talked to — sends ``ADV_NONCONN_IND`` (0x02).  ``0x03`` is *SCAN_REQ*,
        which is what a scanner sends, and a device that advertised one would look to the
        decoder like an empty request from ``00:00:00:00:00:00``.
        """
        if self.connectable:
            return 0x00
        return 0x06 if self.scan_name else 0x02

    def report(self, address: str = "", pdu: bytes = b"", scan: bool = False,
               channel: int = 0, rssi: Optional[int] = None) -> Dict[str, Any]:
        """One advertising report, shaped the way the toolkit's scan decoder returns them."""
        payload = pdu or bt.adv_pdu(0x04 if scan else self.pdu_type(),
                                    address or self.address, self.ad_payload())
        out: Dict[str, Any] = {"address": address or self.address,
                               "payload": bt.adv_payload(*(self.scan_structures() if scan
                                                           else self.structures())),
                               "address_type": self.address_type,
                               "address_type_text": "random" if self.address_type & 1 else "public",
                               "channel": channel or self.channel,
                               "rssi": self.rssi if rssi is None else rssi,
                               "event_type": 0x04 if scan else self.pdu_type(),
                               "event_type_text": bt.ADV_REPORT_TYPES.get(
                                   0x04 if scan else self.pdu_type(), "unknown"),
                               "data_length": len(payload)}
        parsed = bt.parse_adv_pdu(bytes(payload))
        out.update({key: parsed.get(key) for key in
                    ("structures", "ad", "name", "company", "tracker", "address_kind",
                     "connectable", "pdu_type", "length") if parsed.get(key) is not None})
        # the decoders read these from a *report*, and the report is where a scanner puts
        # them: the parsed advertising data plus the radio's own numbers
        out.setdefault("ad", parsed.get("ad") or parsed.get("structures") or [])
        out.setdefault("name", parsed.get("name") or "")
        out.setdefault("tracker", parsed.get("tracker"))
        return out

    # -- what the radio and the stack answer --------------------------------- #
    def gatt_rows(self) -> List[Dict[str, Any]]:
        """This device's attribute table, numbered from handle 0x0001."""
        handle = 1
        rows: List[Dict[str, Any]] = []
        for key in self.gatt:
            entry = GATT_LIBRARY.get(key)
            if not entry:
                continue
            service_uuid, characteristics = entry
            start = handle
            handle += 1
            for uuid, label, properties in characteristics:
                rows.append({"handle": handle, "kind": "characteristic", "uuid": uuid,
                             "name": label, "properties": properties,
                             "writable": "write" in properties,
                             "value": _characteristic_value(self, key, label)})
                handle += 1
            rows.append({"handle": start, "kind": "service", "uuid": service_uuid,
                         "name": bt.service_name(service_uuid), "start_handle": start,
                         "end_handle": handle - 1})
        if not rows:                                  # every device serves the basics
            rows = [{"handle": 1, "kind": "service", "uuid": 0x1800,
                     "name": bt.service_name(0x1800), "start_handle": 1, "end_handle": 3},
                    {"handle": 2, "kind": "characteristic", "uuid": 0x2A00,
                     "name": "Device Name", "properties": "read", "writable": False,
                     "value": self.name.encode()}]
        return rows

    def att_services(self) -> List[Tuple[int, int, int]]:
        """``(start handle, end handle, uuid)`` for every primary service."""
        return [(row["start_handle"], row["end_handle"], row["uuid"])
                for row in self.gatt_rows() if row["kind"] == "service"]

    def features(self, page: int = 0) -> bytes:
        """The BR/EDR feature pages this device claims, as eight bytes each."""
        if page == 0:
            bits = (1 << 2) | (1 << 5) | (1 << 8) | (1 << 16) | (1 << 18)
            return bits.to_bytes(8, "little")
        if page == 1:
            bits = (1 << 14) | (1 << 21) | (1 << 5)      # SSP, extended features, ESC0
            return bits.to_bytes(8, "little")
        bits = (1 << 6) | (1 << 7)                       # LE supported, simultaneous LE
        if self.flags.get("secure_connections"):
            bits |= 1 << 2                               # secure connections (controller)
        return bits.to_bytes(8, "little")

    def sdp_records(self) -> List[Dict[str, Any]]:
        """What an SDP browse finds: ``(uuid, name, channel)`` per service."""
        out: List[Dict[str, Any]] = []
        for index, uuid in enumerate(self.sdp):
            channel = self.channels[index] if index < len(self.channels) else 1
            uuid = int(uuid)
            label = (bt.SDP_SERVICES.get(uuid) or bt.service_name(uuid)
                     or f"uuid 0x{uuid:04x}")
            out.append({"uuid": uuid, "name": label, "channel": int(channel)})
        return out

    # -- reporting ----------------------------------------------------------- #
    def to_dict(self) -> Dict[str, Any]:
        return {"address": self.address, "name": self.name, "company": self.company,
                "company_id": self.company_id, "model": self.model, "device": self.device,
                "kind": self.kind, "profile": self.profile, "address_type": self.address_type,
                "address_kind": bt.classify_address(self.address), "rssi": self.rssi,
                "connectable": self.connectable, "bondable": self.bondable,
                "interval_ms": self.interval_ms, "channel": self.channel,
                "services": [bt.service_name(uuid) for uuid in self.services],
                "tracker": self.tracker, "beacon": self.beacon,
                "class_of_device": self.class_of_device,
                "class_text": bt.major_class_name(self.class_of_device)
                if self.class_of_device else "",
                "firmware": self.firmware, "fragile": self.flags.get("fragile", ""),
                "weaknesses": self.weaknesses(), "notes": self.notes,
                "gatt_services": [{"uuid": f"0x{uuid:04x}", "name": bt.service_name(uuid),
                                   "start_handle": start, "end_handle": end}
                                  for start, end, uuid in self.att_services()],
                "sdp": self.sdp_records(), "channels": list(self.channels)}

    def summary(self) -> str:
        """One line: who this is, and what it would be worth to an attacker."""
        if self.beacon:
            what = f"{self.beacon} beacon"
        elif self.tracker:
            what = f"{self.device} (tracker)"
        else:
            what = self.device
        return (f"{self.address} · {self.name or '(unnamed)'} · {what} · "
                f"{self.profile}: {self.weaknesses()[0]}")

    def finding(self) -> str:
        """The sentence a report puts under this device when a probe succeeds."""
        return (f"{self.name or self.address} ({self.model or self.device}) is a "
                f"{self.profile.replace('_', ' ')} device: {self.weaknesses()[0]}")


def _characteristic_value(device: BleDevice, key: str, label: str) -> bytes:
    """A believable value for a characteristic, so a read is not an empty answer."""
    text = f"{device.model or device.name} {device.firmware}".strip()
    if "Firmware" in label:
        return device.firmware.encode() or b"1.0.0"
    if "Model" in label:
        return (device.model or device.name).encode()
    if "Manufacturer" in label:
        return device.company.encode()
    if "Serial" in label:
        return f"SN{device.address.replace(':', '')[-8:]}".encode()
    if "Device Name" in label:
        return device.name.encode()
    if "Battery" in label:
        return bytes([72 if device.interval_ms <= 100 else 41])
    if "Lock State" in label:
        return b"\x00" if device.profile != "hardened" else b"\x01"
    if "Calibration" in label:
        return b"CAL-2024-11"
    return (text or "ok").encode()


def D(address: str, name: str = "", company: str = "", model: str = "", *,
      device: str = "unknown", kind: str = "le", profile: str = "hardened",
      class_of_device: int = 0, appearance: int = 0, rssi: int = -60, interval_ms: float = 500.0,
      channel: int = 37, connectable: bool = True, bondable: bool = True,
      address_type: int = 0, rotate: bool = False, firmware: str = "1.0.0",
      services: Sequence[int] = (), company_id: int = 0xFFFF, manufacturer_data: bytes = b"",
      tracker: str = "", beacon: str = "", beacon_args: Sequence[Any] = (),
      scan_name: bool = False, gatt: Sequence[str] = (), sdp: Sequence[int] = (),
      channels: Sequence[int] = (), at_name: str = "", notes: str = "") -> BleDevice:
    """Build one device row without writing every field name."""
    return BleDevice(address=address, name=name, company=company, model=model,
                     device=device, kind=kind, profile=profile,
                     class_of_device=class_of_device, appearance=appearance, rssi=rssi,
                     interval_ms=interval_ms, channel=channel, connectable=connectable,
                     bondable=bondable, address_type=address_type, rotate=rotate,
                     firmware=firmware, services=tuple(services), company_id=company_id,
                     manufacturer_data=manufacturer_data, tracker=tracker, beacon=beacon,
                     beacon_args=tuple(beacon_args), scan_name=scan_name, gatt=tuple(gatt),
                     sdp=tuple(sdp), channels=tuple(channels), at_name=at_name, notes=notes)


# --------------------------------------------------------------------------- #
# the floor
# --------------------------------------------------------------------------- #

#: Every device the simulated estate owns.  The list is deliberately not a list of
#: vulnerabilities: most of these are ordinary, correctly configured products, because a
#: scan that finds twelve devices has to place them next to the two that matter.  What
#: each one carries is the evidence its advertisement would give a real scanner — a name
#: or no name, a vendor, a beacon payload, a rotating address — plus the profile the
#: controller uses to answer for it.
#:
#: The devices were chosen so that between them they cover every question the wave asks:
#: three trackers on three different networks, an iBeacon and both Eddystone variants,
#: a device that names itself only in a scan response, a sensor advertising twenty times
#: a second next to a tag advertising once every two seconds, an address that rotates and
#: a shelf of devices that keep one for years, a Just Works keyboard, a KNOB-affected
#: soundbar, a stack from before the advisories, an old handset with its object store
#: open, and a patched fleet that refuses everything, so every audit has both an answer
#: and a refusal to report.
DEVICE_TABLE: List[BleDevice] = [
    # -- the things people leave behind ------------------------------------- #
    D("5c:8d:2f:11:00:01", "", "Apple", "AirTag", device="item tracker", profile="hardened",
      address_type=1, rotate=True, interval_ms=2000.0, rssi=-78, company_id=0x004C,
      manufacturer_data=b"\x12\x19\x00", tracker="apple",
      notes="a Find My tag: the payload is encrypted, the manufacturer is not"),
    D("c9:41:77:22:00:02", "", "Tile", "Mate", device="item tracker", profile="hardened",
      address_type=1, rotate=True, interval_ms=1000.0, rssi=-81, company_id=0x2C7C,
      manufacturer_data=b"\x01\x02", tracker="tile"),
    D("e0:22:aa:33:00:03", "", "Samsung", "SmartTag2", device="item tracker",
      profile="hardened", address_type=1, rotate=True, interval_ms=1500.0, rssi=-84,
      company_id=0x0075, manufacturer_data=b"\x02\x00\x01", tracker="samsung"),
    D("a4:11:22:33:44:55", "Pixel Buds A", "Google", "GPX-100", device="earbuds",
      kind="dual", profile="open_gatt", company_id=0x00E0, interval_ms=400.0, rssi=-70,
      services=(0x180A, 0x180F), gatt=("device_info", "battery"),
      notes="a Fast Pair accessory: the pairing is friendly and the vendor service is "
            "writeable"),
    # -- the badges and beacons the estate put up --------------------------- #
    D("d4:3b:2a:11:00:04", "", "Kontakt", "iBeacon M1", device="beacon", profile="hardened",
      beacon="ibeacon", beacon_args=("8ec76ea3-1d1c-4f1a-9b7a-3c2f5d0a7711", 9, 101, -63),
      company_id=0x0183, interval_ms=500.0, rssi=-63, connectable=False,
      notes="the lobby beacon: a fixed identity, cloned in one packet"),
    D("e1:22:33:44:55:66", "", "Estimote", "Location Beacon", device="beacon",
      profile="hardened", beacon="eddystone-url", beacon_args=("shop.example/floor2", 0x03),
      company_id=0x015D, interval_ms=1000.0, rssi=-72, connectable=False,
      notes="an Eddystone-URL on a shopfront: the advertisement carries the link"),
    D("f2:33:44:55:66:77", "", "Nordic", "Thingy:91", device="beacon", profile="hardened",
      beacon="eddystone-uid", beacon_args=("0102030405060708090a", "0b0c0d0e0f10"),
      company_id=0x0059, interval_ms=800.0, rssi=-68, connectable=False,
      notes="an Eddystone-UID: the identity is a number nobody rotates"),
    D("11:22:33:44:55:0a", "Badge-A14", "Arena", "Visitor Badge", device="badge",
      kind="dual", profile="hardened", address_type=0, interval_ms=900.0, rssi=-74,
      services=(0x180F, 0x180A), gatt=("battery", "device_info"), scan_name=True,
      manufacturer_data=b"\x0a\x0b", company_id=0x0059,
      notes="a visitor badge: a public address that follows the same person every day"),
    D("b2:44:55:66:77:88", "AirQ-2", "Qingping", "AQ-200", device="air quality monitor",
      profile="hardened", address_type=1, rotate=True, interval_ms=1100.0, rssi=-76,
      services=(0x181A,), gatt=("device_info",), company_id=0x02E5,
      notes="a sensor that rotates its address the way the specification recommends"),
    # -- wearables, and the medical peripherals ----------------------------- #
    D("d4:11:22:33:44:55", "HRM-Dual", "Garmin", "HRM-200", device="heart-rate strap",
      profile="open_gatt", interval_ms=1000.0, rssi=-66, services=(0x180D, 0x180F),
      gatt=("heart_rate", "battery"), company_id=0x0087,
      notes="a strap that hands its measurements to anybody who subscribes"),
    D("c3:22:55:77:99:11", "BP-7000", "Omron", "BP-7000", device="blood pressure monitor",
      profile="hardened", services=(0x1810,), gatt=("blood_pressure", "device_info"),
      interval_ms=1200.0, rssi=-71, company_id=0x0203),
    D("a1:99:88:77:66:55", "Fit-Band 3", "Fitbit", "FB-3", device="fitness band",
      profile="blesa", services=(0x180F, 0x1814), gatt=("battery", "fitness"),
      interval_ms=800.0, rssi=-74, company_id=0x00D2,
      notes="accepts GATT work on a reconnection before the session is authenticated"),
    D("77:66:55:44:33:22", "GlucoLink", "Abbott", "GL-4", device="glucose meter",
      profile="open_gatt", services=(0x1808,), gatt=("glucose", "vendor_glucose"),
      interval_ms=1000.0, rssi=-79, company_id=0x0218),
    D("66:55:44:33:22:11", "Thermo-4", "Withings", "WT-4", device="thermometer",
      profile="hardened", services=(0x1809,), gatt=("thermometer", "device_info"),
      interval_ms=2000.0, rssi=-80, company_id=0x0242),
    D("55:44:33:22:11:00", "Aid-L", "Oticon", "OTA-L", device="hearing aid", kind="dual",
      profile="hardened", services=(0x180A,), gatt=("device_info",), interval_ms=1500.0,
      rssi=-69, company_id=0x0238),
    D("44:33:22:11:00:99", "ECG-Patch", "Biotronik", "EP-2", device="ECG patch",
      profile="open_gatt", services=(0x180D,), gatt=("heart_rate",), interval_ms=600.0,
      rssi=-72, company_id=0x0194),
    D("38:9e:44:11:22:33", "InfusionPump-3", "B.Braun", "IP-3", device="infusion pump",
      kind="dual", profile="hardened", services=(0x180A,), gatt=("device_info",),
      interval_ms=1000.0, rssi=-77, company_id=0x0214),
    # -- the desk and the meeting room -------------------------------------- #
    D("2c:54:33:22:11:00", "KBD-1C2B", "Logitech", "K380", device="keyboard", kind="dual",
      profile="open_gatt", class_of_device=0x2540, services=(bt.HID_SERVICE_UUID,),
      gatt=("hid",), interval_ms=1000.0, rssi=-70, scan_name=True, company_id=0x0105,
      notes="a keyboard that pairs without a human and hosts HID reports without asking"),
    D("3c:54:33:22:11:aa", "MX-Mouse", "Logitech", "MX-3", device="mouse", kind="dual",
      profile="open_gatt", class_of_device=0x2580, services=(bt.HID_SERVICE_UUID,),
      gatt=("hid",), interval_ms=900.0, rssi=-64, company_id=0x0105),
    D("8c:11:22:33:44:cc", "PRN-4B2C", "HP", "LaserJet M404", device="printer", kind="dual",
      profile="hardened", class_of_device=0x680404, services=(0x180A,),
      gatt=("device_info",), sdp=(0x1116, 0x1124), channels=(1, 2), interval_ms=700.0,
      rssi=-63, at_name="HP LaserJet M404", company_id=0x003D),
    D("9c:32:1a:44:55:66", "Scanner-2D", "Zebra", "DS2278", device="barcode scanner",
      kind="dual", profile="legacy_push", class_of_device=0x1400, sdp=(0x1101, 0x1103),
      channels=(3,), interval_ms=600.0, rssi=-67, company_id=0x0059,
      at_name="Zebra DS2278"),
    D("1c:22:33:44:55:dd", "TV-Living", "Samsung", "Q60", device="smart tv", kind="dual",
      profile="hardened", class_of_device=0x200428, services=(0x180A,),
      gatt=("device_info",), interval_ms=1100.0, rssi=-65, company_id=0x0075),
    D("0c:88:77:66:55:44", "SoundBar K1", "Anker", "K1", device="soundbar", kind="dual",
      profile="knober", class_of_device=0x240414, sdp=(0x110B, 0x110E), channels=(2,),
      interval_ms=700.0, rssi=-61, company_id=0x0176,
      notes="CVE-2019-9506: the two controllers agree on a one-byte key"),
    D("f0:de:11:22:33:44", "Vib-S1", "Nordic", "VibSensor", device="vibration sensor",
      profile="fragile_stack", interval_ms=20.0, channel=38, rssi=-55, company_id=0x0059,
      manufacturer_data=b"\x61\x01\x02", gatt=("vendor_plc",),
      notes="transmits twenty times a second, and its stack is from before the advisories"),
    D("a0:11:22:33:44:55", "Treadmill-9000", "Technogym", "TG-9", device="treadmill console",
      kind="dual", profile="fragile_stack", class_of_device=0x080204,
      services=(0x1814,), gatt=("fitness", "vendor_plc"), interval_ms=400.0, rssi=-62,
      company_id=0x0250),
    D("b0:99:88:77:66:55", "Robot-Toy", "Sphero", "Mini", device="toy robot",
      profile="fragile_stack", services=(0x1815,), gatt=("automation",),
      interval_ms=300.0, rssi=-73, company_id=0x02B1),
    # -- the building and the plant ----------------------------------------- #
    D("d0:0a:11:22:33:44", "LOCK-FRONT", "August", "ASL-2", device="door lock",
      profile="wide_open", services=(0x180F,), gatt=("battery", "vendor_lock"),
      interval_ms=1000.0, rssi=-75, company_id=0x01A9,
      notes="an attribute table a stranger can write: lock control and the admin key"),
    D("d1:0a:11:22:33:45", "Lock-Back", "August", "ASL-2", device="door lock",
      profile="hardened", services=(0x180F,), gatt=("battery", "device_info"),
      interval_ms=1000.0, rssi=-79, company_id=0x01A9),
    D("d2:0a:11:22:33:46", "T-stat 3", "Honeywell", "T3", device="thermostat",
      kind="dual", profile="open_gatt", services=(0x1815,), gatt=("automation", "vendor_plc"),
      interval_ms=1200.0, rssi=-70, company_id=0x0059),
    D("d3:0a:11:22:33:47", "Bulb-Kitchen", "Philips", "Hue-4", device="light bulb",
      profile="open_gatt", services=(0x1815,), gatt=("automation",), interval_ms=900.0,
      rssi=-66, company_id=0x01CD),
    D("d4:0a:11:22:33:48", "Plug-Washer", "TP-Link", "P100", device="smart plug",
      profile="wide_open", services=(0x180F,), gatt=("battery", "vendor_scooter"),
      interval_ms=1000.0, rssi=-72, company_id=0x0059),
    D("d5:0a:11:22:33:49", "Scooter X7", "Xiaomi", "X7", device="e-scooter", kind="dual",
      profile="wide_open", services=(0x1815,), gatt=("vendor_scooter",),
      interval_ms=500.0, rssi=-64, company_id=0x0271,
      notes="speed limit and motor enable are writeable with no pairing at all"),
    D("d6:0a:11:22:33:4a", "Scale-500", "Mettler", "S500", device="industrial scale",
      profile="fragile_stack", interval_ms=450.0, rssi=-68, company_id=0x0059,
      manufacturer_data=b"\x42\x00\x01"),
    D("d7:0a:11:22:33:4b", "Meter-W1", "Kamstrup", "W1", device="water meter",
      profile="hardened", address_type=0, interval_ms=2000.0, rssi=-82,
      company_id=0x0247),
    D("d8:0a:11:22:33:4c", "EV-Charger-2", "ABB", "Terra", device="ev charger", kind="dual",
      profile="hardened", class_of_device=0x080218, services=(0x180A,),
      gatt=("device_info",), interval_ms=1000.0, rssi=-71, company_id=0x0273),
    D("d9:0a:11:22:33:4d", "Doorbell-1", "Ring", "DB-2", device="doorbell camera",
      profile="open_gatt", services=(0x180A,), gatt=("device_info", "vendor_plc"),
      interval_ms=800.0, rssi=-73, company_id=0x0059),
    D("da:0a:11:22:33:4e", "Vending-7", "Nayax", "V7", device="vending machine",
      profile="fragile_stack", interval_ms=1100.0, rssi=-77, company_id=0x02A8),
    # -- the classic shelf: devices an LE scan never sees -------------------- #
    D("00:1a:7d:11:22:01", "Printer-HP-4520", "HP", "LaserJet 4520", device="printer",
      kind="bredr", profile="hardened", class_of_device=0x68040C, sdp=(0x1116, 0x1124),
      channels=(1, 2, 3), rssi=-58, at_name="HP LaserJet 4520", notes="classic only"),
    D("00:1a:7d:11:22:02", "Headset-H500", "Logitech", "H500", device="headset",
      kind="bredr", profile="legacy_push", class_of_device=0x240404, sdp=(0x110E, 0x1112),
      channels=(1, 4), rssi=-60, at_name="Logitech H500"),
    D("00:1a:7d:11:22:03", "CarKit-Audio", "Parrot", "CK-2", device="car kit", kind="bredr",
      profile="legacy_push", class_of_device=0x240408, sdp=(0x111F, 0x1108),
      channels=(2, 5), rssi=-66, at_name="Parrot CK-2"),
    D("00:1a:7d:11:22:04", "Phone-K800i", "Sony Ericsson", "K800i", device="mobile phone",
      kind="dual", profile="legacy_push", class_of_device=0x10020C,
      sdp=(0x1105, 0x1104, 0x111F), channels=(5, 6, 7), rssi=-63,
      at_name="Sony Ericsson K800i",
      notes="the handset from the advisory: OBEX answers, and so does the AT channel"),
    D("00:1a:7d:11:22:05", "Phone-Modern", "Samsung", "S24", device="mobile phone",
      kind="dual", profile="hardened", class_of_device=0x10020C,
      sdp=(0x1105, 0x1112), channels=(6,), rssi=-59, at_name="Samsung S24"),
    D("00:1a:7d:11:22:06", "DESKTOP-7F2A", "Dell", "OptiPlex", device="desktop pc",
      kind="dual", profile="hid_trusting", class_of_device=0x100104,
      sdp=(0x1101, 0x1112), channels=(1, 2), rssi=-61, at_name="Dell OptiPlex"),
    D("00:1a:7d:11:22:07", "PLC-HMI-2", "Siemens", "KTP700", device="hmi panel", kind="dual",
      profile="fragile_stack", class_of_device=0x080204, sdp=(0x111F, 0x1101),
      channels=(1,), rssi=-69, at_name="Siemens KTP700"),
    D("00:1a:7d:11:22:08", "Speaker-Boom", "JBL", "Boom-3", device="speaker", kind="dual",
      profile="knober", class_of_device=0x240414, sdp=(0x110B, 0x1108), channels=(1, 3),
      rssi=-65, at_name="JBL Boom-3"),
    D("00:1a:7d:11:22:09", "UPS-Monitor", "APC", "SMX-750", device="ups", kind="dual",
      profile="hardened", class_of_device=0x100200, sdp=(0x1101,), channels=(4,),
      rssi=-72, at_name="APC SMX-750"),
]


def build_ble(seed: int = 7, limit: int = 0) -> List[BleDevice]:
    """The floor, in a deterministic order: the same seed always buys the same estate.

    Addresses, names, profiles and channels all come from :data:`DEVICE_TABLE` — a demo
    run that finds a lock with a writeable admin key finds it again tomorrow, and a test
    can assert on it.  ``seed`` only jitters the signal, because a scan that returns
    identical numbers every time is a scan nobody believes.
    """
    rng = random.Random(seed)
    devices: List[BleDevice] = []
    for entry in DEVICE_TABLE:
        device = BleDevice(**{**entry.__dict__})
        device.rssi = int(max(-95, min(-35, entry.rssi + rng.randint(-3, 3))))
        devices.append(device)
    return devices[:limit] if limit else devices


def ble_catalog() -> List[Dict[str, Any]]:
    """The floor as data: what the web UI's simulator view renders."""
    return [device.to_dict() for device in ble()]


# --------------------------------------------------------------------------- #
# the airspace
# --------------------------------------------------------------------------- #

class BleLink:
    """One open link to a simulated device: a handle, and what the peer will answer."""

    def __init__(self, device: BleDevice, handle: int = 0x0040) -> None:
        self.device = device
        self.handle = handle
        self.encrypted = False
        self.key_size = 0
        self.authenticated = False
        self.paired = False
        self.bonded = bool(device.flags.get("bonding"))
        self.alive = True
        self.requests = 0
        self.answers = 0
        self.att_answers = 0
        self.att_refusals = 0
        self.transcript: List[Dict[str, Any]] = []

    @property
    def profile(self) -> str:
        return self.device.profile

    def dies(self, reason: str = "") -> None:
        """The stack stops answering: what a fragile profile does to a malformed PDU."""
        self.alive = False
        self.transcript.append({"event": "silence", "reason": reason or "malformed PDU"})

    def to_dict(self) -> Dict[str, Any]:
        return {"handle": f"0x{self.handle:04x}", "address": self.device.address,
                "name": self.device.name, "profile": self.device.profile,
                "alive": self.alive, "encrypted": self.encrypted,
                "key_size": self.key_size, "paired": self.paired,
                "authenticated": self.authenticated, "requests": self.requests,
                "answers": self.answers, "att_answers": self.att_answers,
                "att_refusals": self.att_refusals}


class VirtualBle:
    """The simulated airspace: devices, their radio answers, and their protocols.

    A live run points :mod:`wifipilot.bt` at a controller.  A demo run points it here:
    :meth:`scan` returns the advertising reports a scan would produce,
    :meth:`att_request` answers an ATT PDU out of the device's attribute table,
    :meth:`sdp_request` answers an SDP browse out of its records, :meth:`at_command`
    speaks for its hands-free channel and :meth:`obex_request` for its object store — all
    of it according to the device's profile, so a hardened device refuses and a weak one
    does not.
    """

    def __init__(self, devices: Optional[Sequence[BleDevice]] = None, seed: int = 7) -> None:
        self.devices: List[BleDevice] = (list(devices) if devices is not None
                                         else build_ble(seed=seed))
        self.seed = seed
        self.links: Dict[int, BleLink] = {}
        self.transcript: List[Dict[str, Any]] = []
        self.scans = 0
        self.connections = 0
        self.handle_base = 0x0040

    # -- the floor as a sequence -------------------------------------------- #
    def __iter__(self) -> Any:
        return iter(self.devices)

    def __len__(self) -> int:
        return len(self.devices)

    def __getitem__(self, index: Any) -> Any:
        return self.devices[index]

    def __bool__(self) -> bool:
        return bool(self.devices)

    # -- lookups ------------------------------------------------------------ #
    def by_address(self, address: str) -> Optional[BleDevice]:
        wanted = (address or "").strip().lower()
        return next((device for device in self.devices
                     if device.address.lower() == wanted), None)

    def by_name(self, name: str) -> Optional[BleDevice]:
        wanted = (name or "").strip().lower()
        return next((device for device in self.devices
                     if wanted and wanted in (device.name or "").lower()), None)

    def has_role(self, device: BleDevice, role: str) -> bool:
        """Can this device answer an attack that needs ``role``?"""
        role = (role or "any").lower()
        flags = device.flags
        if role in ("", "any"):
            return True
        if role == "le":
            return device.kind in ("le", "dual") and device.connectable
        if role == "bredr":
            return device.kind in ("bredr", "dual")
        if role == "l2cap":
            return device.connectable
        if role == "gatt":
            return bool(device.gatt) or device.kind in ("le", "dual")
        if role == "smp":
            return device.bondable and bool(flags.get("pairing"))
        if role == "sdp":
            return bool(device.sdp)
        if role == "rfcomm":
            return bool(device.channels)
        if role == "at":
            return bool(flags.get("at")) and bool(device.at_name)
        if role == "obex":
            # an object store is what a phone carries, and it is the object-push and
            # file-transfer profiles in its SDP records that say so
            return bool(flags.get("obex")) and any(uuid in (0x1105, 0x1106)
                                                   for uuid in device.sdp)
        if role == "hid":
            return bool(flags.get("hid")) and device.device in HID_HOSTS
        if role == "fragile":
            return bool(flags.get("fragile"))
        if role == "tracker":
            return bool(device.tracker)
        if role == "beacon":
            return bool(device.beacon)
        return True

    def candidates(self, role: str = "any", profile: str = "",
                   like: str = "") -> List[BleDevice]:
        """Every device that can answer ``role``, weakest profile first — how a run walks.

        A demo run does not stop at the first address in the table: it walks the devices
        that can answer the question, starting with the one whose posture says it answers
        before it asks, and reports the device that actually did.
        """
        found = [device for device in self.devices
                 if self.has_role(device, role)
                 and (not profile or device.profile == profile)
                 and (not like or like.lower() in (device.name + device.model
                                                   + device.device).lower())]
        if role in ("", "any"):
            return devices_by_weakness(found)

        def rank(device: "BleDevice") -> Tuple[int, int, int, str]:
            # a device whose own posture names the battery is the one the battery is for:
            # BlueSmack escalates until the stack stops answering, and the device that
            # documents "l2cap" in its fragile list is the one where that can be *seen*,
            # so it goes first.  Everything else keeps the weakness order.
            fragile = [part.strip() for part in str(device.flags.get("fragile", "")).split(",")]
            return (0 if role in fragile else 1, profile_rank(device.profile),
                    -int(device.rssi), device.address)

        return sorted(found, key=rank)

    def pick(self, role: str = "any", profile: str = "", like: str = "") -> Optional[BleDevice]:
        """The weakest device that can answer ``role``."""
        found = self.candidates(role, profile, like)
        return found[0] if found else None

    def roles_of(self, device: BleDevice) -> List[str]:
        return [role for role in LINK_ROLES if self.has_role(device, role)]

    # -- the radio ---------------------------------------------------------- #
    def scan(self, limit: int = 0) -> List[Dict[str, Any]]:
        """What an LE scan hears: one report per device, plus the scan responses."""
        self.scans += 1
        reports: List[Dict[str, Any]] = []
        for device in self.devices:
            if device.kind == "bredr":
                continue                                  # classic devices do not advertise
            address = device.address
            if device.rotate:
                address = bt.resolvable_private_address(
                    hashlib.sha256(device.address.encode()).digest()[:4], seed=self.scans)
                device.address_type = 1
            reports.append(device.report(address=address))
            if device.scan_name:
                reports.append(device.report(address=address, scan=True))
        self.transcript.append({"event": "scan", "reports": len(reports)})
        return reports[:limit] if limit else reports

    def inquiry(self) -> List[Dict[str, Any]]:
        """What a classic inquiry finds: the BR/EDR devices, with their class of device."""
        found: List[Dict[str, Any]] = []
        for device in self.devices:
            if device.kind not in ("bredr", "dual"):
                continue
            found.append({"address": device.address,
                          "class_of_device": device.class_of_device,
                          "major_class": (device.class_of_device >> 8) & 0x1F,
                          "major_class_text": bt.major_class_name(device.class_of_device),
                          "name": device.name, "rssi": device.rssi})
        self.transcript.append({"event": "inquiry", "found": len(found)})
        return found

    def advertising_payload(self, address: str = "") -> bytes:
        """The payload of the advertisement a device would be cloned from."""
        device = self.by_address(address) or self.pick("le")
        return device.ad_payload() if device else bt.adv_payload(bt.ad_flags())

    # -- the link ----------------------------------------------------------- #
    def open_link(self, device: Optional[BleDevice] = None, handle: int = 0) -> Optional[BleLink]:
        """Create a link to a device, or return the one already open on that handle."""
        if device is None:
            if handle and handle in self.links:
                return self.links[handle]
            device = self.pick("l2cap")
            if device is None:
                return None
        if handle in self.links:
            existing = self.links[handle]
            if existing.alive and (device is None or existing.device is device):
                return existing
            # a link that is dead, or one that belongs to another device: the connection
            # is made again, which is what a crash actually costs — and the device that
            # stopped answering keeps the count
            self.links.pop(handle, None)
            if not existing.alive:
                existing.device.crashes = int(getattr(existing.device, "crashes", 0)) + 1
                self.transcript.append({"event": "reconnect", "address":
                                        existing.device.address,
                                        "after": existing.transcript[-1].get("reason", "")
                                        if existing.transcript else ""})
        handle = handle or (self.handle_base + len(self.links))
        link = BleLink(device, handle)
        self.links[handle] = link
        self.connections += 1
        self.transcript.append({"event": "connect", "address": device.address,
                                "handle": handle, "profile": device.profile})
        return link

    def link_for(self, address: str = "", role: str = "any",
                 handle: int = 0) -> Optional[BleLink]:
        """The link an attack is talking over: the named one, or the weakest of a role."""
        device = self.by_address(address) if address else None
        if device is None and role:
            device = self.pick(role)
        return self.open_link(device, handle) if device is not None else None

    def close_link(self, link: BleLink, reason: str = "") -> None:
        self.links.pop(link.handle, None)
        link.transcript.append({"event": "disconnect", "reason": reason})

    # -- ATT: the attribute table ------------------------------------------- #
    def att_request(self, device: BleDevice, body: bytes, link: Optional[BleLink] = None) -> bytes:
        """Answer an ATT PDU out of the device's table, or refuse it honestly."""
        if not body:
            return b""
        flags = device.flags
        opcode = body[0]
        rows = device.gatt_rows()
        by_handle = {row["handle"]: row for row in rows}
        if link is not None:
            link.requests += 1
        authenticated = bool(link.authenticated) if link is not None else False
        gated = not flags.get("gatt_before_auth", False)

        if opcode == 0x02:                                        # Exchange MTU Request
            mtu = int.from_bytes(body[1:3], "little") or 23
            answer = bytes([0x03]) + struct.pack("<H", min(mtu, 517))
        elif opcode == 0x04:                                      # Find Information Request
            start = int.from_bytes(body[1:3], "little")
            end = int.from_bytes(body[3:5], "little") or 0xFFFF
            entries = [(row["handle"], row["uuid"]) for row in rows
                       if start <= row["handle"] <= end][:18]
            answer = bytes([0x05, 0x01]) + b"".join(
                struct.pack("<HH", handle, uuid & 0xFFFF) for handle, uuid in entries)
        elif opcode == 0x10:                                      # Read By Group Type
            services = device.att_services()
            if not services:
                answer = _att_error(0x10, 1, 0x0A)                # attribute not found
            else:
                entries = b"".join(struct.pack("<HHH", start, end, uuid)
                                   for start, end, uuid in services)
                answer = bytes([0x11, 6]) + entries
        elif opcode == 0x08:                                      # Read By Type Request
            start = int.from_bytes(body[1:3], "little")
            end = int.from_bytes(body[3:5], "little") or 0xFFFF
            uuid = int.from_bytes(body[5:7], "little") if len(body) >= 7 else 0
            matching = [row for row in rows if start <= row["handle"] <= end
                        and row["uuid"] == uuid and row.get("value") is not None]
            if not matching:
                answer = _att_error(0x08, start, 0x0A)
            else:
                first = matching[0]
                length = 2 + len(first["value"])
                answer = bytes([0x09, length]) + struct.pack("<H", first["handle"]) \
                    + first["value"]
        elif opcode in (0x0A, 0x0C):                              # Read / Read Blob
            handle = int.from_bytes(body[1:3], "little")
            row = by_handle.get(handle)
            if row is None or row.get("value") is None:
                answer = _att_error(opcode, handle, 0x0A)
            elif gated and not authenticated and not flags.get("gatt_write"):
                answer = _att_error(opcode, handle, 0x05)         # insufficient auth
                if link is not None:
                    link.att_refusals += 1
            else:
                answer = bytes([0x0B]) + bytes(row["value"])
        elif opcode in (0x12, 0x52):                              # Write / Write Command
            handle = int.from_bytes(body[1:3], "little")
            row = by_handle.get(handle)
            if row is None:
                answer = _att_error(0x12, handle, 0x0A)
            elif not row.get("writable"):
                answer = _att_error(0x12, handle, 0x03)           # write not permitted
            elif gated and not authenticated and not flags.get("gatt_write"):
                answer = _att_error(0x12, handle, 0x05)
                if link is not None:
                    link.att_refusals += 1
            elif not flags.get("gatt_write") and not authenticated:
                answer = _att_error(0x12, handle, 0x0C)           # encryption key size
                if link is not None:
                    link.att_refusals += 1
            else:
                answer = bytes([0x13]) if opcode == 0x12 else b""
        elif opcode in (0x1B, 0x1D):                              # Notification / Indication
            answer = b""
        else:
            answer = _att_error(opcode, 0, 0x06)                  # request not supported
        if link is not None:
            link.answers += 1
            if answer[:1] == b"\x01":
                link.att_refusals += 1
            elif answer:
                link.att_answers += 1
            link.transcript.append({"att": f"0x{opcode:02x}", "sent": len(body),
                                    "answer": len(answer)})
        self.transcript.append({"event": "att", "device": device.address,
                                "opcode": f"0x{opcode:02x}", "answer": len(answer)})
        return answer

    # -- SMP: pairing ------------------------------------------------------- #
    def smp_request(self, device: BleDevice, body: bytes,
                    link: Optional[BleLink] = None) -> bytes:
        """Answer a security-manager command: the pairing a profile permits, or a refusal."""
        if not body:
            return b""
        flags = device.flags
        command = body[0]
        if command in (0x01, 0x02):                               # Pairing Request
            if not flags.get("pairing"):
                if link is not None:
                    link.transcript.append({"smp": "pairing refused",
                                            "reason": "no pairing"})
                return bytes([0x05, 0x05])                        # Pairing Failed: not supported
            auth = 0x01 if flags.get("bonding") else 0x00
            if flags.get("mitm"):
                auth |= 0x04
            if flags.get("secure_connections"):
                auth |= 0x08
            answer = bytes([0x03, _io_capability(flags.get("io", "")), 0x00, auth,
                            int(flags.get("key_size", 16)), 0x0F, 0x0F])
            if link is not None:
                link.transcript.append({"smp": "pairing response",
                                        "auth": f"0x{auth:02x}",
                                        "secure_connections": bool(flags.get("secure_connections")),
                                        "key_size": int(flags.get("key_size", 16))})
            return answer
        if command == 0x0B:                                       # Pairing Public Key
            return bytes([0x0C]) + body[1:65].ljust(64, b"\x00")
        if command == 0x04:                                       # Pairing Confirm
            return bytes([0x05]) + body[1:17].ljust(16, b"\x00")
        if command in (0x0D, 0x0E, 0x0F, 0x10, 0x08, 0x09, 0x0A, 0x03, 0x05):
            # the key-distribution and response PDUs: the peer answers the next step, and
            # a device that requires Secure Connections refuses a legacy exchange here
            if flags.get("secure_connections") and not flags.get("just_works"):
                if link is not None:
                    link.transcript.append({"smp": "legacy exchange refused"})
                return bytes([0x05, 0x03])                        # Pairing Failed: auth
            if link is not None:
                link.paired = True
                link.authenticated = bool(flags.get("mitm")) or bool(flags.get("secure_connections"))
                link.key_size = int(flags.get("key_size", 16))
            return b""
        if command == 0x0C:
            return b""
        return bytes([0x05, 0x07]) if command else b""

    # -- L2CAP signalling --------------------------------------------------- #
    def signalling(self, device: BleDevice, body: bytes,
                   link: Optional[BleLink] = None) -> bytes:
        """Answer an L2CAP signalling PDU, and let a fragile stack fall over."""
        if not body:
            return b""
        flags = device.flags
        code = body[0]
        identifier = body[1] if len(body) > 1 else 1
        fragile = "l2cap" in str(flags.get("fragile", ""))
        if code == 0x0A:                                          # Information Request
            kind = int.from_bytes(body[4:6], "little") if len(body) >= 6 else 0x0002
            result = 0x0000 if not fragile else 0x0001
            return bytes([0x0B, identifier, 0x00, 0x08]) + struct.pack("<HH", kind, result) \
                + b"\x00" * 4
        if code == 0x02:                                          # Connection Request
            if fragile:
                if link is not None:
                    link.dies("L2CAP connection request on a non-offered PSM")
                return b""
            psm = int.from_bytes(body[3:5], "little") if len(body) >= 5 else 1
            source = int.from_bytes(body[1:3], "little")
            channels = {0x0001: 0x0040, 0x0003: 0x0041, 0x000F: 0x0042, 0x0011: 0x0043,
                        0x0013: 0x0044, 0x001F: 0x0045}
            local = channels.get(psm, 0x0046)
            # the response is Destination CID, Source CID, Result, Status — a PSM the
            # stack does not offer comes back as "PSM not supported" rather than silence
            result = 0x0000 if psm in channels else 0x0002
            return bytes([0x03, identifier, 0x00, 0x08]) + struct.pack(
                "<HHHH", local, source, result, 0x0000)
        if code == 0x04:                                          # Configure Request
            if fragile:
                if link is not None:
                    link.dies("L2CAP configure request with a malformed MTU option")
                return b""
            return bytes([0x05, identifier, 0x00, 0x04]) + struct.pack("<HH", 0x0000, 0x0000)
        if code == 0x06:                                          # Disconnect Request
            if link is not None and link.encrypted:
                link.encrypted = False
            return bytes([0x07, identifier, 0x00, 0x04]) + struct.pack("<HH", 0x0040,
                                                                      0x0040)
        if code == 0x08:                                          # Echo Request
            # the parameter length is the second half of the signalling header: an echo
            # request is code, identifier, length, then the payload the peer must return
            size = int.from_bytes(body[2:4], "little") if len(body) >= 4 else 0
            payload = bytes(body[4:4 + size])
            if fragile and size > 0x1000:
                if link is not None:
                    link.dies(f"L2CAP echo request of {size} bytes")
                return b""
            # an echo response carries the same payload back (and the same identifier)
            return bytes([0x09, identifier]) + struct.pack("<H", len(payload)) + payload
        if code == 0x12:                                          # Connection Parameter Update
            return bytes([0x13, identifier, 0x00, 0x02, 0x00, 0x00])
        if 0x80 <= code <= 0xFF:                                  # a response: nothing to say
            return b""
        return bytes([0x01, identifier, 0x00, 0x02]) + struct.pack("<H", code)   # Command Reject

    # -- SDP ---------------------------------------------------------------- #
    def sdp_request(self, device: BleDevice, body: bytes) -> bytes:
        """Answer an SDP request with the device's service records.

        The transaction identifier is echoed, because a client matches the answer to the
        request by it, and a device with no records still answers — an empty attribute
        list, not silence, which is what the specification requires and what tells a
        browser the difference between "nothing to show" and "not there".
        """
        transaction = (body[1] << 8) | body[2] if len(body) >= 3 else 1
        records = device.sdp_records()
        return _sdp_response(records, transaction=transaction)

    # -- RFCOMM: the serial profiles ---------------------------------------- #
    def at_command(self, device: BleDevice, command: bytes) -> bytes:
        """Speak for the hands-free unit: the AT command set a headset answers."""
        flags = device.flags
        if not flags.get("at"):
            return b"ERROR\r\n" if command.strip() else b""
        text = command.decode("latin-1", "replace").strip().upper()
        model = device.at_name or device.model or device.name or "Simulated device"
        if text in ("AT", "AT\r"):
            return b"AT\r\n"
        if "CGMI" in text:
            return f"+CGMI: {device.company}\r\nOK\r\n".encode()
        if "CGMM" in text:
            return f"+CGMM: {model}\r\nOK\r\n".encode()
        if "CGSN" in text:
            return f"+CGSN: {abs(hash(device.address)) % 10**15}\r\nOK\r\n".encode()
        if "CKPD" in text:
            return b"+CKPD: 200,1\r\nOK\r\n"
        if "VGS" in text:
            return b"+VGS: 15\r\nOK\r\n"
        if "CPBS" in text:
            return b"+CPBS: \"SM\",42\r\nOK\r\n"
        if text.startswith("ATD"):
            return b"+CLCC: 1,0,0,0,0,\"+15550100\",129\r\nOK\r\n"
        if "CMGS" in text:
            return b"+CMGS: 12\r\nOK\r\n"
        return b"OK\r\n"

    def obex_request(self, device: BleDevice, body: bytes) -> bytes:
        """Answer an OBEX packet: the object store, if the profile leaves it open."""
        flags = device.flags
        parsed = bt.parse_obex_packet(body)
        opcode = parsed.get("opcode", 0)
        if not flags.get("obex"):
            return _obex_response(0xC1 if opcode else 0xC6)        # unauthorized / conflict
        if opcode == bt.OBEX_CONNECT:
            # CONNECT answers with the connection id the session will carry
            return _obex_response(0xA0, extra=bytes([0xC4, 0x00, 0x00, 0x00, 0x01]))
        if opcode in (bt.OBEX_GET, bt.OBEX_GET_FINAL):
            name = parsed.get("name") or _obex_name(body)
            return _obex_vcard(device, name)
        if opcode in (bt.OBEX_PUT, bt.OBEX_PUT_FINAL):
            return _obex_response(0xA2)                             # accepted
        if opcode == bt.OBEX_SETPATH:
            return _obex_response(0xA0)
        if opcode == bt.OBEX_DISCONNECT:
            return _obex_response(0xA0)
        return _obex_response(0xC3)                                 # forbidden


# --------------------------------------------------------------------------- #
# the small builders the answers are made of
# --------------------------------------------------------------------------- #

def _att_error(request_opcode: int, handle: int, code: int) -> bytes:
    """An ATT Error Response: which request failed, on which handle, and why."""
    return bytes([0x01, request_opcode & 0xFF]) + struct.pack("<H", handle & 0xFFFF) \
        + bytes([code & 0xFF])


def _io_capability(name: str) -> int:
    """The IO capability byte for a profile's ``io`` string."""
    return {"display only": 0x00, "display yes/no": 0x01, "keyboard only": 0x02,
            "no input no output": 0x03, "keyboard display": 0x04,
            "display yes/no (keyboard)": 0x04}.get(str(name).lower(), 0x03)


def _ber_length(size: int) -> bytes:
    if size < 0x80:
        return bytes([size])
    if size < 0x100:
        return bytes([0x81, size])
    return bytes([0x82]) + struct.pack(">H", size)


def _ber(tag: int, content: bytes = b"") -> bytes:
    return bytes([tag]) + _ber_length(len(content)) + content


def _ber_read(data: bytes, offset: int = 0) -> Tuple[int, bytes, int]:
    """``(tag, content, consumed)`` for the data element at ``offset``."""
    if offset + 2 > len(data):
        return 0, b"", 0
    tag = data[offset]
    size, header = _ber_short(data, offset + 1)
    start = offset + 1 + header
    return tag, data[start:start + size], 1 + header + size


def _ber_short(data: bytes, offset: int) -> Tuple[int, int]:
    """A BER length at ``offset``: ``(size, bytes used)``."""
    if offset >= len(data):
        return 0, 0
    first = data[offset]
    if first < 0x80:
        return first, 1
    count = first & 0x7F
    if count == 0 or offset + 1 + count > len(data):
        return 0, 1
    return int.from_bytes(data[offset + 1:offset + 1 + count], "big"), 1 + count


def _sdp_response(records: Sequence[Dict[str, Any]], transaction: int = 1) -> bytes:
    """A real SDP ServiceSearchAttributeResponse for a device's records.

    Every attribute is a proper data element — attribute 0x0001 is a sequence of UUID16s,
    0x0004 is the protocol descriptor list with the RFCOMM channel inside it, 0x0100 is
    the service name as a text element — because the module's own :func:`wifipilot.bt.parse_sdp`
    reads data elements, and a simulator whose answers the toolkit cannot parse would be
    a simulator of nothing.
    """
    lists = bytearray()
    offset = 0
    for record in records:
        uuid = int(record.get("uuid", 0))
        channel = int(record.get("channel", 1))
        name = str(record.get("name", ""))
        attributes = bytearray()
        attributes += _ber(0x09, struct.pack(">H", 0x0000))                    # record handle
        attributes += _ber(0x0A, struct.pack(">I", 0x00010000 + offset))
        attributes += _ber(0x09, struct.pack(">H", 0x0001))                    # service class
        attributes += _ber(0x35, _ber(0x19, struct.pack(">H", uuid)))
        attributes += _ber(0x09, struct.pack(">H", 0x0004))                    # protocol list
        attributes += _ber(0x35,
                           _ber(0x35, _ber(0x19, struct.pack(">H", 0x0100)))   # L2CAP
                           + _ber(0x35, _ber(0x19, struct.pack(">H", 0x0003))  # RFCOMM
                                  + _ber(0x08, bytes([channel & 0xFF]))))
        attributes += _ber(0x09, struct.pack(">H", 0x0005))                    # browse group
        attributes += _ber(0x35, _ber(0x19, struct.pack(">H", 0x1002)))
        if name:
            attributes += _ber(0x09, struct.pack(">H", 0x0100))
            attributes += _ber(0x25, name.encode()[:40])
        lists += _ber(0x30, bytes(attributes))
        offset += 1
    parameters = _ber(0x35, bytes(lists)) + b"\x00"           # + continuation state
    return struct.pack(">BHH", 0x07, transaction & 0xFFFF, len(parameters)) + parameters


def _obex_response(code: int, extra: bytes = b"") -> bytes:
    """An OBEX response packet: the code, its length, and any headers."""
    body = extra
    length = 3 + len(body)
    return bytes([code, (length >> 8) & 0xFF, length & 0xFF]) + body


def _obex_name(payload: bytes) -> str:
    """The object name inside an OBEX GET, whatever encoding the client used."""
    index = 3
    while index + 2 <= len(payload):
        identifier = payload[index]
        if identifier == 0x01:                                # Name (UTF-16)
            size = int.from_bytes(payload[index + 1:index + 3], "big")
            text = payload[index + 3:index + size]
            return text.decode("utf-16-be", "replace")
        if identifier == 0x05:                                # Name
            size = int.from_bytes(payload[index + 1:index + 3], "big")
            return payload[index + 3:index + size].decode("latin-1", "replace")
        size = int.from_bytes(payload[index + 1:index + 3], "big") or 3
        index += size
    return ""


def _obex_vcard(device: BleDevice, name: str = "") -> bytes:
    """A vCard for one of the phonebook objects, or ``not found`` for anything else."""
    entry = next((candidate for candidate in SNARF_OBJECTS
                  if candidate.split("/")[-1] in (name or "").split("/")[-1]), None)
    if name and not entry:
        return _obex_response(0xC4)                           # not found
    entry = entry or SNARF_OBJECTS[0]
    contact = (f"BEGIN:VCARD\r\nVERSION:2.1\r\nN:Doe;Jane\r\n"
               f"FN:Jane Doe\r\nTEL;CELL:+15550100\r\nTEL;WORK:+15550111\r\n"
               f"EMAIL:jane.doe@example.com\r\nORG:{device.company or 'Example'}\r\n"
               f"END:VCARD\r\n")
    body = contact.encode()
    headers = bt.obex_name_header(entry) + bt.obex_header(0x42, b"text/x-vcard") \
        + bt.obex_header(0x48, body)
    return _obex_response(0xA0, headers)


#: the objects a phone's object store holds, in the order a snarf reads them
SNARF_OBJECTS: Tuple[str, ...] = (
    "telecom/pb.vcf", "telecom/cal.vcs", "telecom/ich.vcf", "telecom/oop.vcf",
    "telecom/pb_intern.vcf", "SIM1/telecom/pb.vcf", "telecom/mch.vcf",
)


# --------------------------------------------------------------------------- #
# the controller: HCI in, H4 packets out
# --------------------------------------------------------------------------- #

#: the HCI commands the simulated controller knows by name, so the dispatch table reads
#: like the specification instead of like a list of numbers
LE_OPCODES = {name: (ogf << 10) | ocf for name, (ogf, ocf) in bt.HCI_COMMANDS.items()}


class VirtualController:
    """A controller that answers for a floor of devices.

    Everything the attacks send arrives here as the H4 packets a real tool would write:
    the advertising and scanning commands, the link-control commands that negotiate a key,
    the ACL data that carries L2CAP — and every answer goes back as the H4 packets a real
    controller would report: Command Complete, Command Status, LE Meta events carrying
    advertising reports, inquiry results, a Connection Complete when a link opens, and
    the peer's own replies as ACL data.
    """

    def __init__(self, airspace: Optional[VirtualBle] = None, seed: int = 0,
                 link: Optional[BleLink] = None) -> None:
        self.ble = airspace if airspace is not None else ble()
        self.rng = random.Random(seed or 7)
        self.pending: List[bytes] = []
        self.commands: List[Dict[str, Any]] = []
        self.advertising = False
        self.scanning = False
        self.advertising_data = b""
        self.scan_response_data = b""
        self.address = "5c:8d:2f:00:00:01"
        self.link = link
        self.connected: List[str] = []
        self.alive = True

    # -- H4 framing ---------------------------------------------------------- #
    @staticmethod
    def _event(code: int, parameters: bytes = b"") -> bytes:
        return bytes([bt.HCI_EVENT_PACKET, code, len(parameters) & 0xFF]) + bytes(parameters)

    def _queue(self, *packets: bytes) -> None:
        for packet in packets:
            if packet:
                self.pending.append(packet)

    def feed(self, packet: bytes) -> None:
        """Take one HCI packet (H4 framed) and queue the controller's answer."""
        if not packet:
            return
        if packet[0] == bt.HCI_COMMAND_PACKET:
            self._command(packet[1:])
        elif packet[0] == bt.HCI_ACL_PACKET:
            self._acl(packet[1:])
        elif packet[0] == bt.HCI_EVENT_PACKET:
            pass                                     # a host event: the controller ignores it

    def take(self) -> bytes:
        """The next event packet, or ``b""`` when there is nothing to report."""
        return self.pending.pop(0) if self.pending else b""

    def has_events(self) -> bool:
        return bool(self.pending)

    # -- commands ------------------------------------------------------------ #
    def _command(self, body: bytes) -> None:
        if len(body) < 3:
            return
        opcode = int.from_bytes(body[0:2], "little")
        length = body[2]
        parameters = body[3:3 + length]
        name = next((key for key, value in LE_OPCODES.items() if value == opcode), "")
        self.commands.append({"opcode": opcode, "name": name or f"0x{opcode:04x}",
                              "parameters": len(parameters)})
        handler = getattr(self, f"_cmd_{_handler_name(name)}", None) if name else None
        if handler is not None:
            handler(opcode, parameters)
            return
        # everything else is acknowledged the way a controller acknowledges a command it
        # has nothing more to say about: a Command Complete, or a Command Status for the
        # commands that answer later
        if opcode >> 10 in (0x08, 0x04):
            self._queue(self._event(bt.HCI_EVENT_COMMAND_COMPLETE,
                                    bytes([1]) + struct.pack("<H", opcode) + b"\x00"))
        else:
            self._queue(self._event(bt.HCI_EVENT_COMMAND_STATUS,
                                    b"\x00" + bytes([1]) + struct.pack("<H", opcode)))

    def _complete(self, opcode: int, status: int = 0, extra: bytes = b"") -> bytes:
        return self._event(bt.HCI_EVENT_COMMAND_COMPLETE,
                           bytes([1]) + struct.pack("<H", opcode) + bytes([status]) + extra)

    def _status(self, opcode: int, status: int = 0) -> bytes:
        return self._event(bt.HCI_EVENT_COMMAND_STATUS,
                           bytes([status]) + bytes([1]) + struct.pack("<H", opcode))

    # -- LE advertising and scanning ----------------------------------------- #
    def _cmd_le_set_advertising_data(self, opcode: int, parameters: bytes) -> None:
        self.advertising_data = parameters[1:] if parameters else b""
        self._queue(self._complete(opcode))

    def _cmd_le_set_scan_response_data(self, opcode: int, parameters: bytes) -> None:
        self.scan_response_data = parameters[1:] if parameters else b""
        self._queue(self._complete(opcode))

    def _cmd_le_set_advertising_parameters(self, opcode: int, parameters: bytes) -> None:
        self._queue(self._complete(opcode))

    def _cmd_le_set_random_address(self, opcode: int, parameters: bytes) -> None:
        if len(parameters) >= 6:
            self.address = bt.mac_text(parameters[0:6])
        self._queue(self._complete(opcode))

    def _cmd_le_set_advertising_enable(self, opcode: int, parameters: bytes) -> None:
        self.advertising = bool(parameters and parameters[0] & 0x01)
        self._queue(self._complete(opcode))

    def _cmd_le_set_scan_parameters(self, opcode: int, parameters: bytes) -> None:
        self._queue(self._complete(opcode))

    def _cmd_le_set_scan_enable(self, opcode: int, parameters: bytes) -> None:
        """A scan answers with the floor: one advertising report per device it hears."""
        enable = bool(parameters and parameters[0] & 0x01)
        self.scanning = enable
        self._queue(self._complete(opcode))
        if not enable:
            return
        for report in self.ble.scan():
            self._queue(self._advertising_report(report))
        self._queue(self._event(bt.HCI_EVENT_LE_META, bytes([0x02, 0x00])))   # nothing more

    def _advertising_report(self, report: Dict[str, Any], channel: int = 0) -> bytes:
        address = bt.mac_bytes(str(report.get("address", "")).replace("-", ":"))
        payload = bytes(report.get("payload") or b"")[:31]
        parameters = bytes([0x02, 0x01]) + bytes([int(report.get("event_type", 0)) & 0xFF,
                                                  int(report.get("address_type", 0)) & 0x01]) \
            + address + bytes([len(payload)]) + payload \
            + bytes([int(report.get("rssi", -60)) & 0xFF])
        # the channel is the byte the scan attack reads as the radio's own report channel
        return self._event(bt.HCI_EVENT_LE_META, parameters)

    def _cmd_inquiry(self, opcode: int, parameters: bytes) -> None:
        """Classic inquiry: a Command Status, an Inquiry Result, an Inquiry Complete."""
        self._queue(self._status(opcode))
        found = self.ble.inquiry()
        # an event carries at most 255 parameter bytes, so the responses are reported in
        # several Inquiry Result events, each with its own count — which is what a real
        # controller does when the room is full of devices
        batch: List[bytes] = []
        for item in found:
            address = bt.mac_bytes(str(item["address"]))
            class_of_device = int(item.get("class_of_device", 0)) | (0x01 << 13)
            batch.append(address + bytes([0x01, 0x00])
                         + int(class_of_device).to_bytes(3, "little") + b"\x00\x00")
            if len(batch) == 15:
                self._queue(self._event(bt.HCI_EVENT_INQUIRY_RESULT,
                                        bytes([len(batch)]) + b"".join(batch)))
                batch = []
        if batch:
            self._queue(self._event(bt.HCI_EVENT_INQUIRY_RESULT,
                                    bytes([len(batch)]) + b"".join(batch)))
        self._queue(self._event(bt.HCI_EVENT_INQUIRY_COMPLETE, b"\x00"))

    # -- links --------------------------------------------------------------- #
    def _device_for(self, handle: int) -> Optional[BleDevice]:
        link = self.ble.links.get(handle) or self.link
        return link.device if link is not None else None

    def _cmd_le_create_connection(self, opcode: int, parameters: bytes) -> None:
        address = bt.mac_text(parameters[7:13]) if len(parameters) >= 13 else ""
        device = self.ble.by_address(address) or self.ble.pick("le")
        link = self.ble.open_link(device, handle=0x0040)
        if link is not None:
            self.link = link
            self.connected.append(link.device.address)
        self._queue(self._status(opcode))
        if link is not None:
            self._queue(self._le_connection_complete(link))

    def _le_connection_complete(self, link: BleLink) -> bytes:
        parameters = bytes([0x01, 0x00]) + struct.pack("<H", link.handle) + bytes([0x00]) \
            + bytes([link.device.address_type & 0x01]) + bt.mac_bytes(link.device.address) \
            + struct.pack("<HHHH", 0x0006, 0x0000, 0x01F4, 0x00) + b"\x00"
        return self._event(bt.HCI_EVENT_LE_META, parameters)

    def _cmd_read_remote_features(self, opcode: int, parameters: bytes) -> None:
        """Read Remote [Extended] Features: the feature pages the peer claims."""
        page = parameters[2] if len(parameters) >= 3 else 0
        handle = int.from_bytes(parameters[0:2], "little") if len(parameters) >= 2 else 0x0040
        device = self._device_for(handle)
        features = device.features(page) if device is not None else b"\x00" * 8
        extended = bool(page) or opcode == LE_OPCODES.get("Read Remote Extended Features", 0)
        code = bt.HCI_EVENT_READ_REMOTE_EXTENDED_FEATURES if extended \
            else bt.HCI_EVENT_READ_REMOTE_SUPPORTED_FEATURES
        payload = bytes([0x00]) + struct.pack("<H", handle)
        if extended:
            payload += bytes([page, 0x02])
        payload += features
        self._queue(self._status(opcode), self._event(code, payload))
        self._queue(self._complete(opcode))

    def _cmd_le_read_remote_features(self, opcode: int, parameters: bytes) -> None:
        handle = int.from_bytes(parameters[0:2], "little") if len(parameters) >= 2 else 0x0040
        device = self._device_for(handle)
        features = device.features(0) if device is not None else b"\x00" * 8
        self._queue(self._status(opcode),
                    self._event(bt.HCI_EVENT_LE_META,
                                bytes([0x04, 0x00]) + struct.pack("<H", handle) + features))

    def _cmd_change_connection_link_key(self, opcode: int, parameters: bytes) -> None:
        """A re-key: the peer is asked for its stored key, or a fresh pairing starts."""
        handle = int.from_bytes(parameters[0:2], "little") if len(parameters) >= 2 else 0x0040
        device = self._device_for(handle)
        self._queue(self._status(opcode))
        if device is not None and device.bondable:
            self._queue(self._event(0x17, bt.mac_bytes(device.address)))   # link key request
            self._queue(self._event(0x36, b"\x00" + bt.mac_bytes(device.address)))
        self._queue(self._complete(opcode))

    def _cmd_authentication_requested(self, opcode: int, parameters: bytes) -> None:
        handle = int.from_bytes(parameters[0:2], "little") if len(parameters) >= 2 else 0x0040
        device = self._device_for(handle)
        self._queue(self._status(opcode))
        if device is None:
            self._queue(self._event(0x06, b"\x05" + struct.pack("<H", handle)))
            return
        flags = device.flags
        if flags.get("link_key") is not False:
            self._queue(self._event(0x17, bt.mac_bytes(device.address)))
        status = 0x00
        if flags.get("secure_connections") and not flags.get("just_works"):
            status = 0x05                          # authentication failure: legacy refused
        self._queue(self._event(0x06, bytes([status]) + struct.pack("<H", handle)))
        if status == 0x00 and not flags.get("secure_connections"):
            self._queue(self._event(0x36, b"\x00" + bt.mac_bytes(device.address)))

    def _cmd_set_connection_encryption(self, opcode: int, parameters: bytes) -> None:
        """Encryption Change carries the key size — the number KNOB is measured in."""
        handle = int.from_bytes(parameters[0:2], "little") if len(parameters) >= 2 else 0x0040
        enable = bool(parameters[2]) if len(parameters) >= 3 else True
        device = self._device_for(handle)
        self._queue(self._status(opcode))
        key_size = int(device.flags.get("key_size", 16)) if device is not None else 16
        link = self.ble.links.get(handle) or self.link
        if link is not None and enable:
            link.encrypted = True
            link.key_size = key_size
        self._queue(self._event(0x08, b"\x00" + struct.pack("<H", handle)
                                + bytes([1 if enable else 0, key_size if enable else 0])))

    def _cmd_disconnect(self, opcode: int, parameters: bytes) -> None:
        handle = int.from_bytes(parameters[0:2], "little") if len(parameters) >= 2 else 0x0040
        reason = parameters[2] if len(parameters) >= 3 else 0x13
        self._queue(self._status(opcode))
        link = self.ble.links.get(handle) or self.link
        if link is not None:
            self.ble.close_link(link, f"host disconnect 0x{reason:02x}")
        self._queue(self._event(bt.HCI_EVENT_DISCONNECTION_COMPLETE,
                                b"\x00" + struct.pack("<H", handle) + bytes([reason])))

    # -- ACL: the peer's own protocols --------------------------------------- #
    def _acl(self, body: bytes) -> None:
        if len(body) < 4:
            return
        handle = int.from_bytes(body[0:2], "little") & 0x0FFF
        length = int.from_bytes(body[2:4], "little")
        data = body[4:4 + length]
        link = self.ble.links.get(handle)
        if link is None and self.link is not None:
            link = self.link
            self.ble.links[handle] = link
        if link is None or not data:
            return
        device = link.device
        if not link.alive:
            return                                     # a stack that has stopped answering
        if len(data) < 4:
            self._queue(self._ll_control(link, data))
            return
        size = int.from_bytes(data[0:2], "little")
        cid = int.from_bytes(data[2:4], "little")
        payload = data[4:4 + size] if size else data[4:]
        if cid in (0x0001, 0x0005):                    # signalling (BR/EDR and LE)
            answer = self.ble.signalling(device, payload, link)
        elif cid == 0x0004:                            # ATT
            answer = self.ble.att_request(device, payload, link)
        elif cid == 0x0006:                            # SMP
            answer = self.ble.smp_request(device, payload, link)
        else:                                          # a dynamic channel: SDP, RFCOMM, OBEX
            answer = self._dynamic(link, payload)
        if not link.alive:
            return
        if answer:
            self._queue(bt.acl_packet(link.handle, bt.l2cap_frame(cid, answer)))
        elif payload[:1] in (b"\x52", b"\x1b", b"\x1d"):     # a write command needs no answer
            self._queue(self._event(0x13, bytes([1]) + struct.pack("<H", link.handle)
                                    + struct.pack("<H", 1)))

    def _dynamic(self, link: BleLink, payload: bytes) -> bytes:
        """A dynamic L2CAP channel: SDP on PSM 1, RFCOMM (and OBEX inside it) above it."""
        if not payload:
            return b""
        device = link.device
        if payload[0] in (0x02, 0x04, 0x06, 0x08, 0x0A):
            return self.ble.sdp_request(device, payload)
        if payload[0] in bt.OBEX_REQUESTS:
            return self.ble.obex_request(device, payload)
        if device.flags.get("at") and device.at_name:
            return self.ble.at_command(device, payload)
        return self.ble.obex_request(device, payload)

    def _ll_control(self, link: BleLink, data: bytes) -> bytes:
        """A bare link-layer control PDU: a ping answers, and a fragile stack may not."""
        device = link.device
        opcode = data[0]
        fragile = "ll" in str(device.flags.get("fragile", ""))
        if fragile and opcode == 0x14 and len(data) < 6:
            # a length request whose body is shorter than the eight bytes the opcode
            # implies, which is the family of malformed PDU SweynTooth is named for
            link.dies("truncated LL_LENGTH_REQ")
            return b""
        if fragile and opcode in (0x14, 0xFE):
            link.dies(f"malformed LL control PDU 0x{opcode:02x}")
            return b""
        if opcode == 0x12:                                  # LL_PING_REQ
            return bt.acl_packet(link.handle, bytes([0x13]))     # LL_PING_RSP
        if opcode == 0x13:                                  # an unsolicited PING_RSP
            return b""
        if opcode in (0x18, 0x14):                          # LL_LENGTH_REQ / RSP
            return bt.acl_packet(link.handle,
                                 bytes([0x15 if opcode == 0x14 else 0x14])
                                 + struct.pack("<HHHH", 251, 2120, 251, 2120))
        if opcode == 0x08:                                  # LL_FEATURE_REQ
            page = data[1] if len(data) > 1 else 0
            if page not in (0, 1):
                return b""
            return bt.acl_packet(link.handle, bytes([0x09])
                                 + device.features(min(page, 2))[:8])
        if opcode in (0x0A, 0x0B):                          # version exchange
            return bt.acl_packet(link.handle, bytes([0x0C, 0x09, 0x00, 0x00, 0x05]))
        if fragile:
            link.dies(f"unhandled LL control PDU 0x{opcode:02x}")
            return b""
        # the specification has the peer answer a PDU it does not implement with
        # LL_UNKNOWN_RSP, and a controller that does is one SweynTooth does *not* take
        # down: the answer is what separates a patched stack from a quiet one
        return bt.acl_packet(link.handle, bytes([0x07, opcode]))


def _handler_name(name: str) -> str:
    """``"LE Set Scan Enable"`` -> ``"le_set_scan_enable"``: the handler's suffix."""
    return "".join(character.lower() if character.isalnum() else "_" for character in name) \
        .strip("_").replace("__", "_")


# --------------------------------------------------------------------------- #
# the sockets an attack talks through
# --------------------------------------------------------------------------- #

class DemoHciSocket:
    """The controller, behind the three methods :func:`wifipilot.bt.hci_send` uses.

    ``send`` hands the controller an H4 packet and ``recv`` takes the answer, so every
    attack that writes HCI runs its real code path in demo mode: the same commands, the
    same parsers, the same transcripts.  ``has_events`` is what lets a scan loop stop
    instead of waiting out its own timeout — an event queue can be empty and finished,
    which a socket cannot say.
    """

    simulated = True

    def __init__(self, controller: VirtualController) -> None:
        self.controller = controller
        self.timeout = 1.0
        self.closed = False

    # -- the socket interface ------------------------------------------------ #
    def send(self, packet: bytes) -> int:
        if self.closed:
            return 0
        self.controller.feed(bytes(packet))
        return len(packet)

    def recv(self, size: int = 4096) -> bytes:
        if self.closed:
            return b""
        return self.controller.take()[:size]

    def settimeout(self, value: float) -> None:
        self.timeout = value

    def gettimeout(self) -> float:
        return self.timeout

    def has_events(self) -> bool:
        return self.controller.has_events()

    def close(self) -> None:
        self.closed = True

    def fileno(self) -> int:
        raise OSError("the simulated controller has no file descriptor")

    @property
    def airspace(self) -> VirtualBle:
        return self.controller.ble


class DemoRfcommSocket:
    """An RFCOMM channel to a simulated device: bytes in, the peer's bytes out.

    AT commands and OBEX requests travel over the same serial profile, so one socket
    serves both: what the payload *is* decides which engine answers, exactly as it does
    on a real device, and a channel the device does not offer is not open at all.
    """

    simulated = True

    def __init__(self, airspace: VirtualBle, device: BleDevice, channel: int) -> None:
        self.ble = airspace
        self.device = device
        self.channel = channel
        self.buffer = bytearray()
        self.timeout = 1.0
        self.closed = False

    def send(self, data: bytes) -> int:
        if self.closed or not data:
            return 0
        payload = bytes(data)
        if payload[0] in bt.OBEX_REQUESTS:
            answer = self.ble.obex_request(self.device, payload)
        else:
            answer = self.ble.at_command(self.device, payload)
        if answer:
            self.buffer += answer
        return len(payload)

    def recv(self, size: int = 4096) -> bytes:
        if self.closed or not self.buffer:
            return b""
        chunk = bytes(self.buffer[:size])
        del self.buffer[:size]
        return chunk

    def settimeout(self, value: float) -> None:
        self.timeout = value

    def gettimeout(self) -> float:
        return self.timeout

    def close(self) -> None:
        self.closed = True

    def fileno(self) -> int:
        raise OSError("the simulated channel has no file descriptor")


# --------------------------------------------------------------------------- #
# the singleton, and how an attack finds a target
# --------------------------------------------------------------------------- #

_BLE: Optional[VirtualBle] = None


def ble(seed: int = 7, rebuild: bool = False) -> VirtualBle:
    """The simulated airspace, built once and reused (the way ``itsvc.demo_lan`` does)."""
    global _BLE
    if _BLE is None or rebuild:
        _BLE = VirtualBle(seed=seed)
    return _BLE


def reset_ble(seed: int = 7) -> VirtualBle:
    """Build the floor again: a test wants the same addresses as yesterday's run."""
    airspace = ble(seed=seed, rebuild=True)
    reset_targets()
    return airspace


#: which role an attack needs.  A demo run picks the weakest device that can answer the
#: question the attack is about — an AT channel for BlueBugging, an object store for
#: BlueSnarfing, a fragile stack for BlueBorne — instead of the first address it sees.
ATTACK_ROLES: Dict[str, str] = {
    "bt_le_scan": "le", "bt_hci_inquiry": "bredr", "bt_device_census": "le",
    "bt_sdp_browse": "sdp", "bt_rfcomm_discovery": "rfcomm", "bt_gatt_enumeration": "gatt",
    "bt_advertising_flood": "le", "bt_beacon_clone": "beacon", "bt_tracker_clone": "tracker",
    "bt_connectable_lure": "le", "bt_pairing_flood": "smp", "bt_l2cap_echo_flood": "l2cap",
    "bt_blueborne": "fragile", "bt_bias": "bredr", "bt_knob": "bredr",
    "bt_bluebugging": "at", "bt_blesa": "gatt", "bt_sweyntooth": "fragile",
    "bt_bluesnarf": "obex", "bt_bluesmack": "l2cap", "bt_hid_injection": "hid",
}

#: the device classes that *are* a HID host: keystroke injection ends on a machine that
#: takes input, and a keyboard is not one of them
HID_HOSTS: Tuple[str, ...] = ("desktop pc", "mobile phone", "tablet", "smart tv", "laptop")

#: the roles a device is *moving through*: after a sweep has tried every device of a
#: role it comes back to the first, so a wave of attacks does not all land on one
_CURSOR: Dict[str, int] = {}
#: what a role is aimed at, once it has been decided.  An attack asks twice — once for
#: the address it reports and once for the socket it talks through — and both answers
#: have to be the same device, or the report names a phone while the controller has
#: opened a link to a scooter.
_CHOSEN: Dict[Any, str] = {}


def role_for(name: str, default: str = "any") -> str:
    return ATTACK_ROLES.get(str(name), default)


def target_key(name: str, role: str = "") -> Any:
    """What a choice is remembered under: the attack's own aim, or its role."""
    return (str(name), role) if name else (role, "")


def choose_target(name: str = "", ctx: Any = None, role: str = "") -> str:
    """The address an attack should aim at in demo mode: the weakest that can answer.

    The choice walks the floor rather than repeating it: the sweeps run their attacks
    over the same airspace, so each device of a role takes a turn at being the target,
    and a run that meets a hardened device reports the refusal that device earned.  It is
    remembered per attack *and* per role, so the address the report prints and the device
    behind the socket are one and the same.
    """
    airspace = ble()
    wanted = role or role_for(name)
    key = target_key(name, wanted)
    if key in _CHOSEN:
        return _CHOSEN[key]
    found = airspace.candidates(wanted)
    if not found:
        found = airspace.candidates("l2cap") or airspace.devices
    if not found:
        return ""
    cursor = _CURSOR.get(wanted, 0)
    chosen = found[cursor % len(found)]
    _CURSOR[wanted] = cursor + 1
    _CHOSEN[key] = chosen.address
    return chosen.address


def reset_targets() -> None:
    """Forget every remembered aim (used with :func:`reset_ble` in the tests)."""
    _CURSOR.clear()
    _CHOSEN.clear()


def controller_socket(ctx: Any = None, address: str = "", role: str = "any",
                      name: str = "") -> DemoHciSocket:
    """An HCI socket backed by the simulation, linked to the run's target device."""
    airspace = ble()
    wanted = address or (getattr(getattr(ctx, "config", None), "bt_target", "") or "")
    if not wanted:
        attack = name or getattr(ctx, "bt_attack", "")
        wanted = choose_target(attack, role=role or "any")
    device = airspace.by_address(wanted) if wanted else None
    if device is None:
        device = airspace.pick(role or "l2cap") or airspace.pick("any")
    link = airspace.open_link(device, handle=0x0040) if device is not None else None
    controller = VirtualController(airspace, seed=abs(hash(wanted or "sim")) % 997,
                                  link=link)
    return DemoHciSocket(controller)


def rfcomm_socket(ctx: Any = None, address: str = "", channel: int = 1,
                  name: str = "") -> Optional[DemoRfcommSocket]:
    """A simulated RFCOMM channel: ``None`` when the device does not offer that one."""
    airspace = ble()
    wanted = address or (getattr(getattr(ctx, "config", None), "bt_target", "") or "")
    device = airspace.by_address(wanted) if wanted else None
    if device is None:
        device = airspace.pick(role_for(name or "", "rfcomm")) or airspace.pick("at")
    if device is None:
        return None
    offered = set(device.channels) or {1}
    if int(channel) not in offered:
        return None
    return DemoRfcommSocket(airspace, device, int(channel))


# --------------------------------------------------------------------------- #
# the capture the offline audits read
# --------------------------------------------------------------------------- #

def write_capture(path: str, seconds: float = 20.0, seed: int = 7,
                  base_time: float = 1_700_000_000.0) -> str:
    """Write the simulated floor as a real BLE capture (link type 256).

    The offline audits do not talk to a radio; they read a capture.  This writes *the
    same floor* the on-air attacks meet — the same addresses, beacons, trackers and
    intervals — plus one connection whose security manager, attribute table and link
    layer are all visible, so a report on the radio and a report on the capture describe
    one estate rather than two.
    """
    airspace = ble(seed=seed)
    records: List[bytes] = []
    times: List[float] = []

    def emit(moment: float, pdu: bytes, channel: int, rssi: int,
             access_address: bytes = b"") -> None:
        records.append(bt.le_wrapper(pdu, channel=channel, rssi=rssi,
                                     access_address=access_address))
        times.append(base_time + moment)

    rng = random.Random(seed)
    for index, device in enumerate(airspace.devices):
        if device.kind == "bredr":
            continue
        interval = max(0.02, float(device.interval_ms) / 1000.0)
        moment = rng.random() * 0.05
        step = 0
        while moment < seconds:
            address = device.address
            if device.rotate:
                address = bt.resolvable_private_address(
                    hashlib.sha256(device.address.encode()).digest()[:4], seed=step)
            payload = device.ad_payload()
            pdu = bt.adv_pdu(device.pdu_type(), address, payload)
            rssi = device.rssi + ((step * 7 + index) % 5) - 2
            emit(moment, pdu, device.channel, rssi)
            if device.scan_name and step % 4 == 1:
                response = bt.adv_pdu(0x04, address, bt.adv_payload(*device.scan_structures()))
                emit(moment + 0.002, response, device.channel, rssi)
            moment += interval
            step += 1

    # -- one connection, in full: the pairing, the attribute table, the link layer ----- #
    target = airspace.pick("gatt") or (airspace.devices[0] if airspace.devices else None)
    if target is not None:
        link = bytes([0x4B, 0x1C, 0x2B, 0x00])
        moment = seconds + 0.25

        def data(llid: int, payload: bytes, when: float) -> None:
            header = bytes([llid & 0x03, len(payload) & 0x1F])
            emit(when, link + header + payload, 37, -64, access_address=link)

        def l2cap(cid: int, body: bytes) -> bytes:
            return struct.pack("<HH", len(body), cid) + body

        emit(moment - 0.05,
             bt.adv_pdu(0x05, target.address,
                        link + bytes([0x18, 0x00]) + (0x0006).to_bytes(2, "little")
                        + (0x0000).to_bytes(2, "little") + (0x0018).to_bytes(2, "little")
                        + (0x01A0).to_bytes(2, "little")
                        + (0xFFFFFFFF1F).to_bytes(5, "little") + bytes([0x25]),
                        ch_sel=False, peer_address=target.address),
             37, -64)
        # the feature exchange, then the pairing the profile permits: a device whose
        # profile allows Just Works has one in the capture, and a hardened one has the
        # Secure Connections request it would have sent instead
        features = (1 << 0) | (1 << 4) | (1 << 5) | (1 << 8) | (1 << 14)
        data(3, bytes([0x0A]) + features.to_bytes(8, "little"), moment)
        flags = target.flags
        auth = (0x01 if flags.get("bonding") else 0x00) | (0x04 if flags.get("mitm") else 0x00) \
            | (0x08 if flags.get("secure_connections") else 0x00)
        data(2, l2cap(0x0006, bytes([0x01, 0x03, 0x00, auth,
                                     int(flags.get("key_size", 16)), 0x0F, 0x0F])),
             moment + 0.02)
        data(2, l2cap(0x0004, bytes([0x10, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28])),
             moment + 0.04)
        services = target.att_services()[:2] or [(1, 10, 0x1800)]
        entries = b"".join(struct.pack("<HHH", start, end, uuid)
                           for start, end, uuid in services)
        data(2, l2cap(0x0004, bytes([0x11, 6]) + entries), moment + 0.06)
        data(3, bytes([0x04]) + bytes(range(8)) + bytes(range(8, 16)), moment + 0.08)

    bt.write_le_pcap(path, records, times=times)
    return str(path)


def summary() -> Dict[str, Any]:
    """What the simulated floor is, for a CLI or an API to print."""
    airspace = ble()
    by_profile: Dict[str, int] = {}
    by_device: Dict[str, int] = {}
    roles: Dict[str, int] = {}
    for device in airspace.devices:
        by_profile[device.profile] = by_profile.get(device.profile, 0) + 1
        by_device[device.device] = by_device.get(device.device, 0) + 1
        for role in airspace.roles_of(device):
            roles[role] = roles.get(role, 0) + 1
    return {"devices": len(airspace.devices), "profiles": len(PROFILES),
            "by_profile": by_profile, "by_device": by_device, "roles": roles,
            "trackers": sum(1 for device in airspace.devices if device.tracker),
            "beacons": sum(1 for device in airspace.devices if device.beacon),
            "classic": sum(1 for device in airspace.devices if device.kind != "le"),
            "gatt_servers": sum(1 for device in airspace.devices if device.gatt),
            "taken_down": [device.address for device in airspace.devices if device.crashes],
            "rssi_range": [min(device.rssi for device in airspace.devices),
                           max(device.rssi for device in airspace.devices)]}
