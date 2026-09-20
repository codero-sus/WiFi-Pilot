"""Listen-only attack: harvest whatever the network broadcasts anyway."""

from __future__ import annotations

import contextlib
import os
import time
from typing import Optional

from ..deps import registry
from ..models import STATUS_SUCCESS, AccessPoint, Attempt, Capture
from ..util import Process, human_duration
from .base import Attack, AttackContext, AttackOutcome


class PassiveAttack(Attack):
    name = "passive"
    label = "Passive capture"
    tool = "airodump-ng"
    description = ("Never transmits. Records beacons, probes, EAPOL frames and PMKIDs "
                   "that happen to be on air — the zero-risk option for a first pass "
                   "or for networks where disruption is not allowed.")
    requires = ("airodump",)
    needs_injection = False

    def applies(self, ap: AccessPoint) -> bool:
        return True

    def available(self, ctx: AttackContext) -> bool:
        return bool(ctx.demo or registry.has("airodump-ng"))

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(
            self.name, ap.bssid, tool=self.tool, chosen_by=getattr(ap, "picked_by", "heuristic"),
            reason=getattr(ap, "pick_reason", ""),
        )
        duration = ctx.config.attack_timeout_for(self.name)
        channel = ap.channel or 0
        if ctx.demo:
            deadline = time.time() + min(duration, 30)
            step = 0
            while time.time() < deadline and not ctx.want_stop():
                step += 1
                ctx.progress(f"passive capture · {ap.display_name}", kind="capture",
                             bssid=ap.bssid, percent=min(95, step * 12),
                             detail="listening (no frames transmitted)")
                time.sleep(0.7)
                if ctx.radio.handshake_ok(ap.bssid, 1) and step > 2:
                    from .handshake import HandshakeAttack
                    path = ctx.artifact_path("handshakes", ap, ".cap")
                    demo_ap = ctx.radio.find(ap.bssid)
                    HandshakeAttack._write_placeholder(
                        path, ap, password=(demo_ap.psk if demo_ap else ""))
                    saved = ctx.session.save_artifact(path, "handshake",
                                                      ctx.loot_name(ap, "handshake"))
                    capture = Capture(kind="handshake", bssid=ap.bssid, essid=ap.essid,
                                      path=saved, valid=True, tool="airodump-ng (simulated)",
                                      eapol=3, extra={"simulated": True})
                    ctx.session.add_capture(capture)
                    ctx.session.end_attempt(attempt, STATUS_SUCCESS,
                                            "handshake seen passively", "", capture)
                    return AttackOutcome.success("handshake seen passively", capture,
                                                 "captured without transmitting")
            return self._fail(ctx, attempt, "nothing captured passively",
                              f"{int(duration)}s of listening")

        airodump = registry.path("airodump-ng")
        if not airodump:
            return self._fail(ctx, attempt, "airodump-ng missing", "install aircrack-ng")
        prefix = ctx.artifact_path("handshakes", ap, "")
        cap_path = prefix + "-01.cap"
        args = [airodump, ctx.monitor]
        if channel:
            args += ["-c", str(channel)]
        args += ["--bssid", ap.bssid, "-w", prefix, "--output-format", "pcap,csv",
                 "--write-interval", "1", "--ignore-negative-one"]
        proc = Process(args, name="airodump-ng", echo_lines=ctx.config.verbose_tools)
        proc.start()
        if proc.error:
            return self._fail(ctx, attempt, "airodump-ng failed", proc.error)
        started = time.time()
        try:
            while not ctx.want_stop() and time.time() - started < duration:
                time.sleep(1.5)
                ctx.progress(f"passive capture · {ap.display_name}", kind="capture",
                             bssid=ap.bssid, percent=min(95, (time.time() - started) / duration * 100),
                             detail="listening (no frames transmitted)")
                if os.path.exists(cap_path) and os.path.getsize(cap_path) > 0:
                    from ..pcap import analyze_file
                    analysis = analyze_file(cap_path, max_packets=60000)
                    if analysis.has_handshake or analysis.has_pmkid:
                        kind = "handshake" if analysis.has_handshake else "pmkid"
                        return self._succeed(ctx, ap, attempt, kind, cap_path, "airodump-ng",
                                             f"{kind} observed passively",
                                             "no frames were transmitted by wifipilot",
                                             eapol=analysis.eapol_messages,
                                             extra={"analysis": analysis.to_dict()})
        finally:
            with contextlib.suppress(Exception):
                proc.stop()
        return self._fail(ctx, attempt, "nothing captured passively",
                          f"{human_duration(duration)} of listening produced no handshake/PMKID")
