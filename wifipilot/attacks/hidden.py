"""Hidden SSID discovery: learn the name of a network that hides it.

An AP that clears the SSID field of its beacons is not invisible: the SSID is
still in the clear in every beacon *probe response*, in the association request of
any client joining it, and in the WPA handshake itself.  So the attack listens —
nothing else — and names the network.

It is a real attack despite transmitting nothing, because it changes what the
engagement knows: a hidden BSSID becomes a target with a name, which is what the
planner, the vendor dossier and the mask generator all need.  Where a client is
not currently associating, the ``reveal_with_probe`` flag asks the AP directly with a
wildcard probe request — a misconfigured AP answers with the name it is hiding.
That is opt-in because it is the only part of this that transmits, and the operator
is the one who decides when a radio goes live.
"""

from __future__ import annotations

import contextlib
import os
import time

from ..deps import registry
from ..events import EK
from ..models import STATUS_FAILED, STATUS_SUCCESS, AccessPoint, Attempt, Capture
from ..pcap import analyze_file
from ..util import Process, human_duration, mac_norm
from .base import Attack, AttackContext, AttackOutcome


class HiddenSsidAttack(Attack):
    name = "hidden_ssid"
    label = "Hidden SSID discovery"
    tool = "airodump-ng"
    description = ("Watch a hidden AP until a client reveals its name (probe "
                   "response, association or handshake), optionally asking for it "
                   "with a directed probe.  Turns '<hidden>' into a target.")
    requires = ("airodump",)
    needs_injection = False
    applies_to = ("WPA", "WPA2", "WPA2/WPA3", "WPA3", "WEP", "OPEN")

    def applies(self, ap: AccessPoint) -> bool:
        return bool(ap.hidden or not ap.essid)

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(
            self.name, ap.bssid, tool=self.tool,
            chosen_by=getattr(ap, "picked_by", "heuristic"),
            reason=getattr(ap, "pick_reason", ""),
        )
        if ap.essid:
            return AttackOutcome.skipped(f"SSID already known ({ap.essid})")
        timeout = min(ctx.config.attack_timeout_for("passive"), 120.0)
        if ctx.demo:
            return self._run_demo(ctx, ap, attempt, timeout)
        return self._run_live(ctx, ap, attempt, timeout)

    # ---------------------------------------------------------------- #
    def _reveal(self, ctx: AttackContext, ap: AccessPoint, essid: str,
                source: str) -> AttackOutcome:
        ap.essid = essid
        ap.hidden = False
        ap.remember("revealed", f"SSID {essid!r} learned via {source}")
        ctx.session.stats.hidden_revealed += 1
        ctx.bus.publish(EK.AP_UPDATE, {"bssid": ap.bssid, "ssid": essid,
                                       "reason": f"hidden SSID revealed via {source}"})
        ctx.log(f"hidden SSID of {ap.bssid} revealed: {essid!r} (via {source})",
                level="ok", bssid=ap.bssid)
        return AttackOutcome.success(
            f"SSID revealed: {essid}",
            detail=f"learned from {source} — wifipilot transmitted "
                   f"{'a directed probe' if source == 'directed probe' else 'nothing'}",
            extra={"essid": essid, "source": source})

    def _run_demo(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                  timeout: float) -> AttackOutcome:
        radio = ctx.radio
        demo_ap = radio.find(ap.bssid) if radio else None
        deadline = time.time() + min(timeout, 20)
        step = 0
        while time.time() < deadline and not ctx.want_stop():
            step += 1
            ctx.progress(f"watching hidden AP {ap.bssid} for its name", kind="capture",
                         bssid=ap.bssid, percent=min(95, step * 20),
                         detail="beacons carry no SSID · waiting for a client")
            time.sleep(0.6)
            if demo_ap is not None and demo_ap.hidden and step >= 2:
                revealed = getattr(demo_ap, "hidden_name", "") or demo_ap.essid
                outcome = self._reveal(ctx, ap, revealed or "HiddenNet",
                                       "probe response (simulated)")
                ctx.session.end_attempt(attempt, STATUS_SUCCESS, outcome.result,
                                        outcome.detail)
                return outcome
        ctx.session.end_attempt(attempt, STATUS_FAILED, "SSID stayed hidden",
                                f"{int(timeout)}s without a probe response")
        return AttackOutcome.failed(
            "SSID stayed hidden",
            "no client associated and no directed probe was answered")

    def _run_live(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                  timeout: float) -> AttackOutcome:
        airodump = registry.path("airodump-ng")
        if not airodump:
            return self._fail(ctx, attempt, "airodump-ng missing",
                              "install aircrack-ng")
        prefix = ctx.artifact_path("hidden", ap, "")
        cap_path = prefix + "-01.cap"
        channel = ap.channel or 0
        ctx.set_channel(channel)
        args = [airodump, ctx.monitor]
        if channel:
            args += ["-c", str(channel)]
        args += ["--bssid", ap.bssid, "-w", prefix, "--output-format", "pcap",
                 "--write-interval", "1", "--ignore-negative-one"]
        probe = None
        if getattr(ctx.config, "reveal_with_probe", False):
            # The one part that transmits, and the reason it is opt-in: a probe
            # request for the *wildcard* SSID.  A correctly configured AP hides the
            # name even from that; a surprising number answer with it in the clear,
            # which is the whole reason this is worth asking.  (Probing for a name
            # we already know would answer a question we have.)
            mdk = registry.path("mdk4")
            if mdk and not ctx.config.stealth:
                args = [mdk, ctx.monitor, "p", "-t", ap.bssid]
                if channel:
                    args += ["-c", str(channel)]
                probe = Process(args, name="mdk4", echo_lines=ctx.config.verbose_tools)
                probe.start()
                if probe.error:
                    probe = None
            else:
                ctx.log("reveal_with_probe asked for, but mdk4 is unavailable or "
                        "stealth mode is on: listening only", level="warning")
        proc = Process(args, name="airodump-ng", echo_lines=ctx.config.verbose_tools)
        proc.start()
        if proc.error:
            if probe:
                with contextlib.suppress(Exception):
                    probe.stop()
            return self._fail(ctx, attempt, "could not start airodump-ng", proc.error)

        started = time.time()
        essid = ""
        try:
            while not ctx.want_stop() and time.time() - started < timeout:
                time.sleep(1.5)
                ctx.progress(f"watching hidden AP {ap.bssid} for its name", kind="capture",
                             bssid=ap.bssid,
                             percent=min(95, (time.time() - started) / timeout * 100),
                             detail="beacon/probe/association frames only")
                if not os.path.exists(cap_path) or not os.path.getsize(cap_path):
                    continue
                analysis = analyze_file(cap_path, max_packets=60000)
                essid = analysis.essids.get(mac_norm(ap.bssid), "") or ""
                if not essid:
                    essid = next((name for name in analysis.essids.values() if name), "")
                if essid:
                    break
        finally:
            with contextlib.suppress(Exception):
                proc.stop()
            if probe is not None:
                with contextlib.suppress(Exception):
                    probe.stop()
        if not essid:
            return self._fail(ctx, attempt, "SSID stayed hidden",
                              f"{human_duration(time.time() - started)} without a "
                              f"probe response or association")
        saved = ctx.session.save_artifact(cap_path, "hidden", ctx.loot_name(ap, "hidden"))
        capture = Capture(kind="handshake", bssid=ap.bssid, essid=essid, path=saved,
                          valid=True, tool="airodump-ng",
                          extra={"revealed": True, "source": "probe response"})
        ctx.session.add_capture(capture)
        outcome = self._reveal(ctx, ap, essid, "probe response")
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, outcome.result, outcome.detail,
                                capture)
        return outcome
