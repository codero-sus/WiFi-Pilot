# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""WPA3: the SAE capture and the audit that says where the network is still reachable.

WPA3 is the one security type where the honest answer to "did it fall?" is *no*:
SAE is a password-authenticated key exchange, so a captured commit/confirm exchange
cannot be checked against a wordlist no matter how long the cracking rig runs.  Two
attacks follow from that, and neither of them pretends otherwise.

* ``saewolf`` captures the SAE exchange for the report and answers the questions a
  capture *can* answer: which group the network uses, whether a full exchange was
  recorded, and — the useful part — whether the network also advertises PSK, in which
  case its WPA2 door is still open and the handshake attack is the way in.
* ``pmf_audit`` reads the RSN elements and reports exactly which of the classic
  attacks remain possible: no required PMF means a deauth can force a handshake,
  transition mode means there is a handshake to force at all, and an OWE transition
  SSID is the shape a downgrade twin imitates.

Both are read-only, so neither is gated by the authorisation prompt — a network's
*documented* weakness is not an intrusion.
"""

from __future__ import annotations

import contextlib
import os
import time
from typing import Dict

from ..deps import registry
from ..models import STATUS_SUCCESS, AccessPoint, Attempt, Capture
from ..synth import build_wpa3_capture
from ..util import Process, human_duration
from ..wpa3 import capture_wpa3, sae_exchange, wpa3_findings
from .base import Attack, AttackContext, AttackOutcome


class SaeWolfAttack(Attack):
    name = "saewolf"
    label = "WPA3 SAE capture (dragonslayer)"
    tool = "airodump-ng + wpa3.py (SAE/PMF decoder)"
    description = ("Capture a WPA3 SAE commit/confirm exchange and report the group, "
                   "whether the exchange completed, and whether the network also "
                   "offers a WPA2 AKM.  SAE cannot be checked offline, so this attack "
                   "hunts the WPA2 path, not the WPA3 one.")
    requires = ("airodump",)
    needs_injection = False
    applies_to = ("WPA3", "WPA2/WPA3", "OWE", "WPA2")

    def applies(self, ap: AccessPoint) -> bool:
        return bool(ap.sae or "WPA3" in (ap.encryption or "") or ap.sai)

    # ---------------------------------------------------------------- #
    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(
            self.name, ap.bssid, tool=self.tool,
            chosen_by=getattr(ap, "picked_by", "heuristic"),
            reason=getattr(ap, "pick_reason", ""),
        )
        if not self.applies(ap):
            ctx.session.end_attempt(attempt, "skipped", "not a WPA3 network")
            return AttackOutcome.skipped(
                "not a WPA3 network", f"{ap.display_name} uses {ap.encryption or 'PSK'}")
        if ctx.demo:
            return self._demo(ctx, ap, attempt)
        return self._live(ctx, ap, attempt)

    # ---------------------------------------------------------------- #
    def _report(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                path: str, simulated: bool) -> AttackOutcome:
        exchange = sae_exchange(path)
        rsn = capture_wpa3(path)
        findings = wpa3_findings(rsn.get("networks") or [])
        for finding in findings:
            if finding["bssid"] not in ("", ap.bssid):
                continue
            _add_finding_once(ctx, finding, ap.bssid)

        complete = int(exchange.get("complete") or 0)
        entries = exchange.get("exchanges") or []
        group = entries[0]["group"] if entries else ""
        transition = any((entry.get("rsn") or {}).get("transition_mode")
                         for entry in (rsn.get("networks") or []))
        # the AP's own flags are the fallback when the capture has no beacon
        if not rsn.get("networks"):
            transition = bool(ap.sai or (ap.sae and "WPA2" in (ap.encryption or "")))

        parts = [f"SAE exchange: {complete} complete"]
        if group:
            parts.append(f"group {group}")
        parts.append(f"{exchange.get('auth_frames', 0)} SAE frame(s)")
        parts.append("WPA2 path advertised (transition mode)" if transition
                     else "no WPA2 path advertised")
        if simulated:
            parts.append("simulated")
        detail = "; ".join(parts)

        saved = ""
        if path and os.path.exists(path):
            saved = ctx.session.save_artifact(path, "saewolf", ctx.loot_name(ap, "wpa3"))
            ctx.session.add_capture(Capture(
                kind="handshake", bssid=ap.bssid, essid=ap.essid, path=saved,
                valid=complete > 0, tool="airodump-ng", extra={"sae": True,
                                                               "simulated": simulated}))

        ap.remember("sae_capture", detail, group=group, transition=transition)
        ctx.session.stats.sae_captures += 1
        actionable = ("the WPA2 path is the way in: run the handshake attack"
                      if transition else
                      "no WPA2 path: nothing here falls to an offline attack")
        ctx.bus.log(f"WPA3 survey of {ap.display_name}: {detail} — {actionable}",
                    level="info")
        ctx.session.end_attempt(attempt, STATUS_SUCCESS,
                                "SAE exchange captured" if complete else "WPA3 surveyed",
                                detail)
        return AttackOutcome.success(
            "SAE exchange captured" if complete else "WPA3 surveyed",
            detail=f"{detail} — {actionable}",
            extra={"sae_frames": exchange.get("auth_frames", 0),
                   "complete": complete, "group": group, "transition_mode": transition,
                   "offline_feasible": False,
                   "rsn": [entry.get("rsn") for entry in (rsn.get("networks") or [])],
                   "findings": [finding["title"] for finding in findings],
                   "note": ("SAE is a PAKE: no offline attack exists.  The value here "
                            "is the transition-mode answer, not the capture")})

    def _fail_note(self, ctx: AttackContext, attempt: Attempt, why: str) -> AttackOutcome:
        return self._fail(ctx, attempt, why,
                          "SAE needs a client to authenticate: without one there is no "
                          "exchange to capture (and nothing to crack if there were)")

    # ---------------------------------------------------------------- #
    def _demo(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt
              ) -> AttackOutcome:
        radio = ctx.radio
        demo_ap = radio.find(ap.bssid) if radio else None
        # the scanned flags first, the simulated AP record as a fallback
        transition = bool(ap.sai or (ap.sae and "WPA2" in (ap.encryption or "")))
        if not transition and demo_ap is not None:
            privacy = (demo_ap.privacy or "").upper()
            transition = "WPA3" in privacy and "WPA2" in privacy
        path = ctx.artifact_path("saewolf", ap, ".pcap")
        for step in range(1, 4):
            ctx.progress(f"SAE capture on {ap.display_name}", kind="capture",
                         bssid=ap.bssid, percent=step * 30,
                         detail="commit/confirm exchange · simulation")
            time.sleep(0.4)
            if ctx.want_stop():
                return self._fail_note(ctx, attempt, "stopped")
        build_wpa3_capture(
            path, essid=ap.essid or "demo-wpa3", bssid=ap.bssid,
            station="02:00:00:00:00:31",
            akm="sae+psk" if transition else "sae", pmf=not transition,
            group=19 if (int(ap.bssid.replace(":", ""), 16) % 2) else 21)
        return self._report(ctx, ap, attempt, path, True)

    # ---------------------------------------------------------------- #
    def _live(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt
              ) -> AttackOutcome:
        airodump = registry.path("airodump-ng")
        if not airodump:
            return self._fail(ctx, attempt, "airodump-ng missing", "install aircrack-ng")
        timeout = min(ctx.config.attack_timeout_for("saewolf"), 180.0)
        prefix = ctx.artifact_path("saewolf", ap, "")
        cap_path = prefix + "-01.cap"
        channel = ap.channel or 0
        ctx.set_channel(channel)
        args = [airodump, ctx.monitor]
        if channel:
            args += ["-c", str(channel)]
        args += ["--bssid", ap.bssid, "-w", prefix, "--output-format", "pcap",
                 "--write-interval", "1", "--ignore-negative-one"]
        proc = Process(args, name="airodump-ng", echo_lines=ctx.config.verbose_tools)
        proc.start()
        if proc.error:
            return self._fail(ctx, attempt, "could not start airodump-ng", proc.error)
        started = time.time()
        found = False
        try:
            while not ctx.want_stop() and time.time() - started < timeout:
                time.sleep(1.5)
                ctx.progress(f"SAE capture on {ap.display_name}", kind="capture",
                             bssid=ap.bssid,
                             percent=min(95, (time.time() - started) / timeout * 100),
                             detail="waiting for a client to authenticate (nothing sent)")
                if os.path.exists(cap_path) and os.path.getsize(cap_path):
                    report = sae_exchange(cap_path)
                    if report.get("complete"):
                        found = True
                        break
        finally:
            with contextlib.suppress(Exception):
                proc.stop()
        if not found:
            return self._fail_note(
                ctx, attempt,
                f"no complete SAE exchange in {human_duration(time.time() - started)}")
        return self._report(ctx, ap, attempt, cap_path, False)


class PmfAuditAttack(Attack):
    name = "pmf_audit"
    label = "PMF / transition-mode audit"
    tool = "wifipilot wpa3.py (RSN decoder)"
    description = ("Read the RSN elements of the neighbourhood and say which classic "
                   "attacks remain possible: no required PMF means a deauth can force a "
                   "handshake, transition mode means there is a WPA2 path at all, and "
                   "an OWE transition SSID is the shape a downgrade twin imitates.")
    requires = ("airodump",)
    needs_injection = False
    applies_to = ("WPA", "WPA2", "WPA2/WPA3", "WPA3", "OWE", "OPEN", "ENTERPRISE",
                  "WPA2-ENTERPRISE")

    def applies(self, ap: AccessPoint) -> bool:
        return True

    def available(self, ctx: AttackContext) -> bool:
        return True                          # pure analysis of beacons

    # ---------------------------------------------------------------- #
    def _already_audited(self, ctx: AttackContext) -> bool:
        for ap in ctx.session.aps.values():
            for entry in ap.history:
                if entry.get("kind") == "pmf_audit":
                    return True
        return False

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(
            self.name, ap.bssid, tool=self.tool,
            chosen_by=getattr(ap, "picked_by", "heuristic"),
            reason=getattr(ap, "pick_reason", ""),
        )
        path = self._capture_path(ctx, ap)
        if ctx.demo and not path:
            path = self._demo_capture(ctx, ap)
        networks = capture_wpa3(path).get("networks") if path else []
        if not networks:
            networks = self._from_session(ctx)
        findings = wpa3_findings(networks)
        for finding in findings:
            _add_finding_once(ctx, finding, finding["bssid"] or ap.bssid)
        transition = [finding for finding in findings
                      if finding["kind"] == "wpa3_transition"]
        deauthable = [entry for entry in networks
                      if (entry.get("rsn") or {}).get("psk")
                      and not (entry.get("rsn") or {}).get("mfpr")]
        summary = (f"{len(networks)} network(s) read: {len(transition)} in transition "
                   f"mode, {len(deauthable)} deauthable (no required PMF), "
                   f"{len(findings)} finding(s)")
        detail = ("; ".join(finding["title"] for finding in findings)
                  or "no RSN weaknesses in the beacons read")
        ap.remember("pmf_audit", summary, networks=len(networks),
                    findings=[finding["kind"] for finding in findings])
        ap.pmf_checked = True
        for entry in networks:                # the audit is per-BSSID, not per-target
            peer = ctx.session.ap(entry.get("bssid") or "")
            rsn = entry.get("rsn") or {}
            if peer is not None and rsn:
                peer.pmf_checked = True
                peer.pmf = bool(rsn.get("mfpc"))
                peer.sae = bool(rsn.get("sae"))
                if rsn.get("transition_mode"):
                    peer.sai = True
        ctx.session.stats.pmf_audits += 1
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, "RSN audit complete", detail)
        return AttackOutcome.success(
            "RSN audit complete", detail=f"{summary} — {detail}",
            extra={"networks": networks, "findings": findings,
                   "transition_mode": [entry["bssid"] for entry in transition],
                   "deauthable": [entry.get("bssid") for entry in deauthable],
                   "note": ("read from the beacons themselves: airodump's CSV does not "
                            "carry the RSN capabilities bits, so MFPC/MFPR come from "
                            "the frames")})

    # ---------------------------------------------------------------- #
    @staticmethod
    def _capture_path(ctx: AttackContext, ap: AccessPoint) -> str:
        for capture in ap.captures:
            if capture.path and os.path.exists(capture.path):
                return capture.path
        captures = [item for item in ctx.session.all_captures()
                    if item.path and os.path.exists(item.path)]
        return captures[-1].path if captures else ""

    @staticmethod
    def _akm_for(entry: AccessPoint) -> str:
        if entry.sae and (entry.sai or "WPA2" in (entry.encryption or "")):
            return "sae+psk"                    # transition mode: both doors open
        if entry.sae:
            return "sae"
        return "psk"

    def _demo_capture(self, ctx: AttackContext, ap: AccessPoint) -> str:
        """Build beacons that say what the neighbourhood is, and read them back."""
        from ..synth import build_beacon, write_pcap
        path = ctx.artifact_path("pmfaudit", ap, ".pcap")
        frames = [build_beacon(ap.essid or "demo", ap.bssid, channel=ap.channel or 6,
                               akm=self._akm_for(ap), pmf=bool(ap.pmf))]
        for other in list(ctx.session.aps.values())[:12]:      # the whole neighbourhood
            frames.append(build_beacon(other.essid or "hidden", other.bssid,
                                       channel=other.channel or 6,
                                       akm=self._akm_for(other),
                                       pmf=bool(other.pmf)))
        write_pcap(path, frames, spacing=0.005)
        return path


def _add_finding_once(ctx: AttackContext, finding: Dict[str, str],
                      bssid: str) -> bool:
    """Raise a finding unless the session already carries the same one.

    The PMF audit reads the whole neighbourhood in one pass, so the same weakness
    (``no_pmf`` on a network two rooms away) would otherwise be reported again for
    every AP that runs the audit.  A finding is identified by its kind, its BSSID
    and its title.
    """
    from ..models import Finding
    for existing in ctx.session.findings:
        if (existing.kind == finding["kind"] and existing.bssid == bssid
                and existing.title == finding["title"]):
            return False
    ctx.session.add_finding(Finding(
        kind=finding["kind"], severity=finding["severity"], bssid=bssid,
        title=finding["title"], detail=finding["detail"]))
    return True


def pmf_from_capabilities(capabilities: int) -> Dict[str, bool]:
    """``{"mfpc": …, "mfpr": …}`` from a raw RSN capabilities word."""
    return {"mfpc": bool(capabilities & 0x0020), "mfpr": bool(capabilities & 0x0010)}
