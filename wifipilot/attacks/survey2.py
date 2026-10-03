"""The SAE-group audit: what a WPA3 network's own RSN element says about its edges.

``saewolf`` captures an SAE exchange and reports whether there is a WPA2 door next to
it.  This audit answers the two questions the *elements* can answer without an
exchange at all:

* **Which groups does the network use?**  A commit frame carries its group in the
  status field of the authentication frame, so a capture that holds a commit tells us
  the group.  Groups 22/23/24 are the ones Dragonblood called out: they are cheaper for
  an attacker to abuse (small subgroup attacks, weaker parameters) and more expensive
  for the AP to use than group 19.
* **Does it do Hash-to-Element?**  H2E is a property of the AKM suite the AP advertises
  (24/25 alongside SAE's 8/9).  Without it, the *first* SAE commit from any sender gets
  a full cryptographic answer — which is what makes ``sae_commit_flood`` work at all.

Both answers come from a capture.  If the session already has one for this BSSID, the
audit reads it; otherwise it takes a short, bounded one, and if radio time is not
available it says what it could not check instead of guessing.
"""

from __future__ import annotations

import contextlib
import os
import time
from typing import Any, Dict, List, Optional

from ..deps import registry
from ..models import STATUS_SUCCESS, AccessPoint, Attempt
from ..util import Process, human_duration
from ..wpa3 import capture_wpa3, sae_exchange
from .base import Attack, AttackContext, AttackOutcome

#: groups RFC 8110 §2.3 / Dragonblood treat as weak for SAE
WEAK_GROUPS = {22: "group 22 (1024-bit MODP)", 23: "group 23 (2048-bit MODP)",
               24: "group 24 (2048-bit MODP with 256-bit subgroup)"}
#: groups recommended by RFC 8110
STRONG_GROUPS = {19: "group 19 (256-bit random ECP)", 20: "group 20 (384-bit random ECP)",
                 21: "group 21 (521-bit random ECP)"}
#: AKM suite codes: SAE, and the SAE-EXT-KEY variants that mandate Hash-to-Element
AKM_SAE = {8, 9}
AKM_SAE_H2E = {24, 25}
#: the names :mod:`wifipilot.wpa3` gives those codes, for captures without raw codes
AKM_BY_NAME = {8: "SAE", 9: "FT-SAE", 24: "SAE-EXT-KEY", 25: "SAE-EXT-KEY-FT"}


class SaeGroupAuditAttack(Attack):
    """Read a WPA3 network's RSN element and SAE commits; rank its parameters."""

    name = "sae_group_audit"
    label = "SAE group and H2E audit (WPA3 parameters)"
    tool = "wifipilot wpa3.py (RSN + SAE decoder)"
    description = ("Decode the network's RSN element and its SAE commits and rank the "
                   "parameters: a weak group (22/23/24) costs the AP more than the "
                   "attacker and weakens the PAKE, and an AP without Hash-to-Element "
                   "answers the first commit from every sender — which is the whole "
                   "basis of the SAE commit flood.  Read-only: it prefers a capture "
                   "the session already has and only listens if there is none.")
    requires = ()
    needs_injection = False
    category = "survey"
    noise = "silent"
    impact = "info"
    applies_to = ("WPA3", "WPA2/WPA3")
    #: how long a capture we are willing to take when there is not one already
    max_seconds = 45.0

    def applies(self, ap: AccessPoint) -> bool:
        return bool(ap.sae or "WPA3" in (ap.encryption or "").upper() or ap.sai)

    def available(self, ctx: AttackContext) -> bool:
        # a capture already in the session is enough: no radio, no authorisation
        return True if self._existing_capture(ctx, None) else bool(registry.path("airodump-ng"))

    def unavailable_reason(self, ctx: AttackContext) -> str:
        return ("no capture for this BSSID and no airodump-ng to take one: the audit "
                "reads frames, so it needs frames")

    # ---------------------------------------------------------------- #
    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(
            self.name, ap.bssid, tool=self.tool,
            chosen_by=getattr(ap, "picked_by", "heuristic"),
            reason=getattr(ap, "pick_reason", ""),
        )
        if not self.applies(ap):
            ctx.session.end_attempt(attempt, "skipped", "not a WPA3 network")
            return AttackOutcome.skipped("not a WPA3 network",
                                         f"{ap.display_name} is {ap.encryption or 'PSK'}")
        path = self._existing_capture(ctx, ap)
        simulated = False
        if ctx.demo and not path:
            path = self._demo_capture(ctx, ap)
            simulated = True
        elif not path:
            if not registry.path("airodump-ng"):
                return self._fail(ctx, attempt, "no capture to read",
                                  self.unavailable_reason(ctx))
            path = self._listen(ctx, ap)
            if not path:
                return self._fail(
                    ctx, attempt, "no usable capture",
                    "the bounded listen produced nothing to decode: run it again while "
                    "a WPA3 client associates, or point it at a capture you already have")
        return self._report(ctx, ap, attempt, path, simulated)

    # ---------------------------------------------------------------- #
    def _existing_capture(self, ctx: AttackContext, ap: Optional[AccessPoint]) -> str:
        """The newest capture the session holds for this BSSID, if any."""
        candidates = []
        for capture in ctx.session.all_captures():
            path = getattr(capture, "path", "")
            if not path or not os.path.exists(path):
                continue
            if ap is not None and capture.bssid and capture.bssid != ap.bssid:
                continue
            candidates.append((os.path.getsize(path), path))
        return max(candidates)[1] if candidates else ""

    # ---------------------------------------------------------------- #
    def _demo_capture(self, ctx: AttackContext, ap: AccessPoint) -> str:
        from ..synth import build_wpa3_capture

        path = ctx.artifact_path("sae-audit", ap, ".pcap")
        seed = int(ap.bssid.replace(":", ""), 16)
        group = 19 if seed % 3 == 0 else (22 if seed % 3 == 1 else 24)
        build_wpa3_capture(
            path, essid=ap.essid or "demo-wpa3", bssid=ap.bssid,
            station="02:00:00:00:00:51", akm="sae+h2e" if seed % 2 else "sae",
            pmf=True, group=group)
        return path

    # ---------------------------------------------------------------- #
    def _listen(self, ctx: AttackContext, ap: AccessPoint) -> str:
        """A short, bounded capture so there is something to decode."""
        seconds = min(ctx.config.attack_timeout_for(self.name), self.max_seconds)
        prefix = ctx.artifact_path("sae-audit", ap, "")
        cap_path = prefix + "-01.cap"
        ctx.set_channel(ap.channel)
        args = [registry.path("airodump-ng") or "airodump-ng", ctx.monitor]
        if ap.channel:
            args += ["-c", str(ap.channel)]
        args += ["--bssid", ap.bssid, "-w", prefix, "--output-format", "pcap",
                 "--write-interval", "1", "--ignore-negative-one"]
        proc = Process(args, name="airodump-ng", echo_lines=ctx.config.verbose_tools)
        proc.start()
        if proc.error:
            return ""
        started = time.time()
        try:
            while not ctx.want_stop() and time.time() - started < seconds:
                time.sleep(1.0)
                ctx.progress(f"SAE audit on {ap.display_name}", kind="capture",
                             bssid=ap.bssid,
                             percent=min(95, (time.time() - started) / seconds * 100),
                             detail="reading the RSN element and any SAE commits")
        finally:
            with contextlib.suppress(Exception):
                proc.stop()
            time.sleep(0.5)
        return cap_path if os.path.exists(cap_path) else ""

    # ---------------------------------------------------------------- #
    def _report(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                path: str, simulated: bool) -> AttackOutcome:
        rsn = capture_wpa3(path)
        groups = self._groups(path)
        entry = self._our_entry(rsn.get("networks") or [], ap)
        rsn_info = entry.get("rsn") or {}
        akm = [int(code) for code in (rsn_info.get("akm_codes") or [])]
        if not akm:                                  # names are all the decoder gave us
            akm = [code for code, name in AKM_BY_NAME.items()
                   if name in (rsn_info.get("akm") or [])]
        ext_key = any(code in AKM_SAE_H2E for code in akm)
        psk_path = bool(rsn_info.get("psk"))
        transition = bool(psk_path and any(code in AKM_SAE for code in akm)) or bool(ap.sai)
        mfpr = bool(rsn_info.get("mfpr"))
        weak = [group for group in groups if group in WEAK_GROUPS]
        strong = [group for group in groups if group in STRONG_GROUPS]

        parts = []
        parts.append("groups " + ", ".join(str(group) for group in groups)
                     if groups else
                     "no SAE commit in the capture, so no group could be read")
        parts.append("SAE-EXT-KEY advertised" if ext_key
                     else "no SAE-EXT-KEY AKM (H2E is negotiated inside the commit)")
        parts.append("PMF required" if mfpr else "PMF capable, not required")
        parts.append("transition mode: a WPA2 path is offered" if transition
                     else "SAE-only posture")
        if simulated:
            parts.append("simulated")
        detail = "; ".join(parts)

        findings: List[str] = []
        if weak:
            findings.append("weak SAE group(s) in use: "
                            + ", ".join(WEAK_GROUPS[group] for group in weak)
                            + " — Dragonblood's advice is group 19 or 20+")
        if not ext_key:
            findings.append("the RSN element does not advertise a SAE-EXT-KEY AKM, so "
                            "Hash-to-Element is negotiated inside the commit itself and "
                            "this read-only audit cannot confirm it; without H2E the "
                            "AP answers every first commit in full, which is the cost "
                            "`sae_commit_flood` exploits")
        if not mfpr:
            findings.append("PMF is capable but not required: forged deauth, "
                            "disassociation and CSA frames still reach clients that "
                            "support 802.11w without requiring it")
        if transition:
            findings.append("transition mode: the WPA2 path is still offered, so a 4-way "
                            "handshake from this network is crackable (`handshake`)")
        if not findings:
            findings.append("parameters look right: strong group, 802.11w required, no "
                            "WPA2 path advertised")

        severity = "high" if weak else ("medium" if (not ext_key or not mfpr
                                                    or transition) else "low")
        if weak:
            title = "WPA3 uses a weak SAE group"
        elif transition or not mfpr:
            title = "WPA3 posture has a cheaper path than it should"
        elif not ext_key:
            title = "WPA3 parameters are good, with H2E unconfirmed"
        else:
            title = "WPA3 parameters are in good shape"

        body = ("Read-only audit of the SAE parameters.  " + "  ".join(findings) +
                "  What this does *not* say: SAE is a PAKE, so no group choice makes a "
                "captured exchange crackable — the weaknesses here are availability and "
                "downgrade ones, not password recovery.")
        from ..models import Finding

        ctx.session.add_finding(Finding(kind=self.name, severity=severity,
                                        bssid=ap.bssid, title=title, detail=body))
        ctx.session.stats.offline_audits += 1
        ctx.session.stats.sae_captures += 1
        ap.remember(self.name, detail, groups=groups, ext_key=ext_key,
                    transition=transition, mfpr=mfpr)
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, title, detail)
        return AttackOutcome.success(
            title, detail=detail,
            extra={"groups": groups, "weak_groups": weak, "strong_groups": strong,
                   "sae_ext_key": ext_key, "h2e_advertised": ext_key,
                   "pmf_required": mfpr, "transition_mode": transition, "akm": akm,
                   "akm_names": list(rsn_info.get("akm") or []),
                   "findings": findings, "capture": path, "simulated": simulated,
                   "offline_feasible": False,
                   "note": ("this audit is silent: it reads frames that were already "
                            "captured, and a PAKE capture is not crackable in any "
                            "group")})

    # ---------------------------------------------------------------- #
    @staticmethod
    def _our_entry(networks: List[Dict[str, Any]], ap: AccessPoint
                   ) -> Dict[str, Any]:
        for entry in networks:
            if entry.get("bssid") == ap.bssid:
                return entry
        return networks[0] if networks else {}

    @staticmethod
    def _groups(path: str) -> List[int]:
        """SAE groups seen in commits, in the order they were seen."""
        try:
            exchange = sae_exchange(path)
        except Exception:                                     # pragma: no cover
            return []
        groups: List[int] = []
        for item in exchange.get("exchanges") or []:
            # every commit's group lands in the auth frame's status field: a commit
            # carries the id there, a confirm carries the status code (usually 0)
            for code in item.get("status") or []:
                try:
                    code = int(code)
                except (TypeError, ValueError):
                    continue
                if code > 0 and code not in groups:
                    groups.append(code)
        return groups
