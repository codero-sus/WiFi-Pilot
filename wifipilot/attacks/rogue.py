"""Rogue AP / evil-twin survey — read-only, and it says so.

The question this answers is not "can I attack this?" but "has somebody already
attacked the environment I am auditing?".  A twin shows up as the same ESSID on a
BSSID from a different vendor, a very different signal on the same name, or a
name that only exists in clients' probe requests.

Everything is derived from what was already captured plus the live target list, so
this module never transmits and never associates.  Findings are labelled
``heuristic``: a second AP with the same name is evidence, not proof, and a
literal warning symbol in an engagement report that cannot be justified is worse
than no warning at all.
"""

from __future__ import annotations

import os

from ..models import STATUS_SKIPPED, STATUS_SUCCESS, AccessPoint, Finding
from ..sniff import passive_report
from .base import Attack, AttackContext, AttackOutcome


class RogueApAttack(Attack):
    name = "rogue_ap"
    label = "Rogue AP / evil twin survey"
    tool = "wifipilot (offline analysis)"
    description = ("Compare every ESSID on air against its BSSIDs, vendors, signal "
                   "levels and the names clients are probing for.  Reports twins and "
                   "attacker infrastructure; transmits nothing.")
    requires = ()
    needs_injection = False
    applies_to = ("WPA", "WPA2", "WPA2/WPA3", "WPA3", "WEP", "OPEN")

    def applies(self, ap: AccessPoint) -> bool:
        return True

    def available(self, ctx: AttackContext) -> bool:
        return True                     # pure analysis: always available

    def _already_surveyed(self, ctx: AttackContext) -> bool:
        """Has this environment been surveyed already in this session?

        The report is about the *environment*, not about one BSSID, so running it
        once per target would produce the same findings a dozen times.  It is
        re-run when a fresh scan has brought in new access points, because that is
        when the answer can have changed.
        """
        seen = [entry.get("aps", 0)
                for ap in ctx.session.aps.values()
                for entry in ap.history if entry.get("kind") == "rogue_survey"]
        if not seen:
            return False
        return len(ctx.session.aps) <= max(seen)

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(
            self.name, ap.bssid, tool=self.tool,
            chosen_by=getattr(ap, "picked_by", "heuristic"),
            reason=getattr(ap, "pick_reason", ""),
        )
        if self._already_surveyed(ctx):
            # recorded as a skipped attack rather than silently repeated: a campaign
            # log that shows the same survey six times reads like six findings
            result = "environment already surveyed"
            detail = "the target list has not changed since the last survey"
            ctx.session.end_attempt(attempt, STATUS_SKIPPED, result, detail)
            return AttackOutcome.skipped(result, detail)
        # the capture of this AP (if any) gives us probe requests to compare with
        capture_path = ""
        for capture in ap.captures:
            if capture.path and os.path.exists(capture.path):
                capture_path = capture.path
                break
        aps = [item.to_dict() for item in ctx.session.aps.values()]
        report = passive_report(capture_path, aps)

        twins = report.get("rogue", [])
        hidden = report.get("hidden_targets", [])
        probes = report.get("probes", [])
        attacks = report.get("attacks", {}) or {}

        finding_rows = []
        ctx.session.stats.rogue_twins += len(twins)
        # the survey is about the environment, so every twin it saw is a finding —
        # not only the one whose name happens to match the BSSID that triggered it
        for twin in twins:
            detail = (f"{twin['essid']!r} is served by {len(twin['bssids'])} BSSIDs "
                      f"({', '.join(twin['bssids'])}); vendors: "
                      f"{', '.join(twin['vendors']) or 'unknown'}; "
                      f"{twin['signal_spread_db']} dB spread — {twin['reason']}")
            finding_rows.append(detail)
            ctx.session.add_finding(Finding(
                kind="rogue_ap", severity="high", bssid=ap.bssid,
                title=f"Possible twin of {twin['essid']}", detail=detail))
        if hidden:
            ctx.session.add_finding(Finding(
                kind="probe", severity="info", bssid=ap.bssid,
                title=f"Clients are probing for {len(hidden)} network(s) not on air",
                detail=", ".join(hidden[:10])))
        if attacks.get("flood"):
            ctx.session.add_finding(Finding(
                kind="deauth", severity="medium", bssid=ap.bssid,
                title=f"Deauthentication flood observed ({attacks.get('total')} frames)",
                detail="management frames are unauthenticated: this shows interference "
                       "on the environment, not who caused it"))

        summary = (f"{len(twins)} twin pattern(s), {len(hidden)} probed-but-absent "
                   f"network(s), {len(probes)} probing client(s)")
        ap.remember("rogue_survey", summary, twins=len(twins), probes=len(probes),
                    hidden=len(hidden), aps=len(ctx.session.aps))
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, summary,
                                "; ".join(finding_rows) or "nothing suspicious")
        return AttackOutcome.success(
            "rogue AP survey complete", detail=summary,
            extra={"twins": twins, "hidden_targets": hidden,
                   "probes": probes[:20], "attacks": attacks})
