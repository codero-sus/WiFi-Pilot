"""Follow the client: which network does this device actually trust?

The interesting target on a site is usually not the loudest access point but the
device that carries the credentials: the laptop in the lobby that remembers
``CorpNet``, the phone that has ``HomeWiFi`` in its preferred network list, the
printer that still probes for a WEP network nobody remembers installing.

This attack watches one station and builds its picture from what it broadcasts:
the networks it asks for, the BSSIDs it is associated with, and the signal
trend as it moves.  It is the attack to run *before* a targeted deauth or a
twin, because it decides which name is worth impersonating.

Walking is deliberate: the operator moves (or the target moves), and the
signal trend is the measurement.  Reporting "it is now 20 dB stronger" is only
meaningful next to a start value, so the first sample is kept and compared
against at most once a second — the difference between a survey and a single
number someone will misread.
"""

from __future__ import annotations

import contextlib
import os
import time
from typing import Any, Dict, List, Tuple

from ..deps import registry
from ..models import STATUS_SKIPPED, STATUS_SUCCESS, AccessPoint, Attempt
from ..sniff import probe_requests
from ..util import Process, human_duration, mac_norm
from .base import Attack, AttackContext, AttackOutcome


class TrackerAttack(Attack):
    name = "tracker"
    label = "Station tracker (follow a client)"
    tool = "airodump-ng (listen-only)"
    description = ("Watch one station: the networks it probes for (its real PNL), the "
                   "APs it is associated with, and how its signal moves as you walk.  "
                   "Decides which network is worth impersonating; transmits nothing.")
    requires = ("airodump",)
    needs_injection = False
    applies_to = ("WPA", "WPA2", "WPA2/WPA3", "WPA3", "WEP", "OPEN",
                  "WPA-ENTERPRISE", "WPA2-ENTERPRISE", "ENTERPRISE")

    def applies(self, ap: AccessPoint) -> bool:
        return True

    # ---------------------------------------------------------------- #
    def _pick_station(self, ctx: AttackContext, ap: AccessPoint) -> Tuple[str, str]:
        """The most interesting station we know about, with the reason why."""
        named = mac_norm(getattr(ctx.config, "client_mac", "") or "")
        if named:
            # an operator who names a station means that station, on whichever AP it
            # currently belongs to
            if named in ap.clients:
                return named, "named by the operator"
            return "", f"{named} is not a client of this AP"
        best: Tuple[int, str, str] = (0, "", "")
        for client in ap.clients.values():
            signal = int(getattr(client, "signal", -100) or -100)
            score = 100 + signal                       # strongest first
            if client.probes:
                score += 40                            # it told us where it goes
            if client.handshake:
                score += 20
            reason = (f"{len(client.probes)} probed network(s), {signal} dBm"
                      if client.probes else f"associated, {signal} dBm")
            if score > best[0]:
                best = (score, client.mac, reason)
        if best[1]:
            return best[1], best[2]
        # no client list (a hidden AP, or a scan that only saw beacons): take the
        # station out of the capture the survey already likes
        for client in getattr(ctx.session, "clients", {}).values():
            if client.bssid == ap.bssid or ap.bssid in (client.bssid, ""):
                return client.mac, "only station seen in the session"
        return "", "no station in range"

    # ---------------------------------------------------------------- #
    def _already_tracked(self, ctx: AttackContext, station: str) -> bool:
        """Was this station followed already in this session?

        A signal trend is a measurement taken while walking; repeating it from the
        same chair produces the same number and reads like a second finding.  A new
        walk happens when the operator asks for it, not when the planner revisits an
        access point.
        """
        for ap in ctx.session.aps.values():
            for entry in ap.history:
                if entry.get("kind") == "tracker" and entry.get("station") == station:
                    return True
        return False

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(
            self.name, ap.bssid, tool=self.tool,
            chosen_by=getattr(ap, "picked_by", "heuristic"),
            reason=getattr(ap, "pick_reason", ""),
        )
        station, why = self._pick_station(ctx, ap)
        if not station:
            named = mac_norm(getattr(ctx.config, "client_mac", "") or "")
            if named:
                # --client names one station; every other AP is simply not its home
                result = f"{named} is not on {ap.display_name}"
                detail = ("a named station is tracked where it is associated, not "
                          "everywhere it might appear")
                ctx.session.end_attempt(attempt, STATUS_SKIPPED, result, detail)
                return AttackOutcome.skipped(result, detail)
            return self._fail(ctx, attempt, "no station to follow",
                              "the target has no clients in range: run a scan, or use "
                              "a broadcast deauth to make one appear")
        if self._already_tracked(ctx, station):
            result = f"{station} was followed already"
            detail = ("a signal trend needs a new walk, not a repeat from the same "
                      "place: track it again deliberately, from somewhere else")
            ctx.session.end_attempt(attempt, STATUS_SKIPPED, result, detail)
            return AttackOutcome.skipped(result, detail)
        if ctx.demo:
            return self._demo(ctx, ap, attempt, station, why)
        return self._live(ctx, ap, attempt, station, why)

    # ---------------------------------------------------------------- #
    def _report(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                station: str, why: str, samples: List[Dict[str, Any]],
                probes: List[str], seen_bssids: List[str],
                seconds: float) -> AttackOutcome:
        readings = [sample["signal"] for sample in samples if sample.get("signal")]
        first, last = (readings[0], readings[-1]) if readings else (0, 0)
        trend = last - first if len(readings) > 1 else 0
        direction = ("closer" if trend > 6 else "further away" if trend < -6
                     else "stable")
        detail = (f"{station}: {len(probes)} probed network(s), "
                  f"{len(seen_bssids)} BSSID(s) seen, {len(samples)} sample(s); "
                  f"signal {first} → {last} dBm ({direction}) over "
                  f"{human_duration(seconds)}")
        extra = {
            "station": station,
            "reason": why,
            "probes": probes[:20],
            "bssids": seen_bssids[:20],
            "samples": samples[-40:],
            "signal_start": first, "signal_end": last, "trend_db": trend,
            "direction": direction,
            "seconds": round(seconds, 1),
            "note": ("read-only tracking: the signal trend is a measurement, not a "
                     "position — walls and body absorption move it as much as distance"),
        }
        if probes:
            ap.remember("tracker", detail, station=station, probes=probes[:10])
        ctx.session.stats.stations_tracked += 1
        artifact = self._write_loot(ctx, ap, station, extra)
        if artifact:
            extra["artifact"] = artifact
        ctx.session.end_attempt(attempt, STATUS_SUCCESS,
                                f"station {station} followed", detail)
        return AttackOutcome.success(f"station {station} followed", detail=detail,
                                     extra=extra)

    @staticmethod
    def _write_loot(ctx: AttackContext, ap: AccessPoint, station: str,
                    extra: Dict[str, Any]) -> str:
        """Keep the trace as an artifact, so the report can show the raw samples."""
        import json as _json
        path = ctx.artifact_path("tracker", ap, f"-{station.replace(':', '')}.json")
        try:
            with open(path, "w", encoding="utf-8") as handle:
                _json.dump(extra, handle, indent=2)
        except OSError:                                   # pragma: no cover
            return ""
        return ctx.session.save_artifact(path, "tracker", ctx.loot_name(ap, "tracker"))

    # ---------------------------------------------------------------- #
    def _demo(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
              station: str, why: str) -> AttackOutcome:
        radio = ctx.radio
        demo_ap = radio.find(ap.bssid) if radio else None
        client = next((item for item in getattr(demo_ap, "clients", [])
                       if item.mac == station), None) if demo_ap else None
        start = int(getattr(client, "signal", -70) or -70)
        reported = list(ap.clients[station].probes) if station in ap.clients else []
        samples: List[Dict[str, Any]] = []
        timeout = min(ctx.config.attack_timeout_for(self.name), 30.0)
        # a stable, station-specific walk: some clients come closer, some drift away,
        # some never move — the demo should not print the same trend six times
        seed = int(station.replace(":", ""), 16)
        shape = ("closer", "further away", "stable")[seed % 3]
        rate = 2 + (seed >> 8) % 3
        started = time.time()
        step = 0
        while time.time() - started < timeout and not ctx.want_stop():
            step += 1
            if shape == "closer":
                drift = min(step, 6)
            elif shape == "further away":
                drift = -min(step, 6)
            else:
                drift = 1 if step % 2 else -1
            signal = max(-95, min(-20, start + drift * rate))
            samples.append({"ts": round(time.time() - started, 1), "signal": signal,
                            "bssid": ap.bssid})
            ctx.progress(f"following {station}", kind="capture", bssid=ap.bssid,
                         percent=min(95, step * 18),
                         detail=f"{signal} dBm · {len(reported)} probed network(s)")
            time.sleep(0.4)
            if step >= 8:
                break
        return self._report(ctx, ap, attempt, station, why, samples, reported,
                            [ap.bssid], time.time() - started)

    # ---------------------------------------------------------------- #
    def _live(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
              station: str, why: str) -> AttackOutcome:
        airodump = registry.path("airodump-ng")
        if not airodump:
            return self._fail(ctx, attempt, "airodump-ng missing", "install aircrack-ng")
        timeout = min(ctx.config.attack_timeout_for(self.name), 600.0)
        prefix = ctx.artifact_path("tracker", ap, "")
        cap_path = prefix + "-01.cap"
        channel = ap.channel or 0
        ctx.set_channel(channel)
        args = [airodump, ctx.monitor]
        if channel:
            args += ["-c", str(channel)]
        args += ["--bssid", ap.bssid, "--output-format", "pcap",
                 "--write-interval", "1", "--ignore-negative-one"]
        proc = Process(args, name="airodump-ng", echo_lines=ctx.config.verbose_tools)
        proc.start()
        if proc.error:
            return self._fail(ctx, attempt, "could not start airodump-ng", proc.error)
        samples: List[Dict[str, Any]] = []
        probes: List[str] = []
        seen: List[str] = []
        started = time.time()
        try:
            while not ctx.want_stop() and time.time() - started < timeout:
                time.sleep(1.0)
                ctx.progress(f"following {station}", kind="capture", bssid=ap.bssid,
                             percent=min(95, (time.time() - started) / timeout * 100),
                             detail=f"{len(samples)} sample(s), {len(probes)} probed "
                                    f"network(s)")
                for name in airodump_stations(proc.lines):
                    if name not in seen:
                        seen.append(name)
                client = ap.clients.get(station)
                if client is not None:
                    readings = getattr(client, "signal_history", None) or []
                    if readings:
                        samples.append({"ts": round(time.time() - started, 1),
                                        "signal": int(readings[-1])})
                    for essid in getattr(client, "probes", []) or []:
                        if essid not in probes:
                            probes.append(essid)
                if os.path.exists(cap_path) and os.path.getsize(cap_path):
                    for entry in probe_requests(cap_path).values():
                        if entry.mac.lower() == station.lower():
                            for essid in entry.ssids:
                                if essid not in probes:
                                    probes.append(essid)
        finally:
            with contextlib.suppress(Exception):
                proc.stop()
        if not samples and station in ap.clients:
            samples.append({"ts": 0.0, "signal": int(ap.clients[station].signal)})
        seconds = time.time() - started
        if not samples:
            return self._fail(ctx, attempt, f"lost {station}",
                              f"{human_duration(seconds)} without a frame from the "
                              f"station (is it still on channel {channel or '?'}?)")
        seen = seen or [ap.bssid]
        return self._report(ctx, ap, attempt, station, why, samples, probes, seen,
                            seconds)


def airodump_stations(lines: List[str]) -> List[str]:
    """Station MACs out of an airodump-ng CSV/text tail (tolerant, order kept)."""
    import re
    out: List[str] = []
    for line in lines[-200:]:
        for mac in re.findall(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", line):
            norm = mac_norm(mac)
            if norm and norm not in out:
                out.append(norm)
    return out
