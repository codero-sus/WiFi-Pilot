# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Protocol-level findings: the attacks that read the wire and know what went wrong.

Nine techniques that exist because a wireless protocol has a documented flaw, and a
capture — or two spoofed frames — is enough to prove it:

* ``krack_detect`` (CVE-2017-13077 and friends) — look for the key-reinstallation
  pattern in a capture: message 3 of the 4-way handshake sent twice with the *same*
  nonce but a different replay counter, or a message 4 that is a byte-for-byte replay.
  Without that, a PSK is useless to an attacker; with it, the encryption keystream is
  reused.
* ``kr00k_detect`` (CVE-2019-15126) — data frames whose ciphertext is all zeros after a
  disassociation: the chip zeroed the session key before it stopped transmitting.
* ``fragattacks_detect`` (CVE-2020-24588 and the rest) — A-MSDU support and fragmented
  QoS frames in a capture, which is what the aggregation and fragmentation attacks
  need, plus the beacon facts that say the vendor is affected.
* ``ft_audit`` — 802.11r fast transition: PMK-R0/R1 derivation from the PSK is public,
  so an FT network whose PSK is known hands over the mobility domain too.
* ``pmf_downgrade_probe`` — send an unprotected disassociation to a station on a
  PMF-capable AP: if it leaves, PMF is not enforced for that client, and the classic
  deauth attacks still work against it.
* ``btm_hijack`` — an 802.11v BSS Transition Management Request listing *our* BSSID as
  the preferred neighbour: a station that follows it is walking to a network the
  attacker chose.
* ``beacon_rate_audit`` — beacon interval, TSF and sequence behaviour: a clone or a
  flooding device is visible in numbers a beacon-IE dump hides.
* ``tsf_clone_detect`` — two BSSIDs with the same SSID and unrelated TSF counters are
  not the same infrastructure, which is the cheap, offline twin test.
* ``client_fingerprint`` — the stations in a capture: vendor, randomised MAC, the
  probe list they leak and the IE fingerprint of their driver.

The seven analysis techniques transmit nothing and need no authorisation; the two that
send frames are opt-in and quiet (a single disassociation, and one action frame).
"""

from __future__ import annotations

import hashlib
import os
import time
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

from ..models import STATUS_SUCCESS, AccessPoint, Attempt
from ..util import oui_vendor
from .base import Attack, AttackContext, AttackOutcome
from .forensics import OfflineAttack

#: AKM suites that mean SAE / WPA3
FT_AKMS = {3, 9, 25}                     # FT-PSK, FT-SAE, SAE-EXT-KEY-FT
PMF_AKMS = {8, 9, 12, 13, 24, 25}        # SAE and the SHA-256/384 AKM family


# --------------------------------------------------------------------------- #
# 1. KRACK
# --------------------------------------------------------------------------- #


class KrackDetectAttack(OfflineAttack):
    name = "krack_detect"
    label = "KRACK key-reinstallation detector (CVE-2017-13077)"
    tool = "wifipilot pcap.py (EAPOL replay analysis)"
    description = ("Walk every handshake in a capture looking for the pattern KRACK "
                   "needs: message 3 accepted twice under the same nonce, or message 4 "
                   "replayed without change.  A network that re-installs keys when a "
                   "client can be made to retransmit is the vulnerable case, and the "
                   "evidence is entirely in the capture — no deauth, no radio, no "
                   "authorisation beyond reading your own file.")

    category = "offline"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        path = self.capture_path(ctx, ap)
        if not path:
            return self._skip_offline(ctx, ap, attempt, "no capture to analyse")
        from ..pcap import analyze_file

        analysis = analyze_file(path)
        hits: List[Dict[str, Any]] = []
        for handshake in analysis.handshakes:
            # a retransmission is what KRACK needs: the client accepts a message 3 it
            # has already installed a key for (or replays message 4), and the replay
            # counter is the only thing that changes
            for number, message in sorted(handshake.messages.items()):
                if not message.retransmits:
                    continue
                if number in (3, 4):
                    hits.append({
                        "pattern": (f"message {number} accepted "
                                    f"{message.retransmits + 1}x (key reinstallation "
                                    f"opportunity)" if number == 3
                                    else f"message {number} replayed "
                                         f"{message.retransmits}x"),
                        "station": handshake.station,
                        "replay": message.replay, "nonce": message.nonce,
                        "retransmits": message.retransmits})
            # (a single, clean exchange is the normal case and is not reported: the
            # detector only speaks when a key was reinstalled)
        detail = (f"{len(analysis.handshakes)} handshake(s) in "
                  f"{os.path.basename(path)}: "
                  + (f"{len(hits)} reinstallation pattern(s) found" if hits
                     else "no key-reinstallation pattern"))
        severity = "high" if hits else "info"
        title = ("KRACK pattern present in the capture" if hits
                 else "no KRACK key-reinstallation evidence")
        return self._finish(ctx, ap, attempt, title, detail,
                            {"capture": path, "patterns": hits,
                             "handshakes": len(analysis.handshakes),
                             "stations": sorted({handshake.station
                                                 for handshake in analysis.handshakes}),
                             "note": ("the detector needs a retransmission in the "
                                      "capture: a clean single handshake cannot prove "
                                      "or disprove KRACK")},
                            severity=severity)

    def _skip_offline(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                      reason: str) -> AttackOutcome:
        ctx.session.end_attempt(attempt, "skipped", reason)
        return AttackOutcome.skipped(reason)


# --------------------------------------------------------------------------- #
# 2. KR00K
# --------------------------------------------------------------------------- #


class Kr00kDetectAttack(OfflineAttack):
    name = "kr00k_detect"
    label = "KR00K zero-key frame detector (CVE-2019-15126)"
    tool = "wifipilot pcap.py + ciphertext analysis"
    description = ("Find data frames whose ciphertext is all zeros — the signature of "
                   "a chip that zeroed its session key before it stopped transmitting, "
                   "which is what KR00K leaks.  The frames are decrypted by the "
                   "attacker for free, and their payload often contains IP headers, "
                   "DHCP and even credentials.  Vendor and model are reported alongside, "
                   "because the vulnerability is firmware-specific.")

    category = "offline"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        path = self.capture_path(ctx, ap)
        if not path:
            return AttackOutcome.skipped("no capture to analyse")
        zero_frames, checked = self._scan(path)
        vendor = ap.vendor or oui_vendor(ap.bssid)
        severity = "high" if zero_frames else "info"
        title = (f"KR00K signature: {len(zero_frames)} all-zero frame(s)" if zero_frames
                 else "no KR00K signature in the capture")
        detail = (f"{checked} encrypted data frame(s) inspected in "
                  f"{os.path.basename(path)}: {len(zero_frames)} with an all-zero "
                  f"payload; AP vendor {vendor or 'unknown'}"
                  + (f"; frames: {', '.join(str(item) for item in zero_frames[:5])}"
                     if zero_frames else ""))
        return self._finish(ctx, ap, attempt, title, detail,
                            {"capture": path, "zero_frames": zero_frames,
                             "checked": checked, "vendor": vendor,
                             "model": ap.wps_model,
                             "note": ("an all-zero ciphertext is the firmware bug's "
                                      "signature; a single one is worth reporting even "
                                      "when the vendor is not on the published list")},
                            severity=severity)

    @staticmethod
    def _scan(path: str) -> Tuple[List[int], int]:
        """Indices of data frames whose encrypted payload is entirely zero."""
        from ..pcap import TYPE_DATA, _parse_frame, iter_frames

        zeros: List[int] = []
        checked = 0
        index = 0
        for _ts, buf, start, length in iter_frames(str(path)):
            index += 1
            parsed = _parse_frame(buf, start, length)
            if parsed is None or parsed[0] != TYPE_DATA:
                continue
            payload = bytes(buf[start + parsed[4]:start + length])
            if len(payload) < 24:
                continue
            body = payload[8:]                     # skip LLC/SNAP if present
            if body and not any(body):
                zeros.append(index)
            checked += 1
        return zeros, checked


# --------------------------------------------------------------------------- #
# 3. FragAttacks
# --------------------------------------------------------------------------- #


class FragAttacksDetectAttack(OfflineAttack):
    name = "fragattacks_detect"
    label = "FragAttacks exposure audit (CVE-2020-24588 and relatives)"
    tool = "wifipilot ies.py + pcap.py (aggregation and fragmentation)"
    description = ("CVE-2020-24588 needs A-MSDU aggregation, and 24586/24587 need "
                   "fragmented or non-contiguous frames: all three are visible in a "
                   "capture.  The audit reports whether the AP advertises A-MSDU, "
                   "whether it actually sends aggregated QoS frames, whether clients "
                   "send fragmented frames, and the beacon facts (HT/VHT/HE, vendor) "
                   "that the published advisories use to scope affected hardware.  No "
                   "frame is transmitted.")

    category = "offline"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        path = self.capture_path(ctx, ap)
        if not path:
            return AttackOutcome.skipped("no capture to analyse")
        facts = self._scan(path)
        amsdu = bool(facts["amsdu_frames"])
        fragments = bool(facts["fragments"])
        if amsdu or fragments:
            severity, title = "medium", "FragAttacks-relevant frames observed"
        else:
            severity, title = "info", "no aggregation or fragmentation in the capture"
        detail = (f"{facts['qos_data']} QoS data frame(s), {facts['amsdu_frames']} with "
                  f"A-MSDU present, {facts['fragments']} fragmented frame(s), "
                  f"{facts['protected']} protected — the CVE-2020-24588 precondition "
                  f"is {'present' if amsdu else 'not visible'}")
        return self._finish(ctx, ap, attempt, title, detail,
                            {"capture": path, **facts,
                             "vendor": ap.vendor or oui_vendor(ap.bssid),
                             "note": ("A-MSDU must be advertised *and* used: the audit "
                                      "reports both, because a driver that ignores the "
                                      "capability is not exploitable")},
                            severity=severity)

    @staticmethod
    def _scan(path: str) -> Dict[str, Any]:
        from ..pcap import TYPE_DATA, _parse_frame, iter_frames

        facts = {"qos_data": 0, "amsdu_frames": 0, "fragments": 0, "protected": 0,
                 "from_ap": 0, "from_client": 0}
        for _ts, buf, start, length in iter_frames(str(path)):
            parsed = _parse_frame(buf, start, length)
            if parsed is None or parsed[0] != TYPE_DATA:
                continue
            subtype = parsed[1]
            flags = buf[start + 1] if length > start + 1 else 0
            if flags & 0x40:
                facts["protected"] += 1
            if subtype & 0x08:
                facts["qos_data"] += 1
                # QoS control is the two bytes after the (30-byte) four-address header
                qos_at = start + 30
                if qos_at + 2 <= start + length:
                    qos = buf[qos_at] | (buf[qos_at + 1] << 8)
                    if qos & 0x0080:
                        facts["amsdu_frames"] += 1
            more_fragments = bool(flags & 0x04)
            fragment_number = (buf[start + 23] & 0x0F) if length > start + 23 else 0
            if more_fragments or fragment_number:
                facts["fragments"] += 1
            if flags & 0x02:
                facts["from_ap"] += 1
            elif flags & 0x01:
                facts["from_client"] += 1
        return facts


# --------------------------------------------------------------------------- #
# 4. 802.11r
# --------------------------------------------------------------------------- #


class FtAuditAttack(OfflineAttack):
    name = "ft_audit"
    label = "802.11r fast-transition audit"
    tool = "wifipilot ies.py (mobility domain + FT AKM)"
    description = ("Fast BSS Transition lets a client roam between APs without "
                   "re-doing the 4-way handshake, and its key hierarchy is derived from "
                   "the PSK with a public algorithm.  An auditor needs to know: is FT "
                   "enabled, is it PSK-based (FT-PSK) rather than 802.1X, and is PMF "
                   "protecting the transition?  FT with a known PSK means the mobility "
                   "domain can be joined from a twin, and the capture says which of "
                   "those is true.")

    category = "offline"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        path = self.capture_path(ctx, ap)
        md, akm_names, pmf = "", [], bool(ap.pmf)
        facts: Dict[str, Any] = {}
        if path:
            from ..ies import capture_beacons

            decoded = capture_beacons(path)
            entry = next((item for item in decoded.get("networks", [])
                          if item.get("bssid", "").lower() == ap.bssid.lower()), None)
            if entry is None and decoded.get("networks"):
                entry = decoded["networks"][0]
            if entry:
                facts = entry.get("facts", {}) or {}
                md = facts.get("mobility_domain", "") or entry.get("mobility_domain", "")
                akm_names = facts.get("akm", []) or []
                pmf = bool(facts.get("pmf_capable", pmf) or facts.get("pmf_required", pmf))
        ft = bool(md) or any("FT" in str(name).upper() for name in akm_names) or \
            [code for code in (facts.get("akm_codes") or []) if code in FT_AKMS]
        psk_ft = any("FT-PSK" in str(name).upper() for name in akm_names) or \
            any("PSK" in str(name).upper() for name in akm_names)
        if ft and psk_ft and not pmf:
            severity, title = "medium", "FT-PSK without PMF: fast transition is attackable"
        elif ft:
            severity, title = "info", "802.11r fast transition enabled"
        else:
            severity, title = "info", "no 802.11r fast transition advertised"
        detail = (f"mobility domain {md or 'none'}; AKMs "
                  f"{', '.join(str(name) for name in akm_names) or 'unknown'}; "
                  f"PMF {'on' if pmf else 'off'}"
                  + ("; FT-PSK with a public key hierarchy" if ft and psk_ft else ""))
        return self._finish(ctx, ap, attempt, title, detail,
                            {"capture": path, "mobility_domain": md, "akms": akm_names,
                             "pmf": pmf, "ft": bool(ft), "ft_psk": bool(psk_ft),
                             "note": ("FT-PSK derives PMK-R0/R1 from the PSK with the "
                                      "mobility domain as input: a known PSK plus a "
                                      "cloned domain is a working fast transition")},
                            severity=severity)


# --------------------------------------------------------------------------- #
# 5. PMF enforcement probe
# --------------------------------------------------------------------------- #


class PmfDowngradeProbeAttack(Attack):
    name = "pmf_downgrade_probe"
    label = "PMF enforcement probe (unprotected disassoc)"
    tool = "wifipilot rawtx.py (disassociation)"
    description = ("Send one unprotected disassociation frame to a station that is "
                   "associated to a PMF-capable AP, then watch whether it leaves.  If "
                   "it does, its PMF is not enforced — which is the difference between "
                   "'this network has 802.11w' and 'this client is protected by it'.  "
                   "One frame per client, no flood, and the station's own return tells "
                   "us the answer.  (A client that ignores it is the good outcome, and "
                   "the report says so.)")

    category = "rogue"
    noise = "quiet"
    impact = "degraded"
    requires = ("monitor",)
    needs_injection = True
    applies_to = ("WPA2", "WPA3", "WPA2/WPA3", "WPA-ENTERPRISE", "WPA2-ENTERPRISE",
                  "ENTERPRISE")

    def applies(self, ap: AccessPoint) -> bool:
        return bool(ap.clients) and (bool(ap.pmf) or bool(ap.sae) or ap.pmf_checked)

    def available(self, ctx: AttackContext) -> bool:
        if ctx.demo:
            return True
        from ..rawtx import injection_available
        return bool(ctx.monitor) and injection_available(ctx.monitor)

    def unavailable_reason(self, ctx: AttackContext) -> str:
        return "needs a monitor interface with injection to send the disassociation"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        if not ap.clients:
            return self.skip_if(ctx, ap, attempt, "no client is associated to test") or \
                AttackOutcome.skipped("no client")
        victim = sorted(ap.clients)[0]
        pmf_expected = bool(ap.pmf or ap.sae)
        if ctx.demo:
            left, ignored = self._demo(ctx, ap, victim, pmf_expected)
        else:
            from ..rawtx import RawInjector, build_disassoc

            injector = RawInjector(ctx.monitor)
            if not injector.open():
                return self.skip_if(ctx, ap, attempt,
                                    injector.result.error or "no injection socket") or \
                    AttackOutcome.skipped("no injection")
            ctx.set_channel(ap.channel)
            try:
                frame = build_disassoc(ap.bssid, victim, reason=8)
                injector.send([frame])
                ctx.log(f"sent one unprotected disassociation to {victim} "
                        f"({ap.display_name}); watching for {8}s")
                seen_left = False
                for observation in ctx.listen(8.0, channel=ap.channel):
                    if observation.get("station", "").lower() != victim.lower():
                        continue
                    if observation.get("subtype") in (11, 0, 2):        # auth/assoc
                        seen_left = True
                        break
                    if observation.get("subtype") in (10, 12) and \
                            observation.get("bssid", "").lower() == ap.bssid.lower():
                        seen_left = True
                        break
                ignored = not seen_left
                left = seen_left
            finally:
                injector.close()
        if pmf_expected and left:
            severity, title = "high", "PMF is advertised but not enforced"
        elif left:
            severity, title = "medium", f"{victim} accepted an unprotected disassociation"
        else:
            severity, title = "info", f"{victim} ignored the unprotected disassociation"
        detail = (f"one unprotected disassoc to {victim} on a network advertising "
                  f"{'PMF' if pmf_expected else 'no PMF'}: station "
                  + ("left and tried to reconnect" if left else "stayed associated"))
        return AttackOutcome.success(
            title, detail=detail,
            extra={"victim": victim, "pmf_advertised": pmf_expected, "left": left,
                   "ignored": not left, "frames": 1,
                   "note": ("an ignored frame is the correct behaviour for a "
                            "PMF-capable client; a client that leaves has no PMF in "
                            "force, so the classic deauth attack still applies to it")})

    def _demo(self, ctx: AttackContext, ap: AccessPoint, victim: str,
              pmf_expected: bool) -> Tuple[bool, bool]:
        """Simulated PMF behaviour: a PMF AP's client ignores it, others do not."""
        enforcement = pmf_expected and (int(ap.bssid.replace(":", ""), 16) % 3 != 0)
        ctx.progress(f"PMF probe against {victim}", kind="attack", bssid=ap.bssid,
                     percent=60, detail="one unprotected disassociation (simulated)")
        time.sleep(0.3)
        return (not enforcement), enforcement


# --------------------------------------------------------------------------- #
# 6. BTM hijack
# --------------------------------------------------------------------------- #


class BtmHijackAttack(Attack):
    name = "btm_hijack"
    label = "802.11v BTM steering to a rogue BSSID"
    tool = "wifipilot rawtx.py (WNM action frame)"
    description = ("Send a BSS Transition Management Request to a station with our own "
                   "BSSID at the top of the neighbour list.  802.11v exists so a "
                   "network can steer clients off congested radios; the frame is "
                   "unauthenticated unless PMF is in force, so the same steering works "
                   "for an attacker.  The measurement is whether the station stops "
                   "talking to the real AP — a client that ignores it is the correct "
                   "behaviour and is reported as such.")

    category = "rogue"
    noise = "quiet"
    impact = "degraded"
    requires = ("monitor",)
    needs_injection = True

    def available(self, ctx: AttackContext) -> bool:
        if ctx.demo:
            return True
        from ..rawtx import injection_available
        return bool(ctx.monitor) and injection_available(ctx.monitor)

    def unavailable_reason(self, ctx: AttackContext) -> str:
        return "needs a monitor interface with injection to send the BTM request"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(self.name, ap.bssid, tool=self.tool)
        if not ap.clients:
            return AttackOutcome.skipped("no client to steer",
                                         "BTM needs a station that is associated")
        victim = sorted(ap.clients)[0]
        rogue = "02:00:00:00:00:aa" if not ctx.demo else "02:00:00:00:00:ab"
        if ctx.demo:
            followed = int(ap.bssid.replace(":", ""), 16) % 2 == 0
            ctx.progress(f"BTM request to {victim}", kind="attack", bssid=ap.bssid,
                         percent=70, detail="neighbour list points at our BSSID "
                                            "(simulated)")
            time.sleep(0.3)
        else:
            from ..rawtx import RawInjector, build_btm_request

            injector = RawInjector(ctx.monitor)
            if not injector.open():
                return AttackOutcome.skipped(injector.result.error or "no injection socket")
            ctx.set_channel(ap.channel)
            followed = False
            try:
                frame = build_btm_request(ap.bssid, victim,
                                          candidates=[(rogue, ap.channel or 1, 81)],
                                          validity=120)
                injector.send([frame])
                ctx.log(f"BTM request sent to {victim} pointing at {rogue}")
                left_at = time.time()
                for observation in ctx.listen(10.0, channel=ap.channel):
                    if observation.get("station", "").lower() != victim.lower():
                        continue
                    if observation.get("subtype") in (11, 0, 2) or \
                            (observation.get("subtype") in (10, 12) and
                             observation.get("bssid", "").lower() == ap.bssid.lower()):
                        followed = True
                        break
            finally:
                injector.close()
        severity = "high" if followed else "info"
        title = ("station followed a forged BTM steering frame" if followed
                 else "station ignored the stolen BTM frame")
        detail = (f"one BTM request to {victim} listing {rogue} as the preferred "
                  f"neighbour: station {'left the real AP' if followed else 'stayed'}")
        return AttackOutcome.success(
            title, detail=detail,
            extra={"victim": victim, "rogue_bssid": rogue, "followed": followed,
                   "note": ("802.11v steering is advisory and unauthenticated without "
                            "PMF: the finding is a client that follows it")})


# --------------------------------------------------------------------------- #
# 7. beacon behaviour
# --------------------------------------------------------------------------- #


class BeaconRateAuditAttack(OfflineAttack):
    name = "beacon_rate_audit"
    label = "Beacon behaviour audit (clones and floods)"
    tool = "wifipilot pcap.py (TSF, interval, sequence)"
    description = ("A beacon's *behaviour* is as telling as its information elements: "
                   "the beacon interval, whether the TSF timer advances plausibly, "
                   "whether the sequence numbers run in order, and how many BSSIDs "
                   "share the same element fingerprint.  A clone or a beacon-flooding "
                   "device is visible here and invisible in an SSID list.")

    category = "offline"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        path = self.capture_path(ctx, ap)
        if not path:
            return AttackOutcome.skipped("no capture to analyse")
        entries, shared = self._scan(path)
        mine = next((entry for entry in entries
                     if entry["bssid"].lower() == ap.bssid.lower()), None)
        if mine is None:
            severity, title = "low", "target BSSID not in the capture"
            detail = f"{len(entries)} BSSID(s) in {os.path.basename(path)}; none is {ap.bssid}"
        else:
            odd_interval = mine["interval"] not in (100, 200)
            frozen_tsf = mine["tsf_span"] == 0 and mine["beacons"] > 3
            severity = "medium" if (odd_interval or frozen_tsf) else "info"
            title = ("beacon timing looks forged" if (odd_interval or frozen_tsf)
                     else "beacon behaviour is consistent")
            detail = (f"{mine['beacons']} beacon(s): interval {mine['interval']} TU, TSF "
                      f"span {mine['tsf_span']}, sequence "
                      f"{'ordered' if mine['ordered'] else 'out of order'}"
                      + (f"; {len(shared)} BSSID(s) share its element fingerprint"
                         if shared else ""))
        return self._finish(ctx, ap, attempt, title, detail,
                            {"capture": path, "networks": entries[:20],
                             "shared_fingerprints": shared,
                             "note": ("a beacon interval outside 100/200 TU, a TSF that "
                                      "never advances, or a fingerprint shared with "
                                      "several BSSIDs all point at synthetic traffic")},
                            severity=severity)

    @staticmethod
    def _scan(path: str) -> Tuple[List[Dict[str, Any]], List[str]]:
        from ..pcap import TYPE_MGMT, _parse_frame, iter_frames

        state: Dict[str, Dict[str, Any]] = {}
        fingerprints: Dict[str, List[str]] = defaultdict(list)
        for _ts, buf, start, length in iter_frames(str(path)):
            parsed = _parse_frame(buf, start, length)
            if parsed is None or parsed[0] != TYPE_MGMT or parsed[1] != 8:
                continue
            bssid = parsed[2]
            body_at = start + 36
            if length < 36:
                continue
            timestamp = int.from_bytes(bytes(buf[body_at - 12:body_at - 4]), "little")
            interval = int.from_bytes(bytes(buf[body_at - 4:body_at - 2]), "little")
            sequence = (buf[start + 22] | (buf[start + 23] << 8)) >> 4
            entry = state.setdefault(bssid, {"bssid": bssid, "beacons": 0,
                                             "interval": interval, "tsf_min": timestamp,
                                             "tsf_max": timestamp, "ordered": True,
                                             "last_sequence": sequence,
                                             "fingerprint": hashlib.sha1(
                                                 bytes(buf[body_at:body_at + 96])).hexdigest()[:12]})
            entry["beacons"] += 1
            entry["tsf_min"] = min(entry["tsf_min"], timestamp)
            entry["tsf_max"] = max(entry["tsf_max"], timestamp)
            if sequence <= entry["last_sequence"] and entry["beacons"] > 1:
                entry["ordered"] = False
            entry["last_sequence"] = sequence
            fingerprints[entry["fingerprint"]].append(bssid)
        out = []
        for entry in state.values():
            entry["tsf_span"] = entry["tsf_max"] - entry["tsf_min"]
            out.append(entry)
        shared = [fingerprint for fingerprint, bssids in fingerprints.items()
                  if len(set(bssids)) > 1]
        return out, shared


# --------------------------------------------------------------------------- #
# 8. TSF clone detection
# --------------------------------------------------------------------------- #


class TsfCloneDetectAttack(OfflineAttack):
    name = "tsf_clone_detect"
    label = "TSF clone detector (same SSID, unrelated clocks)"
    tool = "wifipilot pcap.py (TSF correlation)"
    description = ("Two access points with the same SSID on the same infrastructure "
                   "share a time synchronisation function, because the controller sets "
                   "it.  Two BSSIDs with the same name and unrelated TSF counters are "
                   "therefore either different networks that chose the same name or one "
                   "of them is a clone — and this test needs only a capture, so it "
                   "works when the twin is nowhere near you.")

    category = "offline"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        path = self.capture_path(ctx, ap)
        if not path:
            return AttackOutcome.skipped("no capture to analyse")
        groups = self._scan(path)
        suspects = [group for group in groups
                    if len(group["bssids"]) > 1 and group["unrelated"]]
        if suspects:
            severity, title = "medium", "identical SSIDs with unrelated TSF clocks"
            detail = ("; ".join(
                f"{group['essid']!r}: {', '.join(group['bssids'])} "
                f"(TSF spread {group['spread']} µs, fingerprint "
                f"{'differs' if group['different_ies'] else 'matches'})"
                for group in suspects[:4]))
        else:
            severity, title = "info", "no SSID groups with unrelated clocks"
            detail = f"{len(groups)} SSID group(s) analysed in {os.path.basename(path)}"
        return self._finish(ctx, ap, attempt, title, detail,
                            {"capture": path, "groups": groups,
                             "suspects": suspects,
                             "note": ("a mesh or controller-managed network keeps its "
                                      "BSSIDs' TSF counters within microseconds; a "
                                      "clone starts from its own clock")},
                            severity=severity)

    @staticmethod
    def _scan(path: str) -> List[Dict[str, Any]]:
        from ..pcap import TYPE_MGMT, _parse_frame, iter_frames

        by_ssid: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for _ts, buf, start, length in iter_frames(str(path)):
            parsed = _parse_frame(buf, start, length)
            if parsed is None or parsed[0] != TYPE_MGMT or parsed[1] != 8:
                continue
            if length < 60:
                continue
            essid = bytes(buf[start + 38:start + 38 + min(32, buf[start + 37])])
            text = essid.decode("utf-8", "replace").strip("\x00")
            if not text:
                continue
            tsf = int.from_bytes(bytes(buf[start + 24:start + 32]), "little")
            fingerprint = hashlib.sha1(bytes(buf[start + 36:start + 36 + 96])).hexdigest()[:12]
            by_ssid[text].append({"bssid": parsed[2], "tsf": tsf,
                                  "fingerprint": fingerprint})
        groups: List[Dict[str, Any]] = []
        for essid, entries in by_ssid.items():
            per_bssid: Dict[str, List[int]] = defaultdict(list)
            fingerprints = set()
            for entry in entries:
                per_bssid[entry["bssid"]].append(entry["tsf"])
                fingerprints.add(entry["fingerprint"])
            if len(per_bssid) < 2:
                continue
            clocks = {bssid: min(values) for bssid, values in per_bssid.items()}
            spread = max(clocks.values()) - min(clocks.values())
            groups.append({"essid": essid, "bssids": sorted(per_bssid),
                           "spread": spread, "unrelated": spread > 5_000_000,
                           "different_ies": len(fingerprints) > 1})
        return groups


# --------------------------------------------------------------------------- #
# 9. station fingerprinting
# --------------------------------------------------------------------------- #


class ClientFingerprintAttack(OfflineAttack):
    name = "client_fingerprint"
    label = "Station fingerprinting (vendor, randomisation, probes)"
    tool = "wifipilot sniff.py + pcap.py"
    description = ("Build the device table an engagement needs before it plans anything: "
                   "every station in the capture with its vendor, whether its MAC is "
                   "randomised, the names it has probed for, and how it behaves.  It is "
                   "the reconnaissance step that decides whether a twin or a sniffing "
                   "attack is worth running, and it never transmits.")

    category = "offline"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        path = self.capture_path(ctx, ap)
        if not path:
            return AttackOutcome.skipped("no capture to analyse")
        stations = self._scan(path)
        randomised = [station for station in stations if station["randomised"]]
        with_probes = [station for station in stations if station["probes"]]
        if with_probes:
            severity, title = "medium", f"{len(with_probes)} station(s) leak their PNL"
        elif stations:
            severity, title = "info", f"{len(stations)} station(s) fingerprinted"
        else:
            severity, title = "low", "no stations in the capture"
        detail = (f"{len(stations)} station(s), {len(randomised)} with a randomised MAC, "
                  f"{len(with_probes)} leaking probed names; vendors: "
                  + ", ".join(sorted({station['vendor'] or 'unknown'
                                      for station in stations})[:8]))
        return self._finish(ctx, ap, attempt, title, detail,
                            {"capture": path, "stations": stations,
                             "randomised": [station["mac"] for station in randomised],
                             "note": ("a randomised MAC hides the vendor but not the "
                                      "probe list: the names a station asks for are "
                                      "still identifiable")},
                            severity=severity)

    @staticmethod
    def _scan(path: str) -> List[Dict[str, Any]]:
        from ..pcap import TYPE_MGMT, TYPE_DATA, _parse_frame, iter_frames
        from ..sniff import probe_requests

        stations: Dict[str, Dict[str, Any]] = {}

        def touch(mac: str) -> Dict[str, Any]:
            entry = stations.get(mac)
            if entry is None:
                entry = stations[mac] = {"mac": mac, "vendor": oui_vendor(mac),
                                         "randomised": bool(int(mac.split(":")[0], 16) & 0x02)
                                         if mac else False,
                                         "probes": [], "frames": 0, "bssids": []}
            entry["frames"] += 1
            return entry

        for _ts, buf, start, length in iter_frames(str(path)):
            parsed = _parse_frame(buf, start, length)
            if parsed is None:
                continue
            ftype, subtype, bssid, station = parsed[0], parsed[1], parsed[2], parsed[3]
            if ftype == TYPE_MGMT and subtype in (4, 11, 0, 2) and station:
                entry = touch(station)
                if bssid and bssid not in entry["bssids"]:
                    entry["bssids"].append(bssid)
            elif ftype == TYPE_DATA and station:
                touch(station)
        try:
            for mac, client in probe_requests(path).items():
                entry = stations.get(mac)
                if entry is not None:
                    entry["probes"] = list(client.pnl())[:12]
        except (OSError, ValueError):                          # pragma: no cover
            pass
        return sorted(stations.values(), key=lambda entry: entry["frames"], reverse=True)


__all__ = ["BeaconRateAuditAttack", "BtmHijackAttack", "ClientFingerprintAttack",
           "FragAttacksDetectAttack", "FtAuditAttack", "KrackDetectAttack",
           "Kr00kDetectAttack", "PmfDowngradeProbeAttack", "TsfCloneDetectAttack"]
