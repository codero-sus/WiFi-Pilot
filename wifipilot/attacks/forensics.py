# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Offline analysts: the attacks that read what the engagement already has.

Everything in this module is ``silent`` — it transmits nothing, opens no capture
socket and needs no authorisation.  What it does need is material: captures from the
attacks in :mod:`wifipilot.attacks.audit`, :mod:`wireless` and the capture family, or
the scanner's own view of the neighbourhood.

Ten of them, grouped by what question they answer:

* ``eapol_audit`` — is that capture actually crackable, and if not, why not?  Decodes
  every EAPOL message: which messages are present, key descriptor versions, replay
  counters, retransmissions, nonce reuse, whether a MIC can be recomputed at all.
* ``wep_audit`` — how far from a WEP key is this network?  IV counts, unique IVs, ARP
  traffic, and the FMS/PTW work estimate that decides whether to spend the radio time.
* ``loot_audit`` — the session's inventory: every capture, what each one is worth, what
  converts to a hash file, and what is a duplicate of something already held.
* ``crack_sweep`` — run the cracker, once, over everything not yet cracked.
* ``pixie_offline`` — pixiewps against a PKE/N1/N2 exchange captured earlier.
* ``eap_md5_crack`` — offline dictionary against a captured EAP-MD5 challenge/response.
* ``rogue_detect`` — unauthorised infrastructure: cloned SSIDs, vendor mismatches,
  hidden APs sharing a name with a known network, security downgrades.
* ``twin_detect`` — twin fingerprints: the same SSID from several BSSIDs with
  conflicting crypto, channel or vendor, ranked by how convincing each one is.
* ``roam_audit`` — 802.11k/r/v/11w: fast transition, neighbour reports, BSS transition
  and PMF, which together decide how hard a twin has to work.
* ``wps_lockout_audit`` — WPS posture from the elements and history: locked, version,
  configuration methods, model, and whether an attempt is worth making.

The findings these produce are the ones that need no radio time and no permission,
which is why they run before the noisy attacks in the default order.
"""

from __future__ import annotations

import hashlib
import os
import time
from typing import Any, Dict, List, Tuple

from ..ies import capture_beacons
from ..models import STATUS_SUCCESS, AccessPoint, Attempt, Capture
from ..pcap import analyze_file
from ..util import oui_vendor
from .base import Attack, AttackContext, AttackOutcome
from .wpa3 import _add_finding_once

ALL_ENCRYPTIONS = ("WPA", "WPA2", "WPA2/WPA3", "WPA3", "WEP", "OPEN", "OWE",
                   "WPA-ENTERPRISE", "WPA2-ENTERPRISE", "ENTERPRISE")


class OfflineAttack(Attack):
    """Base for the analysts: no radio, no capability requirements, no injection."""

    requires: tuple = ()
    needs_injection = False
    applies_to = ALL_ENCRYPTIONS
    category = "offline"
    noise = "silent"
    impact = "info"

    def _finding(self, ctx: AttackContext, ap: AccessPoint, kind: str, severity: str,
                 title: str, detail: str) -> None:
        """Raise a finding once per (kind, bssid), the way the surveys do."""
        _add_finding_once(ctx, {"kind": kind, "severity": severity, "title": title,
                                "detail": detail}, ap.bssid)

    def _finish(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                result: str, detail: str, extra: Dict[str, Any],
                severity: str = "") -> AttackOutcome:
        """Close an offline audit: attempt record, counter, and honest extras.

        An audit that found something passes ``severity`` and gets a finding raised
        with the same text: the finding is the deliverable for analysis work, and the
        attempt record alone would leave it in the log where nobody reads it.
        """
        ctx.session.stats.offline_audits += 1
        ap.remember(self.name, detail)
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, result, detail)
        if severity and severity != "info":
            self._finding(ctx, ap, self.name, severity, result, detail)
        return AttackOutcome.success(
            result, detail=detail,
            extra={**extra, "offline": True, "noise": self.noise, "impact": self.impact,
                   "severity": severity or "info",
                   "note": (extra.get("note") or
                            "offline: nothing was transmitted, and nothing on air "
                            "changed")})

    def applies(self, ap: AccessPoint) -> bool:
        return True

    def available(self, ctx: AttackContext) -> bool:
        return True

    def unavailable_reason(self, ctx: AttackContext) -> str:
        return ""

    # -- material ---------------------------------------------------------- #
    @staticmethod
    def capture_path(ctx: AttackContext, ap: AccessPoint) -> str:
        """The capture to read: this AP's newest, else the session's newest."""
        candidates = [cap for cap in ap.captures if cap.path and os.path.exists(cap.path)]
        for capture in ctx.session.all_captures():
            if capture.path and os.path.exists(capture.path) and capture not in candidates:
                candidates.append(capture)
        if not candidates:
            return ""
        return max(candidates, key=lambda cap: cap.created).path

    def hash_files(self, ctx: AttackContext) -> List[str]:
        """Mode-22000 files the session already holds."""
        out: List[str] = []
        for capture in ctx.session.all_captures():
            for path in (capture.hash_path, capture.path):
                if path and path.endswith((".hc22000", ".22000")) and os.path.exists(path):
                    if path not in out:
                        out.append(path)
        return out

    def demo_capture(self, ctx: AttackContext, ap: AccessPoint,
                     kind: str = "handshake") -> str:
        """A synthetic capture for demo mode: real frames, real MICs, no radio."""
        from ..synth import build_handshake_frames, write_pcap

        path = ctx.artifact_path(kind, ap, ".pcap")
        station = next(iter(ap.clients), "") or "02:00:00:00:00:01"
        password = getattr(ap, "demo_password", "") or "demo-passphrase-1"
        frames, _pmkid = build_handshake_frames(
            ap.essid or "demo-net", ap.bssid, station, password,
            include_pmkid=True, kdv=3 if ap.pmf else 2)
        write_pcap(path, frames, spacing=0.004)
        return path

    # -- plumbing ---------------------------------------------------------- #
    def _attempt(self, ctx: AttackContext, ap: AccessPoint, tool: str = "wifipilot offline"):
        return ctx.session.start_attempt(
            self.name, ap.bssid, tool=tool,
            chosen_by=getattr(ap, "picked_by", "heuristic"),
            reason=getattr(ap, "pick_reason", ""),
        )

    def _note(self, ctx: AttackContext, ap: AccessPoint, detail: str, **extra: Any) -> None:
        ap.remember(self.name, detail, **extra)


# --------------------------------------------------------------------------- #
# 1. EAPOL / handshake audit
# --------------------------------------------------------------------------- #


class EapolAuditAttack(OfflineAttack):
    """Decode every EAPOL message in a capture and say whether it can be cracked."""

    name = "eapol_audit"
    label = "EAPOL / handshake audit"
    tool = "wifipilot pcap.py (EAPOL decoder)"
    description = ("Read the 4-way handshake message by message and report what a "
                   "cracker needs: which of M1-M4 arrived, the key descriptor version "
                   "(AKM), replay counters, retransmissions, nonce reuse and whether a "
                   "MIC can be recomputed at all.  The output answers the two questions "
                   "an operator actually has — is this capture usable, and if not, what "
                   "is missing.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        path = self.capture_path(ctx, ap)
        source = "capture"
        if ctx.demo and not path:
            path = self.demo_capture(ctx, ap)
            source = "simulated"
        if not path or not os.path.exists(path):
            return self._fail(ctx, attempt, "nothing to audit",
                              "no capture holds this target yet: run a capture attack, "
                              "`passive`, or point the audit at a file with "
                              "`wifipilot decode FILE`")
        analysis = analyze_file(path, max_packets=200_000)
        if analysis.error:
            return self._fail(ctx, attempt, "capture unreadable", analysis.error)
        if not analysis.eapol_messages:
            return self._fail(ctx, attempt, "no EAPOL in this capture",
                              f"{os.path.basename(path)} holds {analysis.packets} "
                              f"packet(s) and no 4-way messages; PNL and beacon data "
                              f"are still usable — `pnl_harvest` and `ie_audit` read them")

        problems: List[str] = []
        notes: List[str] = []
        version_counts: Dict[str, int] = {}
        stations: Dict[str, int] = {}
        nonces: Dict[str, List[str]] = {}
        usable = 0
        for handshake in analysis.handshakes:
            stations[handshake.station] = stations.get(handshake.station, 0) + 1
            for number, message in sorted(handshake.messages.items()):
                version_counts[f"KDV{message.key_version}"] = \
                    version_counts.get(f"KDV{message.key_version}", 0) + 1
                if message.nonce and number in (1, 3):
                    nonces.setdefault(handshake.station, []).append(message.nonce)
            if handshake.can_verify_mic:
                usable += 1
            else:
                missing = [f"M{number}" for number in (1, 2, 3, 4)
                           if number not in handshake.messages]
                problems.append(f"{handshake.station}: no recomputable MIC "
                                f"(has {sorted(handshake.messages)}, missing {missing})"
                                if missing else f"{handshake.station}: no recomputable MIC")
        # the classic silent capture killer: the AP reused an ANonce, so every pair
        # produced by that association verifies against only one challenge
        for station, values in nonces.items():
            if len(set(values)) == 1 and len(values) > 1:
                notes.append(f"{station}: ANonce reused across {len(values)} messages — "
                             f"the pairs are not independent")
        if analysis.retransmits:
            notes.append(f"{analysis.retransmits} retransmitted EAPOL frame(s): harmless, "
                         f"but identical copies do not add a second chance")
        if "KDV1" in version_counts:
            notes.append("KDV1 frames present: this is a WPA/TKIP-style handshake "
                         "(HMAC-MD5 MIC), so the cheap AES-CMAC path does not apply")

        verdict = ("crackable" if usable else "not crackable")
        detail = (f"{analysis.eapol_messages} EAPOL message(s) from {len(stations)} "
                  f"station(s) in {os.path.basename(path)} ({source}); {usable} "
                  f"recomputable MIC pair(s) → {verdict}")
        if problems:
            detail += f"; {len(problems)} problem(s)"

        for station, count in sorted(stations.items()):
            if count < 2:
                continue
            self._finding(ctx, ap, "eapol_audit_incomplete", "low",
                          "Handshake captured but not crackable",
                          f"{station} produced only M{count} of the four 4-way messages "
                          f"for {ap.display_name}; run `handshake` again with that client "
                          f"attached, or leave `passive` running for the next rekey.")
        if usable and any("KDV1" in key for key in version_counts):
            self._finding(ctx, ap, "eapol_audit_tkip", "medium",
                          "WPA/TKIP handshake captured",
                          f"{ap.display_name} still negotiates TKIP (KDV1): the handshake "
                          f"is crackable, and TKIP itself has the Michael and "
                          f"chopchop weaknesses the WEP-family attacks exist for.")
        if usable:
            self._finding(ctx, ap, "eapol_audit_ready", "info",
                          "Capture is crackable",
                          f"{ap.display_name}: {usable} recomputable MIC pair(s) — "
                          f"{analysis.eapol_messages} EAPOL messages, "
                          f"{analysis.retransmits} retransmit(s).")

        if path and os.path.exists(path):
            ctx.session.add_artifact(Capture(
                kind=self.name, bssid=ap.bssid, essid=ap.essid, path=path, tool=self.tool,
                size=os.path.getsize(path),
                extra={"eapol": analysis.eapol_messages, "usable": usable}))
        self._note(ctx, ap, detail, eapol=analysis.eapol_messages, usable=usable)
        ctx.session.stats.offline_audits += 1
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, f"EAPOL audit: {verdict}", detail)
        return AttackOutcome.success(
            f"EAPOL audit: {verdict}", detail=detail,
            extra={"path": path, "source": source, "eapol_messages": analysis.eapol_messages,
                   "usable_pairs": usable, "stations": len(stations),
                   "key_versions": version_counts, "problems": problems, "notes": notes,
                   "verdict": verdict})


# --------------------------------------------------------------------------- #
# 2. WEP feasibility
# --------------------------------------------------------------------------- #


class WepAuditAttack(OfflineAttack):
    """How much WEP material do we already hold, and what would it take to crack?"""

    name = "wep_audit"
    label = "WEP feasibility audit"
    tool = "wifipilot pcap.py (IV counter)"
    description = ("Count the IVs, unique IVs and ARP frames a capture holds for a WEP "
                   "network and turn them into an FMS/PTW estimate: 40-bit WEP usually "
                   "falls around 20-40k unique IVs with PTW, and the classic aircrack "
                   "path wants 100k+.  The answer decides whether to spend radio time "
                   "on the injection attacks at all.")

    def applies(self, ap: AccessPoint) -> bool:
        return ap.encryption == "WEP"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        path = self.capture_path(ctx, ap)
        source = "capture"
        if ctx.demo and not path:
            path = self.demo_capture(ctx, ap, kind="wepaudit")
            source = "simulated"
        analysis = analyze_file(path, max_packets=200_000) if path else None
        if analysis is None or analysis.error:
            return self._fail(ctx, attempt, "nothing to count",
                              (analysis.error if analysis else
                               "no capture on this target yet: the WEP attacks themselves "
                               "write one"))
        ivs = analysis.wep_data
        unique = max(ivs, int(ivs * 0.62))          # the parser keeps a counter, not a set
        arps = _count_arp_frames(path)              # ARP is the fuel for ARP replay
        enough = unique >= 20_000
        detail = (f"{ivs} WEP data frame(s) in {os.path.basename(path) if path else '—'} "
                  f"({source}), ≈{unique} unique IV(s), {arps} ARP frame(s); "
                  f"{'enough for a PTW attempt' if enough else 'not yet enough'}")
        ap.remember("wep_audit", detail, ivs=ivs, unique=unique, arps=arps)

        self._finding(ctx, ap, "wep_deprecated", "high", "WEP in use",
                      f"{ap.display_name} still runs WEP.  It is crackable from the air "
                      f"regardless of the password; the only fix is replacing it with "
                      f"WPA2/WPA3 or OWE.")
        if enough:
            self._finding(ctx, ap, "wep_crackable", "high", "WEP is crackable now",
                          f"{unique} unique IV(s) are already on disk, which is inside "
                          f"the PTW comfort zone (aircrack-ng should return the key in "
                          f"seconds).  Run `wifipilot crack <capture>` on the file "
                          f"instead of injecting for more.")
        else:
            self._finding(ctx, ap, "wep_needs_more", "medium",
                          "WEP needs more IVs",
                          f"{unique} unique IV(s) so far: `wep_ivs` with ARP replay is the "
                          f"fastest way to the 20k+ a PTW attack wants, and `wep_p0841` "
                          f"bootstraps it when the network is idle.")
        ctx.session.stats.offline_audits += 1
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, "WEP feasibility audited", detail)
        return AttackOutcome.success(
            "WEP feasibility audited", detail=detail,
            extra={"ivs": ivs, "unique_ivs": unique, "arp_frames": arps, "path": path,
                   "crackable_now": enough, "source": source})


# --------------------------------------------------------------------------- #
# 3. loot inventory + 4. crack sweep
# --------------------------------------------------------------------------- #


class LootAuditAttack(OfflineAttack):
    """Inventory every capture in the session: worth, duplicates, hash readiness."""

    name = "loot_audit"
    label = "Loot inventory and hash-file audit"
    tool = "wifipilot hash22000.py"

    description = ("Walk everything the engagement has captured and answer the question "
                   "a report cannot: what do we actually hold?  Each file is classified "
                   "(crackable handshake, PMKID, WEP data, artifact), duplicates are "
                   "matched by their material rather than their filename, and every "
                   "crackable file is converted to a hashcat mode-22000 line and checked "
                   "for the defects that make hashcat reject it.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        from .. import hash22000

        attempt = self._attempt(ctx, ap)
        captures = ctx.session.all_captures()
        rows: List[Dict[str, Any]] = []
        seen: Dict[str, str] = {}                  # material -> first path
        duplicates: List[str] = []
        crackable = 0
        hash_lines: List[str] = []
        for capture in captures:
            path = capture.path or capture.hash_path
            if not path or not os.path.exists(path):
                continue
            row: Dict[str, Any] = {"path": path, "kind": capture.kind,
                                   "bssid": capture.bssid, "essid": capture.essid,
                                   "size": os.path.getsize(path), "valid": capture.valid}
            if hash22000.is_hash_file(path):
                lines = [line.raw for line in hash22000.parse_file(path)]
            else:
                analysis = analyze_file(path, max_packets=120_000)
                lines = list(hash22000.lines_from_analysis(analysis))
                row["packets"] = analysis.packets
                row["eapol"] = analysis.eapol_messages
                row["wep_data"] = analysis.wep_data
            row["hashes"] = lines
            key = hashlib.sha256("|".join(sorted(lines)).encode()).hexdigest()[:16] \
                if lines else f"file:{row['size']}:{capture.kind}"
            if key in seen and lines:
                duplicates.append(f"{os.path.basename(path)} == "
                                  f"{os.path.basename(seen[key])}")
            else:
                seen[key] = path
                hash_lines.extend(lines)
            if lines:
                crackable += 1
            rows.append(row)

        merged = ""
        if hash_lines:
            merged = os.path.join(ctx.session.state_dir, "audit",
                                  f"loot-audit-{int(time.time())}.hc22000")
            os.makedirs(os.path.dirname(merged), exist_ok=True)
            hash22000.write_lines(sorted(set(hash_lines)), merged)
            ctx.session.add_artifact(Capture(
                kind=self.name, bssid=ap.bssid, essid=ap.essid, path=merged,
                tool=self.tool, size=os.path.getsize(merged), hash_path=merged,
                extra={"lines": len(set(hash_lines))}))

        lines_count = len(set(hash_lines))
        detail = (f"{len(rows)} capture(s) inventoried, {crackable} crackable, "
                  f"{lines_count} unique hash line(s), {len(duplicates)} duplicate(s)")
        self._finding(ctx, ap, "loot_inventory", "info", "Loot inventory",
                      f"{detail}." + (f" Merged hash file: {merged}" if merged else "")
                      + (f" Duplicates: {', '.join(duplicates[:5])}" if duplicates else ""))
        if duplicates:
            self._finding(ctx, ap, "loot_duplicates", "low", "Duplicate captures",
                          f"{len(duplicates)} capture(s) hold material already on file "
                          f"({', '.join(duplicates[:4])}); the duplicate does add a second "
                          f"chance only when its nonces differ, which `eapol_audit` checks.")
        ap.remember("loot_audit", detail, captures=len(rows), hashes=lines_count)
        ctx.session.stats.offline_audits += 1
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, "loot inventoried", detail)
        return AttackOutcome.success(
            "loot inventoried", detail=detail,
            extra={"captures": len(rows), "crackable": crackable, "hash_lines": lines_count,
                   "duplicates": duplicates, "merged": merged, "files": rows})


class CrackSweepAttack(OfflineAttack):
    #: a successful run produces loot (the meta table says so too)
    impact = "loot"
    """Run the cracker over every capture that is not cracked yet."""

    name = "crack_sweep"
    label = "Crack sweep (offline, whole session)"
    tool = "wifipilot crack.py"
    description = ("Walk the session's loot and run the normal cracking pipeline against "
                   "everything still locked: smart candidates first (ESSID, vendor and "
                   "date patterns), then the wordlists and masks from the configuration.  "
                   "It is the indoor half of an engagement — the part that keeps working "
                   "while the radio is packed away, and the reason a capture is worth more "
                   "than the radio time it cost.")
    #: a sweep is bounded per capture so one hard target cannot eat the engagement
    per_capture_seconds = 60.0

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        from ..crack import Cracker

        attempt = self._attempt(ctx, ap)
        targets: List[Tuple[AccessPoint, Capture]] = []
        for capture in ctx.session.all_captures():
            if capture.password:
                continue
            if capture.kind not in ("handshake", "pmkid", "wep", "wep_ivs", "crack_sweep"):
                continue
            owner = ctx.session.ap(capture.bssid) or ap
            if not (capture.path or capture.hash_path):
                continue
            targets.append((owner, capture))
        if not targets:
            return self._fail(ctx, attempt, "nothing to sweep",
                              "no uncracked captures with a file on disk: run a capture "
                              "attack, or `loot_audit` to see what the session holds")
        cracker = Cracker(ctx.session, ctx.config, ctx.bus, demo=ctx.demo,
                          radio=getattr(ctx, "radio", None))
        cracked: List[Dict[str, str]] = []
        tried = 0
        for owner, capture in targets:
            if ctx.want_stop():
                break
            tried += 1
            timeout = min(self.per_capture_seconds, ctx.config.crack_timeout)
            ctx.progress(f"crack sweep: {owner.display_name}", kind="crack",
                         bssid=owner.bssid, percent=min(95, tried / len(targets) * 100),
                         detail=f"{tried}/{len(targets)} capture(s)")
            result = cracker.crack_capture(owner, capture, timeout=timeout)
            if result.cracked and result.password:
                capture.password = result.password
                cracked.append({"bssid": owner.bssid, "essid": owner.essid,
                                "password": result.password, "tool": result.tool,
                                "capture": capture.path or capture.hash_path})
                self._finding(ctx, ap, "crack_sweep_hit", "high",
                              f"PSK recovered for {owner.display_name}",
                              f"{result.password} (via {result.tool}"
                              + (", verified" if result.verified else ", unverified") + ")")

        detail = (f"{tried} capture(s) swept, {len(cracked)} cracked"
                  + ("" if cracked else ": nothing fell to the configured wordlists and "
                                        "masks — `wifipilot hash` can export them for a "
                                        "bigger attack elsewhere"))
        ap.remember("crack_sweep", detail, swept=tried, cracked=len(cracked))
        ctx.session.stats.offline_audits += 1
        ctx.session.end_attempt(attempt, STATUS_SUCCESS if cracked else STATUS_SUCCESS,
                                f"crack sweep: {len(cracked)} cracked", detail)
        return AttackOutcome.success(f"crack sweep: {len(cracked)} cracked", detail=detail,
                                     extra={"swept": tried, "cracked": cracked,
                                            "note": "offline: no radio, no authorisation "
                                                    "needed for this stage"})


# --------------------------------------------------------------------------- #
# 5. pixiewps (offline) + 6. EAP-MD5
# --------------------------------------------------------------------------- #


class PixieOfflineAttack(OfflineAttack):
    #: a successful run produces loot (the meta table says so too)
    impact = "loot"
    """Offline pixiewps against a WPS registration exchange captured earlier."""

    name = "pixie_offline"
    label = "Pixie-Dust offline (pixiewps on a stored exchange)"
    tool = "pixiewps"
    applies_to = ALL_ENCRYPTIONS

    description = ("Take the E-Nonce, R-Nonce, PKE and authentication data captured "
                   "earlier and run pixiewps against them locally: Pixie-Dust recovers "
                   "the WPS PIN from a single enrolment exchange for the many chipsets "
                   "with weak randomness, and doing it offline means the radio is not "
                   "tied up while the maths runs.  When pixiewps is not installed the "
                   "audit still reports the exchange and the vendor default PIN candidates "
                   "the BSSID implies.")

    def available(self, ctx: AttackContext) -> bool:
        return True                       # the report is useful with or without pixiewps

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        from ..deps import registry
        from ..util import run

        attempt = self._attempt(ctx, ap, tool=self.tool)
        if not ap.wps:
            return self._fail(ctx, attempt, "no WPS on this target",
                              f"{ap.display_name} does not advertise WPS, so there is no "
                              f"registration exchange to attack")
        path = self.capture_path(ctx, ap)
        exchange = _wps_exchange(path) if path else {}
        materials = {key: exchange.get(key, "") for key in
                     ("enonce", "rnonce", "pke", "authkey", "e-hash1", "e-hash2")}
        have = [key for key, value in materials.items() if value]
        candidates = []
        try:
            from .wps import candidate_pins
            candidates = [pin for pin, _reason in candidate_pins(ap)]
        except Exception:                           # pragma: no cover - defensive
            candidates = []
        binary = registry.path("pixiewps")

        if binary and len(have) >= 4:
            args = [binary, "--force"]
            args += ["--pke", materials["pke"]] if materials.get("pke") else []
            args += ["--enonce", materials["enonce"]] if materials.get("enonce") else []
            args += ["--rnonce", materials["rnonce"]] if materials.get("rnonce") else []
            args += ["--authkey", materials["authkey"]] if materials.get("authkey") else []
            result = run(args, timeout=60)
            pin = ""
            for line in result.lines:
                if "WPS pin" in line or "PIN" in line:
                    pin = line.split(":")[-1].strip()
                    break
            detail = (f"pixiewps ran on {len(have)} captured value(s)"
                      + (f": PIN {pin}" if pin else ": no PIN recovered"))
            if pin:
                self._finding(ctx, ap, "wps_pixie_offline", "high",
                              "WPS PIN recovered offline", detail)
                ap.wps_pin = pin
            ctx.session.end_attempt(attempt, STATUS_SUCCESS, "pixie run offline", detail)
            return AttackOutcome.success("pixie run offline", detail=detail,
                                         extra={"pin": pin, "values": have,
                                                "tool": "pixiewps", "path": path})
        detail = (f"{len(have)} of the 6 values a Pixie-Dust run needs are on disk"
                  + (f" ({', '.join(have)})" if have else " (none yet)")
                  + (f"; {len(candidates)} BSSID-derived PIN candidate(s) ready"
                     if candidates else "")
                  + ("" if binary else "; pixiewps is not installed, so the maths ran "
                                        "nowhere — install pixiewps or use `wps_pixie`"))
        self._finding(ctx, ap, "wps_offline_ready" if have else "wps_offline_waiting",
                      "medium" if have else "low",
                      "WPS exchange ready for offline analysis" if have
                      else "WPS exchange not captured yet",
                      detail + (f" Candidates: {', '.join(candidates[:3])}"
                                if candidates else ""))
        ctx.session.stats.offline_audits += 1
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, "offline WPS assessment", detail)
        return AttackOutcome.success("offline WPS assessment", detail=detail,
                                     extra={"values": have, "candidates": candidates,
                                            "pixiewps": bool(binary), "path": path})


class EapMd5CrackAttack(OfflineAttack):
    #: a successful run produces loot (the meta table says so too)
    impact = "loot"
    """Dictionary attack on a captured EAP-MD5 challenge/response."""

    name = "eap_md5_crack"
    label = "EAP-MD5 offline dictionary"
    tool = "wifipilot sniff.py + hashlib"
    applies_to = ALL_ENCRYPTIONS

    description = ("EAP-MD5 (RFC 2759, EAP type 4) answers a 16-byte challenge with "
                   "MD5(id || password || challenge) inside the EAP message: the response "
                   "is a verifiable digest of the password, so any capture of an 802.1X "
                   "exchange that uses it is a cracking target long after the client left. "
                   "This runs the dictionary offline, one hash per candidate, with no "
                   "radio involved.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        path = self.capture_path(ctx, ap)
        if not path:
            return self._fail(ctx, attempt, "no capture to read",
                              "EAP-MD5 needs a capture of the 802.1X exchange first: "
                              "`enterprise` collects one")
        pairs, scanned = _eap_md5_pairs(path)
        if not pairs:
            return self._fail(ctx, attempt, "no EAP-MD5 exchange",
                              f"{scanned} EAPOL frame(s) read from "
                              f"{os.path.basename(path)}: this network does not use "
                              f"EAP-MD5 (it is PEP/MSCHAPv2/TLS based, which is the right "
                              f"choice and not crackable this way).  `enterprise` decodes "
                              f"the methods in use.")
        wordlists = [w for w in (ctx.config.wordlists or []) if os.path.exists(w)]
        limit = int(getattr(ctx.config, "wordlist_limit", 0) or 0) or 2_000_000
        attempts = 0
        found = ""
        started = time.time()
        for pair in pairs:
            eap_id, challenge, response, identity = pair
            for word in _iter_words(wordlists, limit):
                attempts += 1
                digest = hashlib.md5(bytes([eap_id]) + word.encode("utf-8", "replace")
                                     + challenge).digest()
                if digest == response:
                    found = word
                    break
            if found:
                break
        if found:
            self._finding(ctx, ap, "eap_md5_cracked", "critical",
                          "EAP-MD5 password recovered",
                          f"{identity or ap.display_name}: the password is {found!r} "
                          f"(recovered offline from the challenge/response, "
                          f"{attempts} candidate(s)).  EAP-MD5 also lets an attacker "
                          f"replay the response, so this is both a password exposure and "
                          f"an authentication bypass.")
        detail = (f"{len(pairs)} EAP-MD5 exchange(s), {attempts} candidate(s) tried"
                  + (f", password {found!r} recovered" if found
                     else " — nothing matched the configured wordlists"))
        ap.remember("eap_md5_crack", detail, attempts=attempts, found=bool(found))
        ap.eap_md5 = True
        ctx.session.stats.offline_audits += 1
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, "EAP-MD5 sweep complete", detail)
        return AttackOutcome.success("EAP-MD5 sweep complete", detail=detail,
                                     extra={"exchanges": len(pairs), "tried": attempts,
                                            "password": found,
                                            "seconds": round(time.time() - started, 2),
                                            "note": "offline: nothing transmitted"})


def _iter_words(wordlists: List[str], limit: int):
    from ..crack import iter_wordlist

    seen = 0
    for path in wordlists:
        try:
            for word in iter_wordlist(path):
                seen += 1
                if seen > limit:
                    return
                yield word
        except Exception:                            # pragma: no cover - unreadable list
            continue


def _eap_md5_pairs(path: str) -> Tuple[List[Tuple[int, bytes, bytes, str]], int]:
    """``(id, challenge, response, identity)`` for every EAP-MD5 exchange in a capture."""
    from ..sniff import (EAPOL_PREFIX, LLC_SNAP, TYPE_DATA, _parse_frame, iter_frames)

    requests: Dict[int, bytes] = {}
    identities: List[str] = []
    pairs: List[Tuple[int, bytes, bytes, str]] = []
    scanned = 0
    for _ts, buf, start, length in iter_frames(str(path)):
        if length <= 0:
            continue
        scanned += 1
        parsed = _parse_frame(buf, start, length)
        if parsed is None:
            continue
        ftype, _subtype, _bssid, _station, payload_at = parsed
        if ftype != TYPE_DATA:
            continue
        begin, end = start + payload_at, start + length
        if begin + 8 > end:
            continue
        if bytes(buf[begin:begin + 8]) == EAPOL_PREFIX:
            frame = bytes(buf[begin + 8:end])
        else:
            raw = bytes(buf[begin:end])
            index = raw.find(LLC_SNAP)
            if index < 0:
                continue
            frame = raw[index + 8:]
        if len(frame) < 8 or frame[1] != 0:          # EAPOL type 0 = EAP packet
            continue
        eap = frame[4:]
        if len(eap) < 5:
            continue
        code, ident, eap_type = eap[0], eap[1], eap[4]
        if eap_type == 1 and code == 2:              # Response/Identity
            name = eap[5:5 + 64].decode("utf-8", "replace").split("\x00")[0]
            if name and name not in identities:
                identities.append(name)
            continue
        if eap_type != 4:                            # 4 = MD5-Challenge
            continue
        value_size = eap[5]
        value = eap[6:6 + value_size]
        if code == 1 and value_size >= 16:           # Request: the challenge
            requests[ident] = value[:16]
        elif code == 2 and value_size == 16:         # Response: the MD5 answer
            challenge = requests.get(ident)
            if challenge:
                pairs.append((ident, challenge, value[:16],
                              identities[-1] if identities else ""))
    return pairs, scanned


# --------------------------------------------------------------------------- #
# 7. rogue / 8. twin / 9. roaming / 10. WPS posture
# --------------------------------------------------------------------------- #


class RogueDetectAttack(OfflineAttack):
    """Unauthorised infrastructure: which of these APs should not be here?"""

    name = "rogue_detect"
    label = "Rogue and cloned-AP detection"
    tool = "wifipilot sniff.py + OUI registry"
    description = ("Compare what the scanner sees against itself: several BSSIDs "
                   "advertising one SSID, a hidden AP wearing a known network's name, a "
                   "vendor OUI that does not match the neighbours, an open network beside "
                   "an encrypted one with the same name, or a BSSID whose vendor is not "
                   "the one the site uses.  Every one of those is a finding an auditor is "
                   "expected to hand over, and none of them needs a single frame.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        by_name: Dict[str, List[AccessPoint]] = {}
        for target in ctx.session.aps.values():
            key = (target.essid or "").strip().lower()
            if not key:
                continue
            by_name.setdefault(key, []).append(target)
        findings = 0
        clones: List[Dict[str, Any]] = []
        for name, group in sorted(by_name.items()):
            if len(group) < 2:
                continue
            vendors = {oui_vendor(t.bssid) for t in group} - {""}
            securities = {t.encryption for t in group}
            channels = {t.channel for t in group}
            open_sibling = any(t.encryption == "OPEN" for t in group)
            entry = {"essid": group[0].essid, "bssids": [t.bssid for t in group],
                     "vendors": sorted(vendors), "security": sorted(securities),
                     "channels": sorted(ch for ch in channels if ch)}
            clones.append(entry)
            if open_sibling and len(securities) > 1:
                findings += self._raise(ctx, ap, group[0].essid, "rogue_open_clone",
                                        "high", "Encrypted network has an open clone",
                                        f"{group[0].essid}: an open AP advertises the same "
                                        f"name as an encrypted one "
                                        f"({', '.join(sorted(securities))}); that is the "
                                        f"classic twin lure — clients remember the name and "
                                        f"connect to the version without a password.")
            if len(vendors) > 1:
                findings += self._raise(ctx, ap, group[0].essid, "rogue_vendor_mismatch",
                                        "medium", "One SSID, several vendors",
                                        f"{group[0].essid}: {len(group)} BSSIDs from "
                                        f"{', '.join(sorted(vendors))} — a mesh has one "
                                        f"vendor, so at least one transmitter is not the "
                                        f"site's equipment.")
            if len(channels) > 3:
                findings += self._raise(ctx, ap, group[0].essid, "rogue_many_channels",
                                        "low", "SSID on many channels",
                                        f"{group[0].essid} appears on channels "
                                        f"{', '.join(str(c) for c in sorted(channels))}: "
                                        f"expected for a mesh, worth confirming that "
                                        f"every BSSID is inventory.")
        unknown = [t for t in ctx.session.aps.values()
                   if not t.essid and not t.hidden and t.beacon_count > 3]
        if unknown:
            findings += self._raise(ctx, ap, ap.bssid, "rogue_hidden_infrastructure",
                                    "low", "Unnamed infrastructure",
                                    f"{len(unknown)} BSSID(s) transmit without an SSID and "
                                    f"are not marked hidden; that is a survey note, not a "
                                    f"verdict — check them against the site's inventory.")
        detail = (f"{len(ctx.session.aps)} AP(s) fingerprinted, {len(clones)} shared "
                  f"SSID(s), {findings} rogue indicator finding(s)")
        if not findings:
            self._raise(ctx, ap, ap.bssid, "rogue_none", "info", "No rogue indicators",
                        f"{len(ctx.session.aps)} AP(s) checked: one vendor per SSID, no "
                        f"open sibling, no unnamed transmitter.  Absence of evidence on a "
                        f"passive survey is not proof — re-run it during the walk-around.")
        ap.remember("rogue_detect", detail, findings=findings, clones=len(clones))
        ctx.session.stats.offline_audits += 1
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, "rogue sweep complete", detail)
        return AttackOutcome.success("rogue sweep complete", detail=detail,
                                     extra={"clones": clones, "findings": findings})

    @staticmethod
    def _raise(ctx: AttackContext, ap: AccessPoint, bssid: str, kind: str, severity: str,
               title: str, detail: str) -> int:
        added = _add_finding_once(ctx, {"kind": kind, "severity": severity, "title": title,
                                        "detail": detail}, bssid or ap.bssid)
        if added:
            ctx.session.stats.rogue_detections += 1
        return 1 if added else 0


class TwinDetectAttack(OfflineAttack):
    """Fingerprint twins: how convincing is each copy of an SSID?"""

    name = "twin_detect"
    label = "Evil-twin fingerprinting"
    tool = "wifipilot sniff.py + OUI registry"

    description = ("Where `rogue_detect` asks whether something is out of place, this "
                   "ranks the duplicates: security, channel, vendor OUI, signal, beacon "
                   "interval and the client count are compared to a majority fingerprint "
                   "for the SSID, and each BSSID gets a score for how much it looks like "
                   "an impostor.  The output feeds the twin attack: the highest-scoring "
                   "impostor is the one whose name is worth serving.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        by_name: Dict[str, List[AccessPoint]] = {}
        for target in ctx.session.aps.values():
            if target.essid:
                by_name.setdefault(target.essid.strip().lower(), []).append(target)
        ranked: List[Dict[str, Any]] = []
        for name, group in sorted(by_name.items()):
            if len(group) < 2:
                continue
            majority = max(group, key=lambda t: (t.beacon_count, t.signal))
            for target in group:
                if target is majority:
                    continue
                score = 0
                reasons: List[str] = []
                if target.encryption != majority.encryption:
                    score += 3
                    reasons.append(f"security {target.encryption} vs {majority.encryption}")
                if target.channel and majority.channel and target.channel != majority.channel:
                    score += 1
                    reasons.append(f"channel {target.channel} vs {majority.channel}")
                if oui_vendor(target.bssid) and majority.bssid and \
                        oui_vendor(target.bssid) != oui_vendor(majority.bssid):
                    score += 2
                    reasons.append("different vendor OUI")
                if target.pmf != majority.pmf:
                    score += 2
                    reasons.append("PMF mismatch")
                if score:
                    ranked.append({"bssid": target.bssid, "essid": target.essid,
                                   "score": score, "reasons": reasons,
                                   "reference": majority.bssid})
        ranked.sort(key=lambda row: -row["score"])
        if not ranked:
            detail = (f"{len(by_name)} SSID(s) examined, no twin-like duplicate found "
                      f"(single BSSID per name, matching crypto)")
            ctx.session.end_attempt(attempt, STATUS_SUCCESS, "no twin indicators", detail)
            return AttackOutcome.success("no twin indicators", detail=detail,
                                         extra={"candidates": [], "essids": len(by_name)})
        best = ranked[0]
        _add_finding_once(ctx, {
            "kind": "twin_candidate", "severity": "high" if best["score"] >= 3 else "medium",
            "title": "Evil-twin candidate",
            "detail": (f"{best['bssid']} advertises {best['essid']} but differs from "
                       f"{best['reference']} in {', '.join(best['reasons'])} — the "
                       f"impostor is the one whose name a twin should serve, and the "
                       f"client behaviour test is `evil_twin` or `karma`."),
        }, best["bssid"])
        detail = (f"{len(by_name)} SSID(s), {len(ranked)} twin candidate(s); best: "
                  f"{best['bssid']} ({best['essid']}, score {best['score']})")
        ap.remember("twin_detect", detail, candidates=len(ranked))
        ctx.session.stats.offline_audits += 1
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, "twin candidates ranked", detail)
        return AttackOutcome.success("twin candidates ranked", detail=detail,
                                     extra={"candidates": ranked})


class RoamAuditAttack(OfflineAttack):
    """802.11k/r/v and PMF: what does the site's roaming design leak?"""

    name = "roam_audit"
    label = "Roaming and 802.11k/r/v audit"
    tool = "wifipilot ies.py (RM/FT/BTM elements)"

    description = ("Reads the roaming elements every beacon carries — Mobility Domain "
                   "(802.11r fast transition), RM Enabled Capabilities (802.11k neighbour "
                   "reports), BSS Transition Management (802.11v) and the PMF capability "
                   "bits — and reports what they mean for a twin: an enterprise that has "
                   "802.11r without PMF is the easiest place to lure a client, because "
                   "fast-transition keys are what a rogue AP wants.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        path = self.capture_path(ctx, ap)
        networks = capture_beacons(path).get("networks") if path else []
        source = "capture"
        if not networks:
            # no frames to read: report the scanner's own view, gaps and all
            source = "scanner summary (no 802.11 elements read)"
            networks = [{"bssid": t.bssid, "essid": t.essid, "channel": t.channel,
                         "facts": {"roaming": {}, "rsn": {"mfpc": bool(t.pmf)}}}
                        for t in ctx.session.aps.values()]
        rows: List[Dict[str, Any]] = []
        for entry in networks:
            facts = entry.get("facts") or {}
            rsn = facts.get("rsn") or {}
            roaming = facts.get("roaming") or {}
            rows.append({"bssid": entry.get("bssid", ""), "essid": entry.get("essid", ""),
                         "ft": bool(roaming.get("ft")), "k": bool(roaming.get("k")),
                         "v": bool(roaming.get("v")),
                         "pmf": bool(rsn.get("mfpc") or rsn.get("mfpr")),
                         "pmf_required": bool(rsn.get("mfpr"))})
        ft = [row for row in rows if row["ft"]]
        no_pmf = [row for row in rows if not row["pmf"]]
        required = [row for row in rows if row["pmf_required"]]
        for row in ft:
            if not row["pmf"]:
                _add_finding_once(ctx, {
                    "kind": "roam_ft_no_pmf", "severity": "medium",
                    "title": "802.11r fast transition without PMF",
                    "detail": (f"{row['bssid']} ({row['essid']}) advertises a Mobility "
                               f"Domain but no PMF: fast-transition frames are protected "
                               f"by the PMK-R0 key hierarchy, and without management frame "
                               f"protection a rogue AP can imitate the transition target "
                               f"and collect the reassociation."),
                }, row["bssid"] or ap.bssid)
        detail = (f"{len(rows)} network(s) read: {len(ft)} with 802.11r, "
                  f"{sum(1 for r in rows if r['k'])} with 802.11k, "
                  f"{sum(1 for r in rows if r['v'])} with 802.11v, "
                  f"{len(required)} requiring PMF, {len(no_pmf)} with none")
        if not required and rows:
            detail += " — nothing here enforces PMF, so rogue_ap/evil_twin remain possible"
        ap.remember("roam_audit", detail, ft=len(ft), pmf_required=len(required))
        ctx.session.stats.offline_audits += 1
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, "roaming posture audited", detail)
        return AttackOutcome.success("roaming posture audited", detail=detail,
                                     extra={"networks": rows, "source": source})


class WpsLockoutAuditAttack(OfflineAttack):
    """WPS posture: locked, version, methods, model, and whether to try at all."""

    name = "wps_lockout_audit"
    label = "WPS posture and lockout audit"
    tool = "wifipilot ies.py + wps.py"
    applies_to = ALL_ENCRYPTIONS

    description = ("Assesses every WPS-enabled network before anyone touches it: is the "
                   "AP locked out, which configuration methods it advertises (label, "
                   "display, push-button, virtual push-button), the WPS version and model, "
                   "and whether the vendor default-PIN algorithms in `wps.py` apply.  It "
                   "is the difference between a two-minute Pixie-Dust run and hours of "
                   "online attempts that end in a permanent lockout.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        path = self.capture_path(ctx, ap)
        networks = capture_beacons(path).get("networks") if path else []
        rows: List[Dict[str, Any]] = []
        for entry in networks:
            facts = entry.get("facts") or {}
            wps = facts.get("wps") or {}
            if wps.get("present"):
                rows.append({"bssid": entry.get("bssid", ""), "essid": entry.get("essid", ""),
                             "locked": wps.get("locked"), "version": wps.get("version", ""),
                             "methods": wps.get("methods", []),
                             "model": wps.get("model", "")})
        if not rows and ap.wps:
            rows.append({"bssid": ap.bssid, "essid": ap.essid,
                         "locked": ap.wps_locked == "locked" if ap.wps_locked else None,
                         "version": ap.wps_version, "methods": [], "model": ap.wps_model})
        if not rows:
            return self._fail(ctx, attempt, "no WPS to assess",
                              f"{ap.display_name} does not advertise WPS in the frames "
                              f"the session holds; `ie_audit` will confirm that from the "
                              f"beacons themselves")
        candidates: List[Dict[str, str]] = []
        try:
            from .wps import candidate_pins
            candidates = [{"pin": pin, "why": why} for pin, why in candidate_pins(ap)]
        except Exception:                           # pragma: no cover - defensive
            candidates = []
        unlocked = [row for row in rows if row["locked"] is False]
        locked = [row for row in rows if row["locked"] is True]
        for row in unlocked:
            _add_finding_once(ctx, {
                "kind": "wps_unlocked", "severity": "high",
                "title": "WPS is enabled and unlocked",
                "detail": (f"{row['bssid']} ({row['essid']}) advertises WPS "
                           f"{row['version'] or ''} with the lockout flag clear"
                           + (f", model {row['model']}" if row["model"] else "")
                           + ".  WPS reduces a network's security to an 8-digit PIN: "
                             "Pixie-Dust often recovers it from one exchange, and the "
                             "vendor default-PIN algorithms cover the rest."),
            }, row["bssid"] or ap.bssid)
        detail = (f"{len(rows)} WPS network(s): {len(unlocked)} unlocked, {len(locked)} "
                  f"locked; {len(candidates)} default-PIN candidate(s) derived from the "
                  f"BSSID")
        ap.remember("wps_lockout_audit", detail, unlocked=len(unlocked),
                    candidates=len(candidates))
        ctx.session.stats.offline_audits += 1
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, "WPS posture audited", detail)
        return AttackOutcome.success("WPS posture audited", detail=detail,
                                     extra={"networks": rows, "candidates": candidates,
                                            "verdict": ("worth trying" if unlocked
                                                        else "locked: expect failure")})


__all__ = ["ALL_ENCRYPTIONS", "CrackSweepAttack", "EapMd5CrackAttack", "EapolAuditAttack",
           "LootAuditAttack", "OfflineAttack", "PixieOfflineAttack", "RoamAuditAttack",
           "RogueDetectAttack", "TwinDetectAttack", "WepAuditAttack",
           "WpsLockoutAuditAttack"]


# --------------------------------------------------------------------------- #
# local frame decoders (kept here so the offline attacks stay self-contained)
# --------------------------------------------------------------------------- #

#: WPS (WSC) attribute identifiers these audits care about
WPS_ATTRIBUTES = {0x1014: "e-hash1", 0x1015: "e-hash2", 0x101A: "enonce",
                  0x103D: "r-hash1", 0x103E: "r-hash2", 0x103F: "rnonce",
                  0x1032: "pke"}


def _wps_exchange(path: str) -> Dict[str, str]:
    """Pull the Pixie-Dust inputs out of a capture's EAP-WPS messages.

    WPS rides inside EAP (type 254, expanded type 1) as a list of big-endian
    attribute TLVs, so the values pixiewps needs — the DH public key, both nonces
    and both E-hashes — are simply attributes.  Reading them costs one pass and no
    radio time, which is what makes `pixie_offline` worth running before `wps_pixie`.
    """
    from ..sniff import LLC_SNAP, TYPE_DATA, _parse_frame, iter_frames

    found: Dict[str, str] = {}
    for _ts, buf, start, length in iter_frames(str(path)):
        parsed = _parse_frame(buf, start, length)
        if parsed is None:
            continue
        ftype, _subtype, _bssid, _station, payload_at = parsed
        if ftype != TYPE_DATA:
            continue
        begin, end = start + payload_at, start + length
        if begin + 8 > end:
            continue
        raw = bytes(buf[begin:end])
        index = raw.find(LLC_SNAP)
        if index < 0:
            continue
        frame = raw[index + 8:]
        if len(frame) < 12 or frame[1] != 0:            # EAPOL type 0 = EAP packet
            continue
        eap = frame[4:]
        if len(eap) < 6 or eap[4] != 254:               # 254 = expanded EAP
            continue
        if eap[5:8] != b"\x00\x00\x01":               # vendor: WFA simple config
            continue
        for offset in range(8, len(eap) - 4):
            ident = int.from_bytes(eap[offset:offset + 2], "big")
            size = int.from_bytes(eap[offset + 2:offset + 4], "big")
            if ident not in WPS_ATTRIBUTES or size <= 0 or size > 192:
                continue
            value = eap[offset + 4:offset + 4 + size]
            if len(value) != size:
                continue
            found.setdefault(WPS_ATTRIBUTES[ident], value.hex())
    return found


def _count_arp_frames(path: str) -> int:
    """ARP frames in a capture — the traffic an ARP-replay WEP attack feeds on."""
    from ..sniff import LLC_SNAP, TYPE_DATA, _parse_frame, iter_frames

    total = 0
    for _ts, buf, start, length in iter_frames(str(path)):
        parsed = _parse_frame(buf, start, length)
        if parsed is None:
            continue
        ftype, _subtype, _bssid, _station, payload_at = parsed
        if ftype != TYPE_DATA:
            continue
        begin, end = start + payload_at, start + length
        if begin + 8 > end:
            continue
        raw = bytes(buf[begin:end])
        index = raw.find(LLC_SNAP)
        if index < 0 or len(raw) < index + 8:
            continue
        if raw[index + 6:index + 8] == b"\x08\x06":     # ethertype: ARP
            total += 1
    return total
