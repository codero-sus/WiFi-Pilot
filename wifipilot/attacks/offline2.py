# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Ten more analysts: the attacks that need no radio because they need no permission.

Everything here reads what the engagement already has — captures, hash files,
wordlists, the session's own record of the neighbourhood — and everything here is
``silent``: no frames, no monitor interface, no authorisation gate.

* ``capture_quality`` — rank the captures by how crackable they actually are, so the
  cracker spends its budget on the best one.
* ``wordlist_audit`` — what the wordlists really contain: coverage, duplicates, encoding
  problems, and how long each one would take at the measured PBKDF2 rate.
* ``hash_audit`` — validate and rank mode-22000 hash files: which lines are usable,
  which are structurally broken, and what each one would need to crack.
* ``crack_plan`` — benchmark this machine (PBKDF2-HMAC-SHA1, rules, masks) and turn it
  into a time-versus-coverage plan for every uncracked hash.
* ``vendor_fingerprint`` — the device table: OUI vendor, WPS model, element fingerprint
  and beacon behaviour per BSSID, plus what each one is likely to be.
* ``beacon_timeline`` — what changed while we watched: channel moves, SSID changes,
  security downgrades, deauth counts, uptime.  A network that changed while you watched
  it is a finding in itself.
* ``wordlist_mine`` — build a target-specific wordlist out of the engagement's own
  data (SSIDs, vendors, models, common patterns) and report its size.
* ``pmk_check`` — for every key the session already holds, verify it against every
  capture: loot that can be opened without cracking is loot the report must not miss.
* ``loot_manifest`` — the chain-of-custody file: SHA-256 of every artefact, size and
  timestamp, written to ``loot/manifest.json`` for the report.
* ``cleartext_sniff`` — walk a capture for credentials that travelled in the clear:
  HTTP Basic and form logins, FTP USER/PASS, POP3/IMAP logins.  It is the offline twin
  of a passive sniff and it finds what encryption policies are really in force.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

from ..models import STATUS_SUCCESS, AccessPoint, Attempt
from ..netproto import cleartext_credentials, parse_ipv4, pop_imap_credentials
from ..util import human_bytes, human_duration, oui_vendor
from .base import Attack, AttackContext, AttackOutcome
from .forensics import OfflineAttack

#: the bundled suffix/word material the miner uses, all drawn from real engagements
MINED_SUFFIXES = ("", "1", "123", "2024", "2025", "2026", "!", "@123", "#1", "wifi",
                  "guest", "admin", "office", "home", "lab")


class CaptureQualityAttack(OfflineAttack):
    name = "capture_quality"
    label = "Capture quality ranking (what is worth cracking)"
    tool = "wifipilot pcap.py (handshake scoring)"
    description = ("Score every capture the session holds by what a cracker can use: "
                   "complete handshakes, EAPOL message pairs that hold the MIC, PMKIDs, "
                   "WEP IV counts, retransmissions and nonce reuse.  The ranking is the "
                   "deliverable — it decides which file the crack stage spends its time "
                   "on, and it names the captures that cannot crack at all so nobody "
                   "waits for them.")

    category = "offline"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        from ..pcap import analyze_file

        ranked: List[Dict[str, Any]] = []
        for capture in ctx.session.all_captures():
            if not capture.path or not os.path.exists(capture.path):
                continue
            analysis = analyze_file(capture.path)
            best = analysis.best_handshake()
            score = 0
            if analysis.has_pmkid:
                score += 60
            if best is not None:
                score += 40 + min(20, best.score * 5)          # score is a property
            if analysis.wep_data:
                score += min(30, analysis.wep_data // 500)
            score -= min(20, analysis.retransmits // 20)
            ranked.append({
                "path": capture.path, "name": os.path.basename(capture.path),
                "bssid": capture.bssid, "kind": capture.kind, "score": max(0, score),
                "handshakes": len(analysis.handshakes), "pmkids": len(analysis.pmkids),
                "eapol": analysis.eapol_messages, "wep_data": analysis.wep_data,
                "retransmits": analysis.retransmits,
                "crackable": bool(best is not None or analysis.has_pmkid or analysis.wep_data),
                "size": os.path.getsize(capture.path),
            })
        ranked.sort(key=lambda entry: -entry["score"])
        if not ranked:
            return AttackOutcome.skipped("no captures to rank",
                                         "the session holds no capture files yet")
        best = ranked[0]
        detail = (f"{len(ranked)} capture(s) ranked; best: {best['name']} "
                  f"(score {best['score']}, {best['handshakes']} handshake(s), "
                  f"{best['pmkids']} PMKID, {human_bytes(best['size'])})")
        return self._finish(ctx, ap, attempt, "capture quality ranked", detail,
                            {"captures": ranked,
                             "crack_first": best["path"],
                             "uncrackable": [entry["path"] for entry in ranked
                                             if not entry["crackable"]],
                             "note": ("a capture ranked 0 has no handshake, no PMKID "
                                      "and no WEP data: no cracker can help it")})


class WordlistAuditAttack(OfflineAttack):
    name = "wordlist_audit"
    label = "Wordlist audit (coverage and cost)"
    tool = "wifipilot crack.py (measuring, not guessing)"
    description = ("Read the configured wordlists and report what they actually contain: "
                   "size, duplicates, encoding problems, character-class coverage, and "
                   "how long each would take against this network at the measured "
                   "PBKDF2-HMAC-SHA1 rate.  It is the difference between 'we have a "
                   "wordlist' and 'we know what this wordlist can find'.")

    category = "offline"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        entries: List[Dict[str, Any]] = []
        for source in ctx.config.wordlists or []:
            path = source.get("path") if isinstance(source, dict) else str(source)
            if not path or not os.path.exists(path):
                continue
            entry = self._inspect(path, ctx.config.wordlists.index(source))
            if entry:
                entries.append(entry)
        if not entries:
            return AttackOutcome.skipped("no wordlists configured",
                                         "point `wordlists` at one or more files to "
                                         "audit them")
        entries.sort(key=lambda entry: -int(entry.get("unique", 0)))
        total = sum(int(entry.get("unique", 0)) for entry in entries)
        detail = (f"{len(entries)} wordlist(s), {total:,} unique candidate(s); "
                  + ", ".join(f"{entry['name']}: {entry['unique']:,} unique, "
                              f"{entry['duplicates']:,} duplicate(s), "
                              f"{entry['rate']}/s" for entry in entries[:4]))
        return self._finish(ctx, ap, attempt, "wordlists audited", detail,
                            {"wordlists": entries, "total_unique": total,
                             "note": ("the rate is this machine's measured PBKDF2 "
                                      "throughput: candidates per second, one SSID")})

    def _inspect(self, path: str, index: int) -> Dict[str, Any]:
        from ..crack import iter_wordlist

        seen: set = set()
        duplicates = 0
        long_lines = 0
        weird = 0
        classes = Counter()
        total = 0
        for word in iter_wordlist(path):
            total += 1
            if total > 2_000_000:
                break
            if word in seen:
                duplicates += 1
                continue
            seen.add(word)
            if len(word) > 63:
                long_lines += 1
            try:
                word.encode("utf-8")
            except UnicodeEncodeError:                        # pragma: no cover
                weird += 1
            for label, condition in (("lower", word.islower()), ("upper", word.isupper()),
                                     ("digits", word.isdigit()), ("mixed", word.isalnum()
                                                                  and not word.isalpha()),
                                     ("symbol", any(not char.isalnum() for char in word))):
                if condition:
                    classes[label] += 1
        rounds = 4096                     # WPA2's PBKDF2 iteration count
        return {
            "path": path, "name": os.path.basename(path), "index": index,
            "lines": total, "unique": len(seen), "duplicates": duplicates,
            "too_long": long_lines, "encoding_issues": weird,
            "classes": dict(classes), "size": os.path.getsize(path),
            "rate": self._rate(rounds),
            "milliseconds_per_candidate": round(self._benchmark(rounds), 3),
        }

    @classmethod
    def _rate(cls, rounds: int = 4096, samples: int = 400) -> str:
        """Candidates per second at the measured PBKDF2 cost, as a short string."""
        milliseconds = cls._benchmark(rounds, samples)
        if milliseconds <= 0:
            return "unknown"
        return f"{1000.0 / milliseconds:,.0f}/s"

    @staticmethod
    def _benchmark(rounds: int = 4096, samples: int = 400) -> float:
        """PBKDF2-HMAC-SHA1 cost per candidate on this machine, in milliseconds."""
        import hashlib as _hashlib

        started = time.perf_counter()
        for index in range(samples):
            _hashlib.pbkdf2_hmac("sha1", b"candidate%d" % index, b"PTKBench", rounds)
        return (time.perf_counter() - started) / samples * 1000.0


class HashAuditAttack(OfflineAttack):
    name = "hash_audit"
    label = "Hash file audit (mode 22000)"
    tool = "wifipilot hash22000.py"
    description = ("Parse every hash file the session produced and say what is in it: "
                   "PMKID lines against handshake lines, which message pair each "
                   "handshake line uses, whether the ESSID and BSSID can be matched to a "
                   "target the session knows, and which lines are structurally broken.  "
                   "A hash file is the input to a cracker, and a broken one is a silent "
                   "waste of GPU time.")

    category = "offline"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        from ..hash22000 import parse_file, parse_text

        files: List[Dict[str, Any]] = []
        for capture in ctx.session.all_captures():
            for candidate in (capture.hash_path, capture.path):
                if not candidate or not candidate.endswith((".hc22000", ".22000")):
                    continue
                if not os.path.exists(candidate) or any(entry["path"] == candidate
                                                        for entry in files):
                    continue
                with open(candidate, encoding="utf-8", errors="replace") as handle:
                    text = handle.read()
                lines, problems = parse_text(text)
                parsed = parse_file(candidate)
                files.append({
                    "path": candidate, "name": os.path.basename(candidate),
                    "lines": len(lines), "problems": problems,
                    "pmkid": sum(1 for line in parsed if line.kind == "pmkid"),
                    "handshake": sum(1 for line in parsed if line.kind != "pmkid"),
                    "pairs": sorted({line.pair_label() for line in parsed}),
                    "essids": sorted({line.essid for line in parsed if line.essid}),
                    "bssids": sorted({line.ap for line in parsed if line.ap}),
                    "verifiable": sum(1 for line in parsed if line.verifiable()),
                })
        if not files:
            return AttackOutcome.skipped("no mode-22000 hash files",
                                         "run a capture attack that produces them "
                                         "(hcxdump_capture, pmkid, handshake)")
        total = sum(entry["lines"] for entry in files)
        broken = sum(len(entry["problems"]) for entry in files)
        detail = (f"{len(files)} hash file(s), {total} line(s), {broken} problem(s); "
                  + ", ".join(f"{entry['name']}: {entry['pmkid']} PMKID / "
                              f"{entry['handshake']} handshake" for entry in files[:4]))
        severity = "medium" if broken else "info"
        return self._finish(ctx, ap, attempt, "hash files audited", detail,
                            {"files": files, "lines": total, "problems": broken,
                             "note": ("a handshake line needs a complete message pair "
                                      "to be verifiable: the report names the pair each "
                                      "line carries")},
                            severity=severity)


class CrackPlanAttack(OfflineAttack):
    name = "crack_plan"
    label = "Crack plan (benchmarked time estimates)"
    tool = "wifipilot crack.py + masks.py"
    description = ("Measure this machine's PBKDF2-HMAC-SHA1 rate, count the candidates in "
                   "each wordlist and mask space, and produce a plan ordered by "
                   "coverage per second: wordlists first, then rules, then masks.  The "
                   "numbers are measurements, not hopes — a plan that says 'eight hours "
                   "for these 3,000 candidates' is actionable, and one that says 'try "
                   "everything' is not.")

    category = "offline"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        from ..crack import iter_wordlist

        rate = 1.0 / max(1e-6, self._benchmark())
        stages: List[Dict[str, Any]] = []
        for source in ctx.config.wordlists or []:
            path = source.get("path") if isinstance(source, dict) else str(source)
            if not path or not os.path.exists(path):
                continue
            count = 0
            for _word in iter_wordlist(path):
                count += 1
                if count >= 500_000:
                    break
            stages.append({"stage": "wordlist", "source": os.path.basename(path),
                           "candidates": count,
                           "seconds": round(count / rate, 1),
                           "coverage": "the words as they are"})
        stages.append({"stage": "rules", "source": "best wordlist + wifipilot rules",
                       "candidates": int(sum(stage["candidates"] for stage in stages) * 40),
                       "seconds": round(sum(stage["candidates"] for stage in stages) * 40
                                        / rate, 1),
                       "coverage": "leet, suffixes, capitalisation"})
        for mask, size in self._masks(ap):
            stages.append({"stage": "mask", "source": mask, "candidates": size,
                           "seconds": round(size / rate, 1),
                           "coverage": f"{len(mask)}-character pattern"})
        stages.sort(key=lambda stage: stage["seconds"])
        fastest = stages[0] if stages else None
        detail = (f"measured {rate:,.0f} candidates/s on this machine; "
                  + (f"cheapest stage: {fastest['source']} at "
                     f"{human_duration(fastest['seconds'])} for "
                     f"{fastest['candidates']:,} candidates" if fastest else "no stages"))
        return self._finish(ctx, ap, attempt, "crack plan produced", detail,
                            {"plan": stages, "rate_per_second": round(rate, 1),
                             "crack_stages": [stage["source"] for stage in stages[:5]],
                             "note": ("estimates are for one SSID on this CPU: a GPU "
                                      "with hashcat does orders of magnitude better, "
                                      "which is why the plan names the stage order and "
                                      "not a total")})

    @staticmethod
    def _masks(ap: AccessPoint) -> List[Tuple[str, int]]:
        """A couple of honest masks: the ones worth trying before giving up."""
        patterns = [("?d?d?d?d?d?d?d?d", 10 ** 8), ("?u?l?l?l?l?l?d?d", 26 * 26 ** 4 * 10 ** 2)]
        out: List[Tuple[str, int]] = []
        for pattern, size in patterns:
            out.append((pattern, size))
        name = (ap.essid or "").split("-")[0][:6].lower()
        if name.isalpha():
            out.append((f"{name}?d?d?d?d", 10 ** 4))
        return out

    @staticmethod
    def _benchmark(samples: int = 150, rounds: int = 4096) -> float:
        import hashlib as _hashlib

        started = time.perf_counter()
        for index in range(samples):
            _hashlib.pbkdf2_hmac("sha1", b"plan%d" % index, b"CrackPlan", rounds)
        return (time.perf_counter() - started) / samples


class VendorFingerprintAttack(OfflineAttack):
    name = "vendor_fingerprint"
    label = "Device fingerprinting (vendors, models, drivers)"
    tool = "wifipilot ies.py + util.oui_vendor"
    description = ("Build the hardware table for the engagement: OUI vendor, WPS model "
                   "and manufacturer, HT/VHT/HE capability, beacon interval and element "
                   "fingerprint for every BSSID, and for stations the OUI vendor plus "
                   "whether the address is randomised.  It is what decides whether an "
                   "attack is even applicable — a vendor with a known WPS PIN algorithm, "
                   "a chipset with a broken PMF implementation, an AP that is really a "
                   "phone hotspot.")

    category = "offline"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        devices: List[Dict[str, Any]] = []
        for target in ctx.session.sorted_aps():
            devices.append({
                "bssid": target.bssid, "essid": target.essid,
                "vendor": target.vendor or oui_vendor(target.bssid),
                "wps_model": target.wps_model, "wps_manufacturer": target.wps_manufacturer,
                "cipher": target.cipher, "auth": target.auth, "band": target.band,
                "channel": target.channel, "pmf": target.pmf, "sae": target.sae,
                "wps": target.wps, "hidden": target.hidden,
                "encryption": target.encryption,
                "guess": self._guess(target),
                "clients": len(target.clients),
            })
        path = self.capture_path(ctx, ap)
        beacon_facts: List[Dict[str, Any]] = []
        if path:
            from ..ies import capture_beacons, vendor_breakdown

            decoded = capture_beacons(path)
            beacon_facts = vendor_breakdown(decoded.get("networks", []))
        vendors = Counter(device["vendor"] or "unknown" for device in devices)
        detail = (f"{len(devices)} BSSID(s) fingerprinted; top vendors: "
                  + ", ".join(f"{vendor} ({count})" for vendor, count
                              in vendors.most_common(5)))
        return self._finish(ctx, ap, attempt, "devices fingerprinted", detail,
                            {"devices": devices, "vendors": dict(vendors),
                             "beacon_vendors": beacon_facts,
                             "note": ("the model and the vendor element are what make "
                                      "an attack 'applicable': WPS PIN algorithms, PMF "
                                      "implementation bugs and default PINs are all "
                                      "per-vendor facts")})

    @staticmethod
    def _guess(ap: AccessPoint) -> str:
        """A plain-language guess at what the hardware is."""
        if ap.sae:
            kind = "WPA3-capable AP"
        elif ap.wps and ap.wps_model:
            kind = f"WPS AP ({ap.wps_model})"
        elif ap.encryption in ("OPEN", "OWE"):
            kind = "open/hotspot"
        elif ap.encryption == "WEP":
            kind = "legacy WEP device"
        elif ap.hidden:
            kind = "hidden AP"
        else:
            kind = "WPA2 AP"
        if ap.wps_manufacturer:
            kind += f", made by {ap.wps_manufacturer}"
        vendor = ap.vendor or oui_vendor(ap.bssid)
        if vendor:
            kind += f" [{vendor}]"
        return kind


class BeaconTimelineAttack(OfflineAttack):
    name = "beacon_timeline"
    label = "Beacon timeline (what changed while we watched)"
    tool = "wifipilot models.AccessPoint.history"
    description = ("Turn the session's own record into a timeline per network: first and "
                   "last seen, channel and SSID changes, security changes, and the "
                   "deauth counts our own attacks produced.  A network that changed its "
                   "security while an engagement was running is either a misconfiguration "
                   "or an administrator reacting, and both are findings.")

    category = "offline"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        timeline: List[Dict[str, Any]] = []
        for target in ctx.session.sorted_aps():
            history = list(target.history or [])
            channels = sorted({entry.get("channel") for entry in history
                               if entry.get("channel")})
            essids = sorted({entry.get("essid") for entry in history if entry.get("essid")})
            security = sorted({entry.get("encryption") for entry in history
                               if entry.get("encryption")})
            timeline.append({
                "bssid": target.bssid, "essid": target.essid,
                "first_seen": target.first_seen, "last_seen": target.last_seen,
                "minutes": round((target.last_seen - target.first_seen) / 60.0, 1),
                "beacons": target.beacon_count, "data_frames": target.data_count,
                "channels": channels, "essids": essids, "security": security,
                "deauths_from_us": target.deauths_sent,
                "captures": len(target.captures), "attempts": len(target.attempts),
                "changed_channel": len(channels) > 1,
                "changed_security": len(security) > 1,
                "changed_ssid": len(essids) > 1,
            })
        changed = [entry for entry in timeline
                   if entry["changed_channel"] or entry["changed_security"]
                   or entry["changed_ssid"]]
        if not timeline:
            return AttackOutcome.skipped("no networks have been seen yet")
        detail = (f"{len(timeline)} network(s) in the timeline; "
                  + (f"{len(changed)} changed while under observation "
                     f"({', '.join(entry['essid'] or entry['bssid'] for entry in changed[:4])})"
                     if changed else "none changed channel, SSID or security"))
        severity = "medium" if changed else "info"
        return self._finish(ctx, ap, attempt, "beacon timeline built", detail,
                            {"timeline": timeline, "changed": changed,
                             "note": ("a security downgrade seen live is strong "
                                      "evidence: it is the signature of a fallback "
                                      "configuration or of someone else attacking too")},
                            severity=severity)


class WordlistMineAttack(OfflineAttack):
    name = "wordlist_mine"
    label = "Target wordlist mining (off the engagement's own data)"
    tool = "wifipilot (engagement-derived candidates)"
    description = ("Generate a wordlist from the engagement itself: SSID words and their "
                   "parts, vendor names, WPS models, location words found in names, and "
                   "the suffixes people actually append (years, !, 123).  The output is "
                   "a real file under the session's wordlists directory, ranked so the "
                   "cheapest candidates come first, and every candidate traces back to "
                   "the thing that suggested it.")

    category = "offline"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        candidates: Dict[str, str] = {}

        def add(candidate: str, source: str) -> None:
            candidate = candidate.strip()
            if 8 <= len(candidate) <= 63 and candidate not in candidates:
                candidates[candidate] = source

        for target in ctx.session.sorted_aps():
            words = [part for part in (target.essid or "").replace("_", "-").split("-")
                     if len(part) >= 3]
            for word in words:
                base_forms = {word, word.lower(), word.capitalize(), word.upper()}
                for base in base_forms:
                    add(base, f"ssid:{target.essid}")
                    for suffix in MINED_SUFFIXES:
                        add(base + suffix, f"ssid:{target.essid}")
                if any(char.isdigit() for char in word):
                    add(word, f"ssid:{target.essid} digits")
            for attribute in (target.vendor, target.wps_model, target.wps_manufacturer):
                if attribute and len(attribute) >= 4:
                    token = attribute.split()[0]
                    add(token, "vendor")
                    add(token + "123", "vendor")
        path = os.path.join(ctx.session.state_dir, "wordlists",
                            f"mined-{ap.bssid.replace(':', '')}.txt")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            for candidate in sorted(candidates, key=len):
                handle.write(f"{candidate}\n")
        if not candidates:
            return AttackOutcome.skipped("nothing to mine",
                                         "the session has no SSIDs or vendor data yet")
        detail = (f"{len(candidates)} candidate(s) mined from {len(ctx.session.aps)} "
                  f"network(s) into {os.path.basename(path)}: "
                  + ", ".join(sorted(candidates, key=len)[:6]))
        ap.remember(self.name, detail, wordlist=path)
        return self._finish(ctx, ap, attempt, "target wordlist mined", detail,
                            {"wordlist": path, "candidates": len(candidates),
                             "sources": dict(Counter(candidates.values()).most_common(8)),
                             "note": ("the list is derived from the engagement's own "
                                      "identifiers: it is small on purpose, and it is "
                                      "only useful against this neighbourhood")})


class PmkCheckAttack(OfflineAttack):
    name = "pmk_check"
    label = "PMK check (loot that needs no cracking)"
    tool = "wifipilot crypto.py (PTK + MIC verification)"
    description = ("For every key the session already holds — a PSK from an earlier "
                   "crack, a WPS PIN result, a PMK in the cache — verify it against "
                   "every capture for that network by recomputing the MIC.  Loot that "
                   "can be opened without spending a second of cracking time is the "
                   "first thing a report should say, and it is easy to miss when the "
                   "captures arrived before the key did.")

    category = "offline"
    # the answer is a working key: that is loot, not an observation
    impact = "loot"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        from ..pcap import analyze_file

        verified: List[Dict[str, Any]] = []
        checked = 0
        for target in ctx.session.sorted_aps():
            if not (target.cracked and target.password):
                continue
            for capture in target.captures:
                if not capture.path or not os.path.exists(capture.path):
                    continue
                analysis = analyze_file(capture.path)
                best = analysis.best_handshake()
                checked += 1
                if best is None or not best.can_verify_mic:
                    continue
                from ..crypto import ptk, mic_candidates, pmk as derive_pmk
                from ..util import mac_bytes

                pmk_bytes = derive_pmk(target.password, target.essid or "")
                keys = ptk(pmk_bytes, mac_bytes(target.bssid),
                           mac_bytes(best.station or "ff:ff:ff:ff:ff:ff"),
                           bytes.fromhex(best.anonce or "00" * 32),
                           bytes.fromhex(best.snonce or "00" * 32))
                message = best.mic_message
                if message is None or not message.raw:
                    continue
                from ..crypto import _eapol_frame_from_bytes  # noqa: PLC2701

                frame = _eapol_frame_from_bytes(message.raw)
                ok = any(candidate == message.mic for candidate in
                         mic_candidates(keys, frame, message.key_version))
                verified.append({"bssid": target.bssid, "capture": capture.path,
                                 "station": best.station, "verified": bool(ok),
                                 "password_source": "session"})
        if checked == 0:
            return AttackOutcome.skipped(
                "no key/capture pair to check",
                "the session holds no cracked password or no capture for it: this "
                "attack verifies loot, it does not produce it")
        matched = [entry for entry in verified if entry["verified"]]
        detail = (f"{checked} key/capture pair(s) checked, {len(matched)} verified "
                  f"without cracking: "
                  + ", ".join(entry["bssid"] for entry in matched[:5]))
        return self._finish(ctx, ap, attempt, "loot verified", detail,
                            {"verified": verified, "matched": matched,
                             "note": ("these captures can be reported as loot "
                                      "immediately: the key in the session recomputes "
                                      "their MIC")},
                            severity="high" if matched else "low")


class LootManifestAttack(OfflineAttack):
    name = "loot_manifest"
    label = "Loot manifest (chain of custody)"
    tool = "wifipilot (SHA-256 manifest)"
    description = ("Write the chain-of-custody file an engagement needs: every artefact "
                   "the session produced, with its SHA-256, size and timestamp, plus the "
                   "network it belongs to and what it is worth.  A report that cannot "
                   "prove its captures were not altered is a report a client cannot "
                   "act on, and producing the manifest is not something to remember at "
                   "the end of an engagement.")

    category = "offline"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        entries: List[Dict[str, Any]] = []
        total_bytes = 0
        for capture in ctx.session.all_captures():
            if not capture.path or not os.path.exists(capture.path):
                continue
            digest = hashlib.sha256()
            with open(capture.path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1 << 20), b""):
                    digest.update(chunk)
            size = os.path.getsize(capture.path)
            total_bytes += size
            entries.append({
                "path": capture.path, "name": os.path.basename(capture.path),
                "bssid": capture.bssid, "essid": capture.essid, "kind": capture.kind,
                "sha256": digest.hexdigest(), "size": size,
                "created": capture.created, "password": bool(capture.password),
                "tool": capture.tool,
            })
        if not entries:
            return AttackOutcome.skipped("no artefacts to hash")
        path = os.path.join(ctx.session.state_dir, "loot", "manifest.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        payload = {"generated": time.time(), "bssid": ap.bssid,
                   "artifacts": entries, "total_bytes": total_bytes}
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        with open(path + ".sha256", "w", encoding="utf-8") as handle:
            handle.write(f"{hashlib.sha256(json.dumps(payload, indent=2).encode()).hexdigest()}"
                         f"  {os.path.basename(path)}\n")
        from ..models import Capture

        ctx.session.add_artifact(Capture(
            kind="manifest", bssid=ap.bssid, essid=ap.essid, path=path, valid=False,
            tool="wifipilot", size=os.path.getsize(path),
            found_in=self.name, extra={"artifacts": len(entries),
                                       "sha256_file": path + ".sha256"}))
        detail = (f"{len(entries)} artefact(s), {human_bytes(total_bytes)}, hashed into "
                  f"{os.path.relpath(path, ctx.session.state_dir)}")
        return self._finish(ctx, ap, attempt, "loot manifest written", detail,
                            {"manifest": path, "artifacts": entries,
                             "total_bytes": total_bytes,
                             "note": ("give the manifest with the captures: it is what "
                                      "makes them evidence rather than files")},
                            severity="info")


class CleartextSniffAttack(OfflineAttack):
    name = "cleartext_sniff"
    label = "Cleartext credential sniff (HTTP, FTP, mail)"
    tool = "wifipilot netproto.py + pcap.py"
    description = ("Walk a capture for credentials that travelled in the clear: HTTP "
                   "Basic headers and form logins, FTP USER/PASS, POP3 USER/PASS and "
                   "IMAP LOGIN.  On a wireless network this is the finding that matters "
                   "most to a client — 'your guests' passwords are readable by anyone "
                   "with a radio' — and it needs one capture and no transmission at all.")
    # credentials are the deliverable of this one, so it is loot rather than a note
    impact = "loot"
    category = "offline"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = self._attempt(ctx, ap)
        path = self.capture_path(ctx, ap)
        if not path:
            return AttackOutcome.skipped("no capture to read",
                                         "the sniff reads a stored capture: run "
                                         "`passive` or `pcap_replay` first")
        hits = self._scan(path)
        if not hits:
            severity, title = "info", "no cleartext credentials in the capture"
            detail = (f"{os.path.basename(path)} carries no HTTP/FTP/POP3/IMAP "
                      f"credential in the clear")
        else:
            severity = "high"
            users = sorted({hit.get("user") or hit.get("value", "") for hit in hits})
            title = f"{len(hits)} cleartext credential(s) found"
            detail = (f"{len(hits)} cleartext credential(s) in "
                      f"{os.path.basename(path)}: {', '.join(users[:8])} "
                      f"(protocols: {', '.join(sorted({hit['kind'] for hit in hits}))})")
        return self._finish(ctx, ap, attempt, title, detail,
                            {"capture": path, "credentials": hits,
                             "note": ("these credentials were readable from the air: "
                                      "the mitigation is encrypted protocols (HTTPS, "
                                      "FTPS, IMAPS), not a better password")},
                            severity=severity)

    @staticmethod
    def _scan(path: str) -> List[Dict[str, Any]]:
        from ..pcap import TYPE_DATA, _parse_frame, iter_frames

        hits: List[Dict[str, Any]] = []
        for _ts, buf, start, length in iter_frames(str(path), max_packets=400_000):
            parsed = _parse_frame(buf, start, length)
            if parsed is None or parsed[0] != TYPE_DATA:
                continue
            raw = bytes(buf[start + parsed[4]:start + length])
            if len(raw) < 24:
                continue
            # skip LLC/SNAP, then parse the IP packet inside
            body = raw
            for marker in (b"\xaa\xaa\x03\x00\x00\x00\x08\x00", b"\xaa\xaa\x03\x00\x00\x00\x86\xdd"):
                index = body.find(marker)
                if index >= 0:
                    body = body[index + 8:]
                    break
            if not body or body[0] >> 4 != 4:
                continue
            packet = parse_ipv4(body)
            payload = packet.get("l4_payload") or b""
            if not payload:
                continue
            for credential in (cleartext_credentials(payload)
                               + pop_imap_credentials(payload)):
                credential["station"] = parsed[3]
                credential["bssid"] = parsed[2]
                hits.append(credential)
        # the same credential often appears in several frames: report each once
        unique: Dict[str, Dict[str, Any]] = {}
        for hit in hits:
            key = f"{hit.get('kind')}:{hit.get('user', '')}:{hit.get('secret', hit.get('value', ''))}"
            unique.setdefault(key, hit)
        return list(unique.values())


__all__ = ["BeaconTimelineAttack", "CaptureQualityAttack", "CleartextSniffAttack",
           "CrackPlanAttack", "HashAuditAttack", "LootManifestAttack",
           "PmkCheckAttack", "VendorFingerprintAttack", "WordlistAuditAttack",
           "WordlistMineAttack"]
