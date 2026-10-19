# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Offline analysis: fifty more things a capture can be asked.

Every attack in this module reads a capture the session already holds — or, in demo
mode, a synthetic one built with the real frame builders — and answers one question
about it with a real parser.  Nothing is transmitted, so there is no radio, no
authorisation and no noise; the deliverable is the answer.

The module is built on three ideas that keep fifty analyses honest and short:

``_frames()``
    one generator over ``(timestamp, 802.11 frame bytes)``, from a real capture file or
    from a synthesized scene.  Every analysis reads the same stream.
``_EapolFacts``
    what :mod:`wifipilot.pcap` already knows about the capture (handshakes, EAPOL
    messages, retransmits) — reused rather than re-derived, because two parsers that
    disagree about a handshake are worse than one.
``_row()``
    the factory that turns a table row into a class.  The table is the registry of what
    this module contributes, which is what makes it possible to see all fifty at once.

Each analysis raises a finding when it has something to say and reports the numbers
when it does not, so a clean capture still produces a quantified result instead of a
shrug.  The ones that do more than inform — MIC validation, nonce reuse, downgrade
audits — pass a severity, and the finding goes into the session's report.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections import Counter, defaultdict
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from .. import ies as ie_module
from ..models import AccessPoint, Attempt
from ..pcap import (analyze_file, iter_frames)
from .base import AttackContext, AttackOutcome
from .forensics import OfflineAttack
from .frames import parse_80211

# --------------------------------------------------------------------------- #
# reading a capture
# --------------------------------------------------------------------------- #

MGMT, CTRL, DATA = 0, 1, 2


def _frames(path: str, limit: int = 60_000) -> Iterable[Tuple[float, bytes]]:
    """``(timestamp, frame)`` for every frame in a capture.  Never raises.

    ``iter_frames`` has already removed the radiotap header, so what comes out is a
    bare 802.11 frame: no second strip, which could only misfire on a frame whose
    first bytes happen to look like one.
    """
    try:
        for stamp, buf, start, length in iter_frames(str(path), max_packets=limit):
            yield float(stamp), bytes(buf[start:start + length])
    except (OSError, ValueError):                          # pragma: no cover - bad file
        return


def _parsed(path: str, limit: int = 60_000) -> Iterable[Tuple[float, Dict[str, Any]]]:
    """``(timestamp, parsed frame)`` — the shape almost every analysis wants.

    The element area is attached as ``body`` for the frames that have one, so a
    caller that needs an information element does not have to know the fixed-field
    length of that particular subtype.
    """
    for stamp, frame in _frames(path, limit):
        info = parse_80211(frame)
        if not info:
            continue
        if info.get("type") == MGMT:
            # where the element list starts depends on the subtype: 36 for a beacon or
            # probe response, 28 for an association request, 24 for a probe request.
            # The parser already knows (``body_offset``), and guessing 36 for all of
            # them is how an association request comes to look like a client with no
            # HT capabilities at all.
            offset = int(info.get("body_offset") or 36)
            if len(frame) > offset:
                info["body"] = frame[offset:]
        if isinstance(info.get("essid"), bytes):
            # the parser hands back whatever the element held, including NUL padding:
            # everything that reads a name here wants text, so it is normalised once
            info["essid"] = _text(info["essid"])
        yield stamp, info


def _security_of(decoded: Dict[str, Any], info: Dict[str, Any]) -> str:
    """The security a beacon advertises, in the vocabulary the rest of the tool uses."""
    rsn = decoded.get("rsn") or {}
    if rsn:
        akms = {str(item).upper() for item in (rsn.get("akm") or [])}
        if "OWE" in akms:
            return "OWE"
        if any("1X" in akm or "EAP" in akm or "802.1X" in akm for akm in akms):
            return "ENTERPRISE"
        if "SAE" in akms and any("PSK" in akm for akm in akms):
            return "WPA2/WPA3"
        if any("SAE" in akm for akm in akms):
            return "WPA3"
        return "WPA2"
    if decoded.get("wpa1"):
        return "WPA"
    capability = int(info.get("capability", 0) or 0)
    if capability & 0x0010:                       # the privacy bit without an RSN element
        return "WEP"
    return "OPEN"


def _text(value: Any) -> str:
    """A name out of whatever the parser produced (bytes or str)."""
    if isinstance(value, bytes):
        return value.decode("latin-1", "replace").strip("\x00 ")
    return str(value or "").strip("\x00 ")


def frame_body(info: Dict[str, Any], fixed: int) -> bytes:
    """The element area of a management frame, from the parsed frame if it kept it."""
    return info.get("body") or b""


def _bssid_map(path: str) -> Dict[str, Dict[str, Any]]:
    """Per-BSSID facts from a capture: beacons, IEs, channels, clients, signal."""
    out: Dict[str, Dict[str, Any]] = {}
    for _stamp, info in _parsed(path):
        # `bssid` is addr3 for management frames and the DS-bit-selected address for
        # data, and in both cases it is the network the frame belongs to; a broadcast
        # or multicast address (a wildcard probe request) belongs to nobody
        bssid = _text(info.get("bssid"))
        if not bssid or bssid == "ff:ff:ff:ff:ff:ff":
            continue
        try:
            if int(bssid.split(":")[0], 16) & 0x01:      # multicast: not an AP either
                continue
        except (ValueError, IndexError):
            continue
        entry = out.setdefault(bssid, {
            "bssid": bssid, "essid": "", "channel": 0, "beacons": 0, "probes": 0,
            "clients": set(), "intervals": [], "signals": [], "ies": {},
            "encryption": "", "hidden": False, "subtypes": Counter()})
        entry["subtypes"][info.get("kind", "")] += 1
        if info.get("type") == MGMT and info.get("kind") in ("beacon",
                                                             "probe response"):
            entry["beacons"] += 1
            body = frame_body(info, 36)
            name = _text(info.get("essid"))
            if not entry["essid"] and name:
                entry["essid"] = name
            elif not name and not entry["essid"]:
                entry["hidden"] = True
            if info.get("channel"):
                entry["channel"] = info["channel"]
            if info.get("interval"):
                entry["intervals"].append(info["interval"])
            if info.get("signal"):
                entry["signals"].append(info["signal"])
            if body:
                decoded = ie_module.decode_ies(ie_module.parse_ies(body))
                entry["ies"] = {key: decoded.get(key) for key in
                                ("ssid", "channel", "rsn", "wpa1", "wps", "rates")}
                entry["encryption"] = _security_of(decoded, info)
        station = _text(info.get("station"))
        if station and station != bssid and info.get("kind") in (
                "data", "QoS data", "null data", "authentication",
                "association request", "reassociation request",
                "applied data"):
            entry["clients"].add(station)
    return out


# --------------------------------------------------------------------------- #
# EAPOL facts, from the module that already parses them
# --------------------------------------------------------------------------- #


class _EapolFacts:
    """What the session's capture holds of the four-way handshake."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.analysis = analyze_file(path, max_packets=200_000)
        self.messages: List[Any] = []
        for handshake in [*self.analysis.handshakes, *self.analysis.pmkids]:
            self.messages.extend(handshake.messages.values())

    @property
    def handshakes(self) -> List[Any]:
        return self.analysis.handshakes

    def key_versions(self) -> Counter:
        counts: Counter = Counter()
        for message in self.messages:
            key_info = int(getattr(message, "key_info", 0) or 0)
            counts[(key_info >> 3) & 0x07] += 1
        return counts

    def nonces(self) -> Counter:
        return Counter(str(getattr(message, "nonce", "")) for message in self.messages
                       if getattr(message, "nonce", ""))

    def retransmits(self) -> int:
        return int(getattr(self.analysis, "retransmits", 0) or 0)


# --------------------------------------------------------------------------- #
# the base every analysis shares
# --------------------------------------------------------------------------- #


class _Audit(OfflineAttack):
    """An offline analysis: pick a capture, read it, report what it says."""

    category = "offline"
    noise = "silent"
    impact = "info"
    scene = False                      # demo captures: handshake, or a full scene?

    def applies(self, ap: AccessPoint) -> bool:
        return True

    def available(self, ctx: AttackContext) -> bool:
        return True

    def unavailable_reason(self, ctx: AttackContext) -> str:
        return ""

    # -- material ---------------------------------------------------------- #
    def capture(self, ctx: AttackContext, ap: AccessPoint) -> str:
        """The capture to read; in demo mode a synthetic one with real frames.

        A survey wants a mixed capture (beacons, probes, associations, data), a
        handshake audit wants the handshake: an attack that reads the wrong one
        reports a confident zero, which is worse than reporting nothing.
        """
        if ctx.demo and self.scene:
            return self.demo_scene(ctx, ap)
        path = self.capture_path(ctx, ap)
        if path and os.path.exists(path):
            return path
        if not ctx.demo:
            return ""
        return self.demo_scene(ctx, ap) if self.scene else self.demo_capture(ctx, ap)

    def demo_scene(self, ctx: AttackContext, ap: AccessPoint) -> str:
        """A mixed capture: beacons, probes, associations and background data."""
        from ..synth import build_scene

        path = os.path.join(ctx.session.state_dir, "captures",
                            f"scene-{ap.bssid.replace(':', '')}-6-260.pcap")
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            # six networks: the hidden one, a WPA2/3 transition network, a pure WPA3
            # network, a TKIP one, the forged clone and the rest
            build_scene(path, aps=6, clients=6, rounds=260,
                        seed=int(ap.bssid.replace(":", ""), 16) % 997)
        return path

    # -- helpers ----------------------------------------------------------- #
    def bssid_map(self, ctx: AttackContext, ap: AccessPoint) -> Dict[str, Dict[str, Any]]:
        path = self.capture(ctx, ap)
        return _bssid_map(path) if path else {}

    def _need_capture(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                      what: str = "capture") -> Optional[AttackOutcome]:
        ctx.session.end_attempt(attempt, "skipped", f"no {what}")
        return AttackOutcome.skipped(
            f"no {what}", f"{ap.display_name}: the session holds no capture to read")

    def _report(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                result: str, detail: str, extra: Dict[str, Any],
                severity: str = "") -> AttackOutcome:
        return self._finish(ctx, ap, attempt, result, detail, extra, severity=severity)


def _row(name: str, label: str, description: str, detection: str,
         run: Callable[[_Audit, AttackContext, AccessPoint], AttackOutcome], *,
         cls_name: str = "", impact: str = "info", noise: str = "silent",
         category: str = "offline", scene: bool = False,
         tool: str = "wifipilot (own 802.11 parser)") -> type:
    """Turn one table row into an attack class and register it in this module."""
    cls = type(cls_name or "".join(part.capitalize() for part in name.split("_")) + "Attack",
               (_Audit,), {
                   "name": name, "label": label, "tool": tool,
                   "description": description, "detection": detection,
                   "impact": impact, "noise": noise, "category": category,
                   "scene": scene, "run": run,
               })
    cls.__doc__ = description
    cls.__module__ = __name__
    globals()[cls.__name__] = cls
    return cls


REGISTRY: List[Tuple[str, Dict[str, str], type]] = []


def _add(name: str, label: str, description: str, detection: str,
         run: Callable[..., AttackOutcome], **kwargs: Any) -> type:
    cls = _row(name, label, description, detection, run, **kwargs)
    REGISTRY.append((name, {"category": kwargs.get("category", "offline"),
                            "noise": kwargs.get("noise", "silent"),
                            "impact": kwargs.get("impact", "info"),
                            "detection": detection}, cls))
    return cls


# --------------------------------------------------------------------------- #
# 1-10: protocol-level audits of the frames themselves
# --------------------------------------------------------------------------- #


def _mic_check(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """Verify the handshake's MIC against candidate keys — the real crypto, not a flag."""
    from ..crypto import verify_handshake
    from ..pcap import eapol_frame

    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    facts = _EapolFacts(path)
    essids = facts.analysis.essids
    handshakes = [h for h in facts.handshakes if h.can_verify_mic]
    if not handshakes:
        return self._report(ctx, ap, attempt, "no complete handshake to verify",
                            f"{os.path.basename(path)}: the capture has no four-way "
                            f"handshake with message 2, so there is no MIC to check",
                            {"capture": path, "messages": len(facts.messages)})
    words = _candidate_keys(ctx, ap)
    verified: List[Dict[str, Any]] = []
    checked = 0
    started = time.time()
    for handshake in handshakes[:4]:
        frames = {number: eapol_frame(message) for number, message
                  in handshake.messages.items()}
        if 2 not in frames:
            continue
        ssid = essids.get(handshake.bssid, "") or ap.essid or ""
        for word in words:
            checked += 1
            try:
                if verify_handshake(frames, ssid, handshake.bssid, handshake.station,
                                    bytes.fromhex(handshake.anonce),
                                    bytes.fromhex(handshake.snonce), word):
                    verified.append({"bssid": handshake.bssid, "essid": ssid,
                                     "passphrase": word})
                    break
            except (ValueError, KeyError):               # malformed frame: next one
                continue
    taken = max(time.time() - started, 1e-6)
    if verified:
        detail = ("; ".join(f"{item['bssid']} -> {item['passphrase']!r}"
                            for item in verified)
                  + f" ({checked} key/candidate pair(s) in {taken:.2f}s)")
        return self._report(ctx, ap, attempt,
                            f"MIC verified: {len(verified)} passphrase(s) known",
                            detail, {"verified": verified, "checked": checked,
                                     "capture": path}, severity="high")
    return self._report(ctx, ap, attempt, "MIC could not be verified",
                        f"{len(handshakes)} handshake(s), {checked} candidate(s) tried "
                        f"in {taken:.2f}s: the key is not in the wordlist, which is a "
                        f"wordlist result, not a flaw in the handshake",
                        {"handshakes": len(handshakes), "checked": checked,
                         "capture": path})


def _candidate_keys(ctx: AttackContext, ap: AccessPoint) -> List[str]:
    words: List[str] = []
    demo = getattr(ap, "demo_password", "") or ""
    if ctx.demo and demo:
        words.append(demo)
    for path in getattr(ctx.config, "wordlists", []) or []:
        if not path or not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                word = line.rstrip("\r\n")
                if word:
                    words.append(word)
                if len(words) >= 20_000:
                    break
        if words:
            break
    for fallback in (demo, "demo-passphrase-1", "ScenePassword1", "password",
                     "12345678"):
        if fallback:
            words.append(fallback)
    seen: List[str] = []
    for word in words:
        if word not in seen:
            seen.append(word)
    return seen


def _nonce_reuse(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """The same nonce twice: the KRACK precondition, searched for in the capture."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    facts = _EapolFacts(path)
    counts = facts.nonces()
    repeated = {nonce: count for nonce, count in counts.items() if count > 1 and nonce}
    if not counts:
        return self._report(ctx, ap, attempt, "no EAPOL nonces in the capture",
                            f"{os.path.basename(path)}: no key messages, so nothing to "
                            f"compare", {"capture": path})
    reused = [nonce for nonce in repeated
              if nonce.strip("0") and nonce != "0" * len(nonce)]
    detail = (f"{len(counts)} nonce(s) in {len(facts.messages)} message(s); "
              + (f"{len(reused)} value(s) appear more than once, which is the KRACK "
                 f"precondition (the same ANonce under a replayed message 3)"
                 if reused else "every nonce is used once, so the reinstall attack has "
                                "no handle in this capture"))
    return self._report(ctx, ap, attempt,
                        f"nonce reuse: {len(reused)} repeated value(s)", detail,
                        {"nonces": dict(list(counts.items())[:20]), "reused": reused[:10],
                         "capture": path},
                        severity="high" if reused else "info")


def _key_version_audit(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """Which MIC algorithm each handshake used (KDV 1/2/3)."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    facts = _EapolFacts(path)
    counts = facts.key_versions()
    names = {1: "HMAC-MD5 (WPA, with TKIP)", 2: "HMAC-SHA1-128 (WPA2)",
             3: "AES-128-CMAC (802.11w/PMF)"}
    if not counts:
        return self._report(ctx, ap, attempt, "no EAPOL key messages in the capture",
                            f"{os.path.basename(path)}: nothing to classify",
                            {"capture": path})
    legacy = {version: count for version, count in counts.items() if version in (1, 0)}
    detail = ", ".join(f"KDV {version} ({names.get(version, 'unknown')}): {count}"
                       for version, count in sorted(counts.items()))
    return self._report(ctx, ap, attempt,
                        f"key descriptor versions: {len(counts)} distinct", detail,
                        {"key_versions": {str(k): v for k, v in counts.items()},
                         "capture": path},
                        severity="medium" if legacy else "info")


def _tkip_countermeasures_audit(self: _Audit, ctx: AttackContext,
                                ap: AccessPoint) -> AttackOutcome:
    """Deauthentication reason 15/16 in the capture is TKIP countermeasures firing."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    reasons: Counter = Counter()
    for _stamp, info in _parsed(path):
        if info.get("kind") in ("deauthentication", "disassociation"):
            code = int(info.get("reason", 0) or 0)
            reasons[code] += 1
    countermeasures = {code: count for code, count in reasons.items() if code in (15, 16)}
    detail = (f"{sum(reasons.values())} deauth/disassoc frame(s), reasons: "
              + (", ".join(f"{code} x{count}" for code, count in reasons.most_common(6))
                 or "none"))
    if countermeasures:
        detail += ("; reason 15/16 means Michael countermeasures: the AP shut the "
                   "BSS down for a minute after a forged MIC")
    return self._report(ctx, ap, attempt,
                        "TKIP countermeasures: " + (
                            "observed" if countermeasures else "not observed"), detail,
                        {"reasons": {str(k): v for k, v in reasons.items()},
                         "countermeasures": sum(countermeasures.values()),
                         "capture": path},
                        severity="medium" if countermeasures else "info")


def _group_cipher_audit(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """The group cipher an AP advertises: TKIP in 2020s is a finding."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    networks = (ie_module.capture_beacons(path, max_packets=60_000) or {}).get(
        "networks") or []
    rows = []
    weak = []
    for entry in networks:
        facts = entry.get("facts") or {}
        rsn = facts.get("rsn") or {}
        cipher = str(rsn.get("group", "") or "")
        rows.append({"bssid": entry.get("bssid", ""), "essid": entry.get("essid", ""),
                     "group": cipher})
        if cipher and cipher.upper() in ("TKIP", "WEP-40", "WEP-104"):
            weak.append(f"{entry.get('bssid')} {cipher}")
    detail = (f"{len(rows)} network(s): group ciphers "
              + ", ".join(sorted({row["group"] or "(none)" for row in rows}))
              + ("; weak group cipher on " + ", ".join(weak[:5]) if weak else
                 "; every group cipher is CCMP or better"))
    return self._report(ctx, ap, attempt,
                        f"group cipher audit: {len(weak)} weak", detail,
                        {"networks": rows[:30], "weak": weak, "capture": path},
                        severity="medium" if weak else "info")


def _cipher_downgrade_audit(self: _Audit, ctx: AttackContext,
                            ap: AccessPoint) -> AttackOutcome:
    """An AP advertising both TKIP and CCMP lets an attacker force the weak one."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    downgradable = []
    for entry in (ie_module.capture_beacons(path, max_packets=60_000) or {}).get(
            "networks") or []:
        facts = entry.get("facts") or {}
        rsn = facts.get("rsn") or {}
        pairwise = {str(item).upper() for item in rsn.get("ciphers", []) or []}
        if {"TKIP", "CCMP"} <= pairwise:
            downgradable.append({"bssid": entry.get("bssid", ""),
                                 "essid": entry.get("essid", ""),
                                 "pairwise": sorted(pairwise)})
    detail = (f"{len(downgradable)} network(s) offer TKIP and CCMP together: a client "
              f"that will accept TKIP can be walked down to it by a crafted association"
              if downgradable else
              "no network in the capture offers both TKIP and CCMP: there is no "
              "pairwise-cipher downgrade to force")
    return self._report(ctx, ap, attempt,
                        f"cipher downgrade: {len(downgradable)} network(s)", detail,
                        {"networks": downgradable[:10], "capture": path},
                        severity="medium" if downgradable else "info")


def _rsn_ie_audit(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """What the RSN element actually says: AKMs, ciphers, PMF bits, group management."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    rows = []
    problems = []
    for entry in (ie_module.capture_beacons(path, max_packets=60_000) or {}).get(
            "networks") or []:
        facts = entry.get("facts") or {}
        rsn = facts.get("rsn") or {}
        if not rsn:
            continue
        row = {"bssid": entry.get("bssid", ""), "essid": entry.get("essid", ""),
               "akm": rsn.get("akm"), "pairwise": rsn.get("ciphers"),
               "group": rsn.get("group"), "mfpc": rsn.get("mfpc"),
               "mfpr": rsn.get("mfpr"), "version": rsn.get("version"),
               "transition": rsn.get("transition_mode")}
        rows.append(row)
        if rsn.get("mfpr") and not rsn.get("mfpc"):
            problems.append(f"{entry.get('bssid')}: PMF required but not capable — "
                            f"contradictory element")
        if rsn.get("tkip"):
            problems.append(f"{entry.get('bssid')}: TKIP in the RSN element")
        if row["transition"]:
            problems.append(f"{entry.get('bssid')}: transition mode (SAE and PSK "
                            f"together) keeps the WPA2 path open")
    detail = (f"{len(rows)} RSN element(s) decoded"
              + ("; " + "; ".join(problems[:4]) if problems else
                 "; nothing contradictory in the elements"))
    return self._report(ctx, ap, attempt,
                        f"RSN element audit: {len(rows)} network(s), "
                        f"{len(problems)} anomaly/ies", detail,
                        {"networks": rows[:30], "problems": problems, "capture": path},
                        severity="medium" if problems else "info")


def _ie_anomaly_audit(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """Elements that do not belong: KARMA patterns, oversized values, zero-length."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    anomalies: List[Dict[str, Any]] = []
    for _stamp, frame in _frames(path):
        info = parse_80211(frame)
        if not info or info.get("type") != MGMT:
            continue
        if info.get("kind") not in ("beacon", "probe response"):
            continue
        body = frame[36:] if len(frame) > 36 else b""
        offset, ssid_count, zero_length = 0, 0, 0
        while offset + 2 <= len(body):
            tag, length = body[offset], body[offset + 1]
            if length == 0:
                zero_length += 1
            if tag == 0:
                ssid_count += 1
            if tag == 0 and length > 32:
                anomalies.append({"bssid": info.get("bssid"), "kind": "SSID too long",
                                  "length": length})
            if tag == 0 and length == 0 and info.get("kind") == "probe response" and \
                    info.get("addr1") == "ff:ff:ff:ff:ff:ff":
                anomalies.append({"bssid": info.get("bssid"),
                                  "kind": "wildcard probe response (KARMA pattern)"})
            offset += 2 + length
        if ssid_count > 1:
            anomalies.append({"bssid": info.get("bssid"),
                              "kind": f"{ssid_count} SSID elements in one frame"})
        if zero_length > 4:
            anomalies.append({"bssid": info.get("bssid"),
                              "kind": f"{zero_length} zero-length elements"})
    detail = (f"{len(anomalies)} anomaly/ies found"
              + (": " + "; ".join(item["kind"] for item in anomalies[:5])
                 if anomalies else ": the element sets look well formed"))
    return self._report(ctx, ap, attempt, f"IE anomalies: {len(anomalies)}", detail,
                        {"anomalies": anomalies[:40], "capture": path},
                        severity="medium" if anomalies else "info")


def _malformed_ie_audit(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """Elements whose length runs past the end of the frame: a parser bug or an attack."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    bad: List[Dict[str, Any]] = []
    total = 0
    for _stamp, frame in _frames(path):
        if len(frame) < 30 or frame[0] & 0x0C != 0:
            continue
        info = parse_80211(frame)
        if not info or info.get("type") != MGMT:
            continue
        body_start = 36 if info.get("kind") in ("beacon", "probe response") else 24
        body = frame[body_start:]
        offset = 0
        while offset + 2 <= len(body):
            tag, length = body[offset], body[offset + 1]
            total += 1
            if offset + 2 + length > len(body):
                bad.append({"bssid": info.get("bssid"), "tag": tag, "length": length,
                            "remaining": len(body) - offset - 2})
                break
            offset += 2 + length
    detail = (f"{total} element(s) walked; {len(bad)} run past the end of their frame "
              f"(a compliant parser truncates, a naive one reads the next element)"
              if bad else f"{total} element(s) walked, every one inside its frame")
    return self._report(ctx, ap, attempt, f"malformed elements: {len(bad)}", detail,
                        {"malformed": bad[:20], "elements": total, "capture": path},
                        severity="medium" if bad else "info")


# --------------------------------------------------------------------------- #
# 11-20: what the clients do
# --------------------------------------------------------------------------- #


def _wildcard_probe_audit(self: _Audit, ctx: AttackContext,
                          ap: AccessPoint) -> AttackOutcome:
    """Clients probing for the empty SSID will join anything: the KARMA customer list."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    clients: Dict[str, int] = {}
    total = 0
    for _stamp, info in _parsed(path):
        if info.get("kind") != "probe request":
            continue
        total += 1
        if not info.get("essid"):
            station = info.get("station") or info.get("addr2") or ""
            if station:
                clients[station] = clients.get(station, 0) + 1
    detail = (f"{len(clients)} of {total} probe request(s) carried the wildcard SSID "
              f"(the stations a KARMA AP can answer): "
              + ", ".join(list(clients)[:8]) if clients else
              f"{total} probe request(s), none with an empty SSID: every client names "
              f"the network it wants")
    return self._report(ctx, ap, attempt,
                        f"wildcard probes: {len(clients)} client(s)", detail,
                        {"clients": dict(list(clients.items())[:40]), "probes": total,
                         "capture": path},
                        severity="medium" if clients else "info")


def _randomised_mac_ratio(self: _Audit, ctx: AttackContext,
                          ap: AccessPoint) -> AttackOutcome:
    """The locally-administered bit tells you how much of the client population hides."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    seen: Dict[str, bool] = {}
    for _stamp, info in _parsed(path):
        station = info.get("station") or ""
        if not station or station == info.get("bssid"):
            continue
        if len(station.split(":")) != 6:
            continue
        first = int(station.split(":")[0], 16)
        seen[station] = bool(first & 0x02)
    random = [mac for mac, bit in seen.items() if bit]
    ratio = (len(random) / len(seen) * 100) if seen else 0.0
    detail = (f"{len(seen)} station(s) in the capture, {len(random)} randomised "
              f"({ratio:.0f}%): "
              + ("good privacy hygiene, and it also means a MAC-based client list is "
                 "wrong" if ratio >= 40 else
                 "most stations transmit a burned-in address, so they are trackable "
                 "across networks"))
    return self._report(ctx, ap, attempt,
                        f"randomised MACs: {len(random)}/{len(seen)} ({ratio:.0f}%)",
                        detail, {"randomised": random[:30], "stations": len(seen),
                                 "capture": path})


def _probe_privacy_audit(self: _Audit, ctx: AttackContext,
                         ap: AccessPoint) -> AttackOutcome:
    """Direct probe requests leak the networks a client has joined before."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    directory: Dict[str, List[str]] = {}
    for _stamp, info in _parsed(path):
        if info.get("kind") != "probe request":
            continue
        essid = _text(info.get("essid"))
        station = _text(info.get("station"))
        if not essid or not station:
            continue
        names = directory.setdefault(station, [])
        if essid not in names:
            names.append(essid)
    shared = [name for station, names in directory.items() for name in names]
    detail = (f"{len(directory)} station(s) sent directed probes naming "
              f"{len(set(shared))} distinct network(s)"
              + (": " + ", ".join(sorted(set(shared))[:6]) if shared else
                 " (only wildcard probes were seen)"))
    return self._report(ctx, ap, attempt,
                        f"directed probes: {len(directory)} station(s), "
                        f"{len(set(shared))} network name(s)", detail,
                        {"directory": {k: v[:8] for k, v in
                                       list(directory.items())[:20]},
                         "capture": path},
                        severity="low" if directory else "info")


def _assoc_history_audit(self: _Audit, ctx: AttackContext,
                         ap: AccessPoint) -> AttackOutcome:
    """Association and reassociation traffic: which clients roam, and to what."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    events: Counter = Counter()
    clients: Dict[str, int] = {}
    for _stamp, info in _parsed(path):
        kind = info.get("kind", "")
        if kind in ("association request", "reassociation request", "association "
                    "response", "reassociation response", "authentication",
                    "deauthentication", "disassociation"):
            events[kind] += 1
            station = info.get("station") or ""
            if station:
                clients[station] = clients.get(station, 0) + 1
    detail = (", ".join(f"{kind}: {count}" for kind, count in events.most_common())
              or "no association traffic in the capture")
    return self._report(ctx, ap, attempt,
                        f"association history: {sum(events.values())} frame(s)", detail,
                        {"events": dict(events), "clients": dict(list(clients.items())[:20]),
                         "capture": path},
                        severity="medium" if events.get("deauthentication") else "info")


def _client_vendor_audit(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """Vendor of every station in the capture, from its OUI."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    from ..util import oui_vendor

    vendors: Counter = Counter()
    stations: Dict[str, str] = {}
    for _stamp, info in _parsed(path):
        station = info.get("station") or ""
        if not station or station == info.get("bssid") or station in stations:
            continue
        vendor = ""
        try:
            vendor = oui_vendor(station) or ""
        except Exception:                                  # pragma: no cover - optional
            vendor = ""
        stations[station] = vendor
        vendors[vendor or "(unknown)"] += 1
    detail = (f"{len(stations)} station(s): "
              + ", ".join(f"{name} x{count}" for name, count in vendors.most_common(6)))
    return self._report(ctx, ap, attempt,
                        f"client vendors: {len(vendors)} distinct", detail,
                        {"stations": dict(list(stations.items())[:40]),
                         "vendors": dict(vendors), "capture": path})


def _client_count_audit(self: _Audit, ctx: AttackContext,
                        ap: AccessPoint) -> AttackOutcome:
    """How many stations each BSSID is actually serving, from the frames."""
    attempt = self._attempt(ctx, ap)
    networks = self.bssid_map(ctx, ap)
    if not networks:
        return self._need_capture(ctx, ap, attempt, "a capture with 802.11 frames")
    rows = [{"bssid": entry["bssid"], "essid": entry["essid"] or "(hidden)",
             "clients": len(entry["clients"]), "beacons": entry["beacons"]}
            for entry in networks.values()]
    rows.sort(key=lambda row: row["clients"], reverse=True)
    busiest = rows[0] if rows else {}
    detail = (f"{len(rows)} BSSID(s); busiest is {busiest.get('bssid', '?')} "
              f"({busiest.get('essid', '?')}) with {busiest.get('clients', 0)} station(s)"
              if rows else "no BSSID in the capture")
    return self._report(ctx, ap, attempt,
                        f"client counts: {sum(row['clients'] for row in rows)} "
                        f"association(s) over {len(rows)} BSSID(s)", detail,
                        {"networks": rows[:30], "capture": self.capture(ctx, ap)})


def _data_frame_audit(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """The data-frame mix: how much of this network is actual traffic."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    subtypes: Counter = Counter()
    protected = 0
    total = 0
    for _stamp, info in _parsed(path):
        total += 1
        subtypes[info.get("kind", "?")] += 1
        if info.get("protected"):
            protected += 1
    detail = (f"{total} frame(s): "
              + ", ".join(f"{kind} x{count}" for kind, count in subtypes.most_common(8))
              + f"; {protected} carried the protected bit")
    return self._report(ctx, ap, attempt,
                        f"frame mix: {len(subtypes)} kind(s) of {total} frame(s)", detail,
                        {"subtypes": dict(subtypes), "protected": protected,
                         "total": total, "capture": path})


def _protected_ratio_audit(self: _Audit, ctx: AttackContext,
                           ap: AccessPoint) -> AttackOutcome:
    """Protected versus clear data frames: cleartext traffic is the finding."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    clear: Counter = Counter()
    protected = 0
    for _stamp, info in _parsed(path):
        if info.get("type") != DATA:
            continue
        if info.get("protected"):
            protected += 1
        else:
            ethertype = info.get("ethertype")
            clear[f"0x{ethertype:04x}" if ethertype else "no LLC"] += 1
    if not clear and not protected:
        return self._report(ctx, ap, attempt, "no data frames in the capture",
                            f"{os.path.basename(path)} holds only management frames",
                            {"capture": path})
    ratio = protected / max(1, protected + sum(clear.values())) * 100
    detail = (f"{protected} protected, {sum(clear.values())} clear ({ratio:.0f}% "
              f"protected); clear ethertypes: "
              + ", ".join(f"{name} x{count}" for name, count in clear.most_common(6)))
    return self._report(ctx, ap, attempt,
                        f"protected ratio: {ratio:.0f}% of data frames", detail,
                        {"protected": protected, "clear": dict(clear),
                         "capture": path})


def _duration_field_audit(self: _Audit, ctx: AttackContext,
                          ap: AccessPoint) -> AttackOutcome:
    """Duration/NAV values that are wildly out of range reserve the medium."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    durations: Counter = Counter()
    outliers = 0
    for _stamp, info in _parsed(path):
        value = int(info.get("duration", 0) or 0)
        durations[value // 100 * 100] += 1
        if value > 1000:
            outliers += 1
    detail = (f"{sum(durations.values())} frame(s); {outliers} with a duration over "
              f"1000µs (a NAV long enough to silence the channel); most common: "
              + ", ".join(f"{value}µs x{count}"
                          for value, count in durations.most_common(5)))
    return self._report(ctx, ap, attempt,
                        f"duration fields: {outliers} outlier(s)", detail,
                        {"histogram": {str(k): v for k, v in durations.most_common(12)},
                         "outliers": outliers, "capture": path},
                        severity="medium" if outliers else "info")


def _retransmit_audit(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """The retry bit: a noisy channel, a hidden node, or a jammer."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    retries = total = 0
    per_station: Counter = Counter()
    for _stamp, info in _parsed(path):
        total += 1
        if info.get("retry"):
            retries += 1
            per_station[info.get("station") or info.get("addr2") or "?"] += 1
    ratio = retries / max(1, total) * 100
    detail = (f"{retries} of {total} frame(s) were retransmissions ({ratio:.1f}%); "
              f"worst transmitters: "
              + ", ".join(f"{mac} x{count}" for mac, count in per_station.most_common(5)))
    return self._report(ctx, ap, attempt,
                        f"retransmissions: {ratio:.1f}% of frames", detail,
                        {"retries": retries, "frames": total, "ratio": ratio,
                         "stations": dict(per_station.most_common(15)),
                         "capture": path},
                        severity="medium" if ratio > 25 else "info")


def _fragment_audit(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """Fragmented data frames: rare on a healthy network, and the FragAttacks vehicle."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    fragments = 0
    stations: Counter = Counter()
    for _stamp, info in _parsed(path):
        if info.get("type") != DATA:
            continue
        index = int(info.get("fragment", 0) or 0)
        if index:
            fragments += 1
            stations[info.get("station") or info.get("addr2") or "?"] += 1
    detail = (f"{fragments} fragmented frame(s)"
              + (": " + ", ".join(f"{mac} x{count}"
                                  for mac, count in stations.most_common(4))
                 if fragments else ": no fragmentation, so the aggregation attacks "
                                   "have no fragment handling to abuse"))
    return self._report(ctx, ap, attempt, f"fragmentation: {fragments} frame(s)", detail,
                        {"fragments": fragments, "stations": dict(stations),
                         "capture": path},
                        severity="medium" if fragments else "info")


# --------------------------------------------------------------------------- #
# 21-30: the network's own paperwork
# --------------------------------------------------------------------------- #


def _beacon_interval_audit(self: _Audit, ctx: AttackContext,
                           ap: AccessPoint) -> AttackOutcome:
    """Beacon intervals that are not 100 TU: a clone detector's simplest signal."""
    attempt = self._attempt(ctx, ap)
    networks = self.bssid_map(ctx, ap)
    if not networks:
        return self._need_capture(ctx, ap, attempt, "a capture with beacons")
    rows = []
    odd = []
    for entry in networks.values():
        intervals = Counter(entry["intervals"])
        if not intervals:
            continue
        common = intervals.most_common(1)[0][0]
        rows.append({"bssid": entry["bssid"], "essid": entry["essid"],
                     "interval": common, "distinct": len(intervals)})
        if common not in (100, 200) or len(intervals) > 2:
            odd.append(f"{entry['bssid']} advertises {common} TU")
    detail = (f"{len(rows)} BSSID(s); "
              + (", ".join(odd[:5]) if odd else "every one advertises the usual 100 TU"))
    return self._report(ctx, ap, attempt,
                        f"beacon intervals: {len(odd)} unusual", detail,
                        {"networks": rows[:30], "unusual": odd,
                         "capture": self.capture(ctx, ap)},
                        severity="medium" if odd else "info")


def _tsf_skew_audit(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """Beacon timestamps that disagree with capture time: a replaying twin."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    per_bssid: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
    for stamp, frame in _frames(path):
        info = parse_80211(frame)
        if not info or info.get("kind") != "beacon":
            continue
        if len(frame) < 32:
            continue
        tsf = int.from_bytes(frame[24:32], "little")
        per_bssid[info.get("bssid") or "?"].append((stamp, tsf))
    offenders = []
    rows = []
    for bssid, samples in per_bssid.items():
        if len(samples) < 3:
            continue
        drift = []
        stalled = 0
        for (t1, v1), (t2, v2) in zip(samples, samples[1:]):
            elapsed = (t2 - t1) * 1_000_000
            if elapsed <= 0:
                continue
            step = (v2 - v1) - elapsed
            drift.append(step)
            if (v2 - v1) <= 0 < elapsed:
                stalled += 1                       # the clock stood still between beacons
        if not drift:
            continue
        worst = max(abs(value) for value in drift)
        # A replayed beacon does not have to jump a second in one gap: the giveaway is
        # that its clock *never advances*, so the error accumulates over the capture.
        cumulative = (samples[-1][1] - samples[0][1]) - (samples[-1][0] - samples[0][0]) * 1e6
        rows.append({"bssid": bssid, "worst_step_us": round(worst, 1),
                     "cumulative_us": round(cumulative, 1), "stalled_steps": stalled,
                     "samples": len(drift)})
        if abs(cumulative) > 1_000_000 or worst > 1_000_000:
            offenders.append(f"{bssid} off by {cumulative / 1e6:+.1f}s over the capture"
                             + (f" ({stalled} stalls)" if stalled else ""))
    detail = (f"{len(rows)} BSSID(s) measured; "
              + (", ".join(offenders[:5]) + " — a beacon replayed from a recording "
                 "cannot keep its timestamp honest"
                 if offenders else "every beacon clock tracks capture time to within a "
                 "second across the whole capture"))
    return self._report(ctx, ap, attempt,
                        f"TSF skew: {len(offenders)} suspicious BSSID(s)", detail,
                        {"measurements": rows[:30], "offenders": offenders,
                         "capture": path},
                        severity="medium" if offenders else "info")


def _assoc_response_audit(self: _Audit, ctx: AttackContext,
                          ap: AccessPoint) -> AttackOutcome:
    """Status codes in association responses: what this network refuses, and why."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    from .frames import STATUS_CODES

    codes: Counter = Counter()
    for _stamp, info in _parsed(path):
        if info.get("kind") in ("association response", "reassociation response"):
            code = int(info.get("status", 0) or 0)
            codes[code] += 1
    detail = (", ".join(f"{code} {STATUS_CODES.get(code, '')} x{count}"
                        for code, count in codes.most_common())
              or "no association responses in the capture")
    denied = sum(count for code, count in codes.items() if code)
    return self._report(ctx, ap, attempt,
                        f"association responses: {sum(codes.values())}, "
                        f"{denied} refused", detail,
                        {"codes": {str(k): v for k, v in codes.items()},
                         "capture": path},
                        severity="medium" if denied else "info")


def _auth_response_audit(self: _Audit, ctx: AttackContext,
                         ap: AccessPoint) -> AttackOutcome:
    """Authentication exchanges: open, shared-key (WEP) or SAE, and what was refused."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    from .frames import AUTH_ALGORITHMS, STATUS_CODES

    algorithms: Counter = Counter()
    statuses: Counter = Counter()
    for _stamp, info in _parsed(path):
        if info.get("kind") != "authentication":
            continue
        algorithms[int(info.get("algorithm", 0) or 0)] += 1
        statuses[int(info.get("status", 0) or 0)] += 1
    detail = ("algorithms: " + ", ".join(
        f"{AUTH_ALGORITHMS.get(code, code)} x{count}"
        for code, count in algorithms.most_common())
        + "; status: " + ", ".join(f"{STATUS_CODES.get(code, code)} x{count}"
                                   for code, count in statuses.most_common(4)))
    shared = algorithms.get(1, 0)
    return self._report(ctx, ap, attempt,
                        f"authentication frames: {sum(algorithms.values())}", detail,
                        {"algorithms": dict(algorithms),
                         "statuses": {str(k): v for k, v in statuses.items()},
                         "capture": path},
                        severity="medium" if shared else "info")


def _ssid_length_audit(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """SSID lengths, including the maximum-length name a clone can hide behind."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    lengths: Counter = Counter()
    names: List[str] = []
    for _stamp, info in _parsed(path):
        if info.get("kind") in ("beacon", "probe response") and info.get("essid"):
            name = info["essid"]
            lengths[len(name)] += 1
            if name not in names:
                names.append(name)
    if not lengths:
        return self._report(ctx, ap, attempt, "no named beacons in the capture",
                            f"{os.path.basename(path)} holds no SSID element",
                            {"capture": path})
    longest = max(names, key=len) if names else ""
    detail = (f"{len(names)} name(s), lengths "
              + ", ".join(f"{length}x{count}"
                          for length, count in sorted(lengths.items())[:10])
              + (f"; longest is {longest!r} ({len(longest)} characters)"
                 if longest else ""))
    return self._report(ctx, ap, attempt,
                        f"SSID inventory: {len(names)} name(s)", detail,
                        {"names": names[:60], "lengths": {str(k): v
                                                          for k, v in lengths.items()},
                         "capture": path})


def _encryption_inventory(self: _Audit, ctx: AttackContext,
                          ap: AccessPoint) -> AttackOutcome:
    """What security each network claims, counted across the capture."""
    attempt = self._attempt(ctx, ap)
    networks = self.bssid_map(ctx, ap)
    if not networks:
        return self._need_capture(ctx, ap, attempt, "a capture with beacons")
    counts = Counter(entry["encryption"] or "(unknown)" for entry in networks.values())
    detail = (f"{len(networks)} network(s): "
              + ", ".join(f"{name} x{count}" for name, count in counts.most_common()))
    return self._report(ctx, ap, attempt,
                        f"encryption inventory: {len(counts)} kind(s)", detail,
                        {"counts": dict(counts), "capture": self.capture(ctx, ap)})


def _bssid_oui_audit(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """Which vendors built the access points: the equipment an estate actually runs."""
    attempt = self._attempt(ctx, ap)
    networks = self.bssid_map(ctx, ap)
    if not networks:
        return self._need_capture(ctx, ap, attempt, "a capture with beacons")
    from ..util import oui_vendor

    vendors: Counter = Counter()
    rows = []
    for entry in networks.values():
        vendor = ""
        try:
            vendor = oui_vendor(entry["bssid"]) or ""
        except Exception:                                  # pragma: no cover
            vendor = ""
        vendors[vendor or "(unknown)"] += 1
        rows.append({"bssid": entry["bssid"], "vendor": vendor,
                     "essid": entry["essid"]})
    detail = ", ".join(f"{name} x{count}" for name, count in vendors.most_common(6))
    return self._report(ctx, ap, attempt,
                        f"BSSID vendors: {len(vendors)} distinct", detail,
                        {"vendors": dict(vendors), "access_points": rows[:40],
                         "capture": self.capture(ctx, ap)})


def _signal_histogram(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """The signal distribution: how far away the estate is, from the radio's view."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    buckets: Counter = Counter()
    values: List[int] = []
    for _stamp, info in _parsed(path):
        signal = info.get("signal")
        if signal:
            values.append(int(signal))
            buckets[f"{int(signal) // 10 * 10} to {int(signal) // 10 * 10 + 9}"] += 1
    if not values:
        return self._report(ctx, ap, attempt, "no signal metadata in the capture",
                            f"{os.path.basename(path)}: the frames carry no radiotap "
                            f"signal field, so distance cannot be estimated",
                            {"capture": path})
    values.sort()
    median = values[len(values) // 2]
    detail = (f"{len(values)} frame(s): median {median} dBm, strongest {max(values)}, "
              f"weakest {min(values)}")
    return self._report(ctx, ap, attempt, f"signal: median {median} dBm", detail,
                        {"histogram": dict(buckets), "median": median,
                         "capture": path})


def _channel_usage_audit(self: _Audit, ctx: AttackContext,
                         ap: AccessPoint) -> AttackOutcome:
    """Channel occupancy: which channels are crowded, and where a test should sit."""
    attempt = self._attempt(ctx, ap)
    networks = self.bssid_map(ctx, ap)
    if not networks:
        return self._need_capture(ctx, ap, attempt, "a capture with beacons")
    counts = Counter(entry["channel"] for entry in networks.values() if entry["channel"])
    if not counts:
        return self._report(ctx, ap, attempt, "no channel information in the capture",
                            f"{os.path.basename(self.capture(ctx, ap))}: no DS "
                            f"parameter set in any beacon", {})
    busiest = counts.most_common(1)[0]
    detail = (", ".join(f"ch {channel}: {count} AP(s)" for channel, count in
                        counts.most_common(8))
              + f"; ch {busiest[0]} is the busiest with {busiest[1]}")
    return self._report(ctx, ap, attempt,
                        f"channel usage: {len(counts)} channel(s) in use", detail,
                        {"channels": {str(k): v for k, v in counts.items()},
                         "capture": self.capture(ctx, ap)})


def _channel_overlap_audit(self: _Audit, ctx: AttackContext,
                           ap: AccessPoint) -> AttackOutcome:
    """Overlapping channels on 2.4GHz: an estate that interferes with itself."""
    attempt = self._attempt(ctx, ap)
    networks = self.bssid_map(ctx, ap)
    if not networks:
        return self._need_capture(ctx, ap, attempt, "a capture with beacons")
    occupancy: Counter = Counter()
    for entry in networks.values():
        channel = int(entry.get("channel") or 0)
        if channel and channel <= 14:                    # 2.4GHz only: 5GHz does not overlap
            occupancy[channel] += 1
    # 2.4GHz channels are five apart for a reason: the same channel is the worst case
    # and anything closer than five still shares air.  Counting *access points* per
    # channel is the point — a set of channel numbers cannot see co-channel
    # interference, which is the commonest fault on this band.
    channels = sorted(occupancy)
    co_channel = {channel: count for channel, count in occupancy.items() if count > 1}
    adjacent = [f"{a}-{b}" for index, a in enumerate(channels)
                for b in channels[index + 1:] if 0 < abs(a - b) < 5]
    detail = (f"{len(networks)} AP(s) across {len(channels)} 2.4GHz channel(s): "
              + ", ".join(f"ch{channel} x{occupancy[channel]}" for channel in channels)
              + (f"; {len(co_channel)} channel(s) carry more than one AP ("
                 + ", ".join(f"ch{channel} x{count}" for channel, count in
                             co_channel.items())
                 + "): those cells share airtime and retries"
                 if co_channel else "")
              + (f"; adjacent channels in use: {', '.join(adjacent[:6])}"
                 if adjacent else ""))
    return self._report(ctx, ap, attempt,
                        f"channel overlap: {len(co_channel)} co-channel, "
                        f"{len(adjacent)} adjacent",
                        detail,
                        {"occupancy": {str(k): v for k, v in occupancy.items()},
                         "co_channel": {str(k): v for k, v in co_channel.items()},
                         "adjacent": adjacent, "capture": self.capture(ctx, ap)},
                        severity="medium" if co_channel else "info")


# --------------------------------------------------------------------------- #
# 31-40: handshake and EAPOL forensics
# --------------------------------------------------------------------------- #


def _handshake_message_audit(self: _Audit, ctx: AttackContext,
                             ap: AccessPoint) -> AttackOutcome:
    """Which of the four messages each handshake actually has."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    facts = _EapolFacts(path)
    essids = facts.analysis.essids
    rows = []
    for handshake in facts.handshakes:
        rows.append({"bssid": handshake.bssid, "essid": essids.get(handshake.bssid, ""),
                     "messages": sorted(handshake.messages), "complete": handshake.complete,
                     "eapol": handshake.eapol_count if hasattr(handshake, "eapol_count")
                     else len(handshake.messages)})
    complete = sum(1 for row in rows if row["complete"])
    detail = (f"{len(rows)} handshake(s), {complete} complete; "
              + "; ".join(f"{row['bssid']}: messages {row['messages']}"
                          for row in rows[:5])
              if rows else "no handshake in the capture")
    return self._report(ctx, ap, attempt,
                        f"handshake messages: {complete}/{len(rows)} complete", detail,
                        {"handshakes": rows[:20], "capture": path})


def _pmkid_presence_audit(self: _Audit, ctx: AttackContext,
                          ap: AccessPoint) -> AttackOutcome:
    """PMKIDs in the capture: material that needs no client and no deauth."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    facts = _EapolFacts(path)
    pmkids = list(facts.analysis.pmkids)
    rows = [{"bssid": item.bssid, "station": getattr(item, "station", ""),
             "essid": facts.analysis.essids.get(item.bssid, "")} for item in pmkids]
    detail = (f"{len(rows)} PMKID(s) present"
              + (": " + ", ".join(f"{row['bssid']} from {row['station']}"
                                  for row in rows[:5]) if rows else
                 " — the capture holds no PMKID, so a crack needs a full handshake"))
    return self._report(ctx, ap, attempt, f"PMKID presence: {len(rows)}", detail,
                        {"pmkids": rows, "capture": path},
                        severity="low" if rows else "info")


def _eapol_retry_audit(self: _Audit, ctx: AttackContext,
                       ap: AccessPoint) -> AttackOutcome:
    """Retransmitted key messages: a client that cannot hear the AP, or a jammer."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    facts = _EapolFacts(path)
    by_number: Counter = Counter()
    for message in facts.messages:
        by_number[int(getattr(message, "number", 0) or 0)] += 1
    retransmits = sum(count - 1 for count in by_number.values() if count > 1)
    detail = (f"{len(facts.messages)} key message(s): "
              + ", ".join(f"M{number} x{count}"
                          for number, count in sorted(by_number.items()))
              + f"; {retransmits} retransmission(s), {facts.retransmits} counted by the "
                f"parser")
    return self._report(ctx, ap, attempt,
                        f"EAPOL retries: {retransmits}", detail,
                        {"messages": {str(k): v for k, v in by_number.items()},
                         "retransmits": retransmits, "capture": path},
                        severity="medium" if retransmits > 4 else "info")


def _wpa3_transition_audit(self: _Audit, ctx: AttackContext,
                           ap: AccessPoint) -> AttackOutcome:
    """WPA3-only versus transition mode: the population a downgrade can reach."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    transition, only, none = [], [], []
    for entry in (ie_module.capture_beacons(path, max_packets=60_000) or {}).get(
            "networks") or []:
        facts = entry.get("facts") or {}
        rsn = facts.get("rsn") or {}
        akms = {str(item).upper() for item in (rsn.get("akm") or [])}
        if not akms:
            none.append(entry.get("bssid", ""))
        elif any("SAE" in akm for akm in akms) and any("PSK" in akm for akm in akms):
            transition.append({"bssid": entry.get("bssid", ""),
                               "essid": entry.get("essid", ""), "akm": sorted(akms)})
        elif any("SAE" in akm for akm in akms):
            only.append({"bssid": entry.get("bssid", ""),
                         "essid": entry.get("essid", "")})
    detail = (f"{len(transition)} transition-mode network(s) (SAE and PSK in the same "
              f"element), {len(only)} WPA3-only, {len(none)} without an RSN element"
              + ("; transition mode is where a downgrade twin finds its clients"
                 if transition else ""))
    return self._report(ctx, ap, attempt,
                        f"WPA3 mode: {len(transition)} transition / {len(only)} pure",
                        detail,
                        {"transition": transition[:20], "wpa3_only": only[:20],
                         "capture": path},
                        severity="medium" if transition else "info")


def _sa_query_activity(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """SA Query traffic proves PMF is actually in force, not just advertised."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    sa_query = 0
    for _stamp, info in _parsed(path):
        if info.get("kind") != "action":
            continue
        if int(info.get("category", -1) or -1) == 8:
            sa_query += 1
    detail = (f"{sa_query} SA Query frame(s) on air: "
              + ("management frame protection is doing its job" if sa_query else
                 "none — either no PMF network was tested, or PMF is advertised and "
                 "unused"))
    return self._report(ctx, ap, attempt, f"SA Query activity: {sa_query} frame(s)",
                        detail, {"sa_query": sa_query, "capture": path},
                        severity="medium" if not sa_query else "info")


def _eapol_logoff_audit(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """EAPOL-Logoff frames: a client asking to be disconnected, or an attacker."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    logoffs: Counter = Counter()
    for _stamp, frame in _frames(path):
        if len(frame) < 36:
            continue                                  # smallest EAPOL-Logoff frame
        for offset in (24, 30, 32):
            if frame[offset:offset + 8] == b"\xaa\xaa\x03\x00\x00\x00\x88\x8e":
                if frame[offset + 8:offset + 9] == b"\x02" and \
                        frame[offset + 9:offset + 10] == b"\x02":
                    logoffs[info_bssid(frame)] += 1
    detail = (f"{sum(logoffs.values())} EAPOL-Logoff frame(s)"
              + (": " + ", ".join(f"{bssid} x{count}"
                                  for bssid, count in logoffs.most_common(5))
                 if logoffs else ": none in this capture"))
    return self._report(ctx, ap, attempt, f"EAPOL-Logoff: {sum(logoffs.values())}",
                        detail, {"logoffs": dict(logoffs), "capture": path})


def info_bssid(frame: bytes) -> str:
    """The transmitter address of a frame, as text (used by the frame scanners)."""
    if len(frame) < 16:
        return "?"
    return ":".join(f"{byte:02x}" for byte in frame[10:16])


def _llc_snap_audit(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """Every ethertype carried over the WLAN: what this network actually speaks."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    ethertypes: Counter = Counter()
    for _stamp, info in _parsed(path):
        ethertype = info.get("ethertype")
        if ethertype:
            ethertypes[ethertype] += 1
    names = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6", 0x888E: "EAPOL",
             0x889A: "ATA over Ethernet", 0x8100: "VLAN"}
    detail = (", ".join(f"{names.get(code, hex(code))} (0x{code:04x}) x{count}"
                        for code, count in ethertypes.most_common())
              or "no LLC/SNAP traffic in the capture")
    return self._report(ctx, ap, attempt,
                        f"ethertypes: {len(ethertypes)} distinct", detail,
                        {"ethertypes": {f"0x{code:04x}": count
                                        for code, count in ethertypes.items()},
                         "capture": path})


def _qos_audit(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """QoS traffic and its traffic identifiers: voice, video, best effort."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    tids: Counter = Counter()
    qos = plain = 0
    for _stamp, info in _parsed(path):
        if info.get("type") != DATA:
            continue
        if "QoS" in str(info.get("kind", "")):
            qos += 1
            tids[int(info.get("tid", 0) or 0)] += 1
        else:
            plain += 1
    detail = (f"{qos} QoS frame(s) and {plain} plain data frame(s); traffic classes: "
              + (", ".join(f"TID {tid} x{count}" for tid, count in tids.most_common())
                 or "none"))
    return self._report(ctx, ap, attempt, f"QoS: {qos} frame(s)", detail,
                        {"tids": {str(k): v for k, v in tids.items()}, "qos": qos,
                         "plain": plain, "capture": path})


def _power_save_audit(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """Power-save frames tell you how many stations are battery-powered IoT devices."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    saving: Counter = Counter()
    active: Counter = Counter()
    for _stamp, info in _parsed(path):
        if info.get("type") != DATA:
            continue
        station = info.get("station") or "?"
        (saving if info.get("power_save") else active)[station] += 1
    sleepers = [mac for mac, count in saving.items() if count > active.get(mac, 0)]
    detail = (f"{len(saving)} station(s) sent power-save frames, {len(active)} sent "
              f"active-traffic frames; {len(sleepers)} sleep more than they talk "
              f"(the IoT half of the estate)")
    return self._report(ctx, ap, attempt,
                        f"power save: {len(sleepers)} sleeping station(s)", detail,
                        {"sleeping": sleepers[:30], "capture": path})


def _broadcast_storm_audit(self: _Audit, ctx: AttackContext,
                           ap: AccessPoint) -> AttackOutcome:
    """Broadcast and multicast share of the traffic: what wakes every station up."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    broadcast = multicast = unicast = 0
    for _stamp, info in _parsed(path):
        if info.get("type") != DATA:
            continue
        target = info.get("addr1") or ""
        if target == "ff:ff:ff:ff:ff:ff":
            broadcast += 1
        elif target and int(target.split(":")[0], 16) & 0x01:
            multicast += 1
        else:
            unicast += 1
    total = broadcast + multicast + unicast
    share = (broadcast + multicast) / max(1, total) * 100
    detail = (f"{broadcast} broadcast, {multicast} multicast, {unicast} unicast "
              f"({share:.1f}% group traffic)")
    return self._report(ctx, ap, attempt, f"group traffic: {share:.1f}%", detail,
                        {"broadcast": broadcast, "multicast": multicast,
                         "unicast": unicast, "capture": path},
                        severity="medium" if share > 40 else "info")


def _gratuitous_arp_audit(self: _Audit, ctx: AttackContext,
                          ap: AccessPoint) -> AttackOutcome:
    """Gratuitous ARP in the capture: the fingerprint of an ARP spoofing tool."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    gratuitous: Counter = Counter()
    replies = requests = 0
    for _stamp, info in _parsed(path):
        if info.get("ethertype") != 0x0806:
            continue
        payload = info.get("payload") or b""
        if len(payload) < 28:
            continue
        operation = int.from_bytes(payload[6:8], "big")
        sender_ip = payload[14:18]
        target_ip = payload[24:28]
        if operation == 2:
            replies += 1
            if sender_ip == target_ip:
                gratuitous[info.get("station") or "?"] += 1
        else:
            requests += 1
    detail = (f"{replies} ARP repl(y|ies) and {requests} request(s); "
              + (f"{sum(gratuitous.values())} gratuitous (sender address equals target) "
                 f"from " + ", ".join(list(gratuitous)[:5])
                 if gratuitous else "no gratuitous ARP, so no poisoning in this capture"))
    return self._report(ctx, ap, attempt,
                        f"gratuitous ARP: {sum(gratuitous.values())}", detail,
                        {"senders": dict(gratuitous.most_common(20)), "replies": replies,
                         "requests": requests, "capture": path},
                        severity="high" if gratuitous else "info")


def _arp_scan_detect(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """Sequential ARP requests are a scan: who is enumerating the subnet."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    from ..netproto import parse_arp

    per_client: Dict[str, List[int]] = defaultdict(list)
    for _stamp, info in _parsed(path):
        if info.get("ethertype") != 0x0806:
            continue
        arp = parse_arp(info.get("payload") or b"")
        if not arp or arp.get("op") != "request":
            continue
        target = arp.get("target_ip") or ""
        try:
            last = int(target.split(".")[-1])
        except (ValueError, IndexError):
            continue
        per_client[arp.get("sender_mac") or "?"].append(last)
    scanners = []
    for mac, hosts in per_client.items():
        unique = sorted(set(hosts))
        if len(unique) < 6:
            continue
        span = unique[-1] - unique[0]
        density = len(unique) / span if span else 1.0
        if density > 0.3:
            scanners.append({"mac": mac, "hosts": len(unique), "span": span})
    detail = (f"{len(per_client)} ARP requester(s); "
              + (f"{len(scanners)} scanning the subnet sequentially (density > 30%): "
                 + ", ".join(f"{item['mac']} ({item['hosts']} hosts)"
                             for item in scanners[:5])
                 if scanners else "none look like a sweep"))
    return self._report(ctx, ap, attempt,
                        f"ARP scans: {len(scanners)} suspected requester(s)", detail,
                        {"scanners": scanners, "requesters": len(per_client),
                         "capture": path},
                        severity="medium" if scanners else "info")


def _dhcp_fingerprint_audit(self: _Audit, ctx: AttackContext,
                            ap: AccessPoint) -> AttackOutcome:
    """DHCP option sets are a client fingerprint: the OS behind each station."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    from ..netproto import parse_dhcp

    fingerprints: Dict[str, Dict[str, Any]] = {}
    for _stamp, info in _parsed(path):
        if info.get("ethertype") != 0x0800:
            continue
        payload = info.get("payload") or b""
        if len(payload) < 28:
            continue
        ihl = (payload[0] & 0x0F) * 4
        if payload[9] != 17:
            continue
        udp = payload[ihl:]
        if len(udp) < 8:
            continue
        if int.from_bytes(udp[0:2], "big") not in (67, 68):
            continue
        dhcp = parse_dhcp(udp[8:])
        if not dhcp or dhcp.get("op") != "request":
            continue
        client = dhcp.get("client_mac") or "?"
        fingerprints[client] = {
            "client": client, "hostname": dhcp.get("hostname", ""),
            "vendor_class": dhcp.get("vendor_class", ""),
            "requested": dhcp.get("requested_ip", ""),
            "server": dhcp.get("server_id", ""),
            "options": sorted(dhcp.get("options", {}))[:24],
            "message_type": dhcp.get("message_type", ""),
        }
    detail = (f"{len(fingerprints)} DHCP client(s): "
              + "; ".join(f"{row['hostname'] or row['client']} "
                          f"({row['vendor_class'] or 'no vendor class'})"
                          for row in list(fingerprints.values())[:5])
              if fingerprints else "no DHCP traffic in this capture")
    return self._report(ctx, ap, attempt,
                        f"DHCP fingerprints: {len(fingerprints)} client(s)", detail,
                        {"clients": list(fingerprints.values())[:30], "capture": path})


def _duplicate_seq_audit(self: _Audit, ctx: AttackContext,
                         ap: AccessPoint) -> AttackOutcome:
    """The same sequence number from the same transmitter: a replay, or a clone."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    seen: Dict[Tuple[str, int], int] = defaultdict(int)
    for _stamp, info in _parsed(path):
        transmitter = info.get("addr2") or info.get("station") or ""
        if not transmitter:
            continue
        key = (transmitter, int(info.get("sequence", 0) or 0))
        seen[key] += 1
    duplicates = {key: count for key, count in seen.items() if count > 1}
    offenders = Counter(mac for (mac, _seq), _count in duplicates.items())
    detail = (f"{len(duplicates)} duplicate (transmitter, sequence) pair(s)"
              + (": " + ", ".join(f"{mac} x{count}" for mac, count
                                  in offenders.most_common(5)) if duplicates else
                 " — every transmitter numbers its frames uniquely in this capture"))
    return self._report(ctx, ap, attempt,
                        f"duplicate sequences: {len(duplicates)}", detail,
                        {"offenders": dict(offenders.most_common(20)),
                         "pairs": [f"{mac}#{seq}" for (mac, seq) in
                                   list(duplicates)[:20]], "capture": path},
                        severity="medium" if duplicates else "info")


def _deauth_storm_detect(self: _Audit, ctx: AttackContext,
                         ap: AccessPoint) -> AttackOutcome:
    """Deauthentication rate: a burst is a flood, and a flood is a finding."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    stamps: List[float] = []
    broadcast = 0
    for stamp, info in _parsed(path):
        if info.get("kind") not in ("deauthentication", "disassociation"):
            continue
        stamps.append(stamp)
        if (info.get("addr1") or "") == "ff:ff:ff:ff:ff:ff":
            broadcast += 1
    stamps.sort()
    bursts = 0
    for index, stamp in enumerate(stamps):
        window = [other for other in stamps[index:] if other - stamp <= 1.0]
        if len(window) >= 20:
            bursts += 1
    detail = (f"{len(stamps)} deauth/disassoc frame(s), {broadcast} to the broadcast "
              f"address"
              + (f"; {bursts} burst(s) of 20+/second — a flood, not a client leaving"
                 if bursts else "; no burst over 20/s"))
    return self._report(ctx, ap, attempt,
                        f"deauth storm: {len(stamps)} frame(s), {bursts} burst(s)",
                        detail,
                        {"frames": len(stamps), "broadcast": broadcast, "bursts": bursts,
                         "capture": path},
                        severity="high" if bursts else "info")


def _auth_flood_detect(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """Authentication frames from many addresses that never associate: a flood."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    authentications: Counter = Counter()
    associations: Counter = Counter()
    for _stamp, info in _parsed(path):
        station = info.get("addr2") or ""
        if info.get("kind") == "authentication":
            authentications[station] += 1
        elif info.get("kind") in ("association request", "reassociation request"):
            associations[station] += 1
    noisy = {mac: count for mac, count in authentications.items()
             if count >= 5 and associations.get(mac, 0) == 0}
    detail = (f"{len(authentications)} authenticating station(s), "
              f"{len(associations)} associating; {len(noisy)} authenticated five or more "
              f"times without ever associating (the flood signature)"
              if noisy else
              f"{len(authentications)} authenticating station(s); every one that "
              f"authenticated more than once also associated")
    return self._report(ctx, ap, attempt,
                        f"auth flood signature: {len(noisy)} station(s)", detail,
                        {"noisy": dict(list(noisy.items())[:30]), "capture": path},
                        severity="high" if noisy else "info")


def _probe_flood_detect(self: _Audit, ctx: AttackContext,
                        ap: AccessPoint) -> AttackOutcome:
    """Probe-request rate and name variety: a flood enumerates, a client asks once."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    per_station: Counter = Counter()
    names: Counter = Counter()
    for _stamp, info in _parsed(path):
        if info.get("kind") != "probe request":
            continue
        station = info.get("addr2") or "?"
        per_station[station] += 1
        if info.get("essid"):
            names[info["essid"]] += 1
    loud = {mac: count for mac, count in per_station.items() if count >= 20}
    random_names = sum(1 for name in names if len(name) >= 28)
    detail = (f"{sum(per_station.values())} probe request(s) from {len(per_station)} "
              f"station(s); {len(loud)} station(s) sent 20 or more, {random_names} "
              f"name(s) are 28+ characters (generated, not typed)")
    return self._report(ctx, ap, attempt,
                        f"probe flood signature: {len(loud)} station(s)", detail,
                        {"stations": dict(per_station.most_common(20)),
                         "names": dict(names.most_common(20)), "capture": path},
                        severity="medium" if loud else "info")


# --------------------------------------------------------------------------- #
# 41-50: reports and inventories that write a file
# --------------------------------------------------------------------------- #


def _pcap_report(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """Write a JSON report of everything this capture holds, as a loot artifact."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    networks = self.bssid_map(ctx, ap)
    analysis = analyze_file(path, max_packets=200_000)
    facts = _EapolFacts(path)
    report = {
        "capture": path, "size": os.path.getsize(path),
        "sha256": _file_hash(path),
        "frames": {"total": analysis.packets, "data": analysis.data_packets,
                   "management": analysis.mgmt_packets, "beacons": analysis.beacons,
                   "eapol": analysis.eapol_messages},
        "networks": [{"bssid": entry["bssid"], "essid": entry["essid"],
                      "channel": entry["channel"], "beacons": entry["beacons"],
                      "clients": len(entry["clients"])}
                     for entry in networks.values()],
        "handshakes": [{"bssid": item.bssid, "messages": sorted(item.messages)}
                       for item in facts.handshakes],
        "pmkids": len(analysis.pmkids),
        "key_versions": {str(k): v for k, v in facts.key_versions().items()},
        "generated": time.time(),
    }
    out = ctx.artifact_path("report", ap, ".json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, default=str)
    saved = ctx.session.save_artifact(out, "report", ctx.loot_name(ap, "pcap-report"))
    detail = (f"{analysis.packets} frame(s), {len(networks)} network(s), "
              f"{len(facts.handshakes)} handshake(s) written to {saved}")
    return self._report(ctx, ap, attempt, "capture report written", detail,
                        {"report": saved, "capture": path})


def _file_hash(path: str, chunk: int = 1 << 20) -> str:
    """SHA-256 of a file, read in chunks (captures can be large)."""
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            while True:
                block = handle.read(chunk)
                if not block:
                    break
                digest.update(block)
    except OSError:                                        # pragma: no cover
        return ""
    return digest.hexdigest()


def _capture_coverage(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """What the session's captures cover: which of the estate is actually in a file."""
    attempt = self._attempt(ctx, ap)
    captures = [cap for cap in ctx.session.all_captures() if cap.path
                and os.path.exists(cap.path)]
    if not captures:
        return self._need_capture(ctx, ap, attempt)
    by_bssid: Dict[str, Dict[str, Any]] = {}
    for capture in captures:
        entry = by_bssid.setdefault(capture.bssid or "?", {"captures": 0, "kinds": set(),
                                                           "size": 0})
        entry["captures"] += 1
        entry["kinds"].add(capture.kind)
        with_size = os.path.getsize(capture.path)
        entry["size"] += with_size
    targets = set(ctx.session.aps)
    covered = {bssid for bssid in by_bssid if bssid in targets}
    missing = sorted(targets - covered)[:20]
    detail = (f"{len(captures)} capture(s) covering {len(by_bssid)} BSSID(s); "
              f"{len(missing)} target(s) have no capture at all"
              + (": " + ", ".join(missing) if missing else ""))
    return self._report(ctx, ap, attempt,
                        f"capture coverage: {len(by_bssid)}/{len(targets or by_bssid)}",
                        detail,
                        {"coverage": [{"bssid": bssid, "captures": entry["captures"],
                                       "kinds": sorted(entry["kinds"]),
                                       "bytes": entry["size"]}
                                      for bssid, entry in by_bssid.items()],
                         "uncovered": missing})


def _beacon_rate_histogram(self: _Audit, ctx: AttackContext,
                           ap: AccessPoint) -> AttackOutcome:
    """Beacon rate per AP: a station repeating a beacon is a clone on air."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    stamps: Dict[str, List[float]] = defaultdict(list)
    for stamp, info in _parsed(path):
        if info.get("kind") == "beacon":
            stamps[info.get("bssid") or "?"].append(stamp)
    rows = []
    for bssid, times in stamps.items():
        if len(times) < 2:
            continue
        times.sort()
        span = max(times[-1] - times[0], 1e-6)
        rows.append({"bssid": bssid, "beacons": len(times),
                     "per_second": round(len(times) / span, 3)})
    rows.sort(key=lambda row: row["per_second"], reverse=True)
    rates = sorted(row["per_second"] for row in rows)
    median = rates[len(rates) // 2] if rates else 0.0
    for row in rows:
        row["versus_median"] = round(row["per_second"] / median, 2) if median else 0.0
    # two ways to stand out: beaconing faster than a 100 TU interval allows, or
    # beaconing at a different rate from every other AP on the site — which is what a
    # clone echoing a recording does, because it cannot help being faster
    loud = [row for row in rows
            if row["per_second"] > 12 or (median and row["versus_median"] >= 1.5)]
    detail = (f"{len(rows)} BSSID(s) beaconing, median {median}/s; "
              + (f"{len(loud)} out of step: "
                 + ", ".join(f"{row['bssid']} at {row['per_second']}/s "
                             f"({row['versus_median']}x median)" for row in loud[:5])
                 if loud else
                 "all within the expected 10/s for a 100 TU interval"))
    return self._report(ctx, ap, attempt,
                        f"beacon rates: {len(loud)} too fast", detail,
                        {"rates": rows[:30], "capture": path},
                        severity="medium" if loud else "info")


def _auth_algorithm_inventory(self: _Audit, ctx: AttackContext,
                              ap: AccessPoint) -> AttackOutcome:
    """What each AP accepts: shared-key WEP still being offered is a finding."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    from .frames import AUTH_ALGORITHMS

    per_bssid: Dict[str, Counter] = defaultdict(Counter)
    for _stamp, info in _parsed(path):
        if info.get("kind") != "authentication":
            continue
        per_bssid[info.get("bssid") or "?"][int(info.get("algorithm", 0) or 0)] += 1
    rows = [{"bssid": bssid, "algorithms": [AUTH_ALGORITHMS.get(code, str(code))
                                            for code in counts]}
            for bssid, counts in per_bssid.items()]
    shared = [row for row in rows if "shared key" in row["algorithms"]]
    detail = (f"{len(rows)} BSSID(s) with authentication traffic; "
              + (f"{len(shared)} still using shared-key WEP authentication: "
                 + ", ".join(row["bssid"] for row in shared[:5]) if shared else
                 "all use open-system or SAE"))
    return self._report(ctx, ap, attempt,
                        f"authentication algorithms: {len(shared)} with shared key",
                        detail, {"networks": rows[:30], "capture": path},
                        severity="high" if shared else "info")


def _station_inventory(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """Every station in the capture, with the networks it was seen on."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    stations: Dict[str, Dict[str, Any]] = {}
    for _stamp, info in _parsed(path):
        station = info.get("station") or ""
        if not station or station == info.get("bssid"):
            continue
        entry = stations.setdefault(station, {"mac": station, "bssids": set(),
                                              "frames": 0, "kinds": Counter()})
        entry["frames"] += 1
        entry["kinds"][info.get("kind", "?")] += 1
        if info.get("bssid"):
            entry["bssids"].add(info["bssid"])
    rows = [{"mac": mac, "bssids": sorted(entry["bssids"]), "frames": entry["frames"],
             "kinds": dict(entry["kinds"].most_common(4))}
            for mac, entry in stations.items()]
    roamers = [row for row in rows if len(row["bssids"]) > 1]
    detail = (f"{len(rows)} station(s); {len(roamers)} seen on more than one BSSID "
              f"(roaming, or a spoofed address)")
    return self._report(ctx, ap, attempt, f"stations: {len(rows)}", detail,
                        {"stations": rows[:60], "capture": path},
                        severity="medium" if roamers else "info")


def _quality_histogram(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """Frame size distribution: what kind of traffic this network carries."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    sizes: Counter = Counter()
    total = 0
    biggest = 0
    for _stamp, frame in _frames(path):
        total += 1
        biggest = max(biggest, len(frame))
        bucket = (len(frame) // 100) * 100
        sizes[bucket] += 1
    detail = (f"{total} frame(s), largest {biggest} bytes; distribution: "
              + ", ".join(f"{bucket}-{bucket + 99}B x{count}"
                          for bucket, count in sorted(sizes.items())[:8]))
    return self._report(ctx, ap, attempt,
                        f"frame sizes: {len(sizes)} bucket(s), max {biggest}B", detail,
                        {"histogram": {str(k): v for k, v in sorted(sizes.items())},
                         "capture": path})


def _vendor_ie_inventory(self: _Audit, ctx: AttackContext,
                         ap: AccessPoint) -> AttackOutcome:
    """Vendor-specific elements: what each vendor stamps into its beacons."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    vendors: Counter = Counter()
    for _stamp, frame in _frames(path):
        info = parse_80211(frame)
        if not info or info.get("kind") not in ("beacon", "probe response"):
            continue
        body = frame[36:] if len(frame) > 36 else b""
        offset = 0
        while offset + 2 <= len(body):
            tag, length = body[offset], body[offset + 1]
            value = body[offset + 2:offset + 2 + length]
            if tag == 221 and len(value) >= 3:
                vendors[":".join(f"{byte:02x}" for byte in value[:3])] += 1
            offset += 2 + length
    detail = (", ".join(f"{oui} x{count}" for oui, count in vendors.most_common(8))
              or "no vendor-specific elements in the capture")
    return self._report(ctx, ap, attempt,
                        f"vendor elements: {len(vendors)} OUI(s)", detail,
                        {"vendors": dict(vendors), "capture": path})


def _hidden_ap_audit(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """Networks that hide their name: which ones, and whether the name leaks anyway."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    hidden: Dict[str, Dict[str, Any]] = {}
    leaked: Dict[str, set] = defaultdict(set)
    for _stamp, info in _parsed(path):
        bssid = info.get("bssid") or ""
        if not bssid:
            continue
        kind = info.get("kind", "")
        if kind in ("beacon", "probe response") and not info.get("essid"):
            hidden.setdefault(bssid, {"bssid": bssid, "beacons": 0,
                                      "channel": info.get("channel", 0)})
            hidden[bssid]["beacons"] += 1
        if kind in ("association request", "reassociation request") and info.get("essid"):
            leaked[bssid].add(info["essid"])
    for bssid, names in leaked.items():
        if bssid in hidden:
            hidden[bssid]["leaked_name"] = sorted(names)[0]
    detail = (f"{len(hidden)} hidden network(s); "
              + (f"{sum(1 for entry in hidden.values() if entry.get('leaked_name'))} had "
                 f"their name revealed by a client's association request: "
                 + ", ".join(f"{entry['bssid']} = {entry['leaked_name']!r}"
                             for entry in hidden.values() if entry.get("leaked_name"))
                 if any(entry.get("leaked_name") for entry in hidden.values())
                 else "no client leaked a hidden name in this capture"))
    return self._report(ctx, ap, attempt, f"hidden networks: {len(hidden)}", detail,
                        {"networks": list(hidden.values())[:30], "capture": path},
                        severity="medium" if hidden else "info")


# --------------------------------------------------------------------------- #
# the table: every analysis above, as an attack
# --------------------------------------------------------------------------- #

_add("mic_check", "Handshake MIC verification (offline)",
     "Run the real 802.11i MIC over a captured handshake with every candidate key "
     "the session has — the config wordlists and the target's demo passphrase — and "
     "report the passphrase that verifies.  A handshake that no candidate verifies is "
     "still a result: the capture is genuine and the key is simply not in the list.",
     "nothing is transmitted; the MIC is computed locally over a stored frame",
     _mic_check, impact="loot", tool="wifipilot (HMAC-SHA1/AES-CMAC MIC)")

_add("nonce_reuse_audit", "Nonce reuse audit (KRACK precondition)",
     "Compare every ANonce and SNonce in the capture.  A value that appears twice is "
     "the precondition the key-reinstall attack needs; a capture where every nonce is "
     "unique says the client and AP are handling replay correctly.",
     "silent: reads EAPOL nonces out of a stored capture", _nonce_reuse,
     impact="info")

_add("key_version_audit", "EAPOL key descriptor version audit",
     "Classify each EAPOL key message by its descriptor version: 1 is HMAC-MD5 over "
     "WPA/TKIP, 2 is HMAC-SHA1-128 for WPA2, 3 is AES-128-CMAC for PMF.  A network "
     "still using version 1 is running the older handshake and the older cipher.",
     "silent: reads the key information field of stored EAPOL frames",
     _key_version_audit, impact="info")

_add("tkip_countermeasures_audit", "TKIP countermeasures detection",
     "Deauthentication with reason 15 or 16 means the AP detected a forged Michael MIC "
     "and shut its BSS down for a minute.  Finding those frames in a capture is "
     "evidence that the countermeasures — the only real defence TKIP has — are armed.",
     "silent: reads deauthentication reason codes out of a capture",
     _tkip_countermeasures_audit, scene=True, impact="info")

_add("group_cipher_audit", "Group cipher audit",
     "The group cipher an AP advertises applies to every station: a network still "
     "sending TKIP-protected broadcast traffic keeps the whole cell on a cipher that "
     "has been broken for a decade.",
     "silent: decodes the RSN element of stored beacons", _group_cipher_audit, scene=True,
     impact="info")

_add("cipher_downgrade_audit", "Pairwise cipher downgrade audit",
     "Networks that offer TKIP and CCMP in the same RSN element can be walked down to "
     "TKIP: a crafted association request naming only the weaker suite is answered by "
     "an AP that offers both.  This finds the networks where that works.",
     "silent: compares the pairwise cipher lists of stored beacons",
     _cipher_downgrade_audit, scene=True, impact="info")

_add("rsn_ie_audit", "RSN element audit",
     "Decode the RSN element of every network in the capture — AKM suites, pairwise and "
     "group ciphers, the PMF capable/required bits, and the PMKID count — and flag the "
     "contradictions, such as PMF required on a network that does not advertise PMF "
     "capability.",
     "silent: reads the RSN element line by line", _rsn_ie_audit, scene=True, impact="info")

_add("ie_anomaly_audit", "Information element anomaly audit",
     "Look for elements that should not be there: an SSID longer than 32 bytes, a "
     "wildcard probe response (the KARMA pattern), more than one SSID element in a "
     "frame, a frame packed with zero-length elements.",
     "silent: walks the element area of every management frame in a capture",
     _ie_anomaly_audit, scene=True, impact="info")

_add("malformed_ie_audit", "Malformed element audit",
     "Elements whose declared length runs past the end of the frame.  A compliant "
     "parser truncates; a naive one reads into the next element, which is a whole class "
     "of client-side bug.  Finding them in a capture smells like a fuzzer.",
     "silent: length-checks every element in every management frame",
     _malformed_ie_audit, scene=True, impact="info")

_add("wildcard_probe_audit", "Wildcard probe audit (KARMA customers)",
     "Stations that probe for the empty SSID will associate with anything that answers "
     "— that is exactly the population a KARMA access point serves.  This counts them "
     "in the capture, and names the addresses.",
     "silent: reads the SSID element of stored probe requests",
     _wildcard_probe_audit, scene=True, impact="info")

_add("randomised_mac_ratio", "Randomised MAC ratio",
     "The locally administered bit in a station's address says whether it randomised "
     "its MAC.  The ratio is a privacy measurement: a network where most addresses are "
     "burned in is a network whose clients are trackable between sites.",
     "silent: reads transmitter addresses out of a capture", _randomised_mac_ratio, scene=True,
     impact="info")

_add("probe_privacy_audit", "Directed probe privacy audit",
     "Directed probe requests name the networks a client has joined before, which is a "
     "history of everywhere that device has been.  This builds that history from the "
     "capture, per station.",
     "silent: builds a per-station network list from stored probe requests",
     _probe_privacy_audit, scene=True, impact="info")

_add("assoc_history_audit", "Association history audit",
     "Count the association, reassociation, authentication and deauthentication frames "
     "in a capture: how many clients joined, how many roamed, and how often something "
     "cut them off.",
     "silent: counts management frame types in a stored capture",
     _assoc_history_audit, scene=True, impact="info")

_add("client_vendor_audit", "Client vendor audit",
     "Resolve the vendor of every station address in a capture from its OUI, which is "
     "the fastest way to see whether an estate is a managed fleet or a bring-your-own-"
     "device problem.",
     "silent: reads transmitter addresses and their OUIs", _client_vendor_audit, scene=True)

_add("client_count_audit", "Client population audit",
     "How many stations each BSSID is actually serving, from the traffic each one "
     "transmits.  An access point advertising sixty clients and showing three in the "
     "frames is a capacity measurement nobody has to guess at.",
     "silent: counts distinct transmitters per BSSID", _client_count_audit, scene=True)

_add("data_frame_audit", "Data frame mix audit",
     "The distribution of frame kinds in a capture, and how many carried the protected "
     "bit.  It is the quickest sanity check on a capture: hundreds of beacons and no "
     "data means the collector sat on the wrong channel.",
     "silent: classifies every frame in a capture", _data_frame_audit, scene=True)

_add("protected_ratio_audit", "Protected frame ratio audit",
     "Protected versus clear data frames, per ethertype.  ARP and management frames are "
     "expected in the clear; a network with IPv4 traffic outside the cipher is "
     "misconfigured, or open.",
     "silent: reads the protected bit and the LLC type of stored data frames",
     _protected_ratio_audit, scene=True, impact="info")

_add("duration_field_audit", "Duration/NAV field audit",
     "The duration field reserves the medium.  Values far above what the frame needs — "
     "a NAV long enough to silence the channel — are either a broken driver or a "
     "deliberate reservation attack.",
     "silent: reads the duration field of every frame in a capture",
     _duration_field_audit, scene=True, impact="info")

_add("retransmit_audit", "Retransmission audit",
     "The retry bit, counted per transmitter.  A high retransmission rate is a noisy "
     "channel, a hidden node, or somebody jamming; the per-transmitter split says which.",
     "silent: reads the retry bit of stored frames", _retransmit_audit, scene=True,
     impact="info")

_add("fragment_audit", "Fragmentation audit",
     "Fragmented data frames are rare on a healthy network and are the vehicle for the "
     "aggregation attacks.  Counting them per station says whether fragmentation is a "
     "normal part of this network's traffic or a red flag.",
     "silent: reads the fragment number of stored data frames", _fragment_audit, scene=True,
     impact="info")

_add("beacon_interval_audit", "Beacon interval audit",
     "Almost every AP beacons every 100 TU.  A network advertising an unusual interval, "
     "or several different ones, is either badly configured or not what it claims to be.",
     "silent: reads the beacon interval of stored beacons", _beacon_interval_audit, scene=True,
     impact="info")

_add("tsf_skew_audit", "Beacon timestamp (TSF) skew audit",
     "Compare each beacon's timestamp against capture time.  A clone that replays "
     "recorded beacons cannot keep the clock honest: its timestamps stop advancing at "
     "the right rate, which is the cheapest twin detector there is.",
     "silent: measures the drift of stored beacon timestamps", _tsf_skew_audit, scene=True,
     impact="info")

_add("assoc_response_audit", "Association response audit",
     "Which status codes this network returns: success, capability mismatch, denied, or "
     "denied for too many stations.  The distribution is a picture of what the AP "
     "refuses and why.",
     "silent: reads the status code of stored association responses",
     _assoc_response_audit, scene=True, impact="info")

_add("auth_response_audit", "Authentication exchange audit",
     "Open system, shared key or SAE — and which of them the AP refused.  Shared-key "
     "authentication is WEP's challenge/response and is a finding on its own.",
     "silent: reads the algorithm and status of stored authentication frames",
     _auth_response_audit, scene=True, impact="info")

_add("ssid_length_audit", "SSID inventory and length audit",
     "Every name on air with its length.  A 32-character maximum-length name is the "
     "classic hiding place for a clone, and a name that appears in beacons but nowhere "
     "in any client's probe list is a name nobody is looking for.",
     "silent: reads SSID elements out of stored beacons and probe responses",
     _ssid_length_audit, scene=True, impact="info")

_add("encryption_inventory", "Encryption inventory",
     "What each network actually claims: open, WEP, WPA, WPA2, WPA3 or enterprise, "
     "counted across the capture.  The inventory is the first line of an assessment "
     "report and the list of what is worth attacking.",
     "silent: decodes the security elements of stored beacons",
     _encryption_inventory, scene=True, impact="info")

_add("bssid_oui_audit", "Access point vendor audit",
     "Which vendors built the access points in a capture, from their OUIs.  An estate "
     "with one vendor gets one set of firmware bugs; one with six has six.",
     "silent: reads BSSID OUIs out of stored beacons", _bssid_oui_audit, scene=True)

_add("signal_histogram", "Signal distribution audit",
     "The distribution of received signal strength across a capture: how far the estate "
     "is, which AP is closest to the collector, and how much of the traffic is at the "
     "edge of the radio's range.",
     "silent: reads the radiotap signal field of stored frames", _signal_histogram, scene=True)

_add("channel_usage_audit", "Channel usage audit",
     "Which channels the estate is spread over and how crowded each one is.  This is "
     "the map an operator uses to decide where a test should sit.",
     "silent: reads the DS parameter set of stored beacons", _channel_usage_audit, scene=True)

_add("channel_overlap_audit", "Channel overlap audit",
     "Two access points within four channels of each other on 2.4GHz interfere, and the "
     "clients pay for it.  Every overlapping pair in the capture is a finding about the "
     "site's own planning.",
     "silent: compares the channels in stored beacons", _channel_overlap_audit, scene=True,
     impact="info")

_add("handshake_message_audit", "Handshake message inventory",
     "Which of the four EAPOL messages each stored handshake actually has.  A capture "
     "with message 1 and 4 but no message 2 is not crackable, and this says so before "
     "anyone spends an hour on it.",
     "silent: reads the message numbers of stored EAPOL frames",
     _handshake_message_audit, scene=True, impact="info")

_add("pmkid_presence_audit", "PMKID presence audit",
     "Does the session hold PMKIDs?  A PMKID is material that needs no client and no "
     "deauthentication — the capture is already a crack target.",
     "silent: reads PMKIDs out of stored EAPOL message 1 frames",
     _pmkid_presence_audit, impact="loot")

_add("eapol_retry_audit", "EAPOL retransmission audit",
     "Retransmitted key messages: a client that cannot hear the AP, an AP that cannot "
     "hear the client, or somebody in the middle.  The count is a cheap link-quality "
     "measurement for a handshake that is failing.",
     "silent: counts repeated key message numbers in a capture",
     _eapol_retry_audit, impact="info")

_add("wpa3_transition_audit", "WPA3 transition mode audit",
     "Networks advertising SAE and PSK in the same RSN element are in transition mode: "
     "their clients will accept WPA2, which is the population a downgrade twin can "
     "serve.  Pure WPA3 networks are listed separately.",
     "silent: reads the AKM suites of stored beacons", _wpa3_transition_audit, scene=True,
     impact="info")

_add("sa_query_activity", "SA Query activity audit",
     "SA Query frames only appear when management frame protection is actually in "
     "force, so their presence proves PMF is working rather than merely advertised.  "
     "Their absence on a PMF network is worth a question.",
     "silent: counts action frames with category 8 in a capture", _sa_query_activity, scene=True,
     impact="info")

_add("eapol_logoff_audit", "EAPOL-Logoff audit",
     "EAPOL-Logoff asks the authenticator to drop the session, is unauthenticated, and "
     "is trivially forged.  Counting the frames in a capture shows whether anyone is "
     "using — or abusing — it.",
     "silent: scans stored frames for EAPOL type 2", _eapol_logoff_audit, scene=True,
     impact="info")

_add("llc_snap_audit", "LLC/SNAP ethertype audit",
     "Every ethertype carried over the WLAN, so the traffic profile of the estate is "
     "a list rather than a guess: IPv4, ARP, IPv6, EAPOL, VLAN tags.",
     "silent: reads the LLC/SNAP header of stored data frames", _llc_snap_audit, scene=True)

_add("qos_audit", "QoS traffic audit",
     "QoS data frames and their traffic identifiers: voice and video classes on a "
     "network tell you which access points matter, and an AP dropping QoS frames has a "
     "capacity problem.",
     "silent: reads the QoS control field of stored data frames", _qos_audit, scene=True)

_add("power_save_audit", "Power save audit",
     "Stations that spend more frames asleep than awake are the battery-powered half of "
     "the estate — IoT sensors, door locks, meters.  They are also the ones that "
     "disappear from a client list first.",
     "silent: reads the power management bit of stored data frames",
     _power_save_audit, scene=True, impact="info")

_add("broadcast_storm_audit", "Broadcast and multicast audit",
     "How much of the traffic is broadcast or multicast.  Group traffic wakes every "
     "sleeping station on the cell, so a high share is a battery and airtime problem "
     "that shows up nowhere in a device list.",
     "silent: reads the receiver address of stored data frames",
     _broadcast_storm_audit, scene=True, impact="info")

_add("gratuitous_arp_audit", "Gratuitous ARP audit",
     "ARP replies whose sender address equals the target address are what a poisoning "
     "tool sends: they update every cache on the segment at once.  Finding them in a "
     "capture is evidence of an ARP attack, not a theory about one.",
     "silent: parses the ARP payloads already in a capture", _gratuitous_arp_audit, scene=True,
     impact="info")

_add("arp_scan_detect", "ARP scan detection",
     "Sequential ARP requests for every address in a subnet are a host-discovery scan. "
     "This measures the density of each requester's targets and names the ones sweeping.",
     "silent: tracks ARP request targets per client", _arp_scan_detect, scene=True,
     impact="info")

_add("dhcp_fingerprint_audit", "DHCP fingerprint audit",
     "The DHCP option set is a fingerprint: vendor class, hostname and requested "
     "addresses identify the operating system behind each station, and the requested "
     "address leaks a static assignment.",
     "silent: parses DHCP options out of stored frames", _dhcp_fingerprint_audit, scene=True)

_add("duplicate_seq_audit", "Duplicate sequence number audit",
     "The same sequence number from the same transmitter is either a retransmission or "
     "a replay.  Counting them per transmitter finds the recording being played back "
     "and the device with a broken sequence counter.",
     "silent: tracks (transmitter, sequence) pairs in a capture",
     _duplicate_seq_audit, scene=True, impact="info")

_add("deauth_storm_detect", "Deauthentication storm detection",
     "A burst of deauthentication frames is a flood, not clients leaving.  This finds "
     "the bursts in a capture and separates broadcast from directed frames, which is "
     "the difference between a targeted and a blanket attack.",
     "silent: counts deauthentication frames per second in a capture",
     _deauth_storm_detect, scene=True, impact="info")

_add("auth_flood_detect", "Authentication flood detection",
     "Stations that authenticate five or more times and never associate are a flood: a "
     "real client authenticates and then associates.  The signature is in the capture "
     "if the flood has already been run.",
     "silent: cross-references authentication and association frames per station",
     _auth_flood_detect, scene=True, impact="info")

_add("probe_flood_detect", "Probe request flood detection",
     "Probe requests at a rate no human produces, with generated-looking 28-character "
     "names, are a flood or a fuzzer.  Counting them per transmitter finds the source.",
     "silent: counts probe requests per station and their name lengths",
     _probe_flood_detect, scene=True, impact="info")

_add("pcap_report", "Capture report (JSON artifact)",
     "Write everything this capture holds into one JSON artifact — frame counts, "
     "networks, handshakes, PMKIDs, key descriptor versions — with the file's SHA-256, "
     "so the report travels with the capture it describes.",
     "silent: writes a file; nothing is transmitted", _pcap_report, scene=True, impact="loot")

_add("capture_coverage", "Capture coverage audit",
     "Which discovered targets have a capture at all, and what each capture holds.  A "
     "run that found twelve networks and captured two of them is a coverage problem "
     "worth seeing before the report is written.",
     "silent: cross-references the session's discovery and capture state",
     _capture_coverage, scene=True, impact="info")

_add("beacon_rate_histogram", "Beacon rate audit",
     "Beacons per second per BSSID.  A station repeating a beacon faster than the "
     "network's own interval is a clone on air, and an AP whose rate is wildly high has "
     "a broken driver.",
     "silent: measures beacon spacing in a capture", _beacon_rate_histogram, scene=True,
     impact="info")

_add("auth_algorithm_inventory", "Authentication algorithm inventory",
     "Shared-key authentication is WEP's challenge/response handshake: an AP that still "
     "offers it is a downgrade target and a sign of hardware nobody has replaced.  This "
     "finds every network in the capture that uses it.",
     "silent: reads the algorithm number of stored authentication frames",
     _auth_algorithm_inventory, scene=True, impact="info")

_add("station_inventory", "Station inventory",
     "Every station address in the capture with the BSSIDs it was seen on.  A station "
     "appearing on several BSSIDs is a roaming device — or a spoofed address, and the "
     "difference matters.",
     "silent: builds a per-address map from stored frames", _station_inventory, scene=True)

_add("quality_histogram", "Frame size histogram",
     "The distribution of frame sizes: management frames cluster at the bottom, bulk "
     "data at the top.  It is the fastest way to tell a capture of a busy network from "
     "a capture of beacons.",
     "silent: measures every frame in a capture", _quality_histogram, scene=True)

_add("vendor_ie_inventory", "Vendor element inventory",
     "Vendor-specific information elements, grouped by OUI: the fingerprints vendors "
     "stamp into their beacons.  They identify hardware that does not answer SNMP, and "
     "some of them carry version numbers.",
     "silent: reads element 221 out of stored beacons", _vendor_ie_inventory, scene=True)

_add("hidden_ap_audit", "Hidden network audit",
     "Hidden networks still answer probe responses, and their clients give the name "
     "away in association requests.  This finds the hidden networks in a capture and "
     "reports which name leaked.",
     "silent: correlates beacons without an SSID with association requests",
     _hidden_ap_audit, scene=True, impact="info")

#: every attack this module contributes, in the order it is documented
ATTACKS: List[type] = [cls for _name, _meta, cls in REGISTRY]
NAMES: List[str] = [name for name, _meta, _cls in REGISTRY]
META: Dict[str, Dict[str, str]] = {name: meta for name, meta, _cls in REGISTRY}

__all__ = [cls.__name__ for cls in ATTACKS] + ["ATTACKS", "META", "NAMES", "REGISTRY"]
