"""The element-level wave: what a beacon actually says, element by element.

Every attack here reads a capture — no radio, no authorisation, no frame — and every
one of them asks a question a report has to answer: *does this network do 802.11k/v/r,
is it a hotspot, what does its WMM configuration say about voice, is its regulatory
domain set, does the same SSID appear twice with different security, which access point
is actually carrying traffic, and what is the EAPOL exchange doing?*

The difference between this module and ``offline3`` is the unit of work.  ``offline3``
counts frames — retries, fragments, storms, duplicates.  This one parses the
**information elements** themselves: the neighbour report an AP hands out, the mobility
domain it roams in, the interworking element that claims it is a public hotspot, the BSS
load it reports, the WMM parameters it runs, the WPS configuration methods it exposes,
and the EAPOL key information flags it negotiates.  All of it is bytes the AP put on the
air in the clear, so none of it costs a frame to learn.

Two real bugs were fixed on the way in, and they are worth naming because they are the
reason the audits exist:

* the mobility domain was read from tag 52 (which is the *neighbour report* element) when
  the standard puts it at 54, so every 802.11r finding was really a neighbour report;
* extended capabilities were read from tag 93 (a vendor element) instead of 127, so
  "this network does 802.11v" was being decided by the wrong bits of a different element.

Building the audits is how those two came to light: an audit that reads an element has
to be told which tag it lives at, and the pair could not both be right.
"""

from __future__ import annotations

import os
import time
from collections import Counter, defaultdict
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..models import AccessPoint
from .base import AttackContext, AttackOutcome, Attempt
from .forensics import OfflineAttack
from .frames import parse_80211
from .offline3 import (_Audit, _EapolFacts, _frames, _parsed, _security_of, _text,
                       frame_body)

from .. import ies as ie_module

__all__ = ["ATTACKS", "META", "NAMES", "REGISTRY"]

#: the wireless-management features an element can advertise, and why it matters
MANAGEMENT_FEATURES = {
    "bss_transition": "802.11v BSS transition: a client can be *told* which AP to join",
    "wnm_sleep": "802.11v WNM sleep: a station can be asked to sleep, then woken by the AP",
    "coexistence": "20/40 BSS coexistence management, which only matters on 2.4GHz",
    "channel_switch": "extended channel switching: the AP can be asked to move channel",
}

#: SSID names that ship in firmware and are never changed — the first guess in any
#: assessment, and a finding in their own right because they identify the hardware
DEFAULT_SSID_PATTERNS = ("fritz!box", "speedport", "tp-link", "tplink", "netgear", "dlink",
                         "d-link", "linksys", "archer", "technicolor", "vodafone", "orange",
                         "sbb", "swisscom", "kabelbox", "unitymedia", "belkin", "asus",
                         "ubiquiti", "mikrotik", "setup", "default", "hidden")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _elements(info: Dict[str, Any]) -> List[Tuple[int, bytes]]:
    """``(tag, value)`` for every element in a management frame's element area."""
    body = frame_body(info, 36)
    out: List[Tuple[int, bytes]] = []
    offset = 0
    while offset + 2 <= len(body):
        tag, length = body[offset], body[offset + 1]
        if offset + 2 + length > len(body):
            break                                   # the frame was cut: stop, do not guess
        out.append((tag, body[offset + 2:offset + 2 + length]))
        offset += 2 + length
    return out


def _beacon_facts(path: str, limit: int = 60_000) -> Dict[str, Dict[str, Any]]:
    """``{bssid: {...}}`` for every beacon or probe response in the capture.

    One decode per BSSID is enough for element work — the second beacon of a network
    says the same thing — so this keeps the *last* element set seen and counts the
    frames, which is what the audits below need and nothing they do not.
    """
    out: Dict[str, Dict[str, Any]] = {}
    for _stamp, info in _parsed(path, limit):
        if info.get("kind") not in ("beacon", "probe response"):
            continue
        bssid = _text(info.get("bssid"))
        if not bssid or bssid == "ff:ff:ff:ff:ff:ff":
            continue
        entry = out.setdefault(bssid, {"bssid": bssid, "frames": 0, "facts": {},
                                       "essential": {}, "ssid": ""})
        entry["frames"] += 1
        elements = _elements(info)
        if not elements:
            continue
        decoded = ie_module.decode_ies(ie_module.parse_ies(
            b"".join(bytes([tag, len(value)]) + value for tag, value in elements)))
        entry["facts"] = decoded
        entry["essential"] = {tag: value for tag, value in elements
                              if tag in (0, 3, 7, 11, 45, 48, 54, 52, 70, 107, 127, 191, 255)}
        entry["ssid"] = _text(decoded.get("ssid")) or entry["ssid"]
    return out


def _ssid_of(entry: Dict[str, Any]) -> str:
    return _text(entry.get("ssid")) or (entry.get("facts") or {}).get("ssid") or "(hidden)"


def _element_table(path: str, tag: int) -> Dict[str, bytes]:
    """``{bssid: element value}`` for one element tag across the capture."""
    out: Dict[str, bytes] = {}
    for bssid, entry in _beacon_facts(path).items():
        value = (entry.get("essential") or {}).get(tag)
        if value is not None:
            out[bssid] = value
    return out


def _row(name: str, label: str, description: str, detection: str,
         run: Callable[[_Audit, AttackContext, AccessPoint], AttackOutcome], *,
         cls_name: str = "", impact: str = "info", noise: str = "silent",
         category: str = "offline", scene: bool = True,
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
# 1-10: what the beacons advertise
# --------------------------------------------------------------------------- #

def _extended_capability_audit(self: _Audit, ctx: AttackContext,
                               ap: AccessPoint) -> AttackOutcome:
    """Extended capabilities: which wireless-management features an AP will act on."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    facts = _beacon_facts(path)
    rows = []
    for bssid, entry in facts.items():
        bits = (entry.get("facts") or {}).get("extended_bits") or {}
        if not bits:
            continue
        rows.append({"bssid": bssid, "ssid": _ssid_of(entry),
                     "features": [name for name, on in bits.items() if on],
                     "raw": (entry.get("facts") or {}).get("extended_capabilities")})
    interesting = [row for row in rows if row["features"]]
    detail = (f"{len(rows)} AP(s) publish an extended capabilities element; "
              + (f"{len(interesting)} name a management feature: "
                 + "; ".join(f"{row['bssid']} {', '.join(row['features'])}"
                             for row in interesting[:4])
                 if interesting else "none of them advertises BSS transition, WNM sleep "
                 "or coexistence management, so a client here cannot be moved or woken "
                 "by the network"))
    return self._report(ctx, ap, attempt,
                        f"extended capabilities: {len(interesting)} AP(s) with features",
                        detail, {"networks": rows[:30], "capture": path},
                        severity="info")

def _rrm_measurement_audit(self: _Audit, ctx: AttackContext,
                           ap: AccessPoint) -> AttackOutcome:
    """802.11k: which APs will measure the air for whoever asks.

    A radio measurement request is issued by *any* associated client, and the answer
    (a beacon report) lists every BSSID the AP can hear, with signal levels — which is
    a location fingerprint of the site, handed out on request.  This reads the
    capability element that says whether the AP would answer at all.
    """
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    rows = []
    for bssid, entry in _beacon_facts(path).items():
        rm = (entry.get("facts") or {}).get("rm_enabled")
        if not rm:
            continue
        rows.append({"bssid": bssid, "ssid": _ssid_of(entry), "capabilities": rm})
    answering = [row for row in rows if row["capabilities"].get("beacon_active")
                 or row["capabilities"].get("beacon_passive")]
    detail = (f"{len(rows)} AP(s) advertise 802.11k RM capabilities; "
              + (f"{len(answering)} would accept an active or passive beacon report "
                 f"request, which returns every BSSID the AP can hear: "
                 + ", ".join(row["bssid"] for row in answering[:5])
                 if answering else "none advertises a beam-report capability, so a "
                 "measurement request would be refused"))
    return self._report(ctx, ap, attempt,
                        f"802.11k measurement: {len(answering)} AP(s) would answer",
                        detail, {"networks": rows[:30], "capture": path},
                        severity="info")

def _neighbour_report_audit(self: _Audit, ctx: AttackContext,
                            ap: AccessPoint) -> AttackOutcome:
    """The neighbour report an AP carries: the BSSIDs around it, unprompted."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    rows = []
    seen = set()
    for bssid, entry in _beacon_facts(path).items():
        for item in (entry.get("facts") or {}).get("neighbour_report") or []:
            rows.append({"from": bssid, "bssid": item.get("bssid"),
                         "channel": item.get("channel"),
                         "operating_class": item.get("operating_class")})
            seen.add(item.get("bssid"))
    detail = (f"{len(rows)} neighbour report entr(y|ies) from {len({row['from'] for row in rows})}"
              f" AP(s), naming {len(seen)} other BSSID(s)"
              + ("; an AP that hands out its neighbours on the air has published the "
                 "rest of the site's layout for anyone listening"
                 if rows else "; no AP in this capture publishes a neighbour report"))
    return self._report(ctx, ap, attempt,
                        f"neighbour reports: {len(rows)} entr(y|ies)", detail,
                        {"reports": rows[:40], "capture": path},
                        severity="medium" if rows else "info")

def _ft_mobility_audit(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """802.11r fast transition: mobility domain, and whether it is over the DS."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    rows = []
    for bssid, entry in _beacon_facts(path).items():
        facts = entry.get("facts") or {}
        if not facts.get("mobility_domain"):
            continue
        rows.append({"bssid": bssid, "ssid": _ssid_of(entry),
                     "mobility_domain": facts.get("mobility_domain"),
                     "ft_over_ds": bool(facts.get("ft_over_ds")),
                     "akm": (facts.get("rsn") or {}).get("akm") or []})
    domains = Counter(row["mobility_domain"] for row in rows)
    over_ds = [row for row in rows if row["ft_over_ds"]]
    detail = (f"{len(rows)} AP(s) in fast transition mode across "
              f"{len(domains)} mobility domain(s) "
              + (", ".join(f"{domain} x{count}" for domain, count in domains.items())
                 or "none")
              + (f"; {len(over_ds)} accept FT over the distribution system, where a "
                 f"roaming client's PMK-R0 is reused across the whole domain"
                 if over_ds else "; all of them keep fast transition inside one AP"))
    return self._report(ctx, ap, attempt,
                        f"fast transition: {len(rows)} AP(s), {len(domains)} domain(s)",
                        detail, {"networks": rows[:30], "capture": path},
                        severity="info")

def _bss_load_audit(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """BSS Load: what each AP says about its own load, in its own words."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    rows = []
    for bssid, entry in _beacon_facts(path).items():
        load = (entry.get("facts") or {}).get("bss_load")
        if not load:
            continue
        rows.append({"bssid": bssid, "ssid": _ssid_of(entry),
                     "stations": load.get("stations"),
                     "utilisation_percent": load.get("utilisation_percent"),
                     "available_admission": load.get("available_admission")})
    busy = [row for row in rows if (row["utilisation_percent"] or 0) >= 50]
    busiest = max(rows, key=lambda row: row["utilisation_percent"] or 0, default=None)
    detail = (f"{len(rows)} AP(s) publish a BSS load element"
              + (f"; busiest is {busiest['bssid']} at {busiest['utilisation_percent']}% "
                 f"of the channel with {busiest['stations']} stations" if busiest else "")
              + (f"; {len(busy)} above half utilisation, so those cells are the ones "
                 f"where a deauth or a flood will be noticed first" if busy else ""))
    return self._report(ctx, ap, attempt,
                        f"BSS load: {len(busy)} busy cell(s)", detail,
                        {"networks": rows[:30], "capture": path},
                        severity="medium" if busy else "info")

def _interworking_audit(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """The Interworking element: is this AP claiming to be a public network?"""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    types = {0: "private", 1: "private with guest access", 2: "chargeable public",
             3: "free public", 4: "personal device", 5: "emergency services only",
             6: "test", 7: "wildcard", 14: "personal device"}
    rows = []
    for bssid, entry in _beacon_facts(path).items():
        interworking = (entry.get("facts") or {}).get("interworking")
        if not interworking:
            continue
        rows.append({"bssid": bssid, "ssid": _ssid_of(entry),
                     "network_type": interworking.get("network_type"),
                     "network_type_text": types.get(interworking.get("network_type"),
                                                    "reserved"),
                     "internet": bool(interworking.get("internet")),
                     "venue_group": interworking.get("venue_group")})
    public = [row for row in rows if row["network_type"] in (2, 3)]
    detail = (f"{len(rows)} AP(s) carry an interworking element; "
              + (f"{len(public)} advertise a public network type ("
                 + ", ".join(f"{row['ssid']} = {row['network_type_text']}"
                             for row in public[:5])
                 + "), which means a captive portal and a client population that will "
                   "associate with anything that looks like the portal"
                 if public else "none of them advertises a public network type"))
    return self._report(ctx, ap, attempt,
                        f"interworking: {len(public)} public network(s)", detail,
                        {"networks": rows[:30], "capture": path},
                        severity="medium" if public else "info")

def _hs20_audit(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """Hotspot 2.0 (Passpoint): release number, ANQP domain, and what it implies."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    rows = []
    for bssid, entry in _beacon_facts(path).items():
        hs20 = (entry.get("facts") or {}).get("hs20")
        if not hs20:
            continue
        rows.append({"bssid": bssid, "ssid": _ssid_of(entry), **hs20})
    releases = Counter(row.get("release") for row in rows)
    detail = (f"{len(rows)} Hotspot 2.0 network(s)"
              + (f", releases " + ", ".join(f"{release} x{count}"
                                            for release, count in releases.items())
                 if rows else "")
              + ("; a Passpoint network answers ANQP queries before association — the "
                 "operator name, the venue, the roaming partners and the realms — so "
                 "its policy is readable without joining it" if rows else
                 "; nothing in this capture advertises Passpoint"))
    return self._report(ctx, ap, attempt,
                        f"hotspot 2.0: {len(rows)} network(s)", detail,
                        {"networks": rows[:30], "capture": path}, severity="info")

def _wmm_parameter_audit(self: _Audit, ctx: AttackContext,
                         ap: AccessPoint) -> AttackOutcome:
    """WMM EDCA parameters, including whether a category needs admission control."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    rows = []
    for bssid, entry in _beacon_facts(path).items():
        facts = entry.get("facts") or {}
        parameters = facts.get("wmm_parameters")
        if facts.get("wmm") and not parameters:
            rows.append({"bssid": bssid, "ssid": _ssid_of(entry), "ac": {},
                         "note": "WMM enabled, no parameter element (WMM is the default)"})
            continue
        if not parameters:
            continue
        rows.append({"bssid": bssid, "ssid": _ssid_of(entry),
                     "ac": parameters.get("ac") or {}})
    with_acm = [row for row in rows
                if any(record.get("acm") for record in (row.get("ac") or {}).values())]
    voice = [row for row in rows if (row.get("ac") or {}).get("voice")]
    detail = (f"{len(rows)} AP(s) with WMM enabled, {len(voice)} publishing EDCA "
              f"parameters"
              + (f"; {len(with_acm)} require admission control for a traffic category, "
                 f"which is voice-grade configuration and means a flood on those cells "
                 f"is felt by callers, not just by file transfers"
                 if with_acm else "; none requires admission control"))
    return self._report(ctx, ap, attempt,
                        f"WMM: {len(with_acm)} AP(s) with admission control", detail,
                        {"networks": rows[:30], "capture": path}, severity="info")

def _wps_config_audit(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """WPS configuration methods and device password ID: how the PIN can be reached."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    rows = []
    for bssid, entry in _beacon_facts(path).items():
        wps = (entry.get("facts") or {}).get("wps") or {}
        if not wps.get("present"):
            continue
        rows.append({"bssid": bssid, "ssid": _ssid_of(entry),
                     "methods": wps.get("methods") or [],
                     "version": wps.get("version"), "locked": bool(wps.get("locked")),
                     "model": wps.get("model"), "device_name": wps.get("device_name")})
    pin_first = [row for row in rows
                 if any("keypad" in str(method).lower() or "display" in str(method).lower()
                        for method in row["methods"])]
    detail = (f"{len(rows)} AP(s) advertise WPS; "
              + (f"{len(pin_first)} offer a keypad or display method, which is the PIN "
                 f"path: " + ", ".join(f"{row['ssid']} ({', '.join(row['methods'])})"
                                       for row in pin_first[:5])
                 if pin_first else "none of them offers a PIN-based method, so the "
                 "Pixie-Dust and PIN attacks have nothing to talk to"))
    return self._report(ctx, ap, attempt,
                        f"WPS configuration: {len(pin_first)} PIN-capable AP(s)", detail,
                        {"networks": rows[:30], "capture": path},
                        severity="medium" if pin_first else "info")

def _country_power_audit(self: _Audit, ctx: AttackContext,
                         ap: AccessPoint) -> AttackOutcome:
    """The country element: regulatory domain and the power limit it claims."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    rows = []
    for bssid, entry in _beacon_facts(path).items():
        value = (entry.get("essential") or {}).get(7)
        if not value or len(value) < 3:
            continue
        code = value[:2].decode("ascii", "replace")
        # after the two-letter code (and the optional third byte) come the
        # (first channel, channel count, max power) triplets
        triplets = []
        cursor = 3 if len(value) >= 6 and len(value) % 3 else 2
        while cursor + 3 <= len(value):
            triplets.append({"first_channel": value[cursor],
                             "channels": value[cursor + 1],
                             "max_power_dbm": value[cursor + 2]})
            cursor += 3
        rows.append({"bssid": bssid, "ssid": _ssid_of(entry), "country": code,
                     "triplets": triplets[:8]})
    codes = Counter(row["country"] for row in rows)
    powers = [triplet["max_power_dbm"] for row in rows for triplet in row["triplets"]]
    odd = [row for row in rows if row["country"] in ("XX", "  ", "")]
    detail = (f"{len(rows)} of {len(_beacon_facts(path))} AP(s) publish a country "
              f"element"
              + (", domains: " + ", ".join(f"{code} x{count}"
                                           for code, count in codes.items()) if codes else "")
              + (f"; declared limits run {min(powers)}-{max(powers)} dBm" if powers else "")
              + (f"; {len(odd)} publish a placeholder domain, which is a configuration "
                 f"finding in a report about compliance" if odd else ""))
    return self._report(ctx, ap, attempt,
                        f"regulatory domains: {len(codes)}", detail,
                        {"networks": rows[:30], "capture": path}, severity="info")


# --------------------------------------------------------------------------- #
# 11-20: what the site looks like, and what the exchange does
# --------------------------------------------------------------------------- #

def _ssid_hygiene_audit(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """SSID hygiene: firmware default names, padding, control characters, BSSID-as-name."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    findings: List[Dict[str, Any]] = []
    for bssid, entry in _beacon_facts(path).items():
        value = (entry.get("essential") or {}).get(0)
        if value is None:
            continue
        name = value.decode("latin-1", "replace")
        problems = []
        if any(pattern in name.lower() for pattern in DEFAULT_SSID_PATTERNS):
            problems.append("firmware default name")
        if name != name.strip("\x00") or "\x00" in name:
            problems.append("NUL padding (a fixed-size SSID was copied wholesale)")
        if any(ord(character) < 32 or ord(character) == 127 for character in name):
            problems.append("control characters")
        if bssid.replace(":", "").lower() in name.lower():
            problems.append("the BSSID used as the network name")
        if not name:
            problems.append("a zero-length SSID element (hidden by construction)")
        if len(name) > 16:
            problems.append(f"{len(name)} characters, so clients show a truncated name")
        if problems:
            findings.append({"bssid": bssid, "ssid": name or "(empty)",
                             "problems": problems})
    detail = (f"{len(findings)} AP(s) with something wrong in the name itself"
              + (": " + "; ".join(f"{item['ssid']} — {', '.join(item['problems'])}"
                                  for item in findings[:4]) if findings else
                 " — every name here looks like somebody typed it on purpose"))
    return self._report(ctx, ap, attempt,
                        f"SSID hygiene: {len(findings)} finding(s)", detail,
                        {"findings": findings[:30], "capture": path},
                        severity="medium" if findings else "info")

def _security_mismatch_audit(self: _Audit, ctx: AttackContext,
                             ap: AccessPoint) -> AttackOutcome:
    """The same SSID advertised with different security: a downgrade waiting to happen.

    If two BSSIDs call themselves the same network and one of them is open, WEP or
    WPA2 while the other is WPA3, a client picks by signal, not by policy.  That is
    what an evil twin exploits, and it is visible in a passive capture.
    """
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    by_name: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for bssid, entry in _beacon_facts(path).items():
        facts = entry.get("facts") or {}
        if not (entry.get("essential") or {}).get(0):
            continue                                   # hidden: no name to collide with
        by_name[_ssid_of(entry)].append({
            "bssid": bssid,
            "security": _security_of(facts, entry),
            "pmf_required": bool(facts.get("pmf_required")),
            "ft": bool(facts.get("mobility_domain"))})
    mismatches = []
    for name, entries in by_name.items():
        securities = {entry["security"] for entry in entries}
        if len(entries) > 1 and len(securities) > 1:
            mismatches.append({"ssid": name, "bssids": entries,
                               "securities": sorted(securities)})
    detail = (f"{len(by_name)} named network(s); "
              + (f"{len(mismatches)} name(s) appear with more than one security setting: "
                 + "; ".join(f"{item['ssid']} = {'/'.join(item['securities'])}"
                             for item in mismatches[:5])
                 + " — a client chooses by signal, so the weakest of those wins"
                 if mismatches else "every name has one security setting across all of "
                 "its BSSIDs"))
    return self._report(ctx, ap, attempt,
                        f"security mismatches: {len(mismatches)}",
                        detail, {"mismatches": mismatches[:10], "capture": path},
                        severity="high" if mismatches else "info")

def _client_capability_audit(self: _Audit, ctx: AttackContext,
                             ap: AccessPoint) -> AttackOutcome:
    """What clients ask for when they associate: capabilities and rates per station."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    rows: Dict[str, Dict[str, Any]] = {}
    for _stamp, info in _parsed(path):
        if info.get("kind") not in ("association request", "reassociation request"):
            continue
        station = _text(info.get("station"))
        if not station:
            continue
        entry = rows.setdefault(station, {"station": station, "bssids": set(),
                                          "capability": int(info.get("capability", 0) or 0),
                                          "elements": [], "requests": 0})
        entry["bssids"].add(_text(info.get("bssid")))
        entry["requests"] += 1
        tags = [tag for tag, _value in _elements(info)]
        entry["elements"] = sorted(set(tags))
        entry["ht"] = 45 in tags
        entry["vht"] = 191 in tags
        entry["he"] = 255 in tags
        entry["power_save"] = bool(entry["capability"] & 0x0010)
        entry["privacy"] = bool(entry["capability"] & 0x0010)
    legacy = [row for row in rows.values() if not (row.get("ht") or row.get("vht")
                                                  or row.get("he"))]
    detail = (f"{len(rows)} station(s) associated in this capture; "
              + f"{len(legacy)} of them asked without a single 802.11n/ac/ax element "
              + ("(802.11g-era hardware still on the cell: it will not do WPA3, and it "
                 "may not do PMF)" if legacy else
                 "(every client here speaks at least 802.11n)"))
    return self._report(ctx, ap, attempt,
                        f"client capabilities: {len(legacy)} pre-11n station(s)", detail,
                        {"stations": [{**row, "bssids": sorted(row["bssids"])}
                                      for row in rows.values()][:40],
                         "capture": path},
                        severity="info")

def _frame_control_audit(self: _Audit, ctx: AttackContext,
                         ap: AccessPoint) -> AttackOutcome:
    """Frame control fields no compliant device sends: version, reserved bits, order."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    counters: Counter = Counter()
    examples: List[Dict[str, Any]] = []
    total = 0
    for _stamp, frame in _frames(path):
        if len(frame) < 24:
            continue
        total += 1
        control = int.from_bytes(frame[:2], "little")
        version = control & 0x0003
        # bit 2 of the second byte is the "protected" flag and bit 3 "order"; the rest
        # of a subtype's own bits are not reserved, so only these two are checkable
        # across every frame type
        if version:
            counters["protocol version != 0"] += 1
            if len(examples) < 8:
                examples.append({"kind": "protocol version", "version": version})
        subtype = (control >> 4) & 0x0F
        ftype = (control >> 2) & 0x03
        if ftype == 0 and subtype == 4 and (control & 0x0100):
            counters["probe request with the protected bit"] += 1
    detail = (f"{total} frame(s) inspected; "
              + (", ".join(f"{reason} x{count}" for reason, count in counters.items())
                 if counters else "every frame control field is a version-0 value, which "
                 "is the only value that exists on air"))
    return self._report(ctx, ap, attempt,
                        f"frame control: {sum(counters.values())} oddit(y|ies)", detail,
                        {"counters": dict(counters), "examples": examples,
                         "frames": total, "capture": path},
                        severity="medium" if counters else "info")

def _airtime_estimate(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """Airtime per BSSID: frame length is time, and time is the shared resource.

    Airtime is what a wireless cell actually runs out of.  Counting *frames* per AP
    ranks the chatty one first; weighting each frame by its length, plus the 802.11
    overhead every frame pays, ranks the one that is really eating the channel.
    """
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    airtime: Dict[str, float] = defaultdict(float)
    counts: Counter = Counter()
    for _stamp, info in _parsed(path):
        bssid = _text(info.get("bssid"))
        if not bssid or bssid == "ff:ff:ff:ff:ff:ff":
            continue
        length = int(info.get("length", 0) or 0)
        # every frame pays a preamble and a header; at the lowest rate these dominate,
        # which is why airtime is not proportional to bytes
        micros = 20 + 4 * ((length + 4) // 4)         # 20µs overhead + 4µs per 4 bytes
        airtime[bssid] += micros
        counts[bssid] += 1
    rows = sorted(({"bssid": bssid, "frames": counts[bssid],
                    "airtime_us": round(value, 1),
                    "airtime_percent": round(value / max(sum(airtime.values()), 1) * 100, 1)}
                   for bssid, value in airtime.items()),
                  key=lambda row: row["airtime_us"], reverse=True)
    chatty = rows[0] if rows else None
    detail = (f"{len(rows)} BSSID(s) accounted for {round(sum(airtime.values()) / 1000, 1)}"
              f" ms of airtime; "
              + (f"{chatty['bssid']} takes {chatty['airtime_percent']}% of it with "
                 f"{chatty['frames']} frame(s): that is the cell where a single "
                 f"injection will be heard by everyone" if chatty else "no traffic"))
    return self._report(ctx, ap, attempt,
                        f"airtime: busiest AP takes "
                        f"{chatty['airtime_percent'] if chatty else 0}%", detail,
                        {"bssids": rows[:20], "capture": path}, severity="info")

def _probe_response_latency_audit(self: _Audit, ctx: AttackContext,
                                  ap: AccessPoint) -> AttackOutcome:
    """Probe request → probe response latency, per client.

    An AP answers a probe in microseconds.  A *lure* answers everything it hears, often
    before the real AP does, and sometimes with a delay that no hardware would have:
    this measures the gap between each probe and the first answer addressed to that
    station, which is a cheap way to spot a responder that is not an AP.
    """
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    pending: Dict[str, float] = {}
    latencies: Dict[str, List[float]] = defaultdict(list)
    names: Dict[str, str] = {}
    answered_broadcast = 0
    for stamp, info in _parsed(path):
        if info.get("kind") == "probe request":
            station = _text(info.get("addr2"))
            if station:
                pending[station] = stamp
                names.setdefault(station, _text(info.get("essid")))
            continue
        if info.get("kind") != "probe response":
            continue
        # a probe *response* is addressed to the station that asked (addr1); an answer
        # sent to the broadcast address cannot be a reply to anybody in particular
        target = _text(info.get("addr1"))
        if target == "ff:ff:ff:ff:ff:ff":
            answered_broadcast += 1
            continue
        if target in pending:
            latencies[target].append((stamp - pending.pop(target)) * 1000)
    rows = []
    for station, values in latencies.items():
        rows.append({"station": station, "answers": len(values),
                     "mean_ms": round(sum(values) / len(values), 3),
                     "max_ms": round(max(values), 3),
                     "asked_for": names.get(station) or "(anything)"})
    rows.sort(key=lambda row: row["mean_ms"], reverse=True)
    slow = [row for row in rows if row["mean_ms"] > 20]
    detail = (f"{len(rows)} station(s) probed and were answered; mean latency "
              + (f"{round(sum(row['mean_ms'] for row in rows) / len(rows), 3)} ms; "
                 f"{len(slow)} slower than 20 ms, which on a quiet channel is a "
                 f"responder with something between it and the radio"
                 if rows else "could not be measured: no probe was answered")
              + (f"; {answered_broadcast} probe response(s) went to the broadcast "
                 f"address, which is a responder answering nobody in particular (the "
                 f"KARMA pattern)" if answered_broadcast else ""))
    return self._report(ctx, ap, attempt,
                        f"probe answers: {len(rows)} client(s), {len(slow)} slow", detail,
                        {"stations": rows[:30], "capture": path}, severity="info")

def _eapol_key_flags_audit(self: _Audit, ctx: AttackContext,
                           ap: AccessPoint) -> AttackOutcome:
    """The key information flags of every EAPOL key message in the capture."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    facts = _EapolFacts(path)
    if not facts.messages:
        return self._report(ctx, ap, attempt, "no EAPOL key messages to read",
                            f"{os.path.basename(path)}: the capture holds no four-way "
                            f"handshake frames", {"capture": path})
    flags = Counter()
    per_message: Dict[str, Dict[str, bool]] = {}
    anomalies = []
    for message in facts.messages:
        info = int(getattr(message, "key_info", 0) or 0)
        number = int(getattr(message, "number", 0) or 0)
        parsed = dict(getattr(message, "flags", {}) or {})
        bits = {"install": bool(parsed.get("install", info & 0x0040)),
                "ack": bool(parsed.get("ack", info & 0x0080)),
                "mic": bool(parsed.get("mic", info & 0x0100)),
                "secure": bool(parsed.get("secure", info & 0x0200)),
                "error": bool(parsed.get("error", info & 0x0400)),
                "request": bool(info & 0x0800),
                "encrypted_key_data": bool(parsed.get("encrypted", info & 0x1000))}
        for name, on in bits.items():
            if on:
                flags[name] += 1
        per_message[f"m{number or message.number if False else number}"] = bits
        # the expected shape per message number, from the standard
        if number == 1 and (bits["install"] or bits["mic"]):
            anomalies.append(f"message 1 with install/mic set")
        if number == 2 and (bits["install"] or bits["ack"]):
            anomalies.append(f"message 2 with install/ack set")
        if number == 3 and not bits["install"]:
            anomalies.append(f"message 3 without the install bit")
        if number == 4 and bits["install"]:
            anomalies.append(f"message 4 with the install bit")
    detail = (f"{len(facts.messages)} key message(s): "
              + ", ".join(f"{name} x{count}" for name, count in flags.most_common())
              + (f"; {len(anomalies)} message(s) carry flags their message number should "
                 f"not have ({'; '.join(sorted(set(anomalies))[:3])}) — a forger that got "
                 f"the flags wrong, or a stack with a bug worth a CVE"
                 if anomalies else "; every message carries exactly the flags its number "
                 "is supposed to"))
    return self._report(ctx, ap, attempt,
                        f"EAPOL key flags: {len(set(anomalies))} anomaly type(s)", detail,
                        {"flags": dict(flags), "messages": per_message,
                         "anomalies": sorted(set(anomalies)), "capture": path},
                        severity="medium" if anomalies else "info")

def _group_rekey_audit(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """Group key handshakes: the rekeying that protects broadcast traffic.

    Message 1 with key data carrying a GTK is the AP rekeying the group; the key index
    it installs is the evidence.  A network that rekeys rarely exposes the same group
    key to every station for as long as it takes somebody to notice.
    """
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    facts = _EapolFacts(path)
    if not facts.messages:
        return self._report(ctx, ap, attempt, "no group key exchange in the capture",
                            f"{os.path.basename(path)}: no EAPOL key frames to read",
                            {"capture": path})
    versions: Counter = Counter()
    lengths: Counter = Counter()
    rekeys: List[Dict[str, Any]] = []
    for message in facts.messages:
        versions[int(getattr(message, "key_version", 0) or 0)] += 1
        lengths[int(getattr(message, "key_len", 0) or 0)] += 1
        if getattr(message, "has_kde", False) or getattr(message, "pmkid", ""):
            # message 1 with key data is the AP rotating the group key; the PMKID KDE
            # is the same frame doing double duty as a client-less crack target
            rekeys.append({"number": int(getattr(message, "number", 0) or 0),
                           "key_version": int(getattr(message, "key_version", 0) or 0),
                           "key_len": int(getattr(message, "key_len", 0) or 0),
                           "pmkid": getattr(message, "pmkid", ""),
                           "encrypted": bool(getattr(message, "encrypted", False))})
    detail = (f"{len(facts.messages)} key message(s), key descriptor version(s) "
              + ", ".join(f"{version} x{count}" for version, count in versions.items())
              + "; key lengths "
              + ", ".join(f"{length * 8}-bit x{count}" for length, count in lengths.items())
              + (f"; {len(rekeys)} carry key data (a group rekey, or a PMKID the AP "
                 f"handed out with the first message)" if rekeys else
                 "; none carries key data, so no rekey is captured"))
    return self._report(ctx, ap, attempt,
                        f"group key: {len(rekeys)} key-data message(s)", detail,
                        {"versions": dict(versions), "lengths": dict(lengths),
                         "rekeys": rekeys[:10], "capture": path}, severity="info")

def _eapol_timing_audit(self: _Audit, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
    """The timings inside the four-way handshake, message by message."""
    attempt = self._attempt(ctx, ap)
    path = self.capture(ctx, ap)
    if not path:
        return self._need_capture(ctx, ap, attempt)
    facts = _EapolFacts(path)
    stamps: Dict[int, float] = {}
    for message in facts.messages:
        number = int(getattr(message, "number", 0) or 0)
        moment = float(getattr(message, "frame_time", 0) or 0)
        if number and moment and number not in stamps:
            stamps[number] = moment
    if len(stamps) < 2:
        return self._report(ctx, ap, attempt, "no handshake timing to measure",
                            f"{os.path.basename(path)}: fewer than two EAPOL messages",
                            {"capture": path})
    pairs = []
    for first, second in ((1, 2), (2, 3), (3, 4)):
        if first in stamps and second in stamps and stamps[second] >= stamps[first]:
            pairs.append({"pair": f"m{first}→m{second}",
                          "milliseconds": round((stamps[second] - stamps[first]) * 1000, 3)})
    slow = [pair for pair in pairs if pair["milliseconds"] > 100]
    detail = (f"{len(pairs)} message pair(s) measured: "
              + ", ".join(f"{pair['pair']} {pair['milliseconds']} ms" for pair in pairs)
              + (f"; {len(slow)} above 100 ms, which is the client taking its time — the "
                 f"AP has already sent the ANonce, so a slow client is a client that "
                 f"will be retransmitted to" if slow else
                 "; every gap is what a quiet cell looks like"))
    return self._report(ctx, ap, attempt,
                        f"handshake timing: {len(slow)} slow pair(s)", detail,
                        {"pairs": pairs, "capture": path}, severity="info")



# --------------------------------------------------------------------------- #
# the table
# --------------------------------------------------------------------------- #

_add("extended_capability_audit", "Extended capabilities audit",
     "Which wireless-management features each AP says it will act on: 802.11v BSS "
     "transition (a client can be told where to go), WNM sleep, 20/40 coexistence and "
     "extended channel switching.  The bits are numbered from the start of the element, "
     "so this reads tag 127 at bit 19 rather than trusting a byte offset.",
     "silent: decodes the extended capabilities element of stored beacons",
     _extended_capability_audit)

_add("rrm_measurement_audit", "802.11k measurement audit",
     "Radio measurement is how an AP says it will measure the air on request, and a "
     "beacon report handed to any associated client lists every BSSID the AP can hear "
     "with signal levels — a site survey and a location fingerprint, for the asking.",
     "silent: decodes the RM enabled capabilities element (tag 70)",
     _rrm_measurement_audit)

_add("neighbour_report_audit", "Neighbour report audit",
     "The neighbour report element lists the BSSIDs and channels an AP will hand a "
     "client to.  An AP that publishes one has documented the rest of the site on air, "
     "which is worth knowing before an assessment spends a day mapping it by hand.",
     "silent: decodes the neighbour report element (tag 52)",
     _neighbour_report_audit)

_add("ft_mobility_audit", "Fast transition (802.11r) audit",
     "Fast BSS transition networks carry a mobility domain identifier and a capability "
     "byte that says whether the AP will accept a transition over the distribution "
     "system.  FT over DS reuses the PMK-R0 across every AP in the domain, so the "
     "domain, not the AP, is the security boundary.",
     "silent: decodes the mobility domain element (tag 54)",
     _ft_mobility_audit, impact="info")

_add("bss_load_audit", "BSS load audit",
     "Every AP's own report of how busy it is: channel utilisation percentage, station "
     "count and available admission capacity.  It is the one measurement that says "
     "which cell is the real target rather than the loudest one.",
     "silent: decodes the BSS load element (tag 11)", _bss_load_audit, impact="info")

_add("interworking_audit", "Interworking element audit",
     "The interworking element says what kind of network an AP is claiming to be — "
     "private, free public, chargeable public, personal device.  A public network type "
     "means a captive portal, a client population that associates with anything that "
     "looks like it, and a legal structure that is not the site's own.",
     "silent: decodes the interworking element (tag 107)", _interworking_audit,
     impact="info")

_add("hs20_audit", "Hotspot 2.0 (Passpoint) audit",
     "Passpoint networks announce a release number and an ANQP domain before anybody "
     "associates, and then answer ANQP queries — operator, venue, roaming partners, "
     "realms — without a credential.  This inventories them and what they advertise.",
     "silent: decodes the Hotspot 2.0 vendor element (221/00:50:f2/0x11)", _hs20_audit,
     impact="info")

_add("wmm_parameter_audit", "WMM parameter audit",
     "The EDCA parameters behind the QoS promise, access category by access category, "
     "including the admission-control bit.  Voice-grade configuration is what makes a "
     "flood visible as dropped calls rather than as slow downloads.",
     "silent: decodes the WMM parameter element (221/00:50:f2/0x02)",
     _wmm_parameter_audit, impact="info")

_add("wps_config_audit", "WPS configuration method audit",
     "WPS configuration methods and the device password identifier decide which PIN "
     "path exists at all: keypad or display means a PIN, push button means a window, "
     "and a locked AP means neither until it unlocks.",
     "silent: decodes the WPS element's configuration methods",
     _wps_config_audit, impact="info")

_add("country_power_audit", "Regulatory domain audit",
     "The country element carries the regulatory domain and the maximum transmit power "
     "per channel.  Missing, placeholder or wrong domains are a compliance finding, and "
     "the power limits are the local rules an active test has to respect.",
     "silent: decodes the country element (tag 7)", _country_power_audit, impact="info")

_add("ssid_hygiene_audit", "SSID hygiene audit",
     "Firmware default names, NUL padding from a truncated copy, control characters, "
     "the BSSID used as the network name, names longer than a client will display: the "
     "problems that live in the SSID itself and show up in every screenshot of the "
     "site.",
     "silent: reads the SSID element of stored beacons", _ssid_hygiene_audit)

_add("security_mismatch_audit", "Security mismatch audit",
     "One network name, several BSSIDs, different security settings.  A client picks by "
     "signal, not by policy, so the weakest AP carrying the name is the one that wins — "
     "which is exactly what a twin relies on.",
     "silent: compares the RSN of every BSSID carrying the same SSID",
     _security_mismatch_audit, impact="info")

_add("client_capability_audit", "Client capability audit",
     "What each station asked for when it associated: HT/VHT/HE elements present, the "
     "capability flags, power management.  A cell with 802.11g-era clients on it will "
     "not do WPA3 and may not do PMF, whatever the AP is configured for.",
     "silent: reads association requests in a capture", _client_capability_audit,
     impact="info")

_add("frame_control_audit", "Frame control audit",
     "Protocol versions other than zero, protected bits on frames that cannot be "
     "protected, other values no compliant device puts on air: the fingerprints of a "
     "frame generator that got the header wrong, or of hardware with a bug.",
     "silent: reads the frame control field of every stored frame", _frame_control_audit)

_add("airtime_estimate", "Airtime estimate",
     "Airtime, not frame count, is what a wireless cell runs out of: each frame is "
     "weighted by its length plus the fixed overhead every transmission pays.  This "
     "ranks the access points by how much of the channel they actually consume.",
     "silent: measures every frame in a capture", _airtime_estimate, impact="info")

_add("probe_response_latency_audit", "Probe response latency audit",
     "The gap between a client's probe request and the answer it gets.  Real APs answer "
     "in microseconds; a responder that is slower than the channel can explain has "
     "something between it and the radio, which is how a lure gives itself away.",
     "silent: pairs probe requests with the responses to them",
     _probe_response_latency_audit, impact="info")

_add("eapol_key_flags_audit", "EAPOL key flag audit",
     "The key information flags of every key message, checked against what that message "
     "number is allowed to carry: an install bit on message 4 or a missing install on "
     "message 3 is either a forgery that got the flags wrong or a stack with a bug.",
     "silent: reads the key information field of stored EAPOL frames",
     _eapol_key_flags_audit)

_add("group_rekey_audit", "Group key rekey audit",
     "Message 1 carrying key data is the AP rekeying the group, and the key data "
     "encapsulations inside it say whether a GTK or an IGTK is being installed.  A "
     "network that never rekeys hands the same group key to everybody for as long as it "
     "takes somebody to notice.",
     "silent: reads key data out of stored EAPOL frames", _group_rekey_audit)

_add("eapol_timing_audit", "EAPOL timing audit",
     "The gaps inside a captured four-way handshake, message pair by message pair.  A "
     "client that takes a hundred milliseconds to answer a message 1 has already been "
     "sent the ANonce, so the handshake is waiting on the client, not on the AP.",
     "silent: times the EAPOL messages in a capture", _eapol_timing_audit, impact="info")

#: every attack this module contributes, in the order it is documented
ATTACKS: List[type] = [cls for _name, _meta, cls in REGISTRY]
NAMES: List[str] = [name for name, _meta, _cls in REGISTRY]
META: Dict[str, Dict[str, str]] = {name: meta for name, meta, _cls in REGISTRY}

__all__ = [cls.__name__ for cls in ATTACKS] + ["ATTACKS", "META", "NAMES", "REGISTRY"]
