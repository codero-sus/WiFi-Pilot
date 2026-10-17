# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Read-only intelligence about what the neighbourhood *says* about itself.

Two attacks, both of which transmit nothing and both of which change the plan:

* ``ie_audit`` decodes the information elements of every beacon-like frame —
  RSN, WPS, HT/VHT/HE, 802.11r/k/v, country, rates, BSS load — and reports the
  *configuration* findings a client report can act on.  It is the read-only half of
  every attack that follows: "this AP advertises TKIP and makes PMF optional" is the
  reason a handshake attack is worth running, and "this AP is 802.11b-era hardware"
  is the reason it is not.
* ``pnl_harvest`` reads the probe requests in a capture and builds the neighbourhood's
  *wanted list*: which networks the clients are asking for, and which of those are not
  on air at all.  Those names are what a twin or a Karma attack would answer, which is
  exactly why the finding matters — a client broadcasting its history in the clear is
  a privacy problem for the site and a target list for the attacker.

Neither needs authorisation: nothing is transmitted.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List

from ..ies import capture_beacons, ie_findings, vendor_breakdown
from ..models import STATUS_SUCCESS, AccessPoint, Capture
from ..sniff import probe_requests
from ..synth import (build_beacon, country_element, extended_capabilities,
                     ht_capabilities, mobility_domain, vht_capabilities, wps_element)
from .base import Attack, AttackContext, AttackOutcome
from .wpa3 import _add_finding_once


class IeAuditAttack(Attack):
    """Decode every beacon's information elements and report the configuration."""

    name = "ie_audit"
    label = "Configuration audit (beacon elements)"
    tool = "wifipilot ies.py (IE decoder)"
    description = ("Read the elements airodump-ng's CSV throws away: RSN, WPS, "
                   "HT/VHT/HE, 802.11r/k/v, country, rates, channel width and BSS "
                   "load.  The findings are configuration ones — TKIP still "
                   "advertised, PMF optional, WPS unlocked, 40 MHz in 2.4 GHz, no "
                   "country element — because those are the ones a report can act on.")
    requires = ("airodump",)
    needs_injection = False
    applies_to = ("WPA", "WPA2", "WPA2/WPA3", "WPA3", "WEP", "OPEN", "OWE",
                  "WPA-ENTERPRISE", "WPA2-ENTERPRISE", "ENTERPRISE")

    def applies(self, ap: AccessPoint) -> bool:
        return True

    def available(self, ctx: AttackContext) -> bool:
        return True                     # pure analysis of frames already on disk

    # ---------------------------------------------------------------- #
    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(
            self.name, ap.bssid, tool=self.tool,
            chosen_by=getattr(ap, "picked_by", "heuristic"),
            reason=getattr(ap, "pick_reason", ""),
        )
        path = self._capture_path(ctx, ap)
        source = "capture"
        if ctx.demo and not path:
            path = self._demo_capture(ctx, ap)
            source = "simulated"
        networks = capture_beacons(path).get("networks") if path else []
        if not networks:
            networks = self._from_session(ctx)
            source = "session"
        if not networks:
            return self._fail(ctx, attempt, "no beacons to read",
                              "no capture on this target and no neighbourhood state "
                              "to audit: run `passive` first, or point the audit at a "
                              "pcap with `wifipilot decode FILE`")

        findings = ie_findings(networks)
        raised = 0
        for finding in findings:
            if _add_finding_once(ctx, finding, finding["bssid"] or ap.bssid):
                raised += 1
        self._annotate(ctx, networks)

        interesting = [entry for entry in networks
                       if (entry.get("facts") or {}).get("wps")
                       or (entry.get("facts") or {}).get("wpa1")
                       or ((entry.get("facts") or {}).get("rsn") or {}).get("tkip")]
        detail = (f"{len(networks)} network(s) read from {source}: "
                  f"{len(findings)} configuration finding(s), {raised} new; "
                  f"{len(interesting)} with legacy crypto or WPS advertised")
        ap.remember("ie_audit", detail, networks=len(networks),
                    findings=[finding["kind"] for finding in findings])
        ap.pmf_checked = True
        if path and os.path.exists(path):
            # keep the file the findings came from: it is evidence, not loot, and a
            # later run (or the operator) can re-read it instead of capturing again
            ctx.session.add_artifact(Capture(
                kind=self.name, bssid=ap.bssid, essid=ap.essid, path=path,
                tool=self.tool, size=os.path.getsize(path),
                extra={"source": source, "networks": len(networks)}))
        ctx.session.stats.ie_audits += 1
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, "configuration audit complete",
                                detail)
        return AttackOutcome.success(
            "configuration audit complete", detail=detail,
            extra={"networks": networks, "findings": findings,
                   "new_findings": raised, "source": source, "capture": path,
                   "vendor_elements": vendor_breakdown(networks),
                   "note": ("decoded from the frames themselves: airodump's CSV has "
                            "no RSN capabilities, no WPS state and no HT/VHT "
                            "elements, which is where most configuration findings "
                            "live")})

    # ---------------------------------------------------------------- #
    @staticmethod
    def _capture_path(ctx: AttackContext, ap: AccessPoint) -> str:
        """The pcap to read, best first: this AP's own captures, then the newest of
        the session's.

        Newest first matters: the file another attack finished a moment ago is the
        one that reflects the neighbourhood as it is, not the one from an earlier
        window whose APs have since moved.
        """
        candidates = [cap for cap in ap.captures
                      if cap.path and os.path.exists(cap.path)]
        for capture in ctx.session.all_captures():
            if capture.path and os.path.exists(capture.path) and capture not in candidates:
                candidates.append(capture)
        if not candidates:
            return ""
        return max(candidates, key=lambda cap: cap.created).path

    def _from_session(self, ctx: AttackContext) -> List[Dict[str, Any]]:
        """Fall back to what the scanner already knows, flagged as such."""
        out = []
        for entry in ctx.session.aps.values():
            facts: Dict[str, Any] = {"ssid": entry.essid, "channel": entry.channel,
                                     "wps": {"present": True, "locked": None,
                                             "methods": []} if entry.wps else None,
                                     "rsn": None, "elements": [], "vendor_ouis": [],
                                     "roaming": {}, "ht": False, "vht": False}
            out.append({"bssid": entry.bssid, "essid": entry.essid,
                        "frames": entry.beacon_count, "hidden": entry.hidden,
                        "channel": entry.channel, "facts": facts,
                        "source": "scanner summary (no frames read)"})
        return out

    def _annotate(self, ctx: AttackContext, networks: List[Dict[str, Any]]) -> None:
        """Write the element-level facts back onto the session's targets."""
        for entry in networks:
            target = ctx.session.ap(entry.get("bssid") or "")
            if target is None:
                continue
            facts = entry.get("facts") or {}
            rsn = facts.get("rsn") or {}
            if facts.get("wps") and facts["wps"].get("present"):
                target.wps = True
                if facts["wps"].get("locked") is False:
                    target.wps_locked = "unlocked"
                elif facts["wps"].get("locked") is True:
                    target.wps_locked = "locked"
                if facts["wps"].get("version") and not target.wps_version:
                    target.wps_version = facts["wps"]["version"]
                if facts["wps"].get("model") and not target.wps_model:
                    target.wps_model = facts["wps"]["model"]
                if facts["wps"].get("manufacturer") and not target.wps_manufacturer:
                    target.wps_manufacturer = facts["wps"]["manufacturer"]
            if rsn:
                if rsn.get("mfpc"):
                    target.pmf = True
                if rsn.get("transition_mode"):
                    target.sai = True
                if "SAE" in (rsn.get("akm") or []):
                    target.sae = True

    # ---------------------------------------------------------------- #
    def _demo_capture(self, ctx: AttackContext, ap: AccessPoint) -> str:
        """Build the neighbourhood's beacons with the elements each AP would send."""
        from ..synth import write_pcap

        path = ctx.artifact_path("ieaudit", ap, ".pcap")
        frames = [self._demo_beacon(entry) for entry in ctx.session.aps.values()][:14]
        write_pcap(path, frames, spacing=0.005)
        return path

    @staticmethod
    def _demo_beacon(entry: AccessPoint) -> bytes:
        """One beacon whose elements match what the simulated AP is."""
        akm = "psk"
        if entry.sae:
            akm = "sae+psk" if (entry.sai or "WPA2" in (entry.encryption or "")) else "sae"
        elif "ENTERPRISE" in (entry.encryption or ""):
            akm = "802.1x"
        extra = b""
        modern = "WEP" not in (entry.encryption or "") and entry.vendor not in ("D-Link",)
        if modern:
            # 40 MHz in 2.4 GHz is what an AP that was never re-configured does; the
            # demo keeps it to the two default channels so the finding stays realistic
            wide = (entry.channel or 0) in (1, 6) and entry.vendor not in ("Cisco",)
            extra += ht_capabilities(width40=wide)
        if (entry.channel or 0) > 14:
            extra += vht_capabilities()
        if entry.wps:
            extra += wps_element(locked=(entry.wps_locked == "locked"),
                                 manufacturer=entry.wps_manufacturer,
                                 model=entry.wps_model, methods=0x0088)
        if "ENTERPRISE" in (entry.encryption or ""):
            # enterprise kit is where 802.11r shows up, usually without PMF
            extra += extended_capabilities() + mobility_domain()
        if entry.vendor not in ("Huawei", "unknown"):
            extra += country_element("IN")
        return build_beacon(entry.essid or "hidden", entry.bssid,
                            channel=entry.channel or 6, akm=akm, pmf=bool(entry.pmf),
                            extra_ies=extra)


class PnlHarvestAttack(Attack):
    """The neighbourhood's wanted list: what clients are asking for, and what is missing."""

    name = "pnl_harvest"
    label = "Probe harvest (preferred network lists)"
    tool = "wifipilot sniff.py (probe decoder)"
    description = ("Read every probe request in a capture: which station is asking for "
                   "which network, and which of those names are not on air at all.  "
                   "Those names are what a twin or a Karma attack answers, and a "
                   "client that broadcasts its history is a privacy finding.")
    requires = ("airodump",)
    needs_injection = False
    applies_to = ("WPA", "WPA2", "WPA2/WPA3", "WPA3", "WEP", "OPEN", "OWE",
                  "WPA-ENTERPRISE", "WPA2-ENTERPRISE", "ENTERPRISE")

    def applies(self, ap: AccessPoint) -> bool:
        return True

    def available(self, ctx: AttackContext) -> bool:
        return True                     # it only reads

    # ---------------------------------------------------------------- #
    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(
            self.name, ap.bssid, tool=self.tool,
            chosen_by=getattr(ap, "picked_by", "heuristic"),
            reason=getattr(ap, "pick_reason", ""),
        )
        path = self._capture_path(ctx, ap)
        simulated = False
        if ctx.demo and not path:
            path = self._demo_capture(ctx, ap)
            simulated = True
        clients = probe_requests(path) if path else {}
        if not clients:
            # the session's own scanner may have seen probes even without a pcap
            clients = self._from_session(ctx)
        if not clients:
            return self._fail(
                ctx, attempt, "no probe requests in range",
                "clients only leak their history when they are looking for a network: "
                "run this over a longer window, or on a capture from a busy site")

        on_air = {(entry.essid or "").lower() for entry in ctx.session.aps.values()
                  if entry.essid}
        wanted: Dict[str, List[str]] = {}
        for client in clients.values():
            for ssid in client.ssids:
                wanted.setdefault(ssid, []).append(client.mac)
        missing = {ssid: macs for ssid, macs in wanted.items()
                   if ssid.lower() not in on_air}
        hidden_aps = [entry for entry in ctx.session.aps.values()
                      if not (entry.essid or "").strip()]
        # a name clients ask for that nothing advertises is either a former network or
        # the name of a hidden AP on site — the second is how hidden_ssid works, and
        # both are worth writing down
        hidden_candidates = list(missing) if hidden_aps else []

        for ssid, macs in sorted(missing.items(), key=lambda item: -len(item[1]))[:5]:
            _add_finding_once(ctx, {
                "kind": "pnl_missing_network", "severity": "medium", "bssid": ap.bssid,
                "title": f"Clients are looking for {ssid!r}, which is not on air",
                "detail": (f"{len(macs)} station(s) ({', '.join(macs[:3])}) probe for "
                           f"{ssid!r} and no AP advertises it: the name is a candidate "
                           f"for a twin or a Karma attack, and the client is "
                           f"broadcasting its history in the clear.")},
                ap.bssid)
        talkative = [client for client in clients.values() if len(client.ssids) >= 3]
        if talkative:
            # one finding for the whole neighbourhood, not one per station: 60 clients
            # leaking their history is one problem, not sixty
            _add_finding_once(ctx, {
                "kind": "pnl_disclosure", "severity": "low", "bssid": "",
                "title": (f"{len(talkative)} station(s) broadcast a preferred network "
                          f"list in the clear"),
                "detail": (f"{len(talkative)} of {len(clients)} stations sent directed "
                           f"probe requests naming networks they remember (up to "
                           f"{max((len(c.ssids) for c in talkative), default=0)} names "
                           f"each).  Probe requests are unencrypted even on WPA3, so "
                           f"anyone in range can read the list.  The fix is "
                           f"client-side: disable 'directed probe requests', or accept "
                           f"that the site's SSID history is public to a listener.")},
                ap.bssid)

        loot = self._write_trace(ctx, ap, clients, wanted, missing, capture=path)
        if path and os.path.exists(path):
            ctx.session.add_artifact(Capture(
                kind=self.name, bssid=ap.bssid, essid=ap.essid, path=path,
                tool=self.tool, size=os.path.getsize(path),
                extra={"probes": len(clients), "networks": len(wanted)}))
        detail = (f"{len(clients)} station(s) probing, {len(wanted)} network(s) named, "
                  f"{len(missing)} of them not on air"
                  + (f"; {len(hidden_candidates)} could be the hidden network's name"
                     if hidden_candidates else "")
                  + (" (simulated)" if simulated else ""))
        ap.remember("pnl_harvest", detail, wanted=len(wanted), missing=len(missing))
        ctx.session.stats.pnl_harvests += 1
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, "preferred network lists read",
                                detail)
        return AttackOutcome.success(
            "preferred network lists read", detail=detail,
            extra={"clients": [client.to_dict() for client in clients.values()],
                   "wanted": {ssid: macs for ssid, macs in wanted.items()},
                   "not_on_air": list(missing)[:20],
                   "hidden_candidates": hidden_candidates[:10],
                   "hidden_aps": [entry.bssid for entry in hidden_aps],
                   "trace": loot, "capture": path, "simulated": simulated,
                   "note": ("read-only: probe requests are broadcast in the clear, so "
                            "this needs no injection and no association")})

    # ---------------------------------------------------------------- #
    @staticmethod
    def _capture_path(ctx: AttackContext, ap: AccessPoint) -> str:
        """The pcap to read: the newest one that actually contains probe requests.

        A capture from an `ie_audit` run holds beacons and nothing else, so falling
        back to it would produce an empty wanted list and a misleading finding.  The
        file is only inspected (`probe_requests`), never modified.
        """
        candidates = [cap for cap in ap.captures
                      if cap.path and os.path.exists(cap.path)]
        for capture in ctx.session.all_captures():
            if capture.path and os.path.exists(capture.path) and capture not in candidates:
                candidates.append(capture)
        candidates.sort(key=lambda cap: cap.created, reverse=True)
        for capture in candidates[:6]:                # bounded: parsing costs time
            if probe_requests(capture.path):
                return capture.path
        # no capture on disk has probes in it: better to say so (the scanner's own
        # live state, or the simulator, is then the source) than to read a file that
        # cannot answer this attack's question and report an empty site
        return ""

    def _from_session(self, ctx: AttackContext) -> Dict[str, Any]:
        from ..sniff import ProbeClient

        out: Dict[str, Any] = {}
        for client in ctx.session.clients.values():
            probes = [ssid for ssid in (client.probes or []) if ssid]
            if not probes:
                continue
            out[client.mac] = ProbeClient(mac=client.mac, ssids=probes,
                                          directed=len(probes), vendor=client.vendor)
        return out

    #: names a real site's clients remember and nothing advertises any more — the
    #: finding this attack exists to produce, so the simulation has to contain some
    FORGOTTEN_NETWORKS = ("Cafe-Guest-Old", "AndroidAP_3172", "HOME-8A2C",
                          "FRITZ!Box 7490 Alt")

    def _demo_capture(self, ctx: AttackContext, ap: AccessPoint) -> str:
        """Write the probes the simulated stations would send, and read them back."""
        from ..synth import build_probe_request, write_pcap

        path = ctx.artifact_path("pnl", ap, ".pcap")
        names = list(self.FORGOTTEN_NETWORKS)
        radio = ctx.radio
        for demo_ap in list(getattr(radio, "aps", []) or []):
            # a hidden network's own name is what its client probes for: the demo
            # therefore reveals it here the same way a real capture does
            if demo_ap.hidden and demo_ap.hidden_name:
                names.append(demo_ap.hidden_name)
        frames = []
        clients = list(ctx.session.clients.values())[:20]
        for index, client in enumerate(clients):
            frames.append(build_probe_request(client.mac, ""))       # wildcard first
            for ssid in [ssid for ssid in (client.probes or []) if ssid][:4]:
                frames.append(build_probe_request(client.mac, ssid))
            # history: one forgotten network each, round-robin, so the finding appears
            if names:
                frames.append(build_probe_request(client.mac, names[index % len(names)]))
        write_pcap(path, frames, spacing=0.01)
        return path

    def _write_trace(self, ctx: AttackContext, ap: AccessPoint, clients: Dict[str, Any],
                     wanted: Dict[str, List[str]], missing: Dict[str, List[str]],
                     capture: str = "") -> str:
        """Persist the harvest as JSON: the report quotes measurements, not prose.

        The trace is what the twin/Karma stage would consume: ``ssids_wanted`` is the
        list of names worth imitating, in the order (most-asked-for first) the harvest
        measured, and ``not_on_air`` is the subset that no AP is currently serving.
        """
        ranked = sorted(wanted.items(), key=lambda item: (-len(item[1]), item[0]))
        payload = {
            "generated": time.time(), "target": ap.bssid,
            "capture": capture or "",
            "clients": {mac: client.to_dict() for mac, client in clients.items()},
            "probes": len(clients),
            "networks": len(wanted),
            "ssids_wanted": [ssid for ssid, _macs in ranked],
            "wanted": wanted, "not_on_air": missing,
            "not_on_air_count": len(missing),
            "watched_bssids": [entry.bssid for entry in ctx.session.aps.values()],
        }
        try:
            path = os.path.join(ctx.session.state_dir, "reports", "pnl.json")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
        except OSError:                                        # pragma: no cover
            return ""
        return path
