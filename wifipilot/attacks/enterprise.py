# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""WPA-Enterprise survey: what the EAP conversation tells you, and what breaks it.

An 802.1X network cannot be cracked the way WPA2-PSK can — there is no PSK to
recover.  What *is* possible is narrower and worth stating precisely:

* the EAP method, the identity and (for TLS-based methods) the certificate the
  server presents are all visible on air, so the survey ends with facts: which
  EAP method, which realm, which CA the client was told to trust;
* a server that presents no certificate, or a self-signed one, is trivially
  impersonated — the client will hand over its credentials to anything that
  answers.  That is the real finding on a badly configured enterprise network;
* an outer identity that equals the inner identity (``anonymous@`` not used)
  leaks usernames to anyone listening, which is a privacy finding.

We can identify all of that from a capture and, on request, run the tool that
does the impersonation (:program:`hostapd-mana`/``eaphammer``, elsewhere).  This
module does not implement a rogue RADIUS: it reports what is on air and says what
it would take, because "WPA-Enterprise cracked" is almost always a misreading.
"""

from __future__ import annotations

import contextlib
import os
import time

from ..deps import registry
from ..models import STATUS_SUCCESS, STATUS_SKIPPED, AccessPoint, Attempt, Capture
from ..pcap import analyze_file
from ..sniff import eap_exchange, x509_name
from ..synth import self_signed_certificate
from ..util import Process, human_duration
from .base import Attack, AttackContext, AttackOutcome

#: EAP type codes -> what they mean for an assessment
EAP_METHODS = {
    1: "Identity", 2: "Notification", 3: "Nak", 4: "MD5-Challenge (weak)",
    5: "One-Time Password", 6: "GTC", 13: "TLS", 17: "LEAP (weak)",
    18: "SIM", 21: "TTLS", 23: "AKA", 25: "PEAP", 26: "MSCHAPv2 (inside PEAP)",
    43: "FAST", 47: "AKA'", 50: "PWD", 55: "TEAP",
}


class EnterpriseSurveyAttack(Attack):
    name = "enterprise"
    label = "WPA-Enterprise survey"
    tool = "airodump-ng (+ hostapd-mana/eaphammer when installed)"
    description = ("Capture the 802.1X exchange: EAP method, outer/inner identity, "
                   "the server certificate and its CA.  Reports the two things that "
                   "actually fall over — a missing or self-signed server certificate "
                   "(trivially impersonated) and an identity that leaks the realm.")
    requires = ("airodump",)
    needs_injection = False
    applies_to = ("WPA-ENTERPRISE", "WPA2-ENTERPRISE", "ENTERPRISE")

    def applies(self, ap: AccessPoint) -> bool:
        return ap.auth.upper() in ("MGT", "802.1X", "ENTERPRISE") or \
            "ENTERPRISE" in (ap.encryption or "").upper()

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(
            self.name, ap.bssid, tool=self.tool,
            chosen_by=getattr(ap, "picked_by", "heuristic"),
            reason=getattr(ap, "pick_reason", ""),
        )
        if not self.applies(ap):
            ctx.session.end_attempt(attempt, STATUS_SKIPPED, "not an enterprise network")
            return AttackOutcome.skipped("not an enterprise network",
                                         f"{ap.essid or ap.bssid} uses {ap.auth or 'PSK'}")
        timeout = min(ctx.config.attack_timeout_for("passive"), 90.0)
        if ctx.demo:
            return self._demo(ctx, ap, attempt)
        return self._live(ctx, ap, attempt, timeout)

    # ---------------------------------------------------------------- #
    def _report(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                eapol: int, method: str, identity: str, cert: str,
                ca: str, source: str) -> AttackOutcome:
        facts = [f"EAP method: {method or 'unknown'}",
                 f"EAPOL frames: {eapol}"]
        if identity:
            facts.append(f"outer identity: {identity}")
            if identity and not identity.lower().startswith("anonymous"):
                facts.append("outer identity is not 'anonymous@...' — usernames leak "
                             "to any listener")
        if cert:
            facts.append(f"server certificate: {cert}")
        if ca:
            facts.append(f"CA offered: {ca}")
        detail = "; ".join(facts)
        ap.remember("enterprise_survey", detail, method=method, identity=identity)
        ctx.session.stats.enterprise_surveys += 1
        if cert and ("self-signed" in cert.lower() or "no certificate" in cert.lower()):
            from ..models import Finding
            ctx.session.add_finding(Finding(
                kind="enterprise", severity="high", bssid=ap.bssid,
                title="Enterprise network trusts any server certificate",
                detail=("the authentication server presented " + cert +
                        ": a rogue RADIUS can impersonate it and harvest credentials")))
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, "802.1X surveyed", detail)
        return AttackOutcome.success(
            "802.1X surveyed", detail=detail,
            extra={"eapol": eapol, "method": method, "identity": identity,
                   "certificate": cert, "ca": ca, "source": source,
                   "note": ("WPA-Enterprise has no PSK to crack: the finding is the "
                            "server's certificate validation (or the lack of it)")})

    def _demo(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt
              ) -> AttackOutcome:
        radio = ctx.radio
        demo_ap = radio.find(ap.bssid) if radio else None
        for step in range(1, 4):
            ctx.progress(f"capturing the 802.1X exchange on {ap.display_name}",
                         kind="capture", bssid=ap.bssid, percent=step * 33,
                         detail="EAP-Request/Identity → EAP-Response → TLS hello")
            time.sleep(0.5)
            if ctx.want_stop():
                break
        facts = x509_name(self_signed_certificate())
        cert = getattr(demo_ap, "eap_certificate", "") if demo_ap else ""
        cert = cert or (f"{facts['subject']} (self-signed)")

        return self._report(ctx, ap, attempt, eapol=12,
                            method=getattr(demo_ap, "eap_method", "PEAP") if demo_ap else "PEAP",
                            identity=getattr(demo_ap, "eap_identity", "") if demo_ap else "",
                            cert=cert, ca="", source="simulated exchange")

    def _live(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
              timeout: float) -> AttackOutcome:
        airodump = registry.path("airodump-ng")
        if not airodump:
            return self._fail(ctx, attempt, "airodump-ng missing",
                              "install aircrack-ng")
        prefix = ctx.artifact_path("enterprise", ap, "")
        cap_path = prefix + "-01.cap"
        channel = ap.channel or 0
        ctx.set_channel(channel)
        args = [airodump, ctx.monitor]
        if channel:
            args += ["-c", str(channel)]
        args += ["--bssid", ap.bssid, "-w", prefix, "--output-format", "pcap,csv",
                 "--write-interval", "1", "--ignore-negative-one"]
        proc = Process(args, name="airodump-ng", echo_lines=ctx.config.verbose_tools)
        proc.start()
        if proc.error:
            return self._fail(ctx, attempt, "could not start airodump-ng", proc.error)
        started = time.time()
        eapol = 0
        try:
            while not ctx.want_stop() and time.time() - started < timeout:
                time.sleep(1.5)
                ctx.progress(f"capturing the 802.1X exchange on {ap.display_name}",
                             kind="capture", bssid=ap.bssid,
                             percent=min(95, (time.time() - started) / timeout * 100),
                             detail="EAPOL/EAP frames (nothing transmitted)")
                if os.path.exists(cap_path) and os.path.getsize(cap_path):
                    analysis = analyze_file(cap_path, max_packets=60000)
                    eapol = analysis.eapol_messages
                    if eapol >= 4:                     # identity exchange plus TLS
                        break
        finally:
            with contextlib.suppress(Exception):
                proc.stop()
        saved = ctx.session.save_artifact(cap_path, "enterprise",
                                          ctx.loot_name(ap, "enterprise")) \
            if os.path.exists(cap_path) else ""
        if saved:
            ctx.session.add_capture(Capture(
                kind="handshake", bssid=ap.bssid, essid=ap.essid, path=saved,
                valid=eapol > 0, tool="airodump-ng",
                extra={"kind_detail": "802.1X", "eapol": eapol}))
        if not eapol:
            return self._fail(ctx, attempt, "no 802.1X exchange captured",
                              f"{human_duration(time.time() - started)}: no client "
                              f"authenticated (an enterprise capture needs a station "
                              f"to join)")
        exchange = eap_exchange(cap_path) if os.path.exists(cap_path) else {}
        methods = [name for name in (exchange.get("methods") or []) if name != "Identity"]
        method = ", ".join(methods) or "unknown"
        identities = list(exchange.get("identities") or [])
        # the outer identity is the one sent before the tunnel is up, so it is the
        # first one in the exchange; an inner identity would be encrypted
        identity = identities[0] if identities else ""
        certificates = list(exchange.get("certificates") or [])
        cert = ""
        ca = ""
        for fact in certificates:
            if fact.get("subject") and not cert:
                cert = fact["subject"] + (" (self-signed)" if fact.get("self_signed") else "")
                ca = fact.get("issuer", "")
                break
        if not cert and exchange.get("methods"):
            cert = "no certificate seen (client did not reach the TLS phase)"
        return self._report(ctx, ap, attempt, eapol=eapol or exchange.get("eapol", 0),
                            method=method, identity=identity, cert=cert, ca=ca,
                            source="captured exchange (decoded offline)")
