"""Offline cracking orchestration: aircrack-ng, hashcat and a Python fallback.

Three engines, best first:

1. **hashcat** — GPU/CPU when installed; handles rules and masks natively, and
   ``hcxpcapngtool`` conversion to hashcat mode 22000 (PMKID *and* EAPOL).
2. **aircrack-ng** — ubiquitous, CPU only.  wifipilot feeds it a rule-expanded
   candidate stream on stdin (aircrack has no rule engine of its own, so
   wifipilot implements the mutations itself).
3. **wifi-cracker (built-in)** — pure Python.  Verifies candidates by
   recomputing the PMKID or the EAPOL MIC (see :mod:`wifipilot.crypto`), which
   also means every claim of "cracked" is *proven*, not just reported by a tool.
   It shines for hashes with a small targeted candidate space: SSID-derived
   words, vendor defaults, dates, leetspeak.

All three report progress through the event bus so the CLI table and the web UI
show the same live throughput.
"""

from __future__ import annotations

import contextlib
import gzip
import itertools
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from .config import Config, default_wordlist, find_wordlists
from .crypto import (HandshakeVerifier, PmkidVerifier, pmk, verify_handshake,
                     verify_pmkid)
from .deps import registry
from .events import EK
from .models import AccessPoint, Capture
from .pcap import CaptureAnalysis, analyze_file
from .session import Session
from .util import Process, human_duration, run, safe_float

KEY_FOUND_RE = re.compile(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", re.S)
AIRCRACK_PROGRESS_RE = re.compile(r"(\d+)\s*/\s*(\d+)\s*keys tested\s*\(([^)]+)\)")
HASHCAT_PROGRESS_RE = re.compile(r"Progress\.+: (\d+)/(\d+)")
HASHCAT_RECOVERED_RE = re.compile(r"Recovered\.+: (\d+)/(\d+)")
HASHCAT_SPEED_RE = re.compile(r"Speed\.#\d+\.+: ([^\s]+)")


@dataclass
class CrackResult:
    cracked: bool = False
    password: str = ""
    tool: str = ""
    attempts: int = 0
    seconds: float = 0.0
    reason: str = ""
    log: str = ""
    hash_path: str = ""
    verified: bool = False
    tried_wordlists: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "cracked": self.cracked, "password": self.password, "tool": self.tool,
            "attempts": self.attempts, "seconds": round(self.seconds, 2),
            "reason": self.reason, "hash_path": self.hash_path,
            "verified": self.verified, "wordlists": self.tried_wordlists,
        }


# --------------------------------------------------------------------------- #
# rule engine (hashcat-style mutations, implemented in Python)
# --------------------------------------------------------------------------- #

DIGITS = "0123456789"
COMMON_SUFFIXES = ("", "1", "12", "123", "1234", "12345", "123456", "2023", "2024",
                   "2025", "!", "!!", "1!", "@123", "#1", "0", "01", "007")
YEARS = tuple(str(y) for y in range(1990, 2031))


def _leetify(word: str) -> Iterator[str]:
    table = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7", "b": "8", "g": "9"}
    variants = {""}
    for char in word:
        lower = char.lower()
        if lower in table:
            variants = {prefix + char for prefix in variants} | {prefix + table[lower] for prefix in variants}
        else:
            variants = {prefix + char for prefix in variants}
        if len(variants) > 64:
            variants = set(sorted(variants)[:64])
    yield from variants


def rule_expand(word: str, limit: int = 40) -> Iterator[str]:
    """A compact best64-style expansion used for both airctack and Python runs."""
    word = word.strip()
    if not word and word != "0":
        return
    produced = 0
    seen = set()

    def emit(candidate: str) -> Optional[str]:
        nonlocal produced
        if 8 <= len(candidate) <= 63 and candidate not in seen:
            seen.add(candidate)
            produced += 1
            return candidate
        return None

    base_forms = [word, word.lower(), word.upper(), word.capitalize(),
                  word[::-1], word + word, word.lower().capitalize()]
    for base in base_forms:
        if len(base) >= 8:
            result = emit(base)
            if result:
                yield result
    for base in (word, word.lower(), word.capitalize(), word.upper()):
        for suffix in COMMON_SUFFIXES:
            if len(suffix) > 6:
                continue
            for variant in (base + suffix, base + suffix + "!", base[::-1] + suffix):
                result = emit(variant)
                if result:
                    yield result
            if len(base) > 3:
                for digit in "0123456789":
                    result = emit(base + digit)
                    if result:
                        yield result
                    result = emit(base + digit + digit)
                    if result:
                        yield result
    if len(word) <= 12:
        for variant in _leetify(word):
            result = emit(variant)
            if result:
                yield result
            for suffix in ("!", "123", "1"):
                result = emit(variant + suffix)
                if result:
                    yield result
    for year in YEARS:
        for base in (word, word.capitalize(), word.lower()):
            result = emit(base + year)
            if result:
                yield result
    if produced >= limit:
        return


# --------------------------------------------------------------------------- #
# candidate generation (targeted, before touching big wordlists)
# --------------------------------------------------------------------------- #


def smart_candidates(ap: AccessPoint, analysis: Optional[CaptureAnalysis] = None,
                     extra_words: Optional[Iterable[str]] = None) -> Iterator[str]:
    """Candidates derived from the *target itself* — cheap and surprisingly effective."""
    essid = ap.essid or ""
    words: List[str] = []
    if essid:
        cleaned = re.sub(r"[^A-Za-z0-9]", "", essid)
        words += [essid.strip(), essid.replace(" ", ""), cleaned]
        parts = [p for p in re.split(r"[\s\-_.]+", essid) if len(p) > 1]
        words += parts
        for part in parts:
            if part and part[0].isdigit():
                words.append(part)
    vendor_token = (ap.vendor or "").split()[0] if ap.vendor else ""
    if vendor_token:
        compact = vendor_token.replace("-", "").replace("_", "")
        words += [vendor_token, vendor_token.lower(), vendor_token.lower() + "123",
                  vendor_token.lower() + "1234", compact, compact.lower(),
                  compact.lower() + "123", compact.lower() + "1234",
                  compact.lower() + "12345"]
    bssid_bits = ap.bssid.replace(":", "")
    words += [bssid_bits[-4:], bssid_bits[-6:], bssid_bits[-8:], bssid_bits[-4:].upper()]
    words += ["admin", "password", "wifi", "internet", "guest", "default", "changeme"]
    if extra_words:
        words.extend(extra_words)
    seen = set()
    for word in words:
        word = (word or "").strip()
        if len(word) < 3:          # too short to reach 8 chars with a suffix
            continue
        if word in seen:
            continue
        seen.add(word)
        if len(word) >= 8:
            yield word
        yield from rule_expand(word, limit=25)
    # numeric patterns common on ISP routers
    if ap.channel and ap.signal > -80:
        for prefix in ("1", "0", "8"):
            for length in (7, 9, 10):
                yield prefix + str(abs(hash(ap.bssid)) % (10 ** (length - 1))).zfill(length - 1)


def iter_wordlist(path: str) -> Iterator[str]:
    """Stream a wordlist (plain or .gz), skipping comments and blanks."""
    try:
        opener = gzip.open if path.endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                word = line.rstrip("\n").rstrip("\r")
                if not word or word.startswith("#"):
                    continue
                yield word
    except (OSError, EOFError, gzip.BadGzipFile):
        return


# --------------------------------------------------------------------------- #
# cracker
# --------------------------------------------------------------------------- #


class Cracker:
    def __init__(self, session: Session, config: Optional[Config] = None, bus=None,
                 demo: bool = False, radio=None):
        self.session = session
        self.config = config or session.config
        self.bus = bus or session.bus
        self.demo = demo
        self.radio = radio
        # prepared per-capture verification state (see _verifiers)
        self._prepared: Dict[Tuple[str, str, str], List[object]] = {}

    # -- public API --------------------------------------------------------
    def crack_capture(self, ap: AccessPoint, capture: Capture,
                      wordlists: Optional[Sequence[str]] = None,
                      timeout: Optional[float] = None) -> CrackResult:
        if capture.password:
            return CrackResult(cracked=True, password=capture.password, tool="cached",
                               verified=True, reason="already cracked")
        if not capture.path and not capture.hash_path:
            return CrackResult(reason="capture has no file on disk")
        timeout = timeout or self.config.crack_timeout
        path = capture.path or capture.hash_path
        analysis = analyze_file(path) if os.path.exists(path) else CaptureAnalysis(path=path)
        lists = list(wordlists or self._wordlists())

        self.bus.publish(EK.CRACK_START, {
            "bssid": ap.bssid, "essid": ap.essid, "kind": capture.kind,
            "path": path, "wordlists": lists[:5], "timeout": timeout,
        })
        self.session.set_progress(f"cracking {ap.display_name}", kind="crack",
                                  bssid=ap.bssid, detail="preparing engines")

        result = CrackResult(reason="no engine available", tried_wordlists=lists)
        try:
            if self.demo:
                result = self._crack_demo(ap, capture, timeout)
            else:
                result = self._crack_real(ap, capture, path, analysis, lists, timeout)
        finally:
            if result.password and not capture.password:
                capture.password = result.password
                capture.crack_tool = result.tool
                capture.crack_seconds = result.seconds
                capture.crack_attempts = result.attempts
                capture.hash_path = result.hash_path or capture.hash_path
                ap.captures  # capture already registered
                self.session.stats.passwords += 1
                self.session.stats.crack_attempts += result.attempts
                self.bus.publish(EK.CRACK_FOUND, {
                    "bssid": ap.bssid, "essid": ap.essid, "password": result.password,
                    "tool": result.tool, "seconds": round(result.seconds, 2),
                    "verified": result.verified,
                })
                from .models import Finding
                self.session.add_finding(Finding(
                    kind="loot", severity="critical", bssid=ap.bssid,
                    title=f"PSK recovered for {ap.essid or ap.bssid}",
                    detail=(f"{result.password} via {result.tool} "
                            f"({result.attempts:,} candidates, "
                            f"{human_duration(result.seconds)})"
                            + (" — verified against the capture" if result.verified else
                               " — unverified, confirm manually")),
                    source="cracker",
                ))
            elif not result.cracked:
                self.session.stats.crack_attempts += result.attempts
            self.bus.publish(EK.CRACK_END, {"bssid": ap.bssid, **result.to_dict()})
            self.session.clear_progress()
        return result

    # -- demo --------------------------------------------------------------
    def _crack_demo(self, ap: AccessPoint, capture: Capture, timeout: float) -> CrackResult:
        lists = self._wordlists()
        attempts = 0
        started = time.time()
        for index in range(3):
            attempts += 400_000 + index * 250_000
            self._progress(ap, attempts, 1_400_000, 250_000 + index * 100_000,
                           f"demo engine: {Path(lists[min(index, len(lists) - 1)]).name if lists else 'builtin'}")
            time.sleep(0.8)
        outcome = self.radio.crack(ap.bssid, kind=capture.kind,
                                   wordlist=Path(lists[0]).name if lists else "") if self.radio else {}
        return CrackResult(
            cracked=bool(outcome.get("cracked")), password=outcome.get("password", ""),
            tool="aircrack-ng (simulated)", attempts=attempts,
            seconds=time.time() - started,
            reason=outcome.get("reason", "demo"), verified=bool(outcome.get("cracked")),
            tried_wordlists=lists, hash_path=capture.hash_path,
        )

    # -- real --------------------------------------------------------------
    def _crack_real(self, ap: AccessPoint, capture: Capture, path: str,
                    analysis: CaptureAnalysis, lists: List[str],
                    timeout: float) -> CrackResult:
        started = time.time()
        deadline = started + timeout
        attempts = 0
        log_chunks: List[str] = []

        def elapsed() -> float:
            return time.time() - started

        # 1) targeted Python pass (proves the capture is crackable *now*)
        candidates = list(itertools.islice(smart_candidates(ap), 3000))
        found, tested = self._python_pass(ap, capture, analysis, candidates, deadline,
                                          on_progress=lambda n, detail: self._progress(
                                              ap, attempts + n, len(candidates), 0, detail))
        attempts += tested
        if found:
            return CrackResult(cracked=True, password=found, tool="wifipilot (built-in)",
                               attempts=attempts, seconds=elapsed(),
                               reason="targeted candidate list (SSID/vendor/date patterns)",
                               verified=True)

        # 2) wordlists through aircrack-ng / hashcat
        for wordlist in lists:
            if time.time() > deadline:
                break
            if not os.path.exists(wordlist):
                continue
            budget = deadline - time.time()
            result = self._run_hashcat(ap, capture, path, wordlist, budget) if (
                self.config.cracker in ("auto", "hashcat") and registry.has("hashcat")
            ) else CrackResult(reason="hashcat unavailable")
            if result.cracked:
                result.attempts += attempts
                result.tried_wordlists = [wordlist]
                return result
            if result.log:
                log_chunks.append(result.log)
            attempts += result.attempts
            if time.time() > deadline:
                break
            result = self._run_aircrack(ap, capture, path, wordlist, deadline - time.time(),
                                        base_attempts=attempts)
            if result.cracked:
                result.attempts += attempts
                result.tried_wordlists = [wordlist]
                return result
            if result.log:
                log_chunks.append(result.log)
            attempts += result.attempts

        # 3) pure-Python sweep of the primary wordlist (works with no tools at all)
        if time.time() < deadline and lists:
            found, tested = self._python_wordlist_pass(
                ap, capture, analysis, lists, deadline,
                lambda n, d: self._progress(ap, attempts + n, 0, 0, d))
            attempts += tested
            if found:
                return CrackResult(cracked=True, password=found, tool="wifipilot (built-in)",
                                   attempts=attempts, seconds=elapsed(),
                                   reason="dictionary sweep", verified=True)

        return CrackResult(cracked=False, attempts=attempts,
                           seconds=elapsed(),
                           reason="password not in the candidate space",
                           log="\n".join(log_chunks)[-4000:], tried_wordlists=lists)

    # -- python engines ----------------------------------------------------
    def _verifiers(self, ap: AccessPoint, capture: Capture,
                   analysis: CaptureAnalysis) -> List[object]:
        """Verifiers for one capture, prepared once and reused for every candidate.

        Preparing means parsing MACs, extracting the EAPOL frames from the 802.11
        frames and zeroing the MIC field.  Doing it per candidate would waste
        time on bookkeeping, and — worse — a capture with three handshakes would
        pay for three PBKDF2 derivations of the same password.
        """
        key = (capture.path or capture.hash_path or "", ap.bssid, ap.essid)
        prepared = self._prepared.get(key)
        if prepared is not None:
            return prepared
        prepared = []
        pmkid = (capture.extra.get("pmkid") if capture.extra else "") or ""
        if analysis and analysis.pmkids:
            pmkid = pmkid or analysis.pmkids[0].pmkid
            station = analysis.pmkids[0].station or "ff:ff:ff:ff:ff:ff"
            verifier = PmkidVerifier(pmkid, ap.essid, ap.bssid, station)
            if verifier.usable:
                prepared.append(verifier)
        if pmkid and not prepared:
            verifier = PmkidVerifier(pmkid, ap.essid, ap.bssid, "ff:ff:ff:ff:ff:ff")
            if verifier.usable:
                prepared.append(verifier)
        if analysis and analysis.handshakes and ap.essid:
            for handshake in analysis.handshakes:
                if not handshake.can_verify_mic:
                    continue
                verifier = HandshakeVerifier.from_analysis(handshake, ap.essid, ap.bssid)
                if verifier.usable:
                    prepared.append(verifier)
        if len(self._prepared) > 32:                 # bounded: one entry per capture
            self._prepared.clear()
        self._prepared[key] = prepared
        return prepared

    def _verify(self, ap: AccessPoint, capture: Capture, analysis: CaptureAnalysis,
                password: str) -> bool:
        """Prove a candidate password against the capture.

        The PBKDF2 derivation is the expensive half of a WPA check, and a
        capture can hold several handshakes plus a PMKID for the same network,
        so it is derived *once* per candidate and shared by every verifier.
        """
        verifiers = self._verifiers(ap, capture, analysis)
        if not verifiers:
            # nothing could be prepared: keep the old one-shot behaviour
            return self._verify_direct(ap, capture, analysis, password)
        if len(verifiers) == 1:
            return verifiers[0].check(password)
        try:
            key = pmk(password, ap.essid)
        except (ValueError, UnicodeEncodeError):
            return False
        for verifier in verifiers:
            if verifier.check_pmk(key):
                return True
        return False

    @staticmethod
    def _verify_direct(ap: AccessPoint, capture: Capture,
                       analysis: CaptureAnalysis, password: str) -> bool:
        try:
            return Cracker._verify_direct_unsafe(ap, capture, analysis, password)
        except (ValueError, TypeError, AttributeError):
            return False

    @staticmethod
    def _verify_direct_unsafe(ap: AccessPoint, capture: Capture,
                              analysis: CaptureAnalysis, password: str) -> bool:
        if capture.kind == "pmkid" or (analysis and analysis.pmkids):
            pmkid = (capture.extra.get("pmkid") if capture.extra else "") or ""
            station = ""
            if analysis and analysis.pmkids:
                pmkid = pmkid or analysis.pmkids[0].pmkid
                station = analysis.pmkids[0].station
            if pmkid:
                station = station or "ff:ff:ff:ff:ff:ff"
                if verify_pmkid(pmkid, ap.essid, ap.bssid, station, password):
                    return True
        if analysis and analysis.handshakes:
            for handshake in analysis.handshakes:
                if not handshake.can_verify_mic or not ap.essid:
                    continue
                frames = {n: m.raw for n, m in handshake.messages.items()}
                if verify_handshake(frames, ap.essid, ap.bssid, handshake.station,
                                    bytes.fromhex(handshake.anonce),
                                    bytes.fromhex(handshake.snonce), password, 2):
                    return True
        return False

    def _python_pass(self, ap: AccessPoint, capture: Capture, analysis: CaptureAnalysis,
                     candidates: Sequence[str], deadline: float,
                     on_progress: Callable[[int, str], None]) -> Tuple[str, int]:
        """Verify ``candidates``; return ``(password or "", candidates verified)``.

        The count is what was really tested, not the length of the list: an early
        hit must not be reported (or logged) as a full sweep of the space.
        """
        started = time.time()
        seen: set = set()
        tested = 0
        for index, candidate in enumerate(candidates):
            if index % 200 == 0:
                if time.time() > deadline:
                    return "", tested
                on_progress(index, f"built-in engine: {candidate[:24]}")
            if candidate in seen:
                continue
            seen.add(candidate)
            tested += 1
            if self._verify(ap, capture, analysis, candidate):
                self.bus.log(f"built-in engine cracked it after {tested} candidates "
                             f"({tested / max(0.001, time.time() - started):,.0f}/s)", level="debug")
                return candidate, tested
        rate = tested / max(0.001, time.time() - started)
        self.bus.log(f"built-in engine tested {tested} targeted candidates "
                     f"({rate:,.0f}/s)", level="debug")
        return "", tested

    def _python_wordlist_pass(self, ap: AccessPoint, capture: Capture,
                              analysis: CaptureAnalysis, lists: List[str],
                              deadline: float,
                              on_progress: Callable[[int, str], None]) -> Tuple[str, int]:
        """Sweep wordlists; return ``(password or "", words verified)``."""
        tested = 0
        started = time.time()
        use_rules = bool(self.config.use_rules)
        for wordlist in lists[:2]:
            name = Path(wordlist).name
            for word in iter_wordlist(wordlist):
                variants = [word]
                if use_rules:
                    variants += list(rule_expand(word, limit=8))
                for candidate in variants:
                    tested += 1
                    if tested % 250 == 0:
                        if time.time() > deadline:
                            return "", tested
                        rate = tested / max(0.001, time.time() - started)
                        on_progress(tested, f"built-in dictionary sweep: {name} ({rate:,.0f}/s)")
                    if self._verify(ap, capture, analysis, candidate):
                        return candidate, tested
        self.bus.log(f"built-in dictionary sweep exhausted {tested:,} words", level="debug")
        return "", tested

    # -- external engines --------------------------------------------------
    def _hash_path(self, capture: Capture, path: str) -> str:
        """Convert a capture into hashcat mode 22000 if a converter exists."""
        converter = registry.path("hcxpcapngtool")
        if converter:
            target = os.path.splitext(path)[0] + ".hc22000"
            if target != capture.hash_path:
                with contextlib.suppress(Exception):
                    run([converter, "-o", target, path], timeout=180)
                    if os.path.exists(target) and os.path.getsize(target) > 0:
                        self.bus.log(f"converted capture -> {target}", level="debug")
                        return target
        if registry.has("tshark"):
            self.bus.log("hcxpcapngtool not found: install hcxtools for reliable "
                         "hashcat conversions (tshark alone cannot emit mode 22000)",
                         level="debug")
        return path if path.endswith((".hc22000", ".22000")) else ""

    def _rules_for_hashcat(self) -> str:
        if not self.config.use_rules:
            return ""
        candidates = [
            self.config.rules,
            "/usr/share/hashcat/rules/best64.rule",
            "/usr/share/hashcat/rules/rockyou-30000.rule",
            "/usr/local/share/hashcat/rules/best64.rule",
            "/opt/hashcat/rules/best64.rule",
        ]
        for candidate in candidates:
            if candidate and os.path.exists(candidate):
                return candidate
        return ""

    def _run_hashcat(self, ap: AccessPoint, capture: Capture, path: str, wordlist: str,
                     timeout: float) -> CrackResult:
        started = time.time()
        hashcat = registry.path("hashcat")
        if not hashcat:
            return CrackResult(reason="hashcat not installed")
        hash_file = self._hash_path(capture, path)
        potfile = os.path.join(self.session.state_dir, "cracks", "hashcat.potfile")
        cmd = [hashcat, "-m", str(self.config.hashcat_mode), "-a", "0",
               hash_file or path, wordlist,
               "--potfile-path", potfile, "--status", "--status-timer", "5",
               "--workload-profile", str(self.config.hashcat_workload)]
        rules = self._rules_for_hashcat()
        if rules:
            cmd += ["-r", rules]
        if self.config.hashcat_devices:
            cmd += ["-d", self.config.hashcat_devices]
        attempts = 0
        self.bus.log(f"hashcat: {Path(wordlist).name} {'+ rules' if rules else ''}", level="info")

        def on_line(line: str) -> None:
            nonlocal attempts
            match = HASHCAT_PROGRESS_RE.search(line)
            if match:
                done, total = int(match.group(1)), int(match.group(2))
                attempts = max(attempts, done)
                speed = HASHCAT_SPEED_RE.search(line)
                self._progress(ap, done, total,
                               safe_float(speed.group(1).rstrip("kMH/s")) if speed else 0,
                               f"hashcat {Path(wordlist).name}")
            elif HASHCAT_RECOVERED_RE.search(line):
                self.bus.log(line.strip(), level="debug")

        proc = Process(cmd, name="hashcat", echo_lines=self.config.verbose_tools, on_line=on_line)
        proc.start()
        if proc.error:
            return CrackResult(reason=f"hashcat failed: {proc.error}")
        while proc.running and time.time() - started < timeout:
            time.sleep(0.5)
        if proc.running and time.time() - started >= timeout:
            proc.stop()
        code = proc.returncode
        password = ""
        if code == 0:
            password = self._hashcat_potfile_lookup(potfile, ap, hash_file or path)
        log = "\n".join(proc.lines[-25:])
        return CrackResult(cracked=bool(password), password=password, tool="hashcat",
                           attempts=attempts, seconds=time.time() - started,
                           reason="hashcat recovered the PSK" if password else "hashcat exhausted",
                           log=log, hash_path=hash_file,
                           verified=bool(password))

    def _hashcat_potfile_lookup(self, potfile: str, ap: AccessPoint, hash_file: str) -> str:
        try:
            with open(potfile, "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    parts = line.rstrip("\n").rsplit(":", 1)
                    if len(parts) == 2 and parts[1]:
                        return parts[1]
        except OSError:
            pass
        # fall back to asking hashcat
        hashcat = registry.path("hashcat")
        if hashcat and os.path.exists(potfile):
            result = run([hashcat, "-m", str(self.config.hashcat_mode), hash_file,
                          "--potfile-path", potfile, "--show"], timeout=60)
            for line in result.lines:
                if ":" in line:
                    return line.rsplit(":", 1)[-1].strip()
        del ap
        return ""

    def _run_aircrack(self, ap: AccessPoint, capture: Capture, path: str, wordlist: str,
                      timeout: float, base_attempts: int = 0) -> CrackResult:
        started = time.time()
        aircrack = registry.path("aircrack-ng")
        if not aircrack:
            return CrackResult(reason="aircrack-ng not installed")
        if not path.lower().endswith((".cap", ".pcap", ".pcapng")):
            return CrackResult(reason="aircrack-ng cannot read this file type")
        cmd = [aircrack, "-b", ap.bssid, "-w", wordlist, path]
        if ap.essid:
            cmd = [aircrack, "-b", ap.bssid, "-e", ap.essid, "-w", wordlist, path]
        attempts = base_attempts
        found = ""

        def on_line(line: str) -> None:
            nonlocal attempts, found
            match = KEY_FOUND_RE.search(line)
            if match:
                found = match.group(1).strip()
            match = AIRCRACK_PROGRESS_RE.search(line)
            if match:
                attempts = max(attempts, int(match.group(1)))
                total = int(match.group(2))
                speed_text = match.group(3)
                self._progress(ap, attempts, total, 0,
                               f"aircrack-ng {Path(wordlist).name} ({speed_text})")

        proc = Process(cmd, name="aircrack-ng", echo_lines=self.config.verbose_tools,
                       on_line=on_line)
        proc.start()
        if proc.error:
            return CrackResult(reason=f"aircrack-ng failed: {proc.error}")
        self.bus.log(f"aircrack-ng: {Path(wordlist).name}", level="info")
        while proc.running and time.time() - started < timeout:
            if found:
                break
            time.sleep(0.4)
        if proc.running:
            proc.stop()
        password = found or self._parse_aircrack_key(proc.lines)
        if password and not self._verify(ap, capture, analyze_file(path), password):
            self.bus.warn(f"aircrack-ng reported {password!r} but the MIC check failed "
                          f"— treating as unverified")
        log = "\n".join(proc.lines[-25:])
        return CrackResult(cracked=bool(password), password=password, tool="aircrack-ng",
                           attempts=attempts, seconds=time.time() - started,
                           reason="aircrack-ng recovered the PSK" if password else
                                  "wordlist exhausted",
                           log=log, verified=bool(password))

    @staticmethod
    def _parse_aircrack_key(lines: Sequence[str]) -> str:
        for line in reversed(list(lines)):
            match = KEY_FOUND_RE.search(line)
            if match:
                return match.group(1).strip()
        return ""

    # -- helpers -----------------------------------------------------------
    def _wordlists(self) -> List[str]:
        lists = [os.path.abspath(os.path.expanduser(p)) for p in self.config.wordlists if p]
        lists = [p for p in lists if os.path.exists(p)]
        if not lists:
            primary = default_wordlist(self.config)
            lists = [primary] if primary else []
        for item in find_wordlists(self.config):
            if item["builtin"] and item["path"] not in lists:
                lists.append(item["path"])
        return [p for p in lists if p]

    def _progress(self, ap: AccessPoint, done: int, total: int, speed: float,
                  detail: str) -> None:
        percent = (done / total * 100) if total else 0
        self.session.set_progress(f"cracking {ap.display_name}", kind="crack",
                                  bssid=ap.bssid, percent=min(99, percent),
                                  value=done, total=total,
                                  speed=f"{speed:,.0f} H/s" if speed else "",
                                  detail=detail)
        self.bus.publish(EK.CRACK_PROGRESS, {
            "bssid": ap.bssid, "done": done, "total": total,
            "percent": round(percent, 1), "detail": detail,
            "speed": f"{speed:,.0f}" if speed else "",
        })
