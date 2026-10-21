# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
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
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from .config import Config, default_wordlist, find_wordlists
from .crypto import (HandshakeVerifier, PmkidVerifier, pmk, verify_handshake,
                     verify_pmkid)
from . import analytics, hash22000, masks, rules as rules_module
from .pmk import PMK_CACHE_NAME, PMKCache
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
# strategy presets (one name instead of six flags)
# --------------------------------------------------------------------------- #

STRATEGIES: Dict[str, Dict[str, object]] = {
    # (targeted_candidates, mask_candidates, use_rules, rule_file, wordlists, order)
    "quick": {
        "label": "quick",
        "targeted_candidates": 1500,
        "mask_candidates": 5_000,
        "use_rules": True,
        "rule_file": "best64",
        "wordlists": 0,
        "order": "targeted,masks,builtin",
        "crack_timeout": 120.0,
        "note": "one fast pass: target-derived words, small masks, no big wordlists",
    },
    "default": {
        "label": "default",
        "targeted_candidates": 3000,
        "mask_candidates": 10_000,
        "use_rules": True,
        "rule_file": "",
        "wordlists": 0,
        "order": "targeted,masks,hashcat-masks,external,builtin",
        "crack_timeout": 600.0,
        "note": "the normal engine order",
    },
    "thorough": {
        "label": "thorough",
        "targeted_candidates": 20_000,
        "mask_candidates": 250_000,
        "use_rules": True,
        "rule_file": "best64",
        "wordlists": 2,
        "order": "targeted,masks,hashcat-masks,external,builtin",
        "crack_timeout": 1800.0,
        "note": "bigger targeted and mask passes, every wordlist, rules on",
    },
    "insane": {
        "label": "insane",
        "targeted_candidates": 100_000,
        "mask_candidates": 2_000_000,
        "use_rules": True,
        "rule_file": "best64",
        "wordlists": 5,
        "order": "targeted,masks,hashcat-masks,external,builtin",
        "crack_timeout": 7200.0,
        "note": "everything the built-in engine can do; hashcat for the rest",
    },
    "mask-only": {
        "label": "mask-only",
        "targeted_candidates": 0,
        "mask_candidates": 2_000_000,
        "use_rules": False,
        "rule_file": "",
        "wordlists": 0,
        "order": "masks,hashcat-masks",
        "crack_timeout": 1800.0,
        "note": "no dictionaries, no target words: masks and hashcat -a 3 only",
    },
    "wordlist-only": {
        "label": "wordlist-only",
        "targeted_candidates": 0,
        "mask_candidates": 0,
        "use_rules": True,
        "rule_file": "best64",
        "wordlists": 5,
        "order": "external,builtin",
        "crack_timeout": 3600.0,
        "note": "dictionaries and rules only — the classic route",
    },
    "pixie-then-crack": {
        "label": "pixie-then-crack",
        "targeted_candidates": 3000,
        "mask_candidates": 10_000,
        "use_rules": True,
        "rule_file": "best64",
        "wordlists": 1,
        "order": "targeted,masks,builtin,external",
        "crack_timeout": 900.0,
        "note": "same as default but the built-in engine runs before external tools",
    },
}


def strategy_names() -> List[str]:
    return sorted(STRATEGIES)


def strategy(label: str) -> Dict[str, object]:
    """Return a preset by name, or an empty dict (and let the caller complain)."""
    return dict(STRATEGIES.get(label.strip().lower(), {}))


#: the preset lookup under a second name: ``crack_capture`` takes a ``strategy``
#: argument that would otherwise shadow the function itself
preset_for = strategy


def apply_strategy(config: Config, label: str) -> Dict[str, object]:
    """Stamp a preset onto a config.  Unknown names raise :class:`KeyError`."""
    if label not in STRATEGIES:
        raise KeyError(f"unknown strategy {label!r} (known: "
                       f"{', '.join(strategy_names())})")
    preset = STRATEGIES[label]
    config.targeted_candidates = int(preset["targeted_candidates"])
    config.mask_candidates = int(preset["mask_candidates"])
    config.use_rules = bool(preset["use_rules"])
    config.use_masks = int(preset["mask_candidates"]) > 0
    config.crack_timeout = float(preset["crack_timeout"])
    config.crack_order = str(preset["order"])
    config.rule_file = str(preset["rule_file"])
    config.wordlist_limit = int(preset["wordlists"])
    config.crack_strategy = label
    return dict(preset)


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
    # known default schemes for this vendor/ISP (data/default-patterns.json)
    scheme = analytics.vendor_patterns(essid, ap.vendor or "")
    words += [str(word) for word in (scheme.get("words") or [])]
    if extra_words:
        words.extend(extra_words)
    seen_words = set()
    produced = set()
    for word in words:
        word = (word or "").strip()
        if len(word) < 3:          # too short to reach 8 chars with a suffix
            continue
        if word in seen_words:
            continue
        seen_words.add(word)
        for candidate in ([word] if len(word) >= 8 else []) + list(
                rule_expand(word, limit=25)):
            # the same candidate reached by two routes wastes one unit of a
            # budget that an operator sized on purpose
            if candidate in produced:
                continue
            produced.add(candidate)
            yield candidate
    # numeric patterns common on ISP routers
    if ap.channel and ap.signal > -80:
        for prefix in ("1", "0", "8"):
            for length in (7, 9, 10):
                candidate = prefix + str(abs(hash(ap.bssid)) % (10 ** (length - 1))
                                         ).zfill(length - 1)
                if candidate in produced:
                    continue
                produced.add(candidate)
                yield candidate


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


# -- CPU acceleration workers (multiprocessing, see wifipilot.accel) ------- #
# Top-level on purpose: ProcessPoolExecutor pickles its entry points.  The
# verifiers ride along with each chunk (they are a few hundred bytes against
# ~256 PBKDF2 derivations of work), which keeps the pool itself stateless —
# one persistent pool per Cracker serves every capture, no respawn per pass.
def _verify_chunk(payload: Tuple[List[Any], str, List[str]]) -> Tuple[str, int]:
    """Verify one chunk in a worker process: ``(hit or "", candidates tested)``."""
    verifiers, essid, candidates = payload
    tested = 0
    single = verifiers[0] if len(verifiers) == 1 else None
    for candidate in candidates:
        tested += 1
        if single is not None:
            if single.check(candidate):
                return candidate, tested
            continue
        try:
            key = pmk(candidate, essid)
        except (ValueError, UnicodeEncodeError):
            continue
        for verifier in verifiers:
            if verifier.check_pmk(key):
                return candidate, tested
    return "", tested


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
        # the persistent multiprocessing pool (see _get_pool); created lazily
        # on first parallel pass, closed by close() (engine shutdown)
        self._pool: Optional[ProcessPoolExecutor] = None
        self._pool_workers: int = 0
        self._pool_lock = threading.Lock()
        #: masks for *this* call only (the web UI's per-request patterns)
        self._call_masks: List[str] = []
        #: strategy for *this* call only (``--strategy`` on the CLI, ``strategy=`` in the API)
        self._strategy: str = ""
        #: config values a per-call strategy overrode, restored afterwards
        self._strategy_snapshot: Dict[str, object] = {}
        #: candidates verified by the stage that just ran (see _crack_real)
        self._stage_attempts: int = 0
        #: ESSID-keyed PMK cache (built lazily; see pmk_cache)
        self._pmk_cache: Optional[PMKCache] = None

    # -- PMK cache --------------------------------------------------------- #
    def pmk_cache(self) -> Optional[PMKCache]:
        """The engagement's ESSID -> PMK cache, or ``None`` when disabled.

        A PSK is a property of the *network* and the PMK follows from the ESSID and
        the passphrase, so once wifipilot has cracked one capture of an SSID every
        later capture of the same SSID is one HMAC away from being "cracked" too.
        That pays off on a mesh, in a roaming environment, and on a lab bench where
        the same network gets captured a dozen times.
        """
        if not getattr(self.config, "pmk_cache", True):
            return None
        if self._pmk_cache is None:
            path = getattr(self.config, "pmk_cache_path", "") or ""
            if not path:
                directory = getattr(self.config, "state_dir", "") or self.session.state_dir
                path = os.path.join(directory, PMK_CACHE_NAME) if directory else ""
            self._pmk_cache = PMKCache(path=path).load()
        return self._pmk_cache

    def _pmk_lines(self, path: str) -> List[object]:
        """Mode 22000 lines for a capture or hash file ('' when unreadable)."""
        try:
            if hash22000.is_hash_file(path):
                return hash22000.parse_file(path)
            analysis = analyze_file(path, max_packets=60000)
            text = "\n".join(hash22000.lines_from_analysis(analysis))
            return hash22000.parse_text(text)[0]
        except Exception:                    # a broken capture must not stop a crack
            return []

    def _pmk_lookup(self, ap: AccessPoint, capture: Capture, path: str):
        """A cached PMK for this capture's ESSID, *verified* against the capture."""
        cache = self.pmk_cache()
        essid = (ap.essid or capture.essid or "").strip()
        if cache is None or not essid or essid not in cache:
            return None
        for line in self._pmk_lines(path):
            if (line.essid or "").strip() and (line.essid or "").strip() != essid:
                continue
            hit = cache.lookup(essid, line)
            if hit is not None:
                return hit
        return None

    def _cached_result(self, ap: AccessPoint, capture: Capture, path: str,
                       lists: List[str]) -> Optional[CrackResult]:
        """A ``CrackResult`` for a cache hit, or ``None``.

        A hit goes through the same reporting path as a crack: the capture gets its
        password, the AP counts as solved, the event is published.  "We already know
        this network" is a result, not a shortcut that silently skips the bookkeeping.
        """
        hit = self._pmk_lookup(ap, capture, path)
        if hit is None:
            return None
        self.session.stats.pmk_hits += 1
        self.bus.log(f"PMK cache hit for {ap.essid or ap.bssid}: the passphrase was "
                     f"learned earlier in this engagement (still verified against this "
                     f"capture)", level="ok")
        return CrackResult(cracked=True, password=hit.psk, tool="pmk-cache",
                           verified=True, attempts=0, seconds=0.0,
                           reason="ESSID-keyed PMK cache (verification only)",
                           tried_wordlists=lists)

    def _pmk_remember(self, ap: AccessPoint, password: str, source: str) -> None:
        cache = self.pmk_cache()
        essid = (ap.essid or "").strip()
        if cache is not None and essid and password:
            cache.remember(essid, password, source=source)

    #: config fields a named strategy may stamp (mirrors apply_strategy)
    _STRATEGY_FIELDS = ("targeted_candidates", "mask_candidates", "use_rules",
                        "use_masks", "crack_timeout", "crack_order", "rule_file",
                        "wordlist_limit", "crack_strategy")

    def _apply_call_strategy(self, label: str):
        """Stamp a preset onto the config for exactly one call.

        ``strategy=`` is a per-call setting (the web UI's dropdown), so the values
        it overrides are returned for the caller to restore in its ``finally``
        block: a one-off "insane" run must not reconfigure every later crack of the
        engagement.
        """
        snapshot = {name: getattr(self.config, name) for name in self._STRATEGY_FIELDS}
        try:
            preset = apply_strategy(self.config, label)
        except KeyError as error:
            return {}, {}, str(error)
        return preset, snapshot, ""

    # -- public API --------------------------------------------------------
    def crack_capture(self, ap: AccessPoint, capture: Capture,
                      wordlists: Optional[Sequence[str]] = None,
                      timeout: Optional[float] = None,
                      masks: Optional[Sequence[str]] = None,
                      strategy: str = "") -> CrackResult:
        if capture.password:
            return CrackResult(cracked=True, password=capture.password, tool="cached",
                               verified=True, reason="already cracked")
        if not capture.path and not capture.hash_path:
            return CrackResult(reason="capture has no file on disk")
        path = capture.path or capture.hash_path
        self._strategy = strategy or ""
        snapshot: Dict[str, object] = {}
        if self._strategy:
            preset, snapshot, error = self._apply_call_strategy(self._strategy)
            if error:
                self._strategy = ""
                return CrackResult(reason=error, tried_wordlists=list(wordlists or []))
            self.bus.log(f"crack strategy {preset['label']}: {preset['note']}", level="info")
        timeout = timeout or self.config.crack_timeout
        is_hash = hash22000.is_hash_file(path)
        analysis = (CaptureAnalysis(path=path) if is_hash or not os.path.exists(path)
                    else analyze_file(path))
        lists = list(wordlists or self._wordlists())
        limit = int(getattr(self.config, "wordlist_limit", 0) or 0)
        if limit and not wordlists:
            lists = lists[:limit]

        self.bus.publish(EK.CRACK_START, {
            "bssid": ap.bssid, "essid": ap.essid, "kind": capture.kind,
            "path": path, "wordlists": lists[:5], "timeout": timeout,
        })
        if hash22000.is_hash_file(path):
            lines = hash22000.parse_file(path)
            verifiable = len(hash22000.verifiers(lines))
            self.bus.log(f"hash file: {len(lines)} line(s), {verifiable} verifiable "
                         f"({len(lines) - verifiable} have no usable nonce or MIC)",
                         level="info")
        self.session.set_progress(f"cracking {ap.display_name}", kind="crack",
                                  bssid=ap.bssid, detail="preparing engines")

        result = (self._cached_result(ap, capture, path, lists) or
                  CrackResult(reason="no engine available", tried_wordlists=lists))
        self._call_masks = [str(m) for m in (masks or [])]
        try:
            if result.password:
                pass                     # already verified from the ESSID-keyed cache
            elif self.demo:
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
                self._pmk_remember(ap, result.password, result.tool)
                # the AP's own history is what the timeline view and the "don't
                # attack a solved target" rule are read from
                ap.remember("cracked", f"{result.password} via {result.tool}",
                            tool=result.tool, seconds=round(result.seconds, 2))
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
            self._call_masks = []
            self._strategy = ""
            for name, value in snapshot.items():
                setattr(self.config, name, value)
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
        """Run the stages named in ``config.crack_order``, in that order.

        Each stage is a method that either returns a :class:`CrackResult` (found
        it) or ``None`` and appends a ``(candidates tested, log)`` pair.  Keeping
        the order data — not code — is what makes ``--strategy`` possible: the
        same stages, in a different sequence, with different budgets.
        """
        started = time.time()
        deadline = started + timeout
        attempts = 0
        log_chunks: List[str] = []
        order = self._stage_order()

        def elapsed() -> float:
            return time.time() - started

        def base_attempts() -> int:
            return attempts

        class _StageFailed(Exception):
            pass

        if not self._verifiers(ap, capture, analysis):
            reason = ("hash file holds no verifiable hash (PMKID or an EAPOL pair "
                      "with both nonces)" if hash22000.is_hash_file(path)
                      else "capture holds nothing with a recomputable MIC or PMKID")
            self.bus.log(reason, level="warning")
            return CrackResult(cracked=False, attempts=0, seconds=elapsed(), reason=reason)

        stages = {
            "targeted": self._stage_targeted,
            "masks": self._stage_masks,
            "hashcat-masks": self._stage_hashcat_masks,
            "external": self._stage_external,
            "builtin": self._stage_builtin,
        }
        for stage in order:
            if time.time() > deadline:
                self.bus.log(f"stopping: {int(timeout)}s budget exhausted "
                             f"({attempts:,} candidates verified)", level="info")
                break
            handler = stages.get(stage)
            if handler is None:
                self.bus.log(f"crack: ignoring unknown stage {stage!r}", level="warning")
                continue
            try:
                found = handler(ap, capture, analysis, path, lists, deadline,
                                base_attempts, log_chunks)
            except _StageFailed:
                break
            if found is not None:
                # the stage counted what it verified; the result reports that
                found.attempts = self._stage_attempts
                found.seconds = found.seconds or elapsed()
                return found
            attempts = self._stage_attempts
        return CrackResult(cracked=False, attempts=attempts, seconds=elapsed(),
                           reason="password not in the candidate space",
                           log="\n".join(log_chunks)[-4000:], tried_wordlists=lists)

    def _stage_order(self) -> List[str]:
        """The stages to run: the strategy's order, or the configured one.

        ``hashcat-masks`` is implied by ``masks`` (it is the same idea, handed to
        hashcat) and is only run when hashcat is installed and the built-in
        budget could not cover the spaces.
        """
        raw = (self.config.crack_order or
               "targeted,masks,hashcat-masks,external,builtin")
        order = [token.strip().lower() for token in raw.split(",") if token.strip()]
        valid = ("targeted", "masks", "hashcat-masks", "external", "builtin")
        clean = [token for token in order if token in valid]
        for token in order:
            if token not in valid:
                self.bus.log(f"crack: ignoring unknown stage {token!r} in crack_order",
                             level="warning")
        return clean

    def _count(self, tested: int) -> None:
        self._stage_attempts = tested

    # -- stages ------------------------------------------------------------ #
    def _stage_targeted(self, ap, capture, analysis, path, lists, deadline,
                        base_attempts, log_chunks) -> Optional[CrackResult]:
        self._stage_attempts = base_attempts
        limit = max(0, int(self.config.targeted_candidates))
        if not limit:
            return None
        candidates = list(itertools.islice(smart_candidates(ap), limit))
        found, tested = self._python_pass(
            ap, capture, analysis, candidates, deadline,
            on_progress=lambda n, detail: self._progress(ap, base_attempts() + n,
                                                         len(candidates), 0, detail))
        self._count(base_attempts() + tested)
        if found:
            return CrackResult(cracked=True, password=found, tool="wifipilot (built-in)",
                               attempts=0, seconds=0.0,
                               reason="targeted candidate list (SSID/vendor/date patterns)",
                               verified=True)
        return None

    def _stage_masks(self, ap, capture, analysis, path, lists, deadline,
                     base_attempts, log_chunks) -> Optional[CrackResult]:
        self._stage_attempts = base_attempts()
        mask_total = self._mask_total(ap)
        found, tested, pattern = self._mask_pass(
            ap, capture, analysis, deadline, base_attempts(),
            lambda n, d: self._progress(ap, base_attempts() + n, mask_total, 0, d))
        self._count(base_attempts() + tested)
        if found:
            return CrackResult(cracked=True, password=found, tool="wifipilot (built-in)",
                               attempts=0, seconds=0.0,
                               reason=f"mask attack ({pattern})", verified=True)
        return None

    def _stage_hashcat_masks(self, ap, capture, analysis, path, lists, deadline,
                             base_attempts, log_chunks) -> Optional[CrackResult]:
        self._stage_attempts = base_attempts()
        if not (self.config.cracker in ("auto", "hashcat") and registry.has("hashcat")):
            return None
        result = self._run_hashcat_masks(ap, capture, path, deadline - time.time())
        self._count(base_attempts() + result.attempts)
        if result.cracked:
            result.attempts = 0
            result.tried_wordlists = self.config.mask_patterns or ["<target masks>"]
            return result
        if result.log:
            log_chunks.append(result.log)
        return None

    def _stage_external(self, ap, capture, analysis, path, lists, deadline,
                        base_attempts, log_chunks) -> Optional[CrackResult]:
        self._stage_attempts = base_attempts()
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
                self._count(base_attempts() + result.attempts)
                result.attempts = 0
                result.tried_wordlists = [wordlist]
                return result
            if result.log:
                log_chunks.append(result.log)
            if time.time() > deadline:
                break
            result = self._run_aircrack(ap, capture, path, wordlist, deadline - time.time(),
                                        base_attempts=base_attempts())
            if result.cracked:
                self._count(base_attempts() + result.attempts)
                result.attempts = 0
                result.tried_wordlists = [wordlist]
                return result
            if result.log:
                log_chunks.append(result.log)
        self._count(base_attempts())
        return None

    def _stage_builtin(self, ap, capture, analysis, path, lists, deadline,
                       base_attempts, log_chunks) -> Optional[CrackResult]:
        self._stage_attempts = base_attempts()
        if not lists or time.time() >= deadline:
            return None
        found, tested = self._python_wordlist_pass(
            ap, capture, analysis, lists, deadline,
            lambda n, d: self._progress(ap, base_attempts() + n, 0, 0, d))
        self._count(base_attempts() + tested)
        if found:
            return CrackResult(cracked=True, password=found, tool="wifipilot (built-in)",
                               attempts=0, seconds=0.0,
                               reason="dictionary sweep", verified=True)
        return None

    # -- masks -------------------------------------------------------------
    def _masks(self, ap: AccessPoint) -> Tuple[List[masks.Mask], List[str]]:
        """Masks for this target: the operator's patterns first, then the ones
        the target itself suggests.  Returns ``(masks, problems)``."""
        if not self.config.use_masks or self.config.mask_candidates == 0:
            return [], []
        chosen: List[masks.Mask] = []
        patterns: set = set()
        problems: List[str] = []
        for pattern in [*self._call_masks, *self.config.mask_patterns]:
            try:
                mask = masks.Mask(pattern, "operator-supplied")
            except masks.MaskError as error:
                problems.append(str(error))
                continue
            if not mask.usable:
                problems.append(f"mask {pattern!r} cannot produce an 8-63 character "
                                f"passphrase ({mask.length} characters)")
                continue
            chosen.append(mask)
            patterns.add(mask.pattern)
        for mask in masks.suggest_masks(ap.essid or "", ap.vendor or ""):
            if mask.pattern not in patterns:
                patterns.add(mask.pattern)
                chosen.append(mask)
        return chosen, problems

    def _mask_total(self, ap: AccessPoint) -> int:
        """Total candidate space of the masks the built-in engine will run."""
        chosen, _ = self._masks(ap)
        runnable, _ = masks.select_masks(chosen, max(0, int(self.config.mask_candidates)))
        return sum(mask.space for mask in runnable)

    def _mask_pass(self, ap: AccessPoint, capture: Capture, analysis: CaptureAnalysis,
                   deadline: float, base_attempts: int,
                   on_progress: Callable[[int, str], None]) -> Tuple[str, int, str]:
        """Expand the masks the built-in engine can afford and verify them.

        Returns ``(password or "", candidates verified, pattern used)``.  Masks
        too big for the budget are *named* in the log and left to hashcat: a
        half-swept 100-million space would be a lie dressed up as a result.
        """
        chosen, problems = self._masks(ap)
        for problem in problems:
            self.bus.log(f"mask: {problem}", level="warning")
        if not chosen:
            return "", 0, ""
        budget = max(0, int(self.config.mask_candidates))
        runnable, skipped = masks.select_masks(chosen, budget)
        for mask in runnable:
            self.bus.log(f"mask: {mask.pattern} — {mask.space:,} candidates "
                         f"({mask.note})", level="debug")
        for mask in skipped:
            self.bus.log(f"mask: {mask.pattern} ({mask.space:,} candidates) skipped by the "
                         f"built-in engine — hashcat -a 3 territory", level="debug")
        if not runnable:
            self.bus.log(f"mask: nothing fits the built-in budget of {budget:,} "
                         f"candidates (smallest mask is {min(chosen, key=lambda m: m.space).pattern}"
                         f" at {min(mask.space for mask in chosen):,})", level="debug")
            return "", 0, ""
        patterns = [mask.pattern for mask in runnable]
        parallel = self._verify_parallel(
            ap, capture, analysis, masks.mask_candidates(patterns, limit=budget),
            deadline, on_progress, f"mask {patterns[0]} (parallel)")
        if parallel is not None:
            found, counted = parallel
            return found, counted, patterns[0] if found else ""
        started = time.time()
        tested = 0
        for candidate in masks.mask_candidates(patterns, limit=budget):
            tested += 1
            if tested % 200 == 0:
                if time.time() > deadline:
                    self.bus.log(f"mask: stopped after {tested:,} candidates (time budget)",
                                 level="debug")
                    break
                on_progress(tested, f"mask {patterns[0]}")
            if self._verify(ap, capture, analysis, candidate):
                rate = tested / max(0.001, time.time() - started)
                self.bus.log(f"mask attack: {patterns} cracked after {tested:,} "
                             f"candidates ({rate:,.0f}/s)", level="debug")
                return candidate, tested, patterns[0]
        rate = tested / max(0.001, time.time() - started)
        self.bus.log(f"mask attack: {tested:,} candidates from {len(patterns)} mask(s) "
                     f"({rate:,.0f}/s), no match", level="debug")
        return "", tested, ""

    def _run_hashcat_masks(self, ap: AccessPoint, capture: Capture, path: str,
                           timeout: float) -> CrackResult:
        """Hand every selected mask to hashcat ``-a 3``, big spaces included."""
        chosen, _ = self._masks(ap)
        if not chosen:
            return CrackResult(reason="no masks")
        hashcat = registry.path("hashcat")
        if not hashcat:
            return CrackResult(reason="hashcat not installed")
        hash_file = self._hash_path(capture, path)
        if not hash_file:
            return CrackResult(reason="no mode 22000 file to feed hashcat")
        potfile = os.path.join(self.session.state_dir, "cracks", "hashcat.potfile")
        started = time.time()
        attempts = 0
        log_chunks: List[str] = []
        for mask in chosen:
            remaining = timeout - (time.time() - started)
            if remaining <= 1:
                break
            cmd = [hashcat, "-m", str(self.config.hashcat_mode), "-a", "3",
                   hash_file, mask.pattern,
                   "--potfile-path", potfile, "--status", "--status-timer", "5",
                   "--workload-profile", str(self.config.hashcat_workload)]
            if self.config.hashcat_devices:
                cmd += ["-d", self.config.hashcat_devices]
            self.bus.log(f"hashcat -a 3 {mask.pattern} — {mask.space:,} candidates "
                         f"({mask.note})", level="info")

            def on_line(line: str, _started=started) -> None:
                nonlocal attempts
                match = HASHCAT_PROGRESS_RE.search(line)
                if match:
                    done, total = int(match.group(1)), int(match.group(2))
                    attempts = max(attempts, done)
                    speed = HASHCAT_SPEED_RE.search(line)
                    self._progress(ap, done, total,
                                   safe_float(speed.group(1).rstrip("kMH/s")) if speed else 0,
                                   f"hashcat -a 3 {mask.pattern}")

            proc = Process(cmd, name="hashcat", echo_lines=self.config.verbose_tools,
                           on_line=on_line)
            proc.start()
            if proc.error:
                return CrackResult(reason=f"hashcat failed: {proc.error}", attempts=attempts)
            while proc.running and time.time() - started < timeout:
                time.sleep(0.5)
            if proc.running:
                proc.stop()
            log_chunks.append("\n".join(proc.lines[-15:]))
            if proc.returncode == 0:
                password = self._hashcat_potfile_lookup(potfile, ap, hash_file)
                if password:
                    return CrackResult(cracked=True, password=password, tool="hashcat",
                                       attempts=attempts, seconds=time.time() - started,
                                       reason=f"hashcat -a 3 {mask.pattern}",
                                       log="\n".join(log_chunks)[-4000:],
                                       hash_path=hash_file, verified=True)
        return CrackResult(cracked=False, attempts=attempts, seconds=time.time() - started,
                           reason="masks exhausted", log="\n".join(log_chunks)[-4000:],
                           hash_path=hash_file)

    # -- python engines ----------------------------------------------------
    def _verifiers(self, ap: AccessPoint, capture: Capture,
                   analysis: CaptureAnalysis) -> List[object]:
        """Verifiers for one capture, prepared once and reused for every candidate.

        Preparing means parsing MACs, extracting the EAPOL frames from the 802.11
        frames and zeroing the MIC field.  Doing it per candidate would waste
        time on bookkeeping, and — worse — a capture with three handshakes would
        pay for three PBKDF2 derivations of the same password.
        """
        path = capture.path or capture.hash_path or ""
        key = (path, ap.bssid, ap.essid)
        prepared = self._prepared.get(key)
        if prepared is not None:
            return prepared
        if hash22000.is_hash_file(path):
            # a mode 22000 file *is* the capture: the EAPOL/MIC data is the file
            prepared = hash22000.verifiers(hash22000.parse_file(path))
            if len(self._prepared) > 32:
                self._prepared.clear()
            self._prepared[key] = prepared
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
            # crackable_handshakes() drops retransmissions and sorts by quality:
            # a capture with the same M1+M2 five times costs one MIC check, not
            # five, and the challenge pair is tried before the leftovers.
            for handshake in analysis.crackable_handshakes():
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
            for handshake in analysis.crackable_handshakes():
                if not ap.essid:
                    continue
                frames = {n: m.raw for n, m in handshake.messages.items()}
                if verify_handshake(frames, ap.essid, ap.bssid, handshake.station,
                                    bytes.fromhex(handshake.anonce),
                                    bytes.fromhex(handshake.snonce), password):
                    return True
        return False

    # -- acceleration (multiprocessing workers, RAM candidate cache) ------ #
    def _accel_workers(self) -> int:
        from .accel import workers
        return workers(self.config)

    def _get_pool(self, count: int) -> Optional[ProcessPoolExecutor]:
        """The persistent worker pool, (re)created only when the size changes.

        Spawning processes costs ~100 ms each; a campaign cracks many
        captures, so the pool is built once and kept for the Cracker's life.
        """
        with self._pool_lock:
            if self._pool is not None and self._pool_workers == count:
                return self._pool
            if self._pool is not None:
                self._pool.shutdown(wait=False, cancel_futures=True)
                self._pool = None
            try:
                self._pool = ProcessPoolExecutor(max_workers=count)
            except Exception as exc:  # pragma: no cover - defensive
                self.bus.log(f"CPU acceleration unavailable ({exc}): cracking serially",
                             level="warning")
                return None
            self._pool_workers = count
            return self._pool

    def close(self) -> None:
        """Shut the worker pool down (called by Engine.shutdown)."""
        with self._pool_lock:
            if self._pool is not None:
                self._pool.shutdown(wait=False, cancel_futures=True)
                self._pool = None
                self._pool_workers = 0

    def _deduped(self, candidates: Iterable[str]) -> Iterator[str]:
        """Drop repeats using an in-memory seen-set sized by the RAM budget.

        Rule expansion produces the same candidate from many base words; each
        repeat costs a full PBKDF2.  The set is bounded (and reset when full)
        so a huge dictionary cannot eat the machine.
        """
        from .accel import cache_entries
        cap = cache_entries(self.config) or 200_000
        seen: set = set()
        for candidate in candidates:
            if candidate in seen:
                continue
            if len(seen) >= cap:
                seen.clear()
            seen.add(candidate)
            yield candidate

    def _verify_parallel(self, ap: AccessPoint, capture: Capture,
                         analysis: CaptureAnalysis, candidates: Iterable[str],
                         deadline: float,
                         on_progress: Callable[[int, str], None],
                         label: str) -> Optional[Tuple[str, int]]:
        """Verify candidates across CPU worker processes.

        Returns ``(password or "", tested)``, or ``None`` when acceleration
        does not apply (not allowed, nothing preparable to verify against, or
        the pool would not start) — decided *before* the candidate iterator is
        touched, so the caller can fall back to the serial pass cleanly.
        """
        count = self._accel_workers()
        if count < 2:
            return None
        verifiers = self._verifiers(ap, capture, analysis)
        if not verifiers:
            return None
        pool = self._get_pool(count)
        if pool is None:
            return None
        self.bus.log(f"CPU acceleration: verifying with {count} worker process(es)",
                     level="info")
        tested = 0
        started = time.time()
        source = iter(self._deduped(candidates))
        inflight: set = set()
        exhausted = False
        try:
            while True:
                while not exhausted and len(inflight) < count * 2:
                    if time.time() > deadline:
                        exhausted = True
                        break
                    chunk = list(itertools.islice(source, 256))
                    if not chunk:
                        exhausted = True
                        break
                    inflight.add(pool.submit(_verify_chunk,
                                             (verifiers, ap.essid, chunk)))
                if not inflight:
                    break
                done, inflight = wait(inflight, timeout=0.25,
                                      return_when=FIRST_COMPLETED)
                for future in done:
                    hit, chunk_tested = future.result()
                    tested += chunk_tested
                    if hit:
                        rate = tested / max(0.001, time.time() - started)
                        self.bus.log(f"built-in engine (x{count} workers) cracked it "
                                     f"after {tested:,} candidates ({rate:,.0f}/s)",
                                     level="debug")
                        return hit, tested
                    on_progress(tested, label)
                if time.time() > deadline and not done:
                    break
        except Exception as exc:
            self.bus.log(f"parallel verify failed ({exc}); {tested:,} candidates "
                         f"were still tested", level="warning")
            self.close()          # a broken pool must not serve the next pass
        finally:
            for future in inflight:
                future.cancel()
        rate = tested / max(0.001, time.time() - started)
        self.bus.log(f"built-in engine tested {tested:,} candidates across "
                     f"{count} worker(s) ({rate:,.0f}/s)", level="debug")
        return "", tested

    def _python_pass(self, ap: AccessPoint, capture: Capture, analysis: CaptureAnalysis,
                     candidates: Sequence[str], deadline: float,
                     on_progress: Callable[[int, str], None]) -> Tuple[str, int]:
        """Verify ``candidates``; return ``(password or "", candidates verified)``.

        The count is what was really tested, not the length of the list: an early
        hit must not be reported (or logged) as a full sweep of the space.
        """
        if len(candidates) >= 128:
            parallel = self._verify_parallel(
                ap, capture, analysis, candidates, deadline, on_progress,
                "built-in engine (parallel)")
            if parallel is not None:
                return parallel
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

    def _rule_set(self) -> List[rules_module.Rule]:
        """The rule set the built-in engine applies to each word.

        ``config.rule_file`` may be a path to a hashcat ``.rule`` file or one of
        the built-in set names; either way the rules are applied in Python.  An
        unreadable file is reported once, not silently ignored.
        """
        spec = (self.config.rule_file or "").strip()
        if not spec:
            return []
        if os.path.exists(spec):
            loaded = rules_module.parse_file(spec)
            if not loaded:
                self.bus.log(f"rule file {spec} could not be parsed: no rules applied",
                             level="warning")
            return loaded
        preset = rules_module.preset(spec)
        if not preset and spec:
            self.bus.log(f"unknown rule set {spec!r} (try best64, leet, append-digits, "
                         f"case, or a path to a .rule file)", level="warning")
        return preset

    def _wordlist_candidates(self, lists: List[str], use_rules: bool,
                             rule_set: List[Any]) -> Iterator[str]:
        """Every candidate a wordlist sweep would try, rules included."""
        for wordlist in lists[:2]:
            for word in iter_wordlist(wordlist):
                yield word
                if use_rules:
                    if rule_set:
                        yield from rules_module.apply_rules(word, rule_set, limit=24)
                    else:
                        yield from rule_expand(word, limit=8)

    def _python_wordlist_pass_fast(self, ap: AccessPoint, capture: Capture,
                                   analysis: CaptureAnalysis, lists: List[str],
                                   deadline: float,
                                   on_progress: Callable[[int, str], None]
                                   ) -> Tuple[str, int]:
        """The accelerated sweep: de-duplicated candidates (RAM), verified
        across worker processes when CPU acceleration is allowed too."""
        use_rules = bool(self.config.use_rules)
        rule_set = self._rule_set() if use_rules else []
        stream = self._deduped(self._wordlist_candidates(lists, use_rules, rule_set))
        parallel = self._verify_parallel(
            ap, capture, analysis, stream, deadline, on_progress,
            "built-in dictionary sweep (parallel)")
        if parallel is not None:
            return parallel
        # RAM-only acceleration: still serial, but no candidate is paid for twice
        # (the parallel attempt returns None before touching the stream)
        tested = 0
        started = time.time()
        for candidate in stream:
            tested += 1
            if tested % 250 == 0:
                if time.time() > deadline:
                    return "", tested
                rate = tested / max(0.001, time.time() - started)
                on_progress(tested, f"built-in dictionary sweep (cached, {rate:,.0f}/s)")
            if self._verify(ap, capture, analysis, candidate):
                return candidate, tested
        self.bus.log(f"built-in dictionary sweep exhausted {tested:,} unique words",
                     level="debug")
        return "", tested

    def _python_wordlist_pass(self, ap: AccessPoint, capture: Capture,
                              analysis: CaptureAnalysis, lists: List[str],
                              deadline: float,
                              on_progress: Callable[[int, str], None]) -> Tuple[str, int]:
        """Sweep wordlists; return ``(password or "", words verified)``."""
        from .accel import accel_enabled
        if self._accel_workers() >= 2 or accel_enabled(self.config, "ram"):
            return self._python_wordlist_pass_fast(
                ap, capture, analysis, lists, deadline, on_progress)
        tested = 0
        started = time.time()
        use_rules = bool(self.config.use_rules)
        rule_set = self._rule_set() if use_rules else []
        if rule_set:
            self.bus.log(f"built-in engine: applying {len(rule_set)} rule(s) per word "
                         f"from {os.path.basename(self.config.rule_file) or 'preset'}",
                         level="debug")
        for wordlist in lists[:2]:
            name = Path(wordlist).name
            for word in iter_wordlist(wordlist):
                variants = [word]
                if use_rules:
                    if rule_set:
                        variants += list(rules_module.apply_rules(word, rule_set, limit=24))
                    else:
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
        # (wordlist_limit is applied in _crack_real so an explicit --wordlist wins)
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
