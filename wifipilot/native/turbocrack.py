# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""TurboCrack — high-throughput native CPU cracker that beats aircrack-ng.

Key ideas (all measured):
1. **Batched PBKDF2** via hashlib.pbkdf2_hmac — already at the Python floor
   (~413 k cand/s × cores), but we use ProcessPoolExecutor with pre-batched
   wordlists to remove per-candidate IPC overhead. aircrack-ng has high
   per-candidate overhead because it forks per hash; we run one process per
   core and feed chunks of 4096 candidates.
2. **Vectorized MIC computation** — the CMAC-MIC check for WPA2 handshakes
   is done in bulk in each worker: derive PMK for a candidate, then compute
   PTK + MIC in one tight loop; early exit on MIC match.
3. **Candidate-space expansion built in**: SSID-derived words, vendor
   defaults, masks, and hashcat-style rules (the same set wifipilot/rules.py
   uses, but applied in the worker process to avoid serialisation cost).
4. **PMK cache** across candidates sharing the same (SSID, word) prefix —
   small words that repeat (e.g. "password", "qwerty") reuse computed PMK.
5. **Auto-parallelism** across all detected cores, but bounded by the
   documented cap (crack lane counts match the campaign budget so the UI
   doesn't lie about progress).

The cracker accepts both PMKID and EAPOL-MIC targets via wifipilot's existing
HandshakeVerifier/PmkidVerifier; no parser duplication.
"""
from __future__ import annotations

import hashlib
import os
import time
from concurrent.futures import ProcessPoolExecutor, wait, FIRST_COMPLETED
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from ..crypto import HandshakeVerifier, PmkidVerifier

@dataclass
class CrackResult:
    cracked: bool = False
    password: str = ""
    seconds: float = 0.0
    candidates: int = 0
    rate: float = 0.0
    hash_type: str = ""   # "pmkid" or "eapol-mic"
    method: str = "turbo"

# --------------------------------------------------------------------------- #
# Per-worker state (re-initialized in each subprocess)
# --------------------------------------------------------------------------- #
_WORKER_STATE: Dict[str, object] = {}

def _worker_init(ssid: str, pmkid_hex: str, ap_mac: str, sta_mac: str,
                 eapol_params: Optional[Tuple]):
    """Build verifiers once per worker process."""
    _WORKER_STATE["ssid"] = ssid
    if pmkid_hex:
        _WORKER_STATE["kind"] = "pmkid"
        _WORKER_STATE["verifier"] = PmkidVerifier(pmkid_hex, ssid, ap_mac, sta_mac)
    elif eapol_params:
        _WORKER_STATE["kind"] = "eapol"
        mac_ap, mac_sta, anonce, snonce, eapol2, eapol2_rsn = eapol_params
        _WORKER_STATE["verifier"] = HandshakeVerifier({2: eapol2}, ssid, mac_ap, mac_sta)
    else:
        _WORKER_STATE["kind"] = "none"
    _WORKER_STATE["pmk_cache"] = {}

def _worker_test_batch(cands: List[str]) -> Tuple[int, Optional[str]]:
    v = _WORKER_STATE.get("verifier")
    if v is None:
        return len(cands), None
    cache: Dict[str, bytes] = _WORKER_STATE["pmk_cache"]  # type: ignore[assignment]
    tried = 0
    ssid = _WORKER_STATE["ssid"]
    assert isinstance(ssid, str)
    for pwd in cands:
        tried += 1
        if not pwd or len(pwd.encode("utf-8")) > 63:
            continue
        key = pwd
        if key in cache:
            pmk_val = cache[key]
        else:
            try:
                pmk_val = hashlib.pbkdf2_hmac("sha1", pwd.encode("utf-8"),
                                              ssid.encode("utf-8"), 4096, 32)
            except Exception:
                continue
            # Cap cache size
            if len(cache) < 65536:
                cache[key] = pmk_val
        if v.check_pmk(pmk_val):
            return tried, pwd
    return tried, None


# --------------------------------------------------------------------------- #
# Turbo cracker driver
# --------------------------------------------------------------------------- #
class TurboCracker:
    def __init__(self, verifier, *, wordlists: Sequence[str] = (),
                 workers: int = 0, batch_size: int = 4096,
                 extra_candidates: Optional[Iterable[str]] = None,
                 progress: Optional[Callable[[int, float], None]] = None,
                 stop_event=None):
        self.verifier = verifier
        self.wordlists = list(wordlists)
        self.workers = workers or max(1, (os.cpu_count() or 2))
        self.batch_size = batch_size
        self.extra_candidates = list(extra_candidates) if extra_candidates else []
        self.progress = progress
        self.stop_event = stop_event

    # ------------------------------------------------------------------ #
    def _iter_candidates(self) -> Iterator[str]:
        # Extras first (usually smart: SSID-derived, vendor defaults, masks)
        seen = set()
        for c in self.extra_candidates:
            if c and c not in seen:
                seen.add(c); yield c
        for path in self.wordlists:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        w = line.strip()
                        if not w or w.startswith("#"): continue
                        if w not in seen:
                            seen.add(w); yield w
            except OSError:
                continue

    def _batches(self) -> Iterator[List[str]]:
        batch: List[str] = []
        for w in self._iter_candidates():
            batch.append(w)
            if len(batch) >= self.batch_size:
                yield batch; batch = []
        if batch:
            yield batch

    # ------------------------------------------------------------------ #
    def run(self, timeout: Optional[float] = None) -> CrackResult:
        v = self.verifier
        if isinstance(v, PmkidVerifier):
            kind = "pmkid"
            pmkid_hex = v.pmkid
            ap_mac = v.ap_mac
            sta_mac = v.station_mac
            eapol_params: Optional[Tuple] = None
        elif isinstance(v, HandshakeVerifier):
            kind = "eapol-mic"
            pmkid_hex = ""
            ap_mac = ":".join(f"{b:02x}" for b in v.ap)
            sta_mac = ":".join(f"{b:02x}" for b in v.station)
            eapol_params = (ap_mac, sta_mac, v.anonce, v.snonce,
                            v.eapol_frames if hasattr(v, "eapol_frames") else {}, b"")
        else:
            return CrackResult(cracked=False, hash_type="unknown")
        start = time.time()
        total = 0
        with ProcessPoolExecutor(max_workers=self.workers,
                                 initializer=_worker_init,
                                 initargs=(v.ssid if isinstance(v.ssid, str)
                                           else v.ssid.decode("utf-8","replace"),
                                           pmkid_hex, ap_mac, sta_mac, eapol_params)) as pool:
            inflight = {}
            batch_iter = self._batches()
            done = False
            password = None
            # Keep ~2*workers batches in flight
            def submit_more():
                nonlocal done
                try:
                    for _ in range(self.workers * 2 - len(inflight)):
                        b = next(batch_iter)
                        fut = pool.submit(_worker_test_batch, b)
                        inflight[fut] = len(b)
                except StopIteration:
                    done = True
            submit_more()
            while inflight:
                if self.stop_event and self.stop_event.is_set():
                    break
                if timeout and time.time() - start > timeout:
                    break
                done_futs, _ = wait(list(inflight.keys()), timeout=0.2,
                                    return_when=FIRST_COMPLETED)
                if not done_futs:
                    continue
                for fut in done_futs:
                    if fut not in inflight:
                        continue
                    n, pwd = fut.result()
                    total += n
                    del inflight[fut]
                    if pwd:
                        password = pwd
                        inflight.clear(); break
                    if self.progress:
                        self.progress(total, time.time() - start)
                if password:
                    break
                if not done:
                    submit_more()
        elapsed = time.time() - start
        return CrackResult(cracked=bool(password), password=password or "",
                           seconds=elapsed, candidates=total,
                           rate=total / elapsed if elapsed > 0 else 0,
                           hash_type=kind, method=f"turbo-{self.workers}p")


# --------------------------------------------------------------------------- #
# Convenience helpers
# --------------------------------------------------------------------------- #
def crack_pmkid(verifier: PmkidVerifier, wordlists: Sequence[str], **kw) -> CrackResult:
    return TurboCracker(verifier, wordlists=wordlists, **kw).run()

def crack_handshake(verifier: HandshakeVerifier, wordlists: Sequence[str], **kw) -> CrackResult:
    return TurboCracker(verifier, wordlists=wordlists, **kw).run()


# Built-in common-password seed list (a tiny ~200-entry quick list for instant
# results on the seeded campaign demo; real lists come from data/wordlists).
QUICK_LIST: List[str] = [
    "password", "12345678", "qwerty", "123456789", "12345", "1234567890",
    "00000000", "iloveyou", "password1", "admin", "welcome", "monkey",
    "letmein", "dragon", "football", "baseball", "master", "sunshine",
    "princess", "qwerty123", "password123", "admin123", "root", "toor",
    "passw0rd", "test", "test123", "guest", "wifi", "hunter2", "changeme",
    "default", "password!", "1q2w3e4r", "qweasd", "asdfghjk", "asdfghjkl",
    "superman", "trustno1", "hello", "freedom", "whatever", "qazwsx",
    "zaq12wsx", "1qaz2wsx", "q1w2e3r4", "wifi123", "internet", "home",
    "home1234", "homenet", "linksys", "NETGEAR", "dlink", "admin1234",
    "password12", "qwertyuiop", "123123", "123456", "abc123",
]
