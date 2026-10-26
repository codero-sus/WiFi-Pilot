# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Precomputed PMKs: hashcat mode 22001, and a cache that saves whole campaigns.

A PMK depends on the passphrase *and the ESSID* — which makes it reusable: the
same network captured three times needs one crack, not three.  This module does
two things with that:

* reads and writes mode **22001** files (the same lines as 22000 with the PMK in
  place of the hash material), so a PMK cracked here can be handed to hashcat and
  vice versa; and
* keeps a small on-disk **PMK cache** (one file per session directory, keyed by
  ESSID+PSK so it can be verified before it is trusted), which the cracker
  consults before it spends a single PBKDF2 round.

Nothing is believed because it is in the cache: every entry is re-derived (PMKID
or MIC) against the capture before a password is reported.  A corrupted or
hand-edited cache entry therefore costs a verification, not a false finding.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import hash22000
from .crypto import pmk
from .util import mac_norm, read_json, write_json

__all__ = ["PMK_CACHE_NAME", "pmk_for", "line_to_22001", "convert_to_22001",
           "read_pmk_file", "verify_pmk", "PMKCache"]

#: where the cache lives inside a session directory
PMK_CACHE_NAME = "pmk-cache.json"

#: hashcat's mode for "the PMK is already known"
MODE_PMK = 22001


def pmk_for(psk: str, essid: str) -> bytes:
    """``PBKDF2-SHA1(psk, essid, 4096, 32)`` — the definition, in one place."""
    return pmk(psk, essid)


def _verifier_for(line: "hash22000.HashLine"):
    """The cracker's own verifier for this line (mode 22000 -> MIC/PMKID check).

    Built on :func:`wifipilot.hash22000.verifiers` on purpose: the KDV -> MIC
    algorithm mapping and the nonce handling live there, and a second copy in
    this module is exactly how a "verified" password turns out to be wrong.
    """
    verifiers = hash22000.verifiers([line])
    return verifiers[0] if verifiers else None


def _pmk_matches(line: "hash22000.HashLine", pmk_bytes: bytes) -> bool:
    verifier = _verifier_for(line)
    return bool(verifier is not None and verifier.check_pmk(pmk_bytes))


def verify_pmk(pmk_hex: str, line: "hash22000.HashLine") -> bool:
    """True when this PMK produces the line's PMKID or MIC.

    This is the only reason the cache is safe to trust: an entry either
    reproduces the cryptographic value in the capture or it is ignored.
    """
    try:
        raw = bytes.fromhex(str(pmk_hex).strip())
    except (TypeError, ValueError):
        return False
    if len(raw) != 32:
        return False
    return _pmk_matches(line, raw)


def verify_psk(psk: str, line: "hash22000.HashLine") -> bool:
    """True when this passphrase produces the line's PMKID or MIC.

    The "did I already find this one?" question, answered without a crack: it
    costs one PBKDF2 derivation, not a candidate sweep.
    """
    if not (8 <= len(psk) <= 63):
        return False
    return _pmk_matches(line, pmk_for(psk, line.essid))


# --------------------------------------------------------------------------- #
# mode 22001
# --------------------------------------------------------------------------- #

def line_to_22001(line: "hash22000.HashLine", pmk_hex: str) -> str:
    """Render ``line`` as a mode-22001 line: same fields, PMK instead of hash.

    hashcat's format is byte-compatible with 22000 — the second field carries the
    32-byte PMK the candidate must match — which is why a PMK cracked once can be
    fed straight back in as a candidate for any other capture of the same
    network.
    """
    essid = line.essid_bytes.hex()
    ap = (line.bssid or "").replace(":", "").lower()
    station = (line.station or "").replace(":", "").lower()
    digest = str(pmk_hex).strip().lower()
    if line.kind == "pmkid":
        return f"WPA*01*{digest}*{ap}*{station}*{essid}***"
    return (f"WPA*02*{digest}*{ap}*{station}*{essid}*{line.nonce.hex().lower()}"
            f"*{line.eapol.hex().lower()}*{line.message_pair:02x}")


def verify_psk_against(psk: str, path: str, essid: str = "") -> Dict[str, Any]:
    """Check a PSK against every line of a capture or hash file.

    The one question that matters after a wordlist run reported a plaintext:
    does this passphrase actually verify against *this* capture?  A cracker that
    printed a candidate it never verified is a common enough failure mode that
    the answer deserves a command of its own.
    """
    if hash22000.is_hash_file(path):
        lines = hash22000.parse_file(path)
    else:
        from .pcap import analyze_file
        analysis = analyze_file(path, max_packets=100_000)
        lines = hash22000.parse_text(
            "\n".join(hash22000.lines_from_analysis(analysis)))[0]
    wanted = (essid or "").strip()
    usable = [line for line in lines
              if not wanted or (line.essid or "").strip() == wanted]
    checked = 0
    for line in usable:
        if not line.essid and not wanted:
            continue
        checked += 1
        if verify_psk(psk, line):
            return {"ok": True, "lines": checked, "total": len(usable),
                    "essids": sorted({line.essid for line in usable if line.essid}),
                    "matched": {"essid": line.essid, "bssid": line.bssid,
                                "kind": line.kind}}
    return {"ok": False, "lines": checked, "total": len(usable),
            "essids": sorted({line.essid for line in usable if line.essid}),
            "matched": {}}


def _is_hex(value: str) -> bool:
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def raw_22001_lines(path: str) -> List[str]:
    """The lines of a file that *already* carry a PMK (field 2 is 32 bytes).

    A 22001 file is not a 22000 file: the hash slot holds the PMK instead of a MIC,
    which is exactly what makes it unparseable by the mode-22000 reader.  Round
    tripping one therefore has to be a text-level copy, not a re-parse.
    """
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out: List[str] = []
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw.upper().startswith("WPA*"):
            continue
        fields = raw.split("*")
        if len(fields) >= 9 and len(fields[2]) == 64 and _is_hex(fields[2]):
            out.append(raw)
    return out


def convert_to_22001(path: str, out: str = "", pmk_hex: str = "", psk: str = "",
                     essid: str = "") -> Dict[str, Any]:
    """Convert a capture or 22000 hash file to mode 22001.

    A PMK comes from one of three places: ``pmk_hex`` (already known), ``psk``
    (derived here — PBKDF2 over the ESSID) or nowhere, in which case the converter
    only rewrites lines that already carry a PMK, which makes a round trip
    loss-free.
    """
    if not psk and not pmk_hex:
        # already mode 22001 (or a mix): copy what carries a PMK, verbatim
        existing = raw_22001_lines(path)
        if existing:
            target = out or (os.path.splitext(path)[0] + f"-m{MODE_PMK}.hc22001")
            hash22000.write_lines(existing, target)
            return {"path": target, "lines": len(existing), "written": len(existing),
                    "mode": MODE_PMK, "needs_pmk": False,
                    "note": "already mode 22001: copied verbatim"}
    if psk:
        if not essid:
            from .pcap import analyze_file as _analyze
            if hash22000.is_hash_file(path):
                first = next((line.essid for line in hash22000.parse_file(path)
                              if line.essid), "")
            else:
                analysis = _analyze(path, max_packets=60_000)
                first = next((name for name in analysis.essids.values() if name), "")
            essid = first
        if not essid:
            return {"path": "", "lines": 0, "mode": MODE_PMK, "needs_pmk": True,
                    "note": "no ESSID: a PMK cannot be derived without the network name"}
        pmk_hex = pmk_for(psk, essid).hex()
    if hash22000.is_hash_file(path):
        lines = hash22000.parse_file(path)
    else:
        from .pcap import analyze_file
        analysis = analyze_file(path, max_packets=100_000)
        lines = hash22000.parse_text(
            "\n".join(hash22000.lines_from_analysis(analysis)))[0]
    if not lines:
        return {"path": "", "lines": 0, "mode": MODE_PMK, "needs_pmk": not pmk_hex,
                "note": "no usable handshake or PMKID in that file"}
    if pmk_hex:
        rendered = [line_to_22001(line, pmk_hex) for line in lines]
    else:
        rendered = [line.raw for line in lines]
    target = out or (os.path.splitext(path)[0] + f"-m{MODE_PMK}.hc22001")
    hash22000.write_lines(rendered, target)
    return {"path": target, "lines": len(rendered), "written": len(rendered),
            "mode": MODE_PMK, "needs_pmk": not pmk_hex,
            "note": ("pass lines to hashcat with -m 22001" if pmk_hex else
                     "no PMK supplied: only lines that already carry one were written")}


def _mac_field(value: str) -> str:
    """A MAC as mode 22000/22001 stores it (bare hex) -> dotted form.

    ``util.mac_norm`` deliberately only accepts punctuated MACs, and these formats
    are unpunctuated, so the twelve hex digits have to be grouped here.
    """
    digits = "".join(ch for ch in str(value) if ch in "0123456789abcdefABCDEF")
    if len(digits) == 12:
        return ":".join(digits[index:index + 2].lower() for index in range(0, 12, 2))
    return mac_norm(value)


def read_pmk_file(path: str) -> List[Dict[str, Any]]:
    """Read a 22001 file: ``[{pmk, bssid, station, essid, kind, raw}]``."""
    out: List[Dict[str, Any]] = []
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for number, raw in enumerate(text.splitlines(), start=1):
        raw = raw.strip()
        if not raw or raw.startswith("#") or not raw.upper().startswith("WPA*"):
            continue
        fields = raw.split("*")
        # type 01 is 10 fields (three empty ones after the ESSID), type 02 is 9
        if len(fields) < 9 or fields[1] not in ("01", "02"):
            continue
        try:
            essid = bytes.fromhex(fields[5]).decode("utf-8", "replace")
        except ValueError:
            essid = ""
        out.append({
            "pmk": fields[2].strip().lower(), "kind": "pmkid" if fields[1] == "01" else "eapol",
            "bssid": _mac_field(fields[3]), "station": _mac_field(fields[4]),
            "essid": essid, "line": number, "raw": raw,
        })
    return out


# --------------------------------------------------------------------------- #
# the cache
# --------------------------------------------------------------------------- #

@dataclass
class CacheEntry:
    essid: str
    psk: str
    pmk: str
    source: str = ""
    created: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {"essid": self.essid, "psk": self.psk, "pmk": self.pmk,
                "source": self.source, "created": self.created}


class PMKCache:
    """ESSID -> PMK for one engagement directory, verified before it is used.

    The key is the **ESSID**, not the BSSID: a network that renamed its AP but
    kept the passphrase, or a mesh of APs sharing one SSID, all derive the same
    PMK, so a hit anywhere pays for every capture of that SSID.  A BSSID-keyed
    cache would miss exactly the case that saves the most time.
    """

    def __init__(self, directory: str = "", path: str = "") -> None:
        self.path = path or (os.path.join(directory, PMK_CACHE_NAME) if directory else "")
        self._entries: Dict[str, CacheEntry] = {}
        self._loaded = False

    # -- storage ------------------------------------------------------- #
    def load(self) -> "PMKCache":
        if self.path and not self._loaded:
            for item in (read_json(self.path, {}) or {}).get("entries", []):
                entry = CacheEntry(essid=str(item.get("essid", "")),
                                   psk=str(item.get("psk", "")),
                                   pmk=str(item.get("pmk", "")),
                                   source=str(item.get("source", "")),
                                   created=float(item.get("created") or 0.0))
                if entry.essid and entry.pmk:
                    self._entries[entry.essid] = entry
        self._loaded = True
        return self

    def save(self) -> str:
        if not self.path:
            return ""
        return write_json(self.path, {
            "note": "PMKs learned in this engagement (ESSID-keyed; re-verified on use)",
            "entries": [entry.to_dict() for _, entry in sorted(self._entries.items())],
        })

    # -- use ----------------------------------------------------------- #
    def remember(self, essid: str, psk: str, pmk_hex: str = "", source: str = ""
                 ) -> CacheEntry:
        """Record a PMK (derived from the PSK when not given)."""
        digest = pmk_hex or (pmk_for(psk, essid).hex() if psk else "")
        entry = CacheEntry(essid=essid, psk=psk, pmk=digest.lower(),
                           source=source, created=time.time())
        if essid and digest:
            self._entries[essid] = entry
            self.save()
        return entry

    def lookup(self, essid: str, line: "hash22000.HashLine" = None) -> Optional[CacheEntry]:
        """The cached PMK for ``essid`` — verified against ``line`` when given."""
        entry = self._entries.get(essid)
        if entry is None:
            return None
        if line is not None and not verify_pmk(entry.pmk, line):
            # a stale or corrupted entry must cost one verification, never a
            # wrong password in the report
            return None
        return entry

    def entries(self) -> List[CacheEntry]:
        return [self._entries[key] for key in sorted(self._entries)]

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, essid: str) -> bool:
        return essid in self._entries
