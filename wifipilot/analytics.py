"""Password analytics: how weak is what we just cracked, and what is it?

A recovered PSK is a finding, but "12345678" and "gT7#pQ2!xLm9" are not the same
finding.  This module classifies a passphrase (pattern family, character
classes, search-space size) and estimates what it would cost to crack from
scratch — on the built-in engine, on a CPU hashcat, and on a GPU — so reports
can say *how* bad a password is instead of just that it was recovered.

It also carries the heuristics that turn "ESSID + vendor" into candidate masks
and words: the default schemes ISPs actually ship (a vendor prefix plus four
digits, ten digits from the serial number, sixteen hex characters, ...).  Those
are heuristics, not facts, and are labelled as such wherever they are shown.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

__all__ = [
    "password_report", "weakness_score", "crack_time", "SPEEDS",
    "DEFAULT_PATTERNS", "vendor_patterns", "guess_vendor", "identify",
]

#: guesses per second, from measurable wifipilot/hashcat figures (see README)
SPEEDS: Dict[str, float] = {
    "wifipilot (built-in, PBKDF2 in Python)": 415.0,
    "hashcat (CPU, WPA mode 22000)": 100_000.0,
    "hashcat (one mid-range GPU)": 1_000_000.0,
    "hashcat (GPU farm, 8 cards)": 8_000_000.0,
}

_KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890")
_KEYBOARD_WALKS = {row[index:index + 8] for row in _KEYBOARD_ROWS
                   for index in range(0, max(1, len(row) - 6))}

_DATE_RE = re.compile(r"(19|20)\d{2}")
_ALNUM = re.compile(r"^[A-Za-z0-9]+$")


def _charset_size(password: str) -> int:
    size = 0
    if any(c.islower() for c in password):
        size += 26
    if any(c.isupper() for c in password):
        size += 26
    if any(c.isdigit() for c in password):
        size += 10
    if any(not c.isalnum() for c in password):
        size += 33
    return size or 1


#: the substitutions people actually make, and what they stand for
_LEET_MAP = {"@": "a", "0": "o", "1": "l", "3": "e", "$": "s", "5": "s",
             "7": "t", "4": "a", "!": "i", "8": "b", "9": "g", "+": "t"}


def _looks_like_leet(password: str) -> bool:
    """True when substituting the classics turns this back into a plain word.

    ``p@ssw0rd`` -> ``password`` (yes), ``sunshine!`` -> ``sunshinei``: the only
    substitution is punctuation at the very end, which is a suffix, not leet.
    """
    if not any(char.isalpha() for char in password):
        return False
    substitutions = [index for index, char in enumerate(password) if char in _LEET_MAP]
    if not substitutions:
        return False
    if all(index == len(password) - 1 for index in substitutions):
        return False
    decoded = "".join(_LEET_MAP.get(char, char) for char in password)
    return decoded.isalpha()


def _patterns(password: str) -> List[str]:
    """Pattern families a password belongs to (a heuristic, and it says so)."""
    families: List[str] = []
    lowered = password.lower()
    if password.isdigit() and len(password) >= 8:
        families.append("all digits (ISP default numbering)")
    if _DATE_RE.search(password):
        families.append("contains a year")
    if any(walk in lowered for walk in _KEYBOARD_WALKS):
        families.append("keyboard walk")
    if _looks_like_leet(password):
        families.append("leet substitutions")
    if re.search(r"(.)\1{2,}", password):
        families.append("repeated characters")
    if lowered.startswith(("password", "admin", "welcome", "wifi", "internet", "guest")):
        families.append("dictionary default")
    if re.search(r"(.)\1$", password):
        families.append("doubled tail")
    if password[-1:].isdigit():
        families.append("trailing digits")
    if len(password) >= 16 and not families:
        families.append("long, no obvious structure")
    return families or ["no obvious pattern"]


@dataclass
class PasswordReport:
    password: str
    length: int
    classes: str
    entropy_bits: float
    space: float
    patterns: List[str] = field(default_factory=list)
    score: int = 0                # 0 (worst) .. 100 (best)
    verdict: str = ""
    times: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "password": self.password, "length": self.length, "classes": self.classes,
            "entropy_bits": round(self.entropy_bits, 1), "space": self.space,
            "patterns": self.patterns, "score": self.score, "verdict": self.verdict,
            "seconds": {name: round(value, 3) for name, value in self.times.items()},
        }


def crack_time(space: float, speed: float) -> float:
    """Average-case seconds to exhaust a space at ``speed`` guesses/second."""
    if speed <= 0:
        return float("inf")
    return max(space, 1) / (2.0 * speed)


def weakness_score(password: str, patterns: Sequence[str]) -> Tuple[int, str]:
    """0–100 where 100 is 'a long random password'; the verdict explains it."""
    length = len(password)
    score = min(60, int((length - 7) * 6))                    # length dominates
    score += {1: 0, 2: 6, 3: 14, 4: 22}.get(
        sum(1 for check in (any(c.islower() for c in password),
                            any(c.isupper() for c in password),
                            any(c.isdigit() for c in password),
                            any(not c.isalnum() for c in password)) if check), 0)
    if "all digits (ISP default numbering)" in patterns:
        score = min(score, 20)
    if "dictionary default" in patterns:
        score = min(score, 15)
    if "keyboard walk" in patterns:
        score = min(score, 25)
    score = max(0, min(100, score))
    if score < 20:
        verdict = "trivially guessable — the vendor's own default scheme"
    elif score < 40:
        verdict = "weak: a targeted candidate list finds this in seconds"
    elif score < 60:
        verdict = "moderate: survives a quick sweep, not a GPU"
    elif score < 80:
        verdict = "strong for a consumer network"
    else:
        verdict = "strong: not reachable by dictionary or mask attacks"
    return score, verdict


def password_report(password: str) -> PasswordReport:
    """Classify one passphrase and estimate its cracking cost."""
    patterns = _patterns(password)
    score, verdict = weakness_score(password, patterns)
    # a password matching a known scheme is *not* charset^length candidates: an
    # 8-digit ISP default is 10^8, even though its entropy looks like 10^8 too —
    # the difference shows up for "sunshine2024", which is ~7.5 million
    # word+year combinations, not 62^12.
    space = float(_charset_size(password)) ** max(1, len(password))
    if "all digits (ISP default numbering)" in patterns:
        space = float(10 ** min(len(password), 18))
    elif "dictionary default" in patterns:
        space = 1_000_000.0                    # a big wordlist plus rules
    elif "contains a year" in patterns and len(password) <= 16:
        space = min(space, 5_000_000.0)
    elif "keyboard walk" in patterns:
        space = min(space, 50_000.0)
    space = max(1.0, min(space, 95.0 ** 63))
    theoretical = math.log2(space)
    return PasswordReport(
        password=password, length=len(password),
        classes="".join(("l" if any(c.islower() for c in password) else "",
                         "u" if any(c.isupper() for c in password) else "",
                         "d" if any(c.isdigit() for c in password) else "",
                         "s" if any(not c.isalnum() for c in password) else "")) or "?",
        entropy_bits=theoretical, space=space, patterns=patterns,
        score=score, verdict=verdict,
        times={name: crack_time(space, speed) for name, speed in SPEEDS.items()},
    )


# --------------------------------------------------------------------------- #
# default-pattern heuristics (ESSID + vendor -> candidates)
# --------------------------------------------------------------------------- #

def _data_path() -> Path:
    return Path(__file__).with_name("data") / "default-patterns.json"


def _load_defaults() -> Dict[str, object]:
    try:
        with open(_data_path(), "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {"vendors": {}, "isps": {}, "notes": ""}


DEFAULT_PATTERNS: Dict[str, object] = _load_defaults()


def _entries(kind: str) -> Dict[str, Dict[str, object]]:
    section = DEFAULT_PATTERNS.get(kind) or {}
    return section if isinstance(section, dict) else {}


def _tokens(text: str) -> List[str]:
    return [token for token in re.split(r"[^A-Za-z0-9]+", (text or "").lower()) if token]


def vendor_patterns(*hints: str) -> Dict[str, object]:
    """Default-pattern entry for the first hint that matches a known vendor/ISP.

    Matching is on lower-cased tokens: ``"AVM GmbH"`` matches the ``fritz``
    entry because of the vendor's product name, ``"TP-LINK_1A2B"`` matches
    ``tp-link`` because of the ESSID prefix.
    """
    words: List[str] = []
    for hint in hints:
        words.extend(_tokens(hint))
        words.append((hint or "").lower())
    for kind in ("vendors", "isps"):
        for key, entry in _entries(kind).items():
            key_tokens = _tokens(key) + [str(alias).lower()
                                         for alias in (entry.get("aliases") or [])]
            for word in words:
                if not word:
                    continue
                if any(word == token or token in word or word in token
                       for token in key_tokens if token):
                    merged = dict(entry)
                    merged["key"] = key
                    merged["kind"] = kind
                    merged["matched"] = word
                    return merged
    return {}


def guess_vendor(essid: str, bssid: str = "") -> str:
    """A best-effort vendor/ISP guess from an ESSID prefix or the BSSID's OUI."""
    from .util import oui_vendor
    if essid:
        entry = vendor_patterns(essid)
        if entry:
            return str(entry.get("label") or entry.get("key") or "")
    if bssid:
        vendor = oui_vendor(bssid)
        if vendor:
            entry = vendor_patterns(vendor)
            if entry:
                return str(entry.get("label") or entry.get("key") or "")
        return vendor
    return ""


def identify(essid: str = "", bssid: str = "") -> Dict[str, object]:
    """Everything wifipilot can guess about a target, and what it would try."""
    from .masks import suggest_masks

    vendor = guess_vendor(essid, bssid)
    entry = vendor_patterns(essid, vendor, bssid)
    patterns = [str(item) for item in (entry.get("masks") or [])]
    words = [str(item) for item in (entry.get("words") or [])]
    masks = suggest_masks(essid, vendor)
    if patterns:
        from .masks import Mask, MaskError
        for pattern in patterns:
            try:
                mask = Mask(pattern, f"known default scheme ({entry.get('key')})")
            except MaskError:
                continue
            if mask.usable and all(mask.pattern != existing.pattern for existing in masks):
                masks.append(mask)
        masks.sort(key=lambda mask: mask.space)
    return {
        "essid": essid, "bssid": bssid, "vendor": vendor,
        "scheme": entry.get("key", ""), "scheme_note": entry.get("note", ""),
        "confidence": "heuristic" if entry else "guess",
        "masks": [mask.to_dict() for mask in masks],
        "words": words,
        "advice": (entry.get("advice") or
                   "no known default scheme for this name: try the derived masks, "
                   "then a wordlist"),
    }
