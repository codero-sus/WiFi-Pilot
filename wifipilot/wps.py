# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""WPS PIN arithmetic: the checksum, the published generators, and a plan.

Two facts drive everything here, and both are geometry rather than opinion:

* **the eighth digit is not free.**  WPS PINs carry a check digit, so the real
  space is 10^7, not 10^8.  Any candidate whose checksum does not match is a
  guaranteed failure — the tool must never spend an online attempt on one.
* **the PIN is verified in two halves** (first four digits, then the last four),
  which is why the documented online attack is ~11,000 attempts rather than
  10^7: a wrong first half is rejected early, and the last digit of the second
  half is determined by the checksum.

What this module will *not* do is pretend to know your router.  The
BSSID-derived generators below are published algorithms (``wpspin``,
``ComputePIN``); they are offered as *candidates with provenance and a
confidence label*, never as "the PIN".  A wrong guess that looks authoritative is
worse than no guess, so every candidate carries where it came from and the
caller can see it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Iterator, List, Sequence

__all__ = [
    "checksum", "complete_pin", "pin_is_valid", "default_pins", "bssid_pins",
    "vendor_pins", "candidate_pins", "pin_attempt_order", "attempt_plan",
    "WPS_PIN_TIMEOUTS",
]

#: how many attempts per second an online WPS PIN attack gets, per tool.  Used
#: only to turn an attempt count into a duration the operator can plan around;
#: real routers lock out, and the number is measured, not promised.
WPS_PIN_TIMEOUTS = {"default (2s per PIN, no lock-out)": 0.5}


# --------------------------------------------------------------------------- #
# the checksum
# --------------------------------------------------------------------------- #

def checksum(pin: str) -> int:
    """The WPS check digit for the first seven digits of ``pin``.

    Weights 3,1,3,1,3,1,3 (the published algorithm); the digit is
    ``(10 - total) % 10``.  ``00000000`` and ``12345670`` come out of this, and
    they are the two PINs every engagement tries first for exactly that reason.
    """
    digits = "".join(ch for ch in str(pin) if ch.isdigit())
    if len(digits) < 7:
        raise ValueError(f"a WPS PIN needs 7 digits to check, got {pin!r}")
    seven = digits[:7]
    total = sum(weight * int(digit) for weight, digit
                in zip((3, 1, 3, 1, 3, 1, 3), seven))
    return (10 - total % 10) % 10


def complete_pin(pin: str) -> str:
    """``pin`` padded to 7 digits with its check digit appended (8 digits)."""
    digits = "".join(ch for ch in str(pin) if ch.isdigit())[:7]
    if not digits:
        raise ValueError("empty PIN")
    seven = digits.zfill(7)
    return seven + str(checksum(seven))


def pin_is_valid(pin: str) -> bool:
    """True when the eighth digit is the checksum of the first seven."""
    digits = "".join(ch for ch in str(pin) if ch.isdigit())
    if len(digits) != 8:
        return False
    return int(digits[7]) == checksum(digits[:7])


# --------------------------------------------------------------------------- #
# candidates
# --------------------------------------------------------------------------- #

@dataclass
class PinCandidate:
    """One PIN, and where the idea for it came from."""

    pin: str
    source: str
    confidence: str = "heuristic"     # certain | likely | heuristic
    note: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {"pin": self.pin, "source": self.source,
                "confidence": self.confidence, "note": self.note}


#: PINs that are worth the first four attempts on any router: the two published
#: "blank" defaults, plus the patterns router vendors ship in bulk.
_DEFAULTS: Sequence[tuple] = (
    ("00000000", "blank/default PIN", "likely",
     "shipped by several vendors when the label is missing"),
    ("12345670", "sequential default PIN", "likely",
     "the classic default: 1234567 plus its check digit"),
    ("11111111", "repeated digit", "heuristic", "common 'we did not set it' value"),
    ("22222222", "repeated digit", "heuristic", "common 'we did not set it' value"),
    ("12345678", "sequential, ignored checksum", "heuristic",
     "invalid by checksum — kept because some firmware accepts it anyway"),
)


def default_pins(include_invalid: bool = False) -> List[PinCandidate]:
    """The PINs every engagement tries first, checksum-checked.

    ``include_invalid`` keeps entries a strict router would reject (some
    firmware does not validate the eighth digit at all) — flagged as such.
    """
    out: List[PinCandidate] = []
    for pin, source, confidence, note in _DEFAULTS:
        if not pin_is_valid(pin):
            if not include_invalid:
                continue
            note = f"{note}; fails the check digit"
            confidence = "heuristic"
        out.append(PinCandidate(pin, source, confidence, note))
    return out


def _numeric_bssid(bssid: str) -> str:
    return "".join(ch for ch in (bssid or "").lower() if ch in "0123456789abcdef")


def bssid_pins(bssid: str) -> List[PinCandidate]:
    """PINs derived from the BSSID, using the published generator family.

    * ``ComputePIN``: the last three octets (or the first three, on the older
      "NIC-based" variant) taken as a number, modulo 10^7, plus the check digit.
      Published in ``wpspin`` and reproduced by every WPS auditor since.
    * the same number zero-padded to 7, which some firmware stores literally.

    Both are *candidates*: the algorithm matches some models and not others, and
    there is no way to know which without trying.  Nothing here decides that the
    PIN *is* the value.
    """
    hexes = _numeric_bssid(bssid)
    if len(hexes) < 12:
        return []
    out: List[PinCandidate] = []
    for label, chunk in (("last three octets", hexes[6:12]),
                         ("first three octets", hexes[0:6])):
        value = int(chunk, 16)
        pin = complete_pin(str(value % 10_000_000))
        out.append(PinCandidate(
            pin, f"ComputePIN ({label})", "heuristic",
            f"0x{chunk.upper()} mod 10^7 — published algorithm, model-dependent"))
        plain = str(value % 10_000_000).zfill(7) + str(value % 10)
        if pin_is_valid(plain) and plain != pin:
            out.append(PinCandidate(plain, f"BSSID digits ({label})", "heuristic",
                                    "literal BSSID remainder with a naive check digit"))
    # the widely-seen "network byte" variants: last two octets as a decimal pair
    tail = int(hexes[8:12], 16)
    for candidate in (f"{tail:04d}0000", f"{tail:04d}1234"):
        pin = complete_pin(candidate)
        out.append(PinCandidate(pin, "BSSID tail + filler", "heuristic",
                                "four BSSID-derived digits followed by a filler block"))
    return _unique(out)


def vendor_pins(vendor: str = "", essid: str = "") -> List[PinCandidate]:
    """Default PINs a vendor/ISP is documented to ship, keyed off the name."""
    from .vendors import _key_for

    key = _key_for(vendor) or _key_for(essid)
    table = {
        "AVM": [("", "AVM firmware does not enable the WPS PIN by default",
                 "note", "")],
        "TP-Link": [("12345670", "TP-Link default PIN", "likely", "")],
        "Netgear": [("12345670", "NETGEAR default PIN", "likely", "")],
        "D-Link": [("12345670", "D-Link default PIN", "likely", "")],
        "Belkin": [("12345670", "Belkin default PIN", "likely", "")],
        "Linksys": [("12345670", "Linksys default PIN", "likely", "")],
        "Zyxel": [("12345670", "Zyxel default PIN", "likely", "")],
        "Huawei": [("12345670", "Huawei default PIN", "heuristic", "")],
        "MikroTik": [("", "RouterOS reports WPS state; PIN is set by the operator",
                      "note", "")],
        "Ubiquiti": [("", "UniFi access points do not expose WPS", "note", "")],
        "ARRIS": [("12345670", "ARRIS default PIN", "heuristic", "")],
    }.get(key, [])
    out: List[PinCandidate] = []
    for pin, source, confidence, note in table:
        if not pin:                                  # a "don't bother" note, not a PIN
            out.append(PinCandidate("", source, confidence,
                                    note or "no documented default"))
            continue
        if pin_is_valid(pin):
            out.append(PinCandidate(pin, source, confidence, note))
    return out


def candidate_pins(bssid: str = "", essid: str = "", vendor: str = "",
                   limit: int = 0) -> List[PinCandidate]:
    """Every PIN worth trying for this target, best-first and deduplicated.

    Order: documented vendor default, the two blank defaults, BSSID-derived
    candidates, then *findings* about firmware that does not validate the check
    digit.  Non-PIN notes (a vendor that ships WPS off, say) are returned too —
    they are the reason the list is short.
    """
    by_vendor = vendor_pins(vendor, essid)
    ordered: List[PinCandidate] = []
    ordered.extend(item for item in by_vendor if item.pin)
    if bssid or not vendor:
        ordered.extend(default_pins())
    ordered.extend(bssid_pins(bssid))
    ordered.extend(default_pins(include_invalid=True))
    notes = [item for item in by_vendor if not item.pin]
    seen: set = set()
    out: List[PinCandidate] = []
    for item in ordered:
        if item.pin in seen:
            continue
        seen.add(item.pin)
        out.append(item)
    out.extend(notes)
    return out[:limit] if limit else out


def _unique(items: Iterable[PinCandidate]) -> List[PinCandidate]:
    seen: set = set()
    out: List[PinCandidate] = []
    for item in items:
        if item.pin in seen:
            continue
        seen.add(item.pin)
        out.append(item)
    return out


# --------------------------------------------------------------------------- #
# the attempt plan
# --------------------------------------------------------------------------- #

def pin_attempt_order(prefer: Sequence[str] = (), first_half: str = ""
                      ) -> Iterator[str]:
    """Yield PINs in the order an online attack should spend attempts.

    * ``prefer`` first — the documented defaults and the derived candidates,
      checksum-checked like everything else here.
    * with a *confirmed* ``first_half`` (four digits): the 1,000 remaining
      possibilities for the second half, which is how a two-phase attack
      finishes in ~11,000 attempts instead of 10^7.
    * otherwise: the whole checksum-valid space, first-half-major, so a router
      that rejects a wrong first half costs one attempt per four candidates
      rather than a full PIN.

    Every yielded value is checksum-valid: the 90% that could never work are
    never attempted.
    """
    seen: set = set()
    for pin in prefer:
        digits = "".join(ch for ch in str(pin) if ch.isdigit())
        if len(digits) == 8 and pin_is_valid(digits) and digits not in seen:
            seen.add(digits)
            yield digits
    head = "".join(ch for ch in str(first_half) if ch.isdigit())
    if len(head) == 4:
        for middle in range(1_000):                 # second half, last digit derived
            pin = complete_pin(f"{head}{middle:03d}")
            if pin not in seen:
                seen.add(pin)
                yield pin
        return
    for prefix in range(10_000):                    # first-half-major sweep
        for middle in range(1_000):
            pin = complete_pin(f"{prefix:04d}{middle:03d}")
            if pin not in seen:
                seen.add(pin)
                yield pin


def attempt_plan(bssid: str = "", essid: str = "", vendor: str = "",
                 seconds_per_attempt: float = 2.0, max_attempts: int = 0
                 ) -> Dict[str, object]:
    """What a WPS PIN run would look like, without running it.

    The numbers are the point: a candidate list you can actually reach beats a
    "brute force the PIN" that would take 231 days.
    """
    candidates = candidate_pins(bssid, essid, vendor)
    runnable = [item for item in candidates if item.pin]
    full_space = 10 ** 8                                   # every 8-digit value
    valid_space = 10 ** 7                                  # minus the check digit
    first_half = 10 ** 4                                   # sweep the first half
    second_half = 10 ** 3                                  # then complete it
    optimised = first_half + second_half
    return {
        "candidates": [item.to_dict() for item in candidates],
        "runnable": len(runnable),
        "notes": [item.to_dict() for item in candidates if not item.pin],
        "spaces": {
            "every 8-digit value": full_space,
            "checksum-valid PINs": valid_space,
            "two-half sweep (the documented attack)": optimised,
            "candidates above": len(runnable),
        },
        "seconds": {
            "two-half sweep": round(optimised * seconds_per_attempt, 1),
            "checksum-valid space": round(valid_space * seconds_per_attempt, 1),
            "candidates above": round(len(runnable) * seconds_per_attempt, 1),
        },
        "seconds_per_attempt": seconds_per_attempt,
        "note": ("routers lock out or rate-limit; these are attempt counts, not a "
                 "promise, and a PIN attempt is transmitted traffic — it needs the "
                 "same authorisation as any active attack"),
        "max_attempts": max_attempts,
    }
