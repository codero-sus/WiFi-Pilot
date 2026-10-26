# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Mask attacks: hashcat-style ``?d`` patterns, expanded locally or handed over.

Most ISP routers ship a *pattern* password — ``Telekom-0000`` to
``Telekom-9999``, a ten-digit number, the vendor name plus four digits.  A
dictionary will not hold those, and enumerating them by hand is not a
candidate space anyone wants to type out.  A mask is that space written down:
``Telekom-?d?d?d?d`` is 10,000 candidates, ``?d?d?d?d?d?d?d?d`` is 100 million.

wifipilot supports the hashcat charset tokens (``?l ?u ?d ?s ?a ?b``, with
``??`` for a literal question mark) in three places:

* ``suggest_masks()`` derives the patterns worth trying from the target itself
  (ESSID prefixes, vendor tokens, ISP numeric defaults);
* the built-in engine expands them, but only the ones that fit its candidate
  budget — a 100-million space is split honestly rather than half-swept
  silently (see :func:`select_masks`);
* hashcat gets them as ``-a 3`` jobs, which is where a big mask belongs.

Because WPA passphrases are 8–63 characters, a mask that cannot reach 8
characters is meaningless and is dropped.
"""

from __future__ import annotations

import itertools
import re
import string
from dataclasses import dataclass
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

__all__ = [
    "CHARSETS", "MIN_PASSPHRASE", "MAX_PASSPHRASE", "MaskError", "Mask",
    "parse_mask", "mask_space", "expand_mask", "suggest_masks", "select_masks",
    "mask_candidates", "MASKS_FOR_SUFFIX_DIGITS",
]

#: hashcat's built-in charsets.  ``?h``/``?H`` (hex) and ``?b`` (all bytes)
#: exist in hashcat too; ``?b`` cannot appear in a WPA passphrase, so it is not
#: offered here.
CHARSETS: Dict[str, str] = {
    "l": string.ascii_lowercase,
    "u": string.ascii_uppercase,
    "d": string.digits,
    "s": " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
    "a": string.ascii_letters + string.digits + " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
}

MIN_PASSPHRASE = 8
MAX_PASSPHRASE = 63

#: how many digits are common as a router's default suffix
MASKS_FOR_SUFFIX_DIGITS = (4, 6, 8, 10)

_TOKEN_RE = re.compile(r"\?.")
_LITERAL_QUESTION = "??"


class MaskError(ValueError):
    """Raised for a mask wifipilot cannot expand (unknown ``?x`` token, ...)."""


@dataclass(frozen=True)
class Mask:
    """One mask pattern plus why it is in the list."""

    pattern: str
    note: str = ""

    def __post_init__(self) -> None:
        # validated on construction: a typo must fail where it was written, not
        # later inside a candidate loop
        parse_mask(self.pattern)

    @property
    def space(self) -> int:
        """How many candidates the mask describes."""
        return mask_space(self.pattern)

    @property
    def length(self) -> int:
        """Candidate length: every token (charset or literal) produces one char."""
        return len(_tokens(self.pattern))

    @property
    def usable(self) -> bool:
        """False for a mask that cannot produce a legal WPA passphrase."""
        return MIN_PASSPHRASE <= self.length <= MAX_PASSPHRASE

    def to_dict(self) -> Dict[str, object]:
        return {"mask": self.pattern, "space": self.space, "note": self.note}

    def __str__(self) -> str:                      # pragma: no cover - display only
        return self.pattern


def _tokens(pattern: str) -> List[str]:
    """Split a mask into its tokens (``?d`` or a single literal character)."""
    tokens: List[str] = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "?":
            if index + 1 >= len(pattern):
                raise MaskError(f"mask {pattern!r} ends with a bare '?' (write '??' "
                                f"for a literal question mark)")
            token = pattern[index:index + 2]
            if token != _LITERAL_QUESTION and token[1] not in CHARSETS:
                known = " ".join("?" + key for key in sorted(CHARSETS))
                raise MaskError(f"unknown mask token {token!r} in {pattern!r} "
                                f"(known: {known}, ?? for a literal '?')")
            tokens.append(token)
            index += 2
        else:
            tokens.append(char)
            index += 1
    return tokens


def parse_mask(pattern: str) -> Tuple[str, ...]:
    """Validate ``pattern`` and return its per-position charsets.

    A literal character becomes a one-character charset, so the result is
    directly usable with :func:`itertools.product`.
    """
    if not pattern:
        raise MaskError("empty mask")
    charsets: List[str] = []
    for token in _tokens(pattern):
        if token == _LITERAL_QUESTION:
            charsets.append("?")
        elif token.startswith("?"):
            charsets.append(CHARSETS[token[1]])
        else:
            charsets.append(token)
    return tuple(charsets)


def mask_space(pattern: str) -> int:
    """Number of candidates a mask describes (``?d?d?d?d`` → 10000)."""
    space = 1
    for charset in parse_mask(pattern):
        space *= len(charset)
    return space


def expand_mask(pattern: str, limit: Optional[int] = None) -> Iterator[str]:
    """Yield the candidates of ``pattern``, optionally stopping after ``limit``."""
    charsets = parse_mask(pattern)
    produced = 0
    for combination in itertools.product(*charsets):
        if limit is not None and produced >= limit:
            return
        produced += 1
        yield "".join(combination)


# --------------------------------------------------------------------------- #
# the masks worth trying for a given target
# --------------------------------------------------------------------------- #

#: vendor-ish ESSID prefixes seen on ISP routers, longest first so
#: ``FRITZ!Box 7590`` is matched by ``FRITZ!Box `` rather than ``FRITZ``.
_PREFIX_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_.!-]{2,15}?)(?=[\s_.\-]|\d)")


def _prefixes(essid: str, vendor: str) -> List[str]:
    out: List[str] = []
    if essid:
        match = _PREFIX_RE.match(essid)
        if match:
            word = essid[:match.end()]
            for sep in ("", "-", "_", " "):
                candidate = word + sep
                if candidate not in out:
                    out.append(candidate)
        # the whole ESSID, upper/lower variants, is itself a plausible prefix
        stripped = essid.strip()
        for candidate in (stripped, stripped.replace(" ", ""), stripped.upper(),
                          stripped.lower()):
            if candidate and candidate not in out:
                out.append(candidate)
    if vendor:
        token = vendor.split()[0]
        for candidate in (token, token.replace("-", ""), token.replace("-", "").lower(),
                          token.lower()):
            if candidate not in out:
                out.append(candidate)
    return out


def suggest_masks(essid: str = "", vendor: str = "", limit: int = 12) -> List[Mask]:
    """Masks worth trying against one target, smallest candidate space first.

    The list is ordered so that a slow engine can work from the top: an 8-digit
    numeric default (100 million) is in there for a GPU, while the four-digit
    suffixes in front of it are runnable by the built-in engine in seconds.
    """
    masks: List[Mask] = []
    seen: set = set()

    def add(pattern: str, note: str) -> None:
        if pattern in seen:
            return
        try:
            mask = Mask(pattern, note)
            if not mask.usable:
                return
        except MaskError:
            return
        seen.add(pattern)
        masks.append(mask)

    for prefix in _prefixes(essid, vendor):
        # only meaningful when the prefix leaves room for a suffix
        if len(prefix) < 4 or len(prefix) >= MIN_PASSPHRASE:
            continue
        for digits in (4, 6):
            add(prefix + "?d" * digits,
                f"{len(prefix)}-character prefix + {digits} digits")
        add(prefix + "?d" * 8, "prefix + 8 digits")
    for digits in MASKS_FOR_SUFFIX_DIGITS:
        if digits < MIN_PASSPHRASE:
            continue  # a bare 4-digit mask cannot be a WPA passphrase
        add("?d" * digits, f"{digits}-digit numeric default")
    add("?l?l?l?l?l?l?l?l", "eight lowercase letters")
    add("?u?l?l?l?l?l?l?l", "capitalised word")
    masks.sort(key=lambda mask: mask.space)
    return masks[:limit]


def select_masks(masks: Sequence[Mask], budget: int,
                 minimum: int = 0) -> Tuple[List[Mask], List[Mask]]:
    """Split ``masks`` into the ones that fit ``budget`` and the ones that don't.

    ``minimum`` guards against a tiny budget starving the pass completely: a
    mask is kept when it fits the budget, or when nothing else did and it fits
    ``minimum``.  Callers are expected to *say* what they skipped — a mask of
    100 million candidates is not something a pure-Python engine should half
    sweep in silence.
    """
    runnable: List[Mask] = []
    skipped: List[Mask] = []
    remaining = max(0, int(budget))
    for mask in masks:
        if mask.space <= remaining:
            runnable.append(mask)
            remaining -= mask.space
        else:
            skipped.append(mask)
    if not runnable and minimum > 0:
        for index, mask in enumerate(skipped):
            if mask.space <= minimum:
                runnable.append(mask)
                skipped.pop(index)
                break
    return runnable, skipped


def mask_candidates(patterns: Iterable[str], limit: Optional[int] = None
                    ) -> Iterator[str]:
    """Yield candidates from several masks, deduplicated, up to ``limit``."""
    seen: set = set()
    produced = 0
    for pattern in patterns:
        for candidate in expand_mask(pattern):
            if limit is not None and produced >= limit:
                return
            if candidate in seen:
                continue
            seen.add(candidate)
            produced += 1
            yield candidate
