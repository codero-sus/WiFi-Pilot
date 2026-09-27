"""hashcat-style rule files, parsed and applied in pure Python.

hashcat ships ~100 rule files (``best64.rule``, ``rockyou-30000.rule``, ...);
wifipilot can hand them to ``hashcat -r`` but until now the *built-in* engine had
only its own small mutation set, so a machine without hashcat could not use
them at all.  This module implements the classic rule language — the subset that
actually appears in ``best64``/``dive.rule`` and friends — so:

* ``wifipilot wordlist expand -r best64.rule`` turns a wordlist into a bigger one;
* ``wifipilot crack --rule-file best64.rule`` makes the built-in engine rule-aware;
* ``wifipilot wordlist rules-info FILE`` explains what a rule file does.

Supported commands (positions are 0-based, as in hashcat):

``:`` no-op · ``l``/``u``/``c``/``C``/``t``/``TN`` case · ``r`` reverse ·
``d`` duplicate · ``f`` reflect · ``{``/``}`` rotate · ``$X``/``^X`` append/prepend ·
``[``/``]`` drop first/last · ``DN`` delete at N · ``xNM`` substring · ``ONM`` omit ·
``iNX`` insert · ``sXY`` substitute · ``@X`` purge · ``pN`` repeat · ``'N`` truncate ·
``z1``/``Z1`` duplicate first/last · ``q`` duplicate every character ·
``k``/``K`` swap first/last two · ``*NM`` swap two positions ·
``<N``/``>N`` length filters · ``!X`` reject-if-contains · ``/X`` reject-unless-contains.

Anything unrecognised is kept verbatim in the parsed rule and *reported*, never
silently dropped: a rule file the engine cannot fully apply must say so.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

__all__ = ["RuleError", "Rule", "parse_rule", "parse_rules", "parse_file", "load",
           "apply_rules", "rule_expand", "describe", "KNOWN_COMMANDS", "MIN_LENGTH",
           "MAX_LENGTH"]

MIN_LENGTH = 8       # WPA passphrase
MAX_LENGTH = 63

#: commands that are meaningless without their argument — a rule line ending in
#: one of these is malformed, and a malformed rule must be skipped, never
#: silently applied as a no-op (hashcat rejects the whole line).
NEEDS_ARGUMENT = "$^!/@sTOp'<>zZDx*i"

KNOWN_COMMANDS = {
    ":", "l", "u", "c", "C", "t", "T", "r", "d", "f", "{", "}", "$", "^", "[", "]",
    "D", "x", "O", "i", "s", "@", "p", "'", "z", "Z", "q", "k", "K", "*", "<", ">",
    "!", "/",
}


class RuleError(ValueError):
    """A rule string could not be parsed."""


@dataclass
class Rule:
    """One parsed rule: the source text plus how it behaved on a sample word."""

    text: str
    commands: List[str] = field(default_factory=list)
    unsupported: List[str] = field(default_factory=list)

    @property
    def usable(self) -> bool:
        """False when any part of the rule could not be modelled.

        A partially-applied rule would produce different candidates than
        hashcat does, which is worse than skipping the rule and saying so.
        """
        return bool(self.commands) and not self.unsupported

    def apply(self, word: str) -> Optional[str]:
        """Apply the rule to ``word``; ``None`` means the rule rejected it."""
        letters = list(word)
        for command in self.commands:
            letters = _step(command, letters)
            if letters is None:
                return None
        result = "".join(letters)
        return result

    def to_dict(self) -> Dict[str, object]:
        return {"rule": self.text, "commands": self.commands,
                "unsupported": self.unsupported, "usable": self.usable}

    def __str__(self) -> str:                      # pragma: no cover - display
        return self.text


def _index(token: str) -> Optional[int]:
    digits = "".join(ch for ch in token if ch.isdigit())
    return int(digits) if digits else None


def _step(command: str, letters: Optional[List[str]]) -> Optional[List[str]]:
    """One rule command.  ``None`` in = rejected; ``None`` out = rejected."""
    if letters is None:
        return None
    op, rest = command[0], command[1:]
    text = "".join(letters)

    if op == ":":
        return letters
    if op == "l":
        return list(text.lower())
    if op == "u":
        return list(text.upper())
    if op == "c":                                    # capitalise
        return list(text.capitalize())
    if op == "C":                                    # lower the first, upper the rest
        return list(text[:1].lower() + text[1:].upper())
    if op == "t":                                    # toggle case of everything
        return list("".join(c.swapcase() for c in text))
    if op == "T":                                    # toggle case at one position
        position = _index(rest)
        if position is None or position >= len(letters):
            return None
        letters = list(letters)
        letters[position] = letters[position].swapcase()
        return letters
    if op == "r":
        return list(reversed(letters))
    if op == "d":
        return letters + letters
    if op == "f":
        return letters + list(reversed(letters))
    if op == "{":                                    # rotate left
        return letters[1:] + letters[:1] if letters else letters
    if op == "}":                                    # rotate right
        return letters[-1:] + letters[:-1] if letters else letters
    if op == "$":
        return letters + list(rest)
    if op == "^":
        return list(rest) + letters
    if op == "[":
        return letters[1:].copy() if letters else letters
    if op == "]":
        return letters[:-1].copy() if letters else letters
    if op == "D":                                    # delete at position
        position = _index(rest)
        if position is None or position >= len(letters):
            return None
        return letters[:position] + letters[position + 1:]
    if op == "x":                                    # extract
        if len(rest) < 2:
            return None
        start, count = _index(rest[0]), _index(rest[1])
        if start is None or count is None:
            return None
        return letters[start:start + count]
    if op == "O":                                    # omit
        if len(rest) < 2:
            return None
        start, count = _index(rest[0]), _index(rest[1])
        if start is None or count is None:
            return None
        return letters[:start] + letters[start + count:]
    if op == "i":                                    # insert char at position
        if len(rest) < 2:
            return None
        position, char = _index(rest[0]), rest[1]
        if position is None:
            return None
        return letters[:position] + [char] + letters[position:]
    if op == "s":                                    # substitute
        if len(rest) < 2:
            return None
        return list(text.replace(rest[0], rest[1]))
    if op == "@":                                    # purge
        return list(text.replace(rest[0], "")) if rest else letters
    if op == "p":                                    # repeat N times
        times = _index(rest)
        if times is None:
            return None
        return list(text * times)
    if op == "'":                                    # truncate
        size = _index(rest)
        if size is None:
            return None
        return letters[:size]
    if op == "z":
        return [letters[0]] + letters if letters else letters
    if op == "Z":
        return letters + [letters[-1]] if letters else letters
    if op == "q":                                    # duplicate every character
        return [char for letter in letters for char in (letter, letter)]
    if op == "k":
        return letters[1::-1] + letters[2:] if len(letters) >= 2 else letters
    if op == "K":                                    # swap the last two
        return letters[:-2] + letters[-1:] + letters[-2:-1] if len(letters) >= 2 else letters
    if op == "*":
        if len(rest) < 2:
            return None
        first, second = _index(rest[0]), _index(rest[1])
        if first is None or second is None:
            return None
        if max(first, second) >= len(letters):
            return None
        letters = list(letters)
        letters[first], letters[second] = letters[second], letters[first]
        return letters
    if op == "<":                                    # reject unless shorter
        size = _index(rest)
        if size is None:
            return None
        return None if len(letters) >= size else letters
    if op == ">":                                    # reject unless longer
        size = _index(rest)
        if size is None:
            return None
        return None if len(letters) <= size else letters
    if op == "!":
        return None if rest and rest[0] in text else letters
    if op == "/":
        return None if rest and rest[0] not in text else letters
    return letters


def _take_digits(text: str, index: int) -> Tuple[str, int]:
    """Consume a run of digits starting at ``index`` (may be empty)."""
    start = index
    while index < len(text) and text[index].isdigit():
        index += 1
    return text[start:index], index


def parse_rule(text: str) -> Rule:
    """Parse one rule line into commands.  Raises :class:`RuleError`."""
    text = text.rstrip("\n")
    if not text:
        raise RuleError("empty rule")
    commands: List[str] = []
    unsupported: List[str] = []
    index = 0
    while index < len(text):
        char = text[index]

        def take(length: int) -> str:
            return text[index:index + length]

        if char not in KNOWN_COMMANDS:
            unsupported.append(text[index:])
            break
        command = ""
        if char in "$^!/@":                       # one-character argument
            command = take(2) if index + 1 < len(text) else take(1)
        elif char in "s":                          # two-character argument
            command = take(3)
        elif char == "i":                          # digit + character
            digits, after = _take_digits(text, index + 1)
            command = text[index:after + 1] if len(digits) == 1 and after < len(text) \
                else take(1)
        elif char in "TOp'<>zZD":                  # numeric argument (multi-digit)
            digits, after = _take_digits(text, index + 1)
            command = text[index:after] if digits else take(1)
        elif char in "xO*":                        # two single-digit arguments
            first = text[index + 1] if index + 1 < len(text) and text[index + 1].isdigit() else ""
            after = index + 1 + len(first)
            second = text[after] if after < len(text) and text[after].isdigit() else ""
            after2 = after + len(second)
            command = (text[index:after2] if first and second else take(1))
        else:                                      # ': l u c C t r d f { } q k K [ ]'
            command = take(1)
        if len(command) == 1 and command[0] in NEEDS_ARGUMENT:
            # a command with missing arguments: keep the text, flag it
            unsupported.append(text[index:])
            break
        commands.append(command)
        index += len(command)
    return Rule(text=text, commands=commands, unsupported=unsupported)


def parse_rules(lines: Iterable[str]) -> List[Rule]:
    """Parse many rule lines, skipping blanks and ``#`` comments."""
    rules: List[Rule] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            rules.append(parse_rule(stripped))
        except RuleError:
            continue
    return rules


def parse_file(path: str) -> List[Rule]:
    """Parse a rule file from disk (missing/unreadable file -> no rules)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return parse_rules(handle)
    except OSError:
        return []


def load(spec: str) -> Tuple[List[Rule], str]:
    """Load rules from ``spec`` — a file path, or one rule given inline.

    Returns ``(rules, description)``: an inline rule is anything containing one
    of the rule commands and no path separator that exists on disk.
    """
    import os
    if spec and os.path.exists(spec):
        rules = parse_file(spec)
        return rules, os.path.basename(spec)
    if spec:
        return [parse_rule(spec)], f"inline rule {spec!r}"
    return [], ""


RULE_PRESETS: Dict[str, List[str]] = {
    #: a small built-in file, so `--rules` works with no hashcat installed
    "best64": [
        ":", "l", "u", "c", "C", "r", "d", "f", "t", "{", "}", "$1", "$2", "$3",
        "$!", "$!$!", "$1$2$3", "$1$2$3$4", "$2$0$2$4", "$2$0$2$5", "^1",
        "sa@", "se3", "so0", "si1", "ss$", "s1!", "'6", "'7", "'8",
        "c$1", "c$1$2$3", "l$1", "u$1", "t$1", "r$1", "d$1",
    ],
    "leet": ["sa@", "se3", "si1", "so0", "ss$", "sa@se3", "sa@si1so0"],
    "append-digits": ["$0", "$1", "$2", "$3", "$4", "$5", "$6", "$7", "$8", "$9",
                      "$0$1", "$1$2", "$1$2$3", "$1$2$3$4", "$1$2$3$4$5"],
    "case": [":", "l", "u", "c", "C", "t"],
}


def preset(name: str) -> List[Rule]:
    """A named built-in rule set (``best64``, ``leet``, ...), for no-hashcat runs."""
    return [parse_rule(text) for text in RULE_PRESETS.get(name, [])]


def describe(rules: Sequence[Rule]) -> Dict[str, object]:
    """Summarise a rule file: counts, commands used, anything unsupported."""
    counts: Dict[str, int] = {}
    unsupported: Dict[str, int] = {}
    for rule in rules:
        for command in rule.commands:
            counts[command[0]] = counts.get(command[0], 0) + 1
        for item in rule.unsupported:
            unsupported[item] = unsupported.get(item, 0) + 1
    usable = [rule for rule in rules if rule.usable]
    examples = [(rule.text, rule.apply("password")) for rule in usable[:3]]
    return {
        "rules": len(rules),
        "usable": len(usable),
        "skipped": len(rules) - len(usable),
        "commands": dict(sorted(counts.items(), key=lambda item: -item[1])),
        "unsupported": unsupported,
        "examples": [{"rule": text, "password": result} for text, result in examples],
    }


def apply_rules(word: str, rules: Sequence[Rule], limit: int = 0,
                dedupe: bool = True) -> Iterator[str]:
    """Yield ``word`` mutated by every rule (bounded by ``limit`` if given)."""
    seen = set()
    produced = 0
    for rule in rules:
        if not rule.usable:
            continue
        candidate = rule.apply(word)
        if candidate is None:
            continue
        if not (MIN_LENGTH <= len(candidate) <= MAX_LENGTH):
            continue
        if dedupe:
            if candidate in seen:
                continue
            seen.add(candidate)
        produced += 1
        yield candidate
        if limit and produced >= limit:
            return


def rule_expand(word: str, limit: int = 40) -> List[str]:
    """``best64`` expansions of a single word (the built-in engine's default)."""
    return list(apply_rules(word, preset("best64"), limit=limit))
