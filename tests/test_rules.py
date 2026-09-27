"""The hashcat rule language, parsed and applied in pure Python.

Every case here is a claim about what hashcat does with that rule: if one of
these is wrong, `wifipilot wordlist expand -r file.rule` produces different
candidates than `hashcat -r file.rule` would, which is exactly the failure the
tests exist to catch.
"""

from __future__ import annotations

import pytest

from wifipilot import rules
from wifipilot.rules import RuleError


@pytest.mark.parametrize("text,word,expected", [
    (":", "sunshine", "sunshine"),
    ("l", "SUNSHINE", "sunshine"),
    ("u", "sunshine", "SUNSHINE"),
    ("c", "hELLO", "Hello"),
    ("C", "HASHCAT", "hASHCAT"),
    ("t", "aBc", "AbC"),
    ("r", "abc", "cba"),
    ("d", "ab", "abab"),
    ("f", "ab", "abba"),
    ("{", "abcd", "bcda"),
    ("}", "abcd", "dabc"),
    ("$1", "sunshine", "sunshine1"),
    ("$2$0$2$4", "net", "net2024"),
    ("^!", "sunshine", "!sunshine"),
    ("[", "abcd", "bcd"),
    ("]", "abcd", "abc"),
    ("D2", "abcd", "abd"),
    ("D0", "abcd", "bcd"),
    ("x12", "abcdefgh", "bc"),
    ("x28", "abcdefghijkl", "cdefghij"),
    ("O13", "abcdefgh", "aefgh"),
    ("i3!", "abcdef", "abc!def"),
    ("s1!", "a1b1", "a!b!"),
    ("@a", "banana", "bnn"),
    ("p2", "ab", "abab"),
    ("'6", "sunshine", "sunshi"),
    ("z1", "abc", "aabc"),
    ("Z1", "abc", "abcc"),
    ("q", "ab", "aabb"),
    ("k", "abcd", "bacd"),
    ("K", "abcd", "abdc"),
    ("*03", "abcd", "dbca"),
    ("T1", "abc", "aBc"),
    ("sa@c$1", "password", "P@ssword1"),
])
def test_rule_commands_match_hashcat(text, word, expected):
    parsed = rules.parse_rule(text)
    assert parsed.commands, text
    assert not parsed.unsupported, (text, parsed.unsupported)
    assert parsed.apply(word) == expected


def test_rejection_rules_return_none():
    """``!X`` rejects a word *containing* X; ``/X`` rejects one that lacks it."""
    assert rules.parse_rule("!o").apply("hello") is None
    assert rules.parse_rule("!x").apply("hello") == "hello"
    assert rules.parse_rule("/e").apply("hello") == "hello"
    assert rules.parse_rule("/z").apply("hello") is None


def test_rejection_rules_test_the_mutated_word_not_the_original():
    """hashcat evaluates every step against the word as it stands right then."""
    assert rules.parse_rule("l!s").apply("SUN") is None      # lower() makes it contain 's'
    assert rules.parse_rule("u!s").apply("sun") == "SUN"     # upper() removes it


def test_length_filters_are_recorded():
    assert rules.parse_rule("<9").apply("abcdefgh") == "abcdefgh"
    assert rules.parse_rule("<8").apply("abcdefgh") is None
    assert rules.parse_rule(">8").apply("abcdefgh") is None
    assert rules.parse_rule(">4").apply("abcdefgh") == "abcdefgh"


@pytest.mark.parametrize("text", ["$", "^", "!", "/", "@", "s", "T", "p", "'", "x", "O",
                                  "i", "D", "z", "Z", "<", ">"])
def test_a_command_without_its_argument_is_unusable_not_half_applied(text):
    """A malformed rule line must be skipped, never silently applied as a no-op."""
    parsed = rules.parse_rule(text)
    assert parsed.unsupported == [text]
    assert not parsed.usable

    # ... and a rule that *is* malformed must not be produced as a candidate
    assert list(rules.apply_rules("sunshine", [parsed])) == []


def test_multi_character_presets_are_written_as_sequences():
    """hashcat's ``$X`` takes one character: ``$2024`` is ``$2`` then junk."""
    parsed = rules.parse_rule("$2024")
    assert parsed.unsupported == ["024"]
    assert not parsed.usable, "a partially-modelled rule must not run"


def test_empty_rule_is_refused():
    with pytest.raises(RuleError):
        rules.parse_rule("")


def test_parse_rules_skips_comments_and_blanks():
    parsed = rules.parse_rules(["# comment", "", "l", "  u  "])
    assert [rule.text for rule in parsed] == ["l", "u"]


def test_best64_preset_is_complete_and_usable():
    preset = rules.preset("best64")
    info = rules.describe(preset)
    assert info["rules"] >= 30
    assert info["usable"] == info["rules"]
    assert info["skipped"] == 0
    assert info["examples"], "describe() should show what the rules do"


def test_apply_rules_only_yields_wpa_passphrases():
    ruleset = rules.preset("best64")
    for candidate in rules.apply_rules("password", ruleset, limit=60):
        assert 8 <= len(candidate) <= 63


def test_apply_rules_respects_the_limit_and_deduplicates():
    ruleset = [rules.parse_rule(":")]
    produced = list(rules.apply_rules("sunshine", ruleset * 3, limit=10))
    assert produced == ["sunshine"]


def test_rule_expand_is_the_best64_expansion():
    candidates = rules.rule_expand("sunshine", limit=5)
    assert candidates[0] == "sunshine"
    assert "SUNSHINE" in candidates


def test_load_takes_a_path_or_an_inline_rule(tmp_path):
    path = tmp_path / "test.rule"
    path.write_text("l\nu\n# comment\n$1\n")
    loaded, label = rules.load(str(path))
    assert label == "test.rule" and len(loaded) == 3
    inline, label = rules.load("$123")
    assert len(inline) == 1 and label.startswith("inline")
    missing, label = rules.load("")
    assert missing == [] and label == ""


def test_unknown_preset_yields_nothing_rather_than_guessing():
    assert rules.preset("nope-not-a-set") == []
