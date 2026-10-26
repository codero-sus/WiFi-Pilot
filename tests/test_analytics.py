# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Password analytics and default-pattern heuristics.

The numbers here are not security promises — they are the numbers the report
will print, so they have to be stable and monotone: a longer, more random
password must never score lower than a shorter, dictionary one.
"""

from __future__ import annotations

import pytest

from wifipilot import analytics
from wifipilot.analytics import crack_time, identify, password_report, weakness_score


def test_the_worst_passwords_score_lowest():
    assert password_report("12345678").score <= 10
    assert password_report("password").score < 20


def test_more_random_scores_higher():
    weak = password_report("sunshine2024").score
    medium = password_report("Sunshine2024!").score
    strong = password_report("gT7#pQ2!xLm9zR4v").score
    assert weak < medium < strong
    assert strong >= 70


def test_report_carries_the_estimates_and_says_what_it_is():
    report = password_report("sunshine2024").to_dict()
    assert report["length"] == 12
    assert report["classes"] == "ld"                 # lower + digits
    assert report["entropy_bits"] > 0
    assert report["space"] > 0
    assert "contains a year" in report["patterns"]
    assert report["score"] == report["score"] and 0 <= report["score"] <= 100
    assert report["verdict"]
    assert set(report["seconds"]) == set(analytics.SPEEDS)
    # a slower engine must always take longer than a faster one
    seconds = report["seconds"]
    assert seconds["wifipilot (built-in, PBKDF2 in Python)"] > seconds["hashcat (CPU, WPA mode 22000)"]
    assert seconds["hashcat (CPU, WPA mode 22000)"] > seconds["hashcat (GPU farm, 8 cards)"]


def test_patterns_are_named_not_guessed_silently():
    assert "keyboard walk" in password_report("qwertyui").patterns
    assert "contains a year" in password_report("summer2021").patterns
    assert "trailing digits" in password_report("telekom1234").patterns
    assert "leet substitutions" in password_report("p@ssw0rd").patterns
    # ... but a suffix is not a substitution
    assert "leet substitutions" not in password_report("sunshine!").patterns
    assert "leet substitutions" not in password_report("gT7#pQ2!xLm9zR4v").patterns


def test_weakness_score_is_monotone_in_length():
    for length in range(8, 24):
        shorter = weakness_score("a" * length, [])[0]
        longer = weakness_score("a" * (length + 1), [])[0]
        assert longer >= shorter


def test_crack_time_handles_the_extremes():
    assert crack_time(0, 1000) <= 0.001        # an empty space is still not a promise
    assert crack_time(1000, 0) == float("inf")
    assert crack_time(1000, 1000) == 0.5             # average case is half the space


def test_vendor_patterns_finds_known_vendors_case_insensitively():
    fritz = analytics.vendor_patterns("AVM GmbH")
    assert fritz and fritz.get("label", "").lower().startswith("avm")
    assert analytics.vendor_patterns("tp-link")["label"]
    assert analytics.vendor_patterns("nothing-like-this") == {}


def test_guess_vendor_prefers_the_essid_then_the_oui():
    assert "TP-Link" in analytics.guess_vendor("TP-LINK_1A2B")
    assert analytics.guess_vendor("FRITZ!Box 7590 QY").lower().startswith("avm")
    assert "AVM" in analytics.guess_vendor("", "d0:9e:12:9d:36:cc")
    assert analytics.guess_vendor("totally-unknown", "aa:bb:cc:dd:ee:ff") == ""


def test_identify_returns_a_scheme_and_small_runnable_masks():
    info = identify("Telekom-9F3A")
    assert info["essid"] == "Telekom-9F3A"
    assert info["scheme"]
    assert info["confidence"] == "heuristic"
    assert info["masks"], "identify() is useless without something to try"
    assert info["masks"] == sorted(info["masks"], key=lambda item: item["space"])
    # the *whole point* of ordering: what runs first must fit in a lifetime
    assert info["masks"][0]["space"] <= 10_000_000
    assert all(item["mask"] and item["space"] > 0 for item in info["masks"])


def test_identify_on_an_unknown_essid_still_proposes_something():
    info = identify("nothing-familiar-here")
    assert info["vendor"] == ""
    assert info["masks"]
    assert info["masks"][0]["space"] <= 10_000_000


@pytest.mark.parametrize("password", ["", "x", "a" * 70])
def test_extreme_passwords_do_not_crash_the_report(password):
    """WPA passphrases are 8-63 characters, but a report may be handed anything."""
    report = password_report(password)
    assert 0 <= report.score <= 100
    assert report.length == len(password)
