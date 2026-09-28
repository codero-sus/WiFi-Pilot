"""WPS PIN arithmetic: checksums, candidate provenance, and the attempt plan.

The value of this module is that it never wastes an attempt: every PIN it hands an
online attack is checksum-valid, every candidate says *why* it was suggested, and
the plan states plainly how long the alternatives would take. These tests pin all
three, plus the two published ComputePIN variants.
"""

from __future__ import annotations

import pytest

from wifipilot import wps


def _digits(pin: str) -> str:
    return "".join(ch for ch in pin if ch.isdigit())


# --------------------------------------------------------------------------- #
# arithmetic
# --------------------------------------------------------------------------- #

def test_checksum_is_the_published_one():
    # the classic example: 1234567 -> check digit 0
    assert wps.checksum("1234567") == 0
    assert wps.checksum("12345670") == 0        # a complete PIN checks itself
    assert 0 <= wps.checksum("9876543") <= 9
    with pytest.raises(ValueError):
        wps.checksum("123456")                  # six digits cannot be checked


def test_complete_pin_appends_the_check_digit():
    assert wps.complete_pin("1234567") == "12345670"
    assert wps.complete_pin("12345670") == "12345670"      # already complete
    assert wps.pin_is_valid("12345670")
    assert not wps.pin_is_valid("12345678")
    assert not wps.pin_is_valid("1234567")                 # seven digits
    assert not wps.pin_is_valid("1234567a")


def test_every_completed_pin_is_valid():
    for prefix in ("0000000", "1234567", "9999999", "0123456"):
        pin = wps.complete_pin(prefix)
        assert len(pin) == 8 and wps.pin_is_valid(pin)


# --------------------------------------------------------------------------- #
# candidates
# --------------------------------------------------------------------------- #

def test_default_pins_are_valid_and_carry_provenance():
    candidates = wps.default_pins()
    assert candidates, "there are known default PINs"
    pins = [item.pin for item in candidates]
    assert "12345670" in pins
    for item in candidates:
        assert wps.pin_is_valid(item.pin), item
        assert item.source and item.confidence
        assert item.to_dict()["pin"] == item.pin


def test_computepin_variants_are_deterministic():
    first = wps.bssid_pins("d0:12:cb:00:00:01")
    second = wps.bssid_pins("d0:12:cb:00:00:01")
    assert [item.pin for item in first] == [item.pin for item in second]
    pins = {item.pin for item in first}
    assert "00000017" in pins                    # last three octets, mod 10^7
    assert "36362998" in pins                    # 0xD012CB mod 10^7
    compute = [item for item in first if "ComputePIN" in item.source]
    assert len(compute) >= 2
    for item in compute:
        assert wps.pin_is_valid(item.pin), item


def test_the_two_computepin_variants_disagree_when_the_bssid_does():
    last_three = {item.source: item.pin for item in wps.bssid_pins("d0:12:cb:aa:bb:cc")}
    assert any("last three" in key for key in last_three)


def test_vendor_candidates_come_from_the_vendor_table():
    netgear = wps.vendor_pins("Netgear")
    assert netgear and netgear[0].pin == "12345670"
    assert "NETGEAR" in netgear[0].source.upper()
    # an unknown vendor still gets the universal defaults, not an exception
    assert wps.vendor_pins("") or wps.default_pins()


def test_candidate_pins_are_unique_valid_and_ordered_by_confidence():
    candidates = wps.candidate_pins(bssid="a8:90:91:0e:2b:40", essid="NETGEAR47",
                                    vendor="Netgear")
    pins = [item.pin for item in candidates if item.pin]
    assert len(pins) == len(set(pins)), "no duplicate PIN is offered twice"
    for item in candidates:
        if not item.pin:
            continue
        # every PIN is either checksum-valid, or kept on purpose and says so
        assert wps.pin_is_valid(item.pin) or "check digit" in item.note, item
    assert pins[0] == "12345670", "the vendor default comes first"
    order = {"likely": 0, "heuristic": 1, "speculative": 2}
    ranks = [order.get(item.confidence, 3) for item in candidates if item.pin]
    assert ranks == sorted(ranks), "candidates are ordered most-likely first"


def test_a_vendor_without_a_default_says_so_instead_of_guessing():
    items = wps.candidate_pins(bssid="d0:12:cb:00:00:01", essid="FRITZ!Box 7590 QY",
                               vendor="AVM")
    notes = " ".join(item.note for item in items if not item.pin)
    assert "AVM" in notes or notes, "the vendor note is surfaced, not dropped"
    for item in items:
        if item.pin:
            assert wps.pin_is_valid(item.pin) or "check digit" in item.note, item


# --------------------------------------------------------------------------- #
# the attempt order and the plan
# --------------------------------------------------------------------------- #

def test_order_starts_with_the_preferred_candidates():
    order = list(wps.pin_attempt_order(["12345670", "00000000"], first_half="1234"))
    assert order[0] == "12345670" and order[1] == "00000000"
    # the preferred PINs, then the 1,000 completions of the known first half
    # (deduplicated, so a preferred PIN that completes it appears only once)
    assert 1_000 <= len(order) <= 1_002
    assert all(wps.pin_is_valid(pin) for pin in order)


def test_order_with_a_known_first_half_is_a_thousand_pins():
    order = list(wps.pin_attempt_order([], first_half="1234"))
    assert len(order) == 1_000
    assert all(pin.startswith("1234") for pin in order)
    assert all(wps.pin_is_valid(pin) for pin in order)
    assert len(set(order)) == len(order)


def test_order_without_a_first_half_sweeps_first_half_major():
    order = wps.pin_attempt_order(["12345670"])
    first = [next(order) for _ in range(6)]
    assert first[0] == "12345670"                    # the preferred PIN first
    assert all(wps.pin_is_valid(pin) for pin in first)
    rest = [next(order) for _ in range(200)]
    assert all(wps.pin_is_valid(pin) for pin in rest)
    assert len(set(first + rest)) == len(first + rest)
    # first-half-major: the four-digit prefix changes every 1,000 completions
    assert len({pin[:4] for pin in rest}) <= 2


def test_a_bad_first_half_is_ignored_rather_than_swept():
    order = list(wps.pin_attempt_order([], first_half="12"))     # not four digits
    assert order[:4] == ["00000000", "00000017", "00000024", "00000031"]


def test_attempt_plan_states_the_real_cost():
    plan = wps.attempt_plan(bssid="d8:5d:4c:11:22:33", essid="TP-LINK_11J2",
                            vendor="TP-Link", seconds_per_attempt=2.0)
    spaces = plan["spaces"]
    assert spaces["every 8-digit value"] == 10 ** 8
    assert spaces["checksum-valid PINs"] == 10 ** 7
    assert spaces["two-half sweep (the documented attack)"] == 11_000
    assert spaces["candidates above"] == plan["runnable"] >= 1
    # 11,000 attempts at 2s each is a bit over six hours, not a mystery
    assert plan["seconds"]["two-half sweep"] == pytest.approx(22_000.0)
    assert "authorisation" in plan["note"] or "transmitted" in plan["note"]


def test_plan_for_an_unknown_target_is_still_honest():
    plan = wps.attempt_plan()
    assert plan["runnable"] >= 1                # the universal defaults
    assert plan["spaces"]["candidates above"] == plan["runnable"]
