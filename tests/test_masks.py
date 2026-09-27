"""Mask attacks: hashcat-style ``?d`` patterns, expanded locally or handed over.

The tests pin three things: the mask language itself (tokens, literal ``??``,
spaces, refusals), the patterns wifipilot derives from a target, and the
cracker's behaviour — a small mask is swept by the built-in engine, a mask that
does not fit the budget is *named* and left to hashcat rather than half-swept.
"""

from __future__ import annotations

import string
import time

import pytest

from wifipilot import masks
from wifipilot.crack import Cracker
from wifipilot.models import AccessPoint, Capture
from wifipilot.masks import Mask, MaskError
from wifipilot.pcap import analyze_file
from wifipilot.synth import build_capture

ESSID = "Telekom-9F3A"
#: a router default no candidate generator will guess, but Telekom?d?d?d?d gives
#: on its third try — so the test also proves the mask stage runs at all
PSK = "Telekom0002"


def test_parse_mask_expands_tokens_and_literals():
    charsets = masks.parse_mask("a?d?u")
    assert charsets == ("a", string.digits, string.ascii_uppercase)


def test_expand_mask_yields_every_combination_in_order():
    candidates = list(masks.expand_mask("?d?d"))
    assert len(candidates) == 100
    assert candidates[:3] == ["00", "01", "02"]
    assert candidates[-1] == "99"


def test_expand_mask_respects_a_limit():
    assert len(list(masks.expand_mask("?d?d?d", limit=7))) == 7


def test_mask_space_matches_the_expansion():
    for pattern in ("?d?d?d?d", "x?l?d", "?u?l?l?l"):
        assert masks.mask_space(pattern) == len(list(masks.expand_mask(pattern)))


def test_double_question_mark_is_a_literal():
    assert list(masks.expand_mask("a??b")) == ["a?b"]
    assert masks.mask_space("??") == 1


def test_unknown_tokens_are_refused():
    with pytest.raises(MaskError):
        masks.parse_mask("?z?d")
    with pytest.raises(MaskError):
        masks.parse_mask("abc?")
    with pytest.raises(MaskError):
        masks.parse_mask("")


def test_a_mask_must_be_able_to_make_a_wpa_passphrase():
    assert not Mask("?d?d?d?d").usable          # 4 characters is too short for WPA
    assert Mask("Telekom?d?d?d?d").usable
    assert not Mask("x" * 70).usable


def test_suggested_masks_are_usable_and_ordered_by_space():
    suggested = masks.suggest_masks("Telekom-9F3A", "AVM GmbH")
    assert suggested, "a router-ish ESSID must produce patterns"
    assert all(mask.usable for mask in suggested)
    assert [mask.space for mask in suggested] == sorted(mask.space for mask in suggested)
    assert len({mask.pattern for mask in suggested}) == len(suggested)


def test_suggested_masks_follow_the_essid_prefix():
    patterns = [mask.pattern for mask in masks.suggest_masks("Telekom-9F3A")]
    assert "Telekom?d?d?d?d" in patterns


def test_suggested_masks_follow_the_vendor_name():
    patterns = [mask.pattern for mask in masks.suggest_masks("", "TP-Link")]
    assert "TP-Link?d?d?d?d" in patterns


def test_suggested_masks_for_an_anonymous_target_are_generic_but_usable():
    suggested = masks.suggest_masks()
    assert suggested
    assert all(mask.length >= masks.MIN_PASSPHRASE for mask in suggested)
    assert "?d?d?d?d?d?d?d?d" in [mask.pattern for mask in suggested]


def test_select_masks_splits_what_fits_the_budget():
    suggested = masks.suggest_masks("Telekom-9F3A")
    runnable, skipped = masks.select_masks(suggested, 15_000)
    assert [mask.pattern for mask in runnable] == ["Telekom?d?d?d?d"]
    assert skipped and all(mask.space > 15_000 for mask in skipped)
    assert sum(mask.space for mask in runnable) <= 15_000


def test_select_masks_reports_everything_as_skipped_when_nothing_fits():
    suggested = masks.suggest_masks("Telekom-9F3A")
    runnable, skipped = masks.select_masks(suggested, 10)
    assert not runnable
    assert skipped == list(suggested)


def test_mask_candidates_deduplicates_across_patterns():
    candidates = list(masks.mask_candidates(["Telekom?d?d", "Telekom0?d"], limit=1000))
    assert candidates[0] == "Telekom00"
    assert len(candidates) == len(set(candidates))
    assert len(candidates) == len(list(masks.expand_mask("Telekom?d?d")))  # subset of the first


# --------------------------------------------------------------------------- #
# the cracker
# --------------------------------------------------------------------------- #

def _crack(tmp_path, config, session, name: str, **overrides):
    path = str(tmp_path / f"{name}.pcap")
    build_capture(path, ESSID, "aa:bb:cc:11:22:33", "02:00:00:00:00:09", PSK)
    # the targeted stage is exercised in test_crack.py; here it only delays
    config.targeted_candidates = 1
    for key, value in overrides.items():
        setattr(config, key, value)
    ap, _ = session.upsert_ap("aa:bb:cc:11:22:33", ESSID, publish=False)
    ap.vendor = "TP-Link"
    analysis = analyze_file(path)
    capture = Capture(kind="handshake", bssid=ap.bssid, essid=ESSID, path=path, valid=True,
                      hash_path=path)
    assert analysis.has_handshake
    cracker = Cracker(session, config, session.bus, demo=False)
    return ap, capture, cracker


def test_builtin_mask_pass_cracks_a_router_default(tmp_path, config, session):
    ap, capture, cracker = _crack(tmp_path, config, session, "mask")
    result = cracker.crack_capture(ap, capture, wordlists=[], timeout=60)
    assert result.cracked and result.password == PSK and result.verified
    assert result.reason.startswith("mask attack (")
    assert "Telekom" in result.reason


def test_an_operator_mask_is_used_verbatim(tmp_path, config, session):
    ap, capture, cracker = _crack(tmp_path, config, session, "custom",
                                  mask_patterns=["Telekom000?d"])
    found, tested, pattern = cracker._mask_pass(
        ap, capture, analyze_file(capture.path), deadline=time.time() + 30,
        base_attempts=0, on_progress=lambda n, d: None)
    assert found == PSK and pattern == "Telekom000?d"
    assert tested == 3, "Telekom0000, 0001, 0002 — nothing else"


def test_masks_can_be_turned_off(tmp_path, config, session):
    ap, capture, cracker = _crack(tmp_path, config, session, "nomask",
                                  use_masks=False, mask_patterns=["Telekom000?d"])
    result = cracker.crack_capture(ap, capture, wordlists=["/nonexistent-wordlist.txt"],
                                   timeout=10)
    assert not result.cracked and "mask" not in result.reason


def test_a_mask_over_the_budget_is_left_to_hashcat(tmp_path, config, session):
    """Not silently half-swept: the built-in engine must say what it skipped."""
    ap, capture, cracker = _crack(tmp_path, config, session, "big",
                                  mask_patterns=["Telekom?d?d?d?d?d?d"],
                                  mask_candidates=5_000)
    chosen, problems = cracker._masks(ap)
    assert not problems
    runnable, skipped = masks.select_masks(chosen, cracker.config.mask_candidates)
    assert not runnable and skipped
    assert skipped[0].pattern == "Telekom?d?d?d?d?d?d"
    found, tested, pattern = cracker._mask_pass(
        ap, capture, analyze_file(capture.path), deadline=time.time() + 30,
        base_attempts=0, on_progress=lambda n, d: None)
    assert (found, tested, pattern) == ("", 0, "")


def test_the_skip_is_announced_with_its_size(tmp_path, config, session):
    """Whatever the engine does not try, it must name — with the size."""
    ap, capture, cracker = _crack(tmp_path, config, session, "announce",
                                  mask_patterns=["Telekom?d?d?d?d?d?d"],
                                  mask_candidates=5_000)
    events = cracker.bus.subscribe()
    cracker._mask_pass(ap, capture, analyze_file(capture.path),
                       deadline=time.time() + 30, base_attempts=0,
                       on_progress=lambda n, d: None)
    messages = [str(event.data.get("message", "")) for event in events.drain(200)]
    assert any("skipped by the built-in engine" in message and "1,000,000" in message
               for message in messages), messages


def test_a_broken_operator_mask_is_reported_not_fatal(tmp_path, config, session):
    ap, capture, cracker = _crack(tmp_path, config, session, "broken",
                                  mask_patterns=["?z?z?z?z?z?z?z?z", "?d?d?d"])
    chosen, problems = cracker._masks(ap)
    assert len(problems) == 2
    assert any("unknown mask token" in problem for problem in problems)
    assert any("8-63 character" in problem for problem in problems)
    assert chosen, "the target-derived masks still run"
    found, _, pattern = cracker._mask_pass(
        ap, capture, analyze_file(capture.path), deadline=time.time() + 30,
        base_attempts=0, on_progress=lambda n, d: None)
    assert found == PSK, "a typo in --mask must not disable the rest of the stage"
    assert pattern == "Telekom?d?d?d?d"


def test_the_cli_wires_mask_flags_into_the_config():
    from wifipilot.cli import apply_cli_config, build_parser

    args = build_parser().parse_args(["crack", "x.cap", "--mask", "Telekom-?d?d?d?d",
                                      "--mask", "?d" * 10, "--mask-candidates", "500"])
    config = apply_cli_config(args)
    assert config.use_masks is True
    assert config.mask_patterns == ["Telekom-?d?d?d?d", "?d" * 10]
    assert config.mask_candidates == 500
    # bare --mask keeps meaning "derive the patterns from the target"
    config = apply_cli_config(build_parser().parse_args(["crack", "x.cap", "--mask"]))
    assert config.use_masks is True and config.mask_patterns == []
    # and the stage can be switched off
    config = apply_cli_config(build_parser().parse_args(["crack", "x.cap", "--no-masks"]))
    assert config.use_masks is False

# --------------------------------------------------------------------------- #
# the same knobs through the module API and the web UI
# --------------------------------------------------------------------------- #

def test_a_call_can_carry_its_own_masks(tmp_path, config, session):
    """Per-call masks (the web UI's 🎭 button) must not touch the config."""
    ap, capture, cracker = _crack(tmp_path, config, session, "percall",
                                  mask_candidates=5_000, targeted_candidates=1)
    assert cracker.config.mask_patterns == []
    result = cracker.crack_capture(ap, capture, wordlists=[], timeout=30,
                                   masks=["Telekom000?d"])
    assert result.cracked and result.reason == "mask attack (Telekom000?d)"
    assert cracker.config.mask_patterns == [], "per-call masks stay per-call"
    assert cracker._call_masks == []


def test_the_module_api_takes_a_mask(tmp_path):
    import wifipilot as wp

    path = str(tmp_path / "api.pcap")
    build_capture(path, ESSID, "aa:bb:cc:11:22:33", "02:00:00:00:00:09", PSK)
    wp.configure(targeted_candidates=1, mask_candidates=5_000, wordlists=[])
    try:
        result = wp.crack(path, wordlist=[], mask="Telekom000?d")
    finally:
        wp.reset()
    assert result.cracked and result.password == PSK and result.verified
    assert result.reason == "mask attack (Telekom000?d)"
    assert wp.suggest_masks(ESSID)[0]["mask"].startswith("Telekom")


def test_the_engine_queues_masks_for_the_crack_target(tmp_path, config, session):
    """The web UI path: request_crack(..., masks) -> crack_target(..., masks)."""
    from wifipilot.engine import Engine

    engine = Engine(config, session.bus, session=session, demo=True)
    jobs, seen = {}, {}
    engine.start_worker = lambda: None
    engine.add_job = lambda name, job: jobs.setdefault(name, job)
    engine.crack_target = lambda bssid, wordlists=(), masks=(): seen.update(
        bssid=bssid, wordlists=list(wordlists), masks=list(masks))
    message = engine.request_crack("aa:bb:cc:11:22:33", ["rockyou.txt"],
                                   ["Telekom-?d?d?d?d"])
    assert "1 mask(s)" in message
    assert "crack:aa:bb:cc:11:22:33" in jobs
    jobs["crack:aa:bb:cc:11:22:33"]()             # run what was queued
    assert seen["bssid"] == "aa:bb:cc:11:22:33"
    assert seen["masks"] == ["Telekom-?d?d?d?d"] and seen["wordlists"] == ["rockyou.txt"]
