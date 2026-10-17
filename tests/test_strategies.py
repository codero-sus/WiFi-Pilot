# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Crack strategy presets, the stage order, and rule files reaching the engine.

The point of the presets is that an operator picks one word ("thorough") instead
of six flags, and that the cracking *order* is data rather than code: these
tests pin the contract, including that a preset only ever touches the knobs it
advertises.
"""

from __future__ import annotations

import time

import pytest

from wifipilot.config import Config
from wifipilot.crack import (STRATEGIES, Cracker, apply_strategy, smart_candidates,
                             strategy, strategy_names)
from wifipilot.events import EventBus
from wifipilot.models import AccessPoint, Capture
from wifipilot.session import Session


def _session(tmp_path, **knobs) -> Session:
    config = Config()
    config.demo = True
    config.output_dir = str(tmp_path / "loot")
    config.session_dir = str(tmp_path / "sessions")
    for key, value in knobs.items():
        setattr(config, key, value)
    return Session(config, EventBus(), demo=True)


def test_the_presets_are_the_documented_set():
    assert set(strategy_names()) == {
        "quick", "default", "thorough", "insane",
        "mask-only", "wordlist-only", "pixie-then-crack",
    }
    for name in strategy_names():
        preset = strategy(name)
        assert preset["label"] == name
        assert preset["note"], f"{name} has no explanation"
        assert preset["order"], f"{name} has no stage order"


def test_every_preset_names_only_stages_that_exist():
    known = {"targeted", "masks", "hashcat-masks", "external", "builtin"}
    for name in strategy_names():
        stages = [part.strip() for part in str(strategy(name)["order"]).split(",")]
        assert stages, name
        assert set(stages) <= known, f"{name}: {set(stages) - known}"


def test_presets_are_ordered_from_cheap_to_expensive():
    """A stronger preset must never spend less than a weaker one."""
    quick = STRATEGIES["quick"]
    default = STRATEGIES["default"]
    thorough = STRATEGIES["thorough"]
    insane = STRATEGIES["insane"]
    assert quick["targeted_candidates"] < default["targeted_candidates"]
    assert default["targeted_candidates"] < thorough["targeted_candidates"]
    assert thorough["targeted_candidates"] < insane["targeted_candidates"]
    assert quick["mask_candidates"] < default["mask_candidates"]
    assert default["mask_candidates"] < thorough["mask_candidates"]
    assert quick["crack_timeout"] < default["crack_timeout"] < insane["crack_timeout"]


def test_mask_only_uses_no_dictionaries_and_wordlist_only_uses_no_masks():
    assert STRATEGIES["mask-only"]["targeted_candidates"] == 0
    assert STRATEGIES["mask-only"]["wordlists"] == 0
    assert STRATEGIES["wordlist-only"]["mask_candidates"] == 0
    assert "masks" not in str(STRATEGIES["wordlist-only"]["order"])


def test_apply_strategy_stamps_the_config():
    config = Config()
    preset = apply_strategy(config, "thorough")
    assert config.crack_strategy == "thorough"
    assert config.rule_file == "best64"
    assert config.use_rules is True
    assert config.wordlist_limit == preset["wordlists"]
    assert config.crack_order == preset["order"]
    assert config.targeted_candidates == preset["targeted_candidates"]


def test_a_mask_less_strategy_turns_masks_off():
    config = Config()
    apply_strategy(config, "wordlist-only")
    assert config.use_masks is False


def test_an_unknown_strategy_names_the_known_ones():
    with pytest.raises(KeyError) as error:
        apply_strategy(Config(), "turbo")
    assert "turbo" in str(error.value)
    assert "thorough" in str(error.value)


def test_an_unknown_preset_is_an_empty_dict_not_an_exception():
    """`strategy()` is the lookup; `apply_strategy()` is the one that complains."""
    assert strategy("nope") == {}
    assert strategy("  QUICK  ")["label"] == "quick"


# --------------------------------------------------------------------------- #
# the stage order really drives the crack
# --------------------------------------------------------------------------- #

def _mini_wordlist(tmp_path) -> str:
    """A wordlist with nothing useful in it, so a stage cannot grind for long."""
    path = tmp_path / "mini.txt"
    path.write_text("notthepassword\nstillnotit\n")
    return str(path)


def _capture(tmp_path, password="BenchNet2024"):
    from wifipilot.synth import build_capture

    path = tmp_path / "capture.pcap"
    build_capture(str(path), "BenchNet", "d0:9e:12:9d:36:cc", "02:00:00:00:00:11",
                  password, include_pmkid=True)
    return Capture(kind="handshake", bssid="d0:9e:12:9d:36:cc", essid="BenchNet",
                   path=str(path), valid=True)


def test_the_built_in_engine_is_stage_driven(tmp_path):
    """Each stage reports its own attempts, and the order comes from the config."""
    session = _session(tmp_path, use_masks=False, use_rules=False,
                       targeted_candidates=50, crack_order="targeted,builtin")
    cracker = Cracker(session)
    ap, _ = session.upsert_ap("d0:9e:12:9d:36:cc", "BenchNet", publish=False)
    # a PSK the target-derived list cannot reach, on purpose: the stages must
    # run and report honest work, not invent a crack
    capture = _capture(tmp_path, password="zzqqww9911xy")
    started = time.time()
    result = cracker.crack_capture(ap, capture, wordlists=[_mini_wordlist(tmp_path)],
                                   timeout=30)
    assert time.time() - started < 120
    assert result.cracked is False
    assert result.attempts > 0, "a stage that tried nothing must not report success"
    assert result.seconds >= 0


def test_a_stage_outside_the_order_does_not_run(tmp_path):
    """`crack_order` is the contract; a disabled stage must stay disabled."""
    session = _session(tmp_path, crack_order="targeted,builtin", mask_candidates=1000)
    cracker = Cracker(session)

    def explode(*args, **kwargs):                     # pragma: no cover - must not run
        raise AssertionError("the masks stage ran although it is not in crack_order")

    cracker._stage_masks = explode                     # type: ignore[method-assign]
    ap, _ = session.upsert_ap("d0:9e:12:9d:36:cc", "BenchNet", publish=False)
    capture = _capture(tmp_path, password="zzqqww9911xy")
    result = cracker.crack_capture(ap, capture, wordlists=[_mini_wordlist(tmp_path)],
                                   timeout=30)
    assert result.cracked is False


def test_a_rule_file_reaches_the_built_in_engine(tmp_path):
    """`rule_file` is not decoration: the candidates must actually be produced."""
    session = _session(tmp_path, use_masks=False, targeted_candidates=0,
                       rule_file=str(_write_rule(tmp_path)),
                       crack_order="builtin")
    cracker = Cracker(session)
    ap, _ = session.upsert_ap("d0:9e:12:9d:36:cc", "BenchNet", publish=False)
    capture = _capture(tmp_path, password="benchnetx")   # a rule-only mutation
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("benchnet\n")
    result = cracker.crack_capture(ap, capture, wordlists=[str(wordlist)])
    assert result.cracked is True, result.reason
    assert result.password == "benchnetx"


def _write_rule(tmp_path):
    path = tmp_path / "append-x.rule"
    path.write_text("$x\n")
    return path


def test_the_stage_order_can_be_reversed_without_touching_code(tmp_path):
    session = _session(tmp_path, crack_order="builtin,targeted")
    assert Cracker(session)._stage_order() == ["builtin", "targeted"]
    session.config.crack_order = "not-a-stage,builtin,also-not"
    assert Cracker(session)._stage_order() == ["builtin"], \
        "unknown stages are dropped, not run"


def test_smart_candidates_use_the_vendor_scheme():
    """Targeted candidates must be target-derived, not a generic dictionary."""
    ap = AccessPoint("d0:12:cb:00:00:01", "FRITZ!Box 7590 QY")
    ap.enrich()
    candidates = list(smart_candidates(ap))
    assert candidates, "no candidates for a known router brand"
    assert all(8 <= len(item) <= 63 for item in candidates), "not WPA passphrases"
    assert len(set(candidates)) == len(candidates), "duplicates waste the budget"
    lowered = [item.lower() for item in candidates]
    assert any("fritz" in item for item in lowered), "the ESSID never made it in"
    assert any("avm" in item or "7590" in item for item in lowered), \
        "the vendor/pattern words never made it in"


def test_smart_candidates_can_fill_a_small_budget():
    """The generator is lazy: a caller with a 25-candidate budget still gets 25."""
    ap = AccessPoint("d0:9e:12:9d:36:cc", "TP-LINK_1A2B")
    ap.enrich()
    assert len(list(smart_candidates(ap))[:25]) == 25
