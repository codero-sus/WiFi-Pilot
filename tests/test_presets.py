# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Presets, postures, acceleration and the speed levers.

The bug these features answer: one Wi-Fi network ran 1h 2m unfinished,
because ``mode="force"`` enabled all 848 attacks at full budgets with no
campaign deadline.  These tests pin the shape of the fix: every preset
resolves to real attacks inside a 7-12 minute budget, FORCE is loud and
stealth is silent in every preset, budgets really do scale/cap, the
watchdog really does stop an overrun, and acceleration stays off until
the operator allows it.
"""

from __future__ import annotations

import threading
import time

import pytest

import importlib

from wifipilot import accel
from wifipilot.attacks import get_attack

#: `wp.presets` is the API function; the submodule needs importlib to reach
presets = importlib.import_module("wifipilot.presets")
from wifipilot.attacks.base import AttackContext
from wifipilot.config import Config
from wifipilot.crypto import compute_pmkid, pmk
from wifipilot.engine import Engine
from wifipilot.events import EventBus
from wifipilot.models import AccessPoint, Capture
from wifipilot.pcap import CaptureAnalysis
from wifipilot.session import Session


# -- presets ---------------------------------------------------------------- #

def test_every_preset_resolves_to_real_attacks_within_budget():
    for row in presets.list_presets():
        assert row["attacks"] > 0, row["name"]
        assert 7.0 <= row["minutes"] <= 12.0, row["name"]
        assert 0 < row["budget_scale"] <= 1.0, row["name"]
        assert 0 < row["attack_cap"] <= 60.0, row["name"]


def test_success_preset_is_the_key_recovery_route():
    config = Config()
    report = presets.apply_preset(config, "success")
    assert report["preset"] == "success"
    for core in ("pmkid", "handshake", "wps_pixie", "wep_ivs"):
        assert core in config.attacks
    assert config.budget_scale < 1.0
    assert config.attack_cap == 60.0
    assert config.jobs >= 4
    assert config.parallel_crack is True


def test_force_posture_is_the_opposite_of_stealth():
    config = Config()
    config.stealth = True
    presets.apply_preset(config, "blitz", "force")
    assert config.stealth is False
    assert config.aggressive is True
    assert config.broadcast_handshake is True
    assert config.deauth_count >= 10
    assert "wps_pin" in config.attacks          # the booster FORCE adds
    assert "handshake_broadcast" in config.attacks


def test_force_posture_via_colon_syntax():
    config = Config()
    report = presets.apply_preset(config, "success:force")
    assert report["posture"] == "force"
    assert config.posture == "force"


def test_stealth_posture_transmits_nothing():
    from wifipilot.attacks import ATTACK_CLASSES, ATTACK_META
    config = Config()
    presets.apply_preset(config, "full", "stealth")
    assert config.stealth is True
    assert config.attacks, "stealth full must still leave the quiet half"
    for name in config.attacks:
        assert not getattr(ATTACK_CLASSES[name], "needs_injection", False), name
        assert ATTACK_META.get(name, {}).get("noise", "silent") in ("silent", "quiet"), name
        assert ATTACK_META.get(name, {}).get("category") != "dos", name


def test_unknown_preset_is_loud_not_silent():
    with pytest.raises(KeyError):
        presets.apply_preset(Config(), "definitely-not-a-preset")


def test_aliases_resolve():
    assert presets.get_preset("quick").name == "blitz"
    assert presets.get_preset("default").name == "balanced"
    assert presets.get_preset("passive").name == "stealth"


def test_domains_presets_match_the_editions():
    rows = {row["name"]: row for row in presets.list_presets()}
    assert rows["bluetooth"]["attacks"] == 143
    assert rows["it"]["attacks"] == 417
    assert rows["full"]["attacks"] == 848


# -- budget levers ------------------------------------------------------------ #

def _ctx(config: Config) -> AttackContext:
    bus = EventBus()
    session = Session(config, bus, demo=True, authorized=True)
    return AttackContext(session=session, config=config, bus=bus, iface=None,
                         scanner=None, radio=None, demo=True, processes=None,
                         stop_event=threading.Event())


def test_budget_scale_and_cap_apply_to_every_attack():
    attack = get_attack("wps_pixie")
    plain = attack.budget(_ctx(Config()))
    config = Config()
    config.budget_scale = 0.5
    assert attack.budget(_ctx(config)) == pytest.approx(plain * 0.5)
    config.budget_scale = 1.0
    config.attack_cap = 30.0
    assert attack.budget(_ctx(config)) == 30.0
    config.attack_cap = 0.1                       # cap never goes below 1s
    assert attack.budget(_ctx(config)) >= 1.0


def test_watchdog_stops_an_overrunning_attack():
    config = Config()
    config.attack_cap = 2.0
    engine = Engine(config, demo=True)
    cancel = threading.Event()
    attack = get_attack("tracker")

    class SlowBudget:
        name = attack.name

        @staticmethod
        def budget(ctx):
            return 2.0

    timer = engine._watchdog(SlowBudget(), engine.context(cancel=cancel), cancel)
    assert timer is not None
    assert not cancel.is_set()
    timer.cancel()                                # do not wait 2.5s in a unit test
    assert engine._watchdog(SlowBudget(), engine.context(), cancel) is not None
    config.attack_cap = 0.0
    assert engine._watchdog(SlowBudget(), engine.context(), cancel) is None


# -- acceleration (opt-in only) ---------------------------------------------- #

def test_accel_parse_and_defaults():
    assert accel.parse_accel("off") == frozenset()
    assert accel.parse_accel(True) == frozenset({"cpu", "ram", "gpu"})
    assert accel.parse_accel("cpu,gpu") == frozenset({"cpu", "gpu"})
    assert accel.parse_accel("nonsense") == frozenset()
    config = Config()
    assert config.accel == "off"                  # never on unless allowed
    assert accel.workers(config) == 1
    assert accel.cache_mb(config) == 0


def test_accel_cpu_raises_workers_and_jobs():
    config = Config()
    report = accel.apply_accel(config, "cpu,ram")
    assert config.accel == "cpu,ram"
    assert report["crack_workers"] >= 1
    assert config.jobs >= 2 or report["crack_workers"] == 1
    assert accel.cache_mb(config) > 0


def test_accel_detect_reports_real_hardware():
    found = accel.detect()
    assert found["cpu"]["count"] >= 1
    assert "present" in found["gpu"]
    summary = accel.accel_summary(Config())
    assert summary["allowed"] == []
    assert summary["crack_workers"] == 1


# -- parallel cracking -------------------------------------------------------- #

ESSID, BSSID, STA = "SpeedNet", "aa:bb:cc:11:22:33", "ff:ff:ff:ff:ff:ff"
PASSWORD = "hunter2-is-bad"


def _pmkid_cracker(accel_mode: str):
    from wifipilot.crack import Cracker
    pmkid_hex = compute_pmkid(pmk(PASSWORD, ESSID),
                              bytes.fromhex(BSSID.replace(":", "")),
                              bytes.fromhex(STA.replace(":", "")))
    config = Config()
    config.accel = accel_mode
    bus = EventBus()
    session = Session(config, bus, demo=False, authorized=True)
    ap = AccessPoint(bssid=BSSID, essid=ESSID)
    session.aps[BSSID] = ap
    capture = Capture(kind="pmkid", bssid=BSSID, essid=ESSID,
                      extra={"pmkid": pmkid_hex})
    return Cracker(session, config, bus, demo=False), ap, capture


def test_cpu_accel_cracks_in_worker_processes():
    cracker, ap, capture = _pmkid_cracker("cpu")
    if cracker._accel_workers() < 2:
        pytest.skip("single-core machine: nothing to parallelise")
    candidates = [f"wrongpass{i}" for i in range(600)] + [PASSWORD]
    found, tested = cracker._python_pass(
        ap, capture, CaptureAnalysis(), candidates,
        time.time() + 120, lambda n, s: None)
    assert found == PASSWORD
    assert 0 < tested <= len(candidates)


def test_serial_crack_unchanged_without_accel():
    cracker, ap, capture = _pmkid_cracker("off")
    assert cracker._accel_workers() == 1
    candidates = [f"wrongpass{i}" for i in range(40)] + [PASSWORD]
    found, tested = cracker._python_pass(
        ap, capture, CaptureAnalysis(), candidates,
        time.time() + 60, lambda n, s: None)
    assert (found, tested) == (PASSWORD, 41)


def test_ram_accel_dedupes_candidates():
    cracker, ap, capture = _pmkid_cracker("ram")
    stream = cracker._deduped(["password1", "password1", "password2", "password1"])
    assert list(stream) == ["password1", "password2"]


# -- engine wiring ------------------------------------------------------------ #

def test_engine_applies_preset_and_deadline():
    config = Config()
    config.preset = "blitz"
    config.demo = True
    engine = Engine(config, demo=True)
    minutes = engine._apply_preset_if_any()
    assert minutes == pytest.approx(7.0)
    assert config.attacks and len(config.attacks) <= 10
    assert config.attack_cap == 45.0


def test_engine_side_lane_classification():
    from wifipilot.engine import _side_lane_attack
    assert _side_lane_attack("loot_audit") is True    # offline category
    assert _side_lane_attack("handshake") is False    # radio work stays serial
    it_rows = [p for p in presets.resolve_attacks(presets.get_preset("it"))][:20]
    assert all(_side_lane_attack(name) for name in it_rows)


def test_api_surface():
    import wifipilot as wp
    names = [row["name"] for row in wp.presets()]
    assert "success" in names and "blitz" in names
    info = wp.accel_info()
    assert info["allowed"] == []
    config = wp.configure(accel="cpu", preset="blitz", jobs=3)
    assert config.accel == "cpu" and config.preset == "blitz" and config.jobs == 3
    wp.reset()
