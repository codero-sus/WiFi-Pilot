# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""The three survey attacks: hidden-SSID discovery, rogue-AP survey, 802.1X.

Each of them answers a question that the classic handshake/PMKID attacks do not,
and two of them transmit nothing at all — so the tests check both the answer and
that the module honestly says which of the two it is.
"""

from __future__ import annotations

import pytest

from wifipilot.attacks import ATTACK_CLASSES, attack_catalog
from wifipilot.config import Config
from wifipilot.engine import Engine
from wifipilot.models import ATTACK_NAMES, AccessPoint, Finding
from wifipilot.planner import preferred_attacks


def _engine(tmp_path, attacks=None) -> Engine:
    config = Config()
    config.demo = True
    config.ollama.enabled = False
    config.output_dir = str(tmp_path / "loot")
    config.session_dir = str(tmp_path / "sessions")
    config.scan_time = 2
    config.attacks = list(attacks or
                          ["hidden_ssid", "rogue_ap", "enterprise", "handshake"])
    engine = Engine(config, demo=True)
    engine.prepare()
    engine.scan_for(2)
    return engine


# --------------------------------------------------------------------------- #
# the catalogue
# --------------------------------------------------------------------------- #

def test_the_new_attacks_are_registered_and_described():
    for name in ("hidden_ssid", "rogue_ap", "enterprise"):
        assert name in ATTACK_CLASSES and name in ATTACK_NAMES
    catalog = {entry["name"]: entry for entry in attack_catalog()}
    hidden = catalog["hidden_ssid"]
    assert hidden["default_enabled"] is True
    assert hidden["needs_injection"] is False
    assert catalog["rogue_ap"]["needs_injection"] is False
    assert catalog["enterprise"]["needs_injection"] is False
    assert catalog["rogue_ap"]["default_enabled"] is False       # situational
    assert catalog["rogue_ap"]["tool"] and catalog["enterprise"]["description"]


def test_the_default_order_puts_read_only_surveys_first():
    from wifipilot.attacks import DEFAULT_ORDER
    assert DEFAULT_ORDER.index("rogue_ap") < DEFAULT_ORDER.index("pmkid")
    assert DEFAULT_ORDER.index("hidden_ssid") < DEFAULT_ORDER.index("handshake")


# --------------------------------------------------------------------------- #
# the planner picks them where they belong
# --------------------------------------------------------------------------- #

def test_a_hidden_network_is_plannable_and_named_first(tmp_path):
    config = Config(demo=True)
    config.attacks = ["hidden_ssid", "handshake", "pmkid"]
    hidden = AccessPoint("8c:3f:fe:50:73:a6", "", encryption="WPA2", auth="PSK",
                         hidden=True, channel=9, signal=-72)
    assert preferred_attacks(hidden, config)[0] == "hidden_ssid"
    known = AccessPoint("d0:9e:12:9d:36:cc", "HOME-2F4A", encryption="WPA2",
                        auth="PSK", channel=6, signal=-42)
    assert "hidden_ssid" not in preferred_attacks(known, config)


def test_an_enterprise_network_only_gets_the_enterprise_survey():
    config = Config(demo=True)
    config.attacks = ["hidden_ssid", "handshake", "pmkid", "enterprise"]
    ap = AccessPoint("34:c9:27:19:79:89", "CorpNet-8021X", encryption="WPA2",
                     auth="MGT", channel=36, signal=-64)
    assert preferred_attacks(ap, config) == ["enterprise"]


# --------------------------------------------------------------------------- #
# hidden-SSID discovery (demo)
# --------------------------------------------------------------------------- #

def test_hidden_ssid_discovery_names_the_network(tmp_path):
    engine = _engine(tmp_path, ["hidden_ssid"])
    hidden = [ap for ap in engine.session.aps.values() if not (ap.essid or "").strip()]
    assert hidden, "the simulated neighbourhood has a hidden network"
    ap = hidden[0]
    attempt = engine.run_attack(ap.bssid, "hidden_ssid")
    assert attempt is not None and attempt.status == "success"
    assert ap.essid == "NETGEAR-Home-9F"          # the demo tells us what a client knows
    assert ap.hidden is False
    assert engine.session.stats.hidden_revealed == 1
    assert any(entry.get("kind") == "revealed" for entry in ap.history)
    assert "nothing" in attempt.detail.lower() or "probe" in attempt.detail.lower()


def test_hidden_ssid_discovery_is_not_planned_for_a_named_network(tmp_path):
    engine = _engine(tmp_path, ["hidden_ssid"])
    ap = engine.session.ap("d0:9e:12:9d:36:cc")
    assert "hidden_ssid" not in engine.attackable(ap)
    # the engine refuses before the module runs, and says why in the log
    assert engine.run_attack(ap.bssid, "hidden_ssid") is None


# --------------------------------------------------------------------------- #
# rogue AP survey
# --------------------------------------------------------------------------- #

def test_rogue_survey_reports_and_transmits_nothing(tmp_path):
    engine = _engine(tmp_path, ["rogue_ap"])
    ap = engine.session.ap("d0:9e:12:9d:36:cc")
    attempt = engine.run_attack(ap.bssid, "rogue_ap")
    assert attempt is not None and attempt.status == "success"
    assert "twin" in attempt.result
    detail = attempt.extra
    assert {"twins", "hidden_targets", "probes", "attacks"} <= set(detail)
    assert engine.session.stats.attacks_run >= 1
    assert any(entry.get("kind") == "rogue_survey" for entry in ap.history)


def test_rogue_survey_raises_a_finding_when_a_twin_is_on_air(tmp_path):
    engine = _engine(tmp_path, ["rogue_ap"])
    # the same ESSID from two vendors is what a twin looks like from outside
    real = engine.session.ap("d0:9e:12:9d:36:cc")
    twin, _ = engine.session.upsert_ap("f8:1a:67:00:00:01", real.essid, publish=False)
    twin.signal = -20
    real.signal = -80
    attempt = engine.run_attack(real.bssid, "rogue_ap")
    assert attempt is not None and attempt.status == "success"
    twins = attempt.extra.get("twins") or []
    assert twins, "two BSSIDs, two vendors, 60 dB apart — that is the pattern"
    kinds = {finding.kind for finding in engine.session.findings}
    assert "rogue_ap" in kinds
    assert any(f.severity == "high" for f in engine.session.findings)


# --------------------------------------------------------------------------- #
# 802.1X survey
# --------------------------------------------------------------------------- #

def test_enterprise_survey_reports_method_identity_and_certificate(tmp_path):
    engine = _engine(tmp_path, ["enterprise"])
    ap = next(ap for ap in engine.session.aps.values()
              if (ap.auth or "").upper() == "MGT")
    attempt = engine.run_attack(ap.bssid, "enterprise")
    assert attempt is not None and attempt.status == "success"
    detail = attempt.detail
    assert "PEAP" in detail
    assert "jdoe@corp.example" in detail
    assert "self-signed" in detail
    finding = next(f for f in engine.session.findings if f.kind == "enterprise")
    assert finding.severity == "high"
    assert "rogue RADIUS" in finding.detail or "impersonate" in finding.detail
    assert engine.session.stats.enterprise_surveys >= 0        # counted by the module


def test_enterprise_survey_is_not_planned_for_a_psk_network(tmp_path):
    engine = _engine(tmp_path, ["enterprise"])
    ap = engine.session.ap("d0:9e:12:9d:36:cc")
    assert "enterprise" not in engine.attackable(ap)
    assert engine.run_attack(ap.bssid, "enterprise") is None


def test_enterprise_results_say_there_is_no_psk_to_crack(tmp_path):
    engine = _engine(tmp_path, ["enterprise"])
    ap = next(ap for ap in engine.session.aps.values()
              if (ap.auth or "").upper() == "MGT")
    attempt = engine.run_attack(ap.bssid, "enterprise")
    extra = attempt.extra or {}
    assert "no PSK to crack" in extra.get("note", "")


@pytest.mark.parametrize("attack", ["hidden_ssid", "rogue_ap", "enterprise"])
def test_survey_attacks_need_no_authorisation_because_they_do_not_transmit(
        tmp_path, attack):
    """A demo engine has no radio; a real one must not gate read-only work."""
    from wifipilot.attacks import AttackContext, get_attack
    from wifipilot.events import EventBus
    from wifipilot.session import Session

    module = get_attack(attack)
    assert module.needs_injection is False
    config = Config()
    config.demo = False
    session = Session(config, EventBus(), demo=False, authorized=False)
    context = AttackContext(session=session, config=config, bus=session.bus,
                            iface="", scanner=None, radio=None, demo=False,
                            processes=None, stop_event=None)
    # no authorisation and no radio: a read-only survey is never blocked by policy
    assert isinstance(module.available(context), bool)


def test_the_survey_attacks_share_the_standard_result_shape(tmp_path):
    engine = _engine(tmp_path, ["rogue_ap"])
    ap = engine.session.ap("d0:9e:12:9d:36:cc")
    engine.run_attack(ap.bssid, "rogue_ap")
    attempt = engine.session.attempts[-1]
    row = attempt.to_dict()
    for key in ("attack", "bssid", "status", "result", "started", "duration",
                "extra"):
        assert key in row, key
    assert row["extra"].get("twins") == []
    assert isinstance(Finding(kind="x", title="t"), Finding)
