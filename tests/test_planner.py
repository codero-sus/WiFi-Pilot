# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Planner: scoring, preference ordering and — most importantly — plan validation."""

from __future__ import annotations


from wifipilot.planner import (heuristic_plan, preferred_attacks, rank_targets,
                               score_ap, should_replan, validate_plan)
from tests.conftest import AP_MAC


def _ap(session, bssid=AP_MAC, essid="TestNet", **fields):
    ap, _ = session.upsert_ap(bssid, essid, publish=False, **fields)
    for key, value in fields.items():
        setattr(ap, key, value)
    return ap


def test_scoring_prefers_easy_targets(session):
    wep = _ap(session, "aa:00:00:00:00:01", "wep-net", encryption="WEP", signal=-55)
    wpa3 = _ap(session, "aa:00:00:00:00:02", "wpa3-net", encryption="WPA3", signal=-55)
    open_net = _ap(session, "aa:00:00:00:00:03", "guest", encryption="OPEN", signal=-45)
    wps = _ap(session, "aa:00:00:00:00:04", "wps-net", encryption="WPA2", signal=-70,
              wps=True, wps_locked="unlocked")

    assert score_ap(wep, session.config)[0] > score_ap(wpa3, session.config)[0]
    assert score_ap(open_net, session.config)[0] < 0
    assert score_ap(wpa3, session.config)[0] < 0
    assert score_ap(wps, session.config)[0] > score_ap(wpa3, session.config)[0]
    reasons = score_ap(wep, session.config)[1]
    assert any("WEP" in reason for reason in reasons)


def test_cracked_targets_are_never_selected(session):
    from wifipilot.models import Capture
    ap = _ap(session, encryption="WPA2", signal=-50)
    session.add_capture(Capture(kind="handshake", bssid=ap.bssid, essid=ap.essid,
                                path="/tmp/x.cap", valid=True, password="already"))
    score, reasons = score_ap(ap, session.config)
    assert score < -100
    assert preferred_attacks(ap, session.config) == []
    assert heuristic_plan(session).actions == []


def test_preferred_attacks_reflects_state(session):
    clientless = _ap(session, "aa:00:00:00:01:01", "no-clients", encryption="WPA2", signal=-60)
    with_client = _ap(session, "aa:00:00:00:01:02", "has-client", encryption="WPA2", signal=-60)
    session.add_client(with_client.bssid, "02:00:00:00:00:aa", signal=-50)
    wps = _ap(session, "aa:00:00:00:01:03", "wps", encryption="WPA2", signal=-60, wps=True,
              wps_locked="unlocked")
    wpa3 = _ap(session, "aa:00:00:00:01:04", "sae", encryption="WPA3", signal=-60)

    assert "pmkid" in preferred_attacks(clientless, session.config)
    assert "wps_pixie" in preferred_attacks(wps, session.config)
    assert preferred_attacks(wpa3, session.config) == []


def test_successful_attack_is_not_repeated(session):
    from wifipilot.models import Attempt, STATUS_SUCCESS
    ap = _ap(session, encryption="WPA2", signal=-60, wps=True, wps_locked="unlocked")
    ap.attempts.append(Attempt(attack="wps_pixie", bssid=ap.bssid, status=STATUS_SUCCESS))
    assert "wps_pixie" not in preferred_attacks(ap, session.config)


def test_two_failures_retire_an_attack(session):
    from wifipilot.models import Attempt, STATUS_FAILED
    ap = _ap(session, encryption="WPA2", signal=-60, wps=True, wps_locked="unlocked")
    for _ in range(2):
        ap.attempts.append(Attempt(attack="wps_pixie", bssid=ap.bssid, status=STATUS_FAILED))
    assert "wps_pixie" not in preferred_attacks(ap, session.config)


# ------------------------------------------------------------- validation
def test_validate_plan_accepts_a_sane_llm_answer(session):
    _ap(session, encryption="WPA2", signal=-55)
    raw = {
        "reasoning": "client-less AP, PMKID first",
        "actions": [{"attack": "pmkid", "bssid": AP_MAC.upper(), "priority": 1,
                     "reason": "no clients"}],
        "stop": False,
    }
    plan = validate_plan(raw, session, source="llm", model="llama3.1:8b")
    assert len(plan.actions) == 1
    assert plan.actions[0].attack == "pmkid"
    assert plan.actions[0].bssid == AP_MAC          # normalised
    assert plan.source == "llm" and plan.model == "llama3.1:8b"
    assert plan.dropped == []


def test_validate_plan_rejects_hallucinations(session):
    _ap(session, encryption="WPA2", signal=-55)
    raw = {
        "reasoning": "let's try everything",
        "actions": [
            {"attack": "evil_attack", "bssid": AP_MAC},
            {"attack": "pmkid", "bssid": "11:11:11:11:11:11"},
            {"attack": "pmkid", "bssid": "not-a-mac"},
            {"attack": "pmkid", "bssid": AP_MAC},
            {"attack": "pmkid", "bssid": AP_MAC},
        ],
    }
    plan = validate_plan(raw, session, source="llm")
    assert len(plan.actions) == 1
    assert len(plan.dropped) == 4


def test_validate_plan_enforces_hard_safety_rules(session):
    wpa3 = _ap(session, "aa:00:00:00:02:01", "sae-net", encryption="WPA3", signal=-50)
    open_net = _ap(session, "aa:00:00:00:02:02", "guest", encryption="OPEN", signal=-50)
    wpa2_no_wps = _ap(session, "aa:00:00:00:02:03", "plain", encryption="WPA2", signal=-50)
    raw = {"reasoning": "", "actions": [
        {"attack": "handshake", "bssid": wpa3.bssid},
        {"attack": "pmkid", "bssid": wpa3.bssid},
        {"attack": "handshake", "bssid": open_net.bssid},
        {"attack": "wps_pixie", "bssid": wpa2_no_wps.bssid},
        {"attack": "crack", "bssid": wpa2_no_wps.bssid},
    ]}
    plan = validate_plan(raw, session, source="llm")
    assert plan.actions == []
    assert any("WPA3" in entry for entry in plan.dropped)
    assert any("WPS" in entry for entry in plan.dropped)
    assert any("nothing captured" in entry for entry in plan.dropped)


def test_validate_plan_respects_disabled_attacks_and_stealth(session):
    _ap(session, encryption="WPA2", signal=-50, wps=True, wps_locked="unlocked")
    session.config.attacks = ["handshake"]
    raw = {"actions": [{"attack": "wps_pixie", "bssid": AP_MAC}]}
    plan = validate_plan(raw, session, source="llm")
    assert plan.actions == [] and "disabled" in plan.dropped[0]

    session.config.attacks = ["handshake", "wps_pin"]
    session.config.stealth = True
    raw = {"actions": [{"attack": "wps_pin", "bssid": AP_MAC}]}
    plan = validate_plan(raw, session, source="llm")
    assert plan.actions == [] and "stealth" in plan.dropped[0]


def test_validate_plan_handles_junk(session):
    assert validate_plan("nonsense", session).actions == []
    assert validate_plan({}, session).actions == []
    plan = validate_plan({"actions": [{"attack": "stop", "bssid": AP_MAC}]}, session)
    assert plan.stop and plan.actions == []


def test_validate_plan_orders_by_priority(session):
    a = _ap(session, "aa:00:00:00:03:01", "a", encryption="WPA2", signal=-50)
    b = _ap(session, "aa:00:00:00:03:02", "b", encryption="WPA2", signal=-50)
    raw = {"actions": [
        {"attack": "pmkid", "bssid": b.bssid, "priority": 2},
        {"attack": "handshake", "bssid": a.bssid, "priority": 1},
    ]}
    plan = validate_plan(raw, session, source="llm")
    assert [action.bssid for action in plan.actions] == [a.bssid, b.bssid]


def test_heuristic_plan_picks_reachable_actions(session):
    ap = _ap(session, encryption="WPA2", signal=-45, wps=True, wps_locked="unlocked")
    session.add_client(ap.bssid, "02:00:00:00:00:bb", signal=-45)
    plan = heuristic_plan(session)
    assert plan.actions, plan.reasoning
    assert all(action.attack in session.config.attacks for action in plan.actions)
    assert all(action.bssid == ap.bssid for action in plan.actions)


def test_should_replan_triggers(session):
    due, why = should_replan(session, None)
    assert due and why                      # never planned -> plan now
    _ap(session, encryption="WPA2", signal=-50)
    plan = heuristic_plan(session)
    assert plan.actions
    due, why = should_replan(session, plan, interval=999)
    assert not due                          # nothing to do and no failures yet
    due, why = should_replan(session, plan, failures=2, interval=999)
    assert due and "failure" in why         # repeated failures force a rethink
    due, why = should_replan(session, plan, new_aps=5, interval=999)
    assert due and "new access points" in why


def test_rank_targets_sorted_by_score(session):
    _ap(session, "aa:00:00:00:04:01", "weak", encryption="WPA3", signal=-70)
    _ap(session, "aa:00:00:00:04:02", "easy", encryption="WEP", signal=-50)
    ranked = rank_targets(session, session.config, limit=5)
    assert ranked[0][0].essid == "easy"
    assert ranked[0][1] > ranked[1][1]
