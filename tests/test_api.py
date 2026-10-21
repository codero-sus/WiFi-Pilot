# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""The scriptable module API: ``import wifipilot as wp; wp.attack(...)``.

Everything here runs in simulation mode, so the tests exercise the real API
surface — configuration, the authorisation gate, target resolution, the campaign
loop, cracking a file — without a radio.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

import wifipilot as wp
from wifipilot.models import AccessPoint
from wifipilot.synth import build_capture
from tests.conftest import AP_MAC, PSK, SSID, STA_MAC

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(autouse=True)
def clean_context(monkeypatch):
    """Every test starts from a fresh, deterministic, simulated context."""
    monkeypatch.setenv("WIFIPILOT_ALLOW_NON_LINUX", "1")
    monkeypatch.delenv("WIFIPILOT_PLATFORM", raising=False)
    wp.reset()
    wp.configure(demo=True, provider="none", scan_time=2, use_rules=False)
    yield
    wp.stop()
    wp.reset()


# --------------------------------------------------------------------------- #
# the package surface
# --------------------------------------------------------------------------- #


def test_public_names_are_importable_from_the_package_root():
    for name in wp.__all__:
        assert hasattr(wp, name), name
    for name in ("attack", "scan", "crack", "analyze", "configure", "authorize",
                 "subscribe", "stop", "reset", "status", "loot", "report",
                 "set_provider", "providers", "current_run"):
        assert callable(getattr(wp, name)), name


def test_import_does_not_require_a_radio_or_the_web_extras():
    """``import wifipilot`` must be safe on a machine with nothing installed."""
    code = ("import sys; sys.modules['fastapi'] = None; import wifipilot as wp; "
            "print(wp.__version__)")
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                          cwd=str(ROOT))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip()


# --------------------------------------------------------------------------- #
# configuration and authorisation
# --------------------------------------------------------------------------- #


def test_configure_accepts_documented_options():
    config = wp.configure(demo=True, stealth=True, scan_time=7, interface="wlan9",
                          attacks=["handshake", "pmkid"], attack_timeout=45,
                          handshake_timeout=90, use_rules=False, provider="ollama",
                          model="llama3.1:8b", output_dir="/tmp/wp-api-loot")
    assert config.demo and config.stealth and config.interface == "wlan9"
    assert config.attacks == ["handshake", "pmkid"]
    assert config.scan_time == 7 and config.handshake_timeout == 90
    assert config.ollama.model == "llama3.1:8b" and config.ollama.enabled
    assert config.output_dir == "/tmp/wp-api-loot"


def test_configure_accepts_a_single_wordlist_and_comma_separated_attacks():
    config = wp.configure(wordlist="/tmp/words.txt", attacks="pmkid,handshake")
    assert config.wordlists == ["/tmp/words.txt"]
    assert config.attacks == ["pmkid", "handshake"]


def test_configure_provider_and_model_routing():
    config = wp.configure(provider="openrouter", model="openai/gpt-4o-mini",
                          ai_budget=1.5, redact_identifiers=True)
    assert config.ai_provider == "openrouter"
    assert config.openrouter.enabled is True             # asking for it enables it
    assert config.openrouter.model == "openai/gpt-4o-mini"
    assert config.openrouter.max_cost_usd == 1.5
    assert config.openrouter.redact_identifiers is True
    config = wp.configure(provider="ollama", model="qwen2.5:7b")
    assert config.ollama.model == "qwen2.5:7b" and config.ai_provider == "ollama"


def test_provider_helpers_report_status():
    rows = wp.providers()
    assert {row["name"] for row in rows} == {"ollama", "cortex", "openrouter"}
    status = wp.advisor_status()
    assert status["provider"] in ("ollama", "cortex", "openrouter", "none")
    assert "cloud" in status and "policy" in status
    with pytest.raises(ValueError):
        wp.set_provider("gpt-9000")


def test_configure_rejects_unknown_options():
    with pytest.raises(TypeError) as excinfo:
        wp.configure(nonsense_option=1)
    assert "nonsense_option" in str(excinfo.value)


def test_authorize_records_the_note():
    assert wp.config().authorized is False
    wp.authorize("change ticket CHG-42, lab range 10.0.0.0/24")
    assert wp.config().authorized is True
    assert "CHG-42" in wp.config().authorization_note


def test_live_run_without_authorisation_is_refused():
    wp.configure(demo=False)
    assert wp.config().authorized is False
    with pytest.raises(wp.AuthorizationError) as excinfo:
        wp.attack(target=all, mode="force")
    assert "authoris" in str(excinfo.value).lower()


def test_modes_catalogue_is_exposed():
    assert {"force", "stealth", "quick", "passive", "default", "recall"} <= set(wp.MODES)
    assert wp.MODES["force"]["wps_pin"] is True          # the loud preset
    assert wp.MODES["stealth"]["stealth"] is True
    assert "wps_pin" not in wp.MODES["quick"]["attacks"]
    assert wp.MODES["recall"] is wp.MODES["default"]     # alias


def test_unknown_mode_lists_the_valid_ones():
    with pytest.raises(ValueError) as excinfo:
        wp.attack(target=all, mode="turbo", demo=True)
    assert "force" in str(excinfo.value) and "turbo" in str(excinfo.value)


def test_wildcard_targets_accept_all_prefer_all_strings_and_none():
    for wildcard in (all, wp.ALL, "all", "*", None):
        assert wp.api._is_wildcard(wildcard)
    assert not wp.api._is_wildcard(AP_MAC)
    assert not wp.api._is_wildcard("TestNet")


def test_demo_shortcut_switches_the_context():
    wp.configure(demo=False)
    wp.demo()
    assert wp.config().demo is True
    wp.demo(False)
    assert wp.config().demo is False


# --------------------------------------------------------------------------- #
# scanning
# --------------------------------------------------------------------------- #


def test_scan_returns_sorted_access_points():
    result = wp.scan(duration=2)
    assert result.aps and result.session
    assert result.demo and result.modes == "scan"
    scores = [ap.score for ap in result.aps]
    assert scores == sorted(scores, reverse=True)        # best target first


def test_scan_result_selector_helpers():
    result = wp.scan(duration=2)
    first = result.aps[0]
    assert result.get(first.bssid.upper()) is first
    assert result.by_ssid(first.essid[:4])
    assert result.get("00:00:00:00:00:00") is None
    assert result.strongest(3) == result.aps[:3]
    payload = result.to_dict()
    assert len(payload["access_points"]) == len(result.aps)
    assert payload["session"] == result.session.id and payload["demo"] is True


# --------------------------------------------------------------------------- #
# target resolution
# --------------------------------------------------------------------------- #


class _FakeSession:
    """Just the access-point store, for exercising the selector without a radio."""

    def __init__(self, aps):
        self._aps = aps

    def sorted_aps(self):
        return list(self._aps)


def _aps():
    return [
        AccessPoint(bssid="aa:bb:cc:11:22:33", essid="CorpNet", signal=-40),
        AccessPoint(bssid="aa:bb:cc:44:55:66", essid="CorpNet-Guest", signal=-60),
        AccessPoint(bssid="de:ad:be:ef:00:01", essid="", signal=-80),
    ]


def test_select_resolves_every_target_shape():
    session = _FakeSession(_aps())
    assert wp.api._select(session, all) == ["aa:bb:cc:11:22:33", "aa:bb:cc:44:55:66",
                                           "de:ad:be:ef:00:01"]
    assert wp.api._select(session, "aa:bb:cc:44:55:66") == ["aa:bb:cc:44:55:66"]
    assert wp.api._select(session, "AA:BB:CC:44:55:66") == ["aa:bb:cc:44:55:66"]
    assert wp.api._select(session, "CorpNet") == ["aa:bb:cc:11:22:33",
                                                  "aa:bb:cc:44:55:66"]
    assert wp.api._select(session, "Guest") == ["aa:bb:cc:44:55:66"]
    assert wp.api._select(session, ["de:ad:be:ef:00:01", "CorpNet"]) == [
        "aa:bb:cc:11:22:33", "aa:bb:cc:44:55:66", "de:ad:be:ef:00:01"]
    assert wp.api._select(session, _aps()[0]) == ["aa:bb:cc:11:22:33"]
    # an empty target means "everything", exactly like ``all``/``None``
    assert wp.api._select(session, "") == ["aa:bb:cc:11:22:33", "aa:bb:cc:44:55:66",
                                           "de:ad:be:ef:00:01"]


def test_select_rejects_an_unmatched_target_and_says_what_it_saw():
    with pytest.raises(wp.TargetError) as excinfo:
        wp.api._select(_FakeSession(_aps()), "no-such-network")
    message = str(excinfo.value)
    assert "no-such-network" in message and "CorpNet" in message


def test_empty_scan_has_its_own_message():
    with pytest.raises(wp.TargetError) as excinfo:
        wp.api._select(_FakeSession([]), all)
    assert "no access points found" in str(excinfo.value)


def test_attack_with_a_typo_in_the_target_fails_before_attacking():
    with pytest.raises(wp.TargetError):
        wp.attack(target="no-such-network-anywhere", demo=True, duration="2s",
                  scan_time="2s")


# --------------------------------------------------------------------------- #
# campaigns
# --------------------------------------------------------------------------- #


def test_quick_campaign_recovers_and_verifies_loot():
    result = wp.attack(target=all, mode="quick", demo=True, duration="45s",
                       scan_time="3s", max_targets=1)
    assert result.demo and result.error == ""            # simulation needs no authorisation
    assert result.modes == "quick"
    assert result.aps and result.loot
    assert result.passwords, "a recovery should be possible in 45s of simulation"
    for item in result.passwords:
        assert item["password"] and item["verified"] is True
        assert result.get(item["bssid"]).password == item["password"]
    assert result.cracked() == result.passwords
    assert result.summary().startswith("simulation ")
    summary = result.summary()
    assert "password recovered" in summary or "passwords recovered" in summary
    payload = result.to_dict()
    assert payload["passwords"] and payload["stats"]["passwords"] >= 1
    assert json.loads(json.dumps(payload, default=str))["loot"] is not None
    assert result.report_json.endswith("report.json")
    assert result.report_markdown.endswith("report.md")
    # every target that produced no key is reported as unbroken, not hidden
    recovered = {hit["bssid"] for hit in result.passwords}
    assert len(result.unbroken()) == len(result.aps) - len(recovered)
    for hit in result.cracked():
        assert set(hit) >= {"bssid", "essid", "password", "kind", "verified"}


def test_campaign_can_be_limited_to_one_target():
    scan = wp.scan(duration=2)
    chosen = scan.aps[0].bssid
    result = wp.attack(target=chosen, mode="quick", demo=True, duration="30s",
                       scan_time="2s", max_targets=1)
    assert result.session.selected_bssids == [chosen]
    assert all(item["bssid"] == chosen for item in result.passwords)
    assert {attempt.bssid for attempt in result.session.attempts} == {chosen}


def test_only_one_campaign_at_a_time():
    running = wp.attack(target=all, mode="quick", demo=True, duration="60s",
                        scan_time="3s", background=True)
    try:
        assert running.running
        with pytest.raises(wp.BusyError):
            wp.attack(target=all, mode="quick", demo=True, scan_time="2s")
    finally:
        running.stop()
    assert not running.running


def test_background_run_can_be_stopped_early():
    running = wp.attack(target=all, mode="force", demo=True, duration="600s",
                        scan_time="2s", background=True)
    assert wp.current_run() is running and running.running
    running.stop()
    assert not running.running
    assert running.to_dict()["modes"] == "force"
    assert running.to_dict()["demo"] is True


def test_event_callbacks_and_subscriptions_see_the_same_bus():
    seen = []
    unsubscribe = wp.subscribe(lambda event: seen.append(event.kind))
    assert callable(unsubscribe)
    callback = []
    wp.attack(target=all, mode="quick", demo=True, duration="20s", scan_time="2s",
              max_targets=1, on_event=lambda event: callback.append(event.kind))
    assert any(kind.startswith("session") for kind in callback)
    assert seen, "the subscription should have received events too"
    unsubscribe()
    before = list(seen)
    wp.attack(target=all, mode="quick", demo=True, duration="15s", scan_time="2s",
              max_targets=1)
    assert seen == before, "unsubscribed callbacks must stay silent"


def test_status_reports_the_context():
    wp.configure(demo=True, provider="none")
    status = wp.status()
    assert status["running"] is False and status["demo"] is True
    assert status["platform"]["platform"] == "linux"
    assert status["provider"] == "none" and status["model"]
    assert wp.advisor_status()["provider"] == "none"
    running = wp.attack(target=all, mode="quick", demo=True, duration="60s",
                        scan_time="3s", background=True)
    try:
        assert wp.status()["running"] is True
    finally:
        running.stop()


# --------------------------------------------------------------------------- #
# files: analysis, cracking, loot, reports
# --------------------------------------------------------------------------- #


def test_crack_a_capture_file(tmp_path):
    path = tmp_path / "handshake.pcap"
    build_capture(str(path), SSID, AP_MAC, STA_MAC, PSK, include_pmkid=True)
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("\n".join(["password", "12345678", "letmein123", PSK]) + "\n")

    analysis = wp.analyze(str(path))
    assert analysis["has_handshake"] and analysis["has_pmkid"]
    assert analysis["eapol"] == 4 and analysis["packets"] == 5

    result = wp.crack(str(path), wordlist=str(wordlist))
    assert result.cracked and result.password == PSK
    assert result.verified, "a cracked password must be proven against the capture"


def test_crack_refuses_a_missing_file(tmp_path):
    with pytest.raises(wp.WifiPilotError):
        wp.crack(str(tmp_path / "nope.pcap"))


def test_loot_and_report_after_a_run(tmp_path):
    result = wp.attack(target=all, mode="quick", demo=True, duration="45s",
                       scan_time="3s", max_targets=1, output_dir=str(tmp_path / "loot"))
    loot = wp.loot()
    assert loot and all(capture.bssid for capture in loot)
    assert any(capture.password for capture in loot)
    written = wp.report(str(tmp_path / "report.json"))
    assert written.endswith("report.json") and os.path.exists(written)
    again = wp.loot(written)
    assert [capture.bssid for capture in again] == [capture.bssid for capture in loot]
    assert result.session.id in result.report_json


def test_reset_clears_everything():
    wp.attack(target=all, mode="quick", demo=True, duration="8s", scan_time="2s",
              max_targets=1)
    assert wp.status()["access_points"] > 0
    wp.reset()
    assert wp.session() is None and wp.engine() is None
    assert "access_points" not in wp.status()
    assert wp.config().demo is False                     # back to stock defaults


def test_report_without_a_run_is_an_error():
    with pytest.raises(wp.WifiPilotError):
        wp.report()


def test_providers_and_advisor_status_without_probing():
    providers = wp.providers(probe=False)
    assert providers and all("name" in entry for entry in providers)
    assert wp.advisor_status()["provider"] in ("none", "ollama", "cortex", "openrouter")


def test_non_linux_raises_platform_error_for_calls_but_not_for_import(monkeypatch):
    monkeypatch.delenv("WIFIPILOT_ALLOW_NON_LINUX", raising=False)
    monkeypatch.setattr(wp.api, "is_linux", lambda: False)
    with pytest.raises(wp.PlatformError):
        wp.attack(target=all, demo=True, duration="1s")
