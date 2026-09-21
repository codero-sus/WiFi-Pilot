"""Tests for the scriptable API (``import wifipilot as wp``).

The API is the module surface other people's scripts depend on, so these tests
pin the documented behaviour: target resolution, mode presets, the authorisation
and platform gates, results, events, background runs and error taxonomy.
"""

from __future__ import annotations

import json
import os
import time

import pytest

import wifipilot as wp
from wifipilot.models import AccessPoint
from wifipilot.util import PLATFORM_OVERRIDE_ENV
from tests.conftest import AP_MAC, PSK, SSID


@pytest.fixture(autouse=True)
def clean_state(tmp_path, monkeypatch):
    """Every test starts from a fresh configuration in its own directories."""
    monkeypatch.setenv("WIFIPILOT_ALLOW_NON_LINUX", "1")   # not needed on Linux, harmless
    wp.reset()
    wp.configure(demo=True, provider="none",        # keep the tests off the network
                 output_dir=str(tmp_path / "loot"), session_dir=str(tmp_path / "sessions"),
                 scan_time=2, max_targets=2,        # end campaigns as soon as we have loot
                 handshake_timeout=8, pmkid_timeout=6, wps_timeout=8, wep_timeout=6,
                 crack_timeout=15)
    yield
    wp.reset()


# --------------------------------------------------------------------------- #
# module surface
# --------------------------------------------------------------------------- #


def test_public_names_are_importable_from_the_package_root():
    for name in wp.__all__:
        assert hasattr(wp, name), name
    # the documented spellings
    for name in ("attack", "scan", "crack", "analyze", "configure", "authorize", "subscribe",
                 "stop", "reset", "status", "loot", "report", "set_provider", "providers"):
        assert callable(getattr(wp, name)), name
    assert wp.ALL == "all"
    assert set(wp.MODES) >= {"force", "default", "stealth", "passive", "quick"}


def test_import_does_not_require_a_radio_or_the_web_extras():
    """`import wifipilot` must be safe on a machine with nothing installed."""
    import subprocess
    import sys
    code = ("import sys; sys.modules['fastapi'] = None; import wifipilot as wp; "
            "print(wp.__version__)")
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                          cwd=str(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip()


# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #


def test_configure_sets_fields_and_rejects_typos():
    cfg = wp.configure(stealth=True, attacks=["pmkid"])
    assert cfg.stealth is True and cfg.attacks == ["pmkid"]
    assert wp.config() is cfg
    with pytest.raises(TypeError) as excinfo:
        wp.configure(scan_tyme=3)          # typo
    assert "scan_tyme" in str(excinfo.value)


def test_configure_accepts_a_single_wordlist_and_comma_separated_attacks():
    cfg = wp.configure(wordlist="/tmp/words.txt", attacks="pmkid,handshake")
    assert cfg.wordlists == ["/tmp/words.txt"]
    assert cfg.attacks == ["pmkid", "handshake"]


def test_configure_provider_and_model_routing():
    cfg = wp.configure(provider="openrouter", model="openai/gpt-4o-mini",
                       ai_budget=1.5, redact_identifiers=True)
    assert cfg.ai_provider == "openrouter"
    assert cfg.openrouter.enabled is True            # asking for it enables it
    assert cfg.openrouter.model == "openai/gpt-4o-mini"
    assert cfg.openrouter.max_cost_usd == 1.5
    assert cfg.openrouter.redact_identifiers is True
    cfg = wp.configure(provider="ollama", model="qwen2.5:7b")
    assert cfg.ollama.model == "qwen2.5:7b" and cfg.ai_provider == "ollama"


def test_authorize_records_who_approved_the_engagement():
    cfg = wp.authorize("change ticket CHG-4711")
    assert cfg.authorized is True
    assert "CHG-4711" in cfg.authorization_note
    assert wp.status()["authorized"] is True


def test_provider_helpers_report_status():
    rows = wp.providers()
    assert {row["name"] for row in rows} == {"ollama", "openrouter"}
    status = wp.advisor_status()
    assert status["provider"] in ("ollama", "openrouter", "none")
    assert "cloud" in status and "policy" in status
    with pytest.raises(ValueError):
        wp.set_provider("gpt-9000")


# --------------------------------------------------------------------------- #
# target resolution
# --------------------------------------------------------------------------- #


def test_wildcards_including_the_builtin_all():
    assert wp.api._is_wildcard(all) is True            # wp.attack(target=all) in real code
    assert wp.api._is_wildcard(wp.ALL) is True
    assert wp.api._is_wildcard("*") is True
    assert wp.api._is_wildcard(None) is True
    assert wp.api._is_wildcard("CafeWiFi") is False


class _FakeSession:
    """Minimal stand-in so target selection can be tested without a radio."""

    def __init__(self, aps):
        self._aps = aps

    def sorted_aps(self):
        return self._aps


def _aps():
    return [AccessPoint(bssid=AP_MAC, essid=SSID, encryption="WPA2"),
            AccessPoint(bssid="11:22:33:44:55:66", essid="Cafe Guest", encryption="WPA2"),
            AccessPoint(bssid="de:ad:be:ef:00:01", essid="cafe-backoffice",
                        encryption="WPA3", sae=True)]


def test_target_selection_by_bssid_ssid_substring_and_list():
    session = _FakeSession(_aps())
    assert wp.api._select(session, all) == [AP_MAC, "11:22:33:44:55:66", "de:ad:be:ef:00:01"]
    assert wp.api._select(session, SSID.upper()) == [AP_MAC]          # case insensitive
    assert wp.api._select(session, "cafe") == ["11:22:33:44:55:66",   # substring, both
                                               "de:ad:be:ef:00:01"]
    assert wp.api._select(session, ["de:ad:be:ef:00:01", "TestNet"]) == [
        AP_MAC, "de:ad:be:ef:00:01"]
    assert wp.api._select(session, _aps()[1]) == ["11:22:33:44:55:66"]


def test_unknown_target_lists_what_was_found():
    with pytest.raises(wp.TargetError) as excinfo:
        wp.api._select(_FakeSession(_aps()), "no-such-network")
    message = str(excinfo.value)
    assert "no-such-network" in message and SSID in message


def test_empty_scan_has_its_own_message():
    with pytest.raises(wp.TargetError) as excinfo:
        wp.api._select(_FakeSession([]), all)
    assert "no access points found" in str(excinfo.value)


# --------------------------------------------------------------------------- #
# modes
# --------------------------------------------------------------------------- #


def test_mode_presets():
    wp.configure(attacks=["pmkid"], stealth=False)
    wp.api._apply_mode("force", wp.config())
    assert "wps_pin" in wp.config().attacks and wp.config().stealth is False

    wp.api._apply_mode("stealth", wp.config())
    assert wp.config().stealth is True and "wps_pin" not in wp.config().attacks

    wp.api._apply_mode("quick", wp.config())
    assert wp.config().attacks == ["pmkid", "handshake", "crack"]

    wp.api._apply_mode("passive", wp.config())
    assert wp.config().stealth is True and "crack" in wp.config().attacks

    # explicit keyword arguments win over the preset
    wp.api._apply_mode("force", wp.config(), wps_pin=False)
    assert "wps_pin" not in wp.config().attacks


def test_unknown_mode_is_rejected_with_the_options():
    with pytest.raises(ValueError) as excinfo:
        wp.attack(mode="nuke", demo=True)
    assert "force" in str(excinfo.value) and "stealth" in str(excinfo.value)


# --------------------------------------------------------------------------- #
# safety gates
# --------------------------------------------------------------------------- #


def test_live_run_without_authorisation_is_refused_before_anything_happens(monkeypatch):
    monkeypatch.setattr(wp.api, "_require_linux", lambda: None)
    wp.configure(demo=False, authorized=False)
    with pytest.raises(wp.AuthorizationError) as excinfo:
        wp.attack(target=all, mode="force")
    assert "authorize" in str(excinfo.value).lower()
    # nothing was started
    assert wp.api._CTX.engine is None


def test_demo_mode_needs_no_authorisation():
    result = wp.attack(target=all, mode="quick", duration=30, scan_time=2, demo=True)
    assert result.demo is True
    assert result.stats.aps_seen > 0
    assert result.error in ("", None) or isinstance(result.error, str)


def test_non_linux_raises_platform_error_for_calls_but_not_for_import(monkeypatch):
    monkeypatch.delenv(PLATFORM_OVERRIDE_ENV, raising=False)
    monkeypatch.setattr(wp.api, "is_linux", lambda: False)
    with pytest.raises(wp.PlatformError) as excinfo:
        wp.scan(duration=1, demo=True)
    assert "Linux" in str(excinfo.value)


def test_scan_is_safe_even_without_authorisation():
    """Reconnaissance does not transmit: `scan` works in demo mode regardless."""
    result = wp.scan(duration=2, demo=True)
    assert isinstance(result, wp.ScanResult)
    assert len(result) > 0


# --------------------------------------------------------------------------- #
# results
# --------------------------------------------------------------------------- #


def test_scan_result_views(tmp_path):
    result = wp.scan(duration=3, demo=True)
    assert result.aps and result.aps == sorted(result.aps, key=lambda ap: -ap.score)
    first = result.aps[0]
    assert result.get(first.bssid) is first
    assert first in result.strongest(1)
    assert result.by_ssid(first.essid.lower())
    payload = result.to_dict()
    assert payload["access_points"] and payload["demo"] is True
    assert json.loads(json.dumps(payload, default=str))            # JSON-ready
    assert result.report_json.endswith("report.json")


def test_campaign_result_reports_loot_and_gaps():
    result = wp.attack(target=all, mode="force", duration=60, scan_time=3, demo=True)
    assert result.stats.aps_seen >= 5
    assert result.captures, "the simulated neighbourhood should yield captures"
    for hit in result.passwords:
        assert set(hit) >= {"bssid", "essid", "password", "kind", "verified"}
        assert hit["password"]
        assert result.get(hit["bssid"]) is not None
    assert all(hit in result.passwords for hit in result.cracked())
    assert all(hit["verified"] for hit in result.cracked())
    assert len(result.unbroken()) == len(result.aps) - len(
        {hit["bssid"] for hit in result.passwords})
    assert "passwords recovered" in result.summary()
    assert json.loads(result.json())["loot"] is not None


def test_report_and_loot_helpers(tmp_path):
    result = wp.attack(target=all, mode="quick", duration=60, scan_time=2, demo=True)
    path = wp.report()
    assert os.path.exists(path)
    with open(path) as handle:
        assert json.load(handle)["session"]["id"] == result.session.id
    markdown = wp.report(markdown=True)
    assert markdown.endswith(".md") and os.path.exists(markdown)
    assert wp.loot() == result.loot
    assert wp.session() is result.session
    assert wp.engine() is result.engine


def test_no_run_to_report_on():
    with pytest.raises(wp.WifiPilotError):
        wp.report()


# --------------------------------------------------------------------------- #
# cracking and analysis through the API
# --------------------------------------------------------------------------- #


def test_crack_a_handshake_and_read_the_report(handshake_capture, tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("wrong1\nwrong2\n" + PSK + "\n")
    result = wp.crack(handshake_capture, wordlist=str(wordlist), essid=SSID, bssid=AP_MAC)
    assert result.cracked is True
    assert result.password == PSK
    assert result.verified is True

    info = wp.analyze(handshake_capture)
    assert info["has_handshake"] is True
    assert AP_MAC in info["bssids"]
    assert json.loads(json.dumps(info))            # serialisable


def test_crack_reports_a_missing_file(tmp_path):
    with pytest.raises(wp.WifiPilotError) as excinfo:
        wp.crack(str(tmp_path / "nope.pcap"))
    assert "not found" in str(excinfo.value)


# --------------------------------------------------------------------------- #
# events, background runs, cancellation
# --------------------------------------------------------------------------- #


def test_subscribe_receives_events_and_can_unsubscribe():
    seen = []
    unsubscribe = wp.subscribe(lambda event: seen.append(event), kinds=[wp.EK.AP_NEW])
    try:
        wp.attack(target=all, mode="quick", duration=15, scan_time=2, demo=True)
    finally:
        unsubscribe()
    assert seen, "the AP_NEW events should have been delivered"
    assert all(event.kind == wp.EK.AP_NEW for event in seen)

    # unsubscribed: a new run delivers nothing more
    count = len(seen)
    wp.attack(target=all, mode="quick", duration=8, scan_time=2, demo=True)
    assert len(seen) == count


def test_on_event_argument_is_scoped_to_the_call():
    seen = []
    wp.attack(target=all, mode="quick", duration=10, scan_time=2, demo=True,
              on_event=seen.append)
    assert seen and {event.kind for event in seen} >= {wp.EK.AP_NEW}


def test_background_run_can_be_stopped():
    result = wp.attack(target=all, mode="quick", duration=600, scan_time=2, demo=True,
                       background=True)
    assert isinstance(result, wp.CampaignResult)
    deadline = time.time() + 20
    while not wp.status()["access_points"] and time.time() < deadline:
        time.sleep(0.2)
    assert wp.is_running() is True
    assert wp.stop() is True
    result.wait(timeout=30)
    assert result.running is False
    assert wp.is_running() is False


def test_only_one_campaign_at_a_time():
    running = wp.attack(target=all, mode="quick", duration=600, scan_time=2, demo=True,
                        background=True)
    try:
        with pytest.raises(wp.BusyError):
            wp.attack(target=all, mode="quick", duration=5, demo=True)
    finally:
        running.stop()
    # after stopping, the lock is free again
    wp.attack(target=all, mode="quick", duration=8, scan_time=2, demo=True)


# --------------------------------------------------------------------------- #
# status
# --------------------------------------------------------------------------- #


def test_status_shape_before_and_after_a_run():
    before = wp.status()
    assert set(before) >= {"platform", "demo", "authorized", "provider", "running", "mode"}
    assert before["running"] is False and "session" not in before

    wp.attack(target=all, mode="quick", duration=15, scan_time=2, demo=True)
    after = wp.status()
    assert after["running"] is False
    assert after["access_points"] > 0 and after["mode"] == "quick"
    assert after["report"].endswith(".json")
    assert json.loads(json.dumps(after, default=str))


def test_reset_clears_everything():
    wp.attack(target=all, mode="quick", duration=8, scan_time=2, demo=True)
    assert wp.status()["access_points"] > 0
    wp.reset()
    assert wp.session() is None and wp.engine() is None
    assert "access_points" not in wp.status()
    assert wp.config().demo is False          # back to stock defaults
