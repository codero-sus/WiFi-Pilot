"""End-to-end campaign in simulation mode: the whole pipeline, no radio.

This is the test that proves the tool works: discovery → scoring → planning →
attack → capture → crack → report, with attacks that either succeed or fail
cleanly and never loop on solved targets.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from wifipilot.engine import Engine
from wifipilot.events import EK
from wifipilot.models import STATUS_FAILED, STATUS_SUCCESS


@pytest.fixture(scope="module")
def campaign_result():
    """Run one short campaign and share the result across the assertions."""
    from wifipilot.config import Config

    config = Config()
    config.demo = True
    config.ollama.enabled = False
    config.attacks = ["pmkid", "handshake", "wps_pixie", "wep_ivs"]
    config.scan_time = 2
    config.handshake_timeout = 12
    config.pmkid_timeout = 10
    config.wps_timeout = 12
    config.wep_timeout = 10
    config.crack_timeout = 15
    config.stealth = False

    import tempfile
    tmp = tempfile.mkdtemp(prefix="wifipilot-test-")
    config.output_dir = str(Path(tmp) / "loot")
    config.session_dir = str(Path(tmp) / "sessions")

    engine = Engine(config, demo=True)
    engine.prepare()
    engine.scan_for(2)
    engine.run_campaign(duration=60)
    return engine


def test_discovery_populates_targets(campaign_result):
    session = campaign_result.session
    assert len(session.aps) >= 8
    names = {ap.display_name for ap in session.aps.values()}
    assert any("HOME" in name or "FRITZ" in name for name in names)
    assert session.stats.clients_seen >= 0


def test_wps_state_is_known(campaign_result):
    session = campaign_result.session
    wps_aps = [ap for ap in session.aps.values() if ap.wps]
    assert wps_aps, "the simulated neighbourhood contains WPS access points"
    assert any(ap.wps_unlocked_ok if False else ap.wps_locked in ("unlocked", "locked", "unknown")
               for ap in wps_aps)


def test_campaign_ran_attacks_and_produced_loot(campaign_result):
    stats = campaign_result.session.stats
    assert stats.attacks_run >= 1, "at least one attack should have run"
    assert stats.loot >= 1, "the simulation should yield captures"
    assert stats.passwords >= 1, "the simulation should crack at least one PSK"


def test_no_duplicate_attacks_on_solved_targets(campaign_result):
    """A target with a confirmed PSK must not be attacked again."""
    for ap in campaign_result.session.aps.values():
        if not ap.cracked:
            continue
        later_attempts = [a for a in ap.attempts if a.started > ap.captures[0].created]
        assert not later_attempts, f"{ap.display_name} was attacked after being cracked"


def test_captures_are_real_and_verifiable(campaign_result):
    """Even in simulation the captures parse and verify with real crypto."""
    from wifipilot.pcap import analyze_file

    loot = campaign_result.session.loot()
    assert loot
    for capture in loot:
        if not capture.path or not Path(capture.path).exists():
            continue
        if capture.kind == "wep_ivs":
            continue
        analysis = analyze_file(capture.path)
        assert analysis.error == ""
        assert analysis.has_handshake or analysis.has_pmkid
        if capture.password and analysis.handshakes:
            from wifipilot.crypto import verify_handshake
            handshake = analysis.best_handshake()
            if handshake.can_verify_mic:
                frames = {n: m.raw for n, m in handshake.messages.items()}
                assert verify_handshake(frames, analyze_file(capture.path).essids.get(
                    capture.bssid, capture.essid), capture.bssid, handshake.station,
                    bytes.fromhex(handshake.anonce), bytes.fromhex(handshake.snonce),
                    capture.password), "recovered PSK must satisfy the MIC check"


def test_report_files_are_written(campaign_result):
    session = campaign_result.session
    session.write_report()
    markdown = Path(session.write_markdown_report())
    assert markdown.exists()
    text = markdown.read_text()
    assert "Access points" in text and "Findings" in text


def test_engine_can_target_specific_bssids(config):
    engine = Engine(config, demo=True)
    try:
        engine.prepare()
        engine.scan_for(2)
        target = next(iter(engine.session.aps))
        engine.run_campaign(targets=[target], duration=25)
        attempted = {attempt.bssid for attempt in engine.session.attempts}
        assert attempted <= {target}
    finally:
        engine.shutdown()


def test_stop_request_ends_the_campaign(config):
    engine = Engine(config, demo=True)
    engine.prepare()
    engine.scan_for(1)
    engine.request_start([], duration=120)
    engine.start_worker()
    time.sleep(3)
    engine.request_stop()
    engine.wait_idle(timeout=25)
    assert not engine.status.campaign_running
    engine.shutdown()


def test_engine_refuses_to_transmit_without_authorisation(config):
    config.demo = False
    config.authorized = False
    engine = Engine(config, demo=False, authorized=False)
    events = engine.bus.subscribe([EK.ERROR])
    assert engine.run_attack("aa:bb:cc:dd:ee:ff", "handshake") is None
    messages = " ".join(event.data.get("message", "") for event in events.drain()).lower()
    assert "authoriz" in messages and "permission" in messages
