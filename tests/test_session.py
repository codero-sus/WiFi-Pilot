# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Session bookkeeping: APs, captures, attempts, dedup, reports and exports."""

from __future__ import annotations

from pathlib import Path

from wifipilot.models import Attempt, Capture, Client, Finding, STATUS_FAILED, STATUS_SUCCESS
from tests.conftest import AP_MAC


def test_upsert_creates_and_updates_ap(session, bus):
    events = bus.subscribe(["ap.new", "ap.update"])
    ap, created = session.upsert_ap(AP_MAC, "TestNet", channel=6, signal=-40,
                                    encryption="WPA2", publish=True)
    assert created and ap.essid == "TestNet" and ap.channel == 6
    again, created_again = session.upsert_ap(AP_MAC, "", signal=-45)
    assert not created_again and again is ap and again.signal == -45
    kinds = [event.kind for event in events.drain()]
    assert "ap.new" in kinds


def test_upsert_ignores_empty_values(session):
    ap, _ = session.upsert_ap(AP_MAC, "TestNet", channel=6)
    session.upsert_ap(AP_MAC, "TestNet", channel=0, cipher="")
    assert ap.channel == 6
    assert ap.cipher == "CCMP"


def test_clients_are_deduplicated(session):
    ap, _ = session.upsert_ap(AP_MAC, "TestNet")
    client = Client(mac="02:00:00:00:00:aa", bssid=AP_MAC, signal=-50, packets=10)
    assert ap.add_client(client) is True
    assert ap.add_client(Client(mac="02:00:00:00:00:aa", bssid=AP_MAC, signal=-55,
                                packets=99)) is False
    assert len(ap.clients) == 1
    assert ap.clients["02:00:00:00:00:aa"].packets == 99
    session.add_client(AP_MAC, "02:00:00:00:00:bb", signal=-60)
    assert len(ap.clients) == 2


def test_duplicate_captures_are_not_added_twice(session):
    ap, _ = session.upsert_ap(AP_MAC, "TestNet")
    first = Capture(kind="handshake", bssid=AP_MAC, essid="TestNet", path="/tmp/a.cap", valid=True)
    second = Capture(kind="handshake", bssid=AP_MAC, essid="TestNet", path="/tmp/a.cap", valid=True)
    session.add_capture(first)
    session.add_capture(second)
    assert len(ap.captures) == 1


def test_capture_with_password_marks_target_cracked(session):
    ap, _ = session.upsert_ap(AP_MAC, "TestNet")
    session.add_capture(Capture(kind="handshake", bssid=AP_MAC, essid="TestNet",
                                path="/tmp/a.cap", valid=True, password="secret123"))
    assert ap.cracked and ap.password == "secret123"
    assert session.stats.passwords == 1


def test_attempt_lifecycle(session):
    ap, _ = session.upsert_ap(AP_MAC, "TestNet")
    attempt = session.start_attempt("handshake", AP_MAC, tool="airodump-ng")
    assert attempt.status == "running" and ap.status == "running"
    session.end_attempt(attempt, STATUS_FAILED, "no handshake", "clients did not return")
    assert ap.status == STATUS_FAILED
    assert session.stats.attacks_run == 1 and session.stats.attacks_failed == 1
    assert ap.attempts[0].to_dict()["attack"] == "handshake"


def test_findings_and_loot_view(session):
    ap, _ = session.upsert_ap(AP_MAC, "TestNet")
    session.add_finding(Finding(kind="risk", title="WPS enabled", severity="medium"))
    session.add_capture(Capture(kind="pmkid", bssid=AP_MAC, essid="TestNet",
                                path="/tmp/p.cap", valid=True))
    assert any(finding.title == "WPS enabled" for finding in session.findings)
    assert len(session.loot()) == 1


def test_situation_report_is_compact_and_useful(session):
    ap, _ = session.upsert_ap(AP_MAC, "TestNet", channel=6, signal=-52, encryption="WPA2",
                              wps=True, wps_locked="unlocked")
    session.add_client(AP_MAC, "02:00:00:00:00:aa", signal=-50)
    session.start_attempt("pmkid", AP_MAC)
    situation = session.situation()
    assert situation["targets"][0]["bssid"] == AP_MAC
    assert situation["targets"][0]["wps"] == "yes"
    assert situation["targets"][0]["clients"] == 1
    assert situation["stats"]["aps"] == 1
    assert len(str(situation)) < 4000          # must stay token-frugal


def test_reports_are_written(session, tmp_path):
    ap, _ = session.upsert_ap(AP_MAC, "TestNet", encryption="WPA2", signal=-50)
    session.add_capture(Capture(kind="handshake", bssid=AP_MAC, essid="TestNet",
                                path=str(tmp_path / "a.cap"), valid=True, password="pw12345678"))
    markdown = Path(session.write_markdown_report())
    assert "wifipilot engagement" in markdown.read_text()
    assert "pw12345678" in markdown.read_text()
    export = Path(session.write_report())
    assert export.exists()
    assert "access_points" in export.read_text()


def test_export_contains_everything(session):
    session.upsert_ap(AP_MAC, "TestNet")
    export = session.export()
    for key in ("session", "stats", "access_points", "attempts", "findings", "loot"):
        assert key in export
    assert export["access_points"][0]["bssid"] == AP_MAC


def test_drop_stale_targets(session):
    ap, _ = session.upsert_ap(AP_MAC, "Gone")
    ap.last_seen -= 1000
    session.drop_stale(timeout=60)
    assert session.ap(AP_MAC) is None
