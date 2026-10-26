# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""The module-level feature API: scoping, notes, analytics, toolbox wrappers.

These are the functions a script uses *around* a campaign — before it (scope the
targets, look up the vendor), during it (tag what matters) and after it (report
the passwords, prove the loot).  All of it has to work with no radio.
"""

from __future__ import annotations

import json
import os

import pytest

import wifipilot as wp


@pytest.fixture(autouse=True)
def clean_context(monkeypatch, tmp_path):
    monkeypatch.setenv("WIFIPILOT_ALLOW_NON_LINUX", "1")
    wp.reset()
    wp.configure(demo=True, provider="none", scan_time=1,
                 output_dir=str(tmp_path / "loot"),
                 session_dir=str(tmp_path / "sessions"))
    yield
    wp.stop()
    wp.reset()


@pytest.fixture()
def session_with_aps():
    """A small, realistic target set in the live session."""
    config = wp.config()
    from wifipilot.events import EventBus
    from wifipilot.session import Session

    session = Session(config, EventBus(), demo=True)
    for bssid, essid in (("d0:12:cb:00:00:01", "FRITZ!Box 7590 QY"),
                         ("f8:1a:67:00:00:01", "TP-LINK_GUEST"),
                         ("00:1a:2b:00:00:01", "Cafe-Guest-WiFi")):
        ap, _ = session.upsert_ap(bssid, essid, publish=False)
        ap.enrich()
    from wifipilot.api import _CTX
    _CTX.session = session
    return session


# --------------------------------------------------------------------------- #
# strategies and scope
# --------------------------------------------------------------------------- #

def test_strategies_lists_every_preset():
    presets = wp.strategies()
    assert {item["label"] for item in presets} == {
        "quick", "default", "thorough", "insane", "mask-only", "wordlist-only",
        "pixie-then-crack"}
    assert all(item["note"] and item["order"] for item in presets)


def test_targets_and_select_work_on_the_live_session(session_with_aps):
    assert len(wp.targets()) == 3
    assert len(wp.targets(vendor="AVM")) == 1
    assert len(wp.targets(kind="guest")) >= 1

    selected = wp.select(vendor="AVM")
    assert selected == ["d0:12:cb:00:00:01"]
    assert [row["bssid"] for row in wp.selected()] == selected

    wp.select(["f8:1a:67:00:00:01"])
    assert len(wp.selected()) == 2, "select() adds to the scope by default"
    guests = [row["bssid"] for row in wp.targets(kind="guest")]
    wp.select(clear=True, kind="guest")            # clear, then scope the guests
    assert [row["bssid"] for row in wp.selected()] == sorted(guests)
    assert guests, "the fixture needs at least one guest network"
    wp.select(clear=True)
    assert wp.selected() == []


def test_tag_and_history_round_trip(session_with_aps):
    assert wp.tag("d0:12:cb:00:00:01", "in-scope") == ["in-scope"]
    assert wp.tag("d0:12:cb:00:00:01", "retest") == ["in-scope", "retest"]
    assert wp.tag("d0:12:cb:00:00:01", "retest", remove=True) == ["in-scope"]
    assert wp.targets(tag="in-scope")[0]["bssid"] == "d0:12:cb:00:00:01"

    history = wp.history(bssid="d0:12:cb:00:00:01")
    assert any(entry["kind"] == "tag" for entry in history)


def test_notes_are_written_and_read_back(tmp_path):
    entry = wp.note("engagement started")
    assert entry["text"] == "engagement started"
    assert [item["text"] for item in wp.notes()] == ["engagement started"]
    wp.note("AP in the back office", bssid="d0:12:cb:00:00:01")
    assert len(wp.notes()) == 2


# --------------------------------------------------------------------------- #
# vendor intelligence
# --------------------------------------------------------------------------- #

def test_vendor_lookup_by_mac_and_by_name():
    by_mac = wp.vendor(bssid="d0:9e:12:9d:36:cc")
    assert by_mac["vendor"] == "AVM"
    assert by_mac["dossier"]["matched"] is True
    assert by_mac["dossier"]["confidence"] == "heuristic"

    by_name = wp.vendor("tp-link")
    assert by_name["dossier"]["key"] == "TP-Link"


def test_identify_returns_masks_a_script_can_run():
    info = wp.identify("Telekom-9F3A")
    assert info["scheme"]
    assert info["masks"]
    assert info["masks"][0]["space"] <= 10_000_000


def test_passwords_reports_the_cracked_ones(session_with_aps):
    assert wp.passwords() == []                     # nothing cracked yet
    from wifipilot.models import Capture

    ap = session_with_aps.aps["d0:12:cb:00:00:01"]
    ap.captures.append(Capture(kind="handshake", bssid=ap.bssid, essid=ap.essid,
                               path="/tmp/whatever.pcap", valid=True,
                               password="sunshine2024",
                               tool="wifipilot (built-in)"))
    rows = wp.passwords()
    assert rows[0]["password"] == "sunshine2024"
    assert rows[0]["score"] < 50
    assert rows[0]["bssid"] == "d0:12:cb:00:00:01"
    assert rows[0]["essid"] == "FRITZ!Box 7590 QY"
    assert rows[0]["seconds"]
    assert wp.passwords(include_weak=False) == [], "a weak password must be filterable"


def test_advice_is_available_without_an_engine():
    items = wp.advice()
    assert items, "advice with no targets at least suggests a scan"
    assert items[0]["action"] == "scan"


def test_benchmark_measures_this_machine():
    result = wp.benchmark(seconds=1)
    assert result["rate"] > 0
    assert result["candidates"] > 0
    assert "8 digits" in result["estimates"]


# --------------------------------------------------------------------------- #
# the toolbox wrappers
# --------------------------------------------------------------------------- #

def _hash_file(tmp_path):
    line = (
        "WPA*02*024022795224bffca545276c3762686f*6466b38ec3fc*225edc49b7aa*"
        "54502d4c494e4b5f484153484341545f54455354*"
        "10e3be3b005a629e89de088d6a2fdc489db83ad4764f2d186b9cde15446e972e*"
        "0103007502010a0000000000000000000148ce2ccba9c1fda130ff2fbbfb4fd3"
        "b063d1a93920b0f7df54a5cbf787b16171000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "00001630140100000fac040100000fac040100000fac028000*a2")
    path = tmp_path / "example.hc22000"
    path.write_text(line + "\n")
    return str(path)


def test_hash_stats_and_merge(tmp_path):
    path = _hash_file(tmp_path)
    stats = wp.hash_stats(path)
    assert stats["lines"] == 1 and stats["verifiable"] == 1
    merged = wp.merge_hashes([path, path], str(tmp_path / "merged.hc22000"))
    assert merged["written"] == 1 and merged["duplicates"] == 1


def test_rescue_capture_and_wordlist_helpers(tmp_path):
    from wifipilot.synth import build_capture

    capture = tmp_path / "capture.pcap"
    build_capture(str(capture), "BenchNet", "d0:9e:12:9d:36:cc", "02:00:00:00:00:11",
                  "BenchNet2024", include_pmkid=True)
    rescued = wp.rescue_capture(str(capture))
    assert rescued["written"] >= 1

    words = tmp_path / "words.txt"
    words.write_text("password\n12345678\n")
    stats = wp.wordlist_stats(str(words))
    assert stats["lines"] == 2
    expanded = wp.expand_wordlist(str(words), str(tmp_path / "expanded.txt"), "best64")
    assert expanded["written"] > 2


def test_rules_info_describes_a_preset():
    info = wp.rules_info("best64")
    assert info["rules"] > 20
    assert info["usable"] == info["rules"]
    assert info["examples"]


def test_loot_manifest_and_verify(tmp_path):
    loot = tmp_path / "loot"
    loot.mkdir(parents=True, exist_ok=True)
    (loot / "a.hc22000").write_text("WPA*01*...\n")
    written = wp.loot_manifest()
    assert written["files"] == 1
    assert wp.verify_loot()["ok"] is True
    (loot / "a.hc22000").write_text("tampered\n")
    assert wp.verify_loot()["ok"] is False


def test_every_new_name_is_exported():
    for name in ("strategies", "targets", "select", "selected", "note", "notes", "tag",
                 "history", "vendor", "identify", "passwords", "advice", "benchmark",
                 "hash_stats", "merge_hashes", "rescue_capture", "wordlist_stats",
                 "expand_wordlist", "rules_info", "loot_manifest", "verify_loot"):
        assert callable(getattr(wp, name)), name
        assert name in wp.__all__, name
        assert hasattr(__import__("wifipilot.api", fromlist=["x"]), name), name


def test_targets_round_trips_through_json(tmp_path, session_with_aps):
    """A script must be able to hand the result straight to json.dumps."""
    payload = json.dumps(wp.targets())
    parsed = json.loads(payload)
    assert len(parsed) == 3
    assert os.path.isabs(wp.config().output_dir)
