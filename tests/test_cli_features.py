# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""The feature commands: toolbox, vendor, scoping, advice, benchmark.

Every one of these has to work with no radio and no root — they are the parts an
operator runs *after* the engagement, on a laptop, with the loot on disk.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wifipilot.cli import main


def run(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


@pytest.fixture()
def hash_file(tmp_path):
    """hashcat's published example, written as a mode-22000 file."""
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


def test_list_strategies_names_every_preset(capsys):
    code, out, _ = run(capsys, "--json", "crack", "--list-strategies")
    assert code == 0
    assert {item["label"] for item in json.loads(out)} == {
        "quick", "default", "thorough", "insane", "mask-only", "wordlist-only",
        "pixie-then-crack"}


def test_crack_without_a_capture_explains_itself(capsys):
    code, out, _ = run(capsys, "--no-color", "crack")
    assert code == 2
    assert "--list-strategies" in out


def test_hash_stats_json(hash_file, capsys):
    code, out, _ = run(capsys, "--json", "hash", "stats", hash_file)
    payload = json.loads(out)
    assert code == 0
    assert payload[0]["lines"] == 1
    assert payload[0]["verifiable"] == 1
    assert payload[0]["essids"] == ["TP-LINK_HASHCAT_TEST"]


def test_hash_merge_filter_split_normalize_round_trip(hash_file, tmp_path, capsys):
    merged = tmp_path / "merged.hc22000"
    code, out, _ = run(capsys, "hash", "merge", hash_file, hash_file,
                       "--out", str(merged), "--no-color")
    assert code == 0 and "1 line" in out

    filtered = tmp_path / "filtered.hc22000"
    code, out, _ = run(capsys, "hash", "filter", str(merged), "--kind", "eapol",
                       "--out", str(filtered), "--no-color")
    assert code == 0 and "1 kept" in out

    split_dir = tmp_path / "split"
    code, out, _ = run(capsys, "hash", "split", str(filtered),
                       "--out-dir", str(split_dir), "--per-file", "1", "--no-color")
    assert code == 0
    assert len(list(split_dir.glob("*.hc22000"))) == 1

    normalized = tmp_path / "normal.hc22000"
    code, out, _ = run(capsys, "hash", "normalize", str(filtered),
                       "--out", str(normalized), "--no-color")
    assert code == 0
    # the canonical file is still a hash file: the parser reads it back
    code, out, _ = run(capsys, "--json", "hash", "stats", str(normalized))
    assert json.loads(out)[0]["lines"] == 1


def test_hash_rescue_takes_a_capture(tmp_path, capsys, handshake_capture):
    out = tmp_path / "rescued.hc22000"
    code, text, _ = run(capsys, "hash", "rescue", handshake_capture,
                        "--out", str(out), "--no-color")
    assert code == 0
    assert Path(out).exists()


def test_a_split_hash_file_can_be_cracked(hash_file, tmp_path, capsys):
    """The toolbox's output must be something the cracker accepts."""
    split_dir = tmp_path / "split"
    run(capsys, "hash", "split", hash_file, "--out-dir", str(split_dir),
        "--per-file", "1", "--no-color")
    chunk = next(split_dir.glob("*.hc22000"))
    code, out, _ = run(capsys, "crack", str(chunk))
    assert code == 0
    assert "hashcat!" in out, "the split file lost the material"


def test_wordlist_stats_json(tmp_path, capsys):
    words = tmp_path / "words.txt"
    words.write_text("password\n12345678\nsunshine!\n")
    code, out, _ = run(capsys, "--json", "wordlist", "stats", str(words))
    payload = json.loads(out)
    assert code == 0
    assert payload[0]["lines"] == 3
    assert payload[0]["wpa_compatible"] == 3


def test_wordlist_merge_expand_and_from_masks(tmp_path, capsys):
    a = tmp_path / "a.txt"
    a.write_text("alpha1234\nbravo1234\n")
    b = tmp_path / "b.txt"
    b.write_text("bravo1234\ncharlie123\n")
    merged = tmp_path / "merged.txt"
    code, out, _ = run(capsys, "wordlist", "merge", str(a), str(b),
                       "--out", str(merged), "--no-color")
    assert code == 0
    assert merged.read_text().split() == ["alpha1234", "bravo1234", "charlie123"]

    expanded = tmp_path / "expanded.txt"
    code, out, _ = run(capsys, "wordlist", "expand", str(merged), "--out", str(expanded),
                       "-r", "best64", "--no-color")
    assert code == 0
    assert len(expanded.read_text().split()) > 3

    masks = tmp_path / "masks.txt"
    code, out, _ = run(capsys, "wordlist", "from-masks", "--out", str(masks), "?d?d",
                       "--no-color")
    assert code == 0
    assert len(masks.read_text().split()) == 100


def test_wordlist_rules_info_json(capsys):
    code, out, _ = run(capsys, "--json", "wordlist", "rules-info", "best64")
    payload = json.loads(out)
    assert code == 0
    assert payload["rules"] == payload["usable"] > 20


def test_potfile_show_export_remove(tmp_path, capsys):
    pot = tmp_path / "hashcat.potfile"
    pot.write_text("deadbeef:letmein123\ncafebabe:hunter2!\n")
    code, out, _ = run(capsys, "--json", "potfile", "show", str(pot))
    assert json.loads(out)[0]["password"] == "letmein123"

    exported = tmp_path / "cracks.csv"
    code, out, _ = run(capsys, "potfile", "export", str(pot), "--out", str(exported),
                       "--no-color")
    assert code == 0 and exported.exists()
    assert exported.read_text().splitlines()[0] == "essid,bssid,kind,password,hash"

    code, out, _ = run(capsys, "potfile", "remove", str(pot), "deadbeef", "--no-color")
    assert code == 0
    assert "deadbeef" not in pot.read_text()


def test_loot_manifest_and_verify(tmp_path, capsys):
    loot = tmp_path / "loot"
    loot.mkdir()
    (loot / "capture.pcap").write_bytes(b"not really a pcap")
    code, out, _ = run(capsys, "--json", "loot", "manifest", "--dir", str(loot))
    assert json.loads(out)["files"] == 1

    code, out, _ = run(capsys, "--json", "loot", "verify", "--dir", str(loot))
    assert code == 0 and json.loads(out)["ok"] is True

    (loot / "capture.pcap").write_bytes(b"tampered")
    code, out, _ = run(capsys, "--json", "loot", "verify", "--dir", str(loot))
    assert code == 1 and json.loads(out)["ok"] is False


def test_loot_list_shows_files(tmp_path, capsys):
    loot = tmp_path / "loot"
    loot.mkdir()
    (loot / "a.hc22000").write_text("WPA*01*...\n")
    code, out, _ = run(capsys, "loot", "list", "--dir", str(loot), "--no-color")
    assert code == 0 and "a.hc22000" in out


def test_vendor_lookup_from_the_cli(capsys):
    code, out, _ = run(capsys, "--json", "vendor", "--bssid", "d0:9e:12:9d:36:cc")
    payload = json.loads(out)
    assert code == 0
    assert payload["vendor"] == "AVM"
    assert payload["dossier"]["matched"] is True

    code, out, _ = run(capsys, "--json", "vendor", "--oui-stats")
    stats = json.loads(out)
    assert stats["exact"] > 1_000


def test_vendor_import_from_the_cli(tmp_path, capsys):
    dump = tmp_path / "oui.txt"
    dump.write_text("00-11-22   (hex)\t\tSome Vendor Inc\n")
    target = tmp_path / "registry.json"
    target.write_text('{"exact": {}, "prefix": {}}', encoding="utf-8")
    # the CLI writes to the bundled registry, so this test only checks that the
    # library call behind it is wired up and the CLI parses its arguments
    code, out, _ = run(capsys, "--json", "vendor", "--import-oui", str(tmp_path / "nope.txt"))
    assert code == 1


def test_benchmark_json(capsys):
    code, out, _ = run(capsys, "--json", "benchmark", "--seconds", "1")
    payload = json.loads(out)
    assert code == 0
    assert payload["rate"] > 0
    assert "8 digits" in payload["estimates"]


def test_advice_json_without_a_session(capsys):
    code, out, _ = run(capsys, "--json", "advice")
    payload = json.loads(out)
    assert code == 0
    assert isinstance(payload, list)


def test_targets_without_a_radio_explains_itself(tmp_path, capsys):
    """`targets` must not crash on a laptop: it says what to pass instead."""
    empty_sessions = tmp_path / "no-sessions-here"
    code, out, _ = run(capsys, "--no-color", "targets", "--report",
                       "/nonexistent-engagement.json",
                       "--session-dir", str(empty_sessions))
    assert code == 2
    assert "not a wifipilot JSON export" in out


def test_targets_filter_a_saved_session(tmp_path, capsys):
    """The whole point: filter an engagement that was exported earlier."""
    from wifipilot.config import Config
    from wifipilot.events import EventBus
    from wifipilot.session import Session

    config = Config()
    config.output_dir = str(tmp_path / "loot")
    config.session_dir = str(tmp_path / "sessions")
    session = Session(config, EventBus(), demo=True)
    for bssid, essid, kind in (("d0:12:cb:00:00:01", "FRITZ!Box 7590 QY", "home-router"),
                               ("00:1a:2b:00:00:01", "CafeGuest", "guest"),
                               ("d0:9e:12:9d:36:cc", "TP-LINK_1A2B", "home-router")):
        ap, _ = session.upsert_ap(bssid, essid, publish=False)
        ap.enrich()
        if kind:
            ap.target_kind = kind
    session.tag_ap("d0:12:cb:00:00:01", "in-scope")
    export = tmp_path / "report.json"
    # the same JSON the API/CLI export produces
    export.write_text(json.dumps(session.export()), encoding="utf-8")

    code, out, _ = run(capsys, "--json", "targets", "--report", str(export),
                       "--tag", "in-scope")
    rows = json.loads(out)
    assert code == 0
    assert [row["bssid"] for row in rows] == ["d0:12:cb:00:00:01"]

    code, out, _ = run(capsys, "--json", "targets", "--report", str(export),
                       "--kind", "home-router")
    assert len(json.loads(out)) == 2

    code, out, _ = run(capsys, "--json", "targets", "--report", str(export), "--kinds")
    kinds = json.loads(out)
    assert kinds.get("home-router") == 2

    code, out, _ = run(capsys, "--json", "targets", "--report", str(export),
                       "--select", "--tag", "in-scope")
    assert json.loads(out)["count"] == 1


def test_note_writes_and_lists(tmp_path, capsys):
    state = tmp_path / "sessions"
    code, out, _ = run(capsys, "note", "engagement started", "--state-dir", str(state),
                       "--no-color")
    assert code == 0
    code, out, _ = run(capsys, "--json", "note", "--list", "--state-dir", str(state))
    notes = json.loads(out)
    assert [entry["text"] for entry in notes] == ["engagement started"]


def test_tag_lists_when_there_is_nothing_to_tag(capsys):
    code, out, _ = run(capsys, "--json", "tag", "--list")
    assert code == 0
    assert json.loads(out) == {}
