# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""The hash/wordlist toolbox: stats, merge, dedupe, split, rescue, potfiles, manifests."""

from __future__ import annotations

import json

import pytest

from wifipilot import toolbox

# hashcat's published mode-22000 example (see tests/test_hash22000.py)
ESSID = "TP-LINK_HASHCAT_TEST"
EAPOL_LINE = (
    "WPA*02*024022795224bffca545276c3762686f*6466b38ec3fc*225edc49b7aa*"
    "54502d4c494e4b5f484153484341545f54455354*"
    "10e3be3b005a629e89de088d6a2fdc489db83ad4764f2d186b9cde15446e972e*"
    "0103007502010a0000000000000000000148ce2ccba9c1fda130ff2fbbfb4fd3"
    "b063d1a93920b0f7df54a5cbf787b16171000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "00001630140100000fac040100000fac040100000fac028000*a2")
# the same handshake with the message-pair byte changed: one handshake, seen twice
EAPOL_LINE_ALT_PAIR = EAPOL_LINE[:-2] + "00"
PMKID_LINE = ("WPA*01*e7b71e94595346b4c5e084cbf7ac328e*6466b38ec3fc*225edc49b7aa*"
              "54502d4c494e4b5f484153484341545f54455354***")


def model_lines(path):
    """Parse a hash file into :class:`~wifipilot.hash22000.HashLine` objects."""
    from wifipilot import hash22000
    return hash22000.parse_file(str(path))


@pytest.fixture()
def hash_file(tmp_path):
    path = tmp_path / "test.hc22000"
    path.write_text("\n".join([PMKID_LINE, EAPOL_LINE, PMKID_LINE, "", "# comment"]) + "\n")
    return path


def test_hash_stats_counts_and_flags(hash_file):
    stats = toolbox.hash_stats(str(hash_file))
    assert stats["readable"] is True
    assert stats["lines"] == 3              # blank/comment/# lines are not hashes
    assert stats["pmkid"] == 2 and stats["eapol"] == 1
    assert stats["verifiable"] == 3          # every line can actually be checked
    assert stats["essids"] == [ESSID]
    assert stats["bssids"] == ["64:66:b3:8e:c3:fc"]
    assert stats["pairs"]["M2+M3 (authorized, EAPOL from M2)"] == 1


def test_hash_stats_of_a_missing_file_is_empty_not_an_exception(tmp_path):
    """An operator typo must not end in a traceback: report it, keep going."""
    stats = toolbox.hash_stats(str(tmp_path / "nope.hc22000"))
    assert stats["lines"] == 0 and stats["readable"] is False
    assert "No such file" in stats["problems"][0]


def test_merge_deduplicates_and_writes(tmp_path, hash_file):
    """The same handshake captured twice is one handshake (message-pair byte ignored)."""
    out = tmp_path / "merged.hc22000"
    result = toolbox.merge_hash_files([str(hash_file), str(hash_file)], str(out))
    assert result["written"] == 2 and result["duplicates"] == 4
    assert out.read_text().count("WPA*") == 2


def test_merge_without_dedupe_keeps_every_line(tmp_path, hash_file):
    result = toolbox.merge_hash_files([str(hash_file)], "", dedupe=False)
    assert result["written"] == 3 and result["duplicates"] == 0


def test_a_second_message_pair_of_the_same_handshake_is_a_duplicate(tmp_path):
    """hashcat dedupes on the hash material, not on the MP byte."""
    path = tmp_path / "pairs.hc22000"
    path.write_text(f"{EAPOL_LINE}\n{EAPOL_LINE_ALT_PAIR}\n")
    assert toolbox.merge_hash_files([str(path)], str(tmp_path / "out.hc22000"),
                                    dedupe=True)["duplicates"] == 1


def test_dedupe_and_normalize_keep_the_meaning(hash_file, tmp_path):
    assert toolbox.dedupe_hash_file(str(hash_file))["written"] == 2
    normalized = toolbox.normalize_hash_file(str(hash_file), str(tmp_path / "norm.hc22000"))
    assert normalized["written"] == 2
    text = (tmp_path / "norm.hc22000").read_text()
    assert text.splitlines() == sorted(text.splitlines())
    # and the canonical file still parses to the same material
    assert {line.bssid for line in model_lines(str(tmp_path / "norm.hc22000"))} == {
        "64:66:b3:8e:c3:fc"}
    assert {line.essid for line in model_lines(str(tmp_path / "norm.hc22000"))} == {ESSID}


def test_filter_by_essid_kind_and_bssid(hash_file):
    """Filters are case-insensitive where it matters (ESSIDs are not case-folded
    on the wire, but an operator typing the SSID should still find it)."""
    by_essid = toolbox.filter_hash_file(str(hash_file), "", essid="tp-link_hashcat")
    assert by_essid["written"] == 3
    by_kind = toolbox.filter_hash_file(str(hash_file), "", kind="eapol")
    assert by_kind["written"] == 1 and by_kind["dropped"] == 2
    by_bssid = toolbox.filter_hash_file(str(hash_file), "", bssid="64:66:b3:8e:c3:fc")
    assert by_bssid["written"] == 3
    nothing = toolbox.filter_hash_file(str(hash_file), "", essid="other")
    assert nothing["written"] == 0 and nothing["dropped"] == 3


def test_filter_can_keep_only_the_verifiable_lines(hash_file):
    result = toolbox.filter_hash_file(str(hash_file), "", verifiable_only=True)
    assert result["written"] == 3


def test_split_for_a_cracking_farm(hash_file, tmp_path):
    out = tmp_path / "split"
    result = toolbox.split_hash_file(str(hash_file), str(out), per_file=2)
    files = sorted(out.glob("*.hc22000"))
    assert result["files"] == 2 and result["written"] == 3
    assert all(path.read_text().strip() for path in files)
    assert sum(len(path.read_text().splitlines()) for path in files) == 3


def test_rescue_partial_capture_finds_the_pmkid_in_a_pcap(tmp_path):
    from wifipilot.synth import build_capture

    capture = tmp_path / "partial.pcap"
    build_capture(str(capture), "BenchNet", "d0:9e:12:9d:36:cc", "02:00:00:00:00:11",
                  "BenchNet2024", include_pmkid=True)
    result = toolbox.rescue_partial_capture(str(capture), str(tmp_path / "rescued.hc22000"))
    assert result["written"] == 1
    assert "PMKID" in result["note"] or "pmkid" in result["note"].lower()


def test_wordlist_stats_describes_a_list(tmp_path):
    path = tmp_path / "words.txt"
    path.write_text("\n".join(["password", "12345678", "sunshine!", "sh", "password"]) + "\n")
    stats = toolbox.wordlist_stats(str(path))
    assert stats["lines"] == 5 and stats["unique"] == 4 and stats["duplicates"] == 1
    # what the cracker would actually try: WPA passphrases are 8-63 characters
    assert stats["wpa_compatible"] == 4 and stats["wpa_rejected"] == 1
    assert stats["wpa_compatible"] + stats["wpa_rejected"] == stats["lines"]
    assert stats["min_length"] == 2 and stats["max_length"] == 9
    assert stats["classes"]["digits"] >= 1 and stats["classes"]["lower"] >= 1
    assert stats["classes"]["mixed"] >= 1        # 'sunshine!' mixes letters and a symbol
    assert "estimated_seconds_builtin" in stats


def test_wordlist_stats_estimates_a_real_list(tmp_path):
    """The ETA is this machine's measured rates, not a guess from a table."""
    path = tmp_path / "big.txt"
    path.write_text("\n".join(f"candidate{index:05d}" for index in range(30_000)) + "\n")
    stats = toolbox.wordlist_stats(str(path))
    assert stats["wpa_compatible"] == 30_000
    assert stats["estimated_seconds_builtin"] > 0
    assert 0 < stats["estimated_seconds_hashcat_cpu"] < stats["estimated_seconds_builtin"]


def test_merge_wordlists_dedupes_and_bounds(tmp_path):
    """WPA needs 8-63 characters: shorter words are rejected by default."""
    a = tmp_path / "a.txt"; a.write_text("alpha1234\nbravo1234\ncharlie123\n")
    b = tmp_path / "b.txt"; b.write_text("bravo1234\ndelta1234\necho12345\nshort\n")
    out = tmp_path / "merged.txt"
    result = toolbox.merge_wordlists([str(a), str(b)], str(out), min_length=8)
    assert result["written"] == 5 and result["duplicates"] == 1 and result["rejected"] == 1
    assert sorted(out.read_text().split()) == ["alpha1234", "bravo1234", "charlie123",
                                             "delta1234", "echo12345"]


def test_merge_wordlists_honours_the_limit_and_a_missing_source(tmp_path):
    a = tmp_path / "a.txt"; a.write_text("\n".join(f"wordlist{index:04d}" for index in range(50)))
    result = toolbox.merge_wordlists([str(a), str(tmp_path / "missing.txt")],
                                     str(tmp_path / "out.txt"), limit=10)
    assert result["written"] == 10


def test_expand_wordlist_applies_rules(tmp_path):
    source = tmp_path / "words.txt"; source.write_text("password\n")
    result = toolbox.expand_wordlist(str(source), str(tmp_path / "expanded.txt"), "best64")
    assert result["written"] > 10 and result["base_words"] == 1
    words = (tmp_path / "expanded.txt").read_text().split()
    assert "password" in words and "PASSWORD" in words and "drowssap" in words


def test_expand_wordlist_missing_file_writes_nothing(tmp_path):
    result = toolbox.expand_wordlist(str(tmp_path / "nope.txt"),
                                     str(tmp_path / "out.txt"), "best64")
    assert result["written"] == 0 and result["base_words"] == 0


def test_wordlist_from_masks_expands_a_small_space(tmp_path):
    result = toolbox.wordlist_from_masks(["?d?d"], str(tmp_path / "pins.txt"))
    assert result["written"] == 100 and result["space"] == 100
    assert (tmp_path / "pins.txt").read_text().split()[0] == "00"


def test_wordlist_from_masks_stops_at_the_limit(tmp_path):
    result = toolbox.wordlist_from_masks(["Telekom-?d?d?d?d"], str(tmp_path / "out.txt"),
                                         limit=250)
    assert result["written"] == 250 and result["space"] == 10000


def test_potfile_round_trip(tmp_path):
    """hashcat's potfile is ``<hash>:<password>``, one per line.

    A mode-22000 line is understood well enough to name the network it belongs
    to, which is the whole point of reading the potfile instead of ignoring it.
    """
    pot = tmp_path / "hashcat.potfile"
    pot.write_text(f"{EAPOL_LINE}:hashcat!\ndeadbeef:letmein123\n\n")
    entries = toolbox.potfile_entries(str(pot))
    assert len(entries) == 2
    assert entries[0]["password"] == "hashcat!"
    assert entries[0]["essid"] == ESSID
    assert entries[0]["bssid"] == "64:66:b3:8e:c3:fc"
    assert entries[0]["kind"] == "eapol"
    assert entries[1]["kind"] == ""            # a bare digest: told apart, not guessed
    # lookup takes the parsed lines we are about to crack, not a string
    from wifipilot import hash22000
    line, problem = hash22000.parse_line(EAPOL_LINE)
    assert not problem and line is not None     # '' means parsed cleanly
    assert toolbox.potfile_lookup(str(pot), [line]) == {line.raw: "hashcat!"}
    assert toolbox.potfile_lookup(str(pot), []) == {}


def test_potfile_export_and_remove(tmp_path):
    pot = tmp_path / "hashcat.potfile"
    pot.write_text("aaaa:one\nbbbb:two\n")
    exported = toolbox.potfile_export(str(pot))                     # no path -> text only
    assert exported["count"] == 2 and "one" in exported["text"]
    csv_path = tmp_path / "out.csv"
    toolbox.potfile_export(str(pot), str(csv_path))
    assert csv_path.read_text().splitlines()[0] == "essid,bssid,kind,password,hash"
    assert csv_path.read_text().splitlines()[1] == ",,,one,aaaa"
    json_path = tmp_path / "out.json"
    toolbox.potfile_export(str(pot), str(json_path), fmt="json")
    assert json.loads(json_path.read_text())["entries"][0]["password"] == "one"
    result = toolbox.potfile_remove(str(pot), "aaaa")
    assert result["removed"] == 1 and result["kept"] == 1
    assert "aaaa" not in pot.read_text()


def test_manifest_verifies_and_detects_tampering(tmp_path):
    (tmp_path / "a.txt").write_text("alpha")
    (tmp_path / "b.txt").write_text("bravo")
    written = toolbox.write_manifest(str(tmp_path))
    assert written["files"] == 2 and written["bytes"] == 10

    assert toolbox.verify_manifest(str(tmp_path))["ok"] is True

    (tmp_path / "b.txt").write_text("BRAVO")
    broken = toolbox.verify_manifest(str(tmp_path))
    assert broken["ok"] is False and "b.txt" in broken["changed"]

    (tmp_path / "a.txt").unlink()
    missing = toolbox.verify_manifest(str(tmp_path))
    assert "a.txt" in missing["missing"]

    (tmp_path / "extra.txt").write_text("charlie")
    assert "extra.txt" in toolbox.verify_manifest(str(tmp_path))["extra"]


def test_verify_manifest_without_one_is_an_error_not_a_crash(tmp_path):
    result = toolbox.verify_manifest(str(tmp_path))
    assert result["ok"] is False and result["checked"] == 0
