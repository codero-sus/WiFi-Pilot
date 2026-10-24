# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Precomputed PMKs: mode 22001, verification, and the ESSID-keyed cache.

The golden vector is hashcat's own published example
(``TP-LINK_HASHCAT_TEST`` / ``hashcat!``), so a wrong PMK derivation cannot
silently agree with itself. On top of that: a cached PSK must be re-verified
against the capture before it is reported, and a cache hit on one AP has to serve
a second capture of the *same ESSID* on a different BSSID — that is the whole
point of keying it by ESSID.
"""

from __future__ import annotations

import json

import pytest

from wifipilot import hash22000, pmk
from wifipilot.config import Config
from wifipilot.crack import Cracker
from wifipilot.events import EventBus
from wifipilot.models import AccessPoint, Capture
from wifipilot.session import Session
from wifipilot.synth import build_capture

#: hashcat's published PMK for the example network (mode 22000 test vector
#: ``example_hashes``): TP-LINK_HASHCAT_TEST / hashcat!.  The capture itself is
#: generated here with the project's own crypto, so the derivation is checked
#: against a value published outside this repository.
GOLDEN_ESSID = "TP-LINK_HASHCAT_TEST"
GOLDEN_PSK = "hashcat!"
GOLDEN_BSSID = "64:66:b3:8e:c3:fc"
GOLDEN_STATION = "22:5e:dc:49:b7:aa"
GOLDEN_PMK = "0857172bd4d3ebb34cf00f3619726008d27558926d963a547332fab033023b82"


@pytest.fixture(scope="module")
def golden(tmp_path_factory):
    """The golden network as a mode-22000 line, from a generated capture."""
    directory = tmp_path_factory.mktemp("golden")
    capture = directory / "golden.pcap"
    build_capture(str(capture), GOLDEN_ESSID, GOLDEN_BSSID, GOLDEN_STATION,
                  GOLDEN_PSK)
    target, count = hash22000.write_capture(
        str(capture), str(directory / "golden.hc22000"), include_pmkid=False)
    assert count == 1, f"expected one EAPOL line, got {count}"
    line, problem = hash22000.parse_line(
        open(target, encoding="utf-8").read().splitlines()[0])
    assert line is not None, problem
    return line


def _session(tmp_path, **knobs) -> Session:
    config = Config()
    config.demo = True
    config.output_dir = str(tmp_path / "loot")
    config.session_dir = str(tmp_path / "sessions")
    config.state_dir = str(tmp_path / "state")
    for key, value in knobs.items():
        setattr(config, key, value)
    return Session(config, EventBus(), demo=True)


# --------------------------------------------------------------------------- #
# derivation and verification
# --------------------------------------------------------------------------- #

def test_pmk_derivation_matches_the_published_value(golden):
    line = golden
    assert pmk.pmk_for(GOLDEN_PSK, line.essid).hex() == GOLDEN_PMK
    assert pmk.verify_pmk(GOLDEN_PMK, line)
    assert pmk.verify_psk(GOLDEN_PSK, line)
    assert not pmk.verify_psk("hashcat", line)
    assert not pmk.verify_psk("", line)


def test_a_tampered_pmk_is_rejected(golden):
    line = golden
    assert not pmk.verify_pmk("00" * 32, line)
    assert not pmk.verify_pmk(GOLDEN_PMK[:-2] + "ff", line)
    assert not pmk.verify_pmk("not hex", line)


def test_verification_uses_the_line_not_the_caller(golden):
    """A PSK is only "verified" for the ESSID it was derived with."""
    line = golden
    assert not pmk.verify_psk(GOLDEN_PSK, line) is False
    other = pmk.pmk_for(GOLDEN_PSK, "SomeOtherNetwork")
    assert other.hex() != GOLDEN_PMK


# --------------------------------------------------------------------------- #
# mode 22001
# --------------------------------------------------------------------------- #

def test_line_to_22001_keeps_the_fields_and_swaps_the_hash_for_the_pmk(golden):
    line = golden
    rendered = pmk.line_to_22001(line, GOLDEN_PMK)
    fields = rendered.split("*")
    assert fields[0] == "WPA" and fields[1] == "02"
    assert fields[2] == GOLDEN_PMK
    assert fields[3] == "6466b38ec3fc" and fields[4] == "225edc49b7aa"
    assert bytes.fromhex(fields[5]).decode() == GOLDEN_ESSID
    assert rendered.count("*") == line.raw.count("*")


def test_convert_from_a_psk_writes_a_readable_22001_file(tmp_path, golden):
    source = tmp_path / "example.hc22000"
    source.write_text(golden.raw + "\n")
    written = pmk.convert_to_22001(str(source), out=str(tmp_path / "out.hc22001"),
                                   psk=GOLDEN_PSK)
    assert written["lines"] == 1 and written["mode"] == 22001
    rows = pmk.read_pmk_file(written["path"])
    assert len(rows) == 1
    assert rows[0]["pmk"] == GOLDEN_PMK
    assert rows[0]["bssid"] == "64:66:b3:8e:c3:fc"      # bare hex -> dotted
    assert rows[0]["station"] == "22:5e:dc:49:b7:aa"
    assert rows[0]["essid"] == GOLDEN_ESSID


def test_convert_without_a_pmk_is_lossless_for_lines_that_have_one(tmp_path, golden):
    source = tmp_path / "example.hc22000"
    source.write_text(golden.raw + "\n")
    first = pmk.convert_to_22001(str(source), out=str(tmp_path / "one.hc22001"),
                                 psk=GOLDEN_PSK)
    again = pmk.convert_to_22001(first["path"], out=str(tmp_path / "two.hc22001"))
    assert again["lines"] == 1
    assert (tmp_path / "one.hc22001").read_text() == (tmp_path / "two.hc22001").read_text()


def test_convert_refuses_when_there_is_nothing_to_convert(tmp_path):
    empty = tmp_path / "empty.hc22000"
    empty.write_text("")
    result = pmk.convert_to_22001(str(empty), psk=GOLDEN_PSK)
    assert result["lines"] == 0
    assert "handshake" in result["note"] or "ESSID" in result["note"]


def test_a_22001_file_is_recognised_as_such(tmp_path, golden):
    """The reader cannot parse a PMK in the hash slot, so 22001 needs its own path."""
    target = tmp_path / "one.hc22001"
    target.write_text(pmk.line_to_22001(golden, GOLDEN_PMK) + "\n")
    assert pmk.raw_22001_lines(str(target)) == [pmk.line_to_22001(golden, GOLDEN_PMK)]
    # and the mode-22000 reader deliberately refuses it (a PMK is not a MIC)
    assert not hash22000.is_hash_file(str(target))


# --------------------------------------------------------------------------- #
# verifying against a capture
# --------------------------------------------------------------------------- #

def test_verify_against_a_real_capture(tmp_path):
    capture = tmp_path / "net.pcap"
    build_capture(str(capture), "BenchNet", "64:66:b3:8e:c3:fc", "22:5e:dc:49:b7:aa",
                  "correct horse battery")
    good = pmk.verify_psk_against("correct horse battery", str(capture))
    assert good["ok"] and good["lines"] >= 1
    assert good["essids"] == ["BenchNet"]
    bad = pmk.verify_psk_against("wrong passphrase", str(capture))
    assert not bad["ok"] and bad["matched"] == {}


def test_verify_respects_an_explicit_essid(tmp_path):
    capture = tmp_path / "net.pcap"
    build_capture(str(capture), "BenchNet", "64:66:b3:8e:c3:fc", "22:5e:dc:49:b7:aa",
                  "pw12345678")
    assert pmk.verify_psk_against("pw12345678", str(capture), "BenchNet")["ok"]
    assert not pmk.verify_psk_against("pw12345678", str(capture), "OtherNet")["ok"]


# --------------------------------------------------------------------------- #
# the cache
# --------------------------------------------------------------------------- #

def test_cache_is_keyed_by_essid_and_reverifies_on_lookup(tmp_path, golden):
    cache = pmk.PMKCache(path=str(tmp_path / "pmk-cache.json")).load()
    cache.remember(GOLDEN_ESSID, GOLDEN_PSK, source="test")
    assert GOLDEN_ESSID in cache and len(cache) == 1
    line = golden
    hit = cache.lookup(GOLDEN_ESSID, line)
    assert hit is not None and hit.psk == GOLDEN_PSK and hit.pmk == GOLDEN_PMK
    # a *different* network never matches, even with the same passphrase
    assert cache.lookup("SomeOtherNetwork", line) is None


def test_a_tampered_cache_entry_is_not_reported_as_a_hit(tmp_path, golden):
    cache = pmk.PMKCache(path=str(tmp_path / "pmk-cache.json")).load()
    cache.remember(GOLDEN_ESSID, GOLDEN_PSK, source="test")
    cache.lookup(GOLDEN_ESSID)                       # loads and remembers the PMK
    cache._entries[GOLDEN_ESSID].pmk = "00" * 32     # noqa: SLF001 - deliberate tamper
    assert cache.lookup(GOLDEN_ESSID, golden) is None


def test_cache_survives_a_reload(tmp_path):
    path = str(tmp_path / "pmk-cache.json")
    pmk.PMKCache(path=path).load().remember("BenchNet", "hunter2hunter2", source="test")
    payload = json.loads(open(path).read())
    assert payload["entries"][0]["essid"] == "BenchNet"
    reloaded = pmk.PMKCache(path=path).load()
    assert reloaded.lookup("BenchNet").psk == "hunter2hunter2"


# --------------------------------------------------------------------------- #
# the cracker consults it
# --------------------------------------------------------------------------- #

def _capture(tmp_path, name: str, bssid: str, station: str, password: str,
             essid: str = "BenchNet") -> str:
    path = tmp_path / name
    build_capture(str(path), essid, bssid, station, password)
    return str(path)


def test_second_capture_of_the_same_essid_costs_no_candidates(tmp_path):
    config = Config()
    config.demo = False
    config.session_dir = str(tmp_path / "sessions")
    config.output_dir = str(tmp_path / "loot")
    config.state_dir = str(tmp_path / "state")
    config.wordlists = [str(tmp_path / "words.txt")]
    (tmp_path / "words.txt").write_text("nope\nbenchpass99\n")
    config.use_masks = False
    session = Session(config, EventBus(), demo=False)
    cracker = Cracker(session, config, demo=False)

    first_ap = AccessPoint("64:66:b3:8e:c3:fc", "BenchNet", encryption="WPA2",
                           auth="PSK", channel=6, signal=-40)
    session.aps[first_ap.bssid] = first_ap
    session.add_capture(Capture(kind="handshake", bssid=first_ap.bssid,
                                essid="BenchNet",
                                path=_capture(tmp_path, "one.pcap", first_ap.bssid,
                                              "22:5e:dc:49:b7:aa", "benchpass99"),
                                valid=True))
    first = cracker.crack_capture(first_ap, first_ap.captures[-1], timeout=30,
                                  strategy="wordlist-only")
    assert first.cracked and first.password == "benchpass99"
    assert (tmp_path / "state" / pmk.PMK_CACHE_NAME).exists()

    second_ap = AccessPoint("8c:3f:fe:50:73:a6", "BenchNet", encryption="WPA2",
                            auth="PSK", channel=11, signal=-55)
    session.aps[second_ap.bssid] = second_ap
    session.add_capture(Capture(kind="handshake", bssid=second_ap.bssid,
                                essid="BenchNet",
                                path=_capture(tmp_path, "two.pcap", second_ap.bssid,
                                              "02:11:22:33:44:55", "benchpass99"),
                                valid=True))
    second = cracker.crack_capture(second_ap, second_ap.captures[-1], timeout=30)
    assert second.cracked and second.password == "benchpass99"
    assert second.tool == "pmk-cache" and second.attempts == 0
    assert session.stats.pmk_hits == 1
    # a cache hit is a result, not a shortcut: the capture and the AP are updated
    assert second_ap.captures[-1].password == "benchpass99"
    assert second_ap.password == "benchpass99"
    assert session.stats.passwords == 2
    assert any(entry.get("kind") == "cracked" for entry in second_ap.history)


def test_a_different_network_still_gets_cracked_normally(tmp_path):
    config = Config()
    config.demo = False
    config.session_dir = str(tmp_path / "sessions")
    config.output_dir = str(tmp_path / "loot")
    config.state_dir = str(tmp_path / "state")
    config.wordlists = [str(tmp_path / "words.txt")]
    (tmp_path / "words.txt").write_text("otherpw123\n")
    config.use_masks = False
    session = Session(config, EventBus(), demo=False)
    cracker = Cracker(session, config, demo=False)
    ap = AccessPoint("aa:bb:cc:dd:ee:ff", "OtherNet", encryption="WPA2", auth="PSK",
                     channel=1, signal=-60)
    session.aps[ap.bssid] = ap
    session.add_capture(Capture(kind="handshake", bssid=ap.bssid, essid="OtherNet",
                                path=_capture(tmp_path, "three.pcap", ap.bssid,
                                              "02:aa:bb:cc:dd:ee", "otherpw123",
                                              essid="OtherNet"),
                                valid=True))
    result = cracker.crack_capture(ap, ap.captures[-1], timeout=25,
                                   strategy="wordlist-only")
    assert result.cracked and result.password == "otherpw123"
    assert result.tool != "pmk-cache"
    assert session.stats.pmk_hits == 0


def test_the_cache_learns_what_a_crack_found(tmp_path):
    config = Config()
    config.demo = False
    config.session_dir = str(tmp_path / "sessions")
    config.output_dir = str(tmp_path / "loot")
    config.state_dir = str(tmp_path / "state")
    config.wordlists = [str(tmp_path / "words.txt")]
    (tmp_path / "words.txt").write_text("learnme123\n")
    config.use_masks = False
    session = Session(config, EventBus(), demo=False)
    cracker = Cracker(session, config, demo=False)
    ap = AccessPoint("aa:bb:cc:dd:ee:01", "LearnNet", encryption="WPA2", auth="PSK",
                     channel=1, signal=-50)
    session.aps[ap.bssid] = ap
    session.add_capture(Capture(kind="handshake", bssid=ap.bssid, essid="LearnNet",
                                path=_capture(tmp_path, "learn.pcap", ap.bssid,
                                              "02:aa:bb:cc:dd:01", "learnme123",
                                              essid="LearnNet"),
                                valid=True))
    cracker.crack_capture(ap, ap.captures[-1], timeout=25, strategy="wordlist-only")
    cache = cracker.pmk_cache()
    assert cache is not None and cache.lookup("LearnNet").psk == "learnme123"


@pytest.mark.parametrize("disabled", [True])
def test_the_cache_is_optional(tmp_path, disabled):
    config = Config()
    config.pmk_cache = not disabled
    session = _session(tmp_path, pmk_cache=False)
    cracker = Cracker(session, session.config, demo=True)
    assert cracker.pmk_cache() is None
