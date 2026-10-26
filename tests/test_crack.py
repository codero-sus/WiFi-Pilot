# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Cracking: the built-in engine, rule expansion and orchestration behaviour."""

from __future__ import annotations

import time


from wifipilot.crack import Cracker, CrackResult, iter_wordlist, rule_expand, smart_candidates
from wifipilot.models import AccessPoint, Capture
from wifipilot.pcap import analyze_file
from tests.conftest import AP_MAC, PSK, SSID, STA_MAC


def _target(session, essid: str = SSID, bssid: str = AP_MAC) -> AccessPoint:
    ap, _ = session.upsert_ap(bssid, essid, publish=False)
    ap.encryption = "WPA2"
    return ap


def test_rule_expansion_covers_the_usual_mutations():
    variants = list(rule_expand("sunshine", limit=60))
    for expected in ("sunshine", "Sunshine", "sunshine1", "sunshine123", "sunshine!", "sunshine2024"):
        assert expected in variants, expected
    assert all(8 <= len(v) <= 63 for v in variants)


def test_rule_expansion_is_bounded_and_deduplicated():
    variants = list(rule_expand("short", limit=10))
    assert len(variants) == len(set(variants))
    assert len(variants) <= 200


def test_smart_candidates_use_the_essid_and_vendor():
    ap = AccessPoint(bssid=AP_MAC, essid="TestNet", vendor="TP-Link")
    candidates = list(smart_candidates(ap))
    assert "TestNet2024" in candidates
    assert any(c.lower().startswith("tplink") for c in candidates)
    assert all(len(c) >= 8 for c in candidates)


def test_builtin_engine_cracks_a_pmkid(pmkid_capture, session):
    ap = _target(session)
    analysis = analyze_file(pmkid_capture)
    capture = Capture(kind="pmkid", bssid=AP_MAC, essid=SSID, path=pmkid_capture, valid=True,
                      hash_path=pmkid_capture,
                      extra={"pmkid": analysis.pmkids[0].pmkid})
    cracker = Cracker(session, session.config, session.bus, demo=False)
    result = cracker.crack_capture(ap, capture, wordlists=[], timeout=30)
    assert result.cracked and result.password == PSK
    assert result.verified and result.tool.startswith("wifipilot")
    assert capture.password == PSK


def test_attempts_count_what_was_verified_not_the_candidate_space(handshake_capture, session):
    """An early hit must not be reported as a full sweep of the candidate space."""
    cracker = Cracker(session, session.config, session.bus, demo=False)
    ap = _target(session)
    analysis = analyze_file(handshake_capture)
    capture = Capture(kind="handshake", bssid=AP_MAC, essid=SSID, path=handshake_capture,
                      valid=True)
    found, tested = cracker._python_pass(ap, capture, analysis,
                                         ["wrong-1", "wrong-2", "wrong-3", PSK, "unreached"],
                                         time.time() + 30, lambda *_: None)
    assert found == PSK
    assert tested == 4                       # the fifth candidate is never derived
    result = cracker.crack_capture(ap, capture, wordlists=[], timeout=30)
    assert result.cracked and 0 < result.attempts < 100


def test_builtin_engine_cracks_a_handshake_via_mic(handshake_capture, session):
    ap = _target(session)
    capture = Capture(kind="handshake", bssid=AP_MAC, essid=SSID, path=handshake_capture,
                      valid=True)
    cracker = Cracker(session, session.config, session.bus, demo=False)
    result = cracker.crack_capture(ap, capture, wordlists=[], timeout=30)
    assert result.cracked and result.password == PSK and result.verified


def test_builtin_engine_reports_failure_for_unknown_psk(handshake_capture, session, tmp_path):
    from wifipilot.synth import build_capture
    path = str(tmp_path / "other.pcap")
    build_capture(path, SSID, AP_MAC, STA_MAC, "Zx9$unbreakable-Passphrase")
    ap = _target(session)
    capture = Capture(kind="handshake", bssid=AP_MAC, essid=SSID, path=path, valid=True)
    cracker = Cracker(session, session.config, session.bus, demo=False)
    result = cracker.crack_capture(ap, capture, wordlists=[], timeout=8)
    assert not result.cracked and result.reason
    assert result.attempts > 0


def test_wordlist_sweep_and_gzip_support(tmp_path, session, bus):
    words = tmp_path / "small.txt"
    words.write_text("# comment\n\nnotthewifi\n" + PSK + "\ntrailing\n", encoding="utf-8")
    assert list(iter_wordlist(str(words))) == ["notthewifi", PSK, "trailing"]

    import gzip
    gz = tmp_path / "small.txt.gz"
    with gzip.open(gz, "wt") as handle:
        handle.write("another\n" + PSK + "\n")
    assert PSK in list(iter_wordlist(str(gz)))


def test_missing_capture_file_is_reported(session):
    ap = _target(session)
    capture = Capture(kind="handshake", bssid=AP_MAC, essid=SSID, path="")
    cracker = Cracker(session, session.config, session.bus, demo=False)
    result = cracker.crack_capture(ap, capture)
    assert not result.cracked and "no file" in result.reason


def test_demo_cracking_is_simulated_but_consistent(session):
    from wifipilot.demo import DemoRadio
    radio = DemoRadio()
    demo_ap = radio.find(next(iter(radio.aps)).bssid)
    ap = _target(session, demo_ap.essid, demo_ap.bssid)
    capture = Capture(kind="handshake", bssid=demo_ap.bssid, essid=demo_ap.essid, path="/tmp/x.cap")
    cracker = Cracker(session, session.config, session.bus, demo=True, radio=radio)
    result = cracker.crack_capture(ap, capture, timeout=5)
    assert isinstance(result, CrackResult)
    assert result.attempts > 0
    if result.cracked:
        assert result.password == demo_ap.psk
