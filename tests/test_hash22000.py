# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""hashcat mode 22000: reading, writing, and cracking hash files.

The published vector is hashcat's own example for mode 22000 (the TP-LINK one
from the wiki / hcxpmktool write-up): ESSID ``TP-LINK_HASHCAT_TEST``, PSK
``hashcat!``, PMK ``0857172b…3b82``, PMKID ``e7b71e94…328e``.  Its EAPOL frame
is rebuilt here field by field (its length field, 0x0075, has to match), and the
MIC then has to come out as the published ``0240227952…686f`` — which is also
what proves the reconstruction is byte-exact.
"""

from __future__ import annotations

import json
import os

import pytest

from wifipilot import hash22000
from wifipilot.cli import main
from wifipilot.crack import Cracker
from wifipilot.crypto import (KDV_CMAC, KDV_MD5, KDV_SHA1, compute_pmkid, mic_algorithms,
                              mic_from_ptk, pmk)
from wifipilot.models import AccessPoint, Capture
from wifipilot.pcap import analyze_file, clear_cache
from wifipilot.synth import build_capture, build_handshake_frames, write_pcap
from tests.conftest import AP_MAC, PSK, SSID, STA_MAC

# --- hashcat's published example ------------------------------------------ #
EXAMPLE_ESSID = "TP-LINK_HASHCAT_TEST"
EXAMPLE_PSK = "hashcat!"
EXAMPLE_PMK = "0857172bd4d3ebb34cf00f3619726008d27558926d963a547332fab033023b82"
EXAMPLE_PMKID = "e7b71e94595346b4c5e084cbf7ac328e"
EXAMPLE_AP, EXAMPLE_STA = "64:66:b3:8e:c3:fc", "22:5e:dc:49:b7:aa"
EXAMPLE_ANONCE = "10e3be3b005a629e89de088d6a2fdc489db83ad4764f2d186b9cde15446e972e"
EXAMPLE_MIC = "024022795224bffca545276c3762686f"
# EAPOL-Key frame: version 1, type 3, length 0x0075, RSN descriptor, key info
# 0x010a (pairwise + MIC, KDV 2), replay 1, SNonce, zero IV/RSC/key-id/MIC, RSN IE
EXAMPLE_EAPOL = (
    "0103007502010a0000000000000000000148ce2ccba9c1fda130ff2fbbfb4fd3"
    "b063d1a93920b0f7df54a5cbf787b16171000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "00001630140100000fac040100000fac040100000fac028000"
)
EXAMPLE_LINE = ("WPA*02*%s*%s*%s*%s*%s*%s*a2"
                % (EXAMPLE_MIC, EXAMPLE_AP.replace(":", ""), EXAMPLE_STA.replace(":", ""),
                   EXAMPLE_ESSID.encode().hex(), EXAMPLE_ANONCE, EXAMPLE_EAPOL))


# --------------------------------------------------------------------------- #
# the published vector
# --------------------------------------------------------------------------- #
def test_published_pmk_and_pmkid_match_hcxpmktool():
    key = pmk(EXAMPLE_PSK, EXAMPLE_ESSID)
    assert key.hex() == EXAMPLE_PMK
    ap = bytes.fromhex(EXAMPLE_AP.replace(":", ""))
    sta = bytes.fromhex(EXAMPLE_STA.replace(":", ""))
    assert compute_pmkid(key, ap, sta) == EXAMPLE_PMKID


def test_published_example_line_verifies_with_hmac_sha1():
    """Key Descriptor Version 2 means HMAC-SHA1-128, not AES-CMAC."""
    line, problem = hash22000.parse_line(EXAMPLE_LINE)
    assert problem == "" and line is not None
    assert line.essid == EXAMPLE_ESSID and line.key_descriptor == KDV_SHA1
    assert line.mic_algorithm == "sha1" and line.authorized and line.verifiable
    assert line.message == 2 and line.pair_label.startswith("M2+M3")

    verifiers = hash22000.verifiers([line])
    assert len(verifiers) == 1
    assert verifiers[0].check(EXAMPLE_PSK)
    assert verifiers[0].check("hashcat") is False
    assert verifiers[0].check("not-the-passphrase") is False


def test_the_mic_algorithm_follows_the_key_descriptor_version():
    assert mic_algorithms(KDV_MD5) == ("md5",)
    assert mic_algorithms(KDV_SHA1) == ("sha1",)
    assert mic_algorithms(KDV_CMAC) == ("cmac",)
    assert mic_algorithms(0) == ("cmac", "sha1")      # "whatever the AKM says"

    key = os.urandom(64)
    frame = bytes.fromhex(EXAMPLE_EAPOL)
    assert mic_from_ptk(key, frame, KDV_SHA1) != mic_from_ptk(key, frame, KDV_CMAC)
    assert len(mic_from_ptk(key, frame, KDV_MD5)) == 16
    assert mic_from_ptk(key, frame) == mic_from_ptk(key, frame, KDV_SHA1)   # from the frame


# --------------------------------------------------------------------------- #
# writing
# --------------------------------------------------------------------------- #
def _hash_lines(tmp_path, kdv=KDV_SHA1):
    path, _ = build_capture(str(tmp_path / "round.pcap"), SSID, AP_MAC, STA_MAC, PSK,
                            include_pmkid=True, kdv=kdv)
    clear_cache()
    return path, hash22000.lines_from_analysis(analyze_file(path))


def test_capture_round_trips_through_a_hash_file(tmp_path):
    _, lines = _hash_lines(tmp_path)
    assert len(lines) == 2                      # one PMKID, one EAPOL
    kinds = [line.split("*")[1] for line in lines]
    assert kinds == ["01", "02"]

    parsed, problems = hash22000.parse_text("\n".join(lines))
    assert problems == []
    assert [line.kind for line in parsed] == ["pmkid", "eapol"]
    assert all(line.essid == SSID for line in parsed)
    assert all(line.bssid == AP_MAC for line in parsed)

    verifiers = hash22000.verifiers(parsed)
    assert len(verifiers) == 2
    for verifier in verifiers:
        assert verifier.check(PSK) is True
        assert verifier.check("WrongPassphrase") is False


def test_exported_lines_are_shaped_like_hashcat_expects(tmp_path):
    path, lines = _hash_lines(tmp_path)
    pmkid_line, eapol_line = (line.split("*") for line in lines)

    assert pmkid_line[:3] == ["WPA", "01", pmkid_line[2]] and len(pmkid_line) == 9
    assert pmkid_line[6] == "" and pmkid_line[7] == ""     # no nonce/EAPOL for a PMKID
    assert pmkid_line[2] == analyze_file(path).pmkids[0].pmkid

    assert len(eapol_line) == 9
    assert bytes.fromhex(eapol_line[5]).decode() == SSID
    assert len(bytes.fromhex(eapol_line[6])) == 32         # the ANonce
    frame = bytes.fromhex(eapol_line[7])
    assert frame[81:97] == bytes(16)                       # MIC zeroed in the frame
    assert int.from_bytes(frame[2:4], "big") == len(frame) - 4
    assert eapol_line[8] == "00"                           # M1+M2, EAPOL from M2
    for mac in (eapol_line[3], eapol_line[4]):
        assert len(mac) == 12 and ":" not in mac


@pytest.mark.parametrize("kdv", [KDV_MD5, KDV_SHA1, KDV_CMAC])
def test_every_key_descriptor_version_survives_the_round_trip(tmp_path, kdv):
    """Real captures are KDV 2 (WPA2), 3 (PMF/SAE) or 1 (TKIP): all must verify."""
    _, lines = _hash_lines(tmp_path, kdv)
    parsed, _ = hash22000.parse_text("\n".join(lines))
    eapol_line = next(line for line in parsed if line.kind == "eapol")
    assert eapol_line.key_descriptor == kdv
    verifiers = hash22000.verifiers([eapol_line])
    assert verifiers and verifiers[0].check(PSK)
    assert not verifiers[0].check("WrongPassphrase")


def test_non_utf8_ssid_keeps_its_exact_bytes(tmp_path):
    """PBKDF2 salts with the SSID *bytes*; a name that is not UTF-8 must survive."""
    raw = b"Caf\xe9-\xff\xfe"
    ssid = raw.decode("latin-1")
    frames, pmkid = build_handshake_frames(ssid, AP_MAC, STA_MAC, PSK, include_pmkid=True)
    path = str(tmp_path / "odd-ssid.pcap")
    write_pcap(path, frames)
    clear_cache()
    analysis = analyze_file(path)
    lines = hash22000.lines_from_analysis(analysis)
    parsed, problems = hash22000.parse_text("\n".join(lines))
    assert problems == []

    verifiers = hash22000.verifiers(parsed)
    assert verifiers and all(verifier.usable for verifier in verifiers)
    assert any(verifier.check(PSK) for verifier in verifiers)
    assert parsed[0].essid_bytes == raw or parsed[0].essid_bytes == ssid.encode("utf-8")


def test_malformed_lines_are_reported_and_skipped():
    text = "\n".join([
        "# a comment from whoever shared the file",
        "",
        "not a hash at all",
        "WPA*03*00112233445566778899aabbccddeeff*aabbccddeeff*aabbccddeeff*54657374***",
        "WPA*01*zzzz*aabbccddeeff*aabbccddeeff*54657374***02",
        "WPA*01*00112233445566778899aabbccddeeff*aabbccddeeff*aabbccddeeff***02",  # no SSID
        "WPA*02*00112233445566778899aabbccddeeff*aabbccddeeff*aabbccddeeff*54657374**00*00",
    ])
    lines, problems = hash22000.parse_text(text)
    assert len(problems) == 5
    assert any("802.11r" in problem for problem in problems)
    assert any("ESSID" in problem for problem in problems)
    assert any("truncated EAPOL" in problem for problem in problems)
    assert len(lines) == 0


def test_lines_without_a_usable_nonce_are_not_counted_as_crackable(tmp_path):
    """M4-based pairs usually have a zeroed nonce: nobody can verify those."""
    frames, _ = build_handshake_frames(SSID, AP_MAC, STA_MAC, PSK)
    path = str(tmp_path / "m4.pcap")
    write_pcap(path, frames)
    clear_cache()
    parsed, _ = hash22000.parse_text("\n".join(hash22000.lines_from_analysis(analyze_file(path))))
    eapol_line = next(line for line in parsed if line.kind == "eapol")

    line = hash22000.HashLine(kind="eapol", bssid=AP_MAC, station=STA_MAC,
                              essid=SSID, essid_bytes=SSID.encode(),
                              mic=bytes(16), nonce=bytes(32), eapol=bytes(121),
                              message=4)
    assert line.verifiable is False
    assert hash22000.verifiers([line]) == []
    assert eapol_line.verifiable is True            # the M2 line still works


# --------------------------------------------------------------------------- #
# cracking
# --------------------------------------------------------------------------- #
def test_cracker_cracks_a_hash_file_end_to_end(tmp_path, session):
    _, lines = _hash_lines(tmp_path)
    path = hash22000.write_lines(lines, str(tmp_path / "crack.hc22000"))

    ap = AccessPoint(bssid=AP_MAC, essid=SSID, encryption="WPA2")
    capture = Capture(kind="handshake", bssid=AP_MAC, essid=SSID, path=path, valid=True)
    cracker = Cracker(session, session.config, session.bus, demo=False)
    result = cracker.crack_capture(ap, capture, wordlists=[], timeout=60)

    assert result.cracked and result.password == PSK and result.verified
    assert result.tool == "wifipilot (built-in)"
    assert 0 < result.attempts < 100                # counted, not the whole space
    assert capture.password == PSK


def test_cracker_refuses_a_hash_file_with_nothing_to_verify(tmp_path, session):
    """An M4-style pair whose client nonce was zeroed on air: honest refusal."""
    _, lines = _hash_lines(tmp_path)
    frame = bytearray(bytes.fromhex(next(line for line in lines
                                         if line.startswith("WPA*02")).split("*")[7]))
    frame[17:49] = bytes(32)                       # the SNonce never made it to disk
    path = str(tmp_path / "no-nonce.hc22000")
    with open(path, "w") as handle:
        handle.write("*".join(["WPA", "02", "00" * 16, AP_MAC.replace(":", ""),
                               STA_MAC.replace(":", ""), SSID.encode().hex(),
                               "aa" * 32, frame.hex(), "01"]) + "\n")
    ap = AccessPoint(bssid=AP_MAC, essid=SSID)
    capture = Capture(kind="handshake", bssid=AP_MAC, essid=SSID, path=path, valid=True)
    cracker = Cracker(session, session.config, session.bus, demo=False)
    result = cracker.crack_capture(ap, capture, wordlists=[], timeout=20)

    assert not result.cracked and result.attempts == 0
    assert "no verifiable hash" in result.reason


# --------------------------------------------------------------------------- #
# CLI + module surface
# --------------------------------------------------------------------------- #
def test_export_command_writes_a_usable_hash_file(tmp_path, capsys):
    source, _ = build_capture(str(tmp_path / "cli.pcap"), SSID, AP_MAC, STA_MAC, PSK,
                              include_pmkid=True)
    out = tmp_path / "cli.hc22000"
    assert main(["export", source, "--out", str(out), "--no-color"]) == 0
    capsys.readouterr()

    text = out.read_text()
    assert text.count("WPA*") == 2
    lines, problems = hash22000.parse_text(text)
    assert problems == [] and len(hash22000.verifiers(lines)) == 2


def test_export_command_can_print_to_stdout(tmp_path, capsys):
    source, _ = build_capture(str(tmp_path / "cli2.pcap"), SSID, AP_MAC, STA_MAC, PSK)
    assert main(["export", source, "--out", "-", "--eapol-only", "--no-color"]) == 0
    captured = capsys.readouterr().out
    lines, _ = hash22000.parse_text(captured)
    assert len(lines) == 1 and lines[0].kind == "eapol"


def test_analyze_command_reports_hash_files(tmp_path, capsys):
    source, _ = build_capture(str(tmp_path / "an.pcap"), SSID, AP_MAC, STA_MAC, PSK)
    out = tmp_path / "an.hc22000"
    main(["export", source, "--out", str(out), "--no-color"])
    capsys.readouterr()

    assert main(["--json", "analyze", str(out)]) == 0
    payload = json.loads(capsys.readouterr().out)[0]
    assert payload["format"] == "hc22000"
    assert payload["lines"] == 2 and payload["verifiable"] == 2
    assert payload["essids"] == [SSID]
    assert payload["detail"][0]["kind"] in ("pmkid", "eapol")


def test_module_surface_analyzes_and_cracks_hash_files(tmp_path):
    import wifipilot as wp

    os.environ.setdefault("WIFIPILOT_ALLOW_NON_LINUX", "1")
    source, _ = build_capture(str(tmp_path / "api.pcap"), SSID, AP_MAC, STA_MAC, PSK)
    target = str(tmp_path / "api.hc22000")
    assert wp.export(source, target) == target

    report = wp.analyze(target)
    assert report["format"] == "hc22000" and report["lines"] == 2

    wp.configure(demo=False, provider="none")
    result = wp.crack(target, essid=SSID, timeout=60)
    assert result.cracked and result.password == PSK and result.verified
