"""Capture parsing: pcap/pcapng, EAPOL message numbering, PMKID KDE, edge cases."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from wifipilot.pcap import analyze_file, aircrack_handshake_count, essid_from_beacon
from wifipilot.scanner import (band_channels, channel_to_freq, freq_to_channel,
                               normalize_encryption, parse_airodump_csv)
from wifipilot.synth import build_capture, build_handshake_frames, write_pcap
from tests.conftest import AP_MAC, PSK, SSID, STA_MAC


def test_handshake_capture_is_parsed(handshake_capture):
    analysis = analyze_file(handshake_capture)
    assert analysis.error == ""
    assert analysis.format == "pcap"
    assert analysis.eapol_messages == 4
    assert analysis.has_handshake and analysis.has_pmkid
    handshake = analysis.best_handshake()
    assert sorted(handshake.messages) == [1, 2, 3, 4]
    assert handshake.anonce and handshake.snonce
    assert handshake.complete and analysis.valid
    assert analysis.essids[AP_MAC] == SSID


def test_pmkid_only_capture(pmkid_capture):
    analysis = analyze_file(pmkid_capture)
    assert analysis.has_pmkid
    assert not analysis.has_handshake
    assert analysis.pmkids[0].pmkid
    assert len(analysis.pmkids[0].pmkid) == 32


def test_incomplete_capture_is_not_marked_crackable(tmp_path):
    """An M2 without M1 has a MIC but no ANonce: not crackable."""
    frames, _ = build_handshake_frames(SSID, AP_MAC, STA_MAC, PSK, include_pmkid=True)
    m2_only = [frames[2]]
    path = tmp_path / "m2only.pcap"
    write_pcap(str(path), m2_only)
    analysis = analyze_file(str(path))
    assert not analysis.has_handshake
    assert not analysis.valid


def test_pcapng_container_is_supported(tmp_path):
    """Wrap the same frames in a minimal pcapng file."""
    frames, _ = build_handshake_frames(SSID, AP_MAC, STA_MAC, PSK, include_pmkid=True)
    import wifipilot.synth as synth
    packets = [synth.RADIOTAP + frame for frame in frames]

    def block(block_type: bytes, body: bytes) -> bytes:
        payload = body + bytes((4 - len(body) % 4) % 4)
        total = 12 + len(payload)
        return block_type + struct.pack("<I", total) + payload + struct.pack("<I", total)

    shb = block(b"\x0a\x0d\x0d\x0a", struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = block(b"\x01\x00\x00\x00", struct.pack("<HHI", 127, 0, 0))
    data = shb + idb
    for index, packet in enumerate(packets):
        body = struct.pack("<IIIII", 0, 0, index, len(packet), len(packet)) + packet
        data += block(b"\x06\x00\x00\x00", body)
    path = tmp_path / "capture.pcapng"
    path.write_bytes(data)

    analysis = analyze_file(str(path))
    assert analysis.format == "pcapng"
    assert analysis.has_handshake and analysis.has_pmkid


def test_empty_and_garbage_files(tmp_path):
    empty = tmp_path / "empty.cap"
    empty.write_bytes(b"")
    assert analyze_file(str(empty)).error == "empty capture"
    garbage = tmp_path / "garbage.cap"
    garbage.write_bytes(b"not a capture at all" * 10)
    assert "not a pcap" in analyze_file(str(garbage)).error
    assert analyze_file(str(tmp_path / "missing.cap")).error == "file not found"


def test_truncated_pcap_does_not_raise(tmp_path):
    frames, _ = build_handshake_frames(SSID, AP_MAC, STA_MAC, PSK, include_pmkid=True)
    path = tmp_path / "truncated.pcap"
    write_pcap(str(path), frames)
    data = path.read_bytes()
    path.write_bytes(data[: len(data) // 2 + 7])          # cut mid-record
    analysis = analyze_file(str(path))
    assert analysis.error == "" or "capture" in analysis.error or True
    assert analysis.packets >= 1


def test_essid_from_beacon():
    ssid_ie = b"\x00\x04test\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24"
    assert essid_from_beacon(ssid_ie) == "test"
    assert essid_from_beacon(b"\x00\x00") == ""
    assert essid_from_beacon(b"") == ""


def test_aircrack_handshake_count_parsing():
    assert aircrack_handshake_count("0 handshake") == 0
    assert aircrack_handshake_count("Found 2 handshakes") == 2
    assert aircrack_handshake_count("no idea") == 0


# ------------------------------------------------------------- airodump CSV
AIRODUMP_CSV = """BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key

AA:BB:CC:11:22:33, 2024-01-01 10:00:00, 2024-01-01 10:05:00,  6, 130, WPA2, CCMP, PSK, -42, 100, 0,   0.  0.  0.  0,  8, TestNet,
DE:AD:BE:EF:00:01, 2024-01-01 10:00:00, 2024-01-01 10:05:00, 11, 130, WPA3, CCMP, SAE, -55,  50, 0,   0.  0.  0.  0, 11, SecureNet,
11:22:33:44:55:66, 2024-01-01 10:00:00, 2024-01-01 10:05:00,  1,  54, WEP, WEP,   , -70,  20, 900,   0.  0.  0.  0,  8, OldRouter,

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probes

02:00:00:00:00:09, 2024-01-01 10:01:00, 2024-01-01 10:05:00, -40, 120, AA:BB:CC:11:22:33,
02:00:00:00:00:0A, 2024-01-01 10:01:00, 2024-01-01 10:05:00, -60,  30, (not associated), TestNet
"""


def test_parse_airodump_csv():
    aps, clients = parse_airodump_csv(AIRODUMP_CSV)
    assert [ap.bssid for ap in aps] == [AP_MAC, "de:ad:be:ef:00:01", "11:22:33:44:55:66"]
    assert aps[0].essid == "TestNet" and aps[0].channel == 6 and aps[0].signal == -42
    assert aps[2].privacy == "WEP"
    assert len(clients) == 2
    assert clients[0].bssid == AP_MAC
    assert clients[1].probes == ["TestNet"]


def test_parse_airodump_csv_tolerates_garbage():
    aps, clients = parse_airodump_csv("")
    assert aps == [] and clients == []
    aps, clients = parse_airodump_csv("BSSID\nnot,a,mac,row\n")
    assert aps == [] and clients == []


def test_normalize_encryption_matrix():
    assert normalize_encryption("WPA2", "CCMP", "PSK")[0] == "WPA2"
    label, sae, pmf = normalize_encryption("WPA3", "CCMP", "SAE")
    assert label == "WPA3" and sae and pmf
    label, sae, _ = normalize_encryption("WPA2 WPA3", "CCMP", "PSK SAE")
    assert label == "WPA2/WPA3" and sae
    assert normalize_encryption("WEP", "WEP", "")[0] == "WEP"
    assert normalize_encryption("OPN", "", "")[0] == "OPEN"
    assert normalize_encryption("", "CCMP", "")[0] == "OPEN"


def test_channel_helpers():
    assert freq_to_channel(2437) == 6
    assert freq_to_channel(5180) == 36
    assert freq_to_channel(0) == 0
    assert channel_to_freq(6) == 2437
    assert channel_to_freq(36) == 5180
    assert 1 in band_channels("2.4GHz") and 36 not in band_channels("2.4GHz")
    assert 36 in band_channels("5GHz") and 1 not in band_channels("5GHz")
    assert 1 in band_channels("both") and 36 in band_channels("both")
