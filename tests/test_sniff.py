# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Passive intelligence: probe requests, deauth counts, rogue-twin patterns.

Everything in this module is derived from a file that already exists and from the
target list — no radio, no injection, nothing transmitted — so the tests build a
capture with the synth helpers and check the arithmetic of the read-out. The
report's *claims* matter as much as its numbers: a twin pattern must be labelled a
heuristic, not an accusation.
"""

from __future__ import annotations

import struct

from wifipilot import synth
from wifipilot.sniff import (ProbeClient, attack_frames, passive_report,
                             probe_requests, rogue_aps)


def _capture(tmp_path, name: str = "mixed.pcap") -> str:
    frames = [synth.build_beacon("BenchNet", "d0:9e:12:9d:36:cc", channel=6)]
    frames += [
        synth.build_probe_request("02:00:00:00:00:11", "CorpNet"),
        synth.build_probe_request("02:00:00:00:00:11", ""),              # wildcard
        synth.build_probe_request("dc:a6:32:11:22:33", "CafeGuest"),
        synth.build_probe_request("dc:a6:32:11:22:33", "CorpNet"),
        synth.build_probe_request("dc:a6:32:11:22:33", "CorpNet"),       # repeat
    ]
    frames += synth.build_deauth_flood("d0:9e:12:9d:36:cc", rounds=120)
    frames += [synth.build_deauth("d0:9e:12:9d:36:cc", "02:11:22:33:44:55")]
    return synth.write_pcap(str(tmp_path / name), frames)


def _pcapng(tmp_path, frames) -> str:
    """The same frames inside a minimal pcapng container (no pcap writer needed)."""
    def block(block_type: bytes, body: bytes) -> bytes:
        payload = body + bytes((4 - len(body) % 4) % 4)
        total = 12 + len(payload)
        return block_type + struct.pack("<I", total) + payload + struct.pack("<I", total)

    data = block(b"\x0a\x0d\x0d\x0a", struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    data += block(b"\x01\x00\x00\x00", struct.pack("<HHI", 127, 0, 0))
    for index, frame in enumerate(frames):
        packet = synth.RADIOTAP + frame
        body = struct.pack("<IIIII", 0, 0, index, len(packet), len(packet)) + packet
        data += block(b"\x06\x00\x00\x00", body)
    path = tmp_path / "sniff.pcapng"
    path.write_bytes(data)
    return str(path)


def test_the_reader_understands_pcapng_too(tmp_path):
    frames = [synth.build_beacon("BenchNet", "d0:9e:12:9d:36:cc"),
              synth.build_probe_request("dc:a6:32:11:22:33", "CorpNet")]
    frames += synth.build_deauth_flood("d0:9e:12:9d:36:cc", rounds=120)
    path = _pcapng(tmp_path, frames)
    clients = probe_requests(path)
    assert list(clients) == ["dc:a6:32:11:22:33"]
    assert clients["dc:a6:32:11:22:33"].ssids == ["CorpNet"]
    assert attack_frames(path)["total"] == 120


# --------------------------------------------------------------------------- #
# probe requests
# --------------------------------------------------------------------------- #

def test_probe_requests_group_clients_and_keep_their_pnl(tmp_path):
    clients = probe_requests(_capture(tmp_path))
    assert set(clients) == {"02:00:00:00:00:11", "dc:a6:32:11:22:33"}
    first = clients["02:00:00:00:00:11"]
    assert first.ssids == ["CorpNet"]
    assert (first.directed, first.broadcast) == (1, 1)
    assert first.pnl == ["CorpNet"]
    second = clients["dc:a6:32:11:22:33"]
    assert second.ssids == ["CafeGuest", "CorpNet"]      # seen order, deduplicated
    assert (second.directed, second.broadcast) == (3, 0)
    assert second.vendor == "Raspberry Pi"               # dc:a6:32 belongs to them


def test_probe_limit_caps_clients_not_requests(tmp_path):
    path = _capture(tmp_path)
    capped = probe_requests(path, limit=1)
    assert len(capped) == 1
    assert probe_requests(path, limit=500)               # uncapped by default


def test_a_missing_capture_is_not_an_error(tmp_path):
    assert probe_requests(str(tmp_path / "nope.pcap")) == {}
    assert attack_frames(str(tmp_path / "nope.pcap"))["total"] == 0
    assert passive_report("")["probes"] == []


# --------------------------------------------------------------------------- #
# deauth / disassoc
# --------------------------------------------------------------------------- #

def test_attack_frames_count_and_attribute_deauths(tmp_path):
    counts = attack_frames(_capture(tmp_path))
    assert counts["total"] == 121
    assert counts["deauth"] == 121 and counts["disassoc"] == 0
    assert counts["broadcast"] == 120 and counts["directed"] == 1
    assert counts["by_bssid"][0] == {"bssid": "d0:9e:12:9d:36:cc", "count": 121}
    assert counts["flood"] is True                      # >= 100 frames in one capture
    assert "unauthenticated" in counts["note"]


def test_a_single_deauth_is_not_a_flood(tmp_path):
    path = synth.write_pcap(str(tmp_path / "one.pcap"),
                            [synth.build_deauth("d0:9e:12:9d:36:cc")])
    counts = attack_frames(path)
    assert counts["total"] == 1 and counts["flood"] is False


# --------------------------------------------------------------------------- #
# rogue twins
# --------------------------------------------------------------------------- #

def _ap(bssid: str, essid: str, signal: int) -> dict:
    return {"bssid": bssid, "essid": essid, "signal": signal}


def test_one_essid_from_two_vendors_is_reported_as_a_pattern():
    twins = rogue_aps([
        _ap("d0:9e:12:9d:36:cc", "BenchNet", -40),          # AVM
        _ap("f8:1a:67:00:00:01", "benchnet", -80),          # TP-Link, far away
    ])
    assert len(twins) == 1
    twin = twins[0]
    assert twin["essid"] == "BenchNet"
    assert set(twin["vendors"]) == {"AVM", "TP-Link"}
    assert twin["signal_spread_db"] == 40
    assert twin["reason"] == "one ESSID seen from several vendors"
    assert twin["confidence"] == "heuristic"                # evidence, not proof


def test_the_same_vendor_with_a_normal_spread_is_not_a_twin():
    assert rogue_aps([
        _ap("d0:9e:12:9d:36:cc", "MeshNet", -40),
        _ap("d0:9e:12:9d:36:cd", "MeshNet", -48),           # same vendor, same place
    ]) == []


def test_a_wide_signal_spread_alone_is_enough_to_look_at():
    twins = rogue_aps([
        _ap("d0:9e:12:9d:36:cc", "Office", -35),
        _ap("d0:9e:12:9d:36:cd", "Office", -85),            # same vendor, 50 dB apart
    ])
    assert len(twins) == 1
    assert twins[0]["reason"] == "one ESSID with a very wide signal spread"


def test_hidden_networks_are_not_twins():
    assert rogue_aps([_ap("d0:9e:12:9d:36:cc", "", -40),
                      _ap("f8:1a:67:00:00:01", "", -80)]) == []


# --------------------------------------------------------------------------- #
# the combined report
# --------------------------------------------------------------------------- #

def test_passive_report_joins_probes_attacks_and_targets(tmp_path):
    path = _capture(tmp_path)
    report = passive_report(path, [_ap("d0:9e:12:9d:36:cc", "BenchNet", -45)])
    assert report["path"] == path
    assert report["attacks"]["total"] == 121
    assert len(report["probes"]) == 2
    wanted = {item["essid"]: item["clients"] for item in report["wanted_networks"]}
    assert sorted(wanted["CorpNet"]) == ["02:00:00:00:00:11", "dc:a6:32:11:22:33"]
    assert wanted["CafeGuest"] == ["dc:a6:32:11:22:33"]
    # BenchNet is on air; the other two are only in clients' memories
    assert set(report["hidden_targets"]) == {"CafeGuest", "CorpNet"}
    assert report["rogue"] == []
    assert report["note"] == "read-only: nothing was transmitted"


def test_probes_are_ordered_by_how_specific_they_were(tmp_path):
    report = passive_report(_capture(tmp_path))
    assert [entry["mac"] for entry in report["probes"]] == \
        ["dc:a6:32:11:22:33", "02:00:00:00:00:11"]


def test_probe_client_to_dict_matches_the_dataclass():
    client = ProbeClient(mac="aa:bb:cc:dd:ee:ff", ssids=["Home"], directed=2,
                         broadcast=1, vendor="Vendor")
    payload = client.to_dict()
    assert payload == {"mac": "aa:bb:cc:dd:ee:ff", "vendor": "Vendor",
                       "ssids": ["Home"], "probes": 3, "directed": 2, "broadcast": 1}
