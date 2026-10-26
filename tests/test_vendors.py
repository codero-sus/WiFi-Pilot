# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""The OUI/VENDOR layer: who made this radio, and what that usually means.

Two different things are being tested here and they must not be confused:

* the OUI lookup, which is a *lookup* (a MAC prefix is in the registry or not), and
* the vendor dossier, which is a *heuristic* (AVM boxes usually ship with WPS on).

Every dossier answer therefore has to carry its confidence, and an unknown
vendor must produce an empty answer rather than a guess.
"""

from __future__ import annotations

import json

import pytest

from wifipilot import vendors
from wifipilot.vendors import oui_lookup, oui_stats, oui_vendor, vendor_dossier


def test_the_registry_is_readable_and_populated():
    """The bundled registry is a real IEEE subset, not a handful of guesses."""
    stats = oui_stats()
    assert stats["exact"] > 5_000
    assert stats["prefix"] > 20
    assert stats["readable"] is True


def test_oui_lookup_distinguishes_exact_from_prefix():
    """A 24-bit hit is a lookup; a 28-bit hit is a (labelled) fallback."""
    vendor, match = oui_lookup("d0:12:cb:00:00:01")           # a real AVM 24-bit OUI
    assert vendor == "AVM" and match == "exact"

    vendor, match = oui_lookup("d0:9e:12:9d:36:cc")           # covered by d0:9e:1x/28
    assert vendor == "AVM" and match == "prefix"

    vendor, match = oui_lookup("00:00:01:00:00:01")           # XEROX: not in the subset
    assert vendor == "" and match == "none"

    vendor, match = oui_lookup("02:00:00:00:00:01")           # bit 1 set: never a vendor
    assert match == "local" and "locally administered" in vendor


def test_oui_lookup_normalises_whatever_the_operator_pasted():
    for spelling in ("D0:12:CB:00:00:01", "d0-12-cb-00-00-01", "d012cb000001", "D012CB"):
        vendor, match = oui_lookup(spelling)
        assert vendor == "AVM", spelling
        assert match == "exact", spelling


def test_locally_administered_macs_are_named_not_guessed():
    """A randomised MAC is not a vendor: say so instead of inventing one."""
    vendor, match = oui_lookup("02:00:00:00:00:01")
    assert match == "local"
    assert vendor == "locally administered"


def test_oui_vendor_is_strict_on_request():
    """``strict`` drops the 28-bit fallback: a guess is not a lookup."""
    assert oui_vendor("d0:9e:12:9d:36:cc") == "AVM"           # from the 28-bit block
    assert oui_vendor("d0:9e:12:9d:36:cc", strict=True) == ""
    assert oui_vendor("d0:12:cb:00:00:01", strict=True) == "AVM"
    assert oui_vendor("aa:bb:cc:dd:ee:ff") == ""
    assert oui_vendor("aa:bb:cc:dd:ee:ff", strict=True) == ""
    assert oui_vendor("") == ""


def test_dossiers_are_heuristics_and_say_so():
    dossier = vendor_dossier("AVM")
    assert dossier["matched"] is True
    assert dossier["confidence"] == "heuristic"
    assert dossier["label"]
    assert dossier["wps"] and dossier["default_key"] and dossier["notes"]
    assert dossier["attacks"], "a dossier without attack hints is decoration"
    assert "not findings" in dossier["disclaimer"].lower()


def test_every_dossier_label_round_trips_through_the_lookup():
    """A dossier that cannot be found by its own name is a dead entry."""
    for name in vendors.VENDOR_DOSSIERS:
        dossier = vendor_dossier(name)
        assert dossier["matched"] is True, name
        assert dossier["key"] == name


def test_every_registry_vendor_name_reaches_its_dossier():
    """The registry's names and the dossier keys must stay in step.

    A name may legitimately have no dossier (an obscure OEM board), but a name
    that resolves at all has to resolve to a dossier that exists — otherwise a
    discovered AP would map to a key nobody ever wrote.
    """
    names = set(vendors.OUI["exact"].values()) | set(vendors.OUI["prefix"].values())
    for name in names:
        key = vendors._key_for(name)
        if key:
            assert key in vendors.VENDOR_DOSSIERS, f"{name} -> {key}"


def test_the_registry_s_core_brands_all_have_dossiers():
    """Coverage that matters: the brands most likely to be on the air."""
    for brand in ("AVM", "TP-Link", "Netgear", "ARRIS", "Cisco", "D-Link", "Huawei",
                  "MikroTik", "Ubiquiti", "Zyxel", "Belkin", "Linksys", "MediaTek",
                  "Edimax", "Buffalo"):
        dossier = vendors.vendor_dossier(brand)
        assert dossier["matched"] is True, brand
        assert dossier["attacks"], brand


def test_unknown_vendors_get_an_empty_dossier_not_a_guess():
    dossier = vendor_dossier("Definitely Not A Vendor 12345")
    assert dossier["matched"] is False
    assert dossier["attacks"] == [] and dossier["key"] == ""
    assert dossier["confidence"] == "unknown"


def test_import_oui_file_merges_an_ieee_dump(tmp_path):
    """Importing 2 lines must not delete the 10,000 already there."""
    dump = tmp_path / "oui.txt"
    dump.write_text(
        "OUI/MA-L\n\n"
        "00-11-22   (hex)\t\tSome Vendor Inc\n"
        "0A-0B-0C   (hex)\t\tAnother Vendor Ltd\n"
        "not a real line\n")
    target = tmp_path / "registry.json"
    target.write_text('{"exact": {"aa:bb:cc": "Existing"}, "prefix": {}}')
    before = json.loads(target.read_text())["exact"]
    result = vendors.import_oui_file(str(dump), out=str(target))
    assert result["parsed"] >= 2 and result["vendors"] >= 2
    after = json.loads(target.read_text())["exact"]
    assert "aa:bb:cc" in after, "an import must merge into the registry, not replace it"
    assert len(after) > len(before)
    assert after.get("00:11:22") == "Some Vendor Inc"


def test_import_oui_file_writes_somewhere_and_json_round_trips(tmp_path):
    dump = tmp_path / "oui.txt"
    dump.write_text("00-AA-BB   (hex)\t\tRoundtrip Networks\n")
    target = tmp_path / "merged.json"
    result = vendors.import_oui_file(str(dump), out=str(target))
    assert result["path"] == str(target)
    data = json.loads(target.read_text())
    assert data.get("exact"), "the merged file must keep the entries it read"


def test_import_oui_file_refuses_a_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        vendors.import_oui_file(str(tmp_path / "nope.txt"))
