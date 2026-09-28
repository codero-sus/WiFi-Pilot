"""The new surface, seen from each front end: CLI verbs, API calls, web routes.

The point of these three is that a feature only counts once it is reachable: a
module nobody can call from the shell, a script or the browser is a module that
does not exist. Everything here runs without a radio and without root.
"""

from __future__ import annotations

import json

import pytest

from wifipilot import synth
from wifipilot.cli import main


def run(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


@pytest.fixture()
def hash_file(tmp_path):
    """hashcat's published example network, as a mode-22000 file."""
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


@pytest.fixture()
def probe_capture(tmp_path):
    frames = [synth.build_beacon("BenchNet", "d0:9e:12:9d:36:cc")]
    frames += [synth.build_probe_request("dc:a6:32:11:22:33", "CorpNet"),
               synth.build_probe_request("02:00:00:00:00:11", "")]
    frames += synth.build_deauth_flood("d0:9e:12:9d:36:cc", rounds=120)
    return synth.write_pcap(str(tmp_path / "probes.pcap"), frames)  # -> path


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def test_cli_survey_reports_probes_and_attacks(capsys, probe_capture):
    code, out, _ = run(capsys, "--json", "survey", probe_capture,
                       "--session-dir", "")
    assert code == 0
    report = json.loads(out)
    assert report["attacks"]["total"] == 120 and report["attacks"]["flood"] is True
    assert [entry["mac"] for entry in report["probes"]] == ["dc:a6:32:11:22:33",
                                                           "02:00:00:00:00:11"]
    assert report["wanted_networks"][0]["essid"] == "CorpNet"
    assert report["note"] == "read-only: nothing was transmitted"


def test_cli_survey_without_a_capture_says_so(capsys, tmp_path):
    code, out, _ = run(capsys, "survey", "--session-dir", str(tmp_path / "empty"))
    assert code == 0
    assert "passive survey" in out


def test_cli_pins_lists_candidates_and_the_plan(capsys):
    code, out, _ = run(capsys, "--json", "pins", "d0:12:cb:00:00:01",
                       "--essid", "FRITZ!Box 7590 QY")
    assert code == 0
    payload = json.loads(out)
    assert payload["vendor"] == "AVM"
    pins = [item["pin"] for item in payload["candidates"]]
    assert "00000017" in pins and "36362998" in pins
    assert payload["order"][0] in pins
    assert payload["plan"]["spaces"]["two-half sweep (the documented attack)"] == 11_000


def test_cli_pins_accepts_a_known_first_half(capsys):
    code, out, _ = run(capsys, "--json", "pins", "d0:12:cb:00:00:01",
                       "--first-half", "1234")
    assert code == 0
    order = json.loads(out)["order"]
    # the documented candidates come first, then the 1,000 completions of "1234"
    assert order[0] == "00000000"
    completions = [pin for pin in order if pin.startswith("1234")]
    assert len(completions) >= 5
    assert all(len(pin) == 8 for pin in order)


def test_cli_pins_rejects_a_bad_mac(capsys):
    code, out, err = run(capsys, "pins", "not-a-mac")
    assert code == 2
    assert "not a MAC" in (out + err)


def test_cli_pmk_verify_accepts_the_right_psk_and_rejects_a_wrong_one(capsys, hash_file):
    code, out, _ = run(capsys, "--json", "pmk", "verify", hash_file, "--psk", "hashcat!")
    assert code == 0
    result = json.loads(out)
    assert result["ok"] and result["essids"] == ["TP-LINK_HASHCAT_TEST"]

    code, out, _ = run(capsys, "--json", "pmk", "verify", hash_file, "--psk", "nope12345678")
    assert code == 1                       # the shell gets a usable exit status
    assert json.loads(out)["ok"] is False


def test_cli_pmk_convert_and_show_round_trip(capsys, hash_file, tmp_path):
    target = tmp_path / "out.hc22001"
    code, out, _ = run(capsys, "--json", "pmk", "convert", hash_file,
                       "--psk", "hashcat!", "--out", str(target))
    assert code == 0
    assert json.loads(out)["lines"] == 1
    code, out, _ = run(capsys, "--json", "pmk", "show", str(target))
    assert code == 0
    rows = json.loads(out)
    assert rows[0]["pmk"].startswith("0857172b")
    assert rows[0]["bssid"] == "64:66:b3:8e:c3:fc"


def test_cli_pmk_cache_shows_what_was_learned(capsys, tmp_path):
    from wifipilot import pmk
    directory = tmp_path / "state"
    directory.mkdir()
    pmk.PMKCache(path=str(directory / pmk.PMK_CACHE_NAME)).load().remember(
        "BenchNet", "hunter2hunter2", source="cli test")
    code, out, _ = run(capsys, "--json", "pmk", "cache", "--session-dir", str(directory))
    assert code == 0
    entries = json.loads(out)
    assert entries[0]["essid"] == "BenchNet"
    assert entries[0]["psk"] == "hunter2hunter2"


def test_cli_still_offers_the_old_commands(capsys):
    code, out, _ = run(capsys, "--json", "crack", "--list-strategies")
    assert code == 0 and json.loads(out)


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #

def test_api_survey_and_probes(probe_capture):
    import wifipilot as wp
    wp.reset()
    report = wp.survey(probe_capture)
    assert report["attacks"]["total"] == 120
    assert report["hidden_targets"] == ["CorpNet"]
    assert [entry["mac"] for entry in wp.probes(probe_capture)] == \
        ["dc:a6:32:11:22:33", "02:00:00:00:00:11"]


def test_api_pins_matches_the_cli():
    import wifipilot as wp
    payload = wp.pins(bssid="d0:12:cb:00:00:01", essid="FRITZ!Box 7590 QY")
    assert payload["vendor"] == "AVM"
    assert payload["plan"]["runnable"] >= 1
    assert all(len(pin) == 8 for pin in payload["order"])
    with pytest.raises(wp.TargetError):
        wp.pins(bssid="not-a-mac")


def test_api_pmk_verify_convert_and_cache(tmp_path, hash_file):
    import wifipilot as wp
    good = wp.pmk_verify("hashcat!", hash_file)
    assert good["ok"] and good["matched"]["bssid"] == "64:66:b3:8e:c3:fc"
    assert wp.pmk_verify("wrongpass123", hash_file)["ok"] is False

    written = wp.pmk_convert(hash_file, psk="hashcat!",
                             out=str(tmp_path / "api.hc22001"))
    assert written["lines"] == 1 and written["mode"] == 22001
    assert (tmp_path / "api.hc22001").read_text().startswith("WPA*02*0857172b")
    with pytest.raises(wp.TargetError):
        wp.pmk_verify("hashcat!", str(tmp_path / "nope.hc22000"))


def test_api_reveal_names_a_hidden_target(tmp_path):
    import wifipilot as wp
    wp.reset()
    wp.configure(demo=True, provider="none")
    wp.scan(duration=2)
    hidden = [ap for ap in wp.targets() if not (ap.get("essid") or "").strip()]
    assert hidden, "the simulator discovers a hidden network"
    bssid = hidden[0]["bssid"]
    capture, _lines = synth.build_capture(str(tmp_path / "reveal.pcap"),
                                          "NETGEAR-Home-9F", bssid,
                                          "02:11:22:33:44:55", "hunter2hunter2")
    result = wp.reveal(capture)
    assert result["note"].startswith("read-only")
    names = {row["essid"]: row for row in result["networks"]}
    assert names["NETGEAR-Home-9F"]["revealed"] is True
    assert wp.session().ap(bssid).essid == "NETGEAR-Home-9F"
    wp.reset()


def test_the_new_names_are_exported():
    import wifipilot as wp
    for name in ("survey", "probes", "pins", "reveal", "pmk_verify", "pmk_convert",
                 "pmk_cache"):
        assert name in wp.__all__, name
        assert callable(getattr(wp, name))


# --------------------------------------------------------------------------- #
# web
# --------------------------------------------------------------------------- #

@pytest.fixture()
def client(probe_capture):
    from fastapi.testclient import TestClient
    from wifipilot.config import Config
    from wifipilot.web.app import create_app
    config = Config(demo=True)
    app = create_app(config, demo=True, authorized=True)
    with TestClient(app) as test_client:
        yield test_client, probe_capture


def test_web_survey_route(client):
    test_client, capture = client
    response = test_client.get("/api/survey", params={"capture": capture})
    assert response.status_code == 200
    body = response.json()["survey"]
    assert body["attacks"]["total"] == 120
    assert body["wanted_networks"][0]["essid"] == "CorpNet"


def test_web_pins_route(client):
    test_client, _ = client
    response = test_client.get("/api/pins", params={"bssid": "d0:12:cb:00:00:01",
                                                    "essid": "FRITZ!Box 7590 QY"})
    assert response.status_code == 200
    body = response.json()
    assert body["vendor"] == "AVM" and body["candidates"]
    assert test_client.get("/api/pins", params={"bssid": "junk"}).status_code == 400


def test_web_pmk_routes(client, hash_file, tmp_path):
    test_client, _ = client
    response = test_client.get("/api/pmk/cache")
    assert response.status_code == 200 and "entries" in response.json()

    response = test_client.post("/api/pmk/verify", json={"psk": "hashcat!",
                                                         "capture": hash_file})
    assert response.status_code == 200
    assert response.json()["result"]["ok"] is True

    bad = test_client.post("/api/pmk/verify", json={"psk": "hashcat!",
                                                    "capture": str(tmp_path / "x")})
    assert bad.status_code == 400


def test_web_state_still_lists_every_attack(client):
    test_client, _ = client
    state = test_client.get("/api/state").json()
    names = {entry["name"] for entry in state.get("attacks", [])}
    assert {"hidden_ssid", "rogue_ap", "enterprise"} <= names
