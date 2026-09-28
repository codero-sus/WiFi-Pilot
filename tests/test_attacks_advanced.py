"""The two new attacks, the EAP/X.509 decoder and the CLI/API surfaces around them.

`tracker` follows a station; `rogue_radius` impersonates the AP to test the
certificate policy.  Both are honest about what they know: the tracker reports a
signal *trend*, not a position, and the rogue RADIUS reports what a client did or
nothing at all.
"""

from __future__ import annotations

import json

import pytest

from wifipilot import synth
from wifipilot.attacks import ATTACK_CLASSES, DEFAULT_ORDER, attack_catalog
from wifipilot.config import Config
from wifipilot.engine import Engine
from wifipilot.models import ATTACK_NAMES, AccessPoint, Client
from wifipilot.planner import preferred_attacks
from wifipilot.sniff import eap_exchange, x509_name


def _engine(tmp_path, attacks=None) -> Engine:
    config = Config()
    config.demo = True
    config.ollama.enabled = False
    config.output_dir = str(tmp_path / "loot")
    config.session_dir = str(tmp_path / "sessions")
    config.scan_time = 2
    config.attacks = list(attacks or ["tracker", "rogue_radius", "enterprise"])
    engine = Engine(config, demo=True)
    engine.prepare()
    engine.scan_for(2)
    return engine


# --------------------------------------------------------------------------- #
# registration and the planner
# --------------------------------------------------------------------------- #

def test_both_attacks_are_registered_and_described():
    for name in ("tracker", "rogue_radius"):
        assert name in ATTACK_CLASSES and name in ATTACK_NAMES
    catalog = {entry["name"]: entry for entry in attack_catalog()}
    assert catalog["tracker"]["default_enabled"] is True        # read-only
    assert catalog["tracker"]["needs_injection"] is False
    assert catalog["rogue_radius"]["default_enabled"] is False  # it impersonates
    assert catalog["rogue_radius"]["needs_injection"] is True
    assert all(entry["description"] for entry in catalog.values())
    assert DEFAULT_ORDER.index("tracker") < DEFAULT_ORDER.index("pmkid")
    assert DEFAULT_ORDER.index("rogue_radius") > DEFAULT_ORDER.index("enterprise")


def test_the_planner_watches_a_station_before_it_transmits():
    config = Config(demo=True)
    config.attacks = ["tracker", "handshake", "pmkid"]
    ap = AccessPoint("d0:9e:12:9d:36:cc", "HOME-2F4A", encryption="WPA2", auth="PSK")
    ap.clients = {"02:00:00:00:00:09": Client("02:00:00:00:00:09", "d0:9e:12:9d:36:cc")}
    plan = preferred_attacks(ap, config)
    assert plan[0] == "tracker"
    assert "handshake" in plan
    clientless = AccessPoint("aa:bb:cc:11:22:33", "Empty", encryption="WPA2", auth="PSK")
    assert "tracker" not in preferred_attacks(clientless, config)


def test_an_enterprise_target_gets_the_survey_then_the_impersonation():
    config = Config(demo=True)
    config.attacks = ["enterprise", "rogue_radius", "handshake", "pmkid"]
    ap = AccessPoint("34:c9:27:19:79:89", "CorpNet-8021X", encryption="ENTERPRISE",
                     auth="MGT")
    plan = preferred_attacks(ap, config)
    assert plan == ["enterprise", "rogue_radius"]      # no PSK attack is even offered
    config.stealth = True
    assert "rogue_radius" not in preferred_attacks(ap, config)


def test_a_rogue_radius_is_unavailable_without_an_impersonation_tool():
    from wifipilot.attacks import AttackContext
    from wifipilot.events import EventBus
    from wifipilot.session import Session

    from wifipilot.attacks import get_attack
    module = get_attack("rogue_radius")
    config = Config()
    config.demo = False
    session = Session(config, EventBus(), demo=False, authorized=True)
    context = AttackContext(session=session, config=config, bus=session.bus, iface="",
                            scanner=None, radio=None, demo=False, processes=None,
                            stop_event=None)
    assert module.available(context) is False
    reason = module.unavailable_reason(context)
    assert "eaphammer" in reason or "hostapd" in reason


# --------------------------------------------------------------------------- #
# tracker
# --------------------------------------------------------------------------- #

def test_tracker_follows_a_station_and_reports_a_trend(tmp_path):
    engine = _engine(tmp_path, ["tracker"])
    ap = engine.session.ap("d0:9e:12:9d:36:cc")
    attempt = engine.run_attack(ap.bssid, "tracker")
    assert attempt is not None and attempt.status == "success"
    extra = attempt.extra
    assert extra["station"] in ap.clients
    assert len(extra["samples"]) >= 2
    assert extra["signal_start"] and extra["signal_end"]
    assert extra["direction"] in ("closer", "further away", "stable")
    assert extra["trend_db"] == extra["signal_end"] - extra["signal_start"]
    assert "measurement, not a position" in extra["note"]
    assert engine.session.stats.stations_tracked == 1
    assert any(entry.get("kind") == "tracker" for entry in ap.history)


def json_ok(path: str) -> bool:
    import os
    return bool(path) and os.path.exists(path)


def test_tracker_writes_the_raw_samples_to_loot(tmp_path):
    engine = _engine(tmp_path, ["tracker"])
    ap = engine.session.ap("d0:9e:12:9d:36:cc")
    engine.run_attack(ap.bssid, "tracker")
    ap = engine.session.ap("d0:9e:12:9d:36:cc")
    path = engine.debug_last_attempt().extra.get("artifact")
    assert path and json_ok(path), "the trace is an artifact, not just an event"
    payload = json.loads(open(path, encoding="utf-8").read())
    assert payload["station"] and payload["samples"]


def test_tracker_does_not_repeat_the_same_walk(tmp_path):
    engine = _engine(tmp_path, ["tracker"])
    ap = engine.session.ap("d0:9e:12:9d:36:cc")
    assert engine.run_attack(ap.bssid, "tracker").status == "success"
    again = engine.run_attack(ap.bssid, "tracker")
    assert again is not None and again.status == "skipped"
    assert "already" in again.result and "new walk" in again.detail
    assert engine.session.stats.stations_tracked == 1


def test_the_demo_walk_varies_with_the_station(tmp_path):
    """Six identical trends would look like a template, not a measurement."""
    engine = _engine(tmp_path, ["tracker"])
    directions = set()
    for ap in list(engine.session.aps.values()):
        if not ap.clients:
            continue
        attempt = engine.run_attack(ap.bssid, "tracker")
        if attempt is not None and attempt.status == "success":
            directions.add(attempt.extra["direction"])
    assert len(directions) > 1
    assert directions <= {"closer", "further away", "stable"}


def test_tracker_says_so_when_there_is_nothing_to_follow(tmp_path):
    engine = _engine(tmp_path, ["tracker"])
    ap = engine.session.ap("f0:63:da:4a:c1:f5") if engine.session.ap("f0:63:da:4a:c1:f5") \
        else next(iter(engine.session.aps.values()))
    ap.clients.clear()
    attempt = engine.run_attack(ap.bssid, "tracker")
    assert attempt is not None and attempt.status == "failed"
    assert "no station" in attempt.result + attempt.detail


def test_the_tracker_follows_the_client_the_operator_named(tmp_path):
    engine = _engine(tmp_path, ["tracker"])
    first = engine.session.ap("d0:9e:12:9d:36:cc")
    wanted = next(iter(first.clients))
    engine.config.client_mac = wanted
    attempt = engine.run_attack(first.bssid, "tracker")
    assert attempt is not None and attempt.status == "success"
    assert attempt.extra["station"] == wanted
    assert attempt.extra["reason"] == "named by the operator"
    # every other AP is skipped, not failed: the station only lives on one of them
    other = next(ap for ap in engine.session.aps.values() if ap.bssid != first.bssid)
    elsewhere = engine.run_attack(other.bssid, "tracker")
    assert elsewhere is not None and elsewhere.status == "skipped"
    assert "not on" in elsewhere.result


def test_a_named_client_must_belong_to_the_target(tmp_path):
    """`attack --client` is a targeted deauth, so a typo must fail loudly."""
    engine = _engine(tmp_path, ["handshake"])
    engine.config.client_mac = "02:00:00:00:00:ff"
    ap = engine.session.ap("d0:9e:12:9d:36:cc")
    attempt = engine.run_attack(ap.bssid, "handshake")
    assert attempt is not None and attempt.status == "failed"
    assert "is not a client" in attempt.result
    engine.config.client_mac = next(iter(ap.clients))
    attempt = engine.run_attack(ap.bssid, "handshake")
    assert attempt is not None and attempt.status != "failed"


# --------------------------------------------------------------------------- #
# rogue radius
# --------------------------------------------------------------------------- #

def test_rogue_radius_reports_the_attempt_without_inventing_a_password(tmp_path):
    engine = _engine(tmp_path, ["rogue_radius"])
    ap = next(item for item in engine.session.aps.values()
              if (item.auth or "").upper() == "MGT")
    attempt = engine.run_attack(ap.bssid, "rogue_radius")
    assert attempt is not None and attempt.status == "success"
    extra = attempt.extra
    assert extra["method"] == "PEAP"
    assert extra["identity"] == "jdoe@corp.example"
    assert extra["certificate"]
    assert extra["credentials"] == 0            # nothing was guessed
    assert "certificate" in extra["note"]
    assert engine.session.stats.rogue_radius == 1
    assert any(entry.get("kind") == "rogue_radius" for entry in ap.history)
    kinds = {finding.kind for finding in engine.session.findings}
    assert "rogue_radius" in kinds


def test_rogue_radius_is_refused_on_a_psk_network(tmp_path):
    engine = _engine(tmp_path, ["rogue_radius"])
    ap = engine.session.ap("d0:9e:12:9d:36:cc")
    assert "rogue_radius" not in engine.attackable(ap)
    assert engine.run_attack(ap.bssid, "rogue_radius") is None


def test_rogue_radius_uses_the_certificate_the_survey_already_found(tmp_path):
    engine = _engine(tmp_path, ["rogue_radius", "enterprise"])
    ap = next(item for item in engine.session.aps.values()
              if (item.auth or "").upper() == "MGT")
    engine.run_attack(ap.bssid, "enterprise")          # records the survey first
    engine.session.findings.clear()
    attempt = engine.run_attack(ap.bssid, "rogue_radius")
    assert attempt is not None and attempt.status == "success"
    # the pre-check path turns the survey's certificate into the finding itself
    if attempt.result == "certificate policy is weak":
        assert "rogue_radius" in {finding.kind for finding in engine.session.findings}
    else:
        assert attempt.extra["certificate"]


# --------------------------------------------------------------------------- #
# the EAP / X.509 decoder
# --------------------------------------------------------------------------- #

def test_a_self_signed_certificate_is_detected(tmp_path):
    facts = x509_name(synth.self_signed_certificate())
    assert facts["self_signed"] is True
    assert "CN=radius.lab.local" in facts["subject"]
    assert facts["subject"] == facts["issuer"]
    assert facts["serial"] and facts["sha1"]


def test_a_properly_issued_certificate_is_not_flagged(tmp_path):
    facts = x509_name(synth.self_signed_certificate(issuer_cn="Corp Issuing CA",
                                                    issuer_org="Corp"))
    assert facts["self_signed"] is False
    assert "radius.lab.local" in facts["subject"]
    assert "Corp Issuing CA" in facts["issuer"]


def test_the_eap_exchange_decodes_method_identity_and_certificate(tmp_path):
    path, _ = synth.build_enterprise_capture(str(tmp_path / "ent.pcap"))
    report = eap_exchange(path)
    assert report["eapol"] == 2
    assert "Identity" in report["methods"] and "PEAP" in report["methods"]
    assert report["identities"] == ["jdoe@corp.example"]
    assert report["certificates"] and report["certificates"][0]["self_signed"] is True


def test_the_decoder_disagrees_with_a_good_certificate(tmp_path):
    path, _ = synth.build_enterprise_capture(
        str(tmp_path / "issued.pcap"),
        certificate=synth.self_signed_certificate(issuer_cn="Corp Issuing CA"))
    facts = eap_exchange(path)["certificates"][0]
    assert facts["self_signed"] is False
    assert "CN=Corp Issuing CA" in facts["issuer"]


def test_a_capture_without_eapol_is_reported_as_such(tmp_path):
    frames = [synth.build_beacon("BenchNet", "d0:9e:12:9d:36:cc")]
    frames += synth.build_deauth_flood("d0:9e:12:9d:36:cc", rounds=5)
    path = str(tmp_path / "no-eap.pcap")
    synth.write_pcap(path, frames)
    report = eap_exchange(path)
    assert report["eapol"] == 0 and report["methods"] == []


# --------------------------------------------------------------------------- #
# front ends
# --------------------------------------------------------------------------- #

def test_cli_decodes_an_exchange(tmp_path, capsys):
    from wifipilot.cli import main
    path, _ = synth.build_enterprise_capture(str(tmp_path / "ent.pcap"))
    assert main(["eap", path, "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "PEAP" in out and "jdoe@corp.example" in out and "self-signed" in out
    assert main(["--json", "eap", path]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["identities"] == ["jdoe@corp.example"]
    assert payload["certificates"][0]["self_signed"] is True


def test_cli_says_when_a_capture_has_no_8021x(tmp_path, capsys):
    from wifipilot.cli import main
    path = str(tmp_path / "plain.pcap")
    synth.write_pcap(path, [synth.build_beacon("BenchNet", "d0:9e:12:9d:36:cc")])
    assert main(["eap", path, "--no-color"]) == 1
    assert "no EAPOL" in capsys.readouterr().out


def test_the_library_exposes_the_decoder(tmp_path):
    import wifipilot as wp
    assert "eap" in wp.__all__
    path, _ = synth.build_enterprise_capture(str(tmp_path / "ent.pcap"))
    report = wp.eap(path)
    assert report["methods"] and report["certificates"][0]["subject"]
    with pytest.raises(wp.TargetError):
        wp.eap(str(tmp_path / "missing.pcap"))


def test_web_exposes_the_decoder(tmp_path):
    from fastapi.testclient import TestClient
    from wifipilot.web.app import create_app

    config = Config()
    config.demo = True
    config.ollama.enabled = False
    config.output_dir = str(tmp_path / "loot")
    config.session_dir = str(tmp_path / "sessions")
    client = TestClient(create_app(config, demo=True, authorized=True))
    assert client.get("/api/eap").status_code == 400          # nothing to read
    path, _ = synth.build_enterprise_capture(str(tmp_path / "ent.pcap"))
    response = client.get("/api/eap", params={"capture": path})
    assert response.status_code == 200
    assert response.json()["eap"]["certificates"][0]["self_signed"] is True
    assert client.get("/api/eap", params={"capture": "/nope.pcap"}).status_code == 400


# --------------------------------------------------------------------------- #
# plumbing the new attacks rely on
# --------------------------------------------------------------------------- #

def test_timeouts_and_client_following_are_configured():
    config = Config()
    assert config.client_mac == ""
    assert config.attack_timeout_for("rogue_radius") >= 120
    assert config.attack_timeout_for("tracker") >= 45


def test_client_signal_history_is_bounded_and_recorded():
    client = Client("02:00:00:00:00:09", "d0:9e:12:9d:36:cc")
    for reading in range(100, 200):
        client.remember_signal(-reading)
    assert len(client.signal_history) == 60
    assert client.signal_history[-1] == -199
    client.remember_signal(0)                     # a zero reading is not a reading
    assert len(client.signal_history) == 60


def test_the_scanner_keeps_probes_and_signal_history(tmp_path):
    from wifipilot.events import EventBus
    from wifipilot.session import Session

    config = Config()
    config.demo = True
    session = Session(config, EventBus(), demo=True)
    session.upsert_ap("d0:9e:12:9d:36:cc", "HOME-2F4A", publish=False)
    session.add_client("d0:9e:12:9d:36:cc", "02:00:00:00:00:09", signal=-44,
                       packets=3, probes=["HOME-2F4A", "CafeGuest"])
    session.add_client("d0:9e:12:9d:36:cc", "02:00:00:00:00:09", signal=-51, packets=9)
    ap = session.ap("d0:9e:12:9d:36:cc")
    client = ap.clients["02:00:00:00:00:09"]
    assert client.probes == ["HOME-2F4A", "CafeGuest"]
    assert client.signal_history == [-44, -51]
    assert session.stats.probing_clients == 1
    assert session.station("02:00:00:00:00:09") is client
    assert session.station("not-a-mac") is None
