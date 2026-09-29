"""The third attack batch: WPA3, the WEP family, the active PMKID hunt, the twin.

Everything the new attacks claim is checked here against captures this repository
builds itself: RSN elements, SAE exchanges, keystream files and the plans the
planner is willing to emit.  The one thing that is asserted as *false* everywhere is
that a WPA3-SAE capture is worth cracking offline — it is not, and a tool that
implied otherwise would be the most expensive kind of wrong.
"""

from __future__ import annotations

import pytest

from wifipilot import synth
from wifipilot.attacks import ATTACK_CLASSES, DEFAULT_ORDER, attack_catalog
from wifipilot.attacks.flood import BeaconFloodAttack, DeauthFloodAttack
from wifipilot.attacks.pmkid import PmkidFloodAttack
from wifipilot.attacks.twin import EvilTwinAttack
from wifipilot.attacks.wep import (WepChopchopAttack, WepFragmentAttack,
                                   WepHirteAttack, WepP0841Attack, keystream_file)
from wifipilot.attacks.wpa3 import SaeWolfAttack, pmf_from_capabilities
from wifipilot.config import Config
from wifipilot.engine import Engine
from wifipilot.models import ATTACK_NAMES, AccessPoint, Client
from wifipilot.planner import explain_failure, preferred_attacks, validate_plan
from wifipilot.session import Session
from wifipilot.events import EventBus
from wifipilot.wpa3 import capture_wpa3, rsn_from_ies, sae_exchange, wpa3_findings

#: the ten attacks this batch adds on top of the eleven already shipped
NEW_ATTACKS = ("saewolf", "pmf_audit", "evil_twin", "deauth_flood", "beacon_flood",
               "pmkid_flood", "wep_chopchop", "wep_fragment", "wep_hirte", "wep_p0841")


def _engine(tmp_path, attacks=None, timeout=2) -> Engine:
    config = Config()
    config.demo = True
    config.ollama.enabled = False
    config.output_dir = str(tmp_path / "loot")
    config.session_dir = str(tmp_path / "sessions")
    config.scan_time = 2
    config.attack_timeout = timeout          # every attack runs for two seconds
    config.use_masks = False
    config.attacks = list(attacks or NEW_ATTACKS)
    engine = Engine(config, demo=True)
    engine.prepare()
    engine.scan_for(2)
    return engine


def _ap(engine: Engine, essid: str) -> AccessPoint:
    for ap in engine.session.aps.values():
        if ap.essid == essid:
            return ap
    raise AssertionError(f"no {essid} in the demo neighbourhood")


@pytest.fixture(scope="module")
def wpa3_capture(tmp_path_factory):
    """One WPA3-only capture, built by this repository's own frame builder."""
    path = str(tmp_path_factory.mktemp("wpa3") / "sae-only.pcap")
    frames = synth.build_wpa3_capture(path, essid="Vodafone-9C31",
                                      bssid="f0:63:da:4a:c1:f5", akm="sae", pmf=True)
    return path, frames


# --------------------------------------------------------------------------- #
# the offline decoders (wifipilot/wpa3.py)
# --------------------------------------------------------------------------- #

def test_an_rsn_element_is_read_with_the_right_pmf_bits():
    rsn = rsn_from_ies(synth.rsn_element(akm="sae+psk", pmf=True))
    assert rsn is not None
    assert rsn.akm_names == ["SAE", "PSK"]
    assert rsn.sae and rsn.psk and rsn.transition_mode is True
    assert rsn.mfpc is True and rsn.mfpr is True
    # and a PSK-only element is not mistaken for one
    plain = rsn_from_ies(synth.rsn_element(akm="psk", pmf=False))
    assert plain.sae is False and plain.transition_mode is False
    assert plain.mfpc is False and plain.mfpr is False


def test_the_two_pmf_bits_have_their_own_positions():
    assert pmf_from_capabilities(0x0000) == {"mfpc": False, "mfpr": False}
    assert pmf_from_capabilities(0x0020) == {"mfpc": True, "mfpr": False}
    assert pmf_from_capabilities(0x0010) == {"mfpc": False, "mfpr": True}
    assert pmf_from_capabilities(0x0030) == {"mfpc": True, "mfpr": True}


def test_a_wpa3_capture_keeps_its_sae_and_pmf(wpa3_capture):
    path, _ = wpa3_capture
    data = capture_wpa3(path)
    assert data["networks"], "the builder writes at least one beacon"
    entry = data["networks"][0]
    assert entry["rsn"]["akm"] == ["SAE"]
    assert entry["rsn"]["mfpc"] and entry["rsn"]["mfpr"]
    assert entry["rsn"]["transition_mode"] is False


def test_the_sae_exchange_is_decoded_but_never_called_crackable(wpa3_capture):
    path, _ = wpa3_capture
    report = sae_exchange(path)
    assert report["auth_frames"] >= 3
    assert report["complete"] == 1
    group = report["exchanges"][0]["group"]
    assert "group 19" in group and "256-bit" in group
    # the whole point: a captured SAE exchange is not an offline attack target
    assert report["feasible_offline_attack"] is False


def test_transition_mode_and_owe_are_reported_as_findings(tmp_path):
    path = str(tmp_path / "mixed.pcap")
    synth.build_wpa3_capture(path, essid="KabelBox-4321", bssid="68:79:59:36:e3:40",
                             akm="sae+psk", pmf=False)
    kinds = {finding["kind"] for finding in wpa3_findings(
        capture_wpa3(path)["networks"])}
    assert "wpa3_transition" in kinds

    owe = str(tmp_path / "owe.pcap")
    synth.build_wpa3_capture(owe, essid="Lobby-Guest", bssid="34:c9:27:19:79:89",
                             akm="owe", pmf=True)
    kinds = {finding["kind"] for finding in wpa3_findings(
        capture_wpa3(owe)["networks"])}
    assert "owe_transition" in kinds


# --------------------------------------------------------------------------- #
# registration, and the planner's opinion of the new attacks
# --------------------------------------------------------------------------- #

def test_all_ten_new_attacks_are_registered_and_documented():
    for name in NEW_ATTACKS:
        assert name in ATTACK_CLASSES, name
        assert name in ATTACK_NAMES, name
        assert name in DEFAULT_ORDER, name
    catalog = {entry["name"]: entry for entry in attack_catalog()}
    assert len(catalog) == 21
    assert all(entry["label"] and entry["description"] and entry["tool"]
               for entry in catalog.values())
    # read-only first, disruptive last: the catalogue is a plan, not an inventory
    assert catalog["pmf_audit"]["needs_injection"] is False
    assert catalog["saewolf"]["needs_injection"] is False
    for name in ("pmkid_flood", "evil_twin", "deauth_flood", "beacon_flood"):
        assert catalog[name]["needs_injection"] is True
    # and exactly the six attacks Config() enables are marked as defaults
    defaults = {name for name, entry in catalog.items() if entry["default_enabled"]}
    assert defaults == set(Config().attacks)


def test_wpa3_targets_are_sent_to_the_audit_and_never_to_a_deauth():
    config = Config(demo=True)
    config.attacks = list(NEW_ATTACKS) + ["handshake", "pmkid"]
    ap = AccessPoint("f0:63:da:4a:c1:f5", "Vodafone-9C31", encryption="WPA3",
                     auth="SAE", sae=True, channel=100, signal=-61)
    plan = preferred_attacks(ap, config)
    assert "saewolf" in plan
    assert "handshake" not in plan and "pmkid" not in plan and "pmkid_flood" not in plan
    # WPA3-only is a configuration finding, not a cracking job
    assert "crack" not in plan


def test_the_pmf_audit_runs_once_per_target_and_never_again():
    config = Config(demo=True)
    config.attacks = ["pmf_audit", "handshake"]
    ap = AccessPoint("d0:9e:12:9d:36:cc", "HOME-2F4A", encryption="WPA2", auth="PSK",
                     channel=6, signal=-44)
    assert "pmf_audit" in preferred_attacks(ap, config)
    ap.pmf_checked = True
    assert "pmf_audit" not in preferred_attacks(ap, config)


def test_the_planner_reaches_for_the_active_pmkid_hunt_only_when_it_helps():
    config = Config(demo=True)
    config.attacks = ["pmkid", "pmkid_flood", "handshake"]
    quiet = AccessPoint("aa:bb:cc:dd:ee:01", "Quiet", encryption="WPA2", auth="PSK",
                        channel=6, signal=-50)
    assert "pmkid_flood" not in preferred_attacks(quiet, config)   # no client to move
    busy = AccessPoint("aa:bb:cc:dd:ee:02", "Busy", encryption="WPA2", auth="PSK",
                       channel=6, signal=-50)
    busy.clients = {"02:00:00:00:00:07": Client("02:00:00:00:00:07", busy.bssid)}
    assert "pmkid_flood" in preferred_attacks(busy, config)


def test_a_flood_is_never_scheduled_in_stealth_mode():
    config = Config(demo=True, stealth=True)
    config.attacks = ["deauth_flood", "beacon_flood", "handshake", "passive"]
    ap = AccessPoint("d0:9e:12:9d:36:cc", "HOME-2F4A", encryption="WPA2", auth="PSK",
                     channel=6, signal=-44)
    plan = preferred_attacks(ap, config)
    assert "deauth_flood" not in plan and "beacon_flood" not in plan


def test_the_twin_is_scheduled_last_and_only_for_a_named_psk_network():
    config = Config(demo=True)
    config.attacks = ["evil_twin", "handshake"]
    ap = AccessPoint("d0:9e:12:9d:36:cc", "HOME-2F4A", encryption="WPA2", auth="PSK",
                     channel=6, signal=-44)
    plan = preferred_attacks(ap, config)
    assert "evil_twin" in plan
    assert plan.index("evil_twin") > plan.index("handshake")


def test_the_plan_validator_drops_a_plan_that_does_not_make_sense():
    config = Config(demo=True)
    config.attacks = list(NEW_ATTACKS)
    session = Session(config, EventBus())
    psk = AccessPoint("d0:9e:12:9d:36:cc", "HOME-2F4A", encryption="WPA2", auth="PSK")
    wpa3 = AccessPoint("f0:63:da:4a:c1:f5", "Vodafone-9C31", encryption="WPA3",
                       auth="SAE", sae=True)
    enterprise = AccessPoint("3c:37:86:11:22:33", "CorpNet", encryption="ENTERPRISE",
                             auth="MGT")
    hidden = AccessPoint("8c:3f:fe:50:73:a6", "", encryption="WPA2", auth="PSK",
                         hidden=True)
    for ap in (psk, wpa3, enterprise, hidden):
        session.aps[ap.bssid] = ap
    plan = validate_plan({"actions": [
        {"attack": "saewolf", "bssid": psk.bssid},          # not WPA3
        {"attack": "pmkid_flood", "bssid": wpa3.bssid},     # SAE has no PSK PMKID
        {"attack": "wep_chopchop", "bssid": psk.bssid},     # not WEP
        {"attack": "evil_twin", "bssid": enterprise.bssid},  # needs rogue_radius
        {"attack": "evil_twin", "bssid": hidden.bssid},     # nothing to serve
        {"attack": "saewolf", "bssid": wpa3.bssid},         # this one is fine
        {"attack": "evil_twin", "bssid": psk.bssid},        # and so is this
    ]}, session, config)
    kept = {(action.attack, action.bssid) for action in plan.actions}
    assert kept == {("saewolf", wpa3.bssid), ("evil_twin", psk.bssid)}
    assert len(plan.dropped) == 5


def test_a_flood_in_a_plan_is_dropped_in_stealth_mode():
    config = Config(demo=True, stealth=True)
    config.attacks = ["deauth_flood"]
    session = Session(config, EventBus())
    ap = AccessPoint("d0:9e:12:9d:36:cc", "HOME-2F4A", encryption="WPA2", auth="PSK")
    session.aps[ap.bssid] = ap
    plan = validate_plan({"actions": [{"attack": "deauth_flood", "bssid": ap.bssid}]},
                         session, config)
    assert not plan.actions and "denial of service" in plan.dropped[0]


@pytest.mark.parametrize("name", NEW_ATTACKS)
def test_every_new_attack_explains_its_failure(name):
    text = explain_failure({"attack": name, "result": "failed", "detail": ""}, None)
    assert text and len(text) > 20


# --------------------------------------------------------------------------- #
# saewolf and pmf_audit, end to end in simulation mode
# --------------------------------------------------------------------------- #

def test_saewolf_captures_the_exchange_and_says_it_cannot_be_cracked(tmp_path):
    engine = _engine(tmp_path, ["saewolf", "pmf_audit"])
    ap = _ap(engine, "Vodafone-9C31")
    attempt = engine.run_attack(ap.bssid, "saewolf")
    assert attempt.status == "success"
    assert attempt.extra["complete"] == 1
    assert attempt.extra["offline_feasible"] is False          # SAE is a PAKE
    assert "group 19" in attempt.extra["group"] or "group 21" in attempt.extra["group"]
    assert engine.session.stats.sae_captures == 1
    assert any(entry["kind"] == "sae_capture" for entry in ap.history)
    assert any(cap.extra.get("sae") for cap in ap.captures)


def test_saewolf_will_not_run_against_a_ps_network(tmp_path):
    engine = _engine(tmp_path, ["saewolf"])
    psk = _ap(engine, "HOME-2F4A")
    module = SaeWolfAttack()
    assert module.applies(psk) is False
    assert engine.run_attack(psk.bssid, "saewolf") is None     # refused before the radio


def test_the_pmf_audit_reads_the_neighbourhood_once_and_marks_it(tmp_path):
    engine = _engine(tmp_path, ["pmf_audit"])
    ap = _ap(engine, "HOME-2F4A")
    first = engine.run_attack(ap.bssid, "pmf_audit")
    assert first.status == "success"
    assert first.extra["networks"]
    assert engine.session.stats.pmf_audits == 1
    assert ap.pmf_checked is True
    assert sum(1 for entry in engine.session.aps.values() if entry.pmf_checked) > 1

    findings = list(engine.session.findings)
    for other in list(engine.session.aps.values()):
        engine.run_attack(other.bssid, "pmf_audit")
    # reading the same neighbourhood eleven times does not raise eleven copies
    assert engine.session.findings == findings
    signature = [(f.kind, f.bssid, f.title) for f in findings]
    assert len(signature) == len(set(signature)), "the same finding was raised twice"
    assert any(f.kind == "no_pmf" for f in findings)      # the demo is WPA2-heavy


def test_the_audit_reports_transition_mode_from_the_beacons(tmp_path):
    engine = _engine(tmp_path, ["pmf_audit"])
    ap = _ap(engine, "KabelBox-4321")
    attempt = engine.run_attack(ap.bssid, "pmf_audit")
    assert attempt.status == "success"
    assert ap.sai and ap.pmf_checked
    assert any(finding.kind == "wpa3_transition" for finding in engine.session.findings)


# --------------------------------------------------------------------------- #
# the WEP family
# --------------------------------------------------------------------------- #

def test_the_wep_family_is_five_attacks_with_distinct_jobs():
    assert WepChopchopAttack.aireplay_args == ("-4",)
    assert WepFragmentAttack.aireplay_args == ("-5",)
    assert WepHirteAttack.aireplay_args == ("-7",)
    assert WepP0841Attack.aireplay_args[:3] == ("-2", "-p", "0841")
    assert WepChopchopAttack.uses_client is False
    assert WepFragmentAttack.uses_client is False
    assert WepHirteAttack.uses_client is True
    # only two of the five can reach the key on their own
    assert WepP0841Attack.reaches_key is True
    assert WepChopchopAttack.reaches_key is False
    assert WepFragmentAttack.reaches_key is False
    assert WepHirteAttack.reaches_key is False


@pytest.mark.parametrize("cls,expects_client", [
    (WepChopchopAttack, False), (WepFragmentAttack, False),
    (WepHirteAttack, True), (WepP0841Attack, True),
])
def test_the_aireplay_command_matches_the_technique(cls, expects_client):
    config = Config(demo=True)
    session = Session(config, EventBus())
    from wifipilot.attacks.base import AttackContext
    ctx = AttackContext(session=session, config=config, bus=session.bus, demo=True)
    ap = AccessPoint("d0:9e:12:9d:36:cc", "PRINTER-4F", encryption="WEP",
                     channel=3, signal=-70)
    command = cls()._aireplay_command(ctx, ap, "02:00:00:00:00:05")
    assert command[1:len(cls.aireplay_args) + 1] == list(cls.aireplay_args)
    assert ("-h" in command) is expects_client
    assert command[-1] == "mon0" and "--ignore-negative-one" in command


def test_a_keystream_file_is_recognised_from_aireplay_output(tmp_path):
    path = str(tmp_path / "keystream.xor")
    with open(path, "wb") as handle:
        handle.write(b"\x01" * 1500)
    lines = [f"Saving keystream in {path}", "some other line"]
    assert keystream_file(lines) == path
    assert keystream_file(["nothing to see"]) == ""


def test_the_enablers_report_capability_not_the_key(tmp_path):
    engine = _engine(tmp_path, ["wep_chopchop", "wep_ivs"])
    ap = _ap(engine, "PRINTER-4F")
    attempt = engine.run_attack(ap.bssid, "wep_chopchop")
    assert attempt.status == "success"
    assert attempt.extra["enables"] == "wep_ivs"
    assert attempt.extra["keystream_bytes"] > 0
    assert "keystream" in attempt.result
    assert engine.session.stats.wep_enablers == 1
    assert engine.session.stats.wep_cracks == 0        # it did not recover the key
    assert any(entry["kind"] == "wep_enabler" for entry in ap.history)


def test_p0841_harvests_and_does_reach_the_key(tmp_path):
    engine = _engine(tmp_path, ["wep_p0841"], timeout=6)
    ap = _ap(engine, "PRINTER-4F")
    attempt = engine.run_attack(ap.bssid, "wep_p0841")
    assert attempt.status == "success"
    assert engine.session.stats.wep_cracks == 1
    assert ap.cracked
    assert ap.password, "a WEP crack without a key is not a crack"


# --------------------------------------------------------------------------- #
# the active PMKID hunt
# --------------------------------------------------------------------------- #

def test_pmkid_flood_is_injection_gated_and_skips_a_target_it_already_won(tmp_path):
    module = PmkidFloodAttack()
    assert module.needs_injection is True
    engine = _engine(tmp_path, ["pmkid_flood"])
    ap = _ap(engine, "HOME-2F4A")
    from wifipilot.models import Capture
    ap.captures.append(Capture(kind="pmkid", bssid=ap.bssid, valid=True))
    attempt = engine.run_attack(ap.bssid, "pmkid_flood")
    assert attempt.status == "skipped"
    assert attempt.result == "PMKID already captured"
    assert ap.attempts[-1].status == "skipped"          # the record is closed


def test_pmkid_flood_wins_when_the_passive_attack_would_wait(tmp_path):
    engine = _engine(tmp_path, ["pmkid_flood", "pmkid"])
    ap = _ap(engine, "HOME-2F4A")
    attempt = engine.run_attack(ap.bssid, "pmkid_flood")
    assert attempt.status == "success"
    assert ap.has_pmkid
    assert engine.session.stats.pmkids >= 1


# --------------------------------------------------------------------------- #
# the twin
# --------------------------------------------------------------------------- #

def test_the_twin_uses_the_cracked_key_or_a_throwaway():
    machine = EvilTwinAttack()
    ap = AccessPoint("d0:9e:12:9d:36:cc", "HOME-2F4A", encryption="WPA2", auth="PSK")
    throwaway = machine._psk_for_twin(ap)
    assert len(throwaway) == 20 and not ap.cracked
    from wifipilot.models import Capture
    ap.captures.append(Capture(kind="handshake", bssid=ap.bssid, valid=True,
                               password="sunshine2015"))
    assert machine._psk_for_twin(ap) == "sunshine2015"


def test_the_twin_refuses_a_network_it_cannot_serve():
    machine = EvilTwinAttack()
    enterprise = AccessPoint("3c:37:86:11:22:33", "CorpNet", encryption="ENTERPRISE",
                             auth="MGT")
    hidden = AccessPoint("8c:3f:fe:50:73:a6", "", encryption="WPA2", auth="PSK")
    assert machine.applies(enterprise) is False
    assert machine.applies(hidden) is False
    assert machine.applies(AccessPoint("d0:9e:12:9d:36:cc", "HOME", auth="PSK")) is True


def test_the_twin_reports_who_prefers_the_ssid(tmp_path):
    engine = _engine(tmp_path, ["evil_twin"])
    ap = _ap(engine, "HOME-2F4A")
    attempt = engine.run_attack(ap.bssid, "evil_twin")
    assert attempt.status == "success"
    assert attempt.extra["station_count"] >= 1
    assert attempt.extra["psk_known"] is False          # the key is not cracked yet
    assert attempt.extra["note"].startswith("the twin is stopped")
    finding = [f for f in engine.session.findings if f.kind == "evil_twin"][0]
    assert finding.severity == "medium"
    assert "prefer" in finding.title.lower()
    assert engine.session.stats.twins_run == 1


def test_a_twin_with_the_key_known_is_a_high_severity_finding(tmp_path):
    from wifipilot.models import Capture
    engine = _engine(tmp_path, ["evil_twin"])
    ap = _ap(engine, "HOME-2F4A")
    ap.captures.append(Capture(kind="handshake", bssid=ap.bssid, valid=True,
                               password="sunshine2015"))
    attempt = engine.run_attack(ap.bssid, "evil_twin")
    assert attempt.status == "success"
    assert attempt.extra["psk_known"] is True
    finding = [f for f in engine.session.findings if f.kind == "evil_twin"][0]
    assert finding.severity == "high"
    assert "joined a twin" in finding.title


# --------------------------------------------------------------------------- #
# the floods
# --------------------------------------------------------------------------- #

def test_the_floods_are_capped_and_gated():
    assert DeauthFloodAttack.max_seconds == 60.0
    assert BeaconFloodAttack.max_seconds == 45.0
    assert DeauthFloodAttack.mode == "d" and BeaconFloodAttack.mode == "b"
    for module in (DeauthFloodAttack(), BeaconFloodAttack()):
        assert module.needs_injection is True
        assert module.warning and module.finding_title


def test_a_flood_is_unavailable_without_mdk4(tmp_path, monkeypatch):
    import wifipilot.attacks.flood as flood
    engine = _engine(tmp_path, ["deauth_flood"])
    ctx = engine.context()
    ctx.demo = False                       # a live run, without the demo excuses
    monkeypatch.setattr(flood.registry, "path", lambda name, *a, **k: None)
    module = DeauthFloodAttack()
    assert module.available(ctx) is False
    assert "mdk4" in module.unavailable_reason(ctx)
    # the simulated radio provides everything, so demo mode is unaffected
    ctx.demo = True
    assert module.available(ctx) is True


def test_a_deauth_flood_is_a_finding_about_the_site(tmp_path):
    engine = _engine(tmp_path, ["deauth_flood"])
    ap = _ap(engine, "HOME-2F4A")
    attempt = engine.run_attack(ap.bssid, "deauth_flood")
    assert attempt.status == "success"
    assert attempt.extra["frames"] > 1000               # thousands of frames/second
    assert attempt.extra["simulated"] is True
    assert "not a password" in attempt.extra["note"]
    finding = [f for f in engine.session.findings if f.kind == "deauth_flood"][0]
    assert finding.severity == "high"
    assert "802.11w" in finding.detail
    assert engine.session.stats.floods_run == 1


def test_a_beacon_flood_is_a_medium_finding(tmp_path):
    engine = _engine(tmp_path, ["beacon_flood"])
    ap = _ap(engine, "HOME-2F4A")
    attempt = engine.run_attack(ap.bssid, "beacon_flood")
    assert attempt.status == "success"
    assert attempt.extra["frames"] > 100
    finding = [f for f in engine.session.findings if f.kind == "beacon_flood"][0]
    assert finding.severity == "medium"
    assert engine.session.stats.floods_run == 1


# --------------------------------------------------------------------------- #
# the front ends
# --------------------------------------------------------------------------- #

def test_cli_accepts_every_new_attack_and_lists_them_in_help(capsys):
    from wifipilot import cli
    parser = cli.build_parser()
    args = parser.parse_args(["--demo", "attack", "--attacks", ",".join(NEW_ATTACKS)])
    assert args.attacks == ",".join(NEW_ATTACKS)
    assert set(NEW_ATTACKS) <= set(cli.ATTACK_NAMES)

    with pytest.raises(SystemExit):
        cli.main(["--demo", "attack", "--help"])
    text = capsys.readouterr().out
    assert "evil_twin" in text and "saewolf" in text and "deauth_flood" in text
    assert "twin-interface" in text

    # an unknown name is refused with the list of the ones that exist
    code = cli.main(["--demo", "--no-ai", "attack", "--attacks", "saewolf,nope"])
    assert code == 2
    err = capsys.readouterr().err
    assert "unknown attack type(s)" in err and "pmkid_flood" in err


def test_the_web_front_end_serves_the_new_catalog(tmp_path):
    from wifipilot.web.app import create_app
    engine = _engine(tmp_path, NEW_ATTACKS)
    app = create_app(engine.config)
    routes = {route.path for route in app.routes}
    assert "/api/state" in routes and "/api/attack" in routes
    catalog = engine.snapshot()["attacks"]
    names = {entry["name"] for entry in catalog}
    assert set(NEW_ATTACKS) <= names
    assert len(catalog) == 21
    assert all("available" in entry and "enabled" in entry for entry in catalog)
    # the toggle state the UI shows is the config's own list, nothing else
    assert all(entry["enabled"] == (entry["name"] in engine.config.attacks)
               for entry in catalog)
    assert engine.snapshot()["capabilities"]["mdk4"] in (True, False)


def test_the_new_counters_exist_on_the_session_stats(tmp_path):
    engine = _engine(tmp_path, ["pmf_audit"])
    stats = engine.session.stats
    for field in ("sae_captures", "pmf_audits", "twins_run", "floods_run",
                  "wep_enablers"):
        assert hasattr(stats, field) and getattr(stats, field) == 0
    payload = stats.to_dict()
    assert all(field in payload for field in
               ("sae_captures", "pmf_audits", "twins_run", "floods_run", "wep_enablers"))


def test_force_mode_really_means_every_attack_the_build_ships():
    import wifipilot as wp
    assert set(wp.MODES["force"]["attacks"]) == set(DEFAULT_ORDER)
    assert wp.ALL_ATTACKS == list(DEFAULT_ORDER)      # one source of truth
    assert wp.MODES["force"]["wps_pin"] is True
    assert "pmf_audit" in wp.MODES["passive"]["attacks"]    # read-only, so safe there


def test_the_twin_interface_is_configurable(tmp_path):
    config = Config(demo=True, twin_interface="wlan1")
    assert config.twin_interface == "wlan1"
    # and the CLI can set it without exposing anything else
    from wifipilot import cli
    parser = cli.build_parser()
    args = parser.parse_args(["--demo", "attack", "--twin-interface", "wlan9"])
    assert args.twin_interface == "wlan9"
