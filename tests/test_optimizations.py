"""The 200-optimizations sweep: behaviour-equivalence guards.

Every cache and fast path added in the sweep must return exactly what the
un-optimised code returned — these tests pin the equivalences (and the copy
isolation that makes caching safe), so a future "speedup" that changes an
answer fails here instead of in the field.  Timings themselves are *not*
asserted (CI hardware varies); see ``scripts/bench.py`` for the numbers and
``docs/OPTIMIZATIONS.md`` for the catalogue.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import asdict

from wifipilot.config import Config
from wifipilot.crypto import (PmkidVerifier, compute_pmkid, pmk, prf512)
from wifipilot.deps import ToolRegistry, list_interfaces
from wifipilot.events import EK, EventBus
from wifipilot.models import AccessPoint
from wifipilot.planner import preferred_attacks
from wifipilot.util import (append_jsonl, mac_norm, oui_vendor, platform_info)


# --------------------------------------------------------------- config ----

def test_fast_to_dict_matches_asdict_reference():
    cfg = Config()
    cfg.openrouter.api_key = "sk-secret"
    fast = cfg.to_dict()
    ref = asdict(cfg)
    ref.pop("_timeout_cache", None)
    # every real dataclass field matches asdict exactly; to_dict may add
    # derived pseudo-keys (ai_disabled, ai_provider_resolved, ...)
    assert {k: fast[k] for k in ref} == ref
    assert set(ref) <= set(fast)


def test_fast_to_dict_redacts_and_isolates_provider_dicts():
    cfg = Config()
    cfg.openrouter.api_key = "sk-secret"
    data = cfg.to_dict(redact_secrets=True)
    assert data["openrouter"]["api_key"] == ""
    assert cfg.openrouter.api_key == "sk-secret"          # original untouched
    data["ollama"]["model"] = "mutated"
    assert cfg.to_dict()["ollama"]["model"] != "mutated"   # fresh dicts per call


# ----------------------------------------------------------------- meta ----

def test_meta_for_is_copy_isolated():
    from wifipilot.attacks.meta import meta_for
    one = meta_for("pmkid")
    one["noise"] = "MUTATED"
    assert meta_for("pmkid")["noise"] != "MUTATED"
    overridden = meta_for("pmkid", noise="quiet")
    assert overridden["noise"] == "quiet"
    assert meta_for("pmkid")["noise"] != "quiet"


def test_attack_catalog_cached_copy_isolation():
    from wifipilot.attacks import attack_catalog
    first = attack_catalog()
    assert len(first) == 848
    first[0]["name"] = "MUTATED"
    first[0]["devices"].append("MUTATED")
    second = attack_catalog()
    assert second[0]["name"] != "MUTATED"
    assert "MUTATED" not in second[0]["devices"]


# ----------------------------------------------------------------- util ----

def test_mac_norm_and_oui_vendor_cached_results_are_stable():
    assert mac_norm("AA-BB-CC-11-22-33") == mac_norm("aa:bb:cc:11:22:33") \
        == "aa:bb:cc:11:22:33"
    assert mac_norm("not a mac") == mac_norm("not a mac")
    assert oui_vendor("00:0c:29:aa:bb:cc") == oui_vendor("00:0C:29:AA:BB:CC")
    assert oui_vendor("zz:zz:zz:00:00:00") == oui_vendor("zz:zz:zz:00:00:00")


def test_platform_info_copy_isolated():
    info = platform_info()
    info["os"] = "MUTATED"
    assert platform_info()["os"] != "MUTATED"


def test_append_jsonl_cached_handles_write_valid_lines(tmp_path):
    path = str(tmp_path / "sub" / "log.jsonl")
    for i in range(50):
        append_jsonl(path, {"n": i})
    lines = open(path, encoding="utf-8").read().strip().splitlines()
    assert [json.loads(line)["n"] for line in lines] == list(range(50))


# --------------------------------------------------------------- crypto ----

def _prf512_reference(key: bytes, label: bytes, data: bytes) -> bytes:
    out, counter = b"", 0
    while len(out) < 64:
        out += hmac.new(key, label + b"\x00" + data + bytes([counter]),
                        hashlib.sha1).digest()
        counter += 1
    return out[:64]


def test_prf512_template_fast_path_is_bit_identical():
    for key_len in (16, 32, 64, 80):            # incl. >64 (key re-hash path)
        key = bytes(range(key_len))
        assert prf512(key, b"label", b"data" * 8) == \
            _prf512_reference(key, b"label", b"data" * 8)


def test_verifier_salt_fast_path_roundtrip_and_guards():
    ap = bytes.fromhex("aabbcc112233")
    sta = bytes.fromhex("ffffffffffff")
    hexid = compute_pmkid(pmk("password123", "SpeedNet"), ap, sta)
    verifier = PmkidVerifier(hexid, "SpeedNet", "aa:bb:cc:11:22:33",
                             "ff:ff:ff:ff:ff:ff")
    assert verifier.usable
    assert verifier.check("password123")
    assert not verifier.check("password124")
    assert not verifier.check("short")                    # WPA length guard
    assert not verifier.check("x" * 64)


# --------------------------------------------------------------- events ----

def test_eventbus_bounded_history_keeps_latest():
    bus = EventBus(history=10)
    for i in range(25):
        bus.publish(EK.LOG, {"message": str(i)})
    recent = bus.recent(100)
    assert len(recent) == 10
    assert [e.seq for e in recent] == list(range(16, 26))
    assert bus.last_seq == 25
    assert [e.seq for e in bus.since(22)] == [23, 24, 25]


# ----------------------------------------------------------------- deps ----

def test_registry_summary_cached_but_isolated():
    registry = ToolRegistry()
    first = registry.summary()
    assert {"tools", "capabilities", "missing_required", "interfaces",
            "platform", "install_command"} <= set(first)
    first["tools"]["MUTATED"] = {}
    assert "MUTATED" not in registry.summary()["tools"]
    caps = registry.capabilities()
    caps["MUTATED"] = True
    assert "MUTATED" not in registry.capabilities()


def test_list_interfaces_cache_hits_on_empty_result():
    one = list_interfaces()
    two = list_interfaces()
    assert one is two          # same cached object within the TTL


# --------------------------------------------------------------- engine ----

def test_engine_attackable_cache_matches_planner_and_invalidates():
    from wifipilot.engine import Engine
    from wifipilot.models import STATUS_FAILED
    cfg = Config()
    cfg.demo = True          # capabilities all-true: a non-empty ladder
    engine = Engine(cfg, demo=True)
    ap = AccessPoint(bssid="aa:bb:cc:11:22:33", essid="CafeWifi",
                     encryption="WPA2")
    assert engine.attackable(ap) == preferred_attacks(ap, engine.config)
    assert engine.attackable(ap), "demo ladder must be non-empty"
    # a new attempt changes the fingerprint -> a fresh plan is computed
    from wifipilot.models import Attempt
    ap.attempts.append(Attempt(attack="pmkid", bssid=ap.bssid,
                                status=STATUS_FAILED))
    assert engine.attackable(ap) == preferred_attacks(ap, engine.config)
    # and a changed config list is honoured too
    cfg.attacks = ["handshake"]
    assert engine.attackable(ap) == preferred_attacks(ap, cfg) == ["handshake"]


def test_preferred_attacks_wpa2_ladder_head_unchanged():
    cfg = Config()
    cfg.demo = True
    ap = AccessPoint(bssid="aa:bb:cc:11:22:33", essid="CafeWifi",
                     encryption="WPA2")
    order = preferred_attacks(ap, cfg)
    assert order[0] == "pmkid"
    assert "handshake" in order
    assert os.environ.get("PYTEST_CURRENT_TEST")  # sanity: under pytest


# ------------------------------------------------------------- round 2 ----

def test_rule_engines_agree_everywhere():
    """The string fast path must equal the list reference engine, always."""
    from wifipilot import rules as rules_mod
    commands = [":", "l", "u", "c", "C", "t", "T0", "T3", "T9", "T", "r", "d",
                "f", "{", "}", "$1", "$xyz", "^9", "^ab", "[", "]", "D0", "D2",
                "D9", "x02", "x13", "x", "x1", "O11", "O02", "i2X", "i0!",
                "i1", "sa@", "so0", "s", "sa", "@a", "@", "p2", "p0", "p",
                "'4", "'0", "z", "Z", "q", "k", "K", "*02", "*20", "*99",
                "*11", "<5", ">3", "!a", "/z", "Q", "~"]
    words = ["", "a", "Ab", "password", "P@ss W0rd!", "ääÖü", "a" * 30,
             "0123456789", "ßeta", "İstanbul", "x"]
    for command in commands:
        step = rules_mod._compile(command)
        for word in words:
            want = rules_mod._step_c(step, list(word))
            want = None if want is None else "".join(want)
            assert rules_mod._apply_str(word, (step,)) == want, (command, word)
    for name in ("best64", "leet", "append-digits", "case"):
        for rule in rules_mod.preset(name):
            for word in words:
                letters = list(word)
                for step in rule._steps:
                    letters = rules_mod._step_c(step, letters)
                    if letters is None:
                        break
                want = None if letters is None else "".join(letters)
                assert rule.apply(word) == want, (name, rule.text, word)


def test_event_to_dict_timestamps_are_the_events_own():
    from datetime import datetime, timezone
    bus = EventBus()
    event = bus.publish(EK.LOG, {"message": "x"})
    first = event.to_dict()
    # iso is the event's time, not the moment someone serialised it
    parsed = datetime.fromisoformat(first["iso"]).astimezone(timezone.utc)
    assert abs(parsed.timestamp() - event.ts) < 1.0
    assert event.to_dict()["time"] == first["time"]
    assert event.to_dict()["iso"] == first["iso"]


def test_session_stats_fast_to_dict_matches_asdict():
    from wifipilot.models import SessionStats
    stats = SessionStats()
    stats.handshakes, stats.pmkids, stats.llm_cost = 3, 2, 0.37
    fast = stats.to_dict()
    ref = asdict(stats)
    assert {k: fast[k] for k in ref if k != "started"} == \
        {k: v for k, v in ref.items() if k != "started"}
    assert fast["loot"] == 5
    assert abs(fast["uptime"] - round(stats.uptime, 1)) < 0.2


def test_capture_and_finding_created_matches_created_ts():
    from datetime import datetime, timezone
    from wifipilot.models import Capture, Finding
    cap = Capture(kind="pmkid", bssid="aa:bb:cc:11:22:33")
    data = cap.to_dict()
    parsed = datetime.fromisoformat(data["created"]).astimezone(timezone.utc)
    assert abs(parsed.timestamp() - data["created_ts"]) < 1.0
    finding = Finding(kind="note", title="t")
    fdata = finding.to_dict()
    parsed = datetime.fromisoformat(fdata["created"]).astimezone(timezone.utc)
    assert abs(parsed.timestamp() - fdata["created_ts"]) < 1.0


def test_ap_attackable_cache_and_invalidation():
    from wifipilot.models import Capture, Client
    ap = AccessPoint(bssid="aa:bb:cc:11:22:33", essid="CafeWifi",
                     encryption="WPA2")
    first = ap.attackable()
    assert "pmkid" in first and "pmkid_flood" not in first   # no clients yet
    assert ap.attackable() == first                          # cached copy
    ap.clients["02:00:00:00:00:01"] = Client(mac="02:00:00:00:00:01",
                                             bssid=ap.bssid)
    assert "pmkid_flood" in ap.attackable()                  # fingerprint moved
    ap.captures.append(Capture(kind="pmkid", bssid=ap.bssid, valid=True))
    assert "pmkid" not in ap.attackable()                    # already have one
    subset = ap.attackable(["handshake", "ie_audit"])
    assert subset == ["ie_audit", "handshake"]


def test_aes_cached_key_expansion_still_fips_exact():
    from wifipilot.crypto import AES
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plain = bytes.fromhex("00112233445566778899aabbccddeeff")
    cipher = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    assert AES(key).encrypt_block(plain) == cipher
    assert AES(key).encrypt_block(plain) == cipher   # shared expansion
    assert AES(key).decrypt_block(cipher) == plain


def test_vendor_key_resolution_unchanged():
    from wifipilot.vendors import _key_for
    assert _key_for("AVM GmbH") == "AVM"
    assert _key_for("TP-Link") == "TP-Link"
    assert _key_for("linksys") == "Linksys"      # exact key beats stale alias
    assert _key_for("NETGEAR Inc.") == "Netgear"
    assert _key_for("No Such Vendor") == ""
    assert _key_for("") == ""


def test_password_classes_single_pass_matches_reference():
    from wifipilot.analytics import _charset_size, _class_flags, password_report
    for pw in ["password", "Str0ng!Pass", "12345678", "ALLCAPS", "ßetaÜber1",
               "中文密码abc1", "", "a", "!!!!!!!!", "ǅtitle1", "mix3d!Case9"]:
        ref = (any(c.islower() for c in pw), any(c.isupper() for c in pw),
               any(c.isdigit() for c in pw), any(not c.isalnum() for c in pw))
        assert _class_flags(pw) == ref, pw
        size = (26 if ref[0] else 0) + (26 if ref[1] else 0) \
            + (10 if ref[2] else 0) + (33 if ref[3] else 0)
        assert _charset_size(pw) == (size or 1), pw
    assert password_report("Str0ng!Pass").classes == "luds"
    assert password_report("").classes == "?"


def test_model_listing_failures_are_negative_cached(monkeypatch):
    """A downed daemon must not be re-polled on every status() call."""
    from wifipilot.config import OllamaConfig
    from wifipilot.llm import LLMError, OllamaClient
    client = OllamaClient(OllamaConfig())
    calls = {"n": 0}

    def boom(*args, **kwargs):
        calls["n"] += 1
        raise LLMError("connection refused")

    monkeypatch.setattr(client, "_request", boom)
    assert client.list_models() == []
    assert client.list_models() == []
    assert calls["n"] == 1                       # second call served by cache
    assert client.list_models(force=True) == []
    assert calls["n"] == 2                       # force still retries


# ----------------------------------------------------- wall-clock round ----
# The "seconds, not microseconds" sweep: dead air in the campaign loop
# (echo rounds, scan-window sleeps, re-cracked captures, snapshot target
# filters).  End-to-end numbers: scripts/bench_campaign.py.

def _wc_ap(session, bssid="aa:bb:cc:dd:ee:01", essid="HardNet"):
    ap, _ = session.upsert_ap(bssid, essid, publish=False)
    ap.encryption = "WPA2"
    ap.privacy = "WPA2"
    ap.cipher = "CCMP"
    ap.auth = "PSK"
    ap.signal = -50
    ap.channel = 6
    return ap


def test_plan_completed_tracks_attempt_outcomes(session):
    from wifipilot.models import Attempt
    from wifipilot.planner import Action, Plan, plan_completed

    ap = _wc_ap(session)
    action = Action(attack="handshake", bssid=ap.bssid)
    plan = Plan(actions=[action])
    assert not plan_completed(session, plan)            # never attempted
    assert not plan_completed(session, None)
    assert not plan_completed(session, Plan(actions=[]))
    assert not plan_completed(session, Plan(actions=[Action(attack="stop", bssid=ap.bssid)]))

    attempt = Attempt(attack="handshake", bssid=ap.bssid)
    ap.attempts.append(attempt)
    assert not plan_completed(session, plan)            # still running
    attempt.status = "success"
    assert plan_completed(session, plan)                # finished -> exhausted


def test_crack_worth_trying_budget_semantics():
    from wifipilot.models import Capture
    from wifipilot.planner import crack_worth_trying

    def cap(**kw):
        base = dict(kind="handshake", bssid="aa:bb:cc:dd:ee:01", path="/tmp/x.cap")
        base.update(kw)
        return Capture(**base)

    assert crack_worth_trying(cap(), 600)                       # fresh loot
    assert not crack_worth_trying(cap(password="hunter2"), 600)
    assert not crack_worth_trying(cap(kind="wep_ivs"), 600)
    assert not crack_worth_trying(cap(path=""), 600)            # nothing on disk
    assert not crack_worth_trying(cap(extra={"crack_queued": True}), 600)
    tried = cap(extra={"crack_tried_timeout": 180.0})
    assert crack_worth_trying(tried, 600)                       # quick pass only
    assert not crack_worth_trying(tried, 180)                   # budget spent
    assert not crack_worth_trying(cap(extra={"crack_tried_timeout": 600.0}), 600)
    assert crack_worth_trying(cap(extra={"crack_tried_timeout": 600.0}), 3600)


def test_prune_excludes_running_succeeded_and_twice_failed(session):
    from wifipilot.models import Attempt
    from wifipilot.planner import _prune

    ap = _wc_ap(session)
    ap.attempts.append(Attempt(attack="ie_audit", bssid=ap.bssid))          # running
    done = Attempt(attack="pmf_audit", bssid=ap.bssid)
    done.status = "success"
    ap.attempts.append(done)
    for _ in range(2):
        failed = Attempt(attack="deauth", bssid=ap.bssid)
        failed.status = "failed"
        ap.attempts.append(failed)
    once = Attempt(attack="handshake", bssid=ap.bssid)
    once.status = "failed"
    ap.attempts.append(once)

    kept = _prune(["ie_audit", "pmf_audit", "deauth", "handshake", "pmkid"], ap)
    assert kept == ["handshake", "pmkid"]


def test_planner_respects_campaign_scope(session, config):
    from wifipilot.models import Capture
    from wifipilot.planner import heuristic_plan, rank_targets

    wanted_ap = _wc_ap(session, "aa:bb:cc:dd:ee:02", "InScope")
    other_ap = _wc_ap(session, "aa:bb:cc:dd:ee:03", "OutOfScope")
    for ap in (wanted_ap, other_ap):
        ap.captures.append(Capture(kind="handshake", bssid=ap.bssid,
                                   valid=True, path="/tmp/x.cap"))
    ranked = rank_targets(session, config, wanted={wanted_ap.bssid})
    assert [ap.bssid for ap, _, _ in ranked] == [wanted_ap.bssid]
    plan = heuristic_plan(session, config, wanted={wanted_ap.bssid})
    assert plan.actions
    assert {a.bssid for a in plan.actions} == {wanted_ap.bssid}


def test_failed_crack_is_not_renominated_at_same_budget(session, config):
    from wifipilot.models import Capture
    from wifipilot.planner import preferred_attacks

    config.crack_timeout = 600
    ap = _wc_ap(session)
    capture = Capture(kind="handshake", bssid=ap.bssid, valid=True, path="/tmp/x.cap")
    ap.captures.append(capture)
    assert "crack" in preferred_attacks(ap, config)             # fresh loot

    capture.extra["crack_tried_timeout"] = 180.0                # quick pass ran
    assert "crack" in preferred_attacks(ap, config)             # full run still due

    capture.extra["crack_tried_timeout"] = 600.0                # full budget spent
    assert "crack" not in preferred_attacks(ap, config)         # no re-crack loop

    ap.captures.append(Capture(kind="pmkid", bssid=ap.bssid,    # fresh loot reopens
                               valid=True, path="/tmp/y.cap"))
    assert "crack" in preferred_attacks(ap, config)


def test_cracker_stamps_budget_on_failure(tmp_path, session):
    from wifipilot.crack import Cracker
    from wifipilot.models import Capture
    from wifipilot.synth import build_capture
    from tests.conftest import AP_MAC, SSID, STA_MAC

    path = str(tmp_path / "hard.pcap")
    build_capture(path, SSID, AP_MAC, STA_MAC, "xQ9zvL2mR8kW")  # underivable PSK
    junk = tmp_path / "junk.txt"
    junk.write_text("password123\nletmein2024\nqwertyuiop\n")
    ap = _wc_ap(session, AP_MAC, SSID)
    capture = Capture(kind="handshake", bssid=AP_MAC, essid=SSID, path=path, valid=True)
    ap.captures.append(capture)

    cracker = Cracker(session, session.config, session.bus, demo=False)
    # a 3 s budget exercises the same stamp path as 25 s did, in 3 s
    result = cracker.crack_capture(ap, capture, wordlists=[str(junk)], timeout=3)
    assert not result.cracked
    assert capture.extra.get("crack_tried_timeout") == 3.0      # failure is remembered

    nofile = Capture(kind="handshake", bssid=AP_MAC, essid=SSID)
    result = cracker.crack_capture(ap, nofile, wordlists=[str(junk)], timeout=25)
    assert not result.cracked
    assert "crack_tried_timeout" not in nofile.extra            # no run happened


def test_scan_for_exits_early_when_neighbourhood_settles(config, monkeypatch):
    import time as _time

    from wifipilot.demo import DemoRadio
    from wifipilot.engine import Engine

    # Seed the demo world (same trick as scripts/bench_campaign.py): with a
    # random neighbourhood the last AP can legitimately arrive late and the
    # wall-clock bound below turns into a coin flip on loaded CI runners.
    # NB: importlib, not a dotted path — ``wifipilot.engine`` the package
    # attribute is the public ``wp.engine()`` *function*, not the module.
    import importlib

    engine_module = importlib.import_module("wifipilot.engine")
    monkeypatch.setattr(engine_module, "DemoRadio",
                        lambda verbose=False: DemoRadio(seed=42, verbose=verbose))
    engine = Engine(config, demo=True)
    started = _time.time()
    engine.scan_for(20.0)
    elapsed = _time.time() - started
    assert engine.session.aps                                   # found the demo world
    assert elapsed < 16.0, f"discovery took {elapsed:.1f}s of a 20s window"


def test_run_attack_refuses_concurrent_duplicate(config):
    from wifipilot.engine import Engine

    engine = Engine(config, demo=True)
    ap, _ = engine.session.upsert_ap("aa:bb:cc:dd:ee:09", "BusyNet", publish=False)
    engine._inflight.add((ap.bssid, "ie_audit"))
    assert engine.run_attack(ap.bssid, "ie_audit") is None      # already running
    assert not engine.session.attempts                          # nothing started
    assert (ap.bssid, "ie_audit") in engine._inflight           # foreign key kept
