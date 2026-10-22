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
