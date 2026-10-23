#!/usr/bin/env python3
"""Hot-path microbenchmarks for wifipilot's optimization surface.

Run from the repository root::

    python3 scripts/bench.py

Each row is the median of three runs.  The numbers that matter are the
*ratios* against a checkout without the optimization in question — see
``docs/OPTIMIZATIONS.md`` for the catalogue and the before/after table.
"""
from __future__ import annotations

import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wifipilot.attacks import attack_catalog              # noqa: E402
from wifipilot.attacks.meta import meta_for               # noqa: E402
from wifipilot.config import Config, find_wordlists       # noqa: E402
from wifipilot.crypto import PmkidVerifier, compute_pmkid, pmk  # noqa: E402
from wifipilot.deps import registry                       # noqa: E402
from wifipilot.events import EK, EventBus                 # noqa: E402
from wifipilot.models import AccessPoint                  # noqa: E402
from wifipilot.planner import preferred_attacks           # noqa: E402
from wifipilot.util import mac_norm, oui_vendor            # noqa: E402


def bench(name: str, fn, n: int) -> None:
    samples = []
    for _ in range(3):
        started = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - started)
    print(f"{name:44s} {statistics.median(samples) * 1000:9.2f} ms  (x{n})")


def main() -> int:
    cfg = Config()
    cfg.demo = True                      # capabilities all-true: full ladder
    ap = AccessPoint(bssid="aa:bb:cc:11:22:33", essid="TestNet",
                     encryption="WPA2")
    bench("preferred_attacks x200",
          lambda: [preferred_attacks(ap, cfg) for _ in range(200)], 200)
    bench("config.to_dict x200",
          lambda: [cfg.to_dict() for _ in range(200)], 200)
    bench("config.to_dict(redact) x200",
          lambda: [cfg.to_dict(redact_secrets=True) for _ in range(200)], 200)
    bench("mac_norm x20000",
          lambda: [mac_norm("AA-BB-CC-11-22-33") for _ in range(20000)], 20000)
    bench("oui_vendor x20000",
          lambda: [oui_vendor("aa:bb:cc:11:22:33") for _ in range(20000)], 20000)
    bench("meta_for x5000",
          lambda: [meta_for("handshake") for _ in range(5000)], 5000)
    bench("attack_catalog x5",
          lambda: [attack_catalog() for _ in range(5)], 5)
    bench("find_wordlists x50",
          lambda: [find_wordlists(cfg) for _ in range(50)], 50)
    bench("registry.summary x20",
          lambda: [registry.summary() for _ in range(20)], 20)
    bus = EventBus()
    bench("bus.publish log x5000",
          lambda: [bus.publish(EK.LOG, {"message": "x"}) for _ in range(5000)],
          5000)
    hexid = compute_pmkid(pmk("password123", "SpeedNet"),
                          bytes.fromhex("aabbcc112233"),
                          bytes.fromhex("ffffffffffff"))
    verifier = PmkidVerifier(hexid, "SpeedNet", "aa:bb:cc:11:22:33",
                             "ff:ff:ff:ff:ff:ff")
    candidates = [f"wrongpass{i}" for i in range(300)]
    started = time.perf_counter()
    for candidate in candidates:
        verifier.check(candidate)
    elapsed = time.perf_counter() - started
    print(f"{'PmkidVerifier.check x300':44s} {elapsed * 1000:9.2f} ms  "
          f"({300 / elapsed:,.0f}/s, PBKDF2-bound)")

    # -- round 2: rules, events, models, session, crypto, parsing -------- #
    from wifipilot import hash22000, rules as rules_mod
    from wifipilot.analytics import password_report
    from wifipilot.bt import random_address_hash
    from wifipilot.models import Client
    from wifipilot.session import Session

    words = [f"baseword{i}" for i in range(2000)]
    rule_set = rules_mod.preset("best64")
    bench("apply_rules best64 x2000 words",
          lambda: [list(rules_mod.apply_rules(w, rule_set, limit=24))
                   for w in words], 2000)
    bench("Event.to_dict x5000",
          lambda: [e.to_dict() for _ in range(50) for e in bus.recent(100)],
          5000)
    rich_ap = AccessPoint(bssid="aa:bb:cc:11:22:33", essid="TestNet",
                          encryption="WPA2", signal=-42)
    for i in range(8):
        mac = f"02:00:00:00:00:{i:02x}"
        rich_ap.clients[mac] = Client(mac=mac, bssid=rich_ap.bssid)
    bench("AccessPoint.to_dict x2000",
          lambda: [rich_ap.to_dict() for _ in range(2000)], 2000)
    bench("AccessPoint.attackable x2000",
          lambda: [rich_ap.attackable() for _ in range(2000)], 2000)
    sess_bus = EventBus()
    for i in range(150):
        sess_bus.publish(EK.LOG, {"message": f"line {i}"})
    session = Session(cfg, sess_bus, demo=True)
    for i in range(12):
        other = AccessPoint(bssid=f"aa:bb:cc:11:22:{i:02x}", essid=f"Net{i}",
                            encryption="WPA2", signal=-40 - i)
        session.aps[other.bssid] = other
    session.snapshot()          # warm the caches the UI would have warm
    bench("session.snapshot x50 (12 APs)",
          lambda: [session.snapshot() for _ in range(50)], 50)
    hash_text = "\n".join(
        "WPA*01*%034x*%012x*%012x*%s***" % (i, 0xaabbcc112233,
                                            0xffffffffffff, "aa" * 4)
        for i in range(50))
    bench("hash22000.parse_text 50 lines x50",
          lambda: [hash22000.parse_text(hash_text) for _ in range(50)], 50)
    bench("password_report x1000",
          lambda: [password_report(f"Str0ng!Pass{i}") for i in range(1000)],
          1000)
    irk = bytes.fromhex("ec0234a357c8ad05341010a60a397d9b")
    bench("bt.random_address_hash x2000",
          lambda: [random_address_hash(irk, 0x708194) for _ in range(2000)],
          2000)
    from wifipilot import synth
    from wifipilot.pcap import analyze_file
    frames = [synth.build_beacon(f"Net{i % 20}", f"aa:bb:cc:00:00:{i % 20:02x}")
              for i in range(600)]
    pcap_path = synth.write_pcap("/tmp/wifipilot-bench.pcap", frames)
    bench("pcap analyze 600 beacons x10",
          lambda: [analyze_file(pcap_path, use_cache=False)
                   for _ in range(10)], 10)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
