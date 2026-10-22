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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
