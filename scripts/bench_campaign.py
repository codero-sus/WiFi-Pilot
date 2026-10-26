"""Seeded end-to-end campaign benchmark: wall-clock per preset.

Unlike scripts/bench.py (micro-benchmarks of hot functions), this runs
whole demo campaigns against a fixed-seed neighbourhood so run-to-run
numbers are comparable: discovery time, campaign-loop dead air, crack
scheduling — the seconds a real run feels.  Demo "radio time" inside
attacks stands in for live tool time, so treat the *ratio* between
commits as the signal, not the absolute seconds.

Usage: python scripts/bench_campaign.py [preset ...]   (default: blitz)
"""
import importlib
import sys
import time
from collections import Counter

e_mod = importlib.import_module("wifipilot.engine")
demo_mod = importlib.import_module("wifipilot.demo")
_real = demo_mod.DemoRadio
e_mod.DemoRadio = lambda verbose=False: _real(seed=42, verbose=verbose)

import wifipilot as wp

for preset in sys.argv[1:] or ["blitz"]:
    t0 = time.time()
    run = wp.attack(target="all", preset=preset, demo=True, background=True)
    run.wait(timeout=600)
    sess = wp.engine().session
    keys = Counter((a.attack, a.bssid) for a in sess.attempts)
    dupes = {k: v for k, v in keys.items() if v > 1}
    cracked_aps = sum(1 for ap in sess.aps.values() if ap.cracked)
    print(f"seed42 {preset}: wall={time.time()-t0:.1f}s passwords={len(run.passwords)} "
          f"loot={len(run.loot)} attempts={len(sess.attempts)} "
          f"aps={len(sess.aps)} cracked_aps={cracked_aps} dupes={dupes or 'NONE'} "
          f"error={run.error!r}", flush=True)
