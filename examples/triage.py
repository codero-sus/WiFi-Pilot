#!/usr/bin/env python3
"""Reconnaissance only: survey a neighbourhood and write a report.

    sudo python3 examples/triage.py wlan0          # live, listen-only
    python3 examples/triage.py --demo              # no radio needed

Nothing here transmits: `scan()` only listens, so no authorisation is needed.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))   # runnable from a checkout
import wifipilot as wp                                          # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="survey access points with wifipilot")
    parser.add_argument("interface", nargs="?", default="", help="wireless interface (live mode)")
    parser.add_argument("--demo", action="store_true", help="simulate a neighbourhood")
    parser.add_argument("-t", "--time", default="20", help="scan window, e.g. 20, 45s, 2m")
    parser.add_argument("--min-signal", type=int, default=-85, help="ignore weaker than this (dBm)")
    parser.add_argument("-o", "--report", default="", help="write the survey to this JSON file")
    args = parser.parse_args()

    wp.configure(interface=args.interface, demo=args.demo, provider="none")

    window = args.time if str(args.time).endswith(("s", "m", "h")) else f"{args.time}s"
    print(f"scanning for {window}{' (simulation)' if args.demo else ''} …")
    survey = wp.scan(duration=args.time)

    rows = [ap for ap in survey.strongest() if ap.signal >= args.min_signal]
    print(f"\n{len(rows)} access point(s) at or above {args.min_signal} dBm\n")
    print(f"{'SSID':<26} {'BSSID':<18} {'CH':>3} {'dBm':>5}  security")
    print("-" * 78)
    for ap in rows:
        security = ap.encryption or "OPEN"
        if ap.sae:
            security += " (WPA3-SAE)"
        if ap.wps:
            security += " · WPS" + (" locked" if ap.wps_locked else "")
        if ap.pmf:
            security += " · PMF"
        print(f"{(ap.essid or '(hidden)')[:25]:<26} {ap.bssid:<18} {ap.channel:>3} "
              f"{ap.signal:>5}  {security}")

    if args.report:
        path = survey.save(args.report)
        print(f"\nsurvey written to {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
