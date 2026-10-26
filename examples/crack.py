#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Offline cracking: point wifipilot at captures and a wordlist, get plaintext.

    python3 examples/crack.py loot/*.cap  -w /usr/share/wordlists/rockyou.txt

No radio and no authorisation are involved: this only processes files you
already own.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))   # runnable from a checkout
import wifipilot as wp                                          # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="crack captures with wifipilot")
    parser.add_argument("captures", nargs="+", help=".cap/.pcap/.pcapng/.hc22000 files")
    parser.add_argument("-w", "--wordlist", action="append", default=[],
                        help="wordlist (repeatable; defaults to the configured ones)")
    parser.add_argument("-e", "--essid", default="", help="SSID (helps the targeted pass)")
    parser.add_argument("-b", "--bssid", default="", help="BSSID (optional)")
    parser.add_argument("-t", "--timeout", type=float, default=300.0, help="seconds per capture")
    args = parser.parse_args()

    wp.configure(wordlist=args.wordlist or None)

    found = 0
    for capture in args.captures:
        if not Path(capture).exists():
            print(f"  {capture}: not found", file=sys.stderr)
            continue

        info = wp.analyze(capture)
        kind = ("handshake" if info["has_handshake"]
                else "pmkid" if info["has_pmkid"]
                else "wep" if info["wep_data"] > 5000 else "nothing usable")
        print(f"\n{capture}")
        print(f"  {info['packets']:,} packets · {info['eapol']} EAPOL · "
              f"{len(info['handshakes'])} handshake(s) · {len(info['pmkids'])} PMKID(s) · {kind}")
        if info["essids"]:
            print("  networks:", ", ".join(f"{ssid} ({bssid})"
                                           for bssid, ssid in info["essids"].items()))

        if kind == "nothing usable":
            print("  → nothing to crack here")
            continue

        result = wp.crack(capture, wordlist=args.wordlist or None, essid=args.essid,
                          bssid=args.bssid, timeout=args.timeout)
        if result.cracked:
            found += 1
            verified = " (verified against the capture)" if result.verified else " (unverified)"
            print(f"  → PSK: {result.password!r} via {result.tool}, "
                  f"{result.attempts:,} candidates in {result.seconds:.1f}s{verified}")
        else:
            print(f"  → not cracked: {result.reason or 'candidate space exhausted'} "
                  f"after {result.attempts:,} candidates")

    print(f"\n{found} of {len(args.captures)} capture(s) cracked")
    return 0 if found else 1


if __name__ == "__main__":
    sys.exit(main())
