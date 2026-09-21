#!/usr/bin/env python3
"""Targeted engagement with live progress and a report — the API in anger.

    sudo python3 examples/handshake_hunt.py --authorized \
        --target "Cafe Guest" --duration 20m --wordlist rockyou.txt

    python3 examples/handshake_hunt.py --demo -d 2m    # rehearse it safely

Live runs transmit, so they need `--authorized` (or a call to
`wp.authorize("ticket …")`): the engine will not deauthenticate anything without
an explicit attestation, and wifipilot is for networks you are contracted to
test.
"""

from __future__ import annotations

import argparse
import sys
import time

import wifipilot as wp


def main() -> int:
    parser = argparse.ArgumentParser(description="hunt handshakes for one target")
    parser.add_argument("--target", default="all", help="SSID, BSSID, or 'all'")
    parser.add_argument("--mode", default="default", choices=sorted(wp.MODES))
    parser.add_argument("-d", "--duration", default="30m", help="campaign budget")
    parser.add_argument("-t", "--time", default="20", help="discovery window first")
    parser.add_argument("-w", "--wordlist", action="append", default=[])
    parser.add_argument("--provider", default="auto",
                        choices=["auto", "ollama", "openrouter", "none"])
    parser.add_argument("--model", default="", help="model for the chosen provider")
    parser.add_argument("--budget", type=float, default=0.0, help="USD cap (cloud provider)")
    parser.add_argument("--authorized", action="store_true",
                        help="attest that you have written permission to test the targets")
    parser.add_argument("--demo", action="store_true", help="simulate, no radio")
    parser.add_argument("-o", "--report", default="", help="markdown report path")
    args = parser.parse_args()

    wp.configure(provider=args.provider, model=args.model, ai_budget=args.budget,
                 wordlist=args.wordlist or None, demo=args.demo)
    if args.authorized:
        wp.authorize("--authorized on the command line")

    def progress(event) -> None:
        # the loop below keeps a live status line updated with \r: clear it before
        # printing a real line of output so the two never interleave
        if event.kind == wp.EK.AP_NEW:
            data = event.data
            print(f"\r\033[K  + {data.get('essid') or '(hidden)'} {data.get('bssid')} "
                  f"ch {data.get('channel')} {data.get('signal')}dBm", flush=True)
        elif event.kind == wp.EK.ATTACK_START:
            print(f"\r\033[K  » {event.data.get('attack')} on {event.data.get('bssid')} "
                  f"— {event.data.get('reason') or 'scheduled'}", flush=True)
        elif event.kind == wp.EK.CRACK_FOUND:
            print(f"\r\033[K  ★ PSK for {event.data.get('essid') or event.data.get('bssid')}: "
                  f"{event.data.get('password')}", flush=True)
        elif event.kind in (wp.EK.WARNING, wp.EK.ERROR):
            print(f"\r\033[K  ! {event.data.get('message') or event.data}", flush=True)

    unsubscribe = wp.subscribe(progress)
    result = None
    try:
        print(f"engagement: target={args.target!r} mode={args.mode} "
              f"duration={args.duration} provider={args.provider}"
              f"{' (simulation)' if args.demo else ''}")
        run = wp.attack(target=args.target if args.target != "all" else all,
                        mode=args.mode, duration=args.duration, scan_time=args.time,
                        demo=args.demo, background=True)
        while run.running:
            stats = run.stats
            print(f"\r\033[K  … {stats.aps_seen} APs · {stats.attacks_run} attacks "
                  f"({stats.attacks_failed} failed) · {stats.loot} loot · "
                  f"{stats.passwords} password(s)", end="", flush=True)
            time.sleep(2)
        print()
        result = run.wait()
    except KeyboardInterrupt:
        print("\ninterrupted — stopping cleanly")
        wp.stop()
        result = run.wait()
    finally:
        unsubscribe()

    if result is None:
        return 130
    print("\n" + result.summary())
    if result.error:
        print(f"\ncampaign reported an error: {result.error}")
    print(f"\nreport: {result.save(args.report or '', markdown=bool(args.report))}")
    return 0 if not result.error else 1


if __name__ == "__main__":
    sys.exit(main())
