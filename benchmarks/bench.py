#!/usr/bin/env python3
"""Measure the parts of wifipilot that cost real time, CPU or tokens.

    python3 benchmarks/bench.py            # everything
    python3 benchmarks/bench.py pcap crack # a subset

The numbers are the contract for the optimisation work: each benchmark prints
what it measures, how long it took and the derived rate, so a regression shows up
as a number going the wrong way.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from wifipilot import crypto, pcap, planner, synth
from wifipilot.pcap import analyze_file                 # noqa: E402
from wifipilot.config import Config                                # noqa: E402
from wifipilot.crack import Cracker, smart_candidates              # noqa: E402
from wifipilot.events import EventBus                              # noqa: E402
from wifipilot.models import AccessPoint, Capture                  # noqa: E402
from wifipilot.session import Session                              # noqa: E402

SSID, BSSID, STA, PSK = "BenchNet", "aa:bb:cc:11:22:33", "02:00:00:00:00:0a", "BenchNet2024"

RESULTS: list[tuple[str, str]] = []


def report(name: str, seconds: float, detail: str = "", rate: str = "") -> None:
    RESULTS.append((name, f"{seconds * 1000:9.2f} ms  {rate:>18}  {detail}"))


def timed(name: str, function, repeat: int = 3, detail: str = "", unit: str = "") -> float:
    """Run ``function`` ``repeat`` times, report the median, return it."""
    times = []
    value = None
    for _ in range(repeat):
        started = time.perf_counter()
        value = function()
        times.append(time.perf_counter() - started)
    median = statistics.median(times)
    rate = ""
    if unit and median > 0 and isinstance(value, (int, float)):
        rate = f"{value / median:,.0f} {unit}"
    report(name, median, detail, rate)
    return median


# --------------------------------------------------------------------------- #
# benchmarks
# --------------------------------------------------------------------------- #


def bench_pcap(packets: int = 20_000, repeat: int = 3) -> None:
    """Parsing captures: the scanner and the cracker both do this per file."""
    path = Path("/tmp/wifipilot-bench.pcap")
    frames, _ = synth.build_handshake_frames(SSID, BSSID, STA, PSK)
    bulk = (frames * (packets // len(frames) + 1))[:packets]
    synth.write_pcap(str(path), bulk)
    size = path.stat().st_size
    count = len(bulk)

    # cold: the real cost of looking at a capture for the first time
    timed("pcap: analyze_file (cold)", lambda: pcap.analyze_file(str(path), use_cache=False),
          repeat, detail=f"{count:,} frames, {size / 1024:.0f} KiB", unit="frames/s")

    # warm: an attack cycle re-reads the capture it just produced
    pcap.analyze_file(str(path))
    def warm():
        pcap.clear_cache()
        pcap.analyze_file(str(path))          # populate
        return pcap.analyze_file(str(path))   # and this is what a second look costs
    timed("pcap: analyze_file (cached)", lambda: (pcap.analyze_file(str(path)),
                                                  pcap.analyze_file(str(path)))[1],
          repeat, detail="second look at the same file")

    # a realistic capture shape (mostly beacons + background traffic, some EAPOL)
    scene = Path("/tmp/wifipilot-bench-scene.pcap")
    synth.build_scene(str(scene), aps=6, clients=12, rounds=1500)
    megabytes = scene.stat().st_size / 1048576
    timed("pcap: analyze scene (cold)",
          lambda: pcap.analyze_file(str(scene), use_cache=False), repeat,
          detail=f"{megabytes:.1f} MiB, 74% beacons")
    timed("pcap: analyze scene (cached)",
          lambda: (pcap.analyze_file(str(scene)), pcap.analyze_file(str(scene)))[1], repeat,
          detail="what an attack cycle pays after the first look")
    scene.unlink(missing_ok=True)

    for extra in (5, 25):                       # realistic sizes: handshake hunts are MBs
        big = Path(f"/tmp/wifipilot-bench-{extra}x.pcap")
        synth.write_pcap(str(big), ((frames * (extra * count // len(frames) + 1))[:extra * count]))
        megabytes = big.stat().st_size / 1048576
        timed(f"pcap: analyze_file ({extra}x cold)",
              lambda b=big: pcap.analyze_file(str(b), use_cache=False),
              max(1, repeat - 1),
              detail=f"{megabytes:.1f} MiB capture",
              unit="MiB/s" if False else "")
        big.unlink(missing_ok=True)
    path.unlink(missing_ok=True)


def bench_crypto(candidates: int = 1_000, repeat: int = 3) -> None:
    """The built-in cracker's hot path: PBKDF2 + PTK + MIC for every candidate.

    Measured against a real synthesized handshake, so the numbers are the
    cracking throughput the engine actually achieves.
    """
    path = "/tmp/wifipilot-bench-crypto.pcap"
    synth.build_capture(path, SSID, BSSID, STA, PSK)
    analysis = analyze_file(path, use_cache=False)
    handshake = analysis.best_handshake()
    frames = {number: message.raw for number, message in handshake.messages.items()}
    verifier = crypto.HandshakeVerifier.from_analysis(handshake, SSID, BSSID)
    pmk_bytes = crypto.pmk(PSK, SSID)
    ap, station = bytes.fromhex(BSSID.replace(":", "")), bytes.fromhex(STA.replace(":", ""))
    anonce, snonce = bytes.fromhex(handshake.anonce), bytes.fromhex(handshake.snonce)
    ptk_bytes = crypto.ptk(pmk_bytes, ap, station, anonce, snonce)
    eapol = crypto._zero_mic(crypto._eapol_frame_from_bytes(frames[2]))

    timed("crypto: pmk (PBKDF2 4096)", lambda: crypto.pmk(PSK, SSID), repeat,
          detail="one key derivation", unit="keys/s")
    timed("crypto: ptk + mic", lambda: crypto.mic_from_ptk(ptk_bytes, eapol, 2), repeat,
          detail="key expansion + AES-CMAC", unit="ops/s")

    def chain(count=candidates):
        for index in range(count):
            verifier.check(f"candidate-{index}")
        return count

    timed("crypto: verify a candidate", chain, max(1, repeat - 1),
          detail="pmk + ptk + MIC (prepared handshake)", unit="cand/s")

    def one_shot(count=candidates):
        for index in range(count):
            crypto.verify_handshake(frames, SSID, BSSID, STA, handshake.anonce,
                                    handshake.snonce, f"candidate-{index}")
        return count

    timed("crypto: verify a candidate (one-shot API)", one_shot, 1,
          detail="re-parses the frames every call", unit="cand/s")
    Path(path).unlink(missing_ok=True)


def bench_crack(repeat: int = 1) -> None:
    """End-to-end candidate search against a real synthesized handshake."""
    path = "/tmp/wifipilot-bench-crack.pcap"
    synth.build_capture(path, SSID, BSSID, STA, PSK)
    config = Config(demo=False)
    config.crack_timeout = 120
    session = Session(config, EventBus(), demo=False)
    ap = AccessPoint(bssid=BSSID, essid=SSID, encryption="WPA2")
    capture = Capture(kind="handshake", bssid=BSSID, essid=SSID, path=path, valid=True)
    cracker = Cracker(session, config, session.bus, demo=False)

    candidates = list(smart_candidates(ap))
    hit = candidates.index(PSK) if PSK in candidates else len(candidates)
    analysis = analyze_file(path, use_cache=False)
    report("crack: candidate space", 0.0,
           f"{len(candidates)} targeted candidates, password at #{hit}", f"{len(candidates)} cand")

    # honest throughput: verify candidates that are *not* the password, so the
    # engine cannot stop early and flatter the number
    wrong = candidates[:hit] or candidates[1:]
    verifier_deadline = time.time() + 600

    def verify_wrong(count=len(wrong)):
        _, tested = cracker._python_pass(ap, capture, analysis, wrong[:count],
                                         verifier_deadline, lambda *_: None)
        return tested

    timed("crack: built-in verify", verify_wrong, 1,
          detail=f"{len(wrong)} wrong candidates through the real engine",
          unit="cand/s")

    single = cracker.crack_capture(ap, capture, wordlists=[], timeout=120)
    report("crack: handshake (end to end)", single.seconds,
           f"cracked={single.cracked} password={single.password!r} tool={single.tool}",
           f"{single.attempts / max(1e-9, single.seconds):,.0f} cand/s")
    Path(path).unlink(missing_ok=True)


def _session_with(count: int) -> Session:
    config = Config(demo=True)
    config.ollama.enabled = False
    session = Session(config, EventBus(), demo=True)
    for index in range(count):
        bssid = f"aa:bb:cc:{index // 256:02x}:{index % 256:02x}:0f"
        ap, _ = session.upsert_ap(bssid, f"BenchNet-{index}", publish=False)
        ap.encryption = "WPA2" if index % 3 else "WPA3"
        ap.wps = index % 4 == 0
        ap.signal = -40 - (index % 40)
        if index % 5 == 0:
            ap.captures.append(Capture(kind="handshake", bssid=bssid, essid=ap.essid,
                                       path=f"/tmp/bench-{index}.cap", valid=True,
                                       password="hunter2" if index % 10 == 0 else ""))
            session.add_client(bssid, f"02:00:00:{index // 256:02x}:{index % 256:02x}:01")
    return session


def bench_session(counts=(50, 200, 500), repeat: int = 5) -> None:
    """Every web client asks for a snapshot every three seconds."""
    for count in counts:
        session = _session_with(count)
        timed(f"session: snapshot ({count} APs)", session.snapshot, repeat,
              detail=f"{count} APs, {len(session.attempts)} attempts")
        timed(f"session: loot ({count} APs)", session.loot, repeat, detail="loot scan")
        timed(f"session: situation ({count} APs)", session.situation, repeat,
              detail="advisor prompt payload")
        payload = session.situation()
        report("session: situation size", 0.0,
               f"{count} APs -> {len(json.dumps(payload)) / 1024:.1f} KiB")
        timed(f"session: export ({count} APs)", session.export, repeat, detail="report JSON")


def bench_planner(count: int = 200, repeat: int = 20) -> None:
    """The planner runs on every campaign round and on every re-plan."""
    session = _session_with(count)
    config = Config(demo=True)
    config.ollama.enabled = False
    timed("planner: rank_targets", lambda: planner.rank_targets(session, config, limit=3),
          repeat, detail=f"{count} APs")
    timed("planner: heuristic_plan", lambda: planner.heuristic_plan(session, config), repeat,
          detail=f"{count} APs")
    actions = [{"attack": attack, "bssid": bssid, "priority": 1}
               for attack, bssid in zip(["pmkid", "handshake", "wps_pixie", "passive"],
                                        list(session.aps))]
    timed("planner: validate_plan", lambda: planner.validate_plan(
        {"reasoning": "x", "actions": actions}, session), repeat, detail="4 actions")


def bench_web(payload: bool = True) -> None:
    """What the UI actually ships over the socket every three seconds."""
    if not payload:
        return
    try:
        from fastapi.testclient import TestClient
        from wifipilot.web.app import create_app
    except ImportError:
        print("   (web extras not installed: skipping the web benchmark)")
        return
    config = Config(demo=True)
    config.ollama.enabled = False
    app = create_app(config, demo=True)
    with TestClient(app) as client:
        client.get("/api/state")
        response = client.get("/api/state")
        size = len(response.content)
        report("web: GET /api/state", 0.0, f"{size / 1024:.1f} KiB per refresh")
        times = []
        for _ in range(5):
            started = time.perf_counter()
            client.get("/api/state")
            times.append(time.perf_counter() - started)
        report("web: snapshot request", statistics.median(times),
               f"{size / 1024:.1f} KiB", f"{size / statistics.median(times) / 1048576:.2f} MiB/s")


def bench_campaign(budget: float = 20.0) -> None:
    """Wall-clock of a simulated campaign vs the budget it was given."""
    from wifipilot.api import attack, configure, reset
    reset()
    configure(demo=True, provider="none", scan_time=3, max_targets=2)
    started = time.perf_counter()
    run = attack(target="all", mode="quick", duration=budget, scan_time=3, demo=True)
    elapsed = time.perf_counter() - started
    report("campaign: simulated run", elapsed,
           f"budget {budget:.0f}s · overrun {elapsed - budget:+.1f}s · "
           f"{run.stats.attacks_run} attacks · {run.stats.passwords} passwords",
           f"{run.stats.attacks_run / elapsed:.2f} attacks/s")
    reset()


BENCHMARKS = {
    "pcap": bench_pcap,
    "crypto": bench_crypto,
    "crack": bench_crack,
    "session": bench_session,
    "planner": bench_planner,
    "web": bench_web,
    "campaign": bench_campaign,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("benchmarks", nargs="*", choices=sorted(BENCHMARKS) + [[]],
                        default=[], help="which benchmarks to run (default: all but campaign)")
    parser.add_argument("--campaign", action="store_true", help="include the campaign benchmark")
    parser.add_argument("--json", default="", help="also write the numbers to this file")
    args = parser.parse_args()

    selected = args.benchmarks or [b for b in BENCHMARKS if b != "campaign"]
    if args.campaign and "campaign" not in selected:
        selected.append("campaign")

    print(f"wifipilot benchmarks · python {sys.version.split()[0]} · "
          f"{os.cpu_count()} cores\n")
    for name in selected:
        print(f"-- {name}")
        started = time.perf_counter()
        BENCHMARKS[name]()
        print(f"   ({time.perf_counter() - started:.1f}s total)")

    print(f"\n{'benchmark':<34} {'median':>10}  {'rate':>18}  detail")
    print("-" * 118)
    for name, line in RESULTS:
        print(f"{name:<34} {line}")

    if args.json:
        Path(args.json).write_text(json.dumps(
            {"python": sys.version.split()[0], "cores": os.cpu_count(),
             "results": [{"benchmark": n, "measurement": m} for n, m in RESULTS]}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
