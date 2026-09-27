# Benchmarks

```bash
python3 benchmarks/bench.py                 # everything (web + campaign need deps/patience)
python3 benchmarks/bench.py pcap crypto     # pick what you care about
python3 benchmarks/bench.py --json out.json # machine-readable results
python3 benchmarks/bench.py --campaign      # includes a full simulated campaign
```

Each benchmark prints the median wall time, a derived rate and a note explaining what it
actually measured. They run against real artifacts:

| group | what it does |
| --- | --- |
| `pcap` | synthesizes captures (handshake, 20k frames, 69 MiB, a mixed "scene" that is 74% beacons) and parses them cold, from the cache, and incrementally |
| `crypto` | the built-in engine's hot path: PBKDF2, PTK + MIC, and a full candidate verification through a prepared handshake |
| `crack` | the real `Cracker` against a real synthesized handshake — wrong candidates only, so an early hit cannot flatter the throughput |
| `hash` | hashcat mode 22000: writing lines from a capture, parsing + preparing verifiers, and verifying candidates through them |
| `mask` | deriving patterns for a target, expanding a 10k space, budget selection, and one real candidate through the mask stage |
| `session` | snapshot/loot/situation/export at 50/200/500 APs |
| `planner` | `rank_targets`, `heuristic_plan`, `validate_plan` |
| `web` | FastAPI request handling for the state snapshot and the JSON payload size |
| `campaign` | a full simulated campaign end to end |

Two design rules for anything added here:

1. **measure the real path** — no stubs, no simulated engines, and never a loop that can exit
   early without saying so in the detail column;
2. **state the artifact** — a number without the file size, frame count or candidate space next
   to it is not a benchmark.

Recorded results for the efficiency work live in the README's *Performance* section.
