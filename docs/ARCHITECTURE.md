# Architecture

wifipilot is small enough to read in an afternoon. This document explains how the pieces
fit together and, more importantly, *why* they are shaped this way.

```
                       ┌──────────────────────────── presentation ────────────────────────────┐
                       │  cli.py (rich dashboard)                    web/ (FastAPI + SPA)     │
                       └───────▲──────────────────────────────────────────────▲─────────────┘
                               │ events (pub/sub)                             │ REST + WS
                       ┌───────┴──────────────────────────────────────────────┴─────────────┐
                       │                         engine.py                                  │
                       │  job queue · campaign loop · policy gates · single radio owner     │
                       └───┬───────────┬───────────────┬──────────────┬───────────────┬───────┘
                           │           │               │              │               │
             ┌─────────────▼──┐ ┌──────▼──────┐ ┌──────▼──────┐ ┌─────▼──────┐ ┌──────▼──────┐
             │ session.py     │ │ scanner.py  │ │ attacks/*   │ │ crack.py   │ │ advisor.py  │
             │ state + report │ │ airodump    │ │ real tools  │ │ 3 engines  │ │ llm.py      │
             └───────┬────────┘ └──────┬──────┘ └──────┬──────┘ └─────┬──────┘ └──────┬──────┘
                     │                 │               │              │               │
             ┌───────▼─────────────────▼───────────────▼──────────────▼───────────────▼───────┐
             │  events.py · models.py · util.py · iface.py · planner.py                          │
             │  pcap.py (802.11/EAPOL parser) · crypto.py (AES/CMAC/PBKDF2/PRF) · synth.py       │
             └──────────────────────────────────────────────────────────────────────────────────┘
```

## 1. One worker thread owns the radio

A WiFi adapter in monitor mode is a single, exclusive resource: two processes fighting over
it produce garbage. So every operation — a campaign, a one-off attack from the web UI, a
manual crack job — is submitted to `Engine.add_job()` and executed by **one** worker thread.
The public API of the engine (`request_attack`, `request_start`, `request_crack`, …) only
enqueues; nothing else ever touches `airodump-ng`.

Consequences:

* the web UI can be spammed with button presses and nothing breaks;
* `Engine.request_stop()` / `request_cancel_attack()` are events, not signals, so stopping is
  deterministic: the running attack checks `_StopFlag` (union of "session stop" and "cancel
  this attack") between its I/O operations;
* shutdown is a sequence: stop the scanner → stop child processes → tear down monitor mode →
  write the report.

## 2. The event bus is the only UI contract

`events.EventBus` is a thread-safe fan-out with a ring buffer. Every meaningful thing that
happens is published as an `Event(kind, data)`: `ap.new`, `attack.start`, `capture.new`,
`crack.found`, `advisor.plan`, `log`, …

* the CLI subscribes and renders a live table;
* the web UI subscribes per WebSocket connection and streams the raw events to the browser;
* the journal writes the durable subset to `journal.jsonl`.

Because both UIs render the *same* events, they cannot disagree, and adding a new UI (say, a
Kismet-style desktop app) requires no changes to the engine. Publishing never raises and never
blocks: a slow or dead subscriber drops events instead of stalling the radio.

## 3. Nothing is believed without verification

Tool output is a claim; wifipilot checks it.

* `pcap.py` parses pcap/pcapng (both endiannesses, µs/ns, plus radiotap/Prism/AVS), extracts
  802.11 frames, walks LLC/SNAP to EAPOL-Key, numbers the messages (M1–M4) from the key-info
  flags/replay counters, and pulls the PMKID out of the RSN KDE.
* A capture counts as a handshake only if both nonces and a MIC are present (M1+M2 or M2+M3).
* `crypto.py` implements AES-128/192/256 (FIPS-197), AES-CMAC (RFC 4493), PBKDF2-HMAC-SHA1,
  the 802.11i PRF-512 and the PMKID derivation — so wifipilot can *prove* a password by
  recomputing the MIC or the PMKID, and can crack small candidate spaces itself.
* Verified crypto is what makes the simulation mode honest: `synth.py` builds captures with
  real PBKDF2/PTK/CMAC values, so demo mode exercises the same verification path as live mode.

## 4. The LLM is an advisor, never an authority

`llm.py` holds the transports — a local Ollama server and OpenRouter's OpenAI-compatible
gateway — behind one `LLMClient` interface (stdlib `urllib` only, no extra dependency).
`advisor.py` picks the transport, sends a compact situation report and receives JSON.

Provider policy is enforced in the transport, not in the prompt:

* Ollama: loopback-only unless the operator explicitly allows a remote host.
* OpenRouter: disabled until enabled *and* given a key; HTTPS-only unless the base URL is
  loopback; identifiers pseudonymised before sending; a USD budget that hard-stops planning;
  401/402/429 are distinct errors with operator-facing advice.
* The API key never leaves the config layer: `Config.to_dict(redact_secrets=True)` is what the
  web serves, and `key_hint()` exposes only length and source.

The security model:

1. **closed vocabulary** — the prompt lists the allowed attacks; anything else is invalid;
2. **validator** — `planner.validate_plan()` re-checks every proposed action against the live
   session: BSSID must exist, attack must be enabled and applicable, stealth rules and safety
   rules (no handshake against WPA3-SAE, no cracking without captures) are enforced. Rejected
   proposals are surfaced to the operator, never silently executed;
3. **fallback** — a deterministic, explainable planner (`planner.heuristic_plan`) takes over
   whenever the model is unavailable, slow or incoherent. The campaign can always continue.
4. **policy gate** — without explicit authorisation, and in stealth mode, the engine refuses
   to transmit at all, regardless of what any planner says.

## 5. Attack modules are uniform

`attacks/base.py` defines `Attack` (name, label, tool, requirements, applicability) and
`AttackContext` (session, config, events, interface, process manager, stop flag). Each module
implements `run(ctx, ap) -> AttackOutcome` and may use the shared helpers
(`ctx.deauth()`, `ctx.progress()`, `ctx.validate_capture()`, `_succeed()`/`_fail()` which also
close the attempt in the session).

That uniformity is what makes the simulation possible: modules branch on `ctx.demo` for the
packet source only (`ctx.radio` instead of a subprocess), while validation, cracking,
reporting and UI rendering stay identical.

## 6. Data flow of one action

```
planner/LLM ──► validate_plan ──► Engine.run_attack ──► Attack.run
                                        │                     │
                                        │              (real tool / demo radio)
                                        │                     ▼
                                        │            Capture + verification
                                        ▼                     │
                              session.start_attempt           │
                              session.end_attempt ◄───────────┘
                                        │
                                        ▼
                        events: attack.start / capture.new / attack.end
                                        │
                     ┌──────────────────┴───────────────────┐
                     ▼                                      ▼
             CLI dashboard                        web UI (WebSocket)
                                        │
                                        ▼
                              cracker (if loot and not --skip-crack)
```

## 7. Extension points

* **new attack** — add a module in `attacks/`, register it in `attacks/__init__.py`, add its
  name to `models.ATTACK_NAMES` and (if appropriate) to the default `Config.attacks`. The CLI,
  the web UI, the plan validator and the LLM prompt pick it up automatically.
* **new data source** — implement a producer that calls `session.upsert_ap()` /
  `session.add_client()` (Kismet, `iw scan`, a CSV replay, …).
* **new UI** — subscribe to `EventBus` and read `Engine.snapshot()`.
* **new cracking engine** — subclass/extend `Cracker` and return `CrackResult`.
* **new model provider** — implement `LLMClient` (`ping`, `list_models`, `resolve_model`,
  `chat`, optional `pull`), register it in `build_client()` and in `Config.llm_config()`.
  Everything above it (advisor, planner validation, CLI, web UI, cost accounting) works
  unchanged.

## 8. Three front ends, one engine

`cli.py`, `web/app.py` and `api.py` are peers: each one builds a
:class:`~wifipilot.config.Config`, creates a :class:`~wifipilot.engine.Engine`,
and consumes the same event bus.  Nothing in the engine knows which front end is
driving it, which is why the API gets the dashboard's behaviour for free — the
same planner, the same validation, the same authorisation gate, the same reports.

The API adds only what a library needs and a UI does not: one campaign per process
(a second call raises `BusyError` instead of fighting over the radio), setup errors
raised to the caller instead of rendered to a panel, and result objects
(`Run`/`ScanResult`/`CampaignResult`) that are JSON-serialisable.

## 9. Linux-only by construction

The engine drives nl80211 monitor mode through `iw`/`airmon-ng`, reads `/sys/class/net` to
confirm interfaces and MAC addresses, unblocks radios with `rfkill`, and parses Linux-specific
tool output. None of that has a portable equivalent, so the tool does not pretend otherwise:
`util.require_linux()` gates the CLI and the web server (with an explicit
`WIFIPILOT_ALLOW_NON_LINUX` escape hatch for packaging checks and the test suite), the install
hints are Linux package names only, and `tests/test_platform.py` fails if a non-Linux code
path is reintroduced.

## 10. Failure philosophy

Wireless tooling fails constantly: adapters lie about injection, clients sleep, WPS locks,
drivers drop monitor mode. wifipilot therefore treats every failure as data:

* each failure is recorded on the attempt with the tool's own tail output;
* `planner.explain_failure()` classifies the common cases in plain language;
* repeated failures retire an attack for that target (twice), successful ones retire it
  immediately — so the campaign never loops on a solved or hopeless target;
* the advisor can be asked to triage a failure and propose the next move.

## 11. Performance

The hot paths are capture parsing and WPA key derivation, so that is where the
work went — nothing else was allowed to get slower:

* **parsing is offset-based and memory-mapped.** `pcap.py` walks a capture with
  `mmap` + `struct.unpack_from` and slices a frame only when it is kept (EAPOL
  messages, the beacons it still needs an SSID from).  The iterator yields
  `(timestamp, offset, length, next_offset)`.
* **analysis is resumable.** `_AnalysisState` remembers the byte offset of the
  last complete record, so polling a capture that is still being written parses
  only the appended bytes; an unchanged file returns a cached snapshot without
  touching the disk again.  Every call hands out a fresh `CaptureAnalysis`, so a
  result someone already holds never changes underneath them.
* **verification state is prepared once.** `crypto.HandshakeVerifier` and
  `crypto.PmkidVerifier` hoist the per-capture work (EAPOL extraction, MIC
  zeroing, MAC parsing, AES-CMAC subkeys) out of the candidate loop, and
  `Cracker` derives the PMK once per candidate however many handshakes and
  PMKIDs the capture holds.
* **the crypto primitives are table-driven.** AES uses folded T-tables (~20x
  faster than the readable implementation, which is kept and cross-checked in
  the tests); the decryption schedule is built lazily because MIC checks only
  encrypt.
* **benchmarks measure the real path** (`benchmarks/`, `make bench`): real
  captures, real handshakes, wrong candidates only, and the artifact (frame
  count, MiB, candidate space) printed next to every number.
* **counts are counts.** The built-in engine reports the candidates it actually
  derived, and its log line says how many it took to crack, so an early hit
  cannot be presented as a full sweep: the end-to-end benchmark stops at
  candidate #48 and reports 49 candidates at ~340/s, not the 2,799 it never
  derived — nor the 21,000/s that dividing the whole space by the elapsed time
  would have claimed.

Details and before/after numbers: README → *Performance*.
