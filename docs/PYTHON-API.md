# How wifipilot works, and how to use it as a module

Two halves: **the pipeline** (what the tool actually does to a network) and **the
library surface** (`import wifipilot as wp`, which drives that pipeline from your
own Python).

---

## 1. The pipeline

```
                ┌──────────────┐
   radio ──────▶│  discovery   │  airodump-ng / iw scans, beacon + probe parsing
                │  scanner.py  │  → AccessPoints (signal, WPA2/WPA3, WPS, clients)
                └──────┬───────┘
                       │  session.py keeps the live picture (APs, attempts, captures)
                       ▼
                ┌──────────────┐   situation report (a few hundred tokens)
                │   advisor    │◀──────────────────────────────┐
                │  planner.py  │  Ollama (local) or            │
                │  advisor.py  │  OpenRouter (cloud, opt-in)   │ feedback: what
                └──────┬───────┘  → JSON plan: prioritised     │ worked, what
                       │            actions + reasoning       │ failed, time left
                       ▼                                      │
                ┌──────────────┐                              │
                │  validate    │  planner.validate_plan(): drop │
                │              │  impossible/unsafe actions     │
                └──────┬───────┘  (unknown AP, WPA3+handshake,  │
                       │           WPS on non-WPS, stealth…)   │
                       ▼                                      │
                ┌──────────────┐                              │
                │    engine    │  one worker thread runs the    │
                │  engine.py   │  next action, watches it,      │
                │              │  records the outcome ──────────┘
                └──────┬───────┘
                       ▼
   attacks/  handshake (deauth → 4-way capture) · pmkid (`--pmkid` client-less)
             wps_pixie (reaver/bully) · wps_pin (opt-in, online) · wep_ivs · passive
                       │
                       ▼
                ┌──────────────┐
                │   cracking   │  built-in engine first (SSID/vendor/date candidates,
                │  crack.py    │  MIC-verified), then aircrack-ng / hashcat
                └──────┬───────┘
                       ▼
        loot/  (.cap, .hc22000, keys)   sessions/<id>/reports/report.{json,md}
```

**The loop, in words.** Every cycle: the engine takes a *situation report*
(targets with state and history, failures, enabled attacks, capabilities, time
budget), asks the advisor for the next few actions, validates them against the
session and the safety rules, executes them one at a time, records attempts,
captures and findings, and feeds the results into the next cycle. Re-planning is
triggered by an empty plan, two or more consecutive failures, three or more new
access points, the plan interval elapsing, or the plan finishing. When no model is
available — no Ollama daemon, no OpenRouter key, out of credit, over budget, rate
limited, or an answer that will not parse — `planner.py`'s deterministic planner
takes over seamlessly, and the plan is labelled `heuristic`.

**Everything is observable.** Every step publishes an event to the bus
(`session.start`, `ap.new`, `attack.start`, `capture.new`, `crack.found`,
`advisor.plan`, `advisor.cost`, `log`, …). The CLI dashboard, the web UI, the
session journal (`sessions/<id>/journal.jsonl`) and the `on_event`/`subscribe`
hooks in the API are all just consumers of that same stream.

**Safety is structural, not a prompt.** Deauthentication and any transmission
need `authorized`; `stealth` removes deauth and online WPS from the allowed set;
`wps_pin` is opt-in; the model's plan is validated against a closed vocabulary and
the live session; and the advisor's output is only ever a *proposal*.

**Simulation mode** (`demo=True`) swaps the radio for `demo.py`'s simulator: a
fake neighbourhood of access points with clients and known PSKs, driven through
the same scanner/attack/crack code paths. Nothing is transmitted, no adapter is
needed, and the whole pipeline — captures, MIC verification, cracking, reports —
runs for real against simulated frames.

---

## 2. Using it as a module

```python
import wifipilot as wp

# Rehearse the entire pipeline with no radio and no risk
wp.attack(target=all, mode="force", demo=True, duration="2m")

# A real, authorised engagement
wp.authorize("change ticket CHG-4711, client ACME Labs")
result = wp.attack(target="all", mode="force", duration="45m")

for hit in result.passwords:
    print(hit["essid"], "->", hit["password"], f"({hit['kind']})")
print(result.summary())
result.save("engagement.json")          # or markdown=True
```

### Targets

| you pass | meaning |
|---|---|
| `wp.ALL`, `all`, `"all"`, `"*"`, `None` | every access point discovered |
| `"aa:bb:cc:11:22:33"` | one BSSID |
| `"CafeWiFi"` | an SSID or any substring of one (case-insensitive) |
| `["aa:bb:...", "CafeWiFi"]` | union of the above |
| an `AccessPoint` (e.g. from `wp.scan()`) | that access point |
| `"no-such-network"` | `TargetError`, listing what *was* discovered |

Bare `all` is the Python builtin, and wifipilot treats it as "everything", so
`wp.attack(target=all, mode="force")` does exactly what it looks like.

### Budgets

`duration` is the campaign budget (``"45m"``, ``300``, ``"1h30m"``); without one the
run continues until the planner has nothing left worth doing, which in ``force``
mode can be a long time — the online WPS PIN attack alone gets `wps_timeout`
(5 minutes by default) per access point.  Prefer an explicit budget in anything
scripted, and remember the deadline is checked between rounds: a run can overrun
it by the attack that is already in flight.  ``scan_time`` bounds the discovery
phase (default: `Config.scan_time`, 30 s); ``max_targets`` stops the campaign once
that many passwords are recovered.

### Modes

| mode | transmits? | what it runs |
|---|---|---|
| `"force"` | yes, loudly | everything: deauth-driven handshakes, PMKID, WPS Pixie-Dust, WEP, **and the online WPS PIN attack** (can permanently lock an AP's WPS) |
| `"default"` / `"recall"` | yes | the standard set: handshake, PMKID, WPS Pixie-Dust, WEP |
| `"quick"` | yes, briefly | PMKID + handshake + crack only |
| `"stealth"` | listen-only | passive capture, no deauth, no online PIN attacks |
| `"passive"` | never | capture whatever the neighbourhood volunteers |

Individual knobs (`stealth=`, `wps_pin=`, `attacks=`) override the preset.

### The main calls

```python
wp.configure(interface="wlan0", wordlist="/usr/share/wordlists/rockyou.txt",
             provider="ollama", model="qwen2.5:7b", max_targets=3)

scan   = wp.scan(duration="30s")                      # -> ScanResult (.aps, .to_dict())
result = wp.attack(target="all", mode="force", duration="1h", background=True)
while result.running:                                 # non-blocking run
    print(wp.status()["passwords"], "passwords so far")
    time.sleep(5)
result.stop().wait()

hit = wp.crack("capture.cap", wordlist=["words.txt"])  # -> CrackResult
print(hit.cracked, hit.password, hit.verified, hit.tool)

wp.analyze("capture.cap")            # EAPOL/PMKID inventory of a file
wp.report(markdown=True)             # write the last run's report
wp.loot()                            # captures worth keeping
wp.status()                          # provider, targets, loot, spend
wp.session(), wp.engine()            # the underlying objects, if you want them
```

### Watching the run

```python
def on_event(event):                   # every bus event, from its own thread
    if event.kind == wp.EK.AP_NEW:
        print("found", event.data["essid"], event.data["bssid"])
    elif event.kind == wp.EK.CRACK_FOUND:
        print("cracked!", event.data["password"])

unsubscribe = wp.subscribe(on_event, kinds=[wp.EK.AP_NEW, wp.EK.CRACK_FOUND])
...

wp.attack(..., on_event=on_event)      # or scoped to a single call
```

### AI providers from a script

```python
wp.set_provider("ollama", model="qwen2.5:7b")          # local, private, free
wp.set_provider("openrouter", model="openai/gpt-4o-mini",
                ai_budget=0.50, redact_identifiers=True)  # cloud, opt-in, capped
wp.providers(probe=True)      # what is configured and whether it answers
wp.advisor_status()           # provider, model, spend, quota
wp.configure(provider="none") # deterministic planner only
```

The advisor is optional. `provider="none"` (or no daemon/key) means the
heuristic planner runs the engagement; nothing else changes.

### Errors

| exception | when |
|---|---|
| `wp.AuthorizationError` | a live run without `wp.authorize(...)`/`authorized=True` |
| `wp.PlatformError` | a call on a non-Linux machine (importing is always fine) |
| `wp.TargetError` | the target matched nothing, or discovery found nothing |
| `wp.BusyError` | a second campaign while one is still running |
| `wp.CampaignError` | the campaign failed mid-flight (`.result` keeps the partial loot) |
| `wp.WifiPilotError` | base class for all of the above |
| `InterfaceError`, `CrackError`… | from the subsystems, unchanged |

All of them derive from `RuntimeError`, so a one-line `except wp.WifiPilotError`
catches everything the library raises on purpose.

### Notes for scripts

* **One campaign at a time per process.** The module context holds the active
  engine; use `background=True` (plus `wait()`/`stop()`) instead of threads.
* **Set-up failures raise, campaign failures are recorded.** A missing radio or a
  bad target raises before anything runs (even for background calls); a failure
  *during* the campaign sets `result.error` and re-raises `CampaignError` for
  blocking calls (`raise_on_error=False` to keep the result only).
* **Quiet by default.** Progress goes to the event bus, not stdout; pass
  `verbose=True` to echo the tool chatter, or subscribe for structured updates.
* **Paths.** `output_dir` (default `loot/`) holds the artifacts, `session_dir`
  (default `sessions/`) the per-run journals and reports; the API result exposes
  both via `result.report_json` / `result.report_markdown`.
* **Reset** with `wp.reset()` between engagements in a long-lived process (it
  stops the campaign, drops subscribers and clears the configuration).

Runnable examples: `examples/triage.py` (discovery + report), `examples/crack.py`
(offline cracking), `examples/handshake_hunt.py` (targeted, events, loot).
