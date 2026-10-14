# How wifipilot works, and how to use it as a module

Two halves: **the pipeline** (what the tool actually does to a network) and **the
library surface** (`import wifipilot as wp`, which drives that pipeline from your
own Python). The other references are [ATTACKS.md](ATTACKS.md) for the attack set,
[TUI.md](TUI.md) and [web-ui.md](web-ui.md) for the two front ends, and
[AI-PROVIDERS.md](AI-PROVIDERS.md) for the optional advisor and its off switch.

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
             pmkid_flood (active PMKID hunt) · wps_pixie · wps_pin (opt-in, online)
             wep_ivs/wep_p0841 (key) · wep_chopchop/fragment/hirte (enablers)
             saewolf + pmf_audit (read-only WPA3/RSN) · evil_twin (hostapd)
             deauth_flood/beacon_flood (capped DoS tests) · passive
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
takes over seamlessly, and the plan is labelled `heuristic`. Disable the advisor outright
(`wp.ai(disable=True)`, `--no-ai`/`--disable-ai`, `WIFIPILOT_NO_AI=1`) and the same planner
is simply the only planner.

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
| `wp.ALL`, `all`, `"all"`, `"*"`, `None`, `""` | every access point discovered |
| `"aa:bb:cc:11:22:33"` | one BSSID |
| `"CafeWiFi"` | an SSID or any substring of one (case-insensitive) |
| `["aa:bb:...", "CafeWiFi"]` | union of the above |
| an `AccessPoint` (e.g. from `wp.scan()`) | that access point |
| `"no-such-network"` | `TargetError`, listing what *was* discovered |

Bare `all` is the Python builtin, and wifipilot treats it as "everything" (as do
`None` and the empty string), so `wp.attack(target=all, mode="force")` does
exactly what it looks like.  In simulation mode the neighbourhood is seeded, so
a BSSID from one call is a valid target for the next one.

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
| `"force"` | yes, loudly | **all 534 attacks** (`wp.ALL_ATTACKS`, which is the attack registry's own order): the ten floods, the evil twin, Karma, the EAPOL-Logoff disconnect, the active PMKID hunt, the lures (`csa_attack`, `ssid_confusion`, `karma_detect`), the WEP enablers and the online WPS PIN attack (which can permanently lock an AP's WPS) included |
| `"default"` / `"recall"` | yes | the standard six: handshake, PMKID, WPS Pixie-Dust, WEP, hidden-SSID discovery and station tracking |
| `"quick"` | yes, briefly | PMKID + handshake + crack only |
| `"stealth"` | listen-only | passive capture, no deauth, no online PIN attacks, and the floods are refused even if enabled |
| `"passive"` | never | capture whatever the neighbourhood volunteers, plus the read-only audits (RSN/PMF, the element audit, the SAE-parameter audit) |
| `"offline"` | **no radio at all** | the ten attacks that read the session's own files: `loot_audit`, `crack_sweep`, `eapol_audit`, `wep_audit`, `eap_md5_crack`, `pixie_offline`, `rogue_detect`, `twin_detect`, `roam_audit`, `wps_lockout_audit` — no monitor interface, no root, no authorisation prompt |

Individual knobs (`stealth=`, `wps_pin=`, `attacks=`) override the preset, and `attacks=`
is the only way to get a deliberate subset (`attacks=["pmkid","handshake"]`). The two
read-only attacks are worth running on any engagement, because everything after them can
be reasoned about instead of guessed:

```python
# what does the AP say about itself, and what are the clients asking for?
wp.attack(target="all", mode="passive", duration="10m")     # includes ie_audit/pmf_audit
report = wp.status()["findings"]                            # ie_wps_enabled, ie_no_pmf, ...

# no radio at all: audit and crack what a previous run already collected
wp.attack(target="all", mode="offline")                     # ten file-only analyses
len(wp.catalogue())                                         # 534 — every attack
len(wp.catalogue(domain="it"))                              # 286 — the IT edition only
len(wp.catalogue(device="printer"))                         # the ones that fit a device type
wp.editions()                                              # {'wifi': 213, 'bluetooth': 35,
                                                           #  'it': 286, 'all': 534}
len(wp.devices())                                          # 65 device types
wp.device("printer")["plan"]                                # what to run against one
wp.device("nope")                                          # {} — unknown ids answer empty
wp.simulations()                                            # what a --demo run meets: the
                                                            #  simulated floor and segment
wp.simulations("bluetooth")["bluetooth"]["devices"]         # 46 simulated devices, 8 postures
wp.simulations("it")["it"]["hosts"]                         # 51 simulated hosts, 45 responders
wp.catalogue(offline_only=True)                             # the ten that need no radio
wp.catalogue(category="dos")                                # the denial-of-service tests

# one target, the two read-only decoders, no radio time wasted
wp.attack(target="d0:9e:12:9d:36:cc", mode="default",
          attacks=["ie_audit", "pnl_harvest"])              # nothing transmitted
```

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
wp.decode("capture.cap")             # every information element + the IE findings
wp.decode("capture.cap", include_low=False)   # only what is worth acting on
wp.export("capture.cap")             # -> capture.hc22000 (hashcat mode 22000)
wp.crack("web.hc22000")              # crack a hash file with the built-in engine
wp.analyze("web.hc22000")            # -> {"format": "hc22000", "verifiable": 2, ...}
wp.suggest_masks("Telekom-9F3A")     # -> [{"mask": "Telekom?d?d?d?d", "space": 10000, ...}]
wp.crack("capture.cap", mask="Telekom-?d?d?d?d")   # mask attack, built-in engine
wp.report(markdown=True)             # write the last run's report
wp.loot()                            # captures worth keeping
wp.loot("sessions/20260921-124633/reports/report.json")   # ...or from a report
wp.status()                          # provider, targets, loot, spend
wp.session(), wp.engine()            # the underlying objects, if you want them
```

Results carry the engagement's context: `result.demo`, `result.authorized`,
`result.modes`, `result.error`, `result.session.id`, `result.stats`,
`result.to_dict()` / `result.json()` (JSON-ready), `result.report_json` /
`result.report_markdown` (paths, written by `result.save()`), and for campaigns
`result.cracked()` (verified hits) / `result.unbroken()` (targets attacked
without a key — the honest gaps).

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

### The advisor (optional) from a script

Nothing below is required. The deterministic planner runs the whole engagement on its own;
these calls only add a model on top, and one of them takes it away again.

```python
wp.set_provider("ollama", model="qwen2.5:7b")          # local, private, free
wp.set_provider("openrouter", model="openai/gpt-4o-mini",
                ai_budget=0.50, redact_identifiers=True)  # cloud, opt-in, capped
wp.providers(probe=True)      # what is configured and whether it answers
wp.advisor_status()           # provider, model, spend, quota

# ...and the off switch, which is a single idea with three spellings:
wp.ai(disable=True)           # no model is called; nothing leaves this machine
wp.ai(disable=False)          # restore the provider that was in use before
wp.ai(provider="ollama")      # or pick one explicitly (auto|ollama|openrouter|none)
wp.ai(model="qwen2.5:7b")     # just change the model
wp.ai()                       # no arguments: report the current state
# -> {"ok", "changed", "disabled", "enabled", "provider", "reason",
#     "configured_provider", "env_off", "model", "previous", "note"}
```

`wp.set_provider("none")` is exactly `wp.ai(disable=True)`, so the two entry points can never
disagree — including for a live engine, whose `advisor`, `session.auto_think` and config are
updated in one place. The same switch is available from a shell as `wifipilot --no-ai` /
`--disable-ai` / `--offline` / `ai off`, and from the environment as `WIFIPILOT_NO_AI=1`.

While the advisor is off, `Config.ai_off()` is true, `advisor.status()["disabled"]` is true,
`advisor.check()` returns False without probing, `advisor.models()` returns `[]` without
asking a daemon, and `wp.ai()` reports `note: "deterministic planner only: no model is
called, nothing leaves this machine"`.

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

## Hash files (hashcat mode 22000)

``wp.export()`` writes a capture in the format cracking tools speak, and
``wp.crack()``/``wp.analyze()`` read one back — no hashcat and no hcxtools
required, in either direction:

```python
path = wp.export("loot/handshake-01.cap")          # PMKID + EAPOL lines
report = wp.analyze(path)                          # lines, verifiable, essids, pairs
hit = wp.crack(path, wordlist=["rockyou.txt"])     # -> CrackResult
hit.cracked, hit.password, hit.verified
wp.export("capture.cap", "out.json", fmt="json")   # or "csv" for a spreadsheet
```

The MIC algorithm is taken from each line's Key Descriptor Version, so classic
WPA2 (HMAC-SHA1-128), 802.11w/PMF and SAE (AES-128-CMAC) and TKIP (HMAC-MD5)
all verify correctly; lines with no usable nonce are reported as unverifiable
rather than counted as failures.

## Scoping, notes and analytics

The functions around a campaign — usable before it starts and after it ends,
with no radio attached:

```python
wp.configure(output_dir="loot", session_dir="sessions")

wp.strategies()                       # the presets, with what each one does
wp.targets(kind="guest", vendor="AVM", loot=True)   # filter what was discovered
wp.select(tag="in-scope")             # make them the campaign scope
wp.selected()                         # [{"bssid", "essid", "kind", "tags", "score"}]
wp.tag("d0:12:cb:00:00:01", "in-scope")
wp.note("back-office AP, retest after 18:00", bssid="d0:12:cb:00:00:01")
wp.notes()                            # everything on disk, newest first
wp.history(limit=20)                  # attempts, captures, notes, tags

wp.vendor(bssid="d0:12:cb:00:00:01")  # OUI match + dossier (heuristic, and says so)
wp.identify("Telekom-9F3A")           # scheme guess + masks worth trying
wp.passwords()                        # every cracked PSK with its weakness verdict
wp.advice()                           # prioritised next steps, no LLM call
wp.benchmark(seconds=5)               # this machine's candidate rate -> ETAs
```

## Cracking from a file: strategies and the toolbox

```python
wp.crack("capture.cap", strategy="thorough")     # or quick/mask-only/wordlist-only/...
wp.rules_info("best64")                          # what a rule file/preset actually does
wp.hash_stats("someone-elses.hc22000")           # lines, verifiable, ESSIDs, pairs
wp.merge_hashes(["a.hc22000", "b.hc22000"], "all.hc22000")
wp.rescue_capture("partial.pcap", "rescued.hc22000")
wp.wordlist_stats("rockyou.txt")
wp.expand_wordlist("words.txt", "candidates.txt", "best64")
wp.loot_manifest()                               # sha256 every loot file
wp.verify_loot()                                 # {"ok": True, "checked": 12, ...}
```

`wp.crack` is the function; the module behind it is `wifipilot.crack` — import
`from wifipilot.crack import STRATEGIES, apply_strategy` when you want the
presets programmatically (the package attribute is the function, by design).

## Passive intelligence, WPS plans and PMKs

Read-only questions, all of them answerable with no radio and no authorisation:

```python
wp.survey("capture.pcap")             # probes, deauth counts, rogue-twin patterns
wp.probes("capture.pcap")             # [{"mac", "vendor", "ssids", "directed", ...}]
wp.reveal("capture.pcap")             # name hidden networks; updates the session's APs
wp.eap("capture.pcap")                # 802.1X: methods, identities, certificates

wp.pins(bssid="d0:12:cb:00:00:01", essid="FRITZ!Box 7590 QY")
# {"candidates": [{pin, source, confidence, note}], "order": [...], "plan": {...}}
wp.pins(bssid="a8:90:91:0e:2b:40", first_half="1234")   # an M7 leak: 1,000 attempts

wp.pmk_verify("hashcat!", "capture.hc22000")   # {"ok": True, "matched": {...}}
wp.pmk_convert("capture.hc22000", psk="hashcat!", out="out.hc22001")
wp.pmk_cache()                                 # ESSID -> PSK learned this engagement
```

`wp.eap` decodes the EAP conversation in a capture and reports, per certificate, the
subject, the issuer, `self_signed` and the serial. A client that trusts a self-signed
server certificate is impersonable; that is the finding, and it comes out of an
offline file, not a radio.

`wp.survey` and `wp.probes` work off a capture, the current session, or both; a
survey's raw payload also lands on the attack record (`attempt.extra`), so a UI can
render the twins and the competing BSSIDs without re-reading the pcap.

`wp.pmk_verify` is the function to call after *any* wordlist run reports a plaintext:
a candidate that was never verified against the capture is a candidate, not a
password. The cache behind `crack()` uses the same check, so a second capture of an
ESSID already solved in this engagement costs one HMAC instead of a wordlist sweep.

## Mask attacks

`wp.crack(..., mask=...)` takes a hashcat-style mask (`?d ?l ?u ?s ?a`, `??` for a literal `?`)
or a list of them; `masks=False` switches the stage off:

```python
wp.crack("capture.cap", mask=["Telekom-?d?d?d?d", "?d?d?d?d?d?d?d?d"])
wp.suggest_masks(essid="TP-LINK_1A2B", vendor="TP-Link")   # what the cracker would try
```

The built-in engine expands masks whose space fits its budget
(`wp.configure(mask_candidates=50_000)`); bigger ones go to `hashcat -a 3` when it is installed.
Because both engines end in the same verifier, a mask hit is proven the same way a dictionary
hit is.
