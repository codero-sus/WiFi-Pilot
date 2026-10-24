# wifipilot 📡

**An AI-piloted WiFi auditing tool — a modern alternative to `wifite`, in Python, for Linux, with a web UI and an optional local- or cloud-LLM advisor you can switch off completely.**

> Written and maintained by **[codero-sus](https://github.com/codero-sus)** · **[the-codero.web.app](https://the-codero.web.app)**

`wifipilot` automates the boring, error-prone parts of an authorised wireless assessment:
it finds the targets, decides which attack is worth the time, runs it, cracks what it
captures, and explains every decision in plain language.

**Linux only.** Every attack path drives nl80211 monitor mode, `rfkill`, `/sys/class/net`
and the aircrack-ng suite; there is no supported macOS or Windows build, and
`wifipilot` refuses to run on anything but Linux.

**AI-piloted, never AI-dependent.** The pilot is the advisor: it proposes the plan, and
wifipilot validates and executes it — the model never touches the radio. No model is required
to run. The deterministic planner scores targets, picks attacks, triages failures and chooses
cracking strategy on its own, offline and free; the **optional** advisor adds a model on top —
a local one served by [Ollama](https://ollama.com) or
[Cortex LLMHoster](https://github.com/codero-sus/Cortex_LLMHoster) (nothing leaves the
machine) or, opt-in with an API key and a spend cap,
[OpenRouter](https://openrouter.ai). With the advisor off,
wifipilot never opens a socket to anything but your radio.

```bash
wifipilot --no-ai attack -d 30m        # --disable-ai and --offline say the same thing
wifipilot ai off                        # switch it off for good (persist with --save)
WIFIPILOT_NO_AI=1 wifipilot web         # ...or for one shell, e.g. in CI
```
```python
import wifipilot as wp
wp.ai(disable=True)                     # deterministic planner only, nothing sent anywhere
```

```
  ██╗    ██╗██╗███████╗██╗██████╗ ██╗██╗      ██████╗ ████████╗
  ██║    ██║██║██╔════╝██║██╔══██╗██║██║     ██╔═══██╗╚══██╔══╝
  ██║ █╗ ██║██║█████╗  ██║██████╔╝██║██║     ██║   ██║   ██║
  ██║███╗██║██║██╔══╝  ██║██╔═══╝ ██║██║     ██║   ██║   ██║
  ╚███╔███╔╝██║██║     ██║██║     ██║███████╗╚██████╔╝   ██║
   ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝╚═╝     ╚═╝╚══════╝ ╚═════╝    ╚═╝
  AI-piloted wifi auditing · wifite alternative · authorised use only
```

> ⚠️ **Authorised use only.** Active wireless attacks disrupt service and are illegal
> without written permission. Read [docs/ETHICS-AND-LEGAL.md](docs/ETHICS-AND-LEGAL.md)
> before you point this at anything that is not yours. `wifipilot` refuses to transmit
> until you confirm authorisation, and ships with a radio-free simulation mode.

---

## Table of contents

- [Why another wifite?](#why-another-wifite)
- [Features](#features)
- [Install](#install)
- [Use it as a library](#use-it-as-a-library)
- [Quickstart (no hardware required)](#quickstart-no-hardware-required)
- [Real engagement](#real-engagement)
- [Presets: finished in minutes, not an hour](#presets-finished-in-minutes-not-an-hour)
- [The terminal UI](#the-terminal-ui)
- [The web UI](#the-web-ui)
- [Optional: the advisor (a local model, or OpenRouter)](#optional-the-advisor-a-local-model-or-openrouter)
- [Attacks](#attacks) — [reference for every attack](docs/ATTACKS.md)
- [Cracking](#cracking)
- [CLI reference](#cli-reference)
- [Hash files (hashcat mode 22000)](#hash-files-hashcat-mode-22000)
- [Configuration](#configuration)
- [Performance](#performance)
- [Offline toolbox (no radio, no root)](#offline-toolbox-no-radio-no-root)
- [Passive intelligence and PMKs](#passive-intelligence-and-pmks)
- [Architecture](#architecture)
- [Testing](#testing)
- [FAQ / troubleshooting](#faq--troubleshooting)
- [Roadmap](#roadmap)
- [Documentation](#documentation)
- [License](#license)

---

## Documentation

| document | what is in it |
| --- | --- |
| [docs/ATTACKS.md](docs/ATTACKS.md) | all 848 attacks, edition by edition and category by category: what each answers, what it costs, what it puts on the air, how to read the result, and its failure modes — plus the device shelf |
| [docs/TUI.md](docs/TUI.md) | the terminal dashboard: every panel, the three `AI:` states, the plain-text fallback, `--json` behaviour |
| [docs/web-ui.md](docs/web-ui.md) | the browser UI screen by screen, its controls, and the full REST/WebSocket surface |
| [docs/PYTHON-API.md](docs/PYTHON-API.md) | the pipeline and the library surface: `import wifipilot as wp`, run objects, hooks, the advisor switch |
| [docs/AI-PROVIDERS.md](docs/AI-PROVIDERS.md) | the model providers (Ollama, Cortex LLMHoster, OpenRouter), key handling, costs, the privacy model — and how to turn all of it off |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | modules, data flow, the three front ends, the safety model, performance work |
| [docs/OPTIMIZATIONS.md](docs/OPTIMIZATIONS.md) | the 419-optimization catalogue: every cache, fast path, parallel lane and campaign-level dead-air removal, with before/after benchmarks (`scripts/bench.py`, `scripts/bench_campaign.py`) |
| [docs/ETHICS-AND-LEGAL.md](docs/ETHICS-AND-LEGAL.md) | the authorisation gate and the law, before you point this at anything |
| [CHANGELOG.md](CHANGELOG.md) | what changed, batch by batch |

---

## Why another wifite?

`wifite` is excellent and battle-tested, but it is a 2013-era Python 2 script: no web
interface, no machine-readable state, no explanation of *why* it picks a target, and its
decision logic is a hard-coded priority list. `wifipilot` keeps the good part (drive the
aircrack-ng suite properly) and rebuilds everything around it:

| | wifite | wifipilot |
|---|---|---|
| Language / runtime | Python 2/3 script | typed Python 3 package, no build step |
| Interface | terminal menus | live rich TUI **and** a real web UI (WebSocket, REST) |
| Target selection | fixed priority list | scored, explainable, and optionally decided by a local LLM |
| Failure handling | retry the next attack | every failure is diagnosed ("no clients to deauth", "WPS locked") and fed back into the next decision |
| Capture validation | tool output only | parses pcap/pcapng itself: real EAPOL message pairing + PMKID KDE extraction |
| Cracking | hands off to aircrack | aircrack-ng, hashcat **and** a built-in pure-Python engine that verifies candidates by recomputing the PMKID/MIC |
| Explains itself | no | every plan, action and failure has a reason attached, in the report |
| Safety rails | — | authorisation gate, stealth mode, attack whitelist, plan validator, loopback-only LLM |

## Features

**Discovery**
- `airodump-ng` CSV parsing (APs, clients, signal, cipher/auth, beacons/data, hidden SSIDs)
- `wash` integration for real WPS state (version, locked, model, manufacturer)
- `iw`/`nmcli` interface enumeration with driver, bands, monitor/injection capabilities
- 2.4 GHz / 5 GHz / both, channel pinning or hopping, stale-target eviction

**Attacks**
- **PMKID** capture, client-less (hcxdumptool, with an own-parser sniffing fallback)
- **WPA/WPA2 handshake** capture: targeted deauth bursts, per-client or broadcast
- **mask attacks**: `--mask 'Telekom-?d?d?d?d'`, or the patterns the target itself suggests
  (ESSID prefix, vendor, ISP numeric defaults) — small spaces in the built-in engine, big ones
  handed to `hashcat -a 3`
- **WPS Pixie-Dust** (reaver `-K 1` / bully `--pixiewps`), plus opt-in online PIN recovery
  with vendor default-PIN algorithms tried first
- **WEP IV harvesting** with ARP replay
- **Passive** mode that never transmits anything

**Cracking**
- **strategy presets** instead of six flags: `--strategy quick|default|thorough|insane` plus
  `mask-only`, `wordlist-only` and `pixie-then-crack` (`wifipilot crack FILE --list-strategies`)
- **stage-ordered cracking** (`--crack-order targeted,masks,hashcat-masks,external,builtin`):
  the cheap target-derived candidates run first, the expensive sweep last, and a stage can be
  reordered or dropped without touching code
- **hashcat rule files** (`-r best64.rule`, or a built-in preset) applied to every wordlist in
  the built-in engine too, not only by hashcat
- hashcat (with rules; `hcxpcapngtool` is used when present, and the built-in writer
  produces mode 22000 itself)
- aircrack-ng, fed a rule-expanded candidate stream on stdin (aircrack has no rule engine)
- **hashcat mode 22000 in and out**: read a `.hc22000` someone sent you, or write one from a
  capture — no hashcat, no hcxtools, and the PMKID/ESSID bytes survive intact
- **built-in engine**: pure-Python PBKDF2 → PTK → MIC verification (HMAC-SHA1-128 for classic
  WPA2, AES-CMAC for 802.11w/PMF and SAE, HMAC-MD5 for TKIP) and
  PMKID recomputation. It cracks targeted candidate spaces with no GPU and no external tools,
  and it *proves* every password it reports.

**Analysis without a radio**
- **password analytics**: every cracked PSK gets a weakness verdict, its pattern family and
  time-to-crack estimates for four engines (`wifipilot analyze`/session report) — “how bad is
  this password”, not just the string
- **vendor intelligence**: an OUI registry plus per-vendor dossiers (default key scheme, WPS
  behaviour, bands, what to try first) — `wifipilot vendor d0:12:cb:00:00:01`. Dossiers are
  labelled heuristics, never findings
- **target scoping**: classify (`home-router`, `guest`, `iot`, …), tag, filter and select the
  targets of an engagement (`wifipilot targets --tag in-scope --select`), with notes and a
  per-AP history persisted to the session directory
- **file toolbox**: merge/dedupe/filter/split/normalize mode-22000 hash files, rescue the PMKID
  a converter drops (e.g. in message 1), wordlist stats/merge/rule-expansion, hashcat potfile
  import/export, and a sha256 manifest that proves the loot has not changed
- **benchmark**: `wifipilot benchmark` measures this machine's candidate rate and turns it into
  ETAs — no radio, no target, safe to run anywhere

**Intelligence (AI-piloted, and optional — off, local or cloud; all three work)**
- **deterministic planner**: scores every target, picks the attack order, triages failures and
  re-plans when a capture fails. It needs no model, no network and no key — it is what runs
  when nothing else is available, and equally what runs on purpose with
  `--no-ai`/`--disable-ai`, `wifipilot ai off`, `wp.ai(disable=True)` or `WIFIPILOT_NO_AI=1`
- **auto-think** (with a provider enabled): the advisor — the *pilot* — re-reads a compact
  situation report every N seconds and proposes the next actions with reasoning
- **failure triage**: natural-language diagnosis of why an attack failed and what to do next
- **chat**: ask about the running engagement ("what is the biggest risk we found?")
- **local by default**: free, offline, nothing leaves the machine — Ollama, or
  [Cortex LLMHoster](https://github.com/codero-sus/Cortex_LLMHoster) when you would rather
  have `llama.cpp` started for you behind an OpenAI-shaped API
- **cloud on request** (OpenRouter): opt-in with an API key, spend cap, provider routing and
  identifier redaction — SSIDs, BSSIDs, client MACs and recovered PSKs become
  `ssid-1`/`bssid-1`/`mac-1`/`psk-1` before they are sent, and are mapped back before the
  plan runs
- deterministic fallback planner whenever the model is disabled, missing, out of credit,
  rate limited or incoherent — the tool never stalls on the AI, and never asks for one

**Scriptable**
- `import wifipilot as wp` — `wp.attack(target=all, mode="force")`, `wp.scan()`, `wp.crack()`,
  event hooks, target selectors, modes, JSON results ([docs/PYTHON-API.md](docs/PYTHON-API.md))

**Reporting**
- JSON session export, Markdown engagement report, JSONL event journal, loot directory
- web UI: live target table, loot cards, plan viewer, chat, tool diagnostics

**Two front ends, one engine**
- **terminal dashboard** (`docs/TUI.md`): target table ranked by planner score, live vitals
  (APs, clients, attacks run/failed, captures, handshakes, PMKIDs, keys, audits), progress,
  event tail, and an `AI:` segment that says exactly who is deciding — with a plain-text
  fallback for pipes, logs and no-rich installs

### New ways in (added on top of the classic attacks)

- **Hidden-SSID discovery** — a hidden AP is a `?` only until a client says its name;
  probe responses, association requests and the handshake all carry it in the clear.
- **Rogue-AP / evil-twin survey** — one ESSID served by two vendors, or the same name
  at a wildly different signal, is what a twin looks like from outside. Reported as a
  heuristic pattern with the evidence attached (BSSIDs, vendors, dB spread).
- **802.1X survey** — EAP method, outer identity and the server certificate. The
  actionable finding is usually a self-signed certificate, because that is what makes
  a rogue RADIUS trivial; "WPA-Enterprise cracked" is almost always a misreading.
- **WPS PIN arithmetic** — checksum-valid candidates with provenance (vendor defaults,
  both published ComputePIN variants, BSSID junk), plus the attempt plan: 11,000
  attempts for the two-half attack versus 10⁷ for a blind sweep, stated in hours.
- **EAP decoding, offline** — `wifipilot eap capture.pcap` prints the EAP method, the
  outer identity (a username, unless it is `anonymous@…`) and the server certificate,
  including whether the subject and issuer are the same Name, which is what
  "self-signed, therefore impersonable" looks like in a capture.
- **Rogue RADIUS** — the test that survey implies: impersonate the AP for one
  association attempt and see whether the client hands over a credential. Any output
  is reported verbatim, nothing is guessed, and the tool is stopped either way.
- **Station tracking** — point wifipilot at one device and it reports the networks the
  device actually probes for (its real PNL), the APs it associates with, and its
  signal trend as you move. Read-only, and scheduled before anything noisy.
- **WPA3 answered honestly** — `saewolf` captures the SAE exchange and reads it (group,
  completeness, transition mode) while `pmf_audit` decodes the MFPC/MFPR bits and says
  which classic attacks are still possible. No offline attack on SAE exists, so none is
  simulated: the deliverable is the configuration finding.
- **The WEP family of five** — the harvest plus the four injection techniques that make
  it possible on a quiet network (P0841, chopchop, fragmentation, client-oriented
  fragmentation), each reported as capability or key recovery as appropriate.
- **An active PMKID hunt** — `pmkid_flood` deauthenticates until M1 carrying a PMKID
  arrives, so a quiet AP becomes an answer instead of a timeout.
- **Rogue infrastructure** — `evil_twin` (hostapd-mana/hostapd) measures which stations
  prefer the SSID; `rogue_radius` tests the certificate policy. Both stop themselves.
- **The element audit, live or offline** — `ie_audit` decodes what airodump's CSV
  throws away (RSN
  cipher/AKM suites, MFPC/MFPR, WPS state and configuration methods, HT/VHT/HE, 802.11r/k/v,
  country, rates, channel width, BSS load) and reports the configuration findings a
  report can act on: TKIP still advertised, PMF optional, WPS unlocked, 40 MHz in
  2.4 GHz. Read-only, and it annotates the session with element-level facts so the
  planner decides from the elements rather than from a guess. The same decoder is a
  command — `wifipilot decode capture.pcap` (and `wp.decode(...)`) reads an existing
  pcap with no radio and no authorisation, which is how a capture collected by somebody
  else becomes findings.
- **Preferred-network-list harvesting** — `pnl_harvest` reads the probe requests
  stations broadcast in the clear (even on WPA3) and builds the wanted list: which
  names are being asked for, by whom, and which of them nothing is serving. The
  trace lands in `reports/pnl.json` and is the target list a twin or Karma attack
  should serve.
- **Karma** — `karma` runs hostapd-mana with `enable_mana=1` and answers *every*
  probe: the network exists only because the client asked for it. Stations that join
  are the finding (they trust a name and nothing else); stations that refuse are the
  other finding, and the probed SSIDs are intelligence either way.
- **An unauthenticated disconnect test** — `eapol_logoff` builds the three-field
  EAPOL-Logoff frame itself (PMF does not cover it) and sends three frames per client,
  then watches for reassociation. It is a client-behaviour measurement, explicitly not
  a handshake technique.
- **Denial-of-service *detection* tests** — `deauth_flood`/`auth_flood`/`probe_flood`/
  `beacon_flood`, capped at 45-60 s, whose only deliverable is whether the site's
  monitoring notices (and, for the deauth flood, whether 802.11w is real).
- **BLE keystroke injection, the whole path** — `ble_hid` advertises the HID-over-GATT
  service, enumerates the report characteristic over ATT and delivers the payload as
  eight-byte boot reports, decoded back with the toolkit's own decoder so the finding
  names what the host typed. `ble_hid_reconnect` is the identity attack above it:
  advertise as the keyboard the host already bonded — its name and its address — and
  count the hosts that reconnect to those rather than checking the link key. The payload
  defaults to `id` followed by Enter, and it is typed character by character: letters,
  digits, punctuation, spaces and the control characters, with anything a boot keyboard
  cannot spell reported rather than silently dropped.
- **The BLE downgrades, and the proof that they landed** — `ble_hid_boot` writes the HID
  protocol mode back to boot protocol and reads the value back; `ble_smp_downgrade`
  offers every pairable device Just Works with a seven-byte key and reports the key size
  each one settled for; `ble_gatt_hijack` writes a control characteristic of a lock or a
  scooter and reads it back, because an acknowledged write that cannot be confirmed is a
  claim rather than a finding.
- **Following a device through its "anonymous" addresses** — `ble_irk_resolve` tests
  every address on air against the identity resolving keys that leak (vendor examples,
  stack defaults, a firmware dump) with the specification's own ``ah`` function, and a
  match is arithmetic rather than a guess: the toolkit's implementation is checked
  against the Core Specification's sample data.

## Install

Requires Linux (Kali, Parrot, Debian, Ubuntu, Arch, Fedora …) and Python 3.9+.

```bash
git clone https://github.com/codero-sus/WiFi-Pilot
cd WiFi-Pilot
pip install -e .            # core CLI (needs only `rich`)
pip install -e '.[web]'     # + FastAPI/uvicorn for the web UI
wifipilot tools install     # install every external dependency (aircrack-ng, hashcat, …)
wifipilot tools install --yes   # …for real, after showing you the plan
```

External tools (install what you need — `wifipilot tools` tells you exactly what is missing):

```bash
# Debian/Ubuntu/Kali
sudo apt install aircrack-ng reaver bully pixiewps hcxtools hashcat iw rfkill
# Arch
sudo pacman -S aircrack-ng reaver bully pixiewps hcxtools hashcat iw rfkill
# optional, one attack family each
sudo apt install mdk4          # deauth_flood / beacon_flood
sudo apt install hostapd       # evil_twin (hostapd-mana is better: it answers probes)
sudo apt install wpasupplicant # client-side checks
```

Minimum for a live run: `aircrack-ng` (provides `airmon-ng`, `airodump-ng`, `aireplay-ng`).
Everything else unlocks extra attacks. **No tools and no radio? Use `--demo`.**

**Nothing above is required to use wifipilot**: the deterministic planner runs the whole
engagement without a model. If you want the optional advisor, a local model is the default:

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.1:8b        # or qwen2.5:7b / mistral:7b — anything 3–14B works
wifipilot ai status
```

...and the three equivalent ways to turn the advisor off again:

| where | how |
| --- | --- |
| CLI | `wifipilot --no-ai …`, `wifipilot --disable-ai …`, `wifipilot --offline …`, or `wifipilot ai off [--save]` |
| Python | `wp.ai(disable=True)` — `wp.ai(disable=False)` restores the previous provider |
| environment | `WIFIPILOT_NO_AI=1` (also `true`/`yes`/`on`) |

`wifipilot ai on`, `wp.ai(provider="ollama")` and `wifipilot ai toggle` switch it back.
While it is off, `wifipilot ai status` says so instead of probing, `wifipilot ai models`
returns nothing instead of calling a daemon, and the web UI greys the advisor tab out.

Or cloud, if you would rather not run a model locally:

```bash
export OPENROUTER_API_KEY=sk-or-v1-...      # create a key at openrouter.ai/keys
wifipilot --provider openrouter --ai-budget 0.50 ai providers --probe
wifipilot --provider openrouter --model openai/gpt-4o-mini attack -d 45m
```

Or the local OpenAI-compatible host, if that is what you already run:

```bash
cortex-llmhoster --config cortex.toml           # 127.0.0.1:8624 by default
wifipilot --provider cortex --cortex-model qwen-local attack -d 45m
```

OpenRouter is off until you enable it; identifiers are pseudonymised by default; see
[docs/AI-PROVIDERS.md](docs/AI-PROVIDERS.md) for key handling, costs and the privacy model.

## Use it as a library

Everything the CLI does is a Python call, so wifipilot can be a stage in a bigger
tool (a scheduler, a report pipeline, another UI):

```python
import wifipilot as wp

# rehearse the whole pipeline with no radio and no risk
wp.attack(target=all, mode="force", demo=True, duration="2m")

# a real, authorised engagement; "force" runs all 848 attacks, "stealth" is listen-only
wp.authorize("change ticket CHG-4711, client ACME Labs")
result = wp.attack(target="Cafe Guest", mode="default", duration="45m",
                   on_event=lambda event: print(event.kind, event.data))

for hit in result.passwords:                 # verified PSKs, with their access point
    print(hit["essid"], "->", hit["password"], f"({hit['kind']})")
result.save("engagement.json")               # or markdown=True
```

```python
wp.scan(duration="30s")                    # -> ScanResult (.aps sorted by score)
wp.crack("capture.cap", wordlist="rockyou.txt")   # -> CrackResult (.cracked/.password)
wp.analyze("capture.cap")                  # EAPOL/PMKID inventory of a file
wp.set_provider("openrouter", model="openai/gpt-4o-mini", ai_budget=0.50)
wp.status()                                # provider, targets, loot, spend
```

Live runs raise `wp.AuthorizationError` unless you called `wp.authorize(...)` (or
passed `authorized=True`); on non-Linux machines calls raise `wp.PlatformError`
(importing is always safe).  Give scripted runs an explicit `duration`: without
one a campaign continues until the planner runs out of targets.  Full reference —
the pipeline, target selectors, mode presets, event hooks and error taxonomy — is in
[docs/PYTHON-API.md](docs/PYTHON-API.md), with runnable scripts in
[`examples/`](examples/) (`make api-demo`).

## Quickstart (no hardware required)

```bash
wifipilot demo          # full pipeline against a simulated neighbourhood
wifipilot --demo scan   # just discovery, live table
wifipilot web --demo    # web UI in simulation mode (http://127.0.0.1:8787)
```

The simulation drives the **real** code path: a fake radio produces beacon/client records,
the scanner parses them, the planner scores them, the attacks run and produce captures that
are *cryptographically valid* (real PBKDF2/PTK/AES-CMAC values), and the cracker cracks them.
Only the radio is fake — which is why the demo is also the test suite's end-to-end test.

The two non-radio editions have their own simulation, and neither is a stub:

| simulated environment | what answers | look at it |
|---|---|---|
| **Bluetooth floor** — `blesim.py` | a virtual controller (HCI in, H4 events out) and 66 devices across 14 posture profiles: a KNOB-vulnerable soundbar, an open GATT band, a fragile stack, an OBEX object store, five HID hosts bonded to one keyboard (three that take a stranger's keystrokes and two that check the peer), trackers and beacons. The L2CAP, ATT, SMP, SDP, RFCOMM, AT and OBEX engines answer with real protocol bytes, so the same parsers read a demo run and a live one — and the floor is also written as a real `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR` capture for the offline audits | `wifipilot sim --domain bluetooth --list` |
| **IT segment** — `itsim.py` | 51 hosts (routers, cameras, PLCs, printers, a domain controller) across six postures, with 72 open ports and 45 protocol responders — HTTP, SMB, Modbus, IPP, LDAP, MySQL, MQTT, CoAP, SSDP, mDNS and the rest | `wifipilot sim --domain it --list` |

`wifipilot sim` (or `wp.simulations()` / `GET /api/sim`) prints what both contain, including
every simulated device and host, so a demo run can be inspected rather than taken on faith.

## Real engagement

```bash
# 0) look before you leap
sudo wifipilot tools                  # adapter monitor-mode/injection capabilities
sudo wifipilot scan -t 45             # passive discovery only

# 1) dry run without transmitting
sudo wifipilot -y --attacks passive attack -d 10m

# 2) full campaign, AI-piloted
sudo wifipilot -y --model qwen2.5:7b attack -d 45m

# ...or the same campaign with no model in the loop at all
sudo wifipilot -y --no-ai attack -d 45m

# 3) constrain the scope to specific BSSIDs and be gentle
sudo wifipilot -y --stealth -b AA:BB:CC:DD:EE:FF attack -d 20m
```

What happens next:

1. the adapter is put into monitor mode (`airmon-ng`, falling back to `iw`), interfering
   services are stopped, and the original MAC/channel is restored on exit;
2. targets are discovered and scored (signal, encryption, WPS state, clients, prior failures);
3. the advisor picks actions — with a reason for each — and they run in priority order
   (with the advisor off, the deterministic planner picks the same actions, minus the prose);
4. every capture is validated before it is believed;
5. whenever a handshake/PMKID lands, the cracker tries it (targeted candidates first);
6. at the end: `loot/` holds the captures, `sessions/<id>/` holds the journal and report,
   and a Markdown report is written for the client.

Press `Ctrl+C` once for a clean stop (interface restored, report written).

## Presets: finished in minutes, not an hour

848 attacks at full per-attack budgets is a recipe for an hour-long run. A **preset**
fixes that: a named set of attacks with scaled budgets, a hard per-attack cap (a
watchdog stops anything that overruns), parallel side lanes for IT/offline work,
background cracking, and a whole-campaign deadline. One Wi-Fi network lands in the
**7–12 minute** window.

```bash
wifipilot presets                          # the menu, with sizes and time budgets
sudo wifipilot -y attack --preset success  # highest-success-chance route to a key, ~10 min
sudo wifipilot -y attack --preset blitz    # the four classic key attacks, ~7 min
```

| preset | what it is |
|---|---|
| `success` | PMKID/handshake capture, WPS pixie + offline PIN, WEP, then the audits — pick this when the goal is *getting in* |
| `blitz` | the fastest possible answer: key recovery only |
| `balanced` | sensible default audit (alias `default`) |
| `stealth` | listen-only: no injection, no floods (alias `passive`) |
| `survey` | discovery across Wi-Fi, Bluetooth and the LAN |
| `rogue` | evil twin, Karma, captive portal, rogue DHCP/DNS |
| `enterprise` | 802.1X: rogue RADIUS, EAP harvest, MSCHAPv2 |
| `disrupt` | DoS testing, every flood hard-capped |
| `bluetooth` / `it` | the two side editions, highly parallel |
| `full` | all 848, but with the speed governor on |

Every preset has **postures**. `--preset success:force` (or `--force`) is **FORCE** —
the opposite of stealth: it wants success rather than subtlety (aggressive mode,
broadcast handshake deauth, boosters like `wps_pin`, bigger crack budgets).
`:stealth` strips everything that transmits. From Python:
`wp.attack(target=all, preset="success:force")`.

Real hardware joins in **by default** (`--accel auto`): multiprocessing
candidate verification across every CPU core, parallel attack lanes, RAM
candidate caching, and the GPU (via hashcat) when one is detected.
`wifipilot tools` shows what was found; `--accel off` restores the classic
single-threaded run for tiny VMs:

```bash
sudo wifipilot -y attack --preset success              # auto: CPU + RAM (+ GPU if present)
sudo wifipilot -y attack --preset success --accel off  # one thread, like the old days
```

Missing tools? `wifipilot tools install` prints the exact plan for your distro
(apt/pacman/dnf/zypper/apk); `--yes` runs it. Keeping current is one command too:
`wifipilot update --yes` downloads the latest snapshot and swaps it in (backup kept).

## The terminal UI

Anything long-running gets a live dashboard instead of a wall of scrolling text:

```
  SIMULATION   phase: attacking  iface: —  uptime: 4m12s  loot: 2  PSKs: 1  AI: off · deterministic
  APs 11 clients 23 attacks 12 run / 2 failed captures 3 handshakes 1 PMKIDs 1 keys 1 audits 0 decisions deterministic

SSID                  BSSID                    CH   SIG  SEC          WPS          CLI  LOOT       BY     NEXT
HOME-2F4A             d0:9e:12:9d:36:cc         6   -39  WPA2         unlocked       3  HS PMKID   llm    handshake/crack
```

The **`AI:` segment is the honest one** — `AI: qwen2.5:7b ·3 calls` when a model is planning,
`AI: offline → heuristics` when a configured provider is not answering, and
`AI: off · deterministic` when you switched it off. The vitals strip below it repeats the
distinction (`decisions deterministic` vs `decisions model + planner`), the target table is
ranked by the planner's score with loot, selector and next-attack columns, and the event panel
is the same bus the web UI reads. No rich/no colour/`--json`? The same information streams as
plain lines on stderr, so pipes and logs stay clean.

There are no keyboard controls by design: an accidental keystroke must never fire a radio.
Full reference: [docs/TUI.md](docs/TUI.md).

## The web UI

```bash
wifipilot web                 # live mode, http://0.0.0.0:8787
wifipilot web --demo --open   # simulation + opens your browser
```

![tabs: targets · loot · AI advisor · log · tools & settings](docs/web-ui.md)

* **Targets** — live table (SSID, BSSID, channel, signal, security, WPS state, clients, loot,
  score, who decided) with per-row attack/crack buttons and a detail drawer showing clients
  and full attack history.
* **Loot** — every capture with its verification status, recovered PSK, and download links.
* **AI advisor** *(optional — greyed out and inert when the advisor is off, with a one-click
  "turn it back on" banner)* — Ollama status, model picker, `ollama pull` from the browser, the
  last plan with its reasoning and the actions the safety validator rejected, plus a chat panel
  with one-click prompts. The header badge reads `ai: off · deterministic planner` while it is
  disabled, and every button that would need a model is disabled with it.
* **Log** — the live event stream and progress bar, identical to the CLI.
* **Tools & settings** — dependency report with install hints, interface capabilities, attack
  toggles, wordlists, engagement settings.

The UI is a *remote control* for the same engine the CLI uses — same events, same code paths,
no duplicated logic. Everything is served from relative URLs, so it works behind a reverse
proxy or an SSH tunnel (`ssh -L 8787:localhost:8787 box`).

> The UI binds `0.0.0.0` by default so containers and tunnels work out of the box. On an
> untrusted network, bind loopback instead: `wifipilot web --host 127.0.0.1`.

## Optional: the advisor (a local model, or OpenRouter)

**Skip this section if you do not want a model in the loop.** Everything above works without
it; this is the extra. Two providers, one advisor. Switching is a flag, a config key, a
click in the web UI, or one line of Python (`wp.ai(disable=True)`):

```bash
wifipilot ai providers                      # what is configured / what is missing
wifipilot ai status                         # active provider, model, quota, spend
wifipilot ai off                            # stop using a model (add --save to remember)
wifipilot ai on [ollama|openrouter|auto]    # ...and switch it back on
wifipilot ai toggle                         # flip it, whatever it currently is
wifipilot ai models [--search qwen] [--free]
wifipilot ai use openai/gpt-4o-mini --provider openrouter --save
wifipilot ai ask "which target first?" --report sessions/…/reports/report.json
```

| | Ollama | OpenRouter |
|---|---|---|
| runs on | this machine | a third-party cloud service |
| data sent | nothing | the situation report, with identifiers pseudonymised |
| cost | free | per token, hard-capped by `--ai-budget` |
| default | **yes** | opt-in (`--provider openrouter` + key) |

How it works, whichever provider is active:

* wifipilot builds a **compact situation report** (targets with state, recent attempts and
  failures, enabled attacks, time budgets, capabilities) — a few hundred tokens, not a log.
* the model gets a tactical system prompt with a closed action vocabulary
  (`pmkid`, `handshake`, `wps_pixie`, `wps_pin`, `wep_ivs`, `passive`, `crack`, `stop`) and
  returns JSON: reasoning + prioritised actions.
* **every** model response passes through `planner.validate_plan()`, which drops unknown
  attacks, unknown BSSIDs, disabled attacks, WPA3 handshake attempts, WPS attacks on
  non-WPS APs, cracking without captures, and anything stealth mode forbids. Rejections are
  shown in the UI and logged, so you can see when the model was overruled.
* when the provider is down, out of credit, over budget, rate limited, or returns nonsense,
  the **deterministic planner** takes over seamlessly. The campaign never blocks on a model.

### Privacy and cost on the cloud provider

* OpenRouter only runs when explicitly enabled **and** a key is present; the key comes from
  `OPENROUTER_API_KEY`, a key file, or the config (written mode 600, never returned by the
  API, never printed — only its source and length are).
* SSIDs, BSSIDs, client MACs and recovered PSKs are replaced with stable pseudonyms
  (`ssid-1`, `bssid-1`, `mac-1`, `psk-1`) before the report is sent, and mapped back before
  the plan is validated. Disable with `--no-ai-redact` if you need the model to see real names.
* `--ai-budget 0.50` stops planning at $0.50 of spend for the session; usage and cost per
  call are tracked and reported. Provider routing (e.g. `"sort": "throughput"`) passes through.
* HTTPS only, unless the base URL is loopback (a local proxy).

Details, including the full failure matrix and model recommendations:
[docs/AI-PROVIDERS.md](docs/AI-PROVIDERS.md).

## Attacks

**848 attacks in three editions** — 288 on the WiFi radio, 143 on Bluetooth, 417 against
the devices and services behind the bridge — and the list is not a tool inventory: every
entry either answers a question an assessment has to answer or produces loot that can be
cited. They are grouped by what they cost (`wifipilot attacks` prints the same catalogue
the planner, the web UI and the report read; `wifipilot attacks --domain it` prints one
edition, `wifipilot --edition it attack` plans one):

| family | what it is | examples |
|---|---|---|
| **offline** | pure file analysis — no radio, no monitor interface, no authorisation | `loot_audit`, `eapol_audit`, `crack_sweep`, `eap_md5_crack`, `pixie_offline` |
| **survey** | reads the air and decodes what is already there | `passive`, `ie_audit`, `pmf_audit`, `saewolf`, `sae_group_audit`, `hidden_ssid`, `pnl_harvest` |
| **capture** | asks for material that can be cracked later | `pmkid`, `handshake`, `handshake_broadcast`, `hcxdump_capture`, `pmkid_flood` |
| **wps / wep / enterprise** | the protocol-specific paths | `wps_pixie`, `wps_ap_pin`, `wps_lockout_probe`, `wps_pbc`, `wep_ivs`, the four WEP enablers, `enterprise`, `eapol_logoff` |
| **rogue** | impersonation and lures | `evil_twin`, `karma`, `karma_detect`, `csa_attack`, `ssid_confusion`, `ssid_bruteforce`, `ap_isolation_audit`, `rogue_radius` |
| **dos** | deliberate disruption, opt-in and time-capped, with detection as the finding | `deauth_flood`, `assoc_flood`, `null_data_flood`, `eapol_start_flood`, `sae_commit_flood`, `tkip_michael`, `wids_confusion` |
| **bluetooth** | the second radio: censuses, beacons, trackers, pairing, the link layer — and the BLE wave, which impersonates the keyboard a host already trusts and types on it | `bt_device_census`, `bt_tracker_detect`, `bt_gatt_enumeration`, `ble_hid`, `ble_hid_reconnect`, `ble_smp_downgrade`, `ble_irk_resolve` |
| **network** | the layer behind the bridge: DHCP, TCP/IP, name resolution, layer 2, IoT services | `dhcp_starvation`, `dhcp_lease_audit`, `syn_flood`, `rogue_ra`, `llmnr_poisoning`, `pjl_printer_audit` |
| **discovery** (IT) | the service and device census, one protocol at a time, and the two audits every service gets: the version read checked against the advisory list and the proof that the protocol carries its traffic in the clear | `it_http_discover`, `it_mdns_service_census`, `it_host_discovery`, `it_rtsp_version_audit`, `it_telnet_cleartext_audit` |
| **exploit** (IT) | the device and service attacks: default credentials, anonymous access, unauthenticated writes, config dumps, protocol abuse — cameras, printers, PLCs, building systems, servers, VoIP and smart home | `it_rtsp_anonymous`, `it_ipp_default_creds`, `it_modbus_unauth_write`, `it_s7comm_config_dump`, `it_sip_default_creds`, `it_kasa_unauth_write` |

Every attack carries a category, a **noise** level (how visible it is), an **impact**
level (what changes for the site if it works) and a sentence about **what a defender
sees**. `wifipilot attacks --json` returns the lot; `--no-radio` filters it to the
**121** attacks that transmit nothing at all.

The full reference — what each attack answers, what it costs, and how to read a
failure — is in [docs/ATTACKS.md](docs/ATTACKS.md). The short version:

| Attack | Tool | Disruptive? | Notes |
|---|---|---|---|
| `ie_audit` | wifipilot (own IE decoder) | **no** | reads every beacon-like frame's elements — RSN, WPS, HT/VHT/HE, 802.11r/k/v, country, rates, BSS load — and reports the configuration findings (TKIP, PMF optional, WPS unlocked, 40 MHz in 2.4 GHz). Read-only, and it annotates the session for the planner |
| `pnl_harvest` | wifipilot (own probe decoder) | **no** | the preferred network list, out loud: which SSIDs stations ask for, and which of them are not on air. Writes `reports/pnl.json` as the target list for the twin/Karma stage |
| `pmkid` | hcxdumptool / own sniffer | no | client-less, first choice for WPA2 |
| `handshake` | airodump-ng + aireplay-ng | **yes** (deauth) | needs a client; fails vs WPA3-SAE/PMF |
| `wps_pixie` | reaver `-K 1` / bully `--pixiewps` | mildly | usually <60 s on vulnerable chipsets |
| `wps_pin` | reaver / bully | **yes, slow** | opt-in only; can lock WPS permanently |
| `pmkid_flood` | airodump-ng + aireplay-ng deauth | **yes** (repeated deauth) | the active PMKID hunt: force a quiet client to reconnect so M1 with the PMKID is sent. Stops the moment one lands; "AP never sent the KDE" is itself the answer |
| `wep_ivs` | airodump-ng + aireplay `--arpreplay` | yes | legacy networks |
| `wep_p0841` | aireplay-ng `-2 -p 0841` | yes | injects its own ARP, so the IV harvest runs on a network where no client is talking |
| `wep_chopchop` | aireplay-ng `-4` | yes | keystream from one packet, no client needed — this is an **enabler**, not a key recovery |
| `wep_fragment` | aireplay-ng `-5` | yes | the fast fragmentation variant of the same idea |
| `wep_hirte` | aireplay-ng `-7` | yes | client-oriented fragmentation: keystream from a client's traffic when the AP will not answer |
| `saewolf` | airodump-ng + own SAE decoder | **no** | captures the WPA3 SAE commit/confirm exchange and reports the group, whether it completed, and whether the WPA2 path is still advertised. SAE cannot be cracked offline and this attack never claims otherwise |
| `pmf_audit` | wifipilot (offline RSN decoder) | **no** | reads the MFPC/MFPR bits airodump's CSV does not carry and says which classic attacks are still possible: no required PMF, transition mode, OWE transition |
| `evil_twin` | hostapd-mana / hostapd | **yes** (impersonation) | serves the target SSID and measures who prefers it. With the PSK known the network can be *replaced* (high); otherwise the finding is the list of stations that tried |
| `karma` | hostapd-mana (`enable_mana=1`) | **yes** (impersonation) | answers every probe with the name the client just asked for. Stations that join prove they trust a name and nothing else; stations that refuse are reported as the correct behaviour. Anything the daemon prints (including credentials, if a station offers them) is reported verbatim |
| `eapol_logoff` | wifipilot `rawtx.py` (AF_PACKET) | **yes, 3 frames/client** | an EAPOL-Logoff has no authentication field, so 802.11w does not stop it: the attack measures whether the client accepts a disconnect from "the AP". Bounded, and never a handshake — it is a client-behaviour finding |
| `deauth_flood` | mdk4 `d` | **yes, heavily** | ≤60 s denial-of-service *detection test*: is 802.11w/WIDS really deployed, or only documented? |
| `auth_flood` | mdk4 `a` | **yes, heavily** | ≤45 s: fills the AP's association table and answers "is there a limit, and does anybody notice?" |
| `probe_flood` | mdk4 `p` | **yes, heavily** | ≤45 s of probe requests with random SSIDs: the target is the clients' scan lists and the WIDS's alerting, not the AP |
| `beacon_flood` | mdk4 `b` | **yes, heavily** | ≤45 s beacon flood; the finding is whether the site notices |
| `hidden_ssid` | airodump-ng | **no** | names a hidden network from probe responses, associations or the handshake; `--reveal-with-probe` sends the one directed probe |
| `rogue_ap` | wifipilot (offline) | **no** | compares every ESSID against its BSSIDs, vendors and signal spread, and against the names clients are probing for — reports twins as a *pattern*, never as an accusation |
| `enterprise` | airodump-ng | no | 802.1X survey: EAP method, outer identity, server certificate — all decoded offline; identical subject/issuer means self-signed, i.e. impersonable. There is no PSK to crack |
| `rogue_radius` | eaphammer / hostapd-mana / hostapd-wpe | **yes** (impersonation) | The test the survey implies: impersonate the AP for one association attempt and see whether the client hands over a credential or "only" its identity. Output reported verbatim; the rogue service is always stopped |
| `tracker` | airodump-ng (listen-only) | no | Follow one station: the SSIDs it really probes for, the BSSIDs it associates with, and its signal trend as you walk. Decides which name is worth impersonating, before anything transmits |
| `passive` | airodump-ng | no | listen-only; harvests what is on air, then runs the two read-only decoders over the result (`ie_audit`, `pmf_audit`, `pnl_harvest`) |
| `loot_audit` | wifipilot (hash22000.py) | **no** | everything the engagement holds, in one place: what is crackable, what is a duplicate, and every hash line it can produce. No radio, no authorisation, no root |
| `eapol_audit` | wifipilot (pcap.py) | **no** | decodes the EAPOL exchanges already captured and reports what is *missing* (no ANonce, key-version mismatch, M1/M2-only pairs) before anything tries to crack them |
| `wep_audit` | wifipilot (pcap.py) | **no** | counts IVs, unique IVs and ARP frames in a WEP capture and says whether it is crackable *now* or needs another harvest |
| `crack_sweep` | wifipilot (crack.py) | **no** | every usable hash the session holds, swept through the cracker with a per-capture time budget; the batch version of `wifipilot crack` |
| `eap_md5_crack` | wifipilot (sniff.py) | **no** | EAP-MD5 is the one 802.1X method whose exchange is checkable offline: `MD5(identifier ‖ password ‖ challenge)` against a wordlist |
| `pixie_offline` | pixiewps | **no** | runs pixiewps against a WPS exchange already captured (`wps_pixie` with the radio unplugged) |
| `rogue_detect` | wifipilot (sniff.py) | **no** | rogue and cloned-AP patterns in the captures: same ESSID, incompatible vendors, suspicious signal spreads |
| `twin_detect` | wifipilot (sniff.py) | **no** | the twin-specific half: one name, several BSSIDs, and whether any of them moved channel mid-capture |
| `roam_audit` | wifipilot (ies.py) | **no** | 802.11k/r/v and PMF posture — the elements that decide whether a forged CSA/deauth would land at all |
| `wps_lockout_audit` | wifipilot (wps.py) | **no** | the lockout policy of the WPS APs already seen, from what was captured |
| `handshake_broadcast` | airodump-ng + aireplay-ng `-0` | **yes** (every client) | the blunt handshake: deauth *all* clients at once for more chances. Opt-in (`broadcast_handshake = true`), and the report says what that costs in visibility |
| `hcxdump_capture` | hcxdumptool + hcxpcapngtool | **yes** | the hcxtools pipeline: one bounded session, converted to hashcat mode 22000. No client needed, its own air policy, and `crack_sweep` for the next step |
| `sae_group_audit` | wifipilot (wpa3.py) | **no** | which SAE groups the network uses (22/23/24 are the Dragonblood ones), whether a SAE-EXT-KEY AKM is advertised, and whether PMF is required |
| `wps_ap_pin` | reaver `-p` | yes | the *static AP PIN*: vendor algorithms derive it from the BSSID, and on those devices it never changes |
| `wps_lockout_probe` | reaver | **three frames** | three deliberately wrong PINs, then stop: does the AP lock WPS, and after how many failures? That decides whether an online walk is worth hours of radio |
| `wps_pbc` | wpa_supplicant `wps_pbc` | yes | push-button enrolment: is a window open? Inside it, anything in range can enrol as a registrar |
| `karma_detect` | wifipilot (rawtx.py) | yes, quietly | probe for names that *cannot* exist: a device that answers several is Karma/MANA — this one hunts the attacker |
| `csa_attack` | wifipilot (rawtx.py) | **yes** | a forged Channel Switch Announcement in the AP's own name: clients leave the channel with no deauth frame anywhere |
| `ssid_confusion` | wifipilot (rawtx.py) | **yes** | the same SSID from a new BSSID: do clients select a network by name alone? |
| `ssid_bruteforce` | wifipilot (rawtx.py) | yes, patient | one directed probe per second against a hidden AP: a misconfigured AP answers for the name it hides |
| `ap_isolation_audit` | wifipilot (rawtx.py) | yes, quietly | a spoofed ARP between two clients: if a reply comes back, the AP bridged their traffic and the "guest" network is flat |
| `assoc_flood` | wifipilot (rawtx.py) | **yes, heavily** | association requests from thousands of fake stations: the *association* table is the resource that runs out. Built in-process — no mdk4 needed |
| `null_data_flood` | wifipilot (rawtx.py) | **yes, heavily** | QoS Null frames with the power-save bit: the AP buffers for stations that never wake, and no deauth frame is ever sent |
| `eapol_start_flood` | wifipilot (rawtx.py) | **yes, heavily** | EAPOL-Start from fake supplicants: 802.1X session exhaustion, the enterprise shape of the same attack |
| `sae_commit_flood` | wifipilot (rawtx.py) | **yes, heavily** | SAE commits with random scalars: every one costs the AP a scalar multiplication before any authentication |
| `tkip_michael` | wifipilot (rawtx.py) | **yes, extreme** | replay two captured TKIP frames with the MIC corrupted: the Michael countermeasure silences TKIP for 60 seconds. No key needed |
| `wids_confusion` | wifipilot (rawtx.py) | **yes, extreme** | deauths carrying a *neighbour's* BSSID: anything that attributes attacks by transmitter address blames the wrong network |

Only `hidden_ssid --reveal-with-probe`, `rogue_radius`, `evil_twin`, `karma`,
`eapol_logoff`, the four floods and the classic attacks transmit anything; `rogue_ap`,
`enterprise`, `tracker`, `saewolf`, `ie_audit` and `pnl_harvest` are pure analysis of
frames already on disk, and need no authorisation for the part that only reads. The
floods are the attacks to argue about before running: they are the only ones whose value
is entirely in what the defender does about them.
`saewolf`/`pmf_audit` are the WPA3 story: capture the SAE exchange and read it, then say
in plain words that the WPA2 transition path — not the SAE exchange — is the way in. `rogue_radius` is the opposite end of the
same idea as `enterprise`: one reads the certificate, the other tests whether anybody
checks it.

## Cracking

Three engines run in order, and every reported password is verified:

```bash
wifipilot crack loot/handshake-HOME-2F4A-*.cap -e HOME-2F4A
wifipilot crack capture.pcapng -b AA:BB:CC:DD:EE:FF -w rockyou.txt --engine hashcat
wifipilot crack capture.cap -e HOME-2F4A --mask 'HOME-?d?d?d?d'   # router default numbering
wifipilot analyze capture.pcapng          # what is actually in this file?
wifipilot analyze --masks -e HOME-2F4A    # what would the mask stage try, and how big?
```

The stages a single `crack` run goes through:

| # | stage | why here |
| --- | --- | --- |
| 1 | target-derived candidates (ESSID words, vendor, dates, leet) | microseconds each, high hit rate |
| 2 | masks (patterns from the ESSID/vendor, plus any `--mask`) | router defaults are not dictionary words |
| 3 | `hashcat -a 3` for the masks too big for Python | a GPU eats 10⁸ candidates |
| 4 | wordlists through hashcat / aircrack-ng (rules) | the classic path |
| 5 | wordlists through the built-in engine | works on a machine with no tools at all |

The built-in mask stage is *budgeted* (`--mask-candidates`, default 10000 ≈ 25 s): a mask bigger
than the budget is named in the log with its size and left to hashcat, never half-swept in
silence.  `--no-masks` turns the stage off.

1. **hashcat** (`-m 22000`, rules, status parsing) when installed — and `.hc22000` files
   crack with the built-in engine even where hashcat is not;
2. **aircrack-ng** with a rule-expanded candidate stream on stdin;
3. **built-in engine** — PBKDF2 → PTK → MIC (HMAC-SHA1-128 / AES-CMAC / HMAC-MD5, picked
   per frame from the Key Descriptor Version), or PMKID recomputation.
   Also used to *verify* what the external tools claim, so "cracked ✓ verified" means the
   MIC or PMKID actually matched.

## Hash files (hashcat mode 22000)

`wifipilot export` writes the format every cracking tool speaks, from wifipilot's own parser —
no `hcxtools`, no hashcat:

```bash
wifipilot export loot/handshake-01.cap              # -> handshake-01.hc22000
wifipilot export loot/*.cap --out hashes/           # one file per capture
wifipilot export capture.cap --eapol-only --out -   # to stdout, handshakes only
wifipilot export capture.cap --format csv           # sheet: one row per handshake
wifipilot export capture.cap --hcxtools             # prefer hcxpcapngtool when installed
```

Both kinds of line are written and read: `WPA*01` PMKIDs and `WPA*02` EAPOL message pairs, with
the MIC zeroed in the EAPOL field, the ANonce where hashcat expects it, the ESSID hex-encoded so
even a non-UTF-8 network name round-trips, and the message-pair byte describing the pair
(`00` = M1+M2 challenge, `02` = M2+M3 authorized, ...).  The Key Descriptor Version travels with
the frame, so the MIC algorithm is the right one per line — HMAC-SHA1-128 for classic WPA2,
AES-128-CMAC for 802.11w/PMF and SAE, HMAC-MD5 for TKIP.

Reading them back needs no radio, no hashcat and no converter:

```bash
wifipilot analyze web.hc22000                # what is in the file, and what is testable
wifipilot crack web.hc22000 -w rockyou.txt   # built-in engine first, then aircrack/hashcat
```

```python
import wifipilot as wp
wp.export("loot/handshake-01.cap")           # -> loot/handshake-01.hc22000
wp.analyze("web.hc22000")["verifiable"]      # how many lines can be checked at all
hit = wp.crack("web.hc22000", wordlist=["rockyou.txt"])
hit.cracked, hit.password, hit.verified
```

A line whose client nonce was zeroed on air cannot be verified by anyone (hashcat calls those
unbreakable): it is reported as "no usable nonce" rather than counted as a failure.

## CLI reference

```
wifipilot scan   [-t 30] [--band 2.4GHz|5GHz|both] [--save out.json]
wifipilot attack [-b BSSID] [--time 30s] [-d 45m] [--no-scan] [--skip-crack]
                 [--client MAC]        # handshake: deauth that station only; tracker: follow it
wifipilot demo
wifipilot web    [--host 0.0.0.0] [--port 8787] [--open]
wifipilot crack  FILE [FILE…] [-b BSSID] [-e ESSID] [--engine auto|aircrack|hashcat]
                 [--strategy NAME|--list-strategies] [--rule-file FILE]
                 [--mask PATTERN] [--mask-candidates N] [--no-masks]
wifipilot analyze FILE [FILE…] [--masks [-b BSSID] [-e ESSID]]
wifipilot survey [CAPTURE] [--limit N]     # probes, deauths, twins — read-only
wifipilot eap    FILE [--limit N]          # 802.1X: method, identity, certificate
wifipilot pins   [BSSID] [-e ESSID] [--vendor NAME] [--first-half 1234] [--limit N]
wifipilot pmk    verify  FILE… --psk PSK [-e ESSID]
wifipilot pmk    convert FILE… --psk PSK [--out out.hc22001]
wifipilot pmk    show    FILE            # read a mode-22001 (PMK) file
wifipilot pmk    cache   [--session-dir DIR]

wifipilot targets [--kind home-router] [--tag in-scope] [--vendor AVM] [--cracked|--loot]
                  [--encryption WPA2] [--channel N] [--select] [--kinds] [--report export.json]
wifipilot tag     [BSSID TAG] [--remove] [--list]
wifipilot note    [TEXT] [--list] [--history] [--bssid BSSID] [--state-dir DIR]
wifipilot vendor  [MAC|NAME|ESSID] [--bssid MAC] [--oui-stats] [--import-oui oui.txt]
wifipilot advice  [--report export.json]
wifipilot benchmark [--seconds 5]

wifipilot wordlist stats FILE [FILE…]
wifipilot wordlist merge  FILE [FILE…] --out merged.txt [--limit N] [--keep-short]
wifipilot wordlist expand FILE --out candidates.txt [-r best64|file.rule] [--limit N]
wifipilot wordlist from-masks --out out.txt '?d?d?d?d' [--limit N]
wifipilot wordlist rules-info [best64|file.rule]

wifipilot hash    stats    FILE [FILE…]
wifipilot hash    merge    FILE [FILE…] [--out merged.hc22000] [--no-dedupe]
wifipilot hash    dedupe   FILE [--out out.hc22000]
wifipilot hash    filter   FILE [--essid S] [--bssid MAC] [--kind pmkid|eapol]
                           [--verifiable-only] [--out out.hc22000]
wifipilot hash    split    FILE --out-dir DIR [--per-file N]
wifipilot hash    normalize FILE [--out out.hc22000]
wifipilot hash    rescue   capture.pcap [--out rescued.hc22000]

wifipilot potfile show   [FILE] [--limit N]
wifipilot potfile export FILE [--out cracks.csv] [--format csv|json]
wifipilot potfile remove FILE NEEDLE

wifipilot loot    list     [--dir DIR]
wifipilot loot    manifest [--dir DIR]
wifipilot loot    verify   [--dir DIR]

wifipilot tools  [--force]
wifipilot ai     status|models|providers|use MODEL|pull MODEL|ask "…"
                 |off|on [auto|ollama|openrouter]|toggle   [--save]
                 [--provider auto|ollama|openrouter|none] [--report export.json]
wifipilot config [--write FILE] [--init]

global:  -c/--config  -i/--interface  -m/--monitor  --demo  -y/--i-am-authorized
         --stealth  --attacks a,b,c  --wps-pin  --reveal-with-probe  --no-pmk-cache
         -w/--wordlist  -o/--output
         --session-dir  --timeout 5m  -v/--verbose  --json  --no-color
ai:      --provider auto|ollama|openrouter|none  --model NAME  --ollama-host URL
         --openrouter-key KEY  --openrouter-base-url URL
         --ai-redact / --no-ai-redact  --ai-budget USD  --no-ai
         --disable-ai (alias of --no-ai)  --offline (alias of --no-ai)
         --think-interval 30s          # all of this is optional; see "Optional: the advisor"
```

`--json` is supported on every command and keeps stdout machine-readable (human progress
goes to stderr), so wifipilot drops into pipelines and CI.

## Configuration

`wifipilot config --init` writes `wifipilot.json`; every value can also be overridden per run.
See [wifipilot.example.json](wifipilot.example.json) for the annotated version. Highlights:

```jsonc
{
  "interface": "wlan0",
  "band": "both",
  "scan_time": 30.0,
  "attacks": ["pmkid", "handshake", "wps_pixie", "wep_ivs"],
  "handshake_timeout": 90.0, "pmkid_timeout": 60.0, "wps_timeout": 300.0,
  "stealth": false,             // true = never deauthenticate, no online PIN attacks
  "crack_timeout": 600.0,
  "cracker": "auto",            // auto | aircrack | hashcat
  "wordlists": ["/usr/share/wordlists/rockyou.txt"],
  "output_dir": "loot",
  "session_dir": "sessions",
  "ai_provider": "auto",         // auto | ollama | openrouter | none
                                 // "none" = no model at all (--no-ai/--disable-ai, wp.ai(disable=True))
  "ollama": {                    // local, private, free (the default)
    "enabled": true,
    "host": "http://127.0.0.1:11434",
    "model": "auto",             // or "qwen2.5:7b"
    "think_interval": 45.0,
    "allow_remote_host": false
  },
  "openrouter": {                // cloud, opt-in, paid
    "enabled": false,
    "api_key_env": "OPENROUTER_API_KEY",
    "key_file": "",              // or ~/.config/wifipilot/openrouter.key (0600)
    "base_url": "https://openrouter.ai/api/v1",
    "model": "auto",             // or "openai/gpt-4o-mini"
    "redact_identifiers": true,  // pseudonymise SSID/BSSID/MAC/PSK before sending
    "max_cost_usd": 0.0,         // 0 = no cap
    "provider_routing": {}       // e.g. {"sort": "throughput"}
  }
}
```

## Performance

wifipilot is I/O- and crypto-bound, not module-count-bound: a campaign spends its CPU in
capture parsing and in WPA key derivation. Both were measured and optimised (`benchmarks/`,
`python3 benchmarks/bench.py` on a 2-core container, Python 3.11):

| what | before | after |
| --- | --- | --- |
| parse a 1.1 MiB mixed capture (74% beacons, some EAPOL) | 68.7 ms | **22.8 ms** (3.0x) |
| parse a 69 MiB capture | 3515 ms | **1436 ms** (2.4x) |
| parse the same unchanged capture again | full re-parse | **0.02 ms** (cached) |
| poll a capture that grew by a few packets (handshake hunt) | full re-parse every second | **only the new bytes** |
| MIC check alone, classic WPA2 (HMAC-SHA1-128, KDV 2) | 0.19 ms (AES-CMAC, wrong for these frames) | **2.7 µs** → 369,000/s |
| MIC check alone, 802.11w/PMF or SAE (AES-CMAC, KDV 3) | ~3 ms (readable AES) | **0.18 ms** → 5,600/s |
| test one candidate password (1 handshake) | 5.49 ms | **2.41 ms** (2.3x → 415 cand/s) |
| test one candidate password (handshake + PMKID in one file) | 7.79 ms | **2.42 ms** (3.2x → 413 cand/s) |
| built-in engine, 48 wrong candidates through the real cracker | 338 cand/s | **414 cand/s** |
| a capture where every EAPOL frame is on air 5x | 5 MIC checks per candidate | **1 verifier**, 419 cand/s |
| parse + prepare a `.hc22000` hash file | — | **3.2 ms** (63,500 files/s) |
| expand a mask (`TP-Link?d?d?d?d`) | — | **34 ms per 10k space** → 5.8 M candidates/s |
| one candidate through the real mask stage | — | **2.47 ms** → 405 cand/s |
| built-in engine over a 6-capture file workload | 200.6 s | **47.4 s** (4.2x) |

How:

* **memory-mapped, offset-based parsing.** Captures are walked record by record with
  `mmap` and `struct.unpack_from`; nothing is copied unless a frame is kept, and radiotap is
  skipped by length instead of slicing it off.
* **resumable analysis.** A `.cap` that is still being written is parsed incrementally — the
  handshake hunt polls it once a second and now pays for the appended bytes only. Results are
  cached per file, so the scan/crack/report stages never re-read the same capture.
* **table-driven AES.** The CMAC behind the 802.11w/PMF MIC check uses folded T-tables, so a
  CMAC costs ~0.18 ms instead of ~3 ms; the readable implementation stays in the file and the
  two are cross-checked in the tests.  The common case — classic WPA2, whose frames set Key
  Descriptor Version 2 — is HMAC-SHA1-128, which costs microseconds.
* **no wasted verifications.** EAPOL frames are parsed down to their flags, key version and
  MIC, and exact retransmissions are counted instead of stored again: a handshake seen five
  times (or relayed by a second AP) costs one MIC check per candidate, not five.
* **the right MIC for the frame.** The algorithm comes from each frame's Key Descriptor Version —
  HMAC-SHA1-128 for KDV 2 (classic WPA2/CCMP) and KDV 3's AES-CMAC for 802.11w/PMF and SAE — not
  from the descriptor type, which is a different question with a different answer. That is a
  correctness fix first (a CMAC is not what a classic WPA2 frame carries) and a speed win second:
  2.7 µs against 0.18 ms. It is pinned by hashcat's own published mode 22000 example, whose
  PMK, PMKID and MIC all reproduce.
* **a mask is generated, not stored.** `?d?d?d?d` is expanded lazily with `itertools.product`,
  so a 10k space costs 34 ms of generation (5.8 M candidates/s) and nothing in memory; the
  expensive part is, as it should be, the 2.4 ms of PBKDF2 per candidate.
* **one PBKDF2 per candidate.** A capture can hold several handshakes plus a PMKID for the
  same network; the PMK is derived once and shared, and the per-handshake state (EAPOL
  extraction, MIC zeroing) is prepared once instead of per candidate.
* **honest benchmarks and honest counts.** `benchmarks/bench.py` measures the real paths (wrong
  candidates, real handshakes, real captures) so the numbers cannot be flattered by an early
  hit, and the engine reports the candidates it actually derived: a run that stops at candidate
  #48 says 49 candidates at ~340/s, not the full candidate space at an imaginary rate.

At 415 candidates/second the engine is now almost exactly PBKDF2-bound: of the 2.41 ms a
candidate costs, 2.31 ms is the KDF that WPA specifies (4096 rounds of PBKDF2-HMAC-SHA1) and the
MIC is microseconds on top. Nothing in Python is going to change that, which is why the built-in
engine is a fallback: where a GPU or `hashcat` is available, wifipilot writes the capture out in
hashcat mode 22000 and lets it rip — or hands that file to someone else, and cracks what comes
back with the same verifiers.

## Offline toolbox (no radio, no root)

Everything the engagement needs *after* the capture, in one place:

```bash
wifipilot targets --kind home-router --tag in-scope --select   # scope the campaign
wifipilot note "back-office AP, retest Friday"
wifipilot vendor d0:12:cb:00:00:01                             # OUI + what that brand does
wifipilot advice                                               # next steps, no LLM

wifipilot hash merge   a.hc22000 b.hc22000 --out all.hc22000
wifipilot hash filter  all.hc22000 --kind eapol --verifiable-only
wifipilot hash split   all.hc22000 --out-dir farm/ --per-file 1000
wifipilot hash rescue  partial.pcap                            # PMKID in message 1
wifipilot wordlist stats rockyou.txt
wifipilot wordlist expand words.txt --out candidates.txt -r best64
wifipilot potfile export ~/.hashcat/hashcat.potfile --out cracks.csv
wifipilot loot manifest && wifipilot loot verify                # prove nothing changed

wifipilot benchmark --seconds 5                                 # this machine's rate
```

`wifipilot benchmark` on the development machine (2 cores, Python 3.11) measures ~430
candidates/s through the built-in PBKDF2 → PTK → MIC path; the same rate turns a candidate
space into an ETA, which is why the strategies are ordered cheap-first.

### Passive intelligence and PMKs

Three more things work with no radio at all:

```bash
# who is looking for what, and is anyone being deauthenticated?
wifipilot survey capture.pcap --json

# hidden networks are in probe responses, associations and the handshake
wifipilot survey capture.pcap | grep twin
wifipilot --demo attack --attacks hidden_ssid      # live: names a hidden AP

# WPS PIN arithmetic: which candidates, why, and what a sweep would cost
wifipilot pins d0:12:cb:00:00:01 -e 'FRITZ!Box 7590 QY'
wifipilot pins a8:90:91:0e:2b:40 --first-half 1234   # M7 leak -> 1,000 attempts

# who is this client, which networks does it trust, and is it walking towards me?
wifipilot --json survey capture.pcap | jq '.probes'
wifipilot --demo attack --attacks tracker          # live: follows the best station

# an 802.1X exchange, decoded with no radio at all
wifipilot eap corp-8021x.pcap                      # method, identity, certificate
wifipilot eap corp-8021x.pcap --json               # subject/issuer/self_signed

# every information element in a capture, and the findings they imply
wifipilot decode corp-site.pcap                    # RSN/WPS/HT/VHT/roaming/rates
wifipilot decode corp-site.pcap --json             # the networks, findings and vendors
wifipilot decode corp-site.pcap --no-low           # only what is worth acting on

# the PMK cache: a passphrase learned once is verified, not re-cracked, later
wifipilot pmk verify  capture.hc22000 --psk 'hashcat!'
wifipilot pmk convert capture.hc22000 --psk 'hashcat!'   # -> mode 22001
wifipilot pmk cache                                      # ESSID -> PSK, this engagement
```

The cache is keyed by **ESSID**, because the PMK depends on the network name and the
passphrase, not on the BSSID: a mesh, a renaming AP or the same lab network captured
five times all hit the same entry. Every hit is re-verified against the capture it is
claimed for (one HMAC), so a stale cache entry costs microseconds and never produces a
wrong password in a report. Disable it with `--no-pmk-cache` or `"pmk_cache": false`.

## Architecture

```
wifipilot/
├── api.py          scriptable API: wp.attack(target=all, mode="force")
├── cli.py          argparse + rich dashboard          (presentation)
├── engine.py       job queue, campaign loop, policy gates (orchestration)
├── events.py       thread-safe pub/sub bus            (the UI contract)
├── session.py      APs, captures, attempts, reports   (state)
├── scanner.py      airodump-ng CLI + CSV parsing, wash
├── attacks/        one module per primitive; all drive real tools
├── ies.py          information-element decoder: RSN, WPS, HT/VHT/HE, roaming, country
├── rawtx.py        frame builder + AF_PACKET injector (deauth, EAPOL-Logoff)
├── crack.py        hashcat / aircrack-ng / built-in engine + rule engine
├── crypto.py       AES, CMAC, PBKDF2, PRF, PMKID, MIC (pure stdlib)
├── masks.py        hashcat-style ?d?l?u masks: expand, derive, budget
├── pcap.py         pcap/pcapng + 802.11 + EAPOL parser (pure stdlib)
├── synth.py        cryptographically valid capture builder (demo/tests)
├── llm.py          provider transports: local Ollama + OpenRouter (stdlib urllib)
├── advisor.py      planning/triage/chat, identifier redaction, cost accounting
├── planner.py      scoring, heuristic planner, plan validator
├── iface.py        monitor mode, channel hopping, cleanup
├── demo.py         simulated radio (makes everything testable)
└── web/            FastAPI app + single-page UI (no build step)
```

Design rules that keep it honest:

* **one worker thread owns the radio** — no two operations ever fight over the adapter;
* **the event bus is the only UI contract** — CLI and web render the same events, so they
  cannot disagree;
* **nothing is believed without verification** — captures are parsed and MIC-checked;
* **the LLM is an advisor, not an authority** — every plan is validated against a whitelist,
  and cloud providers additionally get pseudonymised identifiers and a hard spend cap.

More detail: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Testing

```bash
pip install -e '.[dev]'
pytest -q                      # 251 tests, ~4 min (includes full simulated campaigns)
make bench                     # timing numbers for the hot paths (see Performance)
```

The suite is organised by concern rather than by module:

| file | what it pins down |
| --- | --- |
| `test_crypto.py`, `test_crack.py` | published vectors (FIPS-197 AES, RFC 4493 CMAC, IEEE 802.11i PMK) and the cracker |
| `test_hash22000.py` | hashcat mode 22000 round trips, including hashcat's own published example |
| `test_pcap.py` | capture parsing: truncated, garbage, pcapng, resumable and cached reads |
| `test_planner.py` | the heuristic planner and the plan validator (hallucination and safety cases) |
| `test_openrouter*.py` | the AI layer, with a fake transport and against a local mock of the real API |
| `test_session.py`, `test_web.py`, `test_cli.py` | the session/report layer, web API and CLI |
| `test_api.py` | the importable module surface — `import wifipilot as wp` behaves as documented |
| `test_ai_optional.py` | the off switch: `wp.ai(disable=True)`, the CLI aliases, `WIFIPILOT_NO_AI`, and a disabled advisor that never opens a socket |
| `test_engine_demo.py`, `test_platform.py`, `test_advisor.py` | end-to-end simulated campaigns, driver/platform guards, Ollama advisor |

The advisor is optional and tested that way: `test_ai_optional.py` asserts that with the
switch off nothing is probed, no client method is reached, and the CLI, the HTTP API and the
dashboard all report the deterministic planner instead. The AI layer itself is tested twice:
once with a faked transport, and once against a local mock of
OpenRouter's API that speaks the real wire format (`/models`, `/key`, `/chat/completions` with
SSE streaming), so request construction, auth headers, streaming, error classification, cost
accounting and identifier redaction are all exercised without touching the internet.

## FAQ / troubleshooting

**"missing required tools: aircrack-ng…"** — install the aircrack-ng suite, or run `--demo`
to explore without hardware. `wifipilot tools` prints the exact install command per distro.

**Monitor mode fails / "monitor interface never appeared"** — the driver must support it
(`iw phy | grep -A8 "Supported interface modes"`). Built-in laptop cards often cannot inject;
an external adapter with `ath9k`/`mt76`/`rt2800usb`/`8812au` is the reliable choice.

**No access points found** — check `--band` (many adapters are 2.4 GHz only), that the
adapter is not managed by NetworkManager, and that channels are not pinned to one with no
traffic. `wifipilot --demo scan` proves the pipeline works when the radio does not.

**"no handshake captured"** — no clients to deauth (use `pmkid` instead), PMF/802.11w active
(targets ignore deauth), or the client is asleep. The advisor's triage says which.

**Ollama: "cannot reach …"** — the model is optional, so this is a note rather than a
failure: the deterministic planner keeps running. To use a model, `ollama serve` then
`ollama pull llama3.1:8b`; to stop the note and never touch a model again,
`wifipilot ai off --save` (or `--no-ai`, or `WIFIPILOT_NO_AI=1`).
The tool keeps working with the deterministic planner meanwhile.

**"it runs on Linux only" / I'm on macOS** — correct, and deliberate: `wifipilot` needs
nl80211 monitor mode, `rfkill` and the aircrack-ng suite. Run it in a Linux VM/container
with the adapter passed through, or on Kali/Parrot/Debian/Ubuntu/Arch.

**OpenRouter: "no API key"** — `export OPENROUTER_API_KEY=sk-or-v1-…` (or store it in a
0600 key file), then `wifipilot ai providers --probe`. `--provider openrouter` alone is not
enough: the provider stays off until it is enabled *and* a key is present.

**OpenRouter: "authentication failed" / "payment required"** — `wifipilot ai status` shows
which key is in use and where it came from (never the key itself); 402 means the account is
out of credits. The engagement continues on the deterministic planner either way.

**"is it safe to send client data to a cloud model?"** — read
[docs/AI-PROVIDERS.md](docs/AI-PROVIDERS.md). Short version: identifiers are pseudonymised by
default, captures and wordlists are never sent, spend is capped, and the local provider needs
no trust at all.

**WPS attacks fail immediately** — WPS is likely locked or rate-limited. wifipilot flags it
and stops rather than burning hours; `wps_pin` is off by default for exactly this reason.

## Roadmap

- [x] WPA3: SAE capture + transition-mode/PMF audit (`saewolf`, `pmf_audit`) — there is
      still no dictionary attack on SAE, and the docs say so
- [x] Evil twin (`evil_twin`) and the capped denial-of-service detection tests
- [x] Enterprise (802.1X) capture + identity harvesting (passive survey — see `attacks/enterprise.py`)
- [x] Rogue RADIUS/hostapd-mana driven credential capture for authorised 802.1X engagements
- [x] The advisor is optional: one switch, three spellings, and a UI that says which brain
      is piloting (`wp.ai(disable=True)`, `--no-ai`/`--disable-ai`, `WIFIPILOT_NO_AI=1`)
- [ ] Multi-adapter support (dedicated deauth + capture radios)
- [ ] Attack scheduling by time window, and a "resume session" flag
- [ ] Landscape/PDF report templates for client deliverables
- [ ] Ollama tool-calling instead of JSON plans (for models that support it)

## Credits

wifipilot is designed, written and maintained by **[codero-sus](https://github.com/codero-sus)**
— [github.com/codero-sus](https://github.com/codero-sus) · [the-codero.web.app](https://the-codero.web.app).

All credit for this project goes to codero-sus. If wifipilot saved you time on an
engagement, star the repo and say so. The external tools wifipilot drives
(aircrack-ng, hashcat, reaver, hcxtools, …) belong to their own authors and are
listed with their licences in [THIRD-PARTY.md](THIRD-PARTY.md).

## License

**Dual-licensed: Apache-2.0 OR BSD-3-Clause.** You pick; both are permissive, both carry
the same "as is, no warranty" disclaimer, and neither one restricts *what you may use the
tool for* — authorisation to test a network is a legal and contractual matter, not a
software licence, and it is handled separately (the `wp.authorize()` gate and
[docs/ETHICS-AND-LEGAL.md](docs/ETHICS-AND-LEGAL.md)).

| | choose it when | what it asks of you |
|---|---|---|
| **Apache-2.0** | you want an express **patent grant** and patent retaliation, or your policy requires one | keep the licence, the `NOTICE` and the attribution notices; mark files you changed |
| **BSD-3-Clause** | you want the shortest obligation list, or you are combining this with GPL-2.0-only code | keep the copyright notice and disclaimer; don't use the authors' names to endorse a fork |

The full texts are in [LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt) and
[LICENSES/BSD-3-Clause.txt](LICENSES/BSD-3-Clause.txt); every Python source carries
`SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause`, and `pyproject.toml` declares the
same expression (PEP 639), so `pip` and scanners read it without guessing. If you are that
kind of person: the two licences are offered **disjunctively**, not cumulatively — a
recipient needs to comply with one of them, not both.

Nothing third-party is vendored. `wifipilot` *runs* the aircrack-ng suite, reaver, bully,
hcxtools, hashcat, hostapd, dnsmasq, tshark and nmap as separate programs, and *imports*
`rich`, `fastapi` and `uvicorn`. Their licences, and what changes if you bundle them into a
`.deb`/snap/container (GPL source offers, the NPSL on nmap), are catalogued in
[THIRD-PARTY.md](THIRD-PARTY.md). Built on the shoulders of that toolchain and of Ollama.
Use it only where you are allowed to.

<!-- attack-index:start -->

## Every attack at a glance

The full reference for each of the **848 attacks** — what it answers, what it costs, what goes on the air, how it fails — is in [docs/ATTACKS.md](docs/ATTACKS.md); this is the index. `wifipilot attacks` prints it with the metadata, `--json` returns it, and `--no-radio` filters it to the attacks that transmit nothing.

Three editions, one registry: **Bluetooth 143**, **IT devices 417**, **WiFi 288** — plus **65 device types** that carry the attacks applying to them. `wifipilot --edition it` (or the web UI's edition switch) plans one of them; `wifipilot attacks --domain it` prints it; `wifipilot.devices()` returns the shelf.

* **Offline analysis (no radio at all) (121)** — `loot_audit`, `eapol_audit`, `wep_audit`, `pixie_offline`, `eap_md5_crack`, `crack_sweep`, `rogue_detect`, `twin_detect`, `roam_audit`, `wps_lockout_audit`, `capture_quality`, `hash_audit`, `wordlist_audit`, `wordlist_mine`, `crack_plan`, `vendor_fingerprint`, `beacon_timeline`, `cleartext_sniff`, `pmk_check`, `loot_manifest`, `krack_detect`, `kr00k_detect`, `fragattacks_detect`, `ft_audit`, `beacon_rate_audit`, `tsf_clone_detect`, `client_fingerprint`, `mschapv2_crack`, `mic_check`, `nonce_reuse_audit`, `key_version_audit`, `tkip_countermeasures_audit`, `group_cipher_audit`, `cipher_downgrade_audit`, `rsn_ie_audit`, `ie_anomaly_audit`, `malformed_ie_audit`, `wildcard_probe_audit`, `randomised_mac_ratio`, `probe_privacy_audit`, `assoc_history_audit`, `client_vendor_audit`, `client_count_audit`, `data_frame_audit`, `protected_ratio_audit`, `duration_field_audit`, `retransmit_audit`, `fragment_audit`, `beacon_interval_audit`, `tsf_skew_audit`, `assoc_response_audit`, `auth_response_audit`, `ssid_length_audit`, `encryption_inventory`, `bssid_oui_audit`, `signal_histogram`, `channel_usage_audit`, `channel_overlap_audit`, `handshake_message_audit`, `pmkid_presence_audit`, `eapol_retry_audit`, `wpa3_transition_audit`, `sa_query_activity`, `eapol_logoff_audit`, `llc_snap_audit`, `qos_audit`, `power_save_audit`, `broadcast_storm_audit`, `gratuitous_arp_audit`, `arp_scan_detect`, `dhcp_fingerprint_audit`, `duplicate_seq_audit`, `deauth_storm_detect`, `auth_flood_detect`, `probe_flood_detect`, `pcap_report`, `capture_coverage`, `beacon_rate_histogram`, `auth_algorithm_inventory`, `station_inventory`, `quality_histogram`, `vendor_ie_inventory`, `hidden_ap_audit`, `extended_capability_audit`, `rrm_measurement_audit`, `neighbour_report_audit`, `ft_mobility_audit`, `bss_load_audit`, `interworking_audit`, `hs20_audit`, `wmm_parameter_audit`, `wps_config_audit`, `country_power_audit`, `ssid_hygiene_audit`, `security_mismatch_audit`, `client_capability_audit`, `frame_control_audit`, `airtime_estimate`, `probe_response_latency_audit`, `eapol_key_flags_audit`, `group_rekey_audit`, `eapol_timing_audit`, `bt_device_census`, `bt_tracker_detect`, `bt_tracker_follow`, `bt_ibeacon_audit`, `bt_eddystone_audit`, `bt_address_privacy`, `bt_manufacturer_census`, `bt_service_census`, `bt_interval_audit`, `bt_channel_audit`, `bt_connectable_audit`, `bt_pairing_audit`, `bt_gatt_audit`, `bt_feature_audit`, `dhcp_lease_audit`, `ipv6_prefix_audit`, `iot_credential_audit`, `iot_service_census`, `ssdp_device_census`
* **Surveys the air, transmits nothing (29)** — `passive`, `rogue_ap`, `ie_audit`, `pmf_audit`, `saewolf`, `sae_group_audit`, `hidden_ssid`, `pnl_harvest`, `tracker`, `ap_admin_audit`, `upnp_audit`, `snmp_audit`, `dns_audit`, `wpad_audit`, `rogue_dhcp_detect`, `arp_spoof_detect`, `ipv6_ra_audit`, `mac_filter_probe`, `channel_sweep`, `bt_le_scan`, `bt_hci_inquiry`, `bt_sdp_browse`, `bt_rfcomm_scan`, `bt_gatt_enumeration`, `ble_hid_audit`, `ble_irk_resolve`, `mqtt_recon`, `rtsp_camera_audit`, `pjl_printer_audit`
* **Capture requests (frames on air) (53)** — `pmkid`, `handshake`, `handshake_broadcast`, `pmkid_flood`, `hcxdump_capture`, `injection_test`, `pcap_replay`, `session_cookie_replay`, `session_deauth_race`, `session_roam_capture`, `enterprise_anonymous_identity`, `it_relay_redis`, `it_relay_memcached`, `it_relay_mongo`, `it_relay_postgres`, `it_relay_mysql`, `it_relay_smb`, `it_relay_ldap`, `it_relay_telnet`, `it_relay_ipp`, `it_relay_http_basic`, `it_steal_camera_stream`, `it_steal_printer_spool`, `it_steal_plc_program`, `it_steal_badge_db`, `it_steal_phone_contacts`, `it_steal_mqtt_retained`, `it_steal_k8s_secrets`, `it_steal_docker_images`, `it_steal_sql_dump`, `it_steal_iot_token`, `it_relay_ftp`, `it_relay_smtp`, `it_relay_imap`, `it_relay_vnc`, `it_relay_rsync`, `it_relay_rdp`, `it_relay_dicom`, `it_relay_elastic`, `it_relay_jenkins`, `it_relay_kubernetes`, `it_steal_ftp_files`, `it_steal_smtp_credentials`, `it_steal_imap_mailbox`, `it_steal_vnc_password`, `it_steal_rsync_modules`, `it_steal_dicom_patients`, `it_steal_elastic_docs`, `it_steal_jenkins_jobs`, `it_steal_kubelet_pods`, `it_steal_smb_shares`, `it_steal_memcached_keys`, `it_steal_ldap_directory`
* **WPS (5)** — `wps_pixie`, `wps_ap_pin`, `wps_lockout_probe`, `wps_pbc`, `wps_pin`
* **WEP (6)** — `arp_replay`, `wep_ivs`, `wep_p0841`, `wep_chopchop`, `wep_fragment`, `wep_hirte`
* **Enterprise (802.1X) (17)** — `enterprise`, `eap_identity_harvest`, `eap_method_probe`, `certificate_audit`, `ttls_inner_audit`, `eap_tls_version`, `radius_secret_test`, `rogue_radius`, `enterprise_rogue_radius`, `enterprise_peap_relay`, `enterprise_certificate_swap`, `enterprise_eap_md5`, `enterprise_gtc_prompt`, `enterprise_ttls_pap`, `enterprise_mschapv2_relay`, `enterprise_downgrade`, `enterprise_supplicant_clone`
* **Rogue infrastructure and lures (237)** — `eapol_logoff`, `karma_detect`, `csa_attack`, `ssid_bruteforce`, `ssid_confusion`, `ap_isolation_audit`, `pmf_downgrade_probe`, `btm_hijack`, `evil_twin`, `karma`, `rogue_dhcp`, `dns_sink`, `captive_portal`, `arp_mitm`, `beacon_clone`, `wpa3_downgrade_twin`, `bt_beacon_clone`, `bt_tracker_clone`, `bt_connectable_lure`, `ble_hid`, `ble_hid_boot`, `ble_hid_reconnect`, `ble_smp_downgrade`, `ble_hid_mimic`, `ble_speaker_mimic`, `ble_pairing_mimic`, `ble_bond_hijack`, `ble_adv_identity_clone`, `ble_name_collision`, `ble_device_mimic`, `ble_tracker_mimic`, `ble_beacon_mimic`, `ble_eddystone_mimic`, `ble_smartlock_mimic`, `ble_badge_mimic`, `ble_ev_charger_mimic`, `ble_mesh_mimic`, `ble_anchor_mimic`, `ble_printer_mimic`, `ble_ir_mimic`, `ble_fastpair_mimic`, `ble_fido_mimic`, `ble_telemetry_mimic`, `ble_patient_mimic`, `ble_hid_multi_host`, `ble_consumer_mimic`, `ble_audio_le_mimic`, `ble_peripheral_shadow`, `ble_mouse_mimic`, `ble_combo_dongle_mimic`, `ble_lock_mimic`, `ble_lock_mesh_mimic`, `ble_bulb_mimic`, `ble_mesh_lamp_mimic`, `ble_plug_mimic`, `ble_band_mimic`, `ble_thermostat_mimic`, `ble_scale_mimic`, `ble_glucose_mimic`, `ble_pressure_mimic`, `ble_ecg_mimic`, `ble_hr_mimic`, `ble_air_quality_mimic`, `ble_charger_mimic`, `ble_label_printer_mimic`, `ble_ir_hub_mimic`, `ble_uwb_anchor_mimic`, `ble_patient_monitor_mimic`, `ble_vehicle_tracker_mimic`, `ble_vending_mimic`, `ble_doorbell_mimic`, `ble_ibeacon_mimic`, `ble_soundbar_mimic`, `ble_hfp_hijack`, `ble_hfp_audio_gateway`, `ble_map_hijack`, `ble_pbap_hijack`, `ble_sap_imsi_read`, `ble_sap_file_sweep`, `ble_obex_push`, `ble_spp_hijack`, `ble_dial_hijack`, `ble_hidp_classic_inject`, `ble_audio_session_takeover`, `ble_gatt_write_sweep`, `ble_notify_spoof`, `ble_service_changed_abuse`, `ble_signed_write_bypass`, `ble_irk_crack`, `ble_version_spoof`, `ble_encryption_negotiation`, `ble_passkey_bruteforce`, `ble_oob_claim`, `ble_lesc_downgrade`, `ble_keypress_spoof`, `ble_ctkd_cross_transport`, `ble_key_size_probe`, `ble_bond_overwrite`, `ble_confirm_replay`, `ble_public_key_audit`, `twin_address_clone`, `twin_element_clone`, `twin_rsn_strip`, `twin_tkip_downgrade`, `twin_pmf_strip`, `twin_wpa3_transition`, `twin_owe_transition`, `twin_hidden_name`, `twin_enterprise_clone`, `twin_mobility_domain`, `twin_bss_load`, `twin_country_mismatch`, `twin_probe_shadow`, `twin_signal_boost`, `twin_ssid_suffix`, `twin_multi_name`, `twin_wmm_acm`, `twin_neighbour_lure`, `twin_quiet_element`, `client_assoc_forgery`, `client_table_flood`, `client_sleep_spoof`, `client_ps_poll_theft`, `client_tdls_teardown`, `client_sa_query_bypass`, `client_roam_hijack`, `client_eapol_logoff`, `client_fourway_race`, `client_amsdu_inject`, `client_blockack_hijack`, `client_rate_downgrade`, `steer_btm_request`, `steer_btm_disassoc`, `steer_beacon_request`, `steer_channel_load`, `steer_spectrum_switch`, `steer_fils_discovery`, `steer_wnm_sleep`, `steer_twt_setup`, `steer_power_constraint`, `steer_ssid_list`, `steer_tpc_request`, `steer_probe_answer`, `session_gateway_impersonation`, `session_dns_spoof`, `session_tcp_reset`, `session_seq_injection`, `session_gtk_rekey`, `session_msg1_flood`, `session_data_replay`, `session_arp_flood`, `portal_clone`, `portal_wildcard_dns`, `portal_wispr_redirect`, `portal_anqp_spoof`, `portal_certificate_phish`, `portal_hsts_downgrade`, `portal_basic_auth`, `portal_cookie_clone`, `portal_oauth_phish`, `portal_credential_reuse`, `portal_javascript_inject`, `it_mimic_dns`, `it_mimic_dhcp`, `it_mimic_ntp`, `it_mimic_syslog`, `it_mimic_mqtt`, `it_mimic_coap`, `it_mimic_modbus`, `it_mimic_bacnet`, `it_mimic_rtsp`, `it_mimic_sip`, `it_mimic_pjl`, `it_mimic_mdns`, `it_mimic_ssdp`, `it_mimic_tftp`, `it_impersonate_onvif`, `it_impersonate_szl`, `it_impersonate_cip`, `it_impersonate_snmp`, `it_impersonate_cast`, `it_impersonate_airplay`, `it_impersonate_kasa`, `it_impersonate_miio`, `it_impersonate_opcua`, `it_impersonate_ipp`, `it_impersonate_stun`, `it_impersonate_docker`, `it_poison_arp_gateway`, `it_poison_dns`, `it_poison_netbios`, `it_poison_mdns`, `it_poison_ssdp`, `it_poison_dhcp_option`, `it_poison_snmp_trap`, `it_poison_bacnet_whois`, `it_poison_ldap_referral`, `it_poison_smb_negotiate`, `it_poison_rdp_negotiation`, `it_poison_telnet_banner`, `it_mimic_ftp`, `it_mimic_smtp`, `it_mimic_imap`, `it_mimic_rsync`, `it_poison_elastic_shard`, `it_poison_kubelet_response`, `it_mimic_dns_reverse`, `it_mimic_ssh`, `it_mimic_rdp`, `it_mimic_coap_write`, `it_impersonate_ssh_banner`, `it_impersonate_sip_pbx`, `it_impersonate_snmp_engine`, `it_poison_mdns_name`, `it_poison_ssdp_location`, `forged_dhcp_release`, `dhcp_nak_injection`, `dhcp_option_injection`, `tcp_reset_injection`, `icmp_redirect_injection`, `icmp_unreachable_injection`, `rogue_ra`, `ns_na_spoof`, `llmnr_poisoning`, `nbns_poisoning`, `mdns_poisoning`, `stp_root_takeover`, `lldp_spoof`, `cdp_spoof`, `vlan_double_tag_hop`, `bt_bias`, `bt_knob`, `bt_bluebugging`, `bt_blesa`, `bt_bluesnarf`, `bt_hid_injection`, `airgeddon_portal`
* **Discovery and fingerprinting (no radio either) (119)** — `ble_hfp_identity_spoof`, `ble_l2cap_psm_sweep`, `ble_sdp_browse_takeover`, `ble_gatt_blob_dump`, `ble_gatt_handle_enum`, `ble_mtu_negotiation_abuse`, `ble_att_handle_brute`, `ble_service_table_dump`, `ble_gatt_value_dump`, `ble_rpa_follow`, `ble_feature_page_spoof`, `ble_smp_command_probe`, `it_survey_mdns_services`, `it_survey_ssdp_description`, `it_survey_cwmp_parameters`, `it_survey_rtsp_describe`, `it_survey_opcua_endpoints`, `it_survey_memcached_stats`, `it_survey_mysql_handshake`, `it_survey_spooler_banner`, `it_http_discover`, `it_http_banner`, `it_http_version_audit`, `it_http_json_discover`, `it_http_json_version_audit`, `it_http_json_jenkins_audit`, `it_mqtt_discover`, `it_mqtt_version_audit`, `it_coap_discover`, `it_coap_version_audit`, `it_modbus_discover`, `it_modbus_version_audit`, `it_bacnet_discover`, `it_bacnet_version_audit`, `it_rtsp_discover`, `it_rtsp_version_audit`, `it_onvif_discover`, `it_onvif_version_audit`, `it_ipp_discover`, `it_ipp_version_audit`, `it_pjl_discover`, `it_pjl_version_audit`, `it_telnet_banner`, `it_telnet_version_audit`, `it_sip_discover`, `it_sip_version_audit`, `it_cwmp_discover`, `it_cwmp_version_audit`, `it_smb_discover`, `it_smb_version_audit`, `it_ldap_discover`, `it_ldap_version_audit`, `it_redis_discover`, `it_redis_version_audit`, `it_memcached_discover`, `it_memcached_version_audit`, `it_mongo_discover`, `it_mongo_version_audit`, `it_kasa_discover`, `it_kasa_version_audit`, `it_cast_discover`, `it_cast_version_audit`, `it_airplay_discover`, `it_airplay_version_audit`, `it_adb_discover`, `it_adb_version_audit`, `it_vnc_discover`, `it_vnc_version_audit`, `it_pjlink_discover`, `it_pjlink_version_audit`, `it_dicom_discover`, `it_dicom_version_audit`, `it_s7comm_discover`, `it_s7comm_version_audit`, `it_cip_discover`, `it_cip_version_audit`, `it_dnp3_discover`, `it_dnp3_version_audit`, `it_iec104_discover`, `it_iec104_version_audit`, `it_opcua_discover`, `it_opcua_version_audit`, `it_ssh_banner`, `it_ssh_version_audit`, `it_rdp_discover`, `it_rdp_version_audit`, `it_postgres_discover`, `it_postgres_version_audit`, `it_mysql_discover`, `it_mysql_version_audit`, `it_rsync_discover`, `it_rsync_version_audit`, `it_ftp_banner`, `it_ftp_version_audit`, `it_smtp_discover`, `it_smtp_version_audit`, `it_miio_discover`, `it_miio_version_audit`, `it_ssdp_discover`, `it_ssdp_version_audit`, `it_mdns_discover`, `it_mdns_service_census`, `it_mdns_version_audit`, `it_host_discovery`, `it_device_inventory`, `it_port_exposure`, `it_cleartext_service_audit`, `it_firmware_advisory_audit`, `it_camera_exposure_audit`, `it_printer_exposure_audit`, `it_ot_exposure_audit`, `it_medical_device_audit`, `it_container_exposure_audit`, `it_database_exposure_audit`, `it_share_enumeration`, `it_voip_exposure_audit`, `it_smart_home_audit`, `it_iot_service_census`, `it_exposure_report`
* **Device and service attacks (IP, not radio) (179)** — `ble_gatt_hijack`, `it_hijack_rtsp`, `it_hijack_sip_register`, `it_hijack_mqtt_retain`, `it_hijack_onvif_uri`, `it_hijack_modbus_coil`, `it_hijack_bacnet_priority`, `it_hijack_iec104`, `it_hijack_dnp3`, `it_hijack_pjl_job`, `it_hijack_http_session`, `it_hijack_cwmp`, `it_hijack_adb`, `it_hijack_ftp_write`, `it_hijack_smtp_relay`, `it_hijack_imap_delete`, `it_hijack_dicom_store`, `it_hijack_vnc_session`, `it_hijack_mysql_query`, `it_hijack_sip_contact`, `it_hijack_opcua_write`, `it_http_version`, `it_http_default_creds`, `it_http_auth_bypass`, `it_http_config_dump`, `it_http_cleartext`, `it_http_json_unauth_read`, `it_http_json_unauth_write`, `it_http_json_config_dump`, `it_http_json_cluster_read`, `it_http_json_search_read`, `it_http_json_cleartext_audit`, `it_mqtt_anonymous`, `it_mqtt_default_creds`, `it_mqtt_subscribe`, `it_mqtt_publish`, `it_mqtt_cleartext_audit`, `it_coap_unauth_read`, `it_coap_unauth_write`, `it_coap_fuzz`, `it_coap_cleartext_audit`, `it_modbus_unauth_read`, `it_modbus_unauth_write`, `it_modbus_config_dump`, `it_modbus_fuzz`, `it_modbus_cleartext_audit`, `it_bacnet_unauth_read`, `it_bacnet_unauth_write`, `it_bacnet_config_dump`, `it_bacnet_cleartext_audit`, `it_rtsp_anonymous`, `it_rtsp_default_creds`, `it_rtsp_version`, `it_rtsp_config_dump`, `it_rtsp_cleartext_audit`, `it_onvif_version`, `it_onvif_config_dump`, `it_onvif_default_creds`, `it_onvif_stream_uri`, `it_onvif_cleartext_audit`, `it_ipp_version`, `it_ipp_anonymous`, `it_ipp_default_creds`, `it_ipp_config_dump`, `it_ipp_cleartext_audit`, `it_pjl_version`, `it_pjl_config_dump`, `it_pjl_unauth_write`, `it_pjl_filesys_audit`, `it_pjl_cleartext_audit`, `it_telnet_version`, `it_telnet_default_creds`, `it_telnet_cleartext`, `it_sip_challenge_audit`, `it_sip_enum`, `it_sip_default_creds`, `it_sip_cleartext`, `it_sip_cleartext_audit`, `it_cwmp_config_dump`, `it_cwmp_unauth_write`, `it_cwmp_version`, `it_cwmp_cleartext_audit`, `it_smb_version`, `it_smb_signing_audit`, `it_smb_null_session`, `it_smb_cleartext_audit`, `it_ldap_anonymous`, `it_ldap_version`, `it_ldap_default_creds`, `it_ldap_unauth_read`, `it_ldap_cleartext_audit`, `it_redis_anonymous`, `it_redis_version`, `it_redis_config_dump`, `it_redis_unauth_write`, `it_redis_cleartext_audit`, `it_memcached_version`, `it_memcached_unauth_read`, `it_memcached_unauth_write`, `it_memcached_cleartext_audit`, `it_mongo_version`, `it_mongo_anonymous`, `it_mongo_unauth_read`, `it_mongo_cleartext_audit`, `it_kasa_anon_read`, `it_kasa_unauth_write`, `it_kasa_version`, `it_kasa_cleartext_audit`, `it_cast_unauth_read`, `it_cast_unauth_write`, `it_cast_cleartext_audit`, `it_airplay_version`, `it_airplay_auth_audit`, `it_airplay_cleartext_audit`, `it_adb_anonymous`, `it_adb_version`, `it_adb_unauth_read`, `it_adb_cleartext_audit`, `it_vnc_anonymous`, `it_vnc_version`, `it_vnc_default_creds`, `it_vnc_cleartext_audit`, `it_pjlink_version`, `it_pjlink_unauth_write`, `it_pjlink_cleartext_audit`, `it_dicom_echo`, `it_dicom_config_dump`, `it_dicom_version`, `it_dicom_cleartext_audit`, `it_s7comm_version`, `it_s7comm_unauth_read`, `it_s7comm_config_dump`, `it_s7comm_cleartext_audit`, `it_cip_version`, `it_cip_unauth_read`, `it_cip_cleartext_audit`, `it_dnp3_unauth_read`, `it_dnp3_version`, `it_dnp3_cleartext_audit`, `it_iec104_unauth_read`, `it_iec104_version`, `it_iec104_cleartext_audit`, `it_opcua_version`, `it_opcua_endpoint_audit`, `it_opcua_cleartext_audit`, `it_ssh_version`, `it_ssh_kex_audit`, `it_ssh_default_creds`, `it_rdp_nla_audit`, `it_rdp_version`, `it_postgres_anonymous`, `it_postgres_version`, `it_postgres_default_creds`, `it_postgres_cleartext_audit`, `it_mysql_version`, `it_mysql_tls_audit`, `it_mysql_default_creds`, `it_mysql_cleartext_audit`, `it_rsync_modules`, `it_rsync_unauth_read`, `it_rsync_version`, `it_rsync_cleartext_audit`, `it_ftp_version`, `it_ftp_anonymous`, `it_ftp_default_creds`, `it_ftp_cleartext`, `it_smtp_version`, `it_smtp_open_relay`, `it_smtp_starttls_audit`, `it_smtp_cleartext`, `it_miio_token`, `it_miio_version`, `it_miio_cleartext_audit`, `it_ssdp_version`, `it_ssdp_unauth_write`, `it_ssdp_cleartext_audit`, `it_mdns_config_dump`, `it_mdns_cleartext_audit`, `it_default_credential_sweep`
* **Denial-of-service tests (opt-in) (82)** — `deauth_flood`, `auth_flood`, `assoc_flood`, `null_data_flood`, `probe_flood`, `eapol_start_flood`, `sae_commit_flood`, `tkip_michael`, `wids_confusion`, `beacon_flood`, `disassoc_flood`, `rts_flood`, `cts_flood`, `channel_switch_flood`, `sa_query_flood`, `tdls_teardown_flood`, `probe_response_flood`, `dhcp_discover_flood`, `bt_adv_name_flood`, `bt_adv_dos`, `bt_pairing_flood`, `bt_l2cap_echo_flood`, `ble_conn_param_hijack`, `ble_gatt_char_fuzz`, `ble_gatt_read_flood`, `ble_adv_flood_le`, `ble_scan_hog`, `ble_conn_flood_le`, `ble_conn_param_starve`, `ble_phy_request`, `ble_data_length_abuse`, `ble_ll_unknown_probe`, `ble_pairing_flood_le`, `ble_pair_lockout_probe`, `it_fuzz_dns_name`, `it_fuzz_smb2_negotiate`, `it_fuzz_ldap_filter`, `it_fuzz_rtsp_method`, `it_fuzz_mqtt_topic`, `it_fuzz_modbus_function`, `it_fuzz_snmp_varbind`, `it_fuzz_sip_uri`, `dhcp_starvation`, `dhcp_flood`, `syn_flood`, `udp_flood`, `udp_reflection`, `ra_flood`, `bt_blueborne`, `bt_sweyntooth`, `bt_bluesmack`, `krack_replay`, `fragattacks_inject`, `it_http_flood`, `it_mqtt_flood`, `it_coap_flood`, `it_modbus_flood`, `it_bacnet_flood`, `it_rtsp_flood`, `it_ipp_flood`, `it_pjl_flood`, `it_sip_flood`, `it_smb_flood`, `it_ldap_flood`, `it_redis_flood`, `it_memcached_flood`, `it_mongo_flood`, `it_kasa_flood`, `it_cast_flood`, `it_adb_flood`, `it_vnc_flood`, `it_pjlink_flood`, `it_dicom_flood`, `it_s7comm_flood`, `it_cip_flood`, `it_dnp3_flood`, `it_iec104_flood`, `it_opcua_flood`, `it_ssh_flood`, `it_rdp_flood`, `it_postgres_flood`, `it_miio_flood`

<!-- 848 attacks -->
<!-- attack-index:end -->
