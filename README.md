# wifipilot 📡

**An AI-piloted WiFi auditing tool — a modern alternative to `wifite`, in Python, for Linux, with a local- or cloud-LLM advisor and a web UI.**

`wifipilot` automates the boring, error-prone parts of an authorised wireless assessment:
it finds the targets, decides which attack is worth the time, runs it, cracks what it
captures, and explains every decision in plain language.

**Linux only.** Every attack path drives nl80211 monitor mode, `rfkill`, `/sys/class/net`
and the aircrack-ng suite; there is no supported macOS or Windows build, and
`wifipilot` refuses to run on anything but Linux.

**Two model providers.** By default the advisor is a local model served by
[Ollama](https://ollama.com) and nothing about the engagement leaves the machine. If you
would rather use a bigger model, [OpenRouter](https://openrouter.ai) is supported — opt-in
only, with an API key, a spend cap, and engagement identifiers pseudonymised before they
are sent. See [docs/AI-PROVIDERS.md](docs/AI-PROVIDERS.md).

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
- [Quickstart (no hardware required)](#quickstart-no-hardware-required)
- [Real engagement](#real-engagement)
- [The web UI](#the-web-ui)
- [The AI advisor (Ollama)](#the-ai-advisor-ollama)
- [Attacks](#attacks)
- [Cracking](#cracking)
- [CLI reference](#cli-reference)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Testing](#testing)
- [FAQ / troubleshooting](#faq--troubleshooting)
- [Roadmap](#roadmap)
- [License](#license)

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
- **WPS Pixie-Dust** (reaver `-K 1` / bully `--pixiewps`), plus opt-in online PIN recovery
  with vendor default-PIN algorithms tried first
- **WEP IV harvesting** with ARP replay
- **Passive** mode that never transmits anything

**Cracking**
- hashcat (with rules + `hcxpcapngtool` → mode 22000 conversion)
- aircrack-ng, fed a rule-expanded candidate stream on stdin (aircrack has no rule engine)
- **built-in engine**: pure-Python PBKDF2 → PTK → AES-CMAC/HMAC-MD5 MIC verification and
  PMKID recomputation. It cracks targeted candidate spaces with no GPU and no external tools,
  and it *proves* every password it reports.

**Intelligence (optional, two providers)**
- **auto-think**: the advisor re-reads a compact situation report every N seconds and picks
  the next actions with reasoning
- **failure triage**: natural-language diagnosis of why an attack failed and what to do next
- **chat**: ask about the running engagement ("what is the biggest risk we found?")
- **local by default** (Ollama): free, offline, nothing leaves the machine
- **cloud on request** (OpenRouter): opt-in with an API key, spend cap, provider routing and
  identifier redaction — SSIDs, BSSIDs, client MACs and recovered PSKs become
  `ssid-1`/`bssid-1`/`mac-1`/`psk-1` before they are sent, and are mapped back before the
  plan runs
- deterministic fallback planner whenever the model is missing, out of credit, rate limited
  or incoherent — the tool never stalls on the AI

**Reporting**
- JSON session export, Markdown engagement report, JSONL event journal, loot directory
- web UI: live target table, loot cards, plan viewer, chat, tool diagnostics

## Install

Requires Linux (Kali, Parrot, Debian, Ubuntu, Arch, Fedora …) and Python 3.9+.

```bash
git clone https://github.com/codero-sus/Pentest-toolkit
cd Pentest-toolkit
pip install -e .            # core CLI (needs only `rich`)
pip install -e '.[web]'     # + FastAPI/uvicorn for the web UI
./scripts/install-tools.sh  # optional: install aircrack-ng, reaver, hcxtools, hashcat…
```

External tools (install what you need — `wifipilot tools` tells you exactly what is missing):

```bash
# Debian/Ubuntu/Kali
sudo apt install aircrack-ng reaver bully pixiewps hcxtools hashcat iw rfkill
# Arch
sudo pacman -S aircrack-ng reaver bully pixiewps hcxtools hashcat iw rfkill
```

Minimum for a live run: `aircrack-ng` (provides `airmon-ng`, `airodump-ng`, `aireplay-ng`).
Everything else unlocks extra attacks. **No tools and no radio? Use `--demo`.**

Optional AI advisor — local (default):

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.1:8b        # or qwen2.5:7b / mistral:7b — anything 3–14B works
wifipilot ai status
```

Or cloud, if you would rather not run a model locally:

```bash
export OPENROUTER_API_KEY=sk-or-v1-...      # create a key at openrouter.ai/keys
wifipilot --provider openrouter --ai-budget 0.50 ai providers --probe
wifipilot --provider openrouter --model openai/gpt-4o-mini attack -d 45m
```

OpenRouter is off until you enable it; identifiers are pseudonymised by default; see
[docs/AI-PROVIDERS.md](docs/AI-PROVIDERS.md) for key handling, costs and the privacy model.

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

## Real engagement

```bash
# 0) look before you leap
sudo wifipilot tools                  # adapter monitor-mode/injection capabilities
sudo wifipilot scan -t 45             # passive discovery only

# 1) dry run without transmitting
sudo wifipilot -y --attacks passive attack -d 10m

# 2) full campaign, AI-planned
sudo wifipilot -y --model qwen2.5:7b attack -d 45m

# 3) constrain the scope to specific BSSIDs and be gentle
sudo wifipilot -y --stealth -b AA:BB:CC:DD:EE:FF attack -d 20m
```

What happens next:

1. the adapter is put into monitor mode (`airmon-ng`, falling back to `iw`), interfering
   services are stopped, and the original MAC/channel is restored on exit;
2. targets are discovered and scored (signal, encryption, WPS state, clients, prior failures);
3. the advisor picks actions — with a reason for each — and they run in priority order;
4. every capture is validated before it is believed;
5. whenever a handshake/PMKID lands, the cracker tries it (targeted candidates first);
6. at the end: `loot/` holds the captures, `sessions/<id>/` holds the journal and report,
   and a Markdown report is written for the client.

Press `Ctrl+C` once for a clean stop (interface restored, report written).

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
* **AI advisor** — Ollama status, model picker, `ollama pull` from the browser, the last plan
  with its reasoning and the actions the safety validator rejected, plus a chat panel with
  one-click prompts.
* **Log** — the live event stream and progress bar, identical to the CLI.
* **Tools & settings** — dependency report with install hints, interface capabilities, attack
  toggles, wordlists, engagement settings.

The UI is a *remote control* for the same engine the CLI uses — same events, same code paths,
no duplicated logic. Everything is served from relative URLs, so it works behind a reverse
proxy or an SSH tunnel (`ssh -L 8787:localhost:8787 box`).

> The UI binds `0.0.0.0` by default so containers and tunnels work out of the box. On an
> untrusted network, bind loopback instead: `wifipilot web --host 127.0.0.1`.

## The AI advisor (Ollama or OpenRouter)

Two providers, one advisor. Switching is a flag, a config key, or a click in the web UI:

```bash
wifipilot ai providers                      # what is configured / what is missing
wifipilot ai status                         # active provider, model, quota, spend
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

| Attack | Tool | Disruptive? | Notes |
|---|---|---|---|
| `pmkid` | hcxdumptool / own sniffer | no | client-less, first choice for WPA2 |
| `handshake` | airodump-ng + aireplay-ng | **yes** (deauth) | needs a client; fails vs WPA3-SAE/PMF |
| `wps_pixie` | reaver `-K 1` / bully `--pixiewps` | mildly | usually <60 s on vulnerable chipsets |
| `wps_pin` | reaver / bully | **yes, slow** | opt-in only; can lock WPS permanently |
| `wep_ivs` | airodump-ng + aireplay `--arpreplay` | yes | legacy networks |
| `passive` | airodump-ng | no | listen-only; harvests what is on air |

## Cracking

Three engines run in order, and every reported password is verified:

```bash
wifipilot crack loot/handshake-HOME-2F4A-*.cap -e HOME-2F4A
wifipilot crack capture.pcapng -b AA:BB:CC:DD:EE:FF -w rockyou.txt --engine hashcat
wifipilot analyze capture.pcapng          # what is actually in this file?
```

1. **hashcat** (`-m 22000`, rules, status parsing) when installed;
2. **aircrack-ng** with a rule-expanded candidate stream on stdin;
3. **built-in engine** — PBKDF2 → PTK → AES-CMAC/HMAC-MD5 MIC, or PMKID recomputation.
   Also used to *verify* what the external tools claim, so "cracked ✓ verified" means the
   MIC or PMKID actually matched.

## CLI reference

```
wifipilot scan   [-t 30] [--band 2.4GHz|5GHz|both] [--save out.json]
wifipilot attack [-b BSSID] [--time 30s] [-d 45m] [--no-scan] [--skip-crack]
wifipilot demo
wifipilot web    [--host 0.0.0.0] [--port 8787] [--open]
wifipilot crack  FILE [FILE…] [-b BSSID] [-e ESSID] [--engine auto|aircrack|hashcat]
wifipilot analyze FILE [FILE…]
wifipilot tools  [--force]
wifipilot ai     status|models|providers|use MODEL|pull MODEL|ask "…"
                 [--provider auto|ollama|openrouter|none] [--report export.json]
wifipilot config [--write FILE] [--init]

global:  -c/--config  -i/--interface  -m/--monitor  --demo  -y/--i-am-authorized
         --stealth  --attacks a,b,c  --wps-pin  -w/--wordlist  -o/--output
         --session-dir  --timeout 5m  -v/--verbose  --json  --no-color
ai:      --provider auto|ollama|openrouter|none  --model NAME  --ollama-host URL
         --openrouter-key KEY  --openrouter-base-url URL
         --ai-redact / --no-ai-redact  --ai-budget USD  --no-ai
         --think-interval 30s
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

## Architecture

```
wifipilot/
├── cli.py          argparse + rich dashboard          (presentation)
├── engine.py       job queue, campaign loop, policy gates (orchestration)
├── events.py       thread-safe pub/sub bus            (the UI contract)
├── session.py      APs, captures, attempts, reports   (state)
├── scanner.py      airodump-ng CLI + CSV parsing, wash
├── attacks/        one module per primitive; all drive real tools
├── crack.py        hashcat / aircrack-ng / built-in engine + rule engine
├── crypto.py       AES, CMAC, PBKDF2, PRF, PMKID, MIC (pure stdlib)
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
pytest -q                      # 184 tests, ~3 min (includes a full simulated campaign)
```

The suite covers published crypto test vectors (FIPS-197 AES, RFC 4493 CMAC, IEEE 802.11i
PMK), capture parsing (including truncated/garbage/pcapng inputs), the cracker, the planner
and plan validator (hallucination and safety-rule cases), the advisor (with a fake Ollama),
the session/report layer, the web API, the CLI, and one end-to-end campaign in simulation
mode that asserts real captures were produced and verified.

The AI layer is tested twice: once with a faked transport, and once against a local mock of
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

**Ollama: "cannot reach …"** — `ollama serve`, then `ollama pull llama3.1:8b`.
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

- [ ] WPA3-SAE dictionary/transition-mode attacks where legitimate tooling exists
- [ ] Enterprise (802.1X) capture + identity harvesting (passive only)
- [ ] Multi-adapter support (dedicated deauth + capture radios)
- [ ] Attack scheduling by time window, and a "resume session" flag
- [ ] Landscape/PDF report templates for client deliverables
- [ ] Ollama tool-calling instead of JSON plans (for models that support it)

## License

MIT — see [LICENSE](LICENSE). Built on the shoulders of the aircrack-ng suite, reaver,
bully, hcxtools, hashcat and Ollama. Use it only where you are allowed to.
