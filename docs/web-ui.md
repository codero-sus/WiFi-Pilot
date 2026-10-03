# The web UI

The browser front end for wifipilot: same engine, same event bus, same planner and the same
optional advisor as the terminal dashboard (see [TUI.md](TUI.md) for the console view, and
[PYTHON-API.md](PYTHON-API.md) for driving the engine from Python).

```bash
wifipilot web --demo --open      # explore safely, opens http://127.0.0.1:8787
sudo wifipilot -y web            # live, after confirming authorisation
wifipilot web --host 127.0.0.1 --port 9000
```

The UI is a single page served by FastAPI; there is no build step, no npm, no CDN. Everything
is relative-URL based, so reverse proxies, container previews and SSH tunnels all work:

```bash
ssh -L 8787:localhost:8787 analyst@target-box     # then open http://localhost:8787
```

## Screen by screen

### Targets

| Column | Meaning |
|---|---|
| SSID / BSSID | ESSID (or `<hidden>`) and the BSSID |
| CH / Band | channel and band of the beacon |
| Signal | RSSI in dBm, colour-coded green/yellow/red |
| Security | WEP / WPA / WPA2 / WPA2+WPA3 / WPA3 / OPN, plus cipher and auth in the drawer |
| WPS | `no`, `WPS unlocked`, `WPS locked`, `WPS unknown` |
| Clients | number of stations seen associating (the deauth material) |
| Loot | `HS` handshake, `PMKID`, `PSK ★` (hover shows the password) |
| Score | planner score (signal, encryption, WPS state, prior attempts, failures) |
| Decided by | `AI` when the local model picked this target, else `heuristic`/`operator` |
| Attack | per-row attack selector (**only enabled, applicable attacks are listed**), `▶ run`, `🔓 crack` |

`＋` opens the detail drawer: cipher/auth, PMF, vendor, deauth count, the AI's reason for
picking the target, the client list, and the full attack history with the tool's own output.

### Loot

One card per capture: kind, target, tool, EAPOL count, the recovered PSK, a **download** link
(the API refuses any path outside the loot/session directories) and a one-click crack button.
Passwords verified by MIC/PMKID recomputation are labelled as such.

### AI advisor *(optional tab — the "AI-piloted" part, and it can be off)*

The tab is deliberately de-emphasised: it carries a muted "optional" label, and while the
advisor is off the header badge reads `ai: off · deterministic planner`, a banner explains
that the rule-based planner is deciding, and every control that would need a model (think,
chat, model picker, `ollama pull`, OpenRouter key) is disabled. A single **turn the advisor
on** button — or the `off` button next to the provider picker — flips it either way.

* **Model provider** — switch between `auto`, `ollama` (local, private), `openrouter`
  (cloud) and `disabled` (rules only) at runtime. The header badge always shows which
  provider is planning and whether it is reachable. Choosing `disabled`, `POST
  /api/ai/toggle {"disabled": true}` and `wifipilot ai off` are the same action; while it is
  off, `/api/ai/think`, `/api/ai/chat` and `/api/ai/models` answer "disabled" without
  contacting anything.
* **Provider status** — reachability, endpoint, selected model, plan counts, call/error
  counters, average latency, tokens and spend.
* **Model picker** — the live catalogue of the active provider (installed Ollama models, or
  OpenRouter's full model list with per-million-token prices), with a search box and a
  *free only* filter. `⟳` refreshes it. `ollama pull <name>` installs a local model without
  leaving the browser (progress streams into the log).
* **OpenRouter card** — paste an API key (stored in `wifipilot.json`, mode 600, and never
  sent back to the page), tick the consent box to enable the cloud provider, toggle
  identifier pseudonymisation, and set a USD spend cap. The card shows the key source and
  the running spend for the session.
* **Last plan** — the model's reasoning verbatim, the prioritised actions, and any actions
  **rejected by the safety validator** (so you can see when the model was overruled).
* **Chat** — ask about the running engagement; answers are grounded in the live situation
  report, streamed token by token. One-click prompts cover the common questions
  ("most promising target", "summarise findings", "triage failures", "client-facing impact note").

### Log

The raw event stream (new APs, attack start/end, deauths, captures, crack progress, advisor
messages) plus a progress bar for whatever is running right now.

### Tools & settings

Dependency report with version and the exact install command per tool, capability flags,
wireless interfaces with monitor/injection support, attack toggles, discovered wordlists and
the effective engagement settings.

## Controls

| Control | Effect |
|---|---|
| **Start campaign** | runs the full loop (scan → plan → attack → crack) with the given budget and scope |
| **Stop** | clean stop: current attack cancelled, interface restored, report written |
| **Cancel attack** | cancels only the running attack, the campaign continues |
| **Rescan** | 20 s extra discovery |
| **Think now** | forces one advisor cycle and shows the plan |
| **switch provider** | moves the advisor between local Ollama and OpenRouter (the cloud switch asks for consent) |
| **save key** | stores an OpenRouter key in the config file; the value is never echoed back |
| **scope** | paste BSSIDs to restrict the campaign |
| **simulation** | switches between live and simulated radio (rebuilds the engine) |
| **I have written authorisation** | required for any live attack; without it the API returns 403 |
| **Attack toggles** | the engine's catalog (in `/api/state`) lists all 27 attacks with their label, tool, description, whether they need injection, whether their tools are installed and whether they are enabled in the current config. The disruptive ones (`wps_pin`, `pmkid_flood`, `evil_twin`, `karma`, `eapol_logoff`, the four floods, the WEP enablers) start unticked, and the two read-only decoders (`ie_audit`, `pnl_harvest`) are marked read-only — tick them freely, they transmit nothing |

## REST API

Everything the UI does is an endpoint you can script:

```
GET  /healthz                 GET  /api/state      GET  /api/tools
GET  /api/interfaces          GET  /api/wordlists  GET  /api/config
POST /api/config              POST /api/config/save
POST /api/mode                POST /api/scan       POST /api/campaign
POST /api/attack              POST /api/cancel     POST /api/crack
POST /api/rescan              POST /api/targets
POST /api/ai/think            POST /api/ai/chat    POST /api/ai/model
POST /api/ai/pull             POST /api/ai/toggle {"autothink"|"enabled"|"disabled"}
GET  /api/ai/models           POST /api/ai/provider   POST /api/ai/key
GET  /api/report              GET  /api/export     GET  /api/file
GET  /api/events              WS   /ws
GET  /api/survey              GET  /api/pins        GET  /api/pmk/cache
POST /api/pmk/verify          GET  /api/eap
```

Example — run a campaign from a script and stream events:

```bash
curl -s -X POST localhost:8787/api/campaign \
     -H 'Content-Type: application/json' \
     -d '{"targets": [], "duration": 1800, "scan_first": true}'

python - <<'PY'
import json, websocket          # pip install websocket-client
ws = websocket.create_connection("ws://localhost:8787/ws")
while True:
    message = json.loads(ws.recv())
    if message["kind"] == "event":
        event = message["event"]
        print(event["time"], event["kind"], event["data"].get("message", ""))
PY
```

## Security notes

* The UI has **no authentication**: it is a local operator console. Bind it to loopback or
  put it behind a reverse proxy with auth when you need remote access.
* The OpenRouter API key is never returned by any endpoint: `GET /api/config` reports only
  `has_api_key`, the source (`environment`, `key file`, `config file`) and the key length.
  Prefer `OPENROUTER_API_KEY` in the server's environment over pasting a key into the UI.
* Switching to OpenRouter from the UI requires the consent checkbox; the server rejects the
  request otherwise (400), and every provider change is published as a `session.info` event
  so it lands in the session journal.
* All state-changing endpoints that transmit are additionally gated by the authorisation flag
  (403 otherwise) and by the plan validator.
* `/api/file` only serves files inside this session's loot and state directories.
