# The terminal UI

`wifipilot` has a live dashboard for anything long-running (a scan, a campaign, an attack
loop) and a plain-text spinner for everything else. Both are views on the same event bus —
they never drive the engine, so the CLI, the web UI and the Python API all see identical
behaviour.

```
  SIMULATION   phase: attacking  iface: —  uptime: 4m12s  loot: 2  PSKs: 1  AI: off · deterministic
  APs 11 clients 23 attacks 12 run / 2 failed captures 3 handshakes 1 PMKIDs 1 keys 1 audits 0 decisions deterministic

SSID                  BSSID                    CH   SIG  SEC          WPS          CLI  LOOT       BY     NEXT
HOME-2F4A             d0:9e:12:9d:36:cc         6   -39  WPA2         unlocked       3  HS PMKID   llm    handshake/crack
FRITZ!Box 7530 XR     74:bf:9c:6b:4c:98        11   -54  WPA2         —              0  —          —      pmkid/handshake
...
  cracking HOME-2F4A  42%  1.2 M/s  rockyou.txt: 3 481 220 / 14 344 391
  events
  ...
```

## What each part means

| part | what it tells you |
| --- | --- |
| mode badge | `SIMULATION` (yellow) or `LIVE · authorised` / `LIVE · not authorised` (red) |
| `phase` | the engine's current phase: `idle`, `scanning`, `attacking`, `cracking`, `reporting` |
| `iface` | the monitor interface in use, or `—` in demo mode |
| `uptime` / `loot` / `PSKs` | session duration, capture count and recovered passwords |
| `AI:` | the piloting state — see [below](#the-ai-segment) |
| vitals strip | `APs`, `clients`, `attacks run / failed`, `captures`, `handshakes`, `PMKIDs`, `keys`, `audits`, and who is making decisions |
| target table | SSID, BSSID, channel, signal (colour-coded), security, WPS state, client count, loot tags (`HS`, `PMKID`, `PSK=…`), `BY` (who selected it: `llm` or the operator) and `NEXT` (the two attacks the planner would try next) |
| progress panel | the current job and its percentage, rate and detail line |
| `events` | the tail of the event bus — the same events the web UI and `journal.jsonl` receive |
| footer | the last plan, one line, labelled `AI plan` / `heuristic plan` / `planner plan` |

## The `AI:` segment

The dashboard is honest about who is deciding, and the three states are distinct:

| segment | meaning |
| --- | --- |
| `AI: qwen2.5:7b ·3 calls` | a model is reachable and has planned at least once |
| `AI: offline → heuristics` | a provider is configured but not answering; the deterministic planner is in charge for now |
| `AI: off · deterministic` | the advisor was switched off on purpose (`--no-ai`/`--disable-ai`, `--offline`, `wifipilot ai off`, `wp.ai(disable=True)`, `WIFIPILOT_NO_AI=1`) — no socket is opened, and the planner is in charge by design |

The vitals strip repeats the distinction as `decisions deterministic` or
`decisions model + planner`, so a screenshot of a campaign always says which brain drove it.
The same rule applies to the footer: a plan produced with the advisor disabled is labelled
`planner plan`, not `heuristic plan` — "off" is not the same thing as "unavailable".

## Layout and terminals

* Rich is optional. Without it (or with `--no-color`, or on a dumb terminal) `wifipilot`
  falls back to `Spinner`, which prints one progress line to **stderr** every few seconds and
  passes event messages through — safe for pipes, logs and `screen`/`tmux` scrollback.
* `--json` always selects the plain path and keeps **stdout** machine-readable; all human
  progress goes to stderr, so `wifipilot --json attack … | jq` works unattended.
* The live view refreshes at 4 Hz and redraws on demand, so a slow SSH link only costs
  bandwidth when something changes.
* The table shows the 14 strongest targets, ranked by the planner's score, and the event
  panel keeps the last 400 lines; both numbers are deliberately small so the view stays
  legible on a 80×24 console.
* Colour is used for meaning, not decoration: signal strength (green/yellow/red), loot
  (green), PSKs (magenta), WPS (yellow), failures (red), `BY: llm` (magenta).

## Keys and interaction

There are none, on purpose: the dashboard is a view, not a control panel. Starting a campaign
is an explicit command (`wifipilot attack`, `POST /api/campaign`), so an accidental keystroke
can never fire a radio. Stop a running campaign with `Ctrl-C` (SIGINT), the web UI's **stop**
button, or `wp.stop()` in Python.

## See also

* [The web UI](web-ui.md) — the same state in a browser, for when a dashboard is not enough.
* [Architecture](ARCHITECTURE.md#8-three-front-ends-one-engine) — why the CLI, web UI and
  library share one engine and one event bus.
