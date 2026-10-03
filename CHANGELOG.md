# Changelog

Notable changes to `wifipilot`, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are the branch's own
milestones rather than published releases.

## Unreleased

### The advisor became optional, and the UIs learned to say so

* **One switch, three spellings.** `wp.ai(disable=True)` / `wp.ai(disable=False)` in Python,
  `--no-ai` / `--disable-ai` / `--offline` on the command line, `WIFIPILOT_NO_AI=1` in the
  environment — plus `wifipilot ai off|on [auto|ollama|openrouter]|toggle [--save]`.
  `Config.ai_off()` is checked before anything else, so a disabled advisor never probes,
  never lists models and never opens a socket.
* **`wp.set_provider("none")` is `wp.ai(disable=True)`.** Both entry points share one code
  path (`_apply_ai_state`), so a live engine's advisor, `session.auto_think` and config can
  never disagree.
* **The CLI's `ai` verbs stop talking to the network while the advisor is off**: `status`,
  `models`, `pull`, `use` and `ask` report the switch instead (exit 0 for `status`, 1 where
  an answer was expected).
* **The TUI** now shows `AI: off · deterministic` (never `disabled`/`offline` for a
  deliberate switch), a live vitals strip (APs, clients, attacks run/failed, captures,
  handshakes, PMKIDs, keys, audits, decisions), and plans produced with the advisor off are
  labelled `planner plan`. Dashboard panels moved from `Panel(box=None)` to a real rich
  `Box` — the live view raised on current rich.
* **The web UI** greys the advisor tab and the OpenRouter/chat cards, disables the controls
  that would need a model, shows an off banner with a one-click *turn the advisor on*, and
  badges the header `ai: off · deterministic planner`. `/api/ai/toggle {"disabled": bool}` is
  the switch; `/api/ai/think`, `/api/ai/chat` and `/api/ai/models` answer `disabled` without
  contacting anything.
* **Docs** grew this changelog, a [terminal UI reference](docs/TUI.md), a documentation index
  in the README and a table of contents in [docs/ATTACKS.md](docs/ATTACKS.md); the advisor is
  documented as an optional extra everywhere, and "AI-piloted" refers to the *pilot* being
  optional, not to a hard dependency.
* `wifipilot --help` groups the advisor options under a title that says they are optional;
  `Config.save()` honours `WIFIPILOT_CONFIG`, matching `Config.load()`.
* `tests/test_ai_optional.py` (30 tests) and a dedicated CI step keep all of the above honest.
  Full suite: **691 passed**.

## 27 attacks — element audit, PNL harvest, Logoff, Karma, two more floods

* `ie_audit` — decode beacon/probe information elements and report what they leak (WPS state,
  WPS model, vendor quirks, country, BSS load, RSN capabilities…), read-only.
* `pnl_harvest` — parse probe requests into a preferred-network-list report: which SSIDs the
  neighbourhood believes in, and which clients believe in them.
* `eapol_logoff` — the EAPOL-Logoff disconnect, keyed on the frames no one authenticates.
* `karma` — answer every probe with the SSID the client is asking for, via hostapd-mana.
* `probe_flood` and `beacon_flood` — two more denial-of-service tests, with rate controls and
  the same authorisation and stealth gates as the rest.
* A supporting 802.11 layer: `rawtx.py` frame builders (deauth, EAPOL-Logoff, radiotap),
  `ies.py` (element decoding, 13 finding kinds), `attacks/audit.py`, and `synth.py`
  improvements used by the tests and `--demo`.
* Docs: [docs/ATTACKS.md](docs/ATTACKS.md) grew to 27 entries with a table of contents;
  `test_attacks_more.py` (64 tests); CI runs the new tests as their own step.

## Ten attacks — WPA3, the WEP family, the twin, two floods

* `saewolf` (SAE exchange capture and decode), `pmf_audit` (which classic attacks survive
  802.11w), the WEP family (`wep_p0841`, `wep_chopchop`, `wep_fragment`, `wep_hirte`),
  `evil_twin`, `deauth_flood`, `auth_flood`, plus the `eap` decoder.
* `docs/ATTACKS.md` gained the per-attack failure-mode sections; `test_attacks_wpa3.py`.
* 21 attacks total; suite 597 passed.

## First release — the pipeline, the web UI and the advisor

* Scan → score → plan → attack → capture → crack → report, with the deterministic planner as
  the safety net and the LLM advisor (Ollama local, OpenRouter opt-in with redaction and a
  spend cap) as a proposal source that never touches the radio.
* 11 attacks at the time: `pmkid`, `pmkid_flood`, `handshake`, `wps_pixie`, `wps_pin`,
  `wep_ivs`, `hidden_ssid`, `rogue_ap`, `enterprise`, `rogue_radius`, `tracker`, `passive`.
* FastAPI + WebSocket web UI, `--demo` simulation mode, hashcat mode 22000 round-trips,
  mask/wordlist tooling, vendor intelligence, session reports and the importable Python API
  (`import wifipilot as wp`).
