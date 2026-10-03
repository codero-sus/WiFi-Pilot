# Changelog

Notable changes to `wifipilot`, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are the branch's own
milestones rather than published releases.

## 54 attacks — offline analysis, lures, and metadata that the whole tool reads

* **27 new attacks, 54 in total**, each one registered, described, gated and tested:
  * **Offline (ten, no radio, no authorisation):** `loot_audit`, `eapol_audit`, `wep_audit`,
    `crack_sweep`, `eap_md5_crack` (RFC 2759: `MD5(id ‖ password ‖ challenge)`),
    `pixie_offline`, `rogue_detect`, `twin_detect`, `roam_audit`, `wps_lockout_audit`.
  * **Capture:** `handshake_broadcast` (opt-in broadcast deauth) and `hcxdump_capture`
    (the hcxdumptool → hcxpcapngtool → mode-22000 pipeline).
  * **Lures and confusion:** `csa_attack` (channel-switch announcement, no deauth frame
    anywhere), `ssid_confusion`, `ssid_bruteforce`, `ap_isolation_audit` (a spoofed ARP
    between two clients) and `karma_detect` — the one attack whose target is the attacker.
  * **WPS:** `wps_ap_pin` (vendor-derived static AP PIN), `wps_lockout_probe` (three wrong
    PINs, then stop: does the AP lock out?) and `wps_pbc` (push-button enrolment through
    `wpa_supplicant`).
  * **WPA3:** `sae_group_audit` — groups, SAE-EXT-KEY/H2E, PMF and transition mode, read
    from a capture with no radio time.
  * **Denial of service (six more, all built in-process, no mdk4):** `assoc_flood`,
    `null_data_flood` (power-save buffers, invisible to deauth-counting WIDS rules),
    `eapol_start_flood`, `sae_commit_flood` (Dragonblood clogging), `tkip_michael`
    (two corrupted frames, sixty seconds of TKIP silence) and `wids_confusion`
    (attribution pointed at a neighbour).
* **`wifipilot/attacks/meta.py`**: category, noise (`silent`→`extreme`), impact
  (`none`→`loot`) and a "what a defender sees" sentence for every attack. The CLI, the
  web UI (`/api/state`), the report and the advisor prompt all read `attack_catalog()`,
  and `validate()` fails the build if an attack is registered without metadata.
* **`wifipilot attacks`**: the catalogue as a command (`--json`, `--category`, `--noise`,
  `--no-radio`), and `wp.catalogue(...)` in the library API.
* **Offline by design**: the ten analyses need no monitor interface, no root and no
  authorisation gate; `mode="offline"` runs them and nothing else.
* **Frames**: ten new builders in `rawtx.py` (auth/assoc/reassoc, Null data with the
  power-save bit, EAPOL-Start, probe request/response, CSA beacon, SSID-confusion beacon,
  ARP request/reply and deterministic spoofed stations), and `describe()` now names
  null-data frames instead of calling everything "data".
* **Web UI**: the attack chips are grouped by category with an enabled counter per group,
  the offline ones are suffixed `· offline`, and each tooltip carries the description,
  `category · noise · impact`, the tools it needs and what a defender sees — 54 chips are
  only usable if the page tells you what a click does.
* **Planner**: `allow()` gained the gates for every new family — DoS never in stealth,
  lures need a monitor interface, the broadcast handshake is opt-in even in `"force"`,
  offline analyses never need a capability — and the plan orders offline work first.
* **Docs**: [docs/ATTACKS.md](docs/ATTACKS.md) grew to 54 entries with sections on the
  offline set, the lures, the new WPS/WPA3 work and the second wave of floods, plus a new
  "reading the catalogue" section; the README table lists all 54.
* Tests: `tests/test_attacks_v3.py` (registry ↔ metadata ↔ planner ↔ docs consistency, a
  demo run of all 27 new attacks, and frame-level checks on the new builders).

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
