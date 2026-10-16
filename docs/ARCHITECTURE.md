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
             │  pcap.py (802.11/EAPOL) · hash22000.py · masks.py · crypto.py · synth.py          │
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

## 4. The LLM is an advisor, never an authority — and it is optional

The rule-based planner is the product; the model is a garnish. `Config.ai_off()` is the one
switch behind `wp.ai(disable=True)`, `--no-ai`/`--disable-ai`/`--offline`, `wifipilot ai off`
and `WIFIPILOT_NO_AI=1`, and everything downstream of it is inert: `ai_enabled()` is false,
`active_provider()` returns `none` without probing, `advisor.check()` short-circuits before
the client is touched, `advisor.models()` returns `[]`, the CLI `ai` subcommands report
"off" instead of calling out, the web API answers `disabled` and the UI greys the tab.

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

There are two simulated environments, one per non-radio edition, and neither is a stub:
what a demo run meets is a device that answers.

* **`itsim.py`** — the IP segment behind the bridge. 51 hosts (routers, cameras, PLCs,
  printers, phones, a domain controller) across six posture profiles, each with the ports it
  really opens and a responder per protocol: `it_http_default_creds` reads an admin page,
  `it_smb_signing_audit` reads a security mode flag, `it_coap_fuzz` sends an oversized option
  block and gets whatever the device answers back.  Weakness order
  (`unauthenticated → anonymous → kiosk → legacy → default_creds → hardened`) is what a sweep
  walks, so a campaign finds the misconfigurations before it finds 401s.
* **`blesim.py`** — the Bluetooth floor. A `VirtualController` takes the H4 packets an attack
  writes and answers the way a controller does: command complete and status events, LE
  advertising reports for every device in range, inquiry results for the classic ones,
  connection complete, encryption change carrying the *negotiated* key size, and the peer's
  own ACL answers through the L2CAP signalling, ATT, SMP, SDP, RFCOMM, AT and OBEX engines.
  66 devices across 14 posture profiles (a KNOB-vulnerable headset, an open GATT band, a
  fragile stack, an OBEX object store, HID hosts) mean the same code path that reads a real
  controller reads the simulation.  Each device answers a set of *roles* — what a battery
  needs of it — and the catalogue publishes them beside the attacks they enable, so a run
  is aimed at a device that can answer the question instead of at the first address heard — `bt.hci_send`, `bt.iter_hci_events`, `bt.parse_acl_packet`
  and `bt.parse_sdp` are the parsers in both cases. The same floor is written as a real
  `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR` capture (`blesim.write_capture`), so the 14 offline
  Bluetooth audits read the devices the on-air attacks just spoke to.

`wifipilot.api.simulations()` (CLI: `wifipilot sim`, web: `GET /api/sim`) returns what both
environments contain, including the per-device catalogue, so a demo run can be inspected
rather than taken on faith.

The 692 attacks are grouped into modules by *what they need*, which is also how the
tests and the docs are organised:

| module | attacks | radio |
|---|---|---|
| `attacks/forensics.py` | 10 offline analyses (`loot_audit`, `eapol_audit`, `wep_audit`, `crack_sweep`, `eap_md5_crack`, `pixie_offline`, `rogue_detect`, `twin_detect`, `roam_audit`, `wps_lockout_audit`) | none — files only |
| `attacks/flood.py` | four `mdk4` floods | transmit, capped |
| `attacks/flood2.py` | six in-process floods (assoc, null-data, EAPOL-Start, SAE commit, TKIP/Michael, WIDS confusion) | transmit, capped |
| `attacks/lure.py` | `csa_attack`, `ssid_confusion`, `ssid_bruteforce`, `karma_detect`, `ap_isolation_audit` — transmit a lie, then *read the capture back* for the answer | transmit + listen |
| `attacks/capture2.py` | `handshake_broadcast`, `hcxdump_capture` | transmit |
| `attacks/wps2.py` | `wps_ap_pin`, `wps_lockout_probe`, `wps_pbc` | transmit |
| `attacks/survey2.py` | `sae_group_audit` | none (reads a capture, or one short listen) |
| `attacks/offline3.py`, `attacks/offline4.py` | 74 further offline analyses — the frame-level decoders, the protocol audits and the byte-mask work (`ie_audit`, `krack_detect`, `hash_audit`, `eap_md5_crack`, …) | none — files only |
| `attacks/btattacks.py` | 26 Bluetooth and BLE attacks: 14 offline audits of an LE capture (`bt_device_census`, `bt_tracker_detect`, `bt_pairing_audit`, `bt_gatt_audit`, …) and 12 that use the host's own controller (`bt_le_scan`, `bt_beacon_clone`, `bt_pairing_flood`, `bt_gatt_enumeration`, …) | offline half none; live half needs an HCI adapter |
| `attacks/netdos.py` | 29 attacks on the network behind the bridge: 5 capture audits (`dhcp_lease_audit`, `ipv6_prefix_audit`, `iot_credential_audit`, `iot_service_census`, `ssdp_device_census`) and 24 that build real DHCP, TCP/IP, ICMPv6, STP, LLDP/CDP, VLAN and device-service traffic | transmit (the audits none) |
| `attacks/blehid.py` | 8 BLE attacks — the wave around HID: `ble_hid` (advertise the keyboard, enumerate the report characteristic, type the payload as boot reports), `ble_hid_audit`, `ble_hid_boot`, `ble_hid_reconnect` (impersonate the bonded keyboard), `ble_smp_downgrade`, `ble_gatt_hijack`, `ble_irk_resolve` and `ble_conn_param_hijack` | an HCI adapter; the demo floor answers with real protocol bytes |
| `attacks/btred.py` | 9 named Bluetooth attacks: BlueBorne's malformed L2CAP/SDP probes, BIAS impersonation, the KNOB key-entropy measurement, BlueBugging over RFCOMM, BLESA pre-authentication ATT work, the SweynTooth link-layer battery, BlueSnarfing's OBEX file pull, BlueSmack's oversized echo and HID keystroke injection | an HCI adapter (the RFCOMM/OBEX pair also needs the serial profile reachable) |
| `attacks/famous.py` | 3 famous Wi-Fi attacks: `krack_replay` (message 3 replayed from a captured handshake), `fragattacks_inject` (plaintext A-MSDU and fragment-cache shapes) and `airgeddon_portal` (the evil-twin captive-portal pipeline, through airgeddon when it is installed) | transmit (a monitor interface that can inject) |
| `attacks/itsvc.py` | 286 IT-device attacks: one table row per `<protocol> × <technique>` (`it_<protocol>_discover`, `_version_audit`, `_default_creds`, `_cleartext_audit`, …) over the 40 services in `SERVICES`, plus the segment sweeps (`it_host_discovery`, `it_port_exposure`, …, `it_exposure_report`) | IP, not radio — the AP is only the bridge |
| `wifipilot/itproto.py` | not attacks: the request builders and reply parsers every IT attack speaks (161 exports — HTTP, SMB2, Modbus, RTSP, ONVIF, IEC-104, LDAP, MySQL, MQTT, IPP, PJL, Kasa/miIO, …) |
| `wifipilot/itsim.py` | not attacks: the simulated segment (51 hosts, 72 ports, 45 responders) an IT attack drives in `--demo`, so the whole collection is exercisable without a lab |
| `wifipilot/blesim.py` | not attacks: the simulated Bluetooth floor — a virtual controller (HCI in, H4 events out), 66 devices across 14 posture profiles, the L2CAP/ATT/SMP/SDP/RFCOMM/OBEX engines behind them, and the LE capture a demo run writes for the offline audits |
| `wifipilot/itdev.py` | not attacks: the editions and the device shelf — 65 device types with their ports, protocols and the attacks that apply to them (`wp.devices()`, `wp.device("printer")`) |

`attacks/meta.py` describes each attack for the *reader* rather than the runner: its
category, its noise level, its impact and one sentence about what a defender sees.
`attack_catalog()` merges the class attributes with that table, and it is the single
source the CLI (`wifipilot attacks`), the web UI's toggles, the report and the advisor
prompt read — so the catalogue cannot describe an attack differently from the module that
runs it. `meta.validate()` fails the build when an attack is registered without metadata
(see the extension checklist below).

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

* **new attack** — add a module in `attacks/`, register it in `attacks/__init__.py`, add an
  entry to `attacks/meta.py` (category, noise, impact, what a defender sees), add its name to
  `models.ATTACK_NAMES` and a place in `DEFAULT_ORDER`, and (only if it is quiet and safe) to
  the default `Config.attacks`. The CLI, the web UI, the plan validator and the LLM prompt pick
  it up automatically; `wifipilot attacks`, `/api/state` and the report all render the metadata.
  `tests/test_attacks_v3.py` checks that you did not forget a step, and that the docs list it.
* **new data source** — implement a producer that calls `session.upsert_ap()` /
  `session.add_client()` (Kismet, `iw scan`, a CSV replay, …).
* **new UI** — subscribe to `EventBus` and read `Engine.snapshot()`.
* **new cracking engine** — subclass/extend `Cracker` and return `CrackResult`.
* **new model provider** — implement `LLMClient` (`ping`, `list_models`, `resolve_model`,
  `chat`, optional `pull`), register it in `build_client()` and in `Config.llm_config()`.
  Everything above it (advisor, planner validation, CLI, web UI, cost accounting) works
  unchanged.

## 8. Three front ends, one engine

`cli.py` (the command line and its live dashboard — see [TUI.md](TUI.md)),
`web/app.py` (the browser UI) and `api.py` (the library) are peers: each one builds a
:class:`~wifipilot.config.Config`, creates a :class:`~wifipilot.engine.Engine`,
and consumes the same event bus.  Nothing in the engine knows which front end is
driving it, which is why the API gets the dashboard's behaviour for free — the
same planner, the same validation, the same authorisation gate, the same reports.

The API adds only what a library needs and a UI does not: one campaign per process
(a second call raises `BusyError` instead of fighting over the radio), setup errors
raised to the caller instead of rendered to a panel, and result objects
(`Run`/`ScanResult`/`CampaignResult`) that are JSON-serialisable.

Each front end has its own reference: [TUI.md](TUI.md) for the terminal dashboard
(panels, the `AI:` states, the plain-text fallback), [web-ui.md](web-ui.md) for the browser
UI and its REST/WebSocket surface, [PYTHON-API.md](PYTHON-API.md) for the library, and
[ATTACKS.md](ATTACKS.md) for the attack set they all drive. The optional advisor they share
is documented in [AI-PROVIDERS.md](AI-PROVIDERS.md).

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

## 11. Mask attacks

A mask is a candidate space written down: `Telekom-?d?d?d?d` is 10,000 candidates, `?d` × 8 is
100 million.  `wifipilot/masks.py` implements the hashcat tokens (`?l ?u ?d ?s ?a`, `??` for a
literal `?`), derives the patterns worth trying from the target (ESSID prefix, vendor token, ISP
numeric defaults), and hands the rest to :class:`~wifipilot.crack.Cracker`, which splits them:

* masks whose space fits the built-in budget (`--mask-candidates`, default 10000) are expanded
  lazily with `itertools.product` and verified — 5.8 M candidates/s of generation, 405/s of
  verification, because PBKDF2 is the wall;
* masks that do not fit are *named in the log with their size* and left to `hashcat -a 3`.  A
  half-swept 100-million space reported as "mask attack exhausted" would be a lie, so the
  engine refuses to do it quietly;
* a pattern the operator typed is validated where it is written (`Mask.__post_init__`), and a
  typo disables that pattern only — never the rest of the stage.

Masks are deliberately *ordered by space*: the cheap, likely ones (four digits behind a
four-character vendor prefix) run first, and the 10^11 "eight lowercase letters" masks are only
useful to a GPU, which is exactly where they go.

## 12. Rules, wordlists and files (no radio required)

`wifipilot/rules.py` and `wifipilot/toolbox.py` are the parts an operator uses on a laptop, with
the loot from an engagement and no adapter:

* **rule files** — hashcat's rule language (the subset that can be modelled exactly: `l u c C t r
  d f { } $ ^ [ ] D x O i s @ z Z q k K * T p '` and the `<N`/`>N`/`!X`/`/X` filters).  A rule
  containing anything unmodelled is *skipped*, never half-applied, because a partial rule would
  silently produce different candidates than `hashcat -r` does.
* **the file toolbox** — merge / dedupe / filter / split / normalize mode-22000 files (dedupe on
  the hash material, ignoring the message-pair byte, exactly as hashcat does),
  `rescue_partial_capture()` for PMKIDs a converter drops, wordlist statistics and rule
  expansion, hashcat potfile import/export, and a sha256 manifest so "the loot has not changed"
  is a check rather than a hope.
* **strategy presets** — `crack.py`'s `STRATEGIES` turn "quick" or "thorough" into the six knobs
  that actually control a run (targeted budget, mask budget, rules, rule file, wordlist count,
  timeout) plus the **stage order**.  Where the stages run is data
  (`crack_order="targeted,masks,hashcat-masks,external,builtin"`), not code: the cheap,
  target-derived candidates always get their chance before a dictionary sweep, and an unknown
  stage name is dropped rather than run.

## 13. Password analytics and vendor intelligence

Two module-level datasets, both labelled as heuristics where they are heuristics:

* `wifipilot/analytics.py` + `data/default-patterns.json` — per-vendor/ISP default schemes (a
  vendor's numeric default, its WPS behaviour, the masks worth trying) and a password report:
  pattern family, character classes, entropy, a 0–100 weakness score, and time-to-crack for four
  engine speeds.  It answers "how bad is this PSK", which a bare password list cannot.
* `wifipilot/vendors.py` + `data/oui-wifi.json` — the OUI registry is a *lookup* (a curated
  subset of IEEE's `oui.txt`: 10,000+ 24-bit prefixes for the WiFi/CPE/chipset vendors an
  engagement meets, plus 28-bit fallback blocks, with `import_oui_file()` merging a full
  `oui.txt` when you want everything).  The vendor *dossier* is explicitly a heuristic:
  `confidence: "heuristic"`, a disclaimer, and attack suggestions.  A randomised MAC is
  reported as locally administered — never matched to a vendor it cannot have.

## 14. Hash files (hashcat mode 22000)

`wifipilot/hash22000.py` reads and writes the text format that WiFi cracking
tools exchange, in both directions and with no external converter:

* `WPA*01` PMKID lines and `WPA*02` EAPOL message pairs, with the fields in the
  order hashcat documents (signature, type, PMKID/MIC, MAC_AP, MAC_STA, ESSID,
  nonce, EAPOL, message-pair byte);
* the ESSID is hex and is kept as *bytes*: `crypto.pmk()` salts PBKDF2 with the
  raw SSID, so a network name that is not valid UTF-8 still verifies;
* the EAPOL field is the raw frame with its MIC zeroed, and the separate MIC
  field is what gets compared;
* a line carries its Key Descriptor Version, so verification picks the right
  MIC algorithm from the line itself (see §12's parsing notes);
* lines that cannot be verified by anyone (a zeroed client nonce, a missing
  ESSID, a truncated frame) are reported as such — `analyze` says "no usable
  nonce", the cracker says "no verifiable hash" — rather than counted as
  failures.

`wifipilot export` (and `wp.export()`) prefer `hcxpcapngtool` when the operator
asks for it (`--hcxtools`) and otherwise use this writer, which means the
feature works on a machine with no hcxtools installed.  Reading a hash file
needs nothing but the file: the built-in engine verifies candidates directly
against the PMKID or the EAPOL MIC.

## 15. Non-transmitting intelligence (and the PMK cache)

Eight of wifipilot's attacks never touch the radio in a way anyone can complain
about, and they share one idea: *the information is already on air or already on
disk, and reading it changes what the engagement knows*.  (The rogue infrastructure in
the next section is the deliberate exception: those ask the question the read-only
tools can only imply.)

* **`hidden_ssid`** (`attacks/hidden.py`) — a hidden AP omits its SSID from beacons,
  not from probe responses, association requests or the handshake. The attack watches
  those frames (and, only with `--reveal-with-probe`, asks for the name directly) and
  writes the result onto the `AccessPoint`, which is what the planner, the vendor
  dossier and the mask generator were missing.
* **`rogue_ap`** (`attacks/rogue.py`, `sniff.py`) — compares every ESSID against its
  BSSIDs, vendors and signal spread, and against the names clients are probing for. It
  reports a *pattern* with its evidence attached and labels it ``heuristic``; a tool
  that prints "EVIL TWIN" without proof is worse than no tool.
* **`enterprise`** (`attacks/enterprise.py`, `sniff.eap_exchange`) — an 802.1X network
  has no PSK, so the honest deliverable is the survey: EAP method, outer identity, and
  the server certificate decoded out of the TLS message. The high-severity finding is
  a missing or self-signed certificate, because that is what lets a rogue RADIUS
  impersonate the real one.
* **`tracker`** (`attacks/tracker.py`, or `--client MAC` to name one) — one station, followed: the SSIDs it probes for
  (its real preferred network list), the BSSIDs it uses, and its signal trend, with the
  raw samples written to loot. It answers "which name is worth impersonating" before
  anything transmits.
* **`pmf_audit`** (`attacks/wpa3.py`, `wpa3.py`) — airodump's CSV does not carry the RSN
  capabilities bits, so the attack reads the beacons themselves and decodes MFPC (bit 5)
  and MFPR (bit 4). Its output is a list of *what is still possible*: no required PMF,
  transition mode, OWE transition. Each finding is raised once per session by
  `_add_finding_once`, because reading the whole neighbourhood in one pass must not
  report the same neighbour eleven times, and each AP it reads is marked
  `pmf_checked` so the planner schedules it exactly once.
* **`ie_audit`** (`attacks/audit.py`, `ies.py`) — the element-level audit.  Where
  `wpa3.py` reads the RSN bits a capture cares about, `ies.py` decodes *every* element
  a beacon-like frame carries, per BSSID: the RSN cipher/AKM suites and TKIP flag, the
  MFPC/MFPR capabilities, the WPS element (version, lock state, configuration methods,
  model and manufacturer) and the vendor elements that hide WPS/WMM/WPA1 behind a
  four-byte vendor id, HT/VHT/HE/EHT capability and channel width, 802.11r mobility
  domain and 802.11k/v capability, the country element, rates, BSS load and TIM.
  `ie_findings()` turns that into thirteen severity-sorted findings, each naming the
  element it came from, and the attack writes what it learned back onto the session
  (`wps_locked`, `pmf_required`, channel width, …) so the planner decides from elements
  rather than from a guess.  The pcap it decoded is registered through
  `Session.add_artifact()` — visible in the report, excluded from loot, because an
  audit file is evidence and cannot be cracked.
* **`pnl_harvest`** (`attacks/audit.py`, `sniff.probe_requests`) — the preferred network
  list, out loud: which stations probe for which SSIDs, and which of those names no AP
  is currently serving.  Findings are the per-name `pnl_missing_network` and a single
  neighbourhood-wide `pnl_disclosure` (sixty clients leaking a history is one problem,
  not sixty findings); the measurements go to `reports/pnl.json`, ranked by how many
  stations asked, which is the machine-readable target list the twin and Karma stages
  consume.
* **`saewolf`** (`attacks/wpa3.py`, `wpa3.py`) — captures the SAE commit/confirm
  exchange and reports the group, whether it completed, and whether the network also
  advertises PSK. The decoder walks the authentication frames itself (an authentication
  frame's body starts at header + 24, not at the beacon payload offset a naive reader
  would use) and the result carries `feasible_offline_attack: False`, because SAE is a
  PAKE: there is no offline attack, and a tool that implies otherwise is lying.

`pcap.iter_frames()` was added for these readers: a stateless, cache-free walk that
yields 802.11 frames with the radiotap header already skipped, so the analysis modules
can parse a capture themselves without disturbing the incremental cache the attack
cycle depends on.

**The PMK cache** (`pmk.py`, consulted by `crack.py`) is the other half of that idea.
A PSK is a property of the *network*: the PMK is `PBKDF2-SHA1(psk, essid, 4096)`, so it
does not mention the BSSID at all. The cache is therefore keyed by ESSID, stores
``ESSID -> (psk, pmk)`` in the engagement's state directory, and every lookup is
verified against the capture it is claimed for before the passphrase is reported. One
HMAC per capture is the difference between "crack the mesh again" and "verify and move
on", and a corrupted or stale entry costs microseconds instead of a wrong password in a
client report. Mode 22001 is the same format as 22000 with the PMK in place of the
MIC/PMKID, which is why a converted file can be handed to hashcat unchanged.

WPS PIN arithmetic (`wps.py`) follows the same rule: every candidate is checksum-valid
(or says in its note why it is kept anyway), carries the reason it was suggested, and
the plan states what the alternatives cost — 11,000 attempts for the documented
two-half attack against 10⁷ for a blind sweep.

## 16. The radio is a last resort

The attacks that transmit do so deliberately, one at a time, and each one stops itself.
They make the same point from different ends: `enterprise` reads the certificate,
`rogue_radius` tests whether anybody checks it, `evil_twin` asks whether clients prefer
the SSID to the real BSSID, `karma` asks whether they will follow a name that exists
only because they said it, and the WEP enablers do the minimum needed to make the
harvest possible.  All of them exist because "we captured a handshake" says nothing
about whether the network is reachable.

Three of them are bounded in the code rather than by policy, because the bound *is* the
technique:

* **`eapol_logoff`** (`attacks/logoff.py`, `rawtx.py`) — builds the frames itself.
  `rawtx.frame_control` packs the first frame-control byte the same way `pcap.py`
  decodes it (`(type << 2) | (subtype << 4)`), the data envelope is FromDS with
  addr1 = client and addr2 = BSSID, and the EAPOL body is three fields with no
  authentication in it.  The attack sends `frames_per_client` (3) per station for at
  most `max_clients` (6) stations, then watches the session for a reassociation whose
  `first_seen` is inside the observation window.  A Logoff cannot produce a 4-way
  handshake, so the module is explicit that it is not a capture technique; the frames
  are also offered as a preview (`logoff_preview`) so the UI can show what would be sent
  before anything is.
* **`karma`** (`attacks/karma.py`) — `hostapd-mana` with `enable_mana=1`, or nothing:
  plain `hostapd` cannot answer a probe it did not expect, so a missing package is a
  stated reason rather than a silent substitution.  The daemon's own output is parsed
  with module-level compiled patterns (`patterns()` exposes them for the tests), the
  config is written into the session directory, and the process is stopped in a
  `finally` block like the twin's.
* **the floods** (`attacks/flood.py`) — one `_FloodAttack` base, four modes
  (`d`/`a`/`p`/`b`), each with its own `max_seconds` (60 s for the deauth flood, 45 s for
  the rest) and its own simulated rate, so the "fastest thing in the tool" is still
  something with a ceiling.  Each one reports frames, seconds and a note saying the
  deliverable is the finding, never a password.

`evil_twin` (`attacks/twin.py`) generates a hostapd config in the session directory
(the target's SSID on `config.twin_interface` or the monitor interface), runs
`hostapd-mana` when it is installed and `hostapd` otherwise, and watches the tool's own
output for `AP-STA-CONNECTED` lines. Two outcomes are reported differently on purpose:
with the PSK already known (it was cracked earlier in the engagement) the twin is a
*working* access point and the finding is high severity — the network can be replaced;
without it, clients still try, the 4-way handshake fails, and the measurement is the
list of stations that preferred the SSID, at medium severity. The module never claims a
password it did not get, and the process is stopped in a `finally` block.

`wep.py` is a family of five rather than one attack: `wep_ivs` and `wep_p0841` can reach
the key on their own (the second injects its own ARP so a silent network still yields
IVs), while `wep_chopchop`, `wep_fragment` and `wep_hirte` recover keystream and are
reported as *enablers* — `stats.wep_enablers` counts them separately from
`stats.wep_cracks`, and the attempt carries `enables: wep_ivs` as the next step.
`wep_p0841` is the one that reuses the harvest loop with different aireplay arguments
(`_aireplay_command`), which is why the "does it need a client" question is a class
attribute (`uses_client`) instead of a conditional.

The ten floods (`attacks/flood.py` for the `mdk4` ones, `attacks/flood2.py` for the six
built in-process) are denial of service by construction, so they are capped twice — each
class has its own `max_seconds` (60 s for the deauth flood, 45 s for the mdk4 set, 30 s
for the in-process ones, 8 s for `tkip_michael`) and the planner refuses all of them in
stealth mode. Their deliverable is a finding about the *environment* (is 802.11w/WIDS
really deployed?), never a password, and the log warning before they start says exactly
what they will do to the network. `flood2.py` exists because these frames are not in
`mdk4`: association requests (the table that actually runs out), Null frames with the
power-save bit (a data-frame attack a deauth-counting WIDS cannot see), EAPOL-Start,
SAE commits, a corrupted-MIC TKIP replay, and deauths carrying a neighbour's BSSID.

The matching decoder lives in `sniff.py` (`eap_exchange`, `x509_name`) and works on
any capture: EAP type codes, the clear-text outer identity, and a small DER walker
that pulls the X.509 subject and issuer out of the TLS certificate message. Identical
subject and issuer is a self-signed certificate, and *that* is the finding — reported
as a certificate subject, never as a signature verification this tool does not do.

`rogue_radius` is the only attack here that is deliberately opt-in *and* transmits:
it starts eaphammer (or hostapd-mana/wpe with a generated config), watches the tool's
output for a credential, and stops the process group in a `finally` block whatever
happens. Nothing about a rogue AP is improved by leaving it running.

`tracker` is the read-only counterpart: one station, followed for as long as the
operator walks, with the signal *trend* reported next to the value it started from
(because a single number is not a measurement) and the raw samples written to loot as
JSON. It is scheduled before the noisy attacks because the client's preferred network
list decides which name is worth impersonating — the answer is usually already on air.

## 17. Performance

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
* **the capture tells the truth about itself.** EAPOL messages are parsed down
  to the flags that matter (ack/install/secure/MIC/encrypted/error), the key
  version (WPA/TKIP vs WPA2/RSN) and the MIC itself; exact retransmissions are
  recognised by replay counter + MIC and *counted* rather than stored again, so
  "12 EAPOL frames" and "1 handshake to verify" stop being the same number.
  `CaptureAnalysis.crackable_handshakes()` is the deduplicated, quality-sorted
  view a cracker wants: a handshake relayed by a second AP, or captured five
  times, costs one MIC check per candidate, not five.
* **verification state is prepared once.** `crypto.HandshakeVerifier` and
  `crypto.PmkidVerifier` hoist the per-capture work (EAPOL extraction, MIC
  zeroing, MAC parsing, AES-CMAC subkeys) out of the candidate loop, and
  `Cracker` derives the PMK once per candidate however many handshakes and
  PMKIDs the capture holds.
* **the crypto primitives are table-driven.** AES uses folded T-tables (~20x
  faster than the readable implementation, which is kept and cross-checked in
  the tests); the decryption schedule is built lazily because MIC checks only
  encrypt.  The MIC algorithm comes from the frame's Key Descriptor Version —
  HMAC-MD5 (KDV 1), HMAC-SHA1-128 (KDV 2, classic WPA2/CCMP), AES-128-CMAC
  (KDV 3, 802.11w/PMF and SAE) — not from the descriptor type; a version of 0
  ("whatever the negotiated AKM says") is the only case that tries two.  This
  is checked against hashcat's own published mode 22000 example, whose
  PMK/PMKID/MIC all reproduce.
* **the candidate loop is PBKDF2-bound.** At ~415 candidates/s on this container,
  2.31 ms of the 2.41 ms per candidate is PBKDF2-HMAC-SHA1 with 4096 rounds —
  the MIC verification is a rounding error on top (2.7 µs for HMAC-SHA1-128,
  0.18 ms for AES-CMAC).  That is the argument for the hashcat path: the KDF is
  the wall, and a GPU is the only thing that moves it.
* **benchmarks measure the real path** (`benchmarks/`, `make bench`): real
  captures, real handshakes, wrong candidates only, and the artifact (frame
  count, MiB, candidate space) printed next to every number.
* **the offline decoders are cheap enough to run on every poll.** The element walk is
  offset-based and allocation-light: decoding a 174-byte beacon with WPS, HT, VHT,
  country, extended-capabilities and mobility elements costs 28.6 µs
  (~35,000 beacons/s), so a 660-frame neighbourhood read is 16 ms and `ie_audit` is
  effectively free next to the capture it reads.  Frame building is cheaper still —
  4.2 µs per EAPOL-Logoff frame (~238,000 frames/s), which is why `eapol_logoff` can
  afford to preview the exact frames it will send.
* **counts are counts.** The built-in engine reports the candidates it actually
  derived, and its log line says how many it took to crack, so an early hit
  cannot be presented as a full sweep: the end-to-end benchmark stops at
  candidate #48 and reports 49 candidates at ~340/s, not the 2,799 it never
  derived — nor the 21,000/s that dividing the whole space by the elapsed time
  would have claimed.

Details and before/after numbers: README → *Performance*.
