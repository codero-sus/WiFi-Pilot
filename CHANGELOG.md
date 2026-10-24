# Changelog

Notable changes to `wifipilot`, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are the branch's own
milestones rather than published releases.

## Follow-through: the last preload, and CI in parallel (catalogue 420)

* **Startup, finished** — the presets submodule preload (kept last round
  only as shadow-flip insurance) is removed now that the package-module
  guard covers it: `import wifipilot` 78 ms → 66 ms. The same round
  profiled the built-in cracker at the raw-PBKDF2 floor (408–418 vs
  413 candidates/s for `pbkdf2_hmac` alone — nothing left to shave) and
  tested-and-rejected waking the campaign loop on lane completions:
  6 s faster on the seeded bench but 9 passwords instead of 12, because
  the loop's give-up counters count rounds, and instantaneous rounds
  outrun in-flight work and late discovery. Speed that costs loot is
  not speed.
* **CI runs the full suite in parallel** — `pytest-xdist` joins the dev
  extra; the full-suite step uses `-n auto --dist loadfile` (each test
  file stays on one worker, so module fixtures remain coherent). The
  suite is wait-heavy, so waits overlap: locally 4m05s serial → 1m23s
  on 2 cores. Targeted steps stay serial for per-area signal.

## Startup & simulation wall-clock: lazy registry, honest demo clocks (catalogue 415–419)

* **Instant startup** — `import wifipilot` no longer loads the 848-attack
  registry before returning: 655 ms → ~78 ms (`wifipilot --json config`
  ≈ 0.13 s end to end). The registry, `Engine`, `ALL_ATTACKS` and `MODES`
  materialise on first use; `models.ATTACK_NAMES` is now written out in
  full (848 names, AST drift-guarded) so CLI validation, help text and
  the planner whitelist are correct before anything heavy loads. A
  module-class guard keeps the six function/submodule name twins
  (`wp.crack`, `wp.demo`, …) resolving to the API functions no matter
  what gets imported in what order.
* **Demo time is simulated, not slept** — demo floods and the tracker
  walk burned real wall-clock for their whole simulated window (8–12 s
  per flood). They now tick on a shared ~0.25 s cadence and report the
  simulated duration. Demo campaigns feel snappier; the test suite's
  slowest single test fell 170 s → 5 s.
* **`pins` is instant** — the CLI/API/web WPS-PIN endpoints built all
  10,000,000 ordered PINs to display the first page (30.3 s); they now
  slice the generator (0.18 s), and the sweep itself computes check
  digits arithmetically (full space 30 s → ~6 s, identical order).
* **`wifipilot demo` takes `-t/--time` and `-d/--duration`** — it used
  to discard user timing and always run a 20 s discovery plus the full
  plan (~35 s).

## Hardening round: CI de-flake, hostile-SSID fixes, TUI on the design tokens

* **CI de-flake** — the lone Python 3.13 failure was the full-suite step:
  `test_scan_for_exits_early_when_neighbourhood_settles` raced a
  wall-clock bound against a *random* demo neighbourhood. The test now
  seeds its world (`seed=42`, like `scripts/bench_campaign.py`), and
  `scan_for`'s settle clock only resets on a genuinely new AP — an
  expiring one no longer stalls discovery.
* **Attack-script hardening** — an ESSID is attacker-controlled bytes,
  and three sinks trusted it: the airgeddon portal's tmux launch built
  a shell string with `repr()` quoting (a hostile SSID could break out
  into arbitrary commands; everything is `shlex.quote`d now), the twin
  SSID was written raw into `hostapd.conf` in two attacks (a newline
  injected whole directives; new `util.config_safe()` for line-based
  configs), and the portal page served the SSID as raw HTML (escaped).
  Regression tests drive all three sinks with hostile SSIDs. The wider
  audit came back clean: one `Popen` chokepoint, zero `shell=True`.
* **TUI modernisation** — the live dashboard now draws from the same
  design tokens as the web console (sky accent, soft status colours,
  hairline panel rules, dot mode-badge, security column coloured by
  scheme). rich degrades hex colours gracefully, so plain-text output
  and every pinned dashboard string are unchanged.

## Sidebar navigation + modern console redesign (and live detection latency)

The web UI graduates from a top tab bar to a proper console:

* **Sidebar navigation** with grouped sections (Engage / Think / Machine),
  count pills, a collapse toggle (persisted) and keyboard shortcuts
  (`1`–`0` switch views, `/` focuses the target filter, `b` folds the
  sidebar). Four new views:
  * **Tasks** — campaign state, live progress, the running attack, a
    filterable attempt history and the findings feed, all off the
    existing snapshot (no new backend).
  * **Setup** — a readiness checklist (platform, radio, tools,
    wordlists, mode, advisor) plus one-click tool-install planning /
    execution, radio inventory, demo↔live switching, acceleration and
    wordlist summaries.
  * **Docs** — the bundled `docs/*.md` manuals rendered in-app via two
    read-only, traversal-guarded endpoints (`GET /api/docs[/{name}]`)
    with search and internal cross-links.
  * **About** — registry counts (848 = 288 Wi-Fi / 143 Bluetooth /
    417 IT), session/platform facts and credits.
* **Full visual redesign** — a professional dark console theme built on
  design tokens (layered surfaces, hairline borders, soft-tint status
  tags, tabular-numeral KPIs, sticky blurred topbar) and a stroke-style
  **SVG icon system** that replaces every emoji in the UI chrome,
  including the logo mark and favicon. All previous element IDs and the
  SPA's rendering pipeline are unchanged.
* **Live-radio detection latency** (catalogue 412–414): scanner CSV
  polling at 0.25 s mtime-gated slices, size-gated 0.25 s handshake
  analysis with a file-settle wait instead of the flat 1.5 s flush nap,
  and a check-first 0.25 s PMKID poll. Sightings and captures are
  noticed up to ~1 s sooner per event on real hardware.

## The wall-clock round — killing campaign dead air (and three real bugs)

Microseconds were never the campaign's problem; *waiting* was.
Profiling a demo `blitz` run showed ~63 of 74 seconds spent not
attacking.  This round removes that dead air (catalogue entries
401–411 in `docs/OPTIMIZATIONS.md`, marked ⏱; reproduce with
`scripts/bench_campaign.py` — seeded: **blitz 79.8s → 39.4s,
success 107.9s → 42.2s, with more passwords recovered: 8 → 12/13**):

* **No more echo rounds**: every productive plan round used to be
  followed by a wasted one re-offering the just-executed plan; an
  exhausted plan now bridges straight to a fresh heuristic plan.
* **No more 36-second dead tail**: finished campaigns slept a whole
  scan window (10–30s) per empty round before concluding there was
  nothing left; they now break as soon as everything in scope is
  handled.  Round-end pacing drops 2.0s → 0.25s, and discovery exits
  early once the neighbourhood settles (12s → ~5s on blitz).
* **Bug fix — `target=all` now means all**: the target list was frozen
  at the end of discovery, so APs appearing later were silently never
  attacked (and the planner nominating them anyway caused the dead
  tail above).  The planner is now scope-aware everywhere.
* **Bug fix — failed cracks are remembered**: a failed crack left no
  trace, so the planner re-nominated `crack` forever and one
  uncrackable capture could re-run the same wordlists until the
  campaign deadline.  Captures now carry the budget already spent;
  a larger budget or fresh loot may still retry.
* **Bug fix — no duplicate concurrent attacks**: the same
  (target, attack) could run twice via overlapping lanes/sweeps;
  an in-flight guard at the `run_attack` funnel now refuses that.
* **Cracks overlap the radio**: plan-nominated full cracks moved to
  the crack lane (they used to stall all radio work for up to
  `crack_timeout` each), with in-flight markers, lane-aware campaign
  completion and a stop-responsive shutdown reap.  The planner's
  attackable cache is now keyed on attempt *outcomes* and crack
  state, not just list lengths.

## The 400-optimizations sweep — the snapshot path, the rule engine, negative caching

The second sweep (catalogue entries 201–400 in `docs/OPTIMIZATIONS.md`,
new code marked ⚡; reproduce with `scripts/bench.py`):

* **The web snapshot is ~3.6× cheaper**: `engine._attack_catalog` no longer
  scans the 848-name enabled list once per attack (3.9 ms → 1.5 ms, cached
  per enabled/capabilities state); `SessionStats.to_dict` dropped its
  `asdict()` deepcopy; `Event.to_dict` formats timestamps once per event
  (5.9×); `AccessPoint.attackable()` is fingerprint-cached (8.3× warm) and
  `AccessPoint.to_dict` is 2.3×.
* **No more per-tick network probes**: LLM model-list failures are
  negative-cached by all three provider clients — with Ollama enabled but
  not running, the UI used to open a fresh TCP+HTTP request every tick
  (50 snapshots: 50 connects → 2).
* **Rule engine 1.9×**: commands are pre-parsed once and applied by a
  string-native engine whose equivalence with the list reference engine is
  fuzz-pinned in the test suite.
* **Bluetooth crypto ~4.8×**: AES key expansion is shared per key, so
  one-block users (BLE `ah()` RPA hashing) stop paying 37 µs to encrypt
  for 9 µs.
* **Correctness fixes found by the sweep**: `Event`/`Capture`/`Finding`/
  stats timestamps now report the record's own time instead of the moment
  it was serialised.
* Plus: vendor-dossier lookups LRU-cached, single-pass password class
  analysis, in-place pcap EAPOL search, one wordlist-discovery walk per
  crack (was up to three), and the full catalogue of the remaining
  subsystems' efficiency design (advisor, BLE, IT, simulators, frontend,
  updater, attack runtime).
* Behaviour preserved — `tests/test_optimizations.py` grew to 23 guards
  (rule-engine equivalence over ~700 cases, asdict parity, timestamp
  truth, negative-cache behaviour, FIPS vectors through the AES cache).

## The 200-optimizations sweep — every hot path, measured

A full-catalogue optimization pass (see `docs/OPTIMIZATIONS.md` for all 200
entries and `scripts/bench.py` to reproduce the numbers):

* **Planner**: the attack-action set is cached as a frozenset and the
  per-AP plan (`engine.attackable`) is cached on a fingerprint of everything
  the planner reads — `preferred_attacks` is **4.7× faster**, and repeat
  asks are dict lookups.
* **Config serialisation**: `to_dict()` no longer deep-copies the whole
  dataclass tree (`asdict`) on every web push — **4.7× faster**, equality
  with the old output pinned by tests.
* **Catalogue & metadata**: the 848-row attack catalogue is built once and
  copied per call (**4.1×**); per-attack metadata is cached copy-on-return.
* **Crypto**: PRF-512 uses pre-keyed HMAC templates (bit-identical output),
  verifiers precompute their PBKDF2 salt, PMKID message and PTK expansion
  input once instead of per candidate.
* **Tool registry**: `summary()` and `capabilities()` are cached until the
  next probe (**188×** on the 1 Hz web push), and adaptor-less machines no
  longer re-run interface enumeration on every call.
* **Utilities**: `mac_norm`/`oui_vendor` are LRU-cached (**7.9× / 24×**);
  event journaling writes through cached line-buffered handles instead of
  opening the file per line; event history is a bounded deque.
* **Cracker**: the multiprocessing pool starts with the fork context (no
  module re-import per worker), rule sets parse once per file mtime, and
  the serial verify loops use bound-method locals.
* **Web**: the state snapshot memoises wordlists (one discovery + 5 s TTL,
  was three per tick), presets and edition counts.
* Behaviour is unchanged — `tests/test_optimizations.py` pins equivalence
  (asdict parity, PRF identity, cache copy-isolation) for every cache added.

## Faster still — multiprocessing and acceleration are now the default

* **`accel="auto"` out of the box**: the cracker verifies candidates in a
  persistent multiprocessing pool (one process per usable CPU, affinity-mask
  aware), RAM de-duplication caches are always sized, and a detected GPU is
  handed to hashcat automatically.  `jobs` defaults to auto (one parallel
  attack lane per CPU, cap 8) and loot cracks on the background lane by
  default.  `--accel off` / `accel="off"` restores the classic single
  thread everywhere.
* **The crack pool is persistent**: previously every parallel pass spawned
  fresh worker processes (~100 ms each); one pool per cracker now serves
  every capture, verifiers ride with each chunk, and the parallel threshold
  dropped from 512 to 128 candidates.
* **`attack_timeout_for` is cached**: the ~200-entry budget table was
  rebuilt on every call (some attacks ask per loop iteration); it is now
  memoised per timeout-field set and never serialises.

## Speed — presets, FORCE postures, parallel lanes, hardware acceleration

One Wi-Fi network ran **1h 2m unfinished**: `mode="force"` enabled all 848
attacks at full budgets, the planner served them two at a time, loot cracks
blocked the next attack for up to three minutes, nothing had a deadline — and
rounds whose planned actions had all gone stale (target cracked since the plan
was made) re-executed the same dead plan forever.  Now a single network lands
in **7–12 minutes**:

* **Presets** (`wifipilot.presets`, `wifipilot presets`, `--preset`,
  `wp.attack(preset=…)`, web preset picker): named, time-boxed plans —
  `success` (highest-success-chance route to a key), `blitz`, `balanced`,
  `stealth`, `survey`, `rogue`, `enterprise`, `disrupt`, `bluetooth`, `it`,
  `full` — each with scaled budgets, a watchdog-enforced per-attack cap, a
  short scan and a campaign deadline of its own.
* **Postures in every preset**: `:force` (`--force` / `force=True`) is the
  opposite of stealth — loud, aggressive, broadcast deauth, boosters like
  `wps_pin`, success over subtlety.  `:stealth` strips everything that
  transmits.
* **Parallel everything that can be**: IT/offline attacks run on side lanes
  beside the one radio (`jobs`), loot cracks on a dedicated crack lane
  instead of blocking the capturing attack, per-round planner caching, and
  stale rounds now force an immediate replan (three dead rounds end the
  campaign).  Demo proof: `success` finishes the simulated neighbourhood in
  ~52s with 15 passwords; `blitz` in ~79s via the API.
* **Opt-in hardware acceleration** (`wifipilot.accel`, `--accel cpu,ram,gpu`,
  `wp.attack(accel="all")`): CPU = process-pool candidate verification
  (PBKDF2 across cores), RAM = bounded candidate de-duplication caches,
  GPU = hashcat pointed at the detected GPU.  Off unless the operator allows
  it; `wp.accel_info()` reports what the machine actually has.
* **`wifipilot tools install`** installs every missing external dependency
  for the detected distro (apt/pacman/dnf/zypper/apk), plan first, `--yes`
  to run; same on the web UI (`POST /api/tools/install`) and in Python
  (`wp.install_tools()`).
* **`wifipilot update`** updates in place from a downloaded zip snapshot —
  no git needed, current package backed up beside the new one.
* Credits: wifipilot is by **codero-sus** — github.com/codero-sus ·
  the-codero.web.app (now stated in the package, README, web footer,
  `--version` and project metadata).

## Fixed — every error ruff can see, and the live paths hiding behind them

A pyflakes sweep (`ruff --select F,E9`) found 200 errors the demo-driven
suite could not see. Most were dead imports and placeholder-less f-strings;
the interesting ones were live-only paths that had never executed:

* **`rogue_dhcp_detect` raised `NameError` on its first live frame** — it
  called `parse_ipv4` without importing it. Behind that sat the real bug:
  `parse_ipv4` never decoded UDP, so both DHCP listeners (`rogue_dhcp_detect`,
  `rogue_dhcp`) read a `sport` key that does not exist, skipped every frame,
  and fed `parse_dhcp` a BOOTP body still wearing its UDP header. The rogue
  DHCP *server* has therefore never leased anything outside demo mode.
  `parse_ipv4` now strips the UDP header and reports `sport`/`dport`;
  `tests/test_errorfixes.py` drives both live loops end-to-end.
* **Successful attacks filed as "skipped".** `pmf_downgrade_probe` and
  `btm_hijack` returned success without closing their attempt, so the
  engine stamped them skipped; their computed `severity` (and
  `mac_filter_probe`'s) never reached the report. Attempts are closed,
  severities ride in `extra`.
* Smaller drops on the floor, now wired or deleted: a management audit
  computed `http`/`https` and never recorded it; an SDP browse fetched the
  link state and never reported it; a mesh mimic opened a socket and link
  it never used; duplicate keys in the simulator's port map and the vendor
  table (all same-valued, all dead); a DHCP builder computing a client-id
  nobody sent (the discover builder already adds option 61 itself).
* `wifipilot/__init__.py` imported `catalogue`, `current_run`, `EK`, the
  LLM exception tree and the Config/AccessPoint/Capture classes for scripts
  but never listed them in `__all__` — now exported properly.
* **Prevention:** `[tool.ruff]` (F + E9 only) in `pyproject.toml`, ruff in
  the `dev` extra, an "Error gate" step in CI, and Python 3.13 added to the
  CI matrix. `make lint` no longer needs FastAPI installed to pass.

## Fixed — the web UI dies on machines that have a WiFi card

* **`ToolRegistry.summary()` shipped raw `WirelessInterface` dataclasses.** The
  REST endpoints never noticed — FastAPI's encoder converts dataclasses — but
  the WebSocket handler's plain `json.dumps()` raised `TypeError: Object of
  type WirelessInterface is not JSON serializable` on the very first state
  frame, killing the live UI on every real laptop. CI has no radio, so the
  list was always empty there and the suite stayed green. The summary now
  emits `to_dict()` rows (the shape `static/app.js` already renders), the
  three `json.dumps` calls in the socket go through a `_json_default` hook
  (`to_dict` → dataclass fields → ISO dates → sets/bytes → `str`) so no one
  stray object can take the stream down again, and three regression tests
  pin the behaviour with a mocked ath9k adaptor present.

## Relicensed — Apache-2.0 OR BSD-3-Clause (was MIT)

* **The project is now dual-licensed.** Every file is offered under the **Apache License
  2.0** *or* the **BSD 3-Clause License**, at the recipient's option — not both at once.
  The two texts live in `LICENSES/Apache-2.0.txt` and `LICENSES/BSD-3-Clause.txt`, `LICENSE`
  explains which to choose and what each costs you, and `NOTICE` carries the attribution
  Apache-2.0 asks downstream to propagate.

  * **Why Apache-2.0.** It adds an express patent grant (section 3) and patent
    retaliation, plus the "mark the files you changed" and NOTICE obligations. Corporate
    security teams, and anybody embedding `wifipilot` in a product, ask for exactly this.
  * **Why BSD-3-Clause as well.** It is the shortest obligation list in the catalogue and,
    unlike Apache-2.0, it can be combined with GPL-2.0-only code without a compatibility
    argument. Anyone who cannot take a patent clause can take this branch instead.
  * **Nothing was taken away.** MIT was already permissive and compatible with both; the
    dual grant adds a patent licence and a no-endorsement clause, and removes nothing that
    the old licence allowed. Copies of the previous MIT-licensed revisions stay MIT.

* **Machine-readable everywhere it matters.** `pyproject.toml` moved to PEP 639: a plain
  SPDX expression (`license = "Apache-2.0 OR BSD-3-Clause"`, not the deprecated
  `{ text = ... }` table) and `license-files`, with `setuptools>=77` to parse it. Every
  Python source in `wifipilot/`, `tests/`, `tools/`, `examples/` and `benchmarks/` — 138
  files — now opens with `SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause`, so
  `reuse`, `licensee`, `scancode` and friends have nothing to infer.

* **`THIRD-PARTY.md` added.** One page for the things this repository does not contain:
  the external tools it drives (aircrack-ng, reaver, bully, mdk4, hostapd, dnsmasq,
  hcxtools, hashcat, tshark, tcpdump, nmap — GPL-2.0/3.0, MIT, BSD-3 and the NPSL),
  the Python packages it imports (all permissive), and the services it talks to. It also
  spells out what changes the moment somebody bundles those binaries into an AppImage, a
  `.deb`, a snap or a container image: the bundle has to carry each GPL tool's licence
  text and a written offer of its source, and that obligation belongs to the bundle, not
  to `wifipilot`'s own dual licence.

* **What did not change.** The authorisation gate, `docs/ETHICS-AND-LEGAL.md` and the
  "authorised use only" warning are usage policy, not licence terms. They stay out of the
  licence on purpose: a field-of-use restriction inside a licence stops a project being
  open source and buys no legal protection that the law does not already give.

## 848 attacks — the peripheral wave: the devices a room already trusts

* **25 further Bluetooth attacks, 848 in total (Bluetooth 143).** The imitation wave was
  about being believed; this one is about what a believed device can *do*.  Every attack
  copies a device that exists on the simulated floor and then performs the device's own
  job, so the finding is never "the advertisement looked right" but a write that was read
  back, a notification a host recorded, a profile that opened, or a payload a scanner
  decoded:

  * **The peripherals (25).** A mouse that clicks on every desk bonded to the keyboard it
    copied, and a combo receiver that sends volume, mute and next-track instead of letters
    (`ble_mouse_mimic`, `ble_combo_dongle_mimic`); the door lock that takes the unlock
    command and the mesh lock that accepts a new admin key (`ble_lock_mimic`,
    `ble_lock_mesh_mimic`); the building — a bulb, a mesh lamp invited into its own
    network, a smart plug switching a washer on, a charger starting a session, a doorbell
    ringing, an IR hub firing a NEC frame, a UWB anchor rewriting the range
    (`ble_bulb_mimic`, `ble_mesh_lamp_mimic`, `ble_plug_mimic`, `ble_charger_mimic`,
    `ble_doorbell_mimic`, `ble_ir_hub_mimic`, `ble_uwb_anchor_mimic`); the clinical set —
    a fitness band, a thermometer, a blood-pressure cuff, an ECG patch, a chest strap and
    a patient monitor, five of them forged *readings* rather than commands
    (`ble_band_mimic`, `ble_thermostat_mimic`, `ble_pressure_mimic`, `ble_ecg_mimic`,
    `ble_hr_mimic`, `ble_patient_monitor_mimic`); the meter, the printer, the tracker, the
    vending telemetry, the scale and the air-quality monitor, which report from a read-back
    because they have nothing to write (`ble_glucose_mimic`, `ble_label_printer_mimic`,
    `ble_vehicle_tracker_mimic`, `ble_vending_mimic`, `ble_scale_mimic`,
    `ble_air_quality_mimic`); a soundbar that takes the AVDTP and AVRCP link the room's
    phone should have opened (`ble_soundbar_mimic`); and a beacon whose UUID, major and
    minor are cloned onto the air (`ble_ibeacon_mimic`).

* **The simulator now records what a *host* received, not just what a client sent.**
  A notification is not a request, so nothing can "succeed" on the wire: the only evidence
  is the receiving side's record.  `BleLink.notifications` is that record — handle, value,
  whether it was an indication — and it is what the six push-style attacks report against.

* **Two names were renamed rather than reused.** `ble_printer_mimic` and
  `ble_beacon_mimic` are the first imitation wave's attacks and still are; the peripheral
  wave ships as `ble_label_printer_mimic` and `ble_ibeacon_mimic`.  Reusing the strings
  would have overwritten two registry entries while every count still added up, which is
  exactly the failure mode `register_batch` cannot see.

* **A gated attribute is still an enumerable one.** A Read Request for an attribute that
  needs authentication is answered with *Insufficient Authentication*; the same attribute
  comes back from a Read By Type, and the wave's read path falls back to it.  The report
  keeps the two apart, because "the device refused me" and "nothing came back" are
  different findings.

## 823 attacks — the LAN half, second pass: the file and mail protocols, and the edge

* **61 further attacks, 823 in total (IT 417).** The IT wave grew past the routing and
  control protocols into everything a managed network runs, and then out to the malformed
  packets at the end of the protocol range:

  * **The second half of the wave (30).** FTP, SMTP, IMAP, rsync, VNC, RDP, DICOM,
    Elasticsearch, Jenkins and kubelet joins the relay family (ten relays whose claim is
    still that the client's bytes were the device's own); the same ten protocols get a
    mimic, and the mail and medical ones get a hijack — an anonymous FTP write, an open
    relay mailing in the CEO's name, a mailbox folder deleted in someone else's name, a
    study filed on the archive.  DNS, SSH, RDP and CoAP get a look-alike, the directory and
    the cache get a theft, and Elastic, kubelet, mDNS and SSDP get a forgery.
  * **The edge of the wave (31): `it_fuzz_*` and `it_survey_*`.**  Eight fuzzers send
    *legal packets at illegal sizes* — a DNS name of seven 68-byte labels, an SMB2
    negotiate offering 32 dialects that do not exist, an LDAP filter a kilobyte deep, a
    Modbus function code that is not a function, 300 SNMP varbinds in one get, a SIP
    request-URI four hundred characters long — and grade what the service does next.
    Eight surveys ask one question and read the whole inventory back: mDNS service types,
    the UPnP description URL, TR-069 firmware and connection status, the RTSP codec list,
    OPC-UA endpoints, memcached's stats, the MySQL greeting's version and salt, and the
    spooler's own identity.

* **Two new families, and the metadata to go with them.** `fuzz` is `dos · moderate ·
  degraded` and `survey` is `discovery · quiet · degraded`; the two families bring the IT
  edition its first denial-of-service and first discovery attacks, so the wave is no
  longer all rogue, capture and exploit.  Every family carries its own one-sentence
  defender note, filled in with the protocol and the port the attack runs on.

* **`it_relay_imap` is honest about a segment with no IMAP server.** Where the simulated
  network runs no responder, the relay hands back the login it carried and says so, rather
  than reporting a byte-for-byte match against bytes that never arrived.

## 762 attacks — the IT hijacker wave: seventy devices that answer as something else

* **70 further attacks, 762 in total (IT 356).** `attacks/ithijack.py` is the LAN half of the
  impersonation work.  Every attack talks to a real service — the simulated network in demo
  mode, the segment under test live — and every claim it makes is read back out of a
  capture, decoded again by the protocol's own codec.  Six families:

  * **`it_mimic_*` (14) — stand up the same service.** A second DNS server, a rogue DHCP
    handing out our own gateway, a rogue NTP that moves every clock, forged syslog in a
    device's name, a look-alike MQTT broker, CoAP endpoint, Modbus slave, BACnet device,
    RTSP camera, SIP registrar, raw-print service, mDNS responder, SSDP announcement and
    TFTP server.
  * **`it_impersonate_*` (12) — wear a device's identity.** ONVIF (manufacturer, model,
    firmware, serial), S7 (the CPU's order number), CIP (vendor, product, serial), SNMP
    (sysDescr), Cast, AirPlay, Kasa, MiIO, OPC-UA, IPP, STUN and the Docker API.
  * **`it_hijack_*` (12) — take over the session or the value.** RTSP PLAY with a chosen
    session id, a SIP re-REGISTER, a retained MQTT publish, an ONVIF stream-URI rewrite,
    a Modbus coil write, a BACnet priority-1 write, IEC 60870-5-104 command injection, a
    DNP3 link reset and integrity poll, print-job takeover, session-cookie replay, a forged
    TR-069 Inform and an ADB shell.
  * **`it_poison_*` (12) — corrupt what the network believes.** ARP gateway poisoning, DNS
    cache poisoning, NBNS name poisoning, mDNS name theft, SSDP response spoofing, a DHCP
    offer whose option 6 is us, an SNMP trap in another device's name, a forged BACnet
    I-Am, a LDAP referral, an SMB negotiate downgrade, RDP negotiation spoofing and a
    Telnet banner in the switch's name.
  * **`it_relay_*` (10) — be the wire.** Relays in front of Redis, memcached, MongoDB,
    PostgreSQL, MySQL, SMB, LDAP, Telnet, IPP and an HTTP basic-auth service, each one
    proving that the bytes the client received were the device's own.
  * **`it_steal_*` (10) — take the material.** The camera's stream URI, the printer's spool,
    a PLC's identity block, the badge database, a phone directory, retained MQTT topics,
    Kubernetes secrets, the Docker inventory, a MySQL greeting and an IoT device's sysinfo.

* **The wave is graded in two halves on purpose.** The *device* half is what the network's
  own host answered — that is the identity being worn.  The *wire* half is what our
  look-alike put on the link, read back out of the capture down to the field that matters
  (a lease, a topic, a value, a device name, an ARP claim).  `tests/test_ithijack_wave.py`
  proves the readers decode what the builders wrote, and then tests the claims in both
  directions: the relay that carried the device's own bytes reports byte-for-byte equality,
  and the printer we impersonate reports the printer's own name.

* **Also fixed:** `hijack75._arp_bytes` wrote the Ethernet ethertype (`0x0806`) where the ARP
  protocol type belongs (`0x0800`); a reader that validates the field rejected every frame
  the Wi-Fi wave built.

## 692 attacks — the hijacker wave: 75 more ways to be the network

* **75 further attacks, 692 in total (Wi-Fi 288).** `attacks/hijack75.py` is the Wi-Fi half
  of the impersonation work, in six families that share one base class each:

  * **`twin_*` (19) — be the access point.** Every attack builds its twin from the target's
    own beacon and then changes exactly one axis: the address, one information element, the
    RSN's PMF bits, TKIP instead of CCMP, WPA3 in transition mode, OWE, the hidden name, the
    enterprise settings, the mobility domain, the BSS load, the country element, the probe
    responses, the signal level (the twin's capture carries an RSSI and the attack is graded
    on what the reader finds there), the SSID suffix, the second name, WMM admission control,
    the neighbour report and the quiet element.  Each one reports the axis it matched and the
    axis it did not, decoded from two beacons in a capture.
  * **`client_*` (12) — be the client.** Association forgery, the association-table flood
    (which is the memory exhaustion a WPA3 AP suffers from a hundred forged associations,
    while the wired side is left alone), sleep-mode spoofing, PS-Poll theft, TDLS teardown,
    SA Query bypass, the roaming hijack, EAPOL-Logoff, the four-way-handshake race (msg 3
    replayed under the same counter), the A-MSDU injection and the Block Ack hijack of
    FragAttacks, and the rate-set downgrade.
  * **`steer_*` (12) — make the client move.** BSS transition management requests (with and
    without a disassociation Imminent bit), radio-measurement beacon requests, channel-load
    steering, spectrum management, FILS discovery, WNM sleep, TWT setup, power constraint,
    the SSID-list offset, TPC requests and the probe answer.
  * **`session_*` (11) — be the wire.** Gateway impersonation by ARP, DNS spoofing, TCP
    resets, sequence injection, cookie replay, GTK rekey, the EAPOL-Key message-one flood,
    the deauthentication race, the roam capture, data replay and the ARP flood — all built
    on the module's own IP/TCP/ARP writers and graded on what the readers decode.
  * **`portal_*` (11) — be the login.** The captive portal clone (plus the wildcard DNS that
    makes every client find it), the WISPr redirect, ANQP spoofing, the certificate phish,
    the HSTS downgrade, basic auth, cookie cloning, the OAuth phish, credential reuse and
    JavaScript injection.
  * **`enterprise_*` (10) — be the RADIUS.** The rogue authenticator, the PEAP relay that
    keeps the tunnel intact and reads the MSCHAPv2 exchange inside it, the certificate swap,
    EAP-MD5, the GTC prompt, TTLS/PAP, the MSCHAPv2 relay, anonymous-identity harvesting,
    the EAP downgrade and the supplicant clone (with a self-signed certificate and a real
    EAPOL-Request/Identity).

* **The wave exercised the readers.** Building these attacks meant writing the capture
  readers that grade them — ARP replies, IP/TCP segments with their flags, DNS answers, MAC
  and cleartext text, action frames by category, EAPOL-Key frames with their replay counter
  and install bit, beacons with their element lists, and the radiotap signal level of every
  frame — and then proving in `tests/test_hijack_wave.py` that each one decodes what the
  builders wrote, in both directions: a clone that matches every axis reports that it
  matches, and the one that changes a single axis reports *that* axis.

## 617 attacks — the impersonation waves: 75 more ways to be somebody else

* **75 further attacks, 617 in total (Bluetooth 118).** Two waves, both about *being
  trusted when you are not*:
  * **`attacks/blemimic.py` — 25 attacks that fake a device convincingly.** `ble_hid_mimic`
    advertises the HID service from a copy of the keyboard's own advertisement, waits for
    the hosts that reconnect to a name they already trust, and types at them.  The rest of
    the family is the same idea in every posture the floor carries: a speaker, an earbud,
    a tracker, a fast-pair tag, a badge reader, a lock, a doorbell, a printer, a beacon
    (`ble_speaker_mimic`, `ble_tag_mimic`, `ble_fastpair_mimic`, `ble_badge_mimic`,
    `ble_lock_mimic`, `ble_beacon_mimic`, …), each one built from the *observed* device's
    own advertising data, so the clone answers the same probes with the same names.
  * **`attacks/blehijack2.py` — 50 attacks that take a link over.** Fourteen run against
    the classic profiles (HFP: headset, audio gateway, `ble_map_hijack`, `ble_pbap_hijack`,
    `ble_sap_imsi_read`, `ble_obex_push`, `ble_spp_hijack`, `ble_hidp_classic_inject`,
    `ble_audio_session_takeover`), twelve against the attribute table
    (`ble_gatt_write_sweep`, `ble_gatt_blob_dump`, `ble_notify_spoof`,
    `ble_signed_write_bypass`, `ble_att_handle_brute`, …), twelve at the air and link layer
    (`ble_irk_crack`, `ble_rpa_follow`, `ble_adv_flood_le`, `ble_scan_hog`,
    `ble_phy_request`, `ble_data_length_abuse`, `ble_ll_unknown_probe`,
    `ble_encryption_negotiation`, …) and twelve at the security manager
    (`ble_passkey_bruteforce`, `ble_oob_claim`, `ble_lesc_downgrade`, `ble_keypress_spoof`,
    `ble_ctkd_cross_transport`, `ble_bond_overwrite`, `ble_confirm_replay`, …).  Every one
    of them is decoded with a parser from `bt.py`, and the finding is what the parser said.
* **The floor grew the devices those attacks need (`blesim.py`).** 66 devices across 14
  postures, 19 link roles and the classic-profile engines: an AVDTP/AVCTP media path with
  a picky AV receiver, an HFP car kit that answers AT commands, an OBEX phone with a
  phonebook and a message store, a Bluetooth SAP reader over RFCOMM, an HIDP television
  that requires a bond, a BNEP PAN access point, and a GATT library that serves real
  characteristics (a Lock-Front with a state/control/admin-key table, a fast-pair tag, a
  media player with a volume characteristic, a service-changed hold).
* **`bt.py` gained the codecs those engines speak:** `aes_cmac` (RFC 4493, checked
  against the specification's own test vectors), `h7` and the CMAC salt, AVDTP/AVCTP/AVRCP,
  HIDP, BNEP, SAP and APDU framing, and `ef_imsi` — so a demo run and a capture are read
  by the same code.
* **Tests:** `tests/test_ble_mimic_wave.py` and `tests/test_ble_takeover_wave.py` — the
  whole wave runs in demo mode and every attack has to end `success`, plus the engines
  (the AT command, the OBEX store, the SAP reader, the PSM sweep, the attribute table, the
  link layer, the security manager, the HIDP and AVDTP paths) and the negative controls: a
  lock that checks the write refuses it, and a television that requires a bond takes no
  keystrokes from an open link.

## 542 attacks — the BLE wave: keyboards, downgrades and identity

* **8 further attacks, 542 in total (Bluetooth 43).** A wave that lives in
  `attacks/blehid.py` and answers the question a Bluetooth assessment is really about: a
  BLE keyboard is a GATT server that *notifies* its host, and a host that subscribes
  believes every notification it receives on the report characteristic.
  `ble_hid` advertises the HID service, enumerates the report characteristic over ATT and
  types the payload as boot reports, decoded back with the toolkit's own decoder;
  `ble_hid_audit` finds which hosts accept input without a bond; `ble_hid_boot` writes the
  protocol mode back to boot protocol and reads it back; `ble_hid_reconnect` impersonates
  the keyboard a host already bonded and counts the hosts that reconnect to the name and
  address instead of checking the link key; `ble_smp_downgrade` offers Just Works with a
  seven-byte key and reports what each device settled for; `ble_gatt_hijack` writes a
  control characteristic and verifies it by reading the value back; `ble_irk_resolve`
  follows a device through its rotating addresses with the identity keys that leak;
  `ble_conn_param_hijack` asks the link layer for the shortest interval the specification
  allows and reports which peers accept being starved of radio time.
* **The simulation grew the postures the wave needs (`blesim.py`).** 50 devices across 9
  profiles: five HID hosts bonded to one keyboard, three that reconnect to it and two that
  verify the link key, the HID-over-GATT service with a real report map, HID Information,
  a Protocol Mode characteristic and a report characteristic served on 0x0005. ATT writes
  persist and are read back, the SMP responder negotiates or refuses on the *offer* (a
  weak offer to a device that requires MITM or Secure Connections gets a Pairing Failed,
  and the answer is a real Pairing Response), and advertising under a bonded identity makes
  the hosts that trust that identity connect — which is the whole reconnect attack.
* **Correctness fixes the wave forced, each with the specification behind it.**
  * `bt.ah` is the privacy function of Core Vol 3 Part H 2.2.2: **one** AES block of
    ``prand`` zero-padded to 128 bits, with the hash taken from the low 24 bits of the
    output, and the address written ``prand || hash`` with prand most significant — which
    is why the ``0b01`` marker is visible in the first octet of every resolvable private
    address. The implementation is now checked against the specification's own sample data
    (IRK `ec0234a3…`, prand `0x708194` → hash `0x0dfbaa`).
  * `bt.LL_CONTROL_OPCODES` was shifted by one: every link-layer PDU in a capture was
    named after its neighbour, and the feature pages were read out of the wrong opcodes.
    The table is the specification's own now, and `parse_ll_header` reads features from
    LL_FEATURE_REQ/LL_FEATURE_RSP/LL_PERIPHERAL_FEATURE_REQ (0x08/0x09/0x0E).
  * `blesim` read the peer address of ``LE Create Connection`` one byte late, so a run
    that named a device connected to a different one.
  * `hid_key_reports` typed letters and dropped everything else: a payload of `id\n`
    pressed no Enter key, and neither a space nor a `|` nor a `/` was ever typed. The
    keyboard now types printable ASCII, punctuation and shift symbols, plus Enter, Tab,
    Escape, Backspace and Delete, and `hid_type_plan` reports the characters a boot
    keyboard cannot type. The shipped payload is `id\n` — a command line is submitted.
* **Tests:** `tests/test_attacks_ble_wave.py` — 26 tests over the wave, the HID
  encoder/decoder round trip (every printable character, one at a time), the ``ah`` sample
  vector, the link-layer table, and the simulated floor's postures.

## 248 attacks — the famous ones, by name

* **12 further attacks, 248 in total.** Every name on the brief that was still missing,
  and no name that was already there counted twice: DHCP starvation, the rogue DHCP
  server, the DHCP flood, the UDP flood and the forged RELEASE/DECLINE were already in
  the network wave (the forged-release attack has said *RELEASE / DECLINE* in its label
  since it was written — a DECLINE is the same packet aimed at the pool), as were the
  evil twin, SSID confusion, the deauthentication flood, beacon flooding and Karma.
* **The Bluetooth classics, all nine of them (`attacks/btred.py`).** BlueBorne
  (`bt_blueborne`: the malformed L2CAP configuration, information and SDP requests, with
  a liveness check after each), BIAS (`bt_bias`: the peer that has a stored key and still
  completes a legacy pairing), KNOB (`bt_knob`: the key size the controllers actually
  negotiated, read out of the controller's own Encryption Change event), BlueBugging
  (`bt_bluebugging`: AT commands over RFCOMM), BLESA (`bt_blesa`: ATT work sent before
  authentication completes), SweynTooth (`bt_sweyntooth`: the malformed link-layer
  battery with a ping after each PDU), BlueSnarfing (`bt_bluesnarf`: OBEX GET against the
  phonebook objects), BlueSmack (`bt_bluesmack`: escalating L2CAP echoes up to the largest
  PDU that fits one ACL packet) and HID injection (`bt_hid_injection`: advertise the HID
  service, then type with eight-byte boot reports as ATT notifications).
* **The three famous Wi-Fi attacks that were only detectors (`attacks/famous.py`).**
  `krack_replay` finds message 3 of a captured four-way handshake and replays it in a QoS
  data frame with the retry bit set — the reinstall KRACK is built on; `fragattacks_inject`
  builds the aggregation flaw (plaintext A-MSDU with the present bit set, a gateway source
  address and a real IP packet inside) and the fragment-cache pair (a plaintext first
  fragment with More Fragments, then a non-contiguous sequence);
  `airgeddon_portal` prepares the whole evil-twin captive-portal pipeline (hostapd,
  dnsmasq blackhole, portal document root, handshake for the check) and either starts
  airgeddon in a tmux session — it is menu-driven by design, and the report says so — or
  serves wifipilot's own portal and says *that* is what ran.
* **The protocol layer grew the profiles those attacks need (`bt.py`):** RFCOMM frame
  building with the LAPB CRC-8, the OBEX packet and header codec (CONNECT/GET/SETPATH,
  response codes, multi-packet body reassembly), HID over GATT (the boot-keyboard report
  map, the usage-ID table, key strings to press/release report pairs, the attribute table
  and the handle-value notification), the HCI link-control command set (authentication,
  key replies, IO-capability and confirmation replies, feature pages) and the BR/EDR
  feature tables, page 2 included, because that is where Secure Connections lives. The
  four service groups (`PRINTER`, `AUDIO`, `HID`, `WEARABLE`) that `__all__` had promised
  since the first wave finally exist, and `parse_features_event` decodes a feature
  complete event into named bits.
* **Config:** `bt_handle`, `hid_payload` and `gateway_mac`, plus per-attack budgets for
  all twelve (30–60 s for the probe batteries, 90 s for the portal pipeline).
* **Tests:** `tests/test_attacks_famous.py` — 24 tests over the OBEX, RFCOMM, HID and LMP
  helpers, the KRACK and FragAttacks frame shapes (including the A-MSDU present bit, the
  retry bit and the non-contiguous fragment numbers), the airgeddon workspace, the
  batteries of all seven link-layer Bluetooth attacks, and a demo run of every
  transmitting attack in the wave — which is how the wave caught its own two bugs: a
  battery list built from tuples instead of labels, and a 65 KB echo that no ACL length
  field can express.

## 236 attacks — the second radio, and the network behind the bridge

* **55 further attacks, 236 in total.** Two waves, and both of them leave the 802.11
  header behind: one goes down to the radio next door, the other goes up to the wired
  network the access point is bridging.
* **`btattacks.py` (26 attacks).** Fourteen offline audits of a Bluetooth Low Energy
  capture — the device census, tracker detection and follow-through, the iBeacon and
  Eddystone inventories, address privacy, the manufacturer and service censuses, the
  advertising interval and channel analyses, and the audits of what the devices are
  *offering* (connectable advertising, a captured pairing exchange, the GATT table and
  the link-layer features) — plus twelve that use the host's own controller: a live LE
  scan, classic inquiry, an advertising name flood and channel DoS, an iBeacon and a
  tracker clone, a connectable lure, a pairing flood, an L2CAP echo flood, and SDP,
  RFCOMM and GATT enumeration against `--bt-target`.
* **`netdos.py` (29 attacks).** Five capture audits — the DHCP lease table rebuilt from
  the wire (conflicts, forged RELEASEs, a second server), the IPv6 prefix and router
  inventory, cleartext device credentials, the embedded service census and the UPnP
  census — and twenty-four that build real protocol traffic: DHCP starvation, a DHCP
  flood, forged RELEASE/DECLINE, NAK injection and option injection; SYN, UDP and
  reflection floods; TCP RST injection; ICMP redirect and unreachable injection; a rogue
  router, an RA flood and neighbour spoofing; LLMNR, NBNS and mDNS poisoning; an STP
  root takeover, LLDP and CDP spoofing, a VLAN double-tag hop; and MQTT, RTSP and PJL
  service audits.
* **`bt.py` and `netstack.py`, written from scratch.** A Bluetooth LE decoder (advertising
  PDUs, beacons, trackers, L2CAP, ATT, SMP and the HCI command/event layer) and an
  Ethernet/IP/TCP/UDP/ICMPv6/STP/LLDP/CDP dissector with matched builders, so both waves
  read a capture and *produce* the frames they describe with the same code.
* **`synth.build_bt_scene()` and `synth.build_network_scene()`** generate the demo
  material for both waves: a deterministic BLE capture of ten devices (beacons, a rotating
  tracker, a sensor at 20 ms, a connection that pairs with Just Works) and a deterministic
  network capture in which every audit has something real to find.
* **The five attacks the brief named** are in the catalogue by name — `dhcp_starvation`,
  `dhcp_flood`, `forged_dhcp_release`, `udp_flood` and the rogue DHCP server
  (`rogue_dhcp`, in the rogue-infrastructure wave) — together with the classics they sit
  next to, `syn_flood` and `tcp_reset_injection`.
* **`wifipilot web` now works without `rich`.** The CLI advertised "works without rich,
  just plainer" while several commands raised `NameError: Panel`; the no-rich path now has
  plain stand-ins for the panels, tables and bars, so a minimal box runs the tool and the
  web UI with nothing but fastapi and uvicorn installed.

## 181 attacks — the offline half gets its teeth

* **127 further attacks, 181 in total.** The new wave is dominated by *offline analysis*:
  102 attacks that read a capture and transmit nothing at all, so an engagement gets its
  findings from files the session already has (`wifipilot attacks --no-radio`).
* **`offline3.py` (55 attacks)** decodes the frames themselves: the RSN element (ciphers,
  AKMs, PMF bits, transition mode, TKIP countermeasures), IE anomalies and malformed
  elements, probe privacy and randomised-MAC ratios, association history, retransmission
  and fragmentation rates, TSF skew and beacon-rate outliers, QoS and power save, DHCP
  fingerprints, gratuitous ARP and ARP scans, auth/association/deauth storms, handshake
  message inventories, encapsulation ratios, duplicate sequence numbers, a capture report
  written as a JSON artefact, and a station/vendor/frame-size inventory.
* **Six real bugs the new audits found in the tool itself**, all fixed:
  * `pcap.py` divided a microsecond capture's sub-second field by `1e9` instead of `1e6`,
    so *every* timestamp was a thousandth of a second early — which turned "10 beacons a
    second" into "10000 beacons a second" for every rate, burst and drift calculation;
  * `synth.build_probe_request` wrote beacon-scale fixed fields, making every directed
    probe request look like a wildcard one;
  * `synth.build_assoc_request` emitted its SSID element twice, so the name read back out
    of an association request was a length byte and a rate tag;
  * `synth.build_scene` built the association requests from whatever SSID the beacon loop
    left behind, and its beacons had a clock that ran at 60x real time;
  * `frames.parse_80211` left probe-request SSIDs as raw bytes, which crashed the privacy
    audit the moment a real directed probe appeared (`TypeError: expected str`);
  * `OfflineAttack` and the scene builder are now consistent about which capture an
    offline audit reads (a survey audit handed the session's handshake capture reports a
    confident zero — worse than reporting nothing).
* **The scene is richer, and the audits find things in it:** a hidden network whose name
  leaks in the association requests, WPA2/WPA3 transition and pure-WPA3 networks, a
  TKIP-only RSN element with both pairwise ciphers advertised (a downgrade target),
  Michael-countermeasure deauths (reason 15/16), a forged clone with a frozen clock and
  double the beacon rate, retries and fragments, QoS/power-save stations, directed and
  wildcard probes, shared-key authentication, ARP sweeps, a truncated beacon and a KARMA
  probe response.
* **Registration is a wave, not an edit:** a batch module carries its metadata and
  registers with one tuple entry (`attacks.BATCH_MODULES`), extending
  `models.ATTACK_NAMES` in place so the planner, the CLI and the AI pilot see it. Every
  attack gets a timeout budget from its own category when it is not named explicitly.
* **`docs/ATTACKS.md` now ends with the complete generated catalogue**
  (`tools/gen_attack_docs.py`, checked into the test suite), because a hand-maintained
  list of that many entries is a list that is wrong.

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
