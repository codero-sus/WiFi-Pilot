# Changelog

Notable changes to `wifipilot`, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are the branch's own
milestones rather than published releases.

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
