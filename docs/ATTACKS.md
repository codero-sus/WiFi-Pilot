# Attacks

wifipilot ships **848 attacks** across three editions (288 WiFi, 143 Bluetooth, 417 IT
services and devices): every technique a WiFi assessment genuinely needs, and
nothing that exists only to lengthen the list — the offline half of the catalogue was
built the same way the headers of a report are, by asking what a *capture* can still be
made to say. The families are **offline analysis**
(one hundred and two attacks that read files and transmit nothing at all), **surveys** (passive
decoding: elements, RSN, PNL, SAE parameters), **capture** (handshake, PMKID, the
active hunt, the hcxdumptool pipeline), **WPS/WEP/802.1X**, **WPA3** (which is an
audit, not a crack), **rogue infrastructure and lures** (impersonation, channel-switch
announcements, SSID confusion), and the **denial-of-service tests** that are opt-in,
time-capped and honest about it. What follows is the reference for each one:
**what question it answers, what it costs, what it puts on the air, and how to read
the result** — including the failure modes, which are the part most tools leave out.

Every attack also carries machine-readable metadata — category, noise, impact and a
"what a defender sees" sentence — in `wifipilot/attacks/meta.py`. `wifipilot attacks`
prints it, `/api/state` returns it, and `tests/test_attacks_v3.py` fails if an attack
is registered without it.

The one rule the whole set follows: an attack that cannot answer its question is not
shipped. There is no "WPA3 crack" here, because SAE cannot be checked offline, and
there is no 40-entry list of tools pretending to be techniques.

If you have not read it yet, [ETHICS-AND-LEGAL.md](ETHICS-AND-LEGAL.md) explains the
authorisation gate. Nothing here is a way around it: the attacks that transmit refuse
to start without `--i-am-authorized` (or the UI checkbox, or `authorized=true`).

---

## Contents

| section | attacks |
| --- | --- |
| [1. The table](#1-the-table) | the quick reference: what each attack needs and costs |
| [2. Choosing an attack](#2-choosing-an-attack) | how the planner (and you) should pick |
| [3. Read-only intelligence](#3-read-only-intelligence) | `ie_audit`, `pnl_harvest` — transmit nothing |
| [4. Capture attacks](#4-capture-attacks) | `pmkid`, `pmkid_flood`, `handshake` |
| [5. Online and semi-online](#5-online-and-semi-online-attacks) | `wps_pixie`, `wps_pin`, the five WEP attacks |
| [6. WPA3 and RSN](#6-wpa3-and-rsn-the-two-honest-attacks) | `saewolf`, `pmf_audit` |
| [7. Rogue infrastructure and DoS tests](#7-rogue-infrastructure-disconnects-and-denial-of-service-tests) | `evil_twin`, `karma`, `eapol_logoff`, the four floods |
| [8. Surveys](#8-surveys-and-why-they-are-attacks) | `hidden_ssid`, `rogue_ap`, `enterprise`, `rogue_radius`, `tracker`, `passive` |
| [9. What each attack costs](#9-what-each-attack-costs) | runtime, noise, prerequisites |
| [10. Interpreting failures](#10-interpreting-failures) | the message → cause → next step table |
| [11. Where the AI fits](#11-where-the-ai-fits) | proposals, validation, and what happens with the advisor off |
| [12. Offline analysis](#12-offline-analysis-ten-attacks-that-transmit-nothing) | `loot_audit`, `eapol_audit`, `wep_audit`, `crack_sweep`, `eap_md5_crack`, `pixie_offline`, `rogue_detect`, `twin_detect`, `roam_audit`, `wps_lockout_audit` — no radio, no authorisation |
| [13. Capture, lures and confusion](#13-capture-lures-and-confusion) | `handshake_broadcast`, `hcxdump_capture`, `csa_attack`, `ssid_confusion`, `ssid_bruteforce`, `karma_detect`, `ap_isolation_audit` |
| [14. WPS and WPA3 parameters](#14-wps-and-wpa3-parameters) | `wps_ap_pin`, `wps_lockout_probe`, `wps_pbc`, `sae_group_audit` |
| [15. The second wave of floods](#15-the-second-wave-of-floods) | `assoc_flood`, `null_data_flood`, `eapol_start_flood`, `sae_commit_flood`, `tkip_michael`, `wids_confusion` |
| [16. Reading the catalogue](#16-reading-the-catalogue) | `wifipilot attacks`, the metadata table, and how to add an attack |

---

## 1. The table

| Attack | Family | Transmits | Needs | Answers | Default |
|---|---|---|---|---|---|
| `ie_audit` | read-only | no | airodump-ng (or any pcap) | "What does this AP say about itself — RSN, WPS, HT/VHT, 802.11r/k/v?" | ❌ safe |
| `pnl_harvest` | read-only | no | airodump-ng (or any pcap) | "Which networks are the clients here asking for, and which are not on air?" | ❌ safe |
| `pmkid` | capture | no\* | hcxdumptool or airodump-ng | "Is there a PMKID I can crack offline, without a client?" | ✅ |
| `pmkid_flood` | capture | **yes** | airodump-ng + aireplay-ng | "The AP is quiet — can I force a PMKID out of it now?" | ❌ loud |
| `handshake` | capture | **yes** | airodump-ng + aireplay-ng, ≥1 client | "Can I force a fresh 4-way handshake out of this AP?" | ✅ |
| `wps_pixie` | online/offline | mildly | reaver/bully, WPS unlocked | "Is this WPS implementation one of the broken ones?" | ✅ |
| `wps_pin` | online | **yes, slow** | reaver/bully, WPS unlocked | "Does the AP accept a guessed PIN?" | ❌ opt-in |
| `wep_ivs` | legacy | yes | airodump-ng + aireplay-ng, ARP traffic | "Is this WEP network still decryptable in minutes?" | ✅ |
| `wep_p0841` | legacy | yes | aireplay-ng | "No ARP traffic at all — can I inject my own and still harvest?" | ❌ opt-in |
| `wep_chopchop` | legacy enabler | yes | aireplay-ng | "Can I decrypt one packet without any client and without the key?" | ❌ enabler |
| `wep_fragment` | legacy enabler | yes | aireplay-ng | "Can I obtain keystream from one captured packet fast?" | ❌ enabler |
| `wep_hirte` | legacy enabler | yes | aireplay-ng + a client | "The AP ignores me — can I get keystream from a client's traffic?" | ❌ enabler |
| `saewolf` | WPA3 | no | airodump-ng | "Is this WPA3 network really WPA3-only, or is the WPA2 door still open?" | ❌ opt-in |
| `pmf_audit` | WPA3/RSN | no | airodump-ng | "Which classic attacks are still possible against this network?" | ❌ opt-in |
| `hidden_ssid` | survey | no\* | airodump-ng | "What is the name of this hidden network?" | ✅ |
| `rogue_ap` | survey | no | nothing | "Is somebody already impersonating this network?" | ❌ situational |
| `enterprise` | survey | no | airodump-ng | "What does the 802.1X conversation expose, and is the server certificate checkable?" | ❌ situational |
| `evil_twin` | rogue AP | **yes** | hostapd or hostapd-mana | "Will clients prefer my copy of this SSID, and can I replace the network?" | ❌ opt-in |
| `karma` | rogue AP | **yes** | hostapd-mana (`enable_mana=1`) | "Will a station join a network that exists only because it asked for it?" | ❌ opt-in |
| `eapol_logoff` | disconnect | **yes, small** | a monitor interface, 3 frames per client | "Does this client tear down its session for an unauthenticated Logoff?" | ❌ opt-in |
| `rogue_radius` | rogue AP | **yes** | eaphammer or hostapd-mana/wpe | "Will a client hand its credentials to a server it has never seen?" | ❌ situational |
| `deauth_flood` | DoS test | **yes, heavily** | mdk4 (or aireplay-ng) | "Is 802.11w/WIDS actually deployed here, or only documented?" | ❌ opt-in |
| `auth_flood` | DoS test | **yes, heavily** | mdk4 | "Can the AP's association table be filled, and does anything notice?" | ❌ opt-in |
| `probe_flood` | DoS test | **yes, heavily** | mdk4 | "How do the clients and the WIDS react to a storm of probe requests?" | ❌ opt-in |
| `beacon_flood` | DoS test | **yes, heavily** | mdk4 | "Does this site notice a beacon flood?" | ❌ opt-in |
| `tracker` | survey | no | airodump-ng | "Which networks does this device really trust, and where is it going?" | ✅ |
| `passive` | survey | no | airodump-ng | "What is on air right now, with zero risk?" | ❌ situational |
| `loot_audit` | offline | **no** | nothing | "What do we actually hold, and what is missing from it?" | ❌ safe |
| `eapol_audit` | offline | **no** | nothing | "Is this capture a *usable* handshake, or four frames that look like one?" | ❌ safe |
| `wep_audit` | offline | **no** | nothing | "Is this WEP capture crackable now, or does it need another harvest?" | ❌ safe |
| `crack_sweep` | offline | **no** | a wordlist (optional) | "Sweep everything we hold through the cracker while I read the report" | ❌ safe |
| `eap_md5_crack` | offline | **no** | nothing | "Is this 802.1X deployment using the one EAP method with an offline attack?" | ❌ safe |
| `pixie_offline` | offline | **no** | pixiewps | "Can the WPS exchange we captured be solved with the radio unplugged?" | ❌ safe |
| `rogue_detect` | offline | **no** | nothing | "Is there rogue or cloned infrastructure in these captures?" | ❌ safe |
| `twin_detect` | offline | **no** | nothing | "One SSID, several BSSIDs — which of them moved?" | ❌ safe |
| `roam_audit` | offline | **no** | nothing | "Would a forged CSA or deauth land here (802.11k/r/v, PMF)?" | ❌ safe |
| `wps_lockout_audit` | offline | **no** | nothing | "How does this AP's WPS lockout policy read from what we already have?" | ❌ safe |
| `handshake_broadcast` | capture | **yes** | airodump-ng + aireplay-ng, ≥1 client, `broadcast_handshake` | "The quiet handshake keeps failing — what if every client drops at once?" | ❌ opt-in |
| `hcxdump_capture` | capture | **yes** | hcxdumptool + hcxpcapngtool | "Hand the whole problem to hcxtools and get mode-22000 lines back" | ❌ opt-in |
| `sae_group_audit` | survey | no | a capture (or a short listen) | "Which SAE groups, is H2E advertised, and is PMF required?" | ❌ opt-in |
| `wps_ap_pin` | WPS | yes | reaver, WPS unlocked | "Is the *static* AP PIN derived from the BSSID on this device?" | ❌ opt-in |
| `wps_lockout_probe` | WPS | yes, 3 frames | reaver, WPS unlocked | "Does WPS lock out, and after how many wrong PINs?" | ❌ opt-in |
| `wps_pbc` | WPS | **yes** | wpa_supplicant + wpa_cli, a managed interface | "Is a push-button window open right now?" | ❌ opt-in |
| `karma_detect` | rogue | yes, quietly | a monitor interface | "Is something out there answering probes for names that cannot exist?" | ❌ opt-in |
| `csa_attack` | rogue | **yes** | a monitor interface | "Will clients follow a channel-switch announcement from an AP's name?" | ❌ opt-in |
| `ssid_confusion` | rogue | **yes** | a monitor interface | "Do these clients select a network by name alone?" | ❌ opt-in |
| `ssid_bruteforce` | rogue | yes, patient | a monitor interface, a hidden AP | "Will the hidden AP answer for the name it is hiding?" | ❌ opt-in |
| `ap_isolation_audit` | rogue | yes, quietly | a monitor interface, ≥2 clients | "Can one guest reach another on this 'isolated' network?" | ❌ opt-in |
| `assoc_flood` | DoS test | **yes, heavily** | a monitor interface (no mdk4) | "Can the association table be filled, and does anything rate-limit?" | ❌ opt-in |
| `null_data_flood` | DoS test | **yes, heavily** | a monitor interface | "Are power-save buffers bounded per station — with *no* deauth frames to see?" | ❌ opt-in |
| `eapol_start_flood` | DoS test | **yes, heavily** | a monitor interface, 802.1X | "Can 802.1X sessions be opened from the air without limit?" | ❌ opt-in |
| `sae_commit_flood` | DoS test | **yes, heavily** | a monitor interface, WPA3 | "Do SAE commits cost the AP CPU before anyone authenticates?" | ❌ opt-in |
| `tkip_michael` | DoS test | **yes, extreme** | a monitor interface, TKIP or a capture | "Can two corrupted frames silence TKIP for a minute?" | ❌ opt-in |
| `wids_confusion` | DoS test | **yes, extreme** | a monitor interface | "Can the site's monitoring be pointed at an innocent neighbour?" | ❌ opt-in |

\* `pmkid` transmits only if you ask it to (the association-based path inside
hcxdumptool); `hidden_ssid` transmits only with `--reveal-with-probe`.

The last column is what `Config().attacks` contains: six quiet attacks enabled, and
everything else — the ten offline analyses, the two read-only decoders (`ie_audit`,
`pnl_harvest`), the situational surveys, the lures and everything disruptive
(`wps_pin`, `pmkid_flood`, `handshake_broadcast`, the WEP enablers, the twin, Karma, the
Logoff and all ten floods) — opt-in, through `--attacks`, the web UI's checkbox list,
`attacks=[...]` in the API, `mode="offline"` for the radio-less set, or `mode="force"`
when you really do mean all of them. `❌ safe` means the attack transmits nothing at all: it
decodes frames already on disk, so it is always safe to add to the list, and it is
included in `mode="passive"` for exactly that reason.

`wifipilot attack --attacks pmkid,handshake` runs exactly those, in that order, and
the planner (or the LLM advisor) will restrict itself to the list you enabled. All
enabled attacks are additionally filtered by `available()` (are the tools installed?)
and `applies()` (is this the right kind of network?), so an enabled attack that cannot
run is skipped with a reason instead of failing halfway.

```
$ wifipilot --json tools | jq '.capabilities | with_entries(select(.value == false))'
{}                       # everything wifipilot uses is installed
```

---

## 2. Choosing an attack

The order below is the one the built-in planner uses, minus the parts that need a
human decision. Read it as "what a competent tester would do next", not as a script:

1. **`rogue_ap` / `passive` first on an unfamiliar site.** Minutes of listening tells
   you whether you are walking into somebody else's attack (a twin, a deauth flood),
   and it costs nothing. A rogue-AP finding changes the *rest* of the engagement.
2. **`ie_audit` on every target before anything is transmitted.** It decodes the
   information elements airodump's CSV throws away and reports the configuration
   findings that decide the rest of the plan: TKIP still advertised, PMF optional,
   WPS unlocked, 802.11r without PMF, 40 MHz in 2.4 GHz. Read-only and free, and it is
   what turns "try everything" into a reasoned order. On a site where nothing is
   associated yet, `pnl_harvest` runs with it: the names the clients ask for are the
   target list for `evil_twin` and `karma`.
3. **`hidden_ssid` on anything without a name.** You cannot plan, vendor-profile or
   mask a network you cannot name.
4. **`pmkid` before `handshake`, always.** PMKID needs no client, no deauth, and no
   cooperation; when the AP supports it, the handshake campaign is wasted radio time.
5. **`pmkid_flood` when `pmkid` sat there for a whole window and got nothing** and a
   client does exist: making that client reconnect is the difference between an AP
   that is quiet and an AP that does not do PMKIDs. Louder, and worth it once.
6. **`handshake` when PMKID fails and a client exists** — and accept that this is the
   noisy, slow one.
7. **`wps_pixie` on any AP advertising WPS that is not locked.** It is fast and it
   either works or it does not.
8. **`wps_pin`** only when Pixie-Dust failed, the operator accepts the lock risk, and
   `wifipilot pins` produced a short candidate list (a vendor default or an M7 leak —
   not a blind 10⁷ sweep).
9. **`wep_ivs`** for WEP, which still shows up in industrial and medical kit. On a
   WEP network that has gone quiet, the injection techniques are what restart it:
   `wep_p0841` (inject an ARP and harvest), `wep_fragment`/`wep_chopchop` (keystream
   from any single packet, no client needed), `wep_hirte` (keystream from a client's
   own traffic when the AP will not answer). They recover *capability*, not the key —
   run `wep_ivs` again once they succeed.
10. **`saewolf`/`pmf_audit` on anything WPA3 or novel.** The audit says which of the
   classic attacks are still possible before you spend radio time on them, and
   `saewolf` answers the only question that matters about a WPA3 network: is the WPA2
   path still open? Read §6 before pointing either at a customer's WPA3 site.
11. **`evil_twin`** when the engagement authorises impersonating the AP and you want
   to know who prefers it — the deliverable is the client list, not a password, unless
   the PSK is already known.
12. **`deauth_flood`/`beacon_flood`/`auth_flood`/`probe_flood`** only as detection
   tests, with a stated reason in the report: they are denial of service, and the
   finding is whether the site notices. `auth_flood` also answers a question the
   deauth flood cannot — whether the association table is finite and monitored — and
   `probe_flood` is the one that tests client-side behaviour rather than the AP's.
13. **`enterprise`** for 802.1X networks — there is no PSK to crack, and pretending
   otherwise is the most common mistake in WiFi reporting. Read the certificate it
   decodes before deciding anything else.
14. **`rogue_radius`** only when the survey says the certificate is worth testing
   (missing or self-signed) and the engagement authorises impersonating the AP. It is
   also the point at which a target may have to be *dropped*: a properly issued
   certificate that clients validate is the finding.
15. **`tracker`** whenever the interesting device is a client rather than an AP:
   which SSIDs does it remember, which BSSID is it on, and is it walking towards you.
   Run it before a targeted deauth or a twin, not after.

The AI advisor (`--think-interval`, the web UI's "think" button) re-orders these per
target and says why; the printed reason is stored on the attempt, so the report can
show that a target was skipped deliberately rather than forgotten.

---

## 3. Read-only intelligence

Two attacks exist to *read*: they decode frames that are already on disk, transmit
nothing at all, and need no authorisation. Between them they answer the two questions
that make every later decision cheaper — *what does this AP say about itself*, and *what
are the clients here asking for* — and because they cost nothing they are included in
`mode="passive"` and are safe to add to any attack list.

### `ie_audit` — the information elements nobody reads

**What it is.** Airodump's CSV records the SSID, the BSSID, the channel, the privacy
flag and a signal level. Everything else an AP broadcasts — the RSN cipher and AKM
suites, the MFPC/MFPR bits, WPS state and configuration methods, HT/VHT/HE capability,
802.11r/k/v roaming, the country element, supported rates, channel width, BSS load — is
thrown away, and those elements are where the configuration findings live. `ie_audit`
walks every beacon, probe response and association response, decodes the elements
(vendor elements included, which is where WPS, WMM and WPA1 hide) and reports what it
found:

* `ie_wps_enabled` (`high` while unlocked, `medium` once the AP says it is locked) —
  WPS is on, with the configuration methods it advertises, which is the reason to run
  `wps_pixie`;
* `ie_tkip` / `ie_wpa1` (`high`) — deprecated crypto still advertised;
* `ie_no_pmf` / `ie_pmf_optional` (`low`) — the findings that say a deauth will land;
* `ie_wpa3_transition` (`medium`) — the WPA2 door is still open on a "WPA3" network;
* `ie_ft_without_pmf` (`medium`) — 802.11r with unauthenticated management frames;
* `ie_40mhz_2ghz`, `ie_no_country`, `ie_open_network`, `ie_legacy_only`,
  `ie_busy_channel` — the housekeeping findings a good wireless report also contains.

**How wifipilot runs it.** Pure analysis of frames already on disk: the pcap another
attack produced, or — under `--demo` — a capture the simulator writes. It annotates the
session as it goes (`wps_locked`, `wps_model`, `pmf_required`, channel width), so the
planner and the LLM advisor see element-level facts rather than a guess, and it stores
the file it read as an **artifact**: visible in the report and re-readable later, but
never listed as loot, because nothing in it can be cracked.

**Reading the result.** Every finding names the element it came from, because "your
network is insecure" is not a finding. The two worth acting on immediately are WPS
unlocked (run `wps_pixie`) and `ie_no_pmf` (a `handshake` or `deauth_flood` will work);
the one worth putting in the report even when the engagement stops there is
`ie_wpa3_transition`, because it is the difference between "WPA3 site" and "WPA2 site
with a WPA3 sticker".

```
wifipilot attack -b d0:9e:12:9d:36:cc --attacks ie_audit
wifipilot decode capture.pcap --json | jq '.networks[] | {bssid, essid, facts}'
```

**Failure modes.** `no beacons to read` means there is no capture on the target and the
scanner has not seen it yet — run `passive` for a window first, or point the audit at a
file. A finding count of zero on a modern site is a *result*, not a failure: it means
the elements are what they should be.

### `pnl_harvest` — the preferred network list, out loud

**What it is.** Stations broadcast the names of the networks they remember, in the
clear, in directed probe requests — including on WPA3 networks, where the data plane is
protected but the probe is not. `pnl_harvest` reads those probes and builds the
neighbourhood's **wanted list**: which SSIDs are being asked for, by which stations, and
which of them are not on air at all. The last part is the finding: a name that clients
ask for and nothing advertises is either a network that moved away or the hidden SSID of
the site you are standing in, and either way it is a name an attacker can serve.

**How wifipilot runs it.** It decodes probe requests from any capture (or from the live
session state the scanner already holds) and reports:

* `pnl_missing_network` (`medium`) — per SSID, the stations looking for a network that
  is not on air. These are the candidate names for `evil_twin` and `karma`.
* `pnl_disclosure` (`low`) — one finding for the whole neighbourhood, counting the
  stations that leak a preferred network list of three names or more. Sixty clients
  leaking their history is one problem, not sixty findings.

The measurements are written to `reports/pnl.json` — stations, wanted list ranked by how
many stations asked, the subset that is not on air, the capture the numbers came from —
and the capture is kept as an artifact, so the twin stage has a machine-readable target
list rather than a paragraph of prose.

**Reading the result.** This is the attack that makes `karma` and `evil_twin`
evidence-driven instead of speculative: run it first, and the twin serves a name
somebody is actually looking for. The site-side fix is client configuration — directed
probe requests off — which is worth stating in the report, because it is the only one of
the two findings a customer can act on.

```
wifipilot attack -b d0:9e:12:9d:36:cc --attacks pnl_harvest
ls sessions/*/reports/pnl.json          # the trace, with the wanted list inside
```

---

## 4. Capture attacks

### `pmkid` — client-less PMKID harvest

**What it is.** When a client (or an attacker) starts a 4-way handshake, an AP that
supports PMKID includes the PMKID in the first EAPOL message. The PMKID is
`HMAC-SHA1(PMK, "PMK Name" + AP_MAC + STA_MAC)` — an offline-verifiable function of the
passphrase and the SSID, with no client needed. One frame, crackable exactly like a
handshake.

**How wifipilot runs it.** `hcxdumptool` when present, with a filtered `--bpf` of the
target BSSID, for `pmkid_timeout`; the pcapng is then read by wifipilot's own parser
(RSN PMKID KDE inside EAPOL message 1) and converted into a hashcat mode 22000
`WPA*01*` line. If hcxdumptool is missing, airodump-ng with `--pmkid` is the fallback,
which is slower but has no extra dependencies.

**Reading the result.** `has_pmkid` on the target means a line exists; `wp.passwords()`
will show the recovered PSK. An AP with `pmkid_vulnerable=False` in the demo, or one
that returns M1 *without* a KDE on real hardware, means "vendor disabled it" — move on
to `handshake` rather than retrying.

**Failure modes.** WPA3-only and OWE networks do not use PMKID this way; the radar
clients means the frame never comes. `passive` may still catch it from a real client.

### `pmkid_flood` — the active PMKID hunt

**What it is.** `pmkid` waits. If the AP's clients are asleep, off-site, or simply
associated and idle, no M1 ever arrives and the passive attack collects nothing —
which is not the same as "this AP does not do PMKIDs". This attack makes the frame
happen: a broadcast deauth burst every `deauth_interval`, a client reconnects, the AP
answers with M1, and if the firmware emits the PMKID KDE it is in the capture. It stops
the moment a PMKID lands.

**How wifipilot runs it.** airodump-ng with `--pmkid` on the target channel, plus
aireplay-ng deauth bursts on the same timer the handshake attack uses
(`deauth_count`, `deauth_interval`, `deauth_burst`). The capture is re-read every
0.75 s by wifipilot's own parser and the first PMKID becomes a hashcat mode 22000
`WPA*01*` line.

**Reading the result.** A PMKID here is worth exactly as much as one from the passive
attack — it is the same hash — and the attempt record says which one produced it. If
the deauths succeed but no PMKID appears, that is a *firmware* answer: the KDE is
disabled, so go to `handshake` (and say so in the report) rather than repeating it.

**Failure modes.** No clients at all (broadcast deauth still transmits, but nothing
reconnects); PMF required, so the client ignores the deauth and only reconnects on its
own schedule; a client that reconnects faster than airodump-ng writes the packet out.
This is a loud attack: it is not in the default set and the planner only reaches for
it when the passive attempt failed on a target that does have clients.

### `handshake` — forced 4-way handshake

**What it is.** Wait for a client to (re)connect and record the four EAPOL frames; the
deauth burst just makes that happen on demand. The capture is validated locally
(EAPOL message numbering, nonce sanity, and a real MIC check when the PSK is known)
before it is offered to the cracker, because "handshake captured" without a MIC check
is a claim, not a result.

**How wifipilot runs it.** airodump-ng on the target channel with `--bssid`, an
aireplay-ng deauth (broadcast, or per client), then a rescan of the capture file every
few seconds; `deauth_count` and `--time` cap how much noise it makes. Hashcat or
aircrack-ng validates it when `check_handshakes` is on (the default).

**Reading the result.** A capture with 4/4 EAPOL messages and a verified MIC is
crackable; the tool reports which message numbers were seen. If the AP has WPA3-SAE
(and not transition mode) or requires PMF, this attack is refused up front with the
reason, not attempted for ten minutes.

**Failure modes.** No clients in range (nothing to deauth); PMF required (the deauth
is ignored); a client that reconnects too fast to catch M1; the "handshake" being a
replay of an old one.

---

## 5. Online and semi-online attacks

### `wps_pixie` — Pixie-Dust

**What it is.** Some WPS implementations generate their nonces weakly enough that the
PIN can be computed offline from a single M1–M7 exchange (`pixiewps`). Nothing is
brute-forced against the AP, so there is no lock-out risk and the whole thing takes
seconds.

**How wifipilot runs it.** `wash` (parsed by `scanner.parse_wash`) decides whether WPS is present and
unlocked; reaver's Pixie-Dust mode (`-K 1`) collects the exchange; the PIN and PSK are
read from reaver's output. `bully --pixiewps` is the fallback. A locked AP is never
started.

**Reading the result.** Success means the PIN *and* PSK are known; the crack path then
verifies the PSK against a real handshake like any other password. Failure on a device
that *is* vulnerable usually means the exchange was incomplete (poor signal).

### `wps_pin` — online PIN recovery (opt-in)

**What it is.** WPS splits the PIN into two halves and tells the AP which half failed,
so a full 8-digit PIN is ~11,000 attempts instead of 10⁸ — about six hours at 2 s per
attempt. Modern APs rate-limit or lock permanently after a handful of failures, which
is why this attack is off by default and documented as destructive.

**How wifipilot runs it.** `wifipilot pins <bssid>` produces the candidate order with
provenance (vendor defaults computed from the BSSID, the two published ComputePIN
variants, ESSID-derived guesses) and the plan: `--first-half 1234` turns a leaked M7
half into 1,000 attempts. reaver/bully then walk the candidates, and a lock message in
the output stops the attack immediately instead of hammering a dead radio.

**Failure modes.** Lock-out (permanent on some chipsets), rate-limiting, offline AP.
This is the one attack where the honest answer is often "not worth it".

### The WEP family — five attacks on one broken cipher

WEP is broken in two different ways, and wifipilot ships both halves. RC4's key
schedule leaks the key once enough distinct IVs have been seen (**`wep_ivs`**,
**`wep_p0841`**), and the IV space is small enough that aireplay-ng can decrypt or
forge individual packets without knowing the key at all (**`wep_chopchop`**,
**`wep_fragment`**, **`wep_hirte`**). The second group recovers *capability*, not the
key: they exist because a WEP network with nothing on air produces almost no IVs, and
an attacker who cannot inject cannot harvest. Only the first two can reach the key on
their own, and the report says which half produced what.

### `wep_ivs` — ARP-replay IV harvesting

**What it is.** WEP's IV space is 24 bits and the RC4 key schedule is weak. Collecting
enough IVs (typically tens of thousands for a 104-bit key) lets aircrack-ng recover the
key statistically. ARP traffic is the fastest generator of fresh IVs, so the attack
replays one captured ARP packet to make the AP produce more.

**How wifipilot runs it.** airodump-ng for the capture, `aireplay-ng --arpreplay`
against the target (with `-h <client>` when one is known), aircrack-ng as soon as IVs
pass the threshold (or halfway through the timeout), and `KEY FOUND!` parsed from its
output.

**Failure modes.** A network with no ARP traffic (no clients talking) produces almost
no IVs — that is what the rest of the family is for. WEP with a hidden SSID needs
`hidden_ssid` first for the fake-auth/ARP steps to be reliable.

### `wep_p0841` — injected ARP (P0841)

**What it is.** The ARP-replay attack needs *a* captured ARP packet to replay, and on a
silent network there is none. P0841 sidesteps that: aireplay-ng crafts the ARP request
itself (`-2 -p 0841 -c ff:ff:ff:ff:ff:ff`, source frozen to the P0841 known-plaintext)
and injects it as a broadcast, so the AP answers with fresh IVs on demand. It needs no
captured packet and no client of its own.

**Reading the result.** Like `wep_ivs` it can reach the key on its own, because it
*generates* the traffic the IV harvest needs; the attempt reports IV count and the
recovered key when aircrack-ng finds one.

**Failure modes.** The AP filters broadcast ARP (`-p 0841` becomes useless), or the
card/AP combination cannot inject at all — check injection with `aireplay-ng -9` before
blaming the technique. Modern firmware on old hardware also simply drops craft-looking
ARP.

### `wep_chopchop` — KoreK chopchop

**What it is.** Take one encrypted packet, truncate it byte by byte, and watch how the
AP's ICV check responds: each response reveals one more byte of keystream, until the
whole packet can be decrypted without the key. aireplay-ng implements it as `-4`. No
client is needed and nothing has to be known beforehand.

**Reading the result.** 1,500 bytes of keystream are enough to forge the small ARP
packet that the IV harvest needs, so a successful chopchop is reported as *injection is
now possible*, with the `enables: wep_ivs` next step on the attempt. It is not a key
recovery and the report never claims it is.

**Failure modes.** Slow and success-rate dependent: an AP that answers every truncation
with silence gives you nothing (it can also drop the association while it tries). That
is what `wep_fragment` is for.

### `wep_fragment` — fragmentation attack

**What it is.** The faster sibling: aireplay-ng (`-5`) sends a captured packet as
fragments and reassembles the keystream from the AP's responses, typically getting
1,500 bytes in seconds rather than minutes. Still an enabler, still not the key.

**Failure modes.** Needs one captured packet to start from — with nothing on air at
all, run `wep_p0841` first, or wait for a beacon/data frame the card can hear.

### `wep_hirte` — client-oriented fragmentation

**What it is.** The same idea pointed at a client instead of the AP (`-7`), for the
case where the AP will not talk to you but a client is sending traffic. Requires an
associated client and (`-h`) its MAC, which the planner only schedules when one is
known.

**Failure modes.** The client has to actually transmit during the window; a sleeping
laptop gives you nothing. Track it with `tracker` first if the traffic is sporadic.

---

## 6. WPA3 and RSN: the two honest attacks

A WPA3 assessment is where most tools start lying. SAE is a password-authenticated key
exchange: the commit/confirm exchange contains no material that can be checked against
a wordlist, so **there is no offline attack on WPA3-SAE** — no matter what the cracking
rig is, and no matter what a vendor's marketing page claims. wifipilot ships two
attacks here, and neither pretends otherwise.

### `saewolf` — capture the SAE exchange, and read it

**What it is.** airodump-ng records the SAE authentication frames (algorithm 3) while
a client joins, and wifipilot's own decoder (``wifipilot/wpa3.py``) reports what a
capture *can* answer: the exchange group (19 = 256-bit ECP, 20 = 384-bit, 21 = 521-bit),
whether a complete commit **and** confirm pair was seen, and — the useful part — whether
the network also advertises PSK. A network in **transition mode** still has a WPA2 door,
and that door is opened by the `handshake` attack, not by this one.

**How wifipilot runs it.** Read-only: airodump-ng on the target channel with `--bssid`,
polling the capture until a complete exchange appears or the timeout expires. The
capture is stored as an artifact and the RSN reading is attached to it.

**Reading the result.** ``complete: 1`` with a group means the exchange was captured;
``transition_mode: true`` means the WPA2 path exists and the report should say so in
one sentence: *the network is not WPA3-only*. ``offline_feasible`` is always ``false``,
because it is. Do not let a report imply otherwise: the finding is the configuration,
not a password.

**Failure modes.** SAE needs a client to authenticate — a WPA3 network with no clients
in range produces nothing. A client that authenticates before airodump-ng is on the
channel produces a partial exchange (a commit with no confirm), which is reported as
incomplete rather than as a capture.

### `pmf_audit` — which classic attacks are still possible

**What it is.** Management Frame Protection (802.11w) is the reason a deauth attack
stops working, and it lives in two bits of the RSN capabilities word: **MFPC** (capable,
bit 5) and **MFPR** (required, bit 4). Airodump's CSV does not carry those bits, so this
attack reads the beacons themselves and reports, per BSSID:

* **no PMF required** (`low`) — a deauth can still force a handshake here;
* **transition mode** (`medium`) — the WPA2 AKM is still advertised, so the WPA2 door
  is open even on a "WPA3" network;
* **OWE transition** (`medium`) — an Enhanced Open network that still runs an open
  twin of itself, which is the shape a downgrade twin imitates;
* **required PMF** — reported as *nothing to report*, which is the correct finding for
  a modern deployment.

**How wifipilot runs it.** Pure analysis: it reads any capture already on the target
(beacons, probe responses, or the pcap another attack just produced), decodes the RSN
elements itself, and raises each finding once per session — the neighbourhood is read
in one pass and the same `no_pmf` on a network two rooms away is not repeated eleven
times. It marks each AP it read (`pmf_checked`), so the planner schedules it once and
does not spend a second window on it.

**Reading the result.** This attack is what makes the rest of the plan honest: with
`no_pmf` findings you know a deauth will land, and with transition-mode findings you
know there is a handshake to force at all. It is read-only, so it is not gated by the
authorisation prompt, and it is safe to run on a network you are only allowed to
listen to.

---

## 7. Rogue infrastructure, disconnects and denial-of-service tests

Every attack here transmits, and every one of them is opt-in twice over: out of the
default set, and skipped by the planner in `--stealth` mode regardless of the
configuration. They divide into three kinds — impersonation (`evil_twin`, `karma`,
`rogue_radius`), disconnection (`eapol_logoff`) and denial of service (`deauth_flood`,
`auth_flood`, `probe_flood`, `beacon_flood`) — and each produces a **finding**, not a
password. The report says exactly that, and the denial-of-service tests are the ones to
argue about before running: they are the only attacks here whose value is entirely in
what the *defender* does about them.

### `evil_twin` — serve the SSID and see who prefers it

**What it is.** A station prefers the network it remembers over the one it can hear: it
will associate with whichever BSSID answers first, which is why a twin needs no
deauthentication at all. wifipilot starts `hostapd-mana` when it is installed (it also
answers probes for networks that are not on air) and plain `hostapd` otherwise, with a
generated config for the target's SSID and channel, and watches for stations that join
or try to.

**Reading the result.** Two different outcomes, reported differently, because they are
different findings:

* **the PSK is already known** (it was cracked earlier in the engagement) — clients
  join and complete the 4-way handshake: the network can be *replaced*, not merely
  imitated. Severity **high**.
* **the PSK is unknown** — clients still try, the handshake fails because the twin's
  PSK is not the real one, and the measurement is the list of stations that preferred
  this SSID. Severity **medium**, and it is the shortlist for a targeted next step. It
  is *not* a password, and the module never claims one.

**How wifipilot runs it.** The config is written into the session directory, the
interface defaults to the monitor interface (`--twin-interface` to put the twin on a
second radio and keep the capture running), and the process is stopped in a `finally`
block — an impersonating AP still running when the operator moves on is the same class
of accident as a deauth that never stops.

**Failure modes.** No station tried the twin: either nothing was in range, or the
client has the real BSSID cached and stayed with it. Hidden networks are refused
(there is no name to serve) and 802.1X networks are refused with a pointer to
`rogue_radius` (a PSK twin cannot answer a supplicant's EAP exchange).

### `karma` — answer every probe, learn which stations trust a name

**What it is.** A station that has ever joined a network broadcasts probes for it
whenever it is not connected — in the clear, including on WPA3. Karma answers *every*
probe with a beacon for whatever name was just asked for, which means the network exists
only because the client asked for it. A station that then associates has proved it
trusts the name without knowing anything else about it; a station that does not is the
modern behaviour, and it is reported as such.

**How wifipilot runs it.** `hostapd-mana` with `enable_mana=1`, `mana_loud=1` and a
credential output file, on the target's channel, for a bounded window. `hostapd-mana` is
the only tool that implements this — plain `hostapd` cannot answer probes it does not
expect — so a missing package is reported as *why the attack cannot run* rather than
silently substituted. The config is written into the session directory, the process is
stopped in a `finally` block, and everything the daemon printed is parsed with the same
patterns the operator can read (`patterns()` exposes them):

* `AP-STA-CONNECTED` — a station associated with a network it named;
* `SSID=…` inside a probe line — the names being asked for, which is the intelligence
  the attack also produces when nobody joins.

**Reading the result.** Two findings, and they are very different:

* **stations associated** (`high`) — these clients do not verify the identity of a
  network beyond its name. Nothing about their traffic is decrypted by this attack
  (the twin has no PSK), so the deliverable is the list of stations plus the list of
  names they will follow, which is exactly the input a targeted `evil_twin` needs.
* **probes answered, nobody joined** (`medium`) — the clients ignore a network they are
  not configured for, which is the correct behaviour. The harvested SSID list is still
  intelligence, and it is the honest half of the report: *we answered 40 probes and
  nobody was fooled*.

**Failure modes.** `no probe requests were seen` means nothing in range is looking for
a network: run it on a busy channel, or after `pnl_harvest` says which names are being
asked for. An 802.1X site is refused by the plan validator (a Karma AP cannot complete
an EAP exchange — `rogue_radius` is the right attack), and `--stealth` skips it
entirely, because beaconing for every name in range is the opposite of stealth.

### `eapol_logoff` — the disconnect nobody authenticates

**What it is.** 802.11w protects deauthentication and disassociation frames. It does not
protect EAPOL-Logoff, because a Logoff is not a management frame: it is an 802.1X
packet, three fields long (version, type, length), with no cryptographic material and no
way to authenticate it in the original design. A supplicant that receives one is
supposed to tear its port down. So a site that deployed PMF believing it had solved
"clients can be disconnected" has a gap, and this attack measures it: *does this client
stop when it receives an unauthenticated Logoff from the AP it is talking to?*

**How wifipilot runs it.** wifipilot builds the frames itself (`wifipilot/rawtx.py`) and
sends a handful per client with `AF_PACKET` injection: both shapes, plain data and QoS
data — some drivers drop the un-QoS'd frame for an associated station — and never more
than `frames_per_client × max_clients` frames in one attempt. It then watches for
reassociation: a station that re-appears as a fresh association inside the observation
window accepted the Logoff. `logoff_preview(bssid, client)` prints exactly what would be
sent, without sending anything, which is what the CLI and the UI show before the first
frame leaves the card.

**Reading the result.**

* **clients re-associated** (`high`) — the Logoff was accepted. The finding is a
  client-side behaviour: supplicant configurations differ, and the ones that ignore
  Logoff are the ones to note as *not* vulnerable.
* **frames delivered, no response** (`medium`) — the client ignored it, or the deployment
  is WPA3-only with clients that only believe authenticated disconnects. Both are
  acceptable, and neither is a password.

**What it is *not*.** A Logoff never produces a 4-way handshake, so it is not a capture
technique and will not feed a cracker; the temptation to bolt it onto a handshake attack
should be resisted. It is a one-shot disconnect test with a bounded frame count, and the
report wording reflects that.

### `deauth_flood` — is 802.11w actually deployed?

**What it is.** A broadcast deauthentication flood (`mdk4 d`, or aireplay-ng when mdk4
is absent) against every client of a target, for a bounded time (≤60 s, further capped
by `attack_timeout`). The only honest use is a *detection* test: if the site has a
wireless IDS, this is the traffic it exists to notice, and if clients hold their
connection, 802.11w is doing its job. Both are findings; neither is a step towards a
password. If the goal is a handshake, `handshake` does that with a handful of frames.

**Reading the result.** The finding is about the *site*, at severity **high**: every
client of this SSID could be disconnected at will, which means neither a WIPS nor
required PMF is in place. Pair it with the `pmf_audit` result — one is the measurement,
the other is the explanation.

**Failure modes.** mdk4 missing (the attack says so instead of silently doing nothing);
the monitor interface not being on the target's channel; an operator running it on a
production network "to see what happens". The last one is a process problem, and the
warning in the log is written for exactly that.

### `auth_flood` — the association table, and who is watching it

**What it is.** Every authentication frame forces the AP to allocate state for a station
that does not exist. An authentication flood sends them by the thousand from random
source addresses, which fills that table until either the AP stops accepting real
clients or its firmware starts evicting the oldest entries. It is a denial-of-service
test with a specific question attached: *is there a limit, and does anything notice when
it is reached?* It is also a useful control for the deauth flood — an AP that ignores a
deauth flood but falls over on an auth flood is not resilient, it is lucky.

**How wifipilot runs it.** `mdk4 a` for at most 45 s, on the target's channel, with the
frame count reported from what the tool prints. The deliverable is the finding
(`high`): the association table is a finite resource that this deployment does not
protect. Nothing is cracked, and the module says so in the note it attaches to the
result.

**Reading the result.** A site where real clients keep working through the flood has
answer the question with "yes"; a site where they do not has a finding worth a
paragraph in the report. Either way the honest framing — and the one the module uses —
is *this is a deliberate denial-of-service test*, with the duration and the frame count
recorded.

### `probe_flood` — clients, not access points

**What it is.** A flood of probe requests with random SSIDs. Unlike the other floods,
the target of this one is not the AP: probe requests are handled by every client in
range, and some drivers and supplicants react — they wake up, they add the network to a
scan list, occasionally they expose a bug. The finding (`medium`) is whether the site's
monitoring notices a storm of probes at all, because a flood of probes is also what a
misconfigured client fleet looks like, which is exactly why it is hard to alert on.

**How wifipilot runs it.** `mdk4 p` for at most 45 s on the target's channel, frame count
reported as for the other floods. Lower severity than the deauth and auth floods because
probe requests are broadcast by every station anyway; the difference here is volume.

**Reading the result.** Treat this as a detection-quality measurement, not an outage
test: nobody's traffic stops. The report should say what the monitoring did (or did
not) show, and the answer "no alert in 45 s" is a finding about the *site*, not about
the tool.

### `beacon_flood` — is beacon-flood detection in place?

**What it is.** `mdk4 b` fills the channel with fake beacons, which puts hundreds of
phantom networks into every client's scan list until it stops. Shorter than the deauth
flood (≤45 s) and reported at severity **medium**, because it confuses clients rather
than disconnecting them.

**Reading the result.** The deliverable is the environment's reaction, not any target's
state. A site with beacon-flood monitoring notices; one without does not, and that is
the finding to write up (with the caveat that the test itself was disruptive).

---

## 8. Surveys (and why they are attacks)

A survey changes what the engagement knows, which is what an attack does. wifipilot
files them under attacks because the campaign loop has to schedule them like any other
step (`--attacks rogue_ap,hidden_ssid`), not because they transmit.

### `hidden_ssid` — name a hidden network

A hidden AP clears the SSID in its beacons, not in probe responses, association
requests or the handshake — so a client that knows the name hands it over. wifipilot
listens for those frames and writes the name onto the target, which is what the
planner, the vendor dossier and the mask generator need. With
`--reveal-with-probe` (opt-in, and the only part that transmits) it also sends a
wildcard probe request, which a misconfigured AP answers with the name it is hiding.

Failure is normal and not a dead end: a quiet hidden AP with no clients stays hidden
until somebody joins it.

### `rogue_ap` — twin and attacker-infrastructure survey

Compares every ESSID on air against its BSSIDs, vendors and signal spread, and against
the names clients are probing for. One ESSID from two vendors, or the same name at a
60 dB difference, is what a twin looks like from the outside — reported as a
`heuristic` pattern with the evidence attached (BSSIDs, vendors, dB spread, clients
involved), never as an accusation. The survey is about the *environment*: it runs once
per target list, is skipped when nothing new has appeared, and the raw payload (twins,
hidden targets, probes, deauth counts) lands on the attempt record for the UI and the
report.

### `enterprise` — 802.1X survey

There is no PSK on an 802.1X network, so the deliverable is the exchange: EAP method,
outer/inner identity, and the server certificate. All three are decoded *offline* from
the capture — EAP type codes, the clear-text outer identity, and the X.509 subject and
issuer (identical names mean the server signed its own certificate, which
`wifipilot eap FILE` prints outright).

The genuinely high-severity finding is a missing or self-signed certificate — a rogue
RADIUS can impersonate it and harvest credentials — and the demo neighbourhood
includes exactly that case. An outer identity that is not `anonymous@…` is reported as
the username-leak finding it is. `eap` transmits nothing, so it can run against a
capture somebody else took, months ago.

### `rogue_radius` — rogue RADIUS, with the certificate policy as the result

An 802.1X assessment that stops at "the network uses PEAP" has not tested anything:
the question is whether a client will complete the exchange with a server it cannot
validate. This attack impersonates the AP for one association attempt (eaphammer, or
`hostapd-mana`/`hostapd-wpe` with a generated config) and watches what the client
does:

* **a credential arrives** — critical: a hostile RADIUS harvested an MSCHAPv2
  challenge/response, which is offline-crackable. The tool output is reported
  verbatim; wifipilot does not guess a password from an identity.
* **an identity arrives but no credential** — high: the client accepted the unknown
  certificate and exposed the username and realm. That is the difference between
  "hard to reach" and "reachable".
* **nothing associates** — reported as a failure. The certificate policy was *not*
  tested, and saying otherwise would be a lie with a client's name on it.

The rogue service is stopped before the attack returns, always; an impersonating AP
that is still running when the operator moves on is the same class of accident as a
deauth that never stops. If the `enterprise` survey already decoded a self-signed
certificate, that becomes the finding immediately and nothing needs to transmit — the
survey is the read-only half of this attack.

### `tracker` — follow a station

The most useful target on a site is often a client: the laptop that remembers
`CorpNet`, the printer still probing for a network nobody remembers installing. The
tracker watches one station (the strongest, or the one named with `--client`) and
builds its picture from what the station broadcasts: the SSIDs it asks for — its real
preferred network list — the BSSIDs it associates with, and how the signal moves as
you walk. The signal change is reported next to the value it started from, with the
honest caveat that walls and bodies move the number as much as distance does.

Both the raw samples and the summary are written to loot as a JSON trace, so the
report can show the measurements rather than only the conclusion. It transmits
nothing, which is why it is enabled by default and why it is scheduled before the
noisy attacks: half of "which network should I impersonate?" is answered by the
client itself.

### `passive` — listen-only

airodump-ng on the target channel, recording beacons, probes, EAPOL and PMKIDs that
are on air anyway. This is the correct first pass on any site, and the only attack
that is safe to leave running when the client's rules say "no disruption". `--stealth`
makes *every* attack behave like this one: deauth helpers become no-ops.

---

## 9. What each attack costs

| Attack | Frames per attempt | Time | Risk to the network | Windows/IDS visibility |
|---|---|---|---|---|
| `passive` | 0 | scan window | none | low |
| `rogue_ap` | 0 | <1 s (local analysis) | none | none |
| `ie_audit` | 0 | <1 s per AP (reads a capture) | none | none |
| `pmf_audit` | 0 | <1 s per AP | none | none |
| `pnl_harvest` | 0 | <1 s per capture | none | none |
| `enterprise` | 0 | until a client authenticates | none | low |
| `tracker` | 0 | as long as you follow | none | low |
| `saewolf` | 0 | until a client authenticates | none | low |
| `hidden_ssid` | 0 (or 1 wildcard probe) | until a client joins | none | low |
| `pmkid` | association requests | seconds to minutes | none | medium |
| `evil_twin` | a twin AP, beaconing | seconds after a client tries | **high** (impersonation) | **high** |
| `karma` | a beacon per probed name | as long as the window allows | **high** (impersonation) | **high** |
| `eapol_logoff` | 3 frames per client (≤18) | <1 s per client | a blip per client that accepts | low (a handful of frames) |
| `rogue_radius` | a twin AP + association attempts | seconds after a client tries | **high** (impersonation) | **high** |
| `wps_pixie` | one WPS exchange | seconds | low | medium |
| `pmkid_flood` | deauth bursts every few seconds | until a PMKID lands | clients reconnect repeatedly | **high** |
| `handshake` | deauth bursts + retries | minutes | clients reconnect (visible blip) | **high** |
| `wep_chopchop` | hundreds of truncated frames | minutes | network slowed, may deauth you | high |
| `wep_fragment` | fragments + reassembly | seconds to minutes | network slowed | high |
| `wep_hirte` | fragments aimed at one client | minutes | that client's traffic disturbed | high |
| `wep_ivs` | ARP replay flood | minutes | network saturated | **high** |
| `wep_p0841` | injected ARP flood | minutes | network saturated | **high** |
| `deauth_flood` | thousands of deauth frames/second | ≤60 s, capped | **every client of the AP is disconnected** | **maximum** |
| `auth_flood` | thousands of auth frames/second | ≤45 s, capped | the AP's association table fills | **maximum** |
| `probe_flood` | thousands of probe requests/second | ≤45 s, capped | clients wake up, scan lists fill | **maximum** |
| `beacon_flood` | hundreds of fake beacons/second | ≤45 s, capped | phantom networks in every scan list | **maximum** |
| `wps_pin` | thousands of EAP-WSC exchanges | hours, may brick WPS | lock-out | **high** |
| `loot_audit`, `eapol_audit`, `wep_audit`, `rogue_detect`, `twin_detect`, `roam_audit`, `wps_lockout_audit` | 0 | <1 s per capture (local analysis) | none | none |
| `crack_sweep` | 0 | the wordlist's own runtime, per capture | none | none |
| `eap_md5_crack` | 0 | seconds to minutes (local) | none | none |
| `pixie_offline` | 0 | <1 s per exchange (pixiewps) | none | none |
| `sae_group_audit` | 0 (reads a capture; or a short listen) | <1 s | none | none |
| `handshake_broadcast` | broadcast deauth bursts + retries | minutes | **every client of the AP drops at once** | **maximum** |
| `hcxdump_capture` | the tool's own policy: deauths, associations | ≤120 s, capped | clients reconnect repeatedly | **high** |
| `wps_ap_pin` | ≤3 registrar attempts | seconds each | a logged WPS failure per candidate | low |
| `wps_lockout_probe` | 3 EAP-WSC exchanges | seconds | may lock WPS until a reboot | low (three frames) |
| `wps_pbc` | one enrolment attempt per window | up to the window (≤60 s here) | a new client joins if the window is open | medium |
| `karma_detect` | 4 probe requests, one address | seconds | none (only a Karma device answers) | low |
| `csa_attack` | 2 CSA beacons per round | ≤30 s | clients hop channels and reconnect | medium (no deauth to count) |
| `ssid_confusion` | 3 beacons per round | ≤30 s | clients may try an impostor BSSID | medium |
| `ssid_bruteforce` | 1 directed probe per second | ≤30 s | none | low |
| `ap_isolation_audit` | 2 ARP frames per round | ≤30 s | none | very low |
| `assoc_flood` | 24 association requests per round | ≤30 s, capped | the association table fills | **maximum** |
| `null_data_flood` | 32 Null frames per round | ≤30 s, capped | buffers fill for stations that do not exist | **maximum** (and invisible to deauth rules) |
| `eapol_start_flood` | 24 EAPOL-Starts per round | ≤30 s, capped | the authenticator holds half-open sessions | **maximum** |
| `sae_commit_flood` | 8 commits per round | ≤30 s, capped | the AP spends CPU before authentication | **maximum** |
| `tkip_michael` | 2 corrupted frames | <8 s | TKIP clients lose service for 60 s (the countermeasure) | **high** (it is a MIC failure by definition) |
| `wids_confusion` | 16 deauths per round, foreign BSSID | ≤25 s, capped | clients of the target drop, the neighbour gets blamed | **maximum** |

Times come from `wp.benchmark()` and the target's own history, not from a fixed
promise, so the estimate in the UI reflects the machine actually running the sweep. The
flood caps are hard limits in the attack classes (60 s for the deauth flood, 45 s for
the other three) *and* in the planner: the shortest of `attack_timeout`, the class cap
and the operator's patience wins. `eapol_logoff` is bounded a different way — three
frames per client and at most six clients per attempt — because the whole point of that
attack is that it is *not* a flood.

---

## 10. Interpreting failures

| Message | What it actually means | What to do |
|---|---|---|
| `WPA3-SAE target` | no PSK handshake exists to capture | nothing to crack; report the configuration |
| `refusing to transmit: pass --i-am-authorized` | the policy gate, not a bug | confirm written authorisation first |
| `no client in range` | a deauth has nobody to deauthenticate | wait, or run `pmkid`/`passive` |
| `WPS is locked` | the AP turned WPS off after failures | stop; further attempts are destructive |
| `no 802.1X exchange captured` | no client authenticated while you listened | the survey needs a station to join; run `eap` on an older capture instead |
| `handshake already captured` | the attack is done; the work left is cracking | `wp.crack(...)`/the crack stage |
| `does not apply to <AP>` | wrong attack for this security type | trust `engine.attackable(ap)` |
| `missing capability: hashcat` | tool not installed | `wifipilot tools` lists what is missing |
| `PMK cache hit` | the passphrase was learned earlier in this engagement | verified, not re-cracked — see [ARCHITECTURE §15](ARCHITECTURE.md) |
| `no station to follow` | a tracker with no client can only see beacons | wait for a client, or track a different AP |
| `is not a client of …` | `--client` named a station that is not on that AP | trust the error: a targeted deauth has no other meaning |
| `no rogue-RADIUS tool installed` | eaphammer/hostapd-mana/wpe are absent | install one, or use the read-only `enterprise` survey |
| `no client attempted to associate` | the certificate policy was **not** tested | treat it as untested, not as "secure" |
| `no complete SAE exchange` | a WPA3 client did not authenticate while you listened | listen longer, or accept "partial exchange" — SAE cannot be cracked offline either way |
| `no PMKID returned after deauth` | the AP's firmware does not emit the PMKID KDE | stop retrying; the way in is `handshake` |
| `no station came to the twin` | nobody was in range, or clients stayed on the cached BSSID | try while a client is active, after `tracker` says who is around |
| `no packet to work with` | a WEP enabler found nothing to work from | run `wep_p0841` first, or wait for traffic; check `aireplay-ng -9` |
| `mdk4 missing` | the flood has no engine and will not run | install mdk4, or use `handshake` for a targeted deauth |
| `<flood> produced no output` | the monitor interface is probably not on the target channel | re-check `wifipilot scan`, then retry |
| `no beacons to read` | `ie_audit` had no capture and no scanner state | run `passive` for a window first, or point it at a pcap |
| `no probe requests in range` | nothing is looking for a network yet | run `pnl_harvest` on a busier channel, or after `tracker` has seen stations |
| `the Logoff was not accepted` | the client ignored it, which is correct behaviour | report it as *not vulnerable*; do not retry — it never yields a handshake |
| `no probe requests were seen` (Karma) | beacons went out and nothing asked for anything | check the channel; run after `pnl_harvest` says which names are wanted |
| `already cracked, no reason to disrupt it` | the plan asked for a flood on a network whose key is known | nothing to do; the validator dropped the action deliberately |
| `not a WPA3 network, there is no SAE exchange` | `saewolf` was scheduled against a PSK-only AP | the planner will not do it; an LLM plan that asks for it is dropped with this reason |

Every one of these is also a *finding-ish* event in the session log, so the report can
state that a target was skipped deliberately and why.

---

## 11. Where the AI fits

The advisor never touches the radio and never invents a result. It receives the target
list (now including each station's probed network list and signal history), the
capabilities, the recent attempts and their outcomes, and returns a plan
(which attack against which BSSID, and a one-line reason) plus a short diagnosis when
an attack fails. The deterministic planner in `wifipilot/planner.py` produces the same
shape of answer with no model at all, and it is what runs when no provider is reachable —
**or when you switched the advisor off** (`--no-ai`/`--disable-ai`/`--offline`,
`wifipilot ai off`, `wp.ai(disable=True)`, `WIFIPILOT_NO_AI=1`).

So: the attack set is fully usable offline, and the advisor changes only the ordering and
the commentary. AI-piloted means the model proposes; wifipilot validates every action
against the registry and the live session and then executes it, one at a time. Turn it off
and the pilot is the planner — the attacks behave identically.

See [AI-PROVIDERS.md](AI-PROVIDERS.md) for the advisor itself (including the off switch),
[ARCHITECTURE.md](ARCHITECTURE.md) for how a plan becomes an attempt, and
[TUI.md](TUI.md) for how the dashboard shows which of the two is deciding.

---

## 12. Offline analysis: ten attacks that transmit nothing

These ten read files the session already holds. They need no radio, no monitor
interface, no root and — because nothing is transmitted — no authorisation prompt:
`wp.attack(target=..., mode="offline")` runs them on a laptop that has never touched a
wireless card, and `wifipilot attacks --no-radio` lists them. If you are building a report
from captures you took yesterday, this is the section you want.

### `loot_audit` — what do we actually hold?

Walks every capture, hash file and artifact in the session, classifies each one
(usable handshake, PMKID, WEP data, credential, plain artifact), matches duplicates by
the *material* they contain rather than by filename, and converts everything crackable
into a hashcat mode-22000 line. The answer to "did that engagement actually collect
anything?" is usually less flattering than the operator remembers, which is the point:
the report says `4 captures inventoried, 4 crackable, 5 unique hashes (1 duplicate
merged)` instead of listing files. When the session holds several hash files it also
produces a merged artifact (`audit/loot-audit-*.hc22000`).

*Failure modes:* an empty session is a valid audit ("0 captures") and reports as such; a
capture that yields no mode-22000 line is listed with the reason (no ESSID, no
handshake, MIC zeroed) rather than silently skipped.

### `eapol_audit` — is this handshake usable?

Decodes the EAPOL exchanges in a capture and answers the question a file size cannot:
which stations produced a *complete, checkable* pair (M1+M2 or M2+M3 with a real
ANonce), which key version was used (HMAC-MD5, HMAC-SHA1 or AES-CMAC — i.e. whether this
is TKIP-era or CCMP), how many retransmits there were, and what is missing. A capture
with four frames from three stations is described here, not in the cracker's output.

*Failure modes:* no EAPOL at all → "no EAPOL in this capture" (the file may hold beacons
only); a handshake whose MIC is zeroed is reported as *uncheckable* by anyone, which is a
finding about the capture, not about the password.

### `wep_audit` — is the WEP network crackable now?

Counts IVs, estimates unique IVs, counts the ARP frames that feed an ARP-replay attack,
and applies the classic rule of thumb (a few tens of thousands of unique IVs, or ARP
traffic to replay). "Crackable now" and "needs another five minutes of harvesting" are
different findings, and only one of them means you have to touch the radio again.

### `crack_sweep` — sweep everything through the cracker

Every usable hash the session holds, one after another, with a per-capture time budget
(`per_capture_seconds`). This is the batch version of `wifipilot crack`, and the one the
planner reaches for when a campaign ends with loot it never got round to cracking.

*Failure modes:* no wordlist (or none big enough) is reported as the reason nothing was
recovered; a hash that no verifier can check is skipped with that stated explicitly.

### `eap_md5_crack` — the one 802.1X method with an offline attack

EAP-MD5 answers a challenge with `MD5(identifier ‖ password ‖ challenge)` that anyone who
captured it can check. The attack pulls every EAP-MD5 exchange out of the session's
captures and runs the wordlist against them. The finding is not "a password was found"
but "this deployment is still using EAP-MD5", which is the sentence the client's auditor
needs. EAP-TLS/PEAP/TTLS exchanges are left alone, because they cannot be attacked this
way — say so rather than implying they can.

### `pixie_offline` — pixiewps with the radio unplugged

Runs `pixiewps` against a WPS exchange already captured (WPS attributes are decoded out
of the EAP-WPS messages in the capture: PKE, both nonces, both E-hashes). The online
`wps_pixie` attack needs a radio and a few seconds of WPS traffic; this one needs a file.
If the session holds no exchange, the attack says what is missing instead of guessing.

### `rogue_detect`, `twin_detect`, `roam_audit` — the pattern audits

Three read-only sweeps over what is already captured:

* `rogue_detect` — several BSSIDs behind one SSID, vendors that do not match the
  established one, signal spreads that only make sense for a rogue transmitter.
* `twin_detect` — the twin-specific half: one name, several BSSIDs, channel changes
  mid-capture, and whether an impostor appeared *after* the real AP.
* `roam_audit` — the 802.11k/r/v elements and the PMF bits, i.e. whether a forged
  CSA or deauth would land at all. It feeds the decision to run `csa_attack`,
  `karma` or `evil_twin`.

All three report a *pattern* with the evidence attached, never an accusation: a
neighbour's new router looks like a twin to a five-minute capture.

### `wps_lockout_audit` — what does the WPS record say?

Reads the WPS state the session already knows (which APs advertise WPS, which were
locked, which gave up their PIN) and reports the posture: how many APs expose WPS, how
many have a lockout policy, and which ones have neither. The online `wps_lockout_probe`
answers the same question with three frames; this one answers it from the session.

---

## 13. Capture, lures and confusion

### `handshake_broadcast` — the blunt handshake

The same 4-way capture as `handshake`, with one difference that matters: the
deauthentication is *broadcast*, so every client of the AP drops at once and several
stations offer a fresh handshake. It is better at its job and much worse for the site —
which is why it is not in the default set and the planner only runs it with
`broadcast_handshake = true` (`--broadcast-handshake`), on top of the usual
authorisation gate.

*Failure modes:* no clients → the attack is skipped (there is nothing to deauth, and
`pmkid` is the right answer); WPA3-SAE → refused, as with `handshake`, because SAE does
not produce a crackable capture.

### `hcxdump_capture` — the hcxtools pipeline

Runs `hcxdumptool` against one BSSID for a bounded time with a filter file, then
`hcxpcapngtool` to convert the result into hashcat mode 22000. It needs no client at all,
which is its whole point, and it follows *its own* air policy (association attempts,
deauths, its own idea of what provokes a PMKID): the report says so rather than pretending
this is passive. The hash file it produces is what `crack_sweep` consumes next.

*Failure modes:* the tool version matters — the flags changed between v6 and v7, and a
version mismatch is reported as exactly that, not as "no PMKIDs here"; missing
`hcxpcapngtool` is a hard failure, because nothing else converts the capture; a capture
with no PMKID and no complete handshake produces an empty hash file and a `low` finding.

### `csa_attack` — silent eviction

A **Channel Switch Announcement** is how a real AP tells its clients "move to channel N
now". It is a plain management frame: any transmitter can send it, clients in the
transition phase obey it, and — unlike a deauthentication — there is no disconnect for a
WIDS to count and nothing for 802.11w to protect, because the frame arrives inside a
beacon. The attack sends the announcement in the target's own name, then moves the
monitor to the announced channel and looks for the target's clients probing there. That
capture is the deliverable: clients that followed, or clients that ignored it.

*Failure modes:* clients that validate the transmitter ignore the frame — that is a
*result* (report it as such); without a monitor interface there is nothing to observe
and the report says the lure was sent but not read back.

### `ssid_confusion` — the same name, a different BSSID

Beaconing the target's SSID from a BSSID the network does not use tests whether clients
select a network by name alone. A station that probes for, or associates with, that
BSSID proves it does; a station that does not is a real result too (managed SSID lists
and BSSID pinning work). The impostor BSSID is deterministic per target, so the report
can be replayed.

### `ssid_bruteforce` — patient probes against a hidden network

Hidden networks are supposed to answer only stations that already know the name. This
sends one directed probe per second from a station address the AP already knows, working
through a wordlist (the session's wordlist when one is configured, a small built-in panel
otherwise), and reads the capture for a probe response. A misconfigured AP answers for a
name it does not have; an AP that answers with its real name discloses it in full. The
`probe_flood` attack is the blunt version of the same idea; this one is quiet, targeted
and stops the moment it has an answer.

### `karma_detect` — hunting the hunter

Sends probe requests for names that *cannot* exist from one fixed station address, then
reads the capture. A normal AP answers nothing (it does not know those names). A device
that answers several different made-up names is Karma/MANA behaviour — a rogue AP
claiming every SSID a client remembers, which is how credentials get collected. This is
the one attack in the set whose target is the attacker, and it is worth running on any
network where the client's staff carry laptops through a lobby.

### `ap_isolation_audit` — is the guest network flat?

Client isolation is a configuration claim, and this is the frame that tests it: a
spoofed ARP request from one client's address asking for another client's IP. If an ARP
reply is relayed between them, the AP bridged their traffic — a "guest" network where
every device is one hop from every other device, including the printer, the NAS and the
router's own web interface. Only the *reply* counts as evidence (broadcast ARP is
forwarded by most APs even with isolation on), and the report says so.

*Failure modes:* fewer than two clients → skipped, because there is nobody to talk to.

---

## 14. WPS and WPA3 parameters

### `wps_ap_pin` — the static AP PIN

Vendor algorithms derive a device's *registrar* PIN (the AP PIN) from its BSSID. On the
devices that shipped one, it never changes — resetting the WPS PIN does not touch it —
so a single correct candidate hands over the PSK. The attack tries at most three
candidates from the vendor algorithm, then stops and reports which source each one came
from. A refusal is a real result: "the registrar PIN is unique to this device", which is
the hardware-specific case.

### `wps_lockout_probe` — three wrong PINs, then stop

The single fact that decides whether an online PIN walk is worth hours of radio time is
the lockout policy. This attack sends three deliberately wrong PINs and reads the AP's
answer: lockout after N attempts, rate limiting, or nothing at all. Measuring a lockout
means triggering it, so the attack stops after three attempts by design — and a site
that ends up locked out because of it is a finding, not a side effect: report it.

### `wps_pbc` — push-button enrolment

`wpa_supplicant`'s own `wps_pbc` method, exactly what a phone does when the owner presses
the button: enrol, get the credential, read it back from the supplicant. Outside the
window it fails visibly. Inside the window — 60 to 120 seconds, and re-opened whenever
WPS is used at all — anything with radio range can enrol as a registrar, which is why
this is a critical finding when it succeeds and a timing result when it does not. It
needs a *managed* interface (not a monitor one) and both `wpa_supplicant` and `wpa_cli`.

### `sae_group_audit` — WPA3 parameters, read without an attack

Reads the RSN element and any SAE commits in a capture (or takes a short, bounded listen
if there is none) and reports:

* **the groups in use** — a commit carries its group in the authentication frame's
  status field, so the capture says whether the network is on group 19/20/21 (the
  RFC 8110 set) or on 22/23/24 (the Dragonblood set: cheaper for an attacker, more
  expensive for the AP);
* **whether a SAE-EXT-KEY AKM (24/25) is advertised** — without it, Hash-to-Element is
  negotiated inside the commit and this read-only audit cannot confirm it, which is
  exactly the situation `sae_commit_flood` exploits;
* **whether PMF is required** — capable-but-not-required still means a forged deauth,
  disassociation or CSA lands on clients that support 802.11w without requiring it;
* **whether a WPA2 path is still offered** (transition mode), in which case a captured
  handshake is crackable and `handshake` is the attack that matters.

It never claims a group makes SAE crackable: SAE is a PAKE, and the weaknesses here are
availability and downgrade ones.

---

## 15. The second wave of floods

Six more denial-of-service tests, all built in-process with `rawtx.py` (no `mdk4`), all
off by default, all capped in time. Every one of their reports opens with the same
sentence in different words: *the deliverable is the finding, not a password.* Their
fragments are in the table in section 9.

### `assoc_flood` — the association table

Association requests from fake stations. The difference from `auth_flood` is real: an
authentication flood makes the AP answer, but an association request makes it *allocate
and hold state*, which is the resource that runs out first on consumer gear. The finding
is whether anything rate-limits management frames at all.

### `null_data_flood` — power-save buffers

QoS Null frames with the power-management bit set, alternating awake and asleep, from
addresses that do not exist. The AP buffers frames for stations it believes are asleep
until its buffers run out. Because these are *data* frames carrying no payload, a WIDS
that counts deauth/disassoc frames sees nothing at all — which is the finding.

### `eapol_start_flood` — 802.1X session exhaustion

EAPOL-Start frames from fake supplicants: the authenticator opens one 802.1X session per
frame and must hold each of them until the RADIUS exchange times out. This is the
enterprise shape of the association flood (the AP falls over before the RADIUS server
does), and it is why 802.1X deployments need per-client rate limits and a WIPS rather
than "strong credentials".

### `sae_commit_flood` — WPA3 CPU exhaustion

SAE commit frames with random scalars. Every commit costs the AP a scalar multiplication
on the negotiated group *before* any authentication happens — the Dragonblood "clogging"
result. Aimed at the weakest group the AP is known to advertise (groups 22/23/24 cost the
AP more and the attacker less than 19). The mitigation is an anti-clogging token plus
H2E, which is exactly what `sae_group_audit` reports on.

### `tkip_michael` — two frames, sixty seconds

A TKIP frame taken from a capture with its MIC corrupted, replayed twice. No key is
needed: the AP decrypts with its own session key, recomputes the MIC and sees a mismatch;
two failures inside 60 seconds start the Michael countermeasure, which silences *all*
TKIP traffic on the AP for a minute. This was the reason TKIP was banned from 802.11n
onward, and the usual finding is simpler and more damning than the attack: the network
still offers TKIP.

*Failure modes:* no TKIP advertised and no protected frame captured yet → skipped with
that reason (run a capture first); a synthetic stand-in frame is used when the operator
insists, and the report marks it as best-effort.

### `wids_confusion` — blaming the neighbour

Deauthentication frames whose transmitter address is a *neighbouring* AP's BSSID (up to
three of the loudest). Clients of the target are disconnected — that part is ordinary —
but anything that attributes management frames by address now blames an innocent network,
and the site's first incident response goes to the wrong place. The finding is about the
monitoring: can it tell a spoofed transmitter from a genuine one (RSSI, sequence numbers,
a second sensor)?

---

## 16. Reading the catalogue

Everything section 1 describes by hand is also a data structure. `wifipilot/attacks/meta.py`
holds, for every attack, four facts: **category** (offline, capture, survey, wps, wep,
enterprise, rogue, dos), **noise** (silent → quiet → moderate → loud → extreme),
**impact** (none → info → degraded → outage → loot) and **what a defender sees**. The CLI,
the web UI, the report and the advisor prompt all read the same function:

```console
$ wifipilot attacks                 # every attack, grouped by category, with its costs
$ wifipilot attacks --no-radio      # the ten that transmit nothing
$ wifipilot attacks --noise loud    # the ones a site will notice
$ wifipilot attacks --json          # the same data for a script
```

```python
from wifipilot.attacks import attack_catalog, validate, OFFLINE_ATTACKS
catalogue = attack_catalog()        # 848 dicts: name, label, tool, requires, category,
                                    # noise, impact, detection, offline, default_enabled
assert validate() == []             # every attack described, no orphan metadata
```

`validate()` is the integrity check, and the test suite runs it: an attack that is
registered without a category, a noise level, an impact level or a detection sentence
fails the build, and so does a metadata entry for an attack that no longer exists. The
same tests check that `docs/ATTACKS.md` and the README mention every registered attack by
name, and that `Config().attacks` is exactly the set marked `default_enabled` — so a
batch like this one cannot land with the registry, the planner, the UI and the docs
disagreeing about what the tool does.

**Adding an attack** is therefore: a class in `wifipilot/attacks/` (with `name`, `label`,
`tool`, `description`, `requires`, `needs_injection`, `applies_to`), an entry in
`ATTACK_META`, a registration in `ATTACK_CLASSES` and a place in `DEFAULT_ORDER`, the
name in `models.ATTACK_NAMES`, gates in `planner.allow()` if it needs tools or is
disruptive, and a row in the tables above. The tests in `tests/test_attacks_v3.py` will
tell you which of those you forgot.

## 17. Bluetooth: the radio next door

Every phone, laptop and door sensor has a second radio, and it is on by default. `bt.py`
is a Bluetooth Low Energy decoder written for this tool — advertising PDUs, beacons,
trackers, L2CAP, ATT, SMP, the link layer and the HCI layer — and the Bluetooth wave is
what it makes possible: **43 attacks**, from offline analysis of a capture to keystroke
injection over a link the host opened itself.

| attack | what it answers |
|---|---|
| `bt_device_census` | every device on air, with what its advertisement said |
| `bt_tracker_detect` / `bt_tracker_follow` | which devices follow people, and for how long |
| `bt_ibeacon_audit` / `bt_eddystone_audit` | the beacons: proximity UUID, major/minor, URLs |
| `bt_address_privacy` | which devices rotate their address and which are a fingerprint |
| `bt_manufacturer_census` / `bt_service_census` | who made everything, and what it says it does |
| `bt_interval_audit` / `bt_channel_audit` | intervals and channels: battery life, discoverability |
| `bt_connectable_audit` / `bt_pairing_audit` | what accepts a connection, and how weakly it pairs |
| `bt_gatt_audit` / `bt_feature_audit` | the attribute table and the link-layer features |
| `bt_le_scan` / `bt_hci_inquiry` | live censuses: LE advertising reports, classic inquiry |
| `bt_adv_name_flood` / `bt_adv_dos` | the advertising channel, filled |
| `bt_beacon_clone` / `bt_tracker_clone` | an identity replayed from a different transmitter |
| `bt_connectable_lure` | a device that invites connections and counts who asks |
| `bt_pairing_flood` / `bt_l2cap_echo_flood` | the two protocols that must answer every request |
| `bt_sdp_browse` / `bt_rfcomm_scan` / `bt_gatt_enumeration` | what a connected device exposes |
| `bt_blueborne` / `bt_bias` / `bt_knob` | the classic named vulnerabilities, run rather than described |
| `bt_sweyntooth` / `bt_bluesmack` / `bt_bluesnarf` / `bt_bluebugging` / `bt_blesa` | malformed link-layer PDUs, oversized echoes, the object store, the AT channel, pre-authentication ATT work |
| `bt_hid_injection` | classic keystroke injection: advertise the keyboard, type the payload |

### The BLE wave: keyboards, downgrades and identity

Eight attacks that live in `attacks/blehid.py` and are the reason a BLE assessment is
worth running at all — a BLE keyboard is a GATT server that *notifies* its host, and a
host that subscribes believes every notification it receives on the report
characteristic.

| attack | what it answers |
|---|---|
| `ble_hid` | advertise the HID service, enumerate the host's report characteristic and deliver the payload as boot reports; the finding names what the host typed |
| `ble_hid_audit` | which HID hosts accept input without a bond, and which demand one — the survey that sizes the wave |
| `ble_hid_boot` | write the HID protocol mode back to boot protocol and *read it back* to prove the downgrade landed |
| `ble_hid_reconnect` | advertise as the keyboard a host already bonded and count the hosts that reconnect to the name and the address instead of checking the link key |
| `ble_smp_downgrade` | what each device settles for when offered Just Works with a seven-byte key — the answer that decides whether the pairing is worth anything |
| `ble_gatt_hijack` | an unauthenticated write to a control characteristic, verified by reading the value back: a lock, a speed limit, a setpoint |
| `ble_irk_resolve` | follow a device through its rotating addresses with the identity keys that leak, using the specification's own AES derivation |
| `ble_conn_param_hijack` | a link-layer connection update nobody asked for, and whether the peer accepted being starved of radio time |

Two of them are worth reading before running them. `ble_irk_resolve` is arithmetic, not a
heuristic: an address resolves or it does not, and the toolkit checks the same ``ah``
function the specification's own sample data describes (Vol 3, Part H, Appendix D.7) —
one AES block, hash in the low 24 bits, prand in the most significant 24. And
`ble_hid_reconnect` is a *comparison*: the demo floor has five hosts bonded to one
keyboard, three of which reconnect to whoever advertises as `WF-KEYBOARD`, and two of
which check the link key and stay away. A run that reports "3 reconnected, 2 verified" is
the attack and its negative control in one report.

The offline half reads `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR` captures — including the one
`scripts/demo.sh` generates — and needs no adapter at all. The live half needs a Bluetooth
controller; without one it reports what it would have done rather than pretending
otherwise, and `--bt-target` names the device a live attack should talk to.

## 18. The network behind the access point

An access point is a bridge, and everything a client sends goes onto the wired network.
**29 attacks** work at that layer: five read a capture (a network capture, a wireless one,
or a span port — the dissector unwraps whichever it is given), and twenty-four transmit
real protocol messages.

| attack | what it answers |
|---|---|
| `dhcp_lease_audit` | the lease table rebuilt from a capture: conflicts, forgeries, a second server |
| `ipv6_prefix_audit` | which router, which prefix, which resolver — and who is not on the list |
| `iot_credential_audit` | Telnet, SNMP, MQTT, RTSP and PJL credentials that travelled in the clear |
| `iot_service_census` / `ssdp_device_census` | the embedded services on the segment, and UPnP's self-descriptions |
| `dhcp_starvation` / `dhcp_flood` | the pool, emptied; the handler, saturated |
| `forged_dhcp_release` / `dhcp_nak_injection` / `dhcp_option_injection` | a lease taken away, a client refused, a rogue gateway handed out |
| `syn_flood` / `udp_flood` / `tcp_reset_injection` / `udp_reflection` | the connection table, the slow path, the sessions, the amplifiers |
| `icmp_redirect_injection` / `icmp_unreachable_injection` | routing and reachability, decided by whoever answers |
| `rogue_ra` / `ra_flood` / `ns_na_spoof` | IPv6's default route and neighbour cache, claimed |
| `llmnr_poisoning` / `nbns_poisoning` / `mdns_poisoning` | the three name-resolution protocols that believe the first answer |
| `stp_root_takeover` / `lldp_spoof` / `cdp_spoof` | the topology, and the management map that describes it |
| `vlan_double_tag_hop` | the 802.1Q tag a switch was never asked to look at |
| `mqtt_recon` / `rtsp_camera_audit` / `pjl_printer_audit` | the device services that answer on the first connection |

The four attacks the brief named — DHCP starvation, a rogue DHCP server, a DHCP flood and
a forged DHCP release — are in the table by name; the rogue server itself is
`rogue_dhcp`, in the rogue-infrastructure wave, because it is a *service* rather than a
frame, and `dhcp_lease_audit` is what proves afterwards that it was there.

<!-- catalogue:start -->

## 11. The complete catalogue

**848 attacks**, of which **121** transmit nothing at all — no radio, no monitor interface, no frame.  The table is generated from the registry (`python3 tools/gen_attack_docs.py`), so it cannot drift from the code: `wifipilot attacks` prints the same list, `--json` returns it, and the web UI, the planner and the report are all built from it.

They are split into three editions — **Bluetooth 143**, **IT devices 417**, **WiFi 288** — and **65 device types** carry the attacks that apply to them. The **edition** column below is that split: `wifipilot --edition it` (or the web UI's first control) plans only those attacks, and `wifipilot attacks --domain it` prints them.

How to read the columns: **edition** is which toolbox the attack belongs to, **noise** is what a defender sees (extreme 17, loud 68, moderate 239, quiet 386, silent 138), **impact** is what the *network* loses when the attack works (degraded 221, info 323, loot 258, none 9, outage 37), and **detection** is the artefact left behind — the thing to look for in a capture when asking whether this was run against you.

### Offline analysis (no radio at all) — 121

| attack | answers | edition | noise | impact | tool | defender sees |
| --- | --- | --- | --- | --- | --- | --- |
| `loot_audit` | Loot inventory and hash-file audit | WiFi | dim | green | wifipilot hash22000.py | nothing on air; reads the session's own files |
| `eapol_audit` | EAPOL / handshake audit | WiFi | dim | green | wifipilot pcap.py (EAPOL decoder) | nothing on air; decodes EAPOL already captured |
| `wep_audit` | WEP feasibility audit | WiFi | dim | green | wifipilot pcap.py (IV counter) | nothing on air; counts IVs already captured |
| `pixie_offline` | Pixie-Dust offline (pixiewps on a stored exchange) | WiFi | dim | bold green | pixiewps | nothing on air; runs pixiewps against a stored exchange |
| `eap_md5_crack` | EAP-MD5 offline dictionary | WiFi | dim | bold green | wifipilot sniff.py + hashlib | nothing on air; offline dictionary against a captured EAP-MD5 exchange |
| `crack_sweep` | Crack sweep (offline, whole session) | WiFi | dim | bold green | wifipilot crack.py | nothing on air; CPU only |
| `rogue_detect` | Rogue and cloned-AP detection | WiFi | dim | green | wifipilot sniff.py + OUI registry | nothing on air; compares what the scanner already sees |
| `twin_detect` | Evil-twin fingerprinting | WiFi | dim | green | wifipilot sniff.py + OUI registry | nothing on air; fingerprints identical SSIDs |
| `roam_audit` | Roaming and 802.11k/r/v audit | WiFi | dim | green | wifipilot ies.py (RM/FT/BTM elements) | nothing on air; reads 802.11k/r/v elements |
| `wps_lockout_audit` | WPS posture and lockout audit | WiFi | dim | green | wifipilot ies.py + wps.py | nothing on air; assesses WPS from IEs and history |
| `capture_quality` | Capture quality ranking (what is worth cracking) | WiFi | dim | green | wifipilot pcap.py (handshake scoring) | nothing on air; scores the session's own captures |
| `hash_audit` | Hash file audit (mode 22000) | WiFi | dim | green | wifipilot hash22000.py | nothing on air; parses mode-22000 hash files |
| `wordlist_audit` | Wordlist audit (coverage and cost) | WiFi | dim | green | wifipilot crack.py (measuring, not guessing) | nothing on air; reads the configured wordlists |
| `wordlist_mine` | Target wordlist mining (off the engagement's own data) | WiFi | dim | green | wifipilot (engagement-derived candidates) | nothing on air; candidates derived from the SSIDs and vendors already seen |
| `crack_plan` | Crack plan (benchmarked time estimates) | WiFi | dim | green | wifipilot crack.py + masks.py | nothing on air; a PBKDF2 benchmark and a multiplication |
| `vendor_fingerprint` | Device fingerprinting (vendors, models, drivers) | WiFi | dim | green | wifipilot ies.py + util.oui_vendor | nothing on air; groups the scanner's findings by vendor and model |
| `beacon_timeline` | Beacon timeline (what changed while we watched) | WiFi | dim | green | wifipilot models.AccessPoint.history | nothing on air; the session's own history of the neighbourhood |
| `cleartext_sniff` | Cleartext credential sniff (HTTP, FTP, mail) | WiFi | dim | bold green | wifipilot netproto.py + pcap.py | nothing on air; reads credentials out of a capture |
| `pmk_check` | PMK check (loot that needs no cracking) | WiFi | dim | bold green | wifipilot crypto.py (PTK + MIC verification) | nothing on air; recomputes MICs with keys the session already holds |
| `loot_manifest` | Loot manifest (chain of custody) | WiFi | dim | green | wifipilot (SHA-256 manifest) | nothing on air; SHA-256 over the session's artefacts |
| `krack_detect` | KRACK key-reinstallation detector (CVE-2017-13077) | WiFi | dim | green | wifipilot pcap.py (EAPOL replay analysis) | nothing on air; the retransmission pattern is read out of a capture we already have |
| `kr00k_detect` | KR00K zero-key frame detector (CVE-2019-15126) | WiFi | dim | green | wifipilot pcap.py + ciphertext analysis | nothing on air; scans captured ciphertext for the all-zero keystream signature |
| `fragattacks_detect` | FragAttacks exposure audit (CVE-2020-24588 and relatives) | WiFi | dim | green | wifipilot ies.py + pcap.py (aggregation and fragmentation) | nothing on air; looks for A-MSDU and fragment patterns in stored frames |
| `ft_audit` | 802.11r fast-transition audit | WiFi | dim | green | wifipilot ies.py (mobility domain + FT AKM) | nothing on air; reads mobility-domain and AKM elements |
| `beacon_rate_audit` | Beacon behaviour audit (clones and floods) | WiFi | dim | green | wifipilot pcap.py (TSF, interval, sequence) | nothing on air; compares beacon intervals, TSF and sequence numbers in a capture |
| `tsf_clone_detect` | TSF clone detector (same SSID, unrelated clocks) | WiFi | dim | green | wifipilot pcap.py (TSF correlation) | nothing on air; TSF timers compared between identical BSSIDs |
| `client_fingerprint` | Station fingerprinting (vendor, randomisation, probes) | WiFi | dim | green | wifipilot sniff.py + pcap.py | nothing on air; reads probe requests and their element sets |
| `mschapv2_crack` | MS-CHAPv2 challenge/response recovery | WiFi | dim | bold green | wifipilot (MD4 + DES, RFC 2759) | nothing on air; a dictionary against a captured MS-CHAPv2 exchange |
| `mic_check` | Handshake MIC verification (offline) | WiFi | dim | bold green | wifipilot (HMAC-SHA1/AES-CMAC MIC) | nothing is transmitted; the MIC is computed locally over a stored frame |
| `nonce_reuse_audit` | Nonce reuse audit (KRACK precondition) | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads EAPOL nonces out of a stored capture |
| `key_version_audit` | EAPOL key descriptor version audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads the key information field of stored EAPOL frames |
| `tkip_countermeasures_audit` | TKIP countermeasures detection | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads deauthentication reason codes out of a capture |
| `group_cipher_audit` | Group cipher audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: decodes the RSN element of stored beacons |
| `cipher_downgrade_audit` | Pairwise cipher downgrade audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: compares the pairwise cipher lists of stored beacons |
| `rsn_ie_audit` | RSN element audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads the RSN element line by line |
| `ie_anomaly_audit` | Information element anomaly audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: walks the element area of every management frame in a capture |
| `malformed_ie_audit` | Malformed element audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: length-checks every element in every management frame |
| `wildcard_probe_audit` | Wildcard probe audit (KARMA customers) | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads the SSID element of stored probe requests |
| `randomised_mac_ratio` | Randomised MAC ratio | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads transmitter addresses out of a capture |
| `probe_privacy_audit` | Directed probe privacy audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: builds a per-station network list from stored probe requests |
| `assoc_history_audit` | Association history audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: counts management frame types in a stored capture |
| `client_vendor_audit` | Client vendor audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads transmitter addresses and their OUIs |
| `client_count_audit` | Client population audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: counts distinct transmitters per BSSID |
| `data_frame_audit` | Data frame mix audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: classifies every frame in a capture |
| `protected_ratio_audit` | Protected frame ratio audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads the protected bit and the LLC type of stored data frames |
| `duration_field_audit` | Duration/NAV field audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads the duration field of every frame in a capture |
| `retransmit_audit` | Retransmission audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads the retry bit of stored frames |
| `fragment_audit` | Fragmentation audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads the fragment number of stored data frames |
| `beacon_interval_audit` | Beacon interval audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads the beacon interval of stored beacons |
| `tsf_skew_audit` | Beacon timestamp (TSF) skew audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: measures the drift of stored beacon timestamps |
| `assoc_response_audit` | Association response audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads the status code of stored association responses |
| `auth_response_audit` | Authentication exchange audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads the algorithm and status of stored authentication frames |
| `ssid_length_audit` | SSID inventory and length audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads SSID elements out of stored beacons and probe responses |
| `encryption_inventory` | Encryption inventory | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: decodes the security elements of stored beacons |
| `bssid_oui_audit` | Access point vendor audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads BSSID OUIs out of stored beacons |
| `signal_histogram` | Signal distribution audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads the radiotap signal field of stored frames |
| `channel_usage_audit` | Channel usage audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads the DS parameter set of stored beacons |
| `channel_overlap_audit` | Channel overlap audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: compares the channels in stored beacons |
| `handshake_message_audit` | Handshake message inventory | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads the message numbers of stored EAPOL frames |
| `pmkid_presence_audit` | PMKID presence audit | WiFi | dim | bold green | wifipilot (own 802.11 parser) | silent: reads PMKIDs out of stored EAPOL message 1 frames |
| `eapol_retry_audit` | EAPOL retransmission audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: counts repeated key message numbers in a capture |
| `wpa3_transition_audit` | WPA3 transition mode audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads the AKM suites of stored beacons |
| `sa_query_activity` | SA Query activity audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: counts action frames with category 8 in a capture |
| `eapol_logoff_audit` | EAPOL-Logoff audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: scans stored frames for EAPOL type 2 |
| `llc_snap_audit` | LLC/SNAP ethertype audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads the LLC/SNAP header of stored data frames |
| `qos_audit` | QoS traffic audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads the QoS control field of stored data frames |
| `power_save_audit` | Power save audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads the power management bit of stored data frames |
| `broadcast_storm_audit` | Broadcast and multicast audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads the receiver address of stored data frames |
| `gratuitous_arp_audit` | Gratuitous ARP audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: parses the ARP payloads already in a capture |
| `arp_scan_detect` | ARP scan detection | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: tracks ARP request targets per client |
| `dhcp_fingerprint_audit` | DHCP fingerprint audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: parses DHCP options out of stored frames |
| `duplicate_seq_audit` | Duplicate sequence number audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: tracks (transmitter, sequence) pairs in a capture |
| `deauth_storm_detect` | Deauthentication storm detection | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: counts deauthentication frames per second in a capture |
| `auth_flood_detect` | Authentication flood detection | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: cross-references authentication and association frames per station |
| `probe_flood_detect` | Probe request flood detection | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: counts probe requests per station and their name lengths |
| `pcap_report` | Capture report (JSON artifact) | WiFi | dim | bold green | wifipilot (own 802.11 parser) | silent: writes a file; nothing is transmitted |
| `capture_coverage` | Capture coverage audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: cross-references the session's discovery and capture state |
| `beacon_rate_histogram` | Beacon rate audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: measures beacon spacing in a capture |
| `auth_algorithm_inventory` | Authentication algorithm inventory | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads the algorithm number of stored authentication frames |
| `station_inventory` | Station inventory | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: builds a per-address map from stored frames |
| `quality_histogram` | Frame size histogram | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: measures every frame in a capture |
| `vendor_ie_inventory` | Vendor element inventory | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads element 221 out of stored beacons |
| `hidden_ap_audit` | Hidden network audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: correlates beacons without an SSID with association requests |
| `extended_capability_audit` | Extended capabilities audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: decodes the extended capabilities element of stored beacons |
| `rrm_measurement_audit` | 802.11k measurement audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: decodes the RM enabled capabilities element (tag 70) |
| `neighbour_report_audit` | Neighbour report audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: decodes the neighbour report element (tag 52) |
| `ft_mobility_audit` | Fast transition (802.11r) audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: decodes the mobility domain element (tag 54) |
| `bss_load_audit` | BSS load audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: decodes the BSS load element (tag 11) |
| `interworking_audit` | Interworking element audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: decodes the interworking element (tag 107) |
| `hs20_audit` | Hotspot 2.0 (Passpoint) audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: decodes the Hotspot 2.0 vendor element (221/00:50:f2/0x11) |
| `wmm_parameter_audit` | WMM parameter audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: decodes the WMM parameter element (221/00:50:f2/0x02) |
| `wps_config_audit` | WPS configuration method audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: decodes the WPS element's configuration methods |
| `country_power_audit` | Regulatory domain audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: decodes the country element (tag 7) |
| `ssid_hygiene_audit` | SSID hygiene audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads the SSID element of stored beacons |
| `security_mismatch_audit` | Security mismatch audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: compares the RSN of every BSSID carrying the same SSID |
| `client_capability_audit` | Client capability audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads association requests in a capture |
| `frame_control_audit` | Frame control audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads the frame control field of every stored frame |
| `airtime_estimate` | Airtime estimate | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: measures every frame in a capture |
| `probe_response_latency_audit` | Probe response latency audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: pairs probe requests with the responses to them |
| `eapol_key_flags_audit` | EAPOL key flag audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads the key information field of stored EAPOL frames |
| `group_rekey_audit` | Group key rekey audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: reads key data out of stored EAPOL frames |
| `eapol_timing_audit` | EAPOL timing audit | WiFi | dim | green | wifipilot (own 802.11 parser) | silent: times the EAPOL messages in a capture |
| `bt_device_census` | Bluetooth device census | Bluetooth | dim | green | wifipilot bt.py (own BLE decoder) | the capture itself: the census is what the air already carries |
| `bt_tracker_detect` | Tracker detection | Bluetooth | dim | green | wifipilot bt.py (own BLE decoder) | a tracker in a building is a tracker in somebody's database |
| `bt_tracker_follow` | Tracker follow-through | Bluetooth | dim | green | wifipilot bt.py (own BLE decoder) | the device that never rotates its address is the one that can be followed |
| `bt_ibeacon_audit` | iBeacon inventory | Bluetooth | dim | green | wifipilot bt.py (own BLE decoder) | an iBeacon is a plaintext identity, and a cloned one needs no hardware |
| `bt_eddystone_audit` | Eddystone audit | Bluetooth | dim | green | wifipilot bt.py (own BLE decoder) | a URL in an advertisement is a URL somebody will follow |
| `bt_address_privacy` | Address privacy check | Bluetooth | dim | bold green | wifipilot bt.py (own BLE decoder) | a fixed address is a device that can be followed for months |
| `bt_manufacturer_census` | Manufacturer census | Bluetooth | dim | green | wifipilot bt.py (own BLE decoder) | the manufacturer field is not encrypted and is not optional |
| `bt_service_census` | Service census | Bluetooth | dim | green | wifipilot bt.py (own BLE decoder) | the advertised service list is the device's function, in plaintext |
| `bt_interval_audit` | Advertising interval audit | Bluetooth | dim | green | wifipilot bt.py (own BLE decoder) | an interval is a battery-life and a detectability decision at once |
| `bt_channel_audit` | Advertising channel audit | Bluetooth | dim | green | wifipilot bt.py (own BLE decoder) | a device on one channel is a device half the scanners never see |
| `bt_connectable_audit` | Connectable device audit | Bluetooth | dim | bold green | wifipilot bt.py (own BLE decoder) | connectable advertising is an open door with a name on it |
| `bt_pairing_audit` | Pairing configuration audit | Bluetooth | dim | green | wifipilot bt.py (own BLE decoder) | the pairing request is plaintext, and it says how weak the link will be |
| `bt_gatt_audit` | GATT structure audit | Bluetooth | dim | bold green | wifipilot bt.py (own BLE decoder) | the attribute table is the device's API, and the capture has it |
| `bt_feature_audit` | Link-layer feature audit | Bluetooth | dim | green | wifipilot bt.py (own BLE decoder) | a device without LE Encryption cannot encrypt the link, whatever the app says |
| `dhcp_lease_audit` | DHCP lease audit | WiFi | dim | green | wifipilot netstack.py | silent: reads DHCP messages already in a capture |
| `ipv6_prefix_audit` | IPv6 prefix and router audit | WiFi | dim | green | wifipilot netstack.py | silent: reads ICMPv6 neighbour discovery from a capture |
| `iot_credential_audit` | Device credential audit (Telnet, SNMP, MQTT, RTSP, PJL) | WiFi | dim | bold green | wifipilot netstack.py | silent: reads device protocol payloads from a capture |
| `iot_service_census` | Embedded service census | WiFi | dim | green | wifipilot netstack.py | silent: counts ports and protocols in a capture |
| `ssdp_device_census` | UPnP / SSDP device census | WiFi | dim | green | wifipilot netstack.py | silent: reads SSDP announcements from a capture |

### Surveys the air, transmits nothing — 29

| attack | answers | edition | noise | impact | tool | defender sees |
| --- | --- | --- | --- | --- | --- | --- |
| `passive` | Passive capture | WiFi | dim | dim | airodump-ng | nothing at all; listen-only capture |
| `rogue_ap` | Rogue AP / evil twin survey | WiFi | dim | green | wifipilot (offline analysis) | nothing on air; cross-checks the neighbourhood |
| `ie_audit` | Configuration audit (beacon elements) | WiFi | dim | green | wifipilot ies.py (IE decoder) | nothing on air; decodes beacons |
| `pmf_audit` | PMF / transition-mode audit | WiFi | dim | green | wifipilot wpa3.py (RSN decoder) | nothing on air; reads RSN capabilities |
| `saewolf` | WPA3 SAE capture (dragonslayer) | WiFi | green | bold green | airodump-ng + wpa3.py (SAE/PMF decoder) | captures SAE frames; sends nothing until a client authenticates |
| `sae_group_audit` | SAE group and H2E audit (WPA3 parameters) | WiFi | dim | green | wifipilot wpa3.py (RSN + SAE decoder) | nothing on air beyond the capture that was already happening; reads the RSN element and SAE commits |
| `hidden_ssid` <br>_on by default_ | Hidden SSID discovery | WiFi | green | green | airodump-ng | one probe request per hidden name; the AP's own answer reveals it |
| `pnl_harvest` | Probe harvest (preferred network lists) | WiFi | dim | green | wifipilot sniff.py (probe decoder) | nothing on air; reads probe requests |
| `tracker` <br>_on by default_ | Station tracker (follow a client) | WiFi | dim | green | airodump-ng (listen-only) | follows a station with the capture radio only |
| `ap_admin_audit` | Management surface audit (admin ports and pages) | WiFi | green | dim | wifipilot (raw sockets + HTTP) | TCP connections to management ports: a port scan of one host |
| `upnp_audit` | UPnP/SSDP audit (device description and IGD) | WiFi | green | dim | wifipilot netproto.py (SSDP + HTTP) | one SSDP M-SEARCH multicast, then HTTP GETs to the description URLs |
| `snmp_audit` | SNMP audit (default community strings) | WiFi | green | dim | wifipilot netproto.py (BER codec) | SNMP GET requests carrying default community strings |
| `dns_audit` | DNS resolver audit (open resolver, DNSSEC) | WiFi | green | dim | wifipilot netproto.py (DNS client) | a handful of DNS queries to the network's own resolver |
| `wpad_audit` | WPAD audit (proxy auto-discovery exposure) | WiFi | green | dim | wifipilot netproto.py (DNS + HTTP) | DNS queries for the wpad names, then a GET for wpad.dat |
| `rogue_dhcp_detect` | Rogue DHCP detection (second server on the segment) | WiFi | dim | green | wifipilot netproto.py (DHCP sniff) | nothing but listening for DHCP replies from the segment |
| `arp_spoof_detect` | ARP spoofing detection (address conflicts) | WiFi | dim | green | wifipilot netproto.py (ARP parsing) | nothing on air; reads ARP claims from a capture or a listen window |
| `ipv6_ra_audit` | IPv6 router advertisement audit | WiFi | dim | green | wifipilot (ICMPv6 parsing) | nothing but listening for router advertisements |
| `mac_filter_probe` <br>_injects_ | MAC filtering probe (random station) | WiFi | green | dim | wifipilot rawtx.py + a live listen window | association attempts from random MACs; a MAC filter rejects them visibly |
| `channel_sweep` | Channel sweep (live channel map) | WiFi | dim | dim | wifipilot rawtx.py + airodump-ng fallback | nothing but channel changes on our own radio |
| `bt_le_scan` <br>_injects_ | LE scan (live census) | Bluetooth | green | green | wifipilot bt.py (LE Set Scan Enable + advertising reports) | the capture itself |
| `bt_hci_inquiry` <br>_injects_ | Classic inquiry (BR/EDR census) | Bluetooth | green | green | wifipilot bt.py (HCI Inquiry) | the capture itself |
| `bt_sdp_browse` <br>_injects_ | SDP service browse | Bluetooth | cyan | green | wifipilot bt.py (SDP Service Search Attribute) | the capture itself |
| `bt_rfcomm_scan` <br>_injects_ | RFCOMM channel scan | Bluetooth | cyan | green | wifipilot bt.py (SDP search per RFCOMM profile) | the capture itself |
| `bt_gatt_enumeration` <br>_injects_ | GATT enumeration | Bluetooth | cyan | bold green | wifipilot bt.py (ATT Read By Group Type over a connection) | the capture itself |
| `ble_hid_audit` <br>_injects_ | BLE HID exposure audit (who accepts input) | Bluetooth | green | green | wifipilot bt.py (LE scan + ATT reads) | One LE connection per HID-serving device and an ATT read of the HID service: no keystroke is sent, so a host that watches its own connections sees the enumeration rather than the injection. |
| `ble_irk_resolve` <br>_injects_ | BLE identity resolution (rotating addresses, leaked IRKs) | Bluetooth | green | green | wifipilot blesim + bt.py (AES-128 identity resolution) | Nothing on the device: the resolution is offline arithmetic over addresses anybody can receive. That is the finding — the privacy control fails silently, and only a listener holding the key can tell one address from another. |
| `mqtt_recon` | MQTT broker reconnaissance | WiFi | green | green | wifipilot netstack.py (MQTT CONNECT/SUBSCRIBE) | a CONNECT and a SUBSCRIBE on port 1883 from an unknown client: the broker's log has it, and a broker with authentication refuses it |
| `rtsp_camera_audit` | RTSP camera audit (streams and authentication) | WiFi | green | green | wifipilot netstack.py (RTSP OPTIONS/DESCRIBE) | OPTIONS and DESCRIBE requests from an unexpected client: the camera's log shows an anonymous session |
| `pjl_printer_audit` | PJL printer audit (identity and filesystem) | WiFi | green | green | wifipilot netstack.py (PJL over port 9100) | PJL commands on port 9100 from a host that is not a print server: the printer's job log shows a command job |

### Capture requests (frames on air) — 53

| attack | answers | edition | noise | impact | tool | defender sees |
| --- | --- | --- | --- | --- | --- | --- |
| `pmkid` <br>_on by default, injects_ | PMKID capture (client-less) | WiFi | dim | bold green | hcxdumptool / tcpdump | nothing from us; the AP volunteers the PMKID to associated clients |
| `handshake` <br>_on by default, injects_ | WPA handshake capture | WiFi | green | bold green | airodump-ng + aireplay-ng | two short deauth bursts per client; a WIDS counting deauths sees them |
| `handshake_broadcast` <br>_injects_ | WPA handshake capture (broadcast deauth) | WiFi | cyan | bold green | airodump-ng + aireplay-ng -0 (broadcast) | broadcast deauth; every client on the channel drops at once |
| `pmkid_flood` <br>_injects_ | PMKID hunt (deauth + harvest) | WiFi | yellow | yellow | aireplay-ng + airodump-ng --pmkid | deauth-driven PMKID hunt; frequent disconnects |
| `hcxdump_capture` <br>_injects_ | hcxdumptool capture (client-less PMKID pipeline) | WiFi | cyan | bold green | hcxdumptool + hcxpcapngtool | an active hcxdumptool session: association attempts and deauths under its own policy |
| `injection_test` <br>_injects_ | Injection test (aireplay-ng --test) | WiFi | green | dim | aireplay-ng --test | aireplay-ng's own test frames: a handful of probe requests, then it stops |
| `pcap_replay` <br>_injects_ | Capture replay (frames back on the air) | WiFi | yellow | yellow | wifipilot rawtx.py (replay of a stored capture) | frames replayed from a capture file at their recorded timing |
| `session_cookie_replay` <br>_injects_ | Session-cookie replay (take the session out of the capture) | WiFi | cyan | bold green | wifipilot netproto.py (credential patterns) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `session_deauth_race` <br>_injects_ | Disconnect race (deauth then reassociation in the client's name) | WiFi | cyan | bold green | wifipilot rawtx.py + synthesised reconnection | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `session_roam_capture` <br>_injects_ | Roam following (capture the keys a fast transition moves) | WiFi | cyan | bold green | wifipilot rawtx.py (reassociation) + airodump-ng | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `enterprise_anonymous_identity` <br>_injects_ | Anonymous outer-identity harvest (usernames in the clear) | WiFi | green | green | wifipilot synth.py (EAP-Response/Identity) + sniff.py | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `it_relay_redis` | Redis relay (every command passes through us) | IT devices | cyan | bold green | wifipilot itproto.py (redis_command/parse_resp) + TCP 6379 | two connections to the same redis service on port 6379 — one from the client and one from an address that is not the device — and mirrored traffic whose timing follows the relay rather than the server |
| `it_relay_memcached` | memcached relay (the cache's values pass through us) | IT devices | cyan | bold green | wifipilot itproto.py (memcached_command) + TCP 11211 | two connections to the same memcached service on port 11211 — one from the client and one from an address that is not the device — and mirrored traffic whose timing follows the relay rather than the server |
| `it_relay_mongo` | MongoDB relay (an unauthenticated handshake, carried by us) | IT devices | cyan | bold green | wifipilot itproto.py (mongo_hello/parse_mongo) + TCP 27017 | two connections to the same mongo service on port 27017 — one from the client and one from an address that is not the device — and mirrored traffic whose timing follows the relay rather than the server |
| `it_relay_postgres` | PostgreSQL relay (auth exchange carried through us) | IT devices | cyan | bold green | wifipilot itproto.py (postgres_startup/parse_postgres) + TCP 5432 | two connections to the same postgres service on port 5432 — one from the client and one from an address that is not the device — and mirrored traffic whose timing follows the relay rather than the server |
| `it_relay_mysql` | MySQL relay (server greeting and salt carried through us) | IT devices | cyan | bold green | wifipilot itproto.py (mysql_handshake_parse) + TCP 3306 | two connections to the same mysql service on port 3306 — one from the client and one from an address that is not the device — and mirrored traffic whose timing follows the relay rather than the server |
| `it_relay_smb` | SMB relay (negotiation carried, dialects chosen by us) | IT devices | cyan | bold green | wifipilot itproto.py (smb2_negotiate/parse_smb2) + TCP 445 | two connections to the same smb service on port 445 — one from the client and one from an address that is not the device — and mirrored traffic whose timing follows the relay rather than the server |
| `it_relay_ldap` | LDAP relay (binds carried through us) | IT devices | cyan | bold green | wifipilot itproto.py (ldap_bind_request/parse_ldap) + TCP 389 | two connections to the same ldap service on port 389 — one from the client and one from an address that is not the device — and mirrored traffic whose timing follows the relay rather than the server |
| `it_relay_telnet` | Telnet relay (banner and prompt carried through us) | IT devices | cyan | bold green | wifipilot itproto.py (telnet_banner/parse_telnet_negotiation) + TCP 23 | two connections to the same telnet service on port 23 — one from the client and one from an address that is not the device — and mirrored traffic whose timing follows the relay rather than the server |
| `it_relay_ipp` | IPP relay (print jobs carried through us) | IT devices | cyan | bold green | wifipilot itproto.py (ipp_get_printer_attributes/parse_ipp) + TCP 631 | two connections to the same ipp service on port 631 — one from the client and one from an address that is not the device — and mirrored traffic whose timing follows the relay rather than the server |
| `it_relay_http_basic` | HTTP basic-auth relay (the Authorization header passes through us) | IT devices | cyan | bold green | wifipilot itproto.py (http_request) + TCP 80 | two connections to the same http service on port 80 — one from the client and one from an address that is not the device — and mirrored traffic whose timing follows the relay rather than the server |
| `it_steal_camera_stream` | Onvif stream-URI theft (the camera hands over its stream) | IT devices | green | bold green | wifipilot itproto.py (onvif_get_stream_uri) | a onvif request for inventory, credentials or device identity from an address with no business asking, followed by a copy of the answer leaving the segment |
| `it_steal_printer_spool` | Print-spool theft (job names and the file list) | IT devices | green | bold green | wifipilot itproto.py (pjl_command) + TCP 9100 | a pjl request for inventory, credentials or device identity from an address with no business asking, followed by a copy of the answer leaving the segment |
| `it_steal_plc_program` | PLC identity theft (order number, module and serial) | IT devices | green | bold green | wifipilot itproto.py (s7_read_szl) + TCP 102 | a s7comm request for inventory, credentials or device identity from an address with no business asking, followed by a copy of the answer leaving the segment |
| `it_steal_badge_db` | Badge-database theft (the controller's user list) | IT devices | green | bold green | wifipilot itproto.py (http_request) + the controller's API | a http request for inventory, credentials or device identity from an address with no business asking, followed by a copy of the answer leaving the segment |
| `it_steal_phone_contacts` | Phone-directory theft (the handset's own address book) | IT devices | green | bold green | wifipilot itproto.py (http_request) against the handset | a http request for inventory, credentials or device identity from an address with no business asking, followed by a copy of the answer leaving the segment |
| `it_steal_mqtt_retained` | MQTT retained-topic theft (subscribe to '#' and read everything) | IT devices | green | bold green | wifipilot itproto.py (mqtt_subscribe/parse_mqtt) | a mqtt request for inventory, credentials or device identity from an address with no business asking, followed by a copy of the answer leaving the segment |
| `it_steal_k8s_secrets` | Kubernetes secrets theft (the API server answers the list) | IT devices | green | bold green | wifipilot itproto.py (http_request) against port 6443 | a kubernetes request for inventory, credentials or device identity from an address with no business asking, followed by a copy of the answer leaving the segment |
| `it_steal_docker_images` | Docker inventory theft (images and containers over TCP 2375) | IT devices | green | bold green | wifipilot itproto.py (http_request) against the daemon | a docker request for inventory, credentials or device identity from an address with no business asking, followed by a copy of the answer leaving the segment |
| `it_steal_sql_dump` | MySQL greeting theft (version and salt for offline cracking) | IT devices | green | bold green | wifipilot itproto.py (mysql_handshake_parse) | a mysql request for inventory, credentials or device identity from an address with no business asking, followed by a copy of the answer leaving the segment |
| `it_steal_iot_token` | IoT identity theft (model, alias and MAC out of get_sysinfo) | IT devices | green | bold green | wifipilot itproto.py (kasa_command/parse_kasa) | a kasa request for inventory, credentials or device identity from an address with no business asking, followed by a copy of the answer leaving the segment |
| `it_relay_ftp` | FTP credential relay (logins carried through us) | IT devices | cyan | bold green | wifipilot itproto.py (ftp_login/parse_line_protocol) + TCP 21 | two connections to the same ftp service on port 21 — one from the client and one from an address that is not the device — and mirrored traffic whose timing follows the relay rather than the server |
| `it_relay_smtp` | SMTP relay (AUTH exchange and envelope carried through us) | IT devices | cyan | bold green | wifipilot itproto.py (smtp_ehlo) + TCP 25 | two connections to the same smtp service on port 25 — one from the client and one from an address that is not the device — and mirrored traffic whose timing follows the relay rather than the server |
| `it_relay_imap` | IMAP relay (the mailbox login passes through us) | IT devices | cyan | bold green | wifipilot itproto.py (imap_login) + TCP 143 | two connections to the same imap service on port 143 — one from the client and one from an address that is not the device — and mirrored traffic whose timing follows the relay rather than the server |
| `it_relay_vnc` | VNC handshake relay (we choose the security type) | IT devices | cyan | bold green | wifipilot itproto.py (vnc_version/parse_vnc_security) + TCP 5900 | two connections to the same vnc service on port 5900 — one from the client and one from an address that is not the device — and mirrored traffic whose timing follows the relay rather than the server |
| `it_relay_rsync` | rsync relay (module list carried through us) | IT devices | cyan | bold green | wifipilot itproto.py (rsync_hello/parse_line_protocol) + TCP 873 | two connections to the same rsync service on port 873 — one from the client and one from an address that is not the device — and mirrored traffic whose timing follows the relay rather than the server |
| `it_relay_rdp` | RDP negotiation relay (protocol selection carried through us) | IT devices | cyan | bold green | wifipilot itproto.py (rdp_negotiation_request/parse_rdp) + TCP 3389 | two connections to the same rdp service on port 3389 — one from the client and one from an address that is not the device — and mirrored traffic whose timing follows the relay rather than the server |
| `it_relay_dicom` | DICOM relay (associations carried through us) | IT devices | cyan | bold green | wifipilot itproto.py (dicom_associate/parse_dicom_pdu) + TCP 104 | two connections to the same dicom service on port 104 — one from the client and one from an address that is not the device — and mirrored traffic whose timing follows the relay rather than the server |
| `it_relay_elastic` | Elasticsearch relay (an unauthenticated index carried through us) | IT devices | cyan | bold green | wifipilot itproto.py (http_request) + TCP 9200 | two connections to the same elastic service on port 9200 — one from the client and one from an address that is not the device — and mirrored traffic whose timing follows the relay rather than the server |
| `it_relay_jenkins` | Jenkins relay (job list and console carried through us) | IT devices | cyan | bold green | wifipilot itproto.py (jenkins_json) + TCP 8080 | two connections to the same jenkins service on port 8080 — one from the client and one from an address that is not the device — and mirrored traffic whose timing follows the relay rather than the server |
| `it_relay_kubernetes` | kubelet relay (the node's pod list carried through us) | IT devices | cyan | bold green | wifipilot itproto.py (http_request) + TCP 10250 | two connections to the same kubernetes service on port 10250 — one from the client and one from an address that is not the device — and mirrored traffic whose timing follows the relay rather than the server |
| `it_steal_ftp_files` | Anonymous FTP listing (the files a guest can see) | IT devices | green | bold green | wifipilot itproto.py (ftp_login) + TCP 21 | a ftp request for inventory, credentials or device identity from an address with no business asking, followed by a copy of the answer leaving the segment |
| `it_steal_smtp_credentials` | SMTP credential attempt (AUTH with the defaults) | IT devices | green | bold green | wifipilot itproto.py (smtp_ehlo) + TCP 25 | a smtp request for inventory, credentials or device identity from an address with no business asking, followed by a copy of the answer leaving the segment |
| `it_steal_imap_mailbox` | IMAP mailbox theft (a login away from the mail) | IT devices | green | bold green | wifipilot itproto.py (imap_login) + TCP 143 | a imap request for inventory, credentials or device identity from an address with no business asking, followed by a copy of the answer leaving the segment |
| `it_steal_vnc_password` | VNC security-profile theft (the challenge to crack offline) | IT devices | green | bold green | wifipilot itproto.py (vnc_version/parse_vnc_security) | a vnc request for inventory, credentials or device identity from an address with no business asking, followed by a copy of the answer leaving the segment |
| `it_steal_rsync_modules` | rsync module theft (the shares a guest can list) | IT devices | green | bold green | wifipilot itproto.py (rsync_hello) + TCP 873 | a rsync request for inventory, credentials or device identity from an address with no business asking, followed by a copy of the answer leaving the segment |
| `it_steal_dicom_patients` | DICOM association theft (the archive answers an unknown AE title) | IT devices | green | bold green | wifipilot itproto.py (dicom_associate/parse_dicom_pdu) | a dicom request for inventory, credentials or device identity from an address with no business asking, followed by a copy of the answer leaving the segment |
| `it_steal_elastic_docs` | Elasticsearch index theft (an unauthenticated index dump) | IT devices | green | bold green | wifipilot itproto.py (http_request) + TCP 9200 | a elastic request for inventory, credentials or device identity from an address with no business asking, followed by a copy of the answer leaving the segment |
| `it_steal_jenkins_jobs` | Jenkins job theft (the job list and its stored credentials) | IT devices | green | bold green | wifipilot itproto.py (jenkins_json) + TCP 8080 | a jenkins request for inventory, credentials or device identity from an address with no business asking, followed by a copy of the answer leaving the segment |
| `it_steal_kubelet_pods` | kubelet pod theft (the node's workload inventory) | IT devices | green | bold green | wifipilot itproto.py (http_request) + TCP 10250 | a kubernetes request for inventory, credentials or device identity from an address with no business asking, followed by a copy of the answer leaving the segment |
| `it_steal_smb_shares` | SMB share theft (dialects negotiated, shares next) | IT devices | green | bold green | wifipilot itproto.py (smb2_negotiate/parse_smb2) + TCP 445 | a smb request for inventory, credentials or device identity from an address with no business asking, followed by a copy of the answer leaving the segment |
| `it_steal_memcached_keys` | memcached key theft (the keys a cache server will list to a guest) | IT devices | green | bold green | wifipilot itproto.py (memcached_command/parse_resp) + TCP 11211 | a memcached request for inventory, credentials or device identity from an address with no business asking, followed by a copy of the answer leaving the segment |
| `it_steal_ldap_directory` | LDAP directory theft (an anonymous search for every object) | IT devices | green | bold green | wifipilot itproto.py (ldap_search_request/parse_ldap) + TCP 389 | a ldap request for inventory, credentials or device identity from an address with no business asking, followed by a copy of the answer leaving the segment |

### WPS — 5

| attack | answers | edition | noise | impact | tool | defender sees |
| --- | --- | --- | --- | --- | --- | --- |
| `wps_pixie` <br>_on by default, injects_ | WPS Pixie-Dust (offline) | WiFi | green | bold green | reaver -K 1 / bully --pixiewps | one WPS exchange (EAP messages 1-4); the AP sees a normal enrolment |
| `wps_ap_pin` <br>_injects_ | WPS AP-PIN attempt (vendor algorithm) | WiFi | green | bold green | reaver -p <AP PIN> (or bully) | static AP-PIN attempts from a vendor algorithm |
| `wps_lockout_probe` <br>_injects_ | WPS lockout probe (policy measurement) | WiFi | green | green | reaver (wrong PINs, then stop) / wash | a few deliberately-wrong PINs, then stop: the finding is whether the AP locked out |
| `wps_pbc` <br>_injects_ | WPS push-button enrolment (window check) | WiFi | green | bold green | wpa_supplicant (wps_pbc) + wpa_cli | push-button enrolment attempts; fails visibly while the AP's button window is shut |
| `wps_pin` <br>_injects_ | WPS PIN recovery (online) | WiFi | cyan | bold green | reaver / bully | a stream of PIN attempts; APs with lockout will report it |

### WEP — 6

| attack | answers | edition | noise | impact | tool | defender sees |
| --- | --- | --- | --- | --- | --- | --- |
| `arp_replay` <br>_injects_ | ARP replay (WEP IV generation) | WiFi | yellow | yellow | aireplay-ng -3 (with a raw-frame fallback) | injected ARP frames that the AP rebroadcasts; network traffic rises while IVs accumulate |
| `wep_ivs` <br>_on by default, injects_ | WEP IV harvesting | WiFi | yellow | bold green | airodump-ng + aireplay-ng --arpreplay | ARP-replay injection; the network's own traffic rises |
| `wep_p0841` <br>_injects_ | WEP P0841 (injected ARP) | WiFi | yellow | bold green | aireplay-ng -2 -p 0841 | injected ARP frames with a spoofed client |
| `wep_chopchop` <br>_injects_ | WEP chopchop | WiFi | yellow | bold green | aireplay-ng -4 (KoreK chopchop) | one frame chopped byte by byte; thousands of injected frames |
| `wep_fragment` <br>_injects_ | WEP fragmentation | WiFi | cyan | bold green | aireplay-ng -5 (fragmentation) | fragmented injected frames |
| `wep_hirte` <br>_injects_ | WEP Hirte (client fragmentation) | WiFi | cyan | bold green | aireplay-ng -7 (client-oriented fragmentation) | client-driven fragmentation; a station must be active |

### Enterprise (802.1X) — 17

| attack | answers | edition | noise | impact | tool | defender sees |
| --- | --- | --- | --- | --- | --- | --- |
| `enterprise` | WPA-Enterprise survey | WiFi | dim | green | airodump-ng (+ hostapd-mana/eaphammer when installed) | nothing on air; decodes 802.1X already captured |
| `eap_identity_harvest` <br>_injects_ | EAP identity harvest (cleartext usernames) | WiFi | dim | green | wifipilot (EAP parser over a capture or a live listen) | nothing from us until a client authenticates; reads the EAP-Response/Identity the AP asked for |
| `eap_method_probe` <br>_injects_ | EAP method probe (what the server will negotiate) | WiFi | green | green | wifipilot (EAPOL-Start + EAP Nak) | one EAPOL-Start per identity, then the NAK method list: a short negotiation the AP logs |
| `certificate_audit` <br>_injects_ | RADIUS certificate audit (X.509) | WiFi | dim | green | wifipilot (TLS Certificate + X.509 DER parser) | nothing on air; parses certificates already captured |
| `ttls_inner_audit` <br>_injects_ | TTLS/PEAP inner conversation audit | WiFi | dim | green | wifipilot (EAP-in-TLS decoder) | nothing on air; reads the inner conversation of a captured TTLS tunnel |
| `eap_tls_version` <br>_injects_ | EAP-TLS version and cipher audit | WiFi | dim | green | wifipilot (TLS record parser) | nothing on air; reads the TLS version out of a captured EAP-TLS handshake |
| `radius_secret_test` <br>_injects_ | RADIUS shared-secret test | WiFi | green | green | wifipilot netproto (own RADIUS client) | one Access-Request per candidate secret; a real RADIUS server logs the failures |
| `rogue_radius` <br>_injects_ | Rogue RADIUS (credential check) | WiFi | cyan | bold green | eaphammer / hostapd-mana / hostapd-wpe | a rogue RADIUS/eaphammer AP; clients that trust any certificate will offer credentials |
| `enterprise_rogue_radius` <br>_injects_ | Rogue authenticator (802.1X served from our radio) | WiFi | cyan | bold green | wifipilot netproto.py (RADIUS) + a RADIUS identity of our own | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `enterprise_peap_relay` <br>_injects_ | PEAP relay (the attacker carries the exchange to the real RADIUS) | WiFi | cyan | bold green | wifipilot netproto.py (RADIUS builder and parser) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `enterprise_certificate_swap` <br>_injects_ | EAP-TLS certificate swap (right name, wrong issuer) | WiFi | cyan | bold green | wifipilot synth.py (certificate builder) + EAP-TLS frames | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `enterprise_eap_md5` <br>_injects_ | EAP-MD5 harvest (challenge/response for the dictionary) | WiFi | cyan | bold green | wifipilot synth.py (EAP frames) + a wordlist | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `enterprise_gtc_prompt` <br>_injects_ | EAP-GTC prompt (the password, typed into our tunnel) | WiFi | cyan | bold green | wifipilot synth.py (EAP frames) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `enterprise_ttls_pap` <br>_injects_ | EAP-TTLS/PAP harvest (cleartext inner credential) | WiFi | cyan | bold green | wifipilot synth.py (TTLS/PAP exchange) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `enterprise_mschapv2_relay` <br>_injects_ | MSCHAPv2 relay (challenge/response captured from both ends) | WiFi | cyan | bold green | wifipilot netproto.py (MSCHAPv2) + EAP frames | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `enterprise_downgrade` <br>_injects_ | EAP method downgrade (PEAP to a crackable inner method) | WiFi | cyan | bold green | wifipilot synth.py (EAP request frames) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `enterprise_supplicant_clone` <br>_injects_ | Supplicant impersonation (harvested identity, our radio) | WiFi | cyan | bold green | wifipilot synth.py (EAP-Response/Identity) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |

### Rogue infrastructure and lures — 237

| attack | answers | edition | noise | impact | tool | defender sees |
| --- | --- | --- | --- | --- | --- | --- |
| `eapol_logoff` <br>_injects_ | EAPOL-Logoff (unauthenticated disconnect) | WiFi | green | yellow | wifipilot rawtx.py (AF_PACKET injection) | EAPOL-Logoff frames: no deauth, and PMF does not cover them |
| `karma_detect` <br>_injects_ | Karma/MANA rogue-AP detection (probe all names) | WiFi | green | green | wifipilot rawtx.py (probe requests, random names) | probe requests for names that do not exist; anything that answers is a Karma device |
| `csa_attack` <br>_injects_ | Channel-switch announcement (silent eviction) | WiFi | cyan | yellow | wifipilot rawtx.py (CSA beacon) | beacons with a Channel Switch Announcement; clients leave the channel |
| `ssid_bruteforce` <br>_injects_ | Hidden-SSID brute force (directed probes) | WiFi | cyan | green | wifipilot rawtx.py (probe requests, wordlist) | probe/association attempts with dictionary SSIDs against a hidden network |
| `ssid_confusion` <br>_injects_ | SSID confusion (impostor BSSID) | WiFi | cyan | yellow | wifipilot rawtx.py (beacon, existing SSID) | beacons for an existing SSID from a new BSSID |
| `ap_isolation_audit` <br>_injects_ | Client-isolation audit (spoofed ARP) | WiFi | green | green | wifipilot rawtx.py (ARP request between two clients) | a handful of spoofed ARP frames between two clients |
| `pmf_downgrade_probe` <br>_injects_ | PMF enforcement probe (unprotected disassoc) | WiFi | green | yellow | wifipilot rawtx.py (disassociation) | association attempts with MFPC/MFPR cleared: the AP either enforces PMF or negotiates it away |
| `btm_hijack` <br>_injects_ | 802.11v BTM steering to a rogue BSSID | WiFi | green | yellow | wifipilot rawtx.py (WNM action frame) | BTM requests naming candidate BSSIDs that are not the AP's neighbours |
| `evil_twin` <br>_injects_ | Evil twin (client lure) | WiFi | cyan | bold green | hostapd-mana / hostapd | a second access point with the same SSID; the real network's clients may prefer it |
| `karma` <br>_injects_ | Karma (answer every probe request) | WiFi | cyan | bold green | hostapd-mana (enable_mana=1) | an AP that answers every probe request (hostapd-mana) |
| `rogue_dhcp` <br>_injects_ | Rogue DHCP server (leases to anyone who asks) | WiFi | cyan | yellow | wifipilot netproto.py (DHCP) + rawtx.py (injected offers) | a second DHCP server on the segment: offers carry our gateway and resolver |
| `dns_sink` <br>_injects_ | DNS sink (every name answered, every query logged) | WiFi | cyan | yellow | wifipilot netproto.py (own DNS server) | every DNS query answered by us, one log line per name |
| `captive_portal` <br>_injects_ | Captive portal (a login page served by us) | WiFi | cyan | bold green | wifipilot (http.server) | a portal page asking for credentials, served by us |
| `arp_mitm` <br>_injects_ | ARP man-in-the-middle (gateway masquerade) | WiFi | yellow | yellow | wifipilot rawtx.py (gratuitous ARP) | gratuitous ARP replies claiming the gateway: traffic passes through our radio |
| `beacon_clone` <br>_injects_ | Beacon clone (the SSID from a second radio) | WiFi | cyan | yellow | wifipilot rawtx.py (beacons) | beacons with the network's own BSSID and elements, sent from a second radio |
| `wpa3_downgrade_twin` <br>_injects_ | WPA3 downgrade twin (offer the network as WPA2-only) | WiFi | cyan | yellow | hostapd with a WPA2-only profile | a twin with SAE and PMF stripped: clients that do not require WPA3 may join it |
| `bt_beacon_clone` <br>_injects_ | iBeacon clone | Bluetooth | cyan | bold green | wifipilot bt.py (advertising a copied beacon payload) | the capture itself |
| `bt_tracker_clone` <br>_injects_ | Tracker advertisement clone | Bluetooth | cyan | bold green | wifipilot bt.py (advertising a copied tracker payload) | the capture itself |
| `bt_connectable_lure` <br>_injects_ | Connectable advertising lure | Bluetooth | cyan | green | wifipilot bt.py (connectable advertising + LE connection events) | the capture itself |
| `ble_hid` <br>_injects_ | BLE HID injection (keyboard over GATT) | Bluetooth | cyan | bold green | wifipilot bt.py (LE advertising + ATT notifications) | A new HID peripheral in the host's Bluetooth settings, and keystrokes nobody typed: the host's own log carries the connection, the service discovery and the input reports, and a keyboard the user never paired stays in the device list for as long as the bond is kept. |
| `ble_hid_boot` <br>_injects_ | BLE HID boot-protocol downgrade | Bluetooth | cyan | bold green | wifipilot bt.py (ATT write to the HID Protocol Mode characteristic) | An ATT write to the HID service of the host, from a peripheral it has not paired with: a host that logs its GATT writes shows the protocol change and the boot reports that follow it. |
| `ble_hid_reconnect` <br>_injects_ | BLE reconnect hijack (impersonate the bonded keyboard) | Bluetooth | cyan | bold green | wifipilot bt.py (LE Set Random Address + advertising) | Two devices with the same Bluetooth name and address on air, and a host that connects to the second one: the host's device list shows the duplicate, and a passive receiver sees one address on two transmitters. |
| `ble_smp_downgrade` <br>_injects_ | LE pairing downgrade probe (Just Works + 7-byte key) | Bluetooth | cyan | bold green | wifipilot bt.py (SMP Pairing Request over L2CAP) | A Pairing Request with the MITM and Secure Connections bits clear: a host that logs pairing shows the attempt, and the device's own menu shows a pairing the user never accepted. |
| `ble_hid_mimic` <br>_injects_ | BLE HID mimic (clone the keyboard, keystroke every host) | Bluetooth | cyan | bold green | wifipilot bt.py (identity clone + HID over GATT) | Two keyboards with one name: the host that reconnects logs a connection it did not ask for, the device list keeps the duplicate, and the input reports that follow arrive on a link the user never initiated. |
| `ble_speaker_mimic` <br>_injects_ | BLE speaker mimic (clone the speaker, take the audio link) | Bluetooth | cyan | bold green | wifipilot bt.py (identity clone + AVDTP/AVRCP over L2CAP) | An A2DP configuration from a device the site does not own: the speaker logs an audio link and an AVRCP session, and the phone that was bonded to it finds another device answering to the same name. |
| `ble_pairing_mimic` <br>_injects_ | BLE pairing mimic (complete the exchange without a human) | Bluetooth | cyan | bold green | wifipilot bt.py (identity clone + security manager) | A pairing that nobody initiated: the host's Bluetooth log carries the bond and the Just Works flag, and a key was established with a device that was never in the room. |
| `ble_bond_hijack` <br>_injects_ | BLE bond hijack (replace the stored link key) | Bluetooth | cyan | bold green | wifipilot bt.py (HCI link-key commands + identity clone) | A link key change the host did not ask for, and a subsequent pairing for a device that is already bonded: the controller's own log records both. |
| `ble_adv_identity_clone` <br>_injects_ | BLE advertising identity clone (a duplicate on air) | Bluetooth | green | green | wifipilot bt.py (advertising data + LE Set Random Address) | One device identity, two transmitters: a passive receiver that logs addresses sees the same address twice with different signal strengths. |
| `ble_name_collision` <br>_injects_ | BLE name collision (every trusted name, one transmitter) | Bluetooth | yellow | bold green | wifipilot bt.py (advertising under a list of names) | One address advertising a handful of different names in a minute: an advertising monitor shows the sequence, and every host that reconnects logs it. |
| `ble_device_mimic` <br>_injects_ | BLE device mimic (clone any advertising device) | Bluetooth | green | green | wifipilot bt.py (advertisement copy) | A duplicate advertisement: two transmitters under one address, which an advertising monitor records as one device with two signal strengths. |
| `ble_tracker_mimic` <br>_injects_ | BLE tracker mimic (clone a find-my tag) | Bluetooth | green | green | wifipilot bt.py (tracker advertisement copy) | A tracker that is not on the asset register: the vendor's own network logs a new tag, and the site's fixed scanners see it move. |
| `ble_beacon_mimic` <br>_injects_ | BLE beacon mimic (clone an iBeacon identity) | Bluetooth | green | green | wifipilot bt.py (iBeacon builder + decoder) | Two transmitters with one beacon identity: an iBeacon scanner sees the same major and minor from two addresses, which is exactly the collision detection it is supposed to alarm on. |
| `ble_eddystone_mimic` <br>_injects_ | BLE Eddystone mimic (clone a URL beacon) | Bluetooth | green | green | wifipilot bt.py (Eddystone builder + decoder) | A second beacon with one URL: an Eddystone scanner sees two transmitters with the same service data, and the phones nearby will open whichever is closer. |
| `ble_smartlock_mimic` <br>_injects_ | BLE smart-lock mimic (clone the commissioning phone) | Bluetooth | cyan | red | wifipilot bt.py (identity clone + vendor lock characteristic) | An unlock from a device that is not the resident phone, at a time nobody asked for: the lock's own log carries the connection and the characteristic write. |
| `ble_badge_mimic` <br>_injects_ | BLE badge mimic (clone an access badge) | Bluetooth | cyan | red | wifipilot bt.py (identity clone + badge characteristics) | A badge that is in two places at once: the access system logs a badge presented at a reader the holder never visited. |
| `ble_ev_charger_mimic` <br>_injects_ | BLE EV charger mimic (take a charge session) | Bluetooth | cyan | red | wifipilot bt.py (identity clone + charge control characteristic) | A charge session started, stopped or limited from an unknown phone: the charger and the back-office both log the session against a device that is not the user's. |
| `ble_mesh_mimic` <br>_injects_ | BLE mesh mimic (join through the proxy service) | Bluetooth | cyan | green | wifipilot bt.py (Mesh Proxy service over ATT) | An unprovisioned proxy connection: the mesh node logs a proxy client whose address is not in the network's provisioning list. |
| `ble_anchor_mimic` <br>_injects_ | BLE anchor mimic (spoof a positioning anchor) | Bluetooth | cyan | yellow | wifipilot bt.py (anchor characteristics over ATT) | An anchor configuration write from a device that is not the site's fleet manager, followed by location data that drifts. |
| `ble_printer_mimic` <br>_injects_ | BLE printer mimic (accept a print job as a clone) | Bluetooth | green | bold green | wifipilot bt.py (print service clone) | A printer that is in two places: the site's fleet management sees two devices with one name, and the print server logs a job to a device it does not know. |
| `ble_ir_mimic` <br>_injects_ | BLE IR blaster mimic (take the room's remote control) | Bluetooth | cyan | yellow | wifipilot bt.py (IR command characteristic) | An IR command from a phone that is not the room's: the hub logs the connection, and the equipment in the room logs the command. |
| `ble_fastpair_mimic` <br>_injects_ | BLE Fast Pair mimic (clone an accessory's model id) | Bluetooth | green | green | wifipilot bt.py (Fast Pair service + model id) | A Fast Pair accessory that is not the one on the asset register: the phone's pairing prompt names a model the site does not own. |
| `ble_fido_mimic` <br>_injects_ | BLE FIDO key mimic (registration without a touch) | Bluetooth | green | bold green | wifipilot bt.py (FIDO service over ATT) | A security key registration from a device the user did not insert: the identity provider logs the credential, and the user did not press anything. |
| `ble_telemetry_mimic` <br>_injects_ | BLE telemetry mimic (read a vehicle's log as the clone) | Bluetooth | cyan | bold green | wifipilot bt.py (telemetry and log characteristics) | A telematics unit being read from an address the fleet does not own: the back office sees a second reader on the same device. |
| `ble_patient_mimic` <br>_injects_ | BLE patient-monitor mimic (read telemetry as the app) | Bluetooth | cyan | bold green | wifipilot bt.py (medical telemetry characteristics) | A monitor read by an application instance that is not the ward's: the clinical network logs a second client for one device. |
| `ble_hid_multi_host` <br>_injects_ | BLE HID multi-host (type on every host that reconnects) | Bluetooth | cyan | bold green | wifipilot bt.py (identity clone + HID reports per host) | One clone with several connections: each host logs an HID connection at the same moment, and the keystrokes appear in each machine's own log. |
| `ble_consumer_mimic` <br>_injects_ | BLE consumer-control mimic (media keys as a clone) | Bluetooth | cyan | yellow | wifipilot bt.py (HID consumer control reports) | Media-key reports from a remote the user does not hold: the host logs the HID connection and the consumer-control usage codes. |
| `ble_audio_le_mimic` <br>_injects_ | BLE LE-Audio mimic (write the media and volume control points) | Bluetooth | cyan | yellow | wifipilot bt.py (media control and volume control services) | A volume or media control write from a device that is not the phone: the sink logs the ATT write and the volume changes for the user. |
| `ble_peripheral_shadow` <br>_injects_ | BLE peripheral shadow (clone a device's whole attribute table) | Bluetooth | cyan | green | wifipilot bt.py (Read By Group Type + ATT reads) | A second device serving one attribute table: the device's own service log sees a peer it did not provision, and the fixed scanners see a duplicate. |
| `ble_mouse_mimic` <br>_injects_ | BLE mouse mimic (clone the mouse, click on the host) | Bluetooth | cyan | bold green | wifipilot bt.py (HID reports over GATT) + blesim | Pointer movement with nobody at the desk: the host logs HID reports on a reconnected link, and the device list shows two devices with one address. |
| `ble_combo_dongle_mimic` <br>_injects_ | BLE combo dongle mimic (consumer keys on a bonded receiver) | Bluetooth | cyan | bold green | wifipilot bt.py (HID reports over GATT) + blesim | two peripherals with one address on the floor, and a capability that executed on a link the user did not start |
| `ble_lock_mimic` <br>_injects_ | BLE lock mimic (clone the lock, take the unlock command) | Bluetooth | cyan | bold green | wifipilot bt.py (vendor ATT write) + blesim | An unlock with no credential presented: the lock's own audit trail shows a locked-to-unlocked transition on a link it did not pair with. |
| `ble_lock_mesh_mimic` <br>_injects_ | BLE lock admin mimic (write the admin key on a networked lock) | Bluetooth | cyan | bold green | wifipilot bt.py (vendor ATT write) + blesim | An admin write from the lock's own address on a link with no pairing record: the management platform sees a credential change it did not issue. |
| `ble_bulb_mimic` <br>_injects_ | BLE bulb mimic (clone the bulb, drive the light) | Bluetooth | cyan | bold green | wifipilot bt.py (ATT write) + blesim | A light that changes with no command from the controller: the bridge log shows writes on a link it did not create. |
| `ble_mesh_lamp_mimic` <br>_injects_ | BLE mesh node mimic (provisioning PDU at a mesh lamp) | Bluetooth | cyan | bold green | wifipilot bt.py (ATT write) + blesim | A provisioning beacon from an address already in the mesh: the provisioner's log shows an unprovisioned device where there should be a managed node. |
| `ble_plug_mimic` <br>_injects_ | BLE plug mimic (clone the plug, switch the load) | Bluetooth | cyan | bold green | wifipilot bt.py (ATT write) + blesim | A load that cycles with no schedule: the plug's cloud log shows state changes from a device that reconnected under the plug's own address. |
| `ble_band_mimic` <br>_injects_ | BLE fitness band mimic (clone the band, forge the activity data) | Bluetooth | cyan | bold green | wifipilot bt.py (ATT notification) + blesim | Activity data with no gait behind it: the platform's ingest shows a second device with the band's address and a session the wearer never started. |
| `ble_thermostat_mimic` <br>_injects_ | BLE thermometer mimic (clone the sensor, send a forged measurement) | Bluetooth | cyan | bold green | wifipilot bt.py (ATT indication) + blesim | Readings with no measurement event: the app's history shows entries from the device's address with no corresponding on-device measurement. |
| `ble_scale_mimic` <br>_injects_ | BLE scale mimic (clone the scale, take its provisioning identity) | Bluetooth | cyan | bold green | wifipilot bt.py (ATT reads) + blesim | two peripherals with one address on the floor, and a capability that executed on a link the user did not start |
| `ble_glucose_mimic` <br>_injects_ | BLE glucose meter mimic (clone the meter, skew its calibration) | Bluetooth | cyan | bold green | wifipilot bt.py (vendor ATT write) + blesim | A calibrated medical device whose calibration changed out of hours, on a link the meter's own log does not show as an operator session. |
| `ble_pressure_mimic` <br>_injects_ | BLE blood-pressure mimic (clone the cuff, send a forged reading) | Bluetooth | cyan | bold green | wifipilot bt.py (ATT indication) + blesim | two peripherals with one address on the floor, and a capability that executed on a link the user did not start |
| `ble_ecg_mimic` <br>_injects_ | BLE ECG patch mimic (clone the patch, send a forged rhythm) | Bluetooth | cyan | bold green | wifipilot bt.py (ATT notification) + blesim | two peripherals with one address on the floor, and a capability that executed on a link the user did not start |
| `ble_hr_mimic` <br>_injects_ | BLE heart-rate strap mimic (clone the strap, drive the zone) | Bluetooth | cyan | bold green | wifipilot bt.py (ATT notification) + blesim | two peripherals with one address on the floor, and a capability that executed on a link the user did not start |
| `ble_air_quality_mimic` <br>_injects_ | BLE air-quality mimic (clone the monitor, take its identity) | Bluetooth | cyan | bold green | wifipilot bt.py (device-information reads) + blesim | One sensor disagreeing with its neighbours: the platform's dashboard shows a clean room beside dirty ones, both reporting from the same name. |
| `ble_charger_mimic` <br>_injects_ | BLE charge-point mimic (clone the charger, start a session) | Bluetooth | cyan | bold green | wifipilot bt.py (vendor ATT write) + blesim | A session on a bay with no vehicle on it: the back-office record shows an authorisation from the charger's own address. |
| `ble_label_printer_mimic` <br>_injects_ | BLE label printer mimic (clone the printer, take the job) | Bluetooth | cyan | bold green | wifipilot bt.py (vendor ATT write) + blesim | two peripherals with one address on the floor, and a capability that executed on a link the user did not start |
| `ble_ir_hub_mimic` <br>_injects_ | BLE IR-hub mimic (clone the hub, send an IR command) | Bluetooth | cyan | bold green | wifipilot bt.py (vendor ATT write) + blesim | An IR transmission with no app command behind it: the hub's own log shows a send from a link it did not create. |
| `ble_uwb_anchor_mimic` <br>_injects_ | BLE/UWB anchor mimic (clone the anchor, forge the range) | Bluetooth | cyan | bold green | wifipilot bt.py (vendor ATT write) + blesim | A tag that moved without moving: the location platform shows a trajectory that contradicts the door reader and the cameras. |
| `ble_patient_monitor_mimic` <br>_injects_ | BLE patient monitor mimic (clone the monitor, send a forged vital sign) | Bluetooth | cyan | bold green | wifipilot bt.py (ATT notification) + blesim | A vital sign that disagrees with the bedside device: two monitors with one address, and a chart that changed without an alarm. |
| `ble_vehicle_tracker_mimic` <br>_injects_ | BLE vehicle tracker mimic (clone the tracker, forge the position) | Bluetooth | cyan | bold green | wifipilot bt.py (vendor ATT write) + blesim | two peripherals with one address on the floor, and a capability that executed on a link the user did not start |
| `ble_vending_mimic` <br>_injects_ | BLE vending mimic (clone the telemetry unit, take its identity) | Bluetooth | cyan | bold green | wifipilot bt.py (ATT reads) + blesim | two peripherals with one address on the floor, and a capability that executed on a link the user did not start |
| `ble_doorbell_mimic` <br>_injects_ | BLE doorbell mimic (clone the doorbell, write its setpoint) | Bluetooth | cyan | bold green | wifipilot bt.py (vendor ATT write) + blesim | A ring with no motion event: the camera's own event log has a press that no sensor corroborates. |
| `ble_ibeacon_mimic` <br>_injects_ | BLE beacon mimic (clone a beacon's UUID, major and minor) | Bluetooth | cyan | bold green | wifipilot bt.py (iBeacon payload) + blesim | Two beacons with one identity on the floor plan: the asset tracking platform shows a tag in two places at once, and neither is wrong. |
| `ble_soundbar_mimic` <br>_injects_ | BLE soundbar mimic (clone the soundbar, take the audio link) | Bluetooth | cyan | bold green | wifipilot bt.py (AVDTP/AVRCP over L2CAP) + blesim | An A2DP configuration from a device the site does not own: the room's phone shows a second soundbar with the same name and an audio link it did not open. |
| `ble_hfp_hijack` <br>_injects_ | Bluetooth HFP hijack (answer, hang up and dial over RFCOMM) | Bluetooth | cyan | yellow | wifipilot blesim.py (RFCOMM + AT) | A call answered, hung up or dialled with nobody touching the phone: the headset or car kit logs the AT channel, and the phone's call log carries the number. |
| `ble_hfp_audio_gateway` <br>_injects_ | Bluetooth HFP audio gateway (establish the call audio channel) | Bluetooth | cyan | bold green | wifipilot blesim.py (AT + audio channel handshake) | An audio channel established without a call: the phone logs the codec negotiation and the headset logs a second channel. |
| `ble_map_hijack` <br>_injects_ | Bluetooth MAP hijack (download the message store) | Bluetooth | green | bold green | wifipilot blesim.py (OBEX + MAP) | A message download from a device that is not the car kit: the phone logs the OBEX session, and the SMS store is asked for a folder nobody's app opened. |
| `ble_pbap_hijack` <br>_injects_ | Bluetooth PBAP hijack (download the phonebook) | Bluetooth | green | bold green | wifipilot blesim.py (OBEX + PBAP) | A phonebook download outside the pairing: the phone logs the PBAP session, and the listing is pulled from an address that is not the car. |
| `ble_sap_imsi_read` <br>_injects_ | Bluetooth SAP IMSI read (the SIM's identity over RFCOMM) | Bluetooth | cyan | bold green | wifipilot bt.py (SAP + APDU) + blesim.py | A SIM session from a device that is not the car: the phone's SIM tooling logs the APDU exchange, and the network sees the card in two places at once. |
| `ble_sap_file_sweep` <br>_injects_ | Bluetooth SAP file sweep (read every SIM file) | Bluetooth | cyan | bold green | wifipilot bt.py (SAP constants + APDU) + blesim.py | A burst of APDU selects from one session: the SIM's own log and the phone's SIM tooling both show a client walking the file table. |
| `ble_obex_push` <br>_injects_ | Bluetooth OBEX push (send an object to an object store) | Bluetooth | cyan | bold green | wifipilot blesim.py (OBEX PUT) | An OBEX push from an unpaired sender: the receiving device shows the incoming file, and the store logs the session. |
| `ble_spp_hijack` <br>_injects_ | Bluetooth SPP hijack (write to a serial port profile) | Bluetooth | cyan | yellow | wifipilot blesim.py (RFCOMM raw) | A device taking bytes on SPP from an address that is not its host: the printer or the scale logs the connection, and the label stock changes. |
| `ble_dial_hijack` <br>_injects_ | Bluetooth DIAL hijack (launch an app on a media device) | Bluetooth | green | yellow | wifipilot blesim.py (OBEX GET on the app endpoint) | An app launch from a device that is not the phone: the television logs the DIAL session, and the screen changes. |
| `ble_hidp_classic_inject` <br>_injects_ | Bluetooth HIDP injection (classic keystrokes over PSM 0x0013) | Bluetooth | cyan | bold green | wifipilot bt.py (HIDP frames) + blesim.py | Input reports on a HID channel the host did not initiate: the host's input stack logs the device, and the keystrokes appear in whatever has focus. |
| `ble_audio_session_takeover` <br>_injects_ | Bluetooth audio takeover (configure AVDTP and drive AVRCP) | Bluetooth | cyan | bold green | wifipilot bt.py (AVDTP + AVCTP/AVRCP) + blesim.py | An audio configuration from a device that is not the paired phone: the speaker logs the AVDTP session and the AVRCP notifications go to a second controller. |
| `ble_gatt_write_sweep` <br>_injects_ | BLE GATT write sweep (write the whole table, read it back) | Bluetooth | yellow | red | wifipilot blesim.py (ATT write + read-back) | A burst of writes across one attribute table: the device logs the ATT session per characteristic, and the values it serves have changed. |
| `ble_notify_spoof` <br>_injects_ | BLE notification spoof (a notification the host did not ask for) | Bluetooth | cyan | bold green | wifipilot blesim.py (Handle Value Notification) | Input notifications from a peripheral that is not connected: the host's input stack logs the report, and the device list has no matching connection. |
| `ble_service_changed_abuse` <br>_injects_ | BLE service-changed abuse (force the host to re-discover) | Bluetooth | cyan | bold green | wifipilot blesim.py (Service Changed characteristic) | A service-changed write outside a firmware update: the host re-discovers its attribute table, and the device's own firmware log has no update to explain it. |
| `ble_signed_write_bypass` <br>_injects_ | BLE signed-write bypass (unsigned write where signing is required) | Bluetooth | green | red | wifipilot blesim.py (ATT Write Command) | A write with no signature where the descriptor asks for one: the device's log shows the ATT write command, and the value has changed. |
| `ble_irk_crack` <br>_injects_ | BLE IRK recovery (resolve an address to the identity behind it) | Bluetooth | green | bold green | wifipilot bt.py (ah/ AES resolution) + blesim.py | None on air: the resolution happens offline against addresses that were already broadcast, which is why a leaked IRK is worth more than a captured one. |
| `ble_version_spoof` <br>_injects_ | BLE version exchange (spoof an old controller version) | Bluetooth | green | green | wifipilot bt.py (LL_VERSION_IND) + blesim.py | A version exchange outside a connection setup: it is a legitimate PDU, which is what makes a forged one hard to see. |
| `ble_encryption_negotiation` <br>_injects_ | BLE encryption negotiation (encrypt the link with our key) | Bluetooth | cyan | bold green | wifipilot bt.py (Set Connection Encryption + Link Key Reply) + blesim.py | An encryption change on a link that never paired: the peer's controller log shows the encryption event without a pairing before it. |
| `ble_passkey_bruteforce` <br>_injects_ | BLE passkey brute force (Pairing Confirm guesses) | Bluetooth | yellow | red | wifipilot bt.py (SMP pairing + confirm) + blesim.py | Repeated pairing attempts from one address: the device's security manager log carries the failed exchanges, and a user-facing pairing mode that stays open shows them as well. |
| `ble_oob_claim` <br>_injects_ | BLE out-of-band claim (pair with OOB data that does not exist) | Bluetooth | cyan | bold green | wifipilot bt.py (SMP pairing request, OOB flag) + blesim.py | A pairing request with the OOB flag from a device that was never given any: the device's own pairing UI never showed a code, which is the contradiction an operator can see. |
| `ble_lesc_downgrade` <br>_injects_ | BLE Secure Connections downgrade (KNOB, on the pairing request) | Bluetooth | cyan | bold green | wifipilot bt.py (SMP auth requirements) + blesim.py | A pairing request without the Secure Connections bit to a device that supports it: the device's log carries the negotiated auth byte, and a legacy exchange on a modern device is the finding. |
| `ble_keypress_spoof` <br>_injects_ | BLE keypress spoof (notification messages during a passkey exchange) | Bluetooth | green | bold green | wifipilot bt.py (SMP keypress notification) + blesim.py | Keypress notifications from a device that has no keyboard: the pairing exchange carries messages the device's own UI cannot produce. |
| `ble_ctkd_cross_transport` <br>_injects_ | BLE cross-transport key derivation (one pairing, two transports) | Bluetooth | cyan | bold green | wifipilot bt.py (SMP auth bits + h7) + blesim.py | An LE pairing followed by a classic connection with no classic pairing: the two device logs side by side show one bond and two transports. |
| `ble_key_size_probe` <br>_injects_ | BLE key size probe (what the device accepts, seven bytes or sixteen) | Bluetooth | cyan | bold green | wifipilot bt.py (SMP key size negotiation) + blesim.py | A pairing request with a seven-byte key from a device that reports sixteen: the device's log carries the negotiated size, and an implementation that does not check is the finding. |
| `ble_bond_overwrite` <br>_injects_ | BLE bond overwrite (install our key during key distribution) | Bluetooth | cyan | bold green | wifipilot bt.py (SMP encryption information) + blesim.py | A key distribution without a completed pairing: the device's security manager log carries an Encryption Information command it never asked for. |
| `ble_confirm_replay` <br>_injects_ | BLE pairing confirm replay (the same value, twice) | Bluetooth | green | bold green | wifipilot bt.py (SMP confirm/random) + blesim.py | Two identical confirm values in one session: the device's security manager log carries the pair, and a real exchange never produces them. |
| `ble_public_key_audit` <br>_injects_ | BLE public key audit (send a known debug key to a Secure Connections pair) | Bluetooth | cyan | bold green | wifipilot bt.py (SMP public key) + blesim.py | A public key from a device that then fails to complete: the device's log carries the exchange, and a valid pairing never follows it. |
| `twin_address_clone` <br>_injects_ | Twin on the target's own BSSID (address cloning) | WiFi | cyan | yellow | wifipilot synth.py (beacon builder) + airodump-ng | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `twin_element_clone` <br>_injects_ | Twin that clones the whole element set (fingerprint collision) | WiFi | cyan | yellow | wifipilot synth.py (element library) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `twin_rsn_strip` <br>_injects_ | Twin without RSN (secured network cloned open) | WiFi | cyan | yellow | wifipilot synth.py (beacon builder) + airodump-ng | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `twin_tkip_downgrade` <br>_injects_ | Twin with TKIP (CCMP downgraded, Michael countermeasure) | WiFi | cyan | yellow | wifipilot synth.py (RSN builder) + airodump-ng | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `twin_pmf_strip` <br>_injects_ | Twin with PMF stripped (802.11w downgrade) | WiFi | cyan | yellow | wifipilot synth.py (RSN builder) + airodump-ng | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `twin_wpa3_transition` <br>_injects_ | Twin in WPA3 transition mode (WPA2 handshake harvest) | WiFi | cyan | yellow | wifipilot synth.py (transition-mode RSN) + airodump-ng | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `twin_owe_transition` <br>_injects_ | Twin against OWE (open clone of an unauthenticated-encryption network) | WiFi | cyan | yellow | wifipilot synth.py (OWE RSN) + airodump-ng | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `twin_hidden_name` <br>_injects_ | Twin that serves a hidden SSID by its real name | WiFi | cyan | yellow | wifipilot synth.py (probe + beacon builders) + airodump-ng | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `twin_enterprise_clone` <br>_injects_ | Twin of an 802.1X network (rogue authenticator, same realm) | WiFi | cyan | yellow | wifipilot synth.py + a RADIUS identity of our own | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `twin_mobility_domain` <br>_injects_ | Twin inside the target's 802.11r mobility domain (fast-roam lure) | WiFi | cyan | yellow | wifipilot synth.py (Mobility Domain element) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `twin_bss_load` <br>_injects_ | Twin with a forged BSS Load element (steering by admission control) | WiFi | cyan | yellow | wifipilot synth.py (BSS Load + WMM elements) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `twin_country_mismatch` <br>_injects_ | Twin with the target's country element on a channel it may not use | WiFi | cyan | yellow | wifipilot synth.py (Country element) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `twin_probe_shadow` <br>_injects_ | Probe-response shadow twin (no beacons to see in a scan) | WiFi | green | yellow | wifipilot synth.py (probe response builder) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `twin_signal_boost` <br>_injects_ | Twin with a signal advantage (steering by RSSI) | WiFi | cyan | yellow | wifipilot synth.py + a transmitter near the client | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `twin_ssid_suffix` <br>_injects_ | Twin with a look-alike SSID (trailing space and homoglyph) | WiFi | cyan | yellow | wifipilot synth.py (beacon builder) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `twin_multi_name` <br>_injects_ | Multi-name twin (KARMA-style answers, one beacon list) | WiFi | yellow | yellow | wifipilot synth.py + airodump-ng (probe feed) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `twin_wmm_acm` <br>_injects_ | Twin with forged WMM admission control (bandwidth steering) | WiFi | cyan | yellow | wifipilot synth.py (WMM parameter element) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `twin_neighbour_lure` <br>_injects_ | Twin named in a forged 802.11k neighbour report | WiFi | cyan | yellow | wifipilot synth.py (Neighbor Report element) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `twin_quiet_element` <br>_injects_ | Twin with a forged Quiet element (silence on the channel) | WiFi | cyan | yellow | wifipilot synth.py (Quiet element) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `client_assoc_forgery` <br>_injects_ | Client impersonation: association as an existing station | WiFi | green | yellow | wifipilot rawtx.py (authentication + association) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `client_table_flood` <br>_injects_ | Client-table flood with the network's own station addresses | WiFi | yellow | yellow | wifipilot rawtx.py | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `client_sleep_spoof` <br>_injects_ | Power-save spoof (null data in a client's name buffers its traffic) | WiFi | green | yellow | wifipilot rawtx.py (QoS null data) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `client_ps_poll_theft` <br>_injects_ | PS-Poll frame theft (collect a client's buffered traffic) | WiFi | green | yellow | wifipilot rawtx.py (PS-Poll) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `client_tdls_teardown` <br>_injects_ | TDLS teardown between two other stations | WiFi | green | yellow | wifipilot rawtx.py (TDLS action) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `client_sa_query_bypass` <br>_injects_ | SA Query hold (PMF teardown raced by a non-answer) | WiFi | green | yellow | wifipilot rawtx.py (SA Query) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `client_roam_hijack` <br>_injects_ | Roam hijack (forged 802.11r reassociation in a client's name) | WiFi | green | yellow | wifipilot rawtx.py (reassociation request) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `client_eapol_logoff` <br>_injects_ | EAPOL-Logoff in a client's name (session drop with one frame) | WiFi | green | yellow | wifipilot synth.py (EAPOL-Logoff) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `client_fourway_race` <br>_injects_ | 4-way handshake replay (KRACK key reinstallation) | WiFi | green | yellow | wifipilot synth.py (EAPOL builders) + hashcat 22000 for the MIC | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `client_amsdu_inject` <br>_injects_ | A-MSDU injection into a client's connection (FragAttacks) | WiFi | green | yellow | wifipilot synth.py (QoS data with A-MSDU present) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `client_blockack_hijack` <br>_injects_ | Block Ack hijack (forged ADDBA moves a client's window) | WiFi | green | yellow | wifipilot rawtx.py (block-ack action frames) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `client_rate_downgrade` <br>_injects_ | Client rate downgrade (forged 802.11n/ac capability in a client's name) | WiFi | green | yellow | wifipilot rawtx.py (association with reduced capability) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `steer_btm_request` <br>_injects_ | BSS Transition Management request (802.11v steering) | WiFi | green | yellow | wifipilot rawtx.py (BTM request) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `steer_btm_disassoc` <br>_injects_ | BTM request with disassociation imminent (forced handover) | WiFi | cyan | yellow | wifipilot rawtx.py (BTM request, imminent) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `steer_beacon_request` <br>_injects_ | Radio-measurement beacon request (clients survey for us) | WiFi | green | green | wifipilot rawtx.py (RM beacon request) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `steer_channel_load` <br>_injects_ | Radio-measurement channel load (client radio denied service) | WiFi | yellow | yellow | wifipilot rawtx.py (radio-measurement request) + a spoofed AP address | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `steer_spectrum_switch` <br>_injects_ | Channel-switch action frame (spectrum management steering) | WiFi | green | yellow | wifipilot rawtx.py (spectrum management action) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `steer_fils_discovery` <br>_injects_ | FILS discovery frame (pre-association steering) | WiFi | green | green | wifipilot synth.py (FILS discovery) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `steer_wnm_sleep` <br>_injects_ | WNM sleep-mode request (client told to stop listening) | WiFi | green | yellow | wifipilot rawtx.py (WNM action) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `steer_twt_setup` <br>_injects_ | TWT setup abuse (forged target wake time agreement) | WiFi | green | yellow | wifipilot rawtx.py (TWT action) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `steer_power_constraint` <br>_injects_ | Power-constraint steering (clients transmit further from their AP) | WiFi | green | yellow | wifipilot synth.py (Power Constraint element) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `steer_ssid_list` <br>_injects_ | SSID List element (probe behaviour changed by a beacon) | WiFi | green | green | wifipilot synth.py (SSID List element) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `steer_tpc_request` <br>_injects_ | TPC request (transmit-power reporting, location inference) | WiFi | green | green | wifipilot rawtx.py (spectrum management action) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `steer_probe_answer` <br>_injects_ | Probe-response steering (answer first, decide later) | WiFi | cyan | yellow | wifipilot synth.py (probe response) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `session_gateway_impersonation` <br>_injects_ | Gateway impersonation (ARP answers for the router's address) | WiFi | cyan | yellow | wifipilot rawtx.py (ARP reply) + netproto.py (builder) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `session_dns_spoof` <br>_injects_ | DNS answer spoofing through the bridge | WiFi | cyan | yellow | wifipilot netproto.py (DNS builder) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `session_tcp_reset` <br>_injects_ | TCP reset injection (connection teardown through the bridge) | WiFi | cyan | yellow | wifipilot netproto.py (TCP builder) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `session_seq_injection` <br>_injects_ | TCP sequence injection (data into somebody else's stream) | WiFi | cyan | yellow | wifipilot netproto.py (TCP builder) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `session_gtk_rekey` <br>_injects_ | Group-key rekey forgery (GTK handshake from the AP's address) | WiFi | cyan | yellow | wifipilot synth.py (EAPOL builders) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `session_msg1_flood` <br>_injects_ | Message-1 flood (supplicant state machine exhaustion) | WiFi | yellow | yellow | wifipilot synth.py (EAPOL builders) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `session_data_replay` <br>_injects_ | Data-frame replay (replay protection measured from the air) | WiFi | cyan | yellow | wifipilot rawtx.py (data rebuild) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `session_arp_flood` <br>_injects_ | Gratuitous ARP in a client's name (cache poisoning) | WiFi | yellow | yellow | wifipilot rawtx.py (ARP builders) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `portal_clone` <br>_injects_ | Captive-portal clone (the page the network would have served) | WiFi | green | bold green | wifipilot synth.py + netproto.py (HTTP builder) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `portal_wildcard_dns` <br>_injects_ | Wildcard DNS portal (every name resolves to the sign-in page) | WiFi | green | bold green | wifipilot netproto.py (DNS builder) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `portal_wispr_redirect` <br>_injects_ | WISPr redirection (the standard carries the client to our page) | WiFi | green | bold green | wifipilot netproto.py (HTTP builder) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `portal_anqp_spoof` <br>_injects_ | Hotspot 2.0 ANQP spoofing (the venue answers for itself) | WiFi | green | bold green | wifipilot synth.py (ANQP/HS2.0 elements) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `portal_certificate_phish` <br>_injects_ | Portal certificate phishing (self-signed, correct name, wrong issuer) | WiFi | green | bold green | wifipilot synth.py (certificate builder) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `portal_hsts_downgrade` <br>_injects_ | Portal HTTPS downgrade (HSTS-stripped redirect) | WiFi | green | bold green | wifipilot netproto.py (HTTP builder) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `portal_basic_auth` <br>_injects_ | Portal Basic-auth prompt (browser asks, we collect) | WiFi | green | bold green | wifipilot netproto.py (HTTP builder) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `portal_cookie_clone` <br>_injects_ | Portal session-cookie clone (the page loads as the user) | WiFi | green | bold green | wifipilot netproto.py (credential patterns) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `portal_oauth_phish` <br>_injects_ | Portal SSO phishing (the button the user trusts) | WiFi | green | bold green | wifipilot synth.py + netproto.py | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `portal_credential_reuse` <br>_injects_ | Portal credential reuse (harvested credentials against the real gate) | WiFi | green | bold green | wifipilot netproto.py (credential patterns) | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `portal_javascript_inject` <br>_injects_ | Portal JavaScript injection (every keystroke logged in the page) | WiFi | green | bold green | wifipilot synth.py + netproto.py | a second BSSID or a frame from an address that does not own it, which is what a monitor of the channel correlates |
| `it_mimic_dns` | Rogue DNS server (answers in the resolver's name) | IT devices | green | yellow | wifipilot netproto.py (dns_response) + a UDP socket on 53 | two dns services on the segment on port 53, the second one not on the asset list; clients answering an address that is not the server they were told about, and a service that starts answering when the real one is still up |
| `it_mimic_dhcp` | Rogue DHCP server (hands out our own gateway) | IT devices | green | yellow | wifipilot netproto.py (dhcp_offer) + a UDP socket on 67 | two dhcp services on the segment on port 68, the second one not on the asset list; clients answering an address that is not the server they were told about, and a service that starts answering when the real one is still up |
| `it_mimic_ntp` | Rogue NTP server (moves the network's clocks) | IT devices | green | yellow | wifipilot ithijack.ntp_reply + a UDP socket on 123 | two ntp services on the segment on port 123, the second one not on the asset list; clients answering an address that is not the server they were told about, and a service that starts answering when the real one is still up |
| `it_mimic_syslog` | Forged syslog in another device's name | IT devices | green | yellow | wifipilot ithijack.syslog_line + UDP 514 | two syslog services on the segment on port 514, the second one not on the asset list; clients answering an address that is not the server they were told about, and a service that starts answering when the real one is still up |
| `it_mimic_mqtt` | Rogue MQTT broker at the network's own address | IT devices | green | yellow | wifipilot itproto.py (mqtt_connect) + a TCP listener on 1883 | two mqtt services on the segment on port 1883, the second one not on the asset list; clients answering an address that is not the server they were told about, and a service that starts answering when the real one is still up |
| `it_mimic_coap` | Rogue CoAP endpoint (answers the sensor gateway) | IT devices | green | yellow | wifipilot itproto.py (coap_packet) + UDP 5683 | two coap services on the segment on port 5683, the second one not on the asset list; clients answering an address that is not the server they were told about, and a service that starts answering when the real one is still up |
| `it_mimic_modbus` | Rogue Modbus slave (accepts writes meant for the PLC) | IT devices | green | yellow | wifipilot itproto.py (modbus_request) + TCP 502 | two modbus services on the segment on port 502, the second one not on the asset list; clients answering an address that is not the server they were told about, and a service that starts answering when the real one is still up |
| `it_mimic_bacnet` | Rogue BACnet device (sits in the building's device range) | IT devices | green | yellow | wifipilot itproto.py (bacnet_who_is) + UDP 47808 | two bacnet services on the segment on port 47808, the second one not on the asset list; clients answering an address that is not the server they were told about, and a service that starts answering when the real one is still up |
| `it_mimic_rtsp` | Rogue RTSP camera (answers a stream request in the camera's name) | IT devices | green | yellow | wifipilot itproto.py (rtsp_request) + TCP 554 | two rtsp services on the segment on port 554, the second one not on the asset list; clients answering an address that is not the server they were told about, and a service that starts answering when the real one is still up |
| `it_mimic_sip` | Rogue SIP registrar (phones register through it) | IT devices | green | yellow | wifipilot itproto.py (sip_register) + UDP 5060 | two sip services on the segment on port 5060, the second one not on the asset list; clients answering an address that is not the server they were told about, and a service that starts answering when the real one is still up |
| `it_mimic_pjl` | Rogue raw-print service (accepts jobs meant for the printer) | IT devices | green | yellow | wifipilot itproto.py (pjl_command) + TCP 9100 | two pjl services on the segment on port 9100, the second one not on the asset list; clients answering an address that is not the server they were told about, and a service that starts answering when the real one is still up |
| `it_mimic_mdns` | Rogue mDNS responder (owns a device's name in discovery) | IT devices | green | yellow | wifipilot netproto.py (dns_response) + UDP 5353 | two mdns services on the segment on port 5353, the second one not on the asset list; clients answering an address that is not the server they were told about, and a service that starts answering when the real one is still up |
| `it_mimic_ssdp` | Rogue SSDP announcement (points controllers at our service) | IT devices | green | yellow | wifipilot netproto.py (ssdp_notify) + UDP 1900 | two ssdp services on the segment on port 1900, the second one not on the asset list; clients answering an address that is not the server they were told about, and a service that starts answering when the real one is still up |
| `it_mimic_tftp` | Rogue TFTP server (serves firmware to a device that asks) | IT devices | green | yellow | wifipilot ithijack.tftp_data + UDP 69 | two tftp services on the segment on port 69, the second one not on the asset list; clients answering an address that is not the server they were told about, and a service that starts answering when the real one is still up |
| `it_impersonate_onvif` | ONVIF identity theft (answers as another camera) | IT devices | green | yellow | wifipilot itproto.py (onvif_envelope) + an HTTP listener | an identity answer (model, serial, device id or name) from an address that does not match the device inventory: the same onvif identity seen twice, with one of the two having no switch port |
| `it_impersonate_szl` | S7 identity theft (answers as the PLC's own order number) | IT devices | green | yellow | wifipilot itproto.py (s7_connect_request/s7_read_szl) | an identity answer (model, serial, device id or name) from an address that does not match the device inventory: the same s7comm identity seen twice, with one of the two having no switch port |
| `it_impersonate_cip` | CIP identity theft (List Identity answers as the controller) | IT devices | green | yellow | wifipilot itproto.py (cip_list_identity) | an identity answer (model, serial, device id or name) from an address that does not match the device inventory: the same cip identity seen twice, with one of the two having no switch port |
| `it_impersonate_snmp` | SNMP identity theft (answers Get with another device's sysDescr) | IT devices | green | yellow | wifipilot netproto.py + ithijack.snmp_response | an identity answer (model, serial, device id or name) from an address that does not match the device inventory: the same snmp identity seen twice, with one of the two having no switch port |
| `it_impersonate_cast` | Cast identity theft (a look-alike receiver in the TV's name) | IT devices | green | yellow | wifipilot itproto.py (cast_message) + TCP 8009 | an identity answer (model, serial, device id or name) from an address that does not match the device inventory: the same cast identity seen twice, with one of the two having no switch port |
| `it_impersonate_airplay` | AirPlay identity theft (another speaker's name and model) | IT devices | green | yellow | wifipilot itproto.py (airplay_info_request) + ithijack.plist_document | an identity answer (model, serial, device id or name) from an address that does not match the device inventory: the same airplay identity seen twice, with one of the two having no switch port |
| `it_impersonate_kasa` | Kasa identity theft (another plug's alias and MAC) | IT devices | green | yellow | wifipilot itproto.py (kasa_command) + UDP 9999 | an identity answer (model, serial, device id or name) from an address that does not match the device inventory: the same kasa identity seen twice, with one of the two having no switch port |
| `it_impersonate_miio` | MiIO identity theft (answers as another vacuum's device id) | IT devices | green | yellow | wifipilot itproto.py (miio_hello) + UDP 54321 | an identity answer (model, serial, device id or name) from an address that does not match the device inventory: the same miio identity seen twice, with one of the two having no switch port |
| `it_impersonate_opcua` | OPC-UA identity theft (a look-alike endpoint for the PLC) | IT devices | green | yellow | wifipilot itproto.py (opcua_hello) + TCP 4840 | an identity answer (model, serial, device id or name) from an address that does not match the device inventory: the same opcua identity seen twice, with one of the two having no switch port |
| `it_impersonate_ipp` | IPP identity theft (another printer's name and model) | IT devices | green | yellow | wifipilot itproto.py (ipp_get_printer_attributes) + TCP 631 | an identity answer (model, serial, device id or name) from an address that does not match the device inventory: the same ipp identity seen twice, with one of the two having no switch port |
| `it_impersonate_stun` | STUN answer forgery (tells a client it is behind our address) | IT devices | green | yellow | wifipilot ithijack.stun_binding_response + UDP 3478 | an identity answer (model, serial, device id or name) from an address that does not match the device inventory: the same stun identity seen twice, with one of the two having no switch port |
| `it_impersonate_docker` | Docker API impersonation (answers as the host's daemon) | IT devices | green | yellow | wifipilot itproto.py (docker_version) + an HTTP listener on 2375 | an identity answer (model, serial, device id or name) from an address that does not match the device inventory: the same docker identity seen twice, with one of the two having no switch port |
| `it_poison_arp_gateway` | ARP gateway poisoning (the segment routes through us) | IT devices | green | yellow | wifipilot ithijack.ether + netproto.py (parse_arp) | a arp answer on port 80 whose address does not match the real device, and a client-side cache entry (ARP, DNS, NBNS, SSDP, DHCP) that outlives the frame: the same name resolving differently on two hosts |
| `it_poison_dns` | DNS cache poisoning (a known name points at us) | IT devices | green | yellow | wifipilot netproto.py (dns_response) + UDP 53 | a dns answer on port 53 whose address does not match the real device, and a client-side cache entry (ARP, DNS, NBNS, SSDP, DHCP) that outlives the frame: the same name resolving differently on two hosts |
| `it_poison_netbios` | NBNS name poisoning (a NetBIOS name resolves to us) | IT devices | green | yellow | wifipilot ithijack.netbios_positive_response + UDP 137 | a netbios answer on port 137 whose address does not match the real device, and a client-side cache entry (ARP, DNS, NBNS, SSDP, DHCP) that outlives the frame: the same name resolving differently on two hosts |
| `it_poison_mdns` | mDNS name theft (another device's discovery name points at us) | IT devices | green | yellow | wifipilot netproto.py (dns_response) + UDP 5353 | a mdns answer on port 5353 whose address does not match the real device, and a client-side cache entry (ARP, DNS, NBNS, SSDP, DHCP) that outlives the frame: the same name resolving differently on two hosts |
| `it_poison_ssdp` | SSDP response spoofing (the control point caches our URL) | IT devices | green | yellow | wifipilot netproto.py (ssdp_notify) + UDP 1900 | a ssdp answer on port 1900 whose address does not match the real device, and a client-side cache entry (ARP, DNS, NBNS, SSDP, DHCP) that outlives the frame: the same name resolving differently on two hosts |
| `it_poison_dhcp_option` | DHCP option poisoning (option 6 points the client at us) | IT devices | green | yellow | wifipilot netproto.py (dhcp_offer) + UDP 67 | a dhcp answer on port 68 whose address does not match the real device, and a client-side cache entry (ARP, DNS, NBNS, SSDP, DHCP) that outlives the frame: the same name resolving differently on two hosts |
| `it_poison_snmp_trap` | SNMP trap forgery (the monitoring server acts on a lie) | IT devices | green | yellow | wifipilot ithijack.snmp_trap + UDP 162 | a snmp answer on port 162 whose address does not match the real device, and a client-side cache entry (ARP, DNS, NBNS, SSDP, DHCP) that outlives the frame: the same name resolving differently on two hosts |
| `it_poison_bacnet_whois` | BACnet I-Am forgery (a device appears in the BMS device table) | IT devices | green | yellow | wifipilot itproto.py (bacnet_who_is) + a forged I-Am | a bacnet answer on port 47808 whose address does not match the real device, and a client-side cache entry (ARP, DNS, NBNS, SSDP, DHCP) that outlives the frame: the same name resolving differently on two hosts |
| `it_poison_ldap_referral` | LDAP referral injection (the client follows our referral) | IT devices | green | yellow | wifipilot ithijack.ldap_referral + TCP 389 | a ldap answer on port 389 whose address does not match the real device, and a client-side cache entry (ARP, DNS, NBNS, SSDP, DHCP) that outlives the frame: the same name resolving differently on two hosts |
| `it_poison_smb_negotiate` | SMB negotiate spoofing (a downgrade in the server's name) | IT devices | green | yellow | wifipilot ithijack.smb2_negotiate_response + TCP 445 | a smb answer on port 445 whose address does not match the real device, and a client-side cache entry (ARP, DNS, NBNS, SSDP, DHCP) that outlives the frame: the same name resolving differently on two hosts |
| `it_poison_rdp_negotiation` | RDP negotiation spoofing (the client connects to us instead) | IT devices | green | yellow | wifipilot ithijack.rdp_negotiation_response + TCP 3389 | a rdp answer on port 3389 whose address does not match the real device, and a client-side cache entry (ARP, DNS, NBNS, SSDP, DHCP) that outlives the frame: the same name resolving differently on two hosts |
| `it_poison_telnet_banner` | Telnet banner spoofing (an operator session lands on us) | IT devices | green | yellow | wifipilot itproto.py (telnet_banner) + TCP 23 | a telnet answer on port 23 whose address does not match the real device, and a client-side cache entry (ARP, DNS, NBNS, SSDP, DHCP) that outlives the frame: the same name resolving differently on two hosts |
| `it_mimic_ftp` | Rogue FTP server (answers in the file server's name) | IT devices | green | yellow | wifipilot itproto.py (ftp_login) + TCP 21 | two ftp services on the segment on port 21, the second one not on the asset list; clients answering an address that is not the server they were told about, and a service that starts answering when the real one is still up |
| `it_mimic_smtp` | Rogue SMTP server (accepts mail meant for the relay) | IT devices | green | yellow | wifipilot itproto.py (smtp_ehlo) + TCP 25 | two smtp services on the segment on port 25, the second one not on the asset list; clients answering an address that is not the server they were told about, and a service that starts answering when the real one is still up |
| `it_mimic_imap` | Rogue IMAP server (mail login lands on us) | IT devices | green | yellow | wifipilot itproto.py (imap_login) + TCP 993 | two imap services on the segment on port 993, the second one not on the asset list; clients answering an address that is not the server they were told about, and a service that starts answering when the real one is still up |
| `it_mimic_rsync` | Rogue rsync daemon (the client's backup syncs to us) | IT devices | green | yellow | wifipilot itproto.py (rsync_hello) + TCP 873 | two rsync services on the segment on port 873, the second one not on the asset list; clients answering an address that is not the server they were told about, and a service that starts answering when the real one is still up |
| `it_poison_elastic_shard` | Elasticsearch node forgery (our node joins the cluster view) | IT devices | green | yellow | wifipilot ithijack.http_answer + TCP 9200 | a elastic answer on port 9200 whose address does not match the real device, and a client-side cache entry (ARP, DNS, NBNS, SSDP, DHCP) that outlives the frame: the same name resolving differently on two hosts |
| `it_poison_kubelet_response` | kubelet response forgery (a node that is not there reports healthy) | IT devices | green | yellow | wifipilot ithijack.http_answer + TCP 10250 | a kubernetes answer on port 10250 whose address does not match the real device, and a client-side cache entry (ARP, DNS, NBNS, SSDP, DHCP) that outlives the frame: the same name resolving differently on two hosts |
| `it_mimic_dns_reverse` | Rogue reverse-DNS server (PTR answers in the resolver's place) | IT devices | green | yellow | wifipilot itproto.py (dns_query) + UDP 53 | two dns services on the segment on port 53, the second one not on the asset list; clients answering an address that is not the server they were told about, and a service that starts answering when the real one is still up |
| `it_mimic_ssh` | Rogue SSH server (banner and algorithms in the server's name) | IT devices | green | yellow | wifipilot itproto.py (ssh_kexinit/parse_ssh_algorithms) + TCP 22 | two ssh services on the segment on port 22, the second one not on the asset list; clients answering an address that is not the server they were told about, and a service that starts answering when the real one is still up |
| `it_mimic_rdp` | Rogue RDP endpoint (negotiation answer in the server's name) | IT devices | green | yellow | wifipilot attacks/ithijack.rdp_negotiation_response + TCP 3389 | two rdp services on the segment on port 3389, the second one not on the asset list; clients answering an address that is not the server they were told about, and a service that starts answering when the real one is still up |
| `it_mimic_coap_write` | Rogue CoAP resource (a write answered from our resource tree) | IT devices | green | yellow | wifipilot itproto.py (coap_packet/parse_coap) + UDP 5683 | two coap services on the segment on port 5683, the second one not on the asset list; clients answering an address that is not the server they were told about, and a service that starts answering when the real one is still up |
| `it_impersonate_ssh_banner` | SSH banner impersonation (the host's own ss hd version, one keystroke off) | IT devices | green | yellow | wifipilot itproto.py (ssh_kexinit/parse_ssh_algorithms) | an identity answer (model, serial, device id or name) from an address that does not match the device inventory: the same ssh identity seen twice, with one of the two having no switch port |
| `it_impersonate_sip_pbx` | PBX impersonation (200 OK to a registration we never authorised) | IT devices | green | yellow | wifipilot itproto.py (sip_register/parse_sip) + UDP 5060 | an identity answer (model, serial, device id or name) from an address that does not match the device inventory: the same sip identity seen twice, with one of the two having no switch port |
| `it_impersonate_snmp_engine` | SNMP engine impersonation (sysDescr and engine id of another device) | IT devices | green | yellow | wifipilot attacks/ithijack.py (_ber, snmp_response) + UDP 161 | an identity answer (model, serial, device id or name) from an address that does not match the device inventory: the same snmp identity seen twice, with one of the two having no switch port |
| `it_poison_mdns_name` | mDNS name theft (a conflicting announcement for a device's name) | IT devices | green | yellow | wifipilot itproto.py (dns_query/parse_mdns) + UDP 5353 | a mdns answer on port 5353 whose address does not match the real device, and a client-side cache entry (ARP, DNS, NBNS, SSDP, DHCP) that outlives the frame: the same name resolving differently on two hosts |
| `it_poison_ssdp_location` | SSDP announcement forgery (the control URL points at us) | IT devices | green | yellow | wifipilot itproto.py (ssdp_notify/parse_ssdp) + UDP 1900 | a ssdp answer on port 1900 whose address does not match the real device, and a client-side cache entry (ARP, DNS, NBNS, SSDP, DHCP) that outlives the frame: the same name resolving differently on two hosts |
| `forged_dhcp_release` <br>_injects_ | Forged DHCP RELEASE / DECLINE | WiFi | cyan | yellow | wifipilot netproto.py (RELEASE and DECLINE) | RELEASE and DECLINE messages for addresses whose owner did not send them: a DHCP server log shows a client losing a lease it was using |
| `dhcp_nak_injection` <br>_injects_ | Forged DHCP NAK injection | WiFi | cyan | yellow | wifipilot netproto.py (NAK with options) | NAK messages from a source that is not the server: a snooping switch drops them when it is configured |
| `dhcp_option_injection` <br>_injects_ | Rogue DHCP option injection (route, DNS, WPAD) | WiFi | cyan | yellow | wifipilot netproto.py (options 3, 6, 121, 249, 252) | a second DHCP server answering with its own router and resolver options: two OFFERs for one DISCOVER |
| `tcp_reset_injection` <br>_injects_ | TCP reset injection | WiFi | cyan | yellow | wifipilot netstack.py (RST with a guessed sequence) | RST segments on connections whose endpoints did not send them, which ends sessions and is obvious in a packet capture on either endpoint |
| `icmp_redirect_injection` <br>_injects_ | ICMP redirect injection | WiFi | cyan | yellow | wifipilot netstack.py (ICMP type 5) | ICMP redirects from the gateway naming a different next hop: a host that logs them shows the redirection |
| `icmp_unreachable_injection` <br>_injects_ | ICMP unreachable injection | WiFi | cyan | yellow | wifipilot netstack.py (ICMP type 3) | ICMP unreachable messages quoting traffic the victim sent — indistinguishable from a router withdrawing a route unless the source is checked |
| `rogue_ra` <br>_injects_ | Rogue IPv6 router advertisement | WiFi | cyan | yellow | wifipilot netstack.py (ICMPv6 RA with RDNSS) | router advertisements from an address that is not the site's router: RA Guard on the switches drops them, and without it hosts accept them |
| `ns_na_spoof` <br>_injects_ | IPv6 neighbour solicitation / advertisement spoofing | WiFi | cyan | yellow | wifipilot netstack.py (NS and NA with override) | neighbour advertisements for the gateway claiming a new MAC: ND inspection drops them, and the gateway's own traffic counters stop matching |
| `llmnr_poisoning` <br>_injects_ | LLMNR poisoning | WiFi | cyan | bold green | wifipilot netstack.py (LLMNR responses) | LLMNR answers from a host that is not the owner of the name; the victims' next connection goes to the attacker |
| `nbns_poisoning` <br>_injects_ | NetBIOS name service poisoning | WiFi | cyan | bold green | wifipilot netstack.py (NBNS responses) | NetBIOS name answers from an unexpected host, followed by SMB sessions to it |
| `mdns_poisoning` <br>_injects_ | mDNS response poisoning | WiFi | cyan | yellow | wifipilot netstack.py (mDNS responses) | mDNS answers for names that belong to other devices on the segment |
| `stp_root_takeover` <br>_injects_ | Spanning tree root bridge takeover | WiFi | yellow | red | wifipilot netstack.py (802.1D configuration BPDUs) | configuration BPDUs with a superior bridge ID arriving on an access port: BPDU Guard is the control, and its absence is a log entry on the switch |
| `lldp_spoof` <br>_injects_ | LLDP neighbour spoofing | WiFi | green | green | wifipilot netstack.py (LLDP TLVs) | LLDP frames describing a device that is not in the inventory: the switch's neighbour table shows a new switch or router |
| `cdp_spoof` <br>_injects_ | CDP neighbour spoofing | WiFi | green | green | wifipilot netstack.py (CDP TLVs) | CDP frames describing a Cisco device that was never installed: the switch's neighbour inventory changes |
| `vlan_double_tag_hop` <br>_injects_ | VLAN double tagging (hop) | WiFi | cyan | yellow | wifipilot netstack.py (802.1Q tags) | frames leaving an access port with the outer tag stripped and an inner tag intact: the only place it shows is the receiving VLAN |
| `bt_bias` <br>_injects_ | BIAS impersonation probe (CVE-2020-10135) | Bluetooth | cyan | bold green | wifipilot bt.py (Authentication Requested, key replies, pairing events) | a link-key request answered with a negative reply and an immediate re-pairing on the same handle: the peer's own controller log shows it, and so does the second pairing |
| `bt_knob` <br>_injects_ | KNOB key-entropy probe (CVE-2019-9506) | Bluetooth | green | bold green | wifipilot bt.py (feature pages + Encryption Change key size) | a fresh key negotiated on an established link: the peer's controller log shows the re-key, and the KNOB tool has to encrypt the link to measure it |
| `bt_bluebugging` <br>_injects_ | BlueBugging (AT commands over RFCOMM) | Bluetooth | cyan | bold green | wifipilot bt.py (RFCOMM, AF_BLUETOOTH BTPROTO_RFCOMM) | an RFCOMM channel opened to a hands-free profile by a device the phone does not know: the phone logs the AT session, and the user may see a key press they did not make |
| `bt_blesa` <br>_injects_ | BLESA pre-authentication data injection | Bluetooth | green | bold green | wifipilot bt.py (LE connection + ATT before pairing) | an ATT exchange on a link that has not paired: the peripheral's own logs show the unauthenticated request, and a client sees a session it did not start |
| `bt_bluesnarf` <br>_injects_ | BlueSnarfing (OBEX file pull) | Bluetooth | cyan | bold green | wifipilot bt.py (OBEX over RFCOMM) | an OBEX session from a device the phone does not know: the phone's own Bluetooth log shows the connection to the object exchange channel |
| `bt_hid_injection` <br>_injects_ | Bluetooth keystroke injection (HID spoofing) | Bluetooth | cyan | bold green | wifipilot bt.py (HID over GATT: report map + boot reports) | a new HID device in the host's Bluetooth settings and keystrokes nobody typed: the host's own log shows the connection and the input reports |
| `airgeddon_portal` <br>_injects_ | Airgeddon captive portal phishing (evil twin + portal) | WiFi | yellow | bold green | airgeddon (evil twin menu / CLI plugin) or wifipilot's portal server | a second access point with the target's name plus a portal page and a DNS blackhole: the twin shows up in any site survey, and the portal's DNS answers are visible to the client |

### Discovery and fingerprinting (no radio either) — 119

| attack | answers | edition | noise | impact | tool | defender sees |
| --- | --- | --- | --- | --- | --- | --- |
| `ble_hfp_identity_spoof` <br>_injects_ | Bluetooth HFP identity read (model and serial over AT) | Bluetooth | green | green | wifipilot blesim.py (AT +CGMI/+CGMM/+CGSN) | An AT identity request from a device that is not the user's: the unit logs the channel, and the manufacturer's fleet system sees an unpaired client. |
| `ble_l2cap_psm_sweep` <br>_injects_ | Bluetooth PSM sweep (which profiles the device really offers) | Bluetooth | green | green | wifipilot bt.py (L2CAP signalling) | A burst of connection requests from one address: the device's controller logs the signalling exchange, and the profile services log the connections. |
| `ble_sdp_browse_takeover` <br>_injects_ | Bluetooth SDP takeover (read every service record) | Bluetooth | green | green | wifipilot bt.py (SDP search + attribute decode) | A service search from an address that is not the pairing device: the SDP server logs the browse, and it is indistinguishable from a legitimate one — which is the point. |
| `ble_gatt_blob_dump` <br>_injects_ | BLE GATT blob dump (read a value in parts) | Bluetooth | green | bold green | wifipilot blesim.py (Read Blob) | Repeated reads of one handle with rising offsets: an ATT log shows one client walking the value, which is what a legitimate client does too — the difference is that this one is not the paired app. |
| `ble_gatt_handle_enum` <br>_injects_ | BLE handle enumeration (Find Information across the table) | Bluetooth | green | green | wifipilot blesim.py (Find Information + ATT error decoding) | A client walking the handle range in blocks: the ATT log shows the Find Information requests, and the device answers all of them because the operation is not restricted. |
| `ble_mtu_negotiation_abuse` <br>_injects_ | BLE MTU negotiation abuse (what the peer will admit to) | Bluetooth | green | green | wifipilot blesim.py (Exchange MTU) | Two MTU exchanges on one connection: legitimate clients negotiate once, and a second exchange is either a re-connection or a probe. |
| `ble_att_handle_brute` <br>_injects_ | BLE handle brute force (read attributes by guessing numbers) | Bluetooth | cyan | green | wifipilot blesim.py (blind ATT reads) | Reads of handles that no discovery asked about: an ATT log shows a client reading between the services, which no correct client does. |
| `ble_service_table_dump` <br>_injects_ | BLE service table dump (Read By Group Type) | Bluetooth | green | green | wifipilot blesim.py (Read By Group Type) | A primary-service discovery: every legitimate client does this once, which is why it is also the step that is never anomalous on its own. |
| `ble_gatt_value_dump` <br>_injects_ | BLE value dump (read the whole table for secrets) | Bluetooth | green | bold green | wifipilot blesim.py (ATT reads across the table) | A client reading the whole table: the ATT log carries one read per characteristic, which is what a map application does and what a data extraction looks like. |
| `ble_rpa_follow` <br>_injects_ | BLE address following (link a rotating address back to a device) | Bluetooth | green | green | wifipilot bt.py (address classification + resolution) + blesim.py | None on air: the addresses were broadcast in the open, and the linking is done from a list somebody else already recorded. |
| `ble_feature_page_spoof` <br>_injects_ | BLE feature read (feature pages, and what the peer claims) | Bluetooth | green | green | wifipilot bt.py (LL_FEATURE_REQ + FEATURE_BITS) + blesim.py | A feature request from a device that is not the pairing host: it is a normal procedure, so it is invisible — which is why an inventory of features is worth reading early. |
| `ble_smp_command_probe` <br>_injects_ | BLE SMP command probe (which security-manager commands exist) | Bluetooth | cyan | green | wifipilot bt.py (SMP commands) + blesim.py | Every SMP command in one session: the device's security manager log carries the sequence, and no pairing ever starts from it. |
| `it_survey_mdns_services` | mDNS service survey (every service the segment advertises) | IT devices | green | yellow | wifipilot itproto.py (dns_query/parse_mdns) + UDP 5353 | one host asking every mdns service on port 5353 the same inventory question, in sequence, from a single address: the answers name firmware, models and endpoints that no asset register has |
| `it_survey_ssdp_description` | UPnP description survey (device type, firmware and control URL) | IT devices | green | yellow | wifipilot itproto.py (ssdp_msearch/parse_ssdp) + UDP 1900 | one host asking every ssdp service on port 1900 the same inventory question, in sequence, from a single address: the answers name firmware, models and endpoints that no asset register has |
| `it_survey_cwmp_parameters` | TR-069 parameter survey (firmware, connection status, uptime) | IT devices | green | yellow | wifipilot itproto.py (cwmp_get_parameter_values/parse_cwmp) + TCP 7547 | one host asking every cwmp service on port 7547 the same inventory question, in sequence, from a single address: the answers name firmware, models and endpoints that no asset register has |
| `it_survey_rtsp_describe` | RTSP DESCRIBE survey (codecs, resolution and session limits) | IT devices | green | yellow | wifipilot itproto.py (rtsp_request/parse_rtsp) + TCP 554 | one host asking every rtsp service on port 554 the same inventory question, in sequence, from a single address: the answers name firmware, models and endpoints that no asset register has |
| `it_survey_opcua_endpoints` | OPC-UA endpoint survey (endpoint URL, message limits, security) | IT devices | green | yellow | wifipilot itproto.py (opcua_hello/parse_opcua) + TCP 4840 | one host asking every opcua service on port 4840 the same inventory question, in sequence, from a single address: the answers name firmware, models and endpoints that no asset register has |
| `it_survey_memcached_stats` | memcached stats survey (uptime, items, current connections, key list) | IT devices | green | yellow | wifipilot itproto.py (memcached_command/parse_resp) + TCP 11211 | one host asking every memcached service on port 11211 the same inventory question, in sequence, from a single address: the answers name firmware, models and endpoints that no asset register has |
| `it_survey_mysql_handshake` | MySQL greeting survey (version, thread id, salt, auth plugin) | IT devices | green | yellow | wifipilot itproto.py (mysql_handshake_parse) + TCP 3306 | one host asking every mysql service on port 3306 the same inventory question, in sequence, from a single address: the answers name firmware, models and endpoints that no asset register has |
| `it_survey_spooler_banner` | Spooler banner survey (PJL identity and page count) | IT devices | green | yellow | wifipilot itproto.py (pjl_command/parse_pjl) + TCP 9100 | one host asking every pjl service on port 9100 the same inventory question, in sequence, from a single address: the answers name firmware, models and endpoints that no asset register has |
| `it_http_discover` | Web management interface: management page answered | IT devices | green | green | wifipilot itproto (HTTP/1.1 request builder) | Web management interface traffic from an unexpected host to port 80: management page answered — a service log or an IDS rule on the protocol sees it |
| `it_http_banner` | Web management interface: server header | IT devices | green | green | wifipilot itproto (HTTP/1.1 request builder) | Web management interface traffic from an unexpected host to port 80: server header — a service log or an IDS rule on the protocol sees it |
| `it_http_version_audit` | Web management interface: web management interface version audit | IT devices | green | green | wifipilot itproto (HTTP/1.1 request builder) | A version request to http on port 80 from an unexpected host. |
| `it_http_json_discover` | JSON/REST API: API version endpoint | IT devices | green | green | wifipilot itproto (HTTP JSON request builder) | JSON/REST API traffic from an unexpected host to port 2375: api version endpoint — a service log or an IDS rule on the protocol sees it |
| `it_http_json_version_audit` | JSON/REST API: Kubernetes API version | IT devices | green | green | wifipilot itproto (HTTP JSON request builder) | JSON/REST API traffic from an unexpected host to port 2375: kubernetes api version — a service log or an IDS rule on the protocol sees it |
| `it_http_json_jenkins_audit` | JSON/REST API: CI server information | IT devices | green | green | wifipilot itproto (HTTP JSON request builder) | JSON/REST API traffic from an unexpected host to port 2375: ci server information — a service log or an IDS rule on the protocol sees it |
| `it_mqtt_discover` | MQTT broker: broker answered CONNECT | IT devices | green | green | wifipilot itproto (MQTT 3.1.1/5.0 CONNECT, PUBLISH, SUBSCRIBE) | MQTT broker traffic from an unexpected host to port 1883: broker answered connect — a service log or an IDS rule on the protocol sees it |
| `it_mqtt_version_audit` | MQTT broker: mqtt broker version audit | IT devices | green | green | wifipilot itproto (MQTT 3.1.1/5.0 CONNECT, PUBLISH, SUBSCRIBE) | A version request to mqtt on port 1883 from an unexpected host. |
| `it_coap_discover` | CoAP endpoint: resource discovery | IT devices | green | green | wifipilot itproto (CoAP RFC 7252 GET/POST with options) | CoAP endpoint traffic from an unexpected host to port 5683: resource discovery — a service log or an IDS rule on the protocol sees it |
| `it_coap_version_audit` | CoAP endpoint: coap endpoint version audit | IT devices | green | green | wifipilot itproto (CoAP RFC 7252 GET/POST with options) | A version request to coap on port 5683 from an unexpected host. |
| `it_modbus_discover` | Modbus/TCP controller: device identification | IT devices | green | green | wifipilot itproto (Modbus TCP MBAP, function codes 1-43) | Modbus/TCP controller traffic from an unexpected host to port 502: device identification — a service log or an IDS rule on the protocol sees it |
| `it_modbus_version_audit` | Modbus/TCP controller: modbus/tcp controller version audit | IT devices | green | green | wifipilot itproto (Modbus TCP MBAP, function codes 1-43) | A version request to modbus on port 502 from an unexpected host. |
| `it_bacnet_discover` | BACnet building controller: Who-Is sweep | IT devices | green | green | wifipilot itproto (BACnet/IP BVLC, Who-Is, Read-Property) | BACnet building controller traffic from an unexpected host to port 47808: who-is sweep — a service log or an IDS rule on the protocol sees it |
| `it_bacnet_version_audit` | BACnet building controller: bacnet building controller version audit | IT devices | green | green | wifipilot itproto (BACnet/IP BVLC, Who-Is, Read-Property) | A version request to bacnet on port 47808 from an unexpected host. |
| `it_rtsp_discover` | RTSP video stream: OPTIONS answered | IT devices | green | green | wifipilot itproto (RTSP OPTIONS/DESCRIBE/PLAY, SDP) | RTSP video stream traffic from an unexpected host to port 554: options answered — a service log or an IDS rule on the protocol sees it |
| `it_rtsp_version_audit` | RTSP video stream: rtsp video stream version audit | IT devices | green | green | wifipilot itproto (RTSP OPTIONS/DESCRIBE/PLAY, SDP) | A version request to rtsp on port 554 from an unexpected host. |
| `it_onvif_discover` | ONVIF device service: GetDeviceInformation | IT devices | green | green | wifipilot itproto (ONVIF SOAP GetDeviceInformation/GetStreamUri) | ONVIF device service traffic from an unexpected host to port 80: getdeviceinformation — a service log or an IDS rule on the protocol sees it |
| `it_onvif_version_audit` | ONVIF device service: onvif device service version audit | IT devices | green | green | wifipilot itproto (ONVIF SOAP GetDeviceInformation/GetStreamUri) | A version request to onvif on port 80 from an unexpected host. |
| `it_ipp_discover` | IPP print service: Get-Printer-Attributes | IT devices | green | green | wifipilot itproto (IPP RFC 8010/8011) | IPP print service traffic from an unexpected host to port 631: get-printer-attributes — a service log or an IDS rule on the protocol sees it |
| `it_ipp_version_audit` | IPP print service: ipp print service version audit | IT devices | green | green | wifipilot itproto (IPP RFC 8010/8011) | A version request to ipp on port 631 from an unexpected host. |
| `it_pjl_discover` | PJL printer command port: INFO ID | IT devices | green | green | wifipilot itproto (PJL @PJL INFO/USTATUS) | PJL printer command port traffic from an unexpected host to port 9100: info id — a service log or an IDS rule on the protocol sees it |
| `it_pjl_version_audit` | PJL printer command port: pjl printer command port version audit | IT devices | green | green | wifipilot itproto (PJL @PJL INFO/USTATUS) | A version request to pjl on port 9100 from an unexpected host. |
| `it_telnet_banner` | Telnet management: banner and login prompt | IT devices | green | green | wifipilot itproto (telnet negotiation and banner) | Telnet management traffic from an unexpected host to port 23: banner and login prompt — a service log or an IDS rule on the protocol sees it |
| `it_telnet_version_audit` | Telnet management: telnet management version audit | IT devices | green | green | wifipilot itproto (telnet negotiation and banner) | A version request to telnet on port 23 from an unexpected host. |
| `it_sip_discover` | SIP telephony: OPTIONS | IT devices | green | green | wifipilot itproto (SIP OPTIONS/REGISTER, digest challenge parsing) | SIP telephony traffic from an unexpected host to port 5060: options — a service log or an IDS rule on the protocol sees it |
| `it_sip_version_audit` | SIP telephony: sip telephony version audit | IT devices | green | green | wifipilot itproto (SIP OPTIONS/REGISTER, digest challenge parsing) | A version request to sip on port 5060 from an unexpected host. |
| `it_cwmp_discover` | TR-069 / CWMP management: CWMP Inform | IT devices | green | green | wifipilot itproto (CWMP Inform and GetParameterValues) | TR-069 / CWMP management traffic from an unexpected host to port 7547: cwmp inform — a service log or an IDS rule on the protocol sees it |
| `it_cwmp_version_audit` | TR-069 / CWMP management: tr-069 / cwmp management version audit | IT devices | green | green | wifipilot itproto (CWMP Inform and GetParameterValues) | A version request to cwmp on port 7547 from an unexpected host. |
| `it_smb_discover` | SMB file sharing: SMB2 negotiate | IT devices | green | green | wifipilot itproto (SMB2 NEGOTIATE, NetBIOS) | SMB file sharing traffic from an unexpected host to port 445: smb2 negotiate — a service log or an IDS rule on the protocol sees it |
| `it_smb_version_audit` | SMB file sharing: smb file sharing version audit | IT devices | green | green | wifipilot itproto (SMB2 NEGOTIATE, NetBIOS) | A version request to smb on port 445 from an unexpected host. |
| `it_ldap_discover` | LDAP directory: rootDSE read | IT devices | green | green | wifipilot itproto (LDAP bindRequest and rootDSE search) | LDAP directory traffic from an unexpected host to port 389: rootdse read — a service log or an IDS rule on the protocol sees it |
| `it_ldap_version_audit` | LDAP directory: ldap directory version audit | IT devices | green | green | wifipilot itproto (LDAP bindRequest and rootDSE search) | A version request to ldap on port 389 from an unexpected host. |
| `it_redis_discover` | Redis data store: PING | IT devices | green | green | wifipilot itproto (Redis RESP) | Redis data store traffic from an unexpected host to port 6379: ping — a service log or an IDS rule on the protocol sees it |
| `it_redis_version_audit` | Redis data store: redis data store version audit | IT devices | green | green | wifipilot itproto (Redis RESP) | A version request to redis on port 6379 from an unexpected host. |
| `it_memcached_discover` | Memcached: stats | IT devices | green | green | wifipilot itproto (memcached text protocol) | Memcached traffic from an unexpected host to port 11211: stats — a service log or an IDS rule on the protocol sees it |
| `it_memcached_version_audit` | Memcached: memcached version audit | IT devices | green | green | wifipilot itproto (memcached text protocol) | A version request to memcached on port 11211 from an unexpected host. |
| `it_mongo_discover` | MongoDB: hello | IT devices | green | green | wifipilot itproto (MongoDB OP_MSG hello) | MongoDB traffic from an unexpected host to port 27017: hello — a service log or an IDS rule on the protocol sees it |
| `it_mongo_version_audit` | MongoDB: mongodb version audit | IT devices | green | green | wifipilot itproto (MongoDB OP_MSG hello) | A version request to mongo on port 27017 from an unexpected host. |
| `it_kasa_discover` | TP-Link Kasa / smart home: systeminfo | IT devices | green | green | wifipilot itproto (Kasa autokey XOR framing) | TP-Link Kasa / smart home traffic from an unexpected host to port 9999: systeminfo — a service log or an IDS rule on the protocol sees it |
| `it_kasa_version_audit` | TP-Link Kasa / smart home: tp-link kasa / smart home version audit | IT devices | green | green | wifipilot itproto (Kasa autokey XOR framing) | A version request to kasa on port 9999 from an unexpected host. |
| `it_cast_discover` | Cast / Chromecast service: connection open | IT devices | green | green | wifipilot itproto (CASTV2 message framing) | Cast / Chromecast service traffic from an unexpected host to port 8009: connection open — a service log or an IDS rule on the protocol sees it |
| `it_cast_version_audit` | Cast / Chromecast service: cast / chromecast service version audit | IT devices | green | green | wifipilot itproto (CASTV2 message framing) | A version request to cast on port 8009 from an unexpected host. |
| `it_airplay_discover` | AirPlay / Apple media service: media service info | IT devices | green | green | wifipilot itproto (AirPlay /info and text plist) | AirPlay / Apple media service traffic from an unexpected host to port 7000: media service info — a service log or an IDS rule on the protocol sees it |
| `it_airplay_version_audit` | AirPlay / Apple media service: airplay / apple media service version audit | IT devices | green | green | wifipilot itproto (AirPlay /info and text plist) | A version request to airplay on port 7000 from an unexpected host. |
| `it_adb_discover` | Android debug bridge: CNXN | IT devices | green | green | wifipilot itproto (ADB CNXN/AUTH framing) | Android debug bridge traffic from an unexpected host to port 5555: cnxn — a service log or an IDS rule on the protocol sees it |
| `it_adb_version_audit` | Android debug bridge: android debug bridge version audit | IT devices | green | green | wifipilot itproto (ADB CNXN/AUTH framing) | A version request to adb on port 5555 from an unexpected host. |
| `it_vnc_discover` | VNC remote desktop: RFB version | IT devices | green | green | wifipilot itproto (RFB version and security types) | VNC remote desktop traffic from an unexpected host to port 5900: rfb version — a service log or an IDS rule on the protocol sees it |
| `it_vnc_version_audit` | VNC remote desktop: vnc remote desktop version audit | IT devices | green | green | wifipilot itproto (RFB version and security types) | A version request to vnc on port 5900 from an unexpected host. |
| `it_pjlink_discover` | PJLink projector control: POWR query | IT devices | green | green | wifipilot itproto (PJLink %1 commands) | PJLink projector control traffic from an unexpected host to port 4352: powr query — a service log or an IDS rule on the protocol sees it |
| `it_pjlink_version_audit` | PJLink projector control: pjlink projector control version audit | IT devices | green | green | wifipilot itproto (PJLink %1 commands) | A version request to pjlink on port 4352 from an unexpected host. |
| `it_dicom_discover` | DICOM medical imaging: association request | IT devices | green | green | wifipilot itproto (DICOM A-ASSOCIATE and C-ECHO) | DICOM medical imaging traffic from an unexpected host to port 104: association request — a service log or an IDS rule on the protocol sees it |
| `it_dicom_version_audit` | DICOM medical imaging: dicom medical imaging version audit | IT devices | green | green | wifipilot itproto (DICOM A-ASSOCIATE and C-ECHO) | A version request to dicom on port 104 from an unexpected host. |
| `it_s7comm_discover` | Siemens S7 communication: COTP connect | IT devices | green | green | wifipilot itproto (ISO-TSAP COTP and S7comm SZL) | Siemens S7 communication traffic from an unexpected host to port 102: cotp connect — a service log or an IDS rule on the protocol sees it |
| `it_s7comm_version_audit` | Siemens S7 communication: siemens s7 communication version audit | IT devices | green | green | wifipilot itproto (ISO-TSAP COTP and S7comm SZL) | A version request to s7comm on port 102 from an unexpected host. |
| `it_cip_discover` | EtherNet/IP and CIP: List-Identity | IT devices | green | green | wifipilot itproto (EtherNet/IP encapsulation and List-Identity) | EtherNet/IP and CIP traffic from an unexpected host to port 44818: list-identity — a service log or an IDS rule on the protocol sees it |
| `it_cip_version_audit` | EtherNet/IP and CIP: ethernet/ip and cip version audit | IT devices | green | green | wifipilot itproto (EtherNet/IP encapsulation and List-Identity) | A version request to cip on port 44818 from an unexpected host. |
| `it_dnp3_discover` | DNP3 SCADA telemetry: link reset | IT devices | green | green | wifipilot itproto (DNP3 link layer with CRC-DNP and application frames) | DNP3 SCADA telemetry traffic from an unexpected host to port 20000: link reset — a service log or an IDS rule on the protocol sees it |
| `it_dnp3_version_audit` | DNP3 SCADA telemetry: dnp3 scada telemetry version audit | IT devices | green | green | wifipilot itproto (DNP3 link layer with CRC-DNP and application frames) | A version request to dnp3 on port 20000 from an unexpected host. |
| `it_iec104_discover` | IEC 60870-5-104 SCADA: STARTDT | IT devices | green | green | wifipilot itproto (IEC-104 APCI U/I/S frames) | IEC 60870-5-104 SCADA traffic from an unexpected host to port 2404: startdt — a service log or an IDS rule on the protocol sees it |
| `it_iec104_version_audit` | IEC 60870-5-104 SCADA: iec 60870-5-104 scada version audit | IT devices | green | green | wifipilot itproto (IEC-104 APCI U/I/S frames) | A version request to iec104 on port 2404 from an unexpected host. |
| `it_opcua_discover` | OPC-UA server: HEL/ACK | IT devices | green | green | wifipilot itproto (OPC-UA HEL/ACK) | OPC-UA server traffic from an unexpected host to port 4840: hel/ack — a service log or an IDS rule on the protocol sees it |
| `it_opcua_version_audit` | OPC-UA server: opc-ua server version audit | IT devices | green | green | wifipilot itproto (OPC-UA HEL/ACK) | A version request to opcua on port 4840 from an unexpected host. |
| `it_ssh_banner` | SSH management: identification string | IT devices | green | green | wifipilot itproto (SSH identification string and KEXINIT) | SSH management traffic from an unexpected host to port 22: identification string — a service log or an IDS rule on the protocol sees it |
| `it_ssh_version_audit` | SSH management: ssh management version audit | IT devices | green | green | wifipilot itproto (SSH identification string and KEXINIT) | A version request to ssh on port 22 from an unexpected host. |
| `it_rdp_discover` | Remote desktop (RDP): negotiation request | IT devices | green | green | wifipilot itproto (RDP X.224 negotiation) | Remote desktop (RDP) traffic from an unexpected host to port 3389: negotiation request — a service log or an IDS rule on the protocol sees it |
| `it_rdp_version_audit` | Remote desktop (RDP): remote desktop (rdp) version audit | IT devices | green | green | wifipilot itproto (RDP X.224 negotiation) | A version request to rdp on port 3389 from an unexpected host. |
| `it_postgres_discover` | PostgreSQL: startup message | IT devices | green | green | wifipilot itproto (Postgres startup and authentication request) | PostgreSQL traffic from an unexpected host to port 5432: startup message — a service log or an IDS rule on the protocol sees it |
| `it_postgres_version_audit` | PostgreSQL: postgresql version audit | IT devices | green | green | wifipilot itproto (Postgres startup and authentication request) | A version request to postgres on port 5432 from an unexpected host. |
| `it_mysql_discover` | MySQL / MariaDB: handshake packet | IT devices | green | green | wifipilot itproto (MySQL initial handshake) | MySQL / MariaDB traffic from an unexpected host to port 3306: handshake packet — a service log or an IDS rule on the protocol sees it |
| `it_mysql_version_audit` | MySQL / MariaDB: mysql / mariadb version audit | IT devices | green | green | wifipilot itproto (MySQL initial handshake) | A version request to mysql on port 3306 from an unexpected host. |
| `it_rsync_discover` | rsync daemon: daemon greeting | IT devices | green | green | wifipilot itproto (rsync daemon greeting) | rsync daemon traffic from an unexpected host to port 873: daemon greeting — a service log or an IDS rule on the protocol sees it |
| `it_rsync_version_audit` | rsync daemon: rsync daemon version audit | IT devices | green | green | wifipilot itproto (rsync daemon greeting) | A version request to rsync on port 873 from an unexpected host. |
| `it_ftp_banner` | FTP service: greeting | IT devices | green | green | wifipilot itproto (FTP command and reply lines) | FTP service traffic from an unexpected host to port 21: greeting — a service log or an IDS rule on the protocol sees it |
| `it_ftp_version_audit` | FTP service: ftp service version audit | IT devices | green | green | wifipilot itproto (FTP command and reply lines) | A version request to ftp on port 21 from an unexpected host. |
| `it_smtp_discover` | SMTP mail server: EHLO | IT devices | green | green | wifipilot itproto (SMTP EHLO/MAIL/RCPT) | SMTP mail server traffic from an unexpected host to port 25: ehlo — a service log or an IDS rule on the protocol sees it |
| `it_smtp_version_audit` | SMTP mail server: smtp mail server version audit | IT devices | green | green | wifipilot itproto (SMTP EHLO/MAIL/RCPT) | A version request to smtp on port 25 from an unexpected host. |
| `it_miio_discover` | Xiaomi miIO device: hello handshake | IT devices | green | green | wifipilot itproto (miIO hello) | Xiaomi miIO device traffic from an unexpected host to port 54321: hello handshake — a service log or an IDS rule on the protocol sees it |
| `it_miio_version_audit` | Xiaomi miIO device: xiaomi miio device version audit | IT devices | green | green | wifipilot itproto (miIO hello) | A version request to miio on port 54321 from an unexpected host. |
| `it_ssdp_discover` | UPnP / SSDP: M-SEARCH | IT devices | green | green | wifipilot itproto (SSDP M-SEARCH) | UPnP / SSDP traffic from an unexpected host to port 1900: m-search — a service log or an IDS rule on the protocol sees it |
| `it_ssdp_version_audit` | UPnP / SSDP: upnp / ssdp version audit | IT devices | green | green | wifipilot itproto (SSDP M-SEARCH) | A version request to ssdp on port 1900 from an unexpected host. |
| `it_mdns_discover` | mDNS / DNS-SD: service query | IT devices | green | green | wifipilot itproto (mDNS query) | mDNS / DNS-SD traffic from an unexpected host to port 5353: service query — a service log or an IDS rule on the protocol sees it |
| `it_mdns_service_census` | mDNS / DNS-SD: host records | IT devices | green | green | wifipilot itproto (mDNS query) | mDNS / DNS-SD traffic from an unexpected host to port 5353: host records — a service log or an IDS rule on the protocol sees it |
| `it_mdns_version_audit` | mDNS / DNS-SD: mdns / dns-sd version audit | IT devices | green | green | wifipilot itproto (mDNS query) | A version request to mdns on port 5353 from an unexpected host. |
| `it_host_discovery` | IT host discovery sweep | IT devices | green | green | wifipilot itproto + itsim (real protocol probes) | a sweep of 11 service port(s) across the segment: connection logs and service logs show one client greeting everything |
| `it_device_inventory` | IT device inventory and typing | IT devices | green | green | wifipilot itproto + itsim (real protocol probes) | a sweep of 9 service port(s) across the segment: connection logs and service logs show one client greeting everything |
| `it_port_exposure` | IT port exposure sweep | IT devices | green | green | wifipilot itproto + itsim (real protocol probes) | a sweep of 90 service port(s) across the segment: connection logs and service logs show one client greeting everything |
| `it_cleartext_service_audit` | cleartext service audit | IT devices | green | green | wifipilot itproto + itsim (real protocol probes) | a sweep of 7 service port(s) across the segment: connection logs and service logs show one client greeting everything |
| `it_firmware_advisory_audit` | firmware advisory audit | IT devices | green | green | wifipilot itproto + itsim (real protocol probes) | a sweep of 5 service port(s) across the segment: connection logs and service logs show one client greeting everything |
| `it_camera_exposure_audit` | camera and recorder exposure audit | IT devices | green | green | wifipilot itproto + itsim (real protocol probes) | a sweep of 4 service port(s) across the segment: connection logs and service logs show one client greeting everything |
| `it_printer_exposure_audit` | printer and MFP exposure audit | IT devices | green | green | wifipilot itproto + itsim (real protocol probes) | a sweep of 4 service port(s) across the segment: connection logs and service logs show one client greeting everything |
| `it_ot_exposure_audit` | OT / industrial exposure audit | IT devices | green | green | wifipilot itproto + itsim (real protocol probes) | a sweep of 7 service port(s) across the segment: connection logs and service logs show one client greeting everything |
| `it_medical_device_audit` | medical device exposure audit | IT devices | green | green | wifipilot itproto + itsim (real protocol probes) | a sweep of 3 service port(s) across the segment: connection logs and service logs show one client greeting everything |
| `it_container_exposure_audit` | container and cluster exposure audit | IT devices | green | green | wifipilot itproto + itsim (real protocol probes) | a sweep of 4 service port(s) across the segment: connection logs and service logs show one client greeting everything |
| `it_database_exposure_audit` | database exposure audit | IT devices | green | green | wifipilot itproto + itsim (real protocol probes) | a sweep of 6 service port(s) across the segment: connection logs and service logs show one client greeting everything |
| `it_share_enumeration` | file share enumeration | IT devices | green | green | wifipilot itproto + itsim (real protocol probes) | a sweep of 4 service port(s) across the segment: connection logs and service logs show one client greeting everything |
| `it_voip_exposure_audit` | VoIP exposure audit | IT devices | green | green | wifipilot itproto + itsim (real protocol probes) | a sweep of 3 service port(s) across the segment: connection logs and service logs show one client greeting everything |
| `it_smart_home_audit` | smart home and consumer device audit | IT devices | green | green | wifipilot itproto + itsim (real protocol probes) | a sweep of 5 service port(s) across the segment: connection logs and service logs show one client greeting everything |
| `it_iot_service_census` | IoT service census | IT devices | green | green | wifipilot itproto + itsim (real protocol probes) | a sweep of 7 service port(s) across the segment: connection logs and service logs show one client greeting everything |
| `it_exposure_report` | segment exposure report | IT devices | green | green | wifipilot itproto + itsim (real protocol probes) | a sweep of 28 service port(s) across the segment: connection logs and service logs show one client greeting everything |

### Device and service attacks (IP, not radio) — 179

| attack | answers | edition | noise | impact | tool | defender sees |
| --- | --- | --- | --- | --- | --- | --- |
| `ble_gatt_hijack` <br>_injects_ | BLE GATT hijack (unauthenticated write, verified) | Bluetooth | green | bold green | wifipilot bt.py (ATT Read/Write) | An ATT Write Request on a control characteristic from a host the device never bonded with, followed by a Read: the device's own log carries the write, and the physical device shows the effect. |
| `it_hijack_rtsp` | RTSP session takeover (streams the camera to us) | IT devices | cyan | red | wifipilot itproto.py (rtsp_request) + TCP 554 | a second rtsp session on port 554 from an address the device has no association with, and a value, registration or job the operator did not change; the device's own log shows the write and the source it does not recognise |
| `it_hijack_sip_register` | SIP registration takeover (the extension registers to us) | IT devices | cyan | red | wifipilot itproto.py (sip_register) | a second sip session on port 5060 from an address the device has no association with, and a value, registration or job the operator did not change; the device's own log shows the write and the source it does not recognise |
| `it_hijack_mqtt_retain` | MQTT retained-message takeover (subscribers read ours first) | IT devices | cyan | red | wifipilot itproto.py (mqtt_publish with retain) | a second mqtt session on port 1883 from an address the device has no association with, and a value, registration or job the operator did not change; the device's own log shows the write and the source it does not recognise |
| `it_hijack_onvif_uri` | ONVIF stream-URI rewrite (points the client at our stream) | IT devices | cyan | red | wifipilot itproto.py (onvif_get_stream_uri) | a second onvif session on port 80 from an address the device has no association with, and a value, registration or job the operator did not change; the device's own log shows the write and the source it does not recognise |
| `it_hijack_modbus_coil` | Modbus coil takeover (writes a coil the PLC acts on) | IT devices | cyan | red | wifipilot itproto.py (modbus_request, function 5) | a second modbus session on port 502 from an address the device has no association with, and a value, registration or job the operator did not change; the device's own log shows the write and the source it does not recognise |
| `it_hijack_bacnet_priority` | BACnet priority override (writes at priority 1) | IT devices | cyan | red | wifipilot ithijack.bacnet_write_property + UDP 47808 | a second bacnet session on port 47808 from an address the device has no association with, and a value, registration or job the operator did not change; the device's own log shows the write and the source it does not recognise |
| `it_hijack_iec104` | IEC 60870-5-104 command injection | IT devices | cyan | red | wifipilot itproto.py (iec104_interrogation/iec104_start) | a second iec104 session on port 2404 from an address the device has no association with, and a value, registration or job the operator did not change; the device's own log shows the write and the source it does not recognise |
| `it_hijack_dnp3` | DNP3 link reset and integrity poll | IT devices | cyan | red | wifipilot itproto.py (dnp3_reset_link/dnp3_integrity_poll) | a second dnp3 session on port 20000 from an address the device has no association with, and a value, registration or job the operator did not change; the device's own log shows the write and the source it does not recognise |
| `it_hijack_pjl_job` | Print-job takeover (deletes spooled jobs by name) | IT devices | cyan | red | wifipilot itproto.py (pjl_command) | a second pjl session on port 9100 from an address the device has no association with, and a value, registration or job the operator did not change; the device's own log shows the write and the source it does not recognise |
| `it_hijack_http_session` | Session-cookie replay against a device's own web UI | IT devices | cyan | red | wifipilot itproto.py (http_request with Cookie) | a second http session on port 80 from an address the device has no association with, and a value, registration or job the operator did not change; the device's own log shows the write and the source it does not recognise |
| `it_hijack_cwmp` | TR-069 Inform forgery (the ACS acts on a device we claim) | IT devices | cyan | red | wifipilot itproto.py (cwmp_inform) | a second tr069 session on port 7547 from an address the device has no association with, and a value, registration or job the operator did not change; the device's own log shows the write and the source it does not recognise |
| `it_hijack_adb` | ADB shell takeover (debug bridge left listening) | IT devices | cyan | red | wifipilot itproto.py (adb_connect) + TCP 5555 | a second adb session on port 5555 from an address the device has no association with, and a value, registration or job the operator did not change; the device's own log shows the write and the source it does not recognise |
| `it_hijack_ftp_write` | Anonymous FTP write (a file we choose lands on the server) | IT devices | cyan | red | wifipilot itproto.py (ftp_login) + a STOR command | a second ftp session on port 21 from an address the device has no association with, and a value, registration or job the operator did not change; the device's own log shows the write and the source it does not recognise |
| `it_hijack_smtp_relay` | Open-relay hijack (mail in another sender's name) | IT devices | cyan | red | wifipilot itproto.py (smtp_ehlo) + MAIL FROM/RCPT TO | a second smtp session on port 25 from an address the device has no association with, and a value, registration or job the operator did not change; the device's own log shows the write and the source it does not recognise |
| `it_hijack_imap_delete` | Mailbox deletion hijack (a folder is removed in another user's name) | IT devices | cyan | red | wifipilot itproto.py (imap_login) + DELETE | a second imap session on port 143 from an address the device has no association with, and a value, registration or job the operator did not change; the device's own log shows the write and the source it does not recognise |
| `it_hijack_dicom_store` | DICOM store hijack (a study we choose is filed on the archive) | IT devices | cyan | red | wifipilot itproto.py (dicom_associate/dicom_echo) | a second dicom session on port 104 from an address the device has no association with, and a value, registration or job the operator did not change; the device's own log shows the write and the source it does not recognise |
| `it_hijack_vnc_session` | VNC session hijack (the 'none' security type is a login) | IT devices | cyan | red | wifipilot itproto.py (vnc_version/parse_vnc_security) + TCP 5900 | a second vnc session on port 5900 from an address the device has no association with, and a value, registration or job the operator did not change; the device's own log shows the write and the source it does not recognise |
| `it_hijack_mysql_query` | MySQL query hijack (the client's SQL is answered by us) | IT devices | cyan | red | wifipilot itproto.py (mysql_handshake_parse) + TCP 3306 | a second mysql session on port 3306 from an address the device has no association with, and a value, registration or job the operator did not change; the device's own log shows the write and the source it does not recognise |
| `it_hijack_sip_contact` | SIP contact hijack (a phone's contact points at us) | IT devices | cyan | red | wifipilot itproto.py (sip_register/parse_sip) + UDP 5060 | a second sip session on port 5060 from an address the device has no association with, and a value, registration or job the operator did not change; the device's own log shows the write and the source it does not recognise |
| `it_hijack_opcua_write` | OPC-UA node write (a process value changed by an unauthenticated session) | IT devices | cyan | red | wifipilot itproto.py (opcua_hello/parse_opcua) + TCP 4840 | a second opcua session on port 4840 from an address the device has no association with, and a value, registration or job the operator did not change; the device's own log shows the write and the source it does not recognise |
| `it_http_version` | Web management interface: version banner | IT devices | green | green | wifipilot itproto (HTTP/1.1 request builder) | Web management interface traffic from an unexpected host to port 80: version banner — a service log or an IDS rule on the protocol sees it |
| `it_http_default_creds` | Web management interface: default credentials | IT devices | cyan | bold green | wifipilot itproto (HTTP/1.1 request builder) | Web management interface traffic from an unexpected host to port 80: default credentials — a service log or an IDS rule on the protocol sees it |
| `it_http_auth_bypass` | Web management interface: authentication bypass (header spoof) | IT devices | cyan | bold green | wifipilot itproto (HTTP/1.1 request builder) | Web management interface traffic from an unexpected host to port 80: authentication bypass (header spoof) — a service log or an IDS rule on the protocol sees it |
| `it_http_config_dump` | Web management interface: configuration page | IT devices | cyan | bold green | wifipilot itproto (HTTP/1.1 request builder) | Web management interface traffic from an unexpected host to port 80: configuration page — a service log or an IDS rule on the protocol sees it |
| `it_http_cleartext` | Web management interface: plaintext management | IT devices | green | green | wifipilot itproto (HTTP/1.1 request builder) | Web management interface traffic from an unexpected host to port 80: plaintext management — a service log or an IDS rule on the protocol sees it |
| `it_http_json_unauth_read` | JSON/REST API: container list without auth | IT devices | cyan | bold green | wifipilot itproto (HTTP JSON request builder) | JSON/REST API traffic from an unexpected host to port 2375: container list without auth — a service log or an IDS rule on the protocol sees it |
| `it_http_json_unauth_write` | JSON/REST API: container create without auth | IT devices | cyan | bold green | wifipilot itproto (HTTP JSON request builder) | JSON/REST API traffic from an unexpected host to port 2375: container create without auth — a service log or an IDS rule on the protocol sees it |
| `it_http_json_config_dump` | JSON/REST API: daemon information | IT devices | green | green | wifipilot itproto (HTTP JSON request builder) | JSON/REST API traffic from an unexpected host to port 2375: daemon information — a service log or an IDS rule on the protocol sees it |
| `it_http_json_cluster_read` | JSON/REST API: cluster object read | IT devices | cyan | bold green | wifipilot itproto (HTTP JSON request builder) | JSON/REST API traffic from an unexpected host to port 2375: cluster object read — a service log or an IDS rule on the protocol sees it |
| `it_http_json_search_read` | JSON/REST API: search cluster read | IT devices | green | bold green | wifipilot itproto (HTTP JSON request builder) | JSON/REST API traffic from an unexpected host to port 2375: search cluster read — a service log or an IDS rule on the protocol sees it |
| `it_http_json_cleartext_audit` | JSON/REST API: json/rest api without encryption | IT devices | green | bold green | wifipilot itproto (HTTP JSON request builder) | A http_json handshake on port 2375 to an unexpected host. |
| `it_mqtt_anonymous` | MQTT broker: anonymous connect | IT devices | green | bold green | wifipilot itproto (MQTT 3.1.1/5.0 CONNECT, PUBLISH, SUBSCRIBE) | MQTT broker traffic from an unexpected host to port 1883: anonymous connect — a service log or an IDS rule on the protocol sees it |
| `it_mqtt_default_creds` | MQTT broker: default broker credentials | IT devices | cyan | bold green | wifipilot itproto (MQTT 3.1.1/5.0 CONNECT, PUBLISH, SUBSCRIBE) | MQTT broker traffic from an unexpected host to port 1883: default broker credentials — a service log or an IDS rule on the protocol sees it |
| `it_mqtt_subscribe` | MQTT broker: topic subscription | IT devices | green | bold green | wifipilot itproto (MQTT 3.1.1/5.0 CONNECT, PUBLISH, SUBSCRIBE) | MQTT broker traffic from an unexpected host to port 1883: topic subscription — a service log or an IDS rule on the protocol sees it |
| `it_mqtt_publish` | MQTT broker: publish to a device topic | IT devices | green | yellow | wifipilot itproto (MQTT 3.1.1/5.0 CONNECT, PUBLISH, SUBSCRIBE) | MQTT broker traffic from an unexpected host to port 1883: publish to a device topic — a service log or an IDS rule on the protocol sees it |
| `it_mqtt_cleartext_audit` | MQTT broker: mqtt broker without encryption | IT devices | green | bold green | wifipilot itproto (MQTT 3.1.1/5.0 CONNECT, PUBLISH, SUBSCRIBE) | A mqtt handshake on port 1883 to an unexpected host. |
| `it_coap_unauth_read` | CoAP endpoint: state read | IT devices | green | green | wifipilot itproto (CoAP RFC 7252 GET/POST with options) | CoAP endpoint traffic from an unexpected host to port 5683: state read — a service log or an IDS rule on the protocol sees it |
| `it_coap_unauth_write` | CoAP endpoint: configuration write | IT devices | green | yellow | wifipilot itproto (CoAP RFC 7252 GET/POST with options) | CoAP endpoint traffic from an unexpected host to port 5683: configuration write — a service log or an IDS rule on the protocol sees it |
| `it_coap_fuzz` | CoAP endpoint: oversized option block | IT devices | cyan | green | wifipilot itproto (CoAP RFC 7252 GET/POST with options) | CoAP endpoint traffic from an unexpected host to port 5683: oversized option block — a service log or an IDS rule on the protocol sees it |
| `it_coap_cleartext_audit` | CoAP endpoint: coap endpoint without encryption | IT devices | green | bold green | wifipilot itproto (CoAP RFC 7252 GET/POST with options) | A coap handshake on port 5683 to an unexpected host. |
| `it_modbus_unauth_read` | Modbus/TCP controller: holding register read | IT devices | green | bold green | wifipilot itproto (Modbus TCP MBAP, function codes 1-43) | Modbus/TCP controller traffic from an unexpected host to port 502: holding register read — a service log or an IDS rule on the protocol sees it |
| `it_modbus_unauth_write` | Modbus/TCP controller: single register write | IT devices | green | yellow | wifipilot itproto (Modbus TCP MBAP, function codes 1-43) | Modbus/TCP controller traffic from an unexpected host to port 502: single register write — a service log or an IDS rule on the protocol sees it |
| `it_modbus_config_dump` | Modbus/TCP controller: register map enumeration | IT devices | cyan | bold green | wifipilot itproto (Modbus TCP MBAP, function codes 1-43) | Modbus/TCP controller traffic from an unexpected host to port 502: register map enumeration — a service log or an IDS rule on the protocol sees it |
| `it_modbus_fuzz` | Modbus/TCP controller: illegal function and oversized count | IT devices | cyan | green | wifipilot itproto (Modbus TCP MBAP, function codes 1-43) | Modbus/TCP controller traffic from an unexpected host to port 502: illegal function and oversized count — a service log or an IDS rule on the protocol sees it |
| `it_modbus_cleartext_audit` | Modbus/TCP controller: modbus/tcp controller without encryption | IT devices | green | bold green | wifipilot itproto (Modbus TCP MBAP, function codes 1-43) | A modbus handshake on port 502 to an unexpected host. |
| `it_bacnet_unauth_read` | BACnet building controller: object-name read | IT devices | green | green | wifipilot itproto (BACnet/IP BVLC, Who-Is, Read-Property) | BACnet building controller traffic from an unexpected host to port 47808: object-name read — a service log or an IDS rule on the protocol sees it |
| `it_bacnet_unauth_write` | BACnet building controller: setpoint write | IT devices | green | yellow | wifipilot itproto (BACnet/IP BVLC, Who-Is, Read-Property) | BACnet building controller traffic from an unexpected host to port 47808: setpoint write — a service log or an IDS rule on the protocol sees it |
| `it_bacnet_config_dump` | BACnet building controller: device object walk | IT devices | green | bold green | wifipilot itproto (BACnet/IP BVLC, Who-Is, Read-Property) | BACnet building controller traffic from an unexpected host to port 47808: device object walk — a service log or an IDS rule on the protocol sees it |
| `it_bacnet_cleartext_audit` | BACnet building controller: bacnet building controller without encryption | IT devices | green | bold green | wifipilot itproto (BACnet/IP BVLC, Who-Is, Read-Property) | A bacnet handshake on port 47808 to an unexpected host. |
| `it_rtsp_anonymous` | RTSP video stream: stream without credentials | IT devices | green | bold green | wifipilot itproto (RTSP OPTIONS/DESCRIBE/PLAY, SDP) | RTSP video stream traffic from an unexpected host to port 554: stream without credentials — a service log or an IDS rule on the protocol sees it |
| `it_rtsp_default_creds` | RTSP video stream: default camera credentials | IT devices | cyan | bold green | wifipilot itproto (RTSP OPTIONS/DESCRIBE/PLAY, SDP) | RTSP video stream traffic from an unexpected host to port 554: default camera credentials — a service log or an IDS rule on the protocol sees it |
| `it_rtsp_version` | RTSP video stream: server banner | IT devices | green | green | wifipilot itproto (RTSP OPTIONS/DESCRIBE/PLAY, SDP) | RTSP video stream traffic from an unexpected host to port 554: server banner — a service log or an IDS rule on the protocol sees it |
| `it_rtsp_config_dump` | RTSP video stream: stream inventory | IT devices | cyan | bold green | wifipilot itproto (RTSP OPTIONS/DESCRIBE/PLAY, SDP) | RTSP video stream traffic from an unexpected host to port 554: stream inventory — a service log or an IDS rule on the protocol sees it |
| `it_rtsp_cleartext_audit` | RTSP video stream: rtsp video stream without encryption | IT devices | green | bold green | wifipilot itproto (RTSP OPTIONS/DESCRIBE/PLAY, SDP) | A rtsp handshake on port 554 to an unexpected host. |
| `it_onvif_version` | ONVIF device service: firmware version read | IT devices | green | green | wifipilot itproto (ONVIF SOAP GetDeviceInformation/GetStreamUri) | ONVIF device service traffic from an unexpected host to port 80: firmware version read — a service log or an IDS rule on the protocol sees it |
| `it_onvif_config_dump` | ONVIF device service: system time and network settings | IT devices | green | green | wifipilot itproto (ONVIF SOAP GetDeviceInformation/GetStreamUri) | ONVIF device service traffic from an unexpected host to port 80: system time and network settings — a service log or an IDS rule on the protocol sees it |
| `it_onvif_default_creds` | ONVIF device service: SOAP with default credentials | IT devices | cyan | bold green | wifipilot itproto (ONVIF SOAP GetDeviceInformation/GetStreamUri) | ONVIF device service traffic from an unexpected host to port 80: soap with default credentials — a service log or an IDS rule on the protocol sees it |
| `it_onvif_stream_uri` | ONVIF device service: media profile walk | IT devices | cyan | bold green | wifipilot itproto (ONVIF SOAP GetDeviceInformation/GetStreamUri) | ONVIF device service traffic from an unexpected host to port 80: media profile walk — a service log or an IDS rule on the protocol sees it |
| `it_onvif_cleartext_audit` | ONVIF device service: onvif device service without encryption | IT devices | green | bold green | wifipilot itproto (ONVIF SOAP GetDeviceInformation/GetStreamUri) | A onvif handshake on port 80 to an unexpected host. |
| `it_ipp_version` | IPP print service: model and firmware read | IT devices | green | green | wifipilot itproto (IPP RFC 8010/8011) | IPP print service traffic from an unexpected host to port 631: model and firmware read — a service log or an IDS rule on the protocol sees it |
| `it_ipp_anonymous` | IPP print service: attributes without authentication | IT devices | green | bold green | wifipilot itproto (IPP RFC 8010/8011) | IPP print service traffic from an unexpected host to port 631: attributes without authentication — a service log or an IDS rule on the protocol sees it |
| `it_ipp_default_creds` | IPP print service: default credentials | IT devices | cyan | bold green | wifipilot itproto (IPP RFC 8010/8011) | IPP print service traffic from an unexpected host to port 631: default credentials — a service log or an IDS rule on the protocol sees it |
| `it_ipp_config_dump` | IPP print service: attributes inventory | IT devices | cyan | bold green | wifipilot itproto (IPP RFC 8010/8011) | IPP print service traffic from an unexpected host to port 631: attributes inventory — a service log or an IDS rule on the protocol sees it |
| `it_ipp_cleartext_audit` | IPP print service: ipp print service without encryption | IT devices | green | bold green | wifipilot itproto (IPP RFC 8010/8011) | A ipp handshake on port 631 to an unexpected host. |
| `it_pjl_version` | PJL printer command port: firmware string | IT devices | green | green | wifipilot itproto (PJL @PJL INFO/USTATUS) | PJL printer command port traffic from an unexpected host to port 9100: firmware string — a service log or an IDS rule on the protocol sees it |
| `it_pjl_config_dump` | PJL printer command port: INFO CONFIG | IT devices | cyan | bold green | wifipilot itproto (PJL @PJL INFO/USTATUS) | PJL printer command port traffic from an unexpected host to port 9100: info config — a service log or an IDS rule on the protocol sees it |
| `it_pjl_unauth_write` | PJL printer command port: display message write | IT devices | green | yellow | wifipilot itproto (PJL @PJL INFO/USTATUS) | PJL printer command port traffic from an unexpected host to port 9100: display message write — a service log or an IDS rule on the protocol sees it |
| `it_pjl_filesys_audit` | PJL printer command port: filesystem and job inventory | IT devices | cyan | green | wifipilot itproto (PJL @PJL INFO/USTATUS) | PJL printer command port traffic from an unexpected host to port 9100: filesystem and job inventory — a service log or an IDS rule on the protocol sees it |
| `it_pjl_cleartext_audit` | PJL printer command port: pjl printer command port without encryption | IT devices | green | bold green | wifipilot itproto (PJL @PJL INFO/USTATUS) | A pjl handshake on port 9100 to an unexpected host. |
| `it_telnet_version` | Telnet management: version in the banner | IT devices | green | green | wifipilot itproto (telnet negotiation and banner) | Telnet management traffic from an unexpected host to port 23: version in the banner — a service log or an IDS rule on the protocol sees it |
| `it_telnet_default_creds` | Telnet management: default credentials | IT devices | cyan | bold green | wifipilot itproto (telnet negotiation and banner) | Telnet management traffic from an unexpected host to port 23: default credentials — a service log or an IDS rule on the protocol sees it |
| `it_telnet_cleartext` | Telnet management: telnet in the clear | IT devices | green | green | wifipilot itproto (telnet negotiation and banner) | Telnet management traffic from an unexpected host to port 23: telnet in the clear — a service log or an IDS rule on the protocol sees it |
| `it_sip_challenge_audit` | SIP telephony: authentication challenge read | IT devices | green | green | wifipilot itproto (SIP OPTIONS/REGISTER, digest challenge parsing) | SIP telephony traffic from an unexpected host to port 5060: authentication challenge read — a service log or an IDS rule on the protocol sees it |
| `it_sip_enum` | SIP telephony: extension enumeration | IT devices | cyan | green | wifipilot itproto (SIP OPTIONS/REGISTER, digest challenge parsing) | SIP telephony traffic from an unexpected host to port 5060: extension enumeration — a service log or an IDS rule on the protocol sees it |
| `it_sip_default_creds` | SIP telephony: default credentials | IT devices | cyan | bold green | wifipilot itproto (SIP OPTIONS/REGISTER, digest challenge parsing) | SIP telephony traffic from an unexpected host to port 5060: default credentials — a service log or an IDS rule on the protocol sees it |
| `it_sip_cleartext` | SIP telephony: SIP in the clear | IT devices | green | green | wifipilot itproto (SIP OPTIONS/REGISTER, digest challenge parsing) | SIP telephony traffic from an unexpected host to port 5060: sip in the clear — a service log or an IDS rule on the protocol sees it |
| `it_sip_cleartext_audit` | SIP telephony: sip telephony without encryption | IT devices | green | bold green | wifipilot itproto (SIP OPTIONS/REGISTER, digest challenge parsing) | A sip handshake on port 5060 to an unexpected host. |
| `it_cwmp_config_dump` | TR-069 / CWMP management: parameter read | IT devices | cyan | bold green | wifipilot itproto (CWMP Inform and GetParameterValues) | TR-069 / CWMP management traffic from an unexpected host to port 7547: parameter read — a service log or an IDS rule on the protocol sees it |
| `it_cwmp_unauth_write` | TR-069 / CWMP management: parameter write | IT devices | green | yellow | wifipilot itproto (CWMP Inform and GetParameterValues) | TR-069 / CWMP management traffic from an unexpected host to port 7547: parameter write — a service log or an IDS rule on the protocol sees it |
| `it_cwmp_version` | TR-069 / CWMP management: software version | IT devices | green | green | wifipilot itproto (CWMP Inform and GetParameterValues) | TR-069 / CWMP management traffic from an unexpected host to port 7547: software version — a service log or an IDS rule on the protocol sees it |
| `it_cwmp_cleartext_audit` | TR-069 / CWMP management: tr-069 / cwmp management without encryption | IT devices | green | bold green | wifipilot itproto (CWMP Inform and GetParameterValues) | A cwmp handshake on port 7547 to an unexpected host. |
| `it_smb_version` | SMB file sharing: dialect list | IT devices | green | green | wifipilot itproto (SMB2 NEGOTIATE, NetBIOS) | SMB file sharing traffic from an unexpected host to port 445: dialect list — a service log or an IDS rule on the protocol sees it |
| `it_smb_signing_audit` | SMB file sharing: signing requirement | IT devices | green | green | wifipilot itproto (SMB2 NEGOTIATE, NetBIOS) | SMB file sharing traffic from an unexpected host to port 445: signing requirement — a service log or an IDS rule on the protocol sees it |
| `it_smb_null_session` | SMB file sharing: anonymous session enumeration | IT devices | cyan | bold green | wifipilot itproto (SMB2 NEGOTIATE, NetBIOS) | SMB file sharing traffic from an unexpected host to port 445: anonymous session enumeration — a service log or an IDS rule on the protocol sees it |
| `it_smb_cleartext_audit` | SMB file sharing: smb file sharing without encryption | IT devices | green | bold green | wifipilot itproto (SMB2 NEGOTIATE, NetBIOS) | A smb handshake on port 445 to an unexpected host. |
| `it_ldap_anonymous` | LDAP directory: anonymous bind | IT devices | green | bold green | wifipilot itproto (LDAP bindRequest and rootDSE search) | LDAP directory traffic from an unexpected host to port 389: anonymous bind — a service log or an IDS rule on the protocol sees it |
| `it_ldap_version` | LDAP directory: vendor version | IT devices | green | green | wifipilot itproto (LDAP bindRequest and rootDSE search) | LDAP directory traffic from an unexpected host to port 389: vendor version — a service log or an IDS rule on the protocol sees it |
| `it_ldap_default_creds` | LDAP directory: default credentials | IT devices | cyan | bold green | wifipilot itproto (LDAP bindRequest and rootDSE search) | LDAP directory traffic from an unexpected host to port 389: default credentials — a service log or an IDS rule on the protocol sees it |
| `it_ldap_unauth_read` | LDAP directory: user and group search | IT devices | cyan | bold green | wifipilot itproto (LDAP bindRequest and rootDSE search) | LDAP directory traffic from an unexpected host to port 389: user and group search — a service log or an IDS rule on the protocol sees it |
| `it_ldap_cleartext_audit` | LDAP directory: ldap directory without encryption | IT devices | green | bold green | wifipilot itproto (LDAP bindRequest and rootDSE search) | A ldap handshake on port 389 to an unexpected host. |
| `it_redis_anonymous` | Redis data store: command without AUTH | IT devices | green | bold green | wifipilot itproto (Redis RESP) | Redis data store traffic from an unexpected host to port 6379: command without auth — a service log or an IDS rule on the protocol sees it |
| `it_redis_version` | Redis data store: server version | IT devices | green | green | wifipilot itproto (Redis RESP) | Redis data store traffic from an unexpected host to port 6379: server version — a service log or an IDS rule on the protocol sees it |
| `it_redis_config_dump` | Redis data store: configuration read | IT devices | cyan | bold green | wifipilot itproto (Redis RESP) | Redis data store traffic from an unexpected host to port 6379: configuration read — a service log or an IDS rule on the protocol sees it |
| `it_redis_unauth_write` | Redis data store: key write test | IT devices | cyan | yellow | wifipilot itproto (Redis RESP) | Redis data store traffic from an unexpected host to port 6379: key write test — a service log or an IDS rule on the protocol sees it |
| `it_redis_cleartext_audit` | Redis data store: redis data store without encryption | IT devices | green | bold green | wifipilot itproto (Redis RESP) | A redis handshake on port 6379 to an unexpected host. |
| `it_memcached_version` | Memcached: version string | IT devices | green | green | wifipilot itproto (memcached text protocol) | Memcached traffic from an unexpected host to port 11211: version string — a service log or an IDS rule on the protocol sees it |
| `it_memcached_unauth_read` | Memcached: key read | IT devices | green | bold green | wifipilot itproto (memcached text protocol) | Memcached traffic from an unexpected host to port 11211: key read — a service log or an IDS rule on the protocol sees it |
| `it_memcached_unauth_write` | Memcached: key write | IT devices | cyan | yellow | wifipilot itproto (memcached text protocol) | Memcached traffic from an unexpected host to port 11211: key write — a service log or an IDS rule on the protocol sees it |
| `it_memcached_cleartext_audit` | Memcached: memcached without encryption | IT devices | green | bold green | wifipilot itproto (memcached text protocol) | A memcached handshake on port 11211 to an unexpected host. |
| `it_mongo_version` | MongoDB: wire version | IT devices | green | green | wifipilot itproto (MongoDB OP_MSG hello) | MongoDB traffic from an unexpected host to port 27017: wire version — a service log or an IDS rule on the protocol sees it |
| `it_mongo_anonymous` | MongoDB: status without authentication | IT devices | green | bold green | wifipilot itproto (MongoDB OP_MSG hello) | MongoDB traffic from an unexpected host to port 27017: status without authentication — a service log or an IDS rule on the protocol sees it |
| `it_mongo_unauth_read` | MongoDB: database list probe | IT devices | cyan | bold green | wifipilot itproto (MongoDB OP_MSG hello) | MongoDB traffic from an unexpected host to port 27017: database list probe — a service log or an IDS rule on the protocol sees it |
| `it_mongo_cleartext_audit` | MongoDB: mongodb without encryption | IT devices | green | bold green | wifipilot itproto (MongoDB OP_MSG hello) | A mongo handshake on port 27017 to an unexpected host. |
| `it_kasa_anon_read` | TP-Link Kasa / smart home: relay state read | IT devices | green | green | wifipilot itproto (Kasa autokey XOR framing) | TP-Link Kasa / smart home traffic from an unexpected host to port 9999: relay state read — a service log or an IDS rule on the protocol sees it |
| `it_kasa_unauth_write` | TP-Link Kasa / smart home: relay toggle | IT devices | cyan | yellow | wifipilot itproto (Kasa autokey XOR framing) | TP-Link Kasa / smart home traffic from an unexpected host to port 9999: relay toggle — a service log or an IDS rule on the protocol sees it |
| `it_kasa_version` | TP-Link Kasa / smart home: firmware string | IT devices | green | green | wifipilot itproto (Kasa autokey XOR framing) | TP-Link Kasa / smart home traffic from an unexpected host to port 9999: firmware string — a service log or an IDS rule on the protocol sees it |
| `it_kasa_cleartext_audit` | TP-Link Kasa / smart home: tp-link kasa / smart home without encryption | IT devices | green | bold green | wifipilot itproto (Kasa autokey XOR framing) | A kasa handshake on port 9999 to an unexpected host. |
| `it_cast_unauth_read` | Cast / Chromecast service: receiver status | IT devices | green | green | wifipilot itproto (CASTV2 message framing) | Cast / Chromecast service traffic from an unexpected host to port 8009: receiver status — a service log or an IDS rule on the protocol sees it |
| `it_cast_unauth_write` | Cast / Chromecast service: app launch | IT devices | cyan | yellow | wifipilot itproto (CASTV2 message framing) | Cast / Chromecast service traffic from an unexpected host to port 8009: app launch — a service log or an IDS rule on the protocol sees it |
| `it_cast_cleartext_audit` | Cast / Chromecast service: cast / chromecast service without encryption | IT devices | green | bold green | wifipilot itproto (CASTV2 message framing) | A cast handshake on port 8009 to an unexpected host. |
| `it_airplay_version` | AirPlay / Apple media service: model and build | IT devices | green | green | wifipilot itproto (AirPlay /info and text plist) | AirPlay / Apple media service traffic from an unexpected host to port 7000: model and build — a service log or an IDS rule on the protocol sees it |
| `it_airplay_auth_audit` | AirPlay / Apple media service: PIN requirement | IT devices | green | green | wifipilot itproto (AirPlay /info and text plist) | AirPlay / Apple media service traffic from an unexpected host to port 7000: pin requirement — a service log or an IDS rule on the protocol sees it |
| `it_airplay_cleartext_audit` | AirPlay / Apple media service: airplay / apple media service without encryption | IT devices | green | bold green | wifipilot itproto (AirPlay /info and text plist) | A airplay handshake on port 7000 to an unexpected host. |
| `it_adb_anonymous` | Android debug bridge: authorisation bypass | IT devices | green | bold green | wifipilot itproto (ADB CNXN/AUTH framing) | Android debug bridge traffic from an unexpected host to port 5555: authorisation bypass — a service log or an IDS rule on the protocol sees it |
| `it_adb_version` | Android debug bridge: device identity | IT devices | green | green | wifipilot itproto (ADB CNXN/AUTH framing) | Android debug bridge traffic from an unexpected host to port 5555: device identity — a service log or an IDS rule on the protocol sees it |
| `it_adb_unauth_read` | Android debug bridge: package list | IT devices | cyan | bold green | wifipilot itproto (ADB CNXN/AUTH framing) | Android debug bridge traffic from an unexpected host to port 5555: package list — a service log or an IDS rule on the protocol sees it |
| `it_adb_cleartext_audit` | Android debug bridge: android debug bridge without encryption | IT devices | green | bold green | wifipilot itproto (ADB CNXN/AUTH framing) | A adb handshake on port 5555 to an unexpected host. |
| `it_vnc_anonymous` | VNC remote desktop: security type none | IT devices | green | bold green | wifipilot itproto (RFB version and security types) | VNC remote desktop traffic from an unexpected host to port 5900: security type none — a service log or an IDS rule on the protocol sees it |
| `it_vnc_version` | VNC remote desktop: client banner | IT devices | green | green | wifipilot itproto (RFB version and security types) | VNC remote desktop traffic from an unexpected host to port 5900: client banner — a service log or an IDS rule on the protocol sees it |
| `it_vnc_default_creds` | VNC remote desktop: default credentials | IT devices | cyan | bold green | wifipilot itproto (RFB version and security types) | VNC remote desktop traffic from an unexpected host to port 5900: default credentials — a service log or an IDS rule on the protocol sees it |
| `it_vnc_cleartext_audit` | VNC remote desktop: vnc remote desktop without encryption | IT devices | green | bold green | wifipilot itproto (RFB version and security types) | A vnc handshake on port 5900 to an unexpected host. |
| `it_pjlink_version` | PJLink projector control: INFO query | IT devices | green | green | wifipilot itproto (PJLink %1 commands) | PJLink projector control traffic from an unexpected host to port 4352: info query — a service log or an IDS rule on the protocol sees it |
| `it_pjlink_unauth_write` | PJLink projector control: power command | IT devices | green | yellow | wifipilot itproto (PJLink %1 commands) | PJLink projector control traffic from an unexpected host to port 4352: power command — a service log or an IDS rule on the protocol sees it |
| `it_pjlink_cleartext_audit` | PJLink projector control: pjlink projector control without encryption | IT devices | green | bold green | wifipilot itproto (PJLink %1 commands) | A pjlink handshake on port 4352 to an unexpected host. |
| `it_dicom_echo` | DICOM medical imaging: C-ECHO | IT devices | green | green | wifipilot itproto (DICOM A-ASSOCIATE and C-ECHO) | DICOM medical imaging traffic from an unexpected host to port 104: c-echo — a service log or an IDS rule on the protocol sees it |
| `it_dicom_config_dump` | DICOM medical imaging: SOP class negotiation | IT devices | cyan | green | wifipilot itproto (DICOM A-ASSOCIATE and C-ECHO) | DICOM medical imaging traffic from an unexpected host to port 104: sop class negotiation — a service log or an IDS rule on the protocol sees it |
| `it_dicom_version` | DICOM medical imaging: calling AE title | IT devices | green | green | wifipilot itproto (DICOM A-ASSOCIATE and C-ECHO) | DICOM medical imaging traffic from an unexpected host to port 104: calling ae title — a service log or an IDS rule on the protocol sees it |
| `it_dicom_cleartext_audit` | DICOM medical imaging: dicom medical imaging without encryption | IT devices | green | bold green | wifipilot itproto (DICOM A-ASSOCIATE and C-ECHO) | A dicom handshake on port 104 to an unexpected host. |
| `it_s7comm_version` | Siemens S7 communication: component identification | IT devices | green | green | wifipilot itproto (ISO-TSAP COTP and S7comm SZL) | Siemens S7 communication traffic from an unexpected host to port 102: component identification — a service log or an IDS rule on the protocol sees it |
| `it_s7comm_unauth_read` | Siemens S7 communication: data block read | IT devices | cyan | bold green | wifipilot itproto (ISO-TSAP COTP and S7comm SZL) | Siemens S7 communication traffic from an unexpected host to port 102: data block read — a service log or an IDS rule on the protocol sees it |
| `it_s7comm_config_dump` | Siemens S7 communication: hardware configuration | IT devices | cyan | bold green | wifipilot itproto (ISO-TSAP COTP and S7comm SZL) | Siemens S7 communication traffic from an unexpected host to port 102: hardware configuration — a service log or an IDS rule on the protocol sees it |
| `it_s7comm_cleartext_audit` | Siemens S7 communication: siemens s7 communication without encryption | IT devices | green | bold green | wifipilot itproto (ISO-TSAP COTP and S7comm SZL) | A s7comm handshake on port 102 to an unexpected host. |
| `it_cip_version` | EtherNet/IP and CIP: product revision | IT devices | green | green | wifipilot itproto (EtherNet/IP encapsulation and List-Identity) | EtherNet/IP and CIP traffic from an unexpected host to port 44818: product revision — a service log or an IDS rule on the protocol sees it |
| `it_cip_unauth_read` | EtherNet/IP and CIP: identity object read | IT devices | cyan | bold green | wifipilot itproto (EtherNet/IP encapsulation and List-Identity) | EtherNet/IP and CIP traffic from an unexpected host to port 44818: identity object read — a service log or an IDS rule on the protocol sees it |
| `it_cip_cleartext_audit` | EtherNet/IP and CIP: ethernet/ip and cip without encryption | IT devices | green | bold green | wifipilot itproto (EtherNet/IP encapsulation and List-Identity) | A cip handshake on port 44818 to an unexpected host. |
| `it_dnp3_unauth_read` | DNP3 SCADA telemetry: integrity poll | IT devices | cyan | bold green | wifipilot itproto (DNP3 link layer with CRC-DNP and application frames) | DNP3 SCADA telemetry traffic from an unexpected host to port 20000: integrity poll — a service log or an IDS rule on the protocol sees it |
| `it_dnp3_version` | DNP3 SCADA telemetry: device attributes | IT devices | green | green | wifipilot itproto (DNP3 link layer with CRC-DNP and application frames) | DNP3 SCADA telemetry traffic from an unexpected host to port 20000: device attributes — a service log or an IDS rule on the protocol sees it |
| `it_dnp3_cleartext_audit` | DNP3 SCADA telemetry: dnp3 scada telemetry without encryption | IT devices | green | bold green | wifipilot itproto (DNP3 link layer with CRC-DNP and application frames) | A dnp3 handshake on port 20000 to an unexpected host. |
| `it_iec104_unauth_read` | IEC 60870-5-104 SCADA: general interrogation | IT devices | cyan | bold green | wifipilot itproto (IEC-104 APCI U/I/S frames) | IEC 60870-5-104 SCADA traffic from an unexpected host to port 2404: general interrogation — a service log or an IDS rule on the protocol sees it |
| `it_iec104_version` | IEC 60870-5-104 SCADA: common address | IT devices | green | green | wifipilot itproto (IEC-104 APCI U/I/S frames) | IEC 60870-5-104 SCADA traffic from an unexpected host to port 2404: common address — a service log or an IDS rule on the protocol sees it |
| `it_iec104_cleartext_audit` | IEC 60870-5-104 SCADA: iec 60870-5-104 scada without encryption | IT devices | green | bold green | wifipilot itproto (IEC-104 APCI U/I/S frames) | A iec104 handshake on port 2404 to an unexpected host. |
| `it_opcua_version` | OPC-UA server: buffer limits | IT devices | green | green | wifipilot itproto (OPC-UA HEL/ACK) | OPC-UA server traffic from an unexpected host to port 4840: buffer limits — a service log or an IDS rule on the protocol sees it |
| `it_opcua_endpoint_audit` | OPC-UA server: endpoint security | IT devices | green | green | wifipilot itproto (OPC-UA HEL/ACK) | OPC-UA server traffic from an unexpected host to port 4840: endpoint security — a service log or an IDS rule on the protocol sees it |
| `it_opcua_cleartext_audit` | OPC-UA server: opc-ua server without encryption | IT devices | green | bold green | wifipilot itproto (OPC-UA HEL/ACK) | A opcua handshake on port 4840 to an unexpected host. |
| `it_ssh_version` | SSH management: software version | IT devices | green | green | wifipilot itproto (SSH identification string and KEXINIT) | SSH management traffic from an unexpected host to port 22: software version — a service log or an IDS rule on the protocol sees it |
| `it_ssh_kex_audit` | SSH management: algorithm negotiation | IT devices | green | green | wifipilot itproto (SSH identification string and KEXINIT) | SSH management traffic from an unexpected host to port 22: algorithm negotiation — a service log or an IDS rule on the protocol sees it |
| `it_ssh_default_creds` | SSH management: default credentials | IT devices | cyan | bold green | wifipilot itproto (SSH identification string and KEXINIT) | SSH management traffic from an unexpected host to port 22: default credentials — a service log or an IDS rule on the protocol sees it |
| `it_rdp_nla_audit` | Remote desktop (RDP): network level authentication | IT devices | green | bold green | wifipilot itproto (RDP X.224 negotiation) | Remote desktop (RDP) traffic from an unexpected host to port 3389: network level authentication — a service log or an IDS rule on the protocol sees it |
| `it_rdp_version` | Remote desktop (RDP): protocol selection | IT devices | green | green | wifipilot itproto (RDP X.224 negotiation) | Remote desktop (RDP) traffic from an unexpected host to port 3389: protocol selection — a service log or an IDS rule on the protocol sees it |
| `it_postgres_anonymous` | PostgreSQL: trust authentication | IT devices | green | bold green | wifipilot itproto (Postgres startup and authentication request) | PostgreSQL traffic from an unexpected host to port 5432: trust authentication — a service log or an IDS rule on the protocol sees it |
| `it_postgres_version` | PostgreSQL: authentication method | IT devices | green | green | wifipilot itproto (Postgres startup and authentication request) | PostgreSQL traffic from an unexpected host to port 5432: authentication method — a service log or an IDS rule on the protocol sees it |
| `it_postgres_default_creds` | PostgreSQL: default credentials | IT devices | cyan | bold green | wifipilot itproto (Postgres startup and authentication request) | PostgreSQL traffic from an unexpected host to port 5432: default credentials — a service log or an IDS rule on the protocol sees it |
| `it_postgres_cleartext_audit` | PostgreSQL: postgresql without encryption | IT devices | green | bold green | wifipilot itproto (Postgres startup and authentication request) | A postgres handshake on port 5432 to an unexpected host. |
| `it_mysql_version` | MySQL / MariaDB: server version | IT devices | green | green | wifipilot itproto (MySQL initial handshake) | MySQL / MariaDB traffic from an unexpected host to port 3306: server version — a service log or an IDS rule on the protocol sees it |
| `it_mysql_tls_audit` | MySQL / MariaDB: TLS capability | IT devices | green | green | wifipilot itproto (MySQL initial handshake) | MySQL / MariaDB traffic from an unexpected host to port 3306: tls capability — a service log or an IDS rule on the protocol sees it |
| `it_mysql_default_creds` | MySQL / MariaDB: default credentials | IT devices | cyan | bold green | wifipilot itproto (MySQL initial handshake) | MySQL / MariaDB traffic from an unexpected host to port 3306: default credentials — a service log or an IDS rule on the protocol sees it |
| `it_mysql_cleartext_audit` | MySQL / MariaDB: mysql / mariadb without encryption | IT devices | green | bold green | wifipilot itproto (MySQL initial handshake) | A mysql handshake on port 3306 to an unexpected host. |
| `it_rsync_modules` | rsync daemon: module list | IT devices | green | bold green | wifipilot itproto (rsync daemon greeting) | rsync daemon traffic from an unexpected host to port 873: module list — a service log or an IDS rule on the protocol sees it |
| `it_rsync_unauth_read` | rsync daemon: module contents | IT devices | cyan | bold green | wifipilot itproto (rsync daemon greeting) | rsync daemon traffic from an unexpected host to port 873: module contents — a service log or an IDS rule on the protocol sees it |
| `it_rsync_version` | rsync daemon: daemon version | IT devices | green | green | wifipilot itproto (rsync daemon greeting) | rsync daemon traffic from an unexpected host to port 873: daemon version — a service log or an IDS rule on the protocol sees it |
| `it_rsync_cleartext_audit` | rsync daemon: rsync daemon without encryption | IT devices | green | bold green | wifipilot itproto (rsync daemon greeting) | A rsync handshake on port 873 to an unexpected host. |
| `it_ftp_version` | FTP service: server software | IT devices | green | green | wifipilot itproto (FTP command and reply lines) | FTP service traffic from an unexpected host to port 21: server software — a service log or an IDS rule on the protocol sees it |
| `it_ftp_anonymous` | FTP service: anonymous login | IT devices | green | bold green | wifipilot itproto (FTP command and reply lines) | FTP service traffic from an unexpected host to port 21: anonymous login — a service log or an IDS rule on the protocol sees it |
| `it_ftp_default_creds` | FTP service: default credentials | IT devices | cyan | bold green | wifipilot itproto (FTP command and reply lines) | FTP service traffic from an unexpected host to port 21: default credentials — a service log or an IDS rule on the protocol sees it |
| `it_ftp_cleartext` | FTP service: FTP in the clear | IT devices | green | green | wifipilot itproto (FTP command and reply lines) | FTP service traffic from an unexpected host to port 21: ftp in the clear — a service log or an IDS rule on the protocol sees it |
| `it_smtp_version` | SMTP mail server: MTA identification | IT devices | green | green | wifipilot itproto (SMTP EHLO/MAIL/RCPT) | SMTP mail server traffic from an unexpected host to port 25: mta identification — a service log or an IDS rule on the protocol sees it |
| `it_smtp_open_relay` | SMTP mail server: relay decision | IT devices | cyan | yellow | wifipilot itproto (SMTP EHLO/MAIL/RCPT) | SMTP mail server traffic from an unexpected host to port 25: relay decision — a service log or an IDS rule on the protocol sees it |
| `it_smtp_starttls_audit` | SMTP mail server: STARTTLS availability | IT devices | green | green | wifipilot itproto (SMTP EHLO/MAIL/RCPT) | SMTP mail server traffic from an unexpected host to port 25: starttls availability — a service log or an IDS rule on the protocol sees it |
| `it_smtp_cleartext` | SMTP mail server: SMTP in the clear | IT devices | green | green | wifipilot itproto (SMTP EHLO/MAIL/RCPT) | SMTP mail server traffic from an unexpected host to port 25: smtp in the clear — a service log or an IDS rule on the protocol sees it |
| `it_miio_token` | Xiaomi miIO device: token disclosure | IT devices | green | bold green | wifipilot itproto (miIO hello) | Xiaomi miIO device traffic from an unexpected host to port 54321: token disclosure — a service log or an IDS rule on the protocol sees it |
| `it_miio_version` | Xiaomi miIO device: device identity | IT devices | green | green | wifipilot itproto (miIO hello) | Xiaomi miIO device traffic from an unexpected host to port 54321: device identity — a service log or an IDS rule on the protocol sees it |
| `it_miio_cleartext_audit` | Xiaomi miIO device: xiaomi miio device without encryption | IT devices | green | bold green | wifipilot itproto (miIO hello) | A miio handshake on port 54321 to an unexpected host. |
| `it_ssdp_version` | UPnP / SSDP: product string | IT devices | green | green | wifipilot itproto (SSDP M-SEARCH) | UPnP / SSDP traffic from an unexpected host to port 1900: product string — a service log or an IDS rule on the protocol sees it |
| `it_ssdp_unauth_write` | UPnP / SSDP: port mapping request | IT devices | green | yellow | wifipilot itproto (SSDP M-SEARCH) | UPnP / SSDP traffic from an unexpected host to port 1900: port mapping request — a service log or an IDS rule on the protocol sees it |
| `it_ssdp_cleartext_audit` | UPnP / SSDP: upnp / ssdp without encryption | IT devices | green | bold green | wifipilot itproto (SSDP M-SEARCH) | A ssdp handshake on port 1900 to an unexpected host. |
| `it_mdns_config_dump` | mDNS / DNS-SD: TXT records | IT devices | green | green | wifipilot itproto (mDNS query) | mDNS / DNS-SD traffic from an unexpected host to port 5353: txt records — a service log or an IDS rule on the protocol sees it |
| `it_mdns_cleartext_audit` | mDNS / DNS-SD: mdns / dns-sd without encryption | IT devices | green | bold green | wifipilot itproto (mDNS query) | A mdns handshake on port 5353 to an unexpected host. |
| `it_default_credential_sweep` | default credential sweep | IT devices | cyan | bold green | wifipilot itproto + itsim (real protocol probes) | a sweep of 7 service port(s) across the segment: connection logs and service logs show one client greeting everything |

### Denial-of-service tests (opt-in) — 82

| attack | answers | edition | noise | impact | tool | defender sees |
| --- | --- | --- | --- | --- | --- | --- |
| `deauth_flood` <br>_injects_ | Deauthentication flood (detection test) | WiFi | red | red | mdk4 d (or aireplay-ng -0) | every client of the AP is disconnected, repeatedly |
| `auth_flood` <br>_injects_ | Authentication flood (state exhaustion test) | WiFi | yellow | yellow | mdk4 a | thousands of authentication frames from fake stations |
| `assoc_flood` <br>_injects_ | Association flood (state exhaustion) | WiFi | yellow | yellow | wifipilot rawtx.py (association requests) | thousands of association requests; the association table fills |
| `null_data_flood` <br>_injects_ | Null-data flood (power-save buffer exhaustion) | WiFi | yellow | yellow | wifipilot rawtx.py (QoS Null, PS bit) | QoS Null frames only — no deauth frames at all, so deauth-based WIDS rules do not fire |
| `probe_flood` <br>_injects_ | Probe flood (hidden-SSID disclosure test) | WiFi | yellow | yellow | mdk4 p | a dictionary of directed probe requests |
| `eapol_start_flood` <br>_injects_ | EAPOL-Start flood (802.1X session exhaustion) | WiFi | yellow | yellow | wifipilot rawtx.py (EAPOL-Start) | EAPOL-Starts from fake supplicants; the RADIUS server holds half-open sessions |
| `sae_commit_flood` <br>_injects_ | SAE commit flood (WPA3 CPU exhaustion) | WiFi | yellow | yellow | wifipilot rawtx.py (SAE commit frames) | SAE commit frames from fake stations; anti-clogging tokens are the mitigation |
| `tkip_michael` <br>_injects_ | TKIP Michael countermeasure (capture replay) | WiFi | red | red | wifipilot rawtx.py (captured TKIP frames, MIC corrupted) | TKIP MIC failures trigger the AP's 60-second Michael countermeasure shutdown |
| `wids_confusion` <br>_injects_ | WIDS attribution confusion (spoofed transmitter test) | WiFi | red | yellow | wifipilot rawtx.py (deauth frames, foreign BSSID) | attack frames from a list of spoofed transmitters; the test is whether the site's monitoring can tell |
| `beacon_flood` <br>_injects_ | Beacon flood (WIDS test) | WiFi | red | yellow | mdk4 b | hundreds of phantom SSIDs in every scan list |
| `disassoc_flood` <br>_injects_ | Disassociation flood | WiFi | red | red | wifipilot rawtx.py (disassociation frames) | disassociation frames in a loop: every client of the AP drops, and rules that count deauths do not fire |
| `rts_flood` <br>_injects_ | RTS/NAV flood (medium reservation) | WiFi | red | yellow | wifipilot rawtx.py (RTS frames) | RTS frames with a maximal duration reserve the medium and are never answered: control frames only |
| `cts_flood` <br>_injects_ | CTS-to-self flood (quiet NAV attack) | WiFi | red | yellow | wifipilot rawtx.py (CTS frames) | CTS-to-self frames hold the channel silent; no management frame is on air at all |
| `channel_switch_flood` <br>_injects_ | Channel-switch flood (clients chase a quiet channel) | WiFi | yellow | red | wifipilot rawtx.py (CSA beacons) | beacons carrying CSA elements, one channel move after another |
| `sa_query_flood` <br>_injects_ | SA Query flood (PMF association state) | WiFi | yellow | yellow | wifipilot rawtx.py (SA Query action frames) | SA Query requests with rotating tokens: the AP's association state is walked at frame rate |
| `tdls_teardown_flood` <br>_injects_ | TDLS teardown flood (direct links dropped) | WiFi | yellow | yellow | wifipilot rawtx.py (TDLS action frames) | TDLS Teardown action frames break direct links and push traffic through the AP |
| `probe_response_flood` <br>_injects_ | Probe response flood (phantom scan lists) | WiFi | yellow | yellow | wifipilot rawtx.py (probe responses) | probe responses from BSSIDs that do not exist: client scan lists fill with phantoms |
| `dhcp_discover_flood` <br>_injects_ | DHCP DISCOVER flood (lease pool exhaustion) | WiFi | yellow | yellow | wifipilot netproto.py + rawtx.py (UDP broadcast) | DHCP DISCOVER broadcasts from fake stations walk the server through its pool |
| `bt_adv_name_flood` <br>_injects_ | Advertising name flood | Bluetooth | red | yellow | wifipilot bt.py (LE Set Advertising Data in a loop) | the capture itself |
| `bt_adv_dos` <br>_injects_ | Advertising channel DoS | Bluetooth | red | yellow | wifipilot bt.py (continuous advertising on all three channels) | the capture itself |
| `bt_pairing_flood` <br>_injects_ | Pairing request flood | Bluetooth | red | yellow | wifipilot bt.py (repeated pairing requests over a connection) | the capture itself |
| `bt_l2cap_echo_flood` <br>_injects_ | L2CAP echo request flood | Bluetooth | red | yellow | wifipilot bt.py (L2CAP signalling echo requests) | the capture itself |
| `ble_conn_param_hijack` <br>_injects_ | LE connection parameter hijack (link starvation) | Bluetooth | yellow | yellow | wifipilot bt.py (LL_CONNECTION_UPDATE_REQ over ACL) | An LL_CONNECTION_UPDATE_REQ from a peer that was never paired, and a device whose radio stays busy: the host's own controller log carries the request, and the battery drain shows up long before anybody reads the log. |
| `ble_gatt_char_fuzz` <br>_injects_ | BLE characteristic fuzz (write malformed values, count the answers) | Bluetooth | yellow | yellow | wifipilot blesim.py (ATT write fuzzing) | A run of malformed ATT writes: the device's log carries the errors, and a stack that handles them badly shows up as a disconnect. |
| `ble_gatt_read_flood` <br>_injects_ | BLE read flood (resource exhaustion on the attribute server) | Bluetooth | yellow | yellow | wifipilot blesim.py (repeated ATT reads) | Sixty reads of one attribute from one connection: the device's ATT log shows the burst, and its battery graph shows the cost. |
| `ble_adv_flood_le` <br>_injects_ | BLE advertising flood (fill the channels with advertisements) | Bluetooth | yellow | yellow | wifipilot bt.py (advertising) + blesim.py | A flood of advertisements from one address: an advertising monitor shows the address changing name dozens of times a minute, and every other advertiser's signal-to-noise falls. |
| `ble_scan_hog` <br>_injects_ | BLE scan hog (full-duty scanning next to a live link) | Bluetooth | yellow | yellow | wifipilot bt.py (LE Set Scan Parameters/Enable) + blesim.py | One address scanning continuously: a sniffer sees the scan requests and the controller's own radio scheduling shows the duty cycle. |
| `ble_conn_flood_le` <br>_injects_ | BLE connection flood (repeat LE Create Connection) | Bluetooth | yellow | yellow | wifipilot bt.py (LE Create Connection) + blesim.py | One address connecting repeatedly in seconds: the peer's connection log carries the burst, and its battery graph carries the cost. |
| `ble_conn_param_starve` <br>_injects_ | BLE connection starvation (a four-second connection interval) | Bluetooth | cyan | yellow | wifipilot bt.py (LL_CONNECTION_UPDATE_IND) + blesim.py | A connection update that no application asked for: the peer's controller log carries the new parameters, and the application sees its latency rise. |
| `ble_phy_request` <br>_injects_ | BLE PHY request (ask the link to leave the fast PHY) | Bluetooth | cyan | yellow | wifipilot bt.py (LL_PHY_REQ) + blesim.py | A PHY update with no application behind it: the peer's controller log carries the request and the connection's throughput curve shows the change. |
| `ble_data_length_abuse` <br>_injects_ | BLE data length abuse (LL_LENGTH_REQ at the maximum) | Bluetooth | cyan | green | wifipilot bt.py (LL_LENGTH_REQ) + blesim.py | A data-length negotiation from a peripheral: it is a legitimate procedure, and the anomaly is only in the values and the timing. |
| `ble_ll_unknown_probe` <br>_injects_ | BLE link-layer unknown-PDU probe (what the stack refuses) | Bluetooth | cyan | green | wifipilot bt.py (LL_CONTROL_OPCODES) + blesim.py | A run of link-layer PDUs no procedure called for: the peer's controller log carries the opcodes, and a stack that registers them shows the sweep. |
| `ble_pairing_flood_le` <br>_injects_ | BLE pairing flood (repeat the pairing exchange) | Bluetooth | yellow | red | wifipilot bt.py (SMP pairing request) + blesim.py | Forty pairing requests in a minute: the device's log carries the flood, and a pairing mode that stays open shows the attempts to the user. |
| `ble_pair_lockout_probe` <br>_injects_ | BLE pairing lockout probe (does the device ever stop accepting?) | Bluetooth | yellow | red | wifipilot bt.py (SMP pairing failed) + blesim.py | Repeated pairing failures from one address: the device's log carries the reason codes, and a pairing window that stays open shows them. |
| `it_fuzz_dns_name` | DNS name fuzzing (labels and a total length past the limit) | IT devices | cyan | yellow | wifipilot itproto.py (dns_query) + UDP 53 | a dns request on port 53 that is legal in shape and illegal in size (labels, dialects, varbinds, verbs) from one address, repeated; the service's log shows the parse error and any restart that follows it |
| `it_fuzz_smb2_negotiate` | SMB2 negotiate fuzzing (dialects the server has to reject) | IT devices | cyan | yellow | wifipilot itproto.py (smb2_negotiate) + TCP 445 | a smb request on port 445 that is legal in shape and illegal in size (labels, dialects, varbinds, verbs) from one address, repeated; the service's log shows the parse error and any restart that follows it |
| `it_fuzz_ldap_filter` | LDAP filter fuzzing (deeply nested search filter) | IT devices | cyan | yellow | wifipilot itproto.py (ldap_search_request/parse_ldap) + TCP 389 | a ldap request on port 389 that is legal in shape and illegal in size (labels, dialects, varbinds, verbs) from one address, repeated; the service's log shows the parse error and any restart that follows it |
| `it_fuzz_rtsp_method` | RTSP method fuzzing (an unknown verb of illegal length) | IT devices | cyan | yellow | wifipilot itproto.py (rtsp_request/parse_rtsp) + TCP 554 | a rtsp request on port 554 that is legal in shape and illegal in size (labels, dialects, varbinds, verbs) from one address, repeated; the service's log shows the parse error and any restart that follows it |
| `it_fuzz_mqtt_topic` | MQTT topic fuzzing (a filter with a thousand levels) | IT devices | cyan | yellow | wifipilot itproto.py (mqtt_subscribe/parse_mqtt) + TCP 1883 | a mqtt request on port 1883 that is legal in shape and illegal in size (labels, dialects, varbinds, verbs) from one address, repeated; the service's log shows the parse error and any restart that follows it |
| `it_fuzz_modbus_function` | Modbus function fuzzing (an unimplemented code on a live PLC) | IT devices | cyan | yellow | wifipilot itproto.py (modbus_request/parse_modbus) + TCP 502 | a modbus request on port 502 that is legal in shape and illegal in size (labels, dialects, varbinds, verbs) from one address, repeated; the service's log shows the parse error and any restart that follows it |
| `it_fuzz_snmp_varbind` | SNMP varbind fuzzing (300 OIDs in a single get) | IT devices | cyan | yellow | wifipilot attacks/ithijack.py (_ber) + UDP 161 | a snmp request on port 161 that is legal in shape and illegal in size (labels, dialects, varbinds, verbs) from one address, repeated; the service's log shows the parse error and any restart that follows it |
| `it_fuzz_sip_uri` | SIP URI fuzzing (an oversized request line at the registrar) | IT devices | cyan | yellow | wifipilot itproto.py (sip_request/parse_sip) + UDP 5060 | a sip request on port 5060 that is legal in shape and illegal in size (labels, dialects, varbinds, verbs) from one address, repeated; the service's log shows the parse error and any restart that follows it |
| `dhcp_starvation` <br>_injects_ | DHCP starvation (lease pool exhaustion) | WiFi | yellow | yellow | wifipilot netproto.py (DHCP + client identifiers) | thousands of DHCP transactions from fabricated client identifiers: a DHCP log shows the pool emptying, and a DHCP snooping switch shows the rate |
| `dhcp_flood` <br>_injects_ | DHCP flood (request-rate exhaustion) | WiFi | red | yellow | wifipilot netproto.py (mixed DHCP message types) | an extreme rate of DHCP messages on one access point: visible in any DHCP log, and in the AP's own client table |
| `syn_flood` <br>_injects_ | TCP SYN flood (connection-table exhaustion) | WiFi | red | yellow | wifipilot netstack.py (TCP headers, spoofed sources) | a burst of SYNs with source addresses that never complete a handshake: the target's connection table fills and its logs show hundreds of half-open sessions |
| `udp_flood` <br>_injects_ | UDP flood / router resource exhaustion | WiFi | red | yellow | wifipilot netstack.py (UDP to the router's own stack) | datagrams to closed ports at line rate, and an ICMP port-unreachable for each: the router's own CPU is visibly busy |
| `udp_reflection` <br>_injects_ | UDP reflection (SSDP, mDNS, NetBIOS) | WiFi | red | yellow | wifipilot netstack.py (broadcast queries with a spoofed source) | broadcast queries whose source address is not the sender's, answered by every device that speaks the protocol |
| `ra_flood` <br>_injects_ | IPv6 router advertisement flood | WiFi | yellow | red | wifipilot netstack.py (RA flood with prefix churn) | router advertisements at a rate no router uses, with rotating sources and prefixes |
| `bt_blueborne` <br>_injects_ | BlueBorne probe (L2CAP/SDP stack, CVE-2017-1000250/1000251) | Bluetooth | cyan | yellow | wifipilot bt.py (L2CAP signalling and SDP PDUs over ACL) | an ACL link that speaks malformed L2CAP on the signalling channel: a controller log shows the PDUs, and the target's own dmesg shows the crash if there is one |
| `bt_sweyntooth` <br>_injects_ | SweynTooth malformed LL control battery (CVE-2019-17060 family) | Bluetooth | cyan | yellow | wifipilot bt.py (LL control PDUs over an LE connection) | malformed LL control PDUs on an LE link: a sniffer sees them, and a device that stops advertising is the symptom the users report |
| `bt_bluesmack` <br>_injects_ | BlueSmack (oversized L2CAP echo) | Bluetooth | yellow | yellow | wifipilot bt.py (L2CAP echo requests at escalating sizes) | an L2CAP echo request larger than any normal signalling PDU: visible to a sniffer, and a device that stops answering is visible to its user |
| `krack_replay` <br>_injects_ | KRACK key reinstallation (CVE-2017-13077 playback) | WiFi | yellow | yellow | wifipilot rawtx.py (message 3 replayed from the captured handshake) | message 3 retransmitted from a station that is not the AP: a WIDS with EAPOL sequencing sees the duplicate, and a client that logs its own handshakes sees the reinstall |
| `fragattacks_inject` <br>_injects_ | FragAttacks plaintext injection (CVE-2020-24588/24586/24587) | WiFi | yellow | yellow | wifipilot rawtx.py (A-MSDU and fragment-cache shapes) | plaintext aggregation and fragment sequences on a channel whose clients are encrypted: a sniffer sees the A-MSDU present bit on an unencrypted frame, which the standard says cannot happen |
| `it_http_flood` | Web management interface: management request flood | IT devices | yellow | yellow | wifipilot itproto (HTTP/1.1 request builder) | Web management interface traffic from an unexpected host to port 80: management request flood — a service log or an IDS rule on the protocol sees it |
| `it_mqtt_flood` | MQTT broker: CONNECT flood | IT devices | yellow | yellow | wifipilot itproto (MQTT 3.1.1/5.0 CONNECT, PUBLISH, SUBSCRIBE) | MQTT broker traffic from an unexpected host to port 1883: connect flood — a service log or an IDS rule on the protocol sees it |
| `it_coap_flood` | CoAP endpoint: notification storm | IT devices | yellow | yellow | wifipilot itproto (CoAP RFC 7252 GET/POST with options) | CoAP endpoint traffic from an unexpected host to port 5683: notification storm — a service log or an IDS rule on the protocol sees it |
| `it_modbus_flood` | Modbus/TCP controller: write loop | IT devices | red | red | wifipilot itproto (Modbus TCP MBAP, function codes 1-43) | Modbus/TCP controller traffic from an unexpected host to port 502: write loop — a service log or an IDS rule on the protocol sees it |
| `it_bacnet_flood` | BACnet building controller: Who-Is storm | IT devices | red | red | wifipilot itproto (BACnet/IP BVLC, Who-Is, Read-Property) | BACnet building controller traffic from an unexpected host to port 47808: who-is storm — a service log or an IDS rule on the protocol sees it |
| `it_rtsp_flood` | RTSP video stream: DESCRIBE storm | IT devices | yellow | yellow | wifipilot itproto (RTSP OPTIONS/DESCRIBE/PLAY, SDP) | RTSP video stream traffic from an unexpected host to port 554: describe storm — a service log or an IDS rule on the protocol sees it |
| `it_ipp_flood` | IPP print service: attribute request flood | IT devices | yellow | yellow | wifipilot itproto (IPP RFC 8010/8011) | IPP print service traffic from an unexpected host to port 631: attribute request flood — a service log or an IDS rule on the protocol sees it |
| `it_pjl_flood` | PJL printer command port: echo flood | IT devices | yellow | yellow | wifipilot itproto (PJL @PJL INFO/USTATUS) | PJL printer command port traffic from an unexpected host to port 9100: echo flood — a service log or an IDS rule on the protocol sees it |
| `it_sip_flood` | SIP telephony: OPTIONS flood | IT devices | yellow | yellow | wifipilot itproto (SIP OPTIONS/REGISTER, digest challenge parsing) | SIP telephony traffic from an unexpected host to port 5060: options flood — a service log or an IDS rule on the protocol sees it |
| `it_smb_flood` | SMB file sharing: negotiate flood | IT devices | yellow | yellow | wifipilot itproto (SMB2 NEGOTIATE, NetBIOS) | SMB file sharing traffic from an unexpected host to port 445: negotiate flood — a service log or an IDS rule on the protocol sees it |
| `it_ldap_flood` | LDAP directory: bind flood | IT devices | yellow | yellow | wifipilot itproto (LDAP bindRequest and rootDSE search) | LDAP directory traffic from an unexpected host to port 389: bind flood — a service log or an IDS rule on the protocol sees it |
| `it_redis_flood` | Redis data store: command flood | IT devices | yellow | yellow | wifipilot itproto (Redis RESP) | Redis data store traffic from an unexpected host to port 6379: command flood — a service log or an IDS rule on the protocol sees it |
| `it_memcached_flood` | Memcached: stats flood | IT devices | yellow | yellow | wifipilot itproto (memcached text protocol) | Memcached traffic from an unexpected host to port 11211: stats flood — a service log or an IDS rule on the protocol sees it |
| `it_mongo_flood` | MongoDB: connection flood | IT devices | yellow | yellow | wifipilot itproto (MongoDB OP_MSG hello) | MongoDB traffic from an unexpected host to port 27017: connection flood — a service log or an IDS rule on the protocol sees it |
| `it_kasa_flood` | TP-Link Kasa / smart home: datagram flood | IT devices | yellow | red | wifipilot itproto (Kasa autokey XOR framing) | TP-Link Kasa / smart home traffic from an unexpected host to port 9999: datagram flood — a service log or an IDS rule on the protocol sees it |
| `it_cast_flood` | Cast / Chromecast service: CONNECT flood | IT devices | yellow | yellow | wifipilot itproto (CASTV2 message framing) | Cast / Chromecast service traffic from an unexpected host to port 8009: connect flood — a service log or an IDS rule on the protocol sees it |
| `it_adb_flood` | Android debug bridge: connection flood | IT devices | yellow | yellow | wifipilot itproto (ADB CNXN/AUTH framing) | Android debug bridge traffic from an unexpected host to port 5555: connection flood — a service log or an IDS rule on the protocol sees it |
| `it_vnc_flood` | VNC remote desktop: handshake flood | IT devices | yellow | yellow | wifipilot itproto (RFB version and security types) | VNC remote desktop traffic from an unexpected host to port 5900: handshake flood — a service log or an IDS rule on the protocol sees it |
| `it_pjlink_flood` | PJLink projector control: poll flood | IT devices | yellow | yellow | wifipilot itproto (PJLink %1 commands) | PJLink projector control traffic from an unexpected host to port 4352: poll flood — a service log or an IDS rule on the protocol sees it |
| `it_dicom_flood` | DICOM medical imaging: association flood | IT devices | yellow | yellow | wifipilot itproto (DICOM A-ASSOCIATE and C-ECHO) | DICOM medical imaging traffic from an unexpected host to port 104: association flood — a service log or an IDS rule on the protocol sees it |
| `it_s7comm_flood` | Siemens S7 communication: connect flood | IT devices | yellow | yellow | wifipilot itproto (ISO-TSAP COTP and S7comm SZL) | Siemens S7 communication traffic from an unexpected host to port 102: connect flood — a service log or an IDS rule on the protocol sees it |
| `it_cip_flood` | EtherNet/IP and CIP: identity flood | IT devices | yellow | yellow | wifipilot itproto (EtherNet/IP encapsulation and List-Identity) | EtherNet/IP and CIP traffic from an unexpected host to port 44818: identity flood — a service log or an IDS rule on the protocol sees it |
| `it_dnp3_flood` | DNP3 SCADA telemetry: reset flood | IT devices | yellow | yellow | wifipilot itproto (DNP3 link layer with CRC-DNP and application frames) | DNP3 SCADA telemetry traffic from an unexpected host to port 20000: reset flood — a service log or an IDS rule on the protocol sees it |
| `it_iec104_flood` | IEC 60870-5-104 SCADA: start-stop flood | IT devices | yellow | yellow | wifipilot itproto (IEC-104 APCI U/I/S frames) | IEC 60870-5-104 SCADA traffic from an unexpected host to port 2404: start-stop flood — a service log or an IDS rule on the protocol sees it |
| `it_opcua_flood` | OPC-UA server: hello flood | IT devices | yellow | yellow | wifipilot itproto (OPC-UA HEL/ACK) | OPC-UA server traffic from an unexpected host to port 4840: hello flood — a service log or an IDS rule on the protocol sees it |
| `it_ssh_flood` | SSH management: handshake flood | IT devices | yellow | yellow | wifipilot itproto (SSH identification string and KEXINIT) | SSH management traffic from an unexpected host to port 22: handshake flood — a service log or an IDS rule on the protocol sees it |
| `it_rdp_flood` | Remote desktop (RDP): connection flood | IT devices | yellow | yellow | wifipilot itproto (RDP X.224 negotiation) | Remote desktop (RDP) traffic from an unexpected host to port 3389: connection flood — a service log or an IDS rule on the protocol sees it |
| `it_postgres_flood` | PostgreSQL: connection flood | IT devices | yellow | yellow | wifipilot itproto (Postgres startup and authentication request) | PostgreSQL traffic from an unexpected host to port 5432: connection flood — a service log or an IDS rule on the protocol sees it |
| `it_miio_flood` | Xiaomi miIO device: hello flood | IT devices | yellow | yellow | wifipilot itproto (miIO hello) | Xiaomi miIO device traffic from an unexpected host to port 54321: hello flood — a service log or an IDS rule on the protocol sees it |

## 12. The editions and the device shelf

Every attack is stamped with an **edition** (which toolbox it belongs to) and with the **device types** it works against. That is what the web UI's edition switch and device picker are drawn from, what `wifipilot --edition` selects, and what `wifipilot.itdev.classify` returns when you point the tool at a fingerprint:

| device type | edition | group | ports | answers | attacks |
| --- | --- | --- | --- | --- | --- |
| **Router / residential gateway** (`router`) | IT devices | Network infrastructure | `53, 80, 443, 1900, 5353, 7547, 8080` | mdns, ssdp, upnp, http, tr069, dns | 69 — `it_mimic_dns`, `it_mimic_dhcp`, `it_mimic_ntp`, `it_mimic_syslog`, `it_mimic_mdns`, +64 more |
| **Firewall / UTM appliance** (`firewall`) | IT devices | Network infrastructure | `443, 4443, 500, 4500, 8443` | tls, http, ssh | 15 — `it_mimic_dhcp`, `it_mimic_syslog`, `it_fuzz_dns_name`, `it_fuzz_snmp_varbind`, `it_survey_cwmp_parameters`, +10 more |
| **Managed switch** (`switch`) | IT devices | Network infrastructure | `22, 23, 80, 161, 443` | snmp, telnet, ssh, lldp, http | 53 — `ble_lock_mimic`, `ble_plug_mimic`, `it_mimic_dhcp`, `it_mimic_syslog`, `it_mimic_tftp`, +48 more |
| **Access point** (`access_point`) | WiFi | Network infrastructure | `22, 80, 443, 161, 8080` | http, ssh, snmp, mdns | 95 — `ble_lock_mesh_mimic`, `ble_uwb_anchor_mimic`, `twin_address_clone`, `twin_element_clone`, `twin_rsn_strip`, +90 more |
| **VPN concentrator** (`vpn_gateway`) | IT devices | Network infrastructure | `443, 500, 4500, 10443` | ike, tls, http | 2 — `it_mimic_dhcp`, `it_mimic_tftp` |
| **Modem / ONT** (`modem_ont`) | IT devices | Network infrastructure | `80, 443, 7547` | tr069, http, dns | 12 — `it_mimic_dns`, `it_mimic_dhcp`, `it_hijack_cwmp`, `it_poison_dns`, `it_poison_dhcp_option`, +7 more |
| **Wireless LAN controller** (`wireless_controller`) | WiFi | Network infrastructure | `22, 80, 443, 161` | http, ssh, snmp | 1 — `ble_uwb_anchor_mimic` |
| **IP camera** (`ip_camera`) | IT devices | IoT and embedded | `80, 443, 554, 8000, 8080, 8554` | rtsp, onvif, http, mdns | 36 — `ble_doorbell_mimic`, `it_mimic_rtsp`, `it_impersonate_onvif`, `it_hijack_rtsp`, `it_hijack_onvif_uri`, +31 more |
| **NVR / DVR** (`nvr_dvr`) | IT devices | IoT and embedded | `80, 443, 554, 8000, 8080, 34567` | rtsp, onvif, http | 34 — `it_mimic_rtsp`, `it_impersonate_onvif`, `it_hijack_rtsp`, `it_hijack_onvif_uri`, `it_steal_camera_stream`, +29 more |
| **Video doorbell / intercom** (`doorbell`) | IT devices | IoT and embedded | `80, 443, 5060, 8000` | http, sip, onvif, mdns | 21 — `ble_doorbell_mimic`, `it_mimic_sip`, `it_steal_badge_db`, `it_fuzz_sip_uri`, `it_impersonate_sip_pbx`, +16 more |
| **Access control reader** (`badge_reader`) | IT devices | IoT and embedded | `80, 443, 4070` | http, osdp, serial | 9 — `ble_badge_mimic`, `ble_anchor_mimic`, `ble_ibeacon_mimic`, `ble_gatt_value_dump`, `ble_irk_crack`, +4 more |
| **Alarm / intrusion panel** (`alarm_panel`) | IT devices | IoT and embedded | `80, 443, 5000, 3060` | http, proprietary | 2 — `ble_doorbell_mimic`, `it_steal_badge_db` |
| **Smart home hub / bridge** (`gateway_hub`) | IT devices | IoT and embedded | `80, 443, 6667, 8080` | http, mdns, zigbee_gateway | 21 — `ble_mesh_lamp_mimic`, `ble_ir_hub_mimic`, `ble_uwb_anchor_mimic`, `ble_ibeacon_mimic`, `it_mimic_mqtt`, +16 more |
| **Wireless sensor / detector** (`sensor`) | IT devices | IoT and embedded | `80, 161, 5353` | mdns, snmp, http | 31 — `ble_thermostat_mimic`, `ble_scale_mimic`, `ble_air_quality_mimic`, `it_mimic_mqtt`, `it_mimic_coap`, +26 more |
| **Network printer** (`printer`) | IT devices | IoT and embedded | `80, 161, 443, 515, 631, 9100` | pjl, ipp, snmp, http, telnet | 81 — `ble_printer_mimic`, `ble_label_printer_mimic`, `ble_vending_mimic`, `it_mimic_pjl`, `it_mimic_mdns`, +76 more |
| **MFP / scanner** (`mfp_scanner`) | IT devices | IoT and embedded | `80, 139, 443, 445, 631, 9100` | pjl, ipp, smb, http | 49 — `ble_label_printer_mimic`, `it_mimic_pjl`, `it_impersonate_ipp`, `it_hijack_pjl_job`, `it_poison_netbios`, +44 more |
| **Label / receipt printer** (`label_printer`) | IT devices | IoT and embedded | `80, 443, 9100` | pjl, ipp, http | 23 — `ble_printer_mimic`, `ble_label_printer_mimic`, `it_mimic_pjl`, `it_impersonate_ipp`, `it_relay_ipp`, +18 more |
| **NAS / file share** (`nas`) | IT devices | Servers and storage | `22, 111, 139, 443, 445, 2049, 5000, 873` | smb, nfs, rsync, ssh, http, http_json | 90 — `it_mimic_mdns`, `it_hijack_http_session`, `it_poison_arp_gateway`, `it_poison_netbios`, `it_poison_mdns`, +85 more |
| **Backup appliance** (`backup_appliance`) | IT devices | Servers and storage | `22, 443, 3260, 8000` | http, ssh, iscsi | 46 — `it_poison_smb_negotiate`, `it_relay_postgres`, `it_relay_mysql`, `it_steal_sql_dump`, `it_mimic_ftp`, +41 more |
| **Virtualisation host** (`hypervisor_host`) | IT devices | Servers and storage | `22, 443, 5988, 8006` | http, ssh, cim | 40 — `it_mimic_ntp`, `it_impersonate_docker`, `it_poison_rdp_negotiation`, `it_steal_k8s_secrets`, `it_steal_docker_images`, +35 more |
| **Linux server** (`linux_server`) | IT devices | Servers and storage | `22, 80, 443, 3306, 5432, 6379` | ssh, http, redis, mysql, postgres, tls | 104 — `ble_fido_mimic`, `ble_mouse_mimic`, `ble_combo_dongle_mimic`, `it_mimic_ntp`, `it_mimic_syslog`, +99 more |
| **Windows server** (`windows_server`) | IT devices | Servers and storage | `135, 139, 445, 3389, 5985` | smb, rdp, netbios, winrm | 51 — `ble_mouse_mimic`, `ble_combo_dongle_mimic`, `it_poison_netbios`, `it_poison_ldap_referral`, `it_poison_smb_negotiate`, +46 more |
| **Domain controller / identity server** (`domain_controller`) | IT devices | Servers and storage | `53, 88, 389, 445, 636, 3268` | ldap, kerberos, dns, smb | 33 — `it_mimic_dns`, `it_mimic_ntp`, `it_mimic_syslog`, `it_poison_arp_gateway`, `it_poison_dns`, +28 more |
| **Mail server** (`mail_server`) | IT devices | Servers and storage | `25, 110, 143, 443, 465, 587, 993` | smtp, imap, http, tls | 20 — `it_mimic_smtp`, `it_mimic_imap`, `it_relay_smtp`, `it_relay_imap`, `it_hijack_smtp_relay`, +15 more |
| **Database server** (`database_server`) | IT devices | Servers and storage | `1433, 3306, 5432, 6379, 9200, 27017` | mysql, postgres, redis, mongodb, elastic, mssql | 58 — `it_relay_redis`, `it_relay_memcached`, `it_relay_mongo`, `it_relay_postgres`, `it_relay_mysql`, +53 more |
| **Container host / orchestrator** (`container_host`) | IT devices | Servers and storage | `2375, 2376, 5000, 6443, 8080, 10250` | docker, kubernetes, http, registry | 40 — `it_impersonate_docker`, `it_relay_redis`, `it_relay_memcached`, `it_relay_mongo`, `it_steal_k8s_secrets`, +35 more |
| **Web / application server** (`web_server`) | IT devices | Servers and storage | `80, 443, 8080, 8443` | http, http_json, tls | 43 — `it_impersonate_stun`, `it_relay_memcached`, `it_relay_mysql`, `it_steal_sql_dump`, `it_mimic_smtp`, +38 more |
| **CI / build server** (`ci_server`) | IT devices | Servers and storage | `80, 443, 8080, 8443` | http_json, http, tls | 17 — `it_steal_k8s_secrets`, `it_relay_jenkins`, `it_relay_kubernetes`, `it_poison_kubelet_response`, `it_steal_jenkins_jobs`, +12 more |
| **VoIP desk phone** (`voip_phone`) | IT devices | Telephony and conferencing | `80, 443, 5060, 5061` | sip, http, tftp, mdns | 21 — `it_mimic_sip`, `it_impersonate_stun`, `it_hijack_sip_register`, `it_steal_phone_contacts`, `it_fuzz_sip_uri`, +16 more |
| **PBX / SIP server** (`pbx`) | IT devices | Telephony and conferencing | `80, 443, 5038, 5060, 8088` | sip, http, ami | 16 — `it_mimic_sip`, `it_impersonate_stun`, `it_hijack_sip_register`, `it_steal_phone_contacts`, `it_fuzz_sip_uri`, +11 more |
| **Conference room system** (`video_conference`) | IT devices | Telephony and conferencing | `80, 443, 5060, 8080` | http, sip, onvif | 40 — `ble_soundbar_mimic`, `it_mimic_sip`, `it_impersonate_stun`, `it_hijack_sip_register`, `it_steal_phone_contacts`, +35 more |
| **PLC / industrial controller** (`plc`) | IT devices | Industrial and building systems | `102, 502, 4840, 44818` | modbus, s7comm, cip, opcua | 67 — `it_mimic_modbus`, `it_impersonate_szl`, `it_impersonate_cip`, `it_impersonate_opcua`, `it_hijack_modbus_coil`, +62 more |
| **HMI / operator panel** (`hmi_panel`) | IT devices | Industrial and building systems | `80, 443, 102, 502, 3389` | http, rdp, modbus | 74 — `it_mimic_modbus`, `it_impersonate_szl`, `it_impersonate_cip`, `it_impersonate_opcua`, `it_hijack_modbus_coil`, +69 more |
| **RTU / remote telemetry unit** (`rtu`) | IT devices | Industrial and building systems | `502, 20000, 2404` | dnp3, iec104, modbus | 47 — `it_mimic_modbus`, `it_impersonate_szl`, `it_hijack_modbus_coil`, `it_hijack_iec104`, `it_hijack_dnp3`, +42 more |
| **Building / HVAC controller** (`building_controller`) | IT devices | Industrial and building systems | `80, 443, 47808` | bacnet, http, modbus | 44 — `it_mimic_bacnet`, `it_impersonate_opcua`, `it_hijack_bacnet_priority`, `it_poison_bacnet_whois`, `it_fuzz_modbus_function`, +39 more |
| **Energy meter / inverter** (`energy_meter`) | IT devices | Industrial and building systems | `80, 161, 502` | modbus, snmp, http | 75 — `ble_scale_mimic`, `ble_charger_mimic`, `ble_vehicle_tracker_mimic`, `it_mimic_coap`, `it_mimic_modbus`, +70 more |
| **Medical device** (`medical_device`) | IT devices | IoT and embedded | `80, 104, 2575, 11112` | http, dicom, hl7, modbus | 33 — `ble_patient_mimic`, `ble_glucose_mimic`, `ble_pressure_mimic`, `ble_ecg_mimic`, `ble_hr_mimic`, +28 more |
| **POS / payment terminal** (`pos_terminal`) | IT devices | IoT and embedded | `80, 443, 9100, 3389` | http, ipp, rdp | 58 — `ble_vending_mimic`, `it_mimic_pjl`, `it_hijack_pjl_job`, `it_hijack_http_session`, `it_steal_printer_spool`, +53 more |
| **Kiosk / self-service** (`kiosk`) | IT devices | IoT and embedded | `80, 443, 5555, 8080` | http, adb, vnc | 34 — `ble_vending_mimic`, `it_hijack_adb`, `it_steal_badge_db`, `it_relay_vnc`, `it_hijack_vnc_session`, +29 more |
| **Digital signage / display** (`digital_signage`) | IT devices | IoT and embedded | `80, 443, 8080` | http, mdns | 46 — `ble_ir_hub_mimic`, `ble_vending_mimic`, `it_mimic_ssdp`, `it_impersonate_cast`, `it_hijack_adb`, +41 more |
| **Projector / AV matrix** (`projector`) | IT devices | IoT and embedded | `80, 23, 3629, 4352` | pjlink, http, telnet, crestron | 28 — `ble_ir_hub_mimic`, `it_impersonate_cast`, `it_http_discover`, `it_http_banner`, `it_http_version`, +23 more |
| **Smart TV / media player** (`smart_tv`) | IT devices | Consumer and smart home | `80, 443, 7000, 8008, 8009, 9080` | http, airplay, cast, mdns | 55 — `ble_ir_mimic`, `ble_consumer_mimic`, `ble_band_mimic`, `ble_hr_mimic`, `ble_ir_hub_mimic`, +50 more |
| **Smart speaker / voice assistant** (`smart_speaker`) | IT devices | Consumer and smart home | `443, 8008, 8443` | http, cast, mdns | 19 — `ble_bulb_mimic`, `ble_soundbar_mimic`, `it_mimic_mdns`, `it_impersonate_airplay`, `it_survey_mdns_services`, +14 more |
| **Smart plug / relay** (`smart_plug`) | IT devices | Consumer and smart home | `80, 443, 6668, 9999` | kasa, http, mdns | 50 — `ble_ir_mimic`, `ble_bulb_mimic`, `ble_mesh_lamp_mimic`, `ble_plug_mimic`, `ble_charger_mimic`, +45 more |
| **Smart bulb / lighting** (`smart_bulb`) | IT devices | Consumer and smart home | `80, 443, 55443, 6668` | http, zigbee_gateway, mdns | 31 — `ble_mesh_mimic`, `ble_peripheral_shadow`, `ble_bulb_mimic`, `ble_mesh_lamp_mimic`, `ble_gatt_blob_dump`, +26 more |
| **Smart lock / door controller** (`smart_lock`) | IT devices | Consumer and smart home | `80, 443, 8080` | http, ble, mdns | 17 — `ble_smartlock_mimic`, `ble_lock_mimic`, `ble_lock_mesh_mimic`, `ble_gatt_write_sweep`, `ble_signed_write_bypass`, +12 more |
| **Thermostat / climate control** (`thermostat`) | IT devices | Consumer and smart home | `80, 443, 8080` | http, mdns, zigbee_gateway | 46 — `ble_thermostat_mimic`, `ble_air_quality_mimic`, `it_mimic_mqtt`, `it_mimic_bacnet`, `it_hijack_mqtt_retain`, +41 more |
| **Robot vacuum / appliance** (`robot_vacuum`) | IT devices | Consumer and smart home | `80, 443, 54321` | miio, http, mqtt | 15 — `it_impersonate_cip`, `it_impersonate_miio`, `it_cip_discover`, `it_cip_version`, `it_cip_unauth_read`, +10 more |
| **EV charger** (`ev_charger`) | IT devices | Consumer and smart home | `80, 443, 502, 8080` | http, modbus, ocpp | 19 — `ble_ev_charger_mimic`, `ble_telemetry_mimic`, `ble_charger_mimic`, `it_mimic_modbus`, `it_http_discover`, +14 more |
| **Consumer camera / baby monitor** (`camera_doorbell`) | IT devices | Consumer and smart home | `80, 443, 554` | http, rtsp, mqtt | 31 — `ble_doorbell_mimic`, `it_mimic_rtsp`, `it_impersonate_onvif`, `it_hijack_rtsp`, `it_hijack_onvif_uri`, +26 more |
| **Smartphone** (`smartphone`) | IT devices | Phones, tablets and wearables | `80, 443, 5555, 62078` | http, adb, mdns | 21 — `ble_fido_mimic`, `ble_hid_multi_host`, `ble_mouse_mimic`, `ble_band_mimic`, `ble_glucose_mimic`, +16 more |
| **Tablet / mobile workstation** (`tablet`) | IT devices | Phones, tablets and wearables | `80, 443, 5900` | http, vnc, mdns | 36 — `ble_fido_mimic`, `ble_hid_multi_host`, `ble_band_mimic`, `ble_glucose_mimic`, `ble_pressure_mimic`, +31 more |
| **Fitness tracker / smartwatch** (`fitness_tracker`) | Bluetooth | Phones, tablets and wearables | `—` | ble, gatt | 15 — `ble_hid_audit`, `ble_smp_downgrade`, `ble_gatt_hijack`, `ble_irk_resolve`, `ble_conn_param_hijack`, +10 more |
| **Bluetooth headset / audio** (`bt_headset`) | Bluetooth | Bluetooth devices | `—` | bluetooth, rfcomm, obex, a2dp | 24 — `ble_hid_audit`, `ble_smp_downgrade`, `ble_conn_param_hijack`, `ble_hid_mimic`, `ble_speaker_mimic`, +19 more |
| **Bluetooth keyboard / mouse** (`bt_keyboard`) | Bluetooth | Bluetooth devices | `—` | bluetooth, hid | 18 — `ble_hid`, `ble_hid_audit`, `ble_hid_boot`, `ble_hid_reconnect`, `ble_smp_downgrade`, +13 more |
| **BLE sensor / tag** (`ble_sensor`) | Bluetooth | Bluetooth devices | `—` | ble, gatt, adv | 53 — `ble_smp_downgrade`, `ble_gatt_hijack`, `ble_irk_resolve`, `ble_conn_param_hijack`, `ble_pairing_mimic`, +48 more |
| **BLE beacon / proximity tag** (`ble_beacon`) | Bluetooth | Bluetooth devices | `—` | ble, ibeacon | 8 — `ble_adv_identity_clone`, `ble_device_mimic`, `ble_beacon_mimic`, `ble_eddystone_mimic`, `ble_peripheral_shadow`, +3 more |
| **Bluetooth lock / padlock** (`bt_lock`) | Bluetooth | Bluetooth devices | `—` | ble, gatt | 24 — `ble_smp_downgrade`, `ble_gatt_hijack`, `ble_bond_hijack`, `ble_name_collision`, `ble_smartlock_mimic`, +19 more |
| **Car kit / infotainment** (`bt_car_kit`) | Bluetooth | Bluetooth devices | `—` | bluetooth, hfp, pbap, obex | 7 — `ble_hfp_hijack`, `ble_hfp_audio_gateway`, `ble_map_hijack`, `ble_pbap_hijack`, `ble_hfp_identity_spoof`, +2 more |
| **Bluetooth printer** (`bt_printer`) | Bluetooth | Bluetooth devices | `—` | bluetooth, spp, rfcomm | 4 — `ble_label_printer_mimic`, `ble_hfp_identity_spoof`, `ble_obex_push`, `ble_spp_hijack` |
| **UPS / power management** (`ups`) | IT devices | Industrial and building systems | `80, 161, 443, 161, 502` | snmp, http, modbus, tls | 14 — `ble_plug_mimic`, `ble_scale_mimic`, `ble_vehicle_tracker_mimic`, `it_impersonate_snmp`, `it_poison_snmp_trap`, +9 more |
| **HVAC unit / rooftop controller** (`hvac`) | IT devices | Industrial and building systems | `80, 443, 47808, 502` | bacnet, http, modbus | 27 — `ble_bulb_mimic`, `ble_thermostat_mimic`, `ble_air_quality_mimic`, `it_mimic_bacnet`, `it_hijack_bacnet_priority`, +22 more |
| **Clinical workstation** (`medical_workstation`) | IT devices | IoT and embedded | `80, 104, 443, 445` | dicom, http, smb | 13 — `ble_pressure_mimic`, `ble_ecg_mimic`, `ble_patient_monitor_mimic`, `it_relay_dicom`, `it_hijack_dicom_store`, +8 more |
| **Networked speaker / amplifier** (`speaker`) | IT devices | Consumer and smart home | `80, 443, 1400, 1443, 8008, 8080` | http, cast, mdns, airplay | 17 — `ble_speaker_mimic`, `ble_bond_hijack`, `ble_name_collision`, `ble_fastpair_mimic`, `ble_audio_le_mimic`, +12 more |

The shelf is what the planner walks when the IT edition is selected: for each device it proposes the discovery rows first (cheap, quiet, and they name the model), then the attacks that the fingerprint justifies. The same list is served by the web UI at `/api/devices` and by the CLI:

```console
$ wifipilot --edition it --attacks it_http_discover,it_httpservices --demo attack
$ wifipilot attacks --domain it          # print the IT edition
$ wifipilot --edition bluetooth attack    # plan BLE/classic only
```

<!-- 848 attacks -->
<!-- catalogue:end -->
