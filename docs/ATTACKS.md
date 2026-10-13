# Attacks

wifipilot ships **162 attacks**: every technique a WiFi assessment genuinely needs, and
nothing that exists only to lengthen the list — the offline half of the catalogue was
built the same way the headers of a report are, by asking what a *capture* can still be
made to say. The families are **offline analysis**
(eighty-two attacks that read files and transmit nothing at all), **surveys** (passive
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
catalogue = attack_catalog()        # 162 dicts: name, label, tool, requires, category,
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

<!-- catalogue:start -->

## 11. The complete catalogue

**181 attacks**, of which **102** transmit nothing at all — no radio, no monitor interface, no frame.  The table is generated from the registry (`python3 tools/gen_attack_docs.py`), so it cannot drift from the code: `wifipilot attacks` prints the same list, `--json` returns it, and the web UI, the planner and the report are all built from it.

How to read the columns: **noise** is what a defender sees (extreme 7, loud 18, moderate 16, quiet 21, silent 119), **impact** is what the *network* loses when the attack works (degraded 27, info 114, loot 27, none 9, outage 4), and **detection** is the artefact left behind — the thing to look for in a capture when asking whether this was run against you.

### Offline analysis (no radio at all) — 102

| attack | answers | noise | impact | tool | defender sees |
| --- | --- | --- | --- | --- | --- |
| `loot_audit` | Loot inventory and hash-file audit | dim | green | wifipilot hash22000.py | nothing on air; reads the session's own files |
| `eapol_audit` | EAPOL / handshake audit | dim | green | wifipilot pcap.py (EAPOL decoder) | nothing on air; decodes EAPOL already captured |
| `wep_audit` | WEP feasibility audit | dim | green | wifipilot pcap.py (IV counter) | nothing on air; counts IVs already captured |
| `pixie_offline` | Pixie-Dust offline (pixiewps on a stored exchange) | dim | bold green | pixiewps | nothing on air; runs pixiewps against a stored exchange |
| `eap_md5_crack` | EAP-MD5 offline dictionary | dim | bold green | wifipilot sniff.py + hashlib | nothing on air; offline dictionary against a captured EAP-MD5 exchange |
| `crack_sweep` | Crack sweep (offline, whole session) | dim | bold green | wifipilot crack.py | nothing on air; CPU only |
| `rogue_detect` | Rogue and cloned-AP detection | dim | green | wifipilot sniff.py + OUI registry | nothing on air; compares what the scanner already sees |
| `twin_detect` | Evil-twin fingerprinting | dim | green | wifipilot sniff.py + OUI registry | nothing on air; fingerprints identical SSIDs |
| `roam_audit` | Roaming and 802.11k/r/v audit | dim | green | wifipilot ies.py (RM/FT/BTM elements) | nothing on air; reads 802.11k/r/v elements |
| `wps_lockout_audit` | WPS posture and lockout audit | dim | green | wifipilot ies.py + wps.py | nothing on air; assesses WPS from IEs and history |
| `capture_quality` | Capture quality ranking (what is worth cracking) | dim | green | wifipilot pcap.py (handshake scoring) | nothing on air; scores the session's own captures |
| `hash_audit` | Hash file audit (mode 22000) | dim | green | wifipilot hash22000.py | nothing on air; parses mode-22000 hash files |
| `wordlist_audit` | Wordlist audit (coverage and cost) | dim | green | wifipilot crack.py (measuring, not guessing) | nothing on air; reads the configured wordlists |
| `wordlist_mine` | Target wordlist mining (off the engagement's own data) | dim | green | wifipilot (engagement-derived candidates) | nothing on air; candidates derived from the SSIDs and vendors already seen |
| `crack_plan` | Crack plan (benchmarked time estimates) | dim | green | wifipilot crack.py + masks.py | nothing on air; a PBKDF2 benchmark and a multiplication |
| `vendor_fingerprint` | Device fingerprinting (vendors, models, drivers) | dim | green | wifipilot ies.py + util.oui_vendor | nothing on air; groups the scanner's findings by vendor and model |
| `beacon_timeline` | Beacon timeline (what changed while we watched) | dim | green | wifipilot models.AccessPoint.history | nothing on air; the session's own history of the neighbourhood |
| `cleartext_sniff` | Cleartext credential sniff (HTTP, FTP, mail) | dim | bold green | wifipilot netproto.py + pcap.py | nothing on air; reads credentials out of a capture |
| `pmk_check` | PMK check (loot that needs no cracking) | dim | bold green | wifipilot crypto.py (PTK + MIC verification) | nothing on air; recomputes MICs with keys the session already holds |
| `loot_manifest` | Loot manifest (chain of custody) | dim | green | wifipilot (SHA-256 manifest) | nothing on air; SHA-256 over the session's artefacts |
| `krack_detect` | KRACK key-reinstallation detector (CVE-2017-13077) | dim | green | wifipilot pcap.py (EAPOL replay analysis) | nothing on air; the retransmission pattern is read out of a capture we already have |
| `kr00k_detect` | KR00K zero-key frame detector (CVE-2019-15126) | dim | green | wifipilot pcap.py + ciphertext analysis | nothing on air; scans captured ciphertext for the all-zero keystream signature |
| `fragattacks_detect` | FragAttacks exposure audit (CVE-2020-24588 and relatives) | dim | green | wifipilot ies.py + pcap.py (aggregation and fragmentation) | nothing on air; looks for A-MSDU and fragment patterns in stored frames |
| `ft_audit` | 802.11r fast-transition audit | dim | green | wifipilot ies.py (mobility domain + FT AKM) | nothing on air; reads mobility-domain and AKM elements |
| `beacon_rate_audit` | Beacon behaviour audit (clones and floods) | dim | green | wifipilot pcap.py (TSF, interval, sequence) | nothing on air; compares beacon intervals, TSF and sequence numbers in a capture |
| `tsf_clone_detect` | TSF clone detector (same SSID, unrelated clocks) | dim | green | wifipilot pcap.py (TSF correlation) | nothing on air; TSF timers compared between identical BSSIDs |
| `client_fingerprint` | Station fingerprinting (vendor, randomisation, probes) | dim | green | wifipilot sniff.py + pcap.py | nothing on air; reads probe requests and their element sets |
| `mschapv2_crack` | MS-CHAPv2 challenge/response recovery | dim | bold green | wifipilot (MD4 + DES, RFC 2759) | nothing on air; a dictionary against a captured MS-CHAPv2 exchange |
| `mic_check` | Handshake MIC verification (offline) | dim | bold green | wifipilot (HMAC-SHA1/AES-CMAC MIC) | nothing is transmitted; the MIC is computed locally over a stored frame |
| `nonce_reuse_audit` | Nonce reuse audit (KRACK precondition) | dim | green | wifipilot (own 802.11 parser) | silent: reads EAPOL nonces out of a stored capture |
| `key_version_audit` | EAPOL key descriptor version audit | dim | green | wifipilot (own 802.11 parser) | silent: reads the key information field of stored EAPOL frames |
| `tkip_countermeasures_audit` | TKIP countermeasures detection | dim | green | wifipilot (own 802.11 parser) | silent: reads deauthentication reason codes out of a capture |
| `group_cipher_audit` | Group cipher audit | dim | green | wifipilot (own 802.11 parser) | silent: decodes the RSN element of stored beacons |
| `cipher_downgrade_audit` | Pairwise cipher downgrade audit | dim | green | wifipilot (own 802.11 parser) | silent: compares the pairwise cipher lists of stored beacons |
| `rsn_ie_audit` | RSN element audit | dim | green | wifipilot (own 802.11 parser) | silent: reads the RSN element line by line |
| `ie_anomaly_audit` | Information element anomaly audit | dim | green | wifipilot (own 802.11 parser) | silent: walks the element area of every management frame in a capture |
| `malformed_ie_audit` | Malformed element audit | dim | green | wifipilot (own 802.11 parser) | silent: length-checks every element in every management frame |
| `wildcard_probe_audit` | Wildcard probe audit (KARMA customers) | dim | green | wifipilot (own 802.11 parser) | silent: reads the SSID element of stored probe requests |
| `randomised_mac_ratio` | Randomised MAC ratio | dim | green | wifipilot (own 802.11 parser) | silent: reads transmitter addresses out of a capture |
| `probe_privacy_audit` | Directed probe privacy audit | dim | green | wifipilot (own 802.11 parser) | silent: builds a per-station network list from stored probe requests |
| `assoc_history_audit` | Association history audit | dim | green | wifipilot (own 802.11 parser) | silent: counts management frame types in a stored capture |
| `client_vendor_audit` | Client vendor audit | dim | green | wifipilot (own 802.11 parser) | silent: reads transmitter addresses and their OUIs |
| `client_count_audit` | Client population audit | dim | green | wifipilot (own 802.11 parser) | silent: counts distinct transmitters per BSSID |
| `data_frame_audit` | Data frame mix audit | dim | green | wifipilot (own 802.11 parser) | silent: classifies every frame in a capture |
| `protected_ratio_audit` | Protected frame ratio audit | dim | green | wifipilot (own 802.11 parser) | silent: reads the protected bit and the LLC type of stored data frames |
| `duration_field_audit` | Duration/NAV field audit | dim | green | wifipilot (own 802.11 parser) | silent: reads the duration field of every frame in a capture |
| `retransmit_audit` | Retransmission audit | dim | green | wifipilot (own 802.11 parser) | silent: reads the retry bit of stored frames |
| `fragment_audit` | Fragmentation audit | dim | green | wifipilot (own 802.11 parser) | silent: reads the fragment number of stored data frames |
| `beacon_interval_audit` | Beacon interval audit | dim | green | wifipilot (own 802.11 parser) | silent: reads the beacon interval of stored beacons |
| `tsf_skew_audit` | Beacon timestamp (TSF) skew audit | dim | green | wifipilot (own 802.11 parser) | silent: measures the drift of stored beacon timestamps |
| `assoc_response_audit` | Association response audit | dim | green | wifipilot (own 802.11 parser) | silent: reads the status code of stored association responses |
| `auth_response_audit` | Authentication exchange audit | dim | green | wifipilot (own 802.11 parser) | silent: reads the algorithm and status of stored authentication frames |
| `ssid_length_audit` | SSID inventory and length audit | dim | green | wifipilot (own 802.11 parser) | silent: reads SSID elements out of stored beacons and probe responses |
| `encryption_inventory` | Encryption inventory | dim | green | wifipilot (own 802.11 parser) | silent: decodes the security elements of stored beacons |
| `bssid_oui_audit` | Access point vendor audit | dim | green | wifipilot (own 802.11 parser) | silent: reads BSSID OUIs out of stored beacons |
| `signal_histogram` | Signal distribution audit | dim | green | wifipilot (own 802.11 parser) | silent: reads the radiotap signal field of stored frames |
| `channel_usage_audit` | Channel usage audit | dim | green | wifipilot (own 802.11 parser) | silent: reads the DS parameter set of stored beacons |
| `channel_overlap_audit` | Channel overlap audit | dim | green | wifipilot (own 802.11 parser) | silent: compares the channels in stored beacons |
| `handshake_message_audit` | Handshake message inventory | dim | green | wifipilot (own 802.11 parser) | silent: reads the message numbers of stored EAPOL frames |
| `pmkid_presence_audit` | PMKID presence audit | dim | bold green | wifipilot (own 802.11 parser) | silent: reads PMKIDs out of stored EAPOL message 1 frames |
| `eapol_retry_audit` | EAPOL retransmission audit | dim | green | wifipilot (own 802.11 parser) | silent: counts repeated key message numbers in a capture |
| `wpa3_transition_audit` | WPA3 transition mode audit | dim | green | wifipilot (own 802.11 parser) | silent: reads the AKM suites of stored beacons |
| `sa_query_activity` | SA Query activity audit | dim | green | wifipilot (own 802.11 parser) | silent: counts action frames with category 8 in a capture |
| `eapol_logoff_audit` | EAPOL-Logoff audit | dim | green | wifipilot (own 802.11 parser) | silent: scans stored frames for EAPOL type 2 |
| `llc_snap_audit` | LLC/SNAP ethertype audit | dim | green | wifipilot (own 802.11 parser) | silent: reads the LLC/SNAP header of stored data frames |
| `qos_audit` | QoS traffic audit | dim | green | wifipilot (own 802.11 parser) | silent: reads the QoS control field of stored data frames |
| `power_save_audit` | Power save audit | dim | green | wifipilot (own 802.11 parser) | silent: reads the power management bit of stored data frames |
| `broadcast_storm_audit` | Broadcast and multicast audit | dim | green | wifipilot (own 802.11 parser) | silent: reads the receiver address of stored data frames |
| `gratuitous_arp_audit` | Gratuitous ARP audit | dim | green | wifipilot (own 802.11 parser) | silent: parses the ARP payloads already in a capture |
| `arp_scan_detect` | ARP scan detection | dim | green | wifipilot (own 802.11 parser) | silent: tracks ARP request targets per client |
| `dhcp_fingerprint_audit` | DHCP fingerprint audit | dim | green | wifipilot (own 802.11 parser) | silent: parses DHCP options out of stored frames |
| `duplicate_seq_audit` | Duplicate sequence number audit | dim | green | wifipilot (own 802.11 parser) | silent: tracks (transmitter, sequence) pairs in a capture |
| `deauth_storm_detect` | Deauthentication storm detection | dim | green | wifipilot (own 802.11 parser) | silent: counts deauthentication frames per second in a capture |
| `auth_flood_detect` | Authentication flood detection | dim | green | wifipilot (own 802.11 parser) | silent: cross-references authentication and association frames per station |
| `probe_flood_detect` | Probe request flood detection | dim | green | wifipilot (own 802.11 parser) | silent: counts probe requests per station and their name lengths |
| `pcap_report` | Capture report (JSON artifact) | dim | bold green | wifipilot (own 802.11 parser) | silent: writes a file; nothing is transmitted |
| `capture_coverage` | Capture coverage audit | dim | green | wifipilot (own 802.11 parser) | silent: cross-references the session's discovery and capture state |
| `beacon_rate_histogram` | Beacon rate audit | dim | green | wifipilot (own 802.11 parser) | silent: measures beacon spacing in a capture |
| `auth_algorithm_inventory` | Authentication algorithm inventory | dim | green | wifipilot (own 802.11 parser) | silent: reads the algorithm number of stored authentication frames |
| `station_inventory` | Station inventory | dim | green | wifipilot (own 802.11 parser) | silent: builds a per-address map from stored frames |
| `quality_histogram` | Frame size histogram | dim | green | wifipilot (own 802.11 parser) | silent: measures every frame in a capture |
| `vendor_ie_inventory` | Vendor element inventory | dim | green | wifipilot (own 802.11 parser) | silent: reads element 221 out of stored beacons |
| `hidden_ap_audit` | Hidden network audit | dim | green | wifipilot (own 802.11 parser) | silent: correlates beacons without an SSID with association requests |
| `extended_capability_audit` | Extended capabilities audit | dim | green | wifipilot (own 802.11 parser) | silent: decodes the extended capabilities element of stored beacons |
| `rrm_measurement_audit` | 802.11k measurement audit | dim | green | wifipilot (own 802.11 parser) | silent: decodes the RM enabled capabilities element (tag 70) |
| `neighbour_report_audit` | Neighbour report audit | dim | green | wifipilot (own 802.11 parser) | silent: decodes the neighbour report element (tag 52) |
| `ft_mobility_audit` | Fast transition (802.11r) audit | dim | green | wifipilot (own 802.11 parser) | silent: decodes the mobility domain element (tag 54) |
| `bss_load_audit` | BSS load audit | dim | green | wifipilot (own 802.11 parser) | silent: decodes the BSS load element (tag 11) |
| `interworking_audit` | Interworking element audit | dim | green | wifipilot (own 802.11 parser) | silent: decodes the interworking element (tag 107) |
| `hs20_audit` | Hotspot 2.0 (Passpoint) audit | dim | green | wifipilot (own 802.11 parser) | silent: decodes the Hotspot 2.0 vendor element (221/00:50:f2/0x11) |
| `wmm_parameter_audit` | WMM parameter audit | dim | green | wifipilot (own 802.11 parser) | silent: decodes the WMM parameter element (221/00:50:f2/0x02) |
| `wps_config_audit` | WPS configuration method audit | dim | green | wifipilot (own 802.11 parser) | silent: decodes the WPS element's configuration methods |
| `country_power_audit` | Regulatory domain audit | dim | green | wifipilot (own 802.11 parser) | silent: decodes the country element (tag 7) |
| `ssid_hygiene_audit` | SSID hygiene audit | dim | green | wifipilot (own 802.11 parser) | silent: reads the SSID element of stored beacons |
| `security_mismatch_audit` | Security mismatch audit | dim | green | wifipilot (own 802.11 parser) | silent: compares the RSN of every BSSID carrying the same SSID |
| `client_capability_audit` | Client capability audit | dim | green | wifipilot (own 802.11 parser) | silent: reads association requests in a capture |
| `frame_control_audit` | Frame control audit | dim | green | wifipilot (own 802.11 parser) | silent: reads the frame control field of every stored frame |
| `airtime_estimate` | Airtime estimate | dim | green | wifipilot (own 802.11 parser) | silent: measures every frame in a capture |
| `probe_response_latency_audit` | Probe response latency audit | dim | green | wifipilot (own 802.11 parser) | silent: pairs probe requests with the responses to them |
| `eapol_key_flags_audit` | EAPOL key flag audit | dim | green | wifipilot (own 802.11 parser) | silent: reads the key information field of stored EAPOL frames |
| `group_rekey_audit` | Group key rekey audit | dim | green | wifipilot (own 802.11 parser) | silent: reads key data out of stored EAPOL frames |
| `eapol_timing_audit` | EAPOL timing audit | dim | green | wifipilot (own 802.11 parser) | silent: times the EAPOL messages in a capture |

### Surveys the air, transmits nothing — 19

| attack | answers | noise | impact | tool | defender sees |
| --- | --- | --- | --- | --- | --- |
| `passive` | Passive capture | dim | dim | airodump-ng | nothing at all; listen-only capture |
| `rogue_ap` | Rogue AP / evil twin survey | dim | green | wifipilot (offline analysis) | nothing on air; cross-checks the neighbourhood |
| `ie_audit` | Configuration audit (beacon elements) | dim | green | wifipilot ies.py (IE decoder) | nothing on air; decodes beacons |
| `pmf_audit` | PMF / transition-mode audit | dim | green | wifipilot wpa3.py (RSN decoder) | nothing on air; reads RSN capabilities |
| `saewolf` | WPA3 SAE capture (dragonslayer) | green | bold green | airodump-ng + wpa3.py (SAE/PMF decoder) | captures SAE frames; sends nothing until a client authenticates |
| `sae_group_audit` | SAE group and H2E audit (WPA3 parameters) | dim | green | wifipilot wpa3.py (RSN + SAE decoder) | nothing on air beyond the capture that was already happening; reads the RSN element and SAE commits |
| `hidden_ssid` <br>_on by default_ | Hidden SSID discovery | green | green | airodump-ng | one probe request per hidden name; the AP's own answer reveals it |
| `pnl_harvest` | Probe harvest (preferred network lists) | dim | green | wifipilot sniff.py (probe decoder) | nothing on air; reads probe requests |
| `tracker` <br>_on by default_ | Station tracker (follow a client) | dim | green | airodump-ng (listen-only) | follows a station with the capture radio only |
| `ap_admin_audit` | Management surface audit (admin ports and pages) | green | dim | wifipilot (raw sockets + HTTP) | TCP connections to management ports: a port scan of one host |
| `upnp_audit` | UPnP/SSDP audit (device description and IGD) | green | dim | wifipilot netproto.py (SSDP + HTTP) | one SSDP M-SEARCH multicast, then HTTP GETs to the description URLs |
| `snmp_audit` | SNMP audit (default community strings) | green | dim | wifipilot netproto.py (BER codec) | SNMP GET requests carrying default community strings |
| `dns_audit` | DNS resolver audit (open resolver, DNSSEC) | green | dim | wifipilot netproto.py (DNS client) | a handful of DNS queries to the network's own resolver |
| `wpad_audit` | WPAD audit (proxy auto-discovery exposure) | green | dim | wifipilot netproto.py (DNS + HTTP) | DNS queries for the wpad names, then a GET for wpad.dat |
| `rogue_dhcp_detect` | Rogue DHCP detection (second server on the segment) | dim | green | wifipilot netproto.py (DHCP sniff) | nothing but listening for DHCP replies from the segment |
| `arp_spoof_detect` | ARP spoofing detection (address conflicts) | dim | green | wifipilot netproto.py (ARP parsing) | nothing on air; reads ARP claims from a capture or a listen window |
| `ipv6_ra_audit` | IPv6 router advertisement audit | dim | green | wifipilot (ICMPv6 parsing) | nothing but listening for router advertisements |
| `mac_filter_probe` <br>_injects_ | MAC filtering probe (random station) | green | dim | wifipilot rawtx.py + a live listen window | association attempts from random MACs; a MAC filter rejects them visibly |
| `channel_sweep` | Channel sweep (live channel map) | dim | dim | wifipilot rawtx.py + airodump-ng fallback | nothing but channel changes on our own radio |

### Capture requests (frames on air) — 7

| attack | answers | noise | impact | tool | defender sees |
| --- | --- | --- | --- | --- | --- |
| `pmkid` <br>_on by default, injects_ | PMKID capture (client-less) | dim | bold green | hcxdumptool / tcpdump | nothing from us; the AP volunteers the PMKID to associated clients |
| `handshake` <br>_on by default, injects_ | WPA handshake capture | green | bold green | airodump-ng + aireplay-ng | two short deauth bursts per client; a WIDS counting deauths sees them |
| `handshake_broadcast` <br>_injects_ | WPA handshake capture (broadcast deauth) | cyan | bold green | airodump-ng + aireplay-ng -0 (broadcast) | broadcast deauth; every client on the channel drops at once |
| `pmkid_flood` <br>_injects_ | PMKID hunt (deauth + harvest) | yellow | yellow | aireplay-ng + airodump-ng --pmkid | deauth-driven PMKID hunt; frequent disconnects |
| `hcxdump_capture` <br>_injects_ | hcxdumptool capture (client-less PMKID pipeline) | cyan | bold green | hcxdumptool + hcxpcapngtool | an active hcxdumptool session: association attempts and deauths under its own policy |
| `injection_test` <br>_injects_ | Injection test (aireplay-ng --test) | green | dim | aireplay-ng --test | aireplay-ng's own test frames: a handful of probe requests, then it stops |
| `pcap_replay` <br>_injects_ | Capture replay (frames back on the air) | yellow | yellow | wifipilot rawtx.py (replay of a stored capture) | frames replayed from a capture file at their recorded timing |

### WPS — 5

| attack | answers | noise | impact | tool | defender sees |
| --- | --- | --- | --- | --- | --- |
| `wps_pixie` <br>_on by default, injects_ | WPS Pixie-Dust (offline) | green | bold green | reaver -K 1 / bully --pixiewps | one WPS exchange (EAP messages 1-4); the AP sees a normal enrolment |
| `wps_ap_pin` <br>_injects_ | WPS AP-PIN attempt (vendor algorithm) | green | bold green | reaver -p <AP PIN> (or bully) | static AP-PIN attempts from a vendor algorithm |
| `wps_lockout_probe` <br>_injects_ | WPS lockout probe (policy measurement) | green | green | reaver (wrong PINs, then stop) / wash | a few deliberately-wrong PINs, then stop: the finding is whether the AP locked out |
| `wps_pbc` <br>_injects_ | WPS push-button enrolment (window check) | green | bold green | wpa_supplicant (wps_pbc) + wpa_cli | push-button enrolment attempts; fails visibly while the AP's button window is shut |
| `wps_pin` <br>_injects_ | WPS PIN recovery (online) | cyan | bold green | reaver / bully | a stream of PIN attempts; APs with lockout will report it |

### WEP — 6

| attack | answers | noise | impact | tool | defender sees |
| --- | --- | --- | --- | --- | --- |
| `arp_replay` <br>_injects_ | ARP replay (WEP IV generation) | yellow | yellow | aireplay-ng -3 (with a raw-frame fallback) | injected ARP frames that the AP rebroadcasts; network traffic rises while IVs accumulate |
| `wep_ivs` <br>_on by default, injects_ | WEP IV harvesting | yellow | bold green | airodump-ng + aireplay-ng --arpreplay | ARP-replay injection; the network's own traffic rises |
| `wep_p0841` <br>_injects_ | WEP P0841 (injected ARP) | yellow | bold green | aireplay-ng -2 -p 0841 | injected ARP frames with a spoofed client |
| `wep_chopchop` <br>_injects_ | WEP chopchop | yellow | bold green | aireplay-ng -4 (KoreK chopchop) | one frame chopped byte by byte; thousands of injected frames |
| `wep_fragment` <br>_injects_ | WEP fragmentation | cyan | bold green | aireplay-ng -5 (fragmentation) | fragmented injected frames |
| `wep_hirte` <br>_injects_ | WEP Hirte (client fragmentation) | cyan | bold green | aireplay-ng -7 (client-oriented fragmentation) | client-driven fragmentation; a station must be active |

### Enterprise (802.1X) — 8

| attack | answers | noise | impact | tool | defender sees |
| --- | --- | --- | --- | --- | --- |
| `enterprise` | WPA-Enterprise survey | dim | green | airodump-ng (+ hostapd-mana/eaphammer when installed) | nothing on air; decodes 802.1X already captured |
| `eap_identity_harvest` <br>_injects_ | EAP identity harvest (cleartext usernames) | dim | green | wifipilot (EAP parser over a capture or a live listen) | nothing from us until a client authenticates; reads the EAP-Response/Identity the AP asked for |
| `eap_method_probe` <br>_injects_ | EAP method probe (what the server will negotiate) | green | green | wifipilot (EAPOL-Start + EAP Nak) | one EAPOL-Start per identity, then the NAK method list: a short negotiation the AP logs |
| `certificate_audit` <br>_injects_ | RADIUS certificate audit (X.509) | dim | green | wifipilot (TLS Certificate + X.509 DER parser) | nothing on air; parses certificates already captured |
| `ttls_inner_audit` <br>_injects_ | TTLS/PEAP inner conversation audit | dim | green | wifipilot (EAP-in-TLS decoder) | nothing on air; reads the inner conversation of a captured TTLS tunnel |
| `eap_tls_version` <br>_injects_ | EAP-TLS version and cipher audit | dim | green | wifipilot (TLS record parser) | nothing on air; reads the TLS version out of a captured EAP-TLS handshake |
| `radius_secret_test` <br>_injects_ | RADIUS shared-secret test | green | green | wifipilot netproto (own RADIUS client) | one Access-Request per candidate secret; a real RADIUS server logs the failures |
| `rogue_radius` <br>_injects_ | Rogue RADIUS (credential check) | cyan | bold green | eaphammer / hostapd-mana / hostapd-wpe | a rogue RADIUS/eaphammer AP; clients that trust any certificate will offer credentials |

### Rogue infrastructure and lures — 16

| attack | answers | noise | impact | tool | defender sees |
| --- | --- | --- | --- | --- | --- |
| `eapol_logoff` <br>_injects_ | EAPOL-Logoff (unauthenticated disconnect) | green | yellow | wifipilot rawtx.py (AF_PACKET injection) | EAPOL-Logoff frames: no deauth, and PMF does not cover them |
| `karma_detect` <br>_injects_ | Karma/MANA rogue-AP detection (probe all names) | green | green | wifipilot rawtx.py (probe requests, random names) | probe requests for names that do not exist; anything that answers is a Karma device |
| `csa_attack` <br>_injects_ | Channel-switch announcement (silent eviction) | cyan | yellow | wifipilot rawtx.py (CSA beacon) | beacons with a Channel Switch Announcement; clients leave the channel |
| `ssid_bruteforce` <br>_injects_ | Hidden-SSID brute force (directed probes) | cyan | green | wifipilot rawtx.py (probe requests, wordlist) | probe/association attempts with dictionary SSIDs against a hidden network |
| `ssid_confusion` <br>_injects_ | SSID confusion (impostor BSSID) | cyan | yellow | wifipilot rawtx.py (beacon, existing SSID) | beacons for an existing SSID from a new BSSID |
| `ap_isolation_audit` <br>_injects_ | Client-isolation audit (spoofed ARP) | green | green | wifipilot rawtx.py (ARP request between two clients) | a handful of spoofed ARP frames between two clients |
| `pmf_downgrade_probe` <br>_injects_ | PMF enforcement probe (unprotected disassoc) | green | yellow | wifipilot rawtx.py (disassociation) | association attempts with MFPC/MFPR cleared: the AP either enforces PMF or negotiates it away |
| `btm_hijack` <br>_injects_ | 802.11v BTM steering to a rogue BSSID | green | yellow | wifipilot rawtx.py (WNM action frame) | BTM requests naming candidate BSSIDs that are not the AP's neighbours |
| `evil_twin` <br>_injects_ | Evil twin (client lure) | cyan | bold green | hostapd-mana / hostapd | a second access point with the same SSID; the real network's clients may prefer it |
| `karma` <br>_injects_ | Karma (answer every probe request) | cyan | bold green | hostapd-mana (enable_mana=1) | an AP that answers every probe request (hostapd-mana) |
| `rogue_dhcp` <br>_injects_ | Rogue DHCP server (leases to anyone who asks) | cyan | yellow | wifipilot netproto.py (DHCP) + rawtx.py (injected offers) | a second DHCP server on the segment: offers carry our gateway and resolver |
| `dns_sink` <br>_injects_ | DNS sink (every name answered, every query logged) | cyan | yellow | wifipilot netproto.py (own DNS server) | every DNS query answered by us, one log line per name |
| `captive_portal` <br>_injects_ | Captive portal (a login page served by us) | cyan | bold green | wifipilot (http.server) | a portal page asking for credentials, served by us |
| `arp_mitm` <br>_injects_ | ARP man-in-the-middle (gateway masquerade) | yellow | yellow | wifipilot rawtx.py (gratuitous ARP) | gratuitous ARP replies claiming the gateway: traffic passes through our radio |
| `beacon_clone` <br>_injects_ | Beacon clone (the SSID from a second radio) | cyan | yellow | wifipilot rawtx.py (beacons) | beacons with the network's own BSSID and elements, sent from a second radio |
| `wpa3_downgrade_twin` <br>_injects_ | WPA3 downgrade twin (offer the network as WPA2-only) | cyan | yellow | hostapd with a WPA2-only profile | a twin with SAE and PMF stripped: clients that do not require WPA3 may join it |

### Denial-of-service tests (opt-in) — 18

| attack | answers | noise | impact | tool | defender sees |
| --- | --- | --- | --- | --- | --- |
| `deauth_flood` <br>_injects_ | Deauthentication flood (detection test) | red | red | mdk4 d (or aireplay-ng -0) | every client of the AP is disconnected, repeatedly |
| `auth_flood` <br>_injects_ | Authentication flood (state exhaustion test) | yellow | yellow | mdk4 a | thousands of authentication frames from fake stations |
| `assoc_flood` <br>_injects_ | Association flood (state exhaustion) | yellow | yellow | wifipilot rawtx.py (association requests) | thousands of association requests; the association table fills |
| `null_data_flood` <br>_injects_ | Null-data flood (power-save buffer exhaustion) | yellow | yellow | wifipilot rawtx.py (QoS Null, PS bit) | QoS Null frames only — no deauth frames at all, so deauth-based WIDS rules do not fire |
| `probe_flood` <br>_injects_ | Probe flood (hidden-SSID disclosure test) | yellow | yellow | mdk4 p | a dictionary of directed probe requests |
| `eapol_start_flood` <br>_injects_ | EAPOL-Start flood (802.1X session exhaustion) | yellow | yellow | wifipilot rawtx.py (EAPOL-Start) | EAPOL-Starts from fake supplicants; the RADIUS server holds half-open sessions |
| `sae_commit_flood` <br>_injects_ | SAE commit flood (WPA3 CPU exhaustion) | yellow | yellow | wifipilot rawtx.py (SAE commit frames) | SAE commit frames from fake stations; anti-clogging tokens are the mitigation |
| `tkip_michael` <br>_injects_ | TKIP Michael countermeasure (capture replay) | red | red | wifipilot rawtx.py (captured TKIP frames, MIC corrupted) | TKIP MIC failures trigger the AP's 60-second Michael countermeasure shutdown |
| `wids_confusion` <br>_injects_ | WIDS attribution confusion (spoofed transmitter test) | red | yellow | wifipilot rawtx.py (deauth frames, foreign BSSID) | attack frames from a list of spoofed transmitters; the test is whether the site's monitoring can tell |
| `beacon_flood` <br>_injects_ | Beacon flood (WIDS test) | red | yellow | mdk4 b | hundreds of phantom SSIDs in every scan list |
| `disassoc_flood` <br>_injects_ | Disassociation flood | red | red | wifipilot rawtx.py (disassociation frames) | disassociation frames in a loop: every client of the AP drops, and rules that count deauths do not fire |
| `rts_flood` <br>_injects_ | RTS/NAV flood (medium reservation) | red | yellow | wifipilot rawtx.py (RTS frames) | RTS frames with a maximal duration reserve the medium and are never answered: control frames only |
| `cts_flood` <br>_injects_ | CTS-to-self flood (quiet NAV attack) | red | yellow | wifipilot rawtx.py (CTS frames) | CTS-to-self frames hold the channel silent; no management frame is on air at all |
| `channel_switch_flood` <br>_injects_ | Channel-switch flood (clients chase a quiet channel) | yellow | red | wifipilot rawtx.py (CSA beacons) | beacons carrying CSA elements, one channel move after another |
| `sa_query_flood` <br>_injects_ | SA Query flood (PMF association state) | yellow | yellow | wifipilot rawtx.py (SA Query action frames) | SA Query requests with rotating tokens: the AP's association state is walked at frame rate |
| `tdls_teardown_flood` <br>_injects_ | TDLS teardown flood (direct links dropped) | yellow | yellow | wifipilot rawtx.py (TDLS action frames) | TDLS Teardown action frames break direct links and push traffic through the AP |
| `probe_response_flood` <br>_injects_ | Probe response flood (phantom scan lists) | yellow | yellow | wifipilot rawtx.py (probe responses) | probe responses from BSSIDs that do not exist: client scan lists fill with phantoms |
| `dhcp_discover_flood` <br>_injects_ | DHCP DISCOVER flood (lease pool exhaustion) | yellow | yellow | wifipilot netproto.py + rawtx.py (UDP broadcast) | DHCP DISCOVER broadcasts from fake stations walk the server through its pool |

<!-- 181 attacks -->
<!-- catalogue:end -->
