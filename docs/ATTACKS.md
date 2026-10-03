# Attacks

wifipilot ships **27 attacks**: every technique a WiFi assessment genuinely needs, and
nothing that exists only to lengthen the list. The families are read-only intelligence
(the element audit and the preferred-network-list harvest), capture (handshake, PMKID,
the active PMKID hunt), WPS/WEP, WPA3 (which is an audit, not a crack), the surveys that
decide what is worth attacking, and the rogue-infrastructure and denial-of-service tests
that impersonate, disconnect or flood. What follows is the reference for each one:
**what question it answers, what it costs, what it puts on the air, and how to read
the result** — including the failure modes, which are the part most tools leave out.

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

\* `pmkid` transmits only if you ask it to (the association-based path inside
hcxdumptool); `hidden_ssid` transmits only with `--reveal-with-probe`.

The last column is what `Config().attacks` contains: six quiet attacks enabled, and
everything else — the two read-only decoders (`ie_audit`, `pnl_harvest`), the
situational surveys and everything disruptive (`wps_pin`, `pmkid_flood`, the WEP
enablers, the twin, Karma, the Logoff and all four floods) — opt-in, through `--attacks`,
the web UI's checkbox list, `attacks=[...]` in the API, or `mode="force"` when you
really do mean all of them. `❌ safe` means the attack transmits nothing at all: it
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
