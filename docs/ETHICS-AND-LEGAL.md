# Ethics and legal use

wifipilot is an **offensive** tool. It deauthenticates clients, associates with access points,
attempts WPS PINs and recovers Wi-Fi credentials. This page is not legal advice; it is the
minimum you need to know before running it.

## The short version

1. **Written authorisation, per network, before you start.** A verbal "go ahead" from a
   colleague is not authorisation. You want a scope document naming the SSIDs/BSSIDs,
   the addresses, the time window, the contact who can be reached during the test, and what
   you may and may not do.
2. **Legal risk sits with you.** In most jurisdictions unauthorised access — and in some,
   merely *attempting* it — is a criminal offence (CFAA, CMA, StGB §202a-c, and equivalents).
   Aggravating: capturing third-party traffic, degrading a network in use, or keeping
   credentials you were not asked to keep.
3. **Active attacks disrupt service.** Deauthentication and WPS PIN attempts knock real users
   offline. Schedule them, announce them, and keep them short. Some networks have critical
   traffic (medical, industrial, payment) where a two-second outage is a serious incident.
4. **Recovered credentials are confidential client data.** Handle them like any other
   sensitive finding: store them encrypted, don't reuse them, don't roam, destroy them at the
   end of the engagement unless the contract says otherwise.

## Built-in guardrails (and why you should not rely on them)

| Guardrail | What it does | What it does *not* do |
|---|---|---|
| Authorisation gate | refuses to transmit until you pass `--i-am-authorized` (or tick the box) | prove that you *are* authorised |
| Stealth mode | `--stealth` never deauthenticates and disables online PIN attacks | stop passive capture, which may itself be regulated |
| Attack whitelist | only the six implemented attacks can ever run | stop misuse of those six |
| Plan validator | rejects LLM proposals that violate rules | audit your scope |
| Loopback-only LLM (Ollama) | engagement data stays on the machine | prevent a remote model if you set `allow_remote_host` |
| OpenRouter consent + budget | cloud use is opt-in, capped, and identifiers are pseudonymised by default | make a cloud provider acceptable under your client's data-processing terms |
| Linux-only guard | refuses to run anywhere but Linux | — |

## Operational hygiene

* Prefer the **least disruptive** attack that answers the question: `passive` → `pmkid` →
  `wps_pixie` → `handshake` → `wep_ivs` → `wps_pin`.
* Work on a **test network you built** first, or on `--demo`, so your first run doesn't
  happen on a client's production network.
* Keep a time-boxed window and a **rollback plan** for anything that degrades service.
* Log what you did (`sessions/<id>/journal.jsonl` is written for exactly this reason) — an
  audit trail protects you.
* Never leave a monitor interface or a stopped `NetworkManager` behind: wifipilot restores
  the interface and MAC on exit, but verify with `iw dev` and `systemctl status NetworkManager`.
* Report what you find — including the WPS-locked APs and the SAE-only ones you could not
  break. "Not vulnerable" is a finding.

## Third-party AI providers

Using OpenRouter means your **client's** engagement data (network inventory, security
posture, timing of attacks) is processed by a third party under *their* terms, and your API
key identifies you. Before enabling it:

* check the engagement contract and any DPA/NDA for third-party processing clauses;
* keep `redact_identifiers` on (the default) — SSIDs, BSSIDs, client MACs and recovered PSKs
  are replaced with pseudonyms before anything is sent;
* set `--ai-budget` so a runaway loop cannot spend the client's money;
* remember that captures, handshakes, hashes and wordlists are never sent — only the tactical
  summary — and note in the report which AI provider was used;
* if the contract forbids it, use the local provider: `--provider ollama`. It costs nothing,
  needs no key, and keeps every byte on the audit box.

## What to warn clients about (the usual outcomes)

* **WPA2-PSK** with a weak passphrase: trivially recoverable once a handshake or PMKID is
  captured. Mitigation: long random passphrase, no WPS, PMF where available.
* **WPS enabled**: Pixie-Dust recovers the PIN *and* the PSK in under a minute on many
  consumer routers. Mitigation: disable WPS entirely.
* **WPA3-SAE**: deauth/PMKID attacks do not apply; handshakes cannot be cracked offline.
  This is the single most effective upgrade for most networks.
* **WEP**: broken in minutes; break-glass networks only, never for confidentiality.
* **Open / guest networks**: nothing to crack, but everything to intercept — say so in the
  report, and recommend a captive portal with per-user credentials or a VPN requirement.

## Consent checklist

Before pressing enter on a live campaign:

- [ ] I have written authorisation naming these networks (SSID/BSSID) and these dates.
- [ ] I know who to call if a user or device is affected.
- [ ] I have told the client that clients will be disconnected for a few seconds.
- [ ] WPS PIN brute force is either explicitly in scope or left disabled (it is off by default).
- [ ] I know where the loot is stored and how it will be destroyed afterwards.
- [ ] I know the legal basis (own network / pentest contract / lab environment / CTF).
