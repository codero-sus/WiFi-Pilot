# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""ULTRA native engines — pure-Python replacements for the heavy external
tools wifipilot used to shell out to. Importing ``wifipilot.native`` does NOT
pull the engines in at once — each is self-contained and only imports when
actually used, so ``import wifipilot`` stays fast.

Modules:

* :mod:`ieee80211` — minimal 802.11 frame builders (beacon, probe, auth,
  assoc, deauth, EAPOL-M1..M4).
* :mod:`radiotap` — radiotap header builder/parser for injection + signal.
* :mod:`scanner` — passive AF_PACKET scanner replacing airodump-ng/wash.
* :mod:`sniff` — EAPOL/EAP sniffer with BSSID filtering.
* :mod:`pmkid` — native client-less PMKID + EAPOL grabber replacing hcxdumptool.
* :mod:`wpscrack` — pure-Python WPS online M1-M8 state machine with
  Pixie-Dust, replacing reaver/bully.
* :mod:`eviltwin` — rogue AP (beacon+probe/auth/assoc+DHCP+DNS+phish)
  replacing hostapd+dnsmasq for the credential-phishing use case.
* :mod:`turbocrack` — multi-core batched PBKDF2 cracker that beats aircrack-ng.
* :mod:`deauth` — high-rate deauth/disassoc broadcaster (replaces aireplay-ng -0
  and mdk4 for the common targeted-broadcast case).
* :mod:`handshake` — AF_PACKET 4-way handshake grabber with deauth kick and
  pcap writer; replaces airodump-ng's EAPOL listener for targeted captures.
* :mod:`pcapng` — pcap writer (linktype 127, append, thread-safe) plus an
  in-memory ring capture for time-bounded evidence buffering.
* :mod:`probe` — active probe-request sweeper: wildcard + popular-SSID probes
  from rotating MACs across channels; ~1 s 2.4 GHz sweep, replaces wash/airodump
  for quick neighbourhood discovery.
"""

# Nothing imported eagerly — submodules are light enough to load on demand.
__all__ = ["ieee80211", "radiotap", "scanner", "sniff", "pmkid", "wpscrack",
           "eviltwin", "turbocrack", "deauth", "handshake", "pcapng", "probe"]
