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
"""

# Nothing imported eagerly — submodules are light enough to load on demand.
__all__ = ["ieee80211", "radiotap", "scanner", "sniff", "pmkid", "wpscrack",
           "eviltwin", "turbocrack", "deauth"]
