"""wifipilot -- an AI-piloted alternative to wifite.

wifipilot automates the boring parts of authorised WiFi auditing:

* discovery of access points and their clients (airodump-ng / iw / nmcli)
* capture of WPA/WPA2 4-way handshakes and client-less PMKID hashes
* WPS Pixie-Dust / PIN recovery (reaver / bully, via wash for discovery)
* WEP IV harvesting
* offline cracking orchestration (aircrack-ng / hashcat) with wordlist + rule
  intelligence
* **auto-think**: a local LLM served by Ollama plans the engagement, adapts when
  an attack fails and explains itself in plain language
* a live web UI (FastAPI + WebSocket) that mirrors the whole session

Everything is MIT licensed and intended for *authorised* testing only.
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__", "TOOL_NAME", "LEGAL_NOTICE"]

TOOL_NAME = "wifipilot"

LEGAL_NOTICE = """\
wifipilot is an offensive WiFi auditing framework.

Using it against networks you do not own or do not have explicit written
permission to test is a criminal offence in most jurisdictions
(Computer Fraud and Abuse Act, Computer Misuse Act, StGB s.202a-c, ...).

Active attacks (deauthentication, WPS PIN brute force, association floods)
disrupt the target network: never run them on a production network without a
maintenance window and a named authorising party.
"""
