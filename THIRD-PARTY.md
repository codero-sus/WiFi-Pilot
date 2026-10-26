# Third-party software

`wifipilot` is dual-licensed under **Apache-2.0 OR BSD-3-Clause** (see `LICENSE`).
None of the code below is vendored into this repository: the external tools are executed
as **separate programs** (`subprocess`) and the Python packages are **installed by you**,
not bundled. That matters for licensing, and it matters again the moment somebody packages
a bundle — so this file records both.

## 1. External tools wifipilot drives

These are separate executables. Using them from `wifipilot` does not put their code into
this project (mere aggregation, not a derivative work), and their licences do not reach
into `wifipilot`'s source.

| Tool | Licence | Used for |
|---|---|---|
| `aircrack-ng` (airodump-ng, aireplay-ng, airmon-ng, airbase-ng, packetforge-ng) | GPL-2.0 | scanning, capture, injection, WEP enablers, PMKID/PTK cracking |
| `reaver`, `wash` | GPL-2.0 | WPS PIN / pixie-dust attacks and WPS AP discovery |
| `bully` | GPL-2.0 | the second WPS implementation, for APs reaver cannot hold |
| `pixiewps` | GPL-2.0 | offline pixie-dust computation |
| `mdk4` | GPL-2.0 | the four floods it implements (deauth, auth, probe, beacon) |
| `hostapd` / `hostapd-mana` | BSD-3-Clause / GPL-2.0 | evil twin and Karma (the `mana` build is GPL-2.0) |
| `dnsmasq` | GPL-2.0 or GPL-3.0 (dual) | DHCP and DNS for a rogue AP |
| `hcxdumptool`, `hcxtools` (`hcxpcapngtool`) | MIT | PMKID and EAPOL capture and conversion |
| `hashcat` | MIT | offline cracking of mode 22000 material |
| `john` | GPL-2.0 | optional fallback cracker |
| `tshark` / `wireshark` | GPL-2.0 | optional pcap decoding |
| `tcpdump` / `libpcap` | BSD-3-Clause | capture where aircrack-ng is not present |
| `iw`, `rfkill` (util-linux), `ethtool`, `nmcli` (NetworkManager) | GPL-2.0 (GPL-2.0-or-later for iw/util-linux) | interface, radio and NetworkManager control |
| `nmap` | Nmap Public Source License (NPSL) | IT edition discovery — **not** an OSI-approved licence; keep it optional and do not bundle it without reading the NPSL's terms |

The list mirrors `scripts/install-tools.sh`, which installs them from your distribution's
packages. Nothing in this repository redistributes them.

### If you ship a bundle

An AppImage, `.deb`, snap, Flatpak or container image that *contains* these binaries is a
distribution of them, and GPL-2.0/3.0 then requires you to ship the licence texts, the
copyright notices and a written offer of the corresponding source — for **each** GPL tool
in the bundle. `hashcat`, `hcxtools`, `tcpdump` and `hostapd` (mainline) only require their
notice. `wifipilot`'s own dual licence does not change any of that: a bundled product is
still governed by every tool's licence inside it.

## 2. Python dependencies

Declared in `pyproject.toml` and `requirements.txt`; installed from PyPI, never copied in.

| Package | Licence | Role |
|---|---|---|
| `rich` | MIT | the CLI and TUI |
| `fastapi` | MIT | the web API |
| `uvicorn` | BSD-3-Clause | the ASGI server |
| `starlette` | BSD-3-Clause | pulled in by FastAPI |
| `pydantic` | MIT | pulled in by FastAPI |
| `jinja2` | BSD-3-Clause | web templates |
| `httpx` | BSD-3-Clause | dev/test client (also the OpenRouter client path) |
| `pytest`, `pytest-randomly` | MIT | dev/test only |
| `uvicorn[standard]` extras (`uvloop`, `httptools`, `watchfiles`, `websockets`, `python-dotenv`, `PyYAML`, `colorama`) | MIT / BSD-3-Clause | pulled in by the `web` extra |

All of these are permissive and compatible with both of wifipilot's licences. The
authoritative statement for any version you install is that package's own metadata
(`pip show <name>`, or its `dist-info/METADATA`); the table above is the upstream
declaration, not a legal opinion.

## 3. Services, not dependencies

* **Ollama** (MIT) — optional local model server, spoken to over HTTP on loopback.
* **OpenRouter** — optional cloud API; governed by its terms of service, not a licence.
* **Cortex LLMHoster** — optional, **non-commercial** licence. `wifipilot` talks to it over
  HTTP and never vendors it; if you ever bundle it, that non-commercial term attaches to
  the bundle, so keep it an external service.

## 4. What this means for contributors

Contributions are accepted under **Apache-2.0 OR BSD-3-Clause**, matching the project
(see `LICENSE`). Do not paste code from GPL-2.0-only sources into `wifipilot` without
saying so first: it cannot be relicensed under either of this project's licences, and it
would force the whole project to GPL-2.0-only.
