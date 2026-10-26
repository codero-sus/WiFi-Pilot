# wifipilot examples

Runnable scripts that use wifipilot as a library (`import wifipilot as wp`).
Every one of them works with `--demo`, which swaps the radio for a simulated
neighbourhood — so you can run them anywhere, with no adapter and no risk.

| script | what it shows |
|---|---|
| [`triage.py`](triage.py) | listen-only survey (`wp.scan`), signal/WPS/WPA3 summary, JSON export |
| [`crack.py`](crack.py) | offline cracking of captures you already have (`wp.analyze` + `wp.crack`) |
| [`handshake_hunt.py`](handshake_hunt.py) | a live campaign with progress events, an AI provider, loot and a report |

```bash
python3 examples/triage.py --demo -t 5
python3 examples/handshake_hunt.py --demo --mode quick -d 30 -t 3
python3 examples/crack.py loot/*.cap -w /usr/share/wordlists/rockyou.txt

sudo python3 examples/handshake_hunt.py --authorized --target "Cafe Guest" -d 20m
```

`handshake_hunt.py` transmits on a live radio, so it requires `--authorized` (an
attestation that you have written permission to test the targets). If wifipilot is
not installed as a package, run them with the repository on `PYTHONPATH`:
`PYTHONPATH=. python3 examples/triage.py --demo`.

Full API reference: [../docs/PYTHON-API.md](../docs/PYTHON-API.md).
