# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""The OUI registry and what wifipilot knows about a vendor.

Two related things live here:

* **OUI lookup** — ``oui_vendor(mac, strict=True/False)`` and ``oui_lookup()``
  read the bundled registry (``data/oui-wifi.json``: a curated subset of IEEE's
  ``oui.txt`` covering the WiFi/CPE/chipset brands an engagement meets, plus a
  small set of 28-bit blocks).  An exact 24-bit prefix wins; a 28-bit block is
  the fallback; a full ``oui.txt`` can be merged in with
  :func:`import_oui_file` if you want the complete 35,000-entry registry.
* **Vendor dossiers** — what is *usually* true of that brand's access points
  (default PSK schemes, WPS behaviour, roaming hints).  These are heuristics and
  every response says so; they are meant to rank what to try, never to be
  reported as fact.

The point of the dossier is that a freshly discovered AP already has a plan:
``vendor_dossier("AVM GmbH")`` says "try the 16-digit printed key, WPS is
usually on, 2.4 GHz only" — before a single packet has been captured.
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .util import mac_norm

__all__ = ["OUI", "oui_lookup", "oui_vendor", "import_oui_file", "vendor_dossier",
           "VENDOR_DOSSIERS", "oui_stats"]

_DATA = Path(__file__).with_name("data") / "oui-wifi.json"

#: heuristic notes per vendor key.  ``source`` is deliberately "heuristic".
VENDOR_DOSSIERS: Dict[str, Dict[str, Any]] = {
    "AVM": {
        "label": "AVM (FRITZ!Box)",
        "wps": "usually enabled by default, and Pixie-Dust-prone on older firmware",
        "bands": "2.4 + 5 GHz (5 GHz often off on older boxes)",
        "default_key": "16 digits printed on the case (not crackable by dictionary)",
        "notes": "PMF is optional: PMKID capture works. 'FRITZ!Box' ESSIDs leak the model.",
        "attacks": ["pmkid", "handshake", "wps_pixie"],
    },
    "TP-Link": {
        "label": "TP-Link",
        "wps": "enabled by default on most Archer/TL models",
        "bands": "2.4 + 5 GHz",
        "default_key": "8-digit numeric, or nothing at all",
        "notes": "ESSID suffix is usually not the key; PMKID collection tends to be easy.",
        "attacks": ["pmkid", "wps_pixie", "handshake"],
    },
    "Netgear": {
        "label": "NETGEAR",
        "wps": "enabled on many models, often push-button only",
        "bands": "2.4 + 5 GHz",
        "default_key": "dictionary word or short phrase ('password' on old WNR)",
        "notes": "Often hides the SSID; probing clients leak it.",
        "attacks": ["handshake", "pmkid"],
    },
    "Huawei": {
        "label": "Huawei",
        "wps": "on by default on many ONTs",
        "bands": "2.4 GHz on ISP ONTs, 2.4 + 5 on retail",
        "default_key": "8 uppercase characters or 8 digits",
        "notes": "ISP firmware often locks WPS after a few attempts.",
        "attacks": ["pmkid", "wps_pixie", "handshake"],
    },
    "MikroTik": {
        "label": "MikroTik",
        "wps": "off by default",
        "bands": "depends on the card, 2.4/5",
        "default_key": "none (blank) until configured",
        "notes": "RouterOS devices: check for a management page instead of cracking.",
        "attacks": ["handshake", "pmkid"],
    },
    "Ubiquiti": {
        "label": "Ubiquiti",
        "wps": "off by default",
        "bands": "2.4 + 5 GHz",
        "default_key": "random 8-12 characters",
        "notes": "Enterprise-ish deployment: client-side and WPS routes are the realistic ones.",
        "attacks": ["handshake", "pmkid"],
    },
    "Cisco": {
        "label": "Cisco",
        "wps": "varies; often off",
        "bands": "2.4 + 5 GHz",
        "default_key": "per-site configuration",
        "notes": "Business APs: look for a known PSK from other footage or a weak WPA2-Enterprise client.",
        "attacks": ["handshake"],
    },
    "ASUS": {
        "label": "ASUS",
        "wps": "enabled by default on consumer models",
        "bands": "2.4 + 5 GHz",
        "default_key": "10 digits or a short mixed string",
        "notes": "AiMesh satellites broadcast the same key with a different BSSID.",
        "attacks": ["pmkid", "handshake", "wps_pixie"],
    },
    "Zyxel": {
        "label": "Zyxel",
        "wps": "varies by ISP firmware",
        "bands": "2.4 + 5 GHz",
        "default_key": "mixed schemes; ISP variants use an 8-digit number",
        "notes": "Common on European fibre ONTs.",
        "attacks": ["pmkid", "wps_pixie"],
    },
    "ARRIS": {
        "label": "ARRIS",
        "wps": "on by default on many cable gateways",
        "bands": "2.4 + 5 GHz",
        "default_key": "8 digits or a mixed 12-character key",
        "notes": "Cable ISP gateways expose the same PSK on both bands.",
        "attacks": ["pmkid", "handshake"],
    },
    "D-Link": {
        "label": "D-Link",
        "wps": "on by default on most models",
        "bands": "2.4 + 5 GHz",
        "default_key": "blank, 'admin', 8 digits, or 10 alphanumerics",
        "notes": "A surprising number ship with no PSK at all — try an open join first.",
        "attacks": ["pmkid", "wps_pixie", "handshake"],
    },
    "Belkin": {
        "label": "Belkin",
        "wps": "enabled by default on most F routers and extenders",
        "bands": "2.4 + 5 GHz",
        "default_key": "often blank at first boot, or an 8-character word",
        "notes": "Belkin and Linksys share ownership: WPS is push-button on newer "
                 "firmware and PIN on older builds.",
        "attacks": ["wps_pixie", "handshake", "pmkid"],
    },
    "Linksys": {
        "label": "Linksys",
        "wps": "PIN enabled by default on many EA/EA-Series builds",
        "bands": "2.4 + 5 GHz",
        "default_key": "'admin' or a word from the setup wizard",
        "notes": "Smart Wi-Fi models require a cloud account before the local UI "
                 "opens; the PSK is still WPA2-PSK underneath.",
        "attacks": ["wps_pixie", "handshake", "pmkid"],
    },
    "MediaTek": {
        "label": "MediaTek / Ralink",
        "wps": "varies by OEM firmware (the chipset alone decides nothing)",
        "bands": "2.4 + 5 GHz",
        "default_key": "set by the OEM, not the chipset vendor",
        "notes": "Chipset OUIs appear on OEM boards: trust the ESSID and the "
                 "capture, not the brand on the radio.",
        "attacks": ["handshake", "pmkid"],
    },
    "Edimax": {
        "label": "Edimax",
        "wps": "enabled by default on most BR/EW series",
        "bands": "2.4 + 5 GHz",
        "default_key": "'1234' style PIN and no PSK on some travel routers",
        "notes": "Travel routers frequently ship open or with WPS-only protection.",
        "attacks": ["wps_pixie", "handshake"],
    },
    "Buffalo": {
        "label": "Buffalo",
        "wps": "enabled by default on many AirStation models",
        "bands": "2.4 + 5 GHz",
        "default_key": "printed key or 'password' on older AirStations",
        "notes": "AirStation firmware exposes the WPS PIN in the web UI once the "
                 "device is reachable.",
        "attacks": ["wps_pixie", "handshake", "pmkid"],
    },
    "locally administered": {
        "label": "locally administered (randomised MAC)",
        "wps": "n/a",
        "bands": "n/a",
        "default_key": "n/a",
        "notes": "Phone hotspots and virtual APs: the MAC tells you it is not a router.",
        "attacks": [],
    },
}

#: alias -> dossier key
_ALIASES = {
    "avm gmbh": "AVM", "fritz": "AVM", "fritz!box": "AVM",
    "tp-link technologies": "TP-Link", "tplink": "TP-Link",
    "netgear": "Netgear", "net gear": "Netgear",
    "huawei technologies": "Huawei", "mikrotik": "MikroTik", "routerboard": "MikroTik",
    "ubiquiti networks": "Ubiquiti", "ubnt": "Ubiquiti",
    "cisco-linksys": "Cisco", "linksys": "Linksys", "cisco systems": "Cisco",
    "asustek": "ASUS", "asustek computer": "ASUS",
    "zyxel communications": "Zyxel", "arris group": "ARRIS",
    "d-link": "D-Link", "dlink": "D-Link",
    "avm": "AVM", "tplink technologies": "TP-Link", "netgear inc": "Netgear",
    "arris group inc": "ARRIS",
    "ralink": "MediaTek", "mediatek": "MediaTek",
    "linksys llc": "Linksys", "cisco systems inc": "Cisco",
}


def _load() -> Dict[str, Dict[str, str]]:
    try:
        with open(_DATA, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {"exact": {}, "prefix": {}}
    exact = dict(data.get("exact") or {})
    prefix = dict(data.get("prefix") or {})
    return {"exact": exact, "prefix": prefix}


OUI: Dict[str, Dict[str, str]] = _load()


def oui_stats() -> Dict[str, object]:
    return {"exact": len(OUI["exact"]), "prefix": len(OUI["prefix"]),
            "best": len(OUI["exact"]) == 0,
            "file": str(_DATA),
            "readable": os.path.exists(_DATA)}


def _mac_key(mac: str) -> str:
    """Normalise a MAC — including the bare-hex spellings tools print.

    ``mac_norm`` wants colons, but hashcat/hcxdumptool lines and csv exports
    hand us ``d012cb000001`` or ``D012CB``, so those are expanded here.
    """
    text = (mac or "").strip()
    bare = re.sub(r"[^0-9A-Fa-f]", "", text)
    if len(text) in (12, 7, 6) and len(bare) == len(text):
        # a bare OUI block (6 or 7 hex digits) is an exact-prefix query: pad it
        padded = bare.ljust(12, "0")
        text = ":".join(padded[i:i + 2] for i in range(0, 12, 2))
    return mac_norm(text)


def oui_lookup(mac: str) -> Tuple[str, str]:
    """``(vendor, match)``: ``"exact"``, ``"prefix"``, ``"local"`` or ``"none"``."""
    key = _mac_key(mac)
    if not key:
        return "", ""
    vendor = OUI["exact"].get(key[:8])
    if vendor:
        return vendor, "exact"
    vendor = OUI["prefix"].get(key[:7])
    if vendor:
        return vendor, "prefix"
    # locally administered bit (bit 1 of the first octet) — never a real OUI
    try:
        first = int(key.split(":")[0], 16)
    except (ValueError, IndexError):
        return "", "none"
    if first & 0x02:
        return "locally administered", "local"
    return "", "none"


def oui_vendor(mac: str, strict: bool = False) -> str:
    """Vendor for a MAC.  ``strict`` disables the 28-bit block fallback."""
    key = _mac_key(mac)
    if not key:
        return ""
    vendor = OUI["exact"].get(key[:8])
    if vendor:
        return vendor
    return "" if strict else OUI["prefix"].get(key[:7], "")


def import_oui_file(path: str, out: str = "") -> Dict[str, object]:
    """Merge IEEE's ``oui.txt`` (or an ``OUI:`` list) into the bundled registry.

    The registry file is JSON, so the merge is a dict update: prefixes from the
    file *add to* whatever the target already holds (an existing entry for the
    same prefix is replaced, never the whole registry — losing 10,000 prefixes
    to one import is not a merge).  With ``out`` omitted the bundled registry is
    updated in place; pass ``out`` to write somewhere else instead.
    """
    exact: Dict[str, str] = {}
    checked = 0
    assigned = 0
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.rstrip("\n")
            match = re.match(r"^([0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2})"
                             r"\s*\(?(?:hex|base16)?\)?\s+(.+)$", line)
            if not match and "\t" in line:
                parts = line.split("\t", 1)
                if re.match(r"^[0-9A-Fa-f]{6}$", parts[0].strip()):
                    match = re.match(r"^([0-9A-Fa-f]{6})\t(.+)$", line)
            if not match:
                continue
            checked += 1
            prefix = match.group(1).lower().replace("-", ":")
            name = match.group(2).strip()
            if prefix and name:
                exact[prefix] = name
                assigned += 1
    target = out or str(_DATA)
    try:
        current = json.loads(Path(target).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        current = {}
    merged_exact = dict(current.get("exact") or {})
    merged_exact.update(exact)
    merged_prefix = dict(current.get("prefix") or {}) or dict(OUI["prefix"])
    data = {
        "notes": current.get("notes") or "curated IEEE OUI subset plus local imports",
        "source": current.get("source", "IEEE OUI registry (oui.txt), redistributed subset"),
        "imports": (current.get("imports") or 0) + 1,
        "exact": dict(sorted(merged_exact.items())),
        "prefix": merged_prefix,
    }
    Path(target).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return {"path": target, "parsed": checked, "vendors": assigned,
            "exact": len(exact)}


_DOSSIER_LOOKUP: Optional[Tuple[Dict[str, str], List[Tuple[str, str]],
                                List[Tuple[str, str]]]] = None


def _dossier_lookup() -> Tuple[Dict[str, str], List[Tuple[str, str]],
                               List[Tuple[str, str]]]:
    """Pre-lowered dossier keys, built once (the tables are static)."""
    global _DOSSIER_LOOKUP
    if _DOSSIER_LOOKUP is None:
        exact: Dict[str, str] = {}
        lowered_keys: List[Tuple[str, str]] = []
        for key in VENDOR_DOSSIERS:
            lowered = key.lower()
            exact.setdefault(lowered, key)      # first wins, as the scan did
            lowered_keys.append((lowered, key))
        _DOSSIER_LOOKUP = (exact, lowered_keys, list(_ALIASES.items()))
    return _DOSSIER_LOOKUP


@lru_cache(maxsize=1024)
def _key_for_lowered(lowered: str) -> str:
    exact, lowered_keys, aliases = _dossier_lookup()
    # an exact dossier key always wins: a stale alias must never shadow the
    # vendor's own entry (``linksys`` used to point at its one-time parent)
    hit = exact.get(lowered)
    if hit is not None:
        return hit
    if lowered in _ALIASES:
        return _ALIASES[lowered]
    for low, key in lowered_keys:
        if lowered.startswith(low) or low in lowered:
            return key
    for alias, key in aliases:
        if alias in lowered:
            return key
    return ""


def _key_for(vendor: str) -> str:
    text = (vendor or "").strip()
    if not text:
        return ""
    # vendor strings repeat constantly during a scan: resolve each once
    return _key_for_lowered(text.lower())


def vendor_dossier(vendor_or_mac: str, mac: str = "") -> Dict[str, Any]:
    """What wifipilot knows about a vendor (or a MAC's vendor).

    Always includes ``confidence``: ``"heuristic"`` when a dossier matched,
    ``"unknown"`` when it did not — the caller must not present a heuristic as a
    measurement.
    """
    vendor = vendor_or_mac
    if mac_norm(vendor_or_mac) and not _key_for(vendor_or_mac):
        vendor = oui_vendor(vendor_or_mac) or oui_vendor(mac)
    key = _key_for(vendor)
    if not key:
        # keep the shape the same as a matched dossier: callers iterate attacks
        return {"vendor": vendor, "confidence": "unknown", "matched": False,
                "key": "", "label": vendor or "unknown vendor",
                "wps": "", "bands": "", "default_key": "", "attacks": [],
                "notes": "no dossier for this vendor: treat it like any other AP"}
    dossier = dict(VENDOR_DOSSIERS[key])
    dossier.update({"vendor": vendor or dossier.get("label", key), "key": key,
                    "confidence": "heuristic", "matched": True,
                    "disclaimer": "vendor behaviour varies by model and firmware; "
                                  "these are starting points, not findings"})
    return dossier
