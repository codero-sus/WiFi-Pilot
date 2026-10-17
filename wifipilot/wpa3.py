# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""WPA3: SAE exchanges, PMF, OWE and the transition-mode downgrade.

WPA3 is not "WPA2 but harder to crack" — it removes the offline attack entirely.
SAE (Dragonfly) is a password-authenticated key exchange, so a capture of the
commit/confirm exchange cannot be dictionary-checked the way a WPA2 handshake can;
what it *can* tell you is which group was used, whether the network is really
WPA3-only, and whether it also offers a WPA2 path that is worth attacking instead.

That last point is the whole reason this module exists.  A "WPA3" access point in
transition mode advertises both SAE and PSK, and the PSK side still produces a
crackable 4-way handshake — the strongest network on site is usually reachable
through its weakest advertised AKM.  The same walk answers the neighbouring
questions:

* **PMF** (802.11w) — if management frame protection is not *required*, deauth-based
  capture works; if it is, the handshake needs a client that roams.
* **OWE** (Enhanced Open) — an OWE transition network advertises an open SSID next to
  the encrypted one, which is what a downgrade twin imitates.

Everything here is read-only: it parses beacons and SAE frames that are already on
air.  No key is derived, no candidate is guessed, and a PAKE is never claimed to
have fallen to an offline attack it is immune to.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .pcap import (SUBTYPE_AUTH, SUBTYPE_BEACON, SUBTYPE_PROBE_RESP, TYPE_MGMT,
                   iter_frames, essid_from_beacon)
from .util import mac_norm

__all__ = ["AKM_SUITES", "CIPHER_SUITES", "RsnInfo", "rsn_from_ies", "rsn_capabilities",
           "capture_wpa3", "SaeExchange", "sae_exchange", "wpa3_findings",
           "SAE_GROUPS"]

#: AKM suite selectors worth naming (the rest are reported as their hex selector)
AKM_SUITES = {
    1: "802.1X", 2: "PSK", 3: "FT-802.1X", 4: "FT-PSK", 5: "802.1X-SHA256",
    6: "PSK-SHA256", 8: "SAE", 9: "FT-SAE", 12: "802.1X-SUITE-B",
    13: "802.1X-SUITE-B-192", 18: "OWE", 24: "SAE-EXT-KEY", 25: "FT-SAE-EXT-KEY",
}

CIPHER_SUITES = {0: "USE-GROUP", 1: "WEP-40", 2: "TKIP", 4: "CCMP", 5: "WEP-104",
                 6: "BIP-CMAC-128", 8: "GCMP-128", 9: "GCMP-256", 10: "CCMP-256",
                 11: "BIP-GMAC-128", 12: "BIP-GMAC-256", 13: "BIP-CMAC-256"}

#: SAE groups seen in the wild (a commit frame's status field carries the group)
SAE_GROUPS = {0: "unspecified", 1: "group 1 (768-bit MODP)", 2: "group 2 (1024-bit MODP)",
              5: "group 5 (1536-bit MODP)", 14: "group 14 (2048-bit MODP)",
              15: "group 15 (3072-bit MODP)", 16: "group 16 (4096-bit MODP)",
              19: "group 19 (256-bit ECP)", 20: "group 20 (384-bit ECP)",
              21: "group 21 (521-bit ECP)", 22: "group 22 (1024-bit MODP)",
              23: "group 23 (2048-bit MODP)", 24: "group 24 (3072-bit MODP)"}


@dataclass
class RsnInfo:
    """What an RSN information element says about a network's security."""

    akm: List[int] = field(default_factory=list)
    pairwise: List[int] = field(default_factory=list)
    group: int = 0
    capabilities: int = 0

    @property
    def akm_names(self) -> List[str]:
        return [AKM_SUITES.get(code, f"akm-{code}") for code in self.akm]

    @property
    def pairwise_names(self) -> List[str]:
        return [CIPHER_SUITES.get(code, f"cipher-{code}") for code in self.pairwise]

    @property
    def sae(self) -> bool:
        return any(code in (8, 9, 24, 25) for code in self.akm)

    @property
    def psk(self) -> bool:
        return any(code in (2, 4, 6) for code in self.akm)

    @property
    def enterprise(self) -> bool:
        return any(code in (1, 3, 5, 12, 13) for code in self.akm)

    @property
    def owe(self) -> bool:
        return 18 in self.akm

    @property
    def mfpc(self) -> bool:
        """Management frame protection *capable* (RSN capabilities bit 5)."""
        return bool(self.capabilities & 0x0020)

    @property
    def mfpr(self) -> bool:
        """Management frame protection *required* (RSN capabilities bit 4)."""
        return bool(self.capabilities & 0x0010)

    @property
    def transition_mode(self) -> bool:
        """SAE *and* PSK advertised: the WPA2 door is still open."""
        return self.sae and self.psk

    def to_dict(self) -> Dict[str, Any]:
        return {
            "akm": self.akm_names, "pairwise": self.pairwise_names,
            "group": CIPHER_SUITES.get(self.group, f"cipher-{self.group}"),
            "sae": self.sae, "psk": self.psk, "enterprise": self.enterprise,
            "owe": self.owe, "mfpc": self.mfpc, "mfpr": self.mfpr,
            "transition_mode": self.transition_mode, "capabilities": self.capabilities,
        }


def rsn_from_ies(ies: bytes) -> Optional[RsnInfo]:
    """Parse the RSN information element out of a beacon/probe-response IE blob."""
    offset = 0
    while offset + 2 <= len(ies):
        element_id = ies[offset]
        length = ies[offset + 1]
        body = ies[offset + 2:offset + 2 + length]
        offset += 2 + length
        if element_id != 48 or len(body) < 8:            # 48 = RSN
            continue
        info = RsnInfo()
        cursor = 2                                       # skip version
        info.group = int.from_bytes(body[cursor:cursor + 4], "little") & 0xFF
        cursor += 4
        if cursor + 2 > len(body):
            return info
        count = int.from_bytes(body[cursor:cursor + 2], "little")
        cursor += 2
        for _ in range(count):
            if cursor + 4 > len(body):
                return info
            info.pairwise.append(int.from_bytes(body[cursor:cursor + 4], "little") & 0xFF)
            cursor += 4
        if cursor + 2 > len(body):
            return info
        count = int.from_bytes(body[cursor:cursor + 2], "little")
        cursor += 2
        for _ in range(count):
            if cursor + 4 > len(body):
                return info
            info.akm.append(int.from_bytes(body[cursor:cursor + 4], "little") & 0xFF)
            cursor += 4
        if cursor + 2 <= len(body):
            info.capabilities = int.from_bytes(body[cursor:cursor + 2], "little")
        return info
    return None


def rsn_capabilities(ies: bytes) -> Tuple[bool, bool]:
    """``(mfpc, mfpr)`` for a beacon's IE blob, ``(False, False)`` when no RSN IE."""
    info = rsn_from_ies(ies)
    if info is None:
        return False, False
    return info.mfpc, info.mfpr


@dataclass
class BssRsn:
    bssid: str
    essid: str = ""
    info: Optional[RsnInfo] = None
    channel: int = 0
    beacons: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {"bssid": self.bssid, "essid": self.essid, "channel": self.channel,
                "beacons": self.beacons, "rsn": self.info.to_dict() if self.info else None}


def capture_wpa3(path: str, max_packets: int = 200_000) -> Dict[str, Any]:
    """RSN facts per BSSID out of a capture's beacons and probe responses.

    Read-only, and deliberately small: airodump's CSV does not carry the RSN
    capabilities word, so the MFPC/MFPR bits — the difference between "deauth works"
    and "the client must roam" — can only come from the frames themselves.
    """
    networks: Dict[str, BssRsn] = {}
    frames = 0
    for _ts, buf, start, length in iter_frames(str(path), max_packets=max_packets):
        frames += 1
        from .pcap import _parse_frame
        parsed = _parse_frame(buf, start, length)
        if parsed is None:
            continue
        ftype, subtype, bssid, _station, payload_at = parsed
        if ftype != TYPE_MGMT or subtype not in (SUBTYPE_BEACON, SUBTYPE_PROBE_RESP):
            continue
        bssid = mac_norm(bssid)
        if not bssid or payload_at >= length:
            continue
        ies = bytes(buf[start + payload_at:start + length])
        entry = networks.get(bssid)
        if entry is None:
            entry = networks[bssid] = BssRsn(bssid=bssid)
        entry.beacons += 1
        essid = essid_from_beacon(ies)
        if essid and not entry.essid:
            entry.essid = essid
        if entry.info is None:
            entry.info = rsn_from_ies(ies)
    return {"path": str(path), "frames": frames,
            "networks": [entry.to_dict() for entry in networks.values()],
            "note": "read-only: beacons and probe responses, nothing transmitted"}


# --------------------------------------------------------------------------- #
# SAE (WPA3) exchange
# --------------------------------------------------------------------------- #


@dataclass
class SaeExchange:
    """One station's SAE authentication attempt."""

    bssid: str
    station: str
    commits: int = 0
    confirms: int = 0
    groups: List[int] = field(default_factory=list)
    status: List[int] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        """Commit *and* confirm seen: the exchange ran to the end."""
        return self.commits > 0 and self.confirms > 0

    @property
    def group_name(self) -> str:
        if not self.groups:
            return ""
        return SAE_GROUPS.get(self.groups[0], f"group {self.groups[0]}")

    def to_dict(self) -> Dict[str, Any]:
        return {"bssid": self.bssid, "station": self.station,
                "commits": self.commits, "confirms": self.confirms,
                "complete": self.complete, "group": self.group_name,
                "status": self.status}


def sae_exchange(path: str, max_packets: int = 200_000) -> Dict[str, Any]:
    """SAE commit/confirm exchanges in a capture, per station.

    SAE is a PAKE: the commit frame commits to a password without revealing
    anything that can be checked offline, so this reports the exchange and the
    group and says so — a WPA3 network does not fall to a wordlist.  What is
    actionable is elsewhere in the network: transition mode, PMF, and the WPA2
    path those two leave open.
    """
    from .pcap import _parse_frame
    exchanges: Dict[Tuple[str, str], SaeExchange] = {}
    auth_frames = 0
    for _ts, buf, start, length in iter_frames(str(path), max_packets=max_packets):
        parsed = _parse_frame(buf, start, length)
        if parsed is None:
            continue
        ftype, subtype, bssid, station, payload_at = parsed
        if ftype != TYPE_MGMT or subtype != SUBTYPE_AUTH:
            continue
        # a management frame's body starts right after the 24-byte header; the frame
        # walker reports the *beacon* payload offset (header + 12 fixed bytes), which
        # would skip an authentication frame's algorithm/transaction/status fields
        body = bytes(buf[start + 24:start + length])
        if len(body) < 6:
            continue
        algorithm = int.from_bytes(body[0:2], "little")
        if algorithm != 3:                              # 3 = SAE
            continue
        transaction = int.from_bytes(body[2:4], "little")
        status = int.from_bytes(body[4:6], "little")
        if transaction not in (1, 2):                    # 1 = commit, 2 = confirm
            continue
        auth_frames += 1
        bssid, station = mac_norm(bssid), mac_norm(station)
        entry = exchanges.get((bssid, station))
        if entry is None:
            entry = exchanges[(bssid, station)] = SaeExchange(bssid=bssid, station=station)
        if transaction == 1:
            entry.commits += 1
            if status not in entry.groups:
                entry.groups.append(status)
        else:
            entry.confirms += 1
        entry.status.append(status)
    ordered = sorted(exchanges.values(), key=lambda item: -(item.commits + item.confirms))
    return {
        "path": str(path), "auth_frames": auth_frames,
        "exchanges": [entry.to_dict() for entry in ordered],
        "complete": sum(1 for entry in ordered if entry.complete),
        "feasible_offline_attack": False,
        "note": ("SAE is a PAKE: the commit/confirm exchange cannot be checked "
                 "offline, so a WPA3 network does not fall to a wordlist. Capture it "
                 "for the report, then look at transition mode, PMF and the WPA2 AKM "
                 "the network may also advertise"),
    }


# --------------------------------------------------------------------------- #
# findings
# --------------------------------------------------------------------------- #


def wpa3_findings(networks: Iterable[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Actionable conclusions from RSN facts, each with the reason it is actionable.

    A finding here is a *path*, not a vulnerability: transition mode means the WPA2
    handshake is still on the table, unprotected management frames mean a deauth can
    force one, and an OWE transition SSID is what a downgrade twin imitates.
    """
    out: List[Dict[str, str]] = []
    for entry in networks:
        rsn = entry.get("rsn") or {}
        essid = entry.get("essid") or entry.get("bssid", "")
        bssid = entry.get("bssid", "")
        if not rsn:
            continue
        if rsn.get("transition_mode"):
            out.append({
                "kind": "wpa3_transition", "bssid": bssid, "essid": essid,
                "severity": "medium",
                "title": "WPA3 transition mode: the WPA2 path is still open",
                "detail": (f"{essid} advertises SAE *and* PSK ({', '.join(rsn['akm'])}): "
                           f"a client can be brought down to the WPA2 handshake, which "
                           f"is captured and cracked like any other.  WPA3 alone would "
                           f"not offer that path."),
            })
        elif rsn.get("sae") and not rsn.get("mfpr"):
            out.append({
                "kind": "wpa3_no_pmf", "bssid": bssid, "essid": essid,
                "severity": "low",
                "title": "WPA3 without required management frame protection",
                "detail": (f"{essid} uses SAE but does not *require* PMF: management "
                           f"frames are unprotected, so clients can be disconnected "
                           f"(the handshake itself stays uncrackable offline)."),
            })
        if rsn.get("owe"):
            out.append({
                "kind": "owe_transition", "bssid": bssid, "essid": essid,
                "severity": "info",
                "title": "OWE (Enhanced Open) in use",
                "detail": (f"{essid} advertises OWE: the data is encrypted without a "
                           f"passphrase, and a transition-mode twin that offers a plain "
                           f"open SSID next to it is the classic downgrade lure."),
            })
        if rsn.get("psk") and not rsn.get("sae") and not rsn.get("mfpr"):
            out.append({
                "kind": "no_pmf", "bssid": bssid, "essid": essid,
                "severity": "low",
                "title": "WPA2 without required PMF",
                "detail": (f"{essid} does not require 802.11w: a deauthentication burst "
                           f"can force a fresh handshake, which is what the handshake "
                           f"attack needs."),
            })
    return out
