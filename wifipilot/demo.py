"""Simulation radio: a fake neighbourhood so wifipilot is testable and demoable.

Everything downstream of discovery (scoring, planning, attacks, cracking,
reporting, the web UI) runs against this exactly as it runs against a real
airodump-ng CSV — only the packet source is synthetic.  This is what makes the
"try it without hardware" button in the UI honest: the code paths are the same,
the radio is not.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .scanner import ApRecord, ClientRecord, channel_to_freq

# --- a believable, deliberately varied set of targets --------------------- #

SSID_POOL = [
    "HOME-2F4A", "TP-LINK_A1B2", "FRITZ!Box 7530 XR", "Vodafone-9C31",
    "NETGEAR47", "Gastzugang-Cafe", "Synology_WiFi", "AndroidAP_8921",
    "KabelBox-4321", "dlink-3F21", "Lobby-Guest", "Warehouse-AP2",
    "ideapad-L340", "HUAWEI-B535-4C1D", "PRINTER-4F", "WLAN-Hotspot-Rathaus",
    "Sophos-WiFi", "Cisco-Setup", "IoT-Net", "iPhone von Lisa",
]

VENDORS = ["TP-Link", "Netgear", "AVM", "Vodafone", "D-Link", "Huawei",
           "Ubiquiti", "Cisco", "Synology", "unknown"]


@dataclass
class DemoAP:
    bssid: str
    essid: str
    channel: int
    encryption: str
    privacy: str
    cipher: str
    auth: str
    signal: int
    vendor: str
    wps: bool = False
    wps_locked: str = ""
    wps_version: str = "1.0"
    wps_model: str = ""
    wps_manufacturer: str = ""
    hidden: bool = False
    hidden_name: str = ""      # the name a client reveals for a hidden network
    eap_method: str = ""       # 802.1X only
    eap_identity: str = ""
    eap_certificate: str = ""
    client_count: int = 0
    psk: str = ""              # set -> the demo will hand it over when cracked
    pmkid_vulnerable: bool = True
    wps_pixie_vulnerable: bool = False
    wps_pin_hint: str = ""
    deauth_visible: bool = True
    beacon_count: int = 0
    data_count: int = 0
    clients: List[ClientRecord] = field(default_factory=list)
    # runtime
    jitter: float = 0.0
    first_seen: float = field(default_factory=time.time)


def _demo_mac(rng: random.Random, locally_administered: bool = False) -> str:
    """A MAC drawn from the seeded RNG.

    The simulator has to be reproducible: a scan whose result cannot be used as
    a target for the next call makes scripted runs (and the tests) useless.
    """
    raw = bytearray(rng.getrandbits(8) for _ in range(6))
    raw[0] = (raw[0] | 0x02) if locally_administered else (raw[0] & ~0x02)
    raw[0] &= ~0x01                                  # unicast
    return ":".join(f"{byte:02x}" for byte in raw)


def build_neighbourhood(seed: Optional[int] = None) -> List[DemoAP]:
    rng = random.Random(seed if seed is not None else 20240920)
    aps: List[DemoAP] = []

    def add(essid, channel, encryption, signal, vendor, **kw) -> None:
        ap = DemoAP(
            bssid=_demo_mac(rng),
            essid=essid, channel=channel, signal=signal, vendor=vendor,
            encryption=encryption,
            privacy={"WPA2": "WPA2", "WPA3": "WPA3", "WPA2/WPA3": "WPA2 WPA3",
                     "WEP": "WEP", "OPEN": "OPN", "WPA": "WPA",
                     "ENTERPRISE": "WPA2"}[encryption],
            cipher=("TKIP" if encryption == "WPA" else
                    "WEP" if encryption == "WEP" else
                    "OPN" if encryption == "OPEN" else "CCMP"),
            auth="SAE" if encryption == "WPA3" else ("MGT" if encryption == "ENTERPRISE" else "PSK"),
            beacon_count=kw.pop("beacon_count", rng.randint(40, 400)),
            data_count=kw.pop("data_count", rng.randint(0, 5000)),
            **kw,
        )
        aps.append(ap)

    # the juicy one: WPS unlocked + weak PSK + clients to deauth
    add("HOME-2F4A", 6, "WPA2", -42, "TP-Link", wps=True, wps_locked="unlocked",
        wps_model="Archer C7", wps_manufacturer="TP-LINK Technologies Co.,Ltd.",
        client_count=3, psk="sunshine2015", wps_pixie_vulnerable=True)
    # client-less PMKID target
    add("FRITZ!Box 7530 XR", 11, "WPA2", -55, "AVM", wps=False, client_count=0,
        psk="Fritz!Box7530", pmkid_vulnerable=True)
    # strong WPA3-only: nothing to do, tests the planner's refusal logic
    add("Vodafone-9C31", 100, "WPA3", -61, "Vodafone", client_count=2,
        psk="ThisWillNotBeCrackedEasily!", pmkid_vulnerable=False)
    # transition mode: WPA2 clients still deauthable
    add("KabelBox-4321", 1, "WPA2/WPA3", -67, "AVM", wps=True,
        wps_locked="locked", client_count=1, psk="kabelbox123")
    # open guest network
    add("Gastzugang-Cafe", 1, "OPEN", -58, "unknown", client_count=4)
    # hidden SSID, no WPS — a client knows the name even when the AP hides it
    add("", 9, "WPA2", -72, "Netgear", hidden=True, client_count=1,
        hidden_name="NETGEAR-Home-9F", psk="hunter2hunter2")
    # 802.1X: the finding is the server certificate, not a PSK
    add("CorpNet-8021X", 36, "ENTERPRISE", -64, "Cisco", client_count=3,
        eap_method="PEAP", eap_identity="jdoe@corp.example",
        eap_certificate="self-signed certificate")
    # the weak old thing: WEP
    add("PRINTER-4F", 3, "WEP", -70, "D-Link", psk="12345ABCDE",
        data_count=180000, client_count=1)
    # WPS PIN default-ish device (bully/reaver territory)
    add("NETGEAR47", 4, "WPA2", -63, "Netgear", wps=True, wps_locked="unlocked",
        wps_model="WNR2000v4", wps_manufacturer="NETGEAR", client_count=2,
        psk="netgear47", wps_pin_hint="default")
    # 5 GHz with no WPS and busy clients
    add("Synology_WiFi", 44, "WPA2", -74, "Synology", client_count=5,
        psk="synology2024")
    # noisy far-away AP
    add("IoT-Net", 13, "WPA2", -88, "Huawei", wps=True, wps_locked="unlocked",
        wps_version="2.0", client_count=1, psk="iotnet123")
    return aps


class DemoRadio:
    """Emits ApRecord/ClientRecord dictionaries on each ``tick()``.

    It also *reacts* to the rest of wifipilot: :meth:`deauth` simulates clients
    reconnecting (which is when our capture modules decide a handshake arrived),
    :meth:`handshake_after_deauth` decides whether that actually worked, and
    :meth:`crack` reproduces a plausible aircrack/hashcat run.
    """

    def __init__(self, seed: Optional[int] = None, verbose: bool = False):
        self.seed = seed if seed is not None else 20240920
        self.rng = random.Random(self.seed)
        self.aps: List[DemoAP] = build_neighbourhood(self.seed)
        self.verbose = verbose
        self.started = time.time()
        self.deauth_events: List[Dict[str, Any]] = []
        self.captured_handshakes: Dict[str, float] = {}
        self.captured_pmkids: Dict[str, float] = {}
        self.emitted: Dict[str, int] = {}

    # -- discovery ---------------------------------------------------------
    def tick(self) -> List[Any]:
        """One second of "radio": RSSI jitter, new clients, unknown APs."""
        out: List[Any] = []
        elapsed = time.time() - self.started
        for ap in self.aps:
            ap.jitter += self.rng.uniform(-1.5, 1.5)
            ap.jitter = max(-4.0, min(4.0, ap.jitter))
            ap.beacon_count += self.rng.randint(5, 12)
            if self.rng.random() < 0.35:
                ap.data_count += self.rng.randint(0, 60)
            self.emitted[ap.bssid] = self.emitted.get(ap.bssid, 0) + 1
            out.append(ApRecord(
                bssid=ap.bssid,
                essid="" if ap.hidden else ap.essid,
                channel=ap.channel,
                frequency=channel_to_freq(ap.channel),
                privacy=ap.privacy, cipher=ap.cipher, auth=ap.auth,
                signal=int(round(ap.signal + ap.jitter)),
                beacons=ap.beacon_count, data=ap.data_count,
                essid_len=0 if ap.hidden else len(ap.essid),
            ))
        # WPS capability records (normally supplied by wash)
        for ap in self.aps:
            if ap.wps:
                out.append({
                    "bssid": ap.bssid,
                    "wps_locked": ap.wps_locked or "unknown",
                    "wps_version": ap.wps_version or "1.0",
                    "wps_model": ap.wps_model,
                    "wps_manufacturer": ap.wps_manufacturer,
                })
        # clients trickle in; after a deauth they "reconnect" all at once
        names = [item.essid for item in self.aps if item.essid]
        for ap in self.aps:
            want = ap.client_count
            need_new = len(ap.clients) < want
            reconnect = ap.bssid in self.captured_handshakes and self.rng.random() < 0.25
            if need_new or reconnect:
                if len(ap.clients) < max(want, 6):
                    # a real station remembers several networks, not only the one it
                    # is talking to — that list is what the tracker reads
                    probes = [ap.essid] if ap.essid else []
                    for _ in range(self.rng.randint(1, 3)):
                        other = self.rng.choice(names) if names else ""
                        if other and other != ap.essid and other not in probes:
                            probes.append(other)
                    client = ClientRecord(
                        mac=_demo_mac(self.rng, locally_administered=True),
                        bssid=ap.bssid,
                        signal=int(ap.signal + self.rng.randint(2, 12)),
                        packets=self.rng.randint(20, 900),
                        probes=probes,
                    )
                    ap.clients.append(client)
        for ap in self.aps:
            for client in ap.clients:
                client.packets += self.rng.randint(1, 40)
                out.append(client)
        # a neighbour appears after ~20s to keep the UI alive
        if elapsed > 20 and len(self.aps) < 14 and self.rng.random() < 0.25:
            name = self.rng.choice([s for s in SSID_POOL if s not in {a.essid for a in self.aps}])
            new_ap = DemoAP(
                bssid=_demo_mac(self.rng), essid=name, channel=self.rng.choice([1, 6, 11, 36, 149]),
                encryption="WPA2", privacy="WPA2", cipher="CCMP", auth="PSK",
                signal=self.rng.randint(-85, -60), vendor=self.rng.choice(VENDORS),
                client_count=self.rng.randint(0, 3), psk="newneighbour",
            )
            self.aps.append(new_ap)
        return out

    # -- attack reactions --------------------------------------------------
    def deauth(self, bssid: str, count: int = 5, broadcast: bool = False) -> Dict[str, Any]:
        """Simulate an aireplay-ng deauth burst."""
        ap = self.find(bssid)
        if ap is None:
            return {"sent": 0, "reconnected": 0}
        sent = count
        reconnected = 0
        if ap.auth == "SAE" and ap.encryption == "WPA3":
            reconnected = 0                      # PMF protects it
        else:
            reconnected = len(ap.clients) if ap.clients else 0
            if reconnected == 0 and self.rng.random() < 0.5:
                reconnected = 1                  # client walks back into range
                ap.clients.append(ClientRecord(mac=_demo_mac(self.rng, True),
                                               bssid=ap.bssid, signal=ap.signal))
        event = {"bssid": bssid, "sent": sent, "reconnected": reconnected, "ts": time.time()}
        self.deauth_events.append(event)
        return event

    def handshake_ok(self, bssid: str, attempts: int) -> bool:
        """Did the deauth+listen cycle capture a 4-way handshake?"""
        ap = self.find(bssid)
        if ap is None:
            return False
        if not ap.deauth_visible or ap.encryption == "WPA3":
            return self.rng.random() < 0.03
        if ap.clients and attempts >= 1:
            self.captured_handshakes[bssid] = time.time()
            return True
        return self.rng.random() < 0.25 * min(attempts, 4)

    def pmkid_ok(self, bssid: str) -> bool:
        ap = self.find(bssid)
        if ap is None:
            return False
        if not ap.pmkid_vulnerable:
            return False
        if self.rng.random() < 0.75:
            self.captured_pmkids[bssid] = time.time()
            return True
        return False

    def pixie_ok(self, bssid: str) -> bool:
        ap = self.find(bssid)
        if ap is None or not ap.wps:
            return False
        if ap.wps_locked == "locked":
            return self.rng.random() < 0.05
        if ap.wps_pixie_vulnerable:
            return self.rng.random() < 0.85
        return self.rng.random() < 0.3

    def wep_ok(self, bssid: str) -> bool:
        ap = self.find(bssid)
        return bool(ap and ap.encryption == "WEP")

    def crack(self, bssid: str, kind: str = "handshake", wordlist: str = "") -> Dict[str, Any]:
        """Simulate an offline crack: dict hit, wordlist miss, or WPS pin."""
        ap = self.find(bssid)
        if ap is None:
            return {"cracked": False, "reason": "target vanished"}
        found = bool(ap.psk)
        if ap.psk and not self.rng.random() < 0.9:
            found = False
        return {
            "cracked": found,
            "password": ap.psk if found else "",
            "tries": self.rng.randint(50_000, 40_000_000),
            "seconds": self.rng.uniform(4, 90),
            "reason": "PSK found in wordlist" if found else
                      (f"exhausted {wordlist or 'wordlist'}" if wordlist else "candidate space exhausted"),
        }

    def find(self, bssid: str) -> Optional[DemoAP]:
        bssid = (bssid or "").lower()
        for ap in self.aps:
            if ap.bssid.lower() == bssid:
                return ap
        return None

    def add_ap(self, essid: str, channel: int = 6, encryption: str = "WPA2",
               signal: int = -50, wps: bool = False, psk: str = "password123") -> DemoAP:
        ap = DemoAP(
            bssid=_demo_mac(self.rng), essid=essid, channel=channel, encryption=encryption,
            privacy={"WPA2": "WPA2", "WPA3": "WPA3", "WEP": "WEP", "OPEN": "OPN"}.get(encryption, "WPA2"),
            cipher="CCMP", auth="PSK", signal=signal, vendor="unknown",
            wps=wps, wps_locked="unlocked" if wps else "", client_count=2, psk=psk,
        )
        self.aps.append(ap)
        return ap

    def summary(self) -> Dict[str, Any]:
        return {
            "mode": "simulation",
            "seed": self.seed,
            "aps": len(self.aps),
            "handshakes": len(self.captured_handshakes),
            "pmkids": len(self.captured_pmkids),
            "deauths": len(self.deauth_events),
        }
