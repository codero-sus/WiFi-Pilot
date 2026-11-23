# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Active probe-request sweeper — replaces `wash`, `airodump-ng --band ag`
for the "where is everything on every channel" use case.

Given a monitor interface and a channel list, this script:

1. Hops channels at a configured dwell time.
2. On every channel transmits a burst of directed probe requests from a
   random locally-administered STA MAC, for a list of common SSIDs plus
   a wildcard probe. Directed probes force many APs to respond with probe
   responses that the passive beacon scan might miss (hidden SSIDs, APs
   that don't beacon fast, 5 GHz APs with short dwell times).
3. Collects probe responses (and beacons) from the same sniffer used by
   ``scanner.py``, deduplicating by BSSID, and returns a list of dicts
   with BSSID, SSID, channel, crypto, signal.

This script is what ``wifipilot ultra scan`` calls: it finishes a full
2.4 GHz sweep in ~1 s (three channels × 250 ms dwell + probe burst), or
~3 s on the full 2.4+5 GHz list. That is fast enough to run inside the
first second of every campaign before any attack decisions are made.
"""
from __future__ import annotations

import random
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from . import ieee80211, radiotap, scanner

# Common SSIDs APs actually reply to (hidden SSIDs often have a remembered
# name a client will probe for; we broadcast wildcard + a small popular set).
COMMON_PROBE_SSIDS: List[str] = [
    "",    # wildcard
    "linksys", "NETGEAR", "NETGEAR-5G", "dlink", "dlink-5G",
    "xfinitywifi", "XFINITY", "ATTWiFi", "CenturyLink",
    "Home", "home", "WiFi", "MySpectrumWiFia", "MySpectrumWiFi",
    "TP-Link", "TP-LINK", "ASUS", "Huawei", "Sunrise",
    "UPC", "Ziggo", "Virgin Media", "SKY", "BTHub",
    "AndroidAP", "iPhone", "DIRECT",
]

# Channels: 2.4 GHz (1-13) and the common 5 GHz UNII-1/2/3 bands (36-165 step 4)
CHANNELS_2GHZ = list(range(1, 14))
CHANNELS_5GHZ = list(range(36, 68, 4)) + list(range(100, 148, 4)) + list(range(149, 166, 4))


@dataclass
class ProbeAP:
    bssid: str
    ssid: str = ""
    channel: int = 0
    crypto: List[str] = field(default_factory=list)
    signal: int = -99
    wps: bool = False
    beacons: int = 0
    responses: int = 0
    last_seen: float = field(default_factory=time.time)
    hidden: bool = False


class ProbeSweep:
    def __init__(self, interface: str, channels: Optional[List[int]] = None,
                 dwell: float = 0.20, ssids: Optional[List[str]] = None,
                 stop_event: Optional[threading.Event] = None,
                 on_ap: Optional[Callable[[ProbeAP], None]] = None):
        self.interface = interface
        self.channels = channels or CHANNELS_2GHZ
        self.dwell = dwell
        self.ssids = ssids if ssids is not None else COMMON_PROBE_SSIDS
        self.stop_event = stop_event or threading.Event()
        self.on_ap = on_ap or (lambda a: None)
        self.aps: Dict[str, ProbeAP] = {}
        self._sock: Optional[socket.socket] = None
        self._sock_recv: Optional[socket.socket] = None
        self.stats = {"packets": 0, "responses": 0, "probes": 0}
        self._sta = bytes([0x02, 0x00, 0x00]
                          + [random.randint(0, 255) for _ in range(3)])
        self._seq = 1

    def open(self) -> bool:
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            s.bind((self.interface, 0))
            s.settimeout(0.05)
            self._sock = s
            return True
        except OSError:
            return False

    def close(self) -> None:
        self.stop_event.set()
        if self._sock:
            with contextlib.suppress(Exception): self._sock.close()
            self._sock = None

    def _send_probes(self, channel: int) -> None:
        if not self._sock: return
        sta_s = ieee80211.mac_from_bytes(self._sta)
        # Rotate source MAC every full sweep to avoid caching
        for ssid in self.ssids:
            pr = ieee80211.probe_request(sta_s, ssid=ssid, seq=self._seq & 0xFFF)
            self._seq += 1
            try:
                self._sock.send(radiotap.with_header(pr, rate_mbps=1.0, channel=channel))
                self.stats["probes"] += 1
            except OSError:
                break
            # tiny inter-frame gap so the card queues them but doesn't drop
            time.sleep(0.002)

    def _recv_until(self, deadline: float, channel: int) -> None:
        if not self._sock: return
        buf = bytearray(4096)
        while time.time() < deadline and not self.stop_event.is_set():
            try:
                n, _ = self._sock.recvfrom_into(buf)
            except socket.timeout:
                continue
            except OSError:
                break
            if n < 30: continue
            pkt = bytes(buf[:n])
            frame = radiotap.strip_radiotap(pkt)
            if len(frame) < 24: continue
            sig = radiotap.parse_signal(pkt)
            self._handle(frame, sig, channel)
            self.stats["packets"] += 1

    def _handle(self, frame: bytes, sig: int, channel: int) -> None:
        info = ieee80211.parse_beacon_info(frame)
        if info is None: return
        fc = struct.unpack("<H", frame[:2])[0]
        subtype = (fc >> 4) & 0xF
        bssid = info["bssid"]
        ap = self.aps.get(bssid)
        is_resp = (subtype == ieee80211.ST_PROBE_RESP)
        is_new = False
        if ap is None:
            ap = ProbeAP(bssid=bssid, ssid=info["ssid"], channel=int(info["channel"]) or channel,
                         crypto=list(info["crypto"]), signal=sig)
            self.aps[bssid] = ap
            is_new = True
        ap.last_seen = time.time()
        if sig < 0:
            ap.signal = max(ap.signal, sig) if ap.signal != -99 else sig
        if is_resp:
            ap.responses += 1
        else:
            ap.beacons += 1
        if info["ssid"] and not ap.ssid:
            ap.ssid = info["ssid"]
        if not ap.channel and info["channel"]:
            ap.channel = int(info["channel"])
        if not ap.ssid:
            ap.hidden = True
        # WPS detect
        if not ap.wps:
            off = 24 + 12
            while off + 2 < len(frame):
                t = frame[off]; ln = frame[off+1]; off += 2
                if off+ln > len(frame): break
                if t == 221 and ln >= 4 and frame[off:off+4] == b"\x00\x50\xf2\x04":
                    ap.wps = True; break
                off += ln
        if is_new:
            self.on_ap(ap)

    def run(self, rounds: int = 1) -> Dict[str, ProbeAP]:
        for r in range(rounds):
            if self.stop_event.is_set(): break
            for ch in self.channels:
                if self.stop_event.is_set(): break
                if not scanner.set_channel(self.interface, ch):
                    continue
                # small settle time
                time.sleep(0.02)
                self._send_probes(ch)
                self._recv_until(time.time() + self.dwell, ch)
        return self.aps


def quick_scan(interface: str, band: str = "2g", dwell: float = 0.20,
               rounds: int = 1) -> List[ProbeAP]:
    """One-shot convenience: probe-sweep and return sorted-by-signal APs."""
    chans = CHANNELS_2GHZ if band == "2g" else (CHANNELS_2GHZ + CHANNELS_5GHZ if band == "both" else CHANNELS_5GHZ)
    stop = threading.Event()
    sweep = ProbeSweep(interface, channels=chans, dwell=dwell, stop_event=stop)
    if not sweep.open():
        return []
    try:
        aps = sweep.run(rounds=rounds)
    finally:
        sweep.close()
    return sorted(aps.values(), key=lambda a: a.signal, reverse=True)


import contextlib
