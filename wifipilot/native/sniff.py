# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Frame sniffer & dissector used by the PMKID/EAPOL grabber and WPS engine.

Reads from a monitor-interface AF_PACKET socket, optionally filters by BSSID
and ESSID, parses EAPOL-Key and EAP-WPS packets, and offers a tiny matching
callback. Two features matter to the higher engines:

* **Hop-on-match**: the sniffer can lock to the channel it saw a matching
  frame on, for the next N seconds, before resuming hop — essential because
  our PMKID grabber must send M1-trigger frames on the same channel the AP
  is beaconing on.
* **EAPOL/WPS reassembly**: 802.1X packets larger than the MTU can be
  fragmented at the 802.2/EAPOL/EAP layer. We don't fully defragment but we
  collect what we see and expose raw key data for the caller.
"""
from __future__ import annotations

import socket
import struct
import threading
from dataclasses import dataclass
from typing import Callable, Optional

from . import ieee80211, radiotap

# EAP over LAN over 802.2 LLC/SNAP with EAPOL ethertype handled by ieee80211.
# EAP Request/Response types we care about: 1 Identity, 2 Notification, 13 WPS
# EAP-Expanded is type 254.
EAP_WPS_TYPE = 254     # expanded Nak/Expanded; WPS actually uses type 254 with
                       # Microsoft WSC OUI. We match on the OUI.

@dataclass
class SniffedEapol:
    """One EAPOL-Key frame, parsed."""
    src: str
    dst: str
    bssid: str
    descriptor: int
    info: int
    key_len: int
    replay_counter: bytes   # 8 bytes
    nonce: bytes            # 32 bytes (ANonce/SNonce)
    key_iv: bytes           # 16 bytes
    key_rsc: int
    mic: bytes              # 16 bytes
    key_data_len: int
    key_data: bytes
    frame: bytes            # full 802.11 frame (no radiotap)

@dataclass
class SniffedEap:
    """One EAP packet (identity or WPS), payload being the EAP data."""
    src: str
    dst: str
    bssid: str
    code: int
    identifier: int
    eap_type: int
    data: bytes


class Sniffer:
    def __init__(self, interface: str, bssid: str = "",
                 channel_lock: Optional[float] = None,
                 on_eapol: Optional[Callable[[SniffedEapol], None]] = None,
                 on_eap: Optional[Callable[[SniffedEap], None]] = None,
                 on_any: Optional[Callable[[bytes, int], None]] = None,
                 stop_event: Optional[threading.Event] = None):
        self.interface = interface
        self.bssid_filter = mac_norm(bssid) if bssid else ""
        self.on_eapol = on_eapol
        self.on_eap = on_eap
        self.on_any = on_any
        self.stop_event = stop_event or threading.Event()
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self.locked_until: float = 0.0
        self.lock_channel = channel_lock or 3.0
        self.stats = {"frames": 0, "eapol": 0, "eap": 0}
        self._channel = 0

    def open(self) -> bool:
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            s.bind((self.interface, 0))
            s.settimeout(0.2)
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

    def start(self) -> None:
        if self._sock is None and not self.open():
            raise RuntimeError(f"cannot open {self.interface}")
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def join(self, timeout: Optional[float] = None) -> None:
        if self._thread:
            self._thread.join(timeout)

    def _loop(self) -> None:
        assert self._sock is not None
        buf = bytearray(8192)
        while not self.stop_event.is_set():
            try:
                n, _ = self._sock.recvfrom_into(buf)
            except socket.timeout:
                continue
            except OSError:
                break
            if n < 32:
                continue
            pkt = bytes(buf[:n])
            frame = radiotap.strip_radiotap(pkt)
            if not frame:
                continue
            self.stats["frames"] += 1
            try:
                self._handle(frame)
            except Exception:
                pass

    def _handle(self, frame: bytes) -> None:
        if self.on_any:
            self.on_any(frame, len(frame))
        # Data frames
        addrs = ieee80211.parse_data_frame_addresses(frame)
        if addrs is None:
            return
        a1, a2, a3, subtype, fc = addrs
        to_ds = bool(fc & ieee80211.FC_TO_DS)
        from_ds = bool(fc & ieee80211.FC_FROM_DS)
        if to_ds and not from_ds:
            bssid = a1; src = a2; dst = a3
        elif from_ds and not to_ds:
            bssid = a2; src = a3; dst = a1
        elif to_ds and from_ds:
            # WDS: a4 present; skip for simplicity
            return
        else:
            return
        if self.bssid_filter and mac_norm(bssid) != self.bssid_filter:
            return
        body_off = 24 + (2 if subtype & 8 else 0)
        # LLC/SNAP EAPOL detection
        if len(frame) < body_off + 8:
            return
        if frame[body_off:body_off+8] != ieee80211.LLC_SNAP_EAPOL:
            return
        eapol = frame[body_off+8:]
        if len(eapol) < 4:
            return
        ver, etype, elen = struct.unpack("!BBH", eapol[:4])
        body = eapol[4:4+elen]
        if etype == ieee80211.EAP_KEY and len(body) >= 95:
            self.stats["eapol"] += 1
            self._emit_eapol(src, dst, bssid, body, frame)
        elif etype == ieee80211.EAP_PACKET and len(body) >= 4:
            self.stats["eap"] += 1
            self._emit_eap(src, dst, bssid, body, frame)

    def _emit_eapol(self, src: str, dst: str, bssid: str, body: bytes,
                    frame: bytes) -> None:
        # body layout: descriptor(1), key_info_version(1), key_len(2),
        #              replay_counter(8), nonce(32), key_iv(16), key_rsc(8),
        #              key_id(8), key_mic(16), key_data_len(2), key_data(var)
        try:
            descriptor = body[0]
            info = struct.unpack("!H", body[1:3])[0]
            key_len = struct.unpack("!H", body[3:5])[0]
            replay = body[5:13]
            nonce = body[13:45]
            key_iv = body[45:61]
            key_rsc = struct.unpack("!Q", body[61:69])[0]
            mic = body[77:93]
            kdl = struct.unpack("!H", body[93:95])[0]
            key_data = body[95:95+kdl] if 95+kdl <= len(body) else b""
            ev = SniffedEapol(src=src, dst=dst, bssid=bssid,
                              descriptor=descriptor, info=info, key_len=key_len,
                              replay_counter=replay, nonce=nonce, key_iv=key_iv,
                              key_rsc=key_rsc, mic=mic, key_data_len=kdl,
                              key_data=key_data, frame=frame)
            if self.on_eapol:
                self.on_eapol(ev)
        except Exception:
            return

    def _emit_eap(self, src: str, dst: str, bssid: str, body: bytes,
                  frame: bytes) -> None:
        # EAP packet: code(1), id(1), length(2), type(1), data(var)
        if len(body) < 4:
            return
        code, ident, elen = struct.unpack("!BBH", body[:4])
        etype = body[4] if len(body) >= 5 else 0
        data = body[5:4+elen-1] if elen >= 5 else b""
        ev = SniffedEap(src=src, dst=dst, bssid=bssid, code=code, identifier=ident,
                        eap_type=etype, data=data)
        if self.on_eap:
            self.on_eap(ev)


import contextlib
from ..util import mac_norm as _macn  # noqa
mac_norm = _macn
