# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Native 802.11 scanner — replaces airodump-ng + wash for the common case.

A single AF_PACKET socket on a monitor interface, passive-only, with per-frame
parsing of beacons and probe responses. Outputs an event stream compatible with
wifipilot's existing bus so the TUI and web UI pick up APs live. Channel hop
logic is in-process and uses nl80211 via a small netlink helper (no external
``iw`` process, no ``airodump-ng`` dependency). The parser also reports WPS
support when it sees the WPS vendor IE, replacing ``wash`` scanning for
attack target selection.

This is intentionally narrower than airodump-ng: we do not write pcap, we do
not do GPS, we do not decode WPA handshakes (that's pmkid.py's job). We DO
report BSSID/SSID/channel/rate/crypto/signal/WPS and the first seen station MAC
from data frames — exactly what wifipilot's campaign loop needs to plan.
"""
from __future__ import annotations

import os
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set

from . import ieee80211, radiotap

# --------------------------------------------------------------------------- #
# nl80211 channel hop via Generic Netlink — single function, no external lib
# --------------------------------------------------------------------------- #
_NL_MSG_HDR = "=IHHII"
NLA_HDR = "=HH"
_GENL_HDR    = "=BBH"
CTRL_CMD_GETFAMILY = 3
NL80211_GENL_NAME = b"nl80211\0"
NL80211_CMD_SET_INTERFACE = 7   # actually get_interface + set_channel
NL80211_CMD_GET_WIPHY     = 1
NL80211_CMD_SET_CHANNEL   = 32
NL80211_ATTR_WIPHY_FREQ   = 34
NL80211_ATTR_IFINDEX      = 3
NL80211_ATTR_WIPHY        = 1
NL80211_ATTR_CHANNEL_WIDTH = 60
NLM_F_REQUEST = 1
NLM_F_ACK     = 4

def _ifindex(ifname: str) -> int:
    try:
        return int(os.listdir(f"/sys/class/net/{ifname}/iflink")[0]) if False else None  # placeholder
    except Exception:
        pass
    # read /proc/net/if_inet6 or ioctl SIOCGIFINDEX via socket
    import ctypes
    import fcntl
    SIOCGIFINDEX = 0x8933
    IFNAMSIZ = 16
    class IfReq(ctypes.Structure):
        _fields_ = [("ifr_name", ctypes.c_char * IFNAMSIZ),
                    ("ifr_ifindex", ctypes.c_int)]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    req = IfReq()
    req.ifr_name = ifname.encode()[:15]
    fcntl.ioctl(sock.fileno(), SIOCGIFINDEX, req)
    sock.close()
    return req.ifr_ifindex

def _nl80211_id(s: socket.socket) -> int:
    """Resolve nl80211 generic netlink family id."""
    # Build CTRL_CMD_GETFAMILY request
    hdrlen = struct.calcsize(_NL_MSG_HDR)
    genhlen = struct.calcsize(_GENL_HDR)
    # NLA: CTRL_ATTR_FAMILY_NAME (id 2) = "nl80211"
    name_attr = struct.pack(NLA_HDR, 4 + len(NL80211_GENL_NAME), 2) + NL80211_GENL_NAME
    while len(name_attr) % 4:
        name_attr += b"\x00"
    length = hdrlen + genhlen + len(name_attr)
    msg = (struct.pack(_NL_MSG_HDR, length, 16, NLM_F_REQUEST, 1, 0)
           + struct.pack(_GENL_HDR, CTRL_CMD_GETFAMILY, 0, 0)
           + name_attr)
    s.sendto(msg, (0, 0))
    while True:
        data, _ = s.recvfrom(16384)
        if len(data) < hdrlen:
            continue
        nlen, ntype, flags, seq, pid = struct.unpack(_NL_MSG_HDR, data[:hdrlen])
        if ntype == 2:       # NLMSG_ERROR
            return -1
        if seq != 1:
            continue
        body = data[hdrlen + genhlen:]
        # parse attrs for CTRL_ATTR_FAMILY_ID (id 2) u16
        off = 0
        while off + 4 <= len(body):
            alen, atype = struct.unpack(NLA_HDR, body[off:off+4])
            if atype == 2 and alen >= 6:
                return struct.unpack("=H", body[off+4:off+6])[0]
            off += (alen + 3) & ~3
    return -1

def set_channel(ifname: str, channel: int) -> bool:
    """Set monitor interface to a channel via nl80211 (no external ``iw``)."""
    try:
        s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_GENERIC)
        s.bind((0, 0))
        fid = _nl80211_id(s)
        if fid <= 0:
            s.close()
            return False
        ifindex = _ifindex(ifname)
        # build NL80211_CMD_SET_CHANNEL: attrs IFINDEX(u32) + WIPHY_FREQ(u32) + CHANNEL_WIDTH(u32=0)
        attrs = b""
        def _nla(t: int, v: bytes) -> bytes:
            raw = struct.pack(NLA_HDR, 4 + len(v), t) + v
            while len(raw) % 4:
                raw += b"\x00"
            return raw
        attrs += _nla(NL80211_ATTR_IFINDEX, struct.pack("=I", ifindex))
        attrs += _nla(NL80211_ATTR_WIPHY_FREQ, struct.pack("=I", radiotap.channel_to_freq(channel)))
        attrs += _nla(NL80211_ATTR_CHANNEL_WIDTH, struct.pack("=I", 0))
        hdrlen = struct.calcsize(_NL_MSG_HDR)
        genhlen = struct.calcsize(_GENL_HDR)
        length = hdrlen + genhlen + len(attrs)
        msg = (struct.pack(_NL_MSG_HDR, length, fid, NLM_F_REQUEST | NLM_F_ACK, 2, 0)
               + struct.pack(_GENL_HDR, NL80211_CMD_SET_CHANNEL, 0, 0)
               + attrs)
        s.sendto(msg, (0, 0))
        # read ack
        while True:
            data, _ = s.recvfrom(16384)
            if len(data) < hdrlen:
                continue
            nlen, ntype, flags, seq, pid = struct.unpack(_NL_MSG_HDR, data[:hdrlen])
            if seq != 2:
                continue
            s.close()
            return ntype != 2 or struct.unpack("=i", data[hdrlen:hdrlen+4])[0] == 0
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Scan result + scanner
# --------------------------------------------------------------------------- #
@dataclass
class AP:
    bssid: str
    ssid: str = ""
    channel: int = 0
    crypto: List[str] = field(default_factory=list)
    signal: int = -99
    wps: bool = False
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    stations: Set[str] = field(default_factory=set)
    beacons: int = 0


class NativeScanner:
    """AF_PACKET monitor-mode scanner. Passive; calls ``on_ap`` when an AP is
    first seen or its data changes materially."""

    def __init__(self, interface: str, channels: Optional[List[int]] = None,
                 dwell: float = 0.25, on_ap: Optional[Callable[[AP], None]] = None,
                 on_sta: Optional[Callable[[str, str], None]] = None,
                 stop_event: Optional[threading.Event] = None):
        self.interface = interface
        self.channels = channels or [1, 6, 11]
        self.dwell = dwell
        self.on_ap = on_ap or (lambda ap: None)
        self.on_sta = on_sta or (lambda bssid, sta: None)
        self.stop_event = stop_event or threading.Event()
        self.aps: Dict[str, AP] = {}
        self._sock: Optional[socket.socket] = None
        self._hop_thread: Optional[threading.Thread] = None
        self._recv_thread: Optional[threading.Thread] = None
        self._current_channel = 0
        self.stats = {"packets": 0, "beacons": 0, "data": 0, "probes": 0}

    # ------------------------------------------------------------------ #
    def open(self) -> bool:
        try:
            self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                       socket.htons(0x0003))   # ETH_P_ALL
            self._sock.bind((self.interface, 0))
            self._sock.settimeout(0.2)
            return True
        except OSError:
            self._sock = None
            return False

    def close(self) -> None:
        self.stop_event.set()
        if self._sock:
            with contextlib.suppress(Exception):
                self._sock.close()
            self._sock = None

    # ------------------------------------------------------------------ #
    def start(self) -> None:
        if self._sock is None and not self.open():
            raise RuntimeError(f"cannot open {self.interface}: are you root?")
        self._hop_thread = threading.Thread(target=self._hop_loop, daemon=True)
        self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._hop_thread.start()
        self._recv_thread.start()

    def join(self, timeout: Optional[float] = None) -> None:
        if self._recv_thread:
            self._recv_thread.join(timeout)

    # ------------------------------------------------------------------ #
    def _hop_loop(self) -> None:
        idx = 0
        while not self.stop_event.is_set():
            ch = self.channels[idx % len(self.channels)]
            if ch != self._current_channel:
                if set_channel(self.interface, ch):
                    self._current_channel = ch
            idx += 1
            self.stop_event.wait(self.dwell)

    def _recv_loop(self) -> None:
        assert self._sock is not None
        buf = bytearray(4096)
        while not self.stop_event.is_set():
            try:
                n, _ = self._sock.recvfrom_into(buf)
            except socket.timeout:
                continue
            except OSError:
                break
            if n < 14:
                continue
            self.stats["packets"] += 1
            pkt = bytes(buf[:n])
            frame = radiotap.strip_radiotap(pkt)
            if not frame:
                continue
            sig = radiotap.parse_signal(pkt)
            self._handle_frame(frame, sig)

    # ------------------------------------------------------------------ #
    def _handle_frame(self, frame: bytes, signal: int) -> None:
        if len(frame) < 24:
            return
        fc = struct.unpack("<H", frame[:2])[0]
        ftype = (fc >> 2) & 3
        subtype = (fc >> 4) & 0xF
        _ = subtype
        if ftype == 0:  # management
            info = ieee80211.parse_beacon_info(frame)
            if info is None:
                return
            self.stats["beacons"] += 1
            bssid = info["bssid"]
            ap = self.aps.get(bssid)
            is_new = False
            if ap is None:
                ap = AP(bssid=bssid, ssid=info["ssid"],
                        channel=int(info["channel"]), crypto=list(info["crypto"]),
                        signal=signal)
                self.aps[bssid] = ap
                is_new = True
            # update fields
            if signal < 0:
                ap.signal = max(ap.signal, signal) if ap.signal != -99 else signal
            ap.last_seen = time.time()
            ap.beacons += 1
            if not ap.channel and info["channel"]:
                ap.channel = int(info["channel"])
            if info["ssid"] and not ap.ssid:
                ap.ssid = info["ssid"]
            # detect WPS: look for 0x00 0x37 0x2a (WPS vendor + simpleconfig type)
            # vendor IE (tag 221) with OUI 00:50:f2 type 0x04 and element wps UUID 0x1044
            # Quick and dirty: scan for b"\x00\x50\xf2\x04" in IE region.
            if not ap.wps:
                off = 24 + 12
                while off + 2 < len(frame):
                    t = frame[off]; ln = frame[off+1]; off += 2
                    if off + ln > len(frame): break
                    if t == 221 and ln >= 4 and frame[off:off+4] == b"\x00\x50\xf2\x04":
                        ap.wps = True
                        break
                    off += ln
            if is_new or (ap.ssid and signal > ap.signal - 5):
                self.on_ap(ap)
        elif ftype == 2:  # data
            self.stats["data"] += 1
            addrs = ieee80211.parse_data_frame_addresses(frame)
            if addrs is None:
                return
            a1, a2, a3, stype, fc = addrs
            # to_ds and from_ds bit layout: for AP-bridged traffic, addr3 is BSSID
            to_ds   = bool(fc & ieee80211.FC_TO_DS)
            from_ds = bool(fc & ieee80211.FC_FROM_DS)
            bssid = ""
            sta = ""
            if not to_ds and not from_ds:     # IBSS
                return
            if to_ds and not from_ds:         # STA -> AP (a1=BSSID, a2=STA, a3=DA)
                bssid = a1; sta = a2
            elif from_ds and not to_ds:       # AP -> STA (a1=STA, a2=BSSID, a3=SA)
                bssid = a2; sta = a1
            if not bssid:
                return
            ap = self.aps.get(bssid)
            if ap is None:
                return
            if sta and sta not in ap.stations:
                ap.stations.add(sta)
                self.on_sta(bssid, sta)


import contextlib
