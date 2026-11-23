# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Tiny IEEE 802.11 frame builder / parser primitives for native engines.

Stripped to the fields the ULTRA native engines actually need: management frames
(beacon, probe req/resp, auth, assoc req/resp, deauth, disassoc), data frames
carrying EAPOL over LLC/SNAP, and EAP/WPS over EAPOL. This is NOT a general-
purpose dissector — it is the minimum scaffolding so that the native scanner,
PMKID grabber, WPS cracker, and evil-twin AP can all speak the air without
shelling out to aircrack-ng/hcxdumptool/reaver/bully/hostapd.
"""
from __future__ import annotations

import struct
from typing import Dict, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
# Frame types / subtypes (top 2 bits = type, next 4 = subtype, shifted by 2 in FC)
TYPE_MGMT = 0
TYPE_CTRL = 1
TYPE_DATA = 2

# Management subtypes
ST_BEACON      = 8
ST_PROBE_REQ   = 4
ST_PROBE_RESP  = 5
ST_AUTH        = 11
ST_DEAUTH      = 12
ST_ASSOC_REQ   = 0
ST_ASSOC_RESP  = 1
ST_REASSOC_REQ = 2
ST_DISASSOC    = 10
ST_ACTION      = 13

# Data subtypes (selected)
ST_DATA        = 0
ST_QOS_DATA    = 8
ST_NULL        = 4
ST_QOS_NULL    = 12

# Frame control flags (FC bits 0..7)
FC_TO_DS   = 0x0100
FC_FROM_DS = 0x0200
FC_MOREFRAGS = 0x0400
FC_RETRY    = 0x0800
FC_PWRMGT   = 0x1000
FC_MOREDATA = 0x2000
FC_PROTECTED= 0x4000
FC_ORDER    = 0x8000

# Reason codes (deauth/disassoc, we only emit a handful)
REASON_UNSPEC           = 1
REASON_PREV_AUTH_EXPIRED= 2
REASON_DEAUTH_LEAVING   = 3
REASON_INACTIVITY       = 4
REASON_CLASS2_FRAME     = 6
REASON_CLASS3_FRAME     = 7
REASON_DISASSOC_INACT   = 8

# Status codes (auth/assoc response)
STATUS_SUCCESS      = 0
STATUS_UNSPEC_FAIL  = 1

# Auth algorithm numbers
AUTH_OPEN = 0
AUTH_SHARED = 1

# EAPOL / EAP types
ETH_P_PAE  = 0x888E          # Ethertype for 802.1X EAPOL
EAP_PACKET = 0
EAP_START  = 1
EAP_LOGOFF = 2
EAP_KEY    = 3
EAP_REQ_ID = 1
EAP_RESP_ID= 2
EAP_SUCCESS= 3
EAP_FAIL   = 4
EAP_EXPAND = 254

# LLC/SNAP header for EAPOL
LLC_SNAP_EAPOL = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def mac_to_bytes(mac: str) -> bytes:
    return bytes(int(p, 16) for p in mac.replace("-", ":").split(":"))

def mac_from_bytes(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b[:6])

def mac_norm(s: str) -> str:
    return mac_from_bytes(mac_to_bytes(s))

def broadcast() -> bytes:
    return b"\xff\xff\xff\xff\xff\xff"

def build_fc(ftype: int, subtype: int, flags: int = 0, to_ds: bool = False,
             from_ds: bool = False) -> int:
    fc = (ftype << 2) | (subtype << 4)
    if to_ds:   fc |= FC_TO_DS
    if from_ds: fc |= FC_FROM_DS
    fc |= flags
    return fc

# --------------------------------------------------------------------------- #
# Generic 802.11 header builder
# --------------------------------------------------------------------------- #
def mgmt_header(fc: int, duration: int, da: bytes, sa: bytes, bssid: bytes,
                seq: int = 0) -> bytes:
    """24-byte 802.11 management header (ToDS=0/FromDS=0)."""
    seqctl = (seq & 0xFFF) << 4
    return struct.pack("<HH", fc, duration) + da + sa + bssid + struct.pack("<H", seqctl)

def data_header(fc: int, duration: int, addr1: bytes, addr2: bytes, addr3: bytes,
                seq: int = 0) -> bytes:
    seqctl = (seq & 0xFFF) << 4
    return (struct.pack("<HH", fc, duration) + addr1 + addr2 + addr3
            + struct.pack("<H", seqctl))

# --------------------------------------------------------------------------- #
# Tagged parameters (information elements) builder
# --------------------------------------------------------------------------- #
TAG_SSID     = 0
TAG_RATES    = 1
TAG_DSSET    = 3
TAG_TIM      = 5
TAG_ERP      = 42   # or 73? we use 73 (ERP info)
TAG_EXT_RATES= 50
TAG_RSN      = 48
TAG_HT_CAPS  = 45
TAG_HT_INFO  = 61
TAG_VHT_CAPS = 191
TAG_VHT_OP   = 192
TAG_COUNTRY  = 7
TAG_PWR_CNST = 32
TAG_CHANNEL_SWITCH = 37
TAG_WPS      = 221   # vendor-specific (Microsoft, 0x0050F2-04)
TAG_WPA      = 221   # same, different OUI

def tag(num: int, content: bytes) -> bytes:
    return bytes([num, len(content)]) + content

def tag_ssid(ssid: str) -> bytes:
    raw = ssid.encode("utf-8")[:32]
    return tag(TAG_SSID, raw)

def tag_ds_set(channel: int) -> bytes:
    return tag(TAG_DSSET, bytes([channel]))

_basic_rates = bytes([0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24,
                      0x30, 0x48, 0x60, 0x6c])
def tag_supported_rates() -> bytes:
    return tag(TAG_RATES, _basic_rates[:8]) + tag(TAG_EXT_RATES, _basic_rates[8:])

def tag_ds_channel(channel: int) -> bytes:
    return tag(TAG_DSSET, bytes([channel]))

def tag_country_ie() -> bytes:
    # DE/US/etc placeholder; two bytes padding + 3 sub triplets
    return tag(TAG_COUNTRY, b"DE " + b"\x20" + b"\x01\x0d\x1e\x00"
               + b"\x24\x1e\x1e\x00" + b"\x95\x05\x1e\x00")

# Minimal RSN (WPA2-PSK CCMP)
_RSN_WPA2PSK_CCMP = (
    b"\x01\x00"                    # version 1
    b"\x00\x0f\xac\x04"            # group cipher CCMP
    b"\x01\x00"                    # pairwise count 1
    b"\x00\x0f\xac\x04"            # pairwise CCMP
    b"\x01\x00"                    # AKM count 1
    b"\x00\x0f\xac\x02"            # PSK
    b"\x00\x00"                    # RSN caps
)

def tag_rsn() -> bytes:
    return tag(TAG_RSN, _RSN_WPA2PSK_CCMP)

# Minimal WPA (vendor) for mixed APs
_WPA_VENDOR_OUI = b"\x00\x50\xf2\x01\x01\x00"
_WPA_WPAPSK_TKIP = (_WPA_VENDOR_OUI
                    + b"\x00\x50\xf2\x02\x01\x00"
                    + b"\x00\x50\xf2\x02\x01\x00"
                    + b"\x00\x50\xf2\x02\x00\x00")

def tag_wpa() -> bytes:
    return tag(TAG_WPA, _WPA_WPAPSK_TKIP)

# Minimal HT Capabilities / Operation so modern STAs don't ignore us
def tag_ht_cap() -> bytes:
    caps = b"\xef\x19" + b"\x00" * 24   # ~26 bytes: 40MHz shortGI etc
    return tag(TAG_HT_CAPS, caps)

def tag_ht_op(channel: int) -> bytes:
    # byte 0 = channel, byte 1 = secondary offset 0, byte 2 = any widths off
    return tag(TAG_HT_INFO, bytes([channel, 0x00, 0x00]) + b"\x00"*22 + b"\x00"*4)

def tag_vht_cap() -> bytes:
    return tag(TAG_VHT_CAPS, b"\x00" * 12)

def tag_vht_op(channel: int) -> bytes:
    # VHT Operation: channel width=0 (20/40 MHz) to match 2.4GHz
    return tag(TAG_VHT_OP, bytes([0, channel, 0]) + b"\x00" * 6)

# --------------------------------------------------------------------------- #
# Concrete management frame builders
# --------------------------------------------------------------------------- #
def beacon(bssid: str, ssid: str, channel: int, interval: int = 100,
           seq: int = 0, ts: Optional[bytes] = None,
           capabilities: int = 0x1111) -> bytes:
    bss = mac_to_bytes(bssid)
    if ts is None:
        ts = b"\x00" * 8
    body = (ts
            + struct.pack("<HH", interval, capabilities)
            + tag_ssid(ssid)
            + tag_supported_rates()
            + tag_ds_channel(channel)
            + tag_country_ie()
            + tag_ht_cap()
            + tag_ht_op(channel)
            + tag_rsn())
    fc = build_fc(TYPE_MGMT, ST_BEACON)
    return mgmt_header(fc, 0, broadcast(), bss, bss, seq=seq) + body

def probe_response(bssid: str, dst: str, ssid: str, channel: int, seq: int = 0,
                   capabilities: int = 0x1111) -> bytes:
    bss = mac_to_bytes(bssid)
    d = mac_to_bytes(dst)
    ts = b"\x00" * 8
    body = (ts + struct.pack("<HH", 100, capabilities)
            + tag_ssid(ssid)
            + tag_supported_rates()
            + tag_ds_channel(channel)
            + tag_country_ie()
            + tag_ht_cap()
            + tag_ht_op(channel)
            + tag_rsn())
    fc = build_fc(TYPE_MGMT, ST_PROBE_RESP)
    return mgmt_header(fc, 0, d, bss, bss, seq=seq) + body

def probe_request(sta: str, ssid: str = "", seq: int = 0) -> bytes:
    s = mac_to_bytes(sta)
    body = tag_ssid(ssid) + tag_supported_rates()
    fc = build_fc(TYPE_MGMT, ST_PROBE_REQ)
    return mgmt_header(fc, 0, broadcast(), s, broadcast(), seq=seq) + body

def deauth(dst: str, src: str, bssid: str, reason: int = REASON_CLASS3_FRAME,
           seq: int = 0) -> bytes:
    d, s, b = mac_to_bytes(dst), mac_to_bytes(src), mac_to_bytes(bssid)
    fc = build_fc(TYPE_MGMT, ST_DEAUTH)
    return mgmt_header(fc, 0, d, s, b, seq=seq) + struct.pack("<H", reason)

def disassoc(dst: str, src: str, bssid: str, reason: int = REASON_DISASSOC_INACT,
             seq: int = 0) -> bytes:
    d, s, b = mac_to_bytes(dst), mac_to_bytes(src), mac_to_bytes(bssid)
    fc = build_fc(TYPE_MGMT, ST_DISASSOC)
    return mgmt_header(fc, 0, d, s, b, seq=seq) + struct.pack("<H", reason)

def auth_open_req(bssid: str, sta: str, seq: int = 0) -> bytes:
    b, s = mac_to_bytes(bssid), mac_to_bytes(sta)
    body = struct.pack("<HHH", AUTH_OPEN, 0x0001, STATUS_SUCCESS)  # algo, seq 1, status 0
    fc = build_fc(TYPE_MGMT, ST_AUTH)
    return mgmt_header(fc, 0, b, s, b, seq=seq) + body

def auth_open_resp(bssid: str, sta: str, seq: int = 0) -> bytes:
    b, s = mac_to_bytes(bssid), mac_to_bytes(sta)
    body = struct.pack("<HHH", AUTH_OPEN, 0x0002, STATUS_SUCCESS)
    fc = build_fc(TYPE_MGMT, ST_AUTH)
    return mgmt_header(fc, 0, s, b, b, seq=seq) + body

def assoc_request(bssid: str, sta: str, ssid: str, seq: int = 0) -> bytes:
    b, s = mac_to_bytes(bssid), mac_to_bytes(sta)
    # capabilities: ESS+privacy+short-slot+short-preamble etc (0x0431)
    cap = 0x0431
    body = struct.pack("<HH", cap, 0x00c8)  # listen interval 200
    body += tag_ssid(ssid)
    body += tag_supported_rates()
    # RSN IE so the AP sends a proper PMKID-bearing M1
    body += tag_rsn()
    fc = build_fc(TYPE_MGMT, ST_ASSOC_REQ)
    return mgmt_header(fc, 0, b, s, b, seq=seq) + body

def disassoc_msg(sta: str, bssid: str, reason: int = REASON_PREV_AUTH_EXPIRED,
                 seq: int = 0) -> bytes:
    return disassoc(bssid, sta, bssid, reason=reason, seq=seq)

# --------------------------------------------------------------------------- #
# Data frames carrying EAPOL over LLC/SNAP
# --------------------------------------------------------------------------- #
def eapol_frame(dst: str, src: str, bssid: str, payload: bytes, qos: bool = False,
                seq: int = 0) -> bytes:
    """802.11 data frame from AP->STA (ToDS=0, FromDS=1) carrying EAPOL."""
    d, s, b = mac_to_bytes(dst), mac_to_bytes(src), mac_to_bytes(bssid)
    subtype = ST_QOS_DATA if qos else ST_DATA
    fc = build_fc(TYPE_DATA, subtype, from_ds=True)
    hdr = data_header(fc, 0x01ca, d, s, b, seq=seq)
    qos_ctrl = b"\x00\x00" if qos else b""
    return hdr + qos_ctrl + LLC_SNAP_EAPOL + payload

def eapol_start(sta_addr: str) -> bytes:
    # EAPOL-Start has no body, length 0.
    return struct.pack("!BBH", 0x02, EAP_START, 0)

def eapol_logoff() -> bytes:
    return struct.pack("!BBH", 0x02, EAP_LOGOFF, 0)

def eapol_packet(code: int, identifier: int, eap_body: bytes) -> bytes:
    # EAPOL type EAP_PACKET wrapping EAP.
    return (struct.pack("!BBH", 0x02, EAP_PACKET, 4 + len(eap_body))
            + struct.pack("!BBH%ds" % len(eap_body),
                          code, identifier, 4 + len(eap_body), eap_body))

def eap_identity_response(ident: int, identity: bytes) -> bytes:
    return eapol_packet(EAP_RESP_ID, ident, bytes([EAP_RESP_ID]) + identity)

def eapol_key(descriptor_type: int, info: int, nonce: bytes,
              key_iv: bytes = b"\x00"*16, key_rsc: int = 0, key_id: int = 0,
              key_mic: bytes = b"\x00"*16, key_len: int = 0,
              key_data: bytes = b"") -> bytes:
    """Build a raw EAPOL-Key frame body (M1..M4 / group etc)."""
    key_data_len = len(key_data)
    length = 95 + key_data_len
    body = struct.pack("!BBH", 0x02, EAP_KEY, length - 4)  # eapol ver,type,len
    body += struct.pack("!BBH", descriptor_type, 0, key_len)
    body += struct.pack("!Q", info)
    body += nonce
    body += key_iv
    body += struct.pack("!Q", key_rsc)
    body += struct.pack("!Q", key_id)
    body += key_mic
    body += struct.pack("!H", key_data_len)
    body += key_data
    return body

# Key Info bit flags
KI_FLAGS_HMAC_MD5   = 0x0001  # desc type 1
KI_FLAGS_AES_CMAC   = 0x0002  # desc type 2
KI_FLAGS_PAIRWISE   = 0x0008
KI_FLAGS_INSTALL    = 0x0040
KI_FLAGS_ACK        = 0x0080
KI_FLAGS_MIC        = 0x0100
KI_FLAGS_SECURE     = 0x0200
KI_FLAGS_ERROR      = 0x0400
KI_FLAGS_REQUEST    = 0x0800
KI_FLAGS_ENC_DATA   = 0x1000
KI_FLAGS_SMK_MESG   = 0x2000

def eapol_m1(anonce: bytes) -> bytes:
    """AP -> STA M1 (pairwise, AES-CMAC, ACK set, no MIC, no install yet)."""
    info = KI_FLAGS_AES_CMAC | KI_FLAGS_PAIRWISE | KI_FLAGS_ACK | KI_FLAGS_REQUEST
    return eapol_key(2, info, anonce, key_len=32)

def eapol_m2(keyp: bytes, anonce: bytes, snonce: bytes, mic: bytes,
             rsn_ie: bytes) -> bytes:
    """STA -> AP M2 response (pairwise, MIC set, carries SNonce + RSN IE)."""
    info = KI_FLAGS_AES_CMAC | KI_FLAGS_PAIRWISE | KI_FLAGS_MIC
    return eapol_key(2, info, anonce, nonce=snonce, key_mic=mic,
                     key_data=rsn_ie)

def eapol_m3(anonce: bytes, snonce: bytes = b"\x00"*32,
             mic: bytes = b"\x00"*16, key_data: bytes = b"", install: bool = True) -> bytes:
    """AP -> STA M3 (pairwise, MIC, INSTALL, ACK, SECURE later if 4way done)."""
    info = (KI_FLAGS_AES_CMAC | KI_FLAGS_PAIRWISE | KI_FLAGS_MIC
            | KI_FLAGS_ACK | KI_FLAGS_INSTALL if install else 0)
    return eapol_key(2, info, anonce, nonce=snonce, key_mic=mic, key_data=key_data)

def eapol_m4(anonce: bytes, mic: bytes) -> bytes:
    """STA -> AP M4 final ack."""
    info = KI_FLAGS_AES_CMAC | KI_FLAGS_PAIRWISE | KI_FLAGS_MIC
    return eapol_key(2, info, anonce, key_mic=mic)

# --------------------------------------------------------------------------- #
# Minimal parser: extract BSSID/SSID/channel from beacons & probe responses.
# --------------------------------------------------------------------------- #
def parse_beacon_info(frame: bytes) -> Optional[Dict[str, object]]:
    """Pull BSSID, SSID, channel, capabilities from a beacon/probe-response.

    ``frame`` should be the 802.11 frame (radiotap stripped). Returns None if
    the frame is not a beacon/probe-resp or is truncated.
    """
    if len(frame) < 24:
        return None
    fc = struct.unpack("<H", frame[:2])[0]
    ftype = (fc >> 2) & 3
    subtype = (fc >> 4) & 0xF
    if ftype != TYPE_MGMT or subtype not in (ST_BEACON, ST_PROBE_RESP):
        return None
    bssid = mac_from_bytes(frame[16:22])
    body_off = 24
    # timestamp 8, beacon interval 2, capabilities 2
    if len(frame) < body_off + 12:
        return None
    cap = struct.unpack("<H", frame[body_off + 10:body_off + 12])[0]
    body_off += 12
    ssid = ""
    channel = 0
    crypto: List[str] = []
    rsn_present = False
    wpa_present = False
    p = body_off
    while p + 2 <= len(frame):
        tag_num = frame[p]
        tag_len = frame[p + 1]
        p += 2
        if p + tag_len > len(frame):
            break
        if tag_num == TAG_SSID:
            try:
                ssid = frame[p:p + tag_len].decode("utf-8", errors="replace")
            except Exception:
                ssid = ""
        elif tag_num == TAG_DSSET and tag_len >= 1:
            channel = frame[p]
        elif tag_num == TAG_RSN:
            rsn_present = True
        elif tag_num == TAG_WPA and tag_len >= 4:
            if frame[p:p+4] == b"\x00\x50\xf2\x01":
                wpa_present = True
        p += tag_len
    is_ess = bool(cap & 0x0001)
    privacy = bool(cap & 0x0010)
    if not privacy:
        crypto = ["OPEN"]
    elif rsn_present:
        crypto = ["WPA2"]
    elif wpa_present:
        crypto = ["WPA"]
    else:
        crypto = ["WEP"]
    return {"bssid": bssid, "ssid": ssid, "channel": channel,
            "capabilities": cap, "crypto": crypto,
            "privacy": privacy, "ess": is_ess}

def parse_data_frame_addresses(frame: bytes) -> Optional[Tuple[str, str, str, int, int]]:
    """Parse a data frame header and return (addr1, addr2, addr3, subtype, fc).

    Returns None for non-data or too-short frames.
    """
    if len(frame) < 24:
        return None
    fc = struct.unpack("<H", frame[:2])[0]
    ftype = (fc >> 2) & 3
    subtype = (fc >> 4) & 0xF
    if ftype != TYPE_DATA:
        return None
    a1 = mac_from_bytes(frame[4:10])
    a2 = mac_from_bytes(frame[10:16])
    a3 = mac_from_bytes(frame[16:22])
    return a1, a2, a3, subtype, fc

def extract_eapol_payload(frame: bytes) -> Optional[bytes]:
    """If frame is a data frame carrying EAPOL (LLC/SNAP 0x888e), return the
    EAPOL body (starting at version byte). Otherwise None.
    """
    info = parse_data_frame_addresses(frame)
    if info is None:
        return None
    a1, a2, a3, subtype, fc = info
    body_off = 24
    if subtype & 8:    # QoS
        body_off += 2
    if len(frame) < body_off + 8 + 8:
        return None
    llc = frame[body_off:body_off+8]
    if llc != LLC_SNAP_EAPOL:
        return None
    return frame[body_off + 8:]
