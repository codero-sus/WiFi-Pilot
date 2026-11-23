# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Minimal radiotap builder/parser for native inject/capture.

The native engines want to inject frames with the correct TX flags (no FCS,
2GHz OFDM rate, channel frequency) so drivers accept them; and when capturing
they need to know where the 802.11 frame starts in each received buffer.
This module implements a tiny subset of radiotap:
- parser: read present-bitmask, compute header length, find the IEEE80211 header
- builder: construct an injection header with channel + rate + no-FCS flags

We deliberately ignore antenna signal decoding (the scanner just counts); and
we do not try MCS/HT flags because the vast majority of WiFi chips accept the
legacy 802.11b/g rate 1/2/5.5/11/6/9/12/24 Mbps headers for management and
EAPOL frames on 2.4 GHz. For 5 GHz the caller falls back to 6 Mbps OFDM.
"""
from __future__ import annotations
import struct
from typing import Tuple

# Present bits we care about
_PRESENT_TSFT    = 1 << 0
_PRESENT_FLAGS   = 1 << 1
_PRESENT_RATE    = 1 << 2
_PRESENT_CHAN    = 1 << 3
_PRESENT_FHSS    = 1 << 4
_PRESENT_DBM_ANT = 1 << 5
_PRESENT_EXT     = 1 << 31

# Channel field flags (flags word in radiotap channel tuple)
_CHAN_FLAG_OFDM = 0x0040   # 0x0040 = OFDM (5 GHz or 2.4 GHz g rates)
_CHAN_FLAG_2GHZ = 0x0004
_CHAN_FLAG_5GHZ = 0x0010
_CHAN_FLAG_CCK  = 0x0020   # 2.4 GHz b rates

# Injection flags byte flags
_FLAG_F_FCS = 0x10   # frame includes FCS at end (we never inject one)


def header_length(pkt: bytes) -> int:
    """Return the radiotap header length of a received radiotap packet."""
    if len(pkt) < 8 or pkt[:2] != b"\x00\x00":
        return 0
    it_len = struct.unpack("<H", pkt[2:4])[0]
    present = struct.unpack("<I", pkt[4:8])[0]
    # Extended present bitmaps chained if bit 31 set. Each ext is another u32
    off = 8
    p = present
    while p & _PRESENT_EXT:
        if off + 4 > it_len:
            break
        p = struct.unpack("<I", pkt[off:off+4])[0]
        off += 4
    return it_len


def strip_radiotap(pkt: bytes) -> bytes:
    """Return the 802.11 frame (802.11 header+body, no FCS strip attempt)."""
    hl = header_length(pkt)
    if hl == 0:
        return pkt
    return pkt[hl:]


def channel_to_freq(ch: int) -> int:
    if 1 <= ch <= 13:
        return 2407 + 5 * ch
    if ch == 14:
        return 2484
    if ch >= 36:
        return 5000 + 5 * ch
    return 2412   # fallback ch 1


def build_injection_header(rate_mbps: float = 1.0, channel: int = 1,
                           short_preamble: bool = False) -> bytes:
    """Construct a radiotap injection header suitable for monitor mode.

    We emit TSFT=0 (8), FLAGS=0 (no FCS), RATE, CHANNEL. The kernel/driver
    usually ignores the rate on chips that auto-select; specifying a 1 Mbps
    legacy CCK rate maximises compatibility for management / EAPOL frames on
    2.4 GHz.
    """
    freq = channel_to_freq(channel)
    if 1 <= channel <= 14:
        chan_flags = _CHAN_FLAG_2GHZ
        if rate_mbps >= 6.0:
            chan_flags |= _CHAN_FLAG_OFDM
        else:
            chan_flags |= _CHAN_FLAG_CCK
    else:
        chan_flags = _CHAN_FLAG_5GHZ | _CHAN_FLAG_OFDM
    # Fields present: TSFT | FLAGS | RATE | CHANNEL = 0b1111 = 0x000f
    present = _PRESENT_TSFT | _PRESENT_FLAGS | _PRESENT_RATE | _PRESENT_CHAN
    it_present = present
    header_len = 8 + 8 + 1 + 1 + 4   # align
    # layout: ver/pad/len/present, tsft(8), flags(1), pad(1), rate(1), pad(1), chan(4)
    # total must be 8-byte aligned
    while header_len % 8:
        header_len += 1
    buf = bytearray(header_len)
    struct.pack_into("<HHI", buf, 0, 0, header_len, it_present)
    # TSFT=0 already zeroed
    # flags = 0 (no FCS appended)
    # rate is in units of 500 kbps
    rate_field = int(round(rate_mbps * 2)) & 0xFF
    buf[16] = 0    # flags
    buf[17] = 0    # padding
    buf[18] = rate_field
    buf[19] = 0    # padding
    struct.pack_into("<HH", buf, 20, freq, chan_flags)
    return bytes(buf)


def with_header(frame_80211: bytes, *, rate_mbps: float = 1.0, channel: int = 1) -> bytes:
    """Prepend a radiotap injection header to an 802.11 frame."""
    return build_injection_header(rate_mbps=rate_mbps, channel=channel) + frame_80211


def parse_signal(pkt: bytes) -> int:
    """Parse antenna signal in dBm from a received radiotap packet (or 0)."""
    hl = header_length(pkt)
    if hl < 8:
        return 0
    present = struct.unpack("<I", pkt[4:8])[0]
    off = 8
    def _walk(pres: int, o: int) -> Tuple[int, int]:
        if pres & _PRESENT_EXT:
            if o + 4 <= hl:
                nextp = struct.unpack("<I", pkt[o:o+4])[0]
                o += 4
                return _walk(nextp, o)
        return pres, o
    pres, off = _walk(present, off)
    # Skip fields we don't care about but which precede DBM_ANT when present.
    # TSFT(8), FLAGS(1), RATE(1), CHANNEL(4), FHSS(2)
    def skip(bits_needed: Tuple[int, ...], sizes: Tuple[int, ...]) -> int:
        nonlocal pres
        o = off
        for bit, sz in zip(bits_needed, sizes):
            if pres & bit:
                # align by natural width
                if sz in (2, 4, 8):
                    while o % sz:
                        o += 1
                # for 1-byte fields we align to 1 (no action)
                o += sz
        return o
    o = skip((_PRESENT_TSFT, _PRESENT_FLAGS, _PRESENT_RATE, _PRESENT_CHAN, _PRESENT_FHSS),
             (8, 1, 1, 4, 2))
    if pres & _PRESENT_DBM_ANT and o + 1 <= hl:
        return struct.unpack("b", pkt[o:o+1])[0]
    return 0
