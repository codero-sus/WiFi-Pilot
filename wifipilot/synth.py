"""Build *cryptographically valid* captures for tests, demos and self-checks.

A capture written here is not a mock-up: the PMK is derived from the real PSK
with PBKDF2, the PTK with the 802.11i PRF, and every EAPOL MIC is computed with
AES-CMAC over the actual frame.  That means

* wifipilot's own verifier accepts it,
* the built-in cracking engine can *recall* the PSK from it, proving the whole
  pipeline (PBKDF2 → PTK → MIC → comparison) is correct end to end,
* ``aircrack-ng`` reads it as a normal capture (radiotap + 802.11 + EAPOL).

Used by ``wifipilot demo`` (so simulation mode exercises the real code paths)
and by the test-suite.
"""

from __future__ import annotations

import hashlib
import os
import random
import struct
import time
from pathlib import Path
from typing import List, Optional, Tuple

from .crypto import compute_pmkid, mic_from_ptk, pmk, ptk

RADIOTAP = bytes([0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00])
PCAP_HEADER = bytes.fromhex("d4c3b2a1") + struct.pack("<HHiiii", 2, 4, 0, 0, 262144, 105)


def _mac(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def _data_header(src: bytes, dst: bytes, bssid: bytes, seq: int = 0,
                 to_ds: bool = True) -> bytes:
    """802.11 data frame header. to_ds=True => station->AP, False => AP->station."""
    fc = b"\x08\x01" if to_ds else b"\x08\x02"
    duration = b"\x00\x00"
    seq_control = struct.pack("<H", (seq & 0x0FFF) << 4)
    return fc + duration + dst + src + bssid + seq_control


def _llc_eapol(eapol: bytes) -> bytes:
    return b"\xaa\xaa\x03\x00\x00\x00\x88\x8e" + eapol


def _kmd(key_info: int, replay: int, nonce: bytes, key_data: bytes = b"",
         mic: bytes = b"") -> bytes:
    return (b"\x02"                                  # descriptor type: RSN
            + struct.pack(">H", key_info)
            + b"\x00\x10"                            # key length (16 for CCMP)
            + struct.pack(">Q", replay)
            + nonce                                  # 32 bytes
            + bytes(16)                              # key IV
            + bytes(8)                               # key RSC
            + bytes(8)                               # key ID
            + (mic or bytes(16))                     # MIC
            + struct.pack(">H", len(key_data))
            + key_data)


def _eapol(key_info: int, replay: int, nonce: bytes, key_data: bytes = b"",
           mic: bytes = b"") -> bytes:
    body = _kmd(key_info, replay, nonce, key_data, mic)
    return b"\x02\x03" + struct.pack(">H", len(body)) + body


#: KeyMIC sits at byte 77 of the EAPOL-Key body, i.e. 81 of the EAPOL frame
#: (4 byte EAPOL header + type/keyinfo/keylength/replay/nonce/iv/rsc/keyid).
MIC_OFFSET = 81


def _mic_offset(eapol_frame: bytes) -> int:
    return MIC_OFFSET


def _sign(eapol_frame: bytes, ptk_bytes: bytes) -> bytes:
    offset = _mic_offset(eapol_frame)
    zeroed = eapol_frame[:offset] + bytes(16) + eapol_frame[offset + 16:]
    return mic_from_ptk(ptk_bytes, zeroed, 2)


def build_handshake_frames(ssid: str, bssid: str, station: str, password: str,
                           seed: Optional[int] = None,
                           include_pmkid: bool = False,
                           pmkid: str = "") -> Tuple[List[bytes], str]:
    """Return (frames, pmkid) containing beacon + M1/M2 (+M3/M4) with valid MICs."""
    rng = random.Random(seed if seed is not None else int(hashlib.sha256(
        (ssid + bssid + password).encode()).hexdigest()[:8], 16))
    ap, sta = _mac(bssid), _mac(station)
    anonce = bytes(rng.getrandbits(8) for _ in range(32))
    snonce = bytes(rng.getrandbits(8) for _ in range(32))
    pmk_bytes = pmk(password, ssid)
    ptk_bytes = ptk(pmk_bytes, ap, sta, anonce, snonce)
    computed_pmkid = compute_pmkid(pmk_bytes, ap, sta) if include_pmkid else pmkid

    frames: List[bytes] = []
    # beacon
    ssid_bytes = ssid.encode()[:32]
    beacon = (b"\x80\x00\x00\x00" + b"\xff" * 6 + sta + ap + b"\x00\x00"
              + bytes(8)                                   # timestamp
              + b"\x64\x00"                                # beacon interval
              + b"\x01\x04"                                # capability: ESS+privacy
              + b"\x00" + bytes([len(ssid_bytes)]) + ssid_bytes
              + b"\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24")
    frames.append(beacon)

    pmkid_kde = (b"\xdd\x14\x00\x0f\xac\x04" + bytes.fromhex(computed_pmkid)) if computed_pmkid else b""
    # M1: ANonce, no MIC (key_info 0x008a: pairwise + ack)
    m1 = _eapol(0x008a, 1, anonce, pmkid_kde)
    frames.append(_data_header(ap, sta, ap, 1, to_ds=False) + _llc_eapol(m1))
    # M2: SNonce + MIC (0x010a)
    m2 = _eapol(0x010a, 1, snonce)
    m2 = m2[:_mic_offset(m2)] + _sign(m2, ptk_bytes) + m2[_mic_offset(m2) + 16:]
    frames.append(_data_header(sta, ap, ap, 2) + _llc_eapol(m2))
    # M3: ANonce + MIC + install + secure + GTK (0x13ca)
    gtk_kde = b"\xdd\x16\x00\x0f\xac\x01" + bytes(4) + bytes(16)
    m3 = _eapol(0x13ca, 2, anonce, gtk_kde)
    m3 = m3[:_mic_offset(m3)] + _sign(m3, ptk_bytes) + m3[_mic_offset(m3) + 16:]
    frames.append(_data_header(ap, sta, ap, 3, to_ds=False) + _llc_eapol(m3))
    # M4: MIC only (0x030a)
    m4 = _eapol(0x030a, 2, bytes(32))
    m4 = m4[:_mic_offset(m4)] + _sign(m4, ptk_bytes) + m4[_mic_offset(m4) + 16:]
    frames.append(_data_header(sta, ap, ap, 4) + _llc_eapol(m4))
    return frames, computed_pmkid


def write_pcap(path: str, frames: List[bytes], spacing: float = 0.001) -> str:
    """Write radiotap + 802.11 frames as a libpcap file."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    buffer = bytearray(PCAP_HEADER)
    base = int(time.time())
    for index, frame in enumerate(frames):
        packet = RADIOTAP + frame
        timestamp = base + int(index * spacing)
        usec = int((index * spacing % 1) * 1_000_000)
        buffer += struct.pack("<IIII", timestamp, usec, len(packet), len(packet))
        buffer += packet
    target.write_bytes(bytes(buffer))
    return str(target)


def build_capture(path: str, ssid: str, bssid: str, station: str, password: str,
                  seed: Optional[int] = None, include_pmkid: bool = True,
                  include_handshake: bool = True) -> Tuple[str, str]:
    """Write a valid capture. Returns (path, pmkid)."""
    frames: List[bytes] = []
    pmkid = ""
    if include_handshake:
        frames, pmkid = build_handshake_frames(ssid, bssid, station, password, seed,
                                               include_pmkid=include_pmkid)
    elif include_pmkid:
        pmk_bytes = pmk(password, ssid)
        pmkid = compute_pmkid(pmk_bytes, _mac(bssid), _mac(station))
        anonce = bytes(random.Random(seed or 1).getrandbits(8) for _ in range(32))
        kde = b"\xdd\x14\x00\x0f\xac\x04" + bytes.fromhex(pmkid)
        m1 = _eapol(0x008a, 1, anonce, kde)
        frames = [_data_header(_mac(bssid), _mac(station), _mac(bssid), 1, to_ds=False)
                  + _llc_eapol(m1)]
    write_pcap(path, frames)
    return path, pmkid


def random_mac(locally_administered: bool = False) -> str:
    raw = bytearray(os.urandom(6))
    raw[0] = (raw[0] | 0x02) if locally_administered else (raw[0] & ~0x02)
    return ":".join(f"{b:02x}" for b in raw)
