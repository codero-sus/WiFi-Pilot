"""WPA/WPA2 crypto, implemented in the standard library only.

Why re-implement this?  Because it lets wifipilot

* verify a capture is a *real* crackable handshake (not just "a file exists"),
* test candidate passwords itself — including candidates derived from the SSID,
  the BSSID and the vendor — without shelling out to aircrack-ng/hashcat,
* confirm a recovered key by recomputing the MIC / PMKID (proof, not a claim),
* crack PMKID captures on machines with no GPU and no hashcat.

Implemented from the specifications: PBKDF2 (RFC 2898, via hashlib), the WPA
key hierarchy (IEEE 802.11i / RFC 3610 KCK layout), AES-128 (FIPS-197),
AES-CMAC (RFC 4493), HMAC-SHA1 based key expansion (802.11i PRF-512) and
HMAC-MD5 (RFC 2104) for TKIP MICs.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass, field
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------- #
# AES (FIPS-197)
# --------------------------------------------------------------------------- #

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
)
_INV_SBOX = bytes([_SBOX.index(i) for i in range(256)])
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
         0x6C, 0xD8, 0xAB, 0x4D)


def _xtime(value: int) -> int:
    return ((value << 1) ^ 0x1B) & 0xFF if value & 0x80 else (value << 1) & 0xFF


def _mul(a: int, b: int) -> int:
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result


class AES:
    """AES-128/192/256 block cipher (encrypt + decrypt)."""

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24 or 32 bytes")
        self.rounds = {16: 10, 24: 12, 32: 14}[len(key)]
        self.round_keys = self._expand(key)

    def _expand(self, key: bytes) -> List[List[int]]:
        nk = len(key) // 4
        words = [list(key[4 * i: 4 * i + 4]) for i in range(nk)]
        total = 4 * (self.rounds + 1)
        for i in range(nk, total):
            temp = list(words[i - 1])
            if i % nk == 0:
                temp = temp[1:] + temp[:1]
                temp = [_SBOX[b] for b in temp]
                temp[0] ^= _RCON[i // nk - 1]
            elif nk > 6 and i % nk == 4:
                temp = [_SBOX[b] for b in temp]
            words.append([words[i - nk][j] ^ temp[j] for j in range(4)])
        return [sum(words[4 * r: 4 * r + 4], []) for r in range(self.rounds + 1)]

    def _add_round_key(self, state: List[int], round_index: int) -> None:
        key = self.round_keys[round_index]
        for i in range(16):
            state[i] ^= key[i]

    @staticmethod
    def _shift_rows(state: List[int]) -> None:
        for row in range(4):
            cells = [state[row + 4 * col] for col in range(4)]
            cells = cells[row:] + cells[:row]
            for col in range(4):
                state[row + 4 * col] = cells[col]

    @staticmethod
    def _inv_shift_rows(state: List[int]) -> None:
        for row in range(4):
            cells = [state[row + 4 * col] for col in range(4)]
            cells = cells[-row:] + cells[:-row] if row else cells
            for col in range(4):
                state[row + 4 * col] = cells[col]

    @staticmethod
    def _mix_columns(state: List[int]) -> None:
        for col in range(4):
            a = state[4 * col: 4 * col + 4]
            state[4 * col + 0] = _mul(a[0], 2) ^ _mul(a[1], 3) ^ a[2] ^ a[3]
            state[4 * col + 1] = a[0] ^ _mul(a[1], 2) ^ _mul(a[2], 3) ^ a[3]
            state[4 * col + 2] = a[0] ^ a[1] ^ _mul(a[2], 2) ^ _mul(a[3], 3)
            state[4 * col + 3] = _mul(a[0], 3) ^ a[1] ^ a[2] ^ _mul(a[3], 2)

    @staticmethod
    def _inv_mix_columns(state: List[int]) -> None:
        for col in range(4):
            a = state[4 * col: 4 * col + 4]
            state[4 * col + 0] = _mul(a[0], 14) ^ _mul(a[1], 11) ^ _mul(a[2], 13) ^ _mul(a[3], 9)
            state[4 * col + 1] = _mul(a[0], 9) ^ _mul(a[1], 14) ^ _mul(a[2], 11) ^ _mul(a[3], 13)
            state[4 * col + 2] = _mul(a[0], 13) ^ _mul(a[1], 9) ^ _mul(a[2], 14) ^ _mul(a[3], 11)
            state[4 * col + 3] = _mul(a[0], 11) ^ _mul(a[1], 13) ^ _mul(a[2], 9) ^ _mul(a[3], 14)

    def encrypt_block(self, block: bytes) -> bytes:
        state = list(block)
        self._add_round_key(state, 0)
        for round_index in range(1, self.rounds):
            state = [_SBOX[b] for b in state]
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, round_index)
        state = [_SBOX[b] for b in state]
        self._shift_rows(state)
        self._add_round_key(state, self.rounds)
        return bytes(state)

    def decrypt_block(self, block: bytes) -> bytes:
        state = list(block)
        self._add_round_key(state, self.rounds)
        for round_index in range(self.rounds - 1, 0, -1):
            self._inv_shift_rows(state)
            state = [_INV_SBOX[b] for b in state]
            self._add_round_key(state, round_index)
            self._inv_mix_columns(state)
        self._inv_shift_rows(state)
        state = [_INV_SBOX[b] for b in state]
        self._add_round_key(state, 0)
        return bytes(state)


# --------------------------------------------------------------------------- #
# AES-CMAC (RFC 4493)
# --------------------------------------------------------------------------- #

_CMAC_RB = 0x87


def _left_shift(block: bytes) -> bytes:
    value = int.from_bytes(block, "big")
    overflow = value >> 127
    value = (value << 1) & ((1 << 128) - 1)
    if overflow:
        value ^= _CMAC_RB
    return value.to_bytes(16, "big")


def aes_cmac(key: bytes, message: bytes) -> bytes:
    engine = AES(key)
    zero = bytes(16)
    l_value = engine.encrypt_block(zero)
    k1 = _left_shift(l_value)
    k2 = _left_shift(k1)
    if message and len(message) % 16 == 0:
        last = bytes(a ^ b for a, b in zip(message[-16:], k1))
        data = message[:-16]
    else:
        padded = message + b"\x80"
        padded += bytes(16 - (len(padded) % 16)) if len(padded) % 16 else b""
        last = bytes(a ^ b for a, b in zip(padded[-16:], k2))
        data = padded[:-16]
    state = zero
    for offset in range(0, len(data), 16):
        state = engine.encrypt_block(bytes(a ^ b for a, b in zip(state, data[offset:offset + 16])))
    return engine.encrypt_block(bytes(a ^ b for a, b in zip(state, last)))


# --------------------------------------------------------------------------- #
# WPA key hierarchy
# --------------------------------------------------------------------------- #

PMKID_LABEL = b"PMK Name"
WPA_PMK_BITS = 4096
PTK_BITS = 512


def pmk(passphrase: str, ssid: str) -> bytes:
    """PSK = PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 32) — the WPA PMK.

    WPA passphrases are 8-63 printable characters; anything else cannot be a
    valid PSK, so we reject it instead of producing a meaningless hash.
    """
    if not isinstance(passphrase, str) or not 8 <= len(passphrase) <= 63:
        raise ValueError("WPA passphrase must be 8-63 characters")
    if not isinstance(ssid, str) or not 1 <= len(ssid.encode("utf-8")) <= 32:
        raise ValueError("SSID must be 1-32 bytes")
    return hashlib.pbkdf2_hmac("sha1", passphrase.encode("utf-8"),
                               ssid.encode("utf-8"), WPA_PMK_BITS, 32)


def prf512(key: bytes, label: bytes, data: bytes) -> bytes:
    """802.11i PRF (HMAC-SHA1 based) producing 512 bits of PTK."""
    out, counter = b"", 0
    while len(out) < PTK_BITS // 8:
        out += hmac.new(key, label + b"\x00" + data + bytes([counter]), hashlib.sha1).digest()
        counter += 1
    return out[: PTK_BITS // 8]


def ptk(pmk_bytes: bytes, ap: bytes, station: bytes, anonce: bytes, snonce: bytes) -> bytes:
    data = (min(ap, station) + max(ap, station)
            + min(anonce, snonce) + max(anonce, snonce))
    return prf512(pmk_bytes, b"Pairwise key expansion", data)


def compute_pmkid(pmk_bytes: bytes, ap: bytes, station: bytes) -> str:
    return hmac.new(pmk_bytes, PMKID_LABEL + ap + station, hashlib.sha1).digest()[:16].hex()


def mic_from_ptk(ptk_bytes: bytes, eapol_frame: bytes, key_descriptor: int) -> bytes:
    """MIC of an EAPOL-Key frame: AES-CMAC (CCMP/AES) or HMAC-MD5 (TKIP)."""
    kck = ptk_bytes[:16]
    if key_descriptor == 2:                       # RSN / AES
        return aes_cmac(kck, eapol_frame)[:16]
    return hmac.new(kck, eapol_frame, hashlib.md5).digest()[:16]   # WPA / TKIP


# --------------------------------------------------------------------------- #
# capture verification
# --------------------------------------------------------------------------- #


@dataclass
class VerifyResult:
    ok: bool = False
    reason: str = ""
    method: str = ""
    candidates_tried: int = 0
    seconds: float = 0.0


def _eapol_frame_from_bytes(frame: bytes) -> bytes:
    """Extract the raw EAPOL frame from an 802.11 data frame.

    Layout: LLC/SNAP (aa aa 03 00 00 00) | ethertype 0x888e | EAPOL ...
    The returned buffer starts at the EAPOL header because the MIC offset is
    defined relative to it.
    """
    index = frame.find(b"\xaa\xaa\x03\x00\x00\x00")
    return frame[index + 8:] if index >= 0 else b""   # skip LLC/SNAP + ethertype


def _zero_mic(eapol: bytes, mic_offset: int = 81) -> bytes:
    if len(eapol) < mic_offset + 16:
        return eapol
    return eapol[:mic_offset] + bytes(16) + eapol[mic_offset + 16:]


def verify_pmkid(pmkid_hex: str, ssid: str, ap_mac: str, station_mac: str,
                 password: str) -> bool:
    """Does ``password`` produce this PMKID?"""
    try:
        key = pmk(password, ssid)
    except (ValueError, UnicodeEncodeError):
        return False
    ap = bytes(int(x, 16) for x in ap_mac.split(":"))
    station = bytes(int(x, 16) for x in station_mac.split(":"))
    return compute_pmkid(key, ap, station) == pmkid_hex.lower()


def verify_handshake(frames: Dict[int, bytes], ssid: str, ap_mac: str,
                     station_mac: str, anonce: bytes, snonce: bytes,
                     password: str, key_descriptor: int = 2) -> bool:
    """Recompute the MIC of message 2/4 and compare it with what is on air."""
    try:
        pmk_bytes = pmk(password, ssid)
    except (ValueError, UnicodeEncodeError):
        return False
    ptk_bytes = ptk(pmk_bytes, bytes.fromhex(ap_mac.replace(":", "")),
                    bytes.fromhex(station_mac.replace(":", "")), anonce, snonce)
    for number in (2, 4):
        frame = frames.get(number)
        if not frame:
            continue
        eapol = _eapol_frame_from_bytes(frame)
        if len(eapol) < 97:
            continue
        mic = eapol[81:97]
        expected = mic_from_ptk(ptk_bytes, _zero_mic(eapol), key_descriptor)
        if hmac.compare_digest(mic, expected):
            return True
    return False
