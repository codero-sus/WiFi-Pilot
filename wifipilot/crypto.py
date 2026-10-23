# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
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
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

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


#: filled in by _build_tables() below (see that function for the layout)
_TE0: Tuple[int, ...] = ()
_TE1: Tuple[int, ...] = ()
_TE2: Tuple[int, ...] = ()
_TE3: Tuple[int, ...] = ()
_TD0: Tuple[int, ...] = ()
_TD1: Tuple[int, ...] = ()
_TD2: Tuple[int, ...] = ()
_TD3: Tuple[int, ...] = ()


def _build_tables() -> None:
    """Build the T-tables used by the fast AES round function.

    Classic Rijndael trick: fold SubBytes + ShiftRows + MixColumns into four
    256-entry lookup tables per direction.  In pure Python this is the difference
    between ~1.5 ms and ~0.03 ms per block, i.e. the difference between a
    handshake candidate costing 6 ms and 3 ms to test.
    """
    global _TE0, _TE1, _TE2, _TE3, _TD0, _TD1, _TD2, _TD3
    te0, te1, te2, te3 = [0] * 256, [0] * 256, [0] * 256, [0] * 256
    td0, td1, td2, td3 = [0] * 256, [0] * 256, [0] * 256, [0] * 256
    for index in range(256):
        s_box = _SBOX[index]
        mul2 = _xtime(s_box)
        mul3 = mul2 ^ s_box
        te0[index] = (mul2 << 24) | (s_box << 16) | (s_box << 8) | mul3
        te1[index] = (mul3 << 24) | (mul2 << 16) | (s_box << 8) | s_box
        te2[index] = (s_box << 24) | (mul3 << 16) | (mul2 << 8) | s_box
        te3[index] = (s_box << 24) | (s_box << 16) | (mul3 << 8) | mul2

        inv = _INV_SBOX[index]
        m9 = _mul(inv, 9)
        m11 = _mul(inv, 11)
        m13 = _mul(inv, 13)
        m14 = _mul(inv, 14)
        td0[index] = (m14 << 24) | (m9 << 16) | (m13 << 8) | m11
        td1[index] = (m11 << 24) | (m14 << 16) | (m9 << 8) | m13
        td2[index] = (m13 << 24) | (m11 << 16) | (m14 << 8) | m9
        td3[index] = (m9 << 24) | (m13 << 16) | (m11 << 8) | m14
    _TE0, _TE1, _TE2, _TE3 = tuple(te0), tuple(te1), tuple(te2), tuple(te3)
    _TD0, _TD1, _TD2, _TD3 = tuple(td0), tuple(td1), tuple(td2), tuple(td3)



_build_tables()


_KEY_CACHE: Dict[bytes, tuple] = {}


class AES:
    """AES-128/192/256 block cipher (encrypt + decrypt).

    The public API is deliberately tiny (``encrypt_block``/``decrypt_block``) and
    the result is bit-identical to FIPS-197; ``encrypt_block_reference`` keeps the
    straightforward implementation around so the fast path can be cross-checked.
    """

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24 or 32 bytes")
        self._decrypt_words = None
        # Key expansion costs ~4 block encryptions and its output is never
        # mutated, so share it between instances: BLE's ah() encrypts ONE
        # block per AES() and used to pay full expansion for it every time.
        cached = _KEY_CACHE.get(key)
        if cached is not None:
            self.rounds, self.round_keys, self.words = cached
            return
        self.rounds = {16: 10, 24: 12, 32: 14}[len(key)]
        self.round_keys = self._expand(key)
        # 32-bit words: one per column, four columns per round
        self.words = [tuple(int.from_bytes(row[4 * column:4 * column + 4], "big")
                            for column in range(4))
                      for row in self.round_keys]
        if len(_KEY_CACHE) >= 128:
            _KEY_CACHE.clear()
        _KEY_CACHE[key] = (self.rounds, self.round_keys, self.words)
        # the decryption schedule (equivalent inverse cipher) costs 16 field
        # multiplications per round key, so build it on first use: MIC checks
        # only ever encrypt
        self._decrypt_words: Optional[List[Tuple[int, int, int, int]]] = None

    @property
    def decrypt_words(self) -> List[Tuple[int, int, int, int]]:
        if self._decrypt_words is None:
            # reversed schedule, InvMixColumns on the intermediate round keys
            # only (the first and last stay as they are)
            self._decrypt_words = (
                [self.words[self.rounds]]
                + [self._inverse_words(self.words[self.rounds - rnd])
                   for rnd in range(1, self.rounds)]
                + [self.words[0]]
            )
        return self._decrypt_words

    # -- key schedule ------------------------------------------------------- #
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

    @staticmethod
    def _inverse_words(columns: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
        """A round key with InvMixColumns applied (for the inverse cipher)."""
        out = []
        for word in columns:
            a0, a1, a2, a3 = (word >> 24) & 0xFF, (word >> 16) & 0xFF, (word >> 8) & 0xFF, word & 0xFF
            out.append(((_mul(a0, 14) ^ _mul(a1, 11) ^ _mul(a2, 13) ^ _mul(a3, 9)) << 24)
                       | ((_mul(a0, 9) ^ _mul(a1, 14) ^ _mul(a2, 11) ^ _mul(a3, 13)) << 16)
                       | ((_mul(a0, 13) ^ _mul(a1, 9) ^ _mul(a2, 14) ^ _mul(a3, 11)) << 8)
                       | (_mul(a0, 11) ^ _mul(a1, 13) ^ _mul(a2, 9) ^ _mul(a3, 14)))
        return tuple(out)

    # -- block cipher (T-table) --------------------------------------------- #
    def encrypt_block(self, block: bytes) -> bytes:
        te0, te1, te2, te3 = _TE0, _TE1, _TE2, _TE3
        s_box = _SBOX
        keys = self.words
        s0 = int.from_bytes(block[0:4], "big") ^ keys[0][0]
        s1 = int.from_bytes(block[4:8], "big") ^ keys[0][1]
        s2 = int.from_bytes(block[8:12], "big") ^ keys[0][2]
        s3 = int.from_bytes(block[12:16], "big") ^ keys[0][3]
        for rnd in range(1, self.rounds):
            k = keys[rnd]
            t0 = te0[s0 >> 24] ^ te1[(s1 >> 16) & 0xFF] ^ te2[(s2 >> 8) & 0xFF] ^ te3[s3 & 0xFF] ^ k[0]
            t1 = te0[s1 >> 24] ^ te1[(s2 >> 16) & 0xFF] ^ te2[(s3 >> 8) & 0xFF] ^ te3[s0 & 0xFF] ^ k[1]
            t2 = te0[s2 >> 24] ^ te1[(s3 >> 16) & 0xFF] ^ te2[(s0 >> 8) & 0xFF] ^ te3[s1 & 0xFF] ^ k[2]
            t3 = te0[s3 >> 24] ^ te1[(s0 >> 16) & 0xFF] ^ te2[(s1 >> 8) & 0xFF] ^ te3[s2 & 0xFF] ^ k[3]
            s0, s1, s2, s3 = t0, t1, t2, t3
        k = keys[self.rounds]
        state = (
            (s_box[s0 >> 24] << 24) | (s_box[(s1 >> 16) & 0xFF] << 16)
            | (s_box[(s2 >> 8) & 0xFF] << 8) | s_box[s3 & 0xFF],
            (s_box[s1 >> 24] << 24) | (s_box[(s2 >> 16) & 0xFF] << 16)
            | (s_box[(s3 >> 8) & 0xFF] << 8) | s_box[s0 & 0xFF],
            (s_box[s2 >> 24] << 24) | (s_box[(s3 >> 16) & 0xFF] << 16)
            | (s_box[(s0 >> 8) & 0xFF] << 8) | s_box[s1 & 0xFF],
            (s_box[s3 >> 24] << 24) | (s_box[(s0 >> 16) & 0xFF] << 16)
            | (s_box[(s1 >> 8) & 0xFF] << 8) | s_box[s2 & 0xFF],
        )
        return b"".join(((word ^ k[index]).to_bytes(4, "big")
                         for index, word in enumerate(state)))

    def decrypt_block(self, block: bytes) -> bytes:
        td0, td1, td2, td3 = _TD0, _TD1, _TD2, _TD3
        inverse = _INV_SBOX
        keys = self.decrypt_words
        s0 = int.from_bytes(block[0:4], "big") ^ keys[0][0]
        s1 = int.from_bytes(block[4:8], "big") ^ keys[0][1]
        s2 = int.from_bytes(block[8:12], "big") ^ keys[0][2]
        s3 = int.from_bytes(block[12:16], "big") ^ keys[0][3]
        for rnd in range(1, self.rounds):
            k = keys[rnd]
            t0 = td0[s0 >> 24] ^ td1[(s3 >> 16) & 0xFF] ^ td2[(s2 >> 8) & 0xFF] ^ td3[s1 & 0xFF] ^ k[0]
            t1 = td0[s1 >> 24] ^ td1[(s0 >> 16) & 0xFF] ^ td2[(s3 >> 8) & 0xFF] ^ td3[s2 & 0xFF] ^ k[1]
            t2 = td0[s2 >> 24] ^ td1[(s1 >> 16) & 0xFF] ^ td2[(s0 >> 8) & 0xFF] ^ td3[s3 & 0xFF] ^ k[2]
            t3 = td0[s3 >> 24] ^ td1[(s2 >> 16) & 0xFF] ^ td2[(s1 >> 8) & 0xFF] ^ td3[s0 & 0xFF] ^ k[3]
            s0, s1, s2, s3 = t0, t1, t2, t3
        k = keys[self.rounds]
        state = (
            (inverse[s0 >> 24] << 24) | (inverse[(s3 >> 16) & 0xFF] << 16)
            | (inverse[(s2 >> 8) & 0xFF] << 8) | inverse[s1 & 0xFF],
            (inverse[s1 >> 24] << 24) | (inverse[(s0 >> 16) & 0xFF] << 16)
            | (inverse[(s3 >> 8) & 0xFF] << 8) | inverse[s2 & 0xFF],
            (inverse[s2 >> 24] << 24) | (inverse[(s1 >> 16) & 0xFF] << 16)
            | (inverse[(s0 >> 8) & 0xFF] << 8) | inverse[s3 & 0xFF],
            (inverse[s3 >> 24] << 24) | (inverse[(s2 >> 16) & 0xFF] << 16)
            | (inverse[(s1 >> 8) & 0xFF] << 8) | inverse[s0 & 0xFF],
        )
        return b"".join(((word ^ k[index]).to_bytes(4, "big")
                         for index, word in enumerate(state)))

    # -- readable reference (verified against FIPS-197 in the tests) -------- #
    def encrypt_block_reference(self, block: bytes) -> bytes:
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

    def decrypt_block_reference(self, block: bytes) -> bytes:
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

    # -- reference helpers -------------------------------------------------- #
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


class _Cmac:
    """AES-CMAC for one key, reusable across messages.

    The subkeys depend only on the key, so a cracking loop that tests many
    candidates against the same frame builds this once per candidate instead of
    once per message.
    """

    __slots__ = ("engine", "k1", "k2")

    def __init__(self, key: bytes):
        engine = AES(key)
        l_value = engine.encrypt_block(bytes(16))
        self.engine = engine
        self.k1 = _left_shift(l_value)
        self.k2 = _left_shift(self.k1)

    def digest(self, message: bytes) -> bytes:
        k1, k2, engine = self.k1, self.k2, self.engine
        if message and len(message) % 16 == 0:
            last = bytes(a ^ b for a, b in zip(message[-16:], k1))
            data = message[:-16]
        else:
            padded = message + b"\x80"
            padded += bytes(16 - (len(padded) % 16)) if len(padded) % 16 else b""
            last = bytes(a ^ b for a, b in zip(padded[-16:], k2))
            data = padded[:-16]
        state = bytes(16)
        for offset in range(0, len(data), 16):
            state = engine.encrypt_block(bytes(a ^ b for a, b in zip(state, data[offset:offset + 16])))
        return engine.encrypt_block(bytes(a ^ b for a, b in zip(state, last)))


def aes_cmac(key: bytes, message: bytes) -> bytes:
    return _Cmac(key).digest(message)


def _aes_cmac_readable(key: bytes, message: bytes) -> bytes:
    """The same function without the hoisting, kept for tests and reading."""
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


def ssid_bytes(ssid) -> bytes:
    """The SSID as the bytes WPA salts with.

    Callers that read an SSID from a *capture* have raw bytes; callers that got
    a name from a user have text.  Both must produce the same PBKDF2 salt, so
    bytes pass through untouched and text is UTF-8 encoded (which is what
    ``str.encode`` did before this existed).
    """
    if isinstance(ssid, (bytes, bytearray, memoryview)):
        return bytes(ssid)
    if isinstance(ssid, str):
        return ssid.encode("utf-8")
    return b""


def pmk(passphrase: str, ssid) -> bytes:
    """PSK = PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 32) — the WPA PMK.

    WPA passphrases are 8-63 printable characters; anything else cannot be a
    valid PSK, so we reject it instead of producing a meaningless hash.  ``ssid``
    may be text or the raw bytes from a capture (or a hash file).
    """
    if not isinstance(passphrase, str) or not 8 <= len(passphrase) <= 63:
        raise ValueError("WPA passphrase must be 8-63 characters")
    salt = ssid_bytes(ssid)
    if not 1 <= len(salt) <= 32:
        raise ValueError("SSID must be 1-32 bytes")
    return hashlib.pbkdf2_hmac("sha1", passphrase.encode("utf-8"), salt, WPA_PMK_BITS, 32)


def _hmac_sha1_templates(key: bytes):
    """Pre-keyed inner/outer SHA1 states for repeated HMAC with one key.

    ``hmac.new`` re-derives both pads (and copies the key block) on every
    call; the PRF asks five times with the same key, per candidate.
    """
    if len(key) > 64:
        key = hashlib.sha1(key).digest()
    key = key.ljust(64, b"\x00")
    inner = hashlib.sha1(bytes(b ^ 0x36 for b in key))
    outer = hashlib.sha1(bytes(b ^ 0x5C for b in key))
    return inner, outer


def prf512(key: bytes, label: bytes, data: bytes) -> bytes:
    """802.11i PRF (HMAC-SHA1 based) producing 512 bits of PTK."""
    inner_t, outer_t = _hmac_sha1_templates(key)
    base = label + b"\x00" + data
    out, counter = b"", 0
    while len(out) < PTK_BITS // 8:
        inner = inner_t.copy()
        inner.update(base + bytes([counter]))
        outer = outer_t.copy()
        outer.update(inner.digest())
        out += outer.digest()
        counter += 1
    return out[: PTK_BITS // 8]


def ptk(pmk_bytes: bytes, ap: bytes, station: bytes, anonce: bytes, snonce: bytes) -> bytes:
    data = (min(ap, station) + max(ap, station)
            + min(anonce, snonce) + max(anonce, snonce))
    return prf512(pmk_bytes, b"Pairwise key expansion", data)


def compute_pmkid(pmk_bytes: bytes, ap: bytes, station: bytes) -> str:
    return hmac.new(pmk_bytes, PMKID_LABEL + ap + station, hashlib.sha1).digest()[:16].hex()


#: Key Descriptor Version -> MIC algorithm (IEEE 802.11-2024 §12.7.2, Table 12-11)
KDV_MD5, KDV_SHA1, KDV_CMAC = 1, 2, 3

MIC_ALGORITHMS = {KDV_MD5: ("md5",), KDV_SHA1: ("sha1",), KDV_CMAC: ("cmac",)}


def key_descriptor_version(eapol_frame: bytes) -> int:
    """The Key Descriptor Version an EAPOL-Key frame asks for (bits 0-2).

    This — not the descriptor *type* — decides the MIC algorithm: version 1 is
    HMAC-MD5, 2 is HMAC-SHA1-128 (classic WPA2/CCMP), 3 is AES-128-CMAC
    (802.11w/PMF, SAE and the SHA-256 AKMs), and 0 means "whatever the
    negotiated AKM says", which in practice is CMAC for WPA3 and SHA1 for the
    older ones.
    """
    if len(eapol_frame) < 7:
        return 0
    return int.from_bytes(eapol_frame[5:7], "big") & 0x0007


def mic_algorithms(kdv: int) -> Tuple[str, ...]:
    """The MIC algorithm(s) a Key Descriptor Version allows, best guess first."""
    return MIC_ALGORITHMS.get(kdv, ("cmac", "sha1"))


def mic_candidates(ptk_bytes: bytes, eapol_frame: bytes, kdv: int = 0) -> Iterator[bytes]:
    """Every MIC this frame could carry, in the order its version allows."""
    kck = ptk_bytes[:16]
    for algorithm in mic_algorithms(kdv):
        if algorithm == "cmac":
            yield aes_cmac(kck, eapol_frame)[:16]
        elif algorithm == "sha1":
            yield hmac.new(kck, eapol_frame, hashlib.sha1).digest()[:16]
        else:
            yield hmac.new(kck, eapol_frame, hashlib.md5).digest()[:16]


def mic_from_ptk(ptk_bytes: bytes, eapol_frame: bytes, kdv: int = 0) -> bytes:
    """The MIC of an EAPOL-Key frame for a known Key Descriptor Version.

    ``kdv`` 0 (or anything unrecognised) resolves to the frame's own version,
    falling back to AES-CMAC — the modern default.  Use
    :func:`mic_candidates` when the version itself is uncertain and every
    algorithm has to be tried.
    """
    if not kdv:
        kdv = key_descriptor_version(eapol_frame)
    return next(mic_candidates(ptk_bytes, eapol_frame, kdv))


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


def _nonce_bytes(value) -> bytes:
    """Nonces arrive as raw bytes or as the hex strings a capture exposes."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        try:
            return bytes.fromhex(value)
        except ValueError:
            return b""
    return b""


def _zero_mic(eapol: bytes, mic_offset: int = 81) -> bytes:
    if len(eapol) < mic_offset + 16:
        return eapol
    return eapol[:mic_offset] + bytes(16) + eapol[mic_offset + 16:]


class PmkidVerifier:
    """One PMKID, ready to be tested against any number of candidates.

    Parsing the MAC addresses and validating the hash happens once here instead
    of once per password: at ~2.3 ms of PBKDF2 per candidate, every avoidable
    microsecond of bookkeeping is a lost candidate.
    """

    __slots__ = ("pmkid", "ssid", "ap_mac", "station_mac", "ap", "station",
                 "salt", "msg", "pmkid_bytes")

    def __init__(self, pmkid_hex: str, ssid, ap_mac: str, station_mac: str):
        self.pmkid = (pmkid_hex or "").strip().lower()
        self.ssid = ssid if ssid else b""
        # the PBKDF2 salt is derived once here, not per candidate
        self.salt = ssid_bytes(ssid)
        self.ap_mac = ap_mac or ""
        self.station_mac = station_mac or ""
        try:
            self.ap = bytes(int(part, 16) for part in self.ap_mac.split(":"))
            self.station = bytes(int(part, 16) for part in self.station_mac.split(":"))
        except ValueError:
            self.ap = self.station = b""
        # per-candidate constants, built once: the HMAC message and the
        # expected digest as bytes (compare_digest on bytes, no .hex() churn)
        self.msg = PMKID_LABEL + self.ap + self.station
        try:
            self.pmkid_bytes = bytes.fromhex(self.pmkid)
        except ValueError:
            self.pmkid_bytes = b""

    @property
    def usable(self) -> bool:
        return bool(self.pmkid_bytes and self.salt and len(self.salt) <= 32
                    and len(self.ap) == 6 and len(self.station) == 6)

    def check(self, password: str) -> bool:
        """Does ``password`` hash to this PMKID?"""
        if not self.usable or not 8 <= len(password) <= 63:
            return False
        try:
            key = hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"),
                                      self.salt, WPA_PMK_BITS, 32)
        except (ValueError, UnicodeEncodeError):
            return False
        return self.check_pmk(key)

    def check_pmk(self, pmk_bytes: bytes) -> bool:
        if not self.usable:
            return False
        digest = hmac.new(pmk_bytes, self.msg, hashlib.sha1).digest()
        return hmac.compare_digest(digest[:16], self.pmkid_bytes)


class HandshakeVerifier:
    """A handshake prepared for MIC verification.

    ``verify_handshake()`` is fine for a single check, but a cracker calls it
    once per candidate: extracting the EAPOL frame and zeroing the MIC offset
    are the same every time, so this object does them once.  What is left per
    candidate is exactly the work WPA defines — PBKDF2, the PTK expansion and
    the CMAC.
    """

    __slots__ = ("ssid", "ap", "station", "anonce", "snonce", "key_descriptor",
                 "targets", "salt", "ptk_data")

    def __init__(self, frames: Dict[int, bytes], ssid, ap_mac: str,
                 station_mac: str, anonce: bytes, snonce: bytes,
                 key_descriptor: int = 0, eapol_frames: Sequence[bytes] = (),
                 mic: bytes = b""):
        self.ssid = ssid if ssid else b""
        self.salt = ssid_bytes(ssid)
        self.anonce = _nonce_bytes(anonce)
        self.snonce = _nonce_bytes(snonce)
        self.key_descriptor = key_descriptor
        try:
            self.ap = bytes.fromhex((ap_mac or "").replace(":", ""))
            self.station = bytes.fromhex((station_mac or "").replace(":", ""))
        except ValueError:
            self.ap = self.station = b""
        # the PTK expansion input never changes per candidate: sort once
        self.ptk_data = (min(self.ap, self.station) + max(self.ap, self.station)
                         + min(self.anonce, self.snonce)
                         + max(self.anonce, self.snonce))
        targets = []
        for frame in eapol_frames:               # already an EAPOL-Key frame
            if len(frame) < 97:
                continue
            expected = mic if len(mic) == 16 else frame[81:97]
            targets.append((expected, _zero_mic(frame), key_descriptor_version(frame)))
        for number in (2, 4):
            frame = frames.get(number)
            if not frame:
                continue
            eapol = _eapol_frame_from_bytes(frame)
            if len(eapol) < 97:
                continue
            targets.append((eapol[81:97], _zero_mic(eapol), key_descriptor_version(eapol)))
        self.targets = tuple(targets)

    @classmethod
    def from_eapol(cls, eapol: bytes, ssid, ap_mac: str, station_mac: str,
                   anonce: bytes, snonce: bytes, mic: bytes = b"",
                   key_descriptor: int = 0) -> "HandshakeVerifier":
        """Build one from an EAPOL-Key frame (hashcat mode 22000 lines carry
        exactly this, with the MIC in its own field and zeroed in the frame)."""
        return cls({}, ssid, ap_mac, station_mac, anonce, snonce, key_descriptor,
                   eapol_frames=[eapol], mic=mic)

    @classmethod
    def from_analysis(cls, handshake, ssid: str,
                      bssid: str = "") -> "HandshakeVerifier":
        """Build one from a :class:`wifipilot.pcap.Handshake`."""
        frames = {number: message.raw for number, message in handshake.messages.items()}
        return cls(frames, ssid, bssid or handshake.bssid, handshake.station,
                   handshake.anonce, handshake.snonce)

    @property
    def usable(self) -> bool:
        return bool(self.targets and self.ssid and len(self.ap) == 6
                    and len(self.station) == 6 and len(self.anonce) == 32
                    and len(self.snonce) == 32)

    def check(self, password: str) -> bool:
        """Does ``password`` produce the MIC that is on air?"""
        if not self.usable or not 8 <= len(password) <= 63 or not self.salt:
            return False
        try:
            key = hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"),
                                      self.salt, WPA_PMK_BITS, 32)
        except (ValueError, UnicodeEncodeError):
            return False
        return self.check_pmk(key)

    def check_pmk(self, pmk_bytes: bytes) -> bool:
        if not self.usable:
            return False
        ptk_bytes = prf512(pmk_bytes, b"Pairwise key expansion", self.ptk_data)
        kck = ptk_bytes[:16]
        compare = hmac.compare_digest
        fallback_kdv = self.key_descriptor
        cmac_engine = None
        for expected_mic, eapol, kdv in self.targets:
            # every frame says which MIC it carries; a version of 0 is the only
            # case that needs more than one algorithm tried
            for algorithm in mic_algorithms(kdv or fallback_kdv):
                if algorithm == "cmac":
                    if cmac_engine is None:
                        cmac_engine = _Cmac(kck)
                    digest = cmac_engine.digest(eapol)
                elif algorithm == "sha1":
                    digest = hmac.new(kck, eapol, hashlib.sha1).digest()[:16]
                else:
                    digest = hmac.new(kck, eapol, hashlib.md5).digest()[:16]
                if compare(expected_mic, digest):
                    return True
        return False


def verify_pmkid(pmkid_hex: str, ssid: str, ap_mac: str, station_mac: str,
                 password: str) -> bool:
    """Does ``password`` produce this PMKID?"""
    return PmkidVerifier(pmkid_hex, ssid, ap_mac, station_mac).check(password)


def verify_handshake(frames: Dict[int, bytes], ssid: str, ap_mac: str,
                     station_mac: str, anonce: bytes, snonce: bytes,
                     password: str, key_descriptor: int = 0) -> bool:
    """Recompute the MIC of message 2/4 and compare it with what is on air."""
    verifier = HandshakeVerifier(frames, ssid, ap_mac, station_mac, anonce, snonce,
                                 key_descriptor)
    return verifier.check(password)
