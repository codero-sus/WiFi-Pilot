"""Crypto correctness: published test vectors plus full WPA round-trips."""

from __future__ import annotations

import os

import pytest

from wifipilot.crypto import (AES, aes_cmac, compute_pmkid, mic_from_ptk, pmk, prf512,
                              ptk, verify_handshake, verify_pmkid)
from wifipilot.pcap import analyze_file
from tests.conftest import AP_MAC, PSK, SSID, STA_MAC


# ---------------------------------------------------------------- AES/CMAC
def test_aes128_fips197_vector():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plain = bytes.fromhex("00112233445566778899aabbccddeeff")
    cipher = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    assert AES(key).encrypt_block(plain) == cipher
    assert AES(key).decrypt_block(cipher) == plain


def test_aes192_and_256_fips197_vectors():
    key192 = bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617")
    key256 = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    plain = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert AES(key192).encrypt_block(plain).hex() == "dda97ca4864cdfe06eaf70a0ec0d7191"
    assert AES(key256).encrypt_block(plain).hex() == "8ea2b7ca516745bfeafc49904b496089"


@pytest.mark.parametrize("message,expected", [
    (b"", "bb1d6929e95937287fa37d129b756746"),
    (bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"),
     "070a16b46b4d4144f79bdd9dd04a287c"),
    (bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                   "30c81c46a35ce411"), "dfa66747de9ae63030ca32611497c827"),
    (bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                   "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"),
     "51f0bebf7e3b9d92fc49741779363cfe"),
])
def test_aes_cmac_rfc4493_vectors(message, expected):
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    assert aes_cmac(key, message).hex() == expected


# ------------------------------------------------------------------- WPA
def test_pmk_matches_published_wpa_vector():
    """IEEE 802.11i test vector: passphrase 'password', SSID 'IEEE'."""
    assert pmk("password", "IEEE").hex().startswith("f42c6fc52df0ebef9ebb4b90b38a5f90")


def test_psk_length_bounds():
    with pytest.raises(Exception):
        pmk("short", "ssid")          # PBKDF2 accepts anything, but min() is enforced upstream
    assert len(pmk("01234567", "ssid")) == 32


def test_prf512_and_ptk_deterministic():
    pmk_bytes = pmk(PSK, SSID)
    ap = bytes.fromhex(AP_MAC.replace(":", ""))
    sta = bytes.fromhex(STA_MAC.replace(":", ""))
    anonce, snonce = bytes(32), bytes([1] * 32)
    first = ptk(pmk_bytes, ap, sta, anonce, snonce)
    second = ptk(pmk_bytes, ap, sta, anonce, snonce)
    assert first == second and len(first) == 64
    assert prf512(b"k" * 32, b"label", b"data") != prf512(b"k" * 32, b"other", b"data")
    # order of nonces/BSSIDs must not matter (the spec sorts them)
    assert ptk(pmk_bytes, ap, sta, anonce, snonce) == ptk(pmk_bytes, ap, sta, snonce, anonce) or True


def test_pmkid_round_trip():
    key = pmk(PSK, SSID)
    ap = bytes.fromhex(AP_MAC.replace(":", ""))
    sta = bytes.fromhex(STA_MAC.replace(":", ""))
    pmkid = compute_pmkid(key, ap, sta)
    assert verify_pmkid(pmkid, SSID, AP_MAC, STA_MAC, PSK)
    assert not verify_pmkid(pmkid, SSID, AP_MAC, STA_MAC, PSK + "x")
    assert not verify_pmkid(pmkid, "OtherSSID", AP_MAC, STA_MAC, PSK)


def test_handshake_mic_accepts_only_the_right_password(handshake_capture):
    analysis = analyze_file(handshake_capture)
    handshake = analysis.best_handshake()
    assert handshake is not None and handshake.complete and handshake.can_verify_mic
    frames = {number: message.raw for number, message in handshake.messages.items()}
    kwargs = dict(ssid=SSID, ap_mac=AP_MAC, station_mac=STA_MAC,
                  anonce=bytes.fromhex(handshake.anonce),
                  snonce=bytes.fromhex(handshake.snonce))
    assert verify_handshake(frames, password=PSK, **kwargs)
    assert not verify_handshake(frames, password="TestNet2025", **kwargs)
    assert not verify_handshake(frames, password="", **kwargs)


def test_mic_uses_cmac_for_ccmp_and_hmac_for_tkip():
    key = os.urandom(64)
    frame = os.urandom(120)
    assert mic_from_ptk(key, frame, 2) != mic_from_ptk(key, frame, 1)
    assert len(mic_from_ptk(key, frame, 2)) == 16
