# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
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
from typing import Any, Dict, List, Optional, Tuple

from .crypto import KDV_SHA1, compute_pmkid, mic_from_ptk, pmk, ptk

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


def _with_kdv(key_info: int, kdv: int) -> int:
    """The key information field with a given Key Descriptor Version."""
    return (key_info & ~0x0007) | (kdv & 0x0007)


def _sign(eapol_frame: bytes, ptk_bytes: bytes, kdv: int = KDV_SHA1) -> bytes:
    """Sign a frame the way a real AP/STA would for that Key Descriptor Version.

    Version 2 (HMAC-SHA1-128) is what classic WPA2/CCMP handshakes carry; 3 is
    AES-128-CMAC (802.11w/PMF, SAE); 1 is HMAC-MD5 (TKIP).
    """
    offset = _mic_offset(eapol_frame)
    zeroed = eapol_frame[:offset] + bytes(16) + eapol_frame[offset + 16:]
    return mic_from_ptk(ptk_bytes, zeroed, kdv)


def build_handshake_frames(ssid: str, bssid: str, station: str, password: str,
                           seed: Optional[int] = None,
                           include_pmkid: bool = False,
                           pmkid: str = "",
                           kdv: int = KDV_SHA1) -> Tuple[List[bytes], str]:
    """Return (frames, pmkid) containing beacon + M1/M2 (+M3/M4) with valid MICs.

    ``kdv`` picks the Key Descriptor Version (and therefore the MIC algorithm)
    the frames claim: 2 = classic WPA2/CCMP (HMAC-SHA1-128, the default), 3 =
    802.11w/PMF or SAE (AES-128-CMAC), 1 = WPA/TKIP (HMAC-MD5).
    """
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
    m1 = _eapol(_with_kdv(0x008a, kdv), 1, anonce, pmkid_kde)
    frames.append(_data_header(ap, sta, ap, 1, to_ds=False) + _llc_eapol(m1))
    # M2: SNonce + MIC (0x010a)
    m2 = _eapol(_with_kdv(0x010a, kdv), 1, snonce)
    m2 = m2[:_mic_offset(m2)] + _sign(m2, ptk_bytes, kdv) + m2[_mic_offset(m2) + 16:]
    frames.append(_data_header(sta, ap, ap, 2) + _llc_eapol(m2))
    # M3: ANonce + MIC + install + secure + GTK (0x13ca)
    gtk_kde = b"\xdd\x16\x00\x0f\xac\x01" + bytes(4) + bytes(16)
    m3 = _eapol(_with_kdv(0x13ca, kdv), 2, anonce, gtk_kde)
    m3 = m3[:_mic_offset(m3)] + _sign(m3, ptk_bytes, kdv) + m3[_mic_offset(m3) + 16:]
    frames.append(_data_header(ap, sta, ap, 3, to_ds=False) + _llc_eapol(m3))
    # M4: MIC only (0x030a)
    m4 = _eapol(_with_kdv(0x030a, kdv), 2, bytes(32))
    m4 = m4[:_mic_offset(m4)] + _sign(m4, ptk_bytes, kdv) + m4[_mic_offset(m4) + 16:]
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


#: the four 802.11b basic rates, and the 802.11b/g set a modern AP advertises
LEGACY_RATES = b"\x82\x84\x8b\x96"
MODERN_RATES = b"\x82\x84\x8b\x96\x0c\x12\x18\x24"


def ie(tag: int, value: bytes) -> bytes:
    """One information element: tag, length, value."""
    return bytes([tag & 0xFF, len(value) & 0xFF]) + value


def wps_element(version: str = "1.0", methods: int = 0x0088, locked: bool = False,
                manufacturer: str = "", model: str = "", device_name: str = "",
                model_number: str = "", serial: str = "") -> bytes:
    """A WPS element (vendor-specific, OUI 00:50:f2:04) as an AP advertises it.

    ``methods`` is the configuration-methods bit field: 0x0080 is push-button,
    0x0008 label, 0x0100 keypad.  The default here is label + push-button, which is
    what a consumer AP ships with.
    """
    major, _, minor = (version or "1.0").partition(".")
    attributes = bytearray()

    def attr(name: int, body: bytes) -> None:
        # closure over a bytearray: ``+=`` would rebind the name, ``extend`` mutates
        attributes.extend(name.to_bytes(2, "big"))
        attributes.extend(len(body).to_bytes(2, "big"))
        attributes.extend(body)

    attr(0x1044, bytes([int(major or 1), int(minor or 0)]))
    attr(0x1053, b"\x00")                                  # selected registrar
    attr(0x1057, b"\x02")                                  # response type: AP
    attr(0x1012, methods.to_bytes(2, "big"))
    attr(0x1051, b"\x01" if locked else b"\x00")
    if manufacturer:
        attr(0x1021, manufacturer.encode()[:64])
    if model:
        attr(0x1023, model.encode()[:32])
    if model_number:
        attr(0x1024, model_number.encode()[:32])
    if device_name:
        attr(0x1026, device_name.encode()[:32])
    if serial:
        attr(0x104A, serial.encode()[:32])
    return ie(221, b"\x00\x50\xf2\x04" + bytes(attributes))


def country_element(code: str = "IN", first_channel: int = 1, channels: int = 13,
                    max_power: int = 20, code_bytes: int = 3) -> bytes:
    """The country element: a country code and one regulatory class' triplets."""
    body = code.upper().encode("ascii")[:2].ljust(2, b"X")
    body += b"\x20" if code_bytes == 3 else b""
    triplet = bytes([first_channel, channels, max_power])
    return ie(7, body + triplet * 4)


def ht_capabilities(width40: bool = False, streams: int = 1) -> bytes:
    """HT capabilities: the 2.4/5 GHz high-throughput element.

    ``streams`` sets the basic MCS set's highest supported rate index in the
    supported-MCS field (0xFF = 1..8 for two or more spatial streams), which is what
    the element decoder reads back out of the capture.
    """
    capa = 0x000C                                   # LDPC + short GI, 20 MHz
    if width40:
        capa |= 0x0400                              # 40 MHz intolerant off -> 40 MHz
    mcs_set = bytearray(16)
    mcs_set[0] = 0xFF if streams > 1 else 0x00      # Rx MCS bitmask: MCS 0-7
    # HT Capabilities Info (2) + A-MPDU parameters (1) + supported MCS set (16) +
    # HT extended capabilities (2) + transmit beamforming (4) + ASEL (1)
    return ie(45, struct.pack("<H", capa) + bytes([0x1B]) + bytes(mcs_set) + bytes(9))


def vht_capabilities() -> bytes:
    """VHT capabilities: the 5 GHz element that says the AP is 802.11ac."""
    body = struct.pack("<I", 0x0F8F0000) + bytes([0x00, 0x00, 0x00, 0x00])
    body += bytes(8) + bytes([0xFC, 0x00, 0x00]) + bytes(4)
    return ie(191, body)


#: Extended Capabilities bits, by the numbers the standard gives them (table 9-169).
#: They matter because this one element answers "does this AP do 802.11v/k/r", and
#: because reading it at the wrong offset is how a tool reports a feature the network
#: does not have.
EXTENDED_CAPABILITY_BITS = {"20/40 coexistence": 0, "extended channel switching": 2,
                            "BSS transition (802.11v)": 19, "WNM sleep mode": 24,
                            "WNM notifications": 25, "TIM broadcast": 22,
                            "multi-band": 40, "SSPN interface": 10}


def extended_capabilities(bss_transition: bool = True, wnm_sleep: bool = False,
                          coexistence: bool = False, channel_switch: bool = False,
                          **extra: bool) -> bytes:
    """The Extended Capabilities element (tag **127**), bit by bit.

    The bits are set by their standard numbers rather than by byte offsets, because
    "bit 19 is BSS transition" is checkable and "byte 3 bit 3" is how the element was
    read wrongly for years.
    """
    wanted = dict(EXTENDED_CAPABILITY_BITS)
    wanted.update({key.replace("_", " "): value for key, value in extra.items()})
    flags = {"BSS transition (802.11v)": bss_transition, "WNM sleep mode": wnm_sleep,
             "20/40 coexistence": coexistence, "extended channel switching": channel_switch}
    value = bytearray(8)
    for name, on in flags.items():
        bit = wanted.get(name)
        if on and bit is not None:
            value[bit // 8] |= 1 << (bit % 8)
    return ie(127, bytes(value))


def mobility_domain(md: bytes = b"\x00\x01", over_ds: bool = True) -> bytes:
    """The 802.11r Mobility Domain element (tag 54).

    Two bytes of MDID and a capability byte whose bit 0 says the AP accepts fast
    BSS transitions over the distribution system — the bit that decides whether a
    roaming assessment has anything to work with.
    """
    return ie(54, md[:2] + bytes([0x01 if over_ds else 0x00]))


def rm_enabled_capabilities(neighbour_report: bool = True, beacon_passive: bool = True,
                            beacon_active: bool = True, beacon_table: bool = True,
                            link_measurement: bool = True) -> bytes:
    """RM Enabled Capabilities (tag 70): which 802.11k measurements an AP will do.

    Five bytes of bitmap.  A neighbour report request can only be answered by an AP
    that advertises the capability, which is why an audit reads this before it says
    anything about location privacy.
    """
    value = bytearray(5)
    for bit, on in ((1, link_measurement), (2, neighbour_report), (3, beacon_passive),
                    (4, beacon_active), (5, beacon_table)):
        if on:
            value[bit // 8] |= 1 << (bit % 8)
    return ie(70, bytes(value))


def neighbour_report_element(entries: Optional[List[Tuple[str, int, int]]] = None) -> bytes:
    """A Neighbour Report element (tag 52): the APs this one will hand a client to.

    Each entry is a BSSID, its BSSID information field, an operating class, a channel
    and a PHY type — 13 bytes each, exactly as a beacon report response carries them.
    """
    # (bssid, operating class, channel) — the default entry is a 2.4GHz neighbour
    entries = entries or [("aa:bb:cc:11:22:33", 81, 6)]
    body = bytearray()
    for bssid, operating_class, channel in entries:
        body += _mac(bssid)
        body += struct.pack("<I", 0x00000003)          # AP reachable, security: same
        body += bytes([operating_class, channel, 7])   # operating class, channel, PHY
    return ie(52, bytes(body))


def bss_load_element(station_count: int = 8, utilisation: int = 90,
                     available_admission: int = 1200) -> bytes:
    """BSS Load (tag 11): how busy the cell says it is.

    ``utilisation`` is the channel-utilisation byte (0-255, so 90 is 35%), and the
    station count is the AP's own association table — the two numbers that turn
    "which AP is the target" from a guess into a measurement.
    """
    # station count (2), channel utilisation (1), available admission capacity (2)
    return ie(11, struct.pack("<HBH", station_count & 0xFFFF, utilisation & 0xFF,
                              available_admission & 0xFFFF))


def interworking_element(network_type: int = 2, internet: bool = True,
                         venue_group: int = 1) -> bytes:
    """The Interworking element (tag 107): what kind of network this claims to be.

    The low nibble of the first byte is the access network type (``2`` is a chargeable
    public network, ``14`` is a personal device), bit 4 is the internet bit, and the
    second byte's low nibble is the venue group.
    """
    first = (network_type & 0x0F) | (0x10 if internet else 0x00)
    return ie(107, bytes([first, (venue_group & 0x0F) << 4]))


def hs20_element(release: int = 2, anqp_domain: int = 0x1234,
                 operator: bytes = b"\x00\x01\x02") -> bytes:
    """The Hotspot 2.0 (Passpoint) element: vendor 221, OUI 00:50:f2, type 0x11."""
    body = bytes([release & 0x0F]) + struct.pack(">H", anqp_domain & 0xFFFF)
    if operator:
        body += bytes([len(operator)]) + operator
    return ie(221, WFA_VENDOR_OUI + b"\x11" + body)


def wmm_parameter_element(acm_be: bool = False, aifsn: int = 3, ecw_min: int = 4,
                          ecw_max: int = 10, acm_voice: bool = False) -> bytes:
    """The WMM Parameter element: vendor 221, OUI 00:50:f2, type 2.

    Four access-category records (best effort, background, video, voice) of four bytes
    each, prefixed by a version and a QoS info byte.  APs that require admission
    control for a category set the ACM bit, and that is what a voice deployment's
    capacity numbers hinge on.
    """
    def record(index: int) -> bytes:
        acm = (index == 0 and acm_be) or (index == 3 and acm_voice)
        return bytes([aifsn, (ecw_max << 4) | ecw_min, 0x01 if acm else 0x00, 0x00])

    return (ie(221, WFA_VENDOR_OUI + b"\x02" + bytes([1, 0x80])
               + b"".join(record(index) for index in range(4))))


def he_capabilities(mcs_map: int = 0xFA) -> bytes:
    """HE Capabilities as an Element Extension (tag 255, extension id 35)."""
    return ie(255, bytes([35]) + struct.pack("<H", 0x03F0) + bytes([mcs_map, 0x00]) + bytes(8))


def build_beacon(ssid: str, bssid: str, channel: int = 6, include_rsn: bool = True,
                 akm: str = "psk", pmf: bool = False, extra_ies: bytes = b"",
                 rates: bytes = MODERN_RATES, tsf: int = 0, tkip: bool = False) -> bytes:
    """A well-formed 802.11 beacon, for capture-shape benchmarks and tests.

    ``akm`` selects the AKM suites in the RSN element (``psk``, ``sae``,
    ``sae+psk`` for transition mode, ``owe``, ``802.1x``) and ``pmf`` sets the
    MFPC/MFPR bits, because the WPA3 audit reads exactly those two fields.
    ``extra_ies`` appends any further elements (WPS, country, HT/VHT, 802.11r, …),
    which is how the configuration audit gets something to audit.
    """
    ap = _mac(bssid)
    ssid_bytes = ssid.encode()[:32]
    body = (b"\x80\x00\x00\x00" + b"\xff" * 6 + ap + ap + b"\x00\x00"
            + struct.pack("<Q", tsf & 0xFFFFFFFFFFFFFFFF)     # timestamp (µs)
            + b"\x64\x00"                                    # beacon interval
            + b"\x01\x04")                                   # capability: ESS + privacy
    if include_rsn:
        body += b"\x00" + bytes([len(ssid_bytes)]) + ssid_bytes
        body += ie(1, rates)
        body += b"\x03\x01" + bytes([channel])                          # DS parameter
        body += (rsn_element(akm, pmf=pmf, group="tkip", pairwise="tkip+ccmp")
                 if tkip else rsn_element(akm, pmf=pmf))
    else:
        body += b"\x00\x00"                                            # hidden SSID
    return body + bytes(extra_ies)


def build_probe_request(station: str, ssid: str = "", bssid: str = "ff:ff:ff:ff:ff:ff"
                        ) -> bytes:
    """A probe request: ``ssid=""`` is the wildcard ("is anything out there?").

    Clients send these in the clear, including on WPA3 networks, which is why a
    passive capture can map a client's preferred network list without any
    injection at all.
    """
    sta = _mac(station)
    # a probe request has no fixed field area: the element list starts right after the
    # 24-byte header.  Writing beacon-scale fields here (a timestamp, an interval)
    # makes the first "element" a zero-length SSID, which is how a directed probe comes
    # to look like a wildcard one to every reader downstream.
    ssid_bytes = ssid.encode()[:32]
    body = b"\x00" + bytes([len(ssid_bytes)]) + ssid_bytes
    body += b"\x01\x04\x82\x84\x8b\x96"     # rates
    return b"\x40\x00\x00\x00" + b"\xff" * 6 + sta + _mac(bssid) + b"\x00\x00" + body


def build_deauth(bssid: str, station: str = "ff:ff:ff:ff:ff:ff", reason: int = 7
                 ) -> bytes:
    """A deauthentication frame (subtype 12), the frame an attack is made of."""
    return (b"\xc0\x00\x00\x00" + _mac(station) + _mac(bssid) + _mac(bssid)
            + b"\x00\x00" + bytes([reason, 0]))


def build_deauth_flood(bssid: str, rounds: int = 40, broadcast: bool = True,
                       reason: int = 7) -> List[bytes]:
    """A burst of deauth frames — enough of them for ``sniff.attack_frames``.

    ``reason=15``/``16`` is not a mistake: those are the codes an AP sends when a
    forged TKIP MIC trips its Michael countermeasures, which is a *finding* to an
    audit rather than an attack.
    """
    frames: List[bytes] = []
    for index in range(max(1, rounds)):
        frames.append(build_deauth(bssid, "ff:ff:ff:ff:ff:ff" if broadcast
                                   else random_mac(locally_administered=True),
                                   reason=reason if reason != 15 else 15 + index % 2))
    return frames


#: AKM suite selector bytes (little-endian 4-byte selectors 00-0f-ac-XX)
_AKM_CODES = {"802.1x": 1, "psk": 2, "ft-802.1x": 3, "ft-psk": 4, "psk-sha256": 6,
              "sae": 8, "ft-sae": 9, "owe": 18, "sae-ext": 24, "sae-h2e": 24,
              "h2e": 24, "sae-h2e-ext": 25}


_CIPHER_CODES = {"wep40": 1, "wep64": 1, "tkip": 2, "ccmp": 4, "wep104": 5, "wep128": 5,
                 "gcmp": 9, "gcmp256": 10, "ccmp256": 11, "bip": 6, "bipcmac": 6}


def _cipher_codes(value) -> List[int]:
    """Accept an OUI code (``4``) or the names an assessment talks in (``tkip+ccmp``)."""
    if isinstance(value, int):
        return [value]
    codes: List[int] = []
    for name in str(value).replace("/", "+").split("+"):
        code = _CIPHER_CODES.get(name.strip().lower())
        if code is not None and code not in codes:
            codes.append(code)
    return codes or [4]


def rsn_element(akm: str = "psk", pmf: bool = False, pairwise="ccmp",
                group="ccmp") -> bytes:
    """An RSN information element (tag 48) with the AKM list and PMF bits.

    ``akm="sae+psk"`` builds the transition-mode element that makes a "WPA3" network
    still reachable through its WPA2 path — the thing the WPA3 audit looks for.
    """
    suites: List[int] = []
    for name in str(akm).replace("/", "+").split("+"):
        code = _AKM_CODES.get(name.strip().lower())
        if code is not None and code not in suites:
            suites.append(code)
    if not suites:
        suites = [2]
    capabilities = 0
    if pmf:
        capabilities = 0x0030                     # MFPC (bit 5) + MFPR (bit 4)
    group_codes = _cipher_codes(group)
    pairwise_codes = _cipher_codes(pairwise)
    body = (bytes([1, 0])                          # RSN version 1
            + bytes([group_codes[0], 0, 0, 0])     # group cipher
            + struct.pack("<H", len(pairwise_codes))
            + b"".join(bytes([code, 0, 0, 0]) for code in pairwise_codes)
            + bytes([len(suites), 0])
            + b"".join(bytes([code, 0, 0, 0]) for code in suites)
            + struct.pack("<H", capabilities))
    return bytes([48, len(body)]) + body


def build_sae_commit(bssid: str, station: str, group: int = 19, scalar: bytes = b"",
                     element: bytes = b"", status: int = 0) -> bytes:
    """An SAE commit frame (802.11 auth, algorithm 3, transaction 1).

    The commit carries the *group* in its status field and a fixed-size scalar and
    element; nothing in it can be checked against a password guess offline, which is
    the whole point of a PAKE.
    """
    scalar = scalar or bytes((index * 7 + 3) % 256 for index in range(32))
    element = element or bytes((index * 11 + 5) % 256 for index in range(64))
    body = struct.pack("<HHH", 3, 1, group if not status else status)
    body += scalar + element
    return (b"\xb0\x00\x00\x00" + _mac(bssid) + _mac(station) + _mac(bssid)
            + b"\x00\x00" + body)


def build_sae_confirm(bssid: str, station: str, status: int = 0) -> bytes:
    """An SAE confirm frame (802.11 auth, algorithm 3, transaction 2)."""
    body = struct.pack("<HHH", 3, 2, status) + bytes((index * 13 + 7) % 256
                                                     for index in range(32))
    return (b"\xb0\x00\x00\x00" + _mac(bssid) + _mac(station) + _mac(bssid)
            + b"\x00\x00" + body)


def build_wpa3_capture(path: str, essid: str = "Vodafone-9C31",
                       bssid: str = "f0:63:da:4a:c1:f5",
                       station: str = "02:00:00:00:00:31", akm: str = "sae",
                       pmf: bool = True, group: int = 19) -> Tuple[str, List[bytes]]:
    """A WPA3 beacon plus a complete SAE commit/confirm exchange."""
    frames = [build_beacon(essid, bssid, channel=100, akm=akm, pmf=pmf),
              build_sae_commit(bssid, station, group=group),
              build_sae_confirm(bssid, station),
              build_sae_commit(bssid, station, group=group)]
    write_pcap(path, frames, spacing=0.01)
    return str(path), frames


def self_signed_certificate(common_name: str = "radius.lab.local",
                            organization: str = "wifipilot lab",
                            country: str = "IN",
                            issuer_cn: str = "", issuer_org: str = "") -> bytes:
    """A minimal but *parseable* X.509 certificate (DER).

    Real enough for the part that matters in an assessment: with no ``issuer_cn``
    the subject and the issuer are the same Name, which is exactly what
    ``sniff.x509_name`` reports as ``self_signed`` — the finding that matters,
    because a client that accepts it will accept anybody's.  A different issuer is
    used to test the *other* case (a properly issued certificate).  This is not a
    valid signature chain and does not claim to be.
    """
    def tlv(tag: int, body: bytes) -> bytes:
        if len(body) < 0x80:
            return bytes([tag, len(body)]) + body
        return bytes([tag, 0x82]) + struct.pack(">H", len(body)) + body

    def oid(dotted: str) -> bytes:
        parts = [int(part) for part in dotted.split(".")]
        out = bytes([parts[0] * 40 + parts[1]])
        for part in parts[2:]:
            chunk: List[int] = []
            while True:
                chunk.insert(0, part & 0x7F)
                part >>= 7
                if not part:
                    break
            out += bytes([byte | 0x80 for byte in chunk[:-1]] + [chunk[-1]])
        return tlv(0x06, out)

    def rdn(dotted: str, value: str) -> bytes:
        return tlv(0x31, tlv(0x30, oid(dotted) + tlv(0x0C, value.encode())))

    subject = (rdn("2.5.4.3", common_name) + rdn("2.5.4.10", organization)
               + rdn("2.5.4.6", country))
    if issuer_cn or issuer_org:
        issuer = (rdn("2.5.4.3", issuer_cn or "Corp Issuing CA")
                  + rdn("2.5.4.10", issuer_org or organization))
    else:
        issuer = subject                            # self-signed
    tbs = (tlv(0xA0, tlv(0x02, b"\x02"))                    # version 3
           + tlv(0x02, b"\x01\x02\x03\x04")                 # serial
           + tlv(0x30, oid("1.2.840.113549.1.1.11"))       # sha256WithRSAEncryption
           + tlv(0x30, issuer)
           + tlv(0x30, tlv(0x17, b"250101000000Z") + tlv(0x17, b"350101000000Z"))
           + tlv(0x30, subject))
    return tlv(0x30, tlv(0x30, tbs))


def build_test_certificate(common_name: str = "radius.corp.example",
                           organization: str = "Example Corp",
                           country: str = "IN", issuer_cn: str = "",
                           issuer_org: str = "", bits: int = 2048,
                           not_before: str = "230104000000Z",
                           not_after: str = "270103000000Z",
                           signature_algorithm: str = "1.2.840.113549.1.1.11") -> bytes:
    """A structurally complete X.509 certificate (DER) for the certificate audits.

    :func:`self_signed_certificate` is deliberately minimal — it exists so the
    *self-signed* finding can be tested.  This one carries the rest of the structure an
    audit reads: an explicit version, the signature AlgorithmIdentifier, the validity
    window, and a real ``subjectPublicKeyInfo`` whose RSA modulus is ``bits`` long, so a
    key-size finding is a finding about this certificate and not about a constant.  With
    no ``issuer_cn``/``issuer_org`` the issuer is the subject: a self-signed certificate.
    """
    def tlv(tag: int, body: bytes) -> bytes:
        if len(body) < 0x80:
            return bytes([tag, len(body)]) + body
        if len(body) < 0x100:
            return bytes([tag, 0x81, len(body)]) + body
        return bytes([tag, 0x82]) + struct.pack(">H", len(body)) + body

    def oid(dotted: str) -> bytes:
        parts = [int(part) for part in dotted.split(".")]
        out = bytes([parts[0] * 40 + parts[1]])
        for part in parts[2:]:
            chunk = [part & 0x7F]
            part >>= 7
            while part:
                chunk.insert(0, (part & 0x7F) | 0x80)
                part >>= 7
            out += bytes(chunk)
        return tlv(0x06, out)

    def rdn(dotted: str, value: str) -> bytes:
        return tlv(0x31, tlv(0x30, oid(dotted) + tlv(0x0C, value.encode())))

    def name(cn: str, org: str, country_code: str) -> bytes:
        parts = rdn("2.5.4.3", cn) + rdn("2.5.4.10", org) + rdn("2.5.4.6", country_code)
        return tlv(0x30, parts)

    subject = name(common_name, organization, country)
    issuer = name(issuer_cn, issuer_org, country) if (issuer_cn or issuer_org) else subject
    # a plausible modulus of the requested size: only its length is judged, so it is
    # derived from the name (deterministic) rather than being a valid RSA key
    seed = hashlib.sha256(f"{common_name}|{bits}".encode()).digest()
    modulus = bytearray(seed * (bits // 8 // len(seed) + 1))[:bits // 8 or 128]
    modulus[0] |= 0x80
    modulus[-1] |= 0x01
    rsa_public_key = tlv(0x30, tlv(0x02, bytes(modulus)) + tlv(0x02, b"\x01\x00\x01"))
    spki = tlv(0x30, tlv(0x30, oid("1.2.840.113549.1.1.1"))
               + tlv(0x03, b"\x00" + rsa_public_key))
    signature = oid(signature_algorithm)
    tbs = (tlv(0xA0, tlv(0x02, b"\x02"))                  # v3
           + tlv(0x02, hashlib.sha256(common_name.encode()).digest()[:8])
           + tlv(0x30, signature)                          # signature AlgorithmIdentifier
           + issuer
           + tlv(0x30, tlv(0x17, not_before.encode()) + tlv(0x17, not_after.encode()))
           + subject
           + spki)
    return tlv(0x30, tlv(0x30, tbs) + tlv(0x30, signature)
               + tlv(0x03, b"\x00" + hashlib.sha256(common_name.encode()).digest() * 4))


def build_eap_response_identity(station: str, bssid: str, identity: str) -> bytes:
    """An EAP-Response/Identity frame — the clear-text username carrier."""
    body = identity.encode()[:253]
    eap = bytes([2, 1]) + struct.pack(">H", 5 + len(body)) + bytes([1]) + body
    eapol = bytes([2, 0]) + struct.pack(">H", len(eap)) + eap
    return (_data_header(_mac(station), _mac(bssid), _mac(bssid), 0) + _llc_eapol(eapol))


def build_eap_tls_certificate(station: str, bssid: str, certificate: bytes,
                              method: int = 25) -> bytes:
    """An EAP-Response carrying a TLS Certificate message (PEAP/TTLS/EAP-TLS).

    This is the frame that lets an *offline* survey prove a server presents a
    self-signed certificate, without transmitting anything.
    """
    handshake = (bytes([0x0B]) + struct.pack(">I", 6 + len(certificate))[1:]
                 + struct.pack(">I", 3 + len(certificate))[1:]
                 + struct.pack(">I", len(certificate))[1:] + certificate)
    record = bytes([0x16, 0x03, 0x03]) + struct.pack(">H", len(handshake)) + handshake
    flags = b"\x00" if method == 25 else b"\x20"          # PEAP: no start bit needed
    eap_body = flags + record
    eap = bytes([2, 2]) + struct.pack(">H", 5 + len(eap_body)) + bytes([method]) + eap_body
    eapol = bytes([2, 0]) + struct.pack(">H", len(eap)) + eap
    return (_data_header(_mac(station), _mac(bssid), _mac(bssid), 0) + _llc_eapol(eapol))


def build_eap_tls_server_hello(station: str, bssid: str, version: int = 0x0301,
                               cipher: int = 0xC02F, method: int = 25,
                               session_id: bytes = b"") -> bytes:
    """An EAP-Response carrying a TLS ServerHello record.

    The version field is what an audit reads: ``0x0301`` is TLS 1.0, ``0x0303`` is TLS
    1.2.  A capture that claims 802.1X security but negotiates TLS 1.0 is a finding,
    and it is one an offline reader can prove without transmitting anything.
    """
    random_bytes = hashlib.sha256((bssid + station).encode()).digest()
    body = (struct.pack(">H", version) + random_bytes
            + bytes([len(session_id)]) + session_id
            + struct.pack(">H", cipher) + b"\x00"          # no compression
            + struct.pack(">H", 0))                        # no extensions
    handshake = bytes([0x02]) + struct.pack(">I", len(body))[1:] + body
    record = bytes([0x16, version >> 8 & 0xFF, version & 0xFF]) \
        + struct.pack(">H", len(handshake)) + handshake
    flags = b"\x00" if method == 25 else b"\x20"
    eap_body = flags + record
    eap = bytes([2, 2]) + struct.pack(">H", 5 + len(eap_body)) + bytes([method]) + eap_body
    eapol = bytes([2, 0]) + struct.pack(">H", len(eap)) + eap
    return (_data_header(_mac(station), _mac(bssid), _mac(bssid), 0) + _llc_eapol(eapol))


def _eap_frame(station: str, bssid: str, code: int, eap_type: int, identifier: int,
               body: bytes) -> bytes:
    payload = bytes([code, identifier]) + struct.pack(">H", 5 + len(body)) \
        + bytes([eap_type]) + body
    eapol = bytes([2, 0]) + struct.pack(">H", len(payload)) + payload
    return (_data_header(_mac(station), _mac(bssid), _mac(bssid), 0) + _llc_eapol(eapol))


def build_mschapv2_exchange(station: str, bssid: str, username: str, password: str,
                            challenge: Optional[bytes] = None,
                            peer_challenge: Optional[bytes] = None,
                            identifier: int = 2) -> List[bytes]:
    """A real MS-CHAPv2 exchange: server challenge, then the client's response.

    The challenge and the 24-byte NT-Response are computed exactly as RFC 2759 says
    (see :mod:`wifipilot.netproto`), which is what makes the offline crack that reads
    this capture a genuine dictionary attack rather than a lookup of a value we stored.
    """
    from .netproto import mschapv2_response

    challenge = challenge or bytes(range(16))
    peer_challenge = peer_challenge or bytes(range(16, 32))
    # the MS-CHAPv2 packet inside the EAP type: Code, Identifier, MS-Length,
    # Value-Size, Value, Name (RFC 2759 §4 — the identifier is repeated here)
    def packet(code: int, value: bytes, name: bytes) -> bytes:
        return (bytes([code, identifier]) + struct.pack(">H", 5 + len(value) + len(name))
                + bytes([len(value)]) + value + name)

    response = (peer_challenge + b"\x00" * 8
                + mschapv2_response(password, challenge, peer_challenge, username)
                + b"\x00")
    # the Name field of the Response *is* the user name (RFC 2759 §4): an offline
    # reader that recomputes the ChallengeHash needs it to be the real one
    return [_eap_frame(bssid, station, 1, 26, identifier,
                       packet(1, challenge, b"MSCHAPv2")),
            _eap_frame(station, bssid, 2, 26, identifier,
                       packet(2, response, username.encode("latin-1")))]


def build_mschapv2_capture(path: str, essid: str = "CorpNet-8021X",
                           bssid: str = "34:c9:27:19:79:89",
                           station: str = "02:00:00:00:00:22",
                           username: str = "User", password: str = "clientPass",
                           challenge: Optional[bytes] = None,
                           peer_challenge: Optional[bytes] = None
                           ) -> Tuple[str, List[bytes], Dict[str, Any]]:
    """A capture holding one PEAP/MS-CHAPv2 authentication, plus its real material."""
    frames = [build_beacon(essid, bssid)]
    frames += build_mschapv2_exchange(station, bssid, username, password, challenge,
                                      peer_challenge)
    write_pcap(path, frames, spacing=0.01)
    auth_challenge = challenge or bytes(range(16))
    peer = peer_challenge or bytes(range(16, 32))
    from .netproto import mschapv2_response

    material = {
        "username": username, "challenge": auth_challenge.hex(),
        "peer_challenge": peer.hex(), "method": "MSCHAPv2",
        # the response is recomputed from the real password so an offline cracker has
        # a genuine target and a hit can be proved against it
        "response": mschapv2_response(password, auth_challenge, peer, username).hex(),
    }
    return str(path), frames, material


def build_ttls_pap_exchange(station: str, bssid: str, username: str, password: str,
                            number: int = 1) -> List[bytes]:
    """A TTLS tunnel carrying PAP: the credentials are inside, and printable.

    The AVP layout is the one RFC 2865 uses for RADIUS attributes, wrapped in the
    TTLS message header — which is why an attack that reads inside the tunnel can pull
    a username and a password out of a capture.
    """
    user_avp = bytes([0, 1]) + struct.pack(">H", 2 + len(username)) + username.encode()
    pass_avp = bytes([0, 2]) + struct.pack(">H", 2 + len(password)) + password.encode()
    inner = bytes([0, number]) + struct.pack(">H", 4 + len(user_avp) + len(pass_avp)) \
        + user_avp + pass_avp
    tls = bytes([0x17, 0x03, 0x03]) + struct.pack(">H", len(inner)) + inner
    return [_eap_frame(bssid, station, 1, 21, number, b"\x00" + tls)]


def build_ttls_capture(path: str, essid: str = "CorpNet-TTLS",
                       bssid: str = "34:c9:27:19:79:8b",
                       station: str = "02:00:00:00:00:23",
                       username: str = "alice", password: str = "Winter2026"
                       ) -> Tuple[str, List[bytes]]:
    frames = [build_beacon(essid, bssid)]
    frames += build_ttls_pap_exchange(station, bssid, username, password)
    write_pcap(path, frames, spacing=0.01)
    return str(path), frames


def build_enterprise_capture(path: str, essid: str = "CorpNet-8021X",
                             bssid: str = "34:c9:27:19:79:89",
                             station: str = "02:00:00:00:00:21",
                             identity: str = "jdoe@corp.example",
                             certificate: Optional[bytes] = None,
                             tls_version: int = 0x0301,
                             method: int = 25) -> Tuple[str, List[bytes]]:
    """A beacon plus an 802.1X exchange: identity, TLS hello and server certificate."""
    frames = [build_beacon(essid, bssid),
              build_eap_response_identity(station, bssid, identity),
              build_eap_tls_server_hello(station, bssid, version=tls_version,
                                         method=method),
              build_eap_tls_certificate(station, bssid,
                                        certificate or self_signed_certificate(),
                                        method=method)]
    write_pcap(path, frames, spacing=0.01)
    return str(path), frames


def build_data_frame(bssid: str, station: str, payload: bytes = b"",
                     to_ds: bool = False) -> bytes:
    """A plain 802.11 data frame (ARP/DHCP-like background traffic).

    The direction bits and the addresses have to agree: with ``to_ds`` clear this is
    the access point talking to a station (``addr1`` the station, ``addr2`` the AP),
    which is what a parser reading the DS bits expects.  Getting these backwards makes
    a frame that decodes as its own mirror image — a reversed client list.
    """
    body = payload or (b"\xaa\xaa\x03\x00\x00\x00\x08\x06" + bytes(28))
    if to_ds:
        return _data_header(_mac(station), _mac(bssid), _mac(bssid), 0, to_ds=True) + body
    return _data_header(_mac(bssid), _mac(station), _mac(bssid), 0, to_ds=False) + body


#: the WPA (not WPA2) vendor element and a WPS element, for the scenes and tests
WPA_VENDOR_OUI = b"\x00\x50\xf2"
#: the Wi-Fi Alliance OUI that carries WPS, WMM, Hotspot 2.0 and the rest
WFA_VENDOR_OUI = b"\x00\x50\xf2"

#: what a consumer AP's WPS element looks like: label, display, keypad and push button
#: all offered, device names filled in, not locked.  Built with the real element builder
#: rather than by hand — the hand-rolled version carried a configuration-methods
#: attribute with an attribute id that does not exist (0x0088 instead of 0x1012), which
#: is exactly the kind of thing a decoder has to be able to survive and an audit should
#: not be manufacturing.
WPS_VENDOR_IE = wps_element(version="2.0", methods=0x0188, locked=False,
                            manufacturer="Example Networks", model="EN-AP300",
                            model_number="v1.2", device_name="corp-ap-3f",
                            serial="EN300-0001")


def retry(frame: bytes) -> bytes:
    """The same frame with the retry bit set — what a repeat transmission looks like."""
    return frame[:1] + bytes([frame[1] | 0x08]) + frame[2:]


def fragment(frame: bytes, index: int = 1) -> bytes:
    """A frame carrying a fragment number (the low nibble of the sequence control)."""
    control = int.from_bytes(frame[22:24], "little")
    control = (control & 0xFFF0) | (index & 0x0F)
    return frame[:22] + struct.pack("<H", control) + frame[24:]


def bcast(frame: bytes) -> bytes:
    """A data frame addressed to the broadcast address (group traffic)."""
    return frame[:4] + b"\xff" * 6 + frame[10:]


def build_probe_response(ssid: str, bssid: str, station: str = "ff:ff:ff:ff:ff:ff",
                         channel: int = 6, extra_ies: bytes = b"",
                         include_rsn: bool = True, akm: str = "psk",
                         tsf: int = 0) -> bytes:
    """A probe response (subtype 5): the beacon body sent by request.

    The wildcard form of this frame — a zero-length SSID element sent to the broadcast
    address — is the fingerprint of an AP that answers *every* probe it hears, which is
    how a lure behaves.  It is built here so a capture of one can be audited.
    """
    ap = _mac(bssid)
    body = (struct.pack("<Q", tsf & 0xFFFFFFFFFFFFFFFF) + b"\x64\x00" + b"\x01\x04")
    ssid_bytes = ssid.encode()[:32]
    body += ie(0, ssid_bytes) + ie(1, MODERN_RATES) + ie(3, bytes([channel]))
    if include_rsn:
        body += rsn_element(akm)
    body += extra_ies
    return (b"\x50\x00\x00\x00" + _mac(station) + ap + ap + b"\x00\x00" + body)


def build_llc_data_frame(bssid: str, station: str, ethernet: bytes,
                         to_ds: bool = True, seq: int = 0) -> bytes:
    """An 802.11 data frame carrying an Ethernet payload, LLC/SNAP included.

    This is what a *network* payload looks like on a wireless capture: the 802.11 data
    header, then the eight-byte LLC/SNAP header (``aa aa 03 00 00 00`` and the
    ethertype), then the frame the wired side would have seen.  A parser that takes the
    body as-is reads the SNAP header as if it were ARP, which is why an analysis has to
    know the difference.
    """
    kind = int.from_bytes(ethernet[12:14], "big") if len(ethernet) >= 14 else 0x0800
    body = b"\xaa\xaa\x03\x00\x00\x00" + struct.pack(">H", kind) + ethernet[14:]
    return build_data_frame(bssid, station, body, to_ds=to_ds)




def build_network_scene(path: str, bssid: str = "aa:bb:cc:00:00:01",
                        gateway: str = "192.168.1.1", clients: int = 6,
                        rounds: int = 1, seed: int = 11) -> str:
    """A capture of everything that happens *above* the 802.11 layer.

    The wireless side of an assessment is mostly gossip; the findings live one layer up:
    a DHCP server handing out a second default gateway, a client that released an
    address it never held, a router that is not the one the network was configured
    with, an IPv6 prefix nobody assigned, a printer that answers PJL on port 9100.  This
    scene carries all of those as real frames — ARP, IPv4, ICMP, TCP, UDP, ICMPv6,
    spanning tree, LLDP — wrapped in 802.11 data frames, so the network-layer attacks
    have something real to read offline and something real to compare against on air.

    The scene is deterministic for a given ``seed``: the same capture every time, which
    is what makes a demo run reproducible.
    """
    from . import netproto
    from . import netstack as ns


    rng = random.Random(seed)
    frames: List[bytes] = []
    stations = ["02:00:00:00:%02x:%02x" % (index // 256, index % 256)
                for index in range(clients)]
    hosts = {station: f"192.168.{1 + index // 254}.{20 + index}"
             for index, station in enumerate(stations)}
    leases = {station: f"192.168.1.{100 + index}"
              for index, station in enumerate(stations)}

    def data(station: str, payload: bytes, to_ds: bool = True) -> None:
        frames.append(build_llc_data_frame(bssid, station, payload, to_ds=to_ds))

    def udp_frame(station: str, source: str, destination: str, sport: int, dport: int,
                  payload: bytes, to_ds: bool = True) -> None:
        data(station, ns.ethernet_frame(ns.BROADCAST,
                                        station, ns.ipv4_packet(
                                            source, destination, 17,
                                            ns.udp_packet(source, destination, sport,
                                                          dport, payload)), 0x0800),
             to_ds=to_ds)

    # -- DHCP: a discovery, an offer, a request, an acknowledgement, per client ----
    for station in stations:
        xid = rng.getrandbits(32)
        discover = netproto.dhcp_discover(station, xid=xid, hostname=f"ws-{station[-2:]}")
        udp_frame(station, "0.0.0.0", "255.255.255.255", netproto.DHCP_CLIENT_PORT,
                  netproto.DHCP_SERVER_PORT, discover)
        offer = netproto.dhcp_offer(station, leases[station], gateway, gateway,
                                    dns=[gateway], xid=xid)
        udp_frame(station, gateway, leases[station], netproto.DHCP_SERVER_PORT,
                  netproto.DHCP_CLIENT_PORT, offer, to_ds=False)
        request = netproto.dhcp_request(station, leases[station], gateway, xid=xid)
        udp_frame(station, "0.0.0.0", "255.255.255.255", netproto.DHCP_CLIENT_PORT,
                  netproto.DHCP_SERVER_PORT, request)
        ack = netproto.dhcp_offer(station, leases[station], gateway, gateway,
                                  dns=[gateway], xid=xid, message_type=5)
        udp_frame(station, gateway, leases[station], netproto.DHCP_SERVER_PORT,
                  netproto.DHCP_CLIENT_PORT, ack, to_ds=False)

    # -- a rogue server answering the same discoveries, with itself as the gateway --
    rogue = "192.168.1.66"
    for station in stations[:3]:
        offer = netproto.dhcp_offer(station, "192.168.1.200", rogue, rogue,
                                    dns=[rogue], lease=600, xid=rng.getrandbits(32))
        udp_frame(station, rogue, "255.255.255.255", netproto.DHCP_SERVER_PORT,
                  netproto.DHCP_CLIENT_PORT, offer, to_ds=False)

    # -- a starvation burst: many MACs, one address each, no follow-through --------
    for index in range(24):
        mac = f"02:0d:0d:{index:02x}:{rng.randrange(256):02x}:00"
        udp_frame(mac, "0.0.0.0", "255.255.255.255", netproto.DHCP_CLIENT_PORT,
                  netproto.DHCP_SERVER_PORT,
                  netproto.dhcp_discover(mac, xid=rng.getrandbits(32)))

    # -- forged RELEASE and DECLINE for the first client's lease ------------------
    victim = stations[0]
    release = netproto.dhcp_release(victim, leases[victim], gateway)
    udp_frame(victim, "0.0.0.0", gateway, netproto.DHCP_CLIENT_PORT,
              netproto.DHCP_SERVER_PORT, release)
    decline = netproto.dhcp_decline(victim, f"192.168.1.{200}", gateway)
    udp_frame(victim, "0.0.0.0", "255.255.255.255", netproto.DHCP_CLIENT_PORT,
              netproto.DHCP_SERVER_PORT, decline)

    # -- ARP: a scan, a poisoning burst, and gratuitous announcements -------------
    for host in range(1, 26):
        data(stations[1], ns.ethernet_frame(ns.BROADCAST, stations[1],
                                            ns.arp_packet(1, stations[1],
                                                          hosts[stations[1]],
                                                          "00:00:00:00:00:00",
                                                          gateway), 0x0806))
    for _ in range(12):
        data(stations[2], ns.ethernet_frame(ns.BROADCAST, "02:0d:0d:99:99:99",
                                            ns.arp_reply("02:0d:0d:99:99:99", gateway,
                                                         ns.BROADCAST, gateway), 0x0806))
    for station in stations[:4]:
        data(station, ns.ethernet_frame(ns.BROADCAST, station,
                                        ns.gratuitous_arp(station, leases[station]),
                                        0x0806))

    # -- ICMP: echo, a redirect at the gateway, an unreachable --------------------
    for index in range(4):
        station = stations[index % len(stations)]
        data(station, ns.ethernet_frame("aa:bb:cc:00:00:01", station,
                                        ns.ipv4_packet(hosts[station], gateway, 1,
                                                       ns.icmp_echo(0x1234, index + 1,
                                                                    b"wifipilot-probe")),
                                        0x0800))
    data(stations[3], ns.ethernet_frame(stations[3], bssid,
                                        ns.ipv4_packet(gateway, hosts[stations[3]], 1,
                                                       ns.icmp_redirect("192.168.1.66")),
                                        0x0800), to_ds=False)

    # -- TCP: a SYN flood, and one honest HTTP conversation ----------------------
    for index in range(40):
        source = f"10.66.{index % 4}.{index + 2}"
        data(stations[4], ns.ethernet_frame("aa:bb:cc:00:00:01", stations[4],
                                            ns.ipv4_packet(source, gateway, 6,
                                                           ns.tcp_packet(source, gateway,
                                                                         rng.randrange(1024,
                                                                                       65535),
                                                                         80,
                                                                         flags=ns.tcp_flags(
                                                                             syn=True))),
                                            0x0800))
    http = (b"GET /admin HTTP/1.1\r\nHost: 192.168.1.1\r\n"
            b"Authorization: Basic YWRtaW46YWRtaW4=\r\n\r\n")  # ggignore: synthetic packet fixture (base64 of the default admin:admin), not a real credential
    data(stations[5], ns.ethernet_frame("aa:bb:cc:00:00:01", stations[5],
                                        ns.ipv4_packet(hosts[stations[5]], gateway, 6,
                                                       ns.tcp_packet(hosts[stations[5]],
                                                                     gateway, 40001, 80,
                                                                     flags=ns.tcp_flags(
                                                                         psh=True, ack=True),
                                                                     payload=http)),
                                        0x0800))

    # -- UDP: a DNS query with a forged answer, LLMNR, NBNS, mDNS -----------------
    dns_payload = netproto.dns_query("intranet.corp.example")
    udp_frame(stations[0], hosts[stations[0]], gateway, 51000, 53, dns_payload)
    spoof = netproto.dns_response(dns_payload, [("intranet.corp.example", "192.168.1.66")])
    udp_frame(stations[0], gateway, hosts[stations[0]], 53, 51000, spoof, to_ds=False)
    udp_frame(stations[1], hosts[stations[1]], "224.0.0.252", 53500, 5355,
              ns.llmnr_query("fileserver"))
    udp_frame(stations[1], "192.168.1.66", hosts[stations[1]], 5355, 53500,
              ns.llmnr_response(ns.llmnr_query("fileserver"), rogue), to_ds=False)
    udp_frame(stations[2], hosts[stations[2]], "192.168.1.255", 137, 137,
              ns.nbns_query("FILESERVER"))
    udp_frame(stations[3], hosts[stations[3]], "224.0.0.251", 5353, 5353,
              ns.mdns_query("printer.local"))
    udp_frame(stations[3], rogue, "224.0.0.251", 5353, 5353,
              ns.mdns_response("printer.local", rogue), to_ds=False)
    for index in range(20):
        udp_frame(stations[4], f"10.66.0.{index + 2}", gateway, 4444, 1900,
                  netproto.ssdp_msearch("ssdp:all"))
    # the answers to those searches: two devices that describe themselves completely,
    # which is the whole reason SSDP is a census rather than a guess
    subnet = gateway.rsplit(".", 1)[0]
    for host, name, model, location in (
            (gateway, "router", "NETGEAR R7000", f"http://{gateway}:80/desc.xml"),
            (f"{subnet}.44", "nas", "Synology DS220+", f"http://{subnet}.44:5000/desc.xml"),
            (f"{subnet}.21", "printer", "HP LaserJet 1022", f"http://{subnet}.21:80/desc.xml")):
        for index in range(2):
            body = netproto.ssdp_notify(name=name, address=host, model=model,
                                       location=location, nt="upnp:rootdevice",
                                       usn=f"uuid:wifipilot-{name}-{index}")
            udp_frame(stations[1], host, netproto.SSDP_ADDRESS, 1900, 1900, body)

    # -- IPv6: a rogue router advertisement and a neighbour advertisement --------
    station = stations[0]
    data(station, ns.ethernet_frame("33:33:00:00:00:01", station,
                                    ns.ipv6_packet("fe80::66", ns.IPV6_MULTICAST_ALL_NODES,
                                                   58,
                                                   ns.icmpv6_router_advertisement(
                                                       router="fe80::66",
                                                       prefix="2001:db8:bad::",
                                                       dns=["2001:db8:bad::53"])),
                                    0x86DD), to_ds=False)
    data(station, ns.ethernet_frame("33:33:00:00:00:01", station,
                                    ns.ipv6_packet("fe80::66", ns.IPV6_MULTICAST_ALL_NODES,
                                                   58,
                                                   ns.icmpv6_neighbor_advertisement(
                                                       "2001:db8:bad::1", "2001:db8:bad::5",
                                                       "02:0d:0d:99:99:99",
                                                       router=True, solicited=False)),
                                    0x86DD))

    # -- spanning tree and neighbour discovery: forged topology ------------------
    for source in ("02:0d:0d:99:99:99", "02:0d:0d:99:99:98"):
        llc = ns.stp_configuration_bpdu("00:0d:0d:99:99:99", source, root_priority=0)
        frames.append(build_llc_data_frame(bssid, stations[0],
                                           ns.ethernet_frame(ns.STP_MULTICAST, source,
                                                             llc, len(llc)),
                                           to_ds=True))
    lldp = ns.lldp_packet("02:0d:0d:99:99:99", "Gi1/0/1", "core-switch-9",
                          management_ip="192.168.1.66")
    data(stations[0], lldp)

    # -- VLAN: a doubly tagged frame, the classic hopping primitive -------------
    inner = ns.ethernet_frame("ff:ff:ff:ff:ff:ff", "02:0d:0d:99:99:99",
                              ns.arp_packet(1, "02:0d:0d:99:99:99", "192.168.1.66",
                                            "00:00:00:00:00:00", "192.168.1.1"), 0x0806)
    tagged = (_mac(ns.BROADCAST) + _mac("02:0d:0d:99:99:99")
              + struct.pack(">H", 0x8100)                 # the outer tag a switch strips
              + ns.vlan_tag(1, inner=0x8100) + ns.vlan_tag(99, inner=0x0806) + inner[14:])
    data(stations[0], tagged)

    # -- cleartext credentials and device services --------------------------------
    telnet_login = (b"\xff\xfd\x18\xff\xfd\x20" + b"admin\r\n" + b"admin\r\n")
    data(stations[1], ns.ethernet_frame("aa:bb:cc:00:00:01", stations[1],
                                        ns.ipv4_packet(hosts[stations[1]], gateway, 6,
                                                       ns.tcp_packet(hosts[stations[1]],
                                                                     gateway, 40100, 23,
                                                                     flags=ns.tcp_flags(
                                                                         psh=True,
                                                                         ack=True),
                                                                     payload=telnet_login)),
                                        0x0800))
    mqtt = ns.mqtt_connect("meter-01", username="admin", password="admin")  # ggignore: synthetic packet fixture (default admin/admin), not a real credential
    data(stations[2], ns.ethernet_frame("aa:bb:cc:00:00:01", stations[2],
                                        ns.ipv4_packet(hosts[stations[2]], gateway, 6,
                                                       ns.tcp_packet(hosts[stations[2]],
                                                                     gateway, 40200, 1883,
                                                                     flags=ns.tcp_flags(
                                                                         psh=True, ack=True),
                                                                     payload=mqtt)),
                                        0x0800))
    rtsp = ns.rtsp_request("DESCRIBE", f"rtsp://{gateway}/stream1")
    data(stations[3], ns.ethernet_frame("aa:bb:cc:00:00:01", stations[3],
                                        ns.ipv4_packet(hosts[stations[3]], gateway, 6,
                                                       ns.tcp_packet(hosts[stations[3]],
                                                                     gateway, 40300, 554,
                                                                     flags=ns.tcp_flags(
                                                                         psh=True, ack=True),
                                                                     payload=rtsp)),
                                        0x0800))
    pjl = ns.pjl_job(("@PJL INFO ID", "@PJL INFO CONFIG"))
    data(stations[4], ns.ethernet_frame("aa:bb:cc:00:00:01", stations[4],
                                        ns.ipv4_packet(hosts[stations[4]], gateway, 6,
                                                       ns.tcp_packet(hosts[stations[4]],
                                                                     gateway, 40400, 9100,
                                                                     flags=ns.tcp_flags(
                                                                         psh=True, ack=True),
                                                                     payload=pjl)),
                                        0x0800))
    snmp_req = netproto.snmp_get("public", ["1.3.6.1.2.1.1.5.0"])
    udp_frame(stations[5], hosts[stations[5]], gateway, 41600, 161, snmp_req)

    write_pcap(path, frames, spacing=0.01)
    return str(path)


def build_bt_scene(path: str, seconds: float = 20.0, seed: int = 7,
                   base_time: float = 1_700_000_000.0) -> str:
    """A Bluetooth Low Energy capture of a floor of devices.

    Ten devices, each with its own advertising interval and its own idea of privacy: a
    beacon in a doorway that never changes its address, a tracker that rotates its own on
    every report, a sensor that transmits twenty times a second, a keyboard that only
    names itself when asked, and a phone that connects and pairs with its Just Works
    default.  The capture is written as ``LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR`` — the
    format BLE analysis starts from — so the Bluetooth attacks read a real capture rather
    than a description of one.

    The device list is the point: one device is trackable and one is not, one names its
    manufacturer and one says nothing about itself, two carry a beacon payload and three
    carry a service.  Every audit in the Bluetooth wave has something real to find.
    """
    from . import bt

    records: List[bytes] = []
    times: List[float] = []

    def emit(moment: float, pdu: bytes, channel: int, rssi: int,
             access_address: bytes = b"") -> None:
        records.append(bt.le_wrapper(pdu, channel=channel, rssi=rssi,
                                     access_address=access_address))
        times.append(base_time + moment)

    devices = [
        # an iBeacon in a doorway: mains-powered, so a fixed address and a fixed identity.
        # Its advertising payload is 27 bytes, which leaves room for flags and nothing
        # else — a name would be a scan response at best, and usually there is none.
        {"address": "c4:3b:2a:11:00:01", "interval": 500.0, "pdu": 0x00, "channel": 37,
         "rssi": -60,
         "structures": [bt.ad_flags(le_general=True),
                        bt.ibeacon("8ec76ea3-1d1c-4f1a-9b7a-3c2f5d0a7711", 1, 17, -59)]},
        # an Eddystone-URL on a shopfront: the URL, and only the URL
        {"address": "e1:22:33:44:55:66", "interval": 1000.0, "pdu": 0x02, "channel": 38,
         "rssi": -72,
         "structures": [bt.ad_flags(), bt.ad_service_uuids([0xFEAA]),
                        bt.eddystone_url("shop.example", 0x00, scheme=0x03)]},
        # a tracker: a resolvable private address that changes on every single report
        {"address": "", "rotate": True, "interval": 2000.0, "pdu": 0x00, "channel": 39,
         "rssi": -78,
         "structures": [bt.ad_flags(), bt.ad_manufacturer(0x004C, b"\x12\x19\x00")]},
        # a heart-rate strap: a service UUID and the measured power that goes with it
        {"address": "d4:11:22:33:44:55", "interval": 1000.0, "pdu": 0x00, "channel": 37,
         "rssi": -66,
         "structures": [bt.ad_flags(), bt.ad_name("HRM-Dual"), bt.ad_tx_power(-60),
                        bt.ad_service_uuids([0x180D])]},
        # a sensor that transmits twenty times a second: an interval no phone uses, and
        # the reason its battery lasts a week instead of a year
        {"address": "f0:de:11:22:33:44", "interval": 20.0, "pdu": 0x02, "channel": 38,
         "rssi": -55,
         "structures": [bt.ad_flags(), bt.ad_manufacturer(0x0059, b"\x61\x01\x02")]},
        # a keyboard that advertises a flag, and names itself only when scanned
        {"address": "2c:54:33:22:11:00", "interval": 1000.0, "pdu": 0x00, "channel": 39,
         "rssi": -70, "scan_response": True,
         "structures": [bt.ad_flags()],
         "scan_structures": [bt.ad_flags(), bt.ad_name("KBD-1C2B")]},
        # a fitness band: an incomplete name, a battery service, and connectable
        {"address": "aa:bb:cc:dd:ee:ff", "interval": 800.0, "pdu": 0x00, "channel": 37,
         "rssi": -74,
         "structures": [bt.ad_flags(), bt.ad_name("Fit-Band", complete=False),
                        bt.ad_service_uuids([0x180F])]},
        # a device with nothing to say: a manufacturer field and no name at all
        {"address": "11:22:33:44:55:66", "interval": 1500.0, "pdu": 0x01, "channel": 38,
         "rssi": -80,
         "structures": [bt.ad_manufacturer(0x0075, b"\x42\x00\x01")]},
        # a printer: a name and the Device Information service
        {"address": "9c:32:1a:44:55:66", "interval": 700.0, "pdu": 0x00, "channel": 39,
         "rssi": -63,
         "structures": [bt.ad_flags(), bt.ad_name("PRN-4B2C"),
                        bt.ad_service_uuids([0x180A])]},
        # a weight scale: a vendor service and a slow interval
        {"address": "6b:22:99:44:11:77", "interval": 1200.0, "pdu": 0x02, "channel": 37,
         "rssi": -69,
         "structures": [bt.ad_flags(), bt.ad_manufacturer(0x0006, b"\x0a\x0b\x0c")]},
    ]

    rng = random.Random(seed)
    for index, device in enumerate(devices):
        interval = float(device["interval"]) / 1000.0
        moment = rng.random() * 0.05
        step = 0
        while moment < seconds:
            address = device["address"]
            if device.get("rotate"):
                # a resolvable private address: it changes on every report, and only the
                # holder of the identity key can link the next one to the last
                address = bt.resolvable_private_address(
                    bytes([index & 0xFF, step & 0xFF, seed & 0xFF, 0x5A]), seed=step)
            payload = bt.adv_payload(*device["structures"])
            pdu = bt.adv_pdu(int(device["pdu"]), address, payload)
            rssi = int(device["rssi"]) + ((step * 7 + index) % 5) - 2
            emit(moment, pdu, int(device["channel"]), rssi)
            if device.get("scan_response") and step % 4 == 1:
                response = bt.adv_pdu(0x04, address,
                                      bt.adv_payload(*device["scan_structures"]))
                emit(moment + 0.002, response, int(device["channel"]), rssi)
            moment += interval
            step += 1

    # -- the phone that trusts the keyboard, and everything the two then say ------- #
    # a connection has its own access address; the link layer, L2CAP, ATT and the
    # security manager sit on top of it, and each of them is readable from the capture
    link = bytes([0x4B, 0x1C, 0x2B, 0x00])
    phone = "2c:54:33:22:11:00"
    moment = (max(times) - base_time if times else seconds) + 0.25

    def data(llid: int, payload: bytes, when: float, channel: int = 37) -> None:
        header = bytes([llid & 0x03, len(payload) & 0x1F])
        emit(when, link + header + payload, channel, -64, access_address=link)

    def l2cap(cid: int, body: bytes) -> bytes:
        return struct.pack("<HH", len(body), cid) + body

    # the CONNECT_IND that starts it: an advertising-channel PDU naming both ends
    emit(moment - 0.05,
         bt.adv_pdu(0x05, phone,
                    link + bytes([0x18, 0x00]) + (0x0006).to_bytes(2, "little")
                    + (0x0000).to_bytes(2, "little") + (0x0018).to_bytes(2, "little")
                    + (0x01A0).to_bytes(2, "little")
                    + (0xFFFFFFFF1F).to_bytes(5, "little") + bytes([0x25]),
                    ch_sel=False, peer_address="2c:54:33:22:11:00"),
         37, -64)
    # the feature exchange: what the two ends claim they can do
    features = (1 << 0) | (1 << 4) | (1 << 5) | (1 << 8) | (1 << 14)
    data(3, bytes([0x09]) + features.to_bytes(8, "little"), moment)   # LL_FEATURE_RSP
    # the pairing request: Just Works, no MITM, no Secure Connections — the finding
    data(2, l2cap(0x0006, bytes([0x01, 0x03, 0x00, 0x00, 0x10, 0x0F, 0x0F])), moment + 0.02)
    # an ATT read of the primary services, and the answer that names them
    data(2, l2cap(0x0004, bytes([0x10, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28])), moment + 0.04)
    # Read By Group Type Response: the length byte is the size of *one* entry, and each
    # entry is a start handle, an end handle and the 16-bit service UUID
    data(2, l2cap(0x0004,
                  bytes([0x11, 0x06, 0x01, 0x00, 0x0A, 0x00, 0x00, 0x18,
                         0x0B, 0x00, 0x0E, 0x00, 0x0F, 0x18])), moment + 0.06)
    # the encryption request that starts the link's encryption
    # LL_ENC_REQ: Rand (8), EDIV (2), SKDm (8) and IVm (4) — the start of
    # the encryption setup an analyst reads to see the link become encrypted
    data(3, bytes([0x03]) + bytes(range(8)) + b"\x00\x00"
         + bytes(range(8, 16)) + bytes(4), moment + 0.08)

    bt.write_le_pcap(path, records, times=times)
    return str(path)



def build_scene(path: str, aps: int = 6, clients: int = 10, rounds: int = 400,
                seed: int = 7) -> str:
    """A mixed capture with the shapes an analyst's parser has to survive.

    Real airodump-ng output is dominated by beacons and background traffic, so a
    capture made only of handshakes measures the wrong thing.  This scene carries:
    hidden and named networks, an overlapping-channel pair, a WPA3 transition-mode
    network, a WPA one (so the old element decoder has work), a clone of a named
    network with a beacon rate and a timestamp that give it away, directed and
    wildcard probe requests, open-system and shared-key authentication exchanges,
    association responses both accepted and refused, QoS and power-save data,
    retransmissions and a duplicated sequence number, a fragment, ARP traffic
    including a gratuitous reply, DHCP, SA Query action frames, EAPOL handshakes at
    both key descriptor versions, an EAPOL-Logoff, and a deauthentication burst.

    Everything is built by the same builders the attacks use, so a reader that finds
    something here would find it on air.
    """
    rng = random.Random(seed)
    frames: List[bytes] = []

    # -- the networks ------------------------------------------------------- #
    networks: List[Tuple[str, str, int, str, bool, bytes]] = []
    for index in range(max(7, aps)):        # index 6 is the 802.11k/v/r AP
        bssid = "aa:bb:cc:%02x:%02x:%02x" % (index, index * 3 % 256, index * 7 % 256)
        if index == 0:
            # a hidden network still beacons: no name, but rates, channel and RSN
            networks.append((bssid, "", 1, "psk", False, b""))
        elif index == 1:
            networks.append((bssid, f"Scene-{index}", 1, "psk", False,
                             country_element("IN", 1, 13, max_power=20)
                             + ht_capabilities(width40=True, streams=2)))
        elif index == 2:
            networks.append((bssid, f"Scene-{index}", 11, "sae+psk", False,
                             country_element("DE", 36, 4, max_power=23)
                             + ht_capabilities() + vht_capabilities()
                             + he_capabilities()))
        elif index == 3:
            networks.append((bssid, f"Scene-{index}", 6, "sae", True,
                             extended_capabilities(bss_transition=True, wnm_sleep=True,
                                                   coexistence=True)
                             + rm_enabled_capabilities()
                             + neighbour_report_element([("aa:bb:cc:00:00:00", 81, 1),
                                                         ("aa:bb:cc:05:0f:23", 81, 6)])
                             + bss_load_element(21, 148, 2400)))
        elif index == 4:
            # a WPA-era AP: the legacy WPA vendor element, not an RSN one — and a
            # hotspot, because that is what a "Guest" SSID with a portal always is
            networks.append((bssid, f"Scene-{index}", 6, "psk", False,
                             ie(221, WPA_VENDOR_OUI + b"\x01\x00")
                             + interworking_element(network_type=2, internet=True)
                             + hs20_element(release=3, anqp_domain=0x0bad)))
        elif index == 5:
            # a network still running TKIP in its RSN element, 2020s or not — and
            # offering both pairwise ciphers, so a client can be walked down to TKIP
            networks.append((bssid, f"Scene-{index}", 1 + index % 11, "psk", False,
                             mobility_domain(b"\x12\x34", over_ds=True)
                             + wmm_parameter_element(acm_voice=True)))
        elif index == 6:
            # an AP that does 802.11k/v/r: it will hand over a client, and it will
            # answer a neighbour report request with the BSSIDs around it
            networks.append((bssid, f"Scene-{index}", 1 + index % 11, "psk", False,
                             extended_capabilities(bss_transition=True, wnm_sleep=True)
                             + rm_enabled_capabilities()
                             + neighbour_report_element([("aa:bb:cc:00:00:00", 81, 1),
                                                         ("aa:bb:cc:02:06:0e", 81, 11)])
                             + mobility_domain(b"\x12\x34")
                             + bss_load_element(station_count=14, utilisation=141)
                             + wmm_parameter_element(acm_voice=True)
                             + WPS_VENDOR_IE))
        else:
            networks.append((bssid, f"Scene-{index}", 1 + index % 11, "psk", False,
                             WPS_VENDOR_IE))
    clone_bssid = "aa:bb:cc:99:99:99"
    # the name each network is known by: a hidden network hides its name in its beacons
    # only, and the client that connects to it still asks for it by name
    public_names = {bssid: (name or "Hidden-Corp") for bssid, name, *_rest in networks}
    tsf_base = int(time.time() * 1_000_000)
    tsf_clone = tsf_base - 9_000_000                 # nine seconds behind, and frozen
    stations = ["02:00:00:00:%02x:%02x" % (index // 256, index % 256)
                for index in range(clients)]
    stray_names = ["HomeNet-4F2A", "Corp-WiFi", "eduroam", "HP-Print-42"]

    # -- the traffic -------------------------------------------------------- #
    for round_index in range(rounds):
        for index, (bssid, ssid, channel, akm, pmf, extra) in enumerate(networks):
            # the timestamp has to track the capture clock, not the round number: an AP
            # whose beacon clock runs at 1.0x real time is what a TSF audit expects to
            # measure, and a synthetic 60ms-per-round clock is what makes it cry wolf
            frames.append(build_beacon(ssid, bssid, channel=channel,
                                       include_rsn=True, akm=akm, pmf=pmf,
                                       extra_ies=extra, tkip=index == 5))
        if round_index % 50 == 0:                        # the clone answers a probe
            frames.append(build_probe_response("", clone_bssid, extra_ies=WPS_VENDOR_IE))
        if round_index % 90 == 0 and networks:           # a beacon cut short by the capture
            frames.append(build_beacon("Scene-3", networks[-1][0], channel=1,
                                       extra_ies=WPS_VENDOR_IE + ie(221, bytes(180)))[:-48])
        if round_index % 2 == 0:
            # the clone: twice the beacon rate, a *frozen* clock, its own element set —
            # the two things a replayed beacon cannot fake
            # the clone upgrades the security *claim* of the network it copies: a
            # client that prefers WPA3 picks it, and the name now exists at two
            # security levels on the same channel
            frames.append(build_beacon("Scene-1", clone_bssid, channel=1, akm="sae",
                                       pmf=True, extra_ies=WPS_VENDOR_IE))
        for station in rng.sample(stations, k=min(len(stations), max(1, clients // 4))):
            name = rng.choice(stray_names)
            frames.append(build_probe_request(station, name))
            if round_index % 4 == 0:
                # an AP that hears its own name answers the station that asked
                frames.append(build_probe_response(name, networks[1][0], station=station,
                                                   channel=1))
            if rng.random() < 0.4:
                frames.append(build_probe_request(station, ""))
        for index in range(max(1, clients // 5)):        # background traffic
            bssid = rng.choice(networks)[0]
            station = rng.choice(stations)
            frames.append(build_data_frame(bssid, station))
            if index % 2 == 0:
                frames.append(build_qos_data_frame(bssid, station,
                                                   tid=index % 8,
                                                   power_save=index % 3 == 0))
            if index % 5 == 0:                       # a retransmission, as seen on air
                frames.append(retry(build_data_frame(bssid, station)))
            if index % 7 == 0:                       # a second fragment
                frames.append(fragment(build_data_frame(bssid, station), 1))
        if round_index % 12 == 0:                        # association paperwork
            bssid = networks[round_index % len(networks)][0]
            station = rng.choice(stations)
            frames.append(build_auth_frame(bssid, station, algorithm=0, sequence=1))
            frames.append(build_auth_frame(bssid, station, algorithm=0, sequence=2))
            # a real client's association request carries what the client can do:
            # HT for anything made this decade, and about a third of the estate here
            # is the old hardware that has to be planned around
            frames.append(build_assoc_request(bssid, station,
                                              public_names.get(bssid, "Scene"),
                                              extra_ies=(ht_capabilities(width40=True)
                                                         if station.endswith("1")
                                                         else b"")))
            frames.append(build_assoc_response(bssid, station,
                                               status=0 if round_index % 24 else 17))
        if round_index % 30 == 0:
            bssid = networks[1][0]                  # a shared-key WEP challenge
            station = rng.choice(stations)
            frames.append(build_auth_frame(bssid, station, algorithm=1, sequence=1,
                                           status=0))
            frames.append(build_auth_frame(bssid, station, algorithm=1, sequence=2,
                                           status=0))
        if round_index % 20 == 0:                        # ARP: request and a gratuitous reply
            bssid, station = networks[1][0], rng.choice(stations)
            frames.append(build_arp_frame(bssid, station, op=1,
                                          sender_ip="192.168.1.20",
                                          target_ip="192.168.1.1"))
            frames.append(build_arp_frame(bssid, station, op=2,
                                          sender_ip="192.168.1.1",
                                          target_ip="192.168.1.1"))
            frames.append(bcast(build_arp_frame(bssid, station, op=1,
                                                sender_ip="192.168.1.20",
                                                target_ip="255.255.255.255")))
        if round_index % 40 == 0:                        # DHCP
            bssid, station = networks[1][0], rng.choice(stations)
            frames.extend(build_dhcp_frames(bssid, station))
        if round_index % 25 == 0:                        # an occasional handshake
            bssid, ssid = networks[round_index % len(networks)][:2]
            if ssid:
                handshake, _ = build_handshake_frames(
                    ssid, bssid, rng.choice(stations), "ScenePassword1",
                    kdv=1 if round_index % 50 == 0 else KDV_SHA1)
                frames.extend(handshake)
        if round_index % 60 == 0 and len(networks) > 3:
            bssid = networks[3][0]                  # SA Query: PMF at work
            station = rng.choice(stations)
            frames.append(build_action_frame(bssid, station, category=8, action=0,
                                             payload=bytes([round_index & 0xFF, 0x01])))
            frames.append(build_action_frame(bssid, station, category=8, action=1,
                                             payload=bytes([round_index & 0xFF, 0x01]),
                                             station_is_source=True))
        if round_index % 80 == 0:                        # somebody logging off
            bssid, station = networks[1][0], rng.choice(stations)
            frames.append(build_eapol_logoff(bssid, station))
        if round_index == rounds // 2:                   # a deauthentication burst
            bssid = networks[1][0]
            frames.extend(build_deauth_flood(bssid, rounds=24, broadcast=True))
        if round_index == rounds // 2 + 3 and len(networks) == 6:
            # and the Michael countermeasure firing: reason 15 (MIC failure) followed
            # by reason 16 (the BSS shutting down for a minute)
            bssid = networks[5][0]
            frames.extend(build_deauth_flood(bssid, rounds=6, broadcast=True, reason=15))
            frames.extend(build_deauth_flood(bssid, rounds=4, broadcast=True, reason=16))
        if round_index % 15 == 0:                        # a fragment and a retry
            bssid, station = networks[1][0], rng.choice(stations)
            frames.append(fragment(build_data_frame(bssid, station), 1))
            frames.append(retry(build_data_frame(bssid, station)))
        if round_index % 45 == 0:                        # an ARP sweep of the subnet
            bssid, station = networks[1][0], rng.choice(stations)
            for host in range(1, 10):
                frames.append(build_arp_frame(bssid, station, op=1,
                                              sender_ip="192.168.1.20",
                                              target_ip=f"192.168.1.{host}"))
        # the battery-powered half of the estate talks almost only in power save
        for sleepy in stations[-2:]:
            frames.append(build_qos_data_frame(networks[1][0], sleepy, tid=5,
                                               power_save=True))
        if round_index % 70 == 0:                        # an authentication flood
            flooder = "02:00:00:00:ff:ff"               # never associates, ever
            for sequence in range(8):
                frames.append(build_auth_frame(networks[1][0], flooder, algorithm=0,
                                               sequence=1 + sequence % 3))
    # a real capture interleaves frames far slower than once a millisecond: at 10 ms a
    # frame this scene is 30-odd seconds of air, which puts beacons at the ~8/s a 100 TU
    # interval actually produces instead of at a rate no AP could reach
    spacing = 0.01
    frames = clock_beacons(frames, tsf_base, spacing_us=int(spacing * 1_000_000),
                           frozen_bssid=clone_bssid, frozen_tsf=tsf_clone)
    write_pcap(path, frames, spacing=spacing)
    return path


def clock_beacons(frames: List[bytes], tsf_base: int = 0, spacing_us: int = 10_000,
                  frozen_bssid: str = "", frozen_tsf: int = 0) -> List[bytes]:
    """Give every beacon a TSF that matches the moment it was transmitted.

    A beacon carries the access point's own clock, and that clock is what a client uses
    to decide whether the access point is still there: a beacon whose timestamp does not
    advance is either a replay or a clone.  The scene therefore has to write a *moving*
    TSF into every frame it emits — and leave the clone's frozen, which is exactly the
    evidence the timestamp-clone detection looks for.
    """
    frozen = _mac(frozen_bssid) if frozen_bssid else b""
    out: List[bytes] = []
    for index, frame in enumerate(frames):
        if not frame or (frame[0] >> 4) != 8 or len(frame) < 32:      # not a beacon
            out.append(frame)
            continue
        if frozen and frame[16:22] == frozen:
            # the clone's clock is frozen nine seconds behind: its beacons look exactly
            # like a replay of the real access point, which is what the detection finds
            out.append(frame[:24] + struct.pack("<Q", frozen_tsf) + frame[32:])
            continue
        tsf = (tsf_base + index * spacing_us) & 0xFFFFFFFFFFFFFFFF
        out.append(frame[:24] + struct.pack("<Q", tsf) + frame[32:])
    return out


def build_qos_data_frame(bssid: str, station: str, tid: int = 0,
                         power_save: bool = False, payload: bytes = b"") -> bytes:
    """A QoS data frame (subtype 8) with a traffic identifier and a power-save bit."""
    body = payload or (b"\xaa\xaa\x03\x00\x00\x00\x08\x00" + bytes(28))
    flags = 0x01 | (0x10 if power_save else 0x00)         # to-DS, plus power management
    header = (bytes([0x88, flags]) + b"\x00\x00" + _mac(bssid) + _mac(station)
              + _mac(bssid) + b"\x00\x00" + struct.pack("<H", tid & 0x0F))
    return header + body


def build_auth_frame(bssid: str, station: str, algorithm: int = 0, sequence: int = 1,
                     status: int = 0, from_ap: bool = False) -> bytes:
    """An authentication frame (algorithm, sequence, status) in either direction."""
    transmitter, receiver = (bssid, station) if from_ap else (station, bssid)
    body = (struct.pack("<HHH", algorithm, sequence, status))
    return (b"\xb0\x00" + b"\x00\x00" + _mac(receiver) + _mac(transmitter)
            + _mac(bssid) + b"\x00\x00" + body)


def build_assoc_request(bssid: str, station: str, ssid: str,
                        extra_ies: bytes = b"") -> bytes:
    """An association request carrying its SSID, rates and whatever else the client has.

    ``extra_ies`` is where a real client puts its HT/VHT/HE capabilities: a station
    that sends an association request with no HT element at all is 802.11g-era
    hardware, and that is a finding about the estate rather than about the frame.
    """
    body = (b"\x31\x04" + b"\x0a\x00"          # capability, listen interval
            + ie(0, ssid.encode()[:32]) + ie(1, MODERN_RATES) + bytes(extra_ies))
    return (b"\x00\x00" + b"\x00\x00" + _mac(bssid) + _mac(station) + _mac(bssid)
            + b"\x00\x00" + body)


def build_assoc_response(bssid: str, station: str, status: int = 0,
                         association_id: int = 1) -> bytes:
    """An association response with a status code: ``0`` accepted, anything else refused."""
    body = b"\x31\x04" + struct.pack("<H", status) + struct.pack("<H", association_id) \
        + ie(1, MODERN_RATES)
    return (b"\x10\x00" + b"\x00\x00" + _mac(station) + _mac(bssid) + _mac(bssid)
            + b"\x00\x00" + body)


def build_arp_frame(bssid: str, station: str, op: int = 1, sender_ip: str = "192.168.1.20",
                    target_ip: str = "192.168.1.1", sender_mac: str = "",
                    target_mac: str = "") -> bytes:
    """An ARP frame over the WLAN: the Ethernet ARP layout inside an 802.11 data frame."""
    import socket as _socket

    sender_mac = sender_mac or station
    target_mac = target_mac or ("00:00:00:00:00:00" if op == 1 else bssid)
    arp = (b"\x00\x01\x08\x00\x06\x04" + struct.pack(">H", op)
           + _mac(sender_mac) + _socket.inet_aton(sender_ip)
           + _mac(target_mac) + _socket.inet_aton(target_ip))
    return _data_header(_mac(station), _mac(bssid), _mac(bssid), 0) \
        + b"\xaa\xaa\x03\x00\x00\x00\x08\x06" + arp


def build_dhcp_frames(bssid: str, station: str, hostname: str = "laptop",
                      offered_ip: str = "192.168.1.50") -> List[bytes]:
    """A DHCP discover and the offer it draws, over the WLAN."""
    from .netproto import DHCP_CLIENT_PORT, DHCP_SERVER_PORT, dhcp_discover, dhcp_offer, \
        ipv4_udp_packet

    discover = dhcp_discover(station, hostname=hostname, requested_ip=offered_ip)
    offer = dhcp_offer(station, offered_ip, "192.168.1.1", "192.168.1.1",
                       dns=["192.168.1.1"], hostname=hostname)
    out = []
    out.append(_data_header(_mac(station), _mac(bssid), _mac(bssid), 0)
               + b"\xaa\xaa\x03\x00\x00\x00\x08\x00"
               + ipv4_udp_packet("0.0.0.0", "255.255.255.255", DHCP_CLIENT_PORT,
                                 DHCP_SERVER_PORT, discover))
    out.append(_data_header(_mac(bssid), _mac(station), _mac(bssid), 0, to_ds=False)
               + b"\xaa\xaa\x03\x00\x00\x00\x08\x00"
               + ipv4_udp_packet("192.168.1.1", offered_ip, DHCP_SERVER_PORT,
                                 DHCP_CLIENT_PORT, offer))
    return out


def build_action_frame(bssid: str, station: str, category: int = 0, action: int = 0,
                       payload: bytes = b"", station_is_source: bool = False) -> bytes:
    """A management action frame without the radiotap header (capture form)."""
    transmitter, receiver = ((station, bssid) if station_is_source else (bssid, station))
    return (b"\xd0\x00" + b"\x00\x00" + _mac(receiver) + _mac(transmitter)
            + _mac(bssid) + b"\x00\x00" + bytes([category, action]) + payload)


def build_eapol_logoff(bssid: str, station: str) -> bytes:
    """An EAPOL-Logoff frame: type 2, no body, unauthenticated by design."""
    eapol = b"\x02\x02\x00\x00"
    return _data_header(_mac(station), _mac(bssid), _mac(bssid), 0) + _llc_eapol(eapol)


def build_capture(path: str, ssid: str, bssid: str, station: str, password: str,
                  seed: Optional[int] = None, include_pmkid: bool = True,
                  include_handshake: bool = True,
                  kdv: int = KDV_SHA1) -> Tuple[str, str]:
    """Write a valid capture. Returns (path, pmkid).

    ``kdv`` is the Key Descriptor Version the frames claim (see
    :func:`build_handshake_frames`)."""
    frames: List[bytes] = []
    pmkid = ""
    if include_handshake:
        frames, pmkid = build_handshake_frames(ssid, bssid, station, password, seed,
                                               include_pmkid=include_pmkid,
                                               kdv=kdv)
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
