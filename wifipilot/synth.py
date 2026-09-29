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


def build_beacon(ssid: str, bssid: str, channel: int = 6, include_rsn: bool = True,
                 akm: str = "psk", pmf: bool = False) -> bytes:
    """A well-formed 802.11 beacon, for capture-shape benchmarks and tests.

    ``akm`` selects the AKM suites in the RSN element (``psk``, ``sae``,
    ``sae+psk`` for transition mode, ``owe``, ``802.1x``) and ``pmf`` sets the
    MFPC/MFPR bits, because the WPA3 audit reads exactly those two fields.
    """
    ap = _mac(bssid)
    ssid_bytes = ssid.encode()[:32]
    body = (b"\x80\x00\x00\x00" + b"\xff" * 6 + ap + ap + b"\x00\x00"
            + bytes(8)                                        # timestamp
            + b"\x64\x00"                                    # beacon interval
            + b"\x01\x04")                                   # capability: ESS + privacy
    if include_rsn:
        body += b"\x00" + bytes([len(ssid_bytes)]) + ssid_bytes
        body += b"\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24"    # rates
        body += b"\x03\x01" + bytes([channel])                          # DS parameter
        body += rsn_element(akm, pmf=pmf)
    else:
        body += b"\x00\x00"                                            # hidden SSID
    return body


def build_probe_request(station: str, ssid: str = "", bssid: str = "ff:ff:ff:ff:ff:ff"
                        ) -> bytes:
    """A probe request: ``ssid=""`` is the wildcard ("is anything out there?").

    Clients send these in the clear, including on WPA3 networks, which is why a
    passive capture can map a client's preferred network list without any
    injection at all.
    """
    sta = _mac(station)
    body = (b"\x00" * 8                       # timestamp
            + b"\x64\x00"                    # beacon interval
            + b"\x04\x01")                   # capability: privacy
    ssid_bytes = ssid.encode()[:32]
    body += b"\x00" + bytes([len(ssid_bytes)]) + ssid_bytes
    body += b"\x01\x04\x82\x84\x8b\x96"     # rates
    return b"\x40\x00\x00\x00" + b"\xff" * 6 + sta + _mac(bssid) + b"\x00\x00" + body


def build_deauth(bssid: str, station: str = "ff:ff:ff:ff:ff:ff", reason: int = 7
                 ) -> bytes:
    """A deauthentication frame (subtype 12), the frame an attack is made of."""
    return (b"\xc0\x00\x00\x00" + _mac(station) + _mac(bssid) + _mac(bssid)
            + b"\x00\x00" + bytes([reason, 0]))


def build_deauth_flood(bssid: str, rounds: int = 40, broadcast: bool = True) -> List[bytes]:
    """A burst of deauth frames — enough of them for ``sniff.attack_frames``."""
    frames: List[bytes] = []
    for _ in range(max(1, rounds)):
        frames.append(build_deauth(bssid, "ff:ff:ff:ff:ff:ff" if broadcast
                                   else random_mac(locally_administered=True)))
    return frames


#: AKM suite selector bytes (little-endian 4-byte selectors 00-0f-ac-XX)
_AKM_CODES = {"802.1x": 1, "psk": 2, "ft-802.1x": 3, "ft-psk": 4, "psk-sha256": 6,
              "sae": 8, "ft-sae": 9, "owe": 18, "sae-ext": 24}


def rsn_element(akm: str = "psk", pmf: bool = False, pairwise: int = 4,
                group: int = 4) -> bytes:
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
    body = (bytes([1, 0])                          # RSN version 1
            + bytes([group, 0, 0, 0])              # group cipher: CCMP
            + bytes([1, 0]) + bytes([pairwise, 0, 0, 0])
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


def build_enterprise_capture(path: str, essid: str = "CorpNet-8021X",
                             bssid: str = "34:c9:27:19:79:89",
                             station: str = "02:00:00:00:00:21",
                             identity: str = "jdoe@corp.example",
                             certificate: Optional[bytes] = None) -> Tuple[str, List[bytes]]:
    """A beacon plus an 802.1X exchange: identity response and server certificate."""
    frames = [build_beacon(essid, bssid),
              build_eap_response_identity(station, bssid, identity),
              build_eap_tls_certificate(station, bssid,
                                        certificate or self_signed_certificate())]
    write_pcap(path, frames, spacing=0.01)
    return str(path), frames


def build_data_frame(bssid: str, station: str, payload: bytes = b"") -> bytes:
    """A plain 802.11 data frame (ARP/DHCP-like background traffic)."""
    body = payload or (b"\xaa\xaa\x03\x00\x00\x00\x08\x06" + bytes(28))
    return _data_header(_mac(bssid), _mac(station), _mac(bssid), 0) + body


def build_scene(path: str, aps: int = 6, clients: int = 10, rounds: int = 400,
                seed: int = 7) -> str:
    """A realistic mixed capture: mostly beacons, some data, occasional EAPOL.

    Real airodump-ng output is dominated by beacons and background traffic; a
    capture made only of handshakes measures the wrong thing.
    """
    rng = random.Random(seed)
    networks = []
    for index in range(aps):
        bssid = "aa:bb:cc:%02x:%02x:%02x" % (index, index * 3 % 256, index * 7 % 256)
        ssid = f"Scene-{index}" if index % 4 else ""
        networks.append((bssid, ssid))
    stations = ["02:00:00:00:%02x:%02x" % (index // 256, index % 256) for index in range(clients)]
    frames: List[bytes] = []
    for round_index in range(rounds):
        for bssid, ssid in networks:                 # the bulk: beacons
            frames.append(build_beacon(ssid, bssid, channel=1 + round_index % 11,
                                       include_rsn=bool(ssid)))
        for index in range(max(1, clients // 5)):    # background traffic
            frames.append(build_data_frame(rng.choice(networks)[0], rng.choice(stations)))
        if round_index % 25 == 0:                    # an occasional handshake
            bssid, ssid = networks[round_index % len(networks)]
            handshake, _ = build_handshake_frames(ssid or "Scene", bssid,
                                                  rng.choice(stations), "ScenePassword1")
            frames.extend(handshake)
    write_pcap(path, frames)
    return path


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
