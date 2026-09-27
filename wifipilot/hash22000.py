"""hashcat mode 22000 hashes: read them, write them, crack them.

Mode 22000 is the format people actually pass around: it is text, it carries
both PMKIDs and EAPOL message pairs, and every capture tool emits it.  wifipilot
should not need hashcat — or hcxtools — to work with it, so this module reads
and writes it in pure Python::

    WPA*01*PMKID*MAC_AP*MAC_STA*ESSID***MESSAGEPAIR
    WPA*02*MIC*MAC_AP*MAC_STA*ESSID*NONCE*EAPOL*MESSAGEPAIR

* every field is hex; ``ESSID`` is the SSID *bytes*, so a network whose name is
  not valid UTF-8 survives a round trip;
* ``NONCE`` is whichever nonce is not in the EAPOL frame (the ANonce when the
  frame is M2/M4, the SNonce when it is M3), and both nonces are the ones the
  PTK is derived from;
* ``MESSAGEPAIR`` is the bitmask hashcat documents: bits 0-2 the message pair
  (000 = M1+M2 with the MIC from M2, 010 = M2+M3 with the MIC from M2, ...),
  bit 4 "ap-less", bits 5/6 the AP nonce byte order, bit 7 "nonce correction
  was needed".  Verification does not depend on it, but it is preserved.

Reading a hash file gives :class:`HashLine` objects and, from them, the same
verifiers the capture path uses — so ``wifipilot crack handshake.hc22000``
proves a password with the MIC, exactly like cracking the capture would.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .crypto import HandshakeVerifier, PmkidVerifier, key_descriptor_version, mic_algorithms
from .pcap import CaptureAnalysis, eapol_frame, mac, parse_eapol_frame

#: file suffixes that are mode 22000 rather than a capture
HASH_SUFFIXES = (".hc22000", ".22000")

#: message pair bitmask bits (hashcat wiki, "cracking WPA/WPA2 with hashcat")
MP_PAIR_MASK = 0x07
MP_AP_LESS = 0x10
MP_LE = 0x20
MP_BE = 0x40
MP_NC = 0x80

PAIR_LABELS = {
    0b000: "M1+M2 (challenge, EAPOL from M2)",
    0b001: "M1+M4 (EAPOL from M4)",
    0b010: "M2+M3 (authorized, EAPOL from M2)",
    0b011: "M2+M3 (authorized, EAPOL from M3)",
    0b100: "M3+M4 (EAPOL from M3)",
    0b101: "M3+M4 (EAPOL from M4)",
}


def is_hash_file(path: str) -> bool:
    """Is ``path`` a mode 22000 hash file?"""
    return str(path).lower().endswith(HASH_SUFFIXES)


@dataclass
class HashLine:
    """One hashcat mode 22000 line."""

    kind: str                       # "pmkid" | "eapol"
    bssid: str = ""
    station: str = ""
    essid: str = ""                 # decoded for display
    essid_bytes: bytes = b""        # ...and exact, for PBKDF2
    pmkid: str = ""                 # kind == "pmkid"
    mic: bytes = b""                # kind == "eapol"
    nonce: bytes = b""              # the nonce *not* inside the EAPOL frame
    eapol: bytes = b""              # EAPOL-Key frame, MIC zeroed
    message_pair: int = 0
    key_descriptor: int = 0         # Key Descriptor Version (see crypto.mic_algorithms)
    message: int = 0                # 1..4, for EAPOL lines
    raw: str = ""

    # -- descriptions --------------------------------------------------- #
    @property
    def pair_label(self) -> str:
        return PAIR_LABELS.get(self.message_pair & MP_PAIR_MASK, "unknown pair")

    @property
    def authorized(self) -> bool:
        """Was the handshake completed (M2+M3, M3+M4) rather than challenged?"""
        return (self.message_pair & MP_PAIR_MASK) in (0b010, 0b011, 0b100, 0b101)

    @property
    def ap_less(self) -> bool:
        return bool(self.message_pair & MP_AP_LESS)

    @property
    def ap(self) -> str:
        return self.bssid

    @property
    def mic_algorithm(self) -> str:
        """The MIC algorithm the line's Key Descriptor Version implies."""
        return "+".join(mic_algorithms(self.key_descriptor))

    @property
    def label(self) -> str:
        name = self.essid or self.bssid
        if self.kind == "pmkid":
            return f"PMKID {name}"
        return f"M{self.message} {name} ({self.pair_label})"

    def nonces(self) -> Tuple[bytes, bytes]:
        """``(anonce, snonce)`` as far as the line allows.

        The frame carries one nonce, the extra field the other; a zeroed field
        means the hash cannot be verified (hashcat calls those "unbreakable")
        and is reported as such rather than guessed at.
        """
        inside = self.eapol[17:49] if len(self.eapol) >= 49 else b""
        outside = self.nonce
        if not inside or not any(inside):
            return b"", b""
        if not outside or not any(outside):
            return b"", b""
        if self.message == 3:                     # frame is AP -> STA
            return inside, outside
        return outside, inside                    # frame is STA -> AP (M2/M4)

    @property
    def verifiable(self) -> bool:
        """Can this line be checked at all? (hashcat calls the others unbreakable.)"""
        if self.kind == "pmkid":
            return len(self.pmkid) == 32 and bool(self.essid_bytes) and len(self.bssid) == 17
        anonce, snonce = self.nonces()
        return bool(len(self.mic) == 16 and len(self.eapol) >= 97
                    and len(anonce) == 32 and len(snonce) == 32
                    and len(self.bssid) == 17 and len(self.station) == 17)

    def to_dict(self) -> Dict[str, object]:
        return {
            "kind": self.kind, "bssid": self.bssid, "station": self.station,
            "essid": self.essid or self.essid_bytes.hex(), "message": self.message,
            "pmkid": self.pmkid, "mic": self.mic.hex(),
            "message_pair": self.message_pair, "pair": self.pair_label,
            "authorized": self.authorized, "ap_less": self.ap_less,
            "verifiable": self.verifiable, "eapol_bytes": len(self.eapol),
            "key_descriptor_version": self.key_descriptor,
            "mic_algorithm": self.mic_algorithm,
        }


# --------------------------------------------------------------------------- #
# reading
# --------------------------------------------------------------------------- #


def _mac(value: str) -> str:
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return ""
    return mac(raw) if len(raw) == 6 else ""


def _hex_bytes(value: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError:
        return b""


def _decode_essid(raw: bytes) -> str:
    for encoding in ("utf-8", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.hex()


def parse_line(text: str) -> Tuple[Optional[HashLine], str]:
    """``(line, problem)`` — exactly one of the two is set."""
    text = text.strip()
    if not text:
        return None, ""
    if text.startswith("#"):
        return None, ""
    fields = text.split("*")
    if len(fields) < 6 or fields[0].upper() != "WPA":
        return None, "not a WPA* hash line"
    kind_code = fields[1]
    if kind_code in ("03", "04"):
        return None, "802.11r (FT) hash lines are not supported"
    if kind_code not in ("01", "02"):
        return None, f"unknown hash type WPA*{kind_code}"
    while len(fields) < 9:
        fields.append("")
    _, _, hash_field, mac_ap, mac_sta, essid_hex, nonce, eapol_hex, mp = fields[:9]

    essid_bytes = _hex_bytes(essid_hex)
    line = HashLine(
        kind="pmkid" if kind_code == "01" else "eapol",
        bssid=_mac(mac_ap), station=_mac(mac_sta) or "ff:ff:ff:ff:ff:ff",
        essid=_decode_essid(essid_bytes), essid_bytes=essid_bytes,
        message_pair=int(mp, 16) if len(mp) == 2 and _is_hex(mp) else 0,
        nonce=_hex_bytes(nonce), raw=text,
    )
    if not line.essid_bytes:
        return None, "hash line without an ESSID cannot be verified"
    if not line.bssid:
        return None, f"bad AP MAC {mac_ap!r}"
    if line.kind == "pmkid":
        line.pmkid = hash_field.lower()
        if len(line.pmkid) != 32 or not _is_hex(line.pmkid):
            return None, f"bad PMKID {hash_field!r}"
        return line, ""
    line.mic = _hex_bytes(hash_field)
    line.eapol = _hex_bytes(eapol_hex)
    if len(line.mic) != 16:
        return None, f"bad MIC {hash_field!r}"
    if len(line.eapol) < 97:
        return None, "truncated EAPOL frame"
    line.key_descriptor = key_descriptor_version(line.eapol)
    parsed = parse_eapol_frame(line.eapol)
    if parsed:
        line.message = parsed["number"]
    return line, ""


def _is_hex(value: str) -> bool:
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def parse_text(text: str) -> Tuple[List[HashLine], List[str]]:
    """``(lines, problems)`` for a whole hash file."""
    lines: List[HashLine] = []
    problems: List[str] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line, problem = parse_line(raw)
        if line is not None:
            lines.append(line)
        elif problem:
            problems.append(f"line {number}: {problem}")
    return lines, problems


def parse_file(path: str) -> List[HashLine]:
    """Every usable hash line in a mode 22000 file (problems are dropped)."""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return parse_text(text)[0]


def prepare(path: str) -> Tuple[List[HashLine], List[object]]:
    """``(lines, verifiers)`` — the verifiers are the ones the cracker uses."""
    lines = parse_file(path)
    return lines, verifiers(lines)


def verifiers(lines: Sequence[HashLine]) -> List[object]:
    """Verifiers for every line this build can actually check.

    A hash file is not a capture: an M4-based pair whose nonce was zeroed on air
    cannot be verified by anyone, so those lines are left out instead of being
    counted as failures.
    """
    out: List[object] = []
    for line in lines:
        if line.kind == "pmkid":
            verifier = PmkidVerifier(line.pmkid, line.essid_bytes, line.bssid, line.station)
            if verifier.usable:
                out.append(verifier)
            continue
        anonce, snonce = line.nonces()
        if not (line.mic and anonce and snonce):
            continue
        verifier = HandshakeVerifier.from_eapol(
            line.eapol, line.essid_bytes, line.bssid, line.station,
            anonce, snonce, mic=line.mic, key_descriptor=line.key_descriptor)
        if verifier.usable:
            out.append(verifier)
    return out


# --------------------------------------------------------------------------- #
# writing
# --------------------------------------------------------------------------- #


def message_pair(handshake, number: int) -> int:
    """The message-pair byte for the frame we are exporting."""
    has_m1 = 1 in handshake.messages
    if number == 2:
        return 0x00 if has_m1 else 0x02          # M1+M2 / M2+M3, MIC from M2
    if number == 4:
        return 0x01 if has_m1 else 0x05          # M1+M4 / M3+M4, MIC from M4
    return 0x00


def line_from_message(handshake, message, essid: str = "") -> Optional[str]:
    """Build the ``WPA*02`` line for one stored EAPOL message."""
    if not message.mic or len(message.raw) < 16:
        return None
    frame = eapol_frame(message)
    if len(frame) < 97:
        return None
    anonce = handshake.messages.get(1) or handshake.messages.get(3)
    nonce = anonce.nonce if anonce else ""
    if not nonce and message.number != 3:
        return None
    essid_bytes = essid.encode("utf-8", "replace") if essid else b""
    if not essid_bytes:
        return None
    zeroed = frame[:81] + bytes(16) + frame[97:]
    return "*".join((
        "WPA", "02", message.mic.hex(), handshake.bssid.replace(":", ""),
        handshake.station.replace(":", ""), essid_bytes.hex(), nonce, zeroed.hex(),
        "%02x" % message_pair(handshake, message.number),
    ))


def line_from_pmkid(bssid: str, station: str, essid: str, pmkid: str) -> Optional[str]:
    """Build the ``WPA*01`` line for one PMKID."""
    if not pmkid or not essid:
        return None
    essid_bytes = essid.encode("utf-8", "replace") if isinstance(essid, str) else bytes(essid)
    return "*".join(("WPA", "01", pmkid.lower(), bssid.replace(":", ""),
                     (station or "ff:ff:ff:ff:ff:ff").replace(":", ""),
                     essid_bytes.hex(), "", "", "02"))


def lines_from_analysis(analysis: CaptureAnalysis, include_pmkid: bool = True,
                        include_eapol: bool = True) -> List[str]:
    """Every hash a capture holds, as mode 22000 lines (best handshake first)."""
    out: List[str] = []
    seen_pmkid = set()
    if include_pmkid:
        for handshake in analysis.pmkids:
            if handshake.pmkid in seen_pmkid:
                continue
            seen_pmkid.add(handshake.pmkid)
            line = line_from_pmkid(handshake.bssid, handshake.station,
                                   analysis.essids.get(handshake.bssid, ""),
                                   handshake.pmkid)
            if line:
                out.append(line)
    if include_eapol:
        for handshake in analysis.crackable_handshakes():
            message = handshake.mic_message
            if message is None:
                continue
            essid = analysis.essids.get(handshake.bssid, "")
            line = line_from_message(handshake, message, essid)
            if line:
                out.append(line)
    return out


def write_lines(lines: Sequence[str], path: str) -> str:
    """Write lines to ``path`` (one per line, trailing newline)."""
    target = Path(path)
    if target.parent and str(target.parent):
        target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("".join(line + "\n" for line in lines), encoding="utf-8")
    return str(target)


def write_capture(capture: str, path: str = "", include_pmkid: bool = True,
                  include_eapol: bool = True) -> Tuple[str, int]:
    """Convert a capture to a mode 22000 hash file; ``(path, line count)``."""
    from .pcap import analyze_file
    analysis = analyze_file(str(capture))
    lines = lines_from_analysis(analysis, include_pmkid, include_eapol)
    target = path or (os.path.splitext(str(capture))[0] + ".hc22000")
    return write_lines(lines, target), len(lines)


# --------------------------------------------------------------------------- #
# describing
# --------------------------------------------------------------------------- #


def summary(lines: Sequence[HashLine], problems: Sequence[str] = ()) -> Dict[str, object]:
    """A small picture of a hash file (what ``analyze`` prints)."""
    pmkids = [line for line in lines if line.kind == "pmkid"]
    eapol = [line for line in lines if line.kind == "eapol"]
    pairs: Dict[str, int] = {}
    for line in eapol:
        pairs[line.pair_label] = pairs.get(line.pair_label, 0) + 1
    return {
        "lines": len(lines), "pmkid": len(pmkids), "eapol": len(eapol),
        "verifiable": sum(1 for line in lines if line.verifiable),
        "authorized": sum(1 for line in lines if line.authorized),
        "ap_less": sum(1 for line in lines if line.ap_less),
        "pairs": pairs,
        "essids": sorted({line.essid or line.essid_bytes.hex() for line in lines}),
        "bssids": sorted({line.bssid for line in lines}),
        "problems": list(problems),
    }
