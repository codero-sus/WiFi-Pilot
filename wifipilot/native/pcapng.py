# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Zero-copy pcap / pcapng writer and packet logger used by native engines.

The existing ``wifipilot.pcap`` module already reads pcap/pcapng; this writer
is specialised for live capture (ring-buffered, no copy, append-to-file in
real time so kills don't lose handshakes). It does NOT re-implement parsing.

Two output paths:
* ``PcapWriter`` — classic pcap (24-byte global header, 16-byte per-packet
  record, linktype 127 = radiotap). This is the format airodump-ng writes;
  aircrack-ng, hashcat, tshark, and wifipilot itself all read it.
* ``RingCapture`` — in-memory ring of the last N seconds of packets, to keep
  a post-handshake buffer around for evidence without filling the disk.
"""
from __future__ import annotations

import os
import struct
import threading
import time
from typing import Iterable, List, Optional

PCAP_MAGIC = 0xa1b2c3d4
PCAP_MAJOR = 2
PCAP_MINOR = 4
LINKTYPE_IEEE802_11_RADIOTAP = 127


def _write_pcap_header(f) -> None:
    # magic, major, minor, thiszone, sigfigs, snaplen, network
    f.write(struct.pack("<IHHiIII", PCAP_MAGIC, PCAP_MAJOR, PCAP_MINOR, 0, 0,
                        65535, LINKTYPE_IEEE802_11_RADIOTAP))


class PcapWriter:
    def __init__(self, path: str, append: bool = False, snaplen: int = 65535):
        self.path = path
        self.snaplen = snaplen
        self._f = None
        self._lock = threading.Lock()
        if append and os.path.exists(path) and os.path.getsize(path) > 24:
            self._f = open(path, "ab")
        else:
            d = os.path.dirname(path)
            if d: os.makedirs(d, exist_ok=True)
            self._f = open(path, "wb")
            _write_pcap_header(self._f)
            self._f.flush()

    def write(self, packet: bytes, ts: Optional[float] = None) -> None:
        if self._f is None: return
        if ts is None: ts = time.time()
        sec = int(ts); usec = int((ts - sec) * 1_000_000)
        orig_len = len(packet)
        cap_len = min(orig_len, self.snaplen)
        rec = struct.pack("<IIII", sec, usec, cap_len, orig_len)
        with self._lock:
            try:
                self._f.write(rec + packet[:cap_len])
            except OSError:
                pass

    def write_batch(self, packets: Iterable[bytes], ts: Optional[float] = None) -> None:
        if ts is None: ts = time.time()
        sec = int(ts); usec = int((ts - sec) * 1_000_000)
        parts: List[bytes] = []
        for p in packets:
            orig = len(p); cap = min(orig, self.snaplen)
            parts.append(struct.pack("<IIII", sec, usec, cap, orig))
            parts.append(p[:cap])
        with self._lock:
            try:
                self._f.write(b"".join(parts))
            except OSError:
                pass

    def flush(self) -> None:
        if self._f:
            with contextlib.suppress(OSError): self._f.flush()

    def close(self) -> None:
        if self._f:
            with contextlib.suppress(OSError): self._f.close()
            self._f = None

    def __enter__(self): return self
    def __exit__(self, *a): self.close()


class RingCapture:
    """Bounded in-memory ring of the last ``seconds`` seconds of packets."""

    def __init__(self, seconds: float = 30.0, max_packets: int = 50000):
        self.seconds = seconds
        self.max_packets = max_packets
        self._buf: List[tuple] = []   # (ts, packet)
        self._lock = threading.Lock()

    def add(self, packet: bytes, ts: Optional[float] = None) -> None:
        if ts is None: ts = time.time()
        with self._lock:
            self._buf.append((ts, packet))
            # Trim old packets
            cutoff = ts - self.seconds
            while self._buf and self._buf[0][0] < cutoff:
                self._buf.pop(0)
            if len(self._buf) > self.max_packets:
                del self._buf[:len(self._buf) - self.max_packets]

    def snapshot(self, since: Optional[float] = None) -> List[bytes]:
        with self._lock:
            if since is None:
                return [p for _, p in self._buf]
            return [p for ts, p in self._buf if ts >= since]

    def flush_to(self, writer: PcapWriter) -> int:
        pkts = self.snapshot()
        for p in pkts:
            writer.write(p)
        return len(pkts)

    def __len__(self) -> int:
        with self._lock: return len(self._buf)


import contextlib
