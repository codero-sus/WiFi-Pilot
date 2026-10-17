# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Thread-safe publish/subscribe event bus.

Every part of wifipilot talks to the UI through this bus: the CLI renders it,
the web UI streams it over a WebSocket, and the session journal persists it.
Publishing must never raise and must never block, no matter which thread the
event came from.
"""

from __future__ import annotations

import itertools
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

from .util import append_jsonl, now_iso

# --------------------------------------------------------------------------- #
# event kinds (single source of truth for the front-end)
# --------------------------------------------------------------------------- #


class EK:
    SESSION_START = "session.start"
    SESSION_END = "session.end"
    SESSION_INFO = "session.info"
    STATE = "state"                      # full UI snapshot
    NOTE = "note"
    LOG = "log"
    WARNING = "warning"
    ERROR = "error"

    SCAN_START = "scan.start"
    SCAN_STOP = "scan.stop"
    SCAN_STATS = "scan.stats"
    AP_NEW = "ap.new"
    AP_UPDATE = "ap.update"
    AP_LOST = "ap.lost"
    CLIENT_NEW = "client.new"

    ATTACK_START = "attack.start"
    ATTACK_PROGRESS = "attack.progress"
    ATTACK_END = "attack.end"
    CAPTURE_NEW = "capture.new"
    CAPTURE_PROGRESS = "capture.progress"
    DEAUTH = "deauth"

    CRACK_START = "crack.start"
    CRACK_PROGRESS = "crack.progress"
    CRACK_FOUND = "crack.found"
    CRACK_END = "crack.end"

    ADVISOR_THINKING = "advisor.thinking"
    ADVISOR_TOKEN = "advisor.token"
    ADVISOR_PLAN = "advisor.plan"
    ADVISOR_CHAT = "advisor.chat"
    ADVISOR_STATUS = "advisor.status"
    ADVISOR_ERROR = "advisor.error"
    ADVISOR_COST = "advisor.cost"

    FINDING = "finding"
    TOOL_STATUS = "tool.status"
    INTERFACE = "interface"

    #: kinds that are persisted to the journal by default (chatty ones are not)
    JOURNALED = {
        SESSION_START, SESSION_END, SESSION_INFO, AP_NEW, ATTACK_START, ATTACK_END,
        CAPTURE_NEW, CRACK_START, CRACK_FOUND, CRACK_END, ADVISOR_PLAN,
        ADVISOR_CHAT, ADVISOR_COST, FINDING, WARNING, ERROR, INTERFACE,
    }


@dataclass
class Event:
    kind: str
    data: Dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)
    source: str = "core"
    seq: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seq": self.seq, "kind": self.kind, "data": self.data,
            "ts": self.ts, "time": time.strftime("%H:%M:%S", time.localtime(self.ts)),
            "iso": now_iso(), "source": self.source,
        }


class Subscription:
    """A queue-backed view of the bus; safe to read from any thread."""

    def __init__(self, bus: "EventBus", kinds: Optional[Sequence[str]] = None, maxsize: int = 2000):
        self.bus = bus
        self.kinds = set(kinds) if kinds else None
        self.queue: "queue.Queue[Event]" = queue.Queue(maxsize=maxsize)
        self.dropped = 0
        self.closed = False

    def _matches(self, event: Event) -> bool:
        return self.kinds is None or event.kind in self.kinds

    def feed(self, event: Event) -> None:
        if self.closed or not self._matches(event):
            return
        try:
            self.queue.put_nowait(event)
        except queue.Full:
            self.dropped += 1
            # drop the oldest event so the UI always ends up current
            try:
                self.queue.get_nowait()
                self.queue.put_nowait(event)
            except queue.Empty:
                pass

    def get(self, timeout: Optional[float] = None) -> Optional[Event]:
        try:
            if timeout is None:
                return self.queue.get_nowait()
            return self.queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def drain(self, limit: int = 200) -> List[Event]:
        out: List[Event] = []
        while len(out) < limit:
            event = self.get()
            if event is None:
                break
            out.append(event)
        return out

    def close(self) -> None:
        self.closed = True
        self.bus.unsubscribe(self)

    def __enter__(self) -> "Subscription":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class EventBus:
    """Fan-out bus with a ring buffer of recent events."""

    def __init__(self, journal_path: Optional[str] = None, history: int = 500,
                 echo: Optional[Callable[[str], None]] = None):
        self._subs: List[Subscription] = []
        self._lock = threading.RLock()
        self._counter = itertools.count(1)
        self._recent: List[Event] = []
        self.history_size = history
        self.journal_path = journal_path
        self.echo = echo
        self.counts: Dict[str, int] = {}

    # -- subscription ------------------------------------------------------
    def subscribe(self, kinds: Optional[Sequence[str]] = None, maxsize: int = 2000) -> Subscription:
        sub = Subscription(self, kinds, maxsize)
        with self._lock:
            self._subs.append(sub)
        return sub

    def unsubscribe(self, sub: Subscription) -> None:
        with self._lock:
            if sub in self._subs:
                self._subs.remove(sub)

    @property
    def subscribers(self) -> int:
        with self._lock:
            return len(self._subs)

    # -- publishing --------------------------------------------------------
    def publish(self, kind: str, data: Optional[Dict[str, Any]] = None, source: str = "core",
                **kwargs: Any) -> Event:
        payload = dict(data or {})
        payload.update(kwargs)
        event = Event(kind=kind, data=payload, source=source, ts=time.time(),
                      seq=next(self._counter))
        with self._lock:
            self.counts[kind] = self.counts.get(kind, 0) + 1
            self._recent.append(event)
            if len(self._recent) > self.history_size:
                del self._recent[: len(self._recent) - self.history_size]
            subs = list(self._subs)
        for sub in subs:
            try:
                sub.feed(event)
            except Exception:  # pragma: no cover - never let a bad subscriber break the run
                pass
        if self.journal_path and (kind in EK.JOURNALED or kind == EK.LOG):
            append_jsonl(self.journal_path, event.to_dict())
        if self.echo is not None:
            try:
                self.echo(kind)
            except Exception:
                pass
        return event

    # -- convenience -------------------------------------------------------
    def log(self, message: str, level: str = "info", **extra: Any) -> Event:
        return self.publish(EK.LOG, {"message": message, "level": level, **extra})

    def warn(self, message: str, **extra: Any) -> Event:
        return self.publish(EK.WARNING, {"message": message, **extra})

    def error(self, message: str, **extra: Any) -> Event:
        return self.publish(EK.ERROR, {"message": message, **extra})

    def finding(self, kind: str, title: str, detail: str = "", severity: str = "info",
                bssid: str = "", source: str = "core") -> Event:
        return self.publish(EK.FINDING, {
            "kind": kind, "title": title, "detail": detail,
            "severity": severity, "bssid": bssid, "source": source,
        })

    # -- history -----------------------------------------------------------
    def recent(self, limit: int = 100, kinds: Optional[Iterable[str]] = None) -> List[Event]:
        wanted = set(kinds) if kinds else None
        with self._lock:
            events = [e for e in self._recent if wanted is None or e.kind in wanted]
        return events[-limit:]

    def since(self, seq: int, limit: int = 1000) -> List[Event]:
        with self._lock:
            return [e for e in self._recent if e.seq > seq][-limit:]

    @property
    def last_seq(self) -> int:
        with self._lock:
            return self._recent[-1].seq if self._recent else 0

    def clear(self) -> None:
        with self._lock:
            self._recent.clear()
            self.counts.clear()

    def close(self) -> None:
        with self._lock:
            subs = list(self._subs)
            self._subs.clear()
        for sub in subs:
            sub.closed = True
