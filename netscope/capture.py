"""Thread-safe, Streamlit-independent live packet capture controller."""

from __future__ import annotations

import queue
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from scapy.all import AsyncSniffer, conf, get_if_list

from .models import PacketRecord
from .parser import normalize_packet


class CaptureError(RuntimeError):
    """Friendly live-capture lifecycle failure."""


@dataclass(frozen=True, slots=True)
class CaptureSnapshot:
    """Immutable status view safe for display by the UI thread."""

    state: str
    interface: str | None
    duration_seconds: float
    retained_records: int
    queued_records: int
    dropped_queue: int
    dropped_retention: int
    parse_errors: int
    error: str | None


@dataclass(frozen=True, slots=True)
class InterfaceInfo:
    """Capture interface identifier and professor-friendly label."""

    identifier: str
    label: str


def list_interfaces() -> list[InterfaceInfo]:
    """Enumerate Scapy interfaces without starting a capture."""

    interfaces: list[InterfaceInfo] = []
    seen: set[str] = set()
    try:
        candidates = list(conf.ifaces.values())
    except Exception:
        candidates = []
    for candidate in candidates:
        identifier = str(getattr(candidate, "network_name", None) or getattr(candidate, "name", "")).strip()
        if not identifier or identifier in seen:
            continue
        seen.add(identifier)
        name = str(getattr(candidate, "name", identifier))
        description = str(getattr(candidate, "description", "") or "")
        ip = str(getattr(candidate, "ip", "") or "")
        details = " · ".join(part for part in (description, ip) if part and part != name)
        label = f"{name} — {details}" if details else name
        interfaces.append(InterfaceInfo(identifier, label))
    if not interfaces:
        try:
            interfaces = [InterfaceInfo(name, name) for name in get_if_list()]
        except Exception:
            return []
    return sorted(interfaces, key=lambda item: item.label.lower())


class CaptureController:
    """Own one stoppable sniffer, bounded queue, and bounded retained records."""

    def __init__(
        self,
        *,
        queue_size: int = 1_000,
        max_retained: int = 5_000,
        sniffer_factory: Callable[..., Any] = AsyncSniffer,
    ) -> None:
        if queue_size < 1 or max_retained < 1:
            raise ValueError("queue_size and max_retained must be positive")
        self._queue: queue.Queue[PacketRecord] = queue.Queue(maxsize=queue_size)
        self._retained: deque[PacketRecord] = deque(maxlen=max_retained)
        self._sniffer_factory = sniffer_factory
        self._sniffer: Any | None = None
        self._lock = threading.RLock()
        self._state = "idle"
        self._interface: str | None = None
        self._error: str | None = None
        self._next_packet_id = 1
        self._dropped_queue = 0
        self._dropped_retention = 0
        self._parse_errors = 0
        self._start_monotonic: float | None = None
        self._duration_at_stop = 0.0

    def _on_packet(self, packet: Any) -> None:
        with self._lock:
            packet_id = self._next_packet_id
            self._next_packet_id += 1
        try:
            record = normalize_packet(packet, packet_id)
        except Exception:
            with self._lock:
                self._parse_errors += 1
            return
        try:
            self._queue.put_nowait(record)
        except queue.Full:
            with self._lock:
                self._dropped_queue += 1

    def start(self, interface: str) -> None:
        """Start one authorized capture; reject duplicate starts."""

        if not interface:
            raise CaptureError("Select a network interface before starting capture.")
        with self._lock:
            if self._state in {"starting", "capturing"}:
                raise CaptureError("A capture is already running for this session.")
            self._state = "starting"
            self._interface = interface
            self._error = None
            self._duration_at_stop = 0.0
            self._start_monotonic = time.monotonic()
        try:
            sniffer = self._sniffer_factory(iface=interface, prn=self._on_packet, store=False)
            self._sniffer = sniffer
            sniffer.start()
        except Exception as exc:
            message = self._friendly_error(exc)
            with self._lock:
                self._state = "error"
                self._error = message
                self._sniffer = None
                self._start_monotonic = None
            raise CaptureError(message) from exc
        with self._lock:
            self._state = "capturing"

    def stop(self) -> None:
        """Stop safely; stopping while idle is intentionally harmless."""

        with self._lock:
            if self._state not in {"starting", "capturing"}:
                return
            sniffer = self._sniffer
            if self._start_monotonic is not None:
                self._duration_at_stop = max(0.0, time.monotonic() - self._start_monotonic)
            self._state = "stopping"
        try:
            if sniffer is not None:
                sniffer.stop(join=True)
        except Exception as exc:
            message = self._friendly_error(exc)
            with self._lock:
                self._error = message
                self._state = "error"
                self._sniffer = None
            raise CaptureError(message) from exc
        with self._lock:
            self._state = "stopped"
            self._sniffer = None
            self._start_monotonic = None

    def drain(self, max_items: int = 1_000) -> list[PacketRecord]:
        """Move up to ``max_items`` queued records into bounded retention."""

        if max_items < 1:
            return []
        drained = []
        for _ in range(max_items):
            try:
                record = self._queue.get_nowait()
            except queue.Empty:
                break
            with self._lock:
                if len(self._retained) == self._retained.maxlen:
                    self._dropped_retention += 1
                self._retained.append(record)
            drained.append(record)
        return drained

    def records(self) -> tuple[PacketRecord, ...]:
        """Return a stable snapshot of retained normalized records."""

        with self._lock:
            return tuple(self._retained)

    def status(self) -> CaptureSnapshot:
        """Return current status without exposing mutable controller state."""

        with self._lock:
            duration = self._duration_at_stop
            if self._state in {"starting", "capturing", "stopping"} and self._start_monotonic is not None:
                duration = max(0.0, time.monotonic() - self._start_monotonic)
            return CaptureSnapshot(
                state=self._state,
                interface=self._interface,
                duration_seconds=duration,
                retained_records=len(self._retained),
                queued_records=self._queue.qsize(),
                dropped_queue=self._dropped_queue,
                dropped_retention=self._dropped_retention,
                parse_errors=self._parse_errors,
                error=self._error,
            )

    def clear(self) -> None:
        """Stop capture and discard this session's live metadata."""

        self.stop()
        with self._lock:
            self._retained.clear()
            while True:
                try:
                    self._queue.get_nowait()
                except queue.Empty:
                    break
            self._next_packet_id = 1
            self._dropped_queue = 0
            self._dropped_retention = 0
            self._parse_errors = 0
            self._duration_at_stop = 0.0
            self._interface = None
            self._error = None
            self._state = "idle"

    @staticmethod
    def _friendly_error(exc: Exception) -> str:
        details = str(exc).strip() or exc.__class__.__name__
        return (
            "Live capture is unavailable on this machine or interface. "
            "On Windows install/enable Npcap and use appropriate privileges; on Linux verify capture privileges and libpcap. "
            f"Details: {details}"
        )
