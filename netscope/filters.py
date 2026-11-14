"""Pure, non-mutating packet filtering functions."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from .models import PacketRecord


@dataclass(frozen=True, slots=True)
class PacketFilters:
    """Filter values used consistently by every dashboard output."""

    protocol: str = "All"
    src_ip: str = ""
    dst_ip: str = ""
    ip_match: str = "Contains"
    either_port: int | None = None
    keyword: str = ""
    start_time: datetime | None = None
    end_time: datetime | None = None


def _match_text(actual: str | None, expected: str, mode: str) -> bool:
    if not expected:
        return True
    if actual is None:
        return False
    actual_lower, expected_lower = actual.lower(), expected.strip().lower()
    return actual_lower == expected_lower if mode == "Exact" else expected_lower in actual_lower


def filter_records(records: Iterable[PacketRecord], filters: PacketFilters) -> list[PacketRecord]:
    """Return records matching all supplied filters without changing input."""

    if filters.either_port is not None and not 0 <= filters.either_port <= 65535:
        raise ValueError("Port must be between 0 and 65535.")
    protocol = filters.protocol.upper()
    keyword = filters.keyword.strip().lower()
    selected = []
    for record in records:
        if protocol != "ALL":
            if protocol == "ICMP":
                if record.primary_label != "ICMP":
                    continue
            elif record.primary_label.upper() != protocol:
                continue
        if not _match_text(record.src_ip, filters.src_ip, filters.ip_match):
            continue
        if not _match_text(record.dst_ip, filters.dst_ip, filters.ip_match):
            continue
        if filters.either_port is not None and filters.either_port not in {record.src_port, record.dst_port}:
            continue
        if filters.start_time is not None and record.capture_time < filters.start_time:
            continue
        if filters.end_time is not None and record.capture_time > filters.end_time:
            continue
        searchable = f"{record.summary} {record.dns_query_name or ''}".lower()
        if keyword and keyword not in searchable:
            continue
        selected.append(record)
    return selected
