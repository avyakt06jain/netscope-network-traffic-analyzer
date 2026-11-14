"""Typed immutable data models used throughout NetScope."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class PacketRecord:
    """Normalized packet-header metadata.

    ``length_bytes`` is the number of captured frame bytes serialized by Scapy.
    Raw payload bytes are deliberately not retained.
    """

    packet_id: int
    capture_time: datetime
    length_bytes: int
    l2_protocol: str | None
    src_mac: str | None
    dst_mac: str | None
    network_protocol: str
    src_ip: str | None
    dst_ip: str | None
    ip_ttl_or_hop_limit: int | None
    transport_protocol: str | None
    src_port: int | None
    dst_port: int | None
    application_protocol: str | None
    primary_label: str
    tcp_flags: str | None
    tcp_seq: int | None
    tcp_ack: int | None
    icmp_type: int | None
    icmp_code: int | None
    icmp_label: str | None
    dns_query_name: str | None
    dns_is_response: bool | None
    dns_query_type: str | None
    dns_answer_summary: str | None
    arp_operation: str | None
    arp_sender_ip: str | None
    arp_target_ip: str | None
    capture_interface: str | None
    summary: str

    def as_dict(self) -> dict[str, Any]:
        """Return a serializable mapping without packet payload data."""

        values = asdict(self)
        values["capture_time"] = self.capture_time.isoformat()
        return values


@dataclass(frozen=True, slots=True)
class SummaryStats:
    """Aggregate statistics for one consistent record selection."""

    total_packets: int
    total_bytes: int
    unique_ips: int
    mean_packet_size_bytes: float | None
    duration_seconds: float
    packets_per_second: float | None
    bytes_per_second: float | None
    bits_per_second: float | None


@dataclass(frozen=True, slots=True)
class FlowRecord:
    """Bidirectional TCP or UDP conversation summary."""

    ip_version: str
    transport: str
    endpoint_a: str
    endpoint_b: str
    packet_count: int
    byte_count: int
    first_seen: datetime
    last_seen: datetime
