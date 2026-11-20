"""Shared deterministic PacketRecord fixtures."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from framesight.models import PacketRecord


def make_record(packet_id: int, **changes) -> PacketRecord:
    base = {
        "packet_id": packet_id,
        "capture_time": datetime(2024, 1, 1, tzinfo=UTC) + timedelta(seconds=packet_id),
        "length_bytes": 100,
        "l2_protocol": "Ethernet",
        "src_mac": "02:00:00:00:00:01",
        "dst_mac": "02:00:00:00:00:02",
        "network_protocol": "IPv4",
        "src_ip": "192.0.2.1",
        "dst_ip": "198.51.100.2",
        "ip_ttl_or_hop_limit": 64,
        "transport_protocol": "TCP",
        "src_port": 50000,
        "dst_port": 80,
        "application_protocol": None,
        "primary_label": "TCP",
        "tcp_flags": "ACK",
        "tcp_seq": 1,
        "tcp_ack": 1,
        "icmp_type": None,
        "icmp_code": None,
        "icmp_label": None,
        "dns_query_name": None,
        "dns_is_response": None,
        "dns_query_type": None,
        "dns_answer_summary": None,
        "arp_operation": None,
        "arp_sender_ip": None,
        "arp_target_ip": None,
        "capture_interface": None,
        "summary": "TCP teaching packet",
    }
    base.update(changes)
    return PacketRecord(**base)


@pytest.fixture
def record_factory():
    return make_record
