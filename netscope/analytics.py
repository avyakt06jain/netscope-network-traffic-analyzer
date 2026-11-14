"""Pure packet statistics, chart data, flows, and safe heuristic observations."""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from collections.abc import Iterable
from dataclasses import asdict
from datetime import timedelta

import pandas as pd

from .models import FlowRecord, PacketRecord, SummaryStats


def summary_stats(records: Iterable[PacketRecord]) -> SummaryStats:
    """Calculate metrics for one record selection."""

    items = list(records)
    total_bytes = sum(max(0, record.length_bytes) for record in items)
    unique_ips = {ip for record in items for ip in (record.src_ip, record.dst_ip) if ip}
    if items:
        times = [record.capture_time for record in items]
        duration = max(0.0, (max(times) - min(times)).total_seconds())
        mean_size = total_bytes / len(items)
    else:
        duration = 0.0
        mean_size = None
    packet_rate = len(items) / duration if duration > 0 else None
    byte_rate = total_bytes / duration if duration > 0 else None
    return SummaryStats(
        total_packets=len(items),
        total_bytes=total_bytes,
        unique_ips=len(unique_ips),
        mean_packet_size_bytes=mean_size,
        duration_seconds=duration,
        packets_per_second=packet_rate,
        bytes_per_second=byte_rate,
        bits_per_second=byte_rate * 8 if byte_rate is not None else None,
    )


def protocol_distribution(records: Iterable[PacketRecord]) -> pd.DataFrame:
    """Return mutually exclusive primary-label counts and percentages."""

    counts = Counter(record.primary_label for record in records)
    total = sum(counts.values())
    rows = [
        {"protocol": protocol, "packets": count, "percentage": count * 100 / total if total else 0.0}
        for protocol, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]
    return pd.DataFrame(rows, columns=["protocol", "packets", "percentage"])


def time_series(
    records: Iterable[PacketRecord],
    bin_seconds: int = 1,
    last_seconds: int | None = None,
) -> pd.DataFrame:
    """Return ordered packet/byte bins using capture timestamps."""

    items = list(records)
    columns = ["capture_time", "packets", "bytes"]
    if not items:
        return pd.DataFrame(columns=columns)
    if bin_seconds < 1:
        raise ValueError("bin_seconds must be at least 1")
    if last_seconds is not None:
        cutoff = max(record.capture_time for record in items) - timedelta(seconds=last_seconds)
        items = [record for record in items if record.capture_time >= cutoff]
    frame = pd.DataFrame(
        {"capture_time": [record.capture_time for record in items], "bytes": [record.length_bytes for record in items]}
    ).set_index("capture_time")
    result = frame.resample(f"{bin_seconds}s").agg(packets=("bytes", "size"), bytes=("bytes", "sum"))
    return result.reset_index()[columns]


def top_ips(records: Iterable[PacketRecord], direction: str, limit: int = 10) -> pd.DataFrame:
    """Count top source or destination IP addresses."""

    if direction not in {"source", "destination"}:
        raise ValueError("direction must be source or destination")
    values = (
        record.src_ip if direction == "source" else record.dst_ip
        for record in records
    )
    counts = Counter(value for value in values if value)
    return pd.DataFrame(counts.most_common(limit), columns=["ip", "packets"])


def records_dataframe(records: Iterable[PacketRecord]) -> pd.DataFrame:
    """Build a display table from normalized metadata only."""

    rows = []
    for record in records:
        rows.append({
            "ID": record.packet_id,
            "Timestamp": record.capture_time.astimezone().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "Source": record.src_ip or record.arp_sender_ip or "N/A",
            "Destination": record.dst_ip or record.arp_target_ip or "N/A",
            "Protocol": record.primary_label,
            "Src Port": record.src_port,
            "Dst Port": record.dst_port,
            "Bytes": record.length_bytes,
            "Info": record.summary,
        })
    return pd.DataFrame(rows, columns=[
        "ID", "Timestamp", "Source", "Destination", "Protocol", "Src Port", "Dst Port", "Bytes", "Info"
    ])


def _endpoint(ip: str, port: int) -> str:
    wrapped = f"[{ip}]" if ":" in ip else ip
    return f"{wrapped}:{port}"


def aggregate_flows(records: Iterable[PacketRecord]) -> list[FlowRecord]:
    """Group TCP/UDP packets into direction-independent 5-tuples."""

    groups: dict[tuple, list[PacketRecord]] = defaultdict(list)
    endpoints: dict[tuple, tuple[str, str]] = {}
    for record in records:
        if record.transport_protocol not in {"TCP", "UDP"}:
            continue
        if record.src_ip is None or record.dst_ip is None or record.src_port is None or record.dst_port is None:
            continue
        left = (record.src_ip, record.src_port)
        right = (record.dst_ip, record.dst_port)
        endpoint_a, endpoint_b = sorted((left, right))
        key = (record.network_protocol, record.transport_protocol, endpoint_a, endpoint_b)
        groups[key].append(record)
        endpoints[key] = (_endpoint(*endpoint_a), _endpoint(*endpoint_b))
    flows = []
    for key, packets in groups.items():
        endpoint_a, endpoint_b = endpoints[key]
        flows.append(FlowRecord(
            ip_version=key[0],
            transport=key[1],
            endpoint_a=endpoint_a,
            endpoint_b=endpoint_b,
            packet_count=len(packets),
            byte_count=sum(packet.length_bytes for packet in packets),
            first_seen=min(packet.capture_time for packet in packets),
            last_seen=max(packet.capture_time for packet in packets),
        ))
    return sorted(flows, key=lambda flow: (-flow.packet_count, flow.endpoint_a, flow.endpoint_b))


def flows_dataframe(records: Iterable[PacketRecord]) -> pd.DataFrame:
    """Return bidirectional flows as a display-ready frame."""

    rows = []
    for flow in aggregate_flows(records):
        row = asdict(flow)
        row["first_seen"] = flow.first_seen.astimezone().strftime("%H:%M:%S.%f")[:-3]
        row["last_seen"] = flow.last_seen.astimezone().strftime("%H:%M:%S.%f")[:-3]
        rows.append(row)
    return pd.DataFrame(rows)


def heuristic_observations(
    records: Iterable[PacketRecord],
    rate_threshold: int = 25,
    rate_window_seconds: int = 10,
    port_threshold: int = 10,
    port_window_seconds: int = 60,
) -> list[dict[str, str | int]]:
    """Find tunable patterns worth investigating, never attack verdicts."""

    by_source: dict[str, list[PacketRecord]] = defaultdict(list)
    for record in records:
        if record.src_ip:
            by_source[record.src_ip].append(record)
    observations: list[dict[str, str | int]] = []
    for source, packets in sorted(by_source.items()):
        packets.sort(key=lambda record: record.capture_time)
        window: deque[PacketRecord] = deque()
        max_rate = 0
        for packet in packets:
            window.append(packet)
            cutoff = packet.capture_time - timedelta(seconds=rate_window_seconds)
            while window and window[0].capture_time < cutoff:
                window.popleft()
            max_rate = max(max_rate, len(window))
        if max_rate >= rate_threshold:
            observations.append({
                "kind": "High packet rate",
                "source": source,
                "value": max_rate,
                "detail": f"{max_rate} packets within {rate_window_seconds}s (threshold {rate_threshold})",
            })

        max_ports = 0
        for start_index, first in enumerate(packets):
            cutoff = first.capture_time + timedelta(seconds=port_window_seconds)
            ports = {
                packet.dst_port
                for packet in packets[start_index:]
                if packet.capture_time <= cutoff and packet.dst_port is not None
            }
            max_ports = max(max_ports, len(ports))
        if max_ports >= port_threshold:
            observations.append({
                "kind": "Many destination ports",
                "source": source,
                "value": max_ports,
                "detail": f"{max_ports} ports within {port_window_seconds}s (threshold {port_threshold})",
            })
    return observations
