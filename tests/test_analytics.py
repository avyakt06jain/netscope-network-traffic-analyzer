from dataclasses import replace

from netscope.analytics import (
    aggregate_flows,
    heuristic_observations,
    protocol_distribution,
    summary_stats,
    time_series,
)


def test_stats_empty_and_single_packet_are_safe(record_factory) -> None:
    empty = summary_stats([])
    single = summary_stats([record_factory(1)])
    assert empty.total_packets == 0 and empty.packets_per_second is None
    assert single.total_bytes == 100 and single.packets_per_second is None


def test_protocol_counts_sum_and_unique_ips_exclude_null(record_factory) -> None:
    records = [
        record_factory(1),
        record_factory(2, primary_label="UDP", transport_protocol="UDP"),
        record_factory(3, primary_label="ARP", network_protocol="ARP", src_ip=None, dst_ip=None),
    ]
    distribution = protocol_distribution(records)
    assert distribution["packets"].sum() == len(records)
    assert abs(distribution["percentage"].sum() - 100.0) < 0.001
    assert summary_stats(records).unique_ips == 2


def test_time_series_uses_ordered_capture_timestamps(record_factory) -> None:
    records = [record_factory(5), record_factory(1), record_factory(2)]
    series = time_series(records)
    assert series["capture_time"].is_monotonic_increasing
    assert series["packets"].sum() == 3
    assert series["bytes"].sum() == 300
    assert series.iloc[0]["capture_time"] == record_factory(1).capture_time


def test_bidirectional_flow_is_one_group(record_factory) -> None:
    outward = record_factory(1)
    inward = replace(
        record_factory(2), src_ip=outward.dst_ip, dst_ip=outward.src_ip, src_port=80, dst_port=50000
    )
    arp = replace(record_factory(3), network_protocol="ARP", transport_protocol=None, src_ip=None, dst_ip=None)
    flows = aggregate_flows([outward, inward, arp])
    assert len(flows) == 1
    assert flows[0].packet_count == 2


def test_heuristics_are_tunable(record_factory) -> None:
    records = [record_factory(index, dst_port=1000 + index) for index in range(1, 6)]
    findings = heuristic_observations(records, rate_threshold=5, rate_window_seconds=10, port_threshold=5)
    assert {finding["kind"] for finding in findings} == {"High packet rate", "Many destination ports"}
