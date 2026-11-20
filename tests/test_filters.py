from datetime import timedelta

import pytest

from framesight.filters import PacketFilters, filter_records


def test_combined_filters_and_original_unchanged(record_factory) -> None:
    records = [
        record_factory(1),
        record_factory(2, src_ip="203.0.113.5", dst_port=53, primary_label="DNS", summary="DNS Query", dns_query_name="example.com"),
    ]
    original = list(records)
    selected = filter_records(records, PacketFilters(
        protocol="DNS", src_ip="203.0", ip_match="Contains", either_port=53, keyword="example"
    ))
    assert [record.packet_id for record in selected] == [2]
    assert records == original


def test_exact_ip_and_time_range(record_factory) -> None:
    first, second = record_factory(1), record_factory(2)
    selected = filter_records([first, second], PacketFilters(
        src_ip="192.0.2.1",
        ip_match="Exact",
        start_time=first.capture_time + timedelta(milliseconds=500),
    ))
    assert selected == [second]


def test_invalid_port_is_rejected(record_factory) -> None:
    with pytest.raises(ValueError, match="between 0 and 65535"):
        filter_records([record_factory(1)], PacketFilters(either_port=70_000))
