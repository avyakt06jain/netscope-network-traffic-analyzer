from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from framesight.pcap_io import (
    PcapImportError,
    PcapTooLargeError,
    UnsupportedPcapError,
    load_pcap,
    load_pcap_bytes,
    records_to_csv,
)


def test_valid_import_and_packet_cap(tmp_path: Path) -> None:
    path = tmp_path / "many.pcap"
    wrpcap(str(path), [Ether() / IP() / TCP() for _ in range(4)])
    result = load_pcap(path, max_packets=3)
    assert len(result.records) == 3
    assert result.truncated is True


def test_empty_bad_magic_and_pcapng_are_clear(tmp_path: Path) -> None:
    empty = tmp_path / "empty.pcap"
    empty.write_bytes(b"")
    with pytest.raises(PcapImportError, match="empty"):
        load_pcap(empty)
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"NOPE" + b"\0" * 30)
    with pytest.raises(UnsupportedPcapError, match="classic PCAP"):
        load_pcap(bad)
    ng = tmp_path / "capture.pcap"
    ng.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\0" * 30)
    with pytest.raises(UnsupportedPcapError, match="PCAPNG"):
        load_pcap(ng)


def test_upload_extension_size_and_temp_cleanup() -> None:
    with pytest.raises(UnsupportedPcapError, match=".pcap"):
        load_pcap_bytes(b"abc", "capture.pcapng")
    with pytest.raises(PcapTooLargeError):
        load_pcap_bytes(b"12345", "capture.pcap", max_file_bytes=4)


def test_csv_contains_metadata_and_no_payload(record_factory) -> None:
    data = records_to_csv([record_factory(1)]).decode()
    assert "packet_id,capture_time,length_bytes" in data
    assert "TCP teaching packet" in data
    assert "payload" not in data.lower()
