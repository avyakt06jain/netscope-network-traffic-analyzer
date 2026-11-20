from collections import Counter
from pathlib import Path

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.utils import rdpcap

from framesight.analytics import protocol_distribution, time_series
from framesight.pcap_io import load_pcap
from scripts.generate_demo_pcap import build_demo_packets, generate_demo_pcap


def test_generator_is_exact_and_reproducible(tmp_path: Path) -> None:
    first, second = tmp_path / "first.pcap", tmp_path / "second.pcap"
    generate_demo_pcap(first)
    generate_demo_pcap(second)
    assert first.read_bytes() == second.read_bytes()
    assert len(rdpcap(str(first))) == 80


def test_demo_story_counts_and_parsing(tmp_path: Path) -> None:
    path = generate_demo_pcap(tmp_path / "demo.pcap")
    packets = rdpcap(str(path))
    assert sum(ARP in packet for packet in packets) == 2
    assert sum(ICMP in packet for packet in packets) == 8
    assert sum(DNS in packet for packet in packets) == 10
    assert sum(TCP in packet for packet in packets) == 35
    assert sum(UDP in packet and DNS not in packet and IPv6 not in packet for packet in packets) == 13
    assert sum(UDP in packet and IPv6 in packet for packet in packets) == 6
    flags = [str(packet[TCP].flags) for packet in packets if TCP in packet]
    assert flags[:3] == ["S", "SA", "A"]

    result = load_pcap(path)
    assert len(result.records) == 80
    counts = Counter(record.primary_label for record in result.records)
    assert counts == {"TCP": 35, "UDP": 19, "ICMP": 14, "DNS": 10, "ARP": 2}
    assert protocol_distribution(result.records)["packets"].sum() == 80
    assert time_series(result.records)["packets"].sum() == 80


def test_packet_times_span_deliberate_interval() -> None:
    packets = build_demo_packets()
    span = float(packets[-1].time) - float(packets[0].time)
    assert 44 <= span <= 46
