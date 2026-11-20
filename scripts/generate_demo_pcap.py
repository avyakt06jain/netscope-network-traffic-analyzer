"""Generate FrameSight's deterministic, offline teaching capture."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoReply, ICMPv6EchoRequest, IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "samples" / "framesight_demo.pcap"
BASE_TIME = datetime(2024, 1, 15, 10, 0, tzinfo=UTC).timestamp()

CLIENT_MAC = "02:00:00:00:50:10"
ROUTER_MAC = "02:00:00:00:50:01"
DNS_MAC = "02:00:00:00:50:53"
REMOTE_MAC = "02:00:00:00:00:20"


def _at(packet, seconds: float):
    packet.time = BASE_TIME + seconds
    return packet


def build_demo_packets() -> list:
    """Build exactly 80 coherent packets spanning about 45 seconds."""

    packets = []

    packets.append(_at(Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1,
        hwsrc=CLIENT_MAC,
        psrc="192.168.50.10",
        hwdst="00:00:00:00:00:00",
        pdst="192.168.50.1",
    ), 0.0))
    packets.append(_at(Ether(src=ROUTER_MAC, dst=CLIENT_MAC) / ARP(
        op=2,
        hwsrc=ROUTER_MAC,
        psrc="192.168.50.1",
        hwdst=CLIENT_MAC,
        pdst="192.168.50.10",
    ), 0.4))

    for sequence, start in enumerate((5.0, 7.0, 20.0, 40.0), start=1):
        packets.append(_at(
            Ether(src=CLIENT_MAC, dst=ROUTER_MAC)
            / IP(src="192.168.50.10", dst="203.0.113.8", ttl=64, id=100 + sequence)
            / ICMP(type=8, code=0, id=400, seq=sequence),
            start,
        ))
        packets.append(_at(
            Ether(src=ROUTER_MAC, dst=CLIENT_MAC)
            / IP(src="203.0.113.8", dst="192.168.50.10", ttl=51, id=200 + sequence)
            / ICMP(type=0, code=0, id=400, seq=sequence),
            start + 0.25,
        ))

    dns_starts = (9.0, 12.0, 25.0, 31.0, 44.0)
    dns_names = ("example.com", "www.example.com", "docs.example.com", "example.com", "example.com")
    for index, (start, name) in enumerate(zip(dns_starts, dns_names, strict=True), start=1):
        dns_id = 1000 + index
        query_port = 53000 + index
        question = DNSQR(qname=f"{name}.", qtype="A")
        packets.append(_at(
            Ether(src=CLIENT_MAC, dst=DNS_MAC)
            / IP(src="192.168.50.10", dst="192.168.50.53", ttl=64, id=300 + index)
            / UDP(sport=query_port, dport=53)
            / DNS(id=dns_id, qr=0, rd=1, qd=question),
            start,
        ))
        packets.append(_at(
            Ether(src=DNS_MAC, dst=CLIENT_MAC)
            / IP(src="192.168.50.53", dst="192.168.50.10", ttl=64, id=400 + index)
            / UDP(sport=53, dport=query_port)
            / DNS(
                id=dns_id,
                qr=1,
                aa=1,
                rd=1,
                ra=1,
                qd=DNSQR(qname=f"{name}.", qtype="A"),
                an=DNSRR(rrname=f"{name}.", type="A", ttl=300, rdata="203.0.113.80"),
                ancount=1,
            ),
            start + 0.2,
        ))

    client_ip, server_ip = "192.168.50.10", "198.51.100.20"
    client_port, server_port = 51515, 80
    client_seq, server_seq = 10000, 50000
    packets.extend([
        _at(Ether(src=CLIENT_MAC, dst=REMOTE_MAC) / IP(src=client_ip, dst=server_ip, id=500)
            / TCP(sport=client_port, dport=server_port, flags="S", seq=client_seq), 15.0),
        _at(Ether(src=REMOTE_MAC, dst=CLIENT_MAC) / IP(src=server_ip, dst=client_ip, ttl=52, id=501)
            / TCP(sport=server_port, dport=client_port, flags="SA", seq=server_seq, ack=client_seq + 1), 15.1),
        _at(Ether(src=CLIENT_MAC, dst=REMOTE_MAC) / IP(src=client_ip, dst=server_ip, id=502)
            / TCP(sport=client_port, dport=server_port, flags="A", seq=client_seq + 1, ack=server_seq + 1), 15.2),
    ])
    next_client_seq = client_seq + 1
    for index in range(16):
        payload = f"FrameSight teaching message {index + 1:02d}".encode()
        data_time = 15.5 + index * 0.28
        packets.append(_at(
            Ether(src=CLIENT_MAC, dst=REMOTE_MAC)
            / IP(src=client_ip, dst=server_ip, id=510 + index * 2)
            / TCP(
                sport=client_port,
                dport=server_port,
                flags="PA",
                seq=next_client_seq,
                ack=server_seq + 1,
            )
            / Raw(load=payload),
            data_time,
        ))
        next_client_seq += len(payload)
        packets.append(_at(
            Ether(src=REMOTE_MAC, dst=CLIENT_MAC)
            / IP(src=server_ip, dst=client_ip, ttl=52, id=511 + index * 2)
            / TCP(
                sport=server_port,
                dport=client_port,
                flags="A",
                seq=server_seq + 1,
                ack=next_client_seq,
            ),
            data_time + 0.08,
        ))

    udp_times = (2.0, 2.1, 2.2, 27.0, 27.1, 27.2, 27.3, 29.0, 29.2, 42.0, 42.1, 42.2, 42.3)
    for index, packet_time in enumerate(udp_times):
        packets.append(_at(
            Ether(src=CLIENT_MAC, dst=REMOTE_MAC)
            / IP(src="192.168.50.10", dst="192.0.2.50", id=700 + index)
            / UDP(sport=41000 + index, dport=9000)
            / Raw(load=f"UDP teaching datagram {index + 1:02d}".encode()),
            packet_time,
        ))

    for index, packet_time in enumerate((34.0, 34.1, 34.2, 35.0, 35.1, 35.2)):
        packets.append(_at(
            Ether(src=CLIENT_MAC, dst=REMOTE_MAC)
            / IPv6(src="2001:db8:50::10", dst="2001:db8:100::20", hlim=48)
            / UDP(sport=42000 + index, dport=7000)
            / Raw(load=f"IPv6 UDP example {index + 1}".encode()),
            packet_time,
        ))

    for sequence, start in enumerate((37.0, 38.0, 39.0), start=1):
        packets.append(_at(
            Ether(src=CLIENT_MAC, dst=REMOTE_MAC)
            / IPv6(src="2001:db8:50::10", dst="2001:db8:100::20", hlim=48)
            / ICMPv6EchoRequest(id=600, seq=sequence),
            start,
        ))
        packets.append(_at(
            Ether(src=REMOTE_MAC, dst=CLIENT_MAC)
            / IPv6(src="2001:db8:100::20", dst="2001:db8:50::10", hlim=47)
            / ICMPv6EchoReply(id=600, seq=sequence),
            start + 0.2,
        ))

    assert len(packets) == 80
    packets.sort(key=lambda packet: float(packet.time))
    return packets


def generate_demo_pcap(output: Path = DEFAULT_OUTPUT) -> Path:
    """Write and return a deterministic classic PCAP file."""

    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), build_demo_packets())
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    output = generate_demo_pcap(args.output.resolve())
    print(f"Generated 80 deterministic packets: {output}")


if __name__ == "__main__":
    main()
