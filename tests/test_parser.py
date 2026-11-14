"""Unit tests for real Scapy packet normalization."""

from datetime import UTC, datetime

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
from scapy.layers.l2 import ARP, Ether

from netscope.parser import normalize_packet


def stamp(packet, value: float = 1_700_000_000.125):
    packet.time = value
    return packet


def test_ipv4_tcp_syn_and_timestamp() -> None:
    packet = stamp(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(
        src="192.0.2.1", dst="198.51.100.2", ttl=51
    ) / TCP(sport=49152, dport=80, flags="S", seq=100))
    record = normalize_packet(packet, 7)
    assert record.packet_id == 7
    assert record.capture_time == datetime.fromtimestamp(packet.time, tz=UTC)
    assert record.src_ip == "192.0.2.1"
    assert record.dst_port == 80
    assert record.tcp_flags == "SYN"
    assert record.primary_label == "TCP"
    assert record.length_bytes == len(bytes(packet))


def test_tcp_syn_ack_has_both_readable_flags() -> None:
    packet = Ether() / IP(src="198.51.100.2", dst="192.0.2.1") / TCP(flags="SA")
    record = normalize_packet(packet, 1)
    assert record.tcp_flags == "SYN, ACK"


def test_udp_has_ports_but_no_tcp_flags() -> None:
    packet = Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / UDP(sport=1234, dport=9999)
    record = normalize_packet(packet, 1)
    assert (record.src_port, record.dst_port) == (1234, 9999)
    assert record.tcp_flags is None
    assert record.primary_label == "UDP"


def test_dns_request_and_response_fields() -> None:
    request = Ether() / IP() / UDP(sport=53000, dport=53) / DNS(
        id=9, qr=0, qd=DNSQR(qname=b"example.com.", qtype="A")
    )
    response = Ether() / IP() / UDP(sport=53, dport=53000) / DNS(
        id=9,
        qr=1,
        qd=DNSQR(qname=b"example.com.", qtype="A"),
        an=DNSRR(rrname=b"example.com.", type="A", rdata="203.0.113.80"),
        ancount=1,
    )
    request_record = normalize_packet(request, 1)
    response_record = normalize_packet(response, 2)
    assert request_record.dns_query_name == "example.com"
    assert request_record.dns_is_response is False
    assert request_record.dns_query_type == "A"
    assert response_record.dns_is_response is True
    assert "203.0.113.80" in (response_record.dns_answer_summary or "")
    assert response_record.primary_label == "DNS"


def test_icmp_echo_has_no_ports() -> None:
    packet = Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / ICMP(type=8, code=0)
    record = normalize_packet(packet, 1)
    assert record.transport_protocol == "ICMP"
    assert record.icmp_label == "Echo Request"
    assert record.src_port is None and record.dst_port is None


def test_arp_does_not_fabricate_ip_or_ports() -> None:
    packet = Ether() / ARP(op=1, psrc="192.168.50.10", pdst="192.168.50.1")
    record = normalize_packet(packet, 1)
    assert record.network_protocol == "ARP"
    assert record.src_ip is None and record.dst_ip is None
    assert record.src_port is None and record.dst_port is None
    assert record.arp_sender_ip == "192.168.50.10"
    assert record.arp_operation == "Request"


def test_ipv6_and_icmpv6() -> None:
    packet = Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2", hlim=32) / ICMPv6EchoRequest()
    record = normalize_packet(packet, 1)
    assert record.network_protocol == "IPv6"
    assert record.ip_ttl_or_hop_limit == 32
    assert record.transport_protocol == "ICMPv6"
    assert record.icmp_label == "Echo Request"


def test_unknown_object_is_safe() -> None:
    class Unknown:
        time = "not-a-timestamp"

        def getlayer(self, _layer):
            return None

        def __bytes__(self):
            raise ValueError("malformed")

        def __len__(self):
            return 0

    record = normalize_packet(Unknown(), 1)
    assert record.primary_label == "Other"
    assert record.length_bytes == 0
    assert record.capture_time.tzinfo is not None
