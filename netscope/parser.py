"""Defensive conversion of Scapy packets into normalized metadata records."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

from .models import PacketRecord

DNS_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}

TCP_FLAG_BITS = (
    (0x002, "SYN"),
    (0x010, "ACK"),
    (0x001, "FIN"),
    (0x004, "RST"),
    (0x008, "PSH"),
    (0x020, "URG"),
    (0x040, "ECE"),
    (0x080, "CWR"),
    (0x100, "NS"),
)


def _safe_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError, OverflowError):
        return None


def _safe_text(value: Any) -> str | None:
    if value is None:
        return None
    try:
        return str(value)
    except Exception:  # pragma: no cover - exotic third-party Scapy field
        return None


def _timestamp_utc(packet: Any) -> datetime:
    raw = getattr(packet, "time", None)
    try:
        timestamp = float(raw)
        return datetime.fromtimestamp(timestamp, tz=UTC)
    except (TypeError, ValueError, OverflowError, OSError):
        return datetime.now(tz=UTC)


def _frame_length(packet: Any) -> int:
    try:
        return max(0, len(bytes(packet)))
    except Exception:
        try:
            return max(0, len(packet))
        except Exception:
            return 0


def _decode_dns_name(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    else:
        text = str(value)
    return text.rstrip(".") or None


def _tcp_flags(value: Any) -> str | None:
    flag_value = _safe_int(value)
    if flag_value is None:
        return None
    names = [name for bit, name in TCP_FLAG_BITS if flag_value & bit]
    return ", ".join(names) if names else "None"


def _dns_question(dns: DNS) -> tuple[str | None, str | None]:
    question = getattr(dns, "qd", None)
    if question is None:
        return None, None
    try:
        if isinstance(question, list):
            question = question[0] if question else None
        if not isinstance(question, DNSQR):
            question = question.getlayer(DNSQR) if hasattr(question, "getlayer") else None
        if question is None:
            return None, None
        qtype_number = _safe_int(getattr(question, "qtype", None))
        qtype = DNS_TYPES.get(qtype_number, str(qtype_number)) if qtype_number is not None else None
        return _decode_dns_name(getattr(question, "qname", None)), qtype
    except Exception:
        return None, None


def _dns_answer(dns: DNS) -> str | None:
    if not bool(_safe_int(getattr(dns, "qr", 0))) or not _safe_int(getattr(dns, "ancount", 0)):
        return None
    answer = getattr(dns, "an", None)
    try:
        if isinstance(answer, list):
            answer = answer[0] if answer else None
        if answer is None:
            return None
        if not isinstance(answer, DNSRR) and hasattr(answer, "getlayer"):
            answer = answer.getlayer(DNSRR)
        if answer is None:
            return None
        rr_type_number = _safe_int(getattr(answer, "type", None))
        rr_type = DNS_TYPES.get(rr_type_number, str(rr_type_number))
        rr_name = _decode_dns_name(getattr(answer, "rrname", None)) or "record"
        rdata = _safe_text(getattr(answer, "rdata", None)) or "N/A"
        return f"{rr_name} {rr_type} {rdata}"
    except Exception:
        return None


def _icmpv6_layer(packet: Any) -> Any | None:
    ipv6 = packet.getlayer(IPv6) if hasattr(packet, "getlayer") else None
    layer = getattr(ipv6, "payload", None)
    if layer is not None and layer.__class__.__name__.startswith("ICMPv6"):
        return layer
    return None


def _icmp_label(protocol: str | None, icmp_type: int | None) -> str | None:
    if protocol == "ICMP":
        return {8: "Echo Request", 0: "Echo Reply"}.get(icmp_type, f"Type {icmp_type}")
    if protocol == "ICMPv6":
        return {128: "Echo Request", 129: "Echo Reply"}.get(icmp_type, f"Type {icmp_type}")
    return None


def _summary(
    *,
    primary: str,
    src_ip: str | None,
    dst_ip: str | None,
    src_port: int | None,
    dst_port: int | None,
    flags: str | None,
    icmp_label: str | None,
    dns_name: str | None,
    dns_response: bool | None,
    arp_operation: str | None,
    arp_sender_ip: str | None,
    arp_target_ip: str | None,
) -> str:
    if primary == "ARP":
        return f"ARP {arp_operation or 'message'}: {arp_sender_ip or 'N/A'} → {arp_target_ip or 'N/A'}"
    if primary == "DNS":
        direction = "Response" if dns_response else "Query"
        return f"DNS {direction}: {dns_name or 'unknown name'}"
    if primary in {"ICMP", "ICMPv6"}:
        return f"{primary} {icmp_label or 'message'}: {src_ip or 'N/A'} → {dst_ip or 'N/A'}"
    if primary == "TCP":
        return (
            f"TCP {src_ip or 'N/A'}:{src_port if src_port is not None else 'N/A'} → "
            f"{dst_ip or 'N/A'}:{dst_port if dst_port is not None else 'N/A'} [{flags or 'None'}]"
        )
    if primary == "UDP":
        return (
            f"UDP {src_ip or 'N/A'}:{src_port if src_port is not None else 'N/A'} → "
            f"{dst_ip or 'N/A'}:{dst_port if dst_port is not None else 'N/A'}"
        )
    return f"Other frame: {src_ip or 'N/A'} → {dst_ip or 'N/A'}"


def normalize_packet(packet: Any, packet_id: int) -> PacketRecord:
    """Normalize one Scapy packet without retaining raw payload bytes.

    Unknown and partially malformed layers result in an ``Other`` record rather
    than an exception, allowing one bad packet to coexist with useful records.
    """

    l2_protocol = None
    src_mac = dst_mac = None
    network_protocol = "Other"
    src_ip = dst_ip = None
    ttl_or_hop = None
    transport = None
    src_port = dst_port = None
    tcp_flags = None
    tcp_seq = tcp_ack = None
    icmp_type = icmp_code = None
    dns_name = dns_type = dns_answer = None
    dns_response = None
    arp_operation = arp_sender_ip = arp_target_ip = None

    try:
        ether = packet.getlayer(Ether)
        if ether is not None:
            l2_protocol = "Ethernet"
            src_mac = _safe_text(getattr(ether, "src", None))
            dst_mac = _safe_text(getattr(ether, "dst", None))
    except Exception:
        pass

    try:
        arp = packet.getlayer(ARP)
    except Exception:
        arp = None
    if arp is not None:
        network_protocol = "ARP"
        operation_number = _safe_int(getattr(arp, "op", None))
        arp_operation = {1: "Request", 2: "Reply"}.get(operation_number, f"Operation {operation_number}")
        arp_sender_ip = _safe_text(getattr(arp, "psrc", None))
        arp_target_ip = _safe_text(getattr(arp, "pdst", None))
    else:
        try:
            ipv4 = packet.getlayer(IP)
        except Exception:
            ipv4 = None
        try:
            ipv6 = packet.getlayer(IPv6)
        except Exception:
            ipv6 = None
        if ipv4 is not None:
            network_protocol = "IPv4"
            src_ip = _safe_text(getattr(ipv4, "src", None))
            dst_ip = _safe_text(getattr(ipv4, "dst", None))
            ttl_or_hop = _safe_int(getattr(ipv4, "ttl", None))
        elif ipv6 is not None:
            network_protocol = "IPv6"
            src_ip = _safe_text(getattr(ipv6, "src", None))
            dst_ip = _safe_text(getattr(ipv6, "dst", None))
            ttl_or_hop = _safe_int(getattr(ipv6, "hlim", None))

    try:
        tcp = packet.getlayer(TCP)
    except Exception:
        tcp = None
    try:
        udp = packet.getlayer(UDP)
    except Exception:
        udp = None
    try:
        icmp = packet.getlayer(ICMP)
    except Exception:
        icmp = None
    icmpv6 = _icmpv6_layer(packet)

    if tcp is not None:
        transport = "TCP"
        src_port = _safe_int(getattr(tcp, "sport", None))
        dst_port = _safe_int(getattr(tcp, "dport", None))
        tcp_flags = _tcp_flags(getattr(tcp, "flags", None))
        tcp_seq = _safe_int(getattr(tcp, "seq", None))
        tcp_ack = _safe_int(getattr(tcp, "ack", None))
    elif udp is not None:
        transport = "UDP"
        src_port = _safe_int(getattr(udp, "sport", None))
        dst_port = _safe_int(getattr(udp, "dport", None))
    elif icmp is not None:
        transport = "ICMP"
        icmp_type = _safe_int(getattr(icmp, "type", None))
        icmp_code = _safe_int(getattr(icmp, "code", None))
    elif icmpv6 is not None:
        transport = "ICMPv6"
        icmp_type = _safe_int(getattr(icmpv6, "type", None))
        icmp_code = _safe_int(getattr(icmpv6, "code", None))

    try:
        dns = packet.getlayer(DNS)
    except Exception:
        dns = None
    application = None
    if dns is not None:
        application = "DNS"
        dns_name, dns_type = _dns_question(dns)
        dns_response = bool(_safe_int(getattr(dns, "qr", 0)))
        dns_answer = _dns_answer(dns)

    if network_protocol == "ARP":
        primary = "ARP"
    elif transport in {"ICMP", "ICMPv6"}:
        primary = "ICMP"
    elif application == "DNS":
        primary = "DNS"
    elif transport == "TCP":
        primary = "TCP"
    elif transport == "UDP":
        primary = "UDP"
    else:
        primary = "Other"

    label = _icmp_label(transport, icmp_type)
    interface = _safe_text(getattr(packet, "sniffed_on", None))
    return PacketRecord(
        packet_id=packet_id,
        capture_time=_timestamp_utc(packet),
        length_bytes=_frame_length(packet),
        l2_protocol=l2_protocol,
        src_mac=src_mac,
        dst_mac=dst_mac,
        network_protocol=network_protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        ip_ttl_or_hop_limit=ttl_or_hop,
        transport_protocol=transport,
        src_port=src_port,
        dst_port=dst_port,
        application_protocol=application,
        primary_label=primary,
        tcp_flags=tcp_flags,
        tcp_seq=tcp_seq,
        tcp_ack=tcp_ack,
        icmp_type=icmp_type,
        icmp_code=icmp_code,
        icmp_label=label,
        dns_query_name=dns_name,
        dns_is_response=dns_response,
        dns_query_type=dns_type,
        dns_answer_summary=dns_answer,
        arp_operation=arp_operation,
        arp_sender_ip=arp_sender_ip,
        arp_target_ip=arp_target_ip,
        capture_interface=interface,
        summary=_summary(
            primary=primary,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            flags=tcp_flags,
            icmp_label=label,
            dns_name=dns_name,
            dns_response=dns_response,
            arp_operation=arp_operation,
            arp_sender_ip=arp_sender_ip,
            arp_target_ip=arp_target_ip,
        ),
    )
