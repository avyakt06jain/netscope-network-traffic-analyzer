"""Concise networking explanations used by the packet inspector and viva UI."""

from __future__ import annotations

from .models import PacketRecord

FIELD_EXPLANATIONS = {
    "MAC address": "A link-layer address used for local network delivery. It is not a globally routed internet address.",
    "IP address": "A logical network-layer address that identifies endpoints and enables routing between networks.",
    "TTL / Hop Limit": "A forwarding limit reduced by each router. It prevents routing loops; it is not elapsed travel time.",
    "Port": "A transport-layer number that identifies a communication endpoint or service within a host.",
    "TCP flags": "Control signals such as SYN, ACK, FIN and RST used to establish, manage and close TCP connections.",
    "UDP": "Connectionless datagram delivery with no native ordering, acknowledgement or retransmission guarantee.",
    "ICMP": "Network control and diagnostic messages. Ping commonly uses ICMP Echo Request and Echo Reply.",
    "DNS": "Maps names to resource records. NetScope can parse traditional visible DNS messages, including queries and answers.",
    "TLS / HTTPS": "Application content is normally encrypted. Ordinary packet headers do not let NetScope decrypt HTTPS.",
}

OSI_MAPPING = [
    ("7 Application", "Application", "DNS metadata when visible; encrypted TLS payload remains opaque"),
    ("4 Transport", "Transport", "TCP flags/ports, UDP ports, or ICMP control messages"),
    ("3 Network", "Internet", "IPv4/IPv6 addresses, TTL/Hop Limit, routing semantics"),
    ("2 Data Link", "Network Access", "Ethernet source/destination MAC addresses and ARP"),
]

CONCEPTS_MARKDOWN = """
### Encapsulation and the two models

An Ethernet frame can carry an IPv4 or IPv6 packet, which can carry a TCP/UDP segment, which can carry application data such as DNS. The OSI model has seven conceptual layers; the practical TCP/IP model groups them into Network Access, Internet, Transport and Application. NetScope does not pretend to observe separate Session or Presentation headers.

### Protocol essentials

- **Ethernet and ARP:** Ethernet delivers frames on a local link using MAC addresses. ARP asks which MAC address owns an IPv4 address on that link.
- **IPv4 and IPv6:** IP provides logical addressing and routing. IPv4 uses TTL; IPv6 calls the equivalent field Hop Limit.
- **TCP:** Connection-oriented byte-stream transport. A normal opening uses SYN → SYN-ACK → ACK, then sequence and acknowledgement numbers track bytes.
- **UDP:** Small connectionless datagrams with lower protocol overhead but no built-in delivery guarantee.
- **ICMP:** Control and diagnostics, including the Echo messages used by `ping`; it has types/codes rather than TCP/UDP ports.
- **DNS:** Name-to-record lookup, often over UDP port 53. A port is only a hint; NetScope labels DNS only when Scapy actually decodes a DNS header.
- **TLS/HTTPS:** Payloads are normally encrypted. NetScope can show endpoints, ports and sizes, but it cannot decrypt application content.
"""

EXPERIMENTS = {
    "ICMP ping": (
        "In Live mode, select the active interface and start capture. On authorized equipment run "
        "`ping 8.8.8.8`, stop capture, filter ICMP, and compare Echo Request/Reply type values. "
        "If internet or capture permission is unavailable, use the bundled demo packets."
    ),
    "DNS lookup": (
        "Start an authorized live capture and run `nslookup example.com`. Filter DNS and inspect QR=0 queries versus "
        "QR=1 responses. Cached, encrypted, or differently routed DNS may not appear, so the demo capture is the reliable fallback."
    ),
    "TCP handshake": (
        "Load the demo, filter TCP, and inspect packet IDs around the first connection. Identify SYN, SYN-ACK and ACK "
        "with the same endpoint pair, then explain how sequence and acknowledgement numbers establish state."
    ),
}


def observed_layers(record: PacketRecord) -> list[tuple[str, str]]:
    """Return observed layer/model mappings for one normalized record."""

    layers: list[tuple[str, str]] = []
    if record.l2_protocol:
        layers.append(("OSI Layer 2 / TCP-IP Network Access", record.l2_protocol))
    if record.network_protocol != "Other":
        layers.append(("OSI Layer 3 / TCP-IP Internet", record.network_protocol))
    if record.transport_protocol:
        layers.append(("OSI Layer 4 / TCP-IP Transport", record.transport_protocol))
    if record.application_protocol:
        layers.append(("OSI Layers 5–7 / TCP-IP Application", record.application_protocol))
    return layers
