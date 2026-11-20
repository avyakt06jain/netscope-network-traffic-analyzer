# FrameSight — Network Traffic Analyzer & Protocol Visualization System

**Name:** ____________________  
**Roll Number:** ____________________  
**Section:** ____________________  
**Course:** Computer Networks  
**Faculty:** ____________________  
**Institute:** Netaji Subhas University of Technology (NSUT)

## Abstract

FrameSight is an educational network traffic analyzer developed in Python for a third-year Computer Networks mini-project. It reads real classic-PCAP frames or captures authorized local traffic using Scapy, converts packet headers into immutable normalized records, and presents them through a Streamlit dashboard. The system explains Ethernet and ARP, IPv4 and IPv6, TCP and UDP, ICMP, DNS, encapsulation, traffic rates and practical capture limitations. Its default demonstration is an offline, deterministic 80-frame PCAP containing a coherent ARP exchange, ICMP echo traffic, DNS queries and responses, a TCP three-way handshake, TCP data acknowledgements and IPv4/IPv6 UDP examples. This makes the assessment reliable without internet access, administrator rights or a packet-capture driver. Protocol, address, port, keyword and time filters update statistics, charts, the packet table and CSV output from the same selection. A packet inspector maps observed headers to OSI and TCP/IP layers. Live capture uses a stoppable background sniffer with bounded memory and visible error handling. FrameSight deliberately does not decrypt HTTPS, reconstruct payloads or claim intrusion-detection certainty; its focus is correct, explainable packet analysis.

## 1. Problem Statement and Objectives

Packet analysis tools are powerful but can be difficult to explain during an undergraduate viva, and live demonstrations can fail because of driver or privilege restrictions. The objective is to create a small, truthful analyzer that exposes real packet headers, provides reliable offline data, and connects implementation behavior to syllabus concepts.

Objectives:

- Acquire packets from a bundled PCAP, an imported classic PCAP, or an authorized local interface.
- Normalize heterogeneous headers without inventing absent fields.
- Visualize mutually exclusive protocol counts, packet/byte timelines and top endpoints.
- Demonstrate filtering, TCP handshakes, ICMP, DNS and encapsulation.
- Bound file size, packet count and live memory use.
- Preserve privacy by excluding payload data from normalized records and CSV.
- Remain useful when live capture is unavailable.

## 2. Course Concept Mapping

| Course concept | FrameSight evidence |
|---|---|
| OSI and TCP/IP models | Inspector maps Ethernet, IP, transport/control and application metadata |
| Encapsulation | One record can contain Ethernet + IPv4 + UDP + DNS while receiving one primary chart label |
| MAC and IP addresses | Separate link-layer MAC and routed logical IP fields |
| ARP | Request/reply operation and protocol addresses without fabricated ports |
| IPv4/IPv6 | Address version plus TTL or Hop Limit |
| TCP/UDP | Ports, flags, sequence/acknowledgement numbers and datagram comparison |
| ICMP | Echo type/code and absence of TCP/UDP ports |
| DNS | Query/response bit, question name/type and decoded answer summary |
| Traffic measurement | Captured bytes, packets/s and bytes/s over the PCAP time span |
| Wireshark laboratory | The same bundled PCAP can be opened and filtered in Wireshark |

## 3. System Requirements and Tools

- Python 3.11 or 3.12
- Streamlit 1.x for the local user interface
- Scapy 2.x for packet construction, PCAP reading and authorized live sniffing
- Pandas 2.x for tabular aggregation
- Plotly 5/6.x for interactive charts
- pytest and Ruff for automated checks
- Optional Npcap on Windows or capture privileges/libpcap support on Linux for live mode

Demo and imported-PCAP modes need no network connection or administrator rights.

## 4. Architecture and Workflow

```text
              Demo PCAP       Uploaded PCAP       Local interface
                   \               |                /
                    +------ Scapy decode/capture --+
                                      |
                              normalize_packet()
                                      |
                          immutable PacketRecord list
                           /          |             \
                       filters    analytics      inspector
                           \          |             /
                         Streamlit charts, table and CSV
```

The parser, filters and analytics modules contain no Streamlit calls. The live callback writes only to a bounded thread-safe queue. Streamlit's script thread drains that queue and owns all display/session state.

## 5. Methodology

### Packet acquisition

The sample/import path streams classic-PCAP packets through `PcapReader`. Uploads are limited to 20 MiB and 20,000 packets. A temporary upload file is deleted immediately after parsing. Live mode creates one `AsyncSniffer` only after the user selects an interface and presses Start.

### Parsing and normalization

Each Scapy packet becomes a frozen `PacketRecord`. The parser detects Ethernet/ARP, IPv4/IPv6, TCP/UDP/ICMP and decoded DNS layers. It stores captured-frame length, UTC timestamp, addresses, ports and relevant control fields. Missing layers remain null. Arbitrary payload bytes are neither stored nor exported.

### Aggregation and visualization

Pure functions calculate metrics, one-second bins, primary protocol counts, top IPs, bidirectional flows and optional heuristic observations. Plotly renders these frames; the packet table and CSV use the identical filtered record list.

## 6. Design Decisions and Equations

Each frame receives one primary label in priority order:

```text
ARP > ICMP/ICMPv6 > decoded DNS > TCP > UDP > Other
```

This prevents a DNS-over-UDP packet being counted twice in one pie chart. Transport metadata still records UDP.

For selected records:

```text
total_packets = record count
total_bytes = Σ captured_frame_length
duration = latest_capture_timestamp − earliest_capture_timestamp
packets_per_second = total_packets / duration
bytes_per_second = total_bytes / duration
bits_per_second = 8 × bytes_per_second
```

Rate is `N/A` if duration is zero. These equations measure observed captured traffic, not physical link capacity or ISP speed.

TCP/UDP flows canonicalize the two endpoint `(IP, port)` pairs so both directions share one key. ARP and ICMP are excluded because they do not form TCP-style port flows.

## 7. Results and Screenshots

The deterministic capture currently produces:

- 80 packets and 5,372 captured frame bytes across 44.2 seconds.
- TCP 35, UDP 19, ICMP 14, DNS 10 and ARP 2 primary labels.
- A genuine SYN, SYN-ACK, ACK sequence in the same four-tuple.
- IPv4, IPv6 and a non-IP ARP example.

**Insert actual screenshot 1:** Demo dashboard with source badge, KPIs and charts.  
**Insert actual screenshot 2:** TCP SYN-ACK selected in Packet Inspector.  
**Insert actual screenshot 3:** DNS-filtered table and matching chart.

Screenshots must be captured from the implemented running application; no UI mockup should be submitted as a result.

## 8. Experiments

### ICMP echo

Filter ICMP in the demo and compare Echo Request with Echo Reply. Observe types 8/0 for IPv4 or 128/129 for IPv6 and note that ICMP has no TCP/UDP ports.

### DNS lookup

Filter DNS and compare QR=0 query records with QR=1 responses. Inspect the visible question name/type and synthetic documentation-range answer. In live mode, `nslookup example.com` may be hidden by caching or encrypted DNS.

### TCP handshake

Filter TCP and inspect the initial SYN, SYN-ACK and ACK sharing the same endpoint pair. Compare flags and sequence/acknowledgement numbers, then inspect later PSH/ACK teaching frames.

### Protocol distribution

Clear filters, compare the five primary categories, then filter one protocol. Confirm the KPI count, chart total, table rows and CSV rows remain consistent.

## 9. Testing and Wireshark Validation

The offline pytest suite covers parser fields, malformed input, DNS, ARP, IPv6, deterministic PCAP bytes/counts, import caps/errors, filtering, rates, timelines, flows, heuristics, CSV privacy and mocked capture lifecycle. `ruff check .` supplies static-quality validation.

Opening `samples/framesight_demo.pcap` in Wireshark should show 80 frames. Wireshark display filters `arp`, `icmp || icmpv6`, `dns`, `tcp` and `udp && !dns` validate the underlying layers. FrameSight's primary chart uses its documented precedence, so it should be compared with intentionally equivalent filters rather than Wireshark's highest-layer display text alone.

## 10. Limitations

- Live capture depends on the selected interface, operating-system driver and privileges.
- Switched networks and Wi-Fi do not automatically expose every other device's traffic.
- TLS/HTTPS content remains encrypted; only visible headers are analyzed.
- PCAPNG is not supported; users must export classic PCAP.
- Imports stop at 20 MiB or 20,000 packets and live retention stops growing at 5,000 records.
- Heuristic observations can have false positives and are not security incident verdicts.
- Very unusual or unsupported link-layer types may produce `Other` records or an import error.

## 11. Conclusion and Future Scope

FrameSight demonstrates practical packet analysis while remaining reliable and explainable for a classroom assessment. Its deterministic sample removes dependence on live network conditions, while its parser and inspector still use real Scapy packet structures. Reasonable future work includes verified PCAPNG support, more ICMPv6 subtype descriptions and carefully bounded additional application decoders. It should not expand into payload interception, decryption or intrusive scanning.

## 12. References

1. Scapy Project, “Usage,” https://scapy.readthedocs.io/en/stable/usage.html
2. Scapy Project, “scapy.utils API,” https://scapy.readthedocs.io/en/stable/api/scapy.utils.html
3. Streamlit, “Fragments,” https://docs.streamlit.io/develop/api-reference/execution-flow/st.fragment
4. Streamlit, “Multithreading,” https://docs.streamlit.io/develop/concepts/design/multithreading
5. J. F. Kurose and K. W. Ross, *Computer Networking: A Top-Down Approach*.
