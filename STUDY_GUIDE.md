# FrameSight Study Guide

This guide explains the networking theory, implementation choices, demonstration flow, and likely viva questions for **FrameSight — Network Traffic & Protocol Analyzer**. Study the ideas first, then practice the demonstration until you can explain what every number on the screen means.

## 1. The project in one minute

FrameSight is an educational packet analyzer built with Python, Scapy, Streamlit, Pandas, and Plotly. It accepts three packet sources:

1. **Demo PCAP** — a deterministic, synthetic 80-frame capture bundled with the project.
2. **Imported PCAP** — a user-supplied classic `.pcap` file parsed offline with explicit limits.
3. **Live Capture** — authorized traffic visible to a selected local interface through Scapy `AsyncSniffer`.

Every Scapy packet is converted into an immutable `PacketRecord`. Filters and analytics operate on those normalized records, and the same filtered selection drives the KPIs, charts, table, inspector, flows, heuristic observations, and CSV export.

FrameSight is a packet analyzer. It is not a firewall, deep-packet inspection platform, certified IDS, internet-speed test, or HTTPS decryption tool.

## 2. Architecture and data flow

```text
Demo PCAP ─┐
Upload ────┼──> Scapy decoding ──> normalize_packet() ──> PacketRecord objects
Interface ─┘                                                  │
                                                              ├──> filters
                                                              ├──> analytics
                                                              ├──> flow aggregation
                                                              ├──> heuristic observations
                                                              └──> Streamlit UI / CSV
```

Important source files:

- `app.py` — Streamlit page composition, session state, source switching, and filter controls.
- `framesight/models.py` — immutable packet, summary, flow, and capture data structures.
- `framesight/parser.py` — defensive Scapy packet normalization.
- `framesight/pcap_io.py` — bounded classic-PCAP loading and CSV export.
- `framesight/filters.py` — pure, non-mutating filtering.
- `framesight/analytics.py` — statistics, time bins, endpoint counts, flows, and heuristics.
- `framesight/capture.py` — interface enumeration and thread-safe live capture lifecycle.
- `framesight/educational.py` — explanations, experiments, and OSI mappings.
- `framesight/ui.py` — charts, dashboard, tables, and packet inspector.
- `scripts/generate_demo_pcap.py` — deterministic teaching-capture generator.

### Why separate the modules?

Parsing and analytics should be testable without starting Streamlit or capturing live traffic. Pure functions are easier to reason about, reproduce, and test. The UI consumes results instead of containing networking logic.

## 3. Essential packet terminology

### Packet, frame, segment, and datagram

- **Frame** usually means a Layer-2 unit, such as an Ethernet frame.
- **Packet** usually means a Layer-3 IP packet, but packet analyzers often use the word generically for any captured unit.
- **Segment** is commonly used for TCP at Layer 4.
- **Datagram** is commonly used for UDP or IP because each unit is independently handled.

FrameSight uses “packet record” as a convenient generic term while preserving the actual protocol layers in separate fields.

### Header and payload

A header contains protocol control information such as addresses, ports, flags, and lengths. The payload carries the next layer or application data. FrameSight parses selected headers but deliberately does not retain arbitrary raw payload bytes in normalized records or CSV exports.

### PCAP

PCAP is a file format containing captured packet bytes plus timestamps and capture metadata. FrameSight supports classic PCAP. It rejects PCAPNG rather than falsely claiming support.

## 4. Encapsulation, OSI, and TCP/IP

Encapsulation means that each lower layer wraps higher-layer data:

```text
Ethernet frame
└── IPv4 or IPv6 packet
    └── TCP segment / UDP datagram / ICMP message
        └── DNS or other application data
```

The OSI model has seven conceptual layers. The practical TCP/IP model groups them into fewer layers:

| OSI layer | TCP/IP layer | Evidence visible in FrameSight |
|---|---|---|
| 7 Application | Application | Decoded DNS question/response metadata |
| 4 Transport | Transport | TCP flags and ports, UDP ports, ICMP control information |
| 3 Network | Internet | IPv4/IPv6 addresses and TTL/Hop Limit |
| 2 Data Link | Network Access | Ethernet MAC addresses and ARP |

FrameSight does not pretend that an ordinary packet exposes separate Session and Presentation headers.

## 5. Ethernet and MAC addressing

Ethernet provides local-link frame delivery. Its key fields in this project are:

- Source MAC address
- Destination MAC address
- Encapsulated protocol type

A MAC address identifies a network interface on a local link. It is not normally routed across the internet. Routers rewrite Layer-2 headers for the next link while Layer-3 IP addressing represents the routed endpoints.

The demo uses synthetic, locally administered MAC addresses beginning with `02:`. The ARP request uses the broadcast destination `ff:ff:ff:ff:ff:ff` because the sender does not yet know the target MAC.

## 6. ARP

Address Resolution Protocol maps an IPv4 address to a MAC address on the local network.

Typical exchange:

1. A host broadcasts: “Who has `192.168.50.1`?”
2. The owner replies with its MAC address.

ARP does not use TCP or UDP, so it has no ports. FrameSight keeps IP and port fields null for ARP instead of inventing values. It stores the ARP operation, sender IP, and target IP separately.

Demo packets:

- Packet `#0001` — ARP Request
- Packet `#0002` — ARP Reply

## 7. IPv4 and IPv6

IP provides logical addressing and routing between networks.

### IPv4

- Uses 32-bit addresses such as `192.168.50.10`.
- Uses **TTL (Time To Live)** as a hop counter.
- Each router reduces TTL; a packet is discarded when it reaches zero.

TTL is not elapsed time. Its purpose is to prevent endless routing loops.

### IPv6

- Uses 128-bit addresses such as `2001:db8:50::10`.
- Uses **Hop Limit**, which serves the same loop-prevention role as IPv4 TTL.
- Uses hexadecimal notation and supports address compression with `::`.

The demo uses `2001:db8::/32`, reserved for documentation, so it does not represent real public hosts.

## 8. Ports and transport endpoints

TCP and UDP use 16-bit port numbers from 0 to 65535. An IP address identifies a host or interface; a port helps identify a communication endpoint or service inside that host.

Examples:

- DNS commonly uses port 53.
- HTTP commonly uses TCP port 80.
- HTTPS commonly uses TCP port 443.

A port number is a hint, not proof of an application protocol. FrameSight labels DNS only when Scapy actually decodes a DNS layer. The demo TCP conversation uses port 80 for teaching but its synthetic payload is not claimed to be a valid HTTP exchange.

## 9. TCP

Transmission Control Protocol provides a connection-oriented byte stream with ordering, acknowledgements, retransmission, flow control, and congestion-control behavior.

### TCP three-way handshake

1. **SYN** — the client requests a connection and sends an initial sequence number.
2. **SYN-ACK** — the server accepts and acknowledges the client's sequence.
3. **ACK** — the client acknowledges the server's sequence.

Exact demo packets:

- Packet `#0014` — SYN
- Packet `#0015` — SYN, ACK
- Packet `#0016` — ACK

### Sequence and acknowledgement numbers

- A sequence number identifies a byte position in the TCP stream.
- An acknowledgement number states the next byte expected from the peer.
- A SYN consumes one sequence number even without application data.

### TCP flags used by the parser

- `SYN` — start and synchronize a connection.
- `ACK` — acknowledgement field is valid.
- `FIN` — orderly connection close.
- `RST` — immediate connection reset.
- `PSH` — request prompt delivery to the application.
- `URG`, `ECE`, `CWR`, `NS` — additional control/congestion-related flags.

The demo contains 35 TCP frames: three handshake frames, sixteen teaching-data frames, and sixteen acknowledgements.

## 10. UDP

User Datagram Protocol is connectionless. It sends independent datagrams and does not provide TCP's built-in ordering, acknowledgement, retransmission, or handshake.

Advantages include a small header and low protocol overhead. Reliability, ordering, or timing logic must be supplied by the application when required.

The demo contains:

- 13 IPv4 non-DNS UDP frames.
- 6 IPv6 UDP frames.
- 10 DNS frames carried over UDP but classified as DNS in the primary protocol chart.

Therefore the primary chart reports 19 UDP packets, not 29: decoded DNS receives its own mutually exclusive primary label.

## 11. ICMP and ping

Internet Control Message Protocol carries network control and diagnostic messages. It uses types and codes rather than TCP/UDP ports.

Common echo values:

| Protocol | Request | Reply |
|---|---:|---:|
| ICMPv4 | Type 8 | Type 0 |
| ICMPv6 | Type 128 | Type 129 |

`ping` typically sends an Echo Request and waits for an Echo Reply. A missing reply does not prove that a host is offline; firewalls, routing, permissions, or rate limiting may suppress ICMP.

Demo packets `#0006` and `#0007` are the first IPv4 Echo Request/Reply pair. The complete demo has 8 ICMPv4 and 6 ICMPv6 frames, reported together as 14 ICMP primary labels.

## 12. DNS

Domain Name System maps names to resource records.

FrameSight extracts:

- Query name
- Query type, such as `A` or `AAAA`
- Query/response state from the QR bit
- A safe summary of the first decoded answer

`QR=0` means query and `QR=1` means response. The demo has five query/response pairs, for 10 DNS frames total. Packets `#0010` and `#0011` are the first pair.

Traditional DNS is often visible over UDP port 53, but caching, DNS over HTTPS, DNS over TLS, VPNs, or another interface can hide it during live capture.

## 13. TLS and HTTPS limitation

TLS encrypts application content. A normal packet capture may still expose metadata such as IP addresses, ports, timing, packet sizes, and TCP flags, but FrameSight cannot recover HTTPS plaintext or passwords from ordinary encrypted traffic.

Never claim that the project decrypts HTTPS. That would be technically inaccurate and outside its scope.

## 14. Packet normalization

`normalize_packet(packet, packet_id)` converts a variable Scapy packet into one predictable frozen `PacketRecord`.

Important normalized fields include:

- Packet ID and UTC-aware timestamp
- Captured frame length
- Ethernet source/destination MAC
- ARP fields
- IPv4/IPv6 source/destination and TTL/Hop Limit
- TCP/UDP ports
- TCP flags, sequence, and acknowledgement numbers
- ICMP type, code, and friendly label
- DNS question/response metadata
- Capture interface
- Safe summary

Missing fields remain `None` and appear as `N/A` in the UI. Raw payload data is not stored.

### Defensive parsing

Scapy and capture files may contain missing, malformed, truncated, or unusual fields. Helper functions safely convert integers and text. Unknown layers become `Other` where possible. During PCAP import, one packet failure is isolated so valid earlier packets remain usable.

### Timestamp handling

Capture timestamps are normalized to timezone-aware UTC internally. UI display uses local time with milliseconds. Offline plots use historical PCAP timestamps; they do not pretend the capture happened now.

### Length definition

`length_bytes = len(bytes(packet))` measures serialized captured frame bytes. It is not application payload length, guaranteed physical wire size, link speed, or internet bandwidth.

## 15. Mutually exclusive primary protocol

A single frame can contain Ethernet + IPv4 + UDP + DNS. Counting every layer in one pie chart would count one frame multiple times.

FrameSight assigns exactly one primary label in this order:

```text
ARP > ICMP/ICMPv6 > decoded DNS > TCP > UDP > Other
```

The separate normalized fields still preserve every observed layer. Primary labeling is only a visualization rule for consistent totals.

## 16. Filters and synchronized outputs

`PacketFilters` is immutable and supports:

- Primary protocol
- Source IP
- Destination IP
- Exact or contains IP matching
- Either source or destination port
- Summary/DNS keyword
- Capture time range

`filter_records()` returns a new list and does not mutate the source data. Every dashboard output consumes the same filtered list, which is why “Showing X of Y,” KPIs, charts, packet rows, flows, inspector choices, heuristics, and CSV remain synchronized.

## 17. Analytics and equations

For the current selection:

```text
total_packets = number of selected records
total_bytes = sum of captured frame lengths
duration = latest timestamp − earliest timestamp
packets_per_second = total_packets / duration
bytes_per_second = total_bytes / duration
bits_per_second = 8 × bytes_per_second
mean_packet_size = total_bytes / total_packets
```

If duration is zero, rates are `N/A` instead of dividing by zero.

For the FrameSight demo:

- Packets: 80
- Captured bytes: 5,372 bytes, displayed as approximately 5.25 KiB
- Timestamp span: 44.2 seconds
- Packet rate: approximately 1.81 packets/s
- Byte rate: approximately 122 bytes/s
- Unique normalized IP endpoints: 7

These are observed capture rates, not physical bandwidth or ISP speed.

### Time series

Pandas groups records into ordered one-second bins. Empty seconds remain visible so bursts and gaps are meaningful. Live mode restricts the timeline to a rolling 60-second view.

### Top endpoints

Source and destination IP counts are calculated separately. ARP sender/target addresses are not treated as ordinary IP-layer source/destination fields.

## 18. Bidirectional flows

FrameSight groups TCP and UDP conversations using:

```text
(IP version, transport, endpoint A, endpoint B)
```

Each endpoint includes `(IP address, port)`. The pair is sorted into a canonical order so both directions share one flow key.

ARP and ICMP are excluded because they do not form TCP/UDP port-based flows. Flow output includes packet count, byte count, first seen, and last seen.

## 19. Heuristic observations

The Signals tab can identify:

- A high number of packets from one source within a time window.
- Many distinct destination ports from one source within a time window.

Default thresholds are 25 packets in 10 seconds and 10 destination ports in 60 seconds. These are tunable heuristics, not proof of scanning, denial of service, malware, or any security incident. Normal applications can cross the thresholds.

## 20. Safe PCAP import

Import safeguards include:

- Classic `.pcap` extension and magic-value validation.
- Explicit rejection of PCAPNG.
- Maximum upload size of 20 MiB.
- Maximum of 20,000 parsed packets.
- Streaming through Scapy `PcapReader`.
- One extra read boundary to detect truncation.
- A short-lived temporary file removed in a `finally` block.
- Preservation of successfully normalized records if a later record fails.

CSV exports contain normalized metadata only. They still may contain sensitive IP addresses, MAC addresses, DNS names, ports, and timestamps, so they must be handled responsibly.

## 21. Live capture design

Scapy `AsyncSniffer` runs outside Streamlit's script thread. Its callback must never call `st.*`.

The callback:

1. Assigns a monotonic packet ID.
2. Normalizes the packet.
3. Places the record in a thread-safe bounded queue.

The Streamlit script thread drains the queue and owns session/UI state.

Bounds:

- Queue capacity: 1,000 records
- Retained live records: 5,000
- Visible queue and retention drop counters

A lock protects shared controller state. A monotonic clock measures capture duration because wall-clock changes should not make elapsed duration jump backward.

### Why live capture may fail

- Windows may require Npcap and suitable privileges.
- Linux may require libpcap support or capture capabilities.
- The wrong interface may be selected.
- There may be no visible traffic.
- Switches and Wi-Fi isolation limit visibility.

The Demo and Import modes are intentionally reliable fallbacks.

## 22. Streamlit execution model

Streamlit reruns the Python script after widget interactions. `st.session_state` preserves the active source, records, filters, and capture controller between reruns.

The code prevents duplicate live sniffers, stops capture before source changes, and keeps stopped capture data visible. A one-second fragment refresh drains live data without starting parallel capture workers.

## 23. Deterministic demo PCAP

The generator uses fixed packets, addresses, sequence numbers, timestamps, and ordering. Running it twice produces byte-for-byte identical output.

Story breakdown:

| Story | Frames |
|---|---:|
| ARP request/reply | 2 |
| ICMPv4 echo | 8 |
| DNS query/response | 10 |
| TCP handshake/data/ACK | 35 |
| IPv4 non-DNS UDP | 13 |
| IPv6 UDP | 6 |
| ICMPv6 echo | 6 |
| **Total** | **80** |

Primary-label totals:

```text
TCP   35
UDP   19
ICMP  14
DNS   10
ARP    2
```

The capture uses private or documentation address ranges and harmless teaching strings, not recorded user traffic.

## 24. Automated testing

The offline test suite checks:

- Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, and DNS extraction
- TCP SYN-ACK flag decoding
- Invalid DNS bytes and unknown frames
- Timezone-aware timestamps and safe summaries
- Deterministic demo generation and exact story counts
- PCAP magic, size, packet limits, corrupt input, and truncation behavior
- Filter consistency
- Empty and zero-duration statistics
- Ordered time bins
- CSV payload privacy
- Flow aggregation and heuristic thresholds
- Live-capture lifecycle, duplicate-start prevention, and drop counters using mocked sniffers
- Streamlit import/smoke behavior where the runtime supports it

Ruff checks code quality, and GitHub Actions runs generation, linting, tests, and imports on Python 3.11 and 3.12.

## 25. Exact commands

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python scripts\generate_demo_pcap.py
python -m streamlit run app.py
```

Verification:

```powershell
python -m framesight.pcap_io samples\framesight_demo.pcap
pytest -q
ruff check .
```

## 26. Professor-ready 5–7 minute demonstration

### Minute 0–1: Introduce the project

Say:

> FrameSight is an educational network traffic analyzer. It uses Scapy to decode real packet structures and Streamlit to present synchronized analytics and header inspection. The default source is a deterministic synthetic PCAP, so the demonstration is repeatable without administrator rights or internet access.

Point to the **DEMO SAMPLE** source badge.

### Minute 1–2: Explain the dashboard

Show:

- 80 packets
- About 5.25 KiB captured data
- Approximately 1.81 packets/s
- Approximately 122 B/s
- Seven normalized IP endpoints

Say that rates use the 44.2-second PCAP timestamp span and are not internet speed. Point to the one-second timeline and mutually exclusive protocol donut.

### Minute 2–3: Demonstrate encapsulation

Open packet `#0014` after selecting TCP.

Show Ethernet MAC addresses, IPv4 addresses and TTL, then TCP ports, SYN flag, and sequence number. Explain Ethernet → IP → TCP encapsulation and the OSI/TCP-IP mapping.

### Minute 3–4: Demonstrate the TCP handshake

Select packets `#0014`, `#0015`, and `#0016` in order.

Explain SYN → SYN-ACK → ACK, direction reversal, and how sequence/acknowledgement numbers establish connection state.

### Minute 4–5: Compare protocols

Filter ICMP and inspect packets `#0006` and `#0007`. Explain type/code and why ports are `N/A`.

Filter DNS and inspect packets `#0010` and `#0011`. Explain QR=0 versus QR=1, the question name, answer, and DNS-over-UDP layering.

### Minute 5–6: Prove synchronized filtering

Filter DNS or search for `192.168.50.53`. Point out “Showing X of Y.” Confirm the KPIs, charts, table, inspector choices, and exported CSV all use the same selection.

Open the Flows tab and explain direction-independent TCP/UDP grouping. Open Signals and explicitly call them tunable observations, not attack verdicts.

### Minute 6–7: Import/live mode, Wireshark, and limits

Download or import `samples/framesight_demo.pcap` and show that the same 80 records appear. If live capture is available, briefly start and stop an authorized interface capture. Otherwise state the driver/privilege limitation honestly and use the designed offline path.

Finish with:

> FrameSight does not decrypt HTTPS, capture traffic that the interface cannot see, or replace Wireshark. Its purpose is a smaller, explainable implementation of packet parsing, filtering, traffic measurement, and protocol behavior.

## 27. Demo recovery plan

If anything goes wrong:

1. Return to **Demo PCAP**.
2. Click **Reload sample data**.
3. Confirm 80 packets.
4. Use packet IDs `1–2`, `6–7`, `10–11`, and `14–16` for ARP, ICMP, DNS, and TCP respectively.
5. If live capture fails, explain Npcap/privilege/interface constraints and continue with Import or Demo mode.
6. If the projector is small, collapse filters after setting one and use browser zoom carefully.

Never fake a successful live capture or claim that historical PCAP timestamps are current.

## 28. Rapid viva answers

1. **Why Scapy?** It exposes protocol layers, supports PCAP reading/writing, and provides asynchronous sniffing in Python.
2. **Why Streamlit?** It provides a fast, interactive Python UI while leaving parsing and analytics in testable modules.
3. **Why immutable records?** They prevent accidental mutation and make filters/analytics deterministic.
4. **Why UTC internally?** It avoids mixing naive and timezone-dependent timestamps during comparison and aggregation.
5. **Why one primary label?** It prevents multilayer packets from being counted more than once in a single distribution.
6. **Why is ARP not given ports?** ARP is not TCP or UDP and has no transport endpoints.
7. **Why can DNS be UDP but appear as DNS?** Transport and application layers are stored separately; primary labeling favors decoded DNS.
8. **Why not infer DNS from port 53?** Ports are conventions, while decoded headers provide stronger evidence.
9. **Why is TTL not time?** Routers decrement it per hop; it prevents loops.
10. **TCP versus UDP?** TCP offers a reliable ordered byte stream; UDP offers independent datagrams without those guarantees.
11. **What does ACK mean?** It indicates that the acknowledgement number is valid and reports the next expected byte.
12. **Why does SYN consume sequence space?** TCP treats SYN as occupying one sequence number when establishing state.
13. **Why no ICMP ports?** ICMP is a network control protocol with types and codes, not process ports.
14. **Why might ping fail?** ICMP may be filtered, unrouted, rate-limited, or invisible to the selected interface.
15. **Why might DNS be missing?** Cache, encrypted DNS, VPN routing, another interface, or capture permissions.
16. **Can FrameSight read HTTPS text?** No; TLS encrypts application content.
17. **What is captured length?** The serialized bytes Scapy exposes for the captured frame.
18. **What happens with a corrupt packet?** Import isolates individual normalization errors and preserves good records when possible.
19. **Why cap imports?** To bound memory and processing time for an interactive teaching tool.
20. **Why a bounded live queue?** Capture callbacks must not grow memory without limit when the UI drains more slowly.
21. **Why use a lock?** The sniffer callback and UI thread access shared controller state.
22. **Why a monotonic clock?** Elapsed duration should not be affected by wall-clock adjustments.
23. **What is a flow?** A direction-independent grouping of the same TCP/UDP endpoint pair and transport/IP version.
24. **Are signals attacks?** No; they are threshold-based patterns that require context and can have false positives.
25. **Why deterministic sample data?** It makes counts, packet IDs, timestamps, tests, and demonstrations reproducible.
26. **Why compare with Wireshark?** It independently validates that the PCAP contains the same protocol structures and counts.
27. **Why is live capture local-only?** The sniffer can only observe packets exposed to the selected interface and allowed by the operating system.
28. **Does promiscuous mode reveal the whole LAN?** No; switching, wireless isolation, encryption, and network topology still restrict visibility.
29. **What remains sensitive without payloads?** Addresses, DNS names, ports, timestamps, and traffic patterns.
30. **Biggest limitation?** It intentionally supports a bounded educational subset instead of Wireshark-scale protocol coverage and indexing.

## 29. Claims to avoid

Do not say:

- “This measures my internet speed.”
- “This detects hackers.”
- “This decrypts HTTPS.”
- “This sees everyone on the Wi-Fi.”
- “Every port 53 packet is definitely DNS.”
- “UDP is always faster.”
- “The demo is live traffic.”

Prefer precise statements about captured scope, decoded headers, observed rates, and heuristic limitations.

## 30. Final revision checklist

Before the viva, make sure you can explain:

- Encapsulation and the OSI/TCP-IP mapping
- MAC versus IP versus port
- ARP request/reply
- IPv4 TTL and IPv6 Hop Limit
- TCP handshake, flags, sequence, and acknowledgement numbers
- UDP tradeoffs
- ICMP types/codes and ping
- DNS QR bit and query types
- TLS visibility limits
- Primary-label precedence
- Rate equations and zero-duration handling
- Filters, flows, and heuristic limitations
- Bounded imports and live capture threading
- Exact demo counts and packet IDs
- Why every major design decision improves correctness or reliability

Practice the seven-minute flow twice using only the bundled demo. Live capture should be treated as an optional bonus, not a dependency for a successful presentation.
