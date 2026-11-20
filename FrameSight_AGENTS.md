# AGENTS.md — FrameSight: Computer Networks Mini Project

> **Instructions for autonomous coding agents (Cursor / Windsurf / Copilot / Claude Code / other IDE agents).**
> Read this entire document before writing code. Implement the actual project in the current workspace. Do not merely propose an architecture, generate a UI mockup, or stop after scaffolding. Work in small, testable milestones, run the tests, fix errors, and provide a reproducible demo. If a detail is unspecified, choose the simplest reliable implementation consistent with this document.

**Project name:** FrameSight — Network Traffic Analyzer & Protocol Visualization System  
**Course:** Computer Networks, B.Tech CSE, Year 3, NSUT (V semester syllabus)  
**Project type:** Individual/group-friendly undergraduate mini-project  
**Implementation language:** Python 3.11+  
**Primary goal:** Demonstrate actual Computer Networks concepts through a reliable, attractive, explainable application rather than a generic web dashboard.

---

## 0. EXECUTION CONTRACT — READ FIRST

You are the senior full-stack/Python/networking engineer implementing this educational mini-project. **Build, test, document, and polish it.**

### Non-negotiable outcomes

1. A working **Streamlit** application that starts with one documented command after setup.
2. Three explicit data modes:
   - **Demo dataset:** ready-to-use, deterministic, locally bundled sample PCAP. This is labeled **DEMO / SAMPLE DATA** everywhere relevant. No admin rights or internet needed.
   - **PCAP analysis:** upload/import `.pcap` capture file and analyze it offline. No admin rights needed.
   - **Live capture:** choose an available interface and capture local/authorized traffic using Scapy. Graceful handling when privileges/Npcap/libpcap are missing.
3. Proper **real packet parsing** using Scapy, not random values or fake metrics. Deterministic sample data is allowed only in clearly labeled demo mode.
4. Real **protocol explanations** and a packet inspector demonstrating OSI/TCP-IP concepts. Strong viva focus.
5. Functional filters, charts, stats, CSV export, start/stop capture, clean empty/error states.
6. Automated tests for parser, aggregation, filtering, file import and sample data (offline, no root required).
7. High-quality README, short report, and a 5–7-minute professor presentation script.
8. No placeholder buttons, mock-only results, broken controls, hidden magic assumptions, or unnecessary infrastructure.

### Priority

**Correctness > Demonstrable networking concepts > Reliability > Clean UI > Extra features.**

Keep the application practical for a college mini-project. No cloud services, login/authentication, database, Docker, machine learning, packet injection, or complicated distributed architecture are required. Avoid scope creep.

### Definition of complete

Do not claim completion until:
- `python scripts/generate_demo_pcap.py` succeeds and produces reproducible sample data;
- `pytest -q` passes;
- the app can launch with `streamlit run app.py` and imports without exceptions;
- demo PCAP loads and shows nonzero correct metrics;
- protocol and IP filtering changes both table and relevant filtered charts/statistics consistently;
- CSV download contains the currently filtered rows;
- a packet selection opens details and explains corresponding layers;
- start/stop live-capture paths are implemented (graceful error if unavailable);
- README commands and the recorded demo walkthrough match the implemented functionality.

Where a GUI cannot be visually inspected in the agent's environment, verify imports, unit/integration tests, and a headless Streamlit smoke test when feasible; say clearly what has/has not been visually verified.

---

## 1. WHY THIS PROJECT FITS THE COURSE

The supplied **NSUT Computer Networks syllabus, page 4**, explicitly includes mini-project suggestions:
- Network Traffic Analysis & Packet Sniffing
- VLAN and Network Segmentation
- Dynamic Routing Simulation
- Secure Web Server with TLS

FrameSight implements **Network Traffic Analysis & Packet Sniffing**, aligned with the Wireshark laboratory exercises covering ARP, ICMP, DHCP, congestion/packet loss and packet analysis. Earlier syllabus units cover OSI/TCP-IP, Ethernet, IPv4 and IPv6, TCP/UDP, DNS/HTTP, and network security.

### Concepts the professor must see

| Networking concept | Where it appears in FrameSight | How to demonstrate |
|---|---|---|
| Encapsulation; OSI/TCP-IP model | Packet Inspector / "Layers Explained" | Open Ethernet → IP → TCP/UDP → application metadata |
| MAC vs IP address | Header details | Compare Layer-2 MAC fields to Layer-3 IP fields, when present |
| IPv4, IPv6 and addressing | Packet list, filters, header details | Show source/destination and version; IPv6 if sample includes it |
| TCP vs UDP | Protocol distribution, header details | Compare TCP flags/ports with UDP datagram |
| TCP three-way handshake | TCP flags view, demo PCAP | Explain SYN → SYN-ACK → ACK, provided capture contains all three |
| ICMP | ICMP subtype, packet table | Demonstrate Echo Request/Reply; use `ping` in live mode if available |
| DNS | DNS query/response fields | Demonstrate `nslookup example.com` in live mode if visible, or sample PCAP |
| Traffic measurement | Packet-rate, byte-rate charts | Explain packets/s versus bytes/s and capture scope |
| Packet inspection / security | Protocol information; basic heuristic | Show alerts are **heuristics**, not a certified IDS |
| Wireshark validation | README / demo instructions | Open same PCAP in Wireshark and compare packet records/counts |

**Important truthfulness:** FrameSight is a *packet analyzer*, not a deep packet inspection system, network-wide router monitor, real firewall, or an AI intrusion detection system. Do not claim to decrypt TLS/HTTPS or inspect everyone on a shared Wi-Fi network.

---

## 2. PROJECT SCOPE

### 2.1 Required features (MUST)

**A. Three working sources**

- A clearly labeled **Demo PCAP** load button. On first use, make the demo the default source so a professor can explore instantly.
- Upload a user `.pcap` file, validate extension and size, parse defensively, and show friendly errors for empty/corrupt/unsupported input.
- Live capture via a user-selected local interface, with **Start**, **Stop**, visible status, capture duration, and permission/error handling. Live data updates about once per second without blocking the UI.

**B. Core packet fields**

- Timestamp (human-readable with milliseconds), packet length in bytes, source/destination addresses (IPv4/IPv6 when present), source/destination ports when applicable, source/destination MAC when present, network/transport/application protocol classifications, TCP flags, TTL/hop limit if available, protocol summary.
- For DNS: query name, query/response status, query type and optional answer summary where decoded/available.
- For ICMP: type and code, friendly labeling for Echo Request/Reply when identifiable.
- Explicit `N/A` or null for absent information; never invent ports or IPs for ARP.

**C. Dashboard**

- Summary KPIs: Total Packets, Total Captured Bytes, Observed Average Bytes/s, Observed Packets/s (well-defined window), Unique IPs. Optionally TCP/UDP share.
- Charts: packets over time, captured bytes over time, mutually exclusive **primary protocol** distribution, top source/destination IPs.
- Packet table with timestamp, source → destination, protocol, source/destination ports, length, and short info. Sort/filter/search by protocol/IP/port/time where practical.
- Packet detail/inspector with expandable layer fields and an educational "what this header means" explanation.
- CSV export of normalized **filtered** records, excluding raw payloads.
- Concise, clear capture-source badge: `DEMO SAMPLE`, `IMPORTED PCAP`, or `LIVE CAPTURE`.

**D. Exploration & viva**

- Explanatory "Learn the Concepts" section covering Ethernet, IP, TCP, UDP, ICMP, DNS, basic TLS limitation, and difference between OSI and TCP/IP.
- In UI or documentation, give three named mini-experiments: ICMP ping, DNS lookup and TCP connection/handshake.
- Easy comparison with Wireshark: same sample PCAP available to download/open externally, documented how to validate matching data.

### 2.2 Optional enhancements (SHOULD, only after MVP)

- A lightweight **flow view**, grouping traffic by a clearly defined bidirectional 5-tuple: `(IP version, transport, IP1, port1, IP2, port2)` normalized for either direction; show packet and byte counts. Do not group ICMP and ARP falsely into TCP-style flows.
- Simple **heuristic alerts** such as unusual number of packets from one source in a chosen time window, or many distinct destination ports (a pattern worth investigating). Thresholds must be visible, tunable and described as heuristics; do not claim proof of an attack.
- Helpful "Capture notes" panel: `local interface only`, `not all traffic observable`, `HTTPS is encrypted`.

### 2.3 Explicitly out of scope (DO NOT implement)

- Intrusive or stealth capture of other users; credential collection; payload reconstruction; decrypting HTTPS; scanning external networks; packet crafting/injection as an attack feature.
- Deep learning, trained anomaly detection, SIEM, SOC workflow, massive PCAP indexing, cloud dashboards, auth/database, or external network dependency.
- A clone of every Wireshark feature.

---

## 3. TECHNOLOGY CHOICES

Use a lean, well-established Python stack:

| Component | Required tool | Reason |
|---|---|---|
| UI/web app | Streamlit | Fast, polished Python-native dashboard |
| Packet decode / live capture | Scapy | Exposes packet layers and supports sniffing/PCAP reading |
| Analysis | Python standard library, Pandas | Aggregation and tabular filtering |
| Visualization | Plotly | Interactive charts |
| Tests | pytest | Repeatable networking logic tests |
| Code quality | Ruff (optional but preferred) | Consistent style, low effort |

Use a Python virtual environment; provide **requirements.txt** with tested, reasonably bounded dependencies. Avoid unnecessary packages. Use standard Scapy APIs (e.g., `AsyncSniffer`, `PcapReader`, `wrpcap`) after checking installed-version compatibility.

**Platforms:** Target Windows 10/11 and Linux; keep macOS best-effort. Windows live capture may require **Npcap** and administrative access. Linux may require capture privileges and libpcap-related dependencies. The demo and PCAP modes must work without admin rights.

---

## 4. ARCHITECTURE & DATA FLOW

### 4.1 Data flow

```text
          ┌────────────────┐    ┌───────────────────┐    ┌────────────────────┐
          │ Demo .pcap     │    │ User .pcap upload │    │ Live interface     │
          └──────┬─────────┘    └────────┬──────────┘    └─────────┬──────────┘
                 │                       │                         │
                 └───────────────────────┼─────────────────────────┘
                                         ▼
                            Scapy packet decoding
                                         │
                                         ▼
                              normalize_packet()
                                         │
                           Typed normalized records
                                         │
                        ┌────────────────┴───────────────┐
                        ▼                                ▼
                    Aggregations                        Filters
                        │                                │
                        └────────────────┬───────────────┘
                                         ▼
                     Streamlit Dashboard / Inspector / CSV
```

### 4.2 Separation of concerns

**Keep Scapy parsing, aggregation, and filtering independent of Streamlit** so they can be unit-tested offline. Never put all logic inside `app.py`.

Suggested project structure (reasonable changes allowed if justified):

```text
framesight/
├── AGENTS.md                        # This specification
├── app.py                           # Streamlit entry point and page composition
├── requirements.txt
├── README.md                        # Setup, run, demos, architecture, limitations
├── PROJECT_REPORT.md                # Submission-ready college mini-project report
├── VIVA_GUIDE.md                    # Questions, answers and demos
├── .gitignore
├── .streamlit/
│   └── config.toml                  # Theme; no external secrets
├── framesight/
│   ├── __init__.py
│   ├── models.py                     # Typed PacketRecord, enum/literals, metrics
│   ├── parser.py                     # Scapy packet -> PacketRecord
│   ├── pcap_io.py                    # Safe PCAP import / export helper
│   ├── capture.py                    # Live CaptureController and safe lifecycle
│   ├── analytics.py                  # Pure aggregations + time binning
│   ├── filters.py                    # Pure filtering/search functions
│   ├── educational.py                # Header/OSI concept explanations
│   └── ui.py                         # Reusable visual/chart components
├── scripts/
│   └── generate_demo_pcap.py         # Deterministic sample capture generator
├── samples/
│   └── framesight_demo.pcap            # Small generated demo PCAP (commit it)
└── tests/
    ├── conftest.py
    ├── test_parser.py
    ├── test_pcap_io.py
    ├── test_analytics.py
    ├── test_filters.py
    └── test_demo_capture.py
```

Avoid name collisions between `framesight/` package and the root; structure above is intentional.

### 4.3 PacketRecord model

Use a Python `@dataclass(frozen=True)` or equivalent typed immutable model with fields:

```text
packet_id: int                        # local increasing ID, assigned on ingestion
capture_time: datetime              # timezone-aware or consistently normalized
length_bytes: int                   # captured packet length, documented semantics
l2_protocol: str | None             # e.g. Ethernet
src_mac: str | None
dst_mac: str | None
network_protocol: str               # IPv4, IPv6, ARP, Other
src_ip: str | None
dst_ip: str | None
ip_ttl_or_hop_limit: int | None
transport_protocol: str | None      # TCP, UDP, ICMP, ICMPv6, None
src_port: int | None
dst_port: int | None
application_protocol: str | None    # DNS when Scapy decoded DNS, etc.
tcp_flags: str | None               # SYN, ACK, etc., readable names
icmp_type: int | None
icmp_code: int | None
dns_query_name: str | None
dns_is_response: bool | None
dns_query_type: str | None
summary: str                        # safe, short, informative (no raw payload)
```

Additional fields may be added for DNS answer count, ARP operation, TCP seq/ack numbers, capture interface, or packet id. **Do not store raw payload bytes in normalized records.** Packet details are based on parsed headers only.

### 4.4 Protocol classification — avoid a common bug

Protocols operate at different layers, so a packet may simultaneously be **IPv4 + UDP + DNS**. Do **not** incorrectly count this as three packets in a single pie chart.

Maintain separate fields as above. Define one **mutually exclusive `primary_label`** for the main chart, using a documented priority like:

1. ARP
2. ICMP / ICMPv6
3. DNS (only when actually decoded as DNS)
4. TCP
5. UDP
6. Other

Then separately show **transport-layer breakdown** as TCP/UDP/ICMP/other if useful. If a packet is DNS over UDP, it appears as `DNS` in the primary chart but as `UDP` in a transport-specific breakdown. Explicitly explain this distinction in a tooltip.

Do not infer application protocol solely from port number. For example, UDP/443 can be QUIC/HTTP/3 and TCP/443 is often TLS, but a port is not proof of application content. Label these as `possible service/port hint` if used at all.

---

## 5. IMPLEMENTATION DETAILS

### 5.1 Packet parser (core educational code)

Implement `normalize_packet(packet, packet_id) -> PacketRecord`:

- Interpret Ethernet/ARP, IPv4, IPv6, TCP, UDP, ICMPv4 and DNS when Scapy layers are present.
- Handle ICMPv6 where practical; unknown layers must not crash.
- Distinguish absence of IP (e.g., ARP) from an unknown IP.
- Handle malformed or truncated packets defensively. A single bad packet must not abort an entire PCAP; count skipped packets and show a summary.
- Decode DNS qnames robustly, tolerating invalid bytes, multiple questions, absent fields, and responses.
- Convert TCP flag bitmasks into readable names. A packet may have multiple simultaneous flags, e.g. `SYN, ACK`.
- For packet lengths use `len(bytes(packet))` or appropriate Scapy length semantics consistently; **state what is being counted** (captured frame bytes, not application payload or guaranteed wire bytes).
- Normalize timestamps carefully. Offline files may have historical timestamps and unusual precision. Use UTC for internal aggregation, readable local display when sensible; avoid mixing aware/naive datetimes.
- Treat missing layer values gracefully (`N/A`).
- Produce a non-sensitive, readable summary with protocol/flags/query and endpoint info; avoid dumping arbitrary payloads.

**Useful parser cases:** IPv4/TCP SYN, IPv4/TCP SYN-ACK, UDP, DNS request, DNS response, IPv4/ICMP echo request/reply, ARP request/reply, IPv6 UDP, unknown Ethernet frames, malformed DNS label.

### 5.2 PCAP import

- Support the `.pcap` format (classic PCAP). Clearly reject `.pcapng` unless verified support is explicitly added. Do not claim `.pcapng` support without implementation/tests.
- Use `PcapReader` or another streaming Scapy reader, closing resources properly; do not load huge files blindly into memory.
- Max uploaded file size: **20 MiB** initially. Max packets parsed: **20,000**; show visible truncation warning and parsed/total-if-known counts. Avoid reading unbounded data.
- Temporary uploaded files should be removed safely after processing; no persistent raw traffic archive.
- Provide `Load Sample Data`, `Upload PCAP`, and `Reset` behaviors with no stale-state leaks between modes.
- Validate format/content and handle `empty file`, `bad magic`, `truncated`, `unsupported link type` or general parsing failures with helpful user messages, not raw tracebacks.
- If Scapy can parse some records but not others, preserve successfully parsed records and report skip counts.

### 5.3 Live capture and Streamlit threading

This requires extra care. Streamlit reruns app scripts after interactions. Do not start a new sniffer on every rerun, and **never call `st.*` from a capture worker thread**.

Design a `CaptureController` (per Streamlit session, or another safely isolated ownership model) that:

- Lists actual local interfaces with a clear display label.
- Starts `AsyncSniffer` / a stoppable sniffing worker for an authorized selected interface.
- Converts incoming Scapy packets into normalized records, then writes them into a thread-safe bounded queue.
- Exposes `start(interface)`, `stop()`, `drain(max_items)`, `status()`, and relevant exception state.
- Protects shared mutable state using a lock where required.
- Has bounded queue + bounded retained records (e.g., maximum 5,000 live packets), a clear drop counter, and no unbounded memory growth.
- Enables reliable Stop even with no traffic; test start/stop twice. Handle `AsyncSniffer.stop()` exceptions/edge cases and report failure clearly.
- Tracks capture duration and doesn't discard data after Stop until the user resets.
- Never silently capture when the user has not explicitly clicked Start.
- Prevents running multiple concurrent captures for a single session.
- Does not persist raw captured payloads to disk.

**Recommended UI refresh:** use `@st.fragment(run_every="1s")` for the live data/metrics section, or a similarly supported Streamlit refresh strategy. The UI thread drains the queue and updates session-local records. Do not implement a blocking `while True` loop in the Streamlit script and do not use UI APIs from a background worker.

On privilege/library failure, display:
- Live capture is unavailable on this machine/selected interface.
- Windows: install/enable Npcap and use appropriate privileges.
- Linux: ensure capture privileges and available pcap backend.
- **Demo and PCAP modes still work**; give a one-click switch.

If the specific environment prevents testing actual live traffic, do not fake successful live capture. Test controller state/lifecycle via mocks and document manual validation steps.

### 5.4 Stats and math definitions

Implement pure, tested aggregation functions (not UI-side ad hoc computations):

- `total_packets = len(filtered_records)`
- `total_bytes = sum(p.length_bytes for p in filtered_records)`
- `unique_ips = count(unique non-null src/dst IPs)`
- `mean_packet_size_bytes = total_bytes / total_packets` (0 or N/A on empty)
- `packet_rate = count / duration_seconds` and `byte_rate = bytes / duration_seconds` for a **well-defined observation interval**.
- `bits_per_second = 8 * bytes_per_second`, labeled as **observed captured traffic rate**, not the physical link capacity or actual bandwidth subscription speed.

**Crucial edge case:** With a single packet or identical timestamps, duration is zero. Avoid division by zero; show `N/A` for overall average rate, or use one-second time bins where appropriate.

**Live mode:** time-window graphs use capture/arrival timeline with ~1-second bins; state whether showing last 60 seconds or full retained capture.

**Offline mode:** charts use **timestamps in the PCAP**, not current wall-clock time. If sample contains non-contiguous intervals, reflect them. Don't claim "live" rates from an imported historical file.

**Filters:** Decide and consistently communicate whether KPI cards summarize all ingested packets or only currently filtered packets. Prefer filtered dataset, with a small separate `Showing X of Y` label. Counts, charts and CSV must share the same filtered selection.

**Protocol percentages:** calculated using mutually exclusive labels, so percentages total approximately 100%, allowing rounding.

### 5.5 Filtering behavior

Implement UI and pure filter functions:

- Main protocol selector: All / TCP / UDP / ICMP / DNS / ARP / Other; explain whether protocol matches primary label or transport.
- Source/destination IP substring/exact search, with reasonable validation.
- Source/destination port filter or a single `either port` filter; blank means all.
- Optional keyword search in summary and DNS query name.
- Reset filters button.
- Empty-results message with `Clear filters` action.
- All updates apply to table, charts and CSV download. Filtering must not mutate original dataset.

### 5.6 Basic alerts (optional, simple)

Only after all must-have functionality works, implement:

- `High packet rate`: source IP exceeds configurable N packets in a sliding interval.
- `Many distinct destination ports`: an IP contacts many ports within a window.

Label them **"Heuristic observations (not security incidents)"**. Thresholds are examples, not proof of malicious activity; normal traffic can trigger them. No attack traffic generator, credential interception or intrusive network behavior.

### 5.7 CSV export and privacy

- Export normalized header metadata only (packet time, src/dst IP, ports, lengths, labels, flags, optional DNS query), not raw payloads or decrypted content.
- File name like `framesight_packets_<source>.csv`.
- Include explicit caveat that even IP addresses and DNS names can be sensitive; export only authorized data.
- No server-side storage of upload files beyond temporary parsing. No telemetry, analytics trackers or network calls to outside APIs.

---

## 6. DEMO PCAP — THE MOST IMPORTANT RELIABILITY FEATURE

Build a deterministic sample generator: `python scripts/generate_demo_pcap.py`.

**The resulting file must be a real, valid Scapy-generated classic PCAP** containing coherent, educational packets. Never generate UI-only fake dictionary rows when demo PCAP is selected.

Include at least:

1. ARP Request / Reply on a simple local network (non-IP Ethernet frames).
2. ICMP Echo Request / Reply with matching source/destination.
3. DNS UDP request for `example.com` and a corresponding DNS response. Query/response flag and record fields must be genuinely parseable.
4. TCP SYN, SYN-ACK, ACK packet sequence for a single flow (with consistent 4-tuple, flags and plausible TCP numbers).
5. TCP data/ACK-like packets without real private payload; if using `Raw`, use harmless public test text only. Do not advertise it as decrypted HTTPS.
6. UDP non-DNS packet.
7. Optional IPv6 example for extra syllabus coverage.

Use **documentation-reserved IP addresses** (e.g. `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) for imagined remote endpoints, and a clearly simulated private LAN (`192.168.50.0/24`) where needed. Avoid representing these as real routable internet hosts. Source/destination MACs should be consistent within the synthetic story.

Timestamps: spaced across ~30–60 seconds with deliberate bursts/quiet periods so timeline charts are visually informative; use deterministic timestamps (not `datetime.now()` on each generation). Include a sensible packet mix (e.g. 60–120 packets) and make the packet/story counts assertable in tests. Avoid enormous PCAP size.

**Important:** Real captured TCP/application semantics are complex. The generator is a *teaching example*, not a real replay of a browser session. Do not claim it documents a real live connection.

Automated tests must:
- Confirm file can be opened/read by Scapy.
- Confirm it contains ARP, ICMP, TCP (including SYN/SYN-ACK/ACK), UDP and DNS.
- Confirm parser produces valid records without exceptions.
- Confirm at least one non-IP packet (ARP) is represented correctly.
- Confirm charts/aggregations work and time bins have nonzero values.

Make the bundled file the **default reliable presentation mode**. A professor should be able to assess the project offline without Npcap/admin privileges or internet connectivity.

---

## 7. UI/UX DESIGN — PROFESSIONAL BUT NOT OVERBUILT

Create an attractive, modern, restrained **network observability** dashboard. It should feel polished enough to demonstrate in class but remain clearly educational.

### Layout concept

```text
┌─────────────────────────────────────────────────────────────────┐
│ FrameSight | Network Traffic & Protocol Analyzer    [DEMO SAMPLE] │
├──────────────────┬──────────────────────────────────────────────┤
│ CAPTURE CONTROLS │  KPIs: Packets | Bytes | Pkt/s | Unique IPs   │
│ Source mode      │──────────────────────────────────────────────│
│ Sample / Upload  │  Packet Rate Timeline                         │
│ Live interface   │───────────────────────┬──────────────────────│
│ Start / Stop     │ Protocol Distribution │ Top Talkers          │
│ Status           │                       │                      │
│                 │───────────────────────┴──────────────────────│
│ FILTERS          │  Searchable/filterable packet table          │
│ Protocol         │  [timestamp | source | dest | proto | bytes]  │
│ IP / Port        │──────────────────────────────────────────────│
│ Clear            │  Packet Inspector: Ethernet / IP / TCP / DNS │
│                 │──────────────────────────────────────────────│
│                 │  Learn Concepts / Mini Experiments / About    │
└──────────────────┴──────────────────────────────────────────────┘
```

### Visual guidance

- Use Streamlit wide layout and a consistent theme in `.streamlit/config.toml`.
- Dark navy / slate with restrained cyan/blue/green highlights is an option; accessibility and readability take priority over dramatic styling.
- Clear typographic hierarchy; avoid overdecorated emojis, excessive animation or distracting gradients.
- Responsive enough for a laptop/projector; charts have titles and units.
- Source mode/status should always be obvious: **DEMO**, **IMPORTED**, **LIVE/CAPTURING**, **STOPPED**.
- Units should be accurate: packet count, bytes, KiB/MiB if using 1024 bases, packet/s, bytes/s or bits/s; no mislabeled rates.
- Protocol chart must sum without double-counting.
- Use a proper empty state and actionable error messages instead of stack traces.
- The packet detail inspector should be useful for the professor to ask "what does this field mean?" and get a clear answer.
- CSV export and optional PCAP download button should be easy to find. Do not auto-write live raw PCAP files.

### Packet inspector educational labels

At least these explanations (one or two sentences each):

- **MAC address:** local link-layer hardware/interface address where applicable; not a global internet address.
- **IP address:** logical network-layer address used to identify endpoints and enable routing.
- **TTL/Hop Limit:** limits how many routers may forward an IP packet; not its elapsed travel time.
- **Port:** transport-layer number identifying the communication endpoint/service on a host.
- **TCP flags:** connection/control signaling such as SYN, ACK, FIN, RST.
- **UDP:** connectionless datagram delivery; no native retransmission/ordering guarantee.
- **ICMP:** control/diagnostic messages; echo request/reply used by ping.
- **DNS:** mapping names to DNS resource records; traditional DNS messages may be parsed if visible.
- **TLS/HTTPS:** application data typically encrypted; FrameSight cannot decrypt it from ordinary packet headers.

Add a simple mapping from observed layers to OSI vs TCP/IP to reinforce syllabus learning. Avoid pretending to detect OSI Session and Presentation layers directly.

---

## 8. EXAMPLE PROFESSOR DEMONSTRATION (5–7 MINUTES)

The application and docs must support exactly this reproducible narrative:

**Minute 0–1: Context**
- Introduce FrameSight as a mini-project addressing packet sniffing and traffic analysis from the CN syllabus.
- Point to selected mode label: `DEMO SAMPLE` (offline, deterministic) and explain live mode separately.

**Minute 1–2: Capture source and main dashboard**
- Load sample PCAP; show total packets/bytes and protocol distribution.
- Explain each packet is classified from real Scapy-parsed headers.

**Minute 2–3: OSI/TCP-IP inspection**
- Select a TCP packet; show Ethernet, IPv4, TCP headers, ports and flags.
- Explain encapsulation and which fields belong to each layer.

**Minute 3–4: TCP handshake and protocol comparison**
- Filter TCP; locate sample SYN, SYN-ACK, ACK in the same conversation.
- Compare an ICMP packet (no TCP/UDP port) and a DNS-over-UDP packet (application over transport).

**Minute 4–5: Analytics and filtering**
- Filter `DNS` or a source IP; show that chart, table and exported CSV now match the filter.
- Discuss the difference between captured packet count, captured bytes and observed throughput.

**Minute 5–6: Live or PCAP mode**
- If privileges allow, switch to live mode and run `ping 8.8.8.8` or `nslookup example.com` (only on authorized local equipment). Explain some packets may be missed if wrong interface, encrypted DNS or cached lookup.
- Otherwise import the bundled PCAP via file picker and show that offline analysis gives the same results. This is a valid demo; do not conceal capture limitations.

**Minute 6–7: Wireshark validation and limitations**
- Compare packet count/types in Wireshark using the same PCAP.
- State: cannot decrypt HTTPS, cannot automatically see all LAN traffic, and alerts are heuristics if enabled.

**Demo instructions must not rely on internet connectivity, a second machine, a remote server, or administrator rights.** Those should only enhance the demo.

---

## 9. TEST PLAN / ACCEPTANCE CRITERIA

**Automated tests must not require a network connection, admin/root privileges, or external services.**

### Parser unit tests

- IPv4 TCP packet: extract src/dst, ports, flags, length and timestamp.
- TCP SYN-ACK produces two readable flags, not just `SYN`.
- IPv4 UDP packet: ports correct; no fabricated TCP flags.
- DNS request/response: correctly decode name and QR bit.
- ICMP Echo: type/code captured; ports remain N/A.
- ARP packet: no IP/ports fabricated; show ARP addresses/operation if available.
- IPv6 packet: handle source/destination and hop limit.
- Unknown/unsupported and malformed input does not crash whole pipeline.

### Analytics unit tests

- Packet counts by mutually exclusive primary label sum to total count.
- Filtered totals, charts data and CSV rows describe the same records.
- Bytes counted consistently and never negative.
- Empty input produces valid zero/empty results without exceptions.
- Single-timestamp/single-packet input never divides by zero.
- Time series is ordered; offline timestamps are not replaced with current time.
- Unique IPs excludes null fields.

### IO integration tests

- Bundled sample PCAP opens, parses and produces useful results.
- Import cap of 20,000 packets (simulate for testing) and file size limit enforced.
- Invalid/empty/truncated PCAP handled with clear domain error.
- Reimport/reset does not double-count or leak stale filters.
- CSV includes fields/rows expected, with payload excluded.

### Capture controller tests

- With mocked Scapy sniffer: start → capturing → stop → stopped.
- Starting twice does not create duplicate sniffer.
- Stop when idle is harmless.
- Worker never calls Streamlit UI functions.
- Queue cap/dropped-record accounting works; no unbounded growth.
- Permission/driver failure surfaces a friendly exception and safe recovery.

### Manual QA checklist

- [ ] Launch app with `streamlit run app.py`.
- [ ] Default demo loads with visibly nonzero statistics and at least 4 protocol categories.
- [ ] Select and inspect ARP, ICMP, DNS, TCP SYN and TCP SYN-ACK packets.
- [ ] Filter protocol, IP and port; packet table and charts update correctly.
- [ ] Clear filters restores original data.
- [ ] CSV download matches table selection.
- [ ] Upload `samples/framesight_demo.pcap`: same results as Load Demo.
- [ ] Upload invalid file: helpful error, no crash.
- [ ] Select live interface: Start/Stop works or helpful no-privilege message appears.
- [ ] Repeated Streamlit reruns do not spawn new sniffers.
- [ ] No raw payload display, no hidden external API calls, no credential storage.
- [ ] Documents accurately reflect implemented features and known limitations.

---

## 10. IMPLEMENTATION PHASES FOR THE AGENT

Work sequentially. Complete and test a phase before the next. Do not spend time on visual polish until functional logic and sample PCAP work.

### Phase 1 — Repository and data model

1. Create folder structure, virtual environment instructions, dependencies, `.gitignore`, theme config.
2. Implement typed PacketRecord model and parser for Ethernet, ARP, IPv4/IPv6, TCP/UDP/ICMP/DNS.
3. Add parser unit tests with small constructed Scapy packets.
4. **Checkpoint:** all parser tests pass.

### Phase 2 — Real demo PCAP and offline analytics

1. Generate valid deterministic sample PCAP.
2. Implement bounded PCAP import, filtering, stats and time series.
3. Unit/integration tests for counts, decoding, errors and CSV.
4. **Checkpoint:** CLI/helper can parse sample and print correct protocol totals without Streamlit.

### Phase 3 — Functional user interface

1. Build Streamlit layout with source-mode selector and sample-load control.
2. Dashboard KPIs, Plotly charts, packet table, protocol/IP/port filters.
3. Packet detail inspector with layer explanations.
4. Upload mode, clear/reset, CSV export.
5. **Checkpoint:** all data comes from parser/analytics, not fabricated UI arrays; every visible control works.

### Phase 4 — Live capture

1. Implement capture controller with `AsyncSniffer` (or compatible stoppable mechanism), safe thread/queue ownership and interface selection.
2. Integrate Start/Stop/status into Streamlit without rerun duplicates.
3. Add bounded retention/drop counters and friendly privilege errors.
4. Add mocked controller tests, manual steps for Windows/Linux.
5. **Checkpoint:** sample/import always works even when live capture cannot.

### Phase 5 — Polish, educational content and submission docs

1. Make charts and labels projector-readable; refine statuses and empty states.
2. Add concept explainer, experiment walkthrough, help for choosing correct interface.
3. Write accurate README, project report and viva guide, including architecture diagram and screenshots instructions.
4. Run all tests, lint and smoke test. Fix regressions.
5. **Checkpoint:** definition of complete is satisfied.

### Phase 6 — Optional enhancements

Only if all prior checkpoints pass, add bidirectional flow view, basic heuristic alerts and their tests. Never trade correctness of core features for extras.

---

## 11. SUBMISSION DOCUMENTS TO CREATE

### `README.md` (usable by another student/professor)

Include:
- Project title and 2–3 sentence objective.
- Screenshot(s) after actual implementation, or instructions for generating screenshots if unavailable.
- Features with honest mode labels.
- Architecture and directory structure.
- Setup for Windows PowerShell and Linux/macOS shells.
- Exact commands to install and start:
  ```bash
  python -m venv .venv
  # Activate the virtual environment for your OS
  pip install -r requirements.txt
  python scripts/generate_demo_pcap.py
  streamlit run app.py
  ```
- Npcap/admin requirements, interface selection advice, fallback import mode.
- Demonstration steps with `ping`/`nslookup` and troubleshooting when no packets are captured.
- Data field glossary and math definitions.
- Project limitations and privacy guidance.
- Exact test command `pytest -q`.
- Links to official Scapy and Streamlit docs (below).

### `PROJECT_REPORT.md` (professor-ready)

A clean mini-project report with these headings:

1. Title page placeholders: Name, Roll Number, Section, Course, Faculty, Institute (NSUT).
2. Abstract (150–200 words; accurately describe project).
3. Problem Statement and Objectives.
4. Course Concept Mapping (OSI/TCP-IP, Ethernet, IPv4/v6, TCP/UDP, ICMP, DNS, Wireshark).
5. System Requirements / Tools.
6. Architecture Diagram and Workflow.
7. Methodology: packet acquisition, parsing, normalization, aggregation, visualization.
8. Design Decisions & Equations.
9. Screenshots/results (use actual generated outputs only; if missing, provide explicit insertion markers).
10. Experiments: ICMP, DNS, TCP handshake, protocol distribution.
11. Testing/Validation against sample PCAP and Wireshark.
12. Limitations (permissions, visibility, encrypted traffic, sampling/retention).
13. Conclusion and modest Future Scope.
14. References (credible documentation, no invented studies or results).

Write naturally, accurately and in concise undergraduate engineering language. Do not fabricate lab measurements or claim features that aren't implemented.

### `VIVA_GUIDE.md`

Include:
- A 5–7 minute spoken demo script matching real app controls.
- 20–25 likely viva questions with correct short answers.
- Key concepts: OSI/TCP-IP, encapsulation, TCP vs UDP, SYN/SYN-ACK/ACK, DNS, ICMP, TTL, IP vs MAC, ports, payload encryption, sniffing limitations, capture permissions, protocol labeling, throughput math, why PCAP import is valuable.
- Three step-by-step classroom experiments.
- What to do if live capture is unavailable during assessment.

---

## 12. CODING QUALITY RULES

1. **No placeholder implementations** for required modules; avoid `pass`, dead code, fake success messages, TODO-only methods.
2. Use type hints and docstrings for public parsing, analytics and capture APIs.
3. Keep functions short, logically separated, and deterministic wherever possible.
4. Catch narrow expected exceptions, log useful diagnostics in console, show friendly UI errors (no unhandled traceback in normal flows).
5. Prefer standard-library solutions; do not overengineer with microservices or databases.
6. Ensure no UI state mutation from background capture threads.
7. Bound memory and imported file sizes. Use threads and file descriptors responsibly; cleanup on stop/reset.
8. Clearly distinguish **sample data** from **real captured data**.
9. Do not use `IP in pkt` as the only supported packet path; parse non-IP ARP and IPv6 too.
10. Handle DNS classification without double-counting same packet in layer-based charts.
11. Avoid unsafe claims: don't call packet rate "internet speed," don't infer attack certainty from heuristics, don't claim HTTPS payload visibility.
12. Respect user privacy and authorization; no raw payload exports by default, no network traffic sent to third parties.
13. Commit the small generated sample PCAP if working in a repo; don't commit raw captures from a real network.
14. Don't assume live capture will function in a sandboxed IDE; fallback must always function.
15. If app version changes affect APIs, use the version installed and test against it; mention tradeoffs.

---

## 13. EXPECTED FINAL RESPONSE FROM THE CODING AGENT

At completion, provide a concise but substantive report:

1. **Implemented:** list concrete, tested features and available modes.
2. **Files created:** short tree showing key files.
3. **How to run:** exact setup/start/test commands.
4. **Test output:** actual command/results, not fabricated claims.
5. **Professor demo:** 5–7 steps using bundled sample data.
6. **Known limitations:** especially live-capture permission/support.
7. **Next optional improvements:** only if relevant.

**If you cannot execute something in your environment, say so honestly.** Do not declare fully working live capture without verifying it or clearly flagging that manual hardware/permission validation remains.

---

## 14. REFERENCE DOCUMENTATION FOR THE AGENT

Verify any API detail against installed versions and the official docs:

- Scapy usage, sniffing, packet parsing and PCAP: https://scapy.readthedocs.io/en/stable/usage.html
- Streamlit fragments / timed reruns: https://docs.streamlit.io/develop/api-reference/execution-flow/st.fragment
- Streamlit threading guidance: https://docs.streamlit.io/develop/concepts/design/multithreading
- Streamlit session state: https://docs.streamlit.io/develop/api-reference/caching-and-state/st.session_state

### Important note on the syllabus source

The idea and course-concept mapping come from the uploaded **NSUT Computer Networks syllabus**, specifically units I–V and the **"Project Work & Case Study / Mini Project"** block on **page 4**, which lists **"Network Traffic Analysis & Packet Sniffing"** as a possible topic. The implementation details in this AGENTS.md are **engineering design requirements for this project**, not additional official requirements imposed by NSUT.

---

# BEGIN IMPLEMENTATION NOW

Read the execution contract, then **actually create the working FrameSight project in this workspace**. Do not stop at planning. Start with the parser and deterministic demo PCAP, run tests, then implement the UI, then live capture, then professor documentation. Keep the project simple enough to explain in a third-year Computer Networks viva and polished enough for a classroom demonstration.
