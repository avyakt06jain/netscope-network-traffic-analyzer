# FrameSight — Network Traffic & Protocol Analyzer

FrameSight is a Computer Networks mini-project that decodes real packet headers with Scapy and turns them into an explainable Streamlit dashboard. It demonstrates Ethernet/ARP, IPv4/IPv6, TCP/UDP, ICMP, DNS, traffic measurement, filtering, packet inspection and capture limitations without requiring an internet connection for its primary demo.

The default **DEMO SAMPLE** is a deterministic, locally generated classic PCAP. It is synthetic teaching traffic, not a recording of real users or a claim about a real browser session.

## Features

- Three explicit modes: bundled **DEMO SAMPLE**, bounded **IMPORTED PCAP**, and authorized **LIVE CAPTURE**.
- Defensive Scapy parsing for Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMPv4/v6 and decoded DNS.
- Captured-frame lengths, UTC-normalized timestamps, TCP flags/sequence numbers, ICMP types/codes, DNS questions/answers and safe summaries.
- Synchronized protocol/IP/port/time/keyword filters across KPIs, charts, packet table and CSV export.
- Packet inspector with OSI/TCP-IP mapping and header explanations.
- Bidirectional TCP/UDP flow summaries and tunable heuristic observations clearly labeled as non-verdicts.
- Thread-safe, bounded live capture with interface selection, Start/Stop, duration and drop counters.
- Deterministic 80-frame demo and offline automated tests; no external API, database or telemetry.

## Quick start

Python 3.11 or 3.12 is recommended.

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python scripts\generate_demo_pcap.py
streamlit run app.py
```

If PowerShell blocks activation, run the tools directly:

```powershell
.\.venv\Scripts\python.exe scripts\generate_demo_pcap.py
.\.venv\Scripts\python.exe -m streamlit run app.py
```

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python scripts/generate_demo_pcap.py
streamlit run app.py
```

Open the local address printed by Streamlit, normally `http://localhost:8501`. The demo loads automatically.

## Test and validate

```bash
python scripts/generate_demo_pcap.py
python -m framesight.pcap_io samples/framesight_demo.pcap
pytest -q
ruff check .
```

Expected demo summary:

```text
Packets: 80; bytes: 5372; skipped: 0
TCP: 35
UDP: 19
ICMP: 14
DNS: 10
ARP: 2
```

The committed PCAP is reproducible byte-for-byte. Re-running the generator intentionally replaces it with the same deterministic content.

GitHub Actions repeats generation, linting, tests and an import smoke check on Python 3.11 and 3.12 for every pull request and push to `main`. Use [STUDY_GUIDE.md](STUDY_GUIDE.md) for concept revision and the professor-ready walkthrough; contribution and responsible-reporting guidance are in [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## Architecture

```text
Demo PCAP ─┐
Upload ────┼─> bounded Scapy decode -> immutable PacketRecord -> pure filters/analytics
Interface ─┘            |                                      |
                  CaptureController                       Streamlit UI
                  queue + retention                charts/table/inspector/CSV
```

Key locations:

```text
app.py                         Streamlit entry point and session behavior
framesight/models.py             Immutable records and aggregate types
framesight/parser.py             Packet-to-record normalization
framesight/pcap_io.py            Bounded classic-PCAP import and CSV export
framesight/analytics.py          Metrics, timelines, flows and heuristics
framesight/filters.py            Non-mutating filtering
framesight/capture.py            Thread-safe AsyncSniffer lifecycle
framesight/educational.py        OSI/TCP-IP explanations and experiments
framesight/ui.py                 Reusable dashboard and inspector rendering
scripts/generate_demo_pcap.py  Deterministic 80-frame generator
samples/framesight_demo.pcap     Bundled offline presentation capture
tests/                         Offline parser, IO, analytics, UI and capture tests
```

Scapy parsing, filtering and analytics are independent of Streamlit, which keeps networking behavior testable without a browser, network connection or capture privileges.

## Data modes

### Demo Sample

The default PCAP spans 44.2 seconds and contains a coherent ARP exchange, ICMPv4/v6 echo pairs, five DNS queries/responses, one TCP handshake followed by harmless teaching messages/ACKs, and non-DNS IPv4/IPv6 UDP datagrams. Imagined remote endpoints use IANA documentation ranges; `192.168.50.0/24` is a simulated LAN.

### Imported PCAP

- Supports classic `.pcap` only; `.pcapng` is rejected with conversion advice.
- Maximum file size is 20 MiB and at most 20,000 packet records are read.
- Parsing streams from disk and isolates malformed records where possible.
- Uploaded bytes live only in a temporary file that is removed after parsing.
- Successful records survive a later corrupt record, with visible skip/truncation warnings.

### Live Capture

Select an interface, then explicitly click **Start**. The capture worker sends normalized records to a bounded queue; the Streamlit script drains it about once per second. **Stop** preserves retained data until Reset, and a later Start continues the same session.

- Windows usually requires [Npcap](https://npcap.com/) and may require an elevated terminal.
- Linux requires appropriate packet-capture capabilities/privileges and an available capture backend.
- The correct interface is normally the one holding the host's active IP address. Loopback traffic needs the loopback interface.
- A zero-packet capture can mean the wrong interface, no traffic, filtered/encrypted DNS, missing driver or insufficient permission.
- Demo and Imported modes remain fully usable if live capture is unavailable.

FrameSight sees only traffic exposed to the selected local interface. It does not automatically observe every device on Wi-Fi or a switched LAN.

## Fields and calculations

| Field / metric | Definition |
|---|---|
| Captured frame bytes | `len(bytes(packet))`; not application payload size and not guaranteed on-wire size with every capture backend |
| Primary label | One of ARP, ICMP, DNS, TCP, UDP or Other, applied in that priority to prevent double-counting |
| Total packets / bytes | Count and sum of the currently filtered normalized records |
| Unique IPs | Distinct non-null source and destination IPv4/IPv6 addresses |
| Mean packet size | Captured bytes divided by packet count |
| Observation duration | Latest selected PCAP timestamp minus earliest selected timestamp |
| Observed packet rate | Selected packet count divided by observation duration |
| Observed byte/bit rate | Selected captured bytes divided by duration; bits/s is eight times bytes/s |

Rate is shown as `N/A` for one packet or identical timestamps. It is an observed captured rate, not ISP speed or physical link capacity. Offline graphs use historical PCAP timestamps. Live graphs show the last 60 seconds of retained capture timestamps.

Missing fields are `N/A`: ARP does not receive invented IP-layer endpoints, and ICMP does not receive invented ports. A port number alone is not treated as proof of an application protocol; DNS is labeled only when a DNS layer is decoded.

## Professor demonstration (5–7 minutes)

1. Start in **DEMO SAMPLE** and explain that all 80 records come from a real Scapy-generated PCAP.
2. Show the packet/byte metrics, five-category primary protocol chart and timeline quiet/burst periods.
3. Filter TCP, select SYN, SYN-ACK and ACK records, and explain Ethernet → IPv4 → TCP encapsulation.
4. Compare ICMP (type/code, no port) with DNS over UDP (transport plus application metadata).
5. Filter DNS or an IP; confirm KPIs, chart, table and downloaded CSV all show the same selection.
6. Try authorized Live Capture if Npcap/privileges are ready; otherwise import the bundled PCAP and obtain identical totals.
7. Open `samples/framesight_demo.pcap` in Wireshark, compare the count/types, and state the visibility, permission and encryption limitations.

See [VIVA_GUIDE.md](VIVA_GUIDE.md) for the spoken script and likely questions.

## Wireshark validation

Open `samples/framesight_demo.pcap` in Wireshark. The status bar should show 80 packets. Display filters such as `arp`, `icmp || icmpv6`, `dns`, `tcp` and `udp && !dns` can validate the same headers. Wireshark may name or group protocols differently, but FrameSight's primary chart deliberately counts each frame once.

## Privacy and limitations

- Analyze only captures and interfaces you are authorized to inspect.
- CSV contains normalized header metadata only—never raw payload bytes—but IP addresses and DNS names can still be sensitive.
- FrameSight does not decrypt TLS/HTTPS, reconstruct files or credentials, inject packets, scan networks, act as a firewall, or prove an attack.
- Heuristic thresholds can trigger on normal traffic and are observations only.
- Live retention is capped at 5,000 records; the worker queue is capped at 1,000 and displays drop counts.
- Unsupported link types, severe truncation or unusual vendor layers may yield an error or an `Other` record.
- Actual live capture depends on the operating system, driver, interface and privileges. It is not required for the reliable offline assessment path.

## Screenshot instructions

Run the app, keep **DEMO SAMPLE** selected, collapse the sidebar only if needed, and capture:

1. The source badge, five KPIs, timeline and protocol chart.
2. A TCP SYN-ACK selected in Packet Inspector with Ethernet/IPv4/TCP sections open.
3. The filtered DNS table and matching protocol chart.

No screenshot is committed because the build environment may not match the final student's name/theme/display. Do not substitute a mockup for the actual running app.

## References

- [Scapy usage and PCAP documentation](https://scapy.readthedocs.io/en/stable/usage.html)
- [Scapy API reference](https://scapy.readthedocs.io/en/stable/api/scapy.utils.html)
- [Streamlit fragments](https://docs.streamlit.io/develop/api-reference/execution-flow/st.fragment)
- [Streamlit threading guidance](https://docs.streamlit.io/develop/concepts/design/multithreading)
- [Streamlit Session State](https://docs.streamlit.io/develop/api-reference/caching-and-state/st.session_state)

## License

No software license has been selected yet. Before making the repository public, the owner should add the license that matches the intended reuse policy; GitHub's license chooser can generate the standard file safely.
