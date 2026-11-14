# NetScope Viva and Demonstration Guide

## 5–7 minute spoken demonstration

### Minute 0–1 — Context

“NetScope implements the Network Traffic Analysis and Packet Sniffing mini-project area from Computer Networks. The current badge says **DEMO SAMPLE**. This is a deterministic offline PCAP generated with Scapy, so the demonstration is repeatable without internet, Npcap or administrator rights. It is clearly synthetic and contains no real user's traffic.”

### Minute 1–2 — Source and dashboard

“The sample contains 80 real PCAP frames. NetScope streams and normalizes their headers rather than generating random dashboard rows. The KPIs count captured frames and frame bytes. The rate is packets or captured bytes divided by the PCAP observation span; it is not internet speed. The pie chart is mutually exclusive, so a DNS-over-UDP frame is counted once as DNS.”

Point out TCP 35, UDP 19, ICMP 14, DNS 10 and ARP 2. Show timeline bursts and quiet intervals.

### Minute 2–3 — Encapsulation and header inspection

Filter TCP and select the first SYN packet in Packet Inspector.

“The Ethernet header contains local-link MAC addresses. IPv4 contains logical routed addresses and TTL. TCP contains ports, sequence numbers and control flags. This demonstrates encapsulation: Ethernet carries IP, which carries TCP. NetScope maps these to OSI and TCP/IP layers without pretending to detect separate Session and Presentation headers.”

### Minute 3–4 — Handshake and protocol comparison

Select the SYN, SYN-ACK and ACK packets.

“The client starts with SYN, the server returns SYN plus ACK, and the client acknowledges. Their endpoint pair is consistent, and sequence/acknowledgement values establish state.”

Then filter ICMP and DNS.

“ICMP has type and code but no port. DNS is application metadata decoded over UDP, so the normalized record contains both UDP transport fields and DNS question/response fields.”

### Minute 4–5 — Analytics and filtering

Filter DNS or enter `192.168.50.53` as an endpoint.

“Every KPI, timeline, distribution, table and CSV is calculated from this same filtered record list. The ‘Showing X of Y’ text makes the scope explicit. The CSV contains header metadata only, but IP addresses and DNS names can still be sensitive.”

### Minute 5–6 — Live or imported mode

If Npcap/privileges are available, select the active interface, Start, run an authorized `ping` or `nslookup`, then Stop. Otherwise choose Import PCAP and upload `samples/netscope_demo.pcap`.

“Live capture is optional for the reliable assessment path. Failure is shown honestly with driver/privilege advice; NetScope never fakes live success. Importing the bundled PCAP gives the same 80 records.”

### Minute 6–7 — Wireshark and limitations

Open the same PCAP in Wireshark and show the 80-frame count or describe the validation filters.

“NetScope cannot decrypt HTTPS, automatically see every device on a switched or wireless LAN, or prove an attack from a traffic pattern. The optional observations are tunable heuristics, not IDS verdicts. Its purpose is explainable packet analysis rather than replacing Wireshark.”

## Likely viva questions and short answers

1. **What is packet sniffing?**  
   Capturing packets visible to a network interface so their headers and, when authorized and visible, content can be analyzed.

2. **Why is NetScope a packet analyzer rather than a network-wide monitor?**  
   It only receives traffic exposed to the selected local interface; switches, Wi-Fi isolation and routing limit visibility.

3. **What is encapsulation?**  
   Each layer wraps higher-layer data with its own header, such as Ethernet carrying IP and IP carrying TCP.

4. **How do OSI and TCP/IP differ?**  
   OSI has seven conceptual layers; TCP/IP commonly groups them into Network Access, Internet, Transport and Application.

5. **What is the difference between a MAC and IP address?**  
   A MAC address supports local link delivery; an IP address is a logical routed endpoint address.

6. **Why does ARP have no TCP/UDP ports?**  
   ARP is a link/network-access protocol for mapping IPv4 addresses to MAC addresses, not a transport protocol.

7. **What does TTL mean?**  
   Time To Live is decremented by each IPv4 router to prevent indefinite loops; it is a hop limit, not travel time.

8. **What is the IPv6 equivalent of TTL?**  
   Hop Limit.

9. **Compare TCP and UDP.**  
   TCP is connection-oriented, ordered and reliable through acknowledgements/retransmission. UDP sends independent datagrams without those guarantees.

10. **Explain the TCP three-way handshake.**  
    SYN requests a connection, SYN-ACK accepts and acknowledges it, and ACK confirms the connection state.

11. **What are sequence and acknowledgement numbers?**  
    TCP uses sequence numbers to identify byte positions and acknowledgement numbers to state the next expected byte.

12. **What do FIN and RST mean?**  
    FIN participates in an orderly close; RST abruptly resets a TCP connection.

13. **Why does ICMP not use ports?**  
    ICMP carries network control/diagnostic types and codes rather than process-to-process transport endpoints.

14. **How does ping work?**  
    It normally sends ICMP Echo Request messages and measures corresponding Echo Replies.

15. **What does the DNS QR bit show?**  
    QR=0 identifies a query and QR=1 identifies a response.

16. **Why not label every UDP/53 packet as DNS?**  
    A port is only a service hint. NetScope requires Scapy to decode an actual DNS layer.

17. **Why can DNS be absent during a live `nslookup` experiment?**  
    The lookup may be cached, encrypted, sent through another interface, or hidden by capture permissions/backend limitations.

18. **Can NetScope decrypt HTTPS?**  
    No. TLS normally encrypts application data; ordinary packet headers reveal endpoints and sizes but not plaintext.

19. **Why is protocol distribution mutually exclusive?**  
    A packet can simultaneously be IPv4, UDP and DNS. One primary label prevents the same frame being counted several times in one chart.

20. **How is packet rate calculated?**  
    Selected packet count divided by the span between earliest and latest selected capture timestamps. Zero-duration selections show N/A.

21. **Is captured rate the same as bandwidth?**  
    No. It is traffic observed by this capture, not link capacity or subscribed internet speed.

22. **Why use a PCAP import mode?**  
    It enables repeatable offline analysis, later investigation, Wireshark comparison and demos without capture privileges.

23. **How is memory bounded?**  
    Imports stop at 20,000 packets; live mode uses a 1,000-record queue and retains at most 5,000 normalized records with drop counters.

24. **Why does the worker not call Streamlit functions?**  
    Streamlit UI/session APIs belong to its script thread. The worker only normalizes and queues data to avoid unsafe cross-thread state mutation.

25. **Are heuristic observations proof of attacks?**  
    No. High volume or many ports can be normal; thresholds only identify patterns worth investigation.

## Classroom experiments

### 1. ICMP ping

1. Use Demo mode for a guaranteed result, or start an authorized live capture on the active interface.
2. In a terminal run `ping 8.8.8.8` if connectivity is available.
3. Stop capture and select ICMP.
4. Compare Echo Request/Reply addresses and types; confirm ports are N/A.
5. Explain that missing live replies can result from filtering, routing or ICMP blocking.

### 2. DNS lookup

1. Start an authorized live capture or remain in Demo mode.
2. Run `nslookup example.com` for live mode.
3. Filter DNS and inspect the question name, type and query/response state.
4. Explain UDP transport versus DNS application metadata.
5. State why encrypted or cached DNS may not be visible.

### 3. TCP connection and handshake

1. Load Demo mode and filter TCP.
2. Locate the first SYN, then SYN-ACK, then ACK for the same endpoint pair.
3. Compare direction, flags, sequence and acknowledgement numbers.
4. Inspect later PSH/ACK frames and note that their harmless teaching payload is not stored in normalized records.
5. Clear filters and show the flow table grouping both directions together.

## If live capture is unavailable

State the limitation openly: “This computer does not currently provide the required driver/privilege path, so I am using the project's designed offline fallback.” Reload **DEMO SAMPLE** or import `samples/netscope_demo.pcap`, show identical totals, and continue the full parser/filter/inspector/Wireshark demonstration. This is a valid result, not a simulated live capture.
