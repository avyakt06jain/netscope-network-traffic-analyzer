"""Reusable Streamlit rendering helpers for NetScope."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import asdict

import pandas as pd
import plotly.express as px
import streamlit as st

from .analytics import (
    flows_dataframe,
    heuristic_observations,
    protocol_distribution,
    records_dataframe,
    summary_stats,
    time_series,
    top_ips,
)
from .educational import CONCEPTS_MARKDOWN, EXPERIMENTS, FIELD_EXPLANATIONS, OSI_MAPPING, observed_layers
from .models import PacketRecord
from .pcap_io import records_to_csv

PROTOCOL_COLORS = {
    "TCP": "#22d3ee",
    "UDP": "#60a5fa",
    "ICMP": "#34d399",
    "DNS": "#fbbf24",
    "ARP": "#c084fc",
    "Other": "#94a3b8",
}


def inject_styles() -> None:
    st.markdown(
        """
        <style>
        .block-container {padding-top: 1.7rem; padding-bottom: 3rem; max-width: 1450px;}
        [data-testid="stMetric"] {background: #101d31; border: 1px solid #233551; padding: .8rem; border-radius: .65rem;}
        .netscope-badge {display:inline-block; padding:.28rem .7rem; border-radius:999px; background:#12334b;
            color:#67e8f9; border:1px solid #155e75; font-size:.78rem; font-weight:700; letter-spacing:.05em;}
        .capture-note {padding:.75rem 1rem; border-left:3px solid #22d3ee; background:#0d192b; border-radius:.25rem;}
        div[data-testid="stDataFrame"] {border:1px solid #233551; border-radius:.5rem;}
        </style>
        """,
        unsafe_allow_html=True,
    )


def format_bytes(value: float) -> str:
    """Format bytes using binary units without changing the underlying metric."""

    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if abs(amount) < 1024 or unit == "GiB":
            return f"{amount:.0f} {unit}" if unit == "B" else f"{amount:.2f} {unit}"
        amount /= 1024
    return f"{amount:.2f} GiB"


def source_badge(label: str) -> None:
    st.markdown(f'<span class="netscope-badge">{label}</span>', unsafe_allow_html=True)


def render_packet_inspector(record: PacketRecord) -> None:
    """Render normalized headers and educational explanations for one packet."""

    st.caption(f"Packet #{record.packet_id} · {record.capture_time.astimezone().isoformat(timespec='milliseconds')}")
    st.info(record.summary)
    with st.expander("Layer 2 — Ethernet / ARP", expanded=True):
        st.json({
            "link_protocol": record.l2_protocol or "N/A",
            "source_mac": record.src_mac or "N/A",
            "destination_mac": record.dst_mac or "N/A",
            "arp_operation": record.arp_operation or "N/A",
            "arp_sender_ip": record.arp_sender_ip or "N/A",
            "arp_target_ip": record.arp_target_ip or "N/A",
        })
        st.caption(FIELD_EXPLANATIONS["MAC address"])
    with st.expander("Layer 3 — Network", expanded=True):
        st.json({
            "protocol": record.network_protocol,
            "source_ip": record.src_ip or "N/A",
            "destination_ip": record.dst_ip or "N/A",
            "ttl_or_hop_limit": record.ip_ttl_or_hop_limit if record.ip_ttl_or_hop_limit is not None else "N/A",
        })
        st.caption(FIELD_EXPLANATIONS["IP address"] + " " + FIELD_EXPLANATIONS["TTL / Hop Limit"])
    with st.expander("Layer 4 — Transport / Control", expanded=True):
        st.json({
            "protocol": record.transport_protocol or "N/A",
            "source_port": record.src_port if record.src_port is not None else "N/A",
            "destination_port": record.dst_port if record.dst_port is not None else "N/A",
            "tcp_flags": record.tcp_flags or "N/A",
            "tcp_sequence": record.tcp_seq if record.tcp_seq is not None else "N/A",
            "tcp_acknowledgement": record.tcp_ack if record.tcp_ack is not None else "N/A",
            "icmp_type": record.icmp_type if record.icmp_type is not None else "N/A",
            "icmp_code": record.icmp_code if record.icmp_code is not None else "N/A",
            "icmp_meaning": record.icmp_label or "N/A",
        })
        st.caption(FIELD_EXPLANATIONS["Port"] + " " + FIELD_EXPLANATIONS["TCP flags"])
    with st.expander("Application metadata", expanded=record.application_protocol is not None):
        st.json({
            "application_protocol": record.application_protocol or "N/A",
            "dns_query_name": record.dns_query_name or "N/A",
            "dns_message": "Response" if record.dns_is_response else "Query" if record.dns_is_response is False else "N/A",
            "dns_query_type": record.dns_query_type or "N/A",
            "dns_answer": record.dns_answer_summary or "N/A",
        })
        st.caption(FIELD_EXPLANATIONS["DNS"] + " " + FIELD_EXPLANATIONS["TLS / HTTPS"])
    st.markdown("**Observed encapsulation**")
    st.dataframe(pd.DataFrame(observed_layers(record), columns=["Model layer", "Observed protocol"]), hide_index=True)


def render_dashboard(
    records: Sequence[PacketRecord],
    filtered: Sequence[PacketRecord],
    *,
    source_slug: str,
    source_revision: int,
    clear_filters: Callable[[], None],
    live_window: bool = False,
) -> None:
    """Render every analytical output from the same filtered selection."""

    st.caption(f"Showing **{len(filtered):,} of {len(records):,}** normalized packet records. KPIs, charts, table and CSV use this selection.")
    if not filtered:
        st.warning("No packets match the current filters.")
        st.button("Clear filters", key="empty_clear_filters", on_click=clear_filters)
        return

    stats = summary_stats(filtered)
    columns = st.columns(5)
    columns[0].metric("Total Packets", f"{stats.total_packets:,}")
    columns[1].metric("Captured Bytes", format_bytes(stats.total_bytes), help="Captured frame bytes, not application payload bytes.")
    columns[2].metric(
        "Observed Packets/s",
        f"{stats.packets_per_second:.2f}" if stats.packets_per_second is not None else "N/A",
        help="Packets divided by the selected capture timestamp span; not internet speed.",
    )
    columns[3].metric(
        "Observed Bytes/s",
        format_bytes(stats.bytes_per_second) + "/s" if stats.bytes_per_second is not None else "N/A",
        help="Captured bytes divided by the observation span, not physical link capacity.",
    )
    columns[4].metric("Unique IPs", f"{stats.unique_ips:,}")

    series = time_series(filtered, last_seconds=60 if live_window else None)
    packet_figure = px.line(series, x="capture_time", y="packets", markers=True, title="Packets over capture time")
    byte_figure = px.area(series, x="capture_time", y="bytes", title="Captured bytes over time")
    packet_figure.update_layout(yaxis_title="Packets / 1 s", xaxis_title="Capture timestamp")
    byte_figure.update_layout(yaxis_title="Captured bytes / 1 s", xaxis_title="Capture timestamp")
    chart_columns = st.columns(2)
    chart_columns[0].plotly_chart(packet_figure, width="stretch")
    chart_columns[1].plotly_chart(byte_figure, width="stretch")
    if live_window:
        st.caption("Live timelines show the last 60 seconds of retained capture timestamps.")
    else:
        st.caption("Offline timelines use timestamps stored inside the PCAP; they are not replaced with the current time.")

    distribution = protocol_distribution(filtered)
    protocol_figure = px.pie(
        distribution,
        names="protocol",
        values="packets",
        color="protocol",
        color_discrete_map=PROTOCOL_COLORS,
        hole=0.48,
        title="Primary protocol distribution",
    )
    source_frame = top_ips(filtered, "source")
    destination_frame = top_ips(filtered, "destination")
    talkers = pd.concat([
        source_frame.assign(Direction="Source"),
        destination_frame.assign(Direction="Destination"),
    ], ignore_index=True)
    talker_figure = px.bar(
        talkers,
        x="packets",
        y="ip",
        color="Direction",
        orientation="h",
        barmode="group",
        title="Top IP endpoints",
    )
    chart_columns = st.columns(2)
    chart_columns[0].plotly_chart(protocol_figure, width="stretch")
    chart_columns[1].plotly_chart(talker_figure, width="stretch")
    st.caption("Primary labels are mutually exclusive: ARP → ICMP → DNS → TCP → UDP → Other. DNS-over-UDP is counted once as DNS here.")

    st.subheader("Packet list")
    table = records_dataframe(filtered)
    st.dataframe(table, hide_index=True, width="stretch", height=360)
    st.download_button(
        "Download filtered CSV",
        data=records_to_csv(list(filtered)),
        file_name=f"netscope_packets_{source_slug}.csv",
        mime="text/csv",
        help="Exports normalized header metadata only. IP addresses and DNS names can still be sensitive.",
    )

    inspector_tab, flow_tab, alert_tab, learn_tab = st.tabs([
        "Packet Inspector", "Bidirectional Flows", "Heuristic Observations", "Learn the Concepts"
    ])
    with inspector_tab:
        options = [record.packet_id for record in filtered]
        records_by_id = {record.packet_id: record for record in filtered}
        chosen = st.selectbox(
            "Select a packet ID",
            options,
            format_func=lambda packet_id: f"#{packet_id} — {records_by_id[packet_id].summary}",
            key=f"inspector_{source_revision}",
        )
        render_packet_inspector(records_by_id[chosen])
    with flow_tab:
        st.markdown("TCP and UDP packets are grouped by a direction-independent 5-tuple. ARP and ICMP are deliberately excluded.")
        flows = flows_dataframe(filtered)
        if flows.empty:
            st.info("No complete TCP/UDP IP flows are present in this selection.")
        else:
            st.dataframe(flows, hide_index=True, width="stretch")
    with alert_tab:
        st.warning("Heuristic observations are patterns worth investigating — not security incidents or proof of an attack.")
        threshold_columns = st.columns(4)
        rate_threshold = threshold_columns[0].number_input("Packet threshold", 2, 1000, 25, key="rate_threshold")
        rate_window = threshold_columns[1].number_input("Rate window (s)", 1, 600, 10, key="rate_window")
        port_threshold = threshold_columns[2].number_input("Distinct ports", 2, 65535, 10, key="port_threshold")
        port_window = threshold_columns[3].number_input("Port window (s)", 1, 3600, 60, key="port_window")
        findings = heuristic_observations(
            filtered,
            int(rate_threshold),
            int(rate_window),
            int(port_threshold),
            int(port_window),
        )
        if findings:
            st.dataframe(pd.DataFrame(findings), hide_index=True, width="stretch")
        else:
            st.success("No records cross the selected heuristic thresholds.")
    with learn_tab:
        st.markdown(CONCEPTS_MARKDOWN)
        st.markdown("### OSI and TCP/IP mapping")
        st.dataframe(pd.DataFrame(OSI_MAPPING, columns=["OSI", "TCP/IP", "What NetScope can show"]), hide_index=True)
        st.markdown("### Classroom mini-experiments")
        for name, instructions in EXPERIMENTS.items():
            with st.expander(name):
                st.markdown(instructions)

    with st.expander("Normalized record (payload excluded)"):
        st.json(asdict(filtered[0]))
