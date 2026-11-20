"""Reusable Streamlit rendering helpers for FrameSight."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import asdict
from html import escape

import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from plotly.subplots import make_subplots

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
    "TCP": "#3978C5",
    "UDP": "#6E68C9",
    "ICMP": "#27896F",
    "DNS": "#C88719",
    "ARP": "#B65A7A",
    "Other": "#7A8793",
}

CHART_CONFIG = {"displayModeBar": False, "responsive": True, "scrollZoom": False}


def inject_styles() -> None:
    """Apply a restrained observability-workbench visual system."""

    st.markdown(
        """
        <style>
        :root {
            --ns-bg: #f6f8f9; --ns-sidebar: #eef2f3; --ns-surface: #ffffff;
            --ns-border: #d9e0e4; --ns-border-soft: #e8edef; --ns-text: #17212b;
            --ns-muted: #5f6d79; --ns-subtle: #7b8893; --ns-accent: #0f766e;
            --ns-mono: "Cascadia Code", "IBM Plex Mono", Consolas, monospace;
            --ns-sans: Inter, "IBM Plex Sans", "Segoe UI Variable", "Segoe UI", sans-serif;
        }
        html, body, .stApp {font-family: var(--ns-sans);}
        .material-symbols-rounded,
        [data-testid="stIconMaterial"] {
            font-family: "Material Symbols Rounded" !important;
            font-weight: normal !important;
            font-style: normal !important;
            letter-spacing: normal !important;
            text-transform: none !important;
            white-space: nowrap !important;
            word-wrap: normal !important;
            direction: ltr !important;
            font-feature-settings: "liga" !important;
            -webkit-font-feature-settings: "liga" !important;
        }
        .stApp {background: var(--ns-bg); color: var(--ns-text);}
        [data-testid="stHeader"] {background: rgba(246,248,249,.94); border-bottom: 1px solid var(--ns-border-soft);}
        [data-testid="stToolbar"] {opacity: .65;}
        .block-container {padding: 3.25rem 2.5rem 5rem; max-width: 1480px;}
        [data-testid="stSidebar"] {background: var(--ns-sidebar); border-right: 1px solid var(--ns-border); min-width: 290px;}
        [data-testid="stSidebar"] > div:first-child {padding-top: 1.35rem;}
        [data-testid="stSidebar"] hr {border-color: var(--ns-border); margin: 1.25rem 0;}
        [data-testid="stSidebar"] label, [data-testid="stSidebar"] p {font-size: .84rem;}
        h1, h2, h3 {font-family: var(--ns-sans); color: var(--ns-text); letter-spacing: -.025em;}
        h1 {font-size: 2.45rem !important; font-weight: 670 !important; line-height: 1.05 !important; margin: .15rem 0 .45rem !important;}
        h2 {font-size: 1.15rem !important; font-weight: 640 !important;}
        h3 {font-size: 1rem !important; font-weight: 620 !important;}

        .ns-brand {display: flex; align-items: center; gap: .72rem; padding: .1rem 0 1.35rem;}
        .ns-mark {display: grid; place-items: center; width: 34px; height: 34px; border: 1px solid #9acbc5;
            color: #0b625c; font-family: var(--ns-mono); font-size: .72rem; font-weight: 700;
            background: #dcefeb; border-radius: 7px;}
        .ns-brand-name {font-size: 1.02rem; line-height: 1.1; font-weight: 680; letter-spacing: -.02em; color: var(--ns-text);}
        .ns-brand-copy {font-size: .7rem; color: var(--ns-muted); margin-top: .18rem; letter-spacing: .02em;}
        .ns-sidebar-label, .ns-eyebrow {color: var(--ns-subtle); font-size: .66rem; font-weight: 700;
            letter-spacing: .12em; text-transform: uppercase;}
        .ns-sidebar-label {margin: .35rem 0 .6rem;}
        .ns-sidebar-note {color: #53626e; font-size: .76rem; line-height: 1.55; padding: .72rem .8rem;
            background: #f8fafb; border: 1px solid var(--ns-border); border-left: 2px solid #2a8a80;
            border-radius: 6px; margin: .7rem 0 .9rem;}

        .ns-page-deck {color: var(--ns-muted); font-size: .92rem; line-height: 1.55; margin: 0; max-width: 690px;}
        .ns-source-panel {margin-top: .35rem; padding: .72rem .85rem; background: var(--ns-surface);
            border: 1px solid var(--ns-border); border-radius: 8px; min-width: 195px;}
        .ns-source-label {color: var(--ns-subtle); font-size: .62rem; font-weight: 700; letter-spacing: .11em; text-transform: uppercase;}
        .ns-source-value {display: flex; align-items: center; gap: .48rem; margin-top: .3rem; color: #24313b;
            font-size: .78rem; font-weight: 650; letter-spacing: .035em;}
        .ns-status-dot {width: 7px; height: 7px; border-radius: 50%; background: var(--ns-accent);
            box-shadow: 0 0 0 3px rgba(15,118,110,.12);}

        .ns-selection-bar {display: flex; align-items: center; justify-content: space-between; gap: 1rem;
            padding: .65rem .85rem; margin: 1.55rem 0 .85rem; color: var(--ns-muted); font-size: .77rem;
            background: #ffffff; border: 1px solid var(--ns-border); border-radius: 7px;}
        .ns-selection-bar strong {color: var(--ns-text); font-family: var(--ns-mono); font-weight: 600;}
        .ns-selection-tag {color: #0f766e; font-family: var(--ns-mono); font-size: .67rem;
            letter-spacing: .06em; text-transform: uppercase;}

        [data-testid="stMetric"] {background: var(--ns-surface); border: 1px solid var(--ns-border);
            padding: .95rem 1rem 1rem; border-radius: 8px; min-height: 112px; box-shadow: none;}
        [data-testid="stMetric"]:hover {border-color: #b8c5cb;}
        [data-testid="stMetricLabel"] p {color: var(--ns-muted); font-size: .7rem; font-weight: 670;
            letter-spacing: .055em; text-transform: uppercase; white-space: nowrap;}
        [data-testid="stMetricValue"] {font-family: var(--ns-mono); color: var(--ns-text);
            font-size: 1.72rem; letter-spacing: -.045em;}

        [data-testid="stVerticalBlockBorderWrapper"] {background: var(--ns-surface);
            border-color: var(--ns-border) !important; border-radius: 9px !important;}
        [data-testid="stVerticalBlockBorderWrapper"] > div {padding: .2rem .25rem;}
        .ns-section-heading {display: flex; align-items: flex-start; justify-content: space-between;
            gap: 1rem; padding: .15rem 0 .45rem;}
        .ns-section-heading h2 {font-size: .98rem !important; margin: 0 !important; letter-spacing: -.01em;}
        .ns-section-heading p {color: var(--ns-muted); font-size: .73rem; margin: .22rem 0 0; line-height: 1.45;}
        .ns-section-meta {color: var(--ns-subtle); font-family: var(--ns-mono); font-size: .62rem;
            letter-spacing: .06em; white-space: nowrap; padding-top: .15rem;}

        .stButton > button, .stDownloadButton > button {background: #ffffff; border: 1px solid #cbd4d9;
            border-radius: 7px; color: #293640; font-weight: 590; min-height: 2.35rem; box-shadow: none;}
        .stButton > button:hover, .stDownloadButton > button:hover {background: #f3f6f7; border-color: #9eacb4; color: #17212b;}
        .stButton > button[kind="primary"] {background: #0f766e; border-color: #0f766e; color: #ffffff;}
        .stButton > button[kind="primary"]:hover {background: #0b625c; border-color: #0b625c;}
        .stButton > button:focus, .stDownloadButton > button:focus {box-shadow: 0 0 0 2px rgba(15,118,110,.20);}

        [data-baseweb="select"] > div, [data-baseweb="input"] > div, [data-testid="stTextInput"] input,
        [data-testid="stNumberInput"] input {background: #ffffff !important; border-color: #ccd5da !important;
            border-radius: 7px !important;}
        [data-baseweb="select"] > div:focus-within, [data-testid="stTextInput"] input:focus,
        [data-testid="stNumberInput"] input:focus {border-color: #318c84 !important; box-shadow: 0 0 0 1px #318c84 !important;}
        [data-testid="stRadio"] label {padding: .15rem 0;}
        [data-testid="stFileUploaderDropzone"] {background: #ffffff; border-color: #ccd5da; border-radius: 8px;}

        [data-testid="stExpander"] {background: #ffffff; border: 1px solid var(--ns-border) !important; border-radius: 8px !important;}
        [data-testid="stExpander"] summary {font-weight: 620; font-size: .82rem;}
        [data-baseweb="tab-list"] {gap: 1.6rem; border-bottom: 1px solid var(--ns-border);}
        [data-baseweb="tab"] {height: 3rem; padding: 0 .1rem; color: var(--ns-muted); font-weight: 590;}
        [aria-selected="true"][data-baseweb="tab"] {color: var(--ns-text);}
        [data-baseweb="tab-highlight"] {background: var(--ns-accent); height: 2px;}
        div[data-testid="stDataFrame"] {border: 1px solid var(--ns-border); border-radius: 8px; overflow: hidden;}
        [data-testid="stJson"] {background: #f8fafb !important; border: 1px solid var(--ns-border); border-radius: 7px;}

        .ns-packet-summary {display: flex; justify-content: space-between; gap: 1rem; padding: .78rem .9rem;
            margin: .6rem 0 1rem; background: #edf7f5; border: 1px solid #c9e3df;
            border-left: 2px solid var(--ns-accent); border-radius: 7px;}
        .ns-packet-summary-main {color: #1d3c39; font-family: var(--ns-mono); font-size: .77rem; line-height: 1.5;}
        .ns-packet-id {color: #0f766e; font-family: var(--ns-mono); font-size: .67rem; white-space: nowrap;}
        .ns-field-grid {display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 1px;
            background: var(--ns-border-soft); border: 1px solid var(--ns-border-soft); border-radius: 7px;
            overflow: hidden; margin-bottom: .65rem;}
        .ns-field {background: #f9fbfb; padding: .72rem .8rem; min-width: 0;}
        .ns-field-label {color: var(--ns-subtle); font-size: .61rem; font-weight: 700; letter-spacing: .08em;
            text-transform: uppercase; margin-bottom: .28rem;}
        .ns-field-value {color: #26343e; font-family: var(--ns-mono); font-size: .73rem; overflow-wrap: anywhere;}
        .ns-field-help {color: var(--ns-muted); font-size: .72rem; line-height: 1.5; margin: .2rem 0 .35rem;}
        .ns-notice {padding: .75rem .85rem; border-radius: 7px; font-size: .76rem; line-height: 1.5; margin: .4rem 0 .9rem;}
        .ns-notice-warn {background: #fff8e7; border: 1px solid #ead8a8; color: #70551b;}
        .ns-notice-neutral {background: #f1f5f6; border: 1px solid #d6e0e3; color: #53636e;}
        .ns-footer {color: var(--ns-subtle); font-size: .7rem; line-height: 1.55; padding-top: .5rem;}

        @media (max-width: 1050px) {
            .block-container {padding-left: 1.25rem; padding-right: 1.25rem;}
            .ns-field-grid {grid-template-columns: repeat(2, minmax(0, 1fr));}
        }
        @media (max-width: 700px) {
            h1 {font-size: 2rem !important;}
            .ns-field-grid {grid-template-columns: 1fr;}
            .ns-selection-bar, .ns-section-heading {align-items: flex-start; flex-direction: column;}
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def sidebar_brand() -> None:
    st.sidebar.markdown(
        """
        <div class="ns-brand">
          <div class="ns-mark">FS</div>
          <div><div class="ns-brand-name">FrameSight</div><div class="ns-brand-copy">Packet analysis workbench</div></div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def sidebar_label(label: str) -> None:
    st.sidebar.markdown(f'<div class="ns-sidebar-label">{escape(label)}</div>', unsafe_allow_html=True)


def sidebar_note(message: str) -> None:
    st.sidebar.markdown(f'<div class="ns-sidebar-note">{escape(message)}</div>', unsafe_allow_html=True)


def render_page_header(source_label: str) -> None:
    left, right = st.columns([5.4, 1.55], vertical_alignment="top")
    with left:
        st.markdown('<div class="ns-eyebrow">Network observability workbench</div>', unsafe_allow_html=True)
        st.title("FrameSight")
        st.markdown(
            '<p class="ns-page-deck">Inspect real packet headers, validate protocol behavior, and explain the network stack with reproducible evidence.</p>',
            unsafe_allow_html=True,
        )
    with right:
        st.markdown(
            f'<div class="ns-source-panel"><div class="ns-source-label">Active source</div>'
            f'<div class="ns-source-value"><span class="ns-status-dot"></span>{escape(source_label)}</div></div>',
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


def _section_header(title: str, description: str, meta: str = "") -> None:
    st.markdown(
        f'<div class="ns-section-heading"><div><h2>{escape(title)}</h2><p>{escape(description)}</p></div>'
        f'<span class="ns-section-meta">{escape(meta)}</span></div>',
        unsafe_allow_html=True,
    )


def _style_figure(figure: go.Figure, *, height: int) -> go.Figure:
    figure.update_layout(
        height=height,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin={"l": 12, "r": 12, "t": 16, "b": 12},
        font={"family": "Inter, Segoe UI, sans-serif", "color": "#5F6D79", "size": 11},
        hoverlabel={"bgcolor": "#FFFFFF", "bordercolor": "#CBD4D9", "font_color": "#17212B"},
        legend={"orientation": "h", "yanchor": "bottom", "y": 1.02, "xanchor": "left", "x": 0, "font_size": 10},
        hovermode="x unified",
    )
    figure.update_xaxes(showgrid=False, zeroline=False, linecolor="#D7E0E4", tickfont={"color": "#6F7D88"},
                        title_font={"color": "#7B8893", "size": 10})
    figure.update_yaxes(gridcolor="#E7ECEF", griddash="dot", zeroline=False, linecolor="#D7E0E4",
                        tickfont={"color": "#6F7D88"}, title_font={"color": "#7B8893", "size": 10})
    return figure


def _traffic_figure(series: pd.DataFrame) -> go.Figure:
    figure = make_subplots(specs=[[{"secondary_y": True}]])
    figure.add_trace(go.Bar(
        x=series["capture_time"], y=series["bytes"], name="Captured bytes",
        marker={"color": "rgba(57,120,197,.16)", "line": {"width": 0}},
        hovertemplate="%{y:,} B<extra></extra>",
    ), secondary_y=True)
    figure.add_trace(go.Scatter(
        x=series["capture_time"], y=series["packets"], name="Packets", mode="lines+markers",
        line={"color": "#0F766E", "width": 2},
        marker={"color": "#FFFFFF", "line": {"color": "#0F766E", "width": 1.5}, "size": 5},
        hovertemplate="%{y:,} packets<extra></extra>",
    ), secondary_y=False)
    figure.update_yaxes(title_text="Packets / second", secondary_y=False)
    figure.update_yaxes(title_text="Captured bytes / second", secondary_y=True, showgrid=False)
    figure.update_xaxes(title_text="Capture timestamp")
    return _style_figure(figure, height=345)


def _protocol_figure(distribution: pd.DataFrame) -> go.Figure:
    total = int(distribution["packets"].sum())
    colors = [PROTOCOL_COLORS.get(label, PROTOCOL_COLORS["Other"]) for label in distribution["protocol"]]
    figure = go.Figure(go.Pie(
        labels=distribution["protocol"], values=distribution["packets"], hole=.68, sort=False,
        marker={"colors": colors, "line": {"color": "#FFFFFF", "width": 2}}, textinfo="none",
        hovertemplate="%{label}<br>%{value:,} packets · %{percent}<extra></extra>",
    ))
    figure.add_annotation(
        text=f"<b>{total:,}</b><br><span style='font-size:10px;color:#7B8893'>PACKETS</span>",
        x=.5, y=.5, showarrow=False,
        font={"family": "Cascadia Code, Consolas, monospace", "size": 20, "color": "#17212B"},
    )
    figure.update_layout(legend={"orientation": "v", "x": 1.02, "y": .5, "yanchor": "middle"})
    return _style_figure(figure, height=318)


def _endpoint_figure(source_frame: pd.DataFrame, destination_frame: pd.DataFrame) -> go.Figure:
    figure = make_subplots(rows=1, cols=2, horizontal_spacing=.28, subplot_titles=("Sources", "Destinations"))
    for column, frame, color in ((1, source_frame, "#3978C5"), (2, destination_frame, "#6E68C9")):
        display = frame.head(6).iloc[::-1]
        figure.add_trace(go.Bar(
            x=display["packets"], y=display["ip"], orientation="h",
            marker={"color": color, "opacity": .78},
            hovertemplate="%{y}<br>%{x:,} packets<extra></extra>", showlegend=False,
        ), row=1, col=column)
    figure.update_xaxes(title_text="Packets")
    figure.update_annotations(font={"size": 11, "color": "#53636E"})
    return _style_figure(figure, height=318)


def _field_grid(fields: Sequence[tuple[str, object]]) -> None:
    cells = "".join(
        f'<div class="ns-field"><div class="ns-field-label">{escape(label)}</div>'
        f'<div class="ns-field-value">{escape(str(value if value is not None else "N/A"))}</div></div>'
        for label, value in fields
    )
    st.markdown(f'<div class="ns-field-grid">{cells}</div>', unsafe_allow_html=True)


def render_packet_inspector(record: PacketRecord) -> None:
    """Render normalized headers as a readable technical inspection surface."""
    local_time = record.capture_time.astimezone().isoformat(timespec="milliseconds")
    st.markdown(
        f'<div class="ns-packet-summary"><div class="ns-packet-summary-main">{escape(record.summary)}</div>'
        f'<div class="ns-packet-id">PKT {record.packet_id:04d} · {escape(local_time)}</div></div>',
        unsafe_allow_html=True,
    )
    with st.expander("Link layer · Ethernet / ARP", expanded=True):
        _field_grid([
            ("Link protocol", record.l2_protocol or "N/A"), ("Source MAC", record.src_mac or "N/A"),
            ("Destination MAC", record.dst_mac or "N/A"), ("ARP operation", record.arp_operation or "N/A"),
            ("ARP sender IP", record.arp_sender_ip or "N/A"), ("ARP target IP", record.arp_target_ip or "N/A"),
        ])
        st.markdown(f'<p class="ns-field-help">{escape(FIELD_EXPLANATIONS["MAC address"])}</p>', unsafe_allow_html=True)
    with st.expander("Network layer · IP", expanded=True):
        _field_grid([
            ("Protocol", record.network_protocol), ("Source IP", record.src_ip or "N/A"),
            ("Destination IP", record.dst_ip or "N/A"),
            ("TTL / Hop Limit", record.ip_ttl_or_hop_limit if record.ip_ttl_or_hop_limit is not None else "N/A"),
        ])
        help_text = FIELD_EXPLANATIONS["IP address"] + " " + FIELD_EXPLANATIONS["TTL / Hop Limit"]
        st.markdown(f'<p class="ns-field-help">{escape(help_text)}</p>', unsafe_allow_html=True)
    with st.expander("Transport / control layer", expanded=True):
        _field_grid([
            ("Protocol", record.transport_protocol or "N/A"),
            ("Source port", record.src_port if record.src_port is not None else "N/A"),
            ("Destination port", record.dst_port if record.dst_port is not None else "N/A"),
            ("TCP flags", record.tcp_flags or "N/A"),
            ("TCP sequence", record.tcp_seq if record.tcp_seq is not None else "N/A"),
            ("TCP acknowledgement", record.tcp_ack if record.tcp_ack is not None else "N/A"),
            ("ICMP type", record.icmp_type if record.icmp_type is not None else "N/A"),
            ("ICMP code", record.icmp_code if record.icmp_code is not None else "N/A"),
            ("ICMP meaning", record.icmp_label or "N/A"),
        ])
        help_text = FIELD_EXPLANATIONS["Port"] + " " + FIELD_EXPLANATIONS["TCP flags"]
        st.markdown(f'<p class="ns-field-help">{escape(help_text)}</p>', unsafe_allow_html=True)
    with st.expander("Application metadata", expanded=record.application_protocol is not None):
        dns_message = "Response" if record.dns_is_response else "Query" if record.dns_is_response is False else "N/A"
        _field_grid([
            ("Application protocol", record.application_protocol or "N/A"),
            ("DNS query name", record.dns_query_name or "N/A"), ("DNS message", dns_message),
            ("DNS query type", record.dns_query_type or "N/A"), ("DNS answer", record.dns_answer_summary or "N/A"),
        ])
        help_text = FIELD_EXPLANATIONS["DNS"] + " " + FIELD_EXPLANATIONS["TLS / HTTPS"]
        st.markdown(f'<p class="ns-field-help">{escape(help_text)}</p>', unsafe_allow_html=True)
    st.markdown("#### Observed encapsulation")
    st.dataframe(pd.DataFrame(observed_layers(record), columns=["Model layer", "Observed protocol"]),
                 hide_index=True, width="stretch")


def render_dashboard(
    records: Sequence[PacketRecord],
    filtered: Sequence[PacketRecord],
    *, source_slug: str, source_revision: int, clear_filters: Callable[[], None], live_window: bool = False,
) -> None:
    """Render every analytical output from the same filtered selection."""
    selection_state = "Filtered selection" if len(filtered) != len(records) else "Complete capture"
    st.markdown(
        f'<div class="ns-selection-bar"><span>Showing <strong>{len(filtered):,}</strong> of '
        f'<strong>{len(records):,}</strong> normalized packet records</span>'
        f'<span class="ns-selection-tag">{escape(selection_state)}</span></div>',
        unsafe_allow_html=True,
    )
    if not filtered:
        st.markdown('<div class="ns-notice ns-notice-neutral">No packets match the current filters.</div>',
                    unsafe_allow_html=True)
        st.button("Clear filters", key="empty_clear_filters", on_click=clear_filters)
        return

    stats = summary_stats(filtered)
    columns = st.columns(5, gap="small")
    columns[0].metric("Packets", f"{stats.total_packets:,}")
    columns[1].metric("Captured data", format_bytes(stats.total_bytes),
                      help="Captured frame bytes, not application payload bytes.")
    columns[2].metric("Packet rate", f"{stats.packets_per_second:.2f}/s" if stats.packets_per_second is not None else "N/A",
                      help="Packets divided by the selected capture timestamp span; not internet speed.")
    columns[3].metric("Byte rate", format_bytes(stats.bytes_per_second) + "/s" if stats.bytes_per_second is not None else "N/A",
                      help="Captured bytes divided by the observation span, not physical link capacity.")
    columns[4].metric("Unique IPs", f"{stats.unique_ips:,}")

    series = time_series(filtered, last_seconds=60 if live_window else None)
    with st.container(border=True):
        scope = "Rolling 60-second window" if live_window else "PCAP timestamps · 1 second bins"
        _section_header("Traffic timeline", "Packet volume and captured frame bytes share the same observation clock.", scope)
        st.plotly_chart(_traffic_figure(series), width="stretch", config=CHART_CONFIG)

    chart_columns = st.columns([.92, 1.35], gap="small")
    distribution = protocol_distribution(filtered)
    with chart_columns[0], st.container(border=True):
        _section_header("Protocol mix", "One mutually exclusive primary label per packet.", "NO DOUBLE COUNTING")
        st.plotly_chart(_protocol_figure(distribution), width="stretch", config=CHART_CONFIG)
    with chart_columns[1], st.container(border=True):
        _section_header("Top endpoints", "Most frequently observed source and destination IPs.", "TOP 6 / DIRECTION")
        st.plotly_chart(_endpoint_figure(top_ips(filtered, "source"), top_ips(filtered, "destination")),
                        width="stretch", config=CHART_CONFIG)

    with st.container(border=True):
        header, action = st.columns([5, 1.25], vertical_alignment="center")
        with header:
            _section_header("Packet explorer", "Normalized header metadata; payload bytes are never included.",
                            f"{len(filtered):,} ROWS")
        with action:
            st.download_button("Export filtered CSV", data=records_to_csv(list(filtered)),
                               file_name=f"framesight_packets_{source_slug}.csv", mime="text/csv",
                               help="IP addresses and DNS names can still be sensitive.", width="stretch")
        st.dataframe(
            records_dataframe(filtered), hide_index=True, width="stretch", height=390,
            column_config={
                "ID": st.column_config.NumberColumn("ID", format="%d", width="small"),
                "Timestamp": st.column_config.TextColumn("Timestamp", width="medium"),
                "Source": st.column_config.TextColumn("Source", width="medium"),
                "Destination": st.column_config.TextColumn("Destination", width="medium"),
                "Protocol": st.column_config.TextColumn("Protocol", width="small"),
                "Bytes": st.column_config.NumberColumn("Bytes", format="%d B", width="small"),
                "Info": st.column_config.TextColumn("Info", width="large"),
            },
        )

    inspector_tab, flow_tab, alert_tab, learn_tab = st.tabs(["Inspect", "Flows", "Signals", "Learn"])
    with inspector_tab:
        options = [record.packet_id for record in filtered]
        records_by_id = {record.packet_id: record for record in filtered}
        chosen = st.selectbox("Packet record", options,
                              format_func=lambda packet_id: f"#{packet_id:04d}  {records_by_id[packet_id].summary}",
                              key=f"inspector_{source_revision}")
        render_packet_inspector(records_by_id[chosen])
    with flow_tab:
        st.markdown('<div class="ns-notice ns-notice-neutral">TCP and UDP packets are grouped by a '
                    'direction-independent 5-tuple. ARP and ICMP are deliberately excluded.</div>',
                    unsafe_allow_html=True)
        flows = flows_dataframe(filtered)
        if flows.empty:
            st.info("No complete TCP/UDP IP flows are present in this selection.")
        else:
            st.dataframe(flows, hide_index=True, width="stretch")
    with alert_tab:
        st.markdown('<div class="ns-notice ns-notice-warn">These are tunable patterns worth investigating—not '
                    'security incidents or proof of an attack.</div>', unsafe_allow_html=True)
        threshold_columns = st.columns(4)
        rate_threshold = threshold_columns[0].number_input("Packet threshold", 2, 1000, 25, key="rate_threshold")
        rate_window = threshold_columns[1].number_input("Rate window (s)", 1, 600, 10, key="rate_window")
        port_threshold = threshold_columns[2].number_input("Distinct ports", 2, 65535, 10, key="port_threshold")
        port_window = threshold_columns[3].number_input("Port window (s)", 1, 3600, 60, key="port_window")
        findings = heuristic_observations(filtered, int(rate_threshold), int(rate_window),
                                          int(port_threshold), int(port_window))
        if findings:
            st.dataframe(pd.DataFrame(findings), hide_index=True, width="stretch")
        else:
            st.success("No records cross the selected heuristic thresholds.")
    with learn_tab:
        st.markdown(CONCEPTS_MARKDOWN)
        st.markdown("### OSI and TCP/IP mapping")
        st.dataframe(pd.DataFrame(OSI_MAPPING, columns=["OSI", "TCP/IP", "What FrameSight can show"]),
                     hide_index=True, width="stretch")
        st.markdown("### Classroom mini-experiments")
        for name, instructions in EXPERIMENTS.items():
            with st.expander(name):
                st.markdown(instructions)

    with st.expander("Raw normalized record · payload excluded"):
        st.json(asdict(filtered[0]))
