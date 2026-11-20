"""FrameSight Streamlit application entry point."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import streamlit as st

from framesight.capture import CaptureController, CaptureError, list_interfaces
from framesight.filters import PacketFilters, filter_records
from framesight.pcap_io import PcapImportError, load_pcap, load_pcap_bytes
from framesight.ui import (
    inject_styles,
    render_dashboard,
    render_page_header,
    sidebar_brand,
    sidebar_label,
    sidebar_note,
)

ROOT = Path(__file__).resolve().parent
DEMO_PATH = ROOT / "samples" / "framesight_demo.pcap"
MODES = ("Demo PCAP", "Import PCAP", "Live Capture")


def _load_demo() -> None:
    result = load_pcap(DEMO_PATH)
    st.session_state.records = list(result.records)
    st.session_state.load_warnings = list(result.warnings)
    st.session_state.source_revision += 1
    st.session_state.source_label = "DEMO SAMPLE"
    st.session_state.source_slug = "demo"


def _clear_filter_state() -> None:
    defaults = {
        "filter_protocol": "All",
        "filter_src_ip": "",
        "filter_dst_ip": "",
        "filter_ip_mode": "Contains",
        "filter_port": "",
        "filter_keyword": "",
    }
    for key, value in defaults.items():
        st.session_state[key] = value


def _initialize_state() -> None:
    if "capture_controller" not in st.session_state:
        st.session_state.capture_controller = CaptureController()
    if "source_revision" not in st.session_state:
        st.session_state.source_revision = 0
    if "records" not in st.session_state:
        st.session_state.records = []
        st.session_state.load_warnings = []
        st.session_state.source_label = "DEMO SAMPLE"
        st.session_state.source_slug = "demo"
        _clear_filter_state()
        _load_demo()
    if "active_mode" not in st.session_state:
        st.session_state.active_mode = "Demo PCAP"
    if "mode_selector" not in st.session_state:
        st.session_state.mode_selector = st.session_state.active_mode


def _switch_mode(mode: str) -> None:
    controller: CaptureController = st.session_state.capture_controller
    if mode == st.session_state.active_mode:
        return
    try:
        controller.stop()
    except CaptureError:
        pass
    st.session_state.active_mode = mode
    st.session_state.records = []
    st.session_state.load_warnings = []
    st.session_state.source_revision += 1
    _clear_filter_state()
    if mode == "Demo PCAP":
        _load_demo()
    elif mode == "Import PCAP":
        st.session_state.source_label = "IMPORTED PCAP"
        st.session_state.source_slug = "imported"
    else:
        try:
            controller.clear()
        except CaptureError:
            pass
        st.session_state.source_label = "LIVE · IDLE"
        st.session_state.source_slug = "live"


def _source_controls(mode: str) -> None:
    controller: CaptureController = st.session_state.capture_controller
    if mode == "Demo PCAP":
        sidebar_note("Deterministic offline capture. No internet, Npcap, or administrator rights required.")
        if st.sidebar.button("Reload sample data", width="stretch"):
            _load_demo()
        if DEMO_PATH.exists():
            st.sidebar.download_button(
                "Download sample PCAP",
                DEMO_PATH.read_bytes(),
                file_name="framesight_demo.pcap",
                mime="application/vnd.tcpdump.pcap",
                width="stretch",
            )
    elif mode == "Import PCAP":
        upload = st.sidebar.file_uploader("Choose a classic .pcap file", type=["pcap"])
        sidebar_note("Classic PCAP only · 20 MiB · 20,000 packet limit. Uploaded files are removed after parsing.")
        if st.sidebar.button("Analyze capture", disabled=upload is None, width="stretch", type="primary"):
            try:
                result = load_pcap_bytes(upload.getvalue(), upload.name)
                st.session_state.records = list(result.records)
                st.session_state.load_warnings = list(result.warnings)
                st.session_state.source_revision += 1
                st.session_state.source_label = "IMPORTED PCAP"
                st.session_state.source_slug = "imported"
                _clear_filter_state()
            except PcapImportError as exc:
                st.sidebar.error(str(exc))
        if st.sidebar.button("Reset imported data", width="stretch"):
            st.session_state.records = []
            st.session_state.load_warnings = []
            st.session_state.source_revision += 1
    else:
        interfaces = list_interfaces()
        if interfaces:
            by_label = {item.label: item.identifier for item in interfaces}
            selected_label = st.sidebar.selectbox("Capture interface", list(by_label), key="live_interface")
            selected_interface = by_label[selected_label]
        else:
            selected_interface = ""
            st.sidebar.error("No capture interfaces could be enumerated. Demo and PCAP modes still work.")
        snapshot = controller.status()
        button_columns = st.sidebar.columns(2)
        if button_columns[0].button(
            "Start",
            disabled=snapshot.state in {"starting", "capturing"} or not selected_interface,
            type="primary",
            width="stretch",
        ):
            try:
                if snapshot.state == "error":
                    controller.clear()
                controller.start(selected_interface)
                st.session_state.source_label = "LIVE · CAPTURING"
                st.session_state.source_revision += 1
            except CaptureError as exc:
                st.sidebar.error(str(exc))
        if button_columns[1].button(
            "Stop",
            disabled=snapshot.state not in {"starting", "capturing"},
            width="stretch",
        ):
            try:
                controller.stop()
                controller.drain(5_000)
                st.session_state.records = list(controller.records())
                st.session_state.source_label = "LIVE · STOPPED"
            except CaptureError as exc:
                st.sidebar.error(str(exc))
        if st.sidebar.button("Reset live capture", width="stretch"):
            try:
                controller.clear()
            except CaptureError as exc:
                st.sidebar.error(str(exc))
            st.session_state.records = []
            st.session_state.source_label = "LIVE · IDLE"
            st.session_state.source_revision += 1
        snapshot = controller.status()
        st.sidebar.markdown(f"**Status:** `{snapshot.state.upper()}`  \n**Duration:** {snapshot.duration_seconds:.1f}s")
        st.sidebar.caption(
            f"Retained {snapshot.retained_records:,} · queued {snapshot.queued_records:,} · "
            f"dropped {snapshot.dropped_queue + snapshot.dropped_retention:,}"
        )
        if snapshot.error:
            st.sidebar.error(snapshot.error)
        sidebar_note("Local interface only. Switched LAN traffic may not be visible, and HTTPS content remains encrypted.")


def _filter_controls(records) -> PacketFilters:
    st.sidebar.divider()
    sidebar_label("Explore")
    with st.sidebar.expander("Packet filters", expanded=True):
        st.button("Reset filters", on_click=_clear_filter_state, width="stretch")
        protocol = st.selectbox(
            "Primary protocol",
            ["All", "TCP", "UDP", "ICMP", "DNS", "ARP", "Other"],
            key="filter_protocol",
        )
        ip_mode = st.radio("IP matching", ["Contains", "Exact"], horizontal=True, key="filter_ip_mode")
        src_ip = st.text_input("Source IP", key="filter_src_ip", placeholder="192.168.50")
        dst_ip = st.text_input("Destination IP", key="filter_dst_ip", placeholder="203.0.113.8")
        port_text = st.text_input("Either port", key="filter_port", placeholder="53")
        keyword = st.text_input("Summary / DNS keyword", key="filter_keyword", placeholder="example.com")
        either_port = None
        if port_text.strip():
            try:
                either_port = int(port_text)
                if not 0 <= either_port <= 65535:
                    raise ValueError
            except ValueError:
                st.warning("Enter a whole-number port from 0 to 65535.")
                either_port = None

        start_time = end_time = None
        if records and st.session_state.active_mode != "Live Capture":
            minimum = min(record.capture_time for record in records)
            maximum = max(record.capture_time for record in records)
            if maximum > minimum:
                start_time, end_time = st.slider(
                    "Capture time window",
                    min_value=minimum,
                    max_value=maximum,
                    value=(minimum, maximum),
                    step=timedelta(seconds=1),
                    format="HH:mm:ss",
                    key=f"time_filter_{st.session_state.source_revision}",
                )
    return PacketFilters(protocol, src_ip, dst_ip, ip_mode, either_port, keyword, start_time, end_time)


def main() -> None:
    st.set_page_config(page_title="FrameSight", page_icon="◫", layout="wide", initial_sidebar_state="expanded")
    inject_styles()
    _initialize_state()

    sidebar_brand()
    sidebar_label("Input source")
    mode = st.sidebar.radio("Data source", MODES, key="mode_selector", label_visibility="collapsed")
    _switch_mode(mode)
    _source_controls(mode)
    filters = _filter_controls(st.session_state.records)

    render_page_header(st.session_state.source_label)

    for warning in st.session_state.load_warnings:
        st.warning(warning)
    if mode == "Import PCAP" and not st.session_state.records:
        st.info("Upload a classic `.pcap` file in the sidebar, then choose **Analyze uploaded PCAP**. The bundled Demo remains available without privileges.")
    if not DEMO_PATH.exists():
        st.error("The bundled demo PCAP is missing. Run `python scripts/generate_demo_pcap.py`.")

    controller: CaptureController = st.session_state.capture_controller

    def data_panel() -> None:
        if mode == "Live Capture":
            controller.drain(1_000)
            st.session_state.records = list(controller.records())
            snapshot = controller.status()
            status_columns = st.columns(4)
            status_columns[0].metric("Capture state", snapshot.state.upper())
            status_columns[1].metric("Capture duration", f"{snapshot.duration_seconds:.1f} s")
            status_columns[2].metric("Retained", f"{snapshot.retained_records:,} / 5,000")
            status_columns[3].metric("Dropped", f"{snapshot.dropped_queue + snapshot.dropped_retention:,}")
            if snapshot.error:
                st.error(snapshot.error)
        records = st.session_state.records
        filtered = filter_records(records, filters)
        render_dashboard(
            records,
            filtered,
            source_slug=st.session_state.source_slug,
            source_revision=st.session_state.source_revision,
            clear_filters=_clear_filter_state,
            live_window=mode == "Live Capture",
        )

    if mode == "Live Capture":
        refresh = "1s" if controller.status().state == "capturing" else None

        @st.fragment(run_every=refresh)
        def live_data_panel() -> None:
            data_panel()

        live_data_panel()
    else:
        data_panel()
    st.divider()
    st.markdown(
        '<p class="ns-footer">FrameSight is an educational packet analyzer—not a firewall, certified IDS, '
        'internet-speed test, or HTTPS decryption tool. Analyze only traffic and files you are authorized to inspect.</p>',
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
