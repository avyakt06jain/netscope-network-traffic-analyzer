"""Bounded classic-PCAP import and normalized CSV export."""

from __future__ import annotations

import argparse
import csv
import io
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from scapy.utils import PcapReader

from .analytics import protocol_distribution, summary_stats
from .models import PacketRecord
from .parser import normalize_packet

MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_PACKETS = 20_000
CLASSIC_PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


class PcapImportError(ValueError):
    """Base class for user-facing PCAP import failures."""


class PcapTooLargeError(PcapImportError):
    """Raised when a file exceeds the explicit upload limit."""


class UnsupportedPcapError(PcapImportError):
    """Raised for PCAPNG or a non-classic-PCAP magic value."""


@dataclass(frozen=True, slots=True)
class PcapLoadResult:
    """Successful records plus bounded-import diagnostics."""

    records: tuple[PacketRecord, ...]
    read_packets: int
    skipped_packets: int
    truncated: bool
    warnings: tuple[str, ...]


def _validate_file(path: Path, max_file_bytes: int) -> None:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise PcapImportError(f"Could not access PCAP: {exc}") from exc
    if size == 0:
        raise PcapImportError("The PCAP file is empty.")
    if size > max_file_bytes:
        raise PcapTooLargeError(
            f"The PCAP is {size / (1024 * 1024):.1f} MiB; the limit is {max_file_bytes / (1024 * 1024):.0f} MiB."
        )
    try:
        with path.open("rb") as handle:
            magic = handle.read(4)
    except OSError as exc:
        raise PcapImportError(f"Could not read PCAP: {exc}") from exc
    if magic == PCAPNG_MAGIC:
        raise UnsupportedPcapError("PCAPNG is not supported. Export the capture as classic PCAP first.")
    if magic not in CLASSIC_PCAP_MAGIC:
        raise UnsupportedPcapError("This is not a recognized classic PCAP file (bad magic header).")


def load_pcap(
    path: str | Path,
    *,
    max_file_bytes: int = MAX_FILE_BYTES,
    max_packets: int = MAX_PACKETS,
) -> PcapLoadResult:
    """Stream a bounded classic PCAP and normalize each readable packet."""

    source = Path(path)
    _validate_file(source, max_file_bytes)
    records: list[PacketRecord] = []
    warnings: list[str] = []
    skipped = 0
    read_count = 0
    truncated = False
    try:
        with PcapReader(str(source)) as reader:
            for packet in reader:
                if read_count >= max_packets:
                    truncated = True
                    break
                read_count += 1
                try:
                    records.append(normalize_packet(packet, len(records) + 1))
                except Exception as exc:  # isolate a corrupt individual record
                    skipped += 1
                    if len(warnings) < 5:
                        warnings.append(f"Packet {read_count} was skipped: {exc}")
    except PcapImportError:
        raise
    except Exception as exc:
        if not records:
            raise PcapImportError(f"The PCAP could not be decoded: {exc}") from exc
        warnings.append(f"Parsing stopped after {read_count} packets: {exc}")
    if truncated:
        warnings.append(f"The capture contains more than {max_packets:,} packets; only the first {max_packets:,} were read.")
    if not records and skipped:
        raise PcapImportError("No packets could be normalized from this capture.")
    return PcapLoadResult(tuple(records), read_count, skipped, truncated, tuple(warnings))


def load_pcap_bytes(
    data: bytes,
    filename: str,
    *,
    max_file_bytes: int = MAX_FILE_BYTES,
    max_packets: int = MAX_PACKETS,
) -> PcapLoadResult:
    """Safely parse uploaded bytes through a short-lived temporary file."""

    if not filename.lower().endswith(".pcap"):
        raise UnsupportedPcapError("Choose a file ending in .pcap. PCAPNG is not supported.")
    if len(data) > max_file_bytes:
        raise PcapTooLargeError("The uploaded PCAP exceeds the 20 MiB limit.")
    temp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(prefix="netscope_", suffix=".pcap", delete=False) as handle:
            handle.write(data)
            temp_path = handle.name
        return load_pcap(temp_path, max_file_bytes=max_file_bytes, max_packets=max_packets)
    finally:
        if temp_path:
            try:
                os.unlink(temp_path)
            except FileNotFoundError:
                pass


def records_to_csv(records: list[PacketRecord] | tuple[PacketRecord, ...]) -> bytes:
    """Export normalized header metadata as UTF-8 CSV, excluding payloads."""

    fieldnames = list(PacketRecord.__dataclass_fields__)
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for record in records:
        writer.writerow(record.as_dict())
    return output.getvalue().encode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate and summarize a classic PCAP with NetScope.")
    parser.add_argument("pcap", type=Path)
    args = parser.parse_args()
    result = load_pcap(args.pcap)
    stats = summary_stats(result.records)
    print(f"Packets: {stats.total_packets}; bytes: {stats.total_bytes}; skipped: {result.skipped_packets}")
    distribution = protocol_distribution(result.records)
    for row in distribution.itertuples(index=False):
        print(f"{row.protocol}: {row.packets}")


if __name__ == "__main__":
    main()
