from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterator

from .models import RawPacket


class PcapError(ValueError):
    pass


MAGIC = {
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
}


def read_pcap(path: str | Path, max_packets: int | None = None) -> tuple[int, Iterator[RawPacket]]:
    p = Path(path)
    fh = p.open("rb")
    magic = fh.read(4)
    if magic not in MAGIC:
        fh.close()
        raise PcapError("unsupported file format: expected classic pcap")

    endian, ts_divisor = MAGIC[magic]
    header = fh.read(20)
    if len(header) != 20:
        fh.close()
        raise PcapError("truncated pcap global header")

    _version_major, _version_minor, _thiszone, _sigfigs, _snaplen, link_type = struct.unpack(
        endian + "HHiIII", header
    )

    def packets() -> Iterator[RawPacket]:
        try:
            index = 0
            while max_packets is None or index < max_packets:
                packet_header = fh.read(16)
                if not packet_header:
                    break
                if len(packet_header) != 16:
                    raise PcapError("truncated packet header")

                ts_sec, ts_frac, captured_length, original_length = struct.unpack(
                    endian + "IIII", packet_header
                )
                if captured_length > 256 * 1024 * 1024:
                    raise PcapError(f"refusing unreasonable packet size: {captured_length}")

                data = fh.read(captured_length)
                if len(data) != captured_length:
                    raise PcapError("truncated packet data")

                index += 1
                yield RawPacket(
                    index=index,
                    timestamp=ts_sec + (ts_frac / ts_divisor),
                    captured_length=captured_length,
                    original_length=original_length,
                    data=data,
                )
        finally:
            fh.close()

    return link_type, packets()
