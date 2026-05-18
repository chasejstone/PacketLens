from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from packetlens import analyze_pcap
from packetlens.pcap import read_pcap


class PacketLensTests(unittest.TestCase):
    def test_pcap_reader_counts_packets(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "sample.pcap"
            path.write_bytes(_pcap([_dns_query_packet("example.com")]))
            link_type, packets = read_pcap(path)
            self.assertEqual(link_type, 1)
            self.assertEqual(len(list(packets)), 1)

    def test_analysis_summarizes_dns_http_and_tcp_fanout(self) -> None:
        packets = [_dns_query_packet("example.com")]
        packets.append(_http_packet(b"POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nuser=deo&password=secret"))
        for port in range(20, 32):
            packets.append(_tcp_syn_packet("10.0.0.5", "192.0.2.10", 40000 + port, port))

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "sample.pcap"
            path.write_bytes(_pcap(packets))
            result = analyze_pcap(path)

        titles = {observation.title for observation in result.observations}
        self.assertIn("HTTP field visible in cleartext", titles)
        self.assertIn("TCP SYN fan-out", titles)
        self.assertEqual(result.dns_names[0]["name"], "example.com")
        self.assertEqual(result.http_hosts[0]["host"], "example.com")


def _pcap(frames: list[bytes]) -> bytes:
    out = bytearray()
    out += b"\xd4\xc3\xb2\xa1"
    out += struct.pack("<HHiiii", 2, 4, 0, 0, 65535, 1)
    ts = 1_700_000_000
    for i, frame in enumerate(frames):
        out += struct.pack("<IIII", ts + i, 0, len(frame), len(frame))
        out += frame
    return bytes(out)


def _ethernet(payload: bytes, eth_type: int = 0x0800) -> bytes:
    return bytes.fromhex("00112233445566778899aabb") + eth_type.to_bytes(2, "big") + payload


def _ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    src_b = bytes(int(part) for part in src.split("."))
    dst_b = bytes(int(part) for part in dst.split("."))
    total_len = 20 + len(payload)
    header = bytearray(20)
    header[0] = 0x45
    header[1] = 0
    header[2:4] = total_len.to_bytes(2, "big")
    header[4:6] = b"\x00\x01"
    header[6:8] = b"\x00\x00"
    header[8] = 64
    header[9] = proto
    header[12:16] = src_b
    header[16:20] = dst_b
    header[10:12] = _checksum(bytes(header)).to_bytes(2, "big")
    return _ethernet(bytes(header) + payload)


def _udp(src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    return struct.pack("!HHHH", src_port, dst_port, length, 0) + payload


def _tcp(src_port: int, dst_port: int, flags: int, payload: bytes = b"") -> bytes:
    seq = 1
    ack = 0
    offset = 5 << 4
    window = 8192
    return struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, offset, flags, window, 0, 0) + payload


def _dns_query_packet(name: str) -> bytes:
    labels = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split("."))
    dns = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack("!HH", 1, 1)
    return _ipv4("10.0.0.5", "8.8.8.8", 17, _udp(53000, 53, dns))


def _http_packet(payload: bytes) -> bytes:
    return _ipv4("10.0.0.5", "93.184.216.34", 6, _tcp(51000, 80, 0x18, payload))


def _tcp_syn_packet(src: str, dst: str, src_port: int, dst_port: int) -> bytes:
    return _ipv4(src, dst, 6, _tcp(src_port, dst_port, 0x02))


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(int.from_bytes(data[i : i + 2], "big") for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


if __name__ == "__main__":
    unittest.main()
