from __future__ import annotations

import ipaddress
import struct

from .models import Packet, RawPacket


ETHERNET = 1

ETH_TYPES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
}

IP_PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6",
}

TCP_FLAG_BITS = {
    "fin": 0x01,
    "syn": 0x02,
    "rst": 0x04,
    "psh": 0x08,
    "ack": 0x10,
    "urg": 0x20,
    "ece": 0x40,
    "cwr": 0x80,
}

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ")


def decode_packet(raw: RawPacket, link_type: int) -> Packet:
    packet = Packet(
        index=raw.index,
        timestamp=raw.timestamp,
        captured_length=raw.captured_length,
        original_length=raw.original_length,
        link_type=link_type,
    )

    if link_type != ETHERNET:
        packet.notes.append(f"unsupported link type {link_type}")
        packet.payload = raw.data
        return packet

    _decode_ethernet(packet, raw.data)
    return packet


def _decode_ethernet(packet: Packet, data: bytes) -> None:
    if len(data) < 14:
        packet.notes.append("short ethernet frame")
        return

    packet.dst_mac = _mac(data[0:6])
    packet.src_mac = _mac(data[6:12])
    eth_type = int.from_bytes(data[12:14], "big")
    offset = 14

    if eth_type == 0x8100 and len(data) >= 18:
        packet.layers.append("802.1Q")
        eth_type = int.from_bytes(data[16:18], "big")
        offset = 18

    packet.eth_type = eth_type
    packet.layers.append(ETH_TYPES.get(eth_type, f"0x{eth_type:04x}"))
    payload = data[offset:]

    if eth_type == 0x0800:
        _decode_ipv4(packet, payload)
    elif eth_type == 0x86DD:
        _decode_ipv6(packet, payload)
    elif eth_type == 0x0806:
        _decode_arp(packet, payload)
    else:
        packet.payload = payload


def _decode_ipv4(packet: Packet, data: bytes) -> None:
    if len(data) < 20:
        packet.notes.append("short ipv4 packet")
        return

    version_ihl = data[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4
    if version != 4 or ihl < 20 or len(data) < ihl:
        packet.notes.append("invalid ipv4 header")
        return

    total_length = int.from_bytes(data[2:4], "big")
    proto_num = data[9]
    flags_fragment = int.from_bytes(data[6:8], "big")
    fragment_offset = flags_fragment & 0x1FFF
    packet.ip_version = 4
    packet.src_ip = str(ipaddress.IPv4Address(data[12:16]))
    packet.dst_ip = str(ipaddress.IPv4Address(data[16:20]))

    if total_length < ihl:
        packet.notes.append("invalid ipv4 total length")
        return

    ip_payload = data[ihl:total_length or len(data)]
    packet.protocol = IP_PROTOCOLS.get(proto_num, f"IP-{proto_num}")
    packet.layers.append(packet.protocol)

    if fragment_offset:
        packet.payload = ip_payload
        packet.notes.append("non-first ipv4 fragment")
        return

    _decode_transport(packet, proto_num, ip_payload)


def _decode_ipv6(packet: Packet, data: bytes) -> None:
    if len(data) < 40:
        packet.notes.append("short ipv6 packet")
        return

    version = data[0] >> 4
    if version != 6:
        packet.notes.append("invalid ipv6 header")
        return

    payload_length = int.from_bytes(data[4:6], "big")
    next_header = data[6]
    packet.ip_version = 6
    packet.src_ip = str(ipaddress.IPv6Address(data[8:24]))
    packet.dst_ip = str(ipaddress.IPv6Address(data[24:40]))

    payload = data[40 : 40 + payload_length if payload_length else len(data)]
    next_header, payload = _skip_ipv6_extensions(next_header, payload, packet)
    packet.protocol = IP_PROTOCOLS.get(next_header, f"IP-{next_header}")
    packet.layers.append(packet.protocol)
    _decode_transport(packet, next_header, payload)


def _skip_ipv6_extensions(next_header: int, payload: bytes, packet: Packet) -> tuple[int, bytes]:
    extension_headers = {0, 43, 60}
    while next_header in extension_headers:
        if len(payload) < 2:
            return next_header, payload
        header_len = (payload[1] + 1) * 8
        if len(payload) < header_len:
            return next_header, payload
        packet.layers.append(f"IPv6-ext-{next_header}")
        next_header = payload[0]
        payload = payload[header_len:]

    if next_header == 44:
        packet.layers.append("IPv6-fragment")
        packet.notes.append("ipv6 fragment header not reassembled")

    return next_header, payload


def _decode_arp(packet: Packet, data: bytes) -> None:
    packet.protocol = "ARP"
    if len(data) < 28:
        packet.notes.append("short arp packet")
        return

    op = int.from_bytes(data[6:8], "big")
    packet.arp_op = {1: "request", 2: "reply"}.get(op, str(op))
    packet.src_mac = _mac(data[8:14])
    packet.src_ip = str(ipaddress.IPv4Address(data[14:18]))
    packet.dst_mac = _mac(data[18:24])
    packet.dst_ip = str(ipaddress.IPv4Address(data[24:28]))


def _decode_transport(packet: Packet, proto_num: int, payload: bytes) -> None:
    if proto_num == 6:
        _decode_tcp(packet, payload)
    elif proto_num == 17:
        _decode_udp(packet, payload)
    else:
        packet.payload = payload


def _decode_tcp(packet: Packet, data: bytes) -> None:
    if len(data) < 20:
        packet.notes.append("short tcp segment")
        packet.payload = data
        return

    packet.src_port = int.from_bytes(data[0:2], "big")
    packet.dst_port = int.from_bytes(data[2:4], "big")
    data_offset = (data[12] >> 4) * 4
    flags = data[13]
    packet.tcp_flags = {name: bool(flags & bit) for name, bit in TCP_FLAG_BITS.items()}
    if data_offset < 20 or len(data) < data_offset:
        packet.notes.append("invalid tcp header")
        packet.payload = data[20:]
        return

    packet.payload = data[data_offset:]
    _decode_application(packet)


def _decode_udp(packet: Packet, data: bytes) -> None:
    if len(data) < 8:
        packet.notes.append("short udp datagram")
        packet.payload = data
        return

    packet.src_port = int.from_bytes(data[0:2], "big")
    packet.dst_port = int.from_bytes(data[2:4], "big")
    length = int.from_bytes(data[4:6], "big")
    packet.payload = data[8:length if length >= 8 else len(data)]
    _decode_application(packet)


def _decode_application(packet: Packet) -> None:
    ports = {packet.src_port, packet.dst_port}
    if 53 in ports:
        _decode_dns(packet)

    if packet.protocol == "TCP":
        _decode_http(packet)
        if 443 in ports or 8443 in ports:
            packet.tls_sni = _extract_tls_sni(packet.payload)


def _decode_dns(packet: Packet) -> None:
    payload = packet.payload
    if len(payload) < 12:
        return
    try:
        _txid, flags, qdcount, _ancount, _nscount, _arcount = struct.unpack("!HHHHHH", payload[:12])
        packet.dns_rcode = flags & 0x0F
        offset = 12
        names: list[str] = []
        for _ in range(min(qdcount, 20)):
            name, offset = _read_dns_name(payload, offset)
            if not name:
                break
            names.append(name)
            offset += 4
            if offset > len(payload):
                break
        packet.dns_queries = names
    except (IndexError, ValueError, struct.error):
        packet.notes.append("could not parse dns payload")


def _read_dns_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    if depth > 10:
        raise ValueError("dns compression loop")

    labels: list[str] = []
    jumped = False

    while True:
        if offset >= len(data):
            raise ValueError("dns name out of bounds")
        length = data[offset]
        offset += 1

        if length == 0:
            break

        if length & 0xC0 == 0xC0:
            if offset >= len(data):
                raise ValueError("dns pointer out of bounds")
            pointer = ((length & 0x3F) << 8) | data[offset]
            offset += 1
            next_offset = offset
            suffix, _ = _read_dns_name(data, pointer, depth + 1)
            if suffix:
                labels.append(suffix)
            jumped = True
            offset = next_offset
            break

        if length & 0xC0:
            raise ValueError("unsupported dns label type")

        label = data[offset : offset + length]
        if len(label) != length:
            raise ValueError("truncated dns label")
        labels.append(label.decode("ascii", errors="replace"))
        offset += length

    return ".".join(labels), offset


def _decode_http(packet: Packet) -> None:
    payload = packet.payload
    if not payload:
        return

    if not (payload.startswith(HTTP_METHODS) or payload.startswith(b"HTTP/")):
        return

    try:
        text = payload[:4096].decode("iso-8859-1", errors="replace")
    except UnicodeDecodeError:
        return

    lines = text.splitlines()
    if not lines:
        return

    first = lines[0].strip()
    parts = first.split()
    if payload.startswith(b"HTTP/") and len(parts) >= 2 and parts[1].isdigit():
        packet.http_status = int(parts[1])
    elif len(parts) >= 2:
        packet.http_method = parts[0]
        packet.http_path = parts[1]

    for line in lines[1:]:
        if line.lower().startswith("host:"):
            packet.http_host = line.split(":", 1)[1].strip()
            break


def _extract_tls_sni(data: bytes) -> str | None:
    try:
        if len(data) < 5 or data[0] != 22:
            return None
        record_len = int.from_bytes(data[3:5], "big")
        record = data[5 : 5 + record_len]
        if len(record) < 42 or record[0] != 1:
            return None

        offset = 4
        offset += 2 + 32
        if offset >= len(record):
            return None
        session_id_len = record[offset]
        offset += 1 + session_id_len
        if offset + 2 > len(record):
            return None
        cipher_len = int.from_bytes(record[offset : offset + 2], "big")
        offset += 2 + cipher_len
        if offset >= len(record):
            return None
        compression_len = record[offset]
        offset += 1 + compression_len
        if offset + 2 > len(record):
            return None
        extensions_len = int.from_bytes(record[offset : offset + 2], "big")
        offset += 2
        end = min(len(record), offset + extensions_len)

        while offset + 4 <= end:
            ext_type = int.from_bytes(record[offset : offset + 2], "big")
            ext_len = int.from_bytes(record[offset + 2 : offset + 4], "big")
            offset += 4
            ext_data = record[offset : offset + ext_len]
            offset += ext_len
            if ext_type != 0 or len(ext_data) < 5:
                continue
            list_len = int.from_bytes(ext_data[0:2], "big")
            pos = 2
            list_end = min(len(ext_data), pos + list_len)
            while pos + 3 <= list_end:
                name_type = ext_data[pos]
                name_len = int.from_bytes(ext_data[pos + 1 : pos + 3], "big")
                pos += 3
                name = ext_data[pos : pos + name_len]
                pos += name_len
                if name_type == 0 and name:
                    return name.decode("idna", errors="replace")
    except (IndexError, ValueError):
        return None
    return None


def _mac(data: bytes) -> str:
    return ":".join(f"{b:02x}" for b in data)
