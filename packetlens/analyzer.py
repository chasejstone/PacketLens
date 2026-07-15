from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter, defaultdict
from functools import lru_cache
from pathlib import Path
from statistics import mean, pstdev
from typing import Iterable

from .decode import decode_packet
from .models import AnalysisResult, Observation, Packet
from .pcap import read_pcap


HTTP_FIELD_PATTERN = re.compile(rb"(?i)\b[a-z][a-z0-9_-]{1,32}\s*=\s*[^&\s;]{1,120}")

NOTABLE_PORTS = {
    23: "telnet",
    2323: "alternate telnet",
    4444: "high-number service",
    5555: "adb or custom service",
    6667: "irc",
    9001: "application service",
    31337: "unusual high port",
}


def decode_pcap(path: str | Path, max_packets: int | None = None) -> list[Packet]:
    link_type, raw_packets = read_pcap(path, max_packets=max_packets)
    return [decode_packet(raw, link_type) for raw in raw_packets]


def summarize_packets(source: str, packets: list[Packet], top: int = 10) -> AnalysisResult:
    protocol_counts = Counter(p.protocol or "OTHER" for p in packets)
    captured_bytes = sum(p.captured_length for p in packets)
    started_at = min((packet.timestamp for packet in packets), default=None)
    ended_at = max((packet.timestamp for packet in packets), default=None)
    duration = (ended_at - started_at) if started_at is not None and ended_at is not None else 0.0

    talkers: Counter[str] = Counter()
    flows: Counter[tuple] = Counter()
    ports: Counter[tuple[str, int]] = Counter()
    dns_names: Counter[str] = Counter()
    http_hosts: Counter[str] = Counter()
    tls_names: Counter[str] = Counter()

    for packet in packets:
        if packet.src_ip:
            talkers[packet.src_ip] += packet.original_length
        if packet.dst_ip:
            talkers[packet.dst_ip] += packet.original_length
        flow_key = packet.flow_key()
        if flow_key:
            flows[flow_key] += packet.original_length
        if packet.src_port is not None:
            ports[("src", packet.src_port)] += 1
        if packet.dst_port is not None:
            ports[("dst", packet.dst_port)] += 1
        for name in packet.dns_queries:
            dns_names[name.lower()] += 1
        if packet.http_host:
            http_hosts[packet.http_host.lower()] += 1
        if packet.tls_sni:
            tls_names[packet.tls_sni.lower()] += 1

    observations = _observations(packets)
    observations.sort(key=lambda item: item.category)

    return AnalysisResult(
        source=source,
        packets=len(packets),
        captured_bytes=captured_bytes,
        duration=duration,
        started_at=started_at,
        ended_at=ended_at,
        protocol_counts=dict(protocol_counts.most_common()),
        top_talkers=[{"host": host, "bytes": count} for host, count in talkers.most_common(top)],
        top_flows=[_flow_row(flow, count) for flow, count in flows.most_common(top)],
        top_ports=[
            {"direction": direction, "port": port, "packets": count}
            for (direction, port), count in ports.most_common(top)
        ],
        dns_names=[{"name": name, "count": count} for name, count in dns_names.most_common(top)],
        http_hosts=[{"host": host, "count": count} for host, count in http_hosts.most_common(top)],
        tls_names=[{"name": name, "count": count} for name, count in tls_names.most_common(top)],
        observations=observations,
    )


def analyze_pcap(path: str | Path, top: int = 10, max_packets: int | None = None) -> AnalysisResult:
    source = str(path)
    packets = decode_pcap(path, max_packets=max_packets)
    return summarize_packets(source, packets, top=top)


def _observations(packets: list[Packet]) -> list[Observation]:
    observations: list[Observation] = []
    observations.extend(_observe_http_fields(packets))
    observations.extend(_observe_tcp_fanout(packets))
    observations.extend(_observe_dns_patterns(packets))
    observations.extend(_observe_regular_intervals(packets))
    observations.extend(_observe_arp_fanout(packets))
    observations.extend(_observe_notable_ports(packets))
    observations.extend(_observe_large_public_transfers(packets))
    return _dedupe_observations(observations)


def _observe_http_fields(packets: Iterable[Packet]) -> list[Observation]:
    observations: list[Observation] = []
    for packet in packets:
        if not packet.payload or packet.protocol not in {"TCP", "UDP"}:
            continue
        ports = {packet.src_port, packet.dst_port}
        if not (ports & {21, 23, 25, 80, 110, 143, 587, 8080, 8000, 8888}):
            continue
        match = HTTP_FIELD_PATTERN.search(packet.payload[:4096])
        if not match:
            continue
        snippet = _safe_snippet(match.group(0))
        host = packet.http_host or packet.dst_ip or "unknown"
        observations.append(
            Observation(
                category="application",
                title="HTTP request field",
                detail=f"Packet {packet.index} contains a readable application field sent to {host}.",
                evidence=[f"{packet.src_ip}:{packet.src_port} -> {packet.dst_ip}:{packet.dst_port}", snippet],
            )
        )
    return observations


def _observe_tcp_fanout(packets: Iterable[Packet]) -> list[Observation]:
    attempts: dict[tuple[str, str], set[int]] = defaultdict(set)
    samples: dict[tuple[str, str], list[str]] = defaultdict(list)
    for packet in packets:
        if packet.protocol != "TCP" or not packet.src_ip or not packet.dst_ip or not packet.dst_port:
            continue
        if not packet.tcp_flags.get("syn") or packet.tcp_flags.get("ack"):
            continue
        key = (packet.src_ip, packet.dst_ip)
        attempts[key].add(packet.dst_port)
        if len(samples[key]) < 8:
            samples[key].append(str(packet.dst_port))

    observations: list[Observation] = []
    for (src, dst), ports in attempts.items():
        if len(ports) >= 10:
            observations.append(
                Observation(
                    category="tcp",
                    title="TCP SYN fan-out",
                    detail=f"{src} sent TCP SYN packets to {len(ports)} ports on {dst}.",
                    evidence=[f"sample ports: {', '.join(samples[(src, dst)])}"],
                )
            )
    return observations


def _observe_dns_patterns(packets: Iterable[Packet]) -> list[Observation]:
    observations: list[Observation] = []
    nxdomain_by_client: Counter[str] = Counter()
    seen_names: set[str] = set()

    for packet in packets:
        if packet.dns_rcode == 3 and packet.dst_ip:
            nxdomain_by_client[packet.dst_ip] += 1
        for name in packet.dns_queries:
            lower = name.lower().strip(".")
            if not lower or lower in seen_names:
                continue
            seen_names.add(lower)
            labels = lower.split(".")
            longest_label = max((len(label) for label in labels), default=0)
            entropy = _entropy(lower.replace(".", ""))
            if len(lower) >= 90 or longest_label >= 50 or entropy >= 4.2:
                observations.append(
                    Observation(
                        category="dns",
                        title="Long or high-entropy DNS name",
                        detail="DNS query has unusually long or high-entropy labels.",
                        evidence=[lower, f"length={len(lower)} longest_label={longest_label} entropy={entropy:.2f}"],
                    )
                )

    for client, count in nxdomain_by_client.items():
        if count >= 10:
            observations.append(
                Observation(
                    category="dns",
                    title="Repeated NXDOMAIN responses",
                    detail=f"{client} received {count} NXDOMAIN DNS responses.",
                    evidence=["often useful when reviewing resolver behavior or typo-heavy traffic"],
                )
            )

    return observations


def _observe_regular_intervals(packets: Iterable[Packet]) -> list[Observation]:
    times_by_flow: dict[tuple, list[float]] = defaultdict(list)
    for packet in packets:
        key = packet.flow_key()
        if key and packet.protocol in {"TCP", "UDP"}:
            times_by_flow[key].append(packet.timestamp)

    observations: list[Observation] = []
    for flow, times in times_by_flow.items():
        if len(times) < 6:
            continue
        intervals = [b - a for a, b in zip(times, times[1:]) if b > a]
        if len(intervals) < 5:
            continue
        avg = mean(intervals)
        if avg < 1 or avg > 3600:
            continue
        jitter = pstdev(intervals) if len(intervals) > 1 else 0.0
        if jitter <= max(0.25, avg * 0.12):
            observations.append(
                Observation(
                    category="timing",
                    title="Regular interval flow",
                    detail=f"Flow {_format_flow(flow)} appears at a regular {avg:.2f}s interval.",
                    evidence=[f"packets={len(times)} jitter={jitter:.2f}s"],
                )
            )
    return observations


def _observe_arp_fanout(packets: Iterable[Packet]) -> list[Observation]:
    targets: dict[str, set[str]] = defaultdict(set)
    for packet in packets:
        if packet.protocol == "ARP" and packet.arp_op == "request" and packet.src_ip and packet.dst_ip:
            targets[packet.src_ip].add(packet.dst_ip)

    observations: list[Observation] = []
    for src, target_ips in targets.items():
        if len(target_ips) >= 20:
            observations.append(
                Observation(
                    category="arp",
                    title="ARP fan-out",
                    detail=f"{src} sent ARP requests for {len(target_ips)} different IP addresses.",
                    evidence=["common during local discovery, inventory, or device wake-up activity"],
                )
            )
    return observations


def _observe_notable_ports(packets: Iterable[Packet]) -> list[Observation]:
    seen: set[tuple[str | None, str | None, int]] = set()
    observations: list[Observation] = []
    for packet in packets:
        if not packet.dst_port or packet.dst_port not in NOTABLE_PORTS:
            continue
        key = (packet.src_ip, packet.dst_ip, packet.dst_port)
        if key in seen:
            continue
        seen.add(key)
        observations.append(
            Observation(
                category="port",
                title="Connection to notable port",
                detail=f"{packet.src_ip} contacted {packet.dst_ip}:{packet.dst_port} ({NOTABLE_PORTS[packet.dst_port]}).",
                evidence=[f"packet={packet.index} protocol={packet.protocol}"],
            )
        )
    return observations


def _observe_large_public_transfers(packets: Iterable[Packet]) -> list[Observation]:
    totals: Counter[tuple[str, str]] = Counter()
    for packet in packets:
        if not packet.src_ip or not packet.dst_ip:
            continue
        if _is_private(packet.src_ip) and not _is_private(packet.dst_ip):
            totals[(packet.src_ip, packet.dst_ip)] += packet.original_length

    observations: list[Observation] = []
    for (src, dst), byte_count in totals.items():
        if byte_count >= 5 * 1024 * 1024:
            observations.append(
                Observation(
                    category="volume",
                    title="Large transfer to public address",
                    detail=f"{src} sent about {_human_bytes(byte_count)} to public host {dst}.",
                    evidence=["useful for traffic accounting and conversation review"],
                )
            )
    return observations


def _dedupe_observations(observations: list[Observation]) -> list[Observation]:
    out: list[Observation] = []
    seen: set[tuple[str, str, str]] = set()
    for observation in observations:
        key = (observation.category, observation.title, observation.detail)
        if key not in seen:
            seen.add(key)
            out.append(observation)
    return out


def _flow_row(flow: tuple, byte_count: int) -> dict[str, object]:
    proto, src_ip, src_port, dst_ip, dst_port = flow
    return {
        "protocol": proto,
        "src": src_ip,
        "src_port": src_port,
        "dst": dst_ip,
        "dst_port": dst_port,
        "bytes": byte_count,
    }


def _format_flow(flow: tuple) -> str:
    proto, src_ip, src_port, dst_ip, dst_port = flow
    return f"{proto} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _safe_snippet(data: bytes) -> str:
    text = data[:140].decode("iso-8859-1", errors="replace")
    text = re.sub(r"\s+", " ", text).strip()
    return text.replace("\x00", "")


@lru_cache(maxsize=4096)
def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def _human_bytes(value: int) -> str:
    num = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num < 1024 or unit == "TB":
            return f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} TB"
