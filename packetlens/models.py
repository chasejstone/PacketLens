from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class RawPacket:
    index: int
    timestamp: float
    captured_length: int
    original_length: int
    data: bytes


@dataclass
class Packet:
    index: int
    timestamp: float
    captured_length: int
    original_length: int
    link_type: int
    layers: list[str] = field(default_factory=list)
    src_mac: str | None = None
    dst_mac: str | None = None
    eth_type: int | None = None
    ip_version: int | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    protocol: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: dict[str, bool] = field(default_factory=dict)
    arp_op: str | None = None
    dns_queries: list[str] = field(default_factory=list)
    dns_rcode: int | None = None
    http_method: str | None = None
    http_host: str | None = None
    http_path: str | None = None
    http_status: int | None = None
    tls_sni: str | None = None
    payload: bytes = b""
    notes: list[str] = field(default_factory=list)

    def flow_key(self) -> tuple[Any, ...] | None:
        if not self.src_ip or not self.dst_ip or not self.protocol:
            return None
        return (self.protocol, self.src_ip, self.src_port, self.dst_ip, self.dst_port)

    def endpoint_pair(self) -> tuple[str, str] | None:
        if not self.src_ip or not self.dst_ip:
            return None
        return tuple(sorted((self.src_ip, self.dst_ip)))


@dataclass
class Observation:
    category: str
    title: str
    detail: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    source: str
    packets: int
    captured_bytes: int
    duration: float
    started_at: float | None
    ended_at: float | None
    protocol_counts: dict[str, int]
    top_talkers: list[dict[str, Any]]
    top_flows: list[dict[str, Any]]
    top_ports: list[dict[str, Any]]
    dns_names: list[dict[str, Any]]
    http_hosts: list[dict[str, Any]]
    tls_names: list[dict[str, Any]]
    observations: list[Observation]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "packets": self.packets,
            "captured_bytes": self.captured_bytes,
            "duration": self.duration,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "protocol_counts": self.protocol_counts,
            "top_talkers": self.top_talkers,
            "top_flows": self.top_flows,
            "top_ports": self.top_ports,
            "dns_names": self.dns_names,
            "http_hosts": self.http_hosts,
            "tls_names": self.tls_names,
            "observations": [
                {
                    "category": observation.category,
                    "title": observation.title,
                    "detail": observation.detail,
                    "evidence": observation.evidence,
                }
                for observation in self.observations
            ],
        }
