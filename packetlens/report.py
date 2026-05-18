from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import AnalysisResult


def write_json(result: AnalysisResult, path: str | Path) -> None:
    Path(path).write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")


def write_markdown(result: AnalysisResult, path: str | Path) -> None:
    Path(path).write_text(markdown_report(result), encoding="utf-8")


def console_report(result: AnalysisResult) -> str:
    protocols = ", ".join(f"{k}={v}" for k, v in result.protocol_counts.items()) or "none"
    lines = [
        "PacketLens report",
        f"Source: {result.source}",
        f"Packets: {result.packets}",
        f"Captured bytes: {_human_bytes(result.captured_bytes)}",
        f"Duration: {result.duration:.3f}s",
        f"Protocols: {protocols}",
        f"Observations: {len(result.observations)}",
    ]
    if result.observations:
        lines.append("")
        for observation in result.observations:
            lines.append(f"[{observation.category}] {observation.title}")
            lines.append(f"  {observation.detail}")
    return "\n".join(lines)


def markdown_report(result: AnalysisResult) -> str:
    lines = [
        "# PacketLens Report",
        "",
        "## Summary",
        "",
        f"- Source: `{result.source}`",
        f"- Packets: {result.packets}",
        f"- Captured bytes: {_human_bytes(result.captured_bytes)}",
        f"- Duration: {result.duration:.3f}s",
        f"- Observations: {len(result.observations)}",
        "",
        "## Protocols",
        "",
    ]
    lines.extend(_table(["Protocol", "Packets"], [{"Protocol": k, "Packets": v} for k, v in result.protocol_counts.items()]))
    lines.extend(["", "## Observations", ""])
    if result.observations:
        for observation in result.observations:
            lines.extend(
                [
                    f"### [{observation.category}] {observation.title}",
                    "",
                    observation.detail,
                    "",
                ]
            )
            if observation.evidence:
                lines.append("Evidence:")
                for item in observation.evidence:
                    lines.append(f"- {item}")
                lines.append("")
    else:
        lines.append("No notable traffic observations were detected.")
        lines.append("")

    sections = [
        ("Top Talkers", ["Host", "Bytes"], [{"Host": r["host"], "Bytes": _human_bytes(r["bytes"])} for r in result.top_talkers]),
        (
            "Top Flows",
            ["Protocol", "Source", "Destination", "Bytes"],
            [
                {
                    "Protocol": r["protocol"],
                    "Source": f"{r['src']}:{r['src_port']}",
                    "Destination": f"{r['dst']}:{r['dst_port']}",
                    "Bytes": _human_bytes(r["bytes"]),
                }
                for r in result.top_flows
            ],
        ),
        ("Top Ports", ["Direction", "Port", "Packets"], [{"Direction": r["direction"], "Port": r["port"], "Packets": r["packets"]} for r in result.top_ports]),
        ("DNS Names", ["Name", "Count"], [{"Name": r["name"], "Count": r["count"]} for r in result.dns_names]),
        ("HTTP Hosts", ["Host", "Count"], [{"Host": r["host"], "Count": r["count"]} for r in result.http_hosts]),
        ("TLS Names", ["Name", "Count"], [{"Name": r["name"], "Count": r["count"]} for r in result.tls_names]),
    ]

    for title, headers, rows in sections:
        lines.extend(["", f"## {title}", ""])
        lines.extend(_table(headers, rows))

    return "\n".join(lines).rstrip() + "\n"


def _table(headers: list[str], rows: list[dict[str, Any]]) -> list[str]:
    if not rows:
        return ["No data."]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(_cell(row.get(header, "")) for header in headers) + " |")
    return lines


def _cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _human_bytes(value: int | float) -> str:
    num = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num < 1024 or unit == "TB":
            return f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} TB"
