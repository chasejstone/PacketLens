from __future__ import annotations

import json
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

from .analyzer import decode_pcap, summarize_packets
from .models import AnalysisResult, Packet
from .report import markdown_report


class PacketLensApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("PacketLens")
        self.geometry("1180x760")
        self.minsize(980, 620)

        self.result: AnalysisResult | None = None
        self.packets: list[Packet] = []
        self.current_path: Path | None = None
        self.max_packets = tk.StringVar(value="")
        self.status = tk.StringVar(value="Open a PCAP file to begin.")

        self._configure_style()
        self._build_ui()

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Treeview", rowheight=24)
        style.configure("Header.TLabel", font=("Segoe UI", 12, "bold"))
        style.configure("Metric.TLabel", font=("Segoe UI", 10, "bold"))

    def _build_ui(self) -> None:
        toolbar = ttk.Frame(self, padding=(10, 8))
        toolbar.pack(side=tk.TOP, fill=tk.X)

        ttk.Button(toolbar, text="Open", command=self.open_capture).pack(side=tk.LEFT)
        ttk.Label(toolbar, text="Max packets").pack(side=tk.LEFT, padx=(12, 4))
        max_entry = ttk.Entry(toolbar, textvariable=self.max_packets, width=10)
        max_entry.pack(side=tk.LEFT)
        ttk.Button(toolbar, text="Reload", command=self.reload_capture).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=12)
        ttk.Button(toolbar, text="Export JSON", command=self.export_json).pack(side=tk.LEFT)
        ttk.Button(toolbar, text="Export Markdown", command=self.export_markdown).pack(side=tk.LEFT, padx=(8, 0))

        self.summary_frame = ttk.Frame(self, padding=(10, 2, 10, 8))
        self.summary_frame.pack(side=tk.TOP, fill=tk.X)
        self.metric_vars = {
            "file": tk.StringVar(value="File: -"),
            "packets": tk.StringVar(value="Packets: -"),
            "bytes": tk.StringVar(value="Bytes: -"),
            "duration": tk.StringVar(value="Duration: -"),
            "protocols": tk.StringVar(value="Protocols: -"),
            "observations": tk.StringVar(value="Observations: -"),
        }
        for key in ("file", "packets", "bytes", "duration", "protocols", "observations"):
            ttk.Label(self.summary_frame, textvariable=self.metric_vars[key], style="Metric.TLabel").pack(
                side=tk.LEFT, padx=(0, 18)
            )

        main = ttk.PanedWindow(self, orient=tk.VERTICAL)
        main.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 8))

        packet_frame = ttk.Frame(main)
        main.add(packet_frame, weight=3)
        self.packet_tree = self._make_tree(
            packet_frame,
            columns=("no", "time", "protocol", "source", "destination", "info", "length"),
            headings={
                "no": "#",
                "time": "Time",
                "protocol": "Protocol",
                "source": "Source",
                "destination": "Destination",
                "info": "Info",
                "length": "Length",
            },
            widths={
                "no": 64,
                "time": 112,
                "protocol": 90,
                "source": 180,
                "destination": 180,
                "info": 420,
                "length": 82,
            },
        )
        self.packet_tree.bind("<<TreeviewSelect>>", self._on_packet_selected)

        lower = ttk.PanedWindow(main, orient=tk.HORIZONTAL)
        main.add(lower, weight=2)

        details_frame = ttk.Frame(lower)
        lower.add(details_frame, weight=2)
        ttk.Label(details_frame, text="Packet Details", style="Header.TLabel").pack(anchor=tk.W, pady=(0, 4))
        self.detail_text = tk.Text(details_frame, wrap=tk.WORD, height=12, undo=False)
        detail_scroll = ttk.Scrollbar(details_frame, orient=tk.VERTICAL, command=self.detail_text.yview)
        self.detail_text.configure(yscrollcommand=detail_scroll.set)
        self.detail_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        detail_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        notebook = ttk.Notebook(lower)
        lower.add(notebook, weight=3)
        self.tables: dict[str, ttk.Treeview] = {}
        self._add_table_tab(notebook, "Protocols", "protocols", ("protocol", "packets"))
        self._add_table_tab(notebook, "Talkers", "talkers", ("host", "bytes"))
        self._add_table_tab(notebook, "Flows", "flows", ("protocol", "source", "destination", "bytes"))
        self._add_table_tab(notebook, "Ports", "ports", ("direction", "port", "packets"))
        self._add_table_tab(notebook, "DNS", "dns", ("name", "count"))
        self._add_table_tab(notebook, "HTTP", "http", ("host", "count"))
        self._add_table_tab(notebook, "TLS", "tls", ("name", "count"))
        self._add_table_tab(notebook, "Observations", "observations", ("category", "title", "detail"))

        status_bar = ttk.Frame(self, padding=(10, 4))
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        ttk.Label(status_bar, textvariable=self.status).pack(side=tk.LEFT)

    def _add_table_tab(self, notebook: ttk.Notebook, title: str, key: str, columns: tuple[str, ...]) -> None:
        frame = ttk.Frame(notebook, padding=6)
        notebook.add(frame, text=title)
        headings = {column: column.replace("_", " ").title() for column in columns}
        widths = {column: 150 for column in columns}
        if "detail" in columns:
            widths["detail"] = 480
        if "title" in columns:
            widths["title"] = 220
        if "source" in columns or "destination" in columns:
            widths.update({"source": 210, "destination": 210})
        self.tables[key] = self._make_tree(frame, columns, headings, widths)

    def _make_tree(
        self,
        parent: ttk.Frame,
        columns: tuple[str, ...],
        headings: dict[str, str],
        widths: dict[str, int],
    ) -> ttk.Treeview:
        tree = ttk.Treeview(parent, columns=columns, show="headings", selectmode="browse")
        y_scroll = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=tree.yview)
        x_scroll = ttk.Scrollbar(parent, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        for column in columns:
            tree.heading(column, text=headings[column])
            tree.column(column, width=widths.get(column, 120), minwidth=60, stretch=True)
        tree.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)
        return tree

    def open_capture(self) -> None:
        path = filedialog.askopenfilename(
            title="Open PCAP",
            filetypes=(("PCAP files", "*.pcap"), ("All files", "*.*")),
        )
        if path:
            self.current_path = Path(path)
            self._load_capture(self.current_path)

    def reload_capture(self) -> None:
        if not self.current_path:
            self.open_capture()
            return
        self._load_capture(self.current_path)

    def export_json(self) -> None:
        if not self.result:
            messagebox.showinfo("PacketLens", "Open a PCAP file first.")
            return
        path = filedialog.asksaveasfilename(
            title="Export JSON",
            defaultextension=".json",
            filetypes=(("JSON files", "*.json"), ("All files", "*.*")),
        )
        if path:
            Path(path).write_text(json.dumps(self.result.to_dict(), indent=2), encoding="utf-8")
            self.status.set(f"JSON report written to {path}")

    def export_markdown(self) -> None:
        if not self.result:
            messagebox.showinfo("PacketLens", "Open a PCAP file first.")
            return
        path = filedialog.asksaveasfilename(
            title="Export Markdown",
            defaultextension=".md",
            filetypes=(("Markdown files", "*.md"), ("All files", "*.*")),
        )
        if path:
            Path(path).write_text(markdown_report(self.result), encoding="utf-8")
            self.status.set(f"Markdown report written to {path}")

    def _load_capture(self, path: Path) -> None:
        max_packets = self._parse_max_packets()
        self.status.set(f"Loading {path.name}...")
        self._set_busy(True)

        def worker() -> None:
            try:
                packets = decode_pcap(path, max_packets=max_packets)
                result = summarize_packets(str(path), packets)
            except Exception as exc:  # noqa: BLE001
                self.after(0, lambda: self._load_failed(exc))
                return
            self.after(0, lambda: self._load_finished(path, packets, result))

        threading.Thread(target=worker, daemon=True).start()

    def _load_finished(self, path: Path, packets: list[Packet], result: AnalysisResult) -> None:
        self.packets = packets
        self.result = result
        self.current_path = path
        self._populate_summary(result, path)
        self._populate_packets(packets, result.started_at)
        self._populate_tables(result)
        self._set_detail_text("Select a packet to inspect its decoded layers.")
        self.status.set(f"Loaded {path.name}")
        self._set_busy(False)

    def _load_failed(self, exc: Exception) -> None:
        self._set_busy(False)
        self.status.set("Load failed.")
        messagebox.showerror("PacketLens", str(exc))

    def _set_busy(self, busy: bool) -> None:
        self.configure(cursor="watch" if busy else "")
        self.update_idletasks()

    def _parse_max_packets(self) -> int | None:
        raw = self.max_packets.get().strip()
        if not raw:
            return None
        try:
            value = int(raw)
        except ValueError:
            messagebox.showwarning("PacketLens", "Max packets must be a whole number.")
            self.max_packets.set("")
            return None
        return value if value > 0 else None

    def _populate_summary(self, result: AnalysisResult, path: Path) -> None:
        protocols = ", ".join(f"{name}={count}" for name, count in result.protocol_counts.items()) or "-"
        self.metric_vars["file"].set(f"File: {path.name}")
        self.metric_vars["packets"].set(f"Packets: {result.packets}")
        self.metric_vars["bytes"].set(f"Bytes: {_human_bytes(result.captured_bytes)}")
        self.metric_vars["duration"].set(f"Duration: {result.duration:.3f}s")
        self.metric_vars["protocols"].set(f"Protocols: {protocols}")
        self.metric_vars["observations"].set(f"Observations: {len(result.observations)}")

    def _populate_packets(self, packets: list[Packet], started_at: float | None) -> None:
        self.packet_tree.delete(*self.packet_tree.get_children())
        base = started_at or (packets[0].timestamp if packets else 0.0)
        for packet in packets:
            self.packet_tree.insert(
                "",
                tk.END,
                iid=str(packet.index),
                values=(
                    packet.index,
                    f"{packet.timestamp - base:.6f}",
                    packet.protocol or (packet.layers[-1] if packet.layers else "-"),
                    _endpoint(packet.src_ip, packet.src_port) or packet.src_mac or "-",
                    _endpoint(packet.dst_ip, packet.dst_port) or packet.dst_mac or "-",
                    _packet_info(packet),
                    packet.original_length,
                ),
            )

    def _populate_tables(self, result: AnalysisResult) -> None:
        self._replace_rows(
            "protocols",
            [{"protocol": key, "packets": value} for key, value in result.protocol_counts.items()],
            ("protocol", "packets"),
        )
        self._replace_rows(
            "talkers",
            [{"host": row["host"], "bytes": _human_bytes(row["bytes"])} for row in result.top_talkers],
            ("host", "bytes"),
        )
        self._replace_rows(
            "flows",
            [
                {
                    "protocol": row["protocol"],
                    "source": _endpoint(row["src"], row["src_port"]),
                    "destination": _endpoint(row["dst"], row["dst_port"]),
                    "bytes": _human_bytes(row["bytes"]),
                }
                for row in result.top_flows
            ],
            ("protocol", "source", "destination", "bytes"),
        )
        self._replace_rows("ports", result.top_ports, ("direction", "port", "packets"))
        self._replace_rows("dns", result.dns_names, ("name", "count"))
        self._replace_rows("http", result.http_hosts, ("host", "count"))
        self._replace_rows("tls", result.tls_names, ("name", "count"))
        self._replace_rows(
            "observations",
            [
                {"category": item.category, "title": item.title, "detail": item.detail}
                for item in result.observations
            ],
            ("category", "title", "detail"),
        )

    def _replace_rows(self, key: str, rows: list[dict[str, Any]], columns: tuple[str, ...]) -> None:
        tree = self.tables[key]
        tree.delete(*tree.get_children())
        for row in rows:
            tree.insert("", tk.END, values=tuple(row.get(column, "") for column in columns))

    def _on_packet_selected(self, _event: tk.Event) -> None:
        selected = self.packet_tree.selection()
        if not selected:
            return
        index = int(selected[0])
        packet = next((item for item in self.packets if item.index == index), None)
        if packet:
            self._set_detail_text(_packet_details(packet))

    def _set_detail_text(self, text: str) -> None:
        self.detail_text.configure(state=tk.NORMAL)
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, text)
        self.detail_text.configure(state=tk.DISABLED)


def main() -> int:
    app = PacketLensApp()
    app.mainloop()
    return 0


def _packet_info(packet: Packet) -> str:
    if packet.dns_queries:
        return "DNS " + ", ".join(packet.dns_queries[:3])
    if packet.http_method:
        return f"HTTP {packet.http_method} {packet.http_path or ''} Host={packet.http_host or '-'}".strip()
    if packet.http_status:
        return f"HTTP {packet.http_status}"
    if packet.tls_sni:
        return f"TLS SNI {packet.tls_sni}"
    if packet.protocol == "TCP" and packet.tcp_flags:
        flags = [name.upper() for name, enabled in packet.tcp_flags.items() if enabled]
        return "TCP " + ",".join(flags)
    if packet.protocol == "ARP":
        return f"ARP {packet.arp_op or ''}".strip()
    return " / ".join(packet.layers) if packet.layers else "-"


def _packet_details(packet: Packet) -> str:
    lines = [
        f"Packet {packet.index}",
        f"Timestamp: {packet.timestamp:.6f}",
        f"Captured length: {packet.captured_length}",
        f"Original length: {packet.original_length}",
        "",
        "Layers",
        f"  {' -> '.join(packet.layers) if packet.layers else '-'}",
        "",
        "Link",
        f"  Source MAC: {packet.src_mac or '-'}",
        f"  Destination MAC: {packet.dst_mac or '-'}",
        f"  EtherType: {f'0x{packet.eth_type:04x}' if packet.eth_type is not None else '-'}",
        "",
        "Network",
        f"  IP version: {packet.ip_version or '-'}",
        f"  Source IP: {packet.src_ip or '-'}",
        f"  Destination IP: {packet.dst_ip or '-'}",
        f"  Protocol: {packet.protocol or '-'}",
        "",
        "Transport",
        f"  Source port: {packet.src_port or '-'}",
        f"  Destination port: {packet.dst_port or '-'}",
    ]
    if packet.tcp_flags:
        flags = ", ".join(name.upper() for name, enabled in packet.tcp_flags.items() if enabled) or "-"
        lines.append(f"  TCP flags: {flags}")
    if packet.arp_op:
        lines.append(f"  ARP operation: {packet.arp_op}")

    app_lines = []
    if packet.dns_queries:
        app_lines.append(f"  DNS queries: {', '.join(packet.dns_queries)}")
    if packet.dns_rcode is not None:
        app_lines.append(f"  DNS rcode: {packet.dns_rcode}")
    if packet.http_method:
        app_lines.append(f"  HTTP request: {packet.http_method} {packet.http_path or ''}")
    if packet.http_host:
        app_lines.append(f"  HTTP host: {packet.http_host}")
    if packet.http_status:
        app_lines.append(f"  HTTP status: {packet.http_status}")
    if packet.tls_sni:
        app_lines.append(f"  TLS SNI: {packet.tls_sni}")
    lines.extend(["", "Application"])
    lines.extend(app_lines or ["  -"])

    if packet.notes:
        lines.extend(["", "Notes"])
        lines.extend(f"  {note}" for note in packet.notes)

    lines.extend(["", "Payload Preview", _payload_preview(packet.payload)])
    return "\n".join(lines)


def _payload_preview(payload: bytes, limit: int = 256) -> str:
    if not payload:
        return "  -"
    chunks = []
    data = payload[:limit]
    for offset in range(0, len(data), 16):
        row = data[offset : offset + 16]
        hex_part = " ".join(f"{byte:02x}" for byte in row)
        ascii_part = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in row)
        chunks.append(f"  {offset:04x}  {hex_part:<47}  {ascii_part}")
    if len(payload) > limit:
        chunks.append(f"  ... {len(payload) - limit} more bytes")
    return "\n".join(chunks)


def _endpoint(host: Any, port: Any = None) -> str:
    if not host:
        return ""
    return f"{host}:{port}" if port else str(host)


def _human_bytes(value: int | float) -> str:
    num = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num < 1024 or unit == "TB":
            return f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} TB"


if __name__ == "__main__":
    raise SystemExit(main())
