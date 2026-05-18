from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .analyzer import analyze_pcap
from .pcap import PcapError
from .report import console_report, write_json, write_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="packetlens",
        description="Analyze classic PCAP captures and produce protocol reports.",
    )
    subparsers = parser.add_subparsers(dest="command")

    analyze = subparsers.add_parser("analyze", help="analyze a PCAP file")
    analyze.add_argument("pcap", type=Path, help="path to a .pcap file")
    analyze.add_argument("--json", dest="json_path", type=Path, help="write a JSON report")
    analyze.add_argument("--markdown", dest="markdown_path", type=Path, help="write a Markdown report")
    analyze.add_argument("--top", type=int, default=10, help="number of rows in top-N tables")
    analyze.add_argument("--max-packets", type=int, help="stop after this many packets")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 2

    if args.command == "analyze":
        try:
            result = analyze_pcap(args.pcap, top=args.top, max_packets=args.max_packets)
        except (OSError, PcapError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

        print(console_report(result))

        if args.json_path:
            write_json(result, args.json_path)
            print(f"\nJSON report written to {args.json_path}")
        if args.markdown_path:
            write_markdown(result, args.markdown_path)
            print(f"Markdown report written to {args.markdown_path}")
        return 0

    parser.print_help()
    return 2
