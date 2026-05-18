# PacketLens

PacketLens is a dependency-free PCAP analyzer for protocol inspection. It reads classic `.pcap` captures, decodes common protocols, and summarizes traffic in a Wireshark-style workflow.

## Features

- Classic PCAP reader with microsecond and nanosecond timestamp support
- Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, and ARP decoding
- DNS query/response parsing, including compressed names
- HTTP method, host, path, and response status detection
- TLS ClientHello SNI extraction
- Top talkers, flows, ports, DNS names, HTTP hosts, and TLS names
- Desktop GUI with packet table, decoded detail pane, summary tabs, and report export
- Neutral traffic observations:
  - TCP SYN fan-out
  - HTTP request fields
  - Long or high-entropy DNS names
  - Repeated NXDOMAIN responses
  - Regular interval flows
  - ARP fan-out
  - Connections to notable ports
  - Large transfers to public IPs
- Console, JSON, and Markdown reports

## Quick Start

```bash
cd packetlens
python -m packetlens analyze capture.pcap
```

Write reports:

```bash
python -m packetlens analyze capture.pcap --json report.json --markdown report.md
```

Launch the desktop GUI:

```bash
python -m packetlens.gui
```

Limit output tables:

```bash
python -m packetlens analyze capture.pcap --top 20
```

## Example Output

```text
PacketLens report
Packets: 12491
Duration: 83.412s
Protocols: TCP=9130, UDP=3122, ICMP=18, ARP=221
Observations: 3

[application] HTTP request field
[tcp] TCP SYN fan-out
[dns] Long or high-entropy DNS name
```

## Install Locally

```bash
cd packetlens
python -m pip install -e .
packetlens analyze capture.pcap
packetlens-gui
```

## Testing

```bash
cd packetlens
python -m unittest discover -s tests
```

## Notes

PacketLens does passive analysis only. It does not capture live traffic, transmit packets, decrypt TLS, or bypass authentication. Use it on captures you are allowed to inspect.
