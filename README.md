# Host Scan

[![tests](https://github.com/Ptinoah/host-scan/actions/workflows/tests.yml/badge.svg)](https://github.com/Ptinoah/host-scan/actions/workflows/tests.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A small, Wireshark-inspired network analyzer for a home network, with a local web UI.

It discovers the devices on the LAN, captures traffic and groups packets into
connections, recognizes protocols from OSI layer 4 to layer 7, and lets you dig
into any connection or device. The interface is in French.

*[Version française](README.fr.md)*

## Features

- **Device discovery**: ARP scan of the local subnet (IP, MAC, vendor, reverse DNS),
  plus devices seen passively in the capture (MAC learned from ARP and Ethernet frames).
- **Live capture grouped into connections**: direction (client → server), TCP state,
  packets and bytes each way, last activity.
- **Protocol recognition**: by payload (TLS ClientHello, HTTP, SSH) or by port.
  Each protocol is assigned an OSI layer: L4 transport, L5 session, L6 presentation,
  L7 application.
- **Useful metadata**: TLS SNI (the site name, even when encrypted), HTTP request
  line / Host / User-Agent, DNS questions and answers, IP → name mapping learned
  from DNS responses.
- **Filters**: devices, layers, protocols, port ranges (`53,443,8000-8100`),
  free-text search, optional BPF capture filter.
- **Connection details**: endpoints with scope (LAN / Internet / multicast), TCP flags,
  duration, throughput, last 30 packets with a hex dump of each payload.
- **Follow TCP/UDP stream**: application data reassembled in sequence order
  (out-of-order segments reordered, retransmissions removed, gaps marked), shown as
  a two-colour conversation in text or hex.
- **Live throughput chart**: stacked by protocol or by device, 1 min to whole capture,
  with a hover tooltip.
- **Device details**: protocols used, top peers, ports used / served, and an on-demand
  scan of 36 common TCP ports.
- **PCAP import / export**: open `.pcap` / `.pcapng` files from Wireshark or tcpdump;
  export the whole capture, the filtered view, or a single connection.

## Quick start

```bash
pip install -r requirements.txt
python app.py --demo
```

`--demo` loads [`samples/demo.pcap`](samples/demo.pcap), three minutes of made-up
home traffic (PC, phone, TV, printer). It needs neither Npcap nor admin rights,
so it is the easiest way to try the interface.

### Live capture

- **Windows**: install [Npcap](https://npcap.com) (bundled with Wireshark), then run
  `python app.py` from an **administrator** terminal.
- **Linux / macOS**: `sudo python app.py` (libpcap is used by Scapy).

The UI opens on http://127.0.0.1:5000. Other options: `--pcap FILE`, `--port N`,
`--no-browser`.

## How it works

```
app.py         Flask server and JSON API (hosts, connections, details, stream,
               timeline, PCAP import/export)
sniffer.py     Packet processing: connection tracking, TCP reassembly, per-second
               counters for the chart, raw packet ring buffer for export
protocols.py   Port table, OSI layers, payload heuristics (TLS SNI, HTTP)
netscan.py     ARP sweep, reverse DNS, MAC vendor lookup, TCP connect port scan
static/        Single-page UI in plain HTML/CSS/JS, no build step
tools/         Generator for the synthetic demo capture
tests/         pytest suite run by GitHub Actions
```

Packets are captured with [Scapy](https://scapy.net) and grouped by
normalized 5-tuple. A SYN or SYN-ACK decides which side is the client; otherwise
the ephemeral port is assumed to be the client's. Memory is bounded: at most
20,000 connections, 200,000 raw packets for export, 1 MiB of stream data per
connection, and 64 MiB of stream data in total.

## Limitations

- On a switched network (box, switch, Wi-Fi), a PC only receives **its own traffic**
  plus broadcast and multicast. To see another device's connections, its traffic must
  go through the capturing machine: a mirror port on a managed switch, a capture on
  the router, or the PC acting as a hotspot (Windows: *Mobile hotspot*, then pick the
  `192.168.137.1` adapter).
- Encrypted traffic (TLS, QUIC, SSH) is not decrypted: you see who talks to whom,
  when and how much, plus the SNI, but not the content.
- Protocol detection is heuristic. A service on a non-standard port may show as
  plain TCP or UDP.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

To regenerate the demo capture: `python tools/make_demo_pcap.py`.

## Responsible use

Only capture and scan networks you own or are explicitly allowed to analyze.

## License

[MIT](LICENSE)
