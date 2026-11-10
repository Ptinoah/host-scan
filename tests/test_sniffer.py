from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw

from sniffer import ConnectionTracker, _reassemble_tcp, ip_scope, parse_ports

E = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
ME, SRV = "192.168.1.10", "93.184.215.14"


def feed(tracker, packets, start=1000.0):
    for i, pkt in enumerate(packets):
        pkt = Ether(bytes(pkt))
        pkt.time = start + i * 0.01
        tracker._process(pkt)


# --- capture de démonstration -------------------------------------------------

def test_demo_capture_is_parsed(demo_tracker):
    stats = demo_tracker.snapshot()["stats"]
    assert stats["packets"] == len(demo_tracker.raw_packets) > 1000
    assert stats["source"] == {"type": "file", "name": "demo.pcap"}
    names = {p["name"] for p in demo_tracker.snapshot()["protocols"]}
    assert {"TLS", "HTTP", "DNS", "QUIC", "mDNS", "SSDP", "NetBIOS-NS"} <= names


def test_tls_connections_carry_sni_and_direction(demo_tracker):
    tls = [c for c in demo_tracker.snapshot(protos={"TLS"})["connections"]]
    assert tls and all(c["dport"] == 443 and c["src"].startswith("192.168.1.") for c in tls)
    assert {"github.com", "www.wikipedia.org", "api.spotify.com"} <= {c["info"] for c in tls}


def test_dns_answers_name_remote_addresses(demo_tracker):
    assert demo_tracker.dns_names["140.82.121.3"] == "github.com"


def test_filters_combine(demo_tracker):
    rows = demo_tracker.snapshot(hosts=["192.168.1.23"], layers={6})["connections"]
    assert rows and all("192.168.1.23" in (c["src"], c["dst"]) and c["layer"] == 6 for c in rows)
    rows = demo_tracker.snapshot(ports=parse_ports("9100"))["connections"]
    assert [c["proto"] for c in rows] == ["JetDirect"]


def test_passive_mac_learning(demo_tracker):
    assert demo_tracker.macs["192.168.1.40"] == "02:00:5e:00:00:40"


def test_follow_http_stream(demo_tracker):
    http = demo_tracker.snapshot(protos={"HTTP"})["connections"][0]
    stream = demo_tracker.stream(http["id"])
    assert [c["dir"] for c in stream["chunks"]] == ["out", "in"]
    assert stream["chunks"][0]["data"].startswith(b"GET / HTTP/1.1\r\nHost: example.com")
    assert stream["chunks"][1]["data"].startswith(b"HTTP/1.1 200 OK")
    assert stream["chunks"][1]["data"].endswith(b"</html>\n")


def test_timeline_series(demo_tracker):
    tl = demo_tracker.timeline(window=0)
    assert tl["bins"] and "QUIC" in tl["series"]
    by_host = demo_tracker.timeline(window=0, by="host")
    assert "192.168.1.30" in by_host["series"]            # la TV qui regarde YouTube
    only_phone = demo_tracker.timeline(window=0, hosts=["192.168.1.23"])
    assert "JetDirect" not in only_phone["series"]


def test_export_round_trip(demo_tracker, tmp_path):
    data, count = demo_tracker.export_pcap()
    assert count == demo_tracker.packet_count
    path = tmp_path / "out.pcap"
    path.write_bytes(data)
    again = ConnectionTracker()
    assert again.load_pcap(path) == count
    assert len(again.connections) == len(demo_tracker.connections)


def test_export_single_connection(demo_tracker):
    http = demo_tracker.snapshot(protos={"HTTP"})["connections"][0]
    _, count = demo_tracker.export_pcap({http["id"]})
    assert count == http["packets"]


def test_load_rejects_non_pcap_and_keeps_data(demo_tracker, tmp_path):
    import pytest
    tracker = ConnectionTracker()
    feed(tracker, [E / IP(src=ME, dst=SRV) / TCP(sport=50000, dport=80, flags="S")])
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"not a capture")
    with pytest.raises(ValueError):
        tracker.load_pcap(bad)
    assert len(tracker.connections) == 1


# --- thread de capture planté ---------------------------------------------------

class CrashedSniffer:
    """Imite un AsyncSniffer de Scapy dont le thread est mort sur une exception."""

    def __init__(self):
        import threading
        self.thread = threading.Thread(target=lambda: None)
        self.thread.start()
        self.thread.join()
        self.running = True               # Scapy le laisse à True après un plantage
        self.exception = OSError("adapter removed")
        self.stopped = False

    def stop(self):
        self.stopped = True
        raise self.exception


def test_crashed_capture_is_detected(tracker):
    tracker.sniffer = CrashedSniffer()
    assert tracker.running is False
    assert "adapter removed" in tracker.error
    assert tracker.snapshot()["stats"]["running"] is False


def test_stop_after_crash_does_not_raise(tracker):
    tracker.sniffer = CrashedSniffer()
    tracker.stop()                        # ne doit pas lever d'exception
    tracker.stop()                        # ni au deuxième clic
    assert tracker.sniffer is None and "OSError" in tracker.error


# --- paquets fabriqués ----------------------------------------------------------

def test_syn_ack_sets_direction(tracker):
    feed(tracker, [E / IP(src=SRV, dst=ME) / TCP(sport=443, dport=51000, flags="SA")])
    conn = next(iter(tracker.connections.values()))
    assert (conn["src"], conn["dport"]) == (ME, 443)


def test_tcp_states(tracker):
    feed(tracker, [
        E / IP(src=ME, dst=SRV) / TCP(sport=50000, dport=80, flags="S"),
        E / IP(src=SRV, dst=ME) / TCP(sport=80, dport=50000, flags="SA"),
        E / IP(src=ME, dst=SRV) / TCP(sport=50000, dport=80, flags="A"),
    ])
    conn = next(iter(tracker.connections.values()))
    assert conn["state"] == "ÉTABLIE" and conn["packets_out"] == 2 and conn["packets_in"] == 1
    feed(tracker, [E / IP(src=ME, dst=SRV) / TCP(sport=50000, dport=80, flags="R")], start=2000)
    assert conn["state"] == "RESET"


def test_dns_details_recorded(tracker):
    feed(tracker, [E / IP(src="192.168.1.1", dst=ME) / UDP(sport=53, dport=50000) / DNS(
        qr=1, qd=DNSQR(qname="a.example"),
        an=[DNSRR(rrname="a.example", type="CNAME", rdata="b.example"), DNSRR(rrname="b.example", rdata=SRV)])])
    detail = tracker.connection_detail(next(iter(tracker.by_id)))
    assert detail["dns"][0]["answers"] == ["b.example", SRV]
    assert tracker.dns_names[SRV] == "b.example"


def test_reassembly_reorders_and_drops_retransmissions():
    segments = [
        ("out", 1000, 1.0, b"Hello "),
        ("out", 1012, 1.2, b"!"),            # arrivé avant le segment qui le précède
        ("out", 1006, 1.3, b"world "),
        ("out", 1006, 1.4, b"world "),       # retransmission
        ("in", 5000, 1.1, b"OK"),
    ]
    pieces = _reassemble_tcp(segments)
    out = b"".join(p["data"] for p in pieces if p["dir"] == "out")
    assert out == b"Hello world !"
    assert not any("gap" in p for p in pieces)


def test_reassembly_marks_gaps():
    pieces = _reassemble_tcp([("out", 0, 1.0, b"abc"), ("out", 10, 1.1, b"xyz")])
    assert [p.get("gap") for p in pieces] == [None, 7, None]


def test_ip_scope():
    assert ip_scope("192.168.1.10") == "réseau local"
    assert ip_scope("8.8.8.8") == "Internet"
    assert ip_scope("224.0.0.251") == "multicast"
    assert ip_scope("192.168.1.255") == "broadcast"
    assert ip_scope("fe80::1") == "lien local"


def test_parse_ports():
    assert parse_ports("80, 443,8000-8100") == [(80, 80), (443, 443), (8000, 8100)]
    assert parse_ports("") == []
