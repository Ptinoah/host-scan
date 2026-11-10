"""Génère samples/demo.pcap : quelques minutes de trafic domestique fictif.

Aucune donnée réelle : les adresses MAC sont des adresses « locales » (02:…),
les appareils et le trafic sont inventés. Le fichier sert au mode --demo et
aux tests.

    python tools/make_demo_pcap.py
"""

import random
import sys
from pathlib import Path

from scapy.all import (ARP, DNS, DNSQR, DNSRR, ICMP, IP, NTP, TCP, UDP, Ether, Raw,
                       wrpcap)

OUT = Path(__file__).resolve().parent.parent / "samples" / "demo.pcap"
START = 1_767_225_600.0          # 1er janvier 2026, 00:00 UTC
DURATION = 180                   # secondes de trafic

BOX = ("192.168.1.1", "02:00:5e:00:00:01")
PC = ("192.168.1.10", "02:00:5e:00:00:10")
PHONE = ("192.168.1.23", "02:00:5e:00:00:23")
TV = ("192.168.1.30", "02:00:5e:00:00:30")
PRINTER = ("192.168.1.40", "02:00:5e:00:00:40")

SITES = {
    "www.wikipedia.org": "185.15.59.224",
    "github.com": "140.82.121.3",
    "www.youtube.com": "142.250.179.110",
    "api.spotify.com": "35.186.224.25",
    "catalog.gamepass.com": "81.242.3.34",
    "example.com": "93.184.215.14",
}

rng = random.Random(42)
packets = []


def emit(t, pkt):
    pkt.time = START + t
    packets.append(pkt)


def l2(src, dst):
    return Ether(src=src[1], dst=dst[1] if dst else BOX[1])


def dns_lookup(t, client, name, ip):
    sport = rng.randint(49152, 65000)
    qid = rng.randint(0, 65535)
    emit(t, l2(client, BOX) / IP(src=client[0], dst=BOX[0]) / UDP(sport=sport, dport=53)
         / DNS(id=qid, rd=1, qd=DNSQR(qname=name)))
    emit(t + 0.012, Ether(src=BOX[1], dst=client[1]) / IP(src=BOX[0], dst=client[0])
         / UDP(sport=53, dport=sport)
         / DNS(id=qid, qr=1, rd=1, ra=1, qd=DNSQR(qname=name),
               an=[DNSRR(rrname=name, rdata=ip, ttl=300)]))


def client_hello(server_name):
    name = server_name.encode()
    sni = b"\x00" + len(name).to_bytes(2, "big") + name
    sni = len(sni).to_bytes(2, "big") + sni
    ext = b"\x00\x00" + len(sni).to_bytes(2, "big") + sni
    body = (b"\x03\x03" + bytes(rng.getrandbits(8) for _ in range(32)) + b"\x00"
            + b"\x00\x04\x13\x01\x13\x02" + b"\x01\x00" + len(ext).to_bytes(2, "big") + ext)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def tcp_session(t, client, server_ip, dport, exchanges, mss=1400, rst=False):
    """Poignée de main, échanges [(sens, octets)], puis fermeture."""
    sport = rng.randint(49152, 65000)
    cseq, sseq = rng.getrandbits(31), rng.getrandbits(31)
    up = l2(client, BOX) / IP(src=client[0], dst=server_ip)
    down = Ether(src=BOX[1], dst=client[1]) / IP(src=server_ip, dst=client[0])
    rtt = rng.uniform(0.010, 0.030)
    emit(t, up / TCP(sport=sport, dport=dport, flags="S", seq=cseq))
    emit(t + rtt, down / TCP(sport=dport, dport=sport, flags="SA", seq=sseq, ack=cseq + 1))
    cseq, sseq = cseq + 1, sseq + 1
    t += rtt * 1.1
    emit(t, up / TCP(sport=sport, dport=dport, flags="A", seq=cseq, ack=sseq))
    for direction, data in exchanges:
        t += rtt
        for i in range(0, len(data), mss):
            chunk = data[i:i + mss]
            if direction == "out":
                emit(t, up / TCP(sport=sport, dport=dport, flags="PA", seq=cseq, ack=sseq) / Raw(chunk))
                cseq += len(chunk)
            else:
                emit(t, down / TCP(sport=dport, dport=sport, flags="PA", seq=sseq, ack=cseq) / Raw(chunk))
                sseq += len(chunk)
            t += 0.0008
        if direction == "in":
            emit(t, up / TCP(sport=sport, dport=dport, flags="A", seq=cseq, ack=sseq))
    t += rtt
    if rst:
        emit(t, up / TCP(sport=sport, dport=dport, flags="R", seq=cseq))
        return t
    emit(t, up / TCP(sport=sport, dport=dport, flags="FA", seq=cseq, ack=sseq))
    emit(t + rtt, down / TCP(sport=dport, dport=sport, flags="FA", seq=sseq, ack=cseq + 1))
    emit(t + rtt * 1.1, up / TCP(sport=sport, dport=dport, flags="A", seq=cseq + 1, ack=sseq + 1))
    return t + rtt


def https_visit(t, client, name, response_size):
    dns_lookup(t, client, name, SITES[name])
    tcp_session(t + 0.03, client, SITES[name], 443, [
        ("out", client_hello(name)),
        ("in", b"\x16\x03\x03" + rng.randbytes(response_size)),
        ("out", b"\x17\x03\x03" + rng.randbytes(rng.randint(200, 900))),
        ("in", b"\x17\x03\x03" + rng.randbytes(response_size * 3)),
    ], rst=name == "catalog.gamepass.com")


HTML = (b"<!doctype html>\n<html>\n<head><title>Example Domain</title></head>\n<body>\n"
        b"<h1>Example Domain</h1>\n<p>This domain is for use in illustrative examples in "
        b"documents.</p>\n" + b"<p>" + b"Lorem ipsum dolor sit amet. " * 120 + b"</p>\n"
        b"</body>\n</html>\n")


def http_visit(t, client):
    dns_lookup(t, client, "example.com", SITES["example.com"])
    request = (b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; "
               b"Win64; x64) Firefox/140.0\r\nAccept: text/html\r\nConnection: close\r\n\r\n")
    response = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\n"
                b"Content-Length: " + str(len(HTML)).encode() + b"\r\n\r\n" + HTML)
    tcp_session(t + 0.03, client, SITES["example.com"], 80, [("out", request), ("in", response)])


def quic_burst(t, client, server_ip, seconds, rate_kbps):
    """Vidéo en streaming : beaucoup de paquets UDP/443 entrants."""
    sport = rng.randint(49152, 65000)
    per_second = max(1, rate_kbps * 1000 // 8 // 1200)
    for s in range(seconds):
        for _ in range(per_second):
            dt = s + rng.random()
            emit(t + dt, Ether(src=BOX[1], dst=client[1]) / IP(src=server_ip, dst=client[0])
                 / UDP(sport=443, dport=sport) / Raw(b"\x40" + rng.randbytes(1199)))
        emit(t + s + 0.5, l2(client, BOX) / IP(src=client[0], dst=server_ip)
             / UDP(sport=sport, dport=443) / Raw(b"\x40" + rng.randbytes(60)))


def background(t):
    for device in (PHONE, TV, PRINTER):
        if rng.random() < 0.15:
            emit(t + rng.random(), Ether(src=device[1], dst="ff:ff:ff:ff:ff:ff")
                 / ARP(op=1, hwsrc=device[1], psrc=device[0], pdst=BOX[0]))
    if int(t) % 20 == 0:
        emit(t + 0.2, Ether(src=TV[1], dst="01:00:5e:7f:ff:fa") / IP(src=TV[0], dst="239.255.255.250")
             / UDP(sport=1900, dport=1900)
             / Raw(b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: upnp:rootdevice\r\n\r\n"))
    if int(t) % 15 == 0:
        emit(t + 0.4, Ether(src=PHONE[1], dst="01:00:5e:00:00:fb") / IP(src=PHONE[0], dst="224.0.0.251")
             / UDP(sport=5353, dport=5353) / DNS(qd=DNSQR(qname="_googlecast._tcp.local", qtype="PTR")))
    if int(t) % 30 == 0:
        emit(t + 0.6, Ether(src=PRINTER[1], dst="ff:ff:ff:ff:ff:ff") / IP(src=PRINTER[0], dst="192.168.1.255")
             / UDP(sport=137, dport=137) / Raw(rng.randbytes(50)))


def main():
    for second in range(DURATION):
        background(second)
    emit(1.0, l2(PC, BOX) / IP(src=PC[0], dst="162.159.200.1") / UDP(sport=123, dport=123) / NTP())
    emit(1.0, l2(PC, BOX) / IP(src=PC[0], dst=BOX[0]) / ICMP())
    emit(1.004, Ether(src=BOX[1], dst=PC[1]) / IP(src=BOX[0], dst=PC[0]) / ICMP(type=0))
    http_visit(3.0, PC)
    for t, client, site, size in [(6, PC, "www.wikipedia.org", 4000), (14, PHONE, "api.spotify.com", 2500),
                                  (25, PC, "github.com", 9000), (40, PC, "catalog.gamepass.com", 1500),
                                  (70, PHONE, "www.wikipedia.org", 3000), (95, PC, "github.com", 12000),
                                  (130, PHONE, "api.spotify.com", 2000), (150, PC, "www.wikipedia.org", 6000)]:
        https_visit(t, client, site, size)
    dns_lookup(55, TV, "www.youtube.com", SITES["www.youtube.com"])
    quic_burst(56, TV, SITES["www.youtube.com"], 45, 450)
    quic_burst(120, PHONE, SITES["www.youtube.com"], 20, 250)
    tcp_session(100, PC, PRINTER[0], 9100, [("out", b"\x1b%-12345X@PJL JOB\r\n" + rng.randbytes(30000))])

    packets.sort(key=lambda p: p.time)
    OUT.parent.mkdir(exist_ok=True)
    wrpcap(str(OUT), packets)
    print(f"{len(packets)} paquets écrits dans {OUT}", file=sys.stderr)


if __name__ == "__main__":
    main()
