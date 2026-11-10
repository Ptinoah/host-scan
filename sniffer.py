"""Capture des paquets et regroupement en connexions (flux)."""

import io
import ipaddress
import math
import struct
import threading
import time
from collections import Counter, OrderedDict, deque

from scapy.all import (ARP, DNS, DNSRR, ICMP, IP, TCP, UDP, AsyncSniffer, Ether, IPv6,
                       PcapReader, conf)

import protocols

MAX_CONNECTIONS = 20000
PACKET_LOG = 30              # derniers paquets gardés par connexion (vue détaillée)
PREVIEW_BYTES = 64           # octets de payload gardés par paquet
MAX_DNS_ENTRIES = 30
MAX_STORED_PACKETS = 200_000     # paquets bruts gardés pour l'export PCAP
MAX_STREAM_BYTES = 1 << 20       # données gardées par connexion pour « Suivre le flux »
STREAM_BUDGET = 64 << 20         # plafond de ces données, toutes connexions confondues
TIMELINE_SECONDS = 4 * 3600      # secondes gardées pour les graphiques
OTHER_SERIES = "Autres"
PCAP_MAGICS = {bytes.fromhex(m) for m in ("d4c3b2a1", "a1b2c3d4", "4d3cb2a1", "a1b23c4d",
                                          "0a0d0d0a")}   # pcap (µs, ns, 2 boutismes), pcapng


class ConnectionTracker:
    def __init__(self):
        self.lock = threading.Lock()
        self.sniffer = None
        self.iface = None
        self.error = None
        self._next_id = 1
        self._reset()

    def _reset(self):
        self.connections = OrderedDict()   # clé normalisée -> dict
        self.by_id = {}                    # id de connexion -> clé
        self.dns_names = {}                # ip -> nom résolu vu dans le DNS
        self.seen_ips = {}                 # ip -> dernier paquet vu
        self.macs = {}                     # ip locale -> adresse MAC vue passivement
        self.raw_packets = deque(maxlen=MAX_STORED_PACKETS)  # [t, linktype, octets, id connexion]
        self.buckets = OrderedDict()        # seconde -> compteurs
        self.stream_bytes = 0
        self.packet_count = 0
        self.first_packet_time = None
        self.last_packet_time = None
        self.source = {"type": "live", "name": None}
        self._scopes = {}

    # --- capture -----------------------------------------------------------
    def start(self, iface=None, bpf=None):
        if self.running:
            return
        if self.source["type"] == "file":
            self.clear()                   # on ne mélange pas un fichier et du direct
        self.iface = iface or conf.iface
        self.error = None
        self.sniffer = AsyncSniffer(iface=self.iface, filter=bpf or None,
                                    prn=self._handle, store=False)
        self.sniffer.start()
        time.sleep(0.3)
        self._check_sniffer()

    def stop(self):
        sniffer, self.sniffer = self.sniffer, None
        if sniffer is None:
            return
        # stop() relance l'exception d'un thread de capture planté : on la
        # garde comme message d'erreur au lieu de la laisser remonter.
        try:
            if _sniffer_alive(sniffer):
                sniffer.stop()
        except Exception as exc:
            self.error = _describe_error(exc)
        if getattr(sniffer, "exception", None) is not None:
            self.error = _describe_error(sniffer.exception)

    @property
    def running(self):
        self._check_sniffer()
        return self.sniffer is not None

    def _check_sniffer(self):
        """Détecte un thread de capture mort (Scapy le laisse marqué « running »)."""
        sniffer = self.sniffer
        if sniffer is not None and not _sniffer_alive(sniffer):
            self.sniffer = None
            self.error = _describe_error(sniffer.exception) if getattr(sniffer, "exception", None) else \
                "La capture s'est arrêtée toute seule."

    def clear(self):
        with self.lock:
            self._reset()

    def reference_now(self):
        """« Maintenant » pour les durées : la fin du fichier quand on en lit un."""
        if self.source["type"] == "file" and self.last_packet_time:
            return self.last_packet_time
        return time.time()

    # --- fichiers PCAP -----------------------------------------------------
    def load_pcap(self, path, name=None):
        """Remplace la capture en cours par le contenu d'un fichier pcap/pcapng."""
        with open(path, "rb") as fh:
            if fh.read(4) not in PCAP_MAGICS:
                raise ValueError("ce n'est pas un fichier pcap ou pcapng")
            fh.seek(0)
            self.stop()
            self.clear()
            with PcapReader(fh) as reader:
                for pkt in reader:
                    self._handle(pkt)
        with self.lock:
            self.source = {"type": "file", "name": name or str(path)}
        return self.packet_count

    def export_pcap(self, conn_ids=None):
        """Fichier pcap des paquets gardés, éventuellement limité à certaines connexions."""
        with self.lock:
            entries = [e for e in self.raw_packets if conn_ids is None or e[3] in conn_ids]
        linktype = entries[0][1] if entries else 1
        out = io.BytesIO()
        out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype))
        count = 0
        for t, entry_linktype, raw, _ in entries:
            if entry_linktype != linktype:
                continue               # un pcap classique n'a qu'un type de lien
            sec = int(t)
            usec = min(999_999, int(round((t - sec) * 1_000_000)))
            out.write(struct.pack("<IIII", sec, usec, len(raw), len(raw)))
            out.write(raw)
            count += 1
        return out.getvalue(), count

    # --- analyse d'un paquet -----------------------------------------------
    def _handle(self, pkt):
        try:
            self._process(pkt)
        except Exception:
            pass   # un paquet mal formé ne doit pas arrêter la capture

    def _process(self, pkt):
        now = float(getattr(pkt, "time", 0) or time.time())
        size = len(pkt)
        raw = getattr(pkt, "original", None) or bytes(pkt)
        entry = [now, conf.l2types.layer2num.get(type(pkt), 1), raw, None]

        ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        seg, l4 = None, None
        if ip is not None:
            src, dst = ip.src, ip.dst
            if pkt.haslayer(TCP):
                l4, seg = "tcp", pkt[TCP]
            elif pkt.haslayer(UDP):
                l4, seg = "udp", pkt[UDP]
            elif pkt.haslayer(ICMP) or ip.name == "IPv6" and ip.nh == 58:
                l4 = "icmp" if pkt.haslayer(ICMP) else "icmpv6"

        with self.lock:
            self.packet_count += 1
            self.raw_packets.append(entry)
            self.first_packet_time = self.first_packet_time or now
            self.last_packet_time = max(self.last_packet_time or now, now)
            self._learn_mac(pkt, ip)

            if l4 is None:
                self._count_timeline(now, size, "ARP" if pkt.haslayer(ARP) else "Autre", ())
                return
            sport, dport = (seg.sport, seg.dport) if seg is not None else (0, 0)
            payload = bytes(seg.payload) if seg is not None else b""
            a, b = (src, sport), (dst, dport)
            key = (l4,) + (a + b if a <= b else b + a)

            self.seen_ips[src] = now
            self.seen_ips[dst] = now
            if pkt.haslayer(DNS):
                self._learn_dns(pkt[DNS])

            conn = self.connections.get(key)
            if conn is None:
                conn = self._new_connection(l4, seg, src, sport, dst, dport, now)
                self.connections[key] = conn
                self.by_id[conn["id"]] = key
                if len(self.connections) > MAX_CONNECTIONS:
                    _, old = self.connections.popitem(last=False)
                    self.by_id.pop(old["id"], None)
                    self.stream_bytes -= old["_stream_len"]
            else:
                self.connections.move_to_end(key)
            entry[3] = conn["id"]

            outgoing = src == conn["src"]
            conn["packets"] += 1
            conn["bytes"] += size
            conn["last"] = max(conn["last"], now)
            if outgoing:
                conn["bytes_out"] += size
                conn["packets_out"] += 1
            else:
                conn["bytes_in"] += size
                conn["packets_in"] += 1

            flags = ""
            if l4 == "tcp":
                self._update_tcp_state(conn, seg)
                flags = str(seg.flags)
                conn["_flags"].update(flags)
            elif pkt.haslayer(ICMP):
                flags = pkt[ICMP].sprintf("%ICMP.type%")
            elif seg is None:
                flags = ip.payload.name           # type de message ICMPv6
            conn["_log"].append({
                "t": now, "dir": "out" if outgoing else "in", "size": size,
                "flags": flags, "payload_len": len(payload),
                "preview": payload[:PREVIEW_BYTES].hex(),
            })

            if payload:
                self._inspect_payload(conn, payload, l4)
                self._store_stream(conn, outgoing, seg.seq if l4 == "tcp" else None, now, payload)
            if pkt.haslayer(DNS):
                self._record_dns(conn, pkt[DNS])
            self._count_timeline(now, size, conn["proto"], (src, dst))

    def _new_connection(self, l4, seg, src, sport, dst, dport, now):
        # Sens de la connexion : le SYN désigne le client, sinon le port le plus
        # élevé (port éphémère) est supposé être côté client.
        if l4 == "tcp" and seg.flags & 0x12 == 0x12:          # SYN-ACK
            src, sport, dst, dport = dst, dport, src, sport
        elif not (l4 == "tcp" and seg.flags & 0x02) and sport < dport and sport < 1024:
            src, sport, dst, dport = dst, dport, src, sport

        guess = protocols.from_ports(l4, sport, dport)
        if guess:
            proto, layer = guess
        else:
            proto, layer = l4.upper().replace("V6", "v6"), 4
        conn = {
            "id": self._next_id, "l4": l4.upper().replace("V6", "v6"),
            "proto": proto, "layer": layer,
            "src": src, "sport": sport, "dst": dst, "dport": dport,
            "packets": 0, "bytes": 0, "bytes_out": 0, "bytes_in": 0,
            "packets_out": 0, "packets_in": 0,
            "first": now, "last": now, "state": "", "info": "",
            "_proto_from_payload": False, "_log": deque(maxlen=PACKET_LOG),
            "_flags": set(), "_dns": [], "_http": {},
            "_segments": [], "_stream_len": 0, "_stream_truncated": False,
        }
        self._next_id += 1
        return conn

    @staticmethod
    def _update_tcp_state(conn, seg):
        flags = int(seg.flags)
        if flags & 0x04:
            conn["state"] = "RESET"
        elif flags & 0x01:
            conn["state"] = "FERMÉE"
        elif flags & 0x02 and not flags & 0x10:
            conn["state"] = "SYN"
        elif conn["state"] in ("", "SYN") and flags & 0x10:
            conn["state"] = "ÉTABLIE"

    @staticmethod
    def _inspect_payload(conn, payload, l4):
        # Sur UDP (DNS, QUIC…), les premiers octets sont trop aléatoires pour
        # reconnaître TLS ou HTTP : on garde la détection par port.
        if l4 == "tcp" and not conn["_proto_from_payload"]:
            hit = protocols.from_payload(payload)
            if hit:
                conn["proto"], conn["layer"] = hit
                conn["_proto_from_payload"] = True
        if l4 == "tcp" and not conn["info"]:
            conn["info"] = protocols.tls_sni(payload) or protocols.http_host(payload) or ""
        if l4 == "tcp" and not conn["_http"] and payload.startswith(protocols.HTTP_METHODS[:-1]):
            conn["_http"] = protocols.http_request(payload)

    def _store_stream(self, conn, outgoing, seq, now, payload):
        if (conn["_stream_len"] + len(payload) > MAX_STREAM_BYTES
                or self.stream_bytes + len(payload) > STREAM_BUDGET):
            conn["_stream_truncated"] = True
            return
        conn["_segments"].append(("out" if outgoing else "in", seq, now, payload))
        conn["_stream_len"] += len(payload)
        self.stream_bytes += len(payload)

    def _learn_mac(self, pkt, ip):
        if pkt.haslayer(ARP) and pkt[ARP].op in (1, 2) and pkt[ARP].psrc != "0.0.0.0":
            self.macs[pkt[ARP].psrc] = pkt[ARP].hwsrc
        elif ip is not None and pkt.haslayer(Ether) and self._scope(ip.src) == "réseau local":
            self.macs[ip.src] = pkt[Ether].src

    def _scope(self, ip):
        scope = self._scopes.get(ip)
        if scope is None:
            if len(self._scopes) > 50_000:
                self._scopes.clear()
            scope = self._scopes[ip] = ip_scope(ip)
        return scope

    def _count_timeline(self, now, size, proto, endpoints):
        sec = int(now)
        bucket = self.buckets.get(sec)
        if bucket is None:
            bucket = self.buckets[sec] = {"bytes": 0, "packets": 0, "proto": Counter(),
                                           "host_proto": Counter()}
            while len(self.buckets) > TIMELINE_SECONDS:
                self.buckets.popitem(last=False)
        bucket["bytes"] += size
        bucket["packets"] += 1
        bucket["proto"][proto] += size
        for host in set(endpoints):
            if self._scope(host) == "réseau local":
                bucket["host_proto"][(host, proto)] += size

    @staticmethod
    def _record_dns(conn, dns):
        query = dns.qd[0] if isinstance(dns.qd, list) else dns.qd
        if not query:
            return
        name = query.qname.decode("ascii", "replace").rstrip(".")
        if not conn["info"]:
            conn["info"] = name
        if len(conn["_dns"]) >= MAX_DNS_ENTRIES:
            return
        answers = []
        for i in range(dns.ancount or 0):
            rr = dns.an[i]
            if isinstance(rr, DNSRR):
                answers.append(str(rr.rdata.decode("ascii", "replace")
                                   if isinstance(rr.rdata, bytes) else rr.rdata).rstrip("."))
        conn["_dns"].append({
            "response": bool(dns.qr),
            "name": name,
            "type": query.sprintf("%qtype%"),
            "answers": answers,
        })

    def _learn_dns(self, dns):
        for i in range(dns.ancount or 0):
            rr = dns.an[i]
            if isinstance(rr, DNSRR) and rr.type in (1, 28):    # A, AAAA
                name = rr.rrname.decode("ascii", "replace").rstrip(".")
                self.dns_names[str(rr.rdata)] = name

    # --- lecture -----------------------------------------------------------
    def _filtered(self, hosts=None, layers=None, protos=None, ports=None, search=None):
        """Connexions qui passent les filtres, les plus récentes en premier (verrou tenu)."""
        hosts = set(hosts or [])
        for conn in reversed(self.connections.values()):
            if hosts and conn["src"] not in hosts and conn["dst"] not in hosts:
                continue
            if layers and conn["layer"] not in layers:
                continue
            if protos and conn["proto"] not in protos and conn["l4"] not in protos:
                continue
            if ports and not _port_match(ports, conn["sport"], conn["dport"]):
                continue
            row = {k: v for k, v in conn.items() if not k.startswith("_")}
            row["src_name"] = self.dns_names.get(conn["src"], "")
            row["dst_name"] = self.dns_names.get(conn["dst"], "")
            if search and search not in " ".join(str(v) for v in row.values()).lower():
                continue
            yield row

    def snapshot(self, limit=2000, **filters):
        """Connexions filtrées, les plus récentes en premier."""
        out = []
        with self.lock:
            for row in self._filtered(**filters):
                out.append(row)
                if len(out) >= limit:
                    break
            stats = {
                "running": self.running, "iface": str(self.iface or conf.iface),
                "packets": self.packet_count, "connections": len(self.connections),
                "stored_packets": len(self.raw_packets), "error": self.error,
                "source": dict(self.source),
            }
            seen_protos = sorted({(c["layer"], c["proto"]) for c in self.connections.values()})
        return {"connections": out, "stats": stats,
                "protocols": [{"layer": l, "name": n} for l, n in seen_protos]}

    def matching_ids(self, **filters):
        with self.lock:
            return {row["id"] for row in self._filtered(**filters)}

    def connection_detail(self, conn_id):
        """Tout ce qu'on sait d'une connexion, avec ses derniers paquets."""
        with self.lock:
            key = self.by_id.get(conn_id)
            conn = key and self.connections.get(key)
            if not conn:
                return None
            row = {k: v for k, v in conn.items() if not k.startswith("_")}
            row.update({
                "packet_log": list(conn["_log"]),
                "tcp_flags": sorted(conn["_flags"]),
                "dns": list(conn["_dns"]),
                "http": dict(conn["_http"]),
                "stream_bytes": conn["_stream_len"],
                "src_name": self.dns_names.get(conn["src"], ""),
                "dst_name": self.dns_names.get(conn["dst"], ""),
            })
        row["src_scope"] = ip_scope(row["src"])
        row["dst_scope"] = ip_scope(row["dst"])
        row["layer_name"] = protocols.LAYER_NAMES.get(row["layer"], "")
        row["description"] = protocols.describe(row["proto"])
        return row

    def stream(self, conn_id):
        """Données applicatives d'une connexion, remises dans l'ordre (« Suivre le flux »)."""
        with self.lock:
            key = self.by_id.get(conn_id)
            conn = key and self.connections.get(key)
            if not conn:
                return None
            segments = list(conn["_segments"])
            info = {k: conn[k] for k in ("id", "proto", "l4", "src", "sport", "dst", "dport")}
            info["truncated"] = conn["_stream_truncated"]
        pieces = _reassemble_tcp(segments) if info["l4"] == "TCP" else [
            {"dir": d, "t": t, "data": data} for d, _, t, data in segments]
        info["chunks"] = _merge_chunks(pieces)
        info["bytes_out"] = sum(len(c.get("data", b"")) for c in info["chunks"] if c["dir"] == "out")
        info["bytes_in"] = sum(len(c.get("data", b"")) for c in info["chunks"] if c["dir"] == "in")
        return info

    def timeline(self, window=300, by="proto", hosts=None, max_series=6, max_bins=120):
        """Débit dans le temps, découpé par protocole ou par appareil local."""
        hosts = set(hosts or [])
        with self.lock:
            if not self.buckets:
                return {"bin": 1, "start": None, "bins": [], "series": []}
            end = int(self.reference_now())
            first = next(iter(self.buckets))
            start = max(first, end - window + 1) if window else first
            buckets = [(s, b) for s, b in self.buckets.items() if start <= s <= end]
        step = max(1, math.ceil((end - start + 1) / max_bins))
        bins = {}
        totals = Counter()
        for sec, bucket in buckets:
            values = bins.setdefault(start + (sec - start) // step * step, Counter())
            if hosts or by == "host":
                for (host, proto), size in bucket["host_proto"].items():
                    if hosts and host not in hosts:
                        continue
                    values[host if by == "host" else proto] += size
            else:
                values.update(bucket["proto"])
        for values in bins.values():
            totals.update(values)
        keep = [k for k, _ in totals.most_common(max_series)]
        out = []
        for t in range(start, end + 1, step):
            values = bins.get(t, Counter())
            row = {k: values.get(k, 0) / step for k in keep}
            other = sum(v for k, v in values.items() if k not in keep)
            if other:
                row[OTHER_SERIES] = other / step
            out.append({"t": t, "values": row})
        series = keep + ([OTHER_SERIES] if len(totals) > len(keep) else [])
        return {"bin": step, "start": start, "end": end, "bins": out, "series": series}

    def host_activity(self, ip):
        """Statistiques de capture pour un hôte : protocoles, correspondants, ports."""
        protos, peers, peer_conns = Counter(), Counter(), Counter()
        served, used = Counter(), Counter()
        total = {"connections": 0, "bytes": 0, "bytes_out": 0, "bytes_in": 0,
                 "packets": 0, "first": None, "last": None}
        with self.lock:
            for conn in self.connections.values():
                if ip == conn["src"]:
                    peer, is_client = conn["dst"], True
                elif ip == conn["dst"]:
                    peer, is_client = conn["src"], False
                else:
                    continue
                total["connections"] += 1
                total["bytes"] += conn["bytes"]
                total["packets"] += conn["packets"]
                total["bytes_out"] += conn["bytes_out"] if is_client else conn["bytes_in"]
                total["bytes_in"] += conn["bytes_in"] if is_client else conn["bytes_out"]
                total["first"] = min(total["first"] or conn["first"], conn["first"])
                total["last"] = max(total["last"] or 0, conn["last"])
                protos[(conn["layer"], conn["proto"])] += conn["bytes"]
                peers[peer] += conn["bytes"]
                peer_conns[peer] += 1
                if conn["dport"]:
                    (used if is_client else served)[(conn["l4"], conn["dport"])] += 1
            names = {p: self.dns_names.get(p, "") for p in peers}
            last_seen = self.seen_ips.get(ip)
        return {
            **total, "last_packet": last_seen,
            "protocols": [{"layer": l, "name": n, "bytes": b} for (l, n), b in protos.most_common()],
            "peers": [{"ip": p, "name": names[p], "scope": ip_scope(p), "bytes": b,
                       "connections": peer_conns[p]} for p, b in peers.most_common(15)],
            "served_ports": [{"l4": l, "port": p, "connections": c} for (l, p), c in served.most_common(20)],
            "used_ports": [{"l4": l, "port": p, "connections": c} for (l, p), c in used.most_common(20)],
        }


def _sniffer_alive(sniffer):
    return sniffer.thread is not None and sniffer.thread.is_alive()


def _describe_error(exc):
    return f"La capture s'est arrêtée : {type(exc).__name__}: {exc}"


def _reassemble_tcp(segments):
    """Remet les segments TCP de chaque sens dans l'ordre des numéros de séquence.

    Les retransmissions et chevauchements sont supprimés ; un trou dans la
    séquence (paquet non capturé) devient un morceau {"gap": n}.
    """
    pieces = []
    for direction in ("out", "in"):
        segs = [(seq, t, data) for d, seq, t, data in segments if d == direction]
        if not segs:
            continue
        base = min(segs, key=lambda s: s[1])[0]      # séquence du premier segment reçu
        ordered = sorted(((seq - base) % 2**32, t, data) for seq, t, data in segs)
        next_rel, last_t = None, 0.0
        for rel, t, data in ordered:
            t = max(t, last_t)                        # l'ordre de séquence prime
            if next_rel is not None and rel > next_rel:
                pieces.append({"dir": direction, "t": t, "gap": rel - next_rel})
            elif next_rel is not None and rel < next_rel:
                data = data[next_rel - rel:]          # retransmission partielle
                if not data:
                    continue
                rel = next_rel
            pieces.append({"dir": direction, "t": t, "data": data})
            next_rel, last_t = rel + len(data), t
    pieces.sort(key=lambda p: p["t"])                 # tri stable : l'ordre par sens est gardé
    return pieces


def _merge_chunks(pieces):
    merged = []
    for piece in pieces:
        last = merged[-1] if merged else None
        if last and "data" in piece and "data" in last and last["dir"] == piece["dir"]:
            last["data"] += piece["data"]
        else:
            merged.append(dict(piece))
    return merged


def ip_scope(ip):
    """Classe une adresse : local, public, multicast…"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    if addr.is_multicast:
        return "multicast"
    if str(addr) == "255.255.255.255" or addr.is_private and str(addr).endswith(".255"):
        return "broadcast"
    if addr.is_link_local:
        return "lien local"
    if addr.is_loopback:
        return "boucle locale"
    if addr.is_private:
        return "réseau local"
    return "Internet"


def parse_ports(text):
    """'80,443,8000-8100' -> liste de (début, fin)."""
    ranges = []
    for part in (text or "").replace(" ", "").split(","):
        if not part:
            continue
        lo, _, hi = part.partition("-")
        lo, hi = int(lo), int(hi or lo)
        ranges.append((min(lo, hi), max(lo, hi)))
    return ranges


def _port_match(ranges, sport, dport):
    return any(lo <= p <= hi for lo, hi in ranges for p in (sport, dport))
