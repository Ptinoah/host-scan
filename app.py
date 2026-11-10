"""Serveur web local : python app.py puis ouvrir http://127.0.0.1:5000"""

import argparse
import base64
import io
import ipaddress
import os
import tempfile
import threading
import time
import webbrowser
from pathlib import Path

from flask import Flask, jsonify, request, send_file, send_from_directory
from scapy.all import conf, get_working_ifaces
from scapy.error import Scapy_Exception

import netscan
import protocols
from sniffer import ConnectionTracker, parse_ports

BASE_DIR = Path(__file__).resolve().parent
DEMO_PCAP = BASE_DIR / "samples" / "demo.pcap"

app = Flask(__name__, static_folder=str(BASE_DIR / "static"))
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024 * 1024     # fichiers pcap importés
tracker = ConnectionTracker()
state = {"scan": None, "scanning": False, "scan_error": None}
state_lock = threading.Lock()


def _is_admin():
    # Npcap installé en mode « admin only » ne capture rien sans élévation.
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return getattr(os, "geteuid", lambda: 0)() == 0


IS_ADMIN = _is_admin()


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/api/interfaces")
def interfaces():
    # Relit les cartes et les routes : un point d'accès activé après le
    # lancement du programme doit apparaître avec sa nouvelle adresse.
    conf.ifaces.reload()
    conf.route.resync()
    items = []
    for iface in get_working_ifaces():
        if not iface.ip or iface.ip.startswith(("127.", "169.254.")):
            continue
        items.append({"name": iface.network_name, "label": f"{iface.description} ({iface.ip})",
                      "default": iface.network_name == conf.iface.network_name})
    return jsonify(items)


def _run_scan(iface):
    try:
        result = netscan.scan(iface)
        with state_lock:
            state["scan"], state["scan_error"] = result, None
    except Exception as exc:
        with state_lock:
            state["scan_error"] = str(exc)
    finally:
        with state_lock:
            state["scanning"] = False


@app.post("/api/scan")
def start_scan():
    iface = (request.json or {}).get("iface") or conf.iface
    with state_lock:
        if not state["scanning"]:
            state["scanning"] = True
            threading.Thread(target=_run_scan, args=(iface,), daemon=True).start()
    return jsonify(ok=True)


@app.get("/api/hosts")
def hosts():
    with state_lock:
        payload = {"scanning": state["scanning"], "error": state["scan_error"],
                   "network": state["scan"] and state["scan"]["network"]}
    payload["hosts"] = _all_hosts()
    return jsonify(payload)


@app.get("/api/host/<ip>")
def host_detail(ip):
    host = next((h for h in _all_hosts() if h["ip"] == ip), None)
    if host is None:
        return jsonify(error="Hôte inconnu"), 404
    return jsonify(host=host, activity=tracker.host_activity(ip), now=tracker.reference_now())


@app.post("/api/host/<ip>/ports")
def host_ports(ip):
    if not any(h["ip"] == ip for h in _all_hosts()):
        return jsonify(error="Hôte inconnu"), 404
    open_ports = netscan.scan_ports(ip)
    return jsonify(ports=[{"port": p, "service": (protocols.PORTS.get(("tcp", p)) or ("",))[0]}
                          for p in open_ports],
                   tested=len(netscan.COMMON_PORTS), at=time.time())


@app.get("/api/connection/<int:conn_id>")
def connection_detail(conn_id):
    detail = tracker.connection_detail(conn_id)
    if detail is None:
        return jsonify(error="Connexion introuvable (vidée ou trop ancienne)"), 404
    return jsonify(connection=detail, now=tracker.reference_now())


@app.get("/api/connection/<int:conn_id>/stream")
def connection_stream(conn_id):
    stream = tracker.stream(conn_id)
    if stream is None:
        return jsonify(error="Connexion introuvable (vidée ou trop ancienne)"), 404
    for chunk in stream["chunks"]:
        if "data" in chunk:
            chunk["data"] = base64.b64encode(chunk["data"]).decode("ascii")
    return jsonify(stream)


def _all_hosts():
    """Hôtes du dernier scan, plus les hôtes locaux aperçus pendant la capture."""
    with state_lock:
        scan = state["scan"]
        known = {h["ip"]: dict(h) for h in scan["hosts"]} if scan else {}
        network = ipaddress.ip_network(scan["network"]) if scan else None
    for ip, seen in list(tracker.seen_ips.items()):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.version != 4:
            continue
        if network is not None:
            local = addr in network and addr not in (network.network_address,
                                                     network.broadcast_address)
        else:
            # Sans scan (fichier importé, par exemple) : toute adresse privée.
            local = addr.is_private and not str(addr).endswith((".0", ".255"))
        if local:
            host = known.setdefault(ip, {"ip": ip, "mac": "", "vendor": "", "hostname": "",
                                         "is_self": False, "is_gateway": False, "passive": True})
            host["last_seen"] = max(host.get("last_seen", 0), seen)
    for ip, host in known.items():
        if not host["mac"] and ip in tracker.macs:
            host["mac"] = tracker.macs[ip]
            host["vendor"] = netscan.vendor(host["mac"])
    return sorted(known.values(), key=lambda h: ipaddress.ip_address(h["ip"]))


@app.post("/api/capture/start")
def capture_start():
    body = request.json or {}
    tracker.start(body.get("iface"), body.get("bpf"))
    return jsonify(ok=tracker.running, error=tracker.error)


@app.post("/api/capture/stop")
def capture_stop():
    tracker.stop()
    return jsonify(ok=True)


@app.post("/api/capture/clear")
def capture_clear():
    tracker.clear()
    return jsonify(ok=True)


def _filters(args):
    """Filtres de la vue (hôtes, couches, protocoles, ports, texte) depuis la query string."""
    return {
        "hosts": [h for h in args.get("hosts", "").split(",") if h],
        "layers": {int(x) for x in args.get("layers", "").split(",") if x.strip().isdigit()},
        "protos": {p for p in args.get("protos", "").split(",") if p},
        "ports": parse_ports(args.get("ports")),
        "search": args.get("q", "").strip().lower() or None,
    }


PORT_ERROR = "Filtre de ports invalide (ex : 80,443,8000-8100)"


@app.get("/api/connections")
def connections():
    try:
        filters = _filters(request.args)
    except ValueError:
        return jsonify(error=PORT_ERROR), 400
    result = tracker.snapshot(**filters)
    result["now"] = tracker.reference_now()
    result["stats"]["is_admin"] = IS_ADMIN
    return jsonify(result)


@app.get("/api/timeline")
def timeline():
    args = request.args
    window = int(args.get("window", 300)) if args.get("window", "300").isdigit() else 300
    by = "host" if args.get("by") == "host" else "proto"
    hosts = [h for h in args.get("hosts", "").split(",") if h]
    return jsonify(tracker.timeline(window=window, by=by, hosts=hosts))


@app.get("/api/export")
def export_pcap():
    """Télécharge la capture (scope=all), la vue filtrée (filtered) ou une connexion (conn)."""
    scope = request.args.get("scope", "all")
    if scope == "conn":
        conn_ids = {int(request.args.get("id", 0))}
    elif scope == "filtered":
        try:
            conn_ids = tracker.matching_ids(**_filters(request.args))
        except ValueError:
            return jsonify(error=PORT_ERROR), 400
    else:
        conn_ids = None
    data, count = tracker.export_pcap(conn_ids)
    name = time.strftime("host-scan-%Y%m%d-%H%M%S") + (f"-flux{min(conn_ids)}" if scope == "conn" else "")
    response = send_file(io.BytesIO(data), mimetype="application/vnd.tcpdump.pcap",
                         as_attachment=True, download_name=f"{name}.pcap")
    response.headers["X-Packet-Count"] = str(count)
    return response


@app.post("/api/import")
def import_pcap():
    upload = request.files.get("file")
    if not upload or not upload.filename:
        return jsonify(error="Aucun fichier reçu"), 400
    fd, path = tempfile.mkstemp(suffix=Path(upload.filename).suffix)
    os.close(fd)
    try:
        upload.save(path)
        count = tracker.load_pcap(path, name=upload.filename)
    except (Scapy_Exception, OSError, ValueError, EOFError) as exc:
        return jsonify(error=f"Fichier illisible : {exc}"), 400
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
    return jsonify(ok=True, packets=count, connections=len(tracker.connections))


def main():
    parser = argparse.ArgumentParser(description="Host Scan : scan du réseau local et analyse du trafic.")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--demo", action="store_true",
                        help="charge samples/demo.pcap (aucun droit administrateur requis)")
    parser.add_argument("--pcap", help="ouvre ce fichier pcap/pcapng au démarrage")
    parser.add_argument("--no-browser", action="store_true", help="n'ouvre pas le navigateur")
    args = parser.parse_args()

    pcap = DEMO_PCAP if args.demo else args.pcap
    if pcap:
        count = tracker.load_pcap(pcap, name=Path(pcap).name)
        print(f"{count} paquets chargés depuis {pcap}")
    url = f"http://127.0.0.1:{args.port}"
    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    app.run(host="127.0.0.1", port=args.port, threaded=True)


if __name__ == "__main__":
    main()
