"""Découverte des appareils du réseau local par requêtes ARP."""

import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor

from scapy.all import ARP, Ether, conf, get_if_addr, get_if_hwaddr, srp

# Au-delà de cette taille, on ne scanne que le /24 qui contient notre IP.
MAX_SCAN_HOSTS = 1024

# Ports TCP testés par « Scanner les ports courants » dans la fiche d'un hôte.
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 515, 548, 554,
                631, 1883, 3306, 3389, 5000, 5001, 5353, 5357, 5900, 7000, 8000, 8008,
                8009, 8080, 8443, 8883, 9000, 9100, 32400, 49152, 62078]


def local_network(iface=None):
    """Renvoie (ip locale, réseau IPv4, passerelle) pour l'interface donnée."""
    iface = iface or conf.iface
    my_ip = get_if_addr(iface)
    gateway = None
    network = None
    for net, msk, gw, r_iface, addr, _metric in conf.route.routes:
        if addr != my_ip:
            continue
        if net == 0 and msk == 0 and gw != "0.0.0.0":
            gateway = gw
            continue
        candidate = ipaddress.IPv4Network((net, bin(msk).count("1")), strict=False)
        if gw != "0.0.0.0" or candidate.prefixlen in (0, 32) or candidate.is_multicast:
            continue
        if ipaddress.IPv4Address(my_ip) in candidate:
            if network is None or candidate.prefixlen > network.prefixlen:
                network = candidate
    if network is None:
        network = ipaddress.IPv4Network(f"{my_ip}/24", strict=False)
    return my_ip, network, gateway


def vendor(mac):
    try:
        name = conf.manufdb._get_manuf(mac)
        return "" if name == mac else name
    except Exception:
        return ""


def _hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def scan(iface=None, timeout=2.0, retries=1):
    """Scanne le sous-réseau en ARP et renvoie la liste des hôtes trouvés."""
    iface = iface or conf.iface
    my_ip, network, gateway = local_network(iface)
    if network.num_addresses > MAX_SCAN_HOSTS:
        network = ipaddress.IPv4Network(f"{my_ip}/24", strict=False)

    answered, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network)),
        iface=iface, timeout=timeout, retry=retries, verbose=False,
    )

    now = time.time()
    found = {my_ip: get_if_hwaddr(iface)}
    for _req, rep in answered:
        found[rep[ARP].psrc] = rep[ARP].hwsrc

    with ThreadPoolExecutor(max_workers=32) as pool:
        names = dict(zip(found, pool.map(_hostname, found)))

    hosts = []
    for ip, mac in found.items():
        hosts.append({
            "ip": ip,
            "mac": mac,
            "vendor": vendor(mac),
            "hostname": names.get(ip, ""),
            "is_self": ip == my_ip,
            "is_gateway": ip == gateway,
            "last_seen": now,
        })
    hosts.sort(key=lambda h: ipaddress.IPv4Address(h["ip"]))
    return {"network": str(network), "self": my_ip, "gateway": gateway, "hosts": hosts}


def _tcp_open(ip, port, timeout):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((ip, port)) == 0


def scan_ports(ip, ports=COMMON_PORTS, timeout=0.6):
    """Teste en TCP les ports courants d'un hôte et renvoie ceux qui sont ouverts."""
    with ThreadPoolExecutor(max_workers=len(ports)) as pool:
        results = pool.map(lambda p: _tcp_open(ip, p, timeout), ports)
    return [p for p, is_open in zip(ports, results) if is_open]
