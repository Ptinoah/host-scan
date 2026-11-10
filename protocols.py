"""Identification des protocoles applicatifs et de leur couche OSI.

La couche 4 est le transport (TCP, UDP, ICMP). Au-dessus, chaque protocole
est rangé dans la couche OSI où on le classe habituellement :
  5 = session, 6 = présentation (chiffrement / encodage), 7 = application.
"""

# (nom, couche) indexés par (transport, port)
PORTS = {
    # Couche 5 - session
    ("tcp", 135): ("MS-RPC", 5),
    ("udp", 137): ("NetBIOS-NS", 5),
    ("udp", 138): ("NetBIOS-DGM", 5),
    ("tcp", 139): ("NetBIOS-SSN", 5),
    ("tcp", 1080): ("SOCKS", 5),
    ("tcp", 1723): ("PPTP", 5),
    ("udp", 1701): ("L2TP", 5),
    ("tcp", 111): ("SunRPC", 5),
    ("udp", 111): ("SunRPC", 5),
    # Couche 6 - présentation (TLS et services encapsulés dans TLS)
    ("tcp", 443): ("TLS", 6),
    ("tcp", 465): ("TLS", 6),
    ("tcp", 563): ("TLS", 6),
    ("tcp", 636): ("TLS", 6),
    ("tcp", 853): ("TLS", 6),
    ("tcp", 993): ("TLS", 6),
    ("tcp", 995): ("TLS", 6),
    ("tcp", 5223): ("TLS", 6),
    ("tcp", 8443): ("TLS", 6),
    ("udp", 443): ("QUIC", 6),
    ("udp", 4433): ("QUIC", 6),
    # Couche 7 - application
    ("tcp", 20): ("FTP-DATA", 7),
    ("tcp", 21): ("FTP", 7),
    ("tcp", 22): ("SSH", 7),
    ("tcp", 23): ("Telnet", 7),
    ("tcp", 25): ("SMTP", 7),
    ("tcp", 587): ("SMTP", 7),
    ("tcp", 53): ("DNS", 7),
    ("udp", 53): ("DNS", 7),
    ("udp", 67): ("DHCP", 7),
    ("udp", 68): ("DHCP", 7),
    ("udp", 69): ("TFTP", 7),
    ("tcp", 80): ("HTTP", 7),
    ("tcp", 8000): ("HTTP", 7),
    ("tcp", 8080): ("HTTP", 7),
    ("tcp", 110): ("POP3", 7),
    ("udp", 123): ("NTP", 7),
    ("tcp", 143): ("IMAP", 7),
    ("udp", 161): ("SNMP", 7),
    ("udp", 162): ("SNMP-Trap", 7),
    ("tcp", 389): ("LDAP", 7),
    ("tcp", 445): ("SMB", 7),
    ("udp", 500): ("IKE", 7),
    ("udp", 514): ("Syslog", 7),
    ("tcp", 554): ("RTSP", 7),
    ("tcp", 631): ("IPP", 7),
    ("tcp", 1883): ("MQTT", 7),
    ("udp", 1900): ("SSDP", 7),
    ("tcp", 3306): ("MySQL", 7),
    ("tcp", 3389): ("RDP", 7),
    ("udp", 3478): ("STUN", 7),
    ("udp", 3702): ("WS-Discovery", 7),
    ("udp", 4500): ("IPsec-NAT-T", 7),
    ("tcp", 5432): ("PostgreSQL", 7),
    ("udp", 5353): ("mDNS", 7),
    ("udp", 5355): ("LLMNR", 7),
    ("tcp", 5900): ("VNC", 7),
    ("tcp", 6379): ("Redis", 7),
    ("tcp", 8009): ("Chromecast", 7),
    ("tcp", 8883): ("MQTT", 7),
    ("tcp", 27017): ("MongoDB", 7),
    ("udp", 51820): ("WireGuard", 7),
    ("tcp", 515): ("LPD", 7),
    ("tcp", 548): ("AFP", 7),
    ("tcp", 5000): ("UPnP/AirPlay", 7),
    ("tcp", 5357): ("WSDAPI", 7),
    ("tcp", 7000): ("AirPlay", 7),
    ("tcp", 8008): ("Chromecast", 7),
    ("tcp", 9100): ("JetDirect", 7),
    ("tcp", 32400): ("Plex", 7),
    ("tcp", 62078): ("iPhone-Sync", 7),
}

L4_PROTOCOLS = {"TCP", "UDP", "ICMP", "ICMPv6"}

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ",
                b"PATCH ", b"CONNECT ", b"HTTP/1.")


LAYER_NAMES = {4: "Transport", 5: "Session", 6: "Présentation", 7: "Application"}

# Explication courte affichée dans la vue détaillée d'une connexion.
DESCRIPTIONS = {
    "TCP": "Transport fiable et ordonné ; aucun protocole applicatif reconnu au-dessus.",
    "UDP": "Transport sans connexion ; aucun protocole applicatif reconnu au-dessus.",
    "ICMP": "Messages de contrôle IP (ping, erreurs de routage…).",
    "ICMPv6": "Messages de contrôle IPv6 (voisinage, annonces de routeur, ping…).",
    "MS-RPC": "Appels de procédure distante Windows (partages, gestion à distance).",
    "NetBIOS-NS": "Résolution des noms NetBIOS des PC Windows sur le réseau local.",
    "NetBIOS-DGM": "Annonces NetBIOS (voisinage réseau Windows).",
    "NetBIOS-SSN": "Sessions NetBIOS, ancien transport des partages Windows.",
    "SOCKS": "Proxy générique qui relaie des connexions.",
    "PPTP": "Ancien protocole de VPN.",
    "L2TP": "Tunnel VPN (souvent combiné à IPsec).",
    "SunRPC": "Appels de procédure distante Unix (NFS…).",
    "TLS": "Connexion chiffrée (HTTPS, e-mail sécurisé…). Le contenu est illisible ; "
           "le nom du site apparaît dans le SNI.",
    "QUIC": "Transport chiffré sur UDP utilisé par HTTP/3 (Google, YouTube, Meta…).",
    "FTP": "Transfert de fichiers, non chiffré.",
    "FTP-DATA": "Canal de données d'un transfert FTP.",
    "SSH": "Terminal distant chiffré.",
    "Telnet": "Terminal distant non chiffré.",
    "SMTP": "Envoi d'e-mails.",
    "DNS": "Traduction des noms de domaine en adresses IP.",
    "DHCP": "Attribution automatique d'une adresse IP par la box.",
    "TFTP": "Transfert de fichiers simplifié (démarrage réseau, firmwares).",
    "HTTP": "Web non chiffré : les URL et le contenu sont lisibles.",
    "POP3": "Relève d'e-mails.",
    "NTP": "Synchronisation de l'horloge.",
    "IMAP": "Consultation d'e-mails.",
    "SNMP": "Supervision d'équipements réseau (imprimantes, box…).",
    "SNMP-Trap": "Alertes envoyées par un équipement supervisé.",
    "LDAP": "Annuaire (comptes, authentification).",
    "SMB": "Partage de fichiers et d'imprimantes Windows.",
    "IKE": "Négociation d'un tunnel VPN IPsec.",
    "Syslog": "Envoi de journaux système.",
    "RTSP": "Contrôle de flux vidéo (caméras IP).",
    "IPP": "Impression réseau.",
    "MQTT": "Messagerie légère des objets connectés.",
    "SSDP": "Découverte UPnP : appareils qui s'annoncent (TV, box, consoles…).",
    "MySQL": "Base de données MySQL.",
    "RDP": "Bureau à distance Windows.",
    "STUN": "Découverte de l'adresse publique pour appels vidéo et jeux en ligne.",
    "WS-Discovery": "Découverte d'appareils Windows (imprimantes, scanners…).",
    "IPsec-NAT-T": "Tunnel VPN IPsec à travers la box.",
    "PostgreSQL": "Base de données PostgreSQL.",
    "mDNS": "Découverte locale des appareils (AirPlay, Chromecast, imprimantes…).",
    "LLMNR": "Résolution de noms locale Windows.",
    "VNC": "Partage d'écran à distance.",
    "Redis": "Base de données en mémoire.",
    "Chromecast": "Contrôle d'un appareil Chromecast / Google Cast.",
    "MongoDB": "Base de données MongoDB.",
    "WireGuard": "Tunnel VPN WireGuard.",
    "LPD": "Impression réseau (ancien protocole Unix).",
    "AFP": "Partage de fichiers Apple.",
    "UPnP/AirPlay": "Contrôle UPnP ou AirPlay (Mac, box, appareils multimédia).",
    "WSDAPI": "Services Web pour appareils Windows (découverte d'imprimantes, de PC…).",
    "AirPlay": "Diffusion audio/vidéo Apple.",
    "JetDirect": "Impression réseau directe (imprimantes HP et autres).",
    "Plex": "Serveur multimédia Plex.",
    "iPhone-Sync": "Synchronisation Wi-Fi d'un iPhone ou iPad avec un ordinateur.",
}


def describe(proto_name):
    return DESCRIPTIONS.get(proto_name, "")


def layer_of(proto_name):
    if proto_name in L4_PROTOCOLS:
        return 4
    for name, layer in PORTS.values():
        if name == proto_name:
            return layer
    return 7


def from_payload(payload):
    """Reconnaît un protocole à partir des premiers octets du payload."""
    if len(payload) >= 3 and payload[0] in (0x14, 0x15, 0x16, 0x17) and payload[1] == 0x03:
        return ("TLS", 6)
    if payload.startswith(HTTP_METHODS):
        return ("HTTP", 7)
    if payload.startswith(b"SSH-"):
        return ("SSH", 7)
    return None


def from_ports(transport, sport, dport):
    """Choisit le protocole d'après le port le plus « connu » des deux."""
    for port in sorted((sport, dport)):
        hit = PORTS.get((transport, port))
        if hit:
            return hit
    return None


def tls_sni(payload):
    """Extrait le nom de serveur (SNI) d'un ClientHello TLS, sinon None."""
    try:
        if payload[0] != 0x16 or payload[5] != 0x01:
            return None
        pos = 5 + 4 + 2 + 32                      # en-têtes + version + random
        pos += 1 + payload[pos]                   # session id
        pos += 2 + int.from_bytes(payload[pos:pos + 2], "big")   # cipher suites
        pos += 1 + payload[pos]                   # compression
        end = pos + 2 + int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2
        while pos + 4 <= end:
            ext_type = int.from_bytes(payload[pos:pos + 2], "big")
            ext_len = int.from_bytes(payload[pos + 2:pos + 4], "big")
            pos += 4
            if ext_type == 0:                     # server_name
                name_len = int.from_bytes(payload[pos + 3:pos + 5], "big")
                return payload[pos + 5:pos + 5 + name_len].decode("ascii", "replace")
            pos += ext_len
    except (IndexError, ValueError):
        pass
    return None


def http_host(payload):
    """Extrait l'en-tête Host d'une requête HTTP, sinon None."""
    head = payload[:2048].split(b"\r\n\r\n", 1)[0]
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"host:"):
            return line[5:].strip().decode("ascii", "replace")
    return None


def http_request(payload):
    """Ligne de requête et quelques en-têtes utiles d'une requête HTTP."""
    lines = payload[:4096].split(b"\r\n\r\n", 1)[0].split(b"\r\n")
    result = {"request": lines[0].decode("ascii", "replace")}
    wanted = {b"host": "host", b"user-agent": "user_agent", b"referer": "referer"}
    for line in lines[1:]:
        name, _, value = line.partition(b":")
        key = wanted.get(name.strip().lower())
        if key:
            result[key] = value.strip().decode("ascii", "replace")
    return result
