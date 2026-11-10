# Host Scan

Petit analyseur réseau inspiré de Wireshark, pensé pour le réseau domestique, avec
une interface web locale.

*[English version](README.md)*

## Fonctionnalités

- **Découverte des appareils** : scan ARP du sous-réseau (IP, MAC, fabricant, nom),
  plus les appareils vus passivement dans la capture.
- **Capture regroupée en connexions** : sens client → serveur, état TCP, paquets et
  octets dans chaque sens.
- **Reconnaissance des protocoles** par le contenu (TLS, HTTP, SSH) ou par le port,
  rangés par couche OSI : L4 transport, L5 session, L6 présentation, L7 application.
- **Métadonnées utiles** : SNI TLS (le nom du site, même chiffré), requête HTTP,
  questions et réponses DNS, noms des IP appris dans les réponses DNS.
- **Filtres** : appareils, couches, protocoles, plages de ports (`53,443,8000-8100`),
  recherche texte, filtre de capture BPF.
- **Détail d'une connexion** (clic sur une ligne) : extrémités, flags TCP, durée,
  débit, 30 derniers paquets avec leurs octets en hexadécimal.
- **Suivre le flux TCP/UDP** : les données remises dans l'ordre (segments réordonnés,
  retransmissions supprimées, trous signalés), affichées comme une conversation en
  deux couleurs, en texte ou en hexadécimal.
- **Graphique de débit en direct**, empilé par protocole ou par appareil, avec infobulle.
- **Fiche d'un appareil** (clic sur son nom) : protocoles, principaux correspondants,
  ports, et test des 36 ports TCP courants.
- **Import / export PCAP** : ouvrir un `.pcap` / `.pcapng` de Wireshark ou tcpdump ;
  exporter toute la capture, la vue filtrée ou une seule connexion.

## Démarrage rapide

```bash
pip install -r requirements.txt
python app.py --demo
```

`--demo` charge [`samples/demo.pcap`](samples/demo.pcap) : trois minutes de trafic
domestique inventé (PC, téléphone, TV, imprimante). Ni Npcap ni droits
administrateur ne sont nécessaires.

### Capture en direct

- **Windows** : installer [Npcap](https://npcap.com) (fourni avec Wireshark), puis
  lancer `python app.py` depuis un terminal **administrateur**.
- **Linux / macOS** : `sudo python app.py`.

L'interface s'ouvre sur http://127.0.0.1:5000. Autres options : `--pcap FICHIER`,
`--port N`, `--no-browser`.

## Limites

- Sur un réseau commuté (box, switch, Wi-Fi), le PC ne reçoit que **son propre trafic**
  et le broadcast/multicast des autres. Pour voir les connexions d'un autre appareil,
  son trafic doit passer par le PC : port miroir, capture sur le routeur, ou PC en point
  d'accès (Windows : *Point d'accès sans fil mobile*, puis la carte `192.168.137.1`).
- Le trafic chiffré (TLS, QUIC, SSH) n'est pas déchiffré : on voit qui parle à qui,
  quand et combien, ainsi que le SNI, mais pas le contenu.
- La détection des protocoles est heuristique.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

## Usage responsable

N'analysez que les réseaux qui vous appartiennent ou pour lesquels vous avez une
autorisation explicite.

## Licence

[MIT](LICENSE)
