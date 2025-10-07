# Démo ARP Spoofing sur Docker

Ce dépôt fournit un environnement Docker complet pour démontrer une attaque de type ARP spoofing / man-in-the-middle entre une victime et un serveur HTTP. Trois conteneurs partagent le même réseau L2 :

- `server` : expose un service HTTP (Flask) qui journalise toutes les requêtes reçues.
- `victim` : envoie périodiquement des requêtes POST JSON vers le serveur.
- `attacker` : empoisonne les tables ARP de la victime et du serveur, intercepte le trafic HTTP et le relaie en affichant les requêtes/réponses capturées.

## Prérequis

- Docker et Docker Compose v2.
- Accès root au démon Docker (l'attaquant a besoin des capacités `NET_ADMIN` / `NET_RAW`).

## Lancer la démo

```bash
docker-compose up --build
```

Les conteneurs sont placés sur le réseau dédié `arpnet` avec des adresses fixes :

| Service  | Adresse IP   |
|----------|--------------|
| server   | 172.28.0.10  |
| victim   | 172.28.0.20  |
| attacker | 172.28.0.30  |

Le générateur de trafic (`victim`) émet une requête toutes les 4 secondes. L'attaquant démarre un sniffer Scapy, maintient l'empoisonnement ARP et ré-expédie les paquets pour que la communication se poursuive normalement malgré l'interception.

## Vérifier que l'attaque fonctionne

Affichez les journaux de l'attaquant pour voir les paquets interceptés :

```bash
docker-compose logs -f attacker
```

Exemple obtenu lors d'un run :

```
[ATTACKER] attacker container booting
[ATTACKER] using interface eth0
[ATTACKER] attacker MAC is 3e:08:57:5e:ff:f6
[ATTACKER] resolving MAC address for 172.28.0.20
[ATTACKER] MAC for 172.28.0.20 is 2a:eb:5d:bd:25:38
[ATTACKER] resolving MAC address for 172.28.0.10
[ATTACKER] MAC for 172.28.0.10 is 2a:ab:27:08:3c:77
[ATTACKER] starting ARP poisoning loop
[ATTACKER] starting packet sniffer
[ATTACKER] captured HTTP victim->server seq=3471736572 data="POST / HTTP/1.1"
[ATTACKER] captured HTTP victim->server seq=3471736767 data="{"client": "victim1", "sequence": 2, "ts": "2025-09-22T17:39:42"}"
[ATTACKER] captured HTTP server->victim seq=1001305274 data="HTTP/1.1 200 OK"
[ATTACKER] captured HTTP server->victim seq=1001305441 data="{"echo":"{\"client\": \"victim1\", \"sequence\": 2, \"ts\": \"2025-09-22T17:39:42\"}","status":"ok"}"
```

On observe que l'attaquant reçoit et relaie les requêtes POST de la victime *et* les réponses HTTP 200 du serveur, preuve du succès de l'attaque MITM.

Vous pouvez également consulter les journaux de la victime ou du serveur :

```bash
docker-compose logs victim
docker-compose logs server
```

## Arrêter et nettoyer

```bash
docker-compose down
```

## Personnalisation

Variable d'environnement | Description
-------------------------|------------
`REQUEST_INTERVAL`       | Modifie l'intervalle (en secondes) entre deux requêtes victim -> server (défaut : 4).
`CLIENT_ID`              | Identifiant utilisé par la victime dans la charge utile JSON.
`POISON_INTERVAL`        | Période en secondes entre deux paquets d'empoisonnement ARP.

Ces variables peuvent être surchargées directement dans `docker-compose.yml` ou via `docker compose run`.

## Notes techniques

- L'attaquant active l'IP forwarding si possible, puis effectue un « forwarding » au niveau utilisateur avec Scapy pour garantir que le trafic reste fonctionnel même dans un conteneur sans droits complets.
- Les tables ARP sont remises en état proprement lors de l'arrêt du conteneur attaquant.
- Tous les scripts sont écrits en Python pour rester portables et faciles à lire.
