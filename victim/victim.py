# Ce script simule une victime qui parle en boucle au serveur.
import datetime
import json
import os
import time

import requests

# Ici je garde en mémoire la dernière MAC connue du serveur pour signaler tout changement d'ARP.
last_server_mac: str | None = None

# J'ai pris les paramètres dont j'ai besoin depuis l'environnement.
SERVER_URL = os.environ.get("SERVER_URL", "http://arp_server/")
CLIENT_ID = os.environ.get("CLIENT_ID", "victim")
REQUEST_INTERVAL = float(os.environ.get("REQUEST_INTERVAL", "4"))


def log(message: str) -> None:
    """Affiche côté victime un message horodaté afin de retracer chaque tentative d'envoi HTTP."""
    timestamp = datetime.datetime.utcnow().isoformat(timespec="seconds")
    print(f"[VICTIM {timestamp}Z] {message}", flush=True)


def lookup_mac(ip_address: str) -> str:
    """Récupère la MAC courante pour l'IP spécifiée via la table ARP du noyau."""
    try:
        with open("/proc/net/arp", encoding="ascii") as fd:
            lines = fd.readlines()[1:]
    except OSError as exc:
        log(f"failed reading /proc/net/arp: {exc}")
        return "<unknown>"

    for line in lines:
        fields = line.split()
        if len(fields) >= 4 and fields[0] == ip_address:
            return fields[3]
    return "<unknown>"


def report_server_mac() -> None:
    """Inspecte la MAC du serveur cible et loggue toute variation pour illustrer la compromission ARP."""
    global last_server_mac
    current_mac = lookup_mac(SERVER_URL.split("//", 1)[-1].split("/", 1)[0])
    if last_server_mac is None:
        log(f"ARP cache initial serveur -> {current_mac}")
    elif last_server_mac != current_mac:
        log(f"ARP cache serveur modifié: {last_server_mac} -> {current_mac}")
    last_server_mac = current_mac


if __name__ == "__main__":
    # Ici j'annonce le début du trafic pour le retrouver vite dans les journaux.
    log(f"starting traffic generator towards {SERVER_URL}")
    counter = 1
    while True:
        # Je construis un payload JSON simple pour que l'attaquant puisse le lire facilement.
        payload = {
            "client": CLIENT_ID,
            "sequence": counter,
            "ts": datetime.datetime.utcnow().isoformat(timespec="seconds"),
        }
        try:
            report_server_mac()
            # J'envoie la requête et je loggue la réponse pour vérifier l'aller-retour.
            response = requests.post(
                SERVER_URL,
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"},
                timeout=3,
            )
            log(
                f"POST seq={counter} status={response.status_code} response={response.text.strip()}"
            )
        except Exception as exc:  
            # En cas d'erreur, je loggue aussi l'exception pour voir ce qui se passe si l'attaquant casse la chaîne.
            log(f"request failed: {exc}")
        counter += 1
        time.sleep(REQUEST_INTERVAL)
