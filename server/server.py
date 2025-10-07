# Ici je garde un mini serveur Flask pour incarner la cible de l'attaque.
import datetime
import sys

from flask import Flask, request

# Ici je prévois une mémoire des MAC déjà observées pour déclarer gentiment les changements suspects.
seen_peer_macs: dict[str, str] = {}

app = Flask(__name__)


def log(msg: str) -> None:
    """Affiche un message côté serveur avec un horodatage UTC pour suivre précisément les requêtes reçues."""
    timestamp = datetime.datetime.utcnow().isoformat(timespec="seconds")
    print(f"[SERVER {timestamp}Z] {msg}", flush=True)


def lookup_mac(ip_address: str) -> str:
    """Retourne la MAC connue dans /proc/net/arp pour l'IP demandée ou <unknown> si rien n'est résolu."""
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


def report_mac_change(ip_address: str, mac_address: str) -> None:
    """Compare la MAC observée avec la précédente et loggue tout changement pour mettre en évidence le MITM."""
    previous = seen_peer_macs.get(ip_address)
    if previous is None:
        log(f"ARP cache initial pour {ip_address} -> {mac_address}")
    elif previous != mac_address:
        log(f"ARP cache modifié pour {ip_address}: {previous} -> {mac_address}")
    seen_peer_macs[ip_address] = mac_address


@app.route("/", methods=["GET", "POST"])
def index():
    """Route unique qui journalise l'adresse source, le user-agent et le corps de chaque requête HTTP."""
    body = request.get_data(as_text=True) or "<empty body>"
    source_ip = request.remote_addr
    mac_address = lookup_mac(source_ip)
    report_mac_change(source_ip, mac_address)
    log(
        "message from %s user-agent=%s body=%s"
        % (source_ip, request.user_agent.string, body)
    )
    return {"status": "ok", "echo": body}, 200


if __name__ == "__main__":
    # Ici je lance Flask en mode production minimal, histoire d'écouter sur tous les ports.
    log("HTTP server starting on port 80")
    app.run(host="0.0.0.0", port=80, debug=False)
