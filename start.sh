#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# RaspiScanner — prova rapida su Linux / Raspberry Pi.
#
# Gemello di start.bat: crea un virtualenv nella cartella del progetto,
# installa le dipendenze, avvia la dashboard in primo piano e apre il
# browser. Si ferma con Ctrl-C e non lascia nulla dietro di sé.
#
# NON è l'installazione: per l'uso permanente (servizio systemd, avvio al
# boot, autoconfigurazione della scheda di rete su un Pi dedicato) serve
# `sudo ./install.sh`. Vedi docs/QUICK-START.md.
#
# Cosa NON fa, avviato senza privilegi:
#  - non tocca la configurazione di rete: la scheda resta come l'ha
#    impostata il sistema (sola lettura, esattamente come su Windows);
#  - niente hotspot Wi-Fi;
#  - l'ARP scan a livello 2 richiede root: senza, ripiega su sweep
#    TCP-connect + tabella ARP di sistema. Trova comunque telecamere, NVR e
#    apparati, che espongono quasi sempre una porta di gestione.
#
# Per la scansione completa a livello 2, con la rete comunque intatta:
#   sudo -E RASPISCANNER_NO_NETWORK_CONFIG=1 ./start.sh
# ---------------------------------------------------------------------------
set -euo pipefail
cd "$(dirname "$0")"

PORT="${RASPISCANNER_PORT:-7332}"
URL="https://127.0.0.1:${PORT}"

if ! command -v python3 >/dev/null 2>&1; then
    echo
    echo "  python3 not found. Install it with your distribution's package"
    echo "  manager, for example:  sudo apt install python3 python3-venv"
    echo
    exit 1
fi

if [ ! -d .venv ]; then
    echo "Creating Python environment..."
    if ! python3 -m venv .venv 2>/dev/null; then
        echo
        echo "  Creating the virtualenv failed. On Debian/Ubuntu/Raspberry Pi OS"
        echo "  the package is probably missing:  sudo apt install python3-venv"
        echo
        exit 1
    fi
fi

# shellcheck disable=SC1091
source .venv/bin/activate

echo "Installing/updating dependencies..."
python -m pip install -q --upgrade pip
if ! python -m pip install -q -r requirements.txt; then
    echo
    echo "  Installing dependencies failed: check your connection and try again."
    echo
    exit 1
fi
# `cryptography` genera il certificato TLS quando `openssl` non è nel PATH.
# Su Linux openssl c'è quasi sempre, quindi qui è solo una rete di sicurezza
# e un errore non deve fermare l'avvio.
python -m pip install -q cryptography 2>/dev/null || true

echo "Updating vendor database (OUI) from the IEEE (optional, needs internet)..."
python scripts/update_oui.py --if-missing 2>/dev/null || \
    echo "  (full OUI not downloaded, using the bundled minimal list)"

# Avvertenze utili prima di partire, in modo che l'utente sappia cosa
# aspettarsi invece di scoprirlo dai risultati.
if [ "$(id -u)" -ne 0 ]; then
    echo
    echo "  Running without privileges: the network configuration is NOT touched."
    echo "  The layer-2 ARP scan is not available, using the TCP sweep +"
    echo "  system ARP table instead. For the full scan:"
    echo "    sudo -E RASPISCANNER_NO_NETWORK_CONFIG=1 ./start.sh"
elif [ "${RASPISCANNER_NO_NETWORK_CONFIG:-}" = "" ]; then
    echo
    echo "  WARNING: running as root WITHOUT RASPISCANNER_NO_NETWORK_CONFIG=1."
    echo "  In this mode the scanner may RECONFIGURE the Ethernet interface"
    echo "  (DHCP, then static fallback addresses): that is the intended"
    echo "  behavior on a dedicated Raspberry Pi, not on a work laptop."
    echo "  Press Ctrl-C within 5 seconds to cancel."
    sleep 5
fi

echo
echo "Starting RaspiScanner at ${URL}"
echo "(self-signed certificate: the browser shows a warning you accept once)"
echo "Press Ctrl-C to stop it."
echo

# Apre il browser solo se c'è una sessione grafica: su un Pi headless o via
# SSH non c'è nulla da aprire, e l'URL stampato sopra è già l'istruzione.
if [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] && command -v xdg-open >/dev/null 2>&1; then
    (sleep 2 && xdg-open "$URL" >/dev/null 2>&1) &
fi

exec python raspi-scanner.py --port "$PORT"
