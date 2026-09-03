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
# `sudo ./install.sh`. Vedi docs/PROVA-RAPIDA.md.
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
    echo "  python3 non trovato. Installalo con il gestore pacchetti della tua"
    echo "  distribuzione, per esempio:  sudo apt install python3 python3-venv"
    echo
    exit 1
fi

if [ ! -d .venv ]; then
    echo "Creazione ambiente Python..."
    if ! python3 -m venv .venv 2>/dev/null; then
        echo
        echo "  Creazione del virtualenv fallita. Su Debian/Ubuntu/Raspberry Pi OS"
        echo "  manca probabilmente il pacchetto:  sudo apt install python3-venv"
        echo
        exit 1
    fi
fi

# shellcheck disable=SC1091
source .venv/bin/activate

echo "Installazione/aggiornamento dipendenze..."
python -m pip install -q --upgrade pip
if ! python -m pip install -q -r requirements.txt; then
    echo
    echo "  Installazione dipendenze fallita: controlla la connessione e riprova."
    echo
    exit 1
fi
# `cryptography` genera il certificato TLS quando `openssl` non è nel PATH.
# Su Linux openssl c'è quasi sempre, quindi qui è solo una rete di sicurezza
# e un errore non deve fermare l'avvio.
python -m pip install -q cryptography 2>/dev/null || true

echo "Aggiornamento database vendor (OUI) dall'IEEE (facoltativo, serve internet)..."
python scripts/update_oui.py --if-missing 2>/dev/null || \
    echo "  (OUI completo non scaricato, uso la lista minima inclusa)"

# Avvertenze utili prima di partire, in modo che l'utente sappia cosa
# aspettarsi invece di scoprirlo dai risultati.
if [ "$(id -u)" -ne 0 ]; then
    echo
    echo "  Avvio senza privilegi: la configurazione di rete NON viene toccata."
    echo "  L'ARP scan a livello 2 non è disponibile, si usa lo sweep TCP +"
    echo "  tabella ARP di sistema. Per lo scan completo:"
    echo "    sudo -E RASPISCANNER_NO_NETWORK_CONFIG=1 ./start.sh"
elif [ "${RASPISCANNER_NO_NETWORK_CONFIG:-}" = "" ]; then
    echo
    echo "  ATTENZIONE: avviato da root SENZA RASPISCANNER_NO_NETWORK_CONFIG=1."
    echo "  In questa modalità lo scanner può RICONFIGURARE la scheda ethernet"
    echo "  (DHCP, poi indirizzi statici di fallback): è il comportamento"
    echo "  voluto su un Raspberry Pi dedicato, non su un portatile di lavoro."
    echo "  Ctrl-C entro 5 secondi per annullare."
    sleep 5
fi

echo
echo "RaspiScanner in avvio su ${URL}"
echo "(certificato self-signed: il browser mostra un avviso da accettare una volta)"
echo "Ctrl-C per fermarlo."
echo

# Apre il browser solo se c'è una sessione grafica: su un Pi headless o via
# SSH non c'è nulla da aprire, e l'URL stampato sopra è già l'istruzione.
if [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] && command -v xdg-open >/dev/null 2>&1; then
    (sleep 2 && xdg-open "$URL" >/dev/null 2>&1) &
fi

exec python raspi-scanner.py --port "$PORT"
