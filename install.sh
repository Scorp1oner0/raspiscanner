#!/usr/bin/env bash
# Installa RaspiScanner in /opt/raspiscanner e lo registra come servizio systemd.
# Da lanciare con sudo sul Raspberry Pi, dalla cartella del progetto.
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR="/opt/raspiscanner"

if [ "$EUID" -ne 0 ]; then
  echo "Lanciare con sudo: sudo ./install.sh" >&2
  exit 1
fi

echo "==> Pacchetti di sistema (python3-venv, dhclient, arp-scan tools, nmcli opzionale)"
apt-get update -y
apt-get install -y python3-venv python3-pip isc-dhcp-client iproute2 network-manager openssl || true

echo "==> Copio i sorgenti in $DEST_DIR"
mkdir -p "$DEST_DIR"
rsync -a --delete \
  --exclude "venv" \
  --exclude "__pycache__" \
  "$SRC_DIR"/ "$DEST_DIR"/

echo "==> Creo virtualenv e installo le dipendenze Python"
python3 -m venv "$DEST_DIR/venv"
"$DEST_DIR/venv/bin/pip" install --upgrade pip
"$DEST_DIR/venv/bin/pip" install -r "$DEST_DIR/requirements.txt"

echo "==> Aggiorno il database vendor (OUI) dal registro IEEE (richiede internet)"
echo "    Il repo include solo una versione minimale (~100 voci): questo e' il"
echo "    momento buono per scaricare quella completa (~35.000), di solito"
echo "    l'unico in cui il dispositivo e' ancora connesso a internet prima di"
echo "    essere portato sul campo. Se non c'e' rete, resta quella minimale:"
echo "    va bene lo stesso, non e' richiesta per il funzionamento dello scan."
"$DEST_DIR/venv/bin/python3" "$DEST_DIR/scripts/update_oui.py" || \
  echo "    Download fallito (nessuna connessione?): resta il database minimale incluso nel repo."

echo "==> Installo il servizio systemd"
cp "$DEST_DIR/raspiscanner.service" /etc/systemd/system/raspiscanner.service
systemctl daemon-reload
systemctl enable raspiscanner.service
systemctl restart raspiscanner.service

echo ""
echo "✅ Installato. Servizio: systemctl status raspiscanner"
echo "   Dashboard: https://<ip-del-raspberry>:7332 (certificato self-signed,"
echo "   il browser mostrera' un avviso da accettare la prima volta)"
echo ""
echo "NOTA: se NetworkManager o dhcpcd gestiscono gia' eth0, marcala come"
echo "'unmanaged' per evitare conflitti con l'autoconfigurazione dello scanner"
echo "(vedi README.md, sezione 'Conflitti con NetworkManager/dhcpcd')."
