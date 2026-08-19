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
apt-get install -y python3-venv python3-pip isc-dhcp-client iproute2 network-manager || true

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

echo "==> Installo il servizio systemd"
cp "$DEST_DIR/raspiscanner.service" /etc/systemd/system/raspiscanner.service
systemctl daemon-reload
systemctl enable raspiscanner.service
systemctl restart raspiscanner.service

echo ""
echo "✅ Installato. Servizio: systemctl status raspiscanner"
echo "   Dashboard: http://<ip-del-raspberry>:7332"
echo ""
echo "NOTA: se NetworkManager o dhcpcd gestiscono gia' eth0, marcala come"
echo "'unmanaged' per evitare conflitti con l'autoconfigurazione dello scanner"
echo "(vedi README.md, sezione 'Conflitti con NetworkManager/dhcpcd')."
