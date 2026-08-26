#!/usr/bin/env bash
# Installs RaspiScanner into /opt/raspiscanner and registers it as a systemd service.
# Run with sudo on the Raspberry Pi, from the project directory.
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR="/opt/raspiscanner"

if [ "$EUID" -ne 0 ]; then
  echo "Run with sudo: sudo ./install.sh" >&2
  exit 1
fi

echo "==> System packages (python3-venv, dhclient, arp-scan tools, nmcli optional)"
apt-get update -y
apt-get install -y python3-venv python3-pip isc-dhcp-client iproute2 network-manager openssl || true

echo "==> Copying sources to $DEST_DIR"
mkdir -p "$DEST_DIR"
rsync -a --delete \
  --exclude "venv" \
  --exclude "__pycache__" \
  "$SRC_DIR"/ "$DEST_DIR"/

echo "==> Creating virtualenv and installing Python dependencies"
python3 -m venv "$DEST_DIR/venv"
"$DEST_DIR/venv/bin/pip" install --upgrade pip
"$DEST_DIR/venv/bin/pip" install -r "$DEST_DIR/requirements.txt"

echo "==> Updating the vendor (OUI) database from the IEEE registry (needs internet)"
echo "    The repo only ships a minimal version (~100 entries): this is a good"
echo "    time to fetch the full one (~35,000), usually the only point the"
echo "    device is still online before being taken to the field. No network?"
echo "    The minimal database stays in place, that's fine — it's not required"
echo "    for the scan itself."
"$DEST_DIR/venv/bin/python3" "$DEST_DIR/scripts/update_oui.py" || \
  echo "    Download failed (no connection?): keeping the minimal database from the repo."

echo "==> Installing the systemd service"
cp "$DEST_DIR/raspiscanner.service" /etc/systemd/system/raspiscanner.service
systemctl daemon-reload
systemctl enable raspiscanner.service
systemctl restart raspiscanner.service

echo ""
echo "==> Checking service status and looking for first-login credentials..."
sleep 3
BOOTSTRAP_LINE="$(journalctl -u raspiscanner.service --no-pager 2>/dev/null | grep -i "utente di bootstrap creato" | tail -1 || true)"

echo ""
echo "✅ Installed. Service: systemctl status raspiscanner"
echo "   Dashboard: https://<raspberry-ip>:7332 (self-signed certificate,"
echo "   the browser will show a warning to accept on first visit)"
echo ""
if [ -n "$BOOTSTRAP_LINE" ]; then
  BOOTSTRAP_USER="$(echo "$BOOTSTRAP_LINE" | grep -oP '(?<=utente: )\S+')"
  BOOTSTRAP_PASS="$(echo "$BOOTSTRAP_LINE" | grep -oP '(?<=password iniziale: )\S+')"
  echo "🔑 FIRST LOGIN — shown only once, copy it now:"
  echo "   Username: ${BOOTSTRAP_USER:-RaspiScanner}"
  echo "   Password: ${BOOTSTRAP_PASS:-<see: sudo journalctl -u raspiscanner | grep -i bootstrap>}"
  echo "   You will be required to change it on first login (Settings tab)."
else
  echo "ℹ️  No new bootstrap account was created (data/users.json already existed"
  echo "   from a previous install). If you don't have credentials for it, reset"
  echo "   with: sudo rm /opt/raspiscanner/data/users.json && sudo systemctl restart raspiscanner"
  echo "   then: sudo journalctl -u raspiscanner --no-pager | grep -i bootstrap"
fi
echo ""
echo "NOTE: if NetworkManager or dhcpcd already manage eth0, mark it as"
echo "'unmanaged' to avoid conflicts with the scanner's autoconfiguration"
echo "(see README.md, 'Conflicts with NetworkManager/dhcpcd')."
