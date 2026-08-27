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

apt-get update -y

echo "==> Installing required system packages"
# These are load-bearing: without them the venv can't be created (python3-venv/
# pip) or core scanning/network features silently can't work (iproute2 for
# "ip", isc-dhcp-client for DHCP, openssl for the TLS cert the dashboard
# refuses to start without). A failure here must stop the install instead of
# limping on to a service that starts but can't actually do its job.
REQUIRED_PKGS="python3-venv python3-pip isc-dhcp-client iproute2 openssl"
if ! apt-get install -y $REQUIRED_PKGS; then
  echo "ERROR: failed to install required packages ($REQUIRED_PKGS)." >&2
  echo "RaspiScanner cannot run without them — fix apt/network access and re-run install.sh." >&2
  exit 1
fi

echo "==> Installing optional system packages (Wi-Fi scan/connect/hotspot support)"
# network-manager (nmcli) is only needed for the Wi-Fi and hotspot features;
# a wired-only install works fine without it. Missing/failing here is a
# reduced-functionality warning, not a reason to abort the whole install.
apt-get install -y network-manager || \
  echo "    network-manager not installed: Wi-Fi scan/connect/hotspot will be unavailable, everything else still works."

echo "==> Copying sources to $DEST_DIR"
mkdir -p "$DEST_DIR"
# --delete removes from $DEST_DIR anything no longer present in $SRC_DIR, so
# a file removed from the repo actually disappears from the deployed copy
# too instead of lingering as a stale leftover across upgrades. The 4
# exclusions below are runtime state that only ever exists in $DEST_DIR,
# never in the source repo: without them, --delete would silently wipe out
# the current users/passwords, the TLS certificate (forcing a new
# self-signed-cert browser warning), and the full downloaded OUI database
# on every single re-run of this installer, e.g. an upgrade.
rsync -a --delete \
  --exclude "venv" \
  --exclude "__pycache__" \
  --exclude "data/users.json" \
  --exclude "data/tls_cert.pem" \
  --exclude "data/tls_key.pem" \
  --exclude "data/oui.csv" \
  --exclude "data/history.db" \
  --exclude "data/webhooks.json" \
  --exclude "data/monitoring.json" \
  "$SRC_DIR"/ "$DEST_DIR"/

# data/oui.csv is excluded above specifically so a re-install never clobbers
# a full OUI database fetched by a previous update_oui.py run with the
# minimal ~100-entry one from the repo — but that means a brand-new install
# needs it copied in explicitly this one time, otherwise there's no vendor
# database at all until update_oui.py runs below (and it does nothing on
# failure, e.g. no network — see its own code).
if [ ! -f "$DEST_DIR/data/oui.csv" ]; then
  cp "$SRC_DIR/data/oui.csv" "$DEST_DIR/data/oui.csv"
fi

# rsync -a (girando come root) sincronizza anche proprietario/permessi
# della DIRECTORY data/ da quelli del checkout sorgente — di norma
# l'utente non privilegiato che sviluppa, non root. Il servizio gira
# come root ma con CapabilityBoundingSet ristretto (niente
# CAP_DAC_OVERRIDE, vedi raspiscanner.service): se data/ risulta di
# proprieta' di un altro utente, root non puo' PIU' creare file al suo
# interno (es. data/users.json.tmp scrivendo la password), anche se i
# file gia' esistenti restano leggibili. Impostata sempre esplicitamente
# qui, invece di fidarsi di cosa rsync ha copiato dal sorgente.
chown root:root "$DEST_DIR/data"
chmod 750 "$DEST_DIR/data"

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
# Un sleep fisso qui era troppo ottimista: su una CPU debole (Raspberry Pi
# 3B+, verificato dal vivo) l'avvio di Flask/scapy/il monitor di rete puo'
# richiedere piu' di qualche secondo prima che auth.ensure_default_user()
# arrivi a loggare la riga di bootstrap — un sleep breve concludeva "nessun
# account creato" anche quando l'account stava per essere creato un attimo
# dopo. Poll fino a 15s invece di un'attesa cieca, cosi' funziona sia su
# hardware veloce (esce quasi subito) sia su hardware lento.
BOOTSTRAP_LINE=""
for _ in $(seq 1 15); do
  BOOTSTRAP_LINE="$(journalctl -u raspiscanner.service --no-pager 2>/dev/null | grep -i "utente di bootstrap creato" | tail -1 || true)"
  [ -n "$BOOTSTRAP_LINE" ] && break
  sleep 1
done

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
