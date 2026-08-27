#!/usr/bin/env bash
# Uninstalls RaspiScanner: stops and disables the systemd service, removes
# the unit file, and removes /opt/raspiscanner. Run with sudo.
#
# By default this deletes EVERYTHING, including dashboard users, the TLS
# certificate, and the scanned-device history under data/ — this is a
# destructive operation. Pass --keep-data to preserve that directory
# instead (useful before reinstalling a newer version).
set -euo pipefail

DEST_DIR="/opt/raspiscanner"

if [ "$EUID" -ne 0 ]; then
  echo "Run with sudo: sudo ./uninstall.sh [--keep-data]" >&2
  exit 1
fi

KEEP_DATA=false
if [ "${1:-}" = "--keep-data" ]; then
  KEEP_DATA=true
fi

echo "==> Stopping and disabling the service"
systemctl stop raspiscanner.service 2>/dev/null || true
systemctl disable raspiscanner.service 2>/dev/null || true
rm -f /etc/systemd/system/raspiscanner.service
systemctl daemon-reload

if [ ! -d "$DEST_DIR" ]; then
  echo "==> $DEST_DIR not found, nothing to remove there"
elif [ "$KEEP_DATA" = true ] && [ -d "$DEST_DIR/data" ]; then
  echo "==> Removing $DEST_DIR, keeping data/ (users, TLS certificate, vendor database) as requested"
  TMP_DATA="$(mktemp -d)/data"
  mv "$DEST_DIR/data" "$TMP_DATA"
  rm -rf "$DEST_DIR"
  mkdir -p "$DEST_DIR"
  mv "$TMP_DATA" "$DEST_DIR/data"
  echo "    Preserved at $DEST_DIR/data — a future install.sh run will reuse it."
else
  echo "==> Removing $DEST_DIR"
  rm -rf "$DEST_DIR"
fi

echo ""
echo "✅ Uninstalled."
if [ "$KEEP_DATA" = false ]; then
  echo "   All scan data, dashboard users, and the TLS certificate were removed."
  echo "   Run with --keep-data next time to preserve them instead."
fi
