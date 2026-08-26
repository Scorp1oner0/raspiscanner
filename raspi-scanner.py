#!/usr/bin/env python3
"""RaspiScanner - network + IP camera/NVR scanner for Raspberry Pi.

Auto-configures the ethernet interface (DHCP, with fallback to preset
private classes) and offers two modes of use:

- **Web dashboard** (default): interactive scan of devices/cameras on the
  active eth/wifi networks, with CSV/JSON export.
      sudo python3 raspi-scanner.py

- **Command-line report**: runs a full scan and prints a "NETWORK
  ASSESSMENT" text report (devices, cameras, NVRs, network gear, security
  findings, risk summary), then exits.
      sudo python3 raspi-scanner.py --report
"""
import argparse
import csv
import io
import json
import logging
import sys
import threading
import time

from flask import Flask, Response, jsonify, render_template, request

from scanner import auth, scan_engine, tls
from scanner.network import hotspot
from scanner.network import setup as network_setup
from scanner.reporting import assessment
from scanner.reporting import risk as risk_module
from scanner.reporting import security as security_module

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("raspiscanner.app")

app = Flask(__name__)
auth.ensure_default_user()

_startup_lock = threading.Lock()
_started = False


@app.before_request
def _require_auth():
    creds = request.authorization
    if not creds or not auth.verify(creds.username, creds.password):
        return Response(
            "Accesso non autorizzato.", 401,
            {"WWW-Authenticate": 'Basic realm="RaspiScanner"'},
        )


def _ensure_startup():
    global _started
    with _startup_lock:
        if _started:
            return
        _started = True
        network_setup.start_monitor()
        log.info("monitor rete avviato")


@app.route("/")
def index():
    _ensure_startup()
    return render_template("index.html")


@app.route("/api/network")
def api_network():
    return jsonify(network_setup.get_status())


@app.route("/api/network/rescan", methods=["POST"])
def api_network_rescan():
    data = request.get_json(silent=True) or {}
    force = bool(data.get("force"))

    def _do():
        network_setup.autoconfigure_ethernet(force=force)
        network_setup.refresh_wifi_status()
    threading.Thread(target=_do, daemon=True).start()
    return jsonify({"status": "started", "force": force})


@app.route("/api/network/choose", methods=["POST"])
def api_network_choose():
    data = request.get_json(silent=True) or {}
    cidr = data.get("cidr")
    if not cidr:
        return jsonify({"ok": False, "message": "cidr is required"}), 400
    iface = data.get("iface") or network_setup.get_status()["eth"].get("iface") or network_setup.find_default_eth_iface()
    if not iface:
        return jsonify({"ok": False, "message": "No ethernet interface found"}), 400
    ok, message = network_setup.choose_preset_class(iface, cidr)
    return jsonify({"ok": ok, "message": message}), (200 if ok else 400)


@app.route("/api/wifi/networks")
def api_wifi_networks():
    iface = request.args.get("iface") or None
    return jsonify(network_setup.wifi_scan_networks(iface=iface))


@app.route("/api/wifi/connect", methods=["POST"])
def api_wifi_connect():
    data = request.get_json(silent=True) or {}
    ssid = data.get("ssid")
    password = data.get("password")
    iface = data.get("iface") or None
    if not ssid:
        return jsonify({"error": "ssid is required"}), 400
    ok, message = network_setup.wifi_connect(ssid, password, iface=iface)
    return jsonify({"ok": ok, "message": message}), (200 if ok else 502)


@app.route("/api/wifi/interfaces")
def api_wifi_interfaces():
    return jsonify(network_setup.list_wifi_ifaces())


@app.route("/api/hotspot/status")
def api_hotspot_status():
    status = hotspot.get_hotspot_status()
    wifi_iface = request.args.get("iface") or network_setup.find_default_wifi_iface() or "wlan0"
    status["default_ssid"] = hotspot.default_ssid(iface=wifi_iface)
    return jsonify(status)


@app.route("/api/hotspot/generate-password")
def api_hotspot_generate_password():
    return jsonify({"password": hotspot.generate_password()})


@app.route("/api/hotspot/start", methods=["POST"])
def api_hotspot_start():
    data = request.get_json(silent=True) or {}
    ssid = data.get("ssid") or ""
    password = data.get("password") or ""
    iface = data.get("iface") or network_setup.find_default_wifi_iface()
    if not iface:
        return jsonify({"ok": False, "message": "No Wi-Fi interface found"}), 400
    ok, message = hotspot.start_hotspot(iface, ssid, password)
    return jsonify({"ok": ok, "message": message}), (200 if ok else 400)


@app.route("/api/hotspot/stop", methods=["POST"])
def api_hotspot_stop():
    ok, message = hotspot.stop_hotspot()
    return jsonify({"ok": ok, "message": message}), (200 if ok else 400)


@app.route("/api/scan/start", methods=["POST"])
def api_scan_start():
    ok, message = scan_engine.run_scan()
    return jsonify({"ok": ok, "message": message}), (200 if ok else 409)


@app.route("/api/scan/stop", methods=["POST"])
def api_scan_stop():
    scan_engine.stop_scan()
    return jsonify({"ok": True})


@app.route("/api/scan/status")
def api_scan_status():
    return jsonify(scan_engine.get_state())


@app.route("/api/devices")
def api_devices():
    return jsonify(scan_engine.devices_all())


@app.route("/api/devices/cameras")
def api_devices_cameras():
    return jsonify(scan_engine.devices_cameras())


@app.route("/api/security/summary")
def api_security_summary():
    """Riepilogo compatto per la barra KPI della dashboard: riusa la stessa
    logica del report testuale (security.find_security_issues + risk.summarize)
    invece di ricalcolare severita' lato client."""
    devices = scan_engine.devices_all()
    all_findings = []
    for d in devices:
        all_findings.extend(security_module.find_security_issues(d))
    return jsonify(risk_module.summarize(all_findings))


@app.route("/api/report")
def api_report():
    state = scan_engine.get_state()
    text = assessment.generate_all(state["devices"])
    if state["running"]:
        # Lo scan processa le reti una alla volta e, dentro ciascuna, un
        # host alla volta: un report generato a meta' scan e' un'istantanea
        # reale ma incompleta (es. una rete gia' scansionata per intero,
        # un'altra ancora a meta'), non un errore di conteggio.
        text = (
            "⚠ Scan still in progress: this report is a partial snapshot "
            "(some networks may already be complete, others not yet) — "
            "counts will increase. Retry once the scan has finished.\n\n" + text
        )
    return jsonify({"text": text, "scan_running": state["running"]})


@app.route("/api/export")
def api_export():
    kind = request.args.get("type", "all")
    fmt = request.args.get("format", "json")
    devices = scan_engine.devices_cameras() if kind == "cameras" else scan_engine.devices_all()

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "ip", "mac", "vendor", "model", "hostname", "device_type",
            "open_ports", "rtsp_url", "admin_url",
        ])
        for d in devices:
            ports = ";".join(f"{p['port']}/{p['service']}" for p in d.get("open_ports", []))
            writer.writerow([
                d.get("ip"), d.get("mac"), d.get("vendor"), d.get("model") or "",
                d.get("hostname") or "", d.get("device_type"), ports,
                d.get("rtsp_url") or "", d.get("admin_url") or "",
            ])
        return Response(
            buf.getvalue(), mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename=raspiscanner_{kind}.csv"},
        )

    return Response(
        json.dumps(devices, indent=2, ensure_ascii=False), mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=raspiscanner_{kind}.json"},
    )


@app.route("/api/settings/users")
def api_settings_users():
    return jsonify({"users": auth.list_usernames()})


@app.route("/api/settings/users", methods=["POST"])
def api_settings_add_user():
    data = request.get_json(silent=True) or {}
    ok, message = auth.add_user(data.get("username"), data.get("password"))
    return jsonify({"ok": ok, "message": message}), (200 if ok else 400)


@app.route("/api/settings/users/password", methods=["POST"])
def api_settings_change_password():
    data = request.get_json(silent=True) or {}
    ok, message = auth.set_password(data.get("username"), data.get("password"))
    return jsonify({"ok": ok, "message": message}), (200 if ok else 400)


@app.route("/api/settings/users/<username>", methods=["DELETE"])
def api_settings_delete_user(username):
    ok, message = auth.remove_user(username)
    return jsonify({"ok": ok, "message": message}), (200 if ok else 400)


def run_dashboard(port=7332):
    _ensure_startup()
    cert_path, key_path = tls.ensure_cert()
    if cert_path:
        log.info("TLS attivo (certificato self-signed): il browser mostrera' "
                  "un avviso da accettare la prima volta, e' atteso.")
        ssl_context = (cert_path, key_path)
    else:
        log.warning("TLS non disponibile (openssl assente?): la dashboard "
                    "restera' su HTTP semplice")
        ssl_context = None
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True, ssl_context=ssl_context)


def run_cli_report(timeout=180):
    """Esegue uno scan completo e stampa il report testuale, poi esce.
    Non avvia il server Flask."""
    network_setup.start_monitor()
    time.sleep(2)  # tempo minimo perche' il monitor rilevi lo stato di eth/wifi

    ok, message = scan_engine.run_scan()
    if not ok:
        print(f"Could not start the scan: {message}", file=sys.stderr)
        return 1

    print("Scanning...", file=sys.stderr)
    deadline = time.time() + timeout
    while time.time() < deadline:
        state = scan_engine.get_state()
        if not state["running"]:
            break
        time.sleep(1)
    else:
        print("Timeout reached, printing partial results.", file=sys.stderr)
        scan_engine.stop_scan()

    print(assessment.generate_all(scan_engine.devices_all()))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--report", action="store_true", help="run a scan and print the text report, without starting the dashboard")
    parser.add_argument("--port", type=int, default=7332, help="web dashboard port (default 7332)")
    parser.add_argument("--timeout", type=int, default=180, help="timeout in seconds for --report (default 180)")
    args = parser.parse_args()

    if args.report:
        sys.exit(run_cli_report(timeout=args.timeout))
    else:
        run_dashboard(port=args.port)


if __name__ == "__main__":
    main()
