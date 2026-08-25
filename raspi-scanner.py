#!/usr/bin/env python3
"""RaspiScanner - network + IP camera/NVR scanner per Raspberry Pi.

Auto-configura l'interfaccia ethernet (DHCP, con fallback su classi
private preimpostate) e offre due modalita' d'uso:

- **Dashboard web** (default): scan interattivo di dispositivi/telecamere
  sulle reti eth/wifi attive, con esportazione CSV/JSON.
      sudo python3 raspi-scanner.py

- **Report da riga di comando**: esegue uno scan completo e stampa un
  report testuale "NETWORK ASSESSMENT" (dispositivi, telecamere, NVR,
  apparati di rete, security findings, riepilogo rischio), poi esce.
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

from scanner import scan_engine
from scanner.network import hotspot
from scanner.network import setup as network_setup
from scanner.reporting import assessment

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("raspiscanner.app")

app = Flask(__name__)

_startup_lock = threading.Lock()
_started = False


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
    return jsonify({"status": "avviato", "force": force})


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
        return jsonify({"error": "ssid obbligatorio"}), 400
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
        return jsonify({"ok": False, "message": "Nessuna interfaccia Wi-Fi trovata"}), 400
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
            "⚠ Scansione ancora in corso: questo report e' un'istantanea "
            "parziale (alcune reti possono essere gia' complete, altre no "
            "ancora), i conteggi aumenteranno. Riprova dopo che lo scan e' "
            "terminato.\n\n" + text
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


def run_dashboard(port=7332):
    _ensure_startup()
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)


def run_cli_report(timeout=180):
    """Esegue uno scan completo e stampa il report testuale, poi esce.
    Non avvia il server Flask."""
    network_setup.start_monitor()
    time.sleep(2)  # tempo minimo perche' il monitor rilevi lo stato di eth/wifi

    ok, message = scan_engine.run_scan()
    if not ok:
        print(f"Impossibile avviare lo scan: {message}", file=sys.stderr)
        return 1

    print("Scan in corso...", file=sys.stderr)
    deadline = time.time() + timeout
    while time.time() < deadline:
        state = scan_engine.get_state()
        if not state["running"]:
            break
        time.sleep(1)
    else:
        print("Timeout raggiunto, stampo i risultati parziali.", file=sys.stderr)
        scan_engine.stop_scan()

    print(assessment.generate_all(scan_engine.devices_all()))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--report", action="store_true", help="esegue uno scan e stampa il report testuale, senza avviare la dashboard")
    parser.add_argument("--port", type=int, default=7332, help="porta della dashboard web (default 7332)")
    parser.add_argument("--timeout", type=int, default=180, help="timeout in secondi per --report (default 180)")
    args = parser.parse_args()

    if args.report:
        sys.exit(run_cli_report(timeout=args.timeout))
    else:
        run_dashboard(port=args.port)


if __name__ == "__main__":
    main()
