#!/usr/bin/env python3
"""RaspiScanner - dashboard di rete per Raspberry Pi.

Auto-configura l'interfaccia ethernet (DHCP, con fallback su classi
private preimpostate) e offre una dashboard web per scansionare i
dispositivi sulle reti eth/wifi attive, con una vista dedicata alle sole
telecamere IP/NVR/DVR trovate.

Avvio:
    sudo python3 app.py
"""
import csv
import io
import json
import logging
import threading

from flask import Flask, Response, jsonify, render_template, request

from scanner import network_setup, scan_engine

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
    return jsonify(network_setup.wifi_scan_networks())


@app.route("/api/wifi/connect", methods=["POST"])
def api_wifi_connect():
    data = request.get_json(silent=True) or {}
    ssid = data.get("ssid")
    password = data.get("password")
    if not ssid:
        return jsonify({"error": "ssid obbligatorio"}), 400
    ok, message = network_setup.wifi_connect(ssid, password)
    return jsonify({"ok": ok, "message": message}), (200 if ok else 502)


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


@app.route("/api/export")
def api_export():
    kind = request.args.get("type", "all")
    fmt = request.args.get("format", "json")
    devices = scan_engine.devices_cameras() if kind == "cameras" else scan_engine.devices_all()

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["ip", "mac", "vendor", "hostname", "device_type", "open_ports", "rtsp_url", "admin_url"])
        for d in devices:
            ports = ";".join(f"{p['port']}/{p['service']}" for p in d.get("open_ports", []))
            writer.writerow([
                d.get("ip"), d.get("mac"), d.get("vendor"), d.get("hostname") or "",
                d.get("device_type"), ports, d.get("rtsp_url") or "", d.get("admin_url") or "",
            ])
        return Response(
            buf.getvalue(), mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename=raspiscanner_{kind}.csv"},
        )

    return Response(
        json.dumps(devices, indent=2, ensure_ascii=False), mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=raspiscanner_{kind}.json"},
    )


if __name__ == "__main__":
    _ensure_startup()
    app.run(host="0.0.0.0", port=7332, debug=False, threaded=True)
