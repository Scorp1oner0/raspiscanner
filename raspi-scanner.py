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
from functools import wraps

from flask import Flask, Response, jsonify, render_template, request

from scanner import auth, monitoring, scan_engine, storage, tls, webhooks
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


# Con must_change_password attivo per l'utente autenticato, SOLO questi
# endpoint restano raggiungibili: il minimo indispensabile per mostrare e
# completare la schermata di cambio password forzato (P0: l'utente di
# bootstrap ha una password casuale generata al primo avvio, vedi
# scanner.auth — finche' non viene cambiata, nessun controllo di rete o
# scan deve essere possibile, non solo "consigliato cambiarla appena puoi").
# NON serve GET /api/settings/users qui: l'overlay di cambio forzato usa
# solo /api/settings/me (sempre raggiungibile) per sapere il proprio
# username, mai la lista completa utenti.
_PASSWORD_CHANGE_ALWAYS_ALLOWED = {
    ("GET", "/"),
    ("GET", "/api/settings/me"),
    ("POST", "/api/settings/users/password"),
}


def require_role(min_role):
    """Blocca l'endpoint con 403 se l'utente autenticato non ha almeno
    `min_role` (viewer < operator < admin, vedi scanner.auth.ROLES). Va
    applicato SOTTO @app.route (piu' vicino alla funzione), non sopra —
    ordine standard dei decorator Flask."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            creds = request.authorization
            if not creds or not auth.has_role_at_least(creds.username, min_role):
                return jsonify({
                    "error": "forbidden",
                    "message": f"Requires the '{min_role}' role or higher.",
                }), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


_MUTATING_METHODS = ("POST", "PUT", "PATCH", "DELETE")


def _origin_is_trusted():
    """True se la richiesta non ha un header Origin (molti browser non lo
    mandano per richieste dirette same-origin) o se ce l'ha e corrisponde
    esattamente a questo host.

    Serve sia da CSRF-protection sia da Origin/Host check con un solo
    meccanismo: con HTTP Basic Auth non c'e' un cookie di sessione, ma il
    browser RIATTACCA DA SOLO le credenziali gia' inserite a qualunque
    richiesta verso la stessa origin — incluso un semplice <form
    method="POST"> ospitato su un sito malevolo che punta a un endpoint
    di questa dashboard. Un token CSRF classico richiederebbe uno stato
    di sessione che qui non esiste; verificare Origin (quando presente)
    e' il controllo standard per app stateless come questa e blocca
    esattamente lo stesso attacco.
    """
    origin = request.headers.get("Origin")
    if not origin:
        return True
    return origin.rstrip("/") == request.host_url.rstrip("/")


@app.before_request
def _require_auth():
    creds = request.authorization
    if not creds or not auth.verify(creds.username, creds.password):
        return Response(
            "Accesso non autorizzato.", 401,
            {"WWW-Authenticate": 'Basic realm="RaspiScanner"'},
        )
    if request.path.startswith("/static/"):
        return
    if request.method in _MUTATING_METHODS and not _origin_is_trusted():
        return jsonify({
            "error": "forbidden_origin",
            "message": "Cross-origin request blocked.",
        }), 403
    if auth.must_change_password(creds.username) and (request.method, request.path) not in _PASSWORD_CHANGE_ALWAYS_ALLOWED:
        return jsonify({
            "error": "password_change_required",
            "message": "You must change your password before continuing.",
        }), 403


@app.route("/api/settings/me")
def api_settings_me():
    creds = request.authorization
    return jsonify({
        "username": creds.username,
        "role": auth.get_role(creds.username),
        "must_change_password": auth.must_change_password(creds.username),
    })


def _ensure_startup():
    global _started
    with _startup_lock:
        if _started:
            return
        _started = True
        network_setup.start_monitor()
        log.info("monitor rete avviato")
        monitoring.start_scheduler()


@app.route("/")
def index():
    _ensure_startup()
    return render_template("index.html")


@app.route("/api/network")
@require_role("viewer")
def api_network():
    return jsonify(network_setup.get_status())


@app.route("/api/network/rescan", methods=["POST"])
@require_role("operator")
def api_network_rescan():
    data = request.get_json(silent=True) or {}
    force = bool(data.get("force"))

    def _do():
        network_setup.autoconfigure_ethernet(force=force)
        network_setup.refresh_wifi_status()
    threading.Thread(target=_do, daemon=True).start()
    return jsonify({"status": "started", "force": force})


@app.route("/api/network/choose", methods=["POST"])
@require_role("operator")
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
@require_role("viewer")
def api_wifi_networks():
    iface = request.args.get("iface") or None
    return jsonify(network_setup.wifi_scan_networks(iface=iface))


@app.route("/api/wifi/connect", methods=["POST"])
@require_role("operator")
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
@require_role("viewer")
def api_wifi_interfaces():
    return jsonify(network_setup.list_wifi_ifaces())


@app.route("/api/hotspot/status")
@require_role("viewer")
def api_hotspot_status():
    status = hotspot.get_hotspot_status()
    wifi_iface = request.args.get("iface") or network_setup.find_default_wifi_iface() or "wlan0"
    status["default_ssid"] = hotspot.default_ssid(iface=wifi_iface)
    return jsonify(status)


@app.route("/api/hotspot/generate-password")
@require_role("operator")
def api_hotspot_generate_password():
    return jsonify({"password": hotspot.generate_password()})


@app.route("/api/hotspot/start", methods=["POST"])
@require_role("admin")
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
@require_role("admin")
def api_hotspot_stop():
    ok, message = hotspot.stop_hotspot()
    return jsonify({"ok": ok, "message": message}), (200 if ok else 400)


@app.route("/api/scan/start", methods=["POST"])
@require_role("operator")
def api_scan_start():
    ok, message = scan_engine.run_scan()
    return jsonify({"ok": ok, "message": message}), (200 if ok else 409)


@app.route("/api/scan/stop", methods=["POST"])
@require_role("operator")
def api_scan_stop():
    scan_engine.stop_scan()
    return jsonify({"ok": True})


@app.route("/api/scan/status")
@require_role("viewer")
def api_scan_status():
    return jsonify(scan_engine.get_state())


@app.route("/api/topology")
@require_role("viewer")
def api_topology():
    """P4 'network topology map': adiacenza a un salto per interfaccia
    (gateway + vicini LLDP/CDP visti), popolata dall'ultimo scan."""
    return jsonify(scan_engine.get_state()["topology"])


@app.route("/api/devices")
@require_role("viewer")
def api_devices():
    return jsonify(scan_engine.devices_all())


@app.route("/api/devices/cameras")
@require_role("viewer")
def api_devices_cameras():
    return jsonify(scan_engine.devices_cameras())


@app.route("/api/security/summary")
@require_role("viewer")
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
@require_role("viewer")
def api_report():
    state = scan_engine.get_state()
    text = assessment.generate_all(state["devices"], started_at=state["started_at"], finished_at=state["finished_at"])
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
@require_role("viewer")
def api_export():
    kind = request.args.get("type", "all")
    fmt = request.args.get("format", "json")
    state = scan_engine.get_state()
    devices = scan_engine.devices_cameras() if kind == "cameras" else state["devices"]

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

    # P4 "structured JSON export": un envelope con metadati invece di un
    # array nudo di device — un consumatore esterno (script, altro tool)
    # sa cosi' QUANDO questi dati sono stati raccolti senza doverlo dedurre
    # da un header HTTP o da un file system timestamp.
    payload = {
        "exported_at": time.time(),
        "type": kind,
        "count": len(devices),
        "scan_started_at": state["started_at"],
        "scan_finished_at": state["finished_at"],
        "devices": devices,
    }
    return Response(
        json.dumps(payload, indent=2, ensure_ascii=False), mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=raspiscanner_{kind}.json"},
    )


@app.route("/api/history/scans")
@require_role("viewer")
def api_history_scans():
    """P4 'historical dashboard': metadati (non i device) degli scan
    passati, piu' recenti prima."""
    limit = request.args.get("limit", 20, type=int)
    return jsonify({"scans": storage.list_scans(limit=limit)})


@app.route("/api/history/scans/<int:scan_id>/devices")
@require_role("viewer")
def api_history_scan_devices(scan_id):
    return jsonify({"devices": storage.get_scan_devices(scan_id)})


@app.route("/api/history/compare")
@require_role("viewer")
def api_history_compare():
    """P4 'comparative reports': confronta due scan passati per MAC.
    ?old=<scan_id>&new=<scan_id>, entrambi richiesti."""
    old_id = request.args.get("old", type=int)
    new_id = request.args.get("new", type=int)
    if not old_id or not new_id:
        return jsonify({"error": "bad_request", "message": "'old' and 'new' scan ids are required"}), 400
    return jsonify(storage.compare_scans(old_id, new_id))


@app.route("/api/history/assets")
@require_role("viewer")
def api_history_assets():
    """P4 'local asset database': ogni MAC visto almeno una volta
    attraverso scan diversi, con first_seen/last_seen."""
    limit = request.args.get("limit", 500, type=int)
    return jsonify({"assets": storage.list_assets(limit=limit)})


@app.route("/api/settings/webhook")
@require_role("admin")
def api_settings_webhook_get():
    return jsonify(webhooks.get_config())


@app.route("/api/settings/webhook", methods=["POST"])
@require_role("admin")
def api_settings_webhook_set():
    data = request.get_json(silent=True) or {}
    ok, message = webhooks.set_config(data.get("url"), bool(data.get("enabled")))
    return jsonify({"ok": ok, "message": message}), (200 if ok else 400)


@app.route("/api/settings/monitoring")
@require_role("admin")
def api_settings_monitoring_get():
    return jsonify(monitoring.get_config())


@app.route("/api/settings/monitoring", methods=["POST"])
@require_role("admin")
def api_settings_monitoring_set():
    data = request.get_json(silent=True) or {}
    interval = data.get("interval_minutes", monitoring.DEFAULT_INTERVAL_MINUTES)
    ok, message = monitoring.set_config(bool(data.get("enabled")), interval)
    return jsonify({"ok": ok, "message": message}), (200 if ok else 400)


@app.route("/api/audit/report")
@require_role("viewer")
def api_audit_report():
    """Audit mode (P4): a differenza di /api/report (stato LIVE, puo'
    essere un'istantanea parziale se uno scan e' in corso), questo genera
    un report a partire da uno scan gia' SALVATO — riproducibile in
    qualunque momento a partire dallo stesso scan_id, con la sezione
    "CHANGES SINCE PREVIOUS SCAN" calcolata automaticamente rispetto allo
    scan salvato subito prima. Senza scan_id esplicito, usa l'ultimo
    salvato."""
    scan_id = request.args.get("scan_id", type=int)
    if scan_id is None:
        latest = storage.list_scans(limit=1)
        if not latest:
            return jsonify({
                "error": "no_scans", "message": "No saved scans yet — run a scan first.",
            }), 404
        scan_id = latest[0]["id"]
    meta = storage.get_scan_meta(scan_id)
    if meta is None:
        return jsonify({"error": "not_found", "message": f"Scan #{scan_id} not found."}), 404
    devices = storage.get_scan_devices(scan_id)
    previous_id = storage.get_previous_scan_id(scan_id)
    changes = storage.compare_scans(previous_id, scan_id) if previous_id is not None else None
    text = assessment.generate_all(
        devices, started_at=meta["started_at"], finished_at=meta["finished_at"], changes=changes,
    )
    return jsonify({"text": text, "scan_id": scan_id, "compared_to_scan_id": previous_id})


@app.route("/api/settings/users")
@require_role("admin")
def api_settings_users():
    return jsonify({"users": auth.list_users()})


@app.route("/api/settings/users", methods=["POST"])
@require_role("admin")
def api_settings_add_user():
    data = request.get_json(silent=True) or {}
    role = data.get("role") or auth.DEFAULT_ROLE
    ok, message = auth.add_user(data.get("username"), data.get("password"), role=role)
    return jsonify({"ok": ok, "message": message}), (200 if ok else 400)


@app.route("/api/settings/users/password", methods=["POST"])
def api_settings_change_password():
    # Eccezione al require_role standard: ogni utente autenticato puo'
    # sempre cambiare la PROPRIA password (altrimenti un operator/viewer
    # con must_change_password attivo resterebbe bloccato per sempre, vedi
    # _PASSWORD_CHANGE_ALWAYS_ALLOWED sopra). Cambiare la password di UN
    # ALTRO utente invece richiede admin.
    data = request.get_json(silent=True) or {}
    target_username = data.get("username")
    creds = request.authorization
    is_self = creds and creds.username == target_username
    if not is_self and not auth.has_role_at_least(creds.username, "admin"):
        return jsonify({
            "error": "forbidden",
            "message": "Only admins can change another user's password.",
        }), 403
    ok, message = auth.set_password(target_username, data.get("password"))
    return jsonify({"ok": ok, "message": message}), (200 if ok else 400)


@app.route("/api/settings/users/<username>", methods=["DELETE"])
@require_role("admin")
def api_settings_delete_user(username):
    ok, message = auth.remove_user(username)
    return jsonify({"ok": ok, "message": message}), (200 if ok else 400)


def run_dashboard(port=7332):
    # Il TLS va verificato PRIMA di avviare qualunque altra cosa (monitor
    # rete, server): la dashboard espone credenziali via Basic Auth e
    # l'intero inventario dei dispositivi scansionati, quindi servirla su
    # HTTP semplice come fallback silenzioso vanificherebbe la protezione
    # — meglio non partire affatto e dirlo chiaramente, piuttosto che
    # esporre credenziali in chiaro senza che l'operatore se ne accorga.
    cert_path, key_path = tls.ensure_cert()
    if not cert_path:
        log.error(
            "Certificato TLS non disponibile (openssl assente o generazione "
            "fallita): mi rifiuto di avviare la dashboard su HTTP semplice, "
            "che manderebbe le credenziali Basic Auth in chiaro sulla rete "
            "scansionata. Installa openssl e riavvia il servizio."
        )
        print(
            "ERRORE: certificato TLS non disponibile (openssl assente o "
            "generazione fallita). La dashboard non parte su HTTP semplice: "
            "installa openssl e riavvia.",
            file=sys.stderr,
        )
        sys.exit(1)

    log.info("TLS attivo (certificato self-signed): il browser mostrera' "
              "un avviso da accettare la prima volta, e' atteso.")
    _ensure_startup()
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True, ssl_context=(cert_path, key_path))


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

    state = scan_engine.get_state()
    print(assessment.generate_all(state["devices"], started_at=state["started_at"], finished_at=state["finished_at"]))
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
