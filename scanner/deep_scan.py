"""Scan approfondito delle porte di UN solo dispositivo, su richiesta.

Lo scan normale controlla un elenco fisso di porte su ogni host, che basta a
riconoscere telecamere, NVR e apparati ma non vede servizi su porte insolite
(per esempio la dashboard di RaspiScanner sulla 7332). Qui l'operatore sceglie
un dispositivo gia' trovato e un intervallo (fino a tutte le 65535 porte):
parte in background, una sola alla volta, e i risultati si aggiungono alla
riga del dispositivo.
"""
import logging
import threading
import time

from . import config, scan_engine
from .fingerprint import open_tcp_ports, web_banner

log = logging.getLogger("raspiscanner.deep_scan")

_lock = threading.Lock()
_stop_flag = threading.Event()
_state = {
    "running": False,
    "ip": None,
    "ports_spec": None,
    "ports_total": 0,
    "ports_done": 0,
    "started_at": None,
    "finished_at": None,
    "stopped": False,
    "error": None,
    "open_ports": [],
}


def parse_port_spec(spec):
    """Da "22,80,8000-8100" alla lista ordinata e senza doppioni delle porte.
    Solleva ValueError con un messaggio leggibile se qualcosa non va."""
    if not isinstance(spec, str) or not spec.strip():
        raise ValueError("Port list is empty")
    ports = set()
    for part in spec.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            first, _, last = part.partition("-")
            if not (first.isdigit() and last.isdigit()):
                raise ValueError(f"Invalid port range: {part}")
            low, high = int(first), int(last)
            if low > high:
                raise ValueError(f"Port range goes backwards: {part}")
        elif part.isdigit():
            low = high = int(part)
        else:
            raise ValueError(f"Invalid port: {part}")
        if low < 1 or high > 65535:
            raise ValueError(f"Ports must be between 1 and 65535: {part}")
        ports.update(range(low, high + 1))
    if not ports:
        raise ValueError("Port list is empty")
    return sorted(ports)


def get_state():
    with _lock:
        snap = dict(_state)
        snap["open_ports"] = list(_state["open_ports"])
        return snap


def _update(**kwargs):
    with _lock:
        _state.update(kwargs)


def start(ip, spec=None):
    """Avvia lo scan approfondito di `ip`. Ritorna (ok, messaggio, stato HTTP):
    400 per una richiesta non valida, 409 se c'e' gia' uno scan in corso."""
    spec = spec or config.DEEP_SCAN_DEFAULT_PORTS
    try:
        ports = parse_port_spec(spec)
    except ValueError as exc:
        return False, str(exc), 400
    # Solo dispositivi trovati dallo scan: niente bersagli arbitrari (stessa
    # regola delle reti custom, che devono essere private).
    if not any(d.get("ip") == ip for d in scan_engine.devices_all()):
        return False, f"{ip} is not among the devices found by the last scan", 400
    if scan_engine.get_state()["running"]:
        return False, "Wait for the network scan to finish first", 409
    with _lock:
        if _state["running"]:
            return False, f"A deep scan of {_state['ip']} is already running", 409
        _stop_flag.clear()
        _state.update(running=True, ip=ip, ports_spec=spec, ports_total=len(ports), ports_done=0,
                      started_at=time.time(), finished_at=None, stopped=False, error=None, open_ports=[])
    threading.Thread(target=_run, args=(ip, ports), daemon=True).start()
    return True, f"Deep scan of {ip} started ({len(ports)} ports)", 200


def stop():
    _stop_flag.set()


def _service_name(port):
    return config.PORTS_OF_INTEREST.get(port) or config.EXTENDED_PORTS.get(port) or "unknown"


def _run(ip, ports):
    try:
        found = open_tcp_ports(ip, ports, should_stop=_stop_flag.is_set,
                               on_progress=lambda done: _update(ports_done=done))
        results = []
        banners = {}
        for port in found:
            entry = {"port": port, "service": _service_name(port)}
            if port not in config.NON_WEB_PORTS:
                banner = web_banner(ip, port)
                if banner["server"] or banner["title"]:
                    entry["http"] = banner
                    banners[port] = banner
            results.append(entry)
        _update(open_ports=results, stopped=_stop_flag.is_set())
        scan_engine.merge_deep_scan(ip, results, banners, get_state())
    except Exception as exc:
        log.exception("deep scan of %s failed", ip)
        _update(error=str(exc))
    finally:
        _update(running=False, finished_at=time.time())
