"""Orchestrazione dello scan completo: discovery ARP su tutte le subnet
attive (eth + wifi), probe ONVIF, port scan e classificazione per host.
Mantiene uno stato condiviso in memoria che la dashboard interroga via
polling HTTP (niente websocket/CDN esterni: deve funzionare anche su reti
isolate senza accesso a internet).
"""
import logging
import threading
import time

from . import camera_id, config, network_setup, portscan, vendor
from .discovery import arp_scan, resolve_hostname
from .onvif_discovery import onvif_probe

log = logging.getLogger("raspiscanner.scan_engine")

_lock = threading.Lock()
_state = {
    "running": False,
    "progress": 0,
    "total": 0,
    "current_ip": None,
    "started_at": None,
    "finished_at": None,
    "error": None,
    "devices": {},  # ip -> dettagli
}
_stop_flag = threading.Event()


def get_state():
    with _lock:
        snap = dict(_state)
        snap["devices"] = list(_state["devices"].values())
        return snap


def _update(**kwargs):
    with _lock:
        _state.update(kwargs)


def _set_device(ip, device):
    with _lock:
        _state["devices"][ip] = device


def _active_networks():
    """Ritorna [(iface, cidr, local_ip), ...] per eth e wifi attivi."""
    status = network_setup.get_status()
    nets = []
    for key in ("eth", "wifi"):
        info = status.get(key, {})
        if info.get("up") and info.get("ip") and info.get("cidr"):
            nets.append((info["iface"], info["cidr"], info["ip"]))
    return nets


def _scan_host(ip, mac, iface_ip, onvif_results):
    open_ports = portscan.scan_ports(ip)
    banners = {}
    for p in open_ports:
        if p["port"] in (80, 81, 8000, 8080, 8081, 9000):
            banners[p["port"]] = portscan.grab_http_banner(ip, p["port"])
        elif p["port"] in (443, 8443):
            banners[p["port"]] = portscan.grab_http_banner(ip, p["port"], use_https=True)

    onvif_info = onvif_results.get(ip)
    is_camera, device_type, reasons = camera_id.classify_device(open_ports, banners, onvif_info)

    return {
        "ip": ip,
        "mac": mac,
        "vendor": vendor.lookup_vendor(mac) if mac else "Sconosciuto",
        "hostname": resolve_hostname(ip),
        "open_ports": open_ports,
        "http_banners": banners,
        "onvif": onvif_info,
        "is_camera": is_camera,
        "device_type": device_type,
        "camera_reasons": reasons,
        "rtsp_url": camera_id.guess_rtsp_url(ip, open_ports),
        "admin_url": camera_id.guess_admin_url(ip, open_ports),
    }


def run_scan():
    if _state["running"]:
        return False, "Scansione gia' in corso"

    networks = _active_networks()
    if not networks:
        return False, "Nessuna rete attiva (eth/wifi) su cui scansionare"

    _stop_flag.clear()
    _update(running=True, progress=0, total=0, current_ip=None,
             started_at=time.time(), finished_at=None, error=None, devices={})

    t = threading.Thread(target=_run_scan_thread, args=(networks,), daemon=True)
    t.start()
    return True, "Scansione avviata"


def _run_scan_thread(networks):
    try:
        all_hosts = []  # (ip, mac, iface, iface_ip)
        onvif_results = {}
        for iface, cidr, iface_ip in networks:
            if _stop_flag.is_set():
                break
            log.info("discovery ARP su %s (%s)", cidr, iface)
            hosts = arp_scan(cidr, iface, psrc=iface_ip)
            for h in hosts:
                all_hosts.append((h["ip"], h["mac"], iface, iface_ip))
            onvif_results.update(onvif_probe(iface_ip=iface_ip, timeout=3))

        total = len(all_hosts)
        _update(total=total)

        for idx, (ip, mac, iface, iface_ip) in enumerate(all_hosts):
            if _stop_flag.is_set():
                break
            _update(progress=idx, current_ip=ip)
            device = _scan_host(ip, mac, iface_ip, onvif_results)
            device["iface"] = iface
            _set_device(ip, device)

        _update(progress=total, current_ip=None)
    except Exception as exc:  # non deve mai morire silenziosamente in un thread
        log.exception("errore durante lo scan")
        _update(error=str(exc))
    finally:
        _update(running=False, finished_at=time.time())


def stop_scan():
    _stop_flag.set()


def devices_all():
    with _lock:
        return list(_state["devices"].values())


def devices_cameras():
    return [d for d in devices_all() if d.get("is_camera")]
