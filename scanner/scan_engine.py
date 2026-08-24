"""Orchestrazione dello scan completo: discovery ARP su tutte le subnet
attive (eth + wifi), probe ONVIF, port scan e classificazione (camera,
NVR/DVR, apparato di rete) per host. Mantiene uno stato condiviso in
memoria che la dashboard interroga via polling HTTP (niente websocket/CDN
esterni: deve funzionare anche su reti isolate senza accesso a internet).
"""
import logging
import threading
import time

from . import vendor
from .cameras.classify import classify_camera, guess_admin_url, guess_rtsp_url
from .cameras.onvif import get_device_info, onvif_probe
from .discovery import arp_scan, resolve_hostname
from .fingerprint import grab_http_banner, scan_ports
from .hosts import classify_host
from .network import setup as network_setup
from .network.infra import classify_network_device, get_default_gateway
from .nvr.classify import classify_nvr

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
    """Ritorna [(iface, cidr, local_ip), ...], uno per OGNI indirizzo IPv4
    attivo su eth e wifi (un'interfaccia puo' averne piu' di uno, es. IP
    secondari configurati a mano per raggiungere piu' subnet sullo stesso
    cavo: vanno scansionate tutte, non solo la prima)."""
    status = network_setup.get_status()
    nets = []
    for key in ("eth", "wifi"):
        info = status.get(key, {})
        if not info.get("up"):
            continue
        for addr in info.get("addresses") or []:
            if addr.get("ip") and addr.get("cidr"):
                nets.append((info["iface"], addr["cidr"], addr["ip"]))
    return nets


def _scan_host(ip, mac, onvif_results, gateway_ip):
    open_ports = scan_ports(ip)
    banners = {}
    for p in open_ports:
        if p["port"] in (80, 81, 8000, 8080, 8081, 8899, 9000):
            banners[p["port"]] = grab_http_banner(ip, p["port"])
        elif p["port"] in (443, 8443):
            banners[p["port"]] = grab_http_banner(ip, p["port"], use_https=True)

    onvif_info = onvif_results.get(ip)
    device_vendor = vendor.lookup_vendor(mac) if mac else "Sconosciuto"

    is_camera, camera_reasons = classify_camera(open_ports, banners, onvif_info)
    is_nvr, nvr_reasons = classify_nvr(banners)
    is_infra, infra_subtype, infra_reasons = classify_network_device(ip, gateway_ip, device_vendor, banners)
    host_label, host_reasons = classify_host(device_vendor, open_ports)

    # Se il dispositivo risponde a ONVIF, prova a interrogare
    # GetDeviceInformation per un vendor/model REALI invece di indovinarli
    # dal banner: non sempre riesce (spesso richiede autenticazione), in
    # quel caso restano i valori da OUI/banner.
    model = None
    if onvif_info and onvif_info.get("xaddrs"):
        info = get_device_info(onvif_info["xaddrs"][0])
        if info.get("model"):
            model = info["model"]
        if info.get("manufacturer"):
            device_vendor = info["manufacturer"]

    # Priorita': NVR e camera sono le classificazioni piu' specifiche e
    # affidabili (segnali di protocollo dedicati). Poi l'apparato di rete
    # (Router/Switch/Access Point, o generico se solo il vendor lo
    # suggerisce). Poi l'hardware riconosciuto dal vendor o dalle porte
    # tipiche (Raspberry Pi, PC, stampante). Altrimenti resta "Generico":
    # un dispositivo senza nessuno di questi segnali (comune su telefoni e
    # PC moderni con firewall di default) non e' identificabile oltre
    # questo con uno scan passivo.
    if is_nvr:
        device_type = "NVR/DVR"
    elif is_camera:
        device_type = "Telecamera"
    elif is_infra:
        device_type = infra_subtype or "Apparato di rete"
    elif host_label:
        device_type = host_label
    else:
        device_type = "Generico"

    return {
        "ip": ip,
        "mac": mac,
        "vendor": device_vendor,
        "model": model,
        "hostname": resolve_hostname(ip),
        "open_ports": open_ports,
        "http_banners": banners,
        "onvif": onvif_info,
        "is_camera": is_camera or is_nvr,
        "is_nvr": is_nvr,
        "is_network_infra": is_infra,
        "device_type": device_type,
        "camera_reasons": camera_reasons + nvr_reasons + infra_reasons + host_reasons,
        "rtsp_url": guess_rtsp_url(ip, open_ports),
        "admin_url": guess_admin_url(ip, open_ports),
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
        all_hosts = []  # (ip, mac, iface, cidr)
        onvif_results = {}
        gateways = {}
        for iface, cidr, iface_ip in networks:
            if _stop_flag.is_set():
                break
            log.info("discovery ARP su %s (%s)", cidr, iface)
            hosts = arp_scan(cidr, iface, psrc=iface_ip)
            seen_ips = set()
            for h in hosts:
                all_hosts.append((h["ip"], h["mac"], iface, cidr))
                seen_ips.add(h["ip"])
            if iface_ip not in seen_ips:
                # Un host non riceve mai la propria richiesta ARP broadcast
                # di ritorno: senza questo, la macchina su cui gira lo
                # scanner non comparirebbe mai da sola nei risultati.
                all_hosts.append((iface_ip, network_setup.get_interface_mac(iface), iface, cidr))
            onvif_results.update(onvif_probe(iface_ip=iface_ip, timeout=3))
            if iface not in gateways:
                gateways[iface] = get_default_gateway(iface)

        total = len(all_hosts)
        _update(total=total)

        for idx, (ip, mac, iface, cidr) in enumerate(all_hosts):
            if _stop_flag.is_set():
                break
            _update(progress=idx, current_ip=ip)
            device = _scan_host(ip, mac, onvif_results, gateways.get(iface))
            device["iface"] = iface
            device["network"] = cidr
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
