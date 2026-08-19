"""Auto-configurazione dell'interfaccia ethernet.

Logica richiesta:
  1. Quando l'interfaccia eth ha link (cavo collegato), si prova prima il
     DHCP.
  2. Se il DHCP non risponde entro un timeout, si prova una lista di classi
     private preimpostate: per ciascuna ci si assegna un IP statico "alto"
     (difficilmente occupato) e si verifica con un probe ARP se sulla rete
     rispondono altri host. La prima classe "viva" trovata viene tenuta.
  3. Se nessuna classe risulta viva, l'interfaccia resta senza indirizzo e
     lo stato viene riportato come "nessuna rete rilevata": un nuovo giro
     viene ritentato al prossimo cambio di stato del cavo (o su richiesta
     manuale dalla dashboard).

Il modulo non assume systemd-networkd/dhcpcd/NetworkManager: usa solo i
comandi di base `ip` e `dhclient`, cosi' funziona su qualunque Raspberry Pi
OS purche' l'interfaccia non sia gestita in conflitto da un altro servizio
(vedi README per come marcarla "unmanaged" in NetworkManager/dhcpcd).
"""
import logging
import os
import subprocess
import threading
import time

from . import config
from .discovery import quick_subnet_probe

log = logging.getLogger("raspiscanner.network")

_state_lock = threading.Lock()
_status = {
    "eth": {"iface": None, "up": False, "mode": None, "ip": None, "cidr": None},
    "wifi": {"iface": None, "up": False, "ssid": None, "ip": None, "cidr": None},
}


def get_status():
    with _state_lock:
        return {"eth": dict(_status["eth"]), "wifi": dict(_status["wifi"])}


def _set_status(key, **kwargs):
    with _state_lock:
        _status[key].update(kwargs)


def list_interfaces():
    """Ritorna i nomi delle interfacce di rete presenti (esclusa lo)."""
    try:
        names = os.listdir("/sys/class/net")
    except FileNotFoundError:
        return []
    return [n for n in names if n != "lo"]


def classify_interface(name):
    if name.startswith(config.ETH_IFACE_PREFIXES):
        return "eth"
    if name.startswith(config.WIFI_IFACE_PREFIXES):
        return "wifi"
    return None


def find_default_eth_iface():
    for name in sorted(list_interfaces()):
        if classify_interface(name) == "eth":
            return name
    return None


def find_default_wifi_iface():
    for name in sorted(list_interfaces()):
        if classify_interface(name) == "wifi":
            return name
    return None


def has_carrier(iface):
    """True se il cavo e' collegato (o l'interfaccia wifi e' associata)."""
    try:
        with open(f"/sys/class/net/{iface}/carrier") as fh:
            return fh.read().strip() == "1"
    except (FileNotFoundError, OSError):
        return False


def _run(cmd, timeout=15):
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        log.warning("comando fallito %s: %s", cmd, exc)
        return None


def get_interface_ip(iface):
    """Ritorna (ip, prefix) se l'interfaccia ha un IPv4 assegnato, altrimenti None."""
    res = _run(["ip", "-4", "-o", "addr", "show", "dev", iface])
    if not res or res.returncode != 0:
        return None
    for line in res.stdout.splitlines():
        parts = line.split()
        if "inet" in parts:
            cidr = parts[parts.index("inet") + 1]  # es 192.168.1.42/24
            ip, prefix = cidr.split("/")
            return ip, int(prefix)
    return None


def flush_addresses(iface):
    _run(["ip", "addr", "flush", "dev", iface])


def set_link_up(iface):
    _run(["ip", "link", "set", "dev", iface, "up"])


def try_dhcp(iface, timeout=config.DHCP_TIMEOUT_SECONDS):
    """Tenta un lease DHCP sull'interfaccia. Ritorna True se ottenuto un IP."""
    log.info("provo DHCP su %s (timeout %ss)", iface, timeout)
    _run(["dhclient", "-r", iface], timeout=5)
    flush_addresses(iface)
    set_link_up(iface)
    res = _run(["dhclient", "-1", "-v", "-timeout", str(timeout), iface], timeout=timeout + 5)
    if res is None:
        return False
    ip_info = get_interface_ip(iface)
    if ip_info:
        log.info("DHCP riuscito su %s: %s", iface, ip_info[0])
        return True
    return False


def assign_static(iface, ip, prefix=24):
    flush_addresses(iface)
    set_link_up(iface)
    _run(["ip", "addr", "add", f"{ip}/{prefix}", "dev", iface])


def try_preset_classes(iface):
    """Prova ciascuna classe preimpostata assegnando l'IP statico e
    verificando con un probe ARP se ci sono host attivi su quella rete.
    Ritorna il preset scelto (dict) oppure None se nessuna classe risponde.
    """
    for preset in config.PRESET_SUBNETS:
        cidr = preset["cidr"]
        static_ip = preset["static_ip"]
        log.info("provo classe %s (IP candidato %s)", cidr, static_ip)
        assign_static(iface, static_ip, prefix=cidr.split("/")[1])
        alive = quick_subnet_probe(iface, cidr, timeout=config.CLASS_PROBE_TIMEOUT)
        if alive:
            log.info("classe %s attiva su %s", cidr, iface)
            return preset
        flush_addresses(iface)
    return None


def autoconfigure_ethernet(iface=None):
    """Esegue la logica DHCP -> fallback classi preimpostate su eth."""
    iface = iface or find_default_eth_iface()
    if not iface:
        log.warning("nessuna interfaccia ethernet trovata")
        return

    if not has_carrier(iface):
        _set_status("eth", iface=iface, up=False, mode=None, ip=None, cidr=None)
        return

    if try_dhcp(iface):
        ip_info = get_interface_ip(iface)
        _set_status(
            "eth", iface=iface, up=True, mode="dhcp",
            ip=ip_info[0], cidr=f"{ip_info[0].rsplit('.', 1)[0]}.0/{ip_info[1]}",
        )
        return

    log.info("DHCP non disponibile su %s, provo classi preimpostate", iface)
    preset = try_preset_classes(iface)
    if preset:
        _set_status(
            "eth", iface=iface, up=True, mode="static-fallback",
            ip=preset["static_ip"], cidr=preset["cidr"],
        )
        return

    flush_addresses(iface)
    _set_status("eth", iface=iface, up=True, mode="nessuna-rete", ip=None, cidr=None)
    log.warning("nessuna classe preimpostata ha risposto su %s", iface)


def refresh_wifi_status():
    iface = find_default_wifi_iface()
    if not iface:
        _set_status("wifi", iface=None, up=False, ssid=None, ip=None, cidr=None)
        return
    ip_info = get_interface_ip(iface)
    ssid = None
    res = _run(["iwgetid", "-r", iface], timeout=3)
    if res and res.returncode == 0:
        ssid = res.stdout.strip() or None
    if ip_info:
        _set_status(
            "wifi", iface=iface, up=True, ssid=ssid,
            ip=ip_info[0], cidr=f"{ip_info[0].rsplit('.', 1)[0]}.0/{ip_info[1]}",
        )
    else:
        _set_status("wifi", iface=iface, up=bool(ssid), ssid=ssid, ip=None, cidr=None)


def wifi_scan_networks():
    """Elenca le reti Wi-Fi visibili (best-effort, richiede nmcli)."""
    res = _run(["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY", "device", "wifi", "list"], timeout=10)
    if not res or res.returncode != 0:
        return []
    networks = []
    seen = set()
    for line in res.stdout.splitlines():
        parts = line.split(":")
        if not parts or not parts[0]:
            continue
        ssid = parts[0]
        if ssid in seen:
            continue
        seen.add(ssid)
        networks.append({
            "ssid": ssid,
            "signal": parts[1] if len(parts) > 1 else None,
            "security": parts[2] if len(parts) > 2 else "",
        })
    return networks


def wifi_connect(ssid, password=None):
    """Connette il Wi-Fi tramite nmcli, se disponibile."""
    cmd = ["nmcli", "device", "wifi", "connect", ssid]
    if password:
        cmd += ["password", password]
    res = _run(cmd, timeout=25)
    ok = bool(res and res.returncode == 0)
    if ok:
        refresh_wifi_status()
    return ok, (res.stdout + res.stderr) if res else "nmcli non disponibile"


def _monitor_loop(stop_event):
    eth_iface = find_default_eth_iface()
    last_carrier = None
    while not stop_event.is_set():
        if eth_iface:
            carrier = has_carrier(eth_iface)
            if carrier and not last_carrier:
                log.info("cavo eth collegato su %s, avvio autoconfig", eth_iface)
                autoconfigure_ethernet(eth_iface)
            elif not carrier and last_carrier:
                log.info("cavo eth scollegato da %s", eth_iface)
                _set_status("eth", iface=eth_iface, up=False, mode=None, ip=None, cidr=None)
            last_carrier = carrier
        else:
            eth_iface = find_default_eth_iface()
        refresh_wifi_status()
        stop_event.wait(config.LINK_POLL_INTERVAL)


def start_monitor():
    """Avvia il thread che sorveglia il cavo eth e lo stato wifi."""
    stop_event = threading.Event()
    t = threading.Thread(target=_monitor_loop, args=(stop_event,), daemon=True)
    t.start()
    return stop_event
