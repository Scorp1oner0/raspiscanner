"""Discovery dei dispositivi su una rete locale tramite ARP scan.

Richiede privilegi per socket raw (root o cap_net_raw+cap_net_admin), come
tutto il resto dell'applicazione che deve anche riconfigurare le interfacce.
"""
import logging
import socket

from . import config

log = logging.getLogger("raspiscanner.discovery")

try:
    from scapy.all import ARP, Ether, srp, conf as scapy_conf
    scapy_conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:  # scapy non installato: la discovery ARP non funzionera'
    SCAPY_AVAILABLE = False
    log.warning("scapy non disponibile: la scansione ARP e' disabilitata")


def arp_scan(cidr, iface, timeout=config.ARP_SCAN_TIMEOUT):
    """Esegue un ARP sweep sulla subnet indicata. Ritorna lista di
    {'ip': ..., 'mac': ...} per gli host che hanno risposto.
    """
    if not SCAPY_AVAILABLE:
        return []
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
        answered, _ = srp(pkt, timeout=timeout, iface=iface, retry=1)
    except (PermissionError, OSError) as exc:
        log.error("ARP scan fallito su %s (%s): permessi insufficienti? %s", iface, cidr, exc)
        return []
    results = []
    for _, received in answered:
        results.append({"ip": received.psrc, "mac": received.hwsrc.upper()})
    return results


def quick_subnet_probe(iface, cidr, timeout=config.CLASS_PROBE_TIMEOUT):
    """True se almeno un host risponde su quella subnet (usato durante
    l'autoconfigurazione per capire se una classe preimpostata e' quella giusta).
    """
    hosts = arp_scan(cidr, iface, timeout=timeout)
    return len(hosts) > 0


def resolve_hostname(ip, timeout=config.HOSTNAME_TIMEOUT):
    """Reverse DNS best-effort, non blocca a lungo se non c'e' un DNS server."""
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)
