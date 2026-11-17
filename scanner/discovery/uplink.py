"""Percorso dallo scanner verso Internet: i primi salti del traceroute,
fermandosi al primo indirizzo pubblico (il router del provider).

Serve alla mappa delle reti: su una rete mai vista mostra chi c'e' tra lo
scanner e Internet (per esempio un Pi-hole e poi il modem) senza chiedere
niente a nessun apparato, solo rispondendo ai TTL scaduti che ogni router
manda da se'. E' l'unica sonda che esce dalla rete locale, e verso un solo
indirizzo (config.UPLINK_TRACE_TARGET, di default 1.1.1.1; vuoto la spegne).
"""
import ipaddress
import logging
import time

from .. import config
from .. import platform_net

log = logging.getLogger("raspiscanner.discovery.uplink")

try:
    from scapy.all import ICMP, IP, sr1, conf as scapy_conf
    scapy_conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:  # scapy non installato: il percorso verso Internet e' disabilitato
    SCAPY_AVAILABLE = False
    log.warning("scapy not available: the path to the Internet is disabled")

_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def is_private(ip):
    """Indirizzo non pubblico: privato, link-local o CGNAT (100.64.0.0/10)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_link_local or addr in _CGNAT


def parse_hop_reply(reply):
    """('hop', ip) per un TTL scaduto (ICMP type 11), ('reached', ip) per
    l'echo reply del bersaglio, ('blocked', ip) per una destinazione
    irraggiungibile (type 3), altrimenti (None, None). Estratta a parte per
    essere testabile senza socket raw."""
    if reply is None or not reply.haslayer(ICMP) or not reply.haslayer(IP):
        return None, None
    kind = {11: "hop", 0: "reached", 3: "blocked"}.get(reply[ICMP].type)
    return (kind, reply[IP].src) if kind else (None, None)


def trace_uplink(target=None, max_hops=None, hop_timeout=None):
    """{'target', 'hops': [{'ttl', 'ip', 'rtt_ms', 'private'}], 'reached',
    'internet'} oppure None se la sonda e' spenta o non puo' girare.
    `internet` e' vero se il percorso e' arrivato a un indirizzo pubblico."""
    target = config.UPLINK_TRACE_TARGET if target is None else target
    max_hops = max_hops or config.UPLINK_MAX_HOPS
    hop_timeout = hop_timeout or config.UPLINK_HOP_TIMEOUT
    if not target or not SCAPY_AVAILABLE or not platform_net.has_raw_socket_access():
        return None
    if platform_net.egress_ip_for(target) is None:
        return None

    hops, silent_in_a_row, reached = [], 0, False
    try:
        scapy_conf.route.resync()
        for ttl in range(1, max_hops + 1):
            started = time.monotonic()
            reply = sr1(IP(dst=target, ttl=ttl) / ICMP(), timeout=hop_timeout, verbose=0)
            kind, ip = parse_hop_reply(reply)
            if kind is None:
                hops.append({"ttl": ttl, "ip": None, "rtt_ms": None, "private": None})
                silent_in_a_row += 1
                if silent_in_a_row >= 3:
                    break
                continue
            silent_in_a_row = 0
            hops.append({"ttl": ttl, "ip": ip, "rtt_ms": round((time.monotonic() - started) * 1000, 1),
                         "private": is_private(ip)})
            if kind != "hop":
                reached = kind == "reached"
                break
            if not is_private(ip):
                break
    except Exception as exc:
        log.error("tracing the path to %s failed: %s", target, exc)
        return None

    while hops and hops[-1]["ip"] is None:
        hops.pop()
    if not hops:
        return None
    last = hops[-1]
    return {"target": target, "hops": hops, "reached": reached,
            "internet": bool(reached or (last["ip"] and last["private"] is False))}
