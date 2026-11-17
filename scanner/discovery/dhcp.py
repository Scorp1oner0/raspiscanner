"""Ricerca dei server DHCP di una rete, senza prendere nessun indirizzo.

Manda un DHCPDISCOVER con un indirizzo hardware inventato e ascolta le
OFFER: per ogni server dice chi e' (indirizzo e MAC), che gateway e che DNS
consiglia ai client. Su una rete mai vista e' un modo per sapere chi la
gestisce, quale router e' quello vero e se ci sono due server. Non manda mai
la REQUEST, quindi nessun indirizzo viene assegnato: il server tiene da parte
l'offerta per qualche secondo e poi la libera, come fa ogni client che prova.
E' una richiesta visibile in rete (stessa tecnica dei controlli anti DHCP
abusivo): si spegne con RASPISCANNER_DHCP_PROBE=0.
"""
import logging
import os
import random
import time

from .. import config
from .. import platform_net

log = logging.getLogger("raspiscanner.discovery.dhcp")

try:
    from scapy.all import AsyncSniffer, BOOTP, DHCP, Ether, IP, UDP, get_if_hwaddr, sendp, conf as scapy_conf
    scapy_conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:  # scapy non installato: la ricerca dei server DHCP e' disabilitata
    SCAPY_AVAILABLE = False
    log.warning("scapy not available: DHCP server discovery is disabled")


def _as_list(value):
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]


def parse_offer(pkt, xid):
    """Dati di una DHCPOFFER (message-type 2) con il nostro `xid`:
    {'server', 'mac', 'router', 'dns', 'subnet', 'domain'} oppure None."""
    if not pkt.haslayer(DHCP) or not pkt.haslayer(BOOTP) or pkt[BOOTP].xid != xid:
        return None
    options = {}
    for option in pkt[DHCP].options:
        if isinstance(option, tuple) and len(option) >= 2:
            options[option[0]] = option[1] if len(option) == 2 else list(option[1:])
    if options.get("message-type") != 2:
        return None
    server = str(options.get("server_id") or pkt[IP].src)
    domain = options.get("domain")
    if isinstance(domain, bytes):
        domain = domain.decode("utf-8", errors="replace")
    return {
        "server": server,
        "mac": pkt[Ether].src if pkt.haslayer(Ether) else None,
        "router": _as_list(options["router"])[0] if "router" in options else None,
        "dns": _as_list(options["name_server"]) if "name_server" in options else [],
        "subnet": str(options["subnet_mask"]) if "subnet_mask" in options else None,
        "domain": domain or None,
    }


def dhcp_probe(iface, timeout=None):
    """Elenco dei server DHCP che rispondono su `iface` (vuoto se spenta,
    senza accesso raw o senza risposte). Un server per indirizzo."""
    timeout = timeout or config.DHCP_PROBE_TIMEOUT
    if not config.DHCP_PROBE_ENABLED or not SCAPY_AVAILABLE or not platform_net.has_raw_socket_access():
        return []
    offers = {}
    xid = random.getrandbits(32)

    def _on_packet(pkt):
        offer = parse_offer(pkt, xid)
        if offer:
            offers.setdefault(offer["server"], offer)

    sniffer = None
    try:
        scapy_conf.ifaces.reload()
        fake_mac = bytes([0x02]) + os.urandom(5)
        discover = (
            Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff")
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(chaddr=fake_mac + b"\x00" * 10, xid=xid, flags=0x8000)
            / DHCP(options=[("message-type", "discover"), ("param_req_list", [1, 3, 6, 15]), "end"])
        )
        sniffer = AsyncSniffer(iface=iface, prn=_on_packet, store=False)
        sniffer.start()
        time.sleep(0.3)
        sendp(discover, iface=iface, verbose=0)
        time.sleep(timeout)
    except Exception as exc:
        log.error("DHCP discovery failed on %s: %s", iface, exc)
    finally:
        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception as exc:
                log.error("DHCP sniffer exited with an error on %s: %s", iface, exc)
    return sorted(offers.values(), key=lambda o: o["server"])
