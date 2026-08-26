"""Discovery ICMP per interfacce NOARP: VPN instradate (WireGuard, OpenVPN
in modalita' tun, PPP...) senza dominio di broadcast L2.

L'ARP scan (scanner.discovery.arp) non puo' funzionarci sopra per un
limite del protocollo, non di questo codice: verificato concretamente su
un'interfaccia WireGuard reale, che il kernel marca col flag NOARP (vedi
network.setup.is_noarp) — `ip neigh` su di lei resta sempre vuoto,
indipendentemente da quanti host risponderebbero a un probe IP diretto
(confermato: un ping verso un peer reale su quella subnet funziona benissimo,
l'ARP scan no).

Stesso principio di arp_scan (ascolto attivo per tutta la finestra prima e
durante l'invio, non un giro solo), ma un ICMP echo per ogni IP della
subnet invece di un ARP broadcast: funziona anche instradato, non serve un
dominio di broadcast L2. Il risultato non ha mai un MAC (impossibile: non
c'e' L2 su queste interfacce), solo IP.
"""
import ipaddress
import logging
import time

from .. import config

log = logging.getLogger("raspiscanner.discovery.icmp")

try:
    from scapy.all import ICMP, IP, AsyncSniffer, send, conf as scapy_conf
    scapy_conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:  # scapy non installato: la scansione ICMP e' disabilitata
    SCAPY_AVAILABLE = False
    log.warning("scapy non disponibile: la scansione ICMP e' disabilitata")


def parse_icmp_reply(received, network):
    """Se `received` e' un ICMP echo-reply (type 0) proveniente da un IP
    dentro `network`, ritorna l'IP sorgente. Altrimenti None: non e' ICMP,
    e' una request invece di una reply, o l'IP sorgente non appartiene
    alla subnet scansionata (rumore di rete, non una risposta al nostro
    probe). Estratta a parte per essere testabile senza socket raw reali
    (stesso principio di discovery.arp.parse_arp_reply).

    NIENTE filter="icmp" in AsyncSniffer (dove questa funzione viene
    usata): come in arp_scan, compilare un filtro BPF richiede libpcap,
    non garantito installato — si filtra qui in Python invece.
    """
    if not received.haslayer(ICMP) or received[ICMP].type != 0:
        return None
    if not received.haslayer(IP):
        return None
    src_ip = received[IP].src
    try:
        if ipaddress.ip_address(src_ip) not in network:
            return None
    except ValueError:
        return None
    return src_ip


def icmp_scan(cidr, iface, timeout=config.ARP_SCAN_TIMEOUT, psrc=None):
    """Esegue uno sweep ICMP sulla subnet indicata. Ritorna lista di
    {'ip': ..., 'mac': None} per gli host che hanno risposto.

    `psrc`, se indicato, forza l'IP sorgente del pacchetto invece di
    lasciarlo decidere al routing di scapy — stesso motivo di arp_scan:
    dopo un cambio di rete l'IP sorgente di default puo' non essere piu'
    valido.
    """
    if not SCAPY_AVAILABLE:
        return []

    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        log.error("subnet non valida per ICMP scan: %s", cidr)
        return []

    targets = [str(ip) for ip in network.hosts()]
    if not targets:
        return []

    results = {}

    def _on_packet(received):
        src_ip = parse_icmp_reply(received, network)
        if src_ip:
            results[src_ip] = None

    sniffer = None
    try:
        scapy_conf.route.resync()
        ip_kwargs = {"dst": targets}
        if psrc:
            ip_kwargs["src"] = psrc
        pkt = IP(**ip_kwargs) / ICMP()
    except Exception as exc:
        log.error("costruzione pacchetto ICMP fallita su %s (%s): %s", iface, cidr, exc)
        return []

    try:
        sniffer = AsyncSniffer(iface=iface, prn=_on_packet, store=False)
        sniffer.start()
        send(pkt, iface=iface, verbose=0)
        time.sleep(timeout)
    except Exception as exc:
        # Ampio deliberatamente, stesso motivo di arp_scan: non deve
        # interrompere lo scan sulle altre reti attive.
        log.error("ICMP scan fallito su %s (%s): %s", iface, cidr, exc)
        return []
    finally:
        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception as exc:
                log.error("sniffer ICMP terminato con errore su %s: %s", iface, exc)

    return [{"ip": ip, "mac": mac} for ip, mac in results.items()]
