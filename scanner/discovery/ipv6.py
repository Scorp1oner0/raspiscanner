"""IPv6 discovery (P4): scoperta di host IPv6-abilitati sul link locale.

Niente equivalente diretto dell'ARP sweep (IPv6 non ha broadcast): la
tecnica usata qui e' un ICMPv6 Echo Request verso il multicast "all-nodes
link-local" ff02::1, che ogni nodo IPv6 attivo sull'interfaccia ascolta per
definizione di protocollo (RFC 4291) — non serve conoscere in anticipo
nessun indirizzo. E' l'equivalente IPv6 di "ping -b" sulla subnet, con lo
stesso scopo supplementare (non sostituisce la scoperta IPv4 via ARP, la
completa per gli host che hanno anche IPv6 attivo).

Le risposte arrivano quasi sempre dall'indirizzo link-local (fe80::...) del
rispondente: la selezione dell'indirizzo sorgente IPv6 preferisce lo stesso
scope della destinazione (RFC 6724), e la destinazione qui e' link-local.
Un indirizzo globale, se il device ne ha uno, non emerge da questo probe.
"""
import logging
import time

log = logging.getLogger("raspiscanner.discovery.ipv6")

try:
    from scapy.all import AsyncSniffer, Ether, sendp, conf as scapy_conf
    from scapy.layers.inet6 import ICMPv6EchoReply, ICMPv6EchoRequest, IPv6
    scapy_conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:  # scapy (o il layer inet6) non disponibile
    SCAPY_AVAILABLE = False
    log.warning("scapy non disponibile: la discovery IPv6 e' disabilitata")

ALL_NODES_MULTICAST = "ff02::1"
ALL_NODES_MULTICAST_MAC = "33:33:00:00:00:01"


def parse_icmpv6_echo_reply(received):
    """Se `received` e' un ICMPv6 Echo Reply, ritorna (ipv6_sorgente,
    mac_sorgente_o_None). Altrimenti None."""
    if not SCAPY_AVAILABLE or not received.haslayer(ICMPv6EchoReply):
        return None
    if not received.haslayer(IPv6):
        return None
    mac = received[Ether].src.upper() if received.haslayer(Ether) else None
    return received[IPv6].src, mac


def ipv6_discovery(iface, timeout=None, retry=None):
    """Invia Echo Request ICMPv6 a ff02::1 su `iface` e ascolta le risposte
    per `timeout` secondi (con retry giri di invio, come arp_scan). Ritorna
    una lista di {'ipv6': ..., 'mac': ...}, un elemento per indirizzo IPv6
    distinto visto (un host che risponde piu' volte non e' duplicato)."""
    from .. import config
    if timeout is None:
        timeout = config.IPV6_DISCOVERY_TIMEOUT
    if retry is None:
        retry = config.IPV6_DISCOVERY_RETRY
    if not SCAPY_AVAILABLE:
        return []

    try:
        pkt = (
            Ether(dst=ALL_NODES_MULTICAST_MAC)
            / IPv6(dst=ALL_NODES_MULTICAST)
            / ICMPv6EchoRequest()
        )
    except Exception as exc:
        log.error("costruzione pacchetto ICMPv6 fallita su %s: %s", iface, exc)
        return []

    results = {}

    def _on_packet(received):
        parsed = parse_icmpv6_echo_reply(received)
        if parsed:
            ipv6, mac = parsed
            results[ipv6] = mac

    sniffer = None
    try:
        sniffer = AsyncSniffer(iface=iface, prn=_on_packet, store=False)
        sniffer.start()
        rounds = retry + 1
        for round_idx in range(rounds):
            sendp(pkt, iface=iface, verbose=0)
            if round_idx < rounds - 1:
                time.sleep(timeout / rounds)
        time.sleep(timeout / rounds)
    except Exception as exc:
        # Ampio deliberatamente, come in arp_scan: chiamata in loop su piu'
        # reti da scan_engine, un'eccezione qui non deve interrompere lo
        # scan intero.
        log.error("IPv6 discovery fallita su %s: %s", iface, exc)
        return []
    finally:
        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception as exc:
                log.error("sniffer IPv6 terminato con errore su %s: %s", iface, exc)

    return [{"ipv6": ipv6, "mac": mac} for ipv6, mac in results.items()]
