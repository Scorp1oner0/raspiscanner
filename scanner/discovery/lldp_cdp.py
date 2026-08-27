"""LLDP/CDP discovery (P4): ascolto passivo di annunci che gli apparati
di rete (switch, router, AP) mandano periodicamente sul link locale —
non e' un probe "manda una richiesta, aspetta la risposta" come ARP/
ONVIF/mDNS, e' puro sniffing: LLDP e CDP non hanno un meccanismo di
richiesta esplicita, gli apparati trasmettono da soli ogni ~30-60s.

Per questo un timeout breve puo' non catturare nulla anche se un
dispositivo LLDP/CDP-capable e' presente: e' un limite del protocollo
stesso (il timing di trasmissione non e' sotto il nostro controllo), non
un errore — stesso trattamento gia' dato altrove (VLAN tag, banner HTTP
assente) per segnali che dipendono da condizioni fuori dal nostro
controllo.
"""
import logging
import time

log = logging.getLogger("raspiscanner.discovery.lldp_cdp")

try:
    from scapy.all import AsyncSniffer, Ether
    from scapy.contrib.cdp import (
        CDPMsgDeviceID, CDPMsgPlatform, CDPMsgPortID, CDPMsgSoftwareVersion, CDPv2_HDR,
    )
    from scapy.contrib.lldp import (
        LLDPDUChassisID, LLDPDUPortID, LLDPDUSystemDescription, LLDPDUSystemName,
    )
    SCAPY_AVAILABLE = True
except ImportError:  # scapy (o i moduli contrib) non disponibili
    SCAPY_AVAILABLE = False
    log.warning("scapy non disponibile: la discovery LLDP/CDP e' disabilitata")

LLDP_ETHERTYPE = 0x88CC
CDP_DST_MAC = "01:00:0c:cc:cc:cc"


def _decode_id(value):
    """Il campo "id" di ChassisID/PortID e' bytes per la maggior parte
    dei subtype (nome interfaccia, stringa locale...), ma scapy lo
    formatta gia' come stringa leggibile per i subtype con un tipo noto
    (es. subtype 4 = MAC address). str() su bytes darebbe "b'...'"
    invece del contenuto decodificato."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _parse_lldp(pkt):
    neighbor = {"protocol": "lldp"}
    if pkt.haslayer(LLDPDUChassisID):
        neighbor["chassis_id"] = _decode_id(pkt[LLDPDUChassisID].id)
    if pkt.haslayer(LLDPDUPortID):
        neighbor["port_id"] = _decode_id(pkt[LLDPDUPortID].id)
    if pkt.haslayer(LLDPDUSystemName):
        neighbor["system_name"] = pkt[LLDPDUSystemName].system_name.decode("utf-8", errors="replace")
    if pkt.haslayer(LLDPDUSystemDescription):
        neighbor["system_description"] = pkt[LLDPDUSystemDescription].description.decode("utf-8", errors="replace")
    return neighbor


def _parse_cdp(pkt):
    neighbor = {"protocol": "cdp"}
    for msg in pkt[CDPv2_HDR].msg:
        if isinstance(msg, CDPMsgDeviceID):
            neighbor["system_name"] = msg.val.decode("utf-8", errors="replace")
        elif isinstance(msg, CDPMsgPortID):
            neighbor["port_id"] = msg.iface.decode("utf-8", errors="replace")
        elif isinstance(msg, CDPMsgPlatform):
            neighbor["system_description"] = msg.val.decode("utf-8", errors="replace")
        elif isinstance(msg, CDPMsgSoftwareVersion):
            neighbor.setdefault("system_description", msg.val.decode("utf-8", errors="replace"))
    return neighbor


def parse_lldp_cdp_packet(pkt):
    """Riconosce ed estrae un annuncio LLDP o CDP da un frame Ethernet
    gia' catturato. Ritorna None se non e' ne' l'uno ne' l'altro (il
    grosso del traffico visto durante lo sniff)."""
    if not SCAPY_AVAILABLE or not pkt.haslayer(Ether):
        return None
    if pkt[Ether].type == LLDP_ETHERTYPE:
        return _parse_lldp(pkt)
    if pkt[Ether].dst.lower() == CDP_DST_MAC and pkt.haslayer(CDPv2_HDR):
        return _parse_cdp(pkt)
    return None


def lldp_cdp_probe(iface, timeout=3):
    """Ascolta `iface` per `timeout` secondi, raccoglie ogni annuncio
    LLDP/CDP visto. Ritorna una lista di dict (vedi parse_lldp_cdp_packet),
    uno per pacchetto — un vicino che manda piu' annunci nella finestra
    compare piu' volte, non deduplicato (l'ultimo visto e' spesso il piu'
    aggiornato, deduplicare qui butterebbe via quell'informazione)."""
    if not SCAPY_AVAILABLE:
        return []
    results = []

    def _on_packet(pkt):
        neighbor = parse_lldp_cdp_packet(pkt)
        if neighbor:
            results.append(neighbor)

    sniffer = None
    try:
        sniffer = AsyncSniffer(iface=iface, prn=_on_packet, store=False)
        sniffer.start()
        time.sleep(timeout)
    except Exception as exc:
        log.error("sniff LLDP/CDP fallito su %s: %s", iface, exc)
        return results
    finally:
        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception as exc:
                log.error("sniffer LLDP/CDP terminato con errore su %s: %s", iface, exc)
    return results
