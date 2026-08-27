"""SNMP discovery (P4, opzionale): GET di sysDescr/sysName con la
community "public", la convenzione universale di sola lettura — MAI una
lista di community indovinate (sarebbe credential guessing, esplicitamente
fuori scope per questo tool, vedi SECURITY.md). Nessuna scrittura (SNMP
SET), nessun bruteforce, nessuna community diversa da quella di default.

SNMP e' opzionale sulla stragrande maggioranza dei dispositivi (spesso
disabilitato di default, o filtrato da firewall): nessuna risposta e'
l'esito normale, non un errore — stesso trattamento di ONVIF/mDNS quando
un device non risponde.
"""
import logging

from .. import config

log = logging.getLogger("raspiscanner.discovery.snmp")

try:
    from scapy.all import sr1
    from scapy.layers.inet import IP, UDP
    from scapy.layers.snmp import SNMP, SNMPget, SNMPvarbind
    from scapy.volatile import RandShort
    SCAPY_AVAILABLE = True
except ImportError:  # scapy non installato: la discovery SNMP non funzionera'
    SCAPY_AVAILABLE = False
    log.warning("scapy non disponibile: la scansione SNMP e' disabilitata")

SNMP_PORT = 161
SYSDESCR_OID = "1.3.6.1.2.1.1.1.0"
SYSNAME_OID = "1.3.6.1.2.1.1.5.0"
_OID_LABELS = {SYSDESCR_OID: "sysDescr", SYSNAME_OID: "sysName"}


def parse_snmp_response(resp):
    """Estrae sysDescr/sysName da una risposta SNMP gia' decodificata da
    scapy. Ritorna {"sysDescr": str, "sysName": str} con solo le chiavi
    ottenute — dict vuoto se `resp` e' None (nessuna risposta) o non
    contiene un layer SNMP valido. Funzione pura, separata da snmp_probe()
    per essere testabile senza un vero invio in rete."""
    if resp is None or not SCAPY_AVAILABLE or not resp.haslayer(SNMP):
        return {}
    result = {}
    try:
        for vb in resp[SNMP].PDU.varbindlist:
            label = _OID_LABELS.get(str(vb.oid.val))
            if not label:
                continue
            value = getattr(vb.value, "val", None)
            if isinstance(value, bytes):
                value = value.decode("utf-8", errors="replace").strip()
            if value:
                result[label] = value
    except Exception:
        log.debug("parsing risposta SNMP fallito", exc_info=True)
        return {}
    return result


def snmp_probe(ip, community="public", timeout=1.0):
    """Interroga sysDescr/sysName via SNMP GET (v2c) su un singolo host
    gia' scoperto (non e' un probe broadcast/multicast: SNMP e' unicast
    request/response). Ritorna il dict di parse_snmp_response(), {} se il
    device non risponde entro `timeout` o SNMP non e' disponibile."""
    if not SCAPY_AVAILABLE:
        return {}
    pkt = (
        IP(dst=ip)
        / UDP(sport=RandShort(), dport=SNMP_PORT)
        / SNMP(community=community, PDU=SNMPget(varbindlist=[
            SNMPvarbind(oid=SYSDESCR_OID),
            SNMPvarbind(oid=SYSNAME_OID),
        ]))
    )
    try:
        resp = sr1(pkt, timeout=timeout, verbose=0)
    except Exception as exc:
        log.debug("SNMP probe fallito per %s: %s", ip, exc)
        return {}
    return parse_snmp_response(resp)
