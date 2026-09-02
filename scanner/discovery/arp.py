"""Discovery dei dispositivi su una rete locale tramite ARP scan.

Richiede privilegi per socket raw (root o cap_net_raw+cap_net_admin), come
tutto il resto dell'applicazione che deve anche riconfigurare le interfacce.

Sulla build Windows senza Npcap (nessun socket raw disponibile) l'ARP
scan attivo non parte: si ripiega su scanner.discovery.nopriv (sweep
TCP-connect + tabella ARP di sistema). Su Linux quel ripiego non viene
mai usato.
"""
import ipaddress
import logging
import socket
import threading
import time

from .. import config
from .. import platform_net
from . import nopriv

log = logging.getLogger("raspiscanner.discovery")

try:
    from scapy.all import ARP, AsyncSniffer, Dot1Q, Ether, sendp, conf as scapy_conf
    scapy_conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:  # scapy non installato: la discovery ARP non funzionera'
    SCAPY_AVAILABLE = False
    log.warning("scapy non disponibile: la scansione ARP e' disabilitata")


def extract_vlan_id(received):
    """Ritorna l'ID VLAN (802.1Q) se il frame catturato ne porta uno, None
    altrimenti. La maggior parte delle porte di rete sono in modalita'
    "access" (lo switch toglie il tag prima di consegnare il frame): un
    None qui e' il caso normale, non un errore — l'informazione compare
    solo se il probe gira su una porta "trunk" che lascia passare i tag,
    o su un'interfaccia VLAN dedicata.
    """
    if SCAPY_AVAILABLE and received.haslayer(Dot1Q):
        return received[Dot1Q].vlan
    return None


def parse_arp_reply(received, network):
    """Se `received` e' una risposta ARP ("is-at") proveniente da un IP
    dentro `network` (un ipaddress.ip_network), ritorna (ip, mac_maiuscolo).
    Altrimenti None: non e' ARP, e' una richiesta invece di una risposta,
    o l'IP sorgente non appartiene alla subnet scansionata (traffico ARP di
    altri host sulla rete, non una risposta al nostro probe).
    """
    if not SCAPY_AVAILABLE or not received.haslayer(ARP) or received[ARP].op != 2:
        return None
    src_ip = received[ARP].psrc
    try:
        if ipaddress.ip_address(src_ip) not in network:
            return None
    except ValueError:
        return None
    return src_ip, received[ARP].hwsrc.upper()


def arp_scan(cidr, iface, timeout=config.ARP_SCAN_TIMEOUT, psrc=None):
    """Esegue un ARP sweep sulla subnet indicata. Ritorna lista di
    {'ip': ..., 'mac': ...} per gli host che hanno risposto.

    Invia le richieste e ascolta le risposte SEPARATAMENTE (sniffer attivo
    per tutta la finestra, richieste ripetute), invece di usare `srp()` che
    fa le due cose in un solo giro: `srp()` manda tutti i pacchetti del
    range quasi simultaneamente e ascolta solo nella finestra successiva,
    quindi un host che risponde con un filo di ritardo rispetto al burst di
    invio (comune su subnet /24 intere) puo' arrivare mentre scapy ha gia'
    smesso di ascoltare per quel giro. Qui invece l'ascolto e' attivo
    PRIMA di iniziare a inviare e per tutta la durata di tutti i round di
    retry, quindi cattura anche risposte "in ritardo" rispetto al proprio
    invio.

    `psrc`, se indicato, forza l'IP sorgente del pacchetto ARP invece di
    lasciarlo decidere a scapy dalla sua tabella di routing interna: scapy
    la costruisce una sola volta all'import e non la aggiorna da sola
    quando cambiamo l'IP dell'interfaccia (es. passando da una classe
    preimpostata alla successiva, o da una rete a un'altra dopo un
    "riconfigura rete"). Senza `psrc` esplicito, dopo un cambio di rete lo
    scan puo' partire con un IP sorgente non piu' valido e non ricevere
    risposta da nessuno, sembrando "bloccato" sulla rete precedente.
    """
    if not SCAPY_AVAILABLE:
        return nopriv.windows_arp_scan(cidr) if platform_net.IS_WINDOWS else []

    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        log.error("subnet non valida per ARP scan: %s", cidr)
        return []

    try:
        scapy_conf.route.resync()
        arp_kwargs = {"pdst": cidr}
        if psrc:
            arp_kwargs["psrc"] = psrc
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(**arp_kwargs)
    except Exception as exc:
        log.error("costruzione pacchetto ARP fallita su %s (%s): %s", iface, cidr, exc)
        return nopriv.windows_arp_scan(cidr) if platform_net.IS_WINDOWS else []

    results = {}

    def _on_packet(received):
        parsed = parse_arp_reply(received, network)
        if parsed:
            ip, mac = parsed
            results[ip] = (mac, extract_vlan_id(received))

    sniffer = None
    try:
        # NIENTE filter="arp" qui: la compilazione di un filtro BPF in scapy
        # richiede libpcap, non garantito installato sul sistema (non e' tra
        # le dipendenze del progetto). Filtriamo in Python in _on_packet
        # invece, che e' l'unica cosa che serve davvero.
        sniffer = AsyncSniffer(iface=iface, prn=_on_packet, store=False)
        sniffer.start()
        rounds = config.ARP_SCAN_RETRY + 1
        for round_idx in range(rounds):
            sendp(pkt, iface=iface, verbose=0)
            if round_idx < rounds - 1:
                time.sleep(timeout / rounds)
        # ultima finestra di attesa per le risposte piu' lente dell'ultimo giro
        time.sleep(timeout / rounds)
    except Exception as exc:
        # Deliberatamente ampio (non solo PermissionError/OSError): questa
        # funzione viene chiamata in loop su piu' reti da scan_engine, e
        # un'eccezione non gestita qui (es. ValueError se l'interfaccia non
        # esiste piu') interromperebbe l'intera scansione multi-rete invece
        # di limitarsi a saltare questa singola rete.
        log.error("ARP scan fallito su %s (%s): %s", iface, cidr, exc)
        if platform_net.IS_WINDOWS:
            return nopriv.windows_arp_scan(cidr)
        return []
    finally:
        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception as exc:
                # AsyncSniffer esegue in un thread separato: se il thread di
                # sniffing muore per un'eccezione (es. errore di permessi
                # scoperto solo li'), scapy la rialza solo qui, a .stop().
                # Non va inghiottita in silenzio: altrimenti uno scan
                # completamente fallito e' indistinguibile da "rete vuota".
                log.error("sniffer ARP terminato con errore su %s: %s", iface, exc)

    if not results and platform_net.IS_WINDOWS:
        # scapy ha girato senza errori ma non ha visto nulla: quasi sempre
        # Npcap assente (i socket L2 falliscono in silenzio). Ripiego.
        return nopriv.windows_arp_scan(cidr)

    return [{"ip": ip, "mac": mac, "vlan_id": vlan_id} for ip, (mac, vlan_id) in results.items()]


def resolve_hostname(ip, timeout=config.HOSTNAME_TIMEOUT):
    """Reverse DNS best-effort, con un tetto reale al tempo di attesa.

    NON usa socket.setdefaulttimeout(), come faceva prima, per due motivi
    indipendenti:

    1. **Non funzionava.** Quel timeout vale solo per gli oggetti socket di
       Python; `gethostbyaddr()` chiama il resolver del sistema e non ne
       crea nessuno (verificato: zero socket Python istanziate). La
       risoluzione poteva quindi bloccare per l'intero timeout del
       resolver, molto piu' lungo dei 0,6s richiesti.
    2. **Era pericoloso.** `setdefaulttimeout` e' stato GLOBALE del
       processo, e questa funzione gira dentro un thread pool: piu' thread
       che lo impostano e ripristinano insieme si sovrascrivono a vicenda,
       lasciando un timeout arbitrario a tutte le altre socket della
       scansione. Una porta poteva risultare chiusa solo perche' un altro
       thread aveva accorciato il timeout di default.

    Qui la risoluzione gira in un thread dedicato che viene semplicemente
    abbandonato se sfora: il thread e' daemon, quindi non trattiene
    l'uscita del processo.
    """
    result = []

    def _lookup():
        try:
            result.append(socket.gethostbyaddr(ip)[0])
        except (socket.herror, socket.gaierror, OSError):
            pass

    worker = threading.Thread(target=_lookup, daemon=True)
    worker.start()
    worker.join(timeout)
    return result[0] if result else None
