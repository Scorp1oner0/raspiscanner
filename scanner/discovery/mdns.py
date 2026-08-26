"""mDNS/Bonjour probe (RFC 6762) for devices that announce themselves over
multicast DNS instead of (or in addition to) exposing open TCP ports.

Same principle as the ONVIF WS-Discovery probe in scanner/cameras/onvif.py:
send a multicast query, listen for replies for a fixed window. Useful
specifically for phones/tablets/computers, which usually have no open
ports to fingerprint from (default firewall) but commonly announce a
`_device-info._tcp.local` service with a TXT record containing the real
hardware model (e.g. "iPhone14,2", "MacBookPro18,3") — far more precise
than guessing from a hostname pattern (see scanner/hosts.py).

This is a minimal, best-effort DNS message encoder/decoder, not a full
mDNS/DNS-SD client: it only extracts what's actually used here (PTR
target names and TXT "model="/"md=" keys), and any record it can't or
doesn't need to parse is simply skipped. A malformed or unexpected packet
from one responder must never abort the whole probe — same defensive
stance as the rest of the discovery code.
"""
import logging
import socket
import struct
import time

log = logging.getLogger("raspiscanner.mdns")

MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353

_TYPE_PTR = 12
_TYPE_TXT = 16

# Service types worth asking about. _device-info is Apple's and gives a
# precise model string in its TXT record (the best signal available
# here); the others are common enough on non-Apple devices/printers/
# smart-TVs to be a useful secondary hint (friendly name from the PTR
# target) when device-info doesn't answer.
_QUERY_SERVICES = (
    "_device-info._tcp.local",
    "_airplay._tcp.local",
    "_googlecast._tcp.local",
    "_workstation._tcp.local",
    "_ipp._tcp.local",
    "_smb._tcp.local",
)


def reverse_arpa_name(ip):
    """Nome DNS standard per una query PTR inversa (RFC 1035 §3.5): un
    dispositivo il cui responder mDNS supporta le query inverse (Avahi,
    Bonjour) risponde con il proprio hostname reale (es. "MyLaptop.local"),
    piu' preciso e affidabile del nome dedotto dal target di un PTR di
    servizio (che spesso e' solo un'etichetta scelta a caso dal servizio,
    non l'hostname vero e proprio)."""
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


def _encode_name(name):
    out = bytearray()
    for label in name.strip(".").split("."):
        raw = label.encode("utf-8")
        out.append(len(raw))
        out += raw
    out.append(0)
    return bytes(out)


def _build_query(service_names):
    """Un unico messaggio DNS con una domanda PTR per ciascun servizio.
    Transaction ID e flags a 0: e' la convenzione per le query mDNS
    (RFC 6762 §18.1/§18.2), nessun querier le usa per il matching."""
    header = struct.pack(">HHHHHH", 0, 0, len(service_names), 0, 0, 0)
    body = b"".join(_encode_name(name) + struct.pack(">HH", _TYPE_PTR, 0x0001) for name in service_names)
    return header + body


def _read_name(msg, offset):
    """Decodifica un nome DNS a partire da `offset`, seguendo eventuali
    puntatori di compressione (RFC 1035 §4.1.4) — praticamente ogni
    risposta mDNS reale li usa per non ripetere ".local" in ogni record.
    Ritorna (nome, offset_successivo) dove offset_successivo e' subito
    dopo il nome COSI' COM'ERA nel messaggio originale, non dopo un
    eventuale salto: un puntatore termina sempre la codifica del nome.
    """
    labels = []
    offset_after_pointer = None
    seen_pointers = 0
    while True:
        if offset >= len(msg):
            break
        length = msg[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(msg):
                break
            pointer = ((length & 0x3F) << 8) | msg[offset + 1]
            if offset_after_pointer is None:
                offset_after_pointer = offset + 2
            seen_pointers += 1
            if seen_pointers > 32:  # puntatori circolari: non seguirli all'infinito
                break
            offset = pointer
            continue
        offset += 1
        labels.append(msg[offset:offset + length].decode("utf-8", errors="replace"))
        offset += length
    return ".".join(labels), (offset_after_pointer if offset_after_pointer is not None else offset)


def _parse_txt(rdata):
    """TXT record: sequenza di stringhe con prefisso di lunghezza, in
    genere "chiave=valore" (RFC 6763 §6)."""
    out = {}
    i = 0
    while i < len(rdata):
        length = rdata[i]
        i += 1
        entry = rdata[i:i + length].decode("utf-8", errors="replace")
        i += length
        if "=" in entry:
            key, _, value = entry.partition("=")
            out[key.strip().lower()] = value
    return out


def _iter_records(msg):
    """Itera i resource record di answer/authority/additional (qui non
    interessano le domande, solo le risposte). Ogni record e' un dict con
    "name", "type", "rdata" (bytes) e "rdata_offset" (posizione di rdata
    nel messaggio originale, serve per decomprimere nomi annidati es. nei
    PTR). Un record troncato o malformato interrompe l'iterazione invece
    di sollevare: il chiamante tiene comunque i record letti finora.
    """
    if len(msg) < 12:
        return
    _, _, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", msg[:12])
    offset = 12
    for _ in range(qdcount):
        _, offset = _read_name(msg, offset)
        offset += 4  # qtype + qclass
    for _ in range(ancount + nscount + arcount):
        if offset >= len(msg):
            return
        name, offset = _read_name(msg, offset)
        if offset + 10 > len(msg):
            return
        rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", msg[offset:offset + 10])
        offset += 10
        if offset + rdlength > len(msg):
            return
        yield {"name": name, "type": rtype, "rdata": msg[offset:offset + rdlength], "rdata_offset": offset}
        offset += rdlength


def mdns_probe(iface_ip=None, timeout=2.5, reverse_ips=None):
    """Manda le query mDNS e raccoglie le risposte per `timeout` secondi.
    Ritorna {ip: {"hostname": str|None, "model": str|None}}.

    "hostname" viene dal target del primo PTR ricevuto (nome amichevole
    scelto dal dispositivo stesso, es. "Marios-iPhone"), "model" dalla
    chiave model=/md= di un TXT (tipicamente solo _device-info, i
    dispositivi Apple): quando presente e' molto piu' preciso di un
    pattern indovinato dal nome host (vedi scanner/hosts.py).

    `reverse_ips`, se indicato (tipicamente gli host gia' trovati da
    ARP/ICMP su questa rete), aggiunge una query PTR inversa per ciascuno:
    quando risponde, da' l'hostname reale del dispositivo (piu' preciso
    del nome dedotto da un PTR di servizio) anche per device che non
    espongono nessuno dei servizi comuni interrogati di default.
    """
    query_names = list(_QUERY_SERVICES)
    if reverse_ips:
        query_names += [reverse_arpa_name(ip) for ip in reverse_ips]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        if iface_ip:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(iface_ip))
            sock.bind((iface_ip, 0))
        sock.settimeout(timeout)
        sock.sendto(_build_query(query_names), (MDNS_ADDR, MDNS_PORT))
    except OSError as exc:
        log.warning("probe mDNS non inviato (%s): %s", iface_ip, exc)
        sock.close()
        return {}

    results = {}
    deadline = time.time() + timeout
    while time.time() < deadline:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        sock.settimeout(remaining)
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            break
        except OSError:
            break

        ip = addr[0]
        entry = results.setdefault(ip, {"hostname": None, "model": None})
        try:
            for rec in _iter_records(data):
                if rec["type"] == _TYPE_PTR:
                    target, _ = _read_name(data, rec["rdata_offset"])
                    if rec["name"].lower().endswith(".in-addr.arpa"):
                        # Risposta a una nostra query inversa: il target e'
                        # gia' l'hostname vero e proprio (es. "MyLaptop.local"),
                        # non un'etichetta di servizio — vince sempre su un
                        # nome dedotto da un PTR di servizio, anche se
                        # quest'ultimo e' arrivato prima nello stesso pacchetto.
                        entry["hostname"] = target.rstrip(".")
                    elif entry["hostname"] is None:
                        # Il primo label del target e' il nome scelto dal
                        # dispositivo (es. "Marios-iPhone._device-info._tcp.local"
                        # -> "Marios-iPhone"); il resto e' solo il tipo di servizio.
                        friendly = target.split(".")[0]
                        if friendly:
                            entry["hostname"] = friendly
                elif rec["type"] == _TYPE_TXT:
                    txt = _parse_txt(rec["rdata"])
                    model = txt.get("model") or txt.get("md")
                    if model and not entry["model"]:
                        entry["model"] = model
        except Exception:
            # Un pacchetto malformato/inatteso da un singolo responder non
            # deve interrompere la raccolta delle risposte degli altri.
            log.debug("risposta mDNS malformata da %s, ignorata", ip)

    sock.close()
    return results
