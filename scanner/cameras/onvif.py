"""Probe WS-Discovery (ONVIF) via multicast UDP.

E' il modo standard con cui le telecamere IP "onvif compliant" si
annunciano sulla rete: si manda un Probe multicast e le telecamere
rispondono con i propri XAddrs (URL del servizio ONVIF) e i Types
supportati. E' un segnale molto piu' affidabile del solo controllo porte
per riconoscere una telecamera vera.
"""
import http.client
import ipaddress
import logging
import socket
import time
import urllib.parse
import uuid

from .. import config

log = logging.getLogger("raspiscanner.onvif")

_PROBE_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
            xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <e:Header>
    <w:MessageID>uuid:{msg_id}</w:MessageID>
    <w:To e:mustUnderstand="1">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
    <w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
  </e:Header>
  <e:Body>
    <d:Probe>
      <d:Types>dn:NetworkVideoTransmitter</d:Types>
    </d:Probe>
  </e:Body>
</e:Envelope>"""

_DEVICE_INFO_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <soap:Body>
    <tds:GetDeviceInformation/>
  </soap:Body>
</soap:Envelope>"""


def _extract_between(text, start_tag_frag, end_tag_frag):
    low = text.lower()
    start = low.find(start_tag_frag)
    if start == -1:
        return None
    start = text.find(">", start) + 1
    end = low.find(end_tag_frag, start)
    if end == -1:
        return None
    return text[start:end].strip()


def onvif_probe(iface_ip=None, timeout=3):
    """Manda un probe WS-Discovery e raccoglie le risposte per la durata
    di `timeout` secondi. Ritorna {ip: {"xaddrs": [...], "types": "..."}}.
    """
    msg = _PROBE_TEMPLATE.format(msg_id=uuid.uuid4())
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        if iface_ip:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(iface_ip))
            sock.bind((iface_ip, 0))
        sock.settimeout(timeout)
        sock.sendto(msg.encode("utf-8"), (config.ONVIF_MULTICAST_ADDR, config.ONVIF_DISCOVERY_PORT))
    except OSError as exc:
        log.warning("probe ONVIF non inviato (%s): %s", iface_ip, exc)
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
        text = data.decode("utf-8", errors="ignore")
        xaddrs_raw = _extract_between(text, "<d:xaddrs", "</d:xaddrs") or \
            _extract_between(text, ":xaddrs", ":xaddrs")
        types = _extract_between(text, "<d:types", "</d:types") or ""
        xaddrs = xaddrs_raw.split() if xaddrs_raw else []
        results[ip] = {"xaddrs": xaddrs, "types": types}
    sock.close()
    return results


def _is_safe_xaddr_host(hostname):
    """Rifiuta XAddr che non puntano a un IPv4 privato "normale".

    Il probe ONVIF e' multicast: QUALUNQUE dispositivo sulla stessa rete
    puo' rispondere con l'XAddr che preferisce, inclusi un IP pubblico o
    un servizio interno sensibile — senza questo controllo
    get_device_info() farebbe una richiesta HTTP verso un host arbitrario
    scelto da un mittente non fidato (SSRF: lo scanner gira da root e un
    dispositivo malevolo potrebbe farlo bussare a porte interne che
    altrimenti non toccherebbe mai). Ammessi solo IP IPv4 letterali
    (niente hostname DNS: elimina anche il DNS rebinding) in range privati
    non speciali.

    Deliberatamente NON limitato alle subnet attualmente scansionate: un
    IP privato fuori da ogni rete attiva e' esattamente il caso "telecamera
    con IP sbagliato" che scan_engine.ORPHAN_ONVIF_REASON gestisce di
    proposito, e continua a essere legittimo interrogare.
    """
    try:
        addr = ipaddress.IPv4Address(hostname)
    except (ipaddress.AddressValueError, ValueError):
        return False
    if not addr.is_private:
        return False
    if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        return False
    return True


def get_device_info(xaddr, timeout=3):
    """Interroga l'endpoint ONVIF GetDeviceInformation sull'XAddr ricevuto
    dal WS-Discovery per ottenere Manufacturer/Model/FirmwareVersion REALI,
    invece di indovinarli dal banner HTTP. Ritorna {} se la richiesta fallisce
    o il dispositivo la richiede autenticata (comune: GetDeviceInformation e'
    spesso protetto, non e' garantito ottenere sempre il dato).
    """
    parsed = urllib.parse.urlparse(xaddr)
    if not parsed.hostname:
        return {}
    if not _is_safe_xaddr_host(parsed.hostname):
        log.warning("XAddr ONVIF scartato (host non privato/non valido): %s", xaddr)
        return {}
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/onvif/device_service"
    conn_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection

    try:
        conn = conn_cls(parsed.hostname, port, timeout=timeout)
        conn.request(
            "POST", path, body=_DEVICE_INFO_TEMPLATE.encode("utf-8"),
            headers={
                "Content-Type": "application/soap+xml; charset=utf-8",
                "User-Agent": "raspiscanner",
            },
        )
        resp = conn.getresponse()
        body = resp.read(8192).decode("utf-8", errors="ignore")
        status = resp.status
        conn.close()
    except Exception as exc:
        log.debug("GetDeviceInformation fallito per %s: %s", xaddr, exc)
        return {}

    if status >= 400 or not body:
        return {}

    manufacturer = _extract_between(body, "manufacturer", "manufacturer")
    model = _extract_between(body, "model", "model")
    firmware = _extract_between(body, "firmwareversion", "firmwareversion")
    info = {}
    if manufacturer:
        info["manufacturer"] = manufacturer
    if model:
        info["model"] = model
    if firmware:
        info["firmware"] = firmware
    return info
