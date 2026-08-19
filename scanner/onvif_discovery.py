"""Probe WS-Discovery (ONVIF) via multicast UDP.

E' il modo standard con cui le telecamere IP "onvif compliant" si
annunciano sulla rete: si manda un Probe multicast e le telecamere
rispondono con i propri XAddrs (URL del servizio ONVIF) e i Types
supportati. E' un segnale molto piu' affidabile del solo controllo porte
per riconoscere una telecamera vera.
"""
import logging
import socket
import time
import uuid

from . import config

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
