"""Tabella MAC di uno switch gestito, letta via SNMP v2c in sola lettura con
la community di fabbrica "public" e nessun'altra: come per
scanner.discovery.snmp, niente community indovinate e niente SET (vedi
SECURITY.md). Si prova solo su un apparato che ha gia' risposto a "public".

Dice su quale porta e' stato visto ogni indirizzo MAC, ed e' quello che
permette alla mappa di mettere lo switch al centro con ogni apparecchio sulla
sua porta. Se lo switch non risponde (SNMP spento, community cambiata, filtro)
ritorna None: e' l'esito normale, mai un'eccezione.

Client SNMP minimo in sola libreria standard (GET e GETNEXT, BER a mano): le
dipendenze del progetto restano Flask e Scapy.
"""
import logging
import os
import socket

log = logging.getLogger("raspiscanner.discovery.switch_fdb")

SNMP_PORT = 161
SYSNAME_OID = "1.3.6.1.2.1.1.5.0"
SYSDESCR_OID = "1.3.6.1.2.1.1.1.0"
FDB_PORT_OID = "1.3.6.1.2.1.17.4.3.1.2"
QBRIDGE_FDB_PORT_OID = "1.3.6.1.2.1.17.7.1.2.2.1.2"
BASE_PORT_IFINDEX_OID = "1.3.6.1.2.1.17.1.4.1.2"
IFNAME_OID = "1.3.6.1.2.1.31.1.1.1.1"

_GETNEXT = 0xA1
_GET = 0xA0
_MAX_ROWS = 4096


def _length(n):
    if n < 128:
        return bytes([n])
    if n < 256:
        return b"\x81" + bytes([n])
    return b"\x82" + n.to_bytes(2, "big")


def _tlv(tag, data):
    return bytes([tag]) + _length(len(data)) + data


def _integer(n):
    return _tlv(2, n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big", signed=True))


def _oid(text):
    parts = [int(x) for x in text.strip(".").split(".")]
    out = bytearray([40 * parts[0] + parts[1]])
    for x in parts[2:]:
        block = [x & 0x7F]
        x >>= 7
        while x:
            block.append(0x80 | (x & 0x7F))
            x >>= 7
        out += bytes(reversed(block))
    return _tlv(6, bytes(out))


def _read_tlv(buf, i):
    tag = buf[i]
    n = buf[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(buf[i:i + k], "big")
        i += k
    return tag, buf[i:i + n], i + n


def _decode(tag, value):
    if tag == 6:
        parts = [value[0] // 40, value[0] % 40]
        x = 0
        for c in value[1:]:
            x = (x << 7) | (c & 0x7F)
            if not c & 0x80:
                parts.append(x)
                x = 0
        return ".".join(map(str, parts))
    if tag == 2:
        return int.from_bytes(value, "big", signed=True)
    if tag in (0x41, 0x42, 0x43, 0x46):
        return int.from_bytes(value, "big")
    if tag == 4:
        return value
    return None


def build_request(community, kind, oids, request_id):
    varbinds = b"".join(_tlv(0x30, _oid(o) + b"\x05\x00") for o in oids)
    pdu = _tlv(kind, _integer(request_id) + _integer(0) + _integer(0) + _tlv(0x30, varbinds))
    return _tlv(0x30, _integer(1) + _tlv(4, community.encode()) + pdu)


def parse_response(data):
    """[(oid, valore)] di una risposta; lista vuota se l'agente segnala un
    errore. Alza ValueError/IndexError se il pacchetto non e' SNMP."""
    _, body, _ = _read_tlv(data, 0)
    _, _, i = _read_tlv(body, 0)
    _, _, i = _read_tlv(body, i)
    _, pdu, _ = _read_tlv(body, i)
    j = 0
    _, _, j = _read_tlv(pdu, j)
    _, err, j = _read_tlv(pdu, j)
    _, _, j = _read_tlv(pdu, j)
    _, varbinds, _ = _read_tlv(pdu, j)
    if int.from_bytes(err, "big"):
        return []
    out, k = [], 0
    while k < len(varbinds):
        _, entry, k = _read_tlv(varbinds, k)
        t1, oid, m = _read_tlv(entry, 0)
        t2, value, _ = _read_tlv(entry, m)
        out.append((_decode(t1, oid), _decode(t2, value)))
    return out


def _request(host, community, kind, oids, timeout, port):
    request_id = int.from_bytes(os.urandom(3), "big")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(build_request(community, kind, oids, request_id), (host, port))
        data, _ = sock.recvfrom(65535)
    finally:
        sock.close()
    return parse_response(data)


def _walk(host, community, base, timeout, port):
    rows, current = {}, base
    for _ in range(_MAX_ROWS):
        reply = _request(host, community, _GETNEXT, [current], timeout, port)
        if not reply:
            break
        oid, value = reply[0]
        if oid is None or not oid.startswith(base + ".") or value is None:
            break
        rows[oid[len(base) + 1:]] = value
        current = oid
    return rows


def _mac_from_index(index):
    parts = index.split(".")[-6:]
    if len(parts) != 6 or not all(p.isdigit() and int(p) < 256 for p in parts):
        return None
    return ":".join(f"{int(p):02x}" for p in parts)


def _text(value):
    return value.decode("utf-8", errors="replace").strip() if isinstance(value, bytes) else None


def read_switch(host, community="public", timeout=2.0, port=SNMP_PORT):
    """{"macs": {mac minuscolo: porta}, "ports": {porta: nome}} oppure None
    se l'apparato non risponde o non espone la tabella MAC. La porta 0 (gli
    indirizzi dello switch stesso) e' esclusa."""
    try:
        if not _request(host, community, _GET, [SYSNAME_OID], timeout, port):
            return None
        fdb = _walk(host, community, FDB_PORT_OID, timeout, port)
        if not fdb:
            fdb = _walk(host, community, QBRIDGE_FDB_PORT_OID, timeout, port)
        macs = {}
        for index, bridge_port in fdb.items():
            mac = _mac_from_index(index)
            if mac and isinstance(bridge_port, int) and bridge_port > 0:
                macs[mac] = bridge_port
        if not macs:
            return None
        ifindex = _walk(host, community, BASE_PORT_IFINDEX_OID, timeout, port)
        ifnames = _walk(host, community, IFNAME_OID, timeout, port)
        ports = {}
        for bridge_port in set(macs.values()):
            name = _text(ifnames.get(str(ifindex.get(str(bridge_port), bridge_port))))
            ports[bridge_port] = name or f"port {bridge_port}"
        return {"macs": macs, "ports": ports}
    except (OSError, ValueError, IndexError):
        log.debug("reading the MAC table of %s failed", host, exc_info=True)
        return None
