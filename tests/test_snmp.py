"""Test su scanner.discovery.snmp_probe: nessuna rete reale coinvolta,
parse_snmp_response() e' testata con risposte SNMP costruite a mano
(stesso approccio gia' usato per ONVIF/mDNS/Dot1Q — un dispositivo SNMP
reale non e' disponibile in questa sessione, ma la logica di parsing e'
corretta a prescindere dall'hardware)."""
import unittest

from scapy.layers.snmp import SNMP, SNMPresponse, SNMPvarbind

from scanner.discovery.snmp import (
    SYSDESCR_OID, SYSNAME_OID, parse_snmp_response, snmp_probe,
)


def _response(varbinds):
    # Round-trip byte a byte: un pacchetto scapy appena costruito non ha
    # ancora i campi coercizzati ai tipi ASN.1 veri (es. vb.oid resta una
    # str finche' non viene serializzato e ri-parsato) — sr1() in
    # produzione restituisce sempre un pacchetto ri-parsato dai byte
    # ricevuti, mai un oggetto costruito a mano: il test deve riflettere
    # la stessa condizione, non una piu' comoda ma irrealistica.
    raw = bytes(SNMP(community="public", PDU=SNMPresponse(varbindlist=varbinds)))
    return SNMP(raw)


class TestParseSnmpResponse(unittest.TestCase):
    def test_extracts_sysdescr_and_sysname(self):
        resp = _response([
            SNMPvarbind(oid=SYSDESCR_OID, value="Linux router 5.4.0"),
            SNMPvarbind(oid=SYSNAME_OID, value="my-router"),
        ])
        result = parse_snmp_response(resp)
        self.assertEqual(result, {"sysDescr": "Linux router 5.4.0", "sysName": "my-router"})

    def test_only_sysname_present(self):
        resp = _response([SNMPvarbind(oid=SYSNAME_OID, value="switch-core")])
        result = parse_snmp_response(resp)
        self.assertEqual(result, {"sysName": "switch-core"})

    def test_unrelated_oid_ignored(self):
        resp = _response([SNMPvarbind(oid="1.3.6.1.2.1.1.99.0", value="something else")])
        self.assertEqual(parse_snmp_response(resp), {})

    def test_none_response_returns_empty(self):
        """Nessuna risposta (timeout) e' l'esito normale, non un errore:
        SNMP e' opzionale/spesso disabilitato sulla maggior parte dei
        dispositivi."""
        self.assertEqual(parse_snmp_response(None), {})

    def test_non_snmp_packet_returns_empty(self):
        from scapy.layers.inet import IP
        self.assertEqual(parse_snmp_response(IP()), {})

    def test_empty_value_omitted(self):
        resp = _response([SNMPvarbind(oid=SYSDESCR_OID, value="")])
        self.assertEqual(parse_snmp_response(resp), {})


class TestSnmpProbe(unittest.TestCase):
    """snmp_probe() invia davvero un pacchetto (sr1, richiede root/raw
    socket): qui si verifica solo che senza scapy disponibile degradi a
    {} senza sollevare, coerente con lo stesso trattamento di arp_scan."""

    def test_returns_empty_dict_when_scapy_unavailable(self):
        import scanner.discovery.snmp as mod
        orig = mod.SCAPY_AVAILABLE
        mod.SCAPY_AVAILABLE = False
        try:
            self.assertEqual(snmp_probe("192.168.1.1"), {})
        finally:
            mod.SCAPY_AVAILABLE = orig


if __name__ == "__main__":
    unittest.main()
