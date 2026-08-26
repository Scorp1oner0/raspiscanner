"""Test sulla protezione SSRF di get_device_info: il probe ONVIF e'
multicast, quindi l'XAddr ricevuto viene scelto dal dispositivo che
risponde, non da noi. Senza validarlo, get_device_info farebbe una
richiesta HTTP verso QUALUNQUE host/porta un mittente non fidato decida
di annunciare — un IP pubblico, un servizio interno sensibile, ecc."""
import http.client
import unittest

from scanner.cameras import onvif


class TestIsSafeXaddrHost(unittest.TestCase):
    def test_private_lan_address_is_safe(self):
        self.assertTrue(onvif._is_safe_xaddr_host("192.168.1.64"))
        self.assertTrue(onvif._is_safe_xaddr_host("10.0.0.5"))
        self.assertTrue(onvif._is_safe_xaddr_host("172.16.5.9"))

    def test_public_ip_rejected(self):
        """Il caso SSRF vero e proprio: un dispositivo malevolo annuncia
        un XAddr con un IP pubblico arbitrario."""
        self.assertFalse(onvif._is_safe_xaddr_host("8.8.8.8"))
        self.assertFalse(onvif._is_safe_xaddr_host("1.1.1.1"))

    def test_loopback_rejected(self):
        """Evita che un XAddr possa far bussare lo scanner a un servizio
        locale (127.0.0.1:qualcosa) sotto mentite spoglie di una telecamera."""
        self.assertFalse(onvif._is_safe_xaddr_host("127.0.0.1"))

    def test_link_local_rejected(self):
        """169.254.0.0/16: anche il range delle API di metadata cloud
        (169.254.169.254) su alcune piattaforme — da rifiutare sempre."""
        self.assertFalse(onvif._is_safe_xaddr_host("169.254.169.254"))

    def test_multicast_rejected(self):
        self.assertFalse(onvif._is_safe_xaddr_host("239.255.255.250"))

    def test_dns_hostname_rejected(self):
        """Solo IP letterali: un hostname DNS aprirebbe la porta al DNS
        rebinding (risolve a un IP privato al momento del controllo, poi
        a uno pubblico al momento della richiesta vera)."""
        self.assertFalse(onvif._is_safe_xaddr_host("camera.example.com"))
        self.assertFalse(onvif._is_safe_xaddr_host("localhost"))

    def test_garbage_input_does_not_raise(self):
        self.assertFalse(onvif._is_safe_xaddr_host(""))
        self.assertFalse(onvif._is_safe_xaddr_host("not-an-ip-at-all"))


class TestGetDeviceInfoRejectsUnsafeXaddr(unittest.TestCase):
    """get_device_info deve rifiutare l'XAddr PRIMA di aprire qualunque
    connessione, non solo teoricamente: verificato monkeypatchando
    HTTPConnection/HTTPSConnection perche' sollevino se mai chiamate."""

    def setUp(self):
        self._orig_http = http.client.HTTPConnection
        self._orig_https = http.client.HTTPSConnection

        def _fail(*a, **k):
            raise AssertionError("non doveva aprire nessuna connessione")

        http.client.HTTPConnection = _fail
        http.client.HTTPSConnection = _fail

    def tearDown(self):
        http.client.HTTPConnection = self._orig_http
        http.client.HTTPSConnection = self._orig_https

    def test_public_ip_xaddr_never_connected_to(self):
        info = onvif.get_device_info("http://8.8.8.8/onvif/device_service")
        self.assertEqual(info, {})

    def test_dns_hostname_xaddr_never_connected_to(self):
        info = onvif.get_device_info("http://camera.example.com/onvif/device_service")
        self.assertEqual(info, {})

    def test_loopback_xaddr_never_connected_to(self):
        info = onvif.get_device_info("http://127.0.0.1:8080/onvif/device_service")
        self.assertEqual(info, {})


class TestExtractBetween(unittest.TestCase):
    """Fallback a sottostringa usato quando l'XML e' malformato. Bug reale
    corretto qui: la vecchia versione cercava il tag di chiusura con un
    find() sulla stessa stringa bare del tag ("manufacturer"), che matcha
    dentro "</tds:Manufacturer>" a meta' del tag di chiusura stesso —
    il valore estratto includeva sempre un "</" (o "</prefisso:") finale."""

    def test_prefixed_closing_tag_no_longer_leaks_closing_bracket(self):
        value = onvif._extract_between("<tds:Manufacturer>Hikvision</tds:Manufacturer>", "manufacturer")
        self.assertEqual(value, "Hikvision")

    def test_unprefixed_closing_tag_no_longer_leaks_closing_bracket(self):
        value = onvif._extract_between("<Manufacturer>Hikvision</Manufacturer>", "manufacturer")
        self.assertEqual(value, "Hikvision")

    def test_missing_tag_returns_none(self):
        self.assertIsNone(onvif._extract_between("<a>x</a>", "manufacturer"))


class TestParseProbeResponse(unittest.TestCase):
    """P2: sostituisce il vecchio parsing a sottostringa con un parser XML
    vero (xml.etree.ElementTree), tollerante a prefissi di namespace
    diversi tra vendor — con fallback a sottostringa solo se l'XML e'
    davvero malformato, invece di perdere il dato per intero."""

    def test_standard_ws_discovery_response(self):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
        <e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
                    xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
                    xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
          <e:Body>
            <d:ProbeMatches>
              <d:ProbeMatch>
                <d:Types>dn:NetworkVideoTransmitter</d:Types>
                <d:XAddrs>http://192.168.1.64/onvif/device_service</d:XAddrs>
              </d:ProbeMatch>
            </d:ProbeMatches>
          </e:Body>
        </e:Envelope>"""
        xaddrs, types = onvif._parse_probe_response(xml)
        self.assertEqual(xaddrs, ["http://192.168.1.64/onvif/device_service"])
        self.assertEqual(types, "dn:NetworkVideoTransmitter")

    def test_multiple_xaddrs_space_separated(self):
        xml = """<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
          <Body><ProbeMatches><ProbeMatch>
            <XAddrs xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery">
              http://192.168.1.64/onvif/device_service http://10.0.0.5/onvif/device_service
            </XAddrs>
          </ProbeMatch></ProbeMatches></Body>
        </Envelope>"""
        xaddrs, _ = onvif._parse_probe_response(xml)
        self.assertEqual(xaddrs, [
            "http://192.168.1.64/onvif/device_service",
            "http://10.0.0.5/onvif/device_service",
        ])

    def test_different_namespace_prefix_still_matches(self):
        """Vendor diversi non usano sempre lo stesso prefisso ("d:", "wsd:",
        nessuno...): il match e' sul nome locale dell'elemento, non sul
        prefisso letterale, a differenza del vecchio "<d:xaddrs" hardcoded."""
        xml = """<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
                                 xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">
          <soap:Body><wsd:ProbeMatches><wsd:ProbeMatch>
            <wsd:XAddrs>http://192.168.1.64/onvif/device_service</wsd:XAddrs>
            <wsd:Types>NetworkVideoTransmitter</wsd:Types>
          </wsd:ProbeMatch></wsd:ProbeMatches></soap:Body>
        </soap:Envelope>"""
        xaddrs, types = onvif._parse_probe_response(xml)
        self.assertEqual(xaddrs, ["http://192.168.1.64/onvif/device_service"])
        self.assertEqual(types, "NetworkVideoTransmitter")

    def test_malformed_xml_falls_back_to_substring_extraction(self):
        """Non tutti i firmware ONVIF producono XML valido: un tag non
        chiuso non deve far perdere il dato per intero."""
        broken = '<e:Envelope><d:XAddrs>http://192.168.1.64/onvif/device_service</d:XAddrs>'
        xaddrs, _ = onvif._parse_probe_response(broken)
        self.assertEqual(xaddrs, ["http://192.168.1.64/onvif/device_service"])

    def test_no_match_returns_empty(self):
        xaddrs, types = onvif._parse_probe_response("<Envelope></Envelope>")
        self.assertEqual(xaddrs, [])
        self.assertEqual(types, "")

    def test_doctype_rejected_before_parsing(self):
        """Mitigazione "billion laughs": un documento con DOCTYPE viene
        rifiutato a priori (nessuna risposta ONVIF legittima ne usa uno),
        invece di lasciar espandere entita' definite in una DTD."""
        malicious = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE root [<!ENTITY a "x"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>'
            '<d:XAddrs>&b;</d:XAddrs>'
        )
        xaddrs, _ = onvif._parse_probe_response(malicious)
        # Rifiutato dal parser XML vero (DOCTYPE bloccato): ricade sul
        # fallback a sottostringa, che non risolve MAI le entita' — deve
        # restituire il testo letterale "&b;", non la stringa espansa.
        self.assertNotIn("xxxxxxxxxx", " ".join(xaddrs))


class TestParseDeviceInfo(unittest.TestCase):
    def test_standard_get_device_information_response(self):
        xml = """<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
                                 xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
          <soap:Body><tds:GetDeviceInformationResponse>
            <tds:Manufacturer>Hikvision</tds:Manufacturer>
            <tds:Model>DS-2CD2043G0</tds:Model>
            <tds:FirmwareVersion>V5.5.80</tds:FirmwareVersion>
          </tds:GetDeviceInformationResponse></soap:Body>
        </soap:Envelope>"""
        info = onvif._parse_device_info(xml)
        self.assertEqual(info, {
            "manufacturer": "Hikvision", "model": "DS-2CD2043G0", "firmware": "V5.5.80",
        })

    def test_malformed_xml_falls_back_to_substring_extraction(self):
        broken = "<Manufacturer>Dahua<Model>IPC-HDW</Model>"
        info = onvif._parse_device_info(broken)
        self.assertEqual(info.get("model"), "IPC-HDW")

    def test_missing_fields_omitted_not_empty_strings(self):
        xml = "<a><Manufacturer>Axis</Manufacturer></a>"
        info = onvif._parse_device_info(xml)
        self.assertEqual(info, {"manufacturer": "Axis"})


class TestGetDeviceInfoMulti(unittest.TestCase):
    """P2: prova ogni XAddr annunciato in ordine invece di fermarsi al
    primo — un dispositivo puo' annunciarne piu' di uno (interfacce di
    rete diverse) e non c'e' garanzia che il primo sia il raggiungibile."""

    def setUp(self):
        self._orig_get_device_info = onvif.get_device_info

    def tearDown(self):
        onvif.get_device_info = self._orig_get_device_info

    def test_returns_first_successful_result(self):
        def fake(xaddr, timeout=3):
            return {"manufacturer": "Hikvision"} if xaddr == "http://10.0.0.2/onvif" else {}
        onvif.get_device_info = fake
        info = onvif.get_device_info_multi(["http://10.0.0.1/onvif", "http://10.0.0.2/onvif"])
        self.assertEqual(info, {"manufacturer": "Hikvision"})

    def test_all_fail_returns_empty(self):
        onvif.get_device_info = lambda xaddr, timeout=3: {}
        info = onvif.get_device_info_multi(["http://10.0.0.1/onvif", "http://10.0.0.2/onvif"])
        self.assertEqual(info, {})

    def test_empty_list_returns_empty_without_calling(self):
        def fail(*a, **k):
            raise AssertionError("non doveva essere chiamata")
        onvif.get_device_info = fail
        self.assertEqual(onvif.get_device_info_multi([]), {})


if __name__ == "__main__":
    unittest.main()
