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


if __name__ == "__main__":
    unittest.main()
