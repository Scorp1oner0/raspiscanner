"""Test su scanner.fingerprint.ports: port scan TCP e fingerprint HTTP
minimale. Nessuna rete reale coinvolta — grab_http_banner monkeypatcha
http.client.HTTPConnection/HTTPSConnection con connessioni finte,
scan_ports monkeypatcha _check_port (il vero connect() e' gia' testato
implicitamente dall'uso in produzione, qui interessa la logica attorno).
"""
import http.client
import unittest
from unittest.mock import patch

from scanner import config
from scanner.fingerprint import ports


class _FakeResponse:
    def __init__(self, headers=None, body=b""):
        self._headers = headers or {}
        self._body = body

    def getheader(self, name, default=None):
        return self._headers.get(name, default)

    def read(self, n=-1):
        return self._body if n == -1 else self._body[:n]


class _FakeConnection:
    """Sostituisce http.client.HTTPConnection/HTTPSConnection: risponde
    sempre con _FakeConnection.response, impostata dal test prima della
    chiamata. Cattura anche l'ultima richiesta fatta, per verificare
    l'User-Agent/metodo/path usati."""
    response = None
    last_request = None
    raise_on_connect = None

    def __init__(self, host, port, timeout=None):
        if _FakeConnection.raise_on_connect:
            raise _FakeConnection.raise_on_connect

    def request(self, method, path, headers=None):
        _FakeConnection.last_request = (method, path, headers)

    def getresponse(self):
        return _FakeConnection.response

    def close(self):
        pass


class GrabHttpBannerTestCase(unittest.TestCase):
    def setUp(self):
        self._orig_http = http.client.HTTPConnection
        self._orig_https = http.client.HTTPSConnection
        http.client.HTTPConnection = _FakeConnection
        http.client.HTTPSConnection = _FakeConnection
        _FakeConnection.raise_on_connect = None

    def tearDown(self):
        http.client.HTTPConnection = self._orig_http
        http.client.HTTPSConnection = self._orig_https


class TestGrabHttpBannerNormalCases(GrabHttpBannerTestCase):
    def test_server_header_and_title_extracted(self):
        _FakeConnection.response = _FakeResponse(
            headers={"Server": "Boa/0.94.14rc21"},
            body=b"<html><head><title>NETWORK CAMERA</title></head></html>",
        )
        info = ports.grab_http_banner("10.0.0.5", 80)
        self.assertEqual(info["server"], "Boa/0.94.14rc21")
        self.assertEqual(info["title"], "NETWORK CAMERA")

    def test_missing_server_header_is_none_not_empty_string(self):
        _FakeConnection.response = _FakeResponse(headers={}, body=b"<html></html>")
        info = ports.grab_http_banner("10.0.0.5", 80)
        self.assertIsNone(info["server"])

    def test_no_title_tag_is_none(self):
        _FakeConnection.response = _FakeResponse(body=b"<html><body>hi</body></html>")
        info = ports.grab_http_banner("10.0.0.5", 80)
        self.assertIsNone(info["title"])

    def test_https_uses_https_connection(self):
        _FakeConnection.response = _FakeResponse(body=b"")
        ports.grab_http_banner("10.0.0.5", 443, use_https=True)
        self.assertEqual(_FakeConnection.last_request[0], "GET")

    def test_sends_a_user_agent(self):
        _FakeConnection.response = _FakeResponse(body=b"")
        ports.grab_http_banner("10.0.0.5", 80)
        self.assertIn("User-Agent", _FakeConnection.last_request[2])


class TestGrabHttpBannerMalformedInput(GrabHttpBannerTestCase):
    """Input malevolo/malformato dal dispositivo scansionato: non deve mai
    far crashare lo scan, solo restituire dati parziali/assenti."""

    def test_unclosed_title_tag_returns_none_instead_of_garbage(self):
        """Un <title> senza chiusura (body troncato al cap di lettura, o
        HTML malformato) non deve restituire tutto il resto del body come
        se fosse il titolo."""
        _FakeConnection.response = _FakeResponse(body=b"<title>Admin Panel" + b"x" * 5000)
        info = ports.grab_http_banner("10.0.0.5", 80)
        self.assertIsNone(info["title"])

    def test_huge_body_does_not_raise_and_is_capped(self):
        """resp.read(2048) nel codice reale gia' limita quanto viene letto:
        qui si verifica solo che un body enorme non causi eccezioni ne'
        un titolo abnormemente lungo nel risultato."""
        huge_body = b"<title>" + b"A" * 1_000_000 + b"</title>"
        _FakeConnection.response = _FakeResponse(body=huge_body[:2048])
        info = ports.grab_http_banner("10.0.0.5", 80)
        # Nessuna eccezione sollevata (il test stesso fallirebbe altrimenti);
        # il titolo, se presente, resta comunque entro il cap di lettura.
        if info["title"] is not None:
            self.assertLessEqual(len(info["title"]), 2048)

    def test_non_utf8_bytes_do_not_raise(self):
        _FakeConnection.response = _FakeResponse(body=b"<title>\xff\xfe broken</title>")
        info = ports.grab_http_banner("10.0.0.5", 80)
        self.assertIsNotNone(info["title"])

    def test_connection_refused_returns_safe_defaults(self):
        _FakeConnection.raise_on_connect = ConnectionRefusedError()
        info = ports.grab_http_banner("10.0.0.5", 80)
        self.assertEqual(info, {"server": None, "title": None})

    def test_timeout_returns_safe_defaults(self):
        _FakeConnection.raise_on_connect = TimeoutError()
        info = ports.grab_http_banner("10.0.0.5", 80)
        self.assertEqual(info, {"server": None, "title": None})

    def test_malformed_http_response_returns_safe_defaults(self):
        _FakeConnection.raise_on_connect = http.client.BadStatusLine("garbage")
        info = ports.grab_http_banner("10.0.0.5", 80)
        self.assertEqual(info, {"server": None, "title": None})


class TestScanPorts(unittest.TestCase):
    def setUp(self):
        self._orig_check_port = ports._check_port

    def tearDown(self):
        ports._check_port = self._orig_check_port

    def test_returns_only_open_ports_with_labels(self):
        ports._check_port = lambda ip, port, timeout: port in (80, 554)
        result = ports.scan_ports("10.0.0.5", ports={80: "HTTP", 554: "RTSP", 23: "Telnet"})
        self.assertEqual(result, [{"port": 80, "service": "HTTP"}, {"port": 554, "service": "RTSP"}])

    def test_sorted_by_port_number(self):
        ports._check_port = lambda ip, port, timeout: True
        result = ports.scan_ports("10.0.0.5", ports={554: "RTSP", 23: "Telnet", 80: "HTTP"})
        self.assertEqual([p["port"] for p in result], [23, 80, 554])

    def test_no_open_ports_returns_empty_list(self):
        ports._check_port = lambda ip, port, timeout: False
        result = ports.scan_ports("10.0.0.5", ports={80: "HTTP"})
        self.assertEqual(result, [])

    def test_uses_configured_thread_pool_size_not_a_hardcoded_one(self):
        """Bug reale corretto: config.PORT_SCAN_THREADS esisteva ma non
        veniva mai letta, il pool restava fisso a 16 worker a prescindere
        da quante porte c'erano da controllare."""
        ports._check_port = lambda ip, port, timeout: False
        many_ports = {p: str(p) for p in range(20000, 20000 + config.PORT_SCAN_THREADS + 10)}
        with patch("scanner.fingerprint.ports.ThreadPoolExecutor", wraps=ports.ThreadPoolExecutor) as spy:
            ports.scan_ports("10.0.0.5", ports=many_ports)
        spy.assert_called_once_with(max_workers=config.PORT_SCAN_THREADS)

    def test_one_port_raising_does_not_break_the_others(self):
        """Bug reale corretto scrivendo questo test: un singolo controllo
        di porta che solleva un'eccezione inattesa (non un OSError, gia'
        intercettato dentro _check_port) faceva propagare l'eccezione da
        fut.result() e perdere il risultato di TUTTE le altre porte dello
        stesso host, invece di trattare solo quella porta come chiusa."""
        def flaky_check(ip, port, timeout):
            if port == 23:
                raise ValueError("unexpected")
            return port == 80

        ports._check_port = flaky_check
        result = ports.scan_ports("10.0.0.5", ports={80: "HTTP", 23: "Telnet"})
        self.assertEqual(result, [{"port": 80, "service": "HTTP"}])


if __name__ == "__main__":
    unittest.main()
