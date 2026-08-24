import unittest

from scanner.network import hotspot


class _FakeResult:
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = stderr


class TestGeneratePassword(unittest.TestCase):
    def test_default_length(self):
        self.assertEqual(len(hotspot.generate_password()), 12)

    def test_custom_length(self):
        self.assertEqual(len(hotspot.generate_password(20)), 20)

    def test_meets_minimum_length(self):
        self.assertGreaterEqual(len(hotspot.generate_password()), hotspot.MIN_PASSWORD_LENGTH)


class TestDefaultSsid(unittest.TestCase):
    def test_from_mac(self):
        self.assertEqual(hotspot.default_ssid(mac="b8:27:eb:11:22:33"), "RaspiScanner-2233")

    def test_no_mac_available(self):
        self.assertEqual(hotspot.default_ssid(mac=None, iface="iface-inesistente"), "RaspiScanner-0000")


class TestStartHotspotValidation(unittest.TestCase):
    """La validazione avviene PRIMA di chiamare nmcli: questi test non
    devono toccare subprocess."""

    def setUp(self):
        self._orig_run = hotspot._run
        hotspot._run = lambda *a, **k: (_ for _ in ()).throw(AssertionError("_run non doveva essere chiamato"))

    def tearDown(self):
        hotspot._run = self._orig_run

    def test_empty_ssid_rejected(self):
        ok, message = hotspot.start_hotspot("wlan0", "", "password123")
        self.assertFalse(ok)
        self.assertIn("SSID", message)

    def test_whitespace_only_ssid_rejected(self):
        ok, _ = hotspot.start_hotspot("wlan0", "   ", "password123")
        self.assertFalse(ok)

    def test_short_password_rejected(self):
        ok, message = hotspot.start_hotspot("wlan0", "MiaRete", "corta")
        self.assertFalse(ok)
        self.assertIn("8", message)

    def test_empty_password_rejected(self):
        ok, _ = hotspot.start_hotspot("wlan0", "MiaRete", "")
        self.assertFalse(ok)


class TestStartHotspotSuccess(unittest.TestCase):
    def setUp(self):
        self._orig_run = hotspot._run
        self.calls = []

        def fake_run(cmd, timeout=20):
            self.calls.append(cmd)
            return _FakeResult(returncode=0)

        hotspot._run = fake_run

    def tearDown(self):
        hotspot._run = self._orig_run

    def test_deletes_old_profile_before_creating_new(self):
        ok, message = hotspot.start_hotspot("wlan0", "MiaRete", "password123")
        self.assertTrue(ok)
        self.assertEqual(self.calls[0][:3], ["nmcli", "connection", "delete"])
        self.assertIn("hotspot", self.calls[1])
        self.assertIn("MiaRete", self.calls[1])
        self.assertIn("password123", self.calls[1])


class TestGetHotspotStatus(unittest.TestCase):
    def setUp(self):
        self._orig_run = hotspot._run

    def tearDown(self):
        hotspot._run = self._orig_run

    def test_not_active(self):
        hotspot._run = lambda cmd, timeout=20: _FakeResult(stdout="altra-connessione:eth0\n", returncode=0)
        status = hotspot.get_hotspot_status()
        self.assertFalse(status["active"])
        self.assertIsNone(status["ip"])

    def test_active_parses_ssid_and_ip(self):
        def fake_run(cmd, timeout=20):
            if cmd[:4] == ["nmcli", "-t", "-f", "NAME,DEVICE"]:
                return _FakeResult(stdout=f"{hotspot.HOTSPOT_CONNECTION_NAME}:wlan0\n", returncode=0)
            if "802-11-wireless.ssid" in cmd:
                return _FakeResult(stdout="802-11-wireless.ssid:MiaRete\n", returncode=0)
            if cmd[:3] == ["nmcli", "-t", "-f"] and "device" in cmd:
                return _FakeResult(stdout="IP4.ADDRESS[1]:10.42.0.1/24\n", returncode=0)
            return _FakeResult(returncode=1)

        hotspot._run = fake_run
        status = hotspot.get_hotspot_status()
        self.assertTrue(status["active"])
        self.assertEqual(status["ssid"], "MiaRete")
        self.assertEqual(status["ip"], "10.42.0.1")
        self.assertEqual(status["iface"], "wlan0")

    def test_nmcli_unavailable(self):
        hotspot._run = lambda cmd, timeout=20: None
        status = hotspot.get_hotspot_status()
        self.assertFalse(status["active"])


if __name__ == "__main__":
    unittest.main()
