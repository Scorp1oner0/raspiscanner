import threading
import unittest
from unittest.mock import patch

from scanner.network import setup as network_setup


class _FakeResult:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = ""


_MULTI_IP_OUTPUT = "\n".join([
    "2: eth0    inet 192.168.1.50/24 brd 192.168.1.255 scope global eth0",
    "2: eth0    inet 10.0.0.20/24 brd 10.0.0.255 scope global secondary eth0",
    "2: eth0    inet 172.16.5.9/16 brd 172.16.255.255 scope global secondary eth0",
])


def _fake_run_multi_ip(cmd, timeout=15):
    if cmd[:5] == ["ip", "-4", "-o", "addr", "show"]:
        return _FakeResult(_MULTI_IP_OUTPUT)
    return _FakeResult()


class TestMultiAddressDetection(unittest.TestCase):
    def setUp(self):
        self._orig_run = network_setup._run
        network_setup._run = _fake_run_multi_ip

    def tearDown(self):
        network_setup._run = self._orig_run

    def test_get_interface_ips_returns_all(self):
        ips = network_setup.get_interface_ips("eth0")
        self.assertEqual(len(ips), 3)
        self.assertIn(("192.168.1.50", 24), ips)
        self.assertIn(("172.16.5.9", 16), ips)

    def test_network_cidr_correct_for_non_24_prefix(self):
        """Bug storico: il calcolo ingenuo (azzerare l'ultimo ottetto)
        sbaglia su prefissi diversi da /24, es. una /16."""
        self.assertEqual(network_setup._network_cidr("172.16.5.9", 16), "172.16.0.0/16")
        self.assertEqual(network_setup._network_cidr("192.168.1.50", 24), "192.168.1.0/24")

    def test_address_list_uses_correct_cidr(self):
        addrs = network_setup._address_list("eth0")
        cidrs = {a["cidr"] for a in addrs}
        self.assertIn("192.168.1.0/24", cidrs)
        self.assertIn("172.16.0.0/16", cidrs)


class TestMultiWifiInterfaces(unittest.TestCase):
    """Bug reale: con piu' schede Wi-Fi fisiche, il tool ne rilevava e
    mostrava solo una (find_default_wifi_iface prendeva sempre la prima e
    _status["wifi"] era un unico dict, non uno per interfaccia)."""

    def setUp(self):
        self._orig_run = network_setup._run
        self._orig_list_ifaces = network_setup.list_interfaces
        network_setup._status["wifi"] = {}

    def tearDown(self):
        network_setup._run = self._orig_run
        network_setup.list_interfaces = self._orig_list_ifaces
        network_setup._status["wifi"] = {}

    def test_list_wifi_ifaces_returns_all_not_just_first(self):
        network_setup.list_interfaces = lambda: ["eth0", "wlan0", "wlan1"]
        self.assertEqual(network_setup.list_wifi_ifaces(), ["wlan0", "wlan1"])

    def test_find_default_wifi_iface_still_returns_one_for_callers_that_want_a_single_default(self):
        network_setup.list_interfaces = lambda: ["wlan1", "wlan0"]
        self.assertEqual(network_setup.find_default_wifi_iface(), "wlan0")

    def test_refresh_wifi_status_tracks_every_interface(self):
        network_setup.list_interfaces = lambda: ["eth0", "wlan0", "wlan1"]

        def fake_run(cmd, timeout=15):
            if cmd[0] == "ip":
                iface = cmd[-1]
                if iface == "wlan0":
                    return _FakeResult("2: wlan0    inet 192.168.1.5/24 scope global wlan0")
                return _FakeResult("")
            if cmd[0] == "iwgetid":
                iface = cmd[2]
                return _FakeResult("CasaWifi") if iface == "wlan0" else _FakeResult("", returncode=1)
            return _FakeResult()

        network_setup._run = fake_run
        network_setup.refresh_wifi_status()
        status = network_setup.get_status()

        self.assertEqual(set(status["wifi"].keys()), {"wlan0", "wlan1"})
        self.assertTrue(status["wifi"]["wlan0"]["up"])
        self.assertEqual(status["wifi"]["wlan0"]["ssid"], "CasaWifi")
        self.assertEqual(status["wifi"]["wlan0"]["ip"], "192.168.1.5")
        self.assertFalse(status["wifi"]["wlan1"]["up"])

    def test_refresh_wifi_status_drops_interfaces_no_longer_present(self):
        """Una scheda USB scollegata non deve restare "fantasma" nello stato."""
        network_setup._status["wifi"] = {
            "wlanUSB": {"iface": "wlanUSB", "up": True, "ssid": None, "ip": None, "cidr": None, "addresses": []},
        }
        network_setup.list_interfaces = lambda: ["eth0"]
        network_setup._run = lambda cmd, timeout=15: _FakeResult()

        network_setup.refresh_wifi_status()
        status = network_setup.get_status()
        self.assertNotIn("wlanUSB", status["wifi"])

    def test_wifi_scan_networks_targets_the_given_interface(self):
        captured = {}

        def fake_run(cmd, timeout=15):
            captured["cmd"] = cmd
            return _FakeResult("CasaWifi:80:WPA2\n")

        network_setup._run = fake_run
        network_setup.wifi_scan_networks(iface="wlan1")
        self.assertIn("ifname", captured["cmd"])
        self.assertIn("wlan1", captured["cmd"])

    def test_wifi_scan_networks_without_iface_omits_ifname(self):
        captured = {}

        def fake_run(cmd, timeout=15):
            captured["cmd"] = cmd
            return _FakeResult("")

        network_setup._run = fake_run
        network_setup.wifi_scan_networks()
        self.assertNotIn("ifname", captured["cmd"])

    def test_wifi_connect_targets_the_given_interface(self):
        captured = {}

        def fake_run(cmd, timeout=15):
            captured["cmd"] = cmd
            return _FakeResult("", returncode=0)

        network_setup._run = fake_run
        network_setup.list_interfaces = lambda: []
        network_setup.wifi_connect("CasaWifi", "password123", iface="wlan1")
        self.assertIn("ifname", captured["cmd"])
        self.assertIn("wlan1", captured["cmd"])


class TestExistingConfigProtected(unittest.TestCase):
    """autoconfigure_ethernet non deve cancellare IP preesistenti che non
    ha assegnato lui stesso (es. IP secondari configurati a mano)."""

    def setUp(self):
        self._orig_run = network_setup._run
        self._orig_carrier = network_setup.has_carrier
        network_setup._run = _fake_run_multi_ip
        network_setup.has_carrier = lambda iface: True
        network_setup._autoconfig_lock = threading.Lock()
        # Stato pulito: il test non deve dipendere dall'ordine di esecuzione
        # rispetto ad altri test che potrebbero aver lasciato mode="dhcp".
        network_setup._status["eth"] = {
            "iface": None, "up": False, "mode": None, "ip": None, "cidr": None,
            "addresses": [], "reconfiguring": False, "error": None, "last_change": None,
        }

    def tearDown(self):
        network_setup._run = self._orig_run
        network_setup.has_carrier = self._orig_carrier

    def test_preexisting_addresses_marked_manual_and_untouched(self):
        network_setup.autoconfigure_ethernet("eth0")
        status = network_setup.get_status()
        self.assertEqual(status["eth"]["mode"], "manuale")
        self.assertEqual(len(status["eth"]["addresses"]), 3)


if __name__ == "__main__":
    unittest.main()
