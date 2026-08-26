import threading
import unittest
from unittest.mock import patch

from scanner import config
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


class TestProbePresetClasses(unittest.TestCase):
    """Bug reale segnalato dall'utente: probe_preset_classes (ex
    try_preset_classes) si fermava alla prima classe "viva" trovata,
    nascondendo eventuali altre classi vive sullo stesso cavo e scegliendo
    per un ordine di priorita' arbitrario invece di lasciar scegliere
    all'utente quale scansionare davvero."""

    def setUp(self):
        self._orig_run = network_setup._run
        self._orig_arp_scan = network_setup.arp_scan
        network_setup._run = lambda cmd, timeout=15: _FakeResult()

    def tearDown(self):
        network_setup._run = self._orig_run
        network_setup.arp_scan = self._orig_arp_scan

    def test_no_class_alive_returns_empty(self):
        network_setup.arp_scan = lambda cidr, iface, timeout=None, psrc=None: []
        self.assertEqual(network_setup.probe_preset_classes("eth0"), [])

    def test_single_alive_class_returned_with_host_count(self):
        target_cidr = config.PRESET_SUBNETS[0]["cidr"]

        def fake_arp_scan(cidr, iface, timeout=None, psrc=None):
            return [{"ip": "1.1.1.1", "mac": "aa"}] if cidr == target_cidr else []

        network_setup.arp_scan = fake_arp_scan
        result = network_setup.probe_preset_classes("eth0")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["cidr"], target_cidr)
        self.assertEqual(result[0]["hosts_found"], 1)

    def test_multiple_alive_classes_all_returned_not_just_first(self):
        cidr_a = config.PRESET_SUBNETS[0]["cidr"]
        cidr_b = config.PRESET_SUBNETS[2]["cidr"]

        def fake_arp_scan(cidr, iface, timeout=None, psrc=None):
            if cidr == cidr_a:
                return [{"ip": "1.1.1.1", "mac": "aa"}]
            if cidr == cidr_b:
                return [{"ip": "2.2.2.2", "mac": "bb"}, {"ip": "2.2.2.3", "mac": "cc"}]
            return []

        network_setup.arp_scan = fake_arp_scan
        result = network_setup.probe_preset_classes("eth0")
        by_cidr = {r["cidr"]: r for r in result}
        self.assertEqual(set(by_cidr), {cidr_a, cidr_b})
        self.assertEqual(by_cidr[cidr_a]["hosts_found"], 1)
        self.assertEqual(by_cidr[cidr_b]["hosts_found"], 2)


class TestChoosePresetClass(unittest.TestCase):
    def setUp(self):
        self._orig_run = network_setup._run
        network_setup._run = lambda cmd, timeout=15: _FakeResult()
        network_setup._status["eth"] = {
            "iface": None, "up": False, "mode": "choose-network", "ip": None, "cidr": None,
            "addresses": [], "reconfiguring": False, "error": None, "last_change": None,
            "candidates": [
                {"cidr": "192.168.1.0/24", "static_ip": "192.168.1.250", "hosts_found": 2},
                {"cidr": "192.168.0.0/24", "static_ip": "192.168.0.250", "hosts_found": 1},
            ],
        }

    def tearDown(self):
        network_setup._run = self._orig_run

    def test_valid_cidr_assigns_and_clears_candidates(self):
        ok, _ = network_setup.choose_preset_class("eth0", "192.168.1.0/24")
        self.assertTrue(ok)
        status = network_setup.get_status()
        self.assertEqual(status["eth"]["mode"], "static-fallback")
        self.assertEqual(status["eth"]["cidr"], "192.168.1.0/24")
        self.assertEqual(status["eth"]["ip"], "192.168.1.250")
        self.assertEqual(status["eth"]["candidates"], [])

    def test_unknown_cidr_rejected(self):
        ok, message = network_setup.choose_preset_class("eth0", "9.9.9.0/24")
        self.assertFalse(ok)
        self.assertIn("Unknown", message)


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
        self.assertEqual(status["eth"]["mode"], "manual")
        self.assertEqual(len(status["eth"]["addresses"]), 3)


if __name__ == "__main__":
    unittest.main()
