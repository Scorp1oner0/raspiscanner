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
