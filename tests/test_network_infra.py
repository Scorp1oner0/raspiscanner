import unittest

from scanner.network.infra import classify_network_device


class TestNetworkInfraClassification(unittest.TestCase):
    def test_gateway_ip_is_strong_signal(self):
        is_infra, reasons = classify_network_device("192.168.1.1", "192.168.1.1", "Sconosciuto", {})
        self.assertTrue(is_infra)
        self.assertTrue(any("gateway" in r for r in reasons))

    def test_non_gateway_unknown_vendor_is_not_infra(self):
        is_infra, reasons = classify_network_device("192.168.1.50", "192.168.1.1", "Sconosciuto", {})
        self.assertFalse(is_infra)
        self.assertEqual(reasons, [])

    def test_network_vendor_hint(self):
        is_infra, reasons = classify_network_device("192.168.1.5", "192.168.1.1", "MikroTik", {})
        self.assertTrue(is_infra)

    def test_banner_keyword_hint(self):
        banners = {80: {"server": None, "title": "TP-Link Switch Management"}}
        is_infra, reasons = classify_network_device("192.168.1.5", "192.168.1.1", "Sconosciuto", banners)
        self.assertTrue(is_infra)

    def test_no_gateway_known_falls_back_to_other_signals(self):
        is_infra, _ = classify_network_device("192.168.1.5", None, "Ubiquiti Networks", {})
        self.assertTrue(is_infra)


if __name__ == "__main__":
    unittest.main()
