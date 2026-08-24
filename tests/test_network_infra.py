import unittest

from scanner.network.infra import classify_network_device


class TestNetworkInfraClassification(unittest.TestCase):
    def test_gateway_ip_is_strong_signal(self):
        is_infra, subtype, reasons = classify_network_device("192.168.1.1", "192.168.1.1", "Sconosciuto", {})
        self.assertTrue(is_infra)
        self.assertEqual(subtype, "Router")
        self.assertTrue(any("gateway" in r for r in reasons))

    def test_non_gateway_unknown_vendor_is_not_infra(self):
        is_infra, subtype, reasons = classify_network_device("192.168.1.50", "192.168.1.1", "Sconosciuto", {})
        self.assertFalse(is_infra)
        self.assertIsNone(subtype)
        self.assertEqual(reasons, [])

    def test_network_vendor_hint(self):
        is_infra, subtype, reasons = classify_network_device("192.168.1.5", "192.168.1.1", "MikroTik", {})
        self.assertTrue(is_infra)
        # solo il vendor, nessun banner/gateway: nessun sottotipo specifico
        self.assertIsNone(subtype)

    def test_banner_keyword_hint(self):
        banners = {80: {"server": None, "title": "TP-Link Switch Management"}}
        is_infra, subtype, reasons = classify_network_device("192.168.1.5", "192.168.1.1", "Sconosciuto", banners)
        self.assertTrue(is_infra)
        self.assertEqual(subtype, "Switch")

    def test_access_point_banner_keyword(self):
        banners = {80: {"server": None, "title": "Access Point Configuration"}}
        is_infra, subtype, reasons = classify_network_device("192.168.1.5", "192.168.1.1", "Sconosciuto", banners)
        self.assertTrue(is_infra)
        self.assertEqual(subtype, "Access Point")

    def test_gateway_subtype_wins_over_banner_keyword(self):
        """Se e' il gateway MA il banner dice anche 'switch', vince Router:
        instrada il traffico, quindi e' prima di tutto un router."""
        banners = {80: {"server": None, "title": "Managed Switch"}}
        is_infra, subtype, reasons = classify_network_device("192.168.1.1", "192.168.1.1", "Sconosciuto", banners)
        self.assertTrue(is_infra)
        self.assertEqual(subtype, "Router")

    def test_no_gateway_known_falls_back_to_other_signals(self):
        is_infra, subtype, _ = classify_network_device("192.168.1.5", None, "Ubiquiti Networks", {})
        self.assertTrue(is_infra)


if __name__ == "__main__":
    unittest.main()
