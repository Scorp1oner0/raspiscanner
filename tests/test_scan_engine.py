import unittest

from scanner import scan_engine


class TestActiveNetworks(unittest.TestCase):
    def setUp(self):
        self._orig_get_status = scan_engine.network_setup.get_status

    def tearDown(self):
        scan_engine.network_setup.get_status = self._orig_get_status

    def test_includes_vpn_networks(self):
        """Bug reale: le VPN (WireGuard, OpenVPN...) non finivano mai tra
        le reti scansionate, anche quando attive e con un indirizzo IP
        valido — restavano completamente invisibili allo scan."""
        scan_engine.network_setup.get_status = lambda: {
            "eth": {"up": False, "iface": "eth0", "addresses": []},
            "wifi": {},
            "vpn": {
                "wg0": {"up": True, "iface": "wg0", "addresses": [{"ip": "10.0.0.3", "cidr": "10.0.0.0/24"}]},
            },
        }
        self.assertEqual(scan_engine._active_networks(), [("wg0", "10.0.0.0/24", "10.0.0.3")])

    def test_skips_vpn_interface_that_is_down(self):
        scan_engine.network_setup.get_status = lambda: {
            "eth": {"up": False, "iface": "eth0", "addresses": []},
            "wifi": {},
            "vpn": {
                "wg0": {"up": False, "iface": "wg0", "addresses": []},
            },
        }
        self.assertEqual(scan_engine._active_networks(), [])

    def test_combines_eth_wifi_and_vpn(self):
        scan_engine.network_setup.get_status = lambda: {
            "eth": {"up": True, "iface": "eth0", "addresses": [{"ip": "192.168.88.249", "cidr": "192.168.88.0/24"}]},
            "wifi": {
                "wlan0": {"up": True, "iface": "wlan0", "addresses": [{"ip": "192.168.1.253", "cidr": "192.168.1.0/24"}]},
            },
            "vpn": {
                "wg0": {"up": True, "iface": "wg0", "addresses": [{"ip": "10.0.0.3", "cidr": "10.0.0.0/24"}]},
            },
        }
        result = set(scan_engine._active_networks())
        self.assertEqual(result, {
            ("eth0", "192.168.88.0/24", "192.168.88.249"),
            ("wlan0", "192.168.1.0/24", "192.168.1.253"),
            ("wg0", "10.0.0.0/24", "10.0.0.3"),
        })


class TestOrphanOnvifIps(unittest.TestCase):
    """_orphan_onvif_ips e' pura (nessuna rete reale coinvolta): un IP che
    ha risposto al probe ONVIF ma non e' mai stato trovato dall'ARP scan su
    nessuna rete attiva e' "orfano" nel senso di "non confermato dall'ARP",
    non necessariamente "fuori rete" — quella distinzione la fa
    _classify_orphan_ips (vedi sotto)."""

    def test_ip_not_in_known_ips_is_orphan(self):
        onvif_results = {"192.168.1.64": {"xaddrs": ["http://192.168.1.64/onvif"]}}
        known_ips = {"192.168.88.1", "192.168.88.2"}
        self.assertEqual(scan_engine._orphan_onvif_ips(onvif_results, known_ips), ["192.168.1.64"])

    def test_ip_in_known_ips_is_not_orphan(self):
        onvif_results = {"192.168.88.5": {"xaddrs": []}}
        known_ips = {"192.168.88.5"}
        self.assertEqual(scan_engine._orphan_onvif_ips(onvif_results, known_ips), [])

    def test_mixed_orphan_and_known(self):
        onvif_results = {
            "192.168.88.5": {"xaddrs": []},
            "10.0.0.99": {"xaddrs": []},
        }
        known_ips = {"192.168.88.5"}
        self.assertEqual(scan_engine._orphan_onvif_ips(onvif_results, known_ips), ["10.0.0.99"])

    def test_no_onvif_results_no_orphans(self):
        self.assertEqual(scan_engine._orphan_onvif_ips({}, {"192.168.88.1"}), [])


class TestMatchActiveNetwork(unittest.TestCase):
    def test_ip_inside_active_cidr(self):
        networks = [("eth0", "192.168.1.0/24", "192.168.1.253")]
        self.assertEqual(scan_engine._match_active_network("192.168.1.64", networks), ("eth0", "192.168.1.0/24"))

    def test_ip_outside_all_active_cidrs(self):
        networks = [("eth0", "192.168.88.0/24", "192.168.88.249")]
        self.assertIsNone(scan_engine._match_active_network("192.168.1.64", networks))

    def test_picks_matching_network_among_several(self):
        networks = [
            ("eth0", "192.168.88.0/24", "192.168.88.249"),
            ("wlan0", "192.168.1.0/24", "192.168.1.253"),
        ]
        self.assertEqual(scan_engine._match_active_network("192.168.1.64", networks), ("wlan0", "192.168.1.0/24"))

    def test_no_active_networks(self):
        self.assertIsNone(scan_engine._match_active_network("192.168.1.64", []))

    def test_invalid_ip_returns_none(self):
        networks = [("eth0", "192.168.1.0/24", "192.168.1.253")]
        self.assertIsNone(scan_engine._match_active_network("not-an-ip", networks))


class TestClassifyOrphanIps(unittest.TestCase):
    """Bug reale: una camera "orfana" (vista solo via ONVIF) il cui IP
    ricade comunque in una rete gia' attiva veniva SEMPRE etichettata
    "fuori rete", anche quando l'ARP l'aveva semplicemente mancata in
    quel giro (host lento, pacchetto perso) — visivamente confusa con una
    vera camera fuori rete pur avendo un IP identico alle altre subnet
    scansionate."""

    def test_in_range_ip_goes_to_in_range(self):
        networks = [("eth0", "192.168.1.0/24", "192.168.1.253")]
        in_range, out_of_range = scan_engine._classify_orphan_ips(["192.168.1.64"], networks)
        self.assertEqual(in_range, [("192.168.1.64", "eth0", "192.168.1.0/24")])
        self.assertEqual(out_of_range, [])

    def test_out_of_range_ip_goes_to_out_of_range(self):
        networks = [("eth0", "192.168.88.0/24", "192.168.88.249")]
        in_range, out_of_range = scan_engine._classify_orphan_ips(["192.168.1.64"], networks)
        self.assertEqual(in_range, [])
        self.assertEqual(out_of_range, ["192.168.1.64"])

    def test_mixed_ips_split_correctly(self):
        networks = [("eth0", "192.168.88.0/24", "192.168.88.249")]
        in_range, out_of_range = scan_engine._classify_orphan_ips(
            ["192.168.88.50", "10.0.0.9"], networks,
        )
        self.assertEqual(in_range, [("192.168.88.50", "eth0", "192.168.88.0/24")])
        self.assertEqual(out_of_range, ["10.0.0.9"])

    def test_no_orphans_no_output(self):
        networks = [("eth0", "192.168.1.0/24", "192.168.1.253")]
        self.assertEqual(scan_engine._classify_orphan_ips([], networks), ([], []))


class TestBuildOrphanOnvifDevice(unittest.TestCase):
    def setUp(self):
        self._orig_get_device_info = scan_engine.get_device_info

    def tearDown(self):
        scan_engine.get_device_info = self._orig_get_device_info

    def test_no_manufacturer_available(self):
        scan_engine.get_device_info = lambda xaddr, timeout=3: {}
        onvif_info = {"xaddrs": ["http://192.168.1.64/onvif/device_service"], "types": "NetworkVideoTransmitter"}
        device = scan_engine._build_orphan_onvif_device("192.168.1.64", onvif_info, "eth0")

        self.assertEqual(device["ip"], "192.168.1.64")
        self.assertIsNone(device["mac"])
        self.assertEqual(device["vendor"], "Unknown")
        self.assertIsNone(device["model"])
        self.assertEqual(device["open_ports"], [])
        self.assertTrue(device["is_camera"])
        self.assertFalse(device["is_nvr"])
        self.assertEqual(device["device_type"], "Camera")
        self.assertTrue(device["network_mismatch"])
        self.assertEqual(device["iface"], "eth0")
        self.assertIsNone(device["network"])
        self.assertEqual(device["onvif_xaddr"], "http://192.168.1.64/onvif/device_service")
        self.assertTrue(device["reasons"])

    def test_manufacturer_and_model_from_get_device_information(self):
        scan_engine.get_device_info = lambda xaddr, timeout=3: {
            "manufacturer": "Hikvision", "model": "DS-2CD2043G0",
        }
        onvif_info = {"xaddrs": ["http://192.168.1.64/onvif/device_service"], "types": ""}
        device = scan_engine._build_orphan_onvif_device("192.168.1.64", onvif_info, "wlan0")

        self.assertEqual(device["vendor"], "Hikvision")
        self.assertEqual(device["model"], "DS-2CD2043G0")

    def test_no_xaddrs_skips_device_info_lookup(self):
        def fail(*a, **k):
            raise AssertionError("get_device_info non doveva essere chiamata senza xaddrs")
        scan_engine.get_device_info = fail

        onvif_info = {"xaddrs": [], "types": ""}
        device = scan_engine._build_orphan_onvif_device("192.168.1.64", onvif_info, "eth0")
        self.assertIsNone(device["onvif_xaddr"])
        self.assertEqual(device["vendor"], "Unknown")


if __name__ == "__main__":
    unittest.main()
