"""Test dei parser puri di scanner.platform_net (il layer Windows).

Sono funzioni "testo -> dato": girano anche su Linux/CI, dove psutil e
Windows non ci sono. Le parti che dipendono davvero da psutil/`netsh`
(list_interfaces, get_interface_ips, ...) non sono testabili qui e sono
coperte solo dal degrado a lista vuota.
"""
import unittest

from scanner import platform_net


class TestNetmaskToPrefix(unittest.TestCase):
    def test_common_masks(self):
        self.assertEqual(platform_net.netmask_to_prefix("255.255.255.0"), 24)
        self.assertEqual(platform_net.netmask_to_prefix("255.255.0.0"), 16)
        self.assertEqual(platform_net.netmask_to_prefix("255.255.255.128"), 25)

    def test_invalid_or_missing(self):
        self.assertIsNone(platform_net.netmask_to_prefix(None))
        self.assertIsNone(platform_net.netmask_to_prefix(""))
        self.assertIsNone(platform_net.netmask_to_prefix("nonsense"))
        self.assertIsNone(platform_net.netmask_to_prefix("255.0.255.0"))


class TestNormalizeMac(unittest.TestCase):
    def test_windows_dash_format(self):
        self.assertEqual(platform_net.normalize_mac("aa-bb-cc-dd-ee-ff"), "AA:BB:CC:DD:EE:FF")

    def test_colon_and_bare(self):
        self.assertEqual(platform_net.normalize_mac("aa:bb:cc:dd:ee:ff"), "AA:BB:CC:DD:EE:FF")
        self.assertEqual(platform_net.normalize_mac("AABBCCDDEEFF"), "AA:BB:CC:DD:EE:FF")

    def test_rejects_non_mac(self):
        self.assertIsNone(platform_net.normalize_mac(""))
        self.assertIsNone(platform_net.normalize_mac(None))
        self.assertIsNone(platform_net.normalize_mac("aa-bb-cc"))
        self.assertIsNone(platform_net.normalize_mac("00:00:00:00:00:00:00:00"))


class TestClassifyWindowsInterface(unittest.TestCase):
    def test_ethernet(self):
        self.assertEqual(platform_net.classify_windows_interface("Ethernet"), "eth")
        self.assertEqual(platform_net.classify_windows_interface("Ethernet 2"), "eth")
        self.assertEqual(platform_net.classify_windows_interface("Local Area Connection* 9"), "eth")

    def test_wifi(self):
        self.assertEqual(platform_net.classify_windows_interface("Wi-Fi"), "wifi")
        self.assertEqual(platform_net.classify_windows_interface("Wireless Network Connection"), "wifi")

    def test_vpn(self):
        self.assertEqual(platform_net.classify_windows_interface("WireGuard Tunnel"), "vpn")
        self.assertEqual(platform_net.classify_windows_interface("OpenVPN TAP-Windows6"), "vpn")
        self.assertEqual(platform_net.classify_windows_interface("Tailscale"), "vpn")

    def test_ignored(self):
        self.assertIsNone(platform_net.classify_windows_interface("Loopback Pseudo-Interface 1"))
        self.assertIsNone(platform_net.classify_windows_interface("Bluetooth Network Connection"))
        self.assertIsNone(platform_net.classify_windows_interface("Teredo Tunneling Pseudo-Interface"))
        self.assertIsNone(platform_net.classify_windows_interface("something weird"))


class TestParseRoutePrint(unittest.TestCase):
    SAMPLE = """
===========================================================================
Interface List
 12...aa bb cc dd ee ff ......Intel(R) Ethernet Connection
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0       10.0.0.1       10.0.0.42     25
          0.0.0.0          0.0.0.0     192.168.1.1    192.168.1.77     35
        127.0.0.0        255.0.0.0         On-link        127.0.0.1    331
     10.0.0.0            255.255.255.0     On-link        10.0.0.42    281
===========================================================================
"""

    def test_extracts_default_gateways_in_order(self):
        got = platform_net.parse_route_print_default_gateways(self.SAMPLE)
        self.assertEqual(got, [("10.0.0.1", "10.0.0.42"), ("192.168.1.1", "192.168.1.77")])

    def test_ignores_onlink_and_non_default(self):
        got = platform_net.parse_route_print_default_gateways(self.SAMPLE)
        for gw, _ in got:
            self.assertNotEqual(gw, "On-link")

    def test_empty_input(self):
        self.assertEqual(platform_net.parse_route_print_default_gateways(""), [])


class TestParseNetshWlanInterfaces(unittest.TestCase):
    SAMPLE = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wireless-AC 9560
    GUID                   : 1234abcd
    Physical address       : aa:bb:cc:dd:ee:ff
    State                  : connected
    SSID                   : CasaWifi
    BSSID                  : 11:22:33:44:55:66
    Signal                 : 84%
"""

    def test_maps_name_to_ssid(self):
        got = platform_net.parse_netsh_wlan_interfaces(self.SAMPLE)
        self.assertEqual(got, {"Wi-Fi": "CasaWifi"})

    def test_disconnected_interface_has_none_ssid(self):
        text = "    Name                   : Wi-Fi 2\n    State                  : disconnected\n"
        got = platform_net.parse_netsh_wlan_interfaces(text)
        self.assertEqual(got, {"Wi-Fi 2": None})

    def test_does_not_confuse_bssid_for_ssid(self):
        got = platform_net.parse_netsh_wlan_interfaces(self.SAMPLE)
        self.assertNotEqual(got.get("Wi-Fi"), "11:22:33:44:55:66")


class TestParseNetshWlanNetworks(unittest.TestCase):
    SAMPLE = """
Interface name : Wi-Fi
There are 2 networks currently visible.

SSID 1 : CasaWifi
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 11:22:33:44:55:66
         Signal             : 90%
         Radio type         : 802.11ac

SSID 2 : Guest:Wifi
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : 77:88:99:aa:bb:cc
         Signal             : 55%
"""

    def test_parses_ssid_signal_security(self):
        got = platform_net.parse_netsh_wlan_networks(self.SAMPLE)
        self.assertEqual(len(got), 2)
        self.assertEqual(got[0], {"ssid": "CasaWifi", "signal": "90", "security": "WPA2-Personal"})
        self.assertEqual(got[1]["ssid"], "Guest:Wifi")
        self.assertEqual(got[1]["security"], "Open")

    def test_takes_first_signal_per_ssid(self):
        text = self.SAMPLE + "         Signal             : 10%\n"
        got = platform_net.parse_netsh_wlan_networks(text)
        self.assertEqual(got[0]["signal"], "90")

    def test_empty(self):
        self.assertEqual(platform_net.parse_netsh_wlan_networks(""), [])


class TestEgressIpFor(unittest.TestCase):
    def test_returns_a_local_ip_for_public_target(self):
        # Non invia nulla davvero; se la macchina ha una rotta di default
        # torna un IP locale, altrimenti None. Entrambi accettabili: qui
        # verifichiamo solo che non sollevi e che il tipo sia coerente.
        got = platform_net.egress_ip_for("8.8.8.8")
        self.assertTrue(got is None or isinstance(got, str))

    def test_invalid_target_returns_none(self):
        self.assertIsNone(platform_net.egress_ip_for("not-an-ip"))


if __name__ == "__main__":
    unittest.main()
