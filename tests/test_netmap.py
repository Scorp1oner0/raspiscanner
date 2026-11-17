import unittest
from unittest import mock

from scanner import netmap


def _device(ip, iface, network, hostname=None, mac=None, device_type="Generic", vendor="Unknown"):
    return {"ip": ip, "iface": iface, "network": network, "hostname": hostname, "mac": mac,
            "device_type": device_type, "vendor": vendor, "is_camera": False}


TOPOLOGY = {
    "eth0": {"cidr": "192.168.88.0/24", "gateway": "192.168.88.2", "neighbors": []},
    "wlan0": {"cidr": "172.20.10.0/28", "gateway": "172.20.10.1", "neighbors": []},
    "wg0": {"cidr": "10.0.0.0/24", "gateway": None, "neighbors": []},
}


class TestNetworkMap(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(netmap.network_setup, "is_noarp", side_effect=lambda i: i.startswith("wg"))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_network_kinds(self):
        result = netmap.build_map(TOPOLOGY, [])
        kinds = {n["iface"]: n["kind"] for n in result["networks"]}
        self.assertEqual(kinds, {"eth0": "ethernet", "wlan0": "wifi", "wg0": "vpn"})

    def test_gateway_and_self_are_marked(self):
        devices = [
            _device("192.168.88.2", "eth0", "192.168.88.0/24", "_gateway"),
            _device("192.168.88.250", "eth0", "192.168.88.0/24", "localhost"),
        ]
        result = netmap.build_map(TOPOLOGY, devices, local_ips={"192.168.88.250"})
        by_ip = {d["ip"]: d for d in result["devices"]}
        self.assertTrue(by_ip["192.168.88.2"]["is_gateway"])
        self.assertFalse(by_ip["192.168.88.2"]["is_self"])
        self.assertTrue(by_ip["192.168.88.250"]["is_self"])
        self.assertFalse(by_ip["192.168.88.250"]["is_gateway"])

    def test_cable_and_wifi_on_the_same_addresses_are_one_network(self):
        topology = {
            "eth0": {"cidr": "192.168.88.0/24", "gateway": "192.168.88.2", "neighbors": [],
                     "dhcp": [{"server": "192.168.88.200", "dns": []}]},
            "wlan0": {"cidr": "192.168.88.0/24", "gateway": "192.168.88.2", "neighbors": [], "dhcp": []},
        }
        devices = [
            _device("192.168.88.2", "eth0", "192.168.88.0/24", "pihole", mac="AA:00:00:00:00:02"),
            _device("192.168.88.250", "eth0", "192.168.88.0/24", "localhost", mac="AA:00:00:00:00:fa"),
            _device("192.168.88.190", "wlan0", "192.168.88.0/24", "localhost", mac="AA:00:00:00:00:be"),
        ]
        result = netmap.build_map(topology, devices, local_ips={"192.168.88.250", "192.168.88.190"})
        self.assertEqual(len(result["networks"]), 1)
        net = result["networks"][0]
        self.assertEqual(net["ifaces"], ["eth0", "wlan0"])
        self.assertEqual(net["dhcp"][0]["server"], "192.168.88.200")
        self.assertEqual({d["iface"] for d in result["devices"]}, {"eth0"})
        selves = [d for d in result["devices"] if d["is_self"]]
        self.assertEqual(len(selves), 1)
        self.assertEqual(selves[0]["ips"], ["192.168.88.190", "192.168.88.250"])
        self.assertEqual(result["links"], [])
        self.assertTrue(next(d for d in result["devices"] if d["ip"] == "192.168.88.2")["is_gateway"])

    def test_a_vpn_is_never_merged_into_another_network(self):
        topology = {"eth0": {"cidr": "10.0.0.0/24", "gateway": None, "neighbors": []},
                    "wg0": {"cidr": "10.0.0.0/24", "gateway": None, "neighbors": []}}
        self.assertEqual(len(netmap.build_map(topology, [])["networks"]), 2)

    def test_same_hostname_in_two_networks_is_a_bridge(self):
        devices = [
            _device("192.168.88.248", "eth0", "192.168.88.0/24", "TestPi.local"),
            _device("172.20.10.5", "wlan0", "172.20.10.0/28", "testpi"),
        ]
        result = netmap.build_map(TOPOLOGY, devices)
        self.assertEqual(len(result["links"]), 1)
        self.assertEqual(result["links"][0]["kind"], "same_device")
        self.assertTrue(all(d["is_bridge"] for d in result["devices"]))

    def test_generic_hostnames_are_not_linked(self):
        devices = [
            _device("192.168.88.5", "eth0", "192.168.88.0/24", "localhost"),
            _device("172.20.10.6", "wlan0", "172.20.10.0/28", "localhost"),
        ]
        result = netmap.build_map(TOPOLOGY, devices)
        self.assertEqual(result["links"], [])

    def test_same_hostname_in_same_network_is_not_a_bridge(self):
        devices = [
            _device("192.168.88.10", "eth0", "192.168.88.0/24", "nas"),
            _device("192.168.88.11", "eth0", "192.168.88.0/24", "nas"),
        ]
        result = netmap.build_map(TOPOLOGY, devices)
        self.assertEqual(result["links"], [])
        self.assertFalse(any(d["is_bridge"] for d in result["devices"]))

    def test_scanner_own_addresses_are_linked_across_networks(self):
        devices = [
            _device("192.168.88.250", "eth0", "192.168.88.0/24", "localhost"),
            _device("172.20.10.2", "wlan0", "172.20.10.0/28", "localhost"),
        ]
        result = netmap.build_map(TOPOLOGY, devices, local_ips={"192.168.88.250", "172.20.10.2"})
        self.assertEqual(len(result["links"]), 1)
        self.assertEqual(result["links"][0]["name"], "self")

    def test_label_falls_back_to_vendor_then_type_then_ip(self):
        devices = [
            _device("192.168.88.30", "eth0", "192.168.88.0/24", vendor="Planet"),
            _device("192.168.88.31", "eth0", "192.168.88.0/24"),
            _device("192.168.88.32", "eth0", "192.168.88.0/24", "_gateway", device_type="Router"),
            _device("192.168.88.33", "eth0", "192.168.88.0/24", "NAS-casa"),
        ]
        labels = {d["ip"]: d["label"] for d in netmap.build_map(TOPOLOGY, devices)["devices"]}
        self.assertEqual(labels["192.168.88.30"], "Planet")
        self.assertEqual(labels["192.168.88.31"], "192.168.88.31")
        self.assertEqual(labels["192.168.88.32"], "Router")
        self.assertEqual(labels["192.168.88.33"], "NAS-casa")

    def test_scanner_itself_is_labelled(self):
        devices = [_device("192.168.88.250", "eth0", "192.168.88.0/24", "localhost")]
        result = netmap.build_map(TOPOLOGY, devices, local_ips={"192.168.88.250"})
        self.assertEqual(result["devices"][0]["label"], "This scanner")

    def test_empty_scan(self):
        result = netmap.build_map({}, [])
        self.assertEqual((result["networks"], result["devices"], result["links"]), ([], [], []))


class TestRolesAndPath(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(netmap.network_setup, "is_noarp", side_effect=lambda i: i.startswith("wg"))
        patcher.start()
        self.addCleanup(patcher.stop)

    def _topology(self, dhcp):
        return {"eth0": {"cidr": "192.168.88.0/24", "gateway": "192.168.88.2", "neighbors": [], "dhcp": dhcp}}

    def test_dhcp_server_and_dns_roles_come_from_the_offer(self):
        offer = {"server": "192.168.88.200", "router": "192.168.88.2", "dns": ["192.168.88.2"], "domain": "casa.lan"}
        devices = [_device("192.168.88.200", "eth0", "192.168.88.0/24", "mikrotik"),
                   _device("192.168.88.2", "eth0", "192.168.88.0/24", "pihole")]
        result = netmap.build_map(self._topology([offer]), devices)
        roles = {d["ip"]: d["roles"] for d in result["devices"]}
        self.assertEqual(roles["192.168.88.200"], ["dhcp"])
        self.assertEqual(roles["192.168.88.2"], ["gateway", "dns"])
        self.assertEqual(result["networks"][0]["dhcp"][0]["router"], "192.168.88.2")

    def test_open_dns_port_marks_a_dns_server(self):
        device = _device("192.168.88.9", "eth0", "192.168.88.0/24", "nas")
        device["open_ports"] = [{"port": 53, "service": "DNS"}]
        result = netmap.build_map(self._topology([]), [device])
        self.assertIn("dns", result["devices"][0]["roles"])

    def test_same_mac_in_a_network_is_one_device_with_all_its_addresses(self):
        devices = [_device("192.168.88.10", "eth0", "192.168.88.0/24", mac="AA:BB:CC:00:00:01"),
                   _device("192.168.88.11", "eth0", "192.168.88.0/24", mac="aa:bb:cc:00:00:01"),
                   _device("192.168.88.5", "eth0", "192.168.88.0/24", mac="AA:BB:CC:00:00:01")]
        result = netmap.build_map(self._topology([]), devices)
        self.assertEqual(len(result["devices"]), 1)
        self.assertEqual(result["devices"][0]["ips"], ["192.168.88.5", "192.168.88.10", "192.168.88.11"])

    def test_same_mac_in_two_networks_stays_two_devices(self):
        devices = [_device("192.168.88.10", "eth0", "192.168.88.0/24", mac="AA:BB:CC:00:00:01"),
                   _device("172.20.10.4", "wlan0", "172.20.10.0/28", mac="AA:BB:CC:00:00:01")]
        result = netmap.build_map(TOPOLOGY, devices)
        self.assertEqual(len(result["devices"]), 2)

    def test_devices_without_mac_are_never_merged(self):
        devices = [_device("10.0.0.1", "wg0", "10.0.0.0/24"), _device("10.0.0.2", "wg0", "10.0.0.0/24")]
        self.assertEqual(len(netmap.build_map(TOPOLOGY, devices)["devices"]), 2)

    def test_uplink_path_names_known_hops_and_marks_the_public_one(self):
        uplink = {"target": "1.1.1.1", "internet": True, "reached": False, "hops": [
            {"ttl": 1, "ip": "192.168.88.2", "rtt_ms": 0.6, "private": True},
            {"ttl": 2, "ip": "192.168.1.1", "rtt_ms": 4.0, "private": True},
            {"ttl": 3, "ip": None, "rtt_ms": None, "private": None},
            {"ttl": 4, "ip": "151.5.0.1", "rtt_ms": 12.0, "private": False}]}
        devices = [_device("192.168.88.2", "eth0", "192.168.88.0/24", "pihole")]
        result = netmap.build_map(self._topology([]), devices, uplink=uplink)
        path = result["uplink"]
        self.assertEqual(path["via"], "eth0")
        self.assertTrue(path["internet"])
        self.assertEqual([h["label"] for h in path["hops"]], ["pihole", None, None, None])
        self.assertEqual([h["known"] for h in path["hops"]], [True, False, False, False])
        self.assertEqual([h["is_public"] for h in path["hops"]], [False, False, False, True])

    def test_no_uplink_gives_none(self):
        self.assertIsNone(netmap.build_map(TOPOLOGY, [])["uplink"])
        self.assertIsNone(netmap.build_map(TOPOLOGY, [], uplink={"hops": []})["uplink"])


if __name__ == "__main__":
    unittest.main()
