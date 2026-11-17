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


if __name__ == "__main__":
    unittest.main()
