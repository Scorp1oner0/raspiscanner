"""Test del ripiego di discovery senza privilegi (Windows senza Npcap).

Coperti i parser puri e il fatto che tcp_sweep degradi in modo pulito su
input degeneri. Lo sweep TCP vero (che apre socket) non e' testato qui:
dipende dalla rete della macchina di test.
"""
import unittest
from unittest.mock import patch

from scanner.discovery import nopriv


class TestParseArpTable(unittest.TestCase):
    WINDOWS_SAMPLE = """
Interface: 192.168.1.77 --- 0x7
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
  192.168.1.50          11-22-33-44-55-66     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
"""

    LINUX_SAMPLE = """
192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
192.168.1.9 dev eth0  INCOMPLETE
192.168.1.50 dev eth0 lladdr 11:22:33:44:55:66 STALE
"""

    def test_windows_arp_a(self):
        got = nopriv.parse_arp_table(self.WINDOWS_SAMPLE)
        self.assertEqual(got["192.168.1.1"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(got["192.168.1.50"], "11:22:33:44:55:66")

    def test_drops_broadcast_and_multicast_macs(self):
        got = nopriv.parse_arp_table(self.WINDOWS_SAMPLE)
        self.assertNotIn("192.168.1.255", got)  # ff:ff:... scartato
        # 224.0.0.22 ha un MAC valido (01:00:5e:...): resta, non e' compito
        # del parser filtrare i multicast, ma il filtro per-subnet lo esclude.
        self.assertIn("224.0.0.22", got)

    def test_linux_ip_neigh(self):
        got = nopriv.parse_arp_table(self.LINUX_SAMPLE)
        self.assertEqual(set(got), {"192.168.1.1", "192.168.1.50"})
        self.assertEqual(got["192.168.1.1"], "AA:BB:CC:DD:EE:FF")

    def test_incomplete_entry_ignored(self):
        got = nopriv.parse_arp_table(self.LINUX_SAMPLE)
        self.assertNotIn("192.168.1.9", got)

    def test_empty(self):
        self.assertEqual(nopriv.parse_arp_table(""), {})


class TestArpTableForNetwork(unittest.TestCase):
    def test_filters_to_cidr(self):
        full = {"192.168.1.1": "AA:BB:CC:DD:EE:FF", "10.0.0.1": "00:11:22:33:44:55"}
        with patch.object(nopriv, "read_system_arp_table", return_value=full):
            got = nopriv.arp_table_for_network("192.168.1.0/24")
        self.assertEqual(got, {"192.168.1.1": "AA:BB:CC:DD:EE:FF"})

    def test_bad_cidr_returns_empty(self):
        self.assertEqual(nopriv.arp_table_for_network("not-a-cidr"), {})


class TestTcpSweepGuards(unittest.TestCase):
    def test_invalid_cidr(self):
        self.assertEqual(nopriv.tcp_sweep("nonsense"), set())

    def test_network_too_large_is_skipped(self):
        # /8 = 16M host, ben oltre _SWEEP_MAX_HOSTS: niente sweep, set vuoto.
        with patch.object(nopriv, "_probe_host", side_effect=AssertionError("non deve sondare")):
            self.assertEqual(nopriv.tcp_sweep("10.0.0.0/8"), set())


class TestWindowsFallbacks(unittest.TestCase):
    def test_windows_arp_scan_merges_sweep_and_table(self):
        with patch.object(nopriv, "tcp_sweep", return_value={"192.168.1.10", "192.168.1.20"}), \
             patch.object(nopriv, "arp_table_for_network", return_value={"192.168.1.10": "AA:AA:AA:AA:AA:AA"}):
            got = nopriv.windows_arp_scan("192.168.1.0/24")
        by_ip = {d["ip"]: d for d in got}
        self.assertEqual(set(by_ip), {"192.168.1.10", "192.168.1.20"})
        self.assertEqual(by_ip["192.168.1.10"]["mac"], "AA:AA:AA:AA:AA:AA")
        self.assertIsNone(by_ip["192.168.1.20"]["mac"])
        self.assertIsNone(by_ip["192.168.1.10"]["vlan_id"])

    def test_windows_arp_scan_empty_when_nothing_found(self):
        with patch.object(nopriv, "tcp_sweep", return_value=set()), \
             patch.object(nopriv, "arp_table_for_network", return_value={}):
            self.assertEqual(nopriv.windows_arp_scan("192.168.1.0/24"), [])

    def test_windows_icmp_sweep_has_no_mac(self):
        with patch.object(nopriv, "tcp_sweep", return_value={"10.0.0.5"}):
            got = nopriv.windows_icmp_sweep("10.0.0.0/24")
        self.assertEqual(got, [{"ip": "10.0.0.5", "mac": None}])


if __name__ == "__main__":
    unittest.main()
