import unittest
from unittest import mock

from scapy.all import BOOTP, DHCP, UDP, Ether, IP

from scanner import config
from scanner.discovery import dhcp


def _offer(xid=77, server="192.168.88.200", router="192.168.88.2", dns=("192.168.88.2",), message_type=2,
           src_mac="74:4d:28:e7:25:52"):
    options = [("message-type", message_type), ("server_id", server), ("router", router)]
    if dns:
        options.append(("name_server", *dns))
    options += [("subnet_mask", "255.255.255.0"), ("domain", b"casa.lan"), "end"]
    return (Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") / IP(src=server, dst="255.255.255.255")
            / UDP(sport=67, dport=68) / BOOTP(xid=xid, yiaddr="192.168.88.150") / DHCP(options=options))


class TestParseOffer(unittest.TestCase):
    def test_offer_data(self):
        offer = dhcp.parse_offer(_offer(), 77)
        self.assertEqual(offer["server"], "192.168.88.200")
        self.assertEqual(offer["mac"], "74:4d:28:e7:25:52")
        self.assertEqual(offer["router"], "192.168.88.2")
        self.assertEqual(offer["dns"], ["192.168.88.2"])
        self.assertEqual(offer["subnet"], "255.255.255.0")
        self.assertEqual(offer["domain"], "casa.lan")

    def test_two_dns_servers(self):
        offer = dhcp.parse_offer(_offer(dns=("1.1.1.1", "8.8.8.8")), 77)
        self.assertEqual(offer["dns"], ["1.1.1.1", "8.8.8.8"])

    def test_other_transaction_is_ignored(self):
        self.assertIsNone(dhcp.parse_offer(_offer(xid=1), 77))

    def test_only_offers_count(self):
        self.assertIsNone(dhcp.parse_offer(_offer(message_type=5), 77))

    def test_not_dhcp(self):
        self.assertIsNone(dhcp.parse_offer(Ether() / IP() / UDP(), 77))


class TestProbe(unittest.TestCase):
    def test_off_by_config(self):
        with mock.patch.object(config, "DHCP_PROBE_ENABLED", False):
            self.assertEqual(dhcp.dhcp_probe("eth0", timeout=0.01), [])

    def test_no_raw_access(self):
        with mock.patch.object(dhcp.platform_net, "has_raw_socket_access", return_value=False):
            self.assertEqual(dhcp.dhcp_probe("eth0", timeout=0.01), [])

    def test_collects_one_entry_per_server(self):
        captured = {}

        class FakeSniffer:
            def __init__(self, iface, prn, store):
                captured["prn"] = prn

            def start(self):
                pass

            def stop(self):
                pass

        def fake_send(packet, iface, verbose):
            for offer in (_offer(), _offer(), _offer(server="192.168.88.77", router="192.168.88.1", dns=())):
                captured["prn"](offer)

        with mock.patch.object(dhcp.platform_net, "has_raw_socket_access", return_value=True), \
                mock.patch.object(dhcp.random, "getrandbits", return_value=77), \
                mock.patch.object(dhcp, "get_if_hwaddr", return_value="aa:bb:cc:00:00:01"), \
                mock.patch.object(dhcp.scapy_conf.ifaces, "reload"), \
                mock.patch.object(dhcp, "AsyncSniffer", FakeSniffer), \
                mock.patch.object(dhcp, "sendp", fake_send), \
                mock.patch.object(dhcp.time, "sleep"):
            servers = dhcp.dhcp_probe("eth0", timeout=0.01)
        self.assertEqual([s["server"] for s in servers], ["192.168.88.200", "192.168.88.77"])
        self.assertEqual(servers[1]["dns"], [])

    def test_failure_returns_empty(self):
        with mock.patch.object(dhcp.platform_net, "has_raw_socket_access", return_value=True), \
                mock.patch.object(dhcp, "get_if_hwaddr", side_effect=OSError("no such device")), \
                mock.patch.object(dhcp.scapy_conf.ifaces, "reload"):
            self.assertEqual(dhcp.dhcp_probe("nope0", timeout=0.01), [])


if __name__ == "__main__":
    unittest.main()
