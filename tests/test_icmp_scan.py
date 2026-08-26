"""Test mirati su parse_icmp_reply, la parte di icmp_scan testabile senza
socket raw reali (stesso principio di test_arp_scan.py per l'ARP)."""
import ipaddress
import unittest

from scapy.all import ICMP, IP

from scanner.discovery.icmp import parse_icmp_reply

NETWORK = ipaddress.ip_network("10.0.0.0/24")


def _echo_reply(src):
    return IP(src=src) / ICMP(type=0)


def _echo_request(src):
    return IP(src=src) / ICMP(type=8)


class TestParseIcmpReply(unittest.TestCase):
    def test_reply_inside_network_is_accepted(self):
        self.assertEqual(parse_icmp_reply(_echo_reply("10.0.0.5"), NETWORK), "10.0.0.5")

    def test_reply_outside_network_is_rejected(self):
        """Un ICMP di rumore di rete da un'altra subnet non deve inquinare
        i risultati."""
        self.assertIsNone(parse_icmp_reply(_echo_reply("192.168.1.5"), NETWORK))

    def test_echo_request_is_not_a_reply(self):
        """type=8 (echo request, non reply) va ignorato: altrimenti un
        ping di un ALTRO host verso qualcuno sulla subnet verrebbe
        scambiato per una risposta al nostro probe."""
        self.assertIsNone(parse_icmp_reply(_echo_request("10.0.0.5"), NETWORK))

    def test_non_icmp_packet_is_ignored(self):
        non_icmp = IP(src="10.0.0.5") / (b"\x00" * 8)
        self.assertIsNone(parse_icmp_reply(non_icmp, NETWORK))

    def test_network_boundary_addresses(self):
        self.assertIsNotNone(parse_icmp_reply(_echo_reply("10.0.0.1"), NETWORK))
        self.assertIsNotNone(parse_icmp_reply(_echo_reply("10.0.0.254"), NETWORK))
        self.assertIsNone(parse_icmp_reply(_echo_reply("10.0.1.1"), NETWORK))


if __name__ == "__main__":
    unittest.main()
