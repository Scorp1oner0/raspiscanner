"""Test su scanner.discovery.ipv6: nessuna rete reale coinvolta,
parse_icmpv6_echo_reply() e' testata con un pacchetto ICMPv6 Echo Reply
costruito a mano (round-trip byte a byte, stesso motivo gia' scoperto per
SNMP/LLDP/CDP: un pacchetto scapy "fresco" non ha ancora i campi
coercizzati ai tipi veri finche' non viene serializzato e ri-parsato)."""
import unittest

from scapy.all import Ether
from scapy.layers.inet6 import ICMPv6EchoReply, ICMPv6EchoRequest, IPv6

from scanner.discovery.ipv6 import parse_icmpv6_echo_reply


def _echo_reply_frame(src_mac="aa:bb:cc:11:22:33", src_ip="fe80::1"):
    frame = (
        Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
        / IPv6(src=src_ip, dst="ff02::1")
        / ICMPv6EchoReply()
    )
    return Ether(bytes(frame))


class TestParseIcmpv6EchoReply(unittest.TestCase):
    def test_echo_reply_parsed(self):
        parsed = parse_icmpv6_echo_reply(_echo_reply_frame())
        self.assertEqual(parsed, ("fe80::1", "AA:BB:CC:11:22:33"))

    def test_echo_reply_without_ethernet_layer_still_returns_ip(self):
        """Se il layer Ether manca (es. cattura su un'interfaccia senza
        L2, teoricamente non il nostro caso reale ma la funzione non deve
        esplodere), il MAC e' None invece di un errore."""
        frame = IPv6(src="fe80::1", dst="ff02::1") / ICMPv6EchoReply()
        parsed = parse_icmpv6_echo_reply(IPv6(bytes(frame)))
        self.assertEqual(parsed, ("fe80::1", None))

    def test_echo_request_is_not_a_reply(self):
        frame = (
            Ether(src="aa:bb:cc:11:22:33", dst="33:33:00:00:00:01")
            / IPv6(src="fe80::1", dst="ff02::1")
            / ICMPv6EchoRequest()
        )
        self.assertIsNone(parse_icmpv6_echo_reply(Ether(bytes(frame))))

    def test_unrelated_ipv6_packet_returns_none(self):
        frame = Ether(dst="ff:ff:ff:ff:ff:ff") / IPv6(src="fe80::1", dst="ff02::1") / (b"\x00" * 8)
        self.assertIsNone(parse_icmpv6_echo_reply(Ether(bytes(frame))))


if __name__ == "__main__":
    unittest.main()
