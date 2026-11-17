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


class TestIcmpScanSending(unittest.TestCase):
    """Stessa regola dell'ARP: richieste distanziate e in ordine casuale,
    non un'unica raffica."""

    def test_sweep_is_paced_and_shuffled(self):
        from unittest.mock import MagicMock, patch

        from scanner import config
        from scanner.discovery import icmp

        sent = []

        def _record(packets, **kwargs):
            sent.append(([p[IP].dst for p in packets], [p[IP].src for p in packets], kwargs))

        with patch.object(icmp.platform_net, "has_raw_socket_access", return_value=True), \
                patch.object(icmp, "scapy_conf", MagicMock()), \
                patch.object(icmp, "AsyncSniffer", MagicMock()), \
                patch.object(icmp, "send", side_effect=_record), \
                patch.object(icmp.time, "sleep"), \
                patch.object(icmp.nopriv, "fallback_icmp_sweep", return_value=[]):
            icmp.icmp_scan("10.0.0.0/24", "wg0", psrc="10.0.0.3")

        self.assertEqual(len(sent), 1)
        dsts, srcs, kwargs = sent[0]
        self.assertEqual(set(dsts), {f"10.0.0.{i}" for i in range(1, 255)})
        self.assertNotEqual(dsts, sorted(dsts, key=lambda ip: int(ip.split(".")[-1])))
        self.assertEqual(set(srcs), {"10.0.0.3"})
        self.assertEqual(kwargs.get("inter"), config.SWEEP_SEND_INTERVAL)
