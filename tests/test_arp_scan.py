"""Test mirati sulla funzione arp_scan/parse_arp_reply.

Nascono da un bug reale trovato durante una riscrittura di arp_scan (invio
e ascolto separati invece di srp()): la prima versione filtrava le
risposte con `filter="arp"` in AsyncSniffer, che richiede libpcap non
installato di default -> lo sniffer moriva silenziosamente e lo scan
tornava sempre vuoto. Il fix e' filtrare in Python (parse_arp_reply)
invece di delegare a un filtro BPF. Questi test proteggono quella logica
di filtraggio, che e' l'unica parte testabile senza socket raw reali.
"""
import ipaddress
import unittest

from scapy.all import ARP, Dot1Q, Ether

from scanner.discovery.arp import extract_vlan_id, parse_arp_reply

NETWORK = ipaddress.ip_network("192.168.1.0/24")


def _reply(psrc, hwsrc="aa:bb:cc:dd:ee:ff"):
    return Ether(src=hwsrc, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=psrc, hwsrc=hwsrc)


def _request(pdst):
    return Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=pdst)


class TestParseArpReply(unittest.TestCase):
    def test_reply_inside_network_is_accepted(self):
        parsed = parse_arp_reply(_reply("192.168.1.50"), NETWORK)
        self.assertEqual(parsed, ("192.168.1.50", "AA:BB:CC:DD:EE:FF"))

    def test_mac_is_uppercased(self):
        parsed = parse_arp_reply(_reply("192.168.1.50", hwsrc="aa:bb:cc:00:11:22"), NETWORK)
        self.assertEqual(parsed[1], "AA:BB:CC:00:11:22")

    def test_reply_outside_network_is_rejected(self):
        """Traffico ARP di un host su un'altra subnet visto durante lo
        sniff (es. rumore di rete) non deve inquinare i risultati."""
        parsed = parse_arp_reply(_reply("10.0.0.5"), NETWORK)
        self.assertIsNone(parsed)

    def test_arp_request_is_not_a_reply(self):
        """op=1 (who-has) non e' una risposta: deve essere ignorato, non
        solo per non confondersi ma perche' altrimenti una richiesta ARP di
        un ALTRO host sulla rete verrebbe scambiata per una sua risposta."""
        parsed = parse_arp_reply(_request("192.168.1.50"), NETWORK)
        self.assertIsNone(parsed)

    def test_non_arp_packet_is_ignored(self):
        non_arp = Ether(dst="ff:ff:ff:ff:ff:ff") / (b"\x00" * 20)
        self.assertIsNone(parse_arp_reply(non_arp, NETWORK))

    def test_network_boundary_addresses(self):
        net = ipaddress.ip_network("192.168.1.0/24")
        self.assertIsNotNone(parse_arp_reply(_reply("192.168.1.1"), net))
        self.assertIsNotNone(parse_arp_reply(_reply("192.168.1.254"), net))
        self.assertIsNone(parse_arp_reply(_reply("192.168.2.1"), net))


class TestExtractVlanId(unittest.TestCase):
    """P4 'VLAN awareness': la maggior parte delle porte sono in modalita'
    "access" (lo switch toglie il tag 802.1Q prima di consegnare il
    frame) — None e' il caso normale, non un errore. L'informazione
    compare solo se il probe gira su una porta trunk o un'interfaccia
    VLAN dedicata, che lascia passare il tag intatto fino a scapy."""

    def test_tagged_frame_returns_vlan_id(self):
        tagged = Ether(dst="ff:ff:ff:ff:ff:ff") / Dot1Q(vlan=42) / ARP(op=2, psrc="192.168.1.50", hwsrc="aa:bb:cc:dd:ee:ff")
        self.assertEqual(extract_vlan_id(tagged), 42)

    def test_untagged_frame_returns_none(self):
        untagged = _reply("192.168.1.50")
        self.assertIsNone(extract_vlan_id(untagged))

    def test_non_arp_untagged_packet_returns_none(self):
        non_arp = Ether(dst="ff:ff:ff:ff:ff:ff") / (b"\x00" * 20)
        self.assertIsNone(extract_vlan_id(non_arp))


if __name__ == "__main__":
    unittest.main()
