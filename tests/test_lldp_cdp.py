"""Test su scanner.discovery.lldp_cdp: nessuna rete reale coinvolta,
parse_lldp_cdp_packet() e' testata con frame LLDP/CDP costruiti a mano
(round-trip byte a byte, stesso motivo gia' scoperto per SNMP: un
pacchetto scapy "fresco" non ha ancora i campi coercizzati ai tipi
veri finche' non viene serializzato e ri-parsato)."""
import unittest

from scapy.all import Ether, LLC, SNAP
from scapy.contrib.cdp import (
    CDPMsgDeviceID, CDPMsgPlatform, CDPMsgPortID, CDPv2_HDR,
)
from scapy.contrib.lldp import (
    LLDPDUChassisID, LLDPDUEndOfLLDPDU, LLDPDUPortID, LLDPDUSystemDescription,
    LLDPDUSystemName, LLDPDUTimeToLive,
)

from scanner.discovery.lldp_cdp import parse_lldp_cdp_packet


def _lldp_frame():
    frame = (
        Ether(dst="01:80:c2:00:00:0e", type=0x88CC)
        / LLDPDUChassisID(subtype=4, id=b"\x00\x11\x22\x33\x44\x55")
        / LLDPDUPortID(subtype=5, id=b"Gi0/1")
        / LLDPDUTimeToLive(ttl=120)
        / LLDPDUSystemName(system_name=b"core-switch")
        / LLDPDUSystemDescription(description=b"Cisco IOS Switch")
        / LLDPDUEndOfLLDPDU()
    )
    return Ether(bytes(frame))


def _cdp_frame():
    hdr = CDPv2_HDR(msg=[
        CDPMsgDeviceID(val=b"core-switch.local"),
        CDPMsgPortID(iface=b"GigabitEthernet0/1"),
        CDPMsgPlatform(val=b"cisco WS-C2960"),
    ])
    frame = Ether(dst="01:00:0c:cc:cc:cc") / LLC() / SNAP(OUI=0x00000C, code=0x2000) / hdr
    return Ether(bytes(frame))


class TestParseLldpCdpPacket(unittest.TestCase):
    def test_lldp_frame_parsed(self):
        neighbor = parse_lldp_cdp_packet(_lldp_frame())
        self.assertEqual(neighbor["protocol"], "lldp")
        self.assertEqual(neighbor["chassis_id"], "00:11:22:33:44:55")
        self.assertEqual(neighbor["port_id"], "Gi0/1")
        self.assertEqual(neighbor["system_name"], "core-switch")
        self.assertEqual(neighbor["system_description"], "Cisco IOS Switch")

    def test_cdp_frame_parsed(self):
        neighbor = parse_lldp_cdp_packet(_cdp_frame())
        self.assertEqual(neighbor["protocol"], "cdp")
        self.assertEqual(neighbor["system_name"], "core-switch.local")
        self.assertEqual(neighbor["port_id"], "GigabitEthernet0/1")
        self.assertEqual(neighbor["system_description"], "cisco WS-C2960")

    def test_unrelated_ethernet_frame_returns_none(self):
        plain = Ether(dst="ff:ff:ff:ff:ff:ff") / (b"\x00" * 20)
        self.assertIsNone(parse_lldp_cdp_packet(plain))

    def test_cdp_destination_mac_without_cdp_layer_returns_none(self):
        """Solo l'indirizzo multicast CDP non basta: deve esserci anche
        davvero il layer CDPv2_HDR (evita falsi positivi su traffico
        anomalo verso lo stesso indirizzo multicast)."""
        fake = Ether(dst="01:00:0c:cc:cc:cc") / (b"\x00" * 10)
        self.assertIsNone(parse_lldp_cdp_packet(fake))


if __name__ == "__main__":
    unittest.main()
