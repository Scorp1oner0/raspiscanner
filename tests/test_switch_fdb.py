import socket
import threading
import unittest

from scanner.discovery import switch_fdb


def _oid_key(oid):
    return tuple(int(p) for p in oid.split("."))


def _value(value):
    if value is None:
        return b"\x82\x00"
    if isinstance(value, int):
        return switch_fdb._integer(value)
    return switch_fdb._tlv(4, value)


class FakeAgent(threading.Thread):
    """Un agente SNMP v2c minimo su loopback: risponde a GET e GETNEXT da
    una tabella {oid: valore}, solo se la community e' quella giusta."""

    def __init__(self, table, community="public"):
        super().__init__(daemon=True)
        self.table, self.community = table, community
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.running = True

    def run(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            reply = self._answer(data)
            if reply:
                self.sock.sendto(reply, addr)

    def _answer(self, data):
        _, body, _ = switch_fdb._read_tlv(data, 0)
        _, _, i = switch_fdb._read_tlv(body, 0)
        _, community, i = switch_fdb._read_tlv(body, i)
        if community.decode() != self.community:
            return None
        kind, pdu, _ = switch_fdb._read_tlv(body, i)
        _, request_id, j = switch_fdb._read_tlv(pdu, 0)
        _, _, j = switch_fdb._read_tlv(pdu, j)
        _, _, j = switch_fdb._read_tlv(pdu, j)
        _, varbinds, _ = switch_fdb._read_tlv(pdu, j)
        _, entry, _ = switch_fdb._read_tlv(varbinds, 0)
        _, raw_oid, _ = switch_fdb._read_tlv(entry, 0)
        asked = switch_fdb._decode(6, raw_oid)
        if kind == 0xA0:
            found = asked if asked in self.table else None
        else:
            later = sorted((o for o in self.table if _oid_key(o) > _oid_key(asked)), key=_oid_key)
            found = later[0] if later else None
        answer = (switch_fdb._oid(found) + _value(self.table[found])) if found else (switch_fdb._oid(asked) + _value(None))
        pdu_out = switch_fdb._tlv(0xA2, switch_fdb._tlv(2, request_id) + switch_fdb._integer(0)
                                  + switch_fdb._integer(0) + switch_fdb._tlv(0x30, switch_fdb._tlv(0x30, answer)))
        return switch_fdb._tlv(0x30, switch_fdb._integer(1) + switch_fdb._tlv(4, community) + pdu_out)

    def stop(self):
        self.running = False
        self.sock.close()


def _table(fdb=True):
    table = {switch_fdb.SYSNAME_OID: b"planet"}
    if fdb:
        table[f"{switch_fdb.FDB_PORT_OID}.168.247.224.195.199.220"] = 0
        table[f"{switch_fdb.FDB_PORT_OID}.184.39.235.54.186.185"] = 9
        table[f"{switch_fdb.FDB_PORT_OID}.228.167.160.241.7.157"] = 2
        table[f"{switch_fdb.BASE_PORT_IFINDEX_OID}.9"] = 9
        table[f"{switch_fdb.BASE_PORT_IFINDEX_OID}.2"] = 2
        table[f"{switch_fdb.IFNAME_OID}.9"] = b"GigabitEthernet 9"
    return table


class TestRequestEncoding(unittest.TestCase):
    def test_request_is_a_valid_snmp_v2c_message(self):
        from scapy.layers.snmp import SNMP
        packet = SNMP(switch_fdb.build_request("public", 0xA1, [switch_fdb.FDB_PORT_OID], 77))
        self.assertEqual(packet.community.val, b"public")
        self.assertEqual(packet.PDU.id.val, 77)
        self.assertEqual(packet.PDU.varbindlist[0].oid.val, switch_fdb.FDB_PORT_OID)
        self.assertEqual(type(packet.PDU).__name__, "SNMPnext")


class TestReadSwitch(unittest.TestCase):
    def _read(self, table, community="public", agent_community="public"):
        agent = FakeAgent(table, agent_community)
        agent.start()
        self.addCleanup(agent.stop)
        return switch_fdb.read_switch("127.0.0.1", community, timeout=0.4, port=agent.port)

    def test_reads_the_mac_to_port_table_and_names(self):
        result = self._read(_table())
        self.assertEqual(result["macs"], {"b8:27:eb:36:ba:b9": 9, "e4:a7:a0:f1:07:9d": 2})
        self.assertEqual(result["ports"], {9: "GigabitEthernet 9", 2: "port 2"})

    def test_the_switch_own_addresses_on_port_zero_are_left_out(self):
        self.assertNotIn("a8:f7:e0:c3:c7:dc", self._read(_table())["macs"])

    def test_wrong_community_means_no_answer_and_none(self):
        self.assertIsNone(self._read(_table(), community="public", agent_community="secret"))

    def test_a_device_without_a_mac_table_gives_none(self):
        self.assertIsNone(self._read(_table(fdb=False)))

    def test_nothing_listening_gives_none(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        self.assertIsNone(switch_fdb.read_switch("127.0.0.1", timeout=0.2, port=port))

    def test_garbage_reply_gives_none(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(1)

        def serve():
            try:
                _, addr = sock.recvfrom(4096)
                sock.sendto(b"\x00\x01garbage", addr)
            except OSError:
                pass
        threading.Thread(target=serve, daemon=True).start()
        self.addCleanup(sock.close)
        self.assertIsNone(switch_fdb.read_switch("127.0.0.1", timeout=0.5, port=sock.getsockname()[1]))


if __name__ == "__main__":
    unittest.main()
