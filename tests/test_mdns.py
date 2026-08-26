import socket
import struct
import unittest

from scanner.discovery import mdns


def _dns_name(name):
    out = b""
    for label in name.strip(".").split("."):
        raw = label.encode("utf-8")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _txt_rdata(pairs):
    out = b""
    for key, value in pairs:
        entry = f"{key}={value}".encode("utf-8")
        out += bytes([len(entry)]) + entry
    return out


def _build_fake_response(records, ancount=None):
    """records: list of (name, rtype, rdata_bytes). Nessuna compressione:
    ogni nome e' scritto per esteso, per tenere i test leggibili — la
    compressione e' testata a parte su _read_name."""
    header = struct.pack(">HHHHHH", 0, 0x8400, 0, ancount if ancount is not None else len(records), 0, 0)
    body = b""
    for name, rtype, rdata in records:
        body += _dns_name(name)
        body += struct.pack(">HHIH", rtype, 0x8001, 120, len(rdata))
        body += rdata
    return header + body


class TestReadName(unittest.TestCase):
    def test_simple_name_no_compression(self):
        encoded = _dns_name("_device-info._tcp.local")
        msg = encoded + b"trailing"
        name, offset = mdns._read_name(msg, 0)
        self.assertEqual(name, "_device-info._tcp.local")
        self.assertEqual(offset, len(encoded))

    def test_compression_pointer_resolves_and_advances_past_pointer_only(self):
        """Il punto piu' delicato della decompressione: dopo aver seguito
        un puntatore, l'offset da ritornare al chiamante e' quello subito
        DOPO il puntatore nel messaggio originale (2 byte), non quello
        dopo il nome nella posizione a cui il puntatore rimanda."""
        base = _dns_name("_tcp.local")
        padding = b"XYZ"
        pointer = struct.pack(">H", 0xC000 | 0)  # punta a offset 0
        msg = base + padding + pointer
        pointer_offset = len(base) + len(padding)

        name, next_offset = mdns._read_name(msg, pointer_offset)
        self.assertEqual(name, "_tcp.local")
        self.assertEqual(next_offset, pointer_offset + 2)

    def test_name_with_label_then_pointer(self):
        """Caso reale piu' comune: "Marios-iPhone" seguito da un
        puntatore al suffisso "_device-info._tcp.local" gia' presente
        altrove nel messaggio (compressione parziale)."""
        suffix = _dns_name("_device-info._tcp.local")
        pointer = struct.pack(">H", 0xC000 | 0)
        prefix_label = bytes([len("Marios-iPhone")]) + b"Marios-iPhone"
        msg = suffix + prefix_label + pointer
        name_offset = len(suffix)

        name, next_offset = mdns._read_name(msg, name_offset)
        self.assertEqual(name, "Marios-iPhone._device-info._tcp.local")
        self.assertEqual(next_offset, name_offset + len(prefix_label) + 2)

    def test_truncated_message_does_not_raise(self):
        name, offset = mdns._read_name(b"\x05abc", 0)  # dichiara 5 byte, ce ne sono 3
        self.assertIsInstance(name, str)


class TestParseTxt(unittest.TestCase):
    def test_single_entry(self):
        parsed = mdns._parse_txt(_txt_rdata([("model", "iPhone14,2")]))
        self.assertEqual(parsed["model"], "iPhone14,2")

    def test_multiple_entries(self):
        parsed = mdns._parse_txt(_txt_rdata([("md", "iPhone 13"), ("osxvers", "20")]))
        self.assertEqual(parsed["md"], "iPhone 13")
        self.assertEqual(parsed["osxvers"], "20")

    def test_key_lowercased(self):
        parsed = mdns._parse_txt(_txt_rdata([("MODEL", "Foo")]))
        self.assertEqual(parsed["model"], "Foo")

    def test_entry_without_equals_ignored(self):
        entry = b"justastring"
        rdata = bytes([len(entry)]) + entry
        self.assertEqual(mdns._parse_txt(rdata), {})

    def test_empty_rdata(self):
        self.assertEqual(mdns._parse_txt(b""), {})


class TestBuildQuery(unittest.TestCase):
    def test_header_has_one_question_per_service(self):
        query = mdns._build_query(["_device-info._tcp.local", "_airplay._tcp.local"])
        txid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", query[:12])
        self.assertEqual(txid, 0)
        self.assertEqual(qdcount, 2)
        self.assertEqual(ancount, 0)

    def test_question_name_and_type_encoded_correctly(self):
        query = mdns._build_query(["_device-info._tcp.local"])
        name, offset = mdns._read_name(query, 12)
        self.assertEqual(name, "_device-info._tcp.local")
        qtype, qclass = struct.unpack(">HH", query[offset:offset + 4])
        self.assertEqual(qtype, mdns._TYPE_PTR)
        self.assertEqual(qclass, 0x0001)


class TestIterRecords(unittest.TestCase):
    def test_extracts_ptr_and_txt_records(self):
        msg = _build_fake_response([
            ("_device-info._tcp.local", mdns._TYPE_PTR, _dns_name("Marios-iPhone._device-info._tcp.local")),
            ("Marios-iPhone._device-info._tcp.local", mdns._TYPE_TXT, _txt_rdata([("model", "iPhone14,2")])),
        ])
        records = list(mdns._iter_records(msg))
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["type"], mdns._TYPE_PTR)
        self.assertEqual(records[1]["type"], mdns._TYPE_TXT)

    def test_too_short_message_yields_nothing(self):
        self.assertEqual(list(mdns._iter_records(b"\x00\x01")), [])

    def test_truncated_record_stops_without_raising(self):
        msg = _build_fake_response([("_tcp.local", mdns._TYPE_PTR, b"\x00" * 20)])
        truncated = msg[:-5]  # rdata dichiarata piu' lunga di quella presente
        self.assertEqual(list(mdns._iter_records(truncated)), [])


class _FakeSocket:
    def __init__(self, responses):
        self._responses = list(responses)
        self.sent = []

    def setsockopt(self, *a, **k):
        pass

    def bind(self, *a, **k):
        pass

    def settimeout(self, *a, **k):
        pass

    def sendto(self, data, addr):
        self.sent.append((data, addr))

    def recvfrom(self, bufsize):
        if not self._responses:
            raise socket.timeout()
        return self._responses.pop(0)

    def close(self):
        pass


class TestMdnsProbe(unittest.TestCase):
    def setUp(self):
        self._orig_socket_cls = mdns.socket.socket

    def tearDown(self):
        mdns.socket.socket = self._orig_socket_cls

    def test_extracts_hostname_and_model_from_device_info_response(self):
        packet = _build_fake_response([
            ("_device-info._tcp.local", mdns._TYPE_PTR, _dns_name("Marios-iPhone._device-info._tcp.local")),
            ("Marios-iPhone._device-info._tcp.local", mdns._TYPE_TXT, _txt_rdata([("model", "iPhone14,2")])),
        ])
        mdns.socket.socket = lambda *a, **k: _FakeSocket([(packet, ("192.168.1.50", 5353))])

        results = mdns.mdns_probe(iface_ip="192.168.1.10", timeout=0.05)
        self.assertIn("192.168.1.50", results)
        self.assertEqual(results["192.168.1.50"]["hostname"], "Marios-iPhone")
        self.assertEqual(results["192.168.1.50"]["model"], "iPhone14,2")

    def test_md_key_also_accepted_for_model(self):
        packet = _build_fake_response([
            ("_device-info._tcp.local", mdns._TYPE_TXT, _txt_rdata([("md", "iPhone 13")])),
        ])
        mdns.socket.socket = lambda *a, **k: _FakeSocket([(packet, ("192.168.1.51", 5353))])
        results = mdns.mdns_probe(iface_ip="192.168.1.10", timeout=0.05)
        self.assertEqual(results["192.168.1.51"]["model"], "iPhone 13")

    def test_multiple_responders_all_collected(self):
        packet_a = _build_fake_response([
            ("_workstation._tcp.local", mdns._TYPE_PTR, _dns_name("Desktop-Linux._workstation._tcp.local")),
        ])
        packet_b = _build_fake_response([
            ("_device-info._tcp.local", mdns._TYPE_PTR, _dns_name("Marios-iPad._device-info._tcp.local")),
        ])
        mdns.socket.socket = lambda *a, **k: _FakeSocket([
            (packet_a, ("192.168.1.20", 5353)),
            (packet_b, ("192.168.1.21", 5353)),
        ])
        results = mdns.mdns_probe(iface_ip="192.168.1.10", timeout=0.05)
        self.assertEqual(set(results), {"192.168.1.20", "192.168.1.21"})
        self.assertEqual(results["192.168.1.20"]["hostname"], "Desktop-Linux")
        self.assertEqual(results["192.168.1.21"]["hostname"], "Marios-iPad")

    def test_malformed_packet_from_one_responder_does_not_block_others(self):
        good_packet = _build_fake_response([
            ("_workstation._tcp.local", mdns._TYPE_PTR, _dns_name("Some-Device._workstation._tcp.local")),
        ])
        mdns.socket.socket = lambda *a, **k: _FakeSocket([
            (b"\x00\x01", ("192.168.1.99", 5353)),  # troppo corto per un header valido
            (good_packet, ("192.168.1.50", 5353)),
        ])
        results = mdns.mdns_probe(iface_ip="192.168.1.10", timeout=0.05)
        self.assertEqual(results["192.168.1.50"]["hostname"], "Some-Device")

    def test_no_responses_returns_empty_dict(self):
        mdns.socket.socket = lambda *a, **k: _FakeSocket([])
        self.assertEqual(mdns.mdns_probe(iface_ip="192.168.1.10", timeout=0.05), {})

    def test_send_failure_returns_empty_dict(self):
        class _BrokenSocket(_FakeSocket):
            def sendto(self, data, addr):
                raise OSError("network unreachable")

        mdns.socket.socket = lambda *a, **k: _BrokenSocket([])
        self.assertEqual(mdns.mdns_probe(iface_ip="192.168.1.10"), {})


if __name__ == "__main__":
    unittest.main()
