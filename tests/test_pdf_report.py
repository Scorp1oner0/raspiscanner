"""Report in PDF scritto a mano (scanner/reporting/pdf.py).

Il file deve restare valido senza librerie esterne, quindi si controlla la
struttura vera (tabella xref, numero di pagine) e il testo contenuto, non
solo che "esca qualcosa"."""
import re
import unittest
import zlib

from scanner.reporting import assessment, pdf


def _device(ip, vendor="Acme", network="192.168.1.0/24", ports=(), **extra):
    device = {
        "ip": ip, "mac": "AA:BB:CC:00:00:01", "vendor": vendor, "model": None, "hostname": None,
        "open_ports": [{"port": p, "service": s} for p, s in ports], "http_banners": {},
        "is_camera": False, "is_nvr": False, "is_network_infra": False,
        "device_type": "Generic", "network": network, "iface": "eth0",
    }
    device.update(extra)
    return device


def _sample_devices():
    return [
        _device("192.168.1.10", "Hikvision", ports=[(554, "RTSP"), (23, "Telnet")], is_camera=True,
                device_type="Camera"),
        _device("192.168.1.1", "TP-Link", ports=[(80, "HTTP")], is_network_infra=True, device_type="Router"),
        _device("192.168.1.30", "Dell", ports=[(3389, "RDP")], device_type="PC"),
    ]


def _render(devices=None, **kwargs):
    data = assessment.report_data(devices or _sample_devices(), 1_700_000_000, 1_700_000_027)
    return pdf.render(data, generated_at=1_700_000_100, **kwargs)


def _pages_text(blob):
    """Il testo disegnato, pagina per pagina: legge gli operatori `(..) Tj`
    nei flussi compressi."""
    streams = re.findall(rb"stream\n(.*?)\nendstream", blob, re.S)
    return [" ".join(re.findall(r"\((.*?)(?<!\\)\) Tj", zlib.decompress(s).decode("latin-1"))) for s in streams]


class TestStructure(unittest.TestCase):
    def setUp(self):
        self.blob = _render()

    def test_header_and_trailer(self):
        self.assertTrue(self.blob.startswith(b"%PDF-1.4"))
        self.assertTrue(self.blob.rstrip().endswith(b"%%EOF"))

    def test_xref_offsets_point_at_the_objects(self):
        xref_at = int(re.search(rb"startxref\n(\d+)", self.blob).group(1))
        lines = self.blob[xref_at:].split(b"\n")
        self.assertEqual(lines[0], b"xref")
        count = int(lines[1].split()[1])
        for number in range(1, count):
            offset = int(lines[2 + number].split()[0])
            self.assertTrue(self.blob[offset:].startswith(f"{number} 0 obj".encode()),
                            f"l'oggetto {number} non e' all'offset indicato")

    def test_page_count_matches(self):
        pages = len(re.findall(rb"/Type /Page /Parent", self.blob))
        self.assertEqual(int(re.search(rb"/Count (\d+)", self.blob).group(1)), pages)

    def test_standard_fonts_only(self):
        for name in (b"Helvetica", b"Helvetica-Bold", b"Courier"):
            self.assertIn(b"/BaseFont /" + name, self.blob)
        self.assertNotIn(b"/FontFile", self.blob)

    def test_page_is_a4(self):
        self.assertIn(b"/MediaBox [0 0 595.28 841.89]", self.blob)


class TestContent(unittest.TestCase):
    def test_report_text_is_in_the_file(self):
        text = " ".join(_pages_text(_render()))
        for expected in ("RaspiScanner", "Network 192.168.1.0/24", "192.168.1.10", "Hikvision camera",
                         "CRITICAL", "Telnet exposed", "RISK", "Scan started", "27s"):
            with self.subTest(expected=expected):
                self.assertIn(expected.upper() if expected == "RISK" else expected,
                              text.upper() if expected == "RISK" else text)

    def test_every_page_has_a_numbered_footer(self):
        pages = _pages_text(_render())
        for number, page in enumerate(pages, start=1):
            self.assertIn(f"Page {number} of {len(pages)}", page)

    def test_disclaimers_are_included(self):
        text = " ".join(_pages_text(_render()))
        self.assertIn("not a vulnerability", text)
        self.assertIn("sensitive network data", text)

    def test_partial_note_only_when_asked(self):
        self.assertNotIn("Partial snapshot", " ".join(_pages_text(_render())))
        self.assertIn("Partial snapshot", " ".join(_pages_text(_render(partial=True))))

    def test_changes_section(self):
        changes = {"added": [{"ip": "10.0.0.9", "mac": "AA", "vendor": "Acme"}], "removed": [],
                   "changed": [{"new": {"ip": "10.0.0.2"}, "mac": "BB", "fields": ["open_ports"]}]}
        data = assessment.report_data(_sample_devices(), 1, 2, changes=changes)
        text = " ".join(_pages_text(pdf.render(data)))
        self.assertIn("Changes since previous scan".upper(), text.upper())
        self.assertIn("10.0.0.9", text)
        self.assertIn("open_ports", text)

    def test_no_changes_message(self):
        data = assessment.report_data(_sample_devices(), 1, 2, changes={"added": [], "removed": [], "changed": []})
        self.assertIn("No changes since the previous saved scan", " ".join(_pages_text(pdf.render(data))))

    def test_network_without_findings_says_so(self):
        quiet = [_device("10.1.1.1", network="10.1.1.0/24")]
        self.assertIn("None on this network", " ".join(_pages_text(_render(quiet))))


class TestLayout(unittest.TestCase):
    def test_many_devices_flow_onto_more_pages(self):
        devices = [_device(f"10.5.0.{i}", f"Vendor{i}", network="10.5.0.0/24", ports=[(80, "HTTP")]) for i in range(1, 200)]
        pages = _pages_text(_render(devices))
        self.assertGreater(len(pages), 3)
        joined = " ".join(pages)
        self.assertIn("10.5.0.1 ", joined + " ")
        self.assertIn("10.5.0.199", joined)
        self.assertIn("continued", joined)

    def test_weird_characters_do_not_break_the_file(self):
        devices = [_device("10.2.0.1", "Привет (тест) \\ ⚠ 日本", network="10.2.0.0/24", ports=[(80, "HTTP")])]
        blob = _render(devices)
        self.assertTrue(blob.startswith(b"%PDF"))
        text = " ".join(_pages_text(blob))
        self.assertIn("\\(", text)  # le parentesi sono escapate
        self.assertNotIn("Привет", text)

    def test_very_long_word_is_split_not_overflowing(self):
        long_vendor = "A" * 300
        blob = _render([_device("10.3.0.1", long_vendor, network="10.3.0.0/24")])
        self.assertTrue(blob.startswith(b"%PDF"))


class TestTextMetrics(unittest.TestCase):
    def test_known_widths(self):
        # H 722 + e 556 + l 222 + l 222 + o 556 = 2278 millesimi di em
        self.assertAlmostEqual(pdf._width("Hello", "F1", 10), 22.78)
        self.assertAlmostEqual(pdf._width("Hello", "F2", 10), (722 + 556 + 278 + 278 + 611) / 100)
        self.assertAlmostEqual(pdf._width("ab", "F3", 10), 12.0)

    def test_tables_cover_printable_ascii(self):
        self.assertEqual(len(pdf._HELV), 95)
        self.assertEqual(len(pdf._HELV_BOLD), 95)

    def test_wrap_respects_the_width(self):
        text = "una frase abbastanza lunga da dover andare a capo almeno un paio di volte"
        lines = pdf._wrap(text, "F1", 10, 120)
        self.assertGreater(len(lines), 1)
        for line in lines:
            self.assertLessEqual(pdf._width(line, "F1", 10), 120)
        self.assertEqual(" ".join(lines), text)

    def test_wrap_splits_a_word_wider_than_the_column(self):
        lines = pdf._wrap("X" * 80, "F1", 10, 100)
        self.assertGreater(len(lines), 1)
        self.assertEqual("".join(lines), "X" * 80)

    def test_wrap_keeps_explicit_newlines(self):
        self.assertEqual(pdf._wrap("a\nb", "F1", 10, 100), ["a", "b"])

    def test_escape(self):
        self.assertEqual(pdf._escape("a(b)c\\d"), "a\\(b\\)c\\\\d")
        self.assertEqual(pdf._escape("日"), "?")


class TestReportData(unittest.TestCase):
    def test_none_without_devices(self):
        self.assertIsNone(assessment.report_data([]))

    def test_networks_sorted_and_text_unchanged(self):
        devices = _sample_devices() + [_device("10.0.0.5", network="10.0.0.0/24")]
        data = assessment.report_data(devices, 1, 2)
        self.assertEqual([n["cidr"] for n in data["networks"]], ["10.0.0.0/24", "192.168.1.0/24"])
        text = assessment.generate_all(devices, 1, 2)
        for net in data["networks"]:
            self.assertIn(f"Network: {net['cidr']}", text)
            self.assertIn(f"{net['count']} devices discovered", text)
            for _, ip, _, message in net["findings"]:
                self.assertIn(f"{message} — {ip}", text)



def _netmap(devices):
    return {
        "networks": [{"iface": "eth0", "cidr": "192.168.1.0/24", "gateway": "192.168.1.1", "kind": "ethernet"},
                     {"iface": "wlan0", "cidr": "172.20.10.0/24", "gateway": "172.20.10.1", "kind": "wifi"}],
        "devices": devices,
        "links": [],
    }


def _node(ip, network, iface, label=None, **extra):
    node = {"ip": ip, "label": label or ip, "vendor": None, "device_type": "Generic", "mac": None,
            "iface": iface, "network": network, "is_gateway": False, "is_self": False,
            "is_camera": False, "is_bridge": False}
    node.update(extra)
    return node


class TestNetworkMapSection(unittest.TestCase):
    def test_switch_is_drawn_at_the_centre_with_ports(self):
        nodes = [_node("192.168.1.50", "192.168.1.0/24", "eth0", "Planet", attach="hub", roles=["switch"]),
                 _node("192.168.1.9", "192.168.1.0/24", "eth0", "This scanner", is_self=True, attach="seen", port="port 2"),
                 _node("192.168.1.20", "192.168.1.0/24", "eth0", "NAS", attach="inferred")]
        nm = _netmap(nodes)
        nm["networks"][0]["hub"] = {"ip": "192.168.1.50", "label": "Planet", "source": "snmp"}
        last = _pages_text(_render(netmap=nm))[-1]
        self.assertIn("Planet", last)
        self.assertIn("192.168.1.50 switch", last)
        self.assertIn("ports read from the switch", last)
        self.assertIn("port 2", last)
        self.assertIn("NAS", last)


    def test_map_is_the_last_section(self):
        nodes = [_node("192.168.1.1", "192.168.1.0/24", "eth0", "router", is_gateway=True),
                 _node("192.168.1.9", "192.168.1.0/24", "eth0", "This scanner", is_self=True)]
        pages = _pages_text(_render(netmap=_netmap(nodes)))
        self.assertIn("NETWORK MAP", pages[-1])
        self.assertIn("router", pages[-1])
        self.assertIn("eth0", pages[-1])
        self.assertTrue(all("NETWORK MAP" not in page for page in pages[:-1]))

    def test_no_map_without_netmap(self):
        self.assertNotIn("NETWORK MAP", " ".join(_pages_text(_render())))
        self.assertNotIn("NETWORK MAP", " ".join(_pages_text(_render(netmap={}))))

    def test_linked_devices_are_drawn_dashed(self):
        nodes = [_node("192.168.1.5", "192.168.1.0/24", "eth0", "pi", is_bridge=True),
                 _node("172.20.10.5", "172.20.10.0/24", "wlan0", "pi", is_bridge=True)]
        nm = _netmap(nodes)
        nm["links"] = [{"a": "192.168.1.5", "b": "172.20.10.5", "kind": "same_device", "name": "pi"}]
        streams = re.findall(rb"stream\n(.*?)\nendstream", _render(netmap=nm), re.S)
        self.assertIn("[3 2] 0 d", zlib.decompress(streams[-1]).decode("latin-1"))

    def test_many_devices_continue_on_more_pages(self):
        nodes = [_node(f"192.168.1.{i}", "192.168.1.0/24", "eth0") for i in range(2, 120)]
        nodes += [_node(f"172.20.10.{i}", "172.20.10.0/24", "wlan0") for i in range(2, 60)]
        blob = _render(netmap=_netmap(nodes))
        pages = _pages_text(blob)
        self.assertGreater(len(pages), 3)
        self.assertIn("192.168.1.119", " ".join(pages))
        self.assertIn("172.20.10.59", " ".join(pages))
        self.assertTrue(blob.rstrip().endswith(b"%%EOF"))

    def test_long_names_are_cut_not_overflowing(self):
        nodes = [_node("192.168.1.7", "192.168.1.0/24", "eth0", "x" * 200)]
        text = " ".join(_pages_text(_render(netmap=_netmap(nodes))))
        self.assertNotIn("x" * 60, text)
        self.assertIn("...", text)

    def test_path_to_the_internet_is_drawn_before_the_networks(self):
        nodes = [_node("192.168.1.1", "192.168.1.0/24", "eth0", "router", is_gateway=True, roles=["gateway", "dhcp"])]
        nm = _netmap(nodes)
        nm["uplink"] = {"target": "1.1.1.1", "internet": True, "via": "eth0", "hops": [
            {"ttl": 1, "ip": "192.168.1.1", "rtt_ms": 0.5, "private": True, "label": "router", "known": True, "is_public": False},
            {"ttl": 2, "ip": None, "rtt_ms": None, "private": None, "label": None, "known": False, "is_public": False},
            {"ttl": 3, "ip": "151.5.0.1", "rtt_ms": 9.0, "private": False, "label": None, "known": False, "is_public": True}]}
        text = _pages_text(_render(netmap=nm))[-1]
        self.assertIn("Path to the Internet", text)
        self.assertIn("Provider router", text)
        self.assertIn("no reply", text)
        self.assertIn("Internet", text)
        self.assertLess(text.index("Path to the Internet"), text.index("eth0"))

    def test_roles_dhcp_and_extra_addresses_are_written(self):
        node = _node("192.168.1.1", "192.168.1.0/24", "eth0", "router", is_gateway=True, roles=["gateway", "dhcp", "dns"],
                     ips=["192.168.1.1", "192.168.1.2"])
        nm = _netmap([node])
        nm["networks"][0]["dhcp"] = [{"server": "192.168.1.1", "router": "192.168.1.1", "dns": [], "domain": None}]
        text = _pages_text(_render(netmap=nm))[-1]
        self.assertIn("DHCP 192.168.1.1", text)
        self.assertIn("+1", text)
        self.assertIn("DHCP not seen", text)


if __name__ == "__main__":
    unittest.main()
