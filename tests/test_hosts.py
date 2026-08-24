import unittest

from scanner.hosts import classify_by_ports, classify_by_vendor, classify_host


class TestClassifyByVendor(unittest.TestCase):
    def test_raspberry_pi_recognized(self):
        label, reasons = classify_by_vendor("Raspberry Pi Foundation")
        self.assertEqual(label, "Raspberry Pi")
        self.assertTrue(reasons)

    def test_espressif_recognized(self):
        label, _ = classify_by_vendor("Espressif (ESP8266/ESP32)")
        self.assertIn("IoT", label)

    def test_unknown_vendor_no_hint(self):
        label, reasons = classify_by_vendor("Sconosciuto")
        self.assertIsNone(label)
        self.assertEqual(reasons, [])

    def test_none_vendor_no_crash(self):
        label, reasons = classify_by_vendor(None)
        self.assertIsNone(label)

    def test_apple_deliberately_not_classified(self):
        """L'OUI Apple e' condiviso da Mac/iPhone/iPad: non identifica un
        tipo di dispositivo, solo il vendor (gia' visibile a parte)."""
        label, _ = classify_by_vendor("Apple")
        self.assertIsNone(label)


class TestClassifyByPorts(unittest.TestCase):
    def test_printer_port_9100(self):
        label, reasons = classify_by_ports([{"port": 9100, "service": "JetDirect"}])
        self.assertEqual(label, "Stampante di rete")

    def test_printer_port_631_ipp(self):
        label, _ = classify_by_ports([{"port": 631, "service": "IPP"}])
        self.assertEqual(label, "Stampante di rete")

    def test_windows_smb(self):
        label, reasons = classify_by_ports([{"port": 445, "service": "SMB"}])
        self.assertEqual(label, "PC (Windows/SMB)")

    def test_windows_rdp(self):
        label, _ = classify_by_ports([{"port": 3389, "service": "RDP"}])
        self.assertEqual(label, "PC (Windows/SMB)")

    def test_no_relevant_ports(self):
        label, reasons = classify_by_ports([{"port": 22, "service": "SSH"}])
        self.assertIsNone(label)
        self.assertEqual(reasons, [])

    def test_no_open_ports_at_all(self):
        """Un dispositivo senza porte aperte (comune su telefoni/PC
        moderni) non e' identificabile: limite strutturale, non un bug."""
        label, reasons = classify_by_ports([])
        self.assertIsNone(label)

    def test_printer_takes_priority_over_windows(self):
        ports = [{"port": 9100, "service": "JetDirect"}, {"port": 445, "service": "SMB"}]
        label, _ = classify_by_ports(ports)
        self.assertEqual(label, "Stampante di rete")


class TestClassifyHost(unittest.TestCase):
    def test_vendor_hint_wins_over_port_hint(self):
        """Un Raspberry Pi con SMB attivo resta 'Raspberry Pi', non 'PC':
        il vendor e' un segnale piu' specifico e affidabile."""
        label, _ = classify_host("Raspberry Pi Foundation", [{"port": 445, "service": "SMB"}])
        self.assertEqual(label, "Raspberry Pi")

    def test_falls_back_to_ports_when_no_vendor_hint(self):
        label, _ = classify_host("Sconosciuto", [{"port": 9100, "service": "JetDirect"}])
        self.assertEqual(label, "Stampante di rete")

    def test_nothing_recognized_returns_none(self):
        label, reasons = classify_host("Sconosciuto", [])
        self.assertIsNone(label)
        self.assertEqual(reasons, [])


if __name__ == "__main__":
    unittest.main()
