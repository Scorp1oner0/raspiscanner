import unittest

from scanner.hosts import classify_by_hostname, classify_by_ports, classify_by_vendor, classify_host


class TestClassifyByVendor(unittest.TestCase):
    def test_raspberry_pi_recognized(self):
        label, reasons = classify_by_vendor("Raspberry Pi Foundation")
        self.assertEqual(label, "Raspberry Pi")
        self.assertTrue(reasons)

    def test_espressif_recognized(self):
        label, _ = classify_by_vendor("Espressif (ESP8266/ESP32)")
        self.assertIn("IoT", label)

    def test_unknown_vendor_no_hint(self):
        label, reasons = classify_by_vendor("Unknown")
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
        self.assertEqual(label, "Network printer")

    def test_printer_port_631_ipp(self):
        label, _ = classify_by_ports([{"port": 631, "service": "IPP"}])
        self.assertEqual(label, "Network printer")

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
        self.assertEqual(label, "Network printer")


class TestClassifyByHostname(unittest.TestCase):
    def test_iphone_recognized(self):
        label, reasons = classify_by_hostname("iPhone-di-Mario")
        self.assertEqual(label, "Phone (iPhone)")
        self.assertTrue(reasons)

    def test_ipad_recognized_not_confused_with_iphone(self):
        label, _ = classify_by_hostname("Marios-iPad")
        self.assertEqual(label, "Tablet (iPad)")

    def test_macbook_recognized_as_mac(self):
        label, _ = classify_by_hostname("MacBook-Pro")
        self.assertEqual(label, "Mac")

    def test_android_galaxy_recognized_as_phone(self):
        label, _ = classify_by_hostname("Galaxy-A34-5G")
        self.assertEqual(label, "Phone (Android)")

    def test_galaxy_tab_recognized_as_tablet_not_phone(self):
        """Il match piu' specifico (galaxy-tab) deve vincere su quello
        piu' generico (galaxy) che lo contiene come sottostringa."""
        label, _ = classify_by_hostname("Galaxy-Tab-S9")
        self.assertEqual(label, "Tablet (Android)")

    def test_bare_android_hostname_not_assumed_to_be_a_phone(self):
        """Bug reale trovato su uno scan vero: una Sony BRAVIA (Android TV)
        con hostname "Android.local" (via reverse mDNS) veniva etichettata
        "Phone (Android)" solo perche' il nome conteneva "android" — un
        hostname cosi' generico dice solo "e' un dispositivo Android",
        niente di piu' specifico su che TIPO di dispositivo sia."""
        label, _ = classify_by_hostname("Android.local")
        self.assertEqual(label, "Android device")
        self.assertNotIn("Phone", label)

    def test_android_tv_hostname_recognized_specifically(self):
        label, _ = classify_by_hostname("My-Android-TV")
        self.assertEqual(label, "Android TV")

    def test_windows_auto_generated_desktop_name(self):
        label, _ = classify_by_hostname("DESKTOP-7K2N9QP")
        self.assertEqual(label, "PC (Windows)")

    def test_windows_auto_generated_laptop_name(self):
        label, _ = classify_by_hostname("LAPTOP-3F8B2C1")
        self.assertEqual(label, "PC (Windows)")

    def test_no_known_pattern_returns_none(self):
        label, reasons = classify_by_hostname("printer-office-2")
        self.assertIsNone(label)
        self.assertEqual(reasons, [])

    def test_none_hostname_no_crash(self):
        label, reasons = classify_by_hostname(None)
        self.assertIsNone(label)
        self.assertEqual(reasons, [])

    def test_empty_hostname_no_crash(self):
        label, reasons = classify_by_hostname("")
        self.assertIsNone(label)

    def test_extremely_long_hostname_no_crash(self):
        """Un hostname reverse-DNS/mDNS non e' garantito breve: nessun
        limite di lunghezza va assunto ne' puo' causare un rallentamento
        percepibile (nessuna regex qui, solo substring match)."""
        label, reasons = classify_by_hostname("a" * 100_000 + "-iphone")
        self.assertEqual(label, "Phone (iPhone)")

    def test_unicode_hostname_no_crash(self):
        label, reasons = classify_by_hostname("café-☕-desktop")
        self.assertIsNone(label)

    def test_control_characters_in_hostname_no_crash(self):
        label, reasons = classify_by_hostname("weird\x00\x01\x02-iphone")
        self.assertEqual(label, "Phone (iPhone)")


class TestClassifyHost(unittest.TestCase):
    def test_vendor_hint_wins_over_port_hint(self):
        """Un Raspberry Pi con SMB attivo resta 'Raspberry Pi', non 'PC':
        il vendor e' un segnale piu' specifico e affidabile."""
        label, _ = classify_host("Raspberry Pi Foundation", [{"port": 445, "service": "SMB"}])
        self.assertEqual(label, "Raspberry Pi")

    def test_falls_back_to_ports_when_no_vendor_hint(self):
        label, _ = classify_host("Unknown", [{"port": 9100, "service": "JetDirect"}])
        self.assertEqual(label, "Network printer")

    def test_nothing_recognized_returns_none(self):
        label, reasons = classify_host("Unknown", [])
        self.assertIsNone(label)
        self.assertEqual(reasons, [])

    def test_hostname_recognized_when_vendor_gives_no_hint(self):
        """Caso reale: OUI Apple non distingue Mac da iPhone da iPad (per
        design, vedi TestClassifyByVendor), ma il nome host spesso lo dice
        esplicitamente — qui deve intervenire per completare cio' che il
        vendor da solo non puo' dire."""
        label, reasons = classify_host("Apple, Inc.", [], hostname="iPhone-di-Mario")
        self.assertEqual(label, "Phone (iPhone)")
        self.assertTrue(reasons)

    def test_vendor_hint_wins_over_hostname_hint(self):
        label, _ = classify_host("Raspberry Pi Foundation", [], hostname="some-iphone-named-device")
        self.assertEqual(label, "Raspberry Pi")

    def test_hostname_hint_wins_over_port_hint(self):
        """Un iPhone che espone per qualche motivo una porta SMB-like resta
        'Phone (iPhone)': il nome host e' un segnale piu' specifico di una
        porta generica."""
        label, _ = classify_host("Apple, Inc.", [{"port": 445, "service": "SMB"}], hostname="iPhone-di-Mario")
        self.assertEqual(label, "Phone (iPhone)")

    def test_no_hostname_falls_back_to_ports(self):
        label, _ = classify_host("Unknown", [{"port": 3389, "service": "RDP"}], hostname=None)
        self.assertEqual(label, "PC (Windows/SMB)")


if __name__ == "__main__":
    unittest.main()
