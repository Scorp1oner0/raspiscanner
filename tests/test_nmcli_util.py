import unittest

from scanner.network.nmcli_util import split_nmcli_terse


class TestSplitNmcliTerse(unittest.TestCase):
    def test_simple_fields(self):
        self.assertEqual(split_nmcli_terse("CasaWifi:80:WPA2", 3), ["CasaWifi", "80", "WPA2"])

    def test_escaped_colon_in_value_preserved(self):
        """Bug reale evitato: nmcli emette un ':' letterale dentro un
        valore come '\\:' — uno split ingenuo lo spezzerebbe in un campo
        in piu', disallineando tutti quelli successivi sulla stessa riga."""
        self.assertEqual(split_nmcli_terse("Guest\\:Wifi:70:WPA2", 3), ["Guest:Wifi", "70", "WPA2"])

    def test_escaped_backslash_preserved(self):
        self.assertEqual(split_nmcli_terse("Rete\\\\Wifi:50:", 3), ["Rete\\Wifi", "50", ""])

    def test_trailing_empty_field(self):
        self.assertEqual(split_nmcli_terse("OpenNet::", 3), ["OpenNet", "", ""])

    def test_fewer_separators_than_expected_pads_with_empty(self):
        """Output inatteso/malformato non deve sollevare un'eccezione: i
        campi mancanti diventano stringa vuota invece di far crashare il
        parsing dell'intera riga."""
        self.assertEqual(split_nmcli_terse("SoloUnCampo", 3), ["SoloUnCampo", "", ""])

    def test_extra_colons_beyond_field_count_stay_in_last_field(self):
        self.assertEqual(split_nmcli_terse("a:b:c:d:e", 3), ["a", "b", "c:d:e"])

    def test_two_field_split(self):
        self.assertEqual(split_nmcli_terse("raspiscanner-hotspot:wlan0", 2), ["raspiscanner-hotspot", "wlan0"])

    def test_empty_line(self):
        self.assertEqual(split_nmcli_terse("", 2), ["", ""])


if __name__ == "__main__":
    unittest.main()
