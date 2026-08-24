import unittest

from scanner import vendor


class TestVendorLookup(unittest.TestCase):
    def test_known_prefix(self):
        self.assertEqual(vendor.lookup_vendor("B8:27:EB:11:22:33"), "Raspberry Pi Foundation")

    def test_known_camera_vendor(self):
        self.assertEqual(vendor.lookup_vendor("4C:BD:8F:AA:BB:CC"), "Hikvision")

    def test_unknown_prefix(self):
        self.assertEqual(vendor.lookup_vendor("FF:FF:FF:00:00:00"), "Sconosciuto")

    def test_lowercase_and_no_separators(self):
        self.assertEqual(vendor.lookup_vendor("b827eb112233"), "Raspberry Pi Foundation")


if __name__ == "__main__":
    unittest.main()
