"""Test su scanner.targets: configurazione su file temporaneo, mai il
vero data/targets.json."""
import shutil
import tempfile
import unittest
from pathlib import Path

from scanner import config, targets


class TargetsTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp_dir = tempfile.mkdtemp()
        self._orig_path = config.TARGETS_JSON_PATH
        self._orig_data_dir = config.DATA_DIR
        config.DATA_DIR = self._tmp_dir
        config.TARGETS_JSON_PATH = str(Path(self._tmp_dir) / "targets.json")

    def tearDown(self):
        config.TARGETS_JSON_PATH = self._orig_path
        config.DATA_DIR = self._orig_data_dir
        shutil.rmtree(self._tmp_dir, ignore_errors=True)


class TestTargetsConfig(TargetsTestCase):
    def test_default_config_is_auto_only(self):
        self.assertEqual(targets.get_config(), {"auto_interfaces": True, "custom": []})

    def test_set_and_get_config(self):
        ok, _ = targets.set_config(True, ["192.168.20.0/24", "10.0.5.0/24"])
        self.assertTrue(ok)
        self.assertEqual(
            targets.get_config(),
            {"auto_interfaces": True, "custom": ["192.168.20.0/24", "10.0.5.0/24"]},
        )

    def test_auto_interfaces_can_be_disabled(self):
        ok, _ = targets.set_config(False, ["10.0.5.0/24"])
        self.assertTrue(ok)
        self.assertFalse(targets.get_config()["auto_interfaces"])

    def test_host_bits_are_normalized_to_network_address(self):
        """Un operatore che digita l'indirizzo di un host invece della
        rete (es. "192.168.20.5/24") non deve ottenere uno scan
        silenziosamente sbagliato: la rete va normalizzata."""
        ok, _ = targets.set_config(True, ["192.168.20.5/24"])
        self.assertTrue(ok)
        self.assertEqual(targets.get_config()["custom"], ["192.168.20.0/24"])

    def test_invalid_cidr_rejected_entirely(self):
        """Un solo CIDR invalido rifiuta l'intera lista, invece di
        salvarne silenziosamente solo una parte."""
        ok, message = targets.set_config(True, ["192.168.20.0/24", "not-a-network"])
        self.assertFalse(ok)
        self.assertIn("not-a-network", message)
        self.assertEqual(targets.get_config()["custom"], [])

    def test_duplicate_cidrs_deduplicated(self):
        ok, _ = targets.set_config(True, ["10.0.5.0/24", "10.0.5.0/24"])
        self.assertTrue(ok)
        self.assertEqual(targets.get_config()["custom"], ["10.0.5.0/24"])

    def test_empty_custom_list_is_valid(self):
        ok, _ = targets.set_config(True, [])
        self.assertTrue(ok)
        self.assertEqual(targets.get_config()["custom"], [])

    def test_malformed_file_falls_back_to_default(self):
        with open(config.TARGETS_JSON_PATH, "w") as fh:
            fh.write("{not valid json")
        self.assertEqual(targets.get_config(), {"auto_interfaces": True, "custom": []})


if __name__ == "__main__":
    unittest.main()
