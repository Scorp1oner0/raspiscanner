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


class TestTargetsPolicy(TargetsTestCase):
    """Policy esplicita (vedi scanner/targets.py): solo reti IPv4 private,
    prefisso minimo /22 (max 1024 host) — decisa per evitare che il Pi
    venga puntato su host pubblici non autorizzati o bloccato per ore su
    uno sweep enorme."""

    def test_default_route_rejected(self):
        ok, message = targets.set_config(True, ["0.0.0.0/0"])
        self.assertFalse(ok)
        self.assertIn("0.0.0.0/0", message)
        self.assertEqual(targets.get_config()["custom"], [])

    def test_public_network_rejected(self):
        ok, message = targets.set_config(True, ["8.8.8.0/24"])
        self.assertFalse(ok)
        self.assertIn("private", message.lower())

    def test_network_larger_than_min_prefixlen_rejected(self):
        ok, message = targets.set_config(True, ["10.0.0.0/8"])
        self.assertFalse(ok)
        self.assertIn("too large", message.lower())

    def test_network_at_min_prefixlen_accepted(self):
        ok, _ = targets.set_config(True, ["10.0.0.0/22"])
        self.assertTrue(ok)
        self.assertEqual(targets.get_config()["custom"], ["10.0.0.0/22"])

    def test_network_smaller_than_min_prefixlen_accepted(self):
        ok, _ = targets.set_config(True, ["10.0.0.0/24"])
        self.assertTrue(ok)
        self.assertEqual(targets.get_config()["custom"], ["10.0.0.0/24"])

    def test_carrier_grade_nat_range_rejected(self):
        """100.64.0.0/10 (RFC 6598, CGNAT) non e' 'privato' secondo
        ipaddress.is_private (ne' privato ne' globale nel registro IANA:
        e' spazio condiviso tra ISP e router del cliente, non una LAN
        dell'operatore) — la policy "solo reti private" lo esclude."""
        ok, message = targets.set_config(True, ["100.64.0.0/24"])
        self.assertFalse(ok)
        self.assertIn("private", message.lower())

    def test_multiple_valid_targets_accepted(self):
        ok, _ = targets.set_config(True, ["192.168.1.0/24", "10.0.0.0/24", "172.16.0.0/24"])
        self.assertTrue(ok)
        self.assertEqual(
            targets.get_config()["custom"],
            ["192.168.1.0/24", "10.0.0.0/24", "172.16.0.0/24"],
        )

    def test_one_invalid_target_among_many_rejects_all(self):
        ok, message = targets.set_config(True, ["192.168.1.0/24", "8.8.8.0/24", "10.0.0.0/24"])
        self.assertFalse(ok)
        self.assertIn("8.8.8.0/24", message)
        self.assertEqual(targets.get_config()["custom"], [])


if __name__ == "__main__":
    unittest.main()
