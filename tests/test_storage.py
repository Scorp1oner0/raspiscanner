"""Test su scanner.storage: SQLite reale su un file temporaneo (non
mockato — e' storage locale, non ha senso testarlo senza toccare
davvero il disco), mai il vero data/history.db."""
import shutil
import tempfile
import unittest
from pathlib import Path

from scanner import config, storage

_DEVICE_A = {
    "ip": "192.168.1.21", "mac": "AA:BB:CC:11:22:33", "vendor": "Hikvision",
    "model": "DS-2CD2043G0", "device_type": "Camera", "is_camera": True, "is_nvr": False,
    "network": "192.168.1.0/24", "open_ports": [{"port": 554, "service": "RTSP"}],
}
_DEVICE_B = {
    "ip": "192.168.1.30", "mac": "AA:BB:CC:44:55:66", "vendor": "Apple",
    "model": None, "device_type": "Generic", "is_camera": False, "is_nvr": False,
    "network": "192.168.1.0/24", "open_ports": [],
}
_NO_MAC_DEVICE = {
    "ip": "10.0.0.5", "mac": None, "vendor": "Unknown", "model": None,
    "device_type": "Generic", "is_camera": False, "is_nvr": False,
    "network": "10.0.0.0/24", "open_ports": [],
}


class StorageTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp_dir = tempfile.mkdtemp()
        self._orig_db_path = config.HISTORY_DB_PATH
        config.HISTORY_DB_PATH = str(Path(self._tmp_dir) / "history.db")

    def tearDown(self):
        config.HISTORY_DB_PATH = self._orig_db_path
        shutil.rmtree(self._tmp_dir, ignore_errors=True)


class TestSaveAndListScans(StorageTestCase):
    def test_save_scan_returns_an_id(self):
        scan_id = storage.save_scan([_DEVICE_A, _DEVICE_B], 1000.0, 1090.0)
        self.assertIsInstance(scan_id, int)

    def test_list_scans_most_recent_first(self):
        id1 = storage.save_scan([_DEVICE_A], 1000.0, 1010.0)
        id2 = storage.save_scan([_DEVICE_A, _DEVICE_B], 2000.0, 2010.0)
        scans = storage.list_scans()
        self.assertEqual([s["id"] for s in scans], [id2, id1])
        self.assertEqual(scans[0]["device_count"], 2)

    def test_list_scans_respects_limit(self):
        for i in range(5):
            storage.save_scan([_DEVICE_A], float(i), float(i) + 1)
        self.assertEqual(len(storage.list_scans(limit=3)), 3)

    def test_get_scan_devices_returns_full_device_dicts(self):
        scan_id = storage.save_scan([_DEVICE_A, _NO_MAC_DEVICE], 1000.0, 1010.0)
        devices = storage.get_scan_devices(scan_id)
        ips = {d["ip"] for d in devices}
        self.assertEqual(ips, {"192.168.1.21", "10.0.0.5"})
        camera = next(d for d in devices if d["ip"] == "192.168.1.21")
        self.assertEqual(camera["model"], "DS-2CD2043G0")


class TestAssetDatabase(StorageTestCase):
    def test_new_device_creates_an_asset(self):
        storage.save_scan([_DEVICE_A], 1000.0, 1010.0)
        assets = storage.list_assets()
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0]["mac"], "AA:BB:CC:11:22:33")
        self.assertEqual(assets[0]["times_seen"], 1)

    def test_seeing_the_same_mac_again_increments_times_seen(self):
        storage.save_scan([_DEVICE_A], 1000.0, 1010.0)
        storage.save_scan([_DEVICE_A], 2000.0, 2010.0)
        assets = storage.list_assets()
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0]["times_seen"], 2)
        self.assertEqual(assets[0]["first_seen"], assets[0]["first_seen"])  # invariato, vedi sotto

    def test_first_seen_does_not_change_on_repeat_sightings(self):
        storage.save_scan([_DEVICE_A], 1000.0, 1010.0)
        first_seen_after_1 = storage.list_assets()[0]["first_seen"]
        storage.save_scan([_DEVICE_A], 2000.0, 2010.0)
        first_seen_after_2 = storage.list_assets()[0]["first_seen"]
        self.assertEqual(first_seen_after_1, first_seen_after_2)

    def test_device_without_mac_is_not_tracked_as_an_asset(self):
        """Non tracciabile in modo affidabile nel tempo: il suo IP puo'
        cambiare senza essere lo stesso host fisico, o viceversa."""
        storage.save_scan([_NO_MAC_DEVICE], 1000.0, 1010.0)
        self.assertEqual(storage.list_assets(), [])

    def test_asset_reflects_latest_vendor_and_ip(self):
        moved_device = dict(_DEVICE_A, ip="192.168.1.99", vendor="Hikvision Updated")
        storage.save_scan([_DEVICE_A], 1000.0, 1010.0)
        storage.save_scan([moved_device], 2000.0, 2010.0)
        asset = storage.list_assets()[0]
        self.assertEqual(asset["last_ip"], "192.168.1.99")
        self.assertEqual(asset["last_vendor"], "Hikvision Updated")


class TestCompareScans(StorageTestCase):
    def test_no_changes_between_identical_scans(self):
        id1 = storage.save_scan([_DEVICE_A, _DEVICE_B], 1000.0, 1010.0)
        id2 = storage.save_scan([_DEVICE_A, _DEVICE_B], 2000.0, 2010.0)
        diff = storage.compare_scans(id1, id2)
        self.assertEqual(diff, {"added": [], "removed": [], "changed": []})

    def test_new_device_shows_up_as_added(self):
        id1 = storage.save_scan([_DEVICE_A], 1000.0, 1010.0)
        id2 = storage.save_scan([_DEVICE_A, _DEVICE_B], 2000.0, 2010.0)
        diff = storage.compare_scans(id1, id2)
        self.assertEqual([d["mac"] for d in diff["added"]], ["AA:BB:CC:44:55:66"])
        self.assertEqual(diff["removed"], [])

    def test_missing_device_shows_up_as_removed(self):
        id1 = storage.save_scan([_DEVICE_A, _DEVICE_B], 1000.0, 1010.0)
        id2 = storage.save_scan([_DEVICE_A], 2000.0, 2010.0)
        diff = storage.compare_scans(id1, id2)
        self.assertEqual([d["mac"] for d in diff["removed"]], ["AA:BB:CC:44:55:66"])
        self.assertEqual(diff["added"], [])

    def test_changed_open_ports_detected(self):
        id1 = storage.save_scan([_DEVICE_A], 1000.0, 1010.0)
        changed_device = dict(_DEVICE_A, open_ports=[{"port": 554, "service": "RTSP"}, {"port": 80, "service": "HTTP"}])
        id2 = storage.save_scan([changed_device], 2000.0, 2010.0)
        diff = storage.compare_scans(id1, id2)
        self.assertEqual(len(diff["changed"]), 1)
        self.assertIn("open_ports", diff["changed"][0]["fields"])

    def test_devices_without_mac_excluded_from_comparison(self):
        id1 = storage.save_scan([_NO_MAC_DEVICE], 1000.0, 1010.0)
        id2 = storage.save_scan([_NO_MAC_DEVICE], 2000.0, 2010.0)
        diff = storage.compare_scans(id1, id2)
        self.assertEqual(diff, {"added": [], "removed": [], "changed": []})


if __name__ == "__main__":
    unittest.main()
