"""Scan approfondito di un solo dispositivo e profilo porte esteso.

Nessuna rete reale: le connessioni TCP e i banner sono sostituiti da
versioni finte. Lo scan approfondito nasce dal TestPi che lo scan normale
vedeva con la sola porta 22, mentre ci giravano anche la dashboard sulla
7332 e la plancia sulla 8088."""
import threading
import unittest
from unittest.mock import patch

from scanner import config, deep_scan, scan_engine
from scanner.fingerprint import ports as ports_module


class TestParsePortSpec(unittest.TestCase):
    def test_single_ports_and_ranges(self):
        self.assertEqual(deep_scan.parse_port_spec("22,80,8000-8002"), [22, 80, 8000, 8001, 8002])

    def test_spaces_and_duplicates_are_ignored(self):
        self.assertEqual(deep_scan.parse_port_spec(" 80, 80 ,79-81 "), [79, 80, 81])

    def test_full_range(self):
        self.assertEqual(len(deep_scan.parse_port_spec("1-65535")), 65535)

    def test_invalid_specs_are_rejected(self):
        for spec in ("", " ", ",", "0", "65536", "1-70000", "90-80", "a", "1-b", "22;80", None):
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                deep_scan.parse_port_spec(spec)


class _DeepScanBase(unittest.TestCase):
    """Uno scan_engine con un solo dispositivo noto e una rete finta in cui
    sono aperte 22, 7332 (web in HTTPS) e 8088 (web in HTTP)."""

    OPEN = {22, 7332, 8088}

    def setUp(self):
        self._orig_devices = scan_engine._state["devices"]
        self._orig_running = scan_engine._state["running"]
        scan_engine._state["devices"] = {
            "192.168.88.248": {"ip": "192.168.88.248", "open_ports": [{"port": 22, "service": "SSH"}],
                               "http_banners": {}},
        }
        scan_engine._state["running"] = False
        deep_scan._state.update(running=False, ip=None)
        self.banner_calls = []

        def fake_check(ip, port, timeout):
            return port in self.OPEN

        def fake_banner(ip, port, timeout=1.5, use_https=False):
            self.banner_calls.append((port, use_https))
            if port == 8088 and not use_https:
                return {"server": None, "title": "Plancia"}
            if port == 7332 and use_https:
                return {"server": "RaspiScanner", "title": "RaspiScanner"}
            return {"server": None, "title": None}

        self._patches = [
            patch.object(ports_module, "_check_port", side_effect=fake_check),
            patch.object(ports_module, "grab_http_banner", side_effect=fake_banner),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        scan_engine._state["devices"] = self._orig_devices
        scan_engine._state["running"] = self._orig_running
        deep_scan._state.update(running=False, ip=None)

    def _run_and_wait(self, ip="192.168.88.248", spec="1-10000"):
        done = threading.Event()
        original_run = deep_scan._run

        def wrapped(*args):
            try:
                original_run(*args)
            finally:
                done.set()

        with patch.object(deep_scan, "_run", side_effect=wrapped):
            ok, message, status = deep_scan.start(ip, spec)
            if ok:
                self.assertTrue(done.wait(30), "deep scan never finished")
        return ok, message, status


class TestDeepScanRun(_DeepScanBase):
    def test_finds_open_ports_and_web_banners(self):
        ok, _, status = self._run_and_wait()
        self.assertTrue(ok)
        self.assertEqual(status, 200)
        state = deep_scan.get_state()
        self.assertFalse(state["running"])
        self.assertEqual(state["ports_done"], 10000)
        found = {p["port"]: p for p in state["open_ports"]}
        self.assertEqual(set(found), self.OPEN)
        self.assertEqual(found[7332]["service"], "RaspiScanner")
        self.assertEqual(found[7332]["http"]["title"], "RaspiScanner")
        self.assertEqual(found[8088]["http"]["title"], "Plancia")
        self.assertNotIn("http", found[22])

    def test_no_web_request_on_known_non_web_ports(self):
        self._run_and_wait()
        self.assertNotIn(22, [port for port, _ in self.banner_calls])

    def test_results_are_merged_into_the_device(self):
        self._run_and_wait()
        device = scan_engine._state["devices"]["192.168.88.248"]
        self.assertEqual([p["port"] for p in device["open_ports"]], [22, 7332, 8088])
        self.assertEqual(device["http_banners"][8088]["title"], "Plancia")
        self.assertEqual(device["deep_scan"]["ports"], "1-10000")
        self.assertEqual(device["deep_scan"]["open_ports"], [22, 7332, 8088])

    def test_stop_interrupts_between_batches(self):
        deep_scan._stop_flag.set()
        with patch.object(deep_scan._stop_flag, "clear"):
            self._run_and_wait(spec="1-65535")
        state = deep_scan.get_state()
        self.assertTrue(state["stopped"])
        self.assertLess(state["ports_done"], 65535)
        deep_scan._stop_flag.clear()


class TestDeepScanStartRules(_DeepScanBase):
    def test_unknown_device_is_rejected(self):
        ok, message, status = deep_scan.start("8.8.8.8", "1-100")
        self.assertFalse(ok)
        self.assertEqual(status, 400)
        self.assertIn("not among the devices", message)

    def test_invalid_ports_are_rejected(self):
        ok, _, status = deep_scan.start("192.168.88.248", "1-99999")
        self.assertFalse(ok)
        self.assertEqual(status, 400)

    def test_refused_while_the_network_scan_runs(self):
        scan_engine._state["running"] = True
        ok, _, status = deep_scan.start("192.168.88.248", "1-100")
        self.assertFalse(ok)
        self.assertEqual(status, 409)

    def test_only_one_deep_scan_at_a_time(self):
        deep_scan._state.update(running=True, ip="192.168.88.2")
        ok, message, status = deep_scan.start("192.168.88.248", "1-100")
        self.assertFalse(ok)
        self.assertEqual(status, 409)
        self.assertIn("192.168.88.2", message)


class TestPortProfiles(unittest.TestCase):
    def test_common_profile_is_the_default_list(self):
        self.assertEqual(scan_engine.ports_for_profile("common"), config.PORTS_OF_INTEREST)

    def test_extended_profile_adds_ports(self):
        extended = scan_engine.ports_for_profile("extended")
        self.assertTrue(set(config.PORTS_OF_INTEREST) < set(extended))
        for port in (7332, 8088, 1935, 8554):
            self.assertIn(port, extended)

    def test_unknown_profile_is_refused(self):
        ok, message = scan_engine.run_scan(port_profile="everything")
        self.assertFalse(ok)
        self.assertIn("Unknown port profile", message)

    def test_web_banner_tries_https_after_http_on_alternative_ports(self):
        calls = []

        def fake(ip, port, timeout=1.5, use_https=False):
            calls.append(use_https)
            return {"server": "x", "title": None} if use_https else {"server": None, "title": None}

        with patch.object(ports_module, "grab_http_banner", side_effect=fake):
            banner = ports_module.web_banner("10.0.0.5", 7332)
        self.assertEqual(calls, [False, True])
        self.assertEqual(banner["server"], "x")
