import threading
import unittest

from scanner import scan_engine
from scanner.network import setup as network_setup


class TestRunScanRaceCondition(unittest.TestCase):
    """P1: run_scan() leggeva _state["running"] senza lock prima di
    deciderne il valore nuovo — due chiamate concorrenti a /api/scan/start
    potevano entrambe leggere False prima che l'altra scrivesse True,
    partendo entrambe in parallelo e accavallandosi sullo stesso
    _state["devices"]. Check-then-set ora e' atomico sotto _lock."""

    def setUp(self):
        self._orig_run_thread = scan_engine._run_scan_thread
        self._orig_active_networks = scan_engine._active_networks
        # Nessuna vera scansione di rete nel test: il thread avviato da
        # run_scan() deve solo esistere, non fare I/O reale.
        scan_engine._run_scan_thread = lambda networks: None
        scan_engine._active_networks = lambda: [("eth0", "192.168.1.0/24", "192.168.1.10")]
        scan_engine._state.update(running=False, devices={})

    def tearDown(self):
        scan_engine._run_scan_thread = self._orig_run_thread
        scan_engine._active_networks = self._orig_active_networks
        scan_engine._state.update(running=False, devices={})

    def test_only_one_concurrent_scan_can_start(self):
        n_threads = 20
        results = []
        results_lock = threading.Lock()
        barrier = threading.Barrier(n_threads)

        def attempt():
            barrier.wait()  # massimizza la sovrapposizione, rende il test deterministico
            result = scan_engine.run_scan()
            with results_lock:
                results.append(result)

        threads = [threading.Thread(target=attempt) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        successes = [r for r in results if r[0]]
        self.assertEqual(len(successes), 1, f"attese 1 scan avviata, trovate {len(successes)}: {results}")

    def test_second_call_while_running_is_rejected(self):
        ok1, _ = scan_engine.run_scan()
        self.assertTrue(ok1)
        ok2, message2 = scan_engine.run_scan()
        self.assertFalse(ok2)
        self.assertIn("already in progress", message2)


class TestScanAndNetworkReconfigureConcurrently(unittest.TestCase):
    """P3: run_scan() (scan_engine) e autoconfigure_ethernet() (network.setup)
    sono due sottosistemi indipendenti con lock separati — non devono
    corrompersi a vicenda ne' deadlockare se invocati in parallelo (es.
    l'utente clicca "Riconfigura rete" nella dashboard mentre uno scan e'
    gia' in corso). has_carrier=False forza autoconfigure_ethernet sul
    percorso piu' rapido (nessun tentativo DHCP/probe reale), cosi' il test
    resta veloce e deterministico: qui interessa solo l'assenza di
    deadlock/crash, la logica DHCP/fallback e' gia' testata altrove."""

    def setUp(self):
        self._orig_run_thread = scan_engine._run_scan_thread
        self._orig_active_networks = scan_engine._active_networks
        scan_engine._run_scan_thread = lambda networks: None
        scan_engine._active_networks = lambda: [("eth0", "192.168.1.0/24", "192.168.1.10")]
        scan_engine._state.update(running=False, devices={})

        self._orig_carrier = network_setup.has_carrier
        network_setup.has_carrier = lambda iface: False

    def tearDown(self):
        scan_engine._run_scan_thread = self._orig_run_thread
        scan_engine._active_networks = self._orig_active_networks
        scan_engine._state.update(running=False, devices={})
        network_setup.has_carrier = self._orig_carrier

    def test_no_crash_or_deadlock_when_run_concurrently(self):
        errors = []

        def run_scan_repeatedly():
            for _ in range(50):
                scan_engine.run_scan()
                scan_engine._state.update(running=False)

        def reconfigure_repeatedly():
            try:
                for _ in range(50):
                    network_setup.autoconfigure_ethernet("eth0")
            except Exception as exc:
                errors.append(exc)

        t1 = threading.Thread(target=run_scan_repeatedly)
        t2 = threading.Thread(target=reconfigure_repeatedly)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        self.assertFalse(t1.is_alive(), "run_scan e' rimasto bloccato (deadlock?)")
        self.assertFalse(t2.is_alive(), "autoconfigure_ethernet e' rimasto bloccato (deadlock?)")
        self.assertEqual(errors, [])


class TestActiveNetworks(unittest.TestCase):
    def setUp(self):
        self._orig_get_status = scan_engine.network_setup.get_status

    def tearDown(self):
        scan_engine.network_setup.get_status = self._orig_get_status

    def test_includes_vpn_networks(self):
        """Bug reale: le VPN (WireGuard, OpenVPN...) non finivano mai tra
        le reti scansionate, anche quando attive e con un indirizzo IP
        valido — restavano completamente invisibili allo scan."""
        scan_engine.network_setup.get_status = lambda: {
            "eth": {"up": False, "iface": "eth0", "addresses": []},
            "wifi": {},
            "vpn": {
                "wg0": {"up": True, "iface": "wg0", "addresses": [{"ip": "10.0.0.3", "cidr": "10.0.0.0/24"}]},
            },
        }
        self.assertEqual(scan_engine._active_networks(), [("wg0", "10.0.0.0/24", "10.0.0.3")])

    def test_skips_vpn_interface_that_is_down(self):
        scan_engine.network_setup.get_status = lambda: {
            "eth": {"up": False, "iface": "eth0", "addresses": []},
            "wifi": {},
            "vpn": {
                "wg0": {"up": False, "iface": "wg0", "addresses": []},
            },
        }
        self.assertEqual(scan_engine._active_networks(), [])

    def test_combines_eth_wifi_and_vpn(self):
        scan_engine.network_setup.get_status = lambda: {
            "eth": {"up": True, "iface": "eth0", "addresses": [{"ip": "192.168.88.249", "cidr": "192.168.88.0/24"}]},
            "wifi": {
                "wlan0": {"up": True, "iface": "wlan0", "addresses": [{"ip": "192.168.1.253", "cidr": "192.168.1.0/24"}]},
            },
            "vpn": {
                "wg0": {"up": True, "iface": "wg0", "addresses": [{"ip": "10.0.0.3", "cidr": "10.0.0.0/24"}]},
            },
        }
        result = set(scan_engine._active_networks())
        self.assertEqual(result, {
            ("eth0", "192.168.88.0/24", "192.168.88.249"),
            ("wlan0", "192.168.1.0/24", "192.168.1.253"),
            ("wg0", "10.0.0.0/24", "10.0.0.3"),
        })


class TestOrphanOnvifIps(unittest.TestCase):
    """_orphan_onvif_ips e' pura (nessuna rete reale coinvolta): un IP che
    ha risposto al probe ONVIF ma non e' mai stato trovato dall'ARP scan su
    nessuna rete attiva e' "orfano" nel senso di "non confermato dall'ARP",
    non necessariamente "fuori rete" — quella distinzione la fa
    _classify_orphan_ips (vedi sotto)."""

    def test_ip_not_in_known_ips_is_orphan(self):
        onvif_results = {"192.168.1.64": {"xaddrs": ["http://192.168.1.64/onvif"]}}
        known_ips = {"192.168.88.1", "192.168.88.2"}
        self.assertEqual(scan_engine._orphan_onvif_ips(onvif_results, known_ips), ["192.168.1.64"])

    def test_ip_in_known_ips_is_not_orphan(self):
        onvif_results = {"192.168.88.5": {"xaddrs": []}}
        known_ips = {"192.168.88.5"}
        self.assertEqual(scan_engine._orphan_onvif_ips(onvif_results, known_ips), [])

    def test_mixed_orphan_and_known(self):
        onvif_results = {
            "192.168.88.5": {"xaddrs": []},
            "10.0.0.99": {"xaddrs": []},
        }
        known_ips = {"192.168.88.5"}
        self.assertEqual(scan_engine._orphan_onvif_ips(onvif_results, known_ips), ["10.0.0.99"])

    def test_no_onvif_results_no_orphans(self):
        self.assertEqual(scan_engine._orphan_onvif_ips({}, {"192.168.88.1"}), [])


class TestMatchActiveNetwork(unittest.TestCase):
    def test_ip_inside_active_cidr(self):
        networks = [("eth0", "192.168.1.0/24", "192.168.1.253")]
        self.assertEqual(scan_engine._match_active_network("192.168.1.64", networks), ("eth0", "192.168.1.0/24"))

    def test_ip_outside_all_active_cidrs(self):
        networks = [("eth0", "192.168.88.0/24", "192.168.88.249")]
        self.assertIsNone(scan_engine._match_active_network("192.168.1.64", networks))

    def test_picks_matching_network_among_several(self):
        networks = [
            ("eth0", "192.168.88.0/24", "192.168.88.249"),
            ("wlan0", "192.168.1.0/24", "192.168.1.253"),
        ]
        self.assertEqual(scan_engine._match_active_network("192.168.1.64", networks), ("wlan0", "192.168.1.0/24"))

    def test_no_active_networks(self):
        self.assertIsNone(scan_engine._match_active_network("192.168.1.64", []))

    def test_invalid_ip_returns_none(self):
        networks = [("eth0", "192.168.1.0/24", "192.168.1.253")]
        self.assertIsNone(scan_engine._match_active_network("not-an-ip", networks))


class TestClassifyOrphanIps(unittest.TestCase):
    """Bug reale: una camera "orfana" (vista solo via ONVIF) il cui IP
    ricade comunque in una rete gia' attiva veniva SEMPRE etichettata
    "fuori rete", anche quando l'ARP l'aveva semplicemente mancata in
    quel giro (host lento, pacchetto perso) — visivamente confusa con una
    vera camera fuori rete pur avendo un IP identico alle altre subnet
    scansionate."""

    def test_in_range_ip_goes_to_in_range(self):
        networks = [("eth0", "192.168.1.0/24", "192.168.1.253")]
        in_range, out_of_range = scan_engine._classify_orphan_ips(["192.168.1.64"], networks)
        self.assertEqual(in_range, [("192.168.1.64", "eth0", "192.168.1.0/24")])
        self.assertEqual(out_of_range, [])

    def test_out_of_range_ip_goes_to_out_of_range(self):
        networks = [("eth0", "192.168.88.0/24", "192.168.88.249")]
        in_range, out_of_range = scan_engine._classify_orphan_ips(["192.168.1.64"], networks)
        self.assertEqual(in_range, [])
        self.assertEqual(out_of_range, ["192.168.1.64"])

    def test_mixed_ips_split_correctly(self):
        networks = [("eth0", "192.168.88.0/24", "192.168.88.249")]
        in_range, out_of_range = scan_engine._classify_orphan_ips(
            ["192.168.88.50", "10.0.0.9"], networks,
        )
        self.assertEqual(in_range, [("192.168.88.50", "eth0", "192.168.88.0/24")])
        self.assertEqual(out_of_range, ["10.0.0.9"])

    def test_no_orphans_no_output(self):
        networks = [("eth0", "192.168.1.0/24", "192.168.1.253")]
        self.assertEqual(scan_engine._classify_orphan_ips([], networks), ([], []))


class TestScanHostModelSource(unittest.TestCase):
    """P3 (dashboard UX "detected vs inferred"): model_source distingue un
    "model" auto-dichiarato dal dispositivo via protocollo strutturato
    (ONVIF/mDNS) da uno assente — la dashboard lo mostra diversamente
    da un vendor/model indovinato da OUI/banner."""

    def setUp(self):
        self._orig = {
            name: getattr(scan_engine, name)
            for name in ("scan_ports", "grab_http_banner", "get_device_info_multi", "resolve_hostname")
        }
        scan_engine.scan_ports = lambda ip: []
        scan_engine.grab_http_banner = lambda ip, port, use_https=False: {"server": None, "title": None}
        scan_engine.resolve_hostname = lambda ip, timeout=1: None

    def tearDown(self):
        for name, fn in self._orig.items():
            setattr(scan_engine, name, fn)

    def test_model_source_onvif_when_get_device_information_succeeds(self):
        scan_engine.get_device_info_multi = lambda xaddrs, timeout=3: {"model": "DS-2CD2043G0"}
        onvif_results = {"10.0.0.5": {"xaddrs": ["http://10.0.0.5/onvif"], "types": ""}}
        device = scan_engine._scan_host("10.0.0.5", "AA:BB:CC:00:00:01", onvif_results, {}, None)
        self.assertEqual(device["model"], "DS-2CD2043G0")
        self.assertEqual(device["model_source"], "onvif")

    def test_model_source_mdns_when_onvif_has_no_model(self):
        scan_engine.get_device_info_multi = lambda xaddrs, timeout=3: {}
        mdns_results = {"10.0.0.5": {"hostname": "livingroom.local", "model": "AppleTV11,1"}}
        device = scan_engine._scan_host("10.0.0.5", "AA:BB:CC:00:00:01", {}, mdns_results, None)
        self.assertEqual(device["model"], "AppleTV11,1")
        self.assertEqual(device["model_source"], "mdns")

    def test_model_source_none_when_no_model_available_anywhere(self):
        scan_engine.get_device_info_multi = lambda xaddrs, timeout=3: {}
        device = scan_engine._scan_host("10.0.0.5", "AA:BB:CC:00:00:01", {}, {}, None)
        self.assertIsNone(device["model"])
        self.assertIsNone(device["model_source"])

    def test_onvif_model_takes_priority_over_mdns(self):
        scan_engine.get_device_info_multi = lambda xaddrs, timeout=3: {"model": "DS-2CD2043G0"}
        onvif_results = {"10.0.0.5": {"xaddrs": ["http://10.0.0.5/onvif"], "types": ""}}
        mdns_results = {"10.0.0.5": {"hostname": "cam.local", "model": "SomeOtherModel"}}
        device = scan_engine._scan_host("10.0.0.5", "AA:BB:CC:00:00:01", onvif_results, mdns_results, None)
        self.assertEqual(device["model"], "DS-2CD2043G0")
        self.assertEqual(device["model_source"], "onvif")


class TestScanHostVendorSource(unittest.TestCase):
    """P4 'richer vendor fingerprint database': vendor_source distingue da
    dove viene il vendor mostrato — oui (default), banner (fallback quando
    l'OUI non lo sa), onvif (self-dichiarato, priorita' massima)."""

    UNKNOWN_OUI_MAC = "AA:BB:CC:00:00:01"  # non nel database OUI minimo locale

    def setUp(self):
        self._orig = {
            name: getattr(scan_engine, name)
            for name in ("scan_ports", "grab_http_banner", "get_device_info_multi", "resolve_hostname")
        }
        scan_engine.resolve_hostname = lambda ip, timeout=1: None
        scan_engine.get_device_info_multi = lambda xaddrs, timeout=3: {}

    def tearDown(self):
        for name, fn in self._orig.items():
            setattr(scan_engine, name, fn)

    def test_oui_vendor_used_when_mac_is_known(self):
        scan_engine.scan_ports = lambda ip: []
        scan_engine.grab_http_banner = lambda ip, port, use_https=False: {"server": None, "title": None}
        # Prefisso Raspberry Pi Foundation, presente nel database OUI minimo.
        device = scan_engine._scan_host("10.0.0.5", "B8:27:EB:00:00:01", {}, {}, None)
        self.assertEqual(device["vendor"], "Raspberry Pi Foundation")
        self.assertEqual(device["vendor_source"], "oui")

    def test_banner_fallback_when_oui_is_unknown(self):
        scan_engine.scan_ports = lambda ip: [{"port": 80, "service": "HTTP"}]
        scan_engine.grab_http_banner = lambda ip, port, use_https=False: {"server": None, "title": "Hikvision - Login"}
        device = scan_engine._scan_host("10.0.0.5", self.UNKNOWN_OUI_MAC, {}, {}, None)
        self.assertEqual(device["vendor"], "Hikvision")
        self.assertEqual(device["vendor_source"], "banner")

    def test_vendor_stays_unknown_when_neither_oui_nor_banner_help(self):
        scan_engine.scan_ports = lambda ip: []
        scan_engine.grab_http_banner = lambda ip, port, use_https=False: {"server": None, "title": None}
        device = scan_engine._scan_host("10.0.0.5", self.UNKNOWN_OUI_MAC, {}, {}, None)
        self.assertEqual(device["vendor"], "Unknown")
        self.assertIsNone(device["vendor_source"])

    def test_onvif_manufacturer_overrides_banner_fallback(self):
        scan_engine.scan_ports = lambda ip: [{"port": 80, "service": "HTTP"}]
        scan_engine.grab_http_banner = lambda ip, port, use_https=False: {"server": None, "title": "Dahua NVR"}
        scan_engine.get_device_info_multi = lambda xaddrs, timeout=3: {"manufacturer": "Hikvision"}
        onvif_results = {"10.0.0.5": {"xaddrs": ["http://10.0.0.5/onvif"], "types": ""}}
        device = scan_engine._scan_host("10.0.0.5", self.UNKNOWN_OUI_MAC, onvif_results, {}, None)
        self.assertEqual(device["vendor"], "Hikvision")
        self.assertEqual(device["vendor_source"], "onvif")


class TestBuildOrphanOnvifDevice(unittest.TestCase):
    def setUp(self):
        self._orig_get_device_info_multi = scan_engine.get_device_info_multi

    def tearDown(self):
        scan_engine.get_device_info_multi = self._orig_get_device_info_multi

    def test_no_manufacturer_available(self):
        scan_engine.get_device_info_multi = lambda xaddrs, timeout=3: {}
        onvif_info = {"xaddrs": ["http://192.168.1.64/onvif/device_service"], "types": "NetworkVideoTransmitter"}
        device = scan_engine._build_orphan_onvif_device("192.168.1.64", onvif_info, "eth0")

        self.assertEqual(device["ip"], "192.168.1.64")
        self.assertIsNone(device["mac"])
        self.assertEqual(device["vendor"], "Unknown")
        self.assertIsNone(device["model"])
        self.assertEqual(device["open_ports"], [])
        self.assertTrue(device["is_camera"])
        self.assertFalse(device["is_nvr"])
        self.assertEqual(device["device_type"], "Camera")
        self.assertTrue(device["network_mismatch"])
        self.assertEqual(device["iface"], "eth0")
        self.assertIsNone(device["network"])
        self.assertEqual(device["onvif_xaddr"], "http://192.168.1.64/onvif/device_service")
        self.assertTrue(device["reasons"])

    def test_manufacturer_and_model_from_get_device_information(self):
        scan_engine.get_device_info_multi = lambda xaddrs, timeout=3: {
            "manufacturer": "Hikvision", "model": "DS-2CD2043G0",
        }
        onvif_info = {"xaddrs": ["http://192.168.1.64/onvif/device_service"], "types": ""}
        device = scan_engine._build_orphan_onvif_device("192.168.1.64", onvif_info, "wlan0")

        self.assertEqual(device["vendor"], "Hikvision")
        self.assertEqual(device["model"], "DS-2CD2043G0")
        self.assertEqual(device["model_source"], "onvif")

    def test_model_source_is_none_when_no_model_available(self):
        scan_engine.get_device_info_multi = lambda xaddrs, timeout=3: {}
        onvif_info = {"xaddrs": ["http://192.168.1.64/onvif/device_service"], "types": ""}
        device = scan_engine._build_orphan_onvif_device("192.168.1.64", onvif_info, "eth0")
        self.assertIsNone(device["model_source"])

    def test_no_xaddrs_skips_device_info_lookup(self):
        def fail(*a, **k):
            raise AssertionError("get_device_info_multi non doveva essere chiamata senza xaddrs")
        scan_engine.get_device_info_multi = fail

        onvif_info = {"xaddrs": [], "types": ""}
        device = scan_engine._build_orphan_onvif_device("192.168.1.64", onvif_info, "eth0")
        self.assertIsNone(device["onvif_xaddr"])
        self.assertEqual(device["vendor"], "Unknown")


if __name__ == "__main__":
    unittest.main()
