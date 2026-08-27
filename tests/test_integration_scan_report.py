"""Test di integrazione end-to-end: dalla discovery grezza (mockata al
confine — niente privilegi/hardware reale necessario) fino al report
testuale finale, passando per TUTTA la pipeline reale (build_device,
classificazione camera/NVR/rete/host, security findings, generazione del
report) — non solo i singoli pezzi isolati gia' coperti altrove.

Si mocka solo cio' che richiederebbe root o hardware reale (ARP/ICMP scan,
probe ONVIF/mDNS, port scan, banner HTTP, reverse DNS): tutto il resto
(scan_engine._scan_host, la classificazione, scanner.reporting) e'
codice vero, non stub.
"""
import threading
import time
import unittest

from scanner import scan_engine
from scanner.reporting import assessment


class TestFullScanToReportIntegration(unittest.TestCase):
    def setUp(self):
        self._orig = {
            name: getattr(scan_engine, name)
            for name in ("arp_scan", "icmp_scan", "onvif_probe", "mdns_probe",
                         "get_device_info_multi", "scan_ports", "grab_http_banner",
                         "resolve_hostname", "get_default_gateway")
        }
        self._orig_get_status = scan_engine.network_setup.get_status
        self._orig_is_noarp = scan_engine.network_setup.is_noarp
        self._orig_get_mac = scan_engine.network_setup.get_interface_mac

        scan_engine.network_setup.get_status = lambda: {
            "eth": {"up": True, "iface": "eth0",
                    "addresses": [{"ip": "192.168.10.253", "cidr": "192.168.10.0/24"}]},
            "wifi": {}, "vpn": {},
        }
        scan_engine.network_setup.is_noarp = lambda iface: False
        scan_engine.network_setup.get_interface_mac = lambda iface: "AA:BB:CC:00:00:FE"
        scan_engine.get_default_gateway = lambda iface: "192.168.10.1"
        scan_engine.resolve_hostname = lambda ip, timeout=1: None

        # Un solo host scoperto via ARP: una telecamera con Telnet (critical)
        # e RTSP (medium) esposti — attraversa classificazione camera +
        # security findings + generazione del report in un colpo solo.
        scan_engine.arp_scan = lambda cidr, iface, timeout=None, psrc=None: [
            {"ip": "192.168.10.21", "mac": "AA:BB:CC:11:22:33", "vlan_id": 42},
        ]
        scan_engine.icmp_scan = lambda cidr, iface, timeout=None, psrc=None: []
        scan_engine.onvif_probe = lambda iface_ip=None, timeout=3: {}
        scan_engine.mdns_probe = lambda iface_ip=None, timeout=2.5, reverse_ips=None: {}
        scan_engine.get_device_info_multi = lambda xaddrs, timeout=3: {}
        scan_engine.scan_ports = lambda ip: (
            [{"port": 554, "service": "RTSP"}, {"port": 23, "service": "Telnet"}]
            if ip == "192.168.10.21" else []
        )
        scan_engine.grab_http_banner = lambda ip, port, use_https=False: {"server": None, "title": None}

        scan_engine._state.update(running=False, devices={}, progress=0, total=0,
                                   current_ip=None, started_at=None, finished_at=None, error=None)

    def tearDown(self):
        for name, fn in self._orig.items():
            setattr(scan_engine, name, fn)
        scan_engine.network_setup.get_status = self._orig_get_status
        scan_engine.network_setup.is_noarp = self._orig_is_noarp
        scan_engine.network_setup.get_interface_mac = self._orig_get_mac
        scan_engine._state.update(running=False, devices={})

    def _run_and_wait(self, timeout=5):
        ok, message = scan_engine.run_scan()
        self.assertTrue(ok, message)
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not scan_engine.get_state()["running"]:
                return scan_engine.get_state()
            time.sleep(0.02)
        self.fail("scan did not finish within the test timeout")

    def test_scan_discovers_camera_and_local_host(self):
        state = self._run_and_wait()
        devices = {d["ip"]: d for d in state["devices"]}
        self.assertEqual(set(devices), {"192.168.10.21", "192.168.10.253"})

        camera = devices["192.168.10.21"]
        self.assertTrue(camera["is_camera"])
        self.assertEqual(camera["device_type"], "Camera")
        # vlan_id (P4): propagato da arp_scan fino al device finale, anche
        # se _scan_host stesso non lo sa (aggiunto dopo, in _run_scan_thread).
        self.assertEqual(camera["vlan_id"], 42)

        # L'host locale (iface_ip) non riceve mai la propria richiesta ARP
        # broadcast di ritorno: deve comunque comparire, aggiunto a parte.
        local_host = devices["192.168.10.253"]
        self.assertEqual(local_host["mac"], "AA:BB:CC:00:00:FE")
        self.assertFalse(local_host["is_camera"])
        self.assertIsNone(local_host["vlan_id"])

    def test_scan_result_flows_through_real_classification_and_findings(self):
        from scanner.reporting import security
        state = self._run_and_wait()
        devices = {d["ip"]: d for d in state["devices"]}
        findings = security.find_security_issues(devices["192.168.10.21"])
        finding_ids = {f["id"] for f in findings}
        self.assertIn("telnet_exposed", finding_ids)
        self.assertIn("rtsp_exposed", finding_ids)

    def test_report_generation_end_to_end(self):
        state = self._run_and_wait()
        report = assessment.generate_all(
            state["devices"], started_at=state["started_at"], finished_at=state["finished_at"],
        )
        self.assertIn("NETWORK ASSESSMENT", report)
        self.assertIn("Network: 192.168.10.0/24", report)
        self.assertIn("CAMERAS", report)
        self.assertIn("192.168.10.21", report)
        self.assertIn("⚠ Telnet exposed", report)
        self.assertIn("⚠ RTSP exposed", report)
        self.assertIn("Critical: 1", report)
        self.assertIn("Scan started:", report)
        self.assertIn("Duration:", report)
        self.assertIn("not a vulnerability scanner", report)

    def test_stop_scan_mid_flight_leaves_state_consistent(self):
        """stop_scan() durante uno scan in corso non deve lasciare lo stato
        a meta': running deve tornare False e finished_at valorizzato, e il
        loop si ferma al prossimo host invece di processarli tutti — non
        e' un test "a tempo" (nessuno sleep arbitrario): un Event blocca
        deterministicamente il thread di scan sul primo host finche' il
        thread di test non ha gia' chiamato stop_scan()."""
        proceed = threading.Event()
        started_processing = threading.Event()

        def slow_scan_ports(ip):
            started_processing.set()
            proceed.wait(timeout=2)
            return []

        scan_engine.scan_ports = slow_scan_ports
        scan_engine.arp_scan = lambda cidr, iface, timeout=None, psrc=None: [
            {"ip": "192.168.10.21", "mac": "AA:BB:CC:11:22:33"},
            {"ip": "192.168.10.22", "mac": "AA:BB:CC:11:22:34"},
        ]

        ok, message = scan_engine.run_scan()
        self.assertTrue(ok, message)
        self.assertTrue(started_processing.wait(timeout=2), "scan never started processing hosts")
        scan_engine.stop_scan()
        proceed.set()  # sblocca il thread di scan: al prossimo host trova _stop_flag gia' impostato

        deadline = time.time() + 5
        while time.time() < deadline:
            if not scan_engine.get_state()["running"]:
                break
            time.sleep(0.02)
        else:
            self.fail("scan did not stop within the test timeout")

        state = scan_engine.get_state()
        self.assertFalse(state["running"])
        self.assertIsNotNone(state["finished_at"])
        # 3 host scopribili (2 ARP + l'host locale): lo stop deve averne
        # fermato la lavorazione prima che finissero tutti.
        self.assertLess(len(state["devices"]), 3)


if __name__ == "__main__":
    unittest.main()
