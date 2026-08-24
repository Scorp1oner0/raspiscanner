import unittest

from scanner.reporting import assessment, risk, security


def _device(ip, vendor, open_ports, banners=None, is_camera=False, is_nvr=False, is_infra=False, model=None):
    return {
        "ip": ip,
        "mac": "AA:BB:CC:00:00:01",
        "vendor": vendor,
        "model": model,
        "hostname": None,
        "open_ports": open_ports,
        "http_banners": banners or {},
        "is_camera": is_camera or is_nvr,
        "is_nvr": is_nvr,
        "is_network_infra": is_infra,
        "network": "192.168.10.0/24",
    }


CAMERA = _device(
    "192.168.10.21", "Hikvision",
    [{"port": 80, "service": "HTTP"}, {"port": 443, "service": "HTTPS"}, {"port": 554, "service": "RTSP"}],
    is_camera=True,
)
NVR = _device(
    "192.168.10.10", "Hikvision",
    [{"port": 443, "service": "HTTPS"}, {"port": 554, "service": "RTSP"}, {"port": 23, "service": "Telnet"}],
    is_nvr=True,
)
SWITCH = _device(
    "192.168.10.1", "TP-Link Technologies",
    [{"port": 80, "service": "HTTP"}],
    is_infra=True,
)


class TestSecurityFindings(unittest.TestCase):
    def test_telnet_on_video_device_is_critical(self):
        findings = security.find_security_issues(NVR)
        telnet = [f for f in findings if f["id"] == "telnet_exposed"]
        self.assertEqual(len(telnet), 1)
        self.assertEqual(telnet[0]["severity"], "critical")

    def test_telnet_on_generic_host_is_high(self):
        generic = _device("192.168.10.99", "Sconosciuto", [{"port": 23, "service": "Telnet"}])
        findings = security.find_security_issues(generic)
        self.assertEqual(findings[0]["severity"], "high")

    def test_http_port_flagged_medium(self):
        findings = security.find_security_issues(CAMERA)
        http_findings = [f for f in findings if f["id"] == "http_enabled"]
        self.assertEqual(len(http_findings), 1)
        self.assertEqual(http_findings[0]["severity"], "medium")

    def test_no_open_ports_no_findings(self):
        clean = _device("192.168.10.50", "Apple", [])
        self.assertEqual(security.find_security_issues(clean), [])


class TestRiskSummary(unittest.TestCase):
    def test_counts_across_devices(self):
        all_findings = []
        for d in (CAMERA, NVR, SWITCH):
            all_findings.extend(security.find_security_issues(d))
        counts = risk.summarize(all_findings)
        self.assertEqual(counts["critical"], 1)  # telnet sull'NVR
        self.assertEqual(counts["medium"], 2)    # http su camera + switch
        self.assertEqual(counts["high"], 0)
        self.assertEqual(counts["low"], 0)


class TestAssessmentReport(unittest.TestCase):
    def test_report_structure(self):
        report = assessment.generate("192.168.10.0/24", [CAMERA, NVR, SWITCH])
        self.assertIn("NETWORK ASSESSMENT", report)
        self.assertIn("Network: 192.168.10.0/24", report)
        self.assertIn("3 devices discovered", report)
        self.assertIn("CAMERAS", report)
        self.assertIn("NVR", report)
        self.assertIn("NETWORK", report)
        self.assertIn("SECURITY", report)
        self.assertIn("⚠ Telnet exposed", report)
        self.assertIn("⚠ HTTP enabled", report)
        self.assertIn("RISK SUMMARY", report)
        self.assertIn("Critical: 1", report)
        self.assertIn("High:     0", report)
        self.assertIn("Medium:   2", report)
        self.assertIn("Low:      0", report)

    def test_section_order_camera_before_nvr_before_network(self):
        report = assessment.generate("192.168.10.0/24", [CAMERA, NVR, SWITCH])
        cameras_idx = report.index("CAMERAS")
        nvr_idx = report.index("\nNVR\n")
        network_idx = report.index("\nNETWORK\n")
        self.assertLess(cameras_idx, nvr_idx)
        self.assertLess(nvr_idx, network_idx)

    def test_empty_devices_no_crash(self):
        report = assessment.generate("10.0.0.0/24", [])
        self.assertIn("0 devices discovered", report)
        self.assertNotIn("SECURITY", report)

    def test_generate_all_groups_by_network(self):
        other_net_device = _device("10.0.0.5", "Sconosciuto", [])
        other_net_device["network"] = "10.0.0.0/24"
        text = assessment.generate_all([CAMERA, other_net_device])
        self.assertIn("192.168.10.0/24", text)
        self.assertIn("10.0.0.0/24", text)

    def test_generate_all_empty(self):
        self.assertIn("Nessun dato", assessment.generate_all([]))


if __name__ == "__main__":
    unittest.main()
