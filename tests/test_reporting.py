import unittest

from scanner.reporting import assessment, risk, security


def _device(ip, vendor, open_ports, banners=None, is_camera=False, is_nvr=False,
            is_infra=False, model=None, device_type="Generic"):
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
        "device_type": device_type,
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
RASPBERRY = _device(
    "192.168.10.30", "Raspberry Pi Foundation",
    [{"port": 22, "service": "SSH"}],
    device_type="Raspberry Pi",
)
PC = _device(
    "192.168.10.31", "Unknown",
    [{"port": 3389, "service": "RDP"}],
    device_type="PC (Windows/SMB)",
)
GENERIC_HOST = _device("192.168.10.99", "Unknown", [])

ORPHAN_CAMERA = _device(
    "192.168.10.64", "Hikvision", [], is_camera=True, device_type="Camera",
)
ORPHAN_CAMERA["mac"] = None
ORPHAN_CAMERA["network_mismatch"] = True
ORPHAN_CAMERA["onvif_xaddr"] = "http://192.168.10.64/onvif/device_service"
ORPHAN_CAMERA["network"] = None

VPN_HOST = _device("10.0.0.4", "Unknown", [{"port": 22, "service": "SSH"}])
VPN_HOST["mac"] = None
VPN_HOST["network"] = "10.0.0.0/24"


class TestSecurityFindings(unittest.TestCase):
    def test_telnet_on_video_device_is_critical(self):
        findings = security.find_security_issues(NVR)
        telnet = [f for f in findings if f["id"] == "telnet_exposed"]
        self.assertEqual(len(telnet), 1)
        self.assertEqual(telnet[0]["severity"], "critical")

    def test_telnet_on_generic_host_is_high(self):
        generic = _device("192.168.10.99", "Unknown", [{"port": 23, "service": "Telnet"}])
        findings = security.find_security_issues(generic)
        self.assertEqual(findings[0]["severity"], "high")

    def test_http_with_https_available_is_low_severity(self):
        """CAMERA espone sia HTTP (80) sia HTTPS (443): il rischio reale e'
        "espone anche una porta in chiaro nonostante supporti la
        cifratura", non "nessun modo di cifrare" — severita' bassa, non
        piu' un flat "medium" per qualunque porta HTTP a prescindere dal
        contesto (vedi anche test_http_without_https_is_medium_severity)."""
        findings = security.find_security_issues(CAMERA)
        http_findings = [f for f in findings if f["id"] == "http_with_https"]
        self.assertEqual(len(http_findings), 1)
        self.assertEqual(http_findings[0]["severity"], "low")

    def test_http_without_https_is_medium_severity(self):
        findings = security.find_security_issues(SWITCH)
        http_findings = [f for f in findings if f["id"] == "http_without_https"]
        self.assertEqual(len(http_findings), 1)
        self.assertEqual(http_findings[0]["severity"], "medium")

    def test_http_admin_panel_without_https_is_high_severity(self):
        admin_device = _device(
            "192.168.10.55", "Unknown", [{"port": 80, "service": "HTTP"}],
            banners={80: {"server": None, "title": "Router Admin Login"}},
        )
        findings = security.find_security_issues(admin_device)
        admin_findings = [f for f in findings if f["id"] == "http_admin_without_https"]
        self.assertEqual(len(admin_findings), 1)
        self.assertEqual(admin_findings[0]["severity"], "high")

    def test_http_admin_panel_with_https_is_medium_severity(self):
        admin_device = _device(
            "192.168.10.56", "Unknown", [{"port": 80, "service": "HTTP"}, {"port": 443, "service": "HTTPS"}],
            banners={80: {"server": None, "title": "Admin Login"}},
        )
        findings = security.find_security_issues(admin_device)
        admin_findings = [f for f in findings if f["id"] == "http_admin_with_https"]
        self.assertEqual(len(admin_findings), 1)
        self.assertEqual(admin_findings[0]["severity"], "medium")

    def test_rtsp_exposed_flagged_medium(self):
        findings = security.find_security_issues(CAMERA)
        rtsp_findings = [f for f in findings if f["id"] == "rtsp_exposed"]
        self.assertEqual(len(rtsp_findings), 1)
        self.assertEqual(rtsp_findings[0]["severity"], "medium")

    def test_https_only_device_has_no_http_finding(self):
        """Un dispositivo che espone SOLO HTTPS (nessuna porta HTTP in
        chiaro) non genera nessun finding HTTP: e' il caso "corretto", non
        un rischio da segnalare."""
        https_only = _device("192.168.10.60", "Unknown", [{"port": 443, "service": "HTTPS"}])
        findings = security.find_security_issues(https_only)
        self.assertEqual([f for f in findings if "http" in f["id"]], [])

    def test_no_open_ports_no_findings(self):
        clean = _device("192.168.10.50", "Apple", [])
        self.assertEqual(security.find_security_issues(clean), [])

    def test_network_mismatch_flagged_as_medium(self):
        findings = security.find_security_issues(ORPHAN_CAMERA)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["id"], "network_mismatch")
        self.assertEqual(findings[0]["severity"], "medium")


class TestRiskSummary(unittest.TestCase):
    def test_counts_across_devices(self):
        all_findings = []
        for d in (CAMERA, NVR, SWITCH):
            all_findings.extend(security.find_security_issues(d))
        counts = risk.summarize(all_findings)
        self.assertEqual(counts["critical"], 1)  # telnet sull'NVR
        self.assertEqual(counts["high"], 0)
        # medium: rtsp su CAMERA + rtsp su NVR + http-senza-https su SWITCH
        self.assertEqual(counts["medium"], 3)
        self.assertEqual(counts["low"], 1)       # http-con-https su CAMERA


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
        self.assertIn("⚠ RTSP exposed", report)
        self.assertIn("⚠ HTTP service detected", report)
        self.assertIn("RISK SUMMARY", report)
        self.assertIn("Critical: 1", report)
        self.assertIn("High:     0", report)
        self.assertIn("Medium:   3", report)
        self.assertIn("Low:      1", report)

    def test_interface_shown_when_devices_carry_one(self):
        device_with_iface = dict(CAMERA)
        device_with_iface["iface"] = "eth0"
        report = assessment.generate("192.168.10.0/24", [device_with_iface])
        self.assertIn("Interface: eth0", report)

    def test_no_interface_line_when_devices_lack_it(self):
        report = assessment.generate("192.168.10.0/24", [CAMERA])
        self.assertNotIn("Interface:", report)

    def test_summary_line_counts_by_category(self):
        report = assessment.generate("192.168.10.0/24", [CAMERA, NVR, SWITCH])
        # CAMERA: 1 camera; NVR: 1 nvr; SWITCH: 1 network device; 4 findings totali
        # (rtsp su camera+nvr, http-con-https su camera, http-senza-https su switch, telnet su nvr)
        self.assertIn("Summary: 1 camera, 1 NVR/DVR, 1 network device, 5 security findings", report)

    def test_summary_line_pluralizes_correctly(self):
        report = assessment.generate("192.168.10.0/24", [GENERIC_HOST])
        self.assertIn("Summary: 0 cameras, 0 NVR/DVR, 0 network devices, 0 security findings", report)

    def test_scan_timing_shown_when_provided(self):
        report = assessment.generate_all([CAMERA], started_at=1000.0, finished_at=1075.0)
        self.assertIn("Scan started:", report)
        self.assertIn("Scan finished:", report)
        self.assertIn("Duration:      1m 15s", report)

    def test_scan_timing_omitted_when_not_provided(self):
        report = assessment.generate_all([CAMERA])
        self.assertNotIn("Scan started:", report)
        self.assertNotIn("Duration:", report)

    def test_sensitive_data_disclaimer_present(self):
        report = assessment.generate_all([CAMERA])
        self.assertIn("sensitive network data", report)

    def test_changes_section_omitted_when_not_provided(self):
        """Il report "live" della dashboard (changes=None, il default) non
        ha una sezione di confronto: non ha senso senza uno storico
        salvato rispetto a cui confrontare."""
        report = assessment.generate_all([CAMERA])
        self.assertNotIn("CHANGES SINCE PREVIOUS SCAN", report)

    def test_changes_section_shown_when_provided(self):
        changes = {
            "added": [{"ip": "192.168.10.99", "mac": "AA:BB:CC:00:00:99", "vendor": "Hikvision"}],
            "removed": [], "changed": [],
        }
        report = assessment.generate_all([CAMERA], changes=changes)
        self.assertIn("CHANGES SINCE PREVIOUS SCAN", report)
        self.assertIn("1 new device(s):", report)
        self.assertIn("192.168.10.99", report)

    def test_changes_section_no_changes_message(self):
        changes = {"added": [], "removed": [], "changed": []}
        report = assessment.generate_all([CAMERA], changes=changes)
        self.assertIn("No changes since the previous saved scan.", report)

    def test_changes_section_lists_changed_fields(self):
        changes = {
            "added": [], "removed": [],
            "changed": [{
                "mac": "AA:BB:CC:11:22:33",
                "old": {"ip": "192.168.10.21"}, "new": {"ip": "192.168.10.21"},
                "fields": ["open_ports"],
            }],
        }
        report = assessment.generate_all([CAMERA], changes=changes)
        self.assertIn("1 device(s) changed:", report)
        self.assertIn("open_ports", report)

    def test_other_devices_section_lists_recognized_types(self):
        """Bug reale: un Raspberry Pi o un PC (Windows/SMB) non finivano in
        NESSUNA sezione del report pur essendo contati in "N devices
        discovered" — restavano visibili solo nella tabella della
        dashboard, invisibili leggendo solo il report testuale."""
        report = assessment.generate("192.168.10.0/24", [CAMERA, RASPBERRY, PC])
        self.assertIn("OTHER DEVICES", report)
        self.assertIn("Raspberry Pi — Raspberry Pi Foundation", report)
        self.assertIn("192.168.10.30", report)
        self.assertIn("PC (Windows/SMB)", report)
        self.assertIn("192.168.10.31", report)

    def test_generic_device_without_findings_still_listed_in_other_section(self):
        """"N devices discovered" deve sempre corrispondere al numero di
        righe elencate nel report: un host davvero "Generico" (nessun
        segnale) resta comunque contato E deve comparire in OTHER DEVICES,
        anche senza altro da dire su di lui — nasconderlo produceva un
        conteggio piu' alto di quanto il testo mostrasse davvero."""
        report = assessment.generate("192.168.10.0/24", [CAMERA, GENERIC_HOST])
        self.assertIn("2 devices discovered", report)
        self.assertIn("192.168.10.99", report)
        self.assertIn("OTHER DEVICES", report)

    def test_every_device_appears_somewhere_in_the_report(self):
        """Invariante generale (bug segnalato piu' volte): ogni device
        passato a generate() deve comparire in almeno una sezione, mai
        contato in "N devices discovered" senza mai essere elencato."""
        devices = [CAMERA, NVR, SWITCH, RASPBERRY, PC, GENERIC_HOST]
        report = assessment.generate("192.168.10.0/24", devices)
        self.assertIn(f"{len(devices)} devices discovered", report)
        for d in devices:
            self.assertIn(d["ip"], report, f"{d['ip']} never listed in the report")

    def test_generic_device_with_findings_included_in_other_section(self):
        """Bug reale: un dispositivo "Generico" con una porta HTTP esposta
        (quindi con un finding in SECURITY) non compariva in NESSUNA
        sezione del report: SECURITY citava un IP mai introdotto prima,
        mentre "N devices discovered" lo contava comunque — risultato
        confuso ("6 dispositivi trovati" ma il testo ne descrive 2)."""
        generic_with_http = _device(
            "192.168.10.77", "Hon Hai Precision Ind.",
            [{"port": 80, "service": "HTTP"}],
        )
        report = assessment.generate("192.168.10.0/24", [CAMERA, generic_with_http])
        self.assertIn("OTHER DEVICES", report)
        self.assertIn("192.168.10.77", report)
        self.assertIn("⚠ HTTP service detected, no HTTPS available — 192.168.10.77", report)

    def test_orphan_onvif_camera_labeled_as_ip_misconfigured(self):
        """Bug che questa feature risolve: una telecamera rilevata SOLO via
        ONVIF multicast (IP fuori da qualunque rete attiva, probabile
        errore di configurazione) deve comparire in CAMERAS con
        un'etichetta che lo dica esplicitamente, non silenziosamente come
        se fosse una camera normale raggiungibile."""
        report = assessment.generate("192.168.10.0/24", [ORPHAN_CAMERA])
        self.assertIn("CAMERAS", report)
        self.assertIn("[IP MISCONFIGURED", report)
        self.assertIn("192.168.10.64", report)
        self.assertIn("ONVIF (multicast): http://192.168.10.64/onvif/device_service", report)
        self.assertIn("⚠ Camera IP misconfigured", report)

    def test_no_mac_device_gets_explanatory_note(self):
        """Un device senza MAC trovato via ICMP su una VPN (link NOARP,
        niente livello 2) non deve sembrare un dato mancante per errore:
        il report lo spiega esplicitamente."""
        report = assessment.generate("10.0.0.0/24", [VPN_HOST])
        self.assertIn("Note: 1 device on this network have no MAC address", report)
        self.assertIn("VPN/NOARP", report)

    def test_no_mac_note_uses_plural_for_multiple_devices(self):
        other_vpn_host = _device("10.0.0.5", "Unknown", [])
        other_vpn_host["mac"] = None
        other_vpn_host["network"] = "10.0.0.0/24"
        report = assessment.generate("10.0.0.0/24", [VPN_HOST, other_vpn_host])
        self.assertIn("Note: 2 devices on this network have no MAC address", report)

    def test_no_mac_note_absent_when_all_devices_have_mac(self):
        report = assessment.generate("192.168.10.0/24", [CAMERA])
        self.assertNotIn("no MAC address", report)

    def test_network_mismatch_camera_does_not_trigger_no_mac_note(self):
        """L'ORPHAN_CAMERA non ha MAC per un motivo diverso e gia'
        spiegato (IP fuori rete, non VPN): non deve comparire anche la
        nota generica sul MAC mancante, sarebbe ridondante/fuorviante."""
        report = assessment.generate("192.168.10.0/24", [ORPHAN_CAMERA])
        self.assertNotIn("no MAC address", report)

    def test_camera_nvr_infra_not_duplicated_in_other_section(self):
        report = assessment.generate("192.168.10.0/24", [CAMERA, NVR, SWITCH, RASPBERRY])
        # ognuno dei 4 IP deve comparire su una riga propria una volta sola
        # (match esatto di riga, non substring: "192.168.10.1" e'
        # prefisso di "192.168.10.10", un semplice count() darebbe un falso
        # positivo).
        ip_lines = [line.strip() for line in report.splitlines()]
        for d in (CAMERA, NVR, SWITCH, RASPBERRY):
            self.assertEqual(ip_lines.count(d["ip"]), 1, f"{d['ip']} duplicato o mancante")

    def test_security_findings_attributed_to_device_ip(self):
        """Bug reale: la versione precedente deduplicava i finding SOLO per
        messaggio, senza dire su quale IP si trovassero — un report con
        "RTSP exposed" su due device diversi (CAMERA e NVR condividono la
        porta 554) mostrava una riga sola, indistinguibile."""
        report = assessment.generate("192.168.10.0/24", [CAMERA, NVR, SWITCH])
        self.assertIn("⚠ Telnet exposed — 192.168.10.10", report)
        self.assertIn("⚠ RTSP exposed", report)
        self.assertIn("— 192.168.10.21", report)  # CAMERA
        self.assertIn("— 192.168.10.10", report)  # NVR

    def test_findings_on_different_devices_not_collapsed(self):
        """CAMERA (192.168.10.21) e NVR (192.168.10.10) hanno entrambi la
        porta RTSP esposta (554): devono comparire come DUE righe
        "RTSP exposed" distinte, non una sola deduplicata per messaggio."""
        report = assessment.generate("192.168.10.0/24", [CAMERA, NVR, SWITCH])
        rtsp_lines = [line for line in report.splitlines() if "RTSP exposed" in line]
        self.assertEqual(len(rtsp_lines), 2)

    def test_findings_sorted_by_severity_critical_first(self):
        report = assessment.generate("192.168.10.0/24", [CAMERA, NVR, SWITCH])
        security_section = report.split("SECURITY\n", 1)[1].split("\n\n", 1)[0]
        self.assertTrue(security_section.strip().startswith("⚠ Telnet exposed"))

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
        other_net_device = _device("10.0.0.5", "Unknown", [])
        other_net_device["network"] = "10.0.0.0/24"
        text = assessment.generate_all([CAMERA, other_net_device])
        self.assertIn("192.168.10.0/24", text)
        self.assertIn("10.0.0.0/24", text)

    def test_generate_all_empty(self):
        self.assertIn("No data yet", assessment.generate_all([]))

    def test_generate_all_includes_not_a_vulnerability_scanner_disclaimer(self):
        """Deve essere esplicito nel report stesso, non solo nei commenti
        del codice: nessun exploit, nessun brute-force, nessuna scansione
        CVE — solo esposizione osservata."""
        text = assessment.generate_all([CAMERA])
        self.assertIn("not a vulnerability scanner", text)
        self.assertIn("no exploits", text)

    def test_disclaimer_appears_once_across_multiple_networks(self):
        other_net_device = _device("10.0.0.5", "Unknown", [])
        other_net_device["network"] = "10.0.0.0/24"
        text = assessment.generate_all([CAMERA, other_net_device])
        self.assertEqual(text.count("not a vulnerability scanner"), 1)


if __name__ == "__main__":
    unittest.main()
