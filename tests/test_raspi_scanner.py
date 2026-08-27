"""Test sul comportamento di avvio di raspi-scanner.py (il file entry
point, non un pacchetto: caricato via importlib, stesso approccio gia'
usato manualmente durante lo sviluppo per testare l'app Flask completa)."""
import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner import auth, config, monitoring, scan_engine, storage

RASPI_SCANNER_PATH = Path(__file__).resolve().parent.parent / "raspi-scanner.py"


def _load_raspi_scanner_module():
    spec = importlib.util.spec_from_file_location("raspi_scanner_under_test", RASPI_SCANNER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestDashboardRefusesHttpFallback(unittest.TestCase):
    """P0 (release blocker): se il certificato TLS non e' disponibile, la
    dashboard non deve MAI avviarsi su HTTP semplice — manderebbe le
    credenziali Basic Auth in chiaro sulla stessa rete che sta
    scansionando. Deve rifiutarsi di partire con un errore chiaro invece
    di un fallback silenzioso."""

    def setUp(self):
        self._tmp_dir = tempfile.mkdtemp()
        self._orig_data_dir = config.DATA_DIR
        self._orig_users_path = config.USERS_JSON_PATH
        self._orig_tls_cert = config.TLS_CERT_PATH
        self._orig_tls_key = config.TLS_KEY_PATH
        config.DATA_DIR = self._tmp_dir
        config.USERS_JSON_PATH = str(Path(self._tmp_dir) / "users.json")
        config.TLS_CERT_PATH = str(Path(self._tmp_dir) / "tls_cert.pem")
        config.TLS_KEY_PATH = str(Path(self._tmp_dir) / "tls_key.pem")
        self.module = _load_raspi_scanner_module()
        # tls e' lo STESSO oggetto modulo di scanner.tls (condiviso, non
        # una copia): sovrascrivere ensure_cert qui lo sovrascrive per
        # tutto il processo finche' non lo si ripristina esplicitamente.
        self._orig_ensure_cert = self.module.tls.ensure_cert

    def tearDown(self):
        self.module.tls.ensure_cert = self._orig_ensure_cert
        config.DATA_DIR = self._orig_data_dir
        config.USERS_JSON_PATH = self._orig_users_path
        config.TLS_CERT_PATH = self._orig_tls_cert
        config.TLS_KEY_PATH = self._orig_tls_key
        shutil.rmtree(self._tmp_dir, ignore_errors=True)

    def test_exits_instead_of_falling_back_to_http(self):
        self.module.tls.ensure_cert = lambda: (None, None)
        with patch.object(self.module.app, "run") as mock_run, \
                patch.object(self.module, "_ensure_startup") as mock_ensure_startup:
            with self.assertRaises(SystemExit) as ctx:
                self.module.run_dashboard(port=7799)

        self.assertEqual(ctx.exception.code, 1)
        mock_run.assert_not_called()
        mock_ensure_startup.assert_not_called()

    def test_starts_normally_when_cert_available(self):
        self.module.tls.ensure_cert = lambda: ("/fake/cert.pem", "/fake/key.pem")
        with patch.object(self.module.app, "run") as mock_run, \
                patch.object(self.module, "_ensure_startup") as mock_ensure_startup:
            self.module.run_dashboard(port=7799)

        mock_ensure_startup.assert_called_once()
        mock_run.assert_called_once()
        _, kwargs = mock_run.call_args
        self.assertEqual(kwargs["ssl_context"], ("/fake/cert.pem", "/fake/key.pem"))
        self.assertFalse(kwargs["debug"])


class RaspiScannerAppTestCase(unittest.TestCase):
    """Base per i test che parlano con l'app Flask reale via test_client().
    scanner.auth e' un modulo singleton condiviso: patchare config.DATA_DIR
    prima di caricare raspi-scanner.py (che chiama auth.ensure_default_user()
    a livello di modulo) basta a isolare ogni test dal vero data/users.json."""

    def setUp(self):
        self._tmp_dir = tempfile.mkdtemp()
        self._orig_data_dir = config.DATA_DIR
        self._orig_users_path = config.USERS_JSON_PATH
        self._orig_tls_cert = config.TLS_CERT_PATH
        self._orig_tls_key = config.TLS_KEY_PATH
        self._orig_history_db = config.HISTORY_DB_PATH
        self._orig_webhooks_path = config.WEBHOOKS_JSON_PATH
        self._orig_monitoring_path = config.MONITORING_JSON_PATH
        self._orig_generate = auth.generate_initial_password
        config.DATA_DIR = self._tmp_dir
        config.USERS_JSON_PATH = str(Path(self._tmp_dir) / "users.json")
        config.TLS_CERT_PATH = str(Path(self._tmp_dir) / "tls_cert.pem")
        config.TLS_KEY_PATH = str(Path(self._tmp_dir) / "tls_key.pem")
        # /api/scan/start avvia un vero thread in background (scan_engine
        # non e' mockato in questa base class): se arriva a salvare lo
        # storico o a notificare un webhook, non deve MAI toccare i file
        # reali in data/.
        config.HISTORY_DB_PATH = str(Path(self._tmp_dir) / "history.db")
        config.WEBHOOKS_JSON_PATH = str(Path(self._tmp_dir) / "webhooks.json")
        config.MONITORING_JSON_PATH = str(Path(self._tmp_dir) / "monitoring.json")
        auth.generate_initial_password = lambda: "BootstrapPassw0rd"

        self.module = _load_raspi_scanner_module()
        self.module.app.testing = True
        self.client = self.module.app.test_client()

        # L'utente di bootstrap nasce con must_change_password=True: lo
        # cambiamo subito cosi' i test seguenti non restano bloccati da
        # _PASSWORD_CHANGE_ALWAYS_ALLOWED su endpoint che non c'entrano.
        auth.set_password(auth.DEFAULT_USERNAME, "AdminPassw0rd1")
        auth.add_user("operator1", "OperatorPassw0rd1", role="operator")
        auth.add_user("viewer1", "ViewerPassw0rd1", role="viewer")

        self.admin_auth = (auth.DEFAULT_USERNAME, "AdminPassw0rd1")
        self.operator_auth = ("operator1", "OperatorPassw0rd1")
        self.viewer_auth = ("viewer1", "ViewerPassw0rd1")

    def tearDown(self):
        auth.generate_initial_password = self._orig_generate
        config.DATA_DIR = self._orig_data_dir
        config.USERS_JSON_PATH = self._orig_users_path
        config.TLS_CERT_PATH = self._orig_tls_cert
        config.TLS_KEY_PATH = self._orig_tls_key
        config.HISTORY_DB_PATH = self._orig_history_db
        config.WEBHOOKS_JSON_PATH = self._orig_webhooks_path
        config.MONITORING_JSON_PATH = self._orig_monitoring_path
        shutil.rmtree(self._tmp_dir, ignore_errors=True)


class TestOriginCsrfProtection(RaspiScannerAppTestCase):
    """P1: senza controllo di Origin, un <form method="POST"> ospitato su
    un sito malevolo potrebbe far ripartire uno scan (o peggio) sfruttando
    le credenziali Basic Auth gia' salvate dal browser dell'operatore."""

    def test_mutating_request_with_foreign_origin_is_blocked(self):
        resp = self.client.post(
            "/api/scan/stop", auth=self.operator_auth,
            headers={"Origin": "http://evil.example.com"},
        )
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.get_json()["error"], "forbidden_origin")

    def test_mutating_request_with_matching_origin_is_allowed(self):
        resp = self.client.post(
            "/api/scan/stop", auth=self.operator_auth,
            headers={"Origin": "http://localhost"},
        )
        self.assertEqual(resp.status_code, 200)

    def test_mutating_request_without_origin_header_is_allowed(self):
        """Molti client (curl, richieste dirette same-origin di alcuni
        browser) non mandano affatto l'header Origin: non va bloccata una
        richiesta legittima solo perche' non lo manda."""
        resp = self.client.post("/api/scan/stop", auth=self.operator_auth)
        self.assertEqual(resp.status_code, 200)

    def test_get_request_ignores_origin(self):
        """Il controllo Origin si applica solo ai metodi mutanti: una GET
        con Origin estraneo non deve mai essere bloccata da questo
        meccanismo (non e' un attacco CSRF possibile su una GET idempotente)."""
        resp = self.client.get(
            "/api/network", auth=self.viewer_auth,
            headers={"Origin": "http://evil.example.com"},
        )
        self.assertEqual(resp.status_code, 200)


class TestRoleBasedAccessControl(RaspiScannerAppTestCase):
    def test_viewer_can_read_network_status(self):
        resp = self.client.get("/api/network", auth=self.viewer_auth)
        self.assertEqual(resp.status_code, 200)

    def test_viewer_cannot_start_scan(self):
        resp = self.client.post("/api/scan/start", auth=self.viewer_auth)
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.get_json()["error"], "forbidden")

    def test_operator_can_start_scan(self):
        resp = self.client.post("/api/scan/start", auth=self.operator_auth)
        self.assertNotEqual(resp.status_code, 403)

    def test_operator_cannot_start_hotspot(self):
        """L'hotspot apre un nuovo punto di accesso non autenticato:
        trattato come admin-only, non basta il ruolo operator."""
        resp = self.client.post(
            "/api/hotspot/start", auth=self.operator_auth,
            json={"ssid": "test", "password": "password123"},
        )
        self.assertEqual(resp.status_code, 403)

    def test_viewer_cannot_list_users(self):
        resp = self.client.get("/api/settings/users", auth=self.viewer_auth)
        self.assertEqual(resp.status_code, 403)

    def test_admin_can_list_users_with_roles(self):
        resp = self.client.get("/api/settings/users", auth=self.admin_auth)
        self.assertEqual(resp.status_code, 200)
        by_name = {u["username"]: u["role"] for u in resp.get_json()["users"]}
        self.assertEqual(by_name["operator1"], "operator")

    def test_operator_cannot_add_user(self):
        resp = self.client.post(
            "/api/settings/users", auth=self.operator_auth,
            json={"username": "nuovo", "password": "password123"},
        )
        self.assertEqual(resp.status_code, 403)

    def test_admin_can_add_user_with_role(self):
        resp = self.client.post(
            "/api/settings/users", auth=self.admin_auth,
            json={"username": "nuovo", "password": "password123", "role": "operator"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(auth.get_role("nuovo"), "operator")

    def test_operator_cannot_delete_user(self):
        resp = self.client.delete("/api/settings/users/viewer1", auth=self.operator_auth)
        self.assertEqual(resp.status_code, 403)


class TestSettingsMeIncludesRole(RaspiScannerAppTestCase):
    def test_returns_own_role(self):
        resp = self.client.get("/api/settings/me", auth=self.operator_auth)
        self.assertEqual(resp.get_json()["role"], "operator")


class TestPasswordChangeSelfOrAdmin(RaspiScannerAppTestCase):
    """Ogni utente puo' sempre cambiare la PROPRIA password; cambiare
    quella di un altro utente richiede il ruolo admin."""

    def test_user_can_change_own_password(self):
        resp = self.client.post(
            "/api/settings/users/password", auth=self.viewer_auth,
            json={"username": "viewer1", "password": "NuovaPassword123"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(auth.verify("viewer1", "NuovaPassword123"))

    def test_non_admin_cannot_change_others_password(self):
        resp = self.client.post(
            "/api/settings/users/password", auth=self.viewer_auth,
            json={"username": "operator1", "password": "NuovaPassword123"},
        )
        self.assertEqual(resp.status_code, 403)
        self.assertFalse(auth.verify("operator1", "NuovaPassword123"))

    def test_admin_can_change_others_password(self):
        resp = self.client.post(
            "/api/settings/users/password", auth=self.admin_auth,
            json={"username": "operator1", "password": "NuovaPassword123"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(auth.verify("operator1", "NuovaPassword123"))


class TestExportStructuredJson(RaspiScannerAppTestCase):
    """P4 'structured JSON export': l'export JSON e' un envelope con
    metadati (quando lo scan e' stato raccolto, quanti device, che tipo di
    export), non piu' un array nudo — un consumatore esterno non deve
    dedurre il timing da un header HTTP o da un mtime del file scaricato."""

    _FAKE_DEVICE = {
        "ip": "192.168.1.21", "mac": "AA:BB:CC:11:22:33", "vendor": "Hikvision",
        "model": "DS-2CD2043G0", "hostname": None, "device_type": "Camera",
        "is_camera": True, "open_ports": [{"port": 554, "service": "RTSP"}],
        "rtsp_url": "rtsp://192.168.1.21:554/", "admin_url": None,
    }

    def setUp(self):
        super().setUp()
        self._orig_state = dict(scan_engine._state)
        scan_engine._state.update(
            devices={"192.168.1.21": dict(self._FAKE_DEVICE)},
            started_at=1000.0, finished_at=1090.0,
        )

    def tearDown(self):
        scan_engine._state.clear()
        scan_engine._state.update(self._orig_state)
        super().tearDown()

    def test_json_export_envelope_shape(self):
        resp = self.client.get("/api/export?type=all&format=json", auth=self.viewer_auth)
        self.assertEqual(resp.status_code, 200)
        payload = resp.get_json()
        self.assertEqual(payload["type"], "all")
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["scan_started_at"], 1000.0)
        self.assertEqual(payload["scan_finished_at"], 1090.0)
        self.assertIn("exported_at", payload)
        self.assertEqual(payload["devices"][0]["ip"], "192.168.1.21")

    def test_json_export_cameras_only(self):
        resp = self.client.get("/api/export?type=cameras&format=json", auth=self.viewer_auth)
        payload = resp.get_json()
        self.assertEqual(payload["type"], "cameras")
        self.assertEqual(payload["count"], 1)

    def test_csv_export_unaffected_by_envelope_change(self):
        resp = self.client.get("/api/export?type=all&format=csv", auth=self.viewer_auth)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/csv", resp.content_type)
        body = resp.get_data(as_text=True)
        self.assertIn("192.168.1.21", body)
        self.assertIn("Hikvision", body)


class TestHistoryRoutes(RaspiScannerAppTestCase):
    """P4 'comparative reports' / 'local asset database' / 'historical
    dashboard': le route leggono da scanner.storage, gia' testato a
    fondo in isolamento in tests/test_storage.py — qui interessano solo
    ruoli richiesti e forma della risposta HTTP."""

    def setUp(self):
        super().setUp()
        from scanner import storage
        self.storage = storage
        device_v1 = {"ip": "192.168.1.21", "mac": "AA:BB:CC:11:22:33", "vendor": "Hikvision",
                     "model": None, "device_type": "Camera", "is_camera": True, "is_nvr": False,
                     "network": "192.168.1.0/24", "open_ports": []}
        self.scan_id_1 = storage.save_scan([device_v1], 1000.0, 1010.0)
        device_v2 = dict(device_v1, open_ports=[{"port": 554, "service": "RTSP"}])
        self.scan_id_2 = storage.save_scan([device_v2], 2000.0, 2010.0)

    def test_list_scans(self):
        resp = self.client.get("/api/history/scans", auth=self.viewer_auth)
        self.assertEqual(resp.status_code, 200)
        scans = resp.get_json()["scans"]
        self.assertEqual([s["id"] for s in scans], [self.scan_id_2, self.scan_id_1])

    def test_scan_devices(self):
        resp = self.client.get(f"/api/history/scans/{self.scan_id_1}/devices", auth=self.viewer_auth)
        devices = resp.get_json()["devices"]
        self.assertEqual(devices[0]["ip"], "192.168.1.21")

    def test_compare_requires_both_ids(self):
        resp = self.client.get("/api/history/compare?old=1", auth=self.viewer_auth)
        self.assertEqual(resp.status_code, 400)

    def test_compare_detects_open_port_change(self):
        resp = self.client.get(
            f"/api/history/compare?old={self.scan_id_1}&new={self.scan_id_2}", auth=self.viewer_auth,
        )
        diff = resp.get_json()
        self.assertEqual(len(diff["changed"]), 1)
        self.assertIn("open_ports", diff["changed"][0]["fields"])

    def test_list_assets(self):
        resp = self.client.get("/api/history/assets", auth=self.viewer_auth)
        assets = resp.get_json()["assets"]
        self.assertEqual(assets[0]["mac"], "AA:BB:CC:11:22:33")
        self.assertEqual(assets[0]["times_seen"], 2)


class TestTopologyRoute(RaspiScannerAppTestCase):
    """P4 'network topology map': la route legge scan_engine.get_state()
    direttamente, gia' testato a fondo in test_scan_engine.py e
    test_integration_scan_report.py — qui interessa solo che risponda con
    la forma attesa."""

    def setUp(self):
        super().setUp()
        from scanner import scan_engine
        self._orig_topology = scan_engine._state.get("topology")
        # scan_engine._state e' un singleton di modulo condiviso con TUTTI
        # gli altri file di test nello stesso processo pytest: un test che
        # gira prima di questo (in un altro file) puo' aver lasciato
        # topology popolata. Reset esplicito qui, non ci si affida alla
        # pulizia altrui.
        scan_engine._state["topology"] = {}
        self.scan_engine = scan_engine

    def tearDown(self):
        self.scan_engine._state["topology"] = self._orig_topology
        super().tearDown()

    def test_empty_before_any_scan(self):
        resp = self.client.get("/api/topology", auth=self.viewer_auth)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), {})

    def test_viewer_can_read_topology(self):
        resp = self.client.get("/api/topology", auth=self.viewer_auth)
        self.assertEqual(resp.status_code, 200)


class TestWebhookSettings(RaspiScannerAppTestCase):
    def test_viewer_cannot_read_webhook_config(self):
        resp = self.client.get("/api/settings/webhook", auth=self.viewer_auth)
        self.assertEqual(resp.status_code, 403)

    def test_admin_can_get_and_set_webhook_config(self):
        resp = self.client.get("/api/settings/webhook", auth=self.admin_auth)
        self.assertEqual(resp.get_json(), {"url": None, "enabled": False})

        resp = self.client.post(
            "/api/settings/webhook", auth=self.admin_auth,
            json={"url": "https://example.com/hook", "enabled": True},
        )
        self.assertEqual(resp.status_code, 200)

        resp = self.client.get("/api/settings/webhook", auth=self.admin_auth)
        self.assertEqual(resp.get_json(), {"url": "https://example.com/hook", "enabled": True})

    def test_operator_cannot_set_webhook_config(self):
        resp = self.client.post(
            "/api/settings/webhook", auth=self.operator_auth,
            json={"url": "https://example.com/hook", "enabled": True},
        )
        self.assertEqual(resp.status_code, 403)

    def test_invalid_scheme_rejected(self):
        resp = self.client.post(
            "/api/settings/webhook", auth=self.admin_auth,
            json={"url": "file:///etc/passwd", "enabled": True},
        )
        self.assertEqual(resp.status_code, 400)


class TestMonitoringSettings(RaspiScannerAppTestCase):
    def test_viewer_cannot_read_monitoring_config(self):
        resp = self.client.get("/api/settings/monitoring", auth=self.viewer_auth)
        self.assertEqual(resp.status_code, 403)

    def test_admin_can_get_and_set_monitoring_config(self):
        resp = self.client.get("/api/settings/monitoring", auth=self.admin_auth)
        self.assertEqual(resp.get_json(), {"enabled": False, "interval_minutes": monitoring.DEFAULT_INTERVAL_MINUTES})

        resp = self.client.post(
            "/api/settings/monitoring", auth=self.admin_auth,
            json={"enabled": True, "interval_minutes": 30},
        )
        self.assertEqual(resp.status_code, 200)

        resp = self.client.get("/api/settings/monitoring", auth=self.admin_auth)
        self.assertEqual(resp.get_json(), {"enabled": True, "interval_minutes": 30})

    def test_operator_cannot_set_monitoring_config(self):
        resp = self.client.post(
            "/api/settings/monitoring", auth=self.operator_auth,
            json={"enabled": True, "interval_minutes": 30},
        )
        self.assertEqual(resp.status_code, 403)

    def test_interval_below_minimum_rejected(self):
        resp = self.client.post(
            "/api/settings/monitoring", auth=self.admin_auth,
            json={"enabled": True, "interval_minutes": 1},
        )
        self.assertEqual(resp.status_code, 400)


class TestAuditReportRoute(RaspiScannerAppTestCase):
    """Audit mode (P4): report da uno scan SALVATO (non lo stato live di
    /api/report), con la sezione "changes since previous scan" calcolata
    automaticamente rispetto al giro precedente."""

    def setUp(self):
        super().setUp()
        device_v1 = {"ip": "192.168.1.21", "mac": "AA:BB:CC:11:22:33", "vendor": "Hikvision",
                     "model": None, "device_type": "Camera", "is_camera": True, "is_nvr": False,
                     "network": "192.168.1.0/24", "open_ports": []}
        self.scan_id_1 = storage.save_scan([device_v1], 1000.0, 1010.0)
        device_v2 = dict(device_v1, ip="192.168.1.30", mac="AA:BB:CC:99:88:77")
        self.scan_id_2 = storage.save_scan([device_v1, device_v2], 2000.0, 2010.0)

    def test_no_saved_scans_returns_404(self):
        """Un DB vuoto (nessuno scan mai salvato) e nessuno scan_id
        esplicito: non c'e' nulla da mostrare, 404 con un messaggio
        chiaro invece di un report vuoto o un errore 500."""
        storage.get_scan_meta(self.scan_id_1)  # sanity: il fixture esiste
        import sqlite3
        with sqlite3.connect(config.HISTORY_DB_PATH) as conn:
            conn.execute("DELETE FROM scans")
            conn.execute("DELETE FROM scan_devices")
        resp = self.client.get("/api/audit/report", auth=self.viewer_auth)
        self.assertEqual(resp.status_code, 404)

    def test_defaults_to_latest_scan(self):
        resp = self.client.get("/api/audit/report", auth=self.viewer_auth)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["scan_id"], self.scan_id_2)
        self.assertEqual(data["compared_to_scan_id"], self.scan_id_1)
        self.assertIn("CHANGES SINCE PREVIOUS SCAN", data["text"])
        self.assertIn("192.168.1.30", data["text"])

    def test_explicit_scan_id_with_no_previous_scan(self):
        resp = self.client.get(f"/api/audit/report?scan_id={self.scan_id_1}", auth=self.viewer_auth)
        data = resp.get_json()
        self.assertIsNone(data["compared_to_scan_id"])
        self.assertNotIn("CHANGES SINCE PREVIOUS SCAN", data["text"])

    def test_unknown_scan_id_returns_404(self):
        resp = self.client.get("/api/audit/report?scan_id=999999", auth=self.viewer_auth)
        self.assertEqual(resp.status_code, 404)

    def test_viewer_can_read_audit_report(self):
        resp = self.client.get("/api/audit/report", auth=self.viewer_auth)
        self.assertEqual(resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
