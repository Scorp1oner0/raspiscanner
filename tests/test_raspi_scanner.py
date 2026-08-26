"""Test sul comportamento di avvio di raspi-scanner.py (il file entry
point, non un pacchetto: caricato via importlib, stesso approccio gia'
usato manualmente durante lo sviluppo per testare l'app Flask completa)."""
import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner import config

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


if __name__ == "__main__":
    unittest.main()
