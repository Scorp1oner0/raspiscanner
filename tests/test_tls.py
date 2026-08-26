import shutil
import tempfile
import unittest
from pathlib import Path

from scanner import config, tls


class TestEnsureCert(unittest.TestCase):
    def setUp(self):
        self._tmp_dir = tempfile.mkdtemp()
        self._orig_data_dir = config.DATA_DIR
        self._orig_cert_path = config.TLS_CERT_PATH
        self._orig_key_path = config.TLS_KEY_PATH
        config.DATA_DIR = self._tmp_dir
        config.TLS_CERT_PATH = str(Path(self._tmp_dir) / "tls_cert.pem")
        config.TLS_KEY_PATH = str(Path(self._tmp_dir) / "tls_key.pem")

    def tearDown(self):
        config.DATA_DIR = self._orig_data_dir
        config.TLS_CERT_PATH = self._orig_cert_path
        config.TLS_KEY_PATH = self._orig_key_path
        shutil.rmtree(self._tmp_dir, ignore_errors=True)

    def test_generates_cert_and_key(self):
        cert_path, key_path = tls.ensure_cert()
        self.assertTrue(Path(cert_path).exists())
        self.assertTrue(Path(key_path).exists())
        self.assertIn("BEGIN CERTIFICATE", Path(cert_path).read_text())
        self.assertIn("PRIVATE KEY", Path(key_path).read_text())

    def test_reuses_existing_cert(self):
        cert_path, key_path = tls.ensure_cert()
        original_cert = Path(cert_path).read_text()
        original_key = Path(key_path).read_text()

        cert_path2, key_path2 = tls.ensure_cert()

        self.assertEqual(cert_path, cert_path2)
        self.assertEqual(Path(cert_path2).read_text(), original_cert)
        self.assertEqual(Path(key_path2).read_text(), original_key)

    def test_openssl_missing_returns_none(self):
        original_run = tls.subprocess.run

        def fake_run(cmd, **kwargs):
            raise FileNotFoundError("openssl non trovato")

        tls.subprocess.run = fake_run
        try:
            cert_path, key_path = tls.ensure_cert()
        finally:
            tls.subprocess.run = original_run

        self.assertIsNone(cert_path)
        self.assertIsNone(key_path)


if __name__ == "__main__":
    unittest.main()
