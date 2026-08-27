"""Test su scanner.webhooks: configurazione su file temporaneo, mai il
vero data/webhooks.json. urllib.request.urlopen monkeypatchato per non
fare mai una vera richiesta di rete."""
import shutil
import tempfile
import unittest
import urllib.request
from pathlib import Path

from scanner import config, webhooks


class WebhooksTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp_dir = tempfile.mkdtemp()
        self._orig_path = config.WEBHOOKS_JSON_PATH
        self._orig_data_dir = config.DATA_DIR
        config.DATA_DIR = self._tmp_dir
        config.WEBHOOKS_JSON_PATH = str(Path(self._tmp_dir) / "webhooks.json")

    def tearDown(self):
        config.WEBHOOKS_JSON_PATH = self._orig_path
        config.DATA_DIR = self._orig_data_dir
        shutil.rmtree(self._tmp_dir, ignore_errors=True)


class TestWebhookConfig(WebhooksTestCase):
    def test_default_config_is_disabled(self):
        self.assertEqual(webhooks.get_config(), {"url": None, "enabled": False})

    def test_set_and_get_config(self):
        ok, _ = webhooks.set_config("https://example.com/hook", True)
        self.assertTrue(ok)
        self.assertEqual(webhooks.get_config(), {"url": "https://example.com/hook", "enabled": True})

    def test_enabled_without_url_rejected(self):
        ok, message = webhooks.set_config("", True)
        self.assertFalse(ok)
        self.assertIn("URL is required", message)

    def test_non_http_scheme_rejected(self):
        ok, message = webhooks.set_config("file:///etc/passwd", True)
        self.assertFalse(ok)
        self.assertIn("http", message)

    def test_ftp_scheme_rejected(self):
        ok, _ = webhooks.set_config("ftp://example.com/hook", True)
        self.assertFalse(ok)

    def test_enabled_forced_false_when_url_cleared(self):
        webhooks.set_config("https://example.com/hook", True)
        webhooks.set_config("", False)
        self.assertEqual(webhooks.get_config(), {"url": None, "enabled": False})

    def test_get_config_never_enabled_without_a_url_even_if_file_says_so(self):
        """Difesa in profondita': anche se il file su disco fosse
        malformato/manomesso con enabled=true e url vuoto, get_config()
        non deve mai proporre di notificare un URL vuoto."""
        import json
        with open(config.WEBHOOKS_JSON_PATH, "w") as fh:
            json.dump({"url": None, "enabled": True}, fh)
        self.assertFalse(webhooks.get_config()["enabled"])


class TestNotifyScanComplete(WebhooksTestCase):
    def setUp(self):
        super().setUp()
        self._orig_urlopen = urllib.request.urlopen
        self.requests = []

    def tearDown(self):
        urllib.request.urlopen = self._orig_urlopen
        super().tearDown()

    def _fake_urlopen(self, req, timeout=None):
        self.requests.append(req)

        class _Resp:
            def close(self):
                pass
        return _Resp()

    def test_does_not_call_urlopen_when_disabled(self):
        def fail(*a, **k):
            raise AssertionError("non doveva fare nessuna richiesta")
        urllib.request.urlopen = fail
        webhooks.notify_scan_complete({"device_count": 5})

    def test_posts_json_body_when_enabled(self):
        webhooks.set_config("https://example.com/hook", True)
        urllib.request.urlopen = self._fake_urlopen
        webhooks.notify_scan_complete({"device_count": 5, "scan_id": 3})
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.requests[0].full_url, "https://example.com/hook")
        self.assertEqual(self.requests[0].get_method(), "POST")
        self.assertIn(b"device_count", self.requests[0].data)

    def test_urlopen_failure_does_not_raise(self):
        webhooks.set_config("https://example.com/hook", True)

        def raise_timeout(req, timeout=None):
            raise TimeoutError("connection timed out")
        urllib.request.urlopen = raise_timeout
        webhooks.notify_scan_complete({"device_count": 5})  # non deve sollevare


if __name__ == "__main__":
    unittest.main()
