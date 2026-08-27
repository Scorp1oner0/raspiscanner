"""Test su scanner.monitoring: configurazione su file temporaneo (mai il
vero data/monitoring.json) e scan_engine.run_scan mockato — nessuno scan
reale, nessun vero thread di scheduling lasciato girare oltre la durata
del singolo test che lo avvia esplicitamente."""
import shutil
import tempfile
import unittest
from pathlib import Path

from scanner import config, monitoring


class MonitoringTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp_dir = tempfile.mkdtemp()
        self._orig_path = config.MONITORING_JSON_PATH
        self._orig_data_dir = config.DATA_DIR
        config.DATA_DIR = self._tmp_dir
        config.MONITORING_JSON_PATH = str(Path(self._tmp_dir) / "monitoring.json")

    def tearDown(self):
        config.MONITORING_JSON_PATH = self._orig_path
        config.DATA_DIR = self._orig_data_dir
        shutil.rmtree(self._tmp_dir, ignore_errors=True)


class TestMonitoringConfig(MonitoringTestCase):
    def test_default_config_is_disabled(self):
        self.assertEqual(
            monitoring.get_config(),
            {"enabled": False, "interval_minutes": monitoring.DEFAULT_INTERVAL_MINUTES},
        )

    def test_set_and_get_config(self):
        ok, _ = monitoring.set_config(True, 30)
        self.assertTrue(ok)
        self.assertEqual(monitoring.get_config(), {"enabled": True, "interval_minutes": 30})

    def test_interval_below_minimum_rejected(self):
        ok, message = monitoring.set_config(True, 1)
        self.assertFalse(ok)
        self.assertIn("at least", message)
        # Non deve aver scritto nulla: get_config() resta sul default.
        self.assertFalse(monitoring.get_config()["enabled"])

    def test_non_integer_interval_rejected(self):
        ok, message = monitoring.set_config(True, "not-a-number")
        self.assertFalse(ok)
        self.assertIn("whole number", message)

    def test_interval_accepts_numeric_string(self):
        """Il body JSON di /api/settings/monitoring passa interval_minutes
        cosi' com'e' arrivato dal client: deve funzionare sia con un int
        che con una stringa numerica (un <input type="number"> puo'
        mandare l'uno o l'altro a seconda del browser)."""
        ok, _ = monitoring.set_config(True, "45")
        self.assertTrue(ok)
        self.assertEqual(monitoring.get_config()["interval_minutes"], 45)


class TestSchedulerLoop(MonitoringTestCase):
    """Testa _scheduler_loop() direttamente (non start_scheduler(), che
    lo lancerebbe in un thread reale con un time.sleep(_POLL_SECONDS)
    vero: troppo lento per un test unitario) — monkeypatchando time.sleep
    per farlo girare un numero di iterazioni finito e controllato invece
    che all'infinito."""

    def setUp(self):
        super().setUp()
        self._orig_run_scan = monitoring.scan_engine.run_scan
        self._orig_sleep = monitoring.time.sleep
        self.run_scan_calls = 0

    def tearDown(self):
        monitoring.scan_engine.run_scan = self._orig_run_scan
        monitoring.time.sleep = self._orig_sleep
        super().tearDown()

    def _run_loop_for_n_iterations(self, n):
        calls = {"count": 0}

        def fake_sleep(seconds):
            calls["count"] += 1
            if calls["count"] > n:
                raise StopIteration  # esce dal while True dopo n iterazioni
        monitoring.time.sleep = fake_sleep
        try:
            monitoring._scheduler_loop()
        except StopIteration:
            pass

    def test_disabled_never_calls_run_scan(self):
        def fake_run_scan():
            self.run_scan_calls += 1
            return True, "Scan started"
        monitoring.scan_engine.run_scan = fake_run_scan
        self._run_loop_for_n_iterations(3)
        self.assertEqual(self.run_scan_calls, 0)

    def test_enabled_calls_run_scan_on_first_poll(self):
        monitoring.set_config(True, 60)

        def fake_run_scan():
            self.run_scan_calls += 1
            return True, "Scan started"
        monitoring.scan_engine.run_scan = fake_run_scan
        self._run_loop_for_n_iterations(1)
        self.assertEqual(self.run_scan_calls, 1)

    def test_skipped_scan_does_not_block_next_poll(self):
        """Se run_scan() ritorna "gia' in corso" (scan manuale in corso),
        il prossimo poll (non un intero interval_minutes dopo) deve
        ritentare — non deve considerare quel giro come "fatto"."""
        monitoring.set_config(True, 60)

        def fake_run_scan():
            self.run_scan_calls += 1
            return False, "Scan already in progress"
        monitoring.scan_engine.run_scan = fake_run_scan
        self._run_loop_for_n_iterations(3)
        # Ogni poll ritenta (nessuno e' andato a buon fine, last_scan_at
        # non e' mai stato aggiornato): 3 iterazioni -> 3 tentativi.
        self.assertEqual(self.run_scan_calls, 3)

    def test_exception_in_loop_does_not_propagate(self):
        """Un'eccezione imprevista in un'iterazione non deve terminare il
        thread di scheduling — verrebbe scambiato per un continuous
        monitoring "silenziosamente spento" senza che nessuno se ne
        accorga."""
        monitoring.set_config(True, 60)

        def raising_run_scan():
            raise RuntimeError("boom")
        monitoring.scan_engine.run_scan = raising_run_scan
        self._run_loop_for_n_iterations(2)  # non deve sollevare


if __name__ == "__main__":
    unittest.main()
