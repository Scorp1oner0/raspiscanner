import shutil
import tempfile
import unittest
from pathlib import Path

from scanner import auth, config


class AuthTestCase(unittest.TestCase):
    """Ogni test lavora su una data/ temporanea, cosi' non tocca mai
    data/users.json reale ne' dipende dall'ordine di esecuzione."""

    def setUp(self):
        self._tmp_dir = tempfile.mkdtemp()
        self._orig_data_dir = config.DATA_DIR
        self._orig_users_path = config.USERS_JSON_PATH
        config.DATA_DIR = self._tmp_dir
        config.USERS_JSON_PATH = str(Path(self._tmp_dir) / "users.json")

    def tearDown(self):
        config.DATA_DIR = self._orig_data_dir
        config.USERS_JSON_PATH = self._orig_users_path
        shutil.rmtree(self._tmp_dir, ignore_errors=True)


class TestEnsureDefaultUser(AuthTestCase):
    def test_creates_default_user_when_missing(self):
        auth.ensure_default_user()
        self.assertEqual(auth.list_usernames(), [auth.DEFAULT_USERNAME])
        self.assertTrue(auth.verify(auth.DEFAULT_USERNAME, auth.DEFAULT_PASSWORD))

    def test_does_not_overwrite_existing_users(self):
        auth.ensure_default_user()
        auth.set_password(auth.DEFAULT_USERNAME, "unaltrapassword")
        auth.ensure_default_user()
        self.assertFalse(auth.verify(auth.DEFAULT_USERNAME, auth.DEFAULT_PASSWORD))
        self.assertTrue(auth.verify(auth.DEFAULT_USERNAME, "unaltrapassword"))


class TestVerify(AuthTestCase):
    def setUp(self):
        super().setUp()
        auth.ensure_default_user()

    def test_correct_credentials(self):
        self.assertTrue(auth.verify(auth.DEFAULT_USERNAME, auth.DEFAULT_PASSWORD))

    def test_wrong_password(self):
        self.assertFalse(auth.verify(auth.DEFAULT_USERNAME, "sbagliata"))

    def test_unknown_username(self):
        self.assertFalse(auth.verify("nessuno", auth.DEFAULT_PASSWORD))

    def test_empty_credentials(self):
        self.assertFalse(auth.verify("", ""))
        self.assertFalse(auth.verify(None, None))


class TestAddUser(AuthTestCase):
    def setUp(self):
        super().setUp()
        auth.ensure_default_user()

    def test_add_new_user(self):
        ok, _ = auth.add_user("tecnico", "password123")
        self.assertTrue(ok)
        self.assertIn("tecnico", auth.list_usernames())
        self.assertTrue(auth.verify("tecnico", "password123"))

    def test_reject_duplicate_username(self):
        auth.add_user("tecnico", "password123")
        ok, message = auth.add_user("tecnico", "altrapassword")
        self.assertFalse(ok)
        self.assertIn("esistente", message)

    def test_reject_empty_username(self):
        ok, _ = auth.add_user("", "password123")
        self.assertFalse(ok)

    def test_reject_short_password(self):
        ok, message = auth.add_user("tecnico", "abc")
        self.assertFalse(ok)
        self.assertIn(str(auth.MIN_PASSWORD_LENGTH), message)


class TestSetPassword(AuthTestCase):
    def setUp(self):
        super().setUp()
        auth.ensure_default_user()

    def test_updates_existing_user(self):
        ok, _ = auth.set_password(auth.DEFAULT_USERNAME, "nuovapassword")
        self.assertTrue(ok)
        self.assertTrue(auth.verify(auth.DEFAULT_USERNAME, "nuovapassword"))
        self.assertFalse(auth.verify(auth.DEFAULT_USERNAME, auth.DEFAULT_PASSWORD))

    def test_rejects_unknown_user(self):
        ok, message = auth.set_password("nessuno", "nuovapassword")
        self.assertFalse(ok)
        self.assertIn("inesistente", message)

    def test_rejects_short_password(self):
        ok, _ = auth.set_password(auth.DEFAULT_USERNAME, "abc")
        self.assertFalse(ok)


class TestRemoveUser(AuthTestCase):
    def setUp(self):
        super().setUp()
        auth.ensure_default_user()
        auth.add_user("tecnico", "password123")

    def test_removes_existing_user(self):
        ok, _ = auth.remove_user("tecnico")
        self.assertTrue(ok)
        self.assertNotIn("tecnico", auth.list_usernames())

    def test_cannot_remove_last_user(self):
        auth.remove_user("tecnico")
        ok, message = auth.remove_user(auth.DEFAULT_USERNAME)
        self.assertFalse(ok)
        self.assertIn("unico", message)

    def test_rejects_unknown_user(self):
        ok, message = auth.remove_user("nessuno")
        self.assertFalse(ok)
        self.assertIn("inesistente", message)


if __name__ == "__main__":
    unittest.main()
