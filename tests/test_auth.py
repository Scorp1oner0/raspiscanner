import json
import shutil
import tempfile
import unittest
from pathlib import Path

from scanner import auth, config

TEST_PASSWORD = "TestInitialPassw0rd"


class AuthTestCase(unittest.TestCase):
    """Ogni test lavora su una data/ temporanea, cosi' non tocca mai
    data/users.json reale ne' dipende dall'ordine di esecuzione. La
    password iniziale casuale e' resa deterministica per i test
    monkeypatchando generate_initial_password, non disattivando la
    casualita' nel codice vero."""

    def setUp(self):
        self._tmp_dir = tempfile.mkdtemp()
        self._orig_data_dir = config.DATA_DIR
        self._orig_users_path = config.USERS_JSON_PATH
        self._orig_generate = auth.generate_initial_password
        config.DATA_DIR = self._tmp_dir
        config.USERS_JSON_PATH = str(Path(self._tmp_dir) / "users.json")
        auth.generate_initial_password = lambda: TEST_PASSWORD

    def tearDown(self):
        config.DATA_DIR = self._orig_data_dir
        config.USERS_JSON_PATH = self._orig_users_path
        auth.generate_initial_password = self._orig_generate
        shutil.rmtree(self._tmp_dir, ignore_errors=True)


class TestGenerateInitialPassword(unittest.TestCase):
    def test_default_length(self):
        self.assertEqual(len(auth.generate_initial_password()), auth._INITIAL_PASSWORD_LENGTH)

    def test_alphanumeric_only(self):
        password = auth.generate_initial_password()
        self.assertTrue(password.isalnum())

    def test_different_each_call(self):
        """Bug reale che questa feature elimina: una password di default
        fissa e identica su ogni installazione."""
        passwords = {auth.generate_initial_password() for _ in range(20)}
        self.assertGreater(len(passwords), 1)


class TestEnsureDefaultUser(AuthTestCase):
    def test_creates_default_user_when_missing(self):
        auth.ensure_default_user()
        self.assertEqual(auth.list_usernames(), [auth.DEFAULT_USERNAME])
        self.assertTrue(auth.verify(auth.DEFAULT_USERNAME, TEST_PASSWORD))

    def test_default_user_must_change_password(self):
        """P0: l'utente di bootstrap nasce marcato "da cambiare al primo
        accesso", non e' un utente utilizzabile a tempo indeterminato."""
        auth.ensure_default_user()
        self.assertTrue(auth.must_change_password(auth.DEFAULT_USERNAME))

    def test_does_not_overwrite_existing_users(self):
        auth.ensure_default_user()
        auth.set_password(auth.DEFAULT_USERNAME, "unaltrapassword")
        auth.ensure_default_user()
        self.assertFalse(auth.verify(auth.DEFAULT_USERNAME, TEST_PASSWORD))
        self.assertTrue(auth.verify(auth.DEFAULT_USERNAME, "unaltrapassword"))


class TestMustChangePassword(AuthTestCase):
    def setUp(self):
        super().setUp()
        auth.ensure_default_user()

    def test_true_for_bootstrap_user(self):
        self.assertTrue(auth.must_change_password(auth.DEFAULT_USERNAME))

    def test_cleared_after_password_change(self):
        auth.set_password(auth.DEFAULT_USERNAME, "unanuovapassword")
        self.assertFalse(auth.must_change_password(auth.DEFAULT_USERNAME))

    def test_false_for_user_added_normally(self):
        """Solo l'utente di bootstrap nasce con l'obbligo: uno aggiunto a
        mano da un utente gia' autenticato non lo eredita."""
        auth.add_user("tecnico", "password123")
        self.assertFalse(auth.must_change_password("tecnico"))

    def test_false_for_unknown_user(self):
        self.assertFalse(auth.must_change_password("nessuno"))


class TestBackwardCompatibleOldFormat(AuthTestCase):
    """Installazioni precedenti a must_change_password salvavano
    data/users.json come {username: "hash-diretto"} (stringa, non dict):
    devono continuare a funzionare, mai un errore o un blocco improvviso
    per chi aggiorna un'istanza gia' in uso."""

    def test_reads_old_flat_string_format(self):
        from werkzeug.security import generate_password_hash

        Path(config.DATA_DIR).mkdir(parents=True, exist_ok=True)
        with open(config.USERS_JSON_PATH, "w", encoding="utf-8") as fh:
            json.dump({"RaspiScanner": generate_password_hash("OldStylePassword")}, fh)

        self.assertTrue(auth.verify("RaspiScanner", "OldStylePassword"))
        self.assertFalse(auth.must_change_password("RaspiScanner"))
        self.assertEqual(auth.list_usernames(), ["RaspiScanner"])

    def test_old_format_upgraded_to_new_on_next_write(self):
        from werkzeug.security import generate_password_hash

        Path(config.DATA_DIR).mkdir(parents=True, exist_ok=True)
        with open(config.USERS_JSON_PATH, "w", encoding="utf-8") as fh:
            json.dump({"RaspiScanner": generate_password_hash("OldStylePassword")}, fh)

        auth.set_password("RaspiScanner", "NewPassword123")

        with open(config.USERS_JSON_PATH, encoding="utf-8") as fh:
            on_disk = json.load(fh)
        self.assertIsInstance(on_disk["RaspiScanner"], dict)
        self.assertIn("hash", on_disk["RaspiScanner"])


class TestVerify(AuthTestCase):
    def setUp(self):
        super().setUp()
        auth.ensure_default_user()

    def test_correct_credentials(self):
        self.assertTrue(auth.verify(auth.DEFAULT_USERNAME, TEST_PASSWORD))

    def test_wrong_password(self):
        self.assertFalse(auth.verify(auth.DEFAULT_USERNAME, "sbagliata"))

    def test_unknown_username(self):
        self.assertFalse(auth.verify("nessuno", TEST_PASSWORD))

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
        self.assertIn("exists", message)

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
        self.assertFalse(auth.verify(auth.DEFAULT_USERNAME, TEST_PASSWORD))

    def test_rejects_unknown_user(self):
        ok, message = auth.set_password("nessuno", "nuovapassword")
        self.assertFalse(ok)
        self.assertIn("exist", message)

    def test_rejects_short_password(self):
        ok, _ = auth.set_password(auth.DEFAULT_USERNAME, "abc")
        self.assertFalse(ok)


class TestRoles(AuthTestCase):
    def setUp(self):
        super().setUp()
        auth.ensure_default_user()

    def test_bootstrap_user_is_admin(self):
        self.assertEqual(auth.get_role(auth.DEFAULT_USERNAME), "admin")

    def test_add_user_default_role_is_viewer(self):
        """Principio del privilegio minimo: senza specificare un ruolo,
        un nuovo utente non deve ereditare accesso pieno per omissione."""
        auth.add_user("tecnico", "password123")
        self.assertEqual(auth.get_role("tecnico"), "viewer")

    def test_add_user_explicit_role(self):
        auth.add_user("operatore", "password123", role="operator")
        self.assertEqual(auth.get_role("operatore"), "operator")

    def test_add_user_rejects_invalid_role(self):
        ok, message = auth.add_user("tecnico", "password123", role="superadmin")
        self.assertFalse(ok)
        self.assertIn("Role", message)
        self.assertIsNone(auth.get_role("tecnico"))

    def test_get_role_unknown_user_returns_none(self):
        self.assertIsNone(auth.get_role("nessuno"))

    def test_has_role_at_least_respects_order(self):
        auth.add_user("viewer1", "password123", role="viewer")
        auth.add_user("operator1", "password123", role="operator")
        self.assertTrue(auth.has_role_at_least("viewer1", "viewer"))
        self.assertFalse(auth.has_role_at_least("viewer1", "operator"))
        self.assertTrue(auth.has_role_at_least("operator1", "viewer"))
        self.assertTrue(auth.has_role_at_least("operator1", "operator"))
        self.assertFalse(auth.has_role_at_least("operator1", "admin"))
        self.assertTrue(auth.has_role_at_least(auth.DEFAULT_USERNAME, "admin"))

    def test_has_role_at_least_unknown_user_is_false(self):
        self.assertFalse(auth.has_role_at_least("nessuno", "viewer"))

    def test_set_password_preserves_role(self):
        """Bug reale che questo fix evita: set_password riscriveva
        l'intero record perdendo il ruolo assegnato, declassando in
        silenzio qualunque utente non-default al primo cambio password."""
        auth.add_user("operatore", "password123", role="operator")
        auth.set_password("operatore", "nuovapassword")
        self.assertEqual(auth.get_role("operatore"), "operator")
        self.assertTrue(auth.verify("operatore", "nuovapassword"))

    def test_list_users_includes_role(self):
        auth.add_user("tecnico", "password123", role="operator")
        users = auth.list_users()
        by_name = {u["username"]: u["role"] for u in users}
        self.assertEqual(by_name[auth.DEFAULT_USERNAME], "admin")
        self.assertEqual(by_name["tecnico"], "operator")


class TestRoleBackwardCompatibility(AuthTestCase):
    """Utenti creati da versioni precedenti (senza il campo "role", sia in
    formato stringa diretta sia in dict) devono risultare "admin": avevano
    di fatto accesso pieno prima che i ruoli esistessero, un aggiornamento
    non deve declassarli in silenzio."""

    def test_old_flat_string_format_is_admin(self):
        from werkzeug.security import generate_password_hash

        Path(config.DATA_DIR).mkdir(parents=True, exist_ok=True)
        with open(config.USERS_JSON_PATH, "w", encoding="utf-8") as fh:
            json.dump({"RaspiScanner": generate_password_hash("OldPassword")}, fh)

        self.assertEqual(auth.get_role("RaspiScanner"), "admin")

    def test_dict_without_role_field_is_admin(self):
        from werkzeug.security import generate_password_hash

        Path(config.DATA_DIR).mkdir(parents=True, exist_ok=True)
        with open(config.USERS_JSON_PATH, "w", encoding="utf-8") as fh:
            json.dump({
                "RaspiScanner": {
                    "hash": generate_password_hash("P0Password"),
                    "must_change_password": False,
                },
            }, fh)

        self.assertEqual(auth.get_role("RaspiScanner"), "admin")


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
        self.assertIn("only", message)

    def test_rejects_unknown_user(self):
        ok, message = auth.remove_user("nessuno")
        self.assertFalse(ok)
        self.assertIn("exist", message)


if __name__ == "__main__":
    unittest.main()
