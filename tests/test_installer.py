"""Test statici su install.sh e raspiscanner.service: non installano
davvero nulla (richiederebbe root e modificherebbe il sistema), verificano
solo che i due file siano validi e internamente coerenti — sintassi bash,
sintassi/semantica del unit file systemd, e le regressioni concrete gia'
scoperte controllando dal vivo in questa stessa sessione di lavoro (il
bug data/oui.csv/users.json cancellati da --delete, e data/ che perdeva
la proprieta' di root a ogni reinstallazione).
"""
import shutil
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = REPO_ROOT / "install.sh"
SERVICE_FILE = REPO_ROOT / "raspiscanner.service"


class TestInstallShSyntax(unittest.TestCase):
    def test_bash_syntax_is_valid(self):
        result = subprocess.run(
            ["bash", "-n", str(INSTALL_SH)], capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_requires_sudo_before_doing_anything(self):
        text = INSTALL_SH.read_text()
        self.assertIn('$EUID" -ne 0', text)

    def test_rsync_excludes_runtime_state_files(self):
        """Regressione concreta scoperta dal vivo: senza queste esclusioni,
        `rsync --delete` cancella utenti/password, certificato TLS e
        database vendor scaricato a OGNI reinstallazione/upgrade."""
        text = INSTALL_SH.read_text()
        for excluded in ("data/users.json", "data/tls_cert.pem", "data/tls_key.pem", "data/oui.csv"):
            self.assertIn(f'--exclude "{excluded}"', text)

    def test_data_directory_ownership_fixed_explicitly(self):
        """Regressione concreta scoperta dal vivo: rsync (ora eseguito come
        root) sincronizza anche proprietario/permessi della DIRECTORY
        data/ da quelli del checkout sorgente (l'utente non privilegiato
        che sviluppa), lasciando root incapace di scriverci (niente
        CAP_DAC_OVERRIDE nel unit file, vedi sotto)."""
        text = INSTALL_SH.read_text()
        self.assertIn('chown root:root "$DEST_DIR/data"', text)

    def test_required_packages_stop_the_install_on_failure(self):
        text = INSTALL_SH.read_text()
        self.assertIn("REQUIRED_PKGS=", text)
        self.assertIn("exit 1", text)

    def test_optional_package_failure_only_warns(self):
        text = INSTALL_SH.read_text()
        self.assertIn("network-manager", text)
        # non deve esserci un secondo "exit 1" legato specificamente al
        # pacchetto opzionale: un controllo debole ma sufficiente a
        # verificare che il pattern "|| echo ..." (solo avviso) sia usato.
        self.assertIn("network-manager || \\", text)

    def test_prints_first_login_credentials_instead_of_hiding_in_the_journal(self):
        """Bug reale corretto in questa sessione: la password bootstrap
        finiva solo nel log di systemd, mai mostrata dall'installer."""
        text = INSTALL_SH.read_text()
        self.assertIn("FIRST LOGIN", text)
        self.assertIn("journalctl", text)


class TestSystemdServiceFile(unittest.TestCase):
    def test_required_fields_present(self):
        text = SERVICE_FILE.read_text()
        for field in ("[Unit]", "[Service]", "[Install]", "ExecStart=", "WantedBy="):
            self.assertIn(field, text)

    def test_hardening_directives_present(self):
        text = SERVICE_FILE.read_text()
        for directive in (
            "NoNewPrivileges=true", "ProtectHome=true", "PrivateTmp=true",
            "CapabilityBoundingSet=",
        ):
            self.assertIn(directive, text)

    def test_protect_system_is_not_strict(self):
        """strict renderebbe /etc read-only: dhclient deve poter scrivere
        /etc/resolv.conf durante l'autoconfigurazione della rete."""
        text = SERVICE_FILE.read_text()
        self.assertIn("ProtectSystem=true", text)
        self.assertNotIn("ProtectSystem=strict", text)

    def test_capability_bounding_set_includes_net_admin_and_net_raw(self):
        """Necessarie per ARP/ICMP raw socket e riconfigurazione di rete
        (ip addr/link): senza, il servizio si avvierebbe ma la scansione
        fallirebbe silenziosamente con EPERM."""
        text = SERVICE_FILE.read_text()
        self.assertIn("CAP_NET_ADMIN", text)
        self.assertIn("CAP_NET_RAW", text)

    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd-analyze non disponibile su questo sistema")
    def test_systemd_analyze_verify_reports_no_errors(self):
        """Validazione statica reale del unit file (sintassi + direttive
        note a systemd), non solo un grep sul testo: systemd-analyze verify
        puo' operare su un file standalone senza installarlo davvero."""
        result = subprocess.run(
            ["systemd-analyze", "verify", str(SERVICE_FILE)],
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
