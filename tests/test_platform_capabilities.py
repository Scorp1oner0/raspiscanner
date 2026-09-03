"""Le capacita' dipendono dai PRIVILEGI, non dal sistema operativo.

Prima queste guardie erano agganciate a `IS_WINDOWS`, con due conseguenze
su un Linux avviato senza privilegi — cioe' il caso "sto provando lo
scanner sul mio portatile":

1. il monitor tentava di **riconfigurare la scheda ethernet** dell'utente;
2. l'ARP scan restituiva una lista **vuota** invece di ripiegare sullo
   sweep TCP + tabella ARP, quindi la rete sembrava deserta.

Il ripiego di `scanner.discovery.nopriv` non ha mai avuto nulla di
Windows-specifico (`arp -a` e i connect TCP funzionano su entrambi).
"""
import unittest
from unittest.mock import patch

from scanner import platform_net
from scanner.discovery import arp, icmp, nopriv


class TestCanConfigureNetwork(unittest.TestCase):
    def test_false_on_windows(self):
        with patch.object(platform_net, "IS_WINDOWS", True):
            self.assertFalse(platform_net.can_configure_network())

    def test_false_on_linux_without_privileges(self):
        with patch.object(platform_net, "IS_WINDOWS", False), \
                patch.object(platform_net, "_has_capability", return_value=False):
            self.assertFalse(platform_net.can_configure_network())

    def test_true_on_linux_with_net_admin(self):
        with patch.object(platform_net, "IS_WINDOWS", False), \
                patch.dict("os.environ", {}, clear=False), \
                patch.object(platform_net, "_env_forbids_network_config", return_value=False), \
                patch.object(platform_net, "_has_capability", return_value=True):
            self.assertTrue(platform_net.can_configure_network())

    def test_env_variable_disables_it_even_as_root(self):
        """Il caso `sudo -E RASPISCANNER_NO_NETWORK_CONFIG=1 ./start.sh`:
        scan completo a livello 2, rete dell'utente comunque intatta."""
        with patch.object(platform_net, "IS_WINDOWS", False), \
                patch.object(platform_net, "_has_capability", return_value=True), \
                patch.dict("os.environ",
                           {platform_net.NO_NETWORK_CONFIG_ENV: "1"}, clear=False):
            self.assertFalse(platform_net.can_configure_network())


class TestRawSocketAccess(unittest.TestCase):
    def test_windows_depends_on_npcap(self):
        with patch.object(platform_net, "IS_WINDOWS", True), \
                patch.object(platform_net, "npcap_present", return_value=False):
            self.assertFalse(platform_net.has_raw_socket_access())
        with patch.object(platform_net, "IS_WINDOWS", True), \
                patch.object(platform_net, "npcap_present", return_value=True):
            self.assertTrue(platform_net.has_raw_socket_access())

    def test_linux_depends_on_cap_net_raw(self):
        with patch.object(platform_net, "IS_WINDOWS", False), \
                patch.object(platform_net, "_has_capability", return_value=False):
            self.assertFalse(platform_net.has_raw_socket_access())


class TestSummaryReflectsPrivileges(unittest.TestCase):
    def test_unprivileged_linux_hides_the_same_panels_as_windows(self):
        with patch.object(platform_net, "IS_WINDOWS", False), \
                patch.object(platform_net, "_has_capability", return_value=False):
            s = platform_net.summary()
        self.assertEqual(s["os"], "linux")
        self.assertFalse(s["network_reconfig_supported"])
        self.assertFalse(s["hotspot_supported"])
        self.assertFalse(s["arp_raw_available"])


class TestFallbackIsPlatformIndependent(unittest.TestCase):
    """IL test di regressione: senza socket raw il ripiego deve scattare
    anche su Linux, non solo su Windows."""

    def test_arp_scan_falls_back_on_linux_without_privileges(self):
        with patch.object(platform_net, "IS_WINDOWS", False), \
                patch.object(platform_net, "has_raw_socket_access", return_value=False), \
                patch.object(nopriv, "fallback_arp_scan",
                             return_value=[{"ip": "192.168.1.5", "mac": "AA:BB:CC:00:00:05",
                                            "vlan_id": None}]) as fb:
            got = arp.arp_scan("192.168.1.0/24", "eth0")
        fb.assert_called_once_with("192.168.1.0/24")
        self.assertEqual(got[0]["ip"], "192.168.1.5")

    def test_icmp_scan_falls_back_on_linux_without_privileges(self):
        with patch.object(platform_net, "IS_WINDOWS", False), \
                patch.object(platform_net, "has_raw_socket_access", return_value=False), \
                patch.object(nopriv, "fallback_icmp_sweep",
                             return_value=[{"ip": "10.0.0.9", "mac": None}]) as fb:
            got = icmp.icmp_scan("10.0.0.0/24", "wg0")
        fb.assert_called_once_with("10.0.0.0/24")
        self.assertEqual(got[0]["ip"], "10.0.0.9")

    def test_historic_windows_names_still_work(self):
        """I nomi `windows_*` restano come alias: il ripiego era nato come
        specifico di Windows."""
        self.assertIs(nopriv.windows_arp_scan, nopriv.fallback_arp_scan)
        self.assertIs(nopriv.windows_icmp_sweep, nopriv.fallback_icmp_sweep)


class TestEthernetIsReadOnlyWithoutPrivileges(unittest.TestCase):
    def test_autoconfigure_does_not_touch_the_network(self):
        """Su un portatile non privilegiato `autoconfigure_ethernet` deve
        limitarsi a leggere lo stato, senza eseguire alcun comando `ip`."""
        from scanner.network import setup

        with patch.object(setup.platform_net, "can_configure_network", return_value=False), \
                patch.object(setup, "_read_only_eth_status") as ro, \
                patch.object(setup, "_run") as run:
            setup.autoconfigure_ethernet("eth0")
        ro.assert_called_once_with("eth0")
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
