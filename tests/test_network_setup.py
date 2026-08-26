import threading
import unittest
from unittest.mock import patch

from scanner import config
from scanner.network import setup as network_setup


class _FakeResult:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = ""


_MULTI_IP_OUTPUT = "\n".join([
    "2: eth0    inet 192.168.1.50/24 brd 192.168.1.255 scope global eth0",
    "2: eth0    inet 10.0.0.20/24 brd 10.0.0.255 scope global secondary eth0",
    "2: eth0    inet 172.16.5.9/16 brd 172.16.255.255 scope global secondary eth0",
])


def _fake_run_multi_ip(cmd, timeout=15):
    if cmd[:5] == ["ip", "-4", "-o", "addr", "show"]:
        return _FakeResult(_MULTI_IP_OUTPUT)
    return _FakeResult()


class TestMultiAddressDetection(unittest.TestCase):
    def setUp(self):
        self._orig_run = network_setup._run
        network_setup._run = _fake_run_multi_ip

    def tearDown(self):
        network_setup._run = self._orig_run

    def test_get_interface_ips_returns_all(self):
        ips = network_setup.get_interface_ips("eth0")
        self.assertEqual(len(ips), 3)
        self.assertIn(("192.168.1.50", 24), ips)
        self.assertIn(("172.16.5.9", 16), ips)

    def test_network_cidr_correct_for_non_24_prefix(self):
        """Bug storico: il calcolo ingenuo (azzerare l'ultimo ottetto)
        sbaglia su prefissi diversi da /24, es. una /16."""
        self.assertEqual(network_setup._network_cidr("172.16.5.9", 16), "172.16.0.0/16")
        self.assertEqual(network_setup._network_cidr("192.168.1.50", 24), "192.168.1.0/24")

    def test_address_list_uses_correct_cidr(self):
        addrs = network_setup._address_list("eth0")
        cidrs = {a["cidr"] for a in addrs}
        self.assertIn("192.168.1.0/24", cidrs)
        self.assertIn("172.16.0.0/16", cidrs)


class TestMultiWifiInterfaces(unittest.TestCase):
    """Bug reale: con piu' schede Wi-Fi fisiche, il tool ne rilevava e
    mostrava solo una (find_default_wifi_iface prendeva sempre la prima e
    _status["wifi"] era un unico dict, non uno per interfaccia)."""

    def setUp(self):
        self._orig_run = network_setup._run
        self._orig_list_ifaces = network_setup.list_interfaces
        network_setup._status["wifi"] = {}

    def tearDown(self):
        network_setup._run = self._orig_run
        network_setup.list_interfaces = self._orig_list_ifaces
        network_setup._status["wifi"] = {}

    def test_list_wifi_ifaces_returns_all_not_just_first(self):
        network_setup.list_interfaces = lambda: ["eth0", "wlan0", "wlan1"]
        self.assertEqual(network_setup.list_wifi_ifaces(), ["wlan0", "wlan1"])

    def test_find_default_wifi_iface_still_returns_one_for_callers_that_want_a_single_default(self):
        network_setup.list_interfaces = lambda: ["wlan1", "wlan0"]
        self.assertEqual(network_setup.find_default_wifi_iface(), "wlan0")

    def test_refresh_wifi_status_tracks_every_interface(self):
        network_setup.list_interfaces = lambda: ["eth0", "wlan0", "wlan1"]

        def fake_run(cmd, timeout=15):
            if cmd[0] == "ip":
                iface = cmd[-1]
                if iface == "wlan0":
                    return _FakeResult("2: wlan0    inet 192.168.1.5/24 scope global wlan0")
                return _FakeResult("")
            if cmd[0] == "iwgetid":
                iface = cmd[2]
                return _FakeResult("CasaWifi") if iface == "wlan0" else _FakeResult("", returncode=1)
            return _FakeResult()

        network_setup._run = fake_run
        network_setup.refresh_wifi_status()
        status = network_setup.get_status()

        self.assertEqual(set(status["wifi"].keys()), {"wlan0", "wlan1"})
        self.assertTrue(status["wifi"]["wlan0"]["up"])
        self.assertEqual(status["wifi"]["wlan0"]["ssid"], "CasaWifi")
        self.assertEqual(status["wifi"]["wlan0"]["ip"], "192.168.1.5")
        self.assertFalse(status["wifi"]["wlan1"]["up"])

    def test_refresh_wifi_status_drops_interfaces_no_longer_present(self):
        """Una scheda USB scollegata non deve restare "fantasma" nello stato."""
        network_setup._status["wifi"] = {
            "wlanUSB": {"iface": "wlanUSB", "up": True, "ssid": None, "ip": None, "cidr": None, "addresses": []},
        }
        network_setup.list_interfaces = lambda: ["eth0"]
        network_setup._run = lambda cmd, timeout=15: _FakeResult()

        network_setup.refresh_wifi_status()
        status = network_setup.get_status()
        self.assertNotIn("wlanUSB", status["wifi"])

    def test_wifi_scan_networks_targets_the_given_interface(self):
        captured = {}

        def fake_run(cmd, timeout=15):
            captured["cmd"] = cmd
            return _FakeResult("CasaWifi:80:WPA2\n")

        network_setup._run = fake_run
        network_setup.wifi_scan_networks(iface="wlan1")
        self.assertIn("ifname", captured["cmd"])
        self.assertIn("wlan1", captured["cmd"])

    def test_wifi_scan_networks_without_iface_omits_ifname(self):
        captured = {}

        def fake_run(cmd, timeout=15):
            captured["cmd"] = cmd
            return _FakeResult("")

        network_setup._run = fake_run
        network_setup.wifi_scan_networks()
        self.assertNotIn("ifname", captured["cmd"])

    def test_wifi_scan_networks_unescapes_colon_in_ssid(self):
        """Bug reale: uno split ingenuo su ":" spezzava un SSID come
        "Guest:Wifi" (nmcli lo emette come "Guest\\:Wifi", escaped) in due
        pezzi, disallineando anche segnale e sicurezza sulla stessa riga."""
        network_setup._run = lambda cmd, timeout=15: _FakeResult("Guest\\:Wifi:70:WPA2\n")
        networks = network_setup.wifi_scan_networks()
        self.assertEqual(networks, [{"ssid": "Guest:Wifi", "signal": "70", "security": "WPA2"}])

    def test_wifi_scan_networks_tolerates_malformed_line(self):
        """Una riga con meno campi del previsto (output inatteso di nmcli)
        non deve far crashare l'intero parsing: solo quella riga risulta
        con i campi mancanti vuoti."""
        network_setup._run = lambda cmd, timeout=15: _FakeResult("SoloSSID\n")
        networks = network_setup.wifi_scan_networks()
        self.assertEqual(networks, [{"ssid": "SoloSSID", "signal": None, "security": ""}])

    def test_wifi_connect_targets_the_given_interface(self):
        captured = {}

        def fake_run(cmd, timeout=15):
            captured["cmd"] = cmd
            return _FakeResult("", returncode=0)

        network_setup._run = fake_run
        network_setup.list_interfaces = lambda: []
        network_setup.wifi_connect("CasaWifi", "password123", iface="wlan1")
        self.assertIn("ifname", captured["cmd"])
        self.assertIn("wlan1", captured["cmd"])


class TestProbePresetClasses(unittest.TestCase):
    """Bug reale segnalato dall'utente: probe_preset_classes (ex
    try_preset_classes) si fermava alla prima classe "viva" trovata,
    nascondendo eventuali altre classi vive sullo stesso cavo e scegliendo
    per un ordine di priorita' arbitrario invece di lasciar scegliere
    all'utente quale scansionare davvero."""

    def setUp(self):
        self._orig_run = network_setup._run
        self._orig_arp_scan = network_setup.arp_scan
        network_setup._run = lambda cmd, timeout=15: _FakeResult()

    def tearDown(self):
        network_setup._run = self._orig_run
        network_setup.arp_scan = self._orig_arp_scan

    def test_no_class_alive_returns_empty(self):
        network_setup.arp_scan = lambda cidr, iface, timeout=None, psrc=None: []
        self.assertEqual(network_setup.probe_preset_classes("eth0"), [])

    def test_single_alive_class_returned_with_host_count(self):
        target_cidr = config.PRESET_SUBNETS[0]["cidr"]

        def fake_arp_scan(cidr, iface, timeout=None, psrc=None):
            return [{"ip": "1.1.1.1", "mac": "aa"}] if cidr == target_cidr else []

        network_setup.arp_scan = fake_arp_scan
        result = network_setup.probe_preset_classes("eth0")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["cidr"], target_cidr)
        self.assertEqual(result[0]["hosts_found"], 1)

    def test_multiple_alive_classes_all_returned_not_just_first(self):
        cidr_a = config.PRESET_SUBNETS[0]["cidr"]
        cidr_b = config.PRESET_SUBNETS[2]["cidr"]

        def fake_arp_scan(cidr, iface, timeout=None, psrc=None):
            if cidr == cidr_a:
                return [{"ip": "1.1.1.1", "mac": "aa"}]
            if cidr == cidr_b:
                return [{"ip": "2.2.2.2", "mac": "bb"}, {"ip": "2.2.2.3", "mac": "cc"}]
            return []

        network_setup.arp_scan = fake_arp_scan
        result = network_setup.probe_preset_classes("eth0")
        by_cidr = {r["cidr"]: r for r in result}
        self.assertEqual(set(by_cidr), {cidr_a, cidr_b})
        self.assertEqual(by_cidr[cidr_a]["hosts_found"], 1)
        self.assertEqual(by_cidr[cidr_b]["hosts_found"], 2)


class TestChoosePresetClass(unittest.TestCase):
    def setUp(self):
        self._orig_run = network_setup._run
        self._orig_arp_scan = network_setup.arp_scan
        network_setup._run = lambda cmd, timeout=15: _FakeResult()
        # Nessuno risponde ai probe di collisione: preserva il comportamento
        # storico di questi test (indirizzo di default sempre libero).
        network_setup.arp_scan = lambda cidr, iface, timeout=None, psrc=None: []
        network_setup._status["eth"] = {
            "iface": None, "up": False, "mode": "choose-network", "ip": None, "cidr": None,
            "addresses": [], "reconfiguring": False, "error": None, "last_change": None,
            "candidates": [
                {"cidr": "192.168.1.0/24", "static_ip": "192.168.1.250", "hosts_found": 2},
                {"cidr": "192.168.0.0/24", "static_ip": "192.168.0.250", "hosts_found": 1},
            ],
        }

    def tearDown(self):
        network_setup._run = self._orig_run
        network_setup.arp_scan = self._orig_arp_scan

    def test_valid_cidr_assigns_and_clears_candidates(self):
        ok, _ = network_setup.choose_preset_class("eth0", "192.168.1.0/24")
        self.assertTrue(ok)
        status = network_setup.get_status()
        self.assertEqual(status["eth"]["mode"], "static-fallback")
        self.assertEqual(status["eth"]["cidr"], "192.168.1.0/24")
        self.assertEqual(status["eth"]["ip"], "192.168.1.250")
        self.assertEqual(status["eth"]["candidates"], [])

    def test_unknown_cidr_rejected(self):
        ok, message = network_setup.choose_preset_class("eth0", "9.9.9.0/24")
        self.assertFalse(ok)
        self.assertIn("Unknown", message)

    def test_falls_back_to_free_address_if_default_now_taken(self):
        """Puo' passare del tempo tra il probe automatico e la scelta
        manuale in dashboard: se nel frattempo un altro host ha preso
        l'indirizzo di default, choose_preset_class deve accorgersene
        (ri-probing) e usarne uno alternativo, non assegnarselo comunque."""
        network_setup.arp_scan = lambda cidr, iface, timeout=None, psrc=None: (
            [{"ip": "192.168.1.250", "mac": "AA"}] if cidr == "192.168.1.250/32" else []
        )
        ok, _ = network_setup.choose_preset_class("eth0", "192.168.1.0/24")
        self.assertTrue(ok)
        status = network_setup.get_status()
        self.assertEqual(status["eth"]["ip"], "192.168.1.249")

    def test_rejected_when_every_fallback_address_is_taken(self):
        network_setup.arp_scan = lambda cidr, iface, timeout=None, psrc=None: (
            [{"ip": "x", "mac": "AA"}] if cidr.startswith("192.168.1.") else []
        )
        ok, message = network_setup.choose_preset_class("eth0", "192.168.1.0/24")
        self.assertFalse(ok)
        self.assertIn("No free address", message)


class TestFindFreeStaticIp(unittest.TestCase):
    """Unit test mirati della logica di collisione IP: bug reale evitato
    qui e' assegnarsi (anche solo temporaneamente, per il probe) un
    indirizzo gia' occupato da un altro host sulla stessa rete."""

    def setUp(self):
        self._orig_arp_scan = network_setup.arp_scan

    def tearDown(self):
        network_setup.arp_scan = self._orig_arp_scan

    def test_default_address_returned_when_free(self):
        network_setup.arp_scan = lambda cidr, iface, timeout=None, psrc=None: []
        ip = network_setup._find_free_static_ip("eth0", "192.168.1.0/24")
        self.assertEqual(ip, "192.168.1.250")

    def test_skips_to_next_suffix_when_default_taken(self):
        network_setup.arp_scan = lambda cidr, iface, timeout=None, psrc=None: (
            [{"ip": "192.168.1.250", "mac": "AA"}] if cidr == "192.168.1.250/32" else []
        )
        ip = network_setup._find_free_static_ip("eth0", "192.168.1.0/24")
        self.assertEqual(ip, "192.168.1.249")

    def test_probe_never_binds_the_candidate_itself(self):
        """Il probe deve interrogare la rete con psrc "0.0.0.0" (ARP probe
        RFC 5227), mai rivendicare l'indirizzo candidato come proprio —
        altrimenti il controllo stesso creerebbe il conflitto che dovrebbe
        individuare."""
        captured_psrc = []

        def fake_arp_scan(cidr, iface, timeout=None, psrc=None):
            captured_psrc.append(psrc)
            return []

        network_setup.arp_scan = fake_arp_scan
        network_setup._find_free_static_ip("eth0", "192.168.1.0/24")
        self.assertEqual(captured_psrc, ["0.0.0.0"])

    def test_returns_none_when_all_fallback_addresses_taken(self):
        network_setup.arp_scan = lambda cidr, iface, timeout=None, psrc=None: [{"ip": "x", "mac": "AA"}]
        ip = network_setup._find_free_static_ip("eth0", "192.168.1.0/24")
        self.assertIsNone(ip)


class TestProbePresetClassesProgressStatus(unittest.TestCase):
    """Feedback di avanzamento durante il probe delle classi preimpostate
    (P2): senza questo, la dashboard restava ferma su "reconfiguring..."
    per fino a ~30s (13 classi x timeout) senza altre indicazioni."""

    def setUp(self):
        self._orig_run = network_setup._run
        self._orig_arp_scan = network_setup.arp_scan
        network_setup._run = lambda cmd, timeout=15: _FakeResult()
        network_setup.arp_scan = lambda cidr, iface, timeout=None, psrc=None: []

    def tearDown(self):
        network_setup._run = self._orig_run
        network_setup.arp_scan = self._orig_arp_scan

    def test_probing_flag_cleared_after_completion(self):
        network_setup.probe_preset_classes("eth0")
        status = network_setup.get_status()
        self.assertFalse(status["eth"]["probing"])
        self.assertIsNone(status["eth"]["probe_index"])
        self.assertIsNone(status["eth"]["probe_total"])
        self.assertIsNone(status["eth"]["probe_cidr"])

    def test_progress_reaches_the_last_preset_during_the_loop(self):
        """Cattura lo stato all'ultima iterazione del loop (l'unico punto
        osservabile in un test sincrono a thread singolo): deve riportare
        l'ultima classe della lista, non fermarsi alla prima."""
        seen_last_cidr = []
        last_preset_cidr = config.PRESET_SUBNETS[-1]["cidr"]

        orig_find_free = network_setup._find_free_static_ip

        def spy_find_free(iface, cidr):
            if cidr == last_preset_cidr:
                status = network_setup.get_status()
                seen_last_cidr.append((status["eth"]["probe_cidr"], status["eth"]["probe_index"]))
            return orig_find_free(iface, cidr)

        network_setup._find_free_static_ip = spy_find_free
        try:
            network_setup.probe_preset_classes("eth0")
        finally:
            network_setup._find_free_static_ip = orig_find_free

        self.assertEqual(seen_last_cidr, [(last_preset_cidr, len(config.PRESET_SUBNETS))])


class TestVpnInterfaces(unittest.TestCase):
    """VPN instradate (WireGuard, OpenVPN, PPP...) sono NOARP a livello
    kernel (verificato su un'interfaccia WireGuard reale durante lo
    sviluppo: flag NOARP presente, `ip neigh` vuoto pur avendo un peer
    realmente raggiungibile via ping) — l'ARP scan non puo' funzionarci,
    va tracciata come categoria a parte per scegliere discovery.icmp_scan
    al suo posto (vedi scan_engine)."""

    def setUp(self):
        self._orig_run = network_setup._run
        self._orig_list_ifaces = network_setup.list_interfaces
        network_setup._status["vpn"] = {}

    def tearDown(self):
        network_setup._run = self._orig_run
        network_setup.list_interfaces = self._orig_list_ifaces
        network_setup._status["vpn"] = {}

    def test_classify_interface_recognizes_common_vpn_prefixes(self):
        for name in ("wg0", "tun0", "tap0", "ppp0", "tailscale0", "zt7nnyxxxx"):
            self.assertEqual(network_setup.classify_interface(name), "vpn", name)

    def test_list_vpn_ifaces_returns_all_not_just_first(self):
        network_setup.list_interfaces = lambda: ["eth0", "wlan0", "wg0", "tun0"]
        self.assertEqual(network_setup.list_vpn_ifaces(), ["tun0", "wg0"])

    def test_refresh_vpn_status_tracks_every_interface(self):
        network_setup.list_interfaces = lambda: ["eth0", "wg0", "tun0"]

        def fake_run(cmd, timeout=15):
            if cmd[0] == "ip":
                iface = cmd[-1]
                if iface == "wg0":
                    return _FakeResult("5: wg0    inet 10.0.0.3/24 scope global wg0")
                return _FakeResult("")
            return _FakeResult()

        network_setup._run = fake_run
        network_setup.refresh_vpn_status()
        status = network_setup.get_status()

        self.assertEqual(set(status["vpn"].keys()), {"wg0", "tun0"})
        self.assertTrue(status["vpn"]["wg0"]["up"])
        self.assertEqual(status["vpn"]["wg0"]["ip"], "10.0.0.3")
        self.assertEqual(status["vpn"]["wg0"]["cidr"], "10.0.0.0/24")
        self.assertFalse(status["vpn"]["tun0"]["up"])

    def test_refresh_vpn_status_drops_interfaces_no_longer_present(self):
        """Un tunnel chiuso (es. WireGuard disattivato) non deve restare
        "fantasma" nello stato, stesso principio del Wi-Fi."""
        network_setup._status["vpn"] = {
            "wg0": {"iface": "wg0", "up": True, "ip": "10.0.0.3", "cidr": "10.0.0.0/24", "addresses": [], "noarp": True},
        }
        network_setup.list_interfaces = lambda: ["eth0"]
        network_setup._run = lambda cmd, timeout=15: _FakeResult()

        network_setup.refresh_vpn_status()
        status = network_setup.get_status()
        self.assertNotIn("wg0", status["vpn"])

    def test_is_noarp_true_for_wireguard_like_flags(self):
        """0x91 e' il valore reale osservato su un'interfaccia WireGuard
        (UP|POINTOPOINT|NOARP)."""
        import builtins
        from io import StringIO

        orig_open = builtins.open

        def fake_open(path, *a, **k):
            if path == "/sys/class/net/wg0/flags":
                return StringIO("0x91")
            return orig_open(path, *a, **k)

        with patch("builtins.open", fake_open):
            self.assertTrue(network_setup.is_noarp("wg0"))

    def test_is_noarp_false_for_ethernet_like_flags(self):
        import builtins
        from io import StringIO

        orig_open = builtins.open

        def fake_open(path, *a, **k):
            if path == "/sys/class/net/eth0/flags":
                return StringIO("0x1003")
            return orig_open(path, *a, **k)

        with patch("builtins.open", fake_open):
            self.assertFalse(network_setup.is_noarp("eth0"))

    def test_is_noarp_missing_interface_defaults_to_false(self):
        self.assertFalse(network_setup.is_noarp("does-not-exist-xyz"))


class TestExistingConfigProtected(unittest.TestCase):
    """autoconfigure_ethernet non deve cancellare IP preesistenti che non
    ha assegnato lui stesso (es. IP secondari configurati a mano)."""

    def setUp(self):
        self._orig_run = network_setup._run
        self._orig_carrier = network_setup.has_carrier
        network_setup._run = _fake_run_multi_ip
        network_setup.has_carrier = lambda iface: True
        network_setup._autoconfig_lock = threading.Lock()
        # Stato pulito: il test non deve dipendere dall'ordine di esecuzione
        # rispetto ad altri test che potrebbero aver lasciato mode="dhcp".
        network_setup._status["eth"] = {
            "iface": None, "up": False, "mode": None, "ip": None, "cidr": None,
            "addresses": [], "reconfiguring": False, "error": None, "last_change": None,
        }

    def tearDown(self):
        network_setup._run = self._orig_run
        network_setup.has_carrier = self._orig_carrier

    def test_preexisting_addresses_marked_manual_and_untouched(self):
        network_setup.autoconfigure_ethernet("eth0")
        status = network_setup.get_status()
        self.assertEqual(status["eth"]["mode"], "manual")
        self.assertEqual(len(status["eth"]["addresses"]), 3)


if __name__ == "__main__":
    unittest.main()
