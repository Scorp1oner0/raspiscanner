"""Astrazione delle primitive di rete che dipendono dal sistema operativo.

Su **Linux** (Raspberry Pi, il target principale) questo modulo non cambia
niente: il resto del codice continua a usare `ip`, `/sys/class/net`,
`dhclient`, `nmcli` come prima. Le funzioni OS-specifiche in
`scanner.network.*` mantengono il loro percorso Linux invariato e NON
passano di qui.

Su **Windows** (build per il portatile del tecnico, vedi `docs/WINDOWS.md`)
quelle stesse funzioni deviano qui. Differenze volute rispetto al Pi:

* **sola lettura** della configurazione di rete gia' presente — niente
  DHCP forzato, niente `flush`/assegnazione IP, niente probe delle classi
  preimpostate. Il portatile e' gia' sulla rete (stesso approccio di Field
  Guardian): riconfigurargli la scheda sarebbe distruttivo e inutile.
* le letture usano `psutil` (interfacce / IP / MAC / stato) piu' il parsing
  di `route print` e `netsh wlan`.

I parser (`parse_*`) sono funzioni pure "testo -> dato": restano testabili
anche fuori da Windows, dove `psutil` puo' non essere installato.
"""
import ipaddress
import logging
import os
import re
import socket
import subprocess
import sys

log = logging.getLogger("raspiscanner.platform_net")

IS_WINDOWS = sys.platform.startswith("win")
IS_LINUX = sys.platform.startswith("linux")

try:
    import psutil  # type: ignore
    PSUTIL_AVAILABLE = True
except ImportError:  # pragma: no cover - dipende dall'ambiente
    psutil = None
    PSUTIL_AVAILABLE = False
    if IS_WINDOWS:
        log.warning(
            "psutil not available: on Windows, network reads (interfaces, IP, "
            "status) will be very limited. Install the dependencies from "
            "requirements-windows.txt."
        )


# Parole chiave nel nome "friendly" dell'adattatore Windows -> categoria.
# Windows non usa prefissi tipo eth0/wlan0: gli adattatori si chiamano
# "Ethernet", "Ethernet 2", "Wi-Fi", "Wi-Fi 2", oppure col nome del driver
# per le VPN ("OpenVPN TAP-Windows6", "WireGuard Tunnel", ...).
# Match su sottostringhe del nome friendly: teniamo hint abbastanza
# specifici da non pescare per sbaglio un adattatore della categoria
# sbagliata (niente "wl"/"wg" nudi, che comparirebbero in troppi nomi di
# driver).
_WIN_WIFI_HINTS = ("wi-fi", "wifi", "wireless", "wlan", "802.11")
_WIN_VPN_HINTS = (
    "tunnel", "tap-windows", "tap windows", "openvpn", "wireguard", "wintun",
    "tailscale", "zerotier", "nordlynx", "protonvpn", "vpn",
)
_WIN_ETH_HINTS = ("ethernet", "local area connection")
_WIN_IGNORE_HINTS = ("loopback", "bluetooth", "isatap", "teredo", "6to4", "pseudo")


def npcap_present():
    """True/False se Npcap e' installato (solo Windows), None altrove.

    Npcap mette `wpcap.dll` in System32 e crea una cartella `System32\\Npcap`.
    Serve a scapy per l'ARP scan L2 su Windows; senza, si ripiega su
    scanner.discovery.nopriv."""
    if not IS_WINDOWS:
        return None
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    return (
        os.path.isdir(os.path.join(sysroot, "System32", "Npcap"))
        or os.path.isfile(os.path.join(sysroot, "System32", "wpcap.dll"))
    )


# Bit delle capability Linux che ci interessano (vedi capabilities(7)).
_CAP_NET_ADMIN = 12
_CAP_NET_RAW = 13
# Variabile d'ambiente per rinunciare esplicitamente a riconfigurare la rete
# anche quando si avrebbero i privilegi (usata da start.sh nella modalita'
# "prova": vedi docs/QUICK-START.md).
NO_NETWORK_CONFIG_ENV = "RASPISCANNER_NO_NETWORK_CONFIG"


def _has_capability(bit):
    """True se il processo ha la capability indicata nel set effettivo.
    Su un sistema senza /proc/self/status ripiega su "sono root?"."""
    try:
        with open("/proc/self/status", encoding="ascii") as fh:
            for line in fh:
                if line.startswith("CapEff:"):
                    return bool(int(line.split()[1], 16) & (1 << bit))
    except (OSError, ValueError):
        pass
    return os.geteuid() == 0 if hasattr(os, "geteuid") else False


def _env_forbids_network_config():
    return os.environ.get(NO_NETWORK_CONFIG_ENV, "").strip() not in ("", "0", "false")


def can_configure_network():
    """Se lo scanner puo' RICONFIGURARE la rete dell'host (DHCP, IP statici
    di fallback, hotspot) oppure deve limitarsi a leggerla.

    E' vero solo dove riconfigurare e' il comportamento voluto: l'appliance
    dedicata, cioe' un Raspberry Pi o un box Linux avviato da root via
    systemd, buttato su una rete sconosciuta.

    E' falso in due casi, che vanno trattati allo stesso modo:
    - **Windows**: la riconfigurazione non e' mai supportata;
    - **Linux non privilegiato**: e' il caso "sto provando lo strumento sul
      mio portatile". Senza privilegi non potremmo comunque riconfigurare
      nulla, ma soprattutto non *dobbiamo*: la rete di lavoro dell'utente
      non si tocca. Prima questa guardia esisteva solo per Windows, quindi
      su Linux il monitor tentava l'autoconfigurazione della scheda anche
      quando lo scanner era stato avviato solo per una prova.

    `RASPISCANNER_NO_NETWORK_CONFIG=1` la disattiva anche da root.
    """
    if IS_WINDOWS:
        return False
    if _env_forbids_network_config():
        return False
    return _has_capability(_CAP_NET_ADMIN)


def has_raw_socket_access():
    """Se l'ARP/ICMP scan a livello 2 puo' funzionare: su Windows serve
    Npcap, su Linux root o CAP_NET_RAW. Senza, si ripiega sullo sweep
    TCP-connect + tabella ARP di sistema (`scanner.discovery.nopriv`)."""
    if IS_WINDOWS:
        return npcap_present()
    return _has_capability(_CAP_NET_RAW)


def summary():
    """Riepilogo capacita' della piattaforma per la dashboard (/api/platform)."""
    return {
        "os": "windows" if IS_WINDOWS else ("linux" if IS_LINUX else sys.platform),
        "is_windows": IS_WINDOWS,
        # Non dipendono dal sistema operativo ma dai privilegi effettivi: la
        # dashboard nasconde i pannelli non applicabili sia su Windows sia su
        # un Linux avviato senza privilegi (modalita' "prova").
        "network_reconfig_supported": can_configure_network(),
        "hotspot_supported": can_configure_network(),
        "arp_raw_available": has_raw_socket_access(),
    }


def _run(cmd, timeout=15):
    """Esegue un comando di sistema, mai solleva: None se manca o va in
    timeout (stesso contratto di `scanner.network.setup._run`)."""
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        log.warning("command failed %s: %s", cmd, exc)
        return None


# --------------------------------------------------------------------------
# helper puri (testabili ovunque)
# --------------------------------------------------------------------------

def netmask_to_prefix(netmask):
    """"255.255.255.0" -> 24. Ritorna None se la maschera non e' valida.

    psutil su Windows riporta la netmask in notazione decimale puntata,
    non il prefisso: qui la convertiamo per allinearci al resto del codice
    (che ragiona in CIDR)."""
    if not netmask:
        return None
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
    except (ipaddress.NetmaskValueError, ipaddress.AddressValueError, ValueError):
        return None


def normalize_mac(raw):
    """Uniforma un MAC ("aa-bb-cc-dd-ee-ff" o "aa:bb:..." o "AABBCC...") al
    formato "AA:BB:CC:DD:EE:FF" usato nel resto del progetto. None se non
    sembra un MAC a 6 ottetti."""
    if not raw:
        return None
    hexits = re.sub(r"[^0-9A-Fa-f]", "", raw)
    if len(hexits) != 12:
        return None
    return ":".join(hexits[i:i + 2] for i in range(0, 12, 2)).upper()


def classify_windows_interface(name):
    """Categoria ("eth"/"wifi"/"vpn") di un adattatore Windows dal suo nome
    friendly, o None se e' da ignorare (loopback, Bluetooth PAN, tunnel di
    transizione IPv6...). Speculare a `scanner.network.setup.classify_interface`
    ma basata su parole chiave invece che su prefissi Linux."""
    low = (name or "").lower()
    if any(h in low for h in _WIN_IGNORE_HINTS):
        return None
    if any(h in low for h in _WIN_VPN_HINTS):
        return "vpn"
    if any(h in low for h in _WIN_WIFI_HINTS):
        return "wifi"
    if any(h in low for h in _WIN_ETH_HINTS):
        return "eth"
    return None


def parse_route_print_default_gateways(text):
    """Estrae le rotte di default dall'output di `route print -4`.

    Ritorna [(gateway_ip, iface_ip), ...] nell'ordine di apparizione. La
    sezione "IPv4 Route Table / Active Routes" ha righe a 5 colonne:

        Network Destination  Netmask  Gateway  Interface  Metric
        0.0.0.0              0.0.0.0  10.0.0.1  10.0.0.42  25

    Le rotte di default sono quelle con destinazione e netmask "0.0.0.0".
    Una riga con gateway "On-link" (rotte di sistema) viene ignorata: non
    e' una rotta verso l'esterno.
    """
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        if parts[0] != "0.0.0.0" or parts[1] != "0.0.0.0":
            continue
        gateway, iface_ip = parts[2], parts[3]
        try:
            ipaddress.ip_address(gateway)
            ipaddress.ip_address(iface_ip)
        except ValueError:
            continue
        out.append((gateway, iface_ip))
    return out


def parse_netsh_wlan_interfaces(text):
    """`netsh wlan show interfaces` -> {nome_adattatore: ssid|None}.

    L'output e' a blocchi "chiave : valore" separati da righe vuote, un
    blocco per scheda Wi-Fi. Ci interessano solo "Name" e "SSID" (mai
    "BSSID", che e' il MAC dell'access point)."""
    result = {}
    name = None
    ssid = None
    for line in text.splitlines():
        if ":" not in line:
            if name is not None:
                result[name] = ssid
                name, ssid = None, None
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key == "name":
            if name is not None:
                result[name] = ssid
            name, ssid = value, None
        elif key == "ssid" and name is not None:
            ssid = value or None
    if name is not None:
        result[name] = ssid
    return result


def parse_netsh_wlan_networks(text):
    """`netsh wlan show networks mode=bssid` -> lista di
    {"ssid":.., "signal":.., "security":..}. `signal` e' la percentuale
    senza il segno "%", per allinearsi a quello che restituisce nmcli su
    Linux."""
    networks = []
    current = None
    for line in text.splitlines():
        stripped = line.strip()
        m = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", stripped)
        if m:
            if current and current["ssid"]:
                networks.append(current)
            current = {"ssid": m.group(1).strip(), "signal": None, "security": ""}
            continue
        if current is None:
            continue
        m = re.match(r"^Authentication\s*:\s*(.*)$", stripped)
        if m:
            current["security"] = m.group(1).strip()
            continue
        m = re.match(r"^Signal\s*:\s*(\d+)\s*%?$", stripped)
        if m:
            if current["signal"] is None:
                current["signal"] = m.group(1)
    if current and current["ssid"]:
        networks.append(current)
    return networks


# --------------------------------------------------------------------------
# letture Windows (usano psutil quando disponibile)
# --------------------------------------------------------------------------

def _win_if_addrs():
    return psutil.net_if_addrs() if PSUTIL_AVAILABLE else {}


def _win_if_stats():
    return psutil.net_if_stats() if PSUTIL_AVAILABLE else {}


def list_interfaces():
    """Nomi degli adattatori di rete "veri" (esclusi loopback e tunnel di
    transizione). Windows-only: su Linux si usa os.listdir('/sys/class/net')."""
    names = []
    for name in _win_if_addrs():
        if classify_windows_interface(name) is not None:
            names.append(name)
    return names


def iface_is_up(name):
    stats = _win_if_stats().get(name)
    return bool(stats and stats.isup)


def get_interface_ips(name):
    """[(ip, prefix), ...] IPv4 assegnati all'adattatore. psutil espone
    piu' indirizzi per scheda (come `ip -o addr`), li restituiamo tutti."""
    out = []
    for addr in _win_if_addrs().get(name, []):
        if addr.family != socket.AF_INET:
            continue
        prefix = netmask_to_prefix(addr.netmask)
        if addr.address and prefix is not None:
            out.append((addr.address, prefix))
    return out


def get_interface_mac(name):
    fam = getattr(psutil, "AF_LINK", None) if PSUTIL_AVAILABLE else None
    for addr in _win_if_addrs().get(name, []):
        if fam is not None and addr.family == fam:
            mac = normalize_mac(addr.address)
            if mac:
                return mac
    return None


def has_carrier(name):
    """Su Windows non c'e' un file "carrier" separato: lo stato "su" di
    psutil (adattatore attivo e connesso) e' l'equivalente pratico."""
    return iface_is_up(name)


def is_noarp(name):
    """Euristica Windows: consideriamo NOARP le sole interfacce VPN
    punto-punto (stesso effetto pratico che su Linux, dove il flag NOARP
    del kernel si legge da /sys). Windows non espone quel flag in modo
    comodo, e per un tunnel instradato l'ARP scan e' comunque inutile."""
    return classify_windows_interface(name) == "vpn"


def get_default_gateway(name):
    """IP del gateway di default associato all'adattatore `name`, o None.

    Incrocia le rotte di default di `route print -4` con gli IP
    dell'adattatore (la colonna "Interface" di quel comando e' un IP
    locale, non un nome)."""
    iface_ips = {ip for ip, _ in get_interface_ips(name)}
    if not iface_ips:
        return None
    res = _run(["route", "print", "-4"], timeout=10)
    if not res or res.returncode != 0:
        return None
    defaults = parse_route_print_default_gateways(res.stdout)
    for gateway, iface_ip in defaults:
        if iface_ip in iface_ips:
            return gateway
    return None


def egress_ip_for(target_ip):
    """IP locale che il sistema userebbe per raggiungere `target_ip`,
    ricavato aprendo una socket UDP (nessun pacchetto inviato davvero) e
    leggendo `getsockname()`. Cross-platform e senza dipendere dal parsing
    della tabella di routing. None se non c'e' rotta."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((str(target_ip), 9))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return None


def egress_interface_for(cidr):
    """Nome dell'adattatore che il sistema userebbe per raggiungere `cidr`
    (Windows). None se irraggiungibile. Equivalente Windows di
    `ip -4 route get` usato in scan_engine per le reti target "custom"."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        probe_ip = str(next(network.hosts(), network.network_address))
    except (ValueError, StopIteration):
        return None
    local_ip = egress_ip_for(probe_ip)
    if not local_ip:
        return None
    for name in list_interfaces():
        if any(ip == local_ip for ip, _ in get_interface_ips(name)):
            return name
    return None


def wifi_ssid(name):
    """SSID a cui l'adattatore Wi-Fi `name` e' associato, o None."""
    res = _run(["netsh", "wlan", "show", "interfaces"], timeout=10)
    if not res or res.returncode != 0:
        return None
    return parse_netsh_wlan_interfaces(res.stdout).get(name)


def wifi_scan_networks(name=None):
    """Reti Wi-Fi visibili via `netsh wlan show networks` (best-effort)."""
    res = _run(["netsh", "wlan", "show", "networks", "mode=bssid"], timeout=15)
    if not res or res.returncode != 0:
        return []
    seen = set()
    out = []
    for net in parse_netsh_wlan_networks(res.stdout):
        if not net["ssid"] or net["ssid"] in seen:
            continue
        seen.add(net["ssid"])
        out.append(net)
    return out


def wifi_connect(ssid, password=None, name=None):
    """Connessione Wi-Fi su Windows via `netsh wlan connect`. Funziona solo
    se esiste gia' un profilo salvato per quell'SSID: creare al volo un
    profilo con password richiede generare un XML: fuori portata qui, si
    rimanda l'utente alla UI di Windows con un messaggio chiaro."""
    cmd = ["netsh", "wlan", "connect", f"name={ssid}", f"ssid={ssid}"]
    if name:
        cmd.append(f"interface={name}")
    res = _run(cmd, timeout=20)
    if res is None:
        return False, "netsh not available"
    ok = res.returncode == 0
    if ok:
        return True, res.stdout.strip() or "Connection started"
    hint = (res.stdout + res.stderr).strip()
    if password:
        hint += (
            "  (note: connecting to a new password-protected network has to be "
            "done once from the Windows Wi-Fi UI; after that, the saved "
            "profile lets you reconnect from here)"
        )
    return False, hint or "connection failed"
