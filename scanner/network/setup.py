"""Auto-configurazione dell'interfaccia ethernet.

Logica richiesta:
  1. Quando l'interfaccia eth ha link (cavo collegato), si prova prima il
     DHCP.
  2. Se il DHCP non risponde entro un timeout, si prova una lista di classi
     private preimpostate: per ciascuna ci si assegna un IP statico "alto"
     (difficilmente occupato) e si verifica con un probe ARP se sulla rete
     rispondono altri host. La prima classe "viva" trovata viene tenuta.
  3. Se nessuna classe risulta viva, l'interfaccia resta senza indirizzo e
     lo stato viene riportato come "nessuna rete rilevata": un nuovo giro
     viene ritentato al prossimo cambio di stato del cavo (o su richiesta
     manuale dalla dashboard).

Il modulo non assume systemd-networkd/dhcpcd/NetworkManager: usa solo i
comandi di base `ip` e `dhclient`, cosi' funziona su qualunque Raspberry Pi
OS purche' l'interfaccia non sia gestita in conflitto da un altro servizio
(vedi README per come marcarla "unmanaged" in NetworkManager/dhcpcd).
"""
import ipaddress
import logging
import os
import subprocess
import threading
import time

from .. import config
from ..discovery import quick_subnet_probe

log = logging.getLogger("raspiscanner.network")

_state_lock = threading.Lock()
_status = {
    "eth": {
        "iface": None, "up": False, "mode": None, "ip": None, "cidr": None, "addresses": [],
        "reconfiguring": False, "error": None, "last_change": None,
    },
    # Dizionario iface -> stato, NON un singolo stato: un dispositivo puo'
    # avere piu' schede Wi-Fi (es. una usata come client per raggiungere la
    # rete di casa, un'altra dedicata all'hotspot per la raggiungibilita'
    # senza cavo), e vanno tracciate/mostrate/controllate tutte, non solo la
    # prima trovata.
    "wifi": {},
}

# Serializza autoconfigure_ethernet(): puo' essere chiamata sia dal monitor
# automatico (fronte di salita del carrier) sia manualmente dalla dashboard.
# Senza questo lock due chiamate concorrenti possono accavallare `ip addr
# flush/add` e lasciare l'interfaccia in uno stato incoerente che sembra
# "bloccato" sulla rete precedente.
_autoconfig_lock = threading.Lock()


def get_status():
    with _state_lock:
        return {
            "eth": dict(_status["eth"]),
            "wifi": {iface: dict(info) for iface, info in _status["wifi"].items()},
        }


def _set_status(key, **kwargs):
    with _state_lock:
        _status[key].update(kwargs)


def _get_status_field(key, field, default=None):
    with _state_lock:
        return _status[key].get(field, default)


def list_interfaces():
    """Ritorna i nomi delle interfacce di rete presenti (esclusa lo)."""
    try:
        names = os.listdir("/sys/class/net")
    except FileNotFoundError:
        return []
    return [n for n in names if n != "lo"]


def classify_interface(name):
    if name.startswith(config.ETH_IFACE_PREFIXES):
        return "eth"
    if name.startswith(config.WIFI_IFACE_PREFIXES):
        return "wifi"
    return None


def find_default_eth_iface():
    for name in sorted(list_interfaces()):
        if classify_interface(name) == "eth":
            return name
    return None


def list_wifi_ifaces():
    """Ritorna TUTTE le interfacce Wi-Fi presenti (non solo la prima): un
    dispositivo puo' avere piu' schede Wi-Fi, es. una usata come client per
    raggiungere la rete esistente e un'altra dedicata all'hotspot."""
    return sorted(n for n in list_interfaces() if classify_interface(n) == "wifi")


def find_default_wifi_iface():
    """Prima interfaccia Wi-Fi trovata: comoda dove serve UNA interfaccia
    (es. SSID di default suggerito nella dashboard) quando il chiamante non
    ne specifica una in particolare. NON usare per operazioni che devono
    coprire tutte le schede presenti: qui serve list_wifi_ifaces()."""
    ifaces = list_wifi_ifaces()
    return ifaces[0] if ifaces else None


def has_carrier(iface):
    """True se il cavo e' collegato (o l'interfaccia wifi e' associata)."""
    try:
        with open(f"/sys/class/net/{iface}/carrier") as fh:
            return fh.read().strip() == "1"
    except (FileNotFoundError, OSError):
        return False


def get_interface_mac(iface):
    """MAC address dell'interfaccia locale, o None. Un host non riceve mai
    la propria richiesta ARP broadcast di ritorno (lo switch non la
    rimanda sulla porta da cui e' arrivata), quindi un ARP scan non trova
    mai se stesso: questo serve per aggiungere comunque la macchina locale
    all'elenco dei dispositivi, dato che IP e MAC li conosciamo gia'."""
    try:
        with open(f"/sys/class/net/{iface}/address") as fh:
            mac = fh.read().strip().upper()
            return mac or None
    except (FileNotFoundError, OSError):
        return None


def _run(cmd, timeout=15):
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        log.warning("comando fallito %s: %s", cmd, exc)
        return None


def get_interface_ips(iface):
    """Ritorna [(ip, prefix), ...] per TUTTI gli IPv4 assegnati all'interfaccia.

    Un'interfaccia puo' avere piu' indirizzi (es. IP secondari configurati a
    mano per raggiungere piu' subnet sullo stesso cavo): vanno rilevati e
    scansionati tutti, non solo il primo.
    """
    res = _run(["ip", "-4", "-o", "addr", "show", "dev", iface])
    if not res or res.returncode != 0:
        return []
    out = []
    for line in res.stdout.splitlines():
        parts = line.split()
        if "inet" in parts:
            cidr = parts[parts.index("inet") + 1]  # es 192.168.1.42/24
            ip, prefix = cidr.split("/")
            out.append((ip, int(prefix)))
    return out


def get_interface_ip(iface):
    """Ritorna (ip, prefix) del primo IPv4 assegnato, o None. Scorciatoia
    per i punti (DHCP, classe statica appena assegnata) in cui sappiamo che
    l'interfaccia ha al piu' un indirizzo perche' l'abbiamo appena flushata."""
    ips = get_interface_ips(iface)
    return ips[0] if ips else None


def _network_cidr(ip, prefix):
    """Calcola l'indirizzo di rete corretto per qualunque prefisso (non solo
    /24): l'IP di un'interfaccia configurata a mano puo' benissimo essere su
    una /16 o /23, non solo sulle /24 che questo tool assegna da solo."""
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def _address_list(iface):
    return [
        {"ip": ip, "cidr": _network_cidr(ip, prefix)}
        for ip, prefix in get_interface_ips(iface)
    ]


def flush_addresses(iface):
    _run(["ip", "addr", "flush", "dev", iface])


def set_link_up(iface):
    _run(["ip", "link", "set", "dev", iface, "up"])


def try_dhcp(iface, timeout=config.DHCP_TIMEOUT_SECONDS):
    """Tenta un lease DHCP sull'interfaccia. Ritorna True se ottenuto un IP.

    Usa un file di lease/pid dedicato e lo cancella prima di ogni tentativo:
    con il lease file di default, se la rete e' cambiata, dhclient prova
    prima a rinnovare (INIT-REBOOT) il vecchio indirizzo verso il vecchio
    server DHCP (ormai irraggiungibile) e spesso consuma l'intero timeout
    prima di arrendersi e passare a un DISCOVER pulito sulla rete nuova.
    Partire sempre da un lease vuoto forza un DISCOVER immediato.
    """
    log.info("provo DHCP su %s (timeout %ss)", iface, timeout)
    lease_file = f"/run/raspiscanner-dhclient-{iface}.lease"
    pid_file = f"/run/raspiscanner-dhclient-{iface}.pid"
    dhclient_common = ["-lf", lease_file, "-pf", pid_file]

    _run(["dhclient", "-r"] + dhclient_common + [iface], timeout=5)
    for path in (lease_file, pid_file):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
    flush_addresses(iface)
    set_link_up(iface)
    res = _run(
        ["dhclient", "-1", "-v", "-timeout", str(timeout)] + dhclient_common + [iface],
        timeout=timeout + 5,
    )
    if res is None:
        return False
    ip_info = get_interface_ip(iface)
    if ip_info:
        log.info("DHCP riuscito su %s: %s", iface, ip_info[0])
        return True
    return False


def assign_static(iface, ip, prefix=24):
    flush_addresses(iface)
    set_link_up(iface)
    _run(["ip", "addr", "add", f"{ip}/{prefix}", "dev", iface])


def try_preset_classes(iface):
    """Prova ciascuna classe preimpostata assegnando l'IP statico e
    verificando con un probe ARP se ci sono host attivi su quella rete.
    Ritorna il preset scelto (dict) oppure None se nessuna classe risponde.
    """
    for preset in config.PRESET_SUBNETS:
        cidr = preset["cidr"]
        static_ip = preset["static_ip"]
        log.info("provo classe %s (IP candidato %s)", cidr, static_ip)
        assign_static(iface, static_ip, prefix=cidr.split("/")[1])
        alive = quick_subnet_probe(iface, cidr, timeout=config.CLASS_PROBE_TIMEOUT, psrc=static_ip)
        if alive:
            log.info("classe %s attiva su %s", cidr, iface)
            return preset
        flush_addresses(iface)
    return None


def autoconfigure_ethernet(iface=None, force=False):
    """Esegue la logica DHCP -> fallback classi preimpostate su eth.

    Se l'interfaccia ha GIA' uno o piu' indirizzi IPv4 che non sono stati
    assegnati da noi (mode precedente None/"manuale" invece di
    "dhcp"/"static-fallback" — es. IP secondari configurati a mano per
    raggiungere piu' subnet sullo stesso cavo), non li tocchiamo: si
    passa `force=True` per azzerarli comunque e far ripartire DHCP/fallback
    da zero.

    Serializzata da _autoconfig_lock: se e' gia' in corso un tentativo
    (avviato dal monitor o da una richiesta precedente della dashboard),
    la chiamata viene ignorata invece di accavallarsi alla prima. Qualsiasi
    eccezione durante il tentativo viene intercettata e riportata nello
    stato invece di lasciare la dashboard bloccata sull'ultimo risultato
    valido senza spiegazione.
    """
    iface = iface or find_default_eth_iface()
    if not iface:
        log.warning("nessuna interfaccia ethernet trovata")
        return

    if not _autoconfig_lock.acquire(blocking=False):
        log.info("autoconfigurazione gia' in corso su %s, richiesta ignorata", iface)
        return

    try:
        _set_status("eth", iface=iface, reconfiguring=True, error=None)

        if not has_carrier(iface):
            _set_status(
                "eth", iface=iface, up=False, mode=None, ip=None, cidr=None, addresses=[],
                reconfiguring=False, last_change=time.time(),
            )
            return

        try:
            owns_current_config = _get_status_field("eth", "mode") in ("dhcp", "static-fallback")
            existing = [] if force else _address_list(iface)
            if existing and not owns_current_config:
                primary = existing[0]
                _set_status(
                    "eth", iface=iface, up=True, mode="manual",
                    ip=primary["ip"], cidr=primary["cidr"], addresses=existing,
                    reconfiguring=False, error=None, last_change=time.time(),
                )
                log.info(
                    "%d IP preesistenti su %s non assegnati da questo tool, lasciati invariati",
                    len(existing), iface,
                )
                return

            if try_dhcp(iface):
                addresses = _address_list(iface)
                primary = addresses[0]
                _set_status(
                    "eth", iface=iface, up=True, mode="dhcp",
                    ip=primary["ip"], cidr=primary["cidr"], addresses=addresses,
                    reconfiguring=False, error=None, last_change=time.time(),
                )
                return

            log.info("DHCP non disponibile su %s, provo classi preimpostate", iface)
            preset = try_preset_classes(iface)
            if preset:
                addresses = [{"ip": preset["static_ip"], "cidr": preset["cidr"]}]
                _set_status(
                    "eth", iface=iface, up=True, mode="static-fallback",
                    ip=preset["static_ip"], cidr=preset["cidr"], addresses=addresses,
                    reconfiguring=False, error=None, last_change=time.time(),
                )
                return

            flush_addresses(iface)
            _set_status(
                "eth", iface=iface, up=True, mode="no-network", ip=None, cidr=None, addresses=[],
                reconfiguring=False, error=None, last_change=time.time(),
            )
            log.warning("nessuna classe preimpostata ha risposto su %s", iface)
        except Exception as exc:  # non deve mai lasciare lo stato "congelato" in silenzio
            log.exception("autoconfigurazione fallita su %s", iface)
            _set_status("eth", iface=iface, reconfiguring=False, error=str(exc), last_change=time.time())
    finally:
        _autoconfig_lock.release()


def refresh_eth_addresses(iface):
    """Ri-legge SOLO la lista di indirizzi correnti, senza flush/DHCP: usato
    dal monitor per tenere la dashboard aggiornata quando un IP viene
    aggiunto/rimosso da fuori (es. configurazione manuale) senza un vero e
    proprio evento di link. Non cambia `mode`.
    """
    addresses = _address_list(iface)
    if addresses:
        primary = addresses[0]
        _set_status("eth", addresses=addresses, ip=primary["ip"], cidr=primary["cidr"])
    else:
        _set_status("eth", addresses=[])


def _refresh_one_wifi_iface(iface):
    addresses = _address_list(iface)
    ssid = None
    res = _run(["iwgetid", "-r", iface], timeout=3)
    if res and res.returncode == 0:
        ssid = res.stdout.strip() or None
    if addresses:
        primary = addresses[0]
        status = {
            "iface": iface, "up": True, "ssid": ssid,
            "ip": primary["ip"], "cidr": primary["cidr"], "addresses": addresses,
        }
    else:
        status = {
            "iface": iface, "up": bool(ssid), "ssid": ssid,
            "ip": None, "cidr": None, "addresses": [],
        }
    with _state_lock:
        _status["wifi"][iface] = status


def refresh_wifi_status():
    """Aggiorna lo stato di TUTTE le interfacce Wi-Fi presenti, non solo la
    prima. Una scheda scomparsa (es. adattatore USB scollegato) viene
    rimossa dallo stato invece di restare "fantasma"."""
    ifaces = list_wifi_ifaces()
    for iface in ifaces:
        _refresh_one_wifi_iface(iface)
    with _state_lock:
        for stale in list(_status["wifi"]):
            if stale not in ifaces:
                del _status["wifi"][stale]


def wifi_scan_networks(iface=None):
    """Elenca le reti Wi-Fi visibili (best-effort, richiede nmcli).

    Senza `iface` nmcli usa la prima scheda Wi-Fi disponibile: va bene per
    il caso con una sola scheda, ma con piu' schede va specificata quella su
    cui si vuole cercare (es. quella NON in uso come hotspot in quel
    momento).
    """
    cmd = ["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY", "device", "wifi", "list"]
    if iface:
        cmd += ["ifname", iface]
    res = _run(cmd, timeout=10)
    if not res or res.returncode != 0:
        return []
    networks = []
    seen = set()
    for line in res.stdout.splitlines():
        parts = line.split(":")
        if not parts or not parts[0]:
            continue
        ssid = parts[0]
        if ssid in seen:
            continue
        seen.add(ssid)
        networks.append({
            "ssid": ssid,
            "signal": parts[1] if len(parts) > 1 else None,
            "security": parts[2] if len(parts) > 2 else "",
        })
    return networks


def wifi_connect(ssid, password=None, iface=None):
    """Connette il Wi-Fi tramite nmcli, se disponibile. Senza `iface` nmcli
    sceglie da solo la scheda Wi-Fi da usare (comodo con una sola scheda,
    ambiguo con piu' di una)."""
    cmd = ["nmcli", "device", "wifi", "connect", ssid]
    if password:
        cmd += ["password", password]
    if iface:
        cmd += ["ifname", iface]
    res = _run(cmd, timeout=25)
    ok = bool(res and res.returncode == 0)
    if ok:
        refresh_wifi_status()
    return ok, (res.stdout + res.stderr) if res else "nmcli not available"


def _monitor_loop(stop_event):
    eth_iface = find_default_eth_iface()
    last_carrier = None
    while not stop_event.is_set():
        try:
            if eth_iface:
                carrier = has_carrier(eth_iface)
                if carrier and not last_carrier:
                    log.info("cavo eth collegato su %s, avvio autoconfig", eth_iface)
                    autoconfigure_ethernet(eth_iface)
                elif not carrier and last_carrier:
                    log.info("cavo eth scollegato da %s", eth_iface)
                    _set_status(
                        "eth", iface=eth_iface, up=False, mode=None, ip=None, cidr=None, addresses=[],
                        reconfiguring=False, error=None, last_change=time.time(),
                    )
                elif carrier and not _autoconfig_lock.locked():
                    # Nessun evento di link, ma teniamo aggiornata la lista
                    # indirizzi: puo' cambiare senza un vero cambio di cavo
                    # (es. un IP secondario aggiunto/rimosso a mano).
                    refresh_eth_addresses(eth_iface)
                last_carrier = carrier
            else:
                eth_iface = find_default_eth_iface()
            refresh_wifi_status()
        except Exception:
            # Il monitor gira per tutta la vita del processo: un'eccezione
            # qui non deve fermarlo per sempre, altrimenti nessuna
            # riconfigurazione automatica avverra' mai piu' finche' non si
            # riavvia il servizio.
            log.exception("errore nel loop di monitor rete")
        stop_event.wait(config.LINK_POLL_INTERVAL)


def start_monitor():
    """Avvia il thread che sorveglia il cavo eth e lo stato wifi."""
    stop_event = threading.Event()
    t = threading.Thread(target=_monitor_loop, args=(stop_event,), daemon=True)
    t.start()
    return stop_event
