"""Discovery senza socket raw, per la build Windows priva di Npcap.

L'ARP scan e l'ICMP sweep "veri" (scanner.discovery.arp / .icmp) usano
scapy e richiedono socket raw: root/cap_net_raw su Linux, **Npcap** su
Windows. Se Npcap non c'e', su Windows si ripiega qui:

1. **sweep TCP-connect** su un pugno di porte comuni per tutta la subnet —
   nessun privilegio, e come effetto collaterale "scalda" la cache ARP del
   sistema operativo (per parlare TCP con un host il kernel deve prima
   risolverne il MAC);
2. lettura della **tabella ARP di sistema** (`arp -a`), filtrata sulla
   subnet, per associare un MAC agli IP trovati vivi.

Meno completo di un ARP broadcast (un host che non apre nessuna delle
porte sondate e con cui il PC non ha mai parlato resta invisibile), ma
sufficiente per un sopralluogo dove telecamere/NVR/apparati espongono
quasi sempre almeno una porta di gestione. Su Linux questo modulo non
viene mai interpellato.
"""
import ipaddress
import logging
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor

from .. import platform_net

log = logging.getLogger("raspiscanner.discovery.nopriv")

_MAC_RE = re.compile(r"([0-9A-Fa-f]{1,2}(?:[:-][0-9A-Fa-f]{1,2}){5})")
_IPV4_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")

# Porte "di gestione" tipiche di cio' che interessa a un sopralluogo video:
# HTTP/HTTPS pannelli, RTSP, porte proprietarie Hikvision/Dahua, SSH,
# SMB/RDP per i PC. Poche di proposito: lo sweep gira su tutta la /24.
_SWEEP_PORTS = (80, 443, 554, 8000, 37777, 34567, 22, 445, 3389, 7547)
_SWEEP_TIMEOUT = 0.35
_SWEEP_WORKERS = 128
# Oltre questi host non facciamo lo sweep (una /22 e' il massimo che
# scanner.targets accetta come rete custom): evita decine di migliaia di
# connect su un intervallo troppo grande.
_SWEEP_MAX_HOSTS = 1024


def parse_arp_table(text):
    """Estrae {ip: MAC} dall'output di `arp -a` (o `ip neigh`). Funzione
    pura, testabile senza il SO. Righe senza un MAC valido (voci
    incomplete, intestazioni) vengono ignorate; il MAC broadcast e quello
    tutto-zeri sono scartati."""
    table = {}
    for line in text.splitlines():
        mac_match = _MAC_RE.search(line)
        if not mac_match:
            continue
        mac = platform_net.normalize_mac(mac_match.group(1))
        if not mac or mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
            continue
        for ip_match in _IPV4_RE.finditer(line):
            candidate = ip_match.group(1)
            try:
                ipaddress.IPv4Address(candidate)
            except ipaddress.AddressValueError:
                continue
            table[candidate] = mac
            break
    return table


def read_system_arp_table():
    """Legge la tabella ARP del SO (best-effort): {} se `arp` manca o
    fallisce."""
    for cmd in (["arp", "-a"], ["arp", "-a", "-n"]):
        try:
            out = subprocess.run(
                cmd, capture_output=True, text=True, timeout=6,
                encoding="utf-8", errors="ignore", check=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if out.returncode == 0 and out.stdout.strip():
            return parse_arp_table(out.stdout)
    return {}


def arp_table_for_network(cidr):
    """read_system_arp_table() filtrata sui soli IP dentro `cidr`."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return {}
    return {
        ip: mac for ip, mac in read_system_arp_table().items()
        if ipaddress.ip_address(ip) in network
    }


def _probe_host(ip):
    for port in _SWEEP_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(_SWEEP_TIMEOUT)
                if sock.connect_ex((ip, port)) == 0:
                    return ip
        except OSError:
            continue
    return None


def tcp_sweep(cidr):
    """Ritorna il set degli IP di `cidr` che rispondono su almeno una delle
    porte comuni sondate. Serve sia come liveness sia per scaldare la cache
    ARP del SO."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        log.error("invalid subnet for TCP sweep: %s", cidr)
        return set()
    # Controlla la dimensione PRIMA di materializzare la lista di host: su una
    # subnet enorme (es. /8) generare gli indirizzi uno per uno costerebbe
    # gia' da solo secondi e parecchia memoria.
    if network.num_addresses > _SWEEP_MAX_HOSTS + 2:
        log.warning(
            "subnet %s too large (%d addresses) for the unprivileged sweep, "
            "skipped", cidr, network.num_addresses,
        )
        return set()
    hosts = [str(ip) for ip in network.hosts()]
    if not hosts:
        return set()
    live = set()
    with ThreadPoolExecutor(max_workers=min(_SWEEP_WORKERS, len(hosts))) as pool:
        for result in pool.map(_probe_host, hosts):
            if result:
                live.add(result)
    return live


def fallback_arp_scan(cidr):
    """Ripiego di scanner.discovery.arp.arp_scan quando i socket raw non
    sono usabili — Windows senza Npcap, oppure Linux senza root/CAP_NET_RAW
    (il caso "sto provando lo scanner sul mio portatile"):
    sweep TCP + tabella ARP di sistema. Stesso formato di ritorno
    ([{"ip":.., "mac":.., "vlan_id": None}, ...]); `mac` puo' essere None
    se il SO non ha (ancora) una voce ARP per quell'host."""
    live = tcp_sweep(cidr)
    table = arp_table_for_network(cidr)
    ips = set(live) | set(table)
    if not ips:
        return []
    log.info(
        "unprivileged discovery on %s: %d hosts (%d via TCP sweep, %d in ARP table)",
        cidr, len(ips), len(live), len(table),
    )
    return [{"ip": ip, "mac": table.get(ip), "vlan_id": None} for ip in sorted(ips)]


def fallback_icmp_sweep(cidr):
    """Ripiego di scanner.discovery.icmp.icmp_scan quando i socket raw non
    sono usabili (Windows senza Npcap, Linux senza privilegi).
    Nessun MAC (come l'ICMP scan vero: link NOARP / instradato)."""
    live = tcp_sweep(cidr)
    if not live:
        return []
    log.info("unprivileged TCP sweep on %s: %d hosts", cidr, len(live))
    return [{"ip": ip, "mac": None} for ip in sorted(live)]


# Nomi storici, mantenuti perche' il ripiego era stato introdotto come
# specifico di Windows prima di scoprire che serve identico su un Linux non
# privilegiato: le implementazioni non hanno mai avuto nulla di
# Windows-specifico (`arp -a` e i connect TCP funzionano su entrambi).
windows_arp_scan = fallback_arp_scan
windows_icmp_sweep = fallback_icmp_sweep
