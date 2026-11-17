"""Costanti di configurazione condivise dal progetto."""
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
OUI_CSV_PATH = os.path.join(DATA_DIR, "oui.csv")
# Registro IEEE completo (~40.000 voci) scaricato da
# scripts/update_oui.py. NON tracciato da git: e' stato generato a
# runtime. Va in un file SUO invece di sovrascrivere oui.csv, che e'
# tracciato: cosi' provare lo scanner da un clone non sporca il
# checkout dell'utente ne' perde i nomi vendor curati.
OUI_FULL_CSV_PATH = os.path.join(DATA_DIR, "oui_full.csv")
USERS_JSON_PATH = os.path.join(DATA_DIR, "users.json")
TLS_CERT_PATH = os.path.join(DATA_DIR, "tls_cert.pem")
TLS_KEY_PATH = os.path.join(DATA_DIR, "tls_key.pem")
# Storico scan (P4): asset database, report comparativi, dashboard storica.
# sqlite3 e' stdlib, nessuna nuova dipendenza. Stato runtime generato al
# primo scan salvato, stesso trattamento di users.json/tls_*.pem: mai
# committato, escluso da install.sh (vedi li').
HISTORY_DB_PATH = os.path.join(DATA_DIR, "history.db")
WEBHOOKS_JSON_PATH = os.path.join(DATA_DIR, "webhooks.json")
# Continuous Monitoring mode (P4): stesso trattamento di webhooks.json.
MONITORING_JSON_PATH = os.path.join(DATA_DIR, "monitoring.json")
# Scan target networks (extra reti da scansionare oltre a quelle rilevate
# sulle interfacce attive): stesso trattamento di webhooks.json.
TARGETS_JSON_PATH = os.path.join(DATA_DIR, "targets.json")

# Interfacce di rete gestite (nomi tipici su Raspberry Pi OS / kernel Linux)
ETH_IFACE_PREFIXES = ("eth", "en")
WIFI_IFACE_PREFIXES = ("wlan", "wl")
# VPN comuni: WireGuard (wg*), OpenVPN (tun*/tap*), PPP, Tailscale, ZeroTier.
# Usate solo per raggrupparle nella dashboard: la scelta ARP vs ICMP per lo
# scan (vedi network.setup.is_noarp) si basa sul flag NOARP del kernel, non
# sul nome — piu' affidabile di un prefisso per qualunque interfaccia VPN
# non elencata qui.
VPN_IFACE_PREFIXES = ("tun", "tap", "wg", "ppp", "tailscale", "zt")

# Timeout DHCP prima di passare al fallback su classi preimpostate
DHCP_TIMEOUT_SECONDS = 12

# Ogni quanto il monitor controlla lo stato del cavo eth (secondi)
LINK_POLL_INTERVAL = 2

# Classi di rete private piu' comuni, in ordine di probabilita' d'uso reale.
# "static_ip" e' l'indirizzo che lo scanner si assegna temporaneamente per
# verificare se la classe e' quella giusta (host alto, difficilmente in uso).
PRESET_SUBNETS = [
    {"cidr": "192.168.1.0/24", "static_ip": "192.168.1.250"},
    {"cidr": "192.168.0.0/24", "static_ip": "192.168.0.250"},
    {"cidr": "192.168.2.0/24", "static_ip": "192.168.2.250"},
    {"cidr": "192.168.4.0/24", "static_ip": "192.168.4.250"},
    {"cidr": "192.168.8.0/24", "static_ip": "192.168.8.250"},
    {"cidr": "192.168.10.0/24", "static_ip": "192.168.10.250"},
    {"cidr": "192.168.100.0/24", "static_ip": "192.168.100.250"},
    {"cidr": "192.168.188.0/24", "static_ip": "192.168.188.250"},
    {"cidr": "10.0.0.0/24", "static_ip": "10.0.0.250"},
    {"cidr": "10.0.1.0/24", "static_ip": "10.0.1.250"},
    {"cidr": "10.1.1.0/24", "static_ip": "10.1.1.250"},
    {"cidr": "10.10.10.0/24", "static_ip": "10.10.10.250"},
    {"cidr": "172.16.0.0/24", "static_ip": "172.16.0.250"},
]

# Timeout per il probe ARP di una classe candidata durante l'autoconfig
CLASS_PROBE_TIMEOUT = 2.5

# Porte controllate durante lo scan dispositivi (generiche + telecamere/NVR)
PORTS_OF_INTEREST = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    81: "HTTP-Alt",
    443: "HTTPS",
    554: "RTSP",
    8000: "Hikvision/HTTP-Alt",
    8080: "HTTP-Proxy",
    8081: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8899: "ONVIF-HTTP",
    9000: "HTTP-Alt/NVR",
    37777: "Dahua-DVRIP",
    34567: "Dahua-Legacy",
    5000: "UPnP/HTTP-Alt",
    135: "MSRPC",
    139: "NetBIOS",
    445: "SMB",
    3389: "RDP",
    631: "IPP",
    9100: "JetDirect",
}

# Profilo "esteso" (scelto dall'operatore accanto a "Start scan"): porte che si
# AGGIUNGONO a PORTS_OF_INTEREST. Servizi frequenti su NAS, IoT, apparati di
# rete e videosorveglianza che la lista di base non copre. Alcune (3306, 5900,
# 6379, 9200, 2375) sono anche tipiche esche di honeypot: l'avviso nella
# dashboard lo dice.
EXTENDED_PORTS = {
    25: "SMTP", 110: "POP3", 111: "RPCbind", 143: "IMAP", 389: "LDAP",
    465: "SMTPS", 502: "Modbus", 515: "LPD", 548: "AFP", 587: "SMTP-Submission",
    873: "rsync", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MSSQL",
    1723: "PPTP", 1883: "MQTT", 1935: "RTMP", 2049: "NFS", 2323: "Telnet-Alt",
    2375: "Docker-API", 2376: "Docker-API-TLS", 3000: "HTTP-Alt", 3306: "MySQL",
    4443: "HTTPS-Alt", 5001: "HTTPS-Alt", 5060: "SIP", 5432: "PostgreSQL",
    5555: "ADB", 5900: "VNC", 6379: "Redis", 6443: "Kubernetes-API",
    7001: "HTTP-Alt", 7332: "RaspiScanner", 7547: "TR-069", 8001: "HTTP-Alt",
    8008: "HTTP-Alt", 8009: "AJP", 8088: "HTTP-Alt", 8090: "HTTP-Alt",
    8123: "Home-Assistant", 8181: "HTTP-Alt", 8291: "MikroTik-Winbox",
    8554: "RTSP-Alt", 8728: "MikroTik-API", 8729: "MikroTik-API-TLS",
    8880: "HTTP-Alt", 8883: "MQTT-TLS", 8888: "HTTP-Alt", 9001: "HTTP-Alt",
    9090: "HTTP-Alt", 9200: "Elasticsearch", 9443: "HTTPS-Alt",
    9527: "XiongMai-Debug", 10000: "Webmin", 10554: "RTSP-Alt",
    11211: "Memcached", 27017: "MongoDB", 34599: "XiongMai-Alt",
    37778: "Dahua-Alt", 49152: "UPnP",
}
PORT_PROFILES = ("common", "extended")

# Porte web per cui si legge il banner (Server e <title>). Le "_ANY" sono porte
# alternative senza uno schema fisso: si prova HTTP e, se non risponde, HTTPS.
HTTP_BANNER_PORTS = {80, 81, 8000, 8080, 8081, 8899, 9000}
HTTPS_BANNER_PORTS = {443, 8443}
ANY_WEB_BANNER_PORTS = {
    3000, 4443, 5001, 7001, 7332, 8001, 8008, 8088, 8090, 8123, 8181, 8880,
    8888, 9001, 9090, 9443, 10000,
}

# Scan approfondito di un solo dispositivo (pulsante sulla riga del
# dispositivo). Le porte si controllano a blocchi per non tenere in memoria
# 65535 attese insieme su un Pi 3B+.
DEEP_SCAN_DEFAULT_PORTS = "1-65535"
DEEP_SCAN_THREADS = 100
DEEP_SCAN_BATCH = 1000
# Porte su cui non ha senso chiedere una pagina web nello scan approfondito.
NON_WEB_PORTS = {
    21, 22, 23, 25, 53, 110, 111, 135, 139, 143, 389, 445, 465, 502, 515, 548,
    554, 587, 873, 993, 995, 1433, 1723, 1883, 1935, 2049, 2323, 3306, 3389,
    5060, 5432, 5555, 5900, 6379, 8291, 8554, 8728, 8729, 8883, 9100, 10554,
    11211, 27017, 34567, 34599, 37777, 37778,
}

# Porte usate come segnale forte di "questo e' quasi certamente un dispositivo video".
# 8000 ESCLUSA deliberatamente: e' un HTTP-Alt generico (vedi PORTS_OF_INTEREST,
# "Hikvision/HTTP-Alt") usato da tantissimi dispositivi non video (pannelli NAS,
# server di sviluppo, IoT generico) — da sola causava falsi positivi "Camera" su
# PC/apparati che non c'entrano nulla. Resta comunque tra le porte controllate e
# concorre al match sui banner HTTP in classify_camera(), solo non basta piu' da
# sola a dichiarare is_camera.
CAMERA_SIGNAL_PORTS = {554, 37777, 34567, 8899}

# Porta UDP standard WS-Discovery (ONVIF)
ONVIF_DISCOVERY_PORT = 3702
ONVIF_MULTICAST_ADDR = "239.255.255.250"

# Timeout dei singoli connect TCP durante il port scan (secondi)
PORT_SCAN_TIMEOUT = 0.6
PORT_SCAN_THREADS = 60

# Timeout e ripetizioni dell'ARP scan su una subnet. Un host appena
# collegato (es. dietro una porta switch con STP/RSTP che tiene la porta
# in "listening" per qualche secondo) o semplicemente lento a rispondere
# puo' sfuggire a un singolo giro breve: alziamo timeout/retry rispetto al
# minimo per non perdere questi casi, a scapito di uno scan un po' piu' lento.
ARP_SCAN_TIMEOUT = 4
ARP_SCAN_RETRY = 2

# Pausa tra una richiesta e la successiva negli sweep ARP e ICMP (secondi).
# Mandare l'intera subnet in un'unica raffica faceva perdere blocchi interi
# di richieste a schede di rete lente (Pi 3B+, Ethernet dietro USB) o a
# switch con storm control: l'host interessato non riceveva mai la propria
# domanda e restava invisibile. Con 2 ms una /24 parte in circa mezzo secondo.
SWEEP_SEND_INTERVAL = 0.002

# Timeout risoluzione hostname (reverse DNS, best-effort)
HOSTNAME_TIMEOUT = 0.6

# Timeout e ripetizioni della IPv6 discovery (ICMPv6 Echo Request verso il
# multicast "all-nodes" ff02::1): stessa logica di ARP_SCAN_TIMEOUT/RETRY,
# valori piu' bassi perche' e' un probe locale al link (nessun routing di
# mezzo) e solo supplementare alla scoperta IPv4 principale.
IPV6_DISCOVERY_TIMEOUT = 2
IPV6_DISCOVERY_RETRY = 1
