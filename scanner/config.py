"""Costanti di configurazione condivise dal progetto."""
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
OUI_CSV_PATH = os.path.join(DATA_DIR, "oui.csv")

# Interfacce di rete gestite (nomi tipici su Raspberry Pi OS / kernel Linux)
ETH_IFACE_PREFIXES = ("eth", "en")
WIFI_IFACE_PREFIXES = ("wlan", "wl")

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
}

# Porte usate come segnale forte di "questo e' quasi certamente un dispositivo video"
CAMERA_SIGNAL_PORTS = {554, 8000, 37777, 34567, 8899}

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

# Timeout risoluzione hostname (reverse DNS, best-effort)
HOSTNAME_TIMEOUT = 0.6
