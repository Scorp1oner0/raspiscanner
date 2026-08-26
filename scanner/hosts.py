"""Classificazione leggera di host "generici" (non camera/NVR/apparato di
rete): telefoni/tablet/PC, stampanti, hardware dedicato riconoscibile dal
vendor OUI (Raspberry Pi, moduli IoT, speaker/hub smart-home) o dal nome
host risolto via reverse DNS.

Come le altre classificazioni del progetto, sono euristiche basate su cosa
il dispositivo espone o annuncia volontariamente (porte aperte, vendor
MAC, nome host) — probe attivi ma non intrusivi, non un fingerprint OS
attivo in stile `nmap -O` (nessun pacchetto crafted per analizzare lo
stack TCP/IP).

Limite strutturale, non un bug: un dispositivo che non espone NESSUNA
porta, non ha un vendor OUI distintivo E non ha un hostname risolvibile
(comune su telefoni e computer moderni con firewall attivo di default, se
il router/DHCP locale non registra un nome DNS) non puo' essere
identificato oltre "Generico" — non c'e' nulla da leggere. Un
riconoscimento ancora piu' affidabile richiederebbe mDNS/Bonjour (molti
dispositivi annunciano li' nome/modello reali), non ancora implementato
qui.
"""
WINDOWS_HOST_PORTS = {135, 139, 445, 3389}
PRINTER_PORTS = {631, 9100}

# Vendor OUI il cui nome identifica in modo affidabile un TIPO di hardware
# dedicato (non un generico produttore multi-prodotto): il match e' per
# sottostringa case-insensitive sul nome vendor gia' risolto da vendor.py.
_VENDOR_HINTS = (
    ("raspberry pi", "Raspberry Pi"),
    ("espressif", "IoT device (ESP8266/ESP32)"),
    ("sonos", "Sonos (audio)"),
    ("philips", "Philips Hue (smart home)"),
    ("amazon", "Amazon (Echo/Fire/Ring)"),
    ("google", "Google (Nest/Chromecast)"),
)
# "Apple" e' deliberatamente escluso: l'OUI e' condiviso da Mac, iPhone,
# iPad, Apple TV, HomePod... non identifica un TIPO di dispositivo, solo
# il vendor (gia' visibile nella colonna Vendor). E' esattamente il caso
# che _HOSTNAME_KEYWORDS sotto puo' risolvere, quando il nome host lo dice
# esplicitamente (es. "iPhone-di-Mario", "MacBook-Pro").

# Sottostringa case-insensitive nel nome host (reverse DNS) -> tipo di
# dispositivo. Best-effort quanto il vendor OUI: un nome host e'
# assegnato dall'utente o dal produttore, non verificato in alcun modo —
# ma router/DHCP locali lo popolano spesso con pattern riconoscibili
# (visto in scan reali: "iPhone.lan", "Galaxy-A34-5G.lan",
# "MacBook-Pro.lan"). L'ordine conta: le voci piu' specifiche vanno prima
# di quelle piu' generiche che le conterrebbero come sottostringa.
_HOSTNAME_KEYWORDS = (
    ("ipad", "Tablet (iPad)"),
    ("iphone", "Phone (iPhone)"),
    ("macbook", "Mac"),
    ("imac", "Mac"),
    ("mac-mini", "Mac"),
    ("macmini", "Mac"),
    ("mac-studio", "Mac"),
    ("galaxy-tab", "Tablet (Android)"),
    ("galaxy", "Phone (Android)"),
    ("pixelbook", "Chromebook"),
    ("pixel-tablet", "Tablet (Android)"),
    ("pixel", "Phone (Android)"),
    ("oneplus", "Phone (Android)"),
    ("xiaomi", "Phone (Android)"),
    ("android-tv", "Android TV"),
    ("android", "Phone (Android)"),
)
# Prefisso del nome host (non sottostringa: sono pattern generati in
# automatico da Windows quando non rinominato manualmente, es.
# "DESKTOP-7K2N9QP") -> tipo di dispositivo.
_HOSTNAME_PREFIXES = (
    ("desktop-", "PC (Windows)"),
    ("laptop-", "PC (Windows)"),
)


def classify_by_vendor(vendor):
    """Ritorna (label, reasons) o (None, []) in base al nome vendor OUI."""
    if not vendor:
        return None, []
    vendor_lower = vendor.lower()
    for hint, label in _VENDOR_HINTS:
        if hint in vendor_lower:
            return label, [f"dedicated hardware vendor ({vendor})"]
    return None, []


def classify_by_hostname(hostname):
    """Ritorna (label, reasons) o (None, []) in base a pattern noti nel
    nome host risolto via reverse DNS."""
    if not hostname:
        return None, []
    hostname_lower = hostname.lower()
    for prefix, label in _HOSTNAME_PREFIXES:
        if hostname_lower.startswith(prefix):
            return label, [f"hostname pattern ({hostname})"]
    for keyword, label in _HOSTNAME_KEYWORDS:
        if keyword in hostname_lower:
            return label, [f"hostname pattern ({hostname})"]
    return None, []


def classify_by_ports(open_ports):
    """Ritorna (label, reasons) o (None, []) in base alle porte aperte."""
    ports_open = {p["port"] for p in open_ports}

    printer_hit = ports_open & PRINTER_PORTS
    if printer_hit:
        labels = ", ".join(str(p) for p in sorted(printer_hit))
        return "Network printer", [f"typical printer port ({labels})"]

    windows_hit = ports_open & WINDOWS_HOST_PORTS
    if windows_hit:
        labels = ", ".join(str(p) for p in sorted(windows_hit))
        return "PC (Windows/SMB)", [f"typical Windows/SMB port ({labels})"]

    return None, []


def classify_host(vendor, open_ports, hostname=None):
    """Combina tre segnali in ordine di affidabilita' decrescente: il
    vendor OUI di hardware dedicato (es. Raspberry Pi Foundation) e' il
    piu' specifico; il pattern nel nome host (es. "iPhone-di-Mario") viene
    dopo perche' assegnato dall'utente, non dal produttore, ma resta piu'
    parlante di una porta generica; le porte tipiche (SMB/RDP/stampante)
    sono l'ultima risorsa. Ritorna (label, reasons) o (None, []) se nessun
    segnale e' disponibile (il dispositivo restera' "Generico" nel
    chiamante)."""
    label, reasons = classify_by_vendor(vendor)
    if label:
        return label, reasons
    label, reasons = classify_by_hostname(hostname)
    if label:
        return label, reasons
    return classify_by_ports(open_ports)
