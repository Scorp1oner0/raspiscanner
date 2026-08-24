"""Classificazione leggera di host "generici" (non camera/NVR/apparato di
rete): PC, stampanti, hardware dedicato riconoscibile dal vendor OUI
(Raspberry Pi, moduli IoT, speaker/hub smart-home).

Come le altre classificazioni del progetto, sono euristiche basate su cosa
il dispositivo espone o annuncia volontariamente a una connessione TCP
normale (porte aperte, vendor MAC) — probe attivi ma non intrusivi, non un
fingerprint OS attivo in stile `nmap -O` (nessun pacchetto crafted per
analizzare lo stack TCP/IP).

Limite strutturale, non un bug: un dispositivo che non espone NESSUNA
porta (comune su telefoni e computer moderni, con firewall attivo di
default) non puo' essere identificato oltre "Generico" — non c'e' nulla
da leggere se il dispositivo non risponde a nessuna connessione. Un
riconoscimento affidabile dei telefoni richiederebbe mDNS/Bonjour (molti
annunciano il proprio nome li'), non ancora implementato qui.
"""
WINDOWS_HOST_PORTS = {135, 139, 445, 3389}
PRINTER_PORTS = {631, 9100}

# Vendor OUI il cui nome identifica in modo affidabile un TIPO di hardware
# dedicato (non un generico produttore multi-prodotto): il match e' per
# sottostringa case-insensitive sul nome vendor gia' risolto da vendor.py.
_VENDOR_HINTS = (
    ("raspberry pi", "Raspberry Pi"),
    ("espressif", "Dispositivo IoT (ESP8266/ESP32)"),
    ("sonos", "Sonos (audio)"),
    ("philips", "Philips Hue (smart home)"),
    ("amazon", "Amazon (Echo/Fire/Ring)"),
    ("google", "Google (Nest/Chromecast)"),
)
# "Apple" e' deliberatamente escluso: l'OUI e' condiviso da Mac, iPhone,
# iPad, Apple TV, HomePod... non identifica un TIPO di dispositivo, solo
# il vendor (gia' visibile nella colonna Vendor). Aggiungerlo qui
# darebbe una falsa impressione di precisione senza dire nulla in piu'.


def classify_by_vendor(vendor):
    """Ritorna (label, reasons) o (None, []) in base al nome vendor OUI."""
    if not vendor:
        return None, []
    vendor_lower = vendor.lower()
    for hint, label in _VENDOR_HINTS:
        if hint in vendor_lower:
            return label, [f"vendor hardware dedicato ({vendor})"]
    return None, []


def classify_by_ports(open_ports):
    """Ritorna (label, reasons) o (None, []) in base alle porte aperte."""
    ports_open = {p["port"] for p in open_ports}

    printer_hit = ports_open & PRINTER_PORTS
    if printer_hit:
        labels = ", ".join(str(p) for p in sorted(printer_hit))
        return "Stampante di rete", [f"porta tipica stampante ({labels})"]

    windows_hit = ports_open & WINDOWS_HOST_PORTS
    if windows_hit:
        labels = ", ".join(str(p) for p in sorted(windows_hit))
        return "PC (Windows/SMB)", [f"porta tipica Windows/SMB ({labels})"]

    return None, []


def classify_host(vendor, open_ports):
    """Combina i due segnali: il vendor (hardware dedicato) e' piu'
    specifico e affidabile di una porta generica, quindi ha precedenza.
    Ritorna (label, reasons) o (None, []) se nessun segnale disponibile
    (il dispositivo restera' "Generico" nel chiamante)."""
    label, reasons = classify_by_vendor(vendor)
    if label:
        return label, reasons
    return classify_by_ports(open_ports)
