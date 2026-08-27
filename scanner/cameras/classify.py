"""Classificazione "e' una telecamera IP" + URL RTSP/admin proposti.

La decisione si basa su segnali di protocollo (ONVIF, RTSP, porte tipiche
video, banner HTTP), non sul vendor MAC: e' un metodo molto piu' affidabile
perche' non dipende dalla completezza del database OUI locale.

Non distingue da sola gli NVR/DVR (vedi scanner.nvr.classify): un
registratore condivide spesso le stesse porte/segnali di una telecamera.
La distinzione finale (telecamera vs NVR) la fa scan_engine combinando
questo risultato con quello di nvr.classify.
"""
from .. import config

_CAMERA_KEYWORDS = (
    "camera", "ipcam", "hikvision", "dahua", "axis", "bosch", "ksenia",
    "reolink", "foscam", "vivotek", "onvif", "webcam", "cctv",
)

# P4 "richer vendor fingerprint database": nome vendor da mostrare quando il
# banner HTTP lo rivela esplicitamente, usato come fallback SOLO quando il
# lookup OUI (MAC) non da' un vendor noto — es. un dispositivo con un MAC
# fuori dal nostro database OUI minimo locale, ma il cui banner dice
# letteralmente "Hikvision". Chiavi in minuscolo (confrontate su testo gia'
# minuscolizzato), valori con la capitalizzazione "ufficiale" del vendor.
# Copre sia telecamere sia NVR/DVR: lo stesso banner li identifica
# indipendentemente dal tipo di dispositivo (vedi anche scanner.nvr.classify,
# che classifica il TIPO ma non il vendor).
_VENDOR_BANNER_KEYWORDS = {
    "hikvision": "Hikvision",
    "dahua": "Dahua",
    "axis": "Axis",
    "bosch": "Bosch",
    "ksenia": "Ksenia",
    "reolink": "Reolink",
    "foscam": "Foscam",
    "vivotek": "Vivotek",
    }

# "uc-httpd" e' il webserver embedded usato da molte board DVR/NVR OEM
# cinesi (Dahua compreso, ma non solo): segnale reale e diffuso, ma troppo
# generico per attribuirlo a un vendor specifico con certezza — controllato
# SOLO se nessun vendor specifico sopra ha gia' dato un match su NESSUNA
# porta di questo host (non solo quella con "uc-httpd"), altrimenti un NVR
# multi-porta con "dahua" su una porta e "uc-httpd" su un'altra rischierebbe
# di essere etichettato col fallback generico invece del vendor specifico.
_GENERIC_VENDOR_BANNER_KEYWORDS = {
    "uc-httpd": "Generic DVR/NVR (uc-httpd)",
}


def classify_camera(open_ports, http_banners, onvif_info):
    """open_ports: lista di {"port":.., "service":..}
    http_banners: {port: {"server":.., "title":..}}
    onvif_info: {"xaddrs": [...], "types": "..."} oppure None
    Ritorna (is_camera: bool, reasons: list[str]).
    """
    ports_open = {p["port"] for p in open_ports}
    reasons = []
    is_camera = False

    if onvif_info and onvif_info.get("xaddrs"):
        is_camera = True
        reasons.append("ONVIF WS-Discovery")

    strong_ports = ports_open & config.CAMERA_SIGNAL_PORTS
    if strong_ports:
        is_camera = True
        labels = ", ".join(config.PORTS_OF_INTEREST.get(p, str(p)) for p in sorted(strong_ports))
        reasons.append(f"typical video port ({labels})")

    for port, banner in (http_banners or {}).items():
        text = " ".join(filter(None, [banner.get("server"), banner.get("title")])).lower()
        if not text:
            continue
        for kw in _CAMERA_KEYWORDS:
            if kw in text:
                is_camera = True
                reasons.append(f"HTTP banner on port {port} contains '{kw}'")
                break

    return is_camera, reasons


def guess_vendor_from_banner(http_banners):
    """Cerca un nome vendor esplicito nel banner HTTP (Server/<title>),
    su TUTTE le porte con banner disponibile. Ritorna il nome "ufficiale"
    (es. "Hikvision") o None.

    Due passate: prima i vendor specifici su ogni porta, poi (solo se
    nessuno ha dato un match su nessuna porta) il segnale generico
    "uc-httpd" — cosi' un NVR multi-porta con "dahua" su una porta e
    "uc-httpd" su un'altra viene attribuito al vendor specifico, non al
    fallback generico.
    """
    texts = []
    for banner in (http_banners or {}).values():
        text = " ".join(filter(None, [banner.get("server"), banner.get("title")])).lower()
        if text:
            texts.append(text)

    for text in texts:
        for kw, vendor_name in _VENDOR_BANNER_KEYWORDS.items():
            if kw in text:
                return vendor_name
    for text in texts:
        for kw, vendor_name in _GENERIC_VENDOR_BANNER_KEYWORDS.items():
            if kw in text:
                return vendor_name
    return None


def guess_rtsp_url(ip, open_ports):
    ports_open = {p["port"] for p in open_ports}
    if 554 in ports_open:
        return f"rtsp://{ip}:554/"
    return None


def guess_admin_url(ip, open_ports):
    ports_open = {p["port"] for p in open_ports}
    for port in (80, 8000, 8080, 8081, 443, 8443):
        if port in ports_open:
            scheme = "https" if port in (443, 8443) else "http"
            return f"{scheme}://{ip}:{port}/"
    return None
