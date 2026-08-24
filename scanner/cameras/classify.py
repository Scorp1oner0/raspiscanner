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
    "camera", "ipcam", "hikvision", "dahua", "axis",
    "reolink", "foscam", "vivotek", "onvif", "webcam", "cctv",
)


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
        reasons.append(f"porta tipica video ({labels})")

    for port, banner in (http_banners or {}).items():
        text = " ".join(filter(None, [banner.get("server"), banner.get("title")])).lower()
        if not text:
            continue
        for kw in _CAMERA_KEYWORDS:
            if kw in text:
                is_camera = True
                reasons.append(f"banner HTTP:{port} contiene '{kw}'")
                break

    return is_camera, reasons


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
