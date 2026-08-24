"""Classificazione "e' un NVR/DVR" (registratore), distinta dalla singola
telecamera IP.

Le porte tipiche (37777 Dahua, 8000 Hikvision, RTSP 554) sono condivise
tra telecamere e registratori, quindi da sole non bastano a distinguerli:
qui si usa solo un segnale esplicito nel banner HTTP (nvr/dvr/recorder nel
Server header o nel <title>). Senza questo segnale un registratore verra'
comunque rilevato come dispositivo video da scanner.cameras.classify, ma
etichettato "Telecamera" invece di "NVR/DVR" nel report — un limite noto,
non un errore: distinguere con certezza un NVR da una camera richiederebbe
interrogare l'API proprietaria del vendor (di norma autenticata), fuori
dallo scope di questo tool che resta non intrusivo.
"""
_NVR_KEYWORDS = ("nvr", "dvr", "recorder", "video recorder")


def classify_nvr(http_banners):
    """http_banners: {port: {"server":.., "title":..}}
    Ritorna (is_nvr: bool, reasons: list[str]).
    """
    reasons = []
    is_nvr = False
    for port, banner in (http_banners or {}).items():
        text = " ".join(filter(None, [banner.get("server"), banner.get("title")])).lower()
        if not text:
            continue
        for kw in _NVR_KEYWORDS:
            if kw in text:
                is_nvr = True
                reasons.append(f"banner HTTP:{port} contiene '{kw}'")
                break
    return is_nvr, reasons
