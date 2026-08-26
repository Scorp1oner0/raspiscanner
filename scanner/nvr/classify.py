"""Classificazione "e' un NVR/DVR/encoder" (apparato di registrazione o
codifica video), distinta dalla singola telecamera IP.

Le porte tipiche (37777 Dahua, 8000 Hikvision, RTSP 554) sono condivise
tra telecamere e registratori, quindi da sole non bastano a distinguerli:
qui si usa solo un segnale esplicito nel banner HTTP (nvr/dvr/xvr/encoder/
recorder nel Server header o nel <title>). Senza questo segnale un
registratore verra' comunque rilevato come dispositivo video da
scanner.cameras.classify, ma etichettato "Telecamera" invece che con il
suo tipo specifico nel report — un limite noto, non un errore: distinguere
con certezza il tipo esatto richiederebbe interrogare l'API proprietaria
del vendor (di norma autenticata), fuori dallo scope di questo tool che
resta non intrusivo.

Il "subtype" restituito distingue NVR/DVR/Video Encoder/Video Decoder/
Video Server quando il banner lo consente, invece dell'unica etichetta
generica "NVR/DVR" usata in precedenza per qualunque segnale — piu' utile
in un report (es. sapere che e' un encoder standalone, non un
registratore, cambia cosa cercarci sopra). Resta "NVR/DVR" generico solo
quando il segnale trovato ("recorder"/"video recorder") non permette di
scegliere tra i due.
"""
# Ordine di priorita': i piu' specifici prima. "xvr"/"hcvr" sono i
# registratori ibridi Dahua (analogico+IP), classificati come DVR: al
# fine di questo tool (e' un registratore, non una singola camera) la
# distinzione fine tra DVR/XVR/HCVR non cambia nulla di rilevante.
_NVR_SUBTYPE_KEYWORDS = (
    ("nvr", "NVR"),
    ("xvr", "DVR"),
    ("hcvr", "DVR"),
    ("dvr", "DVR"),
    ("video server", "Video Server"),
    ("encoder", "Video Encoder"),
    ("decoder", "Video Decoder"),
)
# Segnali generici che indicano "e' un registratore" senza permettere di
# scegliere tra NVR e DVR: restano nell'etichetta ombrello "NVR/DVR".
_GENERIC_RECORDER_KEYWORDS = ("recorder", "video recorder")


def classify_nvr(http_banners):
    """http_banners: {port: {"server":.., "title":..}}
    Ritorna (is_nvr: bool, reasons: list[str], subtype: str | None).
    subtype e' "NVR"/"DVR"/"Video Encoder"/"Video Decoder"/"Video Server"
    quando un banner lo indica specificamente, "NVR/DVR" generico se il
    segnale trovato non lo permette, None se is_nvr e' False.
    """
    reasons = []
    is_nvr = False
    subtype = None
    for port, banner in (http_banners or {}).items():
        text = " ".join(filter(None, [banner.get("server"), banner.get("title")])).lower()
        if not text:
            continue
        for kw, label in _NVR_SUBTYPE_KEYWORDS:
            if kw in text:
                is_nvr = True
                if subtype is None:
                    subtype = label
                reasons.append(f"HTTP banner on port {port} contains '{kw}'")
                break
        else:
            for kw in _GENERIC_RECORDER_KEYWORDS:
                if kw in text:
                    is_nvr = True
                    reasons.append(f"HTTP banner on port {port} contains '{kw}'")
                    break
    if is_nvr and subtype is None:
        subtype = "NVR/DVR"
    return is_nvr, reasons, subtype
