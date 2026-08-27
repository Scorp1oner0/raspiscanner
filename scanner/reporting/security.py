"""Findings di sicurezza da porte/banner esposti da un host gia' scoperto.

Si basano su probe di rete attivi ma non intrusivi (connessioni TCP,
richieste HTTP) gia' fatte da fingerprint.ports: nessun tentativo di
login, nessun test di credenziali di default, nessuno sfruttamento,
nessuna scansione CVE. Solo "cosa espone il dispositivo" a una
connessione normale — RaspiScanner non e' un vulnerability scanner: non
verifica se un servizio esposto e' davvero sfruttabile, solo se e'
raggiungibile.
"""
TELNET_PORT = 23
RTSP_PORT = 554
HTTP_PORTS = {80, 81, 8080, 8081, 8000, 8899, 9000, 5000}  # in chiaro
HTTPS_PORTS = {443, 8443}

# Titoli di pagina generici che suggeriscono un'interfaccia web mai
# personalizzata/configurata (segnale debole, va preso come indizio non
# come prova: alcuni vendor usano questi titoli anche a configurazione
# avvenuta).
_DEFAULT_TITLE_MARKERS = ("index of /", "welcome", "login")

# Segnali che il servizio HTTP e' probabilmente un pannello di
# amministrazione (router, NVR, telecamera) invece di una pagina
# qualunque: cambia la severita' del finding, un pannello admin in
# chiaro senza HTTPS e' un rischio concreto di credenziali intercettabili,
# una pagina di stato generica molto meno.
_ADMIN_TITLE_MARKERS = ("login", "admin", "config", "setup", "management")


def find_security_issues(device):
    """device: dict con 'open_ports', 'http_banners', 'is_camera', 'is_nvr'.
    Ritorna una lista di finding: {"id":.., "message":.., "severity":..}
    con severity in critical/high/medium/low.
    """
    ports_open = {p["port"] for p in device.get("open_ports", [])}
    # Normalizza le chiavi porta a int: un device passato per uno storico
    # salvato (storage.save_scan()/get_scan_devices(), usato dall'Audit
    # mode) ha fatto un round-trip JSON, e JSON non supporta chiavi-oggetto
    # non stringa — "80" invece di 80. Bug reale scoperto testando l'Audit
    # mode su hardware vero: banners.get(p) con p intero (da ports_open,
    # sempre int) falliva silenziosamente su un dict con chiavi stringa,
    # degradando "HTTP admin panel" (high) a "HTTP service" generico
    # (medium) SOLO per i report rigenerati da uno scan salvato, mai per
    # il report live (dict Python originale, mai serializzato).
    banners = {int(k): v for k, v in (device.get("http_banners") or {}).items()}
    findings = []

    if device.get("network_mismatch"):
        # Non e' una porta/servizio esposto come gli altri finding: e' una
        # telecamera rilevata solo via multicast ONVIF, con un IP che non
        # appartiene a nessuna rete attiva (probabile errore di
        # configurazione). Rilevante per un assessment CCTV perche' una
        # telecamera irraggiungibile e' de facto fuori dal sistema di
        # sorveglianza monitorato, anche se fisicamente installata.
        findings.append({
            "id": "network_mismatch",
            "message": "Camera IP misconfigured (unreachable on this network)",
            "severity": "medium",
        })
        return findings

    if TELNET_PORT in ports_open:
        # Telnet su una telecamera/NVR e' il caso storicamente piu' sfruttato
        # (botnet IoT tipo Mirai): lo trattiamo come critico specificamente
        # su questi dispositivi, alto altrove.
        is_video_device = device.get("is_camera") or device.get("is_nvr")
        findings.append({
            "id": "telnet_exposed",
            "message": "Telnet exposed",
            "severity": "critical" if is_video_device else "high",
        })

    http_ports_open = ports_open & HTTP_PORTS
    if http_ports_open:
        # Non ogni porta HTTP e' lo stesso rischio: un pannello di
        # amministrazione servito solo in chiaro (nessuna HTTPS disponibile
        # sul dispositivo) e' il caso peggiore; lo stesso pannello con
        # HTTPS disponibile in alternativa e' un problema minore (la
        # configurazione andrebbe corretta, ma l'opzione sicura esiste);
        # un servizio HTTP generico (non un pannello admin) con HTTPS
        # disponibile e' il piu' basso. Prima qualunque porta HTTP
        # diventava sempre e comunque "medium", a prescindere dal contesto.
        is_admin = any(
            any(marker in (banners.get(p, {}).get("title") or "").strip().lower() for marker in _ADMIN_TITLE_MARKERS)
            for p in http_ports_open
        )
        has_https = bool(ports_open & HTTPS_PORTS)
        if is_admin and not has_https:
            findings.append({
                "id": "http_admin_without_https",
                "message": "HTTP administrative interface exposed, no HTTPS available",
                "severity": "high",
            })
        elif is_admin:
            findings.append({
                "id": "http_admin_with_https",
                "message": "HTTP administrative interface exposed (HTTPS also available on this device)",
                "severity": "medium",
            })
        elif not has_https:
            findings.append({
                "id": "http_without_https",
                "message": "HTTP service detected, no HTTPS available",
                "severity": "medium",
            })
        else:
            findings.append({
                "id": "http_with_https",
                "message": "HTTP service detected (HTTPS also available on this device)",
                "severity": "low",
            })

    if RTSP_PORT in ports_open:
        # Segnalato a parte dalla classificazione "e' una camera": qui
        # interessa la sicurezza (lo stream e' raggiungibile in rete),
        # non la classificazione del dispositivo. Non si verifica se lo
        # stream richiede credenziali (richiederebbe un vero handshake
        # RTSP, fuori dallo scope non intrusivo di questo tool).
        findings.append({
            "id": "rtsp_exposed",
            "message": "RTSP exposed (stream reachability not verified — check the camera's credentials)",
            "severity": "medium",
        })

    for port, banner in banners.items():
        title = (banner.get("title") or "").strip().lower()
        if any(marker in title for marker in _DEFAULT_TITLE_MARKERS):
            findings.append({
                "id": "default_service",
                "message": "Default service detected",
                "severity": "low",
            })
            break  # un solo finding di questo tipo per dispositivo

    return findings
