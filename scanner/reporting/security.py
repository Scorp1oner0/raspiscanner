"""Findings di sicurezza da porte/banner esposti da un host gia' scoperto.

Si basano su probe di rete attivi ma non intrusivi (connessioni TCP,
richieste HTTP) gia' fatte da fingerprint.ports: nessun tentativo di
login, nessun test di credenziali di default, nessuno sfruttamento. Solo
"cosa espone il dispositivo" a una connessione normale.
"""
TELNET_PORT = 23
HTTP_PORTS = {80, 81, 8080, 8081, 8000, 8899, 9000, 5000}

# Titoli di pagina generici che suggeriscono un'interfaccia web mai
# personalizzata/configurata (segnale debole, va preso come indizio non
# come prova: alcuni vendor usano questi titoli anche a configurazione
# avvenuta).
_DEFAULT_TITLE_MARKERS = ("index of /", "welcome", "login")


def find_security_issues(device):
    """device: dict con 'open_ports', 'http_banners', 'is_camera', 'is_nvr'.
    Ritorna una lista di finding: {"id":.., "message":.., "severity":..}
    con severity in critical/high/medium/low.
    """
    ports_open = {p["port"] for p in device.get("open_ports", [])}
    banners = device.get("http_banners") or {}
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

    if ports_open & HTTP_PORTS:
        findings.append({
            "id": "http_enabled",
            "message": "HTTP enabled",
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
