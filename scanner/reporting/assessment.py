"""Genera il report testuale "NETWORK ASSESSMENT" per una o piu' reti
scansionate, nel formato:

    NETWORK ASSESSMENT
    ────────────────────────────

    Network: 192.168.10.0/24

    12 devices discovered

    CAMERAS
      Hikvision
      192.168.10.21
      HTTP / HTTPS / RTSP
    ...

    OTHER DEVICES
      PC (Windows/SMB) — Dell
      192.168.10.30
      RDP

    SECURITY
      ⚠ Telnet exposed — 192.168.10.1 (MikroTik network device)
      ⚠ HTTP service detected, no HTTPS available — 192.168.10.21 (Hikvision camera)

    RISK SUMMARY
      Critical: 0
      High:     1
      Medium:   2
      Low:      3

generate_all() appends a one-line scope disclaimer at the end of the
combined report (once, not per-network): questo tool NON e' un
vulnerability scanner, e va detto esplicitamente dove chi legge il report
puo' vederlo, non solo nei commenti del codice.
"""
from . import risk as risk_module
from . import security as security_module

_HEADER_RULE = "─" * 28
_SECTION_RULE = "═" * 40
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

_SCOPE_DISCLAIMER = (
    "This is a network/device discovery and exposure report, not a vulnerability "
    "scanner: no exploits, no brute-force or credential-guessing attempts, no CVE "
    "matching. Findings describe what a service EXPOSES to a normal connection, "
    "not whether it is actually vulnerable or exploitable."
)

# Etichette di protocollo compatte per la riga "servizi" del report: piu'
# leggibili delle etichette descrittive usate nella dashboard (es.
# "Hikvision/HTTP-Alt" -> "HTTP").
_PROTOCOL_LABELS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS",
    80: "HTTP", 81: "HTTP", 443: "HTTPS", 554: "RTSP",
    8000: "HTTP", 8080: "HTTP", 8081: "HTTP", 8443: "HTTPS",
    8899: "HTTP", 9000: "HTTP", 37777: "DVRIP", 34567: "DVRIP", 5000: "HTTP",
}


def _device_label(device):
    vendor = device.get("vendor")
    vendor = vendor if vendor and vendor != "Unknown" else None
    model = device.get("model")

    if vendor and model:
        label = f"{vendor} {model}"
    elif device.get("is_nvr"):
        label = f"{vendor} NVR" if vendor else "NVR (vendor unknown)"
    elif device.get("is_camera"):
        label = f"{vendor} camera" if vendor else "IP camera (vendor unknown)"
    elif device.get("is_network_infra"):
        label = f"{vendor} network device" if vendor else "Network device"
    else:
        label = vendor or "Unknown device"

    if device.get("network_mismatch"):
        label += " [IP MISCONFIGURED]"
    return label


def _services_label(device):
    ports = device.get("open_ports") or []
    labels = []
    seen = set()
    for p in ports:
        label = _PROTOCOL_LABELS.get(p["port"], p.get("service", str(p["port"])))
        if label not in seen:
            seen.add(label)
            labels.append(label)
    if labels:
        return " / ".join(labels)
    if device.get("onvif_xaddr"):
        # Nessuna porta scansionata (l'IP non e' raggiungibile in unicast
        # su questa rete): l'unica evidenza che abbiamo e' la risposta
        # multicast ONVIF, mostrarla e' piu' utile di un "-" muto.
        return f"ONVIF (multicast): {device['onvif_xaddr']}"
    return "-"


def _other_device_label(device):
    """Etichetta per la sezione OTHER DEVICES: qui mostriamo il device_type
    gia' calcolato da scan_engine (Raspberry Pi, PC (Windows/SMB), Stampante
    di rete, ...) invece del fallback generico di _device_label, che non
    conosce questi tipi e mostrerebbe solo il vendor."""
    vendor = device.get("vendor")
    vendor = vendor if vendor and vendor != "Unknown" else None
    device_type = device.get("device_type") or "Unknown device"
    return f"{device_type} — {vendor}" if vendor else device_type


def _device_findings(device):
    return security_module.find_security_issues(device)


def generate(network_cidr, devices):
    """devices: lista di dict scan_engine gia' filtrati per questa rete
    (device["network"] == network_cidr). Ritorna il report come stringa.
    """
    cameras = [d for d in devices if d.get("is_camera") and not d.get("is_nvr")]
    nvrs = [d for d in devices if d.get("is_nvr")]
    infra = [d for d in devices if d.get("is_network_infra")]
    shown_ips = {d["ip"] for d in cameras + nvrs + infra}

    findings_by_ip = {d["ip"]: _device_findings(d) for d in devices}

    # OGNI dispositivo non gia' mostrato in CAMERAS/NVR/NETWORK finisce qui,
    # "Generico" senza alcun segnale incluso: "N devices discovered" deve
    # sempre corrispondere al numero di righe elencate nel report, mai un
    # conteggio piu' alto di cio' che il testo mostra davvero — versioni
    # precedenti escludevano i "Generico" senza finding per non appesantire
    # il report, ma il risultato ("N trovati" con solo M elencati) si e'
    # rivelato piu' confuso che utile.
    other = [d for d in devices if d["ip"] not in shown_ips]

    all_findings = []  # per il riepilogo rischio: ogni finding, non deduplicato
    device_findings = []  # per la lista leggibile: (severity, ip, label, message)
    seen = set()
    for d in devices:
        label = _device_label(d)
        for f in findings_by_ip[d["ip"]]:
            all_findings.append(f)
            key = (d["ip"], f["message"])
            if key in seen:
                continue
            seen.add(key)
            device_findings.append((f.get("severity", "low"), d["ip"], label, f["message"]))
    device_findings.sort(key=lambda t: (_SEVERITY_ORDER.get(t[0], 9), t[1]))
    risk_counts = risk_module.summarize(all_findings)

    lines = ["NETWORK ASSESSMENT", _HEADER_RULE, "", f"Network: {network_cidr}", ""]
    lines.append(f"{len(devices)} devices discovered")

    # Un device senza MAC e senza essere gia' segnalato "fuori rete" e'
    # stato trovato via ICMP invece che ARP (link NOARP: VPN instradata,
    # niente livello 2 — vedi scan_engine/discovery.icmp). Senza questa
    # nota il MAC vuoto nella tabella della dashboard/nel CSV sembra un
    # dato mancante per errore invece di un limite noto del protocollo.
    no_mac_ips = [d["ip"] for d in devices if not d.get("mac") and not d.get("network_mismatch")]
    if no_mac_ips:
        plural = "s" if len(no_mac_ips) != 1 else ""
        lines.append(
            f"Note: {len(no_mac_ips)} device{plural} on this network have no MAC address "
            "available (found via ICMP over a VPN/NOARP link, not ARP) — expected, not a scan error."
        )

    lines.append("")

    def _section(title, group, with_services=True):
        if not group:
            return
        lines.append(title)
        for d in group:
            lines.append(f"  {_device_label(d)}")
            lines.append(f"  {d['ip']}")
            if with_services:
                lines.append(f"  {_services_label(d)}")
        lines.append("")

    _section("CAMERAS", cameras)
    _section("NVR", nvrs)
    _section("NETWORK", infra, with_services=False)

    if other:
        lines.append("OTHER DEVICES")
        for d in other:
            lines.append(f"  {_other_device_label(d)}")
            lines.append(f"  {d['ip']}")
            lines.append(f"  {_services_label(d)}")
        lines.append("")

    if device_findings:
        lines.append("SECURITY")
        for severity, ip, label, message in device_findings:
            lines.append(f"  ⚠ {message} — {ip} ({label})")
        lines.append("")

    lines.append("RISK SUMMARY")
    lines.append(f"  Critical: {risk_counts['critical']}")
    lines.append(f"  High:     {risk_counts['high']}")
    lines.append(f"  Medium:   {risk_counts['medium']}")
    lines.append(f"  Low:      {risk_counts['low']}")

    return "\n".join(lines)


def generate_all(devices):
    """devices: lista piatta di tutti i dispositivi trovati (con campo
    "network" gia' valorizzato da scan_engine). Raggruppa per rete e
    concatena un report per ciascuna. Ritorna la stringa completa, o un
    messaggio se non ci sono dati.
    """
    if not devices:
        return "No data yet — run a scan first."

    by_network = {}
    for d in devices:
        cidr = d.get("network") or "unknown network"
        by_network.setdefault(cidr, []).append(d)

    reports = [generate(cidr, devs) for cidr, devs in sorted(by_network.items())]
    combined = f"\n\n{_SECTION_RULE}\n\n".join(reports)
    return f"{combined}\n\n{_SCOPE_DISCLAIMER}"
