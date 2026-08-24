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

    RISK SUMMARY
      Critical: 0
      High:     1
      Medium:   2
      Low:      3
"""
from . import risk as risk_module
from . import security as security_module

_HEADER_RULE = "─" * 28
_SECTION_RULE = "═" * 40

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
    vendor = vendor if vendor and vendor != "Sconosciuto" else None
    model = device.get("model")

    if vendor and model:
        return f"{vendor} {model}"
    if device.get("is_nvr"):
        return f"{vendor} NVR" if vendor else "NVR (vendor unknown)"
    if device.get("is_camera"):
        return f"{vendor} camera" if vendor else "IP camera (vendor unknown)"
    if device.get("is_network_infra"):
        return f"{vendor} network device" if vendor else "Network device"
    return vendor or "Unknown device"


def _services_label(device):
    ports = device.get("open_ports") or []
    labels = []
    seen = set()
    for p in ports:
        label = _PROTOCOL_LABELS.get(p["port"], p.get("service", str(p["port"])))
        if label not in seen:
            seen.add(label)
            labels.append(label)
    return " / ".join(labels) if labels else "-"


def _device_findings(device):
    return security_module.find_security_issues(device)


def generate(network_cidr, devices):
    """devices: lista di dict scan_engine gia' filtrati per questa rete
    (device["network"] == network_cidr). Ritorna il report come stringa.
    """
    cameras = [d for d in devices if d.get("is_camera") and not d.get("is_nvr")]
    nvrs = [d for d in devices if d.get("is_nvr")]
    infra = [d for d in devices if d.get("is_network_infra")]

    all_findings = []
    seen_messages = []
    for d in devices:
        for f in _device_findings(d):
            all_findings.append(f)
            if f["message"] not in seen_messages:
                seen_messages.append(f["message"])
    risk_counts = risk_module.summarize(all_findings)

    lines = ["NETWORK ASSESSMENT", _HEADER_RULE, "", f"Network: {network_cidr}", ""]
    lines.append(f"{len(devices)} devices discovered")
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

    if seen_messages:
        lines.append("SECURITY")
        for message in seen_messages:
            lines.append(f"  ⚠ {message}")
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
        return "Nessun dato: esegui prima uno scan."

    by_network = {}
    for d in devices:
        cidr = d.get("network") or "rete sconosciuta"
        by_network.setdefault(cidr, []).append(d)

    reports = [generate(cidr, devs) for cidr, devs in sorted(by_network.items())]
    return f"\n\n{_SECTION_RULE}\n\n".join(reports)
