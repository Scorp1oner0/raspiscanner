"""Individuazione degli apparati di rete (router/gateway, switch, access
point) tra i dispositivi trovati da uno scan.

Il segnale piu' forte e affidabile e' essere il gateway di default della
subnet (deterministico, letto dalla tabella di routing del kernel). Vendor
OUI e banner HTTP sono segnali di supporto, meno certi.
"""
import logging
import subprocess

log = logging.getLogger("raspiscanner.network.infra")

# Parola chiave nel banner -> sottotipo specifico da mostrare invece del
# generico "Apparato di rete". L'ordine conta solo per il primo match.
_KEYWORD_SUBTYPE = {
    "router": "Router",
    "gateway": "Router",
    "routeros": "Router",
    "mikrotik": "Router",
    "switch": "Switch",
    "access point": "Access Point",
    "wireless controller": "Access Point",
    "ap management": "Access Point",
}

_INFRA_VENDOR_HINTS = (
    "tp-link", "ubiquiti", "netgear", "d-link", "cisco", "mikrotik",
    "asustek", "huawei technologies", "aruba", "zyxel",
)


def get_default_gateway(iface):
    """Ritorna l'IP del gateway di default per l'interfaccia, o None."""
    try:
        res = subprocess.run(
            ["ip", "-4", "route", "show", "dev", iface],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        log.warning("lettura gateway fallita su %s: %s", iface, exc)
        return None
    if res.returncode != 0:
        return None
    for line in res.stdout.splitlines():
        if line.startswith("default"):
            parts = line.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    return None


def classify_network_device(ip, gateway_ip, vendor_name, http_banners):
    """Ritorna (is_network_infra: bool, subtype: str|None, reasons: list[str]).

    `subtype` e' "Router"/"Switch"/"Access Point" quando un segnale specifico
    lo indica, altrimenti None (resta il generico "Apparato di rete" nel
    chiamante). Essere il gateway di default e' il segnale piu' forte e
    vince su qualunque altro: un dispositivo puo' fare anche da switch, ma
    se instrada il traffico verso l'esterno e' prima di tutto un router.
    """
    reasons = []
    is_infra = False
    subtype = None

    if gateway_ip and ip == gateway_ip:
        is_infra = True
        subtype = "Router"
        reasons.append("is the network's default gateway")

    vendor_lower = (vendor_name or "").lower()
    if any(hint in vendor_lower for hint in _INFRA_VENDOR_HINTS):
        is_infra = True
        reasons.append(f"network vendor ({vendor_name})")

    for port, banner in (http_banners or {}).items():
        text = " ".join(filter(None, [banner.get("server"), banner.get("title")])).lower()
        if not text:
            continue
        for kw, kw_subtype in _KEYWORD_SUBTYPE.items():
            if kw in text:
                is_infra = True
                if subtype is None:
                    subtype = kw_subtype
                reasons.append(f"HTTP banner on port {port} contains '{kw}'")
                break

    return is_infra, subtype, reasons
