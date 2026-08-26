"""Hotspot Wi-Fi (access point) sull'interfaccia wifi.

Serve per raggiungere la dashboard senza cavo quando il dispositivo e'
installato in un punto scomodo da cablare (es. dentro una scatola in
quota): invece di collegare il Wi-Fi a una rete esistente (vedi
network.setup.wifi_connect), qui il dispositivo CREA la propria rete a
cui collegarsi da terra con un PC/telefono.

Usa `nmcli` (NetworkManager), lo stesso meccanismo gia' usato per il Wi-Fi
client: `nmcli device wifi hotspot` gestisce da solo il DHCP interno per i
client connessi (di norma sulla 10.42.0.0/24), senza bisogno di installare
hostapd/dnsmasq separatamente.

Limite fisico, non di questo codice: la stessa radio Wi-Fi non puo' fare
contemporaneamente client (connessa a una rete esistente) e access point.
Attivare l'hotspot scollega wlan0 da qualunque rete a cui era connesso.
"""
import logging
import secrets
import string
import subprocess

log = logging.getLogger("raspiscanner.network.hotspot")

HOTSPOT_CONNECTION_NAME = "raspiscanner-hotspot"
MIN_PASSWORD_LENGTH = 8


def _run(cmd, timeout=20):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        log.warning("comando fallito %s: %s", cmd, exc)
        return None


def generate_password(length=12):
    """Password casuale WPA2-sicura per il valore precompilato nella dashboard."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def default_ssid(mac=None, iface="wlan0"):
    """SSID suggerito, derivato dagli ultimi 4 caratteri del MAC
    dell'interfaccia (cosi' e' riconoscibile e non collide con altri
    RaspiScanner sulla stessa rete)."""
    if mac is None:
        try:
            with open(f"/sys/class/net/{iface}/address") as fh:
                mac = fh.read().strip()
        except (FileNotFoundError, OSError):
            mac = None
    suffix = mac.replace(":", "")[-4:].upper() if mac else "0000"
    return f"RaspiScanner-{suffix}"


def start_hotspot(iface, ssid, password):
    """Attiva l'hotspot su `iface`. Ritorna (ok, messaggio).

    Il profilo creato da `nmcli device wifi hotspot` resta salvato e per
    default si riattiva da solo al riavvio: e' voluto, perche' se il
    dispositivo viene messo in quota e perde alimentazione, deve tornare
    raggiungibile via hotspot senza bisogno di riconfigurarlo da capo con
    un cavo.
    """
    ssid = (ssid or "").strip()
    if not ssid:
        return False, "SSID is required"
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters (WPA2)"

    # rimuove un eventuale profilo hotspot precedente, altrimenti nmcli ne
    # accumula uno nuovo (con nome incrementale) a ogni riconfigurazione
    _run(["nmcli", "connection", "delete", HOTSPOT_CONNECTION_NAME], timeout=10)

    res = _run([
        "nmcli", "device", "wifi", "hotspot",
        "ifname", iface,
        "con-name", HOTSPOT_CONNECTION_NAME,
        "ssid", ssid,
        "password", password,
    ], timeout=30)

    if not res or res.returncode != 0:
        message = (res.stderr.strip() or res.stdout.strip()) if res else "nmcli not available"
        log.error("attivazione hotspot fallita su %s: %s", iface, message)
        return False, message or "failed to activate hotspot"

    log.info("hotspot attivato su %s (SSID %s)", iface, ssid)
    return True, "Hotspot activated"


def stop_hotspot():
    """Disattiva l'hotspot (il profilo resta salvato, solo disattivato:
    per rimuoverlo del tutto va cancellato manualmente con
    `nmcli connection delete raspiscanner-hotspot`)."""
    res = _run(["nmcli", "connection", "down", HOTSPOT_CONNECTION_NAME], timeout=15)
    if not res:
        return False, "nmcli not available"
    ok = res.returncode == 0
    message = (res.stdout.strip() or res.stderr.strip()) if ok else (res.stderr.strip() or res.stdout.strip())
    return ok, message or ("Hotspot deactivated" if ok else "failed to deactivate hotspot")


def get_hotspot_status():
    """Ritorna {'active': bool, 'ssid':.., 'ip':.., 'iface':..}."""
    active_res = _run(["nmcli", "-t", "-f", "NAME,DEVICE", "connection", "show", "--active"], timeout=10)
    iface = None
    if active_res and active_res.returncode == 0:
        for line in active_res.stdout.splitlines():
            name, _, device = line.partition(":")
            if name == HOTSPOT_CONNECTION_NAME:
                iface = device
                break

    if not iface:
        return {"active": False, "ssid": None, "ip": None, "iface": None}

    ssid = None
    ssid_res = _run(
        ["nmcli", "-t", "-f", "802-11-wireless.ssid", "connection", "show", HOTSPOT_CONNECTION_NAME],
        timeout=10,
    )
    if ssid_res and ssid_res.returncode == 0 and ssid_res.stdout.strip():
        ssid = ssid_res.stdout.strip().split(":", 1)[-1] or None

    ip = None
    ip_res = _run(["nmcli", "-t", "-f", "IP4.ADDRESS", "device", "show", iface], timeout=10)
    if ip_res and ip_res.returncode == 0:
        for line in ip_res.stdout.splitlines():
            if line.startswith("IP4.ADDRESS"):
                ip = line.split(":", 1)[-1].split("/")[0].strip() or None
                break

    return {"active": True, "ssid": ssid, "ip": ip, "iface": iface}
