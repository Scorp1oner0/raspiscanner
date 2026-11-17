"""Access point a cui un'interfaccia Wi-Fi dello scanner e' associata.

Lettura locale, senza rete e senza privilegi: il BSSID (il MAC della radio
dell'access point) che NetworkManager conosce per la connessione attiva. Serve
alla mappa per tirare la linea Wi-Fi dal client al suo access point. Senza
NetworkManager o su un'interfaccia non Wi-Fi ritorna None.
"""
import os
import re
import subprocess

from ..network.nmcli_util import split_nmcli_terse

_MAC = re.compile(r"[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}")


def associated_bssid(iface):
    if not os.path.isdir(f"/sys/class/net/{iface}/wireless"):
        return None
    try:
        res = subprocess.run(
            ["nmcli", "-t", "-f", "ACTIVE,BSSID", "device", "wifi", "list", "ifname", iface, "--rescan", "no"],
            capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0:
        return None
    for line in res.stdout.splitlines():
        active, bssid = split_nmcli_terse(line, 2)
        if active == "yes" and _MAC.fullmatch(bssid):
            return bssid.lower()
    return None
