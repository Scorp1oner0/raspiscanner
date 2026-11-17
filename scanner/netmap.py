"""Mappa delle reti scansionate, ricavata solo da cio' che lo scan ha gia'
visto: nessuna credenziale, nessun accesso a switch o router.

Mostra lo scanner, le reti raggiunte sulle sue interfacce (cavo, Wi-Fi,
VPN), il gateway di ciascuna e gli apparecchi trovati. Un apparecchio che
compare in due reti con lo stesso nome (un Raspberry con cavo e Wi-Fi)
viene segnato come ponte tra le due: e' l'unico collegamento che si puo'
dedurre senza interrogare gli apparati.

Non dice su quale porta di uno switch o su quale access point e' attaccato
un apparecchio della stessa rete: quel dato sta solo negli apparati."""

import re

from .network import setup as network_setup

_GENERIC_NAMES = {"", "localhost", "_gateway", "gateway", "unknown"}


def _iface_kind(iface):
    if network_setup.is_noarp(iface):
        return "vpn"
    if iface.startswith(("wl", "wifi", "wlan")):
        return "wifi"
    return "ethernet"


def _normalized_name(hostname):
    name = (hostname or "").strip().lower()
    name = re.sub(r"\.(local|lan|home|localdomain)$", "", name)
    return name


def _label(device, is_self=False):
    if is_self:
        return "This scanner"
    hostname = (device.get("hostname") or "").strip()
    if _normalized_name(hostname) not in _GENERIC_NAMES:
        return hostname
    if device.get("model"):
        return device["model"]
    if device.get("vendor") and device["vendor"] != "Unknown":
        return device["vendor"]
    if device.get("device_type") and device["device_type"] != "Generic":
        return device["device_type"]
    return device["ip"]


def build_map(topology, devices, local_ips=()):
    """topology: {iface: {"cidr", "gateway", "neighbors"}} dello scan.
    devices: elenco dei dispositivi dello scan. local_ips: indirizzi che la
    macchina dello scanner ha sulle proprie interfacce."""
    local_ips = set(local_ips)
    networks = []
    for iface in sorted(topology):
        info = topology[iface]
        networks.append({
            "iface": iface,
            "cidr": info.get("cidr"),
            "gateway": info.get("gateway"),
            "kind": _iface_kind(iface),
        })

    gateways = {(n["iface"], n["gateway"]) for n in networks if n["gateway"]}
    nodes = []
    for device in devices:
        iface = device.get("iface")
        nodes.append({
            "ip": device["ip"],
            "label": _label(device, device["ip"] in local_ips),
            "vendor": device.get("vendor"),
            "device_type": device.get("device_type"),
            "mac": device.get("mac"),
            "iface": iface,
            "network": device.get("network"),
            "is_gateway": (iface, device["ip"]) in gateways,
            "is_self": device["ip"] in local_ips,
            "is_camera": bool(device.get("is_camera")),
        })

    by_name = {}
    for node, device in zip(nodes, devices):
        name = _normalized_name(device.get("hostname"))
        if name in _GENERIC_NAMES or node["is_self"]:
            continue
        by_name.setdefault(name, []).append(node)

    links = []
    for name, group in by_name.items():
        if len({n["network"] for n in group}) < 2:
            continue
        for first, second in zip(group, group[1:]):
            if first["network"] != second["network"]:
                links.append({"a": first["ip"], "b": second["ip"], "kind": "same_device", "name": name})
                first["is_bridge"] = second["is_bridge"] = True

    self_nodes = [n for n in nodes if n["is_self"]]
    for first, second in zip(self_nodes, self_nodes[1:]):
        if first["network"] != second["network"]:
            links.append({"a": first["ip"], "b": second["ip"], "kind": "same_device", "name": "self"})

    for node in nodes:
        node.setdefault("is_bridge", False)

    return {
        "networks": networks,
        "devices": nodes,
        "links": links,
        "limits": "Without credentials a device's switch port or access point can't be seen: "
                  "only the networks and the devices bridging two of them.",
    }
