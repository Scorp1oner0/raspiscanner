"""Mappa delle reti scansionate, ricavata solo da cio' che lo scan ha gia'
visto: nessuna credenziale, nessun accesso a switch o router, nessun dato
sulla rete di chi la usa dentro il codice. Funziona su una rete vista per la
prima volta.

Mostra lo scanner, il percorso fino a Internet (i primi salti del
traceroute), le reti raggiunte sulle sue interfacce (cavo, Wi-Fi, VPN), chi
vi fa da gateway, da server DHCP e da DNS, e gli apparecchi trovati. Un
apparecchio con piu' indirizzi nella stessa rete (stesso MAC) e' uno solo;
uno che compare in due reti con lo stesso nome (un Raspberry con cavo e
Wi-Fi) viene segnato come ponte tra le due.

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


def _ip_key(ip):
    return [int(p) if p.isdigit() else 0 for p in ip.split(".")]


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


def _has_dns(device):
    return any(p.get("port") == 53 for p in device.get("open_ports") or [])


def _roles(node, dhcp_servers, dns_servers):
    roles = []
    if node["is_self"]:
        roles.append("scanner")
    if node["is_gateway"]:
        roles.append("gateway")
    if any(ip in dhcp_servers for ip in node["ips"]):
        roles.append("dhcp")
    if any(ip in dns_servers for ip in node["ips"]) or node.get("_dns_port"):
        roles.append("dns")
    if node.get("is_bridge"):
        roles.append("bridge")
    return roles


def _merge_same_mac(nodes):
    """Un apparecchio con piu' indirizzi nella stessa rete risponde con lo
    stesso MAC: una scatola sola, con tutti gli indirizzi."""
    merged, by_mac = [], {}
    for node in nodes:
        if node["is_self"]:
            key = (node["network"], "self")
        else:
            key = (node["network"], node["mac"].lower()) if node["mac"] else None
        if key and key in by_mac:
            first = by_mac[key]
            first["ips"].append(node["ip"])
            first["is_gateway"] = first["is_gateway"] or node["is_gateway"]
            first["is_self"] = first["is_self"] or node["is_self"]
            first["_dns_port"] = first["_dns_port"] or node["_dns_port"]
            continue
        node["ips"] = [node["ip"]]
        merged.append(node)
        if key:
            by_mac[key] = node
    for node in merged:
        node["ips"].sort(key=_ip_key)
    return merged


def _uplink_path(uplink, nodes, networks):
    if not uplink or not uplink.get("hops"):
        return None
    by_ip = {ip: n for n in nodes for ip in n["ips"]}
    hops = []
    for hop in uplink["hops"]:
        node = by_ip.get(hop["ip"]) if hop["ip"] else None
        hops.append({
            "ttl": hop["ttl"], "ip": hop["ip"], "rtt_ms": hop["rtt_ms"], "private": hop["private"],
            "label": node["label"] if node else None, "known": node is not None,
            "is_public": hop["private"] is False,
        })
    first_ip = next((h["ip"] for h in hops if h["ip"]), None)
    via = next((n["iface"] for n in networks if first_ip and n["gateway"] == first_ip), None)
    return {"target": uplink.get("target"), "hops": hops, "internet": bool(uplink.get("internet")), "via": via}


def _merge_same_network(networks):
    """Due interfacce nello stesso indirizzamento (cavo e Wi-Fi verso la
    stessa rete) sono una rete sola: lo scan identifica gli apparecchi per
    indirizzo e non potrebbe comunque distinguerle. Ritorna le reti unite e
    a quale interfaccia e' stata ricondotta ciascuna."""
    merged, by_cidr, iface_main = [], {}, {}
    for net in networks:
        main = by_cidr.get(net["cidr"]) if net["cidr"] and net["kind"] != "vpn" else None
        if main is None:
            net["ifaces"] = [net["iface"]]
            merged.append(net)
            iface_main[net["iface"]] = net["iface"]
            if net["cidr"] and net["kind"] != "vpn":
                by_cidr[net["cidr"]] = net
            continue
        main["ifaces"].append(net["iface"])
        main["gateway"] = main["gateway"] or net["gateway"]
        known = {o["server"] for o in main["dhcp"]}
        main["dhcp"].extend(o for o in net["dhcp"] if o["server"] not in known)
        iface_main[net["iface"]] = main["iface"]
    return merged, iface_main


def build_map(topology, devices, local_ips=(), uplink=None):
    """topology: {iface: {"cidr", "gateway", "neighbors", "dhcp"}} dello scan.
    devices: elenco dei dispositivi dello scan. local_ips: indirizzi che la
    macchina dello scanner ha sulle proprie interfacce. uplink: il percorso
    verso Internet (scanner.discovery.uplink), se c'e'."""
    local_ips = set(local_ips)
    networks, dhcp_servers, dns_servers = [], set(), set()
    for iface in sorted(topology):
        info = topology[iface]
        dhcp = info.get("dhcp") or []
        for offer in dhcp:
            dhcp_servers.add(offer["server"])
            dns_servers.update(offer.get("dns") or [])
        networks.append({
            "iface": iface,
            "cidr": info.get("cidr"),
            "gateway": info.get("gateway"),
            "kind": _iface_kind(iface),
            "dhcp": [{"server": o["server"], "router": o.get("router"), "dns": o.get("dns") or [],
                      "domain": o.get("domain")} for o in dhcp],
        })

    networks, iface_main = _merge_same_network(networks)
    gateways = {(iface_main.get(n["iface"], n["iface"]), n["gateway"]) for n in networks if n["gateway"]}
    nodes = []
    for device in devices:
        iface = iface_main.get(device.get("iface"), device.get("iface"))
        nodes.append({
            "ip": device["ip"],
            "label": _label(device, device["ip"] in local_ips),
            "hostname": device.get("hostname"),
            "vendor": device.get("vendor"),
            "device_type": device.get("device_type"),
            "mac": device.get("mac"),
            "iface": iface,
            "network": device.get("network"),
            "is_gateway": (iface, device["ip"]) in gateways,
            "is_self": device["ip"] in local_ips,
            "is_camera": bool(device.get("is_camera")),
            "is_bridge": False,
            "_dns_port": _has_dns(device),
        })
    nodes = _merge_same_mac(nodes)

    by_name = {}
    for node in nodes:
        name = _normalized_name(node["hostname"])
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
        node["roles"] = _roles(node, dhcp_servers, dns_servers)
        node.pop("_dns_port", None)
        node.pop("hostname", None)

    return {
        "networks": networks,
        "devices": nodes,
        "links": links,
        "uplink": _uplink_path(uplink, nodes, networks),
        "limits": "Without credentials a device's switch port or access point can't be seen: "
                  "only the networks, who runs them, the path to the Internet and the devices bridging two networks.",
    }
