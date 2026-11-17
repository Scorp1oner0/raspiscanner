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

Al centro di una rete mette lo switch, se ce n'e' uno solo o se lo scan ha
dati sicuri: la porta di ogni apparecchio dove lo switch risponde alla
community di fabbrica, la porta del cavo dello scanner dove annuncia LLDP.
Negli altri casi il collegamento allo switch e' dedotto e lo dice.
Senza accesso agli apparati non si puo' dire di piu'."""

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
    if node.get("is_hub"):
        roles.append("switch")
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
            first["_fdb"] = first["_fdb"] or node["_fdb"]
            first["_lldp"] = first["_lldp"] or node["_lldp"]
            first["macs"] = first["macs"] + [m for m in node["macs"] if m not in first["macs"]]
            continue
        node["ips"] = [node["ip"]]
        merged.append(node)
        if key:
            by_mac[key] = node
    for node in merged:
        node["ips"].sort(key=_ip_key)
    return merged


def _port_of(node, table):
    """La porta dello switch su cui sta il nodo. Un nodo con piu' MAC (il PC
    dello scanner con cavo e Wi-Fi) prende quella con meno indirizzi sopra:
    un cavo e' di norma solo sulla sua porta, mentre dietro un access point
    ce ne sono molti."""
    counts = {}
    for port in table["macs"].values():
        counts[port] = counts.get(port, 0) + 1
    best = None
    for mac in node["macs"]:
        port = table["macs"].get(mac)
        if port is not None and (best is None or (counts[port], port) < best):
            best = (counts[port], port)
    return best[1] if best else None


def _table_rank(node):
    """Tra piu' apparati con una tabella MAC, il centro e' quello i cui
    indirizzi si distribuiscono su piu' porte; a parita' vince lo switch."""
    macs = node["_fdb"]["macs"]
    return (len(set(macs.values())), node["device_type"] == "Switch", len(macs))


def _port_label(raw):
    raw = str(raw).strip()
    return f"port {raw}" if raw.isdigit() else raw


def _attach_hubs(networks, nodes):
    """Per ogni rete, lo switch attorno a cui disegnarla e quanto si sa dei
    collegamenti, dal piu' certo: la tabella MAC dello switch (la porta di
    ogni apparecchio), l'annuncio LLDP/CDP ricevuto sul cavo dello scanner
    (la porta di quel solo cavo), oppure l'unico switch trovato nella rete
    (collegamento solo dedotto, senza porta). Con piu' switch e nessun dato
    sicuro nessuno e' il centro: non si puo' dire chi sta su quale."""
    for node in nodes:
        node["attach"] = None
        node["port"] = None
        node["port_name"] = None
    for net in networks:
        net["hub"] = None
        members = [n for n in nodes if n["network"] == net["cidr"]]
        tabled = [n for n in members if n["_fdb"]]
        switches = [n for n in members if n["device_type"] == "Switch"]
        tabled_switches = [n for n in tabled if n["device_type"] == "Switch"]
        hub, source = None, None
        if tabled_switches:
            hub, source = max(tabled_switches, key=_table_rank), "snmp"
        elif tabled and not switches:
            hub, source = max(tabled, key=_table_rank), "snmp"
        else:
            announced = [n for n in members if n["_lldp"] and n["device_type"] == "Switch"]
            if len(announced) == 1:
                hub, source = announced[0], "lldp"
            elif len(switches) == 1:
                hub, source = switches[0], "inferred"
        if hub is None:
            continue
        net["hub"] = {"ip": hub["ip"], "label": hub["label"], "source": source}
        hub["is_hub"] = True
        hub["attach"] = "hub"
        for node in members:
            if node is hub:
                continue
            node["attach"] = "inferred"
            if source == "snmp":
                table = hub["_fdb"]
                port = _port_of(node, table)
                names = table.get("ports") or {}
                if port is None:
                    node["attach"] = "unseen"
                else:
                    node["attach"], node["port"] = "seen", _port_label(port)
                    node["port_name"] = names.get(port) or names.get(str(port))
            elif source == "lldp" and node["is_self"] and hub["_lldp"].get("port_id"):
                node["attach"], node["port"] = "seen", _port_label(hub["_lldp"]["port_id"])


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
            "_fdb": device.get("switch_ports") or None,
            "_lldp": device.get("lldp_cdp_info") or None,
            "macs": [device["mac"].lower()] if device.get("mac") else [],
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

    _attach_hubs(networks, nodes)

    for node in nodes:
        node["roles"] = _roles(node, dhcp_servers, dns_servers)
        for internal in ("_dns_port", "_fdb", "_lldp", "macs", "hostname"):
            node.pop(internal, None)

    return {
        "networks": networks,
        "devices": nodes,
        "links": links,
        "uplink": _uplink_path(uplink, nodes, networks),
        "limits": "Which switch port a device uses is shown only where the switch answered the default "
                  "SNMP community or announced itself with LLDP. Otherwise the line from the switch is dashed: "
                  "it is deduced from the device being in the same network as the only switch found.",
    }
