"""Orchestrazione dello scan completo: discovery ARP su tutte le subnet
attive (eth + wifi), probe ONVIF, port scan e classificazione (camera,
NVR/DVR, apparato di rete) per host. Mantiene uno stato condiviso in
memoria che la dashboard interroga via polling HTTP (niente websocket/CDN
esterni: deve funzionare anche su reti isolate senza accesso a internet).
"""
import ipaddress
import logging
import threading
import time

from . import storage, vendor, webhooks
from .cameras.classify import classify_camera, guess_admin_url, guess_rtsp_url, guess_vendor_from_banner
from .cameras.onvif import get_device_info_multi, onvif_probe
from .discovery import arp_scan, icmp_scan, lldp_cdp_probe, mdns_probe, resolve_hostname, snmp_probe
from .fingerprint import grab_http_banner, scan_ports
from .hosts import classify_host
from .network import setup as network_setup
from .network.infra import classify_network_device, get_default_gateway
from .nvr.classify import classify_nvr

log = logging.getLogger("raspiscanner.scan_engine")

_lock = threading.Lock()
_state = {
    "running": False,
    "progress": 0,
    "total": 0,
    "current_ip": None,
    "started_at": None,
    "finished_at": None,
    "error": None,
    "devices": {},  # ip -> dettagli
    # P4 "network topology map": adiacenza a un salto, non un grafo
    # multi-hop (richiederebbe interrogare switch remoti via SNMP walk
    # con credenziali che non abbiamo — fuori scope per un tool non
    # intrusivo). {iface: {"cidr":.., "gateway":.., "neighbors": [...]}}
    "topology": {},
}
_stop_flag = threading.Event()


def get_state():
    with _lock:
        snap = dict(_state)
        snap["devices"] = list(_state["devices"].values())
        return snap


def _update(**kwargs):
    with _lock:
        _state.update(kwargs)


def _set_device(ip, device):
    with _lock:
        _state["devices"][ip] = device


def _active_networks():
    """Ritorna [(iface, cidr, local_ip), ...], uno per OGNI indirizzo IPv4
    attivo su eth, su TUTTE le schede wifi e su TUTTE le VPN attive
    (un'interfaccia puo' averne piu' di uno, es. IP secondari configurati a
    mano per raggiungere piu' subnet sullo stesso cavo, e un dispositivo
    puo' avere piu' schede Wi-Fi/VPN: vanno scansionate tutte, non solo la
    prima)."""
    status = network_setup.get_status()
    nets = []
    eth = status.get("eth", {})
    if eth.get("up"):
        for addr in eth.get("addresses") or []:
            if addr.get("ip") and addr.get("cidr"):
                nets.append((eth["iface"], addr["cidr"], addr["ip"]))
    for info in (status.get("wifi") or {}).values():
        if not info.get("up"):
            continue
        for addr in info.get("addresses") or []:
            if addr.get("ip") and addr.get("cidr"):
                nets.append((info["iface"], addr["cidr"], addr["ip"]))
    for info in (status.get("vpn") or {}).values():
        if not info.get("up"):
            continue
        for addr in info.get("addresses") or []:
            if addr.get("ip") and addr.get("cidr"):
                nets.append((info["iface"], addr["cidr"], addr["ip"]))
    return nets


def _scan_host(ip, mac, onvif_results, mdns_results, gateway_ip):
    open_ports = scan_ports(ip)
    banners = {}
    for p in open_ports:
        if p["port"] in (80, 81, 8000, 8080, 8081, 8899, 9000):
            banners[p["port"]] = grab_http_banner(ip, p["port"])
        elif p["port"] in (443, 8443):
            banners[p["port"]] = grab_http_banner(ip, p["port"], use_https=True)

    onvif_info = onvif_results.get(ip)
    mdns_info = mdns_results.get(ip)
    device_vendor = vendor.lookup_vendor(mac) if mac else "Unknown"
    # "vendor_source" (P4 richer vendor fingerprinting): "oui"/"banner"/
    # "onvif" — da dove viene il vendor mostrato, stesso principio di
    # model_source. Il banner HTTP e' usato SOLO come fallback quando il
    # lookup OUI (MAC) non da' un vendor noto: il nostro database OUI
    # locale e' minimo (~120 voci), un dispositivo il cui banner dice
    # letteralmente "Hikvision" non deve restare "Unknown" solo perche'
    # il suo prefisso MAC non e' nella lista.
    vendor_source = "oui" if device_vendor != "Unknown" else None
    if device_vendor == "Unknown":
        banner_vendor = guess_vendor_from_banner(banners)
        if banner_vendor:
            device_vendor = banner_vendor
            vendor_source = "banner"
    # Reverse DNS prima (dipende dal DNS locale, spesso assente per
    # dispositivi personali su reti domestiche); il nome amichevole
    # annunciato via mDNS/Bonjour (es. "Marios-iPhone") come fallback,
    # spesso l'unico disponibile proprio per i device che il reverse DNS
    # non risolve mai.
    hostname = resolve_hostname(ip) or (mdns_info.get("hostname") if mdns_info else None)

    is_camera, camera_reasons = classify_camera(open_ports, banners, onvif_info)
    is_nvr, nvr_reasons, nvr_subtype = classify_nvr(banners)
    is_infra, infra_subtype, infra_reasons = classify_network_device(ip, gateway_ip, device_vendor, banners)
    host_label, host_reasons = classify_host(device_vendor, open_ports, hostname)

    # SNMP (P4, opzionale): solo su apparati gia' sospettati di rete
    # (router/switch/AP), non su ogni host — SNMP e' spento sulla
    # stragrande maggioranza dei dispositivi (telefoni, PC, IoT), provarlo
    # su tutti aggiungerebbe un timeout in piu' per host all'intero scan
    # senza un guadagno reale. community "public" di sola lettura, mai
    # una lista indovinata (vedi scanner.discovery.snmp).
    snmp_info = {}
    if is_infra:
        snmp_info = snmp_probe(ip)
        if snmp_info.get("sysDescr") and device_vendor == "Unknown":
            device_vendor = snmp_info["sysDescr"]
            vendor_source = "snmp"
        if snmp_info.get("sysName") and not hostname:
            hostname = snmp_info["sysName"]

    # Se il dispositivo risponde a ONVIF, prova a interrogare
    # GetDeviceInformation per un vendor/model REALI invece di indovinarli
    # dal banner: non sempre riesce (spesso richiede autenticazione), in
    # quel caso restano i valori da OUI/banner. Il TXT "model=" di mDNS
    # (tipicamente _device-info, dispositivi Apple) e' un fallback quando
    # ONVIF non risponde affatto — comune perche' ONVIF e' una cosa da
    # telecamere, non da telefoni/computer.
    model = None
    # "onvif" | "mdns" | None: da dove viene il campo "model", mostrato in
    # dashboard per distinguere un dato che il dispositivo ha dichiarato di
    # se stesso via protocollo strutturato (ONVIF GetDeviceInformation, o
    # il TXT "model=" di mDNS) da uno assente/indovinato altrove (OUI,
    # banner) — la stessa distinzione "detected vs inferred" gia' fatta
    # per RTSP/Admin URL, qui applicata al vendor/model.
    model_source = None
    if onvif_info and onvif_info.get("xaddrs"):
        info = get_device_info_multi(onvif_info["xaddrs"])
        if info.get("model"):
            model = info["model"]
            model_source = "onvif"
        if info.get("manufacturer"):
            device_vendor = info["manufacturer"]
            vendor_source = "onvif"
    if not model and mdns_info and mdns_info.get("model"):
        model = mdns_info["model"]
        model_source = "mdns"

    # Priorita': NVR e camera sono le classificazioni piu' specifiche e
    # affidabili (segnali di protocollo dedicati). Poi l'apparato di rete
    # (Router/Switch/Access Point, o generico se solo il vendor lo
    # suggerisce). Poi l'hardware riconosciuto dal vendor o dalle porte
    # tipiche (Raspberry Pi, PC, stampante). Altrimenti resta "Generico":
    # un dispositivo senza nessuno di questi segnali (comune su telefoni e
    # PC moderni con firewall di default) non espone nulla da leggere, e
    # non si va oltre con fingerprint attivo dello stack TCP/IP in stile
    # `nmap -O`.
    # "reasons" segue la STESSA priorita' usata per device_type qui sopra:
    # mostra solo i motivi del classificatore che ha vinto, mai un mix di
    # tutti e quattro. Un gateway con anche la porta 631 (IPP) aperta e'
    # comunque "Router" con motivo "e' il gateway di default": mischiare
    # dentro anche "porta tipica stampante" (segnale di un classificatore
    # perdente, non del tipo mostrato) confonderebbe chi legge il report,
    # anche se la classificazione finale resta corretta.
    if is_nvr:
        device_type = nvr_subtype
        reasons = nvr_reasons
    elif is_camera:
        device_type = "Camera"
        reasons = camera_reasons
    elif is_infra:
        device_type = infra_subtype or "Network device"
        reasons = infra_reasons
    elif host_label:
        device_type = host_label
        reasons = host_reasons
    else:
        device_type = "Generic"
        reasons = []

    return {
        "ip": ip,
        "mac": mac,
        "vendor": device_vendor,
        "vendor_source": vendor_source,
        "model": model,
        "model_source": model_source,
        "hostname": hostname,
        "snmp_info": snmp_info,
        "open_ports": open_ports,
        "http_banners": banners,
        "onvif": onvif_info,
        "mdns": mdns_info,
        "is_camera": is_camera or is_nvr,
        "is_nvr": is_nvr,
        "is_network_infra": is_infra,
        "device_type": device_type,
        "reasons": reasons,
        # Scomposizione completa per classificatore (debug/trasparenza):
        # NON usarla per mostrare "il motivo" di un device_type, usa
        # "reasons" sopra, gia' allineata al tipo mostrato.
        "classification_reasons": {
            "camera": camera_reasons,
            "nvr": nvr_reasons,
            "network": infra_reasons,
            "host": host_reasons,
        },
        "rtsp_url": guess_rtsp_url(ip, open_ports),
        "admin_url": guess_admin_url(ip, open_ports),
        "network_mismatch": False,
    }


ORPHAN_ONVIF_REASON = (
    "responds to ONVIF WS-Discovery, but its IP does not belong to any "
    "currently active network: likely a misconfigured static IP on the "
    "camera (e.g. left over from a previous installation)"
)


def _orphan_onvif_ips(onvif_results, known_ips):
    """IP che hanno risposto al probe ONVIF ma non sono stati trovati
    dall'ARP scan su nessuna rete attiva: il probe ONVIF e' multicast e non
    filtra per subnet come l'ARP scan (vedi discovery.arp.parse_arp_reply),
    quindi puo' ricevere risposta anche da una telecamera fisicamente
    collegata allo stesso segmento ma con un IP unicast "sbagliato" per la
    rete attuale — un caso che l'ARP scan da solo non potrebbe mai vedere.
    Estratta a parte per essere testabile senza rete reale.
    """
    return [ip for ip in onvif_results if ip not in known_ips]


def _match_active_network(ip, networks):
    """Ritorna (iface, cidr) della prima rete attiva a cui `ip` appartiene,
    o None se non rientra in nessuna. `networks`: stessa lista [(iface,
    cidr, local_ip), ...] usata per l'ARP scan."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for iface, cidr, _ in networks:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return iface, cidr
        except ValueError:
            continue
    return None


def _match_lldp_cdp_neighbor(mac, neighbors):
    """Se il chassis_id di un vicino LLDP/CDP visto su questa interfaccia
    coincide col MAC di questo device (confronto case-insensitive: LLDP
    formatta il MAC in minuscolo, il resto del progetto in maiuscolo),
    ritorna quel vicino — corrobora "questo e' davvero l'apparato visto
    via LLDP/CDP", non solo un IP/MAC scoperto via ARP. None se nessun
    vicino ha un chassis_id che sembra un MAC, o nessuno coincide."""
    if not mac:
        return None
    mac_upper = mac.upper()
    for neighbor in neighbors:
        chassis_id = neighbor.get("chassis_id")
        if chassis_id and chassis_id.upper() == mac_upper:
            return neighbor
    return None


def _classify_orphan_ips(orphan_ips, networks):
    """Un IP "orfano" (visto solo via ONVIF, mai dall'ARP scan) NON e'
    automaticamente "fuori rete": se rientra comunque in una subnet gia'
    attiva, l'ARP scan puo' semplicemente averlo mancato in questo giro
    (host lento a rispondere, porta switch STP che ritarda, pacchetto
    perso — casi gia' noti, vedi README) — non e' detto sia mal
    configurato. In quel caso va trattato come un host normale (mac
    ignoto), non etichettato erroneamente come "IP fuori rete": e'
    fisicamente indistinguibile da un device ARP-trovato una volta che ci
    proviamo a connettere via IP, quindi merita la stessa pipeline di port
    scan invece di restare un fantasma senza porte.

    Solo un IP che non appartiene a NESSUNA rete attiva e' strutturalmente
    non raggiungibile in unicast da qui: quello si' e' un probabile errore
    di configurazione IP sulla telecamera.

    Ritorna (in_range: list[(ip, iface, cidr)], out_of_range: list[ip]).
    """
    in_range = []
    out_of_range = []
    for ip in orphan_ips:
        match = _match_active_network(ip, networks)
        if match:
            iface, cidr = match
            in_range.append((ip, iface, cidr))
        else:
            out_of_range.append(ip)
    return in_range, out_of_range


def _build_orphan_onvif_device(ip, onvif_info, iface):
    """Device "fantasma": conosciamo solo cio' che il probe ONVIF ci ha
    detto (IP, XAddrs, eventuale vendor/model reali) — niente MAC (l'ARP
    non l'ha mai visto) ne' porte (non ha senso scansionarle: l'IP non e'
    raggiungibile in unicast su questa rete, e' arrivato solo il multicast).
    """
    xaddrs = onvif_info.get("xaddrs") or []
    model = None
    model_source = None
    device_vendor = "Unknown"
    vendor_source = None
    if xaddrs:
        info = get_device_info_multi(xaddrs)
        if info.get("model"):
            model = info["model"]
            model_source = "onvif"
        if info.get("manufacturer"):
            device_vendor = info["manufacturer"]
            vendor_source = "onvif"

    return {
        "ip": ip,
        "mac": None,
        "vendor": device_vendor,
        "vendor_source": vendor_source,
        "model": model,
        "model_source": model_source,
        "hostname": None,
        "snmp_info": {},
        "lldp_cdp_info": None,
        "open_ports": [],
        "http_banners": {},
        "onvif": onvif_info,
        "mdns": None,
        "is_camera": True,
        "is_nvr": False,
        "is_network_infra": False,
        "device_type": "Camera",
        "reasons": [ORPHAN_ONVIF_REASON],
        "classification_reasons": {
            "camera": [ORPHAN_ONVIF_REASON], "nvr": [], "network": [], "host": [],
        },
        "rtsp_url": None,
        "admin_url": None,
        "onvif_xaddr": xaddrs[0] if xaddrs else None,
        "network_mismatch": True,
        "iface": iface,
        "network": None,
        "vlan_id": None,
    }


def run_scan():
    # Check-then-set atomico sotto lo stesso lock: senza tenerlo per tutto
    # il blocco, due richieste /api/scan/start concorrenti potevano
    # entrambe leggere running=False prima che l'altra lo mettesse a True,
    # partendo entrambe (due scan paralleli che si accavallano sullo
    # stesso _state["devices"]). _update() non va chiamata qui dentro:
    # prende lo stesso lock e threading.Lock non e' rientrante, farebbe
    # deadlock — si scrive _state direttamente, gia' dentro il blocco.
    with _lock:
        if _state["running"]:
            return False, "Scan already in progress"
        networks = _active_networks()
        if not networks:
            return False, "No active network (eth/wifi) to scan"
        _stop_flag.clear()
        _state.update(running=True, progress=0, total=0, current_ip=None,
                       started_at=time.time(), finished_at=None, error=None, devices={})

    t = threading.Thread(target=_run_scan_thread, args=(networks,), daemon=True)
    t.start()
    return True, "Scan started"


def _run_scan_thread(networks):
    try:
        all_hosts = []  # (ip, mac, iface, cidr)
        onvif_results = {}
        mdns_results = {}
        gateways = {}
        topology = {}
        for iface, cidr, iface_ip in networks:
            if _stop_flag.is_set():
                break
            is_noarp_iface = network_setup.is_noarp(iface)
            if is_noarp_iface:
                # VPN instradata (WireGuard, OpenVPN tun, PPP...): niente
                # dominio di broadcast L2, l'ARP scan non riceverebbe mai
                # risposta indipendentemente da quanti host reali ci siano
                # (verificato: il kernel marca queste interfacce NOARP).
                log.info("discovery ICMP su %s (%s, interfaccia NOARP)", cidr, iface)
                hosts = icmp_scan(cidr, iface, psrc=iface_ip)
            else:
                log.info("discovery ARP su %s (%s)", cidr, iface)
                hosts = arp_scan(cidr, iface, psrc=iface_ip)
            seen_ips = set()
            for h in hosts:
                # vlan_id: solo arp_scan lo popola (802.1Q, vedi
                # scanner.discovery.arp.extract_vlan_id); icmp_scan (link
                # NOARP/VPN) non ha un concetto di VLAN a questo livello,
                # .get() con default None copre entrambi i casi.
                all_hosts.append((h["ip"], h["mac"], iface, cidr, h.get("vlan_id")))
                seen_ips.add(h["ip"])
            if iface_ip not in seen_ips:
                # Un host non riceve mai la propria richiesta ARP broadcast
                # di ritorno: senza questo, la macchina su cui gira lo
                # scanner non comparirebbe mai da sola nei risultati.
                all_hosts.append((iface_ip, network_setup.get_interface_mac(iface), iface, cidr, None))

            # ONVIF, mDNS e LLDP/CDP sono probe indipendenti: in thread
            # separati invece che in sequenza, cosi' la loro attesa (3s +
            # 2.5s + 3s) si sovrappone invece di sommarsi per ogni rete
            # attiva. LLDP/CDP e' puro ascolto passivo (nessuna richiesta
            # da mandare, gli apparati trasmettono da soli ogni ~30-60s):
            # skippato sulle interfacce NOARP per lo stesso motivo
            # dell'ARP scan (nessun dominio di broadcast L2 su cui
            # ascoltare annunci L2).
            onvif_partial, mdns_partial, lldp_cdp_neighbors = {}, {}, []
            t_onvif = threading.Thread(target=lambda: onvif_partial.update(onvif_probe(iface_ip=iface_ip, timeout=3)))
            # reverse_ips=seen_ips: query PTR inversa per gli host gia'
            # trovati da ARP/ICMP su questa rete, oltre alle query per i
            # servizi comuni — da' l'hostname reale anche per device che
            # non espongono nessuno dei servizi interrogati di default.
            t_mdns = threading.Thread(
                target=lambda: mdns_partial.update(
                    mdns_probe(iface_ip=iface_ip, timeout=2.5, reverse_ips=seen_ips)
                )
            )
            threads = [t_onvif, t_mdns]
            if not is_noarp_iface:
                t_lldp_cdp = threading.Thread(target=lambda: lldp_cdp_neighbors.extend(lldp_cdp_probe(iface, timeout=3)))
                threads.append(t_lldp_cdp)
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            for onvif_ip, info in onvif_partial.items():
                onvif_results[onvif_ip] = {**info, "_iface": iface}
            mdns_results.update(mdns_partial)

            if iface not in gateways:
                gateways[iface] = get_default_gateway(iface)

            # Topologia (P4): un salto solo, per interfaccia — chi e' il
            # gateway, e quali vicini LLDP/CDP sono stati visti (se il
            # timing di trasmissione dell'apparato ha coinciso con la
            # finestra di ascolto: un elenco vuoto NON significa "nessun
            # apparato LLDP/CDP-capable presente", vedi discovery.lldp_cdp).
            topology[iface] = {
                "cidr": cidr, "gateway": gateways[iface], "neighbors": lldp_cdp_neighbors,
            }
        _update(topology=topology)

        known_ips = {h[0] for h in all_hosts}
        orphan_ips = _orphan_onvif_ips(onvif_results, known_ips)
        in_range_orphans, out_of_range_ips = _classify_orphan_ips(orphan_ips, networks)
        # In-range: probabile solo un miss dell'ARP sweep, non un IP mal
        # configurato — trattalo come un host normale (mac ignoto, ma
        # port scan/classificazione completi), non come un fantasma.
        for ip, iface, cidr in in_range_orphans:
            all_hosts.append((ip, None, iface, cidr, None))

        total = len(all_hosts) + len(out_of_range_ips)
        _update(total=total)

        for idx, (ip, mac, iface, cidr, vlan_id) in enumerate(all_hosts):
            if _stop_flag.is_set():
                break
            _update(progress=idx, current_ip=ip)
            device = _scan_host(ip, mac, onvif_results, mdns_results, gateways.get(iface))
            device["iface"] = iface
            device["network"] = cidr
            device["vlan_id"] = vlan_id
            device["lldp_cdp_info"] = _match_lldp_cdp_neighbor(mac, topology.get(iface, {}).get("neighbors", []))
            _set_device(ip, device)

        for idx, ip in enumerate(out_of_range_ips):
            if _stop_flag.is_set():
                break
            _update(progress=len(all_hosts) + idx, current_ip=ip)
            onvif_info = onvif_results[ip]
            device = _build_orphan_onvif_device(ip, onvif_info, onvif_info.get("_iface"))
            _set_device(ip, device)

        _update(progress=total, current_ip=None)
    except Exception as exc:  # non deve mai morire silenziosamente in un thread
        log.exception("errore durante lo scan")
        _update(error=str(exc))
    finally:
        _update(running=False, finished_at=time.time())
        # Storico (P4): salvato anche per uno scan fermato a meta' o
        # terminato con errore — e' comunque un'istantanea reale di cosa
        # e' stato trovato, utile per l'asset database anche se
        # incompleta. Un fallimento qui (disco pieno, permessi) non deve
        # mai far sembrare fallito lo scan appena completato.
        try:
            state = get_state()
            scan_id = storage.save_scan(state["devices"], state["started_at"], state["finished_at"])
            webhooks.notify_scan_complete({
                "scan_id": scan_id,
                "started_at": state["started_at"],
                "finished_at": state["finished_at"],
                "device_count": len(state["devices"]),
                "camera_count": sum(1 for d in state["devices"] if d.get("is_camera")),
            })
        except Exception:
            log.exception("salvataggio storico scan fallito (non bloccante)")


def stop_scan():
    _stop_flag.set()


def devices_all():
    with _lock:
        return list(_state["devices"].values())


def devices_cameras():
    return [d for d in devices_all() if d.get("is_camera")]
