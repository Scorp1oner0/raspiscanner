"""Scan target networks: separa esplicitamente due concetti che prima
coincidevano implicitamente in un solo meccanismo (`scan_engine._active_networks()`,
che resta INVARIATA e continua a leggere solo le interfacce attive):

- **Network bootstrap/fallback** (`scanner.network.setup`): su quale rete
  configurare l'INDIRIZZO DEL RASPBERRY quando il DHCP non risponde. Non
  cambia nulla qui.
- **Scan targets** (questo modulo): quali reti l'operatore vuole
  effettivamente ANALIZZARE. Di default coincidono con le reti attive
  sulle interfacce (`auto_interfaces: true`, comportamento pre-esistente,
  invariato per chi non tocca questa configurazione) — ma un operatore
  puo' anche aggiungere reti extra (`custom`) che il Raspberry non ha
  come proprio indirizzo su nessuna interfaccia.

Una rete custom che il Raspberry NON ha come proprio indirizzo su
nessuna interfaccia non e' raggiungibile via ARP (limite di protocollo:
l'ARP non attraversa un router, vedi README "What it doesn't do") — viene
scansionata via ICMP sweep instradato dal kernel, esattamente come gia'
avviene oggi per le VPN NOARP: niente MAC/vendor, solo IP raggiungibili.
Vedi `scan_engine._routed_target_networks()`.
"""
import ipaddress
import json
import logging
import os

from . import config

log = logging.getLogger("raspiscanner.targets")

DEFAULT_CONFIG = {"auto_interfaces": True, "custom": []}


def _load():
    if not os.path.exists(config.TARGETS_JSON_PATH):
        return dict(DEFAULT_CONFIG)
    try:
        with open(config.TARGETS_JSON_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        log.exception("lettura configurazione scan targets fallita")
        return dict(DEFAULT_CONFIG)
    custom = data.get("custom")
    return {
        "auto_interfaces": bool(data.get("auto_interfaces", True)),
        "custom": list(custom) if isinstance(custom, list) else [],
    }


def _save(auto_interfaces, custom):
    os.makedirs(config.DATA_DIR, exist_ok=True)
    tmp_path = config.TARGETS_JSON_PATH + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump({"auto_interfaces": auto_interfaces, "custom": custom}, fh, indent=2)
    os.replace(tmp_path, config.TARGETS_JSON_PATH)


def get_config():
    """{'auto_interfaces': bool, 'custom': ['192.168.20.0/24', ...]}."""
    return _load()


def _normalize_cidr(raw):
    """Valida e normalizza un CIDR IPv4 (es. "192.168.20.5/24" ->
    "192.168.20.0/24", host bits azzerati — un operatore che digita
    l'indirizzo di un host invece della rete non deve ottenere uno scan
    silenziosamente vuoto/sbagliato). Ritorna None se non valido."""
    try:
        return str(ipaddress.ip_network(raw.strip(), strict=False))
    except (ValueError, AttributeError):
        return None


def set_config(auto_interfaces, custom):
    """`custom`: lista di stringhe CIDR IPv4. Ritorna (ok, messaggio) —
    rifiuta l'intera lista se anche solo un CIDR non e' valido, invece di
    salvarne silenziosamente solo una parte."""
    normalized = []
    for raw in (custom or []):
        cidr = _normalize_cidr(raw)
        if cidr is None:
            return False, f"Invalid network: {raw!r}"
        if cidr not in normalized:
            normalized.append(cidr)
    _save(bool(auto_interfaces), normalized)
    log.info(
        "configurazione scan targets aggiornata: auto_interfaces=%s custom=%s",
        bool(auto_interfaces), normalized,
    )
    return True, "Scan targets saved"
