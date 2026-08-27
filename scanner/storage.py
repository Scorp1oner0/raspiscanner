"""Storico degli scan (SQLite, stdlib — nessuna nuova dipendenza) per
asset database, report comparativi e dashboard storica (P4).

Ogni scan completato viene salvato come "snapshot": una riga in `scans`
(metadati) + una riga per device in `scan_devices` (l'intero device dict,
serializzato JSON — non serve uno schema relazionale completo per dati
che vengono letti per intero, non interrogati campo per campo nel motore
di scan). La tabella `assets` traccia ogni MAC visto ALMENO una volta
attraverso scan diversi, con first_seen/last_seen: e' l'"asset database
locale" richiesto — un device senza MAC (link VPN/NOARP, o orfano ONVIF)
non puo' essere tracciato in modo affidabile nel tempo (il suo IP puo'
cambiare senza che sia lo stesso host fisico, o viceversa), quindi resta
fuori dall'asset tracking pur comparendo nello snapshot dello scan.

File a data/history.db: stesso trattamento di data/users.json/tls_*.pem
(mai committato, escluso dal `rsync --delete` di install.sh).
"""
import json
import logging
import sqlite3
import time
from contextlib import closing

from . import config

log = logging.getLogger("raspiscanner.storage")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at REAL,
    finished_at REAL,
    device_count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_devices (
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    ip TEXT NOT NULL,
    mac TEXT,
    vendor TEXT,
    device_type TEXT,
    is_camera INTEGER NOT NULL,
    is_nvr INTEGER NOT NULL,
    network TEXT,
    data_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scan_devices_scan_id ON scan_devices(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_devices_mac ON scan_devices(mac);
CREATE TABLE IF NOT EXISTS assets (
    mac TEXT PRIMARY KEY,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    last_ip TEXT,
    last_vendor TEXT,
    last_device_type TEXT,
    times_seen INTEGER NOT NULL DEFAULT 1
);
"""

# Campi confrontati da compare_scans() per decidere se un asset e'
# "cambiato" tra due scan: solo quelli che contano davvero per un
# tecnico (un open_ports diverso o un vendor diverso e' rilevante, un
# hostname mai risolto vs risolto stavolta e' rumore quasi sempre).
_COMPARE_FIELDS = ("ip", "vendor", "model", "device_type", "open_ports")


def _connect():
    conn = sqlite3.connect(config.HISTORY_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    return conn


def save_scan(devices, started_at, finished_at):
    """Salva uno snapshot completo dello scan e aggiorna l'asset
    database. Ritorna l'id dello scan salvato. Un device senza MAC
    aggiorna comunque scan_devices (fa parte dello snapshot) ma non
    assets (non tracciabile in modo affidabile nel tempo)."""
    now = time.time()
    with closing(_connect()) as conn:
        with conn:
            cur = conn.execute(
                "INSERT INTO scans (started_at, finished_at, device_count) VALUES (?, ?, ?)",
                (started_at, finished_at, len(devices)),
            )
            scan_id = cur.lastrowid
            for d in devices:
                conn.execute(
                    "INSERT INTO scan_devices "
                    "(scan_id, ip, mac, vendor, device_type, is_camera, is_nvr, network, data_json) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (scan_id, d.get("ip"), d.get("mac"), d.get("vendor"), d.get("device_type"),
                     int(bool(d.get("is_camera"))), int(bool(d.get("is_nvr"))), d.get("network"),
                     json.dumps(d, ensure_ascii=False)),
                )
                mac = d.get("mac")
                if not mac:
                    continue
                existing = conn.execute("SELECT mac FROM assets WHERE mac = ?", (mac,)).fetchone()
                if existing:
                    conn.execute(
                        "UPDATE assets SET last_seen=?, last_ip=?, last_vendor=?, "
                        "last_device_type=?, times_seen=times_seen+1 WHERE mac=?",
                        (now, d.get("ip"), d.get("vendor"), d.get("device_type"), mac),
                    )
                else:
                    conn.execute(
                        "INSERT INTO assets "
                        "(mac, first_seen, last_seen, last_ip, last_vendor, last_device_type, times_seen) "
                        "VALUES (?, ?, ?, ?, ?, ?, 1)",
                        (mac, now, now, d.get("ip"), d.get("vendor"), d.get("device_type")),
                    )
    return scan_id


def list_scans(limit=20):
    """Scan piu' recenti prima, senza i device (solo metadati) — per la
    lista nella dashboard storica."""
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT id, started_at, finished_at, device_count FROM scans ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_scan_devices(scan_id):
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT data_json FROM scan_devices WHERE scan_id = ?", (scan_id,),
        ).fetchall()
    return [json.loads(r["data_json"]) for r in rows]


def list_assets(limit=500):
    """Asset noti (con MAC), ultimo visto per primo."""
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT * FROM assets ORDER BY last_seen DESC LIMIT ?", (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def compare_scans(old_scan_id, new_scan_id):
    """Confronta due scan per MAC: i device senza MAC non sono
    confrontabili in modo affidabile (il loro IP puo' cambiare senza
    essere lo stesso host, o viceversa) e sono esclusi dal confronto.
    Ritorna {"added": [device...], "removed": [device...],
    "changed": [{"mac", "old", "new", "fields": [...]}]}.
    """
    old_devices = {d["mac"]: d for d in get_scan_devices(old_scan_id) if d.get("mac")}
    new_devices = {d["mac"]: d for d in get_scan_devices(new_scan_id) if d.get("mac")}

    added = [d for mac, d in new_devices.items() if mac not in old_devices]
    removed = [d for mac, d in old_devices.items() if mac not in new_devices]

    changed = []
    for mac in sorted(set(old_devices) & set(new_devices)):
        old_d, new_d = old_devices[mac], new_devices[mac]
        changed_fields = [f for f in _COMPARE_FIELDS if old_d.get(f) != new_d.get(f)]
        if changed_fields:
            changed.append({"mac": mac, "old": old_d, "new": new_d, "fields": changed_fields})

    return {"added": added, "removed": removed, "changed": changed}
