"""Lookup del vendor a partire dal prefisso OUI del MAC address.

Usa un CSV locale (data/oui.csv, formato "PREFISSO,Vendor") cosi' funziona
anche senza connessione internet sul campo. Il file incluso nel repo e' una
lista ridotta e "best effort" dei vendor piu' comuni (reti, IoT, telecamere
IP). Per un database completo e aggiornato, lanciare update_oui.py da una
macchina con accesso a internet (scarica il registro ufficiale IEEE) e
copiare il risultato in data/oui.csv.
"""
import csv
import logging
import os

from . import config

log = logging.getLogger("raspiscanner.vendor")

_oui_table = {}
_loaded = False


def _normalize_prefix(mac_or_prefix):
    hexonly = "".join(c for c in mac_or_prefix.upper() if c in "0123456789ABCDEF")
    return hexonly[:6]


def _read_csv_into(path, table):
    """Carica un CSV "PREFISSO,Vendor" dentro `table`. Ritorna il numero di
    voci lette, 0 se il file non c'e'."""
    if not os.path.exists(path):
        return 0
    n = 0
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if not row or row[0].startswith("#") or len(row) < 2:
                continue
            prefix = _normalize_prefix(row[0])
            vendor = row[1].strip()
            if len(prefix) == 6 and vendor:
                table[prefix] = vendor
                n += 1
    return n


def _load():
    """Carica il database OUI da due file, in quest'ordine:

    1. `data/oui_full.csv` — registro IEEE completo (~40.000 voci) scaricato
       da `scripts/update_oui.py`, non tracciato da git. Da' la copertura.
    2. `data/oui.csv` — lista curata inclusa nel repo (~100 vendor comuni),
       caricata DOPO cosi' i suoi nomi hanno la precedenza: sono corti e
       leggibili ("Hikvision") dove l'IEEE e' verboso ("Hangzhou Hikvision
       Digital Technology Co.,Ltd."). Meglio in un report da leggere sul
       campo, e garantisce lo stesso risultato con o senza il DB completo.
    """
    global _loaded
    _oui_table.clear()
    n_full = _read_csv_into(config.OUI_FULL_CSV_PATH, _oui_table)
    n_min = _read_csv_into(config.OUI_CSV_PATH, _oui_table)
    if not n_full and not n_min:
        log.warning("no OUI database found (%s, %s)",
                    config.OUI_FULL_CSV_PATH, config.OUI_CSV_PATH)
    _loaded = True
    log.info("OUI database loaded: %d prefixes (%d from the full IEEE "
             "registry, %d from the curated list)", len(_oui_table), n_full, n_min)


def lookup_vendor(mac):
    if not _loaded:
        _load()
    prefix = _normalize_prefix(mac)
    return _oui_table.get(prefix, "Unknown")


def reload():
    _load()
