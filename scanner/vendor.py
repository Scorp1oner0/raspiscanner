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


def _load():
    global _loaded
    _oui_table.clear()
    if os.path.exists(config.OUI_CSV_PATH):
        with open(config.OUI_CSV_PATH, newline="", encoding="utf-8") as fh:
            for row in csv.reader(fh):
                if not row or row[0].startswith("#"):
                    continue
                if len(row) < 2:
                    continue
                prefix = _normalize_prefix(row[0])
                vendor = row[1].strip()
                if len(prefix) == 6 and vendor:
                    _oui_table[prefix] = vendor
    else:
        log.warning("database OUI non trovato: %s", config.OUI_CSV_PATH)
    _loaded = True
    log.info("database OUI caricato: %d prefissi", len(_oui_table))


def lookup_vendor(mac):
    if not _loaded:
        _load()
    prefix = _normalize_prefix(mac)
    return _oui_table.get(prefix, "Sconosciuto")


def reload():
    _load()
