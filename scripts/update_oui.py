#!/usr/bin/env python3
"""Aggiorna data/oui.csv scaricando il registro ufficiale IEEE.

Da lanciare su una macchina CON accesso a internet (es. in laboratorio,
prima di portare il Raspberry sul campo). Il file prodotto sostituisce
quello incluso nel repo, molto piu' ridotto.

Uso (dalla radice del repo):
    python3 scripts/update_oui.py
"""
import csv
import io
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.config import OUI_CSV_PATH

SOURCE_URL = "https://standards-oui.ieee.org/oui/oui.csv"

# IEEE blocca (HTTP 418) le richieste con lo User-Agent generico di
# urllib ("Python-urllib/x.y"), riconosciuto come traffico da bot. Un
# User-Agent da browser normale basta a farla passare.
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


def main():
    print(f"Scarico {SOURCE_URL} ...")
    req = urllib.request.Request(SOURCE_URL, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except Exception as exc:  # rete non disponibile, host irraggiungibile, bloccato, ecc.
        print(f"Download fallito: {exc}", file=sys.stderr)
        print(
            "Puoi anche scaricare il CSV a mano da "
            f"{SOURCE_URL} e salvarlo come {OUI_CSV_PATH}.",
            file=sys.stderr,
        )
        sys.exit(1)

    reader = csv.reader(io.StringIO(raw))
    next(reader, None)  # intestazione
    rows = []
    for row in reader:
        # formato IEEE: Registry,Assignment,Organization Name,Organization Address
        if len(row) < 3:
            continue
        prefix = row[1].strip().upper()
        vendor = row[2].strip()
        if len(prefix) == 6 and vendor:
            rows.append((prefix, vendor))

    with open(OUI_CSV_PATH, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        for prefix, vendor in rows:
            writer.writerow([prefix, vendor])

    print(f"Scritti {len(rows)} prefissi in {OUI_CSV_PATH}")


if __name__ == "__main__":
    main()
