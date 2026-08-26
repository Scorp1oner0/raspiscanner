#!/usr/bin/env python3
"""Updates data/oui.csv by downloading the official IEEE registry.

Run on a machine WITH internet access (e.g. in the lab, before taking the
Raspberry Pi to the field). The resulting file replaces the much smaller
one shipped in the repo.

Usage (from the repo root):
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

# IEEE blocks (HTTP 418) requests with urllib's generic User-Agent
# ("Python-urllib/x.y"), flagged as bot traffic. A normal browser
# User-Agent is enough to get through.
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


def main():
    print(f"Downloading {SOURCE_URL} ...")
    req = urllib.request.Request(SOURCE_URL, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except Exception as exc:  # network unavailable, host unreachable, blocked, etc.
        print(f"Download failed: {exc}", file=sys.stderr)
        print(
            f"You can also download the CSV by hand from {SOURCE_URL} "
            f"and save it as {OUI_CSV_PATH}.",
            file=sys.stderr,
        )
        sys.exit(1)

    reader = csv.reader(io.StringIO(raw))
    next(reader, None)  # header row
    rows = []
    for row in reader:
        # IEEE format: Registry,Assignment,Organization Name,Organization Address
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

    print(f"Wrote {len(rows)} prefixes to {OUI_CSV_PATH}")


if __name__ == "__main__":
    main()
