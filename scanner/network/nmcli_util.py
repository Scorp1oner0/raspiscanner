"""Parsing robusto dell'output "terse" (-t) di nmcli, condiviso tra
scanner.network.setup (scan/connessione Wi-Fi) e scanner.network.hotspot.

nmcli in modalita' terse separa i campi con ":" ed esegue l'escape di ogni
":" o "\\" letterale DENTRO un valore (es. un SSID che contiene ":")
facendoli precedere da "\\". Uno split ingenuo su ":" (senza rispettare
l'escape) spezza in punti sbagliati un valore che contiene ":" — bug reale
per un SSID come "Guest:Wifi", che finiva troncato e disallineava anche i
campi successivi sulla stessa riga (segnale/sicurezza scambiati).
"""


def split_nmcli_terse(line, n_fields):
    """Divide una riga di output nmcli -t in ESATTAMENTE n_fields campi,
    rispettando l'escape "\\:" / "\\\\" usato da nmcli per i valori.

    Non solleva mai un'eccezione su output inatteso/malformato (righe con
    meno separatori del previsto): i campi mancanti sono restituiti come
    stringa vuota, cosi' una singola riga anomala non manda in crash
    l'intero parsing invece di limitarsi a un valore vuoto per quel campo.
    """
    fields = []
    current = []
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and i + 1 < len(line) and line[i + 1] in (":", "\\"):
            current.append(line[i + 1])
            i += 2
            continue
        if ch == ":" and len(fields) < n_fields - 1:
            fields.append("".join(current))
            current = []
            i += 1
            continue
        current.append(ch)
        i += 1
    fields.append("".join(current))
    while len(fields) < n_fields:
        fields.append("")
    return fields
