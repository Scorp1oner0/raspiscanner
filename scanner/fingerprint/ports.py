"""Port scan TCP leggero e fingerprint HTTP minimale su un host."""
import http.client
import logging
import socket
from concurrent.futures import ThreadPoolExecutor

from .. import config

log = logging.getLogger("raspiscanner.portscan")


def _check_port(ip, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, port)) == 0
    except OSError:
        return False


def scan_ports(ip, ports=None, timeout=config.PORT_SCAN_TIMEOUT):
    """Ritorna la lista delle porte aperte tra quelle indicate, con etichetta."""
    ports = ports or config.PORTS_OF_INTEREST
    open_ports = []
    # Bug reale (P3, performance): config.PORT_SCAN_THREADS esisteva ma non
    # veniva mai letta, il pool restava fisso a 16 worker a prescindere. Con
    # la lista di default (22 porte) questo significava DUE round da
    # PORT_SCAN_TIMEOUT invece di uno solo per ogni host — su una rete
    # grande (es. /16) il costo si moltiplica per il numero di host.
    with ThreadPoolExecutor(max_workers=min(len(ports), config.PORT_SCAN_THREADS)) as pool:
        futures = {pool.submit(_check_port, ip, p, timeout): p for p in ports}
        for fut in futures:
            port = futures[fut]
            try:
                is_open = fut.result()
            except Exception:
                # _check_port intercetta gia' OSError al suo interno: questo
                # e' un ulteriore livello di sicurezza per qualunque altro
                # errore inatteso in un singolo controllo di porta, che non
                # deve far perdere il risultato delle altre porte dello
                # stesso host (ne' l'intero host scan).
                log.exception("controllo porta %s:%s fallito inaspettatamente", ip, port)
                is_open = False
            if is_open:
                open_ports.append({"port": port, "service": ports[port]})
    return sorted(open_ports, key=lambda p: p["port"])


def grab_http_banner(ip, port, timeout=1.5, use_https=False):
    """Recupera Server header e <title> best-effort da un servizio HTTP."""
    conn_cls = http.client.HTTPSConnection if use_https else http.client.HTTPConnection
    try:
        conn = conn_cls(ip, port, timeout=timeout)
        conn.request("GET", "/", headers={"User-Agent": "raspiscanner"})
        resp = conn.getresponse()
        server = resp.getheader("Server", "")
        body = resp.read(2048).decode("utf-8", errors="ignore")
        conn.close()
        title = None
        low = body.lower()
        if "<title>" in low:
            start = low.index("<title>") + len("<title>")
            end = low.find("</title>", start)
            if end != -1:
                title = body[start:end].strip()
        return {"server": server or None, "title": title}
    except Exception:
        return {"server": None, "title": None}
