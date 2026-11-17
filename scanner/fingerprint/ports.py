"""Port scan TCP leggero e fingerprint HTTP minimale su un host."""
import http.client
import logging
import socket
import ssl
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
                log.exception("port check %s:%s failed unexpectedly", ip, port)
                is_open = False
            if is_open:
                open_ports.append({"port": port, "service": ports[port]})
    return sorted(open_ports, key=lambda p: p["port"])


def open_tcp_ports(ip, ports, timeout=config.PORT_SCAN_TIMEOUT, threads=config.DEEP_SCAN_THREADS,
                   batch=config.DEEP_SCAN_BATCH, should_stop=None, on_progress=None):
    """Controlla `ports` (lista di interi) a blocchi e ritorna quelle aperte,
    ordinate. Pensata per lo scan approfondito: `on_progress(fatte)` viene
    chiamata dopo ogni blocco e `should_stop()` permette di interrompere tra
    un blocco e l'altro. Lo stesso lavoro in un solo pool terrebbe in memoria
    fino a 65535 attese contemporanee."""
    found = []
    done = 0
    with ThreadPoolExecutor(max_workers=max(1, min(threads, len(ports)))) as pool:
        for start in range(0, len(ports), batch):
            if should_stop and should_stop():
                break
            chunk = ports[start:start + batch]
            for port, is_open in zip(chunk, pool.map(lambda p: _check_port(ip, p, timeout), chunk)):
                if is_open:
                    found.append(port)
            done += len(chunk)
            if on_progress:
                on_progress(done)
    return sorted(found)


def web_banner(ip, port, timeout=1.5):
    """Banner di una porta web: HTTP o HTTPS secondo la porta. Per le porte
    alternative senza uno schema fisso prova HTTP e poi HTTPS. Ritorna il
    dict di grab_http_banner, con server e title a None se non risponde
    come un servizio web."""
    if port in config.HTTPS_BANNER_PORTS:
        return grab_http_banner(ip, port, timeout, use_https=True)
    if port in config.HTTP_BANNER_PORTS:
        return grab_http_banner(ip, port, timeout)
    banner = grab_http_banner(ip, port, timeout)
    if banner["server"] or banner["title"]:
        return banner
    return grab_http_banner(ip, port, timeout, use_https=True)


def grab_http_banner(ip, port, timeout=1.5, use_https=False):
    """Recupera Server header e <title> best-effort da un servizio HTTP."""
    try:
        if use_https:
            # Telecamere, NVR, router e Pi-hole usano quasi sempre un
            # certificato auto-firmato: verificandolo la connessione falliva e
            # il banner HTTPS restava sempre vuoto. Qui si legge solo una
            # pagina, senza mandare credenziali: la verifica non serve.
            conn = http.client.HTTPSConnection(ip, port, timeout=timeout,
                                               context=ssl._create_unverified_context())
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
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
