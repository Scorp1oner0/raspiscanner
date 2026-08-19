"""Port scan TCP leggero e fingerprint HTTP minimale su un host."""
import http.client
import logging
import socket
from concurrent.futures import ThreadPoolExecutor

from . import config

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
    with ThreadPoolExecutor(max_workers=min(len(ports), 16)) as pool:
        futures = {pool.submit(_check_port, ip, p, timeout): p for p in ports}
        for fut in futures:
            port = futures[fut]
            if fut.result():
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
