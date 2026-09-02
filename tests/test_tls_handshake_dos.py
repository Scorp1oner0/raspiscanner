"""Una stretta di mano TLS mai completata non deve bloccare la dashboard.

Regressione del 27/08/2026: la dashboard e' rimasta in stallo 5 giorni e 22
ore. Causa: werkzeug avvolge il socket IN ASCOLTO con TLS, quindi la stretta
di mano avviene dentro accept(), nel thread principale; un client che apre il
TCP e non parla blocca l'accettazione di ogni connessione successiva.

Questi test aprono una connessione "muta" e verificano che il server continui
a servire chiunque altro.
"""
import socket
import ssl
import threading
import time

import pytest

pytest.importorskip("flask")
pytest.importorskip("werkzeug")

from scanner import tls as tls_mod  # noqa: E402


@pytest.fixture(scope="module")
def server():
    """Avvia la dashboard reale (solo una rotta di prova) su una porta libera."""
    from flask import Flask
    import importlib

    rs = importlib.import_module("raspi-scanner".replace("-", "_")) \
        if False else None  # il modulo ha un trattino: importiamo la classe a mano

    # Ricostruiamo la stessa classe usata in produzione, importandola dal file.
    import importlib.util
    import pathlib
    path = pathlib.Path(__file__).resolve().parent.parent / "raspi-scanner.py"
    spec = importlib.util.spec_from_file_location("raspi_scanner_mod", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    cert, key = tls_mod.ensure_cert()
    if not cert:
        pytest.skip("nessun certificato TLS generabile in questo ambiente")

    app = Flask(__name__)

    @app.route("/ping")
    def ping():
        return "pong"

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv = mod._LateTLSServer("127.0.0.1", 0, app, ctx)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.3)
    yield port
    srv.shutdown()
    srv.server_close()


def _get(port, timeout=5):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw) as s:
            s.settimeout(timeout)
            s.sendall(b"GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            # Legge fino alla chiusura: un solo recv() restituirebbe i soli
            # header, senza il corpo.
            chunks = []
            while True:
                b = s.recv(4096)
                if not b:
                    break
                chunks.append(b)
            return b"".join(chunks)


def test_serve_normally(server):
    assert b"pong" in _get(server)


def test_muted_client_does_not_block_the_server(server):
    """IL test di regressione: una connessione TCP aperta e muta (esattamente
    quello che fa un port scanner) non deve impedire le richieste successive.
    Prima della correzione questa asserzione andava in timeout per sempre.
    """
    mute = socket.create_connection(("127.0.0.1", server), timeout=5)
    try:
        time.sleep(0.4)                      # il server sta aspettando l'handshake
        assert b"pong" in _get(server), "il server e' bloccato dalla connessione muta"
    finally:
        mute.close()


def test_many_muted_clients_do_not_block_the_server(server):
    """Anche una raffica di connessioni mute — uno scan di rete completo —
    non deve degradare il servizio."""
    mutes = [socket.create_connection(("127.0.0.1", server), timeout=5)
             for _ in range(15)]
    try:
        time.sleep(0.5)
        assert b"pong" in _get(server)
    finally:
        for m in mutes:
            m.close()


def test_half_open_tls_is_dropped_and_server_survives(server):
    """Client che manda un ClientHello parziale e si ferma: il server lo
    scarta dopo il timeout e continua a servire."""
    half = socket.create_connection(("127.0.0.1", server), timeout=5)
    try:
        half.sendall(b"\x16\x03\x01\x00\x2f\x01")   # ClientHello troncato
        time.sleep(0.4)
        assert b"pong" in _get(server)
    finally:
        half.close()
