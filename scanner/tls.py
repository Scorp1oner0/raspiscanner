"""Certificato TLS self-signed per la dashboard.

RaspiScanner gira su un Raspberry Pi o un PC Linux qualunque, installato
di volta in volta su reti private diverse (spesso senza uscita internet
durante il sopralluogo) e raggiunto per IP, non per dominio: non esiste
una CA pubblica (Let's Encrypt e simili) che possa emettere o rinnovare
un certificato in queste condizioni, ne' avrebbe senso per un IP privato
che cambia a ogni installazione.

Un certificato self-signed generato dal dispositivo stesso resta la
soluzione standard per questa categoria (lo stesso approccio di router,
NAS, stampanti di rete per il proprio pannello di amministrazione): il
browser mostra un avviso "connessione non sicura" da accettare una volta,
ma il traffico e' comunque cifrato contro chi sniffa passivamente la
stessa rete — il vero rischio concreto per una Basic Auth su HTTP
semplice.

Generato una sola volta con `openssl` (gia' presente su qualunque
distribuzione Linux, niente nuova dipendenza pip, coerente con come il
resto del progetto usa `ip`/`dhclient`/`nmcli` da riga di comando) e
persistito in data/, cosi' l'avviso del browser non ricompare a ogni
riavvio del servizio.
"""
import logging
import os
import subprocess

from . import config

log = logging.getLogger("raspiscanner.tls")

CERT_DAYS = 3650  # ~10 anni: nessun rinnovo automatico possibile offline


def ensure_cert():
    """Ritorna (cert_path, key_path), generandoli con openssl se mancanti.

    Ritorna (None, None) se openssl non e' disponibile o la generazione
    fallisce: il chiamante deve ripiegare su HTTP semplice invece di non
    avviarsi, dato che TLS qui e' un miglioramento best-effort, non un
    requisito per il funzionamento dello scanner.
    """
    cert_path = config.TLS_CERT_PATH
    key_path = config.TLS_KEY_PATH
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path

    os.makedirs(config.DATA_DIR, exist_ok=True)
    try:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-sha256", "-days", str(CERT_DAYS), "-nodes",
                "-keyout", key_path, "-out", cert_path,
                "-subj", "/CN=raspiscanner.local",
            ],
            check=True, capture_output=True, text=True, timeout=30,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as exc:
        log.warning("generazione certificato TLS fallita (openssl assente o errore?): %s", exc)
        return None, None

    os.chmod(key_path, 0o600)
    log.info("certificato TLS self-signed generato: %s", cert_path)
    return cert_path, key_path
