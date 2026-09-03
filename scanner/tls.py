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

Generato una sola volta e persistito in data/, cosi' l'avviso del browser
non ricompare a ogni riavvio del servizio. Due strade, nell'ordine:

1. `openssl` da riga di comando — gia' presente su qualunque distribuzione
   Linux, coerente con come il resto del progetto usa `ip`/`dhclient`/
   `nmcli`. Resta la prima scelta e il percorso invariato su Raspberry Pi.
2. la libreria `cryptography` (pure-Python) come ripiego quando `openssl`
   non c'e' nel PATH — il caso tipico di Windows, dove installarlo a mano
   sarebbe un attrito in piu' sul portatile del tecnico. Import opzionale:
   se manca anche quella si torna al comportamento storico (None, None) e
   il chiamante decide.
"""
import datetime
import ipaddress
import logging
import os
import subprocess

from . import config

log = logging.getLogger("raspiscanner.tls")

CERT_DAYS = 3650  # ~10 anni: nessun rinnovo automatico possibile offline

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    _CRYPTOGRAPHY_AVAILABLE = True
except ImportError:  # pragma: no cover - dipende dall'ambiente
    _CRYPTOGRAPHY_AVAILABLE = False


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
        log.warning("openssl non utilizzabile (%s), provo la libreria cryptography", exc)
        if not _generate_with_cryptography(cert_path, key_path):
            log.warning("generazione certificato TLS fallita: ne' openssl ne' cryptography disponibili")
            return None, None

    os.chmod(key_path, 0o600)
    log.info("certificato TLS self-signed generato: %s", cert_path)
    return cert_path, key_path


def _generate_with_cryptography(cert_path, key_path):
    """Genera cert+chiave self-signed con la libreria `cryptography`, senza
    processi esterni. Ritorna True se scritti, False se la libreria non c'e'
    o la generazione fallisce (il chiamante ripiega su None, None)."""
    if not _CRYPTOGRAPHY_AVAILABLE:
        return False
    try:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "raspiscanner.local")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=CERT_DAYS))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("raspiscanner.local"),
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        with open(key_path, "wb") as fh:
            fh.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(cert_path, "wb") as fh:
            fh.write(cert.public_bytes(serialization.Encoding.PEM))
    except Exception as exc:  # noqa: BLE001 - qualunque errore = ripiego pulito
        log.warning("generazione certificato con cryptography fallita: %s", exc)
        return False
    log.info("certificato TLS self-signed generato con la libreria cryptography")
    return True
