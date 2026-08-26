"""Utenti della dashboard (HTTP Basic Auth).

Credenziali persistite hashate in data/users.json, cosi' sopravvivono ai
riavvii del servizio (a differenza di un token rigenerato a ogni avvio, che
costringerebbe a leggere i log ogni volta). Al primo avvio, se il file non
esiste, viene creato l'utente di bootstrap DEFAULT_USERNAME con una
password casuale (mai fissa/nota in anticipo: una credenziale di default
identica su ogni installazione e' un rischio concreto, non teorico, per
uno strumento pensato per essere esposto su reti sconosciute) — stampata
una sola volta nei log e marcata "da cambiare al primo accesso"
(must_change_password): finche' non viene cambiata, raspi-scanner.py
blocca ogni endpoint tranne quello di cambio password (vedi
_require_auth in raspi-scanner.py).

Formato di data/users.json: {username: {"hash": .., "must_change_password": bool}}.
Compatibilita' con installazioni precedenti (dove il valore era
direttamente la stringa hash, nessun campo must_change_password): lette
come must_change_password=False, mai come errore o motivo per bloccare
l'accesso a un'installazione gia' in uso.
"""
import json
import logging
import os
import secrets
import string
import threading

from werkzeug.security import check_password_hash, generate_password_hash

from . import config

log = logging.getLogger("raspiscanner.auth")

DEFAULT_USERNAME = "RaspiScanner"
MIN_PASSWORD_LENGTH = 6
_INITIAL_PASSWORD_LENGTH = 14

_lock = threading.Lock()


def generate_initial_password(length=_INITIAL_PASSWORD_LENGTH):
    """Password iniziale casuale per l'utente di bootstrap: alfanumerica
    (nessun simbolo) cosi' resta facile da leggere/ritrascrivere dai log
    su un terminale, ma comunque robusta alla lunghezza usata qui."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _normalize_record(value):
    """Un valore letto da users.json puo' essere il vecchio formato
    (stringa hash diretta, installazioni precedenti a must_change_password)
    o quello nuovo (dict). Normalizza sempre al dict, cosi' il resto del
    modulo non deve mai preoccuparsi di quale formato era su disco."""
    if isinstance(value, str):
        return {"hash": value, "must_change_password": False}
    return {
        "hash": value.get("hash"),
        "must_change_password": bool(value.get("must_change_password", False)),
    }


def _load():
    if not os.path.exists(config.USERS_JSON_PATH):
        return {}
    try:
        with open(config.USERS_JSON_PATH, encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, ValueError):
        log.exception("lettura utenti fallita, ripristino solo il default in memoria")
        return {}
    return {username: _normalize_record(value) for username, value in raw.items()}


def _save(users):
    os.makedirs(config.DATA_DIR, exist_ok=True)
    tmp_path = config.USERS_JSON_PATH + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(users, fh, indent=2)
    os.replace(tmp_path, config.USERS_JSON_PATH)


def ensure_default_user():
    """Crea l'utente di bootstrap se data/users.json non esiste ancora o
    e' vuoto, con una password CASUALE (non nota in anticipo, diversa a
    ogni installazione) marcata must_change_password. Va chiamata
    all'avvio del processo, prima che la dashboard accetti richieste."""
    with _lock:
        users = _load()
        if not users:
            password = generate_initial_password()
            users[DEFAULT_USERNAME] = {
                "hash": generate_password_hash(password),
                "must_change_password": True,
            }
            _save(users)
            log.warning(
                "utente di bootstrap creato — utente: %s  password iniziale: %s "
                "(casuale, valida una sola volta: il primo accesso obbliga a "
                "cambiarla dalla scheda Impostazioni)",
                DEFAULT_USERNAME, password,
            )


def list_usernames():
    with _lock:
        return sorted(_load().keys())


def must_change_password(username):
    with _lock:
        users = _load()
    record = users.get(username)
    return bool(record and record["must_change_password"])


def verify(username, password):
    if not username or not password:
        return False
    with _lock:
        users = _load()
    record = users.get(username)
    return bool(record and record["hash"] and check_password_hash(record["hash"], password))


def add_user(username, password):
    username = (username or "").strip()
    if not username:
        return False, "Username is required"
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
    with _lock:
        users = _load()
        if username in users:
            return False, "User already exists"
        users[username] = {"hash": generate_password_hash(password), "must_change_password": False}
        _save(users)
    log.info("utente aggiunto: %s", username)
    return True, "User added"


def set_password(username, password):
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
    with _lock:
        users = _load()
        if username not in users:
            return False, "User does not exist"
        users[username] = {"hash": generate_password_hash(password), "must_change_password": False}
        _save(users)
    log.info("password aggiornata per: %s", username)
    return True, "Password updated"


def remove_user(username):
    with _lock:
        users = _load()
        if username not in users:
            return False, "User does not exist"
        if len(users) <= 1:
            return False, "Cannot remove the only remaining user"
        del users[username]
        _save(users)
    log.info("utente rimosso: %s", username)
    return True, "User removed"
