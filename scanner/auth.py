"""Utenti della dashboard (HTTP Basic Auth).

Credenziali persistite hashate in data/users.json, cosi' sopravvivono ai
riavvii del servizio (a differenza di un token rigenerato a ogni avvio, che
costringerebbe a leggere i log ogni volta). Al primo avvio, se il file non
esiste, viene creato con l'utente di default (vedi DEFAULT_USERNAME/
DEFAULT_PASSWORD): va cambiata dalla scheda "Impostazioni" della dashboard.
"""
import json
import logging
import os
import threading

from werkzeug.security import check_password_hash, generate_password_hash

from . import config

log = logging.getLogger("raspiscanner.auth")

DEFAULT_USERNAME = "RaspiScanner"
DEFAULT_PASSWORD = "RaspiPass"
MIN_PASSWORD_LENGTH = 6

_lock = threading.Lock()


def _load():
    if not os.path.exists(config.USERS_JSON_PATH):
        return {}
    try:
        with open(config.USERS_JSON_PATH, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        log.exception("lettura utenti fallita, ripristino solo il default in memoria")
        return {}


def _save(users):
    os.makedirs(config.DATA_DIR, exist_ok=True)
    tmp_path = config.USERS_JSON_PATH + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(users, fh, indent=2)
    os.replace(tmp_path, config.USERS_JSON_PATH)


def ensure_default_user():
    """Crea l'utente di default se data/users.json non esiste ancora o e'
    vuoto. Va chiamata all'avvio del processo, prima che la dashboard
    accetti richieste."""
    with _lock:
        users = _load()
        if not users:
            users[DEFAULT_USERNAME] = generate_password_hash(DEFAULT_PASSWORD)
            _save(users)
            log.warning(
                "utente di default creato: %s / %s — cambia la password dalla "
                "scheda Impostazioni",
                DEFAULT_USERNAME, DEFAULT_PASSWORD,
            )


def list_usernames():
    with _lock:
        return sorted(_load().keys())


def verify(username, password):
    if not username or not password:
        return False
    with _lock:
        users = _load()
    hashed = users.get(username)
    return bool(hashed and check_password_hash(hashed, password))


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
        users[username] = generate_password_hash(password)
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
        users[username] = generate_password_hash(password)
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
