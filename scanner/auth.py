"""Utenti della dashboard (HTTP Basic Auth) + ruoli.

Credenziali persistite hashate in data/users.json, cosi' sopravvivono ai
riavvii del servizio (a differenza di un token rigenerato a ogni avvio, che
costringerebbe a leggere i log ogni volta). Al primo avvio, se il file non
esiste, viene creato l'utente di bootstrap DEFAULT_USERNAME (ruolo admin)
con una password casuale (mai fissa/nota in anticipo: una credenziale di
default identica su ogni installazione e' un rischio concreto, non
teorico, per uno strumento pensato per essere esposto su reti sconosciute)
— stampata una sola volta nei log e marcata "da cambiare al primo
accesso" (must_change_password): finche' non viene cambiata,
raspi-scanner.py blocca ogni endpoint tranne quello di cambio password
(vedi _require_auth in raspi-scanner.py).

Ruoli (dal meno al piu' privilegiato): viewer (sola lettura: stato rete,
dispositivi, report, export), operator (in piu': avviare/fermare scan,
riconfigurare rete, hotspot, connessione Wi-Fi), admin (in piu':
creare/rimuovere utenti, cambiare la password di altri). Ogni utente puo'
sempre cambiare la PROPRIA password indipendentemente dal ruolo (verificato
lato route in raspi-scanner.py, non qui) — altrimenti un operator/viewer
con must_change_password attivo resterebbe bloccato per sempre.

Formato di data/users.json: {username: {"hash":.., "must_change_password":
bool, "role": "admin"|"operator"|"viewer"}}. Compatibilita' con
installazioni precedenti (valore come stringa hash diretta, prima di
must_change_password; o dict senza "role", prima dei ruoli): lette con
must_change_password=False e role="admin" — un utente che aveva pieno
accesso prima che i ruoli esistessero non deve perderlo silenziosamente
in un aggiornamento.
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

ROLES = ("viewer", "operator", "admin")
DEFAULT_ROLE = "viewer"  # principio del privilegio minimo per chi non lo specifica
ROLE_RANK = {role: rank for rank, role in enumerate(ROLES)}

_lock = threading.Lock()


def generate_initial_password(length=_INITIAL_PASSWORD_LENGTH):
    """Password iniziale casuale per l'utente di bootstrap: alfanumerica
    (nessun simbolo) cosi' resta facile da leggere/ritrascrivere dai log
    su un terminale, ma comunque robusta alla lunghezza usata qui."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _normalize_record(value):
    """Un valore letto da users.json puo' essere in tre formati (dal piu'
    vecchio al piu' nuovo): stringa hash diretta; dict senza "role" (tra
    l'introduzione di must_change_password e quella dei ruoli); dict
    completo. Normalizza sempre al dict completo, cosi' il resto del
    modulo non deve mai preoccuparsi di quale formato era su disco. Il
    default per un ruolo mancante e' "admin", non DEFAULT_ROLE: un utente
    gia' esistente prima dei ruoli aveva di fatto accesso pieno, non va
    declassato in silenzio da un aggiornamento."""
    if isinstance(value, str):
        return {"hash": value, "must_change_password": False, "role": "admin"}
    role = value.get("role")
    if role not in ROLES:
        role = "admin"
    return {
        "hash": value.get("hash"),
        "must_change_password": bool(value.get("must_change_password", False)),
        "role": role,
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
    e' vuoto, ruolo admin, con una password CASUALE (non nota in anticipo,
    diversa a ogni installazione) marcata must_change_password. Va
    chiamata all'avvio del processo, prima che la dashboard accetti
    richieste."""
    with _lock:
        users = _load()
        if not users:
            password = generate_initial_password()
            users[DEFAULT_USERNAME] = {
                "hash": generate_password_hash(password),
                "must_change_password": True,
                "role": "admin",
            }
            _save(users)
            log.warning(
                "utente di bootstrap creato — utente: %s  password iniziale: %s  "
                "ruolo: admin (casuale, valida una sola volta: il primo accesso "
                "obbliga a cambiarla dalla scheda Impostazioni)",
                DEFAULT_USERNAME, password,
            )


def list_usernames():
    with _lock:
        return sorted(_load().keys())


def list_users():
    """Come list_usernames() ma con anche il ruolo — usato dalla scheda
    Impostazioni per mostrarlo, non solo il nome."""
    with _lock:
        users = _load()
    return [{"username": u, "role": r["role"]} for u, r in sorted(users.items())]


def get_role(username):
    with _lock:
        users = _load()
    record = users.get(username)
    return record["role"] if record else None


def has_role_at_least(username, min_role):
    """True se l'utente esiste e il suo ruolo e' min_role o superiore
    nell'ordine viewer < operator < admin."""
    role = get_role(username)
    if role is None:
        return False
    return ROLE_RANK[role] >= ROLE_RANK[min_role]


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


def add_user(username, password, role=DEFAULT_ROLE):
    username = (username or "").strip()
    if not username:
        return False, "Username is required"
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
    if role not in ROLES:
        return False, f"Role must be one of: {', '.join(ROLES)}"
    with _lock:
        users = _load()
        if username in users:
            return False, "User already exists"
        users[username] = {
            "hash": generate_password_hash(password),
            "must_change_password": False,
            "role": role,
        }
        _save(users)
    log.info("utente aggiunto: %s (ruolo %s)", username, role)
    return True, "User added"


def set_password(username, password):
    """Aggiorna solo la password (e azzera must_change_password): il
    ruolo esistente resta invariato — riscrivere l'intero record qui
    perderebbe il ruolo assegnato all'utente, non solo la password."""
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
    with _lock:
        users = _load()
        if username not in users:
            return False, "User does not exist"
        users[username]["hash"] = generate_password_hash(password)
        users[username]["must_change_password"] = False
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
