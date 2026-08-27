"""Webhook opzionale (P4): notifica un URL configurato via POST JSON al
termine di ogni scan. Configurazione in data/webhooks.json, gestita solo
da un admin autenticato via API (mai un URL scelto o influenzato da un
dispositivo scansionato: qui la scelta dell'URL e' deliberatamente
dell'operatore, non input di rete non fidato — non e' lo stesso rischio
SSRF dell'XAddr ONVIF).

Best-effort per design: un webhook che fallisce (URL irraggiungibile,
timeout, errore HTTP) non deve mai far fallire lo scan che lo ha
scatenato, solo essere loggato.
"""
import json
import logging
import os
import urllib.parse
import urllib.request

from . import config

log = logging.getLogger("raspiscanner.webhooks")

TIMEOUT_SECONDS = 5


def _load():
    if not os.path.exists(config.WEBHOOKS_JSON_PATH):
        return {"url": None, "enabled": False}
    try:
        with open(config.WEBHOOKS_JSON_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        log.exception("lettura configurazione webhook fallita")
        return {"url": None, "enabled": False}
    return {"url": data.get("url"), "enabled": bool(data.get("enabled"))}


def _save(url, enabled):
    os.makedirs(config.DATA_DIR, exist_ok=True)
    tmp_path = config.WEBHOOKS_JSON_PATH + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump({"url": url, "enabled": enabled}, fh, indent=2)
    os.replace(tmp_path, config.WEBHOOKS_JSON_PATH)


def get_config():
    """{'url':.., 'enabled': bool} — 'enabled' e' sempre False se 'url'
    e' vuoto, a prescindere da cosa dice il file (un webhook "abilitato"
    ma senza URL non ha senso e non deve mai tentare una richiesta)."""
    cfg = _load()
    return {"url": cfg["url"], "enabled": bool(cfg["enabled"] and cfg["url"])}


def set_config(url, enabled):
    url = (url or "").strip() or None
    if enabled and not url:
        return False, "A URL is required to enable the webhook"
    if url and urllib.parse.urlparse(url).scheme not in ("http", "https"):
        # urllib.request supporta anche file:// e ftp://: senza questo
        # controllo, un URL come "file:///etc/passwd" verrebbe aperto
        # da notify_scan_complete esattamente come un vero endpoint HTTP.
        # L'URL e' scelto da un admin autenticato (non input di rete non
        # fidato), ma un webhook che accetta solo http/https resta la
        # forma minima corretta indipendentemente da chi lo configura.
        return False, "Webhook URL must be http:// or https://"
    _save(url, bool(enabled))
    log.info("configurazione webhook aggiornata: url=%s enabled=%s", url, bool(enabled))
    return True, "Webhook configuration saved"


def notify_scan_complete(summary):
    """Invia `summary` (dict JSON-serializzabile) all'URL configurato,
    se abilitato. Non solleva mai: un fallimento resta solo nei log."""
    cfg = get_config()
    if not cfg["enabled"]:
        return
    body = json.dumps(summary, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        cfg["url"], data=body, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "raspiscanner-webhook"},
    )
    try:
        urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS).close()
        log.info("webhook notificato: %s", cfg["url"])
    except Exception as exc:
        log.warning("notifica webhook fallita (%s): %s", cfg["url"], exc)
