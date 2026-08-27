"""Continuous Monitoring mode (P4): esegue automaticamente uno scan a
intervalli regolari invece di richiedere sempre un avvio manuale, cosi'
uno scostamento (nuovo device, uno sparito, una porta che si apre) viene
rilevato entro l'intervallo configurato invece che alla prossima volta che
un operatore ricorda di lanciare uno scan a mano.

Non e' un secondo motore di scan: chiama scan_engine.run_scan(), la
STESSA funzione usata dal pulsante "Start scan" in dashboard. Se uno scan
manuale e' gia' in corso quando lo scheduler tenta di partire, run_scan()
ritorna semplicemente "gia' in corso" (nessuna modifica a scan_engine):
il giro viene saltato, non forzato — non ha senso interrompere uno scan
manuale per farne partire uno automatico.

Configurazione in data/monitoring.json, stesso trattamento di
data/webhooks.json (mai committato, gestita solo da un admin autenticato).
"""
import json
import logging
import os
import threading
import time

from . import config, scan_engine

log = logging.getLogger("raspiscanner.monitoring")

# Granularita' con cui il thread di scheduling rilegge la configurazione
# e ricontrolla se e' ora di scansionare di nuovo — NON l'intervallo tra
# uno scan automatico e il successivo (quello e' interval_minutes,
# configurabile). Un valore piu' basso di questo renderebbe piu' reattivo
# un cambio di configurazione (abilitare/disabilitare, cambiare
# l'intervallo) a scapito di controlli piu' frequenti per nulla.
_POLL_SECONDS = 30

MIN_INTERVAL_MINUTES = 5
DEFAULT_INTERVAL_MINUTES = 60


def _load():
    if not os.path.exists(config.MONITORING_JSON_PATH):
        return {"enabled": False, "interval_minutes": DEFAULT_INTERVAL_MINUTES}
    try:
        with open(config.MONITORING_JSON_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        log.exception("lettura configurazione continuous monitoring fallita")
        return {"enabled": False, "interval_minutes": DEFAULT_INTERVAL_MINUTES}
    return {
        "enabled": bool(data.get("enabled")),
        "interval_minutes": data.get("interval_minutes", DEFAULT_INTERVAL_MINUTES),
    }


def _save(enabled, interval_minutes):
    os.makedirs(config.DATA_DIR, exist_ok=True)
    tmp_path = config.MONITORING_JSON_PATH + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump({"enabled": enabled, "interval_minutes": interval_minutes}, fh, indent=2)
    os.replace(tmp_path, config.MONITORING_JSON_PATH)


def get_config():
    return _load()


def set_config(enabled, interval_minutes):
    try:
        interval_minutes = int(interval_minutes)
    except (TypeError, ValueError):
        return False, "interval_minutes must be a whole number of minutes"
    if interval_minutes < MIN_INTERVAL_MINUTES:
        # Un intervallo troppo corto su una rete con molti host rischia di
        # far accavallare gli scan automatici in continuazione (il
        # successivo giro trova sempre "gia' in corso" e viene saltato),
        # dando l'illusione di monitoraggio continuo senza esserlo davvero.
        return False, f"interval_minutes must be at least {MIN_INTERVAL_MINUTES}"
    _save(bool(enabled), interval_minutes)
    log.info("continuous monitoring aggiornato: enabled=%s interval_minutes=%s", bool(enabled), interval_minutes)
    return True, "Continuous monitoring configuration saved"


_scheduler_lock = threading.Lock()
_scheduler_started = False


def start_scheduler():
    """Avvia il thread di scheduling una sola volta per processo
    (idempotente: chiamata ripetuta, es. da piu' route che condividono
    _ensure_startup, non crea thread duplicati che farebbero partire piu'
    scan automatici sovrapposti)."""
    global _scheduler_started
    with _scheduler_lock:
        if _scheduler_started:
            return
        _scheduler_started = True
    t = threading.Thread(target=_scheduler_loop, daemon=True)
    t.start()
    log.info("scheduler continuous monitoring avviato (poll ogni %ss)", _POLL_SECONDS)


def _scheduler_loop():
    last_scan_at = 0
    while True:
        time.sleep(_POLL_SECONDS)
        try:
            cfg = get_config()
            if not cfg["enabled"]:
                continue
            interval_seconds = cfg["interval_minutes"] * 60
            if time.time() - last_scan_at < interval_seconds:
                continue
            ok, message = scan_engine.run_scan()
            if ok:
                last_scan_at = time.time()
                log.info("continuous monitoring: scan automatico avviato")
            else:
                # Scan gia' in corso o nessuna rete attiva: non e' un
                # errore, solo un giro saltato. last_scan_at NON viene
                # aggiornato, cosi' il prossimo poll (tra _POLL_SECONDS,
                # non tra un intero interval_minutes) riprova subito
                # invece di aspettare un intero altro intervallo.
                log.info("continuous monitoring: scan automatico saltato (%s)", message)
        except Exception:
            # Il loop di scheduling non deve mai morire: un'eccezione
            # imprevista qui spegnerebbe il continuous monitoring in
            # silenzio, senza che l'operatore se ne accorga finche' non
            # nota che gli scan automatici sono smessi di arrivare.
            log.exception("errore nel loop di continuous monitoring")
