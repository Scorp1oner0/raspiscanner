# Architettura

```
raspi-scanner.py             Entry point: dashboard Flask (default) o CLI --report
├── scanner/
│   ├── config.py              Costanti condivise (classi preimpostate, porte, timeout)
│   ├── auth.py                 Utenti dashboard: ruoli, hash password, must_change_password
│   ├── tls.py                   Certificato TLS self-signed per la dashboard (via openssl)
│   ├── vendor.py                Lookup vendor da OUI offline (data/oui.csv)
│   ├── hosts.py                  "e' un Raspberry Pi/PC/stampante?" (vendor o porte tipiche)
│   ├── scan_engine.py            Orchestrazione: discovery -> fingerprint -> classify -> stato
│   ├── storage.py                 Storico scan/asset database (SQLite, data/history.db)
│   ├── webhooks.py                 Notifica POST opzionale a fine scan
│   ├── monitoring.py                Continuous Monitoring: scheduler di scan automatici
│   ├── targets.py                    Scan targets: reti custom oltre a quelle di interfaccia
│   │
│   ├── discovery/                 Scoperta host su una subnet
│   │   ├── arp.py                   ARP scan (scapy) + reverse DNS + tag VLAN 802.1Q
│   │   ├── icmp.py                   ICMP sweep per link NOARP (tunnel VPN)
│   │   ├── mdns.py                   mDNS/Bonjour (nome amichevole + modello Apple)
│   │   ├── snmp.py                    SNMP opzionale (sysDescr/sysName) su apparati di rete
│   │   ├── lldp_cdp.py                 Ascolto passivo LLDP/CDP (topologia one-hop)
│   │   └── ipv6.py                     IPv6 discovery (ICMPv6 Echo verso ff02::1)
│   │
│   ├── fingerprint/               Cosa espone un host gia' scoperto
│   │   └── ports.py                 Port scan TCP + banner HTTP (Server/<title>)
│   │
│   ├── cameras/                   Tutto cio' che riguarda le telecamere IP
│   │   ├── onvif.py                 WS-Discovery (multicast) + GetDeviceInformation (SOAP)
│   │   └── classify.py               "e' una telecamera?" + URL RTSP/admin + vendor da banner
│   │
│   ├── nvr/                       Registratori (NVR/DVR), distinti dalla singola camera
│   │   └── classify.py               "e' un NVR/DVR?" + sottotipo (DVR/Encoder/Decoder)
│   │
│   ├── network/                   Autoconfig dell'interfaccia + apparati di rete
│   │   ├── setup.py                 DHCP -> fallback classi preimpostate, monitor cavo/wifi
│   │   ├── infra.py                  Gateway di default + "e' un router/switch/AP?"
│   │   └── hotspot.py                 Access point Wi-Fi (nmcli) per raggiungibilita' senza cavo
│   │
│   └── reporting/                 Il report "NETWORK ASSESSMENT"
│       ├── security.py              Findings da probe attivi ma non intrusivi
│       ├── risk.py                   Aggregazione severita' -> Critical/High/Medium/Low
│       └── assessment.py              Genera il testo del report, con sezione diff opzionale
│
├── templates/, static/        Dashboard web (HTML/CSS/JS, nessuna dipendenza esterna/CDN)
├── data/oui.csv                Database OUI offline (best effort)
├── scripts/update_oui.py       Aggiorna oui.csv dal registro IEEE (richiede internet)
└── tests/                      Test unitari, tutti mockati (nessun hardware/rete richiesta)
```

## Flusso di uno scan

1. `scan_engine._active_networks()` legge da `network.setup.get_status()` ogni
   indirizzo IPv4 attivo su eth, su **ogni** scheda Wi-Fi presente e su ogni
   tunnel VPN attivo (WireGuard/OpenVPN/PPP/Tailscale/ZeroTier). Se
   `scanner.targets` ha `auto_interfaces: false`, questo passo viene
   saltato del tutto (vedi "Scan targets vs. network bootstrap" sotto).
   Le reti "custom" configurate in `scanner.targets` che NON corrispondono
   gia' a un'interfaccia attiva vengono aggiunte da
   `scan_engine._routed_target_networks()`, risolte alla vera interfaccia
   di uscita via `ip route get` (`_egress_interface_for()`).
2. Per ciascuna subnet, in parallelo: `discovery.arp_scan()` (o
   `discovery.icmp_scan()` sui link NOARP) trova IP+MAC/IP; contestualmente,
   in thread separati, `cameras.onvif.onvif_probe()` (WS-Discovery),
   `discovery.mdns_probe()`, `discovery.lldp_cdp_probe()` (ascolto passivo)
   e `discovery.ipv6_discovery()` (ICMPv6 verso il multicast all-nodes)
   raccolgono segnali supplementari sulla stessa finestra di tempo.
3. Per ciascun host trovato: `fingerprint.scan_ports()` + `grab_http_banner()`
   raccolgono porte aperte e banner; se il dispositivo risponde a ONVIF si
   tenta `cameras.onvif.get_device_info()` per un vendor/model reali; se e'
   gia' sospettato apparato di rete, `discovery.snmp_probe()` prova
   `sysDescr`/`sysName` come fallback.
4. Il dispositivo viene classificato da quattro classificatori indipendenti
   (`cameras.classify_camera`, `nvr.classify_nvr`,
   `network.infra.classify_network_device`, `hosts.classify_host`) che non
   si escludono a vicenda: scan_engine decide l'etichetta finale in ordine
   di specificita' — NVR/DVR, poi Telecamera, poi apparato di rete, poi
   hardware riconosciuto dal vendor o da porte tipiche, infine "Generico"
   se nessun segnale e' disponibile.
5. A fine scan, `storage.save_scan()` salva uno snapshot completo
   (SQLite) e aggiorna l'asset database; `webhooks.notify_scan_complete()`
   notifica l'esito (incluso un diff rispetto allo scan precedente) a un
   URL opzionale configurato. Il risultato aggregato e' consultabile via
   dashboard, API JSON, o `scanner.reporting.assessment.generate_all()`,
   che raggruppa per rete e produce il report testuale "NETWORK ASSESSMENT"
   con i findings di sicurezza (`reporting.security`) e il riepilogo
   rischio (`reporting.risk`).
6. `monitoring.py` puo' ripetere questo intero flusso automaticamente a
   intervalli, chiamando la stessa `scan_engine.run_scan()` del pulsante
   "Start scan" — nessun percorso di scan separato per gli scan automatici.

## Scan targets vs. network bootstrap

Due concetti separati DELIBERATAMENTE, che prima di questa feature
coincidevano implicitamente in un solo meccanismo:

- **Network bootstrap/fallback** (`scanner/network/setup.py`, INVARIATO):
  su quale indirizzo configurare il Raspberry stesso quando il DHCP non
  risponde (classi preimpostate + probe ARP, vedi README).
- **Scan targets** (`scanner/targets.py`): quali reti un'operazione di
  scan analizza davvero. Di default coincidono con le reti rilevate sulle
  interfacce attive (comportamento originale, invariato per chi non
  tocca `data/targets.json`), ma un operatore puo' anche disattivare
  quell'automatismo e/o aggiungere reti "custom".

Una rete custom che il Raspberry non ha come proprio indirizzo su
nessuna interfaccia non e' raggiungibile via ARP (limite di protocollo,
non implementativo): `scan_engine._egress_interface_for()` chiede al
kernel (`ip route get`) quale interfaccia userebbe per raggiungerla, e
quella rete viene poi scansionata SOLO via ICMP sweep — stesso
trattamento gia' riservato alle interfacce NOARP (VPN). Niente
MAC/vendor, niente ONVIF/mDNS/LLDP-CDP/IPv6 per gli host trovati li'
(richiederebbero un indirizzo locale in quella subnet per avere senso).

## Modello di accesso

Tre ruoli (`viewer`/`operator`/`admin`, `scanner/auth.py`), verificati sia
lato dashboard (tab nascoste) sia — indipendentemente — su ogni singola
route API (`@require_role` in `raspi-scanner.py`). Nessuna route e' protetta
solo lato client: un client che chiama l'API direttamente ottiene comunque
`403` sotto il ruolo minimo richiesto.

## Limiti noti (per scelta, non per dimenticanza)

- Tutte le classificazioni (camera/NVR/rete) e i security findings si
  basano su **probe attivi ma non intrusivi** (ARP/ICMP request, tentativi
  di connessione TCP, richieste HTTP, WS-Discovery multicast, ICMPv6 Echo):
  non sono "passivi" in senso tecnico stretto (mandano pacchetti reali), ma
  non fanno mai login, test di credenziali o tentativi di sfruttamento.
- L'ARP scan funziona solo sulla subnet L2 direttamente connessa: un
  dispositivo raggiungibile solo tramite routing (altra VLAN/subnet) non
  verra' mai trovato da questo meccanismo, per limite strutturale del
  protocollo ARP, non per un bug del tool.
- Il loop che processa gli host scoperti in `scan_engine._run_scan_thread`
  e' sequenziale (il port scan interno a ciascun host e' gia' parallelo,
  ma non c'e' parallelismo tra un host e il successivo): su reti molto
  grandi (`/16` o piu') questo domina il tempo totale di scan. Non
  parallelizzato ulteriormente senza una rete reale di quella scala su cui
  validare la correttezza (stato condiviso tra host concorrenti,
  reattivita' dello stop-flag a meta' di un batch).
- La topologia di rete (`GET /api/topology`) e' volutamente **un solo
  hop** (gateway + vicini LLDP/CDP visti direttamente): un grafo
  multi-hop richiederebbe uno SNMP-walk su switch remoti con credenziali
  che questo tool non ha e non deve indovinare.
