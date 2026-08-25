# Architettura

```
raspi-scanner.py           Entry point: dashboard Flask (default) o CLI --report
├── scanner/
│   ├── config.py            Costanti condivise (classi preimpostate, porte, timeout)
│   ├── vendor.py             Lookup vendor da OUI offline (data/oui.csv)
│   ├── hosts.py                "e' un Raspberry Pi/PC/stampante?" (vendor o porte tipiche)
│   ├── scan_engine.py         Orchestrazione: discovery -> fingerprint -> classify -> stato
│   │
│   ├── discovery/            Scoperta host su una subnet
│   │   └── arp.py              ARP scan (scapy) + reverse DNS
│   │
│   ├── fingerprint/          Cosa espone un host gia' scoperto
│   │   └── ports.py            Port scan TCP + banner HTTP (Server/<title>)
│   │
│   ├── cameras/               Tutto cio' che riguarda le telecamere IP
│   │   ├── onvif.py             WS-Discovery (multicast) + GetDeviceInformation (SOAP)
│   │   └── classify.py           "e' una telecamera?" + URL RTSP/admin
│   │
│   ├── nvr/                   Registratori (NVR/DVR), distinti dalla singola camera
│   │   └── classify.py           "e' un NVR/DVR?" (segnale: banner esplicito)
│   │
│   ├── network/               Autoconfig dell'interfaccia + apparati di rete
│   │   ├── setup.py             DHCP -> fallback classi preimpostate, monitor cavo/wifi
│   │   ├── infra.py              Gateway di default + "e' un router/switch/AP?"
│   │   └── hotspot.py             Access point Wi-Fi (nmcli) per raggiungibilita' senza cavo
│   │
│   └── reporting/             Il report "NETWORK ASSESSMENT"
│       ├── security.py          Findings da probe attivi ma non intrusivi (Telnet esposto, HTTP abilitato, ...)
│       ├── risk.py               Aggregazione severita' -> Critical/High/Medium/Low
│       └── assessment.py          Genera il testo del report per una o piu' reti
│
├── templates/, static/       Dashboard web (HTML/CSS/JS, nessuna dipendenza esterna/CDN)
├── data/oui.csv              Database OUI offline (best effort)
├── scripts/update_oui.py     Aggiorna oui.csv dal registro IEEE (richiede internet)
└── tests/                    Test unitari, tutti mockati (nessun hardware/rete richiesta)
```

## Flusso di uno scan

1. `scan_engine._active_networks()` legge da `network.setup.get_status()` ogni
   indirizzo IPv4 attivo su eth e su **ogni** scheda Wi-Fi presente (un
   dispositivo puo' averne piu' di una, e un'interfaccia puo' averne piu'
   di un indirizzo).
2. Per ciascuna subnet: `discovery.arp_scan()` trova IP+MAC via ARP, piu' un
   probe `cameras.onvif.onvif_probe()` via WS-Discovery e la lettura del
   gateway di default (`network.infra.get_default_gateway()`).
3. Per ciascun host trovato: `fingerprint.scan_ports()` + `grab_http_banner()`
   raccolgono porte aperte e banner; se il dispositivo risponde a ONVIF si
   tenta `cameras.onvif.get_device_info()` per un vendor/model reali.
4. Il dispositivo viene classificato da quattro classificatori indipendenti
   (`cameras.classify_camera`, `nvr.classify_nvr`,
   `network.infra.classify_network_device`, `hosts.classify_host`) che non
   si escludono a vicenda: scan_engine decide l'etichetta finale in ordine
   di specificita' — NVR/DVR, poi Telecamera, poi apparato di rete (Router
   se e' il gateway, altrimenti Switch/Access Point se un banner lo
   suggerisce, altrimenti il generico "Apparato di rete"), poi hardware
   riconosciuto dal vendor o da porte tipiche (Raspberry Pi, PC via
   SMB/RDP, stampante via IPP/JetDirect), infine "Generico" se nessun
   segnale e' disponibile — limite strutturale (un dispositivo senza porte
   aperte, comune su telefoni/PC moderni, non espone nulla da leggere, e
   non si va oltre con fingerprint attivo dello stack TCP/IP in stile
   `nmap -O`).
5. Il risultato aggregato e' consultabile via dashboard (polling HTTP,
   CSV/JSON) o tramite `scanner.reporting.assessment.generate_all()`, che
   raggruppa per rete e produce il report testuale "NETWORK ASSESSMENT" con
   i findings di sicurezza (`reporting.security`) e il riepilogo rischio
   (`reporting.risk`). Ogni dispositivo con un tipo riconosciuto compare
   in qualche sezione (CAMERAS/NVR/NETWORK/OTHER DEVICES): un Raspberry
   Pi o un PC non finiscono piu' in nessuna sezione pur essendo contati in
   "N devices discovered", come succedeva prima di introdurre "OTHER
   DEVICES". Se lo scan e' ancora in corso quando il report viene
   richiesto (`/api/report`), la risposta lo segnala esplicitamente
   invece di presentare un'istantanea parziale come se fosse definitiva.

## Limiti noti (per scelta, non per dimenticanza)

- Tutte le classificazioni (camera/NVR/rete) e i security findings si
  basano su **probe attivi ma non intrusivi** (ARP request, tentativi di
  connessione TCP, richieste HTTP, WS-Discovery multicast): non sono
  "passivi" in senso tecnico stretto (mandano pacchetti reali), ma non
  fanno mai login, test di credenziali o tentativi di sfruttamento. Non
  garantiscono di essere sempre corrette (un falso positivo/negativo e'
  un limite noto, documentato nei docstring dei moduli interessati).
- L'ARP scan funziona solo sulla subnet L2 direttamente connessa: un
  dispositivo raggiungibile solo tramite routing (altra VLAN/subnet) non
  verra' mai trovato da questo meccanismo, per limite strutturale del
  protocollo ARP, non per un bug del tool.
