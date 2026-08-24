# Architettura

```
raspi-scanner.py           Entry point: dashboard Flask (default) o CLI --report
├── scanner/
│   ├── config.py            Costanti condivise (classi preimpostate, porte, timeout)
│   ├── vendor.py             Lookup vendor da OUI offline (data/oui.csv)
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
│   │   └── infra.py              Gateway di default + "e' un router/switch/AP?"
│   │
│   └── reporting/             Il report "NETWORK ASSESSMENT"
│       ├── security.py          Findings passivi (Telnet esposto, HTTP abilitato, ...)
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
   indirizzo IPv4 attivo su eth/wifi (un'interfaccia puo' averne piu' di uno).
2. Per ciascuna subnet: `discovery.arp_scan()` trova IP+MAC via ARP, piu' un
   probe `cameras.onvif.onvif_probe()` via WS-Discovery e la lettura del
   gateway di default (`network.infra.get_default_gateway()`).
3. Per ciascun host trovato: `fingerprint.scan_ports()` + `grab_http_banner()`
   raccolgono porte aperte e banner; se il dispositivo risponde a ONVIF si
   tenta `cameras.onvif.get_device_info()` per un vendor/model reali.
4. Il dispositivo viene classificato da tre classificatori indipendenti
   (`cameras.classify_camera`, `nvr.classify_nvr`,
   `network.infra.classify_network_device`) che non si escludono a vicenda:
   scan_engine decide l'etichetta finale (NVR/DVR ha precedenza su
   Telecamera, che ha precedenza su Apparato di rete).
5. Il risultato aggregato e' consultabile via dashboard (polling HTTP,
   CSV/JSON) o tramite `scanner.reporting.assessment.generate_all()`, che
   raggruppa per rete e produce il report testuale "NETWORK ASSESSMENT" con
   i findings di sicurezza (`reporting.security`) e il riepilogo rischio
   (`reporting.risk`).

## Limiti noti (per scelta, non per dimenticanza)

- Tutte le classificazioni (camera/NVR/rete) e i security findings sono
  **euristiche passive**: nessun login, nessun test di credenziali, nessun
  tentativo di sfruttamento. Non garantiscono di essere sempre corrette (un
  falso positivo/negativo e' un limite noto, documentato nei docstring dei
  moduli interessati), ma non fanno mai nulla di piu' invasivo di una
  richiesta di rete passiva.
- L'ARP scan funziona solo sulla subnet L2 direttamente connessa: un
  dispositivo raggiungibile solo tramite routing (altra VLAN/subnet) non
  verra' mai trovato da questo meccanismo, per limite strutturale del
  protocollo ARP, non per un bug del tool.
