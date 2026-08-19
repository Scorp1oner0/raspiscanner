# RaspiScanner

Progetto standalone: un
Raspberry Pi che, collegato via ethernet a una rete sconosciuta, si
autoconfigura per parlarci e offre una dashboard web per scansionare i
dispositivi presenti — con una vista dedicata alle sole telecamere IP.

## Cosa fa

1. **Autoconfigurazione ethernet.** Quando l'interfaccia `eth0` rileva il
   cavo collegato e non ha gia' un indirizzo, prova prima un lease **DHCP**.
   Se non arriva entro il timeout, prova in sequenza una lista di **classi
   private preimpostate** (192.168.1.0/24, 192.168.0.0/24, 10.0.0.0/24,
   ecc. — vedi `scanner/config.py`): per ciascuna si assegna un IP statico
   "alto" e verifica con un probe ARP se ci sono host che rispondono. La
   prima classe "viva" trovata viene mantenuta. Il monitor gira in
   continuo: se scolleghi e ricolleghi il cavo (magari su un'altra rete),
   rifà tutto da capo automaticamente.

   Se l'interfaccia ha **gia'** uno o piu' indirizzi IPv4 che il tool non
   ha assegnato lui stesso (es. IP secondari configurati a mano per
   raggiungere piu' subnet sullo stesso cavo), non li tocca: li rileva e
   li usa cosi' come sono (modalita' "manuale" nella dashboard). Il
   pulsante "Riconfigura rete" ha un'opzione "forza" per azzerare comunque
   tutto e far ripartire DHCP/fallback da zero.
2. **Dashboard web** (porta `7332`) con:
   - stato di ethernet e Wi-Fi, con **tutti** gli indirizzi IPv4 attivi
     (non solo il primo: un'interfaccia con piu' IP configurati mostra ed
     espone allo scan ognuna delle reti corrispondenti), classe/modalità
     di configurazione;
   - elenco reti Wi-Fi visibili e connessione manuale (se `nmcli` è
     disponibile);
   - **scan "Tutti i dispositivi"**: ARP scan su **tutte** le subnet
     attive (ogni indirizzo IPv4 su eth + wifi, non solo il primo trovato),
     con IP, MAC, vendor (da OUI offline), hostname (reverse DNS
     best-effort), interfaccia, rete di appartenenza, porte aperte, tipo;
   - **scan "Solo camere"**: stesso scan, filtrato sui dispositivi
     riconosciuti come telecamere/NVR/DVR. Il riconoscimento **non** si
     basa sul vendor MAC (poco affidabile offline) ma su segnali di
     protocollo: risposta **ONVIF WS-Discovery**, porte tipiche
     (RTSP 554, Hikvision 8000, Dahua 37777/34567), banner HTTP con
     parole chiave note (hikvision, dahua, axis, nvr, dvr, onvif, ...).
     Per ogni telecamera vengono proposti un URL RTSP e un link
     all'interfaccia di amministrazione;
   - esportazione risultati in **CSV/JSON**.

## Requisiti

- Raspberry Pi OS (o altra distro Linux) con Python 3.9+.
- Va lanciato come **root** (o con capability `cap_net_raw,cap_net_admin`):
  servono per l'ARP scan raw e per riconfigurare l'interfaccia (`ip addr`,
  `dhclient`).
- Pacchetti di sistema: `python3-venv`, `isc-dhcp-client` (per `dhclient`).
  `nmcli` (NetworkManager) è opzionale, usato solo per l'elenco/connessione
  Wi-Fi.

## Installazione

```bash
sudo ./install.sh
```

Installa il progetto in `/opt/raspiscanner`, crea un virtualenv, installa
le dipendenze Python (`Flask`, `scapy`) e registra/avvia il servizio
systemd `raspiscanner.service`. Dashboard su `http://<ip-raspberry>:7332`.

Per eseguirlo senza installarlo come servizio, in sviluppo:

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
sudo venv/bin/python3 app.py
```

## Conflitti con NetworkManager/dhcpcd

Se `eth0` è già gestita da NetworkManager o `dhcpcd` (comportamento di
default su Raspberry Pi OS), quei servizi possono rimuovere l'IP statico
assegnato da RaspiScanner durante il fallback sulle classi preimpostate.
Per evitare conflitti, marca `eth0` come "unmanaged":

- **NetworkManager**: aggiungi a `/etc/NetworkManager/conf.d/unmanaged.conf`
  ```ini
  [keyfile]
  unmanaged-devices=interface-name:eth0
  ```
  poi `sudo systemctl restart NetworkManager`.
- **dhcpcd**: aggiungi a `/etc/dhcpcd.conf`
  ```
  denyinterfaces eth0
  ```
  poi `sudo systemctl restart dhcpcd`.

Il Wi-Fi (`wlan0`) può restare gestito normalmente da NetworkManager: lo
scanner legge solo il suo stato, non lo tocca (a parte l'endpoint opzionale
di connessione via `nmcli`).

## Database vendor (OUI) offline

`data/oui.csv` è un elenco ridotto e "best effort" dei vendor più comuni
(reti, IoT, telecamere IP, Raspberry Pi) pensato per funzionare **senza
internet** sul campo. Il riconoscimento delle telecamere non dipende da
questo file (si basa su porte/protocollo), quindi un vendor mancante è solo
un'etichetta informativa in meno, non un problema di accuratezza dello scan.

Per un database vendor più completo, da una macchina **con** accesso a
internet (es. prima di portare il Pi sul campo):

```bash
python3 update_oui.py
```

Scarica il registro ufficiale IEEE e sovrascrive `data/oui.csv`.

## Note di sicurezza

Questo è uno strumento di ricognizione di rete: usalo solo su reti che sei
autorizzato a scansionare. L'ARP scan e il port scan generano traffico
visibile sulla rete target.

## Struttura del progetto

```
raspiscanner/
  app.py                  Flask app + REST API della dashboard
  scanner/
    config.py              Costanti (classi preimpostate, porte, timeout)
    network_setup.py        Autoconfig eth (DHCP/fallback) + monitor + stato wifi
    discovery.py             ARP scan (scapy) + reverse DNS
    portscan.py               Port scan TCP + banner HTTP
    onvif_discovery.py         Probe WS-Discovery (ONVIF) via multicast
    camera_id.py                Classificazione "è una telecamera?"
    scan_engine.py                Orchestrazione scan + stato per la dashboard
    vendor.py                     Lookup vendor da OUI offline
  data/oui.csv             Database OUI offline (best effort)
  templates/index.html     Dashboard (no CDN esterni: funziona offline)
  static/style.css, app.js
  update_oui.py            Aggiorna oui.csv dal registro IEEE (richiede internet)
  install.sh                Installer (venv + systemd)
  raspiscanner.service       Unit file systemd
```
