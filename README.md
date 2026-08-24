# RaspiScanner

Progetto standalone: un Raspberry Pi (o qualunque Linux) che, collegato via
ethernet a una rete sconosciuta, si autoconfigura per parlarci e offre una
dashboard web **e** una modalita' da riga di comando per scansionare i
dispositivi presenti — telecamere IP, NVR/DVR, apparati di rete — con un
report di sicurezza in stile "assessment".

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

2. **Scan dispositivi** su **tutte** le subnet attive di eth e Wi-Fi (ogni
   indirizzo IPv4 configurato, non solo il primo): ARP scan per IP/MAC,
   port scan mirato + banner HTTP, probe **ONVIF WS-Discovery** (con
   `GetDeviceInformation` per vendor/model reali quando disponibile),
   lookup vendor da OUI offline. Ogni dispositivo viene classificato in
   **Telecamera**, **NVR/DVR**, **Apparato di rete** (router/switch/AP,
   individuato anche via IP == gateway di default) o **Generico** — la
   classificazione video non si basa sul vendor MAC (poco affidabile
   offline) ma su segnali di protocollo: ONVIF, porte tipiche (RTSP 554,
   Hikvision 8000, Dahua 37777/34567), banner HTTP.

3. **Report "NETWORK ASSESSMENT"**: per ogni rete scansionata, un report
   testuale con dispositivi trovati per categoria (camere/NVR/rete),
   findings di sicurezza rilevati passivamente (Telnet esposto, HTTP
   abilitato, servizio con banner di default) e un riepilogo del rischio
   (Critical/High/Medium/Low). Vedi `examples/sample_report.txt` per un
   esempio completo. Disponibile sia dalla dashboard (scheda "Report") sia
   da riga di comando (`--report`).

4. **Dashboard web** (porta `7332`, polling HTTP, nessuna dipendenza da
   CDN esterni — funziona anche offline): stato di rete, elenco/connessione
   Wi-Fi, tabella "Tutti i dispositivi", tabella "Solo camere" (include
   anche gli NVR/DVR), scheda "Report", esportazione **CSV/JSON**.

## Uso

```bash
# Dashboard web (default)
sudo python3 raspi-scanner.py

# Report da riga di comando: scan completo + stampa NETWORK ASSESSMENT, poi esce
sudo python3 raspi-scanner.py --report
```

## Requisiti

- Linux (pensato per Raspberry Pi OS) con Python 3.9+.
- Va lanciato come **root** (o con capability `cap_net_raw,cap_net_admin`):
  servono per l'ARP scan raw e per riconfigurare l'interfaccia (`ip addr`,
  `dhclient`).
- Pacchetti di sistema: `python3-venv`, `isc-dhcp-client` (per `dhclient`).
  `nmcli` (NetworkManager) è opzionale, usato solo per l'elenco/connessione
  Wi-Fi.

## Limiti dello scan ARP (leggere prima di segnalare "non trova un dispositivo")

Lo scan dispositivi si basa su ARP: trova solo host che hanno un IP nella
subnet scansionata e rispondono entro il timeout. Alcuni casi che sembrano
bug non lo sono:

- **La macchina su cui gira lo scanner stesso** non riceverebbe mai la
  propria richiesta ARP broadcast di ritorno (nessuno switch la rimanda
  sulla porta da cui e' arrivata) — per questo il tool la aggiunge sempre
  esplicitamente ai risultati, IP e MAC li conosce gia' senza bisogno di
  interrogare la rete.
- **Switch unmanaged** (molti modelli economici) non hanno nessun indirizzo
  IP: sono pura elettronica L2 e sono invisibili a *qualsiasi* scan basato
  su IP, non solo al nostro. Se un dispositivo di rete non compare mai,
  verifica se ha davvero un'interfaccia di gestione IP.
- **Un dispositivo su un'altra subnet/VLAN**, raggiungibile solo tramite
  routing (es. il ping funziona ma passa dal gateway), non verra' mai
  trovato dall'ARP scan: e' un limite del protocollo, non un bug — l'ARP
  non attraversa un router. Va scansionato dal segmento L2 giusto.
- **Un host appena collegato** puo' non rispondere ancora: se lo switch
  a monte ha (R)STP attivo, la porta resta in stato "listening" per
  qualche secondo prima di inoltrare traffico, oltre al tempo che il
  dispositivo stesso impiega a fare DHCP al boot. Aspetta 20-30s dopo aver
  collegato un cavo prima di lanciare lo scan, o rilancialo se il primo
  giro non lo trova.
- Per verificare in modo indipendente dal tool se un dispositivo e'
  davvero raggiungibile sulla subnet: `sudo arp-scan --interface=eth0
  --localnet` oppure `sudo nmap -sn <subnet>`, oppure controlla la tabella
  dei lease DHCP del router/AP.

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
sudo venv/bin/python3 raspi-scanner.py
```

## Test

Test unitari, tutti mockati (nessun hardware o accesso di rete richiesto):

```bash
python3 -m unittest discover -s tests -v
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
python3 scripts/update_oui.py
```

Scarica il registro ufficiale IEEE e sovrascrive `data/oui.csv`.

## Note di sicurezza

Questo è uno strumento di ricognizione di rete: usalo solo su reti che sei
autorizzato a scansionare. L'ARP scan, il port scan e i security findings
sono **passivi** — nessun login, nessun test di credenziali di default,
nessun tentativo di sfruttamento — ma generano comunque traffico visibile
sulla rete target.

## Struttura del progetto

```
raspi-scanner.py            Entry point: dashboard Flask (default) o CLI --report
scanner/
  config.py                  Costanti condivise (classi preimpostate, porte, timeout)
  vendor.py                   Lookup vendor da OUI offline
  scan_engine.py                Orchestrazione scan + stato per la dashboard
  discovery/
    arp.py                       ARP scan (scapy) + reverse DNS
  fingerprint/
    ports.py                      Port scan TCP + banner HTTP
  cameras/
    onvif.py                       WS-Discovery + GetDeviceInformation (ONVIF)
    classify.py                     Classificazione "e' una telecamera?"
  nvr/
    classify.py                      Classificazione "e' un NVR/DVR?"
  network/
    setup.py                          Autoconfig eth (DHCP/fallback) + monitor + wifi
    infra.py                           Gateway di default + "e' un apparato di rete?"
  reporting/
    security.py                         Security findings (Telnet, HTTP, default service)
    risk.py                              Aggregazione severita' -> riepilogo rischio
    assessment.py                         Genera il report NETWORK ASSESSMENT
tests/                       Test unitari (mockati, nessun hardware richiesto)
docs/ARCHITECTURE.md         Panoramica architetturale piu' in dettaglio
examples/                    Esempi di report e uso programmatico dei classificatori
scripts/update_oui.py        Aggiorna oui.csv dal registro IEEE (richiede internet)
data/oui.csv                 Database OUI offline (best effort)
templates/, static/          Dashboard (HTML/CSS/JS, no CDN esterni: funziona offline)
install.sh                   Installer (venv + systemd)
raspiscanner.service         Unit file systemd
LICENSE                      MIT
```

Approfondimenti sul flusso di uno scan e sulle scelte architetturali in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
