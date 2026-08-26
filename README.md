# RaspiScanner

Progetto standalone: un Raspberry Pi (o qualunque Linux) che, collegato via
ethernet a una rete sconosciuta, si autoconfigura per parlarci e offre una
dashboard web **e** una modalita' da riga di comando per scansionare i
dispositivi presenti — telecamere IP, NVR/DVR, apparati di rete — con un
report di sicurezza in stile "assessment".

## Perché RaspiScanner?

Non è l'ennesimo ARP scanner o l'ennesimo client ONVIF: esistono già ottimi
strumenti per la discovery di rete generica (Nmap, Netdiscover, arp-scan) e
per collegarsi a singole telecamere via ONVIF/RTSP. RaspiScanner nasce per
un caso d'uso più specifico che nessuno dei due copre da solo: mettere in un
unico strumento portatile — un Raspberry Pi che si autoconfigura su una rete
sconosciuta al volo, senza bisogno di sapere in anticipo classe/gateway —
la discovery di rete, il fingerprinting via ARP/porte/ONVIF, la
**distinzione tra telecamera, NVR/DVR e apparato di rete**, e un report di
sicurezza (probe attivi ma non intrusivi) pensato per il sopralluogo su un impianto di
videosorveglianza esistente, non per un audit di rete generico. Non
reinventa Nmap: costruisce un livello sopra alcuni dei suoi stessi
meccanismi di discovery, orientato a un caso d'uso preciso.

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

2. **Scan dispositivi** su **tutte** le subnet attive di eth e di **ogni**
   scheda Wi-Fi presente (un dispositivo puo' averne piu' di una — es. una
   usata come client per raggiungere la rete esistente, un'altra dedicata
   all'hotspot — e vengono tracciate/scansionate tutte, non solo la prima
   trovata; ogni indirizzo IPv4 configurato, non solo il primo): ARP scan per IP/MAC,
   port scan mirato + banner HTTP, probe **ONVIF WS-Discovery** (con
   `GetDeviceInformation` per vendor/model reali quando disponibile),
   lookup vendor da OUI offline. Ogni dispositivo viene classificato, in
   ordine di specificita': **Telecamera**/**NVR-DVR** (segnali di
   protocollo — ONVIF, porte tipiche RTSP 554/Hikvision 8000/Dahua
   37777/34567, banner HTTP — non sul vendor MAC, poco affidabile
   offline), **Router**/**Switch**/**Access Point** (IP == gateway di
   default, o banner/vendor), **Raspberry Pi**/altro hardware IoT
   riconosciuto dal vendor, **PC**/**Stampante di rete** (porte tipiche
   SMB/RDP/IPP/JetDirect), o **Generico** se nessuno di questi segnali e'
   disponibile — limite strutturale, non un bug: un dispositivo senza
   porte aperte (comune su telefoni e PC moderni con firewall attivo di
   default) non espone nulla da leggere, e non si va oltre con fingerprint
   attivo dello stack TCP/IP in stile `nmap -O`.

3. **Report "NETWORK ASSESSMENT"**: per ogni rete scansionata, un report
   testuale con dispositivi trovati per categoria (camere/NVR/rete/altro —
   Raspberry Pi, PC, stampanti compaiono in "OTHER DEVICES", cosi' nessun
   dispositivo trovato resta invisibile nel testo del report pur essendo
   contato in "N devices discovered"), findings di sicurezza rilevati con
   probe attivi ma non intrusivi (Telnet esposto, HTTP abilitato, servizio
   con banner di default) e un riepilogo del rischio (Critical/High/
   Medium/Low). Se richiesto mentre uno scan e' ancora in corso, il report
   lo segnala esplicitamente (e' un'istantanea parziale, i conteggi
   aumenteranno). Vedi `examples/sample_report.txt` per un
   esempio completo. Disponibile sia dalla dashboard (scheda "Report") sia
   da riga di comando (`--report`).

4. **Dashboard web** (porta `7332`, polling HTTP, nessuna dipendenza da
   CDN esterni — funziona anche offline; protetta da login, vedi
   [Autenticazione dashboard](#autenticazione-dashboard)): stato di rete,
   una card per **ciascuna** scheda Wi-Fi rilevata con elenco/connessione
   indipendenti, tabella "Tutti i dispositivi", tabella "Solo camere"
   (include anche gli NVR/DVR), scheda "Report", scheda "⚙️ Impostazioni"
   per gestire gli utenti, esportazione **CSV/JSON**.

5. **Hotspot Wi-Fi** (popup "📡 Hotspot" sulla card della scheda Wi-Fi
   scelta): trasforma quella scheda da client (connessa a una rete
   esistente) ad access point, utile per raggiungere la dashboard senza
   cavo quando il dispositivo e' installato in un punto scomodo da cablare
   (es. dentro una scatola in quota). SSID/password configurabili dal
   popup (password generabile automaticamente); una volta attivo il
   profilo resta salvato e si riattiva da solo ai riavvii successivi, cosi'
   il dispositivo torna raggiungibile via Wi-Fi anche dopo un'interruzione
   di corrente. **Attivarlo scollega quella scheda da qualunque rete a cui
   era connessa**: la stessa antenna non puo' fare contemporaneamente
   client e access point — con **due schede Wi-Fi** questo si aggira
   dedicandone una all'hotspot e lasciando l'altra come client verso la
   rete esistente. Richiede NetworkManager (`nmcli`), gia' usato per la
   connessione Wi-Fi client.

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
systemd `raspiscanner.service`. Dashboard su `https://<ip-raspberry>:7332`
(certificato self-signed generato al primo avvio: il browser mostra un
avviso "connessione non sicura" da accettare una volta — vedi
[Autenticazione dashboard](#autenticazione-dashboard)).

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
sono probe di rete **attivi ma non intrusivi** — mandano pacchetti reali
(ARP request, tentativi di connessione TCP, richieste HTTP, WS-Discovery
multicast), quindi non sono "passivi" in senso stretto, ma non fanno mai
login, test di credenziali di default o tentativi di sfruttamento — e
generano comunque traffico visibile sulla rete target.

### Autenticazione dashboard

La dashboard ascolta su `0.0.0.0:7332` ed espone l'inventario completo dei
dispositivi scansionati (IP, MAC, vendor, **URL RTSP/admin delle
telecamere**) oltre ai controlli di rete/hotspot: è protetta da **HTTP
Basic Auth** cosi' chi e' semplicemente sulla stessa rete/hotspot durante
lo scan non ci accede senza credenziali, servita su **HTTPS** con un
certificato self-signed generato al primo avvio (persistito in
`data/tls_cert.pem`/`data/tls_key.pem`) cosi' le credenziali viaggiano
cifrate invece che in chiaro sulla rete che stai scansionando.

Non esiste un certificato firmato da una CA pubblica per questo caso
d'uso: il dispositivo (Raspberry Pi o PC Linux) viene installato su reti
private diverse ogni volta, spesso senza uscita internet, e raggiunto per
IP, non per dominio — condizioni in cui una CA come Let's Encrypt non può
emettere né rinnovare nulla. Per questo, come router/NAS/stampanti di
rete, il browser mostrerà un **avviso "connessione non sicura"** al primo
accesso: è atteso, va accettato una volta (il certificato resta lo stesso
tra un riavvio e l'altro, l'avviso non si ripete a ogni accensione).
Protegge dall'intercettazione passiva del traffico sulla stessa rete, non
da un attacco attivo man-in-the-middle molto sofisticato che nessuno
verifica in pratica (impronta del certificato) — un miglioramento reale
rispetto ad HTTP semplice, non una garanzia assoluta.

Al primo avvio, se `data/users.json` non esiste ancora, viene creato
l'utente di default:

```
Utente:   RaspiScanner
Password: RaspiPass
```

**Cambia la password appena possibile** dalla scheda "⚙️ Impostazioni"
della dashboard, dove puoi anche aggiungere altri utenti o rimuoverli. Le
credenziali sono persistite (hashate, mai in chiaro) in `data/users.json` e
sopravvivono ai riavvii del servizio — non serve rifare nulla a ogni
accensione. Il browser chiede utente/password una volta sola e li ricorda
per la sessione di navigazione.

`data/users.json` è in `.gitignore`: non va committato (contiene gli hash
delle password del deployment specifico).

## Struttura del progetto

```
raspi-scanner.py            Entry point: dashboard Flask (default) o CLI --report
scanner/
  config.py                  Costanti condivise (classi preimpostate, porte, timeout)
  auth.py                     Utenti dashboard (Basic Auth, persistiti in data/users.json)
  tls.py                       Certificato TLS self-signed per la dashboard (via openssl)
  vendor.py                   Lookup vendor da OUI offline
  hosts.py                     Classificazione "e' un Raspberry Pi/PC/stampante?"
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
    hotspot.py                          Access point Wi-Fi (raggiungibilita' senza cavo)
  reporting/
    security.py                         Security findings (Telnet, HTTP, default service)
    risk.py                              Aggregazione severita' -> riepilogo rischio
    assessment.py                         Genera il report NETWORK ASSESSMENT
tests/                       Test unitari (mockati, nessun hardware richiesto)
docs/ARCHITECTURE.md         Panoramica architetturale piu' in dettaglio
examples/                    Esempi di report e uso programmatico dei classificatori
scripts/update_oui.py        Aggiorna oui.csv dal registro IEEE (richiede internet)
data/oui.csv                 Database OUI offline (best effort)
data/users.json              Utenti dashboard (hash password, generato al primo avvio, gitignored)
data/tls_cert.pem, tls_key.pem  Certificato TLS self-signed (generato al primo avvio, gitignored)
templates/, static/          Dashboard (HTML/CSS/JS, no CDN esterni: funziona offline)
install.sh                   Installer (venv + systemd)
raspiscanner.service         Unit file systemd
LICENSE                      MIT
```

Approfondimenti sul flusso di uno scan e sulle scelte architetturali in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
