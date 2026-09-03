# Provare RaspiScanner senza installarlo

Su **tutti e tre** i sistemi il percorso è lo stesso: uno script che crea un
ambiente Python isolato, installa le dipendenze, avvia la dashboard in primo
piano e apre il browser. Si ferma con `Ctrl-C` (o chiudendo la finestra) e
non lascia nulla dietro di sé: nessun servizio registrato, nessun file
fuori dalla cartella del progetto, **nessuna modifica alla configurazione di
rete**.

| Sistema | Comando |
|---|---|
| Linux (desktop, portatile) | `./start.sh` |
| Raspberry Pi OS | `./start.sh` |
| Windows | doppio click su `start.bat` |

Serve solo Python 3.9+. Su Windows va installato da
[python.org](https://www.python.org/downloads/) spuntando **"Add Python to
PATH"**; su Debian/Ubuntu/Raspberry Pi OS serve anche `python3-venv`
(`sudo apt install python3-venv`).

La dashboard si apre su <https://127.0.0.1:7332>. Il certificato è
self-signed: il browser mostra un avviso da accettare una volta. L'account
admin e una password casuale sono creati al primo avvio e stampati nella
finestra del terminale; la prima login forza il cambio password.

## Cosa cambia rispetto all'installazione

La differenza non è tra sistemi operativi ma tra **prova** e **appliance**.

| | Prova (`start.sh` / `start.bat`) | Installazione (`sudo ./install.sh`, solo Linux/Pi) |
|---|---|---|
| Configurazione di rete | **mai toccata**, solo letta | il Pi si autoconfigura la scheda: DHCP, poi indirizzi statici di fallback |
| Hotspot Wi-Fi | non disponibile | disponibile |
| ARP scan livello 2 | solo se avviato con privilegi (vedi sotto) | sì |
| Avvio automatico | no | servizio `systemd`, parte al boot |
| Dove vive | la cartella del progetto | `/opt/raspiscanner` |

L'installazione serve al caso per cui RaspiScanner è nato: un Raspberry Pi
dedicato, lasciato non presidiato su una rete sconosciuta. Per un
sopralluogo dal proprio portatile la prova è quello che serve.

## Scansione completa senza toccare la rete

L'ARP scan a livello 2 trova anche i dispositivi che non espongono **nessuna**
porta, ma richiede i socket raw: root o `cap_net_raw` su Linux,
[Npcap](https://npcap.com) su Windows.

Senza privilegi RaspiScanner **funziona comunque**: ripiega su uno sweep
TCP-connect più la tabella ARP di sistema. Telecamere, NVR e apparati di rete
espongono quasi sempre un pannello di gestione, quindi per un sopralluogo è
di norma sufficiente — ma un dispositivo del tutto silente può sfuggire. La
dashboard lo segnala (`arp_raw_available: false`).

Per avere lo scan completo **senza** che lo scanner riconfiguri la rete:

```bash
sudo -E RASPISCANNER_NO_NETWORK_CONFIG=1 ./start.sh
```

`RASPISCANNER_NO_NETWORK_CONFIG=1` è la garanzia esplicita: anche da root la
scheda resta come l'ha impostata il sistema. Senza quella variabile, un
avvio da root si comporta come l'appliance — cioè **può riconfigurare la
scheda ethernet** — e `start.sh` avvisa dando cinque secondi per annullare.

Su Windows: installare Npcap (opzione *"WinPcap API compatible"*) e avviare
`start.bat` **come amministratore**.

## Su un Raspberry Pi headless

`start.sh` non prova ad aprire un browser se non c'è una sessione grafica:
stampa l'URL e resta in primo piano. Per raggiungerlo da un altro computer
serve l'IP del Pi al posto di `127.0.0.1`
(`https://192.168.1.42:7332`) — la dashboard ascolta su tutte le interfacce.

## Database vendor (OUI)

Al primo avvio gli script scaricano il registro IEEE completo (~40.000 voci)
in `data/oui_full.csv`, che **non è tracciato da git**: provare lo scanner da
un clone non sporca il checkout. La lista curata `data/oui.csv` inclusa nel
repo resta e ha la precedenza sui nomi che conosce, perché sono più corti e
leggibili in un report (`Hikvision` invece di `Hangzhou Hikvision Digital
Technology Co.,Ltd.`). Senza connessione si usa solo la lista curata.
