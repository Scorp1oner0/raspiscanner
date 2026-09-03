# RaspiScanner su Windows

RaspiScanner nasce per girare **non presidiato su un Raspberry Pi** buttato
su una rete sconosciuta: si autoconfigura la scheda ethernet (DHCP, poi
fallback sulle classi private), può fare da hotspot Wi-Fi per essere
raggiunto senza cavo, gira come servizio `systemd`.

La **build Windows** serve un caso diverso: il tecnico ha già un portatile
**già connesso** alla rete dell'impianto e vuole, in pochi minuti, sapere
cosa c'è e com'è messo a sicurezza — senza Linux, senza riga di comando,
senza toccare la configurazione di rete del portatile. È lo stesso spirito
di [Field Guardian](https://github.com/Scorp1oner0/field-guardian), ma con
il motore di discovery/classificazione/assessment di RaspiScanner.

## Avvio

1. Installa **Python 3.9+** da <https://www.python.org/downloads/>,
   spuntando **"Add Python to PATH"**.
2. Scarica/clona il repo, doppio click su **`start.bat`**.
   Crea un virtualenv, installa `requirements-windows.txt`, apre la
   dashboard su <https://127.0.0.1:7332> (certificato self-signed: il
   browser mostra un avviso da accettare una volta).

Account admin di bootstrap e password casuale sono creati al primo avvio e
stampati nella finestra del `start.bat` — poi la prima login forza il
cambio password. Uguale a Linux.

## Cosa cambia rispetto al Raspberry Pi

| Ambito | Raspberry Pi | Windows |
|---|---|---|
| Scheda di rete | autoconfig: DHCP → fallback classi private, `ip`/`dhclient` | **sola lettura**: si usa quello che ha già impostato Windows. `mode` è sempre `manual` o `no-network`. "Reconfigure network" si limita a ri-leggere gli indirizzi. |
| Hotspot Wi-Fi | `nmcli device wifi hotspot` | **non disponibile** (l'API "hosted network" di Windows è deprecata e inaffidabile). Il pannello è nascosto. |
| Wi-Fi client | `nmcli` | best-effort via `netsh wlan`: scansione reti OK; la connessione funziona solo se esiste già un profilo salvato per quell'SSID (la prima volta collegati dalla UI Wi-Fi di Windows). |
| ARP scan L2 | scapy + root/`cap_net_raw` | scapy + **Npcap** (vedi sotto). Senza Npcap: ripiego automatico su **sweep TCP-connect + tabella ARP di sistema** (`arp -a`). |
| Gateway / rotte | `ip route` | `route print` + `psutil` |
| Certificato TLS | `openssl` | libreria Python **`cryptography`** (in `requirements-windows.txt`), nessun `openssl` da installare |
| Avvio | servizio `systemd` | `start.bat` (in primo piano, una finestra) |

Tutto il resto — port scan, ONVIF/WS-Discovery, mDNS, SNMP, lookup OUI,
classificazione camera/NVR/apparati, report di assessment, storico, audit,
webhook, continuous monitoring — è **identico** a Linux.

## Npcap (facoltativo ma consigliato)

Per l'ARP scan L2 "vero" (broadcast ARP su tutta la subnet, MAC di ogni
host anche se non espone porte) serve **Npcap**:

1. Installa da <https://npcap.com>, lasciando spuntato
   **"Install Npcap in WinPcap API-compatible Mode"**.
2. Avvia `start.bat` **come amministratore** (i socket raw lo richiedono).

Senza Npcap RaspiScanner **funziona lo stesso**: `GET /api/platform`
riporta `arp_raw_available: false` e la dashboard lo segnala. Il ripiego
scopre gli host che rispondono su almeno una porta comune
(HTTP/HTTPS/RTSP/SSH/porte Hikvision-Dahua/SMB/RDP) e recupera il loro MAC
dalla tabella ARP del sistema operativo — sufficiente per un sopralluogo
dove telecamere, NVR e apparati espongono quasi sempre un pannello di
gestione, ma un dispositivo completamente silente può sfuggire.

## Firewall

Al primo avvio Windows può chiedere di consentire a `python.exe` di
accettare connessioni: serve solo se vuoi aprire la dashboard **da un
altro PC** (`https://<ip-del-portatile>:7332`). Per l'uso locale
(`127.0.0.1`) puoi negare.

## Limiti noti sulla build Windows

- La connessione a una rete Wi-Fi **nuova con password** va fatta la prima
  volta dalla UI di Windows (poi il profilo salvato permette la
  riconnessione dalla dashboard).
- Niente hotspot: se il portatile è in un punto scomodo, collega la
  dashboard via cavo o via Wi-Fi gestito da Windows.
- L'IPv6 discovery e l'ascolto passivo LLDP/CDP richiedono Npcap come
  l'ARP scan; senza, vengono saltati.
