# RaspiScanner — Master TODO

Roadmap toward a 1.0 release, ordered by priority. This is the working
checklist — check items off as they land, keep it in sync with reality
instead of letting it drift into aspirational fiction.

Suggested sequence: **Security (P0) → Robustness (P1 networking bits) →
CCTV/ONVIF (P2) → Tests (P3) → Release (P3 packaging) → new features
(P4)**. Followed in practice: P0-P3 closed first, P4 explicitly
authorized by the user afterward (2026-08-27) rather than before 1.0 as
originally sequenced — see the P4 section header for the full note.

## 📊 Stato attuale (2026-08-27)

- **458 test**, tutti verdi, nessuna regressione nota (rieseguita la
  suite ripetutamente dopo ogni batch, incluso dopo i due fix trovati
  sul Pi reale — vedi sotto).
- **P0 (Security)**: chiuso 4/4.
- **P1 (Hardening)**: chiuso 6/6, con un affinamento RBAC dal vivo (vedi
  quella sezione).
- **P2/P3 Architecture**: 0/2, deliberatamente rimandati (non bloccano
  la 1.0 — vedi la sezione dedicata).
- **P2 (Networking/ONVIF/Security assessment)**: chiuso 14/14.
- **P3 Tests**: chiuso 7/7.
- **P3 Dashboard UX**: chiuso 7/7.
- **P3 Reporting**: chiuso 7/7.
- **P3 Performance**: chiuso 4/7 — misurato dal vivo il tempo di scan su
  Pi 3B+ (vedi sotto); restano Pi 4/5, RAM su scan grandi, reti `/16`.
- **P3 Packaging/release**: chiuso 12/14 — verificato dal vivo
  l'installer da zero su Raspberry Pi OS reale (Pi 3B+); resta solo la
  decisione finale "assegnare 1.0.0", che spetta all'utente.
- **P4 (Future evolution)**: chiuso 15/15 delle voci pianificate per la
  1.0. "Field Technician mode" e' stato tentato, rimosso per un bug non
  isolato sul browser reale, e spostato in **P5 (backlog, post-1.0)** —
  non conta come voce P4 aperta.

### ✅ Test hardware reale del 2026-08-27 (Raspberry Pi 3 Model B Plus)

Primo giro completo end-to-end su hardware fisico vero (non emulato):
SD riscritta da zero, `install.sh` da zero, bootstrap, cambio password,
systemd, HTTPS, scan reale (**~11s** per una `/24`, 4 host), report,
Audit mode, topology, IPv6 discovery — tutto verificato via SSH/curl
diretti contro il dashboard reale. Trovati e corretti **due bug reali**
mai visibili testando solo su x86 (vedi i rispettivi punti P3
Packaging/P4 e il commit dedicato):

1. `install.sh` concludeva erroneamente "nessun account bootstrap
   creato" su una CPU lenta (poll troppo breve dopo il restart del
   servizio).
2. L'Audit mode mostrava una severita' diversa dal report live per lo
   STESSO scan, a causa di un bug di round-trip JSON (chiavi intere di
   `http_banners` diventate stringhe passando per lo storage salvato).

Aggiunto anche, durante la verifica: un pulsante "Chiudi" mancante
sull'audit report in dashboard (segnalato dall'utente durante il test
stesso).

### 🔧 Cosa manca ancora solo per hardware reale (non software)

- Tempo di scan su Raspberry Pi 4/5 (solo un 3B+ era disponibile).
- Uso RAM su scan di reti grandi.
- Comportamento su reti `/16` (limite architetturale gia' identificato
  nel codice — loop host sequenziale — non solo "da misurare", vedi P3
  Performance per il dettaglio).

Nessuno di questi blocca il codice dall'essere corretto oggi: bloccano
solo la certezza empirica su scale/hardware che questa sessione non ha
potuto provare.

## 🔴 P0 — Before publishing/release

- [x] Block the HTTP fallback: if TLS/certificate isn't available, refuse
      to start the dashboard instead of silently serving over plain HTTP.
      Show a clear error. *(`run_dashboard` now `sys.exit(1)`s with a
      clear log/stderr message instead of falling back to `ssl_context=None`.)*
- [x] Remove the fixed default credentials (`RaspiScanner` / `RaspiPass`):
      generate a random initial password (or a bootstrap procedure) and
      force a password change on first login. *(`auth.ensure_default_user`
      generates a random password, marks the account `must_change_password`;
      every endpoint except the password-change one returns 403 until it's
      changed, enforced both server-side and with a blocking overlay in
      the dashboard.)*
- [x] Secure the ONVIF XAddr: validate the address received from the
      device, reject public IPs/arbitrary hostnames — GetDeviceInformation
      must not become an SSRF primitive for whatever XAddr a multicast
      responder feels like sending. *(`onvif._is_safe_xaddr_host`: IPv4
      literals only, must be a private, non-loopback/link-local/multicast/
      reserved address.)*
- [x] Test behavior with no OpenSSL available: verify the service refuses
      to start over HTTP, add an automated test for it. *(`tests/test_raspi_scanner.py`.)*

P0 chiuso: 4/4.

## 🟠 P1 — Security hardening

- [x] User roles: `admin` / `operator` / `viewer`. *(`scanner.auth`: `ROLES`,
      `ROLE_RANK`, `has_role_at_least`; every route tagged via
      `@require_role(...)` in `raspi-scanner.py`; pre-existing users with no
      role on disk default to `admin`, never silently downgraded.
      Rifinito durante il test hardware (2026-08-27) su richiesta esplicita
      dell'utente: `viewer` ora vede SOLO Devices/Cameras (tab nascoste in
      dashboard via `applyRoleBasedTabs()`, non solo cosmetico —
      `/api/report`, `/api/history/*`, `/api/topology`, `/api/audit/report`
      sono stati alzati da `viewer` a `operator`); `operator` vede tutto
      tranne Settings (che resta la sola tab admin-only).)*
- [x] Restrict `/api/settings/users` (create/delete/password/account
      management) to admins only. *(`GET`/`POST /api/settings/users` and
      `DELETE /api/settings/users/<username>` are `@require_role("admin")`;
      `POST /api/settings/users/password` allows self-or-admin: any user can
      always change their own password, only an admin can change someone
      else's.)*
- [x] CSRF protection, especially on every dashboard POST. *(`_origin_is_trusted`
      + Origin check in `_require_auth` for all mutating methods — see next
      item, same mechanism covers both.)*
- [x] Origin/Host checks to avoid unwanted cross-origin requests. *(HTTP Basic
      Auth has no session/cookie, so a classic CSRF token doesn't apply
      cleanly; validating the `Origin` header — when the browser sends one —
      against `request.host_url` blocks the same cross-site-POST attack.)*
- [x] systemd hardening: `NoNewPrivileges`, minimal capabilities,
      `ProtectSystem`, `ProtectHome`, `PrivateTmp`. *(`raspiscanner.service`:
      stays `User=root` — vedi separazione privilegi, spostata in P2/P3
      Architecture qui sotto — ma aggiunge `NoNewPrivileges`,
      `ProtectSystem=true` (non `strict`: dhclient deve poter scrivere
      `/etc/resolv.conf`), `ProtectHome`, `PrivateTmp`,
      `ProtectKernelModules/Logs/Clock/Hostname`, `RestrictSUIDSGID`,
      `RestrictRealtime`, `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW`.
      Validato dal vivo: emerso e risolto un bug reale — con
      `CAP_DAC_OVERRIDE` fuori dal bounding set, root non poteva piu'
      scrivere in `data/` perche' la directory era di proprieta' di un
      utente non privilegiato (creata da un rsync non-root durante il
      deploy); fix: `chown -R root:root /opt/raspiscanner/data`, non un
      allargamento delle capability.)*
- [x] Fix the scan-start race condition: lock before checking
      `_state["running"]`, guarantee only one concurrent scan. *(`run_scan()`
      now does check-then-set atomically under one `with _lock:` block;
      `TestRunScanRaceCondition` in `tests/test_scan_engine.py` reproduces
      the race deterministically with a 20-thread barrier.)*

P1 chiuso: 6/6. La separazione privilegi (sotto) e' stata spostata
formalmente in P2/P3 Architecture, non conta piu' come voce aperta di P1.

## 🟡 P2/P3 — Architecture

- [ ] Privilege separation: evaluate running Flask as non-root, with a
      small privileged helper for ARP/raw sockets, DHCP, `ip`,
      NetworkManager/hotspot. *(Spostato qui da P1: rimane deliberatamente
      rimandato — una riscrittura architetturale non verificabile in modo
      affidabile senza un Raspberry Pi reale, dato che la scansione core
      dipende esattamente dalle operazioni socket a basso livello che
      andrebbero ristrette. Non blocca piu' la chiusura di P1.)*
- [ ] `RestrictAddressFamilies` nel systemd unit: valutato e rimandato
      insieme alla separazione privilegi sopra (stesso rischio di
      riscrittura non verificabile senza hardware reale).

P2/P3 Architecture: 0/2, entrambi deliberatamente rimandati (non
bloccano la 1.0 — richiederebbero una riscrittura architetturale non
verificabile in modo affidabile senza hardware reale su cui provarla).

## 🟡 P2 — Networking robustness

- [x] Avoid IP collisions during DHCP fallback: ARP-probe the `.250`
      candidate before assigning it; pick another address if taken.
      *(`_find_free_static_ip`/`_probe_ip_taken` in `scanner/network/setup.py`:
      probe ARP mirato con psrc "0.0.0.0" (RFC 5227) prima di assegnare
      l'indirizzo, prova `.250/.249/.248/...` finche' non ne trova uno
      libero. `choose_preset_class` ri-verifica al momento della scelta
      manuale, non riusa il risultato del probe automatico.)*
- [x] Better feedback during preset-class probing: show current preset,
      `7/13`, subnet being tried, timeout. *(Nuovi campi di stato
      `probing`/`probe_index`/`probe_total`/`probe_cidr`/`probe_timeout`,
      mostrati in dashboard; verificato via screenshot headless.)*
- [x] Handle `nmcli` errors better: distinguish a real error from
      unexpected output, don't parse solely on fragile `:` splitting.
      *(`scanner/network/nmcli_util.split_nmcli_terse`: rispetta l'escape
      "\:"/"\\" di nmcli, mai un'eccezione su righe malformate. Bug reale
      corretto: un SSID con ":" letterale spezzava anche segnale/sicurezza
      sulla stessa riga con lo split ingenuo precedente.)*
- [x] Installer: separate required vs optional dependencies — a required
      package failing should STOP the install, an optional one should
      only warn. *(`install.sh`: python3-venv/pip/isc-dhcp-client/
      iproute2/openssl fermano l'installazione se falliscono;
      network-manager resta opzionale, solo un avviso.)*
- [x] Review `rsync --delete` carefully: document its behavior, consider
      a `--no-delete` mode. *(Trovato un bug reale nel farlo: install.sh
      non escludeva data/users.json, tls_cert.pem, tls_key.pem, oui.csv
      dal `--delete` — ogni reinstallazione avrebbe cancellato utenti,
      certificato TLS e database vendor scaricato. Fix: stesse esclusioni
      gia' usate per i deploy manuali, + copia una tantum di oui.csv
      minimo se assente. Niente flag `--no-delete` aggiuntivo: le
      esclusioni mirate bastano, un `--delete` generale resta utile per
      non lasciare file di versioni precedenti come residui in giro.)*

P2 Networking robustness chiuso: 5/5.

## 🟡 P2 — ONVIF / CCTV

- [x] Replace the manual XML parsing with a standard XML parser, handle
      ONVIF namespaces properly. *(`scanner/cameras/onvif.py`: parsing via
      `xml.etree.ElementTree` (stdlib, nessuna nuova dipendenza), match sul
      nome locale dell'elemento ignorando prefisso/namespace. Fallback a
      sottostringa solo se l'XML e' davvero malformato. Rifiuta a priori
      qualunque documento con `<!DOCTYPE` prima di passarlo a ElementTree
      — mitigazione "billion laughs"/entity-expansion su XML non fidato
      (arriva da un probe multicast non autenticato). Corretto anche un
      bug reale pre-esistente nel fallback a sottostringa: il valore
      estratto includeva sempre i caratteri "</" del tag di chiusura,
      es. manufacturer "Hikvision" diventava "Hikvision</tds:".)*
- [x] Broaden ONVIF compatibility: test against more vendor
      implementations, differing XML responses, multiple XAddrs.
      *(`get_device_info_multi` prova in ordine OGNI XAddr annunciato
      invece di fermarsi al primo; il match sul nome locale (sopra) tollera
      prefissi di namespace diversi tra vendor. "Test contro piu'
      implementazioni vendor reali" resta intrinsecamente aperto: richiede
      hardware reale di piu' marche, non riproducibile solo con XML di
      esempio scritti a mano.)*
- [x] Improve NVR/DVR identification: add specific fingerprints, separate
      camera / NVR / DVR / encoder / video server. *(`scanner/nvr/classify.py`:
      `classify_nvr` ritorna anche un "subtype" — NVR/DVR/Video
      Encoder/Video Decoder/Video Server quando il banner lo indica
      specificamente (incl. "xvr"/"hcvr" per gli ibridi Dahua), altrimenti
      resta l'etichetta ombrello "NVR/DVR" solo per il segnale generico
      "recorder". `device_type` in scan_engine ora mostra il subtype
      specifico invece del blob unico precedente.)*
- [x] Distinguish "detected" from "guessed" URLs: `RTSP endpoint
      detected` vs `RTSP endpoint candidate`, `Admin URL candidate`.
      *(Nessun URL e' oggi verificato davvero — sarebbe intrusivo aprire
      un vero handshake RTSP — quindi entrambi restano sempre "candidate":
      colonne rinominate "RTSP (candidate)"/"Admin (candidate)" con
      tooltip esplicito invece di un link che sembra un dato confermato.)*
- [x] Never present `rtsp://IP:554/` as a guaranteed stream — label it
      explicitly as a candidate endpoint. *(Stesso fix sopra: link con
      `title` esplicito "Guessed from an open RTSP port, not a verified
      working stream".)*

P2 ONVIF/CCTV chiuso: 5/5 (il test multi-vendor reale resta
intrinsecamente aperto — richiede hardware di piu' marche, non e' un
task software residuo).

## 🟡 P2 — Security assessment

- [x] More precise HTTP classification: `HTTP service detected` / `HTTP
      administrative interface` / `HTTPS available` / `HTTP without
      HTTPS`. *(`scanner/reporting/security.py`: 4 combinazioni distinte
      in base a banner-indica-pannello-admin x HTTPS-anche-disponibile,
      invece dell'unico "HTTP enabled" precedente.)*
- [x] Revisit risk scoring: don't let any HTTP automatically become
      Medium — separate "service exposed" from "actually insecure
      configuration". *(Severita' ora varia low/medium/high in base al
      contesto: HTTP generico con HTTPS disponibile = low; HTTP senza
      HTTPS o pannello admin con HTTPS disponibile = medium; pannello
      admin senza HTTPS = high. Prima: sempre "medium" per qualunque
      porta HTTP a prescindere dal contesto.)*
- [x] More specific findings: Telnet, HTTP admin, exposed RTSP, legacy
      services, known CCTV ports. *(Aggiunto un finding dedicato "RTSP
      exposed" (porta 554, prima non generava nessun finding di
      sicurezza, solo usata per la classificazione camera). Telnet e
      HTTP admin coperti dai punti sopra. Legacy services/porte CCTV
      specifiche (FTP, SNMP, porte proprietarie Dahua/Hikvision) restano
      candidati per un giro futuro — non aggiunti ora per non allargare
      lo scope oltre il segnale piu' concreto e gia' verificato (RTSP).)*
- [x] Document clearly that this is not a vulnerability scanner: no
      exploits, no brute force, no credential guessing, no CVE scanning.
      *(Frase esplicita "not a vulnerability scanner" aggiunta in 3 posti
      visibili all'utente: nota di sicurezza in dashboard, README, e come
      riga finale di `assessment.generate_all()` — non solo nei commenti
      del codice, dove gia' c'era.)*

P2 Security assessment chiuso: 4/4.

## 🟢 P3 — Tests

- [x] Full integration test: Flask → scan → classification → report.
      *(`tests/test_integration_scan_report.py`: discovery grezza mockata
      al confine (ARP/ONVIF/mDNS/port scan/banner — richiederebbero
      root/hardware reale), ma build_device, classificazione, security
      findings e generazione del report sono codice vero, non stub.)*
- [x] Concurrency tests: two simultaneous `/scan/start`, scan + network
      reconfiguration, stop mid-scan. *(Due `/scan/start` gia' coperto in
      P1 (`TestRunScanRaceCondition`). Aggiunto
      `TestScanAndNetworkReconfigureConcurrently` (scan_engine +
      network.setup in parallelo, nessun deadlock/crash) e
      `test_stop_scan_mid_flight_leaves_state_consistent` (stop
      deterministico via un Event, non un test "a tempo").)*
- [x] Malicious-input tests: malformed ONVIF XML, malicious XAddr,
      malformed mDNS, odd hostnames, huge/malformed HTTP banners.
      *(ONVIF XML/XAddr e mDNS malformati gia' coperti in P2/sessioni
      precedenti. Aggiunto `tests/test_fingerprint.py` per banner HTTP
      enormi/troncati/non-UTF8/connessione rifiutata — trovato e corretto
      un bug reale: un singolo controllo di porta che sollevava
      un'eccezione inattesa faceva perdere il risultato di TUTTE le altre
      porte dello stesso host. Aggiunti hostname "odd" (lunghezza
      estrema, unicode, caratteri di controllo) in `tests/test_hosts.py`.)*
- [x] Test `nmcli` with unexpected output. *(Gia' coperto in P2
      (`tests/test_nmcli_util.py`, escape/righe malformate); qui aggiunta
      la distinzione con "nmcli assente" (sotto), scenario diverso da
      "nmcli presente ma output inatteso".)*
- [x] Test absence of system commands: `openssl`, `dhclient`, `nmcli`,
      `ip`. *(`openssl` gia' coperto in `test_tls.py`. Aggiunta
      `TestMissingSystemCommands` in `tests/test_network_setup.py`
      (dhclient/ip assenti: `_run` None -> `try_dhcp` False ->
      autoconfigure_ethernet arriva comunque a "no-network" senza
      eccezioni; nmcli assente per wifi_scan/wifi_connect) e
      `TestMissingNmcli` in `tests/test_hotspot.py` (start/stop hotspot).)*
- [x] Installer/service tests. *(`tests/test_installer.py`: sintassi bash
      di install.sh, `systemd-analyze verify` sul unit file (validazione
      statica reale, non solo grep), e guardrail di regressione espliciti
      sui due bug scoperti dal vivo in questa sessione — esclusioni
      rsync per data/users.json/tls_*.pem/oui.csv, e il chown esplicito
      di data/.)*

P3 Tests chiuso: 7/7.

## 🟢 P3 — Performance

- [x] Measure scan times on Raspberry Pi 3B+. *(Misurato dal vivo il
      2026-08-27 su un Pi 3B+ reale (1GB RAM): scan completo di una
      rete `/24` (254 host possibili, 4 realmente attivi) in **~11
      secondi** (`started_at`/`finished_at` reali, non stimati),
      classificazione completa inclusa (router MikroTik via
      vendor+gateway, due Raspberry Pi via OUI, un PC via SMB/RDP).
      Non e' un dato su una rete satura di centinaia di host (vedi la
      voce "/16 networks" sotto, che resta un limite architetturale
      distinto), ma la prima misura reale su questa classe di
      hardware.)*
- [ ] Measure scan times on Raspberry Pi 4/5. *(Richiede hardware reale
      di quel modello specifico, non disponibile in questa sessione —
      solo un Pi 3B+ era disponibile.)*
- [x] Optimize timeouts where possible. *(Bug reale trovato e corretto:
      `config.PORT_SCAN_THREADS = 60` era definita ma MAI letta dal
      codice — `scan_ports()` usava sempre un valore fisso di 16 worker.
      Con la lista di default (22 porte) questo significava due round da
      `PORT_SCAN_TIMEOUT` invece di uno solo per ogni host. Fix + test
      che verifica la dimensione del pool effettivamente usata.
      L'opportunita' piu' grossa resta pero' un'altra, vedi nota sotto
      su "/16 networks" — non e' un timeout da tarare, e' un cambio
      architetturale piu' rischioso.)*
- [x] Evaluate OUI lookup caching. *(Gia' corretto: `vendor.py` carica il
      CSV in un dict UNA sola volta (flag `_loaded`), ogni lookup
      successivo e' O(1) su dict gia' in memoria. Nessuna modifica
      necessaria.)*
- [x] Avoid duplicate scans. *(Gia' garantito dal fix P1 della race
      condition su `run_scan()`: due `/scan/start` concorrenti non
      possono piu' avviare due scan paralleli sovrapposti. All'interno
      di un singolo scan, arp_scan/orphan-filtering gia' deduplicano per
      IP, nessun host viene processato due volte.)*
- [ ] Measure RAM usage on large scans. *(Richiede una rete reale grande
      per una misura significativa — non riproducibile da qui.)*
- [ ] Measure behavior on `/16` networks. *(Non misurabile senza una rete
      reale di quella dimensione, ma revisionando il codice e' emerso un
      limite architetturale concreto, non solo ipotetico: in
      `scan_engine._run_scan_thread`, il loop che processa `all_hosts`
      e' SEQUENZIALE, un host alla volta — il port scan interno a
      ciascun host e' gia' parallelo (ThreadPoolExecutor), ma tra un
      host e il successivo non c'e' parallelismo. Su una `/16` con
      centinaia/migliaia di host vivi, questo e' il fattore dominante
      sulla durata totale dello scan, molto piu' di qualunque singolo
      timeout. Non parallelizzato qui: introdurrebbe rischi reali di
      correttezza (thread-safety di onvif_results/mdns_results
      condivisi, reattivita' dello stop-flag a meta' di un batch,
      ordine di `_update(progress=...)`) che non posso verificare in
      modo affidabile senza una rete grande reale su cui provarlo —
      stessa cautela gia' applicata alla separazione dei privilegi in
      P2/P3 Architecture.)*

P3 Performance chiuso: 3/7 — le 4 voci aperte richiedono TUTTE hardware
reale (vedi "Cosa manca solo per hardware reale" in cima al file), non
sono lavoro software rimasto.

## 🟢 P3 — Dashboard UX

- [x] Scan progress indicator. *(Gia' presente: barra di avanzamento +
      percentuale + IP corrente, polling ogni 1.5s.)*
- [x] Real-time network interface status. *(Gia' presente: polling ogni
      5s su `/api/network`.)*
- [x] VPN status. Wi-Fi status. Hotspot status. *(Gia' presenti: box VPN
      per interfaccia, box Wi-Fi per scheda con reti visibili, modale
      hotspot con stato/generazione password.)*
- [x] Active-subnet indicator. *(Gia' coperto dai box di stato per
      interfaccia — mostrano mode/IP/CIDR attivi; il P2 "Probing preset
      network X/13" aggiunge anche il progresso durante la ricerca
      attiva della subnet giusta.)*
- [x] Device count. *(Gia' presente: tile KPI "DEVICES" in cima.)*
- [x] Visual distinction: Camera / NVR-DVR / Router / PC / Printer /
      Other. *(Gia' presente: `device_type` (ora piu' granulare da P2:
      NVR/DVR/Video Encoder/Video Decoder distinti) + badge colorati.)*
- [x] Clearly show: Detected / Candidate / Inferred. *(RTSP/Admin URL
      gia' etichettati "(candidate)" in P2. Aggiunto qui: nuovo campo
      `model_source` ("onvif"/"mdns"/None) su ogni device — il Model in
      tabella non e' mai indovinato, e' sempre cio' che il dispositivo ha
      dichiarato di se stesso via un protocollo strutturato; il tooltip
      lo rende esplicito ("self-reported via ONVIF/mDNS") invece di
      lasciarlo ambiguo. Verificato via screenshot headless.)*

P3 Dashboard UX chiuso: 7/7.

## 🟢 P3 — Reporting

- [x] Improve the HTML report. *(Non esiste un file HTML separato da
      scaricare — l'unica "versione HTML" del report e' il rendering
      nella scheda Report della dashboard, ora con evidenziazione colorata
      delle severita' (vedi sotto). Un vero export HTML standalone
      sarebbe una feature nuova, non un miglioramento di qualcosa di
      esistente — lasciato fuori scope per non allargare P3.)*
- [x] Improve PDF/print layout, if planned. *(Non applicabile: nessuna
      generazione PDF/print e' mai stata pianificata nel codice esistente
      — condizione "if planned" non soddisfatta, nessuna azione dovuta.)*
- [x] Add scan timestamp, interface used, subnet analyzed, scan duration.
      *(`assessment.generate_all` accetta `started_at`/`finished_at` da
      `scan_engine.get_state()`; ogni report per-rete mostra anche
      l'interfaccia usata, oltre alla subnet gia' presente.)*
- [x] Add a summary: devices, cameras, NVRs, infrastructure, findings.
      *(Riga "Summary: N cameras, N NVR/DVR, N network devices, N security
      findings" subito dopo "N devices discovered".)*
- [x] Highlight Critical/High/Medium/Low severity. *(Nella dashboard: le
      righe RISK SUMMARY e le righe "⚠" nella scheda Report sono colorate
      per severita' — testo prima sempre escaped, poi solo righe con un
      prefisso ESATTO noto vengono avvolte in uno span colorato, nessun
      rischio di injection da campi controllati dal dispositivo
      scansionato. Verificato via screenshot headless.)*
- [x] Add a disclaimer about sensitive data. *(Riga finale di
      `generate_all()`: "This report may contain sensitive network
      data...".)*
- [x] Clearly state the report can contain IP/MAC/hostname. *(Stesso
      disclaimer sopra, esplicito su IP/MAC/hostname/vendor/model/banner.)*

P3 Reporting chiuso: 7/7.

## 🟢 P3 — Packaging / release

- [ ] Official `1.0.0` version. *(Decisione dell'utente, non mia: numerare
      1.0.0 e' una dichiarazione di stabilita'/completezza verso chi lo
      installa, e i tre item hardware sotto (Pi reale, Debian/RPi OS,
      installer da zero) non sono ancora verificati. Non assegnato senza
      conferma esplicita.)*
- [x] Changelog. *(`CHANGELOG.md`, formato Keep a Changelog, sezione
      "Unreleased" — niente numero di versione finche' non se ne decide
      uno, vedi punto sopra.)*
- [x] Verified `LICENSE`. *(MIT, presente e valida, nessuna modifica
      necessaria.)*
- [x] Final `README.md`. *(Aggiornato incrementalmente per tutta la
      sessione; aggiunte qui le sezioni Upgrading/Uninstalling.)*
- [x] `SECURITY.md`. *(Scope di sicurezza specifico di questo progetto
      — gira come root, espone una dashboard sulla rete scansionata —
      + procedura di segnalazione privata via GitHub.)*
- [x] `CONTRIBUTING.md`. *(Setup sviluppo, convenzioni gia' in uso nel
      progetto — lingua commenti/commit vs stringhe utente, niente nuove
      dipendenze senza motivo forte, input non fidato trattato come
      tale — checklist prima di una PR.)*
- [x] Final `.gitignore`. *(Gia' completo: venv/pycache, log, i 3 file
      sensibili generati al primo avvio. `data/oui.csv` NON e' ignorato
      di proposito — e' la versione minima committata nel repo, quella
      completa scaricata da update_oui.py e' locale-only e va ripristinata
      con `git checkout` prima di ogni commit, non ignorata.)*
- [x] Verified `requirements.txt`. *(Solo Flask e scapy, range di versioni
      gia' presenti — coerente con la scelta deliberata di non aggiungere
      dipendenze, vedi CONTRIBUTING.md.)*
- [x] Installer verified from scratch on a real Raspberry Pi. *(Fatto dal
      vivo il 2026-08-27: SD riscritta da zero (Raspberry Pi OS Trixie
      via `dd` + cloud-init, dopo che Raspberry Pi Imager e' crashato
      due volte per un bug proprio — non nostro), `sudo ./install.sh`
      su un Raspberry Pi 3B+ reale, tutto verificato via SSH: pacchetti
      apt, venv, OUI database completo scaricato, servizio systemd
      avviato, password bootstrap generata e stampata, cambio password,
      HTTPS raggiungibile, scan reale (~11s, vedi P3 Performance), Audit
      mode e topology interrogati con successo. Trovati e corretti DUE
      bug reali mai visibili su x86 (vedi P3 Tests/CHANGELOG): il
      polling della password bootstrap troppo aggressivo per una CPU
      lenta, e un bug di round-trip JSON che degradava la severita' di
      un finding nell'Audit mode.)*
- [x] Install verified on Debian/Raspberry Pi OS. *(Stessa verifica sopra
      — Raspberry Pi OS Trixie (basato su Debian) e' esattamente il
      target "Debian/RPi OS puro" che mancava rispetto alla verifica
      Kali gia' fatta.)*
- [x] Install verified on Kali Linux. *(Fatto davvero in questa sessione,
      non solo sulla carta: installazione pulita con `sudo ./install.sh`
      su questa macchina Kali, servizio partito, dashboard raggiungibile
      via HTTPS e via VPN WireGuard dal telefono, hardening systemd
      validato dal vivo (incluso un bug reale trovato e corretto sulla
      proprieta' di data/), cambio password confermato funzionante.)*
- [x] Verified systemd service. *(Stessa validazione dal vivo sopra, piu'
      `systemd-analyze verify` automatizzato in tests/test_installer.py.)*
- [x] Uninstall procedure. *(`uninstall.sh`, con `--keep-data` opzionale;
      documentato in README.)*
- [x] Upgrade procedure. *(Documentato in README: `git pull` +
      `sudo ./install.sh`, sicuro da rieseguire grazie alle esclusioni
      rsync gia' corrette in P2/questa sessione.)*

P3 Packaging/release chiuso: 10/14 — le 4 voci aperte sono 3 verifiche
hardware (Pi reale, Debian/RPi OS puro, installer da zero su hardware)
piu' la decisione finale "assegnare la versione 1.0.0", che spetta
esplicitamente all'utente, non e' automatica.

## 🚀 P4 — Future evolution

Nota: la sequenza originale prevedeva di non toccare P4 prima della 1.0.
L'utente ha esplicitamente autorizzato di iniziarlo in questa sessione
mentre le verifiche hardware restanti (vedi P3 Performance/Packaging)
sono rimandate a una sessione con un Raspberry Pi reale disponibile —
non e' un cambio di priorita' silenzioso.

- [x] Richer vendor fingerprint database. *(`scanner/cameras/classify.py`:
      nuovo `guess_vendor_from_banner()`, usato da scan_engine come
      fallback SOLO quando il lookup OUI (MAC) non da' un vendor noto —
      il database OUI locale e' minimo (~120 voci), un dispositivo il cui
      banner dice letteralmente "Hikvision" non deve restare "Unknown".
      Nuovo campo `vendor_source` ("oui"/"banner"/"onvif") mostrato in
      dashboard con tooltip, stesso principio gia' usato per
      `model_source` in P3.)*
- [x] Vendor-specific fingerprints: Hikvision/Dahua/Axis/Bosch/Ksenia etc.
      *(Hikvision/Dahua/Axis gia' presenti nei keyword di classificazione
      camera; aggiunti Bosch e Ksenia. `guess_vendor_from_banner()`
      copre lo stesso elenco piu' Reolink/Foscam/Vivotek, con un
      fallback generico "uc-httpd" per le board OEM DVR/NVR cinesi non
      attribuibili con certezza a un vendor specifico — mai inventati
      segnali/porte non verificabili con sicurezza.)*
- [x] Proprietary NVR detection. *(Copertura vendor per NVR/DVR e'
      la STESSA funzione di cui sopra (banner-based, indipendente dal
      tipo di dispositivo): un NVR con banner "Dahua" viene attribuito
      correttamente anche se il MAC non e' nel database OUI. Porte
      proprietarie specifiche (Dahua 37777/34567) erano gia' coperte da
      prima; non aggiunte porte per altri vendor senza una fonte
      affidabile da verificare — un segnale sbagliato sarebbe peggio di
      nessun segnale.)*
- [x] VLAN awareness. *(`scanner/discovery/arp.py`: nuovo `extract_vlan_id()`
      legge il layer Dot1Q (802.1Q) dal frame catturato, se presente.
      Propagato fino al device finale (`vlan_id`), mostrato in dashboard
      SOLO quando non None — la maggior parte delle porte sono "access"
      (lo switch toglie il tag prima di consegnare il frame), quindi None
      e' l'esito normale, non un errore: niente colonna sempre vuota.
      Non verificabile con un vero switch trunk in questa sessione, ma la
      logica di estrazione e' testata direttamente con un frame Dot1Q
      costruito a mano — corretta a prescindere dall'hardware disponibile.)*
- [x] Optional SNMP discovery. *(`scanner/discovery/snmp.py`: GET
      sysDescr/sysName via SNMP v2c, community "public" (la convenzione
      universale di sola lettura, MAI una lista indovinata — sarebbe
      credential guessing, fuori scope). Provato SOLO su host gia'
      classificati come apparato di rete (`is_infra`), non su ogni host:
      SNMP e' spento sulla stragrande maggioranza dei device, provarlo
      su tutti aggiungerebbe un timeout per host all'intero scan senza
      guadagno reale. `sysDescr` riempie il vendor solo se ancora
      "Unknown" (nuovo `vendor_source="snmp"`), `sysName` riempie
      l'hostname solo se mancante. Non verificabile con un vero
      dispositivo SNMP-enabled in questa sessione: parsing testato con
      risposte SNMP costruite a mano (round-trip byte a byte, non
      oggetti scapy "freschi" — differenza scoperta scrivendo il test).)*
- [x] LLDP/CDP discovery. *(`scanner/discovery/lldp_cdp.py`: sniff passivo
      (AsyncSniffer, nessun pacchetto inviato — questi protocolli sono
      annunci periodici spontanei) su multicast LLDP/CDP per la durata
      dello scan, parsing di chassis ID/port ID/system name/description.
      Frame LLDP e CDP costruiti a mano nei test: scoperto che un oggetto
      scapy appena creato non ha i campi ASN.1/tipizzati coerenti finche'
      non viene serializzato e riparsato — stesso problema gia' visto con
      SNMP, stessa correzione (round-trip byte a byte nei test).)*
- [x] IPv6 discovery. *(`scanner/discovery/ipv6.py`: ICMPv6 Echo Request
      verso il multicast "all-nodes" ff02::1 — IPv6 non ha broadcast, ma
      ogni nodo IPv6 attivo ascolta quell'indirizzo per definizione di
      protocollo (RFC 4291), quindi non serve conoscere in anticipo nessun
      indirizzo, esattamente come l'ARP sweep per IPv4. Probe supplementare
      alla scoperta IPv4 principale, non un secondo scan indipendente:
      corre in parallelo per interfaccia insieme a ONVIF/mDNS/LLDP-CDP,
      skippato sulle interfacce NOARP (nessun L2 su cui inviare un frame
      multicast Ethernet, stesso motivo di LLDP/CDP). Nuovo campo
      `device["ipv6_addresses"]` (lista, non singolo valore: un host puo'
      rispondere da piu' di un indirizzo, es. privacy extension RFC 4941),
      correlato per MAC. Le risposte sono quasi sempre link-local
      (fe80::...): la selezione dell'indirizzo sorgente IPv6 preferisce lo
      stesso scope della destinazione (RFC 6724), un indirizzo globale non
      emerge da questo probe. Verificato dal vivo il 2026-08-27 su hardware
      reale (Raspberry Pi 3B+ + rete domestica): 2 dei 4 device dello scan
      hanno risposto con un indirizzo link-local reale, uno dei quali
      combacia esattamente con l'EUI-64 derivato dal suo MAC
      (`b8:27:eb:36:ba:b9` -> `fe80::ba27:ebff:fe36:bab9`) — comportamento
      SLAAC corretto, non solo teoricamente plausibile. Prima di quella
      verifica: `parse_icmpv6_echo_reply()` testato con un Echo Reply
      costruito a mano, stesso trattamento round-trip-a-bytes gia'
      necessario per SNMP/LLDP/CDP.)*
- [x] Network topology map. *(GET /api/topology, nuova sezione "Topology
      (one-hop)" in dashboard. Per-interfaccia: gateway (gia' noto) +
      vicini LLDP/CDP. Deliberatamente UN SOLO hop, non un grafo
      multi-hop: quello richiederebbe SNMP-walk su switch remoti con
      credenziali che lo scanner non ha e non deve indovinare — fuori
      scope, documentato come tale in `API.md`. Il vicino LLDP/CDP viene
      anche correlato al device scoperto via ARP con lo stesso MAC
      (chassis_id), popolando `device["lldp_cdp_info"]`. Non verificabile
      con hardware LLDP/CDP-enabled reale in questa sessione: correlazione
      testata end-to-end in `test_integration_scan_report.py` con vicini
      costruiti a mano. Nota anche nella UI: un elenco vuoto non significa
      "nessun vicino", solo che nessuno ha trasmesso durante i pochi
      secondi dello scan — questi protocolli hanno un timer proprio,
      tipicamente 30-60s.)*
- [x] Structured JSON export. *(`/api/export?format=json` ora ritorna un
      envelope con metadati — `exported_at`, `type`, `count`,
      `scan_started_at`/`scan_finished_at`, `devices` — invece di un
      array nudo: un consumatore esterno sa quando i dati sono stati
      raccolti senza doverlo dedurre da un header HTTP. CSV invariato
      (resta tabellare per natura). Cambio di forma pre-1.0, nessun
      consumatore esterno esisteva prima che l'API fosse documentata in
      questa stessa sessione.)*
- [x] Documented API. *(`API.md`, nuovo: ogni endpoint con ruolo richiesto,
      request/response, e lo schema completo del "device object". Test
      di regressione (`tests/test_api_docs.py`) che tiene la doc
      sincronizzata con le route reali in entrambe le direzioni — nessuna
      route nuova non documentata, nessuna route documentata ma rimossa.)*
- [x] Webhooks. *(`scanner/webhooks.py`: notifica opzionale via POST JSON
      a fine scan, configurazione admin-only (`data/webhooks.json`, mai
      committato). Solo URL http/https accettati (mai `file://`, anche
      se l'URL e' scelto da un admin autenticato — non e' lo stesso
      rischio SSRF dell'XAddr ONVIF, ma resta la forma minima corretta).
      Best-effort: un fallimento (timeout, URL irraggiungibile) e' solo
      loggato, non fa mai fallire lo scan. API `GET`/`POST
      /api/settings/webhook`, sezione dedicata in Impostazioni.)*
- [x] Comparative reports between scans ("first scan vs current scan").
      *(`storage.compare_scans()`: confronto per MAC tra due scan salvati
      — added/removed/changed (con i campi esatti cambiati). Device
      senza MAC esclusi dal confronto (IP non affidabile come identita'
      nel tempo). UI dedicata nella tab History: due tendine + pulsante
      "Compare".)*
- [x] Local asset database. *(`scanner/storage.py`, SQLite (stdlib,
      nessuna nuova dipendenza) — `data/history.db`, mai committato,
      escluso dal `rsync --delete` di install.sh come users.json/tls_*.pem.
      Ogni MAC visto almeno una volta viene tracciato con first_seen/
      last_seen/times_seen, aggiornato a ogni scan. Un device senza MAC
      resta fuori dall'asset tracking per lo stesso motivo dei report
      comparativi.)*
- [x] Historical dashboard. *(Nuova tab "History" in dashboard: elenco
      scan passati, confronto tra due scan, elenco asset noti. Salvataggio
      dello storico avviene automaticamente a fine di OGNI scan (anche
      fermato a meta' o terminato con errore — resta un'istantanea reale),
      dentro `scan_engine._run_scan_thread`, mai bloccante per lo scan
      stesso se il salvataggio fallisce.)*
- [x] Audit mode. Continuous Monitoring mode.
      *(Nessuna specifica precedente esisteva per questi due nomi:
      interpretazione minima, esplicita, che riusa l'infrastruttura P4
      gia' scritta invece di aprire un sottosistema nuovo per ciascuno.

      **Continuous Monitoring**: `scanner/monitoring.py`, uno scheduler
      che chiama scan_engine.run_scan() — la STESSA funzione del pulsante
      "Start scan" — a intervalli configurabili (minimo 5 minuti, per
      non far accavallare scan su reti con molti host). Se uno scan e'
      gia' in corso, il giro viene saltato (mai forzato/in coda). Ogni
      scan salvato (manuale o automatico) calcola ora un diff col
      precedente (storage.compare_scans) incluso nel payload webhook
      (`changes_since_previous_scan`), cosi' il continuous monitoring ha
      un senso concreto insieme al webhook gia' esistente: sapere COSA e'
      cambiato, non solo che uno scan e' finito.

      **Audit mode**: nuovo `GET /api/audit/report`, distinto da
      `/api/report` (stato LIVE, puo' essere un'istantanea parziale a
      scan in corso) — genera invece da uno scan gia' SALVATO
      (riproducibile: lo stesso scan_id da' sempre lo stesso report), con
      la sezione "CHANGES SINCE PREVIOUS SCAN" anteposta automaticamente
      (stesso compare_scans, nuovi storage.get_scan_meta()/
      get_previous_scan_id()). Pulsante "Audit report" per riga nella tab
      History.

      425 -> 451 test (26 nuovi: scheduler, storage, sezione "changes"
      del report, route Flask). Nessuna regressione.)*

P4 chiuso: 15/15 delle voci pianificate per la 1.0. "Field Technician
mode" era nel backlog P4 originale ma e' stato tentato, rimosso, e
spostato in **P5 (backlog, post-1.0)** qui sotto — non conta come voce
P4 aperta, e non blocca la 1.0.

## 🧪 P5 — Backlog (post-1.0, non richiesto per la 1.0)

Idee valutate ma deliberatamente rimandate oltre la 1.0 — non bloccano
la release, da riprendere solo se richiesto esplicitamente in futuro.

- [ ] Field Technician mode. *(Tentato e rimosso il 2026-08-27: un
      toggle client-side che nascondeva History/Settings via
      `body.technician-mode` + CSS non si comportava in modo affidabile
      sul browser reale usato per il test hardware (la classe risultava
      applicata secondo la console, ma le tab restavano visibili —
      causa non isolata prima che l'utente chiedesse di rimuoverlo).
      Codice e pulsante rimossi da index.html/app.js/style.css per non
      lasciare una feature visibile ma non funzionante. Da ripensare
      (eventualmente con un approccio diverso, es. classe su un
      contenitore piu' vicino invece che su `<body>`) solo se richiesto
      di nuovo esplicitamente.)*
- [ ] Privilege separation (vedi P2/P3 Architecture sopra): stessa voce,
      elencata anche qui perche' e' un candidato naturale per un futuro
      giro di lavoro con hardware reale disponibile, non solo "rimandata
      a tempo indeterminato".
- [ ] Multi-hop network topology (SNMP-walk su switch remoti): fuori
      scope per design, non solo per questa sessione — richiederebbe
      credenziali che lo scanner non ha e non deve indovinare. Elencato
      qui solo come nota per chi in futuro volesse valutare un modello
      "bring your own credentials" esplicito e opt-in.
