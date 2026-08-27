# RaspiScanner — Master TODO

Roadmap toward a 1.0 release, ordered by priority. This is the working
checklist — check items off as they land, keep it in sync with reality
instead of letting it drift into aspirational fiction.

Suggested sequence: **Security (P0) → Robustness (P1 networking bits) →
CCTV/ONVIF (P2) → Tests (P3) → Release (P3 packaging) → new features
(P4, not before 1.0)**. Resist the urge to start P4 before P0-P3 are
done — a small, solid, documented 1.0 beats an endlessly growing 0.x.

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

## 🟠 P1 — Security hardening

- [x] User roles: `admin` / `operator` / `viewer`. *(`scanner.auth`: `ROLES`,
      `ROLE_RANK`, `has_role_at_least`; every route tagged via
      `@require_role(...)` in `raspi-scanner.py`; pre-existing users with no
      role on disk default to `admin`, never silently downgraded.)*
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

## 🟢 P3 — Performance

- [ ] Measure scan times on Raspberry Pi 3B+.
- [ ] Measure scan times on Raspberry Pi 4/5.
- [ ] Optimize timeouts where possible.
- [ ] Evaluate OUI lookup caching.
- [ ] Avoid duplicate scans.
- [ ] Measure RAM usage on large scans.
- [ ] Measure behavior on `/16` networks.

## 🟢 P3 — Dashboard UX

- [ ] Scan progress indicator.
- [ ] Real-time network interface status.
- [ ] VPN status. Wi-Fi status. Hotspot status.
- [ ] Active-subnet indicator.
- [ ] Device count.
- [ ] Visual distinction: Camera / NVR-DVR / Router / PC / Printer /
      Other.
- [ ] Clearly show: Detected / Candidate / Inferred.

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

## 🟢 P3 — Packaging / release

- [ ] Official `1.0.0` version.
- [ ] Changelog.
- [ ] Verified `LICENSE`.
- [ ] Final `README.md`.
- [ ] `SECURITY.md`.
- [ ] `CONTRIBUTING.md`.
- [ ] Final `.gitignore`.
- [ ] Verified `requirements.txt`.
- [ ] Installer verified from scratch on a real Raspberry Pi.
- [ ] Install verified on Debian/Raspberry Pi OS.
- [ ] Install verified on Kali Linux.
- [ ] Verified systemd service.
- [ ] Uninstall procedure.
- [ ] Upgrade procedure.

## 🚀 P4 — Future evolution (not before 1.0)

- [ ] Richer vendor fingerprint database.
- [ ] Vendor-specific fingerprints: Hikvision/Dahua/Axis/Bosch/Ksenia etc.
- [ ] Proprietary NVR detection.
- [ ] VLAN awareness.
- [ ] Optional SNMP discovery.
- [ ] LLDP/CDP discovery.
- [ ] IPv6 discovery.
- [ ] Network topology map.
- [ ] Structured JSON export.
- [ ] Documented API.
- [ ] Webhooks.
- [ ] Comparative reports between scans ("first scan vs current scan").
- [ ] Local asset database.
- [ ] Historical dashboard.
- [ ] Field Technician mode. Audit mode. Continuous Monitoring mode.
