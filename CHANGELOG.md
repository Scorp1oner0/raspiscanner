# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## [1.7.0] - 2026-11-17

### Added

- **The network map now works on a network it has never seen.** It uses two
  new probes and no credentials, and nothing about any particular network is
  written in the code:
  - **Path to the Internet.** The first hops of a traceroute to
    `1.1.1.1`, stopping at the first public address (the provider's router),
    drawn as a row above the networks: scanner, each router on the way
    (named when the scan found it, otherwise "Router" with its address and
    delay), then the provider router and Internet. This is the one probe
    that leaves the local network, towards a single address. Switch it off
    with `RASPISCANNER_TRACE_TARGET=` (empty) or point it elsewhere.
  - **DHCP servers.** On each Ethernet and Wi-Fi network it sends one
    DHCPDISCOVER with an invented hardware address and listens for the
    offers, never sending the request, so no address is taken. For every
    server it shows who it is, the gateway and DNS it recommends. Switch it
    off with `RASPISCANNER_DHCP_PROBE=0`.
  - **Roles.** Each device carries its roles: gateway, DHCP server, DNS
    (offered by DHCP or with port 53 open), bridge between two networks, or
    this scanner. Each network box shows its gateway and its DHCP servers.
  - **One device, several addresses.** Addresses answering with the same MAC
    in the same network are drawn as one device with "+N".
- The same additions are drawn in the PDF map. `GET /api/topology` now has a
  `dhcp` list per interface and `GET /api/topology/map` has `uplink`, `roles`,
  `ips` and each network's `dhcp`; `GET /api/scan/status` carries `uplink`.

## [1.6.0] - 2026-11-17

### Added

- **The network map is the last page of the PDF report.** The downloaded
  PDF of the current scan ends with the same map the History tab draws:
  the scanner, each network with its gateway, the devices found in it, and
  a dashed line for a device seen in two networks. It is drawn as vector
  graphics, continues on more pages when a network has many devices, and is
  left out of the audit PDF of an older saved scan, because the saved scan
  keeps the devices but not the interfaces and gateways it was made on.

### Fixed

- The History tab (network map and one-hop topology) showed "No map yet"
  when it was opened while a scan was still running, and stayed that way
  after the scan ended. It now refreshes by itself when the scan finishes
  while History is open.

## [1.5.0] - 2026-11-17

### Added

- **Network map.** The History tab now draws the networks the last scan
  covered: the scanner on the left, each network on its interface (Ethernet,
  Wi-Fi or VPN) with its gateway, and the devices found in it. A device seen
  in two networks under the same name (a Raspberry Pi on cable and Wi-Fi)
  is marked as a bridge and linked between them, and the scanner's own
  addresses are linked the same way. It is built only from what the scan
  already saw, with no credentials and nothing asked of switches or
  routers, so it can't say which switch port or access point a device of
  the same network hangs on. New `GET /api/topology/map` (operator), see
  `API.md`. The existing one-hop `GET /api/topology` is unchanged.

## [1.4.0] - 2026-11-17

### Added

- **Choose which detected networks to scan.** Until now the dashboard could
  only scan every network found on an active interface or none of them. The
  "Scan targets" card now lists each detected network (Ethernet, every
  Wi-Fi adapter, every VPN tunnel) with a checkbox, so a scan can cover the
  home network and skip a VPN or a phone hotspot. The choice is saved in
  `data/targets.json` as a new `excluded` list and applies to manual scans
  and to Continuous Monitoring alike. A network that shows up later is
  scanned until you untick it, and an unticked one that is not connected
  right now stays in the list ("not connected now") so it can be ticked
  again. The list refreshes every 10 seconds, so a VPN connected while the
  dashboard is open appears by itself.
- `POST /api/settings/targets` takes `excluded` (omit it to keep the saved
  list), `GET /api/settings/targets` returns it, and `GET /api/scan/targets`
  adds `detected` (every network seen now, with `scanned: true|false`) and
  `excluded`. A scan with every detected network unticked answers `409`
  with a message saying so, instead of the generic "no active network".

### Fixed

- The plain-text report download sent `Content-Type: text/plain;
  charset=utf-8; charset=utf-8` (the charset twice). It is now sent once.
- In the deep scan window, a service name such as "HTTP-Alt" no longer
  wraps onto two lines.

## [1.3.1] - 2026-11-17

### Fixed

- The PDF of an **audit report** said "Network assessment report" like the
  live one. It now says "Audit report - scan #N", in the page header and in
  the document title.

## [1.3.0] - 2026-11-17

### Added

- **Save the report as a PDF or a text file.** "⬇ PDF" and "⬇ TXT" in the
  Report tab download the live report; each scan in the History tab has a
  "⬇ PDF" for its audit report, and the audit box has both. Same endpoints
  as the on-screen report with a new `format` parameter
  (`/api/report?format=pdf|txt`, `/api/audit/report?scan_id=N&format=pdf|txt`,
  operator): JSON stays the default. The PDF is A4 with a header band, a
  device table per category, findings colored by severity, the risk summary
  as four boxes, page numbers and the usual disclaimers; a report taken
  mid-scan is marked as a partial snapshot, and the audit version includes
  the changes since the previous scan.
- It is written by hand with the standard library only (Helvetica and
  Courier, which every PDF viewer has built in), so there is still no
  dependency beyond Flask and Scapy and nothing extra to install on a Pi.
  Characters outside Western European text (non-Latin names, emoji) print
  as `?`.

### Changed

- `scanner/reporting/assessment.py` now builds a structured description of
  each network (`network_data`, `report_data`) and the text report is
  formatted from it, so the text and the PDF cannot disagree. The text
  output is unchanged.

## [1.2.0] - 2026-11-17

### Added

- **Extended port profile.** A selector next to "Start scan" picks
  between the 23 common ports (default, unchanged) and an extended list of
  84: NAS, IoT, databases, MQTT, MikroTik, alternative web and RTSP ports.
  The dashboard warns that it includes ports honeypots use as bait.
  `POST /api/scan/start` takes `{"port_profile": "common" | "extended"}`,
  `GET /api/scan/profiles` returns how many ports each one checks.
- **Deep port scan of one device.** A "🔎 Deep scan" button on each row of
  the device table scans a chosen range, up to all 65535 TCP ports, on that
  device only, in the background and with a progress bar, then reads the
  banner of every open web port (HTTP, then HTTPS on ports with no fixed
  scheme). Results are added to the device and count for the report's
  security findings. New endpoints `POST /api/devices/deep-scan`,
  `GET /api/devices/deep-scan`, `POST /api/devices/deep-scan/stop`
  (operator). Only devices found by the last scan can be targeted, and not
  while a network scan is running.

### Changed

- Web banners are now read on the alternative web ports of the extended
  list too (3000, 4443, 5001, 7332, 8088, 8888, 9443...), trying HTTP first
  and HTTPS after on ports that have no fixed scheme.

### Fixed

- **HTTPS banners were always empty.** The banner request verified the
  certificate, and cameras, NVRs, routers and Pi-hole almost always use a
  self-signed one, so the connection failed and `http_banners` showed
  `null` on every HTTPS port. The certificate is no longer verified for
  this request, which only reads a page and never sends credentials.

## [1.1.1] - 2026-11-17

### Fixed

- **Hosts missing from the ARP scan on networks that drop broadcast
  bursts.** The whole subnet was sent in a single burst, and a slow network
  card (a Raspberry Pi 3B+, whose Ethernet sits behind USB) or a switch with
  storm control dropped whole blocks of requests, always in the same
  positions. On a `/24` the tail from `.219` up never arrived in any of the
  three rounds, so a device at `.248` never received its own request and
  never showed up, while ping and SSH to it worked fine. Requests are now
  sent with a short gap between them (`config.SWEEP_SEND_INTERVAL`, 2 ms:
  about half a second per `/24` round) and in a different random order every
  round, so a loss can no longer hit the same addresses each time. The ICMP
  sweep used for VPN tunnels and routed networks gets the same treatment.

## [1.1.0] - 2026-11-13

Runs on a technician's laptop as well as on a dedicated Pi, fixes a
dashboard stall that a single port scan could trigger, and everything the
user sees is now in English.

### Added

- Runs on a technician's **Windows** laptop via `start.bat` (no Linux, no
  command line). New `docs/WINDOWS.md`, `requirements-windows.txt`
  (`psutil` + `cryptography`).
- `start.sh`: quick trial on Linux and Raspberry Pi, twin of `start.bat`
  (virtualenv, dependencies, dashboard in the foreground, browser). It
  installs nothing and doesn't touch the network. New `docs/QUICK-START.md`.
- `scanner/platform_net.py`: OS abstraction for interface/IP/MAC/gateway
  reads. On Windows uses `psutil` + `route print` + `netsh wlan`; on
  Linux the existing `ip`/`/sys/class/net` paths are unchanged.
- `GET /api/platform`: reports host capabilities so the dashboard hides
  the panels that don't apply (network reconfiguration, Wi-Fi hotspot)
  and warns when the full layer-2 scan isn't available.
- `scanner/discovery/nopriv.py`: when the raw-socket ARP/ICMP scan can't
  run (no root on Linux, no Npcap on Windows), falls back to a
  TCP-connect sweep plus the system ARP table.
- `RASPISCANNER_NO_NETWORK_CONFIG=1` disables network reconfiguration even
  as root: full layer-2 scan, network left intact.
- TLS certificate falls back to the pure-Python `cryptography` library
  when `openssl` isn't on `PATH` (typical on Windows). `openssl` stays the
  preferred path on Linux.

### Changed

- Platform capabilities now depend on **privileges**, not on the operating
  system (`platform_net.can_configure_network()`,
  `has_raw_socket_access()`). On an unprivileged Linux the network
  interface is no longer reconfigured and the ARP scan uses the fallback
  above instead of returning an empty list.
- On Windows the network interface is **read-only**: no DHCP/`dhclient`,
  no static-fallback probing, no `ip addr` changes. `autoconfigure` just
  re-reads the addresses Windows already set (`mode: manual`). The Wi-Fi
  hotspot is not available on Windows.
- The full IEEE registry is downloaded into `data/oui_full.csv`, untracked
  by git, instead of overwriting the curated list `data/oui.csv`: trying
  the scanner from a clone no longer dirties the checkout. The curated
  list keeps precedence for the names it knows (shorter and easier to read
  in a report). `update_oui.py --if-missing` avoids re-downloading on
  every launch.
- Everything the user sees is in English: log messages, dashboard error
  texts, `start.sh`/`start.bat` output, the systemd unit description, and
  the docs (`docs/PROVA-RAPIDA.md` is now `docs/QUICK-START.md`). If you
  grep the service log for the old Italian messages, update the patterns.

### Fixed

- **Dashboard stall from a single unfinished TLS handshake.** Werkzeug
  wrapped the *listening* socket in TLS, so the handshake ran inside
  `accept()` on the main thread: one client that opened TCP and never
  completed the handshake (a port scanner is enough, including this one)
  blocked every later connection for good. Observed in the field: the
  service stayed "active" for almost six days while serving nothing. The
  listening socket is now plain, and each connection is wrapped in its own
  thread with a timeout. Regression tests in
  `tests/test_tls_handshake_dos.py`.
- Reverse DNS lookups no longer change the global socket timeout from a
  thread pool; they run in a dedicated thread with a real time limit.
- Port 8000 (generic HTTP-Alt) on its own no longer marks a device as a
  **Camera**: it caused false positives on PCs and other devices with a
  web panel on that port.
- A network interface that appears after the service started (typically a
  VPN connected later) is now scanned instead of failing with
  "No such device": Scapy's interface list is reloaded before each ARP/ICMP
  scan.

## [1.0.0] - 2026-08-28

First stable release. Grouped by the priority phases used during
development (P0 security → P1 hardening → P2 robustness → P3 tests/
release → P4 extended discovery). See [ROADMAP.md](ROADMAP.md) for
what's next.

### P0 — Security

- No fixed default credentials: a random, single-use bootstrap password
  is generated on first launch and printed to the service log; the
  account is locked to nothing else until it's changed.
- Dashboard refuses to start over plain HTTP if a TLS certificate can't
  be generated, instead of silently exposing Basic Auth credentials in
  cleartext.
- ONVIF XAddr validated against SSRF: rejects any address that isn't a
  private, non-special IPv4 literal before an outbound request is made.

### P1 — Access control & hardening

- Role-based access control (`viewer` / `operator` / `admin`) on every
  API route, enforced independently of the dashboard UI. `viewer` sees
  Devices/Cameras only; `operator` adds Report/History/topology/Audit;
  `admin` adds user, webhook, and monitoring management.
- CSRF/Origin validation on every mutating request.
- systemd hardening (`NoNewPrivileges`, `ProtectSystem`, `ProtectHome`,
  `PrivateTmp`, a minimal `CapabilityBoundingSet`) while keeping
  `User=root` (required for raw-socket discovery and network
  reconfiguration).
- Fixed a scan-start race condition where two concurrent
  `/api/scan/start` requests could both begin scanning and corrupt
  shared state.

### P2 — Discovery, ONVIF, and reporting robustness

- Replaced hand-rolled ONVIF XML parsing with `xml.etree.ElementTree`,
  with an explicit `<!DOCTYPE` rejection (entity-expansion/"billion
  laughs" mitigation) — this data arrives from an unauthenticated
  multicast probe. Fixed a related bug where a malformed/prefixed
  closing tag left trailing garbage in the extracted vendor/model.
  mDNS/Bonjour discovery added as a second identification signal
  alongside ONVIF.
- VPN-aware scanning: NOARP interfaces (WireGuard, OpenVPN, PPP) are
  scanned via ICMP instead of ARP, detected from the kernel's own
  interface flags.
- IP collision avoidance during the DHCP-fallback path: the scanner now
  ARP-probes a candidate address before assigning it to itself, instead
  of assuming it's free.
- `nmcli`'s terse-output escaping (`\:`, `\\`) is now handled correctly;
  a Wi-Fi SSID containing a literal `:` no longer corrupts the parsed
  signal/security fields on the same line.
- More precise HTTP security findings (admin panel vs. generic service,
  HTTPS-available vs. not) instead of a flat "medium" for any open HTTP
  port; a new "RTSP exposed" finding.
- More granular NVR/DVR classification (NVR / DVR / Video Encoder /
  Video Decoder) instead of one umbrella label; classification extended
  to phones/tablets/PCs/Macs via hostname patterns.
- RTSP and admin-panel URLs in the dashboard are explicitly labeled
  "(candidate)" — a best-effort guess from an open port, never a
  verified working stream or confirmed admin panel.

### P3 — Testing & release packaging

- Full test suite: integration tests (discovery → classification →
  report), concurrency tests, and malformed-input tests (ONVIF XML,
  mDNS, HTTP banners). Fixed a bug found by the latter: a single
  failing port check could discard the port-scan results for every
  other port on the same host.
- `PORT_SCAN_THREADS` was defined but never read — the port scanner's
  thread pool was hardcoded to 16 workers regardless of the setting.
- `install.sh`: required system packages now stop the install on
  failure instead of continuing silently; `network-manager` stays
  optional (Wi-Fi/hotspot only). `rsync --delete` now excludes
  `data/users.json`, TLS certs, and the OUI database, so a
  reinstall/upgrade no longer wipes dashboard users, the certificate,
  or a downloaded full vendor database. Ownership of `data/` is fixed
  explicitly to `root:root` on install — without it, the P1 systemd
  capability hardening silently breaks every future write after
  looking fine at first boot.
- `uninstall.sh` (with an optional `--keep-data` flag), `SECURITY.md`,
  `CONTRIBUTING.md`.
- Full English translation of the dashboard, CLI output, and generated
  report.

### P4 — Extended discovery & operations

- Richer vendor identification: HTTP banner-based vendor/model guessing
  as a fallback when the OUI (MAC) database has no match, covering
  common camera/NVR vendors and generic OEM DVR/NVR boards.
- 802.1Q VLAN tag awareness on ARP traffic, when present.
- Optional SNMP probing (`sysDescr`/`sysName`, community `public`,
  read-only) on hosts already classified as network infrastructure.
- Passive LLDP/CDP listening, correlated to ARP-discovered devices by
  MAC, surfaced as a one-hop network topology map (`GET /api/topology`)
  — deliberately not multi-hop (see [ROADMAP.md](ROADMAP.md)).
- IPv6 discovery: ICMPv6 Echo Request to the link-local all-nodes
  multicast, a supplementary signal alongside the primary IPv4/ARP
  scan.
- Local scan history (SQLite): every completed scan is saved, a local
  asset database tracks every MAC ever seen, and two scans can be
  diffed.
- Optional webhook notification after each scan (including what
  changed since the previous one); Continuous Monitoring mode runs
  scans automatically on an interval instead of requiring a manual
  start.
- Audit mode (`GET /api/audit/report`): a report generated from a
  saved scan — reproducible, unlike the live `/api/report`, which can
  be a partial snapshot mid-scan.
- Structured JSON export (metadata envelope instead of a bare device
  array) and a full API reference (`API.md`), kept in sync with the
  real routes by an automated test.
- Scan targets, separated from network bootstrap: what a scan analyzes
  is now an explicit setting (`GET`/`POST /api/settings/targets`),
  independent of what network this device configures itself on. Custom
  networks the device has no address in are scanned via a routed ICMP
  sweep (kernel routing table, `ip route get`) instead of ARP — no
  MAC/vendor there, same limitation as a VPN tunnel. Previously the two
  concepts were implicitly the same thing.

### Found only on real Raspberry Pi hardware

458 automated tests never caught either of these — both needed a real,
resource-constrained device to surface:

- The installer could report "no bootstrap account was created" on a
  slow CPU: it checked the log only 3 seconds after restarting the
  service, before Flask/scapy had actually finished starting and
  logging the account. Now polls for up to 15 seconds.
- Audit mode could show a *lower* severity than the live report for the
  identical scan. A device round-tripped through the SQLite-backed
  history (`storage.save_scan()` → `get_scan_devices()`) has its
  `http_banners` port keys turned from integers into strings — JSON
  object keys are always strings — silently breaking an admin-panel
  detection lookup keyed by integer, and degrading a real "HTTP admin
  panel, no HTTPS" finding to a generic, lower-severity one.

### Known limitations

- Hosts within one scan are processed sequentially, not in parallel —
  not tuned for very large (`/16`-scale) networks. See
  [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- RAM usage has not been profiled on a large scan.
- Scan timing verified on a real Raspberry Pi 3B+, two distinct
  scenarios (not directly comparable): 10.98s for a single `/24`
  network (4 hosts) and 22.3s for a multi-interface scan (eth0 + Wi-Fi,
  two networks, 8 hosts combined) — both ~2.7-2.8s/host, consistent
  with each other. Pi 4/5 not yet benchmarked.
