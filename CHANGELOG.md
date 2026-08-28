# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/).

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
