# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/); no version has
been tagged yet (pre-1.0, see [TODO.md](TODO.md) for release-readiness
status), so everything below is grouped under **Unreleased**.

## Unreleased

### Security

- Dashboard no longer starts over plain HTTP if the TLS certificate
  can't be generated — it refuses to start instead of silently exposing
  Basic Auth credentials in cleartext.
- Removed the fixed default credentials: a random bootstrap password is
  generated on first launch, printed once to the service log (and, since
  the installer fix below, to the terminal), and must be changed before
  any other dashboard action is allowed.
- Role-based access control (`viewer` / `operator` / `admin`) on every
  API route; user management restricted to admins, with a self-or-admin
  exception for changing your own password. `viewer` is now scoped to
  Devices/Cameras only — the report, history/asset/comparison, topology,
  and audit-report endpoints (and their dashboard tabs) require
  `operator` or higher.
- CSRF/Origin validation on every mutating request.
- Fixed the scan-start race condition: concurrent `/scan/start` requests
  could previously both begin scanning and corrupt shared state.
- ONVIF XAddr SSRF guard: rejects any address that isn't a private,
  non-special IPv4 literal before making an outbound request.
- Replaced ONVIF's hand-rolled string parsing with `xml.etree.ElementTree`,
  with an explicit `<!DOCTYPE` rejection (entity-expansion/"billion
  laughs" mitigation) — this data arrives from an unauthenticated
  multicast probe.
- systemd hardening (`NoNewPrivileges`, `ProtectSystem`, `ProtectHome`,
  `PrivateTmp`, a minimal `CapabilityBoundingSet`, and more) on the
  installed service, while keeping `User=root` (required for raw-socket
  discovery and network reconfiguration).

### Fixed

- `install.sh`'s `rsync --delete` was not excluding `data/users.json`,
  `data/tls_cert.pem`, `data/tls_key.pem`, or `data/oui.csv` — every
  reinstall/upgrade would have wiped dashboard users, the TLS
  certificate, and any downloaded full vendor database.
- `data/`'s ownership could revert to the installing user instead of
  root on reinstall, which — combined with the systemd capability
  hardening above — would silently break every future write (password
  changes, new users) after looking fine at first boot.
- A malformed/prefixed closing tag (e.g. `</tds:Manufacturer>`) in a
  device's ONVIF response left trailing garbage (`"Hikvision</tds:"`) in
  the extracted manufacturer/model.
- `nmcli`'s terse output escaping (`\:`, `\\`) wasn't handled: a Wi-Fi
  SSID containing a literal `:` corrupted the parsed signal/security
  fields on the same line.
- IP address collisions during the preset-subnet DHCP fallback: the
  scanner now ARP-probes a candidate "high" address before assigning it
  to itself, instead of assuming it's always free.
- A single failing port check in the TCP port scanner could raise and
  discard the results for every other port on that host.
- `PORT_SCAN_THREADS` was defined but never actually used — the port
  scanner's thread pool was hardcoded to 16 workers regardless.

### Added

- Full user management in the dashboard's Settings tab (add/remove
  users, change password, per-user role).
- mDNS/Bonjour discovery, used both for hostnames/models and as a
  fallback identification signal when a device doesn't respond to ONVIF.
- VPN discovery and scanning: NOARP interfaces (WireGuard, OpenVPN tun,
  PPP) are scanned via ICMP instead of ARP, detected from the kernel's
  own interface flags rather than guessed from the interface name.
- Device classification for phones/tablets/PCs/Macs via hostname
  patterns, in addition to the existing camera/NVR/network-gear
  detection.
- More granular NVR/DVR classification (NVR / DVR / Video Encoder /
  Video Decoder, where the device's own banner indicates it) instead of
  a single "NVR/DVR" label.
- More precise HTTP security findings (admin-panel vs. generic service,
  HTTPS-available vs. not) instead of a flat "medium" for any open HTTP
  port; a new "RTSP exposed" finding.
- Report now includes scan start/end timestamps, duration, the
  interface used per network, and a per-network summary line; the
  dashboard's Report tab highlights severity levels and finding lines
  by color.
- Progress feedback during the preset-subnet DHCP fallback probe
  ("Probing preset network 7/13: 192.168.x.0/24").
- Full English translation of the dashboard, CLI output, and generated
  report; redesigned as a clean, professional dashboard.
- `uninstall.sh` (with an optional `--keep-data` flag).
- Richer vendor fingerprinting: HTTP banner-based vendor/model guessing
  (`vendor_source`/`model_source` shown in the dashboard) used as a
  fallback when the local OUI (MAC) database has no match, covering
  Hikvision/Dahua/Axis/Bosch/Ksenia/Reolink/Foscam/Vivotek and generic
  OEM DVR/NVR boards.
- VLAN awareness: the 802.1Q tag seen on a device's ARP traffic, when
  present (most switch ports are "access" mode and strip it).
- Optional SNMP discovery (`sysDescr`/`sysName`, community `public`,
  read-only) on hosts already classified as network infrastructure.
- LLDP/CDP discovery: passive listening for network gear's own
  periodic announcements, correlated to ARP-discovered devices by MAC.
- One-hop network topology map (`GET /api/topology`, new "Topology"
  section in the dashboard) — gateway + LLDP/CDP neighbors per
  interface, deliberately not a multi-hop graph (would require
  SNMP-walking remote switches with credentials this tool doesn't have).
- IPv6 discovery: ICMPv6 Echo Request to the link-local all-nodes
  multicast (`ff02::1`), a supplementary signal alongside the primary
  IPv4/ARP scan.
- Structured JSON export (`/api/export?format=json`) as a metadata
  envelope (`exported_at`, `scan_started_at`/`finished_at`, `count`)
  instead of a bare device array.
- Full API reference (`API.md`), kept in sync with the real routes by a
  regression test in both directions.
- Optional webhook: `POST`s a JSON summary (including a
  `changes_since_previous_scan` diff) to one configured URL after every
  scan; `http`/`https` only.
- Local scan history (SQLite, `data/history.db`): every completed scan
  is saved, a local asset database tracks every MAC ever seen, and two
  past scans can be diffed ("first scan vs. current scan") — new
  "History" tab in the dashboard.
- Continuous Monitoring mode: optionally runs a scan automatically every
  N minutes (skipping a cycle instead of overlapping if one is already
  running) instead of always requiring a manual start.
- Audit mode (`GET /api/audit/report`): a report generated from a
  **saved** scan (reproducible — unlike the live `/api/report`, which can
  be a partial snapshot mid-scan) with a "changes since previous scan"
  section prepended automatically.
### Changed

- `install.sh` now stops on failure to install required system packages
  (`python3-venv`, `python3-pip`, `isc-dhcp-client`, `iproute2`,
  `openssl`) instead of silently continuing; `network-manager` remains
  optional (Wi-Fi/hotspot only) and only warns on failure.
- RTSP and admin-panel URLs in the dashboard are now explicitly labeled
  "(candidate)" — they're a best-effort guess from an open port, never a
  verified working stream or confirmed admin panel.
