# API Reference

RaspiScanner's dashboard is a thin client over a JSON HTTP API — everything
the browser does, a script can do too. This document is for anyone
integrating with RaspiScanner from another tool, not for browsing the
dashboard itself.

There is no separate API token: all endpoints use the same **HTTP Basic
Auth** credentials as the dashboard (`scanner/auth.py`), served over
**HTTPS only** (self-signed certificate — see
[README, "Dashboard authentication"](README.md#dashboard-authentication)).
There is currently no OpenAPI/Swagger spec; this document is the reference.

## Conventions

- **Base URL**: `https://<host>:7332` (default port; `--port` changes it).
- **Auth**: every request needs `Authorization: Basic ...`. A missing or
  wrong credential gets `401` with a `WWW-Authenticate` challenge.
- **Roles**: `viewer < operator < admin` (`scanner/auth.py`). Each endpoint
  below lists the minimum role required. Below that, you get
  `403 {"error": "forbidden", "message": "Requires the '<role>' role or higher."}`.
- **CSRF/Origin**: `POST`/`PUT`/`PATCH`/`DELETE` requests are rejected with
  `403 {"error": "forbidden_origin", ...}` if they carry an `Origin` header
  that doesn't match the dashboard's own origin. A request with **no**
  `Origin` header (the normal case for a script/`curl`) is always allowed —
  this check exists to stop a browser acting on a *different* site's behalf,
  not to block direct API clients.
- **Forced password change**: if the authenticated user still has
  `must_change_password` set (true right after installation, see
  [README](README.md)), every endpoint except `GET /`, `GET /api/settings/me`,
  and `POST /api/settings/users/password` returns
  `403 {"error": "password_change_required", ...}`.
- **Content type**: request bodies are JSON (`Content-Type: application/json`);
  a missing/invalid body is treated as `{}`, not an error, unless a field
  documented as required is then missing.
- Errors that aren't role/CSRF/auth-related generally come back as
  `{"ok": false, "message": "..."}` with a `4xx`/`5xx` status matching the
  particular endpoint (documented per-endpoint below).

## Platform

### `GET /api/platform` — viewer
Capabilities of the host RaspiScanner is running on. The dashboard uses
this to hide panels that don't apply on the Windows build (interface
reconfiguration, Wi-Fi hotspot) and to warn when Npcap is missing.

```json
{
  "os": "linux",
  "is_windows": false,
  "network_reconfig_supported": true,
  "hotspot_supported": true,
  "arp_raw_available": true
}
```
On Windows `network_reconfig_supported` and `hotspot_supported` are
`false` (the interface is read-only, DHCP/static is left to Windows), and
`arp_raw_available` reflects whether Npcap is installed — when `false` the
ARP scan falls back to a TCP-connect sweep plus the system ARP table.

## Network

### `GET /api/network` — viewer
Current status of the ethernet interface, every Wi-Fi adapter, and every
active VPN interface.

```json
{
  "eth": {
    "iface": "eth0", "up": true, "mode": "dhcp", "ip": "192.168.1.42",
    "cidr": "192.168.1.0/24", "addresses": [{"ip": "192.168.1.42", "cidr": "192.168.1.0/24"}],
    "reconfiguring": false, "error": null, "last_change": 1735000000.0,
    "candidates": [],
    "probing": false, "probe_index": null, "probe_total": null,
    "probe_cidr": null, "probe_timeout": null
  },
  "wifi": {
    "wlan0": {"iface": "wlan0", "up": true, "ssid": "HomeWifi", "ip": "192.168.1.50",
              "cidr": "192.168.1.0/24", "addresses": [...]}
  },
  "vpn": {
    "wg0": {"iface": "wg0", "up": true, "ip": "10.0.0.3", "cidr": "10.0.0.0/24",
            "addresses": [...], "noarp": true}
  }
}
```
`mode` is one of `dhcp`, `static-fallback`, `manual` (pre-existing IPs
RaspiScanner didn't assign), `choose-network` (multiple preset subnets
answered, see `candidates`), `no-network`, or `null` (cable unplugged).
While `mode` is being decided, `probing` is `true` and `probe_index`/
`probe_total`/`probe_cidr` track which preset subnet is being tried.
On the Windows build the interface is never reconfigured: `mode` is always
`manual` (whatever DHCP/static Windows already set) or `no-network`, and
`POST /api/network/rescan` just re-reads the current addresses.

### `POST /api/network/rescan` — operator
Re-runs ethernet autoconfiguration (DHCP → preset-subnet fallback) in the
background. Body: `{"force": false}` — `force: true` also drops any
pre-existing IPs RaspiScanner didn't itself assign. Returns immediately:
`{"status": "started", "force": false}`; poll `GET /api/network` for the
outcome.

### `POST /api/network/choose` — operator
Resolves a `choose-network` ambiguity by picking one of the candidate
preset subnets. Body: `{"cidr": "192.168.1.0/24", "iface": "eth0"}`
(`iface` optional, defaults to the current/default ethernet interface).
`200 {"ok": true, "message": "Network 192.168.1.0/24 selected"}` or
`400` if the CIDR isn't a current candidate, no ethernet interface is
found, or the address that was free during the automatic probe has since
been taken by another host.

### `GET /api/wifi/networks?iface=wlan0` — viewer
Visible Wi-Fi networks (`iface` optional). `[{"ssid": "...", "signal": "70", "security": "WPA2"}, ...]`.

### `POST /api/wifi/connect` — operator
Body: `{"ssid": "...", "password": "...", "iface": "wlan0"}` (`password`
and `iface` optional — an open network needs no password). `200 {"ok": true, "message": "..."}`
or `502` if `nmcli` reports failure.

### `GET /api/wifi/interfaces` — viewer
`["wlan0", "wlan1"]` — every Wi-Fi adapter present.

## Hotspot

### `GET /api/hotspot/status?iface=wlan0` — viewer
`{"active": false, "ssid": null, "ip": null, "iface": null, "default_ssid": "RaspiScanner-A1B2"}`.

### `GET /api/hotspot/generate-password` — operator
`{"password": "aB3xQ9zM2pLk"}` — a random WPA2-strength password for the
"Add user"-style hotspot form; doesn't activate anything by itself.

### `POST /api/hotspot/start` — admin
Body: `{"ssid": "...", "password": "...", "iface": "wlan0"}` (`iface`
optional). Admin-only: activating a hotspot opens a new unauthenticated
network entry point. `200 {"ok": true, ...}` or `400`.

### `POST /api/hotspot/stop` — admin
No body. `200 {"ok": true, "message": "Hotspot deactivated"}` or `400`.

## Scanning

### `POST /api/scan/start` — operator
Optional body `{"port_profile": "common" | "extended"}` (default `common`).
`common` checks the fixed list of ports used to recognize cameras, NVRs and
network gear on every device; `extended` adds more services (NAS, IoT,
databases, alternative web and RTSP ports). `200 {"ok": true, "message":
"Scan started"}`, `400` for an unknown profile, or `409 {"ok": false,
"message": "Scan already in progress"}` if one is already running.

### `GET /api/scan/profiles` — viewer
How many ports each profile checks on every device:
`{"common": {"ports": 23}, "extended": {"ports": 84}}`.

### `POST /api/scan/stop` — operator
No body. `200 {"ok": true}` — requests the running scan to stop at its
next checkpoint (not necessarily instantaneous).

### `GET /api/scan/status` — viewer
```json
{
  "running": false, "progress": 12, "total": 14, "current_ip": null,
  "started_at": 1735000000.0, "finished_at": 1735000090.0, "error": null,
  "port_profile": "common",
  "devices": [ /* device objects, see below */ ]
}
```

### `GET /api/scan/targets` — viewer
What the *next* `run_scan()` would actually scan right now, without
starting anything — networks from active interfaces plus any configured
custom target, already resolved to a real egress interface. See
**Scan targets** below for how to configure it.
```json
{
  "auto_interfaces": true,
  "interfaces": [{"iface": "eth0", "cidr": "192.168.1.0/24"}],
  "routed": [{"iface": "eth0", "cidr": "10.20.0.0/24"}],
  "detected": [
    {"iface": "eth0", "cidr": "192.168.1.0/24", "scanned": true},
    {"iface": "wg0", "cidr": "10.0.0.0/24", "scanned": false}
  ],
  "excluded": ["10.0.0.0/24"]
}
```
`interfaces` are the detected networks the next scan will cover; `detected`
lists **every** network seen on an active interface right now with whether
it will be scanned, and `excluded` is the saved list of networks left out.
`routed` entries are reached only through routing (no local address
there), so they're scanned via ICMP, not ARP — no MAC/vendor for hosts
found there, same limitation as a VPN tunnel (see **Scan targets**).

### `GET /api/topology` — operator
One-hop network adjacency from the last (or current) scan — not a
multi-hop graph (that would need walking remote switches' MIBs via
credentials this tool doesn't have, out of scope for a non-intrusive
tool). Keyed by interface:
```json
{
  "eth0": {
    "cidr": "192.168.1.0/24", "gateway": "192.168.1.1",
    "neighbors": [{"protocol": "lldp", "chassis_id": "aa:bb:cc:11:22:33", "port_id": "Gi0/1", "system_name": "core-switch", "system_description": "Cisco IOS Switch"}]
  }
}
```
`neighbors` comes from passively listening for LLDP/CDP announcements
during the scan (`protocol`: `"lldp"` or `"cdp"`) — these aren't
request/response like ARP, network gear transmits them on its own timer
(commonly every 30-60s), so an empty list doesn't mean no LLDP/CDP-capable
device is present, only that none transmitted during this scan's listen
window. When a neighbor's `chassis_id` matches a MAC seen elsewhere in
this scan, that device's own `lldp_cdp_info` field (see **Device object**)
is set to this same neighbor object.

### `GET /api/topology/map` — operator
Map of the scanned networks, built only from what the last scan already
saw (no credentials, nothing queried on switches or routers):
```json
{
  "networks": [{"iface": "eth0", "cidr": "192.168.1.0/24", "gateway": "192.168.1.1", "kind": "ethernet"}],
  "devices": [{"ip": "192.168.1.20", "label": "TestPi.local", "vendor": "Raspberry Pi Foundation",
               "device_type": "Raspberry Pi", "mac": "b8:27:eb:cf:48:f4", "iface": "eth0",
               "network": "192.168.1.0/24", "is_gateway": false, "is_self": false,
               "is_camera": false, "is_bridge": true}],
  "links": [{"a": "192.168.1.20", "b": "10.42.0.1", "kind": "same_device", "name": "testpi"}],
  "limits": "..."
}
```
`kind` is `ethernet`, `wifi` or `vpn` (a NOARP interface). Each network also
has `dhcp`: the DHCP servers that answered a DHCPDISCOVER on it
(`server`, `router`, `dns`, `domain`; empty when none answered or the probe is
off). A device has `ips` (all addresses sharing its MAC in that network, the
first one is `ip`) and `roles`, a list of `scanner`, `gateway`, `dhcp`, `dns`,
`bridge`. `uplink` is `null` or the path to the Internet:
`{"target": "1.1.1.1", "internet": true, "via": "eth0", "hops": [{"ttl": 1,
"ip": "192.168.1.1", "rtt_ms": 0.6, "private": true, "label": "router",
"known": true, "is_public": false}]}`; a hop with no reply has `ip: null`. A device found
in two networks under the same hostname (a Pi on cable and Wi-Fi) gets
`is_bridge` and a `same_device` link between its two entries; the scanner's
own addresses are linked the same way (`is_self`). It can't tell which switch
port or access point a device of the same network hangs on: that data
lives only in the network gear. The PDF from `GET /api/report?format=pdf`
ends with this same map; the audit PDF of a saved scan does not, because a
saved scan keeps the devices but not the interfaces and gateways.

### `GET /api/devices` — viewer
`[device, ...]` — every device found by the last (or current) scan. See
**Device object** below for the schema.

### `GET /api/devices/cameras` — viewer
Same shape, filtered to `is_camera: true` devices only (includes NVR/DVR).

### `POST /api/devices/deep-scan` — operator
Deep port scan of **one** device found by the last scan:
`{"ip": "192.168.1.20", "ports": "1-65535"}`. `ports` accepts single ports
and ranges separated by commas (`"22,80,7000-9000"`); it defaults to
`1-65535`. Runs in the background, one at a time; the banner of every open
web port is read too. When it ends, the open ports and banners are added to
that device (`open_ports`, `http_banners`, `deep_scan`). `200` when started;
`400` for a missing or unknown IP or an invalid port list; `409` while a
network scan or another deep scan is running.

### `GET /api/devices/deep-scan` — operator
State of the current or last deep scan:
```json
{
  "running": false, "ip": "192.168.1.20", "ports_spec": "1-65535",
  "ports_total": 65535, "ports_done": 65535, "started_at": 1735000000.0,
  "finished_at": 1735000300.0, "stopped": false, "error": null,
  "open_ports": [
    {"port": 22, "service": "SSH"},
    {"port": 7332, "service": "RaspiScanner", "http": {"server": null, "title": "RaspiScanner"}}
  ]
}
```

### `POST /api/devices/deep-scan/stop` — operator
No body. `200 {"ok": true}`: the deep scan stops at the end of the current
block of ports. What it found so far is kept and added to the device.

### `GET /api/security/summary` — viewer
`{"critical": 1, "high": 0, "medium": 3, "low": 1}` — finding counts by
severity across every discovered device (same logic as the text report's
risk summary).

### `GET /api/report` — operator
`{"text": "NETWORK ASSESSMENT\n...", "scan_running": false}` — the full
text report (see [`examples/sample_report.txt`](examples/sample_report.txt)
for a real example). If a scan is still running, `text` is prefixed with a
partial-snapshot warning and `scan_running` is `true`.

`?format=pdf` or `?format=txt` returns the same report as a file to save
(`Content-Disposition: attachment`, named `raspiscanner-report-<date>-<time>`).
The PDF is A4, with a summary box per network, findings colored by severity
and the disclaimers at the end; a report taken mid-scan says it is a partial
snapshot. `404 {"error": "no_data"}` when there is nothing to report yet,
`400` for any other `format`.

### `GET /api/export?type=all&format=json` — viewer
Downloads discovered devices as a file (`Content-Disposition: attachment`).
`type`: `all` (default) or `cameras`. `format`: `csv` (a fixed column
subset: `ip, mac, vendor, model, hostname, device_type, open_ports,
rtsp_url, admin_url`) or `json` (default) — a structured envelope, not a
bare array:

```json
{
  "exported_at": 1735000123.4,
  "type": "all",
  "count": 14,
  "scan_started_at": 1735000000.0,
  "scan_finished_at": 1735000090.0,
  "devices": [ /* device objects, see below */ ]
}
```

## History

Every completed scan (including one stopped early or ended in error — a
partial snapshot is still real data) is saved to a local SQLite database
(`data/history.db`). Devices without a MAC (VPN/NOARP links, orphaned
ONVIF-only cameras) can't be tracked reliably across scans — their IP may
not mean the same host next time — so they're excluded from asset
tracking and from comparisons, though they still appear in each scan's
own device list.

### `GET /api/history/scans?limit=20` — operator
Past scans, most recent first (metadata only, no devices):
`{"scans": [{"id": 7, "started_at": 1735000000.0, "finished_at": 1735000090.0, "device_count": 14}, ...]}`.

### `GET /api/history/scans/<int:scan_id>/devices` — operator
`{"devices": [device, ...]}` — the full device list from that one scan,
same shape as `/api/devices`.

### `GET /api/history/compare?old=<id>&new=<id>` — operator
Diffs two past scans by MAC. `400` if either id is missing.
```json
{
  "added": [device, ...],
  "removed": [device, ...],
  "changed": [{"mac": "AA:BB:CC:11:22:33", "old": device, "new": device, "fields": ["ip", "open_ports"]}]
}
```
`fields` lists which of `ip`, `vendor`, `model`, `device_type`,
`open_ports` differ between the two snapshots.

### `GET /api/history/assets?limit=500` — operator
Every MAC seen at least once, most recently seen first:
`{"assets": [{"mac": "...", "first_seen": 1734000000.0, "last_seen": 1735000090.0, "last_ip": "...", "last_vendor": "...", "last_device_type": "...", "times_seen": 4}, ...]}`.

## Webhook

Optional: notifies one configured URL by `POST`ing a JSON summary after
every scan. Off by default; the URL is set deliberately by an admin, not
influenced by anything a scanned device sends — but only `http://`/`https://`
URLs are accepted (never `file://`, even for an admin-supplied value).
Delivery is best-effort with a 5s timeout: a failed webhook is logged, it
never affects the scan that triggered it.

### `GET /api/settings/webhook` — admin
`{"url": "https://example.com/hook", "enabled": true}` (`enabled` is
always `false` if `url` is empty, regardless of what was last saved).

### `POST /api/settings/webhook` — admin
Body: `{"url": "https://...", "enabled": true}`. `400` if `enabled: true`
with no URL, or the URL isn't `http(s)`. On a completed scan, the payload
posted is:
```json
{
  "scan_id": 7, "started_at": 1735000000.0, "finished_at": 1735000090.0,
  "device_count": 14, "camera_count": 3,
  "changes_since_previous_scan": {"added": 1, "removed": 0, "changed": 2}
}
```
`changes_since_previous_scan` is `null` if this is the very first scan
ever saved (nothing to compare against yet); otherwise it's always
present, computed against the previously saved scan regardless of
whether this scan was started manually or by Continuous Monitoring.

## Continuous Monitoring mode

Optional: instead of always requiring a human to click "Start scan",
automatically runs a scan every `interval_minutes` — the same
`scan_engine.run_scan()` a manual click triggers, not a separate scan
path. If a scan (manual or automatic) is already in progress when it's
time for the next automatic one, that cycle is skipped rather than
queued or forced. Off by default. Combine with the webhook above to get
notified of `changes_since_previous_scan` without watching the dashboard.

### `GET /api/settings/monitoring` — admin
`{"enabled": false, "interval_minutes": 60}`.

### `POST /api/settings/monitoring` — admin
Body: `{"enabled": true, "interval_minutes": 30}`. `400` if
`interval_minutes` isn't a whole number `>= 5` — an interval shorter than
a typical scan's own duration would just make every automatic cycle find
the previous one still running and skip itself, giving the illusion of
monitoring without the substance.

## Audit mode

`/api/report` reflects **live** state — if a scan is still running, it's
an admittedly partial snapshot. Audit mode instead generates a report
from a scan already **saved** to history, so the same `scan_id` always
reproduces the exact same report, and automatically prepends a "CHANGES
SINCE PREVIOUS SCAN" section (see **History**'s `compare` for the same
data in JSON form).

### `GET /api/audit/report?scan_id=<id>` — operator
`scan_id` optional, defaults to the most recently saved scan.
```json
{"text": "CHANGES SINCE PREVIOUS SCAN\n...\n\nNETWORK ASSESSMENT\n...", "scan_id": 7, "compared_to_scan_id": 6}
```
`compared_to_scan_id` is `null` (and the report has no changes section)
if `scan_id` is the first scan ever saved. `404` if `scan_id` doesn't
exist, or if no scan has ever been saved and none was given.

`&format=pdf` or `&format=txt` downloads the same audit report as a file,
named `raspiscanner-audit-scan<id>-<date>-<time>`; the PDF includes the
"Changes since previous scan" section. It also ends with the network map
as it was when that scan finished (kept with each scan since 1.7.1); scans
saved earlier have no map, so their PDF has no map page.

## Scan targets

Two independent settings, deliberately not mixed together:

- **Network bootstrap** (`scanner/network/setup.py`, no dedicated API
  section — see the dashboard's "Network Status" card): decides what
  address *this device* configures on `eth0` (DHCP, then preset-subnet
  fallback). Unaffected by anything below.
- **Scan targets** (this section): decides what a scan actually
  *analyzes*. Defaults to every network detected on an active interface
  (`auto_interfaces: true`, the original, only behavior before this was
  configurable) — optionally with some of them left out (`excluded`, for
  example a VPN or a phone hotspot), and combined with, or replaced by,
  networks the operator adds explicitly. A detected network that is not in
  `excluded` is scanned, so one that shows up later (a VPN connected while
  the service is running) is included until you leave it out.

A custom network the device has no address in at all can't be reached by
ARP (ARP doesn't cross a router — see README, "What it doesn't do"): it's
scanned via an ICMP sweep routed through whatever interface the kernel's
own routing table would use, same as an active VPN tunnel today. That
means IP-only discovery there — no MAC, no vendor, no ONVIF/mDNS/LLDP-CDP/
IPv6 (all of those need a local address on that segment to mean anything).
Use `GET /api/scan/targets` to see exactly what the next scan would do
before running it.

### `GET /api/settings/targets` — operator
`{"auto_interfaces": true, "custom": ["192.168.20.0/24"], "excluded": ["10.0.0.0/24"]}`.

### `POST /api/settings/targets` — operator
Body: `{"auto_interfaces": true, "custom": ["192.168.20.0/24", "10.0.5.0/24"], "excluded": ["10.0.0.0/24"]}`.
`excluded` lists detected networks to leave out of the scan; omit it to keep
the saved list as it is, send `[]` to scan every detected network again.
Entries must be valid IPv4 CIDRs and are normalized like `custom`, but have
no privacy or size limit (they are networks the device already has, not
places to point it at); a network that is both excluded and in `custom` is
not scanned. If every detected network is excluded and there is nothing
else to scan, `POST /api/scan/start` answers `409` with
"Every detected network is unticked in Scan targets".
Each entry in `custom` is normalized to its network address (`.5/24`
becomes `.0/24`); `400` if any entry isn't a valid IPv4 CIDR, isn't a
**private** network (`ipaddress.is_private` — rejects public ranges and
`0.0.0.0/0`), or is larger than **`/22`** (max 1024 hosts) — the whole
list is rejected together rather than saving a partial one. This is a
deliberate policy, not an oversight: the tool is meant for networks the
operator administers, not for pointing a Pi at arbitrary public hosts,
and a huge custom range would make the sequential per-host scan (see
README, "Known limitations") impractically slow anyway.

## Settings

### `GET /api/settings/me`
No role required beyond being authenticated. `{"username": "...", "role": "admin", "must_change_password": false}`.

### `GET /api/settings/users` — admin
`{"users": [{"username": "...", "role": "admin"}, ...]}`.

### `POST /api/settings/users` — admin
Body: `{"username": "...", "password": "...", "role": "viewer"}` (`role`
optional, defaults to `viewer` — least privilege for an unspecified role).
`200 {"ok": true, "message": "User added"}` or `400` (duplicate username,
password too short, invalid role).

### `POST /api/settings/users/password`
Body: `{"username": "...", "password": "..."}`. **No role decorator** —
every authenticated user may always change their **own** password
(`username` must match the caller); changing anyone else's requires
`admin`, otherwise `403`. `200`/`400` on success/failure.

### `DELETE /api/settings/users/<username>` — admin
`200 {"ok": true, "message": "User removed"}`, or `400` if the user
doesn't exist or is the only remaining account (never leaves zero users).

## Device object

The shape returned by `/api/devices`, `/api/devices/cameras`,
`/api/scan/status`'s `devices` array, and `/api/export` (JSON format):

```json
{
  "ip": "192.168.1.21",
  "mac": "AA:BB:CC:11:22:33",
  "vendor": "Hikvision",
  "vendor_source": "banner",
  "model": "DS-2CD2043G0",
  "model_source": "onvif",
  "hostname": null,
  "snmp_info": {},
  "lldp_cdp_info": null,
  "vlan_id": null,
  "ipv6_addresses": [],
  "iface": "eth0",
  "network": "192.168.1.0/24",
  "open_ports": [{"port": 554, "service": "RTSP"}],
  "http_banners": {"80": {"server": null, "title": "Hikvision - Login"}},
  "onvif": {"xaddrs": ["http://192.168.1.21/onvif/device_service"], "types": "..."},
  "mdns": null,
  "is_camera": true,
  "is_nvr": false,
  "is_network_infra": false,
  "device_type": "Camera",
  "reasons": ["ONVIF WS-Discovery"],
  "classification_reasons": {"camera": [...], "nvr": [], "network": [], "host": []},
  "rtsp_url": "rtsp://192.168.1.21:554/",
  "admin_url": "http://192.168.1.21:80/",
  "network_mismatch": false
}
```

- `vendor_source`: `"oui"` (MAC vendor lookup), `"banner"` (guessed from
  the device's own HTTP banner — only used when the OUI lookup found
  nothing), `"snmp"` (from SNMP `sysDescr`, only on devices already
  suspected to be network infrastructure), `"onvif"` (self-reported), or
  `null`.
- `model_source`: `"onvif"`, `"mdns"`, or `null` — `model` is never a
  guess, only ever what the device declared about itself.
- `snmp_info`: `{"sysDescr": "...", "sysName": "..."}` with only the keys
  actually obtained — `{}` on the vast majority of devices (SNMP is
  usually disabled, and only probed on hosts already classified as
  network infrastructure). Community `public`, read-only, never a list
  of guessed communities.
- `lldp_cdp_info`: the LLDP/CDP neighbor object (see `/api/topology`)
  whose `chassis_id` matched this device's MAC, or `null` on the vast
  majority of devices (only network gear announces LLDP/CDP, and only
  if it happened to transmit during the scan's listen window).
- `vlan_id`: the 802.1Q VLAN tag seen on this device's ARP traffic, or
  `null` — most switch ports are "access" mode (the tag is stripped
  before the frame reaches the scanner), so `null` is the normal case,
  not a sign anything is missing.
- `ipv6_addresses`: IPv6 addresses (usually link-local, `fe80::...`) that
  answered an ICMPv6 Echo Request to the all-nodes multicast `ff02::1`
  from this device's MAC — `[]` on devices with IPv6 disabled, or none
  answered during the scan's listen window. Not full IPv6 discovery of
  every device's every address, just a supplementary "is this device also
  reachable over IPv6" signal alongside the primary IPv4/ARP scan.
- `deep_scan`: present only after a deep scan of this device:
  `{"ports": "1-65535", "ports_checked": 65535, "open_ports": [22, 7332],
  "stopped": false, "finished_at": ...}`. The device's classification still
  comes from the network scan; the ports found here count for the security
  findings in the report.
- `rtsp_url`/`admin_url` are **candidates**, not verified endpoints:
  guessed from an open port (554 for RTSP; the first open web port for
  admin), never confirmed with an actual handshake — see
  [README, "Security notes"](README.md#security-notes).
- `network_mismatch: true` marks a camera seen **only** via ONVIF
  multicast with an IP outside every currently active network (likely
  misconfigured) — such devices have `mac: null`, `open_ports: []`, and
  an extra `onvif_xaddr` field instead of the full port/banner data above.
- `reasons` explains only the classifier that decided `device_type` (the
  highest-priority signal that matched — see `classification_reasons`
  for every classifier's individual result).
