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
No body. `200 {"ok": true, "message": "Scan started"}`, or
`409 {"ok": false, "message": "Scan already in progress"}` if one is
already running.

### `POST /api/scan/stop` — operator
No body. `200 {"ok": true}` — requests the running scan to stop at its
next checkpoint (not necessarily instantaneous).

### `GET /api/scan/status` — viewer
```json
{
  "running": false, "progress": 12, "total": 14, "current_ip": null,
  "started_at": 1735000000.0, "finished_at": 1735000090.0, "error": null,
  "devices": [ /* device objects, see below */ ]
}
```

### `GET /api/devices` — viewer
`[device, ...]` — every device found by the last (or current) scan. See
**Device object** below for the schema.

### `GET /api/devices/cameras` — viewer
Same shape, filtered to `is_camera: true` devices only (includes NVR/DVR).

### `GET /api/security/summary` — viewer
`{"critical": 1, "high": 0, "medium": 3, "low": 1}` — finding counts by
severity across every discovered device (same logic as the text report's
risk summary).

### `GET /api/report` — viewer
`{"text": "NETWORK ASSESSMENT\n...", "scan_running": false}` — the full
text report (see [`examples/sample_report.txt`](examples/sample_report.txt)
for a real example). If a scan is still running, `text` is prefixed with a
partial-snapshot warning and `scan_running` is `true`.

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
  nothing), `"onvif"` (self-reported), or `null`.
- `model_source`: `"onvif"`, `"mdns"`, or `null` — `model` is never a
  guess, only ever what the device declared about itself.
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
