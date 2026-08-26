# RaspiScanner

Standalone project: a Raspberry Pi (or any Linux box) that, connected via
ethernet to an unfamiliar network, auto-configures itself to talk to it and
offers a web dashboard **and** a command-line mode to scan the devices
present — IP cameras, NVR/DVR, network gear — with a security "assessment"
style report.

## Why RaspiScanner?

It's not just another ARP scanner or another ONVIF client: great tools
already exist for generic network discovery (Nmap, Netdiscover, arp-scan)
and for connecting to individual cameras via ONVIF/RTSP. RaspiScanner
exists for a more specific use case that neither covers on its own:
bundling into a single portable tool — a Raspberry Pi that auto-configures
itself on an unfamiliar network on the fly, without needing to know the
subnet/gateway in advance — network discovery, ARP/port/ONVIF
fingerprinting, **distinguishing between camera, NVR/DVR and network
gear**, and a security report (active but non-intrusive probes) built for
surveying an existing video surveillance installation, not for a generic
network audit. It doesn't reinvent Nmap: it builds a layer on top of some
of its own discovery mechanisms, aimed at one specific use case.

## What it does

1. **Ethernet auto-configuration.** When the `eth0` interface detects the
   cable plugged in and doesn't already have an address, it first tries a
   **DHCP** lease. If none arrives within the timeout, it tries **all**
   the **preset private classes** (192.168.1.0/24, 192.168.0.0/24,
   10.0.0.0/24, etc. — see `scanner/config.py`), not just the first one:
   for each, it assigns a "high" static IP and checks with an ARP probe
   whether any hosts respond. If only one class turns out to be alive, it
   gets assigned directly. If **more than one** is alive (e.g. several
   private subnets manually configured on the same segment), the tool
   does not pick one on its own based on an arbitrary priority order: the
   interface stays without an address and the dashboard shows all the
   candidate classes found (with how many hosts each one saw), asking you
   to pick one to scan. The monitor runs continuously: if you unplug and
   replug the cable (maybe on a different network), it redoes everything
   automatically.

   If the interface **already** has one or more IPv4 addresses that the
   tool didn't assign itself (e.g. secondary IPs manually configured to
   reach multiple subnets over the same cable), it leaves them alone: it
   detects them and uses them as they are ("manual" mode in the
   dashboard). The "Reconfigure network" button has a "force" option to
   wipe everything anyway and restart DHCP/fallback from scratch.

2. **Device scan** across **all** active subnets on eth and on **every**
   Wi-Fi adapter present (a device can have more than one — e.g. one used
   as a client to reach an existing network, another dedicated to the
   hotspot — and all of them are tracked/scanned, not just the first one
   found; every configured IPv4 address, not just the first): ARP scan for
   IP/MAC, targeted port scan + HTTP banners, **ONVIF WS-Discovery** probe
   (with `GetDeviceInformation` for real vendor/model when available),
   offline OUI vendor lookup, reverse DNS hostname. Each device is
   classified, in order of specificity: **Camera**/**NVR-DVR** (protocol
   signals — ONVIF, typical ports RTSP 554/Hikvision 8000/Dahua
   37777/34567, HTTP banners — not on the MAC vendor, unreliable offline),
   **Router**/**Switch**/**Access Point** (IP == default gateway, or
   banner/vendor), **Raspberry Pi**/other IoT hardware recognized by
   vendor, **Phone**/**Tablet**/**Mac**/**PC (Windows)** recognized from
   hostname patterns (e.g. "iPhone-di-Mario", "Galaxy-A34-5G",
   "MacBook-Pro", "DESKTOP-7K2N9QP" — useful mainly for Apple devices,
   whose shared OUI can't otherwise distinguish a Mac from an iPhone from
   an iPad), **PC (Windows/SMB)**/**Network printer** (typical
   SMB/RDP/IPP/JetDirect ports) as a fallback when no hostname is
   resolved, or **Generic** if none of these signals is available — a
   structural limit, not a bug: a device with no open ports, no
   distinctive vendor and no resolvable hostname (common on phones and
   modern PCs with a default firewall, on networks whose DHCP server
   doesn't register local DNS names) exposes nothing to read, and this
   tool doesn't go as far as active TCP/IP stack fingerprinting
   `nmap -O`-style or mDNS/Bonjour probing (not implemented yet).

3. **"NETWORK ASSESSMENT" report**: for each scanned network, a text
   report with devices found by category (cameras/NVR/network/other —
   Raspberry Pi, PCs, printers show up under "OTHER DEVICES", so no
   discovered device stays invisible in the report text while still being
   counted in "N devices discovered"), security findings from active but
   non-intrusive probes (Telnet exposed, HTTP enabled, default-looking
   service) and a risk summary (Critical/High/Medium/Low). If requested
   while a scan is still running, the report says so explicitly (it's a
   partial snapshot, counts will increase). See `examples/sample_report.txt`
   for a full example. Available both from the dashboard ("Report" tab)
   and from the command line (`--report`).

4. **Web dashboard** (port `7332`, HTTP polling, no external CDN
   dependency — works offline too; protected by a login, see
   [Dashboard authentication](#dashboard-authentication)): network status,
   one card per **each** detected Wi-Fi adapter with independent
   listing/connection, "Devices" table, "Cameras" table (also includes
   NVR/DVR, split into on-network vs. out-of-network), "Report" tab,
   "Settings" tab to manage users, **CSV/JSON** export.

5. **Wi-Fi hotspot** ("📡 Hotspot" popup on the chosen Wi-Fi adapter's
   card): turns that adapter from a client (connected to an existing
   network) into an access point, useful for reaching the dashboard
   without a cable when the device is installed somewhere hard to wire
   (e.g. inside a box up high). SSID/password configurable from the popup
   (password can be auto-generated); once active the profile stays saved
   and reactivates itself on subsequent reboots, so the device stays
   reachable over Wi-Fi even after a power outage. **Activating it
   disconnects that adapter from whatever network it was on** — the same
   radio can't be a client and an access point at the same time — with
   **two Wi-Fi adapters** this is worked around by dedicating one to the
   hotspot and leaving the other as a client toward the existing network.
   Requires NetworkManager (`nmcli`), already used for the Wi-Fi client
   connection.

## Usage

```bash
# Web dashboard (default)
sudo python3 raspi-scanner.py

# Command-line report: full scan + print NETWORK ASSESSMENT, then exit
sudo python3 raspi-scanner.py --report
```

## Requirements

- Linux (built for Raspberry Pi OS) with Python 3.9+.
- Must be run as **root** (or with `cap_net_raw,cap_net_admin`
  capabilities): needed for the raw ARP scan and to reconfigure the
  interface (`ip addr`, `dhclient`).
- System packages: `python3-venv`, `isc-dhcp-client` (for `dhclient`).
  `nmcli` (NetworkManager) is optional, used only for Wi-Fi
  listing/connection.

## ARP scan limits (read before reporting "can't find a device")

The device scan is ARP-based: it only finds hosts that have an IP in the
scanned subnet and respond within the timeout. Some cases that look like
bugs aren't:

- **The machine running the scanner itself** would never receive its own
  broadcast ARP request back (no switch forwards it back out the port it
  came in on) — that's why the tool always adds it explicitly to the
  results, since it already knows its own IP and MAC without needing to
  query the network.
- **Unmanaged switches** (many cheap models) have no IP address at all:
  they're pure L2 electronics and are invisible to *any* IP-based scan,
  not just this one. If a network device never shows up, check whether it
  actually has an IP management interface.
- **A device on another subnet/VLAN**, reachable only through routing
  (e.g. ping works but goes through the gateway), will never be found by
  the ARP scan: it's a protocol limit, not a bug — ARP doesn't cross a
  router. It needs to be scanned from the correct L2 segment.
- **A just-connected host** may not respond yet: if the upstream switch
  has (R)STP active, the port stays in "listening" state for a few
  seconds before forwarding traffic, on top of the time the device itself
  takes to do DHCP at boot. Wait 20-30s after plugging in a cable before
  running the scan, or rerun it if the first pass doesn't find it.
- To independently verify, outside this tool, whether a device is really
  reachable on the subnet: `sudo arp-scan --interface=eth0 --localnet` or
  `sudo nmap -sn <subnet>`, or check the router/AP's DHCP lease table.

## Installation

```bash
sudo ./install.sh
```

Installs the project into `/opt/raspiscanner`, creates a virtualenv,
installs the Python dependencies (`Flask`, `scapy`) and
registers/starts the `raspiscanner.service` systemd service. Dashboard at
`https://<raspberry-ip>:7332` (self-signed certificate generated on first
launch: the browser will show an "insecure connection" warning to accept
once — see [Dashboard authentication](#dashboard-authentication)).

To run it without installing it as a service, for development:

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
sudo venv/bin/python3 raspi-scanner.py
```

## Tests

Unit tests, all mocked (no hardware or network access required):

```bash
python3 -m unittest discover -s tests -v
```

## Conflicts with NetworkManager/dhcpcd

If `eth0` is already managed by NetworkManager or `dhcpcd` (default
behavior on Raspberry Pi OS), those services may remove the static IP
assigned by RaspiScanner during the preset-class fallback. To avoid
conflicts, mark `eth0` as "unmanaged":

- **NetworkManager**: add to `/etc/NetworkManager/conf.d/unmanaged.conf`
  ```ini
  [keyfile]
  unmanaged-devices=interface-name:eth0
  ```
  then `sudo systemctl restart NetworkManager`.
- **dhcpcd**: add to `/etc/dhcpcd.conf`
  ```
  denyinterfaces eth0
  ```
  then `sudo systemctl restart dhcpcd`.

Wi-Fi (`wlan0`) can stay normally managed by NetworkManager: the scanner
only reads its status, it doesn't touch it (aside from the optional
connection endpoint via `nmcli`).

## Offline vendor (OUI) database

`data/oui.csv` is a reduced, "best effort" list of the most common
vendors (networking, IoT, IP cameras, Raspberry Pi) meant to work
**without internet** in the field. Camera recognition doesn't depend on
this file (it's based on ports/protocol), so a missing vendor is only a
missing informational label, not a scan accuracy problem.

`install.sh` already tries to download the full IEEE registry (~35,000
prefixes) automatically during installation, while the device is still
connected to the internet: if it succeeds, there's nothing else to do. If
the installation happened offline, or you want to update an already
installed copy, rerun the script manually (from a machine **with**
internet access — it doesn't have to be the Pi itself, if you then copy
the result into `data/oui.csv`):

```bash
python3 scripts/update_oui.py
```

Note for reinstalls: `install.sh` overwrites `data/oui.csv` with the
repo's minimal version on every `rsync`, so on an already-updated
instance it needs to be rerun **after** every reinstall, not just the
first time (unless you have internet at that moment, in which case it
already does it for you).

## Security notes

This is a network reconnaissance tool: only use it on networks you are
authorized to scan. The ARP scan, port scan, and security findings are
**active but non-intrusive** network probes — they send real packets (ARP
requests, TCP connection attempts, HTTP requests, WS-Discovery multicast),
so they're not "passive" in the strict sense, but they never perform
login, default-credential testing, or exploitation attempts — and they do
generate traffic visible on the target network.

### Dashboard authentication

The dashboard listens on `0.0.0.0:7332` and exposes the full inventory of
scanned devices (IP, MAC, vendor, **camera RTSP/admin URLs**) plus the
network/hotspot controls: it's protected by **HTTP Basic Auth** so that
anyone simply on the same network/hotspot during the scan can't access it
without credentials, served over **HTTPS** with a self-signed certificate
generated on first launch (persisted in `data/tls_cert.pem`/
`data/tls_key.pem`) so credentials travel encrypted instead of in the
clear over the network you're scanning.

There's no certificate signed by a public CA for this use case: the
device (Raspberry Pi or Linux PC) gets installed on a different private
network every time, often without internet access, and reached by IP, not
by domain — conditions under which a CA like Let's Encrypt can't issue or
renew anything. Because of this, like routers/NAS/network printers, the
browser will show an **"insecure connection" warning** on first access:
that's expected, accept it once (the certificate stays the same across
restarts, the warning doesn't repeat on every boot). It protects against
passive traffic interception on the same network, not against a very
sophisticated active man-in-the-middle attack that nobody actually
verifies in practice (certificate fingerprint) — a real improvement over
plain HTTP, not an absolute guarantee.

On first launch, if `data/users.json` doesn't exist yet, the default user
is created:

```
Username: RaspiScanner
Password: RaspiPass
```

**Change the password as soon as possible** from the "Settings" tab of
the dashboard, where you can also add other users or remove them.
Credentials are persisted (hashed, never in the clear) in
`data/users.json` and survive service restarts — nothing needs to be
redone on every boot. The browser asks for the username/password once and
remembers it for the browsing session.

`data/users.json` is in `.gitignore`: it must not be committed (it
contains the password hashes for that specific deployment).

## Project structure

```
raspi-scanner.py            Entry point: Flask dashboard (default) or CLI --report
scanner/
  config.py                  Shared constants (preset classes, ports, timeouts)
  auth.py                     Dashboard users (Basic Auth, persisted in data/users.json)
  tls.py                       Self-signed TLS certificate for the dashboard (via openssl)
  vendor.py                   Vendor lookup from offline OUI
  hosts.py                     Classification "is it a phone/tablet/Mac/PC/printer?"
  scan_engine.py                Scan orchestration + state for the dashboard
  discovery/
    arp.py                       ARP scan (scapy) + reverse DNS
  fingerprint/
    ports.py                      TCP port scan + HTTP banners
  cameras/
    onvif.py                       WS-Discovery + GetDeviceInformation (ONVIF)
    classify.py                     Classification "is it a camera?"
  nvr/
    classify.py                      Classification "is it an NVR/DVR?"
  network/
    setup.py                          Eth autoconfig (DHCP/fallback) + monitor + wifi
    infra.py                           Default gateway + "is it network gear?"
    hotspot.py                          Wi-Fi access point (cable-free reachability)
  reporting/
    security.py                         Security findings (Telnet, HTTP, default service)
    risk.py                              Severity aggregation -> risk summary
    assessment.py                         Generates the NETWORK ASSESSMENT report
tests/                       Unit tests (mocked, no hardware required)
docs/ARCHITECTURE.md         More detailed architectural overview
examples/                    Report examples and programmatic use of the classifiers
scripts/update_oui.py        Updates oui.csv from the IEEE registry (requires internet)
data/oui.csv                 Offline OUI database (best effort)
data/users.json              Dashboard users (password hashes, generated on first launch, gitignored)
data/tls_cert.pem, tls_key.pem  Self-signed TLS certificate (generated on first launch, gitignored)
templates/, static/          Dashboard (HTML/CSS/JS, no external CDN: works offline)
install.sh                   Installer (venv + systemd)
raspiscanner.service         systemd unit file
LICENSE                      MIT
```

More on the scan flow and architectural choices in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
